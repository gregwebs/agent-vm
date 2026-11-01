//! Unit tests for the SecretSpec client (#202): framing, the handshake gate,
//! the outcome mapping and the child lifecycle, all at the module's own seams.
//!
//! Two transports are used. The **fake endpoint** (`fake::serve`) speaks real
//! frames over an in-process pipe pair and is also the contract oracle for the
//! client's own envelopes. A **scripted** transport writes fixed bytes, which is
//! how the framing faults (split, coalesced, oversized, wrong id) are reached
//! deterministically. Real subprocesses appear only where the question is about
//! the process edge itself: argv, cwd, environment, descriptor hygiene and
//! process-group teardown.

use std::io::{BufReader, Write as _};
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::config::{SecretspecName, SecretspecSelection, SessionKey, parse_table};
use super::failure::SecretspecFailure;
use super::fake::{self, Scenario, Transcript};
use super::protocol::{
    self, EmptyResult, ErrorKind, GetResultWire, InitializeResult, Keep, shutdown_frame,
};
use super::session::{Bounds, CallError, Exchange, Session};
use crate::credential_yaml::GuestEnvName;
use crate::secret_store::{Resolved, ServiceName, ValueRejection};

fn name(raw: &str) -> SecretspecName {
    SecretspecName::parse(raw).expect("a valid test name")
}

fn key() -> SessionKey {
    selection("DEFAULT_KEY").session().clone()
}

/// A selection whose session key is the default fixture table.
fn selection(secret: &str) -> SecretspecSelection {
    let mut table = serde_json::Map::new();
    table.insert("executable".into(), "/opt/secretspec".into());
    table.insert("manifest".into(), "/tmp/secretspec.toml".into());
    table.insert("profile".into(), "default".into());
    table.insert("scope".into(), "agent-vm".into());
    table.insert("name".into(), secret.into());
    parse_table(
        &table,
        &GuestEnvName::parse("DEFAULT_KEY").expect("valid guest name"),
    )
    .expect("the fixture table validates")
}

fn service() -> ServiceName {
    ServiceName::parse("alpha").expect("valid service name")
}

/// A server driven by `fake::serve` over a pipe pair.
struct Fake {
    session: Session,
    transcript: PathBuf,
    _dir: tempfile::TempDir,
}

impl Fake {
    fn events(&self) -> Vec<Value> {
        std::fs::read_to_string(&self.transcript)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }

    fn violations(&self) -> Vec<Value> {
        self.events()
            .into_iter()
            .filter(|event| event["event"] == "violation")
            .collect()
    }

    fn requests(&self, method: &str) -> Vec<Value> {
        self.events()
            .into_iter()
            .filter(|event| event["event"] == "request" && event["method"] == method)
            .map(|event| event["frame"].clone())
            .collect()
    }

    fn of_kind(&self, kind: &str) -> Vec<Value> {
        self.events()
            .into_iter()
            .filter(|event| event["event"] == kind)
            .collect()
    }
}

/// Start `fake::serve` with `scenario` on the far end of a pipe pair.
fn fake(scenario: Value) -> Fake {
    let dir = tempfile::tempdir().expect("tempdir");
    let transcript = dir.path().join("transcript.jsonl");
    let mut object = scenario.as_object().cloned().unwrap_or_default();
    object
        .entry("transcript")
        .or_insert_with(|| json!(transcript));
    let scenario: Scenario =
        serde_json::from_value(Value::Object(object)).expect("a well-formed scenario");
    let (server_input, client_output) = std::io::pipe().expect("pipe");
    let (client_input, server_output) = std::io::pipe().expect("pipe");
    let path = transcript.clone();
    std::thread::spawn(move || {
        let mut transcript = Transcript::open(Some(&path));
        fake::serve(
            &scenario,
            BufReader::new(server_input),
            server_output,
            &mut transcript,
        )
    });
    Fake {
        session: Session::over(OwnedFd::from(client_output), OwnedFd::from(client_input)),
        transcript,
        _dir: dir,
    }
}

/// A fake that completes the handshake, with the given secrets.
fn started(scenario: Value) -> Fake {
    let fake = fake(scenario);
    let mut fake = fake;
    fake.session
        .handshake(&key(), Duration::from_secs(10))
        .expect("the fixture handshake is accepted");
    fake
}

/// A transport whose server writes each chunk, then closes. The chunks are
/// written with a short pause so a split frame really is split.
/// One in-process server that writes `chunks` and then stays connected.
///
/// The server's read end is owned by the returned value, not by the writer
/// thread. A thread that closes it when it has finished writing turns the
/// client's *next* request write into `EPIPE`, which is a scheduling race and
/// not a framing property: measured, a 50 ms delay before the first call is
/// enough to make `call_empty` return `WriteClosed`. In a loaded full-suite run
/// that window was missed often enough to fail the chunking proptest about once
/// in ten whole-`--bin` runs, with no framing defect behind it.
struct Scripted {
    session: Session,
    _server_read: OwnedFd,
}

impl std::ops::Deref for Scripted {
    type Target = Session;
    fn deref(&self) -> &Session {
        &self.session
    }
}

impl std::ops::DerefMut for Scripted {
    fn deref_mut(&mut self) -> &mut Session {
        &mut self.session
    }
}

fn scripted(chunks: Vec<Vec<u8>>) -> Scripted {
    let (server_input, client_output) = std::io::pipe().expect("pipe");
    let (client_input, mut server_output) = std::io::pipe().expect("pipe");
    std::thread::spawn(move || {
        for chunk in chunks {
            let _ = server_output.write_all(&chunk);
            let _ = server_output.flush();
            std::thread::sleep(Duration::from_millis(2));
        }
    });
    Scripted {
        session: Session::over(OwnedFd::from(client_output), OwnedFd::from(client_input)),
        _server_read: OwnedFd::from(server_input),
    }
}

/// One `resolver.get` over `session`, with short bounds.
fn get(session: &mut Session) -> Exchange {
    session.get(&name("ALPHA_KEY"), &Bounds::short(), &service())
}

fn resolved(exchange: Exchange) -> (Resolved, Keep) {
    match exchange {
        Exchange::Answered(resolved, keep) => (resolved, keep),
        Exchange::DeadBeforeRequest => panic!("expected an answer, got a dead child"),
    }
}

// ---------------------------------------------------------------------------
// P1 — the client's frames are the protocol's frames
// ---------------------------------------------------------------------------

#[test]
fn frames_follow_the_protocol_shape() {
    let mut fake = started(json!({"secrets": {"ALPHA_KEY": {"value": "sk-CANARY-p1"}}}));
    let (resolved_value, keep) = resolved(get(&mut fake.session));
    assert!(matches!(resolved_value, Resolved::Value(_)));
    assert_eq!(keep, Keep::Session);
    // The contract oracle accepts every frame: no `violation` event at all.
    assert!(
        fake.violations().is_empty(),
        "{}",
        serde_json::to_string(&fake.violations()).unwrap()
    );

    let initialize = fake.requests("rpc.initialize");
    assert_eq!(initialize.len(), 1);
    let frame = &initialize[0];
    assert_eq!(frame["jsonrpc"], "2.0");
    assert_eq!(frame["method"], "rpc.initialize");
    let params = &frame["params"];
    assert_eq!(params["protocol"], "secretspec.resolver");
    assert_eq!(params["versions"], json!([1]));
    assert_eq!(params["client"]["name"], "agent-vm");
    assert_eq!(
        params["limits"],
        json!({"max_frame_bytes": 16384, "max_in_flight": 1})
    );
    assert!(params.get("client_methods").is_none());
    assert_eq!(params["application"]["provider"], Value::Null);
    assert_eq!(params["application"]["profile"], "default");
    assert_eq!(params["application"]["scope"], "agent-vm");
    assert_eq!(params["application"]["reason"], Value::Null);
    assert_eq!(params["application"]["manifest"]["kind"], "path");
    assert_eq!(
        params["application"]["manifest"]["path"],
        "/tmp/secretspec.toml"
    );

    let gets = fake.requests("resolver.get");
    assert_eq!(gets.len(), 1);
    let params = &gets[0]["params"];
    assert_eq!(params["name"], "ALPHA_KEY");
    assert_eq!(params["representation"], "value");
    assert_eq!(
        params["purpose"],
        json!({"consumer": "agent-vm", "operation": "launch"})
    );
    // No value ever appears in the transcript, which is built from client
    // frames only.
    assert!(
        !std::fs::read_to_string(&fake.transcript)
            .unwrap()
            .contains("sk-CANARY-p1")
    );
    // `shutdown` consumes the session, so split the struct first.
    let Fake {
        session,
        transcript,
        _dir,
    } = fake;
    session.shutdown();
    let events: Vec<Value> = std::fs::read_to_string(&transcript)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    assert_eq!(
        events
            .iter()
            .filter(|event| event["event"] == "request" && event["method"] == "rpc.shutdown")
            .count(),
        1
    );
    assert!(
        !std::fs::read_to_string(&transcript)
            .unwrap()
            .contains("sk-CANARY-p1")
    );
}

// ---------------------------------------------------------------------------
// P2/P3/P4 — framing
// ---------------------------------------------------------------------------

fn response(id: u64) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {"status": "missing"}
    }))
    .unwrap();
    bytes.push(b'\n');
    bytes
}

fn notification() -> Vec<u8> {
    let mut bytes =
        serde_json::to_vec(&json!({"jsonrpc": "2.0", "method": "rpc.progress"})).unwrap();
    bytes.push(b'\n');
    bytes
}

fn call_empty(session: &mut Session) -> Result<(), CallError> {
    // The bound only ends a *hung* test: these assertions are about the frame
    // sequence, not latency, and a descheduled writer thread must not be able to
    // fail them. The timeout tests do not use this helper — they drive
    // `Bounds::short()` through `Session::get` — so a generous bound here hides
    // no behaviour.
    session
        .call::<EmptyResult>(
            shutdown_frame,
            Duration::from_secs(60),
            None,
            Duration::from_millis(100),
        )
        .map(|_| ())
}

#[test]
fn split_and_coalesced_frames_parse() {
    // Three answers in one write, with a notification first: the notification is
    // skipped and the two answers are buffered from the same read.
    let mut coalesced = notification();
    coalesced.extend(response(1));
    coalesced.extend(response(2));
    let mut session = scripted(vec![coalesced]);
    assert!(call_empty(&mut session).is_ok());
    assert!(call_empty(&mut session).is_ok());

    // One answer split across four writes, a byte at a time at the boundary.
    let frame = response(1);
    let chunks: Vec<Vec<u8>> = frame.chunks(7).map(<[u8]>::to_vec).collect();
    let mut session = scripted(chunks);
    assert!(call_empty(&mut session).is_ok());
}

proptest::proptest! {
    /// Any chunking of the same byte stream yields the same frame sequence.
    #[test]
    fn random_chunking_preserves_the_frame_sequence(
        cuts in proptest::collection::vec(1usize..40, 0..8),
    ) {
        use proptest::prop_assert;
        let mut stream = Vec::new();
        let mut answer = notification();
        answer.extend(response(1));
        answer.extend(notification());
        answer.extend(response(2));
        answer.extend(response(3));
        stream.extend(answer);
        let mut chunks = Vec::new();
        let mut start = 0;
        for cut in cuts {
            if start >= stream.len() { break }
            let end = (start + cut).min(stream.len());
            chunks.push(stream[start..end].to_vec());
            start = end;
        }
        if start < stream.len() { chunks.push(stream[start..].to_vec()) }
        let mut session = scripted(chunks);
        for i in 0..3 {
            let outcome = call_empty(&mut session);
            prop_assert!(outcome.is_ok(), "call {}: {:?}", i, outcome);
        }
    }
}

/// The fixture keeps the server's read end open after its last chunk.
///
/// While the writer thread owned that end, a caller delayed by more than the
/// write window failed its *next* request with `EPIPE` (`WriteClosed`) — the
/// load-dependent failure that made `random_chunking_preserves_the_frame_sequence`
/// flake in a full-suite run, with no framing defect behind it. The delay makes
/// the race deterministic instead of load-dependent.
#[test]
fn the_fixture_keeps_the_server_read_end_open_after_the_last_chunk() {
    let mut session = scripted(vec![response(1)]);
    std::thread::sleep(Duration::from_millis(50));
    let outcome = call_empty(&mut session);
    assert!(
        outcome.is_ok(),
        "a delayed caller must still be able to write its request: {outcome:?}"
    );
}

#[test]
fn an_oversize_frame_is_refused_before_parsing() {
    for excess in [0usize, 1] {
        let limit = 4096;
        // A frame of exactly `limit` bytes is accepted; `limit + 1` is refused —
        // with and without its LF, so the refusal cannot depend on the
        // terminator arriving.
        let body_len = if excess == 0 { limit } else { limit + 1 };
        let mut frame = vec![b' '; body_len - 2];
        frame.insert(0, b'{');
        frame.push(b'}');
        if excess == 0 {
            frame.push(b'\n');
        }
        let mut session = scripted(vec![frame]);
        session.set_frame_limit(limit);
        let outcome = call_empty(&mut session);
        if excess == 0 {
            // Exactly the limit, but not valid JSON: the framing accepted it and
            // parsing refused it. Both are distinguishable from `TooLarge`.
            assert!(matches!(outcome, Err(CallError::Violation)), "{outcome:?}");
        } else {
            assert!(matches!(outcome, Err(CallError::TooLarge)), "{outcome:?}");
        }
    }
    // A frame one byte under the limit is accepted.
    let limit = 4096;
    let mut frame = response(1);
    frame.pop();
    frame.resize(limit - 1, b' ');
    frame.push(b'\n');
    let mut session = scripted(vec![frame]);
    session.set_frame_limit(limit);
    assert!(call_empty(&mut session).is_ok());
}

#[test]
fn a_mismatched_or_null_id_or_bad_jsonrpc_is_a_protocol_violation() {
    for frame in [
        // The wrong id.
        response(7),
        // `id: null`.
        {
            let mut bytes =
                serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": null, "result": {}})).unwrap();
            bytes.push(b'\n');
            bytes
        },
        // A non-2.0 envelope.
        {
            let mut bytes =
                serde_json::to_vec(&json!({"jsonrpc": "1.0", "id": 1, "result": {}})).unwrap();
            bytes.push(b'\n');
            bytes
        },
        // Not JSON at all.
        b"not a frame\n".to_vec(),
        // Both `result` and `error`.
        {
            let mut bytes = serde_json::to_vec(&json!({
                "jsonrpc": "2.0", "id": 1,
                "result": {},
                "error": {"code": -32603, "data": {"kind": "internal"}}
            }))
            .unwrap();
            bytes.push(b'\n');
            bytes
        },
    ] {
        let mut session = scripted(vec![frame]);
        assert!(
            matches!(call_empty(&mut session), Err(CallError::Violation)),
            "a malformed answer must end the session"
        );
    }
}

#[test]
fn a_hung_request_times_out_sends_rpc_cancel_and_ends_the_session() {
    let mut fake = started(json!({"secrets": {"ALPHA_KEY": "hang"}}));
    let bounds = Bounds::short();
    let (resolved_value, keep) =
        resolved(fake.session.get(&name("ALPHA_KEY"), &bounds, &service()));
    assert!(matches!(
        resolved_value,
        Resolved::SecretspecUnavailable(SecretspecFailure::Unresponsive)
    ));
    assert_eq!(keep, Keep::Kill);
    // The client told the server it gave up before the group was killed.
    let cancels = fake.of_kind("cancel");
    assert_eq!(cancels.len(), 1, "{cancels:?}");
}

#[test]
fn a_client_prompt_is_refused_with_method_not_found_and_the_read_continues() {
    let mut fake = started(json!({"secrets": {"ALPHA_KEY": "prompt"}}));
    let bounds = Bounds::short();
    let (resolved_value, keep) =
        resolved(fake.session.get(&name("ALPHA_KEY"), &bounds, &service()));
    // The prompt is refused with -32601 and the get's own answer still decides.
    let answers = fake.of_kind("prompt_answer");
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0]["code"], -32601);
    assert_eq!(answers[0]["kind"], "method_not_found");
    assert!(matches!(
        resolved_value,
        Resolved::SecretspecUnavailable(SecretspecFailure::PermissionDenied)
    ));
    assert_eq!(keep, Keep::Session);
}

#[test]
fn notifications_are_skipped_and_interleaving_is_bounded() {
    for (count, expected_violation) in [(8usize, false), (9, true)] {
        let mut bytes = Vec::new();
        for _ in 0..count {
            bytes.extend(notification());
        }
        bytes.extend(response(1));
        let mut session = scripted(vec![bytes]);
        let outcome = call_empty(&mut session);
        assert_eq!(
            matches!(outcome, Err(CallError::Violation)),
            expected_violation,
            "{count} interleaved frames: {outcome:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// P8/P9/P12 — the outcome tables (pure)
// ---------------------------------------------------------------------------

fn wire(
    status: &str,
    representation: Option<&str>,
    value: Option<&str>,
    source: Option<&str>,
) -> GetResultWire {
    let frame = json!({
        "status": status,
        "representation": representation,
        "value": value,
        "source": source,
    });
    serde_json::from_value(frame).expect("a decodable get result")
}

#[test]
fn the_outcome_table_maps_every_status_and_error_kind() {
    use SecretspecFailure as F;
    // Statuses.
    assert!(matches!(
        protocol::classify_get(wire(
            "resolved",
            Some("value"),
            Some("sk-ok"),
            Some("provider")
        )),
        (Resolved::Value(_), Keep::Session)
    ));
    for source in ["default", "composed"] {
        assert!(matches!(
            protocol::classify_get(wire("resolved", Some("value"), Some("sk-ok"), Some(source))),
            (Resolved::Value(_), Keep::Session)
        ));
    }
    assert!(matches!(
        protocol::classify_get(wire("missing", None, None, None)),
        (Resolved::Missing, Keep::Session)
    ));
    // `undeclared` is `Missing`, exactly as the issue maps it.
    assert!(matches!(
        protocol::classify_get(wire("undeclared", None, None, None)),
        (Resolved::Missing, Keep::Session)
    ));
    for status in ["generated", "weird"] {
        assert!(matches!(
            protocol::classify_get(wire(status, None, None, None)),
            (
                Resolved::SecretspecUnavailable(F::ProtocolViolation),
                Keep::Kill
            )
        ));
    }

    // Every error kind, with its documented outcome and session fate.
    #[derive(Clone, Copy)]
    enum Expected {
        Unavailable(SecretspecFailure),
        Invalid(ValueRejection),
    }
    let table = [
        (
            ErrorKind::MessageTooLarge,
            Expected::Invalid(ValueRejection::TooLong),
            Keep::Session,
        ),
        (
            ErrorKind::UnsupportedVersion,
            Expected::Unavailable(F::UnsupportedProtocol),
            Keep::Kill,
        ),
        (
            ErrorKind::DeadlineExceeded,
            Expected::Unavailable(F::Unresponsive),
            Keep::Session,
        ),
        (
            ErrorKind::Cancelled,
            Expected::Unavailable(F::Unresponsive),
            Keep::Session,
        ),
        (
            ErrorKind::PermissionDenied,
            Expected::Unavailable(F::PermissionDenied),
            Keep::Session,
        ),
        (
            ErrorKind::InteractionRequired,
            Expected::Unavailable(F::PermissionDenied),
            Keep::Session,
        ),
        (
            ErrorKind::RepresentationMismatch,
            Expected::Unavailable(F::RepresentationMismatch),
            Keep::Session,
        ),
        (
            ErrorKind::ParseError,
            Expected::Unavailable(F::ProtocolViolation),
            Keep::Session,
        ),
        (
            ErrorKind::InvalidRequest,
            Expected::Unavailable(F::ProtocolViolation),
            Keep::Session,
        ),
        (
            ErrorKind::MethodNotFound,
            Expected::Unavailable(F::ProtocolViolation),
            Keep::Session,
        ),
        (
            ErrorKind::InvalidParams,
            Expected::Unavailable(F::ProtocolViolation),
            Keep::Session,
        ),
        (
            ErrorKind::CapabilityRequired,
            Expected::Unavailable(F::ProtocolViolation),
            Keep::Session,
        ),
        (
            ErrorKind::Unavailable,
            Expected::Unavailable(F::ProviderFailed),
            Keep::Session,
        ),
        (
            ErrorKind::OperationFailed,
            Expected::Unavailable(F::ProviderFailed),
            Keep::Session,
        ),
        (
            ErrorKind::Internal,
            Expected::Unavailable(F::ProviderFailed),
            Keep::Session,
        ),
        (
            ErrorKind::Conflict,
            Expected::Unavailable(F::ProviderFailed),
            Keep::Session,
        ),
        (
            ErrorKind::Other,
            Expected::Unavailable(F::ProviderFailed),
            Keep::Session,
        ),
    ];
    for (kind, expected, keep) in table {
        let (resolved_value, actual_keep) = protocol::classify_get_error(kind);
        assert_eq!(actual_keep, keep, "{kind:?}");
        match (expected, resolved_value) {
            (Expected::Invalid(rule), Resolved::InvalidValue(actual)) => {
                assert_eq!(actual, rule, "{kind:?}")
            }
            (Expected::Unavailable(failure), Resolved::SecretspecUnavailable(actual)) => {
                assert_eq!(actual, failure, "{kind:?}")
            }
            (expected, actual) => panic!(
                "{kind:?}: expected {:?}, got {actual:?}",
                match expected {
                    Expected::Invalid(rule) => format!("invalid({rule:?})"),
                    Expected::Unavailable(failure) => format!("unavailable({failure:?})"),
                }
            ),
        }
    }

    // `rpc.initialize` errors.
    for (kind, failure) in [
        (ErrorKind::UnsupportedVersion, F::UnsupportedProtocol),
        (ErrorKind::OperationFailed, F::SessionRejected),
        (ErrorKind::InvalidParams, F::SessionRejected),
        (ErrorKind::PermissionDenied, F::PermissionDenied),
        (ErrorKind::InteractionRequired, F::PermissionDenied),
        (ErrorKind::Unavailable, F::ProviderFailed),
        (ErrorKind::Internal, F::ProviderFailed),
        (ErrorKind::MethodNotFound, F::ProtocolViolation),
    ] {
        assert_eq!(protocol::initialize_failure(kind), failure, "{kind:?}");
    }
}

#[test]
fn a_generated_or_path_result_is_refused_and_kills_the_session() {
    for (representation, source) in [
        (Some("value"), Some("generated")),
        (Some("path"), Some("provider")),
        (None, Some("provider")),
        (Some("value"), None),
    ] {
        let (resolved_value, keep) =
            protocol::classify_get(wire("resolved", representation, Some("x"), source));
        assert!(
            matches!(
                resolved_value,
                Resolved::SecretspecUnavailable(SecretspecFailure::ProtocolViolation)
            ),
            "{representation:?}/{source:?}"
        );
        assert_eq!(keep, Keep::Kill);
    }
}

#[test]
fn a_rejected_value_is_invalid_value() {
    for value in ["", " sk-edge", "sk-\u{7f}", &"x".repeat(4097)] {
        let (resolved_value, keep) = protocol::classify_get(wire(
            "resolved",
            Some("value"),
            Some(value),
            Some("provider"),
        ));
        assert!(
            matches!(resolved_value, Resolved::InvalidValue(_)),
            "{value:?}"
        );
        // A rejected value is about the value, not the session.
        assert_eq!(keep, Keep::Session);
    }
}

// ---------------------------------------------------------------------------
// P10/P13 — the gate and the negotiated limits
// ---------------------------------------------------------------------------

fn initialize_result(
    methods: &[&str],
    protocol: &str,
    version: u64,
    limits: Value,
) -> InitializeResult {
    serde_json::from_value(json!({
        "protocol": protocol,
        "version": version,
        "methods": methods,
        "limits": limits,
    }))
    .expect("a decodable initialize result")
}

#[test]
fn the_gate_requires_get_and_release_and_no_write_method() {
    let echoed = json!({"max_frame_bytes": 16384, "max_in_flight": 1});
    // The accepted shape.
    assert_eq!(
        protocol::gate(&initialize_result(
            &["resolver.get", "resolver.release"],
            "secretspec.resolver",
            1,
            echoed.clone()
        )),
        Ok(16384)
    );
    // The mandatory capability: `get` alone is not enough (B5).
    assert_eq!(
        protocol::gate(&initialize_result(
            &["resolver.get"],
            "secretspec.resolver",
            1,
            echoed.clone()
        )),
        Err(SecretspecFailure::UnsupportedProtocol)
    );
    // A write method anywhere in the list is refused.
    for methods in [
        vec!["resolver.get", "resolver.release", "resolver.set"],
        vec!["resolver.get", "resolver.release", "resolver.delete"],
        vec![
            "resolver.get",
            "resolver.release",
            "resolver.set",
            "resolver.delete",
        ],
    ] {
        assert_eq!(
            protocol::gate(&initialize_result(
                &methods,
                "secretspec.resolver",
                1,
                echoed.clone()
            )),
            Err(SecretspecFailure::NotReadOnly),
            "{methods:?}"
        );
    }
    // The version is a number, not a string, and the protocol is exact.
    for (protocol, version) in [("secretspec.resolver", 2), ("secretspec.provider", 1)] {
        assert_eq!(
            protocol::gate(&initialize_result(
                &["resolver.get", "resolver.release"],
                protocol,
                version,
                echoed.clone()
            )),
            Err(SecretspecFailure::UnsupportedProtocol)
        );
    }

    // Both kernels, over their full Boolean inputs.
    for speaks in [false, true] {
        for get in [false, true] {
            for release in [false, true] {
                assert_eq!(
                    super::capability_satisfied(speaks, get, release),
                    speaks && get && release
                );
            }
        }
    }
    for set in [false, true] {
        for delete in [false, true] {
            assert_eq!(super::offers_no_write_method(set, delete), !set && !delete);
        }
    }
}

#[test]
fn negotiated_limits_are_accepted_and_enforced() {
    // A smaller negotiated frame limit is accepted, stored, and then enforced in
    // both directions.
    let mut negotiated = fake(json!({
        "handshake": {"limits": {"max_frame_bytes": 4096, "max_in_flight": 2}},
        "secrets": {"ALPHA_KEY": {"value": "sk-ok"}}
    }));
    negotiated
        .session
        .handshake(&key(), Duration::from_secs(10))
        .expect("an in-range limit is accepted");
    assert_eq!(negotiated.session.frame_limit(), 4096);
    // A get still fits in 4096 bytes and is answered.
    assert!(matches!(
        resolved(get(&mut negotiated.session)).0,
        Resolved::Value(_)
    ));
    // An outgoing frame above the negotiated limit is refused before a byte is
    // written.
    let long = SecretspecName::parse(&"N".repeat(4096)).expect("a long but valid name");
    let outcome = negotiated.session.get(&long, &Bounds::short(), &service());
    assert!(matches!(resolved(outcome).0, Resolved::InvalidValue(_)));

    // Refused before any `resolver.get`: out-of-range, zero in-flight, absent
    // and malformed limits.
    for handshake in [
        json!({"limits": {"max_frame_bytes": 4095, "max_in_flight": 1}}),
        json!({"limits": {"max_frame_bytes": 16385, "max_in_flight": 1}}),
        json!({"limits": {"max_frame_bytes": 1048577, "max_in_flight": 1}}),
        json!({"limits": {"max_frame_bytes": 16384, "max_in_flight": 0}}),
        json!("no_limits"),
    ] {
        let mut fake = fake(json!({ "handshake": handshake }));
        let failure = fake
            .session
            .handshake(&key(), Duration::from_millis(500))
            .expect_err("unusable limits must refuse the session");
        assert_eq!(failure, SecretspecFailure::ProtocolViolation, "{handshake}");
        assert!(
            fake.requests("resolver.get").is_empty(),
            "no get may be sent after a refused gate"
        );
    }
    // A non-integer limit is a decode failure, hence a violation, not a wrap.
    assert!(
        serde_json::from_value::<InitializeResult>(json!({
            "protocol": "secretspec.resolver",
            "version": 1,
            "methods": ["resolver.get", "resolver.release"],
            "limits": {"max_frame_bytes": 1.5, "max_in_flight": 1}
        }))
        .is_err()
    );
}

// ---------------------------------------------------------------------------
// P14 — poll edges and bounded writes
// ---------------------------------------------------------------------------

/// A `Write` that always reports `EINTR`: a signal storm, not an error.
struct AlwaysInterrupted;

impl std::io::Write for AlwaysInterrupted {
    fn write(&mut self, _frame: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::from(std::io::ErrorKind::Interrupted))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A `Write` that reports `EINTR` twice and then accepts the whole frame.
struct InterruptedTwice(u8);

impl std::io::Write for InterruptedTwice {
    fn write(&mut self, frame: &[u8]) -> std::io::Result<usize> {
        if self.0 > 0 {
            self.0 -= 1;
            return Err(std::io::Error::from(std::io::ErrorKind::Interrupted));
        }
        Ok(frame.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// An `EINTR` stream must not outlive the caller's deadline.
///
/// `write_bounded` used to `continue` on `Interrupted` without re-reading the
/// deadline, so an uninterrupted signal storm could park the write forever (a
/// 200 ms budget took 1516 ms under fault injection). The deadline is now
/// checked at the top of every iteration.
#[test]
fn an_interrupted_write_still_meets_its_deadline() {
    let started = Instant::now();
    let result = super::session::write_bounded_for_test(
        &mut AlwaysInterrupted,
        b"a whole frame",
        Instant::now() + Duration::from_millis(50),
    );
    assert_eq!(result.err(), Some(CallError::TimedOut));
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "the write outlived its deadline by {:?}",
        started.elapsed()
    );
}

/// The same loop still makes progress when the interrupts stop.
#[test]
fn an_interrupted_write_that_stops_interrupting_succeeds() {
    let result = super::session::write_bounded_for_test(
        &mut InterruptedTwice(2),
        b"a whole frame",
        Instant::now() + Duration::from_millis(500),
    );
    assert!(result.is_ok(), "two `EINTR`s must not fail the write");
}

// ---------------------------------------------------------------------------
// The fake endpoint's own contract: the rejections the real 0.21.1 server makes
// ---------------------------------------------------------------------------

/// One raw run of the fake: its answer frames, its exit code and its transcript.
///
/// `Session` only ever speaks a well-formed sequence, so the frames the fake
/// *rejects* have to be written by hand.
struct RawRun {
    answers: Vec<Value>,
    exit: i32,
    events: Vec<Value>,
}

fn serve_raw(frames: &[String]) -> RawRun {
    let dir = tempfile::tempdir().expect("tempdir");
    let transcript = dir.path().join("transcript.jsonl");
    let scenario: Scenario = serde_json::from_value(json!({ "transcript": transcript }))
        .expect("a scenario with only a transcript");
    let input: String = frames.iter().map(|frame| format!("{frame}\n")).collect();
    let mut output: Vec<u8> = Vec::new();
    let mut sink = Transcript::open(Some(&transcript));
    let exit = fake::serve(
        &scenario,
        std::io::Cursor::new(input.into_bytes()),
        &mut output,
        &mut sink,
    );
    RawRun {
        answers: String::from_utf8_lossy(&output)
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect(),
        exit,
        events: std::fs::read_to_string(&transcript)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect(),
    }
}

/// A frame the client itself would write, as the line the fake reads.
fn frame_text(frame: Vec<u8>) -> String {
    String::from_utf8(frame)
        .expect("a UTF-8 frame")
        .trim_end()
        .to_owned()
}

fn initialize_frame_text(id: u64) -> String {
    frame_text(protocol::initialize_frame(
        protocol::RequestId(id),
        &key(),
        protocol::DeadlineUnixMs::after(Duration::from_secs(60)),
    ))
}

fn get_frame_value(id: u64) -> Value {
    serde_json::from_slice(&protocol::get_frame(
        protocol::RequestId(id),
        &name("ALPHA_KEY"),
        protocol::DeadlineUnixMs::after(Duration::from_secs(60)),
    ))
    .expect("the client's get frame is JSON")
}

/// A get before the initialize: recorded as `invalid_request` with the frame's
/// own id. The fake used to answer it, so a client that skipped the handshake
/// passed.
#[test]
fn the_fake_refuses_a_get_before_the_initialize() {
    let run = serve_raw(&[frame_text(protocol::get_frame(
        protocol::RequestId(2),
        &name("ALPHA_KEY"),
        protocol::DeadlineUnixMs::after(Duration::from_secs(5)),
    ))]);
    assert_eq!(run.answers[0]["error"]["data"]["kind"], "invalid_request");
    assert_eq!(run.answers[0]["id"], 2);
    assert_eq!(run.exit, 1);
    assert!(
        run.events
            .iter()
            .any(|event| event["event"] == "violation" && event["rule"] == "get_before_initialize")
    );
}

/// A second initialize: `invalid_request`, as 0.21.1 answers.
#[test]
fn the_fake_refuses_a_second_initialize() {
    let run = serve_raw(&[initialize_frame_text(1), initialize_frame_text(2)]);
    assert_eq!(run.answers.len(), 2);
    assert_eq!(run.answers[1]["error"]["data"]["kind"], "invalid_request");
    assert_eq!(run.answers[1]["id"], 2);
    assert_eq!(run.exit, 1);
}

/// A non-`2.0` envelope: `invalid_request` with `id: null`, because the server
/// cannot attribute a frame that is not a request it recognises.
#[test]
fn the_fake_refuses_a_non_2_0_envelope() {
    let mut value: Value = serde_json::from_str(&initialize_frame_text(1)).expect("JSON");
    value["jsonrpc"] = json!("1.0");
    let run = serve_raw(&[value.to_string()]);
    assert_eq!(run.answers[0]["error"]["data"]["kind"], "invalid_request");
    assert!(run.answers[0]["id"].is_null());
    assert_eq!(run.exit, 1);
}

/// An initialize `params` carrying a key the schema forbids: `invalid_params`,
/// not `invalid_request` — the one case where the recorded kind differs.
#[test]
fn the_fake_refuses_an_unknown_initialize_params_key() {
    let mut value: Value = serde_json::from_str(&initialize_frame_text(1)).expect("JSON");
    value["params"]["prompt"] = json!(true);
    let run = serve_raw(&[value.to_string()]);
    assert_eq!(run.answers[0]["error"]["data"]["kind"], "invalid_params");
    assert_eq!(run.answers[0]["id"], 1);
}

/// A get whose mirrored deadline has already passed: `deadline_exceeded`.
#[test]
fn the_fake_refuses_an_expired_get_deadline() {
    let mut get = get_frame_value(2);
    get["_meta"]["deadline_unix_ms"] = json!(1);
    let run = serve_raw(&[initialize_frame_text(1), get.to_string()]);
    assert_eq!(run.answers[1]["error"]["data"]["kind"], "deadline_exceeded");
    assert_eq!(run.answers[1]["id"], 2);
}

/// An empty `name`: `invalid_params`, so an empty name can never be mistaken for
/// a declared secret with no value (`missing`).
#[test]
fn the_fake_refuses_an_empty_get_name() {
    let mut get = get_frame_value(2);
    get["params"]["name"] = json!("");
    let run = serve_raw(&[initialize_frame_text(1), get.to_string()]);
    assert_eq!(run.answers[1]["error"]["data"]["kind"], "invalid_params");
    assert_eq!(run.answers[1]["id"], 2);
}

// ---------------------------------------------------------------------------
// ADR-0018 — the three new pure decisions, pinned in their erased form
// ---------------------------------------------------------------------------
//
// A `verus!` spec function erases under a plain build, so a table test is the
// only thing that pins the executable form under `cargo test`. Verus itself runs
// in CI (`verus.yml`), not on this host.

/// `executable_is_trusted` over the whole eight-row fact space.
#[test]
fn the_executable_trust_kernels_match_their_truth_table() {
    // (regular file, execute bit, group/other writable) → runnable, trusted
    let table = [
        (true, true, false, true, true),
        (true, true, true, true, false),
        (true, false, false, false, false),
        (true, false, true, false, false),
        (false, true, false, false, false),
        (false, true, true, false, false),
        (false, false, false, false, false),
        (false, false, true, false, false),
    ];
    for (file, execute, writable, runnable, trusted) in table {
        assert!(
            super::session::executable_is_runnable(file, execute) == runnable,
            "runnable({file}, {execute}) must be {runnable}"
        );
        assert!(
            super::session::executable_is_trusted(file, execute, writable) == trusted,
            "trusted({file}, {execute}, {writable}) must be {trusted}"
        );
        // Trusted implies runnable: no table row may accept what the first
        // kernel refuses.
        assert!(!trusted || runnable);
    }
}

/// The negotiated-limit acceptance over its four rows, and the enforced limit at
/// each boundary of the accepted range.
#[test]
fn the_negotiated_limit_kernels_match_their_boundary_table() {
    for (in_range, in_flight, usable) in [
        (true, true, true),
        (true, false, false),
        (false, true, false),
        (false, false, false),
    ] {
        assert!(
            super::protocol::negotiated_limit_is_usable(in_range, in_flight) == usable,
            "usable({in_range}, {in_flight}) must be {usable}"
        );
    }
    let client_max = super::protocol::CLIENT_MAX_FRAME_BYTES as u64;
    let min = super::protocol::MIN_FRAME_BYTES;
    for (negotiated, enforced) in [
        (min, min),
        (client_max, client_max),
        (min + 1, min + 1),
        (8 * 1024, 8 * 1024),
    ] {
        assert_eq!(
            super::protocol::enforced_frame_limit(negotiated, client_max),
            enforced
        );
    }
    // A server that asked for more than the client advertises never widens the
    // session: the enforced limit is the client's own maximum.
    assert_eq!(
        super::protocol::enforced_frame_limit(client_max + 1, client_max),
        client_max
    );
    assert_eq!(
        super::protocol::enforced_frame_limit(u64::MAX, client_max),
        client_max
    );
}

/// The label acceptance rule at each boundary of each condition.
#[test]
fn the_label_kernel_matches_its_boundary_table() {
    use super::config::{MAX_LABEL_BYTES, MAX_LABEL_CHARS};
    let check = |empty, bytes, chars, control, expected| {
        assert!(
            super::config::label_is_accepted(empty, bytes, chars, control) == expected,
            "accepted({empty}, {bytes}, {chars}, {control}) must be {expected}"
        );
    };
    // Each condition alone can refuse; all four together accept.
    check(false, true, true, false, true);
    check(true, true, true, false, false);
    check(false, false, true, false, false);
    check(false, true, false, false, false);
    check(false, true, true, true, false);
    check(true, false, false, true, false);
    // The measured boundaries, through the real predicate: one under, at, and one
    // over each cap, plus a control character on each line and the printable
    // neighbour of each control boundary.
    let at_chars = "a".repeat(MAX_LABEL_CHARS);
    let over_chars = "a".repeat(MAX_LABEL_CHARS + 1);
    assert!(label_ok(&at_chars));
    assert!(!label_ok(&over_chars));
    // `é` is two bytes and one character: 2048 of them fill the byte cap at half
    // the character cap, so the two caps are genuinely independent.
    let at_bytes = "é".repeat(MAX_LABEL_BYTES / 2);
    assert_eq!(at_bytes.len(), MAX_LABEL_BYTES);
    assert!(label_ok(&at_bytes));
    let over_bytes = "é".repeat(MAX_LABEL_BYTES / 2 + 1);
    assert!(!label_ok(&over_bytes));
    assert!(!label_ok(&format!("{}\u{1f}", at_chars)));
    assert!(!label_ok("a\u{7f}"));
    assert!(!label_ok("a\u{0}"));
    assert!(label_ok("a\u{20}"));
    assert!(!label_ok(""));
    // And the same values through the public constructor, so the adapter is
    // pinned too, not only the kernel.
    for accepted in [&at_chars, &at_bytes] {
        assert!(super::config::SecretspecLabel::parse(accepted).is_ok());
    }
    for refused in [&over_chars, &over_bytes] {
        assert!(super::config::SecretspecLabel::parse(refused).is_err());
    }
}

/// `super::config::SecretspecLabel::parse` acceptance, as one call.
fn label_ok(raw: &str) -> bool {
    super::config::SecretspecLabel::parse(raw).is_ok()
}

#[test]
fn poll_edges_and_zero_writes_are_bounded() {
    // A HUP with a frame still buffered delivers the frame: the server writes and
    // closes immediately, so `poll` reports HUP on an otherwise "ready" socket.
    let mut session = scripted(vec![response(1)]);
    assert!(call_empty(&mut session).is_ok());

    // A write that cannot make progress is bounded by the deadline, not by an
    // endless retry: fill a pipe whose reader never reads, then ask for
    // writability. The frame limit caps a single frame well below a filled
    // pipe, so the wait itself is driven here.
    let (held_reader, writer) = std::io::pipe().expect("pipe");
    let fd = std::os::fd::AsRawFd::as_raw_fd(&writer);
    assert!(super::session::set_nonblocking_for_test(fd));
    let filler = vec![b'x'; 4096];
    loop {
        use std::io::Write as _;
        let mut sink = &writer;
        if sink.write(&filler).is_err() {
            break;
        }
    }
    let deadline = Instant::now() + Duration::from_millis(100);
    let started = Instant::now();
    assert!(
        !super::session::wait_writable_for_test(fd, deadline),
        "a full pipe must report no progress, bounded by the deadline"
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    drop(held_reader);

    // An unusable descriptor aborts the start rather than leaving a blocking fd.
    assert!(super::session::unusable_descriptor_is_refused());
}

// ---------------------------------------------------------------------------
// X1–X10 — the process edge, with real children
// ---------------------------------------------------------------------------

/// A path as text for a fixture script. Not `display()`: a test fixture's path
/// is a temp path, and `one_line`'s baseline counts every `.display()` site in
/// the crate, test code included.
fn text(path: &Path) -> String {
    path.to_str().expect("a UTF-8 temp path").to_owned()
}

/// A `/bin/sh` script fixture, mode 0755, in its own temporary directory.
fn script(body: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("secretspec-fixture");
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write the fixture");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    (dir, path)
}

/// The default table with a different executable.
fn key_at(executable: &Path, dir: &Path) -> SessionKey {
    let mut table = serde_json::Map::new();
    table.insert("executable".into(), executable.to_string_lossy().into());
    table.insert(
        "manifest".into(),
        dir.join("secretspec.toml").to_string_lossy().into(),
    );
    table.insert("profile".into(), "default".into());
    parse_table(
        &table,
        &GuestEnvName::parse("DEFAULT_KEY").expect("valid guest name"),
    )
    .expect("the fixture table validates")
    .session()
    .clone()
}

fn pid_alive(pid: i32) -> bool {
    // SAFETY: signal 0 performs only the existence check; no memory is touched.
    !(unsafe { libc::kill(pid, 0) } == -1
        && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH))
}

fn read_pid(path: &Path) -> i32 {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .trim()
        .parse()
        .unwrap_or(0)
}

#[test]
fn a_missing_or_non_executable_path_is_executable_missing() {
    let dir = tempfile::tempdir().unwrap();
    // Absent.
    assert_eq!(
        Session::start(
            &key_at(&dir.path().join("absent"), dir.path()),
            &Bounds::short()
        )
        .err()
        .expect("absent"),
        SecretspecFailure::ExecutableMissing
    );
    // A directory.
    assert_eq!(
        Session::start(&key_at(dir.path(), dir.path()), &Bounds::short())
            .err()
            .expect("directory"),
        SecretspecFailure::ExecutableMissing
    );
    // A regular file with no execute bit.
    let plain = dir.path().join("plain");
    std::fs::write(&plain, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        Session::start(&key_at(&plain, dir.path()), &Bounds::short())
            .err()
            .expect("not executable"),
        SecretspecFailure::ExecutableMissing
    );
}

#[test]
fn a_group_or_world_writable_executable_is_untrusted() {
    let dir = tempfile::tempdir().unwrap();
    for mode in [0o775u32, 0o777] {
        let path = dir.path().join(format!("writable-{mode:o}"));
        std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(
            Session::start(&key_at(&path, dir.path()), &Bounds::short())
                .err()
                .expect("writable"),
            SecretspecFailure::ExecutableUntrusted,
            "{mode:o}"
        );
    }
}

/// The executable predicate is pure over `(is_file, mode)`: **ownership is not
/// an input**, which is the decision B6 records. A foreign-owned, non-writable
/// target is therefore accepted, and the same mode with a group write bit is
/// refused — no root, no `chmod`/`chown` of a real installation.
#[test]
fn a_foreign_owned_but_non_writable_executable_is_accepted() {
    assert_eq!(super::session::executable_trust_for_test(true, 0o555), None);
    assert_eq!(
        super::session::executable_trust_for_test(true, 0o775),
        Some(SecretspecFailure::ExecutableUntrusted)
    );
    assert_eq!(
        super::session::executable_trust_for_test(false, 0o555),
        Some(SecretspecFailure::ExecutableMissing)
    );
    assert_eq!(
        super::session::executable_trust_for_test(true, 0o644),
        Some(SecretspecFailure::ExecutableMissing)
    );
    // The Homebrew layout the plan measured: a symlink followed to a mode-0555
    // target under a group-writable parent. Only the target's own bits are read.
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("Cellar-bin");
    std::fs::write(&target, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o555)).unwrap();
    let link = dir.path().join("bin-link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o775)).unwrap();
    let key = key_at(&link, dir.path());
    // It reaches the spawn (and fails there as a handshake, not a trust check):
    // the trust half accepted the symlinked, foreign-mode target.
    assert!(matches!(
        Session::start(&key, &Bounds::short()),
        Err(SecretspecFailure::StartupFailed)
    ));
}

#[test]
fn an_executable_that_exits_before_the_handshake_is_startup_failed() {
    let (dir, path) = script("exit 2");
    assert_eq!(
        Session::start(&key_at(&path, dir.path()), &Bounds::short())
            .err()
            .expect("exit 2"),
        SecretspecFailure::StartupFailed
    );
    // The same shape with a clean exit: stdout closes before any frame.
    let (dir2, path2) = script("exec cat >/dev/null");
    assert_eq!(
        Session::start(&key_at(&path2, dir2.path()), &Bounds::short())
            .err()
            .expect("closed stdout"),
        SecretspecFailure::StartupFailed
    );
}

#[test]
fn a_hanging_handshake_is_bounded_and_kills_the_process_group() {
    // The budget must outlast the fixture being *scheduled* — spawning `/bin/sh`,
    // forking `sleep`, writing the pid file. The bound is not the property under
    // test here (the production budget is `STARTUP_BUDGET`); "bounded, and the
    // group dies" is.
    let pidfile_dir = tempfile::tempdir().expect("tempdir");
    let pidfile = pidfile_dir.path().join("helper.pid");
    let (dir, path) = script(&format!("sleep 30 &\necho $! > {}\nwait", text(&pidfile)));
    let started = Instant::now();
    let failure = Session::start(
        &key_at(&path, dir.path()),
        &Bounds {
            startup: Duration::from_millis(2_000),
            ..Bounds::short()
        },
    )
    .err()
    .expect("a hanging handshake must time out");
    assert_eq!(failure, SecretspecFailure::HandshakeTimedOut);
    assert!(started.elapsed() < Duration::from_secs(5));
    let helper = read_pid(&pidfile);
    assert!(helper > 0, "the fixture wrote its helper pid");
    // The group signal reaches the helper the leader started, which is the
    // whole point of group teardown.
    let deadline = Instant::now() + Duration::from_secs(2);
    while pid_alive(helper) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!pid_alive(helper), "the helper outlived its group");
}

#[test]
fn the_child_gets_exact_argv_root_cwd_and_no_secretspec_variables() {
    let dir = tempfile::tempdir().unwrap();
    let observed = dir.path().join("observed");
    let path = dir.path().join("fixture");
    std::fs::write(
        &path,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" > {0}\npwd > {0}.pwd\n\
             env | sed -n 's/=.*//' | grep '^SECRETSPEC_' > {0}.env || true\nexit 1\n",
            text(&observed)
        ),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let observed = dir.path().join("observed");
    let mut guard = crate::test_env::guard();
    guard.set_var("SECRETSPEC_FILE", "/tmp/decoy.toml");
    guard.set_var("SECRETSPEC_PROVIDER", "env");
    let failure = Session::start(&key_at(&path, dir.path()), &Bounds::short())
        .err()
        .expect("the fixture exits before a handshake");
    assert_eq!(failure, SecretspecFailure::StartupFailed);
    assert_eq!(
        std::fs::read_to_string(&observed).unwrap().trim(),
        "serve --read-only"
    );
    assert_eq!(
        std::fs::read_to_string(format!("{}.pwd", text(&observed)))
            .unwrap()
            .trim(),
        "/"
    );
    assert_eq!(
        std::fs::read_to_string(format!("{}.env", text(&observed)))
            .unwrap()
            .trim(),
        "",
        "no SECRETSPEC_* variable may reach the child"
    );
}

#[test]
fn a_canary_on_the_child_stderr_reaches_no_agent_vm_output() {
    // The session discards its child's stderr, and this asserts the canary that
    // child wrote reaches neither agent-vm's stderr nor its failure message.
    //
    // The observation runs in a **re-executed** copy of this test binary rather
    // than by `dup2`-ing this process's stderr: a process-global redirect in a
    // parallel test binary also captures every other test's output, follows a
    // predictable path in the shared temp dir, and — because a panic before the
    // restore leaves it installed — outlives the test that started it.
    if std::env::var_os(STDERR_CHILD_ENV).is_some() {
        let (dir, path) = script("echo 'sk-CANARY-202-stderr' >&2\nexit 1");
        let failure = Session::start(&key_at(&path, dir.path()), &Bounds::short())
            .err()
            .expect("the fixture exits before a handshake");
        assert_eq!(failure, SecretspecFailure::StartupFailed);
        assert!(
            !failure.message().contains("sk-CANARY"),
            "the failure message carried the child's payload"
        );
        println!("startup_failed");
        return;
    }
    let output = std::process::Command::new(
        std::env::current_exe().expect("the running test binary's path"),
    )
    .args([
        "credential_secretspec::tests::a_canary_on_the_child_stderr_reaches_no_agent_vm_output",
        "--exact",
        "--nocapture",
        "--test-threads=1",
    ])
    .env(STDERR_CHILD_ENV, "1")
    .output()
    .expect("re-exec this test binary");
    assert!(
        output.status.success(),
        "the child arm did not reach the startup failure"
    );
    let seen = String::from_utf8_lossy(&output.stdout);
    assert!(
        seen.contains("startup_failed"),
        "the child arm must reach the startup failure it asserts"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("sk-CANARY-202-stderr"),
        "child stderr reached agent-vm's stderr"
    );
}

/// Marks the re-executed arm of
/// [`a_canary_on_the_child_stderr_reaches_no_agent_vm_output`].
const STDERR_CHILD_ENV: &str = "AGENT_VM_202_STDERR_CHILD";

#[test]
fn an_unrelated_child_cannot_hold_the_secretspec_pipes_open() {
    let dir = tempfile::tempdir().unwrap();
    // (a) The write end: the fixture reports EOF, which can only happen when no
    // copy of agent-vm's write end leaked into the unrelated child that is still
    // alive at that moment.
    let eof = dir.path().join("eof");
    let (fixture_dir, fixture) = script(&format!(
        "cat >/dev/null\necho eof > {}\nsleep 5",
        text(&eof)
    ));
    let mut session = Session::spawn(&key_at(&fixture, fixture_dir.path())).expect("spawned");
    let unrelated = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("an unrelated child");
    drop(session.drop_writer_for_test());
    let deadline = Instant::now() + Duration::from_secs(5);
    while !eof.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(eof.exists(), "the fixture never saw EOF");
    assert!(pid_alive(unrelated.id() as i32));

    // (b) The read end: the fixture's next write fails with EPIPE while the same
    // unrelated child is alive, which is impossible if it held a copy of the
    // read end.
    let epipe = dir.path().join("epipe");
    // SIGPIPE ignored, so a write to a closed reader is an error the script can
    // observe instead of a signal that kills it.
    let (reader_dir, writer) = script(&format!(
        "trap '' PIPE\nfor _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25; do\n  \
           if ! echo x 2>/dev/null; then\n    echo epipe > {}\n    exit 0\n  fi\n  sleep 0.05\ndone\nexit 0",
        text(&epipe)
    ));
    let mut session = Session::spawn(&key_at(&writer, reader_dir.path())).expect("spawned");
    drop(session.drop_reader_for_test());
    let deadline = Instant::now() + Duration::from_secs(5);
    while !epipe.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(epipe.exists(), "the fixture never saw EPIPE");
    assert!(pid_alive(unrelated.id() as i32));
    let mut unrelated = unrelated;
    let _ = unrelated.kill();
    let _ = unrelated.wait();
}

#[test]
fn the_group_is_killed_when_the_leader_exited_but_a_helper_holds_stdout() {
    // The leader writes a partial frame and exits; the helper inherits stdout, so
    // there is no EOF and the read must time out rather than read a frame.
    let pidfile_dir = tempfile::tempdir().expect("tempdir");
    let pidfile = pidfile_dir.path().join("helper.pid");
    let (dir, path) = script(&format!(
        "sleep 30 &\necho $! > {}\nprintf '{{\"jsonrpc\":\"2.0\",\"id\":1,\"resul'\nexit 0",
        text(&pidfile)
    ));
    let failure = Session::start(
        &key_at(&path, dir.path()),
        &Bounds {
            startup: Duration::from_millis(400),
            ..Bounds::short()
        },
    )
    .err()
    .expect("the handshake must time out");
    assert_eq!(failure, SecretspecFailure::HandshakeTimedOut);
    let helper = read_pid(&pidfile);
    assert!(helper > 0);
    let deadline = Instant::now() + Duration::from_secs(2);
    while pid_alive(helper) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!pid_alive(helper), "the helper outlived its group");
}

#[test]
fn a_normal_shutdown_kills_a_surviving_helper() {
    // A shell that performs a minimal but real handshake: it answers initialize,
    // a get, and shutdown, while a helper it started holds stdout. The pidfile
    // is this test's own, because all three AC11 cases run in one process and a
    // shared path lets one test read a pid another already killed.
    let pidfile_dir = tempfile::tempdir().expect("tempdir");
    let pidfile = pidfile_dir.path().join("helper.pid");
    let (dir, path) = script(&format!(
        r#"sleep 30 &
echo $! > {pidfile}
read init
id=$(printf '%s' "$init" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
printf '{{"jsonrpc":"2.0","id":%s,"result":{{"protocol":"secretspec.resolver","version":1,"methods":["resolver.get","resolver.release"],"limits":{{"max_frame_bytes":16384,"max_in_flight":1}}}}}}\n' "$id"
read get
id=$(printf '%s' "$get" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
printf '{{"jsonrpc":"2.0","id":%s,"result":{{"status":"missing"}}}}\n' "$id"
read stop
id=$(printf '%s' "$stop" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
printf '{{"jsonrpc":"2.0","id":%s,"result":{{}}}}\n' "$id"
exit 0"#,
        pidfile = text(&pidfile)
    ));
    let mut session =
        Session::start(&key_at(&path, dir.path()), &Bounds::short()).expect("the shell handshakes");
    assert!(matches!(resolved(get(&mut session)).0, Resolved::Missing));
    session.shutdown();
    let helper = read_pid(&pidfile);
    assert!(helper > 0);
    let deadline = Instant::now() + Duration::from_secs(2);
    while pid_alive(helper) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !pid_alive(helper),
        "a helper survived an answered rpc.shutdown"
    );
}

// ---------------------------------------------------------------------------
// S1–S8 — the pool and the adapter, at the `CredentialSource` boundary
// ---------------------------------------------------------------------------

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use super::SecretspecSource;
use crate::credential_resolver::CredentialSource;

/// A starter that serves each child from the fake endpoint, counts starts and
/// records **which key** each start was for.
///
/// The key is what the handshake pins, so a starter that answered every child
/// with one fixed key would make the pool's keying unobservable: every
/// `rpc.initialize` would carry the same profile, scope and reason and a pool
/// that ignored the key would look identical to one that honoured it.
struct StartLog {
    starts: AtomicUsize,
    transcripts: StdMutex<Vec<(SessionKey, PathBuf)>>,
    dir: tempfile::TempDir,
}

impl StartLog {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            starts: AtomicUsize::new(0),
            transcripts: StdMutex::new(Vec::new()),
            dir: tempfile::tempdir().expect("tempdir"),
        })
    }

    fn starts(&self) -> usize {
        self.starts.load(Ordering::SeqCst)
    }

    /// One entry per start, in start order: the key it was started for and the
    /// transcript that child produced.
    fn transcripts(&self) -> Vec<(SessionKey, PathBuf)> {
        self.transcripts.lock().unwrap().clone()
    }

    /// Every request the fake saw, across every child, in start order.
    fn requests(&self, method: &str) -> Vec<Value> {
        self.transcripts()
            .iter()
            .flat_map(|(_, path)| requests_in(path, method))
            .collect()
    }

    /// The starter closure. `scenario` is written once per start.
    fn starter(self: &Arc<Self>, scenario: Value) -> super::pool::TestStarter {
        let log = Arc::clone(self);
        Box::new(move |key: &SessionKey, _bounds: &super::session::Bounds| {
            let index = log.starts.fetch_add(1, Ordering::SeqCst);
            let transcript = log.dir.path().join(format!("transcript-{index}.jsonl"));
            log.transcripts
                .lock()
                .unwrap()
                .push((key.clone(), transcript.clone()));
            let mut object = scenario.as_object().cloned().unwrap_or_default();
            object
                .entry("transcript")
                .or_insert_with(|| json!(transcript));
            let scenario: Scenario =
                serde_json::from_value(Value::Object(object)).expect("a scenario");
            let (server_input, client_output) = std::io::pipe().expect("pipe");
            let (client_input, server_output) = std::io::pipe().expect("pipe");
            std::thread::spawn(move || {
                let mut transcript = Transcript::open(Some(&transcript));
                fake::serve(
                    &scenario,
                    BufReader::new(server_input),
                    server_output,
                    &mut transcript,
                )
            });
            let mut session =
                Session::over(OwnedFd::from(client_output), OwnedFd::from(client_input));
            session
                .handshake(key, Duration::from_secs(10))
                .expect("the fixture handshake is accepted");
            Ok(session)
        })
    }
}

/// The `method` requests one child's transcript recorded, in order.
fn requests_in(transcript: &Path, method: &str) -> Vec<Value> {
    std::fs::read_to_string(transcript)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|event| event["event"] == "request" && event["method"] == method)
        .map(|event| event["frame"].clone())
        .collect()
}

/// One requested, authorized `source: secretspec` service.
fn secretspec_authorizations(
    service: &str,
    secret: &str,
) -> (tempfile::TempDir, crate::credential_yaml::AuthorizationSet) {
    secretspec_authorizations_at(
        service,
        secret,
        Path::new("/opt/secretspec"),
        Path::new("/tmp/secretspec.toml"),
    )
}

/// The same, pinned to a named executable and manifest, so a test can point the
/// session key at a real fixture child.
fn secretspec_authorizations_at(
    service: &str,
    secret: &str,
    executable: &Path,
    manifest: &Path,
) -> (tempfile::TempDir, crate::credential_yaml::AuthorizationSet) {
    use std::os::unix::fs::PermissionsExt as _;
    let home = tempfile::tempdir().expect("tempdir");
    let dir = home.path().join(crate::config::USER_CONFIG_DIR_RELATIVE);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.join(crate::credential_yaml::CREDENTIALS_FILE_NAME);
    std::fs::write(
        &path,
        format!(
            "credentials:\n  - service: {service}\n    source: secretspec\n    apiKey:\n      \
             name: {secret}\n      sentinelEnv: true\n      inject: [{{domain: \
             api.example.com, scheme: bearer}}]\n    secretspec:\n      executable: \
             {}\n      manifest: {}\n      profile: default\n",
            text(executable),
            text(manifest)
        ),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let set = crate::credential_yaml::load(home.path()).expect("the fixture loads");
    (home, set)
}

fn requested(list: &[&str]) -> std::collections::BTreeSet<ServiceName> {
    list.iter()
        .map(|raw| ServiceName::parse(raw).expect("a service name"))
        .collect()
}

/// Two requested, authorized SecretSpec services that share one session key
/// (same executable, manifest, profile) and one that does not.
fn two_secret_services() -> (tempfile::TempDir, crate::credential_yaml::AuthorizationSet) {
    use std::os::unix::fs::PermissionsExt as _;
    let home = tempfile::tempdir().expect("tempdir");
    let dir = home.path().join(crate::config::USER_CONFIG_DIR_RELATIVE);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.join(crate::credential_yaml::CREDENTIALS_FILE_NAME);
    std::fs::write(
        &path,
        "credentials:\n  - service: alpha\n    source: secretspec\n    apiKey:\n      name: \
         ALPHA_KEY\n      inject: [{domain: a.example, scheme: bearer}]\n    secretspec:\n      \
         executable: /opt/secretspec\n      manifest: /tmp/secretspec.toml\n      profile: \
         default\n  - service: beta\n    source: secretspec\n    apiKey:\n      name: BETA_KEY\n      \
         inject: [{domain: b.example, scheme: bearer}]\n    secretspec:\n      executable: \
         /opt/secretspec\n      manifest: /tmp/secretspec.toml\n      profile: default\n",
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let set = crate::credential_yaml::load(home.path()).expect("the fixture loads");
    (home, set)
}

#[test]
fn sessions_start_lazily_and_are_shared_per_session_key() {
    let (_home, set) = two_secret_services();
    let log = StartLog::new();
    let source = SecretspecSource::select_with_starter(
        &requested(&["alpha", "beta"]),
        &set,
        super::session::Bounds::test_full(),
        log.starter(json!({
            "secrets": {"ALPHA_KEY": {"value": "sk-a"}, "BETA_KEY": {"value": "sk-b"}}
        })),
    )
    .expect("a SecretSpec source");
    assert!(source.selects(&ServiceName::parse("alpha").unwrap()));
    // Lazy: constructing the source spawns nothing.
    assert_eq!(log.starts(), 0);
    // Two services, one session key: one child, two reads.
    assert!(matches!(
        source.resolve(&ServiceName::parse("alpha").unwrap()),
        Resolved::Value(_)
    ));
    assert!(matches!(
        source.resolve(&ServiceName::parse("beta").unwrap()),
        Resolved::Value(_)
    ));
    assert_eq!(log.starts(), 1, "one child per session key");
    assert_eq!(log.requests("rpc.initialize").len(), 1);
    assert_eq!(log.requests("resolver.get").len(), 2);
    // An unrequested authorization spawns nothing: `gamma` is not in the set at
    // all, so no source is built for it.
    assert!(
        SecretspecSource::select_with(
            &requested(&["gamma"]),
            &set,
            super::session::Bounds::short()
        )
        .is_none()
    );
    assert_eq!(log.starts(), 1);
    // A different session key (another profile) is a second child.
    let (_other_home, other) = secretspec_authorizations("gamma", "GAMMA_KEY");
    let second = SecretspecSource::select_with_starter(
        &requested(&["gamma"]),
        &other,
        super::session::Bounds::test_full(),
        log.starter(json!({"secrets": {"GAMMA_KEY": {"value": "sk-g"}}})),
    )
    .expect("a SecretSpec source");
    assert!(matches!(
        second.resolve(&ServiceName::parse("gamma").unwrap()),
        Resolved::Value(_)
    ));
    assert_eq!(log.starts(), 2);
}

/// Four services in **one** `credentials.yaml`, one per distinct session key:
/// `beta` differs from `alpha` only in profile, `gamma` only in scope and
/// `delta` only in reason. Same executable and manifest throughout, so the key's
/// other fields cannot explain a difference.
fn four_distinct_session_keys() -> (tempfile::TempDir, crate::credential_yaml::AuthorizationSet) {
    use std::os::unix::fs::PermissionsExt as _;
    let home = tempfile::tempdir().expect("tempdir");
    let dir = home.path().join(crate::config::USER_CONFIG_DIR_RELATIVE);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.join(crate::credential_yaml::CREDENTIALS_FILE_NAME);
    std::fs::write(
        &path,
        "credentials:\n  - service: alpha\n    source: secretspec\n    apiKey:\n      name: \
         ALPHA_KEY\n      inject: [{domain: a.example, scheme: bearer}]\n    secretspec:\n      \
         executable: /opt/secretspec\n      manifest: /tmp/secretspec.toml\n      profile: \
         default\n  - service: beta\n    source: secretspec\n    apiKey:\n      name: BETA_KEY\n      \
         inject: [{domain: b.example, scheme: bearer}]\n    secretspec:\n      executable: \
         /opt/secretspec\n      manifest: /tmp/secretspec.toml\n      profile: staging\n  - \
         service: gamma\n    source: secretspec\n    apiKey:\n      name: GAMMA_KEY\n      inject: \
         [{domain: c.example, scheme: bearer}]\n    secretspec:\n      executable: \
         /opt/secretspec\n      manifest: /tmp/secretspec.toml\n      profile: default\n      \
         scope: other\n  - service: delta\n    source: secretspec\n    apiKey:\n      name: \
         DELTA_KEY\n      inject: [{domain: d.example, scheme: bearer}]\n    secretspec:\n      \
         executable: /opt/secretspec\n      manifest: /tmp/secretspec.toml\n      profile: \
         default\n      reason: other reason\n",
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let set = crate::credential_yaml::load(home.path()).expect("the fixture loads");
    (home, set)
}

/// R5's "one session per session key", inside **one** pool.
///
/// `sessions_start_lazily_and_are_shared_per_session_key` proves the *shared*
/// half with one key and the *distinct* half with a second `SecretspecSource`,
/// which is a second pool — so nothing put two keys in one pool. Here four
/// services differ only in profile, scope and reason, and each one's
/// `resolver.get` must land in the child whose `rpc.initialize` carries *that*
/// service's three labels. A pool that keyed on anything less would answer one
/// service from another session's child: cross-session credential confusion.
#[test]
fn one_pool_starts_one_session_per_distinct_session_key() {
    let (_home, set) = four_distinct_session_keys();
    let log = StartLog::new();
    let source = SecretspecSource::select_with_starter(
        &requested(&["alpha", "beta", "gamma", "delta"]),
        &set,
        super::session::Bounds::test_full(),
        log.starter(json!({"secrets": {
            "ALPHA_KEY": {"value": "sk-a"},
            "BETA_KEY": {"value": "sk-b"},
            "GAMMA_KEY": {"value": "sk-g"},
            "DELTA_KEY": {"value": "sk-d"}
        }})),
    )
    .expect("a SecretSpec source");
    // (service, secret name, the labels that distinguish its session key).
    let expected = [
        ("alpha", "ALPHA_KEY", "default", Value::Null, Value::Null),
        ("beta", "BETA_KEY", "staging", Value::Null, Value::Null),
        ("gamma", "GAMMA_KEY", "default", json!("other"), Value::Null),
        (
            "delta",
            "DELTA_KEY",
            "default",
            Value::Null,
            json!("other reason"),
        ),
    ];
    for (service, _, _, _, _) in &expected {
        assert!(
            matches!(
                source.resolve(&ServiceName::parse(service).unwrap()),
                Resolved::Value(_)
            ),
            "{service} must read its own value"
        );
    }
    assert_eq!(
        log.starts(),
        expected.len(),
        "one child per distinct session key"
    );
    let transcripts = log.transcripts();
    assert_eq!(transcripts.len(), expected.len());
    // Each child handshook with the key it was started for: the starter used to
    // answer every child with one fixed key, which made this unobservable.
    for (key, transcript) in &transcripts {
        let initialize = requests_in(transcript, "rpc.initialize");
        assert_eq!(initialize.len(), 1, "one initialize per child");
        let application = &initialize[0]["params"]["application"];
        assert_eq!(application["profile"], json!(key.profile().as_str()));
        assert_eq!(
            application["scope"],
            json!(key.scope().map(|scope| scope.as_str()))
        );
        assert_eq!(
            application["reason"],
            json!(key.reason().map(|reason| reason.as_str()))
        );
    }
    // Exactly one initialize per (profile, scope, reason) combination.
    let mut combinations: Vec<String> = transcripts
        .iter()
        .map(|(_, transcript)| {
            let application =
                &requests_in(transcript, "rpc.initialize")[0]["params"]["application"];
            format!(
                "{}/{}/{}",
                application["profile"], application["scope"], application["reason"]
            )
        })
        .collect();
    combinations.sort();
    combinations.dedup();
    assert_eq!(combinations.len(), expected.len());
    // And each service's get landed in the child that pinned its own labels.
    for (service, secret, profile, scope, reason) in &expected {
        let owner = transcripts
            .iter()
            .find(|(_, transcript)| {
                let application =
                    &requests_in(transcript, "rpc.initialize")[0]["params"]["application"];
                application["profile"] == json!(profile)
                    && application["scope"] == *scope
                    && application["reason"] == *reason
            })
            .unwrap_or_else(|| panic!("no child pinned {service}'s session key"));
        let gets = requests_in(&owner.1, "resolver.get");
        assert_eq!(gets.len(), 1, "{service} must read exactly once");
        assert_eq!(
            gets[0]["params"]["name"],
            json!(secret),
            "{service} was read from another session's child"
        );
    }
    // A second read of `alpha` is served by its existing child.
    assert!(matches!(
        source.resolve(&ServiceName::parse("alpha").unwrap()),
        Resolved::Value(_)
    ));
    assert_eq!(
        log.starts(),
        expected.len(),
        "a second read starts nothing new"
    );
}

#[test]
fn a_failed_start_is_sticky_for_the_launch() {
    let (_home, set) = secretspec_authorizations("alpha", "ALPHA_KEY");
    let starts = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&starts);
    let source = SecretspecSource::select_with_starter(
        &requested(&["alpha"]),
        &set,
        super::session::Bounds::test_full(),
        Box::new(move |_key, _bounds| {
            counter.fetch_add(1, Ordering::SeqCst);
            Err(SecretspecFailure::ExecutableMissing)
        }),
    )
    .expect("a SecretSpec source");
    let service = ServiceName::parse("alpha").unwrap();
    for _ in 0..2 {
        assert!(matches!(
            source.resolve(&service),
            Resolved::SecretspecUnavailable(SecretspecFailure::ExecutableMissing)
        ));
    }
    assert_eq!(
        starts.load(Ordering::SeqCst),
        1,
        "one start attempt per launch"
    );
}

#[test]
fn a_request_level_failure_kills_and_the_next_read_starts_fresh() {
    let (_home, set) = secretspec_authorizations("alpha", "ALPHA_KEY");
    let log = StartLog::new();
    // The first child never answers; the second serves a value.
    let source = SecretspecSource::select_with(
        &requested(&["alpha"]),
        &set,
        super::session::Bounds::test_full(),
    );
    // A pool whose starter counts and whose first child hangs.
    drop(source);
    let starts = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&starts);
    let log2 = Arc::clone(&log);
    let source = SecretspecSource::select_with_starter(
        &requested(&["alpha"]),
        &set,
        super::session::Bounds::test_full(),
        Box::new(move |key: &SessionKey, _bounds| {
            let index = counter.fetch_add(1, Ordering::SeqCst);
            let scenario = if index == 0 {
                json!({"secrets": {"ALPHA_KEY": "hang"}})
            } else {
                json!({"secrets": {"ALPHA_KEY": {"value": "sk-second"}}})
            };
            log2.starter(scenario)(key, &super::session::Bounds::short())
        }),
    )
    .expect("a SecretSpec source");
    let service = ServiceName::parse("alpha").unwrap();
    assert!(matches!(
        source.resolve(&service),
        Resolved::SecretspecUnavailable(SecretspecFailure::Unresponsive)
    ));
    assert!(matches!(source.resolve(&service), Resolved::Value(_)));
    assert_eq!(starts.load(Ordering::SeqCst), 2);
}

#[test]
fn a_read_after_close_fails_without_spawning_and_close_is_idempotent() {
    let (_home, set) = secretspec_authorizations("alpha", "ALPHA_KEY");
    let log = StartLog::new();
    let source = SecretspecSource::select_with_starter(
        &requested(&["alpha"]),
        &set,
        super::session::Bounds::test_full(),
        log.starter(json!({"secrets": {"ALPHA_KEY": {"value": "sk-a"}}})),
    )
    .expect("a SecretSpec source");
    let service = ServiceName::parse("alpha").unwrap();
    assert!(matches!(source.resolve(&service), Resolved::Value(_)));
    let before = log.starts();
    // Through the launch's guard, which is what production closes.
    let guard = crate::credential_resolver::CredentialSessions::for_test(Some(Arc::new(
        SecretspecSource::select_with_starter(
            &requested(&["alpha"]),
            &set,
            super::session::Bounds::test_full(),
            log.starter(json!({"secrets": {"ALPHA_KEY": {"value": "sk-a"}}})),
        )
        .expect("a SecretSpec source"),
    )));
    guard.close();
    source.close();
    source.close();
    assert!(matches!(
        source.resolve(&service),
        Resolved::SecretspecUnavailable(SecretspecFailure::SessionClosed)
    ));
    assert_eq!(log.starts(), before, "a read after close spawns nothing");
}

#[test]
fn values_are_not_cached_between_reads() {
    let (_home, set) = secretspec_authorizations("alpha", "ALPHA_KEY");
    let log = StartLog::new();
    let source = SecretspecSource::select_with_starter(
        &requested(&["alpha"]),
        &set,
        super::session::Bounds::test_full(),
        log.starter(json!({"secrets": {"ALPHA_KEY": {"values": ["sk-first", "sk-second"]}}})),
    )
    .expect("a SecretSpec source");
    let service = ServiceName::parse("alpha").unwrap();
    for expected in ["sk-first", "sk-second"] {
        match source.resolve(&service) {
            Resolved::Value(value) => assert!(
                value.expose_for_test() == expected,
                "a read saw a different value than the fake served"
            ),
            other => panic!("expected a value, got {other:?}"),
        }
    }
    assert_eq!(log.starts(), 1);
}

#[test]
fn an_answer_accepted_then_eof_is_session_lost_and_is_not_retried() {
    let (_home, set) = secretspec_authorizations("alpha", "ALPHA_KEY");
    let log = StartLog::new();
    let source = SecretspecSource::select_with_starter(
        &requested(&["alpha"]),
        &set,
        super::session::Bounds::test_full(),
        log.starter(json!({
            "secrets": {"ALPHA_KEY": "die"},
            "exit_after_gets": 0
        })),
    )
    .expect("a SecretSpec source");
    let service = ServiceName::parse("alpha").unwrap();
    assert!(matches!(
        source.resolve(&service),
        Resolved::SecretspecUnavailable(SecretspecFailure::SessionLost)
    ));
    assert_eq!(
        log.starts(),
        1,
        "a write that was accepted is never re-sent"
    );
}

/// A failed *refusal* write is a session lost mid-request, not a retryable one.
///
/// The fake answers the get with a `client.prompt` and then closes both ends, so
/// the failing write is the client's refusal of that prompt. Before the fix the
/// refusal's `EPIPE` was reported as [`CallError::WriteClosed`], the pool re-sent
/// the get to a new child, and one resolve produced two `resolver.get`s.
#[test]
fn a_failed_prompt_refusal_is_session_lost_and_not_retried() {
    let (_home, set) = secretspec_authorizations("alpha", "ALPHA_KEY");
    let log = StartLog::new();
    let source = SecretspecSource::select_with_starter(
        &requested(&["alpha"]),
        &set,
        super::session::Bounds::test_full(),
        log.starter(json!({"secrets": {"ALPHA_KEY": "prompt_then_close_input"}})),
    )
    .expect("a SecretSpec source");
    let service = ServiceName::parse("alpha").unwrap();
    assert!(matches!(
        source.resolve(&service),
        Resolved::SecretspecUnavailable(SecretspecFailure::SessionLost)
    ));
    assert_eq!(
        log.starts(),
        1,
        "the request was accepted, so the read is not re-sent"
    );
    assert_eq!(log.requests("resolver.get").len(), 1);
    // §1.4: a session that fails during a request is killed and the *next* read
    // starts a fresh one. The fix must not have made the child sticky.
    assert!(matches!(
        source.resolve(&service),
        Resolved::SecretspecUnavailable(SecretspecFailure::SessionLost)
    ));
    assert_eq!(log.starts(), 2, "the next read starts a fresh child");
    assert_eq!(log.requests("resolver.get").len(), 2);
}

#[test]
fn a_leader_that_exited_idle_is_restarted_once() {
    let (_home, set) = secretspec_authorizations("alpha", "ALPHA_KEY");
    let log = StartLog::new();
    // One answer, then the child exits: the second read must start a new child
    // rather than read a dead one.
    //
    // What this drives is `EPIPE` on the first write of the **request** frame
    // (`DeadBeforeRequest`), not an observed exit: the pipe-pair starter has no
    // pid, so `leader_exited()` is never true here. That makes it the guard that
    // the prompt-refusal fix did not over-correct — a request that provably never
    // reached the server must still be retried, exactly once.
    // `a_failed_prompt_refusal_is_session_lost_and_not_retried` guards the other
    // side and `a_pool_restart_kills_the_old_groups_helper` covers the observed
    // exit through a real child.
    let source = SecretspecSource::select_with_starter(
        &requested(&["alpha"]),
        &set,
        super::session::Bounds::test_full(),
        log.starter(json!({
            "secrets": {"ALPHA_KEY": {"value": "sk-a"}},
            "exit_after_gets": 1
        })),
    )
    .expect("a SecretSpec source");
    let service = ServiceName::parse("alpha").unwrap();
    assert!(matches!(source.resolve(&service), Resolved::Value(_)));
    // Let the fake finish exiting, which is what closes both ends of the pipe.
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        matches!(source.resolve(&service), Resolved::Value(_)),
        "the read after the idle death must be served by a fresh child"
    );
    assert_eq!(log.starts(), 2, "exactly one transparent restart");
    assert_eq!(log.requests("resolver.get").len(), 2);
}

// ---------------------------------------------------------------------------
// P11 — nothing renders a value
// ---------------------------------------------------------------------------

#[test]
fn nothing_renders_a_value() {
    let canary = "sk-CANARY-202-p11";
    let (_home, set) = secretspec_authorizations("alpha", "ALPHA_KEY");
    let log = StartLog::new();
    let source = SecretspecSource::select_with_starter(
        &requested(&["alpha"]),
        &set,
        super::session::Bounds::test_full(),
        log.starter(json!({"secrets": {"ALPHA_KEY": {"value": canary}}})),
    )
    .expect("a SecretSpec source");
    let service = ServiceName::parse("alpha").unwrap();
    let resolved_value = source.resolve(&service);
    assert!(matches!(resolved_value, Resolved::Value(_)));
    // Every renderable surface of the module and of the outcome.
    let rendered = format!(
        "{source:?} {resolved_value:?} {:?} {:?} {:?}",
        selection("ALPHA_KEY"),
        key(),
        SecretspecFailure::ProviderFailed
    );
    assert!(
        rendered.contains("alpha"),
        "the source must still name its service"
    );
    assert!(
        !rendered.contains(canary),
        "a value reached a rendered surface"
    );
    // And the fake's transcript is value-free by construction.
    for (_, path) in log.transcripts.lock().unwrap().iter() {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        assert!(
            !text.contains(canary),
            "a value reached a child's transcript"
        );
    }
}

// ---------------------------------------------------------------------------
// X9 — a leader that exits after phase 1 leaves no helper
// ---------------------------------------------------------------------------

#[test]
fn a_leader_that_exits_after_phase_one_leaves_no_helper() {
    // Phase 1 reads through a real child that leaves a helper behind and exits;
    // the phase-2 read restarts, and the old group's helper must be dead.
    let dir = tempfile::tempdir().unwrap();
    let pidfile = dir.path().join("helper.pid");
    let starts = dir.path().join("starts.log");
    let (_fixture_dir, fixture) = {
        let body = format!(
            r#"trap '' PIPE
sleep 30 &
echo $! > {pidfile}
echo start >> {starts}
read init
id=$(printf '%s' "$init" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
printf '{{"jsonrpc":"2.0","id":%s,"result":{{"protocol":"secretspec.resolver","version":1,"methods":["resolver.get","resolver.release"],"limits":{{"max_frame_bytes":16384,"max_in_flight":1}}}}}}\n' "$id"
read get
id=$(printf '%s' "$get" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
printf '{{"jsonrpc":"2.0","id":%s,"result":{{"status":"missing"}}}}\n' "$id"
exit 0"#,
            pidfile = text(&pidfile),
            starts = text(&starts)
        );
        script(&body)
    };
    let key = key_at(&fixture, dir.path());
    // Phase 1.
    let mut first = Session::start(&key, &super::session::Bounds::test_full()).expect("handshake");
    assert!(matches!(resolved(get(&mut first)).0, Resolved::Missing));
    let helper = read_pid(&pidfile);
    assert!(helper > 0, "the fixture started a helper");
    // Wait until the leader has exited (the fake exits after the one get) while
    // the helper stays in the group.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !first.leader_exited() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(pid_alive(helper), "the helper survives its leader");
    // Phase 2: a restarted child, after dropping the old slot — which is what
    // the pool does when it replaces a `Live` slot.
    drop(first);
    let mut second = Session::start(&key, &super::session::Bounds::test_full()).expect("handshake");
    assert!(matches!(resolved(get(&mut second)).0, Resolved::Missing));
    let deadline = Instant::now() + Duration::from_secs(2);
    while pid_alive(helper) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !pid_alive(helper),
        "the old group's helper outlived the restart"
    );
    second.shutdown();
    let starts = std::fs::read_to_string(&starts).unwrap_or_default();
    assert_eq!(starts.lines().count(), 2, "two children, one per phase");
}

/// Kills a fixture helper on drop, so a failing run leaks no `sleep 30`.
struct HelperGuard(libc::pid_t);

impl Drop for HelperGuard {
    fn drop(&mut self) {
        // SAFETY: a signal to a pid this test read from its own fixture; no
        // memory is touched.
        unsafe { libc::kill(self.0, libc::SIGKILL) };
    }
}

/// AC8/AC11 through the **pool**, not a hand-dropped `Session`.
///
/// `a_leader_that_exits_after_phase_one_leaves_no_helper` drops the session
/// itself, so it can only prove that `ChildGuard::drop` signals. The pool's own
/// replacement of a `Live` slot is the path production takes, and until here no
/// pool test reached it: the pipe-pair starter has `child: None`, so
/// `leader_exited()` was always false.
#[test]
fn a_pool_restart_kills_the_old_groups_helper() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pidfile = dir.path().join("helper.pid");
    let marker = dir.path().join("exited");
    // X9's fixture: a real child that leaves a helper in its group, answers one
    // get with `missing`, records that it is exiting, and exits.
    let (_fixture_dir, fixture) = script(&format!(
        r#"sleep 30 &
echo $! > {pidfile}
read init
id=$(printf '%s' "$init" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
printf '{{"jsonrpc":"2.0","id":%s,"result":{{"protocol":"secretspec.resolver","version":1,"methods":["resolver.get","resolver.release"],"limits":{{"max_frame_bytes":16384,"max_in_flight":1}}}}}}\n' "$id"
read get
id=$(printf '%s' "$get" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
printf '{{"jsonrpc":"2.0","id":%s,"result":{{"status":"missing"}}}}\n' "$id"
echo exiting >> {marker}
exit 0"#,
        pidfile = text(&pidfile),
        marker = text(&marker)
    ));
    let (_home, set) = secretspec_authorizations_at(
        "alpha",
        "ALPHA_KEY",
        &fixture,
        &dir.path().join("secretspec.toml"),
    );
    let starts = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&starts);
    let source = SecretspecSource::select_with_starter(
        &requested(&["alpha"]),
        &set,
        super::session::Bounds::test_full(),
        Box::new(move |key: &SessionKey, bounds: &super::session::Bounds| {
            counter.fetch_add(1, Ordering::SeqCst);
            // The real spawn: this is the only pool test with a real child, so
            // the group teardown under test is the production one.
            Session::start(key, bounds)
        }),
    )
    .expect("a SecretSpec source");
    let service = ServiceName::parse("alpha").unwrap();
    let key = source
        .session_for(&service)
        .expect("the fixture selects alpha")
        .0
        .clone();
    // Phase 1.
    assert!(matches!(source.resolve(&service), Resolved::Missing));
    let helper = read_pid(&pidfile);
    assert!(helper > 0, "the fixture started a helper");
    let _killed = HelperGuard(helper);
    assert!(pid_alive(helper), "the helper must outlive its leader");
    // The leader answered and exited. The pool must observe that without
    // reaping, which is the precondition of its restart.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !(marker.exists() && source.pool.leader_exited_for_test(&key))
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(marker.exists(), "the fixture's leader did not exit");
    assert!(
        source.pool.leader_exited_for_test(&key),
        "the pool never observed the leader's exit"
    );
    // Phase 2: the pool replaces the slot, and dropping the old session is what
    // signals the old group.
    assert!(matches!(source.resolve(&service), Resolved::Missing));
    assert_eq!(
        starts.load(Ordering::SeqCst),
        2,
        "an idle-exited leader is replaced once"
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    while pid_alive(helper) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !pid_alive(helper),
        "the old group's helper outlived the pool's restart"
    );
    // Phase 2's own child left a helper of its own; closing the pool must end it
    // too, and this is where the pidfile holds the second helper's pid.
    source.close();
    let second = read_pid(&pidfile);
    assert!(
        second > 0 && second != helper,
        "phase 2 started its own helper"
    );
    let _killed_second = HelperGuard(second);
    let deadline = Instant::now() + Duration::from_secs(2);
    while pid_alive(second) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!pid_alive(second), "the closed pool leaked its helper");
}

// ---------------------------------------------------------------------------
// R1, R8 — routing across three sources, and the launch-owned guard
// ---------------------------------------------------------------------------

/// A keychain stand-in that records what it was asked for.
struct RecordedKeychain {
    lookups: StdMutex<Vec<String>>,
}

impl crate::credential_resolver::CredentialSource for RecordedKeychain {
    fn resolve(&self, service: &ServiceName) -> Resolved {
        self.lookups
            .lock()
            .unwrap()
            .push(service.as_str().to_owned());
        Resolved::Value(
            crate::secret_store::SecretValue::parse(b"sk-alpha".to_vec()).expect("acceptable"),
        )
    }
}

/// One file with all three sources, so a routing mistake lands on the wrong
/// backend rather than on a different YAML.
fn three_source_authorizations() -> (tempfile::TempDir, crate::credential_yaml::AuthorizationSet) {
    use std::os::unix::fs::PermissionsExt as _;
    let home = tempfile::tempdir().expect("tempdir");
    let dir = home.path().join(crate::config::USER_CONFIG_DIR_RELATIVE);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.join(crate::credential_yaml::CREDENTIALS_FILE_NAME);
    std::fs::write(
        &path,
        "credentials:\n  - service: alpha\n    apiKey:\n      name: ALPHA_KEY\n      inject: \
         [{domain: a.example, scheme: bearer}]\n  - service: beta\n    source: env\n    apiKey:\n      \
         name: BETA_KEY\n      inject: [{domain: b.example, scheme: bearer}]\n  - service: gamma\n    \
         source: secretspec\n    apiKey:\n      name: GAMMA_KEY\n      inject: [{domain: \
         c.example, scheme: bearer}]\n    secretspec:\n      executable: /opt/secretspec\n      \
         manifest: /tmp/secretspec.toml\n      profile: default\n",
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let set = crate::credential_yaml::load(home.path()).expect("the fixture loads");
    (home, set)
}

#[test]
fn each_service_reads_only_its_own_source_across_three_sources() {
    use crate::credential_resolver::{LaunchSource, MissingCredentialPolicy, resolve_launch};
    let (_home, set) = three_source_authorizations();
    let log = StartLog::new();
    let secretspec = SecretspecSource::select_with_starter(
        &requested(&["gamma"]),
        &set,
        super::session::Bounds::test_full(),
        log.starter(json!({"secrets": {"GAMMA_KEY": {"value": "sk-gamma"}}})),
    )
    .expect("a SecretSpec source");
    let keychain = Arc::new(RecordedKeychain {
        lookups: StdMutex::new(Vec::new()),
    });
    let source = LaunchSource::for_test(
        Some(keychain.clone()),
        crate::credential_env::EnvCapture::take_with(
            &requested(&["alpha", "beta", "gamma"]),
            &set,
            |_| Some("sk-beta".into()),
        ),
        Some(Arc::new(secretspec)),
    );
    let launch = resolve_launch(
        &requested(&["alpha", "beta", "gamma"]),
        &set,
        &source,
        MissingCredentialPolicy::Fail,
    )
    .expect("all three are available");
    // Each service landed on exactly one backend.
    assert_eq!(keychain.lookups.lock().unwrap().as_slice(), ["alpha"]);
    assert_eq!(log.requests("resolver.get").len(), 1);
    assert_eq!(
        log.requests("resolver.get")[0]["params"]["name"],
        "GAMMA_KEY"
    );
    // And the router never fell through: the SecretSpec service is selected by
    // the SecretSpec source, the env service by the capture, and the keychain
    // service by neither.
    assert!(source.secretspec_selects(&ServiceName::parse("gamma").unwrap()));
    assert!(!source.secretspec_selects(&ServiceName::parse("alpha").unwrap()));
    let withheld: Vec<String> = launch.withheld().iter().map(|w| w.notice()).collect();
    assert_eq!(launch.ready().len(), 3, "{withheld:?}");
}

#[test]
fn dropping_credential_sessions_closes_them() {
    let (_home, set) = secretspec_authorizations("alpha", "ALPHA_KEY");
    let log = StartLog::new();
    let source = SecretspecSource::select_with_starter(
        &requested(&["alpha"]),
        &set,
        super::session::Bounds::test_full(),
        log.starter(json!({"secrets": {"ALPHA_KEY": {"value": "sk-a"}}})),
    )
    .expect("a SecretSpec source");
    let service = ServiceName::parse("alpha").unwrap();
    assert!(matches!(source.resolve(&service), Resolved::Value(_)));
    let starts = log.starts();
    let source = Arc::new(source);
    {
        let guard =
            crate::credential_resolver::CredentialSessions::for_test(Some(Arc::clone(&source)));
        drop(guard);
    }
    assert!(matches!(
        source.resolve(&service),
        Resolved::SecretspecUnavailable(SecretspecFailure::SessionClosed)
    ));
    assert_eq!(log.starts(), starts);
}
