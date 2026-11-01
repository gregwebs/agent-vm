//! The debug-only fake `secretspec serve --read-only` endpoint (#202).
//!
//! It speaks real `secretspec.resolver/1` frames and returns only bytes the
//! test itself wrote into its scenario file: it reads no store, no `$HOME`
//! configuration and no SecretSpec state. Compiled out of release builds
//! (`main`'s hook is `debug_assertions`-only), so a shipped binary can never act
//! as the fake — the `test` arm exists so unit tests can build it under
//! `--release`.
//!
//! It is also the **contract oracle** for agent-vm's own frames: every request
//! envelope is checked against what the real 0.21.1 server enforces and what
//! agent-vm promises (exact keys, monotonic ids, `provider: null`, an absolute
//! manifest, `representation: "value"`, `purpose.consumer: "agent-vm"`, no
//! `client_methods`, the advertised limits). A violation is recorded and the
//! fake answers `invalid_request` and exits 1, so a client change that would
//! break against the real server fails a unit test first.
//!
//! The transcript is built only from client frames and process facts, so it is
//! value-free by construction: a scenario value only ever reaches the fake's own
//! stdout frame.

// Each test crate uses a different subset of this endpoint (the same allowance
// `tests/support/fake_msb.rs` needs), and the release build compiles none of it.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{Value, json};

/// The environment variable that names a scenario file. Read only behind
/// `debug_assertions`.
pub(crate) const FAKE_ENV: &str = "AGENT_VM_TEST_SECRETSPEC_FAKE";

/// The argv the fake activates for: exactly `<program> serve --read-only`.
const ACTIVATION_ARGS: [&str; 2] = ["serve", "--read-only"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Scenario {
    /// Where to append the value-free JSONL transcript (absent: none).
    #[serde(default)]
    pub(crate) transcript: Option<PathBuf>,
    #[serde(default)]
    pub(crate) handshake: Handshake,
    #[serde(default)]
    pub(crate) secrets: BTreeMap<String, Answer>,
    /// Exit cleanly (as if killed while idle) after answering this many gets.
    #[serde(default)]
    pub(crate) exit_after_gets: Option<u32>,
    /// Do not answer any `resolver.get` until this file exists: a real phase
    /// barrier, so a test can order "phase 1 is done" against "the launch is
    /// still booting" instead of guessing with a sleep.
    #[serde(default)]
    pub(crate) gate: Option<PathBuf>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Handshake {
    /// `methods = ["resolver.get", "resolver.release"]`, the client's limits
    /// echoed back.
    #[default]
    Ok,
    /// Read the frame, never answer it.
    Hang,
    /// Exit before answering, with this status (a pre-0.21 binary exits 2).
    Exit { code: i32 },
    /// An `rpc.initialize` error of this kind.
    Error { kind: String },
    /// A result the gate refuses: wrong protocol or version.
    Version { protocol: String, version: u64 },
    /// A session that offers the write methods.
    Writable,
    /// `methods = ["resolver.get"]` only: the mandatory capability is absent.
    NoRelease,
    /// A usable but different negotiated limit.
    Limits {
        max_frame_bytes: u64,
        max_in_flight: u64,
    },
    /// A result without `limits`.
    NoLimits,
    /// A frame that is not JSON.
    Garbage,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Answer {
    /// The one place a fake value exists.
    Value(String),
    /// Successive gets, in order (the rotation test).
    Values(Vec<String>),
    Missing,
    Undeclared,
    /// Never answer; record any `rpc.cancel`.
    Hang,
    /// Send a `client.prompt` request first, record the client's answer, then
    /// refuse with `permission_denied`.
    Prompt,
    /// Send a `client.prompt`, then close both ends without answering the get:
    /// the client's *refusal* of the prompt is the write that gets `EPIPE`,
    /// which is a session lost mid-request rather than "the request never
    /// reached the server".
    PromptThenCloseInput,
    /// `representation_mismatch`.
    AsPath,
    /// `resolved` with `source: "generated"`.
    Generated,
    /// `resolved` with `representation: "path"`.
    Path,
    /// A frame larger than any limit the client accepts.
    Oversize,
    /// The base64/binary case: `operation_failed`.
    Binary,
    /// Exit mid-request.
    Die,
    /// Spawn a helper in our group, write a partial frame, exit.
    DieLeavingHelper,
    /// Any error kind, with its documented code.
    Error {
        kind: String,
    },
}

/// The JSONL transcript. Appends; a failure to write is ignored, because a
/// transcript is test evidence, never a decision.
pub(crate) struct Transcript {
    file: Option<std::fs::File>,
}

impl Transcript {
    pub(crate) fn open(path: Option<&Path>) -> Self {
        Self {
            file: path.and_then(|path| {
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .ok()
            }),
        }
    }

    pub(crate) fn event(&mut self, event: Value) {
        if let Some(file) = &mut self.file {
            let _ = writeln!(file, "{event}");
        }
    }
}

/// Debug builds only: `Some(exit_code)` when this process was started as the
/// fake, i.e. [`FAKE_ENV`] names a scenario **and** argv is exactly
/// `[program, "serve", "--read-only"]`.
///
/// A release binary has no hook, so a `serve --read-only` invocation is the real
/// CLI's to reject.
#[cfg(debug_assertions)]
pub(crate) fn serve_if_requested() -> Option<i32> {
    let scenario_path = std::env::var_os(FAKE_ENV)?;
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv != ACTIVATION_ARGS {
        return None;
    }
    let text = std::fs::read(scenario_path).ok()?;
    let scenario: Scenario = serde_json::from_slice(&text).ok()?;
    // Ownership of fd 0, not `StdinLock`: one scenario closes the client's write
    // end mid-session to make its next write fail with `EPIPE`, and dropping a
    // lock would not close the descriptor. The whole process exists to speak
    // this protocol on stdin/stdout, so nothing else reads it.
    //
    // SAFETY: fd 0 is this process's stdin and the resulting `File` is the only
    // owner; it is dropped, not closed twice, when the scenario closes it.
    let stdin = std::io::BufReader::new(unsafe {
        <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(libc::STDIN_FILENO)
    });
    let stdout = std::io::stdout();
    let mut transcript = Transcript::open(scenario.transcript.as_deref());
    Some(serve(&scenario, stdin, stdout.lock(), &mut transcript))
}

/// The protocol loop, over any byte streams: `main`'s hook passes stdin/stdout,
/// unit tests pass an in-process pipe pair on a thread.
pub(crate) fn serve(
    scenario: &Scenario,
    input: impl BufRead,
    mut output: impl Write,
    transcript: &mut Transcript,
) -> i32 {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let secretspec_env: Vec<String> = std::env::vars()
        .map(|(name, _)| name)
        .filter(|name| name.starts_with("SECRETSPEC_"))
        .collect();
    transcript.event(json!({
        "event": "start",
        "argv": if argv.is_empty() {
            ACTIVATION_ARGS.iter().map(|arg| (*arg).to_owned()).collect::<Vec<String>>()
        } else {
            argv
        },
        "cwd": std::env::current_dir()
            .map(|dir| dir.to_string_lossy().into_owned())
            .unwrap_or_default(),
        "secretspec_env": secretspec_env,
        "pid": std::process::id(),
    }));

    // `Option` so one answer can close the client's write end deterministically:
    // an `EPIPE` on the client's next write must not be a race against this
    // thread returning.
    let mut input = Some(input);
    let mut gets = 0u32;
    let mut last_id = 0u64;
    let mut index = 0usize;
    // The real server answers `resolver.get` before `rpc.initialize`, and a
    // second `rpc.initialize`, with `invalid_request`; the fake used to accept
    // both, so a client that skipped the handshake passed a unit test.
    let mut initialized = false;
    loop {
        let mut line = Vec::new();
        let Some(reader) = input.as_mut() else {
            transcript.event(json!({ "event": "exit", "reason": "input_closed" }));
            return 0;
        };
        match reader.read_until(b'\n', &mut line) {
            Ok(0) => {
                transcript.event(json!({ "event": "exit", "reason": "eof" }));
                return 0;
            }
            Ok(_) => {}
            Err(_) => {
                transcript.event(json!({ "event": "exit", "reason": "read_error" }));
                return 0;
            }
        }
        while line
            .last()
            .is_some_and(|byte| *byte == b'\n' || *byte == b'\r')
        {
            line.pop();
        }
        if line.is_empty() {
            continue;
        }
        let Ok(frame) = serde_json::from_slice::<Value>(&line) else {
            // Not JSON: the client promised NDJSON, so this is the client's bug.
            let _ = writeln!(
                output,
                "{}",
                json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error","data":{"kind":"parse_error","retryable":false}}})
            );
            return 1;
        };
        let method = frame
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let id = frame.get("id").and_then(Value::as_u64);
        transcript.event(json!({
            "event": "request",
            "id": id,
            "method": method,
            "frame": frame,
        }));
        if frame["jsonrpc"] != "2.0" {
            return violate(
                output,
                transcript,
                id,
                Violation::anonymous("jsonrpc_version", "invalid_request"),
            );
        }
        if let Some(id) = id {
            if id <= last_id {
                return violate(
                    output,
                    transcript,
                    Some(id),
                    Violation::with_id("ids_must_increase", "invalid_request"),
                );
            }
            last_id = id;
        }
        match method.as_str() {
            "rpc.initialize" => {
                if initialized {
                    return violate(
                        output,
                        transcript,
                        id,
                        Violation::with_id("second_initialize", "invalid_request"),
                    );
                }
                if let Err(violation) = check_initialize(&frame) {
                    return violate(output, transcript, id, violation);
                }
                initialized = true;
                match &scenario.handshake {
                    Handshake::Ok => {
                        let limits = frame["params"]["limits"].clone();
                        let _ = writeln!(
                            output,
                            "{}",
                            json!({"jsonrpc":"2.0","id":id,"result":{
                                "protocol":"secretspec.resolver","version":1,
                                "server":{"name":"secretspec-resolver","version":"0.21.1"},
                                "methods":["resolver.get","resolver.release"],
                                "capabilities":{},
                                "limits":limits,
                                "application":{"manifest_kind":"path","supports_inline_manifest":true}
                            }})
                        );
                    }
                    Handshake::Hang => continue,
                    Handshake::Exit { code } => {
                        transcript
                            .event(json!({ "event": "exit", "reason": "handshake", "code": code }));
                        return *code;
                    }
                    Handshake::Error { kind } => {
                        answer_error(&mut output, id, kind);
                        transcript.event(json!({ "event": "exit", "reason": "handshake" }));
                        return 0;
                    }
                    Handshake::Version { protocol, version } => {
                        let _ = writeln!(
                            output,
                            "{}",
                            json!({"jsonrpc":"2.0","id":id,"result":{
                                "protocol":protocol,"version":version,
                                "methods":["resolver.get","resolver.release"],
                                "limits":frame["params"]["limits"].clone()
                            }})
                        );
                    }
                    Handshake::Writable => {
                        let _ = writeln!(
                            output,
                            "{}",
                            json!({"jsonrpc":"2.0","id":id,"result":{
                                "protocol":"secretspec.resolver","version":1,
                                "methods":["resolver.get","resolver.release","resolver.set","resolver.delete"],
                                "limits":frame["params"]["limits"].clone()
                            }})
                        );
                    }
                    Handshake::NoRelease => {
                        let _ = writeln!(
                            output,
                            "{}",
                            json!({"jsonrpc":"2.0","id":id,"result":{
                                "protocol":"secretspec.resolver","version":1,
                                "methods":["resolver.get"],
                                "limits":frame["params"]["limits"].clone()
                            }})
                        );
                    }
                    Handshake::Limits {
                        max_frame_bytes,
                        max_in_flight,
                    } => {
                        let _ = writeln!(
                            output,
                            "{}",
                            json!({"jsonrpc":"2.0","id":id,"result":{
                                "protocol":"secretspec.resolver","version":1,
                                "methods":["resolver.get","resolver.release"],
                                "limits":{"max_frame_bytes":max_frame_bytes,"max_in_flight":max_in_flight}
                            }})
                        );
                    }
                    Handshake::NoLimits => {
                        let _ = writeln!(
                            output,
                            "{}",
                            json!({"jsonrpc":"2.0","id":id,"result":{
                                "protocol":"secretspec.resolver","version":1,
                                "methods":["resolver.get","resolver.release"]
                            }})
                        );
                    }
                    Handshake::Garbage => {
                        let _ = writeln!(output, "this is not a frame");
                    }
                }
            }
            "resolver.get" => {
                if !initialized {
                    return violate(
                        output,
                        transcript,
                        id,
                        Violation::with_id("get_before_initialize", "invalid_request"),
                    );
                }
                if let Err(violation) = check_get(&frame) {
                    return violate(output, transcript, id, violation);
                }
                if let Some(gate) = &scenario.gate {
                    wait_for_gate(gate);
                }
                let name = frame["params"]["name"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned();
                let answer = scenario.secrets.get(&name).unwrap_or(&Answer::Missing);
                let current = index;
                index += 1;
                match answer {
                    Answer::Value(value) => answer_value(&mut output, id, value, "provider"),
                    Answer::Values(values) => {
                        let value = values.get(current).or_else(|| values.last());
                        match value {
                            Some(value) => answer_value(&mut output, id, value, "provider"),
                            None => answer_missing(&mut output, id),
                        }
                    }
                    Answer::Missing => answer_missing(&mut output, id),
                    Answer::Undeclared => {
                        let _ = writeln!(
                            output,
                            "{}",
                            json!({"jsonrpc":"2.0","id":id,"result":{"status":"undeclared"}})
                        );
                    }
                    Answer::Hang => {
                        // Keep reading so a `rpc.cancel` is recorded, and stop at
                        // EOF (which is what the client's teardown produces).
                        continue;
                    }
                    Answer::Prompt => {
                        // A server-side id from its own space: JSON-RPC ids are
                        // per-direction, and the client refuses an answer whose
                        // id is not the request it is waiting for.
                        let prompt_id = 1_000_000 + current as u64;
                        let _ = writeln!(
                            output,
                            "{}",
                            json!({"jsonrpc":"2.0","id":prompt_id,"method":"client.prompt","params":{"secret":name}})
                        );
                        let _ = output.flush();
                        let mut reply = Vec::new();
                        if let Some(reader) = input.as_mut() {
                            let _ = reader.read_until(b'\n', &mut reply);
                        }
                        let code = serde_json::from_slice::<Value>(&reply)
                            .ok()
                            .and_then(|frame| frame["error"]["code"].as_i64())
                            .unwrap_or_default();
                        let kind = serde_json::from_slice::<Value>(&reply)
                            .ok()
                            .and_then(|frame| {
                                frame["error"]["data"]["kind"].as_str().map(str::to_owned)
                            })
                            .unwrap_or_default();
                        transcript.event(json!({
                            "event": "prompt_answer", "code": code, "kind": kind
                        }));
                        answer_error(&mut output, id, "permission_denied");
                    }
                    Answer::PromptThenCloseInput => {
                        // Close the read end **before** sending the prompt, so the
                        // client's refusal of it is the write that gets `EPIPE`:
                        // a deterministic ordering rather than a race with this
                        // thread returning.
                        drop(input.take());
                        let prompt_id = 1_000_000 + current as u64;
                        let _ = writeln!(
                            output,
                            "{}",
                            json!({"jsonrpc":"2.0","id":prompt_id,"method":"client.prompt","params":{"secret":name}})
                        );
                        let _ = output.flush();
                        transcript.event(json!({
                            "event": "exit", "reason": "prompt_then_close_input"
                        }));
                        return 0;
                    }
                    Answer::AsPath => answer_error(&mut output, id, "representation_mismatch"),
                    Answer::Generated => answer_value(&mut output, id, "", "generated"),
                    Answer::Path => {
                        let _ = writeln!(
                            output,
                            "{}",
                            json!({"jsonrpc":"2.0","id":id,"result":{"status":"resolved","representation":"path","value":"/dev/null","source":"provider"}})
                        );
                    }
                    Answer::Oversize => {
                        let filler = "x".repeat(32 * 1024);
                        let _ = writeln!(
                            output,
                            "{}",
                            json!({"jsonrpc":"2.0","id":id,"result":{"status":"resolved","representation":"value","value":filler,"source":"provider"}})
                        );
                    }
                    Answer::Binary => answer_error(&mut output, id, "operation_failed"),
                    Answer::Die => {
                        transcript.event(json!({ "event": "exit", "reason": "die" }));
                        return 0;
                    }
                    Answer::DieLeavingHelper => {
                        // A helper that inherits our stdout and outlives us is
                        // exactly the case a leader-liveness teardown misses.
                        let helper = std::process::Command::new("sleep")
                            .arg("30")
                            .stdout(std::process::Stdio::inherit())
                            .spawn();
                        if let Ok(helper) = &helper {
                            transcript.event(json!({
                                "event": "helper", "pid": helper.id(), "argv": ["sleep", "30"]
                            }));
                        }
                        // A partial frame: no LF, so the client must time out
                        // rather than read a usable answer.
                        let _ = write!(
                            output,
                            "{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{{",
                            id.unwrap_or_default()
                        );
                        let _ = output.flush();
                        transcript
                            .event(json!({ "event": "exit", "reason": "die_leaving_helper" }));
                        return 0;
                    }
                    Answer::Error { kind } => answer_error(&mut output, id, kind),
                }
                gets += 1;
                if scenario.exit_after_gets.is_some_and(|limit| gets >= limit) {
                    transcript.event(json!({ "event": "exit", "reason": "exit_after_gets" }));
                    return 0;
                }
                let _ = output.flush();
            }
            "rpc.shutdown" => {
                let _ = writeln!(output, "{}", json!({"jsonrpc":"2.0","id":id,"result":{}}));
                let _ = output.flush();
                transcript.event(json!({ "event": "exit", "reason": "shutdown" }));
                return 0;
            }
            "rpc.cancel" => {
                transcript.event(json!({ "event": "cancel", "id": frame["params"]["id"] }));
            }
            // `client.prompt` answered by the client, or anything unexpected.
            other => {
                transcript.event(json!({ "event": "unexpected", "method": other }));
            }
        }
        let _ = output.flush();
    }
}

/// Block until `path` exists. The wait is bounded by the test runner, not by
/// this function: a gate that never opens leaves the fake waiting, and the test
/// that forgot it fails on its own timeout.
fn wait_for_gate(path: &Path) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while !path.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

fn answer_value(output: &mut impl Write, id: Option<u64>, value: &str, source: &str) {
    let _ = writeln!(
        output,
        "{}",
        json!({"jsonrpc":"2.0","id":id,"result":{
            "status":"resolved","representation":"value","value":value,
            "source":source,"expires_at_unix_ms":null,"refresh_at_unix_ms":null
        }})
    );
}

fn answer_missing(output: &mut impl Write, id: Option<u64>) {
    let _ = writeln!(
        output,
        "{}",
        json!({"jsonrpc":"2.0","id":id,"result":{"status":"missing","required":false}})
    );
}

/// Every error object carries the documented code for its kind, so the client's
/// code fallback and its `data.kind` path agree.
fn answer_error(output: &mut impl Write, id: Option<u64>, kind: &str) {
    let code = error_code(kind);
    let _ = writeln!(
        output,
        "{}",
        json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":"test error","data":{"kind":kind,"retryable":false}}})
    );
}

/// One way a client frame breaks the contract, with the answer the real 0.21.1
/// server gave for it in `adversarial/wire-results.jsonl`.
///
/// The kinds are recorded, not guessed: `invalid_request` for a frame the server
/// cannot attribute or for a protocol-state break (a get before the initialize,
/// a second initialize), `invalid_params` for an initialize whose `params` carry
/// keys the schema forbids and for an empty `name`, and `deadline_exceeded` for a
/// get whose `_meta.deadline_unix_ms` has already passed.
struct Violation {
    rule: &'static str,
    kind: &'static str,
    /// Whether the server echoed the frame's own id. A non-`2.0` envelope is not
    /// a request the server could attribute, so it answers `id: null`.
    echo_id: bool,
}

impl Violation {
    const fn with_id(rule: &'static str, kind: &'static str) -> Self {
        Self {
            rule,
            kind,
            echo_id: true,
        }
    }

    const fn anonymous(rule: &'static str, kind: &'static str) -> Self {
        Self {
            rule,
            kind,
            echo_id: false,
        }
    }
}

/// JSON-RPC code for a documented error kind.
fn error_code(kind: &str) -> i64 {
    match kind {
        "parse_error" => -32700,
        "invalid_request" => -32600,
        "method_not_found" => -32601,
        "invalid_params" => -32602,
        "internal" => -32603,
        "unsupported_version" => -32000,
        "capability_required" => -32001,
        "deadline_exceeded" => -32002,
        "cancelled" => -32003,
        "unavailable" => -32004,
        "permission_denied" => -32005,
        "interaction_required" => -32006,
        "conflict" => -32007,
        "operation_failed" => -32008,
        "message_too_large" => -32009,
        "representation_mismatch" => -32010,
        _ => -32008,
    }
}

/// Record the violation and answer it as the real server does, then end the
/// session: every one of these is a client bug, and the real server ended the
/// session for the initialize cases too.
fn violate(
    mut output: impl Write,
    transcript: &mut Transcript,
    id: Option<u64>,
    violation: Violation,
) -> i32 {
    transcript.event(json!({ "event": "violation", "rule": violation.rule }));
    let answer_id = if violation.echo_id {
        json!(id)
    } else {
        json!(null)
    };
    let _ = writeln!(
        output,
        "{}",
        json!({
            "jsonrpc": "2.0",
            "id": answer_id,
            "error": {
                "code": error_code(violation.kind),
                "message": violation.kind,
                "data": { "kind": violation.kind, "retryable": false }
            }
        })
    );
    1
}

/// The contract oracle's initialize checks: what the real server enforces
/// (`additionalProperties: false`, required `_meta`, integer id from 1) and what
/// agent-vm promises (no `client_methods`, one in-flight request, `provider:
/// null`, an absolute manifest path, the advertised frame limit).
fn check_initialize(frame: &Value) -> Result<(), Violation> {
    let invalid = |rule: &'static str| Violation::with_id(rule, "invalid_request");
    if !keys_are(frame, &["id", "jsonrpc", "method", "_meta", "params"]) {
        return Err(invalid("envelope_keys"));
    }
    let meta = frame["_meta"]
        .as_object()
        .ok_or_else(|| invalid("meta_shape"))?;
    if meta.len() != 1
        || meta
            .get("deadline_unix_ms")
            .and_then(Value::as_u64)
            .is_none()
    {
        return Err(invalid("meta_shape"));
    }
    // The schema is `additionalProperties: false`, so a key the client does not
    // own is refused — recorded as `invalid_params`, not `invalid_request`.
    if !keys_are(
        &frame["params"],
        &["protocol", "versions", "client", "limits", "application"],
    ) {
        return Err(Violation::with_id("params_keys", "invalid_params"));
    }
    let params = frame["params"]
        .as_object()
        .ok_or_else(|| invalid("params_missing"))?;
    if params["protocol"] != "secretspec.resolver" {
        return Err(invalid("protocol"));
    }
    if params["versions"] != json!([1]) {
        return Err(invalid("versions"));
    }
    if params["client"]["name"] != "agent-vm" {
        return Err(invalid("client_name"));
    }
    if params["limits"]["max_in_flight"] != json!(1) {
        return Err(invalid("max_in_flight"));
    }
    if params["limits"]["max_frame_bytes"] != json!(16 * 1024) {
        return Err(invalid("max_frame_bytes"));
    }
    let application = params
        .get("application")
        .ok_or_else(|| invalid("application_missing"))?;
    if application.get("provider").is_none() || !application["provider"].is_null() {
        return Err(invalid("provider_null"));
    }
    if application["manifest"]["kind"] != "path" {
        return Err(invalid("manifest_kind"));
    }
    let path = application["manifest"]["path"]
        .as_str()
        .ok_or_else(|| invalid("manifest_path"))?;
    if !path.starts_with('/') {
        return Err(invalid("manifest_absolute"));
    }
    for key in ["profile", "scope", "reason"] {
        if !application
            .get(key)
            .is_some_and(|value| value.is_null() || value.is_string())
        {
            return Err(invalid("application_nullable_keys"));
        }
    }
    Ok(())
}

/// Whether this object has exactly these keys (order is the sender's business,
/// the set is not).
fn keys_are(value: &Value, expected: &[&str]) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    let mut expected: Vec<&str> = expected.to_vec();
    keys.sort_unstable();
    expected.sort_unstable();
    keys == expected
}

fn check_get(frame: &Value) -> Result<(), Violation> {
    let invalid = |rule: &'static str| Violation::with_id(rule, "invalid_request");
    if !keys_are(frame, &["id", "jsonrpc", "method", "_meta", "params"]) {
        return Err(invalid("envelope_keys"));
    }
    let Some(deadline) = frame["_meta"]["deadline_unix_ms"].as_u64() else {
        return Err(invalid("meta_shape"));
    };
    if !frame["params"].is_object() {
        return Err(invalid("params_missing"));
    }
    if !keys_are(&frame["params"], &["name", "purpose", "representation"]) {
        return Err(invalid("get_params_keys"));
    }
    let params = &frame["params"];
    if params["representation"] != "value" {
        return Err(invalid("representation"));
    }
    if params["purpose"] != json!({"consumer": "agent-vm", "operation": "launch"}) {
        return Err(invalid("purpose"));
    }
    let Some(name) = params["name"].as_str() else {
        return Err(invalid("name"));
    };
    // Recorded: the real server refuses an empty name with `invalid_params`
    // rather than answering `missing`, so an empty name could never be mistaken
    // for a declared secret with no value.
    if name.is_empty() {
        return Err(Violation::with_id("name_empty", "invalid_params"));
    }
    // Recorded: a get whose mirrored deadline has already passed is answered
    // `deadline_exceeded`, which is what the client maps to "unresponsive".
    if deadline < now_unix_ms() {
        return Err(Violation::with_id("deadline_expired", "deadline_exceeded"));
    }
    Ok(())
}

/// Wall-clock milliseconds, the same basis as `_meta.deadline_unix_ms`.
fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}
