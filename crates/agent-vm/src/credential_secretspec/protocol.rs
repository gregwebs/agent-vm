//! The `secretspec.resolver/1` wire: outgoing frames, typed incoming frames,
//! the handshake gate and the outcome mapping (#202).
//!
//! Everything here is pure. The process that speaks it lives in `session.rs`,
//! and the classification tables are the unit-test surface for the outcome map
//! in `spec.md` §1.4 — so a mapping mistake fails a test rather than a launch.
//!
//! Two rules shape the types:
//!
//! - **No `serde_json::Value` and no internally-tagged enum** for an incoming
//!   frame. Both buffer the whole object, which for a `resolver.get` answer is
//!   a second copy of the value that nothing zeroizes. The structs below are
//!   flat, and `value` deserializes straight into a `Zeroizing<String>`.
//! - **A `serde_json::Error` is dropped unrendered.** Its `Display` can quote
//!   the input, which here is a frame that may carry a value.

use serde::Deserialize;
use serde_json::json;
use vstd::prelude::*;
use zeroize::Zeroizing;

use super::config::{SecretspecName, SessionKey};
use super::failure::SecretspecFailure;
use crate::secret_store::{Resolved, SecretValue, ValueRejection};

/// The protocol string `rpc.initialize` must answer with.
pub(super) const PROTOCOL: &str = "secretspec.resolver";
/// The only protocol version agent-vm speaks.
pub(super) const PROTOCOL_VERSION: u64 = 1;
/// What agent-vm accepts per frame and advertises as `limits.max_frame_bytes`.
///
/// A value is at most 4096 printable bytes (`MAX_SECRET_VALUE_LEN`), so ≤ 8 KiB
/// once JSON-escaped; 16 KiB is generous, and the server honours it (it answers
/// `message_too_large` above it). This is the **advertised maximum**: a server
/// that negotiates less sets the session's frame limit to `min(this,
/// negotiated)`.
pub(super) const CLIENT_MAX_FRAME_BYTES: usize = 16 * 1024;
/// The protocol's absolute ceiling (`absolute_max_frame_bytes` in
/// `rpc.discover`). The client limit must stay at or below it.
pub(super) const PROTOCOL_MAX_FRAME_BYTES: usize = 1024 * 1024;
/// The smallest frame limit agent-vm will accept from a server: below it the
/// handshake itself stops fitting, so the session is not usable.
pub(super) const MIN_FRAME_BYTES: u64 = 4096;
const _: () = assert!(CLIENT_MAX_FRAME_BYTES <= PROTOCOL_MAX_FRAME_BYTES);

/// A JSON-RPC request id. Always >= 1 (the protocol excludes 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RequestId(pub(super) u64);

/// The wall-clock deadline sent as `_meta.deadline_unix_ms`. The processor's
/// own bound is enforced on a monotonic clock; this is the mirror the server
/// reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DeadlineUnixMs(u64);

impl DeadlineUnixMs {
    pub(super) fn after(bound: std::time::Duration) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        Self((now + bound).as_millis().min(u128::from(u64::MAX)) as u64)
    }
}

/// One frame, LF-terminated, as the bytes to write.
fn frame(value: serde_json::Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&value).expect("a frame of validated types serializes");
    bytes.push(b'\n');
    bytes
}

/// `rpc.initialize`: the first frame of every session. It pins the manifest,
/// profile, scope and reason, offers no `client_methods` (agent-vm has no
/// callback, so `client.prompt` is never invited), and advertises the frame
/// limit and in-flight bound the client will honour.
pub(super) fn initialize_frame(
    id: RequestId,
    key: &SessionKey,
    deadline: DeadlineUnixMs,
) -> Vec<u8> {
    frame(json!({
        "jsonrpc": "2.0",
        "id": id.0,
        "method": "rpc.initialize",
        "_meta": { "deadline_unix_ms": deadline.0 },
        "params": {
            "protocol": PROTOCOL,
            "versions": [PROTOCOL_VERSION],
            "client": { "name": "agent-vm", "version": env!("CARGO_PKG_VERSION") },
            "limits": { "max_frame_bytes": CLIENT_MAX_FRAME_BYTES, "max_in_flight": 1 },
            "application": {
                "manifest": { "kind": "path", "path": key.manifest().as_str() },
                "provider": null,
                "profile": key.profile().as_str(),
                "scope": key.scope().map(|scope| scope.as_str()),
                "reason": key.reason().map(|reason| reason.as_str()),
            }
        }
    }))
}

/// `resolver.get` for the value representation. This is the only read the
/// client ever sends: no `representation: "auto"`/`"path"`, and no
/// `resolver.set`/`resolver.delete`/`resolver.release` builder exists.
pub(super) fn get_frame(id: RequestId, name: &SecretspecName, deadline: DeadlineUnixMs) -> Vec<u8> {
    frame(json!({
        "jsonrpc": "2.0",
        "id": id.0,
        "method": "resolver.get",
        "_meta": { "deadline_unix_ms": deadline.0 },
        "params": {
            "name": name.as_str(),
            "representation": "value",
            "purpose": { "consumer": "agent-vm", "operation": "launch" },
        }
    }))
}

/// `rpc.cancel` as the notification it is: no `id`, no `_meta`.
pub(super) fn cancel_frame(id: RequestId) -> Vec<u8> {
    frame(json!({
        "jsonrpc": "2.0",
        "method": "rpc.cancel",
        "params": { "id": id.0 }
    }))
}

/// `rpc.shutdown`: the orderly end of a session. The group teardown follows
/// regardless of whether it is answered.
pub(super) fn shutdown_frame(id: RequestId, deadline: DeadlineUnixMs) -> Vec<u8> {
    frame(json!({
        "jsonrpc": "2.0",
        "id": id.0,
        "method": "rpc.shutdown",
        "params": {},
        "_meta": { "deadline_unix_ms": deadline.0 }
    }))
}

/// The refusal of a server-sent request (`client.prompt` is the only one that
/// exists). The read continues: the prompt is refused, not the session.
pub(super) fn method_not_found_frame(their_id: u64) -> Vec<u8> {
    frame(json!({
        "jsonrpc": "2.0",
        "id": their_id,
        "error": {
            "code": -32601,
            "message": "method not found",
            "data": { "kind": "method_not_found", "retryable": false }
        }
    }))
}

/// One incoming frame, flat. A server request/notification has `method`; a
/// response to ours has `result` xor `error`.
///
/// No `Debug`: `R` is a value-bearing result type.
#[derive(Deserialize)]
#[serde(bound(deserialize = "R: Deserialize<'de>"))]
pub(super) struct Incoming<R> {
    pub(super) jsonrpc: String,
    #[serde(default)]
    pub(super) id: Option<u64>,
    #[serde(default)]
    pub(super) method: Option<String>,
    #[serde(default = "absent")]
    pub(super) result: Option<R>,
    #[serde(default = "absent")]
    pub(super) error: Option<RpcError>,
}

/// A frame's absence of `result`/`error` must be `None` for any `R`. Written as
/// a named default so the derive never asks for `R: Default`.
fn absent<T>() -> Option<T> {
    None
}

/// A JSON-RPC error object. Only the two closed fields are read; `message` is
/// never rendered.
#[derive(Deserialize, Debug)]
pub(super) struct RpcError {
    code: i64,
    #[serde(default)]
    data: Option<ErrorData>,
}

#[derive(Deserialize, Debug)]
pub(super) struct ErrorData {
    kind: String,
}

/// The `rpc.initialize` result. `limits` is required by the schema, so a result
/// without it fails the gate instead of defaulting to something permissive.
#[derive(Deserialize)]
pub(super) struct InitializeResult {
    protocol: String,
    version: u64,
    methods: Vec<String>,
    limits: WireLimits,
}

#[derive(Deserialize)]
pub(super) struct WireLimits {
    /// `u64`, so an out-of-range or fractional value is a decode failure rather
    /// than a silent wrap.
    max_frame_bytes: u64,
    max_in_flight: u64,
}

/// A `resolver.get` result, flat. The value deserializes directly into a
/// zeroizing buffer; `representation`, `value` and `source` are optional
/// because a `missing`/`undeclared` answer carries none of them.
#[derive(Deserialize)]
pub(super) struct GetResultWire {
    status: String,
    #[serde(default)]
    representation: Option<String>,
    #[serde(default)]
    value: Option<Zeroizing<String>>,
    #[serde(default)]
    source: Option<String>,
}

/// `{}`: the `rpc.shutdown` result and the shape the client expects of it.
#[derive(Deserialize)]
pub(super) struct EmptyResult {}

/// The closed error kinds, decoded from `data.kind` (else from `code`).
///
/// "Closed for senders, open for receivers": a sender emits one of these, a
/// receiver must tolerate a new one, so the unknown case is a variant rather
/// than a decode failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ErrorKind {
    ParseError,
    InvalidRequest,
    MethodNotFound,
    InvalidParams,
    Internal,
    UnsupportedVersion,
    CapabilityRequired,
    DeadlineExceeded,
    Cancelled,
    Unavailable,
    PermissionDenied,
    InteractionRequired,
    Conflict,
    OperationFailed,
    MessageTooLarge,
    RepresentationMismatch,
    Other,
}

impl ErrorKind {
    fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "parse_error" => Self::ParseError,
            "invalid_request" => Self::InvalidRequest,
            "method_not_found" => Self::MethodNotFound,
            "invalid_params" => Self::InvalidParams,
            "internal" => Self::Internal,
            "unsupported_version" => Self::UnsupportedVersion,
            "capability_required" => Self::CapabilityRequired,
            "deadline_exceeded" => Self::DeadlineExceeded,
            "cancelled" => Self::Cancelled,
            "unavailable" => Self::Unavailable,
            "permission_denied" => Self::PermissionDenied,
            "interaction_required" => Self::InteractionRequired,
            "conflict" => Self::Conflict,
            "operation_failed" => Self::OperationFailed,
            "message_too_large" => Self::MessageTooLarge,
            "representation_mismatch" => Self::RepresentationMismatch,
            _ => return None,
        })
    }

    fn from_code(code: i64) -> Option<Self> {
        Some(match code {
            -32700 => Self::ParseError,
            -32600 => Self::InvalidRequest,
            -32601 => Self::MethodNotFound,
            -32602 => Self::InvalidParams,
            -32603 => Self::Internal,
            -32000 => Self::UnsupportedVersion,
            -32001 => Self::CapabilityRequired,
            -32002 => Self::DeadlineExceeded,
            -32003 => Self::Cancelled,
            -32004 => Self::Unavailable,
            -32005 => Self::PermissionDenied,
            -32006 => Self::InteractionRequired,
            -32007 => Self::Conflict,
            -32008 => Self::OperationFailed,
            -32009 => Self::MessageTooLarge,
            -32010 => Self::RepresentationMismatch,
            _ => return None,
        })
    }
}

/// The kind an error object names. `data.kind` wins when it is one this client
/// knows; the code is the fallback, because the schema allows either.
pub(super) fn error_kind(error: &RpcError) -> ErrorKind {
    error
        .data
        .as_ref()
        .and_then(|data| ErrorKind::from_name(&data.kind))
        .or_else(|| ErrorKind::from_code(error.code))
        .unwrap_or(ErrorKind::Other)
}

/// Whether the session is still trustworthy after an answer. A per-request
/// error keeps it; anything that breaks the framing, the protocol version or
/// the read-only promise ends it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Keep {
    Session,
    Kill,
}

/// The handshake gate. Returns the frame limit the session must then enforce:
/// `min(requested, negotiated)`.
///
/// The gate reads the protocol string, the version, the two **mandatory**
/// capabilities and the write methods — deliberately not the server's product
/// name, because the approved gate is the protocol, not a vendor. Two separate
/// kernels cover the two facts that carry different messages: a session that
/// speaks the wrong protocol (`UnsupportedProtocol`) and one that offers a
/// write method (`NotReadOnly`).
pub(super) fn gate(result: &InitializeResult) -> Result<usize, SecretspecFailure> {
    let speaks_v1 = result.protocol == PROTOCOL && result.version == PROTOCOL_VERSION;
    let offers = |method: &str| result.methods.iter().any(|offered| offered == method);
    let (get, release) = (offers("resolver.get"), offers("resolver.release"));
    let (set, delete) = (offers("resolver.set"), offers("resolver.delete"));
    if !super::capability_satisfied(speaks_v1, get, release) {
        return Err(SecretspecFailure::UnsupportedProtocol);
    }
    if !super::offers_no_write_method(set, delete) {
        return Err(SecretspecFailure::NotReadOnly);
    }
    limits_are_usable(&result.limits)
}

/// A conforming server echoes the client's limits, so it passes. Anything else
/// is a protocol violation: agent-vm never guesses a frame bound.
///
/// `max_in_flight` only has to be at least 1 — the client sends one request at a
/// time regardless — while a **smaller** `max_frame_bytes` is accepted and then
/// enforced on every later read and write.
fn limits_are_usable(limits: &WireLimits) -> Result<usize, SecretspecFailure> {
    let frame_ok =
        (MIN_FRAME_BYTES..=CLIENT_MAX_FRAME_BYTES as u64).contains(&limits.max_frame_bytes);
    if negotiated_limit_is_usable(frame_ok, limits.max_in_flight >= 1) {
        Ok(enforced_frame_limit(limits.max_frame_bytes, CLIENT_MAX_FRAME_BYTES as u64) as usize)
    } else {
        Err(SecretspecFailure::ProtocolViolation)
    }
}

verus! {

/// The negotiated-limit acceptance decision, over two already-measured facts: the
/// server's `max_frame_bytes` is inside `[MIN_FRAME_BYTES, CLIENT_MAX_FRAME_BYTES]`
/// and it allows at least one in-flight request. A rejecting answer sends no
/// `resolver.get`, so acceptance can never bypass either check.
pub(crate) fn negotiated_limit_is_usable(
    frame_bytes_in_range: bool,
    at_least_one_in_flight: bool,
) -> (ok: bool)
    ensures
        ok == (frame_bytes_in_range && at_least_one_in_flight),
{
    frame_bytes_in_range && at_least_one_in_flight
}

/// The limit the session then enforces: `min(requested, negotiated)`, so a server
/// that negotiated less never receives a longer frame and the client never widens
/// its own bound.
pub(crate) fn enforced_frame_limit(negotiated: u64, client_max: u64) -> (limit: u64)
    ensures
        negotiated <= client_max ==> limit == negotiated,
        negotiated > client_max ==> limit == client_max,
{
    if negotiated <= client_max {
        negotiated
    } else {
        client_max
    }
}

} // verus!

/// The failure an `rpc.initialize` *error* maps to. Every initialize error is
/// session-fatal on the server side too, so the caller drops the session either
/// way.
pub(super) fn initialize_failure(kind: ErrorKind) -> SecretspecFailure {
    match kind {
        ErrorKind::UnsupportedVersion => SecretspecFailure::UnsupportedProtocol,
        ErrorKind::OperationFailed | ErrorKind::InvalidParams => SecretspecFailure::SessionRejected,
        ErrorKind::PermissionDenied | ErrorKind::InteractionRequired => {
            SecretspecFailure::PermissionDenied
        }
        ErrorKind::Unavailable | ErrorKind::Internal => SecretspecFailure::ProviderFailed,
        _ => SecretspecFailure::ProtocolViolation,
    }
}

/// The `resolver.get` result mapping: every status, and the value rule.
pub(super) fn classify_get(wire: GetResultWire) -> (Resolved, Keep) {
    match wire.status.as_str() {
        "resolved" => match (
            wire.representation.as_deref(),
            wire.value,
            wire.source.as_deref(),
        ) {
            // `generated` is impossible under `--read-only` (the server refuses
            // it with permission_denied), so seeing one means the server is not
            // honouring read-only, and `path` means the declaration uses
            // `as_path`: both end the session.
            (Some("value"), Some(mut value), Some(source)) if source != "generated" => {
                match SecretValue::try_parse(std::mem::take(&mut *value).into_bytes()) {
                    Ok(value) => (Resolved::Value(value), Keep::Session),
                    Err(rejection) => (Resolved::InvalidValue(rejection), Keep::Session),
                }
            }
            _ => (
                Resolved::SecretspecUnavailable(SecretspecFailure::ProtocolViolation),
                Keep::Kill,
            ),
        },
        "missing" => (Resolved::Missing, Keep::Session),
        // `undeclared` maps to `Missing`, as the issue requires. It also covers
        // a name outside the session scope, which is why the withheld remedy
        // names both readings instead of a new outcome class existing for it.
        "undeclared" => (Resolved::Missing, Keep::Session),
        _ => (
            Resolved::SecretspecUnavailable(SecretspecFailure::ProtocolViolation),
            Keep::Kill,
        ),
    }
}

/// The `resolver.get` *error* mapping.
pub(super) fn classify_get_error(kind: ErrorKind) -> (Resolved, Keep) {
    use SecretspecFailure as F;
    let failure = match kind {
        // An oversized answer is a value agent-vm will not inject, not an
        // unavailable source: hard error under every policy.
        ErrorKind::MessageTooLarge => {
            return (
                Resolved::InvalidValue(ValueRejection::TooLong),
                Keep::Session,
            );
        }
        ErrorKind::DeadlineExceeded | ErrorKind::Cancelled => F::Unresponsive,
        ErrorKind::PermissionDenied | ErrorKind::InteractionRequired => F::PermissionDenied,
        ErrorKind::RepresentationMismatch => F::RepresentationMismatch,
        ErrorKind::UnsupportedVersion => {
            return (
                Resolved::SecretspecUnavailable(F::UnsupportedProtocol),
                Keep::Kill,
            );
        }
        ErrorKind::ParseError
        | ErrorKind::InvalidRequest
        | ErrorKind::MethodNotFound
        | ErrorKind::InvalidParams
        | ErrorKind::CapabilityRequired => F::ProtocolViolation,
        ErrorKind::Unavailable
        | ErrorKind::OperationFailed
        | ErrorKind::Internal
        | ErrorKind::Conflict
        | ErrorKind::Other => F::ProviderFailed,
    };
    (Resolved::SecretspecUnavailable(failure), Keep::Session)
}
