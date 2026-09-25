//! `~/.config/agent-vm/credentials.yaml`: the user's credential
//! **authorization**, agent-vm #161.
//!
//! One deep module: *given `$HOME`, return a validated authorization set or an
//! error*. Everything downstream (launch resolution, the microsandbox
//! resolver, the proxy plan) consumes only the validated types below, so there
//! is exactly one place where an untrusted file becomes an authority decision.
//!
//! # Authority model
//!
//! A project's `credentials = [...]` list *requests*; only this file
//! *authorizes*. A request may not create, widen or override an
//! authorization (AC8): an entry that is never requested changes nothing, and
//! a request without an entry is a hard error that names both lookup
//! locations. Storing a value in the keychain authorizes nothing either — the
//! entry must also name the exact HTTPS origin and the exact request header
//! the value may occupy.
//!
//! # What is rejected, and why the parser is not trusted
//!
//! This file picks the origins that receive a real API key, so accepting more
//! YAML than intended is a security bug, not a usability quirk. The grammar is
//! validated by this module, never by the parser, and it mirrors the runtime's
//! own durable grammar (`microsandbox-types`' `is_valid_origin_host`,
//! `validate_credential_header`, `validate_credential_format`) byte for byte
//! so the two cannot drift; `grammar_matches_the_runtime_fixture` pins that
//! against the runtime's checked-in accept/reject vectors.
//!
//! Parsing is two passes over the same bytes, both with a *reject* bias:
//!
//! 1. `guard_unsupported_syntax` drives `granit-parser` directly (the crate
//!    `serde-saphyr` is built on and re-exports) and refuses any YAML feature
//!    the schema has no use for but that has security weight: anchors,
//!    aliases, tags (`!x`, `!!x`), `%YAML`/`%TAG` directives, and more than
//!    one document. The event stream is the ground truth for "did a tag or an
//!    anchor appear?", so the guard does not have to guess with a byte scan
//!    that would misfire inside quoted scalars.
//! 2. `serde_saphyr::from_str_with_options` deserializes into
//!    `serde_json::Value` with a tight `Budget` and
//!    `DuplicateKeyPolicy::Error` / `MergeKeyPolicy::Error` /
//!    `strict_booleans`. Every limit is a *deterministic* rejection:
//!    "the crate allows it" is not a policy.
//!
//! The `Value` intermediate (rather than `#[serde(deny_unknown_fields)]`
//! structs) is deliberate: a serde error renders the offending field path, and
//! the offending *value* on a type mismatch, either of which can be a
//! credential a user pasted into the wrong place. This module walks the value
//! itself so a diagnostic can name only an index and a constant schema label.
//! The parser's `Display`, `source()` and `Debug` are never rendered; only its
//! line/column are (see `parse_error`).
//!
//! # Integrity
//!
//! The file is opened `O_NOFOLLOW` and every decision (owner, mode, type,
//! size) is taken on that one descriptor, so a symlink or a swap between the
//! check and the read cannot redirect it. An absent file is a valid **empty**
//! authorization set; an unreadable, foreign-owned, group/other-writable or
//! malformed file is a refusal. Group/other-*readable* only warns: the file
//! holds no values, and refusing would break the common `0644` default for no
//! gain.

use std::collections::BTreeMap;
use std::fmt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use vstd::prelude::*;

use crate::config::USER_CONFIG_DIR_RELATIVE;
use crate::host_paths::{HostFileFacts, read_bounded_regular_file_no_follow};
use crate::secret_store::ServiceName;

/// File name inside [`USER_CONFIG_DIR_RELATIVE`].
pub(crate) const CREDENTIALS_FILE_NAME: &str = "credentials.yaml";

/// Ceiling on the file read. A names-and-destinations file; 64 KiB is far above
/// any real authorization list and far below anything that could make a launch
/// slow.
pub(crate) const MAX_CREDENTIALS_FILE_BYTES: u64 = 64 * 1024;

/// A bare `domain` (AC7).
pub(crate) const DEFAULT_HTTPS_PORT: u16 = 443;
/// Structural YAML nesting the schema can possibly need. The real shape is
/// 4 deep; 16 leaves room for a generous future field and rejects a
/// nesting bomb deterministically.
const MAX_YAML_NODES: usize = 4096;
const MAX_YAML_EVENTS: usize = 8192;

/// The non-secret placeholder published to the guest when `sentinelEnv` is
/// true. Docker's literal; it carries no substitution authority and no claim
/// is made that it satisfies any consumer's key-shape validation.
pub(crate) const SENTINEL_ENV_VALUE: &str = "proxy-managed";

/// Field names this release recognizes but deliberately does not support. Each
/// is rejected **by name** rather than falling through to the generic
/// "unknown field" message, because the user's fix differs per category (AC4).
/// The messages are constants; the user's text is never interpolated.
const UNSUPPORTED_ENTRY_FIELDS: &[(&str, &str)] = &[
    (
        "source",
        "`source` is not supported in this release; the only source is the agent-vm keychain item \
         named by `service` (agent-vm#163 adds an environment source)",
    ),
    (
        "permissions",
        "`permissions` is not supported; network authorization is expressed by the exact origin \
         of each `inject` entry, and an authorization never opens egress on its own",
    ),
    (
        "oauth",
        "OAuth is not supported; this release injects an API key into a header",
    ),
    (
        "basic",
        "HTTP basic auth is not supported; this release injects an API key into a header",
    ),
    (
        "username",
        "`username` is not supported; this release injects an API key into a header",
    ),
    (
        "signing",
        "request signing is not supported; this release injects a static header value",
    ),
    (
        "query",
        "injecting into the query string is not supported; only a request header may carry the \
         value",
    ),
    (
        "body",
        "injecting into the request body is not supported; only a request header may carry the \
         value",
    ),
    ("kit", "kit extensions are not supported"),
    ("hooks", "hooks are not supported"),
    ("images", "`images` is not supported"),
    ("mounts", "`mounts` is not supported"),
    ("ports", "`ports` is not supported"),
    (
        "composition",
        "compose-style configuration is not supported",
    ),
];

/// Field names recognized-but-unsupported inside `apiKey`.
const UNSUPPORTED_API_KEY_FIELDS: &[(&str, &str)] = &[
    (
        "value",
        "a literal `value` is not supported; store the value with `agent-vm secret set` and name \
         it with `service`",
    ),
    (
        "source",
        "`apiKey.source` is not supported; the source is the agent-vm keychain item named by the \
         entry's `service`",
    ),
    (
        "env",
        "`apiKey.env` is not supported; the source is the keychain item named by the entry's \
         `service` (agent-vm#163 adds an environment source)",
    ),
];

/// Field names recognized-but-unsupported inside one `inject` entry.
const UNSUPPORTED_INJECT_FIELDS: &[(&str, &str)] = &[
    (
        "query",
        "injecting into the query string is not supported; only the configured header may carry \
         the value",
    ),
    (
        "body",
        "injecting into the request body is not supported; only the configured header may carry \
         the value",
    ),
    (
        "cookies",
        "injecting into cookies is not supported; only the configured header may carry the value",
    ),
    (
        "url",
        "`url` is not supported; write `domain` (with an optional `:port`)",
    ),
    (
        "value",
        "a literal `value` is not supported; the value comes from the keychain at launch time",
    ),
];

// ---------------------------------------------------------------------------
// Validated types
// ---------------------------------------------------------------------------

/// The whole validated authorization, keyed by canonical (case-folded)
/// [`ServiceName`] so a lookup cannot disagree with the keychain account.
#[derive(Debug)]
pub(crate) struct AuthorizationSet {
    entries: BTreeMap<ServiceName, AuthorizedCredential>,
    rules: usize,
    warnings: Vec<String>,
}

impl AuthorizationSet {
    pub(crate) fn empty() -> Self {
        Self {
            entries: BTreeMap::new(),
            rules: 0,
            warnings: Vec::new(),
        }
    }

    pub(crate) fn get(&self, service: &ServiceName) -> Option<&AuthorizedCredential> {
        self.entries.get(service)
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub(crate) fn rules(&self) -> usize {
        self.rules
    }

    /// Non-fatal observations (file mode, `proxyManaged` alias use). A caller
    /// decides whether to surface them; nothing here is a value.
    pub(crate) fn warnings(&self) -> &[String] {
        &self.warnings
    }
}

/// One authorized credential. Holds no value: the value lives in the keychain
/// and is read only by an authorized launch's resolver.
#[derive(Debug)]
pub(crate) struct AuthorizedCredential {
    service: ServiceName,
    /// Docker's human-readable label. Accepted (AC1) and deliberately never
    /// rendered: a diagnostic names an index and a constant schema label only.
    /// Kept rather than dropped so the schema documents it and a future
    /// `doctor` cannot start printing free-form user text without an edit.
    #[allow(dead_code)]
    description: Option<String>,
    required: bool,
    env_name: GuestEnvName,
    sentinel_env: bool,
    inject: Vec<InjectionRule>,
}

impl AuthorizedCredential {
    /// Whether a failed or unavailable source is a hard error before boot.
    pub(crate) fn required(&self) -> bool {
        self.required
    }

    /// The guest environment variable named by `apiKey.name`.
    pub(crate) fn env_name(&self) -> &GuestEnvName {
        &self.env_name
    }

    /// Whether the guest variable receives the non-secret sentinel
    /// ([`SENTINEL_ENV_VALUE`]) or is left unset. Injection is independent of
    /// this (AC2).
    pub(crate) fn sentinel_env(&self) -> bool {
        self.sentinel_env
    }

    pub(crate) fn inject(&self) -> &[InjectionRule] {
        &self.inject
    }
}

/// Guest environment variable names agent-vm itself **always** publishes, so an
/// authorization must not own them: AC2's "leave unset" cannot be honored for a
/// variable the launcher must set, and the honest fail-closed answer is to
/// refuse the authorization rather than emit a contradicting default.
///
/// Enumerated from `run.rs`'s actual emission points, not invented here:
/// `GUEST_ALWAYS_ENV` (`IS_SANDBOX`, `LANG`) and the image-derived `PATH`. The
/// guest-identity triple (`HOME`/`USER`/`LOGNAME`) and the `MSB_` prefix are the
/// same policy and are checked alongside these in [`GuestEnvName::parse`].
pub(crate) const LAUNCHER_OWNED_ENV_NAMES: &[&str] = &["IS_SANDBOX", "LANG", "PATH"];

const LAUNCHER_OWNED_ENV_RULE: &str = "agent-vm always publishes this variable, so a credential cannot own it: it is either a \
     launcher constant (IS_SANDBOX, LANG, PATH), the guest identity (HOME, USER, LOGNAME), or in \
     the reserved `MSB_` namespace; choose a different `apiKey.name`";

/// A guest environment variable name, validated at the boundary.
///
/// Shape: `[A-Za-z_][A-Za-z0-9_]*`, at most [`MAX_ENV_NAME_BYTES`] bytes. The
/// `MSB_` prefix, the guest-identity triple and the launcher-owned names are
/// rejected outright, because all three are published as *guest* environment by
/// agent-vm itself and the SDK/build would otherwise fail later (or, worse,
/// silently emit a value AC2 promised to leave unset) with no file or
/// declaration to point at.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct GuestEnvName(String);

impl GuestEnvName {
    /// The trusted adapter around the proved [`guest_env_name_is_valid_bytes`]
    /// (ADR-0018): the `&str` → bytes measurement is outside the proof.
    pub(crate) fn parse(raw: &str) -> std::result::Result<Self, &'static str> {
        if !guest_env_name_is_valid_bytes(raw.as_bytes()) {
            return Err(ENV_NAME_RULE);
        }
        if raw.starts_with("MSB_") {
            return Err("the `MSB_` prefix is reserved by microsandbox");
        }
        if matches!(raw, "HOME" | "USER" | "LOGNAME") {
            return Err("agent-vm owns the guest identity environment");
        }
        if LAUNCHER_OWNED_ENV_NAMES.contains(&raw) {
            return Err(LAUNCHER_OWNED_ENV_RULE);
        }
        Ok(Self(raw.to_owned()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GuestEnvName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One exact HTTPS origin plus the header and template the value may occupy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InjectionRule {
    host: String,
    port: u16,
    header: String,
    format: String,
}

impl InjectionRule {
    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    pub(crate) fn header(&self) -> &str {
        &self.header
    }

    pub(crate) fn format(&self) -> &str {
        &self.format
    }
}

verus! {

/// Mirrors microsandbox's `MAX_HEADER_CREDENTIALS`.
pub(crate) const MAX_AUTHORIZATIONS: usize = 32;
/// Mirrors microsandbox's `MAX_HEADER_CREDENTIALS`, counted per injection rule.
pub(crate) const MAX_INJECTION_RULES: usize = 32;
/// Mirrors microsandbox's `MAX_HEADER_CREDENTIAL_FORMAT_BYTES`.
pub(crate) const MAX_FORMAT_BYTES: usize = 256;
/// Mirrors the runtime's origin-host checks (`> 253` rejected).
pub(crate) const MAX_HOST_BYTES: usize = 253;
pub(crate) const MAX_LABEL_BYTES: usize = 63;
/// An env name crosses `execve`; 128 bytes is far above any real name.
pub(crate) const MAX_ENV_NAME_BYTES: usize = 128;
/// Structural YAML nesting the schema can possibly need.
pub(crate) const MAX_STRUCTURAL_DEPTH: usize = 16;


// ---------------------------------------------------------------------------
// The proved predicates (ADR-0018)
// ---------------------------------------------------------------------------
//
// One `verus!` block for this module, in place, no moved code. Every constant
// a spec function mentions lives here so the spec can name it. The exec bodies
// restate the spec expressions inline: a `spec fn` erases under a plain build,
// so an exec call to one would not compile (the same rule `secret_store.rs`
// records).

/// An accepted header-name byte: an RFC 9110 `tchar` that is not uppercase.
///
/// The set is written out flat (rather than as "`tchar` minus uppercase") so
/// the exec body below can restate exactly this expression; a nested spec call
/// is one more thing the prover has to unfold, and the flat form is what the
/// runtime's own `is_http_token` + uppercase check amounts to.
pub(crate) open spec fn header_name_byte_allowed(byte: u8) -> bool {
    (b'a' <= byte && byte <= b'z')
        || (b'0' <= byte && byte <= b'9')
        || byte == b'!' || byte == b'#'
        || byte == b'$' || byte == b'%'
        || byte == b'&' || byte == b'\''
        || byte == b'*' || byte == b'+'
        || byte == b'-' || byte == b'.'
        || byte == b'^' || byte == b'_'
        || byte == b'`' || byte == b'|'
        || byte == b'~'
}

/// The whole header-name decision: a non-empty lowercase token. The runtime
/// additionally refuses a fixed framing/hop-by-hop set (`forbidden_header`),
/// which is a policy list, not a shape, and is deliberately outside this
/// contract.
pub(crate) open spec fn header_name_is_valid_spec(bytes: Seq<u8>) -> bool {
    1 <= bytes.len() && forall|i: int| 0 <= i < bytes.len() ==> header_name_byte_allowed(bytes[i])
}

// The `<=` spelling (rather than clippy's suggested `(b'a'..=b'z').contains`)
// is kept so the exec bytes stay syntactically the expression the `verus!`
// spec fn unfolds to; the same allow and the same reason as `secret_store.rs`.
#[allow(clippy::manual_range_contains)]
pub(crate) fn header_name_is_valid_bytes(bytes: &[u8]) -> (ok: bool)
    ensures ok == header_name_is_valid_spec(bytes@),
{
    let len = bytes.len();
    if len == 0 {
        return false;
    }
    let mut i: usize = 0;
    while i < len
        invariant
            i <= len,
            len == bytes@.len(),
            forall|j: int| 0 <= j < i ==> header_name_byte_allowed(bytes@[j]),
        decreases len - i,
    {
        let byte = bytes[i];
        assert(header_name_byte_allowed(byte) == (
            (b'a' <= byte && byte <= b'z')
                || (b'0' <= byte && byte <= b'9')
                || byte == b'!' || byte == b'#'
                || byte == b'$' || byte == b'%'
                || byte == b'&' || byte == b'\''
                || byte == b'*' || byte == b'+'
                || byte == b'-' || byte == b'.'
                || byte == b'^' || byte == b'_'
                || byte == b'`' || byte == b'|'
                || byte == b'~'
        ));
        if !((b'a' <= byte && byte <= b'z')
            || (b'0' <= byte && byte <= b'9')
            || byte == b'!' || byte == b'#'
            || byte == b'$' || byte == b'%'
            || byte == b'&' || byte == b'\''
            || byte == b'*' || byte == b'+'
            || byte == b'-' || byte == b'.'
            || byte == b'^' || byte == b'_'
            || byte == b'`' || byte == b'|'
            || byte == b'~')
        {
            return false;
        }
        i += 1;
    }
    true
}

/// An accepted guest-env-name byte after the first: `[A-Za-z0-9_]`.
pub(crate) open spec fn guest_env_name_byte_allowed(byte: u8) -> bool {
    (b'a' <= byte && byte <= b'z')
        || (b'A' <= byte && byte <= b'Z')
        || (b'0' <= byte && byte <= b'9')
        || byte == b'_'
}

/// The first byte additionally cannot be a digit.
pub(crate) open spec fn guest_env_name_first_byte_allowed(byte: u8) -> bool {
    (b'a' <= byte && byte <= b'z') || (b'A' <= byte && byte <= b'Z') || byte == b'_'
}

/// The whole guest-env-name decision: `[A-Za-z_][A-Za-z0-9_]*`, 1..=`MAX_ENV_NAME_BYTES`.
pub(crate) open spec fn guest_env_name_is_valid_spec(bytes: Seq<u8>) -> bool {
    1 <= bytes.len() && bytes.len() <= MAX_ENV_NAME_BYTES
        && guest_env_name_first_byte_allowed(bytes[0])
        && forall|i: int| 1 <= i < bytes.len() ==> guest_env_name_byte_allowed(bytes[i])
}

#[allow(clippy::manual_range_contains)]
pub(crate) fn guest_env_name_is_valid_bytes(bytes: &[u8]) -> (ok: bool)
    ensures ok == guest_env_name_is_valid_spec(bytes@),
{
    let len = bytes.len();
    if len == 0 || len > MAX_ENV_NAME_BYTES {
        return false;
    }
    let first = bytes[0];
    assert(guest_env_name_first_byte_allowed(first) == (
        (b'a' <= first && first <= b'z')
            || (b'A' <= first && first <= b'Z')
            || first == b'_'
    ));
    if !((b'a' <= first && first <= b'z')
        || (b'A' <= first && first <= b'Z')
        || first == b'_')
    {
        return false;
    }
    let mut i: usize = 1;
    while i < len
        invariant
            i <= len,
            len == bytes@.len(),
            1 <= len,
            len <= MAX_ENV_NAME_BYTES,
            guest_env_name_first_byte_allowed(bytes@[0]),
            forall|j: int| 1 <= j < i ==> guest_env_name_byte_allowed(bytes@[j]),
        decreases len - i,
    {
        let byte = bytes[i];
        assert(guest_env_name_byte_allowed(byte) == (
            (b'a' <= byte && byte <= b'z')
                || (b'A' <= byte && byte <= b'Z')
                || (b'0' <= byte && byte <= b'9')
                || byte == b'_'
        ));
        if !((b'a' <= byte && byte <= b'z')
            || (b'A' <= byte && byte <= b'Z')
            || (b'0' <= byte && byte <= b'9')
            || byte == b'_')
        {
            return false;
        }
        i += 1;
    }
    true
}

/// Resource limit: at most `MAX_AUTHORIZATIONS` entries. Stated plainly: what
/// is proved is that the decision *is* that comparison.
pub(crate) open spec fn authorization_count_within_limit_spec(count: usize) -> bool {
    count <= MAX_AUTHORIZATIONS
}

pub(crate) fn authorization_count_within_limit(count: usize) -> (ok: bool)
    ensures ok == authorization_count_within_limit_spec(count),
{
    count <= MAX_AUTHORIZATIONS
}

/// Resource limit: at most `MAX_INJECTION_RULES` rules across the file.
pub(crate) open spec fn injection_rule_count_within_limit_spec(count: usize) -> bool {
    count <= MAX_INJECTION_RULES
}

pub(crate) fn injection_rule_count_within_limit(count: usize) -> (ok: bool)
    ensures ok == injection_rule_count_within_limit_spec(count),
{
    count <= MAX_INJECTION_RULES
}

/// Resource limit: YAML structure no deeper than `MAX_STRUCTURAL_DEPTH`. The
/// pre-parse guard counts nesting and refuses through this predicate, so the
/// documented depth is a policy this module enforces rather than a parser
/// default.
pub(crate) open spec fn structural_depth_within_limit_spec(depth: usize) -> bool {
    depth <= MAX_STRUCTURAL_DEPTH
}

pub(crate) fn structural_depth_within_limit(depth: usize) -> (ok: bool)
    ensures ok == structural_depth_within_limit_spec(depth),
{
    depth <= MAX_STRUCTURAL_DEPTH
}

// ---------------------------------------------------------------------------
// The format and origin-host contracts (#161 review, M5)
// ---------------------------------------------------------------------------
//
// Both are decisions on untrusted input that the brief required to be
// machine-checked (ADR-0018): the `%s`-placeholder count and the origin-host
// byte shape. The `&str`/`Path` -> bytes measurement stays a trusted adapter
// outside this block (the callers).

/// An accepted origin-host byte: lowercase letter, digit or `-`.
///
/// Written out flat so the exec bodies can restate exactly this expression, the
/// same reason [`header_name_byte_allowed`] is flat.
pub(crate) open spec fn ldh_byte_allowed(byte: u8) -> bool {
    (b'a' <= byte && byte <= b'z') || (b'0' <= byte && byte <= b'9') || byte == b'-'
}

/// Non-overlapping `%s` occurrences, the same count `str::matches("%s")`
/// produces (so `%%s` counts one). Recursive so the executable body below is a
/// direct structural match; the recursion terminates on the shrinking slice.
pub(crate) open spec fn count_placeholders_spec(bytes: Seq<u8>) -> nat
    decreases bytes.len(),
{
    if bytes.len() < 2 {
        0
    } else if bytes[0] == b'%' && bytes[1] == b's' {
        1 + count_placeholders_spec(bytes.subrange(2, bytes.len() as int))
    } else {
        count_placeholders_spec(bytes.subrange(1, bytes.len() as int))
    }
}

pub(crate) fn count_placeholders(bytes: &[u8]) -> (count: usize)
    ensures
        count == count_placeholders_spec(bytes@),
        // Bounds the recursive `1 +`, so the addition provably cannot overflow
        // (the count never exceeds the bytes it consumes).
        count <= bytes@.len(),
    decreases bytes.len(),
{
    if bytes.len() < 2 {
        0
    } else if bytes[0] == b'%' && bytes[1] == b's' {
        1 + count_placeholders(&bytes[2..])
    } else {
        count_placeholders(&bytes[1..])
    }
}

/// All bytes are printable ASCII (the header-value alphabet).
pub(crate) open spec fn printable_ascii_spec(bytes: Seq<u8>) -> bool {
    forall|i: int| 0 <= i < bytes.len() ==> 0x20 <= #[trigger] bytes[i] <= 0x7e
}

// The `<=` spelling is kept so the exec body restates the expression the spec
// unfolds to; same allow and reason as `header_name_is_valid_bytes`.
#[allow(clippy::manual_range_contains)]
pub(crate) fn bytes_are_printable_ascii(bytes: &[u8]) -> (ok: bool)
    ensures ok == printable_ascii_spec(bytes@),
{
    let mut i: usize = 0;
    while i < bytes.len()
        invariant
            i <= bytes.len(),
            bytes@.len() == bytes.len(),
            forall|j: int| 0 <= j < i ==> 0x20 <= #[trigger] bytes@[j] <= 0x7e,
        decreases bytes.len() - i,
    {
        let byte = bytes[i];
        if !(0x20 <= byte && byte <= 0x7e) {
            assert(!(0x20 <= bytes@[i as int] <= 0x7e));
            return false;
        }
        i += 1;
    }
    true
}

/// The whole `format` acceptance decision: <= [`MAX_FORMAT_BYTES`] bytes, all
/// printable ASCII, and exactly one non-overlapping `%s`.
pub(crate) open spec fn format_placeholder_count_is_one_spec(bytes: Seq<u8>) -> bool {
    bytes.len() <= MAX_FORMAT_BYTES
        && printable_ascii_spec(bytes)
        && count_placeholders_spec(bytes) == 1
}

pub(crate) fn format_placeholder_count_is_one(bytes: &[u8]) -> (ok: bool)
    ensures ok == format_placeholder_count_is_one_spec(bytes@),
{
    bytes.len() <= MAX_FORMAT_BYTES
        && bytes_are_printable_ascii(bytes)
        && count_placeholders(bytes) == 1
}

/// Whether `bytes[i..]` continues a valid LDH host given the scanner state:
/// `label_len` bytes into the current label, and `prev_dash` whether the byte
/// just consumed was `-`. At the end of the input the final label must be
/// complete (non-empty, <= [`MAX_LABEL_BYTES`]) and must not end in `-`.
///
/// This is the byte-exact kernel of [`origin_host_is_exact_bytes`]; the
/// canonicalization and the IP-literal/IP policy checks stay outside it.
pub(crate) open spec fn host_prefix_ok(
    bytes: Seq<u8>,
    i: int,
    label_len: int,
    prev_dash: bool,
) -> bool
    decreases bytes.len() - i,
{
    if i >= bytes.len() {
        label_len >= 1 && label_len <= MAX_LABEL_BYTES && !prev_dash
    } else if bytes[i] == b'.' {
        label_len >= 1 && label_len <= MAX_LABEL_BYTES && !prev_dash
            && host_prefix_ok(bytes, i + 1, 0, false)
    } else {
        ldh_byte_allowed(bytes[i])
            && !(label_len == 0 && bytes[i] == b'-')
            && label_len < MAX_LABEL_BYTES
            && host_prefix_ok(bytes, i + 1, label_len + 1, bytes[i] == b'-')
    }
}

/// The LDH *byte shape* of a canonical origin host: non-empty, <= 253 bytes,
/// only `[a-z0-9.-]`, no trailing dot, and non-empty labels of <= 63 bytes that
/// neither start nor end with `-`.
pub(crate) open spec fn origin_host_is_exact_spec(bytes: Seq<u8>) -> bool {
    1 <= bytes.len() && bytes.len() <= MAX_HOST_BYTES && host_prefix_ok(bytes, 0, 0, false)
}

// The recursive body mirrors `host_prefix_ok` clause for clause, so the
// postcondition is definitional; the value is that the accepted language is
// *specified* and the executable form cannot drift from it silently.
#[allow(clippy::manual_range_contains)]
fn host_prefix_ok_exec(
    bytes: &[u8],
    i: usize,
    label_len: usize,
    prev_dash: bool,
) -> (ok: bool)
    ensures ok == host_prefix_ok(bytes@, i as int, label_len as int, prev_dash),
    decreases bytes.len() - i,
{
    if i >= bytes.len() {
        label_len >= 1 && label_len <= MAX_LABEL_BYTES && !prev_dash
    } else {
        let byte = bytes[i];
        if byte == b'.' {
            label_len >= 1 && label_len <= MAX_LABEL_BYTES && !prev_dash
                && host_prefix_ok_exec(bytes, i + 1, 0, false)
        } else {
            let allowed = (b'a' <= byte && byte <= b'z')
                || (b'0' <= byte && byte <= b'9')
                || byte == b'-';
            assert(allowed == ldh_byte_allowed(byte));
            allowed
                && !(label_len == 0 && byte == b'-')
                && label_len < MAX_LABEL_BYTES
                && host_prefix_ok_exec(bytes, i + 1, label_len + 1, byte == b'-')
        }
    }
}

#[allow(clippy::len_zero)]
pub(crate) fn origin_host_is_exact_bytes(bytes: &[u8]) -> (ok: bool)
    ensures ok == origin_host_is_exact_spec(bytes@),
{
    1 <= bytes.len() && bytes.len() <= MAX_HOST_BYTES && host_prefix_ok_exec(bytes, 0, 0, false)
}

} // verus!

/// Framing and hop-by-hop fields a credential value must never reach. Mirrors
/// the runtime's `is_forbidden_credential_header`.
pub(crate) fn forbidden_header(header: &str) -> bool {
    matches!(
        header,
        "host"
            | "content-length"
            | "transfer-encoding"
            | "connection"
            | "upgrade"
            | "te"
            | "trailer"
            | "proxy-authorization"
            | "proxy-connection"
    )
}

// ---------------------------------------------------------------------------
// Rejection labels (constants only; never the input)
// ---------------------------------------------------------------------------

const ENV_NAME_RULE: &str = "'apiKey.name' must be 1-128 characters from [A-Za-z0-9_] and must not start with a digit; \
     the supplied name does not match and is not shown here";

const DOMAIN_EMPTY: &str = "`domain` must not be empty";
const DOMAIN_CONTROL: &str =
    "`domain` must not contain whitespace, control characters or non-ASCII bytes";
const DOMAIN_NON_ASCII: &str =
    "`domain` must be ASCII; write a non-ASCII host name as its A-label (punycode)";
const DOMAIN_SCHEME: &str = "`domain` must be a bare host name; remove the scheme (this release injects only over HTTPS, \
     decided by the live TLS server name)";
const DOMAIN_WILDCARD: &str = "`domain` must be one exact host; wildcards are not supported (a wildcard would authorize \
     every subdomain)";
const DOMAIN_USERINFO: &str = "`domain` must not contain userinfo (`user@host`)";
const DOMAIN_PATH: &str = "`domain` must not contain a path";
const DOMAIN_QUERY: &str = "`domain` must not contain a query or fragment";
const DOMAIN_IP_LITERAL: &str =
    "`domain` must be a DNS name, not an IP literal; authorization is by the TLS server name";
const DOMAIN_MALFORMED: &str = "`domain` is not a well-formed host name (lowercase letters, digits, `-` and `.`; each label \
     1-63 bytes; 253 bytes total; no leading or trailing `-`)";
const DOMAIN_TOO_LONG: &str = "`domain` is longer than 253 bytes";
const DOMAIN_EMPTY_HOST: &str = "`domain` has a port separator but no host";
const DOMAIN_PORT_MALFORMED: &str = "the port in `domain` must be decimal digits only";
const DOMAIN_PORT_RANGE: &str = "the port in `domain` must be between 1 and 65535";
const HEADER_MALFORMED: &str =
    "`header` must be a lowercase RFC 9110 token (letters, digits and `!#$%&'*+-.^_`|~`)";
const HEADER_FORBIDDEN: &str =
    "`header` is a framing or hop-by-hop field, which a credential value must never occupy";
const FORMAT_RULE: &str =
    "`format` must be 1-256 printable ASCII bytes containing exactly one `%s` placeholder";
const SCHEME_UNKNOWN: &str = "`scheme` must be `bearer` (the only supported shorthand); use `header` + `format` for \
     anything else";

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// Where the file lives, given `$HOME`.
pub(crate) fn path_under_home(home: &Path) -> PathBuf {
    home.join(USER_CONFIG_DIR_RELATIVE)
        .join(CREDENTIALS_FILE_NAME)
}

/// Load and validate the authorization file for `home`.
///
/// An absent file (or absent directory) is a valid **empty** set, not an
/// error: a user who has not authorized anything gets today's behaviour. Every
/// other failure is a refusal that names the file and carries no file content.
pub(crate) fn load(home: &Path) -> Result<AuthorizationSet> {
    let path = path_under_home(home);

    // Existence is a fact from `symlink_metadata`, so "absent" is not inferred
    // from a failed read. A symlink *here* is not followed by the read below.
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(AuthorizationSet::empty());
        }
        Err(error) => {
            return Err(file_error(
                &path,
                format_args!("could not be examined ({error})"),
            ));
        }
        Ok(_) => {}
    }

    let parent = path
        .parent()
        .ok_or_else(|| file_error(&path, "has no parent directory"))?;
    let dir_meta = std::fs::metadata(parent).map_err(|error| {
        file_error(
            &path,
            format_args!("its directory could not be examined ({error})"),
        )
    })?;
    if !dir_meta.is_dir() {
        return Err(file_error(&path, "its directory is not a directory"));
    }
    if dir_meta.uid() != current_euid() {
        return Err(file_error(
            &path,
            "its directory is owned by another user; refusing to trust it",
        ));
    }
    if dir_meta.mode() & 0o022 != 0 {
        return Err(file_error(
            &path,
            "its directory is group- or other-writable; refusing to trust it (run `chmod go-w` \
             on the directory)",
        ));
    }

    let (bytes, facts) =
        match read_bounded_regular_file_no_follow(&path, MAX_CREDENTIALS_FILE_BYTES) {
            Ok(read) => read,
            Err(error) => {
                return Err(file_error(
                    &path,
                    format_args!("could not be read ({error:#})"),
                ));
            }
        };
    check_facts(&path, &facts)?;

    let mut warnings = Vec::new();
    if facts.mode & 0o044 != 0 {
        warnings.push(format!(
            "{} is group- or other-readable; it holds no secret values, but `chmod go-r` is \
             still good hygiene",
            path.display()
        ));
    }

    let text = decode(&path, &bytes)?;
    let mut set = parse(&path, text)?;
    // The mode warning is prepended so a file-mode observation always reads
    // first, whatever the entries contributed.
    for warning in warnings.into_iter().rev() {
        set.warnings.insert(0, warning);
    }
    Ok(set)
}

/// Owner, mode and size decisions, all taken on the opened descriptor's own
/// facts (never a second path lookup).
fn check_facts(path: &Path, facts: &HostFileFacts) -> Result<()> {
    if facts.uid != current_euid() {
        return Err(file_error(
            path,
            "is owned by another user; refusing to trust it",
        ));
    }
    if facts.mode & 0o022 != 0 {
        return Err(file_error(
            path,
            "is group- or other-writable; refusing to trust it (run `chmod go-w` on the file)",
        ));
    }
    Ok(())
}

/// `euid` is the identity the kernel checked when it opened the file.
fn current_euid() -> u32 {
    // SAFETY: `geteuid` is an argument-free libc call with no preconditions.
    unsafe { libc::geteuid() }
}

fn file_error(path: &Path, detail: impl fmt::Display) -> anyhow::Error {
    anyhow!("{}: {detail}", path.display())
}

/// A strict decoder. UTF-8 only, and no CR, NUL or BOM: a CRLF file is not one
/// this project's documented editors produce, and rejecting it keeps exactly
/// one line-ending assumption in the grammar. The error never quotes bytes.
fn decode<'a>(path: &Path, bytes: &'a [u8]) -> Result<&'a str> {
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err(file_error(path, "starts with a UTF-8 byte-order mark"));
    }
    if bytes.contains(&0) {
        return Err(file_error(path, "contains a NUL byte"));
    }
    if bytes.contains(&b'\r') {
        return Err(file_error(
            path,
            "contains a carriage return; this file must use LF line endings",
        ));
    }
    std::str::from_utf8(bytes).map_err(|_| file_error(path, "is not valid UTF-8"))
}

// ---------------------------------------------------------------------------
// Pass 1: the pre-parse guard
// ---------------------------------------------------------------------------

/// Refuse every YAML feature the schema does not need but that carries weight:
/// anchors, aliases, tags, directives and additional documents.
///
/// The event stream, not a byte scan, is the ground truth: `keep_tags(true)`
/// makes explicit tags visible as events, so a `!` inside a quoted scalar is
/// correctly ignored. Anything the parser itself cannot make sense of is also a
/// refusal (fail closed).
fn guard_unsupported_syntax(path: &Path, text: &str) -> Result<()> {
    use serde_saphyr::granit_parser::{Event, Parser};

    // Structural depth is counted here as well as bounded by the serde
    // options below: the guard refuses before the more expensive pass, and it
    // is the pass that makes the documented limit a *policy* rather than a
    // parser default.
    let mut depth = 0usize;

    // A directive may only appear before the document's first content, so a
    // single leading scan over the first meaningful line covers `%YAML`/`%TAG`.
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with('%') {
            return Err(file_error(
                path,
                "declares a YAML directive (`%YAML`/`%TAG`), which is not supported",
            ));
        }
        break;
    }

    let mut documents = 0usize;
    for item in Parser::new_from_str(text).keep_tags(true) {
        let (event, _span) = item
            .map_err(|_| file_error(path, "is not valid YAML (the offending text is not shown)"))?;
        match &event {
            Event::DocumentStart(_explicit, version) => {
                documents += 1;
                if documents > 1 {
                    return Err(file_error(
                        path,
                        "contains more than one YAML document (`---`); exactly one is allowed",
                    ));
                }
                if version.is_some() {
                    return Err(file_error(
                        path,
                        "declares a YAML version (`%YAML`), which is not supported",
                    ));
                }
            }
            Event::Alias(_) => {
                return Err(file_error(
                    path,
                    "uses a YAML alias (`*name`), which is not supported",
                ));
            }
            Event::SequenceStart(..) | Event::MappingStart(..) => {
                depth += 1;
                if !structural_depth_within_limit(depth) {
                    return Err(file_error(
                        path,
                        format_args!(
                            "nests more than {MAX_STRUCTURAL_DEPTH} levels deep; this file's \
                             structure is a list of fixed-shape entries"
                        ),
                    ));
                }
            }
            Event::SequenceEnd | Event::MappingEnd => depth = depth.saturating_sub(1),
            _ => {}
        }
        if event.anchor_id().is_some() {
            return Err(file_error(
                path,
                "uses a YAML anchor (`&name`), which is not supported",
            ));
        }
        if event.tag().is_some() {
            return Err(file_error(
                path,
                "uses a YAML tag (`!name` or `!!type`), which is not supported",
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Pass 2: bounded deserialization
// ---------------------------------------------------------------------------

fn parse_error(path: &Path, error: &serde_saphyr::Error) -> anyhow::Error {
    // Only the location crosses this boundary. `Error`'s `Display`, `Debug` and
    // `source()` can all quote input text, so none of them is rendered.
    match error.location() {
        Some(location) => file_error(
            path,
            format_args!(
                "line {} column {}: not valid YAML for this schema (the offending text is not \
                 shown)",
                location.line(),
                location.column()
            ),
        ),
        None => file_error(
            path,
            "is not valid YAML for this schema (the offending text is not shown)",
        ),
    }
}

fn serde_options() -> serde_saphyr::Options {
    serde_saphyr::options! {
        budget: serde_saphyr::budget! {
            max_documents: 1,
            max_depth: MAX_STRUCTURAL_DEPTH,
            max_nodes: MAX_YAML_NODES,
            max_events: MAX_YAML_EVENTS,
            max_aliases: 0,
            max_anchors: 0,
            max_merge_keys: 0,
            max_total_scalar_bytes: MAX_CREDENTIALS_FILE_BYTES as usize,
            enforce_alias_anchor_ratio: false,
        },
        duplicate_keys: serde_saphyr::DuplicateKeyPolicy::Error,
        merge_keys: serde_saphyr::MergeKeyPolicy::Error,
        strict_booleans: true,
        // Snippets re-render the offending line; never.
        with_snippet: false,
        crop_radius: 0,
    }
}

fn parse(path: &Path, text: &str) -> Result<AuthorizationSet> {
    guard_unsupported_syntax(path, text)?;
    if text.trim().is_empty() {
        return Ok(AuthorizationSet::empty());
    }
    let value: serde_json::Value = serde_saphyr::from_str_with_options(text, serde_options())
        .map_err(|error| parse_error(path, &error))?;
    convert(path, value)
}

// ---------------------------------------------------------------------------
// The schema walk
// ---------------------------------------------------------------------------

/// Only the index path and constant schema labels reach a message. The
/// `detail` is always one of this module's constants.
fn at(path: &Path, index_path: &str, detail: impl fmt::Display) -> anyhow::Error {
    file_error(path, format_args!("{index_path}: {detail}"))
}

fn convert(path: &Path, value: serde_json::Value) -> Result<AuthorizationSet> {
    let mut set = AuthorizationSet::empty();
    let Some(map) = value.as_object() else {
        if value.is_null() {
            return Ok(set);
        }
        return Err(file_error(
            path,
            "must be a mapping with a `credentials` key (the content is not shown)",
        ));
    };
    // Validate **every** root key before interpreting `credentials`: a null or
    // empty list must not shortcut the unknown-field rejection, or a file whose
    // key order puts `credentials` first could smuggle an unsupported functional
    // field past validation (the crate enables `preserve_order`, so the old
    // early return made validation order-dependent).
    for key in map.keys() {
        if key != "credentials" {
            return Err(file_error(path, UNKNOWN_TOP_LEVEL_FIELD));
        }
    }
    let Some(credentials) = map.get("credentials") else {
        return Ok(set);
    };
    // A null (or absent) list is a valid empty authorization set. Only now,
    // after every root key is known, is that interpretation safe.
    if credentials.is_null() {
        return Ok(set);
    }
    let Some(array) = credentials.as_array() else {
        return Err(at(
            path,
            "credentials",
            "must be a list (a null list is allowed and means no authorizations)",
        ));
    };
    if !authorization_count_within_limit(array.len()) {
        return Err(at(
            path,
            "credentials",
            format_args!("authorizes more than {MAX_AUTHORIZATIONS} services"),
        ));
    }

    let mut env_names: BTreeMap<String, ServiceName> = BTreeMap::new();
    let mut targets: BTreeMap<(String, u16, String), ServiceName> = BTreeMap::new();
    for (index, entry) in array.iter().enumerate() {
        let credential = convert_entry(path, index, entry, &mut set.warnings)?;
        let service = credential.service.clone();
        if set.entries.contains_key(&service) {
            return Err(at(
                path,
                &format!("credentials[{index}]"),
                format_args!(
                    "duplicates an earlier entry for the same `service` (names are folded to \
                     lowercase, so `Service` and `service` are one credential)"
                ),
            ));
        }
        if let Some(other) =
            env_names.insert(credential.env_name.as_str().to_owned(), service.clone())
        {
            return Err(at(
                path,
                &format!("credentials[{index}].apiKey.name"),
                format_args!(
                    "duplicates the guest environment variable of the `{other}` entry; two \
                     authorized credentials cannot own one variable"
                ),
            ));
        }
        for rule in &credential.inject {
            let key = (rule.host.clone(), rule.port, rule.header.clone());
            if let Some(other) = targets.insert(key, service.clone()) {
                return Err(at(
                    path,
                    &format!("credentials[{index}].apiKey.inject"),
                    format_args!(
                        "authorizes the same (origin, header) pair as the `{other}` entry; one \
                         request location may carry at most one credential"
                    ),
                ));
            }
        }
        set.rules += credential.inject.len();
        set.entries.insert(service, credential);
    }
    if !injection_rule_count_within_limit(set.rules) {
        return Err(at(
            path,
            "credentials",
            format_args!("authorizes more than {MAX_INJECTION_RULES} injection rules in total"),
        ));
    }
    Ok(set)
}

const UNKNOWN_TOP_LEVEL_FIELD: &str =
    "contains a top-level key other than `credentials` (the key is not shown)";

fn convert_entry(
    path: &Path,
    index: usize,
    entry: &serde_json::Value,
    warnings: &mut Vec<String>,
) -> Result<AuthorizedCredential> {
    let index_path = format!("credentials[{index}]");
    let object = expect_mapping(path, &index_path, entry)?;
    let api_key = entry_field(object, "apiKey");
    let mut known = vec!["service", "description", "required", "apiKey"];
    reject_unknown_fields(
        path,
        &index_path,
        object,
        &mut known,
        UNSUPPORTED_ENTRY_FIELDS,
    )?;

    let Some(service_raw) = object.get("service") else {
        return Err(at(
            path,
            &index_path,
            "must set `service` (the agent-vm keychain item to authorize)",
        ));
    };
    let Some(service_str) = service_raw.as_str() else {
        return Err(at(
            path,
            &format!("{index_path}.service"),
            "must be a string (the value is not shown)",
        ));
    };
    let service = ServiceName::parse(service_str)
        .map_err(|error| at(path, &format!("{index_path}.service"), error))?;

    let description = match object.get("description") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(text)) => Some(text.clone()),
        Some(_) => {
            return Err(at(
                path,
                &format!("{index_path}.description"),
                "must be a string (the value is not shown)",
            ));
        }
    };

    let required = match object.get("required") {
        None => false,
        Some(serde_json::Value::Bool(value)) => *value,
        Some(_) => {
            return Err(at(
                path,
                &format!("{index_path}.required"),
                "must be `true` or `false` (a quoted string or null is not a boolean)",
            ));
        }
    };

    let Some(api_key) = api_key else {
        return Err(at(
            path,
            &index_path,
            "must set `apiKey`; this release supports the API-key credential subset only",
        ));
    };
    let api_path = format!("{index_path}.apiKey");
    let api_key = expect_mapping(path, &api_path, api_key)?;
    let mut api_known = vec!["name", "sentinelEnv", "proxyManaged", "inject"];
    reject_unknown_fields(
        path,
        &api_path,
        api_key,
        &mut api_known,
        UNSUPPORTED_API_KEY_FIELDS,
    )?;

    let Some(name_raw) = api_key.get("name") else {
        return Err(at(
            path,
            &api_path,
            "must set `name` (the guest environment variable this credential owns)",
        ));
    };
    let Some(name_str) = name_raw.as_str() else {
        return Err(at(
            path,
            &format!("{api_path}.name"),
            "must be a string (the value is not shown)",
        ));
    };
    let env_name = GuestEnvName::parse(name_str)
        .map_err(|reason| at(path, &format!("{api_path}.name"), reason))?;

    let sentinel = strict_bool_field(path, &api_path, api_key, "sentinelEnv")?;
    let proxy = strict_bool_field(path, &api_path, api_key, "proxyManaged")?;
    let sentinel_env = match (sentinel, proxy) {
        (Some(left), Some(right)) if left != right => {
            return Err(at(
                path,
                &api_path,
                "`sentinelEnv` and its Docker-compatibility alias `proxyManaged` disagree; set \
                 only `sentinelEnv` (the preferred spelling), or make the two match",
            ));
        }
        (Some(value), _) | (_, Some(value)) => value,
        (None, None) => false,
    };
    if sentinel.is_none() && proxy.is_some() {
        warnings.push(format!(
            "credentials[{index}].apiKey.proxyManaged is the Docker-compatibility alias; prefer \
             `sentinelEnv`, which is this project's spelling"
        ));
    }

    let Some(inject_raw) = api_key.get("inject") else {
        return Err(at(
            path,
            &api_path,
            "must set `inject` with at least one entry authorizing one exact HTTPS origin",
        ));
    };
    let Some(rules_raw) = inject_raw.as_array() else {
        return Err(at(
            path,
            &format!("{api_path}.inject"),
            "must be a non-empty list",
        ));
    };
    if rules_raw.is_empty() {
        return Err(at(
            path,
            &format!("{api_path}.inject"),
            "must not be empty; an entry without an origin authorizes nothing",
        ));
    }
    let mut inject = Vec::with_capacity(rules_raw.len());
    for (rule_index, rule) in rules_raw.iter().enumerate() {
        inject.push(convert_rule(path, index, rule_index, rule)?);
    }

    Ok(AuthorizedCredential {
        service,
        description,
        required,
        env_name,
        sentinel_env,
        inject,
    })
}

fn entry_field<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<&'a serde_json::Value> {
    object.get(key)
}

fn strict_bool_field(
    path: &Path,
    api_path: &str,
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<Option<bool>> {
    match object.get(key) {
        None => Ok(None),
        Some(serde_json::Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(at(
            path,
            &format!("{api_path}.{key}"),
            "must be `true` or `false` (a quoted string or null is not a boolean)",
        )),
    }
}

fn convert_rule(
    path: &Path,
    index: usize,
    rule_index: usize,
    rule: &serde_json::Value,
) -> Result<InjectionRule> {
    let index_path = format!("credentials[{index}].apiKey.inject[{rule_index}]");
    let object = expect_mapping(path, &index_path, rule)?;
    let mut known = vec!["domain", "header", "format", "scheme"];
    reject_unknown_fields(
        path,
        &index_path,
        object,
        &mut known,
        UNSUPPORTED_INJECT_FIELDS,
    )?;

    let Some(domain_raw) = object.get("domain") else {
        return Err(at(
            path,
            &index_path,
            "must set `domain` (the exact HTTPS host, with an optional `:port`)",
        ));
    };
    let Some(domain) = domain_raw.as_str() else {
        return Err(at(
            path,
            &format!("{index_path}.domain"),
            "must be a string (the value is not shown)",
        ));
    };
    let (host, port) =
        parse_domain(domain).map_err(|reason| at(path, &format!("{index_path}.domain"), reason))?;

    let scheme = match object.get("scheme") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(value)) => Some(value.as_str()),
        Some(_) => {
            return Err(at(
                path,
                &format!("{index_path}.scheme"),
                "must be a string (the value is not shown)",
            ));
        }
    };
    let header_field = object.get("header");
    let format_field = object.get("format");

    let (header, format) = match scheme {
        Some("bearer") => {
            if header_field.is_some() || format_field.is_some() {
                return Err(at(
                    path,
                    &index_path,
                    "`scheme: bearer` already means `header: authorization` + \
                     `format: \"Bearer %s\"`; set either `scheme` or `header`+`format`, not both",
                ));
            }
            ("authorization".to_owned(), "Bearer %s".to_owned())
        }
        Some(_) => {
            return Err(at(path, &format!("{index_path}.scheme"), SCHEME_UNKNOWN));
        }
        None => {
            let (Some(header), Some(format)) = (header_field, format_field) else {
                return Err(at(
                    path,
                    &index_path,
                    "must set either `scheme: bearer` or both `header` and `format`",
                ));
            };
            let (Some(header), Some(format)) = (header.as_str(), format.as_str()) else {
                return Err(at(
                    path,
                    &index_path,
                    "`header` and `format` must be strings (the values are not shown)",
                ));
            };
            (header.to_owned(), format.to_owned())
        }
    };

    if !header_name_is_valid_bytes(header.as_bytes()) {
        return Err(at(path, &format!("{index_path}.header"), HEADER_MALFORMED));
    }
    if forbidden_header(&header) {
        return Err(at(path, &format!("{index_path}.header"), HEADER_FORBIDDEN));
    }
    if !format_placeholder_count_is_one(format.as_bytes()) {
        return Err(at(path, &format!("{index_path}.format"), FORMAT_RULE));
    }

    Ok(InjectionRule {
        host,
        port,
        header,
        format,
    })
}

/// The `domain` grammar. Returns the canonical `(lowercase host, port)`.
fn parse_domain(raw: &str) -> std::result::Result<(String, u16), &'static str> {
    if raw.is_empty() {
        return Err(DOMAIN_EMPTY);
    }
    if raw.contains("://") {
        return Err(DOMAIN_SCHEME);
    }
    if raw.contains('*') {
        return Err(DOMAIN_WILDCARD);
    }
    if raw.contains('@') {
        return Err(DOMAIN_USERINFO);
    }
    if raw.contains('/') {
        return Err(DOMAIN_PATH);
    }
    if raw.contains('?') || raw.contains('#') {
        return Err(DOMAIN_QUERY);
    }
    if raw.bytes().any(|byte| byte < 0x21 || byte == 0x7f) {
        return Err(DOMAIN_CONTROL);
    }
    if !raw.is_ascii() {
        return Err(DOMAIN_NON_ASCII);
    }

    let (host_raw, port) = match raw.split(':').count() {
        1 => (raw, DEFAULT_HTTPS_PORT),
        2 => {
            let (host, port_raw) = raw.split_once(':').expect("exactly one `:`");
            if host.is_empty() {
                return Err(DOMAIN_EMPTY_HOST);
            }
            if port_raw.is_empty() || !port_raw.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(DOMAIN_PORT_MALFORMED);
            }
            let port = port_raw.parse::<u32>().map_err(|_| DOMAIN_PORT_RANGE)?;
            if port == 0 || port > u32::from(u16::MAX) {
                return Err(DOMAIN_PORT_RANGE);
            }
            (host, port as u16)
        }
        // More than one `:` is an IPv6 literal attempt, whatever its brackets.
        _ => return Err(DOMAIN_IP_LITERAL),
    };

    let host = host_raw.strip_suffix('.').unwrap_or(host_raw);
    if host.is_empty() {
        return Err(DOMAIN_EMPTY_HOST);
    }
    if host.len() > MAX_HOST_BYTES {
        return Err(DOMAIN_TOO_LONG);
    }
    let host = host.to_ascii_lowercase();
    if !origin_host_is_exact_bytes(host.as_bytes()) {
        return Err(DOMAIN_MALFORMED);
    }
    // The runtime rejects anything that parses as an IP address; mirroring it
    // keeps the two grammars from disagreeing about an all-numeric host.
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Err(DOMAIN_IP_LITERAL);
    }
    Ok((host, port))
}

fn expect_mapping<'a>(
    path: &Path,
    index_path: &str,
    value: &'a serde_json::Value,
) -> Result<&'a serde_json::Map<String, serde_json::Value>> {
    match value.as_object() {
        Some(object) => Ok(object),
        None => Err(at(
            path,
            index_path,
            "must be a mapping (the content is not shown)",
        )),
    }
}

/// Reject every key outside `known`, naming the ones this module has a specific
/// message for and never echoing the rest.
fn reject_unknown_fields(
    path: &Path,
    index_path: &str,
    object: &serde_json::Map<String, serde_json::Value>,
    known: &mut Vec<&str>,
    unsupported: &[(&str, &str)],
) -> Result<()> {
    for key in object.keys() {
        if known.contains(&key.as_str()) {
            continue;
        }
        if let Some((_, message)) = unsupported.iter().find(|(name, _)| name == key) {
            return Err(at(path, index_path, *message));
        }
        known.sort_unstable();
        return Err(at(
            path,
            index_path,
            format_args!(
                "contains an unknown field (not shown); accepted keys here: {}",
                known.join(", ")
            ),
        ));
    }
    Ok(())
}

/// Test-only constructor: a rule built from already-validated-looking parts, so
/// the proxy-plan test can assert registration without a YAML fixture. The
/// grammar is exercised by this module's own tests.
#[cfg(test)]
pub(crate) fn rule_for_test(host: &str, port: u16, header: &str, format: &str) -> InjectionRule {
    InjectionRule {
        host: host.to_owned(),
        port,
        header: header.to_owned(),
        format: format.to_owned(),
    }
}

#[cfg(test)]
mod tests;
