//! The `secretspec:` table of one `credentials.yaml` entry (#202): validated,
//! value-free types and the one parse that produces them.
//!
//! Every type here is a fact about *where* a value is read from, never the
//! value. The table is user configuration, so it is validated by this module
//! rather than by the YAML parser: a refusal names the key and a constant rule,
//! and never echoes what the user wrote (the same policy `credential_yaml`
//! applies to every other field).
//!
//! # Two kinds of rule, labelled apart
//!
//! SecretSpec's own bounds (`resolver.GetParams.name`, `resolver.InitializeApplication`'s
//! `profile`/`scope`/`reason`, as published by `rpc.discover`) count **characters**
//! and impose no character class. agent-vm adds a 4096-**byte** cap, refuses
//! ASCII control characters (all three of `profile`, `scope` and `name` are
//! printed on one line by `agent-vm doctor`), and narrows `reason` to printable
//! ASCII of 1..=256 bytes. Those three are **local** restrictions and each
//! message says so, rather than presenting a local choice as an upstream fact.

use std::path::{Path, PathBuf};

use crate::credential_yaml::GuestEnvName;

/// Ceiling on a pinned path. The longest path any supported host accepts is
/// well under this; the cap exists so a hostile file cannot make a `doctor` row
/// unbounded.
pub(crate) const MAX_PINNED_PATH_BYTES: usize = 1024;

/// Upstream `maxLength` for `name`, `profile`, `scope` and `reason`
/// (`rpc.discover`), in **characters**. agent-vm additionally caps bytes;
/// see [`MAX_LABEL_BYTES`].
pub(crate) const MAX_LABEL_CHARS: usize = 4096;
/// agent-vm's own byte cap on `name`, `profile` and `scope`. JSON Schema counts
/// characters, so a 4096-character name can be four times that in bytes.
pub(crate) const MAX_LABEL_BYTES: usize = 4096;
/// agent-vm's own `reason` ceiling (see [`AuditReason`]).
pub(crate) const MAX_REASON_BYTES: usize = 256;

pub(super) const PATH_NOT_STRING: &str = "must be a string (the value is not shown)";
pub(super) const PATH_NOT_ABSOLUTE: &str = "must be an absolute path starting with `/`; agent-vm never searches `PATH` or the working \
     directory";
pub(super) const PATH_NOT_NORMAL: &str =
    "must not contain `.`, `..` or empty components, or end in `/`";
pub(super) const PATH_TOO_LONG: &str = "must be at most 1024 bytes";
pub(super) const PATH_NUL: &str = "must not contain a NUL byte";
/// Shared by `profile` and `scope`; both are one-line labels.
pub(super) const LABEL_RULE: &str = "must be a non-empty string of at most 4096 characters (JSON \
     Schema `maxLength`; agent-vm also caps it at 4096 bytes) with no control character";
pub(super) const NAME_RULE: &str = "must be a non-empty string of at most 4096 characters (JSON \
     Schema `maxLength`; agent-vm also caps it at 4096 bytes) with no control character";
pub(super) const REASON_RULE: &str = "must be 1 to 256 printable ASCII bytes; this is an agent-vm \
     limit, not a SecretSpec requirement";
pub(super) const EXECUTABLE_REQUIRED: &str = "`source: secretspec` requires `secretspec.executable` (the absolute path of the SecretSpec \
     binary)";
pub(super) const MANIFEST_REQUIRED: &str = "`source: secretspec` requires `secretspec.manifest` (the absolute path of a SecretSpec \
     manifest)";
pub(super) const PROFILE_REQUIRED: &str =
    "must set `profile`; agent-vm pins the SecretSpec profile in user configuration";

/// `secretspec.executable` / `secretspec.manifest`: an absolute, normal host
/// path the user pinned.
///
/// Normal = no `.`/`..`/empty component and no trailing `/`, so the path
/// printed by `doctor` is the path that runs: no `PATH` lookup, no working
/// directory and no project input can redirect it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct PinnedPath {
    /// The spelling the user wrote. Kept as text, not re-derived from the
    /// `PathBuf`, so the frame that carries a manifest path is byte-identical
    /// to the configuration.
    text: String,
    path: PathBuf,
}

impl PinnedPath {
    pub(crate) fn parse(raw: &str) -> Result<Self, &'static str> {
        if raw.contains('\0') {
            return Err(PATH_NUL);
        }
        if !raw.starts_with('/') {
            return Err(PATH_NOT_ABSOLUTE);
        }
        if raw.len() > MAX_PINNED_PATH_BYTES {
            return Err(PATH_TOO_LONG);
        }
        let rest = &raw[1..];
        if rest.is_empty()
            || rest.ends_with('/')
            || rest
                .split('/')
                .any(|component| component.is_empty() || component == "." || component == "..")
        {
            return Err(PATH_NOT_NORMAL);
        }
        Ok(Self {
            text: raw.to_owned(),
            path: PathBuf::from(raw),
        })
    }

    pub(crate) fn as_path(&self) -> &Path {
        &self.path
    }

    /// The configured spelling, for the session frame (`manifest.path` must be
    /// the text the user pinned, not a normalization of it).
    pub(super) fn as_str(&self) -> &str {
        &self.text
    }
}

/// A SecretSpec secret name: the identifier `resolver.get` asks for.
///
/// Not a [`GuestEnvName`]: `MSB_*`, `HOME` and the launcher's own variable
/// names are perfectly good names on the SecretSpec side, and the guest
/// variable this credential occupies is `apiKey.name`'s business.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SecretspecName(String);

impl SecretspecName {
    pub(crate) fn parse(raw: &str) -> Result<Self, &'static str> {
        if !label_is_acceptable(raw) {
            return Err(NAME_RULE);
        }
        Ok(Self(raw.to_owned()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SecretspecName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A profile or scope label: the two session labels SecretSpec pins.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SecretspecLabel(String);

impl SecretspecLabel {
    pub(crate) fn parse(raw: &str) -> Result<Self, &'static str> {
        if !label_is_acceptable(raw) {
            return Err(LABEL_RULE);
        }
        Ok(Self(raw.to_owned()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SecretspecLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

use vstd::prelude::*;

verus! {

/// The label acceptance rule, over four already-measured facts.
///
/// The measurement (`str::len`, `chars().count()`, the per-byte control scan) is
/// the trusted adapter; this is the decision, and acceptance can never bypass one
/// of the four conditions because it *is* their conjunction.
pub(crate) fn label_is_accepted(
    is_empty: bool,
    bytes_within_cap: bool,
    chars_within_cap: bool,
    has_control_char: bool,
) -> (ok: bool)
    ensures
        ok == (!is_empty && bytes_within_cap && chars_within_cap && !has_control_char),
{
    !is_empty && bytes_within_cap && chars_within_cap && !has_control_char
}

} // verus!

/// The upstream character bound plus agent-vm's byte cap and rendering rule.
fn label_is_acceptable(raw: &str) -> bool {
    label_is_accepted(
        raw.is_empty(),
        raw.len() <= MAX_LABEL_BYTES,
        raw.chars().count() <= MAX_LABEL_CHARS,
        raw.bytes().any(|byte| byte < 0x20 || byte == 0x7f),
    )
}

/// The optional SecretSpec audit `reason`.
///
/// Deliberately narrower than the protocol allows: the schema's `reason` is
/// `maxLength 4096` characters with no pattern, and agent-vm accepts 1..=256
/// printable ASCII bytes instead. That is a local choice, stated as one in
/// every message. It is sent to SecretSpec and never rendered by agent-vm, so
/// it has no `Display` (the same policy `description` follows).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct AuditReason(String);

impl AuditReason {
    pub(crate) fn parse(raw: &str) -> Result<Self, &'static str> {
        if raw.is_empty() || raw.len() > MAX_REASON_BYTES {
            return Err(REASON_RULE);
        }
        if raw.bytes().any(|byte| !(0x20..=0x7e).contains(&byte)) {
            return Err(REASON_RULE);
        }
        Ok(Self(raw.to_owned()))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

/// Everything that pins one `secretspec serve` session. Two credentials whose
/// keys are equal share one child, so the key is exactly the immutable set of
/// facts sent in `rpc.initialize`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SessionKey {
    executable: PinnedPath,
    manifest: PinnedPath,
    profile: SecretspecLabel,
    scope: Option<SecretspecLabel>,
    reason: Option<AuditReason>,
}

impl SessionKey {
    pub(crate) fn executable(&self) -> &Path {
        self.executable.as_path()
    }

    pub(super) fn manifest(&self) -> &PinnedPath {
        &self.manifest
    }

    pub(super) fn profile(&self) -> &SecretspecLabel {
        &self.profile
    }

    pub(super) fn scope(&self) -> Option<&SecretspecLabel> {
        self.scope.as_ref()
    }

    pub(super) fn reason(&self) -> Option<&AuditReason> {
        self.reason.as_ref()
    }
}

/// One validated `secretspec:` table. Holds no value, and cannot be
/// constructed without a session key and a secret name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SecretspecSelection {
    session: SessionKey,
    name: SecretspecName,
}

impl SecretspecSelection {
    pub(crate) fn name(&self) -> &SecretspecName {
        &self.name
    }

    pub(crate) fn profile(&self) -> &SecretspecLabel {
        &self.session.profile
    }

    pub(crate) fn scope(&self) -> Option<&SecretspecLabel> {
        self.session.scope.as_ref()
    }

    pub(crate) fn manifest(&self) -> &Path {
        self.session.manifest.as_path()
    }

    pub(crate) fn executable(&self) -> &Path {
        self.session.executable.as_path()
    }

    pub(super) fn session(&self) -> &SessionKey {
        &self.session
    }
}

/// Accepted keys of the `secretspec:` table, in the order the refusal message
/// lists them.
pub(crate) const SECRETSPEC_KEYS: &[&str] = &[
    "executable",
    "manifest",
    "profile",
    "scope",
    "name",
    "reason",
];

/// Keys SecretSpec's own configuration has and this table deliberately does
/// not. Each is refused **by name** with a message that says what to do
/// instead, because "unknown field" would leave the user guessing why a
/// familiar key disappeared.
pub(crate) const UNSUPPORTED_SECRETSPEC_FIELDS: &[(&str, &str)] = &[
    (
        "provider",
        "`secretspec.provider` is not supported; choose the provider with SecretSpec's \
         manifest-level `providers = [...]` on the secret or profile (agent-vm sends no provider)",
    ),
    (
        "as_path",
        "`as_path` is not supported; agent-vm needs the value itself, delivered only to the proxy",
    ),
    (
        "asPath",
        "`as_path` is not supported; agent-vm needs the value itself, delivered only to the proxy",
    ),
    (
        "representation",
        "`representation` is not supported; agent-vm always reads the value representation",
    ),
    (
        "generate",
        "generation is not supported; agent-vm only reads SecretSpec values (`secretspec serve \
         --read-only`)",
    ),
    (
        "default",
        "a literal `default` is not supported here; declare defaults in the SecretSpec manifest",
    ),
    (
        "value",
        "a literal `value` is not supported; the value comes from SecretSpec at launch time",
    ),
    (
        "prompt",
        "prompting is not supported; agent-vm never prompts for a SecretSpec value",
    ),
];

/// A refusal inside the table: the key it concerns and a constant rule.
/// Never carries any of the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TableError {
    pub(crate) key: &'static str,
    pub(crate) rule: &'static str,
}

impl TableError {
    const fn new(key: &'static str, rule: &'static str) -> Self {
        Self { key, rule }
    }
}

/// Validate one `secretspec:` mapping whose *keys* `credential_yaml` already
/// checked. `default_name` is the entry's `apiKey.name`, the documented default
/// for `secretspec.name`.
pub(crate) fn parse_table(
    table: &serde_json::Map<String, serde_json::Value>,
    default_name: &GuestEnvName,
) -> Result<SecretspecSelection, TableError> {
    let executable = table
        .get("executable")
        .ok_or(TableError::new("executable", EXECUTABLE_REQUIRED))?;
    let executable = PinnedPath::parse_path_field(executable)
        .map_err(|rule| TableError::new("executable", rule))?;

    let manifest = table
        .get("manifest")
        .ok_or(TableError::new("manifest", MANIFEST_REQUIRED))?;
    let manifest =
        PinnedPath::parse_path_field(manifest).map_err(|rule| TableError::new("manifest", rule))?;

    let profile = table
        .get("profile")
        .ok_or(TableError::new("profile", PROFILE_REQUIRED))?;
    let profile = match profile {
        serde_json::Value::String(raw) => {
            SecretspecLabel::parse(raw).map_err(|rule| TableError::new("profile", rule))?
        }
        serde_json::Value::Null => return Err(TableError::new("profile", PROFILE_REQUIRED)),
        _ => return Err(TableError::new("profile", PATH_NOT_STRING)),
    };

    let scope = match table.get("scope") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(raw)) => {
            Some(SecretspecLabel::parse(raw).map_err(|rule| TableError::new("scope", rule))?)
        }
        Some(_) => return Err(TableError::new("scope", PATH_NOT_STRING)),
    };

    let name = match table.get("name") {
        None | Some(serde_json::Value::Null) => SecretspecName::parse(default_name.as_str())
            .map_err(|rule| TableError::new("name", rule))?,
        Some(serde_json::Value::String(raw)) => {
            SecretspecName::parse(raw).map_err(|rule| TableError::new("name", rule))?
        }
        Some(_) => return Err(TableError::new("name", PATH_NOT_STRING)),
    };

    let reason = match table.get("reason") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(raw)) => {
            Some(AuditReason::parse(raw).map_err(|rule| TableError::new("reason", rule))?)
        }
        Some(_) => return Err(TableError::new("reason", PATH_NOT_STRING)),
    };

    Ok(SecretspecSelection {
        session: SessionKey {
            executable,
            manifest,
            profile,
            scope,
            reason,
        },
        name,
    })
}

impl PinnedPath {
    fn parse_path_field(value: &serde_json::Value) -> Result<Self, &'static str> {
        match value {
            serde_json::Value::String(raw) => Self::parse(raw),
            _ => Err(PATH_NOT_STRING),
        }
    }
}
