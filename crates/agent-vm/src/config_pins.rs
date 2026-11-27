//! Content pins for `trust = false` config sources (#736): the per-project
//! record of which SHA-256 digests of which source paths this user approved,
//! and the exact bytes each approval was given for.
//!
//! # Why the key is a normalized path and the value is a digest set
//!
//! A source is a *path* the project config names, and the file behind it may be
//! on several approved branches or revisions at once. Approval therefore
//! records, per normalized source path, a set of approved SHA-256 digests plus
//! the one most recently active, so switching between two already-approved
//! versions needs no prompt and a new version always does. The key is lexical
//! (`..` preserved) because the OS resolves `..` through symlinks the way the
//! user's spelling says; canonicalizing here would silently approve a different
//! file.
//!
//! # Why snapshots are not authority
//!
//! `pin-<store_id>-<sha256>.toml` holds the exact bytes an approval was given
//! for, so a review can show what changed. It is deliberately **not** an
//! authority record: every read re-hashes it, and a missing or tampered
//! snapshot only makes the diff unavailable. `pins.json` is the authority, and
//! only after directory-first ADR-0040 verification.
//!
//! # Why the generation is `store_id + reset_epoch`
//!
//! A monotonic epoch alone cannot distinguish a store that was reset from one
//! that was replaced wholesale, and a crash during a reset can leave the two
//! files disagreeing. Every unit of store authority is therefore a pair
//! `(store_id, reset_epoch)` recorded in `pins.json`, in the permanent
//! `pins.lock` header, and in each snapshot's name. A stale review, a stale
//! snapshot, or a store recreated under the same path can never match.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::config_sources::{Declaration, SourceAlias, SourceEntry, SourceScope};
use crate::project_config::ProjectTierPaths;

use self::store::ObservedStore;

pub(crate) mod diff;
pub(crate) mod prompt;
pub(crate) mod store;

#[cfg(test)]
mod tests;

/// The approved-hash manifest and its per-key last-active pointer (authority).
pub(crate) const PINS_FILE: &str = "pins.json";
/// The permanent coordination lock inode. Never unlinked, never renamed.
pub(crate) const LOCK_FILE: &str = "pins.lock";
/// Temporary-name prefix for pin-store atomic writes, distinct from the default
/// config writer's `.agent-vm-tmp-*` so neither store can sweep the other's
/// live temporaries.
pub(crate) const PIN_TMP_PREFIX: &str = ".agent-vm-pin-tmp-";
/// Distinct pinned `(source_path)` keys one project store may record.
///
/// Deliberately a *store* bound with its own name and value, separate from
/// `config_sources::MAX_DECLARED_SOURCES` (32), which bounds what a project
/// config may declare. Crossing this bound is a state-defence refusal, and it
/// must never be able to weaken the declaration bound.
pub(crate) const MAX_PINNED_KEYS: usize = 64;
/// Approved digests retained per key. The oldest inactive approvals are evicted
/// first; the active one and the current batch are always protected.
pub(crate) const MAX_APPROVED_PER_SOURCE: usize = 16;
/// Whole-manifest cap. Worst-case valid content is far below this.
pub(crate) const MAX_PIN_STORE_BYTES: u64 = 1_048_576;
/// A normalized pin key's length bound, matching the config path's own.
const MAX_PATH_BYTES: usize = 4096;
/// The fixed on-disk record written to `pins.lock` by one `pwrite`.
///
/// The longest schema text (`rotating` with two `u64::MAX` epochs) is 137
/// bytes; the record is space-padded and ends with one `\n` at byte 143 so a
/// reader can reject a torn or replaced header by shape alone.
pub(crate) const LOCK_HEADER_RECORD_BYTES: usize = 144;
/// Longer than this is not a lock header this build wrote.
pub(crate) const MAX_LOCK_HEADER_BYTES: usize = 256;
/// The snapshot cap: the same text a config source may be.
pub(crate) const MAX_SNAPSHOT_BYTES: u64 = 1_048_576;

/// SHA-256 of the exact bounded bytes a source read returned.
///
/// `Debug` is the documented `sha256:<hex>` spelling, not the 32 raw bytes: a
/// digest is the diagnostic this module prints, and the decimal byte array it
/// would otherwise render says nothing a person can use.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct ContentHash([u8; 32]);

impl ContentHash {
    pub(crate) fn of(bytes: &[u8]) -> Self {
        let digest = Sha256::digest(bytes);
        let mut hash = [0_u8; 32];
        hash.copy_from_slice(&digest);
        Self(hash)
    }

    pub(crate) fn hex(&self) -> String {
        hex_of(&self.0)
    }

    pub(crate) fn parse_hex(text: &str) -> Option<Self> {
        let bytes = hex_bytes::<32>(text)?;
        Some(Self(bytes))
    }

    /// `sha256:<64 lowercase hex>`, the spelling diagnostics use.
    pub(crate) fn parse_prefixed(text: &str) -> Option<Self> {
        Self::parse_hex(text.strip_prefix("sha256:")?)
    }
}

impl fmt::Debug for ContentHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "sha256:{}", self.hex())
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "sha256:{}", self.hex())
    }
}

/// 128 bits minted from the OS CSPRNG: the unforgeable half of a generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct StoreId([u8; 16]);

impl StoreId {
    pub(crate) fn generate() -> anyhow::Result<Self> {
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes)
            .map_err(|error| anyhow::anyhow!("getting a store id: {error}"))?;
        Ok(Self(bytes))
    }

    pub(crate) fn hex(&self) -> String {
        hex_of(&self.0)
    }

    pub(crate) fn parse_hex(text: &str) -> Option<Self> {
        hex_bytes::<16>(text).map(Self)
    }
}

/// One store's authority identity: which store (128 bits) and which reset of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LiveGeneration {
    pub(crate) store_id: StoreId,
    /// `>= 1`. First creation writes `1`; every reset writes at least `2`.
    pub(crate) reset_epoch: u64,
}

impl LiveGeneration {
    /// The next epoch, or a refusal at `u64::MAX` rather than a wrap or a
    /// reused value. Every epoch comparison in this module goes through this.
    pub(crate) fn checked_next_epoch(self) -> Result<u64, EpochExhausted> {
        self.reset_epoch
            .checked_add(1)
            .ok_or(EpochExhausted)
            .map(|next| next.max(2))
    }
}

/// `reset_epoch` cannot be incremented; the caller must quiesce and start over.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct EpochExhausted;

/// A normalized lexical absolute UTF-8 path: the pin key.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct PinKey(String);

impl PinKey {
    /// The key for a `[[sources]]` entry's already-resolved path.
    ///
    /// Normalizes once more (an entry built by hand must not be able to create a
    /// second spelling) and refuses a path no pin record could name.
    pub(crate) fn for_source(path: &Path) -> Result<Self, KeyRefusal> {
        let Some(text) = path.to_str() else {
            return Err(KeyRefusal::NotUtf8);
        };
        let normalized = crate::config_sources::normalize_lexical_absolute(Path::new(text))
            .ok_or(KeyRefusal::NotNormalized)?;
        let Some(normalized) = normalized.to_str() else {
            return Err(KeyRefusal::NotUtf8);
        };
        Self::validate(normalized)
    }

    /// The key from bytes already stored in `pins.json`.
    ///
    /// Also requires the stored spelling to equal its own normal form, so a
    /// hand-edited `/a//b` cannot become a second key for `/a/b`.
    pub(crate) fn from_stored(text: &str) -> Result<Self, KeyRefusal> {
        Self::validate(text)
    }

    fn validate(text: &str) -> Result<Self, KeyRefusal> {
        if text.len() > MAX_PATH_BYTES {
            return Err(KeyRefusal::TooLong);
        }
        if text.chars().any(char::is_control) {
            return Err(KeyRefusal::Control);
        }
        let normalized = crate::config_sources::normalize_lexical_absolute(Path::new(text))
            .ok_or(KeyRefusal::NotNormalized)?;
        // Compared as raw bytes: `Path` equality treats `//` and a trailing
        // `/.` as equal to their normal form, which is exactly how two keys
        // could disagree about their own spelling.
        if normalized.as_os_str().as_encoded_bytes() != text.as_bytes() {
            return Err(KeyRefusal::NotNormalized);
        }
        Ok(Self(text.to_owned()))
    }

    pub(crate) fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PinKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Why a path cannot be a pin key. Fixed clauses: a key is never echoed in a
/// diagnostic until the caller has escaped it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyRefusal {
    NotUtf8,
    NotNormalized,
    TooLong,
    Control,
}

impl KeyRefusal {
    /// The clause after `sources[N].path: ` in a load diagnostic.
    pub(crate) fn clause(self) -> &'static str {
        match self {
            Self::NotUtf8 => "the source path is not valid UTF-8, so agent-vm cannot pin it",
            Self::NotNormalized => {
                "the source path is not in normalized absolute form, so agent-vm cannot pin it"
            }
            Self::TooLong => "the source path is longer than 4096 bytes, so agent-vm cannot pin it",
            Self::Control => {
                "the source path contains a control character, so agent-vm cannot pin it"
            }
        }
    }
}

/// The snapshot's file name for one generation and digest.
///
/// The store id in the name is what makes a snapshot from a reset or recreated
/// store unreachable: `ENOENT`, never a wrong baseline.
pub(crate) fn snapshot_name(store_id: StoreId, hash: &ContentHash) -> String {
    format!("pin-{}-{}.toml", store_id.hex(), hash.hex())
}

/// Case-insensitive `pin-<32 hex>-<64 hex>.toml`, so an APFS case variant of a
/// live snapshot still joins the ADR-0038 one-link guard.
pub(crate) fn is_snapshot_name(name: &std::ffi::OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    let Some(text) = std::str::from_utf8(name.as_bytes()).ok() else {
        return false;
    };
    let lower = text.to_ascii_lowercase();
    let Some(rest) = lower
        .strip_prefix("pin-")
        .and_then(|rest| rest.strip_suffix(".toml"))
    else {
        return false;
    };
    let mut parts = rest.split('-');
    let (Some(id), Some(hash), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    id.len() == 32
        && hash.len() == 64
        && id.bytes().all(|byte| byte.is_ascii_hexdigit())
        && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// One decoded and schema-validated `pins.json`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Current {
    generation: LiveGeneration,
    sources: std::collections::BTreeMap<PinKey, KeyState>,
}

/// An approved digest and the two clock facts the review UI reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Approval {
    pub(crate) hash: ContentHash,
    pub(crate) approved_ms: i64,
    pub(crate) active_ms: i64,
}

/// One source path's approved digests plus the last-active pointer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KeyState {
    pub(crate) active: ContentHash,
    pub(crate) approved: Vec<Approval>,
}

impl KeyState {
    fn is_approved(&self, hash: &ContentHash) -> bool {
        self.approved.iter().any(|approval| approval.hash == *hash)
    }

    fn approval_mut(&mut self, hash: &ContentHash) -> Option<&mut Approval> {
        self.approved
            .iter_mut()
            .find(|approval| approval.hash == *hash)
    }
}

impl Current {
    pub(crate) fn empty(generation: LiveGeneration) -> Self {
        Self {
            generation,
            sources: std::collections::BTreeMap::new(),
        }
    }

    pub(crate) fn generation(&self) -> LiveGeneration {
        self.generation
    }

    pub(crate) fn sources(&self) -> &std::collections::BTreeMap<PinKey, KeyState> {
        &self.sources
    }

    pub(crate) fn key_state(&self, key: &PinKey) -> Option<&KeyState> {
        self.sources.get(key)
    }

    pub(crate) fn is_approved(&self, key: &PinKey, hash: &ContentHash) -> bool {
        self.sources
            .get(key)
            .is_some_and(|state| state.is_approved(hash))
    }

    /// What one read's digest means for this key (R6).
    pub(crate) fn lookup(&self, key: &PinKey, hash: &ContentHash) -> Lookup {
        match self.sources.get(key) {
            Some(state) if state.is_approved(hash) => Lookup::Approved {
                active: state.active == *hash,
            },
            Some(state) => Lookup::Unapproved(PendingReason::Changed {
                last_active: state.active,
            }),
            None => Lookup::Unapproved(PendingReason::NeverApproved),
        }
    }

    /// Record a launch's active digest. A missing or evicted key/approval is
    /// **not** recreated: activation is not an approval.
    pub(crate) fn mark_active(&mut self, key: &PinKey, hash: &ContentHash, now_ms: i64) -> bool {
        let Some(state) = self.sources.get_mut(key) else {
            return false;
        };
        if !state.is_approved(hash) {
            return false;
        }
        if state.active == *hash {
            return true;
        }
        state.active = *hash;
        if let Some(approval) = state.approval_mut(hash) {
            approval.active_ms = now_ms;
        }
        true
    }

    /// Decode strict JSON, enforcing every R2 rule. `v` is probed first so a
    /// later release's file is `Newer` rather than damage.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, DecodeFailure> {
        #[derive(Deserialize)]
        struct VersionProbe {
            v: u32,
        }
        let probe: VersionProbe =
            serde_json::from_slice(bytes).map_err(|_| DecodeFailure::Undecodable)?;
        if probe.v > SCHEMA_VERSION {
            return Err(DecodeFailure::Newer { v: probe.v });
        }
        if probe.v < SCHEMA_VERSION {
            return Err(DecodeFailure::OlderVersion(probe.v));
        }
        let file: RawPinFile =
            serde_json::from_slice(bytes).map_err(|_| DecodeFailure::Undecodable)?;
        Self::from_raw(file).map_err(DecodeFailure::Invalid)
    }

    fn from_raw(file: RawPinFile) -> Result<Self, &'static str> {
        if file.reset_epoch < 1 {
            return Err("reset_epoch is zero");
        }
        let store_id =
            StoreId::parse_hex(&file.store_id).ok_or("store_id is not 32 lowercase hex")?;
        if file.sources.len() > MAX_PINNED_KEYS {
            return Err("more than 64 pinned source keys");
        }
        let mut sources = std::collections::BTreeMap::new();
        for line in file.sources {
            let key = PinKey::from_stored(&line.path)
                .map_err(|_| "a source path is not normalized absolute UTF-8")?;
            if sources.contains_key(&key) {
                return Err("a duplicate source path");
            }
            if line.approved.is_empty() {
                return Err("a source has no approved digests");
            }
            if line.approved.len() > MAX_APPROVED_PER_SOURCE {
                return Err("a source has more than 16 approved digests");
            }
            let active = ContentHash::parse_hex(&line.active)
                .ok_or("a last-active hash is not 64 lowercase hex")?;
            let mut approved: Vec<Approval> = Vec::with_capacity(line.approved.len());
            for raw in line.approved {
                let hash = ContentHash::parse_hex(&raw.sha256)
                    .ok_or("an approved hash is not 64 lowercase hex")?;
                if approved.iter().any(|approval| approval.hash == hash) {
                    return Err("a source repeats an approved digest");
                }
                if raw.approved_ms < 0 || raw.active_ms < 0 {
                    return Err("an approval clock is negative");
                }
                approved.push(Approval {
                    hash,
                    approved_ms: raw.approved_ms,
                    active_ms: raw.active_ms,
                });
            }
            if !approved.iter().any(|approval| approval.hash == active) {
                return Err("a source's active hash is not one of its approved digests");
            }
            sources.insert(key, KeyState { active, approved });
        }
        Ok(Self {
            generation: LiveGeneration {
                store_id,
                reset_epoch: file.reset_epoch,
            },
            sources,
        })
    }

    /// Canonical compact JSON: sources sorted by key, approvals by digest.
    pub(crate) fn encode(&self) -> Result<Vec<u8>, EncodeFailure> {
        if self.sources.len() > MAX_PINNED_KEYS {
            return Err(EncodeFailure::TooManyKeys);
        }
        let mut raw = RawPinFile {
            v: SCHEMA_VERSION,
            store_id: self.generation.store_id.hex(),
            reset_epoch: self.generation.reset_epoch,
            sources: Vec::with_capacity(self.sources.len()),
        };
        for (key, state) in &self.sources {
            if state.approved.is_empty() {
                return Err(EncodeFailure::EmptyApprovals);
            }
            if state.approved.len() > MAX_APPROVED_PER_SOURCE {
                return Err(EncodeFailure::TooManyApprovals);
            }
            if !state.is_approved(&state.active) {
                return Err(EncodeFailure::ActiveNotApproved);
            }
            let mut approved: Vec<RawApproval> = state
                .approved
                .iter()
                .map(|approval| RawApproval {
                    sha256: approval.hash.hex(),
                    approved_ms: approval.approved_ms,
                    active_ms: approval.active_ms,
                })
                .collect();
            approved.sort_by(|left, right| left.sha256.cmp(&right.sha256));
            raw.sources.push(RawSource {
                path: key.as_str().to_owned(),
                active: state.active.hex(),
                approved,
            });
        }
        let bytes = serde_json::to_vec(&raw).map_err(|_| EncodeFailure::Serialize)?;
        if bytes.len() as u64 > MAX_PIN_STORE_BYTES {
            return Err(EncodeFailure::TooLarge);
        }
        Ok(bytes)
    }
}

const SCHEMA_VERSION: u32 = 1;

/// Why a `pins.json` byte sequence is not a store this build reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DecodeFailure {
    Newer { v: u32 },
    OlderVersion(u32),
    Undecodable,
    Invalid(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EncodeFailure {
    TooManyKeys,
    TooManyApprovals,
    EmptyApprovals,
    ActiveNotApproved,
    TooLarge,
    Serialize,
}

/// Why one read's digest needs review (R6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PendingReason {
    NeverApproved,
    Changed { last_active: ContentHash },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lookup {
    Approved { active: bool },
    Unapproved(PendingReason),
}

/// One `pins.json` source line, strictly.
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct RawPinFile {
    v: u32,
    store_id: String,
    reset_epoch: u64,
    sources: Vec<RawSource>,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct RawSource {
    path: String,
    active: String,
    approved: Vec<RawApproval>,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct RawApproval {
    sha256: String,
    approved_ms: i64,
    active_ms: i64,
}

fn hex_of(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut text, "{byte:02x}").expect("writing into a String cannot fail");
    }
    text
}

/// Exactly `N` lowercase hex bytes; uppercase, short and long spellings are all
/// different values, and only the canonical one is accepted.
fn hex_bytes<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N * 2 {
        return None;
    }
    let mut out = [0_u8; N];
    for (index, byte) in out.iter_mut().enumerate() {
        let pair = &text[index * 2..index * 2 + 2];
        if !pair
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return None;
        }
        *byte = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

/// A digest a store read could not produce, mapped to a review-only reason:
/// never authorization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Unavailable {
    Missing,
    NotTrusted(crate::config_authority::AuthorityRefusal),
    NotAFile,
    TooLarge,
    NotUtf8,
    HashMismatch,
    Unreadable(String),
}

impl Unavailable {
    pub(crate) fn reason(&self) -> String {
        match self {
            Self::Missing => "missing".to_owned(),
            Self::NotTrusted(refusal) => format!(
                "not trusted: {}",
                crate::allowances::refusal_clause(refusal)
            ),
            Self::NotAFile => "not a regular file".to_owned(),
            Self::TooLarge => format!("larger than {MAX_SNAPSHOT_BYTES} byte(s)"),
            Self::NotUtf8 => "not valid UTF-8".to_owned(),
            Self::HashMismatch => "contents do not match its SHA-256".to_owned(),
            Self::Unreadable(error) => format!("could not be read ({error})"),
        }
    }
}

// ---------------------------------------------------------------------------
// The load seam: read the store once, decide every `trust = false` source, and
// describe what still needs review (#736 phase 4).
// ---------------------------------------------------------------------------

/// One approved digest and the key it was approved for.
///
/// Constructed only by [`ApprovedHashMatch`], so a report cannot name a pin the
/// policy never looked up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SourcePin {
    key: PinKey,
    hash: ContentHash,
    active: bool,
}

impl SourcePin {
    pub(crate) fn key(&self) -> &PinKey {
        &self.key
    }

    pub(crate) fn hash(&self) -> ContentHash {
        self.hash
    }

    /// Whether this digest is the key's recorded last-active one.
    pub(crate) fn active(&self) -> bool {
        self.active
    }
}

/// One verified membership of a digest in a key's approved set.
///
/// This is the non-forgeable witness [`crate::config_authority::ApprovedSourceContent`]
/// demands: the type is public to the crate so that signature can name it, but
/// its constructor lives in this private module and only ever runs after a
/// [`Current`] lookup. No crate code can pair arbitrary bytes with a
/// `SourcePin`; it must present a match this module observed.
mod match_witness {
    use super::{ContentHash, Current, Lookup, PinKey, SourcePin};

    pub(crate) struct ApprovedHashMatch {
        key: PinKey,
        hash: ContentHash,
        active: bool,
    }

    impl ApprovedHashMatch {
        /// The one constructor: the lookup itself decides membership.
        pub(super) fn find(current: &Current, key: &PinKey, hash: &ContentHash) -> Option<Self> {
            match current.lookup(key, hash) {
                Lookup::Approved { active } => Some(Self {
                    key: key.clone(),
                    hash: *hash,
                    active,
                }),
                Lookup::Unapproved(_) => None,
            }
        }

        pub(crate) fn pin(&self) -> SourcePin {
            SourcePin {
                key: self.key.clone(),
                hash: self.hash,
                active: self.active,
            }
        }
    }
}

pub(crate) use match_witness::ApprovedHashMatch;

/// One pinned source awaiting approval: the exact bytes that were read, and
/// everything a review needs to describe them without reopening the path.
///
/// The review re-hashes `candidate`, so a `PendingSource` that outlived its
/// read cannot present different bytes to the diff and to the commit.
///
/// # No bytes in `Debug`
///
/// B6 says pending and snapshot bytes never reach a debug, error or log path,
/// and `Debug` is what a panic, a backtrace and a failed assertion print. The
/// manual [`fmt::Debug`] below names the identity and the digest and redacts
/// the content itself; the review transcript and the stored snapshot are the two
/// deliberate places the exact text appears.
#[allow(dead_code)] // `pins_cmd`'s review reads the metadata methods
pub(crate) struct PendingSource {
    pub(crate) alias: SourceAlias,
    pub(crate) declared: Declaration,
    pub(crate) scope: SourceScope,
    pub(crate) allow: bool,
    pub(crate) key: PinKey,
    pub(crate) hash: ContentHash,
    pub(crate) reason: PendingReason,
    pub(crate) candidate: Vec<u8>,
}

impl fmt::Debug for PendingSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingSource")
            .field("alias", &self.alias)
            .field("declared", &self.declared)
            .field("scope", &self.scope)
            .field("allow", &self.allow)
            .field("key", &self.key)
            .field("hash", &self.hash)
            .field("reason", &self.reason)
            .field("candidate", &RedactedBytes(self.candidate.len()))
            .finish()
    }
}

/// `n` bytes of source or snapshot text, deliberately not rendered.
///
/// Shared with [`store::DiffState`] and [`store::ApprovalCandidate`], which
/// carry the same class of bytes.
pub(crate) struct RedactedBytes(pub(crate) usize);

impl fmt::Debug for RedactedBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "<redacted {} byte(s)>", self.0)
    }
}

#[cfg(test)]
impl PendingSource {
    /// The fixture the phase-3 review tests need: one key and one candidate,
    /// with the metadata no diff assertion reads.
    pub(crate) fn for_tests(key: PinKey, candidate: Vec<u8>) -> Self {
        Self {
            alias: SourceAlias::for_test("repo"),
            declared: Declaration::Entry(0),
            scope: SourceScope::Checkout,
            allow: false,
            hash: ContentHash::of(&candidate),
            key,
            reason: PendingReason::NeverApproved,
            candidate,
        }
    }
}

#[allow(dead_code)] // the review and commit read these
impl PendingSource {
    /// The key the review and the commit name.
    pub(crate) fn key(&self) -> &PinKey {
        &self.key
    }

    /// The exact bytes that were read, hashed and offered for review.
    pub(crate) fn candidate(&self) -> &[u8] {
        &self.candidate
    }

    pub(crate) fn reason(&self) -> PendingReason {
        self.reason
    }
}

/// One `trust = false` source's inspection outcome, approved or pending.
#[derive(Debug)]
#[allow(dead_code)] // `pins_cmd` and `doctor` read the inspection detail
pub(crate) struct InspectedSource {
    pub(crate) alias: SourceAlias,
    pub(crate) declared: Declaration,
    pub(crate) scope: SourceScope,
    pub(crate) allow: bool,
    pub(crate) key: PinKey,
    pub(crate) hash: ContentHash,
    pub(crate) status: InspectedStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InspectedStatus {
    Approved { active: bool },
    Pending(PendingReason),
}

/// Every declared pinned source, plus the pending candidates and the full
/// declared key set (so a commit never evicts a live key).
#[derive(Debug)]
#[allow(dead_code)] // #739's `config diff|approve` reads this
pub(crate) struct PinInspection {
    project_config: PathBuf,
    store_dir: PathBuf,
    observed: ObservedStore,
    entries: Vec<InspectedSource>,
    pending: Vec<PendingSource>,
    all_declared_keys: BTreeSet<PinKey>,
}

#[allow(dead_code)] // #739's `config diff|approve` reads this
impl PinInspection {
    pub(crate) fn new(
        project_config: PathBuf,
        store_dir: PathBuf,
        observed: ObservedStore,
        entries: Vec<InspectedSource>,
        pending: Vec<PendingSource>,
        all_declared_keys: BTreeSet<PinKey>,
    ) -> Self {
        Self {
            project_config,
            store_dir,
            observed,
            entries,
            pending,
            all_declared_keys,
        }
    }

    /// No project tier: nothing is declared, so nothing is pending.
    pub(crate) fn empty() -> Self {
        Self {
            project_config: PathBuf::new(),
            store_dir: PathBuf::new(),
            observed: ObservedStore {
                store_dir_id: None,
                state: store::ObservedStoreState::Absent { lock: None },
            },
            entries: Vec::new(),
            pending: Vec::new(),
            all_declared_keys: BTreeSet::new(),
        }
    }

    pub(crate) fn project_config(&self) -> &Path {
        &self.project_config
    }

    pub(crate) fn store_dir(&self) -> &Path {
        &self.store_dir
    }

    pub(crate) fn observed(&self) -> ObservedStore {
        self.observed
    }

    pub(crate) fn entries(&self) -> &[InspectedSource] {
        &self.entries
    }

    pub(crate) fn pending(&self) -> &[PendingSource] {
        &self.pending
    }

    pub(crate) fn all_declared_keys(&self) -> &BTreeSet<PinKey> {
        &self.all_declared_keys
    }
}

/// The typed root error of `config::load` when a pinned source is unapproved.
///
/// The load never prompts and never writes: it collects every pinned source in
/// `[[sources]]` order and returns this refusal, so `pins_cmd`'s gate can render
/// the review and commit what the user approves.
///
/// `Debug` is derived **because** [`PendingSource`]'s is redacted: this type
/// reaches an `anyhow` chain, and a panic prints that chain's `Debug`.
#[derive(Debug)]
#[allow(dead_code)] // `pins_cmd` reads the pending list
pub(crate) struct UnapprovedSources {
    project_config: PathBuf,
    store_dir: PathBuf,
    observed: Option<ObservedStore>,
    entries: Vec<InspectedSource>,
    pending: Vec<PendingSource>,
    all_declared_keys: BTreeSet<PinKey>,
    /// The aliases of the sources `pending` holds, so the launch preflight can
    /// tell a verb the approval can make dispatchable from one it cannot.
    pending_aliases: BTreeSet<crate::config_sources::SourceAlias>,
}

#[allow(dead_code)] // `pins_cmd` reads these
impl UnapprovedSources {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        project_config: PathBuf,
        store_dir: PathBuf,
        observed: Option<ObservedStore>,
        entries: Vec<InspectedSource>,
        pending: Vec<PendingSource>,
        all_declared_keys: BTreeSet<PinKey>,
    ) -> Self {
        Self {
            project_config,
            store_dir,
            observed,
            entries,
            pending_aliases: pending.iter().map(|source| source.alias.clone()).collect(),
            pending,
            all_declared_keys,
        }
    }

    pub(crate) fn project_config(&self) -> &Path {
        &self.project_config
    }

    pub(crate) fn store_dir(&self) -> &Path {
        &self.store_dir
    }

    pub(crate) fn observed(&self) -> Option<ObservedStore> {
        self.observed
    }

    pub(crate) fn entries(&self) -> &[InspectedSource] {
        &self.entries
    }

    pub(crate) fn pending(&self) -> &[PendingSource] {
        &self.pending
    }

    pub(crate) fn all_declared_keys(&self) -> &BTreeSet<PinKey> {
        &self.all_declared_keys
    }

    /// Which verbs a review here could make dispatchable.
    ///
    /// Any declaration is launchable (#749), so a pending source may supply any
    /// **bare** name; a qualified `<alias>:<name>` can only be one of these
    /// pending aliases, because an approved source's verbs are already in the
    /// catalog the reload offers.
    pub(crate) fn verb_candidates(&self) -> crate::cli::VerbCandidates<'_> {
        crate::cli::VerbCandidates::Pending(&self.pending_aliases)
    }
}

impl fmt::Display for UnapprovedSources {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = self.pending.len();
        if count == 1 {
            writeln!(
                formatter,
                "config: {}: 1 pinned source is not approved for this project:",
                crate::one_line::quoted_path(&self.project_config)
            )?;
        } else {
            writeln!(
                formatter,
                "config: {}: {count} pinned sources are not approved for this project:",
                crate::one_line::quoted_path(&self.project_config)
            )?;
        }
        for source in &self.pending {
            let status = match source.reason {
                PendingReason::NeverApproved => {
                    format!("never approved (current {})", source.hash)
                }
                PendingReason::Changed { last_active } => format!(
                    "differs from every approved version (current {}; last approved {last_active})",
                    source.hash
                ),
            };
            writeln!(
                formatter,
                "  {} {} {}: {status}",
                source.declared,
                source.alias,
                crate::one_line::quoted_path(source.key.as_path()),
            )?;
        }
        // The alternate path is an eligible *launch*: `doctor`, help and the
        // built-ins print this refusal too, and none of them can prompt. The two
        // batch command names are R8's, and they are named as a later release's
        // because they do not ship in this one.
        if count == 1 {
            formatter.write_str(
                "review the change with `agent-vm config diff` and approve it with \
                 `agent-vm config approve` (a later release's workflow, not this version's); this \
                 version approves only from an eligible launch — a tool verb, `run` or `--`, never \
                 `doctor`, help or a built-in — run in this project's interactive terminal",
            )
        } else {
            formatter.write_str(
                "review the changes with `agent-vm config diff` and approve them with \
                 `agent-vm config approve` (a later release's workflow, not this version's); this \
                 version approves only from an eligible launch — a tool verb, `run` or `--`, never \
                 `doctor`, help or a built-in — run in this project's interactive terminal",
            )
        }
    }
}

impl std::error::Error for UnapprovedSources {}

/// One project's read-only pin state for one load or inspection.
///
/// The manifest is read once, without taking `pins.lock`, creating the store or
/// writing anything. A load with no `trust = false` source never reads it at all
/// (V18).
pub(crate) struct LoadPins {
    observed: ObservedStore,
    current: Current,
}

impl LoadPins {
    fn read(project: &ProjectTierPaths) -> anyhow::Result<Self> {
        let store = store::PinStore::new(project.clone());
        let (observed, current) = store
            .read_state()
            .map_err(|problem| pins_error(project, &problem))?;
        Ok(Self { observed, current })
    }

    pub(crate) fn observed(&self) -> ObservedStore {
        self.observed
    }

    pub(crate) fn current(&self) -> &Current {
        &self.current
    }
}

fn pins_error(project: &ProjectTierPaths, problem: &store::Problem) -> anyhow::Error {
    let pins = project
        .config
        .parent()
        .map_or_else(|| PathBuf::from(PINS_FILE), |dir| dir.join(PINS_FILE));
    anyhow::anyhow!(
        "config: {}: {}",
        crate::one_line::quoted_path(&pins),
        problem.line()
    )
}

/// The pin-aware `#748` seam: every `trust = false` source is decided here,
/// before UTF-8 validation and before any TOML decoding.
///
/// The store is read lazily on the first check, so a project whose sources are
/// all `trust = true` never opens `pins.json`.
#[cfg(test)]
pub(crate) type LookupHook = Box<dyn FnMut(&PinKey, &ContentHash)>;

pub(crate) struct PinsContentPolicy {
    project: Option<ProjectTierPaths>,
    pins: Option<LoadPins>,
    #[cfg(test)]
    pub(crate) looked_up: Option<LookupHook>,
}

impl PinsContentPolicy {
    pub(crate) fn new(project: Option<&ProjectTierPaths>) -> Self {
        Self {
            project: project.cloned(),
            pins: None,
            #[cfg(test)]
            looked_up: None,
        }
    }

    fn pins(&mut self) -> anyhow::Result<&LoadPins> {
        if self.pins.is_none() {
            let project = self.project.as_ref().ok_or_else(|| {
                anyhow::anyhow!("internal: a trust = false source without a project config store")
            })?;
            self.pins = Some(LoadPins::read(project)?);
        }
        Ok(self.pins.as_ref().expect("the pin state was just loaded"))
    }

    /// Read the store once even when nothing is pending, so an inspection always
    /// reports the state it inspected. Still read-only.
    pub(crate) fn load_state(&mut self) -> anyhow::Result<()> {
        self.pins()?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn with_lookup_hook(
        project: Option<&ProjectTierPaths>,
        looked_up: LookupHook,
    ) -> Self {
        Self {
            project: project.cloned(),
            pins: None,
            looked_up: Some(looked_up),
        }
    }
}

impl crate::config_authority::ContentApprovalPolicy for PinsContentPolicy {
    fn check_untrusted_source<'a>(
        &mut self,
        project: &'a crate::config_authority::VerifiedProject,
        entry: &'a SourceEntry,
        scope: SourceScope,
        bytes: &'a [u8],
    ) -> anyhow::Result<crate::config_authority::ContentApproval<'a>> {
        use crate::config_authority::{ApprovedSourceContent, ContentApproval};

        let key = PinKey::for_source(entry.path()).map_err(|refusal| {
            anyhow::anyhow!(
                "config: {}: {}: {}",
                crate::one_line::quoted_path(project.path()),
                entry.declared(),
                refusal.clause()
            )
        })?;
        let hash = ContentHash::of(bytes);
        if self.pins.is_none() {
            let project = self.project.as_ref().ok_or_else(|| {
                anyhow::anyhow!("internal: a trust = false source without a project config store")
            })?;
            self.pins = Some(LoadPins::read(project)?);
        }
        let pins = self.pins.as_ref().expect("the pin state was just loaded");
        #[cfg(test)]
        if let Some(looked_up) = self.looked_up.as_mut() {
            looked_up(&key, &hash);
        }
        match pins.current.lookup(&key, &hash) {
            Lookup::Approved { .. } => {
                let matched =
                    ApprovedHashMatch::find(pins.current(), &key, &hash).ok_or_else(|| {
                        anyhow::anyhow!("internal: an approved lookup produced no witness")
                    })?;
                Ok(ContentApproval::Approved(ApprovedSourceContent::approved(
                    matched, project, entry, bytes,
                )))
            }
            Lookup::Unapproved(reason) => {
                // Only a pending candidate is ever offered for review, so a
                // binary file is refused here with the config UTF-8 refusal
                // rather than becoming an unreadable diff (V22).
                std::str::from_utf8(bytes).map_err(|_| crate::config::utf8_error(entry.path()))?;
                Ok(ContentApproval::Pending(PendingSource {
                    alias: entry.alias().clone(),
                    declared: entry.declared(),
                    scope,
                    allow: entry.is_allowed(),
                    key,
                    hash,
                    reason,
                    candidate: bytes.to_vec(),
                }))
            }
        }
    }

    fn observed(&self) -> Option<ObservedStore> {
        self.pins.as_ref().map(LoadPins::observed)
    }
}
