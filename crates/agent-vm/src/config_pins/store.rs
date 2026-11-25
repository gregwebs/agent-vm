//! The descriptor-anchored `pins.json` store: read, commit, reset, and the
//! permanent coordination lock (#736).
//!
//! # Why every operation starts from an opened directory
//!
//! The store lives inside `~/.config/agent-vm/projects/<id>/`, and every path
//! to it is a name someone could replace between a check and a use. Each
//! operation therefore opens `projects/`, verifies its own facts, opens the
//! project store through that descriptor, verifies it, and then performs every
//! lock, read, write, rename and unlink through the opened `store_fd`. A name
//! is only ever resolved by the kernel relative to a descriptor this module has
//! already measured. The stable outer ancestry is ADR-0040's assumption, as
//! ADR-0073 already states: this defends against aliasing and accidental damage
//! by the same user, not against a hostile owner of `$HOME`.
//!
//! # The commit point and the lock header
//!
//! `pins.json`'s atomic rename is the **sole** commit point. `pins.lock` has a
//! fixed 144-byte header written in place — never unlinked or renamed — that
//! records whether a generation is `init`, `live`, or being rotated. The header
//! lets every reader classify a crash:
//!
//! | `pins.lock` / `pins.json` | lock-free read | writer under `LOCK_EX` |
//! |---|---|---|
//! | `init(G)` + absent | `Absent { lock: init(G) }` | first-use commit uses `G` |
//! | `init(G)` + `Current(G)` | `Existing(G)` (committed) | finalizes `live(G)` |
//! | `live(G)` + absent | `Absent { lock: live(G) }` | recreate after move-aside |
//! | `rotating{next:N}` + `Current(prev)` | `Existing(prev)`, not committed | refuses `InterruptedRotation` |
//! | `rotating{next:N}` + `Current(N)` | `Existing(N)` (committed) | finalizes `live(N)` |
//! | `rotating` + absent | `Damaged(InterruptedRotation)` | refuses; `reset` recovers |
//! | generation mismatch | `Damaged(GenerationMismatch)` | refuses; `reset(Force)` |
//! | corrupt header | `Damaged(CorruptLockHeader)` | refuses; `reset(Force)` |
//!
//! A failure while finalizing the header **after** the manifest rename is
//! committed-with-warning: the approvals are on disk, and the next writer rolls
//! the header forward. It must never be reported as "nothing was approved", and
//! it must not invite a blind repeat.
//!
//! # What this module is not
//!
//! Snapshots are not authority. Every snapshot read re-hashes the bytes, and a
//! missing or tampered snapshot is `Unavailable`, which a diff renders as an
//! empty baseline with an explicit reason. The manifest is the only record of
//! what was approved.

use std::{
    ffi::{OsStr, OsString},
    os::fd::OwnedFd,
    path::{Path, PathBuf},
};

use rustix::fs::{AtFlags, FileType, Mode, OFlags};

use crate::config_authority::{
    AuthorityRefusal, DirFacts, FileFacts, Reached, authority_dir_refusal, authority_refusal,
    raw_mode_u32,
};
use crate::config_pins::{
    Approval, ContentHash, Current, DecodeFailure, EncodeFailure, KeyState, LOCK_FILE,
    LOCK_HEADER_RECORD_BYTES, LiveGeneration, MAX_APPROVED_PER_SOURCE, MAX_LOCK_HEADER_BYTES,
    MAX_PIN_STORE_BYTES, MAX_PINNED_KEYS, MAX_SNAPSHOT_BYTES, PIN_TMP_PREFIX, PINS_FILE, PinKey,
    StoreId, Unavailable, is_snapshot_name, snapshot_name,
};
use crate::host_paths::{
    FileIdentity, FlockWait, HostFileFacts, OpenedLock, ReadBoundedError,
    atomic_write_at_with_prefix, current_euid, flock_within,
    open_regular_no_follow_at_classified_checkpointed, open_verified_lock_at,
    open_verified_lock_if_present_at, opened_dir_facts,
};
use crate::project_config::{ProjectTierPaths, check_store_route};

/// Attempts before a manifest that keeps being renamed is `Unsettled`.
const READ_ATTEMPTS: u32 = 3;
/// How long the commit path (`approve`, `reset`) waits for `pins.lock` (R15).
const COMMIT_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(5);
/// How long the launch path's active-baseline recording waits for `pins.lock`
/// (R15/D10). Recording is best effort: it gives up and warns rather than
/// delaying a launch that has already decided to boot.
const RECORD_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(1);
/// Sweep bounds: entries inspected, and unlink attempts (not successes).
const MAX_SWEEP_SCAN_ENTRIES: usize = 256;
const MAX_SWEEP_UNLINKS: usize = 64;
/// A reset removes every snapshot, so it gets a wider bounded pass.
const MAX_RESET_SWEEP_ENTRIES: usize = 2048;

/// A store that exists but cannot be used. Never a prompt and never a write.
#[derive(Debug)]
pub(crate) enum Problem {
    Untrusted(AuthorityRefusal),
    Damaged(Damage),
    Newer {
        v: u32,
    },
    Unreadable(String),
    Unsettled,
    /// The store or its lock was replaced after it was observed.
    Displaced,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Damage {
    NotAFile(FileType),
    TooLarge,
    Undecodable,
    OlderVersion(u32),
    Invalid(&'static str),
    CorruptLockHeader,
    InterruptedRotation,
    GenerationMismatch,
}

impl Damage {
    pub(crate) fn clause(&self) -> String {
        match self {
            Self::NotAFile(kind) if kind.is_dir() => "a directory".to_owned(),
            Self::NotAFile(_) => "not a regular file".to_owned(),
            Self::TooLarge => format!("larger than {MAX_PIN_STORE_BYTES} byte(s)"),
            Self::Undecodable => "not a JSON document this build reads".to_owned(),
            Self::OlderVersion(v) => format!("version {v}, which this build cannot read"),
            Self::Invalid(reason) => (*reason).to_owned(),
            Self::CorruptLockHeader => "a corrupt source pin store lock header".to_owned(),
            Self::InterruptedRotation => "an interrupted source pin store reset".to_owned(),
            Self::GenerationMismatch => {
                "a manifest generation that disagrees with its lock".to_owned()
            }
        }
    }
}

impl Problem {
    /// One escaped line for a terminal. The caller owns the `config: "<path>":`
    /// framing.
    pub(crate) fn line(&self) -> String {
        let text = match self {
            Self::Untrusted(refusal) => format!(
                "the source pin store is not trusted: {}; review it before trusting it",
                crate::allowances::refusal_clause(refusal)
            ),
            Self::Damaged(damage)
                if matches!(
                    damage,
                    Damage::CorruptLockHeader | Damage::InterruptedRotation
                ) =>
            {
                format!(
                    "the source pin store could not be used ({}); nothing can be approved across it and this release cannot repair it in place — quiesce every agent-vm process for this project, then restore the store's pins.json and its snapshots from a backup; keep `pins.lock`",
                    damage.clause()
                )
            }
            Self::Damaged(damage) => format!(
                "the source pin store could not be used ({}); agent-vm does not repair it — quiesce every agent-vm process for this project, then move `pins.json` aside to start this project's approvals over; keep `pins.lock`",
                damage.clause()
            ),
            Self::Newer { v } => format!(
                "the source pin store was written by a newer agent-vm (version {v}); this version neither reads nor replaces it"
            ),
            Self::Unreadable(error) => format!("the source pin store could not be read ({error})"),
            Self::Unsettled => {
                "the source pin store kept changing while it was read; try again".to_owned()
            }
            Self::Displaced => {
                "the source pin store was replaced while it was open; try again".to_owned()
            }
        };
        crate::one_line::text(&text).to_string()
    }
}

fn error_line(error: &anyhow::Error) -> String {
    format!("{error:#}")
}

fn display(path: &Path) -> String {
    crate::one_line::path(path).to_string()
}

/// What one lock-free observation concluded, and which exact store and
/// generation it concluded it about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ObservedStore {
    /// `None` when no store directory existed at all (no project config either).
    pub(crate) store_dir_id: Option<FileIdentity>,
    pub(crate) state: ObservedStoreState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ObservedStoreState {
    /// No `pins.json`. `lock` is present only for a valid `init`/`live` header
    /// (a reserved first use, or a post-move-aside store); `rotating` + absent
    /// is `Damaged(InterruptedRotation)` instead.
    Absent { lock: Option<LockObservation> },
    Existing {
        generation: LiveGeneration,
        lock_id: Option<FileIdentity>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LockObservation {
    pub(crate) id: FileIdentity,
    pub(crate) header: LockHeader,
}

/// The permanent lock's generation record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LockHeader {
    /// First use reserved before any `pins.json` exists.
    Init(LiveGeneration),
    /// Steady-state committed generation; normal approvals do not touch it.
    Live(LiveGeneration),
    /// A reset or recreation staged its intent before the manifest rename.
    Rotating {
        prev: Option<LiveGeneration>,
        next: LiveGeneration,
    },
}

impl LockHeader {
    fn generation(&self) -> Option<LiveGeneration> {
        match self {
            Self::Init(generation) | Self::Live(generation) => Some(*generation),
            Self::Rotating { .. } => None,
        }
    }
}

/// The 144-byte record one `pwrite` writes.
pub(crate) fn encode_lock_header(header: &LockHeader) -> [u8; LOCK_HEADER_RECORD_BYTES] {
    let text = match header {
        LockHeader::Init(generation) => format!(
            "v=1 state=init id={} epoch={}",
            generation.store_id.hex(),
            generation.reset_epoch
        ),
        LockHeader::Live(generation) => format!(
            "v=1 state=live id={} epoch={}",
            generation.store_id.hex(),
            generation.reset_epoch
        ),
        LockHeader::Rotating { prev, next } => {
            let prev = prev.map_or_else(
                || "none".to_owned(),
                |generation| format!("{}:{}", generation.store_id.hex(), generation.reset_epoch),
            );
            format!(
                "v=1 state=rotating prev={prev} next={}:{}",
                next.store_id.hex(),
                next.reset_epoch
            )
        }
    };
    debug_assert!(text.len() < LOCK_HEADER_RECORD_BYTES);
    let mut record = [b' '; LOCK_HEADER_RECORD_BYTES];
    record[..text.len()].copy_from_slice(text.as_bytes());
    record[LOCK_HEADER_RECORD_BYTES - 1] = b'\n';
    record
}

/// Parse a header record. `None` means the file was empty (a crash after the
/// lock inode was created, before any generation was reserved).
pub(crate) fn parse_lock_header(bytes: &[u8]) -> Result<Option<LockHeader>, Damage> {
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() > MAX_LOCK_HEADER_BYTES {
        return Err(Damage::CorruptLockHeader);
    }
    let Some(rest) = bytes.strip_suffix(b"\n") else {
        return Err(Damage::CorruptLockHeader);
    };
    let Ok(text) = std::str::from_utf8(rest) else {
        return Err(Damage::CorruptLockHeader);
    };
    if text.contains('\n') {
        return Err(Damage::CorruptLockHeader);
    }
    let tokens: Vec<&str> = text.trim_end_matches(' ').split(' ').collect();
    if tokens.first() != Some(&"v=1") {
        return Err(Damage::CorruptLockHeader);
    }
    match tokens.get(1) {
        Some(state) if *state == "state=init" || *state == "state=live" => {
            if tokens.len() != 4 {
                return Err(Damage::CorruptLockHeader);
            }
            let generation = parse_generation(
                tokens[2]
                    .strip_prefix("id=")
                    .ok_or(Damage::CorruptLockHeader)?,
                tokens[3]
                    .strip_prefix("epoch=")
                    .ok_or(Damage::CorruptLockHeader)?,
            )?;
            if generation.reset_epoch < 1 {
                return Err(Damage::CorruptLockHeader);
            }
            Ok(Some(if *state == "state=init" {
                LockHeader::Init(generation)
            } else {
                LockHeader::Live(generation)
            }))
        }
        Some(state) if *state == "state=rotating" => {
            if tokens.len() != 4 {
                return Err(Damage::CorruptLockHeader);
            }
            let prev_token = tokens[2]
                .strip_prefix("prev=")
                .ok_or(Damage::CorruptLockHeader)?;
            let next_token = tokens[3]
                .strip_prefix("next=")
                .ok_or(Damage::CorruptLockHeader)?;
            let (store_id, epoch) = next_token
                .split_once(':')
                .ok_or(Damage::CorruptLockHeader)?;
            let next = parse_generation(store_id, epoch)?;
            let prev = if prev_token == "none" {
                None
            } else {
                let (store_id, epoch) = prev_token
                    .split_once(':')
                    .ok_or(Damage::CorruptLockHeader)?;
                Some(parse_generation(store_id, epoch)?)
            };
            Ok(Some(LockHeader::Rotating { prev, next }))
        }
        _ => Err(Damage::CorruptLockHeader),
    }
}

fn parse_generation(store_id: &str, epoch: &str) -> Result<LiveGeneration, Damage> {
    let store_id = StoreId::parse_hex(store_id).ok_or(Damage::CorruptLockHeader)?;
    let reset_epoch = epoch
        .parse::<u64>()
        .map_err(|_| Damage::CorruptLockHeader)?;
    if reset_epoch < 1 {
        return Err(Damage::CorruptLockHeader);
    }
    Ok(LiveGeneration {
        store_id,
        reset_epoch,
    })
}

/// A writer that refused, or that committed with a warning.
#[derive(Debug)]
pub(crate) enum WriteError {
    NoStore,
    Untrusted(AuthorityRefusal),
    Damaged(Damage),
    Newer {
        v: u32,
    },
    Unreadable(String),
    Unsettled,
    Displaced,
    LockBusy(String),
    /// The reviewed incarnation is no longer the live one.
    IncarnationChanged,
    /// The store was reset or recreated after the review.
    ResetConflict,
    /// A reset was staged but did not finish; nothing may commit across it.
    InterruptedRotation,
    EpochExhausted,
    /// A peer evicted an approval this batch assumed.
    BatchStale,
    /// The next state exceeds a store cap.
    Full,
    /// A snapshot's name is occupied by something that is not a snapshot file.
    SnapshotUnwritable(String),
    /// A snapshot's bytes do not hash to the name it would be written under.
    SnapshotMismatch,
}

impl WriteError {
    pub(crate) fn line(&self) -> String {
        let text = match self {
            Self::NoStore => "this project has no source pin store".to_owned(),
            Self::Untrusted(refusal) => format!(
                "the source pin store is not trusted: {}; review it before trusting it",
                crate::allowances::refusal_clause(refusal)
            ),
            Self::Damaged(damage) => format!(
                "the source pin store could not be used ({}); agent-vm does not repair it — quiesce every agent-vm process for this project, then move `pins.json` aside to start this project's approvals over; keep `pins.lock`",
                damage.clause()
            ),
            Self::Newer { v } => format!(
                "the source pin store was written by a newer agent-vm (version {v}); this version neither reads nor replaces it"
            ),
            Self::Unreadable(error) => format!("the source pin store could not be read ({error})"),
            Self::Unsettled => {
                "the source pin store kept changing while it was read; nothing was written".to_owned()
            }
            Self::Displaced => {
                "the source pin store was replaced while it was open; nothing was written — rerun to review again".to_owned()
            }
            Self::LockBusy(error) => {
                format!("the source pin store is busy ({error}); nothing was written")
            }
            Self::IncarnationChanged => {
                "the source pin store incarnation changed while you were reviewing; nothing was approved — rerun to review again".to_owned()
            }
            Self::ResetConflict => {
                "this project's source approvals were reset while you were reviewing; nothing was approved — rerun to review again".to_owned()
            }
            Self::InterruptedRotation => {
                "a previous source pin store reset or recovery did not finish; nothing was approved and this release cannot finish it in place — quiesce every agent-vm process for this project, then restore the store's pins.json and its snapshots from a backup; keep `pins.lock`".to_owned()
            }
            Self::EpochExhausted => {
                "the source pin store reset_epoch reached u64::MAX and cannot be incremented; nothing was approved — quiesce every agent-vm process for this project, then restore the store's pins.json and its snapshots from a backup; keep `pins.lock`".to_owned()
            }
            Self::BatchStale => {
                "an approval this review assumed was removed by another process; nothing was approved — rerun to review again".to_owned()
            }
            Self::Full => format!(
                "the source pin store is full (limit {MAX_PINNED_KEYS} keys or {MAX_APPROVED_PER_SOURCE} approvals per key); nothing was approved"
            ),
            Self::SnapshotUnwritable(error) => format!(
                "a source pin snapshot could not be written ({error}); nothing was approved"
            ),
            Self::SnapshotMismatch => {
                "a source pin snapshot's bytes do not match its digest; nothing was approved".to_owned()
            }
        };
        crate::one_line::text(&text).to_string()
    }
}

impl From<EncodeFailure> for WriteError {
    fn from(failure: EncodeFailure) -> Self {
        match failure {
            EncodeFailure::Serialize => {
                Self::Unreadable("the next pin manifest could not be encoded".to_owned())
            }
            EncodeFailure::TooManyKeys
            | EncodeFailure::TooManyApprovals
            | EncodeFailure::EmptyApprovals
            | EncodeFailure::ActiveNotApproved
            | EncodeFailure::TooLarge => Self::Full,
        }
    }
}

impl From<Problem> for WriteError {
    fn from(problem: Problem) -> Self {
        match problem {
            Problem::Untrusted(refusal) => Self::Untrusted(refusal),
            Problem::Damaged(damage) => Self::Damaged(damage),
            Problem::Newer { v } => Self::Newer { v },
            Problem::Unreadable(error) => Self::Unreadable(error),
            Problem::Unsettled => Self::Unsettled,
            Problem::Displaced => Self::Displaced,
        }
    }
}

/// One approval in a commit batch.
///
/// The `Debug` below is manual for the same reason [`PendingSource`]'s is
/// ([`super::PendingSource`]): a batch holds the exact reviewed bytes, and B6
/// keeps those out of every debug and error path. The identity and the digest
/// stay, so a failed assertion still says which approval was in flight.
pub(crate) struct ApprovalCandidate {
    pub(crate) key: PinKey,
    pub(crate) hash: ContentHash,
    /// The exact reviewed bytes; re-hashed before any snapshot write.
    pub(crate) bytes: Vec<u8>,
    /// Whether the key's last-active pointer moves to this digest.
    pub(crate) activate: bool,
}

impl std::fmt::Debug for ApprovalCandidate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ApprovalCandidate")
            .field("key", &self.key)
            .field("hash", &self.hash)
            .field("bytes", &super::RedactedBytes(self.bytes.len()))
            .field("activate", &self.activate)
            .finish()
    }
}

/// Everything one locked transaction applies. `retained_keys` are all declared
/// `trust = false` keys, so a full store can never evict a key the project
/// still uses.
#[derive(Debug, Default)]
pub(crate) struct CommitBatch {
    pub(crate) approve: Vec<ApprovalCandidate>,
    pub(crate) activate: Vec<(PinKey, ContentHash)>,
    pub(crate) retained_keys: Vec<PinKey>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReceiptKind {
    Approved,
    AlreadyApproved,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Receipt {
    pub(crate) key: PinKey,
    pub(crate) hash: ContentHash,
    pub(crate) kind: ReceiptKind,
}

/// What a commit did. `warnings` never undoes a committed manifest.
#[derive(Debug)]
pub(crate) struct CommitOutcome {
    pub(crate) receipts: Vec<Receipt>,
    pub(crate) warnings: Vec<String>,
    pub(crate) generation: LiveGeneration,
}

/// The outcome of reading snapshots for a diff. A missing or tampered snapshot
/// is absent from `snapshots`, and its reason is recorded.
///
/// `Debug` names the digests whose snapshots were produced, never their text:
/// snapshot content is source text, and B6 keeps it out of every debug and error
/// path. The review transcript is where it is deliberately shown.
pub(crate) struct DiffState {
    pub(crate) generation: LiveGeneration,
    pub(crate) current: Current,
    pub(crate) snapshots: std::collections::BTreeMap<ContentHash, String>,
    pub(crate) unavailable: std::collections::BTreeMap<ContentHash, Unavailable>,
}

impl std::fmt::Debug for DiffState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        struct Digests<'a>(&'a std::collections::BTreeMap<ContentHash, String>);

        impl std::fmt::Debug for Digests<'_> {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let mut map = formatter.debug_map();
                for (hash, text) in self.0 {
                    map.entry(hash, &super::RedactedBytes(text.len()));
                }
                map.finish()
            }
        }

        formatter
            .debug_struct("DiffState")
            .field("generation", &self.generation)
            .field("current", &self.current)
            .field("snapshots", &Digests(&self.snapshots))
            .field("unavailable", &self.unavailable)
            .finish()
    }
}

/// One pending source as the locked diff read needs it: the key whose baseline
/// the review must describe, and the exact candidate bytes the load read.
///
/// The baseline digest is deliberately not a field. It is whatever the key's
/// `active` digest is in the manifest the read obtains under its shared lock
/// (B7); the digest a pre-lock inspection named can be stale, and a review that
/// fetched that one would mislabel a baseline the store still holds.
pub(crate) struct DiffRequest<'a> {
    pub(crate) key: &'a PinKey,
    pub(crate) candidate: &'a [u8],
}

/// One project's pin store handle. Holds the route, never an open descriptor:
/// each operation re-opens and re-verifies, so a store replaced between two
/// operations is `Displaced` rather than silently used.
pub(crate) struct PinStore {
    route: ProjectTierPaths,
    #[cfg(test)]
    pub(crate) faults: Faults,
}

#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct Faults {
    /// Simulates a failed post-rename `pins.lock` finalization.
    pub(crate) fail_finalize: bool,
    /// Simulates a snapshot whose content-addressed name is occupied, the arm
    /// that reports `SnapshotUnwritable`. The target generation's store id is
    /// generated inside the commit, so a test cannot occupy the real name.
    pub(crate) fail_snapshot: bool,
    /// Simulates the manifest rename failing the way a full disk does.
    pub(crate) fail_publish: bool,
}

impl PinStore {
    pub(crate) fn new(route: ProjectTierPaths) -> Self {
        Self {
            route,
            #[cfg(test)]
            faults: Faults::default(),
        }
    }

    /// A store at a scratch home for this crate's tests.
    #[cfg(test)]
    pub(crate) fn at_for_tests(home: &Path, project: &crate::project::ProjectDir) -> Self {
        Self::new(ProjectTierPaths {
            config: crate::project_config::path(home, project),
            route: crate::project_config::RouteAnchor::Captured {
                home: home.to_path_buf(),
                root: project.path().to_path_buf(),
                root_id: project.identity(),
            },
        })
    }

    /// The post-publish finalization fault seam. Production always finalizes.
    fn injected_finalize_failure(&self) -> bool {
        #[cfg(test)]
        {
            self.faults.fail_finalize
        }
        #[cfg(not(test))]
        {
            false
        }
    }

    /// The pre-publish snapshot fault seam. Production always writes snapshots.
    fn injected_snapshot_failure(&self) -> bool {
        #[cfg(test)]
        {
            self.faults.fail_snapshot
        }
        #[cfg(not(test))]
        {
            false
        }
    }

    /// The pre-publish manifest fault seam. Production always renames.
    fn injected_publish_failure(&self) -> bool {
        #[cfg(test)]
        {
            self.faults.fail_publish
        }
        #[cfg(not(test))]
        {
            false
        }
    }

    /// Read the store without taking the lock and without writing anything.
    pub(crate) fn observe(&self) -> Result<ObservedStore, Problem> {
        self.read_state().map(|(observed, _)| observed)
    }

    /// [`Self::observe`], also returning the manifest it read.
    ///
    /// One descriptor traversal, one lock-header read and one manifest read,
    /// with no `pins.lock` and therefore no lock wait: this is the lock-free
    /// launch `load` (R15) and the lock-free `doctor` read. The atomic rename
    /// guarantees one complete old or new document; the returned state names
    /// exactly the store and generation the manifest came from.
    pub(crate) fn read_state(&self) -> Result<(ObservedStore, Current), Problem> {
        let placeholder = Current::empty(LiveGeneration {
            // No generation was ever published, so no snapshot name can collide
            // with this placeholder.
            store_id: StoreId([0_u8; 16]),
            reset_epoch: 1,
        });
        let Some(dir) = VerifiedStoreDir::open(&self.route)? else {
            return Ok((
                ObservedStore {
                    store_dir_id: None,
                    state: ObservedStoreState::Absent { lock: None },
                },
                placeholder,
            ));
        };
        let lock_id = dir.lock_identity()?;
        let header = dir.read_lock_header()?;
        // The manifest reader retries renames internally; the header and
        // manifest are compared *together* before either state is reported, so
        // a `Rotating` header with no manifest can never be called `Absent`.
        match dir.read_manifest()? {
            None => match header {
                Some(LockHeader::Rotating { .. }) => {
                    Err(Problem::Damaged(Damage::InterruptedRotation))
                }
                Some(header) => {
                    let generation = header.generation().unwrap_or(LiveGeneration {
                        store_id: StoreId([0_u8; 16]),
                        reset_epoch: 1,
                    });
                    Ok((
                        ObservedStore {
                            store_dir_id: Some(dir.store_dir_id),
                            state: ObservedStoreState::Absent {
                                lock: lock_id.map(|id| LockObservation { id, header }),
                            },
                        },
                        Current::empty(generation),
                    ))
                }
                None => Ok((
                    ObservedStore {
                        store_dir_id: Some(dir.store_dir_id),
                        state: ObservedStoreState::Absent { lock: None },
                    },
                    placeholder,
                )),
            },
            Some(current) => {
                let generation = compatible_generation(header, current.generation())?;
                Ok((
                    ObservedStore {
                        store_dir_id: Some(dir.store_dir_id),
                        state: ObservedStoreState::Existing {
                            generation,
                            lock_id,
                        },
                    },
                    current,
                ))
            }
        }
    }

    /// Read the store for a diff: take `LOCK_SH` when the lock exists, enforce
    /// the observed generation, and verify the baseline snapshot of each
    /// request's key.
    ///
    /// `requests` names the pending sources, not the digests to fetch: each
    /// baseline is the key's `active` digest in the manifest **this** read
    /// obtains under the lock (B7). A caller-supplied digest list would be the
    /// observation the load made before the lock, and another launch can move
    /// `active` in between.
    pub(crate) fn read_for_diff(
        &self,
        observed: &ObservedStore,
        requests: &[DiffRequest<'_>],
    ) -> Result<DiffState, Problem> {
        let Some(dir) = VerifiedStoreDir::open(&self.route)? else {
            return Err(Problem::Displaced);
        };
        if observed.store_dir_id != Some(dir.store_dir_id) {
            return Err(Problem::Displaced);
        }
        let lock = open_verified_lock_if_present_at(
            &dir.store_fd,
            OsStr::new(LOCK_FILE),
            dir.euid,
            &dir.store_dir.join(LOCK_FILE),
        )
        .map_err(|error| Problem::Unreadable(error_line(&error)))?;
        let _held = match &lock {
            Some(lock) => {
                match flock_within(
                    &lock.file,
                    crate::host_paths::FlockMode::Shared,
                    std::time::Duration::from_secs(2),
                    |_| {},
                )
                .map_err(|error| Problem::Unreadable(error_line(&error)))?
                {
                    FlockWait::Acquired => {}
                    FlockWait::TimedOut => {
                        return Err(Problem::Unreadable(
                            "timed out after 2s waiting for pins.lock".to_owned(),
                        ));
                    }
                }
                Some(lock)
            }
            None => None,
        };
        if !observed_lock_matches(observed.state, lock.as_ref().map(|lock| lock.identity)) {
            return Err(Problem::Displaced);
        }
        dir.verify_anchored(lock.as_ref())?;
        let header = dir.read_lock_header()?;
        let Some(current) = dir.read_manifest()? else {
            // No manifest yet: a first-use or post-move-aside store has no
            // baseline to diff against, so every pending source reviews against
            // empty. `Rotating` still fails closed.
            let generation = match header {
                Some(LockHeader::Rotating { .. }) => {
                    return Err(Problem::Damaged(Damage::InterruptedRotation));
                }
                Some(header) => header.generation(),
                None => None,
            };
            let generation = generation.unwrap_or(LiveGeneration {
                // No generation was ever published, so no snapshot name can
                // collide with this placeholder.
                store_id: StoreId([0_u8; 16]),
                reset_epoch: 1,
            });
            return Ok(DiffState {
                generation,
                current: Current::empty(generation),
                snapshots: std::collections::BTreeMap::new(),
                unavailable: std::collections::BTreeMap::new(),
            });
        };
        let generation = compatible_generation(header, current.generation())?;
        if matches!(
            header,
            Some(LockHeader::Rotating {
                prev: Some(prev),
                ..
            }) if prev == current.generation()
        ) {
            return Err(Problem::Damaged(Damage::InterruptedRotation));
        }
        match observed.state {
            ObservedStoreState::Existing {
                generation: expected,
                ..
            } if expected == generation => {}
            ObservedStoreState::Absent { .. } if generation.reset_epoch == 1 => {}
            _ => return Err(Problem::Damaged(Damage::GenerationMismatch)),
        }
        let mut snapshots = std::collections::BTreeMap::new();
        let mut unavailable = std::collections::BTreeMap::new();
        for request in requests {
            let Some(key_state) = current.key_state(request.key) else {
                // No manifest entry for this key: a first use reviews against
                // empty, and there is no baseline snapshot to fetch.
                continue;
            };
            if current.is_approved(request.key, &ContentHash::of(request.candidate)) {
                // Approved while we were inspecting: the question is already
                // answered, so this review needs no baseline for it.
                continue;
            }
            let hash = key_state.active;
            if snapshots.contains_key(&hash) || unavailable.contains_key(&hash) {
                continue;
            }
            match dir.read_snapshot(generation.store_id, &hash) {
                Ok(text) => {
                    snapshots.insert(hash, text);
                }
                Err(reason) => {
                    unavailable.insert(hash, reason);
                }
            }
        }
        Ok(DiffState {
            generation,
            current,
            snapshots,
            unavailable,
        })
    }

    /// The exact approved text for one digest in one generation, re-hashed.
    pub(crate) fn read_snapshot(
        &self,
        store_id: StoreId,
        hash: &ContentHash,
    ) -> Result<String, Unavailable> {
        let dir = VerifiedStoreDir::open(&self.route).map_err(unavailable_problem)?;
        let dir = dir.ok_or(Unavailable::Missing)?;
        dir.read_snapshot(store_id, hash)
    }

    /// Commit one batch under `LOCK_EX`, re-verifying store and generation after
    /// the lock. Nothing is written until the whole next manifest encodes.
    pub(crate) fn update(
        &self,
        expected: &ObservedStore,
        batch: &CommitBatch,
        now_ms: i64,
    ) -> Result<CommitOutcome, WriteError> {
        self.update_within(expected, batch, now_ms, COMMIT_LOCK_WAIT, |_| {}, |_| {})
    }

    /// [`Self::update`] for the launch path's best-effort active-baseline
    /// recording (R15/D10): the same one commit path, with a brief lock budget
    /// instead of the commit path's. Recording may never delay a launch that has
    /// already decided to boot, so a busy store answers `LockBusy` and the caller
    /// warns and continues; nothing is retried here.
    pub(crate) fn update_recording(
        &self,
        expected: &ObservedStore,
        batch: &CommitBatch,
        now_ms: i64,
    ) -> Result<CommitOutcome, WriteError> {
        self.update_within(expected, batch, now_ms, RECORD_LOCK_WAIT, |_| {}, |_| {})
    }

    /// [`Self::update`] with the pre-publish checkpoint a test interleaves
    /// through: `before_publish` runs after the snapshots and before the
    /// manifest rename, while the exclusive lock is held. Production passes
    /// no-ops, so there is still one commit path.
    #[cfg(test)]
    pub(crate) fn update_checkpointed(
        &self,
        expected: &ObservedStore,
        batch: &CommitBatch,
        now_ms: i64,
        before_publish: impl FnOnce(&Path),
    ) -> Result<CommitOutcome, WriteError> {
        self.update_within(
            expected,
            batch,
            now_ms,
            COMMIT_LOCK_WAIT,
            before_publish,
            |_| {},
        )
    }

    /// [`Self::update`] with a caller-chosen lock budget, the observation seams
    /// the tests use, or both. Production passes no-ops, so there is still one
    /// commit path.
    fn update_within(
        &self,
        expected: &ObservedStore,
        batch: &CommitBatch,
        now_ms: i64,
        lock_wait: std::time::Duration,
        before_publish: impl FnOnce(&Path),
        after_publish: impl FnOnce(&Path),
    ) -> Result<CommitOutcome, WriteError> {
        let dir = VerifiedStoreDir::open(&self.route)?.ok_or(WriteError::NoStore)?;
        if expected.store_dir_id != Some(dir.store_dir_id) {
            return Err(WriteError::IncarnationChanged);
        }
        let lock = open_verified_lock_at(
            &dir.store_fd,
            OsStr::new(LOCK_FILE),
            dir.euid,
            &dir.store_dir.join(LOCK_FILE),
        )
        .map_err(|error| WriteError::Unreadable(error_line(&error)))?;
        match crate::host_paths::flock_exclusive_within(&lock.file, lock_wait, |_| {})
            .map_err(|error| WriteError::LockBusy(error_line(&error)))?
        {
            FlockWait::Acquired => {}
            FlockWait::TimedOut => {
                return Err(WriteError::LockBusy(format!(
                    "timed out after {}s waiting for pins.lock",
                    lock_wait.as_secs()
                )));
            }
        }
        dir.verify_anchored(Some(&lock))?;
        // `verify_anchored` proves the descriptor is still the *live name*; it
        // says nothing about which inode the review observed, so a replaced
        // lock would be accepted. The observation's identity is the fence.
        if !observed_lock_matches(expected.state, Some(lock.identity)) {
            return Err(WriteError::IncarnationChanged);
        }

        let header = dir.read_lock_header()?;
        // A rotation staged but not committed must never accept a stale review.
        if let Some(LockHeader::Rotating {
            prev: Some(prev), ..
        }) = header
            && let Some(current) = dir.read_manifest()?
            && current.generation() == prev
        {
            return Err(WriteError::InterruptedRotation);
        }
        let current = dir.read_manifest()?;
        let mut target = match (&current, header) {
            (None, Some(LockHeader::Init(generation))) => {
                if expected.state == (ObservedStoreState::Absent { lock: None })
                    && expected.store_dir_id.is_some()
                    && generation.reset_epoch != 1
                {
                    return Err(WriteError::ResetConflict);
                }
                generation
            }
            (None, Some(LockHeader::Live(generation))) => LiveGeneration {
                store_id: StoreId::generate()
                    .map_err(|error| WriteError::Unreadable(error_line(&error)))?,
                reset_epoch: generation
                    .checked_next_epoch()
                    .map_err(|_| WriteError::EpochExhausted)?,
            },
            (None, None) => LiveGeneration {
                store_id: StoreId::generate()
                    .map_err(|error| WriteError::Unreadable(error_line(&error)))?,
                reset_epoch: 1,
            },
            (None, Some(LockHeader::Rotating { .. })) => {
                return Err(WriteError::InterruptedRotation);
            }
            (Some(current), _) => {
                let live = compatible_generation(header, current.generation())?;
                check_expected_generation(expected, live)?;
                live
            }
        };
        // First-use and post-move-aside writers must stage the target before
        // writing snapshots, so a crash cannot publish mismatched names. A
        // `Rotating` record left by a returned error is unwound here; only a
        // crash (where no rollback can run) leaves it for `InterruptedRotation`.
        let mut rollback = StagedRotation {
            lock: &lock.file,
            restore: None,
        };
        let staged = match (header, &current) {
            (Some(LockHeader::Init(generation)), None) if generation == target => {
                Some((target, false))
            }
            (Some(LockHeader::Rotating { next, .. }), Some(current))
                if next == current.generation() =>
            {
                target = next;
                Some((target, true))
            }
            (Some(LockHeader::Init(generation)), Some(current))
                if generation == current.generation() =>
            {
                Some((target, true))
            }
            (Some(LockHeader::Rotating { .. }), None) => {
                return Err(WriteError::InterruptedRotation);
            }
            (Some(LockHeader::Live(_)), None) => {
                // Move-aside recreation: stage the rotated generation first.
                Some((target, true))
            }
            (None, None) => Some((target, true)),
            _ => None,
        };
        if let Some((generation, write_init)) = staged {
            let record = if write_init && generation.reset_epoch >= 2 {
                LockHeader::Rotating {
                    prev: None,
                    next: generation,
                }
            } else {
                LockHeader::Init(generation)
            };
            // What an ordinary error before the manifest rename must put back, so
            // a returned error leaves the readable store it found. A move-aside
            // recreation had a `Live` record; a roll-forward of an already
            // committed `Rotating` record has the manifest published at `next`,
            // so `Live(next)` is its completion. An `Init` reservation needs no
            // rollback: it re-reads as the same absent store.
            let restore = if matches!(record, LockHeader::Rotating { .. }) {
                Some(match header {
                    Some(LockHeader::Live(live)) => LockHeader::Live(live),
                    _ => LockHeader::Live(generation),
                })
            } else {
                None
            };
            if let Err(error) = write_lock_header(&lock.file, &record) {
                return Err(WriteError::Unreadable(error.to_string()));
            }
            rollback = StagedRotation {
                lock: &lock.file,
                restore,
            };
        }

        let manifest_exists = current.is_some();
        let mut next = current.clone().unwrap_or_else(|| Current::empty(target));
        if next.generation() != target {
            next = Current {
                generation: target,
                sources: next.sources().clone(),
            };
        }
        let receipts = next.apply_batch(batch, now_ms)?;
        if !manifest_exists && receipts.is_empty() && batch.activate.is_empty() {
            return Ok(CommitOutcome {
                receipts,
                warnings: Vec::new(),
                generation: target,
            });
        }
        let unchanged = manifest_exists
            && current.as_ref().is_some_and(|current| *current == next)
            && !matches!(header, Some(LockHeader::Rotating { .. }));
        if unchanged {
            return Ok(CommitOutcome {
                receipts,
                warnings: Vec::new(),
                generation: target,
            });
        }
        let encoded = next.encode()?;
        let mut warnings = Vec::new();
        for candidate in &batch.approve {
            if ContentHash::of(&candidate.bytes) != candidate.hash {
                return Err(WriteError::SnapshotMismatch);
            }
            let name = snapshot_name(target.store_id, &candidate.hash);
            let name_os = OsString::from(name.clone());
            if self.injected_snapshot_failure() {
                return Err(WriteError::SnapshotUnwritable(format!(
                    "{name} is a directory (injected)"
                )));
            }
            match dir.entry_kind(&name_os) {
                Ok(None) => {
                    dir.write_snapshot(&name_os, &candidate.bytes)?;
                }
                Ok(Some(FileType::RegularFile)) => {
                    if dir.read_snapshot(target.store_id, &candidate.hash).is_err() {
                        dir.write_snapshot(&name_os, &candidate.bytes)?;
                    }
                }
                Ok(Some(kind)) => {
                    return Err(WriteError::SnapshotUnwritable(format!(
                        "{name} is {}",
                        kind_name(kind)
                    )));
                }
                Err(problem) => return Err(problem.into()),
            }
        }
        before_publish(&dir.store_dir);
        // Immediately before the rename, re-check that this writer still holds
        // the live lock name. A lock replaced while the old inode is held lets a
        // second writer lock the replacement concurrently; without this check
        // both read the same manifest and each publishes a next one, and the
        // last rename silently loses the other's approval.
        dir.verify_anchored(Some(&lock))?;
        if self.injected_publish_failure() {
            return Err(WriteError::Unreadable(
                "renaming pins.json: No space left on device (os error 28) (injected)".to_owned(),
            ));
        }
        if let Err(error) = atomic_write_at_with_prefix(
            &dir.store_fd,
            PIN_TMP_PREFIX,
            OsStr::new(PINS_FILE),
            &encoded,
            0o600,
            &dir.store_dir.join(PINS_FILE),
        ) {
            return Err(WriteError::Unreadable(error_line(&error)));
        }
        // COMMIT POINT: nothing before this point may leave a staged record.
        rollback.disarm();
        after_publish(&dir.store_dir);

        // COMMIT POINT has passed. A finalization failure is reported as a
        // warning: the approvals are on disk and the next writer rolls forward.
        let _ = header;
        let finalize = match dir.read_lock_header() {
            Ok(live_header) => should_finalize(live_header),
            Err(problem) => {
                warnings.push(format!(
                    "the approvals were recorded, but the source pin store lock could not be read back ({}); rerun any agent-vm command to finish recovery",
                    problem.line()
                ));
                false
            }
        };
        if finalize {
            let written = if self.injected_finalize_failure() {
                Err(std::io::Error::other("injected finalization failure"))
            } else {
                write_lock_header(&lock.file, &LockHeader::Live(target))
            };
            if let Err(error) = written {
                warnings.push(format!(
                    "the approvals were recorded, but the source pin store lock could not be finalized ({error}); rerun any agent-vm command to finish recovery"
                ));
            }
        }
        let sweep = dir.sweep(&next, &mut warnings);
        if !sweep {
            warnings.push(format!(
                "pin store cleanup for {} did not finish within the bounded pass; quiesce every agent-vm process for this project and remove the unused pin-*.toml files from that directory, keeping pins.json and pins.lock",
                display(&dir.store_dir)
            ));
        }
        Ok(CommitOutcome {
            receipts,
            warnings,
            generation: target,
        })
    }

    /// Reset the store: rotate `store_id` and advance `reset_epoch` (at least 2),
    /// publish an empty manifest, then sweep every snapshot. `pins.lock` keeps
    /// its inode. `Force` additionally resets a damaged or mismatched store.
    pub(crate) fn reset(&self, mode: ResetMode) -> Result<ResetOutcome, WriteError> {
        let dir = VerifiedStoreDir::open_force(&self.route)?;
        let lock = open_verified_lock_at(
            &dir.store_fd,
            OsStr::new(LOCK_FILE),
            dir.euid,
            &dir.store_dir.join(LOCK_FILE),
        )
        .map_err(|error| WriteError::Unreadable(error_line(&error)))?;
        match crate::host_paths::flock_exclusive_within(&lock.file, COMMIT_LOCK_WAIT, |_| {})
            .map_err(|error| WriteError::LockBusy(error_line(&error)))?
        {
            FlockWait::Acquired => {}
            FlockWait::TimedOut => {
                return Err(WriteError::LockBusy(format!(
                    "timed out after {}s waiting for pins.lock",
                    COMMIT_LOCK_WAIT.as_secs()
                )));
            }
        }
        dir.verify_anchored(Some(&lock))?;

        let header = match dir.read_lock_header() {
            Ok(header) => header,
            Err(problem) if mode == ResetMode::Force => {
                if let Problem::Damaged(Damage::CorruptLockHeader) = problem {
                    None
                } else {
                    return Err(problem.into());
                }
            }
            Err(problem) => return Err(problem.into()),
        };
        let manifest = dir.read_manifest_force(mode == ResetMode::Force)?;
        let mut epochs = Vec::new();
        if let Some(epoch) = manifest.as_ref().and_then(ManifestState::epoch) {
            epochs.push(epoch);
        }
        if let Some(header) = header {
            if let Some(generation) = header.generation() {
                epochs.push(generation.reset_epoch);
            }
            if let LockHeader::Rotating { next, .. } = header {
                epochs.push(next.reset_epoch);
            }
        }
        let base_epoch = epochs.into_iter().max().unwrap_or(1);
        let next_epoch = base_epoch
            .checked_add(1)
            .ok_or(WriteError::EpochExhausted)?
            .max(2);
        let next = LiveGeneration {
            store_id: StoreId::generate()
                .map_err(|error| WriteError::Unreadable(error_line(&error)))?,
            reset_epoch: next_epoch,
        };
        let prev = header.and_then(|header| header.generation());
        write_lock_header(&lock.file, &LockHeader::Rotating { prev, next })
            .map_err(|error| WriteError::Unreadable(error.to_string()))?;
        let empty = Current::empty(next).encode()?;
        atomic_write_at_with_prefix(
            &dir.store_fd,
            PIN_TMP_PREFIX,
            OsStr::new(PINS_FILE),
            &empty,
            0o600,
            &dir.store_dir.join(PINS_FILE),
        )
        .map_err(|error| WriteError::Unreadable(error_line(&error)))?;
        let mut warnings = Vec::new();
        if let Err(error) = write_lock_header(&lock.file, &LockHeader::Live(next)) {
            warnings.push(format!(
                "the reset was recorded, but the source pin store lock could not be finalized ({error}); rerun any agent-vm command to finish recovery"
            ));
        }
        let complete = dir.sweep_all(&mut warnings);
        Ok(ResetOutcome {
            generation: next,
            warnings,
            cleanup_complete: complete,
        })
    }
}

enum ManifestState {
    Current(Current),
    Damaged,
}

impl ManifestState {
    fn epoch(&self) -> Option<u64> {
        match self {
            Self::Current(current) => Some(current.generation().reset_epoch),
            Self::Damaged => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResetMode {
    Normal,
    Force,
}

#[derive(Debug)]
pub(crate) struct ResetOutcome {
    pub(crate) generation: LiveGeneration,
    pub(crate) warnings: Vec<String>,
    pub(crate) cleanup_complete: bool,
}

/// The `Rotating` record a commit stages before its snapshots, and the header
/// that unwinds it.
///
/// Staging before the snapshots is what makes a crash safe:
/// `rotating + absent manifest` is `InterruptedRotation`, never a store called
/// `Absent`. A returned error is *not* a crash, though, and leaving the record
/// behind turns an ordinary write failure into a store only a force reset can
/// recover. While the exclusive lock is still held, dropping this guard puts the
/// readable header back; [`Self::disarm`] at the commit point keeps the staged
/// record for the finalization step.
struct StagedRotation<'a> {
    lock: &'a std::fs::File,
    /// `None` when no `Rotating` record was staged: nothing to unwind.
    restore: Option<LockHeader>,
}

impl StagedRotation<'_> {
    fn disarm(&mut self) {
        self.restore = None;
    }
}

impl Drop for StagedRotation<'_> {
    fn drop(&mut self) {
        if let Some(restore) = self.restore {
            // Best effort: a header write that fails here is the same fault that
            // broke the publish, and the next writer's recovery is unchanged.
            let _ = write_lock_header(self.lock, &restore);
        }
    }
}

/// Whether the lock a writer holds is the one its observation recorded.
///
/// `pins.lock` is a permanent inode *and* the serialization point, so its
/// identity is part of what a review observed. A store with no lock yet is the
/// one transition a writer may perform itself: creating the permanent lock
/// (first use, or a recreation after the manifest was moved aside). Every other
/// presence or identity difference means the store being written is not the one
/// that was reviewed.
fn observed_lock_matches(state: ObservedStoreState, acquired: Option<FileIdentity>) -> bool {
    let observed = match state {
        ObservedStoreState::Existing { lock_id, .. } => lock_id,
        ObservedStoreState::Absent { lock } => lock.map(|observation| observation.id),
    };
    match (observed, acquired) {
        (Some(observed), Some(acquired)) => observed == acquired,
        (None, _) => true,
        (Some(_), None) => false,
    }
}

fn check_expected_generation(
    expected: &ObservedStore,
    live: LiveGeneration,
) -> Result<(), WriteError> {
    match expected.state {
        ObservedStoreState::Existing { generation, .. } => {
            if generation == live {
                Ok(())
            } else if live.reset_epoch > generation.reset_epoch {
                Err(WriteError::ResetConflict)
            } else if generation.store_id != live.store_id {
                Err(WriteError::IncarnationChanged)
            } else {
                Err(WriteError::ResetConflict)
            }
        }
        ObservedStoreState::Absent { .. } if live.reset_epoch == 1 => Ok(()),
        ObservedStoreState::Absent { .. } => Err(WriteError::ResetConflict),
    }
}

fn compatible_generation(
    header: Option<LockHeader>,
    current: LiveGeneration,
) -> Result<LiveGeneration, Problem> {
    match header {
        None => Ok(current),
        Some(header) => match header {
            LockHeader::Init(generation) | LockHeader::Live(generation) => {
                if generation == current {
                    Ok(current)
                } else {
                    Err(Problem::Damaged(Damage::GenerationMismatch))
                }
            }
            LockHeader::Rotating { prev, next } => {
                if current == next || prev == Some(current) {
                    Ok(current)
                } else {
                    Err(Problem::Damaged(Damage::GenerationMismatch))
                }
            }
        },
    }
}

fn should_finalize(live_header: Option<LockHeader>) -> bool {
    // A live header is already final; init and rotating are both pre-final.
    !matches!(live_header, Some(LockHeader::Live(_)))
}

/// One opened and verified project store.
struct VerifiedStoreDir {
    projects_fd: OwnedFd,
    store_fd: OwnedFd,
    project_id: OsString,
    store_dir: PathBuf,
    store_dir_id: FileIdentity,
    euid: u32,
}

impl VerifiedStoreDir {
    fn open(route: &ProjectTierPaths) -> Result<Option<Self>, Problem> {
        let Some(dir) = Self::open_verified(route)? else {
            return Ok(None);
        };
        // The descriptor is the anchor; the route check adds the ADR-0073 alias
        // refusal. Running it after the descriptor open lets a symlinked store
        // directory be reported as `DirNotDirectory`, not as an opaque route.
        check_store_route(route).map_err(|error| Problem::Unreadable(error_line(&error)))?;
        Ok(Some(dir))
    }

    /// [`Self::open`] for a reset that must reach a store the route refuses only
    /// because its bytes are damaged. The directory route itself is still
    /// verified.
    fn open_force(route: &ProjectTierPaths) -> Result<Self, Problem> {
        let dir = Self::open_verified(route)?
            .ok_or_else(|| Problem::Unreadable("no source pin store".to_owned()))?;
        check_store_route(route).map_err(|error| Problem::Unreadable(error_line(&error)))?;
        Ok(dir)
    }

    fn open_verified(route: &ProjectTierPaths) -> Result<Option<Self>, Problem> {
        let store_dir = route
            .config
            .parent()
            .ok_or_else(|| Problem::Unreadable("the store has no directory".to_owned()))?
            .to_path_buf();
        let projects_dir = store_dir
            .parent()
            .ok_or_else(|| Problem::Unreadable("the store has no parent".to_owned()))?
            .to_path_buf();
        let project_id = store_dir
            .file_name()
            .ok_or_else(|| Problem::Unreadable("the store has no name".to_owned()))?
            .to_os_string();
        let euid = current_euid();
        let projects_fd = match rustix::fs::open(
            &projects_dir,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(rustix::io::Errno::LOOP) | Err(rustix::io::Errno::NOTDIR) => {
                return Err(Problem::Untrusted(AuthorityRefusal::DirNotDirectory));
            }
            Err(error) => {
                return Err(Problem::Unreadable(format!(
                    "opening {}: {error}",
                    display(&projects_dir)
                )));
            }
        };
        let projects_facts = opened_dir_facts(&projects_fd, &display(&projects_dir))
            .map_err(|error| Problem::Unreadable(error_line(&error)))?;
        if let Some(refusal) = authority_dir_refusal(dir_facts(&projects_facts), euid) {
            return Err(Problem::Untrusted(refusal));
        }
        let store_fd = match rustix::fs::openat(
            &projects_fd,
            &project_id,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(rustix::io::Errno::LOOP) | Err(rustix::io::Errno::NOTDIR) => {
                return Err(Problem::Untrusted(AuthorityRefusal::DirNotDirectory));
            }
            Err(error) => {
                return Err(Problem::Unreadable(format!(
                    "opening {}: {error}",
                    display(&store_dir)
                )));
            }
        };
        let store_facts = opened_dir_facts(&store_fd, &display(&store_dir))
            .map_err(|error| Problem::Unreadable(error_line(&error)))?;
        if let Some(refusal) = authority_dir_refusal(dir_facts(&store_facts), euid) {
            return Err(Problem::Untrusted(refusal));
        }
        let store_dir_id = FileIdentity {
            dev: store_facts.dev,
            ino: store_facts.ino,
        };
        Ok(Some(Self {
            projects_fd,
            store_fd,
            project_id,
            store_dir,
            store_dir_id,
            euid,
        }))
    }

    fn lock_identity(&self) -> Result<Option<FileIdentity>, Problem> {
        match open_verified_lock_if_present_at(
            &self.store_fd,
            OsStr::new(LOCK_FILE),
            self.euid,
            &self.store_dir.join(LOCK_FILE),
        ) {
            Ok(lock) => Ok(lock.map(|lock| lock.identity)),
            Err(error) => Err(Problem::Unreadable(error_line(&error))),
        }
    }

    fn read_lock_header(&self) -> Result<Option<LockHeader>, Problem> {
        let Some(lock) = open_verified_lock_if_present_at(
            &self.store_fd,
            OsStr::new(LOCK_FILE),
            self.euid,
            &self.store_dir.join(LOCK_FILE),
        )
        .map_err(|error| Problem::Unreadable(error_line(&error)))?
        else {
            return Ok(None);
        };
        read_header_bytes(&lock.file)
    }

    /// Re-verify the descriptor pair and the live names after a lock was taken:
    /// a replaced store or lock must fail closed, never look like an absent one.
    fn verify_anchored(&self, lock: Option<&OpenedLock>) -> Result<(), Problem> {
        let projects_facts = opened_dir_facts(&self.projects_fd, &"the projects directory")
            .map_err(|error| Problem::Unreadable(error_line(&error)))?;
        if let Some(refusal) = authority_dir_refusal(dir_facts(&projects_facts), self.euid) {
            return Err(Problem::Untrusted(refusal));
        }
        let store_facts = opened_dir_facts(&self.store_fd, &"the project store")
            .map_err(|error| Problem::Unreadable(error_line(&error)))?;
        if let Some(refusal) = authority_dir_refusal(dir_facts(&store_facts), self.euid) {
            return Err(Problem::Untrusted(refusal));
        }
        let anchored = rustix::fs::statat(
            &self.projects_fd,
            &self.project_id,
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| Problem::Displaced)?;
        if FileType::from_raw_mode(anchored.st_mode) != FileType::Directory
            || anchored.st_dev as u64 != self.store_dir_id.dev
            || anchored.st_ino != self.store_dir_id.ino
        {
            return Err(Problem::Displaced);
        }
        if let Some(lock) = lock {
            let live = rustix::fs::statat(
                &self.store_fd,
                OsStr::new(LOCK_FILE),
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(|_| Problem::Displaced)?;
            let live_identity = FileIdentity {
                dev: live.st_dev as u64,
                ino: live.st_ino,
            };
            if FileType::from_raw_mode(live.st_mode) != FileType::RegularFile
                || live_identity != lock.identity
            {
                return Err(Problem::Displaced);
            }
        }
        Ok(())
    }

    fn read_manifest(&self) -> Result<Option<Current>, Problem> {
        self.read_manifest_inner()
    }

    fn read_manifest_force(&self, force: bool) -> Result<Option<ManifestState>, WriteError> {
        match self.read_manifest_inner() {
            Ok(None) => Ok(None),
            Ok(Some(current)) => Ok(Some(ManifestState::Current(current))),
            Err(Problem::Damaged(_)) if force => Ok(Some(ManifestState::Damaged)),
            Err(Problem::Newer { v }) => Err(WriteError::Newer { v }),
            Err(problem) => Err(problem.into()),
        }
    }

    fn read_manifest_inner(&self) -> Result<Option<Current>, Problem> {
        let path = self.store_dir.join(PINS_FILE);
        for _ in 0..READ_ATTEMPTS {
            match rustix::fs::statat(
                &self.store_fd,
                OsStr::new(PINS_FILE),
                AtFlags::SYMLINK_NOFOLLOW,
            ) {
                Ok(stat) => {
                    let kind = FileType::from_raw_mode(stat.st_mode);
                    if kind == FileType::Symlink {
                        return Err(Problem::Untrusted(AuthorityRefusal::ThroughSymlink));
                    }
                    if kind != FileType::RegularFile {
                        return Err(Problem::Damaged(Damage::NotAFile(kind)));
                    }
                }
                Err(rustix::io::Errno::NOENT) => return Ok(None),
                Err(error) => {
                    return Err(Problem::Unreadable(format!(
                        "stating {}: {error}",
                        display(&path)
                    )));
                }
            }
            let opened = match open_regular_no_follow_at_classified_checkpointed(
                &self.store_fd,
                OsStr::new(PINS_FILE),
                &path,
                || {},
                || {},
            )
            .map_err(|error| Problem::Unreadable(error_line(&error)))?
            {
                crate::host_paths::OpenNoFollowOutcome::File(opened) => opened,
                crate::host_paths::OpenNoFollowOutcome::Symlink => {
                    return Err(Problem::Untrusted(AuthorityRefusal::ThroughSymlink));
                }
                crate::host_paths::OpenNoFollowOutcome::NotRegular(kind) => {
                    return Err(Problem::Damaged(Damage::NotAFile(kind)));
                }
                crate::host_paths::OpenNoFollowOutcome::NotFound => continue,
            };
            let facts = opened.facts();
            if facts.nlink == 0 {
                continue;
            }
            let store_dir_facts = opened_dir_facts(&self.store_fd, &"the project store")
                .map_err(|error| Problem::Unreadable(error_line(&error)))?;
            if let Some(refusal) = authority_refusal(
                Reached::Direct(file_facts(&facts)),
                dir_facts(&store_dir_facts),
                self.euid,
            ) {
                return Err(Problem::Untrusted(refusal));
            }
            if facts.size > MAX_PIN_STORE_BYTES {
                let probe = opened
                    .prefix(64)
                    .map_err(|error| Problem::Unreadable(error_line(&error)))?;
                return Err(match leading_version(&probe) {
                    Some(v) if v > 1 => Problem::Newer { v },
                    Some(v) if v < 1 => Problem::Damaged(Damage::OlderVersion(v)),
                    _ => Problem::Damaged(Damage::TooLarge),
                });
            }
            let bytes = match opened.read_bounded_classified(MAX_PIN_STORE_BYTES) {
                Ok(bytes) => bytes,
                Err(ReadBoundedError::TooLarge) => {
                    return Err(Problem::Damaged(Damage::TooLarge));
                }
                Err(ReadBoundedError::Io(error)) => {
                    return Err(Problem::Unreadable(error_line(&error)));
                }
            };
            return match Current::decode(&bytes) {
                Ok(current) => Ok(Some(current)),
                Err(DecodeFailure::Newer { v }) => Err(Problem::Newer { v }),
                Err(DecodeFailure::OlderVersion(v)) => {
                    Err(Problem::Damaged(Damage::OlderVersion(v)))
                }
                Err(DecodeFailure::Undecodable) => Err(Problem::Damaged(Damage::Undecodable)),
                Err(DecodeFailure::Invalid(clause)) => {
                    Err(Problem::Damaged(Damage::Invalid(clause)))
                }
            };
        }
        Err(Problem::Unsettled)
    }

    fn entry_kind(&self, name: &OsStr) -> Result<Option<FileType>, Problem> {
        match rustix::fs::statat(&self.store_fd, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => Ok(Some(FileType::from_raw_mode(stat.st_mode))),
            Err(rustix::io::Errno::NOENT) => Ok(None),
            Err(error) => Err(Problem::Unreadable(format!(
                "stating {}: {error}",
                display(&self.store_dir.join(name))
            ))),
        }
    }

    fn write_snapshot(&self, name: &OsStr, bytes: &[u8]) -> Result<(), WriteError> {
        atomic_write_at_with_prefix(
            &self.store_fd,
            PIN_TMP_PREFIX,
            name,
            bytes,
            0o600,
            &self.store_dir.join(name),
        )
        .map_err(|error| WriteError::SnapshotUnwritable(error_line(&error)))
    }

    fn read_snapshot(&self, store_id: StoreId, hash: &ContentHash) -> Result<String, Unavailable> {
        let name = snapshot_name(store_id, hash);
        let path = self.store_dir.join(&name);
        match rustix::fs::statat(&self.store_fd, OsStr::new(&name), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) if FileType::from_raw_mode(stat.st_mode) == FileType::Symlink => {
                return Err(Unavailable::NotTrusted(AuthorityRefusal::ThroughSymlink));
            }
            Ok(stat) if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile => {
                return Err(Unavailable::NotAFile);
            }
            Ok(_) => {}
            Err(rustix::io::Errno::NOENT) => return Err(Unavailable::Missing),
            Err(error) => return Err(Unavailable::Unreadable(format!("{error}"))),
        }
        let opened = match open_regular_no_follow_at_classified_checkpointed(
            &self.store_fd,
            OsStr::new(&name),
            &path,
            || {},
            || {},
        ) {
            Ok(crate::host_paths::OpenNoFollowOutcome::File(opened)) => opened,
            Ok(crate::host_paths::OpenNoFollowOutcome::Symlink) => {
                return Err(Unavailable::NotTrusted(AuthorityRefusal::ThroughSymlink));
            }
            Ok(crate::host_paths::OpenNoFollowOutcome::NotRegular(_)) => {
                return Err(Unavailable::NotAFile);
            }
            Ok(crate::host_paths::OpenNoFollowOutcome::NotFound) => {
                return Err(Unavailable::Missing);
            }
            Err(error) => return Err(Unavailable::Unreadable(format!("{error:#}"))),
        };
        let facts = opened.facts();
        let store_dir_facts = match opened_dir_facts(&self.store_fd, &"the project store") {
            Ok(facts) => facts,
            Err(error) => return Err(Unavailable::Unreadable(format!("{error:#}"))),
        };
        if let Some(refusal) = authority_refusal(
            Reached::Direct(file_facts(&facts)),
            dir_facts(&store_dir_facts),
            self.euid,
        ) {
            return Err(Unavailable::NotTrusted(refusal));
        }
        if facts.size > MAX_SNAPSHOT_BYTES {
            return Err(Unavailable::TooLarge);
        }
        let bytes = match opened.read_bounded_classified(MAX_SNAPSHOT_BYTES) {
            Ok(bytes) => bytes,
            Err(ReadBoundedError::TooLarge) => return Err(Unavailable::TooLarge),
            Err(ReadBoundedError::Io(error)) => {
                return Err(Unavailable::Unreadable(format!("{error:#}")));
            }
        };
        if ContentHash::of(&bytes) != *hash {
            return Err(Unavailable::HashMismatch);
        }
        String::from_utf8(bytes).map_err(|_| Unavailable::NotUtf8)
    }

    /// Remove snapshots the committed manifest no longer references, plus
    /// abandoned pin temporaries, within fixed scan and unlink bounds.
    fn sweep(&self, next: &Current, warnings: &mut Vec<String>) -> bool {
        let live: std::collections::BTreeSet<String> = next
            .sources()
            .values()
            .flat_map(|state| state.approved.iter())
            .map(|approval| snapshot_name(next.generation().store_id, &approval.hash))
            .map(|name| name.to_ascii_lowercase())
            .collect();
        self.sweep_matching(
            MAX_SWEEP_SCAN_ENTRIES,
            MAX_SWEEP_UNLINKS,
            |name| {
                if name.starts_with(PIN_TMP_PREFIX) {
                    return true;
                }
                is_snapshot_name(OsStr::new(name)) && !live.contains(&name.to_ascii_lowercase())
            },
            warnings,
        )
    }

    fn sweep_all(&self, warnings: &mut Vec<String>) -> bool {
        self.sweep_matching(
            MAX_RESET_SWEEP_ENTRIES,
            MAX_RESET_SWEEP_ENTRIES,
            |name| name.starts_with(PIN_TMP_PREFIX) || is_snapshot_name(OsStr::new(name)),
            warnings,
        )
    }

    fn sweep_matching(
        &self,
        scan_cap: usize,
        unlink_cap: usize,
        doomed: impl Fn(&str) -> bool,
        warnings: &mut Vec<String>,
    ) -> bool {
        let Ok(mut dir) = rustix::fs::Dir::read_from(&self.store_fd) else {
            warnings.push(format!(
                "could not list {}: pin store cleanup did not run",
                display(&self.store_dir)
            ));
            return false;
        };
        let mut scanned = 0_usize;
        let mut unlinked = 0_usize;
        let mut failed = 0_usize;
        let mut complete = true;
        while let Some(entry) = dir.read() {
            if scanned >= scan_cap {
                complete = false;
                break;
            }
            let Ok(entry) = entry else {
                failed += 1;
                continue;
            };
            scanned += 1;
            let bytes = entry.file_name().to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            let Ok(name) = std::str::from_utf8(bytes) else {
                continue;
            };
            if name.contains('/') || !doomed(name) {
                continue;
            }
            if unlinked >= unlink_cap {
                complete = false;
                break;
            }
            unlinked += 1;
            if rustix::fs::unlinkat(&self.store_fd, entry.file_name(), AtFlags::empty()).is_err() {
                failed += 1;
            }
        }
        if failed > 0 {
            complete = false;
        }
        complete
    }
}

fn dir_facts(facts: &crate::host_paths::OpenedDirFacts) -> DirFacts {
    DirFacts {
        is_dir: true,
        uid: facts.uid,
        mode: facts.mode,
    }
}

fn file_facts(facts: &HostFileFacts) -> FileFacts {
    FileFacts {
        uid: facts.uid,
        mode: raw_mode_u32(facts.mode),
        nlink: facts.nlink,
    }
}

fn kind_name(kind: FileType) -> &'static str {
    if kind.is_dir() {
        "a directory"
    } else {
        "not a regular file"
    }
}

fn leading_version(bytes: &[u8]) -> Option<u32> {
    let text = std::str::from_utf8(bytes).ok()?;
    let index = text.find("\"v\"")?;
    let rest = text[index + 3..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

fn read_header_bytes(file: &std::fs::File) -> Result<Option<LockHeader>, Problem> {
    use std::os::unix::fs::FileExt as _;
    let mut buffer = vec![0_u8; MAX_LOCK_HEADER_BYTES + 1];
    let mut read = 0_usize;
    while read < buffer.len() {
        match file.read_at(&mut buffer[read..], read as u64) {
            Ok(0) => break,
            Ok(count) => read += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(Problem::Unreadable(format!(
                    "reading a coordination lock header: {error}"
                )));
            }
        }
    }
    buffer.truncate(read);
    parse_lock_header(&buffer).map_err(Problem::Damaged)
}

fn write_lock_header(file: &std::fs::File, header: &LockHeader) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt as _;
    let record = encode_lock_header(header);
    let mut written = 0_usize;
    while written < record.len() {
        let count = file.write_at(&record[written..], written as u64)?;
        if count == 0 {
            return Err(std::io::Error::other("short write of a lock header"));
        }
        written += count;
    }
    // A corrupt header may have been longer than one record; the record's own
    // length is the whole header, never a prefix of old bytes.
    rustix::fs::ftruncate(file, LOCK_HEADER_RECORD_BYTES as u64).map_err(std::io::Error::from)
}

fn unavailable_problem(problem: Problem) -> Unavailable {
    match problem {
        Problem::Untrusted(refusal) => Unavailable::NotTrusted(refusal),
        Problem::Damaged(damage) => Unavailable::Unreadable(damage.clause()),
        Problem::Newer { v } => {
            Unavailable::Unreadable(format!("written by a newer agent-vm (v{v})"))
        }
        Problem::Unreadable(error) => Unavailable::Unreadable(error),
        Problem::Unsettled => Unavailable::Unreadable("kept changing while read".to_owned()),
        Problem::Displaced => Unavailable::Unreadable("the store was replaced".to_owned()),
    }
}

/// Keep one read's batch changes pure and testable: this is the state machine
/// `update` applies under the lock.
impl Current {
    pub(crate) fn apply_batch(
        &mut self,
        batch: &CommitBatch,
        now_ms: i64,
    ) -> Result<Vec<Receipt>, WriteError> {
        let mut receipts = Vec::new();
        let mut batch_hashes: std::collections::BTreeMap<
            PinKey,
            std::collections::BTreeSet<ContentHash>,
        > = std::collections::BTreeMap::new();
        for candidate in &batch.approve {
            batch_hashes
                .entry(candidate.key.clone())
                .or_default()
                .insert(candidate.hash);
        }
        let retained: std::collections::BTreeSet<PinKey> =
            batch.retained_keys.iter().cloned().collect();

        // Every `activate` names a digest a load already used, so this batch only
        // *assumes* it is still approved. A peer may have evicted it as the least
        // recently active digest while the review was open; the manifest read
        // under this lock is the authority, and a batch that cannot honour what it
        // assumed must publish nothing.
        for (key, hash) in &batch.activate {
            if !matches!(
                self.lookup(key, hash),
                crate::config_pins::Lookup::Approved { .. }
            ) {
                return Err(WriteError::BatchStale);
            }
        }

        for candidate in &batch.approve {
            let already = self
                .sources
                .get(&candidate.key)
                .is_some_and(|state| state.is_approved(&candidate.hash));
            if !already {
                if !self.sources.contains_key(&candidate.key)
                    && self.sources.len() >= MAX_PINNED_KEYS
                {
                    self.evict_key(&retained, &batch_hashes)?;
                }
                let state = self
                    .sources
                    .entry(candidate.key.clone())
                    .or_insert_with(|| KeyState {
                        active: candidate.hash,
                        approved: vec![Approval {
                            hash: candidate.hash,
                            approved_ms: now_ms,
                            active_ms: now_ms,
                        }],
                    });
                if !state.is_approved(&candidate.hash) {
                    state.approved.push(Approval {
                        hash: candidate.hash,
                        approved_ms: now_ms,
                        active_ms: if candidate.activate { now_ms } else { 0 },
                    });
                }
                if candidate.activate || state.active == candidate.hash {
                    state.active = candidate.hash;
                    if let Some(approval) = state.approval_mut(&candidate.hash) {
                        approval.active_ms = now_ms;
                    }
                }
                Self::evict_approval(state, &candidate.key, &batch_hashes);
            } else if candidate.activate {
                let state = self.sources.get_mut(&candidate.key).expect("checked above");
                if state.active != candidate.hash {
                    state.active = candidate.hash;
                    if let Some(approval) = state.approval_mut(&candidate.hash) {
                        approval.active_ms = now_ms;
                    }
                }
            }
            receipts.push(Receipt {
                key: candidate.key.clone(),
                hash: candidate.hash,
                kind: if already {
                    ReceiptKind::AlreadyApproved
                } else {
                    ReceiptKind::Approved
                },
            });
        }
        // The approvals above can evict a digest this same batch activates (an
        // approval at the cap displaces the least recently active one), so the
        // activation is re-checked against the state that is about to be
        // published rather than against the state it was validated on.
        for (key, hash) in &batch.activate {
            if !self.mark_active(key, hash, now_ms) {
                return Err(WriteError::BatchStale);
            }
        }
        Ok(receipts)
    }

    fn evict_key(
        &mut self,
        retained: &std::collections::BTreeSet<PinKey>,
        batch: &std::collections::BTreeMap<PinKey, std::collections::BTreeSet<ContentHash>>,
    ) -> Result<(), WriteError> {
        let victim = self
            .sources
            .iter()
            .filter(|(key, _)| !retained.contains(*key) && !batch.contains_key(*key))
            .min_by(|(left_key, left), (right_key, right)| {
                key_age(left)
                    .cmp(&key_age(right))
                    .then_with(|| left_key.cmp(right_key))
            })
            .map(|(key, _)| key.clone());
        let Some(victim) = victim else {
            return Err(WriteError::Full);
        };
        self.sources.remove(&victim);
        Ok(())
    }

    /// Cap one key's approvals, protecting its active digest and every digest
    /// this batch writes for it. Eviction order is (active_ms, approved_ms,
    /// sha256): the least recently active, then the least recently approved,
    /// with a deterministic tie-break.
    fn evict_approval(
        state: &mut KeyState,
        key: &PinKey,
        batch: &std::collections::BTreeMap<PinKey, std::collections::BTreeSet<ContentHash>>,
    ) {
        let protected = batch.get(key);
        while state.approved.len() > MAX_APPROVED_PER_SOURCE {
            let victim = state
                .approved
                .iter()
                .enumerate()
                .filter(|(_, approval)| approval.hash != state.active)
                .filter(|(_, approval)| {
                    !protected.is_some_and(|hashes| hashes.contains(&approval.hash))
                })
                .min_by(|(_, left), (_, right)| {
                    (left.active_ms, left.approved_ms, left.hash).cmp(&(
                        right.active_ms,
                        right.approved_ms,
                        right.hash,
                    ))
                })
                .map(|(index, _)| index);
            let Some(index) = victim else {
                break;
            };
            state.approved.remove(index);
        }
    }
}

fn key_age(state: &KeyState) -> i64 {
    state
        .approved
        .iter()
        .find(|approval| approval.hash == state.active)
        .map_or(i64::MIN, |approval| approval.active_ms)
}
