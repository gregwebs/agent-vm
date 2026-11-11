//! The project allowance record's read path: one file, measured, then decoded.
//!
//! `$HOME/.config/agent-vm/allowances.json` grants egress, so it is an
//! **authority** store: ADR-0065 trusts it only through ADR-0040's proved kernel
//! and never repairs it. Contrast `refusal::log`, the display store that heals.
//!
//! The reader is a state machine, and every state is a *classification*, not an
//! error: the launch, `access` and `doctor` all keep working and each says
//! something different about the same bytes. Two outcomes are deliberately not
//! damage — `Newer` (a later release's file) and `Unsettled` (the path kept being
//! replaced while we read it) — because neither is a defect in the file, and a
//! reader that called either one damaged would tell a user to move aside a file
//! that is doing nothing wrong (ADR-0065 §5.2).
//!
//! **Nothing here writes.** No lock, no create, no rename, no truncate: a read
//! path that creates its own store would let "ask what this project allows"
//! manufacture authority (ADR-0065 R1/R5).
//!
//! The schema types are private to this module (`pub(super)` at most), so the
//! facade above is the only door: a caller cannot hold a record that has not
//! passed [`check_record`], and cannot decode a file this build would refuse.

use std::{
    fs::{FileType, Metadata},
    io::ErrorKind,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::config;
use crate::config_authority::{
    AuthorityRefusal, DirFacts, FileFacts, Reached, authority_dir_refusal, authority_refusal,
    raw_mode_u32,
};
use crate::host_paths::{
    FlockWait, HostFileFacts, atomic_write, current_euid, flock_exclusive_within, open_lock_file,
    open_regular_no_follow_checkpointed,
};

/// The one name this module reads and writes.
pub(crate) const FILE: &str = "allowances.json";
/// The coordination lock beside it. Opened create-if-missing and never unlinked,
/// so two writers always contend on one inode (ADR-0065 Constraint 1).
pub(crate) const LOCK_FILE: &str = "allowances.lock";
/// How long one writer waits for another before reporting `LockBusy`. Short
/// enough that a stuck writer cannot hold a launch, long enough that two
/// ordinary writes do not fail each other (ADR-0065 Constraint 1).
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(1);
/// The schema version this build writes and reads (ADR-0065 P1).
const VERSION: u32 = 1;
/// A store bigger than this is not a record table anyone wrote by hand.
const MAX_BYTES: u64 = 1024 * 1024;
/// How much of a file too large to read whole the version probe reads.
///
/// The schema puts `v` first (ADR-0065 P1), so this covers every file this or a
/// later release writes. It is a bound on *reading*, not on the file: a newer
/// file bigger than [`MAX_BYTES`] is still `Newer`, because a later release
/// writing a larger body must not be told to move its file aside as damaged. A
/// file that large whose version is not in the first [`VERSION_PROBE_BYTES`] is
/// classified as damage — the conservative direction, since it applies nothing
/// either way (see [`leading_version`]).
const VERSION_PROBE_BYTES: usize = 4096;
/// The record bound, so one project's view cannot grow without end.
const MAX_RECORDS: usize = 4096;
/// Longer than this is not a canonical allowance spelling.
const MAX_DESTINATION_BYTES: usize = 512;
/// Open attempts in all when the descriptor turns out to be unlinked.
///
/// A rename is instant, so one retry covers the race; repeated `nlink == 0`
/// means sustained churn, and a fourth attempt would only make the launch wait
/// longer for the same answer.
const READ_ATTEMPTS: usize = 3;

/// The whole file, strictly. An unknown field is refused, because a restricting
/// field this build silently ignored would widen authority (ADR-0065 P1).
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AllowanceFile {
    /// First field, always: the reader's bounded version probe relies on it.
    v: u32,
    records: Vec<RecordLine>,
}

/// One record line, strictly.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordLine {
    project: String,
    path: String,
    destination: String,
    recorded_ms: i64,
}

/// The version probe: `{"v":n}` and nothing else examined.
///
/// Deliberately lenient — no `deny_unknown_fields` — because this decode happens
/// *before* the version is known, and a newer file's extra top-level field must
/// still let the reader classify it as `Newer` rather than as damage.
#[derive(Deserialize)]
struct Version {
    v: u32,
}

/// A record that passed every schema check. The parent module reads these
/// fields; nothing else can.
pub(super) struct StoredRecord {
    pub(super) project: String,
    pub(super) path: String,
    pub(super) destination: String,
    pub(super) recorded_ms: i64,
}

/// One read's classification (ADR-0065 §4.4).
pub(super) enum Read {
    Absent,
    /// Decoded, measured and trusted. `mode` is the read file's own permission
    /// bits, which `doctor` reports and the launch ignores.
    Current {
        records: Vec<StoredRecord>,
        mode: u32,
    },
    /// A later release's file: never applied by anything. `records` is what this
    /// build could read of it for `doctor`'s counts — nothing at all for a file
    /// bigger than [`MAX_BYTES`], whose body is not read.
    Newer {
        v: u32,
        records: Vec<StoredRecord>,
    },
    NotUsed(Problem),
}

/// Why a file that exists is not in force.
#[derive(Debug)]
pub(super) enum Problem {
    Damaged(Damage),
    Untrusted(AuthorityRefusal),
    /// One line, already escaped: the operation and its cause, from
    /// `host_paths`/`std::io`.
    Unreadable(String),
    /// The path was replaced between `open` and `fstat` on every attempt.
    /// Neither damage nor distrust (ADR-0065 AC7).
    Unsettled,
}

#[derive(Debug)]
pub(super) enum Damage {
    NotAFile(FileType),
    TooLarge,
    Undecodable,
    OlderVersion(u32),
    /// A per-record or whole-file rule, named by a fixed clause: a broken record
    /// never echoes its own bytes into a terminal.
    Invalid(&'static str),
}

impl Damage {
    /// The clause inside `could not be used (<this>)`.
    pub(super) fn clause(&self) -> String {
        match self {
            Self::NotAFile(kind) if kind.is_dir() => "a directory".to_owned(),
            Self::NotAFile(_) => "not a regular file".to_owned(),
            Self::TooLarge => format!("larger than {} byte(s)", MAX_BYTES),
            Self::Undecodable => "not a JSON document this build reads".to_owned(),
            Self::OlderVersion(v) => format!("version {v}, which this build cannot read"),
            Self::Invalid(reason) => (*reason).to_owned(),
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct Store {
    dir: PathBuf,
}

impl Store {
    /// `$HOME/.config/agent-vm`, or `None` when `$HOME` is unset: with no
    /// `$HOME` no user config is read at all (ADR-0038), so there is no store to
    /// report either. An `Err` means `$HOME` is set but unusable.
    pub(super) fn host() -> anyhow::Result<Option<Self>> {
        Ok(config::host_home_dir()?.map(|home| Self {
            dir: home.join(config::USER_CONFIG_DIR_RELATIVE),
        }))
    }

    /// A store at an arbitrary directory: a test's seam for every read state.
    #[cfg(test)]
    pub(super) fn at(dir: &Path) -> Self {
        Self {
            dir: dir.to_owned(),
        }
    }

    pub(super) fn file(&self) -> PathBuf {
        self.dir.join(FILE)
    }

    pub(super) fn read(&self) -> Read {
        self.read_with(current_euid(), || {})
    }

    /// [`Self::read`] with the trust decision's euid and the reopen rule's
    /// checkpoint injected, so a test can make the file foreign while the
    /// directory stays trusted, and can replace the path at exactly the moment
    /// between `open` and `fstat` (ADR-0065 AC7).
    fn read_with(&self, euid: u32, mut after_open: impl FnMut()) -> Read {
        let file = self.file();
        for _ in 0..READ_ATTEMPTS {
            // `lstat` first, so the kinds a `stat` would follow or a read would
            // block on — a symlink, a directory, a FIFO, a socket — are decided
            // without opening anything. A FIFO is never opened.
            let stated = match std::fs::symlink_metadata(&file) {
                Ok(stated) => stated,
                Err(error) if error.kind() == ErrorKind::NotFound => return Read::Absent,
                Err(error) => return Read::NotUsed(Problem::Unreadable(error_line(&error))),
            };
            if stated.file_type().is_symlink() {
                return Read::NotUsed(Problem::Untrusted(AuthorityRefusal::ThroughSymlink));
            }
            if !stated.is_file() {
                return Read::NotUsed(Problem::Damaged(Damage::NotAFile(stated.file_type())));
            }
            // Open, then classify in the order the distinctions require:
            // an unlinked descriptor is a rename (retried, AC7), then trust,
            // then version, then size, then the strict decode. Classifying
            // size or damage first would describe a foreign or newer file with
            // the remedy for a broken one.
            let opened = match open_regular_no_follow_checkpointed(&file, &mut after_open) {
                Ok(Some(opened)) => opened,
                // The path became a symlink after the `lstat` above. Still
                // `O_NOFOLLOW`: a symlink is untrusted, never damaged.
                Ok(None) => {
                    return Read::NotUsed(Problem::Untrusted(AuthorityRefusal::ThroughSymlink));
                }
                Err(error) => return Read::NotUsed(Problem::Unreadable(error_line(&error))),
            };
            let facts = opened.facts();
            if facts.nlink == 0 {
                // The descriptor outlived its name: the file was renamed over (or
                // unlinked) after `open`. A rename is what a writer does, not
                // what an attacker does, so this is retried rather than refused
                // — before the size or version can turn it into a warning.
                continue;
            }
            let dir = match std::fs::metadata(&self.dir) {
                Ok(dir) => dir,
                Err(error) => return Read::NotUsed(Problem::Unreadable(error_line(&error))),
            };
            if let Some(refusal) = trust(&facts, &dir, euid) {
                return Read::NotUsed(Problem::Untrusted(refusal));
            }
            // A later release's file is classified by what it says it is, not
            // by how big it grew: a newer file bigger than this build reads is
            // `Newer` (nothing applied), never damage whose remedy is "move it
            // aside".
            if facts.size > MAX_BYTES {
                let probe = match opened.prefix(VERSION_PROBE_BYTES) {
                    Ok(probe) => probe,
                    Err(error) => return Read::NotUsed(Problem::Unreadable(error_line(&error))),
                };
                // An oversized file carries no records: its body is not read, so
                // any count would be a partial count presented as a count. The
                // version is the only fact a bounded probe can establish.
                return match leading_version(&probe) {
                    VersionProbe::Known(v) if v > VERSION => Read::Newer {
                        v,
                        records: Vec::new(),
                    },
                    VersionProbe::Known(v) if v < VERSION => {
                        Read::NotUsed(Problem::Damaged(Damage::OlderVersion(v)))
                    }
                    // A version this build reads, and a size it does not.
                    VersionProbe::Known(_) => Read::NotUsed(Problem::Damaged(Damage::TooLarge)),
                    // The bytes are not this schema's `v` at all: a non-integer
                    // value, a leading zero, a digit run inside an identifier.
                    VersionProbe::Malformed => Read::NotUsed(Problem::Damaged(Damage::Undecodable)),
                    // The prefix does not decide it. Damage either way, and the
                    // size is the one fact the reader established.
                    VersionProbe::Undecided => Read::NotUsed(Problem::Damaged(Damage::TooLarge)),
                };
            }
            let bytes = match opened.read_bounded(MAX_BYTES) {
                Ok(bytes) => bytes,
                Err(error) => return Read::NotUsed(Problem::Unreadable(error_line(&error))),
            };
            return decode(&bytes, raw_mode_u32(facts.mode) & 0o777);
        }
        Read::NotUsed(Problem::Unsettled)
    }
}

// ---------------------------------------------------------------------------
// The writer (ADR-0065 Constraints 1–6)
// ---------------------------------------------------------------------------
//
// One read-modify-write under `allowances.lock`, replacing `allowances.json`
// atomically at 0600. The writer **refuses rather than heals**: every store state
// other than `Absent` or `Current` is reported and left byte-, inode- and
// mtime-identical. A repaired damaged file would silently change the project's
// authority, and ADR-0065 Constraint 4 argues why that can widen guest reach.

/// The trust decision's euid and the three checkpoints one write exposes to its
/// tests, in one value.
///
/// `on_contention` observes each refused lock attempt (the cross-project test's
/// gate), `under_lock` runs exactly once while the lock is held, and `after_open`
/// runs inside each read attempt (the reopen rule's seam). Bundling them keeps
/// the writer's signature about what it does, not about how it is observed.
pub(super) struct WriteProbe<C, U, A> {
    pub(super) euid: u32,
    pub(super) on_contention: C,
    pub(super) under_lock: U,
    pub(super) after_open: A,
}

fn no_op_contention(_: std::time::Duration) {}
fn no_op() {}

impl Default for WriteProbe<fn(std::time::Duration), fn(), fn()> {
    /// The production probe: this process's euid, no checkpoints.
    fn default() -> Self {
        Self {
            euid: current_euid(),
            on_contention: no_op_contention,
            under_lock: no_op,
            after_open: no_op,
        }
    }
}

/// What a writer decided to do with the records it read.
///
/// `Unchanged` is not an optimisation: R7 says a write that changes nothing must
/// leave the file's bytes, inode and mtime exactly as they were.
enum Decision<D> {
    Unchanged(D),
    Replace(D),
}

/// One directory-probe failure, classified as plan §6.1's table states it.
///
/// `ENOTDIR` is that table's "not a dir" row for **both** verbs
/// (`Untrusted(DirNotDirectory)`); every other failure is the host refusing the
/// probe (`Unreadable`). The two verbs shared no classifier before, which is how
/// they drifted on this one row.
fn classify_dir_error(error: &std::io::Error) -> WriteError {
    if error.kind() == ErrorKind::NotADirectory {
        WriteError::Untrusted(AuthorityRefusal::DirNotDirectory)
    } else {
        WriteError::Unreadable(error_line(error))
    }
}

/// What a `record` did. `AlreadyRecorded` is the idempotent answer: the same
/// project and destination were already stored, so nothing was written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RecordOutcome {
    Recorded { recorded_ms: i64 },
    AlreadyRecorded { recorded_ms: i64 },
}

impl RecordOutcome {
    pub(super) fn recorded_ms(self) -> i64 {
        match self {
            Self::Recorded { recorded_ms } | Self::AlreadyRecorded { recorded_ms } => recorded_ms,
        }
    }
}

/// What a `forget` did. `Unchanged` means the record was not there, so nothing
/// was written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ForgetOutcome {
    Removed,
    Unchanged,
}

/// Why a write did not happen. Every variant but `Full` leaves the file exactly
/// as it was; `Full` decides before touching it.
#[derive(Debug)]
pub(super) enum WriteError {
    /// `$HOME` unset or unusable: there is no store to write.
    NoHome(String),
    /// This command has no store at all (a view built without a filesystem).
    NoStore,
    /// A project path that is not valid UTF-8 cannot be a `path` preimage.
    NonUtf8ProjectPath,
    /// The directory, or the file, is not this user's to replace.
    Untrusted(AuthorityRefusal),
    /// The file is not a schema this build writes.
    Damaged(Damage),
    /// A later release's file: never replaced by this one.
    Newer { v: u32 },
    /// The file exists but its bytes could not be read.
    Unreadable(String),
    /// The path kept being replaced while it was read.
    Unsettled,
    /// Another writer held `allowances.lock` past `LOCK_WAIT`.
    LockBusy(String),
    /// `allowances.lock` could not be opened at all (`EACCES`, `ENOTDIR`, a
    /// directory at the name). Kept apart from [`Self::LockBusy`] because the
    /// remedy differs: waiting will not help, and the host's permissions or the
    /// path must change.
    LockUnopenable(String),
    /// The result would exceed `MAX_RECORDS` or `MAX_BYTES`.
    Full,
}

impl WriteError {
    /// One escaped line, for a terminal. The caller owns the framing.
    pub(super) fn line(&self) -> String {
        let text = match self {
            Self::NoHome(error) => format!("no project allowance store: {error}"),
            Self::NoStore => "this command has no project allowance store".to_owned(),
            Self::NonUtf8ProjectPath => {
                "the project path is not valid UTF-8, so it cannot name a record".to_owned()
            }
            Self::Untrusted(refusal) => format!(
                "the project allowance store is not trusted: {}",
                crate::allowances::refusal_clause(refusal)
            ),
            Self::Damaged(damage) => format!(
                "the project allowance store could not be used ({}); this version does not repair it — move it aside to start over",
                damage.clause()
            ),
            Self::Newer { v } => format!(
                "the project allowance store was written by a newer agent-vm (version {v}) and is not replaced by this version"
            ),
            Self::Unreadable(error) => {
                format!("the project allowance store could not be read ({error})")
            }
            Self::Unsettled => {
                "the project allowance store kept changing while it was read; nothing was written"
                    .to_owned()
            }
            Self::LockBusy(error) => {
                format!("the project allowance store is busy ({error}); nothing was written")
            }
            Self::LockUnopenable(error) => format!(
                "the project allowance store's lock file {LOCK_FILE} could not be opened ({error}); nothing was written — waiting will not help, so check that directory's permissions and that {LOCK_FILE} is a regular file this user owns"
            ),
            Self::Full => format!(
                "the project allowance store is full (limit {MAX_RECORDS} records or {MAX_BYTES} bytes); nothing was written"
            ),
        };
        crate::one_line::text(&text).to_string()
    }
}

/// The store's handle for the writer: a resolved directory, or the reason `$HOME`
/// gave none.
///
/// The inner enum is private, so no caller outside `allowances/` can inspect a
/// [`Store`] or construct a path into the host configuration directory.
#[derive(Clone, Debug)]
pub(crate) struct StoreHandle(StoreHandleInner);

#[derive(Clone, Debug)]
enum StoreHandleInner {
    Ready(Store),
    /// A command that never had a store: no path was ever resolved.
    NoStore,
    HomeUnset,
    InvalidHome(String),
}

impl StoreHandle {
    /// Resolve `$HOME/.config/agent-vm` **without reading** `allowances.json`: a
    /// launch needs the handle before `for_launch` reads the file (ADR-0064 AC9).
    pub(super) fn host() -> Self {
        match Store::host() {
            Ok(Some(store)) => Self(StoreHandleInner::Ready(store)),
            Ok(None) => Self(StoreHandleInner::HomeUnset),
            Err(error) => Self(StoreHandleInner::InvalidHome(error_line(&error))),
        }
    }

    /// A store at a temporary directory: every test's seam, so no test can reach
    /// the real `~/.config/agent-vm`.
    #[cfg(test)]
    pub(crate) fn at_for_tests(dir: &Path) -> Self {
        Self(StoreHandleInner::Ready(Store::at(dir)))
    }

    /// A handle for an already-resolved store: used by the read path, which has
    /// the store in hand, so a view and its writer cannot disagree about where
    /// the file is.
    pub(super) fn of(store: &Store) -> Self {
        Self(StoreHandleInner::Ready(store.clone()))
    }

    /// A view with no store at all: no `$HOME`, no directory, nothing to write.
    ///
    /// Distinct from `HomeUnset` on purpose: a view built without a filesystem is
    /// not a host without a `$HOME`, and telling the user `$HOME` is unset when
    /// this command simply has no store was a lie the variant used to tell
    /// (C-m8).
    pub(super) fn without_a_store() -> Self {
        Self(StoreHandleInner::NoStore)
    }

    /// [`Store::record_path`] for a project path the caller has not validated: the
    /// UTF-8 gate lives in the writer, so a handle cannot be used without it.
    pub(super) fn record_path(
        &self,
        project: &str,
        path: &Path,
        destination: &crate::egress_policy::Allowance,
        recorded_ms: i64,
    ) -> Result<RecordOutcome, WriteError> {
        match &self.0 {
            StoreHandleInner::Ready(store) => {
                store.record_path(project, path, destination, recorded_ms)
            }
            StoreHandleInner::NoStore => Err(WriteError::NoStore),
            StoreHandleInner::HomeUnset => Err(WriteError::NoHome("$HOME is not set".into())),
            StoreHandleInner::InvalidHome(error) => Err(WriteError::NoHome(error.clone())),
        }
    }

    pub(super) fn forget(
        &self,
        project: &str,
        destination: &crate::egress_policy::Allowance,
    ) -> Result<ForgetOutcome, WriteError> {
        match &self.0 {
            StoreHandleInner::Ready(store) => store.forget(project, destination),
            StoreHandleInner::NoStore => Err(WriteError::NoStore),
            StoreHandleInner::HomeUnset => Err(WriteError::NoHome("$HOME is not set".into())),
            StoreHandleInner::InvalidHome(error) => Err(WriteError::NoHome(error.clone())),
        }
    }
}

impl Store {
    /// The lock path beside the record file.
    pub(super) fn lock_path(&self) -> PathBuf {
        self.dir.join(LOCK_FILE)
    }

    /// Store one (project, destination) record, or report that it is already
    /// there. Idempotent by bytes, inode and mtime.
    pub(super) fn record(
        &self,
        project: &str,
        path: &str,
        destination: &crate::egress_policy::Allowance,
        recorded_ms: i64,
    ) -> Result<RecordOutcome, WriteError> {
        self.record_with(
            project,
            path,
            destination,
            recorded_ms,
            WriteProbe::default(),
        )
    }

    /// Record one destination for a project **path**, refusing a path that cannot
    /// be the record's `path` column before anything is created or locked (R8).
    ///
    /// Both write paths in the tree go through this, not through
    /// [`Self::record`]: the gate belongs to the writer's entry point, so no
    /// caller can be missing it and no test can pass while it is missing.
    pub(super) fn record_path(
        &self,
        project: &str,
        path: &Path,
        destination: &crate::egress_policy::Allowance,
        recorded_ms: i64,
    ) -> Result<RecordOutcome, WriteError> {
        self.record(project, utf8_project_path(path)?, destination, recorded_ms)
    }

    /// Delete one (project, destination) record, or report it was absent.
    pub(super) fn forget(
        &self,
        project: &str,
        destination: &crate::egress_policy::Allowance,
    ) -> Result<ForgetOutcome, WriteError> {
        self.forget_with(project, destination, WriteProbe::default())
    }

    /// [`Self::record`] with the trust decision's euid and three checkpoints
    /// injected: `on_contention` observes each refused lock attempt, `under_lock`
    /// runs exactly once while the lock is held (the cross-project test's gate),
    /// and `after_open` runs inside each read attempt (the reopen rule's seam).
    fn record_with(
        &self,
        project: &str,
        path: &str,
        destination: &crate::egress_policy::Allowance,
        recorded_ms: i64,
        probe: WriteProbe<impl FnMut(std::time::Duration), impl FnOnce(), impl FnMut()>,
    ) -> Result<RecordOutcome, WriteError> {
        let canonical = destination.to_string();
        // The write's own directory may be created, but only as 0700: the store
        // is authority, so its container never admits another writer.
        self.ensure_directory()?;
        self.with_records_locked(probe, |records| {
            if let Some(existing) = records
                .iter()
                .find(|record| matches_record(record, project, destination, &canonical))
            {
                return Decision::Unchanged(RecordOutcome::AlreadyRecorded {
                    recorded_ms: existing.recorded_ms,
                });
            }
            records.push(StoredRecord {
                project: project.to_owned(),
                path: path.to_owned(),
                destination: canonical.clone(),
                recorded_ms,
            });
            Decision::Replace(RecordOutcome::Recorded { recorded_ms })
        })
    }

    /// [`Self::forget`] with the same three seams as [`Self::record_with`].
    fn forget_with(
        &self,
        project: &str,
        destination: &crate::egress_policy::Allowance,
        probe: WriteProbe<impl FnMut(std::time::Duration), impl FnOnce(), impl FnMut()>,
    ) -> Result<ForgetOutcome, WriteError> {
        let canonical = destination.to_string();
        // A forget creates nothing: with no directory there is no store, and so
        // no record to delete. `ENOTDIR` is not that case — the path *does* carry
        // a store this writer may not speak for — so it is the directory refusal
        // the error table names, for both verbs alike.
        match std::fs::metadata(&self.dir) {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Ok(ForgetOutcome::Unchanged);
            }
            Err(error) => return Err(classify_dir_error(&error)),
        }
        self.with_records_locked(probe, |records| {
            let before = records.len();
            records.retain(|record| !matches_record(record, project, destination, &canonical));
            if records.len() == before {
                Decision::Unchanged(ForgetOutcome::Unchanged)
            } else {
                Decision::Replace(ForgetOutcome::Removed)
            }
        })
    }

    /// One writer's whole sequence, and the only copy of it.
    ///
    /// The order is the security property (ADR-0065 Constraint 1): verify the
    /// directory, lock, verify again under the lock, read the store through the
    /// reader's own state machine, let the caller decide, and only then replace the
    /// file atomically. A second copy of that order is where `record` and `forget`
    /// already drifted on how a non-directory path is classified.
    fn with_records_locked<D, C, U, A>(
        &self,
        probe: WriteProbe<C, U, A>,
        decide: impl FnOnce(&mut Vec<StoredRecord>) -> Decision<D>,
    ) -> Result<D, WriteError>
    where
        C: FnMut(std::time::Duration),
        U: FnOnce(),
        A: FnMut(),
    {
        let WriteProbe {
            euid,
            mut on_contention,
            under_lock,
            mut after_open,
        } = probe;
        self.verify_directory(euid)?;
        let lock = self.lock(&mut on_contention)?;
        under_lock();
        // Under the lock, because the directory could have been replaced while we
        // waited: the check that matters is the one on the inode we now hold.
        self.verify_directory(euid)?;
        let mut records = match self.read_with(euid, &mut after_open) {
            Read::Absent => Vec::new(),
            Read::Current { records, .. } => records,
            Read::Newer { v, .. } => return Err(WriteError::Newer { v }),
            Read::NotUsed(problem) => return Err(problem.into_write_error()),
        };
        match decide(&mut records) {
            Decision::Unchanged(outcome) => {
                drop(lock);
                Ok(outcome)
            }
            Decision::Replace(outcome) => {
                let bytes = encode(&records)?;
                atomic_write(&self.file(), &bytes, 0o600)
                    .map_err(|error| WriteError::Unreadable(error_line(&error)))?;
                drop(lock);
                Ok(outcome)
            }
        }
    }

    /// Create the store's own directory at 0700 if it is absent.
    ///
    /// A *write* may create its container; a read never does. A path whose parent
    /// is not a directory is the directory refusal, not a store problem: the writer
    /// may not speak for a path it cannot even stat.
    fn ensure_directory(&self) -> Result<(), WriteError> {
        match std::fs::metadata(&self.dir) {
            Ok(_) => Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                use std::os::unix::fs::DirBuilderExt as _;
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(&self.dir)
                    .map_err(|error| classify_dir_error(&error))
            }
            Err(error) => Err(classify_dir_error(&error)),
        }
    }

    /// The directory half of ADR-0065's trust decision, through the proved kernel.
    fn verify_directory(&self, euid: u32) -> Result<(), WriteError> {
        let metadata = std::fs::metadata(&self.dir).map_err(|error| classify_dir_error(&error))?;
        match authority_dir_refusal(
            DirFacts {
                is_dir: metadata.is_dir(),
                uid: metadata.uid(),
                mode: metadata.mode(),
            },
            euid,
        ) {
            Some(refusal) => Err(WriteError::Untrusted(refusal)),
            None => Ok(()),
        }
    }

    /// Open and exclusively lock `allowances.lock`, waiting at most `LOCK_WAIT`.
    /// The returned descriptor holds the lock until it is dropped; the file is
    /// never unlinked, so its inode stays stable for the next writer.
    fn lock(
        &self,
        mut on_contention: impl FnMut(std::time::Duration),
    ) -> Result<std::fs::File, WriteError> {
        // Opening is not contending: a permission failure, a path that is not a
        // directory, or a directory at the lock's name all mean no other writer
        // will stop holding it, so the error says what to fix instead of
        // suggesting a retry that cannot work.
        let lock = open_lock_file(&self.lock_path())
            .map_err(|error| WriteError::LockUnopenable(error_line(&error)))?;
        match flock_exclusive_within(&lock, LOCK_WAIT, &mut on_contention)
            .map_err(|error| WriteError::LockBusy(error_line(&error)))?
        {
            FlockWait::Acquired => Ok(lock),
            FlockWait::TimedOut => Err(WriteError::LockBusy(format!(
                "timed out after {}s waiting for {LOCK_FILE}",
                LOCK_WAIT.as_secs()
            ))),
        }
    }
}

impl Problem {
    /// The writer's classification of a store it may not replace.
    fn into_write_error(self) -> WriteError {
        match self {
            Self::Untrusted(refusal) => WriteError::Untrusted(refusal),
            Self::Damaged(damage) => WriteError::Damaged(damage),
            Self::Unreadable(error) => WriteError::Unreadable(error),
            Self::Unsettled => WriteError::Unsettled,
        }
    }
}

/// A project path as the record's `path` column spells it, or the writer's
/// refusal.
///
/// A record's identity is the SHA-256 of the path's bytes, but the `path`
/// column is JSON text, so a path that is not valid UTF-8 cannot be written
/// (ADR-0065 Constraint 7, R8). The check is here, before a lock is opened, so
/// the refusal creates nothing.
pub(super) fn utf8_project_path(path: &Path) -> Result<&str, WriteError> {
    path.to_str().ok_or(WriteError::NonUtf8ProjectPath)
}

/// Whether one stored record already names this project and destination. The
/// destination is compared by parsed value as well as by text, so a record
/// stored under a non-canonical-but-equivalent spelling is not duplicated.
fn matches_record(
    record: &StoredRecord,
    project: &str,
    destination: &crate::egress_policy::Allowance,
    canonical: &str,
) -> bool {
    record.project == project
        && (record.destination == canonical
            || crate::egress_policy::Allowance::parse(&record.destination).as_ref()
                == Ok(destination))
}

/// Encode the whole file, then enforce the bounds **before** anything is
/// replaced. `Full` therefore leaves the existing file untouched.
fn encode(records: &[StoredRecord]) -> Result<Vec<u8>, WriteError> {
    if records.len() > MAX_RECORDS {
        return Err(WriteError::Full);
    }
    let lines: Vec<RecordLine> = records
        .iter()
        .map(|record| RecordLine {
            project: record.project.clone(),
            path: record.path.clone(),
            destination: record.destination.clone(),
            recorded_ms: record.recorded_ms,
        })
        .collect();
    let bytes = serde_json::to_vec(&AllowanceFile {
        v: VERSION,
        records: lines,
    })
    .map_err(|error| WriteError::Unreadable(error_line(&error)))?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(WriteError::Full);
    }
    Ok(bytes)
}

/// The trust adapter: the descriptor's facts, the directory's metadata and the
/// euid in, the proved kernel's verdict out.
///
/// Separate from [`Store::read_with`] so a test can hand it a foreign file over
/// a trusted directory and vice versa, which is the only way to show the two
/// ownership checks are decided independently (ADR-0065 C10a).
fn trust(file: &HostFileFacts, dir: &Metadata, euid: u32) -> Option<AuthorityRefusal> {
    let reached = Reached::Direct(FileFacts {
        uid: file.uid,
        mode: raw_mode_u32(file.mode),
        nlink: file.nlink,
    });
    let dir = DirFacts {
        is_dir: dir.is_dir(),
        uid: dir.uid(),
        mode: dir.mode(),
    };
    authority_refusal(reached, dir, euid)
}

/// Classify decoded-capable bytes. The version is decided *before* the strict
/// decode, so a newer file is `Newer` and never `Damaged` (ADR-0065 C6/C7).
fn decode(bytes: &[u8], mode: u32) -> Read {
    let version: Version = match serde_json::from_slice(bytes) {
        Ok(version) => version,
        Err(_) => return Read::NotUsed(Problem::Damaged(Damage::Undecodable)),
    };
    if version.v > VERSION {
        return Read::Newer {
            v: version.v,
            records: lenient_records(bytes),
        };
    }
    if version.v < VERSION {
        return Read::NotUsed(Problem::Damaged(Damage::OlderVersion(version.v)));
    }
    let file: AllowanceFile = match serde_json::from_slice(bytes) {
        Ok(file) => file,
        Err(_) => return Read::NotUsed(Problem::Damaged(Damage::Undecodable)),
    };
    // The probe above classified `v`; this second copy of it must agree, or the
    // two halves of the file disagree about the version they are reading.
    if file.v != VERSION {
        return Read::NotUsed(Problem::Damaged(Damage::Undecodable));
    }
    if file.records.len() > MAX_RECORDS {
        return Read::NotUsed(Problem::Damaged(Damage::Invalid("more than 4096 records")));
    }
    let mut records = Vec::with_capacity(file.records.len());
    for line in file.records {
        match check_record(line) {
            Ok(record) => records.push(record),
            Err(reason) => return Read::NotUsed(Problem::Damaged(Damage::Invalid(reason))),
        }
    }
    if !unique(&records) {
        return Read::NotUsed(Problem::Damaged(Damage::Invalid(
            "two records name the same project and destination",
        )));
    }
    Read::Current { records, mode }
}

/// The per-record schema checks, in one place so a newer file's best-effort
/// decode cannot accept a record the strict decode would refuse.
fn check_record(line: RecordLine) -> Result<StoredRecord, &'static str> {
    let path = Path::new(&line.path);
    if !path.is_absolute() {
        return Err("a record's path is not absolute");
    }
    // One identity (ADR-0065 P2): `path` is the digest's preimage, so a record
    // whose columns disagree is damaged rather than ambiguous. The comparison
    // also establishes that `project` is 64 lowercase hex.
    if line.project != crate::project::digest_hex_of(path) {
        return Err("a record's project is not the SHA-256 of its path");
    }
    if line.destination.is_empty() {
        return Err("a record's destination is empty");
    }
    if line.destination.len() > MAX_DESTINATION_BYTES {
        return Err("a record's destination is too long");
    }
    if line.destination.chars().any(char::is_control) {
        return Err("a record's destination contains a control character");
    }
    if line.recorded_ms < 0 {
        return Err("a record's recorded_ms is negative");
    }
    Ok(StoredRecord {
        project: line.project,
        path: line.path,
        destination: line.destination,
        recorded_ms: line.recorded_ms,
    })
}

fn unique(records: &[StoredRecord]) -> bool {
    let mut seen = std::collections::HashSet::with_capacity(records.len());
    records
        .iter()
        .all(|record| seen.insert((record.project.as_str(), record.destination.as_str())))
}

/// A newer file's records, as far as this build can read them. Never applied:
/// `doctor` counts them and nothing else looks.
fn lenient_records(bytes: &[u8]) -> Vec<StoredRecord> {
    #[derive(Deserialize)]
    struct Lenient {
        #[serde(default)]
        project: String,
        #[serde(default)]
        path: String,
        #[serde(default)]
        destination: String,
        #[serde(default)]
        recorded_ms: i64,
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return Vec::new();
    };
    let Some(lines) = value.get("records").and_then(|records| records.as_array()) else {
        return Vec::new();
    };
    let mut records: Vec<StoredRecord> = Vec::new();
    for line in lines.iter().take(MAX_RECORDS) {
        let Ok(line) = serde_json::from_value::<Lenient>(line.clone()) else {
            continue;
        };
        let Ok(record) = check_record(RecordLine {
            project: line.project,
            path: line.path,
            destination: line.destination,
            recorded_ms: line.recorded_ms,
        }) else {
            continue;
        };
        if records
            .iter()
            .any(|seen| seen.project == record.project && seen.destination == record.destination)
        {
            continue;
        }
        records.push(record);
    }
    records
}

/// What a bounded prefix of an oversized file proves about its version.
#[derive(Debug, PartialEq, Eq)]
enum VersionProbe {
    /// A complete, valid JSON integer for the leading `"v"` key, in `u32`.
    Known(u32),
    /// The prefix proves the leading `"v"` value is *not* this schema's version:
    /// a non-integer token (`2.5`), a number that runs into an identifier
    /// (`2abc`), a leading zero (`02`), or digits that do not fit `u32`.
    Malformed,
    /// The prefix does not decide it: no leading `"v"`, or the key, the number
    /// or its terminating delimiter lies beyond the probe.
    Undecided,
}

/// The `v` field of a file too large to decode whole, read from a bounded
/// prefix.
///
/// # What the bound can and cannot prove
///
/// The schema puts `v` first (ADR-0065 P1), so the probe reads only the
/// document's leading key and its number. It accepts that number only when it
/// is a *whole, valid* JSON integer followed by the object's structure — the
/// delimiter after the digits and the `,` or `}` after them — because a digit
/// run alone is not a version: `"v":10` cut after the `1` would otherwise read
/// as version 1, and `"v":2.5` or `"v":02` would read as 2. A leading zero is
/// refused (JSON has no such number), as are digits that do not fit `u32`.
///
/// So [`VersionProbe::Known`] is a proof, and everything else is the absence of
/// one: a file whose version field is reordered, padded beyond
/// [`VERSION_PROBE_BYTES`], or cut inside the number is [`VersionProbe::Undecided`]
/// and is classified as damage. That is the conservative direction — damage
/// applies nothing — and the only honest message the reader has, because the
/// body was never read. What the bound costs is a message: an oversized file
/// whose version is this build's own, or that the bound cannot decide, says
/// "larger than N bytes" rather than "not a JSON document this build reads".
/// Both write nothing and both tell the user to move the file aside; the size is
/// the one claim the reader established.
fn leading_version(prefix: &[u8]) -> VersionProbe {
    /// Leading JSON whitespace: the only four bytes it can be.
    fn skip_space(mut bytes: &[u8]) -> &[u8] {
        while let [b' ' | b'\t' | b'\r' | b'\n', rest @ ..] = bytes {
            bytes = rest;
        }
        bytes
    }
    let Some(rest) = skip_space(prefix).strip_prefix(&b"{"[..]) else {
        return VersionProbe::Undecided;
    };
    let Some(rest) = skip_space(rest).strip_prefix(&b"\"v\""[..]) else {
        return VersionProbe::Undecided;
    };
    let Some(rest) = skip_space(rest).strip_prefix(&b":"[..]) else {
        return VersionProbe::Undecided;
    };
    let rest = skip_space(rest);
    let digits = rest.iter().take_while(|byte| byte.is_ascii_digit()).count();
    if digits == 0 {
        // Nothing after the colon inside the probe: it may still be cut.
        return if rest.is_empty() {
            VersionProbe::Undecided
        } else {
            VersionProbe::Malformed
        };
    }
    let after = &rest[digits..];
    match after.first() {
        // The prefix ended inside the digits: their value is unknown.
        None => return VersionProbe::Undecided,
        Some(b' ' | b'\t' | b'\r' | b'\n' | b',' | b'}') => {}
        // `.`, a letter, a non-ASCII byte: not an integer this schema reads.
        Some(_) => return VersionProbe::Malformed,
    }
    if digits > 1 && rest[0] == b'0' {
        return VersionProbe::Malformed;
    }
    // The object's next structural character must be where it belongs, or the
    // number is not the whole value the document would have (`{"v":2` alone).
    match skip_space(after).first() {
        Some(b',' | b'}') => {}
        // Cut before the delimiter: no proof either way.
        _ => return VersionProbe::Undecided,
    }
    // Every byte is an ASCII digit, so this parse cannot fail on encoding.
    match std::str::from_utf8(&rest[..digits])
        .ok()
        .and_then(|digits| digits.parse::<u32>().ok())
    {
        Some(v) => VersionProbe::Known(v),
        // Digits that do not fit `u32` are not this schema's version either.
        None => VersionProbe::Malformed,
    }
}

/// One line, escaped, for a `Problem::Unreadable`. The message is a measured
/// operation and its cause; `one_line` is the policy every measured path uses.
fn error_line(error: &dyn std::fmt::Display) -> String {
    // `{:#}` keeps the whole `anyhow` chain: `{error}` prints only the outermost
    // context, which turns "Permission denied" into "could not be read (opening
    // …)" and leaves the user nothing actionable.
    crate::one_line::text(&format!("{error:#}")).to_string()
}

#[cfg(test)]
mod tests;
