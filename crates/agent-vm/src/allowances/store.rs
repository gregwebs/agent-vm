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

use serde::Deserialize;

use crate::config;
use crate::config_authority::{
    AuthorityRefusal, DirFacts, FileFacts, Reached, authority_refusal, raw_mode_u32,
};
use crate::host_paths::{HostFileFacts, current_euid, open_regular_no_follow_checkpointed};

/// The one name this module reads.
pub(crate) const FILE: &str = "allowances.json";
/// The schema version this build writes and reads (ADR-0065 P1).
const VERSION: u32 = 1;
/// A store bigger than this is not a record table anyone wrote by hand.
const MAX_BYTES: u64 = 1024 * 1024;
/// How much of the file the version probe reads from the start.
///
/// The schema puts `v` first (ADR-0065 P1), so this covers every file this or a
/// later release writes. It is a bound on *reading*, not on the file: a newer
/// file bigger than [`MAX_BYTES`] is still `Newer`, because a later release
/// writing a larger body must not be told to move its file aside as damaged.
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
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowanceFile {
    v: u32,
    records: Vec<RecordLine>,
}

/// One record line, strictly.
#[derive(Deserialize)]
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
    /// A later release's file: decoded as far as possible for `doctor`'s counts
    /// only, and never applied by anything.
    Newer {
        v: u32,
        records: Vec<StoredRecord>,
    },
    NotUsed(Problem),
}

/// Why a file that exists is not in force.
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
            // `Newer` (nothing applied, `doctor` counts it), never damage whose
            // remedy is "move it aside".
            if facts.size > MAX_BYTES {
                let probe = match opened.prefix(VERSION_PROBE_BYTES) {
                    Ok(probe) => probe,
                    Err(error) => return Read::NotUsed(Problem::Unreadable(error_line(&error))),
                };
                let Some(v) = leading_version(&probe).filter(|v| *v > VERSION) else {
                    return Read::NotUsed(Problem::Damaged(Damage::TooLarge));
                };
                // The records this build can still read, bounded: `doctor`'s
                // counts only; `from_read` never applies them.
                let records = opened
                    .prefix(usize::try_from(MAX_BYTES).unwrap_or(usize::MAX))
                    .map(|bytes| lenient_records(&bytes))
                    .unwrap_or_default();
                return Read::Newer { v, records };
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

/// The `v` field of a file too large to decode whole, read from a bounded
/// prefix.
///
/// The schema puts `v` first (ADR-0065 P1), so this reads only the document's
/// leading key and its number. Anything else — a reordered key, a prefix cut
/// before the value — answers `None`, which classifies an oversized file as
/// damage. That is the conservative direction: it applies nothing either way,
/// and `doctor` still reports the file.
fn leading_version(prefix: &[u8]) -> Option<u32> {
    let text = String::from_utf8_lossy(prefix);
    let rest = text.trim_start().strip_prefix('{')?;
    let rest = rest.trim_start().strip_prefix("\"v\"")?;
    let rest = rest.trim_start().strip_prefix(':')?;
    let rest = rest.trim_start();
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return None;
    }
    rest[..digits].parse().ok()
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
