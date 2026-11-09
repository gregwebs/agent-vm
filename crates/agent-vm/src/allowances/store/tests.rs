//! The read path: every state ADR-0065 §4.4 names, and the two things a reader
//! must never do — write, or call a race damage.
//!
//! `Store::at(tempdir)` everywhere, so no test touches the real
//! `~/.config/agent-vm`. The "unchanged" assertions use [`AuthoritySnapshot`],
//! taken **before** the operation: comparing a fixture against itself would
//! assert nothing.

use std::{
    collections::BTreeMap,
    ffi::OsString,
    os::unix::{
        ffi::OsStrExt as _,
        fs::{FileTypeExt as _, PermissionsExt as _},
    },
    path::{Path, PathBuf},
};

use super::*;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// An authority directory at mode 0700 holding nothing yet: the shape
/// `$HOME/.config/agent-vm` has on a healthy host.
fn authority_dir(root: &Path) -> PathBuf {
    let dir = root.join("agent-vm");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn store_at(dir: &Path) -> Store {
    Store::at(dir)
}

/// The digest of the canonical path a record names.
fn digest(path: &str) -> String {
    crate::project::digest_hex_of(Path::new(path))
}

/// One valid record for `path`, with `destination` verbatim, as literal JSON.
fn record(path: &str, destination: &str) -> String {
    format!(
        r#"{{"project":"{}","path":"{}","destination":"{}","recorded_ms":1762680120000}}"#,
        digest(path),
        path,
        destination
    )
}

fn file_of(records: &[String]) -> String {
    format!(r#"{{"v":1,"records":[{}]}}"#, records.join(","))
}

fn write(dir: &Path, bytes: &str) -> PathBuf {
    let file = dir.join(FILE);
    std::fs::write(&file, bytes).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    file
}

fn destinations(read: &Read) -> Vec<String> {
    match read {
        Read::Current { records, .. } => records.iter().map(|r| r.destination.clone()).collect(),
        _ => panic!("not a current read"),
    }
}

// ---------------------------------------------------------------------------
// The snapshot (§8.3)
// ---------------------------------------------------------------------------

/// Everything a read must leave exactly as it was: for the directory itself and
/// for each entry, the name, type, inode, mode, size, mtime, bytes (regular
/// files) or target (symlinks, read without following).
///
/// A FIFO is recorded by type and inode only and is never opened, because
/// opening one is what a wrong reader would do and it would block the test.
#[derive(Debug, PartialEq, Eq)]
struct AuthoritySnapshot {
    dir: EntryFacts,
    entries: BTreeMap<OsString, EntryFacts>,
}

#[derive(Debug, PartialEq, Eq)]
struct EntryFacts {
    kind: &'static str,
    ino: u64,
    mode: u32,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
    bytes: Option<Result<Vec<u8>, std::io::ErrorKind>>,
    target: Option<PathBuf>,
}

impl AuthoritySnapshot {
    fn take(dir: &Path) -> Self {
        let metadata = std::fs::symlink_metadata(dir).expect("the directory exists");
        let entries = std::fs::read_dir(dir)
            .expect("readable")
            .map(|entry| {
                let entry = entry.unwrap();
                (entry.file_name(), facts(&entry.path()))
            })
            .collect();
        Self {
            dir: EntryFacts {
                bytes: None,
                target: None,
                ..facts_of(&metadata)
            },
            entries,
        }
    }
}

fn facts(path: &Path) -> EntryFacts {
    let metadata = std::fs::symlink_metadata(path).expect("lstat");
    let mut facts = facts_of(&metadata);
    if metadata.file_type().is_file() {
        facts.bytes = Some(std::fs::read(path).map_err(|error| error.kind()));
    }
    if metadata.file_type().is_symlink() {
        facts.target = Some(std::fs::read_link(path).unwrap());
    }
    facts
}

fn facts_of(metadata: &std::fs::Metadata) -> EntryFacts {
    let kind = metadata.file_type();
    EntryFacts {
        kind: if kind.is_dir() {
            "dir"
        } else if kind.is_file() {
            "file"
        } else if kind.is_symlink() {
            "symlink"
        } else if kind.is_fifo() {
            "fifo"
        } else if kind.is_socket() {
            "socket"
        } else {
            "other"
        },
        ino: metadata.ino(),
        mode: metadata.mode() & 0o7777,
        size: metadata.size(),
        mtime: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec(),
        bytes: None,
        target: None,
    }
}

// ---------------------------------------------------------------------------
// C1–C8: what a file means
// ---------------------------------------------------------------------------

#[test]
fn current_file_yields_its_records() {
    let root = tempfile::tempdir().unwrap();
    let dir = authority_dir(root.path());
    write(
        &dir,
        &file_of(&[
            record("/tmp/a", "tcp://[203.0.113.10/32]:443"),
            record("/tmp/b", "api.example.com"),
        ]),
    );
    let read = store_at(&dir).read();
    let Read::Current { records, mode } = &read else {
        panic!("a healthy file is current");
    };
    assert_eq!(*mode, 0o600);
    assert_eq!(records.len(), 2);
    let expected: Vec<(String, String, String, i64)> = vec![
        (
            digest("/tmp/a"),
            "/tmp/a".to_owned(),
            "tcp://[203.0.113.10/32]:443".to_owned(),
            1_762_680_120_000,
        ),
        (
            digest("/tmp/b"),
            "/tmp/b".to_owned(),
            "api.example.com".to_owned(),
            1_762_680_120_000,
        ),
    ];
    let actual: Vec<_> = records
        .iter()
        .map(|r| {
            (
                r.project.clone(),
                r.path.clone(),
                r.destination.clone(),
                r.recorded_ms,
            )
        })
        .collect();
    assert_eq!(actual, expected);
}

/// Every strict-schema refusal, each asserted as *the* expected variant: a
/// reader that answered `Undecodable` for all of them would still pass a
/// test that only checked "not current".
#[test]
fn strict_schema_matrix() {
    let root = tempfile::tempdir().unwrap();
    let dir = authority_dir(root.path());
    let oversized_records: Vec<String> = (0..=MAX_RECORDS)
        .map(|n| record(&format!("/tmp/r{n}"), "10.0.0.5"))
        .collect();
    let cases: Vec<(&str, String, Read)> = vec![
        (
            "empty",
            String::new(),
            Read::NotUsed(Problem::Damaged(Damage::Undecodable)),
        ),
        (
            "truncated",
            "{".to_owned(),
            Read::NotUsed(Problem::Damaged(Damage::Undecodable)),
        ),
        (
            "older version",
            r#"{"v":0,"records":[]}"#.to_owned(),
            Read::NotUsed(Problem::Damaged(Damage::OlderVersion(0))),
        ),
        (
            "unknown file field",
            r#"{"v":1,"records":[],"extra":1}"#.to_owned(),
            Read::NotUsed(Problem::Damaged(Damage::Undecodable)),
        ),
        (
            "unknown record field",
            r#"{"v":1,"records":[{"project":"a","path":"/tmp/a","destination":"x","recorded_ms":0,"extra":1}]}"#
                .to_owned(),
            Read::NotUsed(Problem::Damaged(Damage::Undecodable)),
        ),
        (
            "missing field",
            r#"{"v":1,"records":[{"project":"a","path":"/tmp/a","recorded_ms":0}]}"#.to_owned(),
            Read::NotUsed(Problem::Damaged(Damage::Undecodable)),
        ),
        (
            "wrong digest",
            format!(
                r#"{{"v":1,"records":[{{"project":"{}","path":"/tmp/a","destination":"x","recorded_ms":0}}]}}"#,
                "0".repeat(64)
            ),
            Read::NotUsed(Problem::Damaged(Damage::Invalid(
                "a record's project is not the SHA-256 of its path",
            ))),
        ),
        (
            "uppercase digest",
            format!(
                r#"{{"v":1,"records":[{{"project":"{}","path":"/tmp/a","destination":"x","recorded_ms":0}}]}}"#,
                digest("/tmp/a").to_uppercase()
            ),
            Read::NotUsed(Problem::Damaged(Damage::Invalid(
                "a record's project is not the SHA-256 of its path",
            ))),
        ),
        (
            "relative path",
            r#"{"v":1,"records":[{"project":"a","path":"tmp/a","destination":"x","recorded_ms":0}]}"#
                .to_owned(),
            Read::NotUsed(Problem::Damaged(Damage::Invalid(
                "a record's path is not absolute",
            ))),
        ),
        (
            "duplicate key",
            file_of(&[record("/tmp/a", "10.0.0.5"), record("/tmp/a", "10.0.0.5")]),
            Read::NotUsed(Problem::Damaged(Damage::Invalid(
                "two records name the same project and destination",
            ))),
        ),
        (
            "control character",
            // A JSON escape, so this decodes and the control-character check is
            // the gate under test rather than the JSON parser.
            file_of(&[record("/tmp/a", r"10.0.0.5\u001b[31m")]),
            Read::NotUsed(Problem::Damaged(Damage::Invalid(
                "a record's destination contains a control character",
            ))),
        ),
        (
            "empty destination",
            file_of(&[record("/tmp/a", "")]),
            Read::NotUsed(Problem::Damaged(Damage::Invalid(
                "a record's destination is empty",
            ))),
        ),
        (
            "negative timestamp",
            format!(
                r#"{{"v":1,"records":[{{"project":"{}","path":"/tmp/a","destination":"x","recorded_ms":-1}}]}}"#,
                digest("/tmp/a")
            ),
            Read::NotUsed(Problem::Damaged(Damage::Invalid(
                "a record's recorded_ms is negative",
            ))),
        ),
        (
            "too many records",
            file_of(&oversized_records),
            Read::NotUsed(Problem::Damaged(Damage::Invalid("more than 4096 records"))),
        ),
    ];
    for (row, bytes, expected) in cases {
        let file = dir.join(FILE);
        std::fs::write(&file, bytes.as_bytes()).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let before = AuthoritySnapshot::take(&dir);
        let read = store_at(&dir).read();
        assert_eq!(
            std::mem::discriminant(&read),
            std::mem::discriminant(&expected),
            "{row}: wrong state"
        );
        match (&read, &expected) {
            (
                Read::NotUsed(Problem::Damaged(Damage::Invalid(actual))),
                Read::NotUsed(Problem::Damaged(Damage::Invalid(expected))),
            ) => assert_eq!(actual, expected, "{row}"),
            (
                Read::NotUsed(Problem::Damaged(Damage::OlderVersion(actual))),
                Read::NotUsed(Problem::Damaged(Damage::OlderVersion(expected))),
            ) => assert_eq!(actual, expected, "{row}"),
            _ => assert!(
                matches!(
                    (&read, &expected),
                    (
                        Read::NotUsed(Problem::Damaged(Damage::Undecodable)),
                        Read::NotUsed(Problem::Damaged(Damage::Undecodable))
                    )
                ),
                "{row}: {}",
                damage_name(&read)
            ),
        }
        assert_eq!(AuthoritySnapshot::take(&dir), before, "{row}: a read wrote");
    }
}

fn damage_name(read: &Read) -> &'static str {
    match read {
        Read::Absent => "absent",
        Read::Current { .. } => "current",
        Read::Newer { .. } => "newer",
        Read::NotUsed(Problem::Damaged(_)) => "damaged",
        Read::NotUsed(Problem::Untrusted(_)) => "untrusted",
        Read::NotUsed(Problem::Unreadable(_)) => "unreadable",
        Read::NotUsed(Problem::Unsettled) => "unsettled",
    }
}

/// Asking what a project allows must not bring the answer into existence.
#[test]
fn a_read_creates_nothing() {
    let root = tempfile::tempdir().unwrap();
    // No directory at all: `$HOME/.config/agent-vm` need not exist.
    let missing = root.path().join("agent-vm");
    assert!(matches!(store_at(&missing).read(), Read::Absent));
    assert!(!missing.exists(), "a read created the authority directory");
    // A directory with no file: still absent, and still nothing created.
    let dir = authority_dir(root.path());
    let before = AuthoritySnapshot::take(&dir);
    assert!(matches!(store_at(&dir).read(), Read::Absent));
    assert_eq!(AuthoritySnapshot::take(&dir), before);
    assert!(!dir.join("allowances.lock").exists());
}

/// Every fixture a read touches, compared against its own earlier bytes: there
/// is never a lock, a rename, a chmod or a truncation.
#[test]
fn a_read_mutates_nothing() {
    let root = tempfile::tempdir().unwrap();
    let dir = authority_dir(root.path());
    let mut fixtures: Vec<PathBuf> = Vec::new();
    for bytes in [
        file_of(&[record("/tmp/a", "10.0.0.5")]),
        String::new(),
        r#"{"v":0,"records":[]}"#.to_owned(),
        r#"{"v":2,"records":[],"extra":1}"#.to_owned(),
    ] {
        fixtures.push(write(&dir, &bytes));
        let before = AuthoritySnapshot::take(&dir);
        let _ = store_at(&dir).read();
        assert_eq!(AuthoritySnapshot::take(&dir), before, "{bytes:?}");
    }
    // A symlink and a directory at the name are read as their own states, and
    // neither is replaced by a "repaired" file.
    let target = root.path().join("elsewhere.json");
    std::fs::write(&target, file_of(&[record("/tmp/a", "10.0.0.5")])).unwrap();
    let link = dir.join(FILE);
    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let before = AuthoritySnapshot::take(&dir);
    assert!(matches!(
        store_at(&dir).read(),
        Read::NotUsed(Problem::Untrusted(AuthorityRefusal::ThroughSymlink))
    ));
    assert_eq!(AuthoritySnapshot::take(&dir), before);
    std::fs::remove_file(&link).unwrap();
    std::fs::create_dir(&link).unwrap();
    let before = AuthoritySnapshot::take(&dir);
    assert!(matches!(
        store_at(&dir).read(),
        Read::NotUsed(Problem::Damaged(Damage::NotAFile(_)))
    ));
    assert_eq!(AuthoritySnapshot::take(&dir), before);
}

/// The size bound is applied from `lstat`, before any decode: a 2 MiB file is
/// never parsed, so its contents cannot influence the outcome.
#[test]
fn oversized_is_damaged_before_decode() {
    let root = tempfile::tempdir().unwrap();
    let dir = authority_dir(root.path());
    let file = dir.join(FILE);
    // Contents that would decode cleanly if the bound were applied after the
    // read: the *body* must be what makes this row fail, not the size.
    let mut body = file_of(&[record("/tmp/a", "10.0.0.5")]);
    body.push_str(&" ".repeat(MAX_BYTES as usize + 1 - body.len()));
    assert!(body.len() as u64 > MAX_BYTES);
    std::fs::write(&file, body.as_bytes()).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let before = AuthoritySnapshot::take(&dir);
    assert!(matches!(
        store_at(&dir).read(),
        Read::NotUsed(Problem::Damaged(Damage::TooLarge))
    ));
    assert_eq!(AuthoritySnapshot::take(&dir), before);
}

#[test]
fn older_version_is_damaged() {
    let root = tempfile::tempdir().unwrap();
    let dir = authority_dir(root.path());
    write(&dir, r#"{"v":0,"records":[]}"#);
    assert!(matches!(
        store_at(&dir).read(),
        Read::NotUsed(Problem::Damaged(Damage::OlderVersion(0)))
    ));
}

/// A later release's file is `Newer`, never damage — and its records are read
/// as far as this build can, for `doctor`'s counts only.
#[test]
fn newer_version_is_newer_with_best_effort_records() {
    let root = tempfile::tempdir().unwrap();
    let dir = authority_dir(root.path());
    write(
        &dir,
        &format!(
            r#"{{"v":2,"records":[{},{{"project":"bad","path":"/tmp/z","destination":"x","recorded_ms":0}}],"added":"later"}}"#,
            record("/tmp/a", "10.0.0.5")
        ),
    );
    let read = store_at(&dir).read();
    let Read::Newer { v, records } = &read else {
        panic!("a later version is Newer, not {}", damage_name(&read));
    };
    assert_eq!(*v, 2);
    // The one well-formed record survives; the malformed one is dropped.
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].destination, "10.0.0.5");
}

// ---------------------------------------------------------------------------
// C9–C13: what a file can be
// ---------------------------------------------------------------------------

/// The kinds that must never be opened: a directory, a FIFO and a socket.
/// `lstat` decides all three, so this test finishes — a reader that opened the
/// FIFO would block until the harness killed it.
#[test]
fn not_a_file_matrix() {
    let root = tempfile::tempdir().unwrap();
    let dir = authority_dir(root.path());
    let file = dir.join(FILE);

    std::fs::create_dir(&file).unwrap();
    let before = AuthoritySnapshot::take(&dir);
    let read = store_at(&dir).read();
    assert!(matches!(
        read,
        Read::NotUsed(Problem::Damaged(Damage::NotAFile(_)))
    ));
    if let Read::NotUsed(Problem::Damaged(Damage::NotAFile(kind))) = &read {
        assert!(kind.is_dir());
        assert_eq!(Damage::NotAFile(*kind).clause(), "a directory");
    }
    assert_eq!(AuthoritySnapshot::take(&dir), before);
    std::fs::remove_dir(&file).unwrap();

    let fifo = std::ffi::CString::new(file.as_os_str().as_bytes()).unwrap();
    // SAFETY: `mkfifo` takes a NUL-terminated path and a mode; both are valid.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let before = AuthoritySnapshot::take(&dir);
    let read = store_at(&dir).read();
    assert!(matches!(
        read,
        Read::NotUsed(Problem::Damaged(Damage::NotAFile(_)))
    ));
    // The FIFO is still a FIFO, with the same inode: nothing replaced it.
    assert_eq!(AuthoritySnapshot::take(&dir), before);
    assert_eq!(before.entries[&OsString::from(FILE)].kind, "fifo");
    std::fs::remove_file(&file).unwrap();

    let listener = std::os::unix::net::UnixListener::bind(&file).unwrap();
    let before = AuthoritySnapshot::take(&dir);
    assert!(matches!(
        store_at(&dir).read(),
        Read::NotUsed(Problem::Damaged(Damage::NotAFile(_)))
    ));
    assert_eq!(AuthoritySnapshot::take(&dir), before);
    assert_eq!(before.entries[&OsString::from(FILE)].kind, "socket");
    drop(listener);
}

/// The kernel's verdict, twice over: as a table over injected facts, so each
/// ownership check is shown to decide on its own, and over real files, so the
/// adapter that produces those facts is covered too.
#[test]
fn trust_matrix() {
    use crate::config_authority::{
        AuthorityRefusal, DirFacts, FileFacts, Reached, authority_refusal,
    };
    // (a) Injected facts. The directory comes first (ADR-0040's precedence), so
    // a foreign directory hides a foreign file.
    let own = crate::host_paths::current_euid();
    let file = HostFileFacts {
        uid: own,
        mode: 0o600,
        size: 0,
        nlink: 1,
    };
    let trusted_dir = |uid| DirFacts {
        is_dir: true,
        uid,
        mode: 0o700,
    };
    let own_file = |uid: u32| {
        Reached::Direct(FileFacts {
            uid,
            mode: 0o600,
            nlink: 1,
        })
    };
    // A foreign file over a trusted directory is the file's fault.
    assert_eq!(
        authority_refusal(own_file(8), trusted_dir(7), 7),
        Some(AuthorityRefusal::FileOwner)
    );
    // A trusted file in a foreign directory is the directory's fault.
    assert_eq!(
        authority_refusal(own_file(7), trusted_dir(8), 7),
        Some(AuthorityRefusal::DirOwner)
    );
    // Both foreign: the directory decides, because it can replace the file.
    assert_eq!(
        authority_refusal(own_file(8), trusted_dir(8), 7),
        Some(AuthorityRefusal::DirOwner)
    );
    assert_eq!(authority_refusal(own_file(7), trusted_dir(7), 7), None);
    // The adapter's own mapping, over the same facts, is what `read_with` uses.
    let dir_metadata = |uid: u32, mode: u32| {
        // A real directory, chmod'ed, so `Metadata` carries the injected mode;
        // ownership cannot be faked without root, which row (b) reports.
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("d");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
        let metadata = std::fs::symlink_metadata(&dir).unwrap();
        let _ = uid;
        metadata
    };
    assert_eq!(trust(&file, &dir_metadata(own, 0o700), own), None);
    assert_eq!(
        trust(&file, &dir_metadata(own, 0o775), own),
        Some(AuthorityRefusal::DirWritable)
    );
    assert_eq!(
        trust(&file, &dir_metadata(own, 0o777), own),
        Some(AuthorityRefusal::DirWritable)
    );

    // (b) Real files. The mode predicate reads mode bits, so these rows hold
    // even as root.
    let root = tempfile::tempdir().unwrap();
    let dir = authority_dir(root.path());
    let file = write(&dir, &file_of(&[record("/tmp/a", "10.0.0.5")]));
    for (mode, expected) in [
        (0o600, None),
        (0o644, None),
        (0o400, None),
        (0o664, Some(AuthorityRefusal::FileWritable)),
        (0o646, Some(AuthorityRefusal::FileWritable)),
        (0o666, Some(AuthorityRefusal::FileWritable)),
    ] {
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
        let read = store_at(&dir).read();
        match expected {
            None => assert!(
                matches!(read, Read::Current { mode: m, .. } if m == mode),
                "{mode:o}"
            ),
            Some(refusal) => assert!(
                matches!(&read, Read::NotUsed(Problem::Untrusted(actual)) if *actual == refusal),
                "{mode:o}: {}",
                damage_name(&read)
            ),
        }
    }
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();

    // A second name is a real topology: untrusted, not a race.
    let alias = root.path().join("alias.json");
    std::fs::hard_link(&file, &alias).unwrap();
    assert!(matches!(
        store_at(&dir).read(),
        Read::NotUsed(Problem::Untrusted(AuthorityRefusal::FileLinks(2)))
    ));
    std::fs::remove_file(&alias).unwrap();

    // A symlink at the name is untrusted, never damaged.
    let target = root.path().join("target.json");
    std::fs::rename(&file, &target).unwrap();
    std::os::unix::fs::symlink(&target, &file).unwrap();
    assert!(matches!(
        store_at(&dir).read(),
        Read::NotUsed(Problem::Untrusted(AuthorityRefusal::ThroughSymlink))
    ));
    std::fs::remove_file(&file).unwrap();
    std::fs::rename(&target, &file).unwrap();

    // The directory's own bits.
    for mode in [0o775, 0o777] {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(matches!(
            store_at(&dir).read(),
            Read::NotUsed(Problem::Untrusted(AuthorityRefusal::DirWritable))
        ));
    }
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(store_at(&dir).read(), Read::Current { .. }));
}

/// A file this user cannot read is a problem to report, not damage: nothing
/// about its contents was established. The only row that cannot run as root,
/// where every mode is readable.
#[test]
fn unreadable_is_not_damage() {
    if crate::host_paths::current_euid() == 0 {
        eprintln!("unreadable fixture NOT RUN: running as root, so mode 000 is readable");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let dir = authority_dir(root.path());
    let file = write(&dir, &file_of(&[record("/tmp/a", "10.0.0.5")]));
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).unwrap();
    let before = AuthoritySnapshot::take(&dir);
    let read = store_at(&dir).read();
    assert!(
        matches!(read, Read::NotUsed(Problem::Unreadable(_))),
        "{}",
        damage_name(&read)
    );
    assert!(!matches!(
        read,
        Read::NotUsed(Problem::Damaged(_)) | Read::NotUsed(Problem::Untrusted(_))
    ));
    assert_eq!(AuthoritySnapshot::take(&dir), before);
}

// ---------------------------------------------------------------------------
// C11–C12: the reader's half of the link-count race
// ---------------------------------------------------------------------------

/// A replacement between `open` and `fstat` is a writer doing its job: the
/// reader reopens and uses the new file, silently.
#[test]
fn replaced_once_between_open_and_fstat_reads_the_new_file() {
    let root = tempfile::tempdir().unwrap();
    let dir = authority_dir(root.path());
    write(&dir, &file_of(&[record("/tmp/a", "10.0.0.5")]));
    let next = dir.join("next.json");
    std::fs::write(&next, file_of(&[record("/tmp/b", "api.example.com")])).unwrap();
    std::fs::set_permissions(&next, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut attempts = 0;
    let read = store_at(&dir).read_with(crate::host_paths::current_euid(), || {
        attempts += 1;
        if attempts == 1 {
            std::fs::rename(&next, dir.join(FILE)).unwrap();
        }
    });
    assert_eq!(attempts, 2, "one reopen, not a loop");
    assert_eq!(destinations(&read), ["api.example.com"]);
}

/// Sustained churn is `Unsettled`: neither damage nor distrust, and bounded.
#[test]
fn replaced_on_every_attempt_is_unsettled() {
    let root = tempfile::tempdir().unwrap();
    let dir = authority_dir(root.path());
    write(&dir, &file_of(&[record("/tmp/a", "10.0.0.5")]));
    for n in 0..READ_ATTEMPTS {
        let next = dir.join(format!("next-{n}.json"));
        std::fs::write(&next, file_of(&[record(&format!("/tmp/r{n}"), "10.0.0.5")])).unwrap();
        std::fs::set_permissions(&next, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut attempts = 0;
    let read = store_at(&dir).read_with(crate::host_paths::current_euid(), || {
        let next = dir.join(format!("next-{attempts}.json"));
        attempts += 1;
        std::fs::rename(&next, dir.join(FILE)).unwrap();
    });
    assert_eq!(attempts, READ_ATTEMPTS, "exactly three opens in all");
    let Read::NotUsed(Problem::Unsettled) = read else {
        panic!("sustained churn is Unsettled, not {}", damage_name(&read));
    };
}

// ---------------------------------------------------------------------------
// C14: `$HOME`
// ---------------------------------------------------------------------------

/// An unusable `$HOME` is one notice and no store; an unset one is nothing at
/// all, because no user config is read then (ADR-0038).
#[test]
fn invalid_home_is_one_notice() {
    let mut env = crate::test_env::guard();
    env.remove_var("HOME");
    assert!(
        matches!(Store::host(), Ok(None)),
        "an unset $HOME has no store"
    );
    env.set_var("HOME", "");
    let error = Store::host().err().expect("an empty $HOME is an error");
    assert_eq!(format!("{error:#}"), "$HOME is set but empty");
    let project = crate::image_pin::ProjectId::of(
        &crate::project::ProjectDir::from_path_for_tests(
            &tempfile::tempdir().unwrap().path().canonicalize().unwrap(),
        )
        .unwrap(),
    );
    let view = super::super::view(None, Some(error), &project);
    assert_eq!(
        view.notice(),
        Some("project allowances not read: $HOME is set but empty")
    );
    assert_eq!(view.allowances().len(), 0);
    assert!(view.file().is_none());
    // And unset means silent.
    let silent = super::super::view(None, None, &project);
    assert!(silent.notice().is_none());
    assert!(silent.file().is_none());
}
