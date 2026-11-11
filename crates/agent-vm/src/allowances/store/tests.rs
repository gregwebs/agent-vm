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

/// One file's facts, for the cases where a write attempt legitimately creates
/// `allowances.lock`: the store itself must still be byte-, inode- and
/// mtime-identical.
fn file_facts(path: &Path) -> EntryFacts {
    facts(path)
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

/// The size bound is applied after trust and the version probe, and before the
/// strict decode: a 2 MiB *current-version* file is never decoded, so its body
/// cannot influence the outcome.
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

/// MA7: trust is decided before size and version. A file this user does not
/// trust is described as something another account or guest may have written,
/// not as damage to move aside — for a file that is *also* oversized or newer.
#[test]
fn untrusted_beats_damaged_and_newer() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = tempfile::tempdir().unwrap();
    let dir = authority_dir(root.path());
    let oversized = |body: &str| {
        let mut body = body.to_owned();
        body.push_str(&" ".repeat(MAX_BYTES as usize + 1 - body.len()));
        body
    };
    for (row, body) in [
        (
            "oversized",
            oversized(&file_of(&[record("/tmp/a", "10.0.0.5")])),
        ),
        (
            "oversized newer",
            oversized(&format!(
                r#"{{"v":2,"records":[{}]}}"#,
                record("/tmp/a", "10.0.0.5")
            )),
        ),
    ] {
        let file = write(&dir, &body);
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
        let read = store_at(&dir).read();
        assert!(
            matches!(
                &read,
                Read::NotUsed(Problem::Untrusted(AuthorityRefusal::FileWritable))
            ),
            "{row}: {}",
            damage_name(&read)
        );
    }
}

/// MA7: a newer file is classified by what it says it is, so a later release's
/// larger body is not called damage and not sent to "move it aside".
///
/// An oversized file carries **no records**: its body is not read, so a count
/// would be a partial count presented as a count. Both shapes of oversized file
/// prove it — one too large because of its body, one padded after the document —
/// so nothing here depends on which bytes happen to survive the bound.
#[test]
fn oversized_newer_file_is_newer_and_carries_no_records() {
    let root = tempfile::tempdir().unwrap();
    let dir = authority_dir(root.path());
    // A record whose `path` exceeds the bound: the JSON body itself is too big.
    let huge_path = format!("/tmp/{}", "a".repeat(MAX_BYTES as usize));
    let by_body = format!(
        r#"{{"v":2,"records":[{{"project":"{}","path":"{huge_path}","destination":"10.0.0.5","recorded_ms":0}}]}}"#,
        digest("/tmp/a")
    );
    assert!(by_body.len() as u64 > MAX_BYTES);
    // And the same document padded after `}`: a body the prefix *could* parse,
    // which is exactly why the assertion cannot depend on padding.
    let padded = format!(r#"{{"v":2,"records":[{}]}}"#, record("/tmp/a", "10.0.0.5"));
    let padded = {
        let mut padded = padded;
        padded.push_str(&" ".repeat(MAX_BYTES as usize + 1 - padded.len()));
        padded
    };
    for (row, body) in [("body", by_body), ("padded", padded)] {
        write(&dir, &body);
        let before = AuthoritySnapshot::take(&dir);
        let read = store_at(&dir).read();
        let Read::Newer { v, records } = &read else {
            panic!(
                "{row}: an oversized newer file is Newer, not {}",
                damage_name(&read)
            );
        };
        assert_eq!(*v, 2, "{row}");
        assert!(
            records.is_empty(),
            "{row}: an oversized file's records are not counted, because its body is not read ({} found)",
            records.len()
        );
        assert_eq!(AuthoritySnapshot::take(&dir), before, "{row}: a read wrote");
    }
}

/// The bounded and unbounded paths disagree about nothing the *version* decides.
///
/// Every row is the same bytes at both sizes; a padded copy must land in the
/// same version class as the small one. The mutant this kills is the probe that
/// accepts any digit run: it reads `2.5`, `2abc` and `02` as version 2.
#[test]
fn the_version_probe_agrees_with_the_bounded_classification() {
    let root = tempfile::tempdir().unwrap();
    let dir = authority_dir(root.path());
    // A classification is what the version *decides*: the variant and, where it
    // carries one, the version. Size is the only thing allowed to differ.
    #[derive(Debug, PartialEq, Eq)]
    enum Verdict {
        Current,
        Newer(u32),
        Older(u32),
        Undecodable,
        TooLarge,
    }
    let verdict = |read: &Read| match read {
        Read::Current { .. } => Verdict::Current,
        Read::Newer { v, .. } => Verdict::Newer(*v),
        Read::NotUsed(Problem::Damaged(Damage::OlderVersion(v))) => Verdict::Older(*v),
        Read::NotUsed(Problem::Damaged(Damage::Undecodable)) => Verdict::Undecodable,
        Read::NotUsed(Problem::Damaged(Damage::TooLarge)) => Verdict::TooLarge,
        other => panic!("unexpected: {}", damage_name(other)),
    };
    for (body, small, padded) in [
        (r#"{"v":2}"#, Verdict::Newer(2), Verdict::Newer(2)),
        (r#"{"v":0}"#, Verdict::Older(0), Verdict::Older(0)),
        (
            r#"{"v":1,"records":[]}"#,
            Verdict::Current,
            Verdict::TooLarge,
        ),
        (r#"{"v":2.5}"#, Verdict::Undecodable, Verdict::Undecodable),
        (r#"{"v":2abc}"#, Verdict::Undecodable, Verdict::Undecodable),
        (r#"{"v":02}"#, Verdict::Undecodable, Verdict::Undecodable),
    ] {
        let row = body;
        write(&dir, body);
        assert_eq!(verdict(&store_at(&dir).read()), small, "{row}: small");
        let mut big = body.to_owned();
        big.push_str(&" ".repeat(MAX_BYTES as usize + 1 - big.len()));
        write(&dir, &big);
        assert_eq!(verdict(&store_at(&dir).read()), padded, "{row}: oversized");
    }
    // The one case the bound cannot decide, stated rather than hidden: an
    // unclosed `{"v":2` padded past the bound has a *valid* leading number and
    // no reader can tell it from `{"v":2,"records":…` without reading the body.
    // The bounded path says undecodable; the oversized one says too large. Both
    // apply nothing and both tell the user to move the file aside.
    write(&dir, r#"{"v":2"#);
    assert_eq!(
        verdict(&store_at(&dir).read()),
        Verdict::Undecodable,
        "unclosed, small"
    );
    let mut unclosed = r#"{"v":2"#.to_owned();
    unclosed.push_str(&" ".repeat(MAX_BYTES as usize + 1 - unclosed.len()));
    write(&dir, &unclosed);
    assert_eq!(
        verdict(&store_at(&dir).read()),
        Verdict::TooLarge,
        "unclosed, oversized: the bound cannot prove the document is a version"
    );
}

/// A version cut by the probe's own bound is not invented from the digits that
/// survived: `{"v":20000000000…}` whose fourth byte is the last one the probe
/// sees must not read as version 2.
#[test]
fn a_version_cut_at_the_probe_boundary_is_not_invented() {
    let root = tempfile::tempdir().unwrap();
    let dir = authority_dir(root.path());
    // Whitespace pushes the value to the boundary: `{"v":` occupies bytes
    // 4090..4095 and the prefix ends on the `0` of `20000000000`.
    let lead = " ".repeat(VERSION_PROBE_BYTES - 6);
    let body = format!("{lead}{{\"v\":20000000000}}");
    let mut body = body;
    body.push_str(&" ".repeat(MAX_BYTES as usize + 5 - body.len()));
    write(&dir, &body);
    let read = store_at(&dir).read();
    assert!(
        !matches!(read, Read::Newer { .. }),
        "a cut digit run is not a version: {}",
        damage_name(&read)
    );
    assert!(
        matches!(read, Read::NotUsed(Problem::Damaged(Damage::TooLarge))),
        "the bound is undecided, and the size is the certain fact: {}",
        damage_name(&read)
    );
}

/// The probe itself, row for row: a valid leading integer is `Known`, a value
/// the schema could not hold is `Malformed`, and anything the prefix cannot
/// prove is `Undecided` — never a guess from partial digits.
#[test]
fn leading_version_is_a_proof_or_nothing() {
    let cases: Vec<(&[u8], VersionProbe)> = vec![
        (br#"{"v":2,"records":[]}"#, VersionProbe::Known(2)),
        (br#"{"v":2}"#, VersionProbe::Known(2)),
        (br#"{"v":2 }"#, VersionProbe::Known(2)),
        (br#"{"v":0}"#, VersionProbe::Known(0)),
        (br#"  {  "v"  :  10  ,  "#, VersionProbe::Known(10)),
        // Malformed: not this schema's version.
        (br#"{"v":2.5}"#, VersionProbe::Malformed),
        (br#"{"v":2abc}"#, VersionProbe::Malformed),
        (br#"{"v":02}"#, VersionProbe::Malformed),
        (br#"{"v":-1}"#, VersionProbe::Malformed),
        (br#"{"v":20000000000}"#, VersionProbe::Malformed),
        // Undecided: the prefix proves nothing.
        (br#"{"v":2"#, VersionProbe::Undecided),
        (br#"{"v":"#, VersionProbe::Undecided),
        (br#"{"v"#, VersionProbe::Undecided),
        (br#"{"records":[],"v":2}"#, VersionProbe::Undecided),
        (br#"["v"]"#, VersionProbe::Undecided),
        // A byte where a delimiter must be: not JSON at all, so the bounded
        // path would call the same file undecodable.
        (b"{\"v\":2\xff", VersionProbe::Malformed),
    ];
    for (prefix, expected) in cases {
        assert_eq!(leading_version(prefix), expected, "{prefix:?}");
    }
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
    let dir_metadata = |mode: u32| {
        // A real directory, chmod'ed, so `Metadata` carries the injected mode;
        // ownership cannot be faked without root, which row (b) reports.
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("d");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
        std::fs::symlink_metadata(&dir).unwrap()
    };
    assert_eq!(trust(&file, &dir_metadata(0o700), own), None);
    assert_eq!(
        trust(&file, &dir_metadata(0o775), own),
        Some(AuthorityRefusal::DirWritable)
    );
    assert_eq!(
        trust(&file, &dir_metadata(0o777), own),
        Some(AuthorityRefusal::DirWritable)
    );
    // And the file's own ownership, injected independently of the directory: a
    // trusted 0700 directory does not launder a file someone else owns. This is
    // AC4's "foreign file owner (injected independently of the directory)".
    assert_eq!(
        trust(
            &HostFileFacts {
                uid: own + 1,
                ..file
            },
            &dir_metadata(0o700),
            own
        ),
        Some(AuthorityRefusal::FileOwner)
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
    // And the cause survives: the message says what failed *and* why, so a user
    // can tell a permission problem from a race or a missing file.
    let Read::NotUsed(Problem::Unreadable(message)) = &read else {
        unreachable!("asserted above")
    };
    assert!(message.contains("opening"), "{message}");
    assert!(
        message.contains("Permission denied") || message.contains("os error 13"),
        "the errno must reach the user: {message}"
    );
    assert!(!matches!(
        read,
        Read::NotUsed(Problem::Damaged(_)) | Read::NotUsed(Problem::Untrusted(_))
    ));
    assert_eq!(AuthoritySnapshot::take(&dir), before);
}

/// The directory's uid is read from the real `Metadata`, and the directory is
/// decided first: a reader that invented the directory's owner from the euid
/// would call this a file problem, and one that mapped the *file's* uid from
/// the directory would call a healthy store untrusted.
#[test]
fn the_directory_owner_comes_from_real_metadata_and_decides_first() {
    let root = tempfile::tempdir().unwrap();
    let dir = authority_dir(root.path());
    write(&dir, &file_of(&[record("/tmp/a", "10.0.0.5")]));
    let own = crate::host_paths::current_euid();
    assert!(matches!(store_at(&dir).read(), Read::Current { .. }));
    let read = store_at(&dir).read_with(own.wrapping_add(1), || {});
    assert!(
        matches!(
            &read,
            Read::NotUsed(Problem::Untrusted(AuthorityRefusal::DirOwner))
        ),
        "{}",
        damage_name(&read)
    );
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

/// AC7 with an old descriptor that looks broken: the reopen decision is the
/// descriptor's link count, so a size or read failure on the *old* file cannot
/// pre-empt the retry and turn a healthy replacement into a warning.
#[test]
fn an_unlinked_oversized_descriptor_still_reopens() {
    let root = tempfile::tempdir().unwrap();
    let dir = authority_dir(root.path());
    let mut oversized = file_of(&[record("/tmp/a", "10.0.0.5")]);
    oversized.push_str(&" ".repeat(MAX_BYTES as usize + 1 - oversized.len()));
    write(&dir, &oversized);
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
    assert_eq!(
        attempts, 2,
        "the old descriptor was retried, not classified"
    );
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
    let error = Store::host().expect_err("an empty $HOME is an error");
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

// ---------------------------------------------------------------------------
// Group W: the writer (ADR-0065 Constraints 1–6)
// ---------------------------------------------------------------------------

fn allowance(text: &str) -> crate::egress_policy::Allowance {
    crate::egress_policy::Allowance::parse(text).expect(text)
}

/// The store's current records as decoded fields, or a panic naming the state.
fn current(dir: &Path) -> Vec<(String, String, String, i64)> {
    match store_at(dir).read() {
        Read::Current { records, .. } => records
            .iter()
            .map(|r| {
                (
                    r.project.clone(),
                    r.path.clone(),
                    r.destination.clone(),
                    r.recorded_ms,
                )
            })
            .collect(),
        other => panic!(
            "expected a current store, got {}",
            match other {
                Read::Absent => "absent".to_owned(),
                Read::Newer { v, .. } => format!("newer {v}"),
                Read::NotUsed(problem) => format!("not used ({problem:?})"),
                Read::Current { .. } => unreachable!(),
            }
        ),
    }
}

/// W1: a repeated `record` and a `forget` of an absent record write nothing, and
/// a real write updates exactly one row.
#[test]
fn record_and_forget_are_idempotent_by_bytes_inode_and_mtime() {
    let root = tempfile::tempdir().unwrap();
    let dir = authority_dir(root.path());
    let store = store_at(&dir);
    let destination = allowance("tcp://[203.0.113.10/32]:443");
    let path = "/tmp/w1";
    let digest = digest(path);

    assert_eq!(
        store.record(&digest, path, &destination, 1_000).unwrap(),
        RecordOutcome::Recorded { recorded_ms: 1_000 }
    );
    let written = AuthoritySnapshot::take(&dir);
    // The record's canonical spelling is what is stored.
    assert_eq!(
        current(&dir),
        vec![(
            digest.clone(),
            path.to_owned(),
            "tcp://[203.0.113.10/32]:443".to_owned(),
            1_000
        )]
    );

    // Same project and destination under a non-canonical spelling: the parsed
    // value decides, so this is still already recorded and nothing is written.
    assert_eq!(
        store.record(&digest, path, &destination, 9_999).unwrap(),
        RecordOutcome::AlreadyRecorded { recorded_ms: 1_000 }
    );
    assert_eq!(
        AuthoritySnapshot::take(&dir),
        written,
        "a repeated record leaves bytes, inode and mtime untouched"
    );

    // Forgetting a destination the store does not hold writes nothing.
    assert_eq!(
        store
            .forget(&digest, &allowance("tcp://[198.51.100.0/24]:443"))
            .unwrap(),
        ForgetOutcome::Unchanged
    );
    assert_eq!(AuthoritySnapshot::take(&dir), written);

    // A real forget removes exactly that row.
    assert_eq!(
        store.forget(&digest, &destination).unwrap(),
        ForgetOutcome::Removed
    );
    assert!(current(&dir).is_empty());

    // Forgetting again is unchanged, and creates nothing new.
    let after = AuthoritySnapshot::take(&dir);
    assert_eq!(
        store.forget(&digest, &destination).unwrap(),
        ForgetOutcome::Unchanged
    );
    assert_eq!(AuthoritySnapshot::take(&dir), after);
}

/// W2: two writers serialise on one never-unlinked lock, and every key set
/// survives. The checkpoint makes the contention deterministic: A holds the lock
/// inside `under_lock` until B has actually been refused once.
#[test]
fn concurrent_writers_preserve_entire_cross_project_key_set_under_checkpoint() {
    use std::sync::{Arc, mpsc};

    let root = tempfile::tempdir().unwrap();
    let dir = authority_dir(root.path());
    let store = store_at(&dir);

    // Deterministic contention: A signals that it holds the lock and waits for
    // B's first refused attempt before writing and releasing.
    let a = store.clone();
    let (a_locked, wait_locked) = mpsc::channel();
    let (b_contended_tx, b_contended) = mpsc::channel();
    let dir_a = dir.clone();
    let first = std::thread::spawn(move || {
        let store = store_at(&dir_a);
        let _ = &a;
        store.record_with(
            &digest("/tmp/a"),
            "/tmp/a",
            &allowance("10.0.0.1"),
            1_000,
            WriteProbe {
                euid: current_euid(),
                on_contention: |_| {},
                under_lock: || {
                    a_locked.send(()).unwrap();
                    // B cannot be refused until A holds the lock, and A holds it
                    // here, so this wait cannot deadlock.
                    b_contended
                        .recv_timeout(std::time::Duration::from_secs(10))
                        .unwrap();
                },
                after_open: || {},
            },
        )
    });
    wait_locked
        .recv_timeout(std::time::Duration::from_secs(10))
        .unwrap();
    let dir_b = dir.clone();
    let second = std::thread::spawn(move || {
        store_at(&dir_b).record_with(
            &digest("/tmp/b"),
            "/tmp/b",
            &allowance("10.0.0.2"),
            2_000,
            WriteProbe {
                euid: current_euid(),
                on_contention: move |_| {
                    let _ = b_contended_tx.send(());
                },
                under_lock: || {},
                after_open: || {},
            },
        )
    });
    assert_eq!(
        first.join().unwrap().unwrap(),
        RecordOutcome::Recorded { recorded_ms: 1_000 }
    );
    assert_eq!(
        second.join().unwrap().unwrap(),
        RecordOutcome::Recorded { recorded_ms: 2_000 }
    );
    assert_eq!(current(&dir).len(), 2, "both writers' rows survive");

    // The lock inode is stable across writes: it is never unlinked or replaced.
    let lock_ino = std::fs::metadata(store.lock_path()).unwrap().ino();

    // The 8 × 8 round: every pair lands exactly once, with its own timestamp.
    let shared = Arc::new(store.clone());
    let mut threads = Vec::new();
    for thread in 0..8 {
        let store = Arc::clone(&shared);
        threads.push(std::thread::spawn(move || {
            for project in 0..8 {
                let n = thread * 8 + project;
                let path = format!("/tmp/round/{thread}/{project}");
                store
                    .record(
                        &digest(&path),
                        &path,
                        &allowance(&format!("10.{thread}.{project}.1")),
                        n as i64,
                    )
                    .unwrap();
            }
        }));
    }
    for thread in threads {
        thread.join().unwrap();
    }
    let records = current(&dir);
    assert_eq!(records.len(), 2 + 64, "no write was lost or duplicated");
    let mut seen: Vec<(String, String)> = Vec::new();
    for (project, path, destination, recorded_ms) in &records {
        assert_eq!(*project, digest(path), "every row keeps its own identity");
        assert!(
            seen.iter().all(|(p, d)| p != project || d != destination),
            "duplicate row {project} {destination}"
        );
        assert!(
            *recorded_ms >= 0
                && (*recorded_ms < 64 || *recorded_ms == 1_000 || *recorded_ms == 2_000)
        );
        seen.push((project.clone(), destination.clone()));
    }
    for thread in 0..8 {
        for project in 0..8 {
            let path = format!("/tmp/round/{thread}/{project}");
            let wanted = format!("10.{thread}.{project}.1");
            assert!(
                records
                    .iter()
                    .any(|(_, p, d, _)| p == &path && d.contains(&wanted)),
                "the round's key {path} -> {wanted} is present"
            );
        }
    }
    assert_eq!(
        std::fs::metadata(store.lock_path()).unwrap().ino(),
        lock_ino,
        "allowances.lock is never replaced"
    );
}

/// W3: every other record keeps its decoded fields, including a destination this
/// build cannot parse and one for another project.
#[test]
fn write_preserves_other_records_decoded_fields_including_unparseable_destinations() {
    let root = tempfile::tempdir().unwrap();
    let dir = authority_dir(root.path());
    // `not-a-destination` fails `Allowance::parse`, and the reader still accepts
    // the record: the schema checks the columns, not the grammar.
    let untouched = [
        (
            digest("/tmp/other"),
            "/tmp/other".to_owned(),
            "tcp://[198.51.100.9/32]:8443".to_owned(),
            11,
        ),
        (
            digest("/tmp/w3"),
            "/tmp/w3".to_owned(),
            "not-a-destination".to_owned(),
            22,
        ),
        (
            digest("/tmp/other"),
            "/tmp/other".to_owned(),
            "unparseable".to_owned(),
            33,
        ),
    ];
    let lines: Vec<String> = untouched
        .iter()
        .map(|(project, path, destination, recorded_ms)| {
            format!(
                r#"{{"project":"{project}","path":"{path}","destination":"{destination}","recorded_ms":{recorded_ms}}}"#
            )
        })
        .collect();
    write(&dir, &file_of(&lines));

    let store = store_at(&dir);
    let added = allowance("tcp://[203.0.113.10/32]:443");
    assert!(matches!(
        store
            .record(&digest("/tmp/w3"), "/tmp/w3", &added, 44)
            .unwrap(),
        RecordOutcome::Recorded { .. }
    ));
    let after = current(&dir);
    assert_eq!(after.len(), 4);
    for (project, path, destination, recorded_ms) in &untouched {
        assert!(
            after.iter().any(|row| row
                == &(
                    project.clone(),
                    path.clone(),
                    destination.clone(),
                    *recorded_ms
                )),
            "the untouched row {path} {destination} kept its decoded fields"
        );
    }
    // The new row is last, in file order, with the canonical spelling.
    assert_eq!(
        after.last().unwrap(),
        &(
            digest("/tmp/w3"),
            "/tmp/w3".to_owned(),
            "tcp://[203.0.113.10/32]:443".to_owned(),
            44
        )
    );

    // A forget of the parseable new row changes nothing about the others.
    assert_eq!(
        store.forget(&digest("/tmp/w3"), &added).unwrap(),
        ForgetOutcome::Removed
    );
    let after = current(&dir);
    assert_eq!(after.len(), 3);
    for (project, path, destination, recorded_ms) in &untouched {
        assert!(after.iter().any(|row| row
            == &(
                project.clone(),
                path.clone(),
                destination.clone(),
                *recorded_ms
            )));
    }
}

/// W4: at either bound the write is refused with `Full` and the file is exactly
/// as it was.
#[test]
fn full_store_at_record_and_byte_limits_leaves_file_untouched() {
    let root = tempfile::tempdir().unwrap();
    let dir = authority_dir(root.path());
    let store = store_at(&dir);
    let destination = allowance("10.0.0.5");

    // 4,096 records is the largest the reader accepts, so a 4,097th is `Full`.
    let at_records: Vec<String> = (0..MAX_RECORDS)
        .map(|n| record(&format!("/tmp/r{n}"), "10.0.0.5"))
        .collect();
    write(&dir, &file_of(&at_records));
    assert_eq!(current(&dir).len(), MAX_RECORDS);
    let full = file_facts(&dir.join(FILE));
    assert!(
        matches!(
            store.record(&digest("/tmp/one-more"), "/tmp/one-more", &destination, 1),
            Err(WriteError::Full)
        ),
        "a 4,097th record is refused"
    );
    assert_eq!(file_facts(&dir.join(FILE)), full);

    // The byte bound: a valid file just under 1 MiB whose next record crosses it.
    let long = format!("/tmp/{}", "p".repeat(180));
    let one = record(&format!("{long}0000"), "10.0.0.5");
    // Half a record of headroom: the fixture is under the bound, and one more
    // record crosses it.
    let target = (MAX_BYTES as usize).saturating_sub(one.len() / 2);
    let count = target / (one.len() + 1);
    assert!(count < MAX_RECORDS, "the byte bound is reached first");
    // Every path is the same length, so the encoded size is exactly predictable.
    let near: Vec<String> = (0..count)
        .map(|n| record(&format!("{long}{n:04}"), "10.0.0.5"))
        .collect();
    let bytes = file_of(&near);
    assert!(
        (bytes.len() as u64) < MAX_BYTES,
        "the fixture is under the byte bound"
    );
    write(&dir, &bytes);
    let near_snapshot = file_facts(&dir.join(FILE));
    assert!(
        matches!(
            store.record(
                &format!("{long}new-record"),
                &format!("{long}new-record"),
                &destination,
                1
            ),
            Err(WriteError::Full)
        ),
        "the record that crosses 1 MiB is refused"
    );
    assert_eq!(file_facts(&dir.join(FILE)), near_snapshot);
}

/// W5: an untrusted directory is refused before the lock is even opened, so
/// neither `allowances.lock` nor `allowances.json` appears.
#[test]
fn untrusted_directory_is_never_written_or_locked() {
    let root = tempfile::tempdir().unwrap();
    let destination = allowance("10.0.0.5");
    for mode in [0o777, 0o775, 0o757] {
        let dir = root.path().join(format!("dir-{mode:o}"));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
        let before = AuthoritySnapshot::take(&dir);
        let store = store_at(&dir);
        assert!(
            matches!(
                store.record("project", "/tmp/w5", &destination, 1),
                Err(WriteError::Untrusted(_))
            ),
            "mode {mode:o} is refused"
        );
        assert!(matches!(
            store.forget("project", &destination),
            Err(WriteError::Untrusted(_))
        ));
        assert_eq!(AuthoritySnapshot::take(&dir), before);
        assert!(!dir.join(LOCK_FILE).exists(), "mode {mode:o} opens no lock");
        assert!(!dir.join(FILE).exists(), "mode {mode:o} writes no store");
    }

    // A foreign owner, expressed through the injected euid.
    let dir = root.path().join("foreign");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let store = store_at(&dir);
    assert!(matches!(
        store.record_with(
            "project",
            "/tmp/w5",
            &destination,
            1,
            WriteProbe {
                euid: current_euid() + 1,
                on_contention: |_| {},
                under_lock: || {},
                after_open: || {},
            },
        ),
        Err(WriteError::Untrusted(AuthorityRefusal::DirOwner))
    ));
    assert!(!dir.join(LOCK_FILE).exists());

    // A path that is not a directory at all.
    let file = root.path().join("not-a-dir");
    std::fs::write(&file, b"x").unwrap();
    let store = Store::at(&file);
    assert!(matches!(
        store.record("project", "/tmp/w5", &destination, 1),
        Err(WriteError::Untrusted(AuthorityRefusal::DirNotDirectory))
    ));
}

/// W6: a newer, oversized, untrusted or legitimately changed file is never
/// replaced by `record` or `forget`, and every byte, inode, mode and mtime stays.
#[test]
fn writer_refuses_newer_across_oversized_untrusted_and_changed_body() {
    let root = tempfile::tempdir().unwrap();
    let destination = allowance("10.0.0.5");
    let cases: Vec<(&str, Vec<u8>, u32, WriteError)> = vec![
        (
            "newer",
            br#"{"v":2,"records":[],"extra":true}"#.to_vec(),
            0o600,
            WriteError::Newer { v: 2 },
        ),
        (
            "newer-oversized",
            {
                let mut bytes =
                    br#"{"v":2,"records":[{"project":"x","path":"/tmp/x","destination":"10.0.0.5","recorded_ms":0}]}"#
                        .to_vec();
                bytes.resize(MAX_BYTES as usize + 1, b' ');
                bytes
            },
            0o600,
            WriteError::Newer { v: 2 },
        ),
        (
            "damaged",
            br#"{"v":1,"records":[{"project":"broken"}]}"#.to_vec(),
            0o600,
            WriteError::Damaged(Damage::Undecodable),
        ),
        (
            "untrusted-file",
            br#"{"v":2,"records":[]}"#.to_vec(),
            0o666,
            WriteError::Untrusted(AuthorityRefusal::FileWritable),
        ),
    ];
    for (label, bytes, mode, expected) in cases {
        let case_root = root.path().join(label);
        std::fs::create_dir(&case_root).unwrap();
        let dir = authority_dir(&case_root);
        let file = dir.join(FILE);
        std::fs::write(&file, &bytes).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
        let before = file_facts(&file);
        let store = store_at(&dir);
        let record = store.record(&digest("/tmp/w6"), "/tmp/w6", &destination, 1);
        assert!(
            matches!(record, Err(ref e) if std::mem::discriminant(e) == std::mem::discriminant(&expected)),
            "{label}: {record:?}"
        );
        let forget = store.forget(&digest("/tmp/w6"), &destination);
        assert!(
            matches!(forget, Err(ref e) if std::mem::discriminant(e) == std::mem::discriminant(&expected)),
            "{label}: {forget:?}"
        );
        assert_eq!(file_facts(&file), before, "{label} is untouched");
    }
}

/// W7: repeated writes against a damaged store beside an occupied `.damaged`
/// sibling change neither file.
#[test]
fn writer_refuses_repeated_damage_and_occupied_backup_without_changing_directory() {
    let root = tempfile::tempdir().unwrap();
    let dir = authority_dir(root.path());
    write(&dir, r#"{"v":1,"records":[{"project":"x"}]}"#);
    std::fs::write(dir.join("allowances.json.damaged"), b"earlier damage").unwrap();
    let before = (
        file_facts(&dir.join(FILE)),
        file_facts(&dir.join("allowances.json.damaged")),
    );
    let store = store_at(&dir);
    let destination = allowance("10.0.0.5");
    for _ in 0..2 {
        assert!(matches!(
            store.record(&digest("/tmp/w7"), "/tmp/w7", &destination, 1),
            Err(WriteError::Damaged(_))
        ));
        assert!(matches!(
            store.forget(&digest("/tmp/w7"), &destination),
            Err(WriteError::Damaged(_))
        ));
        assert_eq!(
            (
                file_facts(&dir.join(FILE)),
                file_facts(&dir.join("allowances.json.damaged")),
            ),
            before
        );
    }
    assert_eq!(
        std::fs::read(dir.join("allowances.json.damaged")).unwrap(),
        b"earlier damage"
    );
}

/// W8: a write fault leaves the existing store, and no temporary file, behind.
///
/// The fault is a read-only directory: `atomic_write` creates its temporary in
/// the parent, so the operation fails before the rename. Nothing else changes.
#[test]
fn atomic_write_fault_leaves_existing_store_and_directory_intact() {
    let root = tempfile::tempdir().unwrap();
    let dir = authority_dir(root.path());
    write(&dir, &file_of(&[record("/tmp/kept", "10.0.0.5")]));
    // The lock already exists (0600), so a read-only directory lets the lock be
    // opened and holds the fault for the store's own atomic replace.
    std::fs::write(dir.join(LOCK_FILE), b"").unwrap();
    std::fs::set_permissions(dir.join(LOCK_FILE), std::fs::Permissions::from_mode(0o600)).unwrap();
    let store = store_at(&dir);
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let before = AuthoritySnapshot::take(&dir);
    let result = store.record(&digest("/tmp/w8"), "/tmp/w8", &allowance("10.0.0.6"), 1);
    assert!(
        matches!(result, Err(WriteError::Unreadable(_))),
        "a read-only directory fails the write: {result:?}"
    );
    assert_eq!(
        AuthoritySnapshot::take(&dir),
        before,
        "no temp file remains"
    );
    // Restore, so the tempdir can be removed.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(current(&dir).len(), 1);
}

/// W9: a lock-free reader of a store being replaced sees only `Current` or a
/// counted `Unsettled`, never a wrong `Current`.
#[test]
fn concurrent_reader_and_writer_observe_only_current_or_unsettled() {
    let root = tempfile::tempdir().unwrap();
    let dir = authority_dir(root.path());
    let store = store_at(&dir);
    let destination = allowance("10.0.0.5");
    assert_eq!(
        store
            .record(&digest("/tmp/w9"), "/tmp/w9", &destination, 1)
            .unwrap(),
        RecordOutcome::Recorded { recorded_ms: 1 }
    );

    let writer_dir = dir.clone();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let writer_stop = std::sync::Arc::clone(&stop);
    let writer = std::thread::spawn(move || {
        let store = store_at(&writer_dir);
        let mut n = 0i64;
        while !writer_stop.load(std::sync::atomic::Ordering::Relaxed) {
            let path = format!("/tmp/w9/{n}");
            store
                .record(&digest(&path), &path, &destination, n)
                .unwrap();
            n += 1;
            if n > 200 {
                break;
            }
        }
    });
    let mut current_seen = 0usize;
    let mut unsettled_seen = 0usize;
    let reader = store_at(&dir);
    for _ in 0..2_000 {
        match reader.read() {
            Read::Current { .. } => current_seen += 1,
            Read::NotUsed(Problem::Unsettled) => unsettled_seen += 1,
            other => panic!(
                "a concurrent read is only Current or Unsettled, got {}",
                match other {
                    Read::Absent => "Absent",
                    Read::Newer { .. } => "Newer",
                    Read::NotUsed(_) => "another Problem",
                    Read::Current { .. } => unreachable!(),
                }
            ),
        }
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    writer.join().unwrap();
    assert!(current_seen > 0, "the reader did read the store");
    let _ = unsettled_seen;
}

/// W10: a project path that is not valid UTF-8 is refused by the writer itself,
/// before anything is created (R8).
///
/// This goes through `Store::record_path`, the entry point both write paths use,
/// rather than through the gate alone: a test of the gate would stay green if no
/// caller used it, and the gate cannot be dropped from `record_path` without
/// changing the type it takes. (`std::fs::canonicalize` refuses a non-UTF-8
/// component with `EILSEQ` on this host, so a `ProjectDir` carrying one cannot be
/// captured; the writer's own entry point is where R8's "before locking" clause
/// lives, and where a path *can* be constructed.)
#[test]
fn record_refuses_non_utf8_project_path() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt as _;

    let root = tempfile::tempdir().unwrap();
    let authority = authority_dir(root.path());
    let store = store_at(&authority);
    let before = AuthoritySnapshot::take(&authority);
    let path = Path::new(OsStr::from_bytes(b"/tmp/proj-\xff\xfe"));
    assert!(matches!(
        store.record_path("project", path, &allowance("10.0.0.1"), 1),
        Err(WriteError::NonUtf8ProjectPath)
    ));
    assert_eq!(
        AuthoritySnapshot::take(&authority),
        before,
        "the refusal creates no file and no lock"
    );
    assert!(!authority.join(LOCK_FILE).exists(), "no lock was opened");
    assert!(!authority.join(FILE).exists(), "no store was written");
    // A UTF-8 path passes the same gate and writes.
    assert_eq!(
        store
            .record_path("project", Path::new("/tmp/ok"), &allowance("10.0.0.1"), 1)
            .unwrap(),
        RecordOutcome::Recorded { recorded_ms: 1 }
    );
    assert_eq!(
        utf8_project_path(Path::new("/tmp/ok")).unwrap(),
        "/tmp/ok",
        "the gate and the writer agree on what a UTF-8 path is"
    );
}

/// A lock the kernel refuses to open is not a busy lock.
///
/// `EACCES` (an unwritable directory) and a contended lock have different
/// remedies — fix the permissions, or wait — so the writer must not report one as
/// the other. The verifier's end-user matrix showed a `0500` authority directory
/// answered "the store is busy (opening a coordination lock file: Permission
/// denied)", which suggests a retry that cannot help.
#[test]
fn a_lock_the_host_refuses_to_open_is_not_reported_as_busy() {
    use std::os::unix::fs::PermissionsExt as _;

    if current_euid() == 0 {
        // Root bypasses the permission bits this test relies on.
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let dir = authority_dir(root.path());
    let store = store_at(&dir);
    // Readable and searchable for us, but not writable: the record can be read,
    // the lock cannot be created.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let error = store
        .record("project", "/tmp/proj", &allowance("10.0.0.9"), 1)
        .expect_err("an unwritable directory cannot hold a lock");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(error, WriteError::LockUnopenable(_)), "{error:?}");
    let line = error.line();
    assert!(!line.contains("busy"), "{line}");
    assert!(line.contains("could not be opened"), "{line}");
    assert!(line.contains("permissions"), "{line}");
    assert!(!dir.join(LOCK_FILE).exists(), "no lock was created");
    assert!(!dir.join(FILE).exists(), "no store was written");
}

/// Plan §6.1's "not a dir" row, for **both** verbs.
///
/// `record` and `forget` are one sequence now, but they answer for a store path
/// whose parent is a regular file before that sequence starts. A `forget` that
/// said `Ok(Unchanged)` here would tell the caller "no store" about a path that
/// does hold something; the table says the directory refusal.
#[test]
fn a_store_path_below_a_regular_file_is_the_directory_refusal_for_both_verbs() {
    use crate::config_authority::AuthorityRefusal;

    let root = tempfile::tempdir().unwrap();
    let parent = root.path().join("not-a-dir");
    std::fs::write(&parent, b"x").unwrap();
    let store = Store::at(&parent.join("agent-vm"));
    let destination = allowance("10.0.0.7");
    assert!(matches!(
        store.record("project", "/tmp/proj", &destination, 1),
        Err(WriteError::Untrusted(AuthorityRefusal::DirNotDirectory))
    ));
    assert!(matches!(
        store.forget("project", &destination),
        Err(WriteError::Untrusted(AuthorityRefusal::DirNotDirectory))
    ));
    assert!(!parent.join("agent-vm").exists(), "nothing was created");
}
