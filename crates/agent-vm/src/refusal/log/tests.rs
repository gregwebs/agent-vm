//! The store's own rules: serialization, eviction, damage and reservation.
//!
//! `flock` is per open file description, so two threads that open the lock file
//! separately contend exactly as two processes do — which is what makes the
//! concurrency row here evidence about the production shape.

use super::*;
use crate::refusal::{Destination, EntryKey, Kind, RefusalEntry, SessionInfo};

const HASH: &str = "ab12cd34ef56";
const NOW: i64 = 1_790_000_000_000;

fn sid(text: &str) -> SessionId {
    SessionId::parse(text).expect("an 8-hex session ID")
}

fn session(text: &str, socket: bool) -> SessionSnapshot {
    SessionSnapshot::new(SessionInfo {
        id: sid(text),
        pid: text.parse::<u32>().unwrap_or(1),
        started_ms: NOW - 1_000,
        socket,
    })
}

fn entry(id: &str, key: &str, last_ms: i64) -> RefusalEntry {
    RefusalEntry {
        id: id.to_owned(),
        key: EntryKey {
            kind: Kind::NetworkDenial,
            destination: Destination::Address {
                protocol: "tcp".into(),
                ip: Some("203.0.113.10".parse().unwrap()),
                port: Some(443),
            },
            credential: None,
        },
        layer: "tenant".into(),
        last_site: key.to_owned(),
        last_ip: Some("203.0.113.10".parse().unwrap()),
        name: None,
        last_location: None,
        last_reason: None,
        last_revision: 1,
        count: 1,
        first_ms: last_ms,
        last_ms,
    }
}

fn filled(mut snapshot: SessionSnapshot, count: usize, last_ms: i64) -> SessionSnapshot {
    for index in 0..count {
        snapshot
            .entries
            .push(entry(&format!("{index:08x}"), "tcp-syn", last_ms));
    }
    snapshot
}

/// A `0700` directory this euid owns. These tests never boot a guest, so the
/// system temp dir is only a location — nothing here asserts on its spelling.
fn dir() -> (tempfile::TempDir, SessionsDir) {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join(format!("{HASH}.sessions"));
    let dir = SessionsDir::open_or_create(&path).unwrap();
    (root, dir)
}

fn file_mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn log_is_0600_in_a_0700_dir() {
    let (_root, dir) = dir();
    assert_eq!(file_mode(dir.path()), 0o700);
    let own = filled(session("00000001", true), 1, NOW);
    dir.write(&own, NOW).unwrap();
    assert_eq!(file_mode(&dir.record()), 0o600);
    assert_eq!(file_mode(&dir.lock_path()), 0o600);
}

#[test]
fn merge_replaces_only_the_writers_session() {
    let (_root, dir) = dir();
    let mine = filled(session("00000001", true), 1, NOW);
    let theirs = filled(session("00000002", true), 2, NOW);
    dir.write(&theirs, NOW).unwrap();
    dir.write(&mine, NOW).unwrap();
    let log = dir.read().unwrap();
    assert_eq!(log.sessions.len(), 2);
    let reloaded = |id: &str| {
        log.sessions
            .iter()
            .find(|session| session.info.id.as_str() == id)
            .unwrap()
            .clone()
    };
    assert_eq!(reloaded("00000001").entries.len(), 1);
    assert_eq!(reloaded("00000002").entries.len(), 2);

    // The writer's second write replaces its own record, never the other's.
    let mine = filled(session("00000001", true), 3, NOW);
    dir.write(&mine, NOW).unwrap();
    let log = dir.read().unwrap();
    assert_eq!(log.sessions.len(), 2);
    assert_eq!(
        log.sessions
            .iter()
            .find(|s| s.info.id.as_str() == "00000001")
            .unwrap()
            .entries
            .len(),
        3
    );
    assert_eq!(
        log.sessions
            .iter()
            .find(|s| s.info.id.as_str() == "00000002")
            .unwrap()
            .entries
            .len(),
        2
    );
}

#[test]
fn two_writers_on_independent_descriptors_serialize() {
    let (_root, dir) = dir();
    // Both threads open the lock file themselves, so they contend as two
    // processes would. Each writes 20 times; every write must land.
    let mut handles = Vec::new();
    for writer in 0..2u8 {
        let dir = dir.clone();
        handles.push(std::thread::spawn(move || {
            let own = filled(session(&format!("0000000{writer}",), true), 1, NOW);
            for round in 0..20 {
                let mut own = own.clone();
                own.rev = round;
                dir.write(&own, NOW).unwrap();
            }
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }
    let log = dir.read().unwrap();
    assert_eq!(log.sessions.len(), 2, "no writer lost the other's record");
    // Both records are the last write of their thread.
    for session in &log.sessions {
        assert_eq!(session.rev, 19);
    }
}

#[test]
fn eviction_is_deterministic_and_counted() {
    // The ordering rule, over a log built in memory: no file I/O, so the
    // evidence is about the rule rather than about the disk.
    let build = || {
        let mut log = Log::new(0, Vec::new());
        let mut ended = filled(session("00000001", true), 600, NOW - 30_000);
        ended.info.started_ms = NOW - 30_000;
        ended.ended_ms = Some(NOW - 25_000);
        let mut ended_later = filled(session("00000002", true), 600, NOW - 20_000);
        ended_later.info.started_ms = NOW - 20_000;
        ended_later.ended_ms = Some(NOW - 15_000);
        for index in 0..4u8 {
            let mut live = filled(session(&format!("0000009{index}"), true), 300, NOW - 1_000);
            live.info.started_ms = NOW - 1_000;
            log.sessions.push(live);
        }
        log.sessions.push(ended);
        log.sessions.push(ended_later);
        log
    };
    let mut first = build();
    let evicted = first.evict("00000090");
    let mut second = build();
    assert_eq!(evicted, second.evict("00000090"));
    assert_eq!(evicted, 1, "an ended session goes before any live one");
    assert!(first.total_entries() <= MAX_LOG_ENTRIES);
    let ids = |log: &Log| -> Vec<String> {
        log.sessions
            .iter()
            .map(|session| session.info.id.as_str().to_owned())
            .collect()
    };
    assert_eq!(ids(&first), ids(&second), "one ordering, computed once");
    let survivors = ids(&first);
    // The older ended session is the first to go; the newer ended one still
    // fits, and no live session is touched while an ended one remains.
    assert!(!survivors.contains(&"00000001".to_owned()), "{survivors:?}");
    assert!(survivors.contains(&"00000002".to_owned()), "{survivors:?}");
    for index in 0..4 {
        assert!(survivors.contains(&format!("0000009{index}")));
    }
    assert!(
        survivors.contains(&"00000090".to_owned()),
        "the writer's own session is never evicted: {survivors:?}"
    );

    // Oldest activity first among equals: with the ended sessions gone, the
    // older live session is the next to go — and a live one is not counted,
    // because its owner writes it back.
    let mut log = Log::new(0, Vec::new());
    for (text, at) in [("0000000a", NOW - 9_000), ("0000000b", NOW - 2_000)] {
        let mut live = filled(session(text, true), 1_100, at);
        live.info.started_ms = at;
        log.sessions.push(live);
    }
    assert_eq!(log.evict("0000000b"), 0, "a live eviction is not a loss");
    assert_eq!(log.sessions.len(), 1);
    assert_eq!(log.sessions[0].info.id.as_str(), "0000000b");
}

/// A session whose own record is large enough that two of them exceed the byte
/// bound: 512 entries with maximal guest names.
fn bulky(text: &str, last_ms: i64) -> SessionSnapshot {
    let mut snapshot = session(text, true);
    snapshot.info.started_ms = last_ms;
    for index in 0..crate::refusal::MAX_ENTRIES_PER_SESSION {
        let mut entry = entry(&format!("{index:08x}"), "tls-sni", last_ms);
        entry.key.destination = Destination::Host {
            protocol: "tcp".into(),
            name: "x".repeat(crate::refusal::MAX_NAME_BYTES),
            port: Some(443),
        };
        entry.name = Some(crate::refusal::GuestName {
            name: "x".repeat(crate::refusal::MAX_NAME_BYTES),
            source: "sni".into(),
            truncated: false,
        });
        snapshot.entries.push(entry);
    }
    snapshot
}

#[test]
fn an_evicted_live_session_is_restored_by_its_owner() {
    let (_root, dir) = dir();
    // Five maximal sessions: 2,560 entries against a 2,048 cap, all of them
    // live, so the ordering has to fall back to activity. Ours is the oldest,
    // which makes "restored by its owner" a real property rather than a hope.
    let ours = bulky("0000000a", NOW - 100_000);
    dir.write(&ours, NOW - 100_000).unwrap();
    for index in 0..4u8 {
        let other = bulky(&format!("0000000{index}"), NOW - 1_000 + i64::from(index));
        dir.write(&other, NOW).unwrap();
    }
    let log = dir.read().unwrap();
    assert!(
        !log.sessions
            .iter()
            .any(|s| s.info.id.as_str() == "0000000a"),
        "the older live session was evicted to make room"
    );
    // Not counted: it comes back on its owner's next write, and counting a
    // restoration as a loss made the counter climb on every single write while
    // five full live sessions shared a project.
    assert_eq!(
        log.evicted_sessions, 0,
        "a restorable eviction is not a lost record"
    );

    // Its owner's next write puts it back whole, and the list is not truncated.
    dir.write(&ours, NOW).unwrap();
    let restored = dir
        .read()
        .unwrap()
        .sessions
        .into_iter()
        .find(|s| s.info.id.as_str() == "0000000a")
        .expect("restored");
    assert_eq!(
        restored.entries.len(),
        crate::refusal::MAX_ENTRIES_PER_SESSION
    );
}

#[test]
fn serialized_size_never_exceeds_2_mib() {
    let (_root, dir) = dir();
    // The writer's own session is the worst case: 512 entries with maximum-size
    // names. It has to fit, because a session that cannot be persisted would
    // have no log at all.
    let mut own = session("00000001", true);
    for index in 0..crate::refusal::MAX_ENTRIES_PER_SESSION {
        let mut entry = entry(&format!("{index:08x}"), "tls-sni", NOW);
        entry.key.destination = Destination::Host {
            protocol: "tcp".into(),
            name: "x".repeat(crate::refusal::MAX_NAME_BYTES),
            port: Some(443),
        };
        entry.name = Some(crate::refusal::GuestName {
            name: "x".repeat(crate::refusal::MAX_NAME_BYTES),
            source: "sni".into(),
            truncated: false,
        });
        own.entries.push(entry);
    }
    dir.write(&own, NOW).unwrap();
    let bytes = std::fs::read(dir.record()).unwrap();
    assert!(bytes.len() as u64 <= MAX_LOG_BYTES, "{} bytes", bytes.len());
    // And the eviction loop holds the same bound with other sessions present.
    for index in 0..6u8 {
        let mut other = filled(session(&format!("0000001{index}"), true), 512, NOW - 100);
        other.ended_ms = Some(NOW - 50);
        dir.write(&other, NOW).unwrap();
    }
    let bytes = std::fs::read(dir.record()).unwrap();
    assert!(bytes.len() as u64 <= MAX_LOG_BYTES, "{} bytes", bytes.len());
}

/// A socket file for `id`, so the session that names it looks live. The prune
/// rule now drops an empty session whose socket is gone, which is the behaviour
/// the reservation's own write has to leave alone.
fn bind_socket(dir: &SessionsDir, id: &SessionId) -> std::io::Result<()> {
    std::os::unix::net::UnixListener::bind(dir.socket_path(id)).map(drop)
}

/// The three ways a candidate is refused — an ID the log already holds, a socket
/// name already on disk, and a bind that loses the race — are each *forced*
/// here. Left to `SessionId::generate`, none of them would happen often enough
/// to be evidence.
#[test]
fn sid_reservation_redraws_on_log_and_socket_collision() {
    let (_root, dir) = dir();
    // Candidates, in the order the draw returns them.
    let in_log = sid("0000000a");
    let socket_taken = sid("0000000b");
    let loses_the_race = sid("0000000c");
    let free = sid("0000000d");
    // `in_log` is in the log, and `socket_taken` has a socket file, but no log
    // entry: exactly the case the `exists` check exists for.
    dir.write(&filled(session("0000000a", true), 1, NOW), NOW)
        .unwrap();
    bind_socket(&dir, &in_log).unwrap();
    bind_socket(&dir, &socket_taken).unwrap();

    let mut script = [
        in_log.clone(),
        socket_taken.clone(),
        loses_the_race.clone(),
        free.clone(),
    ]
    .into_iter();
    let mut drawn = Vec::new();
    let mut binds = Vec::new();
    let reserved = dir
        .reserve_drawn(
            NOW,
            42,
            true,
            || {
                let id = script.next().expect("the draw ran out of candidates");
                drawn.push(id.as_str().to_owned());
                id
            },
            |id| {
                binds.push(id.as_str().to_owned());
                if *id == loses_the_race {
                    return Err(std::io::ErrorKind::AddrInUse.into());
                }
                bind_socket(&dir, id)
            },
        )
        .unwrap()
        .expect("the lock was free");

    assert_eq!(
        drawn,
        ["0000000a", "0000000b", "0000000c", "0000000d"],
        "each refused candidate costs exactly one redraw, in the order they happen"
    );
    assert_eq!(
        binds,
        ["0000000c", "0000000d"],
        "the candidate the log or the socket already names is never bound"
    );
    assert_eq!(reserved.snapshot.info.id, free);
    assert_eq!(reserved.snapshot.info.pid, 42);
    let log = dir.read().unwrap();
    let ids: Vec<&str> = log
        .sessions
        .iter()
        .map(|session| session.info.id.as_str())
        .collect();
    // The pre-written session and the reserved one; nothing was written for a
    // candidate that was refused.
    assert_eq!(ids.len(), 2, "{ids:?}");
    assert!(ids.contains(&"0000000a"));
    assert!(ids.contains(&"0000000d"));
    assert!(
        dir.socket_path(&free).exists(),
        "the reserved socket is the one bound"
    );
}

/// A log written before the credential fields existed still loads and is still
/// written back. The fields are optional on purpose: an absent `Option` decodes as
/// `None`, and a non-optional one would fail the whole decode — a file this build
/// cannot decode is one it sets aside.
#[test]
fn an_entry_written_before_the_credential_fields_still_loads() {
    let (_root, dir) = dir();
    let older = serde_json::json!({
        "v": 1,
        "evicted_sessions": 0,
        "sessions": [{
            "info": {"id": "0a1b2c3d", "pid": 1, "started_ms": NOW - 1_000, "socket": true},
            "rev": 1, "ended_ms": null, "heartbeat_ms": null,
            "suppressed": 0, "lost": 0, "gap": false,
            "entries": [{
                "id": "46d712fd",
                "key": {"kind": "credential_refusal", "destination": {
                    "variant": "host", "protocol": "tcp",
                    "name": "api.deepseek.com", "port": 443}},
                "layer": "tenant", "last_site": "secret-violation", "last_ip": null,
                "name": null, "last_revision": 1, "count": 1,
                "first_ms": NOW - 500, "last_ms": NOW - 500
            }]
        }]
    });
    std::fs::write(dir.record(), serde_json::to_vec(&older).unwrap()).unwrap();

    let log = dir.read().unwrap();
    assert_eq!(log.damaged, None, "an older entry is not damage");
    assert_eq!(log.sessions.len(), 1);
    let entry = &log.sessions[0].entries[0];
    assert_eq!(entry.key.credential, None);
    assert_eq!(entry.last_location, None);
    assert_eq!(entry.last_reason, None);

    // The next write replaces the file rather than archiving it, and keeps the row.
    let own = filled(session("00000001", true), 1, NOW);
    let report = dir.write(&own, NOW).unwrap();
    assert_eq!(report.warning, None, "nothing to repair");
    assert!(
        !dir.path().join("refusals.json.damaged").exists(),
        "an old log is never set aside"
    );
    assert_eq!(dir.read().unwrap().sessions.len(), 2);
}

#[test]
fn a_damaged_log_is_set_aside() {
    let (_root, dir) = dir();
    std::fs::write(dir.record(), b"{not json").unwrap();
    // Reading reports the damage and leaves the file exactly where it is: a
    // reader that repaired would be a writer without the lock.
    let log = dir.read().unwrap();
    assert!(log.sessions.is_empty());
    assert_eq!(log.damaged, Some(Damage::Undecodable));
    assert_eq!(std::fs::read(dir.record()).unwrap(), b"{not json");
    assert!(
        !dir.path().join("refusals.json.damaged").exists(),
        "the read path created no `.damaged` file"
    );

    // Writing sets the damaged file aside and starts over.
    let own = filled(session("00000001", true), 1, NOW);
    let report = dir.write(&own, NOW).unwrap();
    assert!(
        report
            .warning
            .as_deref()
            .is_some_and(|warning| warning.contains("could not be used")),
        "{:?}",
        report.warning
    );
    assert!(dir.path().join("refusals.json.damaged").exists());
    assert_eq!(dir.read().unwrap().sessions.len(), 1);
}

/// The interleaving that made a read mutate the log: a damaged file exists, a
/// writer replaces it with a good one, and a reader that had already read the
/// damaged bytes renames what is *now* the writer's good file. The read path's
/// repair was a rename, so "a read leaves the record's identity alone" is
/// exactly what makes that impossible.
#[test]
fn a_reader_never_renames_the_log_out_from_under_a_writer() {
    use std::os::unix::fs::MetadataExt as _;
    let (_root, dir) = dir();
    std::fs::write(dir.record(), b"{not json").unwrap();
    let identity = |path: &Path| {
        let m = std::fs::metadata(path).unwrap();
        (m.dev(), m.ino())
    };
    let before = identity(&dir.record());
    let _ = dir.read().unwrap();
    assert_eq!(
        identity(&dir.record()),
        before,
        "a read must not replace or move the record"
    );
    assert!(!dir.path().join("refusals.json.damaged").exists());

    // The same under contention: a writer replacing a damaged file while readers
    // run cannot end with the writer's good file renamed away.
    let good = filled(session("00000002", true), 1, NOW);
    for _ in 0..20 {
        std::fs::write(dir.record(), b"{not json").unwrap();
        let readers: Vec<_> = (0..3)
            .map(|_| {
                let dir = dir.clone();
                std::thread::spawn(move || {
                    for _ in 0..5 {
                        let _ = dir.read();
                    }
                })
            })
            .collect();
        dir.write(&good, NOW).unwrap();
        for reader in readers {
            reader.join().unwrap();
        }
        let log = dir.read().unwrap();
        assert_eq!(
            log.damaged, None,
            "the writer's good file was not renamed away"
        );
        assert_eq!(log.sessions.len(), 1);
        assert_eq!(log.sessions[0].info.id.as_str(), "00000002");
    }
}

/// A failure to *open* the file is not damage. EMFILE, EACCES and EIO say nothing
/// about the bytes, and setting such a file aside would destroy a good log.
#[test]
fn a_transient_read_failure_is_not_damage() {
    let (_root, dir) = dir();
    let own = filled(session("00000001", true), 1, NOW);
    dir.write(&own, NOW).unwrap();
    let bytes = std::fs::read(dir.record()).unwrap();
    std::fs::set_permissions(dir.record(), std::fs::Permissions::from_mode(0o000)).unwrap();

    let error = dir
        .read()
        .expect_err("an unreadable log is an error, not an answer");
    assert!(format!("{error:#}").contains("refusals.json"), "{error:#}");
    assert!(
        !dir.path().join("refusals.json.damaged").exists(),
        "an unreadable log is not renamed away"
    );
    std::fs::set_permissions(dir.record(), std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(std::fs::read(dir.record()).unwrap(), bytes);
    assert_eq!(dir.read().unwrap().sessions.len(), 1);
}

#[test]
fn a_newer_version_log_is_never_overwritten() {
    let (_root, dir) = dir();
    let newer = serde_json::json!({
        "v": 2,
        "evicted_sessions": 7,
        "sessions": [],
        "future_field": {"anything": true}
    });
    let bytes = serde_json::to_vec(&newer).unwrap();
    std::fs::write(dir.record(), &bytes).unwrap();
    // The read path must recognise it from `v` alone, before decoding the body.
    let read = dir.read().unwrap();
    assert_eq!(read.evicted_sessions, 7);
    let own = filled(session("00000001", true), 1, NOW);
    let report = dir.write(&own, NOW).unwrap();
    assert!(report.warning.is_some(), "one warning, once");
    assert_eq!(report.evicted_sessions, 7);
    assert_eq!(std::fs::read(dir.record()).unwrap(), bytes);
    assert!(
        !dir.path().join("refusals.json.damaged").exists(),
        "a newer log is never treated as damage"
    );
    assert!(
        dir.reserve(NOW, 1, true, |_| Ok::<_, std::io::Error>(()))
            .unwrap()
            .is_none(),
        "a newer log is not reserved into either"
    );
}

/// The case `v`-first decoding exists for: a newer build changes the snapshot
/// shape, so the body no longer decodes as this build's `LogFile`. Deciding from
/// the decode would call it damaged, and a damaged file is one this build
/// replaces — which is exactly what AC12 forbids for a newer version.
#[test]
fn a_newer_log_with_a_changed_shape_is_never_overwritten() {
    let (_root, dir) = dir();
    let newer = serde_json::json!({
        "v": 2,
        "evicted_sessions": 3,
        "sessions": [{"id": "0a1b2c3d", "entries": "this build cannot read it"}]
    });
    let bytes = serde_json::to_vec(&newer).unwrap();
    std::fs::write(dir.record(), &bytes).unwrap();

    let read = dir.read().unwrap();
    assert_eq!(read.damaged, None, "a newer version is not damage");
    assert_eq!(read.evicted_sessions, 3, "what still decodes is reported");
    assert!(read.sessions.is_empty(), "what does not decode is dropped");
    assert_eq!(std::fs::read(dir.record()).unwrap(), bytes);

    let own = filled(session("00000001", true), 1, NOW);
    let report = dir.write(&own, NOW).unwrap();
    assert!(report.warning.is_some(), "one warning, once");
    assert_eq!(
        std::fs::read(dir.record()).unwrap(),
        bytes,
        "never overwritten"
    );
    assert!(!dir.path().join("refusals.json.damaged").exists());
}

#[test]
fn a_loose_mode_dir_is_not_adopted() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("loose.sessions");
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let error = SessionsDir::open(&path).unwrap_err().to_string();
    assert!(error.contains("not 0700"), "{error}");

    let tight = root.path().join("tight.sessions");
    std::fs::create_dir(&tight).unwrap();
    std::fs::set_permissions(&tight, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(SessionsDir::open(&tight).unwrap().is_some());

    // A symlink is not a directory agent-vm adopts, and a missing one is not
    // created by a reader.
    let link = root.path().join("link.sessions");
    std::os::unix::fs::symlink(&tight, &link).unwrap();
    assert!(
        SessionsDir::open(&link)
            .unwrap_err()
            .to_string()
            .contains("not a directory")
    );
    assert!(
        SessionsDir::open(&root.path().join("absent.sessions"))
            .unwrap()
            .is_none()
    );
    assert!(!root.path().join("absent.sessions").exists());
}

#[test]
fn prune_drops_history_and_keeps_the_writer() {
    let (_root, dir) = dir();
    let mut stale = filled(session("00000001", true), 1, NOW - RETENTION_MS - 1);
    // `activity_ms` is a maximum, so every cell has to be old for the session to
    // be idle.
    stale.info.started_ms = NOW - RETENTION_MS - 1;
    stale.entries[0].first_ms = NOW - RETENTION_MS - 1;
    stale.heartbeat_ms = Some(NOW - RETENTION_MS - 1);
    let own = filled(session("00000002", true), 1, NOW);
    // Written through `write` so prune runs with the writer's own record present.
    dir.write(&stale, NOW - RETENTION_MS - 1).unwrap();
    dir.write(&own, NOW).unwrap();
    let log = dir.read().unwrap();
    assert!(
        log.sessions
            .iter()
            .all(|s| s.info.id.as_str() != "00000001"),
        "an idle session past retention is pruned"
    );
    assert!(
        log.sessions
            .iter()
            .any(|s| s.info.id.as_str() == "00000002")
    );

    // An ended session with no entries is not worth a reader's attention.
    let mut quiet = session("00000003", true);
    quiet.ended_ms = Some(NOW);
    dir.write(&quiet, NOW).unwrap();
    // Pruning is the *next* writer's work: a session never prunes itself.
    dir.write(&own, NOW).unwrap();
    assert!(
        dir.read()
            .unwrap()
            .sessions
            .iter()
            .all(|s| s.info.id.as_str() != "00000003")
    );

    // An empty session that claims a socket whose file is gone is a pre-create
    // failure or a killed empty session: nothing to act on, and 30 days of the
    // 2 MiB bound. One whose socket is still there may still be reachable.
    std::os::unix::net::UnixListener::bind(dir.socket_path(&sid("00000005"))).unwrap();
    dir.write(&session("00000005", true), NOW).unwrap();
    dir.write(&session("00000004", true), NOW).unwrap();
    // A session that has reserved its ID and bound the hidden name but not yet
    // renamed it into place is not an empty session without a socket.
    std::os::unix::net::UnixListener::bind(dir.path().join("00000006.sock.tmp")).unwrap();
    dir.write(&session("00000006", true), NOW).unwrap();
    dir.write(&own, NOW).unwrap();
    let log = dir.read().unwrap();
    let ids: Vec<&str> = log
        .sessions
        .iter()
        .map(|session| session.info.id.as_str())
        .collect();
    assert!(!ids.contains(&"00000004"), "no socket, no entries: {ids:?}");
    assert!(ids.contains(&"00000005"), "its socket is live: {ids:?}");
    assert!(
        ids.contains(&"00000006"),
        "a socket bound but not yet renamed is not gone: {ids:?}"
    );
}
