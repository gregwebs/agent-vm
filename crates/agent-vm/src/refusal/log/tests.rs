//! The store's own rules: serialization, eviction, damage and reservation.
//!
//! `flock` is per open file description, so two threads that open the lock file
//! separately contend exactly as two processes do — which is what makes the
//! concurrency row here evidence about the production shape.

use super::*;
use crate::refusal::{Kind, Destination, EntryKey, RefusalEntry, SessionInfo};

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
        },
        layer: "tenant".into(),
        last_site: key.to_owned(),
        last_ip: Some("203.0.113.10".parse().unwrap()),
        name: None,
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
            let own = filled(session(&format!("0000000{writer}", ), true), 1, NOW);
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
    // older live session is the next to go.
    let mut log = Log::new(0, Vec::new());
    for (text, at) in [("0000000a", NOW - 9_000), ("0000000b", NOW - 2_000)] {
        let mut live = filled(session(text, true), 1_100, at);
        live.info.started_ms = at;
        log.sessions.push(live);
    }
    assert_eq!(log.evict("0000000b"), 1);
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
        !log.sessions.iter().any(|s| s.info.id.as_str() == "0000000a"),
        "the older live session was evicted to make room"
    );
    assert!(log.evicted_sessions > 0);

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

#[test]
fn sid_reservation_redraws_on_log_and_socket_collision() {
    let (_root, dir) = dir();
    let mut drawn = Vec::new();
    let reserved = dir
        .reserve(NOW, 42, true, |id| {
            drawn.push(id.as_str().to_owned());
            Ok::<_, std::io::Error>(())
        })
        .unwrap()
        .expect("the lock was free");
    assert_eq!(drawn.len(), 1);
    assert_eq!(reserved.snapshot.info.id.as_str(), drawn[0]);
    assert_eq!(
        dir.read()
            .unwrap()
            .sessions
            .first()
            .map(|s| s.info.id.as_str()),
        Some(drawn[0].as_str())
    );

    // A second reservation never reuses the first's ID, even though the log
    // already holds it.
    let mut second = Vec::new();
    dir.reserve(NOW, 43, true, |id| {
        second.push(id.as_str().to_owned());
        Ok::<_, std::io::Error>(())
    })
    .unwrap()
    .unwrap();
    assert_ne!(second[0], drawn[0]);

    // A socket name already on disk forces a redraw.
    let taken = dir.socket_path(&sid("deadbeef"));
    std::fs::write(&taken, "").unwrap();
    let mut attempts = 0;
    let reserved = dir
        .reserve(NOW, 44, true, |id| {
            attempts += 1;
            if attempts == 1 {
                assert!(id.as_str().len() == 8);
                return Err(std::io::ErrorKind::AddrInUse.into());
            }
            Ok::<_, std::io::Error>(())
        })
        .unwrap()
        .expect("a redraw found a free name");
    assert_eq!(attempts, 2);
    assert_eq!(
        dir.read().unwrap().sessions.len(),
        3,
        "each reservation wrote one session"
    );
    assert!(!reserved.snapshot.info.id.as_str().is_empty());
}

#[test]
fn a_damaged_log_is_set_aside() {
    let (_root, dir) = dir();
    std::fs::write(dir.record(), b"{not json").unwrap();
    assert!(dir.read().unwrap().sessions.is_empty());
    // Reading does not repair; writing sets the damaged file aside and starts over.
    let own = filled(session("00000001", true), 1, NOW);
    dir.write(&own, NOW).unwrap();
    assert!(dir.path().join("refusals.json.damaged").exists());
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
    let own = filled(session("00000001", true), 1, NOW);
    let report = dir.write(&own, NOW).unwrap();
    assert!(report.warning.is_some(), "one warning, once");
    assert_eq!(report.evicted_sessions, 7);
    assert_eq!(std::fs::read(dir.record()).unwrap(), bytes);
    assert!(
        dir.reserve(NOW, 1, true, |_| Ok::<_, std::io::Error>(()))
            .unwrap()
            .is_none(),
        "a newer log is not reserved into either"
    );
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
    assert!(SessionsDir::open(&link).unwrap_err().to_string().contains("not a directory"));
    assert!(SessionsDir::open(&root.path().join("absent.sessions")).unwrap().is_none());
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
        log.sessions.iter().all(|s| s.info.id.as_str() != "00000001"),
        "an idle session past retention is pruned"
    );
    assert!(log.sessions.iter().any(|s| s.info.id.as_str() == "00000002"));

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
}
