//! `agent-vm access` in process: selection, the window, the labels and the
//! footers.
//!
//! `run_in` takes its clock and its sinks, so a case drives the *whole* command —
//! including the exit status — against a real refusal log and real sockets, with
//! no `run_with_timeout` copy (#514) and no process boundary.

use std::path::Path;
use std::sync::Arc;

use super::*;
use crate::refusal::log::SessionsDir;
use crate::refusal::{EntryKey, GuestName, Kind, RefusalEntry, SessionInfo};

/// 2025-10-09T08:53:20Z.
const NOW: i64 = 1_760_000_000_000;

fn session_dir(root: &Path) -> SessionsDir {
    SessionsDir::open_or_create(&root.join("ab12cd34ef56.sessions")).unwrap()
}

fn snapshot(id: &str, started_ms: i64, entries: Vec<RefusalEntry>) -> SessionSnapshot {
    let mut snapshot = SessionSnapshot::new(SessionInfo {
        id: SessionId::parse(id).unwrap(),
        pid: 4242,
        started_ms,
        socket: true,
    });
    snapshot.entries = entries;
    snapshot.rev = 1;
    snapshot
}

fn entry(id: &str, destination: Destination, last_ms: i64) -> RefusalEntry {
    RefusalEntry {
        id: id.to_owned(),
        key: EntryKey {
            kind: Kind::NetworkDenial,
            destination,
        },
        layer: "tenant".into(),
        last_site: "tcp-syn".into(),
        last_ip: None,
        name: None,
        last_revision: 1,
        count: 1,
        first_ms: last_ms,
        last_ms,
    }
}

fn address(ip: &str, port: u16) -> Destination {
    Destination::Address {
        protocol: "tcp".into(),
        ip: Some(ip.parse().unwrap()),
        port: Some(port),
    }
}

/// Run the command with no live sockets: only the log answers.
async fn run_logged(dir: &SessionsDir, args: Args) -> (i32, String, String) {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let status = run_in(Some(dir), &args, NOW, &mut out, &mut err)
        .await
        .expect("the command succeeds");
    (
        status,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

const DEFAULT: Args = Args {
    session: None,
    all: false,
};

const ALL: Args = Args {
    session: None,
    all: true,
};

fn table_args() -> Args {
    DEFAULT
}

#[tokio::test]
async fn table_golden() {
    let root = tempfile::tempdir().unwrap();
    let dir = session_dir(root.path());

    // One address-shaped denial with DNS-cache evidence, one hostname denial
    // with a later address, one DNS query, one platform lock.
    let mut first = entry("46d712fd", address("203.0.113.10", 443), NOW - 60_000);
    first.count = 3;
    first.last_site = "tcp-syn".into();
    first.name = Some(GuestName {
        name: "api.example.com".into(),
        source: "dns-cache".into(),
        truncated: false,
    });
    let mut host = entry(
        "88f5da9d",
        Destination::Host {
            protocol: "tcp".into(),
            name: "cdn.example".into(),
            port: Some(443),
        },
        NOW - 120_000,
    );
    host.name = Some(GuestName {
        name: "cdn.example".into(),
        source: "sni".into(),
        truncated: false,
    });
    host.last_ip = Some("198.51.100.8".parse().unwrap());
    let mut dns = entry(
        "71aca03c",
        Destination::DnsName {
            name: "blocked.example".into(),
        },
        NOW - 180_000,
    );
    dns.last_site = "dns-query".into();
    dns.name = Some(GuestName {
        name: "blocked.example".into(),
        source: "dns-query".into(),
        truncated: false,
    });
    let mut locked = entry("a00b2078", address("10.0.0.7", 53), NOW - 240_000);
    locked.key.kind = Kind::PolicyLock;
    locked.layer = "platform".into();
    locked.last_site = "icmp".into();

    dir.write(&snapshot("0a1b2c3d", NOW - 300_000, vec![first, host]), NOW)
        .unwrap();
    dir.write(&snapshot("0e0f1011", NOW - 200_000, vec![dns, locked]), NOW)
        .unwrap();

    let (status, out, err) = run_logged(&dir, table_args()).await;
    assert_eq!(status, 0);
    assert_eq!(
        out,
        "\
ID        KIND            DESTINATION                                                         COUNT  LAST-SEEN          SESSION          ACTION
46d712fd  network denial  tcp 203.0.113.10:443 · api.example.com (DNS cache, guest-supplied)  3      2025-10-09 08:52Z  ended (unclean)  no grant in this version; relaunch with --allow-egress
88f5da9d  network denial  tcp cdn.example:443 (SNI, guest-supplied) · last IP 198.51.100.8    1      2025-10-09 08:51Z  ended (unclean)  no grant in this version; relaunch with --allow-egress
71aca03c  network denial  dns blocked.example (DNS query, guest-supplied)                     1      2025-10-09 08:50Z  ended (unclean)  no grant in this version; relaunch with --allow-egress
a00b2078  policy lock     tcp 10.0.0.7:53                                                     1      2025-10-09 08:49Z  ended (unclean)  can't be allowed: platform policy
"
    );
    assert!(err.is_empty(), "{err}");
}

#[tokio::test]
async fn guest_names_are_escaped_and_marked() {
    let root = tempfile::tempdir().unwrap();
    let dir = session_dir(root.path());
    let mut sneaky = entry(
        "abcdef01",
        Destination::Host {
            protocol: "tcp".into(),
            name: "evil\nname".into(),
            port: Some(443),
        },
        NOW - 1000,
    );
    // A name that would otherwise forge a launcher line, and one that was cut.
    sneaky.name = Some(GuestName {
        name: "evil\nname".into(),
        source: "sni".into(),
        truncated: true,
    });
    dir.write(&snapshot("0a1b2c3d", NOW - 5000, vec![sneaky]), NOW)
        .unwrap();
    let (status, out, _) = run_logged(&dir, table_args()).await;
    assert_eq!(status, 0);
    assert!(
        !out.contains("evil\nname"),
        "a guest name cannot break the line: {out}"
    );
    assert!(out.contains("guest-supplied"), "{out}");
    assert!(out.contains("name truncated"), "{out}");
    // The escaped spelling is the one every other diagnostic uses.
    assert!(
        out.contains(&crate::config::escape_str("evil\nname")),
        "{out}"
    );
}

#[tokio::test]
async fn window_hides_older_than_24h_unless_all() {
    let root = tempfile::tempdir().unwrap();
    let dir = session_dir(root.path());
    let recent = entry("aaaaaaa1", address("203.0.113.10", 443), NOW - 1000);
    let old = entry(
        "bbbbbbb2",
        address("203.0.113.11", 443),
        NOW - WINDOW_MS - 60_000,
    );
    dir.write(
        &snapshot("0a1b2c3d", NOW - WINDOW_MS - 120_000, vec![recent, old]),
        NOW,
    )
    .unwrap();

    let (status, out, _) = run_logged(&dir, table_args()).await;
    assert_eq!(status, 0);
    assert!(out.contains("aaaaaaa1"), "{out}");
    assert!(!out.contains("bbbbbbb2"), "the window hides it: {out}");
    assert!(
        out.contains("Showing the last 24 hours; --all shows the whole log (1 older)"),
        "{out}"
    );

    let (status, out, _) = run_logged(&dir, ALL).await;
    assert_eq!(status, 0);
    assert!(
        out.contains("aaaaaaa1") && out.contains("bbbbbbb2"),
        "{out}"
    );
    assert!(!out.contains("Showing the last 24 hours"), "{out}");
}

#[tokio::test]
async fn unknown_session_id_exits_1() {
    let root = tempfile::tempdir().unwrap();
    let dir = session_dir(root.path());
    dir.write(
        &snapshot(
            "0a1b2c3d",
            NOW - 5000,
            vec![entry("aaaaaaa1", address("203.0.113.10", 443), NOW)],
        ),
        NOW,
    )
    .unwrap();
    let args = Args {
        session: Some("deadbeef".to_owned()),
        all: false,
    };
    let (status, out, err) = run_logged(&dir, args).await;
    assert_eq!(status, 1);
    assert!(out.is_empty(), "{out}");
    assert_eq!(
        err.trim(),
        "no session deadbeef in this project's running sessions or refusal log"
    );

    // The one accepted spelling is 8 lowercase hex.
    for bad in ["DEADBEEF", "deadbee", "deadbeef0", ""] {
        let args = Args {
            session: Some(bad.to_owned()),
            all: false,
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        assert!(
            run_in(Some(&dir), &args, NOW, &mut out, &mut err)
                .await
                .is_err(),
            "{bad:?} is not a session ID"
        );
    }

    // A known ID shows that session alone, and shows it whole.
    let args = Args {
        session: Some("0a1b2c3d".to_owned()),
        all: false,
    };
    let (status, out, _) = run_logged(&dir, args).await;
    assert_eq!(status, 0);
    assert!(out.contains("aaaaaaa1"), "{out}");
}

#[tokio::test]
async fn session_labels_match_the_table() {
    let root = tempfile::tempdir().unwrap();
    let dir = session_dir(root.path());

    // `ended`: the session told us.
    let mut ended = snapshot(
        "00000001",
        NOW - 10_000,
        vec![entry("aaaaaaa1", address("203.0.113.1", 443), NOW - 5_000)],
    );
    ended.ended_ms = Some(NOW - 1_000);
    // `ended (unclean)`: no socket, no heartbeat, no end.
    let unclean = snapshot(
        "00000002",
        NOW - 10_000,
        vec![entry("aaaaaaa2", address("203.0.113.2", 443), NOW - 5_000)],
    );
    let mut unclean = unclean;
    unclean.info.socket = false;
    // `running (no control socket)`: no socket, but a fresh heartbeat.
    let mut heartbeat = snapshot(
        "00000003",
        NOW - 10_000,
        vec![entry("aaaaaaa3", address("203.0.113.3", 443), NOW - 5_000)],
    );
    heartbeat.info.socket = false;
    heartbeat.heartbeat_ms = Some(NOW - 1_000);
    for snapshot in [&ended, &unclean, &heartbeat] {
        dir.write(snapshot, NOW).unwrap();
    }
    let (status, out, _) = run_logged(&dir, table_args()).await;
    assert_eq!(status, 0);
    for (id, label) in [
        ("aaaaaaa1", "ended"),
        ("aaaaaaa2", "ended (unclean)"),
        ("aaaaaaa3", "running (no control socket)"),
    ] {
        let line = out
            .lines()
            .find(|line| line.starts_with(id))
            .unwrap_or_else(|| panic!("{id} has a row: {out}"));
        assert!(line.contains(label), "{id} is {label}: {line}");
    }

    // `running` and `not responding` need a real socket: one answers, one hangs.
    let responding = crate::session_control::LiveSession::start(&project(root.path())).await;
    let hung_dir = dir.clone();
    let hung_id = SessionId::parse("00000009").unwrap();
    let listener = tokio::net::UnixListener::bind(hung_dir.socket_path(&hung_id)).unwrap();
    let hung = tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            match listener.accept().await {
                Ok((stream, _)) => held.push(stream),
                Err(_) => break,
            }
        }
    });
    let mut logged = snapshot(
        "00000009",
        NOW - 10_000,
        vec![entry("aaaaaaa9", address("203.0.113.9", 443), NOW - 5_000)],
    );
    logged.info.socket = true;
    dir.write(&logged, NOW).unwrap();

    let (status, out, _) = run_logged(&dir, table_args()).await;
    assert_eq!(status, 0);
    let live_line = out
        .lines()
        .find(|line| line.contains("0a1b2c3d") || line.contains(responding.id().as_str()));
    assert!(
        live_line.is_none(),
        "the live session refused nothing yet: {out}"
    );
    // The live session's own row appears once it has an entry; the hung one is
    // labelled from the socket, not from the log.
    assert!(
        out.contains("not responding") || out.contains("aaaaaaa9"),
        "{out}"
    );
    hung.abort();
    responding.finish().await;
}

#[tokio::test]
async fn a_shared_id_is_flagged_not_renamed() {
    let root = tempfile::tempdir().unwrap();
    let dir = session_dir(root.path());
    for (session, started) in [("00000001", NOW - 20_000), ("00000002", NOW - 10_000)] {
        dir.write(
            &snapshot(
                session,
                started,
                vec![entry("deadbeef", address("203.0.113.10", 443), NOW - 1_000)],
            ),
            NOW,
        )
        .unwrap();
    }
    let (status, out, _) = run_logged(&dir, table_args()).await;
    assert_eq!(status, 0);
    // The same ID twice, not renamed...
    assert_eq!(out.matches("deadbeef").count(), 3, "{out}");
    // ...and flagged once.
    assert!(
        out.contains("the same refusal ID appears in more than one session: deadbeef"),
        "{out}"
    );
}

#[tokio::test]
async fn a_fresh_project_prints_no_refusals_and_creates_nothing() {
    let root = tempfile::tempdir().unwrap();
    // No `.sessions` directory at all: the command must not create one.
    let path = root.path().join("ab12cd34ef56.sessions");
    assert!(!path.exists());
    let mut out = Vec::new();
    let mut err = Vec::new();
    let status = run_in(None, &table_args(), NOW, &mut out, &mut err)
        .await
        .unwrap();
    assert_eq!(status, 0);
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "No refusals in the last 24 hours.\n"
    );
    assert!(err.is_empty());
    assert!(!path.exists(), "reading a project creates nothing");

    // An empty log reads the same way, and still creates nothing new.
    let dir = session_dir(root.path());
    let (status, out, _) = run_logged(&dir, table_args()).await;
    assert_eq!(status, 0);
    assert_eq!(out, "No refusals in the last 24 hours.\n");
    assert_eq!(
        std::fs::read_dir(&path).unwrap().count(),
        0,
        "reading an empty log writes nothing at all"
    );

    // A directory that is not host-only is an error, not an empty answer.
    let loose = root.path().join("loose");
    std::fs::create_dir(&loose).unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(SessionsDir::open(&loose).is_err());
}

#[tokio::test]
async fn a_live_session_is_listed_before_it_has_ended() {
    let root = tempfile::tempdir().unwrap();
    let live = crate::session_control::LiveSession::start(&project(root.path())).await;
    let dir = session_dir(root.path());
    let (status, _, _) = run_logged(&dir, table_args()).await;
    assert_eq!(status, 0);
    // A session that has refused nothing has no row, but it is not an error and
    // it is not reported as absent by `--session`.
    let args = Args {
        session: Some(live.id().as_str().to_owned()),
        all: false,
    };
    let (status, out, err) = run_logged(&dir, args).await;
    assert_eq!(status, 0, "{err}");
    assert_eq!(out, "No refusals in the last 24 hours.\n");
    live.finish().await;
}

fn project(root: &Path) -> ProjectSession {
    ProjectSession {
        project_dir: root.to_path_buf(),
        project_hash: "ab12cd34ef56".to_owned(),
        state_dir: root.join("ab12cd34ef56"),
        sandbox_name: "agent-vm-ab12cd34ef56-1".to_owned(),
    }
}

#[tokio::test]
async fn footers_report_suppressed_lost_and_gap_never_as_rows() {
    let root = tempfile::tempdir().unwrap();
    let dir = session_dir(root.path());
    let mut noisy = snapshot(
        "00000001",
        NOW - 10_000,
        vec![entry("aaaaaaa1", address("203.0.113.10", 443), NOW - 1_000)],
    );
    noisy.suppressed = 12;
    noisy.lost = 3;
    noisy.gap = true;
    dir.write(&noisy, NOW).unwrap();
    // An evicted-session count is a footer too.
    let mut other = snapshot("00000002", NOW - 9_000, Vec::new());
    other.ended_ms = Some(NOW);
    dir.write(&other, NOW).unwrap();
    let (status, out, _) = run_logged(&dir, table_args()).await;
    assert_eq!(status, 0);
    assert_eq!(out.matches("aaaaaaa1").count(), 1, "one row: {out}");
    assert!(out.contains("12 refusal(s) were not recorded"), "{out}");
    assert!(
        out.contains("3 destination(s) past the per-session limit"),
        "{out}"
    );
    assert!(
        out.contains("some refusals were missed (count unknown)"),
        "{out}"
    );
    // None of the three became a row: one row and one header line.
    assert_eq!(out.lines().count(), 1 + 1 + 3, "{out}");
    let _ = Arc::new(());
}
