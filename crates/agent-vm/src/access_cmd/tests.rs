//! `agent-vm access` in process: selection, the window, the labels and the
//! footers.
//!
//! `run_in` takes its clock and its sinks, so a case drives the *whole* command —
//! including the exit status — against a real refusal log and real sockets, with
//! no `run_with_timeout` copy (#514) and no process boundary.

use std::path::Path;

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

/// No store: every row keeps slice 1's ACTION text.
fn empty_view() -> crate::allowances::ProjectView {
    crate::allowances::ProjectView::empty()
}

/// Run the command with no live sockets: only the log answers.
async fn run_logged(dir: &SessionsDir, args: Args) -> (i32, String, String) {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let status = run_in(
        Some(dir),
        &test_project(),
        &args,
        &empty_view(),
        NOW,
        &mut out,
        &mut err,
    )
    .await
    .expect("the command succeeds");
    (
        status,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

/// A captured project for the command's `--project` writes. It is a real
/// directory, so a store write lands in a tempdir that no assertion reads.
fn test_project() -> crate::project::ProjectDir {
    crate::project::ProjectDir::from_path_for_tests(&std::env::temp_dir())
        .expect("the temp directory is capturable")
}

const DEFAULT: Args = Args {
    command: None,
    session: None,
    all: false,
};

const ALL: Args = Args {
    command: None,
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

/// Every column that can carry text a forged log chose: the ID, the protocol, the
/// destination, the name source, and the site `reason()` names. Under the guard
/// only the host user writes these, but the documented upgrade path admits older
/// launchers that leave `.sessions` writable to their guests (AC5).
#[tokio::test]
async fn every_untrusted_cell_is_escaped() {
    const ESC: char = '\u{1b}';
    let root = tempfile::tempdir().unwrap();
    let dir = session_dir(root.path());
    let mut sneaky = entry(
        &format!("{ESC}[31mdead"),
        Destination::Host {
            protocol: format!("tcp{ESC}[0m"),
            name: format!("evil{ESC}[2J.example"),
            port: Some(443),
        },
        NOW - 1_000,
    );
    // A policy lock names the site it locked, so the reason column carries it.
    sneaky.key.kind = Kind::PolicyLock;
    sneaky.last_site = format!("tcp-syn{ESC}[31m");
    sneaky.name = Some(GuestName {
        name: format!("evil{ESC}[2J.example"),
        source: format!("sni{ESC}[0m"),
        truncated: false,
    });
    dir.write(&snapshot("0a1b2c3d", NOW - 5_000, vec![sneaky]), NOW)
        .unwrap();

    let (status, out, _) = run_logged(&dir, table_args()).await;
    assert_eq!(status, 0);
    assert!(
        !out.contains(ESC),
        "no raw escape reaches the terminal: {out:?}"
    );
    assert!(
        out.contains("\\x1b"),
        "the escaped spelling is printed: {out:?}"
    );
    assert!(
        out.contains("can't be allowed: built-in rule tcp-syn\\x1b[31m"),
        "{out:?}"
    );
    assert!(
        out.contains("tcp\\x1b[0m evil\\x1b[2J.example:443"),
        "{out:?}"
    );
    assert!(
        out.contains("SNI") || out.contains("sni\\x1b[0m"),
        "{out:?}"
    );

    // A session ID read from the log is validated, so a forged one does not even
    // reach the table.
    let raw = serde_json::json!({
        "v": 1,
        "evicted_sessions": 0,
        "sessions": [{
            "info": {"id": format!("{ESC}[31mdead"), "pid": 1, "started_ms": NOW, "socket": true},
            "rev": 1, "ended_ms": null, "heartbeat_ms": null,
            "suppressed": 0, "lost": 0, "gap": false, "entries": []
        }]
    });
    std::fs::write(
        dir.path().join("refusals.json"),
        serde_json::to_vec(&raw).unwrap(),
    )
    .unwrap();
    let (status, out, err) = run_logged(&dir, table_args()).await;
    assert_eq!(status, 0);
    assert!(!out.contains(ESC) && !err.contains(ESC), "{out:?} {err:?}");
    assert!(
        err.contains("could not be used"),
        "a log whose session ID is not one is reported, not shown: {err:?}"
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
        command: None,
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
            command: None,
            session: Some(bad.to_owned()),
            all: false,
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        assert!(
            run_in(
                Some(&dir),
                &test_project(),
                &args,
                &empty_view(),
                NOW,
                &mut out,
                &mut err
            )
            .await
            .is_err(),
            "{bad:?} is not a session ID"
        );
    }

    // A known ID shows that session alone, and shows it whole.
    let args = Args {
        command: None,
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
    let responding = start_live(root.path()).await;
    let hung_dir = dir.clone();
    let hung_id = SessionId::parse("00000009").unwrap();
    let listener = tokio::net::UnixListener::bind(hung_dir.socket_path(&hung_id)).unwrap();
    let hung = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
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
    // The hung session's row is labelled from the socket, not from the log: the
    // fixture already carries `aaaaaaa9`, so accepting "the entry is somewhere" or
    // "some row says not responding" let the label regress unseen.
    let hung_line = out
        .lines()
        .find(|line| line.starts_with("aaaaaaa9"))
        .unwrap_or_else(|| panic!("the hung session's entry has a row: {out}"));
    assert!(
        hung_line.contains("not responding"),
        "a bound socket that does not answer is `not responding`: {hung_line}"
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
    let status = run_in(
        None,
        &test_project(),
        &table_args(),
        &empty_view(),
        NOW,
        &mut out,
        &mut err,
    )
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
    let live = start_live(root.path()).await;
    let dir = session_dir(root.path());
    let (status, _, _) = run_logged(&dir, table_args()).await;
    assert_eq!(status, 0);
    // A session that has refused nothing has no row, but it is not an error and
    // it is not reported as absent by `--session`.
    let args = Args {
        command: None,
        session: Some(live.id().as_str().to_owned()),
        all: false,
    };
    let (status, out, err) = run_logged(&dir, args).await;
    assert_eq!(status, 0, "{err}");
    assert_eq!(out, "No refusals in the last 24 hours.\n");
    live.finish().await;
}

/// Start a session with a temporary store: no test may touch the real
/// `~/.config/agent-vm` (R13).
async fn start_live(root: &Path) -> crate::session_control::LiveSession {
    let session = project(root);
    let project = crate::project::ProjectDir::from_path_for_tests(root).expect("a project");
    let store = crate::allowances::StoreHandle::at_for_tests(&root.join("allowances-store"));
    let plan = crate::network::plan_for_tests(&[], false).live_policy_plan(None);
    crate::session_control::LiveSession::start(
        &session,
        crate::session_control::LiveSetup {
            project: &project,
            store,
            plan,
        },
    )
    .await
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
    let (status, out, _) = run_logged(&dir, table_args()).await;
    assert_eq!(status, 0);
    assert_eq!(out.matches("aaaaaaa1").count(), 1, "one row: {out}");
    assert!(out.contains("12 refusal(s) were not recorded"), "{out}");
    assert!(
        out.contains("3 refusal(s) to destinations beyond the per-session limit"),
        "{out}"
    );
    assert!(
        out.contains("some refusals were missed (count unknown)"),
        "{out}"
    );
    // None of the three became a row: one row and one header line.
    assert_eq!(out.lines().count(), 1 + 1 + 3, "{out}");
}

/// The counters are properties of a *session*, not of the rows the window happens
/// to show. A session whose only news is a `suppressed` count, or whose every
/// entry is older than the window, has nothing to put in the table — and used to
/// be dropped before the footers and the "K older" count were computed, so its
/// counters vanished and it was missing from the count.
#[tokio::test]
async fn a_session_outside_the_window_still_reports_its_footers_and_its_old_entries() {
    let root = tempfile::tempdir().unwrap();
    let dir = session_dir(root.path());
    // Nothing to show as a row: no entries at all, one suppressed counter. No
    // socket, but a fresh heartbeat, so the session is live and its record is
    // kept (an empty socketless session with a stale heartbeat is pruned).
    let mut counters_only = snapshot("00000002", NOW - 10_000, Vec::new());
    counters_only.info.socket = false;
    counters_only.heartbeat_ms = Some(NOW - 1_000);
    counters_only.suppressed = 5;
    dir.write(&counters_only, NOW).unwrap();
    // Nothing recent: every entry is older than the window, and there are two.
    let mut stale = snapshot(
        "00000003",
        NOW - WINDOW_MS - 200_000,
        vec![
            entry(
                "bbbbbbb1",
                address("203.0.113.11", 443),
                NOW - WINDOW_MS - 100_000,
            ),
            entry(
                "bbbbbbb2",
                address("203.0.113.12", 443),
                NOW - WINDOW_MS - 100_000,
            ),
        ],
    );
    stale.gap = true;
    dir.write(&stale, NOW).unwrap();

    let (status, out, _) = run_logged(&dir, table_args()).await;
    assert_eq!(status, 0);
    assert!(out.contains("No refusals in the last 24 hours."), "{out}");
    assert!(
        out.contains("session 00000002: 5 refusal(s) were not recorded"),
        "a counter with no row is still reported: {out}"
    );
    assert!(
        out.contains("session 00000003: some refusals were missed"),
        "{out}"
    );
    assert!(
        out.contains("--all shows the whole log (2 older)"),
        "a wholly old session is counted, not omitted: {out}"
    );
    assert!(!out.contains("bbbbbbb1"), "{out}");

    // ...and `--all` shows them.
    let (status, out, _) = run_logged(&dir, ALL).await;
    assert_eq!(status, 0);
    assert!(
        out.contains("bbbbbbb1") && out.contains("bbbbbbb2"),
        "{out}"
    );
}

/// The eviction footer needs a log that really evicted something: the count is the
/// writer's, not the reader's guess.
#[tokio::test]
async fn an_evicted_session_is_reported_in_the_footer() {
    let root = tempfile::tempdir().unwrap();
    let dir = session_dir(root.path());
    // Five sessions of `MAX_ENTRIES_PER_SESSION` entries: 2,560 against the
    // 2,048-entry bound, so a write has to evict.
    for index in 0..5u8 {
        let id = format!("0000000{index}");
        let mut snapshot = snapshot(&id, NOW - 20_000, Vec::new());
        // Ended, so the eviction is a record that is gone and is counted; a live
        // session's eviction is not (its owner writes it back).
        snapshot.ended_ms = Some(NOW - 10_000);
        snapshot.entries = (0..crate::refusal::MAX_ENTRIES_PER_SESSION)
            .map(|port| {
                entry(
                    &format!("{index}{:07x}", port % 0xf00000),
                    address("203.0.113.10", 1024 + port as u16),
                    NOW - 1_000,
                )
            })
            .collect();
        dir.write(&snapshot, NOW).unwrap();
    }
    let evicted = dir.read().unwrap().evicted_sessions;
    assert!(evicted > 0, "the log had to evict: {evicted}");

    let (status, out, _) = run_logged(&dir, table_args()).await;
    assert_eq!(status, 0);
    assert!(
        out.contains(&format!(
            "{evicted} session(s) were evicted from the refusal log to keep it bounded"
        )),
        "{out}"
    );
}

/// ADR-0064 decision 2 and USAGE's degradation table: a log a *newer* agent-vm
/// wrote is read, and one warning says so — the reader is otherwise unable to
/// tell rows this build decoded from records a later shape introduced and this
/// one dropped.
#[tokio::test]
async fn a_newer_version_log_is_read_with_one_warning_and_never_replaced() {
    let root = tempfile::tempdir().unwrap();
    let dir = session_dir(root.path());
    let mut snapshot = snapshot(
        "0a1b2c3d",
        NOW - 120_000,
        vec![entry("aaaaaaa1", address("203.0.113.10", 443), NOW - 1_000)],
    );
    snapshot.ended_ms = Some(NOW - 60_000);
    dir.write(&snapshot, NOW).unwrap();

    // Exactly what a later build's file looks like to this one: the version
    // alone is newer; the shape is this build's.
    let record = dir.record();
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&record).unwrap()).unwrap();
    value["v"] = serde_json::json!(99);
    let bytes = serde_json::to_vec(&value).unwrap();
    std::fs::write(&record, &bytes).unwrap();

    let (status, out, err) = run_logged(&dir, table_args()).await;
    assert_eq!(status, 0);
    assert!(out.contains("aaaaaaa1"), "the rows are still read: {out}");
    assert_eq!(
        err.matches("was written by a newer agent-vm").count(),
        1,
        "one warning, naming the file: {err:?}"
    );
    assert!(
        err.contains("refusals.json"),
        "the warning names the file: {err:?}"
    );
    assert_eq!(
        std::fs::read(&record).unwrap(),
        bytes,
        "reading a newer log never replaces it"
    );
}

// ---------------------------------------------------------------------------
// ADR-0065: the ACTION cell of a covered row
// ---------------------------------------------------------------------------

/// Run with a store in force.
async fn run_with(
    dir: &SessionsDir,
    allowances: &crate::allowances::ProjectView,
) -> (i32, String, String) {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let status = run_in(
        Some(dir),
        &test_project(),
        &DEFAULT,
        allowances,
        NOW,
        &mut out,
        &mut err,
    )
    .await
    .expect("the command succeeds");
    (
        status,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

/// A covered row names the record and says application is *not* confirmed; an
/// uncovered row keeps slice 1's text byte for byte.
#[tokio::test]
async fn covered_row_says_recorded_not_confirmed() {
    let root = tempfile::tempdir().unwrap();
    let dir = session_dir(root.path());
    // The address's own record covers it.
    let covered = entry("46d712fd", address("203.0.113.10", 443), NOW - 60_000);
    // A hostname's record covers it, through SNI.
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
    // The name was TLS-verified at this site, which is what makes an exact
    // record a claim `covers` will make.
    host.last_site = "tls-sni".into();
    // Nothing recorded names this one.
    let uncovered = entry("a00b2078", address("10.0.0.7", 8443), NOW - 240_000);
    dir.write(
        &snapshot("0a1b2c3d", NOW - 300_000, vec![covered, host, uncovered]),
        NOW,
    )
    .unwrap();

    let view = crate::allowances::ProjectView::for_tests(
        &["tcp://[203.0.113.10/32]:443", "cdn.example"],
        NOW - 60_000,
        None,
    );
    let (status, out, err) = run_with(&dir, &view).await;
    assert_eq!(status, 0);
    assert!(err.is_empty(), "{err}");
    let action = |id: &str| -> String {
        out.lines()
            .find(|line| line.starts_with(id))
            .unwrap_or_else(|| panic!("no row {id}: {out}"))
            .split("  ")
            .filter(|cell| !cell.is_empty())
            .last()
            .unwrap()
            .to_owned()
    };
    assert_eq!(
        action("46d712fd"),
        "recorded project allowance tcp://[203.0.113.10/32]:443 (2025-10-09 08:52Z); not confirmed for this session"
    );
    assert_eq!(
        action("88f5da9d"),
        "recorded project allowance cdn.example (2025-10-09 08:52Z); not confirmed for this session"
    );
    // Slice 1's text, unchanged, for the row no record names.
    assert_eq!(
        action("a00b2078"),
        "no grant in this version; relaunch with --allow-egress"
    );
    // The claim is about a file, never about the session: the old wording that
    // promised nothing must not survive on a covered row.
    assert!(!out.contains("; allowed"));
}

/// One store problem is one `warning:` line, and it changes no row: the table
/// is what the log says either way.
#[tokio::test]
async fn a_store_problem_is_one_warning() {
    let root = tempfile::tempdir().unwrap();
    let dir = session_dir(root.path());
    let row = entry("46d712fd", address("203.0.113.10", 443), NOW - 60_000);
    dir.write(&snapshot("0a1b2c3d", NOW - 300_000, vec![row]), NOW)
        .unwrap();

    let view = crate::allowances::ProjectView::for_tests(
        &[],
        NOW - 60_000,
        Some(
            "project allowances not applied: \"/home/a/.config/agent-vm/allowances.json\" could not be used (not a JSON document this build reads); this version does not repair it — move it aside to start over",
        ),
    );
    let (status, out, err) = run_with(&dir, &view).await;
    assert_eq!(status, 0, "{out}");
    assert_eq!(
        err.lines()
            .filter(|line| line.starts_with("warning: "))
            .count(),
        1,
        "{err}"
    );
    assert!(err.contains("allowances.json"), "{err}");
    // Not covered, so the row says what it said before the store existed.
    assert!(
        out.contains("no grant in this version; relaunch with --allow-egress"),
        "{out}"
    );
    assert!(!out.contains("recorded project allowance"), "{out}");
}

// ---------------------------------------------------------------------------
// Group C: `access allow|allowances|revoke` (PR 2)
// ---------------------------------------------------------------------------

use crate::allowances::ProjectView;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

fn live_project(root: &Path) -> crate::project::ProjectDir {
    crate::project::ProjectDir::from_path_for_tests(root).unwrap()
}

/// The view the CLI writes through: the same directory the live session's store
/// handle points at, so a `--project` write and a later read agree.
fn live_view(root: &Path) -> ProjectView {
    let project = live_project(root);
    ProjectView::at_dir_for_tests(
        &root.join("allowances-store"),
        &crate::image_pin::ProjectId::of(&project),
    )
}

/// A policy updater a test can fail or count, sharing one revision counter.
#[derive(Default)]
struct Updater {
    calls: AtomicUsize,
    fail: AtomicBool,
    unsupported: AtomicBool,
    seen: Mutex<Vec<microsandbox::NetworkPolicy>>,
}

impl Updater {
    fn handle(self: &Arc<Self>) -> crate::allowances::PolicyUpdater {
        let updater = Arc::clone(self);
        Arc::new(move |policy| {
            let updater = Arc::clone(&updater);
            Box::pin(async move {
                if updater.unsupported.load(Ordering::SeqCst) {
                    return Err(microsandbox::MicrosandboxError::Unsupported {
                        op: microsandbox::Operation::SandboxUpdateNetworkPolicy,
                        reason: microsandbox::UnsupportedReason::NotAvailable("test".to_owned()),
                    });
                }
                if updater.fail.load(Ordering::SeqCst) {
                    return Err(microsandbox::MicrosandboxError::ControlStateChanged);
                }
                updater.seen.lock().unwrap().push(policy);
                let previous = updater.calls.fetch_add(1, Ordering::SeqCst);
                Ok(previous as u64 + 2)
            })
        })
    }
}

/// Start a live session over `root`'s sessions directory, optionally attaching a
/// test updater (the launcher's `follow` does this after `create`).
async fn start_fixture(
    root: &Path,
    updater: Option<crate::allowances::PolicyUpdater>,
) -> crate::session_control::LiveSession {
    let session = project(root);
    let project = live_project(root);
    let store = crate::allowances::StoreHandle::at_for_tests(&root.join("allowances-store"));
    let plan = crate::network::plan_for_tests(&[], false).live_policy_plan(None);
    let live = crate::session_control::LiveSession::start(
        &session,
        crate::session_control::LiveSetup {
            project: &project,
            store,
            plan,
        },
    )
    .await;
    if let Some(updater) = updater {
        live.allowances().attach_updater(updater);
    }
    live
}

/// Ingest one `tcp-syn` denial and return its refusal ID.
fn ingest_denial(live: &crate::session_control::LiveSession) -> String {
    // The session refuses any record older than its own start, so the timestamp
    // is "now" rather than the command's injected clock.
    let now_ms = crate::refusal::feed::now_ms();
    let record = microsandbox::logs::NetworkLogRecord {
        v: 1,
        t: chrono::DateTime::from_timestamp_millis(now_ms).unwrap(),
        s: microsandbox::logs::LogSource::Network,
        event: microsandbox::logs::NetworkLogEvent::Refusal(microsandbox::logs::NetworkRefusal {
            site: microsandbox::logs::RefusalSite::TcpSyn,
            layer: microsandbox::logs::RefusalLayer::Tenant,
            protocol: microsandbox_types::Protocol::Tcp,
            dst_ip: Some("203.0.113.10".parse().unwrap()),
            dst_port: Some(443),
            name: None,
            name_source: microsandbox::logs::NameSource::Absent,
            revision: 1,
        }),
    };
    let feed = live.refusals().expect("a live refusal feed");
    let mut dirty = false;
    assert!(feed.ingest(&record, &mut dirty, now_ms));
    feed.snapshot().entries[0].id.clone()
}

async fn run_command(
    root: &Path,
    command: AccessSubcommand,
    view: &ProjectView,
) -> (i32, String, String) {
    let dir = session_dir(root);
    let args = Args {
        command: Some(command),
        session: None,
        all: false,
    };
    let mut out = Vec::new();
    let mut err = Vec::new();
    let status = run_in(
        Some(&dir),
        &live_project(root),
        &args,
        view,
        NOW,
        &mut out,
        &mut err,
    )
    .await
    .expect("the command succeeds");
    (
        status,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

fn allow(id: &str, project: bool) -> AccessSubcommand {
    AccessSubcommand::Allow(AllowArgs {
        id: id.to_owned(),
        project,
        session: None,
    })
}

/// C1: `allow` (session), `allow --project`, the table's applied row, the
/// listing, and `revoke`, all in process against one live session.
#[tokio::test]
async fn allow_session_and_project_end_to_end_in_process() {
    let root = tempfile::tempdir().unwrap();
    let updater = Arc::new(Updater::default());
    let live = start_fixture(root.path(), Some(updater.handle())).await;
    let id = ingest_denial(&live);
    let view = live_view(root.path());

    // A plain allow changes the session only.
    let (status, out, err) = run_command(root.path(), allow(&id, false), &view).await;
    assert_eq!(status, 0, "{out}{err}");
    assert!(out.contains("allowed tcp://[203.0.113.10/32]:443"), "{out}");
    assert!(out.contains("policy revision 2"), "{out}");
    // Nothing was recorded for the project.
    assert_eq!(view.allowances().len(), 0);

    // The row says applied, with the revision.
    let (_, table, _) = run_command(
        root.path(),
        AccessSubcommand::Allowances(AllowancesArgs { session: None }),
        &view,
    )
    .await;
    assert!(table.contains("session"), "{table}");
    assert!(table.contains("applied (rev 2)"), "{table}");

    // `--project` on the same destination records it, without another swap.
    let (status, out, err) = run_command(root.path(), allow(&id, true), &view).await;
    assert_eq!(status, 0, "{out}{err}");
    assert!(out.contains("and recorded for this project"), "{out}");
    assert_eq!(updater.calls.load(Ordering::SeqCst), 1, "no second swap");
    assert_eq!(
        live_view(root.path()).allowances().len(),
        1,
        "the project record was written"
    );

    // `access` renders the applied project allowance for this session.
    let (status, table, _) = run_logged(&session_dir(root.path()), table_args()).await;
    assert_eq!(status, 0);
    assert!(
        table.contains("applied project allowance tcp://[203.0.113.10/32]:443")
            && table.contains("allowed in this session (rev 2)"),
        "{table}"
    );

    // Revoke both: the destination leaves this session's policy.
    let (status, out, err) = run_command(
        root.path(),
        AccessSubcommand::Revoke(RevokeArgs {
            destination: "tcp://[203.0.113.10/32]:443".to_owned(),
            project: false,
            session_only: false,
            session: None,
        }),
        &view,
    )
    .await;
    assert_eq!(status, 0, "{out}{err}");
    assert!(out.contains("revoked tcp://[203.0.113.10/32]:443"), "{out}");
    assert_eq!(updater.calls.load(Ordering::SeqCst), 2);
    let (_, table, _) = run_logged(&session_dir(root.path()), table_args()).await;
    assert!(
        !table.contains("applied"),
        "the row is no longer applied: {table}"
    );
    live.finish().await;
}

/// C2: an older runtime records the allowance for the next launch and exits 0;
/// a store that cannot be written exits 1.
#[tokio::test]
async fn older_runtime_without_policy_update_yields_next_launch_grant_and_never_fails() {
    let root = tempfile::tempdir().unwrap();
    let updater = Arc::new(Updater::default());
    updater.unsupported.store(true, Ordering::SeqCst);
    let live = start_fixture(root.path(), Some(updater.handle())).await;
    let id = ingest_denial(&live);
    let view = live_view(root.path());
    let (status, out, err) = run_command(root.path(), allow(&id, true), &view).await;
    assert_eq!(status, 0, "{out}{err}");
    assert!(out.contains("recorded"), "{out}");
    assert_eq!(live_view(root.path()).allowances().len(), 1);
    live.finish().await;

    // A damaged store is a failure, not a silent no-op.
    let root = tempfile::tempdir().unwrap();
    let updater = Arc::new(Updater::default());
    updater.unsupported.store(true, Ordering::SeqCst);
    let live = start_fixture(root.path(), Some(updater.handle())).await;
    let id = ingest_denial(&live);
    let store_dir = root.path().join("allowances-store");
    std::fs::create_dir(&store_dir).unwrap();
    std::fs::write(store_dir.join("allowances.json"), b"not json").unwrap();
    let view = live_view(root.path());
    let (status, _, err) = run_command(root.path(), allow(&id, true), &view).await;
    assert_eq!(status, 1, "{err}");
    assert!(err.contains("could not be used"), "{err}");
    live.finish().await;
}

/// C3: a runtime failure writes no record; a store failure after the runtime
/// confirmed demotes to session scope and every later render says so.
#[tokio::test]
async fn project_grant_writes_no_record_when_live_session_cannot_confirm() {
    let root = tempfile::tempdir().unwrap();
    let updater = Arc::new(Updater::default());
    updater.fail.store(true, Ordering::SeqCst);
    let live = start_fixture(root.path(), Some(updater.handle())).await;
    let id = ingest_denial(&live);
    let view = live_view(root.path());
    let (status, _, err) = run_command(root.path(), allow(&id, true), &view).await;
    assert_eq!(status, 1, "{err}");
    assert!(
        err.contains("the runtime could not apply the change"),
        "{err}"
    );
    // The store itself is untouched: a stale view would agree with any bug, so
    // the file's absence is the assertion (and kills the mutant that records on
    // a runtime failure).
    assert!(
        !root
            .path()
            .join("allowances-store/allowances.json")
            .exists(),
        "no record was written"
    );
    assert_eq!(
        live_view(root.path()).allowances().len(),
        0,
        "the store was not written"
    );
    live.finish().await;
}

/// C3(d): the runtime applies it, the store cannot record it, and both `access`
/// and `access allowances` render the demoted session-only status afterwards.
#[tokio::test]
async fn applied_not_recorded_demotes_to_session_scope_across_subsequent_access_and_allowances_calls()
 {
    let root = tempfile::tempdir().unwrap();
    let updater = Arc::new(Updater::default());
    let live = start_fixture(root.path(), Some(updater.handle())).await;
    let id = ingest_denial(&live);
    // An authority directory another account could write: the writer refuses.
    use std::os::unix::fs::PermissionsExt as _;
    let store_dir = root.path().join("allowances-store");
    std::fs::create_dir(&store_dir).unwrap();
    std::fs::set_permissions(&store_dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    let view = live_view(root.path());

    let (status, _, err) = run_command(root.path(), allow(&id, true), &view).await;
    assert_eq!(status, 1, "{err}");
    assert!(
        err.contains("applied session allowance tcp://[203.0.113.10/32]:443")
            && err.contains("applied to this session only (rev 2), not recorded for the project:"),
        "{err}"
    );
    // Both later renders carry the demotion.
    let (_, table, _) = run_logged(&session_dir(root.path()), table_args()).await;
    assert!(
        table.contains("applied to this session only (rev 2), not recorded for the project:"),
        "{table}"
    );
    let (_, listing, _) = run_command(
        root.path(),
        AccessSubcommand::Allowances(AllowancesArgs { session: None }),
        &view,
    )
    .await;
    assert!(
        listing.contains("not recorded for the project") && listing.contains("rev 2"),
        "{listing}"
    );
    live.finish().await;
}

/// C4: an unconfirmed revoke deletes the project record, keeps memory, names the
/// session and the hard cut, and exits 1.
#[tokio::test]
async fn revoke_exits_nonzero_and_names_session_when_unconfirmed() {
    let root = tempfile::tempdir().unwrap();
    let updater = Arc::new(Updater::default());
    let live = start_fixture(root.path(), Some(updater.handle())).await;
    let id = ingest_denial(&live);
    let view = live_view(root.path());
    run_command(root.path(), allow(&id, true), &view).await;
    assert_eq!(live_view(root.path()).allowances().len(), 1);
    let before = live.allowances().snapshot();

    updater.fail.store(true, Ordering::SeqCst);
    let (status, _, err) = run_command(
        root.path(),
        AccessSubcommand::Revoke(RevokeArgs {
            destination: "tcp://[203.0.113.10/32]:443".to_owned(),
            project: false,
            session_only: false,
            session: None,
        }),
        &view,
    )
    .await;
    assert_eq!(status, 1, "{err}");
    assert!(err.contains("could not confirm revoking"), "{err}");
    assert!(
        err.contains("Stopping the session is the guaranteed hard cut"),
        "{err}"
    );
    assert_eq!(
        live_view(root.path()).allowances().len(),
        0,
        "the project record is still deleted"
    );
    assert_eq!(
        live.allowances().snapshot(),
        before,
        "unconfirmed removes no in-memory entry"
    );
    live.finish().await;
}

/// C5: siblings are named with their exact states before and after, and are not
/// changed.
#[tokio::test]
async fn siblings_are_named_before_and_after_with_exact_states() {
    let root = tempfile::tempdir().unwrap();
    let updater = Arc::new(Updater::default());
    let target = start_fixture(root.path(), Some(updater.handle())).await;
    let sibling = start_fixture(root.path(), Some(Arc::new(Updater::default()).handle())).await;
    let id = ingest_denial(&target);
    let view = live_view(root.path());

    let (status, out, err) = run_command(root.path(), allow(&id, false), &view).await;
    assert_eq!(status, 0, "{out}{err}");
    let sibling_id = sibling.id().as_str();
    for line in out.lines().filter(|line| line.contains("sibling sessions")) {
        assert!(line.contains(&format!("{sibling_id} (running)")), "{line}");
    }
    assert_eq!(
        out.matches("sibling sessions").count(),
        2,
        "named before and after: {out}"
    );
    // The sibling's own policy never changed.
    assert!(sibling.allowances().snapshot().session.is_empty());
    target.finish().await;
    sibling.finish().await;
}

/// C5 / B-S2 / C-M5: the sibling line names **all five** states, and an offline
/// revoke names its siblings too.
///
/// The five labels come from the same rule the table uses, so a `row.label`
/// replaced by a literal `"running"` has to fail here — that is the mutant this
/// test exists to kill. The offline half is the case the ticket names as the
/// reason target-only is acceptable: a project whose sessions have all ended.
#[tokio::test]
async fn siblings_are_named_in_every_state_and_offline_revoke_names_them() {
    let root = tempfile::tempdir().unwrap();
    let dir = session_dir(root.path());
    let now = NOW;
    // Five sessions, one per label, plus the target of the live change.
    let mut wanted = Vec::new();
    let mut cases: Vec<(String, String, SessionSnapshot)> = Vec::new();
    for (index, label) in [
        "running",
        "running (no control socket)",
        "not responding",
        "ended",
        "ended (unclean)",
    ]
    .into_iter()
    .enumerate()
    {
        let id = format!("0000000{index}");
        let entry_id = format!("aaaaaaa{index}");
        let mut snap = snapshot(
            &id,
            now - 10_000,
            vec![entry(&entry_id, address("203.0.113.10", 443), now - 5_000)],
        );
        match label {
            "running" => {}
            "running (no control socket)" => {
                snap.info.socket = false;
                snap.heartbeat_ms = Some(now - 1_000);
            }
            "not responding" => {
                // A bound socket that never answers: discovery dials it and its
                // `EXCHANGE_TIMEOUT` expires, which is the only way to produce
                // this label (see the hung listener below).
                snap.heartbeat_ms = Some(now - 1_000);
            }
            "ended" => snap.ended_ms = Some(now - 1_000),
            _ => snap.info.socket = false,
        }
        cases.push((id, label.to_owned(), snap));
        wanted.push(entry_id);
    }
    for (_, _, snap) in &cases {
        dir.write(snap, now).unwrap();
    }
    // The `not responding` session's socket accepts and never answers.
    let hung_id = SessionId::parse(&cases[2].0).unwrap();
    let listener = tokio::net::UnixListener::bind(dir.socket_path(&hung_id)).unwrap();
    let hung = tokio::spawn(async move {
        let mut streams = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            streams.push(stream);
        }
    });
    // The target for the live path is the one `running` session; its own row is
    // not a sibling, so four labels must appear beside the change.
    let view = empty_view();
    let args = AccessSubcommand::Allow(AllowArgs {
        id: wanted[0].clone(),
        project: false,
        session: None,
    });
    let (status, out, err) = run_command(root.path(), args, &view).await;
    assert!(status != 0, "the stale socket cannot confirm: {out}{err}");
    let before = out
        .lines()
        .find(|line| line.starts_with("sibling sessions (not targeted"))
        .unwrap_or_else(|| panic!("a before line: {out}{err}"));
    for (id, label) in cases.iter().map(|(id, label, _)| (id, label)) {
        if id == &cases[0].0 {
            assert!(
                !before.contains(&format!("{id} ({label})")),
                "the target is not a sibling"
            );
            continue;
        }
        assert!(
            before.contains(&format!("{id} ({label})")),
            "{label}: {before}"
        );
    }
    hung.abort();

    // Offline: every session has ended, so `revoke` has no target — and must
    // still name them.
    let root = tempfile::tempdir().unwrap();
    let dir = session_dir(root.path());
    let mut ended = snapshot(
        "0000000a",
        now - 10_000,
        vec![entry("aaaaaa0a", address("203.0.113.20", 443), now - 5_000)],
    );
    ended.ended_ms = Some(now - 1_000);
    dir.write(&ended, now).unwrap();
    let mut unclean = snapshot("0000000b", now - 10_000, Vec::new());
    unclean.info.socket = false;
    dir.write(&unclean, now).unwrap();
    let offline_view = live_view(root.path());
    let (status, out, err) = run_command(
        root.path(),
        AccessSubcommand::Revoke(RevokeArgs {
            destination: "tcp://[203.0.113.20/32]:443".to_owned(),
            project: false,
            session_only: false,
            session: None,
        }),
        &offline_view,
    )
    .await;
    assert_eq!(status, 0, "{out}{err}");
    assert!(
        out.contains("no session is active"),
        "the offline answer: {out}"
    );
    for line in out.lines().filter(|line| line.contains("sibling sessions")) {
        assert!(line.contains("0000000a (ended)"), "{line}");
        assert!(line.contains("0000000b (ended (unclean))"), "{line}");
    }
    assert_eq!(
        out.matches("sibling sessions").count(),
        2,
        "named before and after the offline change: {out}"
    );
}

/// B01: a revoke of a destination that only the launch's own authority admits is
/// reported as *still allowed*, never as "not in force", and claims no revision.
#[tokio::test]
async fn revoke_of_a_launch_configured_destination_is_not_reported_as_gone() {
    let root = tempfile::tempdir().unwrap();
    let session = project(root.path());
    let live_project = live_project(root.path());
    let store = crate::allowances::StoreHandle::at_for_tests(&root.path().join("allowances-store"));
    let plan = crate::network::plan_for_tests(&["tcp://[203.0.113.0/24]:443"], false)
        .live_policy_plan(None);
    let live = crate::session_control::LiveSession::start(
        &session,
        crate::session_control::LiveSetup {
            project: &live_project,
            store,
            plan,
        },
    )
    .await;
    let view = live_view(root.path());
    let (status, out, err) = run_command(
        root.path(),
        AccessSubcommand::Revoke(RevokeArgs {
            destination: "tcp://[203.0.113.0/24]:443".to_owned(),
            project: false,
            session_only: false,
            session: None,
        }),
        &view,
    )
    .await;
    assert_eq!(status, 0, "the honest answer is not a failure: {out}{err}");
    assert!(
        out.contains("is not a session or project allowance of session"),
        "{out}"
    );
    assert!(
        out.contains("still allowed by this launch's own --allow-egress or [network] authority"),
        "{out}"
    );
    assert!(!out.contains("not in force"), "the false claim: {out}");
    assert!(
        !out.contains("confirmed "),
        "no runtime call happened: {out}"
    );
    assert!(
        !out.contains("policy revision"),
        "no revision was observed: {out}"
    );
    live.finish().await;
}

/// C-M1: a demoted live project entry beside a store record keeps saying so.
///
/// This is the state the review's surviving mutation needs: the store read lists
/// the destination (so the record loop runs) *and* the session's live snapshot
/// carries the same destination with a demotion. Collapsing the match to
/// `(Some(_), None) => applied (rev N)` used to render it as a plain project
/// allowance and nothing failed.
#[tokio::test]
async fn allowances_keeps_a_demoted_live_project_entry_demoted() {
    let view = ProjectView::for_tests(&["tcp://[203.0.113.30/32]:443"], NOW - 60_000, None);
    let id = SessionId::parse("0000000c").unwrap();
    let snap = crate::allowances::SessionAllowancesSnapshot {
        session: Vec::new(),
        project: vec![crate::allowances::WireAllowance {
            destination: "tcp://[203.0.113.30/32]:443".to_owned(),
            granted_ms: NOW - 30_000,
            revision: Some(2),
            not_recorded_error: Some("the store is not trusted".to_owned()),
        }],
    };
    let discovery = crate::session_control::Discovery {
        live: Vec::new(),
        logged: Vec::new(),
        unresponsive: Vec::new(),
        live_allowances: vec![(id.clone(), snap)],
        evicted_sessions: 0,
        warnings: Vec::new(),
    };
    let mut out = Vec::new();
    let mut err = Vec::new();
    let status = run_allowances(
        &view,
        &discovery,
        &[],
        &AllowancesArgs { session: None },
        &mut out,
        &mut err,
    )
    .unwrap();
    assert_eq!(status, 0);
    let listing = String::from_utf8(out).unwrap();
    let row = listing
        .lines()
        .find(|line| line.starts_with("project"))
        .unwrap_or_else(|| panic!("a project row: {listing}"));
    assert!(
        row.contains("applied to this session only (rev 2), not recorded for the project: the store is not trusted"),
        "{row}"
    );
}

/// C6: a session allowance writes nothing anywhere.
#[tokio::test]
async fn session_allowance_never_touches_disk_or_another_project() {
    let root = tempfile::tempdir().unwrap();
    let updater = Arc::new(Updater::default());
    let live = start_fixture(root.path(), Some(updater.handle())).await;
    let id = ingest_denial(&live);
    let view = live_view(root.path());
    let (status, out, err) = run_command(root.path(), allow(&id, false), &view).await;
    assert_eq!(status, 0, "{out}{err}");
    assert!(
        !root.path().join("allowances-store").exists(),
        "a session grant creates no authority directory"
    );
    assert!(view.allowances().len() == 0);
    let refusals = std::fs::read_to_string(root.path().join("ab12cd34ef56.sessions/refusals.json"))
        .unwrap_or_default();
    assert!(
        !refusals.contains("203.0.113.10/32"),
        "the in-memory grant is not persisted in the refusal log"
    );
    live.finish().await;
}

/// AC9: the listing unions the store and every live session, one row per
/// `(project allowance, active session)`, and names a session that cannot answer.
#[tokio::test]
async fn allowances_subcommand_unions_store_and_live_sessions_and_names_unresponsive() {
    let root = tempfile::tempdir().unwrap();
    let updater = Arc::new(Updater::default());
    let target = start_fixture(root.path(), Some(updater.handle())).await;
    let other = start_fixture(root.path(), Some(Arc::new(Updater::default()).handle())).await;
    let id = ingest_denial(&target);
    let view = live_view(root.path());
    let (status, out, err) = run_command(root.path(), allow(&id, true), &view).await;
    assert_eq!(status, 0, "{out}{err}");
    // Re-read the store: a view is one read, and the grant just wrote it.
    let view = live_view(root.path());

    // A bound socket that holds its connections is `not responding`.
    let hung_id = SessionId::parse("00000009").unwrap();
    let dir = session_dir(root.path());
    let listener = tokio::net::UnixListener::bind(dir.socket_path(&hung_id)).unwrap();
    let held = tokio::spawn(async move {
        let mut streams = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            streams.push(stream);
        }
    });

    let (status, listing, err) = run_command(
        root.path(),
        AccessSubcommand::Allowances(AllowancesArgs { session: None }),
        &view,
    )
    .await;
    assert_eq!(status, 0, "{listing}{err}");
    let target_id = target.id().as_str().to_owned();
    let other_id = other.id().as_str().to_owned();
    let applied = listing
        .lines()
        .find(|line| line.starts_with("project") && line.contains(&target_id))
        .unwrap_or_else(|| panic!("a project row for the target: {listing}"));
    assert!(applied.contains("applied (rev 2)"), "{applied}");
    let pending = listing
        .lines()
        .find(|line| line.starts_with("project") && line.contains(&other_id))
        .unwrap_or_else(|| panic!("a project row for the sibling: {listing}"));
    assert!(pending.contains("not in force until relaunch"), "{pending}");
    assert!(
        err.contains("00000009") && err.contains("not responding"),
        "{err}"
    );
    // AC9's "and in STATUS": the session that could not be asked gets its own row
    // whose STATUS names it, so "not in force" (a session that answered) and "not
    // asked" never share a cell (D1).
    let unasked = listing
        .lines()
        .find(|line| {
            line.starts_with("project") && line.contains("00000009") && line.contains("not shown")
        })
        .unwrap_or_else(|| panic!("the unresponsive session in STATUS: {listing}"));
    assert!(
        unasked.contains("session 00000009 not responding"),
        "{unasked}"
    );
    assert!(
        !pending.contains("00000009"),
        "an answered session's row must not name another session's silence: {pending}"
    );
    held.abort();
    target.finish().await;
    other.finish().await;
}

/// D1, structurally: `--session X` lists X and nobody else.
///
/// The verifier's probe pins the borrowed-suffix half (X's row must not name a
/// session it never asked). This pins the other half: now that a session that
/// could not be asked gets its own row, the filter has to exclude *that row too*,
/// or a listing scoped to X still names Y — and the row is where the leak is
/// observable once the suffix is gone.
#[tokio::test]
async fn allowances_session_filter_lists_only_the_named_session() {
    let root = tempfile::tempdir().unwrap();
    let target = start_fixture(root.path(), Some(Arc::new(Updater::default()).handle())).await;
    let id = ingest_denial(&target);
    let view = live_view(root.path());
    let (status, out, err) = run_command(root.path(), allow(&id, true), &view).await;
    assert_eq!(status, 0, "{out}{err}");
    let view = live_view(root.path());
    let target_id = target.id().as_str().to_owned();

    // A second session that binds a socket and never answers.
    let hung_id = SessionId::parse("00000009").unwrap();
    let dir = session_dir(root.path());
    let listener = tokio::net::UnixListener::bind(dir.socket_path(&hung_id)).unwrap();
    let held = tokio::spawn(async move {
        let mut streams = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            streams.push(stream);
        }
    });

    let (status, listing, err) = run_command(
        root.path(),
        AccessSubcommand::Allowances(AllowancesArgs {
            session: Some(target_id.clone()),
        }),
        &view,
    )
    .await;
    assert_eq!(status, 0, "{listing}{err}");
    assert!(listing.contains(&target_id), "{listing}");
    assert!(
        !listing.contains("00000009"),
        "a session the filter excluded must not appear in the listing: {listing}"
    );
    // The warning still names it: the filter narrows the table, not the report of
    // what could not be asked.
    assert!(
        err.contains("00000009") && err.contains("not responding"),
        "{err}"
    );

    held.abort();
    target.finish().await;
}

/// AC2 (offline half): an ended session records a `--project` grant for the next
/// launch and refuses a session-only one.
#[tokio::test]
async fn allow_on_ended_session_records_project_and_refuses_session_only() {
    let root = tempfile::tempdir().unwrap();
    let dir = session_dir(root.path());
    let mut ended = snapshot(
        "00000001",
        NOW - 10_000,
        vec![entry("aaaaaaa1", address("203.0.113.10", 443), NOW - 5_000)],
    );
    ended.info.socket = false;
    ended.ended_ms = Some(NOW - 4_000);
    dir.write(&ended, NOW).unwrap();
    let view = live_view(root.path());

    // Session-only cannot be recorded: the session that asked is gone.
    let (status, out, err) = run_command(root.path(), allow("aaaaaaa1", false), &view).await;
    assert_eq!(status, 1, "{out}{err}");
    assert!(err.contains("has ended"), "{err}");
    assert_eq!(live_view(root.path()).allowances().len(), 0);

    // `--project` records it for the next launch.
    let (status, out, err) = run_command(root.path(), allow("aaaaaaa1", true), &view).await;
    assert_eq!(status, 0, "{out}{err}");
    assert!(out.contains("recorded project allowance"), "{out}");
    assert_eq!(
        live_view(root.path()).allowances().len(),
        1,
        "the record is what the next launch reads"
    );
}
