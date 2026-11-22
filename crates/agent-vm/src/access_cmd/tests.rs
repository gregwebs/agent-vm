//! `agent-vm access` in process: selection, the window, the labels and the
//! footers.
//!
//! `run_in` takes its clock and its sinks, so a case drives the *whole* command —
//! including the exit status — against a real refusal log and real sockets, with
//! no `run_with_timeout` copy (#514) and no process boundary.

use std::path::Path;

use super::*;
use crate::refusal::log::SessionsDir;
use crate::refusal::{Destination, EntryKey, GuestName, Kind, RefusalEntry, SessionInfo};

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
            credential: None,
        },
        layer: "tenant".into(),
        last_site: "tcp-syn".into(),
        last_ip: None,
        name: None,
        last_location: None,
        last_reason: None,
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
ID        KIND            DESTINATION                                                         COUNT  FIRST-SEEN         LAST-SEEN          SESSION          ACTION
46d712fd  network denial  tcp 203.0.113.10:443 · api.example.com (DNS cache, guest-supplied)  3      2025-10-09 08:52Z  2025-10-09 08:52Z  ended (unclean)  session ended; run `agent-vm access allow 46d712fd --session 0a1b2c3d --project`
88f5da9d  network denial  tcp cdn.example:443 (SNI, guest-supplied) · last IP 198.51.100.8    1      2025-10-09 08:51Z  2025-10-09 08:51Z  ended (unclean)  this hostname was seen over plain HTTP, so an allowance cannot name a port for it without allowing every name on that port
71aca03c  network denial  dns blocked.example (DNS query, guest-supplied)                     1      2025-10-09 08:50Z  2025-10-09 08:50Z  ended (unclean)  session ended; run `agent-vm access allow 71aca03c --session 0e0f1011 --project`
a00b2078  policy lock     tcp 10.0.0.7:53                                                     1      2025-10-09 08:49Z  2025-10-09 08:49Z  ended (unclean)  can't be allowed: platform policy
"
    );
    assert!(err.is_empty(), "{err}");
}

/// A credential-refusal entry: the three facts the runtime stated, and `None`
/// wherever it stated nothing.
fn credential_entry(
    id: &str,
    destination: Destination,
    last_ms: i64,
    credential: Option<&str>,
    location: Option<&str>,
    reason: Option<&str>,
) -> RefusalEntry {
    RefusalEntry {
        key: EntryKey {
            kind: Kind::CredentialRefusal,
            destination,
            credential: credential.map(str::to_owned),
        },
        last_site: "secret-violation".into(),
        last_location: location.map(str::to_owned),
        last_reason: reason.map(str::to_owned),
        ..entry(id, address("203.0.113.10", 443), last_ms)
    }
}

/// What a reader with a hidden 403 needs: which credential was refused, where it
/// was sent, and why its secret could not serve it.
#[tokio::test]
async fn credential_refusal_rows_state_the_credential_the_location_and_the_reason() {
    let root = tempfile::tempdir().unwrap();
    let dir = session_dir(root.path());
    let entries = vec![
        credential_entry(
            "1a000001",
            Destination::Host {
                protocol: "tcp".into(),
                name: "api.deepseek.com".into(),
                port: Some(443),
            },
            NOW - 1_000,
            Some("MSB_AGENT_VM_ANTHROPIC_UNUSED"),
            Some("header"),
            Some("host-not-covered"),
        ),
        credential_entry(
            "1a000002",
            address("203.0.113.11", 443),
            NOW - 2_000,
            Some("OPENAI_API_KEY"),
            Some("query"),
            Some("credential-unavailable"),
        ),
        credential_entry(
            "1a000003",
            address("203.0.113.12", 443),
            NOW - 3_000,
            Some("OPENAI_API_KEY"),
            Some("trailer"),
            Some("destination-unverified"),
        ),
    ];
    dir.write(&snapshot("0a1b2c3d", NOW - 5_000, entries), NOW)
        .unwrap();

    let (status, out, err) = run_logged(&dir, table_args()).await;
    assert_eq!(status, 0);
    assert!(err.is_empty(), "{err}");
    for expected in [
        "can't be allowed here: credential policy; MSB_AGENT_VM_ANTHROPIC_UNUSED was sent in a \
         request header, and its secret does not cover the destination",
        "can't be allowed here: credential policy; OPENAI_API_KEY was sent in the query string, \
         and the real value could not be read outside the sandbox",
        "can't be allowed here: credential policy; OPENAI_API_KEY was sent in a request trailer, \
         and the destination could not be verified",
    ] {
        assert!(out.contains(expected), "missing {expected:?} in:\n{out}");
    }
    assert_eq!(out.matches("credential refusal").count(), 3, "{out}");
}

/// A log written by a build before these fields existed: read and rendered, never
/// reported as damaged. The row says what the record said, which is nothing about
/// the credential.
#[tokio::test]
async fn a_log_written_before_the_credential_fields_still_renders() {
    let root = tempfile::tempdir().unwrap();
    let dir = session_dir(root.path());
    let raw = serde_json::json!({
        "v": 1,
        "evicted_sessions": 0,
        "sessions": [{
            "info": {"id": "0a1b2c3d", "pid": 1, "started_ms": NOW - 9_000, "socket": true},
            "rev": 1, "ended_ms": null, "heartbeat_ms": null,
            "suppressed": 0, "lost": 0, "gap": false,
            "entries": [{
                "id": "1a000001",
                "key": {"kind": "credential_refusal", "destination": {
                    "variant": "host", "protocol": "tcp",
                    "name": "api.deepseek.com", "port": 443}},
                "layer": "tenant", "last_site": "secret-violation", "last_ip": null,
                "name": null, "last_revision": 1, "count": 1,
                "first_ms": NOW - 1_000, "last_ms": NOW - 1_000
            }]
        }]
    });
    std::fs::write(
        dir.path().join("refusals.json"),
        serde_json::to_vec(&raw).unwrap(),
    )
    .unwrap();

    let (status, out, err) = run_logged(&dir, table_args()).await;
    assert_eq!(status, 0);
    assert!(err.is_empty(), "an old log is not damage: {err}");
    assert!(
        out.contains("can't be allowed here: credential policy\n")
            || out
                .trim_end()
                .ends_with("can't be allowed here: credential policy"),
        "{out}"
    );
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
/// destination, the name source, the site `reason()` names, and the credential it
/// names. Under the guard only the host user writes these, but the documented
/// upgrade path admits older launchers that leave `.sessions` writable to their
/// guests (AC5).
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
    // A credential refusal's cell carries the credential the record named, which a
    // forged record can fill with anything.
    let forged_credential = format!("evil{ESC}[31mKEY");
    let credential = credential_entry(
        "abcdef02",
        address("203.0.113.10", 443),
        NOW - 2_000,
        Some(&forged_credential),
        Some("header"),
        Some("host-not-covered"),
    );
    dir.write(
        &snapshot("0a1b2c3d", NOW - 5_000, vec![sneaky, credential]),
        NOW,
    )
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
    assert!(
        out.contains(&crate::config::escape_str(&forged_credential)),
        "the credential is escaped like every other untrusted cell: {out:?}"
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

/// #598: `reason()` escapes the untrusted text it names exactly once, and both
/// surfaces print that text, so `access allow`'s error and the table's ACTION
/// cell must show the record's bytes alike. A backslash is the discriminating
/// byte: escaping it again is visible, while a control byte's `\xNN` only gains a
/// doubled backslash.
#[tokio::test]
async fn a_forged_reason_is_escaped_once_in_the_error_and_the_table() {
    let root = tempfile::tempdir().unwrap();
    let dir = session_dir(root.path());
    let mut forged = entry("abcdef01", address("203.0.113.10", 443), NOW - 1_000);
    forged.key.kind = Kind::PolicyLock;
    // Only a forged log can put a backslash in a site: a decoded record carries a
    // wire token, and `reason()` escapes whatever a forged one holds.
    forged.last_site = r"a\b".to_owned();
    dir.write(&snapshot("0a1b2c3d", NOW - 5_000, vec![forged]), NOW)
        .unwrap();

    let (status, table, _) = run_logged(&dir, table_args()).await;
    assert_eq!(status, 0);
    let (status, _, error) =
        run_command(root.path(), allow("abcdef01", false), &empty_view()).await;
    assert_eq!(status, 1, "{error}");

    // The reason starts at the same words on both surfaces and ends the line in
    // the table, the parentheses in the error.
    let reason_in = |text: &str| {
        let start = text
            .find("can't be allowed: ")
            .unwrap_or_else(|| panic!("the reason is printed: {text:?}"));
        text[start..].trim_end_matches([')', '\n']).to_owned()
    };
    let in_table = reason_in(&table);
    let in_error = reason_in(&error);
    assert_eq!(in_error, in_table, "one refusal, one spelling");
    assert_eq!(in_table, r"can't be allowed: built-in rule a\\b");
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

/// The window is about the *last* sighting, and FIRST-SEEN is the first one.
///
/// The two are separate fields, so a window that selected on `first_ms` would
/// hide a refusal still happening now (first seen days ago) and show one that
/// stopped a day ago (first seen minutes ago as an old log is re-read). Both rows
/// below sit on opposite sides of the boundary, so the two rules disagree.
#[tokio::test]
async fn the_window_selects_on_the_last_sighting_not_the_first() {
    let root = tempfile::tempdir().unwrap();
    let dir = session_dir(root.path());
    // First seen 30 h ago, refused again a minute ago: inside the window.
    let mut refreshed = entry("aaaaaaa1", address("203.0.113.10", 443), NOW - 60_000);
    refreshed.first_ms = NOW - 30 * 60 * 60 * 1000;
    // First seen a minute ago, last refused the day before yesterday: outside.
    let mut lapsed = entry(
        "bbbbbbb2",
        address("203.0.113.11", 443),
        NOW - WINDOW_MS - 60_000,
    );
    lapsed.first_ms = NOW - 60_000;
    dir.write(
        &snapshot(
            "0a1b2c3d",
            NOW - 30 * 60 * 60 * 1000,
            vec![refreshed, lapsed],
        ),
        NOW,
    )
    .unwrap();

    let (status, out, _) = run_logged(&dir, table_args()).await;
    assert_eq!(status, 0);
    let row = out
        .lines()
        .find(|line| line.starts_with("aaaaaaa1"))
        .unwrap_or_else(|| panic!("no row: {out}"));
    assert!(
        row.contains("2025-10-08 02:53Z  2025-10-09 08:52Z"),
        "FIRST-SEEN keeps the first sighting, LAST-SEEN the last: {row}"
    );
    assert!(!out.contains("bbbbbbb2"), "the window hides it: {out}");
    assert!(
        out.contains("Showing the last 24 hours; --all shows the whole log (1 older)"),
        "{out}"
    );

    let (status, out, _) = run_logged(&dir, ALL).await;
    assert_eq!(status, 0);
    assert!(out.contains("bbbbbbb2"), "--all shows it: {out}");
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
    assert_eq!(
        out.lines()
            .filter(|line| line.starts_with("deadbeef"))
            .count(),
        2,
        "{out}"
    );
    // ...each row's command qualifying the ID with its own session, because the
    // ID alone names both...
    for session in ["00000001", "00000002"] {
        assert!(
            out.contains(&format!(
                "agent-vm access allow deadbeef --session {session} --project"
            )),
            "{out}"
        );
    }
    // ...and flagged once.
    assert!(
        out.contains("the same refusal ID appears in more than one session: deadbeef"),
        "{out}"
    );
}

/// A state that cannot confirm a live change is offered no command at all: a
/// table that offered one would be promising a mutation `allow` refuses.
#[tokio::test]
async fn a_session_that_cannot_be_asked_offers_no_command() {
    let root = tempfile::tempdir().unwrap();
    let dir = session_dir(root.path());

    // `running (no control socket)`: alive (a fresh heartbeat), bound no socket.
    let mut no_socket = snapshot(
        "00000005",
        NOW - 10_000,
        vec![entry("aaaaaaa5", address("203.0.113.15", 443), NOW - 5_000)],
    );
    no_socket.info.socket = false;
    no_socket.heartbeat_ms = Some(NOW - 1_000);
    dir.write(&no_socket, NOW).unwrap();

    // `not responding`: the socket is bound and never answers.
    let hung_id = SessionId::parse("00000006").unwrap();
    let listener = tokio::net::UnixListener::bind(dir.socket_path(&hung_id)).unwrap();
    let hung = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    let mut logged = snapshot(
        "00000006",
        NOW - 10_000,
        vec![entry("aaaaaaa6", address("203.0.113.16", 443), NOW - 5_000)],
    );
    logged.info.socket = true;
    dir.write(&logged, NOW).unwrap();

    let (status, out, _) = run_logged(&dir, table_args()).await;
    assert_eq!(status, 0);
    for (refusal, state) in [
        ("aaaaaaa5", "running (no control socket)"),
        ("aaaaaaa6", "not responding"),
    ] {
        let row = out
            .lines()
            .find(|line| line.starts_with(refusal))
            .unwrap_or_else(|| panic!("{refusal} has a row: {out}"));
        assert!(row.contains(state), "{refusal} is {state}: {row}");
        assert!(
            row.ends_with("session cannot confirm live change; relaunch with --allow-egress"),
            "{row}"
        );
        assert!(
            !row.contains("agent-vm access allow"),
            "a session that cannot confirm offers no command: {row}"
        );
    }
    hung.abort();
}

/// The two time columns are two fields: a destination refused again keeps its
/// first sighting, so `FIRST-SEEN` cannot be `LAST-SEEN` rewritten.
#[tokio::test]
async fn first_seen_is_its_own_column_and_keeps_the_evidence_markers() {
    let root = tempfile::tempdir().unwrap();
    let dir = session_dir(root.path());
    let mut repeated = entry("46d712fd", address("203.0.113.10", 443), NOW - 60_000);
    repeated.first_ms = NOW - 600_000;
    repeated.count = 2;
    repeated.name = Some(GuestName {
        name: "api.example.com".into(),
        source: "dns-cache".into(),
        truncated: false,
    });
    dir.write(&snapshot("00000001", NOW - 700_000, vec![repeated]), NOW)
        .unwrap();

    let (status, out, _) = run_logged(&dir, table_args()).await;
    assert_eq!(status, 0);
    let header = out.lines().next().expect("a header line");
    assert!(
        header.find("FIRST-SEEN") < header.find("LAST-SEEN"),
        "FIRST-SEEN comes before LAST-SEEN: {header}"
    );
    let row = out
        .lines()
        .find(|line| line.starts_with("46d712fd"))
        .unwrap_or_else(|| panic!("no row: {out}"));
    // Cells are two spaces apart and none holds two in a row, so this is the
    // column split the header describes.
    let cells: Vec<&str> = row.split("  ").filter(|cell| !cell.is_empty()).collect();
    assert_eq!(cells.len(), 8, "{row}");
    assert_eq!(cells[3], "2", "COUNT: {row}");
    assert_eq!(cells[4], "2025-10-09 08:43Z", "FIRST-SEEN: {row}");
    assert_eq!(cells[5], "2025-10-09 08:52Z", "LAST-SEEN: {row}");
    assert!(
        cells[2].contains("api.example.com (DNS cache, guest-supplied)"),
        "DESTINATION keeps the evidence markers: {row}"
    );
}

/// A refusal ID becomes a command word, so only the 8-hex spelling the feed
/// assigns may reach the ACTION cell. A log the guest can write must not be able
/// to make `access` print a command (AC5).
#[tokio::test]
async fn a_malformed_refusal_id_never_becomes_a_command() {
    let root = tempfile::tempdir().unwrap();
    let dir = session_dir(root.path());
    let forged = entry("$(id)", address("203.0.113.10", 443), NOW - 60_000);
    dir.write(&snapshot("00000001", NOW - 300_000, vec![forged]), NOW)
        .unwrap();

    let (status, out, _) = run_logged(&dir, table_args()).await;
    assert_eq!(status, 0);
    assert!(
        out.contains("cannot build allow command: malformed refusal ID"),
        "{out}"
    );
    // The row is still shown — it is a refusal — but it names no command.
    let row = out
        .lines()
        .find(|line| line.starts_with("$(id)"))
        .unwrap_or_else(|| panic!("no row: {out}"));
    assert!(!row.contains("agent-vm access allow"), "{row}");
    let action = row.split("  ").filter(|cell| !cell.is_empty()).last();
    assert_eq!(
        action,
        Some("cannot build allow command: malformed refusal ID"),
        "{row}"
    );

    // Nor does a malformed ID reach the mutation: it is parsed before anything is
    // looked up, so the same spelling rule decides both what is printed and what
    // runs.
    let view = live_view(root.path());
    let (status, out, err) = run_command(root.path(), allow("$(id)", false), &view).await;
    assert_eq!(status, 1, "{out}{err}");
    assert!(err.contains("`<ID>` takes an 8-hex refusal ID"), "{err}");
    assert!(
        !err.contains("$(id)"),
        "an untrusted ID is never echoed: {err}"
    );
    assert_eq!(live_view(root.path()).allowances().len(), 0, "no record");
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
    assert_eq!(
        out.lines()
            .filter(|line| line.starts_with("aaaaaaa1"))
            .count(),
        1,
        "one row: {out}"
    );
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
    // Slice 1's text is gone: no record names it, so the row offers the one
    // command that would create one, qualified by its own session.
    assert_eq!(
        action("a00b2078"),
        "session ended; run `agent-vm access allow a00b2078 --session 0a1b2c3d --project`"
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
    // Not covered, so the row offers the command that would cover it and claims
    // no record.
    assert!(
        out.contains("run `agent-vm access allow 46d712fd --session 0a1b2c3d --project`"),
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
            credential: None,
            location: None,
            reason: None,
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

fn allow_in_session(id: &str, project: bool, session: &str) -> AccessSubcommand {
    AccessSubcommand::Allow(AllowArgs {
        id: id.to_owned(),
        project,
        session: Some(session.to_owned()),
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

    // Before any allowance, the refusal's row offers both scopes and names this
    // session in each command.
    let sid = live.id().as_str();
    let (status, table, err) = run_logged(&session_dir(root.path()), table_args()).await;
    assert_eq!(status, 0, "{err}");
    assert!(
        table.contains(&format!(
            "run `agent-vm access allow {id} --session {sid}` (session) or `agent-vm access \
             allow {id} --session {sid} --project`"
        )),
        "{table}"
    );

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

/// C3(d): the runtime applies it, the store cannot record it, and `access`,
/// `access allowances` and `access egress` render the demoted session-only
/// status afterwards.
#[tokio::test]
async fn applied_not_recorded_demotes_to_session_scope_across_subsequent_access_allowances_and_egress_calls()
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
    // `access egress` keeps the row in the session tier at the revision the
    // runtime confirmed, never the project tier the record does not carry.
    let session_id = live.id().as_str().to_owned();
    let (status, egress, err) = run_command(root.path(), egress_request(None), &view).await;
    assert_eq!(status, 0, "{err}");
    assert_eq!(
        egress,
        format!(
            "Session {session_id} (policy rev 2)\n\
DESTINATION      PORTS    VIA  SOURCE             STATUS\n\
203.0.113.10/32  tcp:443  -    session allowance  applied (rev 2)\n\
DNS: denied\n"
        )
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

/// B9: the same refusal ID in a live session and in a session that has ended.
///
/// An unqualified ID names both, so `allow` must refuse it rather than mutate the
/// one the listing happened to reach first; a command qualified with the ended
/// session must write the project record and must not touch the live session.
#[tokio::test]
async fn an_ambiguous_refusal_id_is_refused_and_never_targets_the_wrong_session() {
    let root = tempfile::tempdir().unwrap();
    let updater = Arc::new(Updater::default());
    let live = start_fixture(root.path(), Some(updater.handle())).await;
    let id = ingest_denial(&live);
    let view = live_view(root.path());

    // An 8-hex ID is unique per *session*, not across sessions.
    let mut ended = snapshot(
        "00000002",
        NOW - 10_000,
        vec![entry(&id, address("203.0.113.10", 443), NOW - 5_000)],
    );
    ended.info.socket = false;
    ended.ended_ms = Some(NOW - 4_000);
    session_dir(root.path()).write(&ended, NOW).unwrap();

    // Unqualified: two sessions carry it, so nothing is mutated.
    let (status, out, err) = run_command(root.path(), allow(&id, true), &view).await;
    assert_eq!(status, 1, "{out}{err}");
    assert!(err.contains("more than one session"), "{err}");
    assert!(err.contains(live.id().as_str()), "{err}");
    assert!(err.contains("00000002"), "{err}");
    assert!(err.contains("--session <ID>"), "{err}");
    assert_eq!(updater.calls.load(Ordering::SeqCst), 0, "no runtime call");
    assert_eq!(view.allowances().len(), 0, "no record was written");
    assert!(
        live.allowances().snapshot().session.is_empty(),
        "the live session was not mutated"
    );

    // Qualified with the ended session: the record, and only the record.
    let (status, out, err) =
        run_command(root.path(), allow_in_session(&id, true, "00000002"), &view).await;
    assert_eq!(status, 0, "{out}{err}");
    assert!(out.contains("recorded project allowance"), "{out}");
    assert_eq!(live_view(root.path()).allowances().len(), 1);
    assert!(
        live.allowances().snapshot().session.is_empty(),
        "the live session that shares the ID was not mutated"
    );
    assert_eq!(
        updater.calls.load(Ordering::SeqCst),
        0,
        "an ended session takes no policy swap"
    );
    live.finish().await;
}

/// An ID copied from another session still says where it lives: filtering by
/// `--session` first must not hide the answer the ID-only lookup gave.
#[tokio::test]
async fn allow_names_the_session_that_holds_a_qualified_id() {
    let root = tempfile::tempdir().unwrap();
    let dir = session_dir(root.path());
    for (session, refusal, started) in [
        ("00000007", "aaaaaaa7", NOW - 20_000),
        ("00000008", "aaaaaaa8", NOW - 10_000),
    ] {
        let mut ended = snapshot(
            session,
            started,
            vec![entry(refusal, address("203.0.113.10", 443), NOW - 1_000)],
        );
        ended.info.socket = false;
        ended.ended_ms = Some(NOW - 500);
        dir.write(&ended, NOW).unwrap();
    }
    let view = live_view(root.path());

    let (status, out, err) = run_command(
        root.path(),
        allow_in_session("aaaaaaa7", true, "00000008"),
        &view,
    )
    .await;
    assert_eq!(status, 1, "{out}{err}");
    assert!(
        err.contains("refusal aaaaaaa7 is not in session 00000008; it is in 00000007 (ended)"),
        "{err}"
    );
    assert_eq!(live_view(root.path()).allowances().len(), 0, "no record");
}

/// `allow`, `allowances` and `egress` share one `--session` rule
/// ([`parse_session_flag`]), so all three answer a value that is not an ID with
/// the same line, before they look anything up, and none of them acts on it.
///
/// `revoke` is deliberately absent: it still compares the flag as text and
/// deletes the project record before it notices, which is a defect of its own
/// (recorded in the PR 1 verification report, out of this change's scope).
#[tokio::test]
async fn the_verbs_that_take_a_session_reject_a_malformed_one_in_the_same_words() {
    let root = tempfile::tempdir().unwrap();
    let dir = session_dir(root.path());
    let mut ended = snapshot(
        "00000001",
        NOW - 20_000,
        vec![entry("aaaaaaa1", address("203.0.113.10", 443), NOW - 1_000)],
    );
    ended.info.socket = false;
    ended.ended_ms = Some(NOW - 500);
    dir.write(&ended, NOW).unwrap();
    let view = live_view(root.path());

    let verbs: [(&str, AccessSubcommand); 3] = [
        (
            "allow",
            AccessSubcommand::Allow(AllowArgs {
                id: "aaaaaaa1".to_owned(),
                project: true,
                session: Some("nothex".to_owned()),
            }),
        ),
        (
            "allowances",
            AccessSubcommand::Allowances(AllowancesArgs {
                session: Some("nothex".to_owned()),
            }),
        ),
        ("egress", egress_request(Some("nothex"))),
    ];
    for (verb, command) in verbs {
        let (status, out, err) = run_command(root.path(), command, &view).await;
        assert_eq!(status, 1, "{verb}: {out}{err}");
        assert_eq!(err, "`--session` takes an 8-hex session ID\n", "{verb}");
        // Not the lookup it used to be: a value this command cannot parse names
        // no session, so it must not be echoed back as one.
        assert!(!err.contains("is not in session"), "{verb}: {err}");
        assert_eq!(out, "", "{verb}");
    }
    assert_eq!(live_view(root.path()).allowances().len(), 0, "no record");
}

/// Two entries of one ID cannot be resolved by any flag, so `allow` refuses
/// them — and a user who already named a session is never told to name one again.
#[tokio::test]
async fn a_damaged_log_is_refused_and_never_advises_a_named_session() {
    let root = tempfile::tempdir().unwrap();
    let dir = session_dir(root.path());
    let mut doubled = snapshot(
        "00000001",
        NOW - 20_000,
        vec![
            entry("deadbeee", address("203.0.113.12", 443), NOW - 1_000),
            entry("deadbeee", address("203.0.113.13", 443), NOW - 2_000),
            entry("deadbeef", address("203.0.113.10", 443), NOW - 1_000),
            entry("deadbeef", address("203.0.113.11", 443), NOW - 2_000),
        ],
    );
    doubled.info.socket = false;
    doubled.ended_ms = Some(NOW - 500);
    dir.write(&doubled, NOW).unwrap();
    let mut other = snapshot(
        "00000002",
        NOW - 10_000,
        vec![entry("deadbeef", address("203.0.113.14", 443), NOW - 1_000)],
    );
    other.info.socket = false;
    other.ended_ms = Some(NOW - 500);
    dir.write(&other, NOW).unwrap();
    let view = live_view(root.path());

    // One session records one ID twice: no `--session` can choose between them.
    let (status, out, err) = run_command(
        root.path(),
        allow_in_session("deadbeee", true, "00000001"),
        &view,
    )
    .await;
    assert_eq!(status, 1, "{out}{err}");
    assert!(
        err.contains(
            "refusal deadbeee appears in more than one entry of 00000001 (ended); the refusal log \
             is damaged"
        ),
        "{err}"
    );
    assert!(!err.contains("--session <ID>"), "{err}");
    assert_eq!(live_view(root.path()).allowances().len(), 0, "no record");

    // Unqualified, the same ID in two sessions is the documented ambiguity.
    let (status, out, err) = run_command(root.path(), allow("deadbeef", true), &view).await;
    assert_eq!(status, 1, "{out}{err}");
    assert!(err.contains("is in more than one session"), "{err}");
    assert!(err.contains("00000001 (ended)"), "{err}");
    assert!(err.contains("00000002 (ended)"), "{err}");
    assert!(err.contains("--session <ID>"), "{err}");
    assert_eq!(live_view(root.path()).allowances().len(), 0, "no record");

    // Named, and recorded twice in that session while another session carries it
    // too: the damaged-log answer, taken from the named session's own entries.
    let (status, out, err) = run_command(
        root.path(),
        allow_in_session("deadbeef", true, "00000001"),
        &view,
    )
    .await;
    assert_eq!(status, 1, "{out}{err}");
    assert!(
        err.contains(
            "refusal deadbeef appears in more than one entry of 00000001 (ended); the refusal log \
             is damaged"
        ),
        "{err}"
    );
    assert!(!err.contains("--session <ID>"), "{err}");
    assert!(!err.contains("00000002"), "{err}");
    assert_eq!(live_view(root.path()).allowances().len(), 0, "no record");
}

/// A refusal older than the window is still shown when `--session` names it, and
/// a session that has ended is offered `--project` only.
#[tokio::test]
async fn a_stale_ended_session_is_shown_by_session_and_allows_project_only() {
    let root = tempfile::tempdir().unwrap();
    let dir = session_dir(root.path());
    let idle = 30 * 60 * 60 * 1000;
    let mut stale = snapshot(
        "00000004",
        NOW - idle,
        vec![entry("aaaaaaa4", address("203.0.113.10", 443), NOW - idle)],
    );
    stale.info.socket = false;
    stale.ended_ms = Some(NOW - idle);
    dir.write(&stale, NOW).unwrap();
    let view = live_view(root.path());

    // The default window hides it.
    let (status, out, _) = run_logged(&dir, table_args()).await;
    assert_eq!(status, 0);
    assert!(out.contains("No refusals in the last 24 hours."), "{out}");

    // `--session` is a question about one session, not a window over it.
    let (status, out, _) = run_logged(
        &dir,
        Args {
            command: None,
            session: Some("00000004".to_owned()),
            all: false,
        },
    )
    .await;
    assert_eq!(status, 0);
    let row = out
        .lines()
        .find(|line| line.starts_with("aaaaaaa4"))
        .unwrap_or_else(|| panic!("no row: {out}"));
    assert!(
        row.contains(
            "session ended; run `agent-vm access allow aaaaaaa4 --session 00000004 --project`"
        ),
        "{row}"
    );

    // The row's own command, without `--project`, cannot be recorded.
    let (status, out, err) = run_command(
        root.path(),
        allow_in_session("aaaaaaa4", false, "00000004"),
        &view,
    )
    .await;
    assert_eq!(status, 1, "{out}{err}");
    assert!(err.contains("has ended"), "{err}");
    assert_eq!(live_view(root.path()).allowances().len(), 0);

    // With `--project` it records what the next launch reads.
    let (status, out, err) = run_command(
        root.path(),
        allow_in_session("aaaaaaa4", true, "00000004"),
        &view,
    )
    .await;
    assert_eq!(status, 0, "{out}{err}");
    assert!(out.contains("recorded project allowance"), "{out}");
    assert_eq!(live_view(root.path()).allowances().len(), 1);
}

// ---------------------------------------------------------------------------
// Group D: `access egress` (#631)
// ---------------------------------------------------------------------------

/// `start_fixture` over an explicit launch authority: the egress table reports
/// the policy, not the refusals.
async fn start_fixture_plan(
    root: &Path,
    allow_egress: &[&str],
    updater: Option<crate::allowances::PolicyUpdater>,
) -> crate::session_control::LiveSession {
    let session = project(root);
    let project = live_project(root);
    let store = crate::allowances::StoreHandle::at_for_tests(&root.join("allowances-store"));
    let plan = crate::network::plan_for_tests(allow_egress, false).live_policy_plan(None);
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

fn egress_request(session: Option<&str>) -> AccessSubcommand {
    AccessSubcommand::Egress(EgressArgs {
        session: session.map(str::to_owned),
    })
}

/// AC1 and AC2: the whole table before the allow, after it, and after the
/// revoke — byte for byte. A cell in the wrong column or a row out of order must
/// fail here, because this is the only test of the real controller → socket →
/// CLI path.
#[tokio::test]
async fn egress_end_to_end_allow_then_revoke() {
    let root = tempfile::tempdir().unwrap();
    let updater = Arc::new(Updater::default());
    let live = start_fixture_plan(root.path(), &["api.example.com"], Some(updater.handle())).await;
    let id = live.id().as_str().to_owned();
    let view = live_view(root.path());

    let (status, out, err) = run_command(root.path(), egress_request(None), &view).await;
    assert_eq!(status, 0, "{out}{err}");
    assert_eq!(
        out,
        format!(
            "Session {id} (policy rev 1)\n\
DESTINATION      PORTS  VIA  SOURCE          STATUS\n\
api.example.com  443    -    --allow-egress  applied\n\
DNS: allowed hostnames only\n"
        )
    );

    let denied = ingest_denial(&live);
    let (status, _, err) = run_command(root.path(), allow(&denied, false), &view).await;
    assert_eq!(status, 0, "{err}");
    let (status, out, err) = run_command(root.path(), egress_request(None), &view).await;
    assert_eq!(status, 0, "{out}{err}");
    // The new row goes last, in the address section, and the wider cells re-pad
    // the whole table.
    assert_eq!(
        out,
        format!(
            "Session {id} (policy rev 2)\n\
DESTINATION      PORTS    VIA  SOURCE             STATUS\n\
api.example.com  443      -    --allow-egress     applied\n\
203.0.113.10/32  tcp:443  -    session allowance  applied (rev 2)\n\
DNS: allowed hostnames only\n"
        )
    );

    let (status, _, err) = run_command(
        root.path(),
        AccessSubcommand::Revoke(RevokeArgs {
            destination: "tcp://[203.0.113.10/32]:443".to_owned(),
            project: false,
            session_only: true,
            session: None,
        }),
        &view,
    )
    .await;
    assert_eq!(status, 0, "{err}");
    let (status, out, err) = run_command(root.path(), egress_request(None), &view).await;
    assert_eq!(status, 0, "{out}{err}");
    // Only the session row is gone; the configured row and its padding stay.
    assert_eq!(
        out,
        format!(
            "Session {id} (policy rev 3)\n\
DESTINATION      PORTS  VIA  SOURCE          STATUS\n\
api.example.com  443    -    --allow-egress  applied\n\
DNS: allowed hostnames only\n"
        )
    );
}

/// Finding 3: `access egress` prints no store warning. Its subject is not
/// effective egress, and `access allowances` is where it belongs; the pointer
/// line sends the reader there.
#[tokio::test]
async fn egress_prints_no_store_warning_with_no_session() {
    let root = tempfile::tempdir().unwrap();
    let view = crate::allowances::ProjectView::for_tests(
        &[],
        NOW - 60_000,
        Some(
            "project allowances not applied: \"/home/a/.config/agent-vm/allowances.json\" could not be used (not a JSON document this build reads); this version does not repair it — move it aside to start over",
        ),
    );
    let (status, out, err) = run_command(root.path(), egress_request(None), &view).await;
    assert_eq!(status, 0, "{out}{err}");
    assert_eq!(
        out,
        "No running session in this project; `agent-vm access allowances` lists its recorded project allowances.\n"
    );
    assert_eq!(err, "", "the store warning is not this command's");
}

/// Finding 3, the misleading case: beside a live table, whose boot-adopted rows
/// say `applied`, a warning saying they were "not applied" contradicts it.
#[tokio::test]
async fn egress_prints_no_store_warning_with_a_live_session() {
    let root = tempfile::tempdir().unwrap();
    let updater = Arc::new(Updater::default());
    let live = start_fixture_plan(root.path(), &["api.example.com"], Some(updater.handle())).await;
    let view = crate::allowances::ProjectView::for_tests(
        &[],
        NOW - 60_000,
        Some(
            "project allowances not applied: \"/home/a/.config/agent-vm/allowances.json\" could not be used (not a JSON document this build reads); this version does not repair it — move it aside to start over",
        ),
    );
    let (status, out, err) = run_command(root.path(), egress_request(None), &view).await;
    assert_eq!(status, 0, "{out}{err}");
    assert!(
        out.starts_with(&format!("Session {} (policy rev 1)\n", live.id().as_str())),
        "{out}"
    );
    assert!(out.contains("api.example.com"), "{out}");
    assert!(
        out.contains(" applied\n"),
        "the row the warning contradicts: {out}"
    );
    assert_eq!(err, "", "no store warning beside the table");
}

/// AC3: no session is one pointer line and a success status.
///
/// "No running session" includes a project whose only session has ended: the
/// refusal log row is a candidate, but not an active one, so the pointer is the
/// whole answer. Verified against a real launcher whose session had ended.
#[tokio::test]
async fn egress_with_no_session_points_and_exits_0() {
    let root = tempfile::tempdir().unwrap();
    let view = live_view(root.path());
    let (status, out, err) = run_command(root.path(), egress_request(None), &view).await;
    assert_eq!(status, 0, "{err}");
    assert_eq!(
        out,
        "No running session in this project; `agent-vm access allowances` lists its recorded project allowances.\n"
    );
    assert_eq!(err, "");

    // An ended session in the log changes nothing: still the pointer, exit 0.
    session_dir(root.path())
        .write(&snapshot("0000000b", NOW - 10 * 60 * 1000, vec![]), NOW)
        .unwrap();
    let (status, out, err) = run_command(root.path(), egress_request(None), &view).await;
    assert_eq!(status, 0, "{err}");
    assert_eq!(
        out,
        "No running session in this project; `agent-vm access allowances` lists its recorded project allowances.\n"
    );
    assert_eq!(err, "");
}

/// AC3: an ambiguous selection is a usage error naming every candidate.
#[tokio::test]
async fn egress_with_two_sessions_is_a_usage_error_naming_both() {
    let root = tempfile::tempdir().unwrap();
    let first = start_fixture_plan(root.path(), &[], None).await;
    let second = start_fixture_plan(root.path(), &[], None).await;
    let view = live_view(root.path());
    let (status, out, err) = run_command(root.path(), egress_request(None), &view).await;
    assert_eq!(status, 2, "{out}{err}");
    assert_eq!(out, "", "nothing on stdout");
    assert!(err.contains("more than one session is running"), "{err}");
    for live in [&first, &second] {
        assert!(err.contains(live.id().as_str()), "{err}");
    }
    assert!(err.contains("--session <ID>"), "{err}");
}

/// AC3's `--session` cases: the ended and the unknown one are refused, the
/// running one is selected.
#[tokio::test]
async fn egress_named_session_selects_it_and_rejects_ended_and_unknown() {
    let root = tempfile::tempdir().unwrap();
    let live = start_fixture_plan(root.path(), &["api.example.com"], None).await;
    let dir = session_dir(root.path());
    // A logged session with no socket and a stale heartbeat: `ended (unclean)`.
    dir.write(&snapshot("0000000a", NOW - 10 * 60 * 1000, vec![]), NOW)
        .unwrap();
    let view = live_view(root.path());
    let id = live.id().as_str().to_owned();

    let (status, out, err) = run_command(root.path(), egress_request(Some(&id)), &view).await;
    assert_eq!(status, 0, "{out}{err}");
    assert!(out.starts_with(&format!("Session {id} ")), "{out}");

    let (status, out, err) =
        run_command(root.path(), egress_request(Some("0000000a")), &view).await;
    assert_eq!(status, 1, "{out}{err}");
    assert_eq!(out, "");
    assert!(
        err.contains("session 0000000a (ended (unclean)) is not running; effective egress exists only while a session runs"),
        "{err}"
    );

    let (status, out, err) =
        run_command(root.path(), egress_request(Some("0000000b")), &view).await;
    assert_eq!(status, 1, "{out}{err}");
    assert_eq!(out, "");
    assert!(
        err.contains("no session 0000000b in this project's running sessions or refusal log"),
        "{err}"
    );

    let (status, _, err) = run_command(root.path(), egress_request(Some("nothex")), &view).await;
    assert_eq!(status, 1);
    assert!(
        err.contains("`--session` takes an 8-hex session ID"),
        "{err}"
    );
}

/// Review finding 3: a socket that accepted and never answered, with no log
/// record, is a candidate — reported, never silently skipped.
#[tokio::test]
async fn egress_counts_a_socket_only_unresponsive_session() {
    let root = tempfile::tempdir().unwrap();
    let dir = session_dir(root.path());
    let hung = SessionId::parse("0000000c").unwrap();
    let listener = tokio::net::UnixListener::bind(dir.socket_path(&hung)).unwrap();
    let held = tokio::spawn(async move {
        let mut streams = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            streams.push(stream);
        }
    });
    let view = live_view(root.path());

    // Alone: reported, not treated as "no session".
    let (status, out, err) = run_command(root.path(), egress_request(None), &view).await;
    assert_eq!(status, 1, "{out}{err}");
    assert_eq!(out, "");
    assert_eq!(
        err,
        "effective egress is not available for session 0000000c (not responding): it is not responding\n"
    );

    // Beside a healthy session: the selection is ambiguous, and every active
    // candidate is named with its own label — the log row first, then the
    // socket-only one. This is the whole line: a wrong label, separator or
    // order must fail here.
    let live = start_fixture_plan(root.path(), &[], None).await;
    let (status, out, err) = run_command(root.path(), egress_request(None), &view).await;
    assert_eq!(status, 2, "{out}{err}");
    assert_eq!(out, "");
    assert_eq!(
        err,
        format!(
            "more than one session is running: {} (running), 0000000c (not responding); name one with --session <ID>\n",
            live.id().as_str()
        )
    );

    // Named: reported not available, never "no session".
    let (status, out, err) =
        run_command(root.path(), egress_request(Some("0000000c")), &view).await;
    assert_eq!(status, 1, "{out}{err}");
    assert!(
        err.contains("effective egress is not available for session 0000000c (not responding)"),
        "{err}"
    );

    // The other commands are unchanged: the unresponsive warning still prints.
    let (status, _, err) = run_command(
        root.path(),
        AccessSubcommand::Allowances(AllowancesArgs { session: None }),
        &view,
    )
    .await;
    assert_eq!(status, 0);
    assert!(
        err.contains("session 0000000c is not responding; its live allowances are not shown"),
        "{err}"
    );
    held.abort();
}

/// The Specification's example, byte for byte, plus the two degenerate tables
/// and escaping of every wire string.
#[test]
fn egress_render_golden() {
    use crate::effective_egress::*;
    let row = |destination: RowDestination,
               ports: RowPorts,
               via: Option<&str>,
               source: RowSource,
               status: RowStatus| EgressRow {
        destination,
        ports,
        via: via.map(str::to_owned),
        source,
        status,
    };
    let egress = EffectiveEgress {
        policy_revision: Some(2),
        rows: vec![
            row(
                RowDestination::Hostname {
                    name: "api.anthropic.com".to_owned(),
                },
                RowPorts::Tls { ports: vec![443] },
                Some("set:anthropic"),
                RowSource::PersistedGrant,
                RowStatus::Applied,
            ),
            row(
                RowDestination::Hostname {
                    name: "platform.claude.com".to_owned(),
                },
                RowPorts::Tls { ports: vec![443] },
                Some("set:anthropic"),
                RowSource::PersistedGrant,
                RowStatus::Applied,
            ),
            row(
                RowDestination::Hostname {
                    name: "crates.io".to_owned(),
                },
                RowPorts::Tls { ports: vec![443] },
                Some("set:rust"),
                RowSource::PersistedGrant,
                RowStatus::Applied,
            ),
            row(
                RowDestination::Hostname {
                    name: "api.github.com".to_owned(),
                },
                RowPorts::Tls { ports: vec![443] },
                None,
                RowSource::PersistedGrant,
                RowStatus::Applied,
            ),
            row(
                RowDestination::Address {
                    network: "203.0.113.10/32".to_owned(),
                },
                RowPorts::Address {
                    transport: Some(WireTransport::Tcp),
                    port: Some(443),
                },
                None,
                RowSource::SessionAllowance,
                RowStatus::AppliedAt { revision: 2 },
            ),
            row(
                RowDestination::Group {
                    group: EgressGroup::Internet,
                },
                RowPorts::All,
                None,
                RowSource::AllowInternetEgress,
                RowStatus::Applied,
            ),
        ],
        dns: DnsAuthorization::AnyName {
            via: vec!["--allow-internet-egress".to_owned()],
        },
        narrowing: EgressNarrowing {
            credential_rules: true,
            github_repos: vec!["gregwebs/agent-vm".to_owned()],
        },
    };
    let id = SessionId::parse("3f9a12c4").unwrap();
    assert_eq!(
        egress::render(&id, &egress).unwrap().join("\n"),
        "Session 3f9a12c4 (policy rev 2)\n\
DESTINATION          PORTS    VIA            SOURCE                   STATUS\n\
api.anthropic.com    443      set:anthropic  persisted grant          applied\n\
platform.claude.com  443      set:anthropic  persisted grant          applied\n\
crates.io            443      set:rust       persisted grant          applied\n\
api.github.com       443      -              persisted grant          applied\n\
203.0.113.10/32      tcp:443  -              session allowance        applied (rev 2)\n\
internet (public)    all      -              --allow-internet-egress  applied\n\
DNS: any name, via --allow-internet-egress\n\
Narrowed by: credential rules; GitHub repos gregwebs/agent-vm"
    );

    // Starting: no confirmed revision, and nothing narrowing yet.
    let starting = EffectiveEgress {
        policy_revision: None,
        rows: egress.rows.clone(),
        dns: DnsAuthorization::Denied,
        narrowing: EgressNarrowing::default(),
    };
    let lines = egress::render(&id, &starting).unwrap();
    assert_eq!(lines[0], "Session 3f9a12c4 (starting)");
    assert_eq!(lines.last().unwrap(), "DNS: denied");

    // Nothing allowed: header, then exactly one sentence.
    let nothing = EffectiveEgress {
        policy_revision: Some(1),
        rows: Vec::new(),
        dns: DnsAuthorization::Denied,
        narrowing: EgressNarrowing::default(),
    };
    assert_eq!(
        egress::render(&id, &nothing).unwrap(),
        vec![
            "Session 3f9a12c4 (policy rev 1)".to_owned(),
            "All guest egress denied.".to_owned(),
        ]
    );

    // Every wire string is escaped: repo names come from the project's remotes.
    let hostile = EffectiveEgress {
        policy_revision: Some(1),
        rows: vec![row(
            RowDestination::Hostname {
                name: "\u{1b}[31mhost".to_owned(),
            },
            RowPorts::Tls { ports: vec![443] },
            Some("\u{1b}[32mset:x"),
            RowSource::PersistedGrant,
            RowStatus::Applied,
        )],
        dns: DnsAuthorization::AnyName {
            via: vec!["\u{1b}[33mflag".to_owned()],
        },
        narrowing: EgressNarrowing {
            credential_rules: true,
            github_repos: vec!["\u{1b}[34mowner/repo".to_owned()],
        },
    };
    let rendered = egress::render(&id, &hostile).unwrap().join("\n");
    assert!(!rendered.contains('\u{1b}'), "{rendered}");
    assert!(rendered.contains("\\x1b[31mhost"), "{rendered}");
    assert!(rendered.contains("\\x1b[32mset:x"), "{rendered}");
    assert!(rendered.contains("\\x1b[33mflag"), "{rendered}");
    assert!(rendered.contains("\\x1b[34mowner/repo"), "{rendered}");
}

/// The guest marker is the launcher's own, and nothing else.
#[test]
fn in_guest_is_exactly_is_sandbox_1() {
    let lookup = |value: Option<&'static str>| {
        move |name: &str| {
            assert_eq!(name, "IS_SANDBOX", "one variable decides this");
            value.map(str::to_owned)
        }
    };
    assert!(egress::in_guest(lookup(Some("1"))));
    for value in [None, Some("0"), Some("true"), Some(" 1"), Some("1 ")] {
        assert!(!egress::in_guest(lookup(value)), "{value:?}");
    }
}
