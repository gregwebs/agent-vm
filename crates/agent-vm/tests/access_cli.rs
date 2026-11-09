//! `agent-vm access` as a process: the verb exists, needs nothing, and creates
//! nothing.
//!
//! `access` is dispatched before credential preflight, the MSB prologue and the
//! runtime, so it has to work with a broken user config, no patched `msb` and no
//! image. These cases hold that: they assert the process, not the code path.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn agent_vm() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-vm"))
}

/// A `$HOME` with a config file that cannot be parsed, and a `MSB_PATH` that does
/// not exist: nothing this command is allowed to need.
fn broken_home(root: &Path) -> PathBuf {
    let home = root.join("home");
    let config = home.join(".config/agent-vm/config.toml");
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(config.join("config.toml"), "this is not = valid [ toml\n").unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(
        config.parent().unwrap(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o700)).unwrap();
    home
}

fn run(home: &Path, state: &Path, project: &Path, args: &[&str]) -> Output {
    Command::new(agent_vm())
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("AGENT_VM_STATE_DIR", state)
        .env("MSB_PATH", home.join("no-such-msb"))
        .current_dir(project)
        .args(args)
        .output()
        .expect("running agent-vm")
}

/// A broken config and no runtime do not stop the verb that reports refusals.
#[test]
fn access_works_with_a_broken_config_and_no_runtime() {
    let root = tempfile::tempdir().unwrap();
    let home = broken_home(root.path());
    let state = root.path().join("state");
    let project = root.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let out = run(&home, &state, &project, &["access"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout: {stdout}\nstderr: {stderr}");
    assert_eq!(stdout, "No refusals in the last 24 hours.\n");
    assert!(!stderr.contains("Error"), "{stderr}");
    // Reading must not create the store that would answer.
    assert!(
        !state.join("ab12cd34ef56.sessions").exists() && !state.exists(),
        "a read creates no state root: {}",
        state.display()
    );
}

/// `access` is a reserved built-in: it appears in the help and cannot be
/// shadowed by a config tool.
#[test]
fn access_is_a_builtin_verb() {
    let root = tempfile::tempdir().unwrap();
    let home = broken_home(root.path());
    let project = root.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let out = run(&home, &root.path().join("state"), &project, &["--help"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("access"), "the verb is listed: {stdout}");
}

/// An unknown `--session` is a usage answer, not a crash: exit 1 and one line.
#[test]
fn an_unknown_session_exits_1() {
    let root = tempfile::tempdir().unwrap();
    let home = broken_home(root.path());
    let state = root.path().join("state");
    let project = root.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let out = run(
        &home,
        &state,
        &project,
        &["access", "--session", "deadbeef"],
    );
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr).trim(),
        "no session deadbeef in this project's running sessions or refusal log"
    );
}

/// The project hash `access` looks under: the 12-hex prefix of SHA-256 over the
/// canonical project directory (`project.rs::digest_hex`).
fn hash_project(project: &Path) -> String {
    use sha2::{Digest, Sha256};
    use std::os::unix::ffi::OsStrExt;
    let path = project.canonicalize().unwrap();
    Sha256::digest(path.as_os_str().as_bytes())[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// One logged session, as the launcher persists it.
fn logged_session(id: &str, started_ms: i64, ended_ms: Option<i64>) -> String {
    let entry = serde_json::json!({
        "id": "0e7e41fb",
        "key": {"kind": "network_denial", "destination": {
            "variant": "address", "protocol": "tcp", "ip": "203.0.113.10", "port": 443}},
        "layer": "tenant", "last_site": "tcp-syn", "last_ip": "203.0.113.10",
        "name": null, "last_revision": 1, "count": 1,
        "first_ms": started_ms + 1_000, "last_ms": started_ms + 1_000
    });
    serde_json::json!({
        "info": {"id": id, "pid": 1, "started_ms": started_ms, "socket": true},
        "rev": 2,
        "ended_ms": ended_ms,
        "heartbeat_ms": ended_ms.unwrap_or(started_ms + 1_000),
        "suppressed": 0, "lost": 0, "gap": false,
        "entries": [entry]
    })
    .to_string()
}

/// The whole command as a user runs it, against a real project directory and the
/// log a launcher wrote: an orderly end reads `ended`, a killed launcher reads
/// `ended (unclean)`, `--session` narrows to one of them, and neither run changes
/// a byte of the log.
#[test]
fn access_reports_a_logged_session_as_a_user_reads_it() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = tempfile::tempdir().unwrap();
    let home = broken_home(root.path());
    let state = root.path().join("state");
    let project = root.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let sessions = state.join(format!("{}.sessions", hash_project(&project)));
    std::fs::create_dir_all(&sessions).unwrap();
    std::fs::set_permissions(&sessions, std::fs::Permissions::from_mode(0o700)).unwrap();
    let record = sessions.join("refusals.json");
    let bytes = format!(
        "{{\"v\":1,\"evicted_sessions\":0,\"sessions\":[{},{}]}}",
        logged_session("aaaaaaaa", now - 120_000, Some(now - 60_000)),
        logged_session("bbbbbbbb", now - 90_000, None),
    );
    std::fs::write(&record, &bytes).unwrap();
    std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o600)).unwrap();

    let out = run(&home, &state, &project, &["access"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    let ended = stdout
        .lines()
        .find(|line| line.starts_with("0e7e41fb "))
        .unwrap_or_else(|| panic!("no row: {stdout}"));
    assert!(ended.contains("  ended  "), "the orderly one: {ended:?}");
    let table = stdout
        .lines()
        .filter(|line| line.starts_with("0e7e41fb "))
        .collect::<Vec<_>>();
    assert_eq!(table.len(), 2, "one row per session: {stdout}");
    assert!(
        table
            .iter()
            .any(|line| line.contains("  ended (unclean)  ")),
        "the killed launcher says so: {stdout}"
    );

    let out = run(
        &home,
        &state,
        &project,
        &["access", "--session", "bbbbbbbb"],
    );
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout
            .lines()
            .filter(|l| l.starts_with("0e7e41fb "))
            .count(),
        1,
        "--session shows one session: {stdout}"
    );
    assert!(stdout.contains("ended (unclean)"), "{stdout}");

    assert_eq!(
        std::fs::read(&record).unwrap(),
        bytes.as_bytes(),
        "reading a refusal log changes nothing"
    );
}

// ---------------------------------------------------------------------------
// ADR-0065: `access` reads the project allowance record
// ---------------------------------------------------------------------------

#[path = "support/authority_snapshot.rs"]
mod authority_snapshot;

/// A `$HOME` whose config is a *path a launch would refuse*, and whose
/// authority directory is a real 0700 directory: what `access` needs is only the
/// second, because the first is never read by this command.
fn home_with_authority_dir(root: &Path) -> (PathBuf, PathBuf) {
    let home = broken_home(root);
    let dir = authority_snapshot::empty_authority_dir(&home);
    (home, dir)
}

fn digest_of(project: &Path) -> String {
    use sha2::{Digest as _, Sha256};
    use std::os::unix::ffi::OsStrExt as _;
    let path = project.canonicalize().unwrap();
    Sha256::digest(path.as_os_str().as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The store a later release would write, hand-written as literal JSON.
fn write_allowances(dir: &Path, project: &Path, destination: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let path = project.canonicalize().unwrap();
    let file = dir.join("allowances.json");
    std::fs::write(
        &file,
        format!(
            r#"{{"v":1,"records":[{{"project":"{}","path":"{}","destination":"{destination}","recorded_ms":1760000000000}}]}}"#,
            digest_of(project),
            path.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    file
}

/// One logged session whose single entry is an address denial of
/// `203.0.113.10:443`.
fn logged_address_session(id: &str, now: i64) -> String {
    serde_json::json!({
        "info": {"id": id, "pid": 1, "started_ms": now - 60_000, "socket": true},
        "rev": 2, "ended_ms": Some(now - 30_000), "heartbeat_ms": now - 30_000,
        "suppressed": 0, "lost": 0, "gap": false,
        "entries": [{
            "id": "0e7e41fb",
            "key": {"kind": "network_denial", "destination": {
                "variant": "address", "protocol": "tcp", "ip": "203.0.113.10", "port": 443}},
            "layer": "tenant", "last_site": "tcp-syn", "last_ip": "203.0.113.10",
            "name": null, "last_revision": 1, "count": 1,
            "first_ms": now - 50_000, "last_ms": now - 50_000
        }]
    })
    .to_string()
}

fn seed_session_log(state: &Path, project: &Path, now: i64) {
    use std::os::unix::fs::PermissionsExt as _;
    let sessions = state.join(format!("{}.sessions", hash_project(project)));
    std::fs::create_dir_all(&sessions).unwrap();
    std::fs::set_permissions(&sessions, std::fs::Permissions::from_mode(0o700)).unwrap();
    let record = sessions.join("refusals.json");
    let bytes = format!(
        "{{\"v\":1,\"evicted_sessions\":0,\"sessions\":[{}]}}",
        logged_address_session("aaaaaaaa", now)
    );
    std::fs::write(&record, bytes).unwrap();
    std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

/// AC9's positive production control: the real binary loads the store and shows
/// a covered row. Without this, every other `access` test would pass with the
/// store never read.
#[test]
fn the_binary_loads_the_store_and_shows_a_recorded_row() {
    let root = tempfile::tempdir().unwrap();
    let (home, authority) = home_with_authority_dir(root.path());
    let state = root.path().join("state");
    let project = root.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    seed_session_log(&state, &project, now_ms());
    write_allowances(&authority, &project, "tcp://[203.0.113.10/32]:443");

    let out = run(&home, &state, &project, &["access"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let row = stdout
        .lines()
        .find(|line| line.starts_with("0e7e41fb "))
        .unwrap_or_else(|| panic!("no row: {stdout}"));
    assert!(
        row.contains(
            "recorded project allowance tcp://[203.0.113.10/32]:443 (2025-10-09 08:53Z); not confirmed for this session"
        ),
        "{row}"
    );
    assert!(!row.contains("no grant in this version"), "{row}");
}

/// A damaged or untrusted store is one warning on stderr, makes no row claim,
/// and changes nothing on disk.
#[test]
fn damaged_and_untrusted_stores_warn_and_change_nothing() {
    use std::os::unix::fs::PermissionsExt as _;
    for (row, corrupt) in [("damaged", 0u8), ("untrusted", 1), ("newer", 2)] {
        let root = tempfile::tempdir().unwrap();
        let (home, authority) = home_with_authority_dir(root.path());
        let state = root.path().join("state");
        let project = root.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        seed_session_log(&state, &project, now_ms());
        // Every row starts from a record that would cover the session's entry
        // (`203.0.113.10:443`), so "makes no row claim" can fail: a store the
        // command wrongly trusted would print the covered ACTION cell.
        const COVERING: &str = "tcp://[203.0.113.10/32]:443";
        let file = match corrupt {
            0 => {
                let file = write_allowances(&authority, &project, COVERING);
                std::fs::write(&file, b"not json").unwrap();
                file
            }
            1 => {
                let file = write_allowances(&authority, &project, COVERING);
                std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
                file
            }
            _ => {
                // A newer file that *does* carry a covering record: applying
                // one token's worth of it would show up as a covered row.
                let file = write_allowances(&authority, &project, COVERING);
                let path = project.canonicalize().unwrap();
                std::fs::write(
                    &file,
                    format!(
                        r#"{{"v":2,"records":[{{"project":"{}","path":"{}","destination":"{COVERING}","recorded_ms":1760000000000}}],"added":true}}"#,
                        digest_of(&project),
                        path.display()
                    ),
                )
                .unwrap();
                std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
                file
            }
        };
        // The store's own facts, before the command runs.
        let before = authority_snapshot::take(&authority);
        let out = run(&home, &state, &project, &["access"]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{row}: {stderr}");
        assert_eq!(
            stderr
                .lines()
                .filter(|line| line.starts_with("warning: "))
                .count(),
            1,
            "{row}: {stderr}"
        );
        assert!(stderr.contains("allowances.json"), "{row}: {stderr}");
        assert_eq!(
            authority_snapshot::take(&authority),
            before,
            "{row}: access changed the authority directory"
        );
        assert!(file.exists(), "{row}: the store was removed");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            !stdout.contains("recorded project allowance"),
            "{row}: {stdout}"
        );
        let row_text = stdout
            .lines()
            .find(|line| line.starts_with("0e7e41fb "))
            .unwrap_or_else(|| panic!("{row}: no row: {stdout}"));
        assert!(
            row_text.contains("no grant in this version"),
            "{row}: a store this build must not use changed the row: {row_text}"
        );
    }
}

/// A state-root override with no `$HOME` is silent: no user config is read at
/// all then (ADR-0038), so there is no store and nothing to report.
#[test]
fn home_unset_with_state_override_is_silent() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    let project = root.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    seed_session_log(&state, &project, now_ms());
    let out = std::process::Command::new(agent_vm())
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("AGENT_VM_STATE_DIR", &state)
        .env("MSB_PATH", root.path().join("no-such-msb"))
        .current_dir(&project)
        .arg("access")
        .output()
        .expect("running agent-vm");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(!stderr.contains("allowance"), "{stderr}");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("no grant in this version"),
        "{stderr}"
    );
}

/// A `$HOME` that is set but relative is one warning, and the command still
/// answers.
#[test]
fn home_relative_with_state_override_warns() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    let project = root.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    seed_session_log(&state, &project, now_ms());
    let out = std::process::Command::new(agent_vm())
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", "relative/home")
        .env("AGENT_VM_STATE_DIR", &state)
        .env("MSB_PATH", root.path().join("no-such-msb"))
        .current_dir(&project)
        .arg("access")
        .output()
        .expect("running agent-vm");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(
        stderr.contains(
            "warning: project allowances not read: $HOME \"relative/home\" is not absolute"
        ),
        "{stderr}"
    );
}

/// R5: asking never creates the store's answer.
#[test]
fn access_creates_nothing_in_the_authority_dir() {
    let root = tempfile::tempdir().unwrap();
    let (home, authority) = home_with_authority_dir(root.path());
    let state = root.path().join("state");
    let project = root.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    seed_session_log(&state, &project, now_ms());
    let before = authority_snapshot::take(&authority);
    let out = run(&home, &state, &project, &["access"]);
    assert!(out.status.success());
    assert_eq!(authority_snapshot::take(&authority), before);
    assert!(!authority.join("allowances.json").exists());
    assert!(!authority.join("allowances.lock").exists());
}
