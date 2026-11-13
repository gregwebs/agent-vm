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

/// One logged credential refusal, with the fields PR 3 renders. Written by hand
/// so the row is asserted as a user reads it through the real binary.
fn logged_credential_refusal(id: &str, started_ms: i64) -> String {
    let entry = serde_json::json!({
        "id": "5ec0de01",
        "key": {"kind": "credential_refusal", "destination": {
            "variant": "host", "protocol": "tcp", "name": "api.deepseek.com", "port": 443},
            "credential": "MSB_AGENT_VM_ANTHROPIC_UNUSED"},
        "layer": "tenant", "last_site": "secret-violation", "last_ip": null,
        "name": null, "last_location": "header", "last_reason": "host-not-covered",
        "last_revision": 1, "count": 1,
        "first_ms": started_ms + 1_000, "last_ms": started_ms + 1_000
    });
    serde_json::json!({
        "info": {"id": id, "pid": 1, "started_ms": started_ms, "socket": true},
        "rev": 2,
        "ended_ms": started_ms + 2_000,
        "heartbeat_ms": started_ms + 2_000,
        "suppressed": 0, "lost": 0, "gap": false,
        "entries": [entry]
    })
    .to_string()
}

/// #562: outside the sandbox, `agent-vm access` says which credential was refused,
/// where it was sent and why its secret could not serve it.
#[test]
fn access_reports_a_credential_refusal_as_a_user_reads_it() {
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
    std::fs::write(
        &record,
        format!(
            "{{\"v\":1,\"evicted_sessions\":0,\"sessions\":[{}]}}",
            logged_credential_refusal("aaaaaaaa", now - 120_000),
        ),
    )
    .unwrap();
    std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o600)).unwrap();

    let out = run(&home, &state, &project, &["access"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    let row = stdout
        .lines()
        .find(|line| line.starts_with("5ec0de01 "))
        .unwrap_or_else(|| panic!("no row: {stdout}"));
    assert!(row.contains("credential refusal"), "{row:?}");
    assert!(
        row.ends_with(
            "can't be allowed here: credential policy; MSB_AGENT_VM_ANTHROPIC_UNUSED was sent in \
             a request header, and its secret does not cover the destination"
        ),
        "{row:?}"
    );
    let err_text = String::from_utf8_lossy(&out.stderr);
    assert!(!err_text.contains("could not be used"), "{err_text}");

    // And `allow` cannot turn it into a rule: the message repeats the row's own
    // reason, so a reader who tried the wrong command learns why it cannot work.
    let out = run(&home, &state, &project, &["access", "allow", "5ec0de01"]);
    assert_eq!(out.status.code(), Some(1));
    let expected = "cannot allow 5ec0de01: this refusal is not a network denial this command can allow (can't be allowed here: credential policy; MSB_AGENT_VM_ANTHROPIC_UNUSED was sent in a request header, and its secret does not cover the destination)";
    let text = stderr(&out);
    assert!(text.lines().any(|line| line == expected), "{text}");
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

/// `access` reads the store for *this* project only: a record under another
/// project's digest is a row it must not claim, which is what makes a moved or
/// copied checkout inherit nothing here as well as at launch (ADR-0065 P2).
#[test]
fn a_record_for_another_project_claims_nothing() {
    let root = tempfile::tempdir().unwrap();
    let (home, authority) = home_with_authority_dir(root.path());
    let state = root.path().join("state");
    let project = root.path().join("project");
    let other = root.path().join("other");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(&other).unwrap();
    seed_session_log(&state, &project, now_ms());
    // The same destination the session was denied, under a *different* project.
    write_allowances(&authority, &other, "tcp://[203.0.113.10/32]:443");

    let out = run(&home, &state, &project, &["access"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(!stderr.contains("warning:"), "{stderr}");
    assert!(!stdout.contains("recorded project allowance"), "{stdout}");
    let row = stdout
        .lines()
        .find(|line| line.starts_with("0e7e41fb "))
        .unwrap_or_else(|| panic!("no row: {stdout}"));
    assert!(row.contains("no grant in this version"), "{row}");
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

// ---------------------------------------------------------------------------
// ADR-0066: `access allow`, `access revoke` and `access allowances` as processes
//
// Every case here crosses the process boundary: the binary is spawned with a
// real `$HOME`, a real state root and a real project directory, and it reaches a
// *live* session over a real Unix socket. The crate is a binary, so an
// integration test cannot build a `LiveSession`; what it can do is speak the
// protocol one speaks, which is the boundary these cases are about. `FakeSession`
// below is that peer: it answers each request with a literal JSON line, and it
// records what it was asked, so a case can assert the *request* (scope,
// destination) and not only the rendering.
// ---------------------------------------------------------------------------

mod control_socket {
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::os::unix::{
        fs::{FileTypeExt as _, PermissionsExt as _},
        net::{UnixListener, UnixStream},
    };
    use std::path::{Path, PathBuf};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    };
    use std::thread::JoinHandle;

    /// The four answers one session can give this command.
    pub struct Replies {
        pub list: String,
        pub allowances: String,
        pub grant: String,
        pub revoke: String,
        /// A project grant's *other* half. The launcher, not the CLI, writes the
        /// record — `GrantResult::Applied { scope: Project }` means it did — so a
        /// fake launcher that answered `Applied` without recording would be a
        /// launcher that lied. `(file, contents)` is that write.
        pub grant_records: Option<(PathBuf, String)>,
    }

    /// A live session's end of the control socket, driven by the test.
    pub struct FakeSession {
        path: PathBuf,
        requests: Arc<Mutex<Vec<String>>>,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl FakeSession {
        /// Bind `<id>.sock` in `dir`, which must be the project's sessions
        /// directory: discovery reads the directory, never a registry.
        pub fn start(dir: &Path, id: &str, replies: Replies) -> FakeSession {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            let path = dir.join(format!("{id}.sock"));
            let _ = std::fs::remove_file(&path);
            let listener = UnixListener::bind(&path).unwrap();
            let requests = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let recorded = Arc::clone(&requests);
            let stopping = Arc::clone(&stop);
            let thread = std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stopping.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = stream else { break };
                    if let Err(error) = answer(stream, &replies, &recorded) {
                        recorded.lock().unwrap().push(format!("<error: {error}>"));
                    }
                }
            });
            FakeSession {
                path,
                requests,
                stop,
                thread: Some(thread),
            }
        }

        pub fn path(&self) -> &Path {
            &self.path
        }

        /// Every request line received, in order.
        pub fn requests(&self) -> Vec<String> {
            self.requests.lock().unwrap().clone()
        }

        /// The one request whose `op` is `op`.
        pub fn request(&self, op: &str) -> String {
            let wanted = format!("\"op\":\"{op}\"");
            let matches: Vec<String> = self
                .requests()
                .into_iter()
                .filter(|line| line.contains(&wanted))
                .collect();
            assert_eq!(matches.len(), 1, "{op} requests: {matches:?}");
            assert!(
                matches[0].contains("\"v\":2"),
                "a mutation is v2: {}",
                matches[0]
            );
            matches[0].clone()
        }
    }

    impl Drop for FakeSession {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            // One last dial: the accept loop only checks the flag after a
            // connection, so this is what makes the thread leave `incoming()`.
            let _ = UnixStream::connect(&self.path);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    fn answer(
        stream: UnixStream,
        replies: &Replies,
        requests: &Arc<Mutex<Vec<String>>>,
    ) -> std::io::Result<()> {
        let mut reader = BufReader::new(&stream);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        requests.lock().unwrap().push(line.trim_end().to_owned());
        let reply = if line.contains("\"op\":\"list\"") {
            &replies.list
        } else if line.contains("\"op\":\"allowances\"") {
            &replies.allowances
        } else if line.contains("\"op\":\"grant\"") {
            if line.contains("\"scope\":\"project\"")
                && let Some((file, contents)) = &replies.grant_records
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::write(file, contents)?;
                std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600))?;
            }
            &replies.grant
        } else {
            &replies.revoke
        };
        if reply.is_empty() {
            // No answer at all: the connection closes, which is how a session
            // that cannot confirm reaches the client.
            return Ok(());
        }
        let mut writer = &stream;
        writer.write_all(reply.as_bytes())?;
        writer.write_all(b"\n")?;
        writer.flush()
    }

    /// Whether `path` is a socket owned by this user: what discovery requires
    /// before it will dial an entry at all.
    pub fn is_our_socket(path: &Path) -> bool {
        std::fs::symlink_metadata(path)
            .map(|metadata| metadata.file_type().is_socket())
            .unwrap_or(false)
    }
}

use control_socket::{FakeSession, Replies};

/// 2025-10-09T08:53:20Z, the instant `write_allowances` records.
const RECORDED_MS: i64 = 1_760_000_000_000;
const REFUSAL_ID: &str = "0e7e41fb";
const SESSION_ID: &str = "aaaaaaaa";
const DESTINATION: &str = "tcp://[203.0.113.10/32]:443";

fn sessions_dir(state: &Path, project: &Path) -> PathBuf {
    state.join(format!("{}.sessions", hash_project(project)))
}

/// One session, as `list` renders it: `ended_ms` decides `ended`, `socket`
/// decides whether it can be dialed.
fn session_line(id: &str, now: i64, socket: bool, ended: bool) -> String {
    serde_json::json!({
        "info": {"id": id, "pid": 1, "started_ms": now - 60_000, "socket": socket},
        "rev": 2,
        "ended_ms": if ended { Some(now - 30_000) } else { None },
        "heartbeat_ms": now - 30_000,
        "suppressed": 0, "lost": 0, "gap": false,
        "entries": [{
            "id": REFUSAL_ID,
            "key": {"kind": "network_denial", "destination": {
                "variant": "address", "protocol": "tcp", "ip": "203.0.113.10", "port": 443}},
            "layer": "tenant", "last_site": "tcp-syn", "last_ip": "203.0.113.10",
            "name": null, "last_revision": 1, "count": 1,
            "first_ms": now - 50_000, "last_ms": now - 50_000
        }]
    })
    .to_string()
}

/// Write the session log a launcher leaves: one record per session, newest last.
fn write_session_log(dir: &Path, sessions: &str) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::create_dir_all(dir).unwrap();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let record = dir.join("refusals.json");
    std::fs::write(
        &record,
        format!("{{\"v\":1,\"evicted_sessions\":0,\"sessions\":[{sessions}]}}"),
    )
    .unwrap();
    std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// The one reply shape every case starts from: a v1 `list` and an empty v2
/// `allowances` answer, which is what a launcher with no live allowance says.
fn replies(now: i64, socket: bool, ended: bool, grant: &str, revoke: &str) -> Replies {
    Replies {
        list: format!(
            "{{\"reply\":\"session\",\"v\":1,\"session\":{}}}",
            session_line(SESSION_ID, now, socket, ended)
        ),
        allowances:
            "{\"reply\":\"allowances\",\"v\":2,\"allowances\":{\"session\":[],\"project\":[]}}"
                .to_owned(),
        grant: grant.to_owned(),
        revoke: revoke.to_owned(),
        grant_records: None,
    }
}

/// The record a launcher writes for a confirmed `--project` grant.
fn record_json(project: &Path, destination: &str) -> String {
    format!(
        r#"{{"v":1,"records":[{{"project":"{}","path":"{}","destination":"{destination}","recorded_ms":{RECORDED_MS}}}]}}"#,
        digest_of(project),
        project.canonicalize().unwrap().display()
    )
}

fn applied_grant(destination: &str, scope: &str, revision: u64) -> String {
    format!(
        "{{\"reply\":\"grant\",\"v\":2,\"result\":{{\"Applied\":{{\"destination\":\"{destination}\",\
         \"scope\":\"{scope}\",\"revision\":{revision},\"recorded_ms\":{RECORDED_MS}}}}}}}"
    )
}

/// The store as a later launch reads it: parsed, because the writer's own bytes
/// order and mode are the store's business, not this command's.
fn store_records(file: &Path) -> Vec<serde_json::Value> {
    let text =
        std::fs::read_to_string(file).unwrap_or_else(|error| panic!("{}: {error}", file.display()));
    let value: serde_json::Value = serde_json::from_str(&text).expect("the store is JSON");
    assert_eq!(value["v"], 1, "the record version: {text}");
    value["records"].as_array().cloned().unwrap_or_default()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// AC2 through the process boundary: one project-scoped grant, addressed to the
/// destination the refusal named, and a store the command did not write itself.
///
/// What this test **can** see: the CLI sends exactly one `grant` with
/// `"scope":"project"` and the refusal's spelling, the record it then reads is
/// under *this* project's digest, and a second project — same `$HOME`, its own
/// state root — reads nothing from it.
///
/// What it **cannot** see: the write *order*. On the live path the launcher, not
/// the CLI, writes the record, so this fixture's `FakeSession` writes it while
/// answering the grant (`Replies::grant_records`); moving `store.record` above
/// `update_network_policy` in the launcher would leave this test green. The order
/// is pinned in process, by
/// `access_cmd::tests::project_grant_writes_no_record_when_live_session_cannot_confirm`
/// (B-S1, m15).
#[test]
fn allow_project_writes_store_updates_live_session_and_isolates_other_projects() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = tempfile::tempdir().unwrap();
    let (home, authority) = home_with_authority_dir(root.path());
    let state = root.path().join("state");
    let project = root.path().join("project");
    let other = root.path().join("other");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(&other).unwrap();
    let now = now_ms();
    let dir = sessions_dir(&state, &project);
    write_session_log(&dir, &session_line(SESSION_ID, now, true, false));
    let fake = FakeSession::start(
        &dir,
        SESSION_ID,
        Replies {
            grant_records: Some((
                authority.join("allowances.json"),
                record_json(&project, DESTINATION),
            )),
            ..replies(
                now,
                true,
                false,
                &applied_grant(DESTINATION, "Project", 2),
                "",
            )
        },
    );

    let out = run(
        &home,
        &state,
        &project,
        &["access", "allow", REFUSAL_ID, "--project"],
    );
    let text = stdout(&out);
    assert!(
        out.status.success(),
        "stdout: {text}\nstderr: {}",
        stderr(&out)
    );
    assert!(
        text.contains(&format!(
            "allowed {DESTINATION} for session {SESSION_ID} (running) (policy revision 2) and recorded for this project"
        )),
        "{text}"
    );

    // The live half: the socket was asked for exactly this, in the project scope.
    let grant = fake.request("grant");
    assert!(grant.contains("\"scope\":\"project\""), "{grant}");
    assert!(
        grant.contains(&format!("\"destination\":\"{DESTINATION}\"")),
        "{grant}"
    );

    // The durable half: one record, this project's digest, 0600 — the record the
    // launcher writes when its reply says `scope: project`.
    let file = authority.join("allowances.json");
    let records = store_records(&file);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["project"], digest_of(&project));
    assert_eq!(records[0]["destination"], DESTINATION);
    assert_eq!(
        records[0]["path"],
        project.canonicalize().unwrap().display().to_string()
    );
    assert_eq!(
        std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(
        control_socket::is_our_socket(fake.path()),
        "the session stayed live"
    );

    // Isolation: another project reads the same store and claims nothing.
    let before = std::fs::read(&file).unwrap();
    let out = run(&home, &state, &other, &["access", "allowances"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "No allowances.\n");
    assert_eq!(
        std::fs::read(&file).unwrap(),
        before,
        "reading from another project changed the store"
    );
}

/// AC1 through the process boundary: a session-only grant is live and durable
/// in no way at all — the authority directory keeps its exact bytes, and gains
/// neither the record nor the writer's lock.
#[test]
fn allow_session_updates_live_session_and_leaves_authority_dir_untouched() {
    let root = tempfile::tempdir().unwrap();
    let (home, authority) = home_with_authority_dir(root.path());
    let state = root.path().join("state");
    let project = root.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let now = now_ms();
    let dir = sessions_dir(&state, &project);
    write_session_log(&dir, &session_line(SESSION_ID, now, true, false));
    let fake = FakeSession::start(
        &dir,
        SESSION_ID,
        replies(
            now,
            true,
            false,
            &applied_grant(DESTINATION, "Session", 2),
            "",
        ),
    );
    let before = authority_snapshot::take(&authority);

    let out = run(&home, &state, &project, &["access", "allow", REFUSAL_ID]);
    let text = stdout(&out);
    assert!(out.status.success(), "{text}{}", stderr(&out));
    assert!(
        text.contains("(policy revision 2)") && !text.contains("recorded for this project"),
        "a session grant claims no record: {text}"
    );
    assert!(fake.request("grant").contains("\"scope\":\"session\""));
    assert_eq!(
        authority_snapshot::take(&authority),
        before,
        "a session-only grant touched the authority directory"
    );
}

/// AC2's offline half through the process boundary: a session that has ended can
/// have its refusal recorded for the next launch, and nothing else.
#[test]
fn allow_on_ended_session_records_project_and_refuses_session_only() {
    let root = tempfile::tempdir().unwrap();
    let (home, authority) = home_with_authority_dir(root.path());
    let state = root.path().join("state");
    let project = root.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let now = now_ms();
    let dir = sessions_dir(&state, &project);
    write_session_log(&dir, &session_line(SESSION_ID, now, false, true));

    let out = run(&home, &state, &project, &["access", "allow", REFUSAL_ID]);
    assert_eq!(out.status.code(), Some(1));
    let text = stderr(&out);
    assert!(
        text.contains(&format!("session {SESSION_ID} (ended) has ended")),
        "{text}"
    );
    assert!(
        text.contains("session-only allowance cannot be recorded"),
        "{text}"
    );
    assert!(
        !authority.join("allowances.json").exists(),
        "a refused command wrote the store"
    );

    let out = run(
        &home,
        &state,
        &project,
        &["access", "allow", REFUSAL_ID, "--project"],
    );
    let text = stdout(&out);
    assert!(out.status.success(), "{text}{}", stderr(&out));
    assert!(
        text.contains("the next launch of this project applies it"),
        "{text}"
    );
    let records = store_records(&authority.join("allowances.json"));
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["project"], digest_of(&project));
    assert_eq!(records[0]["destination"], DESTINATION);
}

fn seeded_store(authority: &Path, project: &Path) {
    write_allowances(authority, project, DESTINATION);
}

/// Whether the store still carries this project's record for `DESTINATION`.
fn store_carries(authority: &Path, project: &Path, destination: &str) -> bool {
    store_records(&authority.join("allowances.json"))
        .iter()
        .any(|row| row["project"] == digest_of(project) && row["destination"] == destination)
}

/// AC6/R10 through the process boundary: the record goes even when the session
/// cannot confirm, and the command says which session, why, and what the
/// guaranteed cut is — exiting non-zero.
#[test]
fn revoke_deletes_project_record_even_when_session_cannot_confirm() {
    let root = tempfile::tempdir().unwrap();
    let (home, authority) = home_with_authority_dir(root.path());
    let state = root.path().join("state");
    let project = root.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let now = now_ms();
    let dir = sessions_dir(&state, &project);
    // A live session that bound no control socket, and one that has ended: the
    // two unconfirmed targets this host can produce without a runtime.
    write_session_log(
        &dir,
        &format!(
            "{},{}",
            session_line(SESSION_ID, now, false, false),
            session_line("bbbbbbbb", now, false, true)
        ),
    );
    seeded_store(&authority, &project);

    let out = run(&home, &state, &project, &["access", "revoke", DESTINATION]);
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    let text = stderr(&out);
    assert!(
        text.contains(&format!(
            "session {SESSION_ID} (running (no control socket)) cannot confirm a live revoke"
        )),
        "{text}"
    );
    assert!(text.contains("the project record was deleted"), "{text}");
    assert!(
        text.contains("Stopping the session is the guaranteed hard cut"),
        "{text}"
    );
    assert!(
        !store_carries(&authority, &project, DESTINATION),
        "the record survived an unconfirmed revoke"
    );

    // The same claim for an explicitly named session that ended.
    seeded_store(&authority, &project);
    assert!(store_carries(&authority, &project, DESTINATION));
    let out = run(
        &home,
        &state,
        &project,
        &["access", "revoke", DESTINATION, "--session", "bbbbbbbb"],
    );
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    let text = stderr(&out);
    assert!(
        text.contains("session bbbbbbbb (ended) cannot confirm a live revoke"),
        "{text}"
    );
    assert!(
        !store_carries(&authority, &project, DESTINATION),
        "the record survived a revoke targeting an ended session"
    );
}

/// AC5 through the process boundary: `--project` removes the record and asks the
/// session for the project scope only, so a session allowance for the same
/// destination stays in force.
#[test]
fn revoke_project_deletes_the_record_and_renders_the_still_effective_clause() {
    let root = tempfile::tempdir().unwrap();
    let (home, authority) = home_with_authority_dir(root.path());
    let state = root.path().join("state");
    let project = root.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let now = now_ms();
    let dir = sessions_dir(&state, &project);
    write_session_log(&dir, &session_line(SESSION_ID, now, true, false));
    seeded_store(&authority, &project);
    let held = format!(
        "{{\"destination\":\"{DESTINATION}\",\"granted_ms\":{RECORDED_MS},\"revision\":2,\
         \"not_recorded_error\":null}}"
    );
    let mut answers = replies(now, true, false, "", "");
    answers.allowances = format!(
        "{{\"reply\":\"allowances\",\"v\":2,\"allowances\":{{\"session\":[{held}],\
         \"project\":[{held}]}}}}"
    );
    answers.revoke = format!(
        "{{\"reply\":\"revoke\",\"v\":2,\"result\":{{\"Revoked\":{{\"destination\":\"{DESTINATION}\",\
         \"scope\":\"Project\",\"revision\":3,\"still_effective\":true}}}}}}"
    );
    let fake = FakeSession::start(&dir, SESSION_ID, answers);

    let out = run(
        &home,
        &state,
        &project,
        &["access", "revoke", DESTINATION, "--project"],
    );
    let text = stdout(&out);
    assert!(out.status.success(), "{text}{}", stderr(&out));
    assert!(
        text.contains(&format!(
            "revoked {DESTINATION} for session {SESSION_ID} (running) (policy revision 3); the project record was deleted"
        )),
        "{text}"
    );
    assert!(
        text.contains("is still in force from this launch's own --allow-egress or the other scope"),
        "the session allowance must be named as still in force: {text}"
    );
    assert!(fake.request("revoke").contains("\"scope\":\"project\""));
    assert!(
        !store_carries(&authority, &project, DESTINATION),
        "the project record survived"
    );
}

/// AC9 through the process boundary: one table, recorded project rows first, then
/// the session's own rows, each with its own status.
#[test]
fn allowances_lists_project_and_session_entries() {
    let root = tempfile::tempdir().unwrap();
    let (home, authority) = home_with_authority_dir(root.path());
    let state = root.path().join("state");
    let project = root.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let now = now_ms();
    let dir = sessions_dir(&state, &project);
    write_session_log(&dir, &session_line(SESSION_ID, now, true, false));
    seeded_store(&authority, &project);
    const SESSION_ONLY: &str = "udp://[203.0.113.10/32]:53";
    let entry = |destination: &str| {
        format!(
            "{{\"destination\":\"{destination}\",\"granted_ms\":{RECORDED_MS},\"revision\":2,\
             \"not_recorded_error\":null}}"
        )
    };
    let mut answers = replies(now, true, false, "", "");
    answers.allowances = format!(
        "{{\"reply\":\"allowances\",\"v\":2,\"allowances\":{{\"session\":[{}],\"project\":[{}]}}}}",
        entry(SESSION_ONLY),
        entry(DESTINATION)
    );
    let _fake = FakeSession::start(&dir, SESSION_ID, answers);

    let out = run(&home, &state, &project, &["access", "allowances"]);
    let text = stdout(&out);
    assert!(out.status.success(), "{text}{}", stderr(&out));
    assert!(text.starts_with("SCOPE"), "{text}");
    let header = text.lines().next().unwrap();
    assert!(
        header.contains("DESTINATION") && header.contains("STATUS"),
        "{text}"
    );
    let project_row = text
        .lines()
        .find(|line| line.starts_with("project ") && line.contains(DESTINATION))
        .unwrap_or_else(|| panic!("no project row: {text}"));
    assert!(project_row.contains(SESSION_ID), "{project_row}");
    assert!(project_row.contains("applied (rev 2)"), "{project_row}");
    let session_row = text
        .lines()
        .find(|line| line.starts_with("session ") && line.contains(SESSION_ONLY))
        .unwrap_or_else(|| panic!("no session row: {text}"));
    assert!(session_row.contains(SESSION_ID), "{session_row}");
    assert!(session_row.contains("applied (rev 2)"), "{session_row}");
}
