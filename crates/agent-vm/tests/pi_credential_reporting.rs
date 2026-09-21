//! Black-box proof that `agent-vm doctor`'s guest-managed Pi report is
//! **observational** and **non-resolving** (issue #93).
//!
//! Spawns the real compiled binary with a hermetic `$HOME` / state dir / cwd,
//! a private `$PATH` full of executable **sentinels**, and an intentionally
//! failing `MSB_PATH` sentinel. Every sentinel appends its identity to a
//! marker file and exits nonzero, so a nonempty marker after a run is proof
//! that something was executed. Guest credentials are seeded with
//! `!command` values, environment references and canaries, and separate host
//! Pi files with distinct canaries, so a leak in stdout/stderr/debug logs, or
//! a write to the state tree, is observable.
//!
//! A marker test is only worth something if the sentinels are live, so
//! `sentinels_are_live` invokes each one in a control fixture and asserts its
//! marker appears; without that, a non-executable or off-PATH sentinel would
//! make every other assertion vacuous.

use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

fn agent_vm_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-vm"))
}

/// Run `child` to completion, killing it if it doesn't exit in time, reading
/// both pipes on threads so a full pipe can't deadlock. Duplicated across
/// integration test binaries (they are separate crates).
fn run_with_timeout(mut cmd: Command, timeout: Duration) -> Output {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("failed to spawn agent-vm");
    let mut stdout_pipe = child.stdout.take().unwrap();
    let mut stderr_pipe = child.stderr.take().unwrap();
    let stdout_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buf);
        buf
    });
    let stderr_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf);
        buf
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait failed") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("agent-vm did not exit within {timeout:?} (possible hang)");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Output {
        status,
        stdout: stdout_handle.join().unwrap(),
        stderr: stderr_handle.join().unwrap(),
    }
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Bytes, identity and timestamps of one filesystem entry, so a scan that
/// rewrote, truncated, chmodded or recreated anything is caught.
#[derive(Debug, PartialEq, Eq)]
struct Meta {
    is_dir: bool,
    len: u64,
    mode: u32,
    ino: u64,
    dev: u64,
    nlink: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, Meta> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<PathBuf, Meta>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(relative) = path.strip_prefix(root) else {
                continue;
            };
            // `symlink_metadata` (not `metadata`): a scan that replaced a real
            // directory with a symlink, or vice versa, must change the snapshot.
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            out.insert(
                relative.to_path_buf(),
                Meta {
                    is_dir: meta.is_dir(),
                    len: meta.len(),
                    mode: meta.mode(),
                    ino: meta.ino(),
                    dev: meta.dev(),
                    nlink: meta.nlink(),
                    mtime: (meta.mtime(), meta.mtime_nsec()),
                    ctime: (meta.ctime(), meta.ctime_nsec()),
                },
            );
            if meta.is_dir() {
                walk(root, &path, out);
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

/// Write an executable sentinel that appends `name` to the marker file named
/// by `$SENTINEL_MARKER` and exits nonzero. The binary is never found: if it
/// ran, the marker proves it.
fn write_sentinel(dir: &Path, name: &str) {
    let path = dir.join(name);
    fs::write(
        &path,
        format!("#!/bin/sh\nprintf '%s\\n' '{name}' >> \"$SENTINEL_MARKER\"\nexit 1\n"),
    )
    .unwrap();
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).unwrap();
}

/// One hermetic home / state root / project, a private sentinel `PATH`, and a
/// marker file.
struct Harness {
    _home: tempfile::TempDir,
    _state: tempfile::TempDir,
    _project: tempfile::TempDir,
    home_root: PathBuf,
    state_root: PathBuf,
    project_root: PathBuf,
    bin: PathBuf,
    marker: PathBuf,
}

const SENTINELS: [&str; 6] = ["pi", "claude", "codex", "gh", "msb", "credential-sentinel"];

impl Harness {
    fn new() -> Self {
        let home = tempfile::tempdir_in("/tmp").unwrap();
        let state = tempfile::tempdir_in("/tmp").unwrap();
        let project = tempfile::tempdir_in("/tmp").unwrap();
        let home_root = home.path().canonicalize().unwrap();
        let state_root = state.path().canonicalize().unwrap();
        let project_root = project.path().canonicalize().unwrap();
        let bin = home_root.join("sentinels");
        fs::create_dir_all(&bin).unwrap();
        for name in SENTINELS {
            write_sentinel(&bin, name);
        }
        let marker = home_root.join(".sentinel-marker");
        Self {
            _home: home,
            _state: state,
            _project: project,
            home_root,
            state_root,
            project_root,
            bin,
            marker,
        }
    }

    fn base_command(&self) -> Command {
        let mut cmd = Command::new(agent_vm_bin());
        cmd.env_clear()
            // ONLY the sentinel dir on PATH: any subprocess the binary spawns
            // either hits a sentinel (recorded) or is unavailable.
            .env("PATH", &self.bin)
            .env("HOME", &self.home_root)
            .env("AGENT_VM_STATE_DIR", &self.state_root)
            .env("SENTINEL_MARKER", &self.marker)
            // The deliberately-failing msb sentinel. Ordinary doctor must
            // neither run it nor depend on it.
            .env("MSB_PATH", self.bin.join("msb"))
            .env("AGENT_VM_SHARE_MSB_CACHE", "1")
            .current_dir(&self.project_root);
        cmd
    }

    /// Learn the project state dir from doctor's own report (`state: …`).
    /// Doctor is observational, so this creates nothing; the seed below then
    /// places fixtures at exactly the path the scanner reads.
    fn project_state_dir(&self) -> PathBuf {
        let mut cmd = self.base_command();
        cmd.arg("doctor");
        let out = run_with_timeout(cmd, Duration::from_secs(20));
        assert!(out.status.success(), "{}", stderr_of(&out));
        let text = stdout_of(&out);
        let marker = "state:    ";
        let start = text
            .find(marker)
            .unwrap_or_else(|| panic!("no state dir in doctor output:\n{text}"))
            + marker.len();
        let end = text[start..].find('\n').unwrap_or(text.len() - start);
        PathBuf::from(text[start..start + end].trim())
    }

    fn sentinel_marker_lines(&self) -> Vec<String> {
        fs::read_to_string(&self.marker)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn run_doctor(&self, extra: &[&str]) -> Output {
        let mut cmd = self.base_command();
        cmd.arg("doctor").args(extra);
        run_with_timeout(cmd, Duration::from_secs(20))
    }
}

/// Every canary / reference string that must never appear in output.
fn forbidden(h: &Harness) -> Vec<String> {
    vec![
        "CANARY_GUEST_KEY".to_string(),
        "CANARY_HEADER".to_string(),
        "CANARY_MODEL_HEADER".to_string(),
        "CANARY_HOST_PI_AUTH".to_string(),
        "CANARY_HOST_PI_MODELS".to_string(),
        "CANARY_ENV".to_string(),
        "SECRET_ENV_VAR_NAME".to_string(),
        h.bin.to_string_lossy().into_owned(),
        "credential-sentinel --canary".to_string(),
    ]
}

fn seed_guest_state(state_dir: &Path, host_sentinel: &Path) {
    let agent = state_dir.join("pi/agent");
    fs::create_dir_all(&agent).unwrap();
    let auth = format!(
        r#"{{
  "anthropic": {{"type":"api_key","key":"!{sentinel} --canary CANARY_GUEST_KEY"}},
  "openai": {{"type":"oauth","access":"{access}","refresh":"$SECRET_ENV_VAR_NAME","expires":1}},
  "envprov": {{"type":"api_key","key":"{access}","env":{{"SECRET_ENV_VAR_NAME":"CANARY_ENV"}}}}
}}"#,
        sentinel = host_sentinel.display(),
        access = crate::PLACEHOLDER,
    );
    let models = format!(
        r#"{{
  "providers": {{
    "demo": {{
      "apiKey": "!{sentinel} --canary CANARY_MODELS",
      "headers": {{"Authorization":"Bearer CANARY_HEADER","X-Custom":"${{CANARY_ENV}}"}},
      "models": [{{"id":"m","headers":{{"X-Model":"CANARY_MODEL_HEADER"}}}}]
    }}
  }}
}}"#,
        sentinel = host_sentinel.display(),
    );
    fs::write(agent.join("auth.json"), auth).unwrap();
    fs::write(agent.join("models.json"), models).unwrap();
}

const PLACEHOLDER: &str = "msb-anthropic-placeholder-a-v2";

fn seed_host_pi(home: &Path) {
    let agent = home.join(".pi/agent");
    fs::create_dir_all(&agent).unwrap();
    fs::write(
        agent.join("auth.json"),
        r#"{"anthropic":{"type":"api_key","key":"CANARY_HOST_PI_AUTH"}}"#,
    )
    .unwrap();
    fs::write(
        agent.join("models.json"),
        r#"{"providers":{"host":{"apiKey":"CANARY_HOST_PI_MODELS"}}}"#,
    )
    .unwrap();
}

#[test]
fn sentinels_are_live() {
    let h = Harness::new();
    for name in SENTINELS {
        let status = Command::new(h.bin.join(name))
            .env("SENTINEL_MARKER", &h.marker)
            .status()
            .expect("sentinel should spawn");
        assert!(!status.success(), "sentinel {name} must exit nonzero");
    }
    let lines = h.sentinel_marker_lines();
    for name in SENTINELS {
        assert!(
            lines.iter().any(|line| line == name),
            "missing {name}: {lines:?}"
        );
    }
}

#[test]
fn doctor_reports_guest_fields_without_running_or_leaking_anything() {
    let h = Harness::new();
    let state_dir = h.project_state_dir();
    seed_guest_state(&state_dir, &h.bin.join("credential-sentinel"));
    seed_host_pi(&h.home_root);

    let before = (
        snapshot(&h.state_root),
        snapshot(&h.home_root),
        snapshot(&h.project_root),
    );
    // Run with debug tracing to widen the leak surface.
    let out = run_with_timeout(
        {
            let mut cmd = h.base_command();
            cmd.env("RUST_LOG", "trace").arg("doctor");
            cmd
        },
        Duration::from_secs(20),
    );
    let after = (
        snapshot(&h.state_root),
        snapshot(&h.home_root),
        snapshot(&h.project_root),
    );

    let stdout = stdout_of(&out);
    let stderr = stderr_of(&out);

    assert!(out.status.success(), "doctor failed: {stderr}");
    // The report names provider, kind and fields — and nothing more.
    assert!(
        stdout.contains("auth.json: provider=anthropic type=api_key fields=key"),
        "{stdout}"
    );
    assert!(
        stdout.contains("auth.json: provider=openai type=oauth fields=refresh"),
        "{stdout}"
    );
    assert!(
        stdout.contains("auth.json: provider=envprov type=api_key fields=env"),
        "{stdout}"
    );
    assert!(
        stdout.contains("models.json: provider=demo type=configuration"),
        "{stdout}"
    );

    // No sentinel ran.
    assert!(
        h.sentinel_marker_lines().is_empty(),
        "a sentinel executed: {:?}",
        h.sentinel_marker_lines()
    );

    // No canary, command, environment reference or host-Pi byte reached any
    // stream.
    let combined = format!("{stdout}{stderr}");
    for needle in forbidden(&h) {
        assert!(
            !combined.contains(&needle),
            "leaked {needle:?}:\n{combined}"
        );
    }

    // Nothing changed, and no msb bootstrap happened.
    assert_eq!(before.0, after.0, "doctor changed the state tree");
    assert_eq!(before.1, after.1, "doctor changed the host home tree");
    assert_eq!(before.2, after.2, "doctor changed the project tree");
    assert!(
        !h.state_root.join("msb-home").exists(),
        "doctor created msb-home"
    );

    // Second call is still clean (no "cleanup on the second call" effect).
    let second = h.run_doctor(&[]);
    assert_eq!(
        snapshot(&h.state_root),
        after.0,
        "a second doctor call changed the state tree"
    );
    assert!(h.sentinel_marker_lines().is_empty());
    assert!(second.status.success());
}

#[test]
fn report_is_independent_of_environment_contents() {
    let h = Harness::new();
    let state_dir = h.project_state_dir();
    seed_guest_state(&state_dir, &h.bin.join("credential-sentinel"));

    // Same seed, four different environments: referenced vars unset, empty,
    // real-looking, and command-looking. Classification must not depend on them.
    let mut reports = Vec::new();
    for (unset, value) in [
        (true, ""),
        (false, ""),
        (false, "real-token-bytes"),
        (false, "!echo hi"),
    ] {
        let mut cmd = h.base_command();
        if unset {
            cmd.env_remove("SECRET_ENV_VAR_NAME");
            cmd.env_remove("CANARY_ENV");
        } else {
            cmd.env("SECRET_ENV_VAR_NAME", value);
            cmd.env("CANARY_ENV", value);
        }
        cmd.arg("doctor");
        let out = run_with_timeout(cmd, Duration::from_secs(20));
        assert!(out.status.success(), "{}", stderr_of(&out));
        let stdout = stdout_of(&out);
        reports.push(stdout.clone());
        assert!(
            stdout.contains("auth.json: provider=anthropic type=api_key fields=key"),
            "{stdout}"
        );
        assert!(h.sentinel_marker_lines().is_empty());
    }
    assert!(
        reports.windows(2).all(|pair| pair[0] == pair[1]),
        "report changed with the environment: {reports:?}"
    );
}

#[test]
fn legacy_home_is_reported_without_migration() {
    let h = Harness::new();
    let state_dir = h.project_state_dir();
    // A real pre-#96 `<state>/home/.pi` directory, with both files.
    let legacy = state_dir.join("home/.pi/agent");
    fs::create_dir_all(&legacy).unwrap();
    fs::write(
        legacy.join("auth.json"),
        r#"{"anthropic":{"type":"api_key","key":"CANARY_LEGACY_KEY"}}"#,
    )
    .unwrap();
    fs::write(
        legacy.join("models.json"),
        r#"{"providers":{"demo":{"apiKey":"CANARY_LEGACY_MODELS"}}}"#,
    )
    .unwrap();

    let before = snapshot(&h.state_root);
    let out = h.run_doctor(&[]);
    let after = snapshot(&h.state_root);

    let stdout = stdout_of(&out);
    assert!(out.status.success(), "{}", stderr_of(&out));
    assert!(
        stdout.contains("legacy pre-#96 auth.json: provider=anthropic type=api_key fields=key"),
        "{stdout}"
    );
    assert!(stdout.contains("legacy pre-#96 models.json"), "{stdout}");
    assert!(stdout.contains("has not been moved"), "{stdout}");
    // The canary bytes never surface, and nothing moved.
    assert!(!stdout.contains("CANARY_LEGACY_KEY"), "{stdout}");
    assert!(!stdout.contains("CANARY_LEGACY_MODELS"), "{stdout}");
    assert_eq!(before, after, "doctor migrated or mutated legacy state");
    assert!(
        state_dir.join("home/.pi/agent/auth.json").exists(),
        "doctor moved the legacy file"
    );
    assert!(
        !state_dir.join("pi").exists(),
        "doctor created the canonical pi dir"
    );
}

#[test]
fn reset_still_works_and_resolves_nothing() {
    let h = Harness::new();
    let state_dir = h.project_state_dir();
    seed_guest_state(&state_dir, &h.bin.join("credential-sentinel"));
    let db = h.state_root.join("msb-home/db");
    fs::create_dir_all(&db).unwrap();
    fs::write(db.join("msb.db"), b"not a real db").unwrap();

    let guest_auth = state_dir.join("pi/agent/auth.json");
    let before = fs::read(&guest_auth).unwrap();

    let out = h.run_doctor(&["--reset-msb-db"]);
    assert!(out.status.success(), "{}", stderr_of(&out));
    assert!(
        stdout_of(&out).contains("Moved") || stdout_of(&out).contains("moved"),
        "{}",
        stdout_of(&out)
    );
    // Reset is the deliberate mutation; it must not touch guest Pi state or
    // resolve anything.
    assert_eq!(fs::read(&guest_auth).unwrap(), before);
    assert!(h.sentinel_marker_lines().is_empty());
    assert!(!db.exists(), "reset should have moved the db dir aside");
}
