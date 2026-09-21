//! Black-box integration test for the tool-configuration preview in the
//! ordinary `agent-vm doctor` output (issue #80, `src/config.rs` +
//! `src/doctor.rs`).
//!
//! Spawns the real compiled binary with a controlled `HOME` /
//! `AGENT_VM_STATE_DIR` / cwd (the project) / fake version-only `MSB_PATH`,
//! mirroring `tests/doctor_reset.rs`. `doctor` is pure filesystem work
//! dispatched before the tokio runtime, so no VM or network is touched.
//!
//! These tests are deliberately black-box: they prove the discovered paths,
//! tier statuses, resolved order, warnings, and error redaction as the user
//! sees them, not just the pure `describe_config` renderer.

use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

fn agent_vm_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-vm"))
}

/// A fake `msb` reporting the version this build vendors, satisfying
/// `point_at_msb`'s `--version` check. Mirrors `doctor_reset.rs`.
fn write_fake_msb(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("msb");
    std::fs::write(&path, "#!/bin/sh\necho 'msb 0.6.15'\nexit 0\n").unwrap();
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).unwrap();
    path
}

/// Run `child` to completion, killing it if it doesn't exit in time. Reads
/// both pipes on threads so a full pipe can't deadlock. Duplicated from
/// `mount_follow_links.rs` — Rust integration tests are separate binaries.
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

/// One isolated `$HOME`, state dir, and project cwd, plus a fake `msb`.
/// Paths are canonicalized on construction so the printed config locations
/// (which `doctor` canonicalizes) compare directly to `user_config()` /
/// `project_config()` on macOS's `/var` → `/private/var` symlink.
struct Harness {
    _home: tempfile::TempDir,
    state: tempfile::TempDir,
    _project: tempfile::TempDir,
    home_root: PathBuf,
    project_root: PathBuf,
    fake_msb: PathBuf,
}

impl Harness {
    fn new() -> Self {
        let home = tempfile::tempdir_in("/tmp").unwrap();
        let state = tempfile::tempdir_in("/tmp").unwrap();
        let project = tempfile::tempdir_in("/tmp").unwrap();
        let home_root = home.path().canonicalize().unwrap();
        let project_root = project.path().canonicalize().unwrap();
        let fake_msb = write_fake_msb(home.path());
        Self {
            _home: home,
            state,
            _project: project,
            home_root,
            project_root,
            fake_msb,
        }
    }

    fn user_config(&self) -> PathBuf {
        self.home_root.join(".config/agent-vm/config.toml")
    }

    fn project_config(&self) -> PathBuf {
        self.project_root.join(".agent-vm/config.toml")
    }

    fn base_command(&self) -> Command {
        let mut cmd = Command::new(agent_vm_bin());
        cmd.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", &self.home_root)
            .env(
                "AGENT_VM_STATE_DIR",
                self.state.path().canonicalize().unwrap(),
            )
            .env("MSB_PATH", &self.fake_msb)
            .current_dir(&self.project_root);
        cmd
    }

    fn run_doctor(&self) -> Output {
        self.base_command()
            .arg("doctor")
            .output()
            .expect("failed to run agent-vm doctor")
    }

    fn run_doctor_reset(&self) -> Output {
        self.base_command()
            .args(["doctor", "--reset-msb-db"])
            .output()
            .expect("failed to run agent-vm doctor --reset-msb-db")
    }

    fn write_user(&self, contents: &str) {
        write(&self.user_config(), contents);
    }

    fn write_project(&self, contents: &str) {
        write(&self.project_config(), contents);
    }
}

fn write(path: &Path, contents: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

fn assert_success(out: &Output) {
    assert!(
        out.status.success(),
        "expected success; stderr: {}",
        stderr_of(out)
    );
}

fn assert_failure(out: &Output) {
    assert!(
        !out.status.success(),
        "expected failure; stdout: {}",
        stdout_of(out)
    );
}

const ONE_TOOL: &str = "[[tools]]\nname = \"solo\"\ncommand = \"solo\"\n";

#[test]
fn reports_defaults_and_preserves_the_pre_existing_sections() {
    let h = Harness::new();

    let out = h.run_doctor();
    assert_success(&out);
    let stdout = stdout_of(&out);

    assert!(stdout.contains("==> tool configuration"), "{stdout}");
    assert!(!stdout.contains("diagnostic only"), "{stdout}");
    assert!(
        stdout.contains(&format!("{} (absent)", h.user_config().display())),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!("{} (absent)", h.project_config().display())),
        "{stdout}"
    );
    assert!(stdout.contains("resolved: built-in defaults"), "{stdout}");

    let pi = stdout.find("1. pi").expect("pi row");
    let codex = stdout.find("2. codex").expect("codex row");
    let opencode = stdout.find("3. opencode").expect("opencode row");
    let claude = stdout.find("4. claude").expect("claude row");
    let copilot = stdout.find("5. copilot").expect("copilot row");
    let shell = stdout.find("6. shell").expect("shell row");
    assert!(
        pi < codex && codex < opencode && opencode < claude && claude < copilot && copilot < shell,
        "{stdout}"
    );

    // The three pre-existing sections keep their headings and order.
    let home = stdout
        .find("==> active microsandbox home")
        .expect("home section");
    let creds = stdout
        .find("==> host agent credentials")
        .expect("credential section");
    let tools = stdout
        .find("==> tool configuration")
        .expect("config section");
    let ops = stdout
        .find("==> agent-vm doctor: available operations")
        .expect("operations section");
    assert!(home < creds && creds < tools && tools < ops, "{stdout}");
}

#[test]
fn found_empty_tier_is_distinct_from_absent_and_still_uses_defaults() {
    let h = Harness::new();
    h.write_user("");

    let out = h.run_doctor();
    assert_success(&out);
    let stdout = stdout_of(&out);

    assert!(
        stdout.contains(&format!("{} (found, 0 tools)", h.user_config().display())),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!("{} (absent)", h.project_config().display())),
        "{stdout}"
    );
    assert!(stdout.contains("1. pi"), "{stdout}");
}

#[test]
fn a_user_only_catalog_adds_the_shell_fallback_but_no_defaults() {
    let h = Harness::new();
    h.write_user(ONE_TOOL);

    let out = h.run_doctor();
    assert_success(&out);
    let stdout = stdout_of(&out);

    assert!(stdout.contains("resolved: declared tools"), "{stdout}");
    assert!(stdout.contains("1. solo"), "{stdout}");
    // No default agent is added...
    assert!(!stdout.contains("1. pi"), "{stdout}");
    assert!(!stdout.contains("codex ->"), "{stdout}");
    // ...but the built-in `shell` fallback is, and it is labelled.
    assert!(stdout.contains("2. shell"), "{stdout}");
    assert!(stdout.contains("`shell` was not declared"), "{stdout}");
}

#[test]
fn union_order_and_conflict_warning_are_reported_once() {
    let h = Harness::new();
    h.write_user(
        "[[tools]]\nname = \"z\"\ncommand = \"z\"\n[[tools]]\nname = \"a\"\ncommand = \"a\"\n",
    );
    h.write_project(
        "[[tools]]\nname = \"b\"\ncommand = \"b\"\n[[tools]]\nname = \"a\"\ncommand = \"a2\"\n[[tools]]\nname = \"c\"\ncommand = \"c\"\n",
    );

    let out = h.run_doctor();
    assert_success(&out);
    let stdout = stdout_of(&out);

    let order: Vec<usize> = ["1. z", "2. a", "3. b", "4. c"]
        .iter()
        .map(|row| {
            stdout
                .find(row)
                .unwrap_or_else(|| panic!("missing {row}: {stdout}"))
        })
        .collect();
    assert!(order.windows(2).all(|w| w[0] < w[1]), "{stdout}");

    assert_eq!(
        stdout.matches("warning: tool \"a\" in").count(),
        1,
        "exactly one warning: {stdout}"
    );
    // The emitted line matches the documented format byte-for-byte (a
    // quoted, escaped name), not only in prefix.
    assert!(
        stdout.contains(&format!(
            "warning: tool \"a\" in {} overrides\n         {}; differing fields: command",
            h.user_config().display(),
            h.project_config().display()
        )),
        "{stdout}"
    );
    assert!(stdout.contains("differing fields: command"), "{stdout}");
    // The project-only tools carry project provenance.
    assert!(
        stdout.contains(&format!("source=project:{}", h.project_config().display())),
        "{stdout}"
    );
}

#[test]
fn conflict_warning_matches_the_documented_format_for_multiple_fields() {
    let h = Harness::new();
    h.write_user("[[tools]]\nname = \"t\"\ncommand = \"t\"\nargs = [\"a\"]\n");
    h.write_project("[[tools]]\nname = \"t\"\ncommand = \"t2\"\nargs = [\"b\"]\n");

    let out = h.run_doctor();
    assert_success(&out);
    let stdout = stdout_of(&out);

    assert!(
        stdout.contains(&format!(
            "warning: tool \"t\" in {} overrides\n         {}; differing fields: command, args",
            h.user_config().display(),
            h.project_config().display()
        )),
        "{stdout}"
    );
}

#[test]
fn tier_tool_count_is_singular_for_one_and_plural_otherwise() {
    let one = Harness::new();
    one.write_user(ONE_TOOL);
    let out = one.run_doctor();
    assert_success(&out);
    assert!(
        stdout_of(&out).contains(&format!("{} (found, 1 tool)", one.user_config().display())),
        "{}",
        stdout_of(&out)
    );

    let two = Harness::new();
    two.write_project(
        "[[tools]]\nname = \"a\"\ncommand = \"a\"\n[[tools]]\nname = \"b\"\ncommand = \"b\"\n",
    );
    let out = two.run_doctor();
    assert_success(&out);
    assert!(
        stdout_of(&out).contains(&format!(
            "{} (found, 2 tools)",
            two.project_config().display()
        )),
        "{}",
        stdout_of(&out)
    );
}

/// A broken config still exits nonzero, but the failure is rendered as the
/// config section body and every pre-existing section still prints, so a
/// repo-supplied config cannot hide them (issue #80 review finding 1).
#[test]
fn a_broken_project_config_never_suppresses_the_rest_of_the_report() {
    // (a) syntactically invalid TOML
    let syntax = Harness::new();
    syntax.write_project("this is not = = toml\n");
    assert_report_with_config_error(&syntax);

    // (b) valid TOML with an unknown top-level key
    let unknown = Harness::new();
    unknown.write_project("unknown_key = true\n");
    assert_report_with_config_error(&unknown);

    // (c) `.agent-vm/config.toml` is a directory
    let directory = Harness::new();
    std::fs::create_dir_all(directory.project_config()).unwrap();
    assert_report_with_config_error(&directory);
}

fn assert_report_with_config_error(h: &Harness) {
    let out = h.run_doctor();
    assert_failure(&out);
    let stdout = stdout_of(&out);
    for heading in [
        "==> active microsandbox home",
        "==> host agent credentials",
        "==> tool configuration",
        "==> agent-vm doctor: available operations",
    ] {
        assert!(stdout.contains(heading), "missing {heading}: {stdout}");
    }
    assert!(
        stdout.contains("error: config:"),
        "config failure should be the section body: {stdout}"
    );
}

#[test]
fn unknown_provider_is_a_hard_error_still_prints_the_other_sections() {
    let h = Harness::new();
    h.write_user("[[tools]]\nname = \"t\"\ncommand = \"t\"\ncredentials = [\"opencode\"]\n");

    let out = h.run_doctor();
    assert_failure(&out);
    let stderr = stderr_of(&out);
    assert!(stderr.contains("opencode-static"), "{stderr}");
    assert!(stderr.contains("valid names"), "{stderr}");
    let stdout = stdout_of(&out);
    assert!(
        stdout.contains("==> tool configuration"),
        "the config section renders the failure: {stdout}"
    );
    assert!(
        stdout.contains("==> host agent credentials"),
        "pre-existing sections still print: {stdout}"
    );
}

/// **V14 (#83).** The `persist` rules rejected by `config.rs` are exercised
/// end to end through the binary: absolute paths, two tools claiming the same
/// path, an overlapping (ancestor/descendant) pair, and a reserved compiled-in
/// collision. Each fails `doctor` and names the offending field, never a value.
#[test]
fn persist_rule_violations_surface_through_the_binary() {
    let cases: &[(&str, &str, &str)] = &[
        (
            "absolute",
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\npersist = [\"/etc/passwd\"]\n",
            "must be relative to the guest HOME",
        ),
        (
            "two tools claiming one path",
            "[[tools]]\nname = \"a\"\ncommand = \"a\"\npersist = [\"shared\"]\n[[tools]]\nname = \"b\"\ncommand = \"b\"\npersist = [\"shared\"]\n",
            "is claimed by tool",
        ),
        (
            "an overlapping pair",
            "[[tools]]\nname = \"a\"\ncommand = \"a\"\npersist = [\".cache\"]\n[[tools]]\nname = \"b\"\ncommand = \"b\"\npersist = [\".cache/x\"]\n",
            "overlaps",
        ),
        (
            "a reserved compiled-in path",
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\npersist = [\".claude\"]\n",
            "overlaps the reserved guest HOME path",
        ),
    ];
    for (label, body, expected) in cases {
        let h = Harness::new();
        h.write_user(body);
        let out = h.run_doctor();
        assert_failure(&out);
        let stderr = stderr_of(&out);
        assert!(
            stderr.contains(expected),
            "{label}: expected {expected:?}: {stderr}"
        );
        assert!(stderr.contains("persist"), "{label}: {stderr}");
    }
}

#[test]
fn traversal_and_bad_toml_fail_with_context() {
    let traversal = Harness::new();
    traversal.write_user("[[tools]]\nname = \"t\"\ncommand = \"t\"\npersist = [\"../escape\"]\n");
    let out = traversal.run_doctor();
    assert_failure(&out);
    let stderr = stderr_of(&out);
    assert!(stderr.contains("persist"), "{stderr}");
    assert!(stderr.contains("declaration [0]"), "{stderr}");

    let bad_toml = Harness::new();
    bad_toml.write_user("this is not = = toml\n");
    let out = bad_toml.run_doctor();
    assert_failure(&out);
    let stderr = stderr_of(&out);
    assert!(stderr.contains("invalid TOML or tool schema"), "{stderr}");
    // Fixed guidance, not a raw dependency dump.
    assert!(stderr.contains("arrays of strings"), "{stderr}");
}

#[test]
fn sentinel_secrets_never_reach_stdout_or_stderr() {
    const SENTINEL: &str = "SENTINEL_SECRET_9f3a2b";
    for body in [
        format!("[[tools]]\nname = \"t\"\ncommand = \"t\"\nargs = \"--api-key={SENTINEL}\"\n"),
        format!(
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\nargs = [{{ token = \"{SENTINEL}\" }}]\n"
        ),
        format!("[[tools]]\nname = \"t\"\ncommand = \"t\"\nargs = [{SENTINEL}\n"),
        format!("[[tools]]\nname = \"t\"\ncommand = \"t\"\npersist = [\"{SENTINEL}\\u0000x\"]\n"),
    ] {
        let h = Harness::new();
        h.write_user(&body);
        let out = h.run_doctor();
        assert_failure(&out);
        let combined = format!("{}{}", stdout_of(&out), stderr_of(&out));
        assert!(
            !combined.contains(SENTINEL),
            "secret leaked for body {body:?}: {combined}"
        );
        // A usable safe diagnostic is still present.
        assert!(
            combined.contains("invalid TOML or tool schema") || combined.contains("declaration"),
            "expected a safe diagnostic: {combined}"
        );
    }
}

#[test]
fn doctor_never_executes_the_command_or_creates_layer_or_persist_paths() {
    let h = Harness::new();
    let marker = h.project_root.join("EXECUTED");
    let script = h.project_root.join("recorder.sh");
    std::fs::write(
        &script,
        format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).unwrap();
    }
    h.write_user(&format!(
        "[[tools]]\nname = \"evil\"\ncommand = \"{}\"\nlayer = {{ path = \"layers/never\" }}\npersist = [\"cache/never\"]\n",
        script.display()
    ));

    // Persist paths are guest-HOME-relative, so a per-project state dir —
    // not the project root — is where a materialized `cache/never` would
    // appear. `doctor` is now dispatched before msb setup, so it creates
    // nothing at all under the state dir; the whole tree must match.
    let state_before = snapshot_tree(h.state.path());

    let out = h.run_doctor();
    assert_success(&out);
    assert!(!marker.exists(), "doctor executed the declared command");
    assert!(
        !h.project_root.join("layers/never").exists(),
        "doctor created a layer path"
    );
    assert_eq!(
        snapshot_tree(h.state.path()),
        state_before,
        "doctor created an entry under the state dir (e.g. a persist path)"
    );
}

/// Every entry under `root`, as paths relative to `root`, sorted — used to
/// prove a run created nothing there. `doctor` no longer runs any msb
/// bootstrap, so the entire tree must be unchanged.
fn snapshot_tree(root: &Path) -> Vec<PathBuf> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(relative) = path.strip_prefix(root) else {
                continue;
            };
            out.push(relative.to_path_buf());
            if path.is_dir() {
                walk(root, &path, out);
            }
        }
    }
    let mut entries = Vec::new();
    walk(root, root, &mut entries);
    entries.sort();
    entries
}

#[test]
fn a_malformed_config_does_not_block_db_reset() {
    let h = Harness::new();
    h.write_project("totally = = broken\n");

    let out = h.run_doctor_reset();
    assert_success(&out);
    assert!(
        stdout_of(&out).contains("No microsandbox db"),
        "{}",
        stdout_of(&out)
    );
}

#[test]
fn a_missing_home_reports_an_unavailable_user_tier() {
    let h = Harness::new();
    let out = h
        .base_command()
        .env_remove("HOME")
        .arg("doctor")
        .output()
        .expect("failed to run agent-vm doctor without HOME");

    assert_success(&out);
    let stdout = stdout_of(&out);
    assert!(
        stdout.contains("<no HOME; user tier unavailable>"),
        "{stdout}"
    );
}

#[test]
fn a_special_file_or_control_byte_path_is_rejected_with_an_escaped_reason() {
    // A project dir whose name carries a newline and an ESC/ANSI sequence,
    // with `.agent-vm/config.toml` a directory rather than a file.
    let h = Harness::new();
    let evil_project = h.project_root.join("proj\n\x1b[31mred");
    std::fs::create_dir_all(evil_project.join(".agent-vm/config.toml")).unwrap();

    let out = h
        .base_command()
        .current_dir(&evil_project)
        .arg("doctor")
        .output()
        .expect("failed to run agent-vm doctor in an evil project");

    assert_failure(&out);
    let stderr = stderr_of(&out);
    assert!(!stderr.contains('\x1b'), "raw ESC leaked: {stderr:?}");
    assert!(
        stderr.contains("\\x1b"),
        "ESC should be escaped: {stderr:?}"
    );
    assert!(stderr.contains("not a regular file"), "{stderr}");
}

#[test]
fn a_fifo_config_does_not_hang_doctor() {
    let h = Harness::new();
    let path = h.project_config();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

    let mut cmd = h.base_command();
    cmd.arg("doctor");
    let out = run_with_timeout(cmd, Duration::from_secs(15));
    assert_failure(&out);
    assert!(
        stderr_of(&out).contains("not a regular file"),
        "{}",
        stderr_of(&out)
    );
}
