//! Black-box integration test for the tool-configuration preview in the
//! ordinary `agent-vm doctor` output (issue #80, `src/config.rs` +
//! `src/doctor.rs`).
//!
//! Spawns the real compiled binary with a controlled `HOME` /
//! `AGENT_VM_STATE_DIR` / cwd (the project) / fake version-only `MSB_PATH`,
//! mirroring `tests/doctor_reset.rs`. `doctor` avoids runtime/VM setup; these
//! absent/empty-inventory fixtures skip native credential-store I/O.
//!
//! These tests are deliberately black-box: they prove the discovered paths,
//! tier statuses, resolved order, warnings, and error redaction as the user
//! sees them, not just the pure `describe_config` renderer.

use std::{
    ffi::OsStr,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

fn agent_vm_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-vm"))
}

#[path = "support/fake_msb.rs"]
mod fake_msb;

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
    state_dir: tempfile::TempDir,
    _project: tempfile::TempDir,
    home_root: PathBuf,
    project_root: PathBuf,
    state_root: PathBuf,
    fake_msb: PathBuf,
}

impl Harness {
    fn new() -> Self {
        Self::in_leaf("", "", "")
    }

    /// A harness whose three roots end in `home`, `state` and `project`, so a test
    /// can put a byte a directory may legally carry — a newline, or non-ASCII —
    /// into the paths `doctor` measures. The `TempDir`s are kept for their
    /// lifetime; the roots point at the named child inside each.
    fn in_leaf(home: &str, state: &str, project: &str) -> Self {
        Self::in_os_leaf(OsStr::new(home), OsStr::new(state), OsStr::new(project))
    }

    /// [`in_leaf`] with the leaves as raw `OsStr`s, so a leaf may hold a byte a
    /// directory can carry and a `&str` cannot — invalid UTF-8 has no spelling
    /// that survives `Path::display()`.
    fn in_os_leaf(home: &OsStr, state: &OsStr, project: &OsStr) -> Self {
        let home_dir = tempfile::tempdir_in("/tmp").unwrap();
        let state_dir = tempfile::tempdir_in("/tmp").unwrap();
        let project_dir = tempfile::tempdir_in("/tmp").unwrap();
        let child = |dir: &std::path::Path, leaf: &OsStr| -> PathBuf {
            if leaf.is_empty() {
                return dir.to_path_buf();
            }
            let named = dir.join(leaf);
            std::fs::create_dir(&named).unwrap();
            named
        };
        let home_root = child(home_dir.path(), home).canonicalize().unwrap();
        let project_root = child(project_dir.path(), project).canonicalize().unwrap();
        let state_root = child(state_dir.path(), state);
        let fake_msb = fake_msb::write(&home_root);
        Self {
            _home: home_dir,
            state_dir,
            _project: project_dir,
            home_root,
            project_root,
            state_root,
            fake_msb,
        }
    }

    fn user_config(&self) -> PathBuf {
        self.home_root.join(".config/agent-vm/config.toml")
    }

    fn project_config(&self) -> PathBuf {
        self.project_root.join(".agent-vm/config.toml")
    }

    fn credentials(&self) -> PathBuf {
        self.home_root.join(".config/agent-vm/credentials.yaml")
    }

    /// Write `credentials.yaml` at the mode `credential_yaml::load` expects, so
    /// the fixture exercises the launch path rather than the mode warning.
    fn write_credentials(&self, contents: &str) {
        use std::os::unix::fs::PermissionsExt as _;
        let path = self.credentials();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, contents).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn base_command(&self) -> Command {
        let mut cmd = Command::new(agent_vm_bin());
        cmd.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", &self.home_root)
            .env(
                "AGENT_VM_STATE_DIR",
                self.state_root.canonicalize().unwrap(),
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

/// The two sentences `agent-vm --help` appends when the config cannot be read
/// (`CONFIG_BROKEN_NOTE` in `src/cli.rs`). Duplicated as a literal because an
/// integration test sees only the spawned binary; pinning the pair is what proves
/// the note is rendered, where a shorter fragment would match help text that is
/// always there (`AGENT_VM_DEBUG_CONFIG`, `~/.config/agent-vm/…`).
const BROKEN_CONFIG_NOTE: &str = "\
Your tool configuration could not be read, so no launch verbs are listed.
Run `agent-vm doctor` to see the error.";

/// The cause-and-fix tail of a `tools` miss whose name nothing retained declares
/// (a typo, or an agent a custom catalog dropped).
const TYPO_REFERENCE_SENTENCE: &str =
    "names no tool in this configuration file; declare it in this file or remove the entry";

/// The tail when another retained file declares the name: the reference crossed a
/// file boundary, and the message names that file instead of blaming a typo.
const CROSS_TIER_REFERENCE_SENTENCE: &str = "cross-tier tool references are not allowed; copy or redeclare the tool in this file, or remove the entry";

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

    let dsh = stdout.find("1. dsh").expect("dsh row");
    let pi = stdout.find("2. pi").expect("pi row");
    let codex = stdout.find("3. codex").expect("codex row");
    let opencode = stdout.find("4. opencode").expect("opencode row");
    let claude = stdout.find("5. claude").expect("claude row");
    let copilot = stdout.find("6. copilot").expect("copilot row");
    let shell = stdout.find("7. shell").expect("shell row");
    assert!(
        dsh < pi
            && pi < codex
            && codex < opencode
            && opencode < claude
            && claude < copilot
            && copilot < shell,
        "{stdout}"
    );

    // The three pre-existing sections keep their headings and order.
    let home = stdout
        .find("==> active microsandbox home")
        .expect("home section");
    let creds = stdout
        .find("==> host agent credentials")
        .expect("credential section");
    let store = stdout.find("==> credential store").expect("store section");
    assert!(stdout.contains("credential store: not probed (0 tracked names)"));
    let image = stdout.find("==> boot image").expect("image section");
    let tools = stdout
        .find("==> tool configuration")
        .expect("config section");
    let ops = stdout
        .find("==> agent-vm doctor: available operations")
        .expect("operations section");
    assert!(
        home < creds && creds < store && store < tools && tools < image && image < ops,
        "{stdout}"
    );
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
    assert!(stdout.contains("1. dsh"), "{stdout}");
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
    assert!(!stdout.contains("1. dsh"), "{stdout}");
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

    let both = Harness::new();
    both.write_project("broken = = toml");
    write(
        &both
            .home_root
            .join(".config/agent-vm/secret-inventory.json"),
        "not json",
    );
    assert_report_with_config_error(&both);
    assert!(
        stdout_of(&both.run_doctor())
            .contains("credential store: not probed (inventory unavailable)")
    );
}

fn assert_report_with_config_error(h: &Harness) {
    let out = h.run_doctor();
    assert_failure(&out);
    let stdout = stdout_of(&out);
    for heading in [
        "==> active microsandbox home",
        "==> host agent credentials",
        "==> credential store",
        "==> tool configuration",
        "==> boot image",
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
    // #161 widened the validator to any valid keychain service name, so the
    // doctor label `opencode` is now a *request* launch resolution refuses
    // rather than a config error. What is still a config error is a name that
    // could not select a keychain item at all.
    let h = Harness::new();
    h.write_user("[[tools]]\nname = \"t\"\ncommand = \"t\"\ncredentials = [\"opencode!\"]\n");

    let out = h.run_doctor();
    assert_failure(&out);
    let stderr = stderr_of(&out);
    assert!(stderr.contains("opencode-static"), "{stderr}");
    assert!(stderr.contains("not a valid name"), "{stderr}");
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
fn doctor_never_executes_the_command_or_creates_persist_paths() {
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
        "[[tools]]\nname = \"evil\"\ncommand = \"{}\"\npersist = [\"cache/never\"]\n",
        script.display()
    ));

    // Persist paths are guest-HOME-relative, so a per-project state dir —
    // not the project root — is where a materialized `cache/never` would
    // appear. `doctor` is now dispatched before msb setup, so it creates
    // nothing at all under the state dir; the whole tree must match.
    let state_before = snapshot_tree(h.state_dir.path());

    let out = h.run_doctor();
    assert_success(&out);
    assert!(!marker.exists(), "doctor executed the declared command");
    assert_eq!(
        snapshot_tree(h.state_dir.path()),
        state_before,
        "doctor created an entry under the state dir (e.g. a persist path)"
    );
}

/// Every entry under `root`, as paths relative to `root`, sorted — used to
/// prove a run created nothing there. `doctor` runs no msb bootstrap, so the
/// entire tree must be unchanged.
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
    write(
        &h.home_root.join(".config/agent-vm/secret-inventory.json"),
        "corrupt inventory",
    );

    let out = h.run_doctor_reset();
    assert_success(&out);
    assert!(
        stdout_of(&out).contains("No microsandbox db"),
        "{}",
        stdout_of(&out)
    );
    assert!(!stdout_of(&out).contains("==> credential store"));
    assert!(
        !h.home_root
            .join(".config/agent-vm/.secret-inventory.lock")
            .exists()
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

    assert_failure(&out);
    let stdout = stdout_of(&out);
    assert!(stdout.contains("credential store: not probed (inventory unavailable)"));
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

// -- #178: the launch-aware credential view ---------------------------------

const ANTHROPIC_AUTHORIZATION: &str = "\
credentials:
  - service: anthropic
    required: true
    apiKey:
      name: ANTHROPIC_API_KEY
      sentinelEnv: true
      inject:
        - domain: api.anthropic.example
          header: x-api-key
          format: \"%s\"
";

/// A same-named authorization makes the built-in `anthropic` row's host file
/// irrelevant, and doctor must say so rather than leaving a green/absent row to
/// be read as "the launch reads this". The launch section is the positive
/// signal that the authorization supplies the launch.
#[test]
fn a_replaced_provider_is_reported_as_not_read_and_authorized_from_yaml() {
    let h = Harness::new();
    h.write_credentials(ANTHROPIC_AUTHORIZATION);

    let out = h.run_doctor();
    assert_success(&out);
    let stdout = stdout_of(&out);

    assert!(
        stdout.contains(
            "absent - replaced by credentials.yaml for pi, claude, shell (host file not read)"
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains("==> credentials.yaml (launch credentials)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("anthropic  authorized for this launch (replaces the host built-in)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("`agent-vm secret ls` reports whether a value is stored"),
        "{stdout}"
    );
    // The launch view comes after the tool list it is derived from, and before
    // the operations footer.
    let tools = stdout.find("==> tool configuration").unwrap();
    let launch = stdout.find("==> credentials.yaml").unwrap();
    let ops = stdout
        .find("==> agent-vm doctor: available operations")
        .unwrap();
    assert!(tools < launch && launch < ops, "{stdout}");
}

/// **Read-only regression (#178 review).** The launch view must not read the
/// credential store: `SecretStore::resolve` takes the exclusive inventory lock
/// and creates `.secret-inventory.lock`, which would make `doctor` a writing
/// command on a host whose only authorization is this file. `doctor` leaves the
/// config directory exactly as it found it.
#[test]
fn doctor_leaves_no_inventory_lock_behind() {
    for empty in [false, true] {
        let h = Harness::new();
        h.write_credentials(ANTHROPIC_AUTHORIZATION);
        let config_dir = h.credentials().parent().unwrap().to_path_buf();
        if empty {
            write(
                &config_dir.join("secret-inventory.json"),
                r#"{"version":1,"services":[]}"#,
            );
        }
        let snapshot = || {
            let mut files: Vec<_> = std::fs::read_dir(&config_dir)
                .unwrap()
                .map(|e| {
                    let e = e.unwrap();
                    (e.file_name(), std::fs::read(e.path()).unwrap())
                })
                .collect();
            files.sort();
            files
        };
        let before = snapshot();
        let out = h.run_doctor();
        assert_success(&out);
        assert!(stdout_of(&out).contains("credential store: not probed (0 tracked names)"));
        assert_eq!(snapshot(), before);
        assert!(!config_dir.join(".secret-inventory.lock").exists());
    }
}

/// A host with no `credentials.yaml` gets no launch section: the pre-#178
/// output is unchanged when there is nothing launch-specific to say.
#[test]
fn no_credentials_file_adds_no_launch_section() {
    let h = Harness::new();

    let out = h.run_doctor();
    assert_success(&out);
    let stdout = stdout_of(&out);

    assert!(
        !stdout.contains("==> credentials.yaml"),
        "no authorization file must not grow a section: {stdout}"
    );
    assert!(!stdout.contains("replaced by credentials.yaml"), "{stdout}");
}

/// An authorization no configured launch requests is inert, so it produces no
/// credential row and no host-row annotation.
#[test]
fn an_inert_authorization_is_not_reported() {
    let h = Harness::new();
    h.write_credentials(
        "credentials:\n  - service: alpha\n    apiKey:\n      name: ALPHA\n      \
         inject: [{domain: a.example, header: x-a, format: \"%s\"}]\n",
    );

    let out = h.run_doctor();
    assert_success(&out);
    let stdout = stdout_of(&out);

    assert!(
        !stdout.contains("alpha  authorized"),
        "an inert authorization changes nothing: {stdout}"
    );
    assert!(!stdout.contains("replaced by credentials.yaml"), "{stdout}");
}

/// A file diagnostic is about the file, not about one launch, so an inert-only
/// authorization still reports a file-mode warning. The credential rows and
/// host-row annotations stay absent.
#[test]
fn an_inert_authorization_still_reports_a_file_diagnostic() {
    use std::os::unix::fs::PermissionsExt as _;
    let h = Harness::new();
    h.write_credentials(
        "credentials:\n  - service: alpha\n    apiKey:\n      name: ALPHA\n      \
         inject: [{domain: a.example, header: x-a, format: \"%s\"}]\n",
    );
    let path = h.credentials();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let out = h.run_doctor();
    assert_success(&out);
    let stdout = stdout_of(&out);

    assert!(stdout.contains("warning:"), "{stdout}");
    assert!(stdout.contains("group- or other-readable"), "{stdout}");
    assert!(!stdout.contains("alpha  authorized"), "{stdout}");
    assert!(!stdout.contains("replaced by credentials.yaml"), "{stdout}");
}

/// A malformed authorization file is reported rather than hidden, and the rest
/// of the report still renders.
#[test]
fn a_malformed_credentials_file_is_reported_in_band() {
    let h = Harness::new();
    h.write_credentials("credentials:\n  - service: anthropic\n    bogus: true\n");

    let out = h.run_doctor();
    assert_success(&out);
    let stdout = stdout_of(&out);

    assert!(
        stdout.contains("==> credentials.yaml (launch credentials)"),
        "{stdout}"
    );
    assert!(stdout.contains("error:"), "{stdout}");
    assert!(stdout.contains("unknown field"), "{stdout}");
    // The sections that do not depend on the file still render.
    assert!(stdout.contains("==> host agent credentials"), "{stdout}");
    assert!(stdout.contains("==> tool configuration"), "{stdout}");
}

#[test]
fn an_env_sourced_authorization_is_labelled_and_never_read() {
    let h = Harness::new();
    h.write_user("[[tools]]\nname = \"t\"\ncommand = \"t\"\ncredentials = [\"my-env-service\"]\n");
    h.write_credentials("credentials:\n  - service: my-env-service\n    source: env\n    apiKey:\n      name: MY_KEY\n      inject: [{domain: api.example.com, scheme: bearer}]\n");
    let absent = h.run_doctor();
    assert_success(&absent);
    let set = h
        .base_command()
        .env("MY_KEY", "sk-CANARY-163-doctor")
        .arg("doctor")
        .output()
        .unwrap();
    assert_success(&set);
    assert_eq!(set.stdout, absent.stdout);
    assert_eq!(set.stderr, absent.stderr);
    let text = stdout_of(&set);
    assert!(
        text.contains(
            "my-env-service  authorized for this launch from the host environment (`MY_KEY`)"
        ),
        "{text}"
    );
    assert!(text.contains("environment values are read by the launch, not by doctor"));
    assert!(!text.contains("secret ls"));
    assert!(!text.contains("sk-CANARY-163-doctor"));
}

#[test]
fn a_bad_secret_inventory_is_reported_without_suppressing_other_sections() {
    let h = Harness::new();
    const CANARY: &str = "sk-CANARY-inventory-379";
    write(
        &h.home_root.join(".config/agent-vm/secret-inventory.json"),
        &format!(r#"{{"version":"{CANARY}","services":[]}}"#),
    );
    let mut cmd = h.base_command();
    cmd.arg("doctor");
    let out = run_with_timeout(cmd, Duration::from_secs(15));
    assert_failure(&out);
    let stdout = stdout_of(&out);
    assert!(stdout.contains(
        "==> credential store\ncredential store: not probed (inventory unavailable)\nerror: "
    ));
    assert!(stdout.contains("delete this file to reset the listing"));
    for heading in [
        "==> active microsandbox home",
        "==> host agent credentials",
        "==> tool configuration",
        "==> boot image",
        "==> agent-vm doctor: available operations",
    ] {
        assert!(stdout.contains(heading), "{stdout}");
    }
    assert!(!stdout.contains(CANARY));
    assert!(!stderr_of(&out).contains(CANARY));
}

/// Phase 2 made every report write fallible so a closed stdout cannot turn
/// `doctor` into a panic. The unit tests inject a failing writer, which cannot
/// catch a *new* section printed with `println!` (std panics on EPIPE); this
/// runs the real binary against a socket whose peer is already closed, so every
/// stdout write fails. Empty inventory, so no native store access.
#[test]
fn doctor_reports_a_closed_stdout_as_an_error_not_a_panic() {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;

    let h = Harness::new();
    let (reader, writer) = UnixStream::pair().unwrap();
    drop(reader);
    let mut cmd = h.base_command();
    cmd.arg("doctor")
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("failed to spawn agent-vm");
    let mut stderr_pipe = child.stderr.take().unwrap();
    let stderr_handle = std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = stderr_pipe.read_to_string(&mut buf);
        buf
    });
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait failed") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "agent-vm did not exit after its stdout closed"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let stderr = stderr_handle.join().unwrap();
    assert_eq!(status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("writing doctor output") && stderr.contains("Broken pipe"),
        "{stderr}"
    );
    assert!(!stderr.contains("panicked"), "{stderr}");
}

/// `doctor` reports paths it *measured*: the unpacked runtime under
/// `$HOME`/XDG, `MSB_HOME` and its db, the project cwd, the project state dir,
/// the host credential files and the `credentials.yaml` it read — including the
/// error text those two files' readers produce. None is a config value, so none
/// has been sanitized by a parser: a directory name can carry any byte, and a
/// newline must not end a section and leave the rest reading as doctor's own
/// output (issue #414).
#[test]
fn measured_paths_cannot_forge_a_doctor_section() {
    let h = Harness::in_leaf("ho\nFORGED-HOME", "st\nFORGED-STATE", "pro\nFORGED-PROJECT");
    // Existing-but-unreadable credential file: the `UNUSABLE` detail is error text
    // from `host_paths` and names the same path.
    std::fs::create_dir_all(h.home_root.join(".claude/.credentials.json")).unwrap();
    // A valid credentials file at the mode a default umask gives it, so the section
    // emits its mode warning — error text from `credential_yaml` naming the path.
    write(&h.credentials(), ANTHROPIC_AUTHORIZATION);

    assert_only_escaped(h.run_doctor(), &["UNUSABLE - ", "warning: "]);

    // A credentials file that fails to load: the `error:` channel is the other half
    // of that section, and names the same path.
    h.write_credentials("credentials: [\n");
    assert_only_escaped(h.run_doctor(), &["error: "]);
}

/// The same shape with non-ASCII names: a measured path stays legible, because the
/// reader has to act on it. Every path in the report is one of those — including
/// the config file locations, the conflict warning and each tool row's `source=`,
/// which used to be byte-escaped because `config` rendered them too (issue #420).
///
/// The assertion is whole-report: with non-ASCII `HOME`, state dir and cwd, no line
/// may contain a `\xd0` escape, so a regression anywhere fails here rather than on
/// one line somebody remembered to check.
#[test]
fn a_non_ascii_measured_path_is_printed_as_itself() {
    let h = Harness::in_leaf("дом", "состояние", "проект");
    // Both tiers declare an image and a tool: `t` in both (the conflict warning and
    // the `source=user:` row), `u` only in the project (the `source=project:` row).
    h.write_user("image = \"127.0.0.1:1/user:dev\"\n[[tools]]\nname = \"t\"\ncommand = \"t\"\n");
    h.write_project(
        "image = \"127.0.0.1:1/project:dev\"\n[[tools]]\nname = \"t\"\ncommand = \"other\"\n\
         [[tools]]\nname = \"u\"\ncommand = \"u\"\n",
    );

    let out = h.run_doctor();

    assert_success(&out);
    let stdout = stdout_of(&out);
    let project = h.project_root.canonicalize().unwrap().display().to_string();
    assert!(
        stdout.contains(&format!("dir:      {project}\n")),
        "the project path prints as itself: {stdout}"
    );
    let state = h.state_root.canonicalize().unwrap().display().to_string();
    assert!(
        stdout.contains(&format!("state:    {state}")),
        "the state path prints as itself: {stdout}"
    );
    for row in ["claude", "codex", "opencode", "copilot"] {
        let line = stdout
            .lines()
            .find(|l| l.starts_with(row))
            .unwrap_or_else(|| panic!("no {row} row:\n{stdout}"));
        assert!(line.contains("дом"), "{row} row: {line}");
        assert!(!line.contains("\\xd0"), "{row} row is byte-escaped: {line}");
    }
    // The lines that take their value from `config` or `boot_image`: named here so
    // a renamed or missing row fails loudly, then covered by the whole-report check
    // below.
    // Each row is located by content, not only by prefix: the tier rows and the
    // boot-image rows share `user:`/`project:`, so a prefix-only search would
    // re-check the tier row and let a deleted image row pass.
    assert!(
        stdout.contains("==> boot image"),
        "no image section: {stdout}"
    );
    for (site, needle, leaf) in [
        (
            "the user tier line",
            format!("{} (found", h.user_config().display()),
            "дом",
        ),
        (
            "the project tier line",
            format!("{} (found", h.project_config().display()),
            "проект",
        ),
        (
            "the user image row",
            "127.0.0.1:1/user:dev [".to_string(),
            "дом",
        ),
        (
            "the project image row",
            "127.0.0.1:1/project:dev [".to_string(),
            "проект",
        ),
        ("the default row", "default: ".to_string(), "дом"),
        (
            "the selected row",
            "selected (without --image): ".to_string(),
            "дом",
        ),
    ] {
        let line = stdout
            .lines()
            .find(|l| l.contains(&needle))
            .unwrap_or_else(|| panic!("no {site} ({needle}):\n{stdout}"));
        assert!(line.contains(leaf), "{site} lost the leaf: {line}");
        assert!(!line.contains("\\xd0"), "{site} byte-escaped it: {line}");
    }
    // The conflict warning names both files on two lines, and each resolved row
    // names the file it came from.
    for (site, needle) in [
        (
            "the conflict warning",
            format!(
                "in {} overrides",
                h.user_config().canonicalize().unwrap().display()
            ),
        ),
        (
            "the user tool row",
            format!("source=user:{}", h.user_config().display()),
        ),
        (
            "the project tool row",
            format!("source=project:{}", h.project_config().display()),
        ),
    ] {
        assert!(
            stdout.contains(&needle),
            "{site} missing ({needle}): {stdout}"
        );
    }
    let escaped: Vec<&str> = stdout
        .lines()
        .filter(|line| line.contains("\\xd0") || line.contains("\\xd1"))
        .collect();
    assert!(
        escaped.is_empty(),
        "no line may byte-escape a measured path: {escaped:?}"
    );
}

/// A config that fails to parse is reported *inside* the report, on a raw
/// `error:` line carrying the config file's path. That path is measured, so it
/// prints as itself like every other line (issue #420).
///
/// A read failure is the harder half: `host_paths` builds the *cause* text from
/// the same path, so the sentence quotes the file and then repeats it. Both copies
/// have to be legible — the first version of this fix escaped only the quoted
/// copy and printed `/дом/` beside `/\xd0\xb4\xd0\xbe\xd0\xbc/`. Making the config
/// path a directory is the shortest way to reach a reader cause from doctor.
#[test]
fn a_non_ascii_config_path_in_a_read_cause_prints_as_itself() {
    let h = Harness::in_leaf("дом", "состояние", "проект");
    // A directory where the file should be: the reader fails with
    // `… is not a regular file`, naming the same path.
    let config = h.user_config();
    std::fs::create_dir_all(&config).unwrap();

    let out = h.run_doctor();

    let combined = format!(
        "{}{}",
        stdout_of(&out),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("is not a regular file"),
        "the reader cause is reported: {combined}"
    );
    let cause = combined
        .lines()
        .find(|line| line.contains("is not a regular file"))
        .unwrap_or_default();
    assert!(cause.contains("дом"), "the cause names the path: {cause}");
    assert!(
        !cause.contains("\\xd0"),
        "the cause byte-escapes the path: {cause}"
    );
}

#[test]
fn a_non_ascii_config_path_in_a_config_error_prints_as_itself() {
    let h = Harness::in_leaf("дом", "состояние", "проект");
    h.write_user("[[tools]]\nname = \"t\"\ncommand = \"t\"\ntools = [\"missing\"]\n");

    let out = h.run_doctor();

    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let text = stdout_of(&out);
    let combined = format!("{text}{stderr}");
    assert!(
        combined.contains("error:"),
        "the config failure is reported: {combined}"
    );
    assert!(
        combined.contains("дом"),
        "the failing config's path prints as itself: {combined}"
    );
    assert!(
        !combined.contains("\\xd0"),
        "the config error byte-escapes its own path: {combined}"
    );
}

/// The bytes issue #418's acceptance names, all in one `AGENT_VM_STATE_DIR` leaf:
/// a double quote, an apostrophe, a backslash, two substitution shapes that would
/// create or print something if the undo line were interpolated, a newline, and
/// the non-ASCII and forged-line coverage the earlier form of this test carried.
/// `дом` keeps a legible non-ASCII assertion; `FORGED-STATE` follows a real LF.
const HOSTILE_STATE_LEAF: &str =
    "дом\"'\\$(echo pwned)$(touch INJECTED)`touch BACKTICKED`\nFORGED-STATE";

/// `db/msb.db` and its `-wal` sidecar, distinct so a restore that copied one file
/// twice cannot pass.
const DB_BYTES: &[u8] = b"forward-migrated-schema";
const DB_WAL_BYTES: &[u8] = b"write-ahead-log";

/// The one `db.reset-*` directory under `msb_home`, found by enumerating the raw
/// filesystem: the printed `to:` is a diagnostic, so an operand taken from it
/// would make a wrong undo line self-confirming. Entry names are compared as
/// bytes, never through a lossy conversion.
fn reset_backup(msb_home: &Path) -> PathBuf {
    let entries: Vec<PathBuf> = std::fs::read_dir(msb_home)
        .unwrap_or_else(|error| panic!("reading {}: {error}", msb_home.display()))
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            use std::os::unix::ffi::OsStrExt as _;
            path.file_name()
                .is_some_and(|name| name.as_bytes().starts_with(b"db.reset-"))
        })
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "expected exactly one db.reset-* backup in {}: {entries:?}",
        msb_home.display()
    );
    let backup = entries.into_iter().next().unwrap();
    assert!(backup.is_dir(), "the backup is not a directory: {backup:?}");
    backup
}

/// The report's undo instruction with exactly its `To undo: ` prefix removed and
/// nothing else touched — no shell-level repair, so whatever the report prints is
/// what Bash is asked to run.
fn undo_instruction(report: &str) -> &str {
    report
        .lines()
        .find_map(|line| line.strip_prefix("To undo: "))
        .unwrap_or_else(|| panic!("no undo instruction in:\n{report}"))
}

/// Run the real CLI against a seeded db, execute the undo instruction it printed
/// in Bash as-is, and assert the move was reversed byte for byte. Returns the
/// report so a caller can assert its shape.
///
/// Executing (rather than comparing the line to a string) is the only oracle that
/// catches operand reversal, display escaping reused as argv, and substitution at
/// once. Bash is the supported paste dialect (USAGE.md); `$'…'` is not promised
/// for dash or fish.
fn reset_then_undo_in_bash(h: &Harness) -> String {
    let msb_home = h.state_root.join("msb-home");
    let db = msb_home.join("db");
    std::fs::create_dir_all(&db).unwrap();
    std::fs::write(db.join("msb.db"), DB_BYTES).unwrap();
    std::fs::write(db.join("msb.db-wal"), DB_WAL_BYTES).unwrap();

    let out = h.run_doctor_reset();
    assert_success(&out);
    let report = stdout_of(&out);

    let backup = reset_backup(&msb_home);
    assert!(!db.exists(), "the db was not moved aside:\n{report}");
    assert_eq!(std::fs::read(backup.join("msb.db")).unwrap(), DB_BYTES);
    assert_eq!(
        std::fs::read(backup.join("msb.db-wal")).unwrap(),
        DB_WAL_BYTES
    );

    let instruction = undo_instruction(&report).to_owned();
    let undo = Command::new("bash")
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", &h.home_root)
        .current_dir(&h.project_root)
        .args(["-c", &instruction])
        .output()
        .expect("bash must be on PATH for this test");
    assert!(
        undo.status.success(),
        "the printed undo instruction failed ({}):\n{instruction}\nstderr: {}",
        undo.status,
        String::from_utf8_lossy(&undo.stderr)
    );
    assert!(
        undo.stdout.is_empty(),
        "the printed undo instruction wrote to stdout: {:?} (for {instruction})",
        String::from_utf8_lossy(&undo.stdout)
    );

    assert_eq!(std::fs::read(db.join("msb.db")).unwrap(), DB_BYTES);
    assert_eq!(std::fs::read(db.join("msb.db-wal")).unwrap(), DB_WAL_BYTES);
    assert!(!backup.exists(), "the backup survived the undo: {backup:?}");
    for marker in ["INJECTED", "BACKTICKED"] {
        assert!(
            !h.project_root.join(marker).exists(),
            "the undo instruction ran a substitution and created {marker}"
        );
    }
    report
}

/// A report whose only physical lines are doctor's own, so an operator can read
/// the undo instruction off the screen and paste it.
fn assert_five_line_reset_report(report: &str) -> Vec<&str> {
    let lines: Vec<&str> = report.split_terminator('\n').collect();
    assert_eq!(lines.len(), 5, "not five physical lines:\n{report}");
    assert!(
        lines[0].starts_with("==> Moved microsandbox db aside"),
        "{report}"
    );
    assert!(lines[1].starts_with("from: "), "{report}");
    assert!(lines[2].starts_with("to:   "), "{report}");
    assert!(
        lines[3].starts_with("The database will be recreated"),
        "{report}"
    );
    assert!(lines[4].starts_with("To undo: "), "{report}");
    for line in &lines {
        assert!(
            !line.chars().any(char::is_control),
            "a raw control byte survived in {line:?}"
        );
    }
    assert!(
        !report.lines().any(|line| line.starts_with("FORGED-STATE")),
        "the measured state dir forged a line:\n{report}"
    );
    lines
}

/// `--reset-msb-db` names the path it moved and prints an instruction to undo it.
/// Both come from `MSB_HOME`/`AGENT_VM_STATE_DIR`, where a name may hold any
/// non-NUL byte. The report must stay readable — five lines, no forged one, a
/// legible `from:` — while the instruction must still be a runnable Bash command
/// naming the bytes the filesystem actually holds (issue #418).
#[test]
fn the_reset_report_keeps_a_measured_path_on_one_line() {
    let h = Harness::in_leaf("", HOSTILE_STATE_LEAF, "");
    let report = reset_then_undo_in_bash(&h);

    let lines = assert_five_line_reset_report(&report);
    let from = lines[1].trim_start_matches("from: ");
    assert!(from.contains("дом"), "from: {from:?}");
    assert!(from.contains("\\x0aFORGED-STATE"), "from: {from:?}");
    assert!(
        !from.contains("\\xd0"),
        "the diagnostic byte-escaped its non-ASCII text: {from:?}"
    );
    assert!(from.ends_with("/msb-home/db"), "from: {from:?}");
    assert!(lines[2].contains("db.reset-"), "to: {:?}", lines[2]);
}

/// A literal `\x0a` in the name must not alias a real newline: the diagnostic
/// shows one as text and the other as an escape, and the executed instruction has
/// to restore whichever the directory actually carries. Same oracle as above, so
/// an escape scheme that decodes `\\x0a` into a control byte fails here.
#[test]
fn the_reset_undo_distinguishes_a_literal_backslash_from_a_control_byte() {
    let h = Harness::in_leaf("", "дом\\x0aFORGED-STATE", "");
    let report = reset_then_undo_in_bash(&h);

    let lines = assert_five_line_reset_report(&report);
    let from = lines[1].trim_start_matches("from: ");
    assert!(from.contains("x0aFORGED-STATE"), "from: {from:?}");
}

/// Whether this filesystem can hold a directory name that is not valid UTF-8.
///
/// APFS answers `EILSEQ`; ext4 accepts the bytes. A test that needs the name to
/// exist reports the platform limit instead of passing without running.
fn accepts_non_utf8_names(name: &OsStr) -> bool {
    let probe = tempfile::tempdir_in("/tmp").unwrap();
    let path = probe.path().join(name);
    match std::fs::create_dir(&path) {
        Ok(()) => {
            std::fs::remove_dir(&path).unwrap();
            true
        }
        Err(error) if error.raw_os_error() == Some(libc::EILSEQ) => false,
        Err(error) => panic!("probing a non-UTF-8 directory name: {error}"),
    }
}

/// A Unix directory name may hold bytes that are not UTF-8, and the undo operand
/// is raw bytes. `Path::display()` or `to_string_lossy()` anywhere on that path
/// would silently rename the directory to U+FFFD; this fixture fails unless the
/// instruction names the byte the filesystem actually holds.
#[test]
fn the_reset_undo_preserves_non_utf8_path_bytes() {
    use std::os::unix::ffi::OsStringExt as _;
    let state = std::ffi::OsString::from_vec(b"\xff\\x0a\nFORGED-STATE".to_vec());
    if !accepts_non_utf8_names(&state) {
        // APFS rejects every non-UTF-8 name (EILSEQ), so the filesystem half of
        // this case cannot run on macOS. The byte-preservation property it
        // shares with the render step is covered portably, without a directory,
        // by `doctor::tests::the_undo_operand_decodes_to_the_raw_path_bytes`.
        eprintln!("skipped: this filesystem refuses a non-UTF-8 directory name");
        return;
    }
    let h = Harness::in_os_leaf(OsStr::new(""), &state, OsStr::new(""));

    let report = reset_then_undo_in_bash(&h);

    let lines = assert_five_line_reset_report(&report);
    let from = lines[1].trim_start_matches("from: ");
    assert!(
        from.contains("\\xff"),
        "the diagnostic spelled the invalid byte out: {from:?}"
    );
    assert!(from.ends_with("/msb-home/db"), "from: {from:?}");
}

/// Every line of `doctor`'s output must be doctor's own, so the only place a
/// forged fragment may appear is inline after an escaped control character.
fn assert_only_escaped(out: Output, details: &[&str]) {
    let stdout = stdout_of(&out);
    assert_success(&out);
    // The two detail channels print error text that interpolates the same path:
    // `host_paths`' "not a regular file" and `credential_yaml`'s load error. Both
    // were raw before this change, so they are checked on their own line.
    for detail in details {
        let line = stdout
            .lines()
            .find(|line| line.contains(detail))
            .unwrap_or_else(|| panic!("no `{detail}` line:\n{stdout}"));
        assert!(
            line.contains("\\x0aFORGED-HOME"),
            "`{detail}` names the measured path raw: {line:?}"
        );
    }
    for forged in ["FORGED-HOME", "FORGED-PROJECT", "FORGED-STATE"] {
        assert!(
            !stdout
                .lines()
                .any(|line| line.trim_start().starts_with(forged)),
            "{forged} began a line, so a measured path split the report:\n{stdout}"
        );
        assert!(
            stdout.contains(&format!("\\x0a{forged}")),
            "{forged} should appear inline, escaped:\n{stdout}"
        );
    }
}

// ---------------------------------------------------------------------------
// #395 — the preview and the CLI agree on which tier a reference resolves in
// ---------------------------------------------------------------------------

const TIER_DOCTOR_USER: &str = "[[tools]]\nname = \"pi\"\ncommand = \"user-pi\"\n\
     credentials = [\"openai\", \"user-service\"]\npersist = [\".user-pi\"]\n";

const TIER_DOCTOR_PROJECT: &str = "[[tools]]\nname = \"pi\"\ncommand = \"project-pi\"\n\
     credentials = [\"anthropic\", \"project-service\"]\npersist = [\".project-pi\"]\n\
     [[tools]]\nname = \"bridge\"\ncommand = \"bridge\"\ntools = [\"pi\"]\npersist = [\".bridge\"]\n\
     [[tools]]\nname = \"helper\"\ncommand = \"helper\"\ntools = [\"bridge\"]\npersist = [\".helper\"]\n";

/// The `N. name -> ...` rows of the `==> tool configuration` section, in order,
/// so a hidden definition cannot hide in a warning or a note.
fn tool_rows(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter_map(|line| {
            let row = line
                .trim_start()
                .strip_prefix(|character: char| character.is_ascii_digit())?;
            let row = row.trim_start_matches(|character: char| character.is_ascii_digit());
            row.strip_prefix(". ").map(str::to_string)
        })
        .collect()
}

/// **C1.** The preview and `--help` list the same verbs, and neither surfaces the
/// definition hidden by the user's name conflict — while the project helper's row
/// still provisions the hidden project `pi`'s facet.
#[test]
fn a_hidden_definition_is_not_a_verb_but_still_provisions_its_tier() {
    let h = Harness::new();
    h.write_user(TIER_DOCTOR_USER);
    h.write_project(TIER_DOCTOR_PROJECT);
    h.write_credentials(
        "credentials:\n  - service: project-service\n    apiKey:\n      name: PROJECT_SERVICE_KEY\n      sentinelEnv: true\n      inject: [{domain: api.project-service.example, scheme: bearer}]\n",
    );
    let before = snapshot_tree(&h.home_root);

    let out = h.run_doctor();
    assert_success(&out);
    let stdout = stdout_of(&out);
    let rows = tool_rows(&stdout);
    assert_eq!(
        rows.iter()
            .map(|row| row.split(" ->").next().unwrap())
            .collect::<Vec<_>>(),
        ["pi", "bridge", "helper", "shell"],
        "{stdout}"
    );
    // The hidden project `pi` is not a row and its command is not a verb.
    assert!(
        !stdout.contains("project-pi"),
        "a hidden definition must not become a verb: {stdout}"
    );
    // One whole-definition conflict, both files, fixed field order.
    assert_eq!(
        stdout.matches("warning: tool \"pi\" in").count(),
        1,
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "warning: tool \"pi\" in {} overrides\n         {}; differing fields: command, credentials, persist",
            h.user_config().display(),
            h.project_config().display()
        )),
        "{stdout}"
    );
    // The helper's row is its own requirement set and the project closure.
    assert!(
        rows.iter().any(|row| row.starts_with(
            "helper -> \"helper\"; args=0; credentials=none; provisions=anthropic; persist=1"
        )),
        "{rows:?}"
    );
    // The user's verb provisions only its own facets.
    assert!(
        rows.iter().any(|row| row.starts_with(
            "pi -> \"user-pi\"; args=0; credentials=openai; provisions=openai; persist=1"
        )),
        "{rows:?}"
    );
    // The YAML launch view shows the inherited project service, not the user's.
    let launch = stdout
        .split("==> credentials.yaml (launch credentials)")
        .nth(1)
        .unwrap_or_else(|| panic!("no launch section: {stdout}"));
    assert!(launch.contains("project-service"), "{launch}");
    assert!(!launch.contains("user-service"), "{launch}");

    // `--help` lists exactly those verbs.
    let help = h.base_command().arg("--help").output().unwrap();
    assert_success(&help);
    let help_stdout = stdout_of(&help);
    for verb in ["pi", "bridge", "helper", "shell"] {
        assert!(
            help_stdout.contains(&format!("  {verb}")),
            "missing {verb}: {help_stdout}"
        );
    }
    assert!(!help_stdout.contains("project-pi"), "{help_stdout}");

    // The preview materializes nothing.
    assert_eq!(snapshot_tree(&h.home_root), before);
}

/// **C2.** A bad (or cross-tier) reference is reported with its declaring
/// context while every other section still renders, the launch reports the config
/// error rather than an unknown subcommand, and the corrected file is a positive
/// control.
#[test]
fn an_invalid_local_reference_is_previewed_and_recoverable() {
    // The last fragment is the cause-and-fix sentence: only a name another file
    // declares is cross-tier, so the two wordings are asserted apart.
    let cases = [
        (
            "unknown",
            "[[tools]]\nname = \"w\"\ncommand = \"w\"\ntools = [\"nope\"]\n",
            "",
            "user config",
            TYPO_REFERENCE_SENTENCE,
        ),
        (
            "cross-tier",
            "[[tools]]\nname = \"w\"\ncommand = \"w\"\ntools = [\"p\"]\n",
            "[[tools]]\nname = \"p\"\ncommand = \"p\"\n",
            "user config",
            CROSS_TIER_REFERENCE_SENTENCE,
        ),
        (
            "hidden dangling",
            "[[tools]]\nname = \"dup\"\ncommand = \"user-dup\"\n",
            "[[tools]]\nname = \"dup\"\ncommand = \"project-dup\"\ntools = [\"missing\"]\n",
            "project config",
            TYPO_REFERENCE_SENTENCE,
        ),
        (
            "fallback shell",
            "",
            "[[tools]]\nname = \"w\"\ncommand = \"w\"\ntools = [\"shell\"]\n",
            "project config",
            TYPO_REFERENCE_SENTENCE,
        ),
    ];
    for (label, user, project, tier, cause) in cases {
        let h = Harness::new();
        h.write_user(user);
        h.write_project(project);
        let before = snapshot_tree(&h.home_root);
        let out = h.run_doctor();
        assert_failure(&out);
        let stdout = stdout_of(&out);
        for heading in [
            "==> active microsandbox home",
            "==> host agent credentials",
            "==> tool configuration",
            "==> agent-vm doctor: available operations",
        ] {
            assert!(
                stdout.contains(heading),
                "{label}: missing {heading}: {stdout}"
            );
        }
        for fragment in [tier, "declaration [0]", "tools[0]", "names no tool", cause] {
            assert!(
                stdout.contains(fragment),
                "{label}: missing {fragment}: {stdout}"
            );
        }
        assert_eq!(
            snapshot_tree(&h.home_root),
            before,
            "{label}: no state writes"
        );

        // Top-level help still works with the broken-config note; the launch
        // verb reports the config error, never an unknown subcommand.
        let help = h.base_command().arg("--help").output().unwrap();
        assert_success(&help);
        let help_stdout = stdout_of(&help);
        assert!(
            help_stdout.contains(BROKEN_CONFIG_NOTE),
            "{label}: --help must explain the absent verb list: {help_stdout}"
        );
        let launch = h.base_command().arg("shell").output().unwrap();
        let stderr = stderr_of(&launch);
        assert_failure(&launch);
        assert!(
            stderr.contains("names no tool") && stderr.contains(cause),
            "{label}: the launch must report the same cause: {stderr}"
        );
        assert!(
            !stderr.contains("unrecognized subcommand"),
            "{label}: {stderr}"
        );
    }

    // Positive control: declaring the target locally previews cleanly.
    let h = Harness::new();
    h.write_project(
        "[[tools]]\nname = \"shell\"\ncommand = \"bash\"\n\
         [[tools]]\nname = \"w\"\ncommand = \"w\"\ntools = [\"shell\"]\n",
    );
    let out = h.run_doctor();
    assert_success(&out);
    assert!(
        stdout_of(&out).contains("w -> \"w\""),
        "{}",
        stdout_of(&out)
    );
}

/// **C3.** A user-declared `shell` with an omitted `tools` provisions exactly its
/// own tier's set; an explicit `[]` provisions nothing beyond its own
/// declaration. The custom-catalog fallback stays empty either way.
#[test]
fn shell_rows_report_the_tier_local_provisioning_set() {
    let omitted = Harness::new();
    omitted.write_user(
        "[[tools]]\nname = \"shell\"\ncommand = \"bash\"\n\
         [[tools]]\nname = \"sib\"\ncommand = \"sib\"\ncredentials = [\"copilot\"]\n",
    );
    omitted.write_project(
        "[[tools]]\nname = \"proj\"\ncommand = \"proj\"\ncredentials = [\"anthropic\"]\n",
    );
    let out = omitted.run_doctor();
    assert_success(&out);
    let stdout = stdout_of(&out);
    assert!(
        stdout.contains("shell -> \"bash\"; args=0; credentials=none; provisions=copilot"),
        "{stdout}"
    );
    assert!(
        stdout.contains("proj -> \"proj\"; args=0; credentials=anthropic; provisions=anthropic"),
        "{stdout}"
    );
    assert!(!stdout.contains("`shell` was not declared"), "{stdout}");

    let empty = Harness::new();
    empty.write_user(
        "[[tools]]\nname = \"shell\"\ncommand = \"bash\"\ntools = []\n\
         [[tools]]\nname = \"sib\"\ncommand = \"sib\"\ncredentials = [\"copilot\"]\n",
    );
    empty.write_project(
        "[[tools]]\nname = \"proj\"\ncommand = \"proj\"\ncredentials = [\"anthropic\"]\n",
    );
    let out = empty.run_doctor();
    assert_success(&out);
    let stdout = stdout_of(&out);
    assert!(
        stdout.contains("shell -> \"bash\"; args=0; credentials=none; provisions=none"),
        "{stdout}"
    );

    // A custom catalog with no declared shell keeps the empty fallback.
    let fallback = Harness::new();
    fallback.write_user("[[tools]]\nname = \"solo\"\ncommand = \"solo\"\n");
    let out = fallback.run_doctor();
    assert_success(&out);
    let stdout = stdout_of(&out);
    assert!(
        stdout.contains("shell -> \"bash\"; args=2; credentials=none; provisions=none"),
        "{stdout}"
    );
    assert!(stdout.contains("`shell` was not declared"), "{stdout}");
    assert!(
        !stdout.contains("dsh"),
        "no shipped agent may be restored: {stdout}"
    );
}
