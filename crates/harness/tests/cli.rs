//! The binary the shell calls actually builds and runs. A lib-only test would
//! pass while `[[bin]]` was misconfigured, which is the failure this catches.

use serde_json::json;
use std::{
    env, fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT_SCRATCH: AtomicUsize = AtomicUsize::new(0);

/// A directory the binary under test may write into, removed on drop.
struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new(label: &str) -> Self {
        let path = env::temp_dir().join(format!(
            "harness-cli-{label}-{}-{}",
            std::process::id(),
            NEXT_SCRATCH.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).expect("create the scratch directory");
        Self { path }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn harness(arguments: impl IntoIterator<Item = String>) -> Output {
    Command::new(env!("CARGO_BIN_EXE_harness"))
        .args(arguments)
        .output()
        .expect("the harness binary runs")
}

#[test]
fn the_binary_prints_its_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_harness"))
        .arg("--version")
        .output()
        .expect("the harness binary runs");
    assert!(
        output.status.success(),
        "harness --version failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("version output is UTF-8");
    assert_eq!(
        stdout.trim(),
        concat!("harness ", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn the_binary_runs_runtime_provenance_controls() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new(env!("CARGO_BIN_EXE_harness"))
        .args([
            "runtime-provenance",
            "--self-test",
            "--repo-root",
            repo_root.to_str().expect("workspace path is UTF-8"),
        ])
        .output()
        .expect("the harness binary runs provenance controls");
    assert!(
        output.status.success(),
        "runtime provenance controls failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("control output is UTF-8"),
        "runtime provenance tests passed\n"
    );
}

#[test]
fn the_binary_counts_utf8_bytes_and_unicode_scalar_values() {
    let output = Command::new(env!("CARGO_BIN_EXE_harness"))
        .args(["config-dir-guard", "--lengths", "/é"])
        .output()
        .expect("the harness binary counts lengths");
    assert!(
        output.status.success(),
        "length counting failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("length output is UTF-8"),
        "3 2\n"
    );
}

#[test]
fn the_binary_runs_launch_argv_order_controls() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new(env!("CARGO_BIN_EXE_harness"))
        .args([
            "launch-argv-order",
            "--self-test",
            "--repo-root",
            repo_root.to_str().expect("workspace path is UTF-8"),
        ])
        .output()
        .expect("the harness binary runs launch-argument-order controls");
    assert!(
        output.status.success(),
        "launch-argument-order controls failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8(output.stdout)
            .expect("control output is UTF-8")
            .ends_with(
                "launch-argv-order: OK (no old-order caller; create() puts --memory before shell)\n"
            )
    );
}

#[test]
fn the_binary_runs_msb_krun_compat_timeout_controls() {
    let output = Command::new(env!("CARGO_BIN_EXE_harness"))
        .args(["msb-krun-compat", "--self-test"])
        .output()
        .expect("the harness binary runs msb-krun compatibility timeout controls");
    assert!(
        output.status.success(),
        "msb-krun compatibility timeout controls failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("control output is UTF-8"),
        "msb-krun compatibility timeout controls passed\n"
    );
}

#[test]
fn the_binary_runs_build_archive_oracle_controls() {
    let output = Command::new(env!("CARGO_BIN_EXE_harness"))
        .args(["build-archive-oracle", "--self-test"])
        .output()
        .expect("the harness binary runs build-archive-oracle controls");
    assert!(
        output.status.success(),
        "build-archive-oracle controls failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("control output is UTF-8"),
        "build archive oracle controls passed\n"
    );
}

#[test]
fn the_binary_checks_image_pins_dispatch() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new(env!("CARGO_BIN_EXE_harness"))
        .args([
            "image-pins",
            "--e2e",
            repo_root
                .join("script/test/e2e.sh")
                .to_str()
                .expect("workspace path is UTF-8"),
        ])
        .output()
        .expect("the harness binary checks image-pins dispatch");
    assert!(
        output.status.success(),
        "image-pins dispatch check failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("check output is UTF-8"),
        "live-seed dispatch uses the ambient helper\n"
    );
}

#[test]
fn the_binary_runs_image_pins_controls() {
    let output = Command::new(env!("CARGO_BIN_EXE_harness"))
        .args(["image-pins", "--self-test"])
        .output()
        .expect("the harness binary runs image-pins controls");
    assert!(
        output.status.success(),
        "image-pins controls failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("control output is UTF-8"),
        "image pins controls passed\n"
    );
}

#[test]
fn the_binary_runs_build_provenance_controls() {
    let output = Command::new(env!("CARGO_BIN_EXE_harness"))
        .args(["build-provenance", "--self-test"])
        .output()
        .expect("the harness binary runs build-provenance controls");
    assert!(
        output.status.success(),
        "build-provenance controls failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8(output.stdout)
            .expect("control output is UTF-8")
            .ends_with("build-provenance controls passed\n")
    );
}

#[test]
fn the_binary_runs_config_dir_guard_controls() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new(env!("CARGO_BIN_EXE_harness"))
        .args([
            "config-dir-guard",
            "--self-test",
            "--repo-root",
            repo_root.to_str().expect("workspace path is UTF-8"),
        ])
        .output()
        .expect("the harness binary runs configuration-directory guard controls");
    assert!(
        output.status.success(),
        "configuration-directory guard controls failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8(output.stdout)
            .expect("control output is UTF-8")
            .ends_with("config-dir guard tests passed\n")
    );
}

/// A failed command says which command failed. The shared prefix named whichever
/// port was written first, which mislabels every later one, so the label comes
/// from the subcommand that ran.
#[test]
fn the_binary_labels_a_failure_with_the_command_that_failed() {
    let output = Command::new(env!("CARGO_BIN_EXE_harness"))
        .args(["config-dir-guard", "--project-hash", "/does/not/exist"])
        .output()
        .expect("the harness binary runs");
    assert!(!output.status.success(), "a missing path must fail");
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert!(
        stderr.starts_with("config-dir guard: FAIL: "),
        "the failure must name its own command: {stderr}"
    );
}

#[test]
fn the_binary_runs_cpu_commitment_controls() {
    let output = harness(["cpu-commitment".to_owned(), "--self-test".to_owned()]);
    assert!(
        output.status.success(),
        "cpu-commitment controls failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8(output.stdout)
            .expect("control output is UTF-8")
            .ends_with("cpu-commitment controls passed\n")
    );
}

/// The wrapper distinguishes 0, 1, 2 and 3, so the shipped binary has to keep
/// all four. Collapsing a refusal into an inconclusive verdict (or the reverse)
/// would silently change what a failed Phase 0 run means.
#[test]
fn the_binary_keeps_the_cpu_commitment_exit_statuses() {
    let scratch = Scratch::new("cpu-commitment-status");
    let isolated = scratch.path.join("isolated");
    let deps = isolated.join("deps");
    fs::create_dir_all(&deps).expect("create the isolated target");
    let artifact = deps.join("agent_vm-aaaa");
    fs::write(&artifact, "fixture").expect("write the artifact");
    let ledger = scratch.path.join("good.jsonl");
    let rows = [
        json!({"reason": "build-finished", "success": true}),
        json!({
            "reason": "compiler-artifact",
            "target": {"name": "agent-vm", "kind": ["bin"]},
            "profile": {"test": true},
            "executable": artifact,
        }),
    ];
    fs::write(
        &ledger,
        rows.iter()
            .map(|row| format!("{}\n", row))
            .collect::<String>(),
    )
    .expect("write the Cargo ledger");

    let words = |arguments: &[&str]| -> Vec<String> {
        let mut words = vec!["cpu-commitment".to_owned()];
        words.extend(arguments.iter().map(|word| (*word).to_owned()));
        words
    };
    let text = |outcome: &Output| {
        (
            String::from_utf8(outcome.stdout.clone()).expect("stdout is UTF-8"),
            String::from_utf8(outcome.stderr.clone()).expect("stderr is UTF-8"),
        )
    };

    let selected = harness(words(&[
        "select",
        ledger.to_str().expect("ledger path is UTF-8"),
        isolated.to_str().expect("target path is UTF-8"),
    ]));
    let (stdout, stderr) = text(&selected);
    assert_eq!(selected.status.code(), Some(0), "select refused: {stderr}");
    assert_eq!(
        stdout,
        format!(
            "{}\n",
            fs::canonicalize(&artifact)
                .expect("the artifact resolves")
                .display()
        )
    );

    let empty = scratch.path.join("empty.jsonl");
    fs::write(
        &empty,
        "{\"reason\": \"build-finished\", \"success\": true}\n",
    )
    .expect("write an artifact-free ledger");
    let refused = harness(words(&[
        "select",
        empty.to_str().expect("ledger path is UTF-8"),
        isolated.to_str().expect("target path is UTF-8"),
    ]));
    let (_, stderr) = text(&refused);
    assert_eq!(refused.status.code(), Some(1), "a refusal is status 1");
    assert!(
        stderr.contains("select: expected exactly one agent-vm test artifact, got 0"),
        "the refusal must be attributable: {stderr}"
    );

    let misuse = harness(words(&[
        "select",
        ledger.to_str().expect("ledger path is UTF-8"),
    ]));
    assert_eq!(misuse.status.code(), Some(2), "wrong arity is misuse");

    let evidence = scratch.path.join("evidence");
    fs::create_dir_all(&evidence).expect("create the evidence directory");
    let msb = scratch.path.join("msb");
    let firmware = scratch.path.join("firmware");
    fs::write(&msb, "msb").expect("write the msb fixture");
    fs::write(&firmware, "firmware").expect("write the firmware fixture");
    let sha = "a".repeat(40);
    let written = harness(words(&[
        "manifest",
        "write",
        evidence.to_str().expect("evidence path is UTF-8"),
        msb.to_str().expect("msb path is UTF-8"),
        firmware.to_str().expect("firmware path is UTF-8"),
        &sha,
        &sha,
    ]));
    assert_eq!(
        written.status.code(),
        Some(0),
        "manifest write failed: {}",
        String::from_utf8_lossy(&written.stderr)
    );

    let verified = harness(words(&[
        "manifest",
        "verify",
        evidence.to_str().expect("evidence path is UTF-8"),
        msb.to_str().expect("msb path is UTF-8"),
        firmware.to_str().expect("firmware path is UTF-8"),
    ]));
    let (stdout, stderr) = text(&verified);
    assert_eq!(verified.status.code(), Some(0), "verify refused: {stderr}");
    assert_eq!(stdout, "manifest: ok\n");

    let absent = scratch.path.join("absent");
    fs::create_dir_all(&absent).expect("create the empty evidence directory");
    let inconclusive = harness(words(&[
        "manifest",
        "verify",
        absent.to_str().expect("evidence path is UTF-8"),
        msb.to_str().expect("msb path is UTF-8"),
        firmware.to_str().expect("firmware path is UTF-8"),
    ]));
    let (_, stderr) = text(&inconclusive);
    assert_eq!(
        inconclusive.status.code(),
        Some(3),
        "inconclusive evidence is status 3: {stderr}"
    );
    assert!(
        stderr.starts_with("manifest: INCONCLUSIVE: the manifest "),
        "the verdict must be reported as inconclusive: {stderr}"
    );

    let verify_misuse = harness(words(&[
        "manifest",
        "verify",
        evidence.to_str().expect("evidence path is UTF-8"),
    ]));
    assert_eq!(
        verify_misuse.status.code(),
        Some(2),
        "manifest misuse is status 2"
    );
}

// --- Released-image launch (#691) ------------------------------------------
//
// The shell callers read this helper's exit status and rely on it stopping the
// whole owned group, so the controls that need a real process boundary run the
// shipped binary: a library call would pass while the binary's argument
// forwarding or its exit status mapping was wrong.

/// The launched candidate fixture: it and its grandchild ignore SIGTERM, so only
/// the escalation to SIGKILL can stop them. 300 s is a leak bound, not a budget.
const LAUNCH_SCENARIO: &str =
    "#!/bin/sh\ntrap '' TERM\nsleep 300 &\nprintf '%s %s\\n' \"$$\" \"$!\" > \"$1\"\nsleep 300\n";

struct LaunchFixture {
    scratch: Scratch,
    scenario: PathBuf,
}

impl LaunchFixture {
    fn new(label: &str) -> Self {
        let scratch = Scratch::new(label);
        let scenario = scratch.path.join("scenario.sh");
        fs::write(&scenario, LAUNCH_SCENARIO).expect("write the launch scenario");
        fs::set_permissions(&scenario, fs::Permissions::from_mode(0o755))
            .expect("make the launch scenario executable");
        Self { scratch, scenario }
    }

    /// The launcher's arguments up to the `--` that separates the candidate's.
    fn arguments(&self, binary: &Path, timeout: &str) -> Vec<String> {
        let path = |name: &str| self.scratch.path.join(name).display().to_string();
        vec![
            "released-image-launch".to_owned(),
            "--root".to_owned(),
            path("root"),
            "--shim".to_owned(),
            path("shim"),
            "--log".to_owned(),
            path("builder.log"),
            "--binary".to_owned(),
            binary.display().to_string(),
            "--timeout".to_owned(),
            timeout.to_owned(),
            "--grace".to_owned(),
            "1".to_owned(),
            "--".to_owned(),
        ]
    }

    fn command(&self, binary: &Path, timeout: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_harness"));
        command.args(self.arguments(binary, timeout));
        command
    }
}

fn wait_for_pids(pidfile: &Path) -> Vec<u32> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        if let Ok(recorded) = fs::read_to_string(pidfile) {
            let pids: Vec<u32> = recorded
                .split_whitespace()
                .filter_map(|field| field.parse().ok())
                .collect();
            if pids.len() == 2 {
                return pids;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    panic!("the launched scenario never recorded its pids");
}

fn wait_dead(pid: u32, seconds: u64) -> bool {
    let Some(pid) = rustix::process::Pid::from_raw(pid as i32) else {
        return true;
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
    while std::time::Instant::now() < deadline {
        if rustix::process::test_kill_process(pid).is_err() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    rustix::process::test_kill_process(pid).is_err()
}

/// SIGKILL whatever the scenario recorded, so a failed case cannot leave a
/// 300 s sleeper behind.
fn stop_recorded_group(pidfile: &Path) {
    let Ok(recorded) = fs::read_to_string(pidfile) else {
        return;
    };
    if let Some(pgid) = recorded
        .split_whitespace()
        .next()
        .and_then(|pid| pid.parse::<i32>().ok())
        .and_then(rustix::process::Pid::from_raw)
    {
        let _ = rustix::process::kill_process_group(pgid, rustix::process::Signal::KILL);
    }
}

/// The child the launcher started must be its own group and session leader:
/// that is what makes "signal the group" mean "signal exactly what this launch
/// created". Checked while it is alive, because the kernel forgets a dead pid's
/// group.
fn assert_owned_leader(pids: &[u32]) {
    let pid = rustix::process::Pid::from_raw(pids[0] as i32).expect("the recorded pid is valid");
    assert_eq!(
        rustix::process::getpgid(Some(pid)).expect("the launched child has a group"),
        pid,
        "the launched child is not its own group leader"
    );
    assert_eq!(
        rustix::process::getsid(Some(pid)).expect("the launched child has a session"),
        pid,
        "the launched child is not its own session leader"
    );
}

fn assert_group_stopped(pids: &[u32], pidfile: &Path) {
    if !wait_dead(pids[0], 5) {
        stop_recorded_group(pidfile);
        panic!("the launched child {} survived", pids[0]);
    }
    if !wait_dead(pids[1], 5) {
        stop_recorded_group(pidfile);
        panic!("the launched grandchild {} survived", pids[1]);
    }
}

#[test]
fn the_binary_runs_released_image_launch_controls() {
    let output = harness(["released-image-launch".to_owned(), "--self-test".to_owned()]);
    assert!(
        output.status.success(),
        "released-image-launch controls failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("control output is UTF-8"),
        "released-image launch timeout/interruption/group controls passed\n"
    );
}

/// The launcher's interface is its exit status: 0..255 from the candidate, 124
/// for a timeout, 128+N for an interruption, 2 for a bound that cannot
/// terminate, and 1 for a group that could not be reaped.
#[test]
fn the_binary_keeps_the_released_image_launch_exit_statuses() {
    let fixture = LaunchFixture::new("released-image-launch-status");

    let normal = fixture
        .command(Path::new("/bin/sh"), "30")
        .args(["-c", "exit 7"])
        .output()
        .expect("the harness binary runs a normal launch");
    assert_eq!(
        normal.status.code(),
        Some(7),
        "a normal launch must return the child's status: {}",
        String::from_utf8_lossy(&normal.stderr)
    );

    // A bound that cannot terminate is refused before any child exists.
    let marker = fixture.scratch.path.join("invalid-bound.marker");
    for (option, value) in [
        ("--timeout=nan", "NaN"),
        ("--timeout=inf", "infinity"),
        ("--timeout=0", "zero"),
        ("--timeout=-1", "negative"),
        ("--grace=nan", "NaN grace"),
        ("--grace=inf", "infinite grace"),
        ("--grace=0", "zero grace"),
        ("--grace=-1", "negative grace"),
    ] {
        let refused = fixture
            .command(Path::new("/bin/sh"), "30")
            .arg(option)
            .args(["-c", &format!("printf spawned > {}", marker.display())])
            .output()
            .expect("the harness binary refuses an invalid bound");
        assert_eq!(
            refused.status.code(),
            Some(2),
            "a {value} bound must be misuse: {}",
            String::from_utf8_lossy(&refused.stderr)
        );
        assert!(
            !marker.exists(),
            "a {value} bound spawned a child instead of refusing"
        );
    }

    let pidfile = fixture.scratch.path.join("timeout.pids");
    let timed_out = fixture
        .command(&fixture.scenario, "0.5")
        .arg(&pidfile)
        .spawn()
        .expect("the harness binary launches the scenario");
    let pids = wait_for_pids(&pidfile);
    assert_owned_leader(&pids);
    let status = timed_out
        .wait_with_output()
        .expect("the timed-out launch exits");
    assert_eq!(status.status.code(), Some(124), "a timeout is status 124");
    assert_group_stopped(&pids, &pidfile);
}

/// A signal to the *parent* must not leave the new-session candidate, or the
/// native descendant it spawned, alive and mutating private state.
#[test]
fn the_binary_stops_the_owned_group_when_interrupted() {
    let fixture = LaunchFixture::new("released-image-launch-signal");
    for (label, signal, expected) in [
        ("sigint", rustix::process::Signal::INT, 130),
        ("sigterm", rustix::process::Signal::TERM, 143),
    ] {
        let pidfile = fixture.scratch.path.join(format!("{label}.pids"));
        let launcher = fixture
            .command(&fixture.scenario, "3600")
            .arg(&pidfile)
            .spawn()
            .expect("the harness binary launches the scenario");
        let pids = wait_for_pids(&pidfile);
        assert_owned_leader(&pids);
        rustix::process::kill_process(
            rustix::process::Pid::from_raw(launcher.id() as i32)
                .expect("the launcher is a valid pid"),
            signal,
        )
        .expect("the launcher accepts the signal");
        let status = launcher
            .wait_with_output()
            .expect("the interrupted launcher exits");
        if status.status.code() != Some(expected) {
            stop_recorded_group(&pidfile);
            panic!(
                "{label}: the launcher exited {:?}, expected {expected}: {}",
                status.status,
                String::from_utf8_lossy(&status.stderr)
            );
        }
        assert_group_stopped(&pids, &pidfile);
    }
}

#[test]
fn the_binary_canonicalizes_existing_and_absent_paths() {
    let scratch = Scratch::new("released-image-launch-canonicalize");
    let real = scratch.path.join("real");
    fs::create_dir_all(real.join("nested")).expect("create the canonicalize fixture");
    let link = scratch.path.join("link");
    std::os::unix::fs::symlink(&real, &link).expect("link the canonicalize fixture");
    let canonical = fs::canonicalize(&real).expect("the fixture resolves");

    let existing = harness([
        "released-image-launch".to_owned(),
        "--canonicalize".to_owned(),
        link.join("nested").display().to_string(),
    ]);
    assert_eq!(
        existing.status.code(),
        Some(0),
        "canonicalizing an existing path failed: {}",
        String::from_utf8_lossy(&existing.stderr)
    );
    assert_eq!(
        String::from_utf8(existing.stdout).expect("the canonical path is UTF-8"),
        format!("{}\n", canonical.join("nested").display())
    );

    // The absent build-source check compares this against the recorded path, so
    // the resolved prefix has to survive even though the leaf does not exist.
    let absent = harness([
        "released-image-launch".to_owned(),
        "--canonicalize".to_owned(),
        link.join("nested/absent").display().to_string(),
    ]);
    assert_eq!(absent.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(absent.stdout).expect("the canonical path is UTF-8"),
        format!("{}\n", canonical.join("nested/absent").display())
    );
}
