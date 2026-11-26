//! The binary the shell calls actually builds and runs. A lib-only test would
//! pass while `[[bin]]` was misconfigured, which is the failure this catches.

use serde_json::{Value, json};
use std::{
    env, fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
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

/// The persisted network's host-only probe group is shipped, not a library
/// detail: `persisted-network-contract.sh` calls this subcommand, and a
/// misconfigured `[[bin]]` would leave the shell suite calling nothing. The
/// slower helper and live-shell groups run from that script, not here.
#[test]
fn the_binary_runs_the_persisted_network_probe_controls() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new(env!("CARGO_BIN_EXE_harness"))
        .args([
            "persisted-network-controls",
            "--repo-root",
            repo_root.to_str().expect("workspace path is UTF-8"),
            "--only",
            "probe",
        ])
        .output()
        .expect("the harness binary runs the persisted-network probe controls");
    assert!(
        output.status.success(),
        "persisted network probe controls failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("control output is UTF-8");
    assert!(
        stdout.ends_with("persisted network host-only controls PASS\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains("probe guest PASS"),
        "the guest probe control did not run: {stdout}"
    );
}

/// The rows refuse misuse by name and status, before touching a scratch root:
/// a driver that started with the wrong arity would look like a failing row.
#[test]
fn the_persisted_network_driver_refuses_misuse() {
    let output = harness([
        "persisted-network".to_owned(),
        "--repo-root".to_owned(),
        "/tmp".to_owned(),
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .starts_with("usage: persisted-network --repo-root DIR ROOT EVIDENCE BINARY IMAGE"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
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

#[test]
fn the_binary_runs_config_mounts_controls() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new(env!("CARGO_BIN_EXE_harness"))
        .args([
            "config-mounts-controls",
            "--repo-root",
            repo_root.to_str().expect("workspace path is UTF-8"),
        ])
        .output()
        .expect("the harness binary runs the config-mounts controls");
    assert!(
        output.status.success(),
        "config mounts controls failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("control output is UTF-8");
    // Every group ran, not just the cheap one: the receipt's oracle, the GM
    // dispatch over a real fixture, and the guard-rail mutations.
    for line in [
        "config mounts receipt controls passed",
        "config mounts dispatch controls passed",
        "config mounts guard removal mutations passed",
        "config mounts host-only controls PASS",
    ] {
        assert!(stdout.contains(line), "missing {line:?} in: {stdout}");
    }
}

/// A group selector that matches nothing would report a pass for a group that
/// never ran, so an unknown `--only` is misuse, not a no-op.
#[test]
fn the_binary_refuses_an_unknown_config_mounts_group() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new(env!("CARGO_BIN_EXE_harness"))
        .args([
            "config-mounts-controls",
            "--repo-root",
            repo_root.to_str().expect("workspace path is UTF-8"),
            "--only",
            "receipts",
        ])
        .output()
        .expect("the harness binary runs the config-mounts controls");
    assert_eq!(output.status.code(), Some(2), "an unknown group is misuse");
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert!(
        stderr.contains("--only must be one of receipt, dispatch, guard"),
        "the refusal must name the groups: {stderr}"
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

// --- The detach shim and the launcher stand-in (#698) -----------------------

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn the_binary_runs_detached_run_controls() {
    let output = harness(["detached-run".to_owned(), "--self-test".to_owned()]);
    assert!(
        output.status.success(),
        "detached-run controls failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("control output is UTF-8"),
        "detached-run: OK (a real controlling terminal is removed; the child is a session leader \
         with /dev/null stdin)\n"
    );
}

#[test]
fn the_binary_runs_launcher_standin_controls() {
    let output = harness([
        "launcher-standin".to_owned(),
        "--self-test".to_owned(),
        "--repo-root".to_owned(),
        repo_root().display().to_string(),
    ]);
    assert!(
        output.status.success(),
        "launcher-standin controls failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("control output is UTF-8"),
        "launcher-standin: OK (every mode's frames, statuses and terminal transitions)\n"
    );
}

/// The shim's interface is a process's status, so the shipped binary is where it
/// has to hold: the child's code, a signalled child, both channels inherited,
/// `/dev/null` on stdin, and misuse kept apart from a failing child.
#[test]
fn the_binary_detaches_its_program_and_propagates_its_status() {
    let detached = |script: &str| {
        harness([
            "detached-run".to_owned(),
            "--".to_owned(),
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            script.to_owned(),
        ])
    };

    let channels = detached("echo out; echo err >&2; exit 7");
    assert_eq!(channels.status.code(), Some(7));
    assert_eq!(
        String::from_utf8(channels.stdout).expect("the child's stdout is UTF-8"),
        "out\n"
    );
    assert_eq!(
        String::from_utf8(channels.stderr).expect("the child's stderr is UTF-8"),
        "err\n"
    );

    // Python's `sys.exit(subprocess.run(...).returncode)` truncated the negative
    // signal number to 256 - N.
    let signalled = detached("kill -TERM $$");
    assert_eq!(signalled.status.code(), Some(241));

    let stdin = detached("read -r line && echo read || echo eof");
    assert_eq!(stdin.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(stdin.stdout).expect("the child's stdout is UTF-8"),
        "eof\n"
    );

    let misuse = harness(["detached-run".to_owned()]);
    assert_eq!(misuse.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(misuse.stderr).expect("the misuse message is UTF-8"),
        "detached-run: expected a program to run\n"
    );
}

/// A launcher stand-in's statuses are its own 64 for misuse, the guest's
/// otherwise; #699's fixtures read both.
#[test]
fn the_binary_keeps_the_launcher_standin_statuses() {
    let status = harness([
        "launcher-standin".to_owned(),
        "--image".to_owned(),
        "contract-image".to_owned(),
        "run".to_owned(),
        "/bin/sh".to_owned(),
        "-c".to_owned(),
        "exit 3".to_owned(),
    ]);
    assert_eq!(status.status.code(), Some(3));

    let misuse = harness([
        "launcher-standin".to_owned(),
        "--image".to_owned(),
        "contract-image".to_owned(),
        "run".to_owned(),
    ]);
    assert_eq!(misuse.status.code(), Some(64));
    assert_eq!(
        String::from_utf8(misuse.stderr).expect("the misuse message is UTF-8"),
        "standin: no program after the command boundary\n"
    );
}

// --- The egress fixtures (#692) ---------------------------------------------

fn egress(arguments: impl IntoIterator<Item = String>) -> Output {
    let mut argv = vec!["egress-fixtures".to_owned()];
    argv.extend(arguments);
    harness(argv)
}

/// `wait-receipt`'s three statuses are its interface: an egress denial oracle
/// needs "not yet" (1, only after the whole bound) apart from "never" (2).
#[test]
fn the_binary_keeps_the_wait_receipt_statuses() {
    let scratch = Scratch::new("egress-wait");
    fs::write(
        scratch.path.join("receipts.log"),
        "tcp 18080 127.0.0.1 owned-receipt\n",
    )
    .expect("a receipt log");
    let directory = scratch.path.to_str().expect("a UTF-8 scratch path");

    let seen = egress([
        "wait-receipt".to_owned(),
        "--dir".to_owned(),
        directory.to_owned(),
        "owned-receipt".to_owned(),
        "--timeout".to_owned(),
        "0".to_owned(),
    ]);
    assert_eq!(seen.status.code(), Some(0));

    // A prefix of a recorded id is not the id: an ID match that ran on prefixes
    // would certify a probe that never arrived.
    let prefix = egress([
        "wait-receipt".to_owned(),
        "--dir".to_owned(),
        directory.to_owned(),
        "owned".to_owned(),
        "--timeout".to_owned(),
        "0".to_owned(),
    ]);
    assert_eq!(prefix.status.code(), Some(1));

    let started = std::time::Instant::now();
    let unseen = egress([
        "wait-receipt".to_owned(),
        "--dir".to_owned(),
        directory.to_owned(),
        "never-written".to_owned(),
        "--timeout".to_owned(),
        "0.3".to_owned(),
    ]);
    assert_eq!(unseen.status.code(), Some(1));
    assert!(
        started.elapsed() >= std::time::Duration::from_millis(300),
        "the absence bound must elapse before 'never' is answered"
    );

    // An unreadable log is an internal error (2), and says so on stderr.
    let unreadable = egress([
        "wait-receipt".to_owned(),
        "--dir".to_owned(),
        scratch
            .path
            .join("receipts.log")
            .to_str()
            .expect("a path")
            .to_owned(),
        "owned-receipt".to_owned(),
        "--timeout".to_owned(),
        "0".to_owned(),
    ]);
    assert_eq!(unreadable.status.code(), Some(2));
    assert!(
        String::from_utf8(unreadable.stderr)
            .expect("a UTF-8 message")
            .starts_with("wait-receipt: "),
        "an internal error names itself"
    );

    // A bound that cannot be waited is misuse, not a wait that fails.
    let misuse = egress([
        "wait-receipt".to_owned(),
        "--dir".to_owned(),
        directory.to_owned(),
        "owned-receipt".to_owned(),
        "--timeout".to_owned(),
        "-1".to_owned(),
    ]);
    assert_eq!(misuse.status.code(), Some(2));
}

#[test]
fn the_binary_answers_resolve() {
    // A literal address needs no resolver, so this control is the same on every
    // host; the JSON is printed whether or not the address is among them,
    // because a failing calibration is diagnosed from the answer.
    let found = egress([
        "resolve".to_owned(),
        "127.0.0.1".to_owned(),
        "127.0.0.1".to_owned(),
    ]);
    assert_eq!(found.status.code(), Some(0));
    let answer: serde_json::Value =
        serde_json::from_slice(&found.stdout).expect("resolve prints JSON");
    assert_eq!(answer["name"], json!("127.0.0.1"));
    assert_eq!(answer["addresses"], json!(["127.0.0.1"]));

    let other = egress([
        "resolve".to_owned(),
        "127.0.0.1".to_owned(),
        "127.0.0.2".to_owned(),
    ]);
    assert_eq!(other.status.code(), Some(1));
    assert!(!other.stdout.is_empty(), "the answer is printed either way");
}

/// The supervisor's statuses: `ready` only once every listener bound, 0 on
/// SIGTERM, and `health` 1 as soon as its readiness marker is gone.
#[test]
fn the_binary_serves_the_egress_fixtures() {
    let scratch = Scratch::new("egress-serve");
    let directory = scratch.path.join("fx");
    let mut child = Command::new(env!("CARGO_BIN_EXE_harness"))
        .args([
            "egress-fixtures",
            "serve",
            "--dir",
            directory.to_str().expect("a UTF-8 scratch path"),
            "--ephemeral-ports",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("the fixture supervisor starts");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !directory.join("ready").is_file() {
        assert!(
            child.try_wait().expect("poll the supervisor").is_none(),
            "the supervisor exited before it was ready"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "the supervisor did not become ready"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let ports: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(directory.join("ports.json")).expect("ports.json"),
    )
    .expect("ports.json is JSON");
    for kind in ["tcp", "udp"] {
        assert_eq!(ports[kind].as_array().map(Vec::len), Some(2), "{kind}");
        for port in ports[kind].as_array().expect("a list") {
            let port = port.as_u64().expect("a number");
            assert!(
                (1..65535).contains(&port),
                "{kind} port {port} was not bound"
            );
        }
    }
    let healthy = egress([
        "health".to_owned(),
        "--dir".to_owned(),
        directory.to_str().expect("a UTF-8 scratch path").to_owned(),
    ]);
    assert_eq!(healthy.status.code(), Some(0));

    unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
    assert_eq!(child.wait().expect("the supervisor exits").code(), Some(0));

    fs::remove_file(directory.join("ready")).expect("remove readiness");
    let unhealthy = egress([
        "health".to_owned(),
        "--dir".to_owned(),
        directory.to_str().expect("a UTF-8 scratch path").to_owned(),
    ]);
    assert_eq!(unhealthy.status.code(), Some(1));
}

/// An exec shim's status is its candidate's, and its identity receipt exists
/// before the candidate runs: a launch the candidate refuses can still be
/// reaped.
#[test]
fn the_binary_shims_an_exec_into_an_owned_identity() {
    let scratch = Scratch::new("egress-shim");
    let identity = scratch.path.join("id.json");
    let log = scratch.path.join("shim.log");
    let status = egress([
        "exec-shim".to_owned(),
        "--identity".to_owned(),
        identity.to_str().expect("a UTF-8 scratch path").to_owned(),
        "--output".to_owned(),
        log.to_str().expect("a UTF-8 scratch path").to_owned(),
        "--environment".to_owned(),
        "{\"PATH\":\"/usr/bin:/bin\",\"MARK\":\"only-this\"}".to_owned(),
        "--".to_owned(),
        "/bin/sh".to_owned(),
        "-c".to_owned(),
        "echo \"mark=$MARK home=${HOME-unset}\"; exit 7".to_owned(),
    ]);
    assert_eq!(status.status.code(), Some(7));
    assert_eq!(
        fs::read_to_string(&log).expect("the shim log"),
        // The environment is replaced, not extended: an inherited HOME would be
        // a variable the harness never granted leaking into a deny row.
        "mark=only-this home=unset\n"
    );
    let recorded: serde_json::Value =
        serde_json::from_slice(&fs::read(&identity).expect("the identity receipt"))
            .expect("the identity receipt is JSON");
    assert!(recorded["pid"].as_u64().expect("a pid") > 0);
    assert_eq!(
        recorded["start"].as_array().map(Vec::len),
        Some(2),
        "the start time is a (seconds, microseconds) pair"
    );
    assert!(recorded["pgid"].as_u64().expect("a pgid") > 0);
}

#[test]
fn the_binary_runs_the_egress_fixture_controls() {
    let output = egress(["self-test".to_owned()]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("the control output is UTF-8");
    for claim in [
        "host-only SNI parser and opaque recorder controls PASS",
        "self-test: both TCP, both UDP, CONNECT and full 3s absence OK",
        "self-test: HN/OP gate and outcome-(d) wording OK",
    ] {
        assert!(stdout.contains(claim), "missing claim: {claim}\n{stdout}");
    }
}

/// The §6.7 join reads this output: 85 cases and nine administrative objects,
/// each a JSON object on its own line, and the smoke tier a strict subset.
#[test]
fn the_binary_prints_the_whole_case_plan() {
    let plan = egress([
        "run".to_owned(),
        "--print-plan".to_owned(),
        "--work".to_owned(),
        "/var/tmp/av302.PLAN".to_owned(),
        "--binary".to_owned(),
        "/absolute/bundle/bin/agent-vm".to_owned(),
        "--lan".to_owned(),
        "192.168.1.2".to_owned(),
    ]);
    assert_eq!(
        plan.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&plan.stderr)
    );
    let rows: Vec<serde_json::Value> = String::from_utf8(plan.stdout)
        .expect("the plan is UTF-8")
        .lines()
        .map(|line| serde_json::from_str(line).expect("each line is a JSON object"))
        .collect();
    assert_eq!(rows.len(), 94);
    let cases: Vec<&serde_json::Value> = rows.iter().filter(|row| row["kind"] != "admin").collect();
    assert_eq!(cases.len(), 85);
    assert_eq!(
        rows.iter().filter(|row| row["kind"] == "admin").count(),
        9,
        "nine administrative objects"
    );
    // Every case row is executable: an argv, a cwd, a supervisor and a shim that
    // names this binary, so the plan and the supervisor cannot disagree.
    for row in &cases {
        assert!(row["argv"].as_array().is_some_and(|argv| !argv.is_empty()));
        assert!(row["cwd"].as_str().is_some_and(|cwd| !cwd.is_empty()));
        assert!(
            row["supervisor"]
                .as_str()
                .is_some_and(|text| !text.is_empty())
        );
        let shim = row["shim"]["argv"].as_array().expect("a shim argv");
        assert_eq!(shim[1], "egress-fixtures");
        assert_eq!(shim[2], "exec-shim");
    }
    // The smoke tier is the numeric subset plus RF1's two variants: 11 cases,
    // the same nine administrative objects.
    let smoke = egress([
        "run".to_owned(),
        "--print-plan".to_owned(),
        "--smoke".to_owned(),
        "--work".to_owned(),
        "/var/tmp/av302.PLAN".to_owned(),
        "--binary".to_owned(),
        "/absolute/bundle/bin/agent-vm".to_owned(),
        "--lan".to_owned(),
        "192.168.1.2".to_owned(),
    ]);
    assert_eq!(smoke.status.code(), Some(0));
    let smoke: Vec<serde_json::Value> = String::from_utf8(smoke.stdout)
        .expect("the plan is UTF-8")
        .lines()
        .map(|line| serde_json::from_str(line).expect("each line is a JSON object"))
        .collect();
    assert_eq!(smoke.len(), 20);
    assert_eq!(
        smoke.iter().filter(|row| row["kind"] != "admin").count(),
        11
    );
}

/// A run without a candidate, the assets and a fixture LAN is refused *before*
/// anything is created: a sweep that guessed them would launch something else, and
/// one that started and then refused would leave a work directory behind.
#[test]
fn the_binary_refuses_a_run_without_a_candidate() {
    let refused = egress(["run".to_owned()]);
    assert_eq!(refused.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("native run requires absolute AGENT_VM_BIN"),
        "{stderr}"
    );
    assert!(refused.stdout.is_empty(), "no plan is printed");
    // A relative candidate is refused rather than resolved against the cwd.
    let relative = egress([
        "run".to_owned(),
        "--binary".to_owned(),
        "target/debug/agent-vm".to_owned(),
        "--assets".to_owned(),
        "/tmp/assets".to_owned(),
        "--lan".to_owned(),
        "192.168.1.2".to_owned(),
    ]);
    assert_eq!(relative.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&relative.stderr)
            .contains("native run requires absolute AGENT_VM_BIN"),
        "{}",
        String::from_utf8_lossy(&relative.stderr)
    );
    // And a public fixture LAN is refused: it would dial someone else's host.
    let public = egress([
        "run".to_owned(),
        "--binary".to_owned(),
        "/absolute/bundle/bin/agent-vm".to_owned(),
        "--assets".to_owned(),
        "/tmp/assets".to_owned(),
        "--lan".to_owned(),
        "203.0.113.9".to_owned(),
    ]);
    assert_eq!(public.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&public.stderr).contains("RFC1918/CGN"),
        "{}",
        String::from_utf8_lossy(&public.stderr)
    );
}

/// The ingress driver: I1 waits for the guest's readiness line, I2 joins the
/// published body against the case id.
///
/// The driver publishes IN1 on the host port the catalogue gives it (18556), so
/// the control binds that port itself and answers the two bodies that decide the
/// verdict.
#[test]
fn the_binary_joins_the_ingress_body() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let serve = |body: &'static str| {
        let listener = TcpListener::bind(("127.0.0.1", 18556))
            .expect("the IN1 host port 18556 is free for the ingress control");
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                let mut request = [0u8; 1024];
                let _ = stream.read(&mut request);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        })
    };

    let scratch = Scratch::new("egress-ingress");
    fs::write(
        scratch.path.join("IN1.log"),
        "booting\nINGRESS_READY IN1 8000\n",
    )
    .expect("the launch log");
    // The administrative command runs in the case's project, as every launch
    // does, so the directory exists before the driver starts.
    fs::create_dir_all(scratch.path.join("proj")).expect("the project directory");
    let directory = scratch.path.to_str().expect("a UTF-8 scratch path");
    let responder = serve("ingress IN1");
    let matched = egress([
        "ingress".to_owned(),
        "--work".to_owned(),
        directory.to_owned(),
        "--case".to_owned(),
        "IN1".to_owned(),
        "--id".to_owned(),
        "IN1".to_owned(),
    ]);
    assert_eq!(
        matched.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&matched.stderr)
    );
    responder.join().expect("the responder finished");
    // The administrative command leaves its own receipts, so the join can be read
    // back instead of inferred from the status alone.
    let owned = fs::read_to_string(scratch.path.join("owned.jsonl")).expect("the admin receipts");
    assert!(owned.contains("\"phase\":\"admin\""));
    assert!(owned.contains("\"phase\":\"admin-result\""));

    // A body that is not exactly the id is a mismatch, not a pass.
    let scratch = Scratch::new("egress-ingress-wrong");
    fs::write(
        scratch.path.join("IN1.log"),
        "booting\nINGRESS_READY IN1 8000\n",
    )
    .expect("the launch log");
    fs::create_dir_all(scratch.path.join("proj")).expect("the project directory");
    let directory = scratch.path.to_str().expect("a UTF-8 scratch path");
    let responder = serve("ingress IN1 ");
    let mismatched = egress([
        "ingress".to_owned(),
        "--work".to_owned(),
        directory.to_owned(),
        "--case".to_owned(),
        "IN1".to_owned(),
        "--id".to_owned(),
        "IN1".to_owned(),
    ]);
    assert_eq!(mismatched.status.code(), Some(1));
    responder.join().expect("the responder finished");
}

/// A candidate that answers the CLI's own `msb list` with an empty catalog and
/// otherwise prints its environment and exits 7. Through the shipped binary the
/// shim is the real `exec-shim`, so the status, the environment and the identity
/// receipt are the ones a launch actually gets.
fn fake_candidate(work: &Path) -> PathBuf {
    let path = work.join("fake-agent-vm");
    fs::write(
        &path,
        "#!/bin/sh\n\
         if [ \"$1\" = msb ] && [ \"$2\" = list ]; then echo '[]'; exit 0; fi\n\
         env\n\
         exit 7\n",
    )
    .expect("the candidate script");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("an executable script");
    path
}

fn launch_work(label: &str) -> Scratch {
    let scratch = Scratch::new(label);
    for name in ["proj", "home", "state/msb-home"] {
        fs::create_dir_all(scratch.path.join(name)).expect("the launch's directories");
    }
    scratch
}

/// The launch supervisor end to end: `exec-shim` writes the identity, replaces
/// the environment, the candidate's status is the launch's status, and cleanup
/// leaves a receipt behind.
#[test]
fn the_binary_launches_and_cleans_up() {
    let scratch = launch_work("egress-launch");
    let candidate = fake_candidate(&scratch.path);
    let launched = egress([
        "launch".to_owned(),
        "--work".to_owned(),
        scratch.path.to_str().unwrap().to_owned(),
        "--case".to_owned(),
        "PX1".to_owned(),
        "--timeout".to_owned(),
        "30".to_owned(),
        "--grace".to_owned(),
        "5".to_owned(),
        "--env".to_owned(),
        "HTTP_PROXY=http://127.0.0.1:18888".to_owned(),
        "--".to_owned(),
        candidate.to_str().unwrap().to_owned(),
    ]);
    assert_eq!(
        launched.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&launched.stderr)
    );
    let receipts = fs::read_to_string(scratch.path.join("owned.jsonl")).expect("the receipts");
    for phase in ["prepared", "launcher", "primary", "cleanup"] {
        assert!(
            receipts.contains(phase),
            "missing phase {phase}: {receipts}"
        );
    }
    // The case log is the one the receipt named, and the environment in it is the
    // private one plus the permitted extra.
    let log = fs::read_dir(&scratch.path)
        .expect("the work directory")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .find(|path| {
            path.extension().is_some_and(|extension| {
                extension == "log" && !path.to_string_lossy().contains("admin-")
            })
        })
        .expect("the case log");
    let text = fs::read_to_string(&log).expect("the case log");
    assert!(text.contains("HTTP_PROXY=http://127.0.0.1:18888"), "{text}");
    // The launch canonicalizes its work, so `HOME` is the canonical spelling.
    let canonical = scratch
        .path
        .canonicalize()
        .expect("the work directory resolves");
    assert!(
        text.contains(&format!("HOME={}", canonical.join("home").display())),
        "the environment is replaced, not extended: {text}"
    );
}

/// A catalog that cannot be read is a cleanup failure, not a clean run: the
/// supervisor's claim is that the catalog is empty of its names, and it has to
/// be able to read the catalog to make that claim.
#[test]
fn a_launch_without_a_readable_catalog_is_not_green() {
    let scratch = launch_work("egress-launch-catalog");
    let launched = egress([
        "launch".to_owned(),
        "--work".to_owned(),
        scratch.path.to_str().unwrap().to_owned(),
        "--case".to_owned(),
        "LC1".to_owned(),
        "--timeout".to_owned(),
        "30".to_owned(),
        "--grace".to_owned(),
        "5".to_owned(),
        "--".to_owned(),
        // `/bin/true` answers `msb list` with success and no JSON at all.
        "/bin/true".to_owned(),
    ]);
    assert_eq!(
        launched.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&launched.stderr)
    );
}

/// The `--env` extras are whitelisted by case, and a refusal happens before
/// anything is spawned.
#[test]
fn the_binary_refuses_an_unpermitted_launch_extra() {
    let scratch = launch_work("egress-launch-env");
    let refused = egress([
        "launch".to_owned(),
        "--work".to_owned(),
        scratch.path.to_str().unwrap().to_owned(),
        "--case".to_owned(),
        "LC1".to_owned(),
        "--env".to_owned(),
        "HTTP_PROXY=http://127.0.0.1:18888".to_owned(),
        "--".to_owned(),
        "/bin/true".to_owned(),
    ]);
    assert_eq!(refused.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("launch environment permits only PX/FL extras"),
        "{stderr}"
    );
    assert!(
        !scratch.path.join("owned.jsonl").exists(),
        "a refused extra must not leave a receipt behind"
    );
    // `--timeout`/`--grace` are validated before the spawn too.
    let unusable = egress([
        "launch".to_owned(),
        "--work".to_owned(),
        scratch.path.to_str().unwrap().to_owned(),
        "--case".to_owned(),
        "LC1".to_owned(),
        "--timeout".to_owned(),
        "0".to_owned(),
        "--".to_owned(),
        "/bin/true".to_owned(),
    ]);
    assert_eq!(
        unusable.status.code(),
        Some(2),
        "a bound that cannot terminate is misuse"
    );
}

/// The mutation anchors CI resolves: every row's find text is present in this
/// checkout the expected number of times. The count is what `ci-contracts.sh`
/// prints, so a ledger edit that silently drops a row fails here too.
#[test]
fn the_binary_checks_the_mutation_anchors() {
    let output = harness(["egress-mutations".to_owned(), "--check-anchors".to_owned()]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("the anchor report is UTF-8"),
        "PASS: 297 mutation anchors (find text only; a real run compiles each replacement)\n"
    );
}

/// The refusals are distinguished from a surviving mutant: a missing
/// `--evidence`, and an `--only` that names no row, are misuse (2), not a FAIL.
#[test]
fn the_binary_refuses_mutation_misuse() {
    let no_evidence = harness(["egress-mutations".to_owned()]);
    assert_eq!(no_evidence.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&no_evidence.stderr).contains("--evidence is required"),
        "{}",
        String::from_utf8_lossy(&no_evidence.stderr)
    );
    let unmatched = harness([
        "egress-mutations".to_owned(),
        "--only".to_owned(),
        "no such mutation".to_owned(),
        "--evidence".to_owned(),
        env::temp_dir()
            .join(format!("harness-cli-mutations-{}", std::process::id()))
            .to_string_lossy()
            .into_owned(),
    ]);
    assert_eq!(unmatched.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&unmatched.stderr).contains("matched no mutation"),
        "{}",
        String::from_utf8_lossy(&unmatched.stderr)
    );
}

// --- #733: the host-managed project config path ----------------------------

/// `harness project-config-path` is what the shell suites seed, so the binary has
/// to print exactly the product's path. The expectation is recomputed here from
/// the canonical path's bytes, independently of the harness module.
#[test]
fn the_binary_prints_the_host_managed_project_config_path() {
    use sha2::{Digest as _, Sha256};
    use std::os::unix::ffi::OsStrExt as _;

    let scratch = Scratch::new("project-config-path");
    let home = scratch.path.join("home");
    let project = scratch.path.join("project");
    fs::create_dir_all(&home).expect("create home");
    fs::create_dir_all(&project).expect("create the project");
    let canonical = project.canonicalize().expect("canonicalize the project");
    let hex: String = Sha256::digest(canonical.as_os_str().as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let expected = home
        .join(".config/agent-vm/projects")
        .join(&hex)
        .join("config.toml");

    let output = harness([
        "project-config-path".to_owned(),
        "--home".to_owned(),
        home.to_string_lossy().into_owned(),
        "--project".to_owned(),
        project.to_string_lossy().into_owned(),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("UTF-8 path"),
        format!("{}\n", expected.display())
    );

    // A project that does not exist cannot be hashed: misuse (2), not a FAIL.
    let missing = harness([
        "project-config-path".to_owned(),
        "--home".to_owned(),
        home.to_string_lossy().into_owned(),
        "--project".to_owned(),
        scratch.path.join("missing").to_string_lossy().into_owned(),
    ]);
    assert_eq!(missing.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&missing.stderr).contains("cannot canonicalize"),
        "{}",
        String::from_utf8_lossy(&missing.stderr)
    );
}

// --- #700: the `e2e.sh` inline helpers -------------------------------------

/// Every `harness e2e-*` control runs through the binary the shell calls. A
/// missing dispatch arm would exit with a clap error here, not in a native row
/// nobody can run in CI.
#[test]
fn the_binary_runs_the_e2e_controls() {
    for (command, expected) in [
        ("e2e-cache-inventory", "e2e cache-inventory controls passed"),
        ("e2e-debug-json", "e2e debug-json controls passed"),
        ("e2e-direct-argv", "e2e direct-argv controls passed"),
        ("e2e-pin-observer", "e2e pin-observer controls passed"),
        ("e2e-registry-push", "e2e registry-push controls passed"),
        ("e2e-rss-standin", "e2e rss-standin controls passed"),
        ("e2e-state", "e2e state controls passed"),
        ("e2e-stdin-writer", "e2e stdin-writer controls passed"),
    ] {
        let output = harness([command.to_owned(), "--self-test".to_owned()]);
        assert!(
            output.status.success(),
            "{command} controls failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8(output.stdout).expect("control output is UTF-8"),
            format!("{expected}\n")
        );
    }
}

/// The state oracle keeps "absent" and "could not observe" apart, which is the
/// distinction `[ ! -e ]` cannot make.
#[test]
fn the_binary_observes_a_state_root() {
    let scratch = Scratch::new("e2e-state");
    fs::write(scratch.path.join("provisioned"), b"").expect("write the state entry");
    fs::create_dir(scratch.path.join("home")).expect("create the guest home");

    let state = scratch.path.to_str().unwrap().to_owned();
    let absent = harness([
        "e2e-state".to_owned(),
        "--state".to_owned(),
        state.clone(),
        "--desc".to_owned(),
        "probe".to_owned(),
        "--absent".to_owned(),
        "missing".to_owned(),
        "also/missing".to_owned(),
    ]);
    assert!(absent.status.success());
    assert_eq!(
        String::from_utf8(absent.stdout).expect("UTF-8"),
        "state: 2 entries absent\n"
    );

    let present = harness([
        "e2e-state".to_owned(),
        "--state".to_owned(),
        state.clone(),
        "--desc".to_owned(),
        "probe".to_owned(),
        "--absent".to_owned(),
        "provisioned".to_owned(),
    ]);
    assert_eq!(present.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&present.stderr).contains("must not exist"),
        "{}",
        String::from_utf8_lossy(&present.stderr)
    );

    let unobservable = harness([
        "e2e-state".to_owned(),
        "--state".to_owned(),
        state,
        "--desc".to_owned(),
        "probe".to_owned(),
        "--absent".to_owned(),
        "provisioned/child".to_owned(),
    ]);
    assert_eq!(unobservable.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&unobservable.stderr).contains("could not observe"),
        "{}",
        String::from_utf8_lossy(&unobservable.stderr)
    );
}

/// Both launcher-log readers decode one JSON value out of a line that continues
/// with log text, which is why they are not `jq` one-liners.
#[test]
fn the_binary_reads_a_launcher_log() {
    let scratch = Scratch::new("e2e-debug-json");
    let log = scratch.path.join("launch.out");
    fs::write(
        &log,
        "==> banner\n[debug] sandbox config JSON: {\"name\": \"probe\", \"image\": {\"Oci\": {\"reference\": \"repo:tag\"}}}\n\
         [debug] native image acquisition JSON: {\"kind\": \"native-image-acquire\", \"reference\": \"repo@sha256:aa\"}\n",
    )
    .expect("write the launcher log");
    let log = log.to_str().unwrap().to_owned();

    let config = harness([
        "e2e-debug-json".to_owned(),
        "--sandbox-config".to_owned(),
        log.clone(),
    ]);
    assert!(config.status.success());
    assert_eq!(
        String::from_utf8(config.stdout).expect("UTF-8"),
        "{\"image\":{\"Oci\":{\"reference\":\"repo:tag\"}},\"name\":\"probe\"}\n"
    );

    let dumps = harness([
        "e2e-debug-json".to_owned(),
        "--acquisition-dumps".to_owned(),
        log,
    ]);
    assert!(dumps.status.success());
    assert_eq!(
        String::from_utf8(dumps.stdout).expect("UTF-8"),
        "probe\trepo:tag\nnative-image-acquire\trepo@sha256:aa\n"
    );

    let missing = harness([
        "e2e-debug-json".to_owned(),
        "--sandbox-config".to_owned(),
        "/does/not/exist".to_owned(),
    ]);
    assert_eq!(missing.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&missing.stderr).contains("could not read"),
        "{}",
        String::from_utf8_lossy(&missing.stderr)
    );
}

/// A held FIFO writer keeps the write end open until it is killed: the guest
/// sees the payload and *no* EOF while the row holds it. This is the one
/// behaviour the module's own control cannot cover, because it needs a process to
/// kill.
#[test]
fn the_binary_holds_a_fifo_until_it_is_killed() {
    use std::io::Read;
    use std::sync::mpsc::{RecvTimeoutError, channel};
    use std::time::{Duration, Instant};

    let scratch = Scratch::new("e2e-stdin-writer");
    let fifo = scratch.path.join("stdin.fifo");
    let ready = scratch.path.join("stdin.ready");
    let created = Command::new("mkfifo").arg(&fifo).status();
    match created {
        Ok(status) if status.success() => {}
        _ => panic!("mkfifo is required to control the stdin writer"),
    }

    let mut child = Command::new(env!("CARGO_BIN_EXE_harness"))
        .args([
            "e2e-stdin-writer",
            "--fifo",
            fifo.to_str().expect("the scratch path is UTF-8"),
            "--mode",
            "hold",
            "--payload",
            "hello",
            "--ready",
            ready.to_str().expect("the scratch path is UTF-8"),
            "--timeout",
            "30",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("the stdin writer starts");

    // The receipt proves the process reached its open; the reader's own open then
    // completes the FIFO handshake.
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready.exists() {
        assert!(
            Instant::now() < deadline,
            "the writer never wrote its readiness receipt"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut reader = fs::File::open(&fifo).expect("open the FIFO for reading");
    let mut payload = [0_u8; 5];
    reader.read_exact(&mut payload).expect("read the payload");
    assert_eq!(&payload, b"hello");

    // `hold` means the guest has not seen EOF: the next read blocks. A thread owns
    // it so the wait can be bounded, and a signal from it means the stream closed.
    let (sender, receiver) = channel();
    let waiting = std::thread::spawn(move || {
        let mut rest = Vec::new();
        reader
            .read_to_end(&mut rest)
            .expect("read the end of the stream");
        let _ = sender.send(());
        rest
    });
    match receiver.recv_timeout(Duration::from_millis(300)) {
        Err(RecvTimeoutError::Timeout) => {}
        Ok(()) => panic!("a held writer closed the stream"),
        Err(error) => panic!("the control's reader failed: {error}"),
    }

    let pid = child.id() as i32;
    // SAFETY: `pid` is this test's own child and `SIGKILL` takes no payload.
    let killed = unsafe { libc::kill(pid, libc::SIGKILL) };
    assert_eq!(killed, 0, "the writer could not be killed");
    let status = child.wait().expect("reap the writer");
    assert!(!status.success());
    receiver
        .recv_timeout(Duration::from_secs(10))
        .expect("the killed writer released the stream");
    let rest = waiting.join().expect("the control's reader finished");
    assert!(
        rest.is_empty(),
        "the held writer delivered more bytes than its payload"
    );
}

/// A capture that is not the exact argv vector fails, and says where it diverged.
#[test]
fn the_binary_rejects_a_wrong_argv_capture() {
    let scratch = Scratch::new("e2e-direct-argv");
    let capture = scratch.path.join("stdout");
    fs::write(&capture, b"argv-count=13\ndirect-probe-398=ok\n").expect("write the capture");
    let output = harness([
        "e2e-direct-argv".to_owned(),
        "--capture".to_owned(),
        capture.to_str().unwrap().to_owned(),
    ]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("FAIL: direct argv bytes differ from the exact expected vector"),
        "{stderr}"
    );
}

// --- The notifier oracle (#501 slice 4) --------------------------------------

/// One `post`, the `remove` that replaces it and the `quit` that ends the run:
/// the transcript the launcher really writes, as bytes it really writes.
const NOTIFIER_COMMANDS: [&str; 3] = [
    concat!(
        r#"{"op":"post","v":1,"seq":1,"id":"agent-vm-3f9a12c4","thread":"agent-vm","#,
        r#""title":"t","subtitle":"s","body":"b","passive":false,"#,
        r#""click":{"session":"3f9a12c4","project":"/tmp/p","state_dir":"/tmp/s","terminal":"terminal"}}"#,
    ),
    r#"{"op":"remove","v":1,"seq":2,"id":"agent-vm-3f9a12c4"}"#,
    r#"{"op":"quit","v":1}"#,
];

/// Play one scenario: the file, the command stream on stdin, and the verdict.
fn play_notifier(scratch: &Scratch, scenario: &str, commands: &[&str]) -> (Output, Value) {
    let scenario_path = scratch.path.join("scenario.json");
    fs::write(&scenario_path, scenario).expect("write the scenario");
    let commands_path = scratch.path.join("commands.ndjson");
    fs::write(&commands_path, format!("{}\n", commands.join("\n")))
        .expect("write the command stream");
    let verdict_path = scratch.path.join("verdict.json");
    let stdin = fs::File::open(&commands_path).expect("open the command stream");
    let output = Command::new(env!("CARGO_BIN_EXE_harness"))
        .args(["fake-notifier", "--scenario"])
        .arg(&scenario_path)
        .arg("--verdict")
        .arg(&verdict_path)
        // The helper's own argv: the oracle must not care that a spawner adds it.
        .arg("serve")
        .stdin(Stdio::from(stdin))
        .output()
        .expect("the harness binary plays the notifier");
    let verdict = fs::read(&verdict_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or(Value::Null);
    (output, verdict)
}

/// The frames on stdout, each one checked to be a v1 event: the verdict must never
/// be there, because stdout is the protocol.
fn notifier_events(output: &Output) -> Vec<Value> {
    String::from_utf8(output.stdout.clone())
        .expect("the protocol is UTF-8")
        .lines()
        .map(|line| {
            let event: Value = serde_json::from_str(line)
                .unwrap_or_else(|error| panic!("stdout line {line:?} is not a frame: {error}"));
            assert_eq!(event["v"], json!(1), "frame {event} is not v1");
            assert!(event["type"].is_string(), "frame {event} carries no type");
            event
        })
        .collect()
}

/// The oracle is the only thing that catches a broken `[[bin]]` before a macOS
/// runner needs it: `_notify-click`'s child contract spawns this binary.
#[test]
fn the_binary_plays_the_fake_notifier() {
    // The honest run: four frames, the acknowledgements echoing the commands'
    // own `seq` and `id`, and a verdict that agrees with the scenario.
    let scratch = Scratch::new("fake-notifier-good");
    let (output, verdict) = play_notifier(
        &scratch,
        r#"{"expect": {"violations": 0, "ops": ["post", "remove", "quit"]}}"#,
        &NOTIFIER_COMMANDS,
    );
    assert!(
        output.status.success(),
        "the honest scenario failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let events = notifier_events(&output);
    let types: Vec<&str> = events
        .iter()
        .map(|event| event["type"].as_str().expect("a type"))
        .collect();
    assert_eq!(
        types,
        ["launched", "auth", "posted", "removed"],
        "{events:?}"
    );
    assert_eq!(events[0]["serving"], json!(true), "{events:?}");
    assert_eq!(events[1]["status"], json!("authorized"), "{events:?}");
    assert_eq!(events[2]["seq"], json!(1), "{events:?}");
    assert_eq!(events[2]["ok"], json!(true), "{events:?}");
    assert_eq!(events[2]["id"], json!("agent-vm-3f9a12c4"), "{events:?}");
    assert_eq!(events[3]["seq"], json!(2), "{events:?}");
    assert_eq!(verdict["ok"], json!(true), "{verdict}");
    assert_eq!(verdict["violations"], json!([]), "{verdict}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.starts_with("fake-notifier: OK (ended=quit violations=0 "),
        "{stderr}"
    );

    // A launcher that broke the wire: the scenario wants none, one arrives, and
    // the run fails with the reason recorded rather than a count nobody can read.
    let scratch = Scratch::new("fake-notifier-violation");
    let broken = [
        r#"{"op":"post","v":2,"seq":1,"id":"agent-vm-3f9a12c4","thread":"agent-vm","title":"t","subtitle":"s","body":"b","passive":false,"click":{"session":"3f9a12c4","project":"/tmp/p","state_dir":"/tmp/s","terminal":"terminal"}}"#,
        r#"{"op":"quit","v":1}"#,
    ];
    let (output, verdict) = play_notifier(&scratch, r#"{"expect": {"violations": 0}}"#, &broken);
    assert_eq!(output.status.code(), Some(1), "{verdict}");
    assert_eq!(verdict["ok"], json!(false), "{verdict}");
    assert_eq!(verdict["violations"][0]["seq"], json!(1), "{verdict}");
    assert_eq!(
        verdict["violations"][0]["reasons"],
        json!(["v is 2, not 1"]),
        "{verdict}"
    );
    assert_eq!(
        verdict["problems"],
        json!(["the scenario expected 0 refused command line(s), 1 arrived"]),
        "{verdict}"
    );
    // The refused command answered nothing: only the launch frames came out.
    assert_eq!(notifier_events(&output).len(), 2, "{verdict}");

    // The other direction: a control that was supposed to provoke a violation and
    // did not is a control that proves nothing, and fails here.
    let scratch = Scratch::new("fake-notifier-nothing-happened");
    let (output, verdict) = play_notifier(
        &scratch,
        r#"{"expect": {"violations": 1}}"#,
        &NOTIFIER_COMMANDS,
    );
    assert_eq!(output.status.code(), Some(1), "{verdict}");
    assert_eq!(
        verdict["problems"],
        json!(["the scenario expected 1 refused command line(s), 0 arrived"]),
        "{verdict}"
    );

    // A typo in a scenario is an error, not a control that silently does nothing.
    let scratch = Scratch::new("fake-notifier-typo");
    let (output, _) = play_notifier(&scratch, r#"{"auth": {"grantd": true}}"#, &[]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("auth has no key 'grantd'"), "{stderr}");
}
