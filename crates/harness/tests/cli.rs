//! The binary the shell calls actually builds and runs. A lib-only test would
//! pass while `[[bin]]` was misconfigured, which is the failure this catches.

use serde_json::json;
use std::{
    env, fs,
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
