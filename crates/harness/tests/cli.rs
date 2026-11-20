//! The binary the shell calls actually builds and runs. A lib-only test would
//! pass while `[[bin]]` was misconfigured, which is the failure this catches.

use std::{path::Path, process::Command};

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
