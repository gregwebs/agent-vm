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
