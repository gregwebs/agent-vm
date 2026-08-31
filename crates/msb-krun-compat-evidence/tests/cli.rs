use std::{fs, path::Path, process::Command};
use tempfile::tempdir;

fn run(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_msb-krun-compat-evidence"))
        .args(arguments)
        .output()
        .unwrap()
}

fn write(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
}

#[test]
fn discovery_accepts_empty_csv_and_rejects_invalid_indexes_without_output() {
    let dir = tempdir().unwrap();
    let log = dir.path().join("guest.log");
    let output = dir.path().join("discovery.json");
    write(&log, "malformed\nCMDLINE_BYTES| 202 \n");

    let success = run(&[
        "discovery",
        "--guest-log",
        log.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--expected-mounts",
        "0",
        "--selected-indexes=",
    ]);
    assert!(success.status.success(), "{:?}", success);
    assert!(
        fs::read_to_string(&output)
            .unwrap()
            .contains("\"cmdline_bytes\": 202")
    );

    let invalid_output = dir.path().join("invalid.json");
    let failure = run(&[
        "discovery",
        "--guest-log",
        log.to_str().unwrap(),
        "--output",
        invalid_output.to_str().unwrap(),
        "--expected-mounts",
        "0",
        "--selected-indexes=not-a-number",
    ]);
    assert!(!failure.status.success());
    assert!(String::from_utf8_lossy(&failure.stderr).contains("invalid selected mount index"));
    assert!(!invalid_output.exists());
}

#[test]
fn observations_accepts_a_leading_hyphen_failure_reason() {
    let dir = tempdir().unwrap();
    let output = dir.path().join("observations.json");
    let result = run(&[
        "observations",
        "--output",
        output.to_str().unwrap(),
        "--host-os",
        "Linux",
        "--host-arch",
        "x86_64",
        "--last-good",
        "4",
        "--first-failure",
        "8",
        "--repeats",
        "1",
        "--failure-reason=-synthetic",
    ]);
    assert!(result.status.success(), "{:?}", result);
    assert!(
        fs::read_to_string(&output)
            .unwrap()
            .contains("\"failure_reason\": \"-synthetic\"")
    );
}

#[test]
fn create_new_cli_failure_retains_existing_evidence() {
    let dir = tempdir().unwrap();
    let log = dir.path().join("guest.log");
    let output = dir.path().join("retained.json");
    write(&log, "CMDLINE_BYTES|1\n");
    write(&output, "retained\n");

    let result = run(&[
        "discovery",
        "--guest-log",
        log.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--expected-mounts",
        "0",
        "--selected-indexes=",
    ]);
    assert!(!result.status.success());
    assert_eq!(fs::read_to_string(&output).unwrap(), "retained\n");
}
