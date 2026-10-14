#[path = "support/fake_msb.rs"]
mod fake_msb;
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

fn place_binary(path: &Path) {
    match fs::hard_link(env!("CARGO_BIN_EXE_agent-vm"), path) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
            fs::copy(env!("CARGO_BIN_EXE_agent-vm"), path).unwrap();
        }
        Err(e) => panic!("hard_link: {e}"),
    }
}
fn run(binary: &Path, root: &Path) -> Output {
    fs::create_dir_all(root.join("home")).unwrap();
    fs::create_dir_all(root.join("state")).unwrap();
    Command::new(binary)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("HOME", root.join("home"))
        .env("AGENT_VM_STATE_DIR", root.join("state"))
        .current_dir(root)
        .args(["msb", "--version"])
        .output()
        .unwrap()
}
#[cfg(not(feature = "embedded-runtime"))]
#[test]
fn lone_copied_binary_without_payload_explains_bundle_and_single_binary() {
    let temp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let binary = temp.path().join("agent-vm");
    place_binary(&binary);
    let out = run(&binary, temp.path());
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("agent-vm could not find its bundled `msb` binary."),
        "{err}"
    );
    assert!(err.contains("Copied `agent-vm` by itself?"));
    assert!(err.contains(&format!("Searched for `msb` in: {}", temp.path().display())));
    assert_eq!(err.contains("--single-binary"), cfg!(target_os = "macos"));
}
fn symlink_bundle(with_link_msb: bool) {
    let temp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let root = temp.path();
    let bundle = root.join("bundle/bin");
    let links = root.join("links");
    fs::create_dir_all(&bundle).unwrap();
    fs::create_dir(&links).unwrap();
    place_binary(&bundle.join("agent-vm"));
    fake_msb::write(&bundle);
    if with_link_msb {
        fake_msb::write_executable(&links.join("msb"), "#!/bin/sh\necho 'msb 9.9.9'\n");
    }
    std::os::unix::fs::symlink(bundle.join("agent-vm"), links.join("agent-vm")).unwrap();
    let out = run(&links.join("agent-vm"), root);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        fake_msb::VERSION_LINE
    );
    assert!(!root.join("home/.cache/agent-vm").exists());
}
#[test]
fn symlinked_binary_uses_msb_beside_link_target() {
    symlink_bundle(false);
}
#[test]
fn link_target_bundle_wins_over_msb_beside_link() {
    symlink_bundle(true);
}
