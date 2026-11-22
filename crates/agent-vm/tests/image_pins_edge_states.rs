//! Two AC7/R8 edge states the branch's suite reaches only at a seam or not at
//! all, driven through the real binary:
//!
//! 1. a project directory that cannot be captured (`getcwd` fails), and
//! 2. a store path whose parent is a regular file (`ENOTDIR`).
//!
//! `image_pin::presentation`'s unit rows prove the ordering at the seam (an
//! uncapturable project returns before the loader is called). Row 1 drives the
//! state a user actually reaches, with a *damaged* store in place so any store
//! read would change the row and leak the sentinel. Row 2 covers a location
//! failure the current suite only exercises through `$HOME` itself: a valid
//! `$HOME` whose `.config` cannot hold the store must be an error, never a
//! fabricated empty listing or a zero-count row.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, Output};

const ACCESS: &str = "image pin authority at $HOME/.config/agent-vm/image-pins.json \
                      could not be accessed or saved";

/// Run `args` in a directory that is removed before `exec`, so `getcwd` fails.
fn in_deleted_cwd(bin: &str, args: &str, home: &Path, state: &Path, root: &Path) -> Output {
    in_deleted_cwd_with(bin, args, home, state, root, &[])
}

/// [`in_deleted_cwd`] with extra environment for the child.
fn in_deleted_cwd_with(
    bin: &str,
    args: &str,
    home: &Path,
    state: &Path,
    root: &Path,
    extra: &[(&str, &str)],
) -> Output {
    let script = format!(
        "d=$(mktemp -d {root}/gone.XXXXXX) || exit 98; cd \"$d\" || exit 98; \
         rmdir \"$d\" || exit 98; exec {bin} {args}",
        root = root.display(),
        bin = bin,
        args = args,
    );
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg(script)
        .env_clear()
        .env("HOME", home)
        .env("AGENT_VM_STATE_DIR", state)
        .env("PATH", "/usr/bin:/bin");
    for (key, value) in extra {
        command.env(key, value);
    }
    command.output().expect("spawn the shell")
}

fn run(bin: &str, args: &[&str], cwd: &Path, home: &Path, state: &Path) -> Output {
    Command::new(bin)
        .args(args)
        .current_dir(cwd)
        .env_clear()
        .env("HOME", home)
        .env("AGENT_VM_STATE_DIR", state)
        .env("PATH", "/usr/bin:/bin")
        .output()
        .expect("run agent-vm")
}

fn active_rows(stdout: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(stdout)
        .lines()
        .filter(|line| line.starts_with("active images: "))
        .map(str::to_owned)
        .collect()
}

fn fixture(prefix: &str) -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let root = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in("/tmp")
        .unwrap();
    let home = root.path().join("home");
    let state = root.path().join("state");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&state).unwrap();
    (root, home, state)
}

#[test]
fn a_deleted_working_directory_is_unknown_and_reads_no_store() {
    let (root, home, state) = fixture("avpins-unknown-");
    let config = home.join(".config/agent-vm");
    fs::create_dir_all(&config).unwrap();
    // Deliberately damaged, with a sentinel: a store read would turn the row
    // into `error:` and could quote bytes.
    let damaged: &[u8] = b"{\"version\":2,\"pins\":[{\"reference\":\"SENTINEL/secret:tag\"";
    fs::write(config.join("image-pins.json"), damaged).unwrap();
    fs::write(config.join("image-pins.lock"), b"").unwrap();
    fs::set_permissions(
        config.join("image-pins.lock"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let bin = env!("CARGO_BIN_EXE_agent-vm");

    let doctor = in_deleted_cwd(bin, "doctor", &home, &state, root.path());
    let stdout = String::from_utf8_lossy(&doctor.stdout);
    assert_eq!(
        active_rows(&doctor.stdout),
        ["active images: unknown (the project directory could not be captured)"],
        "stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains("SENTINEL"),
        "an uncapturable project must not read the authority:\n{stdout}"
    );

    let pins = in_deleted_cwd(bin, "image pins", &home, &state, root.path());
    assert_eq!(pins.status.code(), Some(1));
    assert_eq!(pins.stdout, b"", "a capture failure prints no listing");
    let stderr = String::from_utf8_lossy(&pins.stderr);
    assert!(
        stderr.contains("capturing the invoking project for image pins"),
        "stderr: {stderr}"
    );
    assert!(
        !stderr.contains("SENTINEL"),
        "no record bytes in the diagnostic: {stderr}"
    );
    assert_eq!(
        fs::read(config.join("image-pins.json")).unwrap(),
        damaged,
        "neither verb repairs or rewrites the store"
    );
}

/// ADR-0073 D2 wanted `image show` to still print an explicit tag when the
/// project capture fails. It does not, and never did: a capture failure makes
/// `main`'s config load fail, and `image show` treats a carried configuration
/// failure as fatal, because the images it would inspect are the substitutes
/// `parse_from` invented. This row pins the real contract, so the plan's claim
/// cannot be re-invented silently.
#[test]
fn a_deleted_working_directory_keeps_image_show_fatal_and_printless() {
    let (root, home, state) = fixture("avm-show-deleted-cwd-");
    let out = in_deleted_cwd_with(
        env!("CARGO_BIN_EXE_agent-vm"),
        "image show",
        &home,
        &state,
        root.path(),
        &[("AGENT_VM_IMAGE_TAG", "127.0.0.1:1/env:dev")],
    );
    assert_eq!(out.status.code(), Some(1), "a capture failure is an error");
    assert!(
        out.stdout.is_empty(),
        "a failed inspection prints no selection: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("reading current directory"),
        "the diagnostic names the capture: {stderr}"
    );
    assert!(
        !stderr.contains("127.0.0.1:1/env:dev"),
        "the refused tag is not echoed: {stderr}"
    );
}

#[test]
fn a_store_path_under_a_regular_file_is_an_error_not_an_empty_listing() {
    let (root, home, state) = fixture("avpins-enotdir-");
    // A valid `$HOME` whose `.config` cannot hold a directory.
    let dot_config = home.join(".config");
    fs::write(&dot_config, b"not a directory").unwrap();
    let project = root.path().join("project");
    fs::create_dir_all(&project).unwrap();
    let bin = env!("CARGO_BIN_EXE_agent-vm");

    let pins = run(bin, &["image", "pins"], &project, &home, &state);
    assert_eq!(
        pins.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&pins.stderr)
    );
    assert_eq!(
        pins.stdout, b"",
        "an unlocatable store must not print a header-only listing"
    );
    assert_eq!(
        String::from_utf8_lossy(&pins.stderr),
        format!("Error: {ACCESS}\n")
    );

    let doctor = run(bin, &["doctor"], &project, &home, &state);
    assert_eq!(
        active_rows(&doctor.stdout),
        [format!("active images: error: {ACCESS}")],
        "the error row has no path suffix: {}",
        String::from_utf8_lossy(&doctor.stdout)
    );
    assert_eq!(fs::read(&dot_config).unwrap(), b"not a directory");
}
