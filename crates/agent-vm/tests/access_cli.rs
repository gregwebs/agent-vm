//! `agent-vm access` as a process: the verb exists, needs nothing, and creates
//! nothing.
//!
//! `access` is dispatched before credential preflight, the MSB prologue and the
//! runtime, so it has to work with a broken user config, no patched `msb` and no
//! image. These cases hold that: they assert the process, not the code path.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn agent_vm() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-vm"))
}

/// A `$HOME` with a config file that cannot be parsed, and a `MSB_PATH` that does
/// not exist: nothing this command is allowed to need.
fn broken_home(root: &Path) -> PathBuf {
    let home = root.join("home");
    let config = home.join(".config/agent-vm/config.toml");
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(config.join("config.toml"), "this is not = valid [ toml\n").unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(
        config.parent().unwrap(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o700)).unwrap();
    home
}

fn run(home: &Path, state: &Path, project: &Path, args: &[&str]) -> Output {
    Command::new(agent_vm())
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("AGENT_VM_STATE_DIR", state)
        .env("MSB_PATH", home.join("no-such-msb"))
        .current_dir(project)
        .args(args)
        .output()
        .expect("running agent-vm")
}

/// A broken config and no runtime do not stop the verb that reports refusals.
#[test]
fn access_works_with_a_broken_config_and_no_runtime() {
    let root = tempfile::tempdir().unwrap();
    let home = broken_home(root.path());
    let state = root.path().join("state");
    let project = root.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let out = run(&home, &state, &project, &["access"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout: {stdout}\nstderr: {stderr}");
    assert_eq!(stdout, "No refusals in the last 24 hours.\n");
    assert!(!stderr.contains("Error"), "{stderr}");
    // Reading must not create the store that would answer.
    assert!(
        !state.join("ab12cd34ef56.sessions").exists() && !state.exists(),
        "a read creates no state root: {}",
        state.display()
    );
}

/// `access` is a reserved built-in: it appears in the help and cannot be
/// shadowed by a config tool.
#[test]
fn access_is_a_builtin_verb() {
    let root = tempfile::tempdir().unwrap();
    let home = broken_home(root.path());
    let project = root.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let out = run(&home, &root.path().join("state"), &project, &["--help"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("access"), "the verb is listed: {stdout}");
}

/// An unknown `--session` is a usage answer, not a crash: exit 1 and one line.
#[test]
fn an_unknown_session_exits_1() {
    let root = tempfile::tempdir().unwrap();
    let home = broken_home(root.path());
    let state = root.path().join("state");
    let project = root.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let out = run(
        &home,
        &state,
        &project,
        &["access", "--session", "deadbeef"],
    );
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr).trim(),
        "no session deadbeef in this project's running sessions or refusal log"
    );
}
