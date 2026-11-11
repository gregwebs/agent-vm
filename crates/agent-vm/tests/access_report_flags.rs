//! `agent-vm access`'s report flags and its verbs are exclusive, as a process.
//!
//! `access --all allow <ID>` and `access --session <SID> allow <ID>` used to
//! parse: `Args` carried the report's flags beside the subcommand, so the flags
//! were accepted, `--session` was validated, and `run_allow` then returned
//! without reading either. A request the tool silently did not perform, on the
//! verb that changes egress authority, is the one failure mode this file pins.
//! The unit test in `cli::tests` asserts clap's own error kind; this one asserts
//! what a user sees: exit status 2, the flag named, and nothing else run.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn agent_vm() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-vm"))
}

/// A `$HOME` and project with nothing in them: these cases must fail before any
/// of it is read, and must change none of it.
fn layout(root: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let home = root.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let state = root.join("state");
    let project = root.join("project");
    std::fs::create_dir_all(&project).unwrap();
    (home, state, project)
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

#[test]
fn a_report_flag_beside_a_verb_is_refused_by_the_parser() {
    let root = tempfile::tempdir().unwrap();
    let (home, state, project) = layout(root.path());
    const ID: &str = "0e7e41fb";
    const DESTINATION: &str = "tcp://[203.0.113.10/32]:443";
    let cases: &[(&[&str], &str)] = &[
        (
            &["access", "--all", "allow", ID],
            "the subcommand 'allow' cannot be used with '--all'",
        ),
        (
            &["access", "--session", "aaaaaaaa", "allow", ID],
            "the subcommand 'allow' cannot be used with '--session <ID>'",
        ),
        (
            &["access", "--all", "revoke", DESTINATION],
            "the subcommand 'revoke' cannot be used with '--all'",
        ),
        (
            &["access", "--session", "aaaaaaaa", "allowances"],
            "the subcommand 'allowances' cannot be used with '--session <ID>'",
        ),
    ];
    for (args, expected) in cases {
        let out = run(&home, &state, &project, args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(stderr.contains(expected), "{args:?}: {stderr}");
        assert!(
            !state.exists(),
            "{args:?} ran a command: the state root was created"
        );
    }
}

/// The shapes that must keep working: the report's own flags, and a verb with no
/// report flag beside it. Without this control the refusals above could be a
/// parser that refuses everything.
#[test]
fn the_report_flags_and_the_verbs_still_parse_on_their_own() {
    let root = tempfile::tempdir().unwrap();
    let (home, state, project) = layout(root.path());
    for args in [
        &["access", "--all"][..],
        &["access", "--session", "deadbeef"][..],
        &["access", "allowances"][..],
        &["access", "allowances", "--session", "deadbeef"][..],
        &[
            "access",
            "revoke",
            "tcp://[203.0.113.10/32]:443",
            "--project",
        ][..],
    ] {
        let out = run(&home, &state, &project, args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_ne!(
            out.status.code(),
            Some(2),
            "{args:?} was refused by the parser: {stderr}"
        );
    }
}
