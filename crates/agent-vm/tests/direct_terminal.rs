//! Real-terminal usage tests for the compiled CLI (issue #400).
//!
//! The direct terminal policy is decided from the process's own descriptors, so
//! the only honest way to test `-t`/`-T` acceptance is to give the real binary a
//! real terminal and watch what it does with it. These cases stop at the runtime
//! boundary (the isolated `MSB_PATH` points at nothing), which is deliberate:
//! they prove the *usage* decision a PTY produces — accepted or refused — and
//! nothing about guest behavior. Guest mode is established by the native rows and
//! by `direct_terminal::tests`' fd-adapter child, which measures the production
//! `HostTerminals::detect()` in a process whose descriptors are assigned.
//!
//! Nothing here touches the operator's environment: every case runs with a
//! private `HOME` and `AGENT_VM_STATE_DIR` and a runtime path that cannot exist.

#![cfg(unix)]

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

#[path = "support/pty.rs"]
mod pty;

use pty::{Pty, PtyOutput, PtyStdio};

/// A direct launch with a valid program but no usable runtime: the usage gate
/// has accepted it and the launcher gives up at its own runtime boundary.
const RUNTIME_FAILURE: i32 = 125;
/// A pre-boot usage error.
const USAGE_ERROR: i32 = 2;

const FORCED_PTY_REFUSAL: &str = "--tty (-t) requires terminal stdin";

struct Case {
    home: tempfile::TempDir,
    state: tempfile::TempDir,
    project: tempfile::TempDir,
}

impl Case {
    fn new() -> Self {
        Self {
            home: tempfile::tempdir().expect("a private HOME"),
            state: tempfile::tempdir().expect("a private state root"),
            project: tempfile::tempdir().expect("a private project"),
        }
    }

    /// A command that cannot reach a guest: `MSB_PATH` names a path that does not
    /// exist, so the launcher's own runtime check fails after parsing.
    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agent-vm"));
        command
            .current_dir(self.project.path())
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", self.home.path())
            .env("AGENT_VM_STATE_DIR", self.state.path().join("state"))
            .env("MSB_PATH", self.home.path().join("no-such-runtime"))
            .env("TERM", "xterm-256color");
        command
    }

    fn stdout_file(&self) -> PathBuf {
        self.project.path().join("stdout.txt")
    }
}

/// Run a case that needs no terminal: stdin is `/dev/null`.
fn run_without_terminal(case: &Case, args: &[&str]) -> std::process::Output {
    let mut command = case.command();
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.output().expect("run agent-vm")
}

fn stderr_of(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout_of(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The terminal controls are accepted when stdin really is a terminal, for every
/// spelling and both direct forms, and the launch then reaches its runtime
/// boundary instead of failing as a usage error.
#[test]
fn terminal_controls_are_accepted_with_a_terminal_stdin() {
    for (args, label) in [
        (vec!["-t", "run", "true"], "-t run"),
        (vec!["--tty", "run", "true"], "--tty run"),
        (vec!["-t", "--", "true"], "-t --"),
        (vec!["--tty", "--", "true"], "--tty --"),
        (vec!["-T", "run", "true"], "-T run"),
        (vec!["--no-tty", "run", "true"], "--no-tty run"),
        (vec!["-T", "--", "true"], "-T --"),
        (vec!["--no-tty", "--", "true"], "--no-tty --"),
    ] {
        let case = Case::new();
        let mut command = case.command();
        command.args(&args);
        let mut pty = Pty::spawn(&mut command, b"").expect("allocate a terminal");
        let mut output = Vec::new();
        let status = pty
            .wait_for_exit(&mut output, Duration::from_secs(120))
            .unwrap_or_else(|error| {
                panic!(
                    "{label}: {error}; terminal output: {:?}",
                    String::from_utf8_lossy(&output)
                )
            });
        assert_eq!(
            status.code(),
            Some(RUNTIME_FAILURE),
            "{label}: expected the runtime boundary, terminal output: {:?}",
            String::from_utf8_lossy(&output)
        );
        assert!(
            !String::from_utf8_lossy(&output).contains(FORCED_PTY_REFUSAL),
            "{label}: a terminal stdin must not be refused"
        );
    }
}

/// Forced streaming selects streaming even from a terminal, with stdout
/// redirected: the usage gate accepts it and the redirected file never receives a
/// launcher notice (nothing about a terminal is written to guest stdout).
#[test]
fn forced_streaming_is_accepted_from_a_terminal_with_redirected_stdout() {
    for args in [vec!["-T", "run", "true"], vec!["--no-tty", "--", "true"]] {
        let case = Case::new();
        let redirected = case.stdout_file();
        let mut command = case.command();
        command.args(&args);
        let mut pty = Pty::spawn_with_stdio(
            &mut command,
            b"",
            PtyStdio {
                stdout: PtyOutput::File(redirected.clone()),
                stderr: PtyOutput::Terminal,
            },
        )
        .expect("allocate a terminal");
        let mut output = Vec::new();
        let status = pty
            .wait_for_exit(&mut output, Duration::from_secs(120))
            .expect("the launch reached its runtime boundary");
        assert_eq!(status.code(), Some(RUNTIME_FAILURE), "{args:?}");
        let written = std::fs::read(&redirected).expect("the redirected stdout");
        assert!(
            written.is_empty(),
            "{args:?}: the launcher wrote {:?} to guest stdout",
            String::from_utf8_lossy(&written)
        );
    }
}

/// Forced PTY with stdin that is not a terminal is refused before boot: status 2,
/// the actionable diagnostic, and no guest-looking output.
#[test]
fn forced_pty_without_a_terminal_stdin_is_refused() {
    for args in [vec!["-t", "run", "true"], vec!["--tty", "--", "true"]] {
        // `/dev/null` and a regular file are both "not a terminal".
        let case = Case::new();
        let output = run_without_terminal(&case, &args);
        assert_eq!(output.status.code(), Some(USAGE_ERROR), "{args:?}");
        let stderr = stderr_of(&output);
        assert!(stderr.contains(FORCED_PTY_REFUSAL), "{args:?}: {stderr}");
        assert!(stderr.contains("--no-tty (-T)"), "{args:?}: {stderr}");
        assert!(stdout_of(&output).is_empty(), "{args:?}");

        let case = Case::new();
        let input = case.project.path().join("stdin.txt");
        std::fs::write(&input, b"unread").expect("write the input file");
        let mut command = case.command();
        command
            .args(&args)
            .stdin(Stdio::from(
                std::fs::File::open(&input).expect("open the input file"),
            ))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = command.output().expect("run agent-vm");
        assert_eq!(output.status.code(), Some(USAGE_ERROR), "{args:?} file");
        assert!(
            stderr_of(&output).contains(FORCED_PTY_REFUSAL),
            "{args:?} file"
        );
    }
}

/// Conflicting terminal flags are a usage error before boot, in every spelling,
/// including a combined short cluster.
#[test]
fn conflicting_terminal_flags_are_refused() {
    for args in [
        vec!["-t", "-T", "run", "true"],
        vec!["-tT", "run", "true"],
        vec!["--tty", "--no-tty", "--", "true"],
    ] {
        let case = Case::new();
        let output = run_without_terminal(&case, &args);
        assert_eq!(output.status.code(), Some(USAGE_ERROR), "{args:?}");
        assert!(
            stderr_of(&output).contains("cannot be used with"),
            "{args:?}: {}",
            stderr_of(&output)
        );
    }
}

/// The same tokens after the command boundary are guest argv, not launch
/// options: nothing about them can be a launcher conflict, so the launch reaches
/// its runtime boundary.
#[test]
fn suffix_terminal_tokens_stay_guest_argv() {
    for args in [
        // A program literally named like the flag.
        vec!["-T", "run", "--tty"],
        vec!["-T", "run", "--no-tty"],
        // Both flags after the program: mutually exclusive if they were ours.
        vec!["-T", "run", "printf", "--tty", "-T"],
        vec!["-T", "--", "printf", "-t", "--no-tty"],
        // The separator after `run` is the program.
        vec!["-T", "run", "--", "-t"],
    ] {
        let case = Case::new();
        let output = run_without_terminal(&case, &args);
        let stderr = stderr_of(&output);
        assert_eq!(
            output.status.code(),
            Some(RUNTIME_FAILURE),
            "{args:?}: {stderr}"
        );
        assert!(
            !stderr.contains("cannot be used with"),
            "{args:?}: a suffix token was treated as a launch option: {stderr}"
        );
        assert!(
            !stderr.contains(FORCED_PTY_REFUSAL),
            "{args:?}: a suffix token selected a terminal mode: {stderr}"
        );
    }
}

/// A catalog tool and `shell` refuse the prefix controls instead of silently
/// changing their own behavior, before any runtime work.
#[test]
fn catalog_and_shell_launches_refuse_the_terminal_controls() {
    for args in [vec!["-t", "shell", "true"], vec!["--no-tty", "shell"]] {
        let case = Case::new();
        let output = run_without_terminal(&case, &args);
        assert_eq!(output.status.code(), Some(USAGE_ERROR), "{args:?}");
        assert!(
            stderr_of(&output).contains("applies only to direct commands"),
            "{args:?}: {}",
            stderr_of(&output)
        );
    }
}

/// A terminal-mode launch that reaches the runtime boundary did not restore a
/// terminal it never made raw: the attributes are unchanged after exit.
#[test]
fn the_driver_terminal_is_untouched_when_no_session_starts() {
    let case = Case::new();
    let mut command = case.command();
    command.args(["-t", "run", "true"]);
    let mut pty = Pty::spawn(&mut command, b"").expect("allocate a terminal");
    let mut output = Vec::new();
    let status = pty
        .wait_for_exit(&mut output, Duration::from_secs(120))
        .expect("the launch reached its runtime boundary");
    assert_eq!(status.code(), Some(RUNTIME_FAILURE));
    assert_eq!(
        pty.terminal_flags(),
        pty.baseline_flags(),
        "no session started, so nothing may have changed the terminal"
    );
}
