//! The detach shim (ADR-0072, #698).
//!
//! The #400 native driver refuses to start while it has a controlling terminal,
//! because a driver that inherited the operator's terminal could look correct
//! while its own PTY did nothing. That precondition is easy to state and easy to
//! violate: `bash script/test/e2e.sh custom-image` from an interactive shell
//! inherits one. So this shim detaches the driver instead of requiring an
//! undisclosed invocation environment, and both the callers and the boot-free
//! control run *this* shim, so the control proves the production path.
//!
//! The contract, unchanged from the Python it replaces:
//!
//! * the child is a session leader with no controlling terminal (`setsid`), and
//!   its stdin is `/dev/null`, so no case can read the caller's keystrokes;
//! * with no program it prints `detached-run: expected a program to run` to
//!   stderr and exits 2;
//! * otherwise it exits with the child's own status.

use std::ffi::OsString;

use clap::Args;

use crate::{Outcome, pty};

/// The message and status of a run with nothing to run. Both are part of the
/// shim's contract: a caller distinguishes misuse from a failing child.
pub const NO_PROGRAM: &str = "detached-run: expected a program to run";

#[derive(Debug, Args)]
pub struct DetachedRunArgs {
    /// Run the boot-free detach controls instead of a program.
    #[arg(long)]
    self_test: bool,

    /// The program and its arguments; everything after the subcommand.
    #[arg(
        value_name = "PROGRAM",
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    program: Vec<OsString>,
}

pub fn run(args: DetachedRunArgs) -> Result<Outcome, String> {
    if args.self_test {
        self_test()?;
        return Ok(Outcome::Report(
            "detached-run: OK (a real controlling terminal is removed; the child is a session \
             leader with /dev/null stdin)"
                .to_owned(),
        ));
    }
    if args.program.is_empty() {
        return Err(NO_PROGRAM.to_owned());
    }
    let mut command = std::process::Command::new(&args.program[0]);
    command.args(&args.program[1..]);
    let mut child = pty::spawn_detached(&mut command).map_err(|error| {
        format!(
            "detached-run: cannot run {}: {error}",
            args.program[0].to_string_lossy()
        )
    })?;
    let status = child
        .wait()
        .map_err(|error| format!("detached-run: cannot wait for the program: {error}"))?;
    Ok(Outcome::Exit(pty::propagate_exit_code(status)))
}

/// A status of its own for the one failure the shim reports about itself.
pub fn failure_status(error: &str) -> Option<i32> {
    (error == NO_PROGRAM).then_some(2)
}

/// How long any one wait in the controls below may take. A control that waits
/// without a deadline is a control that can hang a whole run.
const CONTROL_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

// --- Boot-free controls -----------------------------------------------------

/// The controls behind `--self-test`, all of them real processes and none of
/// them a mock: a session with no terminal, a session *with* one, and a child
/// that reports which of the two it saw.
fn self_test() -> Result<(), String> {
    no_program_is_misuse()?;
    the_child_is_detached()?;
    remove_of_a_real_controlling_terminal()?;
    Ok(())
}

fn no_program_is_misuse() -> Result<(), String> {
    let outcome = run(DetachedRunArgs {
        self_test: false,
        program: Vec::new(),
    });
    match outcome {
        Err(error) if error == NO_PROGRAM && failure_status(&error) == Some(2) => Ok(()),
        Err(error) => Err(format!(
            "an empty program reported {error:?} instead of {NO_PROGRAM:?} with status 2"
        )),
        Ok(_) => Err("an empty program ran instead of being refused".to_owned()),
    }
}

/// The shim's own `harness` path: the controls run the shipped binary, not a
/// library copy, because the shim's interface is a process's status.
fn harness() -> Result<std::path::PathBuf, String> {
    std::env::current_exe().map_err(|error| format!("cannot find this binary's own path: {error}"))
}

fn the_shim() -> Result<OsString, String> {
    Ok(harness()?.into_os_string())
}

/// `/dev/tty` is unreachable, stdin is at its end of file, and a terminal on
/// fd 0 is absent: the three properties a detached child must have.
/// The `/dev/tty` test runs in a subshell: a redirection error there fails the
/// subshell rather than the shell, which is where a Python `os.open` would have
/// raised.
const DETACHED_PROBE: &str = "( : </dev/tty ) 2>/dev/null && exit 1; \
                              test -t 0 && exit 2; \
                              read -r _line && exit 3; \
                              exit 0";

fn the_child_is_detached() -> Result<(), String> {
    let mut command = std::process::Command::new(the_shim()?);
    command.args(["detached-run", "--", "/bin/sh", "-c", DETACHED_PROBE]);
    let child = pty::spawn_detached(&mut command)
        .map_err(|error| format!("cannot spawn the detaching shim: {error}"))?;
    let mut child = pty::OwnedChild::new(child);
    let status = child
        .finish(CONTROL_DEADLINE)
        .map_err(|error| format!("cannot wait for the detaching shim: {error}"))?;
    if status.code() != Some(0) {
        return Err(format!(
            "the detached child reported {status}: its /dev/tty, its stdin or its terminal is \
             not what the shim promises"
        ));
    }
    Ok(())
}

/// The control that matters: a *real* controlling terminal, which this shim has
/// to remove. It proves the environment had one rather than observing that the
/// test process happened to have none.
fn remove_of_a_real_controlling_terminal() -> Result<(), String> {
    let script = format!(
        "if ( : </dev/tty ) 2>/dev/null; then echo attached=yes; else echo attached=no; fi\n\
         \"$1\" detached-run -- /bin/sh -c '{DETACHED_PROBE}'\n\
         echo detached=$?\n"
    );
    let terminal = pty::Pty::with_size(pty::WindowSize::new(24, 80))
        .map_err(|error| format!("cannot open a pseudoterminal: {error}"))?;
    let mut command = std::process::Command::new("/bin/sh");
    command.args(["-c", &script, "sh"]).arg(the_shim()?);
    let child = pty::spawn_on_controlling_terminal(&mut command, terminal.slave())
        .map_err(|error| format!("cannot spawn the controlling-terminal session: {error}"))?;
    // The session leader also leads its own process group, so a control that gives
    // up stops the shim inside it too.
    let mut child = pty::OwnedChild::leading_group(child);

    // Drain the terminal while the child runs: a control that never reads its
    // own child's terminal can block that child on a full buffer.
    let mut seen = Vec::new();
    let mut buffer = [0u8; 4096];
    while let Some(read) = pty::read_chunk(terminal.master(), &mut buffer, CONTROL_DEADLINE)
        .map_err(|error| format!("cannot read the controlling terminal: {error}"))?
    {
        if read == 0 {
            break;
        }
        seen.extend_from_slice(&buffer[..read]);
    }
    let status = child
        .finish(CONTROL_DEADLINE)
        .map_err(|error| format!("cannot wait for the controlling-terminal session: {error}"))?;
    let text = String::from_utf8_lossy(&seen);
    if !text.contains("attached=yes") {
        return Err(format!(
            "the control ran in {text:?}, where /dev/tty was unreachable, so it proves nothing"
        ));
    }
    if !text.contains("detached=0") {
        return Err(format!(
            "the shim's child was not detached: {text:?} (session status {status})"
        ));
    }
    Ok(())
}
