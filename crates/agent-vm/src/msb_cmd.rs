//! `agent-vm msb <args...>` — forward verbatim to the bundled `msb`
//! (the official Microsandbox build this agent-vm vendors), with
//! MSB_PATH / MSB_HOME already pinned in the process env by main()'s
//! prologue (point_at_msb / point_at_msb_home).
//!
//! Pure passthrough: we do not parse or reformat msb's output, and we do
//! not re-check its version identity — point_at_msb() already did
//! both before dispatch. The child inherits our full environment (so
//! MSB_HOME points msb at agent-vm's private sandbox registry) and our
//! stdio. The child's exit status becomes agent-vm's exit status; a child
//! killed by a signal maps to 128+signo (the shell convention) so it can
//! never be mistaken for success.

use std::ffi::OsString;
use std::path::Path;
use std::process::{Command, ExitStatus};

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

#[derive(ClapArgs)]
// disable_help_flag: hand `--help`/`-h` through to msb instead of letting
// clap intercept them. Without this, `agent-vm msb --help` prints clap's
// help and never reaches msb (see module design notes / issue AC#2).
#[command(disable_help_flag = true)]
pub struct Args {
    /// Arguments forwarded verbatim to the bundled `msb`
    /// (e.g. `agent-vm msb ls`, `agent-vm msb images ls`,
    /// `agent-vm msb --help`).
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
    args: Vec<String>,
}

/// Forward to the pinned `msb`. Returns the exit code to hand to
/// `std::process::exit`.
pub fn run(args: Args) -> Result<i32> {
    // Guard the private DB before handing it to the child msb, which would
    // otherwise open+migrate it and hit the opaque missing-file error. Any
    // msb subcommand can open the DB, so this must live here, not only on
    // the boot path. See issue #30.
    crate::msb_preflight::ensure_db_not_ahead_blocking()?;
    // point_at_msb() set MSB_PATH in main()'s prologue; read it back rather
    // than re-resolving so we forward to the exact binary already
    // version-verified, with no second `--version` spawn.
    run_with_path(std::env::var_os("MSB_PATH"), &args.args)
}

/// Pure seam over `run` so tests need not mutate process-wide env.
fn run_with_path(msb_path: Option<OsString>, args: &[String]) -> Result<i32> {
    let msb_path = msb_path.ok_or_else(|| {
        anyhow::anyhow!(
            "MSB_PATH is not set; agent-vm's msb setup did not run before dispatch \
             (this is an internal invariant — `Msb` is not in the needs_msb_setup \
             exclusion list in main.rs)"
        )
    })?;

    // Inherit stdio AND the process environment (MSB_HOME etc.) — the whole
    // point of the shim. Do NOT call .env_clear()/.env_remove(): that would
    // strip MSB_HOME and reintroduce the "No sandboxes found" bug this
    // ticket fixes.
    let status = Command::new(&msb_path)
        .args(args)
        .status()
        .with_context(|| {
            format!(
                "executing bundled msb at {}",
                Path::new(&msb_path).display()
            )
        })?;

    Ok(exit_code_from_status(status))
}

/// Map a child `ExitStatus` to a process exit code. Normal exit → its code;
/// signal death → 128 + signo (shell convention) so it is never 0.
fn exit_code_from_status(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        128 + status.signal().unwrap_or(0)
    }
    #[cfg(not(unix))]
    {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        args: Args,
    }

    #[test]
    fn trailing_args_captured_verbatim() {
        let cli = TestCli::try_parse_from(["t"]).expect("bare `agent-vm msb` parses");
        assert!(cli.args.args.is_empty());

        let cli = TestCli::try_parse_from(["t", "ls"]).expect("single arg parses");
        assert_eq!(cli.args.args, vec!["ls".to_string()]);

        let cli = TestCli::try_parse_from(["t", "images", "ls"]).expect("multi arg parses");
        assert_eq!(cli.args.args, vec!["images".to_string(), "ls".to_string()]);

        let cli =
            TestCli::try_parse_from(["t", "status", "--json"]).expect("hyphenated flag parses");
        assert_eq!(
            cli.args.args,
            vec!["status".to_string(), "--json".to_string()]
        );
    }

    #[test]
    fn help_flags_forward_to_msb_instead_of_being_intercepted_by_clap() {
        // Regression test for the disable_help_flag fix: without
        // #[command(disable_help_flag = true)] clap would intercept
        // --help/-h itself, try_parse_from would return an `Err` (clap's
        // help-display sentinel), and agent-vm would show clap's help
        // instead of forwarding to msb.
        let cli =
            TestCli::try_parse_from(["t", "--help"]).expect("--help forwards, not intercepted");
        assert_eq!(cli.args.args, vec!["--help".to_string()]);

        let cli = TestCli::try_parse_from(["t", "-h"]).expect("-h forwards, not intercepted");
        assert_eq!(cli.args.args, vec!["-h".to_string()]);
    }

    #[test]
    fn exit_code_from_status_maps_normal_and_signal_exits() {
        let status = Command::new("sh").args(["-c", "exit 0"]).status().unwrap();
        assert_eq!(exit_code_from_status(status), 0);

        let status = Command::new("sh").args(["-c", "exit 7"]).status().unwrap();
        assert_eq!(exit_code_from_status(status), 7);

        #[cfg(unix)]
        {
            let status = Command::new("sh")
                .args(["-c", "kill -TERM $$"])
                .status()
                .unwrap();
            assert_eq!(exit_code_from_status(status), 128 + 15);
        }
    }

    #[test]
    fn missing_msb_path_returns_clear_error() {
        let err = run_with_path(None, &[]).expect_err("None MSB_PATH must error");
        assert!(
            err.to_string().contains("MSB_PATH"),
            "error should name MSB_PATH, got: {err}"
        );
    }

    #[test]
    fn run_with_path_inherits_process_env_without_clearing_it() {
        // Guards the actual ticket bug: msb only sees agent-vm's private
        // MSB_HOME because the child inherits the full process env. We
        // can't assert on MSB_HOME directly without mutating process-wide
        // env (unsafe across the parallel test suite), so we prove the
        // underlying mechanism — no `.env_clear()` — via a var that's
        // reliably already present: PATH. MSB_HOME inheritance rides the
        // identical mechanism.
        let dir = std::env::temp_dir().join(format!(
            "agent-vm-msb-cmd-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let stub_path = dir.join("msb");
        let out_path = dir.join("out");
        {
            let mut f = std::fs::File::create(&stub_path).unwrap();
            writeln!(f, "#!/bin/sh").unwrap();
            writeln!(f, "printf '%s' \"$PATH\" > \"$1\"").unwrap();
        }
        std::fs::set_permissions(&stub_path, std::fs::Permissions::from_mode(0o755)).unwrap();

        let code = run_with_path(
            Some(stub_path.into_os_string()),
            &[out_path.to_string_lossy().into_owned()],
        )
        .expect("stub msb runs successfully");
        assert_eq!(code, 0);

        let captured = std::fs::read_to_string(&out_path).unwrap();
        assert_eq!(captured, std::env::var("PATH").unwrap());

        std::fs::remove_dir_all(&dir).ok();
    }
}
