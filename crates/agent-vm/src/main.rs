//! agent-vm — sandboxed microVMs for AI coding agents on microsandbox.

mod clipboard;
mod credential_injection;
mod defaults;
mod doctor;
mod github_graphql;
mod host_paths;
mod image_api_version;
mod image_capabilities;
mod image_check;
mod intercept_hook;
mod layer;
mod mount;
mod msb_cmd;
mod msb_install;
mod msb_preflight;
mod msb_schema;
mod network;
mod pull;
mod pull_progress;
mod pulled_marker;
mod run;
mod secrets;
mod session;
mod setup;
mod user;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

// Shown under the top-level `agent-vm --help`, after the command list.
const TOP_AFTER_HELP: &str = "\
Getting started:
  agent-vm setup       fetch and verify the base image (run once first)
  cd ~/your-project
  agent-vm claude      launch in this project — or codex / opencode / copilot / shell

claude, codex, opencode, copilot and shell share the same options;
see `agent-vm claude --help` for mounts, ports, networking and credentials.";

#[derive(Parser)]
#[command(
    name = "agent-vm",
    version,
    about = "Sandboxed microVMs for AI coding agents.",
    after_help = TOP_AFTER_HELP
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Pull and verify the base image (run once first).
    Setup(setup::Args),

    /// Refresh the cached base image.
    Pull(pull::Args),

    /// Launch Claude Code in a per-project sandbox.
    Claude(run::Args),

    /// Launch Codex CLI in a per-project sandbox.
    Codex(run::Args),

    /// Launch OpenCode in a per-project sandbox.
    Opencode(run::Args),

    /// Launch GitHub Copilot CLI in a per-project sandbox.
    Copilot(run::Args),

    /// Open a bash shell in a per-project sandbox.
    Shell(run::Args),

    /// Forward arguments to the bundled `msb` with agent-vm's MSB_HOME/MSB_PATH
    /// pinned (e.g. `agent-vm msb ls`, `agent-vm msb status`). Relies on
    /// `needs_msb_setup` staying true for this variant — see main().
    Msb(msb_cmd::Args),

    /// Exchange a string between the host and the sandbox.
    Clipboard(clipboard::Args),

    /// Diagnostic / maintenance operations for agent-vm's private
    /// microsandbox state (e.g. --reset-msb-db).
    Doctor(doctor::Args),

    /// Internal: invoked by msb's interceptor hook for matched OAuth
    /// refresh requests. Reads the request on stdin, writes an
    /// HTTP response on stdout. Not meant for direct use.
    #[command(name = "_intercept-hook", hide = true)]
    InterceptHook(intercept_hook::Args),
}

fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    // Locate and pin our patched msb binary via MSB_PATH so a user's
    // separate `~/.microsandbox/bin/msb` can't shadow ours. The hook
    // subcommand runs as a child of msb itself (the binary is
    // already resolved); the clipboard subcommand also runs in
    // contexts where the bundled msb may not be available
    // (e.g. inside the guest VM), so skip the check there too.
    //
    // CRITICAL: `point_at_msb()` / `point_at_msb_home()` mutate the
    // process environment via `unsafe { std::env::set_var(...) }`.
    // setenv() is not thread-safe under POSIX. We MUST run them
    // before the tokio multi-thread runtime spawns workers (which
    // happens inside `Runtime::new()`). Hence the manual sync `fn
    // main` + manual runtime construction instead of `#[tokio::main]`.
    let needs_msb_setup = !matches!(cli.cmd, Cmd::InterceptHook(_) | Cmd::Clipboard(_));
    if needs_msb_setup {
        msb_install::point_at_msb()?;
        // Reroute msb's writable state off `~/.microsandbox/` and into
        // agent-vm's own state dir. msb still finds `libkrunfw.so.*`
        // via MSB_PATH → sibling `../lib/` (the bundle layout), so no
        // copy/sync into MSB_HOME is needed — only the writable state
        // (db, sandboxes, cache, tls/CA, logs) lives here.
        msb_install::point_at_msb_home()?;
    }
    // `msb_cmd::run` is fully synchronous (just spawns a child and waits);
    // dispatch it before paying for a tokio runtime we'd otherwise spin up
    // and immediately block on for a single `Command::status()` call.
    if let Cmd::Msb(args) = cli.cmd {
        return exit_with(msb_cmd::run(args)?);
    }
    // doctor is also pure sync fs work (no VM/network I/O); dispatch it
    // before the runtime for the same reason as Msb above.
    if let Cmd::Doctor(args) = cli.cmd {
        doctor::run(args)?;
        return Ok(());
    }
    let runtime = tokio::runtime::Runtime::new().context("starting tokio runtime")?;
    runtime.block_on(async move {
        match cli.cmd {
            Cmd::Setup(args) => setup::run(args).await,
            Cmd::Pull(args) => pull::run(args).await,
            Cmd::Claude(args) => exit_with(run::launch(run::Agent::Claude, args).await?),
            Cmd::Codex(args) => exit_with(run::launch(run::Agent::Codex, args).await?),
            Cmd::Opencode(args) => exit_with(run::launch(run::Agent::Opencode, args).await?),
            Cmd::Copilot(args) => exit_with(run::launch(run::Agent::Copilot, args).await?),
            Cmd::Shell(args) => exit_with(run::launch(run::Agent::Shell, args).await?),
            Cmd::Clipboard(args) => clipboard::run(args),
            Cmd::InterceptHook(args) => intercept_hook::run(args).await,
            // Already dispatched and returned from, above, before the
            // runtime was built — `Cmd` isn't `Clone`/`Copy`, so this arm
            // exists only to satisfy exhaustiveness.
            Cmd::Msb(_) => unreachable!("Cmd::Msb is dispatched pre-runtime, see above"),
            Cmd::Doctor(_) => unreachable!("Cmd::Doctor is dispatched pre-runtime, see above"),
        }
    })
}

/// Wire `tracing` so `RUST_LOG=agent_vm=debug,microsandbox=info` works.
/// Default level is `warn` — keeps normal output clean, but anything from
/// the microsandbox stack surfaces when you ask for it.
fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(true)
        .compact()
        .init();
}

fn exit_with(code: i32) -> Result<()> {
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory as _, Parser as _};

    use super::Cli;

    // Clap indents blank description spacers at this width. Normalize only lines
    // containing whitespace so fixtures stay clean while still pinning every
    // meaningful character, indentation, and ordering in both help renderings.
    fn normalize_help_whitespace_only_lines(help: &str) -> String {
        help.split_inclusive('\n')
            .map(|line| {
                let (content, newline) = line
                    .strip_suffix('\n')
                    .map_or((line, ""), |content| (content, "\n"));
                if content.trim().is_empty() {
                    newline.to_owned()
                } else {
                    line.to_owned()
                }
            })
            .collect()
    }

    #[test]
    fn shell_accepts_network_options_and_keeps_help_stable() {
        Cli::try_parse_from([
            "agent-vm",
            "shell",
            "-p",
            "8080:3000",
            "--publish",
            "[::1]:8081:3001/tcp",
            "--auto-publish",
            "--allow-egress",
            "10.0.0.5",
            "--allow-egress",
            "fd00::1",
            "--allow-lan",
            "--allow-host",
            "--",
            "--agent-flag",
        ])
        .expect("the real shell subcommand accepts all network options");

        let mut command = Cli::command().term_width(100);
        let mut shell = command
            .find_subcommand_mut("shell")
            .expect("shell subcommand is registered")
            .clone()
            .bin_name("agent-vm shell")
            // These fixtures characterize the CLI contract, not ambient process
            // configuration. Keep the env-variable labels but omit their values
            // on this test-only clone so parallel tests never need setenv().
            .mut_args(|arg| arg.hide_env_values(true));

        let mut short_help = Vec::new();
        shell
            .clone()
            .write_help(&mut short_help)
            .expect("short shell help renders");
        assert_eq!(
            normalize_help_whitespace_only_lines(
                &String::from_utf8(short_help).expect("help is UTF-8"),
            ),
            normalize_help_whitespace_only_lines(include_str!(
                "../tests/fixtures/shell-short-help-columns-100.txt"
            ))
        );

        let mut long_help = Vec::new();
        shell
            .write_long_help(&mut long_help)
            .expect("long shell help renders");
        assert_eq!(
            normalize_help_whitespace_only_lines(
                &String::from_utf8(long_help).expect("help is UTF-8"),
            ),
            normalize_help_whitespace_only_lines(include_str!(
                "../tests/fixtures/shell-help-columns-100.txt"
            ))
        );
    }
}
