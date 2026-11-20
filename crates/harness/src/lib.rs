//! Test-harness tooling for agent-vm (ADR-0072).
//!
//! The shell suites call this binary instead of running Python. Nothing here
//! depends on the `agent-vm` crate: the harness is an independent oracle, so it
//! keeps its own model of every format it reads or writes, and a format change
//! that breaks it is meant to fail.

use clap::{Parser, Subcommand};

mod config_dir_guard;
mod launch_argv_order;

/// The `harness` commands. A port adds one variant, replacing a Python driver or
/// a boot-free Python suite.
#[derive(Debug, Parser)]
#[command(name = "harness", version, about = "Test-harness tooling for agent-vm")]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run configuration-directory guard controls and filesystem queries.
    ConfigDirGuard(config_dir_guard::ConfigDirGuardArgs),
    /// Check that launch options precede tool verbs.
    LaunchArgvOrder(launch_argv_order::LaunchArgvOrderArgs),
}

pub fn run(cli: Cli) -> Result<String, String> {
    match cli.command {
        Command::ConfigDirGuard(args) => config_dir_guard::run(args),
        Command::LaunchArgvOrder(args) => launch_argv_order::run(args),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_cli_definition_is_valid() {
        Cli::command().debug_assert();
    }
}
