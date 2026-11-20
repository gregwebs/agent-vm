//! Test-harness tooling for agent-vm (ADR-0072).
//!
//! The shell suites call this binary instead of running Python. Nothing here
//! depends on the `agent-vm` crate: the harness is an independent oracle, so it
//! keeps its own model of every format it reads or writes, and a format change
//! that breaks it is meant to fail.

use clap::{Parser, Subcommand};

mod runtime_provenance;
mod config_dir_guard;
mod launch_argv_order;
mod msb_krun_compat;

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
    /// Validate the two Cargo roots and the pinned firmware source.
    RuntimeProvenance(runtime_provenance::RuntimeProvenanceArgs),
    /// Run configuration-directory guard controls and filesystem queries.
    ConfigDirGuard(config_dir_guard::ConfigDirGuardArgs),
    /// Check that launch options precede tool verbs.
    LaunchArgvOrder(launch_argv_order::LaunchArgvOrderArgs),
    /// Run the msb-krun compatibility timeout driver.
    MsbKrunCompat(msb_krun_compat::MsbKrunCompatArgs),
}

impl Cli {
    /// The prefix a failure from this command's own code carries. Only the
    /// command that ran can label its error: a shared prefix named whichever
    /// port was written first, which mislabels every later one.
    pub fn failure_label(&self) -> &'static str {
        match self.command {
            Command::RuntimeProvenance(_) => "runtime provenance",
            Command::ConfigDirGuard(_) => "config-dir guard",
            Command::LaunchArgvOrder(_) => "launch argv order",
            Command::MsbKrunCompat(_) => "msb-krun compat",
        }
    }
}

pub fn run(cli: Cli) -> Result<String, String> {
    match cli.command {
        Command::RuntimeProvenance(args) => runtime_provenance::run(args),
        Command::ConfigDirGuard(args) => config_dir_guard::run(args),
        Command::LaunchArgvOrder(args) => launch_argv_order::run(args),
        Command::MsbKrunCompat(args) => msb_krun_compat::run(args),
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
