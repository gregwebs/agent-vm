//! Test-harness tooling for agent-vm (ADR-0072).
//!
//! The shell suites call this binary instead of running Python. Nothing here
//! depends on the `agent-vm` crate: the harness is an independent oracle, so it
//! keeps its own model of every format it reads or writes, and a format change
//! that breaks it is meant to fail.

use clap::{Parser, Subcommand};

mod runtime_provenance;
mod build_archive_oracle;
mod build_provenance;
mod config_dir_guard;
mod cpu_commitment;
mod image_pins;
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
    /// Inspect a buildx OCI archive without extracting it.
    BuildArchiveOracle(build_archive_oracle::BuildArchiveOracleArgs),
    /// Check a binary's build provenance against independently captured source evidence.
    BuildProvenance(build_provenance::BuildProvenanceArgs),
    /// Run configuration-directory guard controls and filesystem queries.
    ConfigDirGuard(config_dir_guard::ConfigDirGuardArgs),
    /// Drive Phase 0 CPU-commitment selection and runtime-provenance manifests.
    CpuCommitment(cpu_commitment::CpuCommitmentArgs),
    /// Check the image-pins live-seed helper dispatch.
    ImagePins(image_pins::ImagePinsArgs),
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
            Command::BuildProvenance(_) => "build provenance",
            Command::ImagePins(_) => "image pins",
            Command::CpuCommitment(_) => "cpu commitment",
            Command::BuildArchiveOracle(_) => "build archive oracle",
        }
    }
}

pub fn run(cli: Cli) -> Result<String, String> {
    match cli.command {
        Command::RuntimeProvenance(args) => runtime_provenance::run(args),
        Command::BuildArchiveOracle(args) => build_archive_oracle::run(args),
        Command::BuildProvenance(args) => build_provenance::run(args),
        Command::ConfigDirGuard(args) => config_dir_guard::run(args),
        Command::CpuCommitment(args) => cpu_commitment::run(args),
        Command::ImagePins(args) => image_pins::run(args),
        Command::LaunchArgvOrder(args) => launch_argv_order::run(args),
        Command::MsbKrunCompat(args) => msb_krun_compat::run(args),
    }
}

/// The exit status a failed command asks for, when it asks for one of its own.
/// A port whose callers distinguish an inconclusive verdict from a refusal keeps
/// the two apart here; everything else exits 1 in `main`.
pub fn failure_status(error: &str) -> Option<i32> {
    cpu_commitment::failure_status(error)
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
