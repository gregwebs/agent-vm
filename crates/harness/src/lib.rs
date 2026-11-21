//! Test-harness tooling for agent-vm (ADR-0072).
//!
//! The shell suites call this binary instead of running Python. Nothing here
//! depends on the `agent-vm` crate: the harness is an independent oracle, so it
//! keeps its own model of every format it reads or writes, and a format change
//! that breaks it is meant to fail.

use clap::{Parser, Subcommand};

mod runtime_provenance;
// The egress fixtures are a library as well as a command: #693-#695 port their
// Python consumers, and `agent-vm`'s dev-dependency uses the same functions.
pub mod egress_allowances;
pub mod egress_cases;
pub mod egress_fixtures;
pub mod egress_hostname_fixtures;
pub mod egress_launch;
pub mod egress_run;
// The supervisor's controls: a library module as well as a command, because its
// call-site controls read this crate's source (`--repo-root`).
pub mod egress_supervisor;
pub mod egress_witness;
pub mod msb_catalog;

mod build_archive_oracle;
mod build_provenance;
mod config_dir_guard;
mod config_mounts;
mod config_mounts_controls;
mod cpu_commitment;
mod detached_run;
mod egress_default_deny;
mod egress_mutations;
mod egress_probe;
mod image_pins;
mod launch_argv_order;
mod launcher_standin;
mod msb_krun_compat;
mod pty;
mod released_image_launch;

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
    /// Run the config-mounts native rows: launches, host oracles and their receipt.
    ConfigMounts(config_mounts::ConfigMountsArgs),
    /// Run the boot-free controls for the config-mounts rows and their guard entries.
    ConfigMountsControls(config_mounts_controls::ConfigMountsControlsArgs),
    /// Drive Phase 0 CPU-commitment selection and runtime-provenance manifests.
    CpuCommitment(cpu_commitment::CpuCommitmentArgs),
    /// Run one command in a session with no controlling terminal and no stdin.
    DetachedRun(detached_run::DetachedRunArgs),
    /// Serve the local egress fixtures, or ask them what they have seen.
    EgressFixtures(egress_fixtures::EgressFixturesArgs),
    /// Run the boot-free controls for the egress probe library and its driver.
    EgressProbe(egress_probe::EgressProbeArgs),
    /// Prove the mutation anchors resolve, or run the mutation controls themselves.
    EgressMutations(egress_mutations::EgressMutationsArgs),
    /// Check the egress default-deny driver's plan inventory and guard rails.
    EgressDefaultDeny(egress_default_deny::EgressDefaultDenyArgs),
    /// Run the boot-free controls for the owned launch supervisor.
    EgressSupervisor(egress_supervisor::EgressSupervisorArgs),
    /// Check the image-pins live-seed helper dispatch.
    ImagePins(image_pins::ImagePinsArgs),
    /// Play a launcher's plumbing for the boot-free direct-terminal controls.
    LauncherStandin(launcher_standin::LauncherStandinArgs),
    /// Check that launch options precede tool verbs.
    LaunchArgvOrder(launch_argv_order::LaunchArgvOrderArgs),
    /// Run the msb-krun compatibility timeout driver.
    MsbKrunCompat(msb_krun_compat::MsbKrunCompatArgs),
    /// Launch an installed released-image candidate in an owned, bounded process group.
    ReleasedImageLaunch(released_image_launch::ReleasedImageLaunchArgs),
}

impl Cli {
    /// The prefix a failure from this command's own code carries. Only the
    /// command that ran can label its error: a shared prefix named whichever
    /// port was written first, which mislabels every later one.
    pub fn failure_label(&self) -> &'static str {
        match self.command {
            Command::RuntimeProvenance(_) => "runtime provenance",
            Command::ConfigDirGuard(_) => "config-dir guard",
            Command::ConfigMounts(_) => "config mounts",
            Command::ConfigMountsControls(_) => "config mounts controls",
            Command::LaunchArgvOrder(_) => "launch argv order",
            Command::MsbKrunCompat(_) => "msb-krun compat",
            Command::BuildProvenance(_) => "build provenance",
            Command::ImagePins(_) => "image pins",
            Command::CpuCommitment(_) => "cpu commitment",
            Command::BuildArchiveOracle(_) => "build archive oracle",
            Command::ReleasedImageLaunch(_) => "released-image launch",
            Command::DetachedRun(_) => "detached-run",
            Command::LauncherStandin(_) => "standin",
            Command::EgressFixtures(_) => "egress fixtures",
            Command::EgressProbe(_) => "egress probe",
            Command::EgressDefaultDeny(_) => "egress default deny",
            Command::EgressSupervisor(_) => "egress supervisor",
            Command::EgressMutations(_) => "egress mutations",
        }
    }
}

/// What the binary does once a command has run.
///
/// A launcher's interface is its child's exit status, which is arbitrary, so a
/// command cannot always report through the text `main` prints for the others.
pub enum Outcome {
    /// Print this text, if any, and exit 0.
    Report(String),
    /// Exit with this status; the command has already said what it had to say.
    Exit(i32),
}

pub fn run(cli: Cli) -> Result<Outcome, String> {
    match cli.command {
        Command::RuntimeProvenance(args) => runtime_provenance::run(args).map(Outcome::Report),
        Command::BuildArchiveOracle(args) => build_archive_oracle::run(args).map(Outcome::Report),
        Command::BuildProvenance(args) => build_provenance::run(args).map(Outcome::Report),
        Command::ConfigDirGuard(args) => config_dir_guard::run(args).map(Outcome::Report),
        Command::ConfigMounts(args) => config_mounts::run(args),
        Command::ConfigMountsControls(args) => {
            config_mounts_controls::run(args).map(Outcome::Report)
        }
        Command::CpuCommitment(args) => cpu_commitment::run(args).map(Outcome::Report),
        Command::DetachedRun(args) => detached_run::run(args),
        Command::EgressFixtures(args) => egress_fixtures::run(args),
        Command::EgressProbe(args) => egress_probe::run(args),
        Command::EgressMutations(args) => egress_mutations::run(args),
        Command::EgressDefaultDeny(args) => egress_default_deny::run(args),
        Command::EgressSupervisor(args) => egress_supervisor::run(args),
        Command::ImagePins(args) => image_pins::run(args).map(Outcome::Report),
        Command::LauncherStandin(args) => launcher_standin::run(args),
        Command::LaunchArgvOrder(args) => launch_argv_order::run(args).map(Outcome::Report),
        Command::MsbKrunCompat(args) => msb_krun_compat::run(args).map(Outcome::Report),
        Command::ReleasedImageLaunch(args) => released_image_launch::run(args),
    }
}

/// The exit status a failed command asks for, when it asks for one of its own.
/// A port whose callers distinguish an inconclusive verdict from a refusal keeps
/// the two apart here; everything else exits 1 in `main`.
pub fn failure_status(error: &str) -> Option<i32> {
    // Misuse: a refused argument value or a missing one. Clap already exits 2
    // for what it can reject itself, so a command that validates its own
    // arguments keeps that status.
    if error.starts_with("usage: ") {
        return Some(2);
    }
    detached_run::failure_status(error)
        .or_else(|| egress_mutations::failure_status(error))
        .or_else(|| launcher_standin::failure_status(error))
        .or_else(|| cpu_commitment::failure_status(error))
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
