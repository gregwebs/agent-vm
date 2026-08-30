use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use msb_krun_compat_evidence as evidence;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "msb-krun-compat-evidence")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Manifest {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        mode: String,
        #[arg(long)]
        host_os: String,
        #[arg(long)]
        host_arch: String,
        #[arg(long)]
        binary: PathBuf,
        #[arg(long)]
        firmware: PathBuf,
        #[arg(long)]
        image: String,
        #[arg(long)]
        image_platform: String,
    },
    Discovery {
        #[arg(long)]
        guest_log: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        expected_mounts: usize,
        #[arg(long, default_value = "")]
        selected_indexes: String,
        #[arg(long)]
        baseline: Option<PathBuf>,
    },
    BaselineStable {
        #[arg(long)]
        before: PathBuf,
        #[arg(long)]
        after: PathBuf,
    },
    Observations {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        host_os: String,
        #[arg(long)]
        host_arch: String,
        #[arg(long)]
        last_good: usize,
        #[arg(long)]
        first_failure: usize,
        #[arg(long)]
        repeats: usize,
        #[arg(long, allow_hyphen_values = true)]
        failure_reason: String,
    },
}
fn indexes(csv: &str) -> Result<Vec<usize>> {
    if csv.is_empty() {
        return Ok(vec![]);
    }
    csv.split(',')
        .map(|value| {
            value
                .parse()
                .with_context(|| format!("invalid selected mount index {value:?}"))
        })
        .collect()
}
fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Manifest {
            output,
            mode,
            host_os,
            host_arch,
            binary,
            firmware,
            image,
            image_platform,
        } => evidence::write_manifest(evidence::ManifestRequest {
            output: &output,
            mode: &mode,
            host_os: &host_os,
            host_arch: &host_arch,
            binary: &binary,
            firmware: &firmware,
            image: &image,
            image_platform: &image_platform,
            started_at: evidence::current_unix_time()?,
        })
        .context("write manifest"),
        Command::Discovery {
            guest_log,
            output,
            expected_mounts,
            selected_indexes,
            baseline,
        } => evidence::write_discovery(evidence::DiscoveryRequest {
            guest_log: &guest_log,
            output: &output,
            expected_mounts,
            selected_indexes: indexes(&selected_indexes)?,
            baseline: baseline.as_deref(),
        })
        .context("write discovery"),
        Command::BaselineStable { before, after } => {
            evidence::assert_baseline_stable(&before, &after).context("compare Darwin baselines")
        }
        Command::Observations {
            output,
            host_os,
            host_arch,
            last_good,
            first_failure,
            repeats,
            failure_reason,
        } => evidence::write_observations(evidence::ObservationsRequest {
            output: &output,
            host_os: &host_os,
            host_arch: &host_arch,
            last_good,
            first_failure,
            repeats,
            failure_reason: &failure_reason,
        })
        .context("write observations"),
    }
}
