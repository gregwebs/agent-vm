//! `agent-vm image import` — publish an already-finished image into agent-vm's
//! own image cache, from the local Docker daemon or a completed archive (#359).
//! Never selects, adopts, configures or boots; launches still never run Docker.
//! Publishes `--tag` plus any names the archive itself carries (see
//! [`crate::image_publish`]); a failed import restores `--tag` only.

use crate::image_publish::{ImageTarget, ResultReference};
use anyhow::{Context, Result, anyhow, bail};
use clap::Args as ClapArgs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::str::FromStr;
use vstd::prelude::*;

const DOCKER_SOURCE_REASON: &str = "--docker must name an image in the local Docker daemon (e.g. my-image:dev): not empty, no whitespace or NUL, and not starting with '-'";
const INPUT_REASON: &str =
    "--input must name an existing regular file (a completed OCI or Docker-save archive)";

#[derive(ClapArgs)]
pub(crate) struct Args {
    /// Import the image under this reference in agent-vm's own image cache.
    /// The reference is mutable: a later build or import replaces it.
    #[arg(short = 't', long, value_name = "REF")]
    tag: ResultReference,
    #[command(flatten)]
    source: SourceArgs,
}

#[derive(ClapArgs)]
#[group(required = true, multiple = false)]
struct SourceArgs {
    /// Take the image from the local Docker daemon (`docker image save`).
    #[arg(long, value_name = "REF")]
    docker: Option<DockerSource>,
    /// Take the image from a completed OCI or Docker-save archive. Docker is not needed.
    #[arg(long, value_name = "PATH")]
    input: Option<PathBuf>,
}

enum Source {
    Docker(DockerSource),
    Input(PathBuf),
}

impl SourceArgs {
    fn into_source(self) -> Result<Source> {
        match (self.docker, self.input) {
            (Some(d), None) => Ok(Source::Docker(d)),
            (None, Some(p)) => Ok(Source::Input(p)),
            _ => bail!("internal: clap must enforce exactly one of --docker/--input"),
        }
    }
}

/// A Docker-daemon reference passed verbatim to `docker image save`. Docker owns
/// reference grammar; this type only guarantees the value cannot be read as an
/// option or split into several arguments.
#[derive(Clone)]
struct DockerSource(String);

impl FromStr for DockerSource {
    type Err = anyhow::Error;

    fn from_str(raw: &str) -> Result<Self> {
        // Measured here, decided by the contracted kernel (ADR-0018).
        if docker_source_is_acceptable(DockerSourceFacts {
            nonempty: !raw.is_empty(),
            has_nul: raw.contains('\0'),
            has_whitespace: raw.chars().any(char::is_whitespace),
            leading_dash: raw.starts_with('-'),
        }) {
            Ok(Self(raw.to_string()))
        } else {
            Err(anyhow!(DOCKER_SOURCE_REASON))
        }
    }
}

verus! {

/// The four already-measured facts the `--docker` decision reads. Named fields
/// rather than adjacent `bool` parameters, so an argument swap cannot invert
/// the decision.
pub(crate) struct DockerSourceFacts {
    pub(crate) nonempty: bool,
    pub(crate) has_nul: bool,
    pub(crate) has_whitespace: bool,
    pub(crate) leading_dash: bool,
}

/// The `--docker` acceptance decision, contracted (ADR-0018): accept **iff** the
/// value is nonempty and cannot be read as an option (`-`), split into several
/// arguments (whitespace) or truncated (NUL). Docker's own grammar is not
/// re-decided here; `save_command` passes the value after `--`.
pub(crate) fn docker_source_is_acceptable(facts: DockerSourceFacts) -> (accepted: bool)
    ensures accepted == (facts.nonempty && !facts.has_nul && !facts.has_whitespace && !facts.leading_dash),
{ facts.nonempty && !facts.has_nul && !facts.has_whitespace && !facts.leading_dash }

} // verus!

/// Input-only checks, run by `main` before the MSB prologue: reads argv and
/// `stat`s `--input`; writes nothing, spawns nothing.
pub(crate) fn preflight(args: &Args) -> Result<()> {
    match &args.source.input {
        Some(path) => require_regular_file(path),
        None => Ok(()),
    }
}

pub(crate) async fn run(args: Args) -> Result<i32> {
    match args.source.into_source()? {
        Source::Input(path) => {
            // Repeated: `run` stays self-contained; `preflight` is the boundary
            // that keeps a path typo from creating state.
            require_regular_file(&path)?;
            let target = ImageTarget::resolve().await?;
            target
                .publish(&path, &args.tag)
                .await
                .context("importing image")?;
        }
        Source::Docker(source) => {
            // Resolve before Docker: invalid shared config must fail first.
            let target = ImageTarget::resolve().await?;
            let staging = target.stage()?;
            let exit = save_archive(&source, staging.path()).await?;
            if exit != 0 {
                // A nonzero save status is a failure even if complete bytes
                // were written: never import an archive from a command that
                // reported failure. No retry.
                let _ = writeln!(
                    std::io::stderr(),
                    "docker image save failed (exit {exit}); nothing was imported"
                );
                return Ok(exit);
            }
            target
                .publish(staging.path(), &args.tag)
                .await
                .context("importing image")?;
        }
    }
    // Best-effort completion notice on stdout: stderr is for errors and
    // Docker's own output.
    let shown = args.tag.shell_arg();
    let _ = writeln!(
        std::io::stdout(),
        "Imported {shown} into agent-vm's image cache; launch it with `--image {shown}`"
    );
    Ok(0)
}

fn require_regular_file(path: &Path) -> Result<()> {
    // `metadata` follows symlinks, so a symlink to a regular file is accepted.
    if std::fs::metadata(path).is_ok_and(|m| m.is_file()) {
        Ok(())
    } else {
        bail!(INPUT_REASON)
    }
}

/// `docker image save --output <output> -- <REF>`; no shell, and `--` before the
/// reference so a leading `-` could never be read as an option.
fn save_command(source: &DockerSource, output: &Path) -> tokio::process::Command {
    let mut command = tokio::process::Command::new("docker");
    command
        .args(["image", "save", "--output"])
        .arg(output)
        .arg("--")
        .arg(&source.0);
    command
}

/// Inherits stdio so Docker's progress and errors reach the user unchanged.
async fn save_archive(source: &DockerSource, output: &Path) -> Result<i32> {
    let status = save_command(source, output)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .context("running `docker image save`; this needs a working Docker CLI on PATH")?;
    Ok(crate::msb_cmd::exit_code_from_status(status))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        args: Args,
    }

    #[test]
    fn docker_source_truth_table() {
        for bits in 0..16 {
            let (a, b, c, d) = (bits & 1 != 0, bits & 2 != 0, bits & 4 != 0, bits & 8 != 0);
            assert_eq!(
                docker_source_is_acceptable(DockerSourceFacts {
                    nonempty: a,
                    has_nul: b,
                    has_whitespace: c,
                    leading_dash: d
                }),
                bits == 1
            );
        }
    }

    #[test]
    fn docker_source_rejects_empty_nul_whitespace_and_leading_dash() {
        for raw in [
            "",
            "a\0b",
            "SENTINEL_DS1 x",
            "SENTINEL_DS2\tx",
            "-SENTINEL_DS3",
            "--privileged",
        ] {
            let error = raw.parse::<DockerSource>().err().unwrap().to_string();
            assert_eq!(error, DOCKER_SOURCE_REASON);
            if !raw.is_empty() {
                assert!(!error.contains(raw));
            }
        }
    }

    #[test]
    fn docker_source_accepts_docker_spellings() {
        for raw in [
            "agent-vm-standard:local",
            "localhost:5000/x:y",
            "repo@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "297bb34a6d27",
        ] {
            assert!(raw.parse::<DockerSource>().is_ok());
        }
    }

    #[test]
    fn save_command_argv_is_exact() {
        let command = save_command(&DockerSource("app:dev".into()), Path::new("/tmp/out"));
        assert_eq!(
            command.as_std().get_args().collect::<Vec<_>>(),
            ["image", "save", "--output", "/tmp/out", "--", "app:dev"]
        );
    }

    #[test]
    fn input_reason_is_exact_and_names_no_path() {
        let root = tempfile::tempdir().unwrap();
        for path in [
            root.path().join("SENTINEL_IN1.tar"),
            root.path().to_path_buf(),
        ] {
            assert_eq!(
                require_regular_file(&path).unwrap_err().to_string(),
                INPUT_REASON
            );
        }
    }

    #[test]
    fn clap_surface() {
        use clap::error::ErrorKind::*;
        for (args, expected) in [
            (vec!["--tag", "app:dev"], MissingRequiredArgument),
            (vec!["--docker", "app"], MissingRequiredArgument),
            (
                vec!["--tag", "app:dev", "--docker", "app", "--input", "file"],
                ArgumentConflict,
            ),
            (
                vec![
                    "--tag",
                    "app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "--docker",
                    "app",
                ],
                ValueValidation,
            ),
        ] {
            assert_eq!(
                TestCli::try_parse_from(std::iter::once("t").chain(args))
                    .err()
                    .unwrap()
                    .kind(),
                expected
            );
        }
        for flag in ["--platform", "--output", "--load", "--push", "extra"] {
            assert_eq!(
                TestCli::try_parse_from(["t", "--tag", "app:dev", "--docker", "app", flag])
                    .err()
                    .unwrap()
                    .kind(),
                UnknownArgument
            );
        }
    }
}
