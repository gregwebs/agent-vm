//! `agent-vm image import` — publish an already-finished image into agent-vm's
//! own image cache, from the local Docker daemon or a completed archive (#359).
//! Never selects, adopts, configures or boots; launches still never run Docker.
//! Publishes the result reference — explicit `--tag`, or the `--docker` source
//! when that is omitted (#385) — plus any names the archive itself carries (see
//! [`crate::image_publish`]); a failed import restores that reference only.
//!
//! A successful import *observes* the selection (read-only, after publication)
//! solely to decide whether launch guidance is noise: a result reference the
//! configuration already selects needs no hint.

use crate::boot_image::BootImage;
use crate::config::ConfiguredImages;
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
const INFERRED_REFERENCE_REASON: &str = "--docker cannot supply the default --tag";

#[derive(ClapArgs)]
pub(crate) struct Args {
    /// Import the image under this reference in agent-vm's own image cache.
    /// The reference is mutable: a later build or import replaces it.
    ///
    /// Required with --input; with --docker it defaults to the source
    /// reference, which must itself be a mutable OCI reference.
    #[arg(
        short = 't',
        long,
        value_name = "REF",
        required_unless_present = "docker"
    )]
    tag: Option<ResultReference>,
    #[command(flatten)]
    source: SourceArgs,
}

impl Args {
    /// The one result reference this import publishes under: an explicit
    /// `--tag`, or the Docker source used as its own default.
    ///
    /// Both routes cross the same [`ResultReference`] parser, so an inferred
    /// destination cannot be a value the explicit spelling would refuse. The
    /// Docker *source* grammar stays wider: an explicit tag is needed only when
    /// that parser rejects the source (e.g. a digest-pinned reference or local
    /// path). Bare hexadecimal IDs may parse as mutable names.
    pub(crate) fn result_reference(&self) -> Result<ResultReference> {
        match (&self.tag, &self.source.docker) {
            (Some(tag), _) => Ok(tag.clone()),
            (None, Some(docker)) => docker.result_reference(),
            // clap's `required_unless_present` already refused this shape; an
            // internal invariant, never a panic. Both reasons are value-free.
            (None, None) => {
                bail!("internal error: clap must require --tag unless --docker is given")
            }
        }
    }
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

impl DockerSource {
    /// The source as the omitted `--tag`. The parser's own reason is fixed text
    /// that names no value, so it is safe to carry into a usage diagnostic;
    /// the source itself never is.
    fn result_reference(&self) -> Result<ResultReference> {
        self.0.parse::<ResultReference>().map_err(|reason| {
            anyhow!("{INFERRED_REFERENCE_REASON}: {reason}. Pass an explicit mutable --tag REF")
        })
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

pub(crate) async fn run(args: Args, configured: Result<&ConfiguredImages>) -> Result<i32> {
    let tag = args.result_reference()?;
    match args.source.into_source()? {
        Source::Input(path) => {
            // Repeated: `run` stays self-contained; `preflight` is the boundary
            // that keeps a path typo from creating state.
            require_regular_file(&path)?;
            let target = ImageTarget::resolve().await?;
            target
                .publish(&path, &tag)
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
                .publish(staging.path(), &tag)
                .await
                .context("importing image")?;
        }
    }
    // Observed only now, after publication: the selector's default tier arms a
    // process-global dependency-log guard, so running it before the native
    // work would change diagnostics this command already had. The observation
    // is advisory — a broken configuration must not turn a committed
    // publication into a failure, and this command changes no selection.
    let selection = configured.and_then(crate::boot_image::ambient_selection);
    if let Some(notice) = completion_notice(&tag, selection) {
        // Best-effort completion notice on stdout: stderr is for errors and
        // Docker's own output. A failed write is not a failed import.
        let _ = writeln!(std::io::stdout(), "{notice}");
    }
    Ok(0)
}

/// The completion sentence, or nothing when the configuration already selects
/// exactly this result reference (#385).
///
/// Compared as exact reference text: `app` and `app:latest` stay different even
/// though native registry resolution treats them alike.
fn completion_notice(tag: &ResultReference, selection: Result<BootImage>) -> Option<String> {
    match selection {
        Ok(selected) if selected.reference().as_str() == tag.as_str() => None,
        // A retained/recommended fallback is not an image the user configured,
        // so there is nothing to point at: keep only the launch guidance.
        Ok(selected) if selected.is_default() => Some(launch_notice(tag)),
        // Either an explicitly configured different image (the user may not
        // know which one wins) or an unknown selection. Neither discloses the
        // selected reference, a source path, nor a selection error.
        Ok(_) | Err(_) => Some(format!(
            "{}\nRun `agent-vm image show` to see the currently configured image.",
            launch_notice(tag)
        )),
    }
}

fn launch_notice(tag: &ResultReference) -> String {
    let shown = tag.shell_arg();
    format!("Imported {shown} into agent-vm's image cache; launch it with `--image {shown}`")
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
            (vec!["--input", "file"], MissingRequiredArgument),
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
            (vec!["--docker", "x", "--tag"], InvalidValue),
        ] {
            assert_eq!(
                TestCli::try_parse_from(std::iter::once("t").chain(args))
                    .err()
                    .unwrap()
                    .kind(),
                expected
            );
        }
        for argv in [
            vec!["--docker", "app"],
            vec!["--docker", "app", "--tag", "other:dev"],
            vec!["--docker", "app", "-t", "other:dev"],
            vec!["--input", "file", "--tag", "app:dev"],
        ] {
            assert!(
                TestCli::try_parse_from(std::iter::once("t").chain(argv.clone()))
                    .unwrap_or_else(|error| panic!("{argv:?} must parse: {error}"))
                    .args
                    .result_reference()
                    .is_ok(),
                "{argv:?}"
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

    #[test]
    fn omitted_tag_defaults_to_the_docker_source() {
        let parsed = TestCli::try_parse_from(["t", "--docker", "localhost:5000/x:y"]).unwrap();
        assert_eq!(
            parsed.args.result_reference().unwrap().as_str(),
            "localhost:5000/x:y"
        );
    }

    #[test]
    fn explicit_tag_overrides_the_docker_source() {
        for tag_flag in ["--tag", "-t"] {
            let parsed =
                TestCli::try_parse_from(["t", "--docker", "src:dev", tag_flag, "dst:dev"]).unwrap();
            assert_eq!(parsed.args.result_reference().unwrap().as_str(), "dst:dev");
        }
    }

    #[test]
    fn a_docker_source_that_cannot_be_a_result_reference_needs_an_explicit_tag() {
        // Docker's own source grammar is wider than a mutable result
        // reference; neither spelling is a destination.
        for source in [
            format!("app@sha256:{}", "a".repeat(64)),
            "./local-rootfs".to_string(),
        ] {
            let parsed = TestCli::try_parse_from(["t", "--docker", &source]).unwrap();
            let error = parsed.args.result_reference().err().unwrap().to_string();
            assert!(
                error.starts_with(INFERRED_REFERENCE_REASON)
                    && error.contains("Pass an explicit mutable --tag REF"),
                "{error}"
            );
            assert!(!error.contains(&source), "{error}");
            // The same source is still a valid Docker source with a target.
            let with_tag =
                TestCli::try_parse_from(["t", "--docker", &source, "--tag", "app:dev"]).unwrap();
            assert_eq!(
                with_tag.args.result_reference().unwrap().as_str(),
                "app:dev"
            );
        }
    }

    #[test]
    fn an_archive_without_a_tag_is_an_internal_invariant_not_a_panic() {
        let args = Args {
            tag: None,
            source: SourceArgs {
                docker: None,
                input: Some(PathBuf::from("image.tar")),
            },
        };
        let error = args.result_reference().err().unwrap().to_string();
        assert!(error.contains("internal error"), "{error}");
    }
}
