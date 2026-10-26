//! `agent-vm image build` — explicitly build a user Dockerfile and import the result
//! into the local image cache (#260).
//!
//! It does **not** choose, adopt or
//! boot an image: it exports one anonymous OCI archive with `docker buildx
//! build`, then hands that archive to the native importer under `--tag` (plus
//! any names the archive itself carries; see [`crate::image_publish`]). Running
//! the result is a separate `agent-vm --image REF shell` operation (see
//! CONTEXT.md → *Boot image* / *Launcher*).
//!
//! ```text
//! docker buildx build            (Docker owns Dockerfile/FROM/layers/cache)
//!   --platform linux/<host>      (host architecture, even on macOS)
//!   --output type=oci,dest=-     (anonymous single image; no Docker -t)
//!         │  stdout → private 0600 file under MSB_HOME/tmp
//!         ▼
//! microsandbox_image::load_archive(cache, archive, tags=[result])
//!         │  materializes content, publishes --tag (restored on failure)
//!         ▼
//! result ref is launchable via `agent-vm --image result shell`
//! ```
//!
//! Publication lives in [`crate::image_publish`].

use std::ffi::OsString;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::Stdio;

use crate::image_publish::{ImageTarget, ResultReference};
use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use crate::config::escape_str;

/// The fixed hint appended when Docker itself cannot be run. OCI export support
/// varies by buildx driver; a classic image-store driver may reject it, while an
/// isolated `docker-container` builder supports the export but cannot always
/// resolve local-daemon-only `FROM` tags. agent-vm never changes or creates a
/// builder for the user.
const DOCKER_STAGE_HINT: &str = "\
this needs a working Docker with buildx, and a builder that supports `--output \
type=oci` (select one explicitly with --builder). To use images that only exist \
in the local Docker daemon, build externally and import them with \
`agent-vm image import --docker REF --tag REF`";

#[derive(ClapArgs)]
pub(crate) struct Args {
    /// Import the built image under this reference in agent-vm's own image
    /// cache — not a Docker-store tag. The reference is mutable: it names the
    /// result a later build or import replaces.
    #[arg(short = 't', long, value_name = "REF")]
    tag: ResultReference,

    /// Dockerfile to build; resolved by Docker relative to the current
    /// directory. Defaults to Docker's own lookup in the context.
    #[arg(short = 'f', long = "file", value_name = "DOCKERFILE")]
    dockerfile: Option<PathBuf>,

    /// Set a build-time variable (`KEY[=VALUE]`), passed verbatim to Docker.
    /// A bare `KEY` reads the host environment as Docker normally does.
    #[arg(long = "build-arg", value_name = "KEY[=VALUE]")]
    build_args: Vec<OsString>,

    /// Build only up to this Dockerfile stage.
    #[arg(long, value_name = "STAGE")]
    target: Option<OsString>,

    /// Buildx builder instance to use for this build.
    #[arg(long, value_name = "NAME")]
    builder: Option<OsString>,

    /// Always attempt to pull newer base images.
    #[arg(long)]
    pull: bool,

    /// Do not use Docker's builder cache.
    #[arg(long = "no-cache")]
    no_cache: bool,

    /// Buildx progress output mode (`auto`, `plain`, `tty`, `rawjson`).
    #[arg(long, value_name = "MODE")]
    progress: Option<OsString>,

    /// Build context path. Passed to Docker untouched.
    #[arg(value_name = "CONTEXT", default_value = ".")]
    context: OsString,
}

/// Build the user's Dockerfile and import the result under `--tag`. Returns the
/// process exit code.
pub(crate) async fn run(args: Args) -> Result<i32> {
    let target = ImageTarget::resolve().await?;
    let staging = target.stage()?;
    let exit = export_archive(&args, staging.writer()?).await?;
    if exit != 0 {
        // A nonzero exporter status is a failure even if complete bytes were
        // written: never import an archive from a command that reported
        // failure. No retry.
        let _ = writeln!(
            std::io::stderr(),
            "docker buildx build failed (exit {exit}); the build result was not imported; {DOCKER_STAGE_HINT}"
        );
        return Ok(exit);
    }

    target
        .publish(staging.path(), &args.tag)
        .await
        .context("importing build result")?;
    let shown = args.tag.shell_arg();
    let shell_note = crate::shell::note_parenthetical(&[&shown]);
    let _ = writeln!(
        std::io::stdout(),
        "Imported build result as {shown}; launch it with `--image {shown}`{shell_note}"
    );
    Ok(0)
}

/// Run `docker buildx build …` with the archive file as its stdout. Inherits
/// stdin (native Dockerfile/context input) and stderr (live build progress).
async fn export_archive(args: &Args, archive: std::fs::File) -> Result<i32> {
    let stdout = Stdio::from(archive);
    let status = build_command(args)
        .stdin(Stdio::inherit())
        .stdout(stdout)
        .stderr(Stdio::inherit())
        .status()
        .await
        .with_context(|| {
            format!(
                "running `docker buildx build` for --tag {}; {DOCKER_STAGE_HINT}",
                escape_str(args.tag.as_str())
            )
        })?;
    Ok(crate::msb_cmd::exit_code_from_status(status))
}

/// `docker buildx build` with agent-vm's bounded option surface plus the flags
/// that make the output one anonymous host-platform OCI image. Values cross
/// `Command::arg`, never a shell.
///
/// Deliberately no Docker `-t`: the result reference is supplied only to the
/// importer's tags, so there is one image and no Docker-store alias.
fn build_command(args: &Args) -> tokio::process::Command {
    let mut command = tokio::process::Command::new("docker");
    command.args(["buildx", "build"]);
    if let Some(builder) = &args.builder {
        command.arg("--builder").arg(builder);
    }
    if let Some(dockerfile) = &args.dockerfile {
        command.arg("-f").arg(dockerfile);
    }
    for build_arg in &args.build_args {
        command.arg("--build-arg").arg(build_arg);
    }
    if let Some(target) = &args.target {
        command.arg("--target").arg(target);
    }
    if args.pull {
        command.arg("--pull");
    }
    if args.no_cache {
        command.arg("--no-cache");
    }
    if let Some(progress) = &args.progress {
        command.arg("--progress").arg(progress);
    }
    command
        .arg("--platform")
        .arg(host_linux_platform())
        // Disable attestations so the export is one runnable image rather than
        // an index with auxiliary attestation manifests the importer would have
        // to ignore.
        .arg("--provenance=false")
        .arg("--sbom=false")
        // `dest=-` avoids CSV quoting problems with commas / non-UTF-8 staging
        // paths in `--output type=oci,dest=<path>`.
        .arg("--output")
        .arg("type=oci,dest=-")
        .arg(&args.context);
    command
}

/// The Linux platform Docker should export for: the host architecture, even on
/// macOS (the guest is always Linux). Derived from the runtime's own mapping so
/// there is no second architecture table.
fn host_linux_platform() -> String {
    let platform = microsandbox_image::Platform::host_linux();
    format!("{}/{}", platform.os, platform.arch)
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

    fn parse(argv: &[&str]) -> Result<Args, clap::Error> {
        TestCli::try_parse_from(argv).map(|cli| cli.args)
    }

    // -- CLI surface -------------------------------------------------------

    #[test]
    fn tag_is_required() {
        assert!(parse(&["t"]).is_err());
        assert!(parse(&["t", "ctx"]).is_err());
    }

    #[test]
    fn defaults_are_a_dot_context_and_no_optional_flags() {
        let args = parse(&["t", "--tag", "my-app:dev"]).expect("minimal invocation parses");
        assert_eq!(args.context, OsString::from("."));
        assert!(args.dockerfile.is_none());
        assert!(args.build_args.is_empty());
        assert!(args.target.is_none());
        assert!(args.builder.is_none());
        assert!(!args.pull);
        assert!(!args.no_cache);
        assert!(args.progress.is_none());
    }

    #[test]
    fn out_of_surface_options_are_usage_errors() {
        for argv in [
            vec!["t", "--tag", "a:1", "--platform", "linux/amd64"],
            vec!["t", "--tag", "a:1", "--output", "type=docker"],
            vec!["t", "--tag", "a:1", "--load"],
            vec!["t", "--tag", "a:1", "--push"],
            vec!["t", "--tag", "a:1", "ctx-a", "ctx-b"],
            vec!["t", "--tag", "a:1", "--unknown-flag"],
            vec!["t", "--tag", "a:1", "ctx", "--", "trailing"],
        ] {
            assert!(parse(&argv).is_err(), "{argv:?} must be a usage error");
        }
    }

    // -- command construction ---------------------------------------------

    fn argv_of(command: &tokio::process::Command) -> Vec<OsString> {
        command
            .as_std()
            .get_args()
            .map(|arg| arg.to_os_string())
            .collect()
    }

    #[test]
    fn owned_output_and_platform_flags_are_always_present() {
        let args = parse(&["t", "--tag", "a:1"]).expect("parses");
        let argv = argv_of(&build_command(&args));
        let render = |argv: &[OsString]| {
            argv.iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        };
        let rendered = render(&argv);

        assert_eq!(
            rendered
                .iter()
                .filter(|arg| arg.starts_with("linux/"))
                .count(),
            1,
            "exactly one host platform flag: {rendered:?}"
        );
        assert_eq!(
            rendered.iter().filter(|arg| **arg == "--platform").count(),
            1
        );
        assert!(rendered.iter().any(|arg| arg == "type=oci,dest=-"));
        assert!(rendered.iter().any(|arg| arg == "--provenance=false"));
        assert!(rendered.iter().any(|arg| arg == "--sbom=false"));
        // No output alias, no load/push, no injected base image.
        assert!(!rendered.iter().any(|arg| arg == "-t" || arg == "--tag"));
        assert!(
            !rendered
                .iter()
                .any(|arg| arg.contains("BASE_IMAGE") || arg.contains("type=docker"))
        );
    }

    #[test]
    fn optional_arguments_reach_docker_as_distinct_values() {
        let args = parse(&[
            "t",
            "--tag",
            "a:1",
            "-f",
            "Containerfile",
            "--build-arg",
            "A=one two",
            "--build-arg",
            "B=",
            "--build-arg",
            "C=a=b",
            "--target",
            "stage",
            "--builder",
            "mybuilder",
            "--pull",
            "--no-cache",
            "--progress",
            "plain",
            "the context",
        ])
        .expect("parses");
        let rendered: Vec<String> = argv_of(&build_command(&args))
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();

        assert_eq!(rendered[0..2], ["buildx", "build"]);
        assert!(rendered.contains(&"--builder".to_string()));
        assert!(rendered.contains(&"mybuilder".to_string()));
        assert!(rendered.windows(2).any(|w| w == ["-f", "Containerfile"]));
        assert!(
            rendered
                .windows(2)
                .any(|w| w == ["--build-arg", "A=one two"]),
            "a value with a space is one argv element: {rendered:?}"
        );
        assert!(rendered.windows(2).any(|w| w == ["--build-arg", "B="]));
        assert!(rendered.windows(2).any(|w| w == ["--build-arg", "C=a=b"]));
        assert!(rendered.windows(2).any(|w| w == ["--target", "stage"]));
        assert!(rendered.contains(&"--pull".to_string()));
        assert!(rendered.contains(&"--no-cache".to_string()));
        assert!(rendered.windows(2).any(|w| w == ["--progress", "plain"]));
        assert_eq!(rendered.last().unwrap(), "the context");
    }

    #[test]
    fn no_dockerfile_flag_when_the_option_is_omitted() {
        let args = parse(&["t", "--tag", "a:1"]).expect("parses");
        let rendered: Vec<String> = argv_of(&build_command(&args))
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert!(!rendered.contains(&"-f".to_string()));
    }

    #[test]
    fn platform_matches_the_running_host() {
        let expected = match std::env::consts::ARCH {
            "x86_64" => "linux/amd64",
            "aarch64" => "linux/arm64",
            other => panic!("unexpected test architecture {other}"),
        };
        assert_eq!(host_linux_platform(), expected);
    }
}
