//! `agent-vm image build` — explicitly build a user Dockerfile and import the result
//! into the local image cache (#260).
//!
//! It does **not** choose, adopt or boot an image, and the only record it changes
//! besides the cache is the invoking project's approval of its own `--tag` (#391): it exports
//! one anonymous OCI archive with `docker buildx build`, hands that archive to
//! the native importer under `--tag`, then approves the content it published.
//! Running the result is a separate `agent-vm --image REF shell` operation (see
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
//! read back (shared barrier, cache only) → approve --tag (stderr old/new)
//!         ▼
//! result ref is launchable via `agent-vm --image result shell`
//! ```
//!
//! Publication lives in [`crate::image_publish`]; the approval of its result in
//! [`crate::image_pin::approve_published`]. The launch build
//! ([`crate::launch_build`]) reuses this export with null stdin, after its
//! [`probe`] (ADR-0071).

use std::ffi::{OsStr, OsString};
use std::io::Write as _;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use crate::image_publish::{ImageTarget, PublishPurpose, ResultReference};
use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use clap::builder::TypedValueParser as _;
use vstd::prelude::*;

use crate::config::escape_str;
// One name for Docker's reported manifest digest across the crate: the same type
// `image_pin` calls `ManifestDigest`.
use crate::image_acquire::ValidatedDigest as ManifestDigest;

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

/// One OCI archive on stdout. `dest=-` avoids CSV quoting problems with commas /
/// non-UTF-8 staging paths in `type=oci,dest=<path>`.
const EXPORT_OUTPUT: &str = "type=oci,dest=-";

/// The launch-build probe (ADR-0071). `store=false` with no name writes no
/// Docker-store image; `oci-mediatypes=true` makes the docker driver report the
/// OCI manifest digest the export writes (without it, that driver reports a
/// Docker-format manifest's digest).
const PROBE_OUTPUT: &str = "type=image,oci-mediatypes=true,store=false";

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

    #[command(flatten)]
    options: BuildOptions,

    /// Build context path. Passed to Docker untouched.
    #[arg(value_name = "CONTEXT", default_value = ".")]
    context: OsString,
}

/// The user-tunable part of `docker buildx build`. A launch build uses the
/// default (none): options belong to `image build` (ADR-0061).
#[derive(ClapArgs, Default)]
pub(crate) struct BuildOptions {
    /// Set a build-time variable (`KEY[=VALUE]`), passed verbatim to Docker.
    /// A bare `KEY` reads the host environment as Docker normally does.
    #[arg(long = "build-arg", value_name = "KEY[=VALUE]")]
    pub(crate) build_args: Vec<OsString>,

    /// Add a named build context (`NAME=PATH`) the Dockerfile can read with
    /// `FROM`, `COPY --from` or `RUN --mount=from`; passed verbatim to Docker.
    #[arg(
        long = "build-context",
        value_name = "NAME=PATH",
        value_parser = clap::builder::OsStringValueParser::new().try_map(BuildContext::parse)
    )]
    pub(crate) build_contexts: Vec<BuildContext>,

    /// Build only up to this Dockerfile stage.
    #[arg(long, value_name = "STAGE")]
    pub(crate) target: Option<OsString>,

    /// Buildx builder instance to use for this build.
    #[arg(long, value_name = "NAME")]
    pub(crate) builder: Option<OsString>,

    /// Always attempt to pull newer base images.
    #[arg(long)]
    pub(crate) pull: bool,

    /// Do not use Docker's builder cache.
    #[arg(long = "no-cache")]
    pub(crate) no_cache: bool,

    /// Buildx progress output mode (`auto`, `plain`, `tty`, `rawjson`).
    #[arg(long, value_name = "MODE")]
    pub(crate) progress: Option<OsString>,
}

/// One `--build-context NAME=PATH` value, accepted only in that shape.
///
/// agent-vm checks just the shape it documents — a `=` with something on both
/// sides — because a value without one can only ever be a Docker error. NAME's
/// grammar (an image reference Docker normalizes, so `alpine` and
/// `docker.io/library/alpine` are one name) and PATH's forms (a local
/// directory, `docker-image://`, `oci-layout://`, a URL) stay Docker's: a copy
/// of either would be a second grammar that drifts. The original bytes are
/// kept, so non-UTF-8 values reach Docker as `--build-arg` values do.
///
/// Every accepted value is forwarded; agent-vm does not read the Dockerfile to
/// prove it is used. BuildKit silently ignores an unreferenced context, and
/// deciding "referenced" means Docker's whole Dockerfile and frontend grammar.
#[derive(Clone, Debug)]
pub(crate) struct BuildContext(OsString);

impl BuildContext {
    /// The measurement half of the contracted decision (ADR-0018): the first
    /// `=` — Docker splits there too, and a reference cannot hold one, so any
    /// later `=` belongs to PATH — reduced to the three facts the kernel reads.
    fn parse(raw: OsString) -> std::result::Result<Self, BuildContextError> {
        let bytes = raw.as_bytes();
        let separator = bytes.iter().position(|&byte| byte == b'=');
        let facts = BuildContextFacts {
            has_separator: separator.is_some(),
            name_nonempty: separator.is_some_and(|index| index > 0),
            path_nonempty: separator.is_some_and(|index| index + 1 < bytes.len()),
        };
        if build_context_is_acceptable(facts) {
            return Ok(Self(raw));
        }
        // The rejection *reason* is a diagnostic derived from the same
        // measurement, not a second boundary decision.
        Err(match separator {
            None => BuildContextError::MissingSeparator,
            Some(0) => BuildContextError::EmptyName,
            Some(_) => BuildContextError::EmptyPath,
        })
    }

    fn as_os_str(&self) -> &OsStr {
        &self.0
    }
}

/// Why a `--build-context` value is not `NAME=PATH`. Names no value: clap
/// already renders the rejected token beside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BuildContextError {
    MissingSeparator,
    EmptyName,
    EmptyPath,
}

impl std::fmt::Display for BuildContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::MissingSeparator => "expected NAME=PATH",
            Self::EmptyName => "NAME is empty; expected NAME=PATH",
            Self::EmptyPath => "PATH is empty; expected NAME=PATH",
        })
    }
}

impl std::error::Error for BuildContextError {}

verus! {

/// The three already-measured facts the `--build-context` decision reads. Named
/// fields rather than adjacent `bool` parameters, so an argument swap cannot
/// invert the decision.
pub(crate) struct BuildContextFacts {
    pub(crate) has_separator: bool,
    pub(crate) name_nonempty: bool,
    pub(crate) path_nonempty: bool,
}

/// The `NAME=PATH` acceptance decision, contracted (ADR-0018): accept **iff**
/// there is a `=` with at least one byte on each side. Docker's context-name
/// grammar, PATH's forms and what the build does with an accepted value are not
/// re-decided here; `build_command` passes the original bytes.
pub(crate) fn build_context_is_acceptable(facts: BuildContextFacts) -> (accepted: bool)
    ensures
        accepted == (facts.has_separator && facts.name_nonempty && facts.path_nonempty),
{ facts.has_separator && facts.name_nonempty && facts.path_nonempty }

} // verus!

/// Docker's inputs for one anonymous host-platform OCI export.
pub(crate) struct DockerBuild<'a> {
    pub(crate) dockerfile: Option<&'a OsStr>,
    pub(crate) context: &'a OsStr,
    pub(crate) options: &'a BuildOptions,
}

/// Where Docker sends the built image: the only part of the argv the launch-build
/// probe and the export do not share (ADR-0071 §4).
#[derive(Clone, Copy)]
enum Output<'a> {
    /// One OCI archive on stdout.
    OciArchive,
    /// The launch-build probe: no image written anywhere, the manifest digest in
    /// `metadata`.
    Probe { metadata: &'a Path },
}

/// Build the user's Dockerfile and import the result under `--tag`. Returns the
/// process exit code.
pub(crate) async fn run(args: Args, project: Result<crate::project::ProjectDir>) -> Result<i32> {
    // `main`'s one capture (ADR-0073 D5), taken before the build: this command
    // approves its result under the project it started in, however Docker
    // changes what `getcwd` reports, and a second read could name a second one.
    let project = project?;
    let target = ImageTarget::resolve().await?;
    // HOME and a readable pin store are checked before Docker runs or the
    // archive is published (R9): a damaged store must not cost a build.
    let scope = crate::image_pin::publication_preflight(&args.tag, &project)?;
    let staging = target.stage()?;
    let build = DockerBuild {
        dockerfile: args.dockerfile.as_deref().map(Path::as_os_str),
        context: &args.context,
        options: &args.options,
    };
    let exit = export_archive(&build, staging.writer()?, Stdio::inherit())
        .await
        .with_context(|| {
            format!(
                "running `docker buildx build` for --tag {}; {DOCKER_STAGE_HINT}",
                escape_str(args.tag.as_str())
            )
        })?;
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

    let published = target
        .publish(staging.path(), &args.tag, PublishPurpose::Approval)
        .await
        .context("importing build result")?;
    // The command that supplied the bytes is the consent (#391). The read-back
    // runs only now, after `publish`'s exclusive barrier is released.
    #[allow(clippy::disallowed_methods)]
    // `image build --tag` names the result it approves (#391).
    let report = crate::image_pin::approve_published(&published, &scope).await?;
    // Committed. The completion notice and its own I/O are reporting, not part
    // of the commit: the command exits 0 either way.
    let shown = args.tag.shell_arg();
    let shell_note = crate::shell::note_parenthetical(&[&shown]);
    let notice =
        format!("Imported build result as {shown}; launch it with `--image {shown}`{shell_note}");
    Ok(crate::image_pin::finish_publication(report, Some(notice)))
}

/// Run `docker buildx build …` with `archive` as stdout and stderr inherited.
/// `stdin` is the caller's decision: `image build` inherits it (Docker's own
/// `-f -`/context-on-stdin), while a launch build passes `Stdio::null()` so a
/// direct command's input is never consumed (ADR-0061 §9, ADR-0052).
pub(crate) async fn export_archive(
    build: &DockerBuild<'_>,
    archive: std::fs::File,
    stdin: Stdio,
) -> std::io::Result<i32> {
    run_status(
        build_command(build, Output::OciArchive),
        stdin,
        Stdio::from(archive),
    )
    .await
}

/// Run the launch-build probe: the build itself, with no image written anywhere
/// and Docker's reported manifest digest in `metadata` (ADR-0071). stdin and
/// stdout are `/dev/null`; stderr is the user's.
///
/// A non-zero exit is Docker's verdict on the build and the caller's failure to
/// report (ADR-0061 §11). Only after a zero exit does the metadata matter.
pub(crate) async fn probe(build: &DockerBuild<'_>, metadata: &Path) -> std::io::Result<ProbeRun> {
    let exit = run_status(
        build_command(build, Output::Probe { metadata }),
        // ADR-0061 §9: a launch build never consumes the guest's input.
        Stdio::null(),
        // The image exporter writes nothing there; the launcher's stdout stays the
        // guest's (R18).
        Stdio::null(),
    )
    .await?;
    if exit != 0 {
        return Ok(ProbeRun::Failed(exit));
    }
    let reported = std::fs::read(metadata)
        .map_err(ProbeUnreported::Unreadable)
        .and_then(|bytes| reported_digest(&bytes));
    Ok(ProbeRun::Built(reported))
}

/// Run `command` with the caller's `stdin`/`stdout` and stderr inherited,
/// returning Docker's exit status. The probe and the export differ only in the
/// descriptors and the output group, so neither can drift on how the child is
/// wired.
async fn run_status(
    mut command: tokio::process::Command,
    stdin: Stdio,
    stdout: Stdio,
) -> std::io::Result<i32> {
    let status = command
        .stdin(stdin)
        .stdout(stdout)
        .stderr(Stdio::inherit())
        .status()
        .await?;
    Ok(crate::msb_cmd::exit_code_from_status(status))
}

/// Docker's verdict on the launch-build probe. A nonzero exit is the build's own
/// failure (ADR-0061 §11): Docker reports a failing step and a rejected exporter
/// alike.
#[derive(Debug)]
pub(crate) enum ProbeRun {
    Failed(i32),
    /// Built; what the metadata said. Only `Ok` can lead to skipping the export.
    Built(Result<ManifestDigest, ProbeUnreported>),
}

/// Why a successful probe named no usable digest. Rendered only in a debug line.
#[derive(Debug)]
pub(crate) enum ProbeUnreported {
    /// The metadata file is missing or unreadable.
    Unreadable(std::io::Error),
    /// Not JSON, or `containerimage.digest` is not a string.
    Malformed(serde_json::Error),
    /// The key is absent.
    NoDigest,
    /// [`ManifestDigest::parse`] refused it.
    InvalidDigest,
}

impl std::fmt::Display for ProbeUnreported {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable(error) => {
                write!(
                    formatter,
                    "the probe metadata file could not be read: {error}"
                )
            }
            Self::Malformed(error) => {
                write!(
                    formatter,
                    "the probe metadata is not the expected build record: {error}"
                )
            }
            Self::NoDigest => {
                write!(
                    formatter,
                    "the probe metadata names no containerimage.digest"
                )
            }
            Self::InvalidDigest => write!(
                formatter,
                "the probe metadata's containerimage.digest is not a usable digest"
            ),
        }
    }
}

/// The one field of Docker's `--metadata-file` this launcher reads. Every other
/// key (`buildx.build.provenance`, `containerimage.descriptor`, `image.name`) is
/// ignored by serde's default.
#[derive(serde::Deserialize)]
struct ProbeMetadata {
    #[serde(rename = "containerimage.digest")]
    digest: Option<String>,
}

/// The pure half: the digest a probe's metadata bytes report.
fn reported_digest(metadata: &[u8]) -> Result<ManifestDigest, ProbeUnreported> {
    let parsed: ProbeMetadata =
        serde_json::from_slice(metadata).map_err(ProbeUnreported::Malformed)?;
    let digest = parsed.digest.ok_or(ProbeUnreported::NoDigest)?;
    ManifestDigest::parse(&digest).map_err(|_| ProbeUnreported::InvalidDigest)
}

/// `docker buildx build` with agent-vm's bounded option surface plus the flags
/// that make the output one anonymous host-platform OCI image. Values cross
/// `Command::arg`, never a shell. `output` is the one thing that varies between
/// the launch-build probe and the export (ADR-0071 §4).
///
/// Deliberately no Docker `-t`: the result reference is supplied only to the
/// importer's tags, so there is one image and no Docker-store alias.
fn build_command(build: &DockerBuild<'_>, output: Output<'_>) -> tokio::process::Command {
    let mut command = tokio::process::Command::new("docker");
    command.args(["buildx", "build"]);
    if let Some(builder) = &build.options.builder {
        command.arg("--builder").arg(builder);
    }
    if let Some(dockerfile) = build.dockerfile {
        command.arg("-f").arg(dockerfile);
    }
    for build_arg in &build.options.build_args {
        command.arg("--build-arg").arg(build_arg);
    }
    for build_context in &build.options.build_contexts {
        command
            .arg("--build-context")
            .arg(build_context.as_os_str());
    }
    if let Some(target) = &build.options.target {
        command.arg("--target").arg(target);
    }
    if build.options.pull {
        command.arg("--pull");
    }
    if build.options.no_cache {
        command.arg("--no-cache");
    }
    if let Some(progress) = &build.options.progress {
        command.arg("--progress").arg(progress);
    }
    command
        .arg("--platform")
        .arg(host_linux_platform())
        // Disable attestations so the export is one runnable image rather than
        // an index with auxiliary attestation manifests the importer would have
        // to ignore.
        .arg("--provenance=false")
        .arg("--sbom=false");
    match output {
        Output::OciArchive => {
            command.arg("--output").arg(EXPORT_OUTPUT);
        }
        Output::Probe { metadata } => {
            // `--metadata-file` takes a plain path, so a comma or a non-UTF-8
            // staging path needs no CSV handling: it is one `OsStr` argument.
            command
                .arg("--output")
                .arg(PROBE_OUTPUT)
                .arg("--metadata-file")
                .arg(metadata);
        }
    }
    command.arg(build.context);
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
    use std::os::unix::ffi::OsStringExt as _;

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
        assert!(args.options.build_args.is_empty());
        assert!(args.options.build_contexts.is_empty());
        assert!(args.options.target.is_none());
        assert!(args.options.builder.is_none());
        assert!(!args.options.pull);
        assert!(!args.options.no_cache);
        assert!(args.options.progress.is_none());
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

    /// Every value following a `--build-context` flag, in argv order. The whole
    /// sequence is the oracle: a presence-only check cannot see an extra pair
    /// or a deduplicated one.
    fn build_context_values(argv: &[OsString]) -> Vec<OsString> {
        argv.windows(2)
            .filter(|window| window[0] == "--build-context")
            .map(|window| window[1].clone())
            .collect()
    }

    fn docker_build_from_args<'a>(args: &'a Args) -> DockerBuild<'a> {
        DockerBuild {
            dockerfile: args.dockerfile.as_deref().map(Path::as_os_str),
            context: &args.context,
            options: &args.options,
        }
    }

    #[test]
    fn owned_output_and_platform_flags_are_always_present() {
        let args = parse(&["t", "--tag", "a:1"]).expect("parses");
        let build = docker_build_from_args(&args);
        let argv = argv_of(&build_command(&build, Output::OciArchive));
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
            "--build-context",
            "bin=out dir",
            "--build-context",
            "y=a=b",
            "--build-context",
            "alpine=docker-image://alpine:3.20",
            "--build-context",
            "x=a",
            "--build-context",
            "x=b",
            "--build-context",
            "alpine=a",
            "--build-context",
            "docker.io/library/alpine:latest=b",
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
        let build = docker_build_from_args(&args);
        let rendered: Vec<String> = argv_of(&build_command(&build, Output::OciArchive))
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
        let argv = argv_of(&build_command(&build, Output::OciArchive));
        assert_eq!(
            build_context_values(&argv),
            vec![
                OsString::from("bin=out dir"),
                OsString::from("y=a=b"),
                OsString::from("alpine=docker-image://alpine:3.20"),
                OsString::from("x=a"),
                OsString::from("x=b"),
                OsString::from("alpine=a"),
                OsString::from("docker.io/library/alpine:latest=b"),
            ],
            "the typed sequence, forwarded once each and in order: {rendered:?}"
        );
        assert!(rendered.contains(&"--pull".to_string()));
        assert!(rendered.contains(&"--no-cache".to_string()));
        assert!(rendered.windows(2).any(|w| w == ["--progress", "plain"]));
        assert_eq!(rendered.last().unwrap(), "the context");
    }

    #[test]
    fn no_dockerfile_flag_when_the_option_is_omitted() {
        let args = parse(&["t", "--tag", "a:1"]).expect("parses");
        let build = docker_build_from_args(&args);
        let rendered: Vec<String> = argv_of(&build_command(&build, Output::OciArchive))
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert!(!rendered.contains(&"-f".to_string()));
    }

    #[test]
    fn launch_build_argv_has_only_owned_flags_plus_file_and_context() {
        let options = BuildOptions::default();
        let build = DockerBuild {
            dockerfile: Some(OsStr::new("/abs/Dockerfile")),
            context: OsStr::new("/abs"),
            options: &options,
        };
        // Both runs of a launch build carry only these, plus their own output group.
        for argv in [
            argv_of(&build_command(&build, Output::OciArchive)),
            argv_of(&build_command(
                &build,
                Output::Probe {
                    metadata: Path::new("/abs/probe.json"),
                },
            )),
        ] {
            let rendered: Vec<String> = argv
                .iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect();
            assert_eq!(rendered[0..2], ["buildx", "build"]);
            assert_eq!(
                rendered
                    .windows(2)
                    .find(|w| w[0] == "-f")
                    .map(|w| w[1].as_str()),
                Some("/abs/Dockerfile")
            );
            assert_eq!(rendered.last().map(String::as_str), Some("/abs"));
            assert!(!rendered.iter().any(|arg| arg == "-t"
                || arg == "--tag"
                || arg == "--builder"
                || arg == "--build-context"
                || arg == "--progress"));
        }
    }

    /// The one contiguous occurrence of `group` in `argv`, as an index.
    fn group_at(argv: &[OsString], group: &[OsString]) -> usize {
        let positions: Vec<usize> = (0..=argv.len().saturating_sub(group.len()))
            .filter(|&index| argv[index..index + group.len()] == *group)
            .collect();
        assert_eq!(
            positions.len(),
            1,
            "the group {group:?} must occur exactly once in {argv:?}"
        );
        positions[0]
    }

    /// `argv` with its one `group` removed, plus where the group was.
    fn without_group(argv: &[OsString], group: &[OsString]) -> (Vec<OsString>, usize) {
        let index = group_at(argv, group);
        let mut rest = argv.to_vec();
        rest.drain(index..index + group.len());
        (rest, index)
    }

    fn group(items: &[&str]) -> Vec<OsString> {
        items.iter().map(OsString::from).collect()
    }

    /// The launch-build probe and the export differ in exactly one place: the
    /// output group (R2, Q10, ADR-0071 §4). Every other flag — builder, build
    /// args, contexts, target, pull, no-cache, progress, platform, provenance,
    /// SBOM, file, context — is shared because it comes from one function.
    #[test]
    fn probe_and_export_differ_only_in_their_output_group() {
        const METADATA: &str = "/tmp/lb/probe.json";
        let launch_options = BuildOptions::default();
        let launch = DockerBuild {
            dockerfile: Some(OsStr::new("/abs/Dockerfile")),
            context: OsStr::new("/abs"),
            options: &launch_options,
        };
        let full_args = parse(&[
            "t",
            "--tag",
            "a:1",
            "-f",
            "Containerfile",
            "--build-arg",
            "A=one two",
            "--build-context",
            "bin=out dir",
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
        let full = docker_build_from_args(&full_args);

        for (name, build) in [("launch default", &launch), ("every option", &full)] {
            let export = argv_of(&build_command(build, Output::OciArchive));
            let probe = argv_of(&build_command(
                build,
                Output::Probe {
                    metadata: Path::new(METADATA),
                },
            ));
            let (export_rest, export_at) =
                without_group(&export, &group(&["--output", EXPORT_OUTPUT]));
            let (probe_rest, probe_at) = without_group(
                &probe,
                &group(&["--output", PROBE_OUTPUT, "--metadata-file", METADATA]),
            );
            assert_eq!(
                export_rest, probe_rest,
                "{name}: the two runs share the whole argv apart from their output group"
            );
            assert_eq!(
                export_at, probe_at,
                "{name}: the output group sits at the same position"
            );
            assert_eq!(
                export_at,
                export_rest.len() - 1,
                "{name}: the output group is immediately before the context: {export_rest:?}"
            );
        }
    }

    /// The probe writes no image and hands Docker the metadata path as one whole
    /// argv element, however odd that path is.
    #[test]
    fn probe_output_writes_no_image_and_passes_the_metadata_path_whole() {
        let options = BuildOptions::default();
        let build = DockerBuild {
            dockerfile: Some(OsStr::new("/abs/Dockerfile")),
            context: OsStr::new("/abs"),
            options: &options,
        };
        for raw in [
            OsString::from("/m d,ir/probe.json"),
            OsString::from_vec(b"/m\x80dir/probe.json".to_vec()),
        ] {
            let metadata = PathBuf::from(&raw);
            let argv = argv_of(&build_command(
                &build,
                Output::Probe {
                    metadata: &metadata,
                },
            ));
            let output = vec![
                OsString::from("--output"),
                OsString::from(PROBE_OUTPUT),
                OsString::from("--metadata-file"),
                raw.clone(),
            ];
            let (rest, at) = without_group(&argv, &output);
            assert_eq!(
                at,
                rest.len() - 1,
                "{raw:?}: the probe group precedes the context"
            );
            let rendered: Vec<String> = argv
                .iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect();
            let output_value = &rendered[at + 1];
            assert!(
                output_value.contains("store=false"),
                "{raw:?}: the probe writes no Docker-store image: {output_value}"
            );
            assert!(
                output_value.contains("oci-mediatypes=true"),
                "{raw:?}: the probe reports the OCI manifest digest: {output_value}"
            );
            for absent in ["-t", "--tag", "--load", "--push"] {
                assert!(
                    !argv.iter().any(|arg| arg == absent),
                    "{raw:?}: a probe names no destination ({absent}): {rendered:?}"
                );
            }
            for absent in ["type=docker", "name="] {
                assert!(
                    !rendered.iter().any(|arg| arg.contains(absent)),
                    "{raw:?}: a probe has no {absent}: {rendered:?}"
                );
            }
        }
    }

    /// Only the documented key counts, and no odd JSON panics.
    #[test]
    fn reported_digest_reads_only_containerimage_digest() {
        let digest = format!("sha256:d435b1ad{}", "0".repeat(56));
        // A trimmed metadata file of the shape Docker writes: unknown keys are
        // ignored, including the descriptor's own digest.
        let colima = format!(
            r#"{{
  "buildx.build.provenance": {{"buildType": "https://mobyproject.org/buildkit@v1", "materials": []}},
  "buildx.build.ref": "colima/colima/abc123",
  "containerimage.config.digest": "{digest}",
  "containerimage.descriptor": {{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "{digest}", "size": 1583, "platform": {{"architecture": "arm64", "os": "linux"}}}},
  "containerimage.digest": "{digest}",
  "image.name": "moby-dangling@{digest}"
}}"#
        );
        assert_eq!(
            reported_digest(colima.as_bytes()).unwrap().as_str(),
            digest,
            "the documented key, whatever else the record holds"
        );

        // Uppercase hex is folded, as every other digest path does.
        let upper = format!(
            "{{\"containerimage.digest\":\"sha256:{}\"}}",
            "AB".repeat(32)
        );
        assert_eq!(
            reported_digest(upper.as_bytes()).unwrap().as_str(),
            format!("sha256:{}", "ab".repeat(32))
        );

        let descriptor_only = format!(
            "{{\"containerimage.descriptor\":{{\"digest\":\"sha256:{}\"}}}}",
            "0".repeat(64)
        );
        let table: [(&[u8], &str, bool); 6] = [
            (b"{}", "no digest", false),
            (descriptor_only.as_bytes(), "descriptor only", false),
            (b"{\"containerimage.digest\":5}", "not a string", true),
            (b"[]", "not an object", true),
            (b"not json", "not JSON", true),
            (b"", "empty", true),
        ];
        for (bytes, why, malformed) in table {
            match reported_digest(bytes) {
                Err(ProbeUnreported::NoDigest) if !malformed => {}
                Err(ProbeUnreported::Malformed(_)) if malformed => {}
                other => panic!(
                    "{why}: expected {} , got {other:?}",
                    if malformed { "Malformed" } else { "NoDigest" }
                ),
            }
        }
        match reported_digest(b"{\"containerimage.digest\":\"sha256:abc\"}") {
            Err(ProbeUnreported::InvalidDigest) => {}
            other => panic!("a malformed digest is its own reason, got {other:?}"),
        }
    }

    // -- build contexts ----------------------------------------------------

    #[test]
    fn build_context_needs_a_name_and_a_path() {
        for (raw, reason) in [
            ("x", "expected NAME=PATH"),
            ("=p", "NAME is empty; expected NAME=PATH"),
            ("=", "NAME is empty; expected NAME=PATH"),
            ("n=", "PATH is empty; expected NAME=PATH"),
        ] {
            let error = match parse(&["t", "--tag", "a:1", "--build-context", raw]) {
                Ok(_) => panic!("{raw} must be a usage error"),
                Err(error) => error,
            };
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::ValueValidation,
                "{raw}"
            );
            assert_eq!(error.exit_code(), 2, "{raw}");
            let rendered = error.to_string();
            assert!(
                rendered.contains("--build-context <NAME=PATH>"),
                "{raw}: {rendered}"
            );
            assert!(rendered.contains(reason), "{raw}: {rendered}");
        }
        // A second `=` belongs to PATH, and a one-byte PATH is enough.
        for raw in ["a=b", "y==", "a==b"] {
            let args = parse(&["t", "--tag", "a:1", "--build-context", raw])
                .unwrap_or_else(|error| panic!("{raw} must be accepted: {error}"));
            assert_eq!(args.options.build_contexts.len(), 1, "{raw}");
        }
    }

    #[test]
    fn build_context_decision_table() {
        // The erased kernel over all eight fact rows: acceptance is exactly the
        // conjunction, so no row can lean on Docker's name or path grammar.
        for bits in 0..8 {
            let facts = BuildContextFacts {
                has_separator: bits & 1 != 0,
                name_nonempty: bits & 2 != 0,
                path_nonempty: bits & 4 != 0,
            };
            assert_eq!(
                build_context_is_acceptable(facts),
                bits == 7,
                "row {bits:03b}"
            );
        }
    }

    #[test]
    fn build_context_bytes_reach_docker_unjudged() {
        for raw in [
            OsString::from_vec(b"n\x80=p\x81".to_vec()),
            OsString::from("Bad Name=."),
        ] {
            let args = TestCli::try_parse_from([
                OsString::from("t"),
                OsString::from("--tag"),
                OsString::from("a:1"),
                OsString::from("--build-context"),
                raw.clone(),
            ])
            .unwrap_or_else(|error| panic!("{raw:?} must be accepted: {error}"))
            .args;
            let build = docker_build_from_args(&args);
            let argv = argv_of(&build_command(&build, Output::OciArchive));
            assert_eq!(
                build_context_values(&argv),
                vec![raw],
                "the identical bytes reach Docker"
            );
        }
    }

    #[test]
    fn usage_names_every_build_option() {
        use clap::CommandFactory as _;
        #[derive(Parser)]
        struct OptionsCli {
            #[command(flatten)]
            options: BuildOptions,
        }
        // USAGE.md is the canonical option surface (ADR-0035), and the
        // launch-build section enumerates what it lacks; both must name every flag.
        let usage = include_str!("../../../USAGE.md");
        let after = |marker: &str| &usage[usage.find(marker).expect(marker)..];
        let synopsis = {
            let block = after("The bounded option surface is:");
            &block[..block.find("\n```\n").expect("synopsis fence")]
        };
        let launch = {
            let block = after("- **No build options.**");
            &block[..block.find(';').expect("launch list end")]
        };
        for long in OptionsCli::command()
            .get_arguments()
            .filter_map(clap::Arg::get_long)
        {
            let flag = format!("--{long}");
            assert!(synopsis.contains(&flag), "USAGE synopsis lacks {flag}");
            assert!(
                launch.contains(&format!("`{flag}`")),
                "launch-build list lacks {flag}"
            );
        }
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
