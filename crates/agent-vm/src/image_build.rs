//! `agent-vm build` — explicitly build a user Dockerfile and import the result
//! into the local image cache (#260).
//!
//! This is the one place agent-vm runs Docker. It does **not** choose, adopt or
//! boot an image: it exports one anonymous OCI archive with `docker buildx
//! build`, then hands that archive to the native importer under the single
//! `--tag` result reference. Running the result is a separate `shell --image
//! REF` operation (see CONTEXT.md → *Boot image* / *Launcher*).
//!
//! ```text
//! docker buildx build            (Docker owns Dockerfile/FROM/layers/cache)
//!   --platform linux/<host>      (host architecture, even on macOS)
//!   --output type=oci,dest=-     (anonymous single image; no Docker -t)
//!         │  stdout → private 0600 file under MSB_HOME/tmp
//!         ▼
//! microsandbox_image::load_archive(cache, archive, tags=[result])
//!         │  materializes content, then atomically writes the reference
//!         ▼
//! result ref is launchable via `shell --image result`
//! ```
//!
//! # Why not shell out to `msb image load`?
//!
//! `msb` (and the SDK's `Image::load_local`) publish the cache reference first
//! and then persist the catalog row in the database as a **separate fallible
//! step** (`commands/image.rs`). A late database error could therefore report
//! failure *after* the result reference was already replaced. The native
//! importer used here materializes content before its atomic metadata rename,
//! and that rename is the last fallible operation — so a failure never adopts a
//! partial result. The trade-off is deliberate: the result is immediately
//! launchable from cache, but has no `msb image ls` row until a first launch
//! persists the cached metadata normally.
//!
//! # Why the ambient backend's cache, not `effective_cache_dir()`?
//!
//! The SDK resolves the same persisted/managed configuration that a launch
//! uses. `msb_install::effective_cache_dir()` ignores a **persisted** shared
//! redirect once `AGENT_VM_SHARE_MSB_CACHE` is unset, so it can point somewhere
//! a launch would not. Using [`microsandbox::backend::default_backend`] keeps
//! build and launch agreeing by construction.

use std::ffi::OsString;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context, Result, anyhow};
use clap::Args as ClapArgs;
use vstd::prelude::*;

use crate::boot_image::ImageRef;
use crate::config::escape_str;

/// The fixed reason a result reference is rejected when it is digest-pinned.
/// Names no value: the supplied text is untrusted input (see the parser).
const PINNED_RESULT_REFERENCE_REASON: &str = "\
--tag must name a mutable result reference (e.g. my-app:dev); a digest-pinned \
reference cannot be updated by a later build";

/// The fixed hint appended when Docker itself cannot be run. OCI export support
/// varies by buildx driver; a classic image-store driver may reject it, while an
/// isolated `docker-container` builder supports the export but cannot always
/// resolve local-daemon-only `FROM` tags. agent-vm never changes or creates a
/// builder for the user.
const DOCKER_STAGE_HINT: &str = "\
this needs a working Docker with buildx, and a builder that supports `--output \
type=oci` (select one explicitly with --builder). To use images that only exist \
in the local Docker daemon, build externally and import the finished archive with \
`docker image save` + `agent-vm msb image load`";

#[derive(ClapArgs)]
pub(crate) struct Args {
    /// Import the built image under this reference in agent-vm's own image
    /// cache — not a Docker-store tag. The reference is mutable: it names the
    /// result a later build replaces.
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

/// The `--tag` result reference. A distinct type from a launch `ImageRef` so a
/// digest-pinned value (valid for `--image`) is a compile-time-different,
/// parse-time-rejected value here.
#[derive(Clone)]
struct ResultReference(ImageRef);

impl std::str::FromStr for ResultReference {
    type Err = anyhow::Error;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        // Both facts are measured here and decided by the contracted kernel
        // (ADR-0018). `reference_has_digest` and `ImageRef::from_config` are the
        // trusted adapters to the native parsers; neither is a new OCI grammar.
        let parsed = ImageRef::from_config(raw);
        let config_reason = parsed.as_ref().err().copied();
        let has_digest = reference_has_digest(raw);
        let facts = ResultReferenceFacts {
            oci_acceptable: parsed.is_ok(),
            has_digest,
        };
        if !result_reference_is_acceptable(facts) {
            // Report which measured fact failed with a fixed reason that names
            // no value. clap still renders the *rejected token* it received
            // before this adapter runs (ordinary clap behavior).
            return Err(if has_digest {
                anyhow!(PINNED_RESULT_REFERENCE_REASON)
            } else {
                anyhow!(
                    "--tag {}",
                    config_reason.unwrap_or("must be an OCI image reference")
                )
            });
        }
        // The kernel accepted, so `oci_acceptable` held when measured from this
        // same `parsed`. Kept as an error rather than a panic.
        parsed.map(Self).map_err(|reason| anyhow!("--tag {reason}"))
    }
}

impl ResultReference {
    fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Does the native OCI parser read `raw` as a digest-pinned reference?
fn reference_has_digest(raw: &str) -> bool {
    raw.parse::<microsandbox_image::Reference>()
        .map(|reference| reference.digest().is_some())
        .unwrap_or(false)
}

/// Build the user's Dockerfile and import the result under `--tag`. Returns the
/// process exit code.
pub(crate) async fn run(args: Args) -> Result<i32> {
    // Guard the private DB before doing anything else, exactly like the launch
    // path: a build must not silently hand a future launch a DB it cannot open.
    crate::msb_preflight::ensure_db_not_ahead().await?;

    // The ambient backend is the same config resolution a launch uses. Resolve
    // it *after* main's prologue (which pinned MSB_HOME) and keep it alive to
    // read the cache directory. No image selection or default record is read.
    let backend = microsandbox::backend::default_backend();
    let cache_dir = backend
        .as_local()
        .ok_or_else(|| {
            anyhow!(
                "agent-vm build imports into the local image cache, but the resolved backend \
                 is not local; unset the cloud backend selection ({DOCKER_STAGE_HINT})"
            )
        })?
        .cache_dir();

    let msb_home = std::env::var_os("MSB_HOME").ok_or_else(|| {
        anyhow!(
            "MSB_HOME is not set; agent-vm's msb setup did not run before dispatch \
             (this is an internal invariant — `build` is not in the needs_msb_setup \
             exclusion list in main.rs)"
        )
    })?;

    let (_staging, archive_file, archive_path) = create_staging(Path::new(&msb_home))?;

    let exit = export_archive(&args, &archive_file).await?;
    // Drop our handle so the writer's bytes are visible to the importer before
    // it opens the archive path. No fsync/durability claim is made here.
    drop(archive_file);

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

    import_build_result(&cache_dir, &archive_path, &args.tag).await?;
    // `staging` is still alive here; it is removed on this scope's exit.

    // Best-effort completion notice. Publication already succeeded; a failed
    // stderr write must not turn success into failure.
    let _ = writeln!(
        std::io::stderr(),
        "Imported build result as {}; launch it with `--image {}`",
        escape_str(args.tag.as_str()),
        escape_str(args.tag.as_str()),
    );
    Ok(0)
}

/// Create the private staging directory under `MSB_HOME/tmp` and the 0600
/// archive file the exporter writes its stdout to.
///
/// Returns the directory owner (cleanup on drop), the open write handle, and
/// the archive path. The caller passes the handle to the exporter, drops it,
/// then hands the path to the importer while the directory is still alive.
fn create_staging(msb_home: &Path) -> Result<(tempfile::TempDir, std::fs::File, PathBuf)> {
    let tmp_root = msb_home.join("tmp");
    std::fs::create_dir_all(&tmp_root)
        .with_context(|| format!("creating staging root {}", tmp_root.display()))?;
    // Explicit permissions keep staging private even with a permissive umask.
    let directory = tempfile::Builder::new()
        .prefix("build-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(&tmp_root)
        .with_context(|| format!("creating build staging under {}", tmp_root.display()))?;
    let path = directory.path().join("result.tar");
    let archive = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("creating build archive {}", path.display()))?;
    Ok((directory, archive, path))
}

/// Run `docker buildx build …` with the archive file as its stdout. Inherits
/// stdin (native Dockerfile/context input) and stderr (live build progress).
async fn export_archive(args: &Args, archive: &std::fs::File) -> Result<i32> {
    let stdout = Stdio::from(
        archive
            .try_clone()
            .context("duplicating the staged archive handle for Docker's stdout")?,
    );
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

/// Import the completed archive under one reference. The cache directory is the
/// ambient backend's, so the result lands exactly where a launch looks.
async fn import_build_result(
    cache_dir: &Path,
    archive: &Path,
    result: &ResultReference,
) -> Result<()> {
    microsandbox_image::load_archive(
        cache_dir,
        archive,
        microsandbox_image::ImageLoadOptions {
            tags: vec![result.as_str().to_string()],
            progress: None,
        },
    )
    .await
    .context("importing build result")?;
    Ok(())
}

verus! {

/// The two already-measured facts the result-reference decision reads. Named
/// fields rather than adjacent `bool` parameters, so an argument swap cannot
/// invert the decision.
pub(crate) struct ResultReferenceFacts {
    pub(crate) oci_acceptable: bool,
    pub(crate) has_digest: bool,
}

/// The `--tag` acceptance decision, contracted (ADR-0018): accept **iff** the
/// config-image policy accepts the text and the native parser sees no digest.
/// Total over all four Boolean combinations; accepting never bypasses a check.
pub(crate) fn result_reference_is_acceptable(facts: ResultReferenceFacts) -> (accepted: bool)
    ensures
        accepted == (facts.oci_acceptable && !facts.has_digest),
        accepted ==> facts.oci_acceptable && !facts.has_digest,
{
    facts.oci_acceptable && !facts.has_digest
}

} // verus!

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

    // -- result-reference acceptance truth table --------------------------

    /// Every Boolean combination of the kernel, independent of any parser.
    #[test]
    fn acceptance_truth_table() {
        let cases = [
            (true, false, true),
            (true, true, false),
            (false, false, false),
            (false, true, false),
        ];
        for (oci_acceptable, has_digest, expected) in cases {
            assert_eq!(
                result_reference_is_acceptable(ResultReferenceFacts {
                    oci_acceptable,
                    has_digest,
                }),
                expected,
                "oci_acceptable={oci_acceptable} has_digest={has_digest}"
            );
        }
    }

    /// Real parser examples: accepted mutable references and the reasons the
    /// rejected ones give (fixed text, never the supplied value).
    #[test]
    fn parser_accepts_mutable_names_and_rejects_digests_paths_and_whitespace() {
        for accepted in [
            "my-app:dev",
            "registry.example.com:5000/team/app:v1.2.3",
            "localhost:1/does-not-exist",
            "bare",
            "bare:latest",
        ] {
            let parsed = accepted
                .parse::<ResultReference>()
                .unwrap_or_else(|error| panic!("{accepted} must be accepted: {error}"));
            assert_eq!(parsed.as_str(), accepted, "the spelling is preserved");
        }

        let digest = "registry.example.com/team/app@sha256:\
                      0000000000000000000000000000000000000000000000000000000000000000";
        let Err(error) = digest.parse::<ResultReference>() else {
            panic!("a digest-pinned reference must be rejected")
        };
        assert_eq!(error.to_string(), PINNED_RESULT_REFERENCE_REASON);
        assert!(!error.to_string().contains("sha256"), "no value is echoed");

        for rejected in [
            "",
            "has space",
            "has\ttab",
            "has\nnewline",
            "./local-path",
            "/absolute/path",
            "../parent",
            ".",
            "..",
        ] {
            let Err(error) = rejected.parse::<ResultReference>() else {
                panic!("{rejected:?} must be rejected")
            };
            let message = error.to_string();
            assert!(
                message.starts_with("--tag must be an OCI image reference"),
                "fixed adapter reason expected for {rejected:?}: {message}"
            );
            // A distinctive rejected spelling is never echoed back.
            assert!(
                !message.contains("local-path") && !message.contains("absolute"),
                "the fixed reason must not echo {rejected:?}: {message}"
            );
        }
    }

    /// A digest-pinned reference is a valid *boot* image but not a valid mutable
    /// build result — the two types must disagree.
    #[test]
    fn digest_is_valid_for_launch_but_not_for_a_build_result() {
        let pinned = "registry.example.com/team/app@sha256:\
                      1111111111111111111111111111111111111111111111111111111111111111";
        assert!(crate::boot_image::ImageRef::from_config(pinned).is_ok());
        assert!(pinned.parse::<ResultReference>().is_err());
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
