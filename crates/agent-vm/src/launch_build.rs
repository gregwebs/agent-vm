//! A **launch build** (CONTEXT.md, ADR-0061): `--dockerfile FILE` typed on the
//! command line builds FILE and boots exactly the result, for this launch.
//!
//! ```text
//! resolve   d/Dockerfile → /home/u/p/d/Dockerfile (canonical)
//!           tag = agent-vm.invalid/dockerfile/3f9a…e1:latest   (sha256 of canonical bytes)
//!           context = /home/u/p/d                           (typed parent, absolute)
//! probe     docker buildx build -f /home/u/p/d/Dockerfile --platform linux/arm64
//!           --provenance=false --sbom=false
//!           --output type=image,oci-mediatypes=true,store=false
//!           --metadata-file MSB_HOME/tmp/image-XXXX/probe.json /home/u/p/d
//!           stdin=/dev/null  stdout=/dev/null  stderr=inherit    exit≠0 → launcher failure, nothing re-run
//! reuse     probe.json containerimage.digest = sha256:abcd…
//!           read repo@sha256:abcd…, CachedOnly (shared barrier, released)
//!           present → BuiltImage(repo@sha256:abcd…); tag untouched; skip to "==> Boot image"
//! export    (on a miss) same argv but --output type=oci,dest=-
//!           stdout=MSB_HOME/tmp/image-XXXX/result.tar
//! publish   tag → digest sha256:abcd…   (exclusive barrier, then released)
//! read back tag, CachedOnly, digest must == sha256:abcd…  → BuiltImage(repo@sha256:abcd…)
//! ==> Boot image: --dockerfile d/Dockerfile
//! prepare   repo@sha256:abcd…, CachedOnly, shared barrier held through create
//! SDK create .image("agent-vm.invalid/dockerfile/3f9a…e1@sha256:abcd…")
//!            PullPolicy::Never, no .insecure()  (cache-only; never a registry)
//! ```

use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context, Result, anyhow, bail};

use crate::boot_image::BootImage;
use crate::boot_image::ImageLabel;
use crate::image_build::{self, BuildOptions, DockerBuild, ProbeRun, ProbeUnreported};
use crate::image_pin::{BuiltImage, ManifestDigest, ProbedCache};
use crate::image_publish::{ImageTarget, PublishPurpose, ResultReference};
use crate::one_line;

const REPOSITORY: &str = "agent-vm.invalid/dockerfile";
const LAUNCH_BUILD_HINT: &str = "this needs a working Docker with buildx and a builder that \
supports both of this build's outputs: `--output type=image,oci-mediatypes=true,store=false` for the \
probe and `--output type=oci` for the export (set `BUILDX_BUILDER` to pick one); for other build \
options, build with `agent-vm image build` and launch the result with `--image`";

/// `--dockerfile` typed alongside a typed `--image`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DockerfileImageConflict;

impl std::fmt::Display for DockerfileImageConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "--dockerfile and --image cannot be used together: --dockerfile builds the image this launch boots"
        )
    }
}

impl std::error::Error for DockerfileImageConflict {}

/// One resolved launch build. Paths are absolute and lexically joined to the cwd,
/// never re-canonicalized, so Docker reads what the user named.
#[derive(Debug)]
pub(crate) struct LaunchBuild {
    typed: PathBuf,      // display only
    dockerfile: PathBuf, // cwd.join(typed)
    context: PathBuf,    // parent of `dockerfile` (the typed parent, ADR-0061 §3)
    result: ResultReference,
}

impl LaunchBuild {
    pub(crate) fn resolve(typed: &Path) -> Result<Self> {
        let cwd =
            std::env::current_dir().context("reading the current directory for --dockerfile")?;
        Self::resolve_from(typed, &cwd)
    }

    /// Pure apart from the filesystem reads, so tests need no cwd change.
    ///
    /// `metadata` (which follows symlinks) answers "is this a regular file?" and
    /// turns a trailing slash on a non-directory into `ENOTDIR`, so
    /// `--dockerfile Dockerfile/` fails rather than being silently accepted —
    /// `canonicalize` alone drops that trailing slash. `canonicalize` supplies
    /// the identity bytes the internal tag is hashed from.
    fn resolve_from(typed: &Path, cwd: &Path) -> Result<Self> {
        if typed.as_os_str().is_empty() {
            bail!("--dockerfile needs a path to a Dockerfile, got an empty value");
        }
        let dockerfile = cwd.join(typed);
        let shown = one_line::path(typed);
        let metadata = std::fs::metadata(&dockerfile)
            .with_context(|| format!("resolving --dockerfile {shown}"))?;
        let canonical = dockerfile
            .canonicalize()
            .with_context(|| format!("resolving --dockerfile {shown}"))?;
        if !metadata.is_file() {
            bail!(
                "--dockerfile {shown} is not a regular file; pass the Dockerfile itself (e.g. --dockerfile DIR/Dockerfile)"
            );
        }
        let context = dockerfile
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| cwd.to_path_buf());
        Ok(Self {
            typed: typed.to_path_buf(),
            dockerfile,
            context,
            result: internal_reference(&canonical)?,
        })
    }

    pub(crate) fn boot_image(&self) -> BootImage {
        BootImage::launch_build(self.result.image_ref().clone(), self.typed.clone())
    }

    /// `==> Building --dockerfile d/Dockerfile (context /abs/d)`; one line, measured paths escaped.
    /// Goes to stderr only (`LaunchNotices::to_stderr`): Docker's stdout is the archive file and
    /// nothing in this path writes to the launcher's stdout (R18).
    pub(crate) fn notice(&self) -> String {
        format!(
            "==> Building --dockerfile {} (context {})",
            one_line::path(&self.typed),
            one_line::path(&self.context)
        )
    }

    /// Docker could not be run at all.
    fn running_docker(&self) -> String {
        format!(
            "running `docker buildx build` for --dockerfile {}; {LAUNCH_BUILD_HINT}",
            one_line::path(&self.typed)
        )
    }

    /// Docker ran and reported failure. Never followed by an export: Docker's
    /// verdict is final (ADR-0061 §11, ADR-0071 §5).
    fn build_failed(&self, exit: i32) -> anyhow::Error {
        anyhow!(
            "docker buildx build failed (exit {exit}) for --dockerfile {}; nothing was booted; {LAUNCH_BUILD_HINT}",
            one_line::path(&self.typed)
        )
    }

    /// Probe → (cached: done) → export → publish → verify. Runs before the banner
    /// (ADR-0061 §8, ADR-0071).
    pub(crate) async fn build(&self, label: &ImageLabel) -> Result<BuiltImage> {
        let target = ImageTarget::resolve().await?;
        let staging = target.stage()?;
        let options = BuildOptions::default();
        let docker = DockerBuild {
            dockerfile: Some(self.dockerfile.as_os_str()),
            context: self.context.as_os_str(),
            options: &options,
        };
        let reported = match image_build::probe(&docker, &staging.probe_metadata_path())
            .await
            .with_context(|| self.running_docker())?
        {
            // Docker's verdict is final: a failing step is never re-run (ADR-0071 §5).
            ProbeRun::Failed(exit) => return Err(self.build_failed(exit)),
            ProbeRun::Built(reported) => reported,
        };
        let probed = match reuse(&self.result, reported, label).await {
            Reuse::Cached(built) => return Ok(built), // `staging` drops here too (R18)
            Reuse::Export { probed } => probed,
        };
        let exit = image_build::export_archive(&docker, staging.writer()?, Stdio::null())
            .await
            .with_context(|| self.running_docker())?;
        if exit != 0 {
            // Never import from a command that reported failure (same rule as `image build`).
            return Err(self.build_failed(exit));
        }
        let published = target
            .publish(
                staging.path(),
                &self.result,
                PublishPurpose::LaunchBuild { typed: &self.typed },
            )
            .await
            .with_context(|| {
                format!(
                    "publishing the --dockerfile {} build result",
                    one_line::path(&self.typed)
                )
            })?;
        if let Some(probed) = &probed
            && probed != published.digest()
        {
            tracing::debug!(
                %probed,
                published = %published.digest(),
                "launch-build probe and export digests differ"
            );
        }
        #[allow(clippy::disallowed_methods)]
        // A launch build boots its own result unpinned; typing --dockerfile is the consent (ADR-0061 §6).
        let built = crate::image_pin::read_back_unpinned(&published, label)
            .await
            .with_context(|| {
                format!(
                    "verifying the --dockerfile {} build result in the image cache",
                    one_line::path(&self.typed)
                )
            })?;
        Ok(built)
        // `staging` drops on every return above (success or `?`), removing the temp dir (R18).
    }
}

/// What a successful probe lets this launch do (ADR-0071).
#[derive(Debug)]
enum Reuse {
    /// The probed result is already cached: boot it; no export, no publication.
    Cached(BuiltImage),
    /// Export and publish (ADR-0061 §7). `probed` is kept only for the debug
    /// comparison.
    Export { probed: Option<ManifestDigest> },
}

/// Decide what a successful probe allows. Never fails: every problem here is a
/// probe problem, handled by exporting (ADR-0071 §5). Docker's own verdict was
/// already taken in `LaunchBuild::build`.
async fn reuse(
    result: &ResultReference,
    reported: Result<ManifestDigest, ProbeUnreported>,
    label: &ImageLabel,
) -> Reuse {
    let probed = match reported {
        Ok(digest) => digest,
        Err(reason) => {
            tracing::debug!(%reason, "launch-build probe reported no usable digest; exporting");
            return Reuse::Export { probed: None };
        }
    };
    #[allow(clippy::disallowed_methods)]
    // A launch build boots its own probed result unpinned, as it boots its export (ADR-0061 §6, ADR-0071).
    let cached = crate::image_pin::cached_unpinned(result, &probed, label).await;
    match cached {
        Ok(ProbedCache::Cached(built)) => {
            tracing::debug!(digest = %probed, "launch-build probe result is cached; skipping the export");
            Reuse::Cached(built)
        }
        Ok(ProbedCache::Miss) => {
            tracing::debug!(digest = %probed, "launch-build probe result is not cached; exporting");
            Reuse::Export {
                probed: Some(probed),
            }
        }
        // Handled by exporting: the export path's own reads report a cache that is
        // really broken.
        Err(error) => {
            tracing::debug!(
                digest = %probed,
                error = %format_args!("{error:#}"),
                "launch-build probe cache read failed; exporting"
            );
            Reuse::Export {
                probed: Some(probed),
            }
        }
    }
}

/// `agent-vm.invalid/dockerfile/<sha256 hex of the canonical path's bytes>:latest`.
fn internal_reference(canonical: &Path) -> Result<ResultReference> {
    use sha2::{Digest as _, Sha256};
    use std::os::unix::ffi::OsStrExt as _;
    let hex: String = Sha256::digest(canonical.as_os_str().as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("{REPOSITORY}/{hex}:latest").parse().map_err(|_| {
        anyhow!("internal error: the launch build reference is not a valid OCI reference")
    })
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // the caching seam under test is the ban's target
mod tests {
    use super::*;
    use crate::image_publish::test_archive;
    use crate::image_publish::{ImageTarget, PublishPurpose};
    use microsandbox::sandbox::PullPolicy;

    #[test]
    fn resolve_from_paths_contexts_and_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path();

        let dockerfile = cwd.join("Dockerfile");
        std::fs::write(&dockerfile, b"FROM scratch\n").unwrap();

        let sub = cwd.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        let sub_dockerfile = sub.join("Dockerfile");
        std::fs::write(&sub_dockerfile, b"FROM scratch\n").unwrap();

        // Relative Dockerfile in cwd
        let resolved = LaunchBuild::resolve_from(Path::new("Dockerfile"), cwd).unwrap();
        assert_eq!(resolved.dockerfile, dockerfile);
        assert_eq!(resolved.context, cwd);
        assert_eq!(resolved.typed, Path::new("Dockerfile"));

        // Relative ./Dockerfile in cwd (same canonical path -> same tag)
        let resolved_dot = LaunchBuild::resolve_from(Path::new("./Dockerfile"), cwd).unwrap();
        assert_eq!(resolved_dot.result.as_str(), resolved.result.as_str());

        // Relative sub/Dockerfile
        let resolved_sub = LaunchBuild::resolve_from(Path::new("sub/Dockerfile"), cwd).unwrap();
        assert_eq!(resolved_sub.dockerfile, sub_dockerfile);
        assert_eq!(resolved_sub.context, sub);

        // Absolute Dockerfile
        let resolved_abs = LaunchBuild::resolve_from(&sub_dockerfile, cwd).unwrap();
        assert_eq!(resolved_abs.dockerfile, sub_dockerfile);
        assert_eq!(resolved_abs.context, sub);

        // Symlink: link/Dockerfile -> ../real/Dockerfile
        let real_dir = cwd.join("real");
        std::fs::create_dir_all(&real_dir).unwrap();
        let real_dockerfile = real_dir.join("Dockerfile");
        std::fs::write(&real_dockerfile, b"FROM scratch\n").unwrap();

        let link_dir = cwd.join("link");
        std::fs::create_dir_all(&link_dir).unwrap();
        let link_dockerfile = link_dir.join("Dockerfile");
        std::os::unix::fs::symlink("../real/Dockerfile", &link_dockerfile).unwrap();

        let resolved_link = LaunchBuild::resolve_from(Path::new("link/Dockerfile"), cwd).unwrap();
        assert_eq!(resolved_link.context, link_dir); // typed parent
        // `-f` gets the typed path, never the canonical one: Docker reads what the
        // user named, and a broken link target must fail there rather than here.
        assert_eq!(resolved_link.dockerfile, link_dockerfile);
        let resolved_real = LaunchBuild::resolve_from(Path::new("real/Dockerfile"), cwd).unwrap();
        assert_eq!(resolved_link.result.as_str(), resolved_real.result.as_str()); // same canonical bytes -> same tag
    }

    #[test]
    fn different_files_have_different_tags_matching_format() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path();
        let f1 = cwd.join("Dockerfile1");
        let f2 = cwd.join("Dockerfile2");
        std::fs::write(&f1, b"FROM scratch\n").unwrap();
        std::fs::write(&f2, b"FROM scratch\n").unwrap();

        let r1 = LaunchBuild::resolve_from(Path::new("Dockerfile1"), cwd).unwrap();
        let r2 = LaunchBuild::resolve_from(Path::new("Dockerfile2"), cwd).unwrap();
        assert_ne!(r1.result.as_str(), r2.result.as_str());

        let tag = r1.result.as_str();
        assert!(tag.starts_with("agent-vm.invalid/dockerfile/"));
        assert!(tag.ends_with(":latest"));
        let hex = &tag["agent-vm.invalid/dockerfile/".len()..tag.len() - ":latest".len()];
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn missing_directory_and_empty_paths_fail() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path();

        // Empty path
        let err_empty = LaunchBuild::resolve_from(Path::new(""), cwd).unwrap_err();
        assert_eq!(
            err_empty.to_string(),
            "--dockerfile needs a path to a Dockerfile, got an empty value"
        );

        // Missing file
        let err_missing = LaunchBuild::resolve_from(Path::new("nonexistent"), cwd).unwrap_err();
        let msg = format!("{err_missing:#}");
        assert!(msg.contains("resolving --dockerfile nonexistent"));

        // Directory
        let err_dir = LaunchBuild::resolve_from(Path::new("."), cwd).unwrap_err();
        assert!(err_dir.to_string().contains("is not a regular file"));

        // Trailing slash on file
        let file = cwd.join("Dockerfile");
        std::fs::write(&file, b"FROM scratch\n").unwrap();
        let err_slash = LaunchBuild::resolve_from(Path::new("Dockerfile/"), cwd).unwrap_err();
        let msg = format!("{err_slash:#}");
        assert!(msg.contains("resolving --dockerfile Dockerfile/"));

        // Trailing slash on directory
        let sub = cwd.join("subdir");
        std::fs::create_dir_all(&sub).unwrap();
        let err_dir_slash = LaunchBuild::resolve_from(Path::new("subdir/"), cwd).unwrap_err();
        assert!(err_dir_slash.to_string().contains("is not a regular file"));
    }

    #[test]
    fn path_with_newlines_escaped_on_one_line() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path();
        let bad_path = Path::new("test\nDockerfile");
        let err = LaunchBuild::resolve_from(bad_path, cwd).unwrap_err();
        let shown = format!("{err:#}");
        assert!(!shown.contains('\n'), "a newline must be escaped: {shown}");
        assert!(
            shown.contains("\\x0a"),
            "the newline must render as \\x0a: {shown}"
        );
    }

    /// A cache holding a fixture archive, isolated from the developer's own.
    async fn cached_fixture(marker: &str) -> (ImageTarget, ResultReference, String) {
        let target = ImageTarget::resolve().await.unwrap();
        let archive_dir = tempfile::tempdir().unwrap();
        let written = test_archive::write(
            &archive_dir.path().join("a.tar"),
            &test_archive::ArchiveSpec {
                marker: marker.to_string(),
                ..Default::default()
            },
        );
        let result = internal_reference(Path::new("/p/Dockerfile")).unwrap();
        let published = target
            .publish(
                &written.path,
                &result,
                PublishPurpose::LaunchBuild {
                    typed: Path::new("Dockerfile"),
                },
            )
            .await
            .unwrap();
        // The read-back is what preserves `repo@digest` metadata, which is the
        // only thing a later probe hit can find (ADR-0071 §2).
        let label = ImageLabel::for_result_reference(result.as_str());
        crate::image_pin::read_back_unpinned(&published, &label)
            .await
            .unwrap();
        (target, result, written.manifest_digest)
    }

    /// A hit is `Reuse::Cached`, and what it boots is exactly `repo@D`.
    #[tokio::test]
    async fn reuse_boots_a_cached_probe_digest() {
        let mut env = crate::test_env::guard();
        let home = tempfile::tempdir().unwrap();
        env.set_var("HOME", home.path());
        let msb_home = tempfile::tempdir().unwrap();
        env.set_var("MSB_HOME", msb_home.path());

        let (_target, result, digest) = cached_fixture("cached").await;
        let label = ImageLabel::for_result_reference(result.as_str());
        let probed = ManifestDigest::parse(&digest).unwrap();

        let reused = reuse(&result, Ok(probed.clone()), &label).await;
        let Reuse::Cached(built) = reused else {
            panic!("a cached probe digest must be reused, got {reused:?}");
        };
        let prepared = crate::image_pin::prepare_unpinned(&built, &label)
            .await
            .unwrap();
        let repo = result.as_str().split(':').next().unwrap();
        assert_eq!(
            prepared.sdk_reference(),
            format!("{repo}@{digest}"),
            "the hit boots the probed digest itself"
        );
        assert_eq!(prepared.pull_policy(), PullPolicy::Never);
        assert!(prepared.is_cache_only());
        assert!(!home.path().join(".config").exists());
    }

    /// A miss is `Reuse::Export`, carrying the digest only for the debug line.
    #[tokio::test]
    async fn reuse_exports_an_uncached_digest() {
        let mut env = crate::test_env::guard();
        let home = tempfile::tempdir().unwrap();
        env.set_var("HOME", home.path());
        let msb_home = tempfile::tempdir().unwrap();
        env.set_var("MSB_HOME", msb_home.path());

        let result = internal_reference(Path::new("/p/Dockerfile")).unwrap();
        let label = ImageLabel::for_result_reference(result.as_str());
        let probed = ManifestDigest::parse(&format!("sha256:{}", "b".repeat(64))).unwrap();

        match reuse(&result, Ok(probed.clone()), &label).await {
            Reuse::Export {
                probed: Some(carried),
            } => assert_eq!(carried, probed),
            other => panic!("an uncached digest must export, got {other:?}"),
        }
    }

    /// A probe problem (here: nothing reported) exports, and carries no digest.
    #[tokio::test]
    async fn reuse_exports_when_the_probe_reported_nothing() {
        let mut env = crate::test_env::guard();
        let home = tempfile::tempdir().unwrap();
        env.set_var("HOME", home.path());
        let msb_home = tempfile::tempdir().unwrap();
        env.set_var("MSB_HOME", msb_home.path());

        let result = internal_reference(Path::new("/p/Dockerfile")).unwrap();
        let label = ImageLabel::for_result_reference(result.as_str());

        match reuse(&result, Err(ProbeUnreported::NoDigest), &label).await {
            Reuse::Export { probed: None } => {}
            other => panic!("an unreported digest must export, got {other:?}"),
        }
    }

    /// A cache that cannot be read exports too: the decision never panics and
    /// never fails a launch.
    #[tokio::test]
    async fn reuse_exports_when_the_cache_cannot_be_read() {
        let mut env = crate::test_env::guard();
        let home = tempfile::tempdir().unwrap();
        env.set_var("HOME", home.path());
        let msb_home = tempfile::tempdir().unwrap();
        env.set_var("MSB_HOME", msb_home.path());

        let target = ImageTarget::resolve().await.unwrap();
        // A cache whose shared barrier cannot be opened. The fault is undone on
        // drop for the rest of this test binary.
        let _fault = crate::image_acquire::PublicationLockFault::install(target.cache_dir());
        let result = internal_reference(Path::new("/p/Dockerfile")).unwrap();
        let label = ImageLabel::for_result_reference(result.as_str());
        let probed = ManifestDigest::parse(&format!("sha256:{}", "c".repeat(64))).unwrap();

        match reuse(&result, Ok(probed.clone()), &label).await {
            Reuse::Export {
                probed: Some(carried),
            } => assert_eq!(carried, probed),
            other => panic!("a broken cache must export, got {other:?}"),
        }
    }

    #[test]
    fn boot_image_and_notice() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path();
        let file = cwd.join("Dockerfile");
        std::fs::write(&file, b"FROM scratch\n").unwrap();

        let resolved = LaunchBuild::resolve_from(Path::new("Dockerfile"), cwd).unwrap();
        let boot = resolved.boot_image();
        assert_eq!(boot.label().text(), "--dockerfile Dockerfile");
        assert!(!boot.is_default());
        assert!(!boot.label().is_redacted());

        let notice = resolved.notice();
        assert!(notice.starts_with("==> Building --dockerfile Dockerfile (context "));
    }
}
