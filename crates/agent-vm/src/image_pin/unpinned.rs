//! An unpinned launch build boots its own result with no approval (ADR-0061): typing
//! `--dockerfile` is the consent, for this launch only. Nothing here reads or
//! writes the pin store or the retained default.
//!
//! Two cache-only reads, never a registry: right after publication the tag is
//! read back and must name the digest the loader reported (§7); that read also
//! preserves the content-addressed `repo@digest` metadata. Preparation later
//! reads that immutable `repo@digest`, so a concurrent rebuild of the same
//! Dockerfile, which moves the shared tag, cannot change what this launch boots.

use anyhow::{Result, anyhow};

use super::*;
use crate::boot_image::ImageLabel;
use crate::image_acquire::{AcquireMode, OciTarget, ValidatedDigest as ManifestDigest};
use crate::image_publish::Published;

/// What one launch build published and verified. Holds no barrier. Fields are
/// private and only `read_back_unpinned` constructs one, so it is proof of a
/// verified read-back.
#[derive(Debug)]
pub(crate) struct BuiltImage {
    immutable: ImmutableImageRef,
    /// The canonical internal tag: the ADR-0060 display-store key, so one
    /// Dockerfile keeps one report entry across rebuilds (R15).
    selection: String,
    digest: ManifestDigest,
}

pub(crate) async fn read_back_unpinned(
    published: &Published,
    label: &ImageLabel,
) -> Result<BuiltImage> {
    let prepared = acquire_or_render(
        published.target(),
        label,
        Rendering::Publication,
        AcquireMode::CachedOnly,
    )
    .await?;
    if prepared.image().acquired_digest() != published.digest() {
        return Err(changed_before_boot());
    }
    let pinned = published
        .target()
        .canonical()
        .with_digest(published.digest())
        .map_err(|_| {
            anyhow!("internal error: the launch build result has no usable digest reference")
        })?;
    let immutable = ImmutableImageRef::parse(&pinned.whole()).map_err(|_| {
        anyhow!("internal error: the launch build result has no usable digest reference")
    })?;
    drop(prepared); // releases the shared barrier; nothing is held across credentials
    Ok(BuiltImage {
        immutable,
        selection: published.target().canonical().whole(),
        digest: published.digest().clone(),
    })
}

pub(crate) async fn prepare_unpinned(
    built: &BuiltImage,
    label: &ImageLabel,
) -> Result<PreparedSelection> {
    let target = OciTarget::parse(built.immutable.as_str()).map_err(|_| {
        anyhow!("internal error: the launch build result is not a usable OCI target")
    })?;
    let prepared = acquire_or_render(
        &target,
        label,
        Rendering::Publication,
        AcquireMode::CachedOnly,
    )
    .await?;
    if prepared.image().acquired_digest() != &built.digest {
        return Err(changed_before_boot());
    }
    Ok(
        PreparedSelection::immutable_content(&built.immutable, built.selection.clone(), prepared)
            .cache_only(),
    )
}

fn changed_before_boot() -> anyhow::Error {
    anyhow!(
        "the --dockerfile build result changed in the image cache before this launch could boot \
         it (possibly a concurrent launch build of the same Dockerfile); re-run the command"
    )
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // the function under test is the ban's target
mod tests {
    use super::*;
    use crate::image_publish::test_archive;
    use crate::image_publish::{ImageTarget, PublishPurpose, ResultReference};
    use microsandbox::sandbox::PullPolicy;

    #[tokio::test]
    async fn unpinned_publish_read_back_and_prepare_lifecycle() {
        let mut env = crate::test_env::guard();
        let home = tempfile::tempdir().unwrap();
        env.set_var("HOME", home.path());
        let msb_home = tempfile::tempdir().unwrap();
        env.set_var("MSB_HOME", msb_home.path());

        let target = ImageTarget::resolve().await.unwrap();
        let archive_dir = tempfile::tempdir().unwrap();
        let written = test_archive::write(
            &archive_dir.path().join("a.tar"),
            &test_archive::ArchiveSpec {
                marker: "first".to_string(),
                ..Default::default()
            },
        );
        let tag_ref: ResultReference =
            "agent-vm.invalid/dockerfile/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:latest"
                .parse()
                .unwrap();
        let label = ImageLabel::for_result_reference(tag_ref.as_str());

        let published = target
            .publish(
                &written.path,
                &tag_ref,
                PublishPurpose::LaunchBuild {
                    typed: std::path::Path::new("Dockerfile"),
                },
            )
            .await
            .unwrap();

        let built = read_back_unpinned(&published, &label).await.unwrap();
        assert_eq!(
            built.selection,
            "agent-vm.invalid/dockerfile/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:latest"
        );
        assert_eq!(built.digest.as_str(), written.manifest_digest);

        let prepared = prepare_unpinned(&built, &label).await.unwrap();
        assert_eq!(
            prepared.sdk_reference(),
            format!(
                "agent-vm.invalid/dockerfile/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@{}",
                written.manifest_digest
            )
        );
        assert!(prepared.image_env().is_some());
        assert_eq!(prepared.pull_policy(), PullPolicy::Never);
        assert!(prepared.is_cache_only());
        // R16's other half, on a real prepared launch build: a plain-HTTP-looking
        // reference must still not turn `.insecure()` on, because the SDK is told
        // `Never` and this name is a cache key.
        assert!(!prepared.registry_is_insecure(prepared.sdk_reference()));
        assert!(!prepared.registry_is_insecure("registry.local:5000/o/i:1"));
        assert!(!home.path().join(".config").exists());
    }

    #[tokio::test]
    async fn tag_moved_between_publish_and_read_back_errors() {
        let mut env = crate::test_env::guard();
        let home = tempfile::tempdir().unwrap();
        env.set_var("HOME", home.path());
        let msb_home = tempfile::tempdir().unwrap();
        env.set_var("MSB_HOME", msb_home.path());

        let target = ImageTarget::resolve().await.unwrap();
        let archive_dir = tempfile::tempdir().unwrap();
        let written1 = test_archive::write(
            &archive_dir.path().join("a1.tar"),
            &test_archive::ArchiveSpec {
                marker: "first".to_string(),
                ..Default::default()
            },
        );
        let written2 = test_archive::write(
            &archive_dir.path().join("a2.tar"),
            &test_archive::ArchiveSpec {
                marker: "second".to_string(),
                ..Default::default()
            },
        );
        let tag_ref: ResultReference =
            "agent-vm.invalid/dockerfile/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:latest"
                .parse()
                .unwrap();
        let label = ImageLabel::for_result_reference(tag_ref.as_str());

        // First publication
        let published1 = target
            .publish(
                &written1.path,
                &tag_ref,
                PublishPurpose::LaunchBuild {
                    typed: std::path::Path::new("Dockerfile"),
                },
            )
            .await
            .unwrap();

        // Second publication moves the tag before read_back_unpinned of the first
        let _published2 = target
            .publish(
                &written2.path,
                &tag_ref,
                PublishPurpose::LaunchBuild {
                    typed: std::path::Path::new("Dockerfile"),
                },
            )
            .await
            .unwrap();

        let err = read_back_unpinned(&published1, &label).await.unwrap_err();
        assert!(
            err.to_string().contains(
                "the --dockerfile build result changed in the image cache before this launch could boot it"
            ),
            "expected changed_before_boot error: {err:#}"
        );
    }

    #[tokio::test]
    async fn tag_moved_after_read_back_still_boots_first_digest() {
        let mut env = crate::test_env::guard();
        let home = tempfile::tempdir().unwrap();
        env.set_var("HOME", home.path());
        let msb_home = tempfile::tempdir().unwrap();
        env.set_var("MSB_HOME", msb_home.path());

        let target = ImageTarget::resolve().await.unwrap();
        let archive_dir = tempfile::tempdir().unwrap();
        let written1 = test_archive::write(
            &archive_dir.path().join("a1.tar"),
            &test_archive::ArchiveSpec {
                marker: "first".to_string(),
                ..Default::default()
            },
        );
        let written2 = test_archive::write(
            &archive_dir.path().join("a2.tar"),
            &test_archive::ArchiveSpec {
                marker: "second".to_string(),
                ..Default::default()
            },
        );
        let tag_ref: ResultReference =
            "agent-vm.invalid/dockerfile/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:latest"
                .parse()
                .unwrap();
        let label = ImageLabel::for_result_reference(tag_ref.as_str());

        // Publish and read back first image
        let published1 = target
            .publish(
                &written1.path,
                &tag_ref,
                PublishPurpose::LaunchBuild {
                    typed: std::path::Path::new("Dockerfile"),
                },
            )
            .await
            .unwrap();
        let built1 = read_back_unpinned(&published1, &label).await.unwrap();

        // Publish second image (tag moves)
        let _published2 = target
            .publish(
                &written2.path,
                &tag_ref,
                PublishPurpose::LaunchBuild {
                    typed: std::path::Path::new("Dockerfile"),
                },
            )
            .await
            .unwrap();

        // prepare_unpinned on built1 still prepares the first digest
        let prepared1 = prepare_unpinned(&built1, &label).await.unwrap();
        assert_eq!(
            prepared1.sdk_reference(),
            format!(
                "agent-vm.invalid/dockerfile/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@{}",
                written1.manifest_digest
            )
        );
    }

    #[tokio::test]
    async fn repo_digest_removed_before_prepare_unpinned_fails_cache_only() {
        let mut env = crate::test_env::guard();
        let home = tempfile::tempdir().unwrap();
        env.set_var("HOME", home.path());
        let msb_home = tempfile::tempdir().unwrap();
        env.set_var("MSB_HOME", msb_home.path());

        let target = ImageTarget::resolve().await.unwrap();
        let archive_dir = tempfile::tempdir().unwrap();
        let written = test_archive::write(
            &archive_dir.path().join("a.tar"),
            &test_archive::ArchiveSpec {
                marker: "first".to_string(),
                ..Default::default()
            },
        );
        let tag_ref: ResultReference =
            "agent-vm.invalid/dockerfile/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:latest"
                .parse()
                .unwrap();
        let label = ImageLabel::for_result_reference(tag_ref.as_str());

        let published = target
            .publish(
                &written.path,
                &tag_ref,
                PublishPurpose::LaunchBuild {
                    typed: std::path::Path::new("Dockerfile"),
                },
            )
            .await
            .unwrap();

        let built = read_back_unpinned(&published, &label).await.unwrap();

        // Remove the cache directory completely
        std::fs::remove_dir_all(target.cache_dir()).unwrap();

        let err = prepare_unpinned(&built, &label).await.unwrap_err();
        // Since it's CachedOnly, it must fail as NotCached and never pull from a registry
        let shown = format!("{err:#}");
        assert!(
            shown.contains("the image cache holds no complete host-platform image for this reference, and this operation never contacts a registry"),
            "expected NotCached publication error: {shown}"
        );
    }
}
