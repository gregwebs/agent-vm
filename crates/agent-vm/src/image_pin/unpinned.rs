//! An unpinned launch build boots its own result with no approval (ADR-0061): typing
//! `--dockerfile` is the consent, for this launch only. Nothing here reads or
//! writes the pin store or the retained default.
//!
//! Two cache-only reads, never a registry: right after publication the tag is
//! read back and must name the digest the loader reported (§7); that read also
//! preserves the content-addressed `repo@digest` metadata. Preparation later
//! reads that immutable `repo@digest`, so a concurrent rebuild of the same
//! Dockerfile, which moves the shared tag, cannot change what this launch boots.
//!
//! When the launch-build probe's digest is already cached ([`cached_unpinned`]),
//! that cache-only `repo@digest` read stands in for publication and read-back
//! (ADR-0071). It leaves the tag alone, and `prepare_unpinned` still re-reads the
//! digest under the shared barrier through create.

use anyhow::{Result, anyhow};

use super::*;
use crate::boot_image::ImageLabel;
use crate::image_acquire::{AcquireMode, OciTarget, ValidatedDigest as ManifestDigest};
use crate::image_publish::{Published, ResultReference};

/// What one launch build verified in the cache. Holds no barrier. Fields are
/// private and only this module constructs one ([`read_back_unpinned`] after a
/// publication, [`cached_unpinned`] for a probe hit), so it is proof of a
/// verified cache read.
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
    let built = built_image(published.target(), published.digest())?;
    drop(prepared); // releases the shared barrier; nothing is held across credentials
    Ok(built)
}

/// What a cache-only read of the probe's digest found: the two outcomes the
/// caller acts on differently. Every other failure stays an error.
#[derive(Debug)]
pub(crate) enum ProbedCache {
    /// The cache already holds `repo@D`: boot it; no export, no publication.
    Cached(BuiltImage),
    /// The cache holds no complete, identity-consistent `repo@D`
    /// ([`AcquireError::NotCached`]): export and publish.
    Miss,
}

/// The launch-build probe's digest, if the cache already holds it for this
/// Dockerfile (ADR-0071): the same cache-only `repo@digest` read
/// [`prepare_unpinned`] performs, so a hit here is exactly what preparation will
/// boot. The shared barrier is released before returning; preparation re-takes it
/// through create.
///
/// [`ProbedCache::Miss`] only for [`AcquireError::NotCached`]; any other failure is
/// an error the caller falls back on. The internal tag is never read and never
/// moved.
pub(crate) async fn cached_unpinned(
    result: &ResultReference,
    probed: &ManifestDigest,
    label: &ImageLabel,
) -> Result<ProbedCache> {
    let tag = OciTarget::parse(result.as_str()).map_err(|_| {
        anyhow!("internal error: the launch build reference is not a usable OCI target")
    })?;
    let built = built_image(&tag, probed)?;
    let target = OciTarget::parse(built.immutable.as_str()).map_err(|_| {
        anyhow!("internal error: the launch build result is not a usable OCI target")
    })?;
    match image_acquire::acquire(&target, label, AcquireMode::CachedOnly).await {
        Ok(prepared) => {
            // Defence in depth, not a reachable case: `acquire` of `repo@D` in
            // `CachedOnly` validates the entry's identity before returning, so
            // `acquired_digest()` is already `D`. It stays so a future change to
            // that validation cannot call content other than the probe's a hit;
            // this failure is safe, because the caller exports.
            let holds_probed = prepared.image().acquired_digest() == probed;
            drop(prepared); // releases the shared barrier; prepare_unpinned re-takes it through create
            if holds_probed {
                Ok(ProbedCache::Cached(built))
            } else {
                Err(anyhow!(
                    "the cached launch-build result does not hold the probed digest"
                ))
            }
        }
        Err(AcquireError::NotCached) => Ok(ProbedCache::Miss),
        // The shared seam owns how a publication read's failure is rendered, so a
        // change to that policy reaches this read too.
        Err(error) => Err(render_failure(
            label,
            Rendering::Publication,
            target.source_text(),
            error,
        )),
    }
}

/// The one way this module builds a [`BuiltImage`] for `tag` at `digest`.
fn built_image(tag: &OciTarget, digest: &ManifestDigest) -> Result<BuiltImage> {
    let pinned = tag
        .canonical()
        .with_digest(digest)
        .map_err(|_| no_digest_reference())?;
    let immutable = ImmutableImageRef::parse(&pinned.whole()).map_err(|_| no_digest_reference())?;
    Ok(BuiltImage {
        immutable,
        selection: tag.canonical().whole(),
        digest: digest.clone(),
    })
}

fn no_digest_reference() -> anyhow::Error {
    anyhow!("internal error: the launch build result has no usable digest reference")
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

    /// The probe's hit is exactly what publication + read-back would have
    /// produced: the same immutable reference, the same display key, the same
    /// digest, and a preparation that is cache-only with `PullPolicy::Never`.
    #[tokio::test]
    async fn cached_unpinned_matches_read_back_and_prepares_cache_only() {
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
        let tag_ref = launch_tag();
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
        let read_back = read_back_unpinned(&published, &label).await.unwrap();
        let probed = ManifestDigest::parse(&written.manifest_digest).unwrap();

        let cached = cached_unpinned(&tag_ref, &probed, &label).await.unwrap();
        let ProbedCache::Cached(cached) = cached else {
            panic!("the published digest is cached, got {cached:?}");
        };
        assert_eq!(cached.immutable.as_str(), read_back.immutable.as_str());
        assert_eq!(cached.selection, read_back.selection);
        assert_eq!(cached.digest, read_back.digest);

        let prepared = prepare_unpinned(&cached, &label).await.unwrap();
        assert_eq!(
            prepared.sdk_reference(),
            format!("{}@{}", internal_repo(), written.manifest_digest),
            "the hit boots exactly the probed content, cache-only"
        );
        assert_eq!(prepared.pull_policy(), PullPolicy::Never);
        assert!(prepared.is_cache_only());
        assert!(!home.path().join(".config").exists());
    }

    /// An absent digest is a miss, never an error and never a pull. Both halves
    /// use a fixture whose manifest annotation is unique to this test, so no
    /// sibling test in this binary can publish that digest into the shared cache.
    #[tokio::test]
    async fn cached_unpinned_is_a_miss_for_an_uncached_digest() {
        let mut env = crate::test_env::guard();
        let home = tempfile::tempdir().unwrap();
        env.set_var("HOME", home.path());
        let msb_home = tempfile::tempdir().unwrap();
        env.set_var("MSB_HOME", msb_home.path());

        let target = ImageTarget::resolve().await.unwrap();
        let tag_ref = launch_tag();
        let label = ImageLabel::for_result_reference(tag_ref.as_str());
        let archive_dir = tempfile::tempdir().unwrap();
        let published_a = test_archive::write(
            &archive_dir.path().join("a.tar"),
            &test_archive::ArchiveSpec {
                marker: "first".to_string(),
                ..Default::default()
            },
        );
        let missing = test_archive::write(
            &archive_dir.path().join("b.tar"),
            &test_archive::ArchiveSpec {
                marker: "uncached".to_string(),
                // Unique to this test: the annotation changes the manifest digest
                // without changing the guest content, so no other test in this
                // binary publishes it (the unit tests share one native cache).
                manifest_annotation: Some(
                    "cached_unpinned_is_a_miss_for_an_uncached_digest".to_string(),
                ),
                ..Default::default()
            },
        );
        let absent = ManifestDigest::parse(&missing.manifest_digest).unwrap();

        // A digest no fixture in this binary publishes.
        assert!(
            matches!(
                cached_unpinned(&tag_ref, &absent, &label).await.unwrap(),
                ProbedCache::Miss
            ),
            "a digest the cache never held is a miss"
        );

        // A cache that holds other content of this Dockerfile.
        target
            .publish(
                &published_a.path,
                &tag_ref,
                PublishPurpose::LaunchBuild {
                    typed: std::path::Path::new("Dockerfile"),
                },
            )
            .await
            .unwrap();
        assert!(
            matches!(
                cached_unpinned(&tag_ref, &absent, &label).await.unwrap(),
                ProbedCache::Miss
            ),
            "a published sibling does not answer for an unpublished digest"
        );
    }

    /// A hit is read-only: the internal tag keeps naming whatever it named, and
    /// its metadata bytes do not change (ADR-0071 §2, Q6).
    #[tokio::test]
    async fn cached_unpinned_leaves_the_tag_alone() {
        let mut env = crate::test_env::guard();
        let home = tempfile::tempdir().unwrap();
        env.set_var("HOME", home.path());
        let msb_home = tempfile::tempdir().unwrap();
        env.set_var("MSB_HOME", msb_home.path());

        let target = ImageTarget::resolve().await.unwrap();
        let archive_dir = tempfile::tempdir().unwrap();
        let written_a = test_archive::write(
            &archive_dir.path().join("a.tar"),
            &test_archive::ArchiveSpec {
                marker: "first".to_string(),
                ..Default::default()
            },
        );
        let written_b = test_archive::write(
            &archive_dir.path().join("b.tar"),
            &test_archive::ArchiveSpec {
                marker: "second".to_string(),
                ..Default::default()
            },
        );
        let tag_ref = launch_tag();
        let label = ImageLabel::for_result_reference(tag_ref.as_str());

        let published_a = target
            .publish(
                &written_a.path,
                &tag_ref,
                PublishPurpose::LaunchBuild {
                    typed: std::path::Path::new("Dockerfile"),
                },
            )
            .await
            .unwrap();
        read_back_unpinned(&published_a, &label).await.unwrap();
        // The tag moves to B, as a later different build would move it.
        target
            .publish(
                &written_b.path,
                &tag_ref,
                PublishPurpose::LaunchBuild {
                    typed: std::path::Path::new("Dockerfile"),
                },
            )
            .await
            .unwrap();

        let reference: microsandbox_image::Reference = tag_ref.as_str().parse().unwrap();
        let cache = microsandbox_image::GlobalCache::new(target.cache_dir()).unwrap();
        let metadata = cache.image_metadata_path(&reference);
        let before = std::fs::read(&metadata).unwrap();
        let cached = cached_unpinned(
            &tag_ref,
            &ManifestDigest::parse(&written_a.manifest_digest).unwrap(),
            &label,
        )
        .await
        .unwrap();
        let ProbedCache::Cached(cached) = cached else {
            panic!("A is still cached, got {cached:?}");
        };
        assert!(
            cached
                .immutable
                .as_str()
                .ends_with(&written_a.manifest_digest),
            "the hit names A: {}",
            cached.immutable.as_str()
        );
        assert_eq!(
            std::fs::read(&metadata).unwrap(),
            before,
            "a hit must not rewrite the tag's metadata"
        );
        assert_eq!(
            cache
                .read_image_metadata(&reference)
                .unwrap()
                .map(|metadata| metadata.manifest_digest),
            Some(written_b.manifest_digest),
            "the tag still names B"
        );
    }

    /// A cache that cannot be read is an error, not a miss: the caller falls back
    /// to the export, where the export path's own reads report the real breakage.
    #[tokio::test]
    async fn cached_unpinned_reports_a_cache_it_cannot_read() {
        let mut env = crate::test_env::guard();
        let home = tempfile::tempdir().unwrap();
        env.set_var("HOME", home.path());
        let msb_home = tempfile::tempdir().unwrap();
        env.set_var("MSB_HOME", msb_home.path());

        let target = ImageTarget::resolve().await.unwrap();
        let tag_ref = launch_tag();
        let label = ImageLabel::for_result_reference(tag_ref.as_str());
        let digest = ManifestDigest::parse(&format!("sha256:{}", "a".repeat(64))).unwrap();

        // A cache whose shared barrier cannot be opened: neither `NotCached` nor a
        // hit. The fault is undone on drop for the rest of this test binary.
        let _fault = crate::image_acquire::PublicationLockFault::install(target.cache_dir());

        let error = cached_unpinned(&tag_ref, &digest, &label)
            .await
            .expect_err("an unreadable cache is an error, not a miss");
        assert!(
            format!("{error:#}").contains("coordination lock"),
            "the error names the cache it could not read: {error:#}"
        );
    }

    const INTERNAL_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// The internal repository of [`launch_tag`].
    fn internal_repo() -> String {
        format!("agent-vm.invalid/dockerfile/{INTERNAL_HEX}")
    }

    /// The internal launch-build tag this file's rows all use.
    fn launch_tag() -> ResultReference {
        format!("{}:latest", internal_repo()).parse().unwrap()
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
