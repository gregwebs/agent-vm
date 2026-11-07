//! Publication into the ambient SDK cache, shared by explicit build and import.
//!
//! # Why not shell out to `msb image load`?
//!
//! `msb` (and the SDK's `Image::load_local`) publish the cache reference first
//! and then persist the catalog row in the database as a **separate fallible
//! step** (`commands/image.rs`). The native importer used here materializes
//! content before its atomic metadata rename. The loader publishes `--tag` plus
//! the names the archive itself carries (Docker `RepoTags`, OCI `ref.name`,
//! every image in a multi-image archive) one reference at a time, and
//! [`ImageTarget::publish`] restores only the requested reference on failure.
//! The trade-off is deliberate: the result is immediately launchable from
//! cache, but has no `msb image ls` row until a first launch persists the
//! cached metadata normally.
//!
//! # Why the ambient backend's cache, not `effective_cache_dir()`?
//!
//! The SDK resolves the same persisted/managed configuration that a launch
//! uses. `msb_install::effective_cache_dir()` ignores a **persisted** shared
//! redirect once `AGENT_VM_SHARE_MSB_CACHE` is unset, so it can point somewhere
//! a launch would not. Using [`microsandbox::backend::default_backend`] keeps
//! publication and launch agreeing by construction.
//!
//! # Publication guarantees
//! On import failure only the requested reference is restored. Archive aliases
//! may remain changed. No rollback covers process termination mid-import.
//! Publication takes the cache-wide **exclusive** publication barrier, so no
//! shared preparation is reading metadata while aliases move and two
//! publications cannot interleave their rollbacks.
//!
//! `publish` returns what it published — canonical result reference and manifest
//! digest — and holds no barrier afterwards; approval is the caller's separate,
//! explicit step (#391), because the read-back takes the shared barrier and would
//! deadlock under this exclusive one.

use crate::boot_image::ImageRef;
use crate::config::escape_str;
use crate::image_acquire::ValidatedDigest;
use anyhow::{Context, Result, anyhow};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use vstd::prelude::*;

/// The fixed reason a result reference is rejected when it is digest-pinned.
/// Names no value: the supplied text is untrusted input (see the parser).
const PINNED_RESULT_REFERENCE_REASON: &str = "\
--tag must name a mutable result reference (e.g. my-app:dev); a digest-pinned \
reference cannot be updated by a later build or import";

/// The `--tag` result reference. A distinct type from a launch `ImageRef` so a
/// digest-pinned value (valid for `--image`) is a compile-time-different,
/// parse-time-rejected value here.
#[derive(Clone)]
pub(crate) struct ResultReference(ImageRef);

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
            // no value. Build keeps clap's rejected-token rendering; import
            // replaces it with value-free diagnostics in cli::parse_from.
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
    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Does the native OCI parser read `raw` as a digest-pinned reference?
fn reference_has_digest(raw: &str) -> bool {
    raw.parse::<microsandbox_image::Reference>()
        .map(|reference| reference.digest().is_some())
        .unwrap_or(false)
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

/// Where a published image lands: the cache a launch reads, and the private
/// staging root beside it. Resolved once per invocation, after main's prologue.
pub(crate) struct ImageTarget {
    cache_dir: PathBuf,
    msb_home: PathBuf,
}

impl ImageTarget {
    /// DB preflight, then the ambient SDK backend's cache dir and MSB_HOME.
    ///
    /// The preflight lives here because both verbs must refuse a
    /// forward-migrated database identically: one place, one message.
    pub(crate) async fn resolve() -> Result<Self> {
        crate::msb_preflight::ensure_db_not_ahead().await?;
        let backend = microsandbox::backend::default_backend();
        let cache_dir = backend.as_local().ok_or_else(|| anyhow!(
            "agent-vm image imports into the local image cache, but the resolved backend is not local; unset the cloud backend selection"
        ))?.cache_dir();
        let msb_home = std::env::var_os("MSB_HOME").ok_or_else(|| anyhow!(
            "MSB_HOME is not set; agent-vm's msb setup did not run before dispatch (this is an internal invariant — `image` is not in the needs_msb_setup exclusion list in main.rs)"
        ))?.into();
        Ok(Self {
            cache_dir,
            msb_home,
        })
    }

    /// A private 0700 dir under MSB_HOME/tmp holding an empty 0600 `result.tar`.
    ///
    /// The directory is agent-vm's own, not Docker's: `image build` writes the
    /// export through this file, `image import` saves into it, and either way
    /// the archive is removed with the directory once publication ends.
    pub(crate) fn stage(&self) -> Result<Staging> {
        let root = self.msb_home.join("tmp");
        std::fs::create_dir_all(&root).context("creating image staging root")?;
        let directory = tempfile::Builder::new()
            .prefix("image-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(&root)
            .with_context(|| format!("creating image staging under {}", root.display()))?;
        let path = directory.path().join("result.tar");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("creating staged archive {}", path.display()))?;
        Ok(Staging {
            _directory: directory,
            file,
            path,
        })
    }

    /// Native import of one completed archive. Publishes `result` plus any names
    /// the archive carries (Docker `RepoTags`, OCI `ref.name`), one at a time.
    /// On failure, restores `result`'s previous metadata (or its absence).
    ///
    /// Only `result` is restored: an alias the archive named may already have
    /// changed (user decision, see the module's publication guarantees).
    ///
    /// On success the returned [`Published`] names exactly `result` and the
    /// digest the loader wrote for it; nothing in it names an alias, so a caller
    /// cannot approve a reference this command did not publish.
    pub(crate) async fn publish(
        &self,
        archive: &Path,
        result: &ResultReference,
    ) -> Result<Published> {
        // The requested reference is the ONE canonical acquisition key, so an
        // import under an equivalent spelling (`alpine:dev`,
        // `registry-1.docker.io/alpine:dev`) lands where a launch/refresh will
        // look. Archive-supplied aliases keep the native loader's semantics and
        // are not rewritten.
        //
        // This re-parses an already-validated `ResultReference` because the
        // loader takes a native `microsandbox_image::Reference` and nothing in
        // this crate can construct one without the native parser. Keeping the
        // parsed value (rather than the text) is what makes the barrier's
        // requested-alias snapshot and the loader's tag agree.
        let target = crate::image_acquire::OciTarget::parse(result.as_str())
            .map_err(|_| anyhow!("the result reference is not a usable OCI target"))?;
        let requested = target.canonical().whole();
        // Exclusive for the whole requested-alias snapshot → loader → rollback
        // interval: the native loader publishes every archive alias one at a
        // time, and a shared preparation must never observe (or boot from) a
        // cache whose metadata is mid-publication. Docker build/save/export
        // staging deliberately happens before this barrier is taken.
        let _publication = crate::image_acquire::PublicationBarrier::exclusive(&self.cache_dir)
            .await
            .map_err(crate::image_acquire::BarrierError::into_explicit_error)
            .context("coordinating image-cache publication")?;
        let cache = microsandbox_image::GlobalCache::new_async(&self.cache_dir).await?;
        let reference = target.reference().clone();
        let path = cache.image_metadata_path(&reference);
        let prior = Prior::read(&path).with_context(|| {
            format!(
                "reading the current metadata for {} before importing",
                escape_str(result.as_str())
            )
        })?;
        match microsandbox_image::load_archive(
            &self.cache_dir,
            archive,
            microsandbox_image::ImageLoadOptions {
                tags: vec![requested.clone()],
                progress: None,
            },
        )
        .await
        {
            // Post-publication: the loader committed, so a missing identity is
            // reported as published-but-not-approved, never as a rolled-back
            // import (D1).
            Ok(loaded) => {
                let digest = published_identity(
                    loaded.iter().map(|image| {
                        (
                            image.reference.as_str(),
                            image.metadata.manifest_digest.as_str(),
                        )
                    }),
                    &requested,
                )?;
                Ok(Published { target, digest })
            }
            Err(import) => match restore_reference(&path, &prior) {
                Ok(()) => Err(import.into()),
                Err(restore) => Err(failed_publication(import, restore, result)),
            },
        }
    }
}

/// What one explicit publication put under its result reference: the canonical
/// target and the manifest digest the native loader reported for it.
///
/// Holds no barrier, so nothing reachable from it runs under the exclusive
/// guard. Constructed only by [`ImageTarget::publish`], which is why the digest
/// here cannot be a value the caller chose.
pub(crate) struct Published {
    target: crate::image_acquire::OciTarget,
    digest: ValidatedDigest,
}

impl Published {
    pub(crate) fn target(&self) -> &crate::image_acquire::OciTarget {
        &self.target
    }

    pub(crate) fn digest(&self) -> &ValidatedDigest {
        &self.digest
    }
}

impl std::fmt::Debug for Published {
    /// Never renders the reference: a result reference can name a private
    /// registry, and `Debug` reaches logs the escaped diagnostics do not.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Published(<redacted reference>)")
    }
}

/// The published-but-not-approved sentence (#391, G4), defined once: the
/// identity hand-off below and every post-read-back failure in
/// `image_pin::publication::approve_published` attach it. `reference` is already
/// escaped (`escape_str`, the spelling `ImageLabel::for_result_reference` shows).
pub(crate) fn approval_not_updated(reference: &str) -> String {
    format!(
        "{reference} was published to agent-vm's image cache, but its approval was not \
         updated, so a launch still boots the content previously approved for it, if any"
    )
}

/// The manifest digest the loader reported for exactly the requested key.
///
/// Failure happens **after** the loader committed, so it says so rather than
/// looking like a failed import. Takes `(reference, manifest digest)` pairs
/// rather than `LoadedImage` so its unit test needs no native metadata.
fn published_identity<'a>(
    loaded: impl IntoIterator<Item = (&'a str, &'a str)>,
    requested: &str,
) -> Result<ValidatedDigest> {
    loaded
        .into_iter()
        .find(|(reference, _)| *reference == requested)
        .and_then(|(_, digest)| ValidatedDigest::parse(digest).ok())
        .ok_or_else(|| {
            anyhow!(
                "internal error: the native loader did not report a usable manifest digest for \
                 the published result reference, so its content cannot be approved"
            )
        })
        .with_context(|| approval_not_updated(&escape_str(requested)))
}

/// Removed (recursively) when dropped.
pub(crate) struct Staging {
    _directory: tempfile::TempDir,
    file: std::fs::File,
    path: PathBuf,
}

impl Staging {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// A duplicate write handle for a child's stdout (`image build`).
    ///
    /// The duplicate goes away with the command. No flush step follows the
    /// child: it writes unbuffered through the fd and has exited before the
    /// importer opens the path by name. The staging directory outlives the
    /// child because `_directory` owns it, not because a handle stays open. No
    /// fsync/durability claim is made here.
    pub(crate) fn writer(&self) -> Result<std::fs::File> {
        self.file
            .try_clone()
            .context("duplicating the staged archive handle for Docker's stdout")
    }
}

/// The requested reference's metadata bytes before the import (or its absence).
#[derive(PartialEq, Eq)]
enum Prior {
    Present(Vec<u8>),
    Absent,
}

impl Prior {
    fn read(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(Self::Present(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::Absent),
            Err(error) => Err(error.into()),
        }
    }
}

/// Put the requested reference back the way [`ImageTarget::publish`] found it.
///
/// The current bytes are read first so a failure that never reached the
/// requested commit costs no write (and cannot race a concurrent writer more
/// than it already has). [`crate::host_paths::atomic_write`] is used rather than
/// the native `.json.part` staging name: a temp file the native loader left
/// blocked must not be able to block the restore.
fn restore_reference(path: &Path, prior: &Prior) -> Result<()> {
    if &Prior::read(path)? == prior {
        return Ok(());
    }
    match prior {
        Prior::Present(bytes) => crate::host_paths::atomic_write(path, bytes, 0o644),
        Prior::Absent => match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        },
    }
}

/// The import error stays the chain root; the restore failure becomes the context.
fn failed_publication(
    import: microsandbox_image::ImageError,
    restore: anyhow::Error,
    result: &ResultReference,
) -> anyhow::Error {
    anyhow::Error::from(import).context(format!("restoring the previous {} after the failed import also failed ({restore:#}); it may now name the image from this failed import", escape_str(result.as_str())))
}

impl ResultReference {
    /// The reference as one word of a command to paste ([`crate::shell`]).
    ///
    /// Used by the success notices and the import hint, which add
    /// [`crate::shell::bash_zsh_note`] when the word is not plain. Diagnostics
    /// keep `escape_str`: they are read, not pasted, and must stay ASCII-safe
    /// without pretending to be a shell word.
    pub(crate) fn shell_arg(&self) -> crate::shell::PastedWord {
        crate::shell::PastedWord::new(self.as_str().as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn digest_is_valid_for_launch_but_not_for_a_result_reference() {
        let pinned = "registry.example.com/team/app@sha256:\
                      1111111111111111111111111111111111111111111111111111111111111111";
        assert!(crate::boot_image::ImageRef::from_config(pinned).is_ok());
        assert!(pinned.parse::<ResultReference>().is_err());
    }
}

#[cfg(test)]
#[path = "../tests/support/image_archive.rs"]
mod test_archive;

#[cfg(test)]
mod publication_tests {
    use super::*;
    use std::os::unix::fs::MetadataExt as _;

    /// Publishing never approves: the shared helper has no approval side effect,
    /// so a verb that reuses it (a future `--dockerfile` launch build, say)
    /// inherits none. A `.config` directory appearing here would mean some
    /// approval code moved inside `publish`.
    #[test]
    fn publication_alone_never_writes_an_approval() {
        let mut env = crate::test_env::guard();
        let home = tempfile::tempdir().unwrap();
        env.set_var("HOME", home.path());
        let root = tempfile::tempdir().unwrap();
        let archive_dir = tempfile::tempdir().unwrap();
        let written = test_archive::write(
            &archive_dir.path().join("a.tar"),
            &test_archive::ArchiveSpec::default(),
        );
        let target = ImageTarget {
            cache_dir: root.path().join("cache"),
            msb_home: root.path().to_path_buf(),
        };
        let published = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(target.publish(&written.path, &"app:dev".parse().unwrap()))
            .unwrap();
        assert_eq!(published.digest().as_str(), written.manifest_digest);
        assert_eq!(
            published.target().canonical().whole(),
            "docker.io/library/app:dev"
        );
        assert!(
            !home.path().join(".config").exists(),
            "publication wrote a HOME approval record"
        );
    }

    /// The identity hand-off failure happens **after** the loader committed, so
    /// it says so and keeps the internal cause: a bare internal error would read
    /// as a failed import and lose the reason.
    #[test]
    fn an_unidentified_publication_is_reported_as_published_but_not_approved() {
        let first = format!("sha256:{}", "a".repeat(64));
        let second = format!("sha256:{}", "b".repeat(64));
        // An alias listed first must not be mistaken for the requested key.
        assert_eq!(
            published_identity(
                [
                    ("docker.io/library/z:alias", first.as_str()),
                    ("docker.io/library/app:dev", second.as_str()),
                ],
                "docker.io/library/app:dev",
            )
            .unwrap()
            .as_str(),
            second
        );

        for loaded in [
            vec![("docker.io/library/z:alias", first.as_str())],
            vec![("docker.io/library/app:dev", "not-a-digest")],
        ] {
            let error = published_identity(loaded, "docker.io/library/app:dev").unwrap_err();
            let shown = format!("{error:#}");
            assert!(
                shown.contains(
                    "docker.io/library/app:dev was published to agent-vm's image cache, but its \
                     approval was not updated"
                ),
                "the context sentence must name the escaped reference: {shown}"
            );
            assert!(
                shown.contains(
                    "internal error: the native loader did not report a usable manifest digest"
                ),
                "the internal cause must be preserved: {shown}"
            );
        }

        // The reference in the sentence is escaped, like every other diagnostic
        // spelling this crate renders.
        let error = published_identity([], "docker.io/library/\x1bapp:dev").unwrap_err();
        let shown = format!("{error:#}");
        assert!(!shown.contains('\u{1b}'), "no raw control byte: {shown}");
        assert!(shown.contains("\\x1b"), "the escape is visible: {shown}");
    }

    #[test]
    fn stage_creates_private_dir_and_empty_0600_file() {
        let root = tempfile::tempdir().unwrap();
        let target = ImageTarget {
            cache_dir: root.path().join("cache"),
            msb_home: root.path().to_path_buf(),
        };
        let stage = target.stage().unwrap();
        let path = stage.path().to_path_buf();
        assert_eq!(
            std::fs::metadata(path.parent().unwrap()).unwrap().mode() & 0o777,
            0o700
        );
        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.len(), 0);
        drop(stage);
        assert!(!path.exists());
    }

    #[test]
    fn shell_arg_of_a_non_ascii_result_reference() {
        assert_eq!(
            "app:é"
                .parse::<ResultReference>()
                .unwrap()
                .shell_arg()
                .to_string(),
            "$'app:\\xc3\\xa9'"
        );
    }

    #[test]
    fn restore_puts_back_previous_bytes() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("a.json");
        std::fs::write(&path, b"B").unwrap();
        restore_reference(&path, &Prior::Present(b"A".to_vec())).unwrap();
        assert_eq!(std::fs::read(path).unwrap(), b"A");
    }

    #[test]
    fn restore_removes_a_reference_the_import_created() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("a.json");
        std::fs::write(&path, b"B").unwrap();
        restore_reference(&path, &Prior::Absent).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn restore_is_a_no_op_when_unchanged() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("a.json");
        std::fs::write(&path, b"A").unwrap();
        let before = std::fs::metadata(&path).unwrap();
        restore_reference(&path, &Prior::Present(b"A".to_vec())).unwrap();
        let after = std::fs::metadata(&path).unwrap();
        assert_eq!(before.ino(), after.ino());
        assert_eq!(before.modified().unwrap(), after.modified().unwrap());
        std::fs::remove_file(&path).unwrap();
        restore_reference(&path, &Prior::Absent).unwrap();
    }

    #[test]
    fn restore_failure_is_reported() {
        let root = tempfile::tempdir().unwrap();
        assert!(
            restore_reference(
                &root.path().join("missing/a"),
                &Prior::Present(b"A".to_vec())
            )
            .is_err()
        );
    }

    #[test]
    fn failed_publication_keeps_both_errors() {
        let import = microsandbox_image::ImageError::Cache {
            path: "cache".into(),
            source: std::io::Error::other("import fault"),
        };
        let error = failed_publication(
            import,
            std::io::Error::other("restore fault").into(),
            &"app:dev".parse().unwrap(),
        );
        let shown = format!("{error:#}");
        assert!(
            shown.contains("import fault")
                && shown.contains("restore fault")
                && shown.contains("restoring the previous")
        );
        assert!(error.root_cause().to_string().contains("import fault"));
    }
}
