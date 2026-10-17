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
//! Concurrent writers are not serialized: rollback can revert another writer,
//! the same last-writer-wins exposure as the native loader today.

use crate::boot_image::ImageRef;
use crate::config::escape_str;
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
    pub(crate) async fn publish(&self, archive: &Path, result: &ResultReference) -> Result<()> {
        let cache = microsandbox_image::GlobalCache::new_async(&self.cache_dir).await?;
        let reference = result.as_str().parse::<microsandbox_image::Reference>()?;
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
                tags: vec![result.as_str().to_string()],
                progress: None,
            },
        )
        .await
        {
            Ok(_) => Ok(()),
            Err(import) => match restore_reference(&path, &prior) {
                Ok(()) => Err(import.into()),
                Err(restore) => Err(failed_publication(import, restore, result)),
            },
        }
    }
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
    /// The reference as one copy-pasteable bash/zsh word.
    ///
    /// Used by the success notices and the import hint. Diagnostics keep
    /// `escape_str`: they are read, not pasted, and must stay ASCII-safe
    /// without pretending to be a shell word.
    pub(crate) fn shell_arg(&self) -> String {
        shell_word(self.as_str())
    }
}

/// Bash/zsh `$'…'` quoting for the bytes a reference may contain that the safe
/// set does not cover.
///
/// The safe set is the identity, so an ordinary reference prints unchanged;
/// everything else becomes `$'…'` with `\\`, `\'` and `\xNN` escapes, which
/// bash and zsh turn back into the same bytes. Split out from
/// [`ResultReference::shell_arg`] so the byte rule is testable on inputs the
/// parser rejects.
fn shell_word(text: &str) -> String {
    if text
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"._/:@-".contains(&b))
    {
        return text.to_string();
    }
    let mut word = String::from("$'");
    for byte in text.bytes() {
        match byte {
            b'\\' => word.push_str("\\\\"),
            b'\'' => word.push_str("\\'"),
            0x20..=0x7e => word.push(char::from(byte)),
            _ => {
                use std::fmt::Write as _;
                let _ = write!(word, "\\x{byte:02x}");
            }
        }
    }
    word.push('\'');
    word
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
mod publication_tests {
    use super::*;
    use std::os::unix::fs::MetadataExt as _;

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
    fn shell_word_is_identity_for_safe_ascii() {
        for raw in [
            "app:dev",
            "localhost:5000/a/b_c:V1.2-x",
            "registry.example.com/x",
        ] {
            assert_eq!(shell_word(raw), raw);
        }
    }

    #[test]
    fn shell_word_round_trips_through_bash_and_zsh() {
        for shell in ["bash", "zsh"] {
            if shell == "zsh"
                && std::process::Command::new(shell)
                    .arg("--version")
                    .output()
                    .is_err()
            {
                eprintln!("zsh not on PATH; skipping zsh round trip");
                continue;
            }
            for raw in ["app:é", "a'b", "a\\b", "a b", "a\nb", "x:\u{200d}"] {
                let word = shell_word(raw);
                assert!(word.is_ascii());
                let out = std::process::Command::new(shell)
                    .args(["-c", &format!("printf %s {word}")])
                    .output()
                    .unwrap();
                assert!(out.status.success());
                assert_eq!(out.stdout, raw.as_bytes());
            }
        }
    }

    #[test]
    fn shell_arg_of_a_non_ascii_result_reference() {
        assert_eq!(
            "app:é".parse::<ResultReference>().unwrap().shell_arg(),
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
