//! The user-scoped record of which immutable boot image this host retains as
//! its default (issue #261).
//!
//! # A bookmark, not a cache
//!
//! The record stores one OCI reference pinned by digest. It names exact image
//! content; microsandbox separately downloads and caches that content. Losing
//! the msb cache, changing `AGENT_VM_STATE_DIR`, enabling a shared cache or
//! working in another project must not change which image a default launch
//! boots, so the record lives beside the other user-scoped agent-vm settings
//! (`$HOME/.config/agent-vm/`) and **never** inside project state, the msb home
//! or `config.toml`. Writing a top-level `image =` into `config.toml` would make
//! the user tier outrank the project tier, which is a precedence change, not a
//! retention.
//!
//! # Why this module only encodes, decodes and snapshots now
//!
//! The record's *decisions* belong to the host approval authority: the first pin
//! and the fallback are committed as one journaled transaction
//! ([`crate::image_pin`]), because a fallback can only be retained for content
//! that was measured and approved. So the mutators that used to live here are
//! gone, and what remains is the byte-level schema: [`decode_snapshot`],
//! [`encode_snapshot`], [`snapshot_at`] and [`load`], which is a read of the
//! logical record through that authority. Keeping the encoding here is what lets
//! the pin store preserve a user's own formatting and a legacy spelling without
//! a second schema.
//!
//! # Failure and atomicity contract
//!
//! Reads are bounded and no-follow: a symlink, FIFO, directory, oversize file
//! or permission error is a hard error, never a silent reset. Writes go through
//! [`crate::host_paths::atomic_write`], so a process killed mid-write leaves
//! either no file or a complete one — never an empty "already selected" file.
//! That primitive does not `fsync`, so this module promises the repository's
//! existing trusted-host interruption atomicity, not power-loss durability. The
//! pin store's `pending_default` journal is what makes the *pair* of records
//! survive an interruption.
//!
//! # Diagnostic safety
//!
//! The record is untrusted input (a user-writable file whose reference may name
//! a private registry). Every failure this module reports is therefore a
//! **closed, fixed reason** plus the escaped record/lock path — never a
//! formatted source error, and never a source chain. Filesystem, lock, reader,
//! serde, UTF-8, digest-parser and save errors are all mapped to one of the
//! reasons below; the original error is discarded (it can embed a raw
//! `path.display()` and, for the reader, the path is the one carrying a
//! control-character `$HOME`). Callers may format the returned error freely:
//! its `Display` and its debug chain are the same safe text.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use vstd::prelude::*;

use crate::boot_image::ImmutableImageRef;
use crate::config;
use crate::host_paths;

/// The record's file name inside the user config directory. The pin store's
/// journal publishes the same file, so this is its one spelling.
pub(crate) const SELECTION_FILE: &str = "default-image.json";

/// One OCI reference plus a schema tag fits in a few hundred bytes; 16 KiB is
/// bounded and generous, so an oversized file is refused before it is parsed.
const MAX_SELECTION_FILE_BYTES: u64 = 16 * 1024;

const SELECTION_VERSION: u32 = 1;

/// The on-disk schema. `deny_unknown_fields` plus serde's duplicate/missing
/// field rejection means an unknown schema is an error, never a lenient read:
/// a record written by a future launcher must not be silently reinterpreted.
/// No launcher version, timestamp, tool name or platform guess is stored —
/// those would make the record a cache index rather than a bookmark.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectionFile {
    version: u32,
    image: String,
}

/// The retained record's path inside the user config directory.
///
/// `$HOME/.config/agent-vm`, through the shared `$HOME` discipline. Deliberately
/// ignores `XDG_CONFIG_HOME`, matching the user config and credential inventory.
pub(super) fn record_path() -> Result<PathBuf> {
    let home = match config::host_home_dir() {
        Ok(Some(home)) => home,
        Ok(None) => {
            return Err(anyhow!(
                "$HOME is not set; cannot locate {}",
                config::quoted_str(config::USER_CONFIG_DIR_RELATIVE)
            ));
        }
        Err(error) => {
            return Err(anyhow!(
                "{error}; cannot locate {}",
                config::quoted_str(config::USER_CONFIG_DIR_RELATIVE)
            ));
        }
    };
    Ok(home
        .join(config::USER_CONFIG_DIR_RELATIVE)
        .join(SELECTION_FILE))
}

/// The retained default, or `None` when no record exists yet.
///
/// Only a *missing* file is `None`. A record that exists but cannot be read,
/// parsed or validated is an error: auto-resetting it would silently discard
/// the user's choice (and, on a shared host, could pick a different image than
/// a concurrent session).
pub(super) fn load() -> Result<Option<ImmutableImageRef>> {
    crate::image_pin::load_default()
}

/// The image this launcher offers when no record exists. Not persisted here:
/// a default-tier preparation retains it only after the content is acquired.
pub(super) fn initial_recommendation() -> Result<ImmutableImageRef> {
    #[cfg(debug_assertions)]
    if let Some(raw) = std::env::var_os("AGENT_VM_TEST_DEFAULT_IMAGE") {
        // A boot-free CLI test that falls through to the default would
        // otherwise start a real multi-GB pull, so the seam exists — but it is
        // an *initial recommendation*, not an override of a saved record, and
        // it is held to the same immutable-reference rule as production. A
        // non-Unicode or unpinned value fails; it is never lossily converted or
        // silently replaced by the production recommendation. The value is
        // never echoed: the seam may itself be sensitive.
        let raw = raw.to_str().ok_or_else(|| {
            anyhow!("AGENT_VM_TEST_DEFAULT_IMAGE is set but is not valid Unicode")
        })?;
        return ImmutableImageRef::parse(raw).map_err(|reason| {
            anyhow!(
                "AGENT_VM_TEST_DEFAULT_IMAGE is not usable as an initial recommendation: {reason}"
            )
        });
    }
    ImmutableImageRef::parse(crate::defaults::INITIAL_DEFAULT_IMAGE_REF)
        .map_err(|reason| anyhow!("the compiled-in initial recommendation is unusable: {reason}"))
}

verus! {
fn selection_bytes_within_limit(bytes: usize) -> (ok: bool)
    ensures ok == (bytes <= 16 * 1024),
{ bytes <= 16 * 1024 }
}

/// Narrow transaction helpers. Callers hold the pin lock before the default
/// lock; these never recursively enter the coordinated reader.
pub(crate) fn decode_snapshot(bytes: &[u8]) -> Result<ImmutableImageRef> {
    if !selection_bytes_within_limit(bytes.len()) {
        return Err(anyhow!("retained default exceeds the size limit"));
    }
    let file: SelectionFile =
        serde_json::from_slice(bytes).map_err(|_| anyhow!("retained default schema is invalid"))?;
    if file.version != SELECTION_VERSION {
        return Err(anyhow!("retained default version is unsupported"));
    }
    ImmutableImageRef::parse(&file.image).map_err(|_| anyhow!("retained default digest is invalid"))
}

pub(crate) fn snapshot_at(directory: &Path) -> Result<Option<Vec<u8>>> {
    let path = directory.join(SELECTION_FILE);
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(_) => Err(selection_error(&path, "could not be examined")),
        Ok(_) => {
            let (bytes, _) =
                host_paths::read_bounded_regular_file_no_follow(&path, MAX_SELECTION_FILE_BYTES)
                    .map_err(|_| selection_error(&path, "could not be read"))?;
            decode_snapshot(&bytes)
                .map_err(|_| selection_error(&path, "is not a valid version 1 digest record"))?;
            Ok(Some(bytes))
        }
    }
}

pub(crate) fn encode_snapshot(reference: &ImmutableImageRef) -> Result<Vec<u8>> {
    let bytes = serialize_v1(reference)?;
    decode_snapshot(&bytes)?;
    Ok(bytes)
}

fn serialize_v1(reference: &ImmutableImageRef) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(&SelectionFile {
        version: SELECTION_VERSION,
        image: reference.as_str().to_string(),
    })
    .map_err(|_| anyhow!("serializing the retained default failed"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// The one diagnostic shape for record, lock and save failures: the escaped
/// path, a fixed reason, and the same two recovery options. Recovery is
/// deliberately manual: silently deleting or repairing the record would erase a
/// choice the user made. `reason` is always a fixed literal (or a fixed literal
/// with a compile-time constant); it never carries a source error or a value
/// read from the record.
fn selection_error(path: &Path, reason: &str) -> anyhow::Error {
    anyhow!(
        "boot-image selection {} {reason}; restore the intended digest record from backup, or \
         deliberately move it aside to reinitialize from the current recommendation",
        config::escape_path(path)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str =
        "localhost:1/a@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str =
        "localhost:1/b@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn parsed(reference: &str) -> ImmutableImageRef {
        ImmutableImageRef::parse(reference).expect("the fixture is immutable")
    }

    /// The snapshot helpers are the pin store's only view of this record: a
    /// complete version 1 file round-trips byte-for-byte, and `None` means the
    /// file is genuinely absent rather than unreadable.
    #[test]
    fn snapshot_round_trips_and_absence_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(snapshot_at(dir.path()).unwrap(), None);
        let bytes = encode_snapshot(&parsed(A)).unwrap();
        std::fs::write(dir.path().join(SELECTION_FILE), &bytes).unwrap();
        assert_eq!(snapshot_at(dir.path()).unwrap().unwrap(), bytes);
        assert_eq!(decode_snapshot(&bytes).unwrap().as_str(), A);
        // A hand-formatted but valid record is preserved exactly: formatting is
        // the user's, not the launcher's.
        let hand = format!("{{ \"version\" : 1 , \"image\" : \"{A}\" }}\n");
        std::fs::write(dir.path().join(SELECTION_FILE), &hand).unwrap();
        assert_eq!(snapshot_at(dir.path()).unwrap().unwrap(), hand.into_bytes());
    }

    #[test]
    fn invalid_records_fail_closed_without_repair() {
        let cases: [(&str, &str); 11] = [
            ("", "empty"),
            ("not json", "not JSON"),
            ("[]", "wrong top-level type"),
            ("{}", "missing fields"),
            (
                r#"{"version":2,"image":"localhost:1/a@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
                "unknown version",
            ),
            (
                r#"{"version":1,"image":"localhost:1/a@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","extra":1}"#,
                "unknown field",
            ),
            (
                r#"{"version":"1","image":"localhost:1/a@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
                "wrong field type",
            ),
            (
                r#"{"version":1,"image":"localhost:1/a@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","image":"localhost:1/b@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}"#,
                "duplicate field",
            ),
            (
                r#"{"version":1,"image":"localhost:1/a:latest"}"#,
                "tag only",
            ),
            (r#"{"version":1,"image":"/rootfs"}"#, "local path"),
            (
                r#"{"version":1,"image":"localhost:1/a@sha256:00ff"}"#,
                "short digest",
            ),
        ];
        for (contents, label) in cases {
            let error = decode_snapshot(contents.as_bytes()).expect_err(label);
            assert!(
                !format!("{error:#}").contains(contents) || contents.is_empty(),
                "{label}: the diagnostic echoed the record bytes"
            );
        }
        assert!(decode_snapshot(&vec![b' '; 16 * 1024 + 1]).is_err());
        assert!(decode_snapshot(b"\xff\xfe").is_err());
    }

    /// A record path that is a symlink, a directory or an oversized file is a
    /// hard error naming only the escaped path — never a silent reset.
    #[cfg(unix)]
    #[test]
    fn damaged_record_paths_fail_closed_with_an_escaped_reason() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.json");
        std::fs::write(&target, "{}").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join(SELECTION_FILE)).unwrap();
        let error = snapshot_at(dir.path()).expect_err("a symlink record must fail");
        assert!(!format!("{error:#}").contains('\u{1b}'));

        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(SELECTION_FILE)).unwrap();
        assert!(snapshot_at(dir.path()).is_err());

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(SELECTION_FILE),
            vec![b' '; MAX_SELECTION_FILE_BYTES as usize + 1],
        )
        .unwrap();
        assert!(snapshot_at(dir.path()).is_err());
    }

    /// A control-character `$HOME` (hence record path) must never reach the
    /// diagnostic raw.
    #[cfg(unix)]
    #[test]
    fn a_control_character_path_is_escaped_not_raw() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("home-\u{1b}[31m").join("agent-vm");
        std::fs::create_dir_all(&config).unwrap();
        let target = dir.path().join("target.json");
        std::fs::write(&target, "{}").unwrap();
        std::os::unix::fs::symlink(&target, config.join(SELECTION_FILE)).unwrap();

        let error = snapshot_at(&config).expect_err("a symlink record must fail");
        let display = format!("{error}");
        assert!(
            !display.contains('\u{1b}'),
            "the raw ESC reached the diagnostic: {display:?}"
        );
        assert!(
            display.contains("\\x1b"),
            "the path must be escaped, not dropped: {display:?}"
        );
        assert_eq!(
            decode_snapshot(&encode_snapshot(&parsed(B)).unwrap())
                .unwrap()
                .as_str(),
            B
        );
    }
}
