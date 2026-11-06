//! The complete digest-addressed artifact inventory of one cached image.
//!
//! "Unchanged by a failed operation" is only meaningful if the oracle covers
//! every artifact an import materializes. Completeness alone is not enough
//! (`CONTRIBUTING.md`), and neither is metadata plus one layer: the native
//! importer also writes fsmeta, a VMDK descriptor and the layer tar blob, and a
//! descriptor names extents outside the content directory. So this module
//! derives the inventory from **independently parsed baseline metadata and
//! descriptor** references — never from a post-failure pull result — and hashes
//! complete bytes, because a structurally valid replacement EROFS is still a
//! failure.
//!
//! `#![allow(dead_code)]` like `pin_gate.rs`: each including binary uses the part
//! it needs.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use microsandbox_image::{GlobalCache, Reference};

use crate::image_archive::{self, Written};

/// Independently checked baseline metadata plus every artifact path it names.
///
/// Returns the immutable metadata file separately: a caller that re-publishes the
/// same reference expects that file to be replaced, while everything
/// content-addressed below it must survive byte-identically.
pub fn artifact_paths(
    cache: &GlobalCache,
    reference: &str,
    written: &Written,
) -> (PathBuf, Vec<PathBuf>) {
    assert!(
        !written.manifest_digest.is_empty(),
        "the inventory needs an OCI fixture: a Docker-save fixture has no manifest digest to key \
         artifacts by"
    );
    let reference: Reference = reference.parse().unwrap();
    let metadata_path = cache.image_metadata_path(&reference);
    let metadata_bytes = fs::read(&metadata_path).unwrap();
    let metadata: serde_json::Value = serde_json::from_slice(&metadata_bytes).unwrap();
    assert_eq!(metadata["manifest_digest"], written.manifest_digest);
    assert_eq!(metadata["config_digest"], written.config_digest);
    assert_eq!(
        image_archive::sha256_hex(metadata["raw_manifest_json"].as_str().unwrap().as_bytes()),
        written.manifest_digest
    );
    assert_eq!(
        image_archive::sha256_hex(metadata["raw_config_json"].as_str().unwrap().as_bytes()),
        written.config_digest
    );
    assert_eq!(metadata["layers"][0]["diff_id"], written.diff_id);
    let manifest = written.manifest_digest.parse().unwrap();
    let descriptor = cache.vmdk_path(&manifest);
    let mut paths = vec![cache.fsmeta_erofs_path(&manifest), descriptor.clone()];
    for layer in metadata["layers"].as_array().unwrap() {
        paths.push(cache.layer_erofs_path(&layer["diff_id"].as_str().unwrap().parse().unwrap()));
        let tar = cache.tar_path(&layer["digest"].as_str().unwrap().parse().unwrap());
        if tar.exists() {
            paths.push(tar);
        }
    }
    let descriptor_bytes = fs::read_to_string(&descriptor).unwrap();
    for line in descriptor_bytes
        .lines()
        .filter(|line| line.starts_with("RW ") || line.starts_with("RDONLY "))
    {
        if let Some(path) = line.split('"').nth(1) {
            let path = Path::new(path);
            paths.push(if path.is_absolute() {
                path.to_owned()
            } else {
                descriptor.parent().unwrap().join(path)
            });
        }
    }
    (metadata_path, paths)
}

/// Length plus SHA-256 of every path's complete bytes.
pub fn hash_paths(paths: impl IntoIterator<Item = PathBuf>) -> BTreeMap<PathBuf, (u64, String)> {
    paths
        .into_iter()
        .map(|path| {
            let bytes = fs::read(&path).unwrap();
            (
                path,
                (bytes.len() as u64, image_archive::sha256_hex(&bytes)),
            )
        })
        .collect()
}

/// Assert every path still has exactly the length and hash it had.
pub fn assert_unchanged(files: &BTreeMap<PathBuf, (u64, String)>) {
    for (path, (len, hash)) in files {
        let bytes = fs::read(path).unwrap();
        assert_eq!(bytes.len() as u64, *len, "{}", path.display());
        assert_eq!(
            image_archive::sha256_hex(&bytes),
            *hash,
            "{}",
            path.display()
        );
    }
}

/// Every artifact preserved from a failed operation, keyed by path.
pub struct Inventory(BTreeMap<PathBuf, (u64, String)>);

impl Inventory {
    /// Snapshot the artifacts of one approved `repo@digest`, including its
    /// immutable metadata file.
    pub fn take(cache: &GlobalCache, immutable_reference: &str, written: &Written) -> Self {
        let (metadata, others) = artifact_paths(cache, immutable_reference, written);
        Self(hash_paths(std::iter::once(metadata).chain(others)))
    }

    /// Snapshot only what is content-addressed below the reference, excluding
    /// its metadata file — for an operation that legitimately republishes that
    /// file.
    pub fn take_content_addressed(
        cache: &GlobalCache,
        immutable_reference: &str,
        written: &Written,
    ) -> Self {
        let (_, others) = artifact_paths(cache, immutable_reference, written);
        Self(hash_paths(others))
    }

    pub fn unchanged(&self) {
        assert_unchanged(&self.0);
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}
