//! Advisory digest baseline for the opt-in launch update banner.
//!
//! `image refresh` and setup record the validated native acquisition's resolved
//! host-manifest digest under the original selected reference. A launch may
//! seed an absent marker from its cached image. This is banner state, never an
//! approval record, publication token or proof of current cache identity: other
//! cache writers need not update it, and marker-write failures are nonfatal.
//!
//! Atomic rename prevents a partially written digest from becoming the banner
//! baseline. It does not couple the marker to native cache publication or the
//! retained default record.

use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::host_paths::{atomic_write, state_root};

pub fn read(image_ref: &str) -> Option<String> {
    let path = marker_path(image_ref)?;
    fs::read_to_string(&path).ok().map(|s| s.trim().to_string())
}

pub fn write(image_ref: &str, digest: &str) -> Result<()> {
    let Some(path) = marker_path(image_ref) else {
        return Ok(());
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    atomic_write(&path, digest.as_bytes(), 0o644)
}

fn marker_path(image_ref: &str) -> Option<PathBuf> {
    Some(state_root()?.join("pulled-digests").join(hash(image_ref)))
}

fn hash(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    let d = h.finalize();
    let mut out = String::with_capacity(16);
    for b in &d[..8] {
        use std::fmt::Write;
        write!(out, "{b:02x}").unwrap();
    }
    out
}
