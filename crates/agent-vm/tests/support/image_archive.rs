//! A test-only writer for minimal one-image OCI layout archives.
//!
//! `agent-vm build`'s real subject is the native importer, so these fixtures
//! feed it genuine bytes rather than a mock: a `docker buildx build` fake only
//! replays one of these archives on stdout. Every digest, size and diff ID is
//! derived here from the bytes this module writes, independently of any
//! production helper, so a drift in the importer's expectations cannot be
//! masked by reusing its own computation.
//!
//! The layout is the OCI image layout `load_archive` accepts when no Docker
//! `manifest.json` is present:
//!
//! ```text
//! oci-layout                       {"imageLayoutVersion":"1.0.0"}
//! index.json                       one manifest descriptor (+ optional platform)
//! blobs/sha256/<manifest>          image manifest (config + one layer)
//! blobs/sha256/<config>            image configuration (rootfs.diff_ids)
//! blobs/sha256/<layer>             uncompressed layer tar with a marker file
//! ```
//!
//! The config's platform (`os`/`architecture`) and the index descriptor's
//! declared platform are selectable **independently**, so the difference
//! between "descriptor-declared platform is filtered out" and "config platform
//! is not compared to the host" is a fixture knob, not a guess.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

/// Platform fields to declare, independently for the config and the index
/// descriptor. `Absent` omits the fields entirely.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlatformSpec {
    /// Omit the platform fields (config: omit `os`/`architecture`; descriptor:
    /// omit `platform`).
    Absent,
    /// The running host's Linux platform.
    Host,
    /// A Linux platform with the *other* architecture.
    Foreign,
    /// An explicit `(os, architecture)` pair.
    OsArch(String, String),
}

impl PlatformSpec {
    fn resolve(&self) -> Option<(String, String)> {
        match self {
            Self::Absent => None,
            Self::Host => Some((HOST_OS.to_string(), host_arch().to_string())),
            Self::Foreign => Some((HOST_OS.to_string(), foreign_arch().to_string())),
            Self::OsArch(os, arch) => Some((os.clone(), arch.clone())),
        }
    }
}

const HOST_OS: &str = "linux";

/// The runtime's `Arch` spelling for the running host.
pub fn host_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => panic!("this harness supports x86_64 and aarch64, not {other}"),
    }
}

/// The other architecture this harness knows how to be "foreign" to.
fn foreign_arch() -> &'static str {
    match host_arch() {
        "amd64" => "arm64",
        _ => "amd64",
    }
}

/// How the layer blob is written relative to its descriptors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayerContent {
    /// A valid uncompressed tar containing the marker file; descriptors match.
    Valid,
    /// Arbitrary bytes that are not a tar; descriptors match (so this is an
    /// integrity-valid but unmaterializable layer stream).
    NotATar,
    /// Write a valid tar for one marker while declaring the descriptors of a
    /// different layer, so archive verification fails.
    DigestMismatch,
}

/// A fixture specification. `Default` is a valid host image with a small
/// `"A"` marker.
#[derive(Clone, Debug)]
pub struct ArchiveSpec {
    /// Contents of the `marker` regular file inside the layer.
    pub marker: String,
    /// `os`/`architecture` in the image config.
    pub config_platform: PlatformSpec,
    /// `platform` on the index descriptor.
    pub descriptor_platform: PlatformSpec,
    /// How the layer blob relates to its descriptors.
    pub layer: LayerContent,
    /// Omit the layer blob entry from the archive entirely.
    pub omit_layer_blob: bool,
}

impl Default for ArchiveSpec {
    fn default() -> Self {
        Self {
            marker: "A".to_string(),
            config_platform: PlatformSpec::Host,
            descriptor_platform: PlatformSpec::Host,
            layer: LayerContent::Valid,
            omit_layer_blob: false,
        }
    }
}

/// What the fixture's references resolved to, derived from the bytes written.
#[derive(Clone, Debug)]
pub struct Written {
    pub path: PathBuf,
    pub marker: String,
    /// Descriptor digest of the image manifest blob.
    pub manifest_digest: String,
    /// Descriptor digest of the image config blob.
    pub config_digest: String,
    /// Descriptor digest of the layer blob.
    pub layer_digest: String,
    /// The config's single `rootfs.diff_ids` entry.
    pub diff_id: String,
    /// `sha256:` hex of the marker file's tar bytes.
    pub layer_tar_sha256: String,
}

/// Write `spec` as an OCI layout tar at `path`, returning its derived values.
pub fn write(path: &Path, spec: &ArchiveSpec) -> Written {
    let (stored, declared) = match spec.layer {
        LayerContent::Valid | LayerContent::NotATar => {
            let bytes = if spec.layer == LayerContent::Valid {
                layer_tar(&spec.marker)
            } else {
                b"this is not a tar stream".to_vec()
            };
            (bytes.clone(), bytes)
        }
        LayerContent::DigestMismatch => (
            layer_tar(&format!("{}-stored", spec.marker)),
            layer_tar(&format!("{}-declared", spec.marker)),
        ),
    };

    let layer_digest = sha256_hex(&declared);
    let diff_id = layer_digest.clone();

    let config_bytes = config_json(spec, &diff_id);
    let config_digest = sha256_hex(&config_bytes);

    let manifest_bytes = manifest_json(
        &config_digest,
        config_bytes.len(),
        &layer_digest,
        declared.len(),
    );
    let manifest_digest = sha256_hex(&manifest_bytes);

    let index_bytes = index_json(spec, &manifest_digest, manifest_bytes.len());

    let mut builder = tar::Builder::new(Vec::new());
    append(
        &mut builder,
        "oci-layout",
        br#"{"imageLayoutVersion":"1.0.0"}"#,
    );
    append(&mut builder, "index.json", &index_bytes);
    append(&mut builder, &blob_path(&manifest_digest), &manifest_bytes);
    append(&mut builder, &blob_path(&config_digest), &config_bytes);
    if !spec.omit_layer_blob {
        append(&mut builder, &blob_path(&layer_digest), &stored);
    }
    let archive = builder.into_inner().expect("finish archive tar");
    std::fs::write(path, &archive).expect("write archive fixture");

    Written {
        path: path.to_path_buf(),
        marker: spec.marker.clone(),
        manifest_digest,
        config_digest,
        layer_digest,
        diff_id,
        layer_tar_sha256: sha256_hex(&layer_tar(&spec.marker)),
    }
}

/// Write an archive whose bytes are not a valid tar at all.
pub fn write_garbage(path: &Path) {
    std::fs::write(path, b"not an archive at all, just bytes").expect("write garbage fixture");
}

fn config_json(spec: &ArchiveSpec, diff_id: &str) -> Vec<u8> {
    let mut doc = serde_json::Map::new();
    if let Some((os, arch)) = spec.config_platform.resolve() {
        doc.insert("os".to_string(), os.into());
        doc.insert("architecture".to_string(), arch.into());
    }
    doc.insert(
        "config".to_string(),
        serde_json::json!({
            "Env": [format!("MARKER={}", spec.marker)],
            "Cmd": ["/bin/marker"],
        }),
    );
    doc.insert(
        "rootfs".to_string(),
        serde_json::json!({ "type": "layers", "diff_ids": [diff_id] }),
    );
    serde_json::to_vec(&serde_json::Value::Object(doc)).expect("serialize config")
}

fn manifest_json(
    config_digest: &str,
    config_size: usize,
    layer_digest: &str,
    layer_size: usize,
) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config_digest,
            "size": config_size,
        },
        "layers": [{
            "mediaType": "application/vnd.oci.image.layer.v1.tar",
            "digest": layer_digest,
            "size": layer_size,
        }],
    }))
    .expect("serialize manifest")
}

fn index_json(spec: &ArchiveSpec, manifest_digest: &str, manifest_size: usize) -> Vec<u8> {
    let mut descriptor = serde_json::Map::new();
    descriptor.insert(
        "mediaType".to_string(),
        "application/vnd.oci.image.manifest.v1+json".into(),
    );
    descriptor.insert("digest".to_string(), manifest_digest.into());
    descriptor.insert("size".to_string(), manifest_size.into());
    if let Some((os, arch)) = spec.descriptor_platform.resolve() {
        descriptor.insert(
            "platform".to_string(),
            serde_json::json!({ "os": os, "architecture": arch }),
        );
    }
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [serde_json::Value::Object(descriptor)],
    }))
    .expect("serialize index")
}

/// A valid uncompressed layer tar with one small regular `marker` file.
pub fn layer_tar(marker: &str) -> Vec<u8> {
    let content = format!("{marker}\n").into_bytes();
    let mut header = tar::Header::new_gnu();
    header.set_size(content.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    let mut builder = tar::Builder::new(Vec::new());
    builder
        .append_data(&mut header, "marker", content.as_slice())
        .expect("append marker");
    builder.into_inner().expect("finish layer tar")
}

fn append(builder: &mut tar::Builder<Vec<u8>>, name: &str, bytes: &[u8]) {
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    builder
        .append_data(&mut header, name, bytes)
        .unwrap_or_else(|error| panic!("append {name}: {error}"));
}

fn blob_path(digest: &str) -> String {
    let hex = digest.strip_prefix("sha256:").expect("sha256 digest");
    format!("blobs/sha256/{hex}")
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("sha256:{}", hex_lower(&Sha256::digest(bytes)))
}

/// Lowercase hex of a byte slice, so the fixture does not need a `hex`
/// dependency the production crate does not have.
fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).expect("high nibble"));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).expect("low nibble"));
    }
    out
}
