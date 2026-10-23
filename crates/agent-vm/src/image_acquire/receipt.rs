//! Cache-only receipts for validated native image content.
//!
//! A receipt records facts this process *validated*: the canonical acquired
//! `repo@digest`, the host Linux platform, the preserved native metadata, the
//! verified content identity, and the source bindings the registry was observed
//! to satisfy. Bindings share one child-keyed content record rather than
//! duplicating metadata per source, and they are **best-effort provenance, never
//! authority**: a full set keeps every association it already proves and leaves
//! the new source unproven (a later unequal cache association then reacquires
//! that immutable source) instead of evicting a proven one or failing content
//! this process already validated. Writer-side, only a source that states an
//! immutable digest is ever bound, because that is the only case the association
//! check consults. It lives inside the native image
//! cache, beside the metadata it describes, and is **not an
//! approval store**: deleting the cache deletes receipts, deleting a receipt
//! grants nothing, and no host authority path is touched.
//!
//! # Why a receipt at all
//!
//! Native acquisition and archive loading both key metadata by *reference*, so
//! an import that publishes `repo@A` overwrites an entry that happens to be
//! keyed by that spelling. The receipt is outside the loader's namespace: it
//! lets a later preparation detect that the canonical entry no longer matches
//! the content validated for it, and repair it from the preserved metadata.
//! It also carries the source→acquired association for an immutable source
//! whose cached manifest digest legitimately differs (an index resolving to its
//! host child), which cache completeness alone cannot establish.
//!
//! # Schema discipline
//!
//! Every nested record is `deny_unknown_fields` and every field is mirrored
//! rather than reusing a native type, because the native `CachedImageMetadata`
//! does not deny unknown fields: an old or future launcher must not be able to
//! add meaning here. Reads are bounded, no-follow, regular-file only and reject
//! trailing bytes. A corrupt receipt is a hard cache error, never "no receipt".

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use microsandbox_image::{CachedImageMetadata, CachedLayerMetadata, ImageConfig, Platform};
use serde::{Deserialize, Serialize};
use vstd::prelude::*;

use super::reference::{CanonicalOciReference, PinnedReference, ValidatedDigest};

/// The directory under the native cache. Deliberately *not* under `manifests/`,
/// which the native loader owns.
pub(crate) const RECEIPT_DIRECTORY: &str = "agent-vm-content-metadata";

/// The one accepted receipt schema version. Written by the encoder and required
/// by the reader from this single declaration.
const RECEIPT_VERSION: u32 = 1;

/// Never evict a proven association merely to admit another source, and never
/// fail validated content because the provenance set is full.
const MAX_SOURCE_BINDINGS: usize = 256;

/// The host OS a receipt is only ever meaningful for.
const RECEIPT_HOST_OS: &str = "linux";

/// Bound on a receipt's platform architecture spelling.
const MAX_PLATFORM_ARCHITECTURE_BYTES: usize = 64;

/// Bound on a receipt's platform variant spelling.
const MAX_PLATFORM_VARIANT_BYTES: usize = 64;

/// The only bytes a variant spelling may contain: visible ASCII, which admits
/// every OCI variant (`v8`, `v8.2`) and refuses whitespace, control bytes and
/// non-ASCII.
const PRINTABLE_ASCII: std::ops::RangeInclusive<u8> = 0x21..=0x7e;

/// The one printable-variant alphabet, shared with the host approval store so the
/// receipt schema and the pin schema cannot accept different variant spellings.
pub(crate) fn is_printable_variant_byte(byte: u8) -> bool {
    PRINTABLE_ASCII.contains(&byte)
}

/// The one repair instruction for any unusable receipt. Written once and used by
/// every rendering, including the launch path's. Cache-side only: a receipt is
/// cache content, and HOME approval records are a different store that ignoring
/// or deleting this file neither needs nor grants.
pub(crate) const RECEIPT_REPAIR_GUIDANCE: &str = "restore the image cache from a backup, or remove the content receipt and re-acquire the image, before retrying";

/// One validated source→acquired binding.
///
/// The source text is the canonical selected *source* (a tag or a digest); the
/// optional digest is the immutable identity the source stated. Both survive
/// independently of the acquired digest, which native verification may
/// legitimately resolve to a different algorithm or a host child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceBinding {
    pub(crate) reference: String,
    pub(crate) stated_digest: Option<ValidatedDigest>,
}

impl SourceBinding {
    /// The binding a canonical source states: its text plus its own digest,
    /// when it names one. The one place a binding is derived, so the acquisition
    /// writer and the validated token cannot disagree.
    pub(crate) fn of(source: &CanonicalOciReference) -> Self {
        Self {
            reference: source.whole(),
            stated_digest: source.digest().cloned(),
        }
    }
}

/// The content identity used to compare two acquisitions of the same guest
/// content: the verified config blob digest and the ordered layer diff IDs.
///
/// Not a manifest byte-identity claim: the native materializer re-serializes
/// manifests, so equality here means "the config and the ordered layer contents
/// are the same", which is what a guest consumes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ContentIdentity {
    pub(crate) config_digest: String,
    pub(crate) diff_ids: Vec<String>,
}

impl ContentIdentity {
    pub(crate) fn of(metadata: &CachedImageMetadata) -> Self {
        Self {
            config_digest: metadata.config_digest.clone(),
            diff_ids: metadata
                .layers
                .iter()
                .map(|layer| layer.diff_id.clone())
                .collect(),
        }
    }
}

/// Why a receipt could not be read, written or trusted. Closed text: a cache
/// error may concern a private image, and the bytes are untrusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReceiptError {
    /// The encoded form exceeds [`MAX_RECEIPT_BYTES`] or a field bound.
    TooLarge,
    /// Not UTF-8, malformed JSON, unknown/duplicate/missing field, trailing
    /// bytes, noncanonical reference, invalid digest/platform, or a metadata
    /// mismatch.
    Corrupt,
    /// The filesystem refused the read or write (including a symlink or a
    /// non-regular entry).
    Io,
    /// The same encoded receipt could not be serialized (an internal error).
    Encode,
    /// One child/platform cannot preserve two different content identities.
    IdentityConflict,
    /// The stored or encoded receipt already holds more bindings than the bound
    /// allows. Merging never produces this: a full set skips the addition.
    BindingLimit,
}

impl ReceiptError {
    pub(crate) fn describe(self) -> &'static str {
        match self {
            Self::TooLarge => "the image cache content receipt exceeds its size limit",
            Self::Corrupt => "the image cache content receipt is corrupt",
            Self::Io => "reading or writing the image cache content receipt failed",
            Self::Encode => "encoding the image cache content receipt failed",
            Self::IdentityConflict => "the image cache content receipt has a conflicting identity",
            Self::BindingLimit => {
                "the image cache content receipt holds more source bindings than its limit allows"
            }
        }
    }
}

/// What merging another receipt's bindings did. A merge that learns nothing is
/// not a change worth writing back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MergedBinding {
    /// At least one source was added to the set.
    Learned,
    /// Every source was already stored, or the set was full.
    Unchanged,
}

impl std::fmt::Display for ReceiptError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.describe())
    }
}

impl std::error::Error for ReceiptError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptFile {
    version: u32,
    acquired_reference: String,
    acquired_digest: String,
    platform: ReceiptPlatform,
    metadata: ReceiptMetadata,
    source_bindings: Vec<ReceiptSource>,
    content_identity: ContentIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptPlatform {
    os: String,
    architecture: String,
    variant: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptSource {
    reference: String,
    stated_digest: Option<String>,
}

impl From<&SourceBinding> for ReceiptSource {
    fn from(binding: &SourceBinding) -> Self {
        Self {
            reference: binding.reference.clone(),
            stated_digest: binding
                .stated_digest
                .as_ref()
                .map(|digest| digest.as_str().to_owned()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptMetadata {
    manifest_digest: String,
    config_digest: String,
    raw_manifest_json: String,
    raw_config_json: String,
    config: ReceiptConfig,
    layers: Vec<ReceiptLayer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptConfig {
    env: Vec<String>,
    cmd: Option<Vec<String>>,
    entrypoint: Option<Vec<String>>,
    working_dir: Option<String>,
    user: Option<String>,
    exposed_ports: Vec<String>,
    volumes: Vec<String>,
    labels: BTreeMap<String, String>,
    stop_signal: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptLayer {
    digest: String,
    media_type: Option<String>,
    size_bytes: Option<u64>,
    diff_id: String,
}

/// One validated receipt. Construction validates everything it can measure;
/// callers can only obtain one through [`Receipt::new`] or [`Receipt::read`].
#[derive(Debug, Clone)]
pub(crate) struct Receipt {
    file: ReceiptFile,
    /// The typed binding measured at construction/read, so consumers never
    /// re-parse stored strings.
    sources: Vec<SourceBinding>,
}

impl Receipt {
    /// Build a receipt from facts a validated acquisition measured.
    pub(crate) fn new(
        acquired: &PinnedReference,
        platform: &Platform,
        metadata: &CachedImageMetadata,
        source: Option<SourceBinding>,
    ) -> Result<Self, ReceiptError> {
        let file = ReceiptFile {
            version: RECEIPT_VERSION,
            acquired_reference: acquired.whole(),
            acquired_digest: acquired.digest().as_str().to_owned(),
            platform: receipt_platform(platform),
            metadata: metadata.into(),
            source_bindings: source.iter().map(ReceiptSource::from).collect(),
            content_identity: ContentIdentity::of(metadata),
        };
        Self::measured(file)
    }

    fn measured(file: ReceiptFile) -> Result<Self, ReceiptError> {
        let sources = file
            .source_bindings
            .iter()
            .map(|stored| {
                Ok(SourceBinding {
                    reference: stored.reference.clone(),
                    stated_digest: stored
                        .stated_digest
                        .as_deref()
                        .map(ValidatedDigest::parse)
                        .transpose()
                        .map_err(|_| ReceiptError::Corrupt)?,
                })
            })
            .collect::<Result<Vec<_>, ReceiptError>>()?;
        let receipt = Self { file, sources };
        receipt.validate()?;
        Ok(receipt)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, ReceiptError> {
        if !receipt_size_within_limit(bytes.len()) {
            return Err(ReceiptError::TooLarge);
        }
        let file: ReceiptFile = serde_json::from_slice(bytes).map_err(|_| ReceiptError::Corrupt)?;
        Self::measured(file)
    }

    /// Called only under the child guard after a fresh acquisition or a proven
    /// cache hit. Equal content can learn another source, never replace one.
    ///
    /// A full binding set is not an error: bindings are best-effort provenance,
    /// so the set keeps what it proves and leaves this source unproven rather
    /// than evicting a proven association or failing a validated acquisition.
    pub(crate) fn merge(&mut self, incoming: &Self) -> Result<MergedBinding, ReceiptError> {
        if self.file.acquired_reference != incoming.file.acquired_reference
            || self.file.platform != incoming.file.platform
            || self.content_identity() != incoming.content_identity()
        {
            return Err(ReceiptError::IdentityConflict);
        }
        let mut merged = MergedBinding::Unchanged;
        for source in &incoming.sources {
            if self.sources.contains(source) || self.sources.len() == MAX_SOURCE_BINDINGS {
                continue;
            }
            self.file.source_bindings.push(ReceiptSource::from(source));
            self.sources.push(source.clone());
            merged = MergedBinding::Learned;
        }
        self.validate()?;
        Ok(merged)
    }

    pub(crate) fn metadata(&self) -> CachedImageMetadata {
        (&self.file.metadata).into()
    }

    pub(crate) fn proves(&self, source: &SourceBinding) -> bool {
        self.sources.contains(source)
    }

    pub(crate) fn content_identity(&self) -> ContentIdentity {
        ContentIdentity::of(&self.metadata())
    }

    /// The receipt path for this acquired identity and platform. The file name
    /// hashes length-delimited inputs so two different triples cannot collide
    /// by concatenation.
    pub(crate) fn path(
        cache_dir: &Path,
        acquired: &PinnedReference,
        platform: &Platform,
    ) -> PathBuf {
        cache_dir
            .join(RECEIPT_DIRECTORY)
            .join(format!("{}.json", receipt_name(acquired, platform)))
    }

    /// Read the receipt for this acquired identity/platform.
    ///
    /// Only `ENOENT` is "absent". A symlink, non-regular entry, oversized file,
    /// unreadable file or invalid schema is an error.
    pub(crate) fn read(
        cache_dir: &Path,
        acquired: &PinnedReference,
        platform: &Platform,
    ) -> Result<Option<Self>, ReceiptError> {
        let path = Self::path(cache_dir, acquired, platform);
        // One bounded, no-follow read: only `ENOENT` is absent. A symlink, a
        // non-regular entry, an oversized file or an I/O failure is a hard cache
        // error, never "no receipt".
        let bytes = match crate::host_paths::read_optional_bounded_regular_file_no_follow(
            &path,
            MAX_RECEIPT_BYTES,
        ) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Ok(None),
            Err(_) => return Err(ReceiptError::Io),
        };
        let receipt = Self::from_bytes(&bytes)?;
        // The file name is a hash of the identity it holds, so a receipt copied
        // from another key still has to *say* this key: file placement alone is
        // never authority over what the bytes describe.
        if receipt.file.acquired_reference != acquired.whole() || receipt.platform() != *platform {
            return Err(ReceiptError::Corrupt);
        }
        Ok(Some(receipt))
    }

    /// Publish atomically (0600, no-follow temporary + rename). The directory
    /// is created 0700 when missing; an existing directory is never chmodded.
    pub(crate) fn write(&self, cache_dir: &Path) -> Result<(), ReceiptError> {
        self.validate()?;
        let bytes = serde_json::to_vec(&self.file).map_err(|_| ReceiptError::Encode)?;
        if !receipt_size_within_limit(bytes.len()) {
            return Err(ReceiptError::TooLarge);
        }
        let platform = self.platform();
        let acquired = CanonicalOciReference::parse(&self.file.acquired_reference)
            .map_err(|_| ReceiptError::Corrupt)?
            .with_digest(
                &ValidatedDigest::parse(&self.file.acquired_digest)
                    .map_err(|_| ReceiptError::Corrupt)?,
            )
            .map_err(|_| ReceiptError::Corrupt)?;
        let directory = cache_dir.join(RECEIPT_DIRECTORY);
        create_private_directory(&directory)?;
        crate::host_paths::atomic_write(&Self::path(cache_dir, &acquired, &platform), &bytes, 0o600)
            .map_err(|_| ReceiptError::Io)
    }

    fn platform(&self) -> Platform {
        let mut platform = Platform::new(
            self.file.platform.os.as_str(),
            self.file.platform.architecture.as_str(),
        );
        platform.variant = self.file.platform.variant.clone();
        platform
    }

    /// Re-measure every fact a consumer trusts. Called on both construction and
    /// read, so a written receipt cannot skip a rule a read enforces.
    fn validate(&self) -> Result<(), ReceiptError> {
        let file = &self.file;
        if file.version != RECEIPT_VERSION {
            return Err(ReceiptError::Corrupt);
        }
        if file.source_bindings.len() > MAX_SOURCE_BINDINGS {
            return Err(ReceiptError::BindingLimit);
        }
        if !reference_within_limit(file.acquired_reference.len())
            || file
                .source_bindings
                .iter()
                .any(|source| !reference_within_limit(source.reference.len()))
        {
            return Err(ReceiptError::TooLarge);
        }
        if file.content_identity != ContentIdentity::of(&self.metadata()) {
            return Err(ReceiptError::Corrupt);
        }
        for (index, source) in self.sources.iter().enumerate() {
            if self.sources[..index].contains(source) {
                return Err(ReceiptError::Corrupt);
            }
        }
        let acquired = CanonicalOciReference::parse(&file.acquired_reference)
            .map_err(|_| ReceiptError::Corrupt)?;
        // The acquired reference *is* repo@digest, exactly as stored, and its
        // digest is the stored one. Anything else would let two identities
        // disagree.
        if acquired.whole() != file.acquired_reference
            || acquired.digest().map(ValidatedDigest::as_str) != Some(file.acquired_digest.as_str())
        {
            return Err(ReceiptError::Corrupt);
        }
        validate_platform(&file.platform)?;
        for source in &file.source_bindings {
            let parsed = CanonicalOciReference::parse(&source.reference)
                .map_err(|_| ReceiptError::Corrupt)?;
            if parsed.whole() != source.reference {
                return Err(ReceiptError::Corrupt);
            }
            match (&source.stated_digest, parsed.digest()) {
                (Some(digest), Some(parsed_digest)) if digest == parsed_digest.as_str() => {}
                (None, None) => {}
                // A source binding either states the digest its reference
                // states, or states none.
                _ => return Err(ReceiptError::Corrupt),
            }
        }
        if file.metadata.manifest_digest != file.acquired_digest {
            return Err(ReceiptError::Corrupt);
        }
        if file
            .metadata
            .config_digest
            .parse::<microsandbox_image::Digest>()
            .is_err()
        {
            return Err(ReceiptError::Corrupt);
        }
        // The preserved metadata's own platform must still be this host Linux
        // one: a receipt is only meaningful for the platform key it lives under.
        let measured = check_metadata_platform(&file.metadata.raw_config_json)?;
        if measured != file.platform {
            return Err(ReceiptError::Corrupt);
        }
        for layer in &file.metadata.layers {
            if layer.digest.parse::<microsandbox_image::Digest>().is_err()
                || layer.diff_id.parse::<microsandbox_image::Digest>().is_err()
            {
                return Err(ReceiptError::Corrupt);
            }
        }
        let encode_len = serde_json::to_vec(file)
            .map_err(|_| ReceiptError::Encode)?
            .len();
        if !receipt_size_within_limit(encode_len) {
            return Err(ReceiptError::TooLarge);
        }
        Ok(())
    }
}

verus! {
// The two receipt bounds are declared *inside* the `verus!` block because Verus
// cannot read a `const` declared outside it (`msb_install.rs` and
// `network_requests.rs` keep theirs there for the same reason); the `ensures`
// clauses below name them directly, so the executable and the spec limit are
// one item with one literal and cannot drift apart.

/// The whole encoded/read receipt bound, including nested native metadata.
/// `pub(crate)` only because Verus forbids a `pub(crate)` function's `ensures`
/// from naming a module-private const; it is still used only in this module.
pub(crate) const MAX_RECEIPT_BYTES_USIZE: usize = 16 * 1024 * 1024;
pub(crate) const MAX_RECEIPT_BYTES: u64 = MAX_RECEIPT_BYTES_USIZE as u64;

/// The bound on any canonical reference field (source or acquired).
pub(crate) const MAX_RECEIPT_REFERENCE_BYTES: usize = 4096;

/// The measured platform facts. Named fields rather than adjacent booleans, so
/// an argument swap cannot invert the decision.
pub(crate) struct PlatformFacts {
    pub(crate) os_is_host: bool,
    pub(crate) architecture_is_bounded_nonempty: bool,
    pub(crate) architecture_is_oci: bool,
    pub(crate) variant_present: bool,
    pub(crate) variant_is_bounded_nonempty: bool,
    pub(crate) variant_is_printable: bool,
}

/// The receipt platform acceptance decision over measured facts: the host OS,
/// a bounded nonempty OCI architecture, and — only when a variant is present — a
/// bounded nonempty printable one. Total over all 64 combinations, so acceptance
/// never bypasses a limit.
pub(crate) fn platform_is_acceptable(facts: PlatformFacts) -> (accepted: bool)
    ensures accepted == (facts.os_is_host
        && facts.architecture_is_bounded_nonempty
        && facts.architecture_is_oci
        && (!facts.variant_present
            || (facts.variant_is_bounded_nonempty && facts.variant_is_printable)))
{
    facts.os_is_host
        && facts.architecture_is_bounded_nonempty
        && facts.architecture_is_oci
        && (!facts.variant_present
            || (facts.variant_is_bounded_nonempty && facts.variant_is_printable))
}

// The bytes-independent reference bound. Only the size is decided here.
pub(crate) fn reference_within_limit(measured_bytes: usize) -> (within: bool)
    ensures within == (measured_bytes <= MAX_RECEIPT_REFERENCE_BYTES)
{
    measured_bytes <= MAX_RECEIPT_REFERENCE_BYTES
}

/// The receipt size limit decision, over an already-measured length.
pub(crate) fn receipt_size_within_limit(measured_bytes: usize) -> (within: bool)
    ensures within == (measured_bytes <= MAX_RECEIPT_BYTES_USIZE)
{
    measured_bytes <= MAX_RECEIPT_BYTES_USIZE
}
} // verus!

fn receipt_name(acquired: &PinnedReference, platform: &Platform) -> String {
    use sha2::{Digest, Sha256};
    let version = RECEIPT_VERSION.to_string();
    let reference = acquired.whole();
    let os = platform.os.to_string();
    let arch = platform.arch.to_string();
    let variant = platform.variant.as_deref().unwrap_or("");
    let mut hasher = Sha256::new();
    for field in [
        version.as_bytes(),
        reference.as_bytes(),
        os.as_bytes(),
        arch.as_bytes(),
        variant.as_bytes(),
    ] {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
    let digest = hasher.finalize();
    let mut name = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(name, "{byte:02x}");
    }
    name
}

fn receipt_platform(platform: &Platform) -> ReceiptPlatform {
    ReceiptPlatform {
        os: platform.os.to_string(),
        architecture: platform.arch.to_string(),
        variant: platform.variant.clone(),
    }
}

/// One architecture byte: the OCI architecture grammar (`arm64`, `x86_64`,
/// `arm.v8`) and nothing else.
fn is_architecture_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
}

/// Prove a stored platform is one a receipt may describe.
///
/// The stored bytes are untrusted cache input, so every limit is decided by the
/// contracted [`platform_is_acceptable`] kernel over measured facts.
fn validate_platform(platform: &ReceiptPlatform) -> Result<(), ReceiptError> {
    let facts = PlatformFacts {
        os_is_host: platform.os == RECEIPT_HOST_OS,
        architecture_is_bounded_nonempty: !platform.architecture.is_empty()
            && platform.architecture.len() <= MAX_PLATFORM_ARCHITECTURE_BYTES,
        architecture_is_oci: platform.architecture.bytes().all(is_architecture_byte),
        variant_present: platform.variant.is_some(),
        variant_is_bounded_nonempty: platform.variant.as_ref().is_some_and(|variant| {
            !variant.is_empty() && variant.len() <= MAX_PLATFORM_VARIANT_BYTES
        }),
        variant_is_printable: platform
            .variant
            .as_ref()
            .is_none_or(|variant| variant.bytes().all(is_printable_variant_byte)),
    };
    if platform_is_acceptable(facts) {
        Ok(())
    } else {
        Err(ReceiptError::Corrupt)
    }
}

/// Measure the OS/architecture/variant out of preserved raw config JSON.
///
/// The measurement is lenient about unrelated OCI fields (a real config carries
/// `created`, `history`, `config`, …); it only requires the fields this cache
/// key depends on to be present and well shaped.
fn check_metadata_platform(raw_config: &str) -> Result<ReceiptPlatform, ReceiptError> {
    #[derive(Deserialize)]
    struct Measured {
        os: String,
        architecture: String,
        #[serde(default)]
        variant: Option<String>,
        #[serde(default)]
        rootfs: Rootfs,
    }
    #[derive(Deserialize, Default)]
    struct Rootfs {
        #[serde(rename = "type", default)]
        _kind: Option<String>,
        #[serde(default)]
        diff_ids: Vec<String>,
    }
    let measured: Measured = serde_json::from_str(raw_config).map_err(|_| ReceiptError::Corrupt)?;
    if measured
        .rootfs
        .diff_ids
        .iter()
        .any(|diff| diff.parse::<microsandbox_image::Digest>().is_err())
    {
        return Err(ReceiptError::Corrupt);
    }
    Ok(ReceiptPlatform {
        os: measured.os,
        architecture: measured.architecture,
        variant: measured.variant,
    })
}

fn create_private_directory(directory: &Path) -> Result<(), ReceiptError> {
    use std::os::unix::fs::DirBuilderExt;
    match std::fs::DirBuilder::new().mode(0o700).create(directory) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(_) => Err(ReceiptError::Io),
    }
}

impl From<&CachedImageMetadata> for ReceiptMetadata {
    fn from(metadata: &CachedImageMetadata) -> Self {
        Self {
            manifest_digest: metadata.manifest_digest.clone(),
            config_digest: metadata.config_digest.clone(),
            raw_manifest_json: metadata.raw_manifest_json.clone(),
            raw_config_json: metadata.raw_config_json.clone(),
            config: (&metadata.config).into(),
            layers: metadata
                .layers
                .iter()
                .map(|layer| ReceiptLayer {
                    digest: layer.digest.clone(),
                    media_type: layer.media_type.clone(),
                    size_bytes: layer.size_bytes,
                    diff_id: layer.diff_id.clone(),
                })
                .collect(),
        }
    }
}

impl From<&ImageConfig> for ReceiptConfig {
    fn from(config: &ImageConfig) -> Self {
        Self {
            env: config.env.clone(),
            cmd: config.cmd.clone(),
            entrypoint: config.entrypoint.clone(),
            working_dir: config.working_dir.clone(),
            user: config.user.clone(),
            exposed_ports: config.exposed_ports.clone(),
            volumes: config.volumes.clone(),
            labels: config
                .labels
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            stop_signal: config.stop_signal.clone(),
        }
    }
}

impl From<&ReceiptMetadata> for CachedImageMetadata {
    fn from(metadata: &ReceiptMetadata) -> Self {
        Self {
            manifest_digest: metadata.manifest_digest.clone(),
            config_digest: metadata.config_digest.clone(),
            raw_manifest_json: metadata.raw_manifest_json.clone(),
            raw_config_json: metadata.raw_config_json.clone(),
            config: ImageConfig {
                env: metadata.config.env.clone(),
                cmd: metadata.config.cmd.clone(),
                entrypoint: metadata.config.entrypoint.clone(),
                working_dir: metadata.config.working_dir.clone(),
                user: metadata.config.user.clone(),
                exposed_ports: metadata.config.exposed_ports.clone(),
                volumes: metadata.config.volumes.clone(),
                labels: metadata
                    .config
                    .labels
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
                stop_signal: metadata.config.stop_signal.clone(),
            },
            layers: metadata
                .layers
                .iter()
                .map(|layer| CachedLayerMetadata {
                    digest: layer.digest.clone(),
                    media_type: layer.media_type.clone(),
                    size_bytes: layer.size_bytes,
                    diff_id: layer.diff_id.clone(),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(digest: &str) -> CachedImageMetadata {
        let platform = Platform::host_linux();
        let raw_config = serde_json::json!({
            "os": platform.os.to_string(),
            "architecture": platform.arch.to_string(),
            "rootfs": {"type": "layers", "diff_ids": [format!("sha256:{}", "1".repeat(64))]},
            "config": {"Env": ["A=1"]},
        })
        .to_string();
        let config = ImageConfig::parse(raw_config.as_bytes()).unwrap().0;
        CachedImageMetadata {
            manifest_digest: digest.to_string(),
            config_digest: format!("sha256:{}", "2".repeat(64)),
            raw_manifest_json: "{}".to_string(),
            raw_config_json: raw_config,
            config,
            layers: vec![CachedLayerMetadata {
                digest: format!("sha256:{}", "3".repeat(64)),
                media_type: Some("application/vnd.oci.image.layer.v1.tar+gzip".to_string()),
                size_bytes: Some(1),
                diff_id: format!("sha256:{}", "1".repeat(64)),
            }],
        }
    }

    fn acquired(digest: &str) -> PinnedReference {
        let typed = ValidatedDigest::parse(digest).unwrap();
        CanonicalOciReference::parse("localhost:5000/a:tag")
            .unwrap()
            .with_digest(&typed)
            .unwrap()
    }

    #[test]
    fn round_trip_preserves_metadata_and_source_binding() {
        let directory = tempfile::tempdir().unwrap();
        let digest = format!("sha256:{}", "a".repeat(64));
        let platform = Platform::host_linux();
        let source = SourceBinding {
            reference: "localhost:5000/a:tag".to_string(),
            stated_digest: None,
        };
        let receipt = Receipt::new(
            &acquired(&digest),
            &platform,
            &metadata(&digest),
            Some(source.clone()),
        )
        .unwrap();
        receipt.write(directory.path()).unwrap();
        let read = Receipt::read(directory.path(), &acquired(&digest), &platform)
            .unwrap()
            .expect("receipt present");
        assert_eq!(read.metadata().manifest_digest, digest);
        assert_eq!(read.metadata().config.env, vec!["A=1".to_string()]);
        assert!(read.proves(&source));
        assert_eq!(
            read.content_identity(),
            ContentIdentity::of(&metadata(&digest))
        );
    }

    #[test]
    fn bindings_are_idempotent_bounded_and_never_evicted() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let platform = Platform::host_linux();
        let mut receipt =
            Receipt::new(&acquired(&digest), &platform, &metadata(&digest), None).unwrap();
        for index in 0..MAX_SOURCE_BINDINGS {
            let binding = SourceBinding::of(
                &CanonicalOciReference::parse(&format!("localhost:5000/a:source-{index}")).unwrap(),
            );
            let next = Receipt::new(
                &acquired(&digest),
                &platform,
                &metadata(&digest),
                Some(binding.clone()),
            )
            .unwrap();
            assert_eq!(receipt.merge(&next), Ok(MergedBinding::Learned));
            assert_eq!(receipt.merge(&next), Ok(MergedBinding::Unchanged));
            assert!(receipt.proves(&binding));
        }
        let bytes = serde_json::to_vec(&receipt.file).unwrap();
        let mut read = Receipt::from_bytes(&bytes).unwrap();
        let overflow =
            SourceBinding::of(&CanonicalOciReference::parse("localhost:5000/a:overflow").unwrap());
        let incoming = Receipt::new(
            &acquired(&digest),
            &platform,
            &metadata(&digest),
            Some(overflow.clone()),
        )
        .unwrap();
        // A full set is provenance exhaustion, not a failure: the acquisition that
        // learned it still succeeds and the new source stays unproven.
        assert_eq!(read.merge(&incoming), Ok(MergedBinding::Unchanged));
        assert!(!read.proves(&overflow));
        assert_eq!(
            serde_json::to_vec(&read.file).unwrap(),
            bytes,
            "a full binding set must retain every proven association"
        );
        assert_eq!(read.file.source_bindings.len(), MAX_SOURCE_BINDINGS);
        // The bound is never exceeded: a stored receipt above it is refused, and
        // exactly at it still reads.
        let mut stored: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let one = stored["source_bindings"][0].clone();
        stored["source_bindings"].as_array_mut().unwrap().push(one);
        assert!(matches!(
            Receipt::from_bytes(&serde_json::to_vec(&stored).unwrap()),
            Err(ReceiptError::BindingLimit)
        ));
    }

    #[test]
    fn conflicting_content_cannot_replace_preserved_identity() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let platform = Platform::host_linux();
        let mut receipt =
            Receipt::new(&acquired(&digest), &platform, &metadata(&digest), None).unwrap();
        let bytes = serde_json::to_vec(&receipt.file).unwrap();
        let mut changed = metadata(&digest);
        changed.config_digest = format!("sha256:{}", "b".repeat(64));
        let conflicting = Receipt::new(&acquired(&digest), &platform, &changed, None).unwrap();
        assert_eq!(
            receipt.merge(&conflicting),
            Err(ReceiptError::IdentityConflict)
        );
        assert_eq!(serde_json::to_vec(&receipt.file).unwrap(), bytes);
        let mut corrupt: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        corrupt["content_identity"]["config_digest"] = changed.config_digest.into();
        assert!(matches!(
            Receipt::from_bytes(&serde_json::to_vec(&corrupt).unwrap()),
            Err(ReceiptError::Corrupt)
        ));
    }

    #[test]
    fn absent_is_the_only_benign_read() {
        let directory = tempfile::tempdir().unwrap();
        let digest = format!("sha256:{}", "a".repeat(64));
        assert!(
            Receipt::read(
                directory.path(),
                &acquired(&digest),
                &Platform::host_linux()
            )
            .unwrap()
            .is_none()
        );
        // A directory where the file should be is corruption, not absence.
        let path = Receipt::path(
            directory.path(),
            &acquired(&digest),
            &Platform::host_linux(),
        );
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(
            Receipt::read(
                directory.path(),
                &acquired(&digest),
                &Platform::host_linux()
            )
            .is_err()
        );
    }

    #[test]
    fn a_symlinked_receipt_is_an_error_not_an_absence() {
        let directory = tempfile::tempdir().unwrap();
        let digest = format!("sha256:{}", "a".repeat(64));
        let acquired = acquired(&digest);
        let platform = Platform::host_linux();
        let target = Receipt::path(directory.path(), &acquired, &platform);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        let linked_target = directory.path().join("real.json");
        std::fs::write(&linked_target, b"{}").unwrap();
        std::os::unix::fs::symlink(&linked_target, &target).unwrap();
        assert!(
            Receipt::read(directory.path(), &acquired, &platform).is_err(),
            "a symlinked receipt must not be followed"
        );
    }

    /// A receipt file copied onto another identity's path still has to *say*
    /// that identity: placement is not authority over the bytes.
    #[test]
    fn a_receipt_copied_to_another_key_is_corruption() {
        let directory = tempfile::tempdir().unwrap();
        let platform = Platform::host_linux();
        let first = format!("sha256:{}", "a".repeat(64));
        let second = format!("sha256:{}", "b".repeat(64));
        Receipt::new(&acquired(&first), &platform, &metadata(&first), None)
            .unwrap()
            .write(directory.path())
            .unwrap();
        let source_path = Receipt::path(directory.path(), &acquired(&first), &platform);
        let target_path = Receipt::path(directory.path(), &acquired(&second), &platform);
        std::fs::copy(&source_path, &target_path).unwrap();
        // The original key still reads.
        assert!(
            Receipt::read(directory.path(), &acquired(&first), &platform)
                .unwrap()
                .is_some()
        );
        // The copied file names the first identity, so the second key is corrupt.
        assert!(matches!(
            Receipt::read(directory.path(), &acquired(&second), &platform),
            Err(ReceiptError::Corrupt)
        ));
    }

    #[test]
    fn writer_refuses_a_metadata_identity_mismatch() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let other = format!("sha256:{}", "b".repeat(64));
        assert!(matches!(
            Receipt::new(
                &acquired(&digest),
                &Platform::host_linux(),
                &metadata(&other),
                None
            ),
            Err(ReceiptError::Corrupt)
        ));
    }

    #[test]
    fn strict_schema_rejects_every_shape_it_measures() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let receipt = Receipt::new(
            &acquired(&digest),
            &Platform::host_linux(),
            &metadata(&digest),
            None,
        )
        .unwrap();
        let encoded = serde_json::to_vec(&receipt.file).unwrap();
        // Trailing bytes, non-UTF-8, unknown field, missing field, duplicate key.
        assert!(Receipt::from_bytes(&[encoded.clone(), b"x".to_vec()].concat()).is_err());
        assert!(Receipt::from_bytes(&[0xff, 0xfe]).is_err());
        let text = String::from_utf8(encoded.clone()).unwrap();
        let unknown = text.replacen('{', "{\"extra\":1,", 1);
        assert!(Receipt::from_bytes(unknown.as_bytes()).is_err());
        let missing = text.replacen("\"version\":1,", "", 1);
        assert!(Receipt::from_bytes(missing.as_bytes()).is_err());
        let duplicate = text.replacen('{', "{\"version\":1,", 1);
        assert!(Receipt::from_bytes(duplicate.as_bytes()).is_err());
        // A noncanonical acquired reference and an unsupported version.
        let noncanonical = text.replacen("localhost:5000/a@", "LOCALHOST:5000/a@", 1);
        assert!(Receipt::from_bytes(noncanonical.as_bytes()).is_err());
        let future = text.replacen("\"version\":1", "\"version\":2", 1);
        assert!(Receipt::from_bytes(future.as_bytes()).is_err());
    }

    #[test]
    fn platform_acceptance_is_total_over_its_measured_facts() {
        for bits in 0..64 {
            let facts = PlatformFacts {
                os_is_host: bits & 1 != 0,
                architecture_is_bounded_nonempty: bits & 2 != 0,
                architecture_is_oci: bits & 4 != 0,
                variant_present: bits & 8 != 0,
                variant_is_bounded_nonempty: bits & 16 != 0,
                variant_is_printable: bits & 32 != 0,
            };
            let expected = bits & 1 != 0
                && bits & 2 != 0
                && bits & 4 != 0
                && (bits & 8 == 0 || bits & 16 != 0 && bits & 32 != 0);
            assert_eq!(platform_is_acceptable(facts), expected, "bits {bits:06b}");
        }
    }

    #[test]
    fn platform_and_reference_limits_are_exact() {
        assert!(reference_within_limit(MAX_RECEIPT_REFERENCE_BYTES));
        assert!(!reference_within_limit(MAX_RECEIPT_REFERENCE_BYTES + 1));
        assert!(receipt_size_within_limit(MAX_RECEIPT_BYTES as usize));
        assert!(!receipt_size_within_limit(MAX_RECEIPT_BYTES as usize + 1));
        for (variant, ok) in [
            (None, true),
            (Some("v8".to_string()), true),
            (Some(String::new()), false),
            (Some("v 8".to_string()), false),
            (Some("v8 ".to_string()), false),
            (Some("v".repeat(65)), false),
        ] {
            assert_eq!(
                validate_platform(&ReceiptPlatform {
                    os: "linux".to_string(),
                    architecture: "arm64".to_string(),
                    variant,
                })
                .is_ok(),
                ok
            );
        }
        assert!(
            validate_platform(&ReceiptPlatform {
                os: "windows".to_string(),
                architecture: "arm64".to_string(),
                variant: None,
            })
            .is_err()
        );
    }
}
