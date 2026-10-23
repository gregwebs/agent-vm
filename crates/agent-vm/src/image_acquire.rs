//! Shared native acquisition of one OCI reference into microsandbox's cache.
//!
//! The selection verbs that need bytes (`image refresh`, `setup`'s pull step and
//! `image set-default`) differ in *policy* — which reference to acquire, what to
//! do on success, how much of a failure may be rendered — but not in *how* bytes
//! arrive. This module owns that one path.
//!
//! # The contract
//!
//! One canonical target ([`CanonicalOciReference`]) keys both the native request
//! and the cache. Success is an opaque [`ValidatedImage`] token: the source
//! binding (canonical source, stated immutable digest) and the acquired
//! identity (`repo@child`) stay separate, and no caller can manufacture one from
//! strings or a raw `PullResult`. [`acquire`] additionally preserves canonical
//! `repo@child` metadata (fresh acquisitions write a cache-only receipt), then
//! returns a [`PreparedNativeImage`] holding the shared publication barrier.
//!
//! [`AcquireMode::CachedOrAcquire`] uses a complete validated cached entry and
//! constructs no registry client (no keyring, auth or trust resolution).
//! [`AcquireMode::ResolveCurrent`] always resolves the source, with
//! `PullPolicy::Always` and `force: false` so valid layers are reused, never
//! destroyed. No sandbox, VM, Docker or alternate download backend is involved.
//!
//! # Source bindings are best-effort provenance, never authority
//!
//! A fresh acquisition records the source→acquired association in a cache-only
//! receipt, but **only for a source that states an immutable digest**: that is
//! the only case [`NativeAcquisition::association_accepted`] ever consults, so a
//! mutable tag would spend one of the bounded binding slots on evidence nothing
//! reads. A full binding set keeps every association it already proves, leaves
//! the new source unproven for a later offline association (a later unequal
//! cache association then reacquires the immutable source), and is never a
//! reason to discard content this process validated. Reaching the bound therefore
//! cannot fail an acquisition whose native pull has already moved the source key.
//!
//! # Consuming a cached entry is not establishing what it is
//!
//! A launch *consumes* the cache: whatever complete, platform-valid,
//! internally-consistent entry sits under its source key is exactly the entry the
//! SDK's `IfMissing` create would boot, whether or not this process can prove how
//! that entry got there. An acquisition that *establishes* content for a later
//! first pin makes a different claim: this process is about to persist an
//! identity and later trust it, so it must prove it.
//!
//! The two differ exactly for a source that states an immutable digest the
//! native cache stored as its resolved host **child**. A retained default names
//! an index digest; the cache holds the child under that source key; a launch
//! then sees two different digests with no receipt, because the cold acquisition
//! went through the SDK rather than through this module. Refusing that entry
//! would break a warm launch that works today, and consuming it adds no claim:
//! the SDK would boot the same bytes. [`AssociationPolicy::Consume`] therefore
//! accepts an unproven association on the launch path, while
//! [`AssociationPolicy::RequireProof`] (the cache-first *acquisition* path that
//! first-pins content) still demands a validated receipt for an unequal
//! immutable association. An unreadable or mis-keyed receipt fails both: it is
//! corruption, never a missing receipt.
//!
//! # One policy for an unreadable receipt
//!
//! A present receipt that cannot be read, or that describes an identity other
//! than its own key, is a hard error — including on a warm tag launch, which
//! would succeed without consulting a receipt at all. That is the planned policy:
//! a corrupt record is never treated as absent, because ignoring it would boot
//! content the cache cannot account for. The rendered text names only cache-side
//! recovery (restore the image cache from a backup, or remove the receipt and
//! re-acquire) and never suggests deleting HOME approval records, which are a
//! different store this module does not read or write.
//!
//! # What a cache hit may write
//!
//! A canonical-source cache hit never rewrites the source key (tag, index or
//! stated digest): it already holds a validated entry, and rewriting a *tag* from
//! metadata read moments earlier would revert a concurrent `image refresh` that
//! moved the tag. Only the pre-canonical compatibility path republishes the
//! canonical source key, and then only after re-checking under that key's guard
//! that it is still absent. The acquired child key stays content-addressed, so
//! preserving it can never revert a publication; it is written only when the
//! cache does not already hold exactly that content there.
//!
//! # Why a reference-local guard
//!
//! Native publication writes the reference metadata file *before* this wrapper
//! can validate the raw platform inside it. If validation fails, restoring the
//! bytes that were there is only correct if no other writer published in
//! between — otherwise the restore would erase a peer's successful acquisition.
//! So every acquisition through this module takes an exclusive `flock` on a
//! persistent sibling of the native reference metadata
//! (`<cache>/manifests/<native key>.agent-vm-acquire.lock`), snapshots the
//! metadata bytes, pulls, validates, and only then rolls back if needed, all
//! while holding that lock. The wait is polled in bounded windows with one
//! reference-free "waiting for another agent-vm acquisition" notice after a
//! second of observed contention: a peer may be blocked on a stalled registry
//! stream for a long time, so silence would be a poor experience, but the total
//! wait stays unbounded (no acquisition deadline, and never a lock bypass).
//!
//! The guard serializes **only callers of this helper** — including processes
//! with a different HOME/state root that still share the same writable cache
//! and reference key. It is bounded to one cache and one reference. Unmodified
//! `msb pull`, direct SDK clients, cache deletion and archive publication do
//! **not** take it; archive publication is excluded by the cache-wide exclusive
//! barrier below, and the remaining external writers must be quiescent for the
//! rollback guarantee. No fsync/power-loss or process-kill rollback is claimed:
//! process death releases the descriptor, not the publication.
//!
//! # Lock order
//!
//! [ARCHITECTURE.md](../../../ARCHITECTURE.md) owns the one lock-order
//! hierarchy (publication barrier → reference guards → native pull/content
//! locks) and why each edge points the way it does. Two consequences are
//! enforced here: a derived reference guard is only taken after the source guard
//! is released, and the native lock file (`cache.image_lock_path`) is never
//! pre-acquired — `Registry::pull_inner` opens and locks it itself with no
//! already-held-lock variant, so taking it would deadlock.

use anyhow::anyhow;
use microsandbox::{MicrosandboxError, backend};
use microsandbox_image::{
    CachedImageMetadata, GlobalCache, ImageError, Platform, PullOptions, PullPolicy, PullResult,
    Reference, Registry,
};
use rustix::fs::{FileType, Mode, OFlags};
use std::path::Path;
use vstd::prelude::*;

use crate::boot_image::ImageLabel;
use crate::host_paths::{FlockAttempt, FlockMode};
use receipt::RECEIPT_REPAIR_GUIDANCE;

mod barrier;
mod receipt;
mod reference;

pub(crate) use barrier::{BarrierError, PublicationBarrier};
pub(crate) use receipt::{ContentIdentity, SourceBinding, is_printable_variant_byte};
use receipt::{MergedBinding, Receipt, ReceiptError};
pub(crate) use reference::{
    CanonicalOciReference, OciTarget, OciTargetError, PinnedReference, ValidatedDigest,
};

/// How an acquisition treats cached native content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AcquireMode {
    /// The cache-first **acquisition** path: use a complete validated cached
    /// entry when one exists, acquire only on a miss. A launch does not come
    /// through here — it calls [`prepare_cached`], which consumes the cache and
    /// establishes nothing. The first-pin consumer of this mode arrives with the
    /// approval store, which is not part of this change; this module's
    /// `only_the_establishing_mode_reads_the_cache_strictly` test is its caller.
    #[allow(dead_code)]
    CachedOrAcquire,
    /// Always resolve the current source, even when it is cached. This is the
    /// explicit refresh/set-default path.
    ResolveCurrent,
}

impl AcquireMode {
    /// The association policy of this mode's cache-first read, or `None` when the
    /// mode never consumes a cached entry at all.
    ///
    /// Only [`AcquireMode::CachedOrAcquire`] reads the cache here, and it
    /// establishes content this process will persist and later trust, so it keeps
    /// the strict rule. A launch that merely consumes the cache passes
    /// [`AssociationPolicy::Consume`] to [`prepare_cached`] instead: it is not an
    /// acquisition and persists no new identity claim.
    fn cache_first_policy(self) -> Option<AssociationPolicy> {
        match self {
            Self::CachedOrAcquire => Some(AssociationPolicy::RequireProof),
            Self::ResolveCurrent => None,
        }
    }
}

/// What a cache-first read proved about an entry whose acquired digest is not
/// the immutable digest the selection states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Association {
    /// The stated identity and the cached identity agree, or no immutable
    /// identity is stated at all (a mutable tag).
    Proven,
    /// The identities differ and no receipt exists to explain the difference.
    /// An index legitimately resolves to a child, so this is not itself a
    /// contradiction; whether it is acceptable is the policy's decision.
    Unproven,
    /// A preserved receipt exists for this content and contradicts it. No
    /// policy accepts this: relaxing the *proof* of an association must never
    /// relax *content consistency*.
    Conflict,
}

/// What a cache-first read must prove about an entry whose acquired digest is not
/// the immutable digest the selection states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AssociationPolicy {
    /// A launch consuming the cache. The entry is complete, platform-valid and
    /// describes its own content; it is precisely what the SDK's `IfMissing`
    /// create would boot, so consuming it claims nothing new about where it came
    /// from. A digest source whose cached child differs therefore stays usable
    /// with no receipt, which is the behaviour a warm launch has always had.
    Consume,
    /// An acquisition establishing content for a later first pin. A claimed
    /// source→acquired association is persisted and trusted later, so an unequal
    /// immutable association needs a validated receipt (or a native acquisition
    /// of the stated source, which is the other mode's job).
    RequireProof,
}

/// A validated native image: the opaque success token every acquisition
/// consumer receives.
///
/// Constructible only inside this module: callers cannot mint one from a
/// reference string or a raw `PullResult`. It carries the two identities the
/// spec keeps separate — the canonical *source* and its stated immutable digest
/// (provenance), and the native *acquired* digest (repo@C) — plus the preserved
/// native metadata and the measured platform.
pub(crate) struct ValidatedImage {
    /// The canonical source with its stated digest, when it named one, so the
    /// source binding is derived rather than stored twice.
    source: CanonicalOciReference,
    source_text: String,
    /// The acquired identity: canonical `repo@C` plus C itself.
    acquired: PinnedReference,
    metadata: CachedImageMetadata,
}

impl ValidatedImage {
    /// The acquired identity: the measured native manifest digest, which is what
    /// an approval pins and what a cache rebuild reacquires.
    pub(crate) fn acquired_digest(&self) -> &ValidatedDigest {
        self.acquired.digest()
    }

    /// The guest environment from these exact validated bytes.
    pub(crate) fn image_env(&self) -> &[String] {
        &self.metadata.config.env
    }

    /// The canonical selected source (a tag or a stated digest).
    pub(crate) fn source(&self) -> &CanonicalOciReference {
        &self.source
    }

    #[allow(dead_code)]
    /// The user's original spelling, for provenance display only.
    pub(crate) fn source_text(&self) -> &str {
        &self.source_text
    }

    /// The verified guest content identity: config digest plus ordered layer
    /// diff IDs. Approval equivalence compares this, not manifest bytes, so an
    /// alternate digest algorithm or unrelated index movement cannot demand a
    /// replacement.
    pub(crate) fn content_identity(&self) -> ContentIdentity {
        ContentIdentity::of(&self.metadata)
    }
}

impl std::fmt::Debug for ValidatedImage {
    /// Never renders either reference: an acquisition target can name a private
    /// registry.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ValidatedImage(<redacted reference>)")
    }
}

/// A validated image plus the shared publication barrier that protected its
/// cache reads and writes.
///
/// The barrier is held until the value is dropped: ordinary preparation holds
/// it across the SDK's cache consumption, setup holds it across its optional
/// verification create, and refresh/set-default drop it once the metadata is
/// preserved. Dropping is the only release; it can never be upgraded.
pub(crate) struct PreparedNativeImage {
    image: ValidatedImage,
    _barrier: PublicationBarrier,
}

impl PreparedNativeImage {
    pub(crate) fn image(&self) -> &ValidatedImage {
        &self.image
    }
}

impl std::fmt::Debug for PreparedNativeImage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparedNativeImage(<redacted reference>)")
    }
}

/// Which acquisition step a native failure came from. Rendered as fixed text;
/// it never carries a reference, path or source chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AcquireStage {
    CachePreparation,
    RegistryConstruction,
    Pull,
    /// Preserving canonical `repo@C` metadata after validation.
    CanonicalPublication,
}

impl AcquireStage {
    fn describe(self) -> &'static str {
        match self {
            Self::CachePreparation => "preparing the native image cache",
            Self::RegistryConstruction => "preparing registry access",
            Self::Pull => "acquiring the image",
            Self::CanonicalPublication => "preserving canonical image cache metadata",
        }
    }
}

/// Why a present cached entry cannot back this selection.
///
/// An incomplete entry, or one whose content is not the identity an immutable
/// selection states, is a *miss* that the cache-first policy then reacquires —
/// by the stated digest, never by a tag. A contradiction with a preserved
/// receipt is different: it means the cache no longer accounts for content a
/// later launch might boot, so it is a closed hard error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CachedEntryError {
    /// A preserved receipt exists for this content and the entry now
    /// contradicts it. Content consistency is never relaxed, not even for a
    /// launch that merely consumes the cache.
    Conflict,
}

impl CachedEntryError {
    fn describe(self) -> &'static str {
        match self {
            Self::Conflict => {
                "the cached image contradicts its preserved content identity; repair or remove the cache entry (for example with `agent-vm image refresh`) before launching"
            }
        }
    }
}

/// A coordination failure before native publication: the guard could not be
/// opened/acquired, or the previous metadata could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReferenceStage {
    LockOpen,
    LockAcquire,
    Snapshot,
}

impl ReferenceStage {
    fn describe(self) -> &'static str {
        match self {
            Self::LockOpen => "opening the image-cache coordination lock",
            Self::LockAcquire => "acquiring the image-cache coordination lock",
            Self::Snapshot => "snapshotting cached reference metadata",
        }
    }
}

/// Why post-acquisition validation refused the native result. Each arm keeps
/// the stage's own source so an explicit-source caller can chain it; redacted
/// callers consume the type into fixed text instead.
#[derive(Debug)]
pub(crate) enum ValidationError {
    /// The complete cached entry could not be read back, or a test-injected
    /// validation failure.
    Completeness(anyhow::Error),
    /// The cached entry is missing, or the cached/returned resolved identities
    /// disagree.
    Identity,
    /// The cached raw config does not describe a host-Linux image.
    Platform(PlatformRejection),
}

/// The raw-platform rejection reason, without any caller-specific suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlatformRejection {
    InvalidMetadata,
    HostMismatch,
}

/// What happened to the pre-acquisition metadata snapshot after a failed
/// postvalidation. `Failed` is reported as a second stage, never swallowed.
#[derive(Debug)]
pub(crate) enum RollbackOutcome {
    Restored,
    Failed(anyhow::Error),
}

/// Every way [`NativeAcquisition::pull`] can fail, typed so callers can pick
/// their own rendering (fixed text for a redacted selection, chains for an
/// explicit one) without inspecting strings.
#[derive(Debug)]
pub(crate) enum AcquireError {
    /// The process default backend is not local; acquisition needs its cache.
    NonLocalBackend,
    /// The target's normalized registry differs from the one this acquisition
    /// opened. Raised before any lock, debug record, request or cache write.
    RegistryMismatch,
    Native {
        stage: AcquireStage,
        source: ImageError,
    },
    RegistrySettings(MicrosandboxError),
    /// The native pull task itself failed to join: publication is uncertain.
    Task(tokio::task::JoinError),
    DebugConfig(anyhow::Error),
    /// A debug-build test-gate I/O or control failure *before* native
    /// publication. Distinct from [`AcquireError::DebugConfig`] (the real
    /// debug-record dump) so failing-test diagnostics name the right stage.
    TestGate(anyhow::Error),
    ReferenceState {
        stage: ReferenceStage,
        source: anyhow::Error,
    },
    PostValidation {
        source: ValidationError,
        rollback: RollbackOutcome,
    },
    /// The shared publication barrier could not be taken.
    Barrier(BarrierError),
    /// The cache-only receipt is corrupt, unreadable or unwritable. Never
    /// treated as "no receipt".
    Receipt(ReceiptError),
    /// A cached entry exists under this selection's key but cannot back it. A
    /// launcher fails closed here instead of letting an unvalidated
    /// re-acquisition replace what the cache is supposed to describe.
    CachedEntry(CachedEntryError),
    /// A validated identity could not be expressed as a canonical immutable
    /// reference. Internal invariant failure; names no value.
    Identity,
}

impl AcquireError {
    /// Reference-free text for the default tier and explicit set-default.
    ///
    /// Never includes the reference, a URL, a native path or a source chain:
    /// those are the values a redacted selection may not disclose. A failed
    /// rollback is spelled out as its own stage with a recovery requirement, so
    /// a postvalidation failure cannot read as "nothing happened".
    pub(crate) fn redacted_message(&self) -> String {
        match self {
            Self::NonLocalBackend => {
                "native image acquisition requires the local image cache; unset the cloud backend selection".to_string()
            }
            Self::RegistryMismatch => {
                "internal error: the acquisition target's registry does not match the opened cache".to_string()
            }
            Self::Native { stage, source } => {
                format!("{} failed: {}", stage.describe(), native_category(source))
            }
            Self::RegistrySettings(_) => "resolving registry trust/auth configuration failed".to_string(),
            Self::Task(_) => {
                "the native acquisition task failed, so image publication is uncertain; check the cache and retry the acquisition".to_string()
            }
            Self::DebugConfig(_) => "preparing the native acquisition debug record failed".to_string(),
            Self::TestGate(_) => "native acquisition test gate failed".to_string(),
            Self::ReferenceState { stage, .. } => format!("{} failed", stage.describe()),
            Self::PostValidation { rollback, .. } => match rollback {
                RollbackOutcome::Failed(_) => POSTVALIDATION_ROLLBACK_FAILED.to_string(),
                RollbackOutcome::Restored => POSTVALIDATION_RESTORED.to_string(),
            },
            Self::Barrier(error) => error.message(),
            Self::Receipt(error) => format!("{}; {RECEIPT_REPAIR_GUIDANCE}", error.describe()),
            Self::CachedEntry(error) => error.describe().to_string(),
            Self::Identity => {
                "the acquired image did not yield a usable immutable identity".to_string()
            }
        }
    }
}

/// Safe text for a validation failure whose snapshot was restored.
pub(crate) const POSTVALIDATION_RESTORED: &str = "image cache post-acquisition validation failed and the previous reference metadata was restored; retry the image acquisition";

/// Safe text for a validation failure whose restore also failed.
pub(crate) const POSTVALIDATION_ROLLBACK_FAILED: &str = "image cache post-acquisition validation failed; restoring previous reference metadata also failed; cache recovery is required before relying on this selection; retry image acquisition after resolving the cache error";

impl std::fmt::Display for AcquireError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Even `{}` is safe: this rendering never names the reference.
        formatter.write_str(&self.redacted_message())
    }
}

/// No `source()` override on purpose: [`AcquireError`]'s `Display` is the safe
/// text, and `{:#}` renders the source chain of whatever error it is attached
/// to. A future `?` in a redacted caller would therefore turn a native source
/// naming the reference into a leaked anyhow chain. Raw causes stay in the
/// typed fields and are exposed only by [`AcquireError::into_explicit_error`].
impl std::error::Error for AcquireError {}

impl AcquireError {
    /// Explicit-source rendering: keeps the native/validation source chain and,
    /// for a failed restore, a second contextual cause. A redacted caller must
    /// use [`AcquireError::redacted_message`] instead.
    pub(crate) fn into_explicit_error(self) -> anyhow::Error {
        match self {
            Self::Native { stage, source } => {
                anyhow::Error::new(source).context(format!("{} failed", stage.describe()))
            }
            Self::RegistrySettings(error) => anyhow::Error::new(error)
                .context("resolving registry trust/auth configuration failed"),
            Self::Task(error) => {
                anyhow::Error::new(error).context(
                    "native acquisition task join failed, so image publication is uncertain; check the cache and retry the acquisition",
                )
            }
            Self::DebugConfig(error) => {
                error.context("preparing the native acquisition debug record")
            }
            Self::TestGate(error) => error.context("native acquisition test gate failed"),
            Self::ReferenceState { stage, source } => {
                source.context(format!("{} failed", stage.describe()))
            }
            Self::PostValidation { source, rollback } => {
                let validation = match source {
                    ValidationError::Completeness(error) => {
                        error.context("validating the acquired image cache")
                    }
                    ValidationError::Identity => anyhow!(
                        "validating the acquired image cache failed: immutable identity or \
                         complete cache unavailable"
                    ),
                    ValidationError::Platform(rejection) => anyhow!(rejection.describe()),
                };
                match rollback {
                    RollbackOutcome::Restored => {
                        validation.context("previous reference metadata was restored")
                    }
                    RollbackOutcome::Failed(failure) => validation.context(format!(
                        "restoring previous reference metadata also failed: {failure:#}; cache recovery is required before relying on this selection; retry image acquisition after resolving the cache error"
                    )),
                }
            }
            Self::Barrier(error) => error.into_explicit_error(),
            Self::Receipt(error) => {
                anyhow!(format!("{}; {RECEIPT_REPAIR_GUIDANCE}", error.describe()))
            }
            other => anyhow!(other.redacted_message()),
        }
    }
}

impl PlatformRejection {
    fn describe(self) -> &'static str {
        match self {
            Self::InvalidMetadata => "acquired image platform metadata is invalid",
            Self::HostMismatch => "acquired image platform does not match host Linux",
        }
    }
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Completeness(_) => {
                formatter.write_str("complete cache identity unavailable after acquisition")
            }
            Self::Identity => formatter
                .write_str("immutable identity or complete cache unavailable after acquisition"),
            Self::Platform(rejection) => formatter.write_str(rejection.describe()),
        }
    }
}

impl std::error::Error for ValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Completeness(error) => Some(error.as_ref()),
            Self::Identity | Self::Platform(_) => None,
        }
    }
}

/// The native error categories this wrapper reports. A raw `ImageError` may
/// name a reference or path, so only the category is rendered.
fn native_category(error: &ImageError) -> &'static str {
    match error {
        ImageError::Registry(_) => "registry reachability/auth/availability",
        ImageError::PlatformNotFound { .. } => "no host platform",
        ImageError::ManifestParse(_) | ImageError::ConfigParse(_) => "invalid OCI metadata",
        ImageError::DigestMismatch { .. } => "layer integrity failure",
        ImageError::Materialize { .. } | ImageError::Cache { .. } | ImageError::Io(_) => {
            "materialization/cache I/O"
        }
        ImageError::InvalidCertificate(_) => "invalid trust configuration",
        _ => "native image validation failure",
    }
}

/// Which evidence a preservation rests on. Only a fresh native acquisition may
/// add a source binding.
#[derive(Clone, Copy)]
enum Preservation {
    FreshAcquisition,
    ValidatedCache,
}

impl Preservation {
    /// The binding this evidence may record.
    ///
    /// Only a source that states an immutable digest gets a binding: the
    /// association check consults bindings for exactly those sources, so a
    /// mutable tag would spend one of the bounded slots on evidence nothing
    /// reads, and per-commit tags would eventually exhaust it for no gain.
    fn binding(self, target: &OciTarget) -> Option<SourceBinding> {
        match self {
            Self::FreshAcquisition => target
                .stated_digest()
                .map(|_| SourceBinding::of(target.canonical())),
            Self::ValidatedCache => None,
        }
    }
}

/// What the cache-first lookup found for one selection.
enum CacheLookup {
    /// A complete, identity-consistent, host-platform entry.
    Hit(Box<CachedImageMetadata>),
    /// No entry under the canonical or the pre-canonical key.
    Absent,
    /// A present entry that cannot back this selection. The reason stays on
    /// [`CanonicalPublication`], where it decides whether a peer's publication
    /// can be reused; a cache-first *read* only needs to know it is a miss.
    Unusable,
}

/// Whether a digest selection had to republish its own child key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Repair {
    /// The cache already held this content under that key; nothing was written.
    NotNeeded,
    /// The preserved metadata was rewritten and read back complete.
    Published,
    /// The write happened but the entry is still not a complete cached image.
    Incomplete,
}

/// What republishing a pre-canonical hit under the canonical source key did.
enum CanonicalPublication {
    /// The canonical key was still absent and now holds this validated metadata.
    Published,
    /// A peer published that key first; this is the peer's validated entry.
    Concurrent(Box<CachedImageMetadata>),
    /// A peer's entry is under the canonical key but cannot back this selection.
    Unusable,
}

/// One native cache for a single registry host.
///
/// The registry client (and therefore every credential/trust resolution) is
/// constructed **lazily**, only on a path that needs the network. A warm cached
/// acquisition never builds one: that is what makes a warm launch
/// registry-free, so registry availability cannot gate a warm launch.
pub(crate) struct NativeAcquisition {
    cache: GlobalCache,
    cache_dir: std::path::PathBuf,
    registry_host: String,
}

impl NativeAcquisition {
    pub(crate) async fn open(target: &OciTarget) -> Result<Self, AcquireError> {
        let backend = backend::default_backend();
        let local = backend.as_local().ok_or(AcquireError::NonLocalBackend)?;
        // The backend's resolved cache dir, including a persisted shared-cache
        // redirect. Not `effective_cache_dir`, not MSB_HOME, not HOME.
        let cache_dir = local.cache_dir();
        let cache = GlobalCache::new(&cache_dir).map_err(|source| AcquireError::Native {
            stage: AcquireStage::CachePreparation,
            source,
        })?;
        let registry_host = target.reference().registry().to_owned();
        Ok(Self {
            cache,
            cache_dir,
            registry_host,
        })
    }

    fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    /// A `Registry` handle is scoped to one registry host: managed settings,
    /// keyring/Docker credentials and CA trust stay the backend's, and this
    /// wrapper never reads credential material or falls back to anonymous
    /// access.
    async fn registry(&self) -> Result<Registry, AcquireError> {
        let backend = backend::default_backend();
        let local = backend.as_local().ok_or(AcquireError::NonLocalBackend)?;
        let settings = local
            .registry_config(
                &self.registry_host,
                microsandbox::config::RegistryOptions {
                    insecure: crate::pull::is_plain_http_registry(&self.registry_host),
                    ..Default::default()
                },
            )
            .await
            .map_err(AcquireError::RegistrySettings)?;
        Registry::builder(Platform::host_linux(), self.cache.clone())
            .auth(settings.auth)
            .extra_ca_certs(settings.ca_certs)
            .add_insecure_registries(settings.insecure_registries)
            .build()
            .map_err(|source| AcquireError::Native {
                stage: AcquireStage::RegistryConstruction,
                source,
            })
    }

    fn ensure_registry(&self, target: &OciTarget) -> Result<(), AcquireError> {
        if target.reference().registry() != self.registry_host {
            return Err(AcquireError::RegistryMismatch);
        }
        Ok(())
    }

    /// Acquire `target` in `mode` and return only after guarded completeness,
    /// identity and host-platform validation succeeded.
    async fn acquire(
        &self,
        target: &OciTarget,
        label: &ImageLabel,
        mode: AcquireMode,
    ) -> Result<ValidatedImage, AcquireError> {
        self.ensure_registry(target)?;
        if let Some(policy) = mode.cache_first_policy()
            && let Some(image) = self.cached(target, policy).await?
        {
            gate::detail(gate::Stage::CacheHit).map_err(AcquireError::TestGate)?;
            return Ok(image);
        }
        self.resolve_and_preserve(target, label).await
    }

    /// Use a complete, validated cached entry when one exists; a miss (or an
    /// entry this selection cannot prove) hands the decision to the caller.
    ///
    /// The canonical key is preferred. On a canonical miss, the *originally
    /// parsed* (pre-canonical) key is tried once: old launchers and the native
    /// loader may have written an uppercase digest or a `registry-1.docker.io`
    /// spelling. Reuse requires the same complete/identity/platform validation
    /// as a canonical entry; the validated metadata is then republished under the
    /// canonical key so the old spelling is never needed again.
    async fn cached(
        &self,
        target: &OciTarget,
        policy: AssociationPolicy,
    ) -> Result<Option<ValidatedImage>, AcquireError> {
        match self.lookup(target, policy).await? {
            CacheLookup::Hit(metadata) => Ok(Some(self.validated(target, *metadata)?)),
            CacheLookup::Absent | CacheLookup::Unusable => Ok(None),
        }
    }

    /// The one cache-first lookup: canonical key, then the bounded pre-canonical
    /// compatibility key, republished under the canonical key when it validates.
    ///
    /// A canonical hit never rewrites that key: the entry is already there and
    /// validated, and rewriting a *tag* from metadata read moments earlier would
    /// revert a concurrent `image refresh` that moved the tag. The pre-canonical
    /// path exists to make the old spelling unnecessary again, so it does publish
    /// the canonical key — but only while that key is still absent.
    async fn lookup(
        &self,
        target: &OciTarget,
        policy: AssociationPolicy,
    ) -> Result<CacheLookup, AcquireError> {
        let canonical = target.canonical();
        // Quiet: the reporting stages belong to the snapshot→validate interval
        // of an acquisition, not to a cache-first read.
        let canonical_path = self.cache.image_metadata_path(canonical.reference());
        let canonical_guard = ReferenceGuard::acquire_quiet(&canonical_path).await?;
        if self.repair_child_key(canonical).await? == Repair::Incomplete {
            return Ok(CacheLookup::Unusable);
        }
        let canonical_present = canonical_path.exists();
        let canonical_cached = self.cached_complete(canonical.reference())?;
        drop(canonical_guard);
        match canonical_cached {
            Some(metadata) => {
                if !self.association_accepted(target, &metadata, policy)? {
                    return Ok(CacheLookup::Unusable);
                }
                gate::detail(gate::Stage::CacheValidated).map_err(AcquireError::TestGate)?;
                self.preserve(target, &metadata, Preservation::ValidatedCache)
                    .await?;
                return Ok(CacheLookup::Hit(Box::new(metadata)));
            }
            None if canonical_present => {
                return Ok(CacheLookup::Unusable);
            }
            None => {}
        }

        let precanonical = target.precanonical();
        if precanonical == canonical.reference() {
            return Ok(CacheLookup::Absent);
        }
        let path = self.cache.image_metadata_path(precanonical);
        let guard = ReferenceGuard::acquire_quiet(&path).await?;
        let present = path.exists();
        let metadata = self.cached_complete(precanonical)?;
        // Release the old spelling's guard before taking the canonical source's
        // guard: reference guards are ordered by native metadata-key bytes, and a
        // derived child may sort before the source (see ARCHITECTURE.md). The
        // migration itself is proved by `publish_metadata`'s readback, not by
        // this guard.
        drop(guard);
        let Some(metadata) = metadata else {
            return Ok(if present {
                CacheLookup::Unusable
            } else {
                CacheLookup::Absent
            });
        };
        if !self.association_accepted(target, &metadata, policy)? {
            return Ok(CacheLookup::Unusable);
        }
        gate::detail(gate::Stage::CacheValidated).map_err(AcquireError::TestGate)?;
        self.preserve(target, &metadata, Preservation::ValidatedCache)
            .await?;
        match self
            .migrate_canonical_key(target, &metadata, policy)
            .await?
        {
            CanonicalPublication::Published => Ok(CacheLookup::Hit(Box::new(metadata))),
            CanonicalPublication::Concurrent(metadata) => Ok(CacheLookup::Hit(metadata)),
            CanonicalPublication::Unusable => Ok(CacheLookup::Unusable),
        }
    }

    /// A digest selection can repair its own child key without having ever been
    /// observed as a source: the receipt preserves content, not approval.
    ///
    /// Only a cache that no longer holds that content under the key needs the
    /// write, so a warm digest launch of a validated entry publishes nothing. A
    /// readback that is still incomplete afterwards is the *completeness* error
    /// (the entry is present but cannot back a launch), not a generic identity
    /// failure: the two have different recoveries.
    async fn repair_child_key(
        &self,
        canonical: &CanonicalOciReference,
    ) -> Result<Repair, AcquireError> {
        let Some(digest) = canonical.digest() else {
            return Ok(Repair::NotNeeded);
        };
        let child = canonical
            .with_digest(digest)
            .map_err(|_| AcquireError::Identity)?;
        let Some(receipt) = Receipt::read(&self.cache_dir, &child, &Platform::host_linux())
            .map_err(AcquireError::Receipt)?
        else {
            return Ok(Repair::NotNeeded);
        };
        if !self.needs_repair(canonical.reference(), &receipt.metadata())? {
            return Ok(Repair::NotNeeded);
        }
        match self
            .publish_metadata(canonical.reference(), &receipt.metadata())
            .await
        {
            Ok(()) => Ok(Repair::Published),
            Err(AcquireError::Identity) => Ok(Repair::Incomplete),
            Err(error) => Err(error),
        }
    }

    /// Publish a validated pre-canonical entry under the canonical source key,
    /// but only while that key is still absent.
    ///
    /// Absence is re-checked under the canonical key's own guard because a
    /// concurrent `image refresh` of a moving tag may have published it in the
    /// gap since this lookup missed it. Overwriting that publication with
    /// metadata read before it would silently revert the tag, so a peer's entry is
    /// kept and used when it validates this selection; an entry that cannot back
    /// the selection is the same closed failure a canonical hit would be.
    async fn migrate_canonical_key(
        &self,
        target: &OciTarget,
        metadata: &CachedImageMetadata,
        policy: AssociationPolicy,
    ) -> Result<CanonicalPublication, AcquireError> {
        let reference = target.canonical().reference();
        let path = self.cache.image_metadata_path(reference);
        let guard = ReferenceGuard::acquire_quiet(&path).await?;
        let published = self.cached_complete(reference)?;
        match published {
            Some(published) => {
                drop(guard);
                return Ok(if self.association_accepted(target, &published, policy)? {
                    CanonicalPublication::Concurrent(Box::new(published))
                } else {
                    CanonicalPublication::Unusable
                });
            }
            None if path.exists() => {
                drop(guard);
                return Ok(CanonicalPublication::Unusable);
            }
            None => {}
        }
        let write = self.publish_metadata(reference, metadata).await;
        drop(guard);
        write?;
        Ok(CanonicalPublication::Published)
    }

    /// A cached entry is usable iff it is complete (native `Never` checks the
    /// materialized layers, fsmeta and VMDK), its identities agree, its
    /// acquired digest is strict, and its raw config is host Linux.
    ///
    /// A failure answers `Ok(None)` so the caller acquires from the registry:
    /// today's launch behaviour on an unusable cached entry. A corrupt receipt
    /// is *not* this case and stays a hard error.
    fn cached_complete(
        &self,
        reference: &Reference,
    ) -> Result<Option<CachedImageMetadata>, AcquireError> {
        let cached = match Registry::pull_cached(
            &self.cache,
            reference,
            &PullOptions {
                pull_policy: PullPolicy::Never,
                force: false,
                ..Default::default()
            },
        ) {
            Ok(cached) => cached,
            Err(_) => return Ok(None),
        };
        let Some((result, metadata)) = cached else {
            return Ok(None);
        };
        if result.manifest_digest.to_string() != metadata.manifest_digest
            || ValidatedDigest::parse(&metadata.manifest_digest).is_err()
            || check_host_platform(&metadata.raw_config_json).is_err()
        {
            return Ok(None);
        }
        Ok(Some(metadata))
    }

    /// An immutable source whose cached acquired digest differs from its stated
    /// digest is only accepted with a validated receipt for that exact source,
    /// platform and content identity — *unless* `policy` says this read only
    /// consumes the cache. Native verification may legitimately resolve an index
    /// to its host child; cache completeness alone proves nothing about that
    /// association, so establishment requires the proof and consumption does not.
    ///
    /// A present receipt is read under **both** policies: corruption is a hard
    /// error either way, never a missing receipt.
    fn association_accepted(
        &self,
        target: &OciTarget,
        metadata: &CachedImageMetadata,
        policy: AssociationPolicy,
    ) -> Result<bool, AcquireError> {
        Ok(match self.association(target, metadata)? {
            Association::Proven => true,
            Association::Unproven => policy == AssociationPolicy::Consume,
            // A contradiction is corruption, not a missing proof: no policy
            // may consume it, so it is never reported as a plain "unusable"
            // cache miss that a caller could treat as absent.
            Association::Conflict => {
                return Err(AcquireError::CachedEntry(CachedEntryError::Conflict));
            }
        })
    }

    /// Classify what the cache proves about a stated immutable identity.
    ///
    /// A present receipt is read under **both** policies: corruption or a
    /// contradiction is a hard error either way, never a missing receipt.
    fn association(
        &self,
        target: &OciTarget,
        metadata: &CachedImageMetadata,
    ) -> Result<Association, AcquireError> {
        let Some(stated) = target.stated_digest() else {
            // A mutable tag states no immutable identity, so completeness is all
            // it can offer.
            return Ok(Association::Proven);
        };
        if stated.as_str() == metadata.manifest_digest {
            return Ok(Association::Proven);
        }
        let acquired = self
            .acquired_reference(target, &metadata.manifest_digest)
            .map_err(|_| AcquireError::Identity)?;
        match Receipt::read(&self.cache_dir, &acquired, &Platform::host_linux())
            .map_err(AcquireError::Receipt)?
        {
            Some(receipt) => {
                if receipt.content_identity() != ContentIdentity::of(metadata) {
                    // The preserved content and the entry disagree. That is
                    // corruption, not a missing association proof.
                    Ok(Association::Conflict)
                } else if receipt.proves(&SourceBinding::of(target.canonical())) {
                    Ok(Association::Proven)
                } else {
                    // The content is preserved and consistent, but this exact
                    // source was never proven to name it (for example a full
                    // binding set). Cache completeness is all that remains.
                    Ok(Association::Unproven)
                }
            }
            None => Ok(Association::Unproven),
        }
    }

    /// `repo@digest` for this target's registry/repository.
    fn acquired_reference(
        &self,
        target: &OciTarget,
        digest: &str,
    ) -> Result<PinnedReference, OciTargetError> {
        target
            .canonical()
            .with_digest(&ValidatedDigest::parse(digest)?)
    }

    /// Resolve the source from the registry, validate it under its reference
    /// guard, then preserve canonical `repo@C` metadata and a cache-only
    /// receipt.
    async fn resolve_and_preserve(
        &self,
        target: &OciTarget,
        label: &ImageLabel,
    ) -> Result<ValidatedImage, AcquireError> {
        let reference = target.reference().clone();
        let metadata_path = self.cache.image_metadata_path(&reference);
        let guard = ReferenceGuard::acquire(&metadata_path).await?;
        let prior = guard.snapshot(&metadata_path)?;

        let registry = self.registry().await?;
        let result = self.native_pull(&registry, &reference, label).await?;

        // Publication is now owned by this guarded writer cohort: validate the
        // requested key's complete cached entry against the returned resolved
        // identity before anyone else may snapshot it. A gate failure here is a
        // postvalidation failure (so the snapshot is restored), never an early
        // return that skips the restore.
        let validated = gate::checkpoint(gate::Stage::NativeOk)
            .map_err(ValidationError::Completeness)
            .and_then(|()| self.validate(&reference, &result));
        let metadata = match validated {
            Ok(metadata) => metadata,
            Err(source) => {
                let rollback = guard.restore(&metadata_path, &prior);
                return Err(AcquireError::PostValidation { source, rollback });
            }
        };
        // The source key is validated and the guard is no longer needed.
        // Release it *before* taking the acquired key's guard: the reference
        // guards have one documented order (see ARCHITECTURE.md).
        drop(guard);
        self.preserve(target, &metadata, Preservation::FreshAcquisition)
            .await?;
        self.validated(target, metadata)
    }

    /// Preserve canonical `repo@C` metadata (C is the native acquired digest)
    /// and the cache-only receipt.
    ///
    /// The child key is content-addressed, so publishing it can never revert a
    /// moved tag — but rewriting an entry that already holds exactly this content
    /// is not a repair either, so a cache hit writes nothing. A fresh acquisition
    /// writes its child key unconditionally: the native pull published the
    /// *requested* spelling, so the derived child key is this module's own
    /// publication and its readback is the completeness proof.
    async fn preserve(
        &self,
        target: &OciTarget,
        metadata: &CachedImageMetadata,
        evidence: Preservation,
    ) -> Result<(), AcquireError> {
        let acquired = self
            .acquired_reference(target, &metadata.manifest_digest)
            .map_err(|_| AcquireError::Identity)?;
        let path = self.cache.image_metadata_path(acquired.reference());
        let guard = ReferenceGuard::acquire_quiet(&path).await?;
        let incoming = Receipt::new(
            &acquired,
            &Platform::host_linux(),
            metadata,
            evidence.binding(target),
        )
        .map_err(AcquireError::Receipt)?;
        let receipt = match Receipt::read(&self.cache_dir, &acquired, &Platform::host_linux())
            .map_err(AcquireError::Receipt)?
        {
            Some(mut existing) => match existing.merge(&incoming).map_err(AcquireError::Receipt)? {
                MergedBinding::Learned => Some(existing),
                // Nothing new to record: a cache hit learns no binding, and a
                // repeated one is already stored, so the file already says this.
                MergedBinding::Unchanged => None,
            },
            None => match evidence {
                Preservation::FreshAcquisition => Some(incoming),
                // Cache completeness is not a newly learned registry binding.
                Preservation::ValidatedCache => None,
            },
        };
        if matches!(evidence, Preservation::FreshAcquisition)
            || self.needs_repair(acquired.reference(), metadata)?
        {
            self.publish_metadata(acquired.reference(), metadata)
                .await?;
        }
        if let Some(receipt) = receipt {
            gate::detail(gate::Stage::Receipt).map_err(AcquireError::TestGate)?;
            receipt
                .write(&self.cache_dir)
                .map_err(AcquireError::Receipt)?;
        }
        drop(guard);
        Ok(())
    }

    /// Whether writing `metadata` under `reference` would change anything.
    ///
    /// A complete cached entry that already carries this identity, config and
    /// content is what preservation would write, and rewriting a file a
    /// concurrent reader may be validating is not a repair. The comparison is the
    /// same one `publish_metadata`'s readback makes, so "no repair needed" and
    /// "the readback would succeed" agree.
    fn needs_repair(
        &self,
        reference: &Reference,
        metadata: &CachedImageMetadata,
    ) -> Result<bool, AcquireError> {
        Ok(match self.cached_complete(reference)? {
            Some(cached) => {
                cached.manifest_digest != metadata.manifest_digest
                    || ContentIdentity::of(&cached) != ContentIdentity::of(metadata)
                    || cached.raw_config_json != metadata.raw_config_json
            }
            None => true,
        })
    }

    /// Caller owns this reference's guard and the shared publication barrier.
    async fn publish_metadata(
        &self,
        reference: &Reference,
        metadata: &CachedImageMetadata,
    ) -> Result<(), AcquireError> {
        self.cache
            .write_image_metadata_async(reference, metadata)
            .await
            .map_err(|source| AcquireError::Native {
                stage: AcquireStage::CanonicalPublication,
                source,
            })?;
        gate::detail(gate::Stage::CanonicalReadback).map_err(AcquireError::TestGate)?;
        let matches = self.cached_complete(reference)?.is_some_and(|readback| {
            readback.manifest_digest == metadata.manifest_digest
                && ContentIdentity::of(&readback) == ContentIdentity::of(metadata)
                && readback.raw_config_json == metadata.raw_config_json
        });
        if !matches {
            return Err(AcquireError::Identity);
        }
        Ok(())
    }

    fn validated(
        &self,
        target: &OciTarget,
        metadata: CachedImageMetadata,
    ) -> Result<ValidatedImage, AcquireError> {
        let acquired = self
            .acquired_reference(target, &metadata.manifest_digest)
            .map_err(|_| AcquireError::Identity)?;
        Ok(ValidatedImage {
            source: target.canonical().clone(),
            source_text: target.source_text().to_owned(),
            acquired,
            metadata,
        })
    }

    fn validate(
        &self,
        reference: &Reference,
        result: &PullResult,
    ) -> Result<CachedImageMetadata, ValidationError> {
        let cached = Registry::pull_cached(
            &self.cache,
            reference,
            &PullOptions {
                pull_policy: PullPolicy::Never,
                force: false,
                ..Default::default()
            },
        )
        .map_err(|error| ValidationError::Completeness(error.into()))?;
        let (cached_result, metadata) = cached.ok_or(ValidationError::Identity)?;
        let resolved = result.manifest_digest.to_string();
        if metadata.manifest_digest != resolved
            || cached_result.manifest_digest != result.manifest_digest
            || ValidatedDigest::parse(&metadata.manifest_digest).is_err()
        {
            return Err(ValidationError::Identity);
        }
        check_host_platform(&metadata.raw_config_json).map_err(ValidationError::Platform)?;
        Ok(metadata)
    }

    /// The one raw native pull. Private so no caller can obtain an unvalidated
    /// success; the progress render task is awaited before either outcome is
    /// returned, preserving terminal cleanup and panic visibility.
    async fn native_pull(
        &self,
        registry: &Registry,
        reference: &Reference,
        label: &ImageLabel,
    ) -> Result<PullResult, AcquireError> {
        let options = PullOptions {
            pull_policy: PullPolicy::Always,
            force: false,
            ..Default::default()
        };
        if let Some(dump) = crate::debug_config::native_acquisition(reference, &options, label)
            .map_err(AcquireError::DebugConfig)?
        {
            eprintln!("{dump}");
        }
        let (progress, task) = registry.pull_with_progress(reference, &options);
        let reference_label = label.is_redacted().then(|| label.text().to_string());
        let render = tokio::spawn(crate::pull_progress::render(progress, reference_label));
        let result = task.await.map_err(AcquireError::Task).and_then(|result| {
            result.map_err(|source| AcquireError::Native {
                stage: AcquireStage::Pull,
                source,
            })
        });
        crate::pull_progress::await_render(render).await;
        result
    }
}

/// Acquire `target` and return an opaque validated token plus the shared
/// publication barrier that protected the cache.
///
/// This is the **only** success seam: no caller receives a raw `PullResult` or
/// constructs a [`ValidatedImage`] from strings. The barrier is taken before the
/// first cache read and held until the returned value is dropped.
pub(crate) async fn acquire(
    target: &OciTarget,
    label: &ImageLabel,
    mode: AcquireMode,
) -> Result<PreparedNativeImage, AcquireError> {
    let acquisition = NativeAcquisition::open(target).await?;
    let barrier = PublicationBarrier::shared(acquisition.cache_dir())
        .await
        .map_err(AcquireError::Barrier)?;
    let image = acquisition.acquire(target, label, mode).await?;
    Ok(PreparedNativeImage {
        image,
        _barrier: barrier,
    })
}

/// The previous bytes of a reference's metadata, read under the guard.
enum PriorMetadata {
    Present(Vec<u8>),
    Absent,
}

/// The exclusive, reference-local coordination lock. Dropping it closes the
/// descriptor and releases the `flock`; the lock file itself is never unlinked
/// or truncated, because a stable inode is what makes two processes at the same
/// path contend at all.
struct ReferenceGuard {
    _file: std::fs::File,
}

/// The poll interval of the intentionally unbounded guard wait: short enough
/// that a released lock is noticed promptly, long enough not to spin.
const GUARD_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(25);

/// Whether a guard acquisition reports the deterministic lock checkpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GuardReporting {
    Report,
    Quiet,
}

/// Emit the contention notice once this much contention has been *observed*.
const GUARD_NOTICE_AFTER: std::time::Duration = std::time::Duration::from_secs(1);

/// The one reference-free contention notice. The holder may be waiting on
/// registry I/O with no deadline, so a peer can be silent for a long time; this
/// names no reference, path, URL or credential and is emitted at most once.
const GUARD_CONTENTION_NOTICE: &str = "waiting for another agent-vm acquisition of this image";

impl ReferenceGuard {
    async fn acquire(metadata_path: &Path) -> Result<Self, AcquireError> {
        Self::acquire_reporting(metadata_path, GuardReporting::Report).await
    }

    /// The canonical-preservation guard is a second, derived reference lock
    /// taken after source validation. It deliberately does not report the
    /// source-guard checkpoints: those belong to the acquisition interval the
    /// deterministic guard tests order against. Preservation is observable
    /// through `canonical-readback`/`receipt` detail stages instead.
    async fn acquire_quiet(metadata_path: &Path) -> Result<Self, AcquireError> {
        Self::acquire_reporting(metadata_path, GuardReporting::Quiet).await
    }

    async fn acquire_reporting(
        metadata_path: &Path,
        reporting: GuardReporting,
    ) -> Result<Self, AcquireError> {
        let report = reporting == GuardReporting::Report;
        let lock_path = metadata_path.with_extension("agent-vm-acquire.lock");
        if report {
            gate::checkpoint(gate::Stage::BeforeLock).map_err(AcquireError::TestGate)?;
        }
        let file = open_lock(&lock_path).map_err(|source| AcquireError::ReferenceState {
            stage: ReferenceStage::LockOpen,
            source,
        })?;
        if report && let Some(blocked) = gate::probe_contended(&file) {
            blocked.map_err(|source| AcquireError::ReferenceState {
                stage: ReferenceStage::LockAcquire,
                source,
            })?;
            gate::checkpoint(gate::Stage::LockContended).map_err(AcquireError::TestGate)?;
        }
        // The holder may be waiting on a stalled registry stream with no
        // deadline, so the total wait stays unbounded (no acquisition deadline,
        // never a lock bypass). It is a real async loop, not a detached
        // blocking task: dropping this future drops `file`, so a cancelled
        // caller cannot leave an orphan that takes the lock with nobody left to
        // release it.
        let started = std::time::Instant::now();
        let mut noticed = false;
        loop {
            match crate::host_paths::try_flock(&file, FlockMode::Exclusive).map_err(|source| {
                AcquireError::ReferenceState {
                    stage: ReferenceStage::LockAcquire,
                    source,
                }
            })? {
                FlockAttempt::Acquired => return Ok(Self { _file: file }),
                FlockAttempt::Contended => {}
            }
            if !noticed && started.elapsed() >= GUARD_NOTICE_AFTER {
                noticed = true;
                eprintln!("{GUARD_CONTENTION_NOTICE}");
            }
            tokio::time::sleep(GUARD_POLL_INTERVAL).await;
        }
    }

    fn snapshot(&self, metadata_path: &Path) -> Result<PriorMetadata, AcquireError> {
        let prior = match std::fs::read(metadata_path) {
            Ok(bytes) => PriorMetadata::Present(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => PriorMetadata::Absent,
            Err(error) => {
                return Err(AcquireError::ReferenceState {
                    stage: ReferenceStage::Snapshot,
                    source: anyhow!(error),
                });
            }
        };
        gate::checkpoint(gate::Stage::Snapshot).map_err(AcquireError::TestGate)?;
        Ok(prior)
    }

    /// Restore exactly the bytes captured before this acquisition, or remove
    /// only the requested metadata file if it was absent. Comparing the current
    /// bytes is an optimization, not ownership: ownership is the uninterrupted
    /// guard.
    fn restore(&self, metadata_path: &Path, prior: &PriorMetadata) -> RollbackOutcome {
        // `fail-restore` is only accepted here: the injected fault runs before
        // the restore primitive mutates metadata.
        if let Err(error) = gate::checkpoint(gate::Stage::BeforeRestore) {
            return RollbackOutcome::Failed(error);
        }
        let outcome = match prior {
            PriorMetadata::Present(bytes) => {
                let unchanged = std::fs::read(metadata_path)
                    .map(|current| current == *bytes)
                    .unwrap_or(false);
                if unchanged {
                    Ok(())
                } else {
                    crate::host_paths::atomic_write(metadata_path, bytes, 0o644)
                }
            }
            PriorMetadata::Absent => match std::fs::remove_file(metadata_path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error.into()),
            },
        };
        match outcome {
            // The bytes are back, but a gate failure here means the caller must
            // not claim a verified recovery either.
            Ok(()) => match gate::checkpoint(gate::Stage::AfterRestore) {
                Ok(()) => RollbackOutcome::Restored,
                Err(error) => RollbackOutcome::Failed(
                    error.context("confirming the restored reference metadata"),
                ),
            },
            Err(error) => RollbackOutcome::Failed(error),
        }
    }
}

/// Open (creating if needed) the guard file as a regular file without following
/// a final-component symlink, matching the retained-record lock's pattern.
fn open_lock(path: &Path) -> anyhow::Result<std::fs::File> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|error| anyhow!(error))?;
    let stat = rustix::fs::fstat(&fd).map_err(|error| anyhow!(error))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(anyhow!("not a regular file"));
    }
    Ok(std::fs::File::from(fd))
}

#[derive(serde::Deserialize)]
struct ConfigPlatform {
    os: String,
    architecture: String,
    variant: Option<String>,
}

/// Prove the cached raw image config describes this host's Linux platform.
///
/// Native index selection alone is not validation of a direct single-platform
/// manifest's config, and `PullResult.config` omits the OS/architecture facts,
/// so the complete cached metadata's raw JSON is the input here.
fn check_host_platform(raw_config: &str) -> Result<(), PlatformRejection> {
    check_platform(raw_config, &Platform::host_linux())
}

fn check_platform(raw_config: &str, host: &Platform) -> Result<(), PlatformRejection> {
    let config: ConfigPlatform =
        serde_json::from_str(raw_config).map_err(|_| PlatformRejection::InvalidMetadata)?;
    if !acquired_platform_is_acceptable(PlatformFacts {
        os_matches: config.os == host.os.to_string(),
        arch_matches: config.architecture == host.arch.to_string(),
        variant_matches: host
            .variant
            .as_ref()
            .is_none_or(|variant| config.variant.as_ref() == Some(variant)),
    }) {
        return Err(PlatformRejection::HostMismatch);
    }
    Ok(())
}

verus! {
struct PlatformFacts {
    os_matches: bool,
    arch_matches: bool,
    variant_matches: bool,
}

fn acquired_platform_is_acceptable(facts: PlatformFacts) -> (accepted: bool)
    ensures accepted == (facts.os_matches && facts.arch_matches && facts.variant_matches)
{
    facts.os_matches && facts.arch_matches && facts.variant_matches
}
}

/// The debug-build-only deterministic checkpoint/fault seam for the two-process
/// coordination tests. A release binary ignores `AGENT_VM_TEST_ACQUIRE_GATE`
/// entirely; with no gate configured every call is a no-op.
///
/// Hooks report stages only — never reference bytes or credentials — and cannot
/// bypass a failed lock: `probe_contended` performs a real non-blocking flock on
/// the just-opened descriptor and only a genuine `WOULDBLOCK` is reported.
mod gate {
    #[cfg(debug_assertions)]
    use std::io::{BufRead, BufReader, Write};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum Stage {
        PublicationContended,
        BeforeLock,
        LockContended,
        Snapshot,
        CacheHit,
        /// A complete, associated cached entry was validated for this selection
        /// and nothing has been republished for it yet. Emitted on both the
        /// canonical and the pre-canonical lookup paths, so a test can order a
        /// peer's publication inside the window this module must not widen.
        CacheValidated,
        NativeOk,
        CanonicalReadback,
        Receipt,
        BeforeRestore,
        AfterRestore,
        /// The launch/setup preparation has validated its image and is about to
        /// hand it to the SDK. Deliberately after every cache read the launcher
        /// owns and before the first SDK consumption.
        BeforeSdkConsume,
        /// The SDK's create call returned (successfully or not), so the barrier
        /// is about to be released.
        CreateReturned,
    }

    impl Stage {
        #[cfg(debug_assertions)]
        fn wire(self) -> &'static str {
            match self {
                Self::PublicationContended => "publication-contended",
                Self::BeforeLock => "before-lock",
                Self::LockContended => "lock-contended",
                Self::Snapshot => "snapshot",
                Self::CacheHit => "cache-hit",
                Self::CacheValidated => "cache-validated",
                Self::NativeOk => "native-ok",
                Self::CanonicalReadback => "canonical-readback",
                Self::Receipt => "receipt",
                Self::BeforeRestore => "before-restore",
                Self::AfterRestore => "after-restore",
                Self::BeforeSdkConsume => "before-sdk-consume",
                Self::CreateReturned => "create-returned",
            }
        }
    }

    /// A non-blocking probe on the freshly opened guard descriptor. `Some(Ok)`
    /// means the checkpoint was emitted after real contention; `Some(Err)` is a
    /// probe I/O failure. `None` means no gate is configured (or a release
    /// build), so the caller just takes the ordinary blocking lock.
    #[cfg(debug_assertions)]
    pub(super) fn probe_contended(file: &std::fs::File) -> Option<Result<(), anyhow::Error>> {
        if std::env::var("AGENT_VM_TEST_ACQUIRE_GATE").is_err() {
            return None;
        }
        let probe = rustix::fs::flock(file, rustix::fs::FlockOperation::NonBlockingLockExclusive);
        match probe {
            Ok(()) => None,
            Err(rustix::io::Errno::WOULDBLOCK) => Some(Ok(())),
            Err(error) => Some(Err(anyhow::anyhow!(error))),
        }
    }

    #[cfg(not(debug_assertions))]
    pub(super) fn probe_contended(_file: &std::fs::File) -> Option<Result<(), anyhow::Error>> {
        None
    }

    /// Send one stage to the test-owned listener and read its reply. A gate I/O
    /// failure is surfaced to the caller, which decides whether it is an
    /// acquisition error or a postvalidation failure (never an early return
    /// that skips a restore).
    #[cfg(debug_assertions)]
    pub(super) fn checkpoint(stage: Stage) -> Result<(), anyhow::Error> {
        use std::os::unix::net::UnixStream;
        let Ok(path) = std::env::var("AGENT_VM_TEST_ACQUIRE_GATE") else {
            return Ok(());
        };
        let mut stream = UnixStream::connect(&path)?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(60)))?;
        stream.set_write_timeout(Some(std::time::Duration::from_secs(60)))?;
        writeln!(stream, "{}", stage.wire())?;
        stream.flush()?;
        let mut reply = String::new();
        BufReader::new(stream).read_line(&mut reply)?;
        // A fault reply is honoured only at the stage it describes, so a test
        // cannot fake a validation failure before native publication or a
        // restore failure after one.
        match (reply.trim(), stage) {
            ("continue", _) => Ok(()),
            ("fail-validation", Stage::NativeOk) => Err(anyhow::anyhow!(
                "test-injected validation failure for https://private-validation-source.invalid/repository"
            )),
            ("fail-restore", Stage::BeforeRestore) => Err(anyhow::anyhow!(
                "test-injected restore failure for https://private-restore-source.invalid/repository"
            )),
            ("", _) => Err(anyhow::anyhow!("acquisition gate closed without a reply")),
            (other, stage) => Err(anyhow::anyhow!(
                "unexpected acquisition gate reply {other:?} at {}",
                stage.wire()
            )),
        }
    }

    /// A stage-only *observation* checkpoint, enabled independently by
    /// `AGENT_VM_TEST_ACQUIRE_GATE_DETAIL`. It reports and waits for a reply,
    /// but only when a test explicitly asked for the fine-grained stages; the
    /// guard/fault protocol above stays deterministic for tests that only need
    /// the publication and validation boundaries.
    #[cfg(debug_assertions)]
    pub(super) fn detail(stage: Stage) -> Result<(), anyhow::Error> {
        if std::env::var_os("AGENT_VM_TEST_ACQUIRE_GATE_DETAIL").is_none() {
            return Ok(());
        }
        checkpoint(stage)
    }

    #[cfg(not(debug_assertions))]
    pub(super) fn checkpoint(_stage: Stage) -> Result<(), anyhow::Error> {
        Ok(())
    }

    #[cfg(not(debug_assertions))]
    pub(super) fn detail(_stage: Stage) -> Result<(), anyhow::Error> {
        Ok(())
    }
}

/// Debug-seam checkpoint immediately before the SDK consumes the image cache.
pub(crate) fn gate_before_sdk_consume() -> anyhow::Result<()> {
    gate::checkpoint(gate::Stage::BeforeSdkConsume)
}

/// Debug-seam checkpoint after the SDK create call returned, before the barrier
/// is released.
pub(crate) fn gate_create_returned() -> anyhow::Result<()> {
    gate::checkpoint(gate::Stage::CreateReturned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_facts_require_every_conjunct() {
        for bits in 0..8 {
            assert_eq!(
                acquired_platform_is_acceptable(PlatformFacts {
                    os_matches: bits & 1 != 0,
                    arch_matches: bits & 2 != 0,
                    variant_matches: bits & 4 != 0
                }),
                bits == 7
            );
        }
    }

    #[test]
    fn raw_config_platform_is_required_and_host_linux() {
        let host = Platform::host_linux();
        let valid = serde_json::json!({"os":host.os.to_string(), "architecture":host.arch.to_string(), "unrelated":true});
        assert!(check_host_platform(&valid.to_string()).is_ok());
        assert!(check_host_platform(
            &serde_json::json!({"os":"linux", "architecture":host.arch.to_string(), "variant":"v8"})
                .to_string()
        )
        .is_ok());
        for raw in [
            "{}",
            "{\"os\":\"linux\"}",
            "{\"os\":7,\"architecture\":\"private-marker\"}",
            "{\"os\":\"linux\",\"os\":\"linux\",\"architecture\":\"amd64\"}",
        ] {
            assert_eq!(
                check_host_platform(raw),
                Err(PlatformRejection::InvalidMetadata)
            );
            assert!(
                !ValidationError::Platform(PlatformRejection::InvalidMetadata)
                    .to_string()
                    .contains("private-marker")
            );
        }
        for (os, arch) in [
            ("windows", host.arch.to_string()),
            ("linux", "foreign".to_string()),
        ] {
            assert_eq!(
                check_host_platform(&serde_json::json!({"os":os,"architecture":arch}).to_string()),
                Err(PlatformRejection::HostMismatch)
            );
        }
    }

    #[test]
    fn required_variant_is_checked_by_the_acquisition_adapter() {
        let host = Platform::with_variant("linux", "arm64", "v8");
        for (variant, accepted) in [(None, false), (Some("v7"), false), (Some("v8"), true)] {
            let raw = serde_json::json!({"os":"linux", "architecture":"arm64", "variant":variant});
            assert_eq!(check_platform(&raw.to_string(), &host).is_ok(), accepted);
        }
    }

    #[test]
    fn targets_are_oci_only_with_typed_refusals() {
        for raw in [
            "alpine:latest",
            "localhost:1234/a:release",
            "repo@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert!(OciTarget::parse(raw).is_ok());
        }
        for raw in [
            "",
            "Foo/Bar:tag",
            "repo:bad tag",
            "repo@sha256:short",
            "repo\nsecret",
            "repo\u{1b}",
        ] {
            assert_eq!(
                OciTarget::parse(raw).err().unwrap(),
                OciTargetError::InvalidReference,
                "{raw:?} is malformed, not a local path"
            );
        }
        for raw in ["/private/path", "./rootfs", "../rootfs", ".", ".."] {
            assert_eq!(
                OciTarget::parse(raw).err().unwrap(),
                OciTargetError::LocalPath,
                "{raw:?} is a local launch target"
            );
        }
    }

    /// T2: neither `{}` nor an anyhow chain iteration may expose a source that
    /// names a reference or URL. Raw causes exist only through the deliberate
    /// explicit conversion, which has its own positive controls here.
    #[test]
    fn implicit_error_chains_are_safe_and_explicit_ones_keep_causes() {
        let sentinel = "https://private.example/secret-repository\u{1b}";
        let reference = format!("registry.example/private@sha256:{}", "d".repeat(64));
        let errors = vec![
            AcquireError::Native {
                stage: AcquireStage::Pull,
                source: ImageError::Io(std::io::Error::other(format!(
                    "io for {reference} {sentinel}"
                ))),
            },
            AcquireError::RegistrySettings(MicrosandboxError::InvalidConfig(format!(
                "config for {reference}"
            ))),
            AcquireError::ReferenceState {
                stage: ReferenceStage::Snapshot,
                source: anyhow!("snapshot for {reference}"),
            },
            AcquireError::PostValidation {
                source: ValidationError::Completeness(anyhow!("validation for {sentinel}")),
                rollback: RollbackOutcome::Failed(anyhow!("restore for {sentinel}")),
            },
            AcquireError::TestGate(anyhow!("gate for {reference}")),
        ];
        for error in errors {
            let safe = error.redacted_message();
            let implicit = format!("{:#}", anyhow::Error::from(error));
            for rendered in [&safe, &implicit] {
                assert!(!rendered.contains("secret-repository"), "{rendered}");
                assert!(!rendered.contains("private"), "{rendered}");
                assert!(!rendered.contains('\u{1b}'), "{rendered}");
            }
        }
        // Explicit positive controls: the deliberate conversion still carries
        // both postvalidation stages and its recovery requirement.
        let explicit = AcquireError::PostValidation {
            source: ValidationError::Completeness(anyhow!("validation for {sentinel}")),
            rollback: RollbackOutcome::Failed(anyhow!("restore for {sentinel}")),
        }
        .into_explicit_error();
        let chain = format!("{explicit:#}");
        assert!(
            chain.contains("validating the acquired image cache"),
            "{chain}"
        );
        assert!(
            chain.contains("restoring previous reference metadata also failed"),
            "{chain}"
        );
        assert!(chain.contains("cache recovery is required"), "{chain}");
        let native = AcquireError::Native {
            stage: AcquireStage::Pull,
            source: ImageError::Io(std::io::Error::other(format!("io for {sentinel}"))),
        }
        .into_explicit_error();
        assert!(format!("{native:#}").contains("acquiring the image failed"));
    }

    /// T4: a prepublication test-gate failure is its own category, not the
    /// debug-record dump. Postpublication gate failures keep their existing
    /// postvalidation/rollback meaning.
    #[test]
    fn test_gate_failures_are_their_own_safe_category() {
        let gate = AcquireError::TestGate(anyhow!("unexpected acquisition gate reply"));
        assert_eq!(
            gate.redacted_message(),
            "native acquisition test gate failed"
        );
        assert!(format!("{gate:#}").contains("native acquisition test gate failed"));
        let debug = AcquireError::DebugConfig(anyhow!("serialize"));
        assert!(debug.redacted_message().contains("debug record"));
        assert_ne!(gate.redacted_message(), debug.redacted_message());
    }

    #[test]
    fn redacted_messages_name_the_rollback_stage_and_no_reference() {
        let sentinel = "registry.example/private@sha256:deadbeef";
        let error = AcquireError::PostValidation {
            source: ValidationError::Completeness(anyhow!("failed for {sentinel}")),
            rollback: RollbackOutcome::Failed(anyhow!("restore failed for {sentinel}")),
        };
        let rendered = error.redacted_message();
        assert_eq!(rendered, POSTVALIDATION_ROLLBACK_FAILED);
        assert!(!rendered.contains(sentinel));
        assert!(rendered.contains("restoring previous reference metadata also failed"));
        assert!(rendered.contains("cache recovery is required"));
        let restored = AcquireError::PostValidation {
            source: ValidationError::Identity,
            rollback: RollbackOutcome::Restored,
        };
        assert_eq!(restored.redacted_message(), POSTVALIDATION_RESTORED);
        assert!(!restored.redacted_message().contains("also failed"));
    }

    /// Native cache metadata for one host-Linux config with a single layer,
    /// built from bytes rather than from an archive.
    fn fixture_metadata(digest: &str) -> CachedImageMetadata {
        let platform = Platform::host_linux();
        let diff_id = format!("sha256:{}", "1".repeat(64));
        let raw_config = serde_json::json!({
            "os": platform.os.to_string(),
            "architecture": platform.arch.to_string(),
            "rootfs": {"type": "layers", "diff_ids": [diff_id]},
            "config": {"Env": ["FROM_BYTES=1"]},
        })
        .to_string();
        let config = microsandbox_image::ImageConfig::parse(raw_config.as_bytes())
            .unwrap()
            .0;
        CachedImageMetadata {
            manifest_digest: digest.to_string(),
            config_digest: format!("sha256:{}", "2".repeat(64)),
            raw_manifest_json: "{}".to_string(),
            raw_config_json: raw_config,
            config,
            layers: vec![microsandbox_image::CachedLayerMetadata {
                digest: format!("sha256:{}", "3".repeat(64)),
                media_type: None,
                size_bytes: Some(1),
                diff_id,
            }],
        }
    }

    fn fixture_acquisition(directory: &std::path::Path) -> NativeAcquisition {
        NativeAcquisition {
            cache: GlobalCache::new(directory).unwrap(),
            cache_dir: directory.to_path_buf(),
            registry_host: "localhost:5000".to_string(),
        }
    }

    /// An immutable source whose cached acquired digest differs from its stated
    /// digest is accepted only with a validated receipt for that exact source,
    /// platform and content identity. A corrupt receipt is a hard error, never
    /// "no receipt".
    #[test]
    fn unequal_immutable_association_requires_a_validated_receipt() {
        let directory = tempfile::tempdir().unwrap();
        let acquisition = fixture_acquisition(directory.path());
        let stated = format!("sha256:{}", "a".repeat(64));
        let acquired = format!("sha256:{}", "b".repeat(64));
        let target = OciTarget::parse(&format!("localhost:5000/a@{stated}")).unwrap();
        let metadata = fixture_metadata(&acquired);
        assert!(
            !acquisition
                .association_accepted(&target, &metadata, AssociationPolicy::RequireProof)
                .unwrap(),
            "cache completeness alone cannot prove an unequal association"
        );
        assert!(
            acquisition
                .association_accepted(&target, &metadata, AssociationPolicy::Consume)
                .unwrap(),
            "a launch consuming this entry accepts it: it is the entry the SDK boots"
        );

        let acquired_ref = target
            .canonical()
            .with_digest(&ValidatedDigest::parse(&acquired).unwrap())
            .unwrap();
        let binding = SourceBinding {
            reference: target.canonical().whole(),
            stated_digest: target.stated_digest().cloned(),
        };
        Receipt::new(
            &acquired_ref,
            &Platform::host_linux(),
            &metadata,
            Some(binding.clone()),
        )
        .unwrap()
        .write(directory.path())
        .unwrap();
        assert!(
            acquisition
                .association_accepted(&target, &metadata, AssociationPolicy::RequireProof)
                .unwrap(),
            "a validated receipt proves the association offline"
        );

        // Different content under the same receipt is corruption, not a
        // missing association: no policy may consume it.
        let mut changed = metadata.clone();
        changed.layers[0].diff_id = format!("sha256:{}", "4".repeat(64));
        for policy in [AssociationPolicy::RequireProof, AssociationPolicy::Consume] {
            let error = acquisition
                .association_accepted(&target, &changed, policy)
                .unwrap_err();
            assert!(matches!(
                &error,
                AcquireError::CachedEntry(CachedEntryError::Conflict)
            ));
        }

        // A binding for a different stated digest does not authorize this one.
        let other =
            OciTarget::parse(&format!("localhost:5000/a@sha256:{}", "c".repeat(64))).unwrap();
        let other_ref = other
            .canonical()
            .with_digest(&ValidatedDigest::parse(&acquired).unwrap())
            .unwrap();
        let incoming = Receipt::new(
            &other_ref,
            &Platform::host_linux(),
            &metadata,
            Some(SourceBinding {
                reference: other.canonical().whole(),
                stated_digest: other.stated_digest().cloned(),
            }),
        )
        .unwrap();
        let mut existing = Receipt::read(directory.path(), &acquired_ref, &Platform::host_linux())
            .unwrap()
            .unwrap();
        assert!(!existing.proves(&SourceBinding::of(other.canonical())));
        existing.merge(&incoming).unwrap();
        existing.write(directory.path()).unwrap();
        // Learning another source must not evict the original association.
        assert!(
            acquisition
                .association_accepted(&target, &metadata, AssociationPolicy::RequireProof)
                .unwrap()
        );

        // Corruption is a hard error under *both* policies: consuming the cache
        // never downgrades a corrupt record to a missing one.
        let path = Receipt::path(directory.path(), &acquired_ref, &Platform::host_linux());
        std::fs::write(&path, b"not json").unwrap();
        for policy in [AssociationPolicy::RequireProof, AssociationPolicy::Consume] {
            assert!(
                matches!(
                    acquisition.association_accepted(&target, &metadata, policy),
                    Err(AcquireError::Receipt(_))
                ),
                "{policy:?}: a corrupt receipt is never a missing receipt"
            );
        }
    }

    /// Only a source that states an immutable digest records a binding: that is
    /// the only case the association check ever consults, so a mutable tag would
    /// spend one of the bounded slots for nothing.
    #[test]
    fn only_immutable_sources_record_a_binding() {
        let tag = OciTarget::parse("localhost:5000/a:Tag").unwrap();
        let pin = OciTarget::parse(&format!("localhost:5000/a@sha256:{}", "a".repeat(64))).unwrap();
        assert_eq!(Preservation::FreshAcquisition.binding(&tag), None);
        assert_eq!(Preservation::ValidatedCache.binding(&tag), None);
        assert_eq!(Preservation::ValidatedCache.binding(&pin), None);
        assert_eq!(
            Preservation::FreshAcquisition.binding(&pin),
            Some(SourceBinding::of(pin.canonical())),
            "an immutable source keeps the association only a receipt can prove"
        );
    }

    /// The token keeps the source binding and the acquired identity separate and
    /// renders no reference in Debug.
    #[test]
    fn validated_token_is_opaque_and_keeps_the_source_binding() {
        let directory = tempfile::tempdir().unwrap();
        let acquisition = fixture_acquisition(directory.path());
        let digest = format!("sha256:{}", "b".repeat(64));
        let target = OciTarget::parse("localhost:5000/a:Tag").unwrap();
        let image = acquisition
            .validated(&target, fixture_metadata(&digest))
            .unwrap();
        assert_eq!(image.source().whole(), "localhost:5000/a:Tag");
        assert_eq!(image.source_text(), "localhost:5000/a:Tag");
        assert!(image.source().digest().is_none());
        assert_eq!(image.acquired_digest().as_str(), digest);
        assert_eq!(image.image_env(), ["FROM_BYTES=1".to_string()]);
        assert_eq!(
            image
                .source()
                .with_digest(&image.acquired_digest().clone())
                .unwrap()
                .whole(),
            format!("localhost:5000/a@{digest}")
        );
        assert_eq!(image.content_identity().diff_ids.len(), 1);
        let rendered = format!("{image:?}");
        assert!(!rendered.contains("localhost"));
        assert!(!rendered.contains(&digest));
    }

    /// A handle opened for one registry can never be aimed at another: a real
    /// listener stands in for the second registry, so a leaked request or
    /// credential would be observable. Refusal happens before a guard, debug
    /// record, cache write or network call.
    #[test]
    fn another_registry_is_refused_before_any_lock_request_or_cache_write() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let directory = tempfile::tempdir().unwrap();
        let cache = GlobalCache::new(directory.path()).unwrap();
        let registry = Registry::builder(Platform::host_linux(), cache.clone())
            .build()
            .unwrap();
        let _ = registry;
        let acquisition = NativeAcquisition {
            cache: cache.clone(),
            cache_dir: directory.path().to_path_buf(),
            registry_host: "127.0.0.1:9".to_string(),
        };
        let target = OciTarget::parse(&format!("127.0.0.1:{port}/private:tag")).unwrap();
        assert!(matches!(
            acquisition.ensure_registry(&target),
            Err(AcquireError::RegistryMismatch)
        ));
        assert!(
            listener.accept().is_err(),
            "the second registry must receive no connection"
        );
        let metadata = cache.image_metadata_path(target.reference());
        assert!(!metadata.exists());
        assert!(!metadata.with_extension("agent-vm-acquire.lock").exists());
    }

    /// A cancelled guard waiter must not keep the reference lock: the wait is a
    /// real async loop, so aborting it drops the descriptor instead of leaving a
    /// detached task that takes the lock with nobody left to release it.
    #[test]
    fn a_cancelled_guard_waiter_releases_the_reference_lock() {
        let directory = tempfile::tempdir().unwrap();
        let metadata_path = directory.path().join("reference.json");
        let lock_path = metadata_path.with_extension("agent-vm-acquire.lock");
        let held = open_lock(&lock_path).unwrap();
        rustix::fs::flock(&held, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .expect("the test must take the reference lock");
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let waiter = tokio::spawn({
                let path = metadata_path.clone();
                async move { ReferenceGuard::acquire(&path).await.map(|_| ()) }
            });
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            waiter.abort();
            assert!(waiter.await.unwrap_err().is_cancelled());
        });
        drop(held);
        // A waiter that survived cancellation would hold the lock forever.
        let probe = open_lock(&lock_path).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if rustix::fs::flock(&probe, rustix::fs::FlockOperation::NonBlockingLockExclusive)
                .is_ok()
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "a cancelled guard waiter kept the reference lock"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// A present entry that cannot back the selection is a *miss* for the
    /// cache-first policy, which then reacquires the stated digest — never a tag.
    /// The one closed failure is a contradiction with a preserved receipt.
    #[tokio::test]
    async fn a_present_but_incomplete_entry_is_a_cache_miss() {
        let directory = tempfile::tempdir().unwrap();
        let acquisition = fixture_acquisition(directory.path());
        let digest = format!("sha256:{}", "a".repeat(64));
        let target = OciTarget::parse(&format!("localhost:5000/a@{digest}")).unwrap();
        // An entry file with no materialized content behind it.
        let metadata_path = acquisition.cache.image_metadata_path(target.reference());
        std::fs::create_dir_all(metadata_path.parent().unwrap()).unwrap();
        std::fs::write(&metadata_path, b"{}").unwrap();
        assert!(
            acquisition
                .cached(&target, AssociationPolicy::RequireProof)
                .await
                .unwrap()
                .is_none(),
            "an unusable entry must be a miss so the digest is reacquired"
        );
        let rendered = AcquireError::CachedEntry(CachedEntryError::Conflict).redacted_message();
        assert!(!rendered.contains("localhost"), "{rendered}");
        assert!(!rendered.contains(&digest), "{rendered}");
        // An absent entry is a miss too.
        std::fs::remove_file(&metadata_path).unwrap();
        assert!(
            acquisition
                .cached(&target, AssociationPolicy::RequireProof)
                .await
                .unwrap()
                .is_none(),
            "an absent entry must stay a miss"
        );
    }

    /// Only the cache-first acquisition mode reads the cache here, and it is the
    /// one that establishes content, so it keeps the strict association rule.
    /// A deliberate resolution never short-circuits on cache contents.
    #[test]
    fn only_the_establishing_mode_reads_the_cache_strictly() {
        assert_eq!(
            AcquireMode::CachedOrAcquire.cache_first_policy(),
            Some(AssociationPolicy::RequireProof)
        );
        assert_eq!(AcquireMode::ResolveCurrent.cache_first_policy(), None);
    }

    /// A mutable tag claims no immutable identity, so completeness is all either
    /// policy can ask of it: a tag whose cached child differs is usable warm.
    #[test]
    fn a_tag_needs_no_association_under_either_policy() {
        let directory = tempfile::tempdir().unwrap();
        let acquisition = fixture_acquisition(directory.path());
        let tag = OciTarget::parse("localhost:5000/a:Tag").unwrap();
        let metadata = fixture_metadata(&format!("sha256:{}", "b".repeat(64)));
        for policy in [AssociationPolicy::Consume, AssociationPolicy::RequireProof] {
            assert!(
                acquisition
                    .association_accepted(&tag, &metadata, policy)
                    .unwrap(),
                "{policy:?}: a mutable tag has no association to prove"
            );
        }
        // An entry that *is* the stated digest needs no proof either.
        let stated = metadata.manifest_digest.clone();
        let pin = OciTarget::parse(&format!("localhost:5000/a@{stated}")).unwrap();
        for policy in [AssociationPolicy::Consume, AssociationPolicy::RequireProof] {
            assert!(
                acquisition
                    .association_accepted(&pin, &metadata, policy)
                    .unwrap(),
                "{policy:?}: equal immutable identities agree"
            );
        }
    }

    /// A preserved receipt proves this content; an entry that now contradicts
    /// it is corruption under **both** policies. Relaxing the proof for a
    /// consuming launch (no receipt) must never relax content consistency (a
    /// receipt that disagrees).
    #[test]
    fn a_receipt_contradicting_the_cached_content_is_a_hard_error() {
        use crate::image_acquire::receipt::{Receipt, SourceBinding};

        let directory = tempfile::tempdir().unwrap();
        let acquisition = fixture_acquisition(directory.path());
        let stated = format!("sha256:{}", "a".repeat(64));
        let child = format!("sha256:{}", "b".repeat(64));
        let target = OciTarget::parse(&format!("localhost:5000/a@{stated}")).unwrap();
        let cached = fixture_metadata(&child);
        // The preserved identity names the same source and child but different
        // content (a different config digest).
        let mut preserved = fixture_metadata(&child);
        preserved.config_digest = format!("sha256:{}", "9".repeat(64));
        let acquired = acquisition.acquired_reference(&target, &child).unwrap();
        Receipt::new(
            &acquired,
            &Platform::host_linux(),
            &preserved,
            Some(SourceBinding::of(target.canonical())),
        )
        .unwrap()
        .write(directory.path())
        .unwrap();

        for policy in [AssociationPolicy::Consume, AssociationPolicy::RequireProof] {
            let error = acquisition
                .association_accepted(&target, &cached, policy)
                .unwrap_err();
            assert!(
                matches!(
                    &error,
                    AcquireError::CachedEntry(CachedEntryError::Conflict)
                ),
                "{policy:?}: a contradicting receipt is corruption, not a miss: {error:?}"
            );
            assert!(!error.redacted_message().contains("localhost"));
        }
    }
}
