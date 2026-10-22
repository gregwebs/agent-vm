//! Shared native acquisition of one OCI reference into microsandbox's cache.
//!
//! The selection verbs that need bytes (`image refresh`, `setup`'s pull step and
//! `image set-default`) differ in *policy* — which reference to acquire, what to
//! do on success, how much of a failure may be rendered — but not in *how* bytes
//! arrive. This module owns that one path: resolve the local backend's cache and
//! registry settings, pull with [`PullPolicy::Always`] and `force: false` (so
//! valid cached layers are reused, not destroyed), then prove the result is
//! usable before returning it. No sandbox, VM, Docker or alternate download
//! backend is involved.
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
//! and reference key. It is bounded to one cache and one reference, so it is
//! not a multi-reference or host-wide transaction. Unmodified `msb pull`,
//! ordinary launch cache writers, archive import/build and cache deletion do
//! **not** take it: those must be quiescent for the rollback guarantee, and
//! concurrent external writers keep their existing last-writer-wins exposure.
//! Readers and launches do not take it either, so they can observe the native
//! publication before this wrapper's validation (or the restored, complete
//! metadata after a rollback). No fsync/power-loss or process-kill rollback is
//! claimed: process death releases the descriptor, not the publication.
//!
//! Lock order is launcher reference guard → native per-reference pull lock →
//! native content locks. The native lock file (`cache.image_lock_path`) is
//! deliberately *not* taken here: `Registry::pull_inner` opens and locks it
//! itself with no already-held-lock variant, so pre-acquiring it would
//! deadlock.

use anyhow::anyhow;
use microsandbox::{MicrosandboxError, backend};
use microsandbox_image::{
    GlobalCache, ImageError, Platform, PullOptions, PullPolicy, PullResult, Reference, Registry,
};
use rustix::fs::{FileType, Mode, OFlags};
use std::path::Path;
use vstd::prelude::*;

use crate::boot_image::{ImageLabel, ImageRef};

/// Why an acquisition target was refused. The two are *different* user mistakes
/// and get different fixed advice: a local rootfs/disk path is a supported
/// launch target that simply cannot be acquired, while a malformed reference is
/// not a local path at all and must not be told to launch itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OciTargetError {
    LocalPath,
    InvalidReference,
}

/// A validated OCI acquisition target: the same acceptance rule config-file
/// images use (OCI, not an SDK local path, no whitespace/control) plus the
/// native parser's normalization for registry and cache keys.
///
/// Deliberately *not* [`ImageRef::from_override`]: a local rootfs launch stays
/// supported, but nothing acquires it from a registry.
pub(crate) struct OciTarget {
    reference: Reference,
}

impl OciTarget {
    pub(crate) fn parse(raw: &str) -> Result<Self, OciTargetError> {
        let reference = raw.parse::<Reference>().map_err(|_| refuse(raw))?;
        // The config-file rule adds the no-whitespace/no-control policy on top
        // of the native parser. Either check failing is a refusal; only the
        // shape of the supplied text decides which fixed advice applies.
        ImageRef::from_config(raw).map_err(|_| refuse(raw))?;
        Ok(Self { reference })
    }

    pub(crate) fn reference(&self) -> &Reference {
        &self.reference
    }
}

/// Classify a refused target from its text alone: no stat, no filesystem read.
fn refuse(raw: &str) -> OciTargetError {
    if microsandbox_utils::looks_like_local_path_text(raw) {
        OciTargetError::LocalPath
    } else {
        OciTargetError::InvalidReference
    }
}

/// Which acquisition step a native failure came from. Rendered as fixed text;
/// it never carries a reference, path or source chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AcquireStage {
    CachePreparation,
    RegistryConstruction,
    Pull,
}

impl AcquireStage {
    fn describe(self) -> &'static str {
        match self {
            Self::CachePreparation => "preparing the native image cache",
            Self::RegistryConstruction => "preparing registry access",
            Self::Pull => "acquiring the image",
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

/// One native cache + registry client for a single registry host.
///
/// `open` fixes the cache and credentials; `pull` refuses any target whose
/// normalized registry differs, so a `Registry` handle (and the credentials
/// resolved for its host) can never be pointed at another registry.
pub(crate) struct NativeAcquisition {
    cache: GlobalCache,
    registry: Registry,
    registry_host: String,
}

impl NativeAcquisition {
    pub(crate) async fn open(target: &OciTarget) -> Result<Self, AcquireError> {
        let backend = backend::default_backend();
        let local = backend.as_local().ok_or(AcquireError::NonLocalBackend)?;
        // The backend's resolved cache dir, including a persisted shared-cache
        // redirect. Not `effective_cache_dir`, not MSB_HOME, not HOME.
        let cache =
            GlobalCache::new(&local.cache_dir()).map_err(|source| AcquireError::Native {
                stage: AcquireStage::CachePreparation,
                source,
            })?;
        let registry_host = target.reference().registry().to_owned();
        // Managed settings, keyring/Docker credentials and CA trust resolution
        // stay the backend's: this wrapper never reads credential material
        // itself and never falls back to anonymous access.
        let settings = local
            .registry_config(
                &registry_host,
                microsandbox::config::RegistryOptions {
                    insecure: crate::pull::is_plain_http_registry(&registry_host),
                    ..Default::default()
                },
            )
            .await
            .map_err(AcquireError::RegistrySettings)?;
        let registry = Registry::builder(Platform::host_linux(), cache.clone())
            .auth(settings.auth)
            .extra_ca_certs(settings.ca_certs)
            .add_insecure_registries(settings.insecure_registries)
            .build()
            .map_err(|source| AcquireError::Native {
                stage: AcquireStage::RegistryConstruction,
                source,
            })?;
        Ok(Self {
            cache,
            registry,
            registry_host,
        })
    }

    /// Acquire `target` and return only after guarded completeness, identity and
    /// host-platform validation succeeded.
    ///
    /// On an ordinary native error nothing is restored: native materialization
    /// and metadata writes precede its atomic rename, so a failed native pull
    /// owned no successful publication to undo. A join failure is treated as
    /// publication-uncertain for the same reason (no speculative rollback).
    pub(crate) async fn pull(
        &self,
        target: &OciTarget,
        label: &ImageLabel,
    ) -> Result<PullResult, AcquireError> {
        if target.reference().registry() != self.registry_host {
            return Err(AcquireError::RegistryMismatch);
        }
        let metadata_path = self.cache.image_metadata_path(target.reference());
        let guard = ReferenceGuard::acquire(&metadata_path).await?;
        let prior = guard.snapshot(&metadata_path)?;

        let result = self.native_pull(target.reference(), label).await?;

        // Publication is now owned by this guarded writer cohort: validate the
        // requested key's complete cached entry against the returned resolved
        // identity before anyone else may snapshot it. A gate failure here is a
        // postvalidation failure (so the snapshot is restored), never an early
        // return that skips the restore.
        let validated = gate::checkpoint(gate::Stage::NativeOk)
            .map_err(ValidationError::Completeness)
            .and_then(|()| self.validate(target.reference(), &result));
        if let Err(source) = validated {
            let rollback = guard.restore(&metadata_path, &prior);
            return Err(AcquireError::PostValidation { source, rollback });
        }
        drop(guard);
        Ok(result)
    }

    fn validate(&self, reference: &Reference, result: &PullResult) -> Result<(), ValidationError> {
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
        {
            return Err(ValidationError::Identity);
        }
        check_host_platform(&metadata.raw_config_json).map_err(ValidationError::Platform)
    }

    /// The one raw native pull. Private so no caller can obtain an unvalidated
    /// success; the progress render task is awaited before either outcome is
    /// returned, preserving terminal cleanup and panic visibility.
    async fn native_pull(
        &self,
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
        let (progress, task) = self.registry.pull_with_progress(reference, &options);
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

/// One bounded observation window of the intentionally unbounded guard wait.
const GUARD_WAIT_WINDOW: std::time::Duration = std::time::Duration::from_secs(30);

/// Emit the contention notice once this much contention has been *observed*.
const GUARD_NOTICE_AFTER: std::time::Duration = std::time::Duration::from_secs(1);

/// The one reference-free contention notice. The holder may be waiting on
/// registry I/O with no deadline, so a peer can be silent for a long time; this
/// names no reference, path, URL or credential and is emitted at most once.
const GUARD_CONTENTION_NOTICE: &str = "waiting for another agent-vm acquisition of this image";

impl ReferenceGuard {
    async fn acquire(metadata_path: &Path) -> Result<Self, AcquireError> {
        let lock_path = metadata_path.with_extension("agent-vm-acquire.lock");
        gate::checkpoint(gate::Stage::BeforeLock).map_err(AcquireError::TestGate)?;
        let file = open_lock(&lock_path).map_err(|source| AcquireError::ReferenceState {
            stage: ReferenceStage::LockOpen,
            source,
        })?;
        if let Some(blocked) = gate::probe_contended(&file) {
            blocked.map_err(|source| AcquireError::ReferenceState {
                stage: ReferenceStage::LockAcquire,
                source,
            })?;
            gate::checkpoint(gate::Stage::LockContended).map_err(AcquireError::TestGate)?;
        }
        // The lock is held by a peer that may be waiting outside agent-vm (a
        // stalled registry stream), so poll in bounded windows rather than
        // blocking invisibly forever. The *total* wait stays unbounded: this is
        // observability, not an acquisition deadline or a lock bypass. The
        // descriptor is the same one throughout.
        let acquired = tokio::task::spawn_blocking(move || {
            let mut observed_contention = std::time::Duration::ZERO;
            let mut noticed = false;
            loop {
                let outcome = crate::host_paths::flock_exclusive_within(
                    &file,
                    GUARD_WAIT_WINDOW,
                    |elapsed| {
                        if !noticed && observed_contention + elapsed >= GUARD_NOTICE_AFTER {
                            noticed = true;
                            eprintln!("{GUARD_CONTENTION_NOTICE}");
                        }
                    },
                )?;
                if outcome == crate::host_paths::FlockWait::Acquired {
                    return Ok(file);
                }
                observed_contention += GUARD_WAIT_WINDOW;
            }
        })
        .await
        .map_err(|error| AcquireError::ReferenceState {
            stage: ReferenceStage::LockAcquire,
            source: anyhow!(error),
        })?;
        let file = acquired.map_err(|source| AcquireError::ReferenceState {
            stage: ReferenceStage::LockAcquire,
            source,
        })?;
        Ok(Self { _file: file })
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
    let config: ConfigPlatform =
        serde_json::from_str(raw_config).map_err(|_| PlatformRejection::InvalidMetadata)?;
    let host = Platform::host_linux();
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
        BeforeLock,
        LockContended,
        Snapshot,
        NativeOk,
        BeforeRestore,
        AfterRestore,
    }

    impl Stage {
        #[cfg(debug_assertions)]
        fn wire(self) -> &'static str {
            match self {
                Self::BeforeLock => "before-lock",
                Self::LockContended => "lock-contended",
                Self::Snapshot => "snapshot",
                Self::NativeOk => "native-ok",
                Self::BeforeRestore => "before-restore",
                Self::AfterRestore => "after-restore",
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

    #[cfg(not(debug_assertions))]
    pub(super) fn checkpoint(_stage: Stage) -> Result<(), anyhow::Error> {
        Ok(())
    }
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

    /// N1: a handle opened for one registry can never be aimed at another. A
    /// real listener stands in for the second registry, so a leaked request or
    /// credential would be observable; refusal happens before a guard, debug
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
        let acquisition = NativeAcquisition {
            cache: cache.clone(),
            registry,
            registry_host: "127.0.0.1:9".to_string(),
        };
        let target = OciTarget::parse(&format!("127.0.0.1:{port}/private:tag")).unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let result = runtime.block_on(acquisition.pull(&target, &ImageLabel::for_tests("t")));
        assert!(matches!(result, Err(AcquireError::RegistryMismatch)));
        assert!(
            listener.accept().is_err(),
            "the second registry must receive no connection"
        );
        let metadata = cache.image_metadata_path(target.reference());
        assert!(!metadata.exists());
        assert!(!metadata.with_extension("agent-vm-acquire.lock").exists());
    }
}
