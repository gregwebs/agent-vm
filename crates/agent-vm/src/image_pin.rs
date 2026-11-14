//! Project-scoped OCI approval authority. Cache evidence is never approval.
//!
//! One selection key — a project, the canonical OCI reference and the host
//! Linux platform — maps to the approved native manifest content. The project is
//! the command's captured working directory (see [`crate::project`]), so an
//! approval made in one project never changes what another project boots, while
//! cached bytes stay shared. Everything a launch or a
//! setup boots from a registry goes through [`prepare_selected`], every
//! deliberate re-resolution goes through [`refresh`], and an explicit
//! build/import approves its own published result through [`approve_published`]
//! (#391): there is one ordinary preparation and one explicit approval path, so
//! no consumer can quietly acquire content the others would refuse.
//!
//! # Approval normally precedes create
//!
//! [`prepare_selected`] acquires, validates and — for a first selection —
//! commits the pin **before** returning anything to the SDK. Creation may then
//! fail for reasons that have nothing to do with image content (credentials,
//! disk, the runtime), and the approval that was established stands: it records
//! measured content, not a successful boot. The reverse ordering — pin after
//! create — would let a launcher boot unapproved bytes on every failed create.
//!
//! # Host locks are short and never span network or input
//!
//! The pin store's exclusive lock covers one bounded read-modify-write of a
//! small user record. Acquisition happens under the cache publication barrier
//! instead, and nothing ever reads a terminal: the explicit command is the
//! consent (ADR-0067). See [`store`] for the schema and [`project_default`] for
//! the per-project default and the host's starting choice.
//!
//! # What a local path is here
//!
//! A local rootfs directory or disk image is a supported launch target and
//! nothing about it is approvable: [`prepare_selected`] hands the original text
//! back untouched and never touches the store, the cache barrier or a receipt.
//!
//! # What a launch build is here
//!
//! A launch build (`--dockerfile`) boots its own result without approval: typing
//! the flag is the consent (ADR-0061). It bypasses the pin store completely.
//! Right after publication the tag is read back cache-only and must match the
//! loader's reported digest; preparation later reads that immutable `repo@digest`
//! cache-only under the shared barrier held through create.

use std::fmt;

use anyhow::{Result, anyhow, bail};
use microsandbox_image::Platform;
use serde::{Deserialize, Serialize};
use vstd::prelude::*;

use crate::boot_image::{
    AdoptionOffer, BootImage, ImageLabel, ImageRef, ImageSource, ImmutableImageRef,
};
use crate::config;
use crate::image_acquire::{
    self, AcquireError, AcquireMode, ContentIdentity, OciTarget, OciTargetError,
    PreparedNativeImage, ValidatedImage,
};
pub(crate) use crate::image_acquire::{CanonicalOciReference, ValidatedDigest as ManifestDigest};
use crate::project::ProjectDir;

mod active;
mod approval;
mod completion;
mod project_default;
mod publication;
mod store;
mod unpinned;

use active::{Role, RoleClaim, ScopeKey};
pub(crate) use completion::{CommitReport, finish_publication};
pub(crate) use project_default::{
    DefaultSlot, HostDefaultSet, InvokingProject, ObservedDefaults, ProjectDefaultChange,
    load_default_slot, observe_defaults, set_default,
};
pub(crate) use publication::{approve_published, publication_preflight};
pub(crate) use unpinned::{BuiltImage, prepare_unpinned, read_back_unpinned};

// `Option` normally accepts missing fields in serde. Version 1 requires the
// field even when its value is null; deserialize_with disables that default.
fn required_option<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostLinuxPlatform {
    os: String,
    architecture: String,
    #[serde(deserialize_with = "required_option")]
    variant: Option<String>,
}

impl HostLinuxPlatform {
    fn host() -> Self {
        let host = Platform::host_linux();
        Self {
            os: host.os.to_string(),
            architecture: host.arch.to_string(),
            variant: host.variant,
        }
    }

    /// A platform a unit test can render and compare without a runtime.
    #[cfg(test)]
    fn for_tests() -> Self {
        Self::host()
    }

    /// `os/architecture`, plus the variant when the platform has one. The
    /// variant is currently always absent from the host measurement, but the
    /// schema and this rendering keep it so a future variant-specific pin is
    /// never mistaken for the unvariant one.
    fn render(&self) -> String {
        match &self.variant {
            Some(variant) => format!("{}/{}/{}", self.os, self.architecture, variant),
            None => format!("{}/{}", self.os, self.architecture),
        }
    }

    fn valid(&self) -> bool {
        // OCI canonical architecture spellings, not arbitrary display labels.
        let arch_ok = matches!(
            self.architecture.as_str(),
            "386"
                | "amd64"
                | "arm"
                | "arm64"
                | "mips"
                | "mipsle"
                | "mips64"
                | "mips64le"
                | "ppc64"
                | "ppc64le"
                | "riscv64"
                | "s390x"
                | "wasm"
                | "loong64"
        );
        let variant_ok = self.variant.as_ref().is_none_or(|v| {
            variant_is_acceptable(
                v.len(),
                v.bytes().all(image_acquire::is_printable_variant_byte),
            )
        });
        platform_is_acceptable(PlatformFacts {
            linux: self.os == "linux",
            architecture: arch_ok,
            variant: variant_ok,
        })
    }
}

/// The approval scope of one project: the lowercase hex SHA-256 of its captured
/// directory. Only [`ProjectId::of`] and `parse` construct one, so a stored
/// record can never name a scope this module would not produce.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ProjectId(String);

impl ProjectId {
    pub(crate) fn of(project: &ProjectDir) -> Self {
        Self(project.digest_hex())
    }

    /// Store decoding only; the caller maps `Err` to its damaged-store error.
    fn parse(stored: &str) -> std::result::Result<Self, ()> {
        project_id_bytes_are_acceptable(stored)
            .then(|| Self(stored.to_owned()))
            .ok_or(())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    #[cfg(test)]
    fn for_tests(fill: char) -> Self {
        Self(fill.to_string().repeat(64))
    }
}

/// The measured half of [`project_id_is_acceptable`] for one stored spelling,
/// shared by the store decoder and by a record's field facts so both read the
/// same bytes the same way.
pub(crate) fn project_id_bytes_are_acceptable(stored: &str) -> bool {
    project_id_is_acceptable(
        stored.len(),
        stored
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
    )
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PinKey {
    project: ProjectId,
    reference: CanonicalOciReference,
    platform: HostLinuxPlatform,
}

impl PinKey {
    pub(crate) fn new(project: &ProjectId, target: &OciTarget) -> Result<Self> {
        if !source_within_limit(target.canonical().whole().len()) {
            return Err(anyhow!("image pin source exceeds the size limit"));
        }
        Ok(Self {
            project: project.clone(),
            reference: target.canonical().clone(),
            platform: HostLinuxPlatform::host(),
        })
    }

    /// True for a source that states its own immutable digest, which can never
    /// legitimately resolve to different content.
    fn is_immutable(&self) -> bool {
        self.reference.digest().is_some()
    }

    /// The scope whose Boot/Output slots this key's successful claims resolve.
    fn scope(&self) -> ScopeKey {
        ScopeKey::of(self.project.clone(), self.platform.clone())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PinRevision(u64);

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ApprovedPin {
    key: PinKey,
    digest: ManifestDigest,
    revision: PinRevision,
}

impl ApprovedPin {
    /// The approved host child — `repo@digest` — which is what the SDK is given
    /// and what a cache rebuild reacquires. Never the selected tag or index.
    fn immutable_reference(&self) -> Result<ImmutableImageRef> {
        immutable_reference(&self.key.reference, &self.digest)
    }
}

/// `repo@digest` for one canonical reference and measured digest: the one
/// spelling of "this exact approved content", used by the pin, the fallback
/// record and the frozen-candidate revalidation.
fn immutable_reference(
    reference: &CanonicalOciReference,
    digest: &ManifestDigest,
) -> Result<ImmutableImageRef> {
    let pinned = reference
        .with_digest(digest)
        .map_err(|_| approval_unusable())?;
    ImmutableImageRef::parse(&pinned.whole()).map_err(|_| approval_unusable())
}

/// Cannot be constructed from stored strings: only complete native validation
/// supplies the candidate and the measured guest-content identity.
pub(crate) struct ValidatedCandidate {
    key: PinKey,
    digest: ManifestDigest,
    identity: ContentIdentity,
}

impl ValidatedCandidate {
    pub(crate) fn from_image(image: &ValidatedImage, project: &ProjectId) -> Result<Self> {
        let target = OciTarget::parse(&image.source().whole())
            .map_err(|_| anyhow!("validated image source is unusable"))?;
        Ok(Self {
            key: PinKey::new(project, &target)?,
            digest: image.acquired_digest().clone(),
            identity: image.content_identity(),
        })
    }
}

/// Candidate-scoped consent; only [`approval::approve_refresh`] and
/// [`approval::approve_publication`] mint a replacement.
/// No disk string or standalone boolean can authorize a candidate.
struct Approval {
    key: PinKey,
    candidate: ManifestDigest,
    /// One variant per legitimate predecessor relationship, so the impossible
    /// "equivalent **and** a replacement" pair cannot be represented.
    authority: Authority,
}

enum Authority {
    /// A first pin: no predecessor, so no consent is required.
    First,
    /// The resolved content is already approved under another manifest digest
    /// or digest algorithm: keep the stored identity and revision, and never
    /// ask for a replacement.
    Equivalent(ApprovedPin),
    /// A different candidate, authorized exactly as it was displayed.
    Replacement(ApprovedPin),
}

impl Approval {
    /// A first pin: no predecessor, so no consent is required.
    fn initial(candidate: &ValidatedCandidate) -> Self {
        Self {
            key: candidate.key.clone(),
            candidate: candidate.digest.clone(),
            authority: Authority::First,
        }
    }

    /// The resolved content is already approved: keep the stored identity and
    /// revision, and never ask for a replacement.
    fn equivalent(expected: &ApprovedPin, candidate: &ValidatedCandidate) -> Self {
        Self {
            key: expected.key.clone(),
            candidate: candidate.digest.clone(),
            authority: Authority::Equivalent(expected.clone()),
        }
    }

    /// A candidate the explicit command authorized, after its change of approved
    /// content was rendered successfully.
    fn replacement(candidate: &ValidatedCandidate, expected: ApprovedPin) -> Self {
        Self {
            key: candidate.key.clone(),
            candidate: candidate.digest.clone(),
            authority: Authority::Replacement(expected),
        }
    }

    /// The approved record this consent was given against, if any.
    fn expected(&self) -> Option<&ApprovedPin> {
        match &self.authority {
            Authority::First => None,
            Authority::Equivalent(pin) | Authority::Replacement(pin) => Some(pin),
        }
    }

    fn is_equivalent(&self) -> bool {
        matches!(self.authority, Authority::Equivalent(_))
    }

    fn is_replacement(&self) -> bool {
        matches!(self.authority, Authority::Replacement(_))
    }
}

pub(crate) enum DefaultAction {
    None,
    /// Record the default tier's own immutable selection as this project's
    /// default when it has none (write-once, ADR-0067).
    Establish {
        reference: ImmutableImageRef,
        host: project_default::HostRetention,
    },
    /// A recommendation selected while the configuration was unreadable:
    /// initialize an absent host record (R4) but establish nothing (R3).
    SeedHostOnly {
        reference: ImmutableImageRef,
    },
}

impl DefaultAction {
    /// The reference this action may record as the project's default or seed
    /// the host record with.
    fn retained_reference(&self) -> Option<&ImmutableImageRef> {
        match self {
            Self::None => None,
            Self::Establish { reference, .. } | Self::SeedHostOnly { reference } => Some(reference),
        }
    }

    /// Whether this action may initialize an absent host record (R4).
    fn initializes_host(&self) -> bool {
        matches!(
            self,
            Self::Establish {
                host: project_default::HostRetention::InitializeIfAbsent,
                ..
            } | Self::SeedHostOnly { .. }
        )
    }
}

/// What one transaction did to the retained fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DefaultChange {
    /// The fallback is byte-for-byte unchanged, including a write-once adoption
    /// that found an existing record.
    Unchanged,
    /// An absent fallback was initialized.
    Initialized,
    /// An existing fallback was replaced with different content.
    Replaced,
}

/// One prepared selection: what the SDK is given, the environment facts of
/// exactly that content, and the shared publication barrier the create needs.
///
/// Constructed only by [`prepare_selected`] or [`prepare_unpinned`]. Dropping it
/// releases the barrier, which callers do immediately after the SDK create resolves
/// and before guest hooks, commands, or in-guest tool probes.
pub(crate) struct PreparedSelection {
    sdk_reference: String,
    image_env: Option<Vec<String>>,
    /// The canonical **selected** target's text, which is the display store's key
    /// (ADR-0060 R15). `None` for a local path. Deliberately not the approved
    /// digest: a tag must keep one entry across refreshes.
    selection: Option<String>,
    /// Held only so the shared publication barrier outlives the SDK's create;
    /// dropping this value is what releases it. It is also the booted content's
    /// validated metadata, which is where the image's request labels are read.
    native: Option<PreparedNativeImage>,
    cache_only: bool,
}

impl PreparedSelection {
    /// A local rootfs/disk target: the original text, no approval, no barrier.
    fn local(reference: &str) -> Self {
        Self {
            sdk_reference: reference.to_owned(),
            image_env: None,
            selection: None,
            native: None,
            cache_only: false,
        }
    }

    fn immutable_content(
        approved: &ImmutableImageRef,
        selection: String,
        prepared: PreparedNativeImage,
    ) -> Self {
        Self {
            sdk_reference: approved.as_str().to_owned(),
            image_env: Some(prepared.image().image_env().to_vec()),
            selection: Some(selection),
            native: Some(prepared),
            cache_only: false,
        }
    }

    fn cache_only(mut self) -> Self {
        self.cache_only = true;
        self
    }

    /// How the SDK may resolve this image. A launch build never pulls: its
    /// registry host (`agent-vm.invalid`) must not be contacted if the cache lost it.
    pub(crate) fn pull_policy(&self) -> microsandbox::sandbox::PullPolicy {
        if self.cache_only {
            microsandbox::sandbox::PullPolicy::Never
        } else {
            microsandbox::sandbox::PullPolicy::IfMissing
        }
    }

    /// Whether this selection is forbidden any registry access. Read by
    /// [`Self::registry_is_insecure`] and by tests.
    #[cfg(test)]
    pub(crate) fn is_cache_only(&self) -> bool {
        self.cache_only
    }

    /// Whether `.insecure()` (plain HTTP) applies to what the SDK is given.
    ///
    /// The one place the cache-only fact and the reference are combined, so the
    /// create line and the tests exercise the same function rather than a copy
    /// of it: a launch build's `agent-vm.invalid/...` name is a cache key, never
    /// a registry, and `PullPolicy::Never` forbids the fetch anyway.
    pub(crate) fn registry_is_insecure(&self, sdk_image: &str) -> bool {
        crate::pull::registry_is_insecure(self.cache_only, sdk_image)
    }

    /// The reference handed to the SDK's `.image(...)`: an approved
    /// `repo@digest` for an OCI selection, the untouched original text for a
    /// local path.
    pub(crate) fn sdk_reference(&self) -> &str {
        &self.sdk_reference
    }

    /// The acquired image's own OCI config `env`, which is also the answer to a
    /// credential's `sentinelEnv: false` collision check. `None` only for a
    /// local path, which has no OCI config.
    pub(crate) fn image_env(&self) -> Option<&[String]> {
        self.image_env.as_deref()
    }

    /// The image-request report's input: the canonical selected reference and the
    /// labels of exactly the content this launch boots (ADR-0060 R1, R15).
    /// `None` for a local path, which has no OCI config and declares nothing.
    pub(crate) fn request_labels(&self) -> Option<crate::image_requests::LabelSource<'_>> {
        let native = self.native.as_ref()?;
        Some(crate::image_requests::LabelSource {
            selection: self.selection.clone()?,
            labels: native.image().image_labels(),
        })
    }
}

/// The one ordinary preparation for a launch and a setup, scoped to `project`.
///
/// A local path short-circuits with its original text. An existing approval is
/// consumed as `repo@approved child` and never re-resolved from its tag. An
/// absent approval acquires cache-first under the strict association policy,
/// and the first pin is committed — insert-if-absent — before anything is
/// returned. A concurrent different candidate is never overwritten: this
/// preparation revalidates the winner's frozen digest and uses it, or fails
/// before create.
pub(crate) async fn prepare_selected(
    boot: &BootImage,
    project: &ProjectDir,
) -> Result<PreparedSelection> {
    // A launch build has no approval to consume, and treating its internal tag as
    // an OCI source here would first-pin it and turn on `IfMissing` + `.insecure()`
    // for that name — the exposure `prepare_unpinned` exists to prevent.
    // Structurally unreachable (`run::launch` branches on the same fact), so a
    // mismatch is an internal error, not a user error.
    if matches!(boot.source(), ImageSource::LaunchBuild(_)) {
        bail!("internal error: a launch build is prepared by prepare_unpinned, never by pinning");
    }
    let label = boot.label();
    let target = match OciTarget::parse(boot.reference().as_str()) {
        Ok(target) => target,
        Err(OciTargetError::LocalPath) => {
            return Ok(PreparedSelection::local(boot.reference().as_str()));
        }
        Err(OciTargetError::InvalidReference) => {
            return Err(anyhow!(
                "the selected boot image is not a usable OCI image reference; an image \
                 selection that is neither a local rootfs/disk path nor a valid reference \
                 cannot be approved or acquired"
            ));
        }
    };
    // The store key is the **selected** target's canonical text, never the
    // approved digest: a tag keeps one display entry across refreshes (R15).
    let selection = target.canonical().whole();
    // After the local-path return: a local rootfs/disk never derives a project
    // identifier, and its launch never touches the store (R11).
    let key = PinKey::new(&ProjectId::of(project), &target)?;
    let current = lookup(&key)?;
    let Some(current) = current else {
        return prepare_first_pin(boot, &target, &key, &selection, &label).await;
    };
    let prepared = approved_preparation(&current, &label, Rendering::Selection).await?;
    // Acquisition and validation succeeded, so this warm use is an affirmative
    // Boot claim (plus any eligible S2 default work). Reporting issues after the
    // commit are consumed here, not returned as a failed preparation.
    record_prepared(boot, &current)?;
    let approved = current.immutable_reference()?;
    Ok(PreparedSelection::immutable_content(
        &approved, selection, prepared,
    ))
}

/// The absent-approval branch: acquire the source itself, then establish the
/// first pin before create.
///
/// The acquisition is cache-first ([`AcquireMode::CachedOrAcquire`]), so this
/// first pin leaves content evidence for the digest it records: a warm cache hit
/// writes the receipt a later repair reads, which keeps the new approval
/// launchable offline even if an archive overwrites the digest-spelled key.
async fn prepare_first_pin(
    boot: &BootImage,
    target: &OciTarget,
    key: &PinKey,
    selection: &str,
    label: &ImageLabel,
) -> Result<PreparedSelection> {
    let prepared = acquire_or_render(
        target,
        label,
        Rendering::Selection,
        AcquireMode::CachedOrAcquire,
    )
    .await?;
    let candidate = ValidatedCandidate::from_image(prepared.image(), &key.project)?;
    store::candidate_ready()?;
    let action = project_default::establishment(boot)?;
    match commit(
        &candidate,
        &Approval::initial(&candidate),
        action,
        RoleClaim::Claim(Role::Boot),
    ) {
        Ok(store::CommitOutcome::Committed(completion)) => {
            completion::finish_preparation(completion.report);
            let approved = completion.value.pin.immutable_reference()?;
            Ok(PreparedSelection::immutable_content(
                &approved,
                selection.to_owned(),
                prepared,
            ))
        }
        Ok(store::CommitOutcome::Conflict) => {
            // A peer may have committed a different candidate while this
            // preparation was acquiring. Only a typed conflict may re-read a
            // winner; an I/O, full or exhausted error never does.
            let winner = lookup(key)?;
            match winner {
                Some(pin) if pin.digest != candidate.digest => {
                    drop(prepared);
                    let prepared = approved_preparation(&pin, label, Rendering::Selection).await?;
                    record_prepared(boot, &pin)?;
                    let approved = pin.immutable_reference()?;
                    Ok(PreparedSelection::immutable_content(
                        &approved,
                        selection.to_owned(),
                        prepared,
                    ))
                }
                _ => Err(anyhow!(
                    "image approval is stale; retry the explicit operation"
                )),
            }
        }
        Err(error) => Err(error),
    }
}

/// Acquire and validate exactly the approved `repo@digest`, cache-first.
///
/// A missing approved digest is an availability failure, never a reason to
/// fall back to the mutable source: that would silently change guest content.
async fn approved_preparation(
    pin: &ApprovedPin,
    label: &ImageLabel,
    rendering: Rendering,
) -> Result<PreparedNativeImage> {
    let approved = pin.immutable_reference()?;
    let target = OciTarget::parse(approved.as_str()).map_err(|_| approval_unusable())?;
    let prepared = acquire_or_render(&target, label, rendering, AcquireMode::CachedOrAcquire)
        .await
        .map_err(|error| {
            error.context(
                "the approved image content is not available; acquire it from its registry \
                 (it is requested by digest, never by tag) or restore the image cache",
            )
        })?;
    if prepared.image().acquired_digest() != &pin.digest {
        return Err(anyhow!(
            "the approved image content could not be validated: the acquired manifest is not the \
             approved digest"
        ));
    }
    Ok(prepared)
}

/// One explicit re-resolution plus the candidate-scoped approval it needs, in
/// `project`.
///
/// Running `image refresh` is the consent for every change it makes (ADR-0067):
/// a first pin, a replaced approval for a moved mutable source, or adoption of
/// the host default. The source is resolved exactly once, the change is rendered
/// before it is committed, and the host transaction then compares and swaps
/// against the revision and digest that were displayed. A failed render, a
/// failed acquisition, a concurrent writer or an immutable reference that
/// resolved to different content leaves the previous approval and default
/// logically unchanged.
pub(crate) async fn refresh(
    boot: &BootImage,
    offer: Option<AdoptionOffer>,
    project: &ProjectDir,
) -> Result<ProjectDefaultChange> {
    if let Some(host) = &offer {
        if !matches!(boot.source(), ImageSource::ProjectDefault(_)) {
            bail!("internal error: an adoption offer needs an established project default");
        }
        if !same_canonical(host.image().reference().as_str(), boot.reference().as_str())? {
            return project_default::adopt_host_default(boot, host, project).await;
        }
    }
    let plan = Plan::for_refresh(boot)?;
    let key = PinKey::new(&ProjectId::of(project), &plan.target)?;
    let current = lookup(&key)?;
    if !matches!(plan.default_action, DefaultAction::None) {
        // A damaged fallback is a hard error before any registry request: a
        // corrupt record is never "absent" and must not be re-pinned.
        store::Store::host()?.default_health()?;
    }
    let prepared = acquire_or_render(
        &plan.target,
        &plan.label,
        plan.rendering,
        AcquireMode::ResolveCurrent,
    )
    .await?;
    let candidate = ValidatedCandidate::from_image(prepared.image(), &key.project)?;
    store::candidate_ready()?;
    let approval = match &current {
        None => Approval::initial(&candidate),
        Some(pin) if pin.digest == candidate.digest => Approval::equivalent(pin, &candidate),
        Some(pin) => {
            if same_guest_content(pin, &candidate, &plan.label, plan.rendering).await? {
                Approval::equivalent(pin, &candidate)
            } else if key.is_immutable() {
                return Err(immutable_integrity_failure());
            } else {
                // The explicit refresh is the consent: render, then mint.
                approval::approve_refresh(
                    &candidate,
                    pin.clone(),
                    &approval::ApprovalRequest {
                        source: &plan.source,
                        platform: &key.platform,
                        old: &pin.digest,
                        new: &candidate.digest,
                    },
                )?
            }
        }
    };
    // Revalidate only the frozen candidate: a mutable source that moved after it
    // was resolved must not be resolved a second time, and the bytes this
    // approval names are the bytes the transaction commits.
    drop(prepared);
    revalidate_frozen(&candidate, &plan.label, plan.rendering).await?;
    let action = plan.default_action;
    // Refresh preserves scope resolution and every holder: it approves content,
    // never a role (ADR-0068 R7).
    match commit(&candidate, &approval, action, RoleClaim::Keep)? {
        store::CommitOutcome::Committed(completion) => {
            completion::finish_preparation(completion.report);
            Ok(completion.value.project_default)
        }
        store::CommitOutcome::Conflict => Err(anyhow!(
            "image approval is stale; retry the explicit operation"
        )),
    }
}

/// Whether two references name the same canonical content: one spelling of the
/// "is this the same record?" question every default comparison asks.
fn same_canonical(left: &str, right: &str) -> Result<bool> {
    let canonical = |text: &str| {
        CanonicalOciReference::parse(text)
            .map_err(|_| anyhow!("the default boot image reference is not canonical"))
    };
    Ok(canonical(left)? == canonical(right)?)
}

/// Everything one explicit operation decided before any I/O, resolved once.
struct Plan {
    target: OciTarget,
    label: ImageLabel,
    /// The render's source: the escaped selection, or the fixed default-tier
    /// label rather than a record-sourced reference.
    source: String,
    rendering: Rendering,
    default_action: DefaultAction,
}

impl Plan {
    fn for_refresh(boot: &BootImage) -> Result<Self> {
        let label = boot.label();
        let source = if label.is_redacted() {
            label.text().to_owned()
        } else {
            config::escape_str(boot.reference().as_str())
        };
        Ok(Self {
            target: oci_target(boot.reference().as_str())?,
            default_action: project_default::establishment(boot)?,
            rendering: Rendering::Selection,
            label,
            source,
        })
    }
}

fn oci_target(text: &str) -> Result<OciTarget> {
    OciTarget::parse(text).map_err(|_| {
        anyhow!(
            "this operation acquires and approves OCI image content, so its target must be an \
             OCI image reference (tag or digest); a local rootfs or disk image is a launch \
             target and is never approved or cached"
        )
    })
}

/// Is the approved digest's validated native content the same guest content as
/// the candidate, under another manifest digest or digest algorithm?
///
/// The comparison is the measured native identity — the verified config digest
/// and the ordered layer diff IDs — never a hash of a reserialized manifest.
/// Missing evidence fails closed: an approved digest that cannot be prepared is
/// an integrity/availability failure, not permission to approve a replacement.
async fn same_guest_content(
    pin: &ApprovedPin,
    candidate: &ValidatedCandidate,
    label: &ImageLabel,
    rendering: Rendering,
) -> Result<bool> {
    let prepared = approved_preparation(pin, label, rendering)
        .await
        .map_err(|error| {
            error.context(
                "the approved image content could not be prepared to compare with the resolved \
             content, so the change was not approved",
            )
        })?;
    let approved = prepared.image().content_identity();
    Ok(content_is_equivalent(ContentFacts {
        config_equal: approved.config_digest == candidate.identity.config_digest,
        layers_equal: approved.diff_ids == candidate.identity.diff_ids,
    }))
}

/// Re-acquire and revalidate exactly the frozen candidate under a fresh shared
/// barrier, so the host transaction cannot record a digest whose content is no
/// longer present and valid.
async fn revalidate_frozen(
    candidate: &ValidatedCandidate,
    label: &ImageLabel,
    rendering: Rendering,
) -> Result<()> {
    let pinned = immutable_reference(&candidate.key.reference, &candidate.digest)?;
    let target = OciTarget::parse(pinned.as_str()).map_err(|_| approval_unusable())?;
    let prepared = acquire_or_render(&target, label, rendering, AcquireMode::CachedOrAcquire)
        .await
        .map_err(|error| {
            error.context(
                "the resolved image content is no longer available, so the approval was not \
                 committed; re-run the explicit command",
            )
        })?;
    if prepared.image().acquired_digest() != &candidate.digest
        || prepared.image().content_identity() != candidate.identity
    {
        return Err(anyhow!(
            "the resolved image content changed before it could be approved, so nothing was \
             committed; re-run the explicit command"
        ));
    }
    Ok(())
}

/// Acquire through the one native seam, rendering a failure with this
/// selection's output policy.
async fn acquire_or_render(
    target: &OciTarget,
    label: &ImageLabel,
    rendering: Rendering,
    mode: AcquireMode,
) -> Result<PreparedNativeImage> {
    image_acquire::acquire(target, label, mode)
        .await
        .map_err(|error| render_failure(label, rendering, target.source_text(), error))
}

/// How an acquisition failure may be rendered for this operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rendering {
    /// A launch, setup or refresh selection: the label decides.
    Selection,
    /// `image set-default`'s typed target: closed stage text only, plus the
    /// retained-default guarantee the command promises.
    Explicit,
    /// An explicit build/import reading back what it just published: the
    /// explicit chain, and never the import hint — the command *is* the import.
    Publication,
}

/// Render an acquisition failure for one selection without leaking a redacted
/// reference, keeping the import hint for a mutable source a user could import.
fn render_failure(
    label: &ImageLabel,
    rendering: Rendering,
    reference: &str,
    error: AcquireError,
) -> anyhow::Error {
    if rendering == Rendering::Explicit {
        return anyhow!(
            "{}; this command did not change the retained default",
            error.redacted_message()
        );
    }
    // A build/import read-back cannot fail on a registry (its mode never
    // contacts one), so the hint could not fire anyway; the variant keeps that
    // structural rather than incidental, so a future mode change cannot print
    // "import it with --docker" straight after an import.
    if rendering == Rendering::Publication {
        return error.into_explicit_error();
    }
    if label.is_redacted() {
        return match error {
            AcquireError::Native { .. } | AcquireError::RegistrySettings(_) => {
                label.redact_error("pulling", anyhow!(error.redacted_message()))
            }
            // These closed diagnostics carry no reference-bearing source chain.
            // Preserve coordination stages and publication-uncertain recovery
            // advice rather than flattening them into a registry failure.
            _ => anyhow!(error.redacted_message()),
        };
    }
    crate::image_miss::attach(error.into_explicit_error(), reference, label)
}

fn approval_unusable() -> anyhow::Error {
    anyhow!(
        "the stored image approval is unusable; restore the intended records from backup or \
         deliberately move them aside to reset approvals"
    )
}

fn immutable_integrity_failure() -> anyhow::Error {
    anyhow!(
        "an image selected by digest resolved to different content, which is an integrity \
         failure; the existing approval and default are unchanged, and no approval can accept \
         replacement content for an immutable reference"
    )
}

pub(crate) fn lookup(key: &PinKey) -> Result<Option<ApprovedPin>> {
    store::Store::host()?.lookup(key)
}

fn commit(
    candidate: &ValidatedCandidate,
    approval: &Approval,
    action: DefaultAction,
    claim: RoleClaim,
) -> Result<store::CommitOutcome> {
    store::Store::host()?.commit(candidate, approval, action, claim)
}

/// Record a successful warm preparation: claim Boot for exactly the approval
/// this preparation consumed, and do any eligible default work in the same save.
fn record_prepared(boot: &BootImage, consumed: &ApprovedPin) -> Result<()> {
    let action = project_default::establishment(boot)?;
    let completion = store::Store::host()?.claim_selected(consumed, &action)?;
    completion::finish_preparation(completion.report);
    Ok(())
}

/// What the image cache holds for the content a launch of `boot` would boot
/// (ADR-0060 R20): the approved digest when one is approved, otherwise the
/// canonical selection.
///
/// An observation for `doctor`, not a preparation: it never acquires, never
/// contacts a registry, takes no lock and writes nothing. Approval selection is
/// shared with launch preparation ([`lookup`] on the same key), so the diagnostic
/// and the launch cannot disagree about which content is meant.
pub(crate) fn cached_request_labels(
    boot: &BootImage,
    project: Option<&ProjectDir>,
    cache_dir: &std::path::Path,
) -> crate::image_requests::CachedLabels {
    use crate::image_acquire::CachedLabelsRead;
    use crate::image_requests::CachedLabels;
    let parse_reference = |text: &str| text.parse::<microsandbox_image::Reference>().ok();
    match OciTarget::parse(boot.reference().as_str()) {
        Ok(target) => {
            // No captured project means this diagnostic cannot name which
            // project's approval a launch would consume, and a launch would
            // fail before reaching the store at all.
            let Some(project) = project else {
                return CachedLabels::ApprovalUnreadable;
            };
            let key = match PinKey::new(&ProjectId::of(project), &target) {
                Ok(key) => key,
                Err(_) => return CachedLabels::Unreadable,
            };
            let reference = match lookup(&key) {
                // A damaged approval record is its own fixed row: the launch would
                // fail here, so nothing can be said about the cached content.
                Err(_) => return CachedLabels::ApprovalUnreadable,
                Ok(Some(pin)) => match pin.immutable_reference() {
                    Ok(approved) => parse_reference(approved.as_str()),
                    Err(_) => return CachedLabels::Unreadable,
                },
                Ok(None) => parse_reference(target.canonical().whole().as_str()),
            };
            let Some(reference) = reference else {
                return CachedLabels::Unreadable;
            };
            match crate::image_acquire::read_cached_labels_for_diagnostics(cache_dir, &reference) {
                CachedLabelsRead::NotCached => CachedLabels::NotCached,
                CachedLabelsRead::Unreadable => CachedLabels::Unreadable,
                CachedLabelsRead::Present(labels) => CachedLabels::Present(labels),
            }
        }
        // A local path has no OCI config; an unusable reference cannot be
        // observed at all, and the boot-image section above already names that
        // failure, so it gets the same "cannot be read" row.
        Err(OciTargetError::LocalPath) => CachedLabels::LocalPath,
        Err(OciTargetError::InvalidReference) => CachedLabels::Unreadable,
    }
}

/// Logical fallback read: bounded, shared, journal-aware and strictly read-only.
pub(crate) fn load_default() -> Result<Option<ImmutableImageRef>> {
    store::Store::host()?.load_default()
}

macro_rules! redacted_debug {
    ($($ty:ty),+ $(,)?) => {$(impl fmt::Debug for $ty {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(concat!(stringify!($ty), "(<redacted>)"))
        }
    })+};
}
redacted_debug!(
    HostLinuxPlatform,
    ProjectId,
    PinKey,
    ApprovedPin,
    ValidatedCandidate,
    Approval,
    DefaultAction,
    project_default::ProjectDefault,
    project_default::DefaultSlot,
    project_default::ObservedDefaults,
    project_default::DefaultAdoption,
    PreparedSelection
);

verus! {
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommitDecision {
    AlreadyApproved,
    Insert,
    Replace,
    Conflict,
}

/// Facts are measured together from ONE under-lock snapshot. Revision equality
/// includes the digest, so an A→B→A transition cannot reuse approval of old A.
#[derive(Clone, Copy)]
struct CommitFacts {
    current_present: bool,
    expected_present: bool,
    candidate_equal: bool,
    predecessor_matches: bool,
    mutable_source: bool,
    consent: bool,
}

fn commit_decision(f: CommitFacts) -> (decision: CommitDecision)
    ensures
        (decision == CommitDecision::AlreadyApproved) == (f.current_present && f.candidate_equal),
        (decision == CommitDecision::Insert) == (!f.current_present && !f.expected_present),
        (decision == CommitDecision::Replace) == (f.current_present && !f.candidate_equal && f.expected_present && f.predecessor_matches && f.mutable_source && f.consent),
{
    if f.current_present && f.candidate_equal { CommitDecision::AlreadyApproved }
    else if !f.current_present && !f.expected_present { CommitDecision::Insert }
    else if f.current_present && f.expected_present && f.predecessor_matches && f.mutable_source && f.consent { CommitDecision::Replace }
    else { CommitDecision::Conflict }
}
/// The record file is bounded well above one reference plus its schema, so an
/// oversized file is refused before it is parsed.
fn store_bytes_within_limit(bytes: usize) -> (ok: bool)
    ensures ok == (bytes <= 4 * 1024 * 1024),
{ bytes <= 4 * 1024 * 1024 }
fn pin_count_within_limit(pins: usize) -> (ok: bool)
    ensures ok == (pins <= 4096),
{ pins <= 4096 }
fn source_within_limit(bytes: usize) -> (ok: bool)
    ensures ok == (bytes <= 4096),
{ bytes <= 4096 }
fn revision_is_acceptable(revision: u64) -> (ok: bool)
    ensures ok == (revision > 0),
{ revision > 0 }
/// The measured platform facts of one host measurement. Named fields rather than
/// adjacent booleans, so an argument swap cannot invert the decision.
struct PlatformFacts {
    linux: bool,
    architecture: bool,
    variant: bool,
}

fn platform_is_acceptable(facts: PlatformFacts) -> (ok: bool)
    ensures ok == (facts.linux && facts.architecture && facts.variant),
{ facts.linux && facts.architecture && facts.variant }
fn variant_is_acceptable(bytes: usize, printable: bool) -> (ok: bool)
    ensures ok == (bytes > 0 && bytes <= 64 && printable),
{ bytes > 0 && bytes <= 64 && printable }
/// The two physical fallback recordings a pending intent may legitimately show.
struct JournalFacts {
    previous_matches: bool,
    proposed_matches: bool,
}

fn journal_pair_is_acceptable(facts: JournalFacts) -> (ok: bool)
    ensures ok == (facts.previous_matches || facts.proposed_matches),
{ facts.previous_matches || facts.proposed_matches }
/// A project identifier is exactly a lowercase hex SHA-256: 64 characters,
/// which is what the store decoder admits and what [`ProjectId::of`] produces.
fn project_id_is_acceptable(bytes: usize, lowercase_hex: bool) -> (ok: bool)
    ensures ok == (bytes == 64 && lowercase_hex),
{ bytes == 64 && lowercase_hex }
/// One record's measured field facts, named so a swap cannot silently accept a
/// pin file it should refuse.
struct PinFieldFacts {
    project: bool,
    source_bounded: bool,
    canonical: bool,
    platform: bool,
    revision: bool,
    digest: bool,
}

fn pin_fields_are_acceptable(facts: PinFieldFacts) -> (ok: bool)
    ensures ok == (facts.project && facts.source_bounded && facts.canonical && facts.platform && facts.revision && facts.digest),
{ facts.project && facts.source_bounded && facts.canonical && facts.platform && facts.revision && facts.digest }
/// The top-level schema facts. Field validity is each record's own decision, so
/// it is not a second, always-true argument here.
fn schema_is_acceptable(version: u32, keys_unique: bool) -> (ok: bool)
    ensures ok == (version == 2 && keys_unique),
{ version == 2 && keys_unique }
/// A stored `roles`/`resolved` mask must name at least one role: omission is how
/// "holds none" / "resolves none" is spelled, so an empty present value is damage.
fn mask_is_acceptable(nonempty: bool) -> (ok: bool)
    ensures ok == nonempty,
{ nonempty }
/// The measured facts of an approval-equivalence comparison. Named fields rather
/// than adjacent booleans, so an argument swap cannot invert the decision.
struct ContentFacts {
    config_equal: bool,
    layers_equal: bool,
}

/// Content equivalence is what keeps a re-resolved digest from becoming a
/// replacement: equal verified config identity AND equal ordered layer diff IDs.
fn content_is_equivalent(facts: ContentFacts) -> (ok: bool)
    ensures ok == (facts.config_equal && facts.layers_equal),
{ facts.config_equal && facts.layers_equal }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn cas_truth_table() {
        for bits in 0u8..64 {
            let f = CommitFacts {
                current_present: bits & 1 != 0,
                expected_present: bits & 2 != 0,
                candidate_equal: bits & 4 != 0,
                predecessor_matches: bits & 8 != 0,
                mutable_source: bits & 16 != 0,
                consent: bits & 32 != 0,
            };
            let expected = match (f.current_present, f.candidate_equal, f.expected_present) {
                (true, true, _) => CommitDecision::AlreadyApproved,
                (false, _, false) => CommitDecision::Insert,
                (true, false, true) if f.predecessor_matches && f.mutable_source && f.consent => {
                    CommitDecision::Replace
                }
                _ => CommitDecision::Conflict,
            };
            assert_eq!(commit_decision(f), expected, "facts {bits}");
        }
    }

    #[test]
    fn pure_acceptance_boundaries() {
        assert!(store_bytes_within_limit(4 * 1024 * 1024));
        assert!(!store_bytes_within_limit(4 * 1024 * 1024 + 1));
        assert!(pin_count_within_limit(4096));
        assert!(!pin_count_within_limit(4097));
        assert!(source_within_limit(4096));
        assert!(!source_within_limit(4097));
        assert!(!revision_is_acceptable(0));
        assert!(revision_is_acceptable(u64::MAX));
        for len in [0, 1, 64, 65] {
            for printable in [false, true] {
                assert_eq!(
                    variant_is_acceptable(len, printable),
                    (1..=64).contains(&len) && printable
                );
            }
        }
        for bits in 0u8..8 {
            assert_eq!(
                platform_is_acceptable(PlatformFacts {
                    linux: bits & 1 != 0,
                    architecture: bits & 2 != 0,
                    variant: bits & 4 != 0
                }),
                bits == 7
            );
            assert_eq!(
                content_is_equivalent(ContentFacts {
                    config_equal: bits & 1 != 0,
                    layers_equal: bits & 2 != 0
                }),
                bits & 3 == 3
            );
        }
        for bits in 0u8..64 {
            assert_eq!(
                pin_fields_are_acceptable(PinFieldFacts {
                    project: bits & 1 != 0,
                    source_bounded: bits & 2 != 0,
                    canonical: bits & 4 != 0,
                    platform: bits & 8 != 0,
                    revision: bits & 16 != 0,
                    digest: bits & 32 != 0,
                }),
                bits == 63
            );
        }
        for version in [0, 1, 2, 3, u32::MAX] {
            for unique in [false, true] {
                assert_eq!(
                    schema_is_acceptable(version, unique),
                    version == 2 && unique
                );
            }
        }
        for bytes in [0, 63, 64, 65] {
            for lowercase_hex in [false, true] {
                assert_eq!(
                    project_id_is_acceptable(bytes, lowercase_hex),
                    bytes == 64 && lowercase_hex
                );
            }
        }
        for (previous_matches, proposed_matches, expected) in [
            (false, false, false),
            (false, true, true),
            (true, false, true),
            (true, true, true),
        ] {
            assert_eq!(
                journal_pair_is_acceptable(JournalFacts {
                    previous_matches,
                    proposed_matches
                }),
                expected
            );
        }
    }

    #[test]
    fn host_linux_and_redacted_debug() {
        let target = OciTarget::parse("private.example/team/secret:tag").unwrap();
        let key = PinKey::new(&ProjectId::for_tests('a'), &target).unwrap();
        assert_eq!(key.platform.os, "linux");
        assert_eq!(key.platform.variant, None);
        assert!(key.platform.valid());
        assert!(!format!("{key:?} {:?}", key.reference).contains("private.example"));
        assert!(!key.is_immutable());
        let pinned = key
            .reference
            .with_digest(&ManifestDigest::parse(&format!("sha256:{}", "a".repeat(64))).unwrap())
            .unwrap();
        assert!(
            OciTarget::parse(&pinned.whole())
                .unwrap()
                .canonical()
                .digest()
                .is_some()
        );
    }

    /// Session state and approval authority are two consumers of ONE captured
    /// project. If they derived it independently they could disagree after an
    /// external rename, and one command would write two projects' records.
    #[test]
    fn session_and_pins_derive_from_one_capture() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("project");
        std::fs::create_dir(&dir).unwrap();
        let project =
            ProjectDir::from_path_for_tests(&dir).expect("canonicalize the fixture project");
        let session = crate::session::ProjectSession::for_project(&project)
            .expect("a project with HOME set has a session");
        let id = ProjectId::of(&project);
        assert_eq!(session.project_dir, project.path());
        assert_eq!(session.project_hash, id.as_str()[..12]);
        assert_eq!(id.as_str().len(), 64);
    }

    #[test]
    fn prepared_local_selection_passes_the_original_text_through() {
        let selection = PreparedSelection::local("/host/rootfs");
        assert_eq!(selection.sdk_reference(), "/host/rootfs");
        assert!(selection.image_env().is_none());
    }

    /// A launch build must never be pinned: `run::launch` branches on the same
    /// fact, so reaching the pin path with one is a wiring bug, and it fails
    /// loudly instead of first-pinning the internal name (which would turn on
    /// `IfMissing` + `.insecure()` for it).
    #[tokio::test]
    async fn prepare_selected_refuses_a_launch_build_selection() {
        let boot = BootImage::launch_build(
            ImageRef::from_config("agent-vm.invalid/dockerfile/abc:latest").unwrap(),
            std::path::PathBuf::from("Dockerfile"),
        );
        let project = ProjectDir::from_path_for_tests(std::env::current_dir().unwrap().as_path())
            .expect("canonicalize the test cwd");
        let error = prepare_selected(&boot, &project).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "internal error: a launch build is prepared by prepare_unpinned, never by pinning"
        );
    }

    /// R16 is a conjunction: only a launch build may skip the registry. A
    /// selection that is `cache_only` by accident would turn every warm launch
    /// into a cache miss, and a `Never` policy on an approved-but-uncached image
    /// would fail instead of pulling. Both ordinary constructors must keep
    /// `IfMissing`.
    #[test]
    fn only_a_launch_build_is_cache_only() {
        use microsandbox::sandbox::PullPolicy;

        let local = PreparedSelection::local("/host/rootfs");
        assert_eq!(local.pull_policy(), PullPolicy::IfMissing);
        assert!(!local.is_cache_only());

        // `cache_only` is private to this module, so `unpinned` is the only
        // caller that can set it.
        assert!(
            PreparedSelection::local("/host/rootfs")
                .cache_only()
                .is_cache_only()
        );
    }

    /// The lost `pull.rs` redaction row, moved here with `render_failure`: a
    /// redacted selection keeps its closed stage diagnostics, and no rendering
    /// leaks the reference, a digest or a control byte.
    #[test]
    fn redacted_acquisition_failures_keep_actionable_stages() {
        use crate::image_acquire::ReferenceStage;

        let label = ImageLabel::for_default_upgrade();
        let sentinel = "https://private.example/secret-repository\u{1b}";
        for (stage, expected) in [
            (
                ReferenceStage::LockOpen,
                "opening the image-cache coordination lock",
            ),
            (
                ReferenceStage::LockAcquire,
                "acquiring the image-cache coordination lock",
            ),
            (
                ReferenceStage::Snapshot,
                "snapshotting cached reference metadata",
            ),
        ] {
            let error = render_failure(
                &label,
                Rendering::Selection,
                sentinel,
                AcquireError::ReferenceState {
                    stage,
                    source: anyhow!(sentinel),
                },
            );
            let text = format!("{error:#}");
            assert!(text.contains(expected), "{text}");
            assert!(!text.contains("private.example"), "{text}");
            assert!(!text.contains('\u{1b}'), "{text}");
        }
        // A closed diagnostic keeps its own text and still never names the
        // reference it was resolved from.
        let closed = render_failure(
            &label,
            Rendering::Selection,
            sentinel,
            AcquireError::RegistryMismatch,
        );
        let text = format!("{closed:#}");
        assert!(!text.contains("private.example"), "{text}");
        assert!(!text.contains('\u{1b}'), "{text}");
        assert!(text.contains("registry does not match"), "{text}");
        // A join failure keeps its publication-uncertain recovery advice.
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let join = runtime.block_on(async {
            tokio::spawn(async { panic!("private source") })
                .await
                .unwrap_err()
        });
        let error = render_failure(
            &label,
            Rendering::Selection,
            sentinel,
            AcquireError::Task(join),
        );
        let text = format!("{error:#}");
        assert!(text.contains("publication is uncertain"), "{text}");
        assert!(text.contains("check the cache and retry"), "{text}");
        assert!(!text.contains("private source"), "{text}");
        // `set-default`'s explicit rendering states the retained-default
        // guarantee and names neither its target nor a source chain.
        let explicit = render_failure(
            &label,
            Rendering::Explicit,
            sentinel,
            AcquireError::RegistryMismatch,
        );
        let text = format!("{explicit:#}");
        assert!(
            text.contains("did not change the retained default"),
            "{text}"
        );
        assert!(!text.contains("private.example"), "{text}");
        assert!(!text.contains(label.text()), "{text}");
        // A registry identity mismatch is not an importable registry miss.
        let shown = ImageLabel::for_tests("example.com/team/image:tag");
        let hinted = render_failure(
            &shown,
            Rendering::Selection,
            "example.com/team/image:tag",
            AcquireError::RegistryMismatch,
        );
        let text = format!("{hinted:#}");
        assert!(!text.contains("private.example"), "{text}");
        assert!(!text.contains("image import"), "{text}");
    }

    /// A build/import read-back renders the explicit chain and never the import
    /// hint: the command *is* the import. Differential, so dropping the arm is
    /// visible rather than silently equal.
    #[test]
    fn publication_failures_keep_the_explicit_chain_without_the_import_hint() {
        let label = ImageLabel::for_result_reference("example.com/team/app:dev");
        let pull = || AcquireError::Native {
            stage: crate::image_acquire::AcquireStage::Pull,
            source: microsandbox_image::ImageError::Registry(
                std::io::Error::other("Not authorized").into(),
            ),
        };
        let selection = format!(
            "{:#}",
            render_failure(&label, Rendering::Selection, label.text(), pull())
        );
        assert!(selection.contains("image import"), "{selection}");

        let publication = format!(
            "{:#}",
            render_failure(&label, Rendering::Publication, label.text(), pull())
        );
        assert!(
            !publication.contains("image import"),
            "an import must not be told to import: {publication}"
        );
        assert!(
            publication.contains("Not authorized"),
            "the explicit chain is kept: {publication}"
        );

        let miss = format!(
            "{:#}",
            render_failure(
                &label,
                Rendering::Publication,
                label.text(),
                AcquireError::NotCached
            )
        );
        assert!(
            miss.contains("never contacts a registry"),
            "the read-back's own miss text: {miss}"
        );
        assert!(!miss.contains("image import"), "{miss}");
    }

    #[test]
    fn verus_gate_covers_pin_kernel() {
        // Pin the source registration as well as runtime truth tables: the
        // repository Verus gate and its pass/fail controls prove verification
        // actually runs, rather than trusting a successful ordinary cargo test.
        let source = include_str!("image_pin.rs");
        let block = source.split_once("verus! {").unwrap().1;
        assert!(block.contains("fn commit_decision"));
        assert!(block.contains("fn store_bytes_within_limit"));
        assert!(block.contains("fn content_is_equivalent"));
        assert!(block.contains("fn mask_is_acceptable"));
        // ADR-0068's kernels are proved too, not only this file's.
        let active = include_str!("image_pin/active.rs");
        for kernel in [
            "fn may_retire",
            "fn claim_knowledge",
            "fn checked_next_sequence",
        ] {
            assert!(active.contains(kernel), "{kernel}");
        }
        assert!(include_str!("../Cargo.toml").contains("[package.metadata.verus]"));
    }
}
