//! Host-wide OCI approval authority. Cache evidence is never approval.
//!
//! One selection key — the canonical OCI reference plus the host Linux platform
//! — maps to the approved native manifest content. Everything a launch or a
//! setup boots from a registry goes through [`prepare_selected`], and every
//! deliberate re-resolution goes through [`update`]: there is one ordinary
//! preparation and one explicit approval path, so no consumer can quietly
//! acquire content the others would refuse.
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
//! instead, and the replacement prompt asks a human with no lock held. See
//! [`store`] for the schema and the three-write default transaction.
//!
//! # What a local path is here
//!
//! A local rootfs directory or disk image is a supported launch target and
//! nothing about it is approvable: [`prepare_selected`] hands the original text
//! back untouched and never touches the store, the cache barrier or a receipt.

use std::fmt;

use anyhow::{Result, anyhow};
use microsandbox_image::Platform;
use serde::{Deserialize, Serialize};
use vstd::prelude::*;

use crate::boot_image::{BootImage, ImageLabel, ImageRef, ImmutableImageRef};
use crate::config;
use crate::image_acquire::{
    self, AcquireError, AcquireMode, ContentIdentity, OciTarget, OciTargetError,
    PreparedNativeImage, ValidatedImage,
};
pub(crate) use crate::image_acquire::{CanonicalOciReference, ValidatedDigest as ManifestDigest};

mod approval;
mod store;

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

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PinKey {
    reference: CanonicalOciReference,
    platform: HostLinuxPlatform,
}

impl PinKey {
    pub(crate) fn new(target: &OciTarget) -> Result<Self> {
        if !source_within_limit(target.canonical().whole().len()) {
            return Err(anyhow!("image pin source exceeds the size limit"));
        }
        Ok(Self {
            reference: target.canonical().clone(),
            platform: HostLinuxPlatform::host(),
        })
    }

    /// True for a source that states its own immutable digest, which can never
    /// legitimately resolve to different content.
    fn is_immutable(&self) -> bool {
        self.reference.digest().is_some()
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
    pub(crate) fn from_image(image: &ValidatedImage) -> Result<Self> {
        let target = OciTarget::parse(&image.source().whole())
            .map_err(|_| anyhow!("validated image source is unusable"))?;
        Ok(Self {
            key: PinKey::new(&target)?,
            digest: image.acquired_digest().clone(),
            identity: image.content_identity(),
        })
    }
}

/// Candidate-scoped consent; only [`approval::approve`] mints a replacement.
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

    /// A candidate a human or `--yes` authorized exactly as displayed.
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
    /// Retain the default tier's own immutable selection on a *first* pin.
    Adopt(ImmutableImageRef),
    /// Store the approved host child as the retained default.
    Set,
}

/// How a changed approval may be authorized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ApprovalMode {
    /// Ask on a real terminal; refuse otherwise.
    Ask,
    /// The operation's own `--yes` pre-authorizes exactly the resolved candidate.
    Yes,
}

impl ApprovalMode {
    /// The one reading of a command's `--yes`: it pre-authorizes exactly the
    /// candidate that command resolves, and nothing else.
    pub(crate) fn of_flag(yes: bool) -> Self {
        if yes { Self::Yes } else { Self::Ask }
    }
}

/// The deliberate operations that are allowed to re-resolve a source.
pub(crate) enum ExplicitOperation<'a> {
    Refresh(&'a BootImage),
    SetDefault(&'a ImageRef),
}

/// What a completed [`update`] changed, reported per record: a matching approval
/// with a different retained fallback is still a change the user must be told
/// about, so the two decisions are never collapsed into one word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UpdateOutcome {
    pub(crate) approval: ApprovalChange,
    pub(crate) retained_default: DefaultChange,
}

impl UpdateOutcome {
    /// True when the command changed either record.
    pub(crate) fn changed_anything(&self) -> bool {
        self.approval != ApprovalChange::Unchanged
            || self.retained_default != DefaultChange::Unchanged
    }
}

/// What one transaction did to the host approval for the operated key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ApprovalChange {
    /// The first approval for this key.
    FirstPin,
    /// Already approved at this content (possibly under another digest
    /// algorithm); the stored identity and revision are unchanged.
    Unchanged,
    /// A different approved candidate replaced the previous one.
    Replaced,
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
/// Constructed only by [`prepare_selected`]. Dropping it releases the barrier,
/// which callers do immediately after the SDK create resolves and before guest
/// hooks, commands, or in-guest tool probes.
pub(crate) struct PreparedSelection {
    sdk_reference: String,
    image_env: Option<Vec<String>>,
    /// Held only so the shared publication barrier outlives the SDK's create;
    /// dropping this value is what releases it.
    _native: Option<PreparedNativeImage>,
}

impl PreparedSelection {
    /// A local rootfs/disk target: the original text, no approval, no barrier.
    fn local(reference: &str) -> Self {
        Self {
            sdk_reference: reference.to_owned(),
            image_env: None,
            _native: None,
        }
    }

    fn approved(approved: &ImmutableImageRef, prepared: PreparedNativeImage) -> Self {
        Self {
            sdk_reference: approved.as_str().to_owned(),
            image_env: Some(prepared.image().image_env().to_vec()),
            _native: Some(prepared),
        }
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
}

/// The one ordinary preparation for a launch and a setup.
///
/// A local path short-circuits with its original text. An existing approval is
/// consumed as `repo@approved child` and never re-resolved from its tag. An
/// absent approval acquires cache-first under the strict association policy,
/// and the first pin is committed — insert-if-absent — before anything is
/// returned. A concurrent different candidate is never overwritten: this
/// preparation revalidates the winner's frozen digest and uses it, or fails
/// before create.
pub(crate) async fn prepare_selected(boot: &BootImage) -> Result<PreparedSelection> {
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
    let key = PinKey::new(&target)?;
    let current = lookup(&key)?;
    let Some(current) = current else {
        return prepare_first_pin(boot, &target, &key, &label).await;
    };
    let prepared = approved_preparation(&current, &label, Rendering::Selection).await?;
    retain_default(boot, &current)?;
    let approved = current.immutable_reference()?;
    Ok(PreparedSelection::approved(&approved, prepared))
}

/// The absent-approval branch: acquire the source itself, then establish the
/// first pin before create.
async fn prepare_first_pin(
    boot: &BootImage,
    target: &OciTarget,
    key: &PinKey,
    label: &ImageLabel,
) -> Result<PreparedSelection> {
    let prepared = acquire_or_render(
        target,
        label,
        Rendering::Selection,
        AcquireMode::CachedOrAcquire,
    )
    .await?;
    let candidate = ValidatedCandidate::from_image(prepared.image())?;
    store::candidate_ready()?;
    let action = adoption(boot)?;
    match commit(&candidate, &Approval::initial(&candidate), action) {
        Ok(committed) => {
            let approved = committed.pin.immutable_reference()?;
            Ok(PreparedSelection::approved(&approved, prepared))
        }
        Err(error) => {
            // A peer may have committed a different candidate while this
            // preparation was acquiring. That record stands; this launch either
            // consumes the winner's frozen digest or fails before create.
            let winner = lookup(key)?;
            match winner {
                Some(pin) if pin.digest != candidate.digest => {
                    drop(prepared);
                    let prepared = approved_preparation(&pin, label, Rendering::Selection).await?;
                    let approved = pin.immutable_reference()?;
                    Ok(PreparedSelection::approved(&approved, prepared))
                }
                _ => Err(error),
            }
        }
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

/// The default-tier's own immutable selection, when this boot image is the
/// default tier (the retained record or the initial recommendation).
/// Acquisition success, not create success, retains it.
fn adoption(boot: &BootImage) -> Result<DefaultAction> {
    if !boot.is_default() {
        return Ok(DefaultAction::None);
    }
    let reference = ImmutableImageRef::parse(boot.reference().as_str()).map_err(|reason| {
        anyhow!("the selected default boot image cannot be retained: {reason}")
    })?;
    Ok(DefaultAction::Adopt(reference))
}

/// The write-once retention that belongs with **every** successful default-tier
/// preparation, not only a first pin.
///
/// A default-tier selection whose key is already approved (an explicit
/// `image refresh` pins without adopting) still initializes an absent fallback,
/// while an existing fallback is left byte-for-byte alone. Adoption failure is a
/// launch failure: the record is part of what a default-tier launch promises.
fn retain_default(boot: &BootImage, pin: &ApprovedPin) -> Result<()> {
    if let DefaultAction::Adopt(reference) = adoption(boot)? {
        store::Store::host()?.adopt_default_if_absent(&pin.key, &reference)?;
    }
    Ok(())
}

/// One explicit re-resolution plus the candidate-scoped approval it needs.
///
/// The source is resolved exactly once. The frozen candidate is revalidated
/// under a fresh shared barrier after any human wait, and the host transaction
/// then compares and swaps against the revision and digest that were displayed.
/// A decline, a refusal without a terminal, an interruption or a failed
/// acquisition leaves the previous approval and default logically unchanged.
pub(crate) async fn update(
    operation: ExplicitOperation<'_>,
    mode: ApprovalMode,
) -> Result<UpdateOutcome> {
    let plan = Plan::resolve(operation)?;
    let key = PinKey::new(&plan.target)?;
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
    let candidate = ValidatedCandidate::from_image(prepared.image())?;
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
                approval::approve(
                    &candidate,
                    pin.clone(),
                    &approval::ApprovalRequest {
                        source: &plan.source,
                        platform: &key.platform,
                        old: &pin.digest,
                        new: &candidate.digest,
                    },
                    mode,
                )?
            }
        }
    };
    // Revalidate only the frozen candidate: a mutable source that moved while
    // the prompt was open must not be resolved a second time, and the bytes
    // this approval names are the bytes the transaction commits.
    drop(prepared);
    revalidate_frozen(&candidate, &plan.label, plan.rendering).await?;
    let action = plan.default_action;
    let committed = commit(&candidate, &approval, action)?;
    Ok(UpdateOutcome {
        approval: committed.approval,
        retained_default: committed.retained_default,
    })
}

/// Everything one explicit operation decided before any I/O, resolved once.
struct Plan {
    target: OciTarget,
    label: ImageLabel,
    /// The prompt's source rendering: the escaped selection, or the fixed
    /// default-tier label rather than a record-sourced reference.
    source: String,
    rendering: Rendering,
    default_action: DefaultAction,
}

impl Plan {
    fn resolve(operation: ExplicitOperation<'_>) -> Result<Self> {
        match operation {
            ExplicitOperation::Refresh(boot) => {
                let label = boot.label();
                let source = if label.is_redacted() {
                    label.text().to_owned()
                } else {
                    config::escape_str(boot.reference().as_str())
                };
                Ok(Self {
                    target: oci_target(boot.reference().as_str())?,
                    default_action: adoption(boot)?,
                    rendering: Rendering::Selection,
                    label,
                    source,
                })
            }
            ExplicitOperation::SetDefault(reference) => Ok(Self {
                target: oci_target(reference.as_str())?,
                label: ImageLabel::for_default_upgrade(),
                source: config::escape_str(reference.as_str()),
                // `set-default` never discloses its typed target on failure and
                // always states the retained-default guarantee.
                rendering: Rendering::Explicit,
                // The explicit target replaces the fallback even on a first pin;
                // its own approval is still established separately.
                default_action: DefaultAction::Set,
            }),
        }
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
) -> Result<store::Committed> {
    store::Store::host()?.commit(candidate, approval, action)
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
    PinKey,
    ApprovedPin,
    ValidatedCandidate,
    Approval,
    DefaultAction,
    ExplicitOperation<'_>,
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
/// One record's measured field facts, named so a swap cannot silently accept a
/// pin file it should refuse.
struct PinFieldFacts {
    source_bounded: bool,
    canonical: bool,
    platform: bool,
    revision: bool,
    digest: bool,
}

fn pin_fields_are_acceptable(facts: PinFieldFacts) -> (ok: bool)
    ensures ok == (facts.source_bounded && facts.canonical && facts.platform && facts.revision && facts.digest),
{ facts.source_bounded && facts.canonical && facts.platform && facts.revision && facts.digest }
/// The top-level schema facts. Field validity is each record's own decision, so
/// it is not a second, always-true argument here.
fn schema_is_acceptable(version: u32, keys_unique: bool) -> (ok: bool)
    ensures ok == (version == 1 && keys_unique),
{ version == 1 && keys_unique }
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
        for bits in 0u8..32 {
            assert_eq!(
                pin_fields_are_acceptable(PinFieldFacts {
                    source_bounded: bits & 1 != 0,
                    canonical: bits & 2 != 0,
                    platform: bits & 4 != 0,
                    revision: bits & 8 != 0,
                    digest: bits & 16 != 0,
                }),
                bits == 31
            );
        }
        for version in [0, 1, 2, u32::MAX] {
            for unique in [false, true] {
                assert_eq!(
                    schema_is_acceptable(version, unique),
                    version == 1 && unique
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
        let key = PinKey::new(&target).unwrap();
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

    #[test]
    fn prepared_local_selection_passes_the_original_text_through() {
        let selection = PreparedSelection::local("/host/rootfs");
        assert_eq!(selection.sdk_reference(), "/host/rootfs");
        assert!(selection.image_env().is_none());
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

    #[test]
    fn approval_modes_come_from_one_yes_reading() {
        assert_eq!(ApprovalMode::of_flag(true), ApprovalMode::Yes);
        assert_eq!(ApprovalMode::of_flag(false), ApprovalMode::Ask);
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
        assert!(include_str!("image_pin/approval.rs").contains("fn prompt_is_permitted"));
        assert!(include_str!("../Cargo.toml").contains("[package.metadata.verus]"));
    }
}
