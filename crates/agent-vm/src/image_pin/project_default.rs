//! A project's own **default boot image** and the host's **starting choice**
//! (ADR-0067).
//!
//! A project's default is a canonical reference that states its digest, recorded
//! with that project's approvals in `image-pins.json`, so establishing it and
//! its first pin are one atomic save. The host record in `default-image.json`
//! stops being every project's default: it is only the starting choice a project
//! adopts when it establishes its own, and the one an explicit `image pull`
//! may move an established project to.
//!
//! These are decisions of the one approval authority ([`crate::image_pin`]), and
//! they share saves with its pins, so they live in its child module rather than
//! in the selector or in a command surface. The schema the transactions need
//! stays in [`super::store`]; this module owns the concepts and the flows.

use std::path::PathBuf;

use anyhow::{Result, anyhow, bail};

use super::approval;
use super::refresh::{ApprovalDelta, RefreshSuccess};
use super::store::{self, Store};
use super::{
    ApprovedPin, BootImage, CanonicalOciReference, DefaultAction, ImageLabel, ImageRef,
    ImageSource, ImmutableImageRef, ManifestDigest, PinKey, ProjectId, Rendering,
    ValidatedCandidate, acquire_or_render, oci_target, revalidate_frozen,
};
use crate::boot_image::{AdoptionOffer, ConfigurationRead};
use crate::image_acquire::{AcquireMode, OciTarget, PreparedNativeImage};
use crate::project::ProjectDir;

/// Whether establishing a project default may also seed the host's starting
/// choice. Only a selection that *was* the initial recommendation may: one read
/// from the host record or the project's own default never writes the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HostRetention {
    Keep,
    InitializeIfAbsent,
}

/// One project's established default: a canonical reference that states its
/// digest. Constructed only from a validated default-tier selection or a decoded
/// store record, so a tag can never become a project default. `digest` is the
/// digest `reference` states, kept beside it so no reader has to re-prove the
/// invariant.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ProjectDefault {
    project: ProjectId,
    reference: CanonicalOciReference,
    digest: ManifestDigest,
}

impl ProjectDefault {
    pub(super) fn new(project: &ProjectId, reference: &ImmutableImageRef) -> Result<Self> {
        let reference = CanonicalOciReference::parse(reference.as_str())
            .map_err(|_| anyhow!("the selected default boot image is not a canonical reference"))?;
        Self::from_canonical(project.clone(), reference)
    }

    /// The store's decoder path: the fields are already canonical, and the
    /// digest is what the reference states.
    pub(super) fn from_canonical(
        project: ProjectId,
        reference: CanonicalOciReference,
    ) -> Result<Self> {
        let digest = reference
            .digest()
            .cloned()
            .ok_or_else(|| anyhow!("the selected default boot image does not state its digest"))?;
        Ok(Self {
            project,
            reference,
            digest,
        })
    }

    pub(super) fn project(&self) -> &ProjectId {
        &self.project
    }

    pub(super) fn reference(&self) -> &CanonicalOciReference {
        &self.reference
    }

    pub(super) fn immutable(&self) -> Result<ImmutableImageRef> {
        ImmutableImageRef::parse(&self.reference.whole()).map_err(|reason| {
            anyhow!("the stored project default boot image is unusable: {reason}")
        })
    }

    /// The digest the reference states: the "old" digest an adoption render
    /// shows when the store holds no pin for it (a hand-edited store).
    pub(super) fn stated_digest(&self) -> ManifestDigest {
        self.digest.clone()
    }
}

/// What one transaction did to the operated project's default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProjectDefaultChange {
    Unchanged,
    Established,
    Adopted,
}

/// The default slot as a launch in one project reads it.
pub(crate) enum DefaultSlot {
    /// The project's own default, recorded in the approval store at `file`.
    Project {
        reference: ImmutableImageRef,
        file: PathBuf,
    },
    /// No project default: the host record (journal-aware), or `None` when the
    /// initial recommendation applies.
    Host(Option<ImmutableImageRef>),
}

/// Both default records from one shared-lock read, for `doctor`.
///
/// The pin store is read once, but each record's result is independent: a host
/// record that could not be read or decoded must not hide a project default
/// that did (R10). A store-level failure still reaches the caller as `Err`.
pub(crate) struct ObservedDefaults {
    pub(crate) project: Result<Option<ImmutableImageRef>>,
    pub(crate) host: Result<Option<ImmutableImageRef>>,
    pub(crate) file: PathBuf,
}

/// Consent to move one project's established default to the host's current
/// retained default. Minted only by [`approval::adopt`], after the change was
/// rendered, from a validated candidate, so no stored string or boolean can
/// move a project's default.
pub(crate) struct DefaultAdoption {
    expected: ProjectDefault,
    proposed: ImmutableImageRef,
    candidate: ManifestDigest,
    /// H as the frozen worklist observed it: `Some(tuple)` or `None` for a
    /// genuinely absent key. Carried through the render and the frozen
    /// revalidation into the one save so an observed-and-retired H cannot be
    /// reinserted as a fresh pin (ADR-0068 D10).
    observed_host: Option<ApprovedPin>,
}

impl DefaultAdoption {
    pub(super) fn new(
        expected: ProjectDefault,
        proposed: ImmutableImageRef,
        candidate: &ValidatedCandidate,
        observed_host: Option<ApprovedPin>,
    ) -> Self {
        Self {
            expected,
            proposed,
            candidate: candidate.digest.clone(),
            observed_host,
        }
    }

    /// The consent must name one project, the host's current reference, and the
    /// candidate's digest exactly: the same binding a replacement approval has.
    /// The observation must name the same key it was taken for, or the store
    /// would compare an unrelated record.
    pub(super) fn binds(&self, candidate: &ValidatedCandidate) -> Result<()> {
        let proposed = CanonicalOciReference::parse(self.proposed.as_str())
            .map_err(|_| anyhow!("default adoption does not bind the validated reference"))?;
        if proposed != candidate.key.reference
            || self.expected.project != candidate.key.project
            || self.candidate != candidate.digest
        {
            bail!("default adoption does not bind the validated source");
        }
        if self
            .observed_host
            .as_ref()
            .is_some_and(|observed| observed.key != candidate.key)
        {
            bail!("default adoption predecessor does not bind the validated source");
        }
        Ok(())
    }

    /// Read-only accessors for [`store::Store::adopt`]; the fields stay private
    /// so only [`Self::new`] can mint one.
    pub(super) fn expected(&self) -> &ProjectDefault {
        &self.expected
    }

    pub(super) fn proposed(&self) -> &ImmutableImageRef {
        &self.proposed
    }

    /// The observed H tuple this adoption was frozen against, if any.
    pub(super) fn observed_host(&self) -> Option<&ApprovedPin> {
        self.observed_host.as_ref()
    }
}

/// What a successful default-tier preparation records (ADR-0067).
///
/// The match is exhaustive on purpose: a new [`ImageSource`] must decide here,
/// not default. The one place a selection becomes a `DefaultAction`, so R3's
/// rule that a selection made while the configuration was unreadable establishes
/// nothing holds for `setup`, launch and `image pull` by construction.
pub(crate) fn establishment(boot: &BootImage) -> Result<DefaultAction> {
    let host = match boot.source() {
        ImageSource::RetainedDefault(_) => HostRetention::Keep,
        ImageSource::InitialRecommendation => HostRetention::InitializeIfAbsent,
        ImageSource::ProjectDefault(_)
        | ImageSource::LaunchBuild(_)
        | ImageSource::CommandLine
        | ImageSource::Environment
        | ImageSource::UserConfig(_)
        | ImageSource::ProjectConfig(_)
        | ImageSource::AllowedSource { .. }
        | ImageSource::SourcedConfig { .. } => return Ok(DefaultAction::None),
    };
    let reference = immutable(boot)?;
    // R3's binding rule: a selection made while the configuration was
    // unreadable is provisional and establishes nothing; R4 still applies.
    Ok(match (boot.configuration(), host) {
        (ConfigurationRead::Read, host) => DefaultAction::Establish { reference, host },
        (ConfigurationRead::Unreadable, HostRetention::InitializeIfAbsent) => {
            DefaultAction::SeedHostOnly { reference }
        }
        (ConfigurationRead::Unreadable, HostRetention::Keep) => DefaultAction::None,
    })
}

/// R7: move an established project's default to the host record. Invoking
/// refresh is the consent; the change is rendered when its content differs.
///
/// `observed_host` is H as the frozen worklist saw it, **not** a fresh read: a
/// peer that retired H between freeze and this save must make the transaction
/// stale rather than resurrect it.
pub(super) async fn adopt_host_default(
    established: &BootImage,
    offer: &AdoptionOffer,
    observed_host: Option<ApprovedPin>,
    project: &ProjectDir,
) -> Result<RefreshSuccess> {
    let id = ProjectId::of(project);
    let expected = ProjectDefault::new(&id, &immutable(established)?)?;
    let host = offer.image();
    let proposed = immutable(host)?;
    let target = oci_target(proposed.as_str())?;
    let label = host.label();
    // The established default's own approval, if any. Absent only for a
    // hand-edited store, where the digest the record states is the "old" one.
    // The stored reference is canonical, so an unusable one is damage, not the
    // user-input refusal `oci_target` renders.
    let established_target = OciTarget::parse(established.reference().as_str())
        .map_err(|_| anyhow!("the stored project default boot image is unusable"))?;
    let current = super::lookup(&PinKey::new(&id, &established_target)?)?;
    let prepared = acquire_or_render(
        &target,
        &label,
        Rendering::Selection,
        AcquireMode::ResolveCurrent,
    )
    .await?;
    let candidate = ValidatedCandidate::from_image(prepared.image(), &id)?;
    store::candidate_ready()?;
    let old = current.map_or_else(|| expected.stated_digest(), |pin| pin.digest);
    let adoption = approval::adopt(expected, proposed, &candidate, &old, observed_host)?;
    drop(prepared);
    revalidate_frozen(&candidate, &label, Rendering::Selection).await?;
    let completion = Store::host()?.adopt(&candidate, &adoption)?;
    super::completion::finish_preparation(completion.report);
    let committed = &completion.value;
    Ok(RefreshSuccess {
        approval: ApprovalDelta::of(committed.previous.as_ref(), &committed.pin),
        project_default: committed.project_default,
        adopted: Some((old, candidate.digest.clone())),
    })
}

/// The fixed reason `image set-default` gives when this project already approves
/// the target reference at different content (ADR-0078 D3).
///
/// Both variants are value-free: the reference the user typed, the approved digest
/// and the acquired digest are all user or registry data. They differ only in
/// whether `agent-vm image pull --image REF` could accept this reference — it
/// targets only references already in use here — so the advice never sends the user
/// to a command that would refuse them.
pub(crate) const PIN_CONFLICT_REASON: &str = "this project already approves this image reference at a different manifest digest, and \
     image set-default writes no approval, so a later launch would boot that approved \
     content instead of the content just acquired; nothing was written. Re-run \
     image set-default with the immutable digest reference of the content you intend \
     (repo@sha256:...) so the selection does not depend on an approval.";

/// [`PIN_CONFLICT_REASON`] for a reference this project holds a role for, which
/// an explicit refresh may therefore re-approve in place.
///
/// The advice is "re-resolve and approve the **held reference**", not "approve the
/// acquired content": `image pull` re-resolves the reference and replaces that
/// reference's approval with whatever it just acquired, which is the action that
/// makes the next launch boot the new content. Nothing can approve bytes already
/// acquired, and the digest alternative names the content rather than the tag.
const PIN_CONFLICT_PULL_REASON: &str = "this project already approves this image reference at a different manifest digest, and \
     image set-default writes no approval, so a later launch would boot that approved \
     content instead of the content just acquired; nothing was written. Re-resolve and \
     approve the held reference with `agent-vm image pull --image REF` (it replaces \
     that reference's approval with what it acquires now), or re-run image set-default \
     with the immutable digest reference (repo@sha256:...) of the content you intend.";

/// `image set-default`'s read-only pre-network check of the approval authority.
///
/// Reads this project's approval store with the rule pin lookups already use: the
/// host record in `default-image.json` is ignored **unless a pending image-pin
/// journal requires it**, and an unreadable or inconsistently paired journal fails
/// closed here, before any registry request (ADR-0078 D5). Recovery is not this
/// command's business and never happens in a read-only check. Writes nothing.
pub(crate) fn preflight_project_default(reference: &ImageRef, project: &ProjectDir) -> Result<()> {
    let target = oci_target(reference.as_str())?;
    let key = PinKey::new(&ProjectId::of(project), &target)?;
    let _ = super::lookup(&key)?;
    Ok(())
}

/// `image set-default`: acquire and validate the typed target and hand the caller
/// the content it measured, **without writing any pin store**.
///
/// The reference this command saves is the project config's root `image`; an
/// approval is never written, replaced or forgotten here (ADR-0078 D3, D7). The
/// returned [`PreparedNativeImage`] holds the cache publication barrier so the
/// caller's commit cannot interleave with a peer publishing other content under
/// the same cache, and it is the content this call validated.
///
/// After acquisition — including when the caller's edit would be a no-op — the
/// project's existing approval for `(project, canonical(REF), host platform)` is
/// compared with the acquired manifest. A mismatch is refused: a later launch would
/// consume the approval, not the content just acquired, and promising the acquired
/// digest at the next launch would be false. The cache may now hold the acquired
/// content; `config.toml` and both pin stores are untouched.
///
/// No cache/OCI lock is taken from inside `config.lock` and the pin lock is not
/// held across it: this function returns before the caller's write begins.
pub(crate) async fn acquire_for_project_default(
    reference: &ImageRef,
    project: &ProjectDir,
) -> Result<PreparedNativeImage> {
    let target = oci_target(reference.as_str())?;
    let key = PinKey::new(&ProjectId::of(project), &target)?;
    let label = ImageLabel::for_default_upgrade();
    let prepared = acquire_or_render(
        &target,
        &label,
        Rendering::Explicit,
        AcquireMode::ResolveCurrent,
    )
    .await?;
    store::candidate_ready()?;
    if let Some(existing) = super::lookup(&key)?
        && existing.digest != *prepared.image().acquired_digest()
    {
        // Advice only: an unreadable scope says nothing about eligibility, so the
        // refusal then names the explicit digest instead of a refusing command.
        let pull_eligible = super::observe_refresh_scope(project)
            .map(|scope| scope.has_held_target(&target))
            .unwrap_or(false);
        return Err(anyhow!(if pull_eligible {
            PIN_CONFLICT_PULL_REASON
        } else {
            PIN_CONFLICT_REASON
        }));
    }
    Ok(prepared)
}

/// The default slot as one project's selection reads it.
pub(crate) fn load_default_slot(project: &ProjectDir) -> Result<DefaultSlot> {
    Store::host()?.default_slot(&ProjectId::of(project))
}

/// Both default records from one shared-lock read.
pub(crate) fn observe_defaults(project: Option<&ProjectDir>) -> Result<ObservedDefaults> {
    Store::host()?.observe_defaults(project.map(ProjectId::of).as_ref())
}

/// The default tier's reference as the immutable type every record needs, with
/// the one error both callers report.
fn immutable(boot: &BootImage) -> Result<ImmutableImageRef> {
    ImmutableImageRef::parse(boot.reference().as_str())
        .map_err(|reason| anyhow!("the selected default boot image cannot be retained: {reason}"))
}
