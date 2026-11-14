//! A project's own **default boot image** and the host's **starting choice**
//! (ADR-0067).
//!
//! A project's default is a canonical reference that states its digest, recorded
//! with that project's approvals in `image-pins.json`, so establishing it and
//! its first pin are one atomic save. The host record in `default-image.json`
//! stops being every project's default: it is only the starting choice a project
//! adopts when it establishes its own, and the one an explicit `image refresh`
//! may move an established project to.
//!
//! These are decisions of the one approval authority ([`crate::image_pin`]), and
//! they share saves with its pins, so they live in its child module rather than
//! in the selector or in a command surface. The schema the transactions need
//! stays in [`super::store`]; this module owns the concepts and the flows.

use std::path::PathBuf;

use anyhow::{Result, anyhow, bail};

use super::approval;
use super::store::{self, Store};
use super::{
    BootImage, CanonicalOciReference, DefaultAction, DefaultChange, ImageLabel, ImageRef,
    ImageSource, ImmutableImageRef, ManifestDigest, PinKey, ProjectId, Rendering,
    ValidatedCandidate, acquire_or_render, immutable_reference, oci_target, revalidate_frozen,
};
use crate::boot_image::{AdoptionOffer, ConfigurationRead};
use crate::image_acquire::{AcquireMode, OciTarget};
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

/// What `image set-default` did: only the host record can change; the invoking
/// project is reported so the notice can say whether it keeps its own default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HostDefaultSet {
    pub(crate) retained_default: DefaultChange,
    pub(crate) this_project: InvokingProject,
}

/// Measured under the pin lock: `AlreadyUses` iff the content this project's
/// default boots (its approved child, else the digest it states) is the new host
/// child.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InvokingProject {
    NotEstablished,
    AlreadyUses,
    KeepsItsOwn,
}

/// Consent to move one project's established default to the host's current
/// retained default. Minted only by [`approval::adopt`], after the change was
/// rendered, from a validated candidate, so no stored string or boolean can
/// move a project's default.
pub(crate) struct DefaultAdoption {
    expected: ProjectDefault,
    proposed: ImmutableImageRef,
    candidate: ManifestDigest,
}

impl DefaultAdoption {
    pub(super) fn new(
        expected: ProjectDefault,
        proposed: ImmutableImageRef,
        candidate: &ValidatedCandidate,
    ) -> Self {
        Self {
            expected,
            proposed,
            candidate: candidate.digest.clone(),
        }
    }

    /// The consent must name one project, the host's current reference, and the
    /// candidate's digest exactly: the same binding a replacement approval has.
    pub(super) fn binds(&self, candidate: &ValidatedCandidate) -> Result<()> {
        let proposed = CanonicalOciReference::parse(self.proposed.as_str())
            .map_err(|_| anyhow!("default adoption does not bind the validated reference"))?;
        if proposed != candidate.key.reference
            || self.expected.project != candidate.key.project
            || self.candidate != candidate.digest
        {
            bail!("default adoption does not bind the validated source");
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
}

/// What a successful default-tier preparation records (ADR-0067).
///
/// The match is exhaustive on purpose: a new [`ImageSource`] must decide here,
/// not default. The one place a selection becomes a `DefaultAction`, so R3's
/// rule that a selection made while the configuration was unreadable establishes
/// nothing holds for `setup`, launch and `image refresh` by construction.
pub(super) fn establishment(boot: &BootImage) -> Result<DefaultAction> {
    let host = match boot.source() {
        ImageSource::RetainedDefault(_) => HostRetention::Keep,
        ImageSource::InitialRecommendation => HostRetention::InitializeIfAbsent,
        ImageSource::ProjectDefault(_)
        | ImageSource::LaunchBuild(_)
        | ImageSource::CommandLine
        | ImageSource::Environment
        | ImageSource::UserConfig(_)
        | ImageSource::ProjectConfig(_) => return Ok(DefaultAction::None),
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
pub(super) async fn adopt_host_default(
    established: &BootImage,
    offer: &AdoptionOffer,
    project: &ProjectDir,
) -> Result<ProjectDefaultChange> {
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
    let adoption = approval::adopt(expected, proposed, &candidate, &old)?;
    drop(prepared);
    revalidate_frozen(&candidate, &label, Rendering::Selection).await?;
    let completion = Store::host()?.adopt(&candidate, &adoption)?;
    super::completion::finish_preparation(completion.report);
    Ok(completion.value.project_default)
}

/// `image set-default`: measure the typed target and make its host child the
/// host's starting choice. No pin and no project default is written (ADR-0067).
pub(crate) async fn set_default(
    reference: &ImageRef,
    project: &ProjectDir,
) -> Result<HostDefaultSet> {
    let target = oci_target(reference.as_str())?;
    let label = ImageLabel::for_default_upgrade();
    let store = Store::host()?;
    // A damaged or legacy record is refused before any registry request.
    store.default_health()?;
    let prepared = acquire_or_render(
        &target,
        &label,
        Rendering::Explicit,
        AcquireMode::ResolveCurrent,
    )
    .await?;
    let retained = immutable_reference(target.canonical(), prepared.image().acquired_digest())?;
    store::candidate_ready()?;
    // Held through the write: the host record never names content this command
    // did not validate in the cache it just used. Nothing waits on a human, so
    // no frozen-candidate revalidation is needed.
    let outcome = store.set_host_default(&retained, &ProjectId::of(project))?;
    drop(prepared);
    Ok(outcome)
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
