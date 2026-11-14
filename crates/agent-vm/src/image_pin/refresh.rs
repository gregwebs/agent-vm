//! Which in-use OCI references one `image refresh` invocation refreshes, and
//! how each one is approved (ADR-0068 D10).
//!
//! # Why a frozen worklist, not a loop over "the selection"
//!
//! `image refresh` had one selected image before S4. Now it has the invocation's
//! in-use set for **this** project on **this** host platform: the ambient
//! next-launch operation (the image a launch here would boot) plus every record
//! holding a Boot/Output role, deduplicated by canonical reference. The set is
//! frozen from one read-only scope snapshot before any registry work, so a
//! concurrent success cannot silently expand or shrink what this invocation
//! promised to do.
//!
//! # What is deliberately not in the set
//!
//! A retained but unheld approval is not a target: uncertainty may protect it
//! from retirement, but "we could not prove it was never used" is not "it is in
//! use". Cache aliases are cache, not authority. Foreign projects and foreign
//! platforms have their own records and are never touched.
//!
//! # One adoption substitution, not a second operation
//!
//! When the ambient operation is this project's own default and the host retains
//! a different default H, the ambient operation *acquires H instead* (ADR-0067
//! D7). An unheld old default D is superseded: it is not re-resolved, so a
//! refresh cannot fail on content nothing will boot. A still-held D is an
//! ordinary member of the union and is refreshed independently after adoption.
//!
//! # Per-operation authority
//!
//! Each target resolves its own source once, renders its own consent, revalidates
//! its own frozen child and commits through the existing compare-and-swap with
//! `RoleClaim::Keep`. No candidate, approval or revision is shared between
//! targets, and a failure preserves only the failing operation's transaction.

use anyhow::{Result, anyhow, bail};
use vstd::prelude::*;

use super::active::{Role, RoleClaim, RoleMask};
use super::project_default::{self, ProjectDefaultChange};
use super::store::{self, RefreshScopeSnapshot};
use super::{
    Approval, ApprovedPin, CanonicalOciReference, DefaultAction, HostLinuxPlatform, ImageLabel,
    ManifestDigest, PinKey, ProjectId, Rendering, ValidatedCandidate, acquire_or_render, approval,
    commit, completion, immutable_integrity_failure, oci_target, revalidate_frozen,
    same_guest_content,
};
use crate::boot_image::{AdoptionOffer, BootImage, HolderRoles};
use crate::config;
use crate::image_acquire::{AcquireMode, OciTarget};
use crate::project::ProjectDir;

/// The fixed refusal for a `--image` value that is not currently in use.
///
/// It names the command shape and a placeholder, never the requested value: the
/// rejected text is user input. The last sentence belongs to a *pre-worklist*
/// refusal only — no operation ran, so nothing was acquired or approved.
pub(crate) const NOT_A_MEMBER_REASON: &str = "`agent-vm image refresh --image REF` targets only references currently in use by \
     this project on the host platform; the requested reference is not in that set. To acquire and \
     approve a new boot reference, run `agent-vm setup --image REF --no-verify`; `image build` and \
     `image import` approve their own output references. Nothing was acquired or approved.";

/// The ambient next-launch operation, as far as this invocation needs it.
pub(crate) enum AmbientRefresh {
    /// A filtered target is already proven held, so the ambient selection is
    /// irrelevant and the default slot is never read.
    NotNeeded,
    /// The image a launch here would boot (env > user > project > default).
    Selected(BootImage),
    /// A filtered target that could not be proven must not invent a selection;
    /// an unfiltered invocation refuses the command with this error instead.
    Unavailable(anyhow::Error),
}

/// Everything one invocation decided before the worklist exists.
pub(crate) struct RefreshRequest {
    pub(crate) ambient: AmbientRefresh,
    /// `--image REF`: a filter over the ambient-reference/held-reference union,
    /// never a boot-selection override and never an adoption.
    pub(crate) filter: Option<OciTarget>,
    /// The host's retained default, offered only to an unfiltered invocation
    /// whose ambient operation is this project's own default. Observation errors
    /// have already refused the command.
    pub(crate) offer: Option<AdoptionOffer>,
}

/// The frozen worklist: planned operations, in execution order.
pub(crate) struct RefreshPlan {
    targets: Vec<RefreshTarget>,
}

/// One planned operation with the evidence it was planned against.
pub(crate) struct RefreshTarget {
    /// The approval observed in the frozen snapshot, if any. Eligibility and
    /// predecessor evidence, never preauthorization of bytes.
    predecessor: Option<ApprovedPin>,
    operation: RefreshOperation,
    label: ImageLabel,
    platform: String,
}

enum RefreshOperation {
    /// Re-resolve one reference and approve what it resolves. Only the ambient
    /// operation of a bare refresh may carry a default action.
    Content {
        target: OciTarget,
        default_action: DefaultAction,
    },
    /// The ambient operation as ADR-0067 D7's substitution: acquire H and move
    /// this project's bookmark to it in the same save.
    Adopt {
        established: BootImage,
        offer: AdoptionOffer,
    },
}

/// What one committed operation did to its approval, measured from the
/// transaction's own under-lock predecessor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ApprovalDelta {
    /// A first pin.
    Approved(ManifestDigest),
    /// The committed content is the content that was already approved: a no-op,
    /// a metadata-only save, or a peer that committed the same candidate.
    Unchanged(ManifestDigest),
    Changed {
        old: ManifestDigest,
        new: ManifestDigest,
    },
}

impl ApprovalDelta {
    pub(super) fn of(previous: Option<&ApprovedPin>, committed: &ApprovedPin) -> Self {
        match previous {
            None => Self::Approved(committed.digest.clone()),
            Some(previous) if previous.digest == committed.digest => {
                Self::Unchanged(committed.digest.clone())
            }
            Some(previous) => Self::Changed {
                old: previous.digest.clone(),
                new: committed.digest.clone(),
            },
        }
    }
}

/// One operation's factual outcome. Constructed only from a typed committed
/// value, never from what the worker intended.
pub(crate) struct RefreshSuccess {
    pub(crate) approval: ApprovalDelta,
    pub(crate) project_default: ProjectDefaultChange,
    /// For an adoption: the old project child and the newly acquired one, as the
    /// report's `default=adopted OLD -> NEW` suffix states them.
    pub(crate) adopted: Option<(ManifestDigest, ManifestDigest)>,
}

impl RefreshPlan {
    /// Consume the worklist. The caller iterates serially, holding only the
    /// report metadata it clones from each target.
    pub(crate) fn into_targets(self) -> Vec<RefreshTarget> {
        self.targets
    }
}

impl RefreshTarget {
    pub(crate) fn label(&self) -> &ImageLabel {
        &self.label
    }

    /// The measured platform the approval is keyed by, rendered as
    /// `linux/<architecture>[/<variant>]`.
    pub(crate) fn platform_label(&self) -> &str {
        &self.platform
    }
}

/// Freeze a worklist from one strict snapshot and one ambient decision.
///
/// Refuses (rather than planning a placeholder target) whenever the unfiltered
/// ambient operation, its adoption offer or the project default's health could
/// not be established: a worklist is a promise, and an unavailable key is not a
/// target.
pub(crate) fn plan_refresh(
    request: RefreshRequest,
    project: &ProjectDir,
    snapshot: RefreshScopeSnapshot,
) -> Result<RefreshPlan> {
    let project_id = ProjectId::of(project);
    let platform = HostLinuxPlatform::host();
    if !snapshot.covers(&project_id, &platform) {
        bail!(
            "internal error: the refresh scope snapshot does not belong to this project and host \
             platform"
        );
    }
    match request.filter {
        Some(filter) => plan_filtered(&project_id, &platform, request.ambient, filter, snapshot),
        None => plan_unfiltered(
            project_id,
            platform,
            request.ambient,
            request.offer,
            snapshot,
        ),
    }
}

/// A filter narrows the ambient-reference/held-reference union; it never grants
/// adoption and never establishes anything.
fn plan_filtered(
    project: &ProjectId,
    platform: &HostLinuxPlatform,
    ambient: AmbientRefresh,
    filter: OciTarget,
    snapshot: RefreshScopeSnapshot,
) -> Result<RefreshPlan> {
    let ambient_reference = match &ambient {
        AmbientRefresh::Selected(boot) => Some(canonical_of(boot.reference().as_str())?),
        AmbientRefresh::NotNeeded | AmbientRefresh::Unavailable(_) => None,
    };
    let member = filter_is_member(
        &snapshot,
        project,
        platform,
        &filter,
        ambient_reference.as_ref(),
    );
    if !member {
        // A store-health error outranks membership: the authority could not be
        // read, so nothing can be said about what is in use.
        if let AmbientRefresh::Unavailable(error) = ambient {
            return Err(error);
        }
        return Err(anyhow!(NOT_A_MEMBER_REASON));
    }
    if matches!(ambient, AmbientRefresh::NotNeeded) && !snapshot.has_held_target(&filter) {
        bail!("internal error: the ambient selection was skipped without held membership");
    }
    let key = PinKey::new(project, &filter)?;
    let label = ImageLabel::for_result_reference(filter.canonical().whole().as_str());
    Ok(RefreshPlan {
        targets: vec![RefreshTarget {
            predecessor: snapshot.predecessor(&key),
            operation: RefreshOperation::Content {
                target: filter,
                default_action: DefaultAction::None,
            },
            label,
            platform: platform.render(),
        }],
    })
}

/// A bare refresh: the ambient operation first (as content, or as ADR-0067 D7's
/// adoption substitution), then the remaining held references in canonical byte
/// order.
fn plan_unfiltered(
    project: ProjectId,
    platform: HostLinuxPlatform,
    ambient: AmbientRefresh,
    offer: Option<AdoptionOffer>,
    snapshot: RefreshScopeSnapshot,
) -> Result<RefreshPlan> {
    let boot = match ambient {
        AmbientRefresh::Selected(boot) => boot,
        AmbientRefresh::Unavailable(error) => return Err(error),
        AmbientRefresh::NotNeeded => bail!(
            "internal error: a bare refresh cannot skip its ambient selection, which supplies the \
             project default"
        ),
    };
    let ambient_action = project_default::establishment(&boot)?;
    // Only the operation that may establish or adopt needs the existing default
    // record to be healthy, and it needs that decided before the worklist is
    // frozen: a damaged record is a command-level refusal, not a failed target.
    if !matches!(ambient_action, DefaultAction::None) {
        store::Store::host()?.default_health()?;
    }
    let mut used: Vec<CanonicalOciReference> = Vec::new();
    let mut targets = Vec::new();
    let adopting = match &offer {
        Some(offer) => !same_reference(
            offer.image().reference().as_str(),
            boot.reference().as_str(),
        )?,
        None => false,
    };
    // The ambient operation's label, whichever shape it takes: an adoption is
    // still the default-tier operation and stays redacted.
    let label = boot.label();
    if adopting {
        let offer = offer.expect("checked just above");
        let host_target = oci_target(offer.image().reference().as_str())?;
        let key = PinKey::new(&project, &host_target)?;
        used.push(key.reference.clone());
        targets.push(RefreshTarget {
            predecessor: snapshot.predecessor(&key),
            operation: RefreshOperation::Adopt {
                established: boot,
                offer,
            },
            label,
            platform: platform.render(),
        });
    } else {
        let ambient_target = oci_target(boot.reference().as_str())?;
        let key = PinKey::new(&project, &ambient_target)?;
        used.push(key.reference.clone());
        targets.push(RefreshTarget {
            predecessor: snapshot.predecessor(&key),
            operation: RefreshOperation::Content {
                target: ambient_target,
                default_action: ambient_action,
            },
            label,
            platform: platform.render(),
        });
    }
    let mut holders: Vec<_> = snapshot
        .pins()
        .iter()
        .filter(|record| record.held.is_some())
        .collect();
    holders.sort_by(|left, right| {
        left.pin
            .key
            .reference
            .whole()
            .as_bytes()
            .cmp(right.pin.key.reference.whole().as_bytes())
    });
    for record in holders {
        if used.contains(&record.pin.key.reference) {
            continue;
        }
        used.push(record.pin.key.reference.clone());
        let held = record
            .held
            .ok_or_else(|| anyhow!("internal error: a holder has no roles"))?;
        let target = oci_target(record.pin.key.reference.whole().as_str())?;
        targets.push(RefreshTarget {
            predecessor: Some(record.pin.clone()),
            operation: RefreshOperation::Content {
                target,
                default_action: DefaultAction::None,
            },
            label: ImageLabel::for_refresh_holder(holder_roles(held.mask())),
            platform: platform.render(),
        });
    }
    Ok(RefreshPlan { targets })
}

/// Execute one frozen operation and report what it committed.
///
/// A caller must not use `?` on this inside the batch loop: an operation failure
/// is a row, not the end of the invocation.
pub(crate) async fn refresh_target(
    target: RefreshTarget,
    project: &ProjectDir,
) -> Result<RefreshSuccess> {
    let project_id = ProjectId::of(project);
    let RefreshTarget {
        predecessor,
        operation,
        label,
        ..
    } = target;
    match operation {
        RefreshOperation::Content {
            target,
            default_action,
        } => refresh_content(&project_id, target, predecessor, default_action, &label).await,
        RefreshOperation::Adopt { established, offer } => {
            project_default::adopt_host_default(&established, &offer, predecessor, project).await
        }
    }
}

/// The content operation, moved here from the single-selection refresh so every
/// target owns one candidate, one render and one compare-and-swap.
async fn refresh_content(
    project: &ProjectId,
    target: OciTarget,
    predecessor: Option<ApprovedPin>,
    default_action: DefaultAction,
    label: &ImageLabel,
) -> Result<RefreshSuccess> {
    if label.is_redacted() {
        crate::image_log_guard::activate();
    }
    let source = if label.is_redacted() {
        label.text().to_owned()
    } else {
        config::escape_str(target.canonical().whole().as_str())
    };
    let prepared = acquire_or_render(
        &target,
        label,
        Rendering::Selection,
        AcquireMode::ResolveCurrent,
    )
    .await?;
    let candidate = ValidatedCandidate::from_image(prepared.image(), project)?;
    store::candidate_ready()?;
    let approval = match &predecessor {
        None => Approval::initial(&candidate),
        Some(pin) => {
            let stored = pin.digest == candidate.digest;
            let equivalent = if stored {
                true
            } else {
                same_guest_content(pin, &candidate, label, Rendering::Selection).await?
            };
            match candidate_authority(stored, equivalent, candidate.key.is_immutable()) {
                CandidateAuthority::Stored | CandidateAuthority::EquivalentContent => {
                    Approval::equivalent(pin, &candidate)
                }
                // The explicit command is the consent: render, then mint.
                CandidateAuthority::Replacement => approval::approve_refresh(
                    &candidate,
                    pin.clone(),
                    &approval::ApprovalRequest {
                        source: &source,
                        platform: &candidate.key.platform,
                        old: &pin.digest,
                        new: &candidate.digest,
                    },
                )?,
                CandidateAuthority::IntegrityFailure => {
                    return Err(immutable_integrity_failure());
                }
            }
        }
    };
    // Revalidate only the frozen candidate: a mutable source that moved after it
    // was resolved must not be resolved a second time.
    drop(prepared);
    revalidate_frozen(&candidate, label, Rendering::Selection).await?;
    match commit(&candidate, &approval, default_action, RoleClaim::Keep)? {
        store::CommitOutcome::Committed(completion) => {
            completion::finish_preparation(completion.report);
            let committed = completion.value;
            Ok(RefreshSuccess {
                approval: ApprovalDelta::of(committed.previous.as_ref(), &committed.pin),
                project_default: committed.project_default,
                adopted: None,
            })
        }
        store::CommitOutcome::Conflict => Err(anyhow!(
            "image approval is stale; retry the explicit operation"
        )),
    }
}

/// What one target may mint for the content it just resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CandidateAuthority {
    /// The resolved manifest is the stored one: keep that approval untouched.
    Stored,
    /// A different manifest encoding the same measured guest content: keep the
    /// stored identity and token (S3's equivalence rule).
    EquivalentContent,
    /// A mutable source that moved: the explicit command is the consent.
    Replacement,
    /// An immutable source that resolved to different content. Never approvable.
    IntegrityFailure,
}

/// The approval decision, exhaustive over what the comparison measured.
///
/// Named and total so the three questions cannot be confused: equality of the
/// stored digest decides first, measured guest-content equivalence decides only
/// between manifests, and immutability closes the replacement door.
fn candidate_authority(
    stored_digest_equal: bool,
    equivalent_content: bool,
    immutable: bool,
) -> CandidateAuthority {
    if stored_digest_equal || equivalent_content {
        if stored_digest_equal {
            CandidateAuthority::Stored
        } else {
            CandidateAuthority::EquivalentContent
        }
    } else if immutable {
        CandidateAuthority::IntegrityFailure
    } else {
        CandidateAuthority::Replacement
    }
}

/// The ambient operation's report label. A default-tier selection is the fixed
/// redacted label; an explicit tier keeps its own escaped reference.
/// The role spellings a report label can take, mapped from the held mask by an
/// exhaustive match on the two roles.
fn holder_roles(mask: RoleMask) -> HolderRoles {
    match (mask.contains(Role::Boot), mask.contains(Role::Output)) {
        (true, false) => HolderRoles::Boot,
        (false, true) => HolderRoles::Output,
        _ => HolderRoles::BootAndOutput,
    }
}

fn canonical_of(reference: &str) -> Result<CanonicalOciReference> {
    CanonicalOciReference::parse(reference)
        .map_err(|_| anyhow!("internal error: a selected image reference is not canonical"))
}

fn same_reference(left: &str, right: &str) -> Result<bool> {
    Ok(canonical_of(left)? == canonical_of(right)?)
}

/// Membership measured for one `--image` filter against the frozen scope.
///
/// Trusted adapter: canonical reference equality, the exact project and platform
/// (variant included) the snapshot was taken for, and the held mask. The proved
/// kernel decides; nothing here restates the rule.
fn filter_is_member(
    snapshot: &RefreshScopeSnapshot,
    project: &ProjectId,
    platform: &HostLinuxPlatform,
    filter: &OciTarget,
    ambient: Option<&CanonicalOciReference>,
) -> bool {
    refresh_member(RefreshMembershipFacts {
        same_project: snapshot.covers_project(project),
        same_platform: snapshot.covers_platform(platform),
        ambient_match: ambient == Some(filter.canonical()),
        holds_role: snapshot.has_held_target(filter),
    })
}

verus! {

/// The facts of one membership question, named so an argument swap cannot invert
/// the answer.
#[derive(Clone, Copy)]
struct RefreshMembershipFacts {
    same_project: bool,
    same_platform: bool,
    ambient_match: bool,
    holds_role: bool,
}

/// Membership is scope **and** use: a record outside this project/platform is
/// never a member, and inside it either the ambient selection or a held role
/// qualifies the reference. Retention alone does not.
fn refresh_member(facts: RefreshMembershipFacts) -> (member: bool)
    ensures
        member == (facts.same_project && facts.same_platform && (facts.ambient_match || facts.holds_role)),
{
    facts.same_project && facts.same_platform && (facts.ambient_match || facts.holds_role)
}

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_pin::active::{HeldRoles, RoleMask};
    use crate::image_pin::store::RefreshScopeSnapshot;
    use crate::image_pin::{PinRevision, ProjectId};

    fn digest(byte: char) -> ManifestDigest {
        ManifestDigest::parse(&format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn pin(project: &ProjectId, reference: &str, byte: char, revision: u64) -> ApprovedPin {
        let target = OciTarget::parse(reference).unwrap();
        ApprovedPin {
            key: PinKey::new(project, &target).unwrap(),
            digest: digest(byte),
            revision: PinRevision(revision),
        }
    }

    /// The approval decision over every measured combination: equality wins,
    /// equivalent guest content keeps the stored identity, and only a mutable
    /// source with different content can be replaced — an immutable one that
    /// moved is a hard integrity failure, never a skip and never a replacement.
    #[test]
    fn candidate_authority_is_total_and_never_replaces_an_immutable_source() {
        use CandidateAuthority::{EquivalentContent, IntegrityFailure, Replacement, Stored};
        let rows = [
            (true, true, true, Stored),
            (true, true, false, Stored),
            (true, false, true, Stored),
            (true, false, false, Stored),
            (false, true, true, EquivalentContent),
            (false, true, false, EquivalentContent),
            (false, false, true, IntegrityFailure),
            (false, false, false, Replacement),
        ];
        for (stored, equivalent, immutable, expected) in rows {
            assert_eq!(
                candidate_authority(stored, equivalent, immutable),
                expected,
                "stored={stored} equivalent={equivalent} immutable={immutable}"
            );
        }
    }

    /// Membership is `same_project && same_platform && (ambient_match ||
    /// holds_role)` over every fact combination, and the adapter applies exactly
    /// that to literal scopes: an unheld ambient selection is a member, an
    /// unheld retained record is not, a held role is, and neither a foreign
    /// project nor a foreign platform/variant qualifies.
    #[test]
    fn refresh_membership_uses_ambient_and_held_roles_only() {
        // Sixteen literal rows, so the expected values do not restate the
        // formula the kernel is written with: `same_project, same_platform,
        // ambient_match, holds_role => member`.
        let rows = [
            (false, false, false, false, false),
            (false, false, false, true, false),
            (false, false, true, false, false),
            (false, false, true, true, false),
            (false, true, false, false, false),
            (false, true, false, true, false),
            (false, true, true, false, false),
            (false, true, true, true, false),
            (true, false, false, false, false),
            (true, false, false, true, false),
            (true, false, true, false, false),
            (true, false, true, true, false),
            (true, true, false, false, false),
            (true, true, false, true, true),
            (true, true, true, false, true),
            (true, true, true, true, true),
        ];
        for (same_project, same_platform, ambient_match, holds_role, expected) in rows {
            assert_eq!(
                refresh_member(RefreshMembershipFacts {
                    same_project,
                    same_platform,
                    ambient_match,
                    holds_role,
                }),
                expected,
                "project={same_project} platform={same_platform} ambient={ambient_match} held={holds_role}"
            );
        }

        let project = ProjectId::for_tests('a');
        let platform = HostLinuxPlatform::host();
        let mut variant_platform = platform.clone();
        variant_platform.variant = Some("v8".to_owned());
        let ambient_c = OciTarget::parse("example.com/team/c:tag").unwrap();
        let held_boot = OciTarget::parse("example.com/team/b:tag").unwrap();
        let held_output = OciTarget::parse("example.com/team/o:tag").unwrap();
        let unheld = OciTarget::parse("example.com/team/u:tag").unwrap();
        let foreign_project = OciTarget::parse("example.com/team/f:tag").unwrap();
        let foreign_platform = OciTarget::parse("example.com/team/p:tag").unwrap();

        let snapshot = RefreshScopeSnapshot::for_tests(
            &project,
            platform.clone(),
            vec![
                (
                    pin(&project, "example.com/team/b:tag", 'd', 1),
                    HeldRoles::new(RoleMask::BOOT),
                ),
                (
                    pin(&project, "example.com/team/o:tag", 'e', 2),
                    HeldRoles::new(RoleMask::OUTPUT),
                ),
                (pin(&project, "example.com/team/u:tag", 'f', 3), None),
            ],
        );
        let member = |filter: &OciTarget, ambient: Option<&str>| {
            let ambient = ambient.map(|text| {
                CanonicalOciReference::parse(text).expect("the fixture ambient is canonical")
            });
            filter_is_member(&snapshot, &project, &platform, filter, ambient.as_ref())
        };

        // The ambient selection is a member even with no record at all (a
        // selection that has never been prepared since the upgrade).
        assert!(member(&ambient_c, Some("example.com/team/c:tag")));
        assert!(!member(&ambient_c, None), "an unrecorded key is not in use");
        // A held role is a member without any ambient match.
        assert!(member(&held_boot, None));
        assert!(member(&held_output, None));
        // A retained-but-unheld approval is not membership.
        assert!(!member(&unheld, None));
        // Canonical spellings compare by identity, not by text.
        assert!(member(
            &OciTarget::parse("docker.io/library/alpine:latest").unwrap(),
            Some("docker.io/library/alpine:latest")
        ));
        // A foreign record is not in this snapshot, and a foreign platform's
        // variant is a different scope.
        assert!(!member(&foreign_project, None));
        assert!(!filter_is_member(
            &snapshot,
            &project,
            &variant_platform,
            &held_boot,
            None
        ));
        assert!(!member(&foreign_platform, None));
        assert!(snapshot.covers_project(&project));
        assert!(!snapshot.covers_platform(&variant_platform));
    }
}
