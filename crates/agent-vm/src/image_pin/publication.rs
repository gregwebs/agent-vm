//! The result reference an explicit `image build`/`image import` names is the one
//! reference that command approves (#391). The command that supplied the bytes is
//! the consent: nothing is asked, but the change is rendered before it is
//! committed.
//!
//! # Why this runs after publication returns
//!
//! [`crate::image_publish::ImageTarget::publish`] holds the cache's exclusive
//! barrier until it returns; this read-back takes the shared one on a new
//! descriptor, which would wait forever under it. The [`Published`] token holds
//! no barrier, and each verb calls this only after `publish` has returned; that
//! call order (not the type system) is what keeps the read-back outside the
//! exclusive guard.
//!
//! # Why the read-back is cache-only
//!
//! A miss must never become a registry pull: that would replace the alias this
//! command just published and approve bytes the operator never supplied.

use anyhow::{Context as _, Result, anyhow};

use super::*;
use crate::image_publish::{Published, ResultReference};

/// The key a publication preflight checked, carried to the approval that
/// follows the Docker run: a build/import approves under the project and
/// result key its own preflight checked, however long Docker ran in between.
pub(crate) struct PublicationScope {
    key: PinKey,
}

/// A bounded advisory check before any Docker work or publication: refuse early
/// when HOME is unusable or the store is unreadable/damaged/locked. A pass does
/// not promise the later commit can be saved (write permission, capacity,
/// revisions and concurrent writers are only known at commit). The observation
/// is discarded: the predecessor is re-read after the read-back.
pub(crate) fn publication_preflight(
    result: &ResultReference,
    project: &ProjectDir,
) -> Result<PublicationScope> {
    let target = OciTarget::parse(result.as_str())
        .map_err(|_| anyhow!("the result reference is not a usable OCI target"))?;
    let key = PinKey::new(&ProjectId::of(project), &target)?;
    lookup(&key).map(drop).context(
        "checking the project image approval before publishing; nothing was built or imported",
    )?;
    Ok(PublicationScope { key })
}

/// Approve the published result and claim Output for it.
///
/// The returned report covers only **post-rename** reporting; a `?` here is a
/// precommit failure, which is why the ordinary "approval was not updated"
/// context still wraps it.
pub(crate) async fn approve_published(
    published: &Published,
    scope: &PublicationScope,
) -> Result<CommitReport> {
    let label = ImageLabel::for_result_reference(&published.target().canonical().whole());
    approve(published, &label, scope)
        .await
        .with_context(|| crate::image_publish::approval_not_updated(label.text()))
}

async fn approve(
    published: &Published,
    label: &ImageLabel,
    scope: &PublicationScope,
) -> Result<CommitReport> {
    store::published_ready()?;
    let prepared = acquire_or_render(
        published.target(),
        label,
        Rendering::Publication,
        AcquireMode::CachedOnly,
    )
    .await?;
    if prepared.image().acquired_digest() != published.digest() {
        return Err(moved_before_approval());
    }
    let candidate = ValidatedCandidate::from_image(prepared.image(), &scope.key.project)?;
    if candidate.key != scope.key {
        return Err(anyhow!(
            "internal error: the published result is not the reference the preflight checked"
        ));
    }
    store::candidate_ready()?;
    let approval = match lookup(&candidate.key)? {
        Some(pin) if pin.digest == candidate.digest => Approval::equivalent(&pin, &candidate),
        Some(pin) => {
            if same_cached_content(&pin, &candidate, label).await? {
                Approval::equivalent(&pin, &candidate)
            } else {
                approval::approve_publication(&candidate, Some(pin), label.text())?
            }
        }
        None => approval::approve_publication(&candidate, None, label.text())?,
    };
    // Committed under the read-back's shared barrier, like a launch's first pin:
    // no exclusive publisher can intervene. A concurrent refresh (also shared)
    // may move the alias; the frozen `repo@digest` candidate and the CAS cover it.
    // Build and import share one Output slot and never select Boot.
    let report = match commit(
        &candidate,
        &approval,
        DefaultAction::None,
        RoleClaim::Claim(Role::Output),
    )? {
        store::CommitOutcome::Committed(completion) => completion.report,
        store::CommitOutcome::Conflict => {
            return Err(anyhow!(
                "image approval is stale; retry the explicit operation"
            ));
        }
    };
    drop(prepared);
    Ok(report)
}

/// Cache-only equivalence: an approved digest whose content is not in this cache
/// is not evidence of equality, so it is a replacement — never a registry fetch.
async fn same_cached_content(
    pin: &ApprovedPin,
    candidate: &ValidatedCandidate,
    label: &ImageLabel,
) -> Result<bool> {
    let approved = pin.immutable_reference()?;
    let target = OciTarget::parse(approved.as_str()).map_err(|_| approval_unusable())?;
    match image_acquire::acquire(&target, label, AcquireMode::CachedOnly).await {
        Ok(prepared) => {
            let identity = prepared.image().content_identity();
            Ok(content_is_equivalent(ContentFacts {
                config_equal: identity.config_digest == candidate.identity.config_digest,
                layers_equal: identity.diff_ids == candidate.identity.diff_ids,
            }))
        }
        Err(AcquireError::NotCached) => Ok(false),
        Err(error) => Err(render_failure(
            label,
            Rendering::Publication,
            target.source_text(),
            error,
        )),
    }
}

fn moved_before_approval() -> anyhow::Error {
    anyhow!(
        "the result reference changed in the image cache before it could be approved (another \
         publication or acquisition moved it); re-run the command"
    )
}
