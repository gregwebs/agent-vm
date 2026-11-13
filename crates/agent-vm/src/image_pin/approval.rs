//! Candidate-scoped consent for replacing one project's approval.
//!
//! Everything the consent needs is bound here and nowhere else: the escaped
//! source, the platform the approval is keyed by, and the two full native
//! manifest digests. The [`Approval`] this module returns names exactly the
//! candidate that was displayed, so a registry that moves again between display
//! and commit cannot ride the same consent — the commit's compare-and-swap
//! checks that digest under the host lock and refuses a different one.
//!
//! # Three consent surfaces, one rendering rule
//!
//! The explicit commands `image refresh`, `image build` and `image import` are
//! the consent (ADR-0043, ADR-0067): running the command *is* the request, so
//! nothing is asked and no input is read, on a terminal or not. Each still
//! renders the change before it is committed — a user who ran the command can
//! see what it did, and a render that cannot be written commits nothing.

use std::io::Write as _;

use anyhow::{Result, anyhow};

use super::project_default::{DefaultAdoption, ProjectDefault};
use super::{
    Approval, ApprovedPin, HostLinuxPlatform, ImmutableImageRef, ManifestDigest, ValidatedCandidate,
};

/// What the render may name: an already-escaped source and the approval key.
pub(super) struct ApprovalRequest<'a> {
    /// The source as the user selected it, already escaped for a terminal. For
    /// a redacted default-tier selection this is the fixed label, never the
    /// stored reference.
    pub(super) source: &'a str,
    pub(super) platform: &'a HostLinuxPlatform,
    pub(super) old: &'a ManifestDigest,
    pub(super) new: &'a ManifestDigest,
}

impl ApprovalRequest<'_> {
    /// States the change; it does not ask. Both digests are full so they can be
    /// compared with the store by eye, and there is no question mark to promise
    /// an answer nothing reads.
    fn render(&self) -> String {
        format!(
            "Replacing the approved image for {} ({}) in this project:\n  old: {}\n  new: {}\n",
            self.source,
            self.platform.render(),
            self.old.as_str(),
            self.new.as_str()
        )
    }
}

/// Take consent to replace the approval `expected` names with exactly
/// `candidate`.
///
/// The explicit refresh is the consent (ADR-0067). The change is rendered
/// first, and a render that cannot be written is fatal *before* any commit, so
/// no approval is ever recorded for a change the user never saw.
pub(super) fn approve_refresh(
    candidate: &ValidatedCandidate,
    expected: ApprovedPin,
    request: &ApprovalRequest<'_>,
) -> Result<Approval> {
    std::io::stderr()
        .write_all(request.render().as_bytes())
        .map_err(|_| render_failed())?;
    Ok(Approval::replacement(candidate, expected))
}

/// Consent to move one project's established default to the host's retained
/// default (R7), rendered when the content differs.
///
/// No content-equivalence comparison is made: invocation is the consent whether
/// or not the content changed, so only the render can depend on the digests. The
/// default tier is always the fixed label, so the render names no source.
pub(super) fn adopt(
    expected: ProjectDefault,
    proposed: ImmutableImageRef,
    candidate: &ValidatedCandidate,
    old: &ManifestDigest,
) -> Result<DefaultAdoption> {
    if old != &candidate.digest {
        let render = adoption_render(&HostLinuxPlatform::host(), old, &candidate.digest);
        std::io::stderr()
            .write_all(render.as_bytes())
            .map_err(|_| render_failed())?;
    }
    Ok(DefaultAdoption::new(expected, proposed, candidate))
}

/// Full digests, the approval key's platform, and no source: an adoption's
/// selection is the default tier, whose reference is redacted everywhere but
/// `image show`.
fn adoption_render(
    platform: &HostLinuxPlatform,
    old: &ManifestDigest,
    new: &ManifestDigest,
) -> String {
    format!(
        "Adopting the host's default boot image ({}) in this project:\n  old: {}\n  new: {}\n",
        platform.render(),
        old.as_str(),
        new.as_str()
    )
}

/// The publishing command is the consent (#391): render the change, then mint
/// it. A render that cannot be written commits nothing.
///
/// `source` is already escaped (`ImageLabel::for_result_reference`); this module
/// never treats it as a shell word.
pub(super) fn approve_publication(
    candidate: &ValidatedCandidate,
    expected: Option<ApprovedPin>,
    source: &str,
) -> Result<Approval> {
    let platform = HostLinuxPlatform::host();
    let render = publication_render(source, &platform, expected.as_ref(), &candidate.digest);
    std::io::stderr()
        .write_all(render.as_bytes())
        .map_err(|_| render_failed())?;
    Ok(match expected {
        Some(pin) => Approval::replacement(candidate, pin),
        None => Approval::initial(candidate),
    })
}

/// Full digests, the approval key's platform, and `none` for a first approval:
/// a truncated digest could not be compared with the store by eye, and a
/// question mark would promise an answer this command never reads.
fn publication_render(
    source: &str,
    platform: &HostLinuxPlatform,
    old: Option<&ApprovedPin>,
    new: &ManifestDigest,
) -> String {
    format!(
        "Approving the image published as {} ({}) for this project:\n  old: {}\n  new: {}\n",
        source,
        platform.render(),
        old.map_or("none".to_string(), |pin| pin.digest.as_str().to_string()),
        new.as_str()
    )
}

fn render_failed() -> anyhow::Error {
    anyhow!("the image approval change could not be shown, so nothing was approved")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_acquire::OciTarget;
    use crate::image_pin::{PinKey, PinRevision, ProjectId};

    /// The refresh render states the change: no question, no answer prompt.
    #[test]
    fn rendered_change_names_both_full_digests_and_the_escaped_source() {
        let old = ManifestDigest::parse(&format!("sha256:{}", "a".repeat(64))).unwrap();
        let new = ManifestDigest::parse(&format!("sha384:{}", "b".repeat(96))).unwrap();
        let platform = HostLinuxPlatform::for_tests();
        let text = ApprovalRequest {
            // Already escaped by the caller, exactly as `image_pin::Plan`
            // renders it; this module never treats the text as a shell word.
            source: "example.com/team/\\x1b[31mimage:tag",
            platform: &platform,
            old: &old,
            new: &new,
        }
        .render();
        assert!(text.contains("old: sha256:"));
        assert!(text.contains(&"a".repeat(64)));
        assert!(text.contains("new: sha384:"));
        assert!(text.contains(&"b".repeat(96)));
        assert!(text.contains("(linux/"));
        assert!(
            text.contains(" in this project:"),
            "the render names the approval scope: {text}"
        );
        assert!(!text.contains('?'), "nothing is asked: {text}");
        assert!(!text.contains("[y/N]"), "nothing is asked: {text}");
        assert!(
            !text.contains('\u{1b}'),
            "no raw control byte reaches the terminal"
        );
        assert!(text.contains("\\x1b"), "the escape is visible, not dropped");
    }

    /// The adoption render: both full digests, the platform, and no source (the
    /// default tier is the fixed label, so there is nothing to name).
    #[test]
    fn adoption_render_names_both_full_digests_and_no_source() {
        let platform = HostLinuxPlatform::for_tests();
        let old = ManifestDigest::parse(&format!("sha256:{}", "a".repeat(64))).unwrap();
        let new = ManifestDigest::parse(&format!("sha384:{}", "b".repeat(96))).unwrap();
        let text = adoption_render(&platform, &old, &new);
        assert!(
            text.starts_with("Adopting the host's default boot image ("),
            "{text}"
        );
        assert!(text.contains(&format!("old: {old}")), "{text}");
        assert!(text.contains(&format!("new: {new}")), "{text}");
        assert!(text.contains("(linux/"), "{text}");
        assert!(!text.contains('?'), "nothing is asked: {text}");
        assert!(!text.contains("//"), "no source is named: {text}");
    }

    /// The publishing command's render: both shapes, full digests, the platform
    /// the pin is keyed by, and no question mark — nothing is read here.
    #[test]
    fn publication_render_names_full_digests_and_a_first_approval() {
        let platform = HostLinuxPlatform::for_tests();
        let old = ManifestDigest::parse(&format!("sha256:{}", "a".repeat(64))).unwrap();
        let new = ManifestDigest::parse(&format!("sha384:{}", "b".repeat(96))).unwrap();
        let key = PinKey::new(
            &ProjectId::for_tests('a'),
            &OciTarget::parse("example.com/team/app:dev").unwrap(),
        )
        .unwrap();
        let previous = ApprovedPin {
            key,
            digest: old.clone(),
            revision: PinRevision(1),
        };

        let replacement = publication_render(
            "example.com/team/\\x1b[31mapp:dev",
            &platform,
            Some(&previous),
            &new,
        );
        assert!(
            replacement.contains(&format!("old: {old}")),
            "{replacement}"
        );
        assert!(
            replacement.contains(&format!("new: {new}")),
            "{replacement}"
        );
        assert!(replacement.contains("(linux/"));
        assert!(
            replacement.contains(" for this project:"),
            "the render names the approval scope: {replacement}"
        );
        assert!(replacement.contains("\\x1b"), "the escape is visible");
        assert!(
            !replacement.contains('\u{1b}'),
            "no raw control byte reaches the terminal"
        );
        assert!(!replacement.contains("[y/N]"), "nothing is asked");

        let first = publication_render("example.com/team/app:dev", &platform, None, &new);
        assert!(first.contains("old: none"), "{first}");
        assert!(first.contains(&format!("new: {new}")), "{first}");
        assert!(
            !first.contains("sha256:"),
            "no invented predecessor: {first}"
        );
    }
}
