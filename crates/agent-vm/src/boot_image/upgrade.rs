//! Deliberate acquisition followed by publication of a user-owned default.
//! Two native pulls populate the canonical digest cache key without inventing
//! aliases; acquisition never holds the selection lock or creates a VM.
//!
//! Both pulls go through [`crate::image_acquire`]'s guarded validating helper,
//! so the requested key is proven complete, host-Linux and identity-consistent
//! before this command constructs a success token or touches the retained
//! record. The second equality below is justified by construction: the child
//! target is derived from the first result, so it must resolve to the same
//! resolved identity. An index requested on the first pull is valid even when
//! its digest differs from the resolved host child.

use std::io::Write;
use std::str::FromStr;

use super::{AcquiredDefaultImage, DefaultUpgradeOutcome, ImageLabel, ImageRef, default_selection};
use crate::image_acquire::{AcquireError, AcquireMode, OciTarget, OciTargetError, acquire};
use anyhow::{Result, anyhow};

/// Fixed text for an acquired identity with no usable immutable reference. It
/// names no value: the target may be a private registry reference.
const IMMUTABLE_IDENTITY_UNAVAILABLE: &str = "the acquired image did not yield a usable immutable reference; this command did not change the retained default";

/// The fixed refusal for a local rootfs/disk `--image` target. Names no value:
/// the rejected text is user input.
const TARGET_REASON: &str = "set-default targets must be OCI image references (tag or digest); launch a local rootfs with agent-vm --image PATH <tool>";

/// The fixed refusal for `--image` text that is not a usable OCI reference at
/// all. It must not suggest a local launch for a malformed reference.
const INVALID_REFERENCE_REASON: &str =
    "set-default needs a valid OCI image reference, e.g. ghcr.io/owner/name:tag or repo@sha256:…";

#[derive(clap::Args)]
pub(crate) struct Args {
    /// OCI image to acquire and retain for future default-image sessions.
    #[arg(long = "image", value_name = "REF", value_parser = SetDefaultTargetParser)]
    target: SetDefaultTarget,
}

#[derive(Clone)]
struct SetDefaultTarget(ImageRef);

impl SetDefaultTarget {
    fn parse(raw: &str) -> std::result::Result<Self, OciTargetError> {
        // The same acceptance rule the acquisition itself will apply, so a
        // target clap accepts cannot be refused later for a different reason.
        OciTarget::parse(raw)?;
        ImageRef::from_config(raw)
            .map(Self)
            .map_err(|_| OciTargetError::InvalidReference)
    }
}

impl FromStr for SetDefaultTarget {
    type Err = &'static str;

    fn from_str(raw: &str) -> std::result::Result<Self, Self::Err> {
        Self::parse(raw).map_err(target_reason)
    }
}

/// This command's value-free reason for a rejected `--image` target.
fn target_reason(error: OciTargetError) -> &'static str {
    match error {
        OciTargetError::LocalPath => TARGET_REASON,
        OciTargetError::InvalidReference => INVALID_REFERENCE_REASON,
    }
}

/// Set-default's own clap value parser.
///
/// clap's stock `FromStr` wrapper renders the rejected value in its error, and a
/// private target is still the user's own input, so every refusal is a raw
/// fixed-reason clap error instead (non-Unicode input included).
#[derive(Clone)]
struct SetDefaultTargetParser;

impl clap::builder::TypedValueParser for SetDefaultTargetParser {
    type Value = SetDefaultTarget;

    fn parse_ref(
        &self,
        _cmd: &clap::Command,
        _arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> std::result::Result<Self::Value, clap::Error> {
        let reason = match value.to_str() {
            Some(text) => match SetDefaultTarget::parse(text) {
                Ok(target) => return Ok(target),
                Err(error) => target_reason(error),
            },
            // Non-Unicode text cannot be an OCI reference; never echo it.
            None => INVALID_REFERENCE_REASON,
        };
        Err(clap::Error::raw(
            clap::error::ErrorKind::ValueValidation,
            reason,
        ))
    }
}

pub(crate) async fn run(args: Args) -> Result<()> {
    crate::msb_preflight::ensure_db_not_ahead().await?;
    crate::image_log_guard::activate();
    // Health only: explicit initialization must not evaluate a recommendation.
    default_selection::load()?;
    let acquired = acquire_target(&args.target).await?;
    let outcome = default_selection::replace(&acquired)
        .map_err(|error| anyhow!("publishing the default boot image failed: {error}; this command did not change the retained default"))?;
    let notice = match outcome {
        DefaultUpgradeOutcome::Changed => {
            "Default boot image selected for future default-image sessions; image overrides and running sessions are unchanged."
        }
        DefaultUpgradeOutcome::Unchanged => {
            "Default boot image is already selected; image overrides and running sessions are unchanged."
        }
    };
    // Publication already committed: output failure cannot turn success into error.
    let _ = writeln!(std::io::stderr(), "{notice}");
    Ok(())
}

async fn acquire_target(target: &SetDefaultTarget) -> Result<AcquiredDefaultImage> {
    let native_target = OciTarget::parse(target.0.as_str()).map_err(|error| {
        anyhow!(
            "{}; this command did not change the retained default",
            target_reason(error)
        )
    })?;
    let label = ImageLabel::for_default_upgrade();
    // One acquisition resolves the explicit target's current content and
    // preserves the validated host child (`repo@C`) as canonical cache
    // metadata. The duplicate second pull this command used to derive the pin
    // is gone: `AcquireMode::ResolveCurrent` plus canonical preservation own
    // identity, and a moving index cannot be resolved twice.
    let prepared = acquire(&native_target, &label, AcquireMode::ResolveCurrent)
        .await
        .map_err(set_default_error)?;
    let reference = prepared
        .image()
        .immutable_reference()
        .map_err(|_| anyhow!(IMMUTABLE_IDENTITY_UNAVAILABLE))?;
    drop(prepared);
    Ok(AcquiredDefaultImage { reference })
}

/// Explicit set-default failures are always rendered as fixed, reference-free
/// text (a valid but private target is still the user's own input we must not
/// echo on failure), with the "no retained change" guarantee spelled out.
fn set_default_error(error: AcquireError) -> anyhow::Error {
    anyhow!(
        "{}; this command did not change the retained default",
        error.redacted_message()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot_image::ImmutableImageRef;

    #[test]
    fn derived_child_is_canonical_and_immutable() {
        let child = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        for (input, expected) in [
            ("localhost:1234/a:tag", "localhost:1234/a@"),
            ("alpine:latest", "docker.io/library/alpine@"),
            (
                "localhost:1234/a@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "localhost:1234/a@",
            ),
        ] {
            let target = OciTarget::parse(input).unwrap();
            let pinned = target
                .canonical()
                .with_digest(&crate::image_acquire::ValidatedDigest::parse(child).unwrap())
                .unwrap();
            assert_eq!(pinned.whole(), format!("{expected}{child}"));
            assert!(ImmutableImageRef::parse(&pinned.whole()).is_ok());
        }
    }

    #[test]
    fn targets_are_oci_only_with_set_default_specific_safe_advice() {
        for raw in [
            "alpine:latest",
            "localhost:1234/a:release",
            "repo@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert!(raw.parse::<SetDefaultTarget>().is_ok());
        }
        for raw in ["", "Foo/Bar:tag", "repo:bad tag", "repo@sha256:short"] {
            let error = raw.parse::<SetDefaultTarget>().err().unwrap();
            assert_eq!(error, INVALID_REFERENCE_REASON);
            assert!(!error.contains("agent-vm --image PATH <tool>"));
        }
        for raw in ["/private/path", "./rootfs", "../rootfs", ".."] {
            let error = raw.parse::<SetDefaultTarget>().err().unwrap();
            assert_eq!(error, TARGET_REASON);
            assert!(error.contains("agent-vm --image PATH <tool>"));
        }
    }
}
