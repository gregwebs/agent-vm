//! Deliberate acquisition of one explicit target and publication of it as the
//! host's **starting choice**. The acquisition path, the approval authority and
//! both records belong to [`crate::image_pin`]: this module owns only the
//! command's argument shape and the words it prints.
//!
//! The target is required and typed (`--image REF`), so no ambient selection,
//! image override, broken catalog or current recommendation can choose it. The
//! host record then stores the validated host child — never the source tag
//! (#392) — and this command writes no approval at all (ADR-0067), so it cannot
//! change what an **established** project boots, including the invoking one. An
//! unestablished project has no default of its own, so the host record is still
//! its starting choice and its next default-tier use boots and establishes it.

use std::io::Write;
use std::str::FromStr;

use super::ImageRef;
use crate::image_acquire::{OciTarget, OciTargetError};
use crate::image_pin::{DefaultChange, HostDefaultSet, InvokingProject};
use crate::project::ProjectDir;
use anyhow::Result;

/// The fixed refusal for a local rootfs/disk `--image` target. Names no value:
/// the rejected text is user input.
const TARGET_REASON: &str = "set-default targets must be OCI image references (tag or digest); launch a local rootfs with agent-vm --image PATH <tool>";

/// The fixed refusal for `--image` text that is not a usable OCI reference at
/// all. It must not suggest a local launch for a malformed reference.
const INVALID_REFERENCE_REASON: &str =
    "set-default needs a valid OCI image reference, e.g. ghcr.io/owner/name:tag or repo@sha256:…";

#[derive(clap::Args)]
pub(crate) struct Args {
    /// OCI image to acquire and retain as the starting default for projects that
    /// have none yet; established projects keep their own (run `agent-vm image
    /// refresh` in one to adopt it).
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
    #[allow(clippy::disallowed_methods)] // one capture per command: every consumer borrows it.
    let project = ProjectDir::capture()?;
    crate::msb_preflight::ensure_db_not_ahead().await?;
    crate::image_log_guard::activate();
    let outcome = crate::image_pin::set_default(&args.target.0, &project).await?;
    let notice = notice(outcome);
    // The host record is already committed: output failure cannot turn success
    // into error.
    let _ = writeln!(std::io::stderr(), "{notice}");
    Ok(())
}

/// What the user is told: the host's starting choice first, then what this
/// project is doing about it. Two sentences on purpose — the host change and the
/// invoking project's disposition are separate facts, and a command whose whole
/// point is that it does not move an established project must say whether it
/// applies here.
fn notice(outcome: HostDefaultSet) -> String {
    let retained = match outcome.retained_default {
        DefaultChange::Unchanged => {
            "Default boot image is already selected for projects that have none yet; \
             established projects, image overrides and running sessions are unchanged."
        }
        DefaultChange::Initialized | DefaultChange::Replaced => {
            "Default boot image selected for projects that have none yet; established \
             projects, image overrides and running sessions are unchanged."
        }
    };
    let this_project = match outcome.this_project {
        InvokingProject::NotEstablished => {
            "This project has no default boot image yet, so its next default-image session \
             starts from this one."
        }
        InvokingProject::AlreadyUses => "This project already uses it.",
        InvokingProject::KeepsItsOwn => {
            "This project keeps its own default boot image; run `agent-vm image refresh` here \
             to adopt this one."
        }
    };
    format!("{retained} {this_project}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot_image::ImmutableImageRef;

    /// The 3x3 notice table: only a host record that did not change says
    /// "already selected", and only a project that keeps its own default names
    /// the command that adopts the new one.
    #[test]
    fn the_notice_states_the_host_choice_then_the_invoking_project() {
        for retained_default in [
            DefaultChange::Unchanged,
            DefaultChange::Initialized,
            DefaultChange::Replaced,
        ] {
            for this_project in [
                InvokingProject::NotEstablished,
                InvokingProject::AlreadyUses,
                InvokingProject::KeepsItsOwn,
            ] {
                let text = notice(HostDefaultSet {
                    retained_default,
                    this_project,
                });
                assert_eq!(
                    text.contains("already selected"),
                    retained_default == DefaultChange::Unchanged,
                    "{retained_default:?}/{this_project:?}: {text}"
                );
                assert_eq!(
                    text.contains("agent-vm image refresh"),
                    this_project == InvokingProject::KeepsItsOwn,
                    "{retained_default:?}/{this_project:?}: {text}"
                );
                assert!(text.ends_with('.'), "the notice is two sentences: {text}");
            }
        }
    }

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
