//! `agent-vm image refresh` — acquire the selected OCI reference into
//! microsandbox's image cache without booting anything.
//!
//! Acquisition is native ([`crate::image_acquire`]): `Registry` with
//! `PullPolicy::Always` and `force: false`, so the registry's current manifest is
//! re-resolved and valid cached layers are reused rather than re-downloaded. No
//! sandbox, VM, temporary disk, Docker or alternate download backend is
//! involved, and nothing about a project or a running guest changes.
//!
//! Retention is a *separate* decision made by the caller after acquisition
//! succeeds ([`boot_image::adopt_default_selection`]): a default-tier refresh may
//! initialize an absent retained default, and neither `--image`, env nor a
//! config tier ever replaces one.
//!
//! The advisory marker (`pulled_marker`) records the resolved manifest digest
//! this acquisition actually landed, keyed by the selected reference. It exists
//! so the launch banner can say "an update is available"; it is not an approval
//! record, not proof of cached identity, and a failed acquisition leaves it
//! untouched.

use anyhow::{Context, Result, anyhow};
use clap::Args as ClapArgs;

use crate::boot_image;
use crate::config::{Catalog, ConfiguredImages};
use crate::image_acquire::{
    AcquireError, AcquireMode, OciTarget, OciTargetError, PreparedNativeImage, acquire,
};

/// The fixed refusal for a refresh target that is a local rootfs or disk path.
/// Names no value: the rejected text is user input.
pub(crate) const TARGET_REASON: &str = "`agent-vm image refresh` acquires OCI image references (tag or digest) only; \
     it never boots, formats or reads a local rootfs — launch a local rootfs or disk image with \
     agent-vm --image PATH <tool> instead";

/// The fixed refusal for a target that is not a usable OCI reference at all.
/// A malformed reference is not a local path, so it must not be told how to
/// launch one; the value itself is never echoed.
pub(crate) const INVALID_REFERENCE_REASON: &str = "`agent-vm image refresh` needs a valid OCI image reference, \
     e.g. ghcr.io/owner/name:tag or repo@sha256:…";

/// Render this command's value-free refusal for a rejected target.
pub(crate) fn target_error(error: OciTargetError) -> anyhow::Error {
    match error {
        OciTargetError::LocalPath => anyhow!(TARGET_REASON),
        OciTargetError::InvalidReference => anyhow!(INVALID_REFERENCE_REASON),
    }
}

#[derive(ClapArgs)]
pub struct Args {
    /// The OCI boot image to acquire into the image cache without booting.
    /// Defaults to the image this configuration would boot. See "Selecting the
    /// boot image" in USAGE.md.
    #[command(flatten)]
    pub(crate) image: boot_image::ImageArgs,
}

pub async fn run(args: Args, catalog: Catalog, images: ConfiguredImages) -> Result<()> {
    // The native pull still reaches the shared microsandbox state (its cache and
    // registry configuration), so it can hit the same forward-migrated-DB crash
    // as the boot path. See src/msb_preflight.rs and issue #30.
    crate::msb_preflight::ensure_db_not_ahead().await?;

    // A broken config leaves the configured image tiers unknown (D7): warn and
    // fall through to `--image`/env or the default boot image, so refresh still
    // recovers.
    if let Catalog::Broken(error) = &catalog {
        println!(
            "==> WARNING: configured image settings could not be read: {error:#}; \
             falling back to --image/AGENT_VM_IMAGE_TAG or the default boot image"
        );
    }
    let boot = boot_image::select(args.image.requested()?, &images)?;
    let label = boot.label();
    println!("==> {label} is the image this configuration boots from");
    // The explicit refresh resolves the current source even when the cache is
    // warm; a returned token holds the shared barrier only until this statement
    // ends, and refresh never boots anything.
    drop(pull_image(boot.reference().as_str(), &label).await?);
    // Success-before-adoption (#261): only after the acquisition succeeded may a
    // default-tier selection become the retained default. An explicit, env or
    // config refresh never adopts its target.
    boot_image::adopt_default_selection(&boot)
        .context("retaining the selected default boot image")?;
    println!(
        "==> {} acquired into the microsandbox image cache",
        label.text()
    );
    Ok(())
}

/// Reject an unusable refresh target from input alone.
///
/// Runs before `main`'s MSB prologue, so a CLI/env local rootfs or disk target
/// cannot create state, read configuration again, select a fallback or stat the
/// path. Every configured/default reference already satisfies the OCI policy;
/// only the override can be a local path.
pub(crate) fn preflight(args: &Args) -> Result<()> {
    let Some(requested) = args.image.requested()? else {
        return Ok(());
    };
    OciTarget::parse(requested.reference().as_str())
        .map(|_| ())
        .map_err(target_error)
}

/// Acquire `image` into the image cache, without booting. Shared by
/// `image refresh` and `setup`'s pull step.
///
/// `label` is the selection's safe output policy: when it is redacted (the
/// default tier) the debug dump, progress display and any acquisition error
/// carry the fixed label instead of the record/recommendation reference.
pub async fn pull_image(
    image: &str,
    label: &boot_image::ImageLabel,
) -> Result<PreparedNativeImage> {
    let target = OciTarget::parse(image).map_err(target_error)?;
    let prepared = acquire(&target, label, AcquireMode::ResolveCurrent)
        .await
        .map_err(|error| acquisition_error(label, image, error))?;
    // Only a successful, validated acquisition updates the advisory marker, and
    // it records *this* pull's acquired digest rather than a second registry
    // probe: a probe could race a moving tag and assumes an index layout.
    if let Err(error) =
        crate::pulled_marker::write(image, prepared.image().acquired_digest().as_str())
    {
        // A trusted-host state path error, never the image reference, so it is
        // printed as-is for debugging (not escaped).
        eprintln!("warn: failed to record the refreshed image digest: {error:#}");
    }
    Ok(prepared)
}

/// Render an acquisition failure for this selection without leaking a redacted
/// reference.
///
/// A redacted selection may not disclose a reference, and a postvalidation
/// failure's sources can name one, so its closed safe text is chosen *before*
/// the generic redactor (which would flatten it into a registry message and lose
/// the failed-restore stage). It keeps its recovery requirement. Explicit
/// sources keep both stages, the native chain and the import hint.
fn acquisition_error(
    label: &boot_image::ImageLabel,
    image: &str,
    error: AcquireError,
) -> anyhow::Error {
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
    crate::image_miss::attach(error.into_explicit_error(), image, label)
}

/// Decide whether the registry needs `--insecure` (plain HTTP).
///
/// Two ways to get a `true`:
/// 1. `AGENT_VM_INSECURE_REGISTRY=1` env var — opt-in escape hatch
///    for airgapped/intranet plain-HTTP registries
///    (`registry.corp.example:5000`, `192.168.1.10:5000`, etc.) that
///    the heuristic can't recognise from the ref alone.
/// 2. Hostname is unambiguously local: `localhost`, `127.0.0.1`,
///    `0.0.0.0`, `*.local`, `*.localhost`.
///
/// The microsandbox SDK's `.insecure()` switches to plain HTTP, so
/// applying it to ghcr.io or any other public HTTPS registry would
/// break the pull. The heuristic stays narrow for safety; the env
/// var is the operator-blessed override.
///
/// IPv6 literal hosts are not supported here (rare for local dev
/// registries; bracketed form would need a real parser). Use
/// `localhost` or `127.0.0.1` instead.
pub(crate) fn is_plain_http_registry(image_ref: &str) -> bool {
    if crate::env_flag::enabled("AGENT_VM_INSECURE_REGISTRY") {
        return true;
    }
    // First path segment is the registry host (with optional :port).
    // If there's no `/` in the ref OR the first segment has no `.` /
    // `:` / `localhost`, the ref points at docker.io's default
    // registry and we never want insecure for that.
    let first = image_ref.split('/').next().unwrap_or("");
    // Strip the port suffix to get just the host.
    let host = first.split(':').next().unwrap_or("");
    matches!(host, "localhost" | "127.0.0.1" | "0.0.0.0")
        || host.ends_with(".local")
        || host.ends_with(".localhost")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot_image::{ImageArgs, OverrideSource};

    #[test]
    fn local_registries_are_plain_http() {
        assert!(is_plain_http_registry("localhost:5000/standard:test"));
        assert!(is_plain_http_registry("127.0.0.1:5000/x"));
        assert!(is_plain_http_registry("0.0.0.0:8080/x"));
        assert!(is_plain_http_registry("dev.local/x"));
        assert!(is_plain_http_registry("foo.localhost:5000/x"));
    }

    #[test]
    fn public_registries_are_not_plain_http() {
        assert!(!is_plain_http_registry(
            "ghcr.io/gregwebs/agent-vm-standard:v0.1.3"
        ));
        assert!(!is_plain_http_registry("docker.io/library/debian:13"));
        assert!(!is_plain_http_registry("registry.example.com/x"));
        // Docker Hub short form has no `/` in the registry part.
        assert!(!is_plain_http_registry("nginx:latest"));
    }

    // Single test exercising the env-var escape hatch in both directions —
    // the heuristic says "secure" for `registry.corp.example` but a truthy
    // env override wins, while a falsy/unrecognised value must not (the
    // fail-closed direction, issue #65). Both directions live in one test
    // (rather than two) because `test_env::guard()` serializes across the
    // whole crate on a single mutex — splitting them would just make two
    // tests take turns for no benefit.
    #[test]
    fn env_override_forces_plain_http() {
        let mut env = crate::test_env::guard();
        env.set_var("AGENT_VM_INSECURE_REGISTRY", "1");
        assert!(is_plain_http_registry("registry.corp.example:5000/x"));
        assert!(is_plain_http_registry(
            "ghcr.io/gregwebs/agent-vm-standard:v0.1.3"
        ));
        env.remove_var("AGENT_VM_INSECURE_REGISTRY");
        // After cleanup the heuristic resumes its normal behaviour.
        assert!(!is_plain_http_registry("registry.corp.example:5000/x"));

        // Fail-closed direction: an explicit falsy value (or a typo that
        // isn't in `env_flag::TRUTHY`) must not be coerced into "insecure"
        // — the widened accepted set only adds new spellings of an opt-in,
        // never a new way to opt in by accident.
        for falsy in ["0", ""] {
            env.set_var("AGENT_VM_INSECURE_REGISTRY", falsy);
            assert!(
                !is_plain_http_registry("registry.corp.example:5000/x"),
                "{falsy:?} must not force plain HTTP"
            );
        }
        env.remove_var("AGENT_VM_INSECURE_REGISTRY");
    }

    fn args_with(value: Option<&str>) -> Args {
        Args {
            image: ImageArgs::for_test(
                value.map(str::to_string),
                value.map(|_| OverrideSource::CommandLine),
            ),
        }
    }

    #[test]
    fn preflight_refuses_local_targets_and_accepts_oci_references() {
        assert!(preflight(&args_with(None)).is_ok());
        assert!(preflight(&args_with(Some("alpine:latest"))).is_ok());
        for local in ["/abs/rootfs", "./rootfs", "..", "/tmp/img.disk"] {
            let error = preflight(&args_with(Some(local))).unwrap_err();
            assert_eq!(error.to_string(), TARGET_REASON);
            assert!(error.to_string().contains("agent-vm --image PATH <tool>"));
            assert!(!error.to_string().contains(local));
        }
        // A malformed reference is not a local launch target and must get the
        // reference-shape refusal instead of local-launch advice.
        for malformed in ["Foo/Bar:tag", "repo:bad tag", "repo@sha256:short"] {
            let error = preflight(&args_with(Some(malformed))).unwrap_err();
            assert_eq!(error.to_string(), INVALID_REFERENCE_REASON);
            assert!(!error.to_string().contains("agent-vm --image PATH <tool>"));
            assert!(!error.to_string().contains(malformed));
        }
    }

    #[test]
    fn redacted_coordination_and_task_failures_keep_actionable_stages() {
        use crate::image_acquire::ReferenceStage;

        let label = boot_image::ImageLabel::for_default_upgrade();
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
            let error = acquisition_error(
                &label,
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
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let join = runtime.block_on(async {
            tokio::spawn(async { panic!("private source") })
                .await
                .unwrap_err()
        });
        let error = acquisition_error(&label, sentinel, AcquireError::Task(join));
        let text = format!("{error:#}");
        assert!(text.contains("publication is uncertain"), "{text}");
        assert!(text.contains("check the cache and retry"), "{text}");
        assert!(!text.contains("private source"), "{text}");
    }

    #[test]
    fn preflight_refuses_a_typed_empty_target() {
        let error = preflight(&args_with(Some(""))).unwrap_err();
        assert!(error.to_string().contains("must not be empty"), "{error}");
    }
}
