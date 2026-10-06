//! Deliberate acquisition followed by publication of a user-owned default.
//! Two native pulls populate the canonical digest cache key without inventing
//! aliases; acquisition never holds the selection lock or creates a VM.

use std::io::Write;
use std::str::FromStr;

use anyhow::{Result, anyhow};
use microsandbox_image::{
    GlobalCache, ImageError, Platform, PullOptions, PullPolicy, PullResult, Reference, Registry,
};
use serde::Deserialize;
use vstd::prelude::*;

use super::{
    AcquiredDefaultImage, DefaultUpgradeOutcome, ImageLabel, ImageRef, ImmutableImageRef,
    default_selection,
};

const TARGET_REASON: &str = "upgrade targets must be OCI image references (tag or digest); use shell --image for a local rootfs launch";

#[derive(clap::Args)]
pub(crate) struct Args {
    /// OCI image to acquire and retain for future default-image sessions.
    #[arg(long = "image", value_name = "REF")]
    target: UpgradeTarget,
}

#[derive(Clone)]
struct UpgradeTarget(ImageRef);

impl FromStr for UpgradeTarget {
    type Err = &'static str;

    fn from_str(raw: &str) -> std::result::Result<Self, Self::Err> {
        ImageRef::from_config(raw)
            .map(Self)
            .map_err(|_| TARGET_REASON)
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

async fn acquire_target(target: &UpgradeTarget) -> Result<AcquiredDefaultImage> {
    let native_target =
        Reference::from_str(target.0.as_str()).map_err(|_| anyhow!(TARGET_REASON))?;
    let backend = microsandbox::backend::default_backend();
    let local = backend.as_local().ok_or_else(|| anyhow!(
        "default-image upgrade requires the local image cache; unset the cloud backend selection; this command did not change the retained default"
    ))?;
    let cache = GlobalCache::new(&local.cache_dir())
        .map_err(|error| native_error("preparing the native cache", error))?;
    let options = microsandbox::config::RegistryOptions {
        insecure: crate::pull::is_plain_http_registry(target.0.as_str()),
        ..Default::default()
    };
    let settings = local.registry_config(native_target.registry(), options).await.map_err(|_| anyhow!(
        "resolving registry trust/auth configuration failed; this command did not change the retained default"
    ))?;
    let registry = Registry::builder(Platform::host_linux(), cache.clone())
        .auth(settings.auth)
        .extra_ca_certs(settings.ca_certs)
        .add_insecure_registries(settings.insecure_registries)
        .build()
        .map_err(|error| native_error("preparing registry access", error))?;
    let label = ImageLabel::for_default_upgrade();
    let resolved = pull_native(&registry, &native_target, &label).await?;
    let pinned_native = pin_reference(&native_target, &resolved);
    let pin = ImmutableImageRef::parse(&pinned_native.whole()).map_err(|_| anyhow!(
        "the acquired image did not yield a usable immutable reference; this command did not change the retained default"
    ))?;
    let acquired = pull_native(&registry, &pinned_native, &label).await?;
    if acquired.manifest_digest != resolved.manifest_digest {
        return Err(identity_error());
    }
    let (_, metadata) = Registry::pull_cached(
        &cache,
        &pinned_native,
        &PullOptions {
            pull_policy: PullPolicy::Never,
            force: false,
            ..Default::default()
        },
    )
    .map_err(|error| native_error("validating the pinned native cache", error))?
    .ok_or_else(identity_error)?;
    if metadata.manifest_digest != resolved.manifest_digest.to_string() {
        return Err(identity_error());
    }
    check_host_platform(&metadata.raw_config_json)?;
    Ok(AcquiredDefaultImage { reference: pin })
}

fn pin_reference(target: &Reference, resolved: &PullResult) -> Reference {
    Reference::with_digest(
        target.registry().to_owned(),
        target.repository().to_owned(),
        resolved.manifest_digest.to_string(),
    )
}

fn identity_error() -> anyhow::Error {
    anyhow!(
        "validating the pinned native cache failed: immutable identity or complete cache unavailable; this command did not change the retained default"
    )
}

async fn pull_native(
    registry: &Registry,
    reference: &Reference,
    label: &ImageLabel,
) -> Result<PullResult> {
    let (progress, task) = registry.pull_with_progress(
        reference,
        &PullOptions {
            pull_policy: PullPolicy::Always,
            force: false,
            ..Default::default()
        },
    );
    let render = tokio::spawn(crate::pull_progress::render(
        progress,
        Some(label.text().to_string()),
    ));
    let result = task.await.map_err(|_| anyhow!(
        "acquiring the requested default boot image failed: native task failed; this command did not change the retained default"
    )).and_then(|result| result.map_err(|error| native_error("acquiring the requested default boot image", error)));
    crate::pull_progress::await_render(render).await;
    result
}

fn native_error(stage: &str, error: ImageError) -> anyhow::Error {
    let category = match error {
        ImageError::Registry(_) => "registry reachability/auth/availability",
        ImageError::PlatformNotFound { .. } => "no host platform",
        ImageError::ManifestParse(_) | ImageError::ConfigParse(_) => "invalid OCI metadata",
        ImageError::DigestMismatch { .. } => "layer integrity failure",
        ImageError::Materialize { .. } | ImageError::Cache { .. } | ImageError::Io(_) => {
            "materialization/cache I/O"
        }
        ImageError::InvalidCertificate(_) => "invalid trust configuration",
        _ => "native image validation failure",
    };
    anyhow!("{stage} failed: {category}; this command did not change the retained default")
}

#[derive(Deserialize)]
struct ConfigPlatform {
    os: String,
    architecture: String,
    variant: Option<String>,
}

fn check_host_platform(raw_config: &str) -> Result<()> {
    let config: ConfigPlatform = serde_json::from_str(raw_config).map_err(|_| anyhow!(
        "acquired image platform metadata is invalid; this command did not change the retained default"
    ))?;
    let host = Platform::host_linux();
    if !acquired_platform_is_acceptable(PlatformFacts {
        os_matches: config.os == host.os.to_string(),
        arch_matches: config.architecture == host.arch.to_string(),
        variant_matches: host
            .variant
            .as_ref()
            .is_none_or(|variant| config.variant.as_ref() == Some(variant)),
    }) {
        return Err(anyhow!(
            "acquired image platform does not match host Linux; this command did not change the retained default"
        ));
    }
    Ok(())
}

verus! {
struct PlatformFacts {
    os_matches: bool,
    arch_matches: bool,
    variant_matches: bool,
}

fn acquired_platform_is_acceptable(facts: PlatformFacts) -> (accepted: bool)
    ensures accepted == (facts.os_matches && facts.arch_matches && facts.variant_matches)
{
    facts.os_matches && facts.arch_matches && facts.variant_matches
}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_pin_preserves_normalized_repository_and_child_identity() {
        let child = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let config = microsandbox_image::ImageConfig::parse(
            br#"{"os":"linux","architecture":"arm64","rootfs":{"type":"layers","diff_ids":[]}}"#,
        )
        .unwrap()
        .0;
        let resolved = PullResult {
            layer_diff_ids: vec![],
            config,
            manifest_digest: child.parse().unwrap(),
            cached: false,
        };
        for (input, expected_repo) in [
            ("localhost:1234/a:tag", "a"),
            ("alpine:latest", "library/alpine"),
            (
                "localhost:1234/a@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "a",
            ),
        ] {
            let target: Reference = input.parse().unwrap();
            let pin = pin_reference(&target, &resolved);
            assert_eq!(pin.registry(), target.registry());
            assert_eq!(pin.repository(), expected_repo);
            assert_eq!(pin.digest(), Some(child));
            assert!(pin.tag().is_none());
            assert!(ImmutableImageRef::parse(&pin.whole()).is_ok());
        }
    }

    #[test]
    fn targets_are_oci_only_with_upgrade_specific_safe_advice() {
        for raw in [
            "alpine:latest",
            "localhost:1234/a:release",
            "repo@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert!(raw.parse::<UpgradeTarget>().is_ok());
        }
        for raw in [
            "",
            "/private/path",
            "./rootfs",
            "..",
            "repo\nsecret",
            "repo\u{1b}",
        ] {
            let error = raw.parse::<UpgradeTarget>().err().unwrap();
            assert_eq!(error, TARGET_REASON);
            assert!(error.contains("shell --image"));
            if !raw.is_empty() {
                assert!(!error.contains(raw));
            }
        }
    }

    #[test]
    fn platform_facts_require_every_conjunct() {
        for bits in 0..8 {
            let os = bits & 1 != 0;
            let arch = bits & 2 != 0;
            let variant = bits & 4 != 0;
            assert_eq!(
                acquired_platform_is_acceptable(PlatformFacts {
                    os_matches: os,
                    arch_matches: arch,
                    variant_matches: variant
                }),
                bits == 7
            );
        }
    }

    #[test]
    fn raw_config_platform_is_required_and_host_linux() {
        let host = Platform::host_linux();
        let valid = serde_json::json!({"os":host.os.to_string(), "architecture":host.arch.to_string(), "unrelated":true});
        assert!(check_host_platform(&valid.to_string()).is_ok());
        // Native host_linux has no variant constraint; optional config variant is allowed.
        assert!(check_host_platform(&serde_json::json!({"os":"linux", "architecture":host.arch.to_string(), "variant":"v8"}).to_string()).is_ok());
        for raw in [
            "{}",
            "{\"os\":\"linux\"}",
            "{\"os\":7,\"architecture\":\"private-marker\"}",
            "{\"os\":\"linux\",\"os\":\"linux\",\"architecture\":\"amd64\"}",
        ] {
            let error = check_host_platform(raw).unwrap_err();
            assert!(error.to_string().contains("metadata is invalid"));
            assert!(!format!("{error:#}").contains("private-marker"));
        }
        for (os, arch) in [
            ("windows", host.arch.to_string()),
            ("linux", "foreign".to_string()),
        ] {
            assert!(
                check_host_platform(&serde_json::json!({"os":os,"architecture":arch}).to_string())
                    .is_err()
            );
        }
    }
}
