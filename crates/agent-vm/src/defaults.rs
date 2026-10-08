//! Module-level constants for distribution-shaped defaults.
//!
//! Kept in one place so a release can re-point the image registry,
//! or change other distribution wiring
//! without grepping for string literals across subcommands.

/// The **initial default-image recommendation**: the immutable image agent-vm
/// offers when no `--image`, `AGENT_VM_IMAGE_TAG`, user config, project config
/// `image` or retained user selection names another.
///
/// It is a *recommendation*, not a selection: the launcher's owned state is the
/// user-scoped retained record ([`crate::boot_image`]), written only after this
/// image has actually been acquired. Changing this constant changes what a user
/// with no record is offered; it never rewrites an existing retained selection.
///
/// The released v0.1.3 multiarch index names immutable content; native msb
/// chooses the Linux child for the host architecture. Image and launcher
/// versions are independent. Changing this recommendation never replaces a
/// retained record.
pub const INITIAL_DEFAULT_IMAGE_REF: &str = "ghcr.io/gregwebs/agent-vm-standard@sha256:04701db70ef6c2c75078ca39a85ce4b4c15b04cacfea47836c2e5d113c4d42de";

/// Marker written last by the Chrome DevTools image after its checks pass.
pub const CHROME_MCP_CAPABILITY_PATH: &str = "/etc/agent-vm-capabilities/chrome-devtools-mcp";

/// Path of the in-guest Chrome DevTools MCP wrapper an image supplies as an
/// ordinary runtime capability. Unlike the capability marker, its presence is
/// read as capability evidence on its own, not as image identity (#258). One
/// source of truth: the capability probe (`image_capabilities`) and the entry
/// the launcher writes (`secrets::chrome_mcp_entry`) must name the same path.
pub const CHROME_MCP_WRAPPER_PATH: &str = "/usr/local/bin/agent-vm-chrome-mcp";

/// Writable OCI-upper capacity for every sandbox, in mebibytes.
///
/// v0.6.15 unified the writable overlay for an OCI rootfs into
/// `SandboxBuilder::root_disk()` (the pre-0.6.0 `oci_upper_size()` alias is
/// `#[deprecated]` and just forwards to it — see `run.rs`'s boot builder).
/// Passed explicitly (AC#3 of agent-vm issue #40) rather than relying on the
/// SDK's own default, so a release can retune capacity by editing this one
/// constant. 16 GiB preserves the headroom the pre-migration `gw` fork's
/// hard-coded ext4-overlay-size patch gave every sandbox.
pub const WRITABLE_UPPER_MIB: u32 = 16 * 1024;

#[cfg(test)]
mod tests {
    #[derive(serde::Deserialize)]
    struct ReleasePin {
        version: String,
        source_sha: String,
        index_digest: String,
        platforms: Vec<PlatformPin>,
    }

    #[derive(serde::Deserialize)]
    struct PlatformPin {
        graph: GraphPin,
    }

    #[derive(serde::Deserialize)]
    struct GraphPin {
        os: String,
        architecture: String,
        manifest: DescriptorPin,
    }

    #[derive(serde::Deserialize)]
    struct DescriptorPin {
        digest: String,
    }

    #[test]
    fn initial_recommendation_matches_released_multiarch_index() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/standard-release/release.json");
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        let pin: ReleasePin = serde_json::from_str(&raw).unwrap();
        assert_eq!(pin.version, "0.1.3");
        assert_eq!(pin.source_sha, "087f8bad3de624a5dad38f1669e7dea96996371a");
        assert_eq!(
            super::INITIAL_DEFAULT_IMAGE_REF,
            format!("ghcr.io/gregwebs/agent-vm-standard@{}", pin.index_digest)
        );
        let mut platforms: Vec<_> = pin
            .platforms
            .iter()
            .map(|p| {
                assert_eq!(p.graph.os, "linux");
                assert_ne!(p.graph.manifest.digest, pin.index_digest);
                (
                    p.graph.architecture.as_str(),
                    p.graph.manifest.digest.as_str(),
                )
            })
            .collect();
        platforms.sort_unstable();
        assert_eq!(
            platforms,
            vec![
                (
                    "amd64",
                    "sha256:b10203f2e4511b7501235f4329c4cf71186b2e46373897407c0eb9604689b582"
                ),
                (
                    "arm64",
                    "sha256:bbfd3732893d5f76eb3dfd3d2e5f7779982b98adaa0be6b73be8084300f88a3b"
                ),
            ]
        );
    }
}
