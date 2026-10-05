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
/// The value is pinned by digest because a mutable tag cannot name exact
/// content: `:latest` is rebuilt hourly, so `:latest` today and `:latest` after
/// a cache loss are different bytes. These are **existing published bytes of the
/// old `agent-vm-template`** — a single `application/vnd.oci.image.manifest.v1+json`
/// for Linux/amd64, not a multiarch index, and not the maintained multiarch
/// release. It is an interim development recommendation only: #265 owns pinning
/// and validating the production recommendation against real artifact
/// consumption. Because selection is success-before-adoption, a host that
/// cannot acquire it (e.g. Apple Silicon) keeps no record and a later compatible
/// recommendation rescues the user.
pub const INITIAL_DEFAULT_IMAGE_REF: &str = "ghcr.io/wirenboard/agent-vm-template@sha256:fd05aaa697c2488e9f7384d069ba2244078faf6b5320998b546c93f98f8d5f18";

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
    use std::cmp::Ordering;

    /// The interlock that stops CI promoting a `:latest` image before an
    /// API-3-capable launcher is on npm (issue #84 §5.4). The file must parse
    /// as a plain `major.minor.patch` semver and must name no version newer
    /// than this crate — a version that does not exist yet would block `:latest`
    /// promotion forever (`script/check-image-promotion-gate.sh`).
    ///
    /// Deliberately **not** equality: `images/min-agent-vm-version` is decoupled
    /// from `CARGO_PKG_VERSION` on purpose, and `CONTRIBUTING.md` makes every
    /// feature PR bump the workspace version, so equality would force every PR
    /// to advance the promotion floor and block the hourly pipeline after every
    /// merge.
    #[test]
    fn min_agent_vm_version_is_a_semver_no_newer_than_this_crate() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../images/min-agent-vm-version");
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        let min = raw.trim();
        let min_parts = parse_semver(min);
        let crate_parts = parse_semver(env!("CARGO_PKG_VERSION"));
        assert_ne!(
            compare(min_parts, crate_parts),
            Ordering::Greater,
            "images/min-agent-vm-version {min} is newer than the crate version {}; \
             CI would block :latest promotion until that version reaches npm",
            env!("CARGO_PKG_VERSION")
        );
    }

    fn parse_semver(s: &str) -> [u64; 3] {
        let parts: Vec<&str> = s.split('.').collect();
        assert_eq!(parts.len(), 3, "not a major.minor.patch version: {s:?}");
        let mut out = [0u64; 3];
        for (slot, part) in out.iter_mut().zip(parts) {
            *slot = part
                .parse()
                .unwrap_or_else(|_| panic!("non-numeric semver component {part:?} in {s:?}"));
        }
        out
    }

    fn compare(a: [u64; 3], b: [u64; 3]) -> Ordering {
        a.cmp(&b)
    }
}
