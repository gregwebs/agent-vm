//! Module-level constants for distribution-shaped defaults.
//!
//! Kept in one place so a release can re-point the image registry,
//! or change other distribution wiring
//! without grepping for string literals across subcommands.

/// Default OCI image reference. This is the **composed default guest
/// template**: the tool-free base plus the six built-in tool layers,
/// chained in declaration order by CI (`images/Dockerfile` +
/// `images/tools/`). agent-vm boots it *verbatim* — no local build, no
/// Docker — when the resolved tool set's declared layer sequence equals
/// the shipped default (`tool_layer::chain_root`'s fast path).
///
/// Overridable per-subcommand via `--image` or the `AGENT_VM_IMAGE_TAG`
/// env var; `--image` boots an image verbatim and skips tool-layer
/// composition. Pulled fresh on `agent-vm setup` / `agent-vm pull`; uses
/// the cached copy otherwise.
///
/// Tags published by CI:
/// - `:latest` — moving tag, rebuilt hourly to pick up agent
///   updates (Claude Code, OpenCode, Codex etc.).
/// - `:YYYY-MM-DDTHH` — timestamped, immutable. Use for
///   reproducible setups.
pub const DEFAULT_IMAGE_REF: &str = "ghcr.io/wirenboard/agent-vm-template:latest";

/// The tool-free base every locally composed tool chain builds `FROM`.
/// Overridable with `--base-image` / `AGENT_VM_BASE_IMAGE`; passing it
/// always forces local composition, even for the shipped default tool set.
///
/// NOTE: a *published registry repository*, unrelated to `layer::BASE_REPO`,
/// which is the Docker-local link namespace `agent-vm-base:<manifest-hex>`
/// minted by `script/build/import-image.sh`. The names coincide by intent
/// but never collide: a link tag is always 64 hex characters.
pub const DEFAULT_BASE_IMAGE_REF: &str = "ghcr.io/wirenboard/agent-vm-base:latest";

/// Marker written last by the Chrome DevTools tooling layer after its checks pass.
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
