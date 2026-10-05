//! Resolve optional image capabilities after the sandbox is booted.
//!
//! Capabilities are *supplied artifacts*, not image identity or lineage: an
//! image that carries the Chrome DevTools capability marker, or supplies the
//! wrapper on its own, opts in; every other image (including a minimal one with
//! no `/etc/agent-vm-image-version`) simply gets the launcher-owned MCP entry
//! removed and boots normally. A probe error disables the optional integration
//! for this session rather than rejecting the image (#258).

use microsandbox::Sandbox;
use vstd::prelude::*;

use crate::defaults::{CHROME_MCP_CAPABILITY_PATH, CHROME_MCP_WRAPPER_PATH};

verus! {

#[derive(Debug, Clone, Copy, PartialEq, Eq, Structural)]
enum ChromeMcpDecision {
    /// The image advertises the capability explicitly.
    Advertised,
    /// The image supplies the wrapper without the explicit marker.
    WrapperProvided,
    /// Neither artifact is present; the integration stays inert.
    Unavailable,
    /// The user opted out; nothing is probed.
    OptedOut,
}

impl ChromeMcpDecision {
    fn enabled(self) -> (r: bool)
        ensures r == (self == ChromeMcpDecision::WrapperProvided
                   || self == ChromeMcpDecision::Advertised),
    {
        matches!(self, Self::WrapperProvided | Self::Advertised)
    }
}

/// Precedence is total: exactly one arm applies to every input, `OptedOut`
/// dominates, nothing else can produce `OptedOut`, and either supplied artifact
/// enables — with the marker taking precedence over the wrapper (`advertised`
/// wins when both are present).
fn chrome_mcp_policy(advertised: bool, wrapper_present: bool, opted_out: bool)
    -> (d: ChromeMcpDecision)
    ensures
        opted_out ==> d == ChromeMcpDecision::OptedOut,
        d == ChromeMcpDecision::OptedOut ==> opted_out,
        !opted_out && advertised ==> d == ChromeMcpDecision::Advertised,
        !opted_out && !advertised && wrapper_present
            ==> d == ChromeMcpDecision::WrapperProvided,
        !opted_out && !advertised && !wrapper_present
            ==> d == ChromeMcpDecision::Unavailable,
{
    if opted_out {
        ChromeMcpDecision::OptedOut
    } else if advertised {
        ChromeMcpDecision::Advertised
    } else if wrapper_present {
        ChromeMcpDecision::WrapperProvided
    } else {
        ChromeMcpDecision::Unavailable
    }
}

} // verus!

/// Resolve whether the launcher-owned Chrome MCP entry belongs in state.
///
/// A probe failure disables the optional integration for this session: the
/// production helper logs the error, and the resolver returns a disabled
/// decision without probing further, so a "disabling" warning is never followed
/// by an enabled result.
pub async fn chrome_mcp_enabled(sandbox: &Sandbox, image_label: &str, opted_out: bool) -> bool {
    resolve_chrome_mcp_probes(
        opted_out,
        || guest_file_present(sandbox, image_label, CHROME_MCP_CAPABILITY_PATH),
        || guest_file_present(sandbox, image_label, CHROME_MCP_WRAPPER_PATH),
    )
    .await
}

/// The probe control flow, split from the RPC so tests can count probes and
/// inject errors. Opt-out probes nothing; the marker is probed first and only
/// its absence probes the wrapper; either error disables the integration.
async fn resolve_chrome_mcp_probes<MarkerProbe, WrapperProbe, MarkerFut, WrapperFut>(
    opted_out: bool,
    marker_probe: MarkerProbe,
    wrapper_probe: WrapperProbe,
) -> bool
where
    MarkerProbe: FnOnce() -> MarkerFut,
    WrapperProbe: FnOnce() -> WrapperFut,
    MarkerFut: std::future::Future<Output = microsandbox::MicrosandboxResult<bool>>,
    WrapperFut: std::future::Future<Output = microsandbox::MicrosandboxResult<bool>>,
{
    if opted_out {
        return chrome_mcp_policy(false, false, true).enabled();
    }
    let advertised = match marker_probe().await {
        Ok(present) => present,
        // Unavailable: `chrome_mcp_policy` with no artifact supplied.
        Err(_) => return chrome_mcp_policy(false, false, false).enabled(),
    };
    if advertised {
        return chrome_mcp_policy(true, false, false).enabled();
    }
    // A wrapper-probe error disables the integration for this session, exactly
    // like an absent wrapper (`unwrap_or_default`); `chrome_mcp_policy` never
    // converts a failed optional probe into an enable.
    let wrapper_present = wrapper_probe().await.unwrap_or_default();
    chrome_mcp_policy(false, wrapper_present, false).enabled()
}

/// Raw artifact probe. Returns the RPC result unchanged — collapsing an error
/// to `false` here would hide it from the caller's disable decision.
async fn guest_file_present(
    sandbox: &Sandbox,
    image_label: &str,
    path: &str,
) -> microsandbox::MicrosandboxResult<bool> {
    sandbox.fs().exists(path).await.map_err(|error| {
        // `image_label` is the selection's safe name (an escaped explicit
        // reference, or the fixed default-tier label), never a raw record value.
        tracing::warn!(
            image = image_label,
            capability_path = path,
            error = %error,
            "unable to probe optional image capability; disabling launcher-owned MCP entry"
        );
        error
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::future::{Future, ready};

    type ProbeResult = microsandbox::MicrosandboxResult<bool>;

    /// The exact decision table: opt-out dominates, a marker enables, a supplied
    /// wrapper enables when there is no marker, and neither artifact leaves the
    /// integration inert. All eight input rows are explicit.
    #[test]
    fn decision_table_covers_all_inputs() {
        let table: [(bool, bool, bool, ChromeMcpDecision); 8] = [
            (false, false, false, ChromeMcpDecision::Unavailable),
            (false, true, false, ChromeMcpDecision::WrapperProvided),
            (true, false, false, ChromeMcpDecision::Advertised),
            (true, true, false, ChromeMcpDecision::Advertised),
            (false, false, true, ChromeMcpDecision::OptedOut),
            (false, true, true, ChromeMcpDecision::OptedOut),
            (true, false, true, ChromeMcpDecision::OptedOut),
            (true, true, true, ChromeMcpDecision::OptedOut),
        ];
        for (advertised, wrapper_present, opted_out, expected) in table {
            assert_eq!(
                chrome_mcp_policy(advertised, wrapper_present, opted_out),
                expected,
                "advertised={advertised} wrapper={wrapper_present} opted_out={opted_out}"
            );
        }
    }

    #[test]
    fn only_supplied_artifacts_enable() {
        assert!(chrome_mcp_policy(true, false, false).enabled());
        assert!(chrome_mcp_policy(false, true, false).enabled());
        assert!(!chrome_mcp_policy(false, false, false).enabled());
        assert!(!chrome_mcp_policy(false, true, true).enabled());
    }

    fn counted(value: bool, calls: &Cell<usize>) -> impl Future<Output = ProbeResult> {
        calls.set(calls.get() + 1);
        ready(Ok(value))
    }

    fn failing(calls: &Cell<usize>) -> impl Future<Output = ProbeResult> {
        calls.set(calls.get() + 1);
        ready(Err(microsandbox::MicrosandboxError::InvalidConfig(
            "probe failed".to_string(),
        )))
    }

    #[tokio::test]
    async fn opt_out_probes_neither_artifact() {
        let marker = Cell::new(0usize);
        let wrapper = Cell::new(0usize);
        let enabled =
            resolve_chrome_mcp_probes(true, || counted(true, &marker), || counted(true, &wrapper))
                .await;
        assert!(!enabled);
        assert_eq!(marker.get(), 0, "opt-out must not probe the marker");
        assert_eq!(wrapper.get(), 0, "opt-out must not probe the wrapper");
    }

    #[tokio::test]
    async fn marker_success_skips_wrapper_probe() {
        let marker = Cell::new(0usize);
        let wrapper = Cell::new(0usize);
        let enabled = resolve_chrome_mcp_probes(
            false,
            || counted(true, &marker),
            || counted(false, &wrapper),
        )
        .await;
        assert!(enabled);
        assert_eq!(marker.get(), 1);
        assert_eq!(
            wrapper.get(),
            0,
            "a present marker must skip the wrapper probe"
        );
    }

    #[tokio::test]
    async fn marker_absent_probes_wrapper() {
        let marker = Cell::new(0usize);
        let wrapper = Cell::new(0usize);
        let enabled = resolve_chrome_mcp_probes(
            false,
            || counted(false, &marker),
            || counted(true, &wrapper),
        )
        .await;
        assert!(enabled, "a supplied wrapper enables without the marker");
        assert_eq!(wrapper.get(), 1);
    }

    #[tokio::test]
    async fn marker_error_never_probes_wrapper() {
        let marker = Cell::new(0usize);
        let wrapper = Cell::new(0usize);
        let enabled =
            resolve_chrome_mcp_probes(false, || failing(&marker), || counted(true, &wrapper)).await;
        assert!(!enabled);
        assert_eq!(wrapper.get(), 0, "a failed marker probe must not continue");
    }

    #[tokio::test]
    async fn wrapper_error_disables() {
        let marker = Cell::new(0usize);
        let wrapper = Cell::new(0usize);
        let enabled =
            resolve_chrome_mcp_probes(false, || counted(false, &marker), || failing(&wrapper))
                .await;
        assert!(!enabled);
        assert_eq!(
            wrapper.get(),
            1,
            "the wrapper probe must run before it fails"
        );
    }
}
