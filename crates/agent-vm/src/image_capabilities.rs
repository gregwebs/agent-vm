//! Resolve optional image capabilities after the sandbox is booted.

use microsandbox::Sandbox;

use crate::defaults::{CHROME_MCP_CAPABILITY_PATH, FIRST_ADVERTISED_CAPABILITIES_IMAGE_API};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChromeMcpDecision {
    Legacy,
    Advertised,
    Unavailable,
    OptedOut,
}

impl ChromeMcpDecision {
    fn enabled(self) -> bool {
        matches!(self, Self::Legacy | Self::Advertised)
    }
}

fn chrome_mcp_policy(image_api: u32, marker_present: bool, opted_out: bool) -> ChromeMcpDecision {
    if opted_out {
        ChromeMcpDecision::OptedOut
    } else if image_api < FIRST_ADVERTISED_CAPABILITIES_IMAGE_API {
        ChromeMcpDecision::Legacy
    } else if marker_present {
        ChromeMcpDecision::Advertised
    } else {
        ChromeMcpDecision::Unavailable
    }
}

/// Resolve whether the launcher-owned Chrome MCP entry belongs in state.
/// API 1 predates advertised capabilities and promised Chrome implicitly.
pub async fn chrome_mcp_enabled(
    sandbox: &Sandbox,
    image: &str,
    image_api: u32,
    opted_out: bool,
) -> bool {
    if opted_out || image_api < FIRST_ADVERTISED_CAPABILITIES_IMAGE_API {
        return chrome_mcp_policy(image_api, false, opted_out).enabled();
    }

    match sandbox.fs().exists(CHROME_MCP_CAPABILITY_PATH).await {
        Ok(marker_present) => chrome_mcp_policy(image_api, marker_present, false).enabled(),
        Err(error) => {
            tracing::warn!(
                image,
                image_api,
                marker_path = CHROME_MCP_CAPABILITY_PATH,
                error = %error,
                "unable to probe Chrome DevTools capability; disabling launcher-owned MCP entry"
            );
            chrome_mcp_policy(image_api, false, false).enabled()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_api_is_available_without_marker() {
        assert_eq!(chrome_mcp_policy(1, false, false), ChromeMcpDecision::Legacy);
    }

    #[test]
    fn advertised_apis_require_marker() {
        assert_eq!(chrome_mcp_policy(2, false, false), ChromeMcpDecision::Unavailable);
        assert_eq!(chrome_mcp_policy(3, false, false), ChromeMcpDecision::Unavailable);
        assert_eq!(chrome_mcp_policy(2, true, false), ChromeMcpDecision::Advertised);
    }

    #[test]
    fn opt_out_wins() {
        assert_eq!(chrome_mcp_policy(1, true, true), ChromeMcpDecision::OptedOut);
        assert_eq!(chrome_mcp_policy(3, true, true), ChromeMcpDecision::OptedOut);
    }
}
