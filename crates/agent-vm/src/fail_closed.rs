//! Fail-closed guard for credential injection, the one fork-only feature
//! still deferred after agent-vm issue #47.
//!
//! Issue #40 originally fail-closed four fork-only features that had no
//! equivalent on the clean Microsandbox v0.6.15 baseline: guest egress via
//! a host HTTP-CONNECT proxy, `--auto-publish`, CIDR/group egress
//! overrides, and host-credential injection. Issue #47 adopted
//! `gregwebs/microsandbox` `origin/main` into the vendored
//! `integration/v0.6.15-agent-vm` line, which supplies baseline
//! implementations of the first three (`HostHttpProxyConnector::from_env()`,
//! `NetworkBuilder::auto_publish()`, and `NetworkPolicy::from_profiles`/
//! `Rule::allow_egress`) — see `network::Plan` in `network.rs` for their
//! CLI translation, builder application, and launch reporting.
//!
//! Credential injection is the one guard that remains. The baseline now
//! *has* the building blocks (file-backed `SecretSource` and
//! `NetworkBuilder::intercept()`), but agent-vm's `secrets.rs`/
//! `intercept_hook.rs` are not yet wired onto them — that rewiring is
//! sized as its own PR (gregwebs/agent-vm#51), preserving the fork's
//! per-connection token-rotation, OAuth-refresh, and GitHub REST
//! path-scoping guarantees rather than risk a silent downgrade (e.g. baking
//! a credential file's current contents into a static value that never
//! rotates and can leak a stale token). This module is that fail-closed
//! boundary until #51 lands.

use anyhow::{Result, bail};

use crate::run::Agent;

/// Whether the selected agent inherently needs a provider/GitHub
/// credential to function, independent of whether the user asked for
/// GitHub access or host egress.
///
/// `Shell` never automatically speaks to Anthropic/OpenAI/GitHub/Copilot
/// on the guest's behalf — a plain `agent-vm shell` launch has no
/// contractual need for host credential injection, so it's the one case
/// where [`check_credential_injection_unneeded`] can pass even when the
/// host happens to have cached credentials.
pub fn agent_requires_credentials(agent: Agent) -> bool {
    !matches!(agent, Agent::Shell)
}

/// Fails closed if this launch has both a captured host credential file
/// and an actual need to inject it into the guest.
///
/// `has_creds` alone (a credential file happens to exist on the host) is
/// not sufficient to fail closed — `agent-vm shell --no-git` must keep
/// booting on any real developer machine regardless of what's cached.
/// Injection is only "needed" when the launch isn't `--no-git` (normal
/// GitHub auto-detection is active), or the selected agent inherently
/// needs a provider credential (see [`agent_requires_credentials`]). Only
/// in that case does skipping injection constitute the silent security
/// weakening AC#5 forbids; otherwise it's simply unused credential
/// material this launch never asked to use.
pub fn check_credential_injection_unneeded(has_creds: bool, needs_injection: bool) -> Result<()> {
    if has_creds && needs_injection {
        bail!(
            "host credential injection (Anthropic/OpenAI/GitHub/Copilot token substitution) is \
             not yet wired into agent-vm: the baseline now has file-backed SecretSource (for \
             per-connection-refreshed rotation) and NetworkBuilder::intercept() (for the \
             per-route dispatcher), but agent-vm's secrets.rs/intercept_hook.rs aren't wired \
             onto them yet. Tracked in gregwebs/agent-vm#51; this launch was refused rather \
             than silently weakening the security behavior credential injection implies — \
             rerun without it."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issue_reference_present(err: &anyhow::Error) {
        assert!(
            err.to_string().contains("agent-vm#51"),
            "error should reference the follow-up tracking issue: {err}"
        );
    }

    #[test]
    fn shell_does_not_require_credentials() {
        assert!(!agent_requires_credentials(Agent::Shell));
    }

    #[test]
    fn other_agents_require_credentials() {
        for agent in [Agent::Claude, Agent::Codex, Agent::Opencode, Agent::Copilot] {
            assert!(
                agent_requires_credentials(agent),
                "{agent:?} should need credentials"
            );
        }
    }

    #[test]
    fn credential_injection_unneeded_passes_without_creds() {
        assert!(check_credential_injection_unneeded(false, true).is_ok());
    }

    #[test]
    fn credential_injection_unneeded_passes_when_not_needed() {
        // `agent-vm shell --no-git` on a host with cached credentials: a
        // credential file exists, but this launch never asked to use it.
        assert!(check_credential_injection_unneeded(true, false).is_ok());
    }

    #[test]
    fn credential_injection_fails_closed_when_both_present_and_needed() {
        let err = check_credential_injection_unneeded(true, true).unwrap_err();
        assert!(err.to_string().contains("credential injection"));
        issue_reference_present(&err);
    }
}
