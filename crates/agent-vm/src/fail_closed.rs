//! Fail-closed guards for fork-only features not yet ported to the clean
//! Microsandbox v0.6.15 baseline (agent-vm issue #40).
//!
//! The 0.5.7 `gw` fork added guest egress via a host HTTP CONNECT proxy,
//! file-backed (per-connection-refreshed) credential secrets dispatched
//! through a per-route intercept hook, `--auto-publish`, and CIDR/group
//! egress overrides. None of the `NetworkBuilder` methods those features
//! depended on — `.intercept()`, `.auto_publish()`, `.allow_egress_group()`,
//! `.allow_egress_cidr()` — exist on the clean baseline
//! (`vendor/microsandbox/crates/network/lib/config/builder.rs`), and
//! baseline's `SecretBuilder::value()` takes a static `String` rather than
//! a file path, so there is no way today to deliver the fork's
//! per-connection token-rotation guarantee at all.
//!
//! Per the issue text, an unported fork-only feature must fail closed with
//! a clear, actionable error rather than either silently dropping the
//! safety behavior it promised (e.g. quietly not enforcing the GitHub repo
//! allow-list) or silently downgrading it (e.g. baking a credential file's
//! contents into a static secret that never rotates and can leak a stale
//! token). This module is that fail-closed boundary. See the issue-40
//! implementation plan's Phase 6 for the option-by-option disposition.

use anyhow::{Result, bail};

use crate::run::Agent;

/// Builds the standard "not supported yet" message: names the option,
/// says why, and points at the tracking issue so the error is actionable
/// instead of a mysterious method-not-found compile error turned runtime
/// dead end.
fn unsupported_message(option: &str, why: &str) -> String {
    format!(
        "{option} is not supported yet on the clean Microsandbox v0.6.15 baseline: {why}. \
         Tracked in gregwebs/agent-vm#40; this launch was refused rather than silently \
         weakening the security behavior {option} implies — rerun without it."
    )
}

/// Fails closed if the operator set a guest-egress HTTP proxy env var.
///
/// The fork's guest-egress-via-host-proxy feature (commits `d6b9b117`/
/// `a05c6b70`) has no baseline equivalent — the baseline SDK carries zero
/// `http_proxy`/`ProxyConfig` references. Silently ignoring
/// `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY` would boot with guest egress
/// going *direct* while the operator believes it's proxied, which is
/// exactly the kind of silent regression AC#5 forbids.
pub fn check_no_guest_proxy_env() -> Result<()> {
    check_no_guest_proxy_env_from(|var| std::env::var(var).ok())
}

/// Pure core of [`check_no_guest_proxy_env`], taking a lookup function
/// instead of reading the real process env — `cargo test`'s default
/// parallel threads make mutating `std::env::set_var`/`remove_var` for
/// `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY` from within a `#[test]` unsafe
/// (another test could read a value mid-mutation), so tests inject a
/// closure instead. Mirrors the `msb_home_dir`/`short_macos_msb_home`
/// split in `msb_install.rs`.
fn check_no_guest_proxy_env_from(lookup: impl Fn(&str) -> Option<String>) -> Result<()> {
    for var in ["HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"] {
        if lookup(var).is_some_and(|v| !v.is_empty()) {
            bail!(unsupported_message(
                &format!("guest egress via the host {var} proxy"),
                "the microsandbox network stack has no HTTP-CONNECT proxying for guest traffic \
                 on this baseline",
            ));
        }
    }
    Ok(())
}

/// Fails closed if `--auto-publish` was requested.
pub fn check_auto_publish_unrequested(requested: bool) -> Result<()> {
    if requested {
        bail!(unsupported_message(
            "--auto-publish",
            "NetworkBuilder::auto_publish() does not exist on this baseline",
        ));
    }
    Ok(())
}

/// Fails closed if `--allow-lan`, `--allow-host`, or `--allow-egress`
/// were requested.
///
/// Baseline expresses egress policy via `NetworkBuilder::policy(..)` and a
/// richer rule-based `NetworkPolicy` grammar rather than the fork's
/// `allow_egress_group`/`allow_egress_cidr` sugar methods (neither exists
/// on baseline). Re-expressing these three flags correctly against the new
/// grammar is real, security-sensitive design work outside minimal boot's
/// scope (see agent-vm issue #40's "explicitly out of scope" list) — so
/// each flag fails closed here instead of risking an incorrect policy
/// translation.
pub fn check_egress_overrides_unrequested(
    allow_lan: bool,
    allow_host: bool,
    egress_cidr_count: usize,
) -> Result<()> {
    if allow_lan {
        bail!(unsupported_message(
            "--allow-lan",
            "NetworkBuilder::allow_egress_group() does not exist on this baseline",
        ));
    }
    if allow_host {
        bail!(unsupported_message(
            "--allow-host",
            "NetworkBuilder::allow_egress_group() does not exist on this baseline",
        ));
    }
    if egress_cidr_count > 0 {
        bail!(unsupported_message(
            "--allow-egress",
            "NetworkBuilder::allow_egress_cidr() does not exist on this baseline",
        ));
    }
    Ok(())
}

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
        bail!(unsupported_message(
            "host credential injection (Anthropic/OpenAI/GitHub/Copilot token substitution)",
            "the fork's file-backed, per-connection-refreshed secret and its per-route \
             intercept-hook dispatcher (NetworkBuilder::intercept()) do not exist on this \
             baseline, and baking the file's current contents into a static value would \
             silently drop token rotation and risk leaking a stale credential",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issue_reference_present(err: &anyhow::Error) {
        assert!(
            err.to_string().contains("agent-vm#40"),
            "error should reference the tracking issue: {err}"
        );
    }

    #[test]
    fn guest_proxy_env_unset_passes_when_absent() {
        assert!(check_no_guest_proxy_env_from(|_| None).is_ok());
    }

    #[test]
    fn guest_proxy_env_ignores_empty_values() {
        // An empty-but-set var (e.g. a shell that exports "" rather than
        // leaving it unset) must not trip the guard.
        assert!(check_no_guest_proxy_env_from(|_| Some(String::new())).is_ok());
    }

    #[test]
    fn guest_proxy_env_fails_closed_when_set() {
        let err = check_no_guest_proxy_env_from(|var| {
            (var == "HTTPS_PROXY").then(|| "http://proxy.example:3128".to_string())
        })
        .unwrap_err();
        assert!(err.to_string().contains("HTTPS_PROXY"));
        issue_reference_present(&err);
    }

    #[test]
    fn auto_publish_passes_when_unrequested() {
        assert!(check_auto_publish_unrequested(false).is_ok());
    }

    #[test]
    fn auto_publish_fails_closed_when_requested() {
        let err = check_auto_publish_unrequested(true).unwrap_err();
        assert!(err.to_string().contains("--auto-publish"));
        issue_reference_present(&err);
    }

    #[test]
    fn egress_overrides_pass_when_none_requested() {
        assert!(check_egress_overrides_unrequested(false, false, 0).is_ok());
    }

    #[test]
    fn allow_lan_fails_closed() {
        let err = check_egress_overrides_unrequested(true, false, 0).unwrap_err();
        assert!(err.to_string().contains("--allow-lan"));
        issue_reference_present(&err);
    }

    #[test]
    fn allow_host_fails_closed() {
        let err = check_egress_overrides_unrequested(false, true, 0).unwrap_err();
        assert!(err.to_string().contains("--allow-host"));
        issue_reference_present(&err);
    }

    #[test]
    fn allow_egress_cidr_fails_closed() {
        let err = check_egress_overrides_unrequested(false, false, 1).unwrap_err();
        assert!(err.to_string().contains("--allow-egress"));
        issue_reference_present(&err);
    }

    #[test]
    fn shell_does_not_require_credentials() {
        assert!(!agent_requires_credentials(Agent::Shell));
    }

    #[test]
    fn other_agents_require_credentials() {
        for agent in [Agent::Claude, Agent::Codex, Agent::Opencode, Agent::Copilot] {
            assert!(agent_requires_credentials(agent), "{agent:?} should need credentials");
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
