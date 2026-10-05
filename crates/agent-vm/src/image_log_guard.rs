//! Process-level tracing guard for a **default-tier** invocation (#261, M2).
//!
//! The default boot image reference is record-sourced and may name a private
//! registry. agent-vm redacts it from its own output, but the lower-level image
//! stack it calls into — `oci_client`, `microsandbox`, `reqwest`, `hyper` — logs
//! the full reference, repository name, digest and manifest URL at debug/trace.
//! Those events are in dependency code we do not own, so the application's own
//! subscriber filters them out instead.
//!
//! The subscriber installed by [`crate::init_tracing`] asks
//! [`dependency_event_allowed`] for every event/span. Until an invocation has
//! actually selected the default tier the guard is off, so an explicit
//! CLI/env/config invocation keeps the dependency logging it had before. Once
//! [`activate`] runs (from selection, before any acquisition), non-`agent_vm`
//! events are suppressed for the rest of the process — which is exactly one
//! invocation. The SDK input, agent-vm's own notices and any failure returned to
//! the caller are unchanged; only dependency *tracing* is dropped, and guest
//! output is never involved.
//!
//! The flag is a process-global `AtomicBool`, not a span field, so it also
//! applies to SDK work on other threads/tasks that do not inherit the current
//! span.
//!
//! The decision itself is a small contracted kernel
//! ([`image_log_event_allowed`], ADR-0018); reading `Metadata::target` and
//! matching the namespace string are the trusted adapters that feed it.

use std::sync::atomic::{AtomicBool, Ordering};

use vstd::prelude::*;

static DEFAULT_TIER_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Mark this process as booting the default tier. Called once, from selection,
/// before any acquisition.
pub(crate) fn activate() {
    DEFAULT_TIER_ACTIVE.store(true, Ordering::SeqCst);
}

/// Whether a tracing event from `metadata` may reach the subscriber.
///
/// The `AtomicBool` read and the target string match are trusted adapters; the
/// security/redaction decision they feed is the contracted kernel.
pub(crate) fn dependency_event_allowed(metadata: &tracing::Metadata<'_>) -> bool {
    image_log_event_allowed(ImageLogFacts {
        default_tier_active: DEFAULT_TIER_ACTIVE.load(Ordering::SeqCst),
        agent_vm_owned: is_agent_vm_owned_target(metadata.target()),
    })
}

/// The trusted namespace match: an event is agent-vm's own when its target is
/// exactly `agent_vm` or under the `agent_vm::` module path. A bare
/// `starts_with("agent_vm")` would also accept an unrelated `agent_vmfoo`.
fn is_agent_vm_owned_target(target: &str) -> bool {
    target == "agent_vm" || target.starts_with("agent_vm::")
}

verus! {

/// The two already-measured facts [`dependency_event_allowed`] decides on: the
/// process-wide default-tier guard, and whether the event's target belongs to
/// agent-vm. Named fields rather than adjacent `bool` parameters, so an argument
/// swap cannot invert the redaction boundary.
pub(crate) struct ImageLogFacts {
    pub(crate) default_tier_active: bool,
    pub(crate) agent_vm_owned: bool,
}

/// The redaction-boundary decision, contracted (ADR-0018): allow the event
/// **iff** the default tier is inactive or the event is agent-vm's own. Total
/// over all four Boolean combinations; a default-tier invocation never allows a
/// dependency event.
pub(crate) fn image_log_event_allowed(facts: ImageLogFacts) -> (allowed: bool)
    ensures
        allowed == (!facts.default_tier_active || facts.agent_vm_owned),
        allowed ==> !facts.default_tier_active || facts.agent_vm_owned,
{
    !facts.default_tier_active || facts.agent_vm_owned
}

} // verus!

#[cfg(test)]
mod tests {
    use super::*;

    /// Exact disjunction over all four fact combinations (ADR-0018): an allowed
    /// event implies the default tier is inactive or the event is agent-vm's.
    #[test]
    fn image_log_decision_is_exactly_the_measured_disjunction() {
        for bits in 0u8..4 {
            let default_tier_active = bits & 1 != 0;
            let agent_vm_owned = bits & 2 != 0;
            let allowed = image_log_event_allowed(ImageLogFacts {
                default_tier_active,
                agent_vm_owned,
            });
            assert_eq!(
                allowed,
                !default_tier_active || agent_vm_owned,
                "bits={bits:02b}"
            );
        }
    }

    /// The behavior the four combinations describe: an explicit-source
    /// invocation lets everything through; an armed default tier drops every
    /// dependency event.
    #[test]
    fn dependency_events_are_dropped_only_for_an_armed_default_tier() {
        for (default_tier_active, agent_vm_owned, expected) in [
            (false, false, true),
            (false, true, true),
            (true, false, false),
            (true, true, true),
        ] {
            assert_eq!(
                image_log_event_allowed(ImageLogFacts {
                    default_tier_active,
                    agent_vm_owned,
                }),
                expected,
                "active={default_tier_active} owned={agent_vm_owned}"
            );
        }
    }

    /// The namespace adapter accepts only agent-vm's own target space, not any
    /// string that happens to start with `agent_vm`.
    #[test]
    fn only_the_agent_vm_namespace_is_owned() {
        assert!(is_agent_vm_owned_target("agent_vm"));
        assert!(is_agent_vm_owned_target("agent_vm::image_check"));
        assert!(is_agent_vm_owned_target("agent_vm::run::launch"));
        assert!(!is_agent_vm_owned_target("agent_vmfoo::x"));
        assert!(!is_agent_vm_owned_target("agent_vm_extra"));
        assert!(!is_agent_vm_owned_target("oci_client::client"));
        assert!(!is_agent_vm_owned_target("microsandbox::config::registry"));
        assert!(!is_agent_vm_owned_target("reqwest::connect"));
        assert!(!is_agent_vm_owned_target(""));
    }
}
