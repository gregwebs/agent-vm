//! Pure Layer DAG core; the active chain keeps v1 until CP10.
//!
//! Issue #228 replaces the position-dependent chain with a parent-declared
//! Layer DAG. The DAG's identity, order and plan concepts are independent of
//! the chain's, so they land here checkpoint by checkpoint rather than beside
//! the chain, which is deleted at the cutover (CP10).
//!
//! The tree holds the normalized build-context enumeration ([`context`])
//! shared with the frozen v1 chain, the hex helper ([`hex`]), the v2 identity
//! encoders ([`identity`]), the Layer DAG ([`dag`]), the pre-build planner
//! ([`plan`]) and the shared account declaration model ([`account_data`]).
//! No v2 identity, DAG, planner or account code is called by the launch path
//! until CP10: `run.rs` keeps using the v1 wrapper in `layer.rs`, which calls
//! the moved v1 context adapter ([`context::NormalizedContext`]) and the
//! [`hex`] helper but no v2 code. The v1 stream is pinned by goldens that may
//! never be re-recorded. See `docs/specs/image-composition.md`.
//!
//! # Handoff
//!
//! The modules carry `#[cfg_attr(not(test), expect(dead_code, ...))]` because
//! the binary does not call them yet; CP10 removes every expectation when it
//! activates the DAG and deletes v1. Obligations this checkpoint deliberately
//! leaves to others:
//!
//! - **CP2/CP5 (builder).** A built layer's context and every passed build
//!   argument must be exactly what [`identity`] hashed. That correspondence is
//!   not type-level (the builder owns it) and must be tested there.
//! - **CP8 (parser).** Owns `[[layers]]` parsing and must retain declaration
//!   order, parent references and every catalog entry, rather than reusing the
//!   chain's source-only dedupe.
//! - **CP9 (adapter).** Supplies every resolved node, parent and complete
//!   [`identity::ArtifactInputs`] to [`plan::CompositionPlan::identify`], and
//!   keeps the complete request outside the compact artifact-only plan.
//! - **CP10 (activation).** Wires the plan into `run.rs`, deletes the v1
//!   wrapper and its goldens, and drops these expectations.

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Account declarations are consumed by CP4/CP8 and launch at CP10"
    )
)]
pub(crate) mod account_data;
pub(crate) mod context;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Layer DAG is wired into launch at the #228 cutover (CP10)"
    )
)]
pub(crate) mod dag;
pub(crate) mod hex;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Layer DAG is wired into launch at the #228 cutover (CP10)"
    )
)]
pub(crate) mod identity;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Layer DAG is wired into launch at the #228 cutover (CP10)"
    )
)]
pub(crate) mod plan;

#[cfg(test)]
pub(crate) mod test_support;
