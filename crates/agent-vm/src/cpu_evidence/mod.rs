//! Phase 0 evidence machinery for #647: the native-protocol analyzer and its runner.
//!
//! Test-only by construction: `main.rs` declares this module under `#[cfg(test)]`, so no
//! ordinary build contains it and no production decision can depend on it. The pieces are:
//!
//! * [`analyze`] — a VM-free, independently written oracle over the raw poll log: the
//!   observation clock (§3.2 high-water/correction), the shadow policy runs, the
//!   predeclared per-trial gates (P0-D) and the exact-rational numeric mechanics (N4).
//! * [`native`] — the ignored native test's driver: one owned sandbox at a time, the
//!   declared trial matrix, P0-E capacity/combined/equality/lifecycle trials, host
//!   quietness sampling, guest workload qualification and retained JSONL evidence.
//!
//! Kept apart from `resources.rs` because it is a measurement harness, not the controller:
//! the analyzer must stay independent of the policy implementation so Phase 0 can fail the
//! input contract before any controller exists (plan P0-C).

pub(crate) mod analyze;
pub(crate) mod native;
