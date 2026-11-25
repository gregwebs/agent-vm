//! The launch gate for pending content pins (#736 phase 5).
//!
//! A project config may name a `trust = false` source. `config::load` refuses
//! such a load with the typed [`UnapprovedSources`], whose `Display` is the
//! non-interactive advice (R8). This module is the one place that may turn that
//! refusal into a review, a question, and one store commit — and it does so only
//! under the whole eligibility conjunction (D3/B3):
//!
//! * the load failed with exactly that typed refusal,
//! * the real CLI preflight accepted the argv as a launch
//!   ([`crate::cli::LaunchRoute`]) — never `doctor`, help, version, a built-in or
//!   `config …`,
//! * and [`crate::config_pins::prompt::StdTerminal::detect`] found this
//!   process's own foreground terminal.
//!
//! Everything else returns the phase-4 refusal unchanged, so the refusal text
//! and every exit code stay exactly as they were.
//!
//! # One question, one commit, one reload
//!
//! The pending candidates are the bytes the load already read and hashed, so the
//! hash R8 named and the diff the user reads are the same read. The baseline for
//! that diff is the store's recorded active digest under `read_for_diff`'s shared
//! lock (B7), never the pre-lock inspection's `PendingReason`: the locked read is
//! given the keys and their candidates, and derives each baseline from the
//! manifest it reads. An approval commits
//! every reviewed candidate in one locked [`PinStore::update`]; the reload then
//! happens **once**. If the source changed again meanwhile, the reload returns the
//! same typed refusal and this module does not prompt a second time: the R8 text
//! is the answer.
//!
//! # A warning is not a failure
//!
//! [`CommitOutcome::warnings`] describe work that happened *after* the commit
//! point (lock-header finalization, the bounded snapshot sweep): the approvals
//! are on disk. They are printed and the launch continues, so the launch never
//! disagrees with what the store already recorded.
//!
//! # The active baseline
//!
//! [`record_active`] marks the approvals a launch actually used as the keys'
//! active digest. It runs only for a dispatch [`crate::cli::Dispatch::is_launch`]
//! and only after a successful parse, and it is best effort: a failure is
//! reported and never turns a successful launch into an error. It is not part of
//! approval — `Current::mark_active` never recreates a missing key or digest — so
//! it cannot widen what the user approved.
//!
//! [`ActiveUpdates`] carries the store observation the **load** made, and the
//! recorder commits against exactly that generation (R12). A reset or a replaced
//! store between load and recorder is then a no-op — nothing is recorded into a
//! store this launch never read — rather than an activation of a digest a fresh
//! observation happens to approve.

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};

use crate::cli::LaunchRoute;
use crate::config::{self, ConfigPaths, ConfigReport};
use crate::config_pins::prompt::{ApprovalTerminal, Outcome, StdTerminal};
use crate::config_pins::store::{
    ApprovalCandidate, CommitBatch, CommitOutcome, DiffRequest, ObservedStore, PinStore,
    ReceiptKind, WriteError,
};
use crate::config_pins::{ContentHash, InspectedStatus, PinKey, UnapprovedSources, diff};

/// What one interactive review decided.
///
/// `Approved` carries nothing: the receipts and warnings were already printed
/// after the commit, and the caller's only remaining duty is the single reload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Interactive {
    /// The commit (or a concurrent approval) settled every pending source.
    Approved,
    /// Nothing was left to ask about: every candidate was approved by another
    /// writer between the load and the diff.
    NothingLeft,
    /// A review crossed an interactive cap, so no part of it was shown and no
    /// question was asked.
    Truncated(diff::TooLarge),
    Declined,
    NoAnswer,
}

/// Which verbs the pending approvals could make dispatchable, for the route
/// preflight (B3).
///
/// A load that succeeded, or failed with anything but a pending pinned source,
/// reaches no prompt at all, so the classification is irrelevant there and the
/// widest answer is the honest one.
pub(crate) fn verb_candidates(config: &Result<ConfigReport>) -> crate::cli::VerbCandidates<'_> {
    let Err(error) = config else {
        return crate::cli::VerbCandidates::AnyPendingSource;
    };
    match error.downcast_ref::<UnapprovedSources>() {
        Some(unapproved) => unapproved.verb_candidates(),
        None => crate::cli::VerbCandidates::AnyPendingSource,
    }
}

/// The gate between `config::load` and `cli::parse_from`.
///
/// A load that succeeded is returned untouched: no store is opened, no lock is
/// created and no pin state is written. A load that failed with anything but a
/// pending pinned source is returned untouched for the same reason. Only the
/// full conjunction reaches a prompt.
pub(crate) fn gate(
    config: Result<ConfigReport>,
    route: Option<LaunchRoute>,
    paths: Option<&ConfigPaths>,
) -> Result<ConfigReport> {
    let mut terminal = StdTerminal::detect();
    gate_with(
        config,
        route,
        paths,
        terminal
            .as_mut()
            .map(|terminal| terminal as &mut dyn ApprovalTerminal),
        &mut std::io::stderr(),
        now_ms(),
    )
}

/// [`gate`] with the two ambient facts supplied: the terminal and the clock.
///
/// `terminal` is the result of [`StdTerminal::detect`] itself — `None` is "no
/// eligible terminal", not "no terminal was checked" — so the eligibility
/// conjunction is testable without a TTY and without any way for a test to
/// prompt on the test harness's own terminal.
pub(crate) fn gate_with(
    config: Result<ConfigReport>,
    route: Option<LaunchRoute>,
    paths: Option<&ConfigPaths>,
    terminal: Option<&mut dyn ApprovalTerminal>,
    render: &mut dyn Write,
    now_ms: i64,
) -> Result<ConfigReport> {
    let unapproved: UnapprovedSources = match config {
        Ok(report) => return Ok(report),
        // Anything that is not a pin refusal keeps its own text and status:
        // `?` re-raises the same error, still downcastable to what it was.
        Err(error) => error.downcast::<UnapprovedSources>()?,
    };
    // The refusal is returned unchanged — byte for byte, exit code for exit
    // code — whenever the conjunction does not hold: no launch route, no
    // project to record in, or no eligible foreground terminal. Nothing below
    // this point runs for `doctor`, help, help/version, a built-in, `config …`
    // or an ordinary refusal.
    let (Some(_route), Some(paths), Some(terminal)) = (route, paths, terminal) else {
        return Err(anyhow::Error::new(unapproved));
    };
    let Some(project) = paths.project.as_ref() else {
        return Err(anyhow::Error::new(unapproved));
    };

    let store = PinStore::new(project.clone());
    let decided = approve_interactively_with(&store, &unapproved, terminal, render, now_ms)?;
    let project_config = unapproved.project_config().to_path_buf();
    let subject = crate::one_line::quoted_path(&project_config);
    match decided {
        // One reload, and only after the commit point: the bytes the launch will
        // use are read from disk rather than taken from the approval.
        Interactive::Approved | Interactive::NothingLeft => config::load(paths),
        // A source that changed again between the review and the reload is
        // refused by that reload itself; prompting again in the same invocation
        // would ask a second question for one launch.
        Interactive::Declined => Err(anyhow!(
            "config: {subject}: the pinned source {} not approved; nothing was recorded",
            if unapproved.pending().len() == 1 {
                "change was"
            } else {
                "changes were"
            },
        )),
        Interactive::NoAnswer => Err(anyhow!(
            "config: {subject}: no answer was read (end of input); nothing was approved"
        )),
        Interactive::Truncated(too_large) => Err(anyhow!(
            "config: {subject}: the review of {} is too large to approve interactively ({}); nothing was approved",
            crate::one_line::quoted_path(too_large.key.as_path()),
            too_large.cap.clause(),
        )),
    }
}

/// Review the pending candidates and, on `y`, commit exactly them.
///
/// The store is a parameter so a test can drive the real transaction with a
/// commit-time fault injected; production always passes a store for the load's
/// own project.
fn approve_interactively_with(
    store: &PinStore,
    unapproved: &UnapprovedSources,
    terminal: &mut dyn ApprovalTerminal,
    render: &mut dyn Write,
    now_ms: i64,
) -> Result<Interactive> {
    let project_config = crate::one_line::quoted_path(unapproved.project_config());
    let observed = unapproved
        .observed()
        .ok_or_else(|| anyhow!("internal: a pending pinned source without a store observation"))?;
    // The keys and the candidates, never the digests the inspection's reason
    // named: another launch can activate a different approved digest before this
    // read, and the review must describe the baseline the locked manifest
    // records. A first-use key has no baseline and reviews against empty; a
    // baseline whose snapshot is genuinely gone is reported as unavailable.
    let requests: Vec<DiffRequest<'_>> = unapproved
        .pending()
        .iter()
        .map(|source| DiffRequest {
            key: source.key(),
            candidate: source.candidate(),
        })
        .collect();
    let state = store
        .read_for_diff(&observed, &requests)
        .map_err(|problem| anyhow!("config: {project_config}: {}", problem.line()))?;

    let outcome = crate::config_pins::prompt::run(unapproved.pending(), &state, terminal, render)?;
    match outcome {
        Outcome::NothingToReview => Ok(Interactive::NothingLeft),
        Outcome::TooLarge(too_large) => Ok(Interactive::Truncated(too_large)),
        Outcome::Declined => Ok(Interactive::Declined),
        Outcome::NoAnswer => Ok(Interactive::NoAnswer),
        Outcome::Approved => {
            // One transaction: every reviewed candidate, plus the
            // already-approved-but-inactive keys this load used, protected by
            // every declared key so the commit can never evict a live one.
            let committed = store
                .update(&observed, &commit_batch(unapproved), now_ms)
                .map_err(|error| anyhow!("config: {project_config}: {}", error.line()))?;
            print_commit(render, unapproved, &committed).map_err(|error| {
                // The commit point has passed, so this can never be reported as
                // "nothing was approved".
                anyhow!(
                    "config: {project_config}: the pinned source approvals were recorded, but \
                     their receipts could not be printed ({error})"
                )
            })?;
            Ok(Interactive::Approved)
        }
    }
}

/// The one batch an interactive approval commits.
fn commit_batch(unapproved: &UnapprovedSources) -> CommitBatch {
    CommitBatch {
        approve: unapproved
            .pending()
            .iter()
            .map(|source| ApprovalCandidate {
                key: source.key().clone(),
                hash: source.hash,
                bytes: source.candidate().to_vec(),
                activate: true,
            })
            .collect(),
        // An approved digest that is not the key's active one becomes active
        // through this launch (R6): no fresh consent, but the baseline moves.
        activate: unapproved
            .entries()
            .iter()
            .filter_map(|entry| match entry.status {
                InspectedStatus::Approved { active: false } => {
                    Some((entry.key.clone(), entry.hash))
                }
                InspectedStatus::Approved { active: true } | InspectedStatus::Pending(_) => None,
            })
            .collect(),
        retained_keys: unapproved.all_declared_keys().iter().cloned().collect(),
    }
}

/// Print one committed transaction's receipts and every warning it reported.
///
/// Built as one transcript so a broken terminal cannot leave the receipts half
/// written; the caller reports a failed write as "recorded, but not printed".
fn print_commit(
    render: &mut dyn Write,
    unapproved: &UnapprovedSources,
    committed: &CommitOutcome,
) -> std::io::Result<()> {
    let mut transcript = String::new();
    for receipt in &committed.receipts {
        let action = match receipt.kind {
            ReceiptKind::Approved => "approved",
            ReceiptKind::AlreadyApproved => "already approved",
        };
        let path = diff::escape_review_line(receipt.key.as_str().as_bytes());
        match unapproved
            .entries()
            .iter()
            .find(|entry| entry.key == receipt.key)
        {
            Some(entry) => transcript.push_str(&format!(
                "==> {action} {} {path} {}\n",
                entry.alias, receipt.hash
            )),
            None => transcript.push_str(&format!("==> {action} {path} {}\n", receipt.hash)),
        }
    }
    for warning in &committed.warnings {
        transcript.push_str(&format!("==> warning: {warning}\n"));
    }
    render.write_all(transcript.as_bytes())?;
    render.flush()
}

/// One project's approved digests that this launch used but that are not
/// recorded as the keys' active ones, plus the store observation the load made.
///
/// The observation travels with the updates because recording fences on the
/// generation the launch actually read (R12): a reset between the load and the
/// recorder must make the recording a no-op, never a write into a store this
/// launch never read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ActiveUpdates {
    observed: ObservedStore,
    updates: Vec<(PinKey, ContentHash)>,
    retained_keys: Vec<PinKey>,
}

impl ActiveUpdates {
    /// The keys this launch used an inactive digest for, in the order the launch
    /// read them: exactly what a failed recording leaves unrecorded (D10).
    fn describe(&self) -> String {
        self.updates
            .iter()
            .map(|(key, _)| diff::escape_review_line(key.as_str().as_bytes()))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// The updates a loaded report implies, or `None` when there are none.
    ///
    /// `None` is what keeps the common launch from opening the store: a load
    /// whose pins are already active records nothing. Only pins the load
    /// *approved* are captured — a trusted source has no pin, and a pending one
    /// never reaches a successful load.
    pub(crate) fn of(report: &ConfigReport) -> Option<Self> {
        // No store was read, so there is nothing this load could record into.
        let observed = report.pins_observed()?;
        let mut updates = Vec::new();
        let mut retained_keys = Vec::new();
        for entry in report.sources().entries() {
            let Some(pin) = entry.pin() else {
                continue;
            };
            retained_keys.push(pin.key().clone());
            if !pin.active() {
                updates.push((pin.key().clone(), pin.hash()));
            }
        }
        if updates.is_empty() {
            return None;
        }
        Some(Self {
            observed,
            updates,
            retained_keys,
        })
    }
}

/// Record this launch's active approvals, best effort.
///
/// The caller must have established that the dispatch is a launch: doctor, help,
/// version and every built-in must not create or update pin state. Nothing here
/// approves anything, so a failure cannot widen an approval.
///
/// D10: recording may never delay a launch. It takes `pins.lock` for at most the
/// store's one-second recording budget, and a busy store is an error the caller
/// prints and moves past: there is no retry here, because the launch has already
/// decided to boot.
pub(crate) fn record_active(paths: Option<&ConfigPaths>, updates: &ActiveUpdates) -> Result<()> {
    let project = paths
        .and_then(|paths| paths.project.as_ref())
        .ok_or_else(|| anyhow!("this project has no source pin store"))?;
    let store = PinStore::new(project.clone());
    let batch = CommitBatch {
        approve: Vec::new(),
        activate: updates.updates.clone(),
        retained_keys: updates.retained_keys.clone(),
    };
    // The load's own observation, never a fresh one: a store reset or replaced
    // between the load and here is a generation the launch never read.
    match store.update_recording(&updates.observed, &batch, now_ms()) {
        Ok(_) => Ok(()),
        // Activation is not an approval: a reset in that window, or a peer's
        // eviction, removed a digest this launch used, so there is nothing left
        // to record and the store published nothing. That is the no-op this
        // best-effort recording is allowed to be, not a failed recording.
        Err(WriteError::BatchStale | WriteError::ResetConflict) => Ok(()),
        Err(error) => Err(anyhow!("{}", error.line())),
    }
}

/// The report for a failed best-effort recording. One line, never fatal, naming
/// the keys whose active digest was not recorded (D10).
pub(crate) fn record_active_warning(error: &anyhow::Error, updates: &ActiveUpdates) -> String {
    format!(
        "warning: the source pin approvals this launch used could not be recorded as active for \
         {} ({error:#}); every approval stands and the launch continues",
        updates.describe()
    )
}

/// Epoch milliseconds, the store's only clock. A pre-epoch clock reads as `0`,
/// which orders every approval before any later one.
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests;
