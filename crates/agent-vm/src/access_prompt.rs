//! The in-terminal access prompt (`agent-vm#501` slice 3, reach A): eligibility,
//! the refusal baseline, the candidate rule, the grant task and the hint route.
//!
//! When a direct command resolved to `DirectIo::Pty` meets a network refusal, the
//! launcher asks about it in that same terminal: the guest's output is held (never
//! paused), host input goes to the question, and one deliberate key answers it. The
//! contract is [`crate::access_prompt::relay`] + `screen`; this module is what
//! `direct_pty` holds, and it owns everything that is not a byte sequence or a
//! phase:
//!
//! * **eligibility** (R2): the setting, `TERM`, and stdout being the *same*
//!   terminal as stdin, so `-t` with a redirected stdout never draws a prompt into a
//!   file;
//! * **the baseline** (R6): the per-entry count from the subscription's own
//!   snapshot, so only refusals that grow after subscribing prompt;
//! * **the candidate rule** (R4, R5, R7): `grantable_destination`, not answered,
//!   and the offer the grant path's own derivation gives;
//! * **the grant** (R19): [`crate::allowances::LiveAllowances::grant_unless_answered`],
//!   spawned and bounded, never cancelled;
//! * **the hint** (R26): the session's one-time line is routed to the relay's writer
//!   while this prompt owns the terminal.
//!
//! Reach A only: no `attach_with` launch, streaming path or catalog tool reaches
//! here, and nothing in this module can change what those forward.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast;
use tokio::time::Instant;

use crate::allowances::LiveAllowances;
use crate::env_flag::{self, FlagValue};
use crate::refusal::feed::{Hint, HintRelay, LiveRefusals};
use crate::refusal::{SessionId, Update};

/// The setting that turns the prompt off (R3).
pub(crate) const SETTING: &str = "AGENT_VM_NO_ACCESS_PROMPT";

/// The terminal geometry the prompt lays out against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Size {
    pub(crate) rows: u16,
    pub(crate) cols: u16,
}

pub(crate) mod guard;
pub(crate) mod input;
pub(crate) mod relay;
pub(crate) mod screen;
#[cfg(test)]
mod tmux_oracle;
pub(crate) mod vt;

/// What the prompt needs from the session's live state. Built by
/// [`crate::session_control::LiveSession::prompt_feed`].
pub(crate) struct Feed {
    pub(crate) refusals: Arc<LiveRefusals>,
    pub(crate) allowances: Arc<LiveAllowances>,
    pub(crate) session: SessionId,
    /// ADR-0064's once-per-session line.
    pub(crate) hint: Arc<Hint>,
    /// The macOS-notifications-off line, which rides the same seam (#501 slice 4
    /// R6). Its own `Hint`, because answering a question claims the refusal line
    /// only.
    pub(crate) notifications_off: Arc<Hint>,
    /// Where the prompt's sequenced signals go, when this launch started a
    /// notifier (B1–B3). `None` is every launch that must not notify.
    pub(crate) signals: Option<crate::notify::SignalSink>,
}

/// An eligible PTY launch's prompt source (R2).
pub(crate) struct Source {
    feed: Feed,
}

/// Read the setting once at the launch boundary and return the one warning a typo
/// deserves.
///
/// This is deliberately separate from eligibility: R3 requires the warning whether
/// or not the launch could ever draw a prompt (a catalog tool, `-T`, a redirected
/// stdout), so the caller reads it before it knows which I/O mode it has.
pub(crate) fn read_setting() -> (FlagValue, Option<String>) {
    let value = env_flag::read(SETTING);
    let warning = warning_for(&value);
    (value, warning)
}

/// Whether this launch may show the prompt at all (R2).
///
/// The same decision [`Source::for_pty_launch`] makes, exposed so the launch can
/// also choose the notifier's prompt trigger: a question that will never be asked
/// must not hold a banner back for the prompt's grace (B8).
pub(crate) fn can_prompt(setting: &FlagValue) -> bool {
    eligible(&Facts::measure(setting.clone())).is_ok()
}

impl Source {
    /// A source over an already-built feed. Production goes through
    /// [`Source::for_pty_launch`]; the full-loop tests build the feed themselves, so
    /// they can keep the `LiveRefusals` and inject a refusal after subscribing.
    #[cfg(test)]
    pub(crate) fn from_feed(feed: Feed) -> Self {
        Self { feed }
    }

    /// Subscribe to this session's feeds and start idle. `timings` exists so a test
    /// can shrink every wait; production passes [`relay::Timings::default`].
    pub(crate) fn start(self, size: Size, timings: relay::Timings) -> Prompt {
        Prompt::start(self.feed, size, timings)
    }

    /// The source, when this PTY launch may prompt. `setting` is the value
    /// [`read_setting`] already read at the launch boundary (R3: read once).
    pub(crate) fn for_pty_launch(feed: Option<Feed>, setting: FlagValue) -> Option<Self> {
        let eligible = can_prompt(&setting);
        feed.filter(|_| eligible).map(|feed| Self { feed })
    }
}

/// The R3 warning: one launch notice naming the variable and the accepted values.
///
/// Returned whether or not the launch is otherwise eligible (N4): a typo must not be
/// hidden by `TERM=dumb`.
pub(crate) fn warning_for(setting: &FlagValue) -> Option<String> {
    setting.unrecognized().map(|value| {
        format!(
            "==> {SETTING}={} is not one of 1/true/yes/on or 0/false/no/off; the in-terminal prompt stays on",
            crate::config::escape_str(value)
        )
    })
}

/// Every fact eligibility reads, measured once.
pub(crate) struct Facts {
    setting: FlagValue,
    term: Option<String>,
    stdout_is_terminal: bool,
    same_terminal: bool,
}

impl Facts {
    fn measure(setting: FlagValue) -> Self {
        Self {
            setting,
            term: std::env::var("TERM").ok(),
            stdout_is_terminal: std::io::IsTerminal::is_terminal(&std::io::stdout()),
            same_terminal: same_terminal(),
        }
    }
}

/// Why this launch cannot prompt. Named so a debug log says which of R2's clauses
/// failed rather than only that one did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ineligible {
    SettingOff,
    NoTerm,
    DumbTerm,
    StdoutNotTerminal,
    DifferentTerminals,
}

/// R2's decision, as a pure function of the measured facts.
pub(crate) fn eligible(facts: &Facts) -> Result<(), Ineligible> {
    if facts.setting == FlagValue::On {
        return Err(Ineligible::SettingOff);
    }
    match facts.term.as_deref() {
        Some("") | None => return Err(Ineligible::NoTerm),
        Some("dumb") => return Err(Ineligible::DumbTerm),
        Some(_) => {}
    }
    if !facts.stdout_is_terminal {
        return Err(Ineligible::StdoutNotTerminal);
    }
    if !facts.same_terminal {
        return Err(Ineligible::DifferentTerminals);
    }
    Ok(())
}

/// Whether stdout is the **same** terminal as stdin, by `st_rdev`.
///
/// `-t` may resolve to a PTY with stdout redirected to a file; drawing a prompt
/// there would put launcher bytes in that file (R2).
fn same_terminal() -> bool {
    // SAFETY: `fstat` only writes into the two `stat` values, both of which are live
    // locals of the right type, and each names a descriptor this process owns.
    unsafe {
        let mut input: libc::stat = std::mem::zeroed();
        let mut output: libc::stat = std::mem::zeroed();
        if libc::fstat(libc::STDIN_FILENO, &mut input) != 0 {
            return false;
        }
        if libc::fstat(libc::STDOUT_FILENO, &mut output) != 0 {
            return false;
        }
        input.st_dev == output.st_dev && input.st_rdev == output.st_rdev
    }
}

/// What one refusal amounts to for the prompt (§7.2's `candidate`).
///
/// Four outcomes rather than `Option`: "this session already answered it" is a real
/// answer and must not be reported as "the prompt could not ask" (B3), so the two
/// reach the notifier as different signals.
pub(crate) enum CandidateOutcome {
    Offer(relay::Candidate),
    /// R4: `agent-vm access allow <ID>` would refuse it.
    NotGrantable,
    /// R5: this session already granted the destination.
    AlreadyAnswered(crate::egress_policy::Allowance),
    /// R7: the grant path offers nothing here (a host proxy is in use).
    Unofferable,
}

/// One refusal worth asking about (§7.2's `candidate`).
fn candidate_for(
    entry: &crate::refusal::RefusalEntry,
    allowances: &LiveAllowances,
) -> CandidateOutcome {
    // R4: exactly what `agent-vm access allow <ID>` would accept.
    let Ok(destination) = crate::allowances::grantable_destination(entry) else {
        return CandidateOutcome::NotGrantable;
    };
    // R5: never re-ask what this session already answered.
    if allowances.answered(&destination) {
        return CandidateOutcome::AlreadyAnswered(destination);
    }
    // R5/R7: the same derivation a grant uses; a host proxy in use offers nothing.
    let Ok(offer) = allowances.offer(&destination) else {
        return CandidateOutcome::Unofferable;
    };
    let port = match &entry.key.destination {
        crate::refusal::Destination::Address { port, .. }
        | crate::refusal::Destination::Host { port, .. } => *port,
        crate::refusal::Destination::DnsName { .. } => None,
    };
    CandidateOutcome::Offer(relay::Candidate {
        entry_id: entry.id.clone(),
        // Already escaped to printable ASCII by the table that renders it (R24:
        // the prompt names the destination exactly as `access` does).
        cell: screen::Cell::from_table(entry.destination_cell()),
        count: entry.count,
        offer,
        port,
        destination,
    })
}

/// The outcome of one spawned grant.
pub(crate) enum GrantOutcome {
    Settled(crate::allowances::PromptGrant),
    /// The 40 s wait expired; the task was left running (never aborted).
    Unconfirmed,
    /// The task panicked or was cancelled by runtime shutdown.
    Lost(String),
}

pub(crate) struct GrantDone {
    pub(crate) generation: u64,
    pub(crate) outcome: GrantOutcome,
}

/// One feed event, one per loop turn.
pub(crate) enum FeedEvent {
    Answered(Result<String, broadcast::error::RecvError>),
    Refusal(Result<Update, broadcast::error::RecvError>),
    Hint(relay::HintKind),
}

/// The prompt a PTY session owns. Every method is synchronous except
/// [`Prompt::next_feed_event`].
pub(crate) struct Prompt {
    relay: relay::Relay,
    feed: Feed,
    refusals: broadcast::Receiver<Update>,
    answers: broadcast::Receiver<String>,
    /// R6: entry id → count, from the subscription's own snapshot.
    baseline: HashMap<String, u64>,
    /// A feed half that reported `Closed` cannot happen while the session's `Arc`s
    /// live, but a closed receiver would be ready for ever and spin the loop, so a
    /// closed half is parked instead.
    refusals_open: bool,
    answers_open: bool,
    /// The hint fires once per session; after that its branch parks, so a routed
    /// hint can never keep the loop's `select!` ready (finding 5). One flag per
    /// line: the two fire at different times and neither parks the other.
    refusal_hint_open: bool,
    notifications_off_open: bool,
    /// Where the relay's sequenced signals go (B1–B3).
    signals: Option<crate::notify::SignalSink>,
}

impl Prompt {
    /// Subscribe, redirect both hints, baseline the snapshot and start idle.
    pub(crate) fn start(feed: Feed, size: Size, timings: relay::Timings) -> Self {
        Self::build(feed, size, timings, stderr_is_stdout_terminal())
    }

    /// The same, with both hint routes taken as if stderr were this terminal.
    ///
    /// `cargo test` has no terminal on stdout and stderr, so [`Prompt::start`] cannot
    /// route a hint there. The hint seam's delivery — which line the writer writes
    /// and whether the eplogue still owes it — is only reachable with a route.
    #[cfg(test)]
    pub(crate) fn start_with_routes(feed: Feed, size: Size, timings: relay::Timings) -> Self {
        Self::build(feed, size, timings, true)
    }

    fn build(feed: Feed, size: Size, timings: relay::Timings, route_hints: bool) -> Self {
        let (snapshot, refusals) = feed.refusals.subscribe();
        let baseline = snapshot
            .entries
            .iter()
            .map(|entry| (entry.id.clone(), entry.count))
            .collect();
        let answers = feed.allowances.subscribe_answers();
        // Both lines are routed only when stderr is the same terminal the prompt
        // draws on; elsewhere today's stderr line is already right.
        let (hint, notifications_off) = if route_hints {
            (
                Some(feed.hint.redirect()),
                Some(feed.notifications_off.redirect()),
            )
        } else {
            (None, None)
        };
        let signals = feed.signals.clone();
        let mut prompt = Self {
            relay: relay::Relay::new(
                feed.session.as_str().to_owned(),
                size,
                timings,
                hint,
                notifications_off,
            ),
            feed,
            refusals,
            answers,
            baseline,
            refusals_open: true,
            answers_open: true,
            refusal_hint_open: true,
            notifications_off_open: true,
            signals,
        };
        // R6/B1: the snapshot is the baseline, so a refusal that existed before this
        // subscription (a retry of an older entry) can never become a question — or
        // a banner. Every entry is named, not only the ones the prompt can see.
        let now = Instant::now();
        for entry in &snapshot.entries {
            prompt.relay.baseline(&entry.id, entry.count, now);
        }
        prompt
    }

    /// Fold one refusal in: baseline it, or ask about it.
    fn consider(&mut self, entry: &crate::refusal::RefusalEntry, now: Instant) {
        let previous = self.baseline.get(&entry.id).copied().unwrap_or(0);
        if entry.count <= previous {
            return;
        }
        self.baseline.insert(entry.id.clone(), entry.count);
        match candidate_for(entry, &self.feed.allowances) {
            CandidateOutcome::Offer(candidate) => self.relay.offer(candidate, now),
            // R5: this session already answered the destination, so the attempt is
            // disposed of as an answer (B3).
            CandidateOutcome::AlreadyAnswered(destination) => {
                self.relay
                    .already_answered(&entry.id, entry.count, &destination, now);
            }
            // R4/R7: nothing can be granted here, so nothing is asked.
            CandidateOutcome::NotGrantable | CandidateOutcome::Unofferable => {
                self.relay.cannot_offer(&entry.id, entry.count, now);
            }
        }
    }

    /// Hand every signal the relay emitted since the last call to the notifier.
    ///
    /// The vector is **always** taken: a launch with no notifier (macOS opt-out,
    /// Linux, SSH, root, a missing helper) would otherwise keep every transition of
    /// the whole session, and the prompt never reads them again. The send is
    /// non-blocking (R12), so no prompt frame waits on a helper.
    pub(crate) fn drain_signals(&mut self) {
        let signals = self.relay.drain_signals();
        let Some(sink) = self.signals.clone() else {
            return;
        };
        for signal in signals {
            sink.signal(signal);
        }
    }

    /// Re-check every destination the relay still holds against the session's own
    /// answer set, closing only those actually answered.
    fn recheck_answers(&mut self, now: Instant) {
        for destination in self.relay.pending_destinations() {
            if self.feed.allowances.answered(&destination) {
                self.relay.answered(&destination, now);
            }
        }
    }
    /// The generation of the takeover in progress (0 when idle): a lost grant task
    /// is reported against it.
    pub(crate) fn generation(&self) -> u64 {
        self.relay.generation()
    }

    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.relay.deadline()
    }

    pub(crate) fn handle_deadline(&mut self, now: Instant) {
        self.relay.handle_deadline(now);
        self.trace_phase();
    }

    /// Cancel-safe: answers, then refusals, then the hint, each of which consumes
    /// nothing when the future is dropped. Polled at the lowest priority.
    pub(crate) async fn next_feed_event(&mut self) -> FeedEvent {
        // The hint handles are cloned from the relay so the four waits borrow
        // disjoint things: a `select!` over `self` twice would not compile, and none
        // of these receivers consumes anything when its future is dropped.
        let refusal_hint = self.relay.hint_handle(relay::HintKind::Refusal);
        let notifications_off = self.relay.hint_handle(relay::HintKind::NotificationsOff);
        tokio::select! {
            biased;
            answer = recv_or_park(self.answers_open, &mut self.answers) => FeedEvent::Answered(answer),
            refusal = recv_or_park(self.refusals_open, &mut self.refusals) => FeedEvent::Refusal(refusal),
            _ = wait_for_hint(if self.refusal_hint_open { refusal_hint } else { None }) => {
                FeedEvent::Hint(relay::HintKind::Refusal)
            }
            _ = wait_for_hint(if self.notifications_off_open { notifications_off } else { None }) => {
                FeedEvent::Hint(relay::HintKind::NotificationsOff)
            }
        }
    }

    /// Fold one feed event in.
    pub(crate) fn handle_feed(&mut self, event: FeedEvent, now: Instant) {
        match event {
            FeedEvent::Answered(Ok(destination)) => {
                if let Ok(destination) = crate::egress_policy::Allowance::parse(&destination) {
                    self.relay.answered(&destination, now);
                } else {
                    // An answer this build cannot spell is one it cannot name: re-check
                    // the answer set instead of assuming every question was answered.
                    self.recheck_answers(now);
                }
                self.trace_phase();
            }
            FeedEvent::Answered(Err(error)) => {
                if matches!(error, broadcast::error::RecvError::Closed) {
                    self.answers_open = false;
                }
                // Lagged or closed: the wakeup list is incomplete, so re-check each
                // open destination against the handler's own `answered()`. Closing a
                // question on a guess would tell the user it was answered when it was
                // not (finding 18).
                self.recheck_answers(now);
                self.trace_phase();
            }
            FeedEvent::Refusal(Ok(update)) => {
                if let Some(entry) = update.entry.as_deref() {
                    self.consider(entry, now);
                }
                self.trace_phase();
            }
            FeedEvent::Refusal(Err(error)) => {
                if matches!(error, broadcast::error::RecvError::Closed) {
                    self.refusals_open = false;
                }
                // R6's lag rule: compare a fresh snapshot with the baseline, then the
                // snapshot becomes the baseline.
                let snapshot = self.feed.refusals.snapshot();
                for entry in &snapshot.entries {
                    self.consider(entry, now);
                }
                self.baseline = snapshot
                    .entries
                    .iter()
                    .map(|entry| (entry.id.clone(), entry.count))
                    .collect();
                self.trace_phase();
            }
            FeedEvent::Hint(kind) => {
                match kind {
                    relay::HintKind::Refusal => self.refusal_hint_open = false,
                    relay::HintKind::NotificationsOff => self.notifications_off_open = false,
                }
                self.relay.hint_fired(kind, now);
            }
        }
    }

    /// Visibility was decided: the loop must flush the terminal's input and report
    /// the reader's read-start counter before any further input is classified.
    pub(crate) fn wants_input_flush(&self) -> bool {
        self.relay.wants_input_flush()
    }

    pub(crate) fn input_flushed(&mut self, epoch: u64, now: Instant) {
        self.relay.input_flushed(epoch, now);
        self.trace_phase();
    }

    /// Spawn the conditional grant, bounded by the socket's own mutation timeout.
    /// The task is never aborted: a grant the user authorized may finish after its
    /// prompt closed (R29).
    pub(crate) fn start_grant(
        &self,
        request: relay::GrantRequest,
    ) -> tokio::task::JoinHandle<GrantDone> {
        let allowances = Arc::clone(&self.feed.allowances);
        let refusals = Arc::clone(&self.feed.refusals);
        let generation = self.relay.generation();
        let now_ms = crate::refusal::feed::now_ms();
        tokio::spawn(async move {
            let task = tokio::spawn(async move {
                allowances
                    .grant_unless_answered(&refusals, &request.entry_id, request.scope, now_ms)
                    .await
            });
            let outcome = match tokio::time::timeout(PROMPT_GRANT_WAIT, task).await {
                Ok(Ok(grant)) => GrantOutcome::Settled(grant),
                Ok(Err(error)) => GrantOutcome::Lost(format!("{error}")),
                Err(_) => GrantOutcome::Unconfirmed,
            };
            GrantDone {
                generation,
                outcome,
            }
        })
    }

    pub(crate) fn guest_output(&mut self, bytes: Vec<u8>, now: Instant) {
        self.relay.guest_output(bytes, now);
        self.trace_phase();
    }

    pub(crate) fn may_receive_guest_output(&self) -> bool {
        self.relay.may_receive_guest_output()
    }

    pub(crate) fn wants_host_input(&self) -> bool {
        self.relay.wants_host_input()
    }

    pub(crate) fn host_input(
        &mut self,
        chunk: relay::HostChunk,
        now: Instant,
    ) -> relay::InputRoute {
        let route = self.relay.host_input(chunk, now);
        self.trace_phase();
        route
    }

    pub(crate) fn take_outbound_if(
        &mut self,
        ready: impl Fn(&relay::Outbound) -> bool,
    ) -> Option<relay::Outbound> {
        self.relay.take_outbound_if(ready)
    }

    /// The hint route for one line, for the pump's delivery wrapper: the relay marks
    /// the line written when the writer accepts its frame (M9).
    pub(crate) fn hint_route(&self, kind: relay::HintKind) -> Option<HintRelay> {
        self.relay.hint_route(kind)
    }

    /// The bytes of one line, for the drain's tail: the kind names which line, and
    /// the route frames it.
    pub(crate) fn hint_bytes(&self, kind: relay::HintKind) -> Option<Vec<u8>> {
        self.relay.hint_bytes(kind)
    }

    /// The writer took one line's bytes and confirmed them: nothing is owed to
    /// stderr for it, so the epilogue must not print it again.
    pub(crate) fn hint_delivered(&self, kind: relay::HintKind) {
        if let Some(hint) = self.relay.hint_route(kind) {
            let _ = hint.take();
        }
    }

    /// The pump handed one outbound item to the writer. Only a result frame cares:
    /// its 1.5 s starts now (R20).
    pub(crate) fn frame_taken(&mut self, now: Instant) {
        self.relay.frame_taken(now);
    }

    pub(crate) fn written(&mut self, generation: u64, now: Instant) {
        self.relay.written(generation, now);
        self.trace_phase();
    }

    pub(crate) fn granted(&mut self, done: GrantDone, now: Instant) {
        match done.outcome {
            GrantOutcome::Settled(grant) => self.relay.granted(done.generation, grant, now),
            GrantOutcome::Unconfirmed => self.relay.grant_unconfirmed(done.generation, now),
            GrantOutcome::Lost(reason) => {
                tracing::debug!(
                    target: "agent_vm::access_prompt",
                    generation = done.generation,
                    reason,
                    "the prompt's grant task ended without a result"
                );
                self.relay.grant_unconfirmed(done.generation, now);
            }
        }
        self.trace_phase();
    }

    pub(crate) fn resized(&mut self, size: Size, now: Instant) {
        self.relay.resized(size, now);
        self.trace_phase();
    }

    pub(crate) fn input_ended(&mut self, now: Instant) {
        self.relay.input_ended(now);
        self.trace_phase();
    }

    /// Guest exited: refuse any open question and return the owed frames in wire
    /// order (§6.3).
    pub(crate) fn finish(&mut self, _now: Instant) -> Vec<relay::OutputItem> {
        let (owed, grants) = self.relay.finish();
        // A grant the user already answered is not cancelled by the session ending:
        // its task keeps running, and a project record it writes late is stated by
        // R29. The handle is dropped; the task is detached on purpose.
        for request in grants {
            drop(self.start_grant(request));
        }
        self.trace_phase();
        owed
    }

    /// Every end, from the epilogue: hand on any signal the loop has not drained,
    /// detach both hint routes and return the lines still owed to stderr (at most
    /// two, one per kind). Writes nothing itself.
    pub(crate) fn abandon(&mut self) -> Vec<&'static str> {
        self.drain_signals();
        let mut owed = Vec::new();
        for kind in relay::HintKind::ALL {
            // The relay marks a line written the moment it queues today's bytes, so
            // `detach` is true only for a line that never reached the writer.
            if let Some(hint) = self.relay.take_hint(kind) {
                let line = hint.line();
                if hint.detach() {
                    owed.push(line);
                }
            }
        }
        owed
    }

    fn trace_phase(&self) {
        tracing::debug!(
            target: "agent_vm::access_prompt",
            phase = self.relay.phase_name(),
            generation = self.relay.generation(),
            held_bytes = self.relay.held_bytes(),
            waiting = self.relay.waiting_len(),
            "access prompt"
        );
    }
}

/// One feed half's next event, parked while that half is closed.
async fn recv_or_park<T: Clone>(
    open: bool,
    receiver: &mut broadcast::Receiver<T>,
) -> Result<T, broadcast::error::RecvError> {
    if open {
        receiver.recv().await
    } else {
        std::future::pending().await
    }
}

async fn wait_for_hint(hint: Option<crate::refusal::feed::HintRelay>) {
    match hint {
        Some(hint) => hint.fired().await,
        None => std::future::pending().await,
    }
}

/// Whether stderr is the **same** terminal as stdout.
///
/// That is the condition for routing the hint through the relay's writer: a hint on
/// a different terminal (or a file) must go where it went before, or the user would
/// look at the wrong screen for it.
fn stderr_is_stdout_terminal() -> bool {
    if !std::io::IsTerminal::is_terminal(&std::io::stderr()) {
        return false;
    }
    // SAFETY: `fstat` only writes into the two `stat` values, both live locals of
    // the right type, and each names a descriptor this process owns.
    unsafe {
        let mut error: libc::stat = std::mem::zeroed();
        let mut output: libc::stat = std::mem::zeroed();
        if libc::fstat(libc::STDERR_FILENO, &mut error) != 0 {
            return false;
        }
        if libc::fstat(libc::STDOUT_FILENO, &mut output) != 0 {
            return false;
        }
        error.st_dev == output.st_dev && error.st_rdev == output.st_rdev
    }
}

/// How long a spawned grant may take before the prompt calls it unconfirmed: the
/// socket's own mutation bound, named once.
pub(crate) const PROMPT_GRANT_WAIT: Duration = crate::session_control::MUTATION_TIMEOUT;

#[cfg(test)]
mod tests;
