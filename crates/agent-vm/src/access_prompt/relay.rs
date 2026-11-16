//! The takeover lifecycle, sans I/O (§6.2): phases, the hold, the queue, the
//! typing guard's use and the frames it asks the writer to write.
//!
//! Everything here is synchronous and takes an `Instant`, so a test drives exact
//! timelines and the session loop's branches stay thin. The relay never writes, never
//! grants and never decides whether a frame may still reach the terminal — that is
//! the writer's ledger (`direct_pty/ledger.rs`), which refuses a frame of a
//! generation that no longer owns the screen.
//!
//! # The phases, and what each one may do
//!
//! | phase | host input | guest output |
//! |---|---|---|
//! | `Idle` | to the guest | forwarded |
//! | `Cutting` | to the guest | forwarded up to the last safe boundary, held after |
//! | every other | consumed by the prompt | held |
//!
//! One takeover asks one question (I6). After its leave is confirmed the relay is
//! `Idle` for [`Timings::release_gap`] before the next question may start, so a guest
//! that keeps meeting refusals still gets its terminal back between questions.
//!
//! # Why one question per takeover
//!
//! Showing the next queued question without releasing the terminal let a
//! replenished queue hold it indefinitely (the first review's finding 8). Each
//! question now gets its own takeover, its own typing guard and its own 2 s of
//! guest time.

use std::collections::VecDeque;

use tokio::time::Instant;

use crate::access_prompt::Size;
use crate::access_prompt::guard::{self, Answer, KeyFacts};
use crate::access_prompt::input::{InputScan, Position};
use crate::access_prompt::screen::{self, OfferText, ResultView, Status, View};
use crate::access_prompt::vt::{RestorableModes, Screen, VtState};
use crate::allowances::{GrantScope, Offer, PromptGrant};
use crate::egress_policy::Allowance;

/// One refusal that may become a question. Built by the facade, which applies
/// the eligibility rules (R4, R5, R7); the relay only decides *when*.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Candidate {
    pub(crate) entry_id: String,
    pub(crate) destination: Allowance,
    pub(crate) cell: screen::Cell,
    pub(crate) guest_named: bool,
    pub(crate) count: u64,
    pub(crate) offer: Offer,
    /// The port the destination names, for the #491 label.
    pub(crate) port: Option<u16>,
}

/// One question, with its latest count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Item {
    pub(crate) entry_id: String,
    pub(crate) destination: Allowance,
    pub(crate) cell: screen::Cell,
    pub(crate) guest_named: bool,
    pub(crate) count: u64,
    pub(crate) offer: Offer,
    pub(crate) port: Option<u16>,
}

impl Item {
    pub(super) fn from_candidate(candidate: Candidate) -> Self {
        Self {
            entry_id: candidate.entry_id,
            destination: candidate.destination,
            cell: candidate.cell,
            guest_named: candidate.guest_named,
            count: candidate.count,
            offer: candidate.offer,
            port: candidate.port,
        }
    }

    pub(super) fn view(&self, session: &str, waiting: u64, overflow: u64) -> View {
        View {
            destination: self.cell.clone(),
            guest_named: self.guest_named,
            count: self.count,
            session: session.to_owned(),
            offer: match self.offer {
                Offer::SessionOrProject => OfferText::SessionOrProject,
                Offer::ProjectNextLaunch => OfferText::ProjectNextLaunch { port: self.port },
            },
            waiting,
            overflow,
        }
    }
}

/// One grant, named by the refusal ID so the handler resolves it exactly as the
/// socket does (C6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GrantRequest {
    pub(crate) entry_id: String,
    pub(crate) scope: GrantScope,
    pub(crate) destination: Allowance,
}

/// One frame for the writer, mapped 1:1 onto its `OutputFrame`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum OutputItem {
    Data(Vec<u8>),
    /// The session's one-time hint. A distinct frame so nothing has to identify it
    /// by comparing bytes (a guest frame could be byte-identical), and so the relay
    /// can mark it delivered only when the writer accepts it (M9/N6).
    Hint,
    Takeover {
        generation: u64,
        step: Step,
        bytes: Vec<u8>,
    },
}

/// Which takeover frame this is. `Enter`/`Leave` are the two the writer confirms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    Enter { screen: Screen },
    Redraw,
    Leave,
}

/// What the session loop must do next, in wire order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Outbound {
    Frame(OutputItem),
    Grant(GrantRequest),
    Nudge,
}

/// Where a host read went.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum InputRoute {
    Guest(Vec<u8>),
    Consumed,
}

/// One host read, with the two stamps the guard needs: `epoch` is taken
/// **before** `read(2)`, `read_at` after it returns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HostChunk {
    pub(crate) bytes: Vec<u8>,
    pub(crate) epoch: u64,
    pub(crate) read_at: Instant,
}

/// How long a question waits before it is refused (R18) — and how long an queued
/// prompt that never became visible is left waiting.
pub(crate) const PROMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
/// How long the grant's sentence is shown (R20).
pub(crate) const RESULT_LINGER: std::time::Duration = std::time::Duration::from_millis(1500);
/// How long the terminal is the guest's before the next question (I4, R15).
pub(crate) const RELEASE_GAP: std::time::Duration = std::time::Duration::from_secs(2);
/// How long a forced cut waits for a safe boundary (R9).
pub(crate) const CUT_DEADLINE: std::time::Duration = std::time::Duration::from_millis(500);
/// How long the terminal has to confirm it drew the prompt (R17, §4.4).
pub(crate) const CPR_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

/// Every duration the relay uses, so a test can shrink them and the production
/// values live in one value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Timings {
    pub(crate) cut: std::time::Duration,
    pub(crate) cpr_wait: std::time::Duration,
    pub(crate) typing_quiet: std::time::Duration,
    pub(crate) prompt_timeout: std::time::Duration,
    pub(crate) result_linger: std::time::Duration,
    pub(crate) release_gap: std::time::Duration,
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            cut: CUT_DEADLINE,
            cpr_wait: CPR_WAIT,
            typing_quiet: std::time::Duration::from_millis(guard::TYPING_QUIET_MS),
            prompt_timeout: PROMPT_TIMEOUT,
            result_linger: RESULT_LINGER,
            release_gap: RELEASE_GAP,
        }
    }
}

/// Why a prompt was closed (R18, R21, R23, R25).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Close {
    Refused,
    StopAsking,
    TimedOut,
    AnsweredElsewhere,
    InputEnded,
    TooSmall,
}

/// Exactly the rows of §6.2.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Phase {
    Idle {
        /// When the leave was confirmed; `None` means no takeover has finished yet,
        /// so a waiting question may start at once.
        released_at: Option<Instant>,
    },
    Cutting {
        g: u64,
        since: Instant,
    },
    Entering {
        g: u64,
        queued_at: Instant,
        close: Option<Close>,
    },
    Confirming {
        g: u64,
        queued_at: Instant,
        written_at: Instant,
        close: Option<Close>,
    },
    Asking {
        g: u64,
        visible_at: Instant,
        /// The reader's read-start counter at the flush that followed visibility.
        visible_epoch: Option<u64>,
        ready_shown: bool,
    },
    Granting {
        g: u64,
    },
    Lingering {
        g: u64,
        /// The result frame's hand-over instant (finding 10): the 1.5 s starts when
        /// the writer is given the result, not when it was queued.
        until: Option<Instant>,
    },
    Restoring {
        g: u64,
    },
}

impl Phase {
    fn generation(&self) -> Option<u64> {
        match self {
            Self::Idle { .. } => None,
            Self::Cutting { g, .. }
            | Self::Entering { g, .. }
            | Self::Confirming { g, .. }
            | Self::Asking { g, .. }
            | Self::Granting { g }
            | Self::Lingering { g, .. }
            | Self::Restoring { g } => Some(*g),
        }
    }

    /// Whether the takeover owns the terminal: host input is consumed, guest output
    /// held (I2).
    fn owns_terminal(&self) -> bool {
        !matches!(self, Self::Idle { .. } | Self::Cutting { .. })
    }
}

/// The relay.
pub(crate) struct Relay {
    vt: VtState,
    input: InputScan,
    phase: Phase,
    generation: u64,
    shown: Option<Item>,
    screen: Option<RestorableModes>,
    waiting: VecDeque<Item>,
    /// Destinations past the waiting cap, one entry each: a repeat of an overflowed
    /// destination must not inflate the count (finding 10).
    overflowed: Vec<Allowance>,
    suppressed: Vec<Allowance>,
    /// R29: destinations whose grant outlived its 40 s wait; not asked again.
    settling: Vec<Allowance>,
    held: Vec<Vec<u8>>,
    held_bytes: usize,
    outbound: VecDeque<Outbound>,
    size: Size,
    session: String,
    last_input: Option<Instant>,
    input_open: bool,
    /// §4.4: `false` after one request went unanswered, so the session stops asking.
    cpr_answers: bool,
    /// The status line the question currently shows, so a redraw keeps it (R17).
    status: Status,
    /// The grant's result, while it is on screen (R20). Kept so a resize redraws the
    /// result instead of the question.
    result: Option<ResultView>,
    /// Whether the result's 1.5 s has started (it starts once, at hand-over).
    linger_started: bool,
    /// The position the enter frame asked the terminal to report (R17). Fixed when
    /// the frame is queued: recomputing it after a resize would expect a position no
    /// request named, cost the 1 s fallback and turn cursor-position replies off for
    /// the session (finding 20).
    asked_position: Option<Position>,
    /// A hint is owed to the relay and must be written at the next safe boundary
    /// before any prompt frame (R26).
    hint_pending: bool,
    /// The session's hint route, when stderr is the same terminal. The relay is what
    /// marks the hint delivered: it is the only place that knows when today's bytes
    /// were handed to the writer.
    hint: Option<crate::refusal::feed::HintRelay>,
    /// The hint's bytes are queued in `outbound` but have not been handed over.
    hint_queued: bool,
    /// The one hint this session gets has been emitted (or had no route here).
    hint_done: bool,
    /// Set when visibility was decided; the loop flushes the terminal's input and
    /// reports the reader's counter before any further input is classified.
    flush_pending: bool,
    /// The scope the shown question's grant was asked for, so its sentence reads as
    /// the CLI's would.
    grant_scope: Option<GrantScope>,
    /// D3-b's counter: consecutive timeouts with no host input. Inert until the
    /// operator adopts D3-b; the rule below never stops prompting.
    unanswered_in_a_row: u8,
    timings: Timings,
}

impl Relay {
    pub(crate) fn new(
        session: String,
        size: Size,
        timings: Timings,
        hint: Option<crate::refusal::feed::HintRelay>,
    ) -> Self {
        Self {
            vt: VtState::new(),
            input: InputScan::new(),
            phase: Phase::Idle { released_at: None },
            generation: 0,
            shown: None,
            screen: None,
            waiting: VecDeque::new(),
            overflowed: Vec::new(),
            suppressed: Vec::new(),
            settling: Vec::new(),
            held: Vec::new(),
            held_bytes: 0,
            outbound: VecDeque::new(),
            size,
            session,
            last_input: None,
            input_open: true,
            cpr_answers: true,
            status: Status::StopTyping,
            result: None,
            linger_started: false,
            asked_position: None,
            hint_pending: false,
            hint,
            hint_queued: false,
            hint_done: false,
            flush_pending: false,
            grant_scope: None,
            unanswered_in_a_row: 0,
            timings,
        }
    }

    // ------------------------------------------------------------- accessors ---

    pub(crate) fn phase_name(&self) -> &'static str {
        match self.phase {
            Phase::Idle { .. } => "idle",
            Phase::Cutting { .. } => "cutting",
            Phase::Entering { .. } => "entering",
            Phase::Confirming { .. } => "confirming",
            Phase::Asking { .. } => "asking",
            Phase::Granting { .. } => "granting",
            Phase::Lingering { .. } => "lingering",
            Phase::Restoring { .. } => "restoring",
        }
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn held_bytes(&self) -> usize {
        self.held_bytes
    }

    pub(crate) fn queued_frames(&self) -> usize {
        self.outbound
            .iter()
            .filter(|item| matches!(item, Outbound::Frame(_)))
            .count()
    }

    /// The hint route, for the pump's delivery wrapper (M9).
    pub(crate) fn hint_route(&self) -> Option<crate::refusal::feed::HintRelay> {
        self.hint.clone()
    }

    pub(crate) fn wants_host_input(&self) -> bool {
        self.phase.owns_terminal()
    }

    /// The one bound on the hold (R14): the relay may take another SDK event while
    /// what it holds stays under the cap.
    pub(crate) fn may_receive_guest_output(&self) -> bool {
        guard::may_hold(self.held_bytes) && self.queued_frames() == 0
    }

    pub(crate) fn wants_input_flush(&self) -> bool {
        self.flush_pending
    }

    pub(crate) fn waiting_len(&self) -> usize {
        self.waiting.len()
    }

    // ---------------------------------------------------------------- input ---

    /// The terminal's pending input was flushed; `epoch` is the reader's read-start
    /// counter at the flush. Only a read that *started* after it can answer.
    pub(crate) fn input_flushed(&mut self, epoch: u64, _now: Instant) {
        if !self.flush_pending {
            return;
        }
        self.flush_pending = false;
        if let Phase::Asking { visible_epoch, .. } = &mut self.phase {
            *visible_epoch = Some(epoch);
        }
    }

    /// One host read. The scan runs in every phase, so paste framing survives a
    /// takeover's start and end (§4.4).
    pub(crate) fn host_input(&mut self, chunk: HostChunk, now: Instant) -> InputRoute {
        if chunk.bytes.is_empty() {
            return InputRoute::Consumed;
        }
        let position = self.cpr_position();
        let scan = self.input.scan(&chunk.bytes, position);
        if !self.phase.owns_terminal() {
            return InputRoute::Guest(chunk.bytes);
        }
        if matches!(self.phase, Phase::Confirming { close: None, .. }) && scan.cpr_at_prompt {
            // The terminal confirmed it processed everything before our request.
            // The reply is not input: it becomes visible, and the flush follows.
            self.become_visible(now);
            return InputRoute::Consumed;
        }
        // The quiet time is measured against the input *before* this read; every
        // host read during a takeover then restarts the guard, whatever the scan
        // made of it (a lone Esc, an arrow key, a paste marker, an unrecognised
        // sequence). The one exception is the reply that made the prompt visible,
        // which returned above: it is the terminal's, not the user's (R17).
        let quiet = match self.phase {
            Phase::Asking { visible_at, .. } => self.quiet_ms(chunk.read_at, visible_at),
            _ => 0,
        };
        let answer = match self.phase.clone() {
            Phase::Asking {
                g,
                visible_epoch,
                ready_shown,
                ..
            } => {
                let answer = guard::answer_of(KeyFacts {
                    chunk_len: chunk.bytes.len(),
                    byte: chunk.bytes[0],
                    read_after_visible: visible_epoch.is_some_and(|epoch| chunk.epoch > epoch),
                    quiet_ms: quiet,
                    // A read that continues a sequence from an earlier read is never
                    // an answer, even when it is the single byte `s`.
                    in_paste: scan.in_paste || scan.continued,
                    session_offered: self
                        .shown
                        .as_ref()
                        .is_some_and(|item| item.offer == Offer::SessionOrProject),
                });
                match answer {
                    Some(answer) => Some((g, answer)),
                    None => {
                        if ready_shown
                            && self.redraw_status(Status::StopTyping)
                            && let Phase::Asking { ready_shown, .. } = &mut self.phase
                        {
                            *ready_shown = false;
                        }
                        None
                    }
                }
            }
            _ => None,
        };
        self.last_input = Some(chunk.read_at);
        self.unanswered_in_a_row = 0;
        if let Some((g, answer)) = answer {
            self.answer(g, answer);
        }
        InputRoute::Consumed
    }

    fn cpr_position(&self) -> Option<Position> {
        match self.phase {
            Phase::Confirming { close: None, .. } if self.cpr_answers => self.asked_position,
            _ => None,
        }
    }

    fn quiet_ms(&self, read_at: Instant, visible_at: Instant) -> u64 {
        let since = self
            .last_input
            .map_or(visible_at, |last| last.max(visible_at));
        read_at
            .saturating_duration_since(since)
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }

    fn become_visible(&mut self, now: Instant) {
        if let Phase::Confirming {
            g,
            written_at,
            close: None,
            ..
        } = self.phase
        {
            if now < written_at {
                return;
            }
            // Asking waits for the flush; the visible instant is now, which is the
            // earliest a read after the flush can be measured from.
            self.phase = Phase::Asking {
                g,
                visible_at: now,
                visible_epoch: None,
                ready_shown: false,
            };
            self.flush_pending = true;
            self.unanswered_in_a_row = 0;
        }
    }

    fn answer(&mut self, g: u64, answer: Answer) {
        let Some(item) = self.shown.clone() else {
            return;
        };
        match answer {
            Answer::Session | Answer::Project => {
                let scope = match answer {
                    Answer::Session => GrantScope::Session,
                    _ => GrantScope::Project,
                };
                self.grant_scope = Some(scope);
                // The "allowing..." redraw comes before the grant, so a queued grant
                // can never delay the one frame that tells the user their key landed
                // (M6). That redraw can also *close* the question (`TooSmall`); if it
                // did, the answer is dropped: granting into a closing takeover queued a
                // second Leave the writer refuses, and the session ended with a writer
                // error (round 3, A R2-1/B B1).
                if !self.redraw_status(Status::Allowing) {
                    return;
                }
                self.outbound.push_back(Outbound::Grant(GrantRequest {
                    entry_id: item.entry_id.clone(),
                    scope,
                    destination: item.destination.clone(),
                }));
                self.phase = Phase::Granting { g };
            }
            Answer::Refuse => self.close(Close::Refused),
            Answer::StopAsking => {
                self.suppressed.push(item.destination.clone());
                self.close(Close::StopAsking);
            }
        }
    }

    // --------------------------------------------------------------- output ---

    /// Guest bytes the SDK delivered.
    pub(crate) fn guest_output(&mut self, bytes: Vec<u8>, now: Instant) {
        if bytes.is_empty() {
            return;
        }
        match self.phase.clone() {
            Phase::Idle { .. } => {
                self.vt.advance(&bytes);
                self.outbound
                    .push_back(Outbound::Frame(OutputItem::Data(bytes)));
                // The hint goes out *at* the boundary these bytes reached, so it
                // cannot be written inside a guest sequence.
                self.emit_hint_if_due();
            }
            Phase::Cutting { g, .. } => match self.vt.last_safe_cut(&bytes) {
                Some(cut) => {
                    let (forward, rest) = bytes.split_at(cut);
                    self.vt.advance(forward);
                    if !forward.is_empty() {
                        self.outbound
                            .push_back(Outbound::Frame(OutputItem::Data(forward.to_vec())));
                    }
                    self.hold(rest.to_vec());
                    self.begin_enter(g, now, false);
                }
                None => {
                    self.vt.advance(&bytes);
                    self.outbound
                        .push_back(Outbound::Frame(OutputItem::Data(bytes)));
                    self.emit_hint_if_due();
                }
            },
            // `Restoring`: the leave is queued (or being written); the guest's bytes
            // follow it in FIFO order, tracked as they go. Holding them here was the
            // split behind three defects: output was dropped when the leave's
            // confirmation cleared the hold, and the tracker never saw the modes the
            // guest set during the takeover (§6.2, R8/R15).
            Phase::Restoring { .. } => self.release(bytes),
            _ => self.hold(bytes),
        }
    }

    /// Forward one frame to the writer and advance the tracker over it.
    ///
    /// One helper for every path that hands the terminal bytes it has not seen yet:
    /// the dispatch and `Cutting` paths above (which advance as they forward), the
    /// `Restoring` path, the held frames released behind a leave, the drain's tail
    /// and the decline path. Advancing exactly once in commit order is what keeps
    /// the tracker's modes and parse state equal to the terminal's (R9, R10, R12).
    fn release(&mut self, frame: Vec<u8>) {
        self.vt.advance(&frame);
        self.outbound
            .push_back(Outbound::Frame(OutputItem::Data(frame)));
        self.emit_hint_if_due();
    }

    fn hold(&mut self, bytes: Vec<u8>) {
        // The receive gate keeps the hold under the cap and clamps each event to the
        // SDK's own bound, so the kernel applies; anything else is counted exactly
        // rather than allowed to wrap.
        self.held_bytes = if self.held_bytes < guard::HELD_OUTPUT_BYTES
            && bytes.len() <= guard::MAX_SDK_EVENT_BYTES
        {
            guard::held_after(self.held_bytes, bytes.len())
        } else {
            self.held_bytes.saturating_add(bytes.len())
        };
        self.held.push(bytes);
    }

    fn emit_hint_if_due(&mut self) {
        if !self.hint_pending {
            return;
        }
        // No route (stderr is not this terminal): the hint already went to stderr,
        // so the relay has nothing to do with it.
        let Some(hint) = &self.hint else {
            self.hint_pending = false;
            self.hint_done = true;
            return;
        };
        let _ = hint;
        if !self.phase.owns_terminal() && self.vt.at_safe_boundary() {
            // Queue it exactly once, as its own frame. It is marked written only when
            // the writer accepts it; a frame queued and then discarded by a forced
            // end still belongs to stderr, and the epilogue prints it.
            self.outbound.push_back(Outbound::Frame(OutputItem::Hint));
            self.hint_pending = false;
            self.hint_queued = true;
            self.hint_done = true;
        }
    }

    // ----------------------------------------------------------- the queue ---

    /// A refusal worth asking about. The facade already applied R4/R5/R7; this adds
    /// the relay's own state (suppressed, settling) and the queue rules (R22).
    pub(crate) fn offer(&mut self, candidate: Candidate, now: Instant) {
        if self.suppressed.contains(&candidate.destination)
            || self.settling.contains(&candidate.destination)
        {
            return;
        }
        if let Some(shown) = &mut self.shown
            && shown.destination == candidate.destination
        {
            shown.count = candidate.count.max(shown.count);
            self.redraw_current();
            return;
        }
        if let Some(existing) = self
            .waiting
            .iter_mut()
            .find(|item| item.destination == candidate.destination)
        {
            existing.count = candidate.count.max(existing.count);
            return;
        }
        if guard::may_queue(self.waiting.len()) {
            self.waiting.push_back(Item::from_candidate(candidate));
        } else if !self.overflowed.contains(&candidate.destination) {
            self.overflowed.push(candidate.destination);
        }
        // The count is part of the question (R22): a new waiting destination or a
        // new overflow is drawn, with the status the question is showing.
        if self.phase.owns_terminal() {
            self.redraw_current();
        }
        self.maybe_start(now);
    }

    /// An answer given elsewhere reached the relay (a wakeup or a lag case).
    pub(crate) fn answered(&mut self, destination: &Allowance, now: Instant) {
        self.waiting.retain(|item| item.destination != *destination);
        // `settling` is deliberately **not** pruned: R29 says a destination whose
        // grant outlived its wait is not prompted again in this session, even after
        // the late grant lands and its wakeup arrives (M10/N7).
        let shown_answered = self
            .shown
            .as_ref()
            .is_some_and(|item| item.destination == *destination);
        if shown_answered {
            match self.phase.clone() {
                // Nothing is queued yet: back to Idle with no frame owed.
                Phase::Idle { .. } => {}
                Phase::Cutting { .. } => {
                    self.drop_shown(now);
                }
                Phase::Entering { g, close: None, .. } => {
                    self.close_phase(Close::AnsweredElsewhere, g)
                }
                Phase::Confirming { g, close: None, .. } => {
                    self.close_phase(Close::AnsweredElsewhere, g)
                }
                Phase::Asking { .. } => self.close(Close::AnsweredElsewhere),
                // `Granting`/`Lingering` show the prompt's own answer; a wakeup
                // changes nothing (I8, R20).
                Phase::Granting { .. } | Phase::Lingering { .. } | Phase::Restoring { .. } => {}
                _ => {}
            }
        }
    }

    /// The destinations the relay is still holding: the shown question first, then
    /// the queue. Used to re-check an answer set that can no longer be trusted (a
    /// lagged or closed answers channel) instead of closing a question on a guess.
    pub(crate) fn pending_destinations(&self) -> Vec<Allowance> {
        let mut destinations = Vec::new();
        if let Some(shown) = &self.shown
            && self.phase.owns_terminal()
        {
            destinations.push(shown.destination.clone());
        }
        destinations.extend(self.waiting.iter().map(|item| item.destination.clone()));
        destinations
    }

    /// A destination whose grant outlived its 40 s wait is not asked again (R29).
    pub(crate) fn settle(&mut self, destination: Allowance) {
        if !self.settling.contains(&destination) {
            self.settling.push(destination);
        }
    }

    // ------------------------------------------------------------ lifecycle ---

    /// Start a takeover if one may start now.
    fn maybe_start(&mut self, now: Instant) {
        let Phase::Idle { released_at } = self.phase else {
            return;
        };
        if !self.input_open || self.waiting.is_empty() {
            return;
        }
        if let Some(released_at) = released_at
            && now < released_at + self.timings.release_gap
        {
            return;
        }
        // The head becomes the question. Whether it can be asked is decided at the
        // cut, where the tracker has seen everything `Cutting` forwards (R9–R12).
        let Some(item) = self.waiting.pop_front() else {
            return;
        };
        self.generation += 1;
        let g = self.generation;
        self.shown = Some(item);
        self.phase = Phase::Cutting { g, since: now };
        // A boundary already reached takes over at once.
        if self.vt.at_safe_boundary() {
            self.begin_enter(g, now, false);
        }
    }

    pub(super) fn current_view(&self) -> View {
        let waiting = self.waiting.len() as u64;
        match &self.shown {
            Some(item) => item.view(&self.session, waiting, self.overflowed.len() as u64),
            None => View {
                destination: screen::Cell::from_guest(""),
                guest_named: false,
                count: 0,
                session: self.session.clone(),
                offer: OfferText::SessionOrProject,
                waiting,
                overflow: self.overflowed.len() as u64,
            },
        }
    }

    /// Decline the takeover at the cut: the held bytes are the guest's and go out
    /// first, in order, then the question is left to `access`.
    fn decline(&mut self, now: Instant) {
        for frame in std::mem::take(&mut self.held) {
            self.release(frame);
        }
        self.held_bytes = 0;
        self.drop_shown(now);
    }

    fn drop_shown(&mut self, now: Instant) {
        self.shown = None;
        self.screen = None;
        self.result = None;
        self.linger_started = false;
        self.status = Status::StopTyping;
        self.asked_position = None;
        self.phase = Phase::Idle {
            released_at: Some(now),
        };
    }

    /// The takeover's screen is ready: queue `Enter` and become `Entering`.
    ///
    /// The tracker is read **here**, after everything `Cutting` forwarded and after
    /// any `CAN`, so a mode the guest set while the stream was being cut is the one
    /// the prompt saves and restores. A state the tracker cannot know, or a question
    /// that no longer fits, declines — and a decline releases every held byte in
    /// order before the relay returns to `Idle` (R8, R10, R25).
    fn begin_enter(&mut self, g: u64, now: Instant, forced_cut: bool) {
        let Some(modes) = self.vt.modes().restorable() else {
            self.decline(now);
            return;
        };
        let view = self.current_view();
        let Some(laid) = screen::layout_with(&view, self.size, self.status) else {
            self.decline(now);
            return;
        };
        // Only now, with the takeover certain to be queued, does a forced cut abandon
        // the guest's half sequence: the `CAN` that does it is in this frame. Doing it
        // before the decision left the tracker at ground while the real terminal was
        // still inside the sequence (M7/N3).
        if forced_cut {
            self.vt.cancelled();
        }
        self.screen = Some(modes);
        let (bytes, _) = screen::enter(&modes, &laid, forced_cut, self.cpr_answers);
        // A hint that fired as the takeover was wanted goes first (R26) — but never
        // before a forced cut's `CAN`, which is the byte that ends the guest's stalled
        // sequence. Queued before it, the hint would be drawn as that sequence's
        // final bytes and lost; the leave's confirmation sends it (finding 9).
        if !forced_cut {
            self.emit_hint_if_due();
        }
        self.outbound
            .push_back(Outbound::Frame(OutputItem::Takeover {
                generation: g,
                step: Step::Enter {
                    screen: modes.screen,
                },
                bytes,
            }));
        self.result = None;
        self.linger_started = false;
        self.status = Status::StopTyping;
        self.asked_position = if self.cpr_answers {
            Some(Position {
                row: (laid.status_row() + 1) as u16,
                col: 3,
            })
        } else {
            None
        };
        self.phase = Phase::Entering {
            g,
            queued_at: now,
            close: None,
        };
    }

    /// The writer wrote the one outstanding `Enter` or `Leave` of this generation.
    pub(crate) fn written(&mut self, generation: u64, now: Instant) {
        let Some(current) = self.phase.generation() else {
            return;
        };
        if current != generation {
            return;
        }
        match self.phase.clone() {
            Phase::Entering {
                g,
                queued_at,
                close,
            } => match close {
                None => {
                    self.phase = Phase::Confirming {
                        g,
                        queued_at,
                        written_at: now,
                        close: None,
                    };
                }
                // Something closed the question while its enter was queued: the
                // leave follows the enter the writer just confirmed.
                Some(_) => self.queue_restore(g),
            },
            Phase::Restoring { .. } => {
                self.phase = Phase::Idle {
                    released_at: Some(now),
                };
                self.shown = None;
                self.screen = None;
                self.emit_hint_if_due();
                self.maybe_start(now);
            }
            _ => {}
        }
    }

    /// The prompt's own grant settled (or its wait expired).
    pub(crate) fn granted(&mut self, generation: u64, grant: PromptGrant, now: Instant) {
        let Phase::Granting { g } = self.phase else {
            return;
        };
        if g != generation {
            return;
        }
        let destination = self.shown.as_ref().map(|item| item.destination.clone());
        let view = match grant {
            PromptGrant::Reached(result) => {
                if let Some(destination) = &destination
                    && matches!(result, crate::allowances::GrantResult::NextLaunch { .. })
                {
                    self.settling.push(destination.clone());
                }
                let scope = self.grant_scope.unwrap_or(GrantScope::Session);
                let report = result.report(&format!("session {}", self.session), scope);
                let mut view = ResultView {
                    sentence: report.text,
                    undo: None,
                    retry: true,
                };
                if let Some(destination) = &destination {
                    view.undo = undo_command(&result, destination);
                }
                view
            }
            PromptGrant::AnsweredElsewhere => {
                let sentence = match &destination {
                    Some(destination) => format!(
                        "already answered elsewhere: {} (agent-vm access allowances)",
                        crate::config::escape_str(&destination.to_string())
                    ),
                    None => "already answered elsewhere (agent-vm access allowances)".to_owned(),
                };
                ResultView {
                    sentence,
                    undo: None,
                    retry: false,
                }
            }
        };
        self.result = Some(view);
        self.redraw_result();
        // From the moment the result is *queued*, the takeover has a deadline. The
        // pump moves it to the frame's acceptance (`frame_taken`); until then this
        // bound is what guarantees the takeover ends even if the frame never moves.
        self.phase = Phase::Lingering {
            g,
            until: Some(now + self.timings.result_linger),
        };
    }

    /// A grant that outlived its 40 s wait: say so and stop asking that destination.
    pub(crate) fn grant_unconfirmed(&mut self, generation: u64, now: Instant) {
        let Phase::Granting { g } = self.phase else {
            return;
        };
        if g != generation {
            return;
        }
        let view = ResultView {
            sentence: "the change was not confirmed; check `agent-vm access allowances`".to_owned(),
            undo: None,
            retry: false,
        };
        if let Some(destination) = self.shown.as_ref().map(|item| item.destination.clone()) {
            self.settle(destination);
        }
        self.result = Some(view);
        self.redraw_result();
        self.phase = Phase::Lingering { g, until: None };
        let _ = now;
    }

    /// Close the open question: queue `Leave`, then the held output, then a nudge.
    fn close(&mut self, why: Close) {
        let Some(g) = self.phase.generation() else {
            return;
        };
        self.close_phase(why, g);
    }

    fn close_phase(&mut self, why: Close, g: u64) {
        match self.phase.clone() {
            Phase::Entering {
                g: current,
                queued_at,
                close: None,
            } if current == g => {
                // The enter frame is queued but not written: the question waits for
                // its confirmation before the leave, so the writer keeps its order.
                self.phase = Phase::Entering {
                    g,
                    queued_at,
                    close: Some(why),
                };
            }
            Phase::Confirming {
                g: current,
                queued_at,
                written_at,
                close: None,
            } if current == g => {
                self.phase = Phase::Confirming {
                    g,
                    queued_at,
                    written_at,
                    close: Some(why),
                };
                self.queue_restore(g);
            }
            Phase::Asking { g: current, .. }
            | Phase::Granting { g: current }
            | Phase::Lingering { g: current, .. }
                if current == g =>
            {
                self.queue_restore(g);
            }
            _ => {}
        }
    }

    fn queue_restore(&mut self, g: u64) {
        let Some(modes) = self.screen else {
            self.phase = Phase::Restoring { g };
            return;
        };
        let (leave, _) = screen::leave(&modes);
        self.outbound
            .push_back(Outbound::Frame(OutputItem::Takeover {
                generation: g,
                step: Step::Leave,
                bytes: leave,
            }));
        for frame in std::mem::take(&mut self.held) {
            self.release(frame);
        }
        self.held_bytes = 0;
        if screen::nudges(modes.screen) {
            self.outbound.push_back(Outbound::Nudge);
        }
        self.result = None;
        self.linger_started = false;
        self.status = Status::StopTyping;
        self.asked_position = None;
        self.phase = Phase::Restoring { g };
    }

    /// The terminal was resized. A question that no longer fits is refused (R25); one
    /// that still fits is redrawn at the new size.
    pub(crate) fn resized(&mut self, size: Size, _now: Instant) {
        self.size = size;
        if !self.phase.owns_terminal() {
            self.emit_hint_if_due();
            return;
        }
        let view = self.current_view();
        match screen::layout_with(&view, size, self.status) {
            Some(_) => self.redraw_current(),
            None => self.close(Close::TooSmall),
        }
    }

    /// Host input ended (terminal EOF/EIO, or the guest closed its input): an open
    /// question is refused and no further prompt is shown (R23).
    pub(crate) fn input_ended(&mut self, _now: Instant) {
        self.input_open = false;
        self.waiting.clear();
        if self.phase.owns_terminal() {
            self.close(Close::InputEnded);
        }
    }

    /// The hint route, cloned for the facade's cancel-safe wait.
    pub(crate) fn hint_handle(&self) -> Option<crate::refusal::feed::HintRelay> {
        self.hint.clone()
    }

    /// Give the route back to the epilogue. `detach` then says whether a hint fired
    /// but never reached the writer, so the epilogue prints exactly that case.
    pub(crate) fn take_hint(&mut self) -> Option<crate::refusal::feed::HintRelay> {
        self.hint.take()
    }

    /// A hint fired and is owed to the relay (R26).
    pub(crate) fn hint_fired(&mut self, now: Instant) {
        if self.hint_done {
            return;
        }
        self.hint_pending = true;
        self.emit_hint_if_due();
        let _ = now;
    }

    // ------------------------------------------------------------- deadlines ---

    pub(crate) fn deadline(&self) -> Option<Instant> {
        match &self.phase {
            Phase::Idle { released_at } if !self.waiting.is_empty() && self.input_open => {
                released_at.map(|at| at + self.timings.release_gap)
            }
            Phase::Cutting { since, .. } => Some(*since + self.timings.cut),
            Phase::Entering {
                queued_at,
                close: None,
                ..
            } => Some(*queued_at + self.timings.prompt_timeout),
            Phase::Confirming {
                queued_at,
                written_at,
                close: None,
                ..
            } => Some(
                (*written_at + self.timings.cpr_wait).min(*queued_at + self.timings.prompt_timeout),
            ),
            Phase::Asking {
                visible_at,
                ready_shown,
                ..
            } => {
                let timeout = *visible_at + self.timings.prompt_timeout;
                Some(if *ready_shown {
                    timeout
                } else {
                    timeout.min(self.ready_at())
                })
            }
            // A `Lingering` whose result frame has not been accepted yet still has the
            // deadline `granted` set; one with none (defensively) fires now.
            Phase::Lingering { until, .. } => Some(until.unwrap_or_else(Instant::now)),
            // `Granting` is bounded by the session loop's slot; `Restoring` by the
            // writer's confirmation.
            _ => None,
        }
    }

    fn ready_at(&self) -> Instant {
        match self.phase {
            Phase::Asking { visible_at, .. } => {
                let since = self
                    .last_input
                    .map_or(visible_at, |last| last.max(visible_at));
                since + self.timings.typing_quiet
            }
            _ => Instant::now(),
        }
    }

    /// Perform exactly the transition [`Self::deadline`] named (I5).
    pub(crate) fn handle_deadline(&mut self, now: Instant) {
        match self.phase.clone() {
            Phase::Idle { released_at } => {
                if released_at.is_some_and(|at| now >= at + self.timings.release_gap) {
                    self.maybe_start(now);
                }
            }
            Phase::Cutting { g, since } => {
                if now >= since + self.timings.cut {
                    // `begin_enter` cancels the tracker only once the takeover is
                    // certain: a decline sends no `CAN`, so cancelling here would
                    // leave the tracker at ground while the terminal is still inside
                    // the guest's sequence (M7/N3).
                    self.begin_enter(g, now, true);
                }
            }
            Phase::Entering { close: None, .. } => {
                self.close(Close::TimedOut);
            }
            Phase::Confirming {
                close: None,
                written_at,
                queued_at,
                ..
            } => {
                if now >= queued_at + self.timings.prompt_timeout {
                    self.close(Close::TimedOut);
                } else if now >= written_at + self.timings.cpr_wait {
                    // No reply: visibility is the write plus one wait, and the
                    // session stops asking.
                    self.cpr_answers = false;
                    self.become_visible(now);
                }
            }
            Phase::Asking {
                visible_at,
                ready_shown,
                ..
            } => {
                if now >= visible_at + self.timings.prompt_timeout {
                    self.unanswered_in_a_row = self.unanswered_in_a_row.saturating_add(1);
                    self.close(Close::TimedOut);
                } else if !ready_shown && now >= self.ready_at() {
                    // Only a *drawn* "ready" counts as shown (M2/N2).
                    if self.redraw_status(Status::Ready)
                        && let Phase::Asking { ready_shown, .. } = &mut self.phase
                    {
                        *ready_shown = true;
                    }
                }
            }
            Phase::Lingering { g, until } if until.is_none_or(|until| now >= until) => {
                self.queue_restore(g);
            }
            _ => {}
        }
    }

    // -------------------------------------------------------------- outbound ---

    pub(crate) fn take_outbound_if(
        &mut self,
        ready: impl Fn(&Outbound) -> bool,
    ) -> Option<Outbound> {
        // A `Grant` is not a terminal byte: while its slot is occupied it must not
        // hold back the frames behind it (M6), so only grants may be skipped.
        let index = self.outbound.iter().position(ready).filter(|index| {
            self.outbound
                .iter()
                .take(*index)
                .all(|item| matches!(item, Outbound::Grant(_)))
        })?;
        let item = self.outbound.remove(index)?;
        if matches!(&item, Outbound::Frame(OutputItem::Hint)) {
            self.hint_queued = false;
        }
        Some(item)
    }

    /// Guest exited: refuse any open question and return every frame still owed, in
    /// wire order (§6.3), plus any grant the user already asked for.
    ///
    /// A queued grant is the user's answer, and the session's end does not cancel it
    /// (R29: an authorised grant may finish after its prompt closed). Dropping it
    /// here lost an `s`/`p` the user had given (finding 17).
    pub(crate) fn finish(&mut self) -> (Vec<OutputItem>, Vec<GrantRequest>) {
        let open = self.phase.owns_terminal();
        let mut owed: Vec<OutputItem> = Vec::new();
        let mut grants: Vec<GrantRequest> = Vec::new();
        for outbound in std::mem::take(&mut self.outbound) {
            match outbound {
                Outbound::Frame(OutputItem::Hint) => owed.push(OutputItem::Data(
                    crate::refusal::feed::HintRelay::BYTES.to_vec(),
                )),
                Outbound::Frame(frame) => owed.push(frame),
                Outbound::Grant(request) => grants.push(request),
                Outbound::Nudge => {}
            }
        }
        let leave_queued = owed.iter().any(|frame| {
            matches!(
                frame,
                OutputItem::Takeover {
                    step: Step::Leave,
                    ..
                }
            )
        });
        let enter_known = matches!(
            self.phase,
            Phase::Entering { .. }
                | Phase::Confirming { .. }
                | Phase::Asking { .. }
                | Phase::Granting { .. }
                | Phase::Lingering { .. }
        );
        if open
            && enter_known
            && !leave_queued
            && let Some(modes) = self.screen
        {
            let (bytes, _) = screen::leave(&modes);
            owed.push(OutputItem::Takeover {
                generation: self.phase.generation().unwrap_or(self.generation),
                step: Step::Leave,
                bytes,
            });
        }
        for frame in std::mem::take(&mut self.held) {
            self.vt.advance(&frame);
            owed.push(OutputItem::Data(frame));
        }
        self.held_bytes = 0;
        self.shown = None;
        self.screen = None;
        self.phase = Phase::Idle { released_at: None };
        (owed, grants)
    }

    // ---------------------------------------------------------------- redraws ---

    /// Draw the whole question with the status it now shows.
    ///
    /// One layout for initial display, status changes and count changes: a
    /// status-only redraw computed its rows from `StopTyping`, so at narrow widths it
    /// wrote over the `d`/`n` key lines or left "ready" on a screen whose guard had
    /// restarted (M2/N2). Redrawing every row costs one frame and cannot disagree
    /// with itself. A question that no longer fits closes (R25) instead of being
    /// skipped, so a display transition is never marked shown without being drawn.
    fn redraw_status(&mut self, status: Status) -> bool {
        self.status = status;
        let view = self.current_view();
        let Some(laid) = screen::layout_with(&view, self.size, status) else {
            self.close(Close::TooSmall);
            return false;
        };
        let bytes = screen::redraw(&laid);
        self.queue_redraw(bytes);
        true
    }

    /// A newer redraw replaces an unsent one (§6.3, N4).
    fn queue_redraw(&mut self, bytes: Vec<u8>) {
        let generation = match self.phase.generation() {
            Some(generation) => generation,
            None => return,
        };
        if let Some(Outbound::Frame(OutputItem::Takeover {
            step: Step::Redraw,
            bytes: queued,
            ..
        })) = self.outbound.back_mut()
        {
            *queued = bytes;
            return;
        }
        self.outbound
            .push_back(Outbound::Frame(OutputItem::Takeover {
                generation,
                step: Step::Redraw,
                bytes,
            }));
    }

    fn redraw_question(&mut self) {
        let view = self.current_view();
        let Some(laid) = screen::layout_with(&view, self.size, self.status) else {
            return;
        };
        let bytes = screen::redraw(&laid);
        self.queue_redraw(bytes);
    }

    /// Redraw whatever the question is showing: the result while it is up (R20),
    /// otherwise the question with the status it has (R17).
    fn redraw_current(&mut self) {
        if self.result.is_some() {
            self.redraw_result();
        } else {
            self.redraw_question();
        }
    }

    fn redraw_result(&mut self) {
        let Some(result) = self.result.clone() else {
            return;
        };
        // The result is laid out from the terminal's geometry alone: it replaced the
        // whole screen, so it must not depend on whether the question (with a grown
        // waiting count) still fits. Requiring that is what left `Lingering` with no
        // frame — and therefore no deadline and no way out (M1/C-F1).
        let bytes = screen::result_frame(self.size, &result);
        self.queue_redraw(bytes);
    }

    /// The pump handed **the result frame** to the writer. The 1.5 s the user reads
    /// it for starts at that acceptance, not before (R20, M1/N2). Any other frame
    /// leaves the bound `granted` already set.
    pub(crate) fn frame_taken(&mut self, now: Instant) {
        if let Phase::Lingering { g, .. } = self.phase
            && !self.linger_started
        {
            self.linger_started = true;
            self.phase = Phase::Lingering {
                g,
                until: Some(now + self.timings.result_linger),
            };
        }
    }
}

/// The command that undoes what a grant did (R20).
fn undo_command(
    result: &crate::allowances::GrantResult,
    destination: &Allowance,
) -> Option<String> {
    let destination = crate::config::escape_str(&destination.to_string());
    match result {
        crate::allowances::GrantResult::Applied { scope, .. } => Some(match scope {
            GrantScope::Session => {
                format!("Undo: agent-vm access revoke {destination} --session-only")
            }
            GrantScope::Project => format!("Undo: agent-vm access revoke {destination}"),
        }),
        crate::allowances::GrantResult::NextLaunch { .. } => Some(format!(
            "Undo: agent-vm access revoke {destination} --project"
        )),
        // The demoted result applied session scope only; the record was not written.
        crate::allowances::GrantResult::AppliedNotRecorded { .. } => Some(format!(
            "Undo: agent-vm access revoke {destination} --session-only"
        )),
        crate::allowances::GrantResult::QueuedForBoot { scope, .. } => Some(match scope {
            GrantScope::Session => {
                format!("Undo: agent-vm access revoke {destination} --session-only")
            }
            GrantScope::Project => format!("Undo: agent-vm access revoke {destination}"),
        }),
        crate::allowances::GrantResult::Refused { .. } => None,
    }
}

#[cfg(test)]
mod tests;
