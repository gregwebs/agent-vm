//! The takeover lifecycle, sans I/O (§6.2): phases, the hold, the queue, the
//! answer line's use and the frames it asks the writer to write.
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
//! question now gets its own takeover, its own answer line and its own 2 s of
//! guest time.

use std::collections::VecDeque;

use tokio::time::Instant;

use crate::access_prompt::Size;
use crate::access_prompt::guard::{self, Answer};
use crate::access_prompt::input::{InputScan, Position};
use crate::access_prompt::screen::{self, OfferText, ResultView, Status, View};
use crate::access_prompt::vt::{RestorableModes, Screen, VtState};
use crate::allowances::{GrantScope, Offer, PromptGrant};
use crate::egress_policy::Allowance;
use crate::notify::PromptSignal;

/// One refusal that may become a question. Built by the facade, which applies
/// the eligibility rules (R4, R5, R7); the relay only decides *when*.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Candidate {
    pub(crate) entry_id: String,
    pub(crate) destination: Allowance,
    pub(crate) cell: screen::Cell,
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
            count: candidate.count,
            offer: candidate.offer,
            port: candidate.port,
        }
    }

    pub(super) fn view(&self, session: &str, waiting: u64, overflow: u64) -> View {
        View {
            destination: self.cell.clone(),
            // The question's own line, filled in by the relay (`current_view`).
            typed: String::new(),
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

/// Which of the session's two once-per-session lines a hint frame carries.
///
/// Two lines, two kinds, one seam (#501 slice 4 §0.3): the notifications-off line
/// rides ADR-0064's hint route rather than a frame type of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HintKind {
    /// ADR-0064's line: the sandbox refused a guest network request.
    Refusal,
    /// macOS notifications are off, so a banner cannot carry the same news.
    NotificationsOff,
}

impl HintKind {
    /// Both kinds, in the order [`Relay::hints`] holds them.
    pub(crate) const ALL: [Self; 2] = [Self::Refusal, Self::NotificationsOff];

    fn index(self) -> usize {
        match self {
            Self::Refusal => 0,
            Self::NotificationsOff => 1,
        }
    }
}

/// One hint's route and delivery state (R26).
struct HintSlot {
    /// The session's route for this line, when stderr is the same terminal. The
    /// relay is what marks the line delivered: it is the only place that knows
    /// when today's bytes were handed to the writer.
    route: Option<crate::refusal::feed::HintRelay>,
    /// Owed to the relay: fired, not yet queued.
    pending: bool,
    /// Queued in `outbound`, not yet handed over.
    queued: bool,
    /// Emitted (or had no route here), so a later fire adds nothing.
    done: bool,
}

impl HintSlot {
    fn new(route: Option<crate::refusal::feed::HintRelay>) -> Self {
        Self {
            route,
            pending: false,
            queued: false,
            done: false,
        }
    }
}

/// One frame for the writer, mapped 1:1 onto its `OutputFrame`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum OutputItem {
    Data(Vec<u8>),
    /// One of the session's two once-per-session lines. A distinct frame so
    /// nothing has to identify it by comparing bytes (a guest frame could be
    /// byte-identical), and so the relay can mark it delivered only when the
    /// writer accepts it (M9/N6).
    Hint(HintKind),
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

/// One host read, with the stamp the guard needs: `epoch` is taken **before**
/// `read(2)`, so a read that began after the visibility flush is the only one that
/// may act on the line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HostChunk {
    pub(crate) bytes: Vec<u8>,
    pub(crate) epoch: u64,
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
/// How long after the question becomes readable its input is ignored. The operator
/// may have been typing at the guest when the question appeared; the tail of that
/// typing must not become an answer, and reading the question always takes longer
/// than this.
pub(crate) const SETTLE_MS: std::time::Duration = std::time::Duration::from_millis(500);

/// Every duration the relay uses, so a test can shrink them and the production
/// values live in one value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Timings {
    pub(crate) cut: std::time::Duration,
    pub(crate) cpr_wait: std::time::Duration,
    pub(crate) settle: std::time::Duration,
    pub(crate) prompt_timeout: std::time::Duration,
    pub(crate) result_linger: std::time::Duration,
    pub(crate) release_gap: std::time::Duration,
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            cut: CUT_DEADLINE,
            cpr_wait: CPR_WAIT,
            settle: SETTLE_MS,
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
    /// The line the operator has typed for the question on screen. Enter submits it;
    /// a read that is not one clean key stroke clears it (see [`super::guard`]).
    answer_line: String,
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
    /// The two once-per-session lines, indexed by [`HintKind::index`] (R26).
    hints: [HintSlot; 2],
    /// Sequenced prompt lifecycle signals for the notifier (B1–B3). Drained by the
    /// prompt's loop, so the relay stays synchronous and I/O-free: it records the
    /// transition, and the loop hands it on with a non-blocking send (R12).
    signals: Vec<PromptSignal>,
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
    /// A relay over both hint routes: stderr is this terminal, so each line goes
    /// out through the writer that owns the screen.
    pub(crate) fn new(
        session: String,
        size: Size,
        timings: Timings,
        refusal: Option<crate::refusal::feed::HintRelay>,
        notifications_off: Option<crate::refusal::feed::HintRelay>,
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
            answer_line: String::new(),
            input_open: true,
            cpr_answers: true,
            status: Status::Asking,
            result: None,
            linger_started: false,
            asked_position: None,
            hints: [HintSlot::new(refusal), HintSlot::new(notifications_off)],
            signals: Vec::new(),
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

    /// The hint route for one line, for the pump's delivery wrapper (M9).
    pub(crate) fn hint_route(&self, kind: HintKind) -> Option<crate::refusal::feed::HintRelay> {
        self.hints[kind.index()].route.clone()
    }

    /// The bytes the writer must write for one line, when that line is routed here.
    pub(crate) fn hint_bytes(&self, kind: HintKind) -> Option<Vec<u8>> {
        self.hints[kind.index()]
            .route
            .as_ref()
            .map(|hint| hint.bytes())
    }

    /// Every signal the relay emitted since the last drain, in the order the
    /// transitions happened. The loop hands them to the notifier and nothing else
    /// reads them, so a drain that never happens costs notifications, not the
    /// session.
    pub(crate) fn drain_signals(&mut self) -> Vec<PromptSignal> {
        std::mem::take(&mut self.signals)
    }

    /// `Baselined`: an entry the prompt started with, so it will never ask for
    /// `<= count` (R6, B1). Named for every entry in the subscription's snapshot,
    /// not only the ones this launch could ask about.
    pub(crate) fn baseline(&mut self, entry_id: &str, count: u64, now: Instant) {
        self.signals.push(PromptSignal::Baselined {
            entry_id: entry_id.to_owned(),
            count,
            observed_at: now.into_std(),
        });
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
        // Answering is a line, not a keystroke: one clean key stroke edits it, Enter
        // submits it, and anything else clears it (§4.4). Reads that started before
        // the flush cannot type, submit or deny either — the guard says so, and its
        // `Clear` is the only thing they can do.
        let answer = match self.phase.clone() {
            Phase::Asking {
                g,
                visible_at,
                visible_epoch,
            } => {
                let step = guard::line_step(guard::LineFacts {
                    chunk_len: chunk.bytes.len(),
                    byte: chunk.bytes[0],
                    too_soon: now < visible_at + self.timings.settle,
                    read_after_visible: visible_epoch.is_some_and(|epoch| chunk.epoch > epoch),
                    // A read that continues a sequence from an earlier read is never
                    // one of the operator's keys, even when it is a single letter.
                    continued: scan.continued,
                    in_paste: scan.in_paste,
                });
                self.edit_line(step);
                match step {
                    guard::LineStep::Submit => guard::answer_of(
                        self.answer_line.as_bytes(),
                        self.shown
                            .as_ref()
                            .is_some_and(|item| item.offer == Offer::SessionOrProject),
                    )
                    .map(|answer| (g, answer)),
                    guard::LineStep::Deny => Some((g, Answer::Refuse)),
                    _ => None,
                }
            }
            _ => None,
        };
        self.unanswered_in_a_row = 0;
        if let Some((g, answer)) = answer {
            self.answer(g, answer, now);
        }
        InputRoute::Consumed
    }

    fn cpr_position(&self) -> Option<Position> {
        match self.phase {
            Phase::Confirming { close: None, .. } if self.cpr_answers => self.asked_position,
            _ => None,
        }
    }

    /// Apply one read to the typed line, redrawing the input row when the line
    /// changed. The question itself never closes here: an unrecognised line does
    /// nothing at all, and Enter on one does nothing either.
    fn edit_line(&mut self, step: guard::LineStep) {
        match step {
            guard::LineStep::Typed(letter) => {
                if self.answer_line.len() >= guard::MAX_ANSWER_CHARS {
                    return;
                }
                self.answer_line.push(char::from(letter));
                self.redraw_status(self.status);
            }
            guard::LineStep::Erase => {
                if self.answer_line.pop().is_none() {
                    return;
                }
                self.redraw_status(self.status);
            }
            guard::LineStep::Clear => {
                if !self.answer_line.is_empty() {
                    self.answer_line.clear();
                    self.redraw_status(self.status);
                }
            }
            guard::LineStep::Submit | guard::LineStep::Deny | guard::LineStep::Ignore => {}
        }
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
            };
            // `Shown` is visibility, not the question's existence: the 5 s grace and
            // the settle window both run from here (B2).
            if let Some(item) = &self.shown {
                self.signals.push(PromptSignal::Shown {
                    entry_id: item.entry_id.clone(),
                    count: item.count,
                    observed_at: now.into_std(),
                });
            }
            self.status = Status::Asking;
            self.flush_pending = true;
            self.unanswered_in_a_row = 0;
        }
    }

    /// The operator answered the question, which is exactly what the once-per-session
    /// hint line exists to say. One notice, not two: the question wins, so the hint
    /// is claimed rather than printed under the answer (an `s` followed by "the
    /// sandbox refused a guest network request" reads as if the refusal stuck).
    /// Claiming also tells the facade to stop waiting for a hint that will never
    /// come, and covers the reverse order — a hint fired after the claim.
    ///
    /// Answering, not visibility: a question that is drawn and withdrawn within
    /// milliseconds (the guest exited) was never readable, and the hint is then the
    /// only notice the operator ever gets.
    fn claim_hint(&mut self) {
        // Only ADR-0064's line. Answering a question tells the operator nothing
        // about notifications, so a notifications-off line is still owed.
        let slot = &mut self.hints[HintKind::Refusal.index()];
        slot.done = true;
        slot.pending = false;
        if let Some(hint) = &slot.route {
            hint.claim();
        }
    }

    /// `Declined`: the prompt will not ask this attempt.
    fn signal_declined(&mut self, entry_id: &str, count: u64, now: Instant) {
        self.signals.push(PromptSignal::Declined {
            entry_id: entry_id.to_owned(),
            count,
            observed_at: now.into_std(),
        });
    }

    /// The same, for the question on screen, when the caller has no identity of its
    /// own (a decline, a resize).
    fn signal_declined_shown(&mut self, now: Instant) {
        if let Some(item) = &self.shown {
            let (entry_id, count) = (item.entry_id.clone(), item.count);
            self.signal_declined(&entry_id, count, now);
        }
    }

    /// `Answered`: a submitted line, Esc or Ctrl-C. `suppress_destination` is `true`
    /// only for `n`/`never`, which ends that destination for this session.
    fn signal_answered(&mut self, item: &Item, suppress_destination: bool, now: Instant) {
        self.signals.push(PromptSignal::Answered {
            entry_id: item.entry_id.clone(),
            count: item.count,
            destination: item.destination.clone(),
            suppress_destination,
            observed_at: now.into_std(),
        });
    }

    fn answer(&mut self, g: u64, answer: Answer, now: Instant) {
        let Some(item) = self.shown.clone() else {
            return;
        };
        self.claim_hint();
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
                // error (round 3, A R2-1/B B1). A dropped answer is a decline, not an
                // answer (§0.2).
                //
                // Unreachable through the public seam, and kept anyway: the status row
                // is always present, so the only layout that fails is a terminal below
                // the minimum — and a shrink reaches `resized`, which declines first.
                // There is deliberately no test for this arm; it is the guard that
                // keeps a future status row from re-opening the writer-error defect.
                if !self.redraw_status(Status::Allowing) {
                    self.signal_declined(&item.entry_id, item.count, now);
                    return;
                }
                self.outbound.push_back(Outbound::Grant(GrantRequest {
                    entry_id: item.entry_id.clone(),
                    scope,
                    destination: item.destination.clone(),
                }));
                // Count-scoped and emitted only once the grant is enqueued: it says
                // the attempt is answered, never that the grant succeeded (B3).
                self.signal_answered(&item, false, now);
                self.phase = Phase::Granting { g };
            }
            Answer::Refuse => {
                self.signal_answered(&item, false, now);
                self.close(Close::Refused);
            }
            Answer::StopAsking => {
                self.signal_answered(&item, true, now);
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
        // Only with no question in flight. A hint written while a takeover is being
        // prepared lands on the main screen, which the leave restores — so it would
        // appear *under* the operator's answer, the very thing the claim prevents.
        // `written` retries this when the leave returns the relay to `Idle`.
        if !matches!(self.phase, Phase::Idle { .. }) || !self.vt.at_safe_boundary() {
            return;
        }
        for kind in HintKind::ALL {
            let slot = &mut self.hints[kind.index()];
            if !slot.pending {
                continue;
            }
            // No route (stderr is not this terminal): the line already went to
            // stderr, so the relay has nothing to do with it.
            let Some(_) = &slot.route else {
                slot.pending = false;
                slot.done = true;
                continue;
            };
            // Queue it exactly once, as its own frame. It is marked written only when
            // the writer accepts it; a frame queued and then discarded by a forced end
            // still belongs to stderr, and the epilogue prints it.
            self.outbound
                .push_back(Outbound::Frame(OutputItem::Hint(kind)));
            slot.pending = false;
            slot.queued = true;
            slot.done = true;
        }
    }

    // ----------------------------------------------------------- the queue ---

    /// A refusal worth asking about. The facade already applied R4/R5/R7; this adds
    /// the relay's own state (suppressed, settling) and the queue rules (R22).
    pub(crate) fn offer(&mut self, candidate: Candidate, now: Instant) {
        if self.suppressed.contains(&candidate.destination) {
            // A destination the operator told us to stop asking about: nothing is
            // asked and nothing is notified, so this attempt has no signal at all.
            return;
        }
        if self.settling.contains(&candidate.destination) || !self.input_open {
            // R29 / R23: the session will not ask, so say so rather than let the
            // attempt wait for a question that cannot come.
            self.signal_declined(&candidate.entry_id, candidate.count, now);
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
            let item = Item::from_candidate(candidate);
            self.signals.push(PromptSignal::Queued {
                entry_id: item.entry_id.clone(),
                count: item.count,
                observed_at: now.into_std(),
            });
            self.waiting.push_back(item);
        } else {
            // Overflow: the queue is full, so this attempt will not be asked. Said
            // for every attempt, not only the first one past the cap: each is
            // declined by its own count (R22).
            self.signal_declined(&candidate.entry_id, candidate.count, now);
            if !self.overflowed.contains(&candidate.destination) {
                self.overflowed.push(candidate.destination);
            }
        }
        // The count is part of the question (R22): a new waiting destination or a
        // new overflow is drawn, with the status the question is showing.
        if self.phase.owns_terminal() {
            self.redraw_current();
        }
        self.maybe_start(now);
    }

    /// The facade could not turn this refusal into a candidate at all (R4, R5,
    /// R7): non-grantable, or a host proxy in use. Nothing is asked, so the
    /// attempt is declined and the banner route may carry it.
    pub(crate) fn cannot_offer(&mut self, entry_id: &str, count: u64, now: Instant) {
        self.signal_declined(entry_id, count, now);
    }

    /// An answer given elsewhere reached the relay (a wakeup or a lag case).
    pub(crate) fn answered(&mut self, destination: &Allowance, now: Instant) {
        self.dispose_answered(destination, now, None);
    }

    /// The facade's `AlreadyAnswered`: this session answered `destination` before the
    /// prompt could ask (R5), so the attempt is a real answer, never a decline
    /// (B3). `entry_id`/`count` are the refusal's, because nothing in the relay may
    /// know this attempt yet.
    pub(crate) fn already_answered(
        &mut self,
        entry_id: &str,
        count: u64,
        destination: &Allowance,
        now: Instant,
    ) {
        self.dispose_answered(destination, now, Some((entry_id.to_owned(), count)));
    }

    /// Drop `destination` from the queue and, if it is the question on screen, close
    /// it as answered. `identity` names the attempt when the caller knows it; a
    /// shown question names itself, and its own count is the truthful one.
    fn dispose_answered(
        &mut self,
        destination: &Allowance,
        now: Instant,
        identity: Option<(String, u64)>,
    ) {
        self.waiting.retain(|item| item.destination != *destination);
        // `settling` is deliberately **not** pruned: R29 says a destination whose
        // grant outlived its wait is not prompted again in this session, even after
        // the late grant lands and its wakeup arrives (M10/N7).
        let shown = self
            .shown
            .clone()
            .filter(|item| item.destination == *destination);
        let Some(item) = shown else {
            // Nothing is on screen for this destination: the attempt is disposed of
            // with the identity the caller carried, and no frame changes.
            if let Some((entry_id, count)) = identity {
                self.signals.push(PromptSignal::AlreadyAnswered {
                    entry_id,
                    count,
                    destination: destination.clone(),
                    observed_at: now.into_std(),
                });
            }
            return;
        };
        // Only a close the relay actually performs is a signal: `Granting`,
        // `Lingering` and `Restoring` already show this question's own answer, so a
        // wakeup changes nothing and says nothing (I8, R20).
        let closed = match self.phase.clone() {
            // Nothing is queued yet: back to Idle with no frame owed.
            Phase::Idle { .. } => false,
            Phase::Cutting { .. } => {
                self.drop_shown(now);
                true
            }
            Phase::Entering { g, close: None, .. } => {
                self.close_phase(Close::AnsweredElsewhere, g);
                true
            }
            Phase::Confirming { g, close: None, .. } => {
                self.close_phase(Close::AnsweredElsewhere, g);
                true
            }
            Phase::Asking { .. } => {
                self.close(Close::AnsweredElsewhere);
                true
            }
            _ => false,
        };
        if closed {
            self.signals.push(PromptSignal::AlreadyAnswered {
                entry_id: item.entry_id,
                count: item.count,
                destination: destination.clone(),
                observed_at: now.into_std(),
            });
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
        // The head becomes the question, with an empty line. Whether it can be asked
        // is decided at the cut, where the tracker has seen everything `Cutting`
        // forwards (R9–R12).
        let Some(item) = self.waiting.pop_front() else {
            return;
        };
        self.answer_line.clear();
        self.generation += 1;
        let g = self.generation;
        // The backstop starts here: from now on the attempt may sit in `Cutting`
        // without reaching a safe boundary, and its banner must not wait for one.
        self.signals.push(PromptSignal::Cutting {
            entry_id: item.entry_id.clone(),
            count: item.count,
            observed_at: now.into_std(),
        });
        self.shown = Some(item);
        self.phase = Phase::Cutting { g, since: now };
        // A boundary already reached takes over at once.
        if self.vt.at_safe_boundary() {
            self.begin_enter(g, now, false);
        }
    }

    pub(super) fn current_view(&self) -> View {
        let waiting = self.waiting.len() as u64;
        let mut view = match &self.shown {
            Some(item) => item.view(&self.session, waiting, self.overflowed.len() as u64),
            None => View {
                destination: screen::Cell::from_guest(""),
                typed: String::new(),
                count: 0,
                session: self.session.clone(),
                offer: OfferText::SessionOrProject,
                waiting,
                overflow: self.overflowed.len() as u64,
            },
        };
        view.typed = self.answer_line.clone();
        view
    }

    /// Decline the takeover at the cut: the held bytes are the guest's and go out
    /// first, in order, then the question is left to `access`.
    fn decline(&mut self, now: Instant) {
        // The cut could not produce a question: the tracker does not know the
        // terminal's state, or the question does not fit (R25).
        self.signal_declined_shown(now);
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
        self.status = Status::Asking;
        self.answer_line.clear();
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
        // No hint here: one that fired while the takeover was wanted waits for the
        // question's outcome. Written now it would land on the main screen and be
        // restored under the answer; if the question is withdrawn unread, the leave's
        // confirmation sends it (see `claim_hint`).
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
        self.status = Status::Asking;
        self.asked_position = if self.cpr_answers {
            Some(Position {
                row: (laid.input_row() + 1) as u16,
                col: laid.cursor_col() as u16,
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
        self.status = Status::Asking;
        self.asked_position = None;
        self.phase = Phase::Restoring { g };
    }

    /// The terminal was resized. A question that no longer fits is refused (R25); one
    /// that still fits is redrawn at the new size.
    pub(crate) fn resized(&mut self, size: Size, now: Instant) {
        self.size = size;
        if !self.phase.owns_terminal() {
            self.emit_hint_if_due();
            return;
        }
        let view = self.current_view();
        match screen::layout_with(&view, size, self.status) {
            Some(_) => self.redraw_current(),
            None => {
                // `Declined` only while the attempt is still unanswered. Host input
                // outranks a resize, so an Enter and a `SIGWINCH` can arrive in the
                // same turn; after an answer (`Granting`/`Lingering`) or a close
                // (`Restoring`) the attempt already has its disposition, and a second,
                // contradictory one would tell the coalescer both at once.
                if matches!(
                    self.phase,
                    Phase::Entering { .. } | Phase::Confirming { .. } | Phase::Asking { .. }
                ) {
                    self.signal_declined_shown(now);
                }
                self.close(Close::TooSmall);
            }
        }
    }

    /// Host input ended (terminal EOF/EIO, or the guest closed its input): an open
    /// question is refused and no further prompt is shown (R23).
    pub(crate) fn input_ended(&mut self, now: Instant) {
        self.input_open = false;
        self.waiting.clear();
        // One signal for both halves: an interrupted question and a queue that will
        // never be asked are the same loss of the terminal.
        self.signals.push(PromptSignal::InputEnded {
            observed_at: now.into_std(),
        });
        if self.phase.owns_terminal() {
            self.close(Close::InputEnded);
        }
    }

    /// The hint route for one line, cloned for the facade's cancel-safe wait.
    pub(crate) fn hint_handle(&self, kind: HintKind) -> Option<crate::refusal::feed::HintRelay> {
        self.hints[kind.index()].route.clone()
    }

    /// Give one route back to the epilogue. `detach` then says whether that line
    /// fired but never reached the writer, so the epilogue prints exactly that case.
    pub(crate) fn take_hint(&mut self, kind: HintKind) -> Option<crate::refusal::feed::HintRelay> {
        self.hints[kind.index()].route.take()
    }

    /// One of the session's lines fired and is owed to the relay (R26).
    pub(crate) fn hint_fired(&mut self, kind: HintKind, now: Instant) {
        let slot = &mut self.hints[kind.index()];
        if slot.done {
            return;
        }
        slot.pending = true;
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
            Phase::Asking { visible_at, .. } => Some(*visible_at + self.timings.prompt_timeout),
            // A `Lingering` whose result frame has not been accepted yet still has the
            // deadline `granted` set; one with none (defensively) fires now.
            Phase::Lingering { until, .. } => Some(until.unwrap_or_else(Instant::now)),
            // `Granting` is bounded by the session loop's slot; `Restoring` by the
            // writer's confirmation.
            _ => None,
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
            Phase::Asking { visible_at, .. } => {
                if now >= visible_at + self.timings.prompt_timeout {
                    self.unanswered_in_a_row = self.unanswered_in_a_row.saturating_add(1);
                    self.close(Close::TimedOut);
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
        if let Outbound::Frame(OutputItem::Hint(kind)) = &item {
            self.hints[kind.index()].queued = false;
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
                // A queued line keeps its kind through the tail: the writer resolves
                // that kind's bytes and marks the line delivered once they are
                // written, so a line the drain wrote is not owed to stderr again.
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
