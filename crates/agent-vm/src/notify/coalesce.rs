//! What one session's banner says, and when it may be replaced.
//!
//! Every rule here is a pure function of the refusals it is told about, the
//! prompt signals it receives and the `Instant` the caller passes in, so the
//! timing rules a reader argues about — the 5 s grace, the 5 s cut backstop, the
//! 3 s flood interval — are testable without a helper process, a socket or
//! Tokio. The driver that owns those channels is Phase 3/4's; this module owns
//! what is shown.

// Phase 4's driver is this module's first caller: that is when this goes.
#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use crate::egress_policy::Allowance;
use crate::refusal::{Kind, MAX_ENTRIES_PER_SESSION, RefusalEntry, SessionId};

/// #494's grace: how long a visible question has before the banner posts.
pub(crate) const PROMPT_GRACE: Duration = Duration::from_secs(5);
/// The bound on how long an attempt may sit in `Cutting` before its banner
/// posts, so a stalled writer cannot hold a refusal back forever.
pub(crate) const CUT_BACKSTOP: Duration = Duration::from_secs(5);
/// The flood interval: at most one banner post, active or passive, per window.
pub(crate) const MIN_POST_INTERVAL: Duration = Duration::from_secs(3);

/// Longest single-line label a banner carries: a destination cell, a project
/// name or a hash. One bound for every one of them.
const MAX_LABEL_CHARS: usize = 80;

/// How many destinations the multi-refusal summary names.
const TOP_DESTINATIONS: usize = 3;

/// How many buffered signals one entry may hold.
///
/// One attempt contributes at most three (`Queued`, `Cutting`, `Shown`) plus one
/// terminal signal, and a signal above the entry's count is superseded by the
/// attempt that follows it, so the newest few are all a replay can use. Keeping
/// the tail bounds a hostile guest's retry storm instead of growing the vector
/// for as long as the entry is unreported.
const MAX_EARLY_SIGNALS_PER_ENTRY: usize = 8;

/// The three durations the rules run on, injected so a test can move the clock
/// past a deadline without waiting. [`Coalescer`] never reads the constants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Timings {
    pub(crate) prompt_grace: Duration,
    pub(crate) cut_backstop: Duration,
    pub(crate) min_post_interval: Duration,
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            prompt_grace: PROMPT_GRACE,
            cut_backstop: CUT_BACKSTOP,
            min_post_interval: MIN_POST_INTERVAL,
        }
    }
}

/// The session a banner speaks for. [`SessionMeta::project_name`] is display text
/// only — it never names a directory or a record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SessionMeta {
    pub(crate) project_hash: String,
    pub(crate) project_name: String,
    pub(crate) session_id: SessionId,
}

/// Whether an attempt waits for the prompt at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PromptMode {
    /// No in-terminal prompt: a refusal posts on first sight.
    Immediate,
    /// An in-terminal prompt will ask: an attempt waits for its signal, bounded
    /// by [`CUT_BACKSTOP`] and [`PROMPT_GRACE`].
    AfterPromptGrace,
}

/// Truthful grantability/offerability, computed by the launcher from
/// `LiveAllowances`. The coalescer only chooses wording from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EntryOffer {
    SessionOrProject,
    ProjectNextLaunch,
    NotGrantableOrUnofferable,
}

/// One sequenced prompt lifecycle signal: attempt identity, count, and the
/// monotonic instant the relay observed it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PromptSignal {
    /// The entry already existed in `Prompt::start`'s baseline snapshot, so the
    /// prompt will never ask for `<= count`.
    Baselined {
        entry_id: String,
        count: u64,
        observed_at: Instant,
    },
    /// The prompt accepted the attempt into its waiting queue. It starts no
    /// timer, so it cannot age into a visible question across a release gap.
    Queued {
        entry_id: String,
        count: u64,
        observed_at: Instant,
    },
    /// The head of the queue began `Cutting`/`Entering`/`Confirming`: the
    /// backstop starts here.
    Cutting {
        entry_id: String,
        count: u64,
        observed_at: Instant,
    },
    /// `Relay::become_visible` (the cursor-position reply, or the 1 s fallback):
    /// the full grace starts here unless the backstop already posted. The
    /// 500 ms settle window is inside it.
    Shown {
        entry_id: String,
        count: u64,
        observed_at: Instant,
    },
    /// The prompt cannot show this attempt: unofferable/host proxy, overflow,
    /// settling, VT unknown, too small (below 40×19, at the cut, on resize or on
    /// the `allowing...` redraw), input closed.
    Declined {
        entry_id: String,
        count: u64,
        observed_at: Instant,
    },
    /// Already answered in `LiveAllowances`. Never a `Declined`: it is a real
    /// answer, so it must not read as "the prompt could not ask".
    AlreadyAnswered {
        entry_id: String,
        count: u64,
        destination: Allowance,
        observed_at: Instant,
    },
    /// The operator submitted an answer: a line (`s`/`session`, `p`/`project`,
    /// `d`/`deny`, empty), Esc or Ctrl-C, or `n`/`never`. Typing, Backspace, an
    /// unrecognised line and anything inside the settle window are not answers
    /// and emit nothing.
    ///
    /// `suppress_destination` is `true` only for `n`/`never`: the operator is
    /// done with that destination for the rest of the session.
    Answered {
        entry_id: String,
        count: u64,
        destination: Allowance,
        suppress_destination: bool,
        observed_at: Instant,
    },
    /// Host terminal input ended (`relay::input_ended`): promote the interrupted
    /// and queued attempts, and switch future attempts to [`PromptMode::Immediate`].
    InputEnded { observed_at: Instant },
}

impl PromptSignal {
    /// The attempt this signal is about, for the signals that name one.
    fn identity(&self) -> Option<(&str, u64)> {
        match self {
            Self::Baselined {
                entry_id, count, ..
            }
            | Self::Queued {
                entry_id, count, ..
            }
            | Self::Cutting {
                entry_id, count, ..
            }
            | Self::Shown {
                entry_id, count, ..
            }
            | Self::Declined {
                entry_id, count, ..
            }
            | Self::AlreadyAnswered {
                entry_id, count, ..
            }
            | Self::Answered {
                entry_id, count, ..
            } => Some((entry_id, *count)),
            Self::InputEnded { .. } => None,
        }
    }
}

/// How one attempt stands with the prompt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AttemptDisposition {
    /// Before the relay has classified it: bounded by [`CUT_BACKSTOP`] so a lost
    /// signal cannot hold a refusal forever.
    AwaitingSignal {
        since: Instant,
    },
    /// In the waiting queue. No timer: a queued item never ages into a visible
    /// one, whatever the release gap.
    Queued,
    Cutting {
        deadline: Instant,
    },
    Visible {
        deadline: Instant,
    },
}

impl AttemptDisposition {
    /// The instant this attempt stops waiting, if it has one. `Queued` is the
    /// arm with no deadline on purpose.
    fn deadline(self, timings: &Timings) -> Option<Instant> {
        match self {
            Self::AwaitingSignal { since } => Some(since + timings.cut_backstop),
            Self::Queued => None,
            Self::Cutting { deadline } | Self::Visible { deadline } => Some(deadline),
        }
    }
}

/// What the helper is asked to show.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NotificationPayload {
    /// `agent-vm.<project_hash>.<sid>`: one banner per session, replaced in place.
    pub(crate) id: String,
    /// `agent-vm.<project_hash>`: the group a project's sessions share.
    pub(crate) thread: String,
    pub(crate) title: String,
    pub(crate) subtitle: String,
    pub(crate) body: String,
    /// `true` for a banner update that must not re-pop in front of the operator.
    pub(crate) passive: bool,
}

/// What the driver should do next, if anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DesiredState {
    /// Take the banner away.
    None,
    Post {
        payload: NotificationPayload,
        /// The entries this payload speaks for, so their acknowledgement can mark
        /// exactly them `alerted`.
        included_ids: Vec<String>,
        /// The [`Coalescer`] revision this payload was built from: the token the
        /// helper's acknowledgement has to echo back for it to settle anything.
        revision: u64,
    },
}

/// What the banner needs to know about one refusal, held identically whether the
/// entry is still waiting for the prompt or already shown.
#[derive(Clone, Debug)]
struct EntryFacts {
    count: u64,
    first_ms: i64,
    last_ms: i64,
    kind: Kind,
    /// `RefusalEntry::destination_cell`, sanitized and length-bounded.
    label: String,
    /// The canonical allowance this entry's destination names, when the launcher
    /// could derive one. `n`/`never` suppression and the authoritative answer
    /// check are keyed on it.
    destination: Option<Allowance>,
    offer: EntryOffer,
}

impl EntryFacts {
    fn new(entry: &RefusalEntry, destination: Option<Allowance>, offer: EntryOffer) -> Self {
        Self {
            count: entry.count,
            first_ms: entry.first_ms,
            last_ms: entry.last_ms,
            kind: entry.key.kind,
            label: sanitize(&entry.destination_cell(), MAX_LABEL_CHARS),
            destination,
            offer,
        }
    }

    /// Adopt a later report of the same entry. Returns whether anything the
    /// banner shows moved, so an unchanged repeat does not count as news.
    ///
    /// `kind` and `first_ms` are identity: a coalesced entry's kind and its first
    /// sighting cannot change.
    fn update(&mut self, other: Self) -> bool {
        let changed = self.count != other.count
            || self.last_ms != other.last_ms
            || self.label != other.label
            || self.offer != other.offer
            || self.destination != other.destination;
        self.count = other.count;
        self.last_ms = other.last_ms;
        self.label = other.label;
        self.offer = other.offer;
        self.destination = other.destination;
        changed
    }
}

#[derive(Clone, Debug)]
struct NotifiedEntry {
    id: String,
    facts: EntryFacts,
    /// Whether a helper acknowledgement has covered this entry: an entry no
    /// banner has carried yet makes the next post active.
    alerted: bool,
}

#[derive(Clone, Debug)]
struct PendingEntry {
    facts: EntryFacts,
    disposition: AttemptDisposition,
}

/// One session's coalescer.
#[derive(Debug)]
pub(crate) struct Coalescer {
    meta: SessionMeta,
    mode: PromptMode,
    timings: Timings,
    /// Entries the banner must speak for.
    notified: HashMap<String, NotifiedEntry>,
    /// Entries whose attempt is still waiting for the prompt to decide.
    pending: HashMap<String, PendingEntry>,
    /// Signals that arrived before the entry they name (B2). A slower refusal
    /// feed must not turn a `Declined` into 5 s of waiting, nor lose an answer.
    early_signals: HashMap<String, Vec<PromptSignal>>,
    /// Highest answered count per entry. A retry carries a higher count and
    /// re-arms; the same or a lower one stays answered.
    handled_count: HashMap<String, u64>,
    /// Destinations the operator is done with (`n`/`never`), keyed on the
    /// canonical allowance the relay keys on.
    suppressed_destinations: HashSet<Allowance>,
    /// When a post was last acknowledged, for the flood interval.
    last_post_at: Option<Instant>,
    /// Bumped by every change to what the payload shows.
    ///
    /// A banner is replaced in place by ID, so an ID set cannot tell one payload
    /// from another: this counter travels with every `Post` and comes back in its
    /// acknowledgement, which is the only thing that can tell which payload was
    /// actually shown.
    revision: u64,
    /// Whether the desired payload differs from the acknowledged one.
    ///
    /// Only `notified` changes move it: a pending attempt is not in the payload,
    /// so it must not owe a post. `has_new_destination` is deliberately *not*
    /// stored beside it — it is derived from the surviving entries on every use,
    /// so an entry removed before a flush cannot leave a stale answer behind.
    dirty: bool,
}

impl Coalescer {
    pub(crate) fn new(meta: SessionMeta, mode: PromptMode, timings: Timings) -> Self {
        Self {
            meta,
            mode,
            timings,
            notified: HashMap::new(),
            pending: HashMap::new(),
            early_signals: HashMap::new(),
            handled_count: HashMap::new(),
            suppressed_destinations: HashSet::new(),
            last_post_at: None,
            revision: 0,
            dirty: false,
        }
    }

    /// One refusal, as the refusal feed last reported it.
    ///
    /// `destination` is the canonical allowance a grant would name, when the
    /// launcher could derive one, and `offer` is what `LiveAllowances` says a
    /// grant could do.
    pub(crate) fn on_entry(
        &mut self,
        entry: &RefusalEntry,
        destination: Option<Allowance>,
        offer: EntryOffer,
        now: Instant,
    ) {
        if let Some(destination) = &destination
            && self.suppressed_destinations.contains(destination)
        {
            self.pending.remove(&entry.id);
            self.discard_through(&entry.id, entry.count);
            return;
        }
        if self
            .handled_count
            .get(&entry.id)
            .is_some_and(|handled| *handled >= entry.count)
        {
            self.pending.remove(&entry.id);
            self.discard_through(&entry.id, entry.count);
            return;
        }
        let facts = EntryFacts::new(entry, destination, offer);

        if let Some(notified) = self.notified.get_mut(&entry.id) {
            if notified.facts.update(facts) {
                self.payload_changed();
            }
            return;
        }
        if let Some(pending) = self.pending.get_mut(&entry.id) {
            // Not a payload change: the attempt has not been shown, so nothing
            // is owed for it yet. The count still has to be current, because it
            // is what decides which signals apply.
            pending.facts.update(facts);
            self.replay(&entry.id, entry.count);
            return;
        }
        if self.mode == PromptMode::Immediate || offer == EntryOffer::NotGrantableOrUnofferable {
            self.insert_notified(entry.id.clone(), facts);
            return;
        }
        self.pending.insert(
            entry.id.clone(),
            PendingEntry {
                facts,
                disposition: AttemptDisposition::AwaitingSignal { since: now },
            },
        );
        self.replay(&entry.id, entry.count);
    }

    /// One prompt lifecycle signal.
    ///
    /// A signal naming an attempt newer than the entry last reported is kept
    /// until [`Self::on_entry`] catches up, exactly like a signal that arrives
    /// before its entry: a retry the refusal feed has not reported yet is still a
    /// retry. A signal naming an attempt the entry has already retried past is
    /// dropped, because its timing belongs to that attempt and not this one.
    ///
    /// An answer is not buffered or dropped: it disposes of the attempt it names
    /// and is applied whenever it arrives.
    pub(crate) fn on_prompt_signal(&mut self, signal: PromptSignal) {
        match signal {
            PromptSignal::InputEnded { .. } => {
                self.mode = PromptMode::Immediate;
                let waiting: Vec<String> = self.pending.keys().cloned().collect();
                for id in waiting {
                    self.promote(&id);
                }
            }
            PromptSignal::Answered {
                entry_id,
                count,
                destination,
                suppress_destination,
                ..
            } => {
                self.on_answered(&entry_id, count, &destination, suppress_destination);
            }
            PromptSignal::AlreadyAnswered {
                entry_id,
                count,
                destination,
                ..
            } => {
                self.on_already_answered(&entry_id, count, &destination);
            }
            other => {
                let Some((entry_id, count)) = other.identity().map(|(id, n)| (id.to_owned(), n))
                else {
                    return;
                };
                match self.known_count(&entry_id) {
                    // The entry has not been reported yet.
                    None => self.buffer(other),
                    // A retry the refusal feed has not reported yet.
                    Some(known) if count > known => self.buffer(other),
                    // A superseded attempt: its disposition would move the
                    // current attempt's timing (a stale `Shown` would restart the
                    // grace, a stale `Declined` would post with none).
                    Some(known) if count < known => {}
                    Some(_) => self.apply(other),
                }
            }
        }
    }

    /// The authoritative answer: `LiveAllowances::answered` holds this
    /// destination, so no banner may keep speaking for it.
    ///
    /// Returns whether an entry was showing, so a driver knows a `Remove` may now
    /// be due. Deliberately *not* a `suppressed_destination`: only the operator's
    /// `n`/`never` is a suppression, and `answered()` is also true when the answer
    /// set is full.
    pub(crate) fn on_answered_destination(&mut self, destination: &Allowance) -> bool {
        let dropped = self.drop_destination(destination);
        if dropped {
            self.payload_changed();
        }
        dropped
    }

    /// The helper acknowledged the post that carried `revision`.
    ///
    /// The plan's signature is `on_post_acked(included_ids, acked_at)`; the
    /// revision is added here (recorded deviation) because banner state may
    /// advance only for the payload the helper actually acknowledged (B6), and an
    /// ID set cannot identify a payload — one banner per session is replaced in
    /// place, so two different payloads carry the same IDs. A driver that only
    /// reported the IDs had to rely on an unstated rule that nothing else was in
    /// flight; a token states the contract in the signature instead.
    ///
    /// Still only reachable after a real `Posted { ok: true }`: nothing here may
    /// run on a request that was merely written.
    pub(crate) fn on_post_acked(
        &mut self,
        included_ids: &[String],
        revision: u64,
        acked_at: Instant,
    ) {
        for id in included_ids {
            if let Some(entry) = self.notified.get_mut(id) {
                entry.alerted = true;
            }
        }
        self.last_post_at = Some(acked_at);
        // An acknowledgement for an older payload settles nothing: whatever moved
        // since then is still owed.
        if revision == self.revision {
            self.dirty = false;
        }
    }

    /// The helper acknowledged taking the banner away.
    ///
    /// A remove means no banner exists, so an entry that arrived while the remove
    /// was in flight has never been in one: it must post, and it must post
    /// actively. The flood anchor goes with the banner — the next post opens one
    /// rather than updating one.
    pub(crate) fn on_remove_acked(&mut self) {
        self.last_post_at = None;
        for entry in self.notified.values_mut() {
            entry.alerted = false;
        }
        self.dirty = !self.notified.is_empty();
    }

    /// The earliest instant at which [`Self::poll_desired`] could have something
    /// new to say, for the driver's timer.
    ///
    /// A deadline that has already passed returns `now`, not `None`: a driver that
    /// recomputes its timer before polling would otherwise wait for an unrelated
    /// event to notice work it already has.
    pub(crate) fn next_deadline(&self, now: Instant) -> Option<Instant> {
        let due = self.pending.values().any(|pending| {
            pending
                .disposition
                .deadline(&self.timings)
                .is_some_and(|deadline| deadline <= now)
        });
        if due {
            return Some(now);
        }
        let waiting = self
            .pending
            .values()
            .filter_map(|pending| pending.disposition.deadline(&self.timings))
            .filter(|deadline| *deadline > now)
            .min();
        let flood = self
            .last_post_at
            .map(|posted| posted + self.timings.min_post_interval)
            .filter(|ready| *ready > now)
            .filter(|_| self.dirty && !self.notified.is_empty());
        match (waiting, flood) {
            (Some(waiting), Some(flood)) => Some(waiting.min(flood)),
            (waiting, flood) => waiting.or(flood),
        }
    }

    /// The next state the helper should be in, when it changes.
    ///
    /// `banner_acked_present` is the acknowledgement state the driver holds:
    /// `false` means the helper has not confirmed a banner, so nothing may be
    /// taken away and the next post must be active.
    pub(crate) fn poll_desired(
        &mut self,
        now: Instant,
        banner_acked_present: bool,
        ended: bool,
    ) -> Option<DesiredState> {
        self.promote_expired(now);
        if self.notified.is_empty() {
            if banner_acked_present {
                return Some(DesiredState::None);
            }
            // Nothing shown, nothing owed: a post would carry no entry at all.
            self.dirty = false;
            return Option::None;
        }
        if !self.dirty {
            return Option::None;
        }
        let ready = !banner_acked_present
            || self
                .last_post_at
                .is_none_or(|posted| now >= posted + self.timings.min_post_interval)
            || ended;
        if !ready {
            return Option::None;
        }
        Some(self.post(ended, banner_acked_present))
    }

    /// The session is ending.
    ///
    /// One documented exception to flood control: an owed banner is flushed
    /// immediately, because a short-lived run would otherwise lose its last
    /// refusals. An attempt still waiting for a *live* question is not promoted —
    /// a normal exit must not turn an unexpired question into a teardown banner —
    /// and a teardown never removes a banner.
    pub(crate) fn on_session_end(
        &mut self,
        now: Instant,
        banner_acked_present: bool,
    ) -> Option<DesiredState> {
        self.promote_expired(now);
        if !self.dirty || self.notified.is_empty() {
            return Option::None;
        }
        Some(self.post(true, banner_acked_present))
    }

    /// The payload for the entries held now, carrying the revision it speaks for
    /// so [`Self::on_post_acked`] can tell whether it is still current.
    fn post(&self, ended: bool, banner_acked_present: bool) -> DesiredState {
        let passive = banner_acked_present && !self.has_new_destination();
        let ordered = self.ordered();
        let project_name = sanitize(&self.meta.project_name, MAX_LABEL_CHARS);
        let project_hash = sanitize(&self.meta.project_hash, MAX_LABEL_CHARS);
        let session = self.meta.session_id.as_str();
        let (title, body) = match ordered.as_slice() {
            [only] => (single_title(only), single_body(only, ended)),
            many => (multi_title(many.len(), &project_name), multi_body(many)),
        };
        DesiredState::Post {
            payload: NotificationPayload {
                id: format!("agent-vm.{project_hash}.{session}"),
                thread: format!("agent-vm.{project_hash}"),
                title,
                subtitle: format!("{project_name} · session {session}"),
                body,
                passive,
            },
            included_ids: self.notified_ids(),
            revision: self.revision,
        }
    }

    /// Record a change to what the banner shows. The one place `dirty` and
    /// [`Self::revision`] move.
    fn payload_changed(&mut self) {
        self.revision += 1;
        self.dirty = true;
    }

    /// Whether a surviving entry has never been in an acknowledged banner. Derived
    /// on every call so a removed entry cannot leave a stale answer behind.
    fn has_new_destination(&self) -> bool {
        self.notified.values().any(|entry| !entry.alerted)
    }

    /// The entries in the order the wording uses: most repeated first, then first
    /// seen, then ID so a tie is stable.
    fn ordered(&self) -> Vec<&NotifiedEntry> {
        let mut ordered: Vec<&NotifiedEntry> = self.notified.values().collect();
        ordered.sort_by(|left, right| {
            right
                .facts
                .count
                .cmp(&left.facts.count)
                .then(left.facts.first_ms.cmp(&right.facts.first_ms))
                .then(left.id.cmp(&right.id))
        });
        ordered
    }

    fn notified_ids(&self) -> Vec<String> {
        sorted(self.notified.keys())
    }

    fn insert_notified(&mut self, id: String, facts: EntryFacts) {
        self.notified.insert(
            id.clone(),
            NotifiedEntry {
                id,
                facts,
                alerted: false,
            },
        );
        self.payload_changed();
    }

    /// Promote every waiting attempt whose deadline has passed. `Queued` has no
    /// deadline and so never promotes.
    fn promote_expired(&mut self, now: Instant) {
        let expired: Vec<String> = self
            .pending
            .iter()
            .filter(|(_, pending)| {
                pending
                    .disposition
                    .deadline(&self.timings)
                    .is_some_and(|deadline| deadline <= now)
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired {
            self.promote(&id);
        }
    }

    fn promote(&mut self, entry_id: &str) -> bool {
        let Some(pending) = self.pending.remove(entry_id) else {
            return false;
        };
        self.insert_notified(entry_id.to_owned(), pending.facts);
        true
    }

    /// `LiveAllowances` already holds this destination, so the attempt was
    /// answered elsewhere: it is dropped, never posted. Unlike [`Self::on_answered`]
    /// there is no deadline to compare — the answer is older than the signal — so
    /// nothing of this attempt stays owed.
    fn on_already_answered(&mut self, entry_id: &str, count: u64, destination: &Allowance) {
        self.note_handled(entry_id, count);
        self.pending.remove(entry_id);
        let mut changed = self.notified.remove(entry_id).is_some();
        changed |= self.drop_destination(destination);
        if changed {
            self.payload_changed();
        }
    }

    /// Record the highest answered count for an entry.
    fn note_handled(&mut self, entry_id: &str, count: u64) {
        let full = self.handled_count.len() >= MAX_ENTRIES_PER_SESSION;
        match self.handled_count.get_mut(entry_id) {
            Some(handled) => *handled = (*handled).max(count),
            None if !full => {
                self.handled_count.insert(entry_id.to_owned(), count);
            }
            // The same bound the refusal table keeps: a session past it has
            // already lost entries, so a count that cannot be recorded protects
            // no entry that exists.
            None => {}
        }
    }

    /// The operator answered this attempt: a submitted line, Esc, Ctrl-C or
    /// `n`/`never`.
    ///
    /// The answer's instant deliberately decides nothing (a deviation from the
    /// plan's `deadline >= observed_at` tie rule, recorded because that rule made
    /// the outcome depend on whether the driver drained the signal before or after
    /// the poll that posted): the banner exists only because nobody answered, so an
    /// answer observed at any time disposes of the attempt it names. An entry the
    /// guest has already retried past this count keeps its newer attempt intact —
    /// the count is what scopes it, not the clock.
    fn on_answered(
        &mut self,
        entry_id: &str,
        count: u64,
        destination: &Allowance,
        suppress_destination: bool,
    ) {
        self.note_handled(entry_id, count);
        let mut changed = false;
        if suppress_destination {
            self.suppressed_destinations.insert(destination.clone());
            changed |= self.drop_destination(destination);
            self.early_signals.remove(entry_id);
        }
        let waiting_this_attempt = self
            .pending
            .get(entry_id)
            .is_some_and(|pending| pending.facts.count <= count);
        // A waiting attempt owes no post once it is answered, so removing it moves
        // nothing the banner shows (`changed` stays as it is).
        if waiting_this_attempt {
            self.pending.remove(entry_id);
        }
        // A banner already posted for this attempt comes down: the banner is the
        // fallback route and the operator has now answered it.
        let showing_this_attempt = self
            .notified
            .get(entry_id)
            .is_some_and(|notified| notified.facts.count <= count);
        if showing_this_attempt && self.notified.remove(entry_id).is_some() {
            changed = true;
        }
        if changed {
            self.payload_changed();
        }
    }

    /// Apply a signal whose attempt the entry is currently on.
    ///
    /// The caller has already established that the signal's count equals the
    /// entry's: a signal for another attempt must not move this one.
    fn apply(&mut self, signal: PromptSignal) {
        let Some((entry_id, _)) = signal.identity().map(|(id, n)| (id.to_owned(), n)) else {
            return;
        };
        match signal {
            PromptSignal::Baselined { .. } | PromptSignal::Declined { .. } => {
                self.promote(&entry_id);
            }
            PromptSignal::Queued { .. } => {
                if let Some(pending) = self.pending.get_mut(&entry_id) {
                    pending.disposition = AttemptDisposition::Queued;
                }
            }
            PromptSignal::Cutting { observed_at, .. } => {
                if let Some(pending) = self.pending.get_mut(&entry_id) {
                    pending.disposition = AttemptDisposition::Cutting {
                        deadline: observed_at + self.timings.cut_backstop,
                    };
                }
            }
            PromptSignal::Shown { observed_at, .. } => {
                if let Some(pending) = self.pending.get_mut(&entry_id) {
                    // The full grace runs from visibility (spec §2.1: "Once
                    // visible, a question gets a full 5 s grace"). The cut
                    // backstop is only the fallback for a relay that never reports
                    // visibility, and it needs no arbitration here: an attempt the
                    // backstop already promoted is no longer pending, so this does
                    // not reschedule it.
                    pending.disposition = AttemptDisposition::Visible {
                        deadline: observed_at + self.timings.prompt_grace,
                    };
                }
            }
            PromptSignal::Answered { .. }
            | PromptSignal::AlreadyAnswered { .. }
            | PromptSignal::InputEnded { .. } => {
                debug_assert!(
                    false,
                    "an answer or the end of input is applied before `apply`"
                );
            }
        }
    }

    /// Keep a signal until the entry it names is reported.
    fn buffer(&mut self, signal: PromptSignal) {
        let Some((entry_id, _)) = signal.identity().map(|(id, n)| (id.to_owned(), n)) else {
            return;
        };
        if !self.early_signals.contains_key(&entry_id)
            && self.early_signals.len() >= MAX_ENTRIES_PER_SESSION
        {
            return;
        }
        let buffered = self.early_signals.entry(entry_id).or_default();
        if buffered.len() >= MAX_EARLY_SIGNALS_PER_ENTRY {
            // Keep the newest: a signal above the entry's count is superseded by
            // the attempt that follows it, so the oldest is the least useful.
            buffered.remove(0);
        }
        buffered.push(signal);
    }

    /// Apply everything buffered for `entry_id` that names the attempt the entry
    /// is now on, and keep what names a later one.
    ///
    /// The plan replayed every buffered signal with `count <= entry.count`
    /// (recorded deviation: equality, not `<=`). Replaying a superseded attempt
    /// hands the current attempt that attempt's timing — a count-1 `Shown` would
    /// start attempt 2's grace at the instant attempt 1 became visible, and a
    /// count-1 `Declined` would post attempt 2 with no grace at all — so a signal
    /// for an older attempt is dropped exactly as a live one now is.
    fn replay(&mut self, entry_id: &str, count: u64) {
        let Some(buffered) = self.early_signals.remove(entry_id) else {
            return;
        };
        let mut later = Vec::new();
        for signal in buffered {
            match signal.identity() {
                Some((_, seen)) if seen == count => self.apply(signal),
                Some((_, seen)) if seen > count => later.push(signal),
                _ => {}
            }
        }
        if !later.is_empty() {
            self.early_signals.insert(entry_id.to_owned(), later);
        }
    }

    /// Drop buffered signals for attempts this entry has already moved past, and
    /// keep the ones naming a retry it has not reported yet.
    fn discard_through(&mut self, entry_id: &str, count: u64) {
        let Some(buffered) = self.early_signals.remove(entry_id) else {
            return;
        };
        let later: Vec<PromptSignal> = buffered
            .into_iter()
            .filter(|signal| signal.identity().is_some_and(|(_, seen)| seen > count))
            .collect();
        if !later.is_empty() {
            self.early_signals.insert(entry_id.to_owned(), later);
        }
    }

    /// The count the entry is currently known at, if it is known at all.
    fn known_count(&self, entry_id: &str) -> Option<u64> {
        self.pending
            .get(entry_id)
            .map(|pending| pending.facts.count)
            .or_else(|| {
                self.notified
                    .get(entry_id)
                    .map(|notified| notified.facts.count)
            })
    }

    /// Remove every entry naming `destination`. Returns whether one was showing.
    fn drop_destination(&mut self, destination: &Allowance) -> bool {
        let showing: Vec<String> = self
            .notified
            .iter()
            .filter(|(_, entry)| entry.facts.destination.as_ref() == Some(destination))
            .map(|(id, _)| id.clone())
            .collect();
        let waiting: Vec<String> = self
            .pending
            .iter()
            .filter(|(_, entry)| entry.facts.destination.as_ref() == Some(destination))
            .map(|(id, _)| id.clone())
            .collect();
        for id in &showing {
            self.notified.remove(id);
        }
        for id in &waiting {
            self.pending.remove(id);
            self.early_signals.remove(id);
        }
        !showing.is_empty()
    }
}

fn sorted<S: AsRef<str>>(items: impl IntoIterator<Item = S>) -> Vec<String> {
    let mut sorted: Vec<String> = items
        .into_iter()
        .map(|item| item.as_ref().to_owned())
        .collect();
    sorted.sort();
    sorted
}

/// `<prefix>: <destination>`, plus the repeat count when the entry is a repeat.
fn single_title(entry: &NotifiedEntry) -> String {
    let prefix = match entry.facts.kind {
        Kind::NetworkDenial => "Blocked",
        Kind::PolicyLock => "Blocked by policy",
        Kind::CredentialRefusal => "Refused",
    };
    format!(
        "{prefix}: {}{}",
        entry.facts.label,
        count_suffix(entry.facts.count)
    )
}

/// The one sentence that says what a click could do about this entry.
fn single_body(entry: &NotifiedEntry, ended: bool) -> String {
    match entry.facts.kind {
        Kind::NetworkDenial => match (ended, entry.facts.offer) {
            (_, EntryOffer::NotGrantableOrUnofferable) => {
                "Network access denied. Click to review; it can't be allowed live from agent-vm."
            }
            (false, EntryOffer::SessionOrProject) => {
                "Network access denied. Click to review; you can allow it for this session or project."
            }
            _ => {
                "Network access denied. Click to review; you can allow it for future launches of this project."
            }
        },
        Kind::PolicyLock => "Administrator or platform policy. It can't be allowed from agent-vm.",
        Kind::CredentialRefusal => {
            "Credential or GitHub repository restriction, not a network block."
        }
    }
    .to_owned()
}

fn multi_title(count: usize, project_name: &str) -> String {
    format!("{count} blocked in {project_name}")
}

/// `<top 3 with counts> · +<more> more`, then how many of them a click could
/// allow.
///
/// The second line answers #316's question for the whole set, so it counts every
/// entry and not only the three the first line names. Each named destination is
/// bounded to a share of the label width, so the line stays readable and the
/// `+<n> more` tail always survives.
fn multi_body(entries: &[&NotifiedEntry]) -> String {
    let share = MAX_LABEL_CHARS / TOP_DESTINATIONS;
    let named: Vec<String> = entries
        .iter()
        .take(TOP_DESTINATIONS)
        .map(|entry| {
            format!(
                "{}{}",
                truncate(entry.facts.label.clone(), share),
                count_suffix(entry.facts.count)
            )
        })
        .collect();
    let mut body = named.join(" · ");
    if entries.len() > TOP_DESTINATIONS {
        body.push_str(&format!(" · +{} more", entries.len() - TOP_DESTINATIONS));
    }
    let approvable = entries
        .iter()
        .filter(|entry| entry.facts.offer != EntryOffer::NotGrantableOrUnofferable)
        .count();
    body.push('\n');
    if approvable == 0 {
        body.push_str("None can be allowed here. Click to review.");
    } else {
        body.push_str(&format!("{approvable} can be allowed. Click to review."));
    }
    body
}

/// ` (N×)` for a repeat, nothing for a first refusal.
fn count_suffix(count: u64) -> String {
    if count > 1 {
        format!(" ({count}×)")
    } else {
        String::new()
    }
}

/// A character a banner must not carry: C0/C1/DEL, the Unicode line and paragraph
/// separators, and the bidi controls that could reorder the rest of the line
/// around guest-supplied text. `U+061C` is included because it reorders in
/// practice even though it sits outside the block.
fn is_disallowed_notification_char(ch: char) -> bool {
    ch.is_control()
        || matches!(
            ch,
            '\u{061C}' | '\u{200E}' | '\u{200F}'
                | '\u{2028}' | '\u{2029}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
        )
}

/// One line of banner text: stripped of the disallowed characters, then bounded.
fn sanitize(text: &str, max_chars: usize) -> String {
    let kept: String = text
        .chars()
        .filter(|ch| !is_disallowed_notification_char(*ch))
        .collect();
    truncate(kept, max_chars)
}

/// Bound a string to `max_chars` characters, marking a cut with `…` so a
/// truncated label never reads as a complete one.
fn truncate(text: String, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text;
    }
    let mut bounded: String = text.chars().take(max_chars.saturating_sub(1)).collect();
    bounded.push('…');
    bounded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::refusal::{Destination, EntryKey};
    use proptest::prelude::*;

    /// The fixture session every test speaks for.
    const SID: &str = "3f9a12c4";
    /// Two entry IDs, both refused on `api.example.com` unless a test says
    /// otherwise.
    const E1: &str = "46d712fd";
    const E2: &str = "71aca03c";

    fn meta() -> SessionMeta {
        SessionMeta {
            project_hash: "9c1f00aa".to_owned(),
            project_name: "demo".to_owned(),
            session_id: SessionId::parse(SID).expect("the fixture is 8 lowercase hex"),
        }
    }

    fn coalescer(mode: PromptMode) -> Coalescer {
        Coalescer::new(meta(), mode, Timings::default())
    }

    fn destination(spelling: &str) -> Allowance {
        Allowance::parse(spelling).expect("the fixture is a valid allowance")
    }

    fn entry(id: &str, kind: Kind, name: &str, count: u64) -> RefusalEntry {
        RefusalEntry {
            id: id.to_owned(),
            key: EntryKey {
                kind,
                destination: Destination::Host {
                    protocol: "tcp".to_owned(),
                    name: name.to_owned(),
                    port: Some(443),
                },
                credential: None,
            },
            layer: "tenant".to_owned(),
            last_site: "tcp-syn".to_owned(),
            last_ip: None,
            name: None,
            last_location: None,
            last_reason: None,
            last_revision: 1,
            count,
            first_ms: 1_000,
            last_ms: 1_000 + count as i64,
        }
    }

    fn denial(id: &str, name: &str, count: u64) -> RefusalEntry {
        entry(id, Kind::NetworkDenial, name, count)
    }

    fn milliseconds(millis: u64) -> Duration {
        Duration::from_millis(millis)
    }

    /// Post whatever is owed at `at` and acknowledge it with the revision that
    /// post carried, as the driver does after the helper answers `Posted { ok: true }`.
    fn ack(coalescer: &mut Coalescer, at: Instant) -> Vec<String> {
        let (_, ids, revision) = owed(coalescer.poll_desired(at, false, false));
        coalescer.on_post_acked(&ids, revision, at);
        ids
    }

    fn payload(state: Option<DesiredState>) -> NotificationPayload {
        match state {
            Some(DesiredState::Post { payload, .. }) => payload,
            other => panic!("expected a post, got {other:?}"),
        }
    }

    /// The payload, the entries it speaks for and the revision it carries, from a
    /// state that must be a post.
    fn owed(state: Option<DesiredState>) -> (NotificationPayload, Vec<String>, u64) {
        match state {
            Some(DesiredState::Post {
                payload,
                included_ids,
                revision,
            }) => (payload, included_ids, revision),
            other => panic!("expected a post, got {other:?}"),
        }
    }

    /// An entry whose first sighting is `first_ms`, for the ordering rules.
    fn seen_at(mut entry: RefusalEntry, first_ms: i64) -> RefusalEntry {
        entry.first_ms = first_ms;
        entry
    }

    fn posted(state: Option<DesiredState>) -> Vec<String> {
        match state {
            Some(DesiredState::Post { included_ids, .. }) => included_ids,
            other => panic!("expected a post, got {other:?}"),
        }
    }

    /// The payload of the post owed at `now`, if any, without an acknowledged
    /// banner: the fixture every wording test starts from.
    fn shown(entries: &[RefusalEntry], ended: bool) -> NotificationPayload {
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::Immediate);
        for entry in entries {
            coalescer.on_entry(entry, None, EntryOffer::SessionOrProject, t);
        }
        payload(coalescer.poll_desired(t, false, ended))
    }

    // ---- timing: when a banner may post -------------------------------------

    #[test]
    fn immediate_mode_posts_a_first_refusal_with_no_wait() {
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::Immediate);
        coalescer.on_entry(
            &denial(E1, "api.example.com", 1),
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );

        assert_eq!(
            payload(coalescer.poll_desired(t, false, false)).title,
            "Blocked: tcp api.example.com:443"
        );
    }

    #[test]
    fn baselined_attempts_post_without_waiting_for_a_question() {
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::AfterPromptGrace);
        coalescer.on_entry(
            &denial(E1, "api.example.com", 1),
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );
        coalescer.on_prompt_signal(PromptSignal::Baselined {
            entry_id: E1.to_owned(),
            count: 1,
            observed_at: t,
        });

        assert_eq!(posted(coalescer.poll_desired(t, false, false)), [E1]);
    }

    #[test]
    fn declined_attempts_post_without_waiting_for_a_question() {
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::AfterPromptGrace);
        coalescer.on_entry(
            &denial(E1, "api.example.com", 1),
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );
        coalescer.on_prompt_signal(PromptSignal::Declined {
            entry_id: E1.to_owned(),
            count: 1,
            observed_at: t,
        });

        assert_eq!(posted(coalescer.poll_desired(t, false, false)), [E1]);
    }

    #[test]
    fn unofferable_entries_post_without_waiting_for_a_question() {
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::AfterPromptGrace);
        coalescer.on_entry(
            &denial(E1, "api.example.com", 4),
            Some(destination("api.example.com")),
            EntryOffer::NotGrantableOrUnofferable,
            t,
        );

        assert_eq!(posted(coalescer.poll_desired(t, false, false)), [E1]);
    }

    #[test]
    fn queued_attempts_never_age_into_a_banner_across_a_release_gap() {
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::AfterPromptGrace);
        coalescer.on_entry(
            &denial(E1, "api.example.com", 1),
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );
        coalescer.on_prompt_signal(PromptSignal::Queued {
            entry_id: E1.to_owned(),
            count: 1,
            observed_at: t,
        });

        assert_eq!(coalescer.next_deadline(t), None);
        assert_eq!(
            coalescer.poll_desired(t + Duration::from_secs(3_600), false, false),
            None
        );
    }

    #[test]
    fn cutting_posts_at_the_five_second_backstop() {
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::AfterPromptGrace);
        coalescer.on_entry(
            &denial(E1, "api.example.com", 1),
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );
        coalescer.on_prompt_signal(PromptSignal::Cutting {
            entry_id: E1.to_owned(),
            count: 1,
            observed_at: t,
        });

        assert_eq!(coalescer.next_deadline(t), Some(t + CUT_BACKSTOP));
        assert_eq!(
            coalescer.poll_desired(t + milliseconds(4_999), false, false),
            None
        );
        assert_eq!(
            posted(coalescer.poll_desired(t + CUT_BACKSTOP, false, false)),
            [E1]
        );
    }

    #[test]
    fn shown_grants_the_full_grace_including_the_settle_window() {
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::AfterPromptGrace);
        coalescer.on_entry(
            &denial(E1, "api.example.com", 1),
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );
        coalescer.on_prompt_signal(PromptSignal::Shown {
            entry_id: E1.to_owned(),
            count: 1,
            observed_at: t + milliseconds(200),
        });

        assert_eq!(
            coalescer.next_deadline(t),
            Some(t + milliseconds(200) + PROMPT_GRACE)
        );
        assert_eq!(coalescer.poll_desired(t + PROMPT_GRACE, false, false), None);
        assert_eq!(
            posted(coalescer.poll_desired(t + milliseconds(200) + PROMPT_GRACE, false, false)),
            [E1]
        );
    }

    #[test]
    fn visibility_grants_the_full_grace_even_when_the_question_appears_late() {
        // F1: an operator who only sees the question at t+3 s still gets 5 s to
        // answer it. The cut backstop decides nothing once visibility is known.
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::AfterPromptGrace);
        coalescer.on_entry(
            &denial(E1, "api.example.com", 1),
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );
        coalescer.on_prompt_signal(PromptSignal::Cutting {
            entry_id: E1.to_owned(),
            count: 1,
            observed_at: t,
        });
        coalescer.on_prompt_signal(PromptSignal::Shown {
            entry_id: E1.to_owned(),
            count: 1,
            observed_at: t + milliseconds(3_000),
        });

        assert_eq!(
            coalescer.next_deadline(t),
            Some(t + milliseconds(3_000) + PROMPT_GRACE)
        );
        assert_eq!(
            coalescer.poll_desired(t + milliseconds(7_999), false, false),
            None
        );
        assert_eq!(
            posted(coalescer.poll_desired(t + milliseconds(8_000), false, false)),
            [E1]
        );
    }

    #[test]
    fn an_unanchored_attempt_is_bounded_by_the_backstop() {
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::AfterPromptGrace);
        coalescer.on_entry(
            &denial(E1, "api.example.com", 1),
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );

        // No signal ever arrives; the entry would otherwise wait forever.
        assert_eq!(coalescer.next_deadline(t), Some(t + CUT_BACKSTOP));
        assert_eq!(
            posted(coalescer.poll_desired(t + CUT_BACKSTOP, false, false)),
            [E1]
        );
    }

    #[test]
    fn an_answer_at_the_deadline_cancels_the_scheduled_post() {
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::AfterPromptGrace);
        coalescer.on_entry(
            &denial(E1, "api.example.com", 1),
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );
        let deadline = t + PROMPT_GRACE;
        coalescer.on_prompt_signal(PromptSignal::Shown {
            entry_id: E1.to_owned(),
            count: 1,
            observed_at: t,
        });
        // The driver drains the answer first, then polls a moment late.
        coalescer.on_prompt_signal(PromptSignal::Answered {
            entry_id: E1.to_owned(),
            count: 1,
            destination: destination("api.example.com"),
            suppress_destination: false,
            observed_at: deadline,
        });

        assert_eq!(
            coalescer.poll_desired(deadline + milliseconds(1), false, false),
            None
        );
    }

    #[test]
    fn an_answer_after_the_deadline_disposes_of_the_attempt() {
        // F5, a recorded deviation from the plan's tie rule: an answer observed at
        // any time disposes of the attempt it names. The tie rule made the outcome
        // depend on whether the driver drained the signal before or after the poll
        // that posted, so a 1 ms-late answer could post a banner nothing removed.
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::AfterPromptGrace);
        coalescer.on_entry(
            &denial(E1, "api.example.com", 1),
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );
        let deadline = t + PROMPT_GRACE;
        coalescer.on_prompt_signal(PromptSignal::Shown {
            entry_id: E1.to_owned(),
            count: 1,
            observed_at: t,
        });
        coalescer.on_prompt_signal(PromptSignal::Answered {
            entry_id: E1.to_owned(),
            count: 1,
            destination: destination("api.example.com"),
            suppress_destination: false,
            observed_at: deadline + milliseconds(1),
        });

        assert_eq!(
            coalescer.poll_desired(deadline + milliseconds(1), false, false),
            None,
            "an answered attempt owes no banner, however late the answer was seen"
        );
        assert_eq!(
            coalescer.poll_desired(deadline + Duration::from_secs(3_600), false, false),
            None
        );
    }

    #[test]
    fn a_late_answer_has_one_outcome_whatever_order_it_arrives_in() {
        // The same scenario delivered answer-last and answer-first: the refusal
        // feed and the prompt are separate channels, so both orders are real.
        let t = Instant::now();
        let answer = |t: Instant| PromptSignal::Answered {
            entry_id: E1.to_owned(),
            count: 1,
            destination: destination("api.example.com"),
            suppress_destination: false,
            observed_at: t + PROMPT_GRACE + milliseconds(1),
        };
        let entry = denial(E1, "api.example.com", 1);
        let shown = |t: Instant| PromptSignal::Shown {
            entry_id: E1.to_owned(),
            count: 1,
            observed_at: t,
        };

        // Answer last: the entry and its visibility are known first.
        let mut last = coalescer(PromptMode::AfterPromptGrace);
        last.on_entry(
            &entry,
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );
        last.on_prompt_signal(shown(t));
        last.on_prompt_signal(answer(t));

        // Answer first: the prompt reports before the refusal feed does.
        let mut first = coalescer(PromptMode::AfterPromptGrace);
        first.on_prompt_signal(answer(t));
        first.on_entry(
            &entry,
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );
        first.on_prompt_signal(shown(t));

        let late = t + Duration::from_secs(3_600);
        let answer_last = last.poll_desired(late, false, false);
        let answer_first = first.poll_desired(late, false, false);
        assert_eq!(answer_last, None);
        assert_eq!(answer_first, answer_last);
    }

    #[test]
    fn an_answer_after_the_banner_takes_it_down() {
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::AfterPromptGrace);
        coalescer.on_entry(
            &denial(E1, "api.example.com", 1),
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );
        let deadline = t + PROMPT_GRACE;
        coalescer.on_prompt_signal(PromptSignal::Shown {
            entry_id: E1.to_owned(),
            count: 1,
            observed_at: t,
        });
        let state = coalescer.poll_desired(deadline, false, false);
        let (_, posted_ids, revision) = owed(state);
        coalescer.on_post_acked(&posted_ids, revision, deadline);
        coalescer.on_prompt_signal(PromptSignal::Answered {
            entry_id: E1.to_owned(),
            count: 1,
            destination: destination("api.example.com"),
            suppress_destination: false,
            observed_at: deadline + milliseconds(200),
        });

        assert_eq!(
            coalescer.poll_desired(deadline + milliseconds(200), true, false),
            Some(DesiredState::None)
        );
    }

    #[test]
    fn a_retry_survives_a_refusing_answer_for_the_earlier_count() {
        // A `d`/deny at count 1 is count-scoped: the guest's retry is count 2.
        for answer_first in [true, false] {
            let t = Instant::now();
            let mut coalescer = coalescer(PromptMode::AfterPromptGrace);
            let answer = PromptSignal::Answered {
                entry_id: E1.to_owned(),
                count: 1,
                destination: destination("api.example.com"),
                suppress_destination: false,
                observed_at: t,
            };
            if answer_first {
                coalescer.on_prompt_signal(answer.clone());
            }
            coalescer.on_entry(
                &denial(E1, "api.example.com", 2),
                Some(destination("api.example.com")),
                EntryOffer::SessionOrProject,
                t,
            );
            if !answer_first {
                coalescer.on_prompt_signal(answer);
            }
            coalescer.on_prompt_signal(PromptSignal::Declined {
                entry_id: E1.to_owned(),
                count: 2,
                observed_at: t,
            });

            assert_eq!(
                posted(coalescer.poll_desired(t, false, false)),
                [E1],
                "a retry at count 2 must not be marked answered by a refusal of count 1 \
                 (answer delivered first: {answer_first})"
            );
        }
    }

    #[test]
    fn an_early_declined_signal_applies_when_the_entry_arrives() {
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::AfterPromptGrace);
        coalescer.on_prompt_signal(PromptSignal::Declined {
            entry_id: E1.to_owned(),
            count: 1,
            observed_at: t,
        });
        coalescer.on_entry(
            &denial(E1, "api.example.com", 1),
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );

        assert_eq!(posted(coalescer.poll_desired(t, false, false)), [E1]);
    }

    #[test]
    fn an_early_shown_signal_applies_when_the_entry_arrives() {
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::AfterPromptGrace);
        coalescer.on_prompt_signal(PromptSignal::Shown {
            entry_id: E1.to_owned(),
            count: 1,
            observed_at: t,
        });
        coalescer.on_entry(
            &denial(E1, "api.example.com", 1),
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );

        assert_eq!(
            coalescer.poll_desired(t + milliseconds(4_999), false, false),
            None
        );
        assert_eq!(
            posted(coalescer.poll_desired(t + PROMPT_GRACE, false, false)),
            [E1]
        );
    }

    #[test]
    fn an_early_answer_skips_the_entry_it_names() {
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::AfterPromptGrace);
        coalescer.on_prompt_signal(PromptSignal::Answered {
            entry_id: E1.to_owned(),
            count: 1,
            destination: destination("api.example.com"),
            suppress_destination: false,
            observed_at: t,
        });
        coalescer.on_entry(
            &denial(E1, "api.example.com", 1),
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );

        assert_eq!(coalescer.poll_desired(t, false, false), None);
    }

    #[test]
    fn an_already_answered_attempt_is_dropped_not_posted() {
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::AfterPromptGrace);
        coalescer.on_entry(
            &denial(E1, "api.example.com", 1),
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );
        coalescer.on_prompt_signal(PromptSignal::AlreadyAnswered {
            entry_id: E1.to_owned(),
            count: 1,
            destination: destination("api.example.com"),
            observed_at: t,
        });

        assert_eq!(
            coalescer.poll_desired(t, false, false),
            None,
            "a destination `LiveAllowances` already holds must not be announced"
        );
        // A retry is a new attempt and does post.
        coalescer.on_prompt_signal(PromptSignal::Declined {
            entry_id: E1.to_owned(),
            count: 2,
            observed_at: t,
        });
        coalescer.on_entry(
            &denial(E1, "api.example.com", 2),
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );
        assert_eq!(posted(coalescer.poll_desired(t, false, false)), [E1]);
    }

    #[test]
    fn an_already_answered_destination_takes_down_every_row_that_names_it() {
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::Immediate);
        for (id, name) in [(E1, "api.example.com"), (E2, "api.example.com")] {
            coalescer.on_entry(
                &denial(id, name, 1),
                Some(destination(name)),
                EntryOffer::SessionOrProject,
                t,
            );
        }
        coalescer.on_prompt_signal(PromptSignal::AlreadyAnswered {
            entry_id: E1.to_owned(),
            count: 1,
            destination: destination("api.example.com"),
            observed_at: t,
        });

        assert_eq!(coalescer.poll_desired(t, false, false), None);
    }

    #[test]
    fn never_suppresses_the_canonical_destination_for_the_session() {
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::AfterPromptGrace);
        coalescer.on_prompt_signal(PromptSignal::Answered {
            entry_id: E1.to_owned(),
            count: 1,
            destination: destination("API.Example.com."),
            suppress_destination: true,
            observed_at: t,
        });
        // A different spelling of the same destination, as the relay would
        // canonicalize it, and a different destination that must still post.
        coalescer.on_entry(
            &denial(E1, "api.example.com", 1),
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );
        coalescer.on_entry(
            &denial(E2, "other.example.com", 1),
            Some(destination("other.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );
        assert_eq!(
            coalescer.poll_desired(t, false, false),
            None,
            "a suppressed destination must never post again"
        );

        coalescer.on_prompt_signal(PromptSignal::Declined {
            entry_id: E2.to_owned(),
            count: 1,
            observed_at: t,
        });
        assert_eq!(posted(coalescer.poll_desired(t, false, false)), [E2]);
    }

    #[test]
    fn input_ended_promotes_every_waiting_attempt() {
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::AfterPromptGrace);
        coalescer.on_entry(
            &denial(E1, "api.example.com", 1),
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );
        coalescer.on_entry(
            &denial(E2, "other.example.com", 1),
            Some(destination("other.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );
        coalescer.on_prompt_signal(PromptSignal::Queued {
            entry_id: E1.to_owned(),
            count: 1,
            observed_at: t,
        });
        coalescer.on_prompt_signal(PromptSignal::InputEnded { observed_at: t });

        let mut ids = posted(coalescer.poll_desired(t, false, false));
        ids.sort();
        assert_eq!(ids, [E1, E2]);
    }

    #[test]
    fn input_ended_switches_later_entries_to_immediate() {
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::AfterPromptGrace);
        coalescer.on_prompt_signal(PromptSignal::InputEnded { observed_at: t });
        coalescer.on_entry(
            &denial(E1, "api.example.com", 1),
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );

        assert_eq!(posted(coalescer.poll_desired(t, false, false)), [E1]);
    }

    #[test]
    fn session_end_does_not_promote_an_unexpired_question() {
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::AfterPromptGrace);
        coalescer.on_entry(
            &denial(E1, "api.example.com", 1),
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );
        coalescer.on_prompt_signal(PromptSignal::Shown {
            entry_id: E1.to_owned(),
            count: 1,
            observed_at: t,
        });

        assert_eq!(
            coalescer.on_session_end(t + milliseconds(1_000), false),
            None,
            "a normal exit must not turn a live question into a teardown banner"
        );
    }

    #[test]
    fn session_end_never_removes_a_banner() {
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::Immediate);

        assert_eq!(coalescer.on_session_end(t, true), None);
    }

    #[test]
    fn session_end_flushes_an_owed_banner_with_ended_wording() {
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::AfterPromptGrace);
        coalescer.on_entry(
            &denial(E1, "api.example.com", 1),
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );
        coalescer.on_prompt_signal(PromptSignal::Declined {
            entry_id: E1.to_owned(),
            count: 1,
            observed_at: t,
        });
        // A post a moment ago must not delay the final flush.
        let (_, first_ids, revision) = owed(coalescer.on_session_end(t, false));
        coalescer.on_post_acked(&first_ids, revision, t);
        coalescer.on_entry(
            &denial(E1, "api.example.com", 2),
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );

        let payload = payload(coalescer.on_session_end(t + milliseconds(500), true));
        assert_eq!(
            payload.body,
            "Network access denied. Click to review; you can allow it for future launches of this project."
        );
    }

    #[test]
    fn session_end_promotes_only_waits_whose_deadline_passed() {
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::AfterPromptGrace);
        coalescer.on_entry(
            &denial(E1, "api.example.com", 1),
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );
        coalescer.on_prompt_signal(PromptSignal::Shown {
            entry_id: E1.to_owned(),
            count: 1,
            observed_at: t,
        });

        assert_eq!(
            posted(coalescer.on_session_end(t + PROMPT_GRACE, false)),
            [E1]
        );
    }

    #[test]
    fn flood_control_replaces_a_banner_at_most_once_per_interval() {
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::Immediate);
        coalescer.on_entry(
            &denial(E1, "api.example.com", 1),
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );
        ack(&mut coalescer, t);
        // The guest retries: news, but not yet allowed to replace the banner.
        coalescer.on_entry(
            &denial(E1, "api.example.com", 2),
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t + milliseconds(1_000),
        );

        assert_eq!(
            coalescer.next_deadline(t + milliseconds(1_000)),
            Some(t + MIN_POST_INTERVAL)
        );
        assert_eq!(
            coalescer.poll_desired(t + milliseconds(2_999), true, false),
            None
        );
        let payload = payload(coalescer.poll_desired(t + MIN_POST_INTERVAL, true, false));
        assert_eq!(payload.title, "Blocked: tcp api.example.com:443 (2×)");
        assert!(payload.passive, "a repeat count update must not re-pop");
    }

    #[test]
    fn the_first_banner_is_active_and_a_repeat_is_passive() {
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::Immediate);
        coalescer.on_entry(
            &denial(E1, "api.example.com", 1),
            None,
            EntryOffer::SessionOrProject,
            t,
        );
        assert!(!payload(coalescer.poll_desired(t, false, false)).passive);

        ack(&mut coalescer, t);
        coalescer.on_entry(
            &denial(E1, "api.example.com", 2),
            None,
            EntryOffer::SessionOrProject,
            t + MIN_POST_INTERVAL,
        );

        assert!(
            payload(coalescer.poll_desired(t + MIN_POST_INTERVAL, true, false)).passive,
            "a repeat count update on a banner already shown must not re-pop"
        );
    }

    #[test]
    fn a_new_destination_makes_the_next_update_active() {
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::Immediate);
        coalescer.on_entry(
            &denial(E1, "api.example.com", 1),
            None,
            EntryOffer::SessionOrProject,
            t,
        );
        ack(&mut coalescer, t);
        coalescer.on_entry(
            &denial(E2, "other.example.com", 1),
            None,
            EntryOffer::SessionOrProject,
            t + MIN_POST_INTERVAL,
        );

        assert!(
            !payload(coalescer.poll_desired(t + MIN_POST_INTERVAL, true, false)).passive,
            "an entry no banner has carried makes the next post active"
        );
    }

    #[test]
    fn a_new_destination_flag_is_derived_from_the_entries_that_survive() {
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::Immediate);
        coalescer.on_entry(
            &denial(E1, "api.example.com", 1),
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );
        ack(&mut coalescer, t);
        coalescer.on_entry(
            &denial(E2, "other.example.com", 1),
            Some(destination("other.example.com")),
            EntryOffer::SessionOrProject,
            t + MIN_POST_INTERVAL,
        );
        // The un-alerted entry is answered before any flush: nothing that no
        // banner has carried survives, so the next update is passive.
        coalescer.on_answered_destination(&destination("other.example.com"));

        let payload = payload(coalescer.poll_desired(t + MIN_POST_INTERVAL, true, false));
        assert!(payload.passive);
        assert_eq!(payload.title, "Blocked: tcp api.example.com:443");
    }

    #[test]
    fn polling_again_without_an_acknowledgement_owes_the_same_active_post() {
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::Immediate);
        coalescer.on_entry(
            &denial(E1, "api.example.com", 1),
            None,
            EntryOffer::SessionOrProject,
            t,
        );
        let first = coalescer.poll_desired(t, false, false);

        assert_eq!(coalescer.poll_desired(t, false, false), first);
        assert!(!payload(first).passive);
    }

    #[test]
    fn removing_the_last_entry_owes_nothing() {
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::Immediate);
        coalescer.on_entry(
            &denial(E1, "api.example.com", 1),
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );

        assert!(coalescer.on_answered_destination(&destination("api.example.com")));
        assert_eq!(coalescer.poll_desired(t, false, false), None);
        assert_eq!(coalescer.next_deadline(t), None);
    }

    #[test]
    fn a_refusal_that_arrives_while_the_remove_is_in_flight_posts_actively() {
        // F3: the remove was requested because nothing was left to show. A refusal
        // that arrives before the helper acknowledges it has never been in a
        // banner, so it must post — actively, and without waiting for an interval
        // that belongs to a banner that no longer exists.
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::Immediate);
        coalescer.on_entry(
            &denial(E1, "api.example.com", 1),
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );
        ack(&mut coalescer, t);
        coalescer.on_prompt_signal(PromptSignal::Answered {
            entry_id: E1.to_owned(),
            count: 1,
            destination: destination("api.example.com"),
            suppress_destination: false,
            observed_at: t + milliseconds(1),
        });
        assert_eq!(
            coalescer.poll_desired(t + milliseconds(1), true, false),
            Some(DesiredState::None),
            "the answered entry's banner comes down"
        );

        // The second refusal lands while the driver awaits the remove ack.
        coalescer.on_entry(
            &denial(E2, "other.example.com", 1),
            None,
            EntryOffer::SessionOrProject,
            t + milliseconds(2),
        );
        coalescer.on_remove_acked();

        assert_eq!(coalescer.next_deadline(t + milliseconds(2)), None);
        let payload = payload(coalescer.poll_desired(t + milliseconds(2), true, false));
        assert_eq!(payload.title, "Blocked: tcp other.example.com:443");
        assert!(
            !payload.passive,
            "an entry that arrived after the remove must open a banner of its own"
        );
    }

    #[test]
    fn an_update_that_races_the_acknowledgement_stays_owed() {
        // F2: a banner is replaced in place by ID, so the ID set cannot tell an
        // acknowledged payload from a newer one. The count-2 payload must still
        // post, or the banner shows count 1 for the rest of the session.
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::Immediate);
        coalescer.on_entry(
            &denial(E1, "api.example.com", 1),
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );
        let (_, first_post, first_revision) = owed(coalescer.poll_desired(t, false, false));
        coalescer.on_post_acked(&first_post, first_revision, t);
        coalescer.on_entry(
            &denial(E1, "api.example.com", 2),
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t + milliseconds(1),
        );
        // The acknowledgement of the *older* payload arrives after the update.
        coalescer.on_post_acked(&first_post, first_revision, t + milliseconds(1));

        // Past the flood interval measured from that acknowledgement.
        let after_interval = t + milliseconds(1) + MIN_POST_INTERVAL;
        assert_eq!(
            payload(coalescer.poll_desired(after_interval, true, false)).title,
            "Blocked: tcp api.example.com:443 (2×)"
        );
    }

    #[test]
    fn an_acknowledgement_for_an_earlier_emission_cannot_clear_a_later_one() {
        // The revision is the acknowledgement token. Two payloads with the same
        // ID and different revisions are two different payloads, so only the
        // second one's own acknowledgement settles the debt it created — the fix
        // for the single-slot record, which a second emission overwrote.
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::Immediate);
        coalescer.on_entry(
            &denial(E1, "api.example.com", 1),
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );
        let (first_payload, first_ids, first_revision) =
            owed(coalescer.poll_desired(t, false, false));
        assert_eq!(first_payload.title, "Blocked: tcp api.example.com:443");
        coalescer.on_entry(
            &denial(E1, "api.example.com", 2),
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t + milliseconds(1),
        );
        let (_, second_ids, second_revision) =
            owed(coalescer.poll_desired(t + milliseconds(1), false, false));
        assert_ne!(first_revision, second_revision);

        // The helper acknowledges the payload it actually showed: the first one.
        coalescer.on_post_acked(&first_ids, first_revision, t + milliseconds(2));

        assert!(
            coalescer.dirty,
            "an acknowledgement for an earlier emission cannot settle a later one"
        );
        let after_interval = t + milliseconds(2) + MIN_POST_INTERVAL;
        assert_eq!(
            payload(coalescer.poll_desired(after_interval, true, false)).title,
            "Blocked: tcp api.example.com:443 (2×)"
        );

        // The second payload's own acknowledgement settles it.
        coalescer.on_post_acked(&second_ids, second_revision, after_interval);
        assert!(!coalescer.dirty);
        assert_eq!(
            coalescer.poll_desired(after_interval + MIN_POST_INTERVAL, true, false),
            None
        );
    }

    #[test]
    fn an_identical_repeat_report_after_the_acknowledgement_owes_nothing() {
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::Immediate);
        let entry = denial(E1, "api.example.com", 1);
        coalescer.on_entry(
            &entry,
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );
        ack(&mut coalescer, t);

        // The same refusal, reported again with nothing about it changed.
        coalescer.on_entry(
            &entry,
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t + MIN_POST_INTERVAL,
        );

        assert!(!coalescer.dirty, "an unchanged repeat is not news");
        assert_eq!(
            coalescer.poll_desired(t + MIN_POST_INTERVAL, true, false),
            None
        );
    }

    #[test]
    fn a_pending_attempts_update_owes_no_post() {
        // F8: a pending attempt is not in the payload, so its repeat must not make
        // an unrelated shown entry re-post.
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::AfterPromptGrace);
        coalescer.on_entry(
            &denial(E1, "api.example.com", 1),
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );
        coalescer.on_prompt_signal(PromptSignal::Declined {
            entry_id: E1.to_owned(),
            count: 1,
            observed_at: t,
        });
        ack(&mut coalescer, t);
        coalescer.on_entry(
            &denial(E2, "other.example.com", 1),
            Some(destination("other.example.com")),
            EntryOffer::SessionOrProject,
            t + milliseconds(1),
        );
        coalescer.on_entry(
            &denial(E2, "other.example.com", 2),
            Some(destination("other.example.com")),
            EntryOffer::SessionOrProject,
            t + milliseconds(2),
        );

        assert!(!coalescer.dirty, "a waiting attempt's update is not news");
        assert_eq!(
            coalescer.poll_desired(t + MIN_POST_INTERVAL, true, false),
            None
        );
    }

    #[test]
    fn a_signal_for_a_superseded_attempt_changes_nothing() {
        // F4: every disposition is count-scoped. A count-1 signal that arrives
        // after the entry has moved to attempt 2 must not promote it, restart its
        // grace or overwrite attempt 2's disposition.
        let t = Instant::now();
        let stale = [
            (
                "Baselined",
                PromptSignal::Baselined {
                    entry_id: E1.to_owned(),
                    count: 1,
                    observed_at: t,
                },
            ),
            (
                "Queued",
                PromptSignal::Queued {
                    entry_id: E1.to_owned(),
                    count: 1,
                    observed_at: t,
                },
            ),
            (
                "Cutting",
                PromptSignal::Cutting {
                    entry_id: E1.to_owned(),
                    count: 1,
                    observed_at: t,
                },
            ),
            (
                "Shown",
                PromptSignal::Shown {
                    entry_id: E1.to_owned(),
                    count: 1,
                    observed_at: t,
                },
            ),
            (
                "Declined",
                PromptSignal::Declined {
                    entry_id: E1.to_owned(),
                    count: 1,
                    observed_at: t,
                },
            ),
        ];
        for (name, signal) in stale {
            let mut coalescer = coalescer(PromptMode::AfterPromptGrace);
            coalescer.on_entry(
                &denial(E1, "api.example.com", 1),
                Some(destination("api.example.com")),
                EntryOffer::SessionOrProject,
                t,
            );
            // The guest retries; the entry is now on attempt 2, still waiting.
            coalescer.on_entry(
                &denial(E1, "api.example.com", 2),
                Some(destination("api.example.com")),
                EntryOffer::SessionOrProject,
                t + milliseconds(100),
            );
            let before = coalescer.next_deadline(t + milliseconds(100));

            coalescer.on_prompt_signal(signal);

            assert_eq!(
                coalescer.next_deadline(t + milliseconds(100)),
                before,
                "{name} for a superseded attempt moved attempt 2's deadline"
            );
            assert_eq!(
                coalescer.poll_desired(t + milliseconds(100), false, false),
                None,
                "{name} for a superseded attempt posted attempt 2 early"
            );
        }
    }

    #[test]
    fn next_deadline_reports_work_that_is_already_due() {
        // F6: a driver that recomputes its timer before polling must be told to
        // poll now, not that there is nothing to wait for.
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::AfterPromptGrace);
        coalescer.on_entry(
            &denial(E1, "api.example.com", 1),
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );
        coalescer.on_prompt_signal(PromptSignal::Cutting {
            entry_id: E1.to_owned(),
            count: 1,
            observed_at: t,
        });

        assert_eq!(
            coalescer.next_deadline(t + milliseconds(6_000)),
            Some(t + milliseconds(6_000))
        );
        assert_eq!(
            posted(coalescer.poll_desired(t + milliseconds(6_000), false, false)),
            [E1]
        );
    }

    #[test]
    fn buffered_signals_are_capped_per_entry_and_still_replay() {
        // F7: a guest's retry storm must not grow one entry's buffer without
        // bound, and the newest attempt is the one that has to survive the cull.
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::AfterPromptGrace);
        for count in 1..=64u64 {
            coalescer.on_prompt_signal(PromptSignal::Cutting {
                entry_id: E1.to_owned(),
                count,
                observed_at: t + milliseconds(count),
            });
        }
        let buffered = coalescer
            .early_signals
            .get(E1)
            .map(Vec::len)
            .unwrap_or_default();

        assert!(
            buffered <= MAX_EARLY_SIGNALS_PER_ENTRY,
            "{buffered} buffered signals for one entry"
        );

        coalescer.on_entry(
            &denial(E1, "api.example.com", 64),
            Some(destination("api.example.com")),
            EntryOffer::SessionOrProject,
            t,
        );
        assert_eq!(
            coalescer.next_deadline(t),
            Some(t + milliseconds(64) + CUT_BACKSTOP),
            "the newest attempt's `Cutting` must be the one that replays"
        );
    }

    #[test]
    fn session_end_does_not_promote_an_unexpired_queued_or_cutting_attempt() {
        let t = Instant::now();
        for name in ["queued", "cutting"] {
            let mut coalescer = coalescer(PromptMode::AfterPromptGrace);
            coalescer.on_entry(
                &denial(E1, "api.example.com", 1),
                Some(destination("api.example.com")),
                EntryOffer::SessionOrProject,
                t,
            );
            coalescer.on_prompt_signal(if name == "queued" {
                PromptSignal::Queued {
                    entry_id: E1.to_owned(),
                    count: 1,
                    observed_at: t,
                }
            } else {
                PromptSignal::Cutting {
                    entry_id: E1.to_owned(),
                    count: 1,
                    observed_at: t,
                }
            });

            assert_eq!(
                coalescer.on_session_end(t + milliseconds(1_000), false),
                None,
                "an unexpired {name} attempt must not be flushed at exit"
            );
        }
    }

    // ---- wording -----------------------------------------------------------

    #[test]
    fn a_repeat_count_appears_in_the_title() {
        assert_eq!(
            shown(&[denial(E1, "api.example.com", 7)], false).title,
            "Blocked: tcp api.example.com:443 (7×)"
        );
    }

    #[test]
    fn a_policy_lock_has_its_own_title_and_body() {
        let payload = shown(&[entry(E1, Kind::PolicyLock, "api.example.com", 1)], false);
        assert_eq!(payload.title, "Blocked by policy: tcp api.example.com:443");
        assert_eq!(
            payload.body,
            "Administrator or platform policy. It can't be allowed from agent-vm."
        );
    }

    #[test]
    fn a_credential_refusal_has_its_own_title_and_body() {
        let payload = shown(
            &[entry(E1, Kind::CredentialRefusal, "api.example.com", 1)],
            false,
        );
        assert_eq!(payload.title, "Refused: tcp api.example.com:443");
        assert_eq!(
            payload.body,
            "Credential or GitHub repository restriction, not a network block."
        );
    }

    #[test]
    fn a_network_denial_names_what_a_click_can_offer() {
        let t = Instant::now();
        for (offer, ended, expected) in [
            (
                EntryOffer::SessionOrProject,
                false,
                "Network access denied. Click to review; you can allow it for this session or project.",
            ),
            (
                EntryOffer::SessionOrProject,
                true,
                "Network access denied. Click to review; you can allow it for future launches of this project.",
            ),
            (
                EntryOffer::ProjectNextLaunch,
                false,
                "Network access denied. Click to review; you can allow it for future launches of this project.",
            ),
            (
                EntryOffer::ProjectNextLaunch,
                true,
                "Network access denied. Click to review; you can allow it for future launches of this project.",
            ),
            (
                EntryOffer::NotGrantableOrUnofferable,
                false,
                "Network access denied. Click to review; it can't be allowed live from agent-vm.",
            ),
            (
                EntryOffer::NotGrantableOrUnofferable,
                true,
                "Network access denied. Click to review; it can't be allowed live from agent-vm.",
            ),
        ] {
            let mut coalescer = coalescer(PromptMode::Immediate);
            coalescer.on_entry(&denial(E1, "api.example.com", 1), None, offer, t);
            assert_eq!(
                payload(coalescer.poll_desired(t, false, ended)).body,
                expected,
                "offer {offer:?}, ended {ended}"
            );
        }
    }

    #[test]
    fn a_multi_refusal_names_three_and_counts_the_rest() {
        let entries = [
            denial(E1, "api.example.com", 9),
            denial("71aca03c", "b.example.com", 4),
            denial("88f5da9d", "c.example.com", 2),
            denial("a00b2078", "d.example.com", 1),
            denial("310ba275", "e.example.com", 1),
        ];
        let payload = shown(&entries, false);

        assert_eq!(payload.title, "5 blocked in demo");
        assert_eq!(
            payload.body,
            "tcp api.example.com:443 (9×) · tcp b.example.com:443 (4×) · tcp c.example.com:443 (2×) · +2 more\n5 can be allowed. Click to review."
        );
    }

    #[test]
    fn a_multi_refusal_counts_only_what_a_click_could_allow() {
        // The title counts what was blocked; the second line counts what a click
        // could actually do something about, which is not the same number.
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::Immediate);
        for (id, name, offer) in [
            (E1, "api.example.com", EntryOffer::SessionOrProject),
            (E2, "other.example.com", EntryOffer::ProjectNextLaunch),
            (
                "88f5da9d",
                "third.example.com",
                EntryOffer::NotGrantableOrUnofferable,
            ),
        ] {
            coalescer.on_entry(&denial(id, name, 1), None, offer, t);
        }

        let payload = payload(coalescer.poll_desired(t, false, false));
        assert_eq!(payload.title, "3 blocked in demo");
        assert!(
            payload
                .body
                .ends_with("\n2 can be allowed. Click to review."),
            "{:?}",
            payload.body
        );
    }

    #[test]
    fn a_multi_refusal_orders_by_count_then_first_seen_then_id() {
        // `(Reverse(count), first_ms, id)`: all counts equal here, so the first
        // sighting decides, and the ID breaks the tie between E1 and E2.
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::Immediate);
        for (entry, seen) in [
            (denial(E2, "b.example.com", 1), 100),
            (denial(E1, "a.example.com", 1), 100),
            (denial("88f5da9d", "c.example.com", 1), 50),
        ] {
            coalescer.on_entry(&seen_at(entry, seen), None, EntryOffer::SessionOrProject, t);
        }

        let payload = payload(coalescer.poll_desired(t, false, false));
        let first_line = payload.body.lines().next().unwrap_or_default();
        assert_eq!(
            first_line,
            "tcp c.example.com:443 · tcp a.example.com:443 · tcp b.example.com:443"
        );
    }

    #[test]
    fn a_multi_refusal_bounds_each_label_and_keeps_the_more_tail() {
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::Immediate);
        for index in 0..5u64 {
            let name = format!("{}.example.com", "a".repeat(200));
            coalescer.on_entry(
                &denial(&entry_id(index as usize), &name, 1),
                None,
                EntryOffer::SessionOrProject,
                t,
            );
        }

        let payload = payload(coalescer.poll_desired(t, false, false));
        let first_line = payload.body.lines().next().unwrap_or_default();
        assert!(
            first_line.ends_with("· +2 more"),
            "the `+N more` tail must survive truncation: {first_line:?}"
        );
        for named in first_line.split(" · ").take(TOP_DESTINATIONS) {
            assert!(
                named.chars().count() <= MAX_LABEL_CHARS / TOP_DESTINATIONS,
                "a named label was not bounded: {named:?}"
            );
            assert!(named.ends_with('…'), "a cut label must say so: {named:?}");
        }
    }

    #[test]
    fn a_multi_refusal_says_when_none_can_be_allowed() {
        let t = Instant::now();
        let mut coalescer = coalescer(PromptMode::Immediate);
        for (id, name) in [(E1, "api.example.com"), (E2, "other.example.com")] {
            coalescer.on_entry(
                &denial(id, name, 1),
                None,
                EntryOffer::NotGrantableOrUnofferable,
                t,
            );
        }

        let payload = payload(coalescer.poll_desired(t, false, false));
        assert_eq!(payload.title, "2 blocked in demo");
        assert!(
            payload
                .body
                .ends_with("\nNone can be allowed here. Click to review.")
        );
    }

    #[test]
    fn one_banner_per_session_grouped_by_project() {
        let payload = shown(&[denial(E1, "api.example.com", 1)], false);

        assert_eq!(payload.id, "agent-vm.9c1f00aa.3f9a12c4");
        assert_eq!(payload.thread, "agent-vm.9c1f00aa");
        assert_eq!(payload.subtitle, "demo · session 3f9a12c4");
    }

    #[test]
    fn guest_text_carries_no_control_separator_or_bidi_characters() {
        // The destination cell escapes guest bytes before it reaches a banner
        // (`config::escape_str`), so no guest character survives as itself. What
        // must hold is that nothing printable in the result can reorder or break
        // the line.
        let hostile = "api\u{202E}.example\u{2066}.com\u{2028}x\u{0007}tcp";
        let payload = shown(&[denial(E1, hostile, 1)], false);

        for text in [&payload.title, &payload.subtitle, &payload.body] {
            assert!(
                !text.chars().any(is_disallowed_notification_char),
                "sanitized text still carries a disallowed character: {text:?}"
            );
        }
        assert!(
            payload.title.contains("\\xe2\\x80\\xae"),
            "guest bytes reach the banner only in escaped form: {:?}",
            payload.title
        );
    }

    #[test]
    fn the_project_name_is_stripped_of_every_disallowed_character() {
        let t = Instant::now();
        let mut coalescer = Coalescer::new(
            SessionMeta {
                project_hash: "9c1f00aa".to_owned(),
                project_name: "de\u{202E}mo\u{2028}\u{0007}".to_owned(),
                session_id: SessionId::parse(SID).expect("the fixture is 8 lowercase hex"),
            },
            PromptMode::Immediate,
            Timings::default(),
        );
        coalescer.on_entry(
            &denial(E1, "api.example.com", 1),
            None,
            EntryOffer::SessionOrProject,
            t,
        );

        let payload = payload(coalescer.poll_desired(t, false, false));
        assert_eq!(payload.subtitle, "demo · session 3f9a12c4");
        for text in [&payload.title, &payload.subtitle, &payload.body] {
            assert!(!text.chars().any(is_disallowed_notification_char));
        }
    }

    #[test]
    fn a_long_label_is_bounded_and_marked() {
        let long = "a".repeat(200);
        let payload = shown(&[denial(E1, &long, 1)], false);

        assert_eq!(
            payload.title.chars().count(),
            "Blocked: ".len() + MAX_LABEL_CHARS
        );
        assert!(payload.title.ends_with('…'));
    }

    // ---- sanitization ------------------------------------------------------

    #[test]
    fn sanitize_keeps_ordinary_text() {
        assert_eq!(
            sanitize("tcp api.example.com:443", MAX_LABEL_CHARS),
            "tcp api.example.com:443"
        );
    }

    #[test]
    fn sanitize_strips_a_newline_and_keeps_the_intentional_one_out_of_it() {
        assert_eq!(sanitize("a\nb", MAX_LABEL_CHARS), "ab");
    }

    #[test]
    fn sanitize_strips_separators_bidi_and_controls() {
        assert_eq!(
            sanitize(
                "a\u{061C}b\u{200E}c\u{200F}d\u{2028}e\u{2029}f\u{202E}g\u{2069}h\u{0007}",
                MAX_LABEL_CHARS
            ),
            "abcdefgh"
        );
    }

    // ---- properties --------------------------------------------------------

    /// One prompt signal a property may deliver, with its observation offset in
    /// milliseconds from the property's base instant.
    #[derive(Clone, Debug)]
    enum Step {
        Baselined,
        Queued,
        Cutting(u64),
        Shown(u64),
        Declined,
        Answered { at: u64, suppress: bool },
    }

    /// One attempt's prompt lifecycle: `Queued`, then `Cutting`, then `Shown`, at
    /// most one terminal signal (`Baselined`/`Declined`, after which the prompt
    /// never asks), and at most one answer, last.
    ///
    /// A generator that emitted a `Shown` without a `Cutting`, or a `Queued` after
    /// one, would describe a relay that cannot exist, so a property about delivery
    /// order would be measuring a fiction.
    fn lifecycle() -> impl Strategy<Value = (u64, Vec<Step>)> {
        (
            1u64..4,
            any::<bool>(),
            proptest::option::of(0u64..8_000),
            proptest::option::of(0u64..8_000),
            0u8..3,
            proptest::option::of((0u64..20_000, any::<bool>())),
        )
            .prop_map(|(count, queued, cutting, shown, terminal, answer)| {
                let mut steps = Vec::new();
                if queued {
                    steps.push(Step::Queued);
                }
                if let Some(at) = cutting {
                    steps.push(Step::Cutting(at));
                }
                if let (Some(_), Some(at)) = (cutting, shown) {
                    steps.push(Step::Shown(at));
                }
                match terminal {
                    1 => steps.push(Step::Baselined),
                    2 => steps.push(Step::Declined),
                    _ => {
                        if let Some((at, suppress)) = answer {
                            steps.push(Step::Answered { at, suppress });
                        }
                    }
                }
                (count, steps)
            })
    }

    /// One plan item: an entry reported at `count` with `steps` delivered to it.
    type Plan = (u64, Vec<Step>);

    fn plan() -> impl Strategy<Value = Vec<Plan>> {
        proptest::collection::vec(lifecycle(), 1..4)
    }

    /// Deliver a plan's events in one of the three orders a real driver can
    /// produce: every entry first, every signal first, or a mixed order where
    /// odd entries report before their signals and even ones after. Signals
    /// within one entry keep the plan's order in all three.
    fn drive(plans: &[Plan], entries_first: bool, mixed: bool) -> Coalescer {
        let t = Instant::now();
        let mut events: Vec<(usize, Option<Step>)> = Vec::new();
        for (index, (_, steps)) in plans.iter().enumerate() {
            events.push((index, None));
            for step in steps {
                events.push((index, Some(step.clone())));
            }
        }
        if mixed {
            events.sort_by_key(|(index, step)| {
                let report_first = index % 2 == 0;
                (*index, step.is_some() == report_first)
            });
        } else if entries_first {
            events.sort_by_key(|(_, step)| step.is_some());
        } else {
            events.sort_by_key(|(_, step)| step.is_none());
        }

        let mut coalescer = coalescer(PromptMode::AfterPromptGrace);
        for (index, step) in events {
            let id = entry_id(index);
            match step {
                Some(Step::Baselined) => coalescer.on_prompt_signal(PromptSignal::Baselined {
                    entry_id: id,
                    count: plans[index].0,
                    observed_at: t,
                }),
                Some(Step::Queued) => coalescer.on_prompt_signal(PromptSignal::Queued {
                    entry_id: id,
                    count: plans[index].0,
                    observed_at: t,
                }),
                Some(Step::Cutting(at)) => coalescer.on_prompt_signal(PromptSignal::Cutting {
                    entry_id: id,
                    count: plans[index].0,
                    observed_at: t + milliseconds(at),
                }),
                Some(Step::Shown(at)) => coalescer.on_prompt_signal(PromptSignal::Shown {
                    entry_id: id,
                    count: plans[index].0,
                    observed_at: t + milliseconds(at),
                }),
                Some(Step::Declined) => coalescer.on_prompt_signal(PromptSignal::Declined {
                    entry_id: id,
                    count: plans[index].0,
                    observed_at: t,
                }),
                Some(Step::Answered { at, suppress }) => {
                    coalescer.on_prompt_signal(PromptSignal::Answered {
                        entry_id: id,
                        count: plans[index].0,
                        destination: destination(&format!("host{index}.example.com")),
                        suppress_destination: suppress,
                        observed_at: t + milliseconds(at),
                    })
                }
                None => coalescer.on_entry(
                    &denial(&id, &format!("host{index}.example.com"), plans[index].0),
                    Some(destination(&format!("host{index}.example.com"))),
                    EntryOffer::SessionOrProject,
                    t,
                ),
            }
        }
        coalescer
    }

    fn entry_id(index: usize) -> String {
        format!("0000{index:04x}")
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]

        #[test]
        fn reordering_entries_and_signals_never_changes_the_final_banner(plans in plan()) {
            // Far enough past every deadline that promotion is not what is being
            // tested: the final notified set must not depend on delivery order.
            let now = Instant::now() + Duration::from_secs(3_600);
            let orders = [
                ("entries-first", true, false),
                ("signals-first", false, false),
                ("mixed", true, true),
            ];
            let mut settled: Vec<(&str, Option<DesiredState>)> = Vec::new();
            for (name, entries_first, mixed) in orders {
                let mut coalescer = drive(&plans, entries_first, mixed);
                settled.push((name, coalescer.poll_desired(now, false, false)));
            }
            for (name, state) in &settled[1..] {
                prop_assert_eq!(
                    state,
                    &settled[0].1,
                    "delivery order {} changed the final banner",
                    name
                );
            }
        }

        #[test]
        fn a_suppressed_destination_never_reaches_a_banner(
            at in 0u64..1_000,
            retries in 0u64..5,
        ) {
            let t = Instant::now();
            let mut coalescer = coalescer(PromptMode::AfterPromptGrace);
            coalescer.on_prompt_signal(PromptSignal::Answered {
                entry_id: entry_id(0),
                count: 1,
                destination: destination("host0.example.com"),
                suppress_destination: true,
                observed_at: t + milliseconds(at),
            });
            for count in 1..=retries + 1 {
                coalescer.on_entry(
                    &denial(&entry_id(0), "host0.example.com", count),
                    Some(destination("host0.example.com")),
                    EntryOffer::SessionOrProject,
                    t,
                );
                coalescer.on_prompt_signal(PromptSignal::Declined {
                    entry_id: entry_id(0),
                    count,
                    observed_at: t,
                });
                let state = coalescer.poll_desired(t + Duration::from_secs(3_600), false, false);
                if let Some(DesiredState::Post { included_ids, .. }) = state {
                    prop_assert!(!included_ids.contains(&entry_id(0)));
                }
            }
        }

        #[test]
        fn an_answered_attempt_is_never_posted(
            cut_ms in 0u64..8_000,
            shown_ms in 0u64..8_000,
            answer_ms in 0u64..40_000,
        ) {
            let t = Instant::now();
            let mut coalescer = coalescer(PromptMode::AfterPromptGrace);
            coalescer.on_entry(
                &denial(E1, "api.example.com", 1),
                Some(destination("api.example.com")),
                EntryOffer::SessionOrProject,
                t,
            );
            coalescer.on_prompt_signal(PromptSignal::Cutting {
                entry_id: E1.to_owned(),
                count: 1,
                observed_at: t + milliseconds(cut_ms),
            });
            coalescer.on_prompt_signal(PromptSignal::Shown {
                entry_id: E1.to_owned(),
                count: 1,
                observed_at: t + milliseconds(shown_ms),
            });
            coalescer.on_prompt_signal(PromptSignal::Answered {
                entry_id: E1.to_owned(),
                count: 1,
                destination: destination("api.example.com"),
                suppress_destination: false,
                observed_at: t + milliseconds(answer_ms),
            });
            let state = coalescer.poll_desired(t + Duration::from_secs(3_600), false, false);
            let posted = matches!(
                &state,
                Some(DesiredState::Post { included_ids, .. })
                    if included_ids.contains(&E1.to_owned())
            );
            // F5: the answer's instant decides nothing. An answer anywhere from
            // well inside the grace to well after it leaves nothing to post.
            prop_assert!(
                !posted,
                "an answered attempt was posted (cut {} ms, shown {} ms, answer {} ms)",
                cut_ms,
                shown_ms,
                answer_ms
            );
        }

        #[test]
        fn the_flood_interval_bounds_every_post_after_the_first(
            posts in proptest::collection::vec(1u64..60, 1..8),
        ) {
            let t = Instant::now();
            let mut coalescer = coalescer(PromptMode::Immediate);
            let mut last: Option<Instant> = None;
            let mut at_ms = 0u64;
            for (index, gap) in posts.iter().enumerate() {
                at_ms += gap;
                let at = t + milliseconds(at_ms);
                coalescer.on_entry(
                    &denial(&entry_id(index), "api.example.com", 1),
                    None,
                    EntryOffer::SessionOrProject,
                    at,
                );
                let state = coalescer.poll_desired(at, last.is_some(), false);
                if let Some(DesiredState::Post {
                    included_ids,
                    revision,
                    ..
                }) = state
                {
                    if let Some(previous) = last {
                        prop_assert!(at >= previous + MIN_POST_INTERVAL);
                    }
                    coalescer.on_post_acked(&included_ids, revision, at);
                    last = Some(at);
                }
            }
        }
    }
}
