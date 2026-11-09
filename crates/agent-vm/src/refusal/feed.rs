//! Following the runtime's `network.log` into memory and onto disk.
//!
//! One task owns the stream; one *thread* owns the file. The split is the whole
//! point: a slow or wedged disk must not stall the reader, and a reader that
//! falls behind must not grow the launcher's memory without bound.
//!
//! Ordering is owned by [`Persister`]: it holds at most one pending job and
//! keeps the newest, so a burst of updates costs one write rather than one write
//! each, and a job older than the last one written is dropped. The final write is
//! terminal — nothing after it may replace the record that says the session
//! ended.
//!
//! Nothing here fails a launch (AC14). Every failure is either a gap in the
//! record (marked, and shown as a footer) or the end of following.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

use futures::StreamExt as _;
use futures::future::BoxFuture;
use microsandbox::MicrosandboxError;
use microsandbox::logs::{
    LogCursor, LogEntry, LogSource, LogStreamOptions, LogStreamStart, NetworkLogRecord,
};
use tokio::sync::{broadcast, watch};

use super::SessionSnapshot;
use super::log::SessionsDir;

/// How often the follower wakes to notice "nothing happened" — the tick that
/// posts a dirty snapshot and refreshes the heartbeat. The runtime's own
/// fallback poll is 2 s (`logs/stream.rs`), so a shorter interval would only
/// spin.
pub(crate) const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// The longest the log may trail ingestion by while writes succeed (AC3).
pub(crate) const POST_INTERVAL: Duration = Duration::from_secs(2);

/// How often a session with no control socket writes a heartbeat. Three of
/// these fit inside [`super::log::HEARTBEAT_STALE_MS`], so one missed write does
/// not make a live session look unclean.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Reopen attempts after a stream error before following gives up.
const REOPEN_TRIES: u32 = 3;
const REOPEN_PAUSE: Duration = Duration::from_secs(1);

/// How long [`Persister::post_final`]'s owner waits for the last write.
pub(crate) const FINAL_WAIT: Duration = Duration::from_secs(2);

/// How many updates a subscriber may fall behind before it is told it lagged.
pub(crate) const UPDATE_BUFFER: usize = 256;

/// The SDK's log stream, restated here because the SDK keeps the alias behind a
/// private module. A type alias is transparent, so this *is* the SDK's
/// `LogStream`.
pub(crate) type LogStream = std::pin::Pin<
    Box<dyn futures::Stream<Item = microsandbox::MicrosandboxResult<LogEntry>> + Send + 'static>,
>;

/// Opens one stream over this sandbox's `network.log`.
///
/// A shared closure rather than a `Sandbox` handle so (a) the real engine can be
/// driven over a hand-written log in a test with no VM, and (b) the follower and
/// the post-stop drain hold the *same* opener. The plan wrote `FnMut`; `Fn` is
/// what lets the drain re-open after the follower has stopped.
pub(crate) type Opener = Arc<
    dyn Fn(LogStreamOptions) -> BoxFuture<'static, microsandbox::MicrosandboxResult<LogStream>>
        + Send
        + Sync,
>;

/// The one non-following read that finishes a session (§6.4's step 2).
pub(crate) fn drain_options(cursor: Option<LogCursor>) -> LogStreamOptions {
    LogStreamOptions {
        sources: vec![LogSource::Network],
        start: match cursor {
            Some(cursor) => LogStreamStart::From(cursor),
            None => LogStreamStart::Beginning,
        },
        until: None,
        follow: false,
    }
}

/// The one shared state a feed has: the entries, and the update channel.
///
/// The mutation lock is also the handoff lock. Taking a snapshot and subscribing
/// under it is what makes `subscribe` race-free: an update can be neither lost
/// between the two nor delivered twice into the snapshot.
pub(crate) struct LiveRefusals {
    state: Mutex<LiveState>,
}

struct LiveState {
    session: super::SessionRefusals,
    updates: broadcast::Sender<super::Update>,
}

impl LiveRefusals {
    pub(crate) fn new(session: super::SessionRefusals) -> Arc<Self> {
        let (updates, _) = broadcast::channel(UPDATE_BUFFER);
        Arc::new(Self {
            state: Mutex::new(LiveState { session, updates }),
        })
    }

    fn lock(&self) -> MutexGuard<'_, LiveState> {
        // A follower panic would poison the lock; the entries are still readable
        // and refusing to serve them would turn a display failure into a launch
        // failure, so the guard is taken through the poison.
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn snapshot(&self) -> SessionSnapshot {
        self.lock().session.snapshot()
    }

    /// A snapshot and a subscription taken together: the one handoff that
    /// neither loses an update nor repeats one.
    pub(crate) fn subscribe(&self) -> (SessionSnapshot, broadcast::Receiver<super::Update>) {
        let state = self.lock();
        (state.session.snapshot(), state.updates.subscribe())
    }

    /// Fold one record in and publish the result, if it changed anything.
    pub(crate) fn ingest(&self, record: &NetworkLogRecord, dirty: &mut bool, now_ms: i64) -> bool {
        let mut state = self.lock();
        state.session.beat(now_ms);
        let Some(update) = state.session.ingest(record) else {
            return false;
        };
        let refused = update.entry.is_some();
        // Sent while the lock is held: `broadcast::Sender::send` never blocks, and
        // sending outside it would let a subscriber take a snapshot that already
        // contains the entry and then receive it again as an update.
        let _ = state.updates.send(update);
        *dirty = true;
        refused
    }

    fn mark_gap(&self, dirty: &mut bool) {
        let mut state = self.lock();
        if let Some(update) = state.session.mark_gap() {
            let _ = state.updates.send(update);
            *dirty = true;
        }
    }

    fn beat(&self, now_ms: i64) {
        self.lock().session.beat(now_ms);
    }

    /// Mark the session ended and publish it. Idempotent: the first end wins, so
    /// a teardown that runs twice cannot move `ended_ms`.
    pub(crate) fn ended(&self, now_ms: i64) -> SessionSnapshot {
        let mut state = self.lock();
        let update = state.session.ended(now_ms);
        let snapshot = state.session.snapshot();
        let _ = state.updates.send(update);
        snapshot
    }
}

/// The one hint stderr gets (AC7).
///
/// A once-flag rather than a rate limit: the ticket asks for one line per
/// session, at the first refusal, and a refusal storm must not turn into a
/// notice storm.
#[derive(Default)]
pub(crate) struct Hint {
    fired: AtomicBool,
}

/// The hint's text. No guest text, because a name the guest chose must never be
/// able to forge a launcher line.
pub(crate) const HINT: &str = "==> The sandbox refused a guest network request; run `agent-vm access` to see refusals (shown once per session)";

impl Hint {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Deliver the hint at most once. Detached, so a stalled stderr delays no
    /// teardown; the delivery handle is dropped, so nothing waits for it either.
    fn fire(&self) {
        if self.fired.swap(true, Ordering::SeqCst) {
            return;
        }
        let line = if std::io::IsTerminal::is_terminal(&std::io::stderr()) {
            // Framed so a line the guest is mid-way through cannot swallow it.
            format!("\r{HINT}\r")
        } else {
            HINT.to_owned()
        };
        drop(crate::launch_notice::LaunchNotices::to_stderr().emit_detached(line));
    }

    #[cfg(test)]
    fn fired(&self) -> bool {
        self.fired.load(Ordering::SeqCst)
    }
}

/// The following stream's options: the refusal log source, from the start, live.
pub(crate) fn options(start: &LogStreamStart) -> LogStreamOptions {
    LogStreamOptions {
        // `Network` is never in the default source set, so this is the only way
        // to read refusal records at all.
        sources: vec![LogSource::Network],
        start: start.clone(),
        until: None,
        follow: true,
    }
}

/// Follow `network.log` until `stop` is set or following gives up.
///
/// Returns the last cursor it read, so the caller can drain the rest of the file
/// after the producer has stopped (§6.4's `finish`) instead of losing whatever
/// was written after the last poll.
pub(crate) async fn follow(
    open: Opener,
    live: Arc<LiveRefusals>,
    persist: PersistHandle,
    hint: Arc<Hint>,
    mut stop: watch::Receiver<bool>,
    has_socket: bool,
) -> Option<LogCursor> {
    let mut cursor: Option<LogCursor> = None;
    let mut dirty = false;
    let mut start = LogStreamStart::Beginning;
    let mut failures = 0u32;
    let mut ticker = tokio::time::interval(POLL_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_post = tokio::time::Instant::now();

    loop {
        if *stop.borrow() {
            return cursor;
        }
        let stream = match open(options(&start)).await {
            Ok(stream) => stream,
            Err(error) => {
                if !resume_after(
                    &error,
                    &mut start,
                    &mut failures,
                    &mut cursor,
                    &live,
                    &mut dirty,
                ) {
                    return cursor;
                }
                tokio::time::sleep(REOPEN_PAUSE).await;
                continue;
            }
        };
        let mut stream = stream;
        failures = 0;
        loop {
            tokio::select! {
                biased;
                changed = stop.changed() => {
                    // A sender that dropped is a stop too: nothing else sets it.
                    if changed.is_err() || *stop.borrow() {
                        return cursor;
                    }
                }
                _ = ticker.tick() => {
                    let now_ms = now_ms();
                    live.beat(now_ms);
                    let due = dirty && last_post.elapsed() >= POST_INTERVAL;
                    let heartbeat = !has_socket && last_post.elapsed() >= HEARTBEAT_INTERVAL;
                    if due || heartbeat {
                        persist.post(live.snapshot());
                        last_post = tokio::time::Instant::now();
                        dirty = false;
                    }
                }
                item = stream.next() => {
                    match item {
                        Some(Ok(entry)) => {
                            failures = 0;
                            accept(entry, &live, &hint, &mut dirty, &mut cursor);
                        }
                        Some(Err(error)) => {
                            if !resume_after(&error, &mut start, &mut failures, &mut cursor, &live, &mut dirty) {
                                return cursor;
                            }
                            tokio::time::sleep(REOPEN_PAUSE).await;
                            break;
                        }
                        // The stream ended by itself. That is not "no more
                        // refusals forever", so the follower tries the same
                        // resume as an error would, bounded.
                        None => {
                            failures += 1;
                            if failures > REOPEN_TRIES {
                                return cursor;
                            }
                            start = match &cursor {
                                Some(cursor) => LogStreamStart::From(cursor.clone()),
                                None => LogStreamStart::Beginning,
                            };
                            tokio::time::sleep(REOPEN_PAUSE).await;
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// Decide how to resume after an error. `false` means stop following.
///
/// A missed rotation or an invalid cursor means the file being read has left the
/// chain, so **every retained file is newer**: reopening from `Beginning` cannot
/// double-count, and needs no watermark. Any other error resumes from the last
/// cursor, because that one is still valid.
fn resume_after(
    error: &MicrosandboxError,
    start: &mut LogStreamStart,
    failures: &mut u32,
    cursor: &mut Option<LogCursor>,
    live: &Arc<LiveRefusals>,
    dirty: &mut bool,
) -> bool {
    *failures += 1;
    if *failures > REOPEN_TRIES {
        return false;
    }
    live.mark_gap(dirty);
    *start = match error {
        MicrosandboxError::MissedRotation { .. } | MicrosandboxError::InvalidCursor(_) => {
            LogStreamStart::Beginning
        }
        _ => match cursor {
            Some(cursor) => LogStreamStart::From(cursor.clone()),
            None => LogStreamStart::Beginning,
        },
    };
    true
}

/// Decode one entry and fold it in.
///
/// The cursor is kept for *every* entry, decodable or not: the position is what
/// a resume means, and a line this build cannot read is still a line that has
/// been consumed.
pub(crate) fn accept(
    entry: LogEntry,
    live: &Arc<LiveRefusals>,
    hint: &Arc<Hint>,
    dirty: &mut bool,
    cursor: &mut Option<LogCursor>,
) {
    *cursor = Some(entry.cursor.clone());
    let Ok(record) = serde_json::from_slice::<NetworkLogRecord>(&entry.data) else {
        // A malformed line is neither a refusal nor a count. It is not a gap
        // either: the line was read, and the runtime wrote something this build
        // does not understand.
        return;
    };
    if live.ingest(&record, dirty, now_ms()) {
        hint.fire();
    }
}

pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or(0)
}

/// The one ordered writer: a thread, one pending job, the newest kept.
pub(crate) struct Persister {
    slot: Arc<Slot>,
    /// `None` once the thread has been detached by `Drop`.
    thread: Option<std::thread::JoinHandle<()>>,
}

struct Slot {
    state: Mutex<SlotState>,
    wake: Condvar,
}

struct SlotState {
    /// The newest job waiting. A second post replaces it; only the newest
    /// snapshot is worth writing, because every snapshot is absolute.
    pending: Option<Job>,
    /// The revision the last write put on disk.
    written_rev: u64,
    stopping: bool,
    /// Set when the final snapshot has been written (or failed).
    finished: bool,
}

enum Job {
    Snapshot(SessionSnapshot),
    Final(SessionSnapshot),
}

impl Job {
    fn snapshot(&self) -> &SessionSnapshot {
        match self {
            Self::Snapshot(snapshot) | Self::Final(snapshot) => snapshot,
        }
    }
}

impl Persister {
    /// Start the writer thread for one session.
    pub(crate) fn new(dir: SessionsDir) -> Self {
        let slot = Arc::new(Slot {
            state: Mutex::new(SlotState {
                pending: None,
                written_rev: 0,
                stopping: false,
                finished: false,
            }),
            wake: Condvar::new(),
        });
        let worker = Arc::clone(&slot);
        let thread = std::thread::Builder::new()
            .name("agent-vm-refusal-log".into())
            .spawn(move || write_loop(&worker, &dir))
            .ok();
        Self { slot, thread }
    }

    fn lock(&self) -> MutexGuard<'_, SlotState> {
        self.slot
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// A handle the follower can hold while this value keeps the thread alive.
    pub(crate) fn handle(&self) -> PersistHandle {
        PersistHandle {
            slot: Arc::clone(&self.slot),
        }
    }

    /// Offer a snapshot. Never blocks, never waits for the disk.
    pub(crate) fn post(&self, snapshot: SessionSnapshot) {
        self.handle().post(snapshot)
    }

    /// Offer the final snapshot, after which nothing replaces it.
    pub(crate) fn post_final(&self, snapshot: SessionSnapshot) -> FinalWait {
        self.handle().post_final(snapshot)
    }
}

/// The posting half of a [`Persister`], cloneable so it can outlive the caller.
#[derive(Clone)]
pub(crate) struct PersistHandle {
    slot: Arc<Slot>,
}

impl PersistHandle {
    fn lock(&self) -> MutexGuard<'_, SlotState> {
        self.slot
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Offer a snapshot. Never blocks, never waits for the disk.
    pub(crate) fn post(&self, snapshot: SessionSnapshot) {
        let mut state = self.lock();
        if state.stopping || state.finished {
            return;
        }
        state.pending = Some(Job::Snapshot(snapshot));
        self.slot.wake.notify_one();
    }

    /// Offer the final snapshot, after which nothing replaces it.
    pub(crate) fn post_final(&self, snapshot: SessionSnapshot) -> FinalWait {
        let mut state = self.lock();
        if !state.stopping && !state.finished {
            state.pending = Some(Job::Final(snapshot));
            self.slot.wake.notify_one();
        }
        let wait = FinalWait {
            slot: Arc::clone(&self.slot),
        };
        // The lock is released before the caller waits.
        drop(state);
        wait
    }
}

impl Drop for Persister {
    /// Nonblocking on purpose: a teardown must not wait for a disk. The thread
    /// is detached; a write in flight finishes on its own, and one that has not
    /// started is dropped with the process.
    fn drop(&mut self) {
        let mut state = self.lock();
        state.stopping = true;
        state.pending = None;
        drop(state);
        self.slot.wake.notify_all();
        drop(self.thread.take());
    }
}

/// A bounded wait for the final write.
pub(crate) struct FinalWait {
    slot: Arc<Slot>,
}

impl FinalWait {
    /// Wait at most `limit`; `true` when the final write finished.
    pub(crate) fn wait(self, limit: Duration) -> bool {
        let deadline = std::time::Instant::now() + limit;
        let mut state = self.slot.state.lock().unwrap_or_else(|p| p.into_inner());
        while !state.finished {
            let now = std::time::Instant::now();
            if now >= deadline {
                return false;
            }
            let (next, timeout) = self
                .slot
                .wake
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state = next;
            if timeout.timed_out() && !state.finished {
                return false;
            }
        }
        true
    }
}

fn write_loop(slot: &Slot, dir: &SessionsDir) {
    // What this thread has already reported, so a newer log's warning is said
    // once and an eviction is not announced on every write.
    let mut reported_warning: Option<String> = None;
    let mut reported_evictions = 0u64;
    loop {
        let job = {
            let mut state = slot.state.lock().unwrap_or_else(|p| p.into_inner());
            loop {
                if let Some(job) = state.pending.take() {
                    break Some(job);
                }
                if state.stopping {
                    break None;
                }
                state = slot
                    .wake
                    .wait(state)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
        };
        let Some(job) = job else { return };
        let snapshot = job.snapshot().clone();
        let final_job = matches!(job, Job::Final(_));
        let state = slot.state.lock().unwrap_or_else(|p| p.into_inner());
        // An older snapshot must never overwrite a newer one, and nothing may
        // replace the final record.
        let skip = snapshot.rev < state.written_rev || state.finished;
        drop(state);
        if !skip {
            match dir.write(&snapshot, now_ms()) {
                Ok(report) => {
                    // A newer build's log is reported once, not on every write;
                    // an eviction is reported when the count moves.
                    if let Some(warning) = report.warning
                        && reported_warning.as_deref() != Some(warning.as_str())
                    {
                        tracing::warn!("{warning}");
                        reported_warning = Some(warning);
                    }
                    if report.evicted_sessions > reported_evictions {
                        reported_evictions = report.evicted_sessions;
                        tracing::info!(
                            evicted = report.evicted_sessions,
                            "the refusal log evicted whole sessions to stay bounded"
                        );
                    }
                }
                // A display log that cannot be written is reported and never
                // fails the launch.
                Err(error) => tracing::warn!("could not write the refusal log: {error:#}"),
            }
        }
        if !skip {
            let mut state = slot.state.lock().unwrap_or_else(|p| p.into_inner());
            state.written_rev = state.written_rev.max(snapshot.rev);
        }
        if final_job {
            let mut state = slot.state.lock().unwrap_or_else(|p| p.into_inner());
            state.finished = true;
            drop(state);
            slot.wake.notify_all();
            return;
        }
    }
}

#[cfg(test)]
mod tests;
