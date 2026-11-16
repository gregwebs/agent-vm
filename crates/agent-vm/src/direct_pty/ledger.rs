//! The terminal ledger: the writer thread's own record of whether a prompt may be
//! on screen, and therefore whether the host restore is owed (#501 slice 3 §6.1).
//!
//! Only the writer knows what reached the descriptor. One thread therefore owns the
//! decision, and the epilogue asks it rather than guessing: from the moment an
//! `Enter(g)` is **admitted** until every byte of that generation's `Leave(g)` is
//! written, `owed` is set and an abnormal end must write the host restore. The
//! restore is correct from every prefix of an enter or a leave (§5.7), so no
//! progress state is needed, and there is no second descriptor to race this one.
//!
//! # What this guarantees, by construction
//!
//! * **G1 — no late prompt byte.** A `Redraw(g)`/`Leave(g)` is written only while
//!   `owed == Some(g)`; `owed` leaves that value only when the leave is complete or
//!   the host restore is taken. A redraw queued behind a leave is discarded.
//! * **G2 — exactly one host restore**, taken under the lock only while owed. It
//!   contains no erase, so even a second copy keeps the main screen.
//! * **G3 — what may follow the wait.** After `Abandoned` the writer starts no write
//!   it had not already passed its check for: at most one more `write(2)`, as after
//!   today's abort.
//!
//! The `admit` kernel is proved (ADR-0018); the writes that surround it are not, and
//! their evidence is the byte-prefix sweep in this module's tests and in the tmux
//! oracle.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use vstd::prelude::*;

use crate::access_prompt::relay::Step;

verus! {

/// Whether the writer may still start a write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriterState {
    Running,
    Aborted,
    Abandoned,
}

/// One frame, as the admission rule sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Frame {
    Data,
    Enter(u64),
    Redraw(u64),
    Leave(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admit {
    Write,
    Discard,
}

/// §6.1's admission table.
pub open spec fn admit_spec(owed: Option<u64>, writer: WriterState, frame: Frame) -> Admit {
    if writer != WriterState::Running {
        Admit::Discard
    } else {
        match frame {
            Frame::Data => Admit::Write,
            Frame::Enter(_) => if owed.is_none() { Admit::Write } else { Admit::Discard },
            Frame::Redraw(g) => if owed == Some(g) { Admit::Write } else { Admit::Discard },
            Frame::Leave(g) => if owed == Some(g) { Admit::Write } else { Admit::Discard },
        }
    }
}

/// The proved admission decision: an `Enter` only when nothing owns the terminal,
/// a `Redraw`/`Leave` only for the generation that owns it, `Data` always while
/// running, and nothing once the writer has stopped.
pub fn admit(owed: Option<u64>, writer: WriterState, frame: Frame) -> (admit: Admit)
    ensures
        // Stated as the case table rather than as equality with `admit_spec`: the
        // equality is definitional, and these are the facts every caller relies on.
        // `admit_spec` stays as the table's one written form (ADR-0018).
        !(writer == WriterState::Running) ==> admit == Admit::Discard,
        match frame {
            Frame::Enter(_) => admit == Admit::Write ==> owed.is_none(),
            Frame::Redraw(g) => admit == Admit::Write ==> owed == Some(g),
            Frame::Leave(g) => admit == Admit::Write ==> owed == Some(g),
            Frame::Data => true,
        },
{
    match writer {
        WriterState::Running => {}
        WriterState::Aborted => return Admit::Discard,
        WriterState::Abandoned => return Admit::Discard,
    }
    match frame {
        Frame::Data => Admit::Write,
        Frame::Enter(_) => {
            if owed.is_none() { Admit::Write } else { Admit::Discard }
        }
        Frame::Redraw(g) => {
            if owed == Some(g) { Admit::Write } else { Admit::Discard }
        }
        Frame::Leave(g) => {
            if owed == Some(g) { Admit::Write } else { Admit::Discard }
        }
    }
}

} // verus!

fn frame_of(step: Step, generation: u64) -> Frame {
    match step {
        Step::Enter { .. } => Frame::Enter(generation),
        Step::Redraw => Frame::Redraw(generation),
        Step::Leave => Frame::Leave(generation),
    }
}

struct State {
    /// `Some(g)` while generation `g` may have a prompt on screen.
    owed: Option<u64>,
    writer: WriterState,
}

/// A test-only rendezvous between a write's admission check and its `write(2)`.
///
/// B2's counterexample is a writer that passes its `Abandoned` check just before
/// the epilogue gives up and then starts the syscall anyway. Only a pause in
/// exactly that window can exercise it, so the hook exists in test builds only and
/// the production writer has no such call at all.
#[cfg(test)]
pub(crate) struct WritePause {
    reached: std::sync::mpsc::Sender<()>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}

#[cfg(test)]
impl WritePause {
    /// The writer's half: announce that a check passed, then wait to be let go.
    pub(crate) fn wait(&self) {
        let _ = self.reached.send(());
        if let Ok(release) = self.release.lock() {
            let _ = release.recv();
        }
    }
}

#[cfg(test)]
fn write_pause(ledger: &TerminalLedger) {
    if let Some(pause) = &ledger.pause {
        pause.wait();
    }
}

#[cfg(not(test))]
fn write_pause(_ledger: &TerminalLedger) {}

/// The ledger the writer and the epilogue share. Decisions under the lock; no write
/// under it.
pub(crate) struct TerminalLedger {
    state: Mutex<State>,
    restored: tokio::sync::Notify,
    #[cfg(test)]
    pause: Option<std::sync::Arc<WritePause>>,
}

impl TerminalLedger {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                owed: None,
                writer: WriterState::Running,
            }),
            restored: tokio::sync::Notify::new(),
            #[cfg(test)]
            pause: None,
        })
    }

    /// Arm the B2 hook. Returns the test's end of it: a receiver that reports each
    /// write that passed its check, and a sender that releases it.
    #[cfg(test)]
    pub(crate) fn armed_for_pause() -> (
        Arc<Self>,
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        let (reached_tx, reached_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let pause = WritePause {
            reached: reached_tx,
            release: std::sync::Mutex::new(release_rx),
        };
        let ledger = Arc::new(TerminalLedger {
            state: Mutex::new(State {
                owed: None,
                writer: WriterState::Running,
            }),
            restored: tokio::sync::Notify::new(),
            pause: Some(Arc::new(pause)),
        });
        (ledger, reached_rx, release_tx)
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Admit one takeover frame, and take the ownership an `Enter` claims.
    pub(crate) fn admit(&self, generation: u64, step: Step) -> Admit {
        let mut state = self.lock();
        let admit = admit(state.owed, state.writer, frame_of(step, generation));
        if admit == Admit::Write && matches!(step, Step::Enter { .. }) {
            state.owed = Some(generation);
        }
        admit
    }

    /// Admit one guest data frame.
    pub(crate) fn admit_data(&self) -> Admit {
        let state = self.lock();
        admit(state.owed, state.writer, Frame::Data)
    }

    /// A frame's every byte reached the descriptor.
    ///
    /// Only a writer that is still `Running` may discharge `owed`: once `abort` has
    /// seen it, the host restore is irrevocable, and a `Leave` that happened to
    /// complete after the abort must not cancel it. Without this, an
    /// alternate-screen guest stayed on its alternate screen with mouse, paste and
    /// synchronized-output modes still on in the host shell (finding 4).
    pub(crate) fn wrote_completely(&self, generation: u64, step: Step) {
        if let Step::Leave = step {
            let mut state = self.lock();
            if state.writer == WriterState::Running && state.owed == Some(generation) {
                state.owed = None;
            }
        }
    }

    /// The B2 hook: called between a write's admission check and its syscall.
    pub(crate) fn pause_before_write(&self) {
        write_pause(self);
    }

    /// Whether the writer may start another write: not once the epilogue gave up.
    pub(crate) fn may_write(&self) -> bool {
        self.lock().writer != WriterState::Abandoned
    }

    /// The epilogue's wait expired: no write may start from now on (G3).
    fn abandon(&self) {
        self.lock().writer = WriterState::Abandoned;
    }

    /// Whether a prompt may be on screen, asked by the writer on its way out.
    pub(crate) fn owed(&self) -> Option<u64> {
        self.lock().owed
    }

    /// The host restore was taken (or the writer had nothing to restore).
    pub(crate) fn restored(&self) {
        let mut state = self.lock();
        state.owed = None;
        drop(state);
        self.restored.notify_waiters();
    }

    /// The epilogue: stop admitting new work, and say whether a restore is owed.
    pub(crate) fn abort(self: &Arc<Self>) -> Option<RestoreWait> {
        let mut state = self.lock();
        state.writer = WriterState::Aborted;
        let owed = state.owed;
        drop(state);
        if owed.is_some() {
            Some(RestoreWait {
                ledger: Arc::clone(self),
            })
        } else {
            None
        }
    }
}

/// The epilogue's wait for the writer's host restore, bounded (§6.1, R28).
pub(crate) struct RestoreWait {
    ledger: Arc<TerminalLedger>,
}

/// How long the epilogue waits for the writer's host restore before giving up.
pub(crate) const HOST_RESTORE_WAIT: Duration = Duration::from_millis(250);

impl RestoreWait {
    /// Wait at most [`HOST_RESTORE_WAIT`], then tell the writer no new write may
    /// start. Returns whether the restore completed in time.
    pub(crate) async fn wait(self) -> bool {
        if self.ledger.owed().is_none() {
            self.ledger.abandon();
            return true;
        }
        let _ = tokio::time::timeout(HOST_RESTORE_WAIT, self.ledger.restored.notified()).await;
        let complete = self.ledger.owed().is_none();
        self.ledger.abandon();
        complete
    }
}

#[cfg(test)]
mod tests;
