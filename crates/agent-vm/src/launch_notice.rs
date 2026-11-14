//! The launch's progress notices: one blocking sink for the ordinary path, one
//! detached delivery for the end that must not be held up by a stalled stderr.
//!
//! The `emit`/`emit_detached` pair replaced `eprintln` wherever the launch path
//! writes progress: `eprintln` panics when the write fails (issue #70), and on the
//! forced path a write can also *never return* (#401), so both facts are owned
//! here rather than at each call site.
//!
//! A notice is one terminal line, and the sink is what makes that true: `emit`
//! escapes every control byte of the message it is given, so no caller can let a
//! measured byte — `$HOME`, a directory entry, a git identity — end the line early
//! and forge another `==> ` notice (#416). A notice the launcher *means* as several
//! lines is the exception and says so, through [`LaunchNotices::emit_block`].
//! [`LaunchNotices::emit_detached`] is not escaped, because one of its callers
//! writes framing control bytes of its own (a `\r` that reclaims a line the guest
//! is mid-way through); its messages are escaped, or control-free, at their source.

use anyhow::{Context, Result};

/// stderr sink for `launch()`'s `==> …` progress notices.
///
/// Exists because `eprintln` panics from inside `std::io::_eprint`
/// ("failed printing to stderr") when the write fails — a real outcome for
/// `agent-vm … 2>&1 | head` (EPIPE) or a full disk — aborting the launcher
/// with exit 101 and no context instead of reaching the error boundary in
/// `main()` (issue #70). Generic over the sink so the failure path is
/// testable without a broken pipe, following `network.rs`'s
/// `emit_launch_notices_to` precedent.
pub(crate) struct LaunchNotices<W> {
    sink: W,
}

impl LaunchNotices<std::io::Stderr> {
    /// The production sink is the `Stderr` *handle*, not a `.lock()` guard:
    /// `StderrLock<'a>` borrows for `'a` and is `!Send`, so it can neither
    /// be a long-lived field here nor cross into the spawned update-banner
    /// task. (Deadlock is not the concern — std's stderr lock is
    /// reentrant-per-thread.) Each `emit` is a single `write_all`, which
    /// takes the lock once, so nothing is lost by not holding it.
    pub(crate) fn to_stderr() -> Self {
        Self::new(std::io::stderr())
    }
}

/// A notice sink that can hand out a second handle to itself.
///
/// [`LaunchNotices::emit_detached`] writes from another thread, so it needs a sink
/// it can own there. `std::io::Stderr` is a handle to one process-wide sink but is
/// deliberately not `Clone`, so "another handle to the same place" is asked for
/// explicitly rather than assumed.
pub(crate) trait NoticeSink: std::io::Write + Send + 'static {
    fn reopened(&self) -> Self;
}

impl NoticeSink for std::io::Stderr {
    fn reopened(&self) -> Self {
        std::io::stderr()
    }
}

impl<W: std::io::Write> LaunchNotices<W> {
    pub(crate) fn new(sink: W) -> Self {
        Self { sink }
    }

    /// Deliver one notice line.
    ///
    /// One `write_all` of the fully rendered line rather than `writeln!`,
    /// which writes once per format-string fragment and could deliver half a
    /// notice before failing. No flush: std's `Stderr` is unbuffered, so
    /// there is nothing to flush and neither `eprintln` nor
    /// `emit_launch_notices_to` does — adding one would change
    /// success-path behavior.
    ///
    /// The line is rendered through [`crate::one_line::text`], so a note's
    /// measured bytes cannot end it early (#416: a mode warning's `$HOME` with a
    /// newline read as a second `==> ` notice). The escape belongs to the sink, not
    /// to the twenty-odd call sites, so the next caller to interpolate something it
    /// did not choose inherits it instead of having to remember it. Nor can it
    /// escape twice: `one_line`'s output holds no control byte, so text a producer
    /// already rendered through `one_line::path`/`text` is unchanged here.
    ///
    /// Several lines are the caller's decision, not the note's — see
    /// [`Self::emit_block`].
    pub(crate) fn emit(&mut self, message: impl std::fmt::Display) -> Result<()> {
        self.write_notice(&crate::one_line::text(&message.to_string()).to_string())
    }

    /// Deliver a notice the launcher deliberately renders as several lines.
    ///
    /// [`Self::emit`]'s escape cannot tell a forged line from a block the launcher
    /// meant, so they are separate doors. What this one guarantees is the
    /// *structure* alone: every line the reader sees is one the launcher wrote.
    /// A measured value inside the block keeps that shape only if the block's own
    /// renderer escapes it, which is why the `AGENT_VM_DEBUG_CONFIG` record spells
    /// its control bytes as JSON escapes (`debug_config::dump_line`) — a project or
    /// bind path inside that JSON is measured. Passing a note in here escapes
    /// nothing.
    pub(crate) fn emit_block(&mut self, message: impl std::fmt::Display) -> Result<()> {
        self.write_notice(&message.to_string())
    }

    fn write_notice(&mut self, line: &str) -> Result<()> {
        let mut rendered = line.to_owned();
        rendered.push('\n');
        self.sink
            .write_all(rendered.as_bytes())
            .with_context(|| format!("writing the launch notice {:?}", rendered.trim_end()))
    }
}

impl<W: NoticeSink> LaunchNotices<W> {
    /// Deliver one notice on a detached thread, best effort.
    ///
    /// For a notice that must not delay a teardown. In a streaming direct launch
    /// this process's stderr is the guest's own channel — `2>&1 | paused-reader`, or
    /// a tty an operator has stopped with Ctrl-S — so `write_all` can fail to return
    /// for as long as the consumer stays away. A notice written synchronously before
    /// the teardown would then leave the sandbox running, with the signal handlers
    /// still installed and capturing every further interrupt: only `SIGKILL` would
    /// end the launcher, which is the one outcome #401 forbids.
    ///
    /// Its cost is that a notice can be lost: the thread is detached, so if the
    /// launcher exits before the consumer accepts the line, the line goes with it.
    /// A progress line is worth less than the VM, and the exit status still says how
    /// the launch ended. Unlike [`Self::emit`] this one flushes: it may be the last
    /// writer before the process exits, and a sink other than stderr may buffer.
    ///
    /// Also unlike [`Self::emit`] it does not escape, because one caller writes
    /// framing bytes on purpose: the refusal hint wraps itself in `\r` to reclaim a
    /// line the guest is mid-way through. That leaves the messages to their
    /// producers — `session_control`'s are its own prose with error chains and
    /// queued-allowance warnings interpolated, which today are escaped or
    /// control-free at their source, not here.
    pub(crate) fn emit_detached(&self, message: impl std::fmt::Display) -> NoticeDelivery {
        let mut line = message.to_string();
        line.push('\n');
        let mut sink = self.sink.reopened();
        let (delivered, settled) = std::sync::mpsc::channel();
        // A failed spawn drops the closure with it, and with the closure the sender,
        // so `settle` then returns at once: the notice is lost and the launch is not.
        let _ = std::thread::Builder::new()
            .name("agent-vm-launch-notice".into())
            .spawn(move || {
                let written = sink.write_all(line.as_bytes()).and_then(|()| sink.flush());
                let _ = delivered.send(written.is_ok());
            });
        NoticeDelivery { settled }
    }
}

/// How long a detached notice is given, after the teardown, to be delivered.
///
/// A bound is all this can be: the write to a stalled consumer never returns, and
/// waiting for it would reintroduce the hang the detached write exists to avoid. A
/// healthy stderr has the whole teardown to accept the line, so this only decides
/// how long the launcher waits past that.
const NOTICE_SETTLE: std::time::Duration = std::time::Duration::from_millis(250);

/// A notice being delivered by a detached thread.
pub(crate) struct NoticeDelivery {
    settled: std::sync::mpsc::Receiver<bool>,
}

impl NoticeDelivery {
    /// Wait, bounded, for the detached write to finish.
    pub(crate) fn settle(self) {
        let _ = self.settled.recv_timeout(NOTICE_SETTLE);
    }
}
