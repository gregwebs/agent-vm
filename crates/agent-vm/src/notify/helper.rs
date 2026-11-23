//! The NDJSON v1 transport to the macOS notification helper, and the one task
//! that owns it.
//!
//! Requirements this file carries (issue #501 slice 4, B6/S6/S7):
//!
//! * **One owner.** A single task owns the helper child, the acknowledged banner
//!   state and the operation sequence. Nothing else may write to the helper, so
//!   "remove after post" can be an ordering this code enforces rather than an
//!   assumption about two writers. The child is owned by [`ReapingChild`], whose
//!   `Drop` kills and reaps it, so no path — a dropped handle, a timed-out
//!   `finish`, a panic — leaves the process behind.
//! * **Serialized operations.** A `Post` or `Remove` is never written while the
//!   previous one is waiting for its acknowledgement, and every wait is bounded
//!   by [`OP_ACK_TIMEOUT`]. A late acknowledgement is ignored rather than
//!   confused with the current one, because every operation carries a monotonic
//!   `seq` that the helper echoes back; an acknowledgement whose `id` is not the
//!   banner the operation named is a protocol failure, because one banner per
//!   session is replaced in place and the ID cannot be inferred from the `seq`.
//! * **Truthful banner state.** [`AckedState`] moves to `Present` only on
//!   `posted { ok: true }` and back to `Absent` only on `removed { ok: true }`.
//!   A write error, an ack timeout, a `posted { ok: false }` or an EOF while an
//!   operation was in flight leaves it `Ambiguous`, which the next `Remove`
//!   reconciles.
//! * **Nothing reaches the operator's stderr.** The child's stderr is
//!   `/dev/null`; the only line this feature prints is the session's hint, which
//!   the caller owns.
//! * **A launch never fails here** (R12). Every failure is a state, not an error
//!   returned to the launch: the helper is respawned within a bounded number of
//!   attempts and otherwise stays quiet.
//! * **The permission dialog is not a timeout.** `auth { status:
//!   "notDetermined" }` is a phase of its own: no `post`, no `remove`, and
//!   therefore no acknowledgement timer and no failure counted while the operator
//!   decides. Only an explicit `notDetermined` frame gates anything, so a helper
//!   that never sends `auth` cannot silence the session (see
//!   [`Driver::authorization`]).
//!
//! The clock is `tokio::time::Instant`, so a test can run the whole lifecycle
//! under `#[tokio::test(start_paused = true)]`; the coalescer is synchronous and
//! takes `std::time::Instant`, so the two meet at [`std_now`].

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;

use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt as _, AsyncRead, AsyncWriteExt as _, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::time::Instant;

use crate::allowances::{LiveAllowances, Offer, grantable_destination};
use crate::egress_policy::Allowance;
use crate::notify::FinalWriteStatus;
use crate::notify::coalesce::{
    Coalescer, DesiredState, EntryOffer, NotificationPayload, PromptMode, PromptSignal,
    SessionMeta, Timings,
};
use crate::refusal::feed::{Hint, LiveRefusals};
use crate::refusal::{RefusalEntry, SessionId, SessionSnapshot, Update};

/// The only protocol version this build speaks (S6).
pub(crate) const PROTOCOL_VERSION: u32 = 1;

/// The longest line the helper may send. A longer one is a frame this build does
/// not understand, and it is skipped rather than buffered (S6).
pub(crate) const MAX_HELPER_LINE_BYTES: usize = 16 * 1024;

/// How long one `Post`/`Remove` may wait for its acknowledgement.
pub(crate) const OP_ACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// How long a graceful quit may take before the child is killed.
pub(crate) const QUIT_WAIT: std::time::Duration = std::time::Duration::from_millis(500);

/// The whole cleanup-only spawn: spawn, `Remove`, `Quit`, reap.
pub(crate) const CLEANUP_SPAWN_TIMEOUT: std::time::Duration =
    std::time::Duration::from_millis(1500);

/// How long [`crate::notify::NotifierHandle::finish`] — and the shutdown
/// [`crate::notify::NotifierHandle`]'s `Drop` asks for — waits for the driver.
///
/// 3 s, not the plan's 1.5 s (recorded deviation, F2): 1.5 s is shorter than
/// [`OP_ACK_TIMEOUT`], so a post written just before teardown could never settle
/// and every teardown with an operation in flight aborted the driver instead of
/// folding the final snapshot. The arithmetic: 2 s for the operation in flight
/// ([`OP_ACK_TIMEOUT`]) + 500 ms for the graceful quit ([`QUIT_WAIT`]) + 500 ms of
/// margin.
///
/// Bounded honestly: a teardown that needs *both* an in-flight settle and a final
/// post can take 2 s + 2 s + 500 ms, and 3 s will abort that one. The final post
/// is the only thing lost, and only when the helper is already slow enough to be
/// two acknowledgements behind.
pub(crate) const NOTIFY_FINISH_WAIT: std::time::Duration = std::time::Duration::from_secs(3);

/// After this long with nothing to do the helper is quit, so a session that
/// stops refusing does not keep an AppKit process alive.
pub(crate) const HELPER_IDLE_EXIT: std::time::Duration = std::time::Duration::from_secs(30);

/// How many consecutive failed operations (spawn, write, acknowledgement) are
/// tolerated before this session stops trying. Two: one transient failure is
/// worth retrying, a helper that fails twice in a row is not going to start
/// working, and the stderr hint plus `agent-vm access` remain (R12).
const MAX_FAILURES: u32 = 2;

/// The argument that puts the helper into `serve` mode.
const SERVE_ARG: &str = "serve";

/// The `auth.status` that means the permission dialog is still up: the one status
/// this driver acts on besides `denied`.
const AUTH_NOT_DETERMINED: &str = "notDetermined";

// ---------------------------------------------------------------------------
// The wire: NDJSON v1
// ---------------------------------------------------------------------------

/// One command to the helper. Serialized as a single line of JSON.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub(crate) enum HelperCommand {
    Post {
        v: u32,
        seq: u64,
        id: String,
        thread: String,
        title: String,
        subtitle: String,
        body: String,
        passive: bool,
        click: ClickUserInfo,
    },
    Remove {
        v: u32,
        seq: u64,
        id: String,
    },
    Quit {
        v: u32,
    },
}

impl HelperCommand {
    fn post(seq: u64, payload: &NotificationPayload, click: &ClickUserInfo) -> Self {
        Self::Post {
            v: PROTOCOL_VERSION,
            seq,
            id: payload.id.clone(),
            thread: payload.thread.clone(),
            title: payload.title.clone(),
            subtitle: payload.subtitle.clone(),
            body: payload.body.clone(),
            passive: payload.passive,
            click: click.clone(),
        }
    }

    fn remove(seq: u64, id: &str) -> Self {
        Self::Remove {
            v: PROTOCOL_VERSION,
            seq,
            id: id.to_owned(),
        }
    }

    fn quit() -> Self {
        Self::Quit {
            v: PROTOCOL_VERSION,
        }
    }
}

/// What a click needs to open the right report hours later (B8).
///
/// Every field is launcher-originated and strict: a path that is not UTF-8 is
/// refused by [`ClickUserInfo::try_from_paths`], because JSON cannot carry it and
/// a lossy conversion would name a directory that does not exist.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct ClickUserInfo {
    pub(crate) session: String,
    pub(crate) project: String,
    pub(crate) state_dir: String,
    pub(crate) terminal: String,
}

impl ClickUserInfo {
    /// `None` on a relative or non-UTF-8 path, or a NUL byte in one.
    ///
    /// `argv` cannot carry a NUL, and a relative path would be resolved against
    /// whatever directory the helper happens to run in, so both are refused here
    /// rather than at click time (R8).
    pub(crate) fn try_from_paths(
        session: &SessionId,
        project: &Path,
        state_root: &Path,
        terminal: &str,
    ) -> Option<Self> {
        Some(Self {
            session: session.as_str().to_owned(),
            project: wire_path(project)?,
            state_dir: wire_path(state_root)?,
            terminal: wire_text(terminal)?,
        })
    }
}

/// One line, as an operand the helper can pass to `--project` / `--state-dir`.
fn wire_path(path: &Path) -> Option<String> {
    if !path.is_absolute() {
        return None;
    }
    wire_text(path.to_str()?)
}

/// Text that survives JSON *and* `argv`: non-empty, NUL-free, valid UTF-8.
fn wire_text(text: &str) -> Option<String> {
    if text.is_empty() || text.contains('\0') {
        return None;
    }
    Some(text.to_owned())
}

/// One event from the helper.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum HelperEvent {
    Launched {
        v: u32,
        #[serde(default)]
        serving: bool,
        #[serde(default)]
        pid: u32,
    },
    Auth {
        v: u32,
        #[serde(default)]
        granted: bool,
        #[serde(default)]
        status: String,
        #[serde(default, rename = "alertStyle")]
        alert_style: String,
        #[serde(default)]
        error: String,
    },
    Posted {
        v: u32,
        seq: u64,
        id: String,
        #[serde(default)]
        ok: bool,
        #[serde(default)]
        denied: bool,
        #[serde(default)]
        error: String,
    },
    Removed {
        v: u32,
        seq: u64,
        id: String,
        #[serde(default)]
        ok: bool,
    },
    Click {
        v: u32,
        action: String,
        session: String,
    },
    OpenFailed {
        v: u32,
        session: String,
        error: String,
    },
    StdinClosed {
        v: u32,
    },
    /// A frame whose `type` this build does not know. It is skipped rather than
    /// treated as an error, so a newer helper cannot break an older launcher.
    #[serde(other)]
    Unknown,
}

/// Decode one line. `None` for anything this build must skip: malformed JSON, a
/// missing or wrong `v`, an unknown shape (S6).
fn decode(line: &[u8]) -> Option<HelperEvent> {
    let value: serde_json::Value = serde_json::from_slice(line).ok()?;
    if value.get("v")?.as_u64()? != u64::from(PROTOCOL_VERSION) {
        return None;
    }
    serde_json::from_value(value).ok()
}

/// Encode one command as one line.
fn encode(command: &HelperCommand) -> io::Result<Vec<u8>> {
    let mut line = serde_json::to_vec(command).map_err(io::Error::other)?;
    line.push(b'\n');
    Ok(line)
}

// ---------------------------------------------------------------------------
// Backends
// ---------------------------------------------------------------------------

/// The helper process, as the driver sees it: write one line, read one line,
/// close stdin, go away.
///
/// Two implementations: [`ChildHelperBackend`] for the real helper, and
/// [`tests::FakeHelperBackend`] for the lifecycle tests, which is why the driver
/// can be exercised under a virtual clock with no child process (S6).
pub(crate) trait HelperBackend: Send {
    fn write<'a>(&'a mut self, command: &'a HelperCommand) -> BoxFuture<'a, io::Result<()>>;
    /// The next event, or `None` at EOF. Cancel-safe: bytes already read stay
    /// buffered in the backend, so dropping the future loses nothing.
    fn read(&mut self) -> BoxFuture<'_, io::Result<Option<HelperEvent>>>;
    fn close_stdin(&mut self) -> BoxFuture<'_, ()>;
    /// Kill if still running, then reap. Idempotent.
    fn terminate(&mut self) -> BoxFuture<'_, ()>;
}

/// How the driver obtains a backend. Production reads the executable once; a
/// test hands out in-memory fakes.
pub(crate) trait HelperSpawner: Send + Sync {
    fn spawn(&self) -> BoxFuture<'static, io::Result<Box<dyn HelperBackend>>>;
}

/// The helper process, held so that dropping the driver's future still kills and
/// reaps it (F3).
///
/// `kill_on_drop(true)` only *signals*: it calls `start_kill` and leaves the
/// reaping to tokio's orphan queue, which a shutting-down runtime never runs. A
/// dropped [`crate::notify::NotifierHandle`], a timed-out `finish` or a panicked
/// driver would then leave a child behind. This guard is the whole lifetime
/// instead of half of it, and it is why the command no longer sets
/// `kill_on_drop`: the signal is certain (synchronous) and the reap is real
/// (`wait()` on the current runtime).
///
/// Residual window, stated rather than papered over: with no runtime to run
/// `wait()` — a plain blocking caller, a runtime already shut down — the child is
/// signalled and `try_wait()` is all that is left, so the kernel may keep a
/// zombie until this process exits. Nothing here can wait without a runtime, and
/// a command that *did* block would deadlock a current-thread runtime instead.
struct ReapingChild {
    child: Option<Child>,
}

impl ReapingChild {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    /// Take the child out, so a bounded caller can kill and reap it itself; the
    /// guard then has nothing left to do.
    fn take(&mut self) -> Option<Child> {
        self.child.take()
    }

    /// The child's pid, for the test that can only observe its exit from outside.
    #[cfg(test)]
    fn pid(&self) -> Option<u32> {
        self.child.as_ref().and_then(|child| child.id())
    }
}

impl Drop for ReapingChild {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        // 1. The signal: synchronous, so it happens even if nothing below runs.
        let _ = child.start_kill();
        // 2. The reap, on whatever runtime is current.
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    let _ = child.wait().await;
                });
            }
            Err(_) => {
                let _ = child.try_wait();
            }
        }
    }
}

/// The production helper: a real child process speaking NDJSON on its stdio.
pub(crate) struct ChildHelperBackend {
    child: ReapingChild,
    /// `None` once stdin has been dropped: closing the pipe's write end is the
    /// EOF the helper drains and exits on. `AsyncWrite::shutdown` on a pipe only
    /// flushes, so the handle itself is what has to go.
    stdin: Option<ChildStdin>,
    frames: Frames<ChildStdout>,
}

impl ChildHelperBackend {
    pub(crate) fn spawn(binary: &Path) -> io::Result<Self> {
        let mut child = Command::new(binary)
            .arg(SERVE_ARG)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // The helper's diagnostics never reach the operator's terminal: one
            // line per session is all this feature is allowed to print (R6).
            .stderr(Stdio::null())
            .spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("the helper has no stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("the helper has no stdout"))?;
        Ok(Self {
            child: ReapingChild::new(child),
            stdin: Some(stdin),
            frames: Frames::new(stdout),
        })
    }

    /// The same backend, for Phase 7's `#[ignore]` child-process contract tests,
    /// which drive this production backend against `harness fake-notifier`.
    #[cfg(test)]
    pub(crate) fn for_binary(binary: &Path) -> io::Result<Self> {
        Self::spawn(binary)
    }

    /// The child's pid, for the test that can only watch from outside.
    #[cfg(test)]
    pub(crate) fn pid(&self) -> Option<u32> {
        self.child.pid()
    }
}

impl HelperBackend for ChildHelperBackend {
    fn write<'a>(&'a mut self, command: &'a HelperCommand) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let line = encode(command)?;
            let stdin = self
                .stdin
                .as_mut()
                .ok_or_else(|| io::Error::other("the helper's stdin is closed"))?;
            stdin.write_all(&line).await?;
            stdin.flush().await
        })
    }

    fn read(&mut self) -> BoxFuture<'_, io::Result<Option<HelperEvent>>> {
        Box::pin(async move { self.frames.next().await })
    }

    fn close_stdin(&mut self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            // Dropping the pipe's write end is the EOF the helper waits for.
            self.stdin = None;
        })
    }

    fn terminate(&mut self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let Some(mut child) = self.child.take() else {
                return;
            };
            let _ = child.start_kill();
            let _ = child.wait().await;
        })
    }
}

/// The line framing every helper frame goes through (S6): one newline-delimited
/// line at a time, at most [`MAX_HELPER_LINE_BYTES`], resynchronizing after an
/// oversize line without ever buffering more than the cap.
///
/// One implementation for the child's stdout and for the tests' byte slice
/// ([`Frames::from_bytes`]), so the boundaries are the ones the child really runs
/// rather than a second copy of the rules (F5).
struct Frames<R> {
    reader: BufReader<R>,
    /// Bytes read but not yet consumed as a line. Kept across `next` calls so a
    /// cancelled read loses nothing.
    line: Vec<u8>,
    /// Set while skipping an oversize frame: everything up to the next newline is
    /// dropped, so a line longer than the cap cannot grow this buffer.
    discarding: bool,
}

impl<R: AsyncRead + Unpin> Frames<R> {
    fn new(reader: R) -> Self {
        Self {
            reader: BufReader::new(reader),
            line: Vec::new(),
            discarding: false,
        }
    }

    /// The next frame this build understands, or `None` at EOF.
    ///
    /// An oversize line, malformed JSON, an event shape this build does not know
    /// and any `v` but ours are skipped rather than reported, so a newer helper
    /// cannot break an older launcher. At EOF a partial line is dropped: nothing
    /// can tell whether the rest would have made it a frame.
    async fn next(&mut self) -> io::Result<Option<HelperEvent>> {
        loop {
            // Whatever is already buffered comes first. The frame that follows an
            // oversize one can arrive in the same read as its terminator, so
            // reading again before taking it would lose it at EOF.
            match self.take_line() {
                Line::Absent => {}
                Line::Skipped => continue,
                Line::Frame(bytes) => {
                    if bytes.len() > MAX_HELPER_LINE_BYTES {
                        continue;
                    }
                    if let Some(event) = decode(&bytes) {
                        return Ok(Some(event));
                    }
                    continue;
                }
            }
            if self.line.len() > MAX_HELPER_LINE_BYTES {
                // An oversize line with no terminator yet: forget what we have
                // and skip to the newline that ends it.
                self.line.clear();
                self.discarding = true;
            }
            let available = self.reader.fill_buf().await?;
            if available.is_empty() {
                // EOF: whatever is left is a line that never ended.
                self.line.clear();
                self.discarding = false;
                return Ok(None);
            }
            self.line.extend_from_slice(available);
            let read = available.len();
            self.reader.consume(read);
        }
    }

    /// Take one complete line out of `line`.
    fn take_line(&mut self) -> Line {
        let Some(end) = self.line.iter().position(|byte| *byte == b'\n') else {
            return Line::Absent;
        };
        let mut bytes: Vec<u8> = self.line.drain(..=end).collect();
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
        if self.discarding {
            self.discarding = false;
            return Line::Skipped;
        }
        Line::Frame(bytes)
    }
}

/// What one [`Frames::take_line`] call found.
enum Line {
    /// No terminator in the buffer yet.
    Absent,
    /// A line was consumed and dropped: the remainder of an oversize one.
    Skipped,
    /// One complete line, without its terminator.
    Frame(Vec<u8>),
}

#[cfg(test)]
impl Frames<io::Cursor<Vec<u8>>> {
    /// The production framing over an in-memory stream, so a test can drive the
    /// boundaries a child would have to hit by chance.
    fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self::new(io::Cursor::new(bytes.into()))
    }
}

/// The production spawner: one executable path, spawned on demand.
pub(crate) struct ChildHelperSpawner {
    binary: PathBuf,
}

impl ChildHelperSpawner {
    pub(crate) fn new(binary: PathBuf) -> Self {
        Self { binary }
    }
}

impl HelperSpawner for ChildHelperSpawner {
    fn spawn(&self) -> BoxFuture<'static, io::Result<Box<dyn HelperBackend>>> {
        let binary = self.binary.clone();
        Box::pin(async move {
            let backend = ChildHelperBackend::spawn(&binary)?;
            Ok(Box::new(backend) as Box<dyn HelperBackend>)
        })
    }
}

// ---------------------------------------------------------------------------
// The client: one child, one line at a time
// ---------------------------------------------------------------------------

/// What a read produced.
enum ClientEvent {
    Event(HelperEvent),
    Eof,
    /// A read that did not produce a line. Every consumer treats it as [`Eof`]:
    /// the child is gone and nothing is owed to it. The error is carried anyway
    /// because it is the only clue when a helper dies for a reason the protocol
    /// does not explain, and a future reader of this state machine should not have
    /// to re-add the plumbing to see it.
    Failed(#[allow(dead_code)] io::Error),
}

/// The driver's view of the child process, with no protocol knowledge: it writes
/// whole commands, reads whole events and closes cleanly.
struct HelperClient {
    spawner: Box<dyn HelperSpawner>,
    backend: Option<Box<dyn HelperBackend>>,
}

impl HelperClient {
    fn new(spawner: Box<dyn HelperSpawner>) -> Self {
        Self {
            spawner,
            backend: None,
        }
    }

    fn is_running(&self) -> bool {
        self.backend.is_some()
    }

    async fn spawn(&mut self) -> io::Result<()> {
        self.backend = None;
        self.backend = Some(self.spawner.spawn().await?);
        Ok(())
    }

    async fn send(&mut self, command: &HelperCommand) -> io::Result<()> {
        let backend = self
            .backend
            .as_mut()
            .ok_or_else(|| io::Error::other("the helper is not running"))?;
        backend.write(command).await
    }

    /// The next event. Parks for ever with no child, so the driver's `select!`
    /// branch is inert instead of busy.
    async fn next_event(&mut self) -> ClientEvent {
        let Some(backend) = self.backend.as_mut() else {
            return std::future::pending().await;
        };
        match backend.read().await {
            Ok(Some(event)) => ClientEvent::Event(event),
            Ok(None) => ClientEvent::Eof,
            Err(error) => ClientEvent::Failed(error),
        }
    }

    async fn close_stdin(&mut self) {
        if let Some(backend) = self.backend.as_mut() {
            backend.close_stdin().await;
        }
    }

    async fn terminate(&mut self) {
        if let Some(mut backend) = self.backend.take() {
            backend.terminate().await;
        }
    }

    /// `Quit`, drop stdin, wait up to `wait` for the child to go, then kill and
    /// reap whatever is left. Events that arrive in the window are discarded: the
    /// session is over, so nothing they say can still be acted on.
    async fn graceful_close(&mut self, wait: std::time::Duration) {
        if !self.is_running() {
            return;
        }
        let _ = self.send(&HelperCommand::quit()).await;
        self.close_stdin().await;
        let deadline = Instant::now() + wait;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, self.next_event()).await {
                Ok(ClientEvent::Eof) | Ok(ClientEvent::Failed(_)) | Err(_) => break,
                Ok(ClientEvent::Event(_)) => continue,
            }
        }
        self.terminate().await;
    }
}

// ---------------------------------------------------------------------------
// The acknowledged banner
// ---------------------------------------------------------------------------

/// What this session knows about the banner the helper is showing (B6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AckedState {
    /// No banner: a post is an add, and there is nothing to remove.
    Absent,
    /// The helper confirmed `posted { ok: true }` for this ID.
    Present { id: String },
    /// An operation's outcome is unknown (write error, ack timeout, EOF while in
    /// flight). The next `Remove` reconciles it.
    Ambiguous,
}

impl AckedState {
    /// Whether a banner may exist. `Ambiguous` counts as "may": the coalescer
    /// then reports `DesiredState::None` once nothing is owed, which is exactly
    /// the reconcile a `Remove` performs.
    fn maybe_present(&self) -> bool {
        !matches!(self, Self::Absent)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Process {
    /// No child. Kept `AckedState` across this state on purpose.
    Idle,
    Ready,
    /// Too many consecutive failures: this session stops trying (R12).
    Broken,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OpKind {
    Post,
    Remove,
}

struct PendingOp {
    seq: u64,
    kind: OpKind,
    /// The banner this operation names. An acknowledgement has to echo it: one
    /// banner per session is replaced in place, so a `seq` that matches but an
    /// `id` that does not is a protocol failure, not an accept (F4).
    expected_id: String,
    /// For a `Post`: the coalescer revision it carried and the entries it spoke
    /// for, so its acknowledgement can settle exactly those.
    post: Option<(u64, Vec<String>)>,
    deadline: Instant,
}

/// Everything the driver needs from the launch.
pub(crate) struct DriverInputs {
    pub(crate) refusals: Arc<LiveRefusals>,
    pub(crate) allowances: Arc<LiveAllowances>,
    pub(crate) notifications_off: Arc<Hint>,
    pub(crate) meta: SessionMeta,
    pub(crate) mode: PromptMode,
    pub(crate) click: ClickUserInfo,
    /// A test seam at the one instant a test cannot otherwise reach: between
    /// building a `Post` and committing it, where the pre-commit drain runs (F1,
    /// F6). `#[cfg(test)]`, so no production build carries a hook at all.
    #[cfg(test)]
    pub(crate) before_commit: Option<Box<dyn FnMut() + Send>>,
}

/// What a completion request asks for.
pub(crate) enum FinishPlan {
    /// The session ended: fold the last drained snapshot, flush one final post
    /// when the final write persisted, then close (R9, B5).
    Session {
        snapshot: SessionSnapshot,
        status: FinalWriteStatus,
    },
    /// The handle was dropped without `finish`: nothing may be folded and no
    /// banner may claim durability, but the child is closed by the same bounded
    /// path, so it is never left running (F3).
    Abandoned,
}

/// The session's completion request.
pub(crate) struct FinishRequest {
    pub(crate) plan: FinishPlan,
    pub(crate) done: oneshot::Sender<()>,
}

/// Start the driver task's body.
pub(crate) async fn run(
    inputs: DriverInputs,
    signals: mpsc::UnboundedReceiver<PromptSignal>,
    spawner: Box<dyn HelperSpawner>,
    requests: mpsc::UnboundedReceiver<FinishRequest>,
) {
    Driver::new(inputs, signals, spawner, requests).run().await
}

/// One wakeup.
enum Tick {
    Finish(Option<FinishRequest>),
    Signal(Option<PromptSignal>),
    Answer(Result<String, broadcast::error::RecvError>),
    Refusal(Result<Update, broadcast::error::RecvError>),
    Event(ClientEvent),
    Timer,
}

struct Driver {
    coalescer: Coalescer,
    allowances: Arc<LiveAllowances>,
    refusals: Arc<LiveRefusals>,
    notifications_off: Arc<Hint>,
    refusals_rx: broadcast::Receiver<Update>,
    answers: broadcast::Receiver<String>,
    signals: mpsc::UnboundedReceiver<PromptSignal>,
    requests: mpsc::UnboundedReceiver<FinishRequest>,
    client: HelperClient,
    click: ClickUserInfo,
    /// `agent-vm.<project_hash>.<sid>`: recorded from the last post, and the
    /// fallback a reconcile uses when the ack state is `Ambiguous`.
    banner_id: String,
    /// Entry ID → canonical destination, for the answer rechecks. Only the
    /// launcher can derive this, and a recheck is a query against the session's
    /// own answer set (B3).
    destinations: HashMap<String, Allowance>,
    /// Entry ID → the highest count folded in, so a lag-recovery snapshot does not
    /// re-announce what is already known.
    seen: HashMap<String, u64>,
    acked: AckedState,
    process: Process,
    /// R5, and the switch that stops a denied session from posting (R6).
    denied: bool,
    /// The helper said `notDetermined`: the permission dialog is up and
    /// human-paced. Nothing is written while this is set ([`Driver::authorization`]).
    auth_pending: bool,
    seq: u64,
    pending: Option<PendingOp>,
    /// Consecutive failed operations; reset by any acknowledgement.
    failures: u32,
    /// When to try again after a failure, so a broken helper cannot spin.
    retry_at: Option<Instant>,
    /// The test seam from [`DriverInputs::before_commit`].
    #[cfg(test)]
    before_commit: Option<Box<dyn FnMut() + Send>>,
    /// When the helper was last written to or heard from.
    last_activity: Instant,
    /// Whether the one bounded cleanup-only spawn of this idle period is still
    /// available (§3.3 B).
    cleanup_armed: bool,
    signals_open: bool,
    answers_open: bool,
    refusals_open: bool,
    requests_open: bool,
}

/// The coalescer's clock. `tokio`'s clock is the one a virtual-clock test can
/// move, and in production it is the same monotonic clock.
fn std_now() -> std::time::Instant {
    Instant::now().into_std()
}

impl Driver {
    fn new(
        inputs: DriverInputs,
        signals: mpsc::UnboundedReceiver<PromptSignal>,
        spawner: Box<dyn HelperSpawner>,
        requests: mpsc::UnboundedReceiver<FinishRequest>,
    ) -> Self {
        // B3: subscribe to the answers *before* the refusals. A grant that lands
        // between the two is then either in the answer set the intake filters
        // against or on the answers channel; subscribed the other way round it
        // could be missed by both.
        let answers = inputs.allowances.subscribe_answers();
        let (snapshot, refusals_rx) = inputs.refusals.subscribe();
        let banner_id = format!(
            "agent-vm.{}.{}",
            inputs.meta.project_hash,
            inputs.meta.session_id.as_str()
        );
        let mut driver = Self {
            coalescer: Coalescer::new(inputs.meta, inputs.mode, Timings::default()),
            allowances: Arc::clone(&inputs.allowances),
            refusals: Arc::clone(&inputs.refusals),
            notifications_off: inputs.notifications_off,
            refusals_rx,
            answers,
            signals,
            requests,
            client: HelperClient::new(spawner),
            click: inputs.click,
            banner_id,
            destinations: HashMap::new(),
            seen: HashMap::new(),
            acked: AckedState::Absent,
            process: Process::Idle,
            denied: false,
            auth_pending: false,
            seq: 0,
            pending: None,
            failures: 0,
            retry_at: None,
            #[cfg(test)]
            before_commit: inputs.before_commit,
            last_activity: Instant::now(),
            cleanup_armed: false,
            signals_open: true,
            answers_open: true,
            refusals_open: true,
            requests_open: true,
        };
        driver.intake_snapshot(snapshot);
        driver
    }

    async fn run(mut self) {
        loop {
            self.pump().await;
            match self.next_tick().await {
                Tick::Finish(Some(request)) => {
                    self.finish(request).await;
                    return;
                }
                // A closed channel is parked, never polled again: a ready branch
                // that never yields would spin the loop.
                Tick::Finish(None) => self.requests_open = false,
                Tick::Signal(Some(signal)) => self.coalescer.on_prompt_signal(signal),
                Tick::Signal(None) => self.signals_open = false,
                Tick::Answer(answer) => self.apply_answer(answer),
                Tick::Refusal(update) => self.apply_update(update),
                Tick::Event(ClientEvent::Event(event)) => self.apply_event(event).await,
                Tick::Event(ClientEvent::Eof) | Tick::Event(ClientEvent::Failed(_)) => {
                    self.child_lost().await;
                }
                Tick::Timer => {}
            }
        }
    }

    // -- intake -------------------------------------------------------------

    /// Fold one snapshot in. Every entry goes through the answer filter, so a
    /// grant that landed before this subscription can never be posted (B3).
    fn intake_snapshot(&mut self, snapshot: SessionSnapshot) {
        for entry in &snapshot.entries {
            self.fold_entry(entry);
        }
    }

    fn fold_entry(&mut self, entry: &RefusalEntry) {
        let known = self.seen.get(&entry.id).copied().unwrap_or(0);
        if entry.count <= known {
            return;
        }
        self.seen.insert(entry.id.clone(), entry.count);
        let destination = grantable_destination(entry).ok();
        if let Some(destination) = &destination {
            self.destinations
                .insert(entry.id.clone(), destination.clone());
            if self.allowances.answered(destination) {
                // Answered elsewhere: the attempt is disposed of, not shown.
                self.coalescer.on_answered_destination(destination);
                return;
            }
        }
        let offer = match &destination {
            Some(destination) => match self.allowances.offer(destination) {
                Ok(Offer::SessionOrProject) => EntryOffer::SessionOrProject,
                Ok(Offer::ProjectNextLaunch) => EntryOffer::ProjectNextLaunch,
                // A host proxy in use, or any other precondition failure: no
                // grant could be offered, so the banner must say so.
                Err(_) => EntryOffer::NotGrantableOrUnofferable,
            },
            None => EntryOffer::NotGrantableOrUnofferable,
        };
        self.coalescer
            .on_entry(entry, destination, offer, std_now());
    }

    fn apply_update(&mut self, update: Result<Update, broadcast::error::RecvError>) {
        match update {
            Ok(update) => {
                if let Some(entry) = update.entry.as_deref() {
                    self.fold_entry(entry);
                }
            }
            Err(broadcast::error::RecvError::Lagged(_)) => {
                // The wakeup list is incomplete, so the snapshot is the truth:
                // recheck the answers first, then fold every entry from it.
                self.recheck_answers();
                let snapshot = self.refusals.snapshot();
                self.intake_snapshot(snapshot);
            }
            Err(broadcast::error::RecvError::Closed) => self.refusals_open = false,
        }
    }

    /// One answers wakeup. The pump that follows it re-checks every destination
    /// this driver still speaks for, so a wakeup naming one destination can never
    /// leave another answered one showing.
    fn apply_answer(&mut self, answer: Result<String, broadcast::error::RecvError>) {
        match answer {
            Ok(spelling) => match Allowance::parse(&spelling) {
                Ok(destination) => {
                    self.coalescer.on_answered_destination(&destination);
                }
                // An answer this build cannot spell is one it cannot name:
                // re-check the whole set rather than assume nothing was answered.
                Err(_) => {
                    self.recheck_answers();
                }
            },
            Err(broadcast::error::RecvError::Lagged(_)) => {
                self.recheck_answers();
            }
            Err(broadcast::error::RecvError::Closed) => self.answers_open = false,
        }
    }

    /// Query the session's answer set for every destination this driver still
    /// speaks for. Returns whether anything was dropped, so a caller that is
    /// about to commit a post knows to recompute (B3).
    fn recheck_answers(&mut self) -> bool {
        let answered: Vec<(String, Allowance)> = self
            .destinations
            .iter()
            .filter(|(_, destination)| self.allowances.answered(destination))
            .map(|(id, destination)| (id.clone(), destination.clone()))
            .collect();
        let mut dropped = false;
        for (id, destination) in answered {
            self.coalescer.on_answered_destination(&destination);
            self.destinations.remove(&id);
            dropped = true;
        }
        dropped
    }

    /// Consume everything already queued, so a signal or an answer that arrived
    /// before a timer expired is acted on before the timer's post (B2).
    fn drain_intake(&mut self) {
        loop {
            match self.signals.try_recv() {
                Ok(signal) => self.coalescer.on_prompt_signal(signal),
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    self.signals_open = false;
                    break;
                }
            }
        }
        loop {
            match self.answers.try_recv() {
                Ok(answer) => self.apply_answer(Ok(answer)),
                Err(broadcast::error::TryRecvError::Empty) => break,
                Err(broadcast::error::TryRecvError::Lagged(missed)) => {
                    self.apply_answer(Err(broadcast::error::RecvError::Lagged(missed)))
                }
                Err(broadcast::error::TryRecvError::Closed) => {
                    self.answers_open = false;
                    break;
                }
            }
        }
        loop {
            match self.refusals_rx.try_recv() {
                Ok(update) => self.apply_update(Ok(update)),
                Err(broadcast::error::TryRecvError::Empty) => break,
                Err(broadcast::error::TryRecvError::Lagged(missed)) => {
                    self.apply_update(Err(broadcast::error::RecvError::Lagged(missed)));
                }
                Err(broadcast::error::TryRecvError::Closed) => {
                    self.refusals_open = false;
                    break;
                }
            }
        }
    }

    // -- the loop -----------------------------------------------------------

    /// Do one round of work: settle an expired operation, then act on what the
    /// coalescer asks for, then quit an idle helper.
    async fn pump(&mut self) {
        let now = Instant::now();
        self.drain_intake();
        // A retry deadline is *consumed* by the pump that reaches it. Whatever
        // happens next — the operation runs, or posting is no longer allowed —
        // nothing is waiting on that instant any more, so a spent deadline can
        // never keep the timer armed and spin the loop.
        if self.retry_at.is_some_and(|retry| now >= retry) {
            self.retry_at = None;
        }
        if self.auth_pending {
            // The permission dialog is up (see `Self::authorization`), so nothing
            // is written: no `post`, no `remove`, and with them no acknowledgement
            // timer and no failure counted for the wait. The intake above is
            // already folded, so refusals keep collecting in the coalescer while
            // the operator decides. A pending operation cannot exist here —
            // entering the phase abandons whatever was in flight — and the idle
            // exit is part of the same silence: quitting the helper would take the
            // dialog down with it.
            return;
        }
        if let Some(pending) = &self.pending {
            if now < pending.deadline {
                // One operation at a time (B6): nothing is written while this one
                // is waiting for its acknowledgement.
                return;
            }
            self.op_timed_out().await;
            return;
        }
        match self.desired(now) {
            Some(DesiredState::Post {
                payload,
                included_ids,
                revision,
            }) => self.post(payload, included_ids, revision).await,
            Some(DesiredState::None) => self.remove().await,
            None => {}
        }
        if self.process == Process::Ready
            && self.pending.is_none()
            && now.saturating_duration_since(self.last_activity) >= HELPER_IDLE_EXIT
        {
            self.idle_exit().await;
        }
    }

    /// What the coalescer wants, with the answer check that must happen
    /// immediately before a post is committed (B3, F1).
    ///
    /// A `Post` is built by one poll and committed by the caller. Between those
    /// two the pre-commit drain runs, and it can dispose of an attempt the poll
    /// had already put in the payload: a drained [`PromptSignal::Answered`]
    /// changes the coalescer without touching [`LiveAllowances`], so
    /// `recheck_answers()` cannot see it. The payload is therefore rebuilt after
    /// the drain and *that* result is returned; the earlier one is never sent.
    ///
    /// Residual window, honestly: the caller then awaits a spawn and the write
    /// itself, so an answer that lands in that gap is only caught by the next
    /// pass — the banner may be one update behind, never a banner for an attempt
    /// this pass had already seen answered.
    fn desired(&mut self, now: Instant) -> Option<DesiredState> {
        self.drain_intake();
        self.recheck_answers();
        let polled = self.poll_desired(now);
        if !matches!(polled, Some(DesiredState::Post { .. })) {
            return polled;
        }
        // The commit point: everything queued is folded, then the payload is
        // rebuilt from what that left behind.
        #[cfg(test)]
        if let Some(hook) = self.before_commit.as_mut() {
            hook();
        }
        self.drain_intake();
        self.recheck_answers();
        self.poll_desired(now)
    }

    /// One poll, with the acknowledgement state this driver holds.
    fn poll_desired(&mut self, now: Instant) -> Option<DesiredState> {
        self.coalescer
            .poll_desired(now.into_std(), self.acked.maybe_present(), false)
    }

    /// The next instant at which [`Self::pump`] has something new to do.
    fn deadline(&self) -> Option<Instant> {
        if self.auth_pending {
            // Nothing this driver writes is time-driven until the dialog is
            // answered, and the coalescer reports already-due work as `now` — a
            // timer here would spin the loop for as long as the dialog is up. The
            // settled `auth` is an event, not a deadline.
            return None;
        }
        if let Some(pending) = &self.pending {
            return Some(pending.deadline);
        }
        if let Some(retry) = self.retry_at {
            return Some(retry);
        }
        let coalescer = self
            .coalescer
            .next_deadline(std_now())
            .map(Instant::from_std);
        let idle = (self.process == Process::Ready).then(|| self.last_activity + HELPER_IDLE_EXIT);
        match (coalescer, idle) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (left, right) => left.or(right),
        }
    }

    async fn next_tick(&mut self) -> Tick {
        let deadline = self.deadline();
        let timer = async {
            match deadline {
                Some(deadline) => tokio::time::sleep_until(deadline).await,
                None => std::future::pending().await,
            }
        };
        let (signals_open, answers_open) = (self.signals_open, self.answers_open);
        let (refusals_open, requests_open) = (self.refusals_open, self.requests_open);
        tokio::select! {
            // Answers before refusals, matching the subscription order: an
            // answer always gets to speak before a refusal is considered.
            biased;
            request = receive_or_park(requests_open, &mut self.requests) => Tick::Finish(request),
            answer = broadcast_or_park(answers_open, &mut self.answers) => Tick::Answer(answer),
            signal = receive_or_park(signals_open, &mut self.signals) => Tick::Signal(signal),
            update = broadcast_or_park(refusals_open, &mut self.refusals_rx) => Tick::Refusal(update),
            event = self.client.next_event() => Tick::Event(event),
            _ = timer => Tick::Timer,
        }
    }

    // -- operations ---------------------------------------------------------

    /// Make sure a child is running. `false` means it is not (and this session
    /// has recorded why); the caller must not write anything.
    async fn ensure_spawn(&mut self) -> bool {
        if self.process == Process::Ready && self.client.is_running() {
            return true;
        }
        if self.process == Process::Broken {
            return false;
        }
        if let Some(retry) = self.retry_at
            && Instant::now() < retry
        {
            return false;
        }
        match self.client.spawn().await {
            Ok(()) => {
                self.process = Process::Ready;
                self.retry_at = None;
                self.touch();
                true
            }
            Err(_) => {
                self.spawn_failed();
                false
            }
        }
    }

    async fn post(
        &mut self,
        payload: NotificationPayload,
        included_ids: Vec<String>,
        revision: u64,
    ) {
        // A denied session stops posting (R6); a broken one has stopped trying.
        if self.denied || self.process == Process::Broken {
            return;
        }
        if !self.ensure_spawn().await {
            return;
        }
        debug_assert_eq!(
            payload.id, self.banner_id,
            "one banner per session: the remove path names the same ID"
        );
        self.seq += 1;
        let seq = self.seq;
        let command = HelperCommand::post(seq, &payload, &self.click);
        let expected_id = payload.id.clone();
        match self.client.send(&command).await {
            Ok(()) => {
                self.banner_id = payload.id;
                self.touch();
                self.pending = Some(PendingOp {
                    seq,
                    kind: OpKind::Post,
                    expected_id,
                    post: Some((revision, included_ids)),
                    deadline: Instant::now() + OP_ACK_TIMEOUT,
                });
            }
            // A write error leaves the outcome unknown, and the child is not
            // trusted with the next operation.
            Err(_) => self.op_failed().await,
        }
    }

    async fn remove(&mut self) {
        if !self.acked.maybe_present() {
            return;
        }
        match self.process {
            Process::Ready => {
                self.seq += 1;
                let seq = self.seq;
                let command = HelperCommand::remove(seq, &self.banner_id);
                let expected_id = self.banner_id.clone();
                match self.client.send(&command).await {
                    Ok(()) => {
                        self.touch();
                        self.pending = Some(PendingOp {
                            seq,
                            kind: OpKind::Remove,
                            expected_id,
                            post: None,
                            deadline: Instant::now() + OP_ACK_TIMEOUT,
                        });
                    }
                    Err(_) => self.op_failed().await,
                }
            }
            // Idle with a banner that may still be up: one bounded cleanup-only
            // spawn takes it away (§3.3 B). Never when `Absent`, and never twice
            // for the same idle period.
            Process::Idle if self.cleanup_armed => self.cleanup().await,
            Process::Idle | Process::Broken => {}
        }
    }

    /// Spawn → `Remove` → `Quit` → reap, all inside [`CLEANUP_SPAWN_TIMEOUT`].
    async fn cleanup(&mut self) {
        self.cleanup_armed = false;
        let id = self.banner_id.clone();
        self.seq += 1;
        let seq = self.seq;
        let removed = tokio::time::timeout(CLEANUP_SPAWN_TIMEOUT, async {
            if self.client.spawn().await.is_err() {
                return false;
            }
            if self
                .client
                .send(&HelperCommand::remove(seq, &id))
                .await
                .is_err()
            {
                return false;
            }
            loop {
                match self.client.next_event().await {
                    // The removal this spawn exists for has to come back naming
                    // the banner it was asked to take away; anything else leaves
                    // the outcome unknown, exactly as a mismatch does elsewhere.
                    ClientEvent::Event(HelperEvent::Removed {
                        seq: acked,
                        id: acked_id,
                        ok,
                        ..
                    }) if acked == seq && acked_id == id => return ok,
                    ClientEvent::Event(_) => continue,
                    ClientEvent::Eof | ClientEvent::Failed(_) => return false,
                }
            }
        })
        .await
        .unwrap_or(false);
        self.client.graceful_close(QUIT_WAIT).await;
        self.process = Process::Idle;
        if removed {
            self.acked = AckedState::Absent;
            self.coalescer.on_remove_acked();
        } else {
            self.acked = AckedState::Ambiguous;
        }
        self.touch();
    }

    /// Quit an idle helper, keeping [`AckedState`]: the banner is still in
    /// Notification Center, so a later removal must still be able to find it.
    async fn idle_exit(&mut self) {
        self.client.graceful_close(QUIT_WAIT).await;
        self.process = Process::Idle;
        if self.acked.maybe_present() {
            self.cleanup_armed = true;
        }
        self.touch();
    }

    /// The op in flight was never acknowledged: its outcome is unknown, and the
    /// helper is replaced rather than trusted.
    async fn op_timed_out(&mut self) {
        self.pending = None;
        self.op_failed().await;
    }

    async fn op_failed(&mut self) {
        self.failures += 1;
        self.acked = AckedState::Ambiguous;
        self.client.terminate().await;
        self.stopped();
        self.retry_at = Some(Instant::now() + OP_ACK_TIMEOUT);
        self.touch();
    }

    fn spawn_failed(&mut self) {
        self.failures += 1;
        self.stopped();
        self.retry_at = Some(Instant::now() + OP_ACK_TIMEOUT);
        self.touch();
    }

    /// No child is running any more. A banner may still be in Notification
    /// Center, so at most one bounded cleanup-only spawn may later take it away;
    /// and enough consecutive failures end the attempts for this session.
    fn stopped(&mut self) {
        self.process = if self.failures >= MAX_FAILURES {
            Process::Broken
        } else {
            Process::Idle
        };
        if self.process == Process::Idle && self.acked.maybe_present() {
            self.cleanup_armed = true;
        }
    }

    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    // -- helper events ------------------------------------------------------

    async fn apply_event(&mut self, event: HelperEvent) {
        match event {
            // Informational, or already handled by `posted`/`removed`.
            HelperEvent::Launched { .. }
            | HelperEvent::Click { .. }
            | HelperEvent::OpenFailed { .. }
            | HelperEvent::StdinClosed { .. }
            | HelperEvent::Unknown => {}
            HelperEvent::Auth { status, .. } => {
                if status == "denied" {
                    self.deny();
                }
                self.authorization(status == AUTH_NOT_DETERMINED);
            }
            HelperEvent::Posted {
                seq,
                id,
                ok,
                denied,
                ..
            } => {
                let Some(pending) = self.settle(seq, OpKind::Post) else {
                    // A late acknowledgement for an operation this driver already
                    // gave up on: it settles nothing.
                    return;
                };
                if pending.expected_id != id {
                    // The helper named a banner this driver did not write: it
                    // cannot say what is showing, so this is a protocol failure
                    // on the existing counter, never a silent accept (F4).
                    self.ack_failed().await;
                    if denied {
                        self.deny();
                    }
                    self.touch();
                    return;
                }
                if ok {
                    self.failures = 0;
                    self.retry_at = None;
                    self.acked = AckedState::Present { id: id.clone() };
                    self.banner_id = id;
                    if let Some((revision, included_ids)) = pending.post {
                        self.coalescer
                            .on_post_acked(&included_ids, revision, std_now());
                    }
                } else {
                    // The helper could not add it: what is showing is unknown.
                    self.ack_failed().await;
                }
                if denied {
                    self.deny();
                }
            }
            HelperEvent::Removed { seq, id, ok, .. } => {
                let Some(pending) = self.settle(seq, OpKind::Remove) else {
                    return;
                };
                if pending.expected_id != id {
                    // A `Removed` for some other banner says nothing about the
                    // one this driver asked to remove: still unknown (F4).
                    self.ack_failed().await;
                    self.touch();
                    return;
                }
                if ok {
                    self.failures = 0;
                    self.retry_at = None;
                    self.acked = AckedState::Absent;
                    self.coalescer.on_remove_acked();
                } else {
                    self.ack_failed().await;
                }
            }
        }
        self.touch();
    }

    /// Take the pending operation when `seq` and `kind` match, so an
    /// acknowledgement for an operation this driver has already timed out cannot
    /// settle the one that replaced it (B6).
    fn settle(&mut self, seq: u64, kind: OpKind) -> Option<PendingOp> {
        match &self.pending {
            Some(pending) if pending.seq == seq && pending.kind == kind => self.pending.take(),
            _ => None,
        }
    }

    /// A negative, mismatched or failed acknowledgement: the banner state is
    /// unknown, and a retry is delayed so the write cannot spin.
    async fn ack_failed(&mut self) {
        self.failures += 1;
        self.acked = AckedState::Ambiguous;
        self.retry_at = Some(Instant::now() + OP_ACK_TIMEOUT);
        if self.failures >= MAX_FAILURES {
            // The child answered, but twice in a row it could not do the work (or
            // named the wrong banner): the session stops asking, and nothing is
            // left running behind it.
            self.process = Process::Broken;
            self.client.terminate().await;
        }
    }

    /// `auth.status == "denied"` or `posted { denied: true }`: posting stops for
    /// the session and the operator is told once, through the session's hint.
    ///
    /// `fire` is called on every denial on purpose — the [`Hint`]'s own once-flag
    /// is what makes the line appear exactly once, so this cannot print a second
    /// line and cannot disagree with ADR-0064's hint.
    fn deny(&mut self) {
        self.denied = true;
        // Nothing owed can still be posted, so no operation may stay in flight.
        self.pending = None;
        self.notifications_off.fire();
    }

    /// `auth` says whether the permission dialog is still up.
    ///
    /// `notDetermined` is a distinct phase rather than a status to ignore. The
    /// dialog is human-paced, so while it is up this driver (i) sends no `post`
    /// and no `remove`, (ii) therefore starts no acknowledgement timer, and (iii)
    /// counts no failure for the wait — see the gate in [`Self::pump`] and the
    /// absent deadline in [`Self::deadline`]. Owed refusals stay in the coalescer
    /// untouched, because only `posted { ok: true }` settles a post: a settled
    /// `authorized` posts them normally, and a settled `denied` takes the existing
    /// path (the hint fires once, posting stops for the session).
    ///
    /// An operation already in flight when the dialog turns up is abandoned, not
    /// blamed: it was written before this driver could know, so its failure would
    /// be the dialog's doing rather than the helper's, and the coalescer still
    /// owes it. That is the first post of a first-run session, written between
    /// the spawn and the helper's own `auth`.
    ///
    /// Keyed on an explicit frame and nothing else. A helper that never sends
    /// `auth` — an older build, or one that died before asking — must not silence
    /// notifications for ever, so absence is fail-open: only `notDetermined`
    /// gates, and losing the child clears the phase to be re-learned from the next
    /// one.
    fn authorization(&mut self, pending: bool) {
        self.auth_pending = pending;
        if pending && self.pending.take().is_some() {
            self.acked = AckedState::Ambiguous;
        }
    }

    /// The child went away without being asked to.
    async fn child_lost(&mut self) {
        let in_flight = self.pending.take().is_some();
        // The dialog went away with the child, so the phase is re-learned from the
        // next spawn's `auth` rather than held against a helper that is not there
        // (fail-open: nothing may gate posting for ever).
        self.auth_pending = false;
        self.client.terminate().await;
        // Only an operation in flight is open-ended: with none, `AckedState`
        // still describes the banner Notification Center is showing.
        if in_flight {
            self.acked = AckedState::Ambiguous;
        }
        self.failures += 1;
        self.stopped();
        self.touch();
    }

    // -- teardown -----------------------------------------------------------

    /// Fold the last drained snapshot, flush one final post when the final write
    /// persisted, then close the helper (R9, B5).
    ///
    /// A dropped handle asks for the same close with nothing to fold
    /// ([`FinishPlan::Abandoned`]), so `Drop` and `finish` share one bounded path
    /// instead of `Drop` aborting the driver (F3).
    async fn finish(&mut self, request: FinishRequest) {
        // 1. One operation at a time: a post already in flight settles (or times
        //    out) before the final one is written.
        self.settle_in_flight().await;
        if let FinishPlan::Session { snapshot, status } = request.plan {
            // 2. The final snapshot, folded against the authoritative answer set.
            self.recheck_answers();
            self.intake_snapshot(snapshot);
            self.recheck_answers();
            // 3. The documented exception to flood control, and only when the
            //    record that claims durability actually landed (R9). No remove: a
            //    banner that is already delivered stays clickable as an `ended`
            //    session.
            if status == FinalWriteStatus::Persisted
                && !self.denied
                // A dialog still up would fail the post, so the teardown obeys the
                // same silence as the rest of the phase.
                && !self.auth_pending
                && let Some(DesiredState::Post {
                    payload,
                    included_ids,
                    revision,
                }) = self
                    .coalescer
                    .on_session_end(std_now(), self.acked.maybe_present())
            {
                self.post(payload, included_ids, revision).await;
                self.settle_in_flight().await;
            }
        }
        // 4. Quit, wait, kill and reap.
        self.client.graceful_close(QUIT_WAIT).await;
        self.process = Process::Idle;
        let _ = request.done.send(());
    }

    /// Wait for the operation in flight, bounded by its own deadline.
    async fn settle_in_flight(&mut self) {
        loop {
            let Some(deadline) = self.pending.as_ref().map(|pending| pending.deadline) else {
                return;
            };
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                self.op_timed_out().await;
                return;
            }
            match tokio::time::timeout(remaining, self.client.next_event()).await {
                Ok(ClientEvent::Event(event)) => self.apply_event(event).await,
                Ok(ClientEvent::Eof) | Ok(ClientEvent::Failed(_)) => {
                    self.child_lost().await;
                    return;
                }
                Err(_) => {
                    self.op_timed_out().await;
                    return;
                }
            }
        }
    }
}

/// `pending()` for a closed channel, so a closed receiver cannot spin a
/// `select!` branch.
async fn receive_or_park<T>(open: bool, receiver: &mut mpsc::UnboundedReceiver<T>) -> Option<T> {
    if open {
        receiver.recv().await
    } else {
        std::future::pending().await
    }
}

async fn broadcast_or_park<T: Clone>(
    open: bool,
    receiver: &mut broadcast::Receiver<T>,
) -> Result<T, broadcast::error::RecvError> {
    if open {
        receiver.recv().await
    } else {
        std::future::pending().await
    }
}

#[cfg(test)]
mod tests;
