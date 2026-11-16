//! The host half of a direct command's PTY session (#400).
//!
//! A direct launch whose resolved policy is [`crate::direct_terminal::DirectIo::Pty`]
//! drives the guest terminal from here, over the **stock** SDK's public
//! `exec_stream_with(... tty(true).stdin_pipe())`: the handle's events, its
//! stdin sink and its `resize`. Nothing in this module needs a patched SDK, and
//! no legacy launch ever reaches it — `shell` and catalog tools keep
//! `Sandbox::attach()` with no options, byte for byte.
//!
//! The session owns four resources with four different lifetimes, and the
//! differences are the design:
//!
//! * the **host terminal**, duplicated (CLOEXEC, never fd 0 itself) so raw mode
//!   and the reader never touch a descriptor a child inherited. There is no
//!   `/dev/tty` fallback: terminal policy selects a PTY only when stdin *is* a
//!   terminal, so a non-terminal stdin here is a caller mistake, and falling
//!   back would attach a redirected launch to the operator's keyboard;
//! * a **detached std thread** doing the blocking `poll(2)`/`read(2)` on that
//!   terminal, because a tty read cannot be cancelled and `Runtime::drop` waits
//!   for Tokio blocking tasks (ADR-0052). A self-pipe wakes it when the session
//!   ends, so it never keeps reading the operator's keyboard after the guest
//!   exits;
//! * a **second detached std thread** owning a CLOEXEC duplicate of stdout with
//!   a bounded queue. Guest output is written with blocking `write(2)`, so a
//!   slow consumer stalls the session instead of failing it, and a failed write
//!   is the session's error rather than a swallowed `let _ =` (the SDK's
//!   `attach` output path is best effort);
//! * the **terminal ledger** ([`ledger`]), owned by the writer thread: whether a
//!   prompt may be on screen now, and therefore whether an abnormal end owes the
//!   host restore (#501 slice 3 §6.1);
//! * the **exec handle** and the **runtime wait**, released in a fixed order:
//!   restore the terminal, abort the writer, stop the reader, then drop the
//!   runtime wait (which may hold the child-handle mutex the caller's teardown
//!   needs).
//!
//! The session must be able to observe a lost runtime, a writer failure and the
//! end of the event stream **at every point it waits**, including while a full
//! queue holds it. Every send that a peer can stall is therefore a held
//! `select!` *branch* rather than work awaited inside an arm body, which is the
//! one structural rule in this module: see [`PendingSend`].
//!
//! What `attach` does that this module must do itself, in one place:
//!
//! | attach | here |
//! |---|---|
//! | the `ExecRequest` carries the host's real rows/cols | `exec_stream` always asks for 24x80, so the session resizes from `TIOCGWINSZ` immediately after the handle exists |
//! | `crossterm` global raw mode plus a best-effort restore | an owning guard that saves the exact `termios`, restores it on every path and *reports* a restore failure |
//! | `Ctrl-]` ends the session | every byte, including `0x1d`, is forwarded |
//! | a nonblocking tty opened by path | blocking `poll(2)` in a thread, so no `O_NONBLOCK` reaches a shared description |
//! | output failures ignored, `Ok(-1)` when the stream ends | an output failure is an error, and a stream that ends without an exit event is an error rather than a fabricated status |
//!
//! A terminal's Ctrl-C is **not** a host signal here: `cfmakeraw` clears `ISIG`,
//! so it arrives as the byte `0x03` and is forwarded to the guest as ordinary
//! input. #401's `SIGINT`/`SIGTERM` forwarding (an external `kill`, or a Ctrl-C
//! on a *cooked* terminal — the streaming path) is a separate, explicitly
//! signalled path ([`crate::host_signals`]), so one interrupt is never delivered
//! twice.

use std::future::Future;
use std::io::IsTerminal as _;
use std::os::fd::{AsRawFd as _, BorrowedFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Context as _;
use microsandbox::MicrosandboxError;
use microsandbox::sandbox::exec::{ExecControl, ExecEvent, ExecHandle, ExecSink};

mod ledger;

use crate::access_prompt::{self, Prompt};
use crate::direct_input::{GuestInputStatus, classify_stdin_error};
use crate::direct_pty::ledger::{Admit, RestoreWait, TerminalLedger};
use crate::host_signals::{
    GuestSignal, PendingSend, SessionEnd, Supervision, SupervisionStep, signal_send,
    supervision_lost,
};
use crate::refusal::feed::write_hint_to_stderr;

/// The most output the writer may hold, **including the frame it is writing**.
///
/// This is a memory bound, not a throughput limit: when the queue is full a
/// frame waits for capacity, exactly as a native `write(2)` to a slow consumer
/// would block. A full queue must never fail the session.
const MAX_PENDING_OUTPUT_BYTES: usize = 8 * 1024 * 1024;

/// One queued frame. Larger events are split into ordered chunks so no single
/// reservation can exceed [`MAX_PENDING_OUTPUT_BYTES`].
const OUTPUT_CHUNK_BYTES: usize = 64 * 1024;

/// Frames in flight, sized so `OUTPUT_CHUNK_BYTES * OUTPUT_QUEUE_FRAMES` is the
/// pending-byte bound above.
const OUTPUT_QUEUE_FRAMES: usize = MAX_PENDING_OUTPUT_BYTES / OUTPUT_CHUNK_BYTES;

/// One host `read(2)`. In raw mode every byte is input, so this is a latency
/// choice rather than a protocol one.
const HOST_READ_BYTES: usize = 4096;

/// The fallback geometry for a terminal that reports a zero dimension, matching
/// the SDK's own fallback so a working session never becomes a 0x0 one.
const FALLBACK_ROWS: u16 = 24;
const FALLBACK_COLS: u16 = 80;

/// How long the guest PTY stays one column narrower after a prompt on an
/// alternate-screen guest (#494, §5.8): long enough for its resize handler to run.
const NUDGE_SETTLE: std::time::Duration = std::time::Duration::from_millis(100);

// ---------------------------------------------------------------------------
// The session
// ---------------------------------------------------------------------------

/// Drive one direct-command PTY session to its guest status.
///
/// `runtime_exit` is the sandbox's own lifetime: whichever resolves first ends
/// the session, and a runtime exit without a guest exit is a **failure**, never
/// a fabricated status. Callers pass `Sandbox::wait()`; tests pass an owned
/// process.
///
/// The caller owns the handle's creation (so the exec request's command, cwd,
/// user and `PATH` stay exactly where they were) and keeps its existing failure
/// reporting: an `Err` here is reported through `contract_spawn_diagnostic` and
/// the usual teardown, and never becomes an exit code.
///
/// `supervision` is the launch's host-signal supervision (#401). It is inert for
/// a launch that installed no handlers, and it decides the session's **end**
/// rather than its status: a forced shutdown comes back as
/// [`SessionEnd::Forced`] so the caller can tear the sandbox down the forced way.
pub(crate) async fn run<R>(
    mut handle: ExecHandle,
    runtime_exit: R,
    supervision: &mut Supervision,
    prompt: Option<access_prompt::Source>,
) -> anyhow::Result<SessionEnd>
where
    R: Future<Output = microsandbox::MicrosandboxResult<std::process::ExitStatus>>,
{
    // A PTY session with no input channel could not be driven at all; that is a
    // caller mistake, not a guest status.
    let Some(sink) = handle.take_stdin() else {
        return Err(anyhow::anyhow!(
            "the guest terminal session has no input channel"
        ));
    };
    // `ExecControl` is a cloneable handle, so resizes never borrow the handle the
    // receive loop is reading from.
    let control = handle.control();
    let fds = HostFds {
        terminal: duplicate(libc::STDIN_FILENO).context("duplicating the host terminal")?,
        output: duplicate(libc::STDOUT_FILENO).context("duplicating host stdout")?,
    };
    run_session(
        &mut handle,
        control,
        Arc::new(sink),
        fds,
        runtime_exit,
        supervision,
        prompt,
        access_prompt::relay::Timings::default(),
    )
    .await
}

/// The test seam (§8.5): the same loop, drain and epilogue over a stub guest and an
/// `openpty` pair, so the whole session runs without a VM.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
async fn run_with<E, T, I, R>(
    events: &mut E,
    control: T,
    sink: Arc<I>,
    fds: HostFds,
    runtime_exit: R,
    supervision: &mut Supervision,
    prompt: Option<access_prompt::Source>,
    timings: access_prompt::relay::Timings,
) -> anyhow::Result<SessionEnd>
where
    E: GuestEvents,
    T: GuestTerminal,
    I: GuestInput,
    R: Future<Output = microsandbox::MicrosandboxResult<std::process::ExitStatus>>,
{
    run_session(
        events,
        control,
        sink,
        fds,
        runtime_exit,
        supervision,
        prompt,
        timings,
    )
    .await
}

/// The guest half of a session, so `session_loop` runs in tests without a VM
/// (finding 20).
///
/// These extend `host_signals::GuestControl`'s pattern — a narrow trait per
/// capability, implemented for the SDK's own type in production and for a recording
/// stub in tests — so the loop has one shape in both.
pub(crate) trait GuestEvents {
    fn recv(&mut self) -> impl Future<Output = Option<ExecEvent>> + Send;
    fn termination_signal(&self) -> Option<i32>;
}

pub(crate) trait GuestTerminal: crate::host_signals::GuestControl {
    fn resize(&self, rows: u16, cols: u16) -> impl Future<Output = anyhow::Result<()>> + Send;
}

pub(crate) trait GuestInput: Send + Sync + 'static {
    fn write(&self, bytes: Vec<u8>) -> impl Future<Output = anyhow::Result<()>> + Send;
}

impl GuestEvents for ExecHandle {
    async fn recv(&mut self) -> Option<ExecEvent> {
        ExecHandle::recv(self).await
    }

    fn termination_signal(&self) -> Option<i32> {
        ExecHandle::termination_signal(self)
    }
}

impl GuestTerminal for ExecControl {
    async fn resize(&self, rows: u16, cols: u16) -> anyhow::Result<()> {
        ExecControl::resize(self, rows, cols)
            .await
            .map_err(anyhow::Error::new)
    }
}

impl GuestInput for ExecSink {
    async fn write(&self, bytes: Vec<u8>) -> anyhow::Result<()> {
        ExecSink::write(self, bytes)
            .await
            .map_err(anyhow::Error::new)
    }
}

/// The host half's two descriptors: the terminal to read and measure, and stdout to
/// write. Production duplicates fds 0 and 1; a test opens a pair.
pub(crate) struct HostFds {
    terminal: OwnedFd,
    output: OwnedFd,
}

/// One PTY session over the guest and host halves it was given.
#[allow(clippy::too_many_arguments)]
async fn run_session<E, T, I, R>(
    events: &mut E,
    control: T,
    sink: Arc<I>,
    fds: HostFds,
    runtime_exit: R,
    supervision: &mut Supervision,
    prompt: Option<access_prompt::Source>,
    timings: access_prompt::relay::Timings,
) -> anyhow::Result<SessionEnd>
where
    E: GuestEvents,
    T: GuestTerminal,
    I: GuestInput,
    R: Future<Output = microsandbox::MicrosandboxResult<std::process::ExitStatus>>,
{
    let mut runtime_exit = Box::pin(runtime_exit);
    let HostFds {
        terminal: terminal_fd,
        output: output_fd,
    } = fds;
    let terminal = HostTerminal::from_fds(terminal_fd)?;
    // The guest PTY already exists at the SDK's fixed 24x80 by the time this
    // returns, so the host's real geometry is the session loop's first send. It
    // cannot undo what a guest has already rendered; it bounds the gap to one
    // round trip. The send is a held branch in the loop, never awaited here.
    let size = terminal.size()?;
    // The signal stream exists before the first resize is sent, so a `SIGWINCH`
    // arriving at any point after the host geometry is known cannot be missed.
    let window = window_changes()?;
    let mut host = Host::start(
        terminal, output_fd, sink, control, window, prompt, size, timings,
    )?;
    let outcome = session_loop(events, &mut host, &mut runtime_exit, supervision, size).await;

    // One epilogue for every outcome, in the order §6.1's G4 fixes: `termios` first
    // (it cannot block and is the reported restore), then the ledger's abort, then
    // the reader, then the bounded wait for the writer's own host restore, then the
    // runtime wait. A forced shutdown takes this same path: queued output is
    // *aborted* rather than drained, and the in-flight sends were dropped when the
    // loop returned.
    let restored = host.raw.restore();
    let owed = host.output.abort();
    let hint_owed = host.prompt.as_mut().is_some_and(Prompt::abandon);
    host.input.stop();
    if let Some(owed) = owed {
        owed.wait().await;
    }
    if hint_owed {
        write_hint_to_stderr();
    }
    drop(runtime_exit);
    with_restore(outcome, restored)
}

/// The session's host side. One value so the loop, and the epilogue that must
/// release it in a fixed order, name the same thing.
struct Host<T: GuestTerminal, I: GuestInput> {
    terminal: HostTerminal,
    raw: RawTerminal,
    input: InputReader,
    output: OutputWriter,
    window: tokio::signal::unix::Signal,
    /// The guest's control handle: resizes and forwarded signals.
    control: T,
    /// Shared with the pump: a forwarded chunk is held in a `select!` branch of
    /// its own, which must own its sink rather than borrow the session's.
    sink: Arc<I>,
    /// The in-terminal access prompt, when this launch may show one (R1, R2).
    prompt: Option<Prompt>,
}

impl<T: GuestTerminal, I: GuestInput> Host<T, I> {
    #[allow(clippy::too_many_arguments)]
    fn start(
        terminal: HostTerminal,
        output: OwnedFd,
        sink: Arc<I>,
        control: T,
        window: tokio::signal::unix::Signal,
        prompt: Option<access_prompt::Source>,
        size: Size,
        timings: access_prompt::relay::Timings,
    ) -> anyhow::Result<Self> {
        let raw = RawTerminal::enter(&terminal)?;
        let output = OutputWriter::start(output)?;
        let input = InputReader::start(&terminal)?;
        let prompt = prompt.map(|source| source.start(size.into(), timings));
        Ok(Self {
            terminal,
            raw,
            input,
            output,
            window,
            control,
            sink,
            prompt,
        })
    }
}

/// A failed restore must never turn into a silvert raw terminal: it is appended
/// to whatever the session reported.
fn with_restore<T>(primary: anyhow::Result<T>, restored: anyhow::Result<()>) -> anyhow::Result<T> {
    match (primary, restored) {
        (Ok(code), Ok(())) => Ok(code),
        (Ok(_), Err(error)) => Err(error),
        (Err(primary), Ok(())) => Err(primary),
        (Err(primary), Err(error)) => Err(primary.context(format!("{error:#}"))),
    }
}

/// Poll a held send. The branch it backs is gated on the slot being occupied, so
/// an empty slot parks the branch instead of producing an `unreachable!`. This is
/// the module's one structural rule: guest output to the writer, host input to the
/// guest, a resize and a forwarded signal all end in a channel whose peer can stop
/// reading, and none of them may be awaited inside a `select!` arm **body** — a
/// pending body stops the macro polling its other branches, so a lost runtime, a
/// writer failure or the end of the event stream would go unobserved and the
/// launcher would hang with the operator's terminal still raw instead of restoring
/// it and exiting 125 (#400). [`crate::host_signals::signal_send`] builds the
/// signal one, so both sessions send an arrival through the same code.
async fn poll_pending(pending: &mut Option<PendingSend>) -> anyhow::Result<()> {
    match pending {
        Some(sending) => sending.as_mut().await,
        None => std::future::pending().await,
    }
}

/// A local credit-window closure awaiting the SDK's EPIPE/terminal event.
/// Bounded so an SDK contract breach cannot leave the terminal raw forever.
struct PendingStdinClosure {
    error: anyhow::Error,
    deadline: Pin<Box<tokio::time::Sleep>>,
}

impl PendingStdinClosure {
    fn from_error(error: anyhow::Error) -> anyhow::Result<Self> {
        if !crate::direct_input::is_stdin_closed(&error) {
            return Err(error);
        }
        Ok(Self {
            error,
            deadline: Box::pin(tokio::time::sleep(
                crate::run::STREAM_END_RUNTIME_EXIT_GRACE,
            )),
        })
    }
}

async fn closure_expired(pending: &mut Option<PendingStdinClosure>) {
    match pending {
        Some(pending) => pending.deadline.as_mut().await,
        None => std::future::pending().await,
    }
}

/// The session proper. Every exit path returns through here, so the epilogue is
/// unconditional.
async fn session_loop<E, T, I, R>(
    events: &mut E,
    host: &mut Host<T, I>,
    runtime_exit: &mut Pin<Box<R>>,
    supervision: &mut Supervision,
    initial_size: Size,
) -> anyhow::Result<SessionEnd>
where
    E: GuestEvents,
    T: GuestTerminal,
    I: GuestInput,
    R: Future<Output = microsandbox::MicrosandboxResult<std::process::ExitStatus>>,
{
    // One mutable borrow per field, so the `select!` arms below borrow disjoint
    // parts of the session instead of all of it.
    let Host {
        terminal,
        raw: _raw,
        input,
        output,
        window,
        control,
        sink,
        prompt,
    } = host;

    let mut forwarding = true;
    let mut failure = output.take_failure();
    // At most one of each kind is in flight. The peer's own queue is the buffer;
    // holding more here would absorb the backpressure the guest must feel.
    let mut slots = Slots {
        sending_output: None,
        takeover_ack: None,
        sending_input: None,
        resizing: Some(resize_send(
            control.clone(),
            initial_size,
            "setting the guest terminal size",
        )),
        signalling: None,
        granting: None,
        nudging: false,
    };
    let mut pending_stdin_closure: Option<PendingStdinClosure> = None;
    let end = loop {
        // The pump runs before every wait: it is synchronous, so it cannot hide a
        // branch, and it is the only place a prompt frame becomes a held send.
        pump(prompt, terminal, input, output, control, &mut slots)?;
        // The prompt's one deadline, rebuilt per iteration: a fired deadline is
        // consumed by its handler, so this branch is never continuously ready (I5).
        let mut deadline_sleep: Option<Pin<Box<tokio::time::Sleep>>> = prompt
            .as_ref()
            .and_then(Prompt::deadline)
            .map(|at| Box::pin(tokio::time::sleep_until(at)));
        let wants_input = prompt.as_ref().is_some_and(Prompt::wants_host_input);
        tokio::select! {
            biased;
            // Work already accepted first, so a full peer delays the branches
            // below without ever hiding the ones after them.
            sent = poll_pending(&mut slots.sending_output), if slots.sending_output.is_some() => {
                slots.sending_output = None;
                if let Err(symptom) = sent {
                    return Err(writer_error(&mut failure, symptom));
                }
            }
            // The one outstanding `Enter`/`Leave` frame's confirmation. A dropped
            // sender means the writer refused the frame or failed, which §6.1 makes
            // a bug worth ending the session for.
            ack = poll_ack(&mut slots.takeover_ack), if slots.takeover_ack.is_some() => {
                slots.takeover_ack = None;
                match ack {
                    Some(generation) => {
                        if let Some(prompt) = prompt.as_mut() {
                            prompt.written(generation, tokio::time::Instant::now());
                        }
                    }
                    None => return Err(writer_error(
                        &mut failure,
                        anyhow::anyhow!("the guest terminal output writer refused a prompt frame"),
                    )),
                }
            }
            // The prompt's grant: settled, timed out (the task keeps running), or
            // lost. Its result is tagged with the generation it was asked for, so a
            // late result cannot reach a later takeover (B4, I8).
            done = poll_grant(&mut slots.granting), if slots.granting.is_some() => {
                slots.granting = None;
                if let Some(prompt) = prompt.as_mut() {
                    let done = match done {
                        Ok(done) => done,
                        Err(error) => access_prompt::GrantDone {
                            generation: prompt.generation(),
                            outcome: access_prompt::GrantOutcome::Lost(error.to_string()),
                        },
                    };
                    prompt.granted(done, tokio::time::Instant::now());
                }
            }
            sent = poll_pending(&mut slots.sending_input), if slots.sending_input.is_some() => {
                slots.sending_input = None;
                if let Err(error) = sent {
                    pending_stdin_closure = Some(PendingStdinClosure::from_error(error)?);
                    forwarding = false;
                    input.stop();
                    if let Some(prompt) = prompt.as_mut() {
                        prompt.input_ended(tokio::time::Instant::now());
                    }
                }
            }
            sent = poll_pending(&mut slots.resizing), if slots.resizing.is_some() => {
                slots.resizing = None;
                sent?;
                if slots.nudging {
                    // The nudge's 100 ms is over: measure the host *now*, so a resize
                    // during the wait is not lost (§5.8).
                    slots.nudging = false;
                    slots.resizing = Some(resize_send(
                        control.clone(),
                        terminal.size()?,
                        "restoring the guest terminal size",
                    ));
                }
            }
            sent = poll_pending(&mut slots.signalling), if slots.signalling.is_some() => {
                slots.signalling = None;
                sent?;
            }
            // Supervision, ahead of every branch that can stay ready forever.
            step = supervision.next() => match step {
                SupervisionStep::Forward(signal) => {
                    slots.signalling = Some(signal_send(control.clone(), signal));
                }
                // The second interrupt (or an expired grace): no drain, no
                // further forwarding. The loop returns and the epilogue cancels
                // what is in flight, restores the terminal and hands a forced
                // end to the caller.
                SupervisionStep::Force(forced) => break SessionEnd::Forced(forced),
                SupervisionStep::ReaderStopped => return Err(supervision_lost()),
            },
            // The prompt's deadline: above guest events, so a guest that writes
            // continuously cannot starve it.
            _ = poll_sleep(&mut deadline_sleep), if deadline_sleep.is_some() => {
                if let Some(prompt) = prompt.as_mut() {
                    prompt.handle_deadline(tokio::time::Instant::now());
                }
            },
            // One event at a time, and none while a frame is still being queued:
            // that is what makes a stalled consumer stall the guest. With a prompt,
            // the gate also closes at the hold's bound (R14).
            event = events.recv(), if slots.sending_output.is_none()
                && prompt.as_ref().is_none_or(Prompt::may_receive_guest_output) => {
                // Terminal events win even at expiry, but a continuously ready
                // output stream must not extend the closure grace indefinitely.
                if matches!(&event, Some(ExecEvent::Started { .. } | ExecEvent::Stdout(_) | ExecEvent::Stderr(_)))
                    && pending_stdin_closure.as_ref().is_some_and(|pending| {
                        tokio::time::Instant::now() >= pending.deadline.deadline()
                    })
                    && let Some(pending) = pending_stdin_closure.take()
                {
                    return Err(pending.error);
                }
                match event {
                    Some(ExecEvent::Started { .. }) => {}
                    // A PTY merges both guest channels into one stream, so a
                    // `Stderr` frame goes to the same writer rather than being
                    // dropped: the guest's own bytes are never discarded.
                    Some(ExecEvent::Stdout(bytes)) | Some(ExecEvent::Stderr(bytes)) => {
                        match prompt.as_mut() {
                            Some(prompt) => {
                                prompt.guest_output(bytes.to_vec(), tokio::time::Instant::now())
                            }
                            None => {
                                slots.sending_output =
                                    Some(Box::pin(output.frame(bytes.to_vec())?.deliver()));
                            }
                        }
                    }
                    // The guest's own exit, reported as it is, even an unknown
                    // `-1`. Identity comes from the accessor the SDK publishes
                    // before this event, never from a signal we forwarded.
                    Some(ExecEvent::Exited { code }) => {
                        break SessionEnd::Guest {
                            code,
                            signal: GuestSignal::reported(events.termination_signal()),
                        };
                    }
                    Some(ExecEvent::Failed(failure)) => {
                        return Err(anyhow::Error::new(MicrosandboxError::ExecFailed(failure)));
                    }
                    Some(ExecEvent::StdinError(payload)) => {
                        // One rule for guest closure, shared with the streamed
                        // path: `errno_name` decides first, so a payload that
                        // names EPIPE without a number is still a guest close.
                        match classify_stdin_error(&payload) {
                            GuestInputStatus::GuestClosedInput => {
                                forwarding = false;
                                // Drop a write still waiting on SDK credit;
                                // EPIPE confirms any local window-close error.
                                slots.sending_input = None;
                                pending_stdin_closure = None;
                                input.stop();
                                if let Some(prompt) = prompt.as_mut() {
                                    prompt.input_ended(tokio::time::Instant::now());
                                }
                            }
                            GuestInputStatus::Failed(text) => {
                                return Err(anyhow::anyhow!(
                                    "forwarding host input to the guest failed: {text}"
                                ));
                            }
                        }
                    }
                    None => {
                        return Err(anyhow::anyhow!(
                            "the guest terminal session ended without reporting an exit status"
                        ));
                    }
                }
            }
            // A ready guest exit/EPIPE or interrupt outranks the local closure
            // deadline, including on the poll in which the deadline expires.
            _ = closure_expired(&mut pending_stdin_closure), if pending_stdin_closure.is_some() => {
                if let Some(pending) = pending_stdin_closure.take() {
                    return Err(pending.error);
                }
            }
            // Host input: the gate opens while forwarding, and — with a prompt — an
            // occupied input slot never holds back a read the prompt must see.
            chunk = input.recv(), if forwarding && (slots.sending_input.is_none() || wants_input) => {
                match classify_host_read(chunk) {
                    HostInput::Forward(chunk) => {
                        let route = match prompt.as_mut() {
                            Some(prompt) => {
                                prompt.host_input(chunk, tokio::time::Instant::now())
                            }
                            None => access_prompt::relay::InputRoute::Guest(chunk.bytes),
                        };
                        if let access_prompt::relay::InputRoute::Guest(bytes) = route {
                            let sink = Arc::clone(sink);
                            slots.sending_input = Some(Box::pin(async move {
                                sink.write(bytes)
                                    .await
                                    .context("forwarding host input to the guest")
                            }));
                        }
                    }
                    // A host-side EOF (or a vanished tty peer) stops forwarding;
                    // for a terminal that is not the end of the session, because
                    // the guest may still be rendering output.
                    HostInput::StopForwarding => {
                        forwarding = false;
                        if let Some(prompt) = prompt.as_mut() {
                            prompt.input_ended(tokio::time::Instant::now());
                        }
                    }
                    HostInput::Failed(error) => return Err(error),
                }
            }
            // A host resize is accepted the same way the session's first one is:
            // as a held send, never as work awaited in an arm body.
            _ = window.recv(), if slots.resizing.is_none() => {
                let size = terminal.size()?;
                slots.resizing = Some(resize_send(
                    control.clone(),
                    size,
                    "resizing the guest terminal",
                ));
                if let Some(prompt) = prompt.as_mut() {
                    prompt.resized(size.into(), tokio::time::Instant::now());
                }
            }
            error = &mut failure => {
                return Err(match error {
                    Ok(error) => anyhow::Error::new(error).context("writing guest terminal output"),
                    Err(_) => anyhow::anyhow!("the guest terminal output writer was lost"),
                });
            }
            result = runtime_exit.as_mut() => {
                return Err(match result {
                    Ok(status) => anyhow::anyhow!(
                        "the sandbox process ended ({status}) before the terminal command reported its exit"
                    ),
                    Err(error) => anyhow::Error::new(error)
                        .context("the sandbox runtime ended before the terminal command reported its exit"),
                });
            }
            // Last, one event per turn: refusal updates can stay ready for as long
            // as a guest keeps growing counts, so they sit below every branch that
            // must stay observable (B8). A lagged receiver recovers in the handler.
            feed = prompt_event(prompt), if prompt.is_some() => {
                if let Some(prompt) = prompt.as_mut() {
                    prompt.handle_feed(feed, tokio::time::Instant::now());
                }
            }
        }
    };
    // Only a guest exit reaches the drain: a forced end returns here without
    // waiting for output the operator has asked to abandon. The reported guest
    // identity is carried through every return below, so the drain cannot turn a
    // signalled guest into a bare code.
    let SessionEnd::Guest { .. } = end else {
        return Ok(end);
    };
    // The prompt's still-owed frames become the drain's tail, in wire order: the
    // leave (if an enter was handed over) then the held output, so the terminal ends
    // as it would have without the prompt (R27).
    let tail = prompt
        .as_mut()
        .map(|prompt| prompt.finish(tokio::time::Instant::now()))
        .unwrap_or_default();
    // The flush is held in one pinned future and re-polled. `finish` takes the
    // session's last sender on its first poll, so re-creating it after a cancelled
    // poll would report a drain that never happened.
    let mut finishing = Box::pin(output.finish(tail));
    drain_guest_output(end, &mut finishing, &mut failure, supervision, runtime_exit).await
}

/// The held slots a session loop keeps. One value so the pump and the `select!`
/// name the same set.
struct Slots {
    sending_output: Option<PendingSend>,
    /// The one outstanding `Enter`/`Leave` confirmation (I1).
    takeover_ack: Option<tokio::sync::oneshot::Receiver<u64>>,
    sending_input: Option<PendingSend>,
    resizing: Option<PendingSend>,
    signalling: Option<PendingSend>,
    granting: Option<GrantSlot>,
    /// Whether the resize in the slot is a nudge, so its completion re-measures the
    /// host and sends the real size (§5.8).
    nudging: bool,
}

/// Move the head of the prompt's outbound queue into an empty slot. Synchronous: it
/// never awaits, so it cannot hide a `select!` branch.
fn pump<T: GuestTerminal>(
    prompt: &mut Option<Prompt>,
    terminal: &HostTerminal,
    input: &InputReader,
    output: &OutputWriter,
    control: &T,
    slots: &mut Slots,
) -> anyhow::Result<()> {
    let Some(prompt) = prompt.as_mut() else {
        return Ok(());
    };
    if prompt.wants_input_flush() {
        terminal.flush_input()?;
        prompt.input_flushed(input.reads_started(), tokio::time::Instant::now());
    }
    loop {
        let next = prompt.take_outbound_if(|head| match head {
            access_prompt::relay::Outbound::Frame(access_prompt::relay::OutputItem::Takeover {
                step: access_prompt::relay::Step::Enter { .. } | access_prompt::relay::Step::Leave,
                ..
            }) => slots.sending_output.is_none() && slots.takeover_ack.is_none(),
            access_prompt::relay::Outbound::Frame(_) => slots.sending_output.is_none(),
            access_prompt::relay::Outbound::Grant(_) => slots.granting.is_none(),
            access_prompt::relay::Outbound::Nudge => slots.resizing.is_none(),
        });
        let Some(next) = next else {
            break;
        };
        match next {
            access_prompt::relay::Outbound::Frame(access_prompt::relay::OutputItem::Data(
                bytes,
            )) => {
                slots.sending_output = Some(Box::pin(output.frame(bytes)?.deliver()));
            }
            // The hint is its own frame. Its route is marked written only when the
            // writer accepted the bytes, so an abandoned delivery still belongs to
            // stderr (M9/N6).
            access_prompt::relay::Outbound::Frame(access_prompt::relay::OutputItem::Hint) => {
                let hint = prompt.hint_route();
                let send = output.frame(crate::refusal::feed::HintRelay::BYTES.to_vec())?;
                slots.sending_output = Some(Box::pin(async move {
                    let delivered = send.deliver().await;
                    if delivered.is_ok()
                        && let Some(hint) = &hint
                    {
                        let _ = hint.take();
                    }
                    delivered
                }));
            }
            access_prompt::relay::Outbound::Frame(access_prompt::relay::OutputItem::Takeover {
                generation,
                step,
                bytes,
            }) => {
                let (send, written) = output.takeover(generation, step, bytes)?;
                slots.sending_output = Some(Box::pin(send.deliver()));
                if matches!(step, access_prompt::relay::Step::Redraw) {
                    // The result frame's acceptance starts the 1.5 s it is read for
                    // (R20, M1/N2); no other frame touches the timer.
                    prompt.frame_taken(tokio::time::Instant::now());
                }
                // Only a frame that confirms (`Enter`/`Leave`) may occupy the
                // confirmation slot. Assigning a `Redraw`'s `None` here dropped a
                // pending confirmation, and the takeover then waited for an ack that
                // could never arrive.
                hold_confirmation(&mut slots.takeover_ack, written);
            }
            access_prompt::relay::Outbound::Grant(request) => {
                slots.granting = Some(prompt.start_grant(request));
            }
            access_prompt::relay::Outbound::Nudge => {
                slots.resizing = Some(nudge_send(control.clone(), terminal.size()?));
                slots.nudging = true;
            }
        }
    }
    Ok(())
}

/// Take the confirmation slot only for a frame that owes one.
///
/// A `Redraw` carries no confirmation; setting the slot to its `None` would discard
/// the `Enter` or `Leave` the relay is waiting for (finding 3).
fn hold_confirmation(
    slot: &mut Option<tokio::sync::oneshot::Receiver<u64>>,
    written: Option<tokio::sync::oneshot::Receiver<u64>>,
) {
    if written.is_some() {
        *slot = written;
    }
}

/// Poll a held confirmation. The branch is gated on the slot being occupied, so an
/// empty slot parks instead of producing an `unreachable!`.
async fn poll_ack(slot: &mut Option<tokio::sync::oneshot::Receiver<u64>>) -> Option<u64> {
    match slot {
        Some(receiver) => receiver.await.ok(),
        None => std::future::pending().await,
    }
}

type GrantSlot = tokio::task::JoinHandle<access_prompt::GrantDone>;

/// Poll the prompt's grant, or park when none is in flight.
async fn poll_grant(
    slot: &mut Option<GrantSlot>,
) -> Result<access_prompt::GrantDone, anyhow::Error> {
    match slot {
        Some(handle) => handle.await.map_err(anyhow::Error::new),
        None => std::future::pending().await,
    }
}

/// Poll a one-shot deadline sleep, or park when the prompt has none.
async fn poll_sleep(slot: &mut Option<Pin<Box<tokio::time::Sleep>>>) {
    match slot {
        Some(sleep) => sleep.as_mut().await,
        None => std::future::pending().await,
    }
}

/// The prompt's next feed event, or park when this launch has no prompt.
async fn prompt_event(prompt: &mut Option<Prompt>) -> access_prompt::FeedEvent {
    match prompt {
        Some(prompt) => prompt.next_feed_event().await,
        None => std::future::pending().await,
    }
}

/// One held resize send, cloned control included so a peer that stops reading
/// delays the session without borrowing the session's own control handle.
fn resize_send<T: GuestTerminal>(control: T, size: Size, context: &'static str) -> PendingSend {
    Box::pin(async move { control.resize(size.rows, size.cols).await.context(context) })
}

/// The size nudge (#494): one column narrower, then 100 ms, then the loop measures
/// the host and sends the real size (§5.8). Only an alternate-screen guest needs it.
fn nudge_send<T: GuestTerminal>(control: T, size: Size) -> PendingSend {
    Box::pin(async move {
        let narrowed = Size {
            rows: if size.cols > 1 {
                size.rows
            } else {
                size.rows.saturating_sub(1)
            },
            cols: size.cols.saturating_sub(1),
        };
        control
            .resize(narrowed.rows, narrowed.cols)
            .await
            .context("nudging the guest terminal size")?;
        tokio::time::sleep(NUDGE_SETTLE).await;
        Ok(())
    })
}

/// The output drain that follows a definitive guest exit.
///
/// Factored out of [`session_loop`] for one reason: the two branches that cut the
/// drain short — an interrupt with nothing left to forward, and runtime loss —
/// must return the **guest's own** `end` rather than a reconstruction of it, and
/// as inline arms of a `select!` over a live SDK handle no test could reach
/// them. Their inputs here are the three things they actually observe.
async fn drain_guest_output<F, R>(
    end: SessionEnd,
    finishing: &mut Pin<Box<F>>,
    failure: &mut tokio::sync::oneshot::Receiver<std::io::Error>,
    supervision: &mut Supervision,
    runtime_exit: &mut Pin<Box<R>>,
) -> anyhow::Result<SessionEnd>
where
    F: Future<Output = anyhow::Result<()>>,
    R: Future<Output = microsandbox::MicrosandboxResult<std::process::ExitStatus>>,
{
    // A definitive exit is necessary but not sufficient: every byte already
    // accepted from the guest must reach the host descriptor before the caller
    // reports the status. The barrier stays cancellable by runtime loss, so a
    // consumer that never drains fails instead of hanging the launcher. Both of
    // its waits are branches, so this select already had the property the loop
    // above was missing.
    tokio::select! {
        biased;
        finished = &mut *finishing => {
            // A failed write is a *different* fact from a runtime that died: the
            // host refused bytes the guest did produce. It is a session failure
            // here for the same reason it is one in the loop.
            if let Err(symptom) = finished {
                return Err(writer_error(failure, symptom));
            }
        }
        // The guest has already reported its status, so an interrupt here has
        // nothing left to forward: what it may do is stop the drain. A first
        // interrupt and a decided shutdown both therefore return the **known**
        // status — including a signal the guest itself reported before the drain
        // began, which is an observation, not an inference from this interrupt.
        // Truncation is not reported separately for the same reason runtime loss
        // during the drain is not (see the arm below).
        step = supervision.next() => match step {
            SupervisionStep::Forward(_) | SupervisionStep::Force(_) => {
                return Ok(end);
            }
            // Supervision ending is not an instruction about a signal: the
            // launcher can no longer observe the interrupts it promised to honour.
            // The loop treats this as a failure, and so does the drain — silently
            // truncating the drain and reporting success would hide it, which is
            // the one thing a lost reader must never do.
            SupervisionStep::ReaderStopped => return Err(supervision_lost()),
        },
        result = runtime_exit.as_mut() => {
            // The loop breaks only on a definitive guest exit, so the status is
            // **already known**: the guest returned it, and a runtime that dies
            // while the rest of its output is still queued cannot change what
            // the guest returned — it can only truncate what is left. So runtime
            // loss ends the drain and the session reports the guest's status.
            //
            // This arm used to report 125, which turned a status into a failure
            // whenever the runtime observation was already ready as the barrier
            // began — the ordinary `exit-wins` shape, and a real CI failure on
            // Linux where the runtime resolved first (#463). The asymmetry is
            // deliberate: *before* the loop breaks, runtime loss is 125 because
            // the status is unknown (see the loop's arm above); after it, there
            // is nothing left to learn about the status, only output to lose.
            //
            // Both `Ok` and `Err` here are that same fact: a runtime that ended
            // or one that can no longer be observed. Truncation is not reported
            // separately — the terminal was restored and the guest's own status
            // is what the caller sees, which is also all `attach` ever promised.
            let _ = result;
            return Ok(end);
        }
    }
    Ok(end)
}

/// The writer's own error, when the queue closed because the writer failed.
///
/// The queue can only report "stopped accepting output", which is the symptom:
/// the writer records its `io::Error` and *then* drops the receiver, so the
/// record is already in place by the time the refusal is observed. Reading it is
/// the difference between naming a broken host stdout and naming no cause at all.
fn writer_error(
    failure: &mut tokio::sync::oneshot::Receiver<std::io::Error>,
    symptom: anyhow::Error,
) -> anyhow::Error {
    match failure.try_recv() {
        Ok(error) => anyhow::Error::new(error).context("writing guest terminal output"),
        Err(_) => symptom,
    }
}

// ---------------------------------------------------------------------------
// Host terminal and raw mode
// ---------------------------------------------------------------------------

/// The host terminal this session reads from and measures.
struct HostTerminal {
    /// Used for `TIOCGWINSZ` and kept alive for the session's lifetime.
    fd: OwnedFd,
    /// The reader thread's own duplicate, so neither end inherits the other's
    /// lifecycle.
    reader: OwnedFd,
}

impl HostTerminal {
    /// A terminal from the session's own duplicate.
    ///
    /// The descriptor is always a **duplicate**: a session must never set a file
    /// status flag or a terminal attribute on fd 0 itself, because fd 0 may be
    /// shared with a child that is still running.
    fn from_fds(fd: OwnedFd) -> anyhow::Result<Self> {
        // Terminal policy selects a PTY only when stdin is a terminal, and a
        // forced PTY with a pipe or a file is refused before boot. Falling back
        // to `/dev/tty` here would attach a redirected launch to the operator's
        // keyboard instead of failing.
        if !fd.is_terminal() {
            return Err(anyhow::anyhow!(
                "a terminal launch needs terminal stdin, and stdin is redirected"
            ));
        }
        let reader = duplicate(fd.as_raw_fd()).context("duplicating the host terminal reader")?;
        Ok(Self { fd, reader })
    }

    /// Discard the terminal's pending input (`tcflush`, not an attribute change).
    ///
    /// At visibility the prompt discards everything typed before it, so a key read
    /// before the prompt cannot answer it (R17). A queue operation, so it neither
    /// blocks nor changes anything the restore has to undo.
    fn flush_input(&self) -> anyhow::Result<()> {
        loop {
            // SAFETY: `self.fd` is an open terminal for this call; `TCIFLUSH`
            // discards input the terminal has received and not read.
            let rc = unsafe { libc::tcflush(self.fd.as_raw_fd(), libc::TCIFLUSH) };
            if rc == 0 {
                return Ok(());
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error).context("discarding the terminal's pending input");
        }
    }

    /// The host's real geometry, read from `TIOCGWINSZ`.
    ///
    /// A zero dimension is normalized to the SDK's own fallback rather than
    /// forwarded as 0x0. A *failing* ioctl is an error: the session cannot honour
    /// a size it could not measure, and the terminal it must restore is the same
    /// descriptor.
    fn size(&self) -> anyhow::Result<Size> {
        // SAFETY: `winsize` is plain data whose all-zero state is valid.
        let mut size: libc::winsize = unsafe { std::mem::zeroed() };
        loop {
            // SAFETY: `self.fd` is an open terminal for this call, and
            // `TIOCGWINSZ` writes exactly the `winsize` behind the pointer.
            let rc = unsafe { libc::ioctl(self.fd.as_raw_fd(), libc::TIOCGWINSZ, &mut size) };
            if rc == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error).context("reading the host terminal size");
        }
        Ok(Size {
            rows: if size.ws_row == 0 {
                FALLBACK_ROWS
            } else {
                size.ws_row
            },
            cols: if size.ws_col == 0 {
                FALLBACK_COLS
            } else {
                size.ws_col
            },
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Size {
    rows: u16,
    cols: u16,
}

/// The prompt's geometry type, from this module's private one: a conversion rather
/// than an export keeps the session's `Size` private.
impl From<Size> for crate::access_prompt::Size {
    fn from(size: Size) -> Self {
        Self {
            rows: size.rows,
            cols: size.cols,
        }
    }
}

/// A private description handle that no child can inherit (a CLOEXEC duplicate).
fn duplicate(fd: RawFd) -> std::io::Result<OwnedFd> {
    // SAFETY: `fd` belongs to the caller and outlives this call (every caller
    // duplicates a descriptor it already owns); `borrow_raw` creates no second
    // owner, and the returned `OwnedFd` is the sole owner of the duplicate.
    unsafe { BorrowedFd::borrow_raw(fd) }.try_clone_to_owned()
}

/// The host terminal's raw mode, owned for exactly the session's lifetime.
///
/// It saves the **exact** attributes and restores that snapshot, rather than
/// toggling named flags: `cfmakeraw` changes bits across four words, and a
/// restore that only undid the ones it knew about would leave the operator's
/// terminal subtly wrong. `restore` runs explicitly on every exit path and
/// returns its error; `Drop` is the last resort for cancellation and panics.
struct RawTerminal {
    fd: OwnedFd,
    saved: libc::termios,
    active: bool,
}

impl RawTerminal {
    fn enter(terminal: &HostTerminal) -> anyhow::Result<Self> {
        let fd = duplicate(terminal.fd.as_raw_fd())?;
        // SAFETY: `termios` is plain data whose all-zero state is valid, and
        // `tcgetattr` is the call that fills it in.
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: `fd` is an open terminal for this call and `saved` is a live,
        // writable `termios`.
        if unsafe { libc::tcgetattr(fd.as_raw_fd(), &mut saved) } != 0 {
            return Err(std::io::Error::last_os_error()).context("reading the terminal attributes");
        }
        let mut raw = saved;
        // SAFETY: `raw` is a live copy of a valid `termios`; `cfmakeraw` writes
        // only into it.
        unsafe { libc::cfmakeraw(&mut raw) };
        // `TCSANOW`, not `TCSADRAIN`: nothing has been written yet, and waiting
        // for a peer that is not reading would hang with the terminal half
        // changed.
        set_attributes(fd.as_raw_fd(), &raw).context("enabling raw terminal mode")?;
        Ok(Self {
            fd,
            saved,
            active: true,
        })
    }

    /// Restore the saved attributes, retrying `EINTR`. Idempotent, and it only
    /// reports success once the change was actually applied.
    fn restore(&mut self) -> anyhow::Result<()> {
        if !self.active {
            return Ok(());
        }
        set_attributes(self.fd.as_raw_fd(), &self.saved).context("restoring the terminal mode")?;
        self.active = false;
        Ok(())
    }
}

impl Drop for RawTerminal {
    fn drop(&mut self) {
        // No place is left to report an errno here; the explicit `restore` above
        // is what reports, and it runs on every normal and error path.
        let _ = self.restore();
    }
}

fn set_attributes(fd: RawFd, attributes: &libc::termios) -> std::io::Result<()> {
    loop {
        // SAFETY: `fd` is an open terminal for every caller (`RawTerminal` owns
        // its duplicate), and `attributes` is a live `termios` the kernel only
        // reads.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, attributes) } == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(error);
    }
}

// ---------------------------------------------------------------------------
// Host input
// ---------------------------------------------------------------------------

/// One message from the terminal reader thread.
#[derive(Debug)]
enum HostRead {
    Chunk {
        bytes: Vec<u8>,
        /// The reader's read-start counter, taken **before** `read(2)`. A chunk with
        /// an epoch at or below the flush that followed visibility can only hold
        /// bytes that arrived before it (R17, B5).
        epoch: u64,
        /// Sampled just after `read(2)` returned: it can lag the return by scheduling
        /// delay, which the restore limits state.
        read_at: std::time::Instant,
    },
    /// Explicit, so a reader that ends for any other reason cannot impersonate
    /// an orderly end of input.
    Eof,
    Failed(std::io::Error),
}

/// What one message from the reader means for the session.
#[derive(Debug)]
enum HostInput {
    /// Offer these bytes to the session; with a prompt they may be consumed by it.
    Forward(access_prompt::relay::HostChunk),
    /// Stop forwarding: the terminal ended, which is not the end of the session
    /// because the guest may still be rendering output.
    StopForwarding,
    /// A launcher failure, never an orderly end of input.
    Failed(anyhow::Error),
}

fn classify_host_read(message: Option<HostRead>) -> HostInput {
    match message {
        Some(HostRead::Chunk {
            bytes,
            epoch,
            read_at,
        }) => HostInput::Forward(access_prompt::relay::HostChunk {
            bytes,
            epoch,
            read_at: tokio::time::Instant::from_std(read_at),
        }),
        Some(HostRead::Failed(error)) => {
            HostInput::Failed(anyhow::Error::new(error).context("reading host terminal input"))
        }
        Some(HostRead::Eof) | None => HostInput::StopForwarding,
    }
}

/// What one `read(2)` on the terminal means for the reader thread.
#[derive(Debug)]
enum ReadOutcome {
    Bytes(usize),
    EndOfInput,
    Retry,
    Failed(std::io::Error),
}

fn classify_read(result: std::io::Result<usize>) -> ReadOutcome {
    match result {
        Ok(0) => ReadOutcome::EndOfInput,
        Ok(count) => ReadOutcome::Bytes(count),
        Err(error) => match error.raw_os_error() {
            // The tty's peer is gone: an orderly end of input, not a launcher
            // failure.
            Some(libc::EIO) => ReadOutcome::EndOfInput,
            Some(libc::EAGAIN) => ReadOutcome::Retry,
            _ if error.kind() == std::io::ErrorKind::Interrupted => ReadOutcome::Retry,
            _ => ReadOutcome::Failed(error),
        },
    }
}

/// A test-only pause between `read(2)` returning and its stamps being used.
///
/// B5's counterexample is a read that returned a key *before* the prompt flushed
/// the terminal, but whose chunk reaches the loop later: a timestamp sampled at
/// delivery would make it look new. The epoch is taken before the syscall, so the
/// pause here changes only the stamp — and the test proves the epoch alone decides.
trait ReaderPause: Send + 'static {
    fn after_read(&self) {}
}

impl ReaderPause for () {}

#[cfg(test)]
struct ReadPauseHook {
    returned: std::sync::mpsc::Sender<()>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}

#[cfg(test)]
impl ReaderPause for Arc<ReadPauseHook> {
    fn after_read(&self) {
        (**self).after_read();
    }
}

#[cfg(test)]
impl ReaderPause for ReadPauseHook {
    fn after_read(&self) {
        let _ = self.returned.send(());
        if let Ok(release) = self.release.lock() {
            let _ = release.recv();
        }
    }
}

/// A detached reader thread over the host terminal.
///
/// The thread is never joined: it can be parked in `poll(2)` for as long as the
/// terminal stays quiet, and neither `Runtime::drop` nor `process::exit` may
/// wait for that (ADR-0052). [`Self::stop`] writes one byte to a self-pipe so the
/// thread wakes up and closes its duplicate immediately, instead of eating the
/// operator's next keystrokes once the guest is gone.
struct InputReader {
    chunks: tokio::sync::mpsc::Receiver<HostRead>,
    wake: Option<OwnedFd>,
    /// Incremented **before** every `read(2)`, so a read that started before a load
    /// of it always reports a smaller epoch whatever the scheduler does afterwards.
    reads_started: Arc<std::sync::atomic::AtomicU64>,
}

impl InputReader {
    fn start(terminal: &HostTerminal) -> anyhow::Result<Self> {
        Self::spawn(terminal, ())
    }

    /// The B5 hook: a reader whose reads pause after returning. Test builds only,
    /// so the production reader has no hook call at all.
    #[cfg(test)]
    fn start_with_pause(
        terminal: &HostTerminal,
        pause: Arc<ReadPauseHook>,
    ) -> anyhow::Result<Self> {
        Self::spawn(terminal, pause)
    }

    fn spawn<P: ReaderPause>(terminal: &HostTerminal, pause: P) -> anyhow::Result<Self> {
        let reader = duplicate(terminal.reader.as_raw_fd())?;
        let (wake_read, wake_write) = self_pipe()?;
        // One chunk in flight: a guest that stops reading bounds the launcher's
        // input backlog instead of growing it.
        let (sender, chunks) = tokio::sync::mpsc::channel(1);
        let reads_started = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let reader_counter = Arc::clone(&reads_started);
        std::thread::Builder::new()
            .name("agent-vm-pty-input".into())
            .spawn(move || input_loop(reader, wake_read, sender, reader_counter, pause))
            .context("starting the host terminal reader")?;
        Ok(Self {
            chunks,
            wake: Some(wake_write),
            reads_started,
        })
    }

    /// The next input message, or `None` when the reader ended. Cancel-safe:
    /// [`tokio::sync::mpsc::Receiver::recv`] either yields an item or consumes
    /// nothing.
    async fn recv(&mut self) -> Option<HostRead> {
        self.chunks.recv().await
    }

    /// The read-start counter's current value.
    fn reads_started(&self) -> u64 {
        self.reads_started.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn stop(&mut self) {
        if let Some(wake) = self.wake.take() {
            // A byte into an empty pipe cannot block, and a failure here means
            // the thread is already gone.
            let byte = [1u8];
            // SAFETY: `wake` is the write end this value owns, and `byte` is a
            // live one-byte buffer.
            let _ = unsafe { libc::write(wake.as_raw_fd(), byte.as_ptr().cast(), 1) };
        }
    }
}

fn input_loop<P: ReaderPause>(
    terminal: OwnedFd,
    wake: OwnedFd,
    sender: tokio::sync::mpsc::Sender<HostRead>,
    reads_started: Arc<std::sync::atomic::AtomicU64>,
    pause: P,
) {
    loop {
        let mut polled = [
            libc::pollfd {
                fd: terminal.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: wake.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: `polled` is a live two-element array of `pollfd`, each naming
        // a descriptor this thread owns (`terminal`, `wake`).
        let ready = unsafe { libc::poll(polled.as_mut_ptr(), 2, -1) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            let _ = sender.blocking_send(HostRead::Failed(error));
            return;
        }
        if polled[1].revents != 0 {
            return; // the session ended
        }
        if polled[0].revents == 0 {
            continue;
        }
        let mut buffer = vec![0u8; HOST_READ_BYTES];
        // The epoch is fixed *before* the syscall (B5): a read that starts before a
        // flush always reports an epoch at or below the flush's count.
        let epoch = reads_started.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        // SAFETY: `terminal` is an open descriptor this thread owns, and
        // `buffer` is a live, writable slice of `buffer.len()` bytes that `read`
        // only writes into.
        let count = unsafe {
            libc::read(
                terminal.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
            )
        };
        // B5's hook: the read has returned; only its stamp is delayed.
        pause.after_read();
        let read_at = std::time::Instant::now();
        let result = if count < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(count as usize)
        };
        match classify_read(result) {
            ReadOutcome::Bytes(count) => {
                buffer.truncate(count);
                if sender
                    .blocking_send(HostRead::Chunk {
                        bytes: buffer,
                        epoch,
                        read_at,
                    })
                    .is_err()
                {
                    return;
                }
            }
            ReadOutcome::EndOfInput => {
                let _ = sender.blocking_send(HostRead::Eof);
                return;
            }
            ReadOutcome::Retry => continue,
            ReadOutcome::Failed(error) => {
                let _ = sender.blocking_send(HostRead::Failed(error));
                return;
            }
        }
    }
}

/// `SIGWINCH` as a stream. Coalescing is unnecessary: each message re-reads the
/// *current* geometry, so a batch of signals becomes one resize frame followed
/// by redundant identical ones.
fn window_changes() -> anyhow::Result<tokio::signal::unix::Signal> {
    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
        .context("watching for terminal resizes")
}

/// A CLOEXEC pipe; no child may inherit either end.
///
/// `std::io::pipe` rather than `pipe(2)` plus `F_SETFD`: the two-step version
/// leaves a window in which another thread's `fork`/`exec` inherits both ends.
fn self_pipe() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let (read, write) = std::io::pipe()?;
    Ok((read.into(), write.into()))
}

// ---------------------------------------------------------------------------
// Guest output
// ---------------------------------------------------------------------------

enum OutputFrame {
    Data(Vec<u8>),
    /// One prompt frame, tagged with its generation. The writer's ledger decides
    /// whether it may still be written (§6.1); `written` confirms an `Enter` or a
    /// `Leave` once every byte reached the descriptor.
    Takeover {
        generation: u64,
        step: access_prompt::relay::Step,
        bytes: Vec<u8>,
        written: Option<tokio::sync::oneshot::Sender<u64>>,
    },
    /// The flush barrier: everything queued before it has been written.
    Finish(tokio::sync::oneshot::Sender<()>),
}

/// A std-thread writer owning a CLOEXEC duplicate of stdout.
///
/// Deliberately **not** `tokio::io::stdout()`: dropping a Tokio write future
/// cannot cancel a write already dispatched to the blocking pool, and
/// `Runtime::drop` then waits for it — so a session that fails while a consumer
/// has stopped reading would hang in runtime destruction instead of reporting
/// 125. A standalone thread keeps the blocking syscall out of Tokio entirely,
/// and [`Self::abort`] never waits for it.
struct OutputWriter {
    frames: Option<tokio::sync::mpsc::Sender<OutputFrame>>,
    /// Resolves with the writer's first I/O error, so an unwritable stdout ends
    /// the session instead of being swallowed.
    failure: Option<tokio::sync::oneshot::Receiver<std::io::Error>>,
    /// Set by [`Self::abort`]: the writer must stop instead of draining what is
    /// still queued.
    cancelled: Arc<AtomicBool>,
    /// The writer's own record of what reached the terminal (§6.1). Shared with the
    /// epilogue, which asks it whether the host restore is owed.
    ledger: Arc<TerminalLedger>,
}

impl OutputWriter {
    fn start(output: OwnedFd) -> anyhow::Result<Self> {
        let (frames, queue) = tokio::sync::mpsc::channel(OUTPUT_QUEUE_FRAMES);
        let (failures, failure) = tokio::sync::oneshot::channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        let ledger = TerminalLedger::new();
        let writer_cancelled = Arc::clone(&cancelled);
        let writer_ledger = Arc::clone(&ledger);
        std::thread::Builder::new()
            .name("agent-vm-pty-output".into())
            .spawn(move || writer_loop(output, queue, failures, writer_cancelled, writer_ledger))
            .context("starting the guest terminal output writer")?;
        Ok(Self {
            frames: Some(frames),
            failure: Some(failure),
            cancelled,
            ledger,
        })
    }

    /// Take the failure receipt so a receive loop can poll it while it also
    /// enqueues output (one `&mut` to the writer would conflict).
    fn take_failure(&mut self) -> tokio::sync::oneshot::Receiver<std::io::Error> {
        self.failure.take().unwrap_or_else(|| {
            let (_sender, receiver) = tokio::sync::oneshot::channel();
            receiver
        })
    }

    /// The delivery for one guest frame, owning a sender clone.
    ///
    /// Owning it is what lets the delivery be a **held** `select!` branch: a
    /// future that borrows the session's writer could not outlive an arm.
    fn frame(&self, bytes: Vec<u8>) -> anyhow::Result<OutputFrameSend> {
        let Some(frames) = self.frames.clone() else {
            return Err(anyhow::anyhow!(
                "the guest terminal output writer was aborted"
            ));
        };
        Ok(OutputFrameSend {
            frames,
            bytes,
            offset: 0,
            kind: SendKind::Data,
        })
    }

    /// The delivery for one prompt frame. `Enter` and `Leave` return the
    /// confirmation the session waits for; a `Redraw` has none.
    fn takeover(
        &self,
        generation: u64,
        step: access_prompt::relay::Step,
        bytes: Vec<u8>,
    ) -> anyhow::Result<(OutputFrameSend, Option<tokio::sync::oneshot::Receiver<u64>>)> {
        let Some(frames) = self.frames.clone() else {
            return Err(anyhow::anyhow!(
                "the guest terminal output writer was aborted"
            ));
        };
        let confirms = matches!(
            step,
            access_prompt::relay::Step::Enter { .. } | access_prompt::relay::Step::Leave
        );
        let (written, ack) = if confirms {
            let (sender, receiver) = tokio::sync::oneshot::channel();
            (Some(sender), Some(receiver))
        } else {
            (None, None)
        };
        Ok((
            OutputFrameSend {
                frames,
                bytes,
                offset: 0,
                kind: SendKind::Takeover {
                    generation,
                    step,
                    written,
                },
            },
            ack,
        ))
    }

    /// Queue the drain's tail, then wait until every queued byte has reached the
    /// host descriptor.
    async fn finish(&mut self, tail: Vec<access_prompt::relay::OutputItem>) -> anyhow::Result<()> {
        let Some(frames) = self.frames.take() else {
            return Ok(());
        };
        for item in tail {
            let frame = match item {
                access_prompt::relay::OutputItem::Data(bytes) => OutputFrame::Data(bytes),
                access_prompt::relay::OutputItem::Hint => {
                    OutputFrame::Data(crate::refusal::feed::HintRelay::BYTES.to_vec())
                }
                access_prompt::relay::OutputItem::Takeover {
                    generation,
                    step,
                    bytes,
                } => OutputFrame::Takeover {
                    generation,
                    step,
                    bytes,
                    written: None,
                },
            };
            if frames.send(frame).await.is_err() {
                return Err(anyhow::anyhow!(
                    "the guest terminal output writer stopped before its final output was written"
                ));
            }
        }
        let (ack, acknowledged) = tokio::sync::oneshot::channel();
        if frames.send(OutputFrame::Finish(ack)).await.is_err() {
            return Err(anyhow::anyhow!(
                "the guest terminal output writer stopped before its final output was written"
            ));
        }
        acknowledged.await.map_err(|_| {
            anyhow::anyhow!(
                "the guest terminal output writer stopped before its final output was written"
            )
        })
    }

    /// Stop the writer without waiting for a write already in progress.
    ///
    /// Queued frames are **discarded**, not drained: a dropped sender still
    /// leaves the receiver with everything it buffered, so up to the full
    /// pending bound of guest output — escape sequences included — would
    /// otherwise reach the host descriptor *after* the terminal was restored and
    /// the failure printed. If a prompt may be on screen, the returned wait is the
    /// bounded one the epilogue takes for the writer's own host restore (§6.1).
    fn abort(&mut self) -> Option<RestoreWait> {
        self.cancelled.store(true, Ordering::Relaxed);
        self.frames = None;
        self.ledger.abort()
    }
}

/// Which frame a delivery carries.
enum SendKind {
    Data,
    Takeover {
        generation: u64,
        step: access_prompt::relay::Step,
        written: Option<tokio::sync::oneshot::Sender<u64>>,
    },
}

/// One output frame, split into ordered chunks and queued with backpressure.
struct OutputFrameSend {
    frames: tokio::sync::mpsc::Sender<OutputFrame>,
    bytes: Vec<u8>,
    offset: usize,
    kind: SendKind,
}

impl OutputFrameSend {
    /// Queue the frame.
    ///
    /// Waiting for capacity — never failing on a full queue — is the contract: a
    /// slow consumer applies backpressure to the guest, exactly as a native
    /// terminal would. Only a writer that has stopped accepting output (failed,
    /// or aborted) is an error.
    async fn deliver(mut self) -> anyhow::Result<()> {
        if let SendKind::Takeover {
            generation,
            step,
            written,
        } = self.kind
        {
            // One prompt frame is one queue entry (§5.4): it is small by
            // construction, so it is never split.
            if self
                .frames
                .send(OutputFrame::Takeover {
                    generation,
                    step,
                    bytes: std::mem::take(&mut self.bytes),
                    written,
                })
                .await
                .is_err()
            {
                return Err(anyhow::anyhow!(
                    "the guest terminal output writer stopped accepting output"
                ));
            }
            return Ok(());
        }
        while self.offset < self.bytes.len() {
            let end = (self.offset + OUTPUT_CHUNK_BYTES).min(self.bytes.len());
            let chunk = self.bytes[self.offset..end].to_vec();
            if self.frames.send(OutputFrame::Data(chunk)).await.is_err() {
                return Err(anyhow::anyhow!(
                    "the guest terminal output writer stopped accepting output"
                ));
            }
            self.offset = end;
        }
        Ok(())
    }
}

fn writer_loop(
    stdout: OwnedFd,
    mut frames: tokio::sync::mpsc::Receiver<OutputFrame>,
    failures: tokio::sync::oneshot::Sender<std::io::Error>,
    cancelled: Arc<AtomicBool>,
    ledger: Arc<TerminalLedger>,
) {
    loop {
        if cancelled.load(Ordering::Relaxed) {
            break;
        }
        let Some(frame) = frames.blocking_recv() else {
            break;
        };
        match frame {
            OutputFrame::Data(bytes) => {
                if ledger.admit_data() == Admit::Discard {
                    continue;
                }
                match write_all(stdout.as_raw_fd(), &bytes, &cancelled) {
                    Ok(true) => {}
                    // Cut short by the abort flag: nothing failed, the frame was
                    // abandoned, and the loop's own check ends the thread.
                    Ok(false) => break,
                    Err(error) => {
                        let _ = failures.send(error);
                        ledger.restored();
                        return;
                    }
                }
            }
            OutputFrame::Takeover {
                generation,
                step,
                bytes,
                written,
            } => {
                if ledger.admit(generation, step) == Admit::Discard {
                    // Dropping the sender tells the session the writer refused a
                    // frame, which §6.1 makes a bug worth ending the session for.
                    tracing::debug!(
                        target: "agent_vm::access_prompt",
                        generation,
                        step = ?step,
                        "the writer discarded a prompt frame it no longer owns"
                    );
                    continue;
                }
                match write_all(stdout.as_raw_fd(), &bytes, &cancelled) {
                    Ok(true) => {
                        ledger.wrote_completely(generation, step);
                        if let Some(written) = written {
                            let _ = written.send(generation);
                        }
                    }
                    Ok(false) => break,
                    Err(error) => {
                        let _ = failures.send(error);
                        ledger.restored();
                        return;
                    }
                }
            }
            OutputFrame::Finish(ack) => {
                // By construction the last frame. A late prompt frame cannot be
                // queued behind it, so `owed` here is impossible — defended anyway.
                if ledger.owed().is_some() {
                    write_host_restore(stdout.as_raw_fd(), &ledger);
                }
                let _ = ack.send(());
                return;
            }
        }
    }
    // Leaving without a barrier: the abort, every sender dropped, or a panic
    // unwinding the loop. If a prompt may be on screen, the writer itself gives the
    // terminal back — it is the only thread that knows what reached the descriptor.
    if ledger.owed().is_some() {
        write_host_restore(stdout.as_raw_fd(), &ledger);
    }
    ledger.restored();
}

/// The host restore (§5.7): written only by this thread, only while a prompt may be
/// on screen.
///
/// It contains no erase, so a second copy keeps the main screen, and it is correct
/// from every prefix of an enter or a leave. Each `write(2)` is preceded by its own
/// `Abandoned` check, so after the epilogue's 250 ms wait at most one syscall it had
/// already committed to can still start (G3, R28).
fn write_host_restore(fd: RawFd, ledger: &TerminalLedger) {
    let bytes = crate::access_prompt::screen::host_restore();
    let mut rest = &bytes[..];
    while !rest.is_empty() {
        if !ledger.may_write() {
            break;
        }
        // The B2 hook sits exactly where the guarantee is made: after the check,
        // before the syscall. Production has no such call.
        ledger.pause_before_write();
        // SAFETY: `fd` is the writer thread's own duplicate of stdout and `rest` is
        // a live slice of `rest.len()` bytes that `write` only reads.
        let written = unsafe { libc::write(fd, rest.as_ptr().cast(), rest.len()) };
        if written < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if written == 0 {
            break;
        }
        rest = &rest[written as usize..];
    }
    ledger.restored();
}

/// Write every byte, or stop when the abort flag is set between syscalls.
///
/// `Ok(true)` means every byte reached the descriptor; `Ok(false)` means the abort
/// cut the frame short — the caller leaves the ledger owed as it was, because the
/// host restore is correct from every prefix.
fn write_all(fd: RawFd, mut bytes: &[u8], cancelled: &AtomicBool) -> std::io::Result<bool> {
    while !bytes.is_empty() {
        // A frame larger than the consumer's capacity blocks here, and `write(2)`
        // itself cannot be cancelled, so `abort` reaches a parked writer between
        // syscalls instead.
        if cancelled.load(Ordering::Relaxed) {
            return Ok(false);
        }
        // SAFETY: `fd` is the writer thread's own duplicate of stdout and
        // `bytes` is a live slice of `bytes.len()` bytes that `write` only reads.
        let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if written < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if written == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::WriteZero));
        }
        bytes = &bytes[written as usize..];
    }
    Ok(true)
}

#[cfg(test)]
mod loop_tests;
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd as _;
    use std::time::Duration;

    /// A real terminal pair, so raw mode and sizing are exercised against a
    /// kernel rather than a description of one.
    struct TestTerminal {
        master: OwnedFd,
        slave: OwnedFd,
    }

    impl TestTerminal {
        fn open(rows: u16, cols: u16) -> Self {
            let mut master: libc::c_int = -1;
            let mut slave: libc::c_int = -1;
            // SAFETY: `openpty` writes two descriptors into the live locals and
            // takes no other pointers; both are taken into `OwnedFd` immediately.
            let rc = unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            assert_eq!(rc, 0, "openpty: {}", std::io::Error::last_os_error());
            // SAFETY: `openpty` succeeded, so each of these is an open descriptor
            // that nothing else owns; `OwnedFd` is now its single owner.
            let master = unsafe { OwnedFd::from_raw_fd(master) };
            // SAFETY: as above for the slave side.
            let slave = unsafe { OwnedFd::from_raw_fd(slave) };
            let size = libc::winsize {
                ws_row: rows,
                ws_col: cols,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            // SAFETY: `slave` is an open terminal and `TIOCSWINSZ` only reads the
            // `winsize` behind the pointer.
            assert_ne!(
                unsafe { libc::ioctl(slave.as_raw_fd(), libc::TIOCSWINSZ, &size) },
                -1
            );
            Self { master, slave }
        }

        fn attributes(&self) -> libc::termios {
            // SAFETY: `termios` is plain data whose all-zero state is valid, and
            // `tcgetattr` fills it in.
            let mut attributes: libc::termios = unsafe { std::mem::zeroed() };
            // SAFETY: `self.slave` is an open terminal and `attributes` is a live,
            // writable `termios`.
            assert_eq!(
                unsafe { libc::tcgetattr(self.slave.as_raw_fd(), &mut attributes) },
                0
            );
            attributes
        }
    }

    #[tokio::test(start_paused = true)]
    async fn stdin_credit_closure_waits_boundedly_but_transport_errors_do_not() {
        let closed =
            anyhow::Error::new(MicrosandboxError::Runtime("execution stdin closed".into()))
                .context("forwarding host input to the guest");
        let mut pending = Some(PendingStdinClosure::from_error(closed).unwrap());
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                closure_expired(&mut pending),
            )
            .await
            .is_err()
        );
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        closure_expired(&mut pending).await;
        assert!(pending.is_some(), "expiry retains the original diagnostic");
        for error in [
            anyhow::anyhow!("execution stdin closed"),
            anyhow::Error::new(MicrosandboxError::Runtime("transport EIO".into())),
            anyhow::Error::new(std::io::Error::from_raw_os_error(libc::EIO)),
        ] {
            assert!(PendingStdinClosure::from_error(error).is_err());
        }
    }

    fn host(terminal: &TestTerminal) -> HostTerminal {
        HostTerminal {
            fd: duplicate(terminal.slave.as_raw_fd()).unwrap(),
            reader: duplicate(terminal.slave.as_raw_fd()).unwrap(),
        }
    }

    /// Every attribute word, so a restore that misses one field is visible.
    ///
    /// The single exclusion is macOS `PENDIN` in `c_lflag`: the kernel sets it as
    /// "retype pending" bookkeeping whenever input is unread, so it reflects the
    /// terminal's queue rather than anything this session set.
    #[derive(Debug, PartialEq, Eq)]
    struct Mode {
        iflag: libc::tcflag_t,
        oflag: libc::tcflag_t,
        cflag: libc::tcflag_t,
        lflag: libc::tcflag_t,
        cc: [libc::cc_t; libc::NCCS],
        ispeed: libc::speed_t,
        ospeed: libc::speed_t,
    }

    fn mode_of(attributes: &libc::termios) -> Mode {
        #[cfg(target_os = "macos")]
        let lflag = attributes.c_lflag & !libc::PENDIN;
        #[cfg(not(target_os = "macos"))]
        let lflag = attributes.c_lflag;
        Mode {
            iflag: attributes.c_iflag,
            oflag: attributes.c_oflag,
            cflag: attributes.c_cflag,
            lflag,
            cc: attributes.c_cc,
            ispeed: attributes.c_ispeed,
            ospeed: attributes.c_ospeed,
        }
    }

    #[test]
    fn raw_mode_clears_the_line_discipline_and_restores_exactly() {
        let terminal = TestTerminal::open(24, 80);
        let before = mode_of(&terminal.attributes());
        let host = host(&terminal);
        {
            let mut raw = RawTerminal::enter(&host).expect("enter raw mode");
            let entered = mode_of(&terminal.attributes());
            assert_eq!(
                entered.lflag & libc::ICANON,
                0,
                "canonical input must be off"
            );
            assert_eq!(entered.lflag & libc::ECHO, 0, "echo must be off");
            assert_eq!(
                entered.lflag & libc::ISIG,
                0,
                "ISIG must be off so Ctrl-C is a byte"
            );
            raw.restore().expect("restore the terminal");
            assert_eq!(mode_of(&terminal.attributes()), before);
        }
        assert_eq!(mode_of(&terminal.attributes()), before);
    }

    #[test]
    fn a_dropped_guard_still_restores_the_terminal() {
        // The cancellation path: the future holding the guard is dropped before
        // its own epilogue can run.
        let terminal = TestTerminal::open(24, 80);
        let before = mode_of(&terminal.attributes());
        let host = host(&terminal);
        {
            let _raw = RawTerminal::enter(&host).expect("enter raw mode");
            assert_eq!(mode_of(&terminal.attributes()).lflag & libc::ICANON, 0);
        }
        assert_eq!(mode_of(&terminal.attributes()), before);
    }

    #[test]
    fn a_failed_restore_is_reported_and_appended_to_a_primary() {
        // A descriptor that cannot take attributes is the one restore failure a
        // test can force deterministically: `tcsetattr` on a pipe is `ENOTTY`.
        let terminal = TestTerminal::open(24, 80);
        let before = mode_of(&terminal.attributes());
        let host = host(&terminal);
        let mut raw = RawTerminal::enter(&host).expect("enter raw mode");
        let (not_a_terminal, keep_open) = std::io::pipe().expect("a pipe");
        let not_a_terminal = duplicate(not_a_terminal.as_raw_fd()).expect("duplicate the pipe");
        let real = std::mem::replace(&mut raw.fd, not_a_terminal);
        assert!(
            raw.restore().is_err(),
            "a restore that cannot be applied is not success"
        );
        assert!(
            raw.restore().is_err(),
            "an unapplied restore must keep reporting, not claim success once"
        );
        // The guard is still the owner of the terminal and still restores it.
        raw.fd = real;
        raw.restore().expect("restore after a failed attempt");
        assert_eq!(mode_of(&terminal.attributes()), before);
        drop(keep_open);

        let success = with_restore(Ok(7), Err(anyhow::anyhow!("restore failed")));
        let text = format!("{:#}", success.unwrap_err());
        assert!(text.contains("restore failed"), "{text}");

        let primary = with_restore::<i32>(
            Err(anyhow::anyhow!("session failed")),
            Err(anyhow::anyhow!("restore failed")),
        );
        let text = format!("{:#}", primary.unwrap_err());
        assert!(text.contains("session failed"), "{text}");
        assert!(text.contains("restore failed"), "{text}");

        let clean = with_restore(Ok(7), Ok(()));
        assert_eq!(clean.unwrap(), 7);
    }

    #[test]
    fn the_terminal_size_comes_from_the_terminal() {
        let terminal = TestTerminal::open(43, 119);
        assert_eq!(
            host(&terminal).size().expect("a measured size"),
            Size {
                rows: 43,
                cols: 119
            }
        );
        // Zero dimensions are normalized, never forwarded as 0x0.
        let zero = TestTerminal::open(0, 0);
        assert_eq!(
            host(&zero).size().expect("a normalized size"),
            Size {
                rows: FALLBACK_ROWS,
                cols: FALLBACK_COLS
            }
        );
    }

    #[tokio::test]
    async fn a_read_that_returned_before_the_flush_cannot_answer_even_if_stamped_late() {
        // B5: the read returned the key *before* the prompt's input flush, and its
        // stamp is taken after. The epoch is taken before `read(2)`, so the chunk
        // still cannot answer — and the late timestamp alone would have said it
        // could.
        let terminal = TestTerminal::open(24, 80);
        let host = host(&terminal);
        let (returned_tx, returned_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let hook = Arc::new(ReadPauseHook {
            returned: returned_tx,
            release: std::sync::Mutex::new(release_rx),
        });
        // Raw mode first: the session makes the terminal raw before it reads, and a
        // canonical terminal would hold a lone key until a newline arrived.
        let _raw = RawTerminal::enter(&host).expect("enter raw mode");
        let mut reader =
            InputReader::start_with_pause(&host, Arc::clone(&hook)).expect("start the reader");
        // The reader is parked in `read(2)`; one key makes it return and pause.
        let typed = *b"s";
        // SAFETY: `master` is the open peer of the test terminal.
        assert_eq!(
            unsafe {
                libc::write(
                    terminal.master.as_raw_fd(),
                    typed.as_ptr().cast(),
                    typed.len(),
                )
            },
            1
        );
        returned_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the read returned and paused before its stamp");
        // The session flushes here and snapshots the counter while the read has
        // already returned: this is exactly B5's ordering.
        let flush_epoch = reader.reads_started();
        let flush_at = std::time::Instant::now();
        release_tx.send(()).expect("release the reader");
        let chunk = tokio::time::timeout(Duration::from_secs(5), reader.recv())
            .await
            .expect("the chunk arrives")
            .expect("a message");
        match chunk {
            HostRead::Chunk {
                bytes,
                epoch,
                read_at,
            } => {
                assert_eq!(bytes, b"s");
                assert!(
                    epoch <= flush_epoch,
                    "a read that started before the flush must report epoch {epoch} <= {flush_epoch}"
                );
                assert!(
                    read_at > flush_at,
                    "the stamp is taken after the flush: it is not what decides"
                );
            }
            other => panic!("expected the paused chunk, got {other:?}"),
        }
        reader.stop();
    }

    #[tokio::test]
    async fn the_input_reader_forwards_bytes_and_a_wake_stops_it() {
        let terminal = TestTerminal::open(24, 80);
        let host = host(&terminal);
        let mut reader = InputReader::start(&host).expect("start the reader");
        // Raw mode belongs to the session, not the reader: this slave is still
        // canonical, so a full line is what arrives first.
        let typed = b"A\x1dB\n";
        // SAFETY: `master` is the open peer of the test terminal and `typed` is a
        // live slice of `typed.len()` bytes that `write` only reads.
        assert_eq!(
            unsafe {
                libc::write(
                    terminal.master.as_raw_fd(),
                    typed.as_ptr().cast(),
                    typed.len(),
                )
            },
            typed.len() as isize
        );
        match reader.recv().await {
            Some(HostRead::Chunk { bytes, epoch, .. }) => {
                assert_eq!(bytes, typed);
                assert_eq!(epoch, 1, "the epoch is taken before the read");
            }
            other => panic!("expected the typed bytes, got {}", other.is_some()),
        }
        reader.stop();
        assert!(
            reader.recv().await.is_none(),
            "a woken reader must not keep reading the terminal"
        );
    }

    #[tokio::test]
    async fn a_closed_tty_peer_ends_input_without_failing_the_session() {
        let terminal = TestTerminal::open(24, 80);
        let host = host(&terminal);
        let mut reader = InputReader::start(&host).expect("start the reader");
        drop(terminal.master);
        let ended = tokio::time::timeout(std::time::Duration::from_secs(5), reader.recv())
            .await
            .expect("a vanished tty peer must not hang the reader");
        // Exactly an end of input: accepting `Failed` here would let a reader
        // that reports a peer's disappearance as a launcher failure pass a test
        // named for the mapping it does not have.
        assert!(
            matches!(ended, Some(HostRead::Eof)),
            "a vanished tty peer is an orderly end of input, got {:?}",
            ended.map(|read| format!("{read:?}"))
        );
    }

    #[test]
    fn a_read_outcome_is_classified_by_errno_not_by_kind_alone() {
        // The EIO mapping is what a real closed peer produces on Linux, and it is
        // the one case a test on macOS cannot drive: the closed-peer test above
        // sees `Ok(0)` here. So the rule itself is asserted directly.
        assert!(matches!(classify_read(Ok(0)), ReadOutcome::EndOfInput));
        assert!(matches!(
            classify_read(Err(std::io::Error::from_raw_os_error(libc::EIO))),
            ReadOutcome::EndOfInput
        ));
        assert!(matches!(
            classify_read(Err(std::io::Error::from_raw_os_error(libc::EAGAIN))),
            ReadOutcome::Retry
        ));
        assert!(matches!(
            classify_read(Err(std::io::Error::from(std::io::ErrorKind::Interrupted))),
            ReadOutcome::Retry
        ));
        // Anything else is a failure, never a silent end of input.
        assert!(matches!(
            classify_read(Err(std::io::Error::from_raw_os_error(libc::EBADF))),
            ReadOutcome::Failed(_)
        ));
        match classify_read(Ok(17)) {
            ReadOutcome::Bytes(count) => assert_eq!(count, 17),
            other => panic!("a read that returned bytes is not {other:?}"),
        }
    }

    #[test]
    fn a_reader_failure_is_a_session_failure_and_an_end_is_not() {
        match classify_host_read(Some(HostRead::Chunk {
            bytes: b"typed".to_vec(),
            epoch: 1,
            read_at: std::time::Instant::now(),
        })) {
            HostInput::Forward(chunk) => assert_eq!(chunk.bytes, b"typed"),
            other => panic!("a chunk must be forwarded, got {other:?}"),
        }
        for end in [Some(HostRead::Eof), None] {
            assert!(matches!(classify_host_read(end), HostInput::StopForwarding));
        }
        let failed = classify_host_read(Some(HostRead::Failed(std::io::Error::from_raw_os_error(
            libc::EBADF,
        ))));
        match failed {
            HostInput::Failed(error) => {
                let text = format!("{error:#}");
                assert!(text.contains("reading host terminal input"), "{text}");
                assert!(text.to_lowercase().contains("descriptor"), "{text}");
            }
            other => panic!("a reader failure must end the session, got {other:?}"),
        }
    }

    #[test]
    fn output_reaches_the_descriptor_in_order_and_the_barrier_proves_it() {
        // The writer owns fd 1 in production, so this drives the same loop over
        // a pipe. The production `start()` is covered by the relay harness in
        // `main.rs`, which needs a real child process to redirect output.
        let (read_end, write_end) = std::io::pipe().expect("a pipe");
        let (frames, queue) = tokio::sync::mpsc::channel(OUTPUT_QUEUE_FRAMES);
        let (failures, _failure) = tokio::sync::oneshot::channel();
        let writer_fd = duplicate(write_end.as_raw_fd()).unwrap();
        drop(write_end);
        let cancelled = Arc::new(AtomicBool::new(false));
        let thread = std::thread::spawn({
            let cancelled = Arc::clone(&cancelled);
            move || writer_loop(writer_fd, queue, failures, cancelled, TerminalLedger::new())
        });
        let (ack, acknowledged) = tokio::sync::oneshot::channel();
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            frames
                .send(OutputFrame::Data(b"first".to_vec()))
                .await
                .unwrap();
            frames
                .send(OutputFrame::Data(b"second".to_vec()))
                .await
                .unwrap();
            frames.send(OutputFrame::Finish(ack)).await.unwrap();
            acknowledged.await.unwrap();
        });
        thread.join().expect("the writer exits after the barrier");
        use std::io::Read as _;
        let mut captured = Vec::new();
        std::io::BufReader::new(read_end)
            .read_to_end(&mut captured)
            .expect("read the capture");
        assert_eq!(captured, b"firstsecond");
    }

    #[tokio::test]
    async fn a_guest_frame_is_split_into_ordered_chunks_within_the_bound() {
        // The delivery, not a description of it: a `deliver` that never split a
        // frame would put one oversized chunk in the queue and pass a test that
        // only counted bytes.
        let (frames, mut queue) = tokio::sync::mpsc::channel(OUTPUT_QUEUE_FRAMES);
        let payload: Vec<u8> = (0..OUTPUT_CHUNK_BYTES * 2 + 1)
            .map(|offset| (offset % 251) as u8)
            .collect();
        OutputFrameSend {
            frames,
            bytes: payload.clone(),
            offset: 0,
            kind: SendKind::Data,
        }
        .deliver()
        .await
        .expect("a queue with capacity accepts the whole frame");

        let mut received = Vec::new();
        let mut queued = 0usize;
        while let Ok(frame) = queue.try_recv() {
            let OutputFrame::Data(chunk) = frame else {
                panic!("the delivery queues data, never the flush barrier");
            };
            assert!(!chunk.is_empty(), "an empty chunk carries no payload");
            assert!(
                chunk.len() <= OUTPUT_CHUNK_BYTES,
                "a chunk of {} bytes exceeds the {} byte bound",
                chunk.len(),
                OUTPUT_CHUNK_BYTES
            );
            received.extend(chunk);
            queued += 1;
        }
        assert_eq!(queued, 3, "one chunk per chunk boundary");
        assert_eq!(received, payload);

        // And the pending bound itself is bytes, not a frame count.
        assert_eq!(
            OUTPUT_CHUNK_BYTES * OUTPUT_QUEUE_FRAMES,
            MAX_PENDING_OUTPUT_BYTES
        );
    }

    /// A writer over a pipe plus the receipt the session reads, so a test drives
    /// the real thread rather than a stand-in for it.
    struct TestWriter {
        frames: tokio::sync::mpsc::Sender<OutputFrame>,
        failure: tokio::sync::oneshot::Receiver<std::io::Error>,
        cancelled: Arc<AtomicBool>,
        thread: std::thread::JoinHandle<()>,
    }

    impl TestWriter {
        fn start(write_end: OwnedFd) -> Self {
            let (frames, queue) = tokio::sync::mpsc::channel(OUTPUT_QUEUE_FRAMES);
            let (failures, failure) = tokio::sync::oneshot::channel();
            let cancelled = Arc::new(AtomicBool::new(false));
            let thread = std::thread::spawn({
                let cancelled = Arc::clone(&cancelled);
                move || writer_loop(write_end, queue, failures, cancelled, TerminalLedger::new())
            });
            Self {
                frames,
                failure,
                cancelled,
                thread,
            }
        }
    }

    /// How many bytes wait unread on a descriptor.
    fn unread_bytes(fd: RawFd) -> i32 {
        let mut unread: libc::c_int = 0;
        // SAFETY: `fd` is an open descriptor the caller owns, and `FIONREAD`
        // writes exactly one `c_int` behind the pointer.
        let rc = unsafe { libc::ioctl(fd, libc::FIONREAD, &mut unread) };
        assert_eq!(rc, 0, "FIONREAD: {}", std::io::Error::last_os_error());
        unread
    }

    #[test]
    fn abort_discards_queued_output_instead_of_draining_it() {
        // The session has already failed, so output written after the terminal is
        // restored is output the host has stopped accepting. A frame far larger
        // than any pipe parks the writer inside its first `write(2)`, which is
        // what keeps the second frame queued behind it.
        //
        // The frame already dispatched may finish (macOS completes one oversized
        // pipe write in a single syscall, so it cannot be interrupted at all);
        // what must never happen is the writer *starting* the frame queued behind
        // the abort, which is what a writer that drained its receiver instead of
        // stopping would do.
        let (read_end, write_end) = std::io::pipe().expect("a pipe");
        let writer_fd = duplicate(write_end.as_raw_fd()).expect("duplicate the pipe");
        drop(write_end);
        let test_writer = TestWriter::start(writer_fd);
        let first = vec![b'a'; 1024 * 1024];
        let second = b"discarded".to_vec();
        test_writer
            .frames
            .try_send(OutputFrame::Data(first.clone()))
            .expect("the queue accepts the first frame");
        test_writer
            .frames
            .try_send(OutputFrame::Data(second.clone()))
            .expect("the queue accepts the second frame");

        // Unread bytes prove the writer started, and a 1 MiB frame cannot fit in
        // any pipe, so the second frame is provably still queued.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while unread_bytes(read_end.as_raw_fd()) == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the writer never started writing"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        let mut writer = OutputWriter {
            frames: Some(test_writer.frames),
            failure: None,
            cancelled: Arc::clone(&test_writer.cancelled),
            ledger: TerminalLedger::new(),
        };
        writer.abort();

        use std::io::Read as _;
        let mut captured = Vec::new();
        std::io::BufReader::new(read_end)
            .read_to_end(&mut captured)
            .expect("drain the writer");
        test_writer.thread.join().expect("the writer thread exits");

        assert!(
            !captured
                .windows(second.len())
                .any(|window| window == second),
            "output queued behind the abort was still written"
        );
        assert!(
            first.starts_with(&captured),
            "the writer wrote something other than the abandoned frame's own prefix"
        );
    }

    #[test]
    fn a_failed_write_is_the_writers_own_error() {
        // A read end that is already closed: the write is EPIPE, and the session
        // must be able to report that rather than only "stopped accepting
        // output". Rust ignores SIGPIPE, so the write fails instead of killing
        // the process.
        let (read_end, write_end) = std::io::pipe().expect("a pipe");
        drop(read_end);
        let writer_fd = duplicate(write_end.as_raw_fd()).expect("duplicate the pipe");
        drop(write_end);
        let mut test_writer = TestWriter::start(writer_fd);
        let frames = test_writer.frames.clone();
        frames
            .try_send(OutputFrame::Data(b"prompt".to_vec()))
            .expect("the queue accepts the frame");
        test_writer
            .thread
            .join()
            .expect("the writer exits after its failure");

        let upgraded = writer_error(
            &mut test_writer.failure,
            anyhow::anyhow!("the guest terminal output writer stopped accepting output"),
        );
        let text = format!("{upgraded:#}");
        assert!(text.contains("writing guest terminal output"), "{text}");
        assert!(
            text.to_lowercase().contains("pipe"),
            "the writer's own errno must survive: {text}"
        );
        assert!(
            !text.contains("stopped accepting output"),
            "the symptom must not replace the cause: {text}"
        );

        // A writer that ended without an error keeps the symptom it was given.
        let (_sender, mut silent) = tokio::sync::oneshot::channel::<std::io::Error>();
        let symptom = writer_error(&mut silent, anyhow::anyhow!("the writer was lost"));
        assert_eq!(format!("{symptom}"), "the writer was lost");
    }

    // ------------------------------------------------- the drain's own arms ---

    use crate::host_signals::HostSignal;

    /// A guest end whose identity is the one thing the drain must never lose.
    fn signalled_end() -> SessionEnd {
        SessionEnd::Guest {
            code: -1,
            signal: GuestSignal::reported(Some(libc::SIGTERM)),
        }
    }

    /// A drain that can never complete, so only the arm under test can decide.
    fn stalled_drain() -> Pin<Box<impl Future<Output = anyhow::Result<()>>>> {
        Box::pin(std::future::pending())
    }

    fn parked_runtime()
    -> Pin<Box<impl Future<Output = microsandbox::MicrosandboxResult<std::process::ExitStatus>>>>
    {
        Box::pin(std::future::pending())
    }

    /// The reported identity and the code, as the caller would report them.
    fn assert_signalled_end(result: anyhow::Result<SessionEnd>, why: &str) {
        let end = result.unwrap_or_else(|error| panic!("{why}: {error:#}"));
        assert_eq!(end, signalled_end(), "{why}");
        assert_eq!(end.exit_status(), 143, "{why}");
    }

    #[test]
    fn a_drain_cut_short_by_an_interrupt_keeps_the_guests_own_signal() {
        // Deterministic, not raced: the arrival is queued before the drain starts,
        // so its branch is ready on the first poll and the other two are pending.
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("a runtime")
            .block_on(async {
                for arriving in [libc::SIGINT, libc::SIGTERM] {
                    let (arrivals, queue) = tokio::sync::mpsc::unbounded_channel();
                    let mut supervision = Supervision::for_test(queue, Duration::from_secs(5));
                    arrivals
                        .send(HostSignal::for_test(arriving))
                        .expect("the queue is open");
                    let mut finishing = stalled_drain();
                    let (_sender, mut failure) = tokio::sync::oneshot::channel();
                    let mut runtime_exit = parked_runtime();
                    assert_signalled_end(
                        drain_guest_output(
                            signalled_end(),
                            &mut finishing,
                            &mut failure,
                            &mut supervision,
                            &mut runtime_exit,
                        )
                        .await,
                        "an interrupt during the drain",
                    );
                }
            });
    }

    #[test]
    fn a_drain_cut_short_by_a_forced_end_keeps_the_guests_own_signal() {
        // The grace expiring during the drain takes the same arm as a repeated
        // interrupt: nothing is left to forward, so the drain stops. A one-step
        // zero grace is what makes that arm reachable on a single poll — the
        // arrival is consumed first (arming the deadline), and the drain's own
        // `next()` is then the expiry.
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("a runtime")
            .block_on(async {
                let (arrivals, queue) = tokio::sync::mpsc::unbounded_channel();
                let mut supervision = Supervision::for_test(queue, Duration::ZERO);
                arrivals
                    .send(HostSignal::for_test(libc::SIGINT))
                    .expect("the queue is open");
                assert!(matches!(
                    supervision.next().await,
                    SupervisionStep::Forward(_)
                ));
                let mut finishing = stalled_drain();
                let (_sender, mut failure) = tokio::sync::oneshot::channel();
                let mut runtime_exit = parked_runtime();
                assert_signalled_end(
                    drain_guest_output(
                        signalled_end(),
                        &mut finishing,
                        &mut failure,
                        &mut supervision,
                        &mut runtime_exit,
                    )
                    .await,
                    "an expired grace during the drain",
                );
            });
    }

    #[test]
    fn a_drain_cut_short_by_runtime_loss_keeps_the_guests_own_signal() {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("a runtime")
            .block_on(async {
                // A runtime that ended cleanly and one that can no longer be
                // observed are the same fact after the guest reported: only output
                // is left to lose.
                let ended = std::process::Command::new("sh")
                    .arg("-c")
                    .arg("exit 0")
                    .status()
                    .expect("a stub exit");
                let outcomes: Vec<microsandbox::MicrosandboxResult<std::process::ExitStatus>> = vec![
                    Ok(ended),
                    Err(microsandbox::MicrosandboxError::Runtime(
                        "the runtime is gone".into(),
                    )),
                ];
                for outcome in outcomes {
                    let mut supervision = Supervision::legacy();
                    let mut finishing = stalled_drain();
                    let (_sender, mut failure) = tokio::sync::oneshot::channel();
                    let mut runtime_exit = Box::pin(std::future::ready(outcome));
                    assert_signalled_end(
                        drain_guest_output(
                            signalled_end(),
                            &mut finishing,
                            &mut failure,
                            &mut supervision,
                            &mut runtime_exit,
                        )
                        .await,
                        "runtime loss during the drain",
                    );
                }
            });
    }

    #[test]
    fn a_lost_reader_still_fails_the_drain_instead_of_reporting_a_status() {
        // The other direction: supervision ending is not an instruction about a
        // signal, so a truncating drain must not turn into a successful report.
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("a runtime")
            .block_on(async {
                let (arrivals, queue) = tokio::sync::mpsc::unbounded_channel();
                drop(arrivals);
                let mut supervision = Supervision::for_test(queue, Duration::from_secs(5));
                let mut finishing = stalled_drain();
                let (_sender, mut failure) = tokio::sync::oneshot::channel();
                let mut runtime_exit = parked_runtime();
                let error = drain_guest_output(
                    signalled_end(),
                    &mut finishing,
                    &mut failure,
                    &mut supervision,
                    &mut runtime_exit,
                )
                .await
                .expect_err("a lost reader is a session failure");
                assert!(
                    format!("{error:#}").to_lowercase().contains("signal"),
                    "the failure must name supervision: {error:#}"
                );
            });
    }
}
