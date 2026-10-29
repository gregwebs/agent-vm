//! Host `SIGINT`/`SIGTERM` supervision for direct command launches (#401).
//!
//! A direct launch runs a guest command the operator can interrupt. While it
//! runs, this process must not die on the first interrupt: it has to forward the
//! signal to the guest, keep watching the guest for a fixed grace period, and
//! tear the sandbox down itself — including when the interrupt is repeated, when
//! the guest ignores it, and when the guest's output has stopped being consumed.
//! Everything about that — the handlers, the queue, the deadline and the status
//! table — lives here so the PTY session ([`crate::direct_pty`]) and the
//! streaming session ([`crate::run`]) cannot drift apart.
//!
//! # Why not `tokio::signal`
//!
//! `tokio::signal::unix::signal` registers a handler that is **never**
//! uninstalled: the process keeps swallowing `SIGINT`/`SIGTERM` for the rest of
//! its life. That is tolerable for `SIGWINCH`, whose disposition is irrelevant to
//! anyone (`direct_pty`'s resize stream is the one existing user), but not for a
//! termination signal the launcher itself must still die on after the session.
//! So the disposition is saved and restored exactly as `secret.rs`'s
//! `SignalGuard` does — this module is the second user of that pattern, and the
//! first whose handlers must stay installed across a whole session.
//!
//! # Signal identity is a byte, not a flag
//!
//! `secret.rs` records an arrival in a per-signal `AtomicBool`, which answers
//! "did this signal arrive at all". Supervision needs "how many times, in what
//! order", because the first interrupt starts the grace and the second one ends
//! it: two `SIGINT`s must be distinguishable from one. A raw handler may only
//! call async-signal-safe functions, so each arrival writes **its own signal
//! number** as one byte to a non-blocking self-pipe. A dedicated blocking thread
//! reads those bytes and turns them into [`HostSignal`]s on an unbounded channel.
//!
//! The queue exists **before** the first poll of any session loop, so an arrival
//! during installation or before the loop starts is neither lost nor coalesced.
//! The self-pipe write is non-blocking: if the pipe were ever full the byte would
//! be dropped rather than blocking inside a handler (a pipe's own buffer of
//! pending arrivals is far beyond any real burst, and the failure mode is a
//! dropped interrupt, not a wedged process).
//!
//! # The status table, and what is never inferred
//!
//! `128 + N` is produced **only** for a shutdown this launcher decided on: the
//! grace expired, or a second interrupt arrived. It is never derived from a guest
//! status of `-1`, from a missing exit event, or from the last signal we happened
//! to forward — a guest that died of `SIGKILL` inside the VM, or a session whose
//! transport died, would then be reported as `143` because we once sent
//! `SIGTERM`, which states a cause nobody observed. Telling a guest's *own*
//! signal death from its exit status needs the runtime to carry the fact (#467,
//! `WIFSIGNALED`/`WTERMSIG`), and until it does this module reports what it saw.
//!
//! | Outcome | [`SessionEnd`] |
//! |---|---|
//! | Guest reported a code (0, 126, 127, an unknown `-1`, …) | `Guest(code)`, passed through — so an unknown `-1` leaves the process as 255 |
//! | Forced shutdown with the guest still running | `Forced(signal)` → `128 + N` |
//! | The stream ended without any status | an `Err` in the caller (125) |
//! | Transport loss, no definitive exit | an `Err` in the caller (125) |
//! | Cleanup failure during teardown | an `Err` in the caller (125) |
//!
//! # Lifetime
//!
//! [`HostSignalGuard`] restores each signal's prior `sigaction` on `Drop`. It must
//! outlive the **teardown** as well as the session: a signal restored to its
//! default disposition mid-cleanup would kill the launcher with the VM still
//! running, which is the orphan-VM failure the teardown exists to prevent. A
//! signal that arrives during teardown is therefore absorbed, and the teardown's
//! own bounded timeouts are what keep that window finite.
//!
//! One process installs once. `signal-hook-registry` calls `sigaction` only the
//! first time it is given a signal, so after this guard's restore a second install
//! could not take effect; [`install`] detects that and refuses rather than
//! supervising nothing. A launcher installs for exactly one launch, so the limit
//! only shows up in tests, which use a process per install.

use std::future::Future;
use std::io::{PipeReader, PipeWriter};
use std::os::fd::{AsRawFd as _, RawFd};
use std::pin::Pin;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

use anyhow::Context as _;

/// The fixed grace a guest gets to act on a forwarded signal (#401).
///
/// Fixed by the feature: no option, and deliberately no environment override —
/// `test_env` is test-only, so an env knob would be a production override wearing
/// a test label. Tests inject the duration through [`install`].
pub(crate) const GRACE: Duration = Duration::from_secs(5);

/// The signals a direct launch forwards. `SIGQUIT` and `SIGHUP` are not
/// supervised: the contract names `SIGINT` and `SIGTERM`, and a signal this
/// launcher does not trap keeps its ordinary disposition (which restores the
/// terminal only as far as `RawTerminal::drop` can — a default-disposition
/// termination does not unwind, exactly as before #401).
const FORWARDED: [libc::c_int; 2] = [libc::SIGINT, libc::SIGTERM];

/// The byte that ends the reader thread. Signal numbers are 1..=64, so no
/// arrival can be confused with it.
const STOP: u8 = 0;

/// The write end the raw handler uses, or [`NO_WAKE`] when no handler is
/// installed.
///
/// A process-global because a signal action takes no context. It is set before
/// the first handler is installed and cleared only after every handler is
/// uninstalled, so no arrival can find it stale.
static WAKE: AtomicI32 = AtomicI32::new(NO_WAKE);
const NO_WAKE: RawFd = -1;

// ---------------------------------------------------------------------------
// Signals and the decisions taken about them
// ---------------------------------------------------------------------------

/// One host signal, identified by its number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HostSignal(i32);

impl HostSignal {
    /// The signal number to forward to the guest.
    pub(crate) fn number(self) -> i32 {
        self.0
    }

    /// What one byte of the self-pipe means. Every byte is written by
    /// [`write_signal_byte`], so it is always a signal number.
    fn from_byte(byte: u8) -> Self {
        Self(i32::from(byte))
    }

    /// A signal a test names directly. Production signals only ever come from
    /// the kernel through [`HostSignals`].
    #[cfg(test)]
    pub(crate) fn for_test(number: i32) -> Self {
        Self(number)
    }
}

/// A shutdown this launcher decided on: the guest is still running and will not
/// be asked again.
///
/// It carries the signal that *ended* the session — the second interrupt, or the
/// one forwarded when the grace expired — and never a claim about how the guest
/// died.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ForcedShutdown {
    signal: HostSignal,
}

impl ForcedShutdown {
    /// A forced end for a test that is not exercising the decision itself.
    #[cfg(test)]
    pub(crate) fn for_test(signal: HostSignal) -> Self {
        Self { signal }
    }

    /// The signal this shutdown followed.
    pub(crate) fn signal(self) -> HostSignal {
        self.signal
    }

    /// The shell convention for a command terminated by signal `N`.
    pub(crate) fn exit_status(self) -> i32 {
        128 + self.signal.number()
    }
}

/// What the supervisor decided for one host arrival or one expiry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SignalDecision {
    /// Forward this signal to the guest. The fixed grace started with it.
    Forward(HostSignal),
    /// End the session now and report this.
    Force(ForcedShutdown),
}

/// How a direct session ended, which is also how it must be torn down.
///
/// The two variants are the status table's two halves: a guest status, reported
/// as the guest gave it, and an explicit forced shutdown, the only source of
/// `128 + N`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SessionEnd {
    /// The guest reported this status itself.
    Guest(i32),
    /// The launcher stopped waiting and will kill the sandbox's guest.
    Forced(ForcedShutdown),
}

impl SessionEnd {
    /// The launcher exit status for this end.
    ///
    /// A guest status is passed through unchanged, `-1` and all: turning an
    /// unknown status into a signal status is the inference this feature forbids.
    pub(crate) fn exit_status(self) -> i32 {
        match self {
            Self::Guest(code) => code,
            Self::Forced(forced) => forced.exit_status(),
        }
    }
}

// ---------------------------------------------------------------------------
// The state machine
// ---------------------------------------------------------------------------

/// The grace and repeated-interrupt rules, with no I/O in them.
///
/// One value per session. It owns the **one** deadline the session polls: the
/// clock starts at the first forwarded signal and is never restarted, neither by
/// a second interrupt nor by output activity, so the grace cannot be extended
/// indefinitely by a guest that keeps writing.
#[derive(Debug)]
pub(crate) struct SignalSupervisor {
    grace: Duration,
    /// The first host signal, already forwarded. Its presence is what arms
    /// [`Self::grace_expired`].
    forwarded: Option<HostSignal>,
    /// Set once the session's end is decided. Kept so a further arrival cannot
    /// rewrite the cause that will be reported.
    forced: Option<ForcedShutdown>,
    /// The absolute end of the grace, fixed when the first signal is forwarded.
    ///
    /// Absolute, not a duration re-started per poll: that is what makes the grace
    /// fixed under activity, and it keeps the state machine's table tests free of
    /// a Tokio runtime.
    deadline_at: Option<std::time::Instant>,
    /// The pinned timer for `deadline_at`, created on the first poll and then
    /// re-polled. Held here rather than recreated so an interrupted poll cannot
    /// restart the grace.
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl SignalSupervisor {
    /// A supervisor with an injected grace: tests use a short one, a launch uses
    /// [`GRACE`].
    pub(crate) fn new(grace: Duration) -> Self {
        Self {
            grace,
            forwarded: None,
            forced: None,
            deadline_at: None,
            deadline: None,
        }
    }

    /// One host arrival: the first forwards and starts the clock, a second ends
    /// the session with **its own** signal.
    pub(crate) fn on_host_signal(&mut self, signal: HostSignal) -> SignalDecision {
        if let Some(forced) = self.forced {
            return SignalDecision::Force(forced);
        }
        match self.forwarded {
            Some(_) => {
                let forced = ForcedShutdown { signal };
                self.forced = Some(forced);
                SignalDecision::Force(forced)
            }
            None => {
                self.forwarded = Some(signal);
                self.deadline_at = Some(std::time::Instant::now() + self.grace);
                SignalDecision::Forward(signal)
            }
        }
    }

    /// The grace expired: the forced shutdown follows the forwarded signal.
    ///
    /// `None` when no signal was ever forwarded, which is the only state in which
    /// a deadline does not exist.
    pub(crate) fn on_grace_expired(&mut self) -> Option<ForcedShutdown> {
        if let Some(forced) = self.forced {
            return Some(forced);
        }
        let signal = self.forwarded?;
        let forced = ForcedShutdown { signal };
        self.forced = Some(forced);
        Some(forced)
    }

    /// The pinned deadline as a `select!` branch: pending until a signal was
    /// forwarded, then the single deadline that was created with it.
    ///
    /// Cancellation-safe: the same `Sleep` is re-polled, so an interrupted poll
    /// cannot restart the grace.
    pub(crate) async fn grace_expired(&mut self) -> ForcedShutdown {
        let Some(at) = self.deadline_at else {
            return std::future::pending().await;
        };
        let deadline = self.deadline.get_or_insert_with(|| {
            Box::pin(tokio::time::sleep_until(tokio::time::Instant::from_std(at)))
        });
        deadline.as_mut().await;
        match self.on_grace_expired() {
            Some(forced) => forced,
            // A deadline exists only alongside a forwarded signal, so this is
            // unreachable by construction. Parking is still the honest response:
            // it cannot fabricate an end.
            None => std::future::pending().await,
        }
    }
}

// ---------------------------------------------------------------------------
// The arrival stream
// ---------------------------------------------------------------------------

/// Arrivals, in the order the kernel delivered them.
pub(crate) struct HostSignals {
    arrivals: tokio::sync::mpsc::UnboundedReceiver<HostSignal>,
}

impl HostSignals {
    /// The next arrival, or `None` once the reader has stopped.
    ///
    /// The reader stops only when [`HostSignalGuard`] is dropped, which cannot
    /// happen while a session is running, or when its pipe breaks. A session
    /// treats `None` as a failure rather than as "no more interrupts": silently
    /// losing supervision would leave the launcher unable to honour the contract
    /// it is in the middle of.
    async fn recv(&mut self) -> Option<HostSignal> {
        self.arrivals.recv().await
    }
}

/// The installed handlers, owned for as long as this process must absorb
/// `SIGINT`/`SIGTERM` itself.
///
/// Dropping it restores each signal's prior disposition and ends the reader
/// thread. Hold it past the sandbox teardown — see the module docs.
pub(crate) struct HostSignalGuard {
    registrations: Vec<signal_hook::SigId>,
    /// Each signal's `sigaction` as it was before this guard installed anything.
    /// `signal_hook::low_level::unregister` removes our action but leaves a
    /// signal-hook handler installed, so without this restore the process would
    /// ignore `SIGINT`/`SIGTERM` for the rest of its life (`secret.rs`'s review
    /// finding R1).
    previous: Vec<(libc::c_int, libc::sigaction)>,
    write: Option<PipeWriter>,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl Drop for HostSignalGuard {
    fn drop(&mut self) {
        // Uninstall first, so a new arrival cannot start.
        for registration in self.registrations.drain(..) {
            signal_hook::low_level::unregister(registration);
        }
        for (signal, action) in self.previous.drain(..) {
            // SAFETY: `action` was read from this signal's own disposition by
            // `install`, and restoring it is what puts the signal back the way it
            // was found.
            unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) };
        }
        // Cleared before the descriptor can become stale, so an arrival from here
        // on writes nothing.
        WAKE.store(NO_WAKE, Ordering::SeqCst);
        let Some(write) = self.write.take() else {
            return;
        };
        // The reader is ended with a sentinel byte rather than by closing the
        // write end, because the descriptor has to stay open (see below).
        if write_byte(write.as_raw_fd(), STOP).is_err() {
            // Two ways the sentinel can be refused: the pipe is full (only after 64
            // KiB of unserialised arrivals), or the reader is already gone and the
            // write is `EPIPE`. Either way closing the write end is the only way left
            // to end the reader, and that reopens a window this function otherwise
            // closes: a handler that already loaded `WAKE` could write after the
            // descriptor number is reused. Both are the exceptional path, so the
            // narrow window is stated rather than removed.
            drop(write);
            if let Some(reader) = self.reader.take() {
                let _ = reader.join();
            }
            return;
        }
        if let Some(reader) = self.reader.take() {
            // The reader cannot be blocked on anything but its own `read`, so the
            // sentinel ends it and this join is bounded. A panicking reader has
            // already closed the arrival queue, which a live session sees as
            // `ReaderStopped` (125); `Drop` has no report of its own, and the
            // panic itself was printed by the thread that took it.
            let _ = reader.join();
        }
        // Deliberately leaked. An action on another thread may have loaded `WAKE`
        // before it was cleared above and be one `write(2)` away from running; if
        // this descriptor were closed, its number could be reused and that byte
        // would land in an unrelated open file. Keeping the number ours makes the
        // late write fail against a broken pipe instead (its read end is closed
        // with the reader), and the launcher is at the end of its life anyway.
        std::mem::forget(write);
    }
}

/// Install the forwarders and return the guard that owns them plus the stream
/// they feed.
///
/// Fails rather than supervises half-heartedly: a claim on [`WAKE`] that another
/// install already holds, or a handler the kernel did not actually take, both make
/// every later interrupt unobservable, which is the failure the ticket exists to
/// prevent.
pub(crate) fn install(grace: Duration) -> anyhow::Result<(HostSignalGuard, Supervision)> {
    // CLOEXEC on both ends: no child may inherit the pipe and keep the reader
    // alive after this process stops supervising (`std::io::pipe` sets it, which
    // is why it is preferred to `pipe(2)` plus `F_SETFD`).
    let (read, write) = std::io::pipe().context("creating the host signal self-pipe")?;
    set_nonblocking(write.as_raw_fd()).context("making the host signal self-pipe non-blocking")?;
    // Claimed before the first handler exists (a handler that found `NO_WAKE` would
    // drop an interrupt) and before the reader starts. Two installs in one process
    // cannot both be supervised: the second would take the arrivals the first one's
    // sessions are waiting for, so it is refused here.
    let wake = write.as_raw_fd();
    match WAKE.compare_exchange(NO_WAKE, wake, Ordering::SeqCst, Ordering::SeqCst) {
        Ok(_) => {}
        Err(held) => {
            return Err(anyhow::anyhow!(
                "host signal handlers are already installed in this process (self-pipe fd {held})"
            ));
        }
    }
    let mut guard = HostSignalGuard {
        registrations: Vec::new(),
        previous: Vec::new(),
        write: Some(write),
        reader: None,
    };
    let (sender, arrivals) = tokio::sync::mpsc::unbounded_channel();
    guard.reader = Some(
        std::thread::Builder::new()
            .name("agent-vm-host-signals".into())
            .spawn(move || reader_loop(read, sender))
            .context("starting the host signal reader")?,
    );
    for signal in FORWARDED {
        // Captured *before* installing anything, so `Drop` can put the signal back.
        let previous =
            disposition(signal).context("reading the previous host-signal disposition")?;
        let action = move || write_signal_byte(signal);
        // SAFETY: the action only calls `write(2)` on the self-pipe, which is
        // async-signal-safe. `signal_hook_registry` chains the disposition that was
        // installed when it first saw this signal, and it never chains *our*
        // action into a handler it installed later: see the read-back below.
        let registration = unsafe { signal_hook::low_level::register(signal, action) }
            .with_context(|| format!("installing the handler for signal {signal}"))?;
        guard.registrations.push(registration);
        guard.previous.push((signal, previous));
        // `register` calls `sigaction` only the first time it is given a signal;
        // afterwards it only adds the action to the slot it already has. Combined
        // with `Drop`'s restore, that makes a second `install` in this process add
        // an action the kernel will never run: `Ok` from `register`, no handler. So
        // the disposition is read back, and an install that did not change it is
        // refused instead of supervising nothing. (This also refuses the one benign
        // case, another in-process `signal_hook` registrant still installed for the
        // same signal, because the public API cannot tell the two apart — refusing
        // is the safe direction.)
        let installed =
            disposition(signal).context("reading back the installed host-signal disposition")?;
        if installed.sa_sigaction == previous.sa_sigaction {
            return Err(anyhow::anyhow!(
                "the handler for signal {signal} did not take effect: this process already \
                 installed and restored host-signal handlers, which signal-hook-registry \
                 cannot reinstall"
            ));
        }
    }
    Ok((guard, Supervision::direct(HostSignals { arrivals }, grace)))
}

/// This signal's current disposition.
fn disposition(signal: libc::c_int) -> std::io::Result<libc::sigaction> {
    // SAFETY: `sigaction` with a null `act` only writes the current disposition
    // into `action`.
    let mut action = std::mem::MaybeUninit::<libc::sigaction>::zeroed();
    if unsafe { libc::sigaction(signal, std::ptr::null(), action.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the call succeeded, so the kernel filled it in.
    Ok(unsafe { action.assume_init() })
}

/// Write one arrival's signal number into the self-pipe.
///
/// The only function that runs in a signal handler: `write(2)` on a non-blocking
/// descriptor is async-signal-safe, and a failed write is deliberately ignored —
/// there is nothing a handler may do about a full pipe but lose the byte.
fn write_signal_byte(signal: libc::c_int) {
    let fd = WAKE.load(Ordering::SeqCst);
    if fd == NO_WAKE {
        return;
    }
    let _ = write_byte(fd, signal as u8);
}

/// One byte to the self-pipe. `fd` is a live descriptor of this module's own pipe;
/// the caller decides what a failure means.
fn write_byte(fd: RawFd, byte: u8) -> std::io::Result<()> {
    let buffer = [byte];
    // SAFETY: `fd` is an open descriptor for the duration of the call (the handler
    // reads it from `WAKE`, which is cleared before the descriptor can close), and
    // `buffer` is a live one-byte buffer.
    let written = unsafe { libc::write(fd, buffer.as_ptr().cast(), buffer.len()) };
    match written {
        1 => Ok(()),
        0 => Err(std::io::ErrorKind::WriteZero.into()),
        _ => Err(std::io::Error::last_os_error()),
    }
}

/// Turn pipe bytes back into arrivals, one per byte, in order, until the guard's
/// [`STOP`] sentinel or end of input.
fn reader_loop(mut read: PipeReader, arrivals: tokio::sync::mpsc::UnboundedSender<HostSignal>) {
    use std::io::Read as _;
    let mut buffer = [0u8; 64];
    loop {
        let count = match read.read(&mut buffer) {
            Ok(0) => return,
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return,
        };
        for byte in &buffer[..count] {
            if *byte == STOP {
                return;
            }
            if arrivals.send(HostSignal::from_byte(*byte)).is_err() {
                return; // nothing is listening any more
            }
        }
    }
}

fn set_nonblocking(fd: RawFd) -> std::io::Result<()> {
    // SAFETY: `fd` is an open descriptor for both calls.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: as above; `F_SETFL` only changes the file status flags.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The per-session handle
// ---------------------------------------------------------------------------

/// One session's supervision: the arrival stream (when handlers are installed)
/// and the rules that decide what to do about each arrival.
///
/// This is the whole vocabulary a session loop needs, and it is inert for a
/// legacy launch: [`Self::legacy`] arms neither branch, so a `shell` or catalog
/// session behaves exactly as it did before #401.
pub(crate) struct Supervision {
    signals: Option<HostSignals>,
    supervisor: SignalSupervisor,
}

impl Supervision {
    /// Supervision over installed handlers.
    fn direct(signals: HostSignals, grace: Duration) -> Self {
        Self {
            signals: Some(signals),
            supervisor: SignalSupervisor::new(grace),
        }
    }

    /// No handlers, no deadlines: every supervision branch parks.
    pub(crate) fn legacy() -> Self {
        Self {
            signals: None,
            supervisor: SignalSupervisor::new(GRACE),
        }
    }

    /// Supervision over a test's own arrival queue.
    ///
    /// No handler is installed, so a session can be driven with a forwarded signal
    /// (and its grace) without a real one — what makes the sessions' forwarding path
    /// testable instead of reachable only through a booted sandbox.
    #[cfg(test)]
    pub(crate) fn for_test(
        arrivals: tokio::sync::mpsc::UnboundedReceiver<HostSignal>,
        grace: Duration,
    ) -> Self {
        Self::direct(HostSignals { arrivals }, grace)
    }

    /// The next supervision event, with its decision already taken.
    ///
    /// **One** `select!` branch, deliberately: the arrival queue and the grace
    /// deadline live in different fields, so they are polled together here and a
    /// session never needs two arms that borrow the same `Supervision`. It is
    /// cancel-safe — `recv()` yields or consumes nothing, and the deadline is the
    /// supervisor's own pinned timer rather than anything this future creates.
    pub(crate) async fn next(&mut self) -> SupervisionStep {
        let signals = self.signals.as_mut();
        let supervisor = &mut self.supervisor;
        tokio::select! {
            biased;
            // An arrival first: it is the rarer event, but a decision about it
            // must reach the session before an expiring grace can claim the
            // cause, or one interrupt could be reported as two.
            arrival = recv_arrival(signals) => match arrival {
                Some(signal) => match supervisor.on_host_signal(signal) {
                    SignalDecision::Forward(signal) => SupervisionStep::Forward(signal),
                    SignalDecision::Force(forced) => SupervisionStep::Force(forced),
                },
                None => SupervisionStep::ReaderStopped,
            },
            forced = supervisor.grace_expired() => SupervisionStep::Force(forced),
        }
    }

    /// Whether handlers are installed for this session. Only a test asserts this;
    /// a session treats both cases identically.
    #[cfg(test)]
    pub(crate) fn is_supervised(&self) -> bool {
        self.signals.is_some()
    }
}

/// What a session must do about the next supervision event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SupervisionStep {
    /// Forward this signal to the guest. The fixed grace started with it.
    Forward(HostSignal),
    /// End the session now and report this.
    Force(ForcedShutdown),
    /// The reader stopped, so supervision is over. A session treats this as a
    /// failure: it cannot honour a contract it is no longer able to observe.
    ReaderStopped,
}

/// The next arrival, or pending forever when no handlers are installed.
async fn recv_arrival(signals: Option<&mut HostSignals>) -> Option<HostSignal> {
    match signals {
        Some(signals) => signals.recv().await,
        None => std::future::pending().await,
    }
}

/// The launcher failure for [`SupervisionStep::ReaderStopped`].
///
/// One text, from this module, so the PTY session and the streaming session cannot
/// describe the same loss differently — supervision ending is one event with one
/// meaning: the launcher can no longer honour the contract it is in.
pub(crate) fn supervision_lost() -> anyhow::Error {
    anyhow::anyhow!("the host signal reader stopped while the command was still running")
}

// ---------------------------------------------------------------------------
// Forwarding an arrival to the guest
// ---------------------------------------------------------------------------

/// The channel a forwarded host signal is sent through.
///
/// A trait rather than the SDK's `ExecControl` directly, so a session loop can be
/// driven by a stub that records what it was asked to forward: forwarding is a
/// production path a test has to be able to exercise, not one that only a booted
/// sandbox can reach.
pub(crate) trait GuestControl: Clone + Send + 'static {
    /// Deliver one host signal to the guest's process.
    fn forward(&self, signal: HostSignal) -> impl Future<Output = anyhow::Result<()>> + Send;
}

impl GuestControl for microsandbox::sandbox::exec::ExecControl {
    async fn forward(&self, signal: HostSignal) -> anyhow::Result<()> {
        self.signal(signal.number())
            .await
            .map_err(anyhow::Error::new)
    }
}

/// A send a session accepted but a peer has not taken yet: guest output, host
/// input, a resize, a signal. One type, so "a held `select!` branch" means one
/// thing in both sessions.
pub(crate) type PendingSend = Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'static>>;

/// Hold one signal send.
///
/// The control is cloned into the future, so this never borrows the session it was
/// taken from: a send awaited in an arm body would suspend the whole loop, and a
/// stalled transport must delay the send without hiding an interrupt, the grace or
/// a lost runtime.
///
/// A failed forward is a launcher failure, not a swallow: the guest was never told,
/// so the session cannot claim it is supervising a guest that has been interrupted —
/// and on a real session the only cause is a transport that is gone, which is 125
/// anyway.
pub(crate) fn signal_send(control: impl GuestControl, signal: HostSignal) -> PendingSend {
    Box::pin(async move {
        control
            .forward(signal)
            .await
            .with_context(|| format!("forwarding signal {} to the guest", signal.number()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering as AtomicOrdering;

    fn sigint() -> HostSignal {
        HostSignal(libc::SIGINT)
    }

    fn sigterm() -> HostSignal {
        HostSignal(libc::SIGTERM)
    }

    /// Drive one arrival through a supervisor and report what it decided.
    fn decide(supervisor: &mut SignalSupervisor, signal: HostSignal) -> SignalDecision {
        supervisor.on_host_signal(signal)
    }

    #[test]
    fn the_first_signal_forwards_and_the_second_forces_with_its_own_identity() {
        let mut supervisor = SignalSupervisor::new(GRACE);
        assert_eq!(
            decide(&mut supervisor, sigint()),
            SignalDecision::Forward(sigint()),
            "the first interrupt is the guest's to handle"
        );
        let force = match decide(&mut supervisor, sigterm()) {
            SignalDecision::Force(forced) => forced,
            other => panic!("a second interrupt must force, got {other:?}"),
        };
        assert_eq!(
            force.signal(),
            sigterm(),
            "the interrupting signal is the one reported, not the first"
        );
        assert_eq!(force.exit_status(), 143);
    }

    #[test]
    fn a_repeated_signal_forces_at_128_plus_its_own_number() {
        let mut supervisor = SignalSupervisor::new(GRACE);
        assert_eq!(
            decide(&mut supervisor, sigint()),
            SignalDecision::Forward(sigint())
        );
        let force = match decide(&mut supervisor, sigint()) {
            SignalDecision::Force(forced) => forced,
            other => panic!("a repeated SIGINT must force, got {other:?}"),
        };
        assert_eq!(force.signal(), sigint());
        assert_eq!(force.exit_status(), 130);
    }

    #[test]
    fn expiry_forces_with_the_forwarded_signal() {
        let mut supervisor = SignalSupervisor::new(GRACE);
        assert_eq!(
            supervisor.on_grace_expired(),
            None,
            "an expiry with nothing forwarded decides nothing"
        );
        decide(&mut supervisor, sigterm());
        let forced = supervisor
            .on_grace_expired()
            .expect("a forwarded signal arms the expiry");
        assert_eq!(forced.signal(), sigterm());
        assert_eq!(forced.exit_status(), 143);
    }

    #[test]
    fn the_reported_cause_cannot_be_rewritten_after_the_shutdown_is_decided() {
        let mut supervisor = SignalSupervisor::new(GRACE);
        decide(&mut supervisor, sigint());
        let first = match decide(&mut supervisor, sigterm()) {
            SignalDecision::Force(forced) => forced,
            other => panic!("a second interrupt must force, got {other:?}"),
        };
        // A third arrival cannot change what will be reported, and neither can a
        // racing expiry: the session has one cause.
        match decide(&mut supervisor, sigint()) {
            SignalDecision::Force(forced) => assert_eq!(forced, first),
            other => panic!("a decided shutdown keeps its cause, got {other:?}"),
        }
        assert_eq!(supervisor.on_grace_expired(), Some(first));
    }

    #[tokio::test]
    async fn the_grace_is_one_deadline_created_with_the_first_signal() {
        let grace = Duration::from_millis(150);
        let mut supervisor = SignalSupervisor::new(grace);
        decide(&mut supervisor, sigint());
        let fixed = supervisor
            .deadline_at
            .expect("the first signal fixes the deadline");
        // An interrupted poll must not move or restart the deadline: this is the
        // property a per-poll `sleep(grace)` would lose.
        assert!(
            tokio::time::timeout(Duration::from_millis(20), supervisor.grace_expired())
                .await
                .is_err(),
            "the grace must not have expired yet"
        );
        assert_eq!(
            supervisor.deadline_at,
            Some(fixed),
            "polling the deadline cannot move it"
        );
        let forced = tokio::time::timeout(Duration::from_secs(5), supervisor.grace_expired())
            .await
            .expect("the grace expires once the fixed deadline passes");
        assert_eq!(forced.signal(), sigint());
        assert_eq!(forced.exit_status(), 130);
    }

    #[tokio::test]
    async fn an_unarmed_supervisor_never_reports_an_expiry() {
        let mut supervisor = SignalSupervisor::new(Duration::from_millis(1));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), supervisor.grace_expired())
                .await
                .is_err(),
            "no forwarded signal means no deadline at all"
        );
    }

    #[test]
    fn a_guest_status_is_passed_through_and_never_turned_into_a_signal_status() {
        // The table's second row: an unknown or absent status is not evidence of
        // a signal death, so `-1` leaves as `-1` (the legacy value) rather than
        // as `128 + N`.
        for code in [0, 1, 7, 126, 127, -1] {
            assert_eq!(SessionEnd::Guest(code).exit_status(), code);
        }
        assert_eq!(
            SessionEnd::Forced(ForcedShutdown { signal: sigint() }).exit_status(),
            130
        );
        assert_eq!(
            SessionEnd::Forced(ForcedShutdown { signal: sigterm() }).exit_status(),
            143
        );
    }

    #[tokio::test]
    async fn arrivals_keep_their_identity_and_their_multiplicity() {
        // The reader, driven through a real pipe: a flag-based design would
        // collapse these three arrivals into "some signal arrived".
        let (read, write) = std::io::pipe().expect("a pipe");
        let (sender, mut arrivals) = tokio::sync::mpsc::unbounded_channel();
        let thread = std::thread::spawn(move || reader_loop(read, sender));
        let bytes = [libc::SIGINT as u8, libc::SIGTERM as u8, libc::SIGINT as u8];
        // SAFETY: `write` is an open descriptor and `bytes` is a live slice.
        assert_eq!(
            unsafe { libc::write(write.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) },
            bytes.len() as isize
        );
        // Closing the write end is what ends the reader, exactly as the guard's
        // `Drop` does.
        drop(write);
        for expected in [sigint(), sigterm(), sigint()] {
            assert_eq!(arrivals.recv().await, Some(expected));
        }
        assert_eq!(arrivals.recv().await, None);
        thread.join().expect("the reader exits at end of input");
    }

    /// This signal's disposition, for comparing what an install changed.
    fn disposition_of(signal: libc::c_int) -> libc::sigaction {
        disposition(signal).expect("reading the disposition")
    }

    /// The whole handler lifecycle, without ever leaving a signal trapped: the
    /// arrival proves the handler identity reaches the queue, and the restore
    /// proves a launcher that has finished a session still dies on `SIGINT`.
    ///
    /// No signal is delivered after the restore — that would kill the test
    /// harness — so the disposition itself is what is asserted.
    #[tokio::test]
    async fn the_guard_forwards_an_arrival_and_restores_the_prior_disposition() {
        let before = disposition_of(libc::SIGINT);
        let (guard, mut supervision) = install(Duration::from_secs(1)).expect("install");
        assert!(supervision.is_supervised());
        assert_ne!(
            disposition_of(libc::SIGINT).sa_sigaction,
            before.sa_sigaction,
            "the handler must be installed while the session runs"
        );
        // SAFETY: `raise` has no preconditions; the handler it invokes only writes
        // one byte to this module's own pipe.
        assert_eq!(unsafe { libc::raise(libc::SIGINT) }, 0);
        let step = tokio::time::timeout(Duration::from_secs(5), supervision.next())
            .await
            .expect("the arrival must reach the queue");
        assert_eq!(
            step,
            SupervisionStep::Forward(sigint()),
            "the signal's identity is carried through"
        );

        drop(guard);
        assert_eq!(
            disposition_of(libc::SIGINT).sa_sigaction,
            before.sa_sigaction,
            "the prior disposition must come back, or the launcher would ignore \
             SIGINT for the rest of its life"
        );
        assert_eq!(WAKE.load(AtomicOrdering::SeqCst), NO_WAKE);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), supervision.next())
                .await
                .expect("the reader ends with the guard"),
            SupervisionStep::ReaderStopped,
            "a dropped guard leaves no arrivals behind"
        );
    }

    #[test]
    fn a_legacy_supervision_is_inert() {
        let supervision = Supervision::legacy();
        assert!(!supervision.is_supervised());
        // `WAKE` belongs to the installed pair, and only the guard test installs
        // one: asserting it here would race that test's install window (they share
        // this process). The guard test is what checks the global is cleared.
    }

    /// The one-shot install rule, in a process of its own: installing here would
    /// make every later install in this test binary fail, and test order is not
    /// deterministic. The child is the whole observation — it installs, is refused
    /// both a concurrent and a post-restore install, and proves the first guard's
    /// handler still works.
    #[test]
    fn a_second_install_in_one_process_is_refused() {
        let output = std::process::Command::new(std::env::current_exe().expect("the test binary"))
            .args([
                "--exact",
                SECOND_INSTALL_CHILD,
                "--nocapture",
                "--test-threads=1",
            ])
            .env(
                SECOND_INSTALL_DIR,
                tempfile::tempdir().expect("a child directory").path(),
            )
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .expect("spawn the child");
        assert!(
            output.status.success(),
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains(SECOND_INSTALL_OK),
            "the child did not report its observations: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }

    const SECOND_INSTALL_DIR: &str = "AGENT_VM_HOST_SIGNALS_SECOND_INSTALL";
    const SECOND_INSTALL_CHILD: &str = "host_signals::tests::second_install_child";
    const SECOND_INSTALL_OK: &str = "SECOND_INSTALL_REFUSED";

    /// Without the env token this is an ordinary passing test.
    #[tokio::test]
    async fn second_install_child() {
        if std::env::var_os(SECOND_INSTALL_DIR).is_none() {
            return;
        }
        let (first, mut supervision) = install(Duration::from_secs(1)).expect("the first install");
        // A concurrent install must not take over the descriptor the first one's
        // sessions are reading: with the claim in place it is refused, and the first
        // guard keeps working, which the arrival below proves.
        let concurrent = install(Duration::from_secs(1));
        assert!(
            concurrent.is_err(),
            "a second concurrent install must be refused, not silently take over"
        );
        // SAFETY: `raise` has no preconditions; the handler it invokes only writes
        // one byte to the first guard's own pipe.
        assert_eq!(unsafe { libc::raise(libc::SIGINT) }, 0);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), supervision.next())
                .await
                .expect("the first guard's arrival"),
            SupervisionStep::Forward(sigint()),
            "the refused install must not have stolen the first guard's arrivals"
        );
        drop(first);
        // The restore put the previous disposition back, and `signal-hook-registry`
        // will not install again for this signal: an install that returned `Ok` here
        // would supervise nothing for the rest of the process.
        let after_restore = install(Duration::from_secs(1));
        assert!(
            after_restore.is_err(),
            "an install that cannot reach the kernel must be refused"
        );
        assert_eq!(WAKE.load(AtomicOrdering::SeqCst), NO_WAKE);
        println!("{SECOND_INSTALL_OK}");
    }
}
