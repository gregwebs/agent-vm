//! One `secretspec serve --read-only` child (or, in unit tests, one pipe pair)
//! and its framing (#202).
//!
//! # Blocking, deliberately
//!
//! Both resolve paths are synchronous trait methods: phase 1 in the root future
//! of `Runtime::block_on`, phase 2 in the SDK's own spawned create task,
//! immediately before `fork`. The keychain already blocks those threads the same
//! way, so this client is `std::process` plus `libc::poll` and owns no Tokio
//! types. A hung child costs its bound, not a wedged runtime.
//!
//! # The process group is the unit of cleanup
//!
//! A `resolver.get` may have made the server start a provider helper (`op`,
//! `vault`, a cloud CLI). That helper can hold a pipe, a credential or a
//! network request after the leader exits, so cleanup is never inferred from
//! leader liveness. One policy governs every stop — timeout, protocol
//! violation, restart, normal close, drop:
//!
//! 1. **observe without reaping** (`waitid(… WNOWAIT)`), which reports an exited
//!    leader while its pid — the pgid — stays reserved;
//! 2. **signal once** (`kill(-pgid, SIGKILL)`, one-shot entitlement);
//! 3. **then reap** the leader, bounded by [`REAP_CEILING`].
//!
//! Only `ESRCH` establishes that the group is gone, and nothing re-arms a
//! guard, so a recycled pgid is never signalled. Two residual windows survive
//! that rule and are recorded in ADR-0055: a pgid can be reused after the group
//! empties, and a leader can be reaped in a teardown whose group signal was not
//! proven delivered. Neither can retarget a later kill.

use std::ffi::OsString;
use std::fs::File;
use std::io::{ErrorKind as IoErrorKind, Read as _};
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use vstd::prelude::*;
use zeroize::Zeroizing;

use super::config::{SecretspecName, SessionKey};
use super::failure::SecretspecFailure;
use super::protocol::{
    self, DeadlineUnixMs, EmptyResult, GetResultWire, InitializeResult, Keep, RequestId,
};
use crate::secret_store::{self, Resolved, ServiceName};

/// Spawn → accepted handshake.
pub(super) const STARTUP_BUDGET: Duration = Duration::from_secs(5);
/// How long a timed-out request waits for the server's `cancelled` answer
/// before the group is killed.
pub(super) const CANCEL_GRACE: Duration = Duration::from_millis(200);
/// How long an orderly `rpc.shutdown` may take.
pub(super) const SHUTDOWN_GRACE: Duration = Duration::from_secs(1);
/// The window in which the leader must be reaped after the group signal.
pub(super) const REAP_CEILING: Duration = Duration::from_secs(1);
const REAP_POLL: Duration = Duration::from_millis(10);
/// Request/response frames a server may interleave before answering one
/// request.
pub(super) const MAX_INTERLEAVED_FRAMES: usize = 8;
const READ_CHUNK: usize = 4096;

/// The per-launch budgets. `production` takes the request bound and the notice
/// delay from the shared host-read policy, so a SecretSpec provider waiting on
/// an unlock prompt gets exactly the keychain's treatment.
#[derive(Debug, Clone, Copy)]
pub(super) struct Bounds {
    pub(super) startup: Duration,
    pub(super) request: Duration,
    pub(super) notice_after: Duration,
}

impl Bounds {
    pub(super) fn production() -> Self {
        Self {
            startup: STARTUP_BUDGET,
            request: secret_store::host_read_bound(),
            notice_after: secret_store::READ_NOTICE_AFTER,
        }
    }

    /// The bounds a *successful* test needs: generous enough that a loaded CI
    /// machine cannot turn a healthy child into a timeout, which would make the
    /// test assert the wrong thing.
    #[cfg(test)]
    pub(super) fn test_full() -> Self {
        Self {
            startup: Duration::from_secs(10),
            request: Duration::from_secs(10),
            notice_after: Duration::from_secs(1),
        }
    }

    #[cfg(test)]
    pub(super) fn short() -> Self {
        Self {
            startup: Duration::from_millis(500),
            request: Duration::from_millis(500),
            notice_after: Duration::from_millis(100),
        }
    }
}

/// What one exchange produced at the transport level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CallError {
    /// The local deadline expired (after `rpc.cancel` and its grace).
    TimedOut,
    /// EOF while reading: the child exited or closed its stdout.
    Closed,
    /// EPIPE on the **first** write of a request frame. The only retryable
    /// boundary: the request provably never reached the server. A later write —
    /// a refusal of a server request, or the tail of a partial frame — can
    /// never produce it; see `call`.
    WriteClosed,
    /// A frame beyond the enforced limit, in either direction.
    TooLarge,
    /// Anything that breaks the session: bad JSON, wrong id, wrong
    /// `jsonrpc`, too many interleaved frames.
    Violation,
}

/// One answered exchange.
pub(super) enum Reply<R> {
    Result(R),
    Error(protocol::ErrorKind),
}

/// The outcome of one `resolver.get` at the adapter's boundary, so the pool
/// decides what happens to the slot without knowing the wire.
pub(super) enum Exchange {
    /// An answer, plus whether the session survives it.
    Answered(Resolved, Keep),
    /// EPIPE before the request was written: the child died while idle.
    DeadBeforeRequest,
}

/// One live session.
pub(super) struct Session {
    to_server: File,
    from_server: File,
    /// `min(CLIENT_MAX_FRAME_BYTES, negotiated limits.max_frame_bytes)`,
    /// applied to every subsequent read **and** write. Starts at the advertised
    /// maximum, because the handshake has no negotiated limit yet.
    frame_limit: usize,
    /// Bytes read past the last LF. Reserved once at
    /// `CLIENT_MAX_FRAME_BYTES + READ_CHUNK` and never grown, so the buffer
    /// cannot leave an un-zeroized copy behind on reallocation.
    pending: Zeroizing<Vec<u8>>,
    next_id: u64,
    /// `None` only for the test transport (a pipe pair, no child).
    child: Option<ChildGuard>,
}

impl Session {
    /// Spawn `<executable> serve --read-only` and complete the handshake within
    /// `bounds.startup`.
    pub(super) fn start(key: &SessionKey, bounds: &Bounds) -> Result<Self, SecretspecFailure> {
        let started = Instant::now();
        let mut session = Self::spawn(key)?;
        let budget = bounds.startup.saturating_sub(started.elapsed());
        session.handshake(key, budget)?;
        Ok(session)
    }

    /// The spawn half: the executable check, the exact argv, the pinned cwd, the
    /// filtered environment and the own process group. Separated from the
    /// handshake so a test can observe the process edge without a server.
    pub(super) fn spawn(key: &SessionKey) -> Result<Self, SecretspecFailure> {
        check_executable(key.executable())?;
        let mut command = Command::new(key.executable());
        command
            .args(["serve", "--read-only"])
            // No project-relative discovery: the manifest is pinned, and so is
            // where the child may claim to be running from.
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Third-party text cannot be redacted, so none of it reaches our
            // stderr; the remedy lines point at `secretspec check` instead.
            .stderr(Stdio::null());
        // Provider CLIs need their own variables (`OP_*`, `VAULT_*`, `AWS_*`)
        // and an `env` provider's input *is* a host variable, so the child
        // inherits the environment. What it must not inherit is SecretSpec's
        // own navigation (`SECRETSPEC_FILE`, `SECRETSPEC_PROVIDER`, …): a
        // project's direnv could export those, and the session pins everything
        // they could steer.
        for (name, _) in std::env::vars_os() {
            if is_secretspec_variable(&name) {
                command.env_remove(&name);
            }
        }
        // Own process group, so a timeout kills provider helpers too (the
        // `oauth_refresh` precedent).
        unsafe {
            // SAFETY: `setpgid` is async-signal-safe and touches no memory of
            // ours; returning an error only fails the spawn.
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
        let mut child = command
            .spawn()
            .map_err(|_| SecretspecFailure::ExecutableMissing)?;
        let to_server = child
            .stdin
            .take()
            .map(|stdin| File::from(OwnedFd::from(stdin)))
            .ok_or(SecretspecFailure::StartupFailed)?;
        let from_server = child
            .stdout
            .take()
            .map(|stdout| File::from(OwnedFd::from(stdout)))
            .ok_or(SecretspecFailure::StartupFailed)?;
        Self::new(to_server, from_server, Some(ChildGuard::new(child)))
    }

    /// `rpc.initialize` within `budget`, then the gate, whose accepted frame
    /// limit is stored before any get is sent. A gate failure drops the session,
    /// whose guard kills the group.
    pub(super) fn handshake(
        &mut self,
        key: &SessionKey,
        budget: Duration,
    ) -> Result<(), SecretspecFailure> {
        let handshake = self.call::<InitializeResult>(
            |id, deadline| protocol::initialize_frame(id, key, deadline),
            budget,
            None,
            budget,
        );
        match handshake {
            Ok(Reply::Result(result)) => {
                let limit = protocol::gate(&result)?;
                self.set_frame_limit(limit);
                Ok(())
            }
            Ok(Reply::Error(kind)) => Err(protocol::initialize_failure(kind)),
            Err(CallError::TimedOut) => Err(SecretspecFailure::HandshakeTimedOut),
            Err(CallError::Closed | CallError::WriteClosed) => {
                Err(SecretspecFailure::StartupFailed)
            }
            Err(CallError::TooLarge | CallError::Violation) => {
                Err(SecretspecFailure::ProtocolViolation)
            }
        }
    }

    /// The internal seam for unit tests: the same framing over an in-process
    /// pipe pair, driven by `fake::serve` on a thread. Not exported: the
    /// production type stores no trait object.
    #[cfg(test)]
    pub(super) fn over(to_server: OwnedFd, from_server: OwnedFd) -> Self {
        Session::new(File::from(to_server), File::from(from_server), None)
            .expect("a pipe pair takes O_NONBLOCK")
    }

    fn new(
        to_server: File,
        from_server: File,
        child: Option<ChildGuard>,
    ) -> Result<Self, SecretspecFailure> {
        set_nonblocking(&to_server)?;
        set_nonblocking(&from_server)?;
        Ok(Self {
            to_server,
            from_server,
            frame_limit: protocol::CLIENT_MAX_FRAME_BYTES,
            pending: Zeroizing::new(Vec::with_capacity(
                protocol::CLIENT_MAX_FRAME_BYTES + READ_CHUNK,
            )),
            next_id: 1,
            child,
        })
    }

    #[cfg(test)]
    pub(super) fn frame_limit(&self) -> usize {
        self.frame_limit
    }

    /// Adopt the negotiated limit, and shrink the read reservation to match
    /// once. The buffer is never grown: a grown `Vec` would free an
    /// un-zeroized copy of whatever it held.
    pub(super) fn set_frame_limit(&mut self, limit: usize) {
        self.frame_limit = limit;
        let capacity = limit.saturating_add(READ_CHUNK);
        if self.pending.capacity() > capacity {
            let mut shrunk = Zeroizing::new(Vec::with_capacity(capacity));
            shrunk.extend_from_slice(&self.pending);
            self.pending = shrunk;
        }
    }

    /// True when the **leader** has exited, observed without reaping it.
    ///
    /// `WNOWAIT` leaves the exited child in the process table, so its pid — and
    /// therefore this guard's pgid — stays reserved until the group signal,
    /// which is the only place the guard reaps. Never touches the group:
    /// helpers may still be alive.
    pub(super) fn leader_exited(&mut self) -> bool {
        self.child
            .as_mut()
            .is_some_and(|guard| guard.leader_exited())
    }

    fn take_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// One request/response exchange, answering server requests and skipping
    /// notifications.
    pub(super) fn call<R: DeserializeOwned>(
        &mut self,
        frame_for: impl FnOnce(RequestId, DeadlineUnixMs) -> Vec<u8>,
        bound: Duration,
        notice: Option<&dyn Fn()>,
        notice_after: Duration,
    ) -> Result<Reply<R>, CallError> {
        let id = self.take_id();
        let deadline = Instant::now() + bound;
        let request = frame_for(RequestId(id), DeadlineUnixMs::after(bound));
        self.write_frame(&request, deadline)?;
        let mut notice = notice.map(|emit| (Instant::now() + notice_after, emit));
        for _ in 0..=MAX_INTERLEAVED_FRAMES {
            let frame = match self.read_frame(deadline, &mut notice) {
                Err(CallError::TimedOut) => {
                    self.cancel(id);
                    return Err(CallError::TimedOut);
                }
                other => other?,
            };
            let Ok(incoming) = serde_json::from_slice::<protocol::Incoming<R>>(&frame) else {
                // `serde_json::Error`'s Display can quote the frame; dropped
                // unrendered, exactly like `keyring::Error`.
                return Err(CallError::Violation);
            };
            if incoming.jsonrpc != "2.0" {
                return Err(CallError::Violation);
            }
            let protocol::Incoming {
                id: incoming_id,
                method,
                result,
                error,
                ..
            } = incoming;
            match (method.is_some(), incoming_id, result, error) {
                // A server request (only `client.prompt` exists): refuse it and
                // keep waiting, because the get's own answer still decides.
                //
                // The request frame has already been accepted, so a failure to
                // write the refusal is a session lost **mid-request**, never
                // "the request did not reach the server". Mapping `WriteClosed`
                // away here is what keeps that boundary to the request frame:
                // retrying a refused prompt would send a second `resolver.get`
                // for one resolve (§1.4, AC2).
                (true, Some(theirs), _, _) => {
                    self.write_frame(&protocol::method_not_found_frame(theirs), deadline)
                        .map_err(|error| match error {
                            CallError::WriteClosed => CallError::Closed,
                            other => other,
                        })?;
                }
                // A notification: nothing to do.
                (true, None, _, _) => {}
                (false, Some(theirs), Some(result), None) if theirs == id => {
                    return Ok(Reply::Result(result));
                }
                (false, Some(theirs), None, Some(error)) if theirs == id => {
                    return Ok(Reply::Error(protocol::error_kind(&error)));
                }
                // A wrong id, both arms, neither arm, or `id: null`.
                _ => return Err(CallError::Violation),
            }
        }
        Err(CallError::Violation)
    }

    /// Tell the server we gave up, give it [`CANCEL_GRACE`] to say `cancelled`,
    /// then let the caller drop the session (which kills the group). The
    /// cancelled reply, if any, is read and discarded.
    fn cancel(&mut self, id: u64) {
        let grace = Instant::now() + CANCEL_GRACE;
        if self
            .write_frame(&protocol::cancel_frame(RequestId(id)), grace)
            .is_ok()
        {
            let _ = self.read_frame(grace, &mut None);
        }
    }

    /// One `resolver.get`. The bound, the notice and the whole outcome mapping
    /// live here so the pool only decides what happens to the slot.
    pub(super) fn get(
        &mut self,
        name: &SecretspecName,
        bounds: &Bounds,
        label: &ServiceName,
    ) -> Exchange {
        let notice = || {
            secret_store::emit_notice_line(&format!(
                "warning: SecretSpec has not answered for `{label}` yet; a provider may be \
                 waiting on an unlock or sign-in prompt. A request with no answer is abandoned \
                 after {:?}",
                bounds.request
            ));
        };
        let exchange = self.call::<GetResultWire>(
            |id, deadline| protocol::get_frame(id, name, deadline),
            bounds.request,
            Some(&notice),
            bounds.notice_after,
        );
        let (resolved, keep) = match exchange {
            Ok(Reply::Result(wire)) => protocol::classify_get(wire),
            Ok(Reply::Error(kind)) => protocol::classify_get_error(kind),
            // The only retryable boundary: no byte of the **request** frame was
            // accepted, so the request never reached the server.
            Err(CallError::WriteClosed) => return Exchange::DeadBeforeRequest,
            Err(CallError::TimedOut) => (
                Resolved::SecretspecUnavailable(SecretspecFailure::Unresponsive),
                Keep::Kill,
            ),
            Err(CallError::Closed) => (
                Resolved::SecretspecUnavailable(SecretspecFailure::SessionLost),
                Keep::Kill,
            ),
            // A value beyond the limit is a value agent-vm will not inject:
            // a hard error under every policy, not an unavailable source.
            Err(CallError::TooLarge) => (
                Resolved::InvalidValue(crate::secret_store::ValueRejection::TooLong),
                Keep::Kill,
            ),
            Err(CallError::Violation) => (
                Resolved::SecretspecUnavailable(SecretspecFailure::ProtocolViolation),
                Keep::Kill,
            ),
        };
        Exchange::Answered(resolved, keep)
    }

    /// Test-only: close agent-vm's write end without touching the guard, so a
    /// test can ask what the child observes at EOF while the reaping owner is
    /// unchanged. Returns the replacement so it is not dropped by the caller.
    #[cfg(test)]
    pub(super) fn drop_writer_for_test(&mut self) -> File {
        let (_read, write) = std::io::pipe().expect("pipe");
        std::mem::replace(&mut self.to_server, File::from(OwnedFd::from(write)))
    }

    /// Test-only: the read-end counterpart of [`Self::drop_writer_for_test`].
    #[cfg(test)]
    pub(super) fn drop_reader_for_test(&mut self) -> File {
        let (read, _write) = std::io::pipe().expect("pipe");
        std::mem::replace(&mut self.from_server, File::from(OwnedFd::from(read)))
    }

    /// `rpc.shutdown` (≤ [`SHUTDOWN_GRACE`]), close stdin, then the group
    /// teardown. A helper that outlived an answered shutdown is killed by the
    /// same path, and a leader that already exited does not skip it.
    pub(super) fn shutdown(mut self) {
        let _ = self.call::<EmptyResult>(
            protocol::shutdown_frame,
            SHUTDOWN_GRACE,
            None,
            SHUTDOWN_GRACE,
        );
        // Closing stdin is the polite EOF; field drop order then runs the
        // guard's kill, which is what actually ends the group.
        drop(self.to_server);
    }

    /// One LF-terminated frame (LF stripped) or an error by `deadline`. Never a
    /// partial frame.
    fn read_frame(
        &mut self,
        deadline: Instant,
        notice: &mut Option<(Instant, &dyn Fn())>,
    ) -> Result<Zeroizing<Vec<u8>>, CallError> {
        loop {
            if let Some(end) = self.pending.iter().position(|&byte| byte == b'\n') {
                if end > self.frame_limit {
                    return Err(CallError::TooLarge);
                }
                return Ok(self.take_frame(end));
            }
            if self.pending.len() > self.frame_limit {
                return Err(CallError::TooLarge);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(CallError::TimedOut);
            }
            let mut wake = deadline;
            if let Some((at, emit)) = notice {
                if now >= *at {
                    emit();
                    *notice = None;
                } else {
                    wake = wake.min(*at);
                }
            }
            match poll_fd(self.from_server.as_raw_fd(), libc::POLLIN, wake - now) {
                // `POLLHUP`/`POLLERR` count as ready: the read below returns the
                // buffered bytes first and only then EOF, so a HUP with a frame
                // still buffered delivers it instead of losing it.
                PollOutcome::Ready => {}
                PollOutcome::TimedOut | PollOutcome::Interrupted => continue,
                PollOutcome::Failed => return Err(CallError::Closed),
            }
            let mut chunk = Zeroizing::new([0u8; READ_CHUNK]);
            match self.from_server.read(&mut chunk[..]) {
                // EOF: the child exited or closed stdout.
                Ok(0) => return Err(CallError::Closed),
                // Capacity is reserved, so this cannot reallocate.
                Ok(read) => self.pending.extend_from_slice(&chunk[..read]),
                Err(error)
                    if matches!(
                        error.kind(),
                        IoErrorKind::WouldBlock | IoErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                Err(_) => return Err(CallError::Closed),
            }
        }
    }

    /// Copy the frame out, shift the tail down, and zero every byte the frame
    /// vacated.
    fn take_frame(&mut self, end: usize) -> Zeroizing<Vec<u8>> {
        let mut frame = Zeroizing::new(Vec::with_capacity(end));
        frame.extend_from_slice(&self.pending[..end]);
        let consumed = end + 1;
        let tail = self.pending.len() - consumed;
        self.pending.copy_within(consumed.., 0);
        for byte in &mut self.pending[tail..] {
            *byte = 0;
        }
        self.pending.truncate(tail);
        frame
    }

    fn write_frame(&mut self, frame: &[u8], deadline: Instant) -> Result<(), CallError> {
        // The negotiated limit binds this direction too: a server that answered
        // a smaller `max_frame_bytes` must never receive a longer frame.
        if frame.len() > self.frame_limit {
            return Err(CallError::TooLarge);
        }
        let fd = self.to_server.as_raw_fd();
        write_bounded(&mut self.to_server, fd, frame, deadline)
    }
}

/// Write one whole frame, or fail by `deadline`.
///
/// The deadline is re-read on **every** iteration, including after an
/// `EINTR`: a signal storm that keeps interrupting `write` must not extend the
/// caller's bound. Extracted from [`Session::write_frame`] so the fault paths
/// are reachable with a stub `Write`, without a live pipe.
fn write_bounded(
    writer: &mut impl std::io::Write,
    fd: libc::c_int,
    frame: &[u8],
    deadline: Instant,
) -> Result<(), CallError> {
    let mut written = 0;
    while written < frame.len() {
        if Instant::now() >= deadline {
            return Err(CallError::TimedOut);
        }
        match writer.write(&frame[written..]) {
            Ok(0) => {
                // No progress is not success; wait for writability and let the
                // deadline decide.
                if !wait_writable(fd, deadline) {
                    return Err(CallError::TimedOut);
                }
            }
            Ok(count) => written += count,
            Err(error) if error.kind() == IoErrorKind::Interrupted => continue,
            Err(error) if error.kind() == IoErrorKind::BrokenPipe => {
                return Err(if written == 0 {
                    CallError::WriteClosed
                } else {
                    CallError::Closed
                });
            }
            Err(error) if error.kind() == IoErrorKind::WouldBlock => {
                if !wait_writable(fd, deadline) {
                    return Err(CallError::TimedOut);
                }
            }
            Err(_) => return Err(CallError::Closed),
        }
    }
    Ok(())
}

/// Whether the descriptor became writable before `deadline`. `false` is "stop
/// waiting", never "the descriptor is broken": the caller turns it into
/// [`CallError::TimedOut`], which is what a full pipe with no reader deserves.
fn wait_writable(fd: libc::c_int, deadline: Instant) -> bool {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        match poll_fd(fd, libc::POLLOUT, deadline - now) {
            PollOutcome::Ready => return true,
            PollOutcome::Interrupted => continue,
            PollOutcome::TimedOut | PollOutcome::Failed => return false,
        }
    }
}

/// Whether an environment variable name belongs to SecretSpec's own
/// configuration, which the child must not inherit.
fn is_secretspec_variable(name: &OsString) -> bool {
    name.as_encoded_bytes().starts_with(b"SECRETSPEC_")
}

/// The executable check, before any spawn.
///
/// Deliberately narrow: the target file (symlinks followed) must be a regular
/// file with an execute bit and must not be group- or other-writable. There is
/// **no ownership rule and no ancestor-directory rule** — a Homebrew install is
/// a symlink into a `Cellar` directory the operator does not own (measured on
/// the operator's host: `/opt/homebrew/bin/secretspec` → `../Cellar/…`, owner
/// `gweber`, invoking uid `claude`, parent `drwxrwxr-x`), so either rule would
/// refuse the very executable this client was measured against. Absolute
/// pinning defeats `PATH` and working-directory shadowing; it is not a checksum
/// against a compromised package manager, and the check-to-exec window is
/// accepted and recorded in ADR-0055.
fn check_executable(path: &Path) -> Result<(), SecretspecFailure> {
    let metadata = std::fs::metadata(path).map_err(|_| SecretspecFailure::ExecutableMissing)?;
    executable_trust(metadata.is_file(), metadata.permissions().mode())
}

/// The pure half of [`check_executable`]: no ownership, no ancestors, so it can
/// be exercised on any host without root and without touching an installation.
/// Test-only: the pure predicate, without a filesystem.
#[cfg(test)]
pub(super) fn executable_trust_for_test(is_file: bool, mode: u32) -> Option<SecretspecFailure> {
    executable_trust(is_file, mode).err()
}

fn executable_trust(is_file: bool, mode: u32) -> Result<(), SecretspecFailure> {
    // Two already-measured facts from the target's mode; the decisions are the
    // proved kernels below, and the metadata read is the trusted adapter.
    let has_execute_bit = mode & 0o111 != 0;
    let writable_by_group_or_others = mode & 0o022 != 0;
    if !executable_is_runnable(is_file, has_execute_bit) {
        return Err(SecretspecFailure::ExecutableMissing);
    }
    if !executable_is_trusted(is_file, has_execute_bit, writable_by_group_or_others) {
        return Err(SecretspecFailure::ExecutableUntrusted);
    }
    Ok(())
}

verus! {

/// The runnable half of the executable check: the target is a regular file with
/// at least one execute bit. Deliberately narrow — no ownership and no ancestor
/// rule — because the operator's own Homebrew install is a symlink into a
/// directory they do not own.
pub(crate) fn executable_is_runnable(is_regular_file: bool, has_execute_bit: bool) -> (ok: bool)
    ensures
        ok == (is_regular_file && has_execute_bit),
{
    is_regular_file && has_execute_bit
}

/// The trust half: a target writable by group or others is refused even when it
/// is runnable. One conjunction, so a runnable-but-writable target can never be
/// accepted.
pub(crate) fn executable_is_trusted(
    is_regular_file: bool,
    has_execute_bit: bool,
    writable_by_group_or_others: bool,
) -> (ok: bool)
    ensures
        ok == (is_regular_file && has_execute_bit && !writable_by_group_or_others),
{
    executable_is_runnable(is_regular_file, has_execute_bit) && !writable_by_group_or_others
}

} // verus!

/// `O_NONBLOCK` on agent-vm's own ends of the pipes (never the child's), so a
/// wedged child cannot park the read loop. A failure here aborts the start
/// instead of silently keeping a blocking descriptor.
fn set_nonblocking(file: &File) -> Result<(), SecretspecFailure> {
    set_nonblocking_fd(file.as_raw_fd())
}

/// Test-only: the `fcntl` failure path of [`set_nonblocking`]. An invalid
/// descriptor is the one way to reach it without a broken pipe.
#[cfg(test)]
pub(super) fn unusable_descriptor_is_refused() -> bool {
    set_nonblocking_fd(-1).is_err()
}

/// Test-only: make a raw descriptor non-blocking, so the test's own end of a
/// pipe behaves like the session's.
#[cfg(test)]
pub(super) fn set_nonblocking_for_test(fd: libc::c_int) -> bool {
    set_nonblocking_fd(fd).is_ok()
}

/// Test-only: the bounded-writability wait, so a full pipe can be observed
/// without going through a frame (whose size is capped by the session).
#[cfg(test)]
pub(super) fn wait_writable_for_test(fd: libc::c_int, deadline: Instant) -> bool {
    wait_writable(fd, deadline)
}

/// Test-only: the bounded frame write, so a stub `Write` can drive the fault
/// paths (`EINTR`, `Ok(0)`, a partial frame then `EPIPE`) under a deadline.
#[cfg(test)]
pub(super) fn write_bounded_for_test(
    writer: &mut impl std::io::Write,
    frame: &[u8],
    deadline: Instant,
) -> Result<(), CallError> {
    // `-1` is never polled: no stub below produces `Ok(0)` or `WouldBlock`, and
    // a real descriptor belongs to `write_frame`.
    write_bounded(writer, -1, frame, deadline)
}

fn set_nonblocking_fd(fd: libc::c_int) -> Result<(), SecretspecFailure> {
    // SAFETY: `fcntl` only reads and writes the descriptor's flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(SecretspecFailure::ExecutableMissing);
    }
    // SAFETY: as above; `O_NONBLOCK` is the only bit changed.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(SecretspecFailure::ExecutableMissing);
    }
    Ok(())
}

enum PollOutcome {
    Ready,
    TimedOut,
    Interrupted,
    Failed,
}

/// `poll(2)` on one descriptor, with the timeout rounded **up** to whole
/// milliseconds (a truncated 0 would busy-loop) and clamped to `i32::MAX`.
fn poll_fd(fd: libc::c_int, events: libc::c_short, timeout: Duration) -> PollOutcome {
    let millis = timeout.as_nanos().div_ceil(1_000_000).min(i32::MAX as u128) as i32;
    let mut descriptor = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    // SAFETY: `descriptor` is one valid `pollfd`; the count matches.
    let ready = unsafe { libc::poll(&mut descriptor, 1, millis) };
    match ready {
        0 => PollOutcome::TimedOut,
        1 => PollOutcome::Ready,
        -1 => {
            if std::io::Error::last_os_error().kind() == IoErrorKind::Interrupted {
                PollOutcome::Interrupted
            } else {
                PollOutcome::Failed
            }
        }
        // `poll` cannot return more ready descriptors than it was given.
        _ => PollOutcome::Failed,
    }
}

/// The process group a session owns.
///
/// `pgid == leader pid` at spawn. The leader is observed **without reaping**
/// (`waitid(… WNOWAIT)`), so the number stays reserved until teardown; teardown
/// issues at most one `kill(-pgid, SIGKILL)` (one-shot entitlement), reaps the
/// leader within [`REAP_CEILING`] afterwards, and disarms only when `ESRCH`
/// establishes that the group is gone.
struct ChildGuard {
    child: std::process::Child,
    pgid: libc::pid_t,
    /// The one signalling attempt has been spent (set on the first
    /// `kill(-pgid, …)`, delivered or not). No path sets this back to false.
    signalled: bool,
    /// The group was established gone by `ESRCH`; no further probe or signal.
    disarmed: bool,
    /// Set only by the bounded reap that runs **after** the group signal; never
    /// from `try_wait`'s `Err`.
    leader_reaped: bool,
}

impl ChildGuard {
    fn new(child: std::process::Child) -> Self {
        let pgid = child.id() as libc::pid_t;
        Self {
            child,
            pgid,
            signalled: false,
            disarmed: false,
            leader_reaped: false,
        }
    }

    fn leader_exited(&mut self) -> bool {
        if self.leader_reaped || self.disarmed {
            return self.leader_reaped;
        }
        let mut info: libc::siginfo_t = unsafe {
            // SAFETY: an all-zero `siginfo_t` is a valid value to pass as the
            // out-parameter; the call overwrites it.
            std::mem::zeroed()
        };
        // SAFETY: `info` is a valid writable `siginfo_t`; `WNOHANG|WNOWAIT`
        // neither blocks nor reaps.
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                self.pgid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        // SAFETY: `si_pid` reads the field the call just wrote; the union
        // accessor is the one `libc` provides for it.
        rc == 0 && unsafe { info.si_pid() } != 0
    }

    /// SIGKILL the whole group (provider helpers included) — at most once,
    /// ever — then reap the leader within [`REAP_CEILING`].
    ///
    /// Never skipped because the leader already exited: a leader can exit while
    /// a helper it spawned holds a pipe, a credential or an open request.
    /// Test-only: `kill`, reporting whether the group is gone afterwards.
    #[cfg(test)]
    fn kill_group_once(&mut self) -> bool {
        self.kill();
        self.group_is_gone()
    }

    fn kill(&mut self) {
        let mut delivered = Ok(());
        if !self.signalled {
            // One-shot: nothing sets this back, so no path signals a pgid twice.
            self.signalled = true;
            // SAFETY: a signal to a negative pid addresses the process group;
            // no memory is touched.
            if unsafe { libc::kill(-self.pgid, libc::SIGKILL) } == -1 {
                delivered = Err(std::io::Error::last_os_error());
            }
        }
        self.note_signal(delivered);
        // The leader is reaped only after that group signal, within a bound.
        if !self.leader_reaped {
            self.reap_within(REAP_CEILING);
        }
        // The group can empty after the signal; only a positive `ESRCH` disarms.
        if !self.disarmed && self.group_is_gone() {
            self.disarmed = true;
        }
    }

    /// The guard's only state transition over a signalling outcome.
    ///
    /// `ESRCH`, and only `ESRCH`, establishes that the group is gone. `EPERM`
    /// and every other error leave the guard armed: the signal was not proven
    /// delivered, so the guard never claims a cleanup that did not happen.
    fn note_signal(&mut self, result: std::io::Result<()>) {
        if let Err(error) = result
            && error.raw_os_error() == Some(libc::ESRCH)
        {
            self.disarmed = true;
        }
    }

    fn reap_within(&mut self, ceiling: Duration) -> bool {
        let start = Instant::now();
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => {
                    self.leader_reaped = true;
                    return true;
                }
                Ok(None) => {}
                // An `Err` is not evidence of reaping: keep the flag false and
                // retry until the ceiling.
                Err(_) => {}
            }
            if start.elapsed() >= ceiling {
                return false;
            }
            std::thread::sleep(REAP_POLL);
        }
    }

    fn group_is_gone(&self) -> bool {
        // SAFETY: signal 0 performs only the existence/permission check; no
        // memory is touched.
        let missing = unsafe { libc::kill(-self.pgid, 0) } == -1;
        missing && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.kill();
    }
}

/// The guard's transitions, driven through the real `ChildGuard` (X11).
///
/// These live here rather than in `tests.rs` because they need the private
/// state the transitions touch, and because a re-implemented predicate would
/// prove nothing about the code that runs in production.
#[cfg(test)]
mod guard_tests {
    use super::*;

    /// A child in its own process group, the shape production spawns.
    fn grouped(body: &str) -> std::process::Child {
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg(body)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: `setpgid` is async-signal-safe and touches no memory of ours.
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
        command.spawn().expect("a fixture child")
    }

    fn wait_for_exit(guard: &mut ChildGuard) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if guard.leader_exited() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        false
    }

    #[test]
    fn leader_exited_observes_without_reaping() {
        let mut guard = ChildGuard::new(grouped("exit 0"));
        assert!(wait_for_exit(&mut guard), "the leader exited");
        assert!(!guard.leader_reaped, "observation must not reap");
        // The leader is still in the process table, so the pid — and therefore
        // the pgid — is still reserved. Reaping is the guard's, and only after
        // the group signal.
        assert!(matches!(guard.child.try_wait(), Ok(Some(_))));
    }

    #[test]
    fn the_first_kill_delivers_a_group_signal_and_reaps() {
        let mut guard = ChildGuard::new(grouped("sleep 30"));
        assert!(guard.kill_group_once());
        assert!(guard.signalled, "the entitlement was spent");
        assert!(guard.leader_reaped, "the leader is reaped after the signal");
        assert!(guard.disarmed, "an emptied group is disarmed");
    }

    #[test]
    fn the_guard_disarms_only_on_esrch() {
        let mut guard = ChildGuard::new(grouped("exit 0"));
        assert!(wait_for_exit(&mut guard));
        // `EPERM` is not proof of absence: the guard stays armed with its
        // entitlement spent, so it never claims a cleanup that did not happen.
        guard.signalled = true;
        guard.note_signal(Err(std::io::Error::from_raw_os_error(libc::EPERM)));
        assert!(!guard.disarmed, "EPERM must not disarm");
        assert!(guard.signalled, "an error does not re-arm the guard");
        // `ESRCH` is the only proof that disarms.
        guard.note_signal(Err(std::io::Error::from_raw_os_error(libc::ESRCH)));
        assert!(guard.disarmed);
    }

    #[test]
    fn a_signalled_guard_issues_no_second_signal() {
        let mut guard = ChildGuard::new(grouped("sleep 30"));
        assert!(guard.kill_group_once());
        let pgid = guard.pgid;
        assert!(guard.group_is_gone(), "the group was killed and emptied");
        // A second call is a no-op: the entitlement is spent, so nothing is
        // signalled even though the number is no longer reserved by us.
        guard.leader_reaped = true;
        guard.signalled = true;
        guard.kill_group_once();
        assert_eq!(guard.pgid, pgid);
        assert!(guard.signalled);
    }
}
