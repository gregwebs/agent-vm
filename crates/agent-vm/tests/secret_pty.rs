//! Controlling-terminal regression tests for the hidden `secret set` prompt
//! (issue #160, review findings 4, N1, N2 and N3).
//!
//! The interactive reader hangs for pastes at or above the terminal's canonical
//! line-buffer size (1024 bytes on macOS) unless it takes the tty out of
//! canonical mode for the whole line. These tests drive the **real binary**
//! under a pseudo-terminal, write a synthetic paste of a boundary length, and
//! assert the process completes within a bounded time instead of hanging.
//!
//! Three properties beyond "it does not hang":
//!
//! **An exact oracle, not the absence of one error.** A debug-only recording
//! backend (`AGENT_VM_TEST_SECRET_RECORD`, see `secret_store::RecordingKeychain`)
//! records the accepted value's length and SHA-256. Supported inputs must
//! produce exactly that record; the previous assertions would also have passed
//! against a reader that rejected every supported input (review finding N3).
//!
//! **Cancellation discards a queued paste suffix.** Writing `prefix`, then
//! Ctrl-C, then a synthetic suffix in one batch must leave the suffix neither
//! echoed nor queued for the caller's shell (review finding N1).
//!
//! **An external signal restores the terminal.** SIGINT/SIGTERM/SIGHUP/SIGQUIT
//! delivered while the reader waits must leave ECHO/ICANON/ISIG as they were
//! before (review finding N2). A typed Ctrl-C byte is a different path and is
//! covered separately.
//!
//! The harness itself is exercised against stand-in children that delay exit and
//! that close the slave without further output, because on Linux the master can
//! report `POLLHUP` alone once the child is gone.
//!
//! The tests run with `HOME` relocated to a temp dir and the recording backend
//! active, so no real credential store is touched and the temp dir carries all
//! cleanup.
//!
//! Two further properties defend the *lifecycle* of the signal guard the reader
//! installs:
//!
//! **A signal after the read still terminates the process.** `SignalGuard::drop`
//! restores the disposition each signal had before agent-vm ran, so the blocking
//! `flock` the store takes *after* the read is terminable with `SIGTERM` rather
//! than only `SIGKILL` (review finding R1).
//!
//! **An inherited `SIG_IGN` stays ignored.** A signal the caller had set to
//! `SIG_IGN` (a shell's background job, `nohup`) does not become fatal while the
//! hidden prompt is up (review finding R2).
//!
//! The baseline terminal flags are captured before the child is spawned, so the
//! restoration assertion cannot sample an already-raw terminal (review finding
//! R6).
//!
//! Note: `cargo test --release -p agent-vm` **fails loudly** rather than skipping.
//! The recording seam is `#[cfg(debug_assertions)]`, so under `--release` the
//! boundary tests fall through to the real store and fail the exit-0 assertion.
//! That is the right behaviour and it is not in CI (CI's release step is
//! `cargo build`); do not add a silent skip (review finding R7).

#![cfg(unix)]

use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

fn agent_vm_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-vm"))
}

/// A synthetic paste of exactly `len` bytes drawn from a pattern that cannot
/// occur in any message the program prints, so its presence in the output would
/// prove terminal echo.
fn synthetic_value(len: usize) -> Vec<u8> {
    const PATTERN: &[u8] = b"Zq3";
    (0..len)
        .map(|index| PATTERN[index % PATTERN.len()])
        .collect()
}

/// The exact line the recording backend appends for `synthetic_value(len)`:
/// `"<len> <sha256 hex>\n"`. No plaintext is written.
fn expected_record(len: usize) -> String {
    use sha2::{Digest as _, Sha256};
    let value = synthetic_value(len);
    let mut hasher = Sha256::new();
    hasher.update(&value);
    format!("{} {:x}\n", value.len(), hasher.finalize())
}

fn unique_name(tag: &str) -> String {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("avm-pty-{tag}-{}-{seq}", std::process::id())
}

fn open_pty() -> io::Result<(RawFd, RawFd)> {
    let mut master: RawFd = -1;
    let mut slave: RawFd = -1;
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((master, slave))
}

/// A child running against a fresh pty, with both ends kept in the parent so the
/// test can inspect the terminal state and any input the child left queued.
struct Pty {
    master: OwnedFd,
    slave: OwnedFd,
    child: Option<Child>,
    status: Option<ExitStatus>,
    /// The terminal's user flags sampled between `openpty` and `spawn`, so the
    /// restoration assertions compare against the real baseline rather than a
    /// value the child may already have made raw (review finding R6).
    baseline_flags: libc::tcflag_t,
}

impl Drop for Pty {
    fn drop(&mut self) {
        // Cleanup on every path, including a panic in the test body: reap a
        // still-running child so a failing test cannot leak a process.
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Spawn `command` with a fresh pty on stdio (the slave end), kept in the
/// parent as well so the test can inspect the terminal state and any queued
/// input. `HOME` is relocated; `record`, when present, enables the debug-only
/// recording backend.
///
/// The child is deliberately **not** made a session leader or given the slave
/// as a controlling terminal: `is_terminal()` only needs the fds to be a tty,
/// and a session-leader death makes macOS revoke the slave, which would hide
/// the terminal state this harness exists to measure. This also matches how a
/// shell actually runs the binary (a foreground member of an existing session).
fn spawn_under_pty(home: &Path, command: &mut Command, record: Option<&Path>) -> io::Result<Pty> {
    let (master, slave) = open_pty()?;
    // Capture the baseline here, while the child cannot yet have run: sampling
    // the flags after `spawn` races the child's `RawHiddenTerminal::enable` and
    // could record the *raw* value, making the restoration assertion vacuous
    // (review finding R6).
    let baseline_flags = terminal_user_flags(slave);
    let dup = |fd: RawFd| unsafe { libc::dup(fd) };
    command
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("AGENT_VM_STATE_DIR", home.join("state"))
        .env("NO_COLOR", "1")
        .current_dir(home)
        .stdin(unsafe { Stdio::from_raw_fd(dup(slave)) })
        .stdout(unsafe { Stdio::from_raw_fd(dup(slave)) })
        .stderr(unsafe { Stdio::from_raw_fd(dup(slave)) });
    if let Some(record) = record {
        command.env("AGENT_VM_TEST_SECRET_RECORD", record);
    }
    let child = command.spawn()?;
    // The child owns its copies; the parent keeps `slave` for attribute/queue
    // inspection. `master` is nonblocking; `slave` must stay blocking because a
    // nonblocking flag is shared with the child's stdio.
    let master = unsafe { OwnedFd::from_raw_fd(master) };
    let slave = unsafe { OwnedFd::from_raw_fd(slave) };
    set_nonblocking(master.as_raw_fd())?;
    Ok(Pty {
        master,
        slave,
        child: Some(child),
        status: None,
        baseline_flags,
    })
}

fn spawn_secret_set(home: &Path, name: &str, record: &Path) -> io::Result<Pty> {
    let mut command = Command::new(agent_vm_bin());
    command.args(["secret", "set", name]);
    spawn_under_pty(home, &mut command, Some(record))
}

fn spawn_stand_in(home: &Path, script: &str) -> io::Result<Pty> {
    let mut command = Command::new("sh");
    command.args(["-c", script]);
    spawn_under_pty(home, &mut command, None)
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn read_some(fd: RawFd, output: &mut Vec<u8>) -> io::Result<bool> {
    let mut buffer = [0_u8; 4096];
    loop {
        let read = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        if read > 0 {
            output.extend_from_slice(&buffer[..read as usize]);
            continue;
        }
        if read == 0 {
            // EOF: the slave side is gone.
            return Ok(false);
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            // EOF on a pty master is reported as EIO once the slave closes.
            Some(libc::EIO) => return Ok(false),
            // No more bytes right now.
            Some(libc::EAGAIN) => return Ok(true),
            _ if error.kind() == io::ErrorKind::Interrupted => continue,
            _ => return Err(error),
        }
    }
}

fn write_some(fd: RawFd, payload: &[u8]) -> io::Result<usize> {
    let written = unsafe { libc::write(fd, payload.as_ptr().cast(), payload.len()) };
    if written >= 0 {
        return Ok(written as usize);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::EAGAIN) => Ok(0),
        // The child is already gone; stop trying to feed it.
        Some(libc::EIO) => Ok(payload.len()),
        _ if error.kind() == io::ErrorKind::Interrupted => Ok(0),
        _ => Err(error),
    }
}

/// What the driver does once the prompt is visible.
enum Action<'a> {
    /// Write these bytes to the child's stdin.
    Write(&'a [u8]),
    /// Deliver this signal to the child.
    Signal(libc::c_int),
}

/// Drive the child: wait for the prompt, perform `action`, then read until the
/// child exits (which `try_wait` detects, so the loop cannot hang when Linux
/// reports `POLLHUP` with no further output) plus a short final drain.
///
/// `deadline` bounds the whole interaction, including process reaping.
fn drive(pty: &mut Pty, action: &Action, deadline: Duration) -> io::Result<(ExitStatus, Vec<u8>)> {
    const PROMPT: &[u8] = b"(input is hidden)";
    let fd = pty.master.as_raw_fd();
    let start = Instant::now();
    let mut output = Vec::new();
    let mut prompt_seen = false;
    let mut acted = false;
    let mut payload_sent = 0usize;
    while pty.child.is_some() {
        if start.elapsed() > deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "the child did not finish within {deadline:?}; output so far: {:?}",
                    String::from_utf8_lossy(&output)
                ),
            ));
        }
        let mut events = libc::POLLIN;
        if prompt_seen && !acted && matches!(action, Action::Write(_)) {
            events |= libc::POLLOUT;
        }
        let mut pollfd = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        // A short tick, so a `POLLHUP`-only state (no readable data) still lets
        // the loop notice a finished child and reap it within the deadline.
        let ready = unsafe { libc::poll(&mut pollfd, 1, 50) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if pollfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            // `read_some` returning `false` means EOF, which is fine here: the
            // `try_wait` below is what ends the loop.
            let _ = read_some(fd, &mut output)?;
        }
        if !prompt_seen && output.windows(PROMPT.len()).any(|window| window == PROMPT) {
            prompt_seen = true;
        }
        if prompt_seen && !acted {
            match action {
                Action::Write(payload) => {
                    if pollfd.revents & libc::POLLOUT != 0 && payload_sent < payload.len() {
                        payload_sent += write_some(fd, &payload[payload_sent..])?;
                    }
                    if payload_sent >= payload.len() {
                        acted = true;
                    }
                }
                Action::Signal(signal) => {
                    if let Some(child) = pty.child.as_ref() {
                        unsafe { libc::kill(child.id() as libc::pid_t, *signal) };
                    }
                    acted = true;
                }
            }
        }
        if let Some(child) = pty.child.as_mut()
            && let Some(status) = child.try_wait()?
        {
            pty.status = Some(status);
            pty.child = None;
        }
    }
    drain_after_exit(fd, &mut output)?;
    let status = pty.status.expect("a reaped child has a status");
    Ok((status, output))
}

/// Read the last buffered bytes after the child exits, bounded so a stalled
/// producer cannot keep the test alive.
fn drain_after_exit(fd: RawFd, output: &mut Vec<u8>) -> io::Result<()> {
    let end = Instant::now() + Duration::from_millis(500);
    loop {
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut pollfd, 1, 50) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if ready > 0 && !read_some(fd, output)? {
            return Ok(());
        }
        if Instant::now() >= end {
            return Ok(());
        }
    }
}

/// Write the whole payload to the master, retrying only while the master would
/// block. The child is alive in every caller, so a short retry loop is enough.
fn write_all_to_pty(fd: RawFd, payload: &[u8]) {
    let mut sent = 0;
    while sent < payload.len() {
        match write_some(fd, &payload[sent..]) {
            Ok(0) => std::thread::sleep(Duration::from_millis(10)),
            Ok(written) => sent += written,
            Err(error) => panic!("writing to the pty: {error}"),
        }
    }
}

/// Poll the master until the hidden prompt appears, returning the output so far.
/// Errors if the child exits first or the deadline passes.
fn wait_for_prompt(pty: &mut Pty, deadline: Duration) -> io::Result<Vec<u8>> {
    const PROMPT: &[u8] = b"(input is hidden)";
    let fd = pty.master.as_raw_fd();
    let start = Instant::now();
    let mut output = Vec::new();
    while start.elapsed() <= deadline {
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut pollfd, 1, 50) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if pollfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            let _ = read_some(fd, &mut output)?;
        }
        if output.windows(PROMPT.len()).any(|window| window == PROMPT) {
            return Ok(output);
        }
        if let Some(child) = pty.child.as_mut()
            && let Some(status) = child.try_wait()?
        {
            pty.status = Some(status);
            pty.child = None;
            return Err(io::Error::other(format!(
                "the child exited before the prompt: {status:?}"
            )));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "the hidden prompt did not appear",
    ))
}

/// Reap the child within `deadline`, draining output, and return its status.
/// Bounded like `drive`: `try_wait` ends the loop, so a `POLLHUP`-only state
/// cannot spin to the deadline.
fn wait_for_exit(
    pty: &mut Pty,
    output: &mut Vec<u8>,
    deadline: Duration,
) -> io::Result<ExitStatus> {
    let fd = pty.master.as_raw_fd();
    let start = Instant::now();
    while pty.child.is_some() {
        if start.elapsed() > deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "the child did not exit within {deadline:?}; output so far: {:?}",
                    String::from_utf8_lossy(output)
                ),
            ));
        }
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut pollfd, 1, 50) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if pollfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            let _ = read_some(fd, output)?;
        }
        if let Some(child) = pty.child.as_mut()
            && let Some(status) = child.try_wait()?
        {
            pty.status = Some(status);
            pty.child = None;
        }
    }
    drain_after_exit(fd, output)?;
    Ok(pty.status.expect("a reaped child has a status"))
}

/// Block until the child's terminal attributes return to the recorded baseline.
/// The reader's guard restores them when the read loop ends, so this is the
/// deterministic signal that the process has moved *past* the hidden read — the
/// window the R1 regression is about.
fn wait_for_restored_terminal(pty: &mut Pty, deadline: Duration) {
    let start = Instant::now();
    while start.elapsed() <= deadline {
        if terminal_user_flags(pty.slave.as_raw_fd()) == pty.baseline_flags {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("the terminal was not restored within {deadline:?}");
}

/// Read anything the child left in the terminal's input queue — what the
/// caller's shell would receive next.
fn read_leftover(slave: RawFd) -> Vec<u8> {
    let mut buffer = [0_u8; 4096];
    let mut pollfd = libc::pollfd {
        fd: slave,
        events: libc::POLLIN,
        revents: 0,
    };
    let ready = unsafe { libc::poll(&mut pollfd, 1, 200) };
    if ready <= 0 {
        return Vec::new();
    }
    let read = unsafe { libc::read(slave, buffer.as_mut_ptr().cast(), buffer.len()) };
    if read > 0 {
        buffer[..read as usize].to_vec()
    } else {
        Vec::new()
    }
}

fn terminal_user_flags(fd: RawFd) -> libc::tcflag_t {
    let mut attrs = std::mem::MaybeUninit::<libc::termios>::uninit();
    let rc = unsafe { libc::tcgetattr(fd, attrs.as_mut_ptr()) };
    assert_eq!(
        rc,
        0,
        "tcgetattr on fd {fd}: {}",
        io::Error::last_os_error()
    );
    let flags = unsafe { attrs.assume_init() }.c_lflag;
    flags & (libc::ECHO | libc::ICANON | libc::ISIG | libc::IEXTEN)
}

/// Assert the hidden reader handles `len` bytes: completes, does not echo, and
/// delivers exactly the supplied bytes (or rejects exactly the over-limit case).
fn assert_boundary(len: usize, expect_length_error: bool) {
    let home = tempfile::tempdir().unwrap();
    let record = home.path().join("record");
    let name = unique_name(&format!("boundary-{len}"));
    let expected = synthetic_value(len);
    let mut payload = expected.clone();
    payload.push(b'\n');
    let mut pty = spawn_secret_set(home.path(), &name, &record).expect("spawn under a pty");
    let (status, output) = drive(&mut pty, &Action::Write(&payload), Duration::from_secs(30))
        .unwrap_or_else(|error| panic!("len {len}: {error}"));
    let text = String::from_utf8_lossy(&output);

    // (a) Bounded completion: a hang would have timed out above, and the child
    //     exited rather than being signalled.
    assert!(
        status.code().is_some(),
        "len {len}: child was signalled: {text}"
    );
    // (b) No echo: the synthetic pattern would appear if the tty echoed it.
    let echo_needle = synthetic_value(9.min(len));
    assert!(
        !output
            .windows(echo_needle.len())
            .any(|window| window == echo_needle),
        "len {len}: the input was echoed: {text}"
    );
    let recorded = std::fs::read_to_string(&record).unwrap_or_default();
    if expect_length_error {
        assert_eq!(
            status.code(),
            Some(1),
            "len {len}: expected the length error exit: {text}"
        );
        assert!(
            text.contains("longer than 4096 bytes"),
            "len {len}: expected the length error: {text}"
        );
        // (c) A rejected value must not reach the store at all.
        assert_eq!(recorded, "", "len {len}: an over-limit value was stored");
    } else {
        // (c) The exact oracle: the accepted value reached the store attempt, and
        //     its recorded length and hash are exactly the supplied bytes.
        assert_eq!(
            status.code(),
            Some(0),
            "len {len}: a supported value was not accepted: {text}"
        );
        assert!(
            text.contains("test recording backend is active"),
            "len {len}: a supported value did not reach the store: {text}"
        );
        assert_eq!(
            recorded,
            expected_record(len),
            "len {len}: the stored value did not match the input"
        );
    }
}

/// The old canonical-mode reader hung at this exact boundary.
#[test]
fn paste_at_the_canonical_buffer_boundary_completes() {
    assert_boundary(1023, false);
    assert_boundary(1024, false);
}

/// The advertised value limit: 4096 is accepted, 4097 is rejected.
#[test]
fn paste_at_the_value_length_boundary_is_accepted_then_rejected() {
    assert_boundary(4096, false);
    assert_boundary(4097, true);
}

/// Finding 3 — the hidden prompt names no service, so a key accidentally typed
/// in the name slot is not printed before the value is entered, and an aborted
/// read does not echo it in either the typed or the case-folded spelling.
#[test]
fn the_hidden_prompt_does_not_repeat_a_key_shaped_name() {
    let typed = "sk-ant-API03-AbCdEf";
    let canonical = typed.to_ascii_lowercase();
    let home = tempfile::tempdir().unwrap();
    let record = home.path().join("record");
    let mut pty = spawn_secret_set(home.path(), typed, &record).expect("spawn under a pty");
    // Cancel with Escape once the prompt appears.
    let (status, output) =
        drive(&mut pty, &Action::Write(b"\x1b"), Duration::from_secs(30)).expect("drive the pty");
    let text = String::from_utf8_lossy(&output);
    assert_ne!(status.code(), Some(0), "a cancelled read must fail: {text}");
    assert!(
        text.contains("(input is hidden)"),
        "the prompt must still appear: {text}"
    );
    assert!(!text.contains(typed), "the typed name was echoed: {text}");
    assert!(
        !text.contains(&canonical),
        "the canonical name was echoed: {text}"
    );
    assert!(
        !record.exists(),
        "a cancelled read must not create a record"
    );
}

/// Finding N1 — a pasted suffix queued behind the cancellation byte must be
/// discarded: not echoed to the terminal and not left for the caller's shell.
#[test]
fn cancelling_discards_a_queued_paste_suffix() {
    const NEEDLE: &[u8] = b"sk-SYNTHETIC-TAIL-NEEDLE";
    let home = tempfile::tempdir().unwrap();
    let record = home.path().join("record");
    let mut pty =
        spawn_secret_set(home.path(), &unique_name("cancel"), &record).expect("spawn under a pty");
    let mut payload = b"prefix".to_vec();
    payload.push(0x03);
    payload.extend_from_slice(NEEDLE);
    payload.push(b'\n');
    let (status, output) =
        drive(&mut pty, &Action::Write(&payload), Duration::from_secs(30)).expect("drive the pty");
    let text = String::from_utf8_lossy(&output);
    assert_ne!(status.code(), Some(0), "a cancelled read must fail: {text}");
    assert!(
        text.contains("no value was supplied"),
        "expected the abort message: {text}"
    );
    assert!(
        !output.windows(NEEDLE.len()).any(|window| window == NEEDLE),
        "the queued suffix was echoed: {text}"
    );
    let leftover = read_leftover(pty.slave.as_raw_fd());
    assert!(
        leftover.is_empty(),
        "the queued suffix was left for the caller's shell: {leftover:?}"
    );
    assert!(
        !record.exists(),
        "a cancelled read must not create a record"
    );
}

/// Finding N2 — an externally delivered termination signal restores the terminal
/// before the process exits with the signal's default disposition.
#[test]
fn external_termination_signals_restore_the_terminal() {
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
        let home = tempfile::tempdir().unwrap();
        let record = home.path().join("record");
        let mut pty = spawn_secret_set(home.path(), &unique_name("signal"), &record)
            .expect("spawn under a pty");
        // The baseline was captured before the child could make the terminal raw
        // (review finding R6).
        let before = pty.baseline_flags;
        let (status, _output) = drive(&mut pty, &Action::Signal(signal), Duration::from_secs(30))
            .unwrap_or_else(|error| panic!("signal {signal}: {error}"));
        assert_eq!(
            status.signal(),
            Some(signal),
            "expected termination by the delivered signal (status {status:?})"
        );
        let after = terminal_user_flags(pty.slave.as_raw_fd());
        assert_eq!(
            before, after,
            "signal {signal} left the terminal raw (lflag {before} -> {after})"
        );
    }
}

/// Finding R1 — once the hidden read has finished, the process must still be
/// terminable. `SignalGuard::drop` used to leave a signal-hook handler installed
/// that swallowed SIGINT/SIGTERM/SIGHUP/SIGQUIT, and `secret set` continues past
/// the read into the store, whose first act is a blocking `flock` on the
/// inventory lock. Holding that lock from the test keeps the child alive in
/// exactly that post-read window, and `SIGTERM` must still end it.
#[test]
fn sigterm_terminates_after_the_hidden_read_while_the_store_lock_is_held() {
    let home = tempfile::tempdir().unwrap();
    let config_dir = home.path().join(".config/agent-vm");
    std::fs::create_dir_all(&config_dir).unwrap();
    let lock = File::create(config_dir.join(".secret-inventory.lock")).unwrap();
    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) },
        0,
        "locking the inventory: {}",
        io::Error::last_os_error()
    );

    let record = home.path().join("record");
    let mut pty = spawn_secret_set(home.path(), &unique_name("postread"), &record)
        .expect("spawn under a pty");
    let _prompt = wait_for_prompt(&mut pty, Duration::from_secs(30)).expect("the prompt");
    let payload = {
        let mut value = synthetic_value(16);
        value.push(b'\n');
        value
    };
    write_all_to_pty(pty.master.as_raw_fd(), &payload);
    // The reader's guard restores the terminal the moment the read loop returns,
    // so this is past the read and into the store's `flock`.
    wait_for_restored_terminal(&mut pty, Duration::from_secs(10));
    // Let the guard drop finish (it restores the saved dispositions) before
    // relying on the restored one.
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        pty.child.as_mut().unwrap().try_wait().unwrap().is_none(),
        "the child should still be blocked on the inventory lock"
    );

    // Send repeatedly rather than once: the guard's own handler is still
    // installed for a few instructions after the terminal is restored, and a
    // signal caught there is swallowed by design. A process that has restored
    // its default disposition dies on one of these; one that has not, never
    // does (the historical R1 bug).
    let pid = pty.child.as_ref().unwrap().id() as libc::pid_t;
    let mut output = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
        match wait_for_exit(&mut pty, &mut output, Duration::from_millis(200)) {
            Ok(status) => {
                assert_eq!(
                    status.signal(),
                    Some(libc::SIGTERM),
                    "expected termination by SIGTERM, got {status:?}: {}",
                    String::from_utf8_lossy(&output)
                );
                break;
            }
            Err(error) => {
                assert!(
                    Instant::now() < deadline,
                    "SIGTERM must terminate the process after the hidden read: {error}"
                );
            }
        }
    }
    unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) };
}

/// Finding R2 — a signal the caller set to `SIG_IGN` before `exec` (what a shell
/// does for `SIGINT`/`SIGQUIT` in background jobs, and `nohup` for `SIGHUP`) must
/// stay ignored while the hidden prompt is up, not be converted into a fatal
/// signal. `SIG_IGN` survives `exec`, so setting it in `pre_exec` reproduces the
/// inherited disposition.
///
/// The final case covers regression D1: an ignored signal must not mask a
/// *default-disposition* signal delivered in the same window.
#[test]
fn an_inherited_sig_ign_is_not_converted_into_termination() {
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        let home = tempfile::tempdir().unwrap();
        let record = home.path().join("record");
        let name = unique_name(&format!("ign-{signal}"));
        let mut command = Command::new(agent_vm_bin());
        command.args(["secret", "set", &name]);
        unsafe {
            command.pre_exec(move || {
                libc::signal(signal, libc::SIG_IGN);
                Ok(())
            });
        }
        let mut pty =
            spawn_under_pty(home.path(), &mut command, Some(&record)).expect("spawn under a pty");
        let _prompt = wait_for_prompt(&mut pty, Duration::from_secs(30)).expect("the prompt");
        let pid = pty.child.as_ref().unwrap().id() as libc::pid_t;
        assert_eq!(unsafe { libc::kill(pid, signal) }, 0);
        std::thread::sleep(Duration::from_millis(300));
        assert!(
            pty.child.as_mut().unwrap().try_wait().unwrap().is_none(),
            "signal {signal} terminated a process that had it set to SIG_IGN"
        );

        // The read must have continued: a value entered afterwards is delivered.
        let payload = {
            let mut value = synthetic_value(24);
            value.push(b'\n');
            value
        };
        write_all_to_pty(pty.master.as_raw_fd(), &payload);
        let mut output = Vec::new();
        let status = wait_for_exit(&mut pty, &mut output, Duration::from_secs(30))
            .unwrap_or_else(|error| panic!("signal {signal}: {error}"));
        assert_eq!(
            status.code(),
            Some(0),
            "signal {signal}: the hidden read should have continued: {}",
            String::from_utf8_lossy(&output)
        );
        assert_eq!(
            std::fs::read_to_string(&record).unwrap_or_default(),
            expected_record(24),
            "signal {signal}: the value entered after an ignored signal was not delivered"
        );
    }

    // D1 — an ignored signal must not mask a default-disposition one delivered
    // in the same window. Send the inherited-`SIG_IGN` SIGINT and a
    // default-disposition SIGTERM back to back at the prompt: the process must
    // die by SIGTERM and leave the terminal restored. With a single shared
    // last-writer-wins flag the ignored SIGINT overwrites the SIGTERM, which
    // signal-hook has already absorbed, so SIGTERM's default action can no
    // longer run and the reader hangs with the terminal raw.
    let home = tempfile::tempdir().unwrap();
    let record = home.path().join("record");
    let name = unique_name("ign-then-default");
    let mut command = Command::new(agent_vm_bin());
    command.args(["secret", "set", &name]);
    unsafe {
        command.pre_exec(move || {
            libc::signal(libc::SIGINT, libc::SIG_IGN);
            Ok(())
        });
    }
    let mut pty =
        spawn_under_pty(home.path(), &mut command, Some(&record)).expect("spawn under a pty");
    let before = pty.baseline_flags;
    let _prompt = wait_for_prompt(&mut pty, Duration::from_secs(30)).expect("the prompt");
    let pid = pty.child.as_ref().unwrap().id() as libc::pid_t;
    assert_eq!(unsafe { libc::kill(pid, libc::SIGINT) }, 0);
    assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
    let mut output = Vec::new();
    let status =
        wait_for_exit(&mut pty, &mut output, Duration::from_secs(10)).unwrap_or_else(|error| {
            panic!("an inherited SIG_IGN must not swallow a later default signal: {error}")
        });
    assert_eq!(
        status.signal(),
        Some(libc::SIGTERM),
        "expected termination by the default-disposition SIGTERM, got {status:?}: {}",
        String::from_utf8_lossy(&output)
    );
    let after = terminal_user_flags(pty.slave.as_raw_fd());
    assert_eq!(
        before, after,
        "the back-to-back signals left the terminal raw (lflag {before} -> {after})"
    );
}

/// Harness control — a child that prints its final message, waits, then exits.
/// The reader must capture the message and reap the child without timing out.
#[test]
fn harness_tolerates_a_delayed_exit() {
    let home = tempfile::tempdir().unwrap();
    let mut pty = spawn_stand_in(
        home.path(),
        r#"printf '(input is hidden): \r\nno value was supplied\r\n'; sleep 0.2; exit 1"#,
    )
    .expect("spawn sh");
    let (status, output) = drive(&mut pty, &Action::Write(b""), Duration::from_secs(10))
        .expect("a delayed exit must not time the harness out");
    assert_eq!(status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output).contains("no value was supplied"),
        "the final output must be drained"
    );
}

/// Harness control — the child closes the slave without further output, the
/// condition Linux can report as `POLLHUP` alone.
#[test]
fn harness_tolerates_a_closed_peer_without_further_output() {
    let home = tempfile::tempdir().unwrap();
    let mut pty =
        spawn_stand_in(home.path(), r#"printf '(input is hidden): '; exit 7"#).expect("spawn sh");
    let (status, _output) = drive(&mut pty, &Action::Write(b""), Duration::from_secs(10))
        .expect("a POLLHUP-only peer must not time the harness out");
    assert_eq!(status.code(), Some(7));
}
