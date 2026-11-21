//! PTY, terminal-mode, read and signal primitives shared by the harness drivers
//! (#698).
//!
//! Two ports sit on this module: `detached_run` and `launcher_standin`, and the
//! direct-terminal driver #699 ports next. The interface is deliberately the
//! *primitives* rather than a driver: each caller owns its process graph and its
//! verdict, and lands here only where the operating system needs a rustix call.
//!
//! What it keeps from the Python it replaces is behaviour, not shape: `raw` is
//! the launcher's raw mode (four local flags and two control codes) and not
//! `cfmakeraw(3)`; a hangup reads as an end of stream rather than as the errno
//! `EIO`; and a read deadline measures one wait, not a whole transfer. A child is
//! `OwnedChild` rather than a bare `Child`, so no driver here can wait forever or
//! leave a process behind.
//!
//! `rustix` covers the process primitives but exposes no signal *handler*
//! registration, so the two `sigaction` calls below come from `libc`, the same
//! escape hatch `released_image_launch` uses.

use std::{
    io,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    os::unix::process::{CommandExt, ExitStatusExt},
    process::{Child, Command, ExitStatus, Stdio},
    sync::atomic::{AtomicI32, Ordering},
    time::{Duration, Instant},
};

use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fs::{Mode, OFlags, open},
    io::Errno,
    process::{self, Pid, Signal},
    pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt},
    termios::{self, LocalModes, SpecialCodeIndex, Termios},
};

// --- Pseudoterminals --------------------------------------------------------

/// A pseudoterminal pair: the master the harness reads and writes, and the
/// slave a guest process uses as its terminal.
///
/// `rustix` has no `openpty(3)`; the `posix_openpt` / `grantpt` / `unlockpt` /
/// `ptsname` sequence it documents is the portable equivalent of what Python's
/// `pty.openpty` did, and works on Linux and macOS alike.
pub struct Pty {
    master: OwnedFd,
    slave: OwnedFd,
}

impl Pty {
    pub fn open() -> io::Result<Self> {
        let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY)?;
        grantpt(&master)?;
        unlockpt(&master)?;
        let path = ptsname(&master, Vec::new())?;
        // `NOCTTY` on the slave too: opening the slave must not hand *this*
        // process a controlling terminal. Only a child that asks for one gets
        // it, through `spawn_on_controlling_terminal`.
        let slave = open(&path, OFlags::RDWR | OFlags::NOCTTY, Mode::empty())?;
        Ok(Self { master, slave })
    }

    /// A pair whose grid is already `size`, the way a launcher starts a guest
    /// PTY at a known geometry.
    pub fn with_size(size: WindowSize) -> io::Result<Self> {
        let pty = Self::open()?;
        pty.set_size(size)?;
        Ok(pty)
    }

    pub fn master(&self) -> BorrowedFd<'_> {
        self.master.as_fd()
    }

    pub fn slave(&self) -> BorrowedFd<'_> {
        self.slave.as_fd()
    }

    /// The size a guest reads with `stty size` / `TIOCGWINSZ`.
    pub fn size(&self) -> io::Result<WindowSize> {
        window_size(self.master.as_fd())
    }

    pub fn set_size(&self, size: WindowSize) -> io::Result<()> {
        set_window_size(self.master.as_fd(), size)
    }
}

// --- Window size ------------------------------------------------------------

/// A terminal's text grid. The pixel fields stay at zero, as they do for every
/// terminal the harness allocates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowSize {
    pub rows: u16,
    pub cols: u16,
}

impl WindowSize {
    pub const fn new(rows: u16, cols: u16) -> Self {
        Self { rows, cols }
    }
}

pub fn window_size(fd: impl AsFd) -> io::Result<WindowSize> {
    let winsize = termios::tcgetwinsize(fd).map_err(io::Error::from)?;
    Ok(WindowSize::new(winsize.ws_row, winsize.ws_col))
}

pub fn set_window_size(fd: impl AsFd, size: WindowSize) -> io::Result<()> {
    termios::tcsetwinsize(
        fd,
        termios::Winsize {
            ws_row: size.rows,
            ws_col: size.cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        },
    )
    .map_err(io::Error::from)
}

// --- Terminal modes ---------------------------------------------------------

/// The terminal's current modes.
pub fn modes(fd: impl AsFd) -> io::Result<Termios> {
    termios::tcgetattr(fd).map_err(io::Error::from)
}

/// Replace the terminal's modes now (`TCSANOW`), which is what a launcher does
/// before forwarding bytes and what it undoes on the way out.
pub fn set_modes(fd: impl AsFd, modes: &Termios) -> io::Result<()> {
    termios::tcsetattr(fd, termios::OptionalActions::Now, modes).map_err(io::Error::from)
}

/// The launcher's raw mode: canonical input, echo, signal keys and extended
/// input processing off, `VMIN = 1`, `VTIME = 0`, and **nothing else changed**.
///
/// This is deliberately not `cfmakeraw(3)`: the historical launcher cleared
/// four local flags and two control codes and left the input, output and
/// control modes alone, so the guest's `\n` still becomes `\r\n` on the way out.
/// Clearing `ICRNL` here would silently rewrite every fixture's output.
pub fn raw(modes: &Termios) -> Termios {
    let mut raw = modes.clone();
    raw.local_modes
        .remove(LocalModes::ICANON | LocalModes::ECHO | LocalModes::ISIG | LocalModes::IEXTEN);
    raw.special_codes[SpecialCodeIndex::VMIN] = 1;
    raw.special_codes[SpecialCodeIndex::VTIME] = 0;
    raw
}

/// Whether `fd` is a terminal, i.e. whether it has modes to change at all.
pub fn is_terminal(fd: impl AsFd) -> bool {
    termios::isatty(fd)
}

// --- Reads with a deadline --------------------------------------------------

/// Wait at most `timeout` for `fd` to become readable.
///
/// `false` means the deadline expired with no data. An interrupted wait
/// (`EINTR`, which a relayed `SIGWINCH` produces) is retried with the time that
/// is left, the way CPython's `select` retries it: a resize must not look like
/// a timeout.
pub fn wait_readable(fd: impl AsFd, timeout: Duration) -> io::Result<bool> {
    let fd = fd.as_fd();
    let deadline = Instant::now() + timeout;
    loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Ok(false);
        };
        let mut fds = [PollFd::new(&fd, PollFlags::IN)];
        match poll(&mut fds, Some(&timespec(remaining))) {
            Ok(0) => return Ok(false),
            Ok(_) => {
                let revents = fds[0].revents();
                if revents.contains(PollFlags::NVAL) {
                    return Err(io::Error::from(Errno::BADF));
                }
                // A descriptor that became readable, or a hangup that is about
                // to read as the end of the stream, are both "read now".
                return Ok(revents.intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR));
            }
            Err(Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

/// Read one chunk within `timeout`: `None` when the deadline expired first.
///
/// A read of zero bytes is the end of the stream. For a pty master that
/// includes its hangup: Linux reports the last slave's close as `EIO`, macOS
/// as a zero-length read, and a caller copying a guest's output treats the two
/// as the same event, so both are reported here as `Some(0)`.
pub fn read_chunk(
    fd: impl AsFd,
    buffer: &mut [u8],
    timeout: Duration,
) -> io::Result<Option<usize>> {
    let fd = fd.as_fd();
    if !wait_readable(fd, timeout)? {
        return Ok(None);
    }
    loop {
        match rustix::io::read(fd, &mut *buffer) {
            Ok(read) => return Ok(Some(read)),
            Err(Errno::IO) => return Ok(Some(0)),
            // A signal between the wait and the read consumed the readiness.
            Err(Errno::AGAIN) => return Ok(None),
            Err(Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

fn timespec(duration: Duration) -> Timespec {
    Timespec {
        tv_sec: duration.as_secs() as i64,
        tv_nsec: duration.subsec_nanos() as i64,
    }
}

// --- Signals ----------------------------------------------------------------

/// Send `signal` to one process.
pub fn send_signal(pid: i32, signal: Signal) -> io::Result<()> {
    let pid = Pid::from_raw(pid).ok_or_else(|| io::Error::from(Errno::INVAL))?;
    process::kill_process(pid, signal).map_err(io::Error::from)
}

/// Send `signal` to every member of a process group: how a launcher stops a
/// guest it started *and* whatever that guest started.
///
/// A signal to the leader's pid reaches only the leader, and a tree whose leader
/// has died has no pid left to name; the group outlives it, so this is the only
/// way to be sure nothing of a launch survives it.
pub fn send_signal_group(group: i32, signal: Signal) -> io::Result<()> {
    let group = Pid::from_raw(group).ok_or_else(|| io::Error::from(Errno::INVAL))?;
    process::kill_process_group(group, signal).map_err(io::Error::from)
}

/// The pid a relayed signal goes to. A handler may not allocate or lock, so the
/// target lives in one atomic and the handler only loads it.
static RELAY_TARGET: AtomicI32 = AtomicI32::new(0);

extern "C" fn relay(number: libc::c_int) {
    let target = RELAY_TARGET.load(Ordering::SeqCst);
    if target > 0 {
        // SAFETY: `kill` is async-signal-safe and the handler does nothing else.
        unsafe { libc::kill(target, number) };
    }
}

/// Forwards one signal to one child for as long as it is alive: a launcher
/// relays the resize *it* receives, because the operator's terminal delivers the
/// signal to the launcher, not to the guest.
///
/// The previous disposition is restored on drop, so a relay cannot outlive the
/// launch that installed it and leave a later signal silently handled.
pub struct SignalRelay {
    number: libc::c_int,
    previous: libc::sigaction,
}

impl SignalRelay {
    pub fn to(pid: i32, signal: Signal) -> io::Result<Self> {
        if Pid::from_raw(pid).is_none() {
            return Err(io::Error::from(Errno::INVAL));
        }
        RELAY_TARGET.store(pid, Ordering::SeqCst);
        let number = signal.as_raw();
        // SAFETY: the action is initialised field by field below and its mask is
        // emptied with `sigemptyset`; `relay` only stores into an atomic and
        // calls `kill`, both async-signal-safe.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = relay as *const () as usize;
            action.sa_flags = 0;
            libc::sigemptyset(&mut action.sa_mask);
            let mut previous: libc::sigaction = std::mem::zeroed();
            if libc::sigaction(number, &action, &mut previous) != 0 {
                RELAY_TARGET.store(0, Ordering::SeqCst);
                return Err(io::Error::last_os_error());
            }
            Ok(Self { number, previous })
        }
    }
}

impl Drop for SignalRelay {
    fn drop(&mut self) {
        RELAY_TARGET.store(0, Ordering::SeqCst);
        // SAFETY: `previous` is the disposition this process had before `to`
        // replaced it, and restoring it is the documented `sigaction` use.
        unsafe { libc::sigaction(self.number, &self.previous, std::ptr::null_mut()) };
    }
}

// --- Pipes ------------------------------------------------------------------

/// A pipe whose ends are close-on-exec, as Python's `os.pipe()` created.
///
/// `rustix::pipe::pipe` does not ask for `CLOEXEC` on macOS, and a guest that
/// inherits the launcher's write end never sees its end of stream: its `read`
/// stays open on a descriptor nobody will write again. Both ends are marked
/// here, and `dup2` still gives a spawned child a working stdin.
pub fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let (reader, writer) = rustix::pipe::pipe()?;
    for fd in [&reader, &writer] {
        rustix::io::fcntl_setfd(fd, rustix::io::FdFlags::CLOEXEC)?;
    }
    Ok((reader, writer))
}

// --- Sessions ---------------------------------------------------------------

/// Spawn `command` as a session leader with no controlling terminal (`setsid`)
/// and `/dev/null` on stdin.
///
/// That is the whole detach contract: an inherited terminal cannot make the
/// child look correct while its own PTY does nothing, and no case can read the
/// operator's keystrokes. stdout and stderr are inherited, as they were.
pub fn spawn_detached(command: &mut Command) -> io::Result<Child> {
    command.stdin(Stdio::null());
    // SAFETY: `setsid` only issues a syscall.
    unsafe {
        command.pre_exec(|| process::setsid().map(|_| ()).map_err(io::Error::from));
    }
    command.spawn()
}

/// Spawn `command` on `terminal` for all three descriptors, with **no**
/// controlling terminal and no new session.
///
/// This is what a PTY launch looks like when the process that spawns it has no
/// controlling terminal itself: the child holds the slave as three plain
/// descriptors. The distinction matters — the kernel sends `SIGWINCH` to the
/// foreground process group of a *session's* terminal, so a child that owns one
/// would observe every resize whether the launcher relayed it or not, and a
/// control could no longer tell a relay from the kernel's own delivery.
pub fn spawn_with_terminal(command: &mut Command, terminal: BorrowedFd<'_>) -> io::Result<Child> {
    command
        .stdin(Stdio::from(terminal.try_clone_to_owned()?))
        .stdout(Stdio::from(terminal.try_clone_to_owned()?))
        .stderr(Stdio::from(terminal.try_clone_to_owned()?));
    command.spawn()
}

/// Spawn `command` in a new session whose controlling terminal is `terminal` on
/// stdin, stdout and stderr: a login session, which is what the detach control
/// has to prove the shim removes, and what makes `/dev/tty` reachable.
///
/// The caller keeps everything else about the command — its working directory,
/// its environment, its arguments — because that is what a launcher's own
/// invocation is.
pub fn spawn_on_controlling_terminal(
    command: &mut Command,
    terminal: BorrowedFd<'_>,
) -> io::Result<Child> {
    command
        .stdin(Stdio::from(terminal.try_clone_to_owned()?))
        .stdout(Stdio::from(terminal.try_clone_to_owned()?))
        .stderr(Stdio::from(terminal.try_clone_to_owned()?));
    // SAFETY: `setsid` and `ioctl(TIOCSCTTY)` only issue syscalls. `setsid`
    // comes first: a process that is a group leader cannot start a session, and
    // only a session leader can adopt a controlling terminal.
    unsafe {
        command.pre_exec(|| {
            process::setsid().map_err(io::Error::from)?;
            process::ioctl_tiocsctty(std::io::stdin()).map_err(io::Error::from)
        });
    }
    command.spawn()
}

// --- Children ---------------------------------------------------------------

/// A child this process owns: waited for with a deadline, and stopped — with the
/// group it leads, when it leads one — if the wait overruns or the owner gives up.
///
/// Both failures are one line away without an owner. A bare `wait` hangs a whole
/// suite when the child hangs, which is how an earlier version of these controls
/// wedged three times; a dropped `Child` leaves a session leader holding a real
/// terminal as `ppid 1` for an operator to find.
pub struct OwnedChild {
    child: Child,
    leads_group: bool,
    reaped: bool,
}

impl OwnedChild {
    /// A child whose signals reach only itself.
    pub fn new(child: Child) -> Self {
        Self {
            child,
            leads_group: false,
            reaped: false,
        }
    }

    /// A child that leads its own process group — spawn it with
    /// `CommandExt::process_group(0)` — so giving up reaches what it started as
    /// well as itself.
    pub fn leading_group(child: Child) -> Self {
        Self {
            child,
            leads_group: true,
            reaped: false,
        }
    }

    pub fn id(&self) -> i32 {
        self.child.id() as i32
    }

    /// Whether it has exited, without reaping it.
    ///
    /// A driver that has to drain a channel while it waits cannot use `finish`:
    /// that would stop reading until the deadline, and a chatty child would block
    /// on a full pipe. Asking for the status and reading are two steps here, and
    /// reaping still happens through `finish` or `stop`.
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        let status = self.child.try_wait()?;
        if status.is_some() {
            self.reaped = true;
        }
        Ok(status)
    }

    /// Wait for it, and kill it when the deadline passes.
    pub fn finish(&mut self, timeout: Duration) -> io::Result<ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    self.reaped = true;
                    return Ok(status);
                }
                Ok(None) => {}
                Err(error) => return Err(error),
            }
            if Instant::now() >= deadline {
                let _ = self.stop();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the child did not exit within its deadline",
                ));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Kill and reap this child alone, leaving anything it started running.
    ///
    /// That is what "the launcher died" has to look like to a control: the guest
    /// only sees its end of stream, and only then reports, when the process
    /// holding the other end is gone. Giving up on the *control* is the different
    /// case, and that is the one `Drop` stops as a group.
    pub fn stop(&mut self) -> io::Result<ExitStatus> {
        self.reaped = true;
        let _ = self.child.kill();
        self.child.wait()
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        // The group first, while the leader still holds its id: a signal to a
        // reaped pid could name somebody else's group. A child spawned without
        // its own group shares this process's, which must not be signalled.
        if self.leads_group {
            let _ = send_signal_group(self.id(), Signal::KILL);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The status a wrapper exits with to reproduce its child's own, as Python's
/// `sys.exit(subprocess.run(...).returncode)` did: an exit code unchanged, a
/// signalled child as the negative signal number, which the process exit status
/// truncates to `256 - N` (`SIGTERM` reads as 241).
pub fn propagate_exit_code(status: ExitStatus) -> i32 {
    status
        .code()
        .unwrap_or_else(|| -status.signal().unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    fn shell(script: &str) -> Command {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", script]);
        command
    }

    #[test]
    fn a_pipe_end_is_close_on_exec() {
        let (reader, writer) = pipe().expect("create a pipe");
        for fd in [&reader, &writer] {
            let flags = rustix::io::fcntl_getfd(fd).expect("read the descriptor flags");
            assert!(
                flags.contains(rustix::io::FdFlags::CLOEXEC),
                "a pipe end would leak into a guest"
            );
        }
    }

    #[test]
    fn a_pty_reports_the_size_it_was_given() {
        let pty = Pty::with_size(WindowSize::new(43, 119)).expect("open a pseudoterminal");
        assert_eq!(pty.size().expect("read the size"), WindowSize::new(43, 119));
        assert_eq!(
            window_size(pty.slave()).expect("read the size from the slave"),
            WindowSize::new(43, 119)
        );
        pty.set_size(WindowSize::new(24, 80)).expect("set the size");
        assert_eq!(pty.size().expect("read the size"), WindowSize::new(24, 80));
        assert!(is_terminal(pty.slave()));
    }

    #[test]
    fn raw_changes_only_the_four_local_flags_and_the_two_codes() {
        let pty = Pty::open().expect("open a pseudoterminal");
        let saved = modes(pty.slave()).expect("read the modes");
        let raw = raw(&saved);
        assert_eq!(raw.input_modes, saved.input_modes);
        assert_eq!(raw.output_modes, saved.output_modes);
        assert_eq!(raw.control_modes, saved.control_modes);
        for flag in [
            LocalModes::ICANON,
            LocalModes::ECHO,
            LocalModes::ISIG,
            LocalModes::IEXTEN,
        ] {
            assert!(!raw.local_modes.contains(flag), "{flag:?} survived raw");
        }
        assert_eq!(raw.special_codes[SpecialCodeIndex::VMIN], 1);
        assert_eq!(raw.special_codes[SpecialCodeIndex::VTIME], 0);
    }

    #[test]
    fn raw_mode_round_trips_through_the_terminal() {
        let pty = Pty::open().expect("open a pseudoterminal");
        let saved = modes(pty.slave()).expect("read the modes");
        let raw = raw(&saved);
        set_modes(pty.slave(), &raw).expect("set raw mode");
        let observed = modes(pty.slave()).expect("read the modes back");
        assert_eq!(observed.local_modes, raw.local_modes);
        assert_eq!(observed.special_codes[SpecialCodeIndex::VMIN], 1);
        assert_eq!(observed.special_codes[SpecialCodeIndex::VTIME], 0);

        set_modes(pty.slave(), &saved).expect("restore the modes");
        let restored = modes(pty.slave()).expect("read the restored modes");
        // `PENDIN` is the kernel's transient "input pending re-print" bit and is
        // not part of what a restore writes, so it is masked out.
        let settle = |modes: &Termios| {
            let mut modes = modes.clone();
            modes.local_modes.remove(LocalModes::PENDIN);
            modes.local_modes
        };
        assert_eq!(settle(&restored), settle(&saved));
        assert_eq!(
            restored.special_codes[SpecialCodeIndex::VMIN],
            saved.special_codes[SpecialCodeIndex::VMIN]
        );
    }

    #[test]
    fn a_read_returns_data_and_then_times_out() {
        let Pty { master, slave } = Pty::open().expect("open a pseudoterminal");
        let mut buffer = [0u8; 64];
        assert_eq!(
            read_chunk(&master, &mut buffer, Duration::from_millis(50))
                .expect("an idle read is not an error"),
            None
        );
        // A child on the slave writes one line; the master reads it, then waits
        // for more and times out rather than blocking.
        let mut child = spawn_with_terminal(&mut shell("echo ready"), slave.as_fd())
            .expect("spawn on the pseudoterminal");
        let read = read_chunk(&master, &mut buffer, Duration::from_secs(10))
            .expect("read the child's line")
            .expect("the child wrote");
        assert_eq!(&buffer[..read], b"ready\r\n");
        child.wait().expect("reap the child");
        // This process's own slave is what keeps the stream open, so the hangup
        // only exists once it is closed as well.
        drop(slave);
        assert_eq!(
            read_chunk(&master, &mut buffer, Duration::from_secs(5))
                .expect("a hangup is not an error"),
            Some(0)
        );
    }

    #[test]
    fn the_last_close_reads_as_the_end_of_the_stream() {
        let Pty { master, slave } = Pty::open().expect("open a pseudoterminal");
        assert!(is_terminal(&slave));
        // The *last* open slave is what closes the stream: Linux reports the
        // read as `EIO`, macOS as zero bytes.
        drop(slave);
        let mut buffer = [0u8; 16];
        assert_eq!(
            read_chunk(&master, &mut buffer, Duration::from_secs(5))
                .expect("a hangup reads as the end, not as an error"),
            Some(0)
        );
    }

    #[test]
    fn a_session_leader_has_no_controlling_terminal_and_no_stdin() {
        // Each failure has its own status, so the message says which property
        // broke: /dev/tty reachable (1), stdin is a terminal (2), stdin is not
        // at its end of file (3).
        let mut child = spawn_detached(&mut shell(
            "( : </dev/tty ) 2>/dev/null && exit 1; \
             test -t 0 && exit 2; \
             read -r _line && exit 3; \
             exit 0",
        ))
        .expect("spawn a session leader");
        let status = child.wait().expect("reap the session leader");
        assert_eq!(status.code(), Some(0), "session leader: {status}");
    }

    #[test]
    fn a_controlling_terminal_child_can_open_dev_tty() {
        let pty = Pty::open().expect("open a pseudoterminal");
        let mut child = spawn_on_controlling_terminal(
            &mut shell("( : </dev/tty ) 2>/dev/null; echo \"tty=$?\"; test -t 0; echo \"tty0=$?\""),
            pty.slave(),
        )
        .expect("spawn on the pseudoterminal");
        let mut seen = Vec::new();
        let mut buffer = [0u8; 64];
        while let Some(read) = read_chunk(pty.master(), &mut buffer, Duration::from_secs(10))
            .expect("read the child's output")
        {
            if read == 0 {
                break;
            }
            seen.extend_from_slice(&buffer[..read]);
        }
        child.wait().expect("reap the child");
        let text = String::from_utf8_lossy(&seen);
        assert!(text.contains("tty=0"), "{text:?}");
        assert!(text.contains("tty0=0"), "{text:?}");
    }

    #[test]
    fn a_relay_forwards_the_signal_to_its_target() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "sleep 30"])
            .spawn()
            .expect("spawn the relay target");
        let relay = SignalRelay::to(child.id() as i32, Signal::TERM).expect("install the relay");
        send_signal(process::getpid().as_raw_pid(), Signal::TERM).expect("signal this process");
        // The handler forwarded it instead of dying: this process is still here
        // and its child took the signal.
        let status = child.wait().expect("reap the relayed child");
        assert_eq!(status.signal(), Some(Signal::TERM.as_raw()));
        drop(relay);
    }

    #[test]
    fn a_group_signal_reaches_every_member_and_not_the_caller() {
        // The child leads its own group and gives it a grandchild; signalling the
        // group is the only call that reaches both.
        let mut child = Command::new("/bin/sh")
            .args(["-c", "/bin/sh -c 'sleep 30' & sleep 30"])
            .process_group(0)
            .spawn()
            .expect("spawn a group leader");
        let group = child.id() as i32;
        // Wait for the grandchild to exist, so the group is not empty when it is
        // signalled.
        assert!(
            await_group(group, |members| members >= 2),
            "the group never grew"
        );
        send_signal_group(group, Signal::TERM).expect("signal the group");
        let status = child.wait().expect("reap the group leader");
        assert_eq!(status.signal(), Some(Signal::TERM.as_raw()));
        // The grandchild is gone too, and this process — which is not in the
        // group — is still here to say so.
        assert!(
            await_group(group, |members| members == 0),
            "a group member survived"
        );
    }

    /// How many live processes are in `group`.
    fn group_members(group: i32) -> usize {
        let output = Command::new("ps")
            .args(["-A", "-o", "pgid="])
            .output()
            .expect("list process groups");
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| line.trim() == group.to_string())
            .count()
    }

    /// Wait for the group to satisfy `predicate`, and report whether it did. The
    /// deadline is the point: a control that waits on a process without one is a
    /// control an operator has to come and kill.
    fn await_group(group: i32, predicate: impl Fn(usize) -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !predicate(group_members(group)) {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        true
    }

    #[test]
    fn a_wait_that_overruns_kills_the_child_it_waited_for() {
        let child = Command::new("/bin/sh")
            .args(["-c", "sleep 30"])
            .spawn()
            .expect("spawn a child that outlives the deadline");
        let pid = Pid::from_raw(child.id() as i32).expect("a pid");
        let mut owned = OwnedChild::new(child);
        let error = owned
            .finish(Duration::from_millis(200))
            .expect_err("the child outlives the deadline");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(
            process::test_kill_process(pid).is_err(),
            "the child survived its deadline"
        );
    }

    #[test]
    fn giving_up_on_a_child_stops_the_group_it_leads() {
        let child = Command::new("/bin/sh")
            .args(["-c", "/bin/sh -c 'sleep 30' & sleep 30"])
            .process_group(0)
            .spawn()
            .expect("spawn a group leader");
        let group = child.id() as i32;
        assert!(
            await_group(group, |members| members >= 2),
            "the group never grew"
        );
        drop(OwnedChild::leading_group(child));
        // The grandchild is what a dropped `Child` leaves behind as `ppid 1`.
        assert!(
            await_group(group, |members| members == 0),
            "a group member survived its owner"
        );
    }

    #[test]
    fn a_signalled_child_propagates_as_its_negative_signal_number() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "exit 7"])
            .spawn()
            .expect("spawn an exiting child");
        assert_eq!(propagate_exit_code(child.wait().expect("reap")), 7);
        let mut child = Command::new("/bin/sh")
            .args(["-c", "kill -TERM $$"])
            .spawn()
            .expect("spawn a signalled child");
        assert_eq!(
            propagate_exit_code(child.wait().expect("reap")),
            -Signal::TERM.as_raw()
        );
    }
}
