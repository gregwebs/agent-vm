//! Shared pseudo-terminal driver for boot-free interactive tests.
//!
//! Extracted from `secret_pty.rs` so a future approval prompt and the hidden
//! secret prompt run the same harness rather than drifting copies. The helper
//! owns only the terminal: the caller builds and isolates the `Command` (env,
//! cwd, arguments) and names the prompt bytes it waits for. No environment is
//! cleared here and no program-specific prose is hardcoded.
//!
//! Deliberate properties, kept from the original:
//!
//! - The child is **not** a session leader and gets no controlling terminal.
//!   `is_terminal()` only needs the descriptors to be a tty, and on macOS a
//!   session-leader death revokes the slave, which would hide the terminal
//!   state these tests measure.
//! - The terminal flags are captured between `openpty` and `spawn`, so a
//!   restoration assertion compares against the real baseline rather than a
//!   value the child may already have made raw.
//! - Every wait is bounded by the caller's deadline, and `Drop` kills and reaps
//!   a still-running child on every path, including a panic.
//! - Polling includes the `try_wait` check, so a `POLLHUP`-only state (Linux
//!   reports that once the child is gone) cannot spin to the deadline.

#![cfg(unix)]
#![allow(dead_code)]

use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// What the driver does once the prompt is visible.
pub enum Action<'a> {
    /// Write these bytes to the child's stdin.
    Write(&'a [u8]),
    /// Deliver this signal to the child.
    Signal(libc::c_int),
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
            return Ok(false);
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EIO) => return Ok(false),
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
        Some(libc::EIO) => Ok(payload.len()),
        _ if error.kind() == io::ErrorKind::Interrupted => Ok(0),
        _ => Err(error),
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

/// A child running against a fresh pty. Both ends stay in the parent so a test
/// can inspect terminal state and any input the child left queued.
pub struct Pty {
    master: OwnedFd,
    slave: OwnedFd,
    child: Option<Child>,
    status: Option<ExitStatus>,
    baseline_flags: libc::tcflag_t,
    prompt: Vec<u8>,
}

impl Drop for Pty {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Pty {
    /// Spawn `command` with a fresh pty on stdin/stdout/stderr and wait for
    /// `prompt` on the master. `prompt` is the caller's expectation; the helper
    /// carries no program-specific text.
    pub fn spawn(command: &mut Command, prompt: &[u8]) -> io::Result<Self> {
        let (master, slave) = open_pty()?;
        let baseline_flags = terminal_user_flags(slave);
        let dup = |fd: RawFd| unsafe { libc::dup(fd) };
        command
            .stdin(unsafe { Stdio::from_raw_fd(dup(slave)) })
            .stdout(unsafe { Stdio::from_raw_fd(dup(slave)) })
            .stderr(unsafe { Stdio::from_raw_fd(dup(slave)) });
        let child = command.spawn()?;
        let master = unsafe { OwnedFd::from_raw_fd(master) };
        let slave = unsafe { OwnedFd::from_raw_fd(slave) };
        set_nonblocking(master.as_raw_fd())?;
        Ok(Self {
            master,
            slave,
            child: Some(child),
            status: None,
            baseline_flags,
            prompt: prompt.to_vec(),
        })
    }

    pub fn id(&self) -> Option<u32> {
        self.child.as_ref().map(|child| child.id())
    }

    /// Whether the child is still running; reaps it if it has exited.
    pub fn is_running(&mut self) -> bool {
        self.reap_if_exited().expect("try_wait the pty child");
        self.child.is_some()
    }

    pub fn baseline_flags(&self) -> libc::tcflag_t {
        self.baseline_flags
    }

    pub fn terminal_flags(&self) -> libc::tcflag_t {
        terminal_user_flags(self.slave.as_raw_fd())
    }

    /// Read anything the child left in the terminal's input queue — what the
    /// caller's shell would receive next.
    pub fn read_leftover(&self) -> Vec<u8> {
        let slave = self.slave.as_raw_fd();
        let mut buffer = [0_u8; 4096];
        let mut pollfd = libc::pollfd {
            fd: slave,
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut pollfd, 1, 200) } <= 0 {
            return Vec::new();
        }
        let read = unsafe { libc::read(slave, buffer.as_mut_ptr().cast(), buffer.len()) };
        if read > 0 {
            buffer[..read as usize].to_vec()
        } else {
            Vec::new()
        }
    }

    /// Block until the terminal attributes return to the recorded baseline.
    pub fn wait_for_restored_terminal(&mut self, deadline: Duration) {
        let start = Instant::now();
        while start.elapsed() <= deadline {
            if self.terminal_flags() == self.baseline_flags {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("the terminal was not restored within {deadline:?}");
    }

    /// Poll until the prompt appears, returning everything read so far.
    pub fn wait_for_prompt(&mut self, deadline: Duration) -> io::Result<Vec<u8>> {
        let fd = self.master.as_raw_fd();
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
            if output.windows(self.prompt.len()).any(|w| w == self.prompt) {
                return Ok(output);
            }
            if self.reap_if_exited()? {
                return Err(io::Error::other(format!(
                    "the child exited before the prompt: {:?}",
                    self.status
                )));
            }
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "the expected prompt did not appear",
        ))
    }

    /// Drive the child: wait for the prompt, perform `action`, then read until
    /// the child exits plus a short final drain. `deadline` bounds the whole
    /// interaction including reaping.
    pub fn drive(
        &mut self,
        action: &Action,
        deadline: Duration,
    ) -> io::Result<(ExitStatus, Vec<u8>)> {
        let fd = self.master.as_raw_fd();
        let start = Instant::now();
        let mut output = Vec::new();
        let mut prompt_seen = false;
        let mut acted = false;
        let mut payload_sent = 0usize;
        while self.child.is_some() {
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
            if !prompt_seen && output.windows(self.prompt.len()).any(|w| w == self.prompt) {
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
                        if let Some(child) = self.child.as_ref() {
                            unsafe { libc::kill(child.id() as libc::pid_t, *signal) };
                        }
                        acted = true;
                    }
                }
            }
            self.reap_if_exited()?;
        }
        self.drain_after_exit(&mut output)?;
        let status = self.status.expect("a reaped child has a status");
        Ok((status, output))
    }

    /// Reap the child within `deadline`, draining output, and return its status.
    pub fn wait_for_exit(
        &mut self,
        output: &mut Vec<u8>,
        deadline: Duration,
    ) -> io::Result<ExitStatus> {
        let fd = self.master.as_raw_fd();
        let start = Instant::now();
        while self.child.is_some() {
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
            self.reap_if_exited()?;
        }
        self.drain_after_exit(output)?;
        Ok(self.status.expect("a reaped child has a status"))
    }

    /// Send the whole payload, retrying only while the master would block. The
    /// child is alive in every caller, so a short retry loop is enough.
    pub fn write_all(&self, payload: &[u8]) {
        let fd = self.master.as_raw_fd();
        let mut sent = 0;
        while sent < payload.len() {
            match write_some(fd, &payload[sent..]) {
                Ok(0) => std::thread::sleep(Duration::from_millis(10)),
                Ok(written) => sent += written,
                Err(error) => panic!("writing to the pty: {error}"),
            }
        }
    }

    fn reap_if_exited(&mut self) -> io::Result<bool> {
        if let Some(child) = self.child.as_mut()
            && let Some(status) = child.try_wait()?
        {
            self.status = Some(status);
            self.child = None;
        }
        Ok(self.child.is_none())
    }

    fn drain_after_exit(&self, output: &mut Vec<u8>) -> io::Result<()> {
        let fd = self.master.as_raw_fd();
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
}
