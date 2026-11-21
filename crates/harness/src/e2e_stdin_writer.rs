//! The row-owned FIFO writer for streamed stdin (#700, from #399).
//!
//! A direct-launch stdin row needs a FIFO whose **write end only the row can
//! close**: `close` writes the payload and closes at once (so the guest sees
//! EOF), and `hold` keeps the write end open so a guest that must observe a
//! *live* stdin really does. The row records the PID and kills it on every path
//! out; a forgotten writer keeps a guest's stdin open forever and turns the row
//! into a timeout, which is why the ownership stays in the shell and only the
//! blocking part lives here.
//!
//! Two properties keep a *failed* row from blocking:
//!
//! * the FIFO is opened `O_WRONLY|O_NONBLOCK` and `ENXIO` is retried under a
//!   deadline, so the worker never blocks in `open` waiting for a launcher that
//!   already died;
//! * the readiness receipt is written **before** the open, so the row proceeds on
//!   a receipt that proves this process is running — never on a `sleep` race
//!   (bash 3.2 has no `BASHPID`; #399 N2).
//!
//! `hold`'s stop path (a signal from the row) is covered by `tests/cli.rs`: it
//! needs a process to kill, which a control inside this process cannot provide.

use std::{
    fs,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use clap::Args;
use rustix::{
    fs::{Mode, OFlags, open},
    io::Errno,
};

/// How long the open retries wait between attempts. Slow enough that a failing
/// row does not spin, fast enough that the handshake is not a schedule.
const RETRY_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Debug, Args)]
pub struct E2eStdinWriterArgs {
    /// The FIFO to write.
    #[arg(long, value_name = "PATH", required_unless_present = "self_test")]
    fifo: Option<PathBuf>,

    /// `close` writes the payload and closes (the guest's EOF); `hold` keeps the
    /// write end open until the row kills this process.
    #[arg(long, value_name = "MODE", required_unless_present = "self_test")]
    mode: Option<String>,

    /// The bytes to write once a reader has opened the FIFO.
    #[arg(long, value_name = "TEXT", default_value = "")]
    payload: String,

    /// Receipt written before the open, so the row can start without a race.
    #[arg(long, value_name = "PATH", required_unless_present = "self_test")]
    ready: Option<PathBuf>,

    /// Seconds to keep retrying the open for a reader.
    #[arg(long, value_name = "SECONDS", default_value_t = 30)]
    timeout: u64,

    /// Run the boot-free controls for the writer.
    #[arg(long)]
    self_test: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriterMode {
    Close,
    Hold,
}

impl WriterMode {
    fn parse(text: &str) -> Result<Self, String> {
        match text {
            "close" => Ok(Self::Close),
            "hold" => Ok(Self::Hold),
            other => Err(format!("FAIL: unknown stdin writer mode: {other}")),
        }
    }
}

pub fn run(args: E2eStdinWriterArgs) -> Result<crate::Outcome, String> {
    if args.self_test {
        self_test()?;
        return Ok(crate::Outcome::Report(
            "e2e stdin-writer controls passed".to_owned(),
        ));
    }
    let fifo = args.fifo.ok_or("--fifo PATH is required")?;
    let ready = args.ready.ok_or("--ready PATH is required")?;
    let mode = WriterMode::parse(&args.mode.ok_or("--mode MODE is required")?)?;
    write_fifo(
        &fifo,
        &args.payload,
        mode,
        &ready,
        Duration::from_secs(args.timeout),
    )
    .map_err(|error| format!("FAIL: {error}"))?;
    Ok(crate::Outcome::Exit(0))
}

/// The whole worker: receipt, non-blocking open under a deadline, payload, then
/// EOF (`close`) or an open write end forever (`hold`).
fn write_fifo(
    fifo: &Path,
    payload: &str,
    mode: WriterMode,
    ready: &Path,
    timeout: Duration,
) -> Result<(), String> {
    fs::write(ready, b"ready").map_err(|error| {
        format!(
            "cannot write the readiness receipt {}: {error}",
            ready.display()
        )
    })?;

    let descriptor = open_writer(fifo, timeout).map_err(|error| {
        format!(
            "{error}\n    no launcher opened the FIFO's read end within {}s",
            timeout.as_secs()
        )
    })?;
    write_payload(&descriptor, payload.as_bytes())?;
    if mode == WriterMode::Hold {
        loop {
            thread::park();
        }
    }
    drop(descriptor);
    Ok(())
}

fn open_writer(fifo: &Path, timeout: Duration) -> Result<rustix::fd::OwnedFd, String> {
    let deadline = Instant::now() + timeout;
    loop {
        match open(fifo, OFlags::WRONLY | OFlags::NONBLOCK, Mode::empty()) {
            // ENXIO is "no reader has opened it yet", which is a retry, not a
            // failure; anything else is a real problem with the FIFO.
            Err(Errno::NXIO) if Instant::now() < deadline => thread::sleep(RETRY_INTERVAL),
            Err(error) => return Err(format!("cannot open {}: {error}", fifo.display())),
            // The FIFO becomes a blocking stream once a reader exists: the
            // payload may be larger than the pipe buffer, and the guest draining
            // it is the transfer this writer exists to perform.
            Ok(descriptor) => {
                rustix::fs::fcntl_setfl(&descriptor, OFlags::empty())
                    .map_err(|error| format!("cannot make {} blocking: {error}", fifo.display()))?;
                return Ok(descriptor);
            }
        }
    }
}

fn write_payload(descriptor: &std::os::fd::OwnedFd, payload: &[u8]) -> Result<(), String> {
    let mut remaining = payload;
    while !remaining.is_empty() {
        match rustix::io::write(descriptor, remaining) {
            Ok(0) => return Err("the FIFO stopped accepting bytes".to_owned()),
            Ok(written) => remaining = &remaining[written..],
            Err(error) => return Err(format!("cannot write the payload: {error}")),
        }
    }
    Ok(())
}

fn self_test() -> Result<(), String> {
    let scratch = crate::scratch::Scratch::new("e2e-stdin-writer")
        .map_err(|error| format!("cannot create the control directory: {error}"))?;
    let fifo = scratch.path().join("stdin.fifo");
    mkfifo(&fifo)?;

    // No reader: the open must give up at its own deadline with the message the
    // row prints, and it must leave the receipt behind (that receipt is what
    // proves the process started).
    let ready = scratch.path().join("no-reader.ready");
    let started = Instant::now();
    let error = write_fifo(
        &fifo,
        "",
        WriterMode::Close,
        &ready,
        Duration::from_millis(150),
    )
    .err()
    .ok_or("the writer blocked instead of failing without a reader")?;
    if !error.contains("no launcher opened the FIFO's read end") {
        return Err(format!(
            "a readerless writer failed without its message: {error}"
        ));
    }
    if started.elapsed() > Duration::from_secs(10) {
        return Err(format!(
            "the readerless writer took {:?}, so its deadline did not bound the open",
            started.elapsed()
        ));
    }
    if fs::read(&ready).map_err(|error| error.to_string())? != b"ready" {
        return Err("the readiness receipt was not written before the open".to_owned());
    }

    // A reader that arrives: it must see exactly the payload and then EOF.
    let reader_fifo = fifo.clone();
    let reader = thread::spawn(move || {
        let mut buffer = Vec::new();
        let mut file = fs::File::open(&reader_fifo).map_err(|error| error.to_string())?;
        std::io::Read::read_to_end(&mut file, &mut buffer).map_err(|error| error.to_string())?;
        Ok::<Vec<u8>, String>(buffer)
    });
    // Give the reader a moment to reach its blocking open; the writer retries, so
    // a lost race only costs one retry interval.
    thread::sleep(Duration::from_millis(100));
    write_fifo(
        &fifo,
        "hello",
        WriterMode::Close,
        &ready,
        Duration::from_secs(5),
    )
    .map_err(|error| format!("the close-mode writer failed with a reader: {error}"))?;
    let received = reader
        .join()
        .map_err(|_| "the control's reader panicked".to_owned())??;
    if received != b"hello" {
        return Err(format!("the reader received {received:?}, not the payload"));
    }

    // An unknown mode is refused, not guessed.
    if WriterMode::parse("sometimes").is_ok() {
        return Err("an unknown writer mode was accepted".to_owned());
    }
    Ok(())
}

fn mkfifo(path: &Path) -> Result<(), String> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let name = CString::new(path.as_os_str().as_bytes())
        .map_err(|error| format!("the control FIFO path is not a C string: {error}"))?;
    // SAFETY: `name` is a live NUL-terminated path and the mode is a plain
    // constant; `mkfifo` reads nothing else. rustix exposes no mknod/mkfifo on
    // Apple, which is where the native e2e runs, and the harness already calls
    // libc for the calls rustix does not wrap (`pty`'s sigaction, egress's
    // `kill`).
    if unsafe { libc::mkfifo(name.as_ptr(), 0o600) } == 0 {
        return Ok(());
    }
    Err(format!(
        "cannot create the control FIFO {}: {}",
        path.display(),
        std::io::Error::last_os_error()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stdin_writer_controls_hold() {
        self_test().expect("e2e stdin-writer controls pass");
    }
}
