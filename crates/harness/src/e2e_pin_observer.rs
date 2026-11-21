//! The pins debug-gate observer (#700, from #390).
//!
//! A launch can be told to report every pin stage it reaches over a Unix socket
//! and wait for the answer. The observer is the row's **ordering oracle**: it
//! answers `continue` to every stage, and it holds one named pin stage until the
//! row has looked at the state it wanted to catch — that is how a row proves the
//! SDK had not consumed the approval yet at the moment the pin committed.
//!
//! Two gates, one thread. Both stages arrive on their own socket, the log is
//! appended in arrival order, and a hold blocks the loop exactly as the Python
//! `select` version did: new connections wait in the listen backlog, which is
//! what lets a row hold the pin gate while the acquisition gate stays queued.
//!
//! Every wait is bounded: a connection read is bounded by its own timeout, the
//! hold by its deadline (the row's release file usually ends it long before), and
//! the accept loop by its poll timeout.

use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use clap::Args;
use rustix::event::{PollFd, PollFlags, Timespec, poll};

/// How long a held stage may wait for its release file before the observer
/// answers anyway: a row that died must not leave a launcher waiting forever.
const HOLD_DEADLINE: Duration = Duration::from_secs(90);
/// How long one connection may take to send its stage, and to receive its answer.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);
/// A stage is one short line; anything longer is a client this observer does not
/// serve and must not read forever.
const READ_LIMIT: usize = 4096;
/// How long the observer sleeps before re-reading the gate state, both inside a
/// hold and after an idle poll.
const STEP: Duration = Duration::from_millis(50);
/// The accept loop's poll timeout: long enough to be idle, short enough that a
/// stop request is noticed promptly.
const POLL_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Args)]
pub struct E2ePinObserverArgs {
    /// The pin gate socket to create.
    #[arg(long, value_name = "PATH", required_unless_present = "self_test")]
    pin: Option<PathBuf>,

    /// The acquisition gate socket to create.
    #[arg(long, value_name = "PATH", required_unless_present = "self_test")]
    acquire: Option<PathBuf>,

    /// The stage log the rows read.
    #[arg(long, value_name = "PATH", required_unless_present = "self_test")]
    log: Option<PathBuf>,

    /// The pin stage to hold until --release exists.
    #[arg(long, value_name = "STAGE", default_value = "pin-committed")]
    hold: String,

    /// The file whose appearance releases the held stage.
    #[arg(long, value_name = "PATH", required_unless_present = "self_test")]
    release: Option<PathBuf>,

    /// Run the boot-free controls for the observer.
    #[arg(long)]
    self_test: bool,
}

pub fn run(args: E2ePinObserverArgs) -> Result<crate::Outcome, String> {
    if args.self_test {
        self_test()?;
        return Ok(crate::Outcome::Report(
            "e2e pin-observer controls passed".to_owned(),
        ));
    }
    let observer = Observer {
        hold: args.hold,
        release: args.release.ok_or("--release PATH is required")?,
        log: args.log.ok_or("--log PATH is required")?,
        hold_deadline: HOLD_DEADLINE,
        connect_timeout: CONNECT_TIMEOUT,
    };
    let pin = args.pin.ok_or("--pin PATH is required")?;
    let acquire = args.acquire.ok_or("--acquire PATH is required")?;
    let gates = [("pin", listener(&pin)?), ("acquire", listener(&acquire)?)];
    // The launcher's own exit is what stops an observer in a row; this flag is
    // how the controls stop the same loop in-process.
    let stop = Arc::new(AtomicBool::new(false));
    serve(&observer, &gates, &stop).map_err(|error| format!("FAIL: {error}"))?;
    Ok(crate::Outcome::Exit(0))
}

struct Observer {
    hold: String,
    release: PathBuf,
    log: PathBuf,
    hold_deadline: Duration,
    connect_timeout: Duration,
}

/// Replace any socket file a previous run left behind, then listen. The rows have
/// already removed the paths, but a bind that fails on a stale file would turn a
/// rerun into a mystery.
fn listener(path: &Path) -> Result<UnixListener, String> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!("cannot remove {}: {error}", path.display()));
        }
    }
    let listener = UnixListener::bind(path)
        .map_err(|error| format!("cannot bind {}: {error}", path.display()))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("cannot make {} non-blocking: {error}", path.display()))?;
    Ok(listener)
}

fn serve(
    observer: &Observer,
    gates: &[(&str, UnixListener); 2],
    stop: &Arc<AtomicBool>,
) -> Result<(), String> {
    while !stop.load(Ordering::Relaxed) {
        let mut polled = gates
            .iter()
            .map(|(_, listener)| PollFd::new(listener, PollFlags::IN))
            .collect::<Vec<_>>();
        match poll(&mut polled, Some(&timespec(POLL_TIMEOUT))) {
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(format!("cannot poll the gates: {error}")),
        }
        for ((name, listener), descriptor) in gates.iter().zip(polled.iter()) {
            if !descriptor.revents().contains(PollFlags::IN) {
                continue;
            }
            // Drain the backlog: a held stage queues several connections, and a
            // single accept per wakeup would serialise them behind the poll
            // timeout.
            loop {
                match listener.accept() {
                    // A connection that cannot be served is that client's
                    // problem: the gate's contract is to answer the launcher,
                    // and a row has many connections to make. Returning here
                    // would let one vanished peer, one slow sender or one
                    // closed read end silence both gates for the rest of the
                    // run, and every later query would see an empty answer.
                    Ok((connection, _)) => {
                        if let Err(error) = handle(observer, name, connection) {
                            eprintln!("e2e-pin-observer: {error}");
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => break,
                    Err(error) => {
                        return Err(format!("cannot accept on the {name} gate: {error}"));
                    }
                }
            }
        }
    }
    Ok(())
}

fn handle(observer: &Observer, gate: &str, mut connection: UnixStream) -> Result<(), String> {
    // BSD hands the accepted socket the listener's `O_NONBLOCK` and Linux does
    // not, so on macOS this is a non-blocking socket that must not be read as a
    // blocking one: a stage that has not arrived yet would be `EAGAIN` rather
    // than a wait, and a socket timeout is ignored on a non-blocking socket.
    // Restoring blocking mode here is what lets `connect_timeout` bound the
    // read, and it is the difference between a gate that answers a slow sender
    // and one that dies on it.
    connection
        .set_nonblocking(false)
        .map_err(|error| format!("cannot make the {gate} connection blocking: {error}"))?;
    connection
        .set_read_timeout(Some(observer.connect_timeout))
        .and_then(|()| connection.set_write_timeout(Some(observer.connect_timeout)))
        .map_err(|error| format!("cannot bound the {gate} connection: {error}"))?;
    let stage = read_stage(&mut connection, gate)?;
    append(&observer.log, &format!("{gate} {stage}\n"))?;
    if gate == "pin" && stage == observer.hold {
        hold_until_released(observer)?;
    }
    connection
        .write_all(b"continue\n")
        .map_err(|error| format!("cannot answer the {gate} gate: {error}"))?;
    Ok(())
}

/// One stage per connection: a short line, read in bounded chunks so a client
/// that never sends a newline cannot pin the observer.
fn read_stage(connection: &mut UnixStream, gate: &str) -> Result<String, String> {
    let mut data = Vec::new();
    let mut chunk = [0_u8; 256];
    while !data.ends_with(b"\n") && data.len() < READ_LIMIT {
        let read = connection
            .read(&mut chunk)
            .map_err(|error| format!("cannot read the {gate} gate: {error}"))?;
        if read == 0 {
            break;
        }
        data.extend_from_slice(&chunk[..read]);
    }
    Ok(String::from_utf8_lossy(&data).trim().to_owned())
}

fn hold_until_released(observer: &Observer) -> Result<(), String> {
    let deadline = Instant::now() + observer.hold_deadline;
    while Instant::now() < deadline {
        if observer.release.exists() {
            return Ok(());
        }
        thread::sleep(STEP);
    }
    // The deadline is not an error: the row has already failed to release, and
    // the launcher it is holding still has to get its answer.
    Ok(())
}

/// Appended line-at-a-time: the rows poll this log while the launcher runs, so a
/// buffered write would hide the very ordering they assert on.
fn append(path: &Path, line: &str) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    file.write_all(line.as_bytes())
        .map_err(|error| format!("cannot append to {}: {error}", path.display()))
}

fn timespec(duration: Duration) -> Timespec {
    Timespec {
        tv_sec: duration.as_secs() as i64,
        tv_nsec: duration.subsec_nanos() as i64,
    }
}

fn self_test() -> Result<(), String> {
    let scratch = crate::scratch::Scratch::new("e2e-pin-observer")
        .map_err(|error| format!("cannot create the control directory: {error}"))?;
    let pin = scratch.path().join("pin.sock");
    let acquire = scratch.path().join("acquire.sock");
    let log = scratch.path().join("gate.log");
    let release = scratch.path().join("release");
    let observer = Observer {
        hold: "pin-committed".to_owned(),
        release: release.clone(),
        log: log.clone(),
        // Long enough that the released case cannot be the deadline, short enough
        // that the deadline case is a second rather than a minute.
        hold_deadline: Duration::from_millis(1200),
        // A second bounds a silent client without being tight enough for a
        // local write that is already buffered when the gate accepts it.
        connect_timeout: Duration::from_millis(1000),
    };
    let gates = [("pin", listener(&pin)?), ("acquire", listener(&acquire)?)];
    let stop = Arc::new(AtomicBool::new(false));
    let running = Arc::clone(&stop);
    // Held as a plain duration too: the closure below owns the observer.
    let hold_deadline = observer.hold_deadline;
    let connect_timeout = observer.connect_timeout;
    let server = thread::spawn(move || serve(&observer, &gates, &running));
    wait_for_sockets(&[pin.clone(), acquire.clone()])?;

    // A query that is not the held stage is answered immediately and logged.
    let started = Instant::now();
    if ask(&acquire, "acquire-start")? != "continue" {
        return Err("the acquisition gate answered something other than continue".to_owned());
    }
    if started.elapsed() > Duration::from_secs(1) {
        return Err(format!(
            "an unheld stage took {:?} to answer",
            started.elapsed()
        ));
    }

    // The hold ends when the row releases it, and the answer is still `continue`.
    let releaser = thread::spawn({
        let release = release.clone();
        move || {
            thread::sleep(Duration::from_millis(150));
            fs::write(&release, b"go")
                .map_err(|error| format!("cannot write {}: {error}", release.display()))
        }
    });
    let started = Instant::now();
    if ask(&pin, "pin-committed")? != "continue" {
        return Err("the held pin stage answered something other than continue".to_owned());
    }
    let released_after = started.elapsed();
    releaser
        .join()
        .map_err(|_| "the control's releaser panicked".to_owned())??;
    if released_after >= hold_deadline {
        return Err(format!(
            "the held stage answered after {released_after:?}, so the release file was not what released it"
        ));
    }

    // With no release, the deadline still answers: a row that failed to release
    // must not leave a launcher waiting forever.
    fs::remove_file(&release).map_err(describe)?;
    let started = Instant::now();
    if ask(&pin, "pin-committed")? != "continue" {
        return Err(
            "the held stage answered after its deadline with something other than continue"
                .to_owned(),
        );
    }
    if started.elapsed() < hold_deadline {
        return Err(format!(
            "the held stage answered after {:?}, before its own deadline",
            started.elapsed()
        ));
    }

    // A stage that is not the held one never waits, even on the pin gate.
    let started = Instant::now();
    ask(&pin, "pin-requested")?;
    if started.elapsed() > Duration::from_secs(1) {
        return Err(format!("a non-held pin stage took {:?}", started.elapsed()));
    }

    // A sender that pauses between its two writes is slow, not broken. BSD hands
    // the accepted socket the listener's non-blocking flag, so the gate's first
    // read lands before the rest of this line and has to wait for it: read as a
    // non-blocking socket, that wait is `EAGAIN` and the stage is lost.
    let mut slow = UnixStream::connect(&pin)
        .map_err(|error| format!("cannot connect to {}: {error}", pin.display()))?;
    slow.set_nonblocking(false)
        .map_err(|error| format!("cannot make the slow client blocking: {error}"))?;
    slow.write_all(b"pin-sl")
        .map_err(|error| format!("cannot send the first half of the stage: {error}"))?;
    thread::sleep(Duration::from_millis(200));
    slow.write_all(b"ow\n")
        .map_err(|error| format!("cannot send the second half of the stage: {error}"))?;
    let mut slow_answer = String::new();
    slow.read_to_string(&mut slow_answer)
        .map_err(|error| format!("cannot read the slow sender's answer: {error}"))?;
    if slow_answer.trim() != "continue" {
        return Err(format!(
            "a stage that arrived in two writes was answered {:?}",
            slow_answer.trim()
        ));
    }

    // A client that connects and sends nothing holds the gate until its read
    // times out, which must cost that client its answer and nothing else: a row
    // with one rude peer still has to be served.
    let silent = UnixStream::connect(&acquire)
        .map_err(|error| format!("cannot connect to {}: {error}", acquire.display()))?;
    silent
        .set_nonblocking(false)
        .map_err(|error| format!("cannot make the silent client blocking: {error}"))?;
    thread::sleep(connect_timeout + Duration::from_millis(400));
    if ask(&pin, "pin-requested")? != "continue" {
        return Err("the gate stopped answering after a client timed out".to_owned());
    }
    drop(silent);

    let text = fs::read_to_string(&log).map_err(describe)?;
    let expected = "acquire acquire-start\n\
                    pin pin-committed\n\
                    pin pin-committed\n\
                    pin pin-requested\n\
                    pin pin-slow\n\
                    pin pin-requested\n";
    if text != expected {
        return Err(format!("the gate log is {text:?}, want {expected:?}"));
    }

    stop.store(true, Ordering::Relaxed);
    server
        .join()
        .map_err(|_| "the control's observer panicked".to_owned())??;
    Ok(())
}

/// The rows poll for the socket files rather than sleeping; the control does the
/// same, so a bind that failed surfaces as a deadline instead of a connect error.
fn wait_for_sockets(paths: &[PathBuf]) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if paths.iter().all(|path| path.exists()) {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(10));
    }
    Err(format!("the gates did not appear as {paths:?}"))
}

fn ask(path: &Path, stage: &str) -> Result<String, String> {
    let mut connection = UnixStream::connect(path)
        .map_err(|error| format!("cannot connect to {}: {error}", path.display()))?;
    connection
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| format!("cannot bound {}: {error}", path.display()))?;
    connection
        .write_all(format!("{stage}\n").as_bytes())
        .map_err(|error| format!("cannot send {stage}: {error}"))?;
    let mut answer = String::new();
    connection
        .read_to_string(&mut answer)
        .map_err(|error| format!("cannot read the answer to {stage}: {error}"))?;
    let answer = answer.trim().to_owned();
    // A closed peer reads as an empty answer, which would otherwise look like a
    // gate that answered something unexpected.
    if answer.is_empty() {
        return Err(format!(
            "{} closed without answering {stage}",
            path.display()
        ));
    }
    Ok(answer)
}

fn describe(error: std::io::Error) -> String {
    format!("control setup failed: {error}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pin_observer_controls_hold() {
        self_test().expect("e2e pin-observer controls pass");
    }
}
