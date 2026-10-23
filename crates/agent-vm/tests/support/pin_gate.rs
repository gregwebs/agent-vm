//! Test-owned control for the **pin publication** stages of #390.
//!
//! [`crate::image_pin::store`] emits exactly these stage names from its real
//! transaction points, and the debug-only gate is the only reader: a test can
//! order a launch against the moment an approval is committed without a sleep.
//! The stage list is closed here, so production cannot invent a test-only stage
//! or relax the bounded, single-reply handshake after the fact.
//!
//! Guarantees the control itself enforces:
//!
//! - every wait is bounded (60s); a missing or malformed handshake fails the
//!   test rather than silently passing it;
//! - a stage name is parsed against the closed enum, so an unexpected stage is
//!   a test failure, not an ignored line;
//! - a fault reply is only accepted for the stage that describes it
//!   ([`Reply::FailBeforeSave`] at the save stages), so a control cannot inject a
//!   failure at a stage production never offers;
//! - the gate carries stage names only — never a reference, digest, path or
//!   consent value — so it can neither forge content nor grant approval.
//!
//! `PinGate` is `dead_code`-allowed because not every including binary uses it.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::Duration;

/// One publication stage. Ordered as production reaches them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinStage {
    /// The candidate's content is acquired and validated but not approved.
    CandidateReady,
    /// About to open the host pin-store lock.
    BeforePinLock,
    /// Holding the exclusive pin-store lock, before rereading.
    PinLocked,
    /// About to write the journal intent.
    BeforeIntentSave,
    /// The journal intent is durable (atomic rename returned).
    IntentSaved,
    /// The default record was written inside the transaction.
    DefaultSaved,
    /// About to write the final pin store (or its recovery form).
    BeforePinSave,
    /// The transaction committed.
    PinCommitted,
}

impl PinStage {
    fn wire(self) -> &'static str {
        match self {
            Self::CandidateReady => "candidate-ready",
            Self::BeforePinLock => "before-pin-lock",
            Self::PinLocked => "pin-locked",
            Self::BeforeIntentSave => "before-intent-save",
            Self::IntentSaved => "intent-saved",
            Self::DefaultSaved => "default-saved",
            Self::BeforePinSave => "before-pin-save",
            Self::PinCommitted => "pin-committed",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        [
            Self::CandidateReady,
            Self::BeforePinLock,
            Self::PinLocked,
            Self::BeforeIntentSave,
            Self::IntentSaved,
            Self::DefaultSaved,
            Self::BeforePinSave,
            Self::PinCommitted,
        ]
        .into_iter()
        .find(|stage| stage.wire() == text)
    }
}

/// The reply a blocked stage receives. Faults are stage-matched by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    Continue,
    /// Simulate the atomic save failing before it mutates the file. The seam is
    /// the save as a whole, so this covers a rename fault too.
    FailBeforeSave,
}

impl Reply {
    fn wire(self) -> &'static str {
        match self {
            Self::Continue => "continue",
            Self::FailBeforeSave => "fail-before-save",
        }
    }
}

/// How long one handshake or one child may take before the test fails.
const BOUND: Duration = Duration::from_secs(60);

/// The parent-owned listener.
pub struct PinGate {
    path: PathBuf,
    received: Receiver<UnixStream>,
    stop: std::sync::Arc<AtomicBool>,
    acceptor: Option<std::thread::JoinHandle<()>>,
}

impl PinGate {
    /// Bind a fresh socket inside `dir` (test-owned; short enough for
    /// `sockaddr_un`).
    pub fn new(dir: &Path) -> Self {
        std::fs::create_dir_all(dir).expect("create the pin-gate directory");
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let path = dir.join(format!(
            "pg{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind the pin-gate socket");
        listener
            .set_nonblocking(true)
            .expect("nonblocking pin-gate listener");
        let (sender, received) = std::sync::mpsc::channel();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&stop);
        let acceptor = std::thread::spawn(move || {
            while !flag.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream.set_nonblocking(false).expect("blocking pin stream");
                        stream
                            .set_read_timeout(Some(BOUND))
                            .expect("bounded pin read");
                        stream
                            .set_write_timeout(Some(BOUND))
                            .expect("bounded pin write");
                        if sender.send(stream).is_err() {
                            return;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => return,
                }
            }
        });
        Self {
            path,
            received,
            stop,
            acceptor: Some(acceptor),
        }
    }

    /// The socket path, for a direct-emitter control.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Point `command` at this gate.
    pub fn attach(&self, command: &mut Command) {
        command.env("AGENT_VM_TEST_PIN_GATE", &self.path);
    }

    /// Block until the child reports `stage`, then return the paused checkpoint.
    pub fn expect(&mut self, stage: PinStage) -> PinCheckpoint {
        let stream = match self.received.recv_timeout(BOUND) {
            Ok(stream) => stream,
            Err(error) => panic!("no `{}` pin checkpoint arrived: {error}", stage.wire()),
        };
        let mut line = String::new();
        BufReader::new(stream.try_clone().expect("clone the pin gate stream"))
            .read_line(&mut line)
            .expect("read the pin checkpoint line");
        let observed = line.trim();
        let observed =
            PinStage::parse(observed).unwrap_or_else(|| panic!("malformed pin stage {observed:?}"));
        assert_eq!(
            observed,
            stage,
            "expected the `{}` pin checkpoint, got `{}`",
            stage.wire(),
            observed.wire()
        );
        PinCheckpoint { stream }
    }

    /// Assert no further stage is pending within `within`.
    pub fn expect_none(&mut self, within: Duration) {
        match self.received.recv_timeout(within) {
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {}
            Ok(stream) => {
                let mut line = String::new();
                let _ = BufReader::new(stream).read_line(&mut line);
                panic!("unexpected pin checkpoint {:?}", line.trim());
            }
        }
    }
}

impl Drop for PinGate {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(acceptor) = self.acceptor.take() {
            let _ = acceptor.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

/// One paused checkpoint. Dropping it without a reply is a child-side gate
/// error, so a panicking test cannot leave a child blocked forever.
pub struct PinCheckpoint {
    stream: UnixStream,
}

impl PinCheckpoint {
    pub fn reply(self, reply: Reply) {
        let mut stream = self.stream;
        writeln!(stream, "{}", reply.wire()).expect("write the pin reply");
        stream.flush().expect("flush the pin reply");
        let _ = stream.shutdown(Shutdown::Both);
    }
}

/// A spawned CLI child killed and reaped if the test panics first.
pub struct PinPeer {
    child: Option<Child>,
}

impl PinPeer {
    pub fn spawn(command: Command, gate: &PinGate, args: &[&str]) -> Self {
        let mut command = command;
        gate.attach(&mut command);
        let child = command
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn the pin peer");
        Self { child: Some(child) }
    }

    pub fn wait(mut self) -> Output {
        let child = self.child.take().expect("peer already collected");
        let id = child.id();
        let (sender, receiver) = std::sync::mpsc::channel();
        let task = std::thread::spawn(move || {
            let _ = sender.send(child.wait_with_output().expect("wait for the pin peer"));
        });
        match receiver.recv_timeout(BOUND) {
            Ok(output) => {
                task.join().expect("pin peer collection thread");
                output
            }
            Err(_) => {
                unsafe {
                    libc::kill(id as i32, libc::SIGKILL);
                }
                task.join().expect("pin peer collection thread");
                panic!("the pin peer exceeded {}s", BOUND.as_secs());
            }
        }
    }
}

impl Drop for PinPeer {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
