//! Deterministic checkpoint/fault control for `image_acquire`'s debug-only
//! acquisition gate.
//!
//! The production side (behind `cfg(debug_assertions)` and the
//! `AGENT_VM_TEST_ACQUIRE_GATE` socket) reports *stages only* — never a
//! reference, path or credential — and blocks until this parent replies. That
//! lets a two-process test order a success precisely against a peer's native
//! failure or postvalidation failure instead of guessing with sleeps.
//!
//! Every wait is bounded: a missing or malformed handshake fails the test
//! rather than passing it. A panicking or timing-out test releases/joins its
//! children (`Peer`) and the socket is removed by `AcquisitionGate::drop`.

// Not every seam helper is used by every test binary that includes this module.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::Duration;

/// One checkpoint the production acquisition routine reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquisitionStage {
    PublicationContended,
    BeforeLock,
    LockContended,
    Snapshot,
    CacheHit,
    CacheValidated,
    NativeOk,
    CanonicalReadback,
    Receipt,
    BeforeRestore,
    AfterRestore,
    BeforeSdkConsume,
    CreateReturned,
}

impl AcquisitionStage {
    fn wire(self) -> &'static str {
        match self {
            Self::PublicationContended => "publication-contended",
            Self::BeforeLock => "before-lock",
            Self::LockContended => "lock-contended",
            Self::Snapshot => "snapshot",
            Self::CacheHit => "cache-hit",
            Self::CacheValidated => "cache-validated",
            Self::NativeOk => "native-ok",
            Self::CanonicalReadback => "canonical-readback",
            Self::Receipt => "receipt",
            Self::BeforeRestore => "before-restore",
            Self::AfterRestore => "after-restore",
            Self::BeforeSdkConsume => "before-sdk-consume",
            Self::CreateReturned => "create-returned",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        [
            Self::PublicationContended,
            Self::BeforeLock,
            Self::LockContended,
            Self::Snapshot,
            Self::CacheHit,
            Self::CacheValidated,
            Self::NativeOk,
            Self::CanonicalReadback,
            Self::Receipt,
            Self::BeforeRestore,
            Self::AfterRestore,
            Self::BeforeSdkConsume,
            Self::CreateReturned,
        ]
        .into_iter()
        .find(|stage| stage.wire() == text)
    }
}

/// The reply a blocked checkpoint receives. `FailValidation`/`FailRestore` are
/// only accepted at their matching stage by the production gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateReply {
    Continue,
    FailValidation,
    FailRestore,
}

impl GateReply {
    fn wire(self) -> &'static str {
        match self {
            Self::Continue => "continue",
            Self::FailValidation => "fail-validation",
            Self::FailRestore => "fail-restore",
        }
    }
}

/// How long one handshake or one child may take before the test fails.
const BOUND: Duration = Duration::from_secs(60);

/// The parent-owned listener. Renamed from the process id so two tests in one
/// binary never share a socket.
pub struct AcquisitionGate {
    path: PathBuf,
    received: Receiver<UnixStream>,
    stop: std::sync::Arc<AtomicBool>,
    acceptor: Option<std::thread::JoinHandle<()>>,
}

impl AcquisitionGate {
    /// Bind a fresh socket inside `dir` (test-owned; the path must stay short
    /// enough for `sockaddr_un`).
    pub fn new(dir: &Path) -> Self {
        std::fs::create_dir_all(dir).expect("create the gate directory");
        // Unique per gate *and* per test process: two gates in one test binary
        // must never share a socket path.
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let path = dir.join(format!(
            "g{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind the acquisition gate socket");
        listener
            .set_nonblocking(true)
            .expect("nonblocking gate listener");
        let (sender, received) = std::sync::mpsc::channel();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&stop);
        let acceptor = std::thread::spawn(move || {
            while !flag.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream.set_nonblocking(false).expect("blocking gate stream");
                        stream
                            .set_read_timeout(Some(BOUND))
                            .expect("bounded gate read");
                        stream
                            .set_write_timeout(Some(BOUND))
                            .expect("bounded gate write");
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

    /// Point `command` at this gate.
    pub fn attach(&self, command: &mut Command) {
        command.env("AGENT_VM_TEST_ACQUIRE_GATE", &self.path);
    }

    /// Block until the child reports `stage`, then return the paused checkpoint.
    pub fn expect(&mut self, stage: AcquisitionStage) -> Checkpoint {
        let stream = match self.received.recv_timeout(BOUND) {
            Ok(stream) => stream,
            Err(error) => panic!("no `{}` checkpoint arrived: {error}", stage.wire()),
        };
        let mut line = String::new();
        BufReader::new(stream.try_clone().expect("clone the gate stream"))
            .read_line(&mut line)
            .expect("read the checkpoint line");
        let observed = line.trim();
        let observed = AcquisitionStage::parse(observed)
            .unwrap_or_else(|| panic!("malformed acquisition stage {observed:?}"));
        assert_eq!(
            observed,
            stage,
            "expected the `{}` checkpoint, got `{}`",
            stage.wire(),
            observed.wire()
        );
        Checkpoint { stream }
    }

    /// Advance through checkpoints, releasing each with `Continue`, until `stage`
    /// arrives.
    ///
    /// Only for stages whose *predecessors* are implementation detail a test must
    /// not depend on (e.g. a repair that may or may not have needed a write). The
    /// number of intermediate checkpoints is bounded, so a stage that never
    /// arrives fails instead of hanging.
    pub fn expect_eventually(&mut self, stage: AcquisitionStage) -> Checkpoint {
        for _ in 0..32 {
            let stream = match self.received.recv_timeout(BOUND) {
                Ok(stream) => stream,
                Err(error) => panic!("no `{}` checkpoint arrived: {error}", stage.wire()),
            };
            let mut line = String::new();
            BufReader::new(stream.try_clone().expect("clone the gate stream"))
                .read_line(&mut line)
                .expect("read the checkpoint line");
            let observed = line.trim();
            let observed = AcquisitionStage::parse(observed)
                .unwrap_or_else(|| panic!("malformed acquisition stage {observed:?}"));
            let checkpoint = Checkpoint { stream };
            if observed == stage {
                return checkpoint;
            }
            checkpoint.reply(GateReply::Continue);
        }
        panic!("`{}` never arrived", stage.wire());
    }

    /// Assert that no further checkpoint is pending within `within`. Used to
    /// prove a peer attempted no restore.
    pub fn expect_none(&mut self, within: Duration) {
        match self.received.recv_timeout(within) {
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {}
            Ok(stream) => {
                let mut line = String::new();
                let _ = BufReader::new(stream).read_line(&mut line);
                panic!("unexpected acquisition checkpoint {:?}", line.trim());
            }
        }
    }
}

impl Drop for AcquisitionGate {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(acceptor) = self.acceptor.take() {
            let _ = acceptor.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

/// One paused checkpoint. Dropping it without a reply is a child-side gate
/// error, so a test panic cannot leave a child blocked forever.
pub struct Checkpoint {
    stream: UnixStream,
}

impl Checkpoint {
    /// Release the paused child (or inject a stage-matched fault).
    pub fn reply(self, reply: GateReply) {
        let mut stream = self.stream;
        writeln!(stream, "{}", reply.wire()).expect("write the gate reply");
        stream.flush().expect("flush the gate reply");
        let _ = stream.shutdown(Shutdown::Both);
    }
}

/// A spawned CLI child that is killed and reaped if the test panics first.
pub struct Peer {
    child: Option<Child>,
}

impl Peer {
    /// Spawn `agent-vm <args>` with `command` attached to `gate`.
    pub fn spawn(command: Command, gate: &AcquisitionGate, args: &[&str]) -> Self {
        let mut command = command;
        gate.attach(&mut command);
        let child = command
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn the acquisition peer");
        Self { child: Some(child) }
    }

    /// Wait (bounded) for the child and return its output.
    pub fn wait(mut self) -> Output {
        let child = self.child.take().expect("peer already collected");
        let id = child.id();
        let (sender, receiver) = std::sync::mpsc::channel();
        let task = std::thread::spawn(move || {
            let _ = sender.send(child.wait_with_output().expect("wait for the peer"));
        });
        match receiver.recv_timeout(BOUND) {
            Ok(output) => {
                task.join().expect("peer collection thread");
                output
            }
            Err(_) => {
                unsafe {
                    libc::kill(id as i32, libc::SIGKILL);
                }
                task.join().expect("peer collection thread");
                panic!("the acquisition peer exceeded {}s", BOUND.as_secs());
            }
        }
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Assert the launcher guard at `lock` is held by another process, by taking a
/// real nonblocking `flock` on an independently opened descriptor.
pub fn assert_guard_held(lock: &Path) {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock)
        .unwrap_or_else(|error| panic!("open the guard {}: {error}", lock.display()));
    match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
        Err(rustix::io::Errno::WOULDBLOCK) => {}
        Ok(()) => panic!("{} was not held", lock.display()),
        Err(error) => panic!("probe {}: {error}", lock.display()),
    }
}

/// Assert the launcher guard at `lock` is currently free.
pub fn assert_guard_free(lock: &Path) {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock)
        .unwrap_or_else(|error| panic!("open the guard {}: {error}", lock.display()));
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .unwrap_or_else(|error| panic!("{} stayed held: {error}", lock.display()));
}

/// The launcher guard's path for `reference`: the native metadata path with the
/// documented `agent-vm-acquire` extension, derived from the actual cache.
pub fn guard_path(cache: &microsandbox_image::GlobalCache, reference: &str) -> PathBuf {
    cache
        .image_metadata_path(&reference.parse().expect("native reference"))
        .with_extension("agent-vm-acquire.lock")
}
