//! Forward host stdin to a direct command's guest stdin (#399, ADR-0052).
//!
//! A direct launch (`agent-vm run PROGRAM`, `agent-vm -- PROGRAM`) streams when
//! the launch is not a PTY — which since #400 includes a *terminal* host stdin
//! chosen into streaming by a redirected stdout or `--no-tty` (#400). Streamed
//! input is therefore not necessarily non-terminal, though it is always
//! line-disciplined input the launcher has not put into raw mode. The command has
//! exclusive ownership of it: the guest bootstrap puts all setup behind
//! `/dev/null` so the program is the only reader (see `run::GuestInput`). This
//! module is the host half of that promise, and it is not used for a PTY, where
//! the SDK's terminal bridge owns input.
//!
//! The shape is three resources with different lifetimes, and the differences
//! are the design:
//!
//! * a **detached** std thread doing the blocking `read(2)` on host stdin. It is
//!   deliberately not `tokio::io::stdin()`: that reads on the blocking pool,
//!   whose task cannot be cancelled, and `Runtime::drop` waits for blocking
//!   tasks — so a launch that fails while a FIFO writer still holds stdin open
//!   would hang instead of reporting its error (ADR-0052).
//! * a bounded channel of one chunk, so a stalled guest bounds the launcher-side
//!   backlog to roughly three chunks instead of the whole stream. The runtime may
//!   hold further input it already accepted, so this is not an end-to-end bound.
//! * a tokio task (the *pump*) that turns chunks into `ExecStdin` frames. It is
//!   cancellable at every await point, so an exit event is observed while a
//!   read or a guest write is pending.
//!
//! EOF is an **empty** `ExecStdin` frame (`GuestStdin::close`), never a
//! zero-length write, which is why [`InputChunk`] cannot be empty.

use std::future::Future;
use std::io::Read;

use microsandbox::protocol::exec::ExecStdinError;

/// Host read/backlog unit, not a wire-frame size. The SDK subframes writes to
/// `stdin_chunk_size` (16 KiB by default) within a 64 KiB per-exec window;
/// `ExecStdinAck` replenishes credit after delivery into the guest stdin pipe.
const HOST_READ_CHUNK_BYTES: usize = 64 * 1024;

/// Chunks in flight between the reader thread and the pump. One, so a stalled
/// guest bounds the *launcher-side* backlog: one chunk in the reader's hand,
/// one queued, one in a pending write. It bounds nothing beyond the launcher —
/// the runtime may hold further accepted input that an early-closing guest
/// never reads, so there is no end-to-end loss bound.
const HOST_READ_QUEUE_CHUNKS: usize = 1;

/// The Linux guest's `EPIPE`. Not the host's `libc::EPIPE`: the number is
/// reported by agentd from inside the guest.
const GUEST_EPIPE: i32 = 32;

/// Pinned SDK sentinel; the vendor-source guard below requires bump-time review.
const STDIN_CLOSED_SENTINEL: &str = "execution stdin closed";

/// Bytes read from host stdin. Never empty, because an empty `ExecStdin` frame
/// *is* EOF — a zero-length chunk would close the guest's stdin early.
#[derive(Debug)]
pub(crate) struct InputChunk(Vec<u8>);

impl InputChunk {
    /// `None` for empty input, so the EOF frame has exactly one producer.
    fn new(bytes: Vec<u8>) -> Option<Self> {
        (!bytes.is_empty()).then_some(Self(bytes))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// One message from the reader thread. EOF is explicit, so a reader that ends
/// without one (a panic) cannot impersonate it.
enum HostRead {
    Chunk(InputChunk),
    Eof,
    Failed(std::io::Error),
}

/// Where guest stdin bytes go. A seam: [`microsandbox::sandbox::exec::ExecSink`]
/// in production, a gated stub in tests.
///
/// The futures are declared `Send` here rather than relying on the concrete
/// implementation's auto traits: the pump is a generic `tokio::spawn`, and a
/// generic body is checked against these bounds. They borrow `&self`, so
/// implementors are `Sync` too.
pub(crate) trait GuestStdin: Send + Sync + 'static {
    fn write(&self, chunk: &InputChunk) -> impl Future<Output = anyhow::Result<()>> + Send;
    fn close(&self) -> impl Future<Output = anyhow::Result<()>> + Send;
}

impl GuestStdin for microsandbox::sandbox::exec::ExecSink {
    async fn write(&self, chunk: &InputChunk) -> anyhow::Result<()> {
        microsandbox::sandbox::exec::ExecSink::write(self, chunk.as_bytes())
            .await
            .map_err(anyhow::Error::new)
    }

    async fn close(&self) -> anyhow::Result<()> {
        microsandbox::sandbox::exec::ExecSink::close(self)
            .await
            .map_err(anyhow::Error::new)
    }
}

/// Spawns the reader loop. A plain `fn` so a test can inject a spawn failure.
pub(crate) type SpawnReader = fn(Box<dyn FnOnce() + Send + 'static>) -> std::io::Result<()>;

/// Drop the `JoinHandle` on purpose: the thread is detached, because the
/// reader can be parked in `read(2)` for as long as the writer at the other end
/// of the user's pipe keeps it open, and neither `Runtime::drop` nor
/// `process::exit` may wait for that (ADR-0052).
fn spawn_detached_reader(body: Box<dyn FnOnce() + Send + 'static>) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("agent-vm-stdin".into())
        .spawn(body)
        .map(drop)
}

/// The host side of a forwarded input, before anything runs.
pub(crate) struct InputSource<R> {
    reader: R,
    spawn: SpawnReader,
}

impl<R: Read + Send + 'static> InputSource<R> {
    pub(crate) fn new(reader: R) -> Self {
        Self {
            reader,
            spawn: spawn_detached_reader,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_spawner(reader: R, spawn: SpawnReader) -> Self {
        Self { reader, spawn }
    }

    /// Spawn the detached reader over `reader` and the pump over `sink`. Must
    /// run inside a tokio runtime.
    ///
    /// On `Err` nothing is running and no byte has been read: the reader and
    /// `sink` were dropped with the failed spawn. That is what lets the caller
    /// treat a start failure like any other failure and still run one release
    /// sequence (no task to abort, no sink to drop later).
    pub(crate) fn start<S: GuestStdin>(self, sink: S) -> Result<InputPump, InputStartError> {
        let (sender, receiver) = tokio::sync::mpsc::channel(HOST_READ_QUEUE_CHUNKS);
        let reader = self.reader;
        (self.spawn)(Box::new(move || reader_loop(reader, sender))).map_err(InputStartError)?;
        Ok(InputPump {
            task: Some(tokio::spawn(pump(receiver, sink))),
        })
    }
}

fn reader_loop<R: Read>(mut reader: R, sender: tokio::sync::mpsc::Sender<HostRead>) {
    loop {
        let mut buffer = vec![0u8; HOST_READ_CHUNK_BYTES];
        match reader.read(&mut buffer) {
            Ok(0) => {
                let _ = sender.blocking_send(HostRead::Eof);
                return;
            }
            Ok(read) => {
                buffer.truncate(read);
                // Unreachable after the `Ok(0)` arm; the empty-input path is the
                // same one rather than an `expect` in production code.
                let Some(chunk) = InputChunk::new(buffer) else {
                    let _ = sender.blocking_send(HostRead::Eof);
                    return;
                };
                // A closed receiver means the launch already stopped the pump.
                if sender.blocking_send(HostRead::Chunk(chunk)).is_err() {
                    return;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                let _ = sender.blocking_send(HostRead::Failed(error));
                return;
            }
        }
    }
}

async fn pump<S: GuestStdin>(
    mut receiver: tokio::sync::mpsc::Receiver<HostRead>,
    sink: S,
) -> Result<InputEnd, InputFailure> {
    loop {
        match receiver.recv().await {
            Some(HostRead::Chunk(chunk)) => {
                sink.write(&chunk).await.map_err(InputFailure::Transport)?;
            }
            Some(HostRead::Eof) => {
                sink.close().await.map_err(InputFailure::Transport)?;
                return Ok(InputEnd::Eof);
            }
            Some(HostRead::Failed(error)) => return Err(InputFailure::HostRead(error)),
            // The reader ended without EOF: a panic in `read`, never an empty
            // stream, because that would turn truncation into silent success.
            None => return Err(InputFailure::ReaderVanished),
        }
    }
}

/// The reader thread could not be spawned.
#[derive(Debug)]
pub(crate) struct InputStartError(std::io::Error);

impl std::fmt::Display for InputStartError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "starting the host stdin reader failed: {}",
            self.0
        )
    }
}

impl std::error::Error for InputStartError {}

/// How the pump ended on its own.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum InputEnd {
    /// Every host byte was accepted by the transport and guest stdin was
    /// closed. Not an acknowledgement of guest **consumption**: a guest that
    /// exits early leaves whatever the runtime already buffered unread.
    Eof,
}

#[derive(Debug)]
pub(crate) enum InputFailure {
    HostRead(std::io::Error),
    ReaderVanished,
    Transport(anyhow::Error),
    Panicked,
}

impl InputFailure {
    /// Waiting for the guest's own terminal event makes sense only when the
    /// transport may have taken the whole session down with the frame. A host
    /// read error leaves the guest waiting for an EOF that will never come.
    pub(crate) fn awaits_session_end(&self) -> bool {
        matches!(self, Self::Transport(_))
    }

    pub(crate) fn is_stdin_closed(&self) -> bool {
        matches!(self, Self::Transport(error) if is_stdin_closed(error))
    }

    /// Never includes input bytes: they are the user's data.
    pub(crate) fn into_error(self) -> anyhow::Error {
        self.error()
    }

    /// [`Self::into_error`] by reference. The input grace owns its failure
    /// behind a `&mut`, so it renders the error where it expires rather than
    /// moving the record out from under the `select!` arm.
    pub(crate) fn error(&self) -> anyhow::Error {
        match self {
            Self::HostRead(error) => anyhow::anyhow!("reading host stdin failed: {error}"),
            Self::ReaderVanished => anyhow::anyhow!(
                "reading host stdin failed: the host stdin reader stopped before end of input"
            ),
            Self::Transport(error) => {
                anyhow::anyhow!("forwarding stdin to the guest failed: {error:#}")
            }
            Self::Panicked => {
                anyhow::anyhow!("forwarding stdin to the guest failed: the input pump panicked")
            }
        }
    }
}

/// The SDK closes its credit window before enqueueing EPIPE or Exited. Only
/// this exact typed error can be reconciled with those events; transport/EIO
/// failures must remain failures even if the guest subsequently exits.
pub(crate) fn is_stdin_closed(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<microsandbox::MicrosandboxError>(),
        Some(microsandbox::MicrosandboxError::Runtime(detail))
            if detail == STDIN_CLOSED_SENTINEL
    )
}

/// The forwarding of host input to one direct command.
///
/// Owns the pump task and, through it, the sink. It does **not** own the reader
/// thread: [`InputPump::stop`] cancels the task, never a reader parked in
/// `read(2)`.
pub(crate) struct InputPump {
    task: Option<tokio::task::JoinHandle<Result<InputEnd, InputFailure>>>,
}

impl InputPump {
    /// Whether there is still a task to await. A pump whose task has completed
    /// is still "running" here until [`Self::finished`] reports the outcome.
    pub(crate) fn is_running(&self) -> bool {
        self.task.is_some()
    }

    /// Resolve with the pump's outcome; afterwards [`Self::is_running`] is
    /// false. Cancel-safe: it polls the same handle by reference, so a
    /// `select!` that loses the race can poll it again.
    pub(crate) async fn finished(&mut self) -> Result<InputEnd, InputFailure> {
        let Some(task) = self.task.as_mut() else {
            // The caller guards the branch with `is_running`; a pending future
            // keeps that a scheduling detail instead of an `unreachable!`.
            return std::future::pending().await;
        };
        let joined = (&mut *task).await;
        self.task = None;
        match joined {
            Ok(outcome) => outcome,
            // `stop()` is the only canceller and it consumes the handle, so an
            // error here is a lost pump, not a clean end of input.
            Err(_) => Err(InputFailure::Panicked),
        }
    }

    /// Abort and join the pump. Idempotent. Afterwards the sink is dropped.
    ///
    /// Joining is what makes "the sink is gone" a fact the caller can rely on
    /// before it releases the wait future and the exec handle; aborting a pump
    /// blocked in `ExecSink::write` is frame-safe (the runtime's writer task
    /// owns whole frames).
    pub(crate) async fn stop(&mut self) {
        let Some(task) = self.task.take() else {
            return;
        };
        task.abort();
        let _ = task.await;
    }

    /// Test-only: the task has completed, so [`Self::finished`] would resolve
    /// without yielding the runtime.
    #[cfg(test)]
    pub(crate) fn has_completed(&self) -> bool {
        self.task.as_ref().is_some_and(|task| task.is_finished())
    }
}

impl Drop for InputPump {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

/// The runtime's non-terminal `StdinError`, classified.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum GuestInputStatus {
    /// The guest closed its read end (`EPIPE`): expected, and never an error.
    GuestClosedInput,
    /// A genuine forwarding failure, rendered for the launcher's error.
    Failed(String),
}

pub(crate) fn classify_stdin_error(error: &ExecStdinError) -> GuestInputStatus {
    let broken_pipe = match (error.errno_name.as_deref(), error.errno) {
        (Some(name), _) => name == "EPIPE",
        (None, errno) => errno == Some(GUEST_EPIPE),
    };
    if broken_pipe {
        return GuestInputStatus::GuestClosedInput;
    }
    let errno = error
        .errno_name
        .clone()
        .or_else(|| error.errno.map(|errno| errno.to_string()))
        .unwrap_or_else(|| "no errno".to_string());
    GuestInputStatus::Failed(format!(
        "{errno}: {}",
        crate::config::escape_str(&error.message)
    ))
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Gated stubs shared with `run.rs`'s lifecycle tests.
    //!
    //! Every concurrency test must prove the state it claims to exercise before
    //! it releases an event, so each stub announces entering (and leaving) the
    //! step it is about to block in. A test waits for a *receipt*, never for
    //! time to pass (#399 review B4).

    use super::{GuestStdin, InputChunk};
    use std::io::Read;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

    /// How long a test waits for a receipt before failing.
    pub(crate) const RECEIPT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(2);

    /// One observation of a stub entering or leaving a step.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) enum Receipt {
        ReaderEntered {
            call: usize,
        },
        ReaderDropped,
        WriteEntered {
            len: usize,
        },
        WriteReturned {
            ok: bool,
        },
        CloseEntered,
        SinkDropped,
        /// An output sink flushed; `stream` is `"stdout"` or `"stderr"`.
        Flushed {
            stream: &'static str,
            total: usize,
        },
    }

    /// An ordered log of drops, so a test asserts one sequence (`["sink",
    /// "runtime", "handle", "stop", …]`) instead of independent booleans.
    pub(crate) type DropLog = Arc<Mutex<Vec<&'static str>>>;

    pub(crate) fn drop_log() -> DropLog {
        DropLog::default()
    }

    pub(crate) fn log_drop(log: &DropLog, what: &'static str) {
        log.lock().unwrap().push(what);
    }

    /// A receipt channel that keeps its history: a receipt one assertion
    /// consumed (or raced past) is still available to a later one.
    pub(crate) struct Receipts {
        receiver: UnboundedReceiver<Receipt>,
        seen: Vec<Receipt>,
    }

    impl Receipts {
        pub(crate) fn channel() -> (UnboundedSender<Receipt>, Self) {
            let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
            (
                sender,
                Self {
                    receiver,
                    seen: Vec::new(),
                },
            )
        }

        /// Wait until `matches` has been received. Panics with `label` on the
        /// deadline: a missing receipt is a failed test, never a skip.
        pub(crate) async fn expect(&mut self, label: &str, matches: impl Fn(&Receipt) -> bool) {
            // `saw` collects first, so a receipt that arrived while the test was
            // doing something else is still in the history.
            if self.saw(&matches) {
                return;
            }
            let deadline = tokio::time::Instant::now() + RECEIPT_DEADLINE;
            loop {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                match tokio::time::timeout(remaining, self.receiver.recv()).await {
                    Ok(Some(receipt)) => {
                        let hit = matches(&receipt);
                        self.seen.push(receipt);
                        if hit {
                            return;
                        }
                    }
                    Ok(None) => panic!("{label}: receipt channel closed; saw {:?}", self.seen),
                    Err(_) => panic!(
                        "{label}: no matching receipt within {RECEIPT_DEADLINE:?}; saw {:?}",
                        self.seen
                    ),
                }
            }
        }

        /// Whether `matches` ever arrived. **Collects first**: after a run has
        /// completed, a negative assertion ("no close", "no read") must not be
        /// answered from a history nothing ever filled in.
        pub(crate) fn saw(&mut self, matches: impl Fn(&Receipt) -> bool) -> bool {
            self.drain_now();
            self.seen.iter().any(matches)
        }

        /// How often `matches` arrived. Collects first, so "exactly once" cannot
        /// miss a queued duplicate.
        pub(crate) fn count(&mut self, matches: impl Fn(&Receipt) -> bool) -> usize {
            self.drain_now();
            self.seen.iter().filter(|receipt| matches(receipt)).count()
        }

        /// Move every receipt that has already arrived into the history, so a
        /// test can inspect a completed run without waiting for one.
        pub(crate) fn drain_now(&mut self) {
            while let Ok(receipt) = self.receiver.try_recv() {
                self.seen.push(receipt);
            }
        }

        /// Every receipt received so far, in arrival order. Collects first.
        pub(crate) fn history(&mut self) -> &[Receipt] {
            self.drain_now();
            &self.seen
        }
    }

    /// How the test answers one read call.
    pub(crate) enum ReaderStep {
        Bytes(Vec<u8>),
        Eof,
        Error(std::io::ErrorKind),
        Interrupted,
        Panic,
    }

    /// A reader that blocks in `read` until the test releases a step, so a test
    /// can act while a host read is genuinely in progress.
    pub(crate) struct GatedReader {
        steps: Mutex<std::sync::mpsc::Receiver<ReaderStep>>,
        receipts: UnboundedSender<Receipt>,
        calls: AtomicUsize,
    }

    impl GatedReader {
        pub(crate) fn new(
            receipts: UnboundedSender<Receipt>,
        ) -> (Self, std::sync::mpsc::Sender<ReaderStep>) {
            let (sender, receiver) = std::sync::mpsc::channel();
            (
                Self {
                    steps: Mutex::new(receiver),
                    receipts,
                    calls: AtomicUsize::new(0),
                },
                sender,
            )
        }
    }

    impl Read for GatedReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            let _ = self.receipts.send(Receipt::ReaderEntered { call });
            let step = self.steps.lock().unwrap().recv();
            match step {
                Ok(ReaderStep::Bytes(bytes)) => {
                    let read = bytes.len().min(buffer.len());
                    buffer[..read].copy_from_slice(&bytes[..read]);
                    Ok(read)
                }
                Ok(ReaderStep::Eof) => Ok(0),
                Ok(ReaderStep::Error(kind)) => Err(std::io::Error::new(kind, "stub reader")),
                Ok(ReaderStep::Interrupted) => Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "stub interrupt",
                )),
                Ok(ReaderStep::Panic) => panic!("gated reader panic"),
                // The test dropped its sender: the bounded way to release the
                // thread at the end of a test.
                Err(_) => Ok(0),
            }
        }
    }

    impl Drop for GatedReader {
        fn drop(&mut self) {
            let _ = self.receipts.send(Receipt::ReaderDropped);
        }
    }

    /// An infinite reader that never blocks, so a test can observe how far
    /// ahead of a stalled guest the reader actually gets.
    pub(crate) struct CountingReader {
        calls: Arc<AtomicUsize>,
        receipts: UnboundedSender<Receipt>,
    }

    impl CountingReader {
        pub(crate) fn new(receipts: UnboundedSender<Receipt>) -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
                receipts,
            }
        }

        pub(crate) fn calls(&self) -> Arc<AtomicUsize> {
            Arc::clone(&self.calls)
        }
    }

    impl Read for CountingReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            let _ = self.receipts.send(Receipt::ReaderEntered { call });
            buffer.fill(b'x');
            Ok(buffer.len())
        }
    }

    impl Drop for CountingReader {
        fn drop(&mut self) {
            let _ = self.receipts.send(Receipt::ReaderDropped);
        }
    }

    /// How the test answers one guest write or close.
    pub(crate) enum SinkStep {
        Accept,
        Fail(&'static str),
        StdinClosed,
    }

    /// A [`GuestStdin`] whose writes and closes block until the test releases
    /// them, recording accepted bytes.
    pub(crate) struct GatedGuestStdin {
        receipts: UnboundedSender<Receipt>,
        steps: tokio::sync::Mutex<UnboundedReceiver<SinkStep>>,
        /// Kept alive so a test that releases nothing parks the write instead
        /// of closing the channel.
        step_sender: UnboundedSender<SinkStep>,
        accepted: Arc<Mutex<Vec<u8>>>,
        auto_accept: bool,
        drop_log: Option<DropLog>,
        dropped: Arc<std::sync::atomic::AtomicBool>,
    }

    impl GatedGuestStdin {
        pub(crate) fn new(receipts: UnboundedSender<Receipt>) -> (Self, UnboundedSender<SinkStep>) {
            let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
            let sink = Self {
                receipts,
                steps: tokio::sync::Mutex::new(receiver),
                step_sender: sender.clone(),
                accepted: Arc::new(Mutex::new(Vec::new())),
                auto_accept: false,
                drop_log: None,
                dropped: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            };
            (sink, sender)
        }

        /// Accepts every write and close without a step.
        pub(crate) fn auto_accept(receipts: UnboundedSender<Receipt>) -> Self {
            let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
            Self {
                receipts,
                steps: tokio::sync::Mutex::new(receiver),
                step_sender: sender,
                accepted: Arc::new(Mutex::new(Vec::new())),
                auto_accept: true,
                drop_log: None,
                dropped: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            }
        }

        pub(crate) fn logging_drops(mut self, log: DropLog) -> Self {
            self.drop_log = Some(log);
            self
        }

        /// The step sender, so a caller that did not create the channel can
        /// still release writes.
        pub(crate) fn steps(&self) -> UnboundedSender<SinkStep> {
            self.step_sender.clone()
        }

        /// Set when this sink is dropped, for a teardown's ordering assertion.
        pub(crate) fn dropped_flag(&self) -> Arc<std::sync::atomic::AtomicBool> {
            Arc::clone(&self.dropped)
        }

        /// The accepted bytes, shared so the test keeps reading them after the
        /// sink has been dropped with its pump.
        pub(crate) fn accepted(&self) -> Arc<Mutex<Vec<u8>>> {
            Arc::clone(&self.accepted)
        }

        async fn decide(&self) -> SinkStep {
            if self.auto_accept {
                return SinkStep::Accept;
            }
            let mut steps = self.steps.lock().await;
            match steps.recv().await {
                Some(step) => step,
                // A test that released nothing keeps the write pending; that is
                // the state a cancellation test needs.
                None => std::future::pending().await,
            }
        }

        fn accept(&self, bytes: &[u8]) {
            self.accepted.lock().unwrap().extend_from_slice(bytes);
        }
    }

    impl GuestStdin for GatedGuestStdin {
        async fn write(&self, chunk: &InputChunk) -> anyhow::Result<()> {
            let _ = self.receipts.send(Receipt::WriteEntered {
                len: chunk.as_bytes().len(),
            });
            match self.decide().await {
                SinkStep::Accept => {
                    self.accept(chunk.as_bytes());
                    let _ = self.receipts.send(Receipt::WriteReturned { ok: true });
                    Ok(())
                }
                SinkStep::Fail(detail) => {
                    let _ = self.receipts.send(Receipt::WriteReturned { ok: false });
                    Err(anyhow::anyhow!("{}", detail))
                }
                SinkStep::StdinClosed => Err(anyhow::Error::new(
                    microsandbox::MicrosandboxError::Runtime("execution stdin closed".into()),
                )),
            }
        }

        async fn close(&self) -> anyhow::Result<()> {
            let _ = self.receipts.send(Receipt::CloseEntered);
            match self.decide().await {
                SinkStep::Accept => {
                    let _ = self.receipts.send(Receipt::WriteReturned { ok: true });
                    Ok(())
                }
                SinkStep::Fail(detail) => {
                    let _ = self.receipts.send(Receipt::WriteReturned { ok: false });
                    Err(anyhow::anyhow!("{}", detail))
                }
                SinkStep::StdinClosed => Err(anyhow::Error::new(
                    microsandbox::MicrosandboxError::Runtime("execution stdin closed".into()),
                )),
            }
        }
    }

    impl Drop for GatedGuestStdin {
        fn drop(&mut self) {
            self.dropped
                .store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(log) = &self.drop_log {
                log_drop(log, "sink");
            }
            let _ = self.receipts.send(Receipt::SinkDropped);
        }
    }

    /// A spawner that always fails, for the "nothing runs" start-failure path.
    pub(crate) fn failing_spawner(
        _body: Box<dyn FnOnce() + Send + 'static>,
    ) -> std::io::Result<()> {
        Err(std::io::Error::other("injected"))
    }

    /// A spawner that runs the reader body **before** reporting failure — the
    /// shape the production spawner never produces, used only to show that a
    /// start-failure test's "no host read" assertion can see a read (review
    /// B2). The body must not block: its steps are released first.
    pub(crate) fn reading_then_failing_spawner(
        body: Box<dyn FnOnce() + Send + 'static>,
    ) -> std::io::Result<()> {
        std::thread::Builder::new()
            .name("agent-vm-test-reader".into())
            .spawn(body)?
            .join()
            .expect("the injected reader body");
        Err(std::io::Error::other("injected"))
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{
        CountingReader, GatedGuestStdin, GatedReader, RECEIPT_DEADLINE, ReaderStep, Receipt,
        Receipts, SinkStep, failing_spawner,
    };
    use super::*;
    use std::time::Duration;

    #[test]
    fn stdin_closed_sentinel_matches_the_bundled_sdk() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../vendor/microsandbox/sdk/rust/lib/sandbox/exec/io.rs");
        let source =
            std::fs::read_to_string(path).expect("read the pinned SDK stdin implementation");
        assert!(
            source.contains(&format!("\"{STDIN_CLOSED_SENTINEL}\"")),
            "SDK stdin-closure sentinel changed; review is_stdin_closed before bumping the vendor"
        );
    }

    /// Five distinguishable 64 KiB chunks (320 KiB), every chunk with its own
    /// marker, every byte value (offset by the chunk number, so a substituted
    /// chunk cannot compare equal) and a NUL run. Several chunks is the point:
    /// a single-chunk input cannot expose reordering, substitution or loss
    /// across a chunk boundary (review B3).
    fn multi_chunk_input() -> Vec<u8> {
        let mut bytes = Vec::new();
        for chunk in 0..5u8 {
            let start = bytes.len();
            bytes.extend(format!("chunk-{chunk}-start").into_bytes());
            bytes.extend((0..=255u8).map(|value| value ^ chunk));
            bytes.extend([0u8; 33]);
            bytes.resize(start + HOST_READ_CHUNK_BYTES, chunk.wrapping_mul(37));
        }
        bytes
    }

    #[test]
    fn an_empty_chunk_is_unrepresentable() {
        assert!(InputChunk::new(Vec::new()).is_none());
        let chunk = InputChunk::new(vec![0, 1, 255]).expect("a non-empty chunk");
        assert_eq!(chunk.as_bytes(), &[0, 1, 255]);
    }

    #[test]
    fn stdin_errors_classify_broken_pipe_only_as_guest_closure() {
        fn error(errno: Option<i32>, name: Option<&str>, message: &str) -> ExecStdinError {
            ExecStdinError {
                errno,
                errno_name: name.map(str::to_string),
                message: message.to_string(),
            }
        }

        assert_eq!(
            classify_stdin_error(&error(Some(GUEST_EPIPE), Some("EPIPE"), "pipe closed")),
            GuestInputStatus::GuestClosedInput
        );
        assert_eq!(
            classify_stdin_error(&error(Some(GUEST_EPIPE), None, "pipe closed")),
            GuestInputStatus::GuestClosedInput
        );
        for failure in [
            error(Some(5), Some("EIO"), "input/output error"),
            error(Some(28), Some("ENOSPC"), "no space"),
            error(None, None, "unknown"),
        ] {
            let GuestInputStatus::Failed(text) = classify_stdin_error(&failure) else {
                panic!("{failure:?} must be a genuine failure, not guest closure");
            };
            assert!(!text.is_empty());
        }
        let GuestInputStatus::Failed(named) =
            classify_stdin_error(&error(Some(5), Some("EIO"), "bad \u{7}byte"))
        else {
            panic!("EIO is a failure");
        };
        assert!(named.starts_with("EIO: "), "{named}");
        assert!(!named.contains('\u{7}'), "control byte unescaped: {named}");
        let GuestInputStatus::Failed(bare) =
            classify_stdin_error(&error(Some(28), None, "no space"))
        else {
            panic!("ENOSPC is a failure");
        };
        assert!(bare.starts_with("28: "), "{bare}");
    }

    #[tokio::test]
    async fn pump_forwards_every_byte_value_in_order_then_closes_once() {
        let bytes = multi_chunk_input();
        assert!(
            bytes.len() >= 300 * 1024 && bytes.len() > 3 * HOST_READ_CHUNK_BYTES,
            "the input must span several chunks, got {} bytes",
            bytes.len()
        );
        let (receipts, mut observed) = Receipts::channel();
        let sink = GatedGuestStdin::auto_accept(receipts);
        let accepted = sink.accepted();
        let mut pump = InputSource::new(std::io::Cursor::new(bytes.clone()))
            .start(sink)
            .expect("the reader starts");

        let end = tokio::time::timeout(RECEIPT_DEADLINE * 5, pump.finished())
            .await
            .expect("the pump must finish")
            .expect("a clean end of input");
        assert_eq!(end, InputEnd::Eof);
        assert_eq!(accepted.lock().unwrap().as_slice(), bytes.as_slice());
        // One write per chunk, so the byte equality above really is a
        // multi-write equality and not one accepted buffer.
        assert_eq!(
            observed.count(|receipt| matches!(
                receipt,
                Receipt::WriteEntered { len } if *len == HOST_READ_CHUNK_BYTES
            )),
            bytes.len() / HOST_READ_CHUNK_BYTES,
            "expected one full-chunk write per chunk"
        );
        assert_eq!(
            observed.count(|receipt| matches!(receipt, Receipt::WriteEntered { len } if *len == 0)),
            0,
            "an empty write would be an EOF frame"
        );
        assert_eq!(
            observed.count(|receipt| *receipt == Receipt::CloseEntered),
            1
        );
        let history = observed.history();
        let close = history
            .iter()
            .position(|receipt| *receipt == Receipt::CloseEntered)
            .expect("a close");
        assert!(
            history[..close].iter().all(|receipt| matches!(
                receipt,
                Receipt::WriteEntered { .. } | Receipt::WriteReturned { .. }
            )),
            "close must be last: {history:?}"
        );
    }

    #[tokio::test]
    async fn empty_input_is_one_close_and_no_writes() {
        let (receipts, mut observed) = Receipts::channel();
        let sink = GatedGuestStdin::auto_accept(receipts);
        let accepted = sink.accepted();
        let mut pump = InputSource::new(std::io::Cursor::new(Vec::new()))
            .start(sink)
            .expect("the reader starts");

        assert_eq!(
            tokio::time::timeout(RECEIPT_DEADLINE, pump.finished())
                .await
                .expect("the pump must finish")
                .expect("a clean end of input"),
            InputEnd::Eof
        );
        observed.drain_now();
        assert_eq!(
            observed.count(|receipt| matches!(receipt, Receipt::WriteEntered { .. })),
            0
        );
        assert_eq!(
            observed.count(|receipt| *receipt == Receipt::CloseEntered),
            1
        );
        assert!(accepted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_host_read_error_is_reported_and_never_closes_guest_stdin() {
        let (receipts, mut observed) = Receipts::channel();
        let (reader, steps) = GatedReader::new(receipts.clone());
        let sink = GatedGuestStdin::auto_accept(receipts);
        let accepted = sink.accepted();
        let mut pump = InputSource::new(reader)
            .start(sink)
            .expect("the reader starts");
        steps.send(ReaderStep::Bytes(b"ab".to_vec())).unwrap();
        steps
            .send(ReaderStep::Error(std::io::ErrorKind::Other))
            .unwrap();

        let failure = tokio::time::timeout(RECEIPT_DEADLINE, pump.finished())
            .await
            .expect("the pump must finish")
            .expect_err("a host read error is a failure");
        assert!(matches!(failure, InputFailure::HostRead(_)), "{failure:?}");
        assert_eq!(accepted.lock().unwrap().as_slice(), b"ab");
        assert!(
            !observed.saw(|receipt| *receipt == Receipt::CloseEntered),
            "a host read error must not fabricate EOF"
        );
        drop(steps);
        observed
            .expect("the reader thread to exit", |receipt| {
                *receipt == Receipt::ReaderDropped
            })
            .await;
    }

    /// The negative control for U5, U11 and U13: the observation those tests
    /// use to forbid a close or a read **detects** one when it is injected, so
    /// their negative assertion cannot pass on an empty history (review B2).
    #[tokio::test]
    async fn an_injected_close_is_visible_to_the_forbidden_eof_oracle() {
        let (receipts, mut observed) = Receipts::channel();
        let (reader, steps) = GatedReader::new(receipts.clone());
        let mut pump = InputSource::new(reader)
            .start(ClosingOnWrite {
                receipts: receipts.clone(),
            })
            .expect("the reader starts");
        steps.send(ReaderStep::Bytes(b"ab".to_vec())).unwrap();
        steps
            .send(ReaderStep::Error(std::io::ErrorKind::Other))
            .unwrap();
        let failure = tokio::time::timeout(RECEIPT_DEADLINE, pump.finished())
            .await
            .expect("the pump must finish")
            .expect_err("a host read error is still a failure");
        assert!(matches!(failure, InputFailure::HostRead(_)), "{failure:?}");
        assert!(
            observed.saw(|receipt| *receipt == Receipt::CloseEntered),
            "the no-close oracle cannot see an injected close, so U5/U11 \
             would pass vacuously"
        );
        assert!(
            observed.saw(|receipt| matches!(receipt, Receipt::WriteEntered { .. })),
            "the injected sink really ran"
        );
        drop(steps);
        observed
            .expect("the reader thread to exit", |receipt| {
                *receipt == Receipt::ReaderDropped
            })
            .await;
    }

    #[tokio::test]
    async fn interrupted_reads_are_retried() {
        let (receipts, mut observed) = Receipts::channel();
        let (reader, steps) = GatedReader::new(receipts.clone());
        let sink = GatedGuestStdin::auto_accept(receipts);
        let accepted = sink.accepted();
        let mut pump = InputSource::new(reader)
            .start(sink)
            .expect("the reader starts");
        steps.send(ReaderStep::Interrupted).unwrap();
        steps.send(ReaderStep::Bytes(b"hello".to_vec())).unwrap();
        steps.send(ReaderStep::Eof).unwrap();

        assert_eq!(
            tokio::time::timeout(RECEIPT_DEADLINE, pump.finished())
                .await
                .expect("the pump must finish")
                .expect("a clean end of input"),
            InputEnd::Eof
        );
        assert_eq!(accepted.lock().unwrap().as_slice(), b"hello");
        observed
            .expect("a third read", |receipt| {
                matches!(receipt, Receipt::ReaderEntered { call: 3 })
            })
            .await;
        // EOF ends the reader's loop; observe that it really exited rather than
        // trusting the pump's completion (#399 NB5).
        drop(steps);
        observed
            .expect("the reader thread to exit", |receipt| {
                *receipt == Receipt::ReaderDropped
            })
            .await;
    }

    /// The launcher-side memory bound: with the guest's write stalled, the
    /// reader stops at three chunks (one in the pending write, one queued, one
    /// in the reader's hand) and cannot run ahead.
    ///
    /// This is a stub sink, not the runtime's relay credit, so it says nothing
    /// about the end-to-end bound; the native `large` e2e row is that check.
    #[tokio::test]
    async fn a_stalled_guest_bounds_host_reads() {
        let (receipts, mut observed) = Receipts::channel();
        let reader = CountingReader::new(receipts.clone());
        let calls = reader.calls();
        let (sink, sink_steps) = GatedGuestStdin::new(receipts);
        let mut pump = InputSource::new(reader)
            .start(sink)
            .expect("the reader starts");

        observed
            .expect("the first guest write", |receipt| {
                matches!(receipt, Receipt::WriteEntered { len } if *len == HOST_READ_CHUNK_BYTES)
            })
            .await;
        observed
            .expect("the reader to reach its third chunk", |receipt| {
                matches!(receipt, Receipt::ReaderEntered { call: 3 })
            })
            .await;
        let bound = HOST_READ_QUEUE_CHUNKS + 2;
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), bound);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            bound,
            "the reader ran ahead of a stalled guest"
        );

        sink_steps.send(SinkStep::Accept).unwrap();
        observed
            .expect("a second guest write", |receipt| {
                matches!(receipt, Receipt::WriteEntered { .. })
            })
            .await;
        observed
            .expect("the reader to reach its fourth chunk", |receipt| {
                matches!(receipt, Receipt::ReaderEntered { call: 4 })
            })
            .await;
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            bound + 1,
            "releasing one write must admit exactly one more chunk"
        );

        tokio::time::timeout(RECEIPT_DEADLINE, pump.stop())
            .await
            .expect("stop must not wait for the reader");
        observed
            .expect("the reader thread to exit", |receipt| {
                *receipt == Receipt::ReaderDropped
            })
            .await;
    }

    #[tokio::test]
    async fn stop_cancels_a_pending_guest_write_and_drops_the_sink() {
        let (receipts, mut observed) = Receipts::channel();
        let (reader, steps) = GatedReader::new(receipts.clone());
        let (sink, _sink_steps) = GatedGuestStdin::new(receipts);
        let mut pump = InputSource::new(reader)
            .start(sink)
            .expect("the reader starts");
        steps.send(ReaderStep::Bytes(b"abc".to_vec())).unwrap();

        observed
            .expect("a pending guest write", |receipt| {
                matches!(receipt, Receipt::WriteEntered { .. })
            })
            .await;
        tokio::time::timeout(Duration::from_secs(1), pump.stop())
            .await
            .expect("stop must cancel a pending write");
        observed
            .expect("the sink to be dropped", |receipt| {
                *receipt == Receipt::SinkDropped
            })
            .await;
        assert!(
            !observed.saw(|receipt| matches!(receipt, Receipt::WriteReturned { ok: true })),
            "the write must have been cancelled, not completed"
        );
        // Idempotent.
        tokio::time::timeout(Duration::from_secs(1), pump.stop())
            .await
            .expect("a second stop is a no-op");
        drop(steps);
        observed
            .expect("the reader thread to exit", |receipt| {
                *receipt == Receipt::ReaderDropped
            })
            .await;
    }

    #[tokio::test]
    async fn stop_returns_while_the_host_read_is_blocked() {
        let (receipts, mut observed) = Receipts::channel();
        let (reader, steps) = GatedReader::new(receipts.clone());
        let (sink, _sink_steps) = GatedGuestStdin::new(receipts);
        let mut pump = InputSource::new(reader)
            .start(sink)
            .expect("the reader starts");

        observed
            .expect("a host read in progress", |receipt| {
                matches!(receipt, Receipt::ReaderEntered { call: 1 })
            })
            .await;
        tokio::time::timeout(Duration::from_secs(1), pump.stop())
            .await
            .expect("stop must not join a reader parked in read(2)");
        observed
            .expect("the sink to be dropped", |receipt| {
                *receipt == Receipt::SinkDropped
            })
            .await;
        assert!(
            !observed.saw(|receipt| *receipt == Receipt::ReaderDropped),
            "stop() must not wait for the parked reader"
        );
        drop(steps);
        observed
            .expect("the reader thread to exit", |receipt| {
                *receipt == Receipt::ReaderDropped
            })
            .await;
    }

    #[tokio::test]
    async fn transport_errors_from_write_and_close_are_failures() {
        for on_close in [false, true] {
            let (receipts, mut observed) = Receipts::channel();
            let (reader, steps) = GatedReader::new(receipts.clone());
            let (sink, sink_steps) = GatedGuestStdin::new(receipts);
            let mut pump = InputSource::new(reader)
                .start(sink)
                .expect("the reader starts");
            if on_close {
                steps.send(ReaderStep::Eof).unwrap();
                observed
                    .expect("a pending close", |receipt| {
                        *receipt == Receipt::CloseEntered
                    })
                    .await;
            } else {
                steps.send(ReaderStep::Bytes(b"a".to_vec())).unwrap();
                observed
                    .expect("a pending write", |receipt| {
                        matches!(receipt, Receipt::WriteEntered { .. })
                    })
                    .await;
            }
            sink_steps.send(SinkStep::Fail("transport down")).unwrap();

            let failure = tokio::time::timeout(RECEIPT_DEADLINE, pump.finished())
                .await
                .expect("the pump must finish")
                .expect_err("a transport error is a failure");
            assert!(matches!(failure, InputFailure::Transport(_)), "{failure:?}");
            let text = failure.into_error().to_string();
            assert!(
                text.starts_with("forwarding stdin to the guest failed: "),
                "{text}"
            );
            assert!(text.contains("transport down"), "{text}");
            drop(steps);
            observed
                .expect("the reader thread to exit", |receipt| {
                    *receipt == Receipt::ReaderDropped
                })
                .await;
        }
    }

    #[tokio::test]
    async fn a_vanished_reader_is_not_eof() {
        let (receipts, mut observed) = Receipts::channel();
        let (reader, steps) = GatedReader::new(receipts.clone());
        let sink = GatedGuestStdin::auto_accept(receipts);
        let mut pump = InputSource::new(reader)
            .start(sink)
            .expect("the reader starts");
        steps.send(ReaderStep::Panic).unwrap();

        let failure = tokio::time::timeout(RECEIPT_DEADLINE, pump.finished())
            .await
            .expect("the pump must finish when its reader vanishes")
            .expect_err("a vanished reader is a failure");
        assert!(
            matches!(failure, InputFailure::ReaderVanished),
            "{failure:?}"
        );
        assert!(
            !observed.saw(|receipt| *receipt == Receipt::CloseEntered),
            "a vanished reader must not fabricate EOF"
        );
        drop(steps);
        observed
            .expect("the reader to be dropped", |receipt| {
                *receipt == Receipt::ReaderDropped
            })
            .await;
    }

    #[tokio::test]
    async fn a_reader_spawn_failure_starts_nothing_and_drops_the_sink() {
        let (receipts, mut observed) = Receipts::channel();
        let (reader, _steps) = GatedReader::new(receipts.clone());
        let (sink, _sink_steps) = GatedGuestStdin::new(receipts);

        let Err(error) = InputSource::with_spawner(reader, failing_spawner).start(sink) else {
            panic!("the injected spawner must fail");
        };
        assert!(error.to_string().contains("injected"), "{error}");
        assert!(
            error
                .to_string()
                .starts_with("starting the host stdin reader failed: "),
            "{error}"
        );
        observed
            .expect("the sink to be dropped", |receipt| {
                *receipt == Receipt::SinkDropped
            })
            .await;
        observed
            .expect("the reader itself to be dropped", |receipt| {
                *receipt == Receipt::ReaderDropped
            })
            .await;
        assert!(
            !observed.saw(|receipt| matches!(receipt, Receipt::ReaderEntered { .. })),
            "a failed spawn must not read anything"
        );
    }

    #[test]
    fn exec_sink_is_a_guest_stdin() {
        fn assert_guest_stdin<T: GuestStdin>() {}
        assert_guest_stdin::<microsandbox::sandbox::exec::ExecSink>();
    }

    /// A deliberately wrong sink: it closes guest stdin on every write — the
    /// defect U5 and U11 exist to forbid. It exists only so the negative
    /// assertions of those tests can be shown to be sensitive (review B2).
    struct ClosingOnWrite {
        receipts: tokio::sync::mpsc::UnboundedSender<Receipt>,
    }

    impl GuestStdin for ClosingOnWrite {
        async fn write(&self, chunk: &InputChunk) -> anyhow::Result<()> {
            let _ = self.receipts.send(Receipt::WriteEntered {
                len: chunk.as_bytes().len(),
            });
            let _ = self.receipts.send(Receipt::CloseEntered);
            Ok(())
        }

        async fn close(&self) -> anyhow::Result<()> {
            let _ = self.receipts.send(Receipt::CloseEntered);
            Ok(())
        }
    }

    // ── The detached reader, against a real process and a real pipe ──

    /// A reader that announces its blocking read, then delegates to the real
    /// host stdin.
    struct AnnouncingStdin {
        receipts: tokio::sync::mpsc::UnboundedSender<Receipt>,
    }

    impl Read for AnnouncingStdin {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let _ = self.receipts.send(Receipt::ReaderEntered { call: 1 });
            eprintln!("U12_READ_ENTERED");
            std::io::stdin().read(buffer)
        }
    }

    /// The child half of U12/U12n: hold a parked host read open, then drop the
    /// runtime the way `main.rs`'s error path does.
    #[test]
    fn parked_reader_child() {
        let Some(variant) = std::env::var_os("AGENT_VM_399_U12_CHILD") else {
            return;
        };
        let variant = variant.to_string_lossy().into_owned();
        let runtime = tokio::runtime::Runtime::new().expect("a runtime");
        let (receipts, mut observed) = Receipts::channel();
        let read_in_progress = |receipt: &Receipt| matches!(receipt, Receipt::ReaderEntered { .. });

        if variant == "tokio-blocking" {
            let reader = AnnouncingStdin { receipts };
            let handle = runtime.handle().clone();
            let blocking = handle.spawn_blocking(move || {
                let mut reader = reader;
                let mut buffer = [0u8; 16];
                let _ = reader.read(&mut buffer);
            });
            runtime.block_on(async {
                observed
                    .expect("a blocking read in progress", read_in_progress)
                    .await;
            });
            drop(blocking);
            drop(runtime);
            eprintln!("U12_RUNTIME_DROPPED");
            return;
        }

        let (sink, sink_steps) = GatedGuestStdin::new(receipts.clone());
        let pump = runtime.block_on(async {
            let source = InputSource::new(AnnouncingStdin { receipts });
            let mut pump = source.start(sink).expect("the reader starts");
            observed
                .expect("a host read in progress", read_in_progress)
                .await;
            if variant == "stop" {
                pump.stop().await;
            }
            pump
        });
        drop(pump);
        drop(sink_steps);
        drop(runtime);
        eprintln!("U12_RUNTIME_DROPPED");
    }

    /// Run the child for one variant and return the lines it wrote to stderr,
    /// with the moment the first read was announced.
    fn spawn_parked_reader_child(
        variant: &str,
    ) -> (std::process::Child, std::sync::mpsc::Receiver<String>) {
        use std::process::{Command, Stdio};
        let mut child = Command::new(std::env::current_exe().unwrap())
            .env("AGENT_VM_399_U12_CHILD", variant)
            .args([
                "--exact",
                "direct_input::tests::parked_reader_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn the child");
        let stderr = child.stderr.take().expect("piped stderr");
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            use std::io::BufRead as _;
            for line in std::io::BufReader::new(stderr).lines() {
                match line {
                    Ok(line) => {
                        if sender.send(line).is_err() {
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
        });
        (child, receiver)
    }

    fn await_line(
        lines: &std::sync::mpsc::Receiver<String>,
        want: &str,
        deadline: Duration,
    ) -> bool {
        let deadline = std::time::Instant::now() + deadline;
        while let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) {
            match lines.recv_timeout(remaining) {
                Ok(line) if line.contains(want) => return true,
                Ok(_) => continue,
                Err(_) => return false,
            }
        }
        false
    }

    fn reap(
        mut child: std::process::Child,
        deadline: Duration,
    ) -> Option<std::process::ExitStatus> {
        let until = std::time::Instant::now() + deadline;
        while std::time::Instant::now() < until {
            if let Some(status) = child.try_wait().unwrap() {
                return Some(status);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = child.kill();
        let _ = child.wait();
        None
    }

    /// The oracle for ADR-0052 decision (1): a reader parked in `read(2)` must
    /// not delay process exit, because `main.rs`'s error path drops the runtime
    /// before it reports 125.
    #[test]
    fn a_parked_reader_does_not_delay_process_exit() {
        for variant in ["drop", "stop"] {
            let (child, lines) = spawn_parked_reader_child(variant);
            // The child's stdin writer stays open and writes nothing, so the
            // read really is parked.
            let mut stdin = child.stdin.as_ref().map(|_| ());
            assert!(
                await_line(&lines, "U12_READ_ENTERED", Duration::from_secs(10)),
                "{variant}: the child never started its host read"
            );
            assert!(
                await_line(&lines, "U12_RUNTIME_DROPPED", Duration::from_secs(5)),
                "{variant}: dropping the runtime waited for the parked read"
            );
            let status = reap(child, Duration::from_secs(5));
            assert_eq!(
                status.and_then(|status| status.code()),
                Some(0),
                "{variant}: the child did not exit cleanly after the runtime drop"
            );
            stdin.take();
        }
    }

    /// U12's negative control: the same harness over `tokio::task::spawn_blocking`
    /// — the design ADR-0052 rejects — must be *caught*. If this child exits
    /// promptly, U12 cannot detect the trap it exists for.
    #[test]
    fn the_parked_reader_oracle_catches_a_tokio_blocking_read() {
        let (child, lines) = spawn_parked_reader_child("tokio-blocking");
        assert!(
            await_line(&lines, "U12_READ_ENTERED", Duration::from_secs(10)),
            "the child never started its blocking read"
        );
        assert!(
            !await_line(&lines, "U12_RUNTIME_DROPPED", Duration::from_secs(3)),
            "U12's oracle cannot detect the tokio blocking-read trap: Runtime::drop \
             returned while a blocking read was parked"
        );
        let status = reap(child, Duration::from_secs(5));
        assert!(status.is_none(), "the child should still have been running");
    }
}
