//! Subprocess harness for host signal supervision (issue #401).
//!
//! Everything here drives a *real* signal against a *real* session in a child
//! process; `main.rs`'s `mod tests` keeps the fixtures the cases share with the
//! older PTY/pipe cases, and this module borrows them rather than duplicating
//! them.

use crate::report_dispatch_failure;
use crate::tests::{
    ChildGuard, FakeRuntime, OVER_BOUND_SETTLE, RelayBackend, RelayTeardown, append_receipt,
    open_pty, process_is_gone, receipt_line_of, receipt_lines_of, terminal_is_raw, terminal_state,
    wait_for_file, wait_until,
};

// -------------------------------------------------------------------------
// Host signal supervision (issue #401)
//
// Every case runs in a child process. An in-process `SIGINT` handler collides
// with the harness (a real signal reaches the test threads), and the two facts
// worth asserting — the *process* status and the *terminal* snapshot — cannot
// be observed from inside the process that produces them.
//
// The child installs the production handlers *before* it creates a session,
// drives the real session (terminal or streaming) over the fake relay, and
// tears down through the production `after_session`. The parent sends real
// signals, and asserts in the plan's order: terminal restored, sandbox torn
// down, exact status.
// -------------------------------------------------------------------------

const SIGNAL_DIR: &str = "AGENT_VM_SIGNAL_DIR";
const SIGNAL_CASE: &str = "AGENT_VM_SIGNAL_CASE";
const SIGNAL_CHILD: &str = "signal_cases::signal_case_child";

/// The grace the child injects. Never an environment override: `test_env` is
/// test-only, so a knob read from the environment would be a production
/// override wearing a test label. The production five seconds would only make
/// the expiry cases slow — what they assert is the rule, not the number.
const SIGNAL_GRACE: std::time::Duration = std::time::Duration::from_millis(400);

/// From spawn to reaped. Every wait in a case is bounded by it, so a session
/// that hangs (which is what a signal the launcher never observes looks like)
/// fails instead of stalling the suite.
const SIGNAL_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

/// One row of the status table, driven by a real signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SignalCase {
    /// `SIGINT` while nothing has polled the arrival queue yet.
    BeforeFirstPoll,
    /// Raw-mode Ctrl-C is a byte to the guest, not a host signal.
    CtrlCIsAByte,
    /// The guest handles the forwarded signal and exits inside the grace.
    GuestExitsInGrace,
    /// `SIGINT` then `SIGTERM`: the second interrupt forces, and it is reported.
    Escalation,
    /// The grace expires with the guest still running.
    GraceExpiry,
    /// The transport dies during the grace: never a signal status.
    TransportLossInGrace,
    /// A genuine teardown failure outranks the signal status.
    CleanupFailure,
    /// Streaming: a cooked terminal's Ctrl-C *is* a host `SIGINT`.
    StreamCookedCtrlC,
    /// Streaming: a consumer that stopped reading cannot hide an interrupt.
    StreamBlockedOutput,
    /// A forced end whose notice can never be written: the teardown must run
    /// anyway, which is only observable through the launch's own composition.
    ForcedNoticeStalled,
    /// The guest's own exit status is unknown (`-1`) *after* a forwarded
    /// signal: reported as the guest gave it, never as `128 + N`.
    UnknownStatus,
}

impl SignalCase {
    const ALL: [SignalCase; 11] = [
        SignalCase::BeforeFirstPoll,
        SignalCase::CtrlCIsAByte,
        SignalCase::GuestExitsInGrace,
        SignalCase::Escalation,
        SignalCase::GraceExpiry,
        SignalCase::TransportLossInGrace,
        SignalCase::CleanupFailure,
        SignalCase::StreamCookedCtrlC,
        SignalCase::StreamBlockedOutput,
        SignalCase::UnknownStatus,
        SignalCase::ForcedNoticeStalled,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::BeforeFirstPoll => "before-first-poll",
            Self::CtrlCIsAByte => "ctrl-c-is-a-byte",
            Self::GuestExitsInGrace => "guest-exits-in-grace",
            Self::Escalation => "escalation",
            Self::GraceExpiry => "grace-expiry",
            Self::TransportLossInGrace => "transport-loss-in-grace",
            Self::CleanupFailure => "cleanup-failure",
            Self::StreamCookedCtrlC => "stream-cooked-ctrl-c",
            Self::StreamBlockedOutput => "stream-blocked-output",
            Self::UnknownStatus => "unknown-status",
            Self::ForcedNoticeStalled => "forced-notice-stalled",
        }
    }

    fn parse(name: &str) -> Self {
        Self::ALL
            .into_iter()
            .find(|case| case.name() == name)
            .unwrap_or_else(|| panic!("unknown signal case {name}"))
    }

    /// Whether the case drives the streaming lifecycle (`-T`) rather than the
    /// terminal session. The terminal state is what distinguishes them: raw
    /// mode swallows Ctrl-C into a byte, a cooked one does not.
    fn is_streaming(self) -> bool {
        matches!(
            self,
            Self::StreamCookedCtrlC | Self::StreamBlockedOutput | Self::ForcedNoticeStalled
        )
    }

    /// What the guest does when the forwarded signal reaches it. `None` means
    /// it ignores the signal, so only the launcher's grace can end the case.
    fn guest_exit_after_signal(self) -> Option<i32> {
        match self {
            Self::BeforeFirstPoll => Some(0),
            Self::GuestExitsInGrace => Some(7),
            Self::StreamCookedCtrlC => Some(5),
            Self::UnknownStatus => Some(-1),
            _ => None,
        }
    }

    /// The status the launcher reports and the teardown stages that must have
    /// run — every number is a row of the status table.
    fn expected(self) -> (i32, &'static [&'static str]) {
        const FAILURE: i32 = crate::launch_target::DIRECT_LAUNCHER_FAILURE_EXIT;
        match self {
            // A guest status, including one it produced after a forwarded
            // signal, is reported as the guest gave it.
            Self::BeforeFirstPoll | Self::CtrlCIsAByte => (0, &["stop", "remove"]),
            Self::GuestExitsInGrace => (7, &["stop", "remove"]),
            Self::StreamCookedCtrlC => (5, &["stop", "remove"]),
            // A forced shutdown is 128 + the *interrupting* signal, and its
            // teardown goes straight to kill and never stops gracefully.
            Self::Escalation => (143, &["kill", "reap", "remove"]),
            Self::GraceExpiry | Self::StreamBlockedOutput | Self::ForcedNoticeStalled => {
                (130, &["kill", "reap", "remove"])
            }
            // Transport loss is 125 — never `128 + N` for a signal we happened
            // to forward — and its ordinary teardown still stops first.
            Self::TransportLossInGrace => (FAILURE, &["stop", "remove"]),
            // A genuine cleanup failure outranks the signal status, and the
            // forced teardown still reaps and removes after the failed kill.
            Self::CleanupFailure => (FAILURE, &["kill", "reap", "remove"]),
            // An unknown status is passed through, so the *process* status is
            // `exit(-1)`: 255. The receipt keeps the `-1` itself, which is what
            // proves it was not converted into `128 + N`.
            Self::UnknownStatus => (255, &["stop", "remove"]),
        }
    }
}

fn signal_receipt(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join("signal.receipt")
}

fn signal_receipt_text(dir: &std::path::Path) -> String {
    std::fs::read_to_string(signal_receipt(dir)).unwrap_or_default()
}

/// Wait for a file without a runtime: the child installs handlers and can be
/// blocked before it builds one.
fn wait_for_file_blocking(dir: &std::path::Path, name: &str) {
    let deadline = std::time::Instant::now() + SIGNAL_DEADLINE;
    while !dir.join(name).exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "{name} was never released"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// The fake guest's side of one signal case: the `[id_min][id_max]` +
/// `Ready` handshake, one exec request, then a script that records what the
/// launcher sent it.
async fn signal_relay(mut io: tokio::io::DuplexStream, dir: std::path::PathBuf, case: SignalCase) {
    use microsandbox::protocol::codec;
    use microsandbox::protocol::core::Ready;
    use microsandbox::protocol::exec::{
        ExecExited, ExecRequest, ExecSignal, ExecStdin, ExecStdout,
    };
    use microsandbox::protocol::message::{Message, MessageType};
    use tokio::io::AsyncWriteExt as _;

    let receipt = signal_receipt(&dir);
    io.write_all(&1u32.to_be_bytes()).await.unwrap();
    io.write_all(&1024u32.to_be_bytes()).await.unwrap();
    let ready = Ready {
        boot_time_ns: 1,
        init_time_ns: 2,
        ready_time_ns: 3,
        agent_version: "signals".to_string(),
        ..Default::default()
    };
    codec::write_message(
        &mut io,
        &Message::with_payload(MessageType::Ready, 0, &ready).unwrap(),
    )
    .await
    .unwrap();

    let request = codec::read_message(&mut io)
        .await
        .expect("the exec request");
    let id = request.id;
    let executed = request
        .payload::<ExecRequest>()
        .expect("the exec request payload");
    // The one property a case reads off the request: the PTY cases ask for a
    // terminal, the streaming ones do not.
    append_receipt(&receipt, &[format!("tty={}", executed.tty)]);

    // The parent releases the payload only once the state the case needs (raw
    // mode, or a full pipe) exists.
    wait_for_file(&dir, "go").await;

    if case == SignalCase::StreamBlockedOutput {
        // More than any pipe holds, so the launcher's write to the host cannot
        // finish while the parent is not reading. An interrupt must still be
        // forwarded and acted on, which is what the case's status proves.
        let frame = vec![b'x'; 64 * 1024];
        for _ in 0..16 {
            codec::write_message(
                &mut io,
                &Message::with_payload(
                    MessageType::ExecStdout,
                    id,
                    &ExecStdout {
                        data: frame.clone(),
                    },
                )
                .unwrap(),
            )
            .await
            .expect("relay write");
        }
        append_receipt(&receipt, &["output=sent".to_string()]);
    }

    while let Ok(message) = codec::read_message(&mut io).await {
        match message.t {
            MessageType::ExecSignal => {
                let signal = message.payload::<ExecSignal>().expect("a signal payload");
                append_receipt(&receipt, &[format!("signal={}", signal.signal)]);
                if let Some(code) = case.guest_exit_after_signal() {
                    codec::write_message(
                        &mut io,
                        &Message::with_payload(MessageType::ExecExited, id, &ExecExited { code })
                            .unwrap(),
                    )
                    .await
                    .expect("relay write");
                }
            }
            MessageType::ExecStdin => {
                let stdin = message.payload::<ExecStdin>().expect("a stdin payload");
                append_receipt(&receipt, &[format!("stdin={}", hex_bytes(&stdin.data))]);
                if stdin.data.contains(&0x03) {
                    // The guest saw the byte and is done; nothing was signalled.
                    codec::write_message(
                        &mut io,
                        &Message::with_payload(
                            MessageType::ExecExited,
                            id,
                            &ExecExited { code: 0 },
                        )
                        .unwrap(),
                    )
                    .await
                    .expect("relay write");
                }
            }
            _ => {}
        }
    }
}

/// Lowercase hex, so a receipt can prove exactly which bytes the guest saw.
fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The stderr a streaming launch can really face: a consumer that stopped
/// reading. A stopped terminal or a full pipe does not *refuse* the write, it
/// never completes it, so the write blocks until the case releases it — and what
/// it received is observable afterwards.
#[derive(Clone)]
struct StalledNotice(std::sync::Arc<StalledNoticeState>);

struct StalledNoticeState {
    released: std::sync::atomic::AtomicBool,
    written: std::sync::Mutex<Vec<u8>>,
}

impl StalledNotice {
    fn new() -> Self {
        Self(std::sync::Arc::new(StalledNoticeState {
            released: std::sync::atomic::AtomicBool::new(false),
            written: std::sync::Mutex::new(Vec::new()),
        }))
    }

    fn release(&self) {
        self.0
            .released
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn received(&self) -> String {
        String::from_utf8_lossy(&self.0.written.lock().expect("the notice record")).into_owned()
    }
}

impl std::io::Write for StalledNotice {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        while !self.0.released.load(std::sync::atomic::Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        self.0
            .written
            .lock()
            .expect("the notice record")
            .extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl crate::launch_notice::NoticeSink for StalledNotice {
    fn reopened(&self) -> Self {
        self.clone()
    }
}

/// The case child's terminal, observed from the **master** only.
///
/// The parent must not keep the slave: the child is a session leader whose
/// controlling terminal is this pty, and a child that exits while another
/// process still holds the slave stops inside `exit` and is never reaped
/// (measured on macOS — the case hung with the slave open and passed without
/// it). Termios is visible through the master, which is also how the full-pipe
/// control compares its terminal snapshots.
struct SignalTerminal {
    master: std::os::fd::OwnedFd,
    baseline: String,
}

impl SignalTerminal {
    /// The terminal and the slave the child must inherit as its stdin.
    fn open() -> (Self, std::os::fd::OwnedFd) {
        use std::os::fd::AsRawFd as _;
        let (master, slave) = open_pty(24, 80);
        let baseline = terminal_state(master.as_raw_fd());
        (Self { master, baseline }, slave)
    }

    fn master_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd as _;
        self.master.as_raw_fd()
    }

    /// Type bytes on the terminal, as the operator's keyboard would.
    fn type_bytes(&self, bytes: &[u8]) {
        // SAFETY: the master is an open descriptor for this value's lifetime and
        // `bytes` is a live slice of exactly `bytes.len()` bytes.
        assert_eq!(
            unsafe { libc::write(self.master_fd(), bytes.as_ptr().cast(), bytes.len()) },
            bytes.len() as isize,
            "write to the terminal: {}",
            std::io::Error::last_os_error()
        );
    }

    fn is_raw(&self) -> bool {
        terminal_is_raw(self.master_fd())
    }
}

impl FakeRuntime {
    /// The same runtime in its own process group, so a cooked terminal's
    /// Ctrl-C — which the line discipline delivers to the launcher child's
    /// whole foreground group — reaches the launcher alone. A real VMM is a
    /// separate process a host interrupt does not kill, and the case that kills
    /// one deliberately is `transport-loss-in-grace`.
    fn spawn_detached() -> Self {
        Self::spawn_with(true)
    }
}

/// The child: real handlers, a real session over a fake relay, the real
/// teardown and the real exit-status policy.
///
/// Without the env token this is an ordinary passing test.
#[test]
fn signal_case_child() {
    let Ok(dir) = std::env::var(SIGNAL_DIR) else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let case = SignalCase::parse(&std::env::var(SIGNAL_CASE).expect("a case"));
    let receipt = signal_receipt(&dir);
    let runtime_process = FakeRuntime::spawn_detached();
    append_receipt(&receipt, &[format!("runtime_pid={}", runtime_process.pid)]);

    // Installed exactly where a launch installs them: before the session
    // exists, so the queue is live before the first poll and an arrival in
    // that window is queued rather than lost — the property a pipe-only wake
    // without a queue would miss.
    let (guard, mut supervision) =
        crate::host_signals::install(SIGNAL_GRACE).expect("install the host signal handlers");
    append_receipt(&receipt, &["installed".to_string()]);
    if case == SignalCase::BeforeFirstPoll {
        // The parent signals here: nothing has polled the queue yet.
        wait_for_file_blocking(&dir, "signal-sent");
    }

    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("an owning runtime");
    let relay_task = runtime.spawn(signal_relay(server_io, dir.clone(), case));
    let client = runtime
        .block_on(
            microsandbox::agent::AgentClient::connect_stream_with_timeout(
                client_io,
                std::time::Duration::from_secs(10),
            ),
        )
        .expect("the fake relay handshake");
    let backend: std::sync::Arc<dyn microsandbox::backend::Backend> =
        std::sync::Arc::new(RelayBackend {
            inner: microsandbox::backend::default_backend(),
            client: std::sync::Mutex::new(Some(client)),
        });
    let config = microsandbox::SandboxConfig::default();
    let options = microsandbox::sandbox::exec::ExecOptions {
        args: vec!["-c".to_string(), "probe".to_string()],
        cwd: Some("/workspace/project".to_string()),
        tty: !case.is_streaming(),
        stdin: microsandbox::sandbox::exec::StdinMode::Pipe,
        ..Default::default()
    };
    let handle = runtime.block_on(backend.as_ref().sandboxes().exec_stream(
        std::sync::Arc::clone(&backend),
        "probe",
        &config,
        "bash".to_string(),
        options,
    ));
    let teardown = RelayTeardown {
        receipt: receipt.clone(),
        runtime: std::sync::Arc::clone(&runtime_process.child),
        fail_at: (case == SignalCase::CleanupFailure).then_some("kill"),
    };
    let runtime_wait = Box::pin(FakeRuntime::wait_future(std::sync::Arc::clone(
        &runtime_process.child,
    )));

    let ended: anyhow::Result<crate::host_signals::SessionEnd> = match handle {
        Err(error) => Err(anyhow::Error::new(error)),
        Ok(handle) => runtime.block_on(async {
            if case.is_streaming() {
                crate::run::test_support::stream_session(
                    &teardown,
                    handle,
                    runtime_wait,
                    "probe-image",
                    "/logs/probe",
                    &mut supervision,
                )
                .await
            } else {
                crate::direct_pty::run(handle, runtime_wait, &mut supervision).await
            }
        }),
    };
    // Exactly the failure ownership a launch has: the streaming wrapper tears
    // its own failures down, and the terminal session leaves that to its
    // caller. `after_session` is the one owner of "the session ended" — and for
    // the stalled case the *launch's own* composition is, because the notice and
    // the teardown are one step there. Driving `finish_launch_with` is what makes
    // the composition observable: `launch()` cannot be driven by a case.
    let stalled = StalledNotice::new();
    let outcome: anyhow::Result<i32> = match ended {
        Ok(end) if case == SignalCase::ForcedNoticeStalled => {
            let result = runtime.block_on(crate::run::test_support::finish_launch_with(
                stalled.clone(),
                &teardown,
                end,
                "probe",
                "/logs/probe",
            ));
            // The teardown has already run and the notice has still not been
            // accepted: that ordering is the whole point, and a launcher that
            // wrote first would never reach these lines.
            append_receipt(
                &receipt,
                &[format!(
                    "notice={}",
                    if stalled.received().is_empty() {
                        "stalled"
                    } else {
                        "delivered-before-teardown"
                    }
                )],
            );
            // Released, the same notice is delivered: the detached writer loses
            // nothing when the consumer comes back.
            stalled.release();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while stalled.received().is_empty() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            append_receipt(
                &receipt,
                &[format!(
                    "notice_after_release={}",
                    if stalled.received().is_empty() {
                        "lost"
                    } else {
                        "delivered"
                    }
                )],
            );
            result
        }
        Ok(end) => runtime.block_on(crate::run::after_session(&teardown, end, "probe")),
        Err(primary) if case.is_streaming() => Err(primary),
        Err(primary) => Err(runtime.block_on(crate::run::finish_failed_exec(
            &teardown,
            primary,
            "/logs/probe",
        ))),
    };
    // The runtime and the handlers are released before the report, and the
    // guard outlives the teardown exactly as a launch's does.
    drop(runtime);
    drop(guard);
    relay_task.abort();

    match outcome {
        Ok(code) => {
            append_receipt(&receipt, &[format!("status=ok:{code}")]);
            std::process::exit(code);
        }
        Err(error) => {
            append_receipt(&receipt, &[format!("error={error:#}")]);
            let _ = report_dispatch_failure(error, true);
            panic!("report_dispatch_failure returned instead of exiting 125");
        }
    }
}

/// Every row of the status table that a real signal can drive, one test per
/// row so a failure names the row.
#[test]
fn a_signal_arriving_before_the_first_poll_is_still_forwarded() {
    run_signal_case(SignalCase::BeforeFirstPoll);
}

#[test]
fn a_raw_mode_ctrl_c_is_a_guest_byte_and_not_a_host_signal() {
    run_signal_case(SignalCase::CtrlCIsAByte);
}

#[test]
fn a_guest_that_exits_inside_the_grace_keeps_its_own_status() {
    run_signal_case(SignalCase::GuestExitsInGrace);
}

#[test]
fn a_second_interrupt_forces_a_shutdown_and_reports_its_own_signal() {
    run_signal_case(SignalCase::Escalation);
}

#[test]
fn an_expired_grace_forces_a_shutdown_and_reports_the_forwarded_signal() {
    run_signal_case(SignalCase::GraceExpiry);
}

#[test]
fn a_transport_loss_during_the_grace_is_never_a_signal_status() {
    run_signal_case(SignalCase::TransportLossInGrace);
}

#[test]
fn a_cleanup_failure_outranks_the_signal_status() {
    run_signal_case(SignalCase::CleanupFailure);
}

#[test]
fn a_cooked_terminal_ctrl_c_is_a_real_signal_in_streaming_mode() {
    run_signal_case(SignalCase::StreamCookedCtrlC);
}

#[test]
fn a_consumer_that_stopped_reading_cannot_hide_an_interrupt() {
    run_signal_case(SignalCase::StreamBlockedOutput);
}

#[test]
fn an_unknown_guest_status_after_a_forwarded_signal_is_never_a_signal_status() {
    run_signal_case(SignalCase::UnknownStatus);
}

#[test]
fn a_forced_shutdown_tears_down_before_a_blocked_notice_can_hold_it() {
    run_signal_case(SignalCase::ForcedNoticeStalled);
}

/// Deliver one signal to the case child, as the operator's terminal or an
/// external `kill` would.
fn signal(pid: libc::pid_t, signal: libc::c_int) {
    // SAFETY: `kill` takes no pointers; the pid is the spawn we are holding
    // (reaped below), so it names a live child or nothing at all.
    assert_eq!(
        unsafe { libc::kill(pid, signal) },
        0,
        "deliver signal {signal}: {}",
        std::io::Error::last_os_error()
    );
}

/// Run one case in its own process and assert the plan's order: terminal
/// restored, sandbox torn down, exact status.
fn run_signal_case(case: SignalCase) {
    use std::io::Read as _;
    use std::os::unix::process::CommandExt as _;

    let dir = tempfile::tempdir().expect("a case directory");
    let (terminal, child_slave) = SignalTerminal::open();
    let mut command = std::process::Command::new(std::env::current_exe().expect("the test binary"));
    command
        .args(["--exact", SIGNAL_CHILD, "--test-threads=1"])
        .env(SIGNAL_DIR, dir.path())
        .env(SIGNAL_CASE, case.name())
        .stdin(std::process::Stdio::from(child_slave))
        // The blocked-output case needs a consumer that never drains; every
        // other case has nothing to write, so a null stdout keeps the parent
        // out of the output path entirely.
        .stdout(if case == SignalCase::StreamBlockedOutput {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .stderr(std::process::Stdio::piped());
    // A new session with this terminal as its controlling terminal. That is
    // what makes a *cooked* Ctrl-C a `SIGINT` to this process group — the
    // streaming case — instead of being lost to a terminal no session owns.
    // In raw mode the byte bypasses the line discipline, which is the PTY
    // case, so the same keystroke proves both halves of the asymmetry.
    //
    // SAFETY: `pre_exec` runs in the forked child before `exec`, which is why it
    // is `unsafe`: only `setsid` and `ioctl` are called, both async-signal-safe
    // syscalls on descriptors the child already has and no allocation happens.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY as _, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = ChildGuard::new(command.spawn().expect("spawn the case child"));
    drop(command);
    let mut child_stderr = child.get().stderr.take().expect("child stderr");
    let stderr_reader = std::thread::spawn(move || {
        let mut sink = Vec::new();
        let _ = child_stderr.read_to_end(&mut sink);
        sink
    });

    let receipt = |key: &str| receipt_line_of(&signal_receipt_text(dir.path()), key);
    wait_until("the handlers to be installed", SIGNAL_DEADLINE, || {
        signal_receipt_text(dir.path()).contains("installed")
    });
    // Everything except the pre-poll case is signalled *after* the session is
    // ready, and the PTY cases need raw mode before a Ctrl-C byte means a byte.
    if case != SignalCase::BeforeFirstPoll && !case.is_streaming() {
        wait_until("raw mode", SIGNAL_DEADLINE, || terminal.is_raw());
    }
    if case != SignalCase::BeforeFirstPoll {
        std::fs::write(dir.path().join("go"), b"go").expect("release the payload");
    }

    let child_pid = child.get().id() as libc::pid_t;
    match case {
        SignalCase::BeforeFirstPoll => {
            // Signalled while the child has not created a session or polled the
            // queue once: the arrival must be queued, not lost.
            signal(child_pid, libc::SIGINT);
            std::fs::write(dir.path().join("signal-sent"), b"sent").expect("release the child");
            std::fs::write(dir.path().join("go"), b"go").expect("release the payload");
        }
        SignalCase::CtrlCIsAByte => {
            // The operator's Ctrl-C: with `ISIG` off it is one byte of guest
            // input, and the guest must receive exactly that.
            terminal.type_bytes(&[0x03]);
        }
        SignalCase::Escalation => {
            signal(child_pid, libc::SIGINT);
            wait_until("the first forwarded signal", SIGNAL_DEADLINE, || {
                receipt("signal").as_deref() == Some("2")
            });
            signal(child_pid, libc::SIGTERM);
        }
        SignalCase::TransportLossInGrace => {
            signal(child_pid, libc::SIGINT);
            wait_until("the forwarded signal", SIGNAL_DEADLINE, || {
                receipt("signal").as_deref() == Some("2")
            });
            // The VMM dies while the grace is still running. Nothing the guest
            // did is observable, so this is 125 and never `143`.
            let pid: u32 = receipt("runtime_pid")
                .expect("the child's owned runtime pid")
                .parse()
                .expect("a pid");
            // SAFETY: `kill` takes no pointers, and `pid` is the fake runtime
            // the child owns and records, so this names that live process.
            assert_eq!(
                unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) },
                0,
                "kill the owned fake runtime"
            );
        }
        SignalCase::CleanupFailure => {
            signal(child_pid, libc::SIGINT);
            wait_until("the forwarded signal", SIGNAL_DEADLINE, || {
                receipt("signal").as_deref() == Some("2")
            });
            signal(child_pid, libc::SIGINT);
        }
        SignalCase::StreamBlockedOutput => {
            // The receipt proves the launcher *accepted* the whole stream, not
            // that its write to the stopped consumer is blocked: acceptance
            // runs through the relay's own buffer, and the sink's pipe holds a
            // buffer of its own. The settle is what makes the signal land while
            // the loop is parked on a write that cannot finish, which is the
            // state this case is about (the full-pipe control's settle exists
            // for the same reason).
            wait_until("the guest's whole stream", SIGNAL_DEADLINE, || {
                signal_receipt_text(dir.path()).contains("output=sent")
            });
            std::thread::sleep(OVER_BOUND_SETTLE);
            signal(child_pid, libc::SIGINT);
        }
        SignalCase::StreamCookedCtrlC => {
            // The same keystroke as `CtrlCIsAByte`, with the terminal cooked:
            // the line discipline turns it into a signal to this process group,
            // which is why streaming must forward it.
            terminal.type_bytes(&[0x03]);
        }
        SignalCase::GraceExpiry
        | SignalCase::GuestExitsInGrace
        | SignalCase::UnknownStatus
        | SignalCase::ForcedNoticeStalled => {
            signal(child_pid, libc::SIGINT);
        }
    }

    if case == SignalCase::StreamBlockedOutput {
        // The documented residual (also stated in `main.rs`'s full-pipe
        // control): a blocking-pool write that was already dispatched cannot be
        // cancelled, and dropping the runtime waits for it, so the *process*
        // cannot finish exiting while its consumer is still stopped. Every
        // decision and every teardown step is already recorded above; draining
        // now only releases that syscall.
        wait_until("the forced teardown", SIGNAL_DEADLINE, || {
            signal_receipt_text(dir.path()).contains("stage=remove")
        });
        let mut pipe = child.get().stdout.take().expect("a piped stdout");
        let (drained, finished) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut sink = Vec::new();
            let result = pipe.read_to_end(&mut sink);
            let _ = drained.send((sink, result));
        });
        let _ = finished
            .recv_timeout(SIGNAL_DEADLINE)
            .expect("the case child never closed its stdout after the teardown");
    }
    let (status, stages) = case.expected();
    // Not `wait_within`: a hanging child is the failure a missing observation
    // looks like, so its receipt is what the report must show.
    let start = std::time::Instant::now();
    let reaped = loop {
        if let Some(reaped) = child.get().try_wait().expect("try_wait") {
            break reaped;
        }
        assert!(
            start.elapsed() < SIGNAL_DEADLINE,
            "{case:?}: the child did not exit within {SIGNAL_DEADLINE:?}; receipt:
{}",
            signal_receipt_text(dir.path())
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    };
    let text = signal_receipt_text(dir.path());
    let stderr = String::from_utf8_lossy(&stderr_reader.join().unwrap()).into_owned();
    assert_eq!(
        reaped.code(),
        Some(status),
        "{case:?}: {stderr}
{text}"
    );
    // 1. The terminal is restored, on every path including the forced one.
    assert_eq!(
        terminal_state(terminal.master_fd()),
        terminal.baseline,
        "{case:?}: the terminal must be restored"
    );
    // 2. The VM is torn down, in the mode the end demanded.
    for stage in stages {
        assert!(
            text.contains(&format!("stage={stage}")),
            "{case:?}: missing stage={stage} in:
{text}"
        );
    }
    let pid: u32 = receipt("runtime_pid")
        .expect("the owned runtime pid")
        .parse()
        .expect("a pid");
    assert!(
        process_is_gone(pid),
        "{case:?}: the owned runtime outlived the launcher"
    );
    // 3. The row's own evidence: what the guest was and was not told.
    match case {
        SignalCase::BeforeFirstPoll | SignalCase::GuestExitsInGrace => {
            assert_eq!(
                receipt("signal").as_deref(),
                Some("2"),
                "{case:?}: the forwarded signal must reach the guest:
{text}"
            );
        }
        SignalCase::Escalation => {
            // Only the first signal is forwarded: the second one *ends the
            // session* rather than being delivered, which is what "forces
            // teardown immediately" means. Its identity is what the status
            // proves — 143, not the 130 that reporting the forwarded signal
            // would give, and not the 130 that `grace-expiry` gives with the
            // same first signal.
            assert_eq!(
                receipt_lines_of(&text, "signal"),
                ["2"],
                "the interrupting signal is not forwarded, it ends the session: {text}"
            );
        }
        SignalCase::GraceExpiry | SignalCase::StreamBlockedOutput => {
            assert_eq!(receipt("signal").as_deref(), Some("2"), "{text}");
        }
        SignalCase::ForcedNoticeStalled => {
            // The launch's composition, not a description of it: the teardown
            // finished (`stage=*` above) while the notice was still blocked, and
            // the same notice arrived once the sink accepted it.
            assert_eq!(receipt("signal").as_deref(), Some("2"), "{text}");
            assert_eq!(
                receipt("notice").as_deref(),
                Some("stalled"),
                "the notice was written before the teardown, which is the hang this \
                 case exists for: {text}"
            );
            assert_eq!(
                receipt("notice_after_release").as_deref(),
                Some("delivered"),
                "the forced notice must still reach stderr once it accepts: {text}"
            );
        }
        SignalCase::UnknownStatus => {
            // The row this case exists for: a signal was forwarded and the
            // guest's own status is unknown, so nothing may be inferred from
            // it. `143`/`130` here would be the defect.
            assert_eq!(receipt("signal").as_deref(), Some("2"), "{text}");
            assert_eq!(
                receipt("status").as_deref(),
                Some("ok:-1"),
                "the unknown status must be reported as the guest gave it: {text}"
            );
        }
        SignalCase::CtrlCIsAByte => {
            assert_eq!(
                receipt("stdin").as_deref(),
                Some("03"),
                "the guest must receive the Ctrl-C byte as input: {text}"
            );
            assert!(
                receipt("signal").is_none(),
                "raw-mode Ctrl-C must never be forwarded as a signal: {text}"
            );
        }
        SignalCase::StreamCookedCtrlC => {
            // Both halves are falsifiable, because the streaming case's session
            // forwards stdin exactly as a direct launch does: a launcher that
            // passed the Ctrl-C byte through would record it as input, and one
            // that forwarded it twice would record two signals. The signal list
            // is compared whole rather than by its first line so a duplicate is
            // visible.
            assert_eq!(
                receipt_lines_of(&text, "signal"),
                ["2"],
                "a cooked Ctrl-C must reach the guest as exactly one signal: {text}"
            );
            assert!(
                receipt_lines_of(&text, "stdin").is_empty(),
                "the line discipline consumed the byte, so it is not input: {text}"
            );
        }
        SignalCase::TransportLossInGrace => {
            assert!(
                stderr.contains("the sandbox process ended"),
                "the transport loss must be named: {stderr}"
            );
            assert!(
                !text.contains("status=ok:143") && !text.contains("status=ok:130"),
                "a forwarded signal must never become a signal status after a transport loss: {text}"
            );
        }
        SignalCase::CleanupFailure => {
            assert!(
                stderr.contains("could not be torn down"),
                "the report must name the failed teardown: {stderr}"
            );
            assert!(
                stderr.contains("refused to kill"),
                "the failing stage must be named: {stderr}"
            );
        }
    }
    assert!(
        text.contains("status=ok:") || text.contains("error="),
        "{case:?}: the child must record how the session ended:
{text}"
    );
}
