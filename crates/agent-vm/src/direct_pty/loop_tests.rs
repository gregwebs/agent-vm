//! The full loop over a stub guest and an `openpty` pair (§10.1's full-loop table):
//! real reader and writer threads, real terminal attributes, a scripted guest, and
//! the real feed → candidate → takeover path.
//!
//! A refusal is injected into the session's own `LiveRefusals` **after** the prompt
//! subscribed, which is exactly the baseline rule (R6): only a refusal whose count
//! grows after subscribing prompts. The grant handler is the real one; with no
//! runtime attached it answers `QueuedForBoot`, which is the sentence the prompt
//! draws, so `s` exercises the whole path without a VM.

use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use microsandbox::logs::{
    LogSource, NameSource, NetworkLogEvent, NetworkLogRecord, NetworkRefusal, RefusalLayer,
    RefusalSite,
};
use microsandbox::sandbox::exec::ExecEvent;
use microsandbox_types::Protocol;

use super::*;
use crate::access_prompt::{self, relay::Timings};
use crate::host_signals::{GuestControl, Supervision};

#[derive(Clone)]
struct StubControl {
    resizes: Arc<Mutex<Vec<(u16, u16)>>>,
    signals: Arc<Mutex<Vec<i32>>>,
}

impl GuestControl for StubControl {
    async fn forward(&self, signal: crate::host_signals::HostSignal) -> anyhow::Result<()> {
        self.signals.lock().unwrap().push(signal.number());
        Ok(())
    }
}

impl GuestTerminal for StubControl {
    async fn resize(&self, rows: u16, cols: u16) -> anyhow::Result<()> {
        self.resizes.lock().unwrap().push((rows, cols));
        Ok(())
    }
}

struct StubInput {
    written: Mutex<Vec<u8>>,
}

impl GuestInput for StubInput {
    async fn write(&self, bytes: Vec<u8>) -> anyhow::Result<()> {
        self.written.lock().unwrap().extend(bytes);
        Ok(())
    }
}

struct StubGuest {
    events: tokio::sync::mpsc::UnboundedReceiver<ExecEvent>,
    exit_signal: Option<i32>,
}

impl GuestEvents for StubGuest {
    async fn recv(&mut self) -> Option<ExecEvent> {
        self.events.recv().await
    }

    fn termination_signal(&self) -> Option<i32> {
        self.exit_signal
    }
}

/// Everything the test drives: the pty pair, the scripted guest and the stubs.
struct Harness {
    master: OwnedFd,
    slave: OwnedFd,
    events: Option<tokio::sync::mpsc::UnboundedSender<ExecEvent>>,
    guest: Option<StubGuest>,
    control: StubControl,
    input: Arc<StubInput>,
    refusals: Arc<crate::refusal::feed::LiveRefusals>,
    /// What the writer wrote, as the test's terminal emulator sees it.
    seen: Vec<u8>,
}

impl Harness {
    fn new() -> Self {
        let mut master: libc::c_int = -1;
        let mut slave: libc::c_int = -1;
        // SAFETY: `openpty` writes two descriptors into the live locals; both are
        // taken into `OwnedFd` immediately.
        let rc = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, 0, "openpty: {}", std::io::Error::last_os_error());
        // SAFETY: each descriptor `openpty` produced is open and unowned.
        let master = unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(master) };
        // SAFETY: as above for the slave side.
        let slave = unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(slave) };
        let size = libc::winsize {
            ws_row: 30,
            ws_col: 100,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: `slave` is an open terminal and `TIOCSWINSZ` only reads the
        // `winsize` behind the pointer.
        assert_ne!(
            unsafe { libc::ioctl(slave.as_raw_fd(), libc::TIOCSWINSZ, &size) },
            -1
        );
        // The master is read by the test's terminal emulator, which must never
        // block a test thread on an idle pty.
        let flags = unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0);
        assert_ne!(
            unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
            -1
        );
        let (events, receiver) = tokio::sync::mpsc::unbounded_channel();
        let session = crate::refusal::SessionId::parse("3f9a12c4").unwrap();
        let refusals = crate::refusal::feed::LiveRefusals::new(
            crate::refusal::SessionRefusals::new(crate::refusal::SessionInfo {
                id: session,
                pid: 1,
                started_ms: 0,
                socket: true,
            }),
        );
        Self {
            master,
            slave,
            events: Some(events),
            guest: Some(StubGuest {
                events: receiver,
                exit_signal: None,
            }),
            control: StubControl {
                resizes: Arc::new(Mutex::new(Vec::new())),
                signals: Arc::new(Mutex::new(Vec::new())),
            },
            input: Arc::new(StubInput {
                written: Mutex::new(Vec::new()),
            }),
            refusals,
            seen: Vec::new(),
        }
    }

    fn send(&self, event: ExecEvent) {
        self.events
            .as_ref()
            .expect("the event stream is open")
            .send(event)
            .expect("the session is running");
    }

    /// End the guest's event stream without an exit: a launcher-side end.
    fn close_events(&mut self) {
        self.events = None;
    }

    fn take_guest(&mut self) -> StubGuest {
        self.guest.take().expect("the guest is taken once")
    }

    fn fds(&self) -> HostFds {
        HostFds {
            terminal: duplicate(self.slave.as_raw_fd()).expect("duplicate the slave"),
            output: duplicate(self.slave.as_raw_fd()).expect("duplicate the slave"),
        }
    }

    /// The prompt's source, over this harness's own live feed.
    fn source(&self, root: &tempfile::TempDir) -> access_prompt::Source {
        let project = crate::project::ProjectDir::from_path_for_tests(root.path()).unwrap();
        let store = crate::allowances::StoreHandle::at_for_tests(&root.path().join("store"));
        let plan = crate::network::plan_for_tests(&[], false).live_policy_plan(None);
        let allowances = crate::allowances::LiveAllowances::new(&project, store, plan);
        access_prompt::Source::from_feed(access_prompt::Feed {
            refusals: Arc::clone(&self.refusals),
            allowances,
            session: crate::refusal::SessionId::parse("3f9a12c4").unwrap(),
            hint: Arc::new(crate::refusal::feed::Hint::new()),
        })
    }

    /// Wait until the session is running, so a refusal injected now is one the
    /// prompt sees as new (R6's baseline rule).
    async fn started(&mut self) {
        let marker = b"PROMPT-READY\r\n".to_vec();
        self.send(ExecEvent::Stdout(marker.clone().into()));
        assert!(
            self.wait_for(b"PROMPT-READY").await,
            "the session must forward"
        );
    }

    /// A refusal recorded after the prompt subscribed, which is what prompts (R6).
    fn refuse(&self) {
        let at = chrono::DateTime::from_timestamp_millis(1_760_000_000_000).unwrap();
        let record = NetworkLogRecord {
            v: 1,
            t: at,
            s: LogSource::Network,
            event: NetworkLogEvent::Refusal(NetworkRefusal {
                site: RefusalSite::TcpSyn,
                layer: RefusalLayer::Tenant,
                protocol: Protocol::Tcp,
                dst_ip: Some("203.0.113.10".parse().unwrap()),
                dst_port: Some(443),
                name: None,
                name_source: NameSource::Absent,
                revision: 1,
                credential: None,
                location: None,
                reason: None,
            }),
        };
        let mut dirty = false;
        assert!(self.refusals.ingest(&record, &mut dirty, 1_760_000_000_000));
    }

    /// A TLS hostname refusal: `grantable_destination` accepts it, and the launch's
    /// own derivation refuses to intercept its port, so the offer is the next-launch
    /// one (the #491 case).
    fn refuse_hostname(&self, name: &str, port: u16) {
        let at = chrono::DateTime::from_timestamp_millis(1_760_000_000_000).unwrap();
        let record = NetworkLogRecord {
            v: 1,
            t: at,
            s: LogSource::Network,
            event: NetworkLogEvent::Refusal(NetworkRefusal {
                site: RefusalSite::TlsSni,
                layer: RefusalLayer::Tenant,
                protocol: Protocol::Tcp,
                dst_ip: Some("203.0.113.10".parse().unwrap()),
                dst_port: Some(port),
                name: Some(name.to_owned()),
                name_source: NameSource::Sni,
                revision: 1,
                credential: None,
                location: None,
                reason: None,
            }),
        };
        let mut dirty = false;
        assert!(self.refusals.ingest(&record, &mut dirty, 1_760_000_000_000));
    }

    fn pump(&mut self) -> Vec<u8> {
        let mut fresh = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            // SAFETY: `master` is this harness's open peer, and `buffer` is a live
            // writable slice of its own length.
            let count = unsafe {
                libc::read(
                    self.master.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            };
            if count <= 0 {
                break;
            }
            fresh.extend_from_slice(&buffer[..count as usize]);
        }
        self.seen.extend_from_slice(&fresh);
        fresh
    }

    async fn wait_for(&mut self, needle: &[u8]) -> bool {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            self.pump();
            if self
                .seen
                .windows(needle.len())
                .any(|window| window == needle)
            {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// The prompt's expected cursor position, from the frame it wrote.
    fn answer_cpr(&mut self) {
        let needle = b"\x1b[6n";
        let end = self
            .seen
            .windows(needle.len())
            .rposition(|window| window == needle)
            .expect("the enter frame asks for the position")
            + needle.len();
        let before = &self.seen[..end - needle.len()];
        let move_at = before
            .windows(2)
            .rposition(|window| window == b"\x1b[")
            .expect("a cursor move");
        let tail = String::from_utf8_lossy(&before[move_at + 2..]);
        let row: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
        let reply = format!("\x1b[{};3R", row.parse::<u16>().expect("a row"));
        self.type_keys(reply.as_bytes());
    }

    /// Answer the prompt, robustly: the confirmation and the key are sent in a
    /// short loop, because the writer's confirmation of the enter frame is not
    /// observable from outside the session and a reply that arrives before it is
    /// (correctly) treated as typing. Repeating both is harmless — a key that does
    /// not answer is typing — so the loop stops as soon as the leave is written.
    async fn answer_prompt(&mut self, key: u8) -> bool {
        for _ in 0..40 {
            self.answer_cpr();
            // The guard's own 700 ms of quiet (R17) must pass between the reply
            // (which is typing if it arrives after visibility) and the key.
            tokio::time::sleep(Duration::from_millis(800)).await;
            self.type_keys(&[key]);
            let deadline = tokio::time::Instant::now() + Duration::from_millis(300);
            while tokio::time::Instant::now() < deadline {
                self.pump();
                // A main-screen guest leaves with `?1049l`; an alternate-screen guest
                // with DECRC (`ESC 8`).
                if self.seen.windows(8).any(|window| window == b"\x1b[?1049l")
                    || self.seen.windows(2).any(|window| window == b"\x1b8")
                {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
        false
    }

    fn type_keys(&mut self, bytes: &[u8]) {
        // SAFETY: `master` is this harness's open peer and `bytes` is a live slice.
        let written =
            unsafe { libc::write(self.master.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
        assert_eq!(written, bytes.len() as isize);
    }

    fn attributes(&self) -> libc::termios {
        // SAFETY: `termios` is plain data whose all-zero state is valid.
        let mut attributes: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: `slave` is an open terminal.
        assert_eq!(
            unsafe { libc::tcgetattr(self.slave.as_raw_fd(), &mut attributes) },
            0
        );
        attributes
    }
}

/// The production timings. The typing guard's 700 ms is a requirement (R17), not a
/// knob a test may shrink: the loop tests wait it out, and the unit tests cover the
/// guard's arithmetic with injected instants.
fn fast_timings() -> Timings {
    Timings::default()
}

fn parked() -> impl Future<Output = microsandbox::MicrosandboxResult<std::process::ExitStatus>> {
    std::future::pending()
}

fn mode_of(attributes: &libc::termios) -> (libc::tcflag_t, libc::tcflag_t, libc::tcflag_t) {
    (attributes.c_iflag, attributes.c_oflag, attributes.c_lflag)
}

#[tokio::test]
async fn with_the_prompt_off_the_forwarded_bytes_are_identical() {
    // R1/R8's reviewable claim: with no prompt the session forwards exactly today's
    // bytes, and with one but no refusal it forwards the same bytes.
    let guest_bytes = b"first \x1b[31mred\x1b[0m\r\n\xc3\xa9\r\n".to_vec();
    let mut results = Vec::new();
    for with_prompt in [false, true] {
        let mut harness = Harness::new();
        let root = tempfile::tempdir().unwrap();
        let source = with_prompt.then(|| harness.source(&root));
        harness.send(ExecEvent::Stdout(guest_bytes.clone().into()));
        harness.send(ExecEvent::Exited { code: 0 });
        let fds = harness.fds();
        let mut supervision = Supervision::legacy();
        let mut guest = harness.take_guest();
        let end = run_with(
            &mut guest,
            harness.control.clone(),
            Arc::clone(&harness.input),
            fds,
            parked(),
            &mut supervision,
            source,
            fast_timings(),
        )
        .await
        .expect("the session ends");
        assert!(matches!(end, SessionEnd::Guest { code: 0, .. }), "{end:?}");
        let _ = harness.pump();
        results.push(harness.seen.clone());
    }
    assert_eq!(results[0], guest_bytes);
    assert_eq!(
        results[1], results[0],
        "with a prompt and no refusal the bytes are identical"
    );
}

#[tokio::test]
async fn a_refusal_prompts_and_d_refuses_without_touching_the_guest() {
    let mut harness = Harness::new();
    let root = tempfile::tempdir().unwrap();
    let source = harness.source(&root);
    let before = mode_of(&harness.attributes());
    let fds = harness.fds();
    let mut supervision = Supervision::legacy();
    let mut guest = harness.take_guest();
    let input = Arc::clone(&harness.input);
    let control = harness.control.clone();
    let session = tokio::spawn(async move {
        run_with(
            &mut guest,
            control,
            input,
            fds,
            parked(),
            &mut supervision,
            Some(source),
            fast_timings(),
        )
        .await
    });
    harness.send(ExecEvent::Stdout(b"GUEST-1\r\n".to_vec().into()));
    assert!(harness.wait_for(b"GUEST-1").await);
    // Only now does the refusal arrive: the baseline rule (R6).
    harness.refuse();
    assert!(
        harness
            .wait_for(b"the sandbox refused a network request")
            .await,
        "the prompt must appear"
    );
    assert!(harness.seen.windows(9).any(|window| window == b"tcp 203.0"));
    assert!(
        harness.answer_prompt(b'd').await,
        "the leave restores; seen tail: {:?}",
        String::from_utf8_lossy(&harness.seen[harness.seen.len().saturating_sub(400)..])
    );
    // Output written during the takeover arrives after the leave.
    harness.send(ExecEvent::Stdout(b"HELD-AFTER\r\n".to_vec().into()));
    assert!(harness.wait_for(b"HELD-AFTER").await);
    let leave = harness
        .seen
        .windows(8)
        .rposition(|window| window == b"\x1b[?1049l")
        .unwrap();
    let held = harness
        .seen
        .windows(10)
        .rposition(|window| window == b"HELD-AFTER")
        .unwrap();
    assert!(leave < held, "held output follows the leave");
    harness.send(ExecEvent::Exited { code: 0 });
    let end = session.await.expect("the task").expect("the session ends");
    assert!(matches!(end, SessionEnd::Guest { code: 0, .. }));
    // `d` never reached the guest.
    assert!(
        harness.input.written.lock().unwrap().is_empty(),
        "no prompt input reached the guest"
    );
    // And the terminal is exactly as it was.
    assert_eq!(mode_of(&harness.attributes()), before);
}

#[tokio::test]
async fn output_arriving_while_the_leave_is_unconfirmed_reaches_the_terminal() {
    // Finding 2 as a full-loop regression: a stalled terminal keeps the leave
    // unconfirmed, and a guest frame that arrives in that window must still reach
    // the terminal behind the leave, in order. The old code held it and dropped it
    // when the confirmation arrived.
    let mut harness = Harness::new();
    let root = tempfile::tempdir().unwrap();
    let source = harness.source(&root);
    let fds = harness.fds();
    let mut supervision = Supervision::legacy();
    let (input, control) = (Arc::clone(&harness.input), harness.control.clone());
    let mut guest = harness.take_guest();
    let session = tokio::spawn(async move {
        run_with(
            &mut guest,
            control,
            input,
            fds,
            parked(),
            &mut supervision,
            Some(source),
            Timings::default(),
        )
        .await
    });
    harness.started().await;
    harness.refuse();
    assert!(
        harness
            .wait_for(b"the sandbox refused a network request")
            .await
    );
    // A large frame the prompt must hold, so the terminal's small buffer fills and
    // the writer cannot confirm the leave until this test reads.
    let held = vec![b'H'; 64 * 1024];
    harness.send(ExecEvent::Stdout(held.clone().into()));
    harness.answer_cpr();
    tokio::time::sleep(Duration::from_millis(800)).await;
    harness.type_keys(b"d");
    // The prompt is closing; the leave is queued but the stalled terminal has not
    // accepted it. This frame arrives in exactly that window.
    let late = b"LATE-AFTER-LEAVE".to_vec();
    harness.send(ExecEvent::Stdout(late.clone().into()));
    // Now drain the terminal, so the writer can finish the leave and the drain.
    let _ = harness.wait_for(b"LATE-AFTER-LEAVE").await;
    let leave = harness
        .seen
        .windows(8)
        .rposition(|window| window == b"\x1b[?1049l")
        .expect("the leave frame");
    let late_at = harness
        .seen
        .windows(late.len())
        .rposition(|window| window == late.as_slice())
        .expect("the late frame must not be dropped");
    assert!(leave < late_at, "the late frame follows the leave");
    // The guest exits once its output has drained.
    harness.send(ExecEvent::Exited { code: 0 });
    let end = tokio::time::timeout(Duration::from_secs(10), session)
        .await
        .expect("the session ends")
        .expect("the task")
        .expect("the session's own end");
    assert!(matches!(end, SessionEnd::Guest { code: 0, .. }), "{end:?}");
}

#[tokio::test]
async fn s_grants_through_the_same_handler_the_socket_uses() {
    let mut harness = Harness::new();
    let root = tempfile::tempdir().unwrap();
    let source = harness.source(&root);
    let fds = harness.fds();
    let mut supervision = Supervision::legacy();
    let (input, control) = (Arc::clone(&harness.input), harness.control.clone());
    let mut guest = harness.take_guest();
    let session = tokio::spawn(async move {
        run_with(
            &mut guest,
            control,
            input,
            fds,
            parked(),
            &mut supervision,
            Some(source),
            fast_timings(),
        )
        .await
    });
    harness.started().await;
    harness.refuse();
    assert!(
        harness
            .wait_for(b"the sandbox refused a network request")
            .await
    );
    // With no runtime attached the handler queues the grant, so the result sentence
    // says `accepted` and points at the command that confirms it.
    assert!(harness.answer_prompt(b's').await, "the leave restores");
    assert!(
        harness.wait_for(b"accepted").await,
        "the result sentence is drawn"
    );
    assert!(harness.wait_for(b"agent-vm access allowances").await);
    harness.send(ExecEvent::Exited { code: 0 });
    let end = session.await.expect("the task").expect("the session ends");
    assert!(matches!(end, SessionEnd::Guest { code: 0, .. }));
    assert!(harness.input.written.lock().unwrap().is_empty());
}

#[test]
fn the_pump_keeps_a_pending_confirmation_through_a_redraw() {
    // M13: the helper's test would pass even if the pump stopped using it, so this
    // pins the pump's own line: a `Redraw`'s `None` may not be assigned to the slot.
    // The test modules are declared at the end of the file; the hooks appear earlier,
    // so the split is at the module, not at the first `#[cfg(test)]`.
    let source = include_str!("../direct_pty.rs");
    let production = &source[..source
        .find("#[cfg(test)]\nmod tests {")
        .expect("direct_pty.rs has a test module")];
    assert!(
        production.contains("hold_confirmation(&mut slots.takeover_ack, written)"),
        "the pump must route a frame's confirmation through the helper"
    );
    assert!(
        !production.contains("slots.takeover_ack = written"),
        "an unconditional assignment drops a pending Enter/Leave confirmation"
    );
}

#[test]
fn a_redraw_never_takes_the_confirmation_slot_from_an_enter_or_leave() {
    // Finding 3: the pump assigned `takeover_ack = written` unconditionally, so a
    // `Redraw` queued while an `Enter` (or `Leave`) was unconfirmed set the slot to
    // `None` and the takeover waited for a confirmation that could never arrive.
    let (_pending_tx, pending) = tokio::sync::oneshot::channel::<u64>();
    let mut slot = Some(pending);
    hold_confirmation(&mut slot, None);
    assert!(
        slot.is_some(),
        "a frame with no confirmation must leave the pending one in place"
    );
    // A real confirmation replaces the slot: only one is ever outstanding.
    let (confirm_tx, confirm) = tokio::sync::oneshot::channel::<u64>();
    hold_confirmation(&mut slot, Some(confirm));
    confirm_tx.send(7).expect("the replacement is live");
    assert_eq!(
        slot.take().expect("a receiver").blocking_recv().ok(),
        Some(7)
    );
}

#[tokio::test]
async fn a_guest_exit_during_a_prompt_ends_with_the_guests_own_state() {
    let mut harness = Harness::new();
    let root = tempfile::tempdir().unwrap();
    let source = harness.source(&root);
    let fds = harness.fds();
    let mut supervision = Supervision::legacy();
    let (input, control) = (Arc::clone(&harness.input), harness.control.clone());
    let mut guest = harness.take_guest();
    let session = tokio::spawn(async move {
        run_with(
            &mut guest,
            control,
            input,
            fds,
            parked(),
            &mut supervision,
            Some(source),
            fast_timings(),
        )
        .await
    });
    harness.started().await;
    harness.refuse();
    assert!(
        harness
            .wait_for(b"the sandbox refused a network request")
            .await
    );
    // The guest exits while the question is up; a held frame must still follow the
    // leave, before the drain completes (R27).
    harness.send(ExecEvent::Stdout(b"TAIL-AFTER-EXIT\r\n".to_vec().into()));
    harness.send(ExecEvent::Exited { code: 7 });
    let end = session.await.expect("the task").expect("the session ends");
    assert!(matches!(end, SessionEnd::Guest { code: 7, .. }), "{end:?}");
    let _ = harness.pump();
    assert!(
        harness
            .seen
            .windows(8)
            .any(|window| window == b"\x1b[?1049l")
    );
    let leave = harness
        .seen
        .windows(8)
        .rposition(|window| window == b"\x1b[?1049l")
        .unwrap();
    let tail = harness
        .seen
        .windows(15)
        .rposition(|window| window == b"TAIL-AFTER-EXIT")
        .expect("the held frame is written");
    assert!(leave < tail, "the leave precedes the held output");
}

#[tokio::test]
async fn a_launcher_error_during_a_prompt_writes_the_host_restore_once() {
    let mut harness = Harness::new();
    let root = tempfile::tempdir().unwrap();
    let source = harness.source(&root);
    let before = mode_of(&harness.attributes());
    let fds = harness.fds();
    let mut supervision = Supervision::legacy();
    let (input, control) = (Arc::clone(&harness.input), harness.control.clone());
    let mut guest = harness.take_guest();
    let session = tokio::spawn(async move {
        run_with(
            &mut guest,
            control,
            input,
            fds,
            parked(),
            &mut supervision,
            Some(source),
            fast_timings(),
        )
        .await
    });
    harness.started().await;
    harness.refuse();
    assert!(
        harness
            .wait_for(b"the sandbox refused a network request")
            .await
    );
    // The event stream ends without an exit: a launcher error, with a prompt up.
    harness.close_events();
    let end = session.await.expect("the task");
    assert!(
        end.is_err(),
        "a stream that ends without a status is an error"
    );
    let _ = harness.pump();
    let restore = crate::access_prompt::screen::host_restore();
    let occurrences = harness
        .seen
        .windows(restore.len())
        .filter(|window| *window == restore.as_slice())
        .count();
    assert_eq!(occurrences, 1, "the host restore is written exactly once");
    assert_eq!(mode_of(&harness.attributes()), before);
}

#[tokio::test]
async fn a_stalled_terminal_still_lets_a_runtime_loss_return() {
    // R28/AC19's shape: the terminal stops reading, the writer parks inside a
    // `write(2)`, and a runtime loss must still return the session promptly. The
    // host restore cannot be written while the descriptor is full — that is stated
    // (a terminal that never reads cannot be written to) — but the wait is bounded.
    let mut harness = Harness::new();
    let root = tempfile::tempdir().unwrap();
    let source = harness.source(&root);
    let fds = harness.fds();
    let mut supervision = Supervision::legacy();
    let (input, control) = (Arc::clone(&harness.input), harness.control.clone());
    let (runtime_exit, runtime) = tokio::sync::oneshot::channel::<
        microsandbox::MicrosandboxResult<std::process::ExitStatus>,
    >();
    let mut guest = harness.take_guest();
    let session = tokio::spawn(async move {
        run_with(
            &mut guest,
            control,
            input,
            fds,
            async move {
                match runtime.await {
                    Ok(outcome) => outcome,
                    Err(_) => Err(microsandbox::MicrosandboxError::Runtime(
                        "the runtime is gone".to_owned(),
                    )),
                }
            },
            &mut supervision,
            Some(source),
            fast_timings(),
        )
        .await
    });
    harness.started().await;
    // More than the hold and the writer's queue, with nothing reading the master.
    for _ in 0..40 {
        harness.send(ExecEvent::Stdout(vec![b'x'; 64 * 1024].into()));
    }
    harness.refuse();
    tokio::time::sleep(Duration::from_millis(300)).await;
    // The runtime dies while the terminal is stalled.
    let _ = runtime_exit.send(Err(microsandbox::MicrosandboxError::Runtime(
        "the runtime is gone".to_owned(),
    )));
    let end = tokio::time::timeout(Duration::from_secs(5), session)
        .await
        .expect("a stalled terminal must not hang the session")
        .expect("the task");
    assert!(
        end.is_err(),
        "runtime loss without a guest status is a failure"
    );
}

#[tokio::test]
async fn an_alternate_screen_guest_is_nudged_with_two_resizes_and_a_main_screen_one_is_not() {
    // F4: on a real boot the alternate-screen guest never saw the nudge, so it was
    // never asked to redraw. The stub records every resize the loop sends: the nudge is
    // (rows, cols-1), then the host's size measured after the wait.
    for (prelude, expect_nudge) in [(b"\x1b[?1049h".as_slice(), true), (b"".as_slice(), false)] {
        let mut harness = Harness::new();
        let root = tempfile::tempdir().unwrap();
        let source = harness.source(&root);
        let resizes = Arc::clone(&harness.control.resizes);
        let fds = harness.fds();
        let mut supervision = Supervision::legacy();
        let (input, control) = (Arc::clone(&harness.input), harness.control.clone());
        let mut guest = harness.take_guest();
        if !prelude.is_empty() {
            harness.send(ExecEvent::Stdout(prelude.to_vec().into()));
        }
        let session = tokio::spawn(async move {
            run_with(
                &mut guest,
                control,
                input,
                fds,
                parked(),
                &mut supervision,
                Some(source),
                Timings::default(),
            )
            .await
        });
        harness.started().await;
        harness.refuse();
        assert!(
            harness
                .wait_for(b"the sandbox refused a network request")
                .await
        );
        assert!(harness.answer_prompt(b'd').await, "the leave restores");
        // Give the nudge's 100 ms window and the second resize time to run.
        tokio::time::sleep(Duration::from_millis(400)).await;
        harness.send(ExecEvent::Exited { code: 0 });
        let end = tokio::time::timeout(Duration::from_secs(10), session)
            .await
            .expect("the session ends")
            .expect("the task")
            .expect("the session's own end");
        assert!(matches!(end, SessionEnd::Guest { code: 0, .. }), "{end:?}");
        let recorded: Vec<(u16, u16)> = resizes.lock().unwrap().clone();
        // The session's first resize sets the host geometry; everything after it is
        // the nudge (or nothing).
        let after_initial: Vec<(u16, u16)> = recorded.iter().copied().skip(1).collect();
        if expect_nudge {
            assert_eq!(
                after_initial.len(),
                2,
                "the nudge must send two resizes: {recorded:?}"
            );
            assert_eq!(
                after_initial[0],
                (30, 99),
                "the nudge narrows by one column: {recorded:?}"
            );
            assert_eq!(
                after_initial[1],
                (30, 100),
                "the second resize restores the host's size: {recorded:?}"
            );
        } else {
            assert!(
                after_initial.is_empty(),
                "a main-screen guest is never nudged: {recorded:?}"
            );
        }
    }
}

#[tokio::test]
async fn a_forced_end_during_a_prompt_writes_the_host_restore_once_on_both_screens() {
    // F2: on a real boot the forced row ended with the ordinary Leave and no host
    // restore, because the first forwarded SIGINT killed the (unarmed) guest probe — a
    // guest exit, R27's path, not a forced end. This drives the forced path itself: the
    // session is forced while the question is up, and the writer must give the terminal
    // back exactly once, on both screens.
    for prelude in [b"".as_slice(), b"\x1b[?1049h".as_slice()] {
        let mut harness = Harness::new();
        let root = tempfile::tempdir().unwrap();
        let source = harness.source(&root);
        let fds = harness.fds();
        let (input, control) = (Arc::clone(&harness.input), harness.control.clone());
        let (arrivals, queue) = tokio::sync::mpsc::unbounded_channel();
        let mut guest = harness.take_guest();
        if !prelude.is_empty() {
            harness.send(ExecEvent::Stdout(prelude.to_vec().into()));
        }
        let session = tokio::spawn(async move {
            let mut supervision = Supervision::for_test(queue, std::time::Duration::from_secs(60));
            run_with(
                &mut guest,
                control,
                input,
                fds,
                parked(),
                &mut supervision,
                Some(source),
                Timings::default(),
            )
            .await
        });
        harness.started().await;
        harness.refuse();
        assert!(
            harness
                .wait_for(b"the sandbox refused a network request")
                .await
        );
        // The question is up; two interrupts force the end.
        arrivals
            .send(crate::host_signals::HostSignal::for_test(libc::SIGINT))
            .expect("the queue is open");
        arrivals
            .send(crate::host_signals::HostSignal::for_test(libc::SIGINT))
            .expect("the queue is open");
        let end = tokio::time::timeout(Duration::from_secs(10), session)
            .await
            .expect("a forced end must not hang")
            .expect("the task")
            .expect("the session's forced end");
        assert!(matches!(end, SessionEnd::Forced(_)), "{end:?}");
        let _ = harness.pump();
        let restore = crate::access_prompt::screen::host_restore();
        let occurrences = harness
            .seen
            .windows(restore.len())
            .filter(|window| *window == restore.as_slice())
            .count();
        assert_eq!(
            occurrences,
            1,
            "the host restore must be written exactly once (prelude {prelude:?}): {:?}",
            String::from_utf8_lossy(&harness.seen[harness.seen.len().saturating_sub(400)..])
        );
        assert!(
            harness.seen.ends_with(&restore),
            "the host restore must be the last thing written"
        );
    }
}

#[tokio::test]
async fn p_on_the_project_next_launch_offer_writes_the_record_and_shows_the_result() {
    // F3: on a real boot `p` on the #491 offer (a hostname whose port this launch did
    // not intercept) produced no result sentence and no record. This drives that offer
    // through the real prompt, the real handler and the real store.
    let mut harness = Harness::new();
    let root = tempfile::tempdir().unwrap();
    let source = harness.source(&root);
    let fds = harness.fds();
    let mut supervision = Supervision::legacy();
    let (input, control) = (Arc::clone(&harness.input), harness.control.clone());
    let mut guest = harness.take_guest();
    let session = tokio::spawn(async move {
        run_with(
            &mut guest,
            control,
            input,
            fds,
            parked(),
            &mut supervision,
            Some(source),
            Timings::default(),
        )
        .await
    });
    harness.started().await;
    // A TLS hostname on a port the launch did not intercept: the offer is the
    // next-launch one.
    harness.refuse_hostname("blocked.example", 443);
    assert!(
        harness
            .wait_for(b"the sandbox refused a network request")
            .await
    );
    assert!(
        harness.wait_for(b"from the next launch").await,
        "the #491 offer must be the next-launch one"
    );
    assert!(
        !harness
            .seen
            .windows(9)
            .any(|window| window == b"  s  allow"),
        "`s` must not be offered"
    );
    // Answer `p` once the guard is satisfied.
    harness.answer_cpr();
    tokio::time::sleep(Duration::from_millis(800)).await;
    harness.type_keys(b"p");
    assert!(
        harness.wait_for(b"recorded").await,
        "the result sentence must be drawn: {:?}",
        String::from_utf8_lossy(&harness.seen[harness.seen.len().saturating_sub(600)..])
    );
    assert!(
        harness.wait_for(b"next launch").await,
        "the result must say the allowance applies at the next launch"
    );
    // The store holds the record (the prompt's grant went through the real handler).
    let store = root.path().join("store").join("allowances.json");
    let contents = std::fs::read_to_string(&store).unwrap_or_default();
    assert!(
        contents.contains("blocked.example"),
        "the project record must be written: {contents:?}"
    );
    harness.send(ExecEvent::Exited { code: 0 });
    let _ = tokio::time::timeout(Duration::from_secs(10), session)
        .await
        .expect("the session ends");
}

#[tokio::test]
async fn one_cursor_reply_then_a_quiet_key_answers_on_the_real_loop() {
    // The driver's shape: answer the enter frame's request **once**, wait for the
    // ready line to be the latest status, then type one key. A driver that answered
    // repeatedly would manufacture host input and the guard would never settle (H15).
    let mut harness = Harness::new();
    let root = tempfile::tempdir().unwrap();
    let source = harness.source(&root);
    let fds = harness.fds();
    let mut supervision = Supervision::legacy();
    let (input, control) = (Arc::clone(&harness.input), harness.control.clone());
    let mut guest = harness.take_guest();
    let session = tokio::spawn(async move {
        run_with(
            &mut guest,
            control,
            input,
            fds,
            parked(),
            &mut supervision,
            Some(source),
            Timings::default(),
        )
        .await
    });
    harness.started().await;
    harness.refuse();
    assert!(
        harness
            .wait_for(b"the sandbox refused a network request")
            .await
    );
    // Exactly one reply to the one request, as a terminal sends it.
    harness.answer_cpr();
    // "ready" must become the latest status within the guard's window.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        harness.pump();
        let text = String::from_utf8_lossy(&harness.seen).into_owned();
        let ready = text.rfind("ready for your answer");
        let stop = text.rfind("stop typing to answer");
        if ready.is_some() && ready > stop {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the ready line never became the latest status: {:?}",
            &text[text.len().saturating_sub(400)..]
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // One quiet key answers.
    harness.type_keys(b"d");
    assert!(harness.wait_for(b"\x1b[?1049l").await, "the leave restores");
    harness.send(ExecEvent::Exited { code: 0 });
    let _ = tokio::time::timeout(Duration::from_secs(10), session)
        .await
        .expect("the session ends");
}

#[tokio::test]
async fn a_reply_that_arrives_before_the_enter_is_confirmed_still_reaches_ready() {
    // The other order a real terminal can produce: the reply is read while the enter
    // is still unconfirmed, so it is typing (no visibility confirmation yet). The
    // question must still become visible (the 1 s fallback) and draw "ready" — a
    // driver that waited for "ready" before answering would deadlock, which is why the
    // one-shot rule is about *how many* replies, not when the first lands.
    let mut harness = Harness::new();
    let root = tempfile::tempdir().unwrap();
    let source = harness.source(&root);
    let fds = harness.fds();
    let mut supervision = Supervision::legacy();
    let (input, control) = (Arc::clone(&harness.input), harness.control.clone());
    let mut guest = harness.take_guest();
    let session = tokio::spawn(async move {
        run_with(
            &mut guest,
            control,
            input,
            fds,
            parked(),
            &mut supervision,
            Some(source),
            Timings::default(),
        )
        .await
    });
    harness.started().await;
    harness.refuse();
    // Reply as soon as the enter frame's request appears — before any confirmation.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        harness.pump();
        if harness.seen.windows(4).any(|window| window == b"\x1b[6n") {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the enter never asked"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    harness.answer_cpr();
    // The fallback (1 s) plus the guard (0.7 s) must bring "ready" as the latest line.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(6);
    loop {
        harness.pump();
        let text = String::from_utf8_lossy(&harness.seen).into_owned();
        let ready = text.rfind("ready for your answer");
        let stop = text.rfind("stop typing to answer");
        if ready.is_some() && ready > stop {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the ready line never became the latest status: {:?}",
            &text[text.len().saturating_sub(400)..]
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    harness.type_keys(b"d");
    assert!(harness.wait_for(b"\x1b[?1049l").await, "the leave restores");
    harness.send(ExecEvent::Exited { code: 0 });
    let _ = tokio::time::timeout(Duration::from_secs(10), session)
        .await
        .expect("the session ends");
}
