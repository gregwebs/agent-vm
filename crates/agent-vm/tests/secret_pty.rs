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
//! That is the right behaviour: CI type-checks the release test profile
//! (`cargo check --release -p agent-vm --tests`) but never runs it, so do not
//! add a silent skip (review finding R7).

#![cfg(unix)]

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd as _;
use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::path::{Path, PathBuf};
use std::process::Command;
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

#[path = "support/pty.rs"]
mod pty;

use pty::{Action, Pty};

/// The hidden prompt the secret reader prints. Named here, not in the shared
/// helper: the helper is program-agnostic.
const PROMPT: &[u8] = b"(input is hidden)";

/// Spawn `command` under a fresh pty after applying this harness's isolation.
///
/// The child is deliberately **not** made a session leader or given the slave
/// as a controlling terminal: `is_terminal()` only needs the fds to be a tty,
/// and a session-leader death makes macOS revoke the slave, which would hide
/// the terminal state this harness exists to measure. This also matches how a
/// shell actually runs the binary (a foreground member of an existing session).
fn spawn_under_pty(home: &Path, command: &mut Command, record: Option<&Path>) -> io::Result<Pty> {
    command
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("AGENT_VM_STATE_DIR", home.join("state"))
        .env("NO_COLOR", "1")
        .current_dir(home);
    if let Some(record) = record {
        command.env("AGENT_VM_TEST_SECRET_RECORD", record);
    }
    Pty::spawn(command, PROMPT)
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
    let (status, output) = pty
        .drive(&Action::Write(&payload), Duration::from_secs(30))
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
    let (status, output) = pty
        .drive(&Action::Write(b"\x1b"), Duration::from_secs(30))
        .expect("drive the pty");
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
    let (status, output) = pty
        .drive(&Action::Write(&payload), Duration::from_secs(30))
        .expect("drive the pty");
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
    let leftover = pty.read_leftover();
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
        let before = pty.baseline_flags();
        let (status, _output) = pty
            .drive(&Action::Signal(signal), Duration::from_secs(30))
            .unwrap_or_else(|error| panic!("signal {signal}: {error}"));
        assert_eq!(
            status.signal(),
            Some(signal),
            "expected termination by the delivered signal (status {status:?})"
        );
        let after = pty.terminal_flags();
        assert_eq!(
            before, after,
            "signal {signal} left the terminal raw (lflag {before} -> {after})"
        );
    }
}

/// Finding R1 — once the hidden read has finished, the process must still be
/// terminable. `SignalGuard::drop` used to leave a signal-hook handler installed
/// that swallowed SIGINT/SIGTERM/SIGHUP/SIGQUIT, and `secret set` continues past
/// the read into the store, whose first act is the bounded wait on the inventory
/// lock (60 s under a PTY, #291). Holding it keeps the child alive in that
/// post-read window, and `SIGTERM` must still end it. The configured post-read
/// waits total about 20.2 s, inside the bound absent excessive scheduling delay.
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
    let _prompt = pty
        .wait_for_prompt(Duration::from_secs(30))
        .expect("the prompt");
    let payload = {
        let mut value = synthetic_value(16);
        value.push(b'\n');
        value
    };
    pty.write_all(&payload);
    // The reader's guard restores the terminal the moment the read loop returns,
    // so this is past the read and into the store's `flock`.
    pty.wait_for_restored_terminal(Duration::from_secs(10));
    // Let the guard drop finish (it restores the saved dispositions) before
    // relying on the restored one.
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        pty.is_running(),
        "the child should still be blocked on the inventory lock"
    );

    // Send repeatedly rather than once: the guard's own handler is still
    // installed for a few instructions after the terminal is restored, and a
    // signal caught there is swallowed by design. A process that has restored
    // its default disposition dies on one of these; one that has not, never
    // does (the historical R1 bug).
    let pid = pty.id().unwrap() as libc::pid_t;
    let mut output = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
        match pty.wait_for_exit(&mut output, Duration::from_millis(200)) {
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
        let _prompt = pty
            .wait_for_prompt(Duration::from_secs(30))
            .expect("the prompt");
        let pid = pty.id().unwrap() as libc::pid_t;
        assert_eq!(unsafe { libc::kill(pid, signal) }, 0);
        std::thread::sleep(Duration::from_millis(300));
        assert!(
            pty.is_running(),
            "signal {signal} terminated a process that had it set to SIG_IGN"
        );

        // The read must have continued: a value entered afterwards is delivered.
        let payload = {
            let mut value = synthetic_value(24);
            value.push(b'\n');
            value
        };
        pty.write_all(&payload);
        let mut output = Vec::new();
        let status = pty
            .wait_for_exit(&mut output, Duration::from_secs(30))
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
    let before = pty.baseline_flags();
    let _prompt = pty
        .wait_for_prompt(Duration::from_secs(30))
        .expect("the prompt");
    let pid = pty.id().unwrap() as libc::pid_t;
    assert_eq!(unsafe { libc::kill(pid, libc::SIGINT) }, 0);
    assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
    let mut output = Vec::new();
    let status = pty
        .wait_for_exit(&mut output, Duration::from_secs(10))
        .unwrap_or_else(|error| {
            panic!("an inherited SIG_IGN must not swallow a later default signal: {error}")
        });
    assert_eq!(
        status.signal(),
        Some(libc::SIGTERM),
        "expected termination by the default-disposition SIGTERM, got {status:?}: {}",
        String::from_utf8_lossy(&output)
    );
    let after = pty.terminal_flags();
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
    let (status, output) = pty
        .drive(&Action::Write(b""), Duration::from_secs(10))
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
    let (status, _output) = pty
        .drive(&Action::Write(b""), Duration::from_secs(10))
        .expect("a POLLHUP-only peer must not time the harness out");
    assert_eq!(status.code(), Some(7));
}

/// The shared PTY harness kills and reaps a child that is still running
/// when the test ends. A leaked process would outlive the suite; a `Drop` that
/// blocks would hang it.
#[test]
fn harness_cleanup_reaps_a_hung_child() {
    let home = tempfile::tempdir().unwrap();
    let mut pty = spawn_stand_in(home.path(), "printf '(input is hidden)'; sleep 60").unwrap();
    pty.wait_for_prompt(Duration::from_secs(10))
        .expect("the stand-in prompt");
    let started = Instant::now();
    drop(pty);
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "dropping the harness must not block on a live child"
    );
}

/// Ctrl-D is the canonical end-of-input under a terminal: it must finish the
/// hidden read within the deadline, never hang. Alone it supplies no value (a
/// closed error, no record); after a value it terminates the line, so the value
/// is stored exactly as `Enter` would store it.
#[test]
fn ctrl_d_ends_the_hidden_read_without_hanging() {
    // Ctrl-D with nothing before it: no value, closed error, no record.
    let home = tempfile::tempdir().unwrap();
    let record = home.path().join("record");
    let name = unique_name("ctrl-d-empty");
    let mut pty = spawn_secret_set(home.path(), &name, &record).expect("spawn under a pty");
    let started = Instant::now();
    let (status, output) = pty
        .drive(&Action::Write(b"\x04"), Duration::from_secs(30))
        .expect("Ctrl-D must end the read, not hang");
    let text = String::from_utf8_lossy(&output);
    assert_ne!(status.code(), Some(0), "no value must fail: {text}");
    assert!(
        text.contains("no value was supplied"),
        "Ctrl-D alone must report the abort message: {text}"
    );
    assert!(
        !record.exists(),
        "Ctrl-D with no value must not create a record"
    );
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "Ctrl-D must complete within the deadline"
    );
    pty.wait_for_restored_terminal(Duration::from_secs(5));

    // Ctrl-D after a value ends the line: the value is delivered as if Enter.
    let home = tempfile::tempdir().unwrap();
    let record = home.path().join("record");
    let value = synthetic_value(32);
    let mut payload = value.clone();
    payload.push(0x04);
    let mut pty =
        spawn_secret_set(home.path(), &unique_name("ctrl-d"), &record).expect("spawn under a pty");
    let (status, output) = pty
        .drive(&Action::Write(&payload), Duration::from_secs(30))
        .expect("Ctrl-D must end the read, not hang");
    let text = String::from_utf8_lossy(&output);
    assert_eq!(
        status.code(),
        Some(0),
        "a value ended by Ctrl-D must be accepted: {text}"
    );
    assert_eq!(
        std::fs::read_to_string(&record).unwrap_or_default(),
        expected_record(32),
        "the stored value must be exactly the bytes before Ctrl-D"
    );
    assert!(
        !output.windows(value.len()).any(|window| window == value),
        "the hidden value was echoed: {text}"
    );
    pty.wait_for_restored_terminal(Duration::from_secs(5));
}
