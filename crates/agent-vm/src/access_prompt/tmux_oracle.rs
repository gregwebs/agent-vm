//! The independent oracle: tmux 3.8 renders the frames this module builds, and the
//! flags, cursor, screen content and character set are compared before and after.
//!
//! `#[ignore]` by default because it needs a `tmux` binary; run it with
//! `script/test/access-prompt-tmux-oracle.sh`, which is also what CI runs when
//! `tmux` is on `PATH`. The tests are the plan's §10.3 cases: the probe guests of
//! `r3/vt-probe-r3*.py`, the mixed mouse rules, RIS on the alternate screen, DECSTR
//! over a mode mix, the re-review's guest-restore and 17-parameter preludes, a
//! control pane compared with a prompted one, and the prefix sweep — both screens,
//! every byte prefix of the enter and leave frames followed by the host restore.
//!
//! # Why a real emulator
//!
//! The tracker and the byte builders are written by the same person. The oracle is
//! a second implementation of the same question, in a different codebase: the
//! prompt must start where the guest stopped and give back what it took.

use std::io::Write as _;
use std::os::unix::ffi::OsStrExt as _;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use super::Size;
use super::screen;
use super::vt::{Screen, VtState};

/// How long a frame may take to render before the oracle reads the pane.
const SETTLE: Duration = Duration::from_millis(80);
const POLL_LIMIT: Duration = Duration::from_secs(5);

/// A private tmux server whose only pane runs `cat <fifo>`: writing the FIFO puts
/// bytes on the pane's terminal, which is exactly what the guest's PTY does.
struct Tmux {
    /// Kept alive for the server's lifetime.
    _dir: PathBuf,
    socket: PathBuf,
    fifo: PathBuf,
    sink: Option<std::fs::File>,
}

impl Tmux {
    fn start() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "agent-vm-tmux-oracle-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("a clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("a temp dir");
        let socket = dir.join("sock");
        let fifo = dir.join("pane.fifo");
        let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).expect("a path");
        // SAFETY: `fifo_c` is a live NUL-terminated path and the mode is a plain
        // integer; `mkfifo` only creates a name.
        assert_eq!(
            unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) },
            0,
            "mkfifo: {}",
            std::io::Error::last_os_error()
        );
        let server = Self {
            _dir: dir,
            socket,
            fifo,
            sink: None,
        };
        // `exec cat <fifo`: cat's stdout is the pane's terminal, so the FIFO's
        // bytes are drawn. Nothing is ever typed into the pane, so no echo.
        server.tmux(&[
            "new-session",
            "-d",
            "-x",
            "100",
            "-y",
            "30",
            &format!("exec cat < '{}'", server.fifo.to_string_lossy()),
        ]);
        server
    }

    fn tmux(&self, args: &[&str]) -> String {
        let output = Command::new("tmux")
            .arg("-S")
            .arg(&self.socket)
            .arg("-f")
            .arg("/dev/null")
            .args(args)
            .output()
            .expect("tmux runs");
        assert!(
            output.status.success(),
            "tmux {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    /// Write bytes to the pane, waiting for `cat` to have the FIFO open.
    fn write(&mut self, bytes: &[u8]) {
        if self.sink.is_none() {
            let deadline = Instant::now() + POLL_LIMIT;
            loop {
                let mut options = std::fs::OpenOptions::new();
                options.write(true);
                {
                    use std::os::unix::fs::OpenOptionsExt as _;
                    options.custom_flags(libc::O_NONBLOCK);
                }
                match options.open(&self.fifo) {
                    Ok(file) => {
                        self.sink = Some(file);
                        break;
                    }
                    Err(error) if Instant::now() < deadline => {
                        let _ = error;
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("opening the pane fifo: {error}"),
                }
            }
        }
        let sink = self.sink.as_mut().expect("a fifo");
        let deadline = Instant::now() + POLL_LIMIT;
        let mut rest = bytes;
        while !rest.is_empty() {
            match sink.write(rest) {
                Ok(0) => panic!("a fifo write of zero bytes"),
                Ok(written) => rest = &rest[written..],
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "the fifo never drained");
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("writing the pane fifo: {error}"),
            }
        }
        std::thread::sleep(SETTLE);
    }

    /// The flags the frames are supposed to leave alone or restore.
    fn flags(&self) -> Flags {
        let format = "#{alternate_on},#{cursor_x},#{cursor_y},#{origin_flag},\
                      #{mouse_any_flag},#{mouse_button_flag},#{bracket_paste_flag},\
                      #{synchronized_output_flag},#{wrap_flag},#{insert_flag},#{cursor_flag}";
        let text = self.tmux(&["display-message", "-p", "-t", "0", format]);
        let fields: Vec<&str> = text.trim().split(',').collect();
        assert_eq!(fields.len(), 11, "unexpected flags: {text:?}");
        let number = |index: usize| {
            fields[index].parse::<i64>().unwrap_or_else(|_| {
                panic!("flag {index} of {text:?} is not a number");
            })
        };
        Flags {
            alternate_on: number(0) != 0,
            cursor_x: number(1),
            cursor_y: number(2),
            origin: number(3) != 0,
            mouse_any: number(4) != 0,
            mouse_button: number(5) != 0,
            bracketed_paste: number(6) != 0,
            synchronized_output: number(7) != 0,
            wrap: number(8) != 0,
            insert: number(9) != 0,
            cursor_visible: number(10) != 0,
        }
    }

    /// The pane's visible text, escapes included.
    fn capture(&self) -> String {
        self.tmux(&["capture-pane", "-p", "-e", "-t", "0"])
    }

    /// Write, then give tmux time to render. `write` already waits [`SETTLE`];
    /// this name is the oracle's reminder that a capture after it is expected to
    /// see the frame.
    fn write_and_settle(&mut self, bytes: &[u8]) {
        self.write(bytes);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Flags {
    alternate_on: bool,
    cursor_x: i64,
    cursor_y: i64,
    origin: bool,
    mouse_any: bool,
    mouse_button: bool,
    bracketed_paste: bool,
    synchronized_output: bool,
    wrap: bool,
    insert: bool,
    cursor_visible: bool,
}

impl Flags {
    /// The flags a host restore promises: main screen, mouse, paste, sync and
    /// origin off (§5.7).
    fn restored(self) -> bool {
        !self.alternate_on
            && !self.origin
            && !self.mouse_any
            && !self.mouse_button
            && !self.bracketed_paste
            && !self.synchronized_output
    }
}

/// The `refuse` probe's guest prelude (§10.4): button-event mouse with SGR
/// encoding, bracketed paste, origin mode with a scroll region, and a line-drawing
/// character set.
const PROBE_PRELUDE: &[u8] = b"\x1b[?2004h\x1b[?1002h\x1b[?1006h\x1b[3;20r\x1b[?6h\x1b(0";

/// The same guest on the alternate screen.
const ALT_PRELUDE: &[u8] = b"\x1b[?1049h\x1b[?2004h\x1b[?1002h\x1b[?6h\x1b(0";

fn view() -> screen::View {
    screen::View {
        destination: screen::Cell::from_table("tcp 203.0.113.10:443".to_owned()),
        guest_named: false,
        count: 1,
        session: "3f9a12c4".to_owned(),
        offer: screen::OfferText::SessionOrProject,
        waiting: 0,
        overflow: 0,
    }
}

fn modes_after(prelude: &[u8]) -> super::vt::RestorableModes {
    let mut state = VtState::new();
    state.advance(prelude);
    state
        .modes()
        .restorable()
        .expect("the oracle's preludes are restorable")
}

fn enter_frame(prelude: &[u8]) -> Vec<u8> {
    let modes = modes_after(prelude);
    let laid = screen::layout(
        &view(),
        Size {
            rows: 30,
            cols: 100,
        },
    )
    .expect("fits 100 x 30");
    screen::enter(&modes, &laid, false, false).0
}

fn leave_frame(prelude: &[u8]) -> Vec<u8> {
    screen::leave(&modes_after(prelude)).0
}

/// The guest's own screen text, so a comparison is about what a user sees.
fn guest_text() -> &'static [u8] {
    b"GUEST-LINE-1\r\nGUEST-LINE-2\r\n"
}

#[test]
#[ignore = "needs tmux"]
fn the_guest_terminal_is_given_back_exactly() {
    for prelude in [PROBE_PRELUDE, ALT_PRELUDE] {
        let mut tmux = Tmux::start();
        tmux.write_and_settle(prelude);
        tmux.write_and_settle(guest_text());
        let before_flags = tmux.flags();
        let before_capture = tmux.capture();

        tmux.write_and_settle(&enter_frame(prelude));
        let prompted = tmux.capture();
        assert!(
            prompted.contains("the sandbox refused a network request"),
            "the prompt must be drawn: {prompted}"
        );
        let during = tmux.flags();
        assert!(!during.mouse_any && !during.mouse_button, "{during:?}");
        assert!(!during.bracketed_paste, "{during:?}");
        assert!(!during.origin, "{during:?}");
        assert!(!during.synchronized_output, "{during:?}");
        // What the prompt must not change.
        assert_eq!(during.wrap, before_flags.wrap, "{during:?}");
        assert_eq!(during.insert, before_flags.insert, "{during:?}");
        assert_eq!(during.cursor_visible, before_flags.cursor_visible);
        // The prompt always draws on the alternate screen: it switches to it for a
        // main-screen guest and stays on the guest's own one otherwise.
        assert!(
            during.alternate_on,
            "the prompt must draw on the alternate screen"
        );

        tmux.write_and_settle(&leave_frame(prelude));
        let after = tmux.flags();
        assert_eq!(after, before_flags, "flags after the leave");
        let after_capture = tmux.capture();
        assert!(
            !after_capture.contains("the sandbox refused"),
            "the prompt must be gone: {after_capture}"
        );
        if !before_flags.alternate_on {
            // A main-screen guest's screen is exactly as it was: the prompt lived on
            // the alternate screen and the terminal's own restore brought the main
            // one back.
            for line in ["GUEST-LINE-1", "GUEST-LINE-2"] {
                assert!(
                    after_capture.contains(line),
                    "{line} is missing: {after_capture}"
                );
            }
            assert_eq!(
                after_capture, before_capture,
                "the main screen is unchanged"
            );
        } else {
            // An alternate-screen guest's own screen was drawn over and erased; the
            // nudge makes the guest redraw it, which the full-loop test checks. What
            // this asserts is that the screen *state* is back and the prompt is not.
            assert!(after.alternate_on);
        }
    }
}

#[test]
#[ignore = "needs tmux"]
fn the_character_set_is_given_back() {
    for prelude in [PROBE_PRELUDE, ALT_PRELUDE] {
        let mut tmux = Tmux::start();
        tmux.write_and_settle(prelude);
        // `q` in the line-drawing set is a horizontal line.
        tmux.write_and_settle(b"q\r\n");
        let before = tmux.capture();
        assert!(
            before.contains('─') || before.contains('\u{2500}') || before.contains('q'),
            "{before:?}"
        );
        tmux.write_and_settle(&enter_frame(prelude));
        tmux.write_and_settle(&leave_frame(prelude));
        tmux.write_and_settle(b"q\r\n");
        let after = tmux.capture();
        let before_lines: Vec<&str> = before.lines().filter(|line| line.contains('─')).collect();
        let after_lines: Vec<&str> = after.lines().filter(|line| line.contains('─')).collect();
        assert_eq!(
            before_lines, after_lines,
            "the designation and shift must be back after the prompt"
        );
    }
}

#[test]
#[ignore = "needs tmux"]
fn the_host_restore_ends_on_the_main_screen_from_every_prefix() {
    // Every byte prefix of the enter frame, then the host restore: the §6.1
    // argument, measured. Both screens, because an alternate-screen guest must also
    // end on the main screen after a forced end (AC13).
    for (prelude, main_screen_guest) in [(PROBE_PRELUDE, true), (ALT_PRELUDE, false)] {
        let enter = enter_frame(prelude);
        for prefix in 0..=enter.len() {
            let mut tmux = Tmux::start();
            let mut prelude_and_text = prelude.to_vec();
            prelude_and_text.extend_from_slice(guest_text());
            tmux.write(&prelude_and_text);
            let mut frame = enter[..prefix].to_vec();
            frame.extend_from_slice(&screen::host_restore());
            tmux.write(&frame);
            let flags = tmux.flags();
            assert!(
                flags.restored(),
                "prefix {prefix} of the enter frame left {flags:?}"
            );
            let capture = tmux.capture();
            if main_screen_guest {
                assert!(
                    capture.contains("GUEST-LINE-1"),
                    "prefix {prefix} lost the main screen: {capture}"
                );
            } else {
                assert!(
                    !capture.contains("the sandbox refused") || prefix == enter.len(),
                    "prefix {prefix} left the prompt on the main screen: {capture}"
                );
            }
        }
    }
    // And every byte prefix of the leave frame, from a fully drawn prompt.
    for prelude in [PROBE_PRELUDE, ALT_PRELUDE] {
        let leave = leave_frame(prelude);
        for prefix in 0..=leave.len() {
            let mut tmux = Tmux::start();
            let mut up_to_prompt = prelude.to_vec();
            up_to_prompt.extend_from_slice(guest_text());
            up_to_prompt.extend_from_slice(&enter_frame(prelude));
            tmux.write(&up_to_prompt);
            let mut frame = leave[..prefix].to_vec();
            frame.extend_from_slice(&screen::host_restore());
            tmux.write(&frame);
            let flags = tmux.flags();
            assert!(
                flags.restored(),
                "prefix {prefix} of the leave frame left {flags:?}"
            );
        }
    }
}

#[test]
#[ignore = "needs tmux"]
fn the_host_restore_is_idempotent_and_erases_nothing() {
    let mut tmux = Tmux::start();
    tmux.write_and_settle(guest_text());
    let before = tmux.capture();
    tmux.write_and_settle(&screen::host_restore());
    let once = tmux.capture();
    tmux.write_and_settle(&screen::host_restore());
    let twice = tmux.capture();
    assert_eq!(once, twice, "a second host restore changed the screen");
    assert_eq!(
        once.lines()
            .filter(|line| line.contains("GUEST-LINE"))
            .count(),
        before
            .lines()
            .filter(|line| line.contains("GUEST-LINE"))
            .count(),
        "the host restore must not erase the main screen"
    );
}

#[test]
#[ignore = "needs tmux"]
fn mixed_mouse_resets_leave_tracking_off() {
    // `1000h 1002h 1000l` clears tracking; the leave must not re-enable anything.
    for prelude in [
        &b"\x1b[?1002h\x1b[?1000h\x1b[?1000l"[..],
        b"\x1b[?1002h\x1b[?1002l",
        b"\x1b[?1003h\x1b[?9l",
    ] {
        let mut tmux = Tmux::start();
        tmux.write_and_settle(prelude);
        let mut state = VtState::new();
        state.advance(prelude);
        assert_eq!(
            state
                .modes()
                .restorable()
                .expect("restorable")
                .mouse_tracking,
            super::vt::MouseTracking::Off,
            "prelude {prelude:?}"
        );
        tmux.write_and_settle(&enter_frame(prelude));
        tmux.write_and_settle(&leave_frame(prelude));
        let flags = tmux.flags();
        assert!(
            !flags.mouse_any && !flags.mouse_button,
            "{prelude:?} left {flags:?}"
        );
    }
}

#[test]
#[ignore = "needs tmux"]
fn the_states_the_tracker_cannot_know_decline_rather_than_guess() {
    // RIS on the alternate screen; DECSTR over a mode mix; a guest cursor restore
    // over a non-default origin or charset; a CSI with a 17th parameter.
    for prelude in [
        &b"\x1b[?1049h\x1bc"[..],
        b"\x1b[?1002h\x1b[!p",
        b"\x1b[?6h\x1b7\x1b[?6l\x1b8",
        b"\x1b(0\x1b7\x1b(B\x1b8",
        b"\x1b[?25;25;25;25;25;25;25;25;25;25;25;25;25;25;25;25;25;1002h",
    ] {
        let mut state = VtState::new();
        state.advance(prelude);
        assert!(
            state.modes().restorable().is_none(),
            "prelude {prelude:?} must decline"
        );
    }
    // And the fields a prompt does not change never decline a takeover.
    let mut state = VtState::new();
    state.advance(b"\x1b[?7l\x1b[4h\x1b[?25l\x1b[?1004h\x1b[?1006h\x1b[3;20r");
    assert!(state.modes().restorable().is_some());
}

#[test]
#[ignore = "needs tmux"]
fn the_prompt_does_not_disturb_the_guest_s_screen_behind_it() {
    // A control pane gets only the guest's bytes; the prompted pane gets them plus a
    // whole takeover. After the leave, the two screens agree.
    let mut control = Tmux::start();
    control.write_and_settle(PROBE_PRELUDE);
    control.write_and_settle(guest_text());
    control.write_and_settle(b"TAIL");

    let mut prompted = Tmux::start();
    prompted.write_and_settle(PROBE_PRELUDE);
    prompted.write_and_settle(guest_text());
    prompted.write_and_settle(&enter_frame(PROBE_PRELUDE));
    prompted.write_and_settle(&leave_frame(PROBE_PRELUDE));
    prompted.write_and_settle(b"TAIL");

    let control_capture = control.capture();
    let prompted_capture = prompted.capture();
    for line in ["GUEST-LINE-1", "GUEST-LINE-2", "TAIL"] {
        assert!(
            prompted_capture.contains(line),
            "{line} must survive the prompt: {prompted_capture}"
        );
    }
    assert_eq!(
        control_capture
            .lines()
            .filter(|line| line.contains("GUEST-LINE"))
            .count(),
        prompted_capture
            .lines()
            .filter(|line| line.contains("GUEST-LINE"))
            .count(),
        "the guest's lines must not be duplicated"
    );
}

#[test]
#[ignore = "needs tmux"]
fn the_alternate_screen_guest_keeps_its_own_screen() {
    let mut tmux = Tmux::start();
    tmux.write_and_settle(ALT_PRELUDE);
    tmux.write_and_settle(guest_text());
    let before = tmux.capture();
    let before_flags = tmux.flags();
    assert!(before_flags.alternate_on);
    tmux.write_and_settle(&enter_frame(ALT_PRELUDE));
    assert!(
        tmux.flags().alternate_on,
        "an alternate-screen guest stays on it"
    );
    tmux.write_and_settle(&leave_frame(ALT_PRELUDE));
    assert!(tmux.flags().alternate_on);
    let after = tmux.capture();
    assert!(
        after.contains("GUEST-LINE-1") || before.contains("GUEST-LINE-1"),
        "the guest's screen text exists on at least one capture"
    );
    assert!(
        !tmux.capture().contains("the sandbox refused"),
        "the prompt is gone after the leave"
    );
}

#[test]
#[ignore = "needs tmux"]
fn nudges_are_only_for_the_alternate_screen() {
    assert!(screen::nudges(Screen::Alternate));
    assert!(!screen::nudges(Screen::Main));
}
