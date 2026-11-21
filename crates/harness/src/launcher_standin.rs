//! The launcher stand-in for the #400 boot-free direct-terminal controls (#698).
//!
//! It accepts a real launcher's argv (`[launch options] run|-- PROGRAM ARG...`),
//! consumes the launch options and the command-boundary token exactly as a
//! launcher does, and then plays the *plumbing* a launcher provides: the host
//! terminal's canonical (or raw, for a terminal-input case) bytes forwarded into
//! the guest's stdin pipe, EOF at the host's own end-of-file, and the guest's
//! stdout/stderr left on their inherited descriptors.
//!
//! `STANDIN_MODE` selects a deliberately broken variant so the driver's oracles
//! can be shown to reject it. Nothing here is ever part of a launch: it exists
//! only to prove that the driver and the guest probe distinguish a correct
//! session from a broken one without a VM, a runtime or an image.
//!
//! Byte compatibility is the point. The direct-terminal driver matches on this
//! program's output, so every frame, message, exit status and terminal
//! transition below is the Python's own, including two quirks that are
//! documented where they appear: the readiness loop rewrites the whole head per
//! byte, and the cadence counts cursor replies per read without carrying a split
//! one over.
//!
//! The Python copy stays on disk until its last importer is ported (#699), which
//! is why nothing shell-side calls this yet.

use std::{
    env,
    ffi::OsString,
    fs, io,
    os::fd::{AsFd, BorrowedFd},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use clap::Args;
use rustix::process::Signal;

use crate::{Outcome, pty};

// --- The prompt controls (#501 slice 3) ------------------------------------
//
// A stand-in that plays a *correct* prompt must satisfy the driver's oracle; the
// broken variants must not. These frames are a control's own minimal rendition —
// the product's frames come from `access_prompt::screen` and are checked by the
// tmux oracle — so nothing here claims to be the launcher's byte stream.

const PROMPT_ENTER: &[u8] = concat!(
    "\x1b[?1049h",
    "\x1b[?1003l\x1b[?1002l\x1b[?1001l\x1b[?1000l\x1b[?9l",
    "\x1b[?2004l\x1b[?6l\x1b[>0u\x1b[0m\x1b(B\x0f",
    "\x1b[H\x1b[2J",
    "\x1b[2;1H\x1b[2Kagent-vm: the sandbox refused a network request from the guest",
    "\x1b[4;1H\x1b[2K  tcp 203.0.113.10:443",
    "\x1b[7;1H\x1b[2KHow should this request be treated?",
    "\x1b[8;1H\x1b[2KType one of the below letters and press enter:",
    "\x1b[9;1H\x1b[2K_",
    "\x1b[11;1H\x1b[2K  d deny     keep refusing (also Enter or Esc)",
    "\x1b[9;1H\x1b[6n",
)
.as_bytes();
/// The question's instruction row: the prompt's evidence, and the row a typed
/// answer appears under.
const PROMPT_INSTRUCTION: &[u8] = b"Type one of the below letters and press enter:";
/// The input row as it is drawn with nothing typed: what a read of the driver's
/// reply puts back before an answer arrives.
const PROMPT_INPUT: &[u8] = b"\x1b[9;1H\x1b[2K_";
const PROMPT_LEAVE: &[u8] = b"\x1b[0m\x1b[H\x1b[2J\x1b[<u\x1b[?6h\x1b[?1049l";
/// What the guest's modes must get back (the `refuse` probe's prelude).
const PROMPT_MODES_BACK: &[u8] = b"\x1b(0\x1b[?1002h\x1b[?2004h";
/// A redraw the product would never write after the leave: a broken variant's tell.
const PROMPT_REDRAW_AFTER_LEAVE: &[u8] =
    b"\x1b[8;1H\x1b[2KType one of the below letters and press enter:";
/// The takeover's single cursor-position request, the enter frame's last bytes.
const PROMPT_CURSOR_REQUEST: &[u8] = b"\x1b[9;1H\x1b[6n";

/// The reply a terminal sends back for the one cursor-position request: the
/// input row the request moved to, in the reply's own spelling.
const PROMPT_ANSWER: &[u8] = b"\x1b[9;1R";

/// How long a host read waits before the launcher is declared dead.
const HOST_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the launcher waits for the operator's answer line and its Enter.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(30);
/// The cadence's reply window: one reply to the one request it sent.
const CADENCE_WINDOW: Duration = Duration::from_secs(1);
/// How long the cadence waits for a second reply to that same request, which a
/// driver answering twice sends at once.
const CADENCE_SETTLE: Duration = Duration::from_millis(200);
/// How long a held stream keeps its consumer open.
const HELD_STREAM: Duration = Duration::from_secs(20);
/// Bytes per forwarded chunk.
const CHUNK: usize = 4096;
/// The answer line the driver types: a letter, then Enter.
const ANSWER_KEY: &[u8] = b"d";
const ANSWER_ENTER: &[u8] = b"\r";
/// How long a control waits for a question the cadence abandoned: the reply
/// window and its settle, with room for the guest to finish and be released. A
/// cadence that took two replies as one would still be waiting out its 30 s
/// answer deadline when this expires.
const ABANDONED_WITHIN: Duration = Duration::from_secs(5);

#[derive(Debug, Args)]
pub struct LauncherStandinArgs {
    /// Run the boot-free stand-in controls instead of a launch.
    #[arg(long)]
    self_test: bool,

    /// Checkout the guest probe is copied from; `--self-test` needs it.
    #[arg(long, value_name = "PATH")]
    repo_root: Option<PathBuf>,

    /// The launcher argv: `[launch options] run|-- PROGRAM ARG...`.
    ///
    /// Only so clap accepts tokens it would otherwise reject (`-t`, `--image`);
    /// see `launch` for which copy of the argv decides.
    #[arg(
        value_name = "ARGS",
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    args: Vec<OsString>,
}

/// The access prompt's takeover variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Prompt {
    /// Play the launcher's answer cadence instead of a plain takeover.
    cadence: bool,
    /// Leave the guest's modes unrestored.
    no_modes: bool,
    /// Withhold one held line.
    drop_line: bool,
    /// Write a frame after the leave.
    redraw_after_leave: bool,
}

impl Prompt {
    const PLAIN: Self = Self {
        cadence: false,
        no_modes: false,
        drop_line: false,
        redraw_after_leave: false,
    };
    const NO_MODES: Self = Self {
        cadence: false,
        no_modes: true,
        drop_line: false,
        redraw_after_leave: false,
    };
    const DROP_LINE: Self = Self {
        cadence: false,
        no_modes: false,
        drop_line: true,
        redraw_after_leave: false,
    };
    const REDRAW_AFTER_LEAVE: Self = Self {
        cadence: false,
        no_modes: false,
        drop_line: false,
        redraw_after_leave: true,
    };
    const CADENCE: Self = Self {
        cadence: true,
        no_modes: false,
        drop_line: false,
        redraw_after_leave: false,
    };
}

/// The deliberately broken variant, or the correct one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// A correct launcher: inherits the terminal, forwards honestly, exits with
    /// the guest's status.
    Correct,
    /// Dies before any readiness barrier.
    EarlyExit,
    /// Leaves the operator's terminal raw.
    RawLeftover,
    /// Never forwards a resize.
    NoWinch,
    /// Changes the guest's stdin bytes.
    MangleInput,
    /// Cuts the streamed payload short.
    StreamTruncated,
    /// Forwards everything and never closes the consumer.
    StreamNoEof,
    /// A `prompt*` variant: plays the launcher's takeover of a refusing guest.
    Prompt(Prompt),
}

impl Mode {
    fn from_env() -> Self {
        Self::from_name(&env::var("STANDIN_MODE").unwrap_or_else(|_| "ok".to_owned()))
    }

    fn from_name(name: &str) -> Self {
        match name {
            "early-exit" => Self::EarlyExit,
            "raw-leftover" => Self::RawLeftover,
            "no-winch" => Self::NoWinch,
            "mangle-input" => Self::MangleInput,
            "stream-truncated" => Self::StreamTruncated,
            "stream-no-eof" => Self::StreamNoEof,
            "prompt-cadence" => Self::Prompt(Prompt::CADENCE),
            "prompt-no-modes" => Self::Prompt(Prompt::NO_MODES),
            "prompt-drop-line" => Self::Prompt(Prompt::DROP_LINE),
            "prompt-redraw-after-leave" => Self::Prompt(Prompt::REDRAW_AFTER_LEAVE),
            other if other.starts_with("prompt") => Self::Prompt(Prompt::PLAIN),
            _ => Self::Correct,
        }
    }
}

pub fn run(args: LauncherStandinArgs) -> Result<Outcome, String> {
    if args.self_test {
        self_test(args.repo_root)?;
        return Ok(Outcome::Report(
            "launcher-standin: OK (every mode's frames, statuses and terminal transitions)"
                .to_owned(),
        ));
    }
    // A launcher's argv is not the harness's: clap consumes a `--` that is the
    // *first* token after the subcommand, and that token is exactly the
    // launcher's command boundary for a launch with no options. So the process's
    // own argv is authoritative, and clap's copy is only what let it through.
    let argv = process_argv().unwrap_or(args.args);
    launch(&argv)
}

fn process_argv() -> Option<Vec<OsString>> {
    let mut words = env::args_os();
    words.next()?;
    let subcommand = words.next()?;
    (subcommand == "launcher-standin").then(|| words.collect())
}

/// Play one launcher invocation.
fn launch(argv: &[OsString]) -> Result<Outcome, String> {
    let (program, probe) = split_argv(argv)?;
    let mode = Mode::from_env();
    match (mode, probe.as_str()) {
        (Mode::Prompt(Prompt { cadence: true, .. }), "refuse") => play_prompt_cadence(program),
        (Mode::Prompt(_), "refuse") => play_prompt(program, mode),
        (Mode::EarlyExit, _) => Ok(Outcome::Exit(0)),
        (Mode::RawLeftover, _) => {
            // No guard on purpose: this variant *is* the launcher that leaves the
            // operator's terminal raw, and the driver's restoration oracle has to
            // notice. The terminal belongs to a control that is torn down with
            // its own PTY.
            take_raw()?;
            finish(run_program(program)?)
        }
        (Mode::NoWinch, _) => {
            let _saved = SavedModes::raw()?;
            finish(run_program(program)?)
        }
        (_, "resize" | "wait") => relay_session(program),
        // Every input case but the mangling one keeps the host terminal: the
        // guest needs it for its own raw mode, exactly as a real PTY launch
        // provides it. The mangling variant is the *streamed* case, which is why
        // it falls through to the pipe below.
        (mode, "input") if mode != Mode::MangleInput => {
            let _saved = SavedModes::raw()?;
            finish(run_program(program)?)
        }
        (_, "stream-input" | "input") => stream_into_pipe(program, &probe, mode),
        _ => finish(run_program(program)?),
    }
}

/// The status a failed stand-in asks for: the Python's `SystemExit(64)`.
pub fn failure_status(error: &str) -> Option<i32> {
    error.starts_with("standin: ").then_some(64)
}

/// Report a stand-in failure the way the Python's `die` did.
fn die(message: &str) -> String {
    format!("standin: {message}")
}

fn finish(status: ExitStatus) -> Result<Outcome, String> {
    Ok(Outcome::Exit(pty::propagate_exit_code(status)))
}

// --- The command line -------------------------------------------------------

/// Consume the launcher's options and its command-boundary token, exactly as the
/// launcher does, and return the program plus the guest probe's mode.
///
/// The probe's mode is its third word, and only when the program really is the
/// guest probe: a stand-in that guessed from any argv would answer a question
/// nobody asked.
fn split_argv(argv: &[OsString]) -> Result<(&[OsString], String), String> {
    let boundary = argv
        .iter()
        .position(|word| word == "run" || word == "--")
        .map(|index| index + 1)
        .unwrap_or(argv.len());
    let program = &argv[boundary..];
    if program.is_empty() {
        return Err(die("no program after the command boundary"));
    }
    let bash = program[0].to_string_lossy().ends_with("bash");
    let probe = program
        .get(1)
        .is_some_and(|word| word.to_string_lossy().ends_with("guest-probe.sh"));
    let mode = if bash && probe {
        program
            .get(2)
            .map(|word| word.to_string_lossy().into_owned())
            .unwrap_or_default()
    } else {
        String::new()
    };
    Ok((program, mode))
}

/// The input row after a key stroke: what is typed, then the cursor's `_`.
fn prompt_input(typed: &[u8]) -> Vec<u8> {
    let mut row = PROMPT_INPUT[..PROMPT_INPUT.len() - 1].to_vec();
    row.extend_from_slice(typed);
    row.push(b'_');
    row
}

// --- The host terminal ------------------------------------------------------

/// The terminal modes to put back when the launch is over.
///
/// Restored on drop, so no `die`, no error and no early return can leave the
/// operator's terminal raw: that is what the Python's `try/finally` bought, and
/// the driver's restoration oracle exists to catch a launcher that forgets.
struct SavedModes {
    saved: rustix::termios::Termios,
}

impl SavedModes {
    /// Remember the host terminal's modes and make it raw.
    fn raw() -> Result<Self, String> {
        if !pty::is_terminal(std::io::stdin()) {
            return Err(die(
                "the host terminal is not a terminal, so it has no modes to save",
            ));
        }
        let saved = pty::modes(std::io::stdin())
            .map_err(|error| die(&format!("cannot read the terminal's modes: {error}")))?;
        make_raw(&saved)?;
        Ok(Self { saved })
    }
}

impl Drop for SavedModes {
    fn drop(&mut self) {
        // A failed restore has nowhere to go: the launch is already over, and the
        // driver observes the terminal's real state, so silence would only hide
        // the failure from the operator.
        if let Err(error) = pty::set_modes(std::io::stdin(), &self.saved) {
            eprintln!("standin: cannot restore the terminal: {error}");
        }
    }
}

fn make_raw(saved: &rustix::termios::Termios) -> Result<(), String> {
    pty::set_modes(std::io::stdin(), &pty::raw(saved))
        .map_err(|error| die(&format!("cannot set raw mode: {error}")))
}

fn take_raw() -> Result<(), String> {
    if !pty::is_terminal(std::io::stdin()) {
        return Err(die(
            "the host terminal is not a terminal, so it has no modes to save",
        ));
    }
    let saved = pty::modes(std::io::stdin())
        .map_err(|error| die(&format!("cannot read the terminal's modes: {error}")))?;
    make_raw(&saved)
}

/// Write bytes to the stand-in's own stdout, unbuffered like `os.write`.
fn write_out(bytes: &[u8]) -> Result<(), String> {
    write_all(std::io::stdout(), bytes)
        .map_err(|error| format!("launcher-standin: cannot write to the terminal: {error}"))
}

fn write_all(fd: impl AsFd, mut bytes: &[u8]) -> io::Result<()> {
    let fd = fd.as_fd();
    while !bytes.is_empty() {
        match rustix::io::write(fd, bytes) {
            Ok(0) => return Err(io::Error::from(rustix::io::Errno::PIPE)),
            Ok(written) => bytes = &bytes[written..],
            Err(rustix::io::Errno::INTR) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

/// Read one chunk of the host terminal within `timeout`; `None` = nothing came.
fn read_host(buffer: &mut [u8], timeout: Duration) -> Result<Option<usize>, String> {
    pty::read_chunk(std::io::stdin(), buffer, timeout)
        .map_err(|error| die(&format!("cannot read the terminal: {error}")))
}

/// Read the typed answer up to its Enter, as a launcher's line reader does.
///
/// `prefix` is what this mode already read while it was counting replies: a
/// letter can arrive before the count is finished, and a line is assembled from
/// bytes, not from reads. The deadline is bounded so a driver that never answers
/// fails the control instead of hanging it.
fn read_answer_line(prefix: &[u8]) -> Result<Vec<u8>, String> {
    let mut seen = prefix.to_vec();
    let deadline = Instant::now() + ANSWER_TIMEOUT;
    let mut buffer = [0u8; 64];
    while !contains(&seen, b"\r") && !contains(&seen, b"\n") {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Err(die("the driver never answered"));
        };
        match read_host(&mut buffer, remaining)? {
            // The terminal is gone, so no Enter can arrive on it.
            Some(0) => return Err(die("the driver never answered")),
            Some(read) => seen.extend_from_slice(&buffer[..read]),
            // Nothing within the time that was left: the loop's own deadline turns
            // that into the failure below rather than a silent read of nothing.
            None => {}
        }
    }
    Ok(seen)
}

// --- The guest program ------------------------------------------------------

fn command_for(program: &[OsString]) -> Result<Command, String> {
    let (name, arguments) = program
        .split_first()
        .ok_or_else(|| die("no program after the command boundary"))?;
    let mut command = Command::new(name);
    command.args(arguments);
    Ok(command)
}

/// The guest on the inherited descriptors: what a launcher's ordinary path does.
fn run_program(program: &[OsString]) -> Result<ExitStatus, String> {
    command_for(program)?
        .status()
        .map_err(|error| format!("launcher-standin: cannot run the guest: {error}"))
}

// --- Forwarding -------------------------------------------------------------

/// How one forward moves the host's bytes into the guest's stdin.
#[derive(Debug, Clone, Copy)]
struct Plan {
    /// Stop after exactly this many bytes.
    truncate: Option<usize>,
    /// Keep the consumer open afterwards, so no EOF can arrive.
    hold: bool,
    /// Replace the escape byte, so the guest receives something else.
    mangle: bool,
}

/// Copy the host terminal into the guest's stdin pipe, byte for byte.
///
/// One host read per chunk with the launcher's own 30 s deadline: a terminal
/// that never delivers input is a dead launcher, not a slow one.
fn forward(sink: BorrowedFd<'_>, plan: Plan) -> Result<(), String> {
    let mut copied = 0;
    let mut buffer = [0u8; CHUNK];
    loop {
        if plan.truncate.is_some_and(|limit| copied >= limit) {
            break;
        }
        let Some(read) = read_host(&mut buffer, HOST_READ_TIMEOUT)? else {
            return Err(die("the host terminal never delivered input"));
        };
        if read == 0 {
            break;
        }
        let mut chunk = buffer[..read].to_vec();
        if plan.mangle {
            for byte in &mut chunk {
                if *byte == 0x1d {
                    *byte = b'A';
                }
            }
        }
        if let Some(limit) = plan.truncate {
            chunk.truncate(limit - copied);
        }
        write_all(sink, &chunk).map_err(|error| {
            format!("launcher-standin: cannot write the guest's stdin: {error}")
        })?;
        copied += chunk.len();
    }
    if plan.hold {
        // Everything forwarded, but the guest's stdin is never closed: the
        // consumer stays open, so no EOF can arrive. Longer than any control's
        // deadline, so the deadline — not this sleep — decides the verdict.
        thread::sleep(HELD_STREAM);
    }
    Ok(())
}

/// A terminal-input case: a pipe to the guest, filled from the host terminal.
fn stream_into_pipe(program: &[OsString], probe: &str, mode: Mode) -> Result<Outcome, String> {
    // A terminal-input case keeps the host terminal raw while it forwards; a
    // streamed one leaves it canonical, because the empty-line VEOF *is* the
    // host's EOF and raw mode would turn it into a literal byte.
    let saved = if probe == "input" {
        Some(SavedModes::raw()?)
    } else {
        None
    };
    let (reader, writer) = pty::pipe()
        .map_err(|error| format!("launcher-standin: cannot create the guest's stdin: {error}"))?;
    let mut child = command_for(program)?
        .stdin(Stdio::from(reader))
        .spawn()
        .map_err(|error| format!("launcher-standin: cannot run the guest: {error}"))?;
    let plan = if probe == "stream-input" {
        Plan {
            truncate: (mode == Mode::StreamTruncated).then_some(15),
            hold: mode == Mode::StreamNoEof,
            mangle: false,
        }
    } else {
        // The input case consumes exactly three bytes, so the relay stops when
        // they have been forwarded instead of waiting for an EOF the driver never
        // sends.
        Plan {
            truncate: Some(3),
            hold: false,
            mangle: mode == Mode::MangleInput,
        }
    };
    let forwarded = forward(writer.as_fd(), plan);
    // Close the sink even when forwarding failed: the guest must not be left
    // waiting for an EOF that a dead launcher will never send.
    drop(writer);
    let status = child
        .wait()
        .map_err(|error| format!("launcher-standin: cannot wait for the guest: {error}"))?;
    drop(saved);
    forwarded?;
    finish(status)
}

// --- Resize relaying --------------------------------------------------------

/// A PTY launch: raw host terminal, a guest on it, and the resize the launcher
/// receives relayed to the guest.
fn relay_session(program: &[OsString]) -> Result<Outcome, String> {
    let _saved = SavedModes::raw()?;
    let mut child = command_for(program)?
        .spawn()
        .map_err(|error| format!("launcher-standin: cannot run the guest: {error}"))?;
    // The driver signals the launcher, not the guest: the operator's terminal
    // delivers the resize here.
    let relay = pty::SignalRelay::to(child.id() as i32, Signal::WINCH)
        .map_err(|error| format!("launcher-standin: cannot relay a resize: {error}"))?;
    let status = child
        .wait()
        .map_err(|error| format!("launcher-standin: cannot wait for the guest: {error}"))?;
    drop(relay);
    finish(status)
}

// --- The access prompt's takeover -------------------------------------------

/// Read the guest's stdout a byte at a time until it says it is ready,
/// forwarding what arrives.
///
/// The whole head is written per byte, exactly as the Python did: the driver's
/// accept control was validated against that stream, so "tidying" it here would
/// change the bytes #699's fixtures match on.
fn forward_until_ready(out: &mut impl io::Read) -> Result<(), String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !contains(&head, b"REFUSE-READY") {
        match out.read(&mut byte) {
            Ok(0) => return Err(die("the probe ended before its readiness")),
            Ok(_) => {
                head.push(byte[0]);
                write_out(&head)?;
            }
            Err(error) => {
                return Err(format!(
                    "launcher-standin: cannot read the guest's output: {error}"
                ));
            }
        }
    }
    Ok(())
}

/// Hold the guest's output until the question is over, then release it in order.
fn release_held(out: &mut impl io::Read) -> Result<Vec<u8>, String> {
    let mut held = Vec::new();
    out.read_to_end(&mut held)
        .map_err(|error| format!("launcher-standin: cannot read the guest's output: {error}"))?;
    Ok(held)
}

/// Play a launcher's takeover over a real `refuse` probe.
///
/// The probe's own prelude and readiness go straight to the terminal (the guest
/// set its modes before the question existed); everything it writes while the
/// question is up is held, then released after the leave, in order.
fn play_prompt(program: &[OsString], mode: Mode) -> Result<Outcome, String> {
    let flag = match mode {
        Mode::Prompt(flag) => flag,
        _ => Prompt::PLAIN,
    };
    let saved = SavedModes::raw()?;
    let (mut child, mut out) = piped_guest(program)?;
    forward_until_ready(&mut out)?;
    write_out(PROMPT_ENTER)?;
    thread::sleep(Duration::from_millis(300));
    // Wait for the answer line, which the driver types at the terminal: a letter
    // (or its word) and then Enter.
    let line = read_answer_line(b"")?;
    write_out(&prompt_input(&without_enter(&line)))?;
    write_out(PROMPT_LEAVE)?;
    if !flag.no_modes {
        write_out(PROMPT_MODES_BACK)?;
    }
    let mut held = release_held(&mut out)?;
    if flag.drop_line {
        // One held line never reaches the terminal: the ordering oracle must
        // notice the gap.
        held = drop_first_line(&held);
    }
    write_out(&held)?;
    if flag.redraw_after_leave {
        thread::sleep(Duration::from_millis(100));
        write_out(PROMPT_REDRAW_AFTER_LEAVE)?;
    }
    let status = child
        .wait()
        .map_err(|error| format!("launcher-standin: cannot wait for the guest: {error}"))?;
    drop(saved);
    finish(status)
}

/// Play the *launcher's* answer cadence, to exercise the driver's own rules.
///
/// The real launcher sends one cursor-position request and treats any later reply
/// as input. A stand-in that accepted any read as the answer (the plain
/// `prompt-ok` mode) cannot catch a driver that answers repeatedly; this mode can
/// (H15). A driver that answers a request twice (H16: a pump without the shared
/// driver re-initialises its count) sends the second reply at once, and this mode
/// then leaves the question unanswered — that is the class it exists to catch.
/// The answer itself is a typed line, and every byte the driver sent before it is
/// kept, because a letter can arrive while this mode is still counting replies.
fn play_prompt_cadence(program: &[OsString]) -> Result<Outcome, String> {
    let saved = SavedModes::raw()?;
    let (mut child, mut out) = piped_guest(program)?;
    forward_until_ready(&mut out)?;
    write_out(PROMPT_ENTER)?;
    // Count *replies*, not reads: the terminal may coalesce several writes into
    // one read, and a driver that answers twice must still be caught. The window
    // ends at the first reply, because a driver that sends none never will.
    let mut pending = Vec::new();
    let mut replies = 0;
    let mut buffer = [0u8; CHUNK];
    let window = Instant::now() + CADENCE_WINDOW;
    while replies == 0 && Instant::now() < window {
        let Some(read) = read_host(&mut buffer, Duration::from_millis(50))? else {
            continue;
        };
        if read == 0 {
            break;
        }
        pending.extend_from_slice(&buffer[..read]);
        replies += count_cursor_replies(&buffer[..read]);
        write_out(PROMPT_INPUT)?;
    }
    // A second reply to the same request arrives immediately; give it its moment.
    let settle = Instant::now() + CADENCE_SETTLE;
    while Instant::now() < settle {
        let Some(read) = read_host(&mut buffer, Duration::from_millis(20))? else {
            continue;
        };
        if read == 0 {
            break;
        }
        pending.extend_from_slice(&buffer[..read]);
        replies += count_cursor_replies(&buffer[..read]);
    }
    if replies != 1 {
        // Zero replies (no driver) or more than one (a driver answering twice):
        // leave the question unanswered, as a real launcher's question would time
        // out.
        write_out(PROMPT_LEAVE)?;
        let held = release_held(&mut out)?;
        write_out(&held)?;
        let status = child
            .wait()
            .map_err(|error| format!("launcher-standin: cannot wait for the guest: {error}"))?;
        drop(saved);
        return finish(status);
    }
    // Now the answer: a letter (or its word), then Enter.
    let line = read_answer_line(&pending)?;
    let typed = without_cursor_replies(&without_enter(&line));
    write_out(&prompt_input(&typed))?;
    write_out(PROMPT_LEAVE)?;
    write_out(PROMPT_MODES_BACK)?;
    let held = release_held(&mut out)?;
    write_out(&held)?;
    let status = child
        .wait()
        .map_err(|error| format!("launcher-standin: cannot wait for the guest: {error}"))?;
    drop(saved);
    finish(status)
}

/// A guest whose stdout the launcher holds.
fn piped_guest(program: &[OsString]) -> Result<(Child, std::process::ChildStdout), String> {
    let mut child = command_for(program)?
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|error| format!("launcher-standin: cannot run the guest: {error}"))?;
    let out = child
        .stdout
        .take()
        .ok_or_else(|| "launcher-standin: the guest has no stdout pipe".to_owned())?;
    Ok((child, out))
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// The line without its Enter, exactly as Python's `rstrip(b"\r\n")` strips it.
fn without_enter(line: &[u8]) -> Vec<u8> {
    let mut end = line.len();
    while end > 0 && (line[end - 1] == b'\r' || line[end - 1] == b'\n') {
        end -= 1;
    }
    line[..end].to_vec()
}

/// The line's bytes with every cursor-position reply removed: a reply is the
/// terminal's, not something the operator typed, so it is not part of the echo.
fn without_cursor_replies(bytes: &[u8]) -> Vec<u8> {
    let mut kept = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if let Some(after) = cursor_reply_at(bytes, index) {
            index = after;
            continue;
        }
        kept.push(bytes[index]);
        index += 1;
    }
    kept
}

/// Where the `CSI row ; col R` reply starting at `index` ends, if one does.
fn cursor_reply_at(bytes: &[u8], index: usize) -> Option<usize> {
    if bytes.get(index) != Some(&0x1b) || bytes.get(index + 1) != Some(&b'[') {
        return None;
    }
    let mut cursor = index + 2;
    for group in 0..2 {
        let start = cursor;
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
        if cursor == start {
            return None;
        }
        if group == 0 {
            if bytes.get(cursor) != Some(&b';') {
                return None;
            }
            cursor += 1;
        }
    }
    (bytes.get(cursor) == Some(&b'R')).then_some(cursor + 1)
}

/// How many times `needle` occurs in `haystack`.
fn count_of(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

/// How many `CSI row ; col R` replies one read holds.
fn count_cursor_replies(bytes: &[u8]) -> usize {
    let mut count = 0;
    let mut index = 0;
    while index + 1 < bytes.len() {
        match cursor_reply_at(bytes, index) {
            Some(after) => {
                count += 1;
                index = after;
            }
            None => index += 1,
        }
    }
    count
}

/// Remove the first `LINE 17` line from the held output.
fn drop_first_line(held: &[u8]) -> Vec<u8> {
    for needle in [&b"LINE 17\r\n"[..], &b"LINE 17\n"[..]] {
        if let Some(at) = held
            .windows(needle.len())
            .position(|window| window == needle)
        {
            let mut dropped = held[..at].to_vec();
            dropped.extend_from_slice(&held[at + needle.len()..]);
            return dropped;
        }
    }
    held.to_vec()
}

// --- Boot-free controls -----------------------------------------------------

fn self_test(repo_root: Option<PathBuf>) -> Result<(), String> {
    let repo_root = repo_root
        .ok_or_else(|| "usage: launcher-standin: --self-test needs --repo-root".to_owned())?;
    let scratch = Scratch::new("launcher-standin").map_err(|error| error.to_string())?;
    fs::copy(
        repo_root.join("script/test/fixtures/direct-terminal/guest-probe.sh"),
        scratch.path.join("guest-probe.sh"),
    )
    .map_err(|error| format!("cannot copy the guest probe: {error}"))?;
    fs::write(scratch.path.join("resize-probe.sh"), RESIZE_PROBE)
        .map_err(|error| error.to_string())?;
    // The prompt probes keep the guest probe's *name*: the stand-in only reads a
    // probe mode from a program it recognises as the guest probe, so the takeover
    // is driven by a probe the launcher recognises as one.
    fs::create_dir_all(scratch.path.join("refuse")).map_err(|error| error.to_string())?;
    fs::write(scratch.path.join("refuse/guest-probe.sh"), REFUSE_PROBE)
        .map_err(|error| error.to_string())?;

    identity_keeps_every_descriptor_a_terminal(&scratch.path)?;
    typed_bytes_reach_the_guest(&scratch.path)?;
    a_mangled_byte_changes_what_the_guest_receives(&scratch.path)?;
    streamed_input_reaches_the_guest_exactly(&scratch.path)?;
    a_truncated_stream_cuts_the_payload(&scratch.path)?;
    a_held_stream_never_delivers_eof(&scratch.path)?;
    a_resize_is_relayed_to_the_guest(&scratch.path)?;
    a_launcher_that_never_relays_leaves_the_guest_waiting(&scratch.path)?;
    a_leftover_raw_terminal_is_visible(&scratch.path)?;
    an_early_exit_reaches_no_readiness(&scratch.path)?;
    a_prompt_takeover_orders_its_frames(&scratch.path)?;
    a_launcher_answer_cadence_answers_once(&scratch.path)?;
    a_second_reply_abandons_the_question(&scratch.path)?;
    no_program_after_the_boundary_is_misuse()?;
    Ok(())
}

/// The guest's readiness and a resize it only believes when the signal arrives.
///
/// A cheap stand-in for the real probe's resize loop: the negative control needs
/// the *absence* of a relay, so its deadline is short rather than the fixture's
/// ten seconds.
const RESIZE_PROBE: &str = "#!/usr/bin/env bash\n\
set -euo pipefail\n\
winch=0\n\
trap 'winch=1' WINCH\n\
echo \"SIZE $(stty size)\"\n\
echo RESIZE-READY\n\
for _ in $(seq 0 19); do\n\
    if IFS= read -r -t 0.1 _ack; then :; fi\n\
    if [ \"$winch\" = 1 ] && [ \"$(stty size)\" = '43 119' ]; then\n\
        echo \"RESIZED $(stty size)\"\n\
        exit 7\n\
    fi\n\
done\n\
echo \"RESIZE-TIMEOUT winch=$winch size=$(stty size)\"\n\
exit 90\n";

/// The guest the prompt modes play over: readiness, then output that arrives
/// while the question is up and has to be released in order afterwards.
const REFUSE_PROBE: &str = "#!/usr/bin/env bash\n\
set -euo pipefail\n\
stty raw -echo 2>/dev/null || true\n\
echo REFUSE-READY\n\
for i in $(seq 0 19); do echo \"LINE $i\"; done\n\
echo HELD-DONE\n\
exit 9\n";

/// Wait for a control's stand-in, with the control's own deadline: the message
/// names the control's subject, not just the child.
fn wait_bounded(child: &mut pty::OwnedChild, timeout: Duration) -> Result<ExitStatus, String> {
    child
        .finish(timeout)
        .map_err(|error| format!("cannot wait for the stand-in: {error}"))
}

/// One launch through a real pseudoterminal, read and written the way the
/// driver reads and writes its own.
///
/// The stand-in is spawned on the terminal with **no** controlling terminal,
/// exactly as the driver spawns it: the kernel signals a session's foreground
/// group on a resize, so a stand-in that owned the terminal would see every
/// resize whether it relayed one or not, and the relay control would prove
/// nothing.
struct Terminal {
    pty: pty::Pty,
    scratch: PathBuf,
}

impl Terminal {
    fn open(scratch: &Path) -> Result<Self, String> {
        let pty = pty::Pty::with_size(pty::WindowSize::new(24, 80))
            .map_err(|error| format!("cannot open a pseudoterminal: {error}"))?;
        Ok(Self {
            pty,
            scratch: scratch.to_path_buf(),
        })
    }

    /// The argv a real launcher receives: options, the boundary, the program.
    fn launch(
        &self,
        standin_mode: &str,
        program: &str,
        probe_mode: &str,
        boundary: &str,
    ) -> Result<pty::OwnedChild, String> {
        let mut argv = vec![
            env::current_exe()
                .map_err(|error| format!("cannot find this binary's own path: {error}"))?
                .into_os_string(),
            OsString::from("launcher-standin"),
            // Launch options the stand-in must consume without looking at them.
            OsString::from("--image"),
            OsString::from("contract-image"),
            OsString::from("-t"),
            OsString::from(boundary),
            OsString::from("bash"),
            OsString::from(format!("./{program}")),
        ];
        if !probe_mode.is_empty() {
            argv.push(OsString::from(probe_mode));
        }
        let mut command = Command::new(&argv[0]);
        command
            .args(&argv[1..])
            .current_dir(&self.scratch)
            // Its own process group, so a control that fails can stop the guest
            // the stand-in started as well as the stand-in. A group needs no
            // controlling terminal, so nothing else here changes.
            .process_group(0)
            .env("STANDIN_MODE", standin_mode);
        pty::spawn_with_terminal(&mut command, self.pty.slave())
            .map(pty::OwnedChild::leading_group)
            .map_err(|error| format!("cannot launch the stand-in ({standin_mode}): {error}"))
    }

    fn write(&self, bytes: &[u8]) -> Result<(), String> {
        write_all(self.pty.master(), bytes)
            .map_err(|error| format!("cannot write to the terminal: {error}"))
    }

    /// Read until `needle` is in `seen`, which accumulates across calls: a needle
    /// that arrived in an earlier chunk must satisfy the later expectation.
    fn need(&self, seen: &mut Vec<u8>, needle: &[u8], timeout: Duration) -> Result<(), String> {
        self.need_count(seen, needle, 1, timeout)
    }

    /// Read until `needle` has been written `times` times, for a needle the
    /// takeover frame already holds one copy of: the second copy is the redraw a
    /// later event wrote, and only the count tells them apart.
    fn need_count(
        &self,
        seen: &mut Vec<u8>,
        needle: &[u8],
        times: usize,
        timeout: Duration,
    ) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        let mut buffer = [0u8; CHUNK];
        while count_of(seen, needle) < times {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err(format!(
                    "the stand-in never wrote {:?}: {:?}",
                    String::from_utf8_lossy(needle),
                    text(seen)
                ));
            };
            match pty::read_chunk(self.pty.master(), &mut buffer, remaining)
                .map_err(|error| format!("cannot read the terminal: {error}"))?
            {
                Some(0) => {
                    return Err(format!(
                        "the stand-in closed the terminal before {:?}: {:?}",
                        String::from_utf8_lossy(needle),
                        text(seen)
                    ));
                }
                Some(read) => seen.extend_from_slice(&buffer[..read]),
                None => continue,
            }
        }
        Ok(())
    }

    /// Everything the stand-in writes until it goes quiet.
    ///
    /// The control keeps its own slave open — that is how it observes the
    /// terminal modes afterwards — so the master never reports a hangup. A quiet
    /// period is the end of output, exactly as the driver's own bounded drain
    /// treats it.
    fn drain(&self, seen: &mut Vec<u8>, quiet: Duration) -> Result<(), String> {
        let mut buffer = [0u8; CHUNK];
        loop {
            match pty::read_chunk(self.pty.master(), &mut buffer, quiet)
                .map_err(|error| format!("cannot read the terminal: {error}"))?
            {
                Some(0) => return Ok(()),
                Some(read) => seen.extend_from_slice(&buffer[..read]),
                None => return Ok(()),
            }
        }
    }

    fn modes(&self) -> Result<rustix::termios::Termios, String> {
        pty::modes(self.pty.slave()).map_err(|error| format!("cannot read the modes: {error}"))
    }

    fn canonical(&self) -> Result<bool, String> {
        Ok(self
            .modes()?
            .local_modes
            .contains(rustix::termios::LocalModes::ICANON))
    }
}

fn check(label: &str, condition: bool, detail: impl FnOnce() -> String) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(format!("{label}: {}", detail()))
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn identity_keeps_every_descriptor_a_terminal(scratch: &Path) -> Result<(), String> {
    let terminal = Terminal::open(scratch)?;
    let mut child = terminal.launch("ok", "guest-probe.sh", "identity", "run")?;
    let mut seen = Vec::new();
    terminal.need(&mut seen, b"IDENTITY-DONE", Duration::from_secs(30))?;
    let status = wait_bounded(&mut child, Duration::from_secs(30))?;
    let seen = text(&seen);
    check(
        "identity",
        status.code() == Some(0) && seen.contains("IDENTITY tty0=1 tty1=1 tty2=1"),
        || format!("status {status}, output {seen:?}"),
    )?;
    check(
        "identity",
        seen.contains("OUT marker") && seen.contains("ERR marker"),
        || format!("a channel was lost: {seen:?}"),
    )
}

fn typed_bytes_reach_the_guest(scratch: &Path) -> Result<(), String> {
    let terminal = Terminal::open(scratch)?;
    let mut child = terminal.launch("ok", "guest-probe.sh", "input", "run")?;
    let mut seen = Vec::new();
    terminal.need(&mut seen, b"INPUT-READY", Duration::from_secs(30))?;
    terminal.write(b"A\x1dB")?;
    terminal.need(&mut seen, b"DONE", Duration::from_secs(30))?;
    let status = wait_bounded(&mut child, Duration::from_secs(30))?;
    let seen = text(&seen);
    check(
        "input",
        status.code() == Some(7) && seen.contains("bytes=411d42"),
        || format!("status {status}, output {seen:?}"),
    )
}

fn a_mangled_byte_changes_what_the_guest_receives(scratch: &Path) -> Result<(), String> {
    let terminal = Terminal::open(scratch)?;
    let mut child = terminal.launch("mangle-input", "guest-probe.sh", "input", "--")?;
    let mut seen = Vec::new();
    terminal.need(&mut seen, b"INPUT-READY", Duration::from_secs(30))?;
    terminal.write(b"A\x1dB")?;
    terminal.need(&mut seen, b"DONE", Duration::from_secs(30))?;
    let status = wait_bounded(&mut child, Duration::from_secs(30))?;
    let seen = text(&seen);
    check(
        "mangle-input",
        status.code() == Some(7) && seen.contains("bytes=414142"),
        || format!("the escape byte was not mangled: status {status}, output {seen:?}"),
    )
}

fn streamed_input_reaches_the_guest_exactly(scratch: &Path) -> Result<(), String> {
    let terminal = Terminal::open(scratch)?;
    let mut child = terminal.launch("ok", "guest-probe.sh", "stream-input", "run")?;
    let mut seen = Vec::new();
    terminal.need(&mut seen, b"STREAM-READY", Duration::from_secs(30))?;
    // Canonical mode is what makes the empty-line VEOF the host's EOF; a
    // launcher must not have touched it for a streamed stdin.
    check("stream-input", terminal.canonical()?, || {
        "the launcher put a streamed terminal stdin into raw mode".to_owned()
    })?;
    terminal.write(b"stream-A\n")?;
    terminal.write(b"stream-B")?;
    terminal.write(b"\n")?;
    terminal.write(b"\x04")?;
    terminal.need(&mut seen, b"STREAM-DONE", Duration::from_secs(30))?;
    let status = wait_bounded(&mut child, Duration::from_secs(30))?;
    let seen = text(&seen);
    check(
        "stream-input",
        status.code() == Some(23) && seen.contains("bytes=18"),
        || format!("status {status}, output {seen:?}"),
    )?;
    check(
        "stream-input",
        seen.contains("hex=73747265616d2d410a73747265616d2d420a"),
        || format!("the guest received different bytes: {seen:?}"),
    )
}

fn a_truncated_stream_cuts_the_payload(scratch: &Path) -> Result<(), String> {
    let terminal = Terminal::open(scratch)?;
    let mut child = terminal.launch("stream-truncated", "guest-probe.sh", "stream-input", "run")?;
    let mut seen = Vec::new();
    terminal.need(&mut seen, b"STREAM-READY", Duration::from_secs(30))?;
    terminal.write(b"stream-A\n")?;
    terminal.write(b"stream-B")?;
    terminal.write(b"\n")?;
    terminal.write(b"\x04")?;
    terminal.need(&mut seen, b"STREAM-DONE", Duration::from_secs(30))?;
    let status = wait_bounded(&mut child, Duration::from_secs(30))?;
    let seen = text(&seen);
    check(
        "stream-truncated",
        status.code() == Some(23) && seen.contains("bytes=15"),
        || format!("the payload was not cut at 15 bytes: status {status}, output {seen:?}"),
    )
}

fn a_held_stream_never_delivers_eof(scratch: &Path) -> Result<(), String> {
    let terminal = Terminal::open(scratch)?;
    let mut child = terminal.launch("stream-no-eof", "guest-probe.sh", "stream-input", "run")?;
    let mut seen = Vec::new();
    terminal.need(&mut seen, b"STREAM-READY", Duration::from_secs(30))?;
    terminal.write(b"stream-A\nstream-B\n")?;
    // The host's own end of file — the empty-line VEOF — arrives, so everything
    // is forwarded; the launcher then holds its end of the guest's stdin open, so
    // no end of stream can reach the guest.
    terminal.write(b"\x04")?;
    let early = terminal.need(&mut seen, b"STREAM-DONE", Duration::from_millis(1500));
    check("stream-no-eof", early.is_err(), || {
        format!("the guest finished early: {:?}", text(&seen))
    })?;
    // Stopping the launcher closes the only write end of the guest's stdin, and
    // only then does the guest finish: what kept it waiting was the launcher's
    // held pipe, not the terminal. Unlike a session leader's death, this leaves
    // the guest running long enough to report.
    let status = child
        .stop()
        .map_err(|error| format!("cannot stop the holding stand-in: {error}"))?;
    check("stream-no-eof", !status.success(), || {
        format!("the holding stand-in exited on its own: {status}")
    })?;
    terminal.need(&mut seen, b"STREAM-DONE", Duration::from_secs(30))?;
    let seen = text(&seen);
    check("stream-no-eof", seen.contains("bytes=18"), || {
        format!("the guest never saw its end of stream: {seen:?}")
    })
}

fn a_resize_is_relayed_to_the_guest(scratch: &Path) -> Result<(), String> {
    let terminal = Terminal::open(scratch)?;
    // The geometry the guest starts with is the launcher's, not the operator's.
    check(
        "resize",
        terminal
            .pty
            .size()
            .map_err(|error| format!("cannot read the size: {error}"))?
            == pty::WindowSize::new(24, 80),
        || "the terminal did not start at 24x80".to_owned(),
    )?;
    let mut child = terminal.launch("ok", "guest-probe.sh", "resize", "run")?;
    let mut seen = Vec::new();
    terminal.need(&mut seen, b"RESIZE-READY", Duration::from_secs(30))?;
    terminal
        .pty
        .set_size(pty::WindowSize::new(43, 119))
        .map_err(|error| format!("cannot resize the terminal: {error}"))?;
    pty::send_signal(child.id(), Signal::WINCH)
        .map_err(|error| format!("cannot signal the stand-in: {error}"))?;
    terminal.need(&mut seen, b"RESIZE-DONE", Duration::from_secs(30))?;
    let status = wait_bounded(&mut child, Duration::from_secs(30))?;
    let seen = text(&seen);
    check(
        "resize",
        status.code() == Some(7) && seen.contains("RESIZED 43 119"),
        || format!("status {status}, output {seen:?}"),
    )?;
    check("resize", !seen.contains("RESIZE-TIMEOUT"), || {
        format!("the guest timed out: {seen:?}")
    })
}

fn a_launcher_that_never_relays_leaves_the_guest_waiting(scratch: &Path) -> Result<(), String> {
    let terminal = Terminal::open(scratch)?;
    let mut child = terminal.launch("no-winch", "resize-probe.sh", "", "run")?;
    let mut seen = Vec::new();
    terminal.need(&mut seen, b"RESIZE-READY", Duration::from_secs(30))?;
    terminal
        .pty
        .set_size(pty::WindowSize::new(43, 119))
        .map_err(|error| format!("cannot resize the terminal: {error}"))?;
    pty::send_signal(child.id(), Signal::WINCH)
        .map_err(|error| format!("cannot signal the stand-in: {error}"))?;
    terminal.need(&mut seen, b"RESIZE-TIMEOUT", Duration::from_secs(30))?;
    let status = wait_bounded(&mut child, Duration::from_secs(30))?;
    let seen = text(&seen);
    check(
        "no-winch",
        status.code() == Some(90) && seen.contains("winch=0"),
        || format!("the guest believed a resize arrived: status {status}, output {seen:?}"),
    )?;
    // This variant still takes the terminal raw and gives it back: only the
    // notification is broken.
    check("no-winch", terminal.canonical()?, || {
        "the stand-in did not restore the terminal it took raw".to_owned()
    })
}

fn a_leftover_raw_terminal_is_visible(scratch: &Path) -> Result<(), String> {
    let terminal = Terminal::open(scratch)?;
    let mut child = terminal.launch("raw-leftover", "guest-probe.sh", "identity", "run")?;
    let mut seen = Vec::new();
    terminal.need(&mut seen, b"IDENTITY-DONE", Duration::from_secs(30))?;
    let status = wait_bounded(&mut child, Duration::from_secs(30))?;
    check("raw-leftover", status.code() == Some(0), || {
        format!("status {status}")
    })?;
    check("raw-leftover", !terminal.canonical()?, || {
        "the variant restored the terminal, so the driver's oracle would miss it".to_owned()
    })
}

fn an_early_exit_reaches_no_readiness(scratch: &Path) -> Result<(), String> {
    let terminal = Terminal::open(scratch)?;
    let mut child = terminal.launch("early-exit", "guest-probe.sh", "identity", "run")?;
    let mut seen = Vec::new();
    terminal.drain(&mut seen, Duration::from_millis(500))?;
    let status = wait_bounded(&mut child, Duration::from_secs(30))?;
    check(
        "early-exit",
        status.code() == Some(0) && seen.is_empty(),
        || {
            format!(
                "status {status} after writing {:?}, so a readiness barrier could be met",
                text(&seen)
            )
        },
    )
}

/// The frames of every prompt takeover, in the order the driver's oracle reads
/// them.
fn a_prompt_takeover_orders_its_frames(scratch: &Path) -> Result<(), String> {
    for (mode, modes_back, line_17, redraw) in [
        ("prompt-ok", true, true, false),
        ("prompt-no-modes", false, true, false),
        ("prompt-drop-line", true, false, false),
        ("prompt-redraw-after-leave", true, true, true),
    ] {
        let terminal = Terminal::open(scratch)?;
        let mut child = terminal.launch(mode, "refuse/guest-probe.sh", "refuse", "run")?;
        let mut seen = Vec::new();
        terminal.need(&mut seen, b"REFUSE-READY", Duration::from_secs(30))?;
        terminal.need(&mut seen, PROMPT_INSTRUCTION, Duration::from_secs(30))?;
        check(mode, contains(&seen, PROMPT_ENTER), || {
            format!("the takeover frame never appeared: {:?}", text(&seen))
        })?;
        // The answer is a line: a letter, then Enter.
        terminal.write(ANSWER_KEY)?;
        terminal.write(ANSWER_ENTER)?;
        terminal.need(&mut seen, b"HELD-DONE", Duration::from_secs(30))?;
        terminal.drain(&mut seen, Duration::from_millis(300))?;
        let status = wait_bounded(&mut child, Duration::from_secs(30))?;
        check(mode, status.code() == Some(9), || {
            format!("status {status} instead of the guest's 9")
        })?;
        check(mode, contains(&seen, PROMPT_LEAVE), || {
            format!("no leave frame in {:?}", text(&seen))
        })?;
        check(
            mode,
            contains(&seen, PROMPT_MODES_BACK) == modes_back,
            || {
                format!(
                    "the guest's modes were {}restored: {:?}",
                    if modes_back { "not " } else { "" },
                    text(&seen)
                )
            },
        )?;
        check(mode, contains(&seen, b"LINE 17") == line_17, || {
            format!("the held-line drop is wrong in {:?}", text(&seen))
        })?;
        check(mode, contains(&seen, b"LINE 16"), || {
            format!("a held line before LINE 17 went missing: {:?}", text(&seen))
        })?;
        check(mode, contains(&seen, b"LINE 18"), || {
            format!("a held line after LINE 17 went missing: {:?}", text(&seen))
        })?;
        check(mode, contains(&seen, &prompt_input(ANSWER_KEY)), || {
            format!("the typed line was not echoed: {:?}", text(&seen))
        })?;
        let leave = seen
            .windows(PROMPT_LEAVE.len())
            .position(|window| window == PROMPT_LEAVE)
            .unwrap_or(0);
        let redrawn = seen
            .windows(PROMPT_REDRAW_AFTER_LEAVE.len())
            .rposition(|window| window == PROMPT_REDRAW_AFTER_LEAVE)
            .is_some_and(|at| at > leave);
        check(mode, redrawn == redraw, || {
            format!("the redraw after the leave is wrong in {:?}", text(&seen))
        })?;
        // Nothing the guest wrote while the question was up may be released
        // before the leave, and everything must arrive in order afterwards.
        check(mode, !contains(&seen[..leave], b"LINE 0"), || {
            format!("held output leaked before the leave: {:?}", text(&seen))
        })?;
        let held = &seen[leave..];
        let mut last = 0;
        for index in 0..20 {
            let line = format!("LINE {index}");
            if !line_17 && line == "LINE 17" {
                continue;
            }
            let Some(at) = held
                .windows(line.len())
                .position(|window| window == line.as_bytes())
            else {
                return Err(format!("{mode}: {line} never arrived in {:?}", text(&seen)));
            };
            check(mode, at >= last, || {
                format!("{mode}: the held lines are out of order at {line}")
            })?;
            last = at;
        }
        check(mode, terminal.canonical()?, || {
            format!("{mode}: the stand-in left the terminal raw")
        })?;
    }
    Ok(())
}

/// One request, one reply: the cadence must then take the answer line and echo it.
fn a_launcher_answer_cadence_answers_once(scratch: &Path) -> Result<(), String> {
    let terminal = Terminal::open(scratch)?;
    let mut child = terminal.launch("prompt-cadence", "refuse/guest-probe.sh", "refuse", "run")?;
    let mut seen = Vec::new();
    terminal.need(&mut seen, b"REFUSE-READY", Duration::from_secs(30))?;
    terminal.need(&mut seen, PROMPT_CURSOR_REQUEST, Duration::from_secs(30))?;
    terminal.write(PROMPT_ANSWER)?;
    // The one reply puts the empty input row back, and only then may the answer
    // be typed: a cadence that is still counting has not offered the line yet.
    terminal.need_count(&mut seen, PROMPT_INPUT, 2, Duration::from_secs(30))?;
    terminal.write(ANSWER_KEY)?;
    terminal.write(ANSWER_ENTER)?;
    terminal.need(&mut seen, b"HELD-DONE", Duration::from_secs(30))?;
    let status = wait_bounded(&mut child, Duration::from_secs(30))?;
    let seen = text(&seen);
    check(
        "prompt-cadence",
        status.code() == Some(9) && seen.contains("HELD-DONE"),
        || format!("status {status}, output {seen:?}"),
    )?;
    // The answered line is echoed on the input row, as the product draws it.
    check(
        "prompt-cadence",
        contains(seen.as_bytes(), &prompt_input(ANSWER_KEY)),
        || format!("the answered line was not echoed: {seen:?}"),
    )
}

/// Two replies to the one request must abandon the question: the class the
/// cadence exists to catch (H16).
fn a_second_reply_abandons_the_question(scratch: &Path) -> Result<(), String> {
    let terminal = Terminal::open(scratch)?;
    let mut child = terminal.launch("prompt-cadence", "refuse/guest-probe.sh", "refuse", "run")?;
    let mut seen = Vec::new();
    terminal.need(&mut seen, b"REFUSE-READY", Duration::from_secs(30))?;
    terminal.need(&mut seen, PROMPT_CURSOR_REQUEST, Duration::from_secs(30))?;
    // Two replies in one write: the terminal coalesced them, and a driver that
    // answered twice must still be caught.
    terminal.write(&[PROMPT_ANSWER, PROMPT_ANSWER].concat())?;
    // The question is left unanswered, so the leave and the held output arrive
    // without an answer: a cadence that took the two replies as one would still
    // be waiting for a line nobody typed when this bound expired.
    terminal.need(&mut seen, b"HELD-DONE", ABANDONED_WITHIN)?;
    let status = wait_bounded(&mut child, Duration::from_secs(30))?;
    let seen = text(&seen);
    check("prompt-cadence", status.code() == Some(9), || {
        format!("status {status} instead of the guest's 9")
    })?;
    check(
        "prompt-cadence",
        contains(seen.as_bytes(), PROMPT_LEAVE),
        || format!("the question was never left: {seen:?}"),
    )?;
    check(
        "prompt-cadence",
        !contains(seen.as_bytes(), &prompt_input(ANSWER_KEY)),
        || format!("an answered line was echoed with no answer typed: {seen:?}"),
    )
}

fn no_program_after_the_boundary_is_misuse() -> Result<(), String> {
    let outcome = launch(&[
        OsString::from("--image"),
        OsString::from("image"),
        OsString::from("run"),
    ]);
    match outcome {
        Err(error) if error == die("no program after the command boundary") => {
            check("boundary", failure_status(&error) == Some(64), || {
                "the misuse status is not 64".to_owned()
            })
        }
        Err(error) => Err(format!("a missing program reported {error:?}")),
        Ok(_) => Err("a missing program ran instead of being refused".to_owned()),
    }
}

/// A directory the controls may write into, removed on drop.
struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new(label: &str) -> io::Result<Self> {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let path = env::temp_dir().join(format!(
            "agent-vm-harness-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(words: &[&str]) -> Vec<OsString> {
        words.iter().map(OsString::from).collect()
    }

    #[test]
    fn a_launch_boundary_is_consumed_with_the_options_before_it() {
        let words = argv(&["--image", "x", "run", "bash", "./guest-probe.sh", "input"]);
        let (program, mode) = split_argv(&words).expect("a program follows the boundary");
        assert_eq!(program[0], "bash");
        assert_eq!(mode, "input");

        let words = argv(&["-t", "--", "bash", "./guest-probe.sh"]);
        let (_, mode) = split_argv(&words).expect("a program follows the boundary");
        assert_eq!(mode, "");
    }

    #[test]
    fn a_program_without_a_boundary_is_not_a_program() {
        let words = argv(&["--image", "x"]);
        assert_eq!(
            split_argv(&words),
            Err(die("no program after the command boundary"))
        );
    }

    #[test]
    fn the_probe_mode_is_only_read_from_a_guest_probe() {
        let words = argv(&["--", "sh", "-c", "refuse", "input"]);
        let (_, mode) = split_argv(&words).expect("a program follows the boundary");
        assert_eq!(mode, "");
    }

    #[test]
    fn a_cursor_reply_is_counted_once_per_request() {
        assert_eq!(count_cursor_replies(b"\x1b[24;80R"), 1);
        assert_eq!(count_cursor_replies(b"\x1b[24;80R\x1b[1;1R"), 2);
        assert_eq!(count_cursor_replies(b"\x1b[24;80"), 0);
        assert_eq!(count_cursor_replies(b"\x1b[;80R"), 0);
        assert_eq!(count_cursor_replies(b"plain"), 0);
    }

    #[test]
    fn a_reply_is_not_part_of_the_typed_line() {
        assert_eq!(
            without_cursor_replies(b"\x1b[9;1Rd\r"),
            b"d\r",
            "the terminal's reply must not be echoed as part of the answer"
        );
        assert_eq!(without_cursor_replies(b"session"), b"session");
        assert_eq!(without_cursor_replies(b"\x1b[9;1"), b"\x1b[9;1");
    }

    #[test]
    fn the_enter_comes_off_the_line_and_not_the_letters() {
        assert_eq!(without_enter(b"d\r\n"), b"d");
        assert_eq!(without_enter(b"d\r"), b"d");
        assert_eq!(without_enter(b"deny"), b"deny");
    }

    #[test]
    fn the_input_row_echoes_the_typed_line_under_its_cursor() {
        assert_eq!(prompt_input(b""), PROMPT_INPUT);
        assert_eq!(prompt_input(b"d"), b"\x1b[9;1H\x1b[2Kd_");
        assert_eq!(prompt_input(b"session"), b"\x1b[9;1H\x1b[2Ksession_");
    }

    #[test]
    fn the_enter_frame_ends_with_its_one_position_request() {
        assert!(
            PROMPT_ENTER.ends_with(PROMPT_CURSOR_REQUEST),
            "the takeover must ask for the input row's position once"
        );
        assert_eq!(
            PROMPT_ENTER
                .windows(PROMPT_CURSOR_REQUEST.len())
                .filter(|window| *window == PROMPT_CURSOR_REQUEST)
                .count(),
            1,
            "one takeover, one position request"
        );
    }

    #[test]
    fn the_first_line_seventeen_is_dropped() {
        assert_eq!(
            drop_first_line(b"LINE 16\r\nLINE 17\r\nLINE 18\r\n"),
            b"LINE 16\r\nLINE 18\r\n"
        );
        assert_eq!(drop_first_line(b"LINE 17\nLINE 18\n"), b"LINE 18\n");
        assert_eq!(drop_first_line(b"LINE 16\n"), b"LINE 16\n");
    }

    #[test]
    fn the_mode_names_are_the_pythons() {
        assert_eq!(Mode::from_name("ok"), Mode::Correct);
        assert_eq!(Mode::from_name(""), Mode::Correct);
        assert_eq!(Mode::from_name("no-winch"), Mode::NoWinch);
        assert_eq!(
            Mode::from_name("prompt-cadence"),
            Mode::Prompt(Prompt::CADENCE)
        );
        assert_eq!(Mode::from_name("prompt-ok"), Mode::Prompt(Prompt::PLAIN));
        assert_eq!(
            Mode::from_name("prompt-redraw-after-leave"),
            Mode::Prompt(Prompt::REDRAW_AFTER_LEAVE)
        );
    }
}
