//! `fake-notifier`: the independent NDJSON v1 oracle for the notifier transport
//! (issue #501 slice 4, S6).
//!
//! `agent-vm`'s driver writes one line of JSON per command to the macOS helper
//! and reads one line of JSON per event back. The authority for that wire is
//! `crates/agent-vm/src/notify/helper.rs`; this module is a **second** model of
//! it, written from the protocol instead of imported from the crate, so `agent-vm`
//! cannot drift from the wire and still pass (ADR-0072: the harness keeps its own
//! idea of every format it reads or writes).
//!
//! **stdout is the protocol.** A scenario's verdict, its recorded violations and
//! any complaint about the scenario itself go to stderr or to `--verdict FILE`,
//! never to stdout: a stray byte there is a frame the launcher would have to
//! parse.
//!
//! # What the scenario says
//!
//! One JSON object, every key optional, an unrecognised key refused so a typo is
//! an error rather than a control that does nothing:
//!
//! ```json
//! {
//!   "launched": {"serving": true},
//!   "auth": {"emit": "ack", "delay_ms": 0, "granted": true,
//!            "status": "authorized", "alert_style": "banner", "error": ""},
//!   "ops": {
//!     "post": {"emit": "ack", "delay_ms": 0, "ok": true, "denied": false, "error": ""},
//!     "remove": {"emit": "ack", "delay_ms": 0, "ok": true},
//!     "quit": {"delay_ms": 0}
//!   },
//!   "after": {"auth": "nothing", "post": "nothing", "remove": "nothing",
//!             "quit": "nothing", "stdin_closed": "nothing"},
//!   "stdin": {"pause_after_ops": 0, "pause_ms": 0},
//!   "expect": {"violations": 0, "ops": ["post", "remove", "quit"]}
//! }
//! ```
//!
//! * `emit` is what the answer to one command looks like:
//!   `ack` (the honest frame), `none` (silence: the launcher's acknowledgement
//!   timeout is what answers), `malformed` (a truncated line), `oversize` (one
//!   frame longer than the 16 KiB cap, which must be skipped without buffering),
//!   `bad_version` (`v: 2`, which must be skipped), `unknown_type` (a `type` this
//!   build does not know, which must also be skipped), `wrong_seq` and `wrong_id`
//!   (an acknowledgement for an operation the launcher did not write, which must
//!   settle nothing).
//! * `after` is what happens once that point has been played: `nothing`, `crash`
//!   (write the verdict, then exit [`CRASH_STATUS`]) or `eof` (close fd 1, so the
//!   launcher reads end-of-file instead of the rest of the run).
//! * `stdin.pause_after_ops` stops reading stdin for `pause_ms` after that many
//!   commands, which is how a test backpressures the launcher's writes.
//! * `expect.violations` is the number of refused command lines this run must
//!   record, and `expect.ops` the accepted command sequence. Both are checked
//!   when the run ends, so a negative control that produced no violation fails
//!   here rather than passing silently. Omitting `expect.ops` skips that check.
//!
//! # What it validates
//!
//! Every incoming line, into the verdict's `violations` transcript: JSON, one
//! object, `v == 1`, a known `op`, and that operation's required fields — a
//! strictly increasing `seq` and a non-empty `id` for `post`/`remove`; the banner
//! text, `passive` and the four click operands (`session` as eight lowercase hex
//! digits, two absolute paths, a known terminal) for `post`. A line with any
//! breach is refused as a whole, so nothing downstream acts on half a command.
//!
//! The events it emits are the ones a `serve` helper emits:
//! `launched`/`auth`/`posted`/`removed`/`stdin_closed`. `stdin_closed` is emitted
//! when stdin ends before `quit` does — the same rule the helper follows — while
//! `quit` ends this process at once, because a helper that has been asked to leave
//! answers nothing further and the launcher's next read is end-of-file either way.

use std::io::{self, BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use clap::Args as ClapArgs;
use serde_json::{Map, Value, json};

use crate::Outcome;

/// The longest command line this oracle reads, in bytes: the helper's own cap
/// (`helper.rs::MAX_HELPER_LINE_BYTES`, mirrored by `Notifier.swift`). A longer
/// line is skipped up to its terminator rather than buffered, and refused.
const MAX_COMMAND_BYTES: usize = 16 * 1024;

/// What a `crash` control exits with. Not 0 (a crash that looked like a clean
/// exit would prove nothing) and not 1 (this command's own failing verdict).
const CRASH_STATUS: i32 = 3;

/// The four click operands' terminal vocabulary, spelled here so a value the
/// helper could never accept is refused at the wire.
const TERMINALS: [&str; 4] = ["terminal", "ghostty", "wezterm", "alacritty"];

#[derive(Debug, ClapArgs)]
pub struct FakeNotifierArgs {
    /// The scenario this run plays, as JSON (see the module documentation).
    #[arg(long)]
    scenario: PathBuf,
    /// Where the verdict JSON goes. Default: stderr, beside the one-line summary.
    #[arg(long)]
    verdict: Option<PathBuf>,
    /// Ignored: the helper's own argv (`serve`) and a wrapper's passthrough, so a
    /// test can point the production spawner at this binary unchanged.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    passthrough: Vec<String>,
}

/// Play one scenario.
pub fn run(args: FakeNotifierArgs) -> Result<Outcome, String> {
    let text = std::fs::read_to_string(&args.scenario)
        .map_err(|error| format!("reading the scenario {}: {error}", args.scenario.display()))?;
    let scenario = Scenario::parse(&text)?;
    let serving = args.passthrough.iter().any(|argument| argument == "serve");
    let mut oracle = Oracle::new(serving, scenario, args.verdict);
    oracle.play();
    let (problems, summary) = oracle.finish();
    if problems.is_empty() {
        eprintln!("fake-notifier: OK ({summary})");
        Ok(Outcome::Exit(0))
    } else {
        eprintln!("fake-notifier: FAIL: {}", problems.join("; "));
        Ok(Outcome::Exit(1))
    }
}

// ---------------------------------------------------------------------------
// The scenario
// ---------------------------------------------------------------------------

/// What one answer to a command looks like.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Emit {
    Ack,
    None,
    Malformed,
    Oversize,
    BadVersion,
    UnknownType,
    WrongSeq,
    WrongId,
}

impl Emit {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "ack" => Some(Self::Ack),
            "none" => Some(Self::None),
            "malformed" => Some(Self::Malformed),
            "oversize" => Some(Self::Oversize),
            "bad_version" => Some(Self::BadVersion),
            "unknown_type" => Some(Self::UnknownType),
            "wrong_seq" => Some(Self::WrongSeq),
            "wrong_id" => Some(Self::WrongId),
            _ => None,
        }
    }
}

/// What happens once a point of the run has been played.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum After {
    Nothing,
    Crash,
    Eof,
}

impl After {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "nothing" => Some(Self::Nothing),
            "crash" => Some(Self::Crash),
            "eof" => Some(Self::Eof),
            _ => None,
        }
    }
}

/// The points a scenario can react at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Point {
    Auth,
    Post,
    Remove,
    Quit,
    StdinClosed,
}

impl Point {
    fn key(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Post => "post",
            Self::Remove => "remove",
            Self::Quit => "quit",
            Self::StdinClosed => "stdin_closed",
        }
    }
}

#[derive(Debug)]
struct AuthPlan {
    emit: Emit,
    delay_ms: u64,
    granted: bool,
    status: String,
    alert_style: String,
    error: String,
}

#[derive(Debug)]
struct OpPlan {
    emit: Emit,
    delay_ms: u64,
    ok: bool,
    denied: bool,
    error: String,
}

impl OpPlan {
    fn honest() -> Self {
        Self {
            emit: Emit::Ack,
            delay_ms: 0,
            ok: true,
            denied: false,
            error: String::new(),
        }
    }
}

#[derive(Debug)]
struct Scenario {
    serving: Option<bool>,
    auth: AuthPlan,
    post: OpPlan,
    remove: OpPlan,
    quit_delay_ms: u64,
    after: Vec<(Point, After)>,
    pause_after_ops: u64,
    pause_ms: u64,
    expect_violations: usize,
    expect_ops: Option<Vec<String>>,
}

impl Default for Scenario {
    fn default() -> Self {
        Self {
            serving: None,
            auth: AuthPlan {
                emit: Emit::Ack,
                delay_ms: 0,
                granted: true,
                status: "authorized".to_owned(),
                alert_style: "banner".to_owned(),
                error: String::new(),
            },
            post: OpPlan::honest(),
            remove: OpPlan::honest(),
            quit_delay_ms: 0,
            after: vec![
                (Point::Auth, After::Nothing),
                (Point::Post, After::Nothing),
                (Point::Remove, After::Nothing),
                (Point::Quit, After::Nothing),
                (Point::StdinClosed, After::Nothing),
            ],
            pause_after_ops: 0,
            pause_ms: 0,
            expect_violations: 0,
            expect_ops: None,
        }
    }
}

impl Scenario {
    fn parse(text: &str) -> Result<Self, String> {
        let value: Value = serde_json::from_str(text)
            .map_err(|error| format!("the scenario is not JSON: {error}"))?;
        let root = value
            .as_object()
            .ok_or_else(|| "the scenario is not a JSON object".to_owned())?;
        let mut scenario = Self::default();
        let mut seen: Vec<String> = Vec::new();
        for (key, value) in root {
            seen.push(key.clone());
            match key.as_str() {
                "launched" => {
                    let plan = Reader::new(value, "launched")?.closed(&["serving"])?;
                    scenario.serving = plan.optional_bool("serving")?;
                }
                "auth" => {
                    let plan = Reader::new(value, "auth")?.closed(&[
                        "emit",
                        "delay_ms",
                        "granted",
                        "status",
                        "alert_style",
                        "error",
                    ])?;
                    scenario.auth.emit = plan.emit("emit")?;
                    scenario.auth.delay_ms = plan.optional_u64("delay_ms")?.unwrap_or(0);
                    scenario.auth.granted = plan
                        .optional_bool("granted")?
                        .unwrap_or(scenario.auth.granted);
                    scenario.auth.status = plan
                        .optional_text("status")?
                        .unwrap_or(scenario.auth.status);
                    scenario.auth.alert_style = plan
                        .optional_text("alert_style")?
                        .unwrap_or(scenario.auth.alert_style);
                    scenario.auth.error = plan.optional_text("error")?.unwrap_or_default();
                }
                "ops" => {
                    let ops = Reader::new(value, "ops")?.closed(&["post", "remove", "quit"])?;
                    for (name, body) in ops.items() {
                        match name.as_str() {
                            "post" => {
                                let plan = Reader::new(body, "ops.post")?
                                    .closed(&["emit", "delay_ms", "ok", "denied", "error"])?;
                                scenario.post.emit = plan.emit("emit")?;
                                scenario.post.delay_ms =
                                    plan.optional_u64("delay_ms")?.unwrap_or(0);
                                scenario.post.ok = plan.optional_bool("ok")?.unwrap_or(true);
                                scenario.post.denied =
                                    plan.optional_bool("denied")?.unwrap_or(false);
                                scenario.post.error =
                                    plan.optional_text("error")?.unwrap_or_default();
                            }
                            "remove" => {
                                let plan = Reader::new(body, "ops.remove")?
                                    .closed(&["emit", "delay_ms", "ok", "error"])?;
                                scenario.remove.emit = plan.emit("emit")?;
                                scenario.remove.delay_ms =
                                    plan.optional_u64("delay_ms")?.unwrap_or(0);
                                scenario.remove.ok = plan.optional_bool("ok")?.unwrap_or(true);
                                scenario.remove.error =
                                    plan.optional_text("error")?.unwrap_or_default();
                            }
                            "quit" => {
                                let plan = Reader::new(body, "ops.quit")?.closed(&["delay_ms"])?;
                                scenario.quit_delay_ms =
                                    plan.optional_u64("delay_ms")?.unwrap_or(0);
                            }
                            other => {
                                return Err(format!(
                                    "ops.{other} is not an operation; post, remove and quit are"
                                ));
                            }
                        }
                    }
                }
                "after" => {
                    let plan = Reader::new(value, "after")?.closed(&[
                        "auth",
                        "post",
                        "remove",
                        "quit",
                        "stdin_closed",
                    ])?;
                    for (name, body) in plan.items() {
                        let point = scenario
                            .after
                            .iter()
                            .map(|(point, _)| *point)
                            .find(|point| point.key() == name)
                            .ok_or_else(|| {
                                format!("after.{name} is not a point of the run; auth, post, remove, quit and stdin_closed are")
                            })?;
                        let text = body
                            .as_str()
                            .ok_or_else(|| format!("after.{name} is not a string"))?;
                        let after = After::parse(text).ok_or_else(|| {
                            format!("after.{name} is '{text}', not nothing, crash or eof")
                        })?;
                        for entry in &mut scenario.after {
                            if entry.0 == point {
                                entry.1 = after;
                            }
                        }
                    }
                }
                "stdin" => {
                    let plan =
                        Reader::new(value, "stdin")?.closed(&["pause_after_ops", "pause_ms"])?;
                    scenario.pause_after_ops = plan.optional_u64("pause_after_ops")?.unwrap_or(0);
                    scenario.pause_ms = plan.optional_u64("pause_ms")?.unwrap_or(0);
                }
                "expect" => {
                    let plan = Reader::new(value, "expect")?.closed(&["violations", "ops"])?;
                    scenario.expect_violations =
                        usize::try_from(plan.optional_u64("violations")?.unwrap_or(0))
                            .map_err(|_| "expect.violations is out of range".to_owned())?;
                    if let Some(ops) = plan.get("ops") {
                        let list = ops
                            .as_array()
                            .ok_or_else(|| "expect.ops is not an array".to_owned())?;
                        let mut wanted = Vec::new();
                        for entry in list {
                            let name = entry.as_str().ok_or_else(|| {
                                "expect.ops holds a value that is not a string".to_owned()
                            })?;
                            if !matches!(name, "post" | "remove" | "quit") {
                                return Err(format!(
                                    "expect.ops names '{name}', not post, remove or quit"
                                ));
                            }
                            wanted.push(name.to_owned());
                        }
                        scenario.expect_ops = Some(wanted);
                    }
                }
                other => {
                    return Err(format!(
                        "the scenario has no key '{other}'; it has launched, auth, ops, after, stdin and expect"
                    ));
                }
            }
        }
        if seen.is_empty() {
            return Err("the scenario states nothing; every key is omitted".to_owned());
        }
        Ok(scenario)
    }

    fn after(&self, point: Point) -> After {
        self.after
            .iter()
            .find(|(at, _)| *at == point)
            .map(|(_, after)| *after)
            .unwrap_or(After::Nothing)
    }
}

/// One JSON object of the scenario, read through one door so an unknown key can
/// be refused and every type error names its own path.
struct Reader<'a> {
    map: &'a Map<String, Value>,
    path: String,
}

impl<'a> Reader<'a> {
    fn new(value: &'a Value, path: &str) -> Result<Self, String> {
        let map = value
            .as_object()
            .ok_or_else(|| format!("{path} is not a JSON object"))?;
        Ok(Self {
            map,
            path: path.to_owned(),
        })
    }

    /// The same object, with every key outside `known` refused.
    fn closed(self, known: &[&str]) -> Result<Self, String> {
        for key in self.map.keys() {
            if !known.contains(&key.as_str()) {
                return Err(format!(
                    "{} has no key '{key}'; it has {}",
                    self.path,
                    known.join(", ")
                ));
            }
        }
        Ok(self)
    }

    fn items(&self) -> impl Iterator<Item = (&String, &Value)> {
        self.map.iter()
    }

    fn get(&self, key: &str) -> Option<&Value> {
        self.map.get(key)
    }

    fn optional_text(&self, key: &str) -> Result<Option<String>, String> {
        match self.map.get(key) {
            None => Ok(None),
            Some(Value::String(text)) => Ok(Some(text.clone())),
            Some(_) => Err(format!("{}.{key} is not a string", self.path)),
        }
    }

    fn optional_bool(&self, key: &str) -> Result<Option<bool>, String> {
        match self.map.get(key) {
            None => Ok(None),
            Some(Value::Bool(flag)) => Ok(Some(*flag)),
            Some(_) => Err(format!("{}.{key} is not true or false", self.path)),
        }
    }

    fn optional_u64(&self, key: &str) -> Result<Option<u64>, String> {
        match self.map.get(key) {
            None => Ok(None),
            Some(Value::Number(number)) => number
                .as_u64()
                .map(Some)
                .ok_or_else(|| format!("{}.{key} is not a non-negative integer", self.path)),
            Some(_) => Err(format!("{}.{key} is not a number", self.path)),
        }
    }

    fn emit(&self, key: &str) -> Result<Emit, String> {
        let Some(text) = self.optional_text(key)? else {
            return Ok(Emit::Ack);
        };
        Emit::parse(&text).ok_or_else(|| {
            format!(
                "{}.{key} is '{text}', not one of ack, none, malformed, oversize, bad_version, \
                 unknown_type, wrong_seq, wrong_id",
                self.path
            )
        })
    }
}

// ---------------------------------------------------------------------------
// The wire out
// ---------------------------------------------------------------------------

/// The one writer of stdout, so a frame is a frame and an `eof` control closes
/// the pipe the launcher is reading.
struct Wire {
    closed: bool,
}

impl Wire {
    fn new() -> Self {
        Self { closed: false }
    }

    fn emit(&mut self, frame: Value) {
        let line = serde_json::to_vec(&frame).expect("a frame this file built serializes");
        self.emit_raw(&line);
    }

    fn emit_raw(&mut self, line: &[u8]) {
        if self.closed {
            return;
        }
        let mut stdout = io::stdout().lock();
        let _ = stdout.write_all(line);
        let _ = stdout.write_all(b"\n");
        let _ = stdout.flush();
    }

    /// Close the launcher's read end, so its next read is end-of-file.
    ///
    /// fd 1 is the protocol channel itself: dropping a `Stdout` handle would not
    /// close it (`std::io::stdout` is a global), so the descriptor is closed
    /// directly. Nothing runs long enough afterwards to open a file that could
    /// land on the freed descriptor.
    fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        // SAFETY: closing a descriptor this process owns, once, with no further
        // use of it through any other handle except the guard above.
        unsafe {
            libc::close(1);
        }
    }
}

// ---------------------------------------------------------------------------
// The wire in
// ---------------------------------------------------------------------------

/// One read of stdin, at the helper's own cap.
enum Next {
    Eof,
    /// A line longer than [`MAX_COMMAND_BYTES`]: the rest of it was discarded, and
    /// nothing was buffered.
    Overlong,
    Line(Vec<u8>),
}

struct Commands<R> {
    reader: BufReader<R>,
    line: Vec<u8>,
    discarding: bool,
}

impl<R: io::Read> Commands<R> {
    fn new(reader: R) -> Self {
        Self {
            reader: BufReader::new(reader),
            line: Vec::new(),
            discarding: false,
        }
    }

    /// The next command line, or end-of-file.
    ///
    /// A partial line at end-of-file is dropped rather than refused: the launcher
    /// never ends a command without its terminator, and nothing can tell whether
    /// the rest would have made it a command — the same rule the helper's framing
    /// applies.
    fn next(&mut self) -> io::Result<Next> {
        loop {
            if let Some(end) = self.line.iter().position(|byte| *byte == b'\n') {
                let mut bytes: Vec<u8> = self.line.drain(..=end).collect();
                bytes.pop();
                if self.discarding {
                    self.discarding = false;
                    return Ok(Next::Overlong);
                }
                // A line can reach the terminator in the same read that took it
                // past the cap, so its length is checked here as well as below.
                if bytes.len() > MAX_COMMAND_BYTES {
                    return Ok(Next::Overlong);
                }
                return Ok(Next::Line(bytes));
            }
            if self.line.len() > MAX_COMMAND_BYTES {
                self.line.clear();
                self.discarding = true;
            }
            let available = self.reader.fill_buf()?;
            if available.is_empty() {
                self.line.clear();
                self.discarding = false;
                return Ok(Next::Eof);
            }
            self.line.extend_from_slice(available);
            let read = available.len();
            self.reader.consume(read);
        }
    }
}

/// One command the launcher wrote, once it has been found valid.
enum Command {
    Post { seq: u64, id: String },
    Remove { seq: u64, id: String },
    Quit,
}

impl Command {
    fn kind(&self) -> &'static str {
        match self {
            Self::Post { .. } => "post",
            Self::Remove { .. } => "remove",
            Self::Quit => "quit",
        }
    }
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

/// A command line this oracle refused.
struct Violation {
    op: String,
    seq: Option<u64>,
    reasons: Vec<String>,
}

impl Violation {
    fn to_json(&self) -> Value {
        json!({"op": self.op, "seq": self.seq, "reasons": self.reasons})
    }
}

/// How many commands of each kind this run accepted.
#[derive(Default)]
struct Counts {
    post: u64,
    remove: u64,
    quit: u64,
}

impl Counts {
    fn of(&mut self, command: &Command) {
        match command {
            Command::Post { .. } => self.post += 1,
            Command::Remove { .. } => self.remove += 1,
            Command::Quit => self.quit += 1,
        }
    }

    fn summary(&self) -> String {
        format!("{},{},{}", self.post, self.remove, self.quit)
    }
}

struct Oracle {
    serving: bool,
    scenario: Scenario,
    verdict_path: Option<PathBuf>,
    wire: Wire,
    violations: Vec<Violation>,
    sequence: Vec<String>,
    counts: Counts,
    events: Vec<String>,
    ended: &'static str,
    last_seq: Option<u64>,
    read_ops: u64,
    paused: bool,
}

impl Oracle {
    fn new(serving: bool, scenario: Scenario, verdict_path: Option<PathBuf>) -> Self {
        Self {
            serving: scenario.serving.unwrap_or(serving),
            scenario,
            verdict_path,
            wire: Wire::new(),
            violations: Vec::new(),
            sequence: Vec::new(),
            counts: Counts::default(),
            events: Vec::new(),
            ended: "running",
            last_seq: None,
            read_ops: 0,
            paused: false,
        }
    }

    fn play(&mut self) {
        self.wire.emit(json!({
            "type": "launched",
            "v": 1,
            "serving": self.serving,
            "pid": std::process::id(),
        }));
        self.events.push("launched".to_owned());
        if self.scenario.auth.delay_ms > 0 {
            thread::sleep(Duration::from_millis(self.scenario.auth.delay_ms));
        }
        self.emit_auth();
        if self.follow(Point::Auth) {
            return;
        }
        let mut commands = Commands::new(io::stdin());
        loop {
            self.maybe_pause();
            let next = match commands.next() {
                Ok(next) => next,
                Err(error) => {
                    self.ended = "stdin_error";
                    eprintln!("fake-notifier: reading a command failed: {error}");
                    return;
                }
            };
            match next {
                Next::Eof => {
                    self.ended = "stdin_closed";
                    self.wire.emit(json!({"type": "stdin_closed", "v": 1}));
                    self.events.push("stdin_closed".to_owned());
                    let _ = self.follow(Point::StdinClosed);
                    return;
                }
                Next::Overlong => {
                    self.violations.push(Violation {
                        op: "?".to_owned(),
                        seq: None,
                        reasons: vec![format!("the line is longer than {MAX_COMMAND_BYTES} bytes")],
                    });
                }
                Next::Line(line) => {
                    self.read_ops += 1;
                    if let Some(command) = self.inspect(&line) {
                        let kind = command.kind().to_owned();
                        let point = match kind.as_str() {
                            "post" => Point::Post,
                            "remove" => Point::Remove,
                            _ => Point::Quit,
                        };
                        self.sequence.push(kind.clone());
                        self.counts.of(&command);
                        self.answer(&command);
                        if self.follow(point) {
                            return;
                        }
                        if kind == "quit" {
                            // The helper shuts down on `quit`; nothing is
                            // acknowledged and nothing else is read.
                            self.ended = "quit";
                            return;
                        }
                    }
                }
            }
        }
    }

    /// Backpressure: stop reading stdin for a while after the agreed number of
    /// commands, so a launcher that wrote ahead has to wait for the drain.
    fn maybe_pause(&mut self) {
        if self.paused
            || self.scenario.pause_ms == 0
            || self.read_ops < self.scenario.pause_after_ops
        {
            return;
        }
        self.paused = true;
        if self.scenario.pause_ms > 0 {
            thread::sleep(Duration::from_millis(self.scenario.pause_ms));
        }
    }

    fn emit_auth(&mut self) {
        match self.scenario.auth.emit {
            // A helper that never answers authorization: its absence is the
            // control, so nothing is recorded as emitted.
            Emit::None => return,
            Emit::Malformed => self.wire.emit_raw(b"{\"type\":\"auth\","),
            Emit::Oversize => self.oversized("auth"),
            Emit::BadVersion => {
                let mut frame = self.auth_frame();
                frame["v"] = json!(2);
                self.wire.emit(frame);
            }
            Emit::UnknownType => {
                let mut frame = self.auth_frame();
                frame["type"] = json!("authorization_pending");
                self.wire.emit(frame);
            }
            // `auth` carries neither a `seq` nor an `id`, so those two controls
            // have nothing to skew here and answer honestly.
            Emit::Ack | Emit::WrongSeq | Emit::WrongId => {
                let frame = self.auth_frame();
                self.wire.emit(frame);
            }
        }
        self.events.push("auth".to_owned());
    }

    fn auth_frame(&self) -> Value {
        json!({
            "type": "auth",
            "v": 1,
            "granted": self.scenario.auth.granted,
            "status": self.scenario.auth.status,
            "alertStyle": self.scenario.auth.alert_style,
            "error": self.scenario.auth.error,
        })
    }

    /// A frame that is longer than the cap, then a newline: the launcher must skip
    /// it without buffering and keep reading.
    fn oversized(&mut self, kind: &str) {
        let mut line = format!("{{\"type\":\"{kind}\",\"v\":1,\"pad\":\"").into_bytes();
        line.resize(MAX_COMMAND_BYTES + 64, b'x');
        line.push(b'"');
        line.push(b'}');
        self.wire.emit_raw(&line);
    }

    /// Write the answer to one command. `quit` is answered with nothing but its
    /// delay: the protocol has no `quitted` frame.
    fn answer(&mut self, command: &Command) {
        let (seq, id) = match command {
            Command::Post { seq, id } | Command::Remove { seq, id } => (*seq, id.clone()),
            Command::Quit => {
                if self.scenario.quit_delay_ms > 0 {
                    thread::sleep(Duration::from_millis(self.scenario.quit_delay_ms));
                }
                return;
            }
        };
        let plan = match command {
            Command::Post { .. } => &self.scenario.post,
            _ => &self.scenario.remove,
        };
        let (emit, ok, denied, error, delay_ms) = (
            plan.emit,
            plan.ok,
            plan.denied,
            plan.error.clone(),
            plan.delay_ms,
        );
        if delay_ms > 0 {
            thread::sleep(Duration::from_millis(delay_ms));
        }
        let (kind, event) = match command {
            Command::Post { .. } => ("posted", "posted"),
            _ => ("removed", "removed"),
        };
        match emit {
            Emit::None => {}
            Emit::Malformed => self
                .wire
                .emit_raw(format!("{{\"type\":\"{kind}\",").as_bytes()),
            Emit::Oversize => self.oversized(kind),
            Emit::BadVersion => self.wire.emit(json!({
                "type": event, "v": 2, "seq": seq, "id": id,
            })),
            Emit::UnknownType => self.wire.emit(json!({
                "type": "queued", "v": 1, "seq": seq, "id": id,
            })),
            Emit::WrongSeq => self.wire.emit(json!({
                "type": event, "v": 1, "seq": seq + 100, "id": id, "ok": ok,
            })),
            Emit::WrongId => self.wire.emit(json!({
                "type": event, "v": 1, "seq": seq, "id": "not-the-banner", "ok": ok,
            })),
            Emit::Ack => {
                if kind == "posted" {
                    self.wire.emit(json!({
                        "type": "posted",
                        "v": 1,
                        "seq": seq,
                        "id": id,
                        "ok": ok,
                        "denied": denied,
                        "error": error,
                    }));
                } else {
                    self.wire.emit(json!({
                        "type": "removed",
                        "v": 1,
                        "seq": seq,
                        "id": id,
                        "ok": ok,
                        "error": error,
                    }));
                }
            }
        }
        // `posted:7` is an acknowledgement of `seq` 7; a trailing `!` means it was
        // not the honest `ok: true` frame the scenario asked for.
        self.events.push(format!(
            "{event}:{seq}{}",
            if emit == Emit::Ack && ok { "" } else { "!" }
        ));
    }

    /// What the scenario wants after this point. `true` when the run has ended.
    fn follow(&mut self, point: Point) -> bool {
        match self.scenario.after(point) {
            After::Nothing => false,
            After::Eof => {
                self.ended = "eof";
                self.wire.close();
                true
            }
            After::Crash => {
                self.ended = "crash";
                let (_, summary) = self.finish();
                eprintln!("fake-notifier: crashed as the scenario asked ({summary})");
                std::process::exit(CRASH_STATUS);
            }
        }
    }

    /// Whether this line is a command the launcher may write, recording every
    /// breach as one refused line.
    fn inspect(&mut self, line: &[u8]) -> Option<Command> {
        let value: Value = match serde_json::from_slice(line) {
            Ok(value) => value,
            Err(error) => {
                self.violations.push(Violation {
                    op: "?".to_owned(),
                    seq: None,
                    reasons: vec![format!("not JSON: {error}")],
                });
                return None;
            }
        };
        let Some(object) = value.as_object() else {
            self.violations.push(Violation {
                op: "?".to_owned(),
                seq: None,
                reasons: vec!["a command is a JSON object".to_owned()],
            });
            return None;
        };
        let mut reasons = Vec::new();
        let op = object
            .get("op")
            .and_then(Value::as_str)
            .unwrap_or("?")
            .to_owned();
        match object.get("v") {
            Some(Value::Number(v)) if v.as_u64() == Some(1) => {}
            Some(other) => reasons.push(format!("v is {other}, not 1")),
            None => reasons.push("the command has no v".to_owned()),
        }
        let seq = object.get("seq").and_then(Value::as_u64);
        let required = |object: &Map<String, Value>, key: &str, reasons: &mut Vec<String>| {
            if !object.contains_key(key) {
                reasons.push(format!("the command has no {key}"));
            }
        };
        let non_empty =
            |object: &Map<String, Value>, key: &str, reasons: &mut Vec<String>| match object
                .get(key)
            {
                Some(Value::String(text)) if !text.is_empty() => {}
                Some(Value::String(_)) => reasons.push(format!("{key} is empty")),
                Some(_) => reasons.push(format!("{key} is not a string")),
                None => reasons.push(format!("the command has no {key}")),
            };
        let command = match op.as_str() {
            "post" => {
                let Some(seq) = seq else {
                    reasons.push("the command has no seq".to_owned());
                    self.refuse(op, None, reasons);
                    return None;
                };
                non_empty(object, "id", &mut reasons);
                for key in ["thread", "title", "subtitle", "body"] {
                    required(object, key, &mut reasons);
                    if let Some(value) = object.get(key)
                        && !value.is_string()
                    {
                        reasons.push(format!("{key} is not a string"));
                    }
                }
                if !matches!(object.get("passive"), Some(Value::Bool(_))) {
                    reasons.push("passive is not true or false".to_owned());
                }
                match object.get("click") {
                    Some(Value::Object(click)) => {
                        match click.get("session").and_then(Value::as_str) {
                            Some(session) if is_session_id(session) => {}
                            Some(session) => reasons.push(format!(
                                "click.session '{session}' is not eight lowercase hex digits"
                            )),
                            None => {
                                reasons.push("the command has no click.session".to_owned());
                            }
                        }
                        for key in ["project", "state_dir"] {
                            match click.get(key).and_then(Value::as_str) {
                                Some(path) if Path::new(path).is_absolute() => {}
                                Some(path) => reasons
                                    .push(format!("click.{key} '{path}' is not an absolute path")),
                                None => reasons.push(format!("the command has no click.{key}")),
                            }
                        }
                        match click.get("terminal").and_then(Value::as_str) {
                            Some(terminal) if TERMINALS.contains(&terminal) => {}
                            Some(terminal) => reasons.push(format!(
                                "click.terminal '{terminal}' is not one of {}",
                                TERMINALS.join("/")
                            )),
                            None => {
                                reasons.push("the command has no click.terminal".to_owned());
                            }
                        }
                    }
                    Some(_) => reasons.push("click is not a JSON object".to_owned()),
                    None => reasons.push("the command has no click".to_owned()),
                }
                Some(Command::Post {
                    seq,
                    id: object
                        .get("id")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                })
            }
            "remove" => {
                let Some(seq) = seq else {
                    reasons.push("the command has no seq".to_owned());
                    self.refuse(op, None, reasons);
                    return None;
                };
                non_empty(object, "id", &mut reasons);
                Some(Command::Remove {
                    seq,
                    id: object
                        .get("id")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                })
            }
            "quit" => {
                if object.contains_key("seq") {
                    reasons.push("quit carries no seq".to_owned());
                }
                Some(Command::Quit)
            }
            other => {
                reasons.push(format!("op '{other}' is not post, remove or quit"));
                None
            }
        };
        if let Some(seq) = seq
            && let Some(last) = self.last_seq
            && seq <= last
        {
            reasons.push(format!("seq {seq} does not follow {last}"));
        }
        if !reasons.is_empty() {
            self.refuse(op, seq, reasons);
            return None;
        }
        let command = command.expect("a command with no reasons");
        if let Some(seq) = seq {
            self.last_seq = Some(seq);
        }
        Some(command)
    }

    fn refuse(&mut self, op: String, seq: Option<u64>, reasons: Vec<String>) {
        self.violations.push(Violation { op, seq, reasons });
    }

    /// What the scenario expected and did not get.
    fn problems(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if self.violations.len() != self.scenario.expect_violations {
            problems.push(format!(
                "the scenario expected {} refused command line(s), {} arrived",
                self.scenario.expect_violations,
                self.violations.len()
            ));
        }
        if let Some(wanted) = &self.scenario.expect_ops
            && wanted != &self.sequence
        {
            problems.push(format!(
                "the scenario expected the commands [{}], [{}] arrived",
                wanted.join(", "),
                self.sequence.join(", ")
            ));
        }
        problems
    }

    fn summary(&self) -> String {
        format!(
            "ended={} violations={} ops={} events={}",
            self.ended,
            self.violations.len(),
            self.counts.summary(),
            self.events.join(",")
        )
    }

    /// Write the verdict, and return what failed plus the one-line summary.
    ///
    /// A verdict that cannot be written is a failure, and the verdict is then
    /// printed instead: a caller that asked for a file must never be left with a
    /// clean status and no evidence.
    fn finish(&self) -> (Vec<String>, String) {
        let mut problems = self.problems();
        let verdict = json!({
            "ok": problems.is_empty(),
            "serving": self.serving,
            "ended": self.ended,
            "violations": self
                .violations
                .iter()
                .map(Violation::to_json)
                .collect::<Vec<_>>(),
            "ops": {
                "post": self.counts.post,
                "remove": self.counts.remove,
                "quit": self.counts.quit,
            },
            "sequence": self.sequence,
            "events": self.events,
            "problems": problems,
        });
        let line = serde_json::to_string(&verdict).expect("the verdict serializes");
        match self.verdict_path.as_deref() {
            Some(path) => {
                if let Err(error) = std::fs::write(path, format!("{line}\n")) {
                    problems.push(format!("writing the verdict {}: {error}", path.display()));
                    eprintln!("fake-notifier: verdict: {line}");
                }
            }
            None => eprintln!("fake-notifier: verdict: {line}"),
        }
        (problems, self.summary())
    }
}

/// `^[0-9a-f]{8}$`, spelled as bytes so no locale decides it.
fn is_session_id(text: &str) -> bool {
    text.len() == 8
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
