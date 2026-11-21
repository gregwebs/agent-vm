//! The #501 in-terminal access prompt: sixteen rows and their oracle (#699).
//!
//! Ported from `observe_prompt` and its helpers in
//! `script/test/lib/direct-terminal.py`. The prompt is the product's own frames
//! drawn over a refusing guest, so every fact here is a byte the launcher wrote
//! or a word its own `access` command printed — never a launcher notice.
//!
//! Two things make this oracle more than a substring match, and both were paid
//! for on a real boot:
//!
//! * **A cursor-position reply is not an answer.** The driver must answer the
//!   prompt's one `CSI 6 n` exactly once per takeover. A second reply is host
//!   input inside the typing guard's quiet window, which restarts the guard for
//!   ever; a key written in that window is typing, not an answer. So the reply
//!   count lives in one [`PromptDriver`] per case, and every key is written only
//!   once the *latest* status line is "ready for your answer".
//! * **Held output is judged by position, not by presence.** The guest's 60
//!   `LINE n` (or 300 `BLOCK n`) must arrive once each, in order, after the
//!   leave frame, and nothing may be written between the enter frame and the
//!   leave: the takeover owns the terminal while the question is up.
//!
//! These rows are **native-only** ([`super::Group::control_proven`] is false for
//! the group): the stand-in plays a prompt, so it can prove the byte oracle
//! rejects a broken takeover, but the allowance store and the refusal log are the
//! real launcher's. `--standin` records the `access` check as skipped rather than
//! faking it.

use std::{
    fs,
    os::unix::process::ExitStatusExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use serde_json::{Map, Value, json};

use super::{Invocation, Session, View, marker_deadline, owned_runtime_identity, require};
use crate::pty;

/// The takeover frame's own line: the prompt's evidence, never a launcher notice.
pub const TITLE: &str = "the sandbox refused a network request";
/// The status line that means the guard's quiet window has passed.
const READY: &str = "ready for your answer";
/// The status line a reply or a keystroke puts back.
const STOP_TYPING: &str = "stop typing to answer";
/// §5.7's host restore, byte for byte as `screen::host_restore` builds it.
const HOST_RESTORE: &str = concat!(
    "\x18\x1b[0m\x1b[<u\x1b[?6l\x1b[r\x1b[?1049l",
    "\x1b[?1003l\x1b[?1002l\x1b[?1001l\x1b[?1000l\x1b[?9l",
    "\x1b[?1004l\x1b[?2004l\x1b[?2026l\x1b(B\x1b)B\x0f\x1b[0m",
);
/// The enter and leave frames' own bytes.
const ENTER: &str = "\x1b[?1049h";
const LEAVE: &str = "\x1b[?1049l";
/// A `refuse` probe prints this many held lines.
const LINE_COUNT: u32 = 60;
/// The guest's `exit-during` payload: this many numbered blocks.
const BLOCK_COUNT: u32 = 300;
/// AC1: how soon after the guest's *refusal* the prompt must appear.
const APPEARS_WITHIN: f64 = 1.0;
/// The stall row's bound: its readiness marker precedes the refusal it observes.
const STALL_WITHIN: f64 = 1.5;
/// One `access` invocation. The CLI answers in milliseconds; the bound exists so
/// a hung one fails the row instead of the matrix.
const ACCESS_TIMEOUT: Duration = Duration::from_secs(120);
/// The one key that releases a probe holding the session open for a live check.
const HOLD_RELEASE: &[u8] = b" ";

// --- The rows ---------------------------------------------------------------

/// What a row's `access`/`access allowances` check must find afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessCheck {
    /// The refusal is still listed.
    Refusal,
    /// A session allowance, applied, at a confirmed revision >= 2.
    SessionApplied,
    /// A project allowance, applied to this session and recorded.
    ProjectApplied,
    /// Only a record for the next launch: no session allowance at all.
    ProjectRecordOnly,
    /// No allowance, because no question was ever answered.
    NoAllowance,
    /// First answer wins: whichever surface answered, the other wrote nothing.
    FirstAnswerWins,
}

impl AccessCheck {
    fn name(self) -> &'static str {
        match self {
            AccessCheck::Refusal => "refusal",
            AccessCheck::SessionApplied => "session-applied",
            AccessCheck::ProjectApplied => "project-applied",
            AccessCheck::ProjectRecordOnly => "project-record-only",
            AccessCheck::NoAllowance => "no-allowance",
            AccessCheck::FirstAnswerWins => "first-answer-wins",
        }
    }

    /// A session-scope allowance exists only in a running session, and the probe
    /// holds itself open for exactly this check.
    fn live(self) -> bool {
        matches!(
            self,
            AccessCheck::SessionApplied
                | AccessCheck::ProjectApplied
                | AccessCheck::ProjectRecordOnly
        )
    }
}

/// One prompt row's own facts. The probe words live in the case's `probe`, so a
/// row cannot disagree with the argv it runs.
#[derive(Debug)]
pub struct Row {
    /// The key the driver answers with; `None` means the guest ends the session.
    pub answer: Option<&'static [u8]>,
    pub expect: i32,
    /// AC6/R8: every held line arrives, once, in order, after the leave.
    pub lines: bool,
    /// AC2: the same connect succeeds after the answer, without a restart.
    pub retry_succeeds: bool,
    pub access: Option<AccessCheck>,
    /// AC3/#491: the offer is "from the next launch" and carries no `s`.
    pub offer_project_only: bool,
    /// A sentence the result must say (`next launch`).
    pub result_says: Option<&'static str>,
    /// AC4: a key before the guard, then `ss` in one write, never grants.
    pub guard: bool,
    /// AC12: the CLI answers while the prompt is up; a concurrent `p` must not
    /// record.
    pub answered_elsewhere: bool,
    pub race_key: Option<&'static [u8]>,
    /// AC7: an alternate-screen guest is restored with DECRC, not `?1049l`.
    pub alt: bool,
    /// AC8: a stalled sequence is cut with CAN before the enter frame.
    pub stall: bool,
    /// AC13: the guest's own exit while the question is up.
    pub exit: bool,
    /// AC13: two SIGINTs force the launcher, whose restore appears exactly once.
    pub forced: bool,
    /// AC13: the owned runtime dies while the question is up.
    pub runtime_loss: bool,
    /// AC9: the prompt is off, so no prompt byte may appear at all.
    pub off: bool,
    /// AC4: no answer byte may reach the guest's stdin.
    pub probe_stdin: bool,
}

impl Row {
    const PLAIN: Self = Self {
        answer: None,
        expect: 0,
        lines: false,
        retry_succeeds: false,
        access: None,
        offer_project_only: false,
        result_says: None,
        guard: false,
        answered_elsewhere: false,
        race_key: None,
        alt: false,
        stall: false,
        exit: false,
        forced: false,
        runtime_loss: false,
        off: false,
        probe_stdin: false,
    };
}

/// AC1: a refused connect prompts; `d` restores; the guest continues; `access`
/// still lists the refusal.
pub const DENY: Row = Row {
    answer: Some(b"d"),
    lines: true,
    access: Some(AccessCheck::Refusal),
    ..Row::PLAIN
};
/// AC2: `s` grants a session allowance, applied at revision >= 2, and the same
/// connect then succeeds without a restart.
pub const SESSION: Row = Row {
    answer: Some(b"s"),
    lines: true,
    retry_succeeds: true,
    access: Some(AccessCheck::SessionApplied),
    ..Row::PLAIN
};
/// AC3: the full offer's `p` applies now and records, which `s` does not.
pub const PROJECT: Row = Row {
    answer: Some(b"p"),
    lines: true,
    retry_succeeds: true,
    access: Some(AccessCheck::ProjectApplied),
    ..Row::PLAIN
};
/// AC3/#491: a destination only a record can admit offers "next launch", and only
/// the record is written.
pub const PROJECT_NEXT: Row = Row {
    answer: Some(b"p"),
    access: Some(AccessCheck::ProjectRecordOnly),
    offer_project_only: true,
    result_says: Some("next launch"),
    ..Row::PLAIN
};
/// AC4: a key typed before the guard, then `ss` in one write, never grants, and
/// no answer byte reaches the guest.
pub const GUARD: Row = Row {
    answer: Some(b"d"),
    guard: true,
    access: Some(AccessCheck::NoAllowance),
    probe_stdin: true,
    ..Row::PLAIN
};
/// AC12: a CLI `access allow` closes the shown prompt, and a `p` typed while that
/// grant is in flight must never write a project record.
pub const ANSWERED_ELSEWHERE: Row = Row {
    answered_elsewhere: true,
    race_key: Some(b"p"),
    access: Some(AccessCheck::FirstAnswerWins),
    ..Row::PLAIN
};
/// AC7's alternate-screen half: DECRC, the host's final size, a redraw asked for.
pub const ALT_SCREEN: Row = Row {
    answer: Some(b"d"),
    alt: true,
    ..Row::PLAIN
};
/// AC8: a stalled sequence is cut with CAN, and the prompt is up by 1.5 s.
pub const STALL: Row = Row {
    answer: Some(b"d"),
    stall: true,
    access: Some(AccessCheck::Refusal),
    ..Row::PLAIN
};
/// AC13's guest-exit half: the guest's own exit ends the session, and its held
/// output arrives after the leave.
pub const EXIT: Row = Row {
    expect: 7,
    exit: true,
    ..Row::PLAIN
};
/// AC13's forced half: the guest ignores INT/TERM, so the second SIGINT forces
/// the launcher and its host restore appears exactly once.
pub const FORCED: Row = Row {
    expect: 130,
    forced: true,
    ..Row::PLAIN
};
/// AC13's forced half on the alternate screen.
pub const FORCED_ALT: Row = Row {
    expect: 130,
    forced: true,
    alt: true,
    ..Row::PLAIN
};
/// AC13's runtime-loss half: the owned runtime is killed while the question is up.
pub const RUNTIME_LOSS: Row = Row {
    expect: 125,
    runtime_loss: true,
    ..Row::PLAIN
};
/// AC13's runtime-loss half on the alternate screen.
pub const RUNTIME_LOSS_ALT: Row = Row {
    expect: 125,
    runtime_loss: true,
    alt: true,
    ..Row::PLAIN
};
/// AC9 with the setting off.
pub const OFF_ENV: Row = Row {
    off: true,
    ..Row::PLAIN
};
/// AC9 with `TERM=dumb`.
pub const OFF_DUMB: Row = Row {
    off: true,
    ..Row::PLAIN
};
/// AC9 with a redirected stdout: `-t` does not make a prompt eligible.
pub const OFF_REDIRECT: Row = Row {
    off: true,
    ..Row::PLAIN
};

// --- Cursor-position replies ------------------------------------------------

/// How many cursor-position requests have been answered, and when the last was.
///
/// The count outlives one pump: a caller that re-pumps would otherwise answer the
/// same request on every pass, and the quiet-window wait would never end. `limit`
/// is the launcher's own shape — one request per takeover — so exactly one reply
/// is ever written.
pub struct PromptDriver {
    answered: usize,
    last_reply: Instant,
    limit: usize,
}

impl PromptDriver {
    fn new(limit: usize) -> Self {
        Self {
            answered: 0,
            last_reply: Instant::now(),
            limit,
        }
    }
}

/// Whether the prompt's *current* status is "ready for your answer".
///
/// The accumulated text keeps every redraw, so a plain `contains(READY)` stays
/// true after a later redraw put "stop typing" back; a key written then is typing
/// inside the guard's quiet window, not an answer.
fn ready_is_latest(text: &str) -> bool {
    text.rfind(READY) > text.rfind(STOP_TYPING)
}

/// The terminal's answer to the prompt's cursor-position request: the same row
/// the prompt last moved to, in the reply's own spelling.
fn cpr_reply(text: &str) -> Result<Vec<u8>, String> {
    let mut moves: Vec<&str> = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find("\x1b[") {
        let tail = &rest[at + 2..];
        let digits = tail.bytes().take_while(u8::is_ascii_digit).count();
        if digits > 0 && tail[digits..].starts_with(";3H") {
            moves.push(&tail[..digits]);
        }
        rest = tail;
    }
    let row = moves
        .last()
        .ok_or_else(|| "the prompt asked for a position it never moved to".to_owned())?;
    Ok(format!("\x1b[{row};3R").into_bytes())
}

impl Session {
    /// Read until `ready` holds on the launcher's own output, answering the
    /// prompt's position requests once each, bounded.
    fn pump_prompt(
        &mut self,
        driver: &mut PromptDriver,
        mut ready: impl FnMut(&str) -> bool,
        what: &str,
    ) -> Result<String, String> {
        let bound = marker_deadline();
        let limit = Instant::now() + bound;
        while Instant::now() < limit {
            self.poll_once(Duration::from_millis(10))?;
            let text = self.launcher_output();
            let requests = text.matches("\x1b[6n").count();
            // One terminal, one request, one reply: `limit` is 1 for every row.
            while driver.answered < requests && driver.answered < driver.limit {
                if self.exited()?.is_some() {
                    break;
                }
                let reply = cpr_reply(&text)?;
                self.write_terminal(&reply)?;
                driver.answered += 1;
                driver.last_reply = Instant::now();
            }
            if ready(&text) {
                return Ok(text);
            }
        }
        Err(format!(
            "{what}: not observed within {}s",
            bound.as_secs_f64().round() as u64
        ))
    }

    /// Pump until the prompt is *stably* ready, then let the caller write its key.
    fn answer_when_ready(
        &mut self,
        driver: &mut PromptDriver,
        label: &str,
    ) -> Result<String, String> {
        self.pump_prompt(
            driver,
            ready_is_latest,
            &format!("{label}: the ready status"),
        )
    }
}

// --- Positional oracles -----------------------------------------------------

/// Every `PREFIX <n>` number in these bytes, in order.
fn numbered(text: &str, prefix: &str) -> Vec<u32> {
    let mut numbers = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find(prefix) {
        let tail = &rest[at + prefix.len()..];
        let digits = tail.bytes().take_while(u8::is_ascii_digit).count();
        if digits > 0
            && let Ok(number) = tail[..digits].parse()
        {
            numbers.push(number);
        }
        rest = tail;
    }
    numbers
}

/// The numbers of every `SIZE r c` report after `start`.
fn sizes_after(text: &str, start: usize) -> Vec<(u32, u32)> {
    let mut sizes = Vec::new();
    let mut rest = text.get(start..).unwrap_or_default();
    while let Some(at) = rest.find("SIZE ") {
        let tail = &rest[at + 5..];
        let mut fields = tail.split_whitespace();
        let rows = fields.next().and_then(|word| word.parse::<u32>().ok());
        let cols = fields.next().and_then(|word| word.parse::<u32>().ok());
        if let (Some(rows), Some(cols)) = (rows, cols) {
            sizes.push((rows, cols));
        }
        rest = tail;
    }
    sizes
}

/// The first `PREFIX <n>` value after `start`.
fn prefix_number(text: &str, prefix: &str) -> Option<u32> {
    let at = text.find(prefix)?;
    let tail = &text[at + prefix.len()..];
    let digits = tail.bytes().take_while(u8::is_ascii_digit).count();
    tail[..digits].parse().ok()
}

/// The guest's modes come back after the leave, in §5.6's order.
fn require_modes_reapplied(window: &str, label: &str) -> Result<(), String> {
    const SEQUENCES: [(&str, &str); 3] = [
        ("\u{1b}(0", "the line-drawing designation"),
        ("\u{1b}[?1002h", "button-event mouse"),
        ("\u{1b}[?2004h", "bracketed paste"),
    ];
    for (sequence, position) in SEQUENCES {
        require(window.contains(sequence), || {
            format!("{label}: the leave did not re-apply {position}: {window:?}")
        })?;
    }
    let positions: Vec<usize> = SEQUENCES
        .iter()
        .map(|(sequence, _)| window.find(sequence).unwrap_or(usize::MAX))
        .collect();
    require(
        positions[0] < positions[1] && positions[1] < positions[2],
        || format!("{label}: the modes were re-applied out of order: {window:?}"),
    )
}

/// Whether these drained bytes are nothing but cursor-position replies.
///
/// The launcher's own reply is written to the terminal after the enter frame and
/// can be read back once the takeover ends — a stated restore limit. The drain is
/// therefore required to be nothing but replies, which excludes every answer byte
/// and a lone Esc/CR/LF too.
fn only_cpr_replies(raw: &[u8]) -> bool {
    let mut rest = raw;
    while !rest.is_empty() {
        let Some(tail) = rest.strip_prefix(b"\x1b[") else {
            return false;
        };
        let mut index = 0;
        let mut groups = 0;
        while groups < 2 {
            let start = index;
            while tail.get(index).is_some_and(u8::is_ascii_digit) {
                index += 1;
            }
            if index == start {
                return false;
            }
            groups += 1;
            if groups == 1 {
                if tail.get(index) != Some(&b';') {
                    return false;
                }
                index += 1;
            }
        }
        if tail.get(index) != Some(&b'R') {
            return false;
        }
        rest = &tail[index + 1..];
    }
    true
}

// --- The launcher's own CLI -------------------------------------------------

struct Ran {
    status: i32,
    stdout: String,
    stderr: String,
}

/// `agent-vm access …` under the case's own state root and project.
///
/// The prompt's grants are the same command's business, so the row asks the
/// launcher's own CLI rather than reading the allowance format here. Both
/// channels go to files: a bounded wait cannot drain a pipe, and a full pipe
/// would turn a hung CLI into a hung row.
struct AccessCli<'a> {
    invocation: &'a Invocation,
    work: PathBuf,
    calls: usize,
}

impl<'a> AccessCli<'a> {
    fn new(invocation: &'a Invocation, work: &Path) -> Self {
        Self {
            invocation,
            work: work.to_path_buf(),
            calls: 0,
        }
    }

    fn run(&mut self, arguments: &[&str]) -> Result<Ran, String> {
        self.calls += 1;
        let stdout_path = self.work.join(format!("access-{}-stdout.txt", self.calls));
        let stderr_path = self.work.join(format!("access-{}-stderr.txt", self.calls));
        let stdout = fs::File::create(&stdout_path)
            .map_err(|error| format!("{}: {error}", stdout_path.display()))?;
        let stderr = fs::File::create(&stderr_path)
            .map_err(|error| format!("{}: {error}", stderr_path.display()))?;
        let mut command = Command::new(&self.invocation.bin);
        command
            .arg("access")
            .args(arguments)
            .current_dir(&self.invocation.project)
            .env_clear()
            .envs(self.invocation.child_env())
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        let child = command.spawn().map_err(|error| {
            format!(
                "cannot run {} access: {error}",
                self.invocation.bin.display()
            )
        })?;
        let mut child = pty::OwnedChild::new(child);
        let status = child.finish(ACCESS_TIMEOUT).map_err(|error| {
            format!(
                "`{} access {}` did not finish within {}s: {error}",
                self.invocation.bin.display(),
                arguments.join(" "),
                ACCESS_TIMEOUT.as_secs()
            )
        })?;
        let status = status
            .code()
            .unwrap_or_else(|| 128 + status.signal().unwrap_or(0));
        let read = |path: &PathBuf| {
            fs::read(path)
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                .unwrap_or_default()
        };
        Ok(Ran {
            status,
            stdout: read(&stdout_path),
            stderr: read(&stderr_path),
        })
    }

    /// stdout and stderr together, as the Python's `access_output` did.
    fn output(&mut self, arguments: &[&str]) -> Result<String, String> {
        let ran = self.run(arguments)?;
        Ok(format!("{}{}", ran.stdout, ran.stderr))
    }
}

/// Rows of `access allowances` whose DESTINATION cell names `destination`.
///
/// The table's columns are SCOPE, DESTINATION, RECORDED, SESSION, STATUS; the
/// first cell is the scope, which is what tells a record from a live allowance.
fn allowance_rows(table: &str, destination: &str) -> Vec<AllowanceRow> {
    let mut rows = Vec::new();
    for line in table.lines() {
        if !line.contains(destination) || line.trim_start().starts_with("SCOPE") {
            continue;
        }
        let mut fields = line.split_whitespace();
        let Some(scope) = fields.next() else {
            continue;
        };
        if scope != "session" && scope != "project" {
            continue;
        }
        rows.push(AllowanceRow {
            scope: scope.to_owned(),
            status: fields.collect::<Vec<_>>().join(" "),
        });
    }
    rows
}

/// One `access allowances` row: its scope cell and everything after it.
struct AllowanceRow {
    scope: String,
    status: String,
}

/// The destination a row's refusal names, spelled as `access` spells it.
fn destination(probe: &[&str]) -> String {
    match probe.first() {
        Some(&"refuse-dns") => "blocked.example".to_owned(),
        _ => probe
            .get(1)
            .map(|word| (*word).to_owned())
            .unwrap_or_else(|| "203.0.113.10".to_owned()),
    }
}

/// The DESTINATION cell of the row naming `needle`.
///
/// `access revoke` takes the destination *as agent-vm records it*
/// (`tcp://[1.1.1.1/32]:443`), so the cell is read back rather than rebuilt.
fn allowance_destination(table: &str, needle: &str) -> Option<String> {
    for line in table.lines() {
        let mut fields = line.split_whitespace();
        let Some(scope) = fields.next() else {
            continue;
        };
        if scope != "session" && scope != "project" {
            continue;
        }
        if let Some(cell) = fields.next()
            && cell.contains(needle)
        {
            return Some(cell.to_owned());
        }
    }
    None
}

/// The 8-hex id of the *live* session's refusal row naming `destination`.
///
/// The project's refusal log outlives a launch, so matching the destination alone
/// can return an ended session's row, and `access allow` on that row fails. The
/// table's SESSION cell is a label, never an id, so the live row is the one whose
/// label is not an ended one.
fn refusal_id(table: &str, destination: &str) -> Option<String> {
    for line in table.lines() {
        if !line.contains(destination) || line.contains("ended") {
            continue;
        }
        let trimmed = line.trim_start();
        let head: String = trimmed.chars().take(8).collect();
        if head.len() == 8 && head.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(head);
        }
    }
    None
}

/// The confirmed revision numbers `access allowances` reports.
fn revisions(table: &str) -> Vec<u32> {
    let mut found = Vec::new();
    let mut rest = table.to_lowercase();
    while let Some(at) = rest.find("rev") {
        let mut tail = &rest[at + 3..];
        if let Some(after) = tail.strip_prefix("ision") {
            tail = after;
        }
        let tail = tail.trim_start();
        let digits = tail.bytes().take_while(u8::is_ascii_digit).count();
        if digits > 0
            && let Ok(number) = tail[..digits].parse()
        {
            found.push(number);
        }
        rest = tail.to_owned();
    }
    found
}

// --- One row ----------------------------------------------------------------

/// Drive one prompt row to its verdict and return the launcher's status.
pub fn observe(
    invocation: &Invocation,
    session: &mut Session,
    receipt: &mut Map<String, Value>,
    row: &'static Row,
) -> Result<i32, String> {
    let mut facts = Map::new();
    facts.insert("probe".to_owned(), json!(invocation.case.probe));
    facts.insert(
        "answer".to_owned(),
        match row.answer {
            Some(answer) => json!(String::from_utf8_lossy(answer).into_owned()),
            None => Value::Null,
        },
    );
    let work = session.work.clone();
    let mut cli = AccessCli::new(invocation, &work);
    let verdict = drive(invocation, session, row, &mut facts, &mut cli);
    receipt.insert("prompt".to_owned(), Value::Object(facts));
    verdict
}

fn drive(
    invocation: &Invocation,
    session: &mut Session,
    row: &'static Row,
    facts: &mut Map<String, Value>,
    cli: &mut AccessCli<'_>,
) -> Result<i32, String> {
    let label = invocation.label();
    let marker = marker_deadline();
    // AC1's latency bound is *recorded* here and fails the row at the end, after
    // every other check has run: a gate at this point would hide the other
    // criteria's evidence, and the case still fails, just with its whole receipt.
    let mut deferred: Vec<String> = Vec::new();
    // One driver for the whole row: no call site can write a reply the launcher
    // did not ask for.
    let mut driver = PromptDriver::new(1);
    session.pump(
        |out| out.contains("REFUSE-READY"),
        "the prompt probe's readiness",
        marker,
        View::Merged,
    )?;

    if row.off {
        // AC9: no prompt bytes anywhere, and the hint exactly once. The probe
        // holds the session open until released, so the observation is on a live
        // session, and the hold marker is read from every channel because the
        // guest's stdout may be a file.
        session.pump(
            |out| out.contains("HOLD-READY"),
            &format!("{label}: the guest's hold"),
            marker,
            View::Merged,
        )?;
        session.write_terminal(HOLD_RELEASE)?;
        session.pump(
            |out| out.contains("REFUSE-DONE"),
            "the guest's completion",
            marker,
            View::Merged,
        )?;
        let status = session.wait(Duration::from_secs(120))?;
        let terminal = session.launcher_output();
        require(!terminal.contains(TITLE), || {
            format!(
                "{label}: a prompt was drawn with it off: {:?}",
                tail(&terminal)
            )
        })?;
        let guest = session.guest_stdout_text();
        require(!guest.contains(TITLE), || {
            format!(
                "{label}: a prompt was drawn into the guest's stdout: {:?}",
                tail(&guest)
            )
        })?;
        const HINT: &str = "The sandbox refused a guest network request";
        require(terminal.matches(HINT).count() == 1, || {
            format!(
                "{label}: the hint must appear exactly once on stderr, saw {}: {:?}",
                terminal.matches(HINT).count(),
                tail(&terminal)
            )
        })?;
        require(status == row.expect, || {
            format!(
                "{label}: status {status}, expected {}; {:?}",
                row.expect,
                tail(&terminal)
            )
        })?;
        return Ok(status);
    }

    // From the guest's readiness; both halves are recorded so the launcher's own
    // share is separable from the guest's spawn and the runtime's log ingestion.
    let started = Instant::now();
    let mut connect_at: Option<Instant> = None;
    let text = session.pump_prompt(
        &mut driver,
        |text| {
            if connect_at.is_none() && text.contains("CONNECT rc=") {
                // Recorded inside the predicate: the guest's own report is the
                // interval AC1 owns, not the readiness marker before it.
                connect_at = Some(Instant::now());
            }
            text.contains(TITLE)
        },
        &format!("{label}: the prompt"),
    )?;
    let appeared_at = Instant::now();
    let appeared = elapsed(started, appeared_at);
    facts.insert("appeared_seconds".to_owned(), json!(appeared));
    if let Some(connect_at) = connect_at {
        facts.insert(
            "refused_seconds".to_owned(),
            json!(elapsed(started, connect_at)),
        );
        facts.insert(
            "after_refusal_seconds".to_owned(),
            json!(elapsed(connect_at, appeared_at)),
        );
    }
    // AC1's bound applies to every prompt row, not only the stalled one. The
    // measured interval is the refusal's own; the stall row's prompt precedes its
    // guest's report, so there the bound stays on the total.
    let bound = if row.stall {
        STALL_WITHIN
    } else {
        APPEARS_WITHIN
    };
    let measured = match facts.get("after_refusal_seconds").and_then(Value::as_f64) {
        Some(measured) => measured,
        None => {
            facts.insert("prompt_before_refusal_report".to_owned(), json!(true));
            appeared
        }
    };
    facts.insert("latency_within_bound".to_owned(), json!(measured <= bound));
    if measured > bound {
        deferred.push(format!(
            "AC1 latency: {measured}s after the guest's refusal ({appeared}s after its \
             readiness), not within {bound}s"
        ));
    }
    if let Some(at) = text.find("session ") {
        let tail = &text[at + "session ".len()..];
        let id: String = tail.chars().take(8).collect();
        if id.len() == 8 && id.chars().all(|c| c.is_ascii_hexdigit()) {
            facts.insert("session".to_owned(), json!(id));
        }
    }
    if row.stall {
        // A stalled sequence must be cancelled before the enter frame.
        let can_at = text.find('\u{18}');
        let enter_at = text.find(ENTER);
        require(
            can_at.is_some() && enter_at.is_some() && can_at < enter_at,
            || {
                format!(
                    "{label}: a stalled sequence must be cancelled with CAN before the enter \
                 frame (can={can_at:?}, enter={enter_at:?}): {:?}",
                    tail(&text)
                )
            },
        )?;
    }
    if row.offer_project_only {
        let text = session.answer_when_ready(&mut driver, &label)?;
        require(text.contains("from the next launch"), || {
            format!("{label}: the #491 offer is missing: {:?}", tail(&text))
        })?;
        require(!text.contains("  s  allow"), || {
            format!(
                "{label}: `s` was offered for a destination only a record can admit: {:?}",
                tail(&text)
            )
        })?;
    }
    if row.guard {
        // A key before the guard is typing; a two-byte read is typing; then a
        // deliberate `d`. Nothing may reach the guest and nothing may be granted.
        session.write_terminal(b"s")?;
        session.pump_prompt(
            &mut driver,
            ready_is_latest,
            &format!("{label}: the ready status"),
        )?;
        session.write_terminal(b"ss")?;
        session.answer_when_ready(&mut driver, &label)?;
        session.write_terminal(b"d")?;
    } else if row.answered_elsewhere {
        session.answer_when_ready(&mut driver, &label)?;
        if !invocation.standin {
            let destination = destination(invocation.case.probe);
            let table = cli.output(&[])?;
            let identifier = refusal_id(&table, &destination).ok_or_else(|| {
                format!("{label}: no refusal row names the destination, so the CLI cannot answer")
            })?;
            facts.insert("answered_elsewhere_id".to_owned(), json!(identifier));
            match row.race_key {
                None => {
                    let ran = cli.run(&["allow", &identifier])?;
                    facts.insert("answered_elsewhere_status".to_owned(), json!(ran.status));
                    require(ran.status == 0, || {
                        format!(
                            "{label}: `access allow {identifier}` failed ({}): {}{}",
                            ran.status, ran.stdout, ran.stderr
                        )
                    })?;
                }
                Some(key) => {
                    // AC12's race: the key is typed *while the CLI's grant is still
                    // running*, so the prompt's conditional grant has to find the
                    // destination answered under the handler's lock.
                    let stdout_path = session.work.join("race-stdout.txt");
                    let stderr_path = session.work.join("race-stderr.txt");
                    let stdout = fs::File::create(&stdout_path)
                        .map_err(|error| format!("{}: {error}", stdout_path.display()))?;
                    let stderr = fs::File::create(&stderr_path)
                        .map_err(|error| format!("{}: {error}", stderr_path.display()))?;
                    let mut command = Command::new(&invocation.bin);
                    command
                        .arg("access")
                        .arg("allow")
                        .arg(&identifier)
                        .current_dir(&invocation.project)
                        .env_clear()
                        .envs(invocation.child_env())
                        .stdin(Stdio::null())
                        .stdout(Stdio::from(stdout))
                        .stderr(Stdio::from(stderr));
                    let child = command
                        .spawn()
                        .map_err(|error| format!("cannot run the racing access: {error}"))?;
                    let mut racing = pty::OwnedChild::new(child);
                    session.write_terminal(key)?;
                    facts.insert(
                        "race_key".to_owned(),
                        json!(String::from_utf8_lossy(key).into_owned()),
                    );
                    let status = racing
                        .finish(ACCESS_TIMEOUT)
                        .map_err(|error| format!("the racing access did not finish: {error}"))?;
                    let status = status
                        .code()
                        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0));
                    facts.insert("race_status".to_owned(), json!(status));
                    require(status == 0, || {
                        let read = |path: &PathBuf| {
                            fs::read(path)
                                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                                .unwrap_or_default()
                        };
                        format!(
                            "{label}: the racing `access allow {identifier}` failed \
                             ({status}): {}{}",
                            read(&stdout_path),
                            read(&stderr_path)
                        )
                    })?;
                }
            }
        }
    } else if row.forced {
        session.answer_when_ready(&mut driver, &label)?;
        let pid = session
            .launcher_pid
            .ok_or_else(|| format!("{label}: no launcher to signal"))?;
        pty::send_signal(pid, rustix::process::Signal::INT)
            .map_err(|error| format!("cannot send the first SIGINT: {error}"))?;
        // The contract's own pause before the second: the first is forwarded, and
        // the launcher forces only on the second.
        std::thread::sleep(Duration::from_millis(300));
        pty::send_signal(pid, rustix::process::Signal::INT)
            .map_err(|error| format!("cannot send the second SIGINT: {error}"))?;
    } else if row.runtime_loss {
        session.answer_when_ready(&mut driver, &label)?;
        let identity =
            owned_runtime_identity(&invocation.state_root, session.launcher_pid, &label)?;
        facts.insert(
            "runtime_pid".to_owned(),
            identity.get("pid").cloned().unwrap_or(Value::Null),
        );
        crate::egress_fixtures::signal_identity(&identity, libc::SIGKILL)?;
    } else if let Some(answer) = row.answer {
        session.answer_when_ready(&mut driver, &label)?;
        session.write_terminal(answer)?;
    }
    // else: the guest ends the session by itself while the question is up.

    // The `access` check runs **while the session is live**: a session allowance
    // exists only in a running session.
    if let Some(access) = row.access {
        session.pump_prompt(
            &mut driver,
            |out| out.contains(LEAVE),
            &format!("{label}: the leave"),
        )?;
        if access.live() {
            session.pump_prompt(
                &mut driver,
                |out| out.contains("HOLD-READY"),
                &format!("{label}: the live hold"),
            )?;
        }
        require_access(invocation, facts, cli, access, &label)?;
        if access.live() {
            session.write_terminal(HOLD_RELEASE)?;
        }
    } else if matches!(
        invocation.case.probe.first().copied(),
        Some("refuse" | "refuse-dns" | "alt")
    ) && !row.forced
        && !row.runtime_loss
    {
        // This row holds the probe open for a live check it does not run:
        // release it so the row does not wait for the probe's own 15 s timeout.
        session.pump_prompt(
            &mut driver,
            |out| out.contains("HOLD-READY"),
            &format!("{label}: the guest's hold"),
        )?;
        session.write_terminal(HOLD_RELEASE)?;
    }

    let status = session.wait(Duration::from_secs(120))?;
    let text = session.launcher_output();
    if let Some(sentence) = row.result_says {
        require(text.contains(sentence), || {
            format!(
                "{label}: the result sentence must say {sentence:?}: {:?}",
                tail(&text)
            )
        })?;
    }
    require(status == row.expect, || {
        format!(
            "{label}: launcher status {status}, expected {}; terminal tail {:?}",
            row.expect,
            tail(&text)
        )
    })?;

    if row.forced || row.runtime_loss {
        // The terminal stream ends at the host restore, and only one copy of it.
        require(text.matches(HOST_RESTORE).count() == 1, || {
            format!(
                "{label}: the host restore must appear exactly once, saw {}: {:?}",
                text.matches(HOST_RESTORE).count(),
                tail(&text)
            )
        })?;
        require(text.trim_end().ends_with(HOST_RESTORE), || {
            format!(
                "{label}: the terminal output must end with the host restore: {:?}",
                tail(&text)
            )
        })?;
    }
    if row.alt {
        require(text.contains("\u{1b}8"), || {
            format!(
                "{label}: an alternate-screen guest is restored with DECRC: {:?}",
                tail(&text)
            )
        })?;
        require(!text.contains(LEAVE), || {
            format!(
                "{label}: ?1049l would drop the guest to the main screen: {:?}",
                tail(&text)
            )
        })?;
        let leave_at = text.rfind("\u{1b}8").unwrap_or(0);
        let sizes = sizes_after(&text, 0);
        let final_report = {
            let at = text.find("SIZE-FINAL ");
            at.and_then(|at| {
                let mut fields = text[at + "SIZE-FINAL ".len()..].split_whitespace();
                let rows = fields.next().and_then(|word| word.parse::<u32>().ok())?;
                let cols = fields.next().and_then(|word| word.parse::<u32>().ok())?;
                Some((rows, cols))
            })
        };
        facts.insert("sizes".to_owned(), json!(sizes));
        facts.insert(
            "final_size_report".to_owned(),
            match final_report {
                Some((rows, cols)) => json!([rows, cols]),
                None => Value::Null,
            },
        );
        let after = sizes_after(&text, leave_at);
        require(!after.is_empty(), || {
            format!(
                "{label}: the guest never saw a size change after the leave, so it was not \
                 asked to redraw (sizes={sizes:?}, final={final_report:?}): {:?}",
                tail(&text)
            )
        })?;
        let final_size = after[after.len() - 1];
        let host = (
            u32::from(super::INITIAL_SIZE.rows),
            u32::from(super::INITIAL_SIZE.cols),
        );
        require(final_size == host, || {
            format!(
                "{label}: the guest's final size is {final_size:?}, not the host's {}x{}",
                super::INITIAL_SIZE.rows,
                super::INITIAL_SIZE.cols
            )
        })?;
    }
    if row.lines {
        require(text.contains(LEAVE), || {
            format!("{label}: no leave frame: {:?}", tail(&text))
        })?;
        let leave_at = text.rfind(LEAVE).unwrap_or(0);
        require(text[..leave_at].contains("\u{1b}[?6h"), || {
            format!(
                "{label}: origin mode must be re-set before the screen restore: {:?}",
                tail(&text)
            )
        })?;
        // AC6/R8: every line arrives exactly once and in order, and none is
        // written while the takeover holds the terminal. Which lines the takeover
        // actually *held* depends on how long the refusal took to reach the feed,
        // so the split point is recorded, not assumed to be zero.
        let written = numbered(&text, "LINE ");
        require(written == (0..LINE_COUNT).collect::<Vec<_>>(), || {
            format!(
                "{label}: the guest's lines must arrive once each and in order; saw {:?}",
                written
            )
        })?;
        let enter_at = text[..leave_at].rfind(ENTER).unwrap_or(0);
        let in_takeover = numbered(&text[enter_at..leave_at], "LINE ");
        require(in_takeover.is_empty(), || {
            format!(
                "{label}: guest output was written during the takeover, not held: {:?}",
                &in_takeover[..in_takeover.len().min(8)]
            )
        })?;
        let numbers = numbered(&text[leave_at..], "LINE ");
        require(!numbers.is_empty(), || {
            format!(
                "{label}: no held line was released after the leave: {:?}",
                tail(&text)
            )
        })?;
        let marker = format!("LINE {}", numbers[0]);
        let first_line_at = text[leave_at..]
            .find(&marker)
            .map(|at| leave_at + at)
            .ok_or_else(|| format!("{label}: no {marker:?} after the leave"))?;
        require_modes_reapplied(&text[leave_at..first_line_at], &label)?;
        // No prompt byte may follow the leave: a redraw written after it would be
        // drawn over the guest.
        let after_leave = &text[leave_at..];
        require(
            !after_leave.contains(READY) && !after_leave.contains(TITLE),
            || {
                format!(
                    "{label}: a prompt frame was written after the leave: {:?}",
                    tail(after_leave)
                )
            },
        )?;
        facts.insert("held_lines".to_owned(), json!(numbers.len()));
    }
    // The probe's own report of its refused connect. A takeover starts within
    // milliseconds of the refusal, so the report is usually written while the
    // takeover holds the guest's output: the rows that end with a leave flush it,
    // and the forced-end and runtime-loss rows, which never flush a hold, lose it.
    let connect = prefix_number(&text, "CONNECT rc=");
    if row.forced || row.runtime_loss {
        facts.insert(
            "connect_report".to_owned(),
            match connect {
                Some(rc) => json!(rc.to_string()),
                None => Value::Null,
            },
        );
    } else {
        let rc = connect.ok_or_else(|| {
            format!(
                "{label}: the probe never reported its connection result: {:?}",
                tail(&text)
            )
        })?;
        require(rc != 0, || {
            format!(
                "{label}: the refused connection succeeded (rc=0), so this row is not a refusal"
            )
        })?;
    }
    if row.exit {
        require(text.contains("EXIT-DURING-DONE"), || {
            format!(
                "{label}: the guest's own completion is missing: {:?}",
                tail(&text)
            )
        })?;
        let leave_at = text.rfind(LEAVE);
        let done_at = text.rfind("EXIT-DURING-DONE");
        require(
            leave_at.is_some() && done_at.is_some() && leave_at < done_at,
            || {
                format!(
                    "{label}: the prompt's leave must precede the guest's held output: {:?}",
                    tail(&text)
                )
            },
        )?;
        // AC14: 300 numbered KiB blocks, each once and in order, all after the leave.
        let blocks = numbered(&text, "BLOCK ");
        require(blocks == (0..BLOCK_COUNT).collect::<Vec<_>>(), || {
            format!(
                "{label}: the held payload must be complete and in order after the leave; \
                 saw {} blocks {:?}",
                blocks.len(),
                &blocks[..blocks.len().min(4)]
            )
        })?;
        facts.insert("held_blocks".to_owned(), json!(blocks.len()));
    }
    if row.retry_succeeds {
        // AC2: after the answer, the same connect succeeds without a restart.
        let retry = prefix_number(&text, "RETRY rc=").ok_or_else(|| {
            format!(
                "{label}: the probe never reported its retry: {:?}",
                tail(&text)
            )
        })?;
        require(retry == 0, || {
            format!("{label}: the guest's retry after the allowance failed (rc={retry})")
        })?;
        facts.insert("retry".to_owned(), json!("succeeded"));
    }
    if row.probe_stdin {
        // AC4's claim is that no *prompt input* reaches the guest. The launcher's
        // own cursor-position reply is not a key: it is written to the terminal
        // after the enter frame and may be read back after the takeover ends, so
        // the drain is required to be nothing but replies.
        let at = text.find("STDIN ").ok_or_else(|| {
            format!(
                "{label}: the probe never reported its stdin: {:?}",
                tail(&text)
            )
        })?;
        let hex: String = text[at + "STDIN ".len()..]
            .chars()
            .take_while(|c| c.is_ascii_hexdigit())
            .collect();
        let raw = unhex(&hex);
        require(only_cpr_replies(&raw), || {
            format!("{label}: prompt input reached the guest: {hex:?}")
        })?;
        facts.insert("guest_stdin".to_owned(), json!(hex));
    }
    if !deferred.is_empty() {
        // Everything above has been checked and recorded; the row's verdict is
        // still a failure, and `deferred` is what makes it one.
        return Err(format!("{label}: {}", deferred.join("; ")));
    }
    Ok(status)
}

fn elapsed(from: Instant, to: Instant) -> f64 {
    let seconds = to.saturating_duration_since(from).as_secs_f64();
    (seconds * 1000.0).round() / 1000.0
}

fn unhex(hex: &str) -> Vec<u8> {
    let digits: Vec<u32> = hex.chars().filter_map(|c| c.to_digit(16)).collect();
    digits
        .chunks(2)
        .filter_map(|pair| match pair {
            [high, low] => Some((high * 16 + low) as u8),
            _ => None,
        })
        .collect()
}

fn tail(text: &str) -> String {
    let mut kept: String = text.chars().rev().take(1200).collect();
    kept = kept.chars().rev().collect();
    kept
}

// --- The access check -------------------------------------------------------

fn require_access(
    invocation: &Invocation,
    facts: &mut Map<String, Value>,
    cli: &mut AccessCli<'_>,
    access: AccessCheck,
    label: &str,
) -> Result<(), String> {
    if invocation.standin {
        // A boot-free control drives a stand-in, which has no session, no refusal
        // log and no allowance store. The control's claim is about the driver's
        // byte oracle, so the CLI check is recorded as skipped, not faked.
        facts.insert(
            "access".to_owned(),
            json!("skipped: boot-free control (a stand-in is not the launcher)"),
        );
        return Ok(());
    }
    let destination = destination(invocation.case.probe);
    let checked = check_access(cli, facts, access, &destination, label);
    // The project is shared by both forms of a row and by its later cases, and a
    // project record outlives the launch: one left behind suppresses the next
    // launch's refusal entirely. The check above is the evidence; this only leaves
    // the project as it was found, and its own status is recorded rather than
    // judged.
    if let Ok(table) = cli.output(&["allowances"])
        && let Some(canonical) = allowance_destination(&table, &destination)
    {
        let ran = cli.run(&["revoke", "--project", &canonical])?;
        facts.insert(
            "revoked_after_check".to_owned(),
            json!({"destination": canonical, "status": ran.status}),
        );
    }
    checked
}

fn check_access(
    cli: &mut AccessCli<'_>,
    facts: &mut Map<String, Value>,
    access: AccessCheck,
    destination: &str,
    label: &str,
) -> Result<(), String> {
    match access {
        AccessCheck::Refusal => {
            let table = cli.output(&[])?;
            require(table.contains(destination), || {
                format!("{label}: `access` does not list the refusal: {table:?}")
            })?;
            facts.insert("access".to_owned(), json!("listed"));
        }
        AccessCheck::SessionApplied => {
            let table = cli.output(&["allowances"])?;
            require(table.contains(destination), || {
                format!("{label}: `access allowances` never names the destination: {table:?}")
            })?;
            require(table.to_lowercase().contains("applied"), || {
                format!("{label}: the session allowance is not applied: {table:?}")
            })?;
            // A revision >= 2 is the confirmed one; revision 1 is the optimistic
            // row written before the session acknowledged it.
            require(revisions(&table).iter().any(|rev| *rev >= 2), || {
                format!("{label}: no confirmed revision >= 2 in `access allowances`: {table:?}")
            })?;
            facts.insert("access".to_owned(), json!("session-applied"));
        }
        AccessCheck::ProjectApplied | AccessCheck::ProjectRecordOnly => {
            let table = cli.output(&["allowances"])?;
            let rows = allowance_rows(&table, destination);
            require(!rows.is_empty(), || {
                format!("{label}: `access allowances` never names the record: {table:?}")
            })?;
            require(rows.iter().any(|row| row.scope == "project"), || {
                format!("{label}: no project record names {destination}: {table:?}")
            })?;
            if access == AccessCheck::ProjectRecordOnly {
                // An *applied* project allowance also has PROJECT scope, so scope
                // alone cannot tell the two apart. The status can: an applied entry
                // reads `applied (rev N)`, a record this session did not adopt reads
                // `not confirmed for this session`.
                require(rows.iter().all(|row| row.scope != "session"), || {
                    format!(
                        "{label}: a session allowance was applied although only a record was \
                         offered: {table:?}"
                    )
                })?;
                require(
                    rows.iter().all(|row| !row.status.contains("applied (rev")),
                    || {
                        format!(
                            "{label}: the project allowance was applied to this session, \
                             although the offer promised only a record for the next launch: \
                             {table:?}"
                        )
                    },
                )?;
                facts.insert("access".to_owned(), json!(access.name()));
            } else {
                require(
                    rows.iter().any(|row| row.scope == "session")
                        || rows
                            .iter()
                            .any(|row| row.status.to_lowercase().contains("applied")),
                    || {
                        format!(
                            "{label}: the project allowance was not applied to this session: \
                             {table:?}"
                        )
                    },
                )?;
                facts.insert("access".to_owned(), json!("project-applied"));
            }
        }
        AccessCheck::FirstAnswerWins => {
            // R19/R21: the prompt's grant is conditional under the handler's lock, so
            // a destination the CLI already answered is reported as answered
            // elsewhere and never promoted. The prompt's `p` is typed while the CLI
            // runs, so *either* surface may win — the row records which and asserts
            // the invariant.
            let table = cli.output(&["allowances"])?;
            let rows = allowance_rows(&table, destination);
            require(!rows.is_empty(), || {
                format!("{label}: `access allowances` never names the allowance: {table:?}")
            })?;
            let session_won = rows.iter().any(|row| row.scope == "session");
            let project_won = rows.iter().any(|row| row.scope == "project");
            require(session_won || project_won, || {
                format!("{label}: neither surface's allowance is listed: {table:?}")
            })?;
            if session_won {
                require(!project_won, || {
                    format!(
                        "{label}: the CLI answered first, so a prompt `p` must not have written \
                         a project record: {table:?}"
                    )
                })?;
            }
            facts.insert("access".to_owned(), json!("first-answer-wins"));
            facts.insert(
                "race_winner".to_owned(),
                json!(if project_won { "prompt" } else { "cli" }),
            );
        }
        AccessCheck::NoAllowance => {
            let table = cli.output(&["allowances"])?;
            require(!table.contains(destination), || {
                format!(
                    "{label}: an allowance was granted for a question that was never answered: \
                     {table:?}"
                )
            })?;
            facts.insert("access".to_owned(), json!("no-allowance"));
        }
    }
    Ok(())
}
