//! #401 host SIGINT/SIGTERM supervision: eighteen rows and their shared oracle
//! (#699).
//!
//! Ported from `signal_case_specs`, `observe_signal`, `guest_end_problems`,
//! `unhandled_hint`, `owned_while_running` and `observe_absence` in
//! `script/test/lib/direct-terminal.py`.
//!
//! A signal row is the only group where the driver signals the launcher instead
//! of typing at it, so its evidence is different in kind:
//!
//! * **The guest's own report is what proves a signal arrived.** A row requires
//!   `SIGNAL-READY` and then the marker naming *that* signal (`SIGNAL-TRAPPED
//!   INT`), and the markers the behaviour under test would contradict
//!   (`SIGNAL-SURVIVED`, `SIGNAL-IGNORED`) must be absent. Identity matters: a row
//!   that only saw "some signal" could not tell a forwarded `SIGINT` from a
//!   forwarded `SIGTERM`.
//! * **A status alone cannot tell a guest end from a forced teardown.** 130 and
//!   143 are exactly what the launcher itself reports when its grace expires, so
//!   the launcher's own account of the end (`Stopping sandbox` versus
//!   `Interrupted by signal N`) is judged with the status. That oracle is
//!   [`guest_end_problems`], and it is *one* function: this driver and the
//!   boot-free controls both call it, so a control cannot certify a copy.
//! * **Ownership is observed while the launch is healthy, and again before any
//!   rescue.** A runtime that is "gone" after [`super::teardown_receipt`] has run
//!   would only prove the rescue worked, so [`observe_absence`] runs first.
//! * **The self-signalled row sends no host signal at all.** Its status can only
//!   come from the guest's own reported identity, so the guest is released
//!   through a per-attempt file whose token this driver writes only after
//!   readiness *and* the live-ownership baseline were both observed ([`Release`]).
//!
//! These rows are **native-only** ([`super::Group::control_proven`] is false for
//! the group): a stand-in has no runtime, no catalog and no host process naming a
//! sandbox, so `owned_while_running` cannot be faked without deleting the very
//! observation the rows exist to make. What the boot-free controls do prove is
//! that the shared oracle bites.

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use serde_json::{Map, Value, json};

use super::{
    Case, Channel, Group, Invocation, Session, View, marker_deadline, owned_catalog_rows,
    owned_runtime_identity, require, tail,
};
use crate::pty;

// --- The shipped numbers ----------------------------------------------------

/// The grace a launch gives its guest between a forwarded signal and the
/// launcher's own forced teardown.
///
/// Fixed by the contract: no option and no environment override, so a row
/// asserts the real five seconds. A shorter injected grace would only prove the
/// rule, not the number that ships. Recorded in every row's receipt and pinned by
/// [`shipped_numbers`].
pub const GRACE_SECONDS: f64 = 5.0;

/// How long a signal row may wait for the launcher after its last signal. The
/// grace is five seconds and the forced teardown is bounded, so anything near
/// this bound is a hang, not a slow machine.
pub const WAIT_SECONDS: f64 = 120.0;

/// The launcher's own account of an end it decided, and of one it did not.
pub const ORDINARY_TEARDOWN: &str = "ordinary teardown";
pub const FORCED_TEARDOWN: &str = "forced teardown";

// --- The signals ------------------------------------------------------------

/// The two signals #401 supervises, by the name the guest and the receipt use.
pub const INT: i32 = libc::SIGINT;
pub const TERM: i32 = libc::SIGTERM;

pub fn name_of(number: i32) -> &'static str {
    match number {
        INT => "INT",
        TERM => "TERM",
        _ => "UNKNOWN",
    }
}

/// The guest's own report that a signal arrived and was deliberately not acted
/// on, by signal: `SIGNAL-IGNORED INT` is not `SIGNAL-IGNORED TERM`.
pub fn ignored_marker(number: i32) -> &'static str {
    match number {
        INT => "SIGNAL-IGNORED INT",
        TERM => "SIGNAL-IGNORED TERM",
        _ => "SIGNAL-IGNORED",
    }
}

fn signal_of(number: i32) -> Result<rustix::process::Signal, String> {
    match number {
        INT => Ok(rustix::process::Signal::INT),
        TERM => Ok(rustix::process::Signal::TERM),
        other => Err(format!("no row drives signal {other}")),
    }
}

// --- The rows ---------------------------------------------------------------

/// The two direct modes, named by what selects them: a PTY owns the host
/// terminal (raw mode), streaming leaves it canonical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Pty,
    Stream,
}

impl Mode {
    pub const fn name(self) -> &'static str {
        match self {
            Mode::Pty => "pty",
            Mode::Stream => "stream",
        }
    }

    const fn options(self) -> &'static [&'static str] {
        match self {
            Mode::Pty => &["-t"],
            Mode::Stream => &["-T"],
        }
    }

    /// The channels this mode selects. One place, so a streaming row cannot
    /// claim a guest terminal and a PTY row cannot claim separate channels.
    const fn channels(self) -> (Channel, Channel, Channel) {
        match self {
            Mode::Pty => (Channel::Tty, Channel::Tty, Channel::Tty),
            Mode::Stream => (Channel::Tty, Channel::File, Channel::File),
        }
    }

    /// A PTY launch owns the host terminal; streaming never touches it.
    fn raw(self) -> bool {
        self == Mode::Pty
    }
}

/// What happens to a forwarded signal, which is what the row's status and
/// teardown expectations follow from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Behaviour {
    /// The guest traps the signal and exits with its own status (42).
    Handled,
    /// The guest dies of the forwarded signal, which the shell convention reports
    /// as `128 + N` from the signal its own kernel reported.
    Unhandled,
    /// The guest records the signal and keeps running, so the fixed grace expires
    /// and the launcher's forced teardown reports `128 + N`.
    GraceExpiry,
    /// A second signal forces immediately and reports **its own** number: INT then
    /// TERM is 143, not 130.
    SecondInterrupt,
    /// The guest kills itself with no host signal involved, so `128 + N` can only
    /// come from its own reported identity.
    SelfSignal,
}

impl Behaviour {
    pub fn name(self) -> &'static str {
        match self {
            Behaviour::Handled => "handled",
            Behaviour::Unhandled => "unhandled",
            Behaviour::GraceExpiry => "grace-expiry",
            Behaviour::SecondInterrupt => "second-interrupt",
            Behaviour::SelfSignal => "self-signal",
        }
    }
}

/// One signal row's own facts. The probe words live in the case's `probe`, so a
/// row cannot disagree with the argv it runs, and the mode owns the options and
/// channels.
#[derive(Debug, Clone, Copy)]
pub struct Row {
    pub mode: Mode,
    pub behaviour: Behaviour,
    /// The signals this driver delivers, in order. Empty for a self-signalled row.
    pub signals: &'static [i32],
    /// The status the published table requires, never what a launcher prints.
    pub expect: i32,
    /// Facts the guest itself must report. Only a *forwarded* signal can appear
    /// here: an interrupting second signal ends the session instead of reaching
    /// the guest, so a `second` row's evidence for it is the status and the forced
    /// notice, both asserted separately.
    pub markers: &'static [&'static str],
    /// Markers that would contradict the behaviour under test.
    pub forbidden: &'static [&'static str],
    /// The launcher's own forced-teardown notice, when the row requires one. A
    /// status alone cannot tell a forced shutdown from a guest that exited with
    /// the same number itself.
    pub forced_notice: Option<&'static str>,
    /// A guest end must show the ordinary teardown notice and never a forced one,
    /// because a status alone cannot tell the two apart.
    pub ordinary_teardown: bool,
}

/// The nine rows of one mode: both signals times the outcomes #401 names, plus
/// the self-signalled row. The marker strings are shared between modes, so a row
/// cannot state a different fact depending on its selection.
const fn mode_rows(mode: Mode) -> Rows {
    Rows {
        int_handled: Row {
            mode,
            behaviour: Behaviour::Handled,
            signals: &[INT],
            expect: 42,
            markers: &["SIGNAL-READY", "SIGNAL-TRAPPED INT"],
            forbidden: &["SIGNAL-SURVIVED", "SIGNAL-IGNORED"],
            forced_notice: None,
            ordinary_teardown: true,
        },
        int_unhandled: Row {
            mode,
            behaviour: Behaviour::Unhandled,
            signals: &[INT],
            expect: 128 + INT,
            markers: &["SIGNAL-READY"],
            forbidden: &["SIGNAL-SURVIVED", "SIGNAL-TRAPPED", "SIGNAL-IGNORED"],
            forced_notice: None,
            ordinary_teardown: true,
        },
        int_ignored: Row {
            mode,
            behaviour: Behaviour::GraceExpiry,
            signals: &[INT],
            expect: 128 + INT,
            markers: &["SIGNAL-READY", "SIGNAL-IGNORED INT"],
            forbidden: &["SIGNAL-SURVIVED", "SIGNAL-TRAPPED"],
            forced_notice: Some("Interrupted by signal 2"),
            ordinary_teardown: false,
        },
        int_second: Row {
            mode,
            behaviour: Behaviour::SecondInterrupt,
            signals: &[INT, TERM],
            expect: 128 + TERM,
            markers: &["SIGNAL-READY", "SIGNAL-IGNORED INT"],
            forbidden: &["SIGNAL-SURVIVED", "SIGNAL-TRAPPED"],
            forced_notice: Some("Interrupted by signal 15"),
            ordinary_teardown: false,
        },
        term_handled: Row {
            mode,
            behaviour: Behaviour::Handled,
            signals: &[TERM],
            expect: 42,
            markers: &["SIGNAL-READY", "SIGNAL-TRAPPED TERM"],
            forbidden: &["SIGNAL-SURVIVED", "SIGNAL-IGNORED"],
            forced_notice: None,
            ordinary_teardown: true,
        },
        term_unhandled: Row {
            mode,
            behaviour: Behaviour::Unhandled,
            signals: &[TERM],
            expect: 128 + TERM,
            markers: &["SIGNAL-READY"],
            forbidden: &["SIGNAL-SURVIVED", "SIGNAL-TRAPPED", "SIGNAL-IGNORED"],
            forced_notice: None,
            ordinary_teardown: true,
        },
        term_ignored: Row {
            mode,
            behaviour: Behaviour::GraceExpiry,
            signals: &[TERM],
            expect: 128 + TERM,
            markers: &["SIGNAL-READY", "SIGNAL-IGNORED TERM"],
            forbidden: &["SIGNAL-SURVIVED", "SIGNAL-TRAPPED"],
            forced_notice: Some("Interrupted by signal 15"),
            ordinary_teardown: false,
        },
        term_second: Row {
            mode,
            behaviour: Behaviour::SecondInterrupt,
            signals: &[TERM, INT],
            expect: 128 + INT,
            markers: &["SIGNAL-READY", "SIGNAL-IGNORED TERM"],
            forbidden: &["SIGNAL-SURVIVED", "SIGNAL-TRAPPED"],
            forced_notice: Some("Interrupted by signal 2"),
            ordinary_teardown: false,
        },
        // The guest kills itself, so no host signal exists to explain the status.
        self_term: Row {
            mode,
            behaviour: Behaviour::SelfSignal,
            signals: &[],
            expect: 128 + TERM,
            markers: &["SIGNAL-READY"],
            forbidden: &["SIGNAL-SURVIVED", "SIGNAL-TRAPPED", "SIGNAL-IGNORED"],
            forced_notice: None,
            ordinary_teardown: true,
        },
    }
}

/// One mode's rows, named, so a case reads `&signal::PTY.int_ignored` instead of
/// an index nobody can check.
pub struct Rows {
    pub int_handled: Row,
    pub int_unhandled: Row,
    pub int_ignored: Row,
    pub int_second: Row,
    pub term_handled: Row,
    pub term_unhandled: Row,
    pub term_ignored: Row,
    pub term_second: Row,
    pub self_term: Row,
}

pub const PTY: Rows = mode_rows(Mode::Pty);
pub const STREAM: Rows = mode_rows(Mode::Stream);

/// Every row, for an inventory control that must see all eighteen.
pub fn all() -> Vec<&'static Row> {
    let mut rows: Vec<&'static Row> = Vec::new();
    for table in [&PTY, &STREAM] {
        rows.extend([
            &table.int_handled,
            &table.int_unhandled,
            &table.int_ignored,
            &table.int_second,
            &table.term_handled,
            &table.term_unhandled,
            &table.term_ignored,
            &table.term_second,
            &table.self_term,
        ]);
    }
    rows
}

/// The plan as the receipt and the failure messages name it.
pub fn expected_name(row: &Row) -> String {
    if row.signals.is_empty() {
        return "no host signal".to_owned();
    }
    row.signals
        .iter()
        .map(|number| name_of(*number))
        .collect::<Vec<_>>()
        .join(" + ")
}

/// One signal row's case, built from the row itself: its mode owns the launch
/// options and the descriptor assignment, so the argv a row runs and the facts it
/// asserts cannot drift apart.
pub const fn case(name: &'static str, probe: &'static [&'static str], row: &'static Row) -> Case {
    let (stdin, stdout, stderr) = row.mode.channels();
    Case {
        name,
        group: Group::Signal,
        options: row.mode.options(),
        probe,
        stdin,
        stdout,
        stderr,
        env: &[],
        route: None,
        expect: super::Expect::Signal(row),
    }
}

// --- The shared oracle ------------------------------------------------------

/// One possible reading of a 255, offered only when the number is 255.
///
/// `128 + N` requires the guest's own terminating signal. A status of exactly 255
/// is consistent with the runtime reporting the unknown code `-1` and no
/// identity, which is what an older runtime does. It is a possibility, not a
/// diagnosis: a failure record carries no frame or metadata that says which layer
/// dropped identity, so nothing here assigns one. Any other status gets no hint at
/// all rather than a guess about a cause nobody observed.
pub fn unhandled_hint(row: &Row, status: i32) -> String {
    if !matches!(row.behaviour, Behaviour::Unhandled | Behaviour::SelfSignal) || status != 255 {
        return String::new();
    }
    "; 255 is also what a runtime that sent the unknown code -1 and no signal \
     produces. If that is what happened here, one possible cause is a built agentd \
     or runtime bundle older than this patch: a new SDK with an old embedded agentd \
     reports that honestly and is not evidence about the mapping"
        .to_owned()
}

/// Every way one signal row's observed end contradicts its published row.
///
/// Pure: it reads only what the driver observed, so the boot-free controls can run
/// the same function against a fabricated record — and they do, rather than a
/// copy, which is what makes them evidence about this oracle.
pub fn guest_end_problems(
    row: &Row,
    status: i32,
    launcher_path: &str,
    text: &str,
    expected_name: &str,
) -> Vec<String> {
    let mut problems: Vec<String> = Vec::new();
    if status != row.expect {
        problems.push(format!(
            "launcher status {status}, but the status table requires {} after {expected_name}, \
             with a guest whose behaviour is {}{}; output {:?}",
            row.expect,
            row.behaviour.name(),
            unhandled_hint(row, status),
            tail(text)
        ));
    }
    if row.ordinary_teardown {
        if !text.contains("Stopping sandbox") {
            problems.push(format!(
                "a guest end must show the ordinary teardown notice: {:?}",
                tail(text)
            ));
        }
        if text.contains("Interrupted by signal") {
            problems.push(format!(
                "a guest end must never report a forced teardown: {:?}",
                tail(text)
            ));
        }
        if launcher_path != ORDINARY_TEARDOWN {
            problems.push(format!(
                "the launcher path was {launcher_path:?}, not the ordinary teardown"
            ));
        }
    }
    problems
}

/// Every way one signal row's *timing* contradicts its behaviour.
///
/// A row that has to wait out the grace and a row that must be forced before it
/// are the two halves of one question, so they are one function. `None` (no
/// timing was recorded) is a problem for a row that needs one, never a pass: a
/// missing observation is not an absence of failure.
pub fn grace_problems(row: &Row, first_signal_to_exit: Option<f64>) -> Vec<String> {
    let needed = matches!(
        row.behaviour,
        Behaviour::GraceExpiry | Behaviour::SecondInterrupt
    );
    if !needed {
        return Vec::new();
    }
    let Some(first) = first_signal_to_exit else {
        return vec!["no first-signal timing was recorded".to_owned()];
    };
    match row.behaviour {
        Behaviour::GraceExpiry if first < GRACE_SECONDS => vec![format!(
            "the launcher ended {first}s after the forwarded signal, before its fixed \
             {GRACE_SECONDS}s grace: a guest that ignores the signal is still owed that grace"
        )],
        Behaviour::SecondInterrupt if first >= GRACE_SECONDS => vec![format!(
            "the launcher ended {first}s after the first signal, which is at or past the \
             {GRACE_SECONDS}s grace, so the expiry decided the end and the status may be the \
             first signal's"
        )],
        _ => Vec::new(),
    }
}

/// The published numbers, as a control reads them: a row asserts the real grace
/// and the real wait, so neither may drift silently.
pub fn shipped_numbers() -> (f64, f64) {
    (GRACE_SECONDS, WAIT_SECONDS)
}

// --- The per-attempt release ------------------------------------------------

/// A per-attempt release file for a self-signalled guest.
///
/// The guest cannot be released by a stale file from another attempt and cannot
/// be released by guessing: the basename carries this case, form and process, and
/// the content is an unguessable token this driver writes only after the
/// readiness and live-ownership observations both succeeded. It is passed as extra
/// probe argv rather than stored on the [`Case`], because the case table is
/// module-global and mutating one would make two attempts share a release.
#[derive(Debug)]
pub struct Release {
    file: String,
    host_path: PathBuf,
    token: String,
    released_after: Option<&'static str>,
    released_after_ready_seconds: Option<f64>,
    removed: bool,
}

impl Release {
    pub fn allocate(
        invocation: &Invocation,
        receipt: &mut Map<String, Value>,
    ) -> Result<Self, String> {
        let label = invocation.label();
        let file = format!(
            ".signal-release-{}-{}-{}",
            invocation.case.name,
            invocation.form.value_name(),
            std::process::id()
        );
        let host_path = invocation.project.join(&file);
        require(!host_path.exists(), || {
            format!(
                "{label}: the release file {} already existed before this attempt",
                host_path.display()
            )
        })?;
        let release = Self {
            file,
            host_path,
            token: random_token()?,
            released_after: None,
            released_after_ready_seconds: None,
            removed: false,
        };
        release.store(receipt);
        Ok(release)
    }

    /// The two extra probe words: the release's name and its token.
    pub fn words(&self) -> Vec<String> {
        vec![self.file.clone(), self.token.clone()]
    }

    fn write(&self) -> Result<(), String> {
        fs::write(&self.host_path, &self.token)
            .map_err(|error| format!("{}: {error}", self.host_path.display()))
    }

    fn mark_released(&mut self, after_ready: f64) {
        self.released_after = Some("readiness+live-ownership");
        self.released_after_ready_seconds = Some(after_ready);
    }

    fn remove(&mut self) {
        let _ = fs::remove_file(&self.host_path);
        self.removed = true;
    }

    fn entry(&self) -> Value {
        let mut entry = Map::new();
        entry.insert("file".to_owned(), json!(self.file));
        entry.insert(
            "host_path".to_owned(),
            json!(self.host_path.display().to_string()),
        );
        entry.insert("token_bytes".to_owned(), json!(self.token.len() / 2));
        entry.insert("distinct_from_previous_attempts".to_owned(), json!(true));
        if let Some(after) = self.released_after {
            entry.insert("released_after".to_owned(), json!(after));
        }
        if let Some(seconds) = self.released_after_ready_seconds {
            entry.insert("released_after_ready_seconds".to_owned(), json!(seconds));
        }
        if self.removed {
            entry.insert("removed_after_proven_cleanup".to_owned(), json!(true));
        }
        Value::Object(entry)
    }

    /// Merge this attempt's release facts into the receipt. Merged, not replaced,
    /// so a later state cannot hide an earlier one.
    pub fn store(&self, receipt: &mut Map<String, Value>) {
        signal_entry(receipt).insert("release".to_owned(), self.entry());
    }
}

/// Sixteen random bytes as hex, from the kernel's CSPRNG: what the Python took
/// from `secrets.token_hex(16)`. The token is a handshake, not a secret that
/// protects anything later, so this is the whole requirement.
fn random_token() -> Result<String, String> {
    use std::io::Read;
    let mut bytes = [0u8; 16];
    fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|error| format!("cannot read /dev/urandom: {error}"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn signal_entry(receipt: &mut Map<String, Value>) -> &mut Map<String, Value> {
    let signal = receipt
        .entry("signal".to_owned())
        .or_insert_with(|| Value::Object(Map::new()));
    if !signal.is_object() {
        *signal = Value::Object(Map::new());
    }
    signal.as_object_mut().expect("just made an object")
}

// --- Ownership, before and after --------------------------------------------

/// Host processes whose command line names any of `patterns`.
///
/// A guest's own descendants live inside the microVM, so the only host-visible
/// thing that can still be running on their behalf is the process that hosts
/// them. An empty result therefore means "this launch is not running any more",
/// and any result at all is a survivor the row must not accept.
///
/// `ps` writes into a file this driver owns rather than a pipe: a bounded wait
/// cannot also drain a pipe, and a full one would stall the observation.
fn host_processes_matching(
    patterns: &[&str],
    scratch: &Path,
    name: &str,
) -> Result<Vec<Value>, String> {
    if patterns.is_empty() {
        return Ok(Vec::new());
    }
    let out_path = scratch.join(name);
    let file =
        fs::File::create(&out_path).map_err(|error| format!("{}: {error}", out_path.display()))?;
    let mut command = Command::new("ps");
    command.args(["-axo", "pid=,ppid=,command="]);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(file))
        .stderr(Stdio::null());
    let mut child = pty::OwnedChild::new(
        command
            .spawn()
            .map_err(|error| format!("cannot run ps: {error}"))?,
    );
    let status = child
        .finish(Duration::from_secs(60))
        .map_err(|error| format!("ps did not finish: {error}"))?;
    require(status.success(), || format!("ps exited {status:?}"))?;
    let text = fs::read_to_string(&out_path)
        .map_err(|error| format!("{}: {error}", out_path.display()))?;
    Ok(parse_ps(&text, patterns))
}

/// The `ps -axo pid=,ppid=,command=` rows that name one of `patterns`.
/// Pure, so the parsing is testable without a host scan.
fn parse_ps(text: &str, patterns: &[&str]) -> Vec<Value> {
    let mut found = Vec::new();
    for line in text.split('\n') {
        let Some((pid, ppid, command)) = three_fields(line) else {
            continue;
        };
        let Some(pattern) = patterns.iter().find(|pattern| command.contains(*pattern)) else {
            continue;
        };
        let command: String = command.chars().take(240).collect();
        found.push(json!({
            "pid": pid,
            "ppid": ppid,
            "pattern": pattern,
            "command": command,
        }));
    }
    found
}

/// `PID PPDF COMMAND`, where the command may itself contain spaces.
fn three_fields(line: &str) -> Option<(u32, u32, &str)> {
    let (pid, rest) = split_field(line)?;
    let (ppid, command) = split_field(rest)?;
    Some((pid.parse().ok()?, ppid.parse().ok()?, command.trim_end()))
}

fn split_field(line: &str) -> Option<(&str, &str)> {
    let line = line.trim_start();
    let end = line.find(char::is_whitespace)?;
    Some((&line[..end], line[end..].trim_start()))
}

/// Socket paths of these sandboxes that still exist on disk.
fn owned_sockets(state_root: &Path, names: &[&str]) -> Vec<String> {
    let root = state_root.join("msb-home");
    let mut found: Vec<String> = Vec::new();
    let mut seen: Vec<&str> = Vec::new();
    for name in names {
        if seen.contains(name) {
            continue;
        }
        seen.push(name);
        for path in crate::egress_launch::socket_paths(&root, name) {
            if path.exists() {
                found.push(path.display().to_string());
            }
        }
    }
    found
}

fn sandbox_names(rows: &[Value]) -> Vec<String> {
    rows.iter()
        .filter_map(|row| row.get("name").and_then(Value::as_str).map(str::to_owned))
        .collect()
}

/// What a healthy launch owns: the VM process, its catalog row, its sockets.
///
/// Recorded *before* any signal, so the later absence is a comparison with a real
/// observation instead of an assumption that nothing was ever there.
pub fn owned_while_running(
    state_root: &Path,
    launcher_pid: Option<i32>,
    label: &str,
    scratch: &Path,
) -> Result<Value, String> {
    let runtime = owned_runtime_identity(state_root, launcher_pid, label)?;
    let names = sandbox_names(&owned_catalog_rows(state_root, launcher_pid)?);
    require(!names.is_empty(), || {
        format!("{label}: no catalog row names this launcher's sandbox")
    })?;
    let patterns: Vec<&str> = names.iter().map(String::as_str).collect();
    let live = host_processes_matching(&patterns, scratch, "ps-before.txt")?;
    // Without this the later "no process names the sandbox" would be vacuous: a
    // scan that never matched anything proves nothing when it matches nothing.
    require(!live.is_empty(), || {
        format!(
            "{label}: the sandbox {names:?} is not named by any running process, so its \
             absence after the session could not be observed either"
        )
    })?;
    Ok(json!({
        "runtime": runtime,
        "sandbox_names": names,
        "sockets": owned_sockets(state_root, &patterns),
        "host_processes": live,
    }))
}

/// Whether the runtime the baseline recorded is gone, given its recorded identity
/// (`before`) and what the host reports now.
///
/// Absence, not "a different process": a PID the kernel has reused is not this
/// launch's VM, so a changed identity counts as gone and an identical one does
/// not.
pub fn runtime_absent(recorded: &Value, current: Option<[u64; 2]>) -> bool {
    match current {
        None => true,
        Some(current) => json!(current) != *recorded,
    }
}

/// What this launch still owned once the launcher had exited.
///
/// Strictly an observation made **before** any rescue cleanup:
/// [`super::teardown_receipt`] stops whatever it finds, so an absence proved after
/// it has run would only prove that the rescue worked, not that the launch cleaned
/// up after itself.
pub fn observe_absence(
    state_root: &Path,
    session: &mut Session,
    before: &Value,
    scratch: &Path,
) -> Result<Value, String> {
    let launcher_pid = session.launcher_pid;
    let rows = owned_catalog_rows(state_root, launcher_pid)?;
    let names = sandbox_names(&rows);
    let before_names: Vec<String> = before
        .get("sandbox_names")
        .and_then(Value::as_array)
        .map(|names| {
            names
                .iter()
                .filter_map(|name| name.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let mut patterns: Vec<&str> = names.iter().map(String::as_str).collect();
    patterns.extend(before_names.iter().map(String::as_str));
    let runtime_pid = before
        .pointer("/runtime/pid")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let start = before.pointer("/runtime/start").cloned().ok_or_else(|| {
        "the baseline recorded no runtime identity, so nothing could be proved absent".to_owned()
    })?;
    let current = match u32::try_from(runtime_pid) {
        Ok(pid) => crate::egress_fixtures::process_identity(pid)?,
        Err(_) => None,
    };
    let runtime_gone = runtime_absent(&start, current);
    let exited = session.exited()?.is_some();
    Ok(json!({
        "observed_after_launcher_exit": exited,
        "launcher_pid": launcher_pid,
        "catalog_rows": rows.len(),
        "catalog_names": names,
        "sockets": owned_sockets(state_root, &patterns),
        "runtime_pid": runtime_pid,
        "runtime_gone": runtime_gone,
        "host_processes": host_processes_matching(&patterns, scratch, "ps-after.txt")?,
    }))
}

// --- The observation --------------------------------------------------------

fn round3(elapsed: Duration) -> f64 {
    (elapsed.as_secs_f64() * 1000.0).round() / 1000.0
}

/// One host-signal row: deliver real signals, then prove status, terminal and
/// absence.
///
/// Nothing about the guest is inferred from the launcher's notices: the guest
/// reports the signals it received itself, the launcher's status is compared with
/// the exact number the published table requires, and the ownership facts are
/// observed before any rescue could hide a survivor.
pub fn observe(
    invocation: &Invocation,
    session: &mut Session,
    receipt: &mut Map<String, Value>,
    row: &Row,
    mut release: Option<&mut Release>,
) -> Result<i32, String> {
    let label = invocation.label();
    let plan = expected_name(row);
    let work = session.work_dir().to_path_buf();
    {
        let entry = signal_entry(receipt);
        entry.insert("mode".to_owned(), json!(row.mode.name()));
        entry.insert("behaviour".to_owned(), json!(row.behaviour.name()));
        entry.insert("plan".to_owned(), json!(plan));
        entry.insert("grace_seconds".to_owned(), json!(GRACE_SECONDS));
        entry.insert("expected_status".to_owned(), json!(row.expect));
    }
    session.pump(
        |out| out.contains("SIGNAL-READY"),
        "the guest's signal readiness",
        marker_deadline(),
        View::Merged,
    )?;
    // The mode is an observation, not an assumption: a PTY launch owns the host
    // terminal in raw mode, streaming never touches it. A signal must not change
    // either, and the snapshot comparison below is what proves it did not.
    let raw = session.raw_observed()?;
    signal_entry(receipt).insert(
        "host_terminal".to_owned(),
        json!(if raw { "raw" } else { "canonical" }),
    );
    require(raw == row.mode.raw(), || {
        format!(
            "{label}: the host terminal is {} under a {} launch",
            if raw { "raw" } else { "canonical" },
            row.mode.name()
        )
    })?;
    let before = owned_while_running(&invocation.state_root, session.launcher_pid, &label, &work)?;
    receipt.insert("owned_before_signal".to_owned(), before.clone());
    let ready_at = Instant::now();
    let mut sent: Vec<Value> = Vec::new();
    let mut sent_at: Vec<Instant> = Vec::new();
    let mut released_at: Option<Instant> = None;
    if row.behaviour == Behaviour::SelfSignal {
        // No host signal is involved anywhere in this row, and the release is
        // written only now that readiness *and* the live-ownership baseline are
        // both observed. A signalling driver would make the status explainable by
        // the host instead of by the guest.
        let release = release
            .as_deref_mut()
            .ok_or_else(|| format!("{label}: a self-signalled row has no release to write"))?;
        release.write()?;
        let released = Instant::now();
        release.mark_released(round3(released.saturating_duration_since(ready_at)));
        released_at = Some(released);
    }
    for (index, number) in row.signals.iter().copied().enumerate() {
        if index > 0 {
            // The guest's own report of the first signal is what makes the second
            // one a *second interrupt* rather than a race with delivery.
            let first = ignored_marker(row.signals[0]);
            session.pump(
                |out| out.contains(first),
                "the guest's report of the first signal",
                marker_deadline(),
                View::Merged,
            )?;
        }
        require(session.exited()?.is_none(), || {
            format!(
                "{label}: the launcher had already exited before signal {} ({})",
                index + 1,
                name_of(number)
            )
        })?;
        let pid = session
            .launcher_pid
            .ok_or_else(|| format!("{label}: no launcher to signal"))?;
        pty::send_signal(pid, signal_of(number)?)
            .map_err(|error| format!("{label}: cannot signal the launcher: {error}"))?;
        let at = Instant::now();
        sent_at.push(at);
        sent.push(json!({
            "number": number,
            "name": name_of(number),
            "sent_after_ready": round3(at.saturating_duration_since(ready_at)),
        }));
    }
    let status = session.wait(Duration::from_secs_f64(WAIT_SECONDS))?;
    let exited_at = Instant::now();
    receipt.insert("launcher_status".to_owned(), json!(status));
    signal_entry(receipt).insert("sent".to_owned(), json!(sent));
    let timing = if row.behaviour == Behaviour::SelfSignal {
        // Nothing was sent, so there is no index into `sent_at` to measure from;
        // the row's own clock starts at the release.
        require(sent.is_empty() && sent_at.is_empty(), || {
            format!("{label}: a self-signalled row must send no host signal: {sent:?}")
        })?;
        let released =
            released_at.ok_or_else(|| format!("{label}: the release was never written"))?;
        json!({"release_to_exit": round3(exited_at.saturating_duration_since(released))})
    } else {
        require(!sent.is_empty(), || {
            format!("{label}: the row requires at least one host signal")
        })?;
        let last = sent_at.last().copied().unwrap_or(exited_at);
        json!({
            "first_signal_to_exit": round3(exited_at.saturating_duration_since(sent_at[0])),
            "last_signal_to_exit": round3(exited_at.saturating_duration_since(last)),
        })
    };
    signal_entry(receipt).insert("timing".to_owned(), timing.clone());
    // Every channel, because a signal row's report may be on the terminal (PTY) or
    // in a redirected file (streaming): the launcher's own notice goes wherever its
    // stderr went, and the guest's report wherever its stdout went.
    let text = session.merged_text();
    let launcher_path = if text.contains("Interrupted by signal") {
        FORCED_TEARDOWN
    } else {
        ORDINARY_TEARDOWN
    };
    signal_entry(receipt).insert("launcher_path".to_owned(), json!(launcher_path));
    for marker in row.markers.iter().copied() {
        require(text.contains(marker), || {
            format!(
                "{label}: the guest never reported {marker:?}, so the signal's arrival was \
                 not observed: {:?}",
                tail(&text)
            )
        })?;
    }
    for marker in row.forbidden.iter().copied() {
        require(!text.contains(marker), || {
            format!(
                "{label}: the guest reported {marker:?}, which contradicts the {} behaviour \
                 under test: {:?}",
                row.behaviour.name(),
                tail(&text)
            )
        })?;
    }
    // Restoration and absence are recorded and judged *before* the status, so a row
    // that is red for its status still carries the two observations it exists to
    // prove — and still fails if either of them is wrong.
    let baseline = session.baseline_state();
    let final_state = session.final_state();
    receipt.insert(
        "terminal".to_owned(),
        json!({
            "baseline": baseline.clone().map(super::state_json),
            "final": final_state.clone().map(super::state_json),
        }),
    );
    require(baseline == final_state, || {
        format!(
            "{label}: the host terminal was not restored: {:?}",
            receipt.get("terminal")
        )
    })?;
    let absence = observe_absence(&invocation.state_root, session, &before, &work)?;
    receipt.insert("absence_before_rescue".to_owned(), absence.clone());
    let left = absence
        .get("catalog_rows")
        .and_then(Value::as_u64)
        .unwrap_or(u64::MAX);
    require(left == 0, || {
        format!(
            "{label}: the launch left {left} catalog row(s) behind: {}",
            absence.get("catalog_names").cloned().unwrap_or(Value::Null)
        )
    })?;
    let sockets = absence
        .get("sockets")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    require(sockets.is_empty(), || {
        format!("{label}: the launch left owned sockets behind: {sockets:?}")
    })?;
    require(absence.get("runtime_gone") == Some(&json!(true)), || {
        format!(
            "{label}: the runtime that hosted the guest is still executing: {}",
            absence.get("runtime_pid").cloned().unwrap_or(Value::Null)
        )
    })?;
    let live = absence
        .get("host_processes")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{label}: the host process scan was not recorded"))?;
    require(live.is_empty(), || {
        format!("{label}: a process still names this launch's sandbox: {live:?}")
    })?;
    let problems = guest_end_problems(row, status, launcher_path, &text, &plan);
    require(problems.is_empty(), || {
        format!("{label}: {}", problems.join("; "))
    })?;
    let first_signal_to_exit = timing.get("first_signal_to_exit").and_then(Value::as_f64);
    let problems = grace_problems(row, first_signal_to_exit);
    require(problems.is_empty(), || {
        format!("{label}: {}", problems.join("; "))
    })?;
    if let Some(notice) = row.forced_notice {
        // The status alone cannot tell a forced shutdown from a guest that exited
        // with the same number itself; the launcher's own account of the end can.
        require(text.contains(notice), || {
            format!(
                "{label}: the launcher never reported a forced teardown after {notice:?}: {:?}",
                tail(&text)
            )
        })?;
        signal_entry(receipt).insert("forced_notice".to_owned(), json!(notice));
    }
    if let Some(release) = release {
        // The row proved everything above, so this attempt's own release file is no
        // longer needed. A row that failed kept it: the failure's evidence is the
        // token that was or was not written, not a cleaned directory.
        release.remove();
    }
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_grace_and_wait_are_the_published_numbers() {
        assert_eq!(shipped_numbers(), (5.0, 120.0));
    }

    #[test]
    fn the_rows_are_both_modes_of_the_published_matrix() {
        let rows = all();
        assert_eq!(rows.len(), 18);
        for mode in [Mode::Pty, Mode::Stream] {
            let of_mode: Vec<&Row> = rows
                .iter()
                .copied()
                .filter(|row| row.mode == mode)
                .collect();
            assert_eq!(of_mode.len(), 9, "{mode:?}");
            assert!(of_mode.iter().any(|row| row.signals.is_empty()));
        }
        // 128 + N comes from the guest's own reported identity, so an unhandled or
        // grace-expiring row states the number of *its* signal, and the second row
        // states the interrupting one.
        for row in rows.iter().copied() {
            let last = row.signals.last().copied().unwrap_or(TERM);
            match row.behaviour {
                Behaviour::Handled => assert_eq!(row.expect, 42),
                Behaviour::Unhandled | Behaviour::GraceExpiry | Behaviour::SecondInterrupt => {
                    assert_eq!(row.expect, 128 + last, "{:?}", row.behaviour);
                }
                Behaviour::SelfSignal => assert_eq!(row.expect, 128 + TERM),
            }
        }
    }

    #[test]
    fn a_reused_pid_is_not_the_launchs_runtime() {
        let recorded = json!([11, 22]);
        assert!(runtime_absent(&recorded, None), "no process is absent");
        assert!(
            !runtime_absent(&recorded, Some([11, 22])),
            "the same process is not gone"
        );
        // A reused PID carries a different start time: absent, not "someone else".
        assert!(runtime_absent(&recorded, Some([11, 23])), "a reused pid");
    }

    #[test]
    fn a_ps_row_keeps_a_command_that_contains_spaces() {
        let text = "  123    1 /path/with a space/microsandbox --flag\n\
                    456    1 something else\n\
                    not-a-row\n";
        let found = parse_ps(text, &["/path/with a space/microsandbox"]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0]["pid"], json!(123));
        assert_eq!(found[0]["ppid"], json!(1));
        assert_eq!(
            found[0]["command"],
            json!("/path/with a space/microsandbox --flag")
        );
        assert!(parse_ps(text, &[]).is_empty());
    }

    #[test]
    fn a_forced_end_is_never_a_guest_end() {
        let ordinary = "==> Stopping sandbox\n[SIGNAL-READY]";
        let forced = "==> Interrupted by signal 2; tearing down the sandbox (exit 130)";
        let row = &PTY.int_unhandled;
        assert!(guest_end_problems(row, 130, ORDINARY_TEARDOWN, ordinary, "INT").is_empty());
        let problems = guest_end_problems(row, 130, FORCED_TEARDOWN, forced, "INT");
        assert!(
            problems
                .iter()
                .any(|problem| problem.contains("never report a forced"))
        );
        assert!(
            problems
                .iter()
                .any(|problem| problem.contains("not the ordinary teardown"))
        );
        // The hint may only name the 255 reading where the number is 255.
        assert!(unhandled_hint(row, 130).is_empty());
        assert!(unhandled_hint(row, 255).contains("unknown code -1"));
    }
}
