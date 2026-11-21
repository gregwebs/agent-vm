//! Boot-free controls for the direct-terminal driver (#699).
//!
//! Ported from `script/test/lib/direct-terminal-contract.py`. These prove the
//! *oracle*: that the driver's exact-byte, EOF, resize-handshake and restoration
//! expectations distinguish a correct session from a broken one. They need no
//! VM, runtime or image, and claim nothing about a launcher's own adapters.
//!
//! Each control runs the **real driver** with `--bin` pointed at
//! `harness launcher-standin` (#698), so the driver's own expectation code, its
//! PTY plumbing, its channel assignments and its bounded deadlines are what get
//! exercised. The stand-in plays only a launcher's part and has deliberately
//! broken variants.
//!
//! A rejection control asserts a *failure* verdict with the expected diagnostic.
//! It never treats a timeout as a success: a driver crash, a missing receipt or
//! this control's own timeout is a failed control, so a broken driver cannot
//! masquerade as a successful rejection.
//!
//! The stand-in is this binary, so each control writes a one-line `sh` wrapper
//! for it — the same shape `egress supervisor` uses for its fake candidate, and
//! the reason `--bin` stays an ordinary executable path.

use std::{
    fs,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

use serde_json::Value;

use crate::{
    direct_terminal::{self, Case, Channel, Expect, Form, cases, signal},
    egress_cases, pty,
};

/// A control's whole run, including a deliberately stalled one.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(60);
/// The driver's per-observation deadline under these controls: short, so a
/// "never delivers EOF" row fails quickly instead of burning a minute.
const CONTROL_MARKER_DEADLINE: &str = "8";
/// Every spelling that forces streaming from a terminal.
const FORCE_OFF: [&str; 2] = ["-T", "--no-tty"];
/// Every spelling that forces a PTY.
const FORCE_ON: [&str; 2] = ["-t", "--tty"];

fn fixture(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

fn harness_binary() -> Result<PathBuf, String> {
    let path = egress_cases::harness_binary();
    if path.is_file() {
        return Ok(path);
    }
    Err(
        "the harness binary is not built: run cargo build --locked -p agent-vm-harness --bins"
            .to_owned(),
    )
}

/// A scratch tree for one control, removed when the control returns. It lives
/// directly under the system temp directory and carries a `dtc-` prefix, so a
/// survivor is identifiable by name.
struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Result<Self, String> {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default();
        let created = std::env::temp_dir().join(format!(
            "dtc-{}-{stamp}-{}",
            std::process::id(),
            name.replace([' ', '/', '(', ')'], "-")
        ));
        fs::create_dir_all(&created).map_err(|error| format!("{}: {error}", created.display()))?;
        Ok(Self { root: created })
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }

    /// The project the driver launches in, with the guest probe installed, and
    /// the stand-in's wrapper next to it.
    fn prepare(&self) -> Result<Prepared, String> {
        let project = self.path("project");
        fs::create_dir_all(&project).map_err(|error| format!("{}: {error}", project.display()))?;
        let probe = fixture("script/test/fixtures/direct-terminal/guest-probe.sh");
        fs::copy(&probe, project.join("guest-probe.sh"))
            .map_err(|error| format!("{}: {error}", probe.display()))?;
        let evidence = self.path("evidence");
        fs::create_dir_all(&evidence)
            .map_err(|error| format!("{}: {error}", evidence.display()))?;
        let standin = self.path("launcher-standin");
        let harness = harness_binary()?;
        fs::write(
            &standin,
            format!(
                "#!/bin/sh\nexec {} launcher-standin \"$@\"\n",
                shell_quote(&harness)
            ),
        )
        .map_err(|error| format!("{}: {error}", standin.display()))?;
        let mut permissions = fs::metadata(&standin)
            .map_err(|error| format!("{}: {error}", standin.display()))?
            .permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
        fs::set_permissions(&standin, permissions)
            .map_err(|error| format!("{}: {error}", standin.display()))?;
        Ok(Prepared {
            project,
            evidence,
            standin,
        })
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct Prepared {
    project: PathBuf,
    evidence: PathBuf,
    standin: PathBuf,
}

/// A path as one shell word. The wrapper is written by this control, so quoting
/// is about a workspace path containing a space, not about an untrusted input.
fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', r"'\''"))
}

/// What one control expects from the driver.
enum Expected {
    /// The driver must accept the stand-in.
    Accept,
    /// The driver must *complete* and reject the stand-in with one of these
    /// diagnostics.
    Reject(&'static [&'static str]),
}

struct DriverControl {
    name: &'static str,
    case: &'static str,
    standin_mode: &'static str,
    expected: Expected,
}

/// The driver-run controls, in the order the Python suite ran them.
const DRIVER_CONTROLS: [DriverControl; 18] = [
    DriverControl {
        name: "accept/identity with both descriptors terminal",
        case: "identity-auto",
        standin_mode: "ok",
        expected: Expected::Accept,
    },
    DriverControl {
        name: "accept/raw input A 1d B reaches the guest, code 7",
        case: "input",
        standin_mode: "ok",
        expected: Expected::Accept,
    },
    // The stand-in's guest inherits the driver's own terminal, so the sizes here
    // are the driver's shared geometry rather than a launcher constant.
    DriverControl {
        name: "accept/resize the host geometry then 43x119, code 7",
        case: "resize",
        standin_mode: "ok",
        expected: Expected::Accept,
    },
    DriverControl {
        name: "accept/streamed terminal stdin, exact bytes and code 23",
        case: "stream-input-no-tty",
        standin_mode: "ok",
        expected: Expected::Accept,
    },
    DriverControl {
        name: "accept/suffix tokens are guest argv",
        case: "suffix-argv",
        standin_mode: "ok",
        expected: Expected::Accept,
    },
    DriverControl {
        name: "reject/a mangled escape byte changes the guest's hex",
        case: "input",
        standin_mode: "mangle-input",
        expected: Expected::Reject(&["guest saw"]),
    },
    DriverControl {
        name: "reject/a truncated streamed payload fails the checksum",
        case: "stream-input-no-tty",
        standin_mode: "stream-truncated",
        expected: Expected::Reject(&["bytes=", "cksum="]),
    },
    DriverControl {
        name: "reject/a missed resize notification fails",
        case: "resize",
        standin_mode: "no-winch",
        expected: Expected::Reject(&[
            "the guest timed out",
            "the guest never observed the resize",
            "the resize verdict",
        ]),
    },
    DriverControl {
        name: "reject/an early exit before readiness fails",
        case: "identity-auto",
        standin_mode: "early-exit",
        expected: Expected::Reject(&["the launcher exited with"]),
    },
    DriverControl {
        name: "reject/a terminal left raw fails the restoration check",
        case: "identity-auto",
        standin_mode: "raw-leftover",
        expected: Expected::Reject(&["the host terminal was not restored"]),
    },
    // The three native-only groups below are *not* claimed as proven here: their
    // subject is a real launcher's own refusal, status table or catalog. What
    // these controls prove is that the driver's oracle for them rejects a
    // stand-in that answers the wrong thing, so the oracle is live and the row
    // cannot be satisfied by a launcher that merely exits.
    DriverControl {
        name: "reject/a launcher that ignores the refusal shape fails the status oracle",
        case: "reject-pipe-tty",
        standin_mode: "ok",
        expected: Expected::Reject(&["not a usage error"]),
    },
    DriverControl {
        name: "reject/a launcher's own failure status is not a missing program's 127",
        case: "status-missing",
        standin_mode: "ok",
        expected: Expected::Reject(&["not 127"]),
    },
    DriverControl {
        name: "reject/a runtime the catalog does not name is never signalled",
        case: "wait",
        standin_mode: "ok",
        expected: Expected::Reject(&["no catalog row names this launcher's sandbox"]),
    },
    // The prompt's oracle is control-proven: the stand-in plays a takeover (its
    // frames are a control's minimal rendition, not the product's byte stream), so
    // a correct one must pass and each broken one must fail for its own reason.
    // What no control claims is the allowance store and the refusal log: those are
    // the real launcher's, and `--standin` records the `access` check as skipped.
    DriverControl {
        name: "accept/a correct prompt, answered with d",
        case: "prompt-deny",
        standin_mode: "prompt-ok",
        expected: Expected::Accept,
    },
    DriverControl {
        name: "accept/the launcher's answer cadence, answered once",
        case: "prompt-deny",
        standin_mode: "prompt-cadence",
        expected: Expected::Accept,
    },
    DriverControl {
        name: "reject/a takeover that leaves the guest's modes unapplied fails",
        case: "prompt-deny",
        standin_mode: "prompt-no-modes",
        expected: Expected::Reject(&["the leave did not re-apply"]),
    },
    DriverControl {
        name: "reject/a withheld held line fails the ordering oracle",
        case: "prompt-deny",
        standin_mode: "prompt-drop-line",
        expected: Expected::Reject(&["once each and in order", "held lines"]),
    },
    DriverControl {
        name: "reject/a frame written after the leave fails",
        case: "prompt-deny",
        standin_mode: "prompt-redraw-after-leave",
        expected: Expected::Reject(&["a prompt frame was written after the leave"]),
    },
];

/// Run one driver invocation against the stand-in and return its receipt and
/// combined log. `(accepted, receipt, log)`.
fn drive(control: &DriverControl) -> Result<(bool, Value, String), String> {
    let scratch = Scratch::new(control.name)?;
    let prepared = scratch.prepare()?;
    let work = scratch.path("work");
    let log_path = scratch.path("driver.log");
    let log_file =
        fs::File::create(&log_path).map_err(|error| format!("{}: {error}", log_path.display()))?;
    let log_err = log_file
        .try_clone()
        .map_err(|error| format!("{}: {error}", log_path.display()))?;
    let form = Form::Run;
    let mut command = Command::new(harness_binary()?);
    command
        .arg("direct-terminal")
        .arg("--bin")
        .arg(&prepared.standin)
        .arg("--project")
        .arg(&prepared.project)
        .arg("--image")
        .arg("contract-image")
        .arg("--runtime")
        .arg(work.join("no-runtime"))
        .arg("--state-root")
        .arg(work.join("state"))
        .arg("--case")
        .arg(control.case)
        .arg("--form")
        .arg("run")
        .arg("--evidence")
        .arg(&prepared.evidence)
        // A boot-free control's launcher is a stand-in: it has no session,
        // refusal log or allowance store, so the driver records `access` as
        // skipped rather than pretending a real CLI ran.
        .arg("--standin")
        .env("STANDIN_MODE", control.standin_mode)
        .env("DIRECT_TERMINAL_MARKER_DEADLINE", CONTROL_MARKER_DEADLINE)
        .env(
            "PATH",
            format!(
                "{}:{}",
                prepared
                    .standin
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_default()
                    .display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .current_dir(&scratch.root)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_err));
    // The driver asserts it has no controlling terminal, and a control's own PTY
    // observation only means something when it does not.
    // SAFETY: `setsid` only issues a syscall.
    unsafe {
        command.pre_exec(|| {
            rustix::process::setsid()
                .map(|_| ())
                .map_err(std::io::Error::from)
        });
    }
    let mut child = match command.spawn() {
        Ok(child) => pty::OwnedChild::new(child),
        Err(error) => {
            return Err(format!(
                "{}: the driver did not start: {error}",
                control.name
            ));
        }
    };
    let status = match child.finish(CONTROL_TIMEOUT) {
        Ok(status) => status,
        Err(error) => {
            return Err(format!(
                "{}: the driver did not finish within {}s: {error}",
                control.name,
                CONTROL_TIMEOUT.as_secs()
            ));
        }
    };
    // The driver was started as a session leader, so anything it left behind (a
    // stand-in's own guest, in the `wait` control) shares its process group. The
    // group is signalled after the driver has exited: a control that leaked a
    // process per run would be a control nobody could trust to run in a loop.
    let _ = pty::send_signal_group(child.id(), rustix::process::Signal::KILL);
    let log = fs::read(&log_path)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default();
    let receipt_path =
        prepared
            .evidence
            .join(format!("{}-{}.json", control.case, form.value_name()));
    let receipt = match fs::read(&receipt_path) {
        Ok(bytes) => serde_json::from_slice::<Value>(&bytes)
            .map_err(|error| format!("{}: the receipt is not JSON: {error}", control.name))?,
        Err(error) => {
            return Err(format!(
                "{}: no receipt at {} ({error}); log={log}",
                control.name,
                receipt_path.display()
            ));
        }
    };
    let accepted =
        status.success() && receipt.get("verdict") == Some(&Value::String("pass".into()));
    Ok((accepted, receipt, log))
}

fn run_driver_control(control: &DriverControl) -> Result<(), String> {
    let (accepted, receipt, log) = drive(control)?;
    let tail = {
        let mut kept: String = log.chars().rev().take(600).collect();
        kept = kept.chars().rev().collect();
        kept
    };
    match &control.expected {
        Expected::Accept => {
            if accepted {
                return Ok(());
            }
            Err(format!(
                "{}: the driver rejected a correct stand-in: receipt={} log={tail}",
                control.name,
                serde_json::to_string(&receipt).unwrap_or_default()
            ))
        }
        Expected::Reject(expected) => {
            let error = receipt
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if accepted {
                return Err(format!(
                    "{}: the driver accepted a broken stand-in: receipt={}",
                    control.name,
                    serde_json::to_string(&receipt).unwrap_or_default()
                ));
            }
            if receipt.get("verdict") != Some(&Value::String("fail".into())) {
                return Err(format!(
                    "{}: the driver did not complete its own verdict: receipt={} log={tail}",
                    control.name,
                    serde_json::to_string(&receipt).unwrap_or_default()
                ));
            }
            if !expected.iter().any(|text| error.contains(text)) {
                return Err(format!(
                    "{}: error={error:?} expected one of {expected:?}",
                    control.name
                ));
            }
            Ok(())
        }
    }
}

// --- #401 host signal supervision -------------------------------------------
//
// The eighteen signal rows are native-only: a stand-in has no runtime, no catalog
// and no host process naming a sandbox, so `owned_while_running` cannot be faked
// without deleting the observation the rows exist to make. What these controls
// prove is the *shared oracle* — `signal::guest_end_problems`,
// `signal::grace_problems` and `signal::unhandled_hint` — against fabricated
// records. They call the production functions, not copies, which is what makes
// them evidence about what the native rows will judge.

/// The launcher's own account of a guest end, and of one it decided.
const ORDINARY_TEXT: &str = "==> Stopping sandbox\n[SIGNAL-READY]";
const FORCED_TEXT: &str = "==> Interrupted by signal 2; tearing down the sandbox (exit 130)";

/// The two guest ends the oracle must accept: the `INT` the guest itself died of
/// (130) and a self-signalled `TERM` (143). Those numbers are exactly what a
/// forced shutdown produces too, which is the whole point of the negatives below.
fn the_shared_oracle_accepts_an_ordinary_guest_end() -> Result<(), String> {
    let int = signal::guest_end_problems(
        &signal::PTY.int_unhandled,
        130,
        signal::ORDINARY_TEARDOWN,
        ORDINARY_TEXT,
        "INT",
    );
    let term = signal::guest_end_problems(
        &signal::PTY.self_term,
        143,
        signal::ORDINARY_TEARDOWN,
        ORDINARY_TEXT,
        "no host signal",
    );
    if int.is_empty() && term.is_empty() {
        return Ok(());
    }
    Err(format!(
        "a correct guest end was rejected: int={int:?} term={term:?}"
    ))
}

/// A forced notice overturns an otherwise perfect record, and so does the
/// receipt's own path string. Both are what tells a guest end from a shutdown the
/// launcher forced at the same number.
fn a_forced_end_is_not_a_guest_end() -> Result<(), String> {
    let mut problems: Vec<String> = Vec::new();
    for (case, path, expected) in [
        (
            "the guest's own 130",
            signal::ORDINARY_TEARDOWN,
            "never report a forced",
        ),
        (
            "the guest's own 143",
            signal::ORDINARY_TEARDOWN,
            "never report a forced",
        ),
        (
            "the receipt's forced path",
            signal::FORCED_TEARDOWN,
            "not the ordinary teardown",
        ),
    ] {
        let judged =
            signal::guest_end_problems(&signal::PTY.int_unhandled, 130, path, FORCED_TEXT, "INT");
        let judged_self = signal::guest_end_problems(
            &signal::PTY.self_term,
            143,
            path,
            FORCED_TEXT,
            "no host signal",
        );
        let named = judged
            .iter()
            .chain(judged_self.iter())
            .any(|problem| problem.contains(expected));
        if !named {
            problems.push(format!("a forced {case} was accepted"));
        }
    }
    if problems.is_empty() {
        return Ok(());
    }
    Err(problems.join("; "))
}

/// The status table is the oracle, not the launcher's habits: a handled row's 42
/// must not pass as 130, and a killed guest's 130 must not pass as 42.
fn a_status_off_the_table_fails() -> Result<(), String> {
    let handled = signal::guest_end_problems(
        &signal::PTY.int_handled,
        130,
        signal::ORDINARY_TEARDOWN,
        ORDINARY_TEXT,
        "INT",
    );
    let unhandled = signal::guest_end_problems(
        &signal::PTY.int_unhandled,
        42,
        signal::ORDINARY_TEARDOWN,
        ORDINARY_TEXT,
        "INT",
    );
    let ok = handled
        .iter()
        .any(|problem| problem.contains("requires 42"))
        && unhandled
            .iter()
            .any(|problem| problem.contains("requires 130"));
    if ok {
        return Ok(());
    }
    Err(format!("handled={handled:?} unhandled={unhandled:?}"))
}

/// A guest that ignores the signal is owed the whole grace; a second interrupt
/// must decide the end before it, or the status may be the first signal's.
fn the_grace_bound_decides_the_end() -> Result<(), String> {
    let mut problems: Vec<String> = Vec::new();
    let early = signal::grace_problems(&signal::PTY.int_ignored, Some(4.9));
    if !early
        .iter()
        .any(|problem| problem.contains("before its fixed 5s grace"))
    {
        problems.push(format!("an expiry before the grace passed: {early:?}"));
    }
    let late = signal::grace_problems(&signal::STREAM.term_second, Some(5.0));
    if !late
        .iter()
        .any(|problem| problem.contains("at or past the 5s grace"))
    {
        problems.push(format!(
            "a second interrupt after the grace passed: {late:?}"
        ));
    }
    // A row that needs a timing cannot pass without one, and a row that does not
    // need one gets no claim at all.
    for row in [&signal::PTY.int_ignored, &signal::PTY.term_second] {
        if signal::grace_problems(row, None).is_empty() {
            problems.push(format!("{} passed with no timing", row.behaviour.name()));
        }
    }
    for row in [
        &signal::PTY.int_handled,
        &signal::PTY.int_unhandled,
        &signal::PTY.self_term,
    ] {
        if !signal::grace_problems(row, None).is_empty() {
            problems.push(format!("{} claims a grace", row.behaviour.name()));
        }
    }
    if problems.is_empty() {
        return Ok(());
    }
    Err(problems.join("; "))
}

/// The 255 hint may only name the unknown-code reading where the number is really
/// 255: a 137 or a 130 says nothing about a runtime that dropped identity, and a
/// failure record must not assign a layer nobody observed.
fn the_identity_hint_is_only_offered_at_255() -> Result<(), String> {
    let row = &signal::PTY.int_unhandled;
    let mut problems: Vec<String> = Vec::new();
    for status in [130, 137, 143, 254] {
        if !signal::unhandled_hint(row, status).is_empty() {
            problems.push(format!("{status} claimed the runtime lost identity"));
        }
    }
    let hint = signal::unhandled_hint(row, 255);
    if !(hint.contains("255") && hint.contains("unknown code -1")) {
        problems.push(format!("a 255 lost its reading: {hint:?}"));
    }
    // A handled row has no identity question at all: its guest exited itself.
    if !signal::unhandled_hint(&signal::PTY.int_handled, 255).is_empty() {
        problems.push("a handled row offered the identity hint".to_owned());
    }
    if problems.is_empty() {
        return Ok(());
    }
    Err(problems.join("; "))
}

/// Both modes x both signals of the `unhandled` row, each at `128 + N`, so a
/// launcher that dropped identity for one signal or one mode cannot pass the
/// matrix with the other three.
fn the_unhandled_rows_cover_every_mode_and_signal() -> Result<(), String> {
    let unhandled: Vec<&signal::Row> = signal::all()
        .into_iter()
        .filter(|row| row.behaviour == signal::Behaviour::Unhandled)
        .collect();
    let mut modes: Vec<&str> = unhandled.iter().map(|row| row.mode.name()).collect();
    modes.sort_unstable();
    modes.dedup();
    let ok = unhandled.len() == 4
        && modes == ["pty", "stream"]
        // Each row's number is its *own* signal's: a `TERM` row that answered 130
        // would be a different fact, not a synonym, and a row that only had to fall
        // in {130, 143} would let one signal's bug certify the other's row.
        && unhandled.iter().all(|row| {
            row.signals.len() == 1
                && row.expect == 128 + row.signals[0]
                && row.ordinary_teardown
        });
    if ok {
        return Ok(());
    }
    Err(format!(
        "unhandled rows: {:?}",
        unhandled
            .iter()
            .map(|row| (row.mode.name(), row.signals, row.expect))
            .collect::<Vec<_>>()
    ))
}

/// A self-signalled guest exists in both modes and sends no host signal: its 143
/// can only come from its own reported identity.
fn a_self_signalled_guest_exists_in_both_modes() -> Result<(), String> {
    let self_rows: Vec<&signal::Row> = signal::all()
        .into_iter()
        .filter(|row| row.behaviour == signal::Behaviour::SelfSignal)
        .collect();
    let ok = self_rows.len() == 2
        && self_rows.iter().all(|row| {
            row.signals.is_empty()
                && row.expect == 128 + signal::TERM
                && row.ordinary_teardown
                && row.forced_notice.is_none()
        })
        && self_rows
            .iter()
            .filter(|row| row.mode == signal::Mode::Pty)
            .count()
            == 1
        && self_rows
            .iter()
            .filter(|row| row.mode == signal::Mode::Stream)
            .count()
            == 1;
    if ok {
        return Ok(());
    }
    Err(format!("self-signal rows: {}", self_rows.len()))
}

/// The grace and the wait are shipped numbers, not tuning knobs: a native row
/// asserts the real five seconds and the real two-minute bound.
fn the_shipped_signal_grace_and_wait_are_the_published_ones() -> Result<(), String> {
    let (grace, wait) = signal::shipped_numbers();
    if (grace, wait) == (5.0, 120.0) {
        return Ok(());
    }
    Err(format!("grace={grace} wait={wait}"))
}

/// Every signal row must run by default: the #467 pending gate is gone, and a gate
/// that came back would silently certify unwitnessed rows.
fn the_native_rows_have_no_pending_gate() -> Result<(), String> {
    let e2e = fs::read_to_string(fixture("script/test/e2e.sh"))
        .map_err(|error| format!("script/test/e2e.sh: {error}"))?;
    let gated = e2e.contains("pending_case_reason") || e2e.contains("AGENT_VM_E2E_INCLUDE_PENDING");
    let self_rows = e2e.contains("signal-pty-self-term signal-stream-self-term");
    if !gated && self_rows {
        return Ok(());
    }
    Err(format!("gated={gated} self_rows={self_rows}"))
}

// --- The case inventory -----------------------------------------------------

fn forcing(case: &Case) -> Vec<&'static str> {
    case.options
        .iter()
        .copied()
        .filter(|option| FORCE_OFF.contains(option) || FORCE_ON.contains(option))
        .collect()
}

fn guest_pty(case: &Case) -> Option<bool> {
    match case.expect {
        Expect::Identity { guest_pty, .. } => Some(guest_pty),
        _ => None,
    }
}

/// Guards on the *native case inventory*, not on any single run.
///
/// A native row proves only what its cases can distinguish. The force-off cases
/// were once written with stdout redirected to a file, which auto already
/// streams: `--no-tty` could have been ignored entirely and the row would still
/// have passed. Nothing in the harness itself noticed, because a passing row
/// looks identical either way. These controls make that class of silent
/// de-discrimination a red gate instead of a green native run.
fn every_streamed_case_with_two_terminals_forces_it() -> Result<(), String> {
    let weakeners: Vec<&str> = cases()
        .values()
        .filter(|case| guest_pty(case) == Some(false))
        .filter(|case| case.stdin == Channel::Tty && case.stdout == Channel::Tty)
        .filter(|case| {
            !forcing(case)
                .iter()
                .any(|option| FORCE_OFF.contains(option))
        })
        .map(|case| case.name)
        .collect();
    if weakeners.is_empty() {
        return Ok(());
    }
    Err(format!(
        "these cases would pass with the force-off option ignored: {weakeners:?}"
    ))
}

fn force_off_has_both_spellings_with_two_terminals() -> Result<(), String> {
    let both: Vec<&Case> = cases()
        .values()
        .filter(|case| case.stdin == Channel::Tty && case.stdout == Channel::Tty)
        .filter(|case| {
            forcing(case)
                .iter()
                .any(|option| FORCE_OFF.contains(option))
        })
        .copied()
        .collect();
    let spellings: Vec<&str> = both
        .iter()
        .flat_map(|case| forcing(case))
        .filter(|option| FORCE_OFF.contains(option))
        .collect();
    if both.len() >= 2 && FORCE_OFF.iter().all(|option| spellings.contains(option)) {
        return Ok(());
    }
    Err(format!(
        "cases={:?} spellings={spellings:?}",
        both.iter().map(|case| case.name).collect::<Vec<_>>()
    ))
}

fn force_on_has_a_redirected_stdout_case() -> Result<(), String> {
    let forced: Vec<&Case> = cases()
        .values()
        .filter(|case| forcing(case).iter().any(|option| FORCE_ON.contains(option)))
        .copied()
        .collect();
    let discriminating: Vec<&str> = forced
        .iter()
        .filter(|case| case.stdout == Channel::File && guest_pty(case) == Some(true))
        .map(|case| case.name)
        .collect();
    let spellings: Vec<&str> = forced
        .iter()
        .flat_map(|case| forcing(case))
        .filter(|option| FORCE_ON.contains(option))
        .collect();
    if !discriminating.is_empty() && spellings.contains(&"-t") {
        return Ok(());
    }
    Err(format!(
        "forced-pty cases={:?} discriminating={discriminating:?}",
        forced.iter().map(|case| case.name).collect::<Vec<_>>()
    ))
}

fn auto_has_both_halves() -> Result<(), String> {
    let table = cases();
    let auto = table.get("identity-auto").copied();
    let redirected = table.get("identity-redirected").copied();
    let ok = auto.is_some_and(|case| {
        guest_pty(case) == Some(true) && case.stdin == Channel::Tty && case.stdout == Channel::Tty
    }) && redirected.is_some_and(|case| {
        guest_pty(case) == Some(false)
            && case.stdin == Channel::Tty
            && case.stdout == Channel::File
            && case.options.is_empty()
    });
    if ok {
        return Ok(());
    }
    Err("the auto cases no longer discriminate a stdin-only predicate".to_owned())
}

/// Both direct boundaries are exercised for every non-legacy case, so a form
/// cannot silently stop covering `--`.
fn both_command_boundaries_stay_distinct() -> Result<(), String> {
    let boundaries: Vec<String> = [Form::Run, Form::Separator]
        .iter()
        .map(|form| {
            direct_terminal::launch_argv(Path::new("agent-vm"), &["-T"], *form, &["true"])[2]
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    if boundaries == ["run", "--"] {
        return Ok(());
    }
    Err(format!("boundaries={boundaries:?}"))
}

/// The ported and remaining rows must add up to the Python's own matrix, so no
/// port can shrink it and no group can be dropped by deleting a row.
fn the_rows_partition_the_inventory() -> Result<(), String> {
    let mut problems: Vec<String> = Vec::new();
    let mut total = 0;
    for (group, expected) in direct_terminal::EXPECTED_ROWS {
        let ported = cases().values().filter(|case| case.group == group).count();
        let remaining = group.remaining_rows().len();
        if ported + remaining != expected {
            problems.push(format!(
                "{:?}: {ported} ported + {remaining} remaining != {expected}",
                group.name()
            ));
        }
        if group.ported() != (remaining == 0) {
            problems.push(format!(
                "{:?}: the ported flag and the remaining rows disagree",
                group.name()
            ));
        }
        total += expected;
    }
    if total != 57 {
        problems.push(format!("the whole inventory is {total} rows, not 57"));
    }
    if problems.is_empty() {
        return Ok(());
    }
    Err(problems.join("; "))
}

/// The groups a boot-free control cannot certify, pinned.
///
/// A stand-in that exited 2, 127 or 255 on demand would prove that the driver
/// reads a status, not that the launcher refuses an argument combination before
/// booting, answers 126 rather than 127 for a program with no execute bit, or
/// reports its own sentinel 255 on a detach. Those rows are ported and runnable;
/// they are verified by the native e2e row, and the artifact names them. Pinning
/// the list keeps a successor from claiming one of them is proven boot-free — or
/// from leaving one silently unclaimed.
fn the_control_proven_groups_are_the_pinned_ones() -> Result<(), String> {
    const NATIVE_ONLY: [&str; 6] = [
        "program",
        "reject",
        "wait",
        "legacy-detach",
        "prompt",
        "signal",
    ];
    let native: Vec<&str> = direct_terminal::Group::ALL
        .iter()
        .filter(|group| !group.control_proven())
        .map(|group| group.name())
        .collect();
    if native == NATIVE_ONLY {
        return Ok(());
    }
    Err(format!(
        "the native-only groups are {native:?}, not {NATIVE_ONLY:?}"
    ))
}

/// Every prompt row must state a fact the oracle checks *beyond* the launcher's
/// status: a row that only compared a status would pass on a launcher that
/// prompted and granted nothing.
fn every_prompt_row_states_a_fact_beyond_its_status() -> Result<(), String> {
    let weak: Vec<&str> = cases()
        .values()
        .filter_map(|case| match case.expect {
            Expect::Prompt(row) => Some((case.name, row)),
            _ => None,
        })
        .filter(|(_, row)| {
            !(row.lines
                || row.retry_succeeds
                || row.access.is_some()
                || row.offer_project_only
                || row.result_says.is_some()
                || row.guard
                || row.answered_elsewhere
                || row.alt
                || row.stall
                || row.exit
                || row.forced
                || row.runtime_loss
                || row.off
                || row.probe_stdin)
        })
        .map(|(name, _)| name)
        .collect();
    if weak.is_empty() {
        return Ok(());
    }
    Err(format!("these prompt rows expect only a status: {weak:?}"))
}

/// AC9's three shapes each turn the prompt off in its own way, so a launcher that
/// only honoured one of them cannot pass all three.
fn the_three_off_shapes_stay_distinct() -> Result<(), String> {
    let table = cases();
    let off = |name: &str| -> Option<&'static Case> {
        table
            .get(name)
            .copied()
            .filter(|case| matches!(case.expect, Expect::Prompt(row) if row.off))
    };
    let env = off("prompt-off-env").is_some_and(|case| {
        case.env
            .iter()
            .any(|(key, value)| *key == "AGENT_VM_NO_ACCESS_PROMPT" && *value == "1")
    });
    let dumb = off("prompt-off-dumb").is_some_and(|case| {
        case.env
            .iter()
            .any(|(key, value)| *key == "TERM" && *value == "dumb")
    });
    let redirect = off("prompt-off-redirect")
        .is_some_and(|case| case.stdout == Channel::File && case.options.contains(&"-t"));
    if env && dumb && redirect {
        return Ok(());
    }
    Err(format!(
        "the prompt-off shapes changed: env={env} dumb={dumb} redirect={redirect}"
    ))
}

/// Both alternate-screen rows exist — the forced and the runtime-loss one — and
/// each runs the alt probe, so the DECRC half is exercised on a real takeover.
fn both_alternate_screen_rows_exist() -> Result<(), String> {
    let mut forced = false;
    let mut lost = false;
    for case in cases().values() {
        if let Expect::Prompt(row) = case.expect
            && row.alt
        {
            forced |= row.forced;
            lost |= row.runtime_loss;
            if (row.forced || row.runtime_loss) && !case.probe.contains(&"alt") {
                return Err(format!(
                    "{} runs the wrong probe: {:?}",
                    case.name, case.probe
                ));
            }
        }
    }
    if forced && lost {
        return Ok(());
    }
    Err(format!("alt rows: forced={forced} runtime_loss={lost}"))
}

// --- The driver -------------------------------------------------------------

type Control = (&'static str, fn() -> Result<(), String>);

/// Every control, named and separately reported. `only` narrows the run to the
/// controls whose name contains one of its strings, which is how the `cargo test`
/// names below run one group in a process of its own.
pub fn self_test(only: &[String]) -> Result<(), String> {
    let wanted =
        |name: &str| only.is_empty() || only.iter().any(|wanted| name.contains(wanted.as_str()));
    let inventory: [Control; 19] = [
        (
            "inventory/every streamed case with two host terminals forces it",
            every_streamed_case_with_two_terminals_forces_it,
        ),
        (
            "inventory/force-off has a two-terminal case for both spellings",
            force_off_has_both_spellings_with_two_terminals,
        ),
        (
            "inventory/force-on has a redirected-stdout case expecting a guest PTY",
            force_on_has_a_redirected_stdout_case,
        ),
        (
            "inventory/auto has both-terminal (PTY) and redirected-stdout (stream) cases",
            auto_has_both_halves,
        ),
        (
            "inventory/both command boundaries stay distinct",
            both_command_boundaries_stay_distinct,
        ),
        (
            "inventory/the ported and remaining rows partition the inventory",
            the_rows_partition_the_inventory,
        ),
        (
            "inventory/only the pinned groups are native-only",
            the_control_proven_groups_are_the_pinned_ones,
        ),
        (
            "inventory/every prompt row states a fact beyond its status",
            every_prompt_row_states_a_fact_beyond_its_status,
        ),
        (
            "inventory/the three prompt-off shapes stay distinct",
            the_three_off_shapes_stay_distinct,
        ),
        (
            "inventory/both alternate-screen prompt rows exist",
            both_alternate_screen_rows_exist,
        ),
        (
            "inventory/the guest-signal rows cover every mode and signal",
            the_unhandled_rows_cover_every_mode_and_signal,
        ),
        (
            "inventory/a self-signalled guest exists in both modes and sends no host signal",
            a_self_signalled_guest_exists_in_both_modes,
        ),
        (
            "inventory/the shipped signal grace and wait are the published numbers",
            the_shipped_signal_grace_and_wait_are_the_published_ones,
        ),
        (
            "inventory/the native signal rows have no pending gate",
            the_native_rows_have_no_pending_gate,
        ),
        // The shared #401 oracle, exercised against fabricated records. These are
        // harness controls, never native evidence: the rows themselves need a real
        // launcher and a runtime this host does not have in this job.
        (
            "accept/an ordinary guest end is accepted by the shared oracle",
            the_shared_oracle_accepts_an_ordinary_guest_end,
        ),
        (
            "reject/a forced end is never a guest-signal end",
            a_forced_end_is_not_a_guest_end,
        ),
        (
            "reject/a status off the published table fails",
            a_status_off_the_table_fails,
        ),
        (
            "reject/an ignored guest that ended before its grace fails",
            the_grace_bound_decides_the_end,
        ),
        (
            "reject/a non-255 status never claims the runtime lost identity",
            the_identity_hint_is_only_offered_at_255,
        ),
    ];
    let mut ran = false;
    for control in &DRIVER_CONTROLS {
        if !wanted(control.name) {
            continue;
        }
        run_driver_control(control)?;
        println!("ok: {}", control.name);
        ran = true;
    }
    for (name, control) in inventory {
        if !wanted(name) {
            continue;
        }
        control()?;
        println!("ok: {name}");
        ran = true;
    }
    if !ran {
        return Err(format!("usage: --only {only:?} matches no control"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(names: &[&str]) {
        let only: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
        self_test(&only).expect("the control passes");
    }

    #[test]
    fn a_correct_standin_passes_and_the_ported_never_eof_control_is_absent() {
        // `stream-no-eof` is deliberately absent from the driver controls: a
        // stand-in cannot reproduce "the guest keeps waiting for an EOF that never
        // comes" without also faking the launcher's own input lifetime, and a
        // control that cannot fail proves nothing. That property is left to the
        // Rust session tests and the native row, and is not claimed here.
        run(&[
            "accept/identity with both descriptors terminal",
            "accept/suffix tokens are guest argv",
        ]);
    }

    #[test]
    fn the_exact_byte_and_channel_oracles_bite() {
        run(&[
            "accept/raw input A 1d B reaches the guest, code 7",
            "reject/a mangled escape byte changes the guest's hex",
            "accept/streamed terminal stdin, exact bytes and code 23",
            "reject/a truncated streamed payload fails the checksum",
        ]);
    }

    #[test]
    fn the_resize_handshake_and_the_restoration_check_bite() {
        run(&[
            "accept/resize the host geometry then 43x119, code 7",
            "reject/a missed resize notification fails",
            "reject/an early exit before readiness fails",
            "reject/a terminal left raw fails the restoration check",
        ]);
    }

    #[test]
    fn the_case_table_stays_discriminating() {
        run(&[
            "inventory/every streamed case with two host terminals forces it",
            "inventory/force-off has a two-terminal case for both spellings",
            "inventory/force-on has a redirected-stdout case expecting a guest PTY",
            "inventory/auto has both-terminal (PTY) and redirected-stdout (stream) cases",
            "inventory/both command boundaries stay distinct",
            "inventory/the ported and remaining rows partition the inventory",
            "inventory/only the pinned groups are native-only",
            "inventory/every prompt row states a fact beyond its status",
            "inventory/the three prompt-off shapes stay distinct",
            "inventory/both alternate-screen prompt rows exist",
            "inventory/the guest-signal rows cover every mode and signal",
            "inventory/a self-signalled guest exists in both modes and sends no host signal",
            "inventory/the shipped signal grace and wait are the published numbers",
            "inventory/the native signal rows have no pending gate",
        ]);
    }

    #[test]
    fn the_signal_oracle_rejects_forced_ends_timings_and_wrong_statuses() {
        // The shared #401 oracle, as the driver and the controls both call it.
        run(&[
            "accept/an ordinary guest end is accepted by the shared oracle",
            "reject/a forced end is never a guest-signal end",
            "reject/a status off the published table fails",
            "reject/an ignored guest that ended before its grace fails",
            "reject/a non-255 status never claims the runtime lost identity",
        ]);
    }

    #[test]
    fn the_prompt_oracle_accepts_a_correct_takeover_and_rejects_broken_ones() {
        run(&[
            "accept/a correct prompt, answered with d",
            "accept/the launcher's answer cadence, answered once",
            "reject/a takeover that leaves the guest's modes unapplied fails",
            "reject/a withheld held line fails the ordering oracle",
            "reject/a frame written after the leave fails",
        ]);
    }

    #[test]
    fn the_native_only_oracles_bite_without_a_launcher() {
        // These three rows' subjects need a real launcher, so no control certifies
        // the row itself. What is proven here is that the driver's oracle for each
        // rejects a launcher that answers the wrong thing.
        run(&[
            "reject/a launcher that ignores the refusal shape fails the status oracle",
            "reject/a launcher's own failure status is not a missing program's 127",
            "reject/a runtime the catalog does not name is never signalled",
        ]);
    }

    #[test]
    fn an_unknown_control_name_is_misuse() {
        let refused = self_test(&["no such control".to_owned()])
            .expect_err("an unmatched --only must not read as a pass");
        assert!(refused.contains("matches no control"), "{refused}");
    }

    #[test]
    fn the_group_the_rows_speak_for_is_the_ported_one() {
        let ported: Vec<&str> = direct_terminal::Group::ALL
            .iter()
            .filter(|group| group.ported())
            .map(|group| group.name())
            .collect();
        assert_eq!(
            ported,
            [
                "identity",
                "input",
                "resize",
                "stream-input",
                "argv",
                "status",
                "program",
                "reject",
                "wait",
                "legacy-detach",
                "prompt",
                "signal"
            ]
        );
    }
}
