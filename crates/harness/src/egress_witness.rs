//! The two live witnesses: RF1's refusal feed and PA2's live allowance change
//! (#692, ADR-0064/ADR-0066).
//!
//! Both are claims about a *running* sandbox, so both are made by a thread that
//! watches the guest's launch log while the launch runs and by separate
//! `agent-vm access` processes in the launch's own environment — an in-process
//! call would prove nothing about the CLI reaching a live launcher.
//!
//! Two vocabularies tie the halves together, and both are spelled here so a
//! rename on one side alone is a compile error or a named failure rather than a
//! half that waits for its full bound:
//!
//! * markers, guest -> host: lines in the launch log (`PA2_MARKERS`);
//! * signals, host -> guest: files in the project directory (`PA2_SIGNALS`,
//!   in the allowance module, the one host path mounted into the guest).
//!
//! Every wait here is bounded and every bound is checked against the witness's
//! own `stop` flag: a witness that cannot see its marker must cost the case one
//! named failure, never the harness's deadline.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    egress_allowances::{
        PA2_SIGNALS, allowance_lock, allowance_present, allowance_store, cleanup_pa2,
    },
    egress_cases::Command,
    egress_fixtures::{monotonic_nanos, signal_identity},
    egress_launch::{Observed, within},
    released_image_launch::exit_code,
};

/// The fixture port the PA2 guest probes, as in `egress-probe.sh`.
pub const PA2_PROBE_PORT: u16 = 18080;
/// The guest's four markers, in order: refused, allowed, refused again, done.
pub const PA2_MARKERS: [&str; 4] = [
    "PA2 PROBE 1 DENIED",
    "PA2 PROBE 2 OK",
    "PA2 PROBE 3 DENIED",
    "PA2 DONE",
];
/// The same bound as `PA2_WAIT:-120` in the probe script: one number for both
/// halves, so a stuck half fails the case instead of the harness deadline.
pub const PA2_WAIT_SECONDS: u64 = 120;
/// ADR-0064's hint, which the launch log must carry exactly once.
pub const RF1_HINT: &str = "==> The sandbox refused a guest network request; run `agent-vm access` \
to see refusals (shown once per session)";

/// What a witness needs from its launch. Owned rather than borrowed so the
/// thread can outlive the borrow that started it, and shared only where the
/// launch itself reads the value: the launcher identity (kill9) and the error
/// list the launch reports.
pub(crate) struct LiveWitness {
    pub work: PathBuf,
    pub command: Command,
    pub log: PathBuf,
    pub sessions: PathBuf,
    pub stop: Arc<AtomicBool>,
    pub observed: Arc<Mutex<Observed>>,
}

impl LiveWitness {
    fn error(&self, error: String) {
        let mut observed = self.observed.lock().expect("the observation lock");
        if !observed.errors.contains(&error) {
            observed.errors.push(error);
        }
    }

    fn text(&self) -> String {
        fs::read(&self.log)
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default()
    }

    /// Sleep in slices so the stop flag is seen within 100 ms.
    fn pause(&self, total: Duration) -> bool {
        let until = Instant::now() + total;
        while Instant::now() < until {
            if self.stop.load(Ordering::SeqCst) {
                return false;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        !self.stop.load(Ordering::SeqCst)
    }

    /// The one live session socket this launch reserved.
    fn session_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = fs::read_dir(&self.sessions)
            .map(|entries| {
                entries
                    .filter_map(|entry| entry.ok())
                    .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "sock"))
                    .filter_map(|entry| {
                        entry
                            .path()
                            .file_stem()
                            .map(|stem| stem.to_string_lossy().into_owned())
                    })
                    .collect()
            })
            .unwrap_or_default();
        ids.sort();
        ids
    }

    /// ADR-0064 RF1: ask the host what the *live* session refused.
    ///
    /// The session id is the one socket this launch reserved, so `--session`
    /// names exactly the session under test and not the other cases' sessions
    /// the shared log has accumulated.
    pub(crate) fn refusal_feed_while_running(&self) {
        let deadline = Instant::now() + Duration::from_secs(120);
        let mut ready = false;
        while Instant::now() < deadline && !self.stop.load(Ordering::SeqCst) {
            if self.text().lines().any(|line| line == "RF1 READY") {
                ready = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if !ready {
            self.error("RF1 READY never appeared".to_owned());
            return;
        }
        let socket_ids = self.session_ids();
        if socket_ids.len() != 1 {
            self.error(format!(
                "expected one live session socket, saw {socket_ids:?}"
            ));
            return;
        }
        let session = &socket_ids[0];
        let session_file = self.work.join("RF1-session.txt");
        if let Err(error) = fs::write(&session_file, session) {
            self.error(format!("{}: {error}", session_file.display()));
            return;
        }
        // AC3 allows the record to trail the refusal by up to 2 s of ingestion
        // plus 2 s of persistence, so the host asks until it answers: the case is
        // about *whether* a live session shows its refusals, not about the first
        // instant it could.
        let mut status = 1;
        let mut output = String::new();
        let mut waited = 0.0f64;
        while waited < 20.0 {
            match refusal_feed_query(&self.command, session, Duration::from_secs(30)) {
                Ok((queried, text)) => {
                    status = queried;
                    output = text;
                }
                Err(error) => {
                    self.error(format!("live access failed: {error}"));
                    return;
                }
            }
            if !refusal_feed_rows(&output).is_empty() {
                break;
            }
            if !self.pause(Duration::from_millis(500)) {
                break;
            }
            waited += 0.5;
        }
        let live = self.work.join("RF1-live.txt");
        if let Err(error) = fs::write(&live, format!("status={status}\n{output}")) {
            self.error(format!("{}: {error}", live.display()));
        }
        if self.command.variant != "kill9" {
            return;
        }
        // The unclean end: kill the launcher while the guest is mid-sleep, so
        // nothing writes `ended` and only the log speaks for the session. The log
        // is waited for too, or the case would prove that a killed launcher loses
        // whatever it had not written.
        let log_path = self.sessions.join("refusals.json");
        while Instant::now() < deadline && !self.stop.load(Ordering::SeqCst) {
            let persisted = fs::read(&log_path)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                .and_then(|record| {
                    let sessions = record.get("sessions")?.as_array()?;
                    let row = sessions.iter().find(|row| {
                        row.get("info")
                            .and_then(|info| info.get("id"))
                            .and_then(Value::as_str)
                            == Some(session.as_str())
                    })?;
                    Some(
                        row.get("entries")
                            .and_then(Value::as_array)
                            .is_some_and(|entries| !entries.is_empty()),
                    )
                });
            if persisted == Some(true) {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        let mut launcher = None;
        while launcher.is_none() && Instant::now() < deadline {
            launcher = self
                .observed
                .lock()
                .expect("the observation lock")
                .launcher
                .clone();
            if launcher.is_none() {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        if let Some(launcher) = launcher
            && let Err(error) = signal_identity(&launcher, libc::SIGKILL)
        {
            self.error(format!("live allowance kill failed: {error}"));
        }
    }

    /// Wait for one guest marker, bounded by `PA2_WAIT_SECONDS`.
    fn pa2_wait_marker(&self, marker: &str) -> bool {
        let deadline = Instant::now() + Duration::from_secs(PA2_WAIT_SECONDS);
        while Instant::now() < deadline {
            if self.stop.load(Ordering::SeqCst) {
                return false;
            }
            if self.text().lines().any(|line| line == marker) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }

    fn pa2_access(&self, argv: &[&str], timeout: Duration) -> Result<(i32, String), String> {
        let mut full = vec![self.command.argv.first().cloned().unwrap_or_default()];
        full.extend(argv.iter().map(|argument| (*argument).to_owned()));
        capture(
            &self.work,
            &full,
            &self.command.env,
            &self.command.cwd,
            timeout,
        )
    }

    /// The running row for this session's refused probe, once it exists.
    ///
    /// The launch log and the persisted feed are separate: the refusal the guest
    /// just caused is visible only after ingestion and persistence, which AC3
    /// allows seconds for.
    fn pa2_rows(&self, session: &str) -> BTreeMap<String, String> {
        let deadline = Instant::now() + Duration::from_secs(PA2_WAIT_SECONDS);
        loop {
            let rows = match self.pa2_access(
                &["access", "--all", "--session", session],
                Duration::from_secs(60),
            ) {
                Ok((_, output)) => refusal_feed_rows(&output),
                Err(error) => {
                    self.error(format!("live access failed: {error}"));
                    BTreeMap::new()
                }
            };
            // The label, not the padding: the table pads to its widest cell, and
            // the row for an answered session is the one that says `running`.
            let running: BTreeMap<String, String> = rows
                .into_iter()
                .filter(|(_, line)| {
                    line.contains(&format!(":{PA2_PROBE_PORT}")) && has_word(line, "running")
                })
                .collect();
            if !running.is_empty() || Instant::now() >= deadline {
                return running;
            }
            if !self.pause(Duration::from_millis(250)) {
                return BTreeMap::new();
            }
        }
    }

    /// ADR-0066 PA2: one live grant and one live revoke, driven from the host.
    ///
    /// The guest's three probes are the evidence that a policy change reached the
    /// sandbox without a restart; everything here is what a user does with
    /// `agent-vm access` while it runs. Each signal file is written whether its
    /// step succeeded or not — a failure must reach the guest as a failed probe
    /// rather than as a stuck harness — and the evidence file is always written,
    /// so `check_live_allowance` can report why.
    pub(crate) fn live_allowance_while_running(&self) {
        let mut evidence = json!({
            "refusal_id": "",
            "session": "",
            "destination": "",
            "steps": [],
            "failures": [],
            "store": "",
        });
        let project = self.work.join("proj");
        let granted = project.join(PA2_SIGNALS[0]);
        let revoked = project.join(PA2_SIGNALS[1]);
        let mut failures: Vec<String> = Vec::new();
        self.witness_allowance(&mut evidence, &mut failures);
        // Always release the guest, in order: a failure above must cost one
        // failed probe, never the harness's deadline.
        for signal in [&granted, &revoked] {
            if let Err(error) = fs::write(signal, b"") {
                failures.push(format!("{}: {error}", signal.display()));
            }
        }
        if let Some(list) = evidence.get_mut("failures").and_then(Value::as_array_mut) {
            *list = failures
                .iter()
                .map(|failure| Value::String(failure.clone()))
                .collect();
        }
        let path = self.work.join("PA2-witness.json");
        match serde_json::to_vec_pretty(&evidence) {
            Ok(bytes) => {
                if let Err(error) = fs::write(&path, bytes) {
                    self.error(format!("{}: {error}", path.display()));
                }
            }
            Err(error) => self.error(format!("{}: {error}", path.display())),
        }
    }

    fn witness_allowance(&self, evidence: &mut Value, failures: &mut Vec<String>) {
        for signal in PA2_SIGNALS {
            let path = self.work.join("proj").join(signal);
            if let Err(error) = fs::remove_file(&path)
                && error.kind() != std::io::ErrorKind::NotFound
            {
                failures.push(format!("{}: {error}", path.display()));
            }
        }
        if !self.pa2_wait_marker(PA2_MARKERS[0]) {
            failures.push("the guest never reported its first refused probe".to_owned());
            return;
        }
        let socket_ids = self.session_ids();
        if socket_ids.len() != 1 {
            failures.push(format!(
                "expected one live session socket, saw {socket_ids:?}"
            ));
            return;
        }
        let session = socket_ids[0].clone();
        evidence["session"] = Value::String(session.clone());
        let rows = self.pa2_rows(&session);
        if rows.len() != 1 {
            failures.push(format!(
                "expected one running row for the refused probe, saw {:?}",
                rows.keys().collect::<Vec<&String>>()
            ));
            return;
        }
        let refusal_id = rows.keys().next().cloned().unwrap_or_default();
        evidence["refusal_id"] = Value::String(refusal_id.clone());
        let (status, output) = match self.pa2_access(
            &["access", "allow", &refusal_id, "--project"],
            Duration::from_secs(60),
        ) {
            Ok(answer) => answer,
            Err(error) => {
                failures.push(format!("the live allowance witness failed: {error}"));
                return;
            }
        };
        record_step(evidence, "allow", status, &output);
        match allowed_application(&output) {
            Some((destination, revision)) if status == 0 => {
                evidence["destination"] = Value::String(destination.to_owned());
                evidence["grant_revision"] = json!(revision);
                let store = allowance_store(&self.work);
                evidence["store"] = Value::String(fs::read_to_string(&store).unwrap_or_default());
            }
            _ => failures.push(format!(
                "the live project grant was not applied: exit {status}: {output:?}"
            )),
        }
        let granted = self.work.join("proj").join(PA2_SIGNALS[0]);
        if let Err(error) = fs::write(&granted, b"") {
            failures.push(format!("{}: {error}", granted.display()));
        }
        if !self.pa2_wait_marker(PA2_MARKERS[1]) {
            failures.push("the guest's second probe was never reported allowed".to_owned());
            return;
        }
        let destination = evidence
            .get("destination")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        if destination.is_empty() {
            return;
        }
        for (step, argv) in [
            (
                "table",
                vec!["access", "--all", "--session", session.as_str()],
            ),
            (
                "allowances",
                vec!["access", "allowances", "--session", session.as_str()],
            ),
        ] {
            let (status, output) = match self.pa2_access(&argv, Duration::from_secs(60)) {
                Ok(answer) => answer,
                Err(error) => {
                    failures.push(format!("the live allowance witness failed: {error}"));
                    return;
                }
            };
            record_step(evidence, step, status, &output);
            let expected = if step == "table" {
                "applied project allowance"
            } else {
                "applied (rev"
            };
            if status != 0 || !output.contains(expected) || !output.contains("(rev 2)") {
                failures.push(format!(
                    "{step} does not report the applied grant at rev 2: exit {status}: {output:?}"
                ));
            }
        }
        let (status, output) =
            match self.pa2_access(&["access", "revoke", &destination], Duration::from_secs(60)) {
                Ok(answer) => answer,
                Err(error) => {
                    failures.push(format!("the live allowance witness failed: {error}"));
                    return;
                }
            };
        record_step(evidence, "revoke", status, &output);
        match revoked_application(&output) {
            Some(revision) if status == 0 => {
                evidence["revoke_revision"] = json!(revision);
                let store = allowance_store(&self.work);
                evidence["store_after_revoke"] =
                    Value::String(fs::read_to_string(&store).unwrap_or_default());
            }
            _ => failures.push(format!(
                "the live revoke was not applied: exit {status}: {output:?}"
            )),
        }
    }
}

/// One witness step, in the order it ran: the verdict joins the step names.
fn record_step(evidence: &mut Value, step: &str, status: i32, output: &str) {
    if let Some(steps) = evidence.get_mut("steps").and_then(Value::as_array_mut) {
        steps.push(json!({"step": step, "status": status, "output": output}));
    }
}

/// `allowed <destination> for … (policy revision N) and recorded for this project`.
///
/// Ported as a line scan rather than a regex because the harness carries no
/// regex engine; the shape asserted is the Python's, in the same order.
pub fn allowed_application(line: &str) -> Option<(&str, u64)> {
    let rest = line.strip_prefix("allowed ")?;
    let (destination, tail) = rest.split_once(' ')?;
    if destination.is_empty() {
        return None;
    }
    let (_, tail) = tail.split_once("(policy revision ")?;
    let (revision, tail) = tail.split_once(')')?;
    if !tail.starts_with(" and recorded for this project") {
        return None;
    }
    Some((destination, revision.parse().ok()?))
}

/// `revoked <destination> for … (policy revision N); the project record was deleted`.
pub fn revoked_application(line: &str) -> Option<u64> {
    let rest = line.strip_prefix("revoked ")?;
    let (destination, tail) = rest.split_once(' ')?;
    if destination.is_empty() {
        return None;
    }
    let (_, tail) = tail.split_once("(policy revision ")?;
    let (revision, tail) = tail.split_once(')')?;
    if !tail.starts_with("; the project record was deleted") {
        return None;
    }
    revision.parse().ok()
}

/// Whether `word` appears in `text` as a whole word, `\b` as Python spelled it.
fn has_word(text: &str, word: &str) -> bool {
    let boundary = |character: char| !(character.is_ascii_alphanumeric() || character == '_');
    let mut from = 0;
    while let Some(index) = text[from..].find(word) {
        let start = from + index;
        let end = start + word.len();
        let before_ok = text[..start].chars().next_back().is_none_or(boundary);
        let after_ok = text[end..].chars().next().is_none_or(boundary);
        if before_ok && after_ok {
            return true;
        }
        from = start + 1;
    }
    false
}

/// One `agent-vm access …` in the launch's own project and environment.
///
/// A separate process, exactly as a user runs it: the case's claim is about the
/// CLI reaching a *running* launcher, so an in-process call would prove nothing.
/// The environment is *replaced*, as the Python's `env=` did.
pub fn refusal_feed_query(
    command: &Command,
    session: &str,
    timeout: Duration,
) -> Result<(i32, String), String> {
    let mut argv = vec![
        command.argv.first().cloned().unwrap_or_default(),
        "access".to_owned(),
        "--all".to_owned(),
    ];
    if !session.is_empty() {
        argv.push("--session".to_owned());
        argv.push(session.to_owned());
    }
    capture(
        Path::new(&command.cwd).parent().unwrap_or(Path::new("/")),
        &argv,
        &command.env,
        &command.cwd,
        timeout,
    )
}

/// Run one command with its output captured into a scratch file, bounded in
/// wall time. The file, not a pipe, is what keeps a chatty child from blocking
/// on a full pipe while this thread waits for it.
fn capture(
    directory: &Path,
    argv: &[String],
    env: &[(String, String)],
    cwd: &str,
    timeout: Duration,
) -> Result<(i32, String), String> {
    let Some(program) = argv.first() else {
        return Err("capture: empty argv".to_owned());
    };
    let log = directory.join(format!("access-{}.log", monotonic_nanos()));
    let handle = fs::File::create(&log).map_err(|error| format!("{}: {error}", log.display()))?;
    let mut child = std::process::Command::new(program)
        .args(&argv[1..])
        .env_clear()
        .envs(env.iter().map(|(name, value)| (name, value)))
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::from(
            handle.try_clone().map_err(|error| error.to_string())?,
        ))
        .stderr(Stdio::from(handle))
        .spawn()
        .map_err(|error| format!("{program}: {error}"))?;
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break exit_code(status),
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "{program}: no answer within {}s",
                    timeout.as_secs()
                ));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => return Err(format!("{program}: {error}")),
        }
    };
    let text = fs::read(&log)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default();
    Ok((status, text))
}

/// Parse the `access` table: id -> its whole line.
///
/// A row starts with the 8-hex ID; the header and the footers do not.
pub fn refusal_feed_rows(text: &str) -> BTreeMap<String, String> {
    let mut rows = BTreeMap::new();
    for line in text.lines() {
        let Some((id, rest)) = line.split_at_checked(8) else {
            continue;
        };
        let hex = id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if hex && rest.starts_with(' ') {
            rows.insert(id.to_owned(), line.to_owned());
        }
    }
    rows
}

/// ADR-0064 RF1, for the one session this launch reserved.
///
/// The project's log also holds every earlier case's session, so the verdict is
/// scoped by `--session`: a row from another case says nothing about this one.
pub fn check_refusal_feed(
    command: &Command,
    status: i32,
    text: &str,
    live_status: i32,
    live_text: &str,
    after_status: i32,
    after_text: &str,
) -> Vec<String> {
    let mut failures = Vec::new();
    let hints = text.lines().filter(|line| *line == RF1_HINT).count();
    if hints != 1 {
        failures.push(format!("the hint must appear exactly once, saw {hints}"));
    }
    if live_status != 0 || after_status != 0 {
        failures.push(format!("access exited {live_status}/{after_status}"));
    }
    let live_rows = refusal_feed_rows(live_text);
    let after_rows = refusal_feed_rows(after_text);
    // The two destinations the guest tried, by the evidence the row carries.
    for needle in ["203.0.113.10:443", "blocked.example"] {
        if !live_rows.values().any(|line| line.contains(needle)) {
            failures.push(format!("live table has no row for {needle}: {live_text:?}"));
        }
        if !after_rows.values().any(|line| line.contains(needle)) {
            failures.push(format!(
                "log has no row for {needle} after the session: {after_text:?}"
            ));
        }
    }
    for line in live_rows.values() {
        if command.variant != "kill9" && !has_word(line, "running") {
            failures.push(format!("live row is not running: {line:?}"));
        }
    }
    let label = if command.variant == "kill9" {
        "ended (unclean)"
    } else {
        "ended"
    };
    for line in after_rows.values() {
        if !line.contains(label) {
            failures.push(format!("row must read {label}: {line:?}"));
        }
    }
    // The *same* entries, not merely as many: an ID is assigned once, stored in
    // the log and never recomputed (AC2), so a rewritten ID between the live view
    // and the log would be a bug a count alone would miss.
    if live_rows.keys().ne(after_rows.keys()) {
        failures.push(format!(
            "the same IDs must survive the session: {:?} live, {:?} logged",
            live_rows.keys().collect::<Vec<&String>>(),
            after_rows.keys().collect::<Vec<&String>>()
        ));
    }
    let expected = if command.variant == "kill9" {
        -libc::SIGKILL
    } else {
        0
    };
    if status != expected {
        failures.push(format!("launch status {status}, expected {expected}"));
    }
    failures
}

/// ADR-0066 PA2: the whole live change, joined from the host's records.
///
/// The guest's three probes and the host's four commands are one claim — a
/// policy change reached a *running* sandbox in both directions — so the verdict
/// joins them: the guest's markers, the witness's steps and revisions, the store
/// the grant wrote and the revoke emptied, and the fixture's receipts (the
/// allowed probe reached it; the refused ones never did).
pub fn check_live_allowance(work: &Path, ident: &str, text: &str) -> Vec<String> {
    let mut failures = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    for marker in PA2_MARKERS {
        if !lines.contains(&marker) {
            failures.push(format!("guest marker missing: {marker}"));
        }
    }
    for line in &lines {
        if line.starts_with("PA2 ") && !PA2_MARKERS.contains(line) {
            failures.push(format!("guest reported: {line}"));
        }
    }
    let evidence = match fs::read(work.join("PA2-witness.json"))
        .map_err(|error| error.to_string())
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).map_err(|e| e.to_string()))
    {
        Ok(evidence) => evidence,
        Err(error) => {
            failures.push(format!(
                "the live allowance witness left no evidence: {error}"
            ));
            return failures;
        }
    };
    if let Some(list) = evidence.get("failures").and_then(Value::as_array) {
        failures.extend(
            list.iter()
                .map(|row| row.as_str().unwrap_or_default().to_owned())
                .filter(|row| !row.is_empty()),
        );
    }
    let steps: Vec<&str> = evidence
        .get("steps")
        .and_then(Value::as_array)
        .map(|steps| {
            steps
                .iter()
                .filter_map(|step| step.get("step").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default();
    let mut sorted = steps.clone();
    sorted.sort_unstable();
    if sorted != ["allow", "allowances", "revoke", "table"] {
        failures.push(format!("the witness did not run every step: {sorted:?}"));
    }
    if evidence.get("grant_revision").and_then(Value::as_u64) != Some(2) {
        failures.push(format!(
            "the grant did not report revision 2: {}",
            evidence
                .get("grant_revision")
                .cloned()
                .unwrap_or(Value::Null)
        ));
    }
    if evidence.get("revoke_revision").and_then(Value::as_u64) != Some(3) {
        failures.push(format!(
            "the revoke did not report revision 3: {}",
            evidence
                .get("revoke_revision")
                .cloned()
                .unwrap_or(Value::Null)
        ));
    }
    let destination = evidence
        .get("destination")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if destination.is_empty() {
        failures.push("the witness recorded no applied destination".to_owned());
    }
    let recorded: Vec<Value> = evidence
        .get("store")
        .and_then(Value::as_str)
        .and_then(|store| serde_json::from_str::<Value>(store).ok())
        .and_then(|store| store.get("records").and_then(Value::as_array).cloned())
        .unwrap_or_default();
    if recorded.len() != 1
        || recorded[0].get("destination").and_then(Value::as_str) != Some(destination)
    {
        failures.push(format!("the grant recorded something else: {recorded:?}"));
    }
    let after: Vec<Value> = evidence
        .get("store_after_revoke")
        .and_then(Value::as_str)
        .and_then(|store| serde_json::from_str::<Value>(store).ok())
        .and_then(|store| store.get("records").and_then(Value::as_array).cloned())
        .unwrap_or_default();
    if after
        .iter()
        .any(|row| row.get("destination").and_then(Value::as_str) == Some(destination))
    {
        failures.push("the revoke left the project record behind".to_owned());
    }
    let receipts = receipt_lines(work);
    if !receipts
        .iter()
        .any(|line| line.split_whitespace().last() == Some(format!("{ident}-p2").as_str()))
    {
        failures.push("the allowed probe left no fixture receipt".to_owned());
    }
    for probe in ["p1", "p3"] {
        if receipts
            .iter()
            .any(|line| line.split_whitespace().last() == Some(format!("{ident}-{probe}").as_str()))
        {
            failures.push(format!("refused probe {probe} reached the fixture"));
        }
    }
    failures
}

/// The fixture's recorded receipt lines, empty when nothing has answered yet.
pub fn receipt_lines(work: &Path) -> Vec<String> {
    let path = work.join("fx").join(crate::egress_fixtures::RECEIPTS_NAME);
    fs::read(&path)
        .map(|bytes| {
            String::from_utf8_lossy(&bytes)
                .lines()
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Everything PA2 must do before it launches, in one testable place.
///
/// PA2 is the case that must start where a fresh host starts: with no record (a
/// record would be a seed it never wrote, and would make the first,
/// supposed-to-be-refused probe pass) and with no signal files (a stale one would
/// make a failed host command look like a completed step, since the guest would
/// stop waiting at once). A leftover is reported before it is removed, exactly as
/// `prepare_allowance` does, because a leak is evidence about an earlier case.
pub fn prepare_live_allowance(work: &Path, case: &str) -> Vec<String> {
    if case != "PA2" {
        return vec![format!("{case} is not the live-allowance case")];
    }
    let mut failures = Vec::new();
    if allowance_present(work) || allowance_lock(work).exists() {
        failures.push(
            "a project allowance store was left from an earlier case; \
             removing it before this case's launch"
                .to_owned(),
        );
        failures.extend(cleanup_pa2(work));
    }
    for name in PA2_SIGNALS {
        let path = work.join("proj").join(name);
        let removed = (|| -> Result<(), String> {
            inside(&path, work)?;
            if path
                .symlink_metadata()
                .is_ok_and(|metadata| metadata.file_type().is_symlink())
            {
                return Err(format!("live-allowance signal {name} is a symlink"));
            }
            match fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(format!("{}: {error}", path.display())),
            }
        })();
        if let Err(error) = removed {
            failures.push(format!(
                "the live-allowance signal remains: {name}: {error}"
            ));
        }
    }
    failures
}

/// `within` for a path that need not exist: an absent file resolves through its
/// parent, so "nothing is there" is not reported as "outside the work
/// directory". A symlink is *not* resolved here; each caller asks about links
/// separately, because a dangling one must read as a link, not as absence.
pub(crate) fn inside(path: &Path, work: &Path) -> Result<PathBuf, String> {
    if let Ok(resolved) = within(path, work) {
        return Ok(resolved);
    }
    let mut missing: Vec<std::ffi::OsString> = Vec::new();
    let mut current = path.to_path_buf();
    while !current.exists() {
        let name = current
            .file_name()
            .ok_or_else(|| format!("{}: no existing ancestor", path.display()))?;
        missing.push(name.to_owned());
        let parent = current
            .parent()
            .ok_or_else(|| format!("{}: no existing ancestor", path.display()))?;
        current = parent.to_path_buf();
    }
    let mut resolved = within(&current, work)?;
    for name in missing.iter().rev() {
        resolved.push(name);
    }
    Ok(resolved)
}

/// A record of every file under the private roots, so a validation-only
/// invocation can be shown to have mutated nothing.
///
/// SQLite rewrites the WAL shared-memory/index sidecars whenever a connection
/// attaches, including this harness's own read-only catalog observation, so
/// hashing them is not evidence that a validation-only invocation created launch
/// state and they are skipped by name.
pub fn snapshot_validation(work: &Path) -> Result<BTreeMap<String, (u32, u64, String)>, String> {
    let mut snapshot = BTreeMap::new();
    for directory in ["home", "config", "state", "proj"] {
        let root = work.join(directory);
        let mut paths = Vec::new();
        collect(&root, &mut paths)?;
        for path in paths {
            let name = path
                .strip_prefix(work)
                .map_err(|error| error.to_string())?
                .to_string_lossy()
                .into_owned();
            if name.ends_with("-shm") || name.ends_with("-wal") || name.ends_with("-journal") {
                continue;
            }
            let metadata = path
                .symlink_metadata()
                .map_err(|error| format!("{}: {error}", path.display()))?;
            use std::os::unix::fs::MetadataExt;
            let detail = if metadata.file_type().is_symlink() {
                fs::read_link(&path)
                    .map(|target| target.to_string_lossy().into_owned())
                    .map_err(|error| format!("{}: {error}", path.display()))?
            } else if metadata.is_file() {
                let bytes =
                    fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
                let mut hasher = Sha256::new();
                hasher.update(&bytes);
                hasher
                    .finalize()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect()
            } else {
                String::new()
            };
            snapshot.insert(name, (metadata.mode(), metadata.size(), detail));
        }
    }
    Ok(snapshot)
}

/// Every entry under `root`, depth first. A symlinked directory is recorded but
/// not descended into: following it could leave the work directory this snapshot
/// is scoped to.
fn collect(root: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("{}: {error}", root.display())),
    };
    for entry in entries {
        let entry = entry.map_err(|error| format!("{}: {error}", root.display()))?;
        let path = entry.path();
        out.push(path.clone());
        let symlink = path
            .symlink_metadata()
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false);
        if entry.file_type().is_ok_and(|kind| kind.is_dir()) && !symlink {
            collect(&path, out)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn scratch(label: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("harness-witness-{label}-{}", monotonic_nanos()));
        fs::create_dir_all(path.join("proj")).expect("a scratch project");
        path
    }

    fn command(variant: &str) -> Command {
        Command {
            case: "RF1".to_owned(),
            variant: variant.to_owned(),
            tool: None,
            kind: "guest".to_owned(),
            env: Vec::new(),
            argv: vec!["/bin/true".to_owned()],
            cwd: "/tmp".to_owned(),
            timeout: 1.0,
            grace: 1.0,
            declared_extras: Vec::new(),
            prerequisites: Vec::new(),
            controls: None,
            setup: Vec::new(),
            expected_attempts: Vec::new(),
            attempt_expectations: None,
            attempt_protocols: None,
            supervisor: String::new(),
        }
    }

    #[test]
    fn a_table_row_is_the_eight_hex_id_and_nothing_else() {
        let text = "\
ID       DESTINATION          COUNT LAST-SEEN SESSION ACTION
1a2b3c4d 203.0.113.10:443     1     1s ago    ab      running
not-a-row
1a2b3c4 203.0.113.10:443     1     1s ago    ab      running
1a2b3c4g 203.0.113.10:443     1     1s ago    ab      running
1a2b3c4d";
        let rows = refusal_feed_rows(text);
        assert_eq!(rows.len(), 1);
        assert!(rows.contains_key("1a2b3c4d"));
        assert!(rows["1a2b3c4d"].contains("running"));
    }

    #[test]
    fn a_whole_word_is_what_the_label_check_reads() {
        assert!(has_word("1a2b3c4d 10.0.0.1:18080 1 running", "running"));
        assert!(has_word("1a2b3c4d … running-out", "running"));
        assert!(!has_word("1a2b3c4d … unrunning", "running"));
        assert!(!has_word("1a2b3c4d … running_late", "running"));
        assert!(has_word("running", "running"));
    }

    #[test]
    fn the_access_application_lines_are_parsed_in_the_asserted_order() {
        assert_eq!(
            allowed_application(
                "allowed tcp://192.168.1.2:18080 for /w/proj (policy revision 2) and recorded for this project"
            ),
            Some(("tcp://192.168.1.2:18080", 2))
        );
        // A line that names a different destination shape, a missing revision or
        // a different tail is refused rather than read optimistically.
        assert_eq!(
            allowed_application("allowed  for x (policy revision 2) and recorded for this project"),
            None
        );
        assert_eq!(
            allowed_application(
                "allowed tcp://x for y (policy revision two) and recorded for this project"
            ),
            None
        );
        assert_eq!(
            allowed_application("allowed tcp://x for y (policy revision 2) but not recorded"),
            None
        );
        assert_eq!(
            revoked_application(
                "revoked tcp://x for y (policy revision 3); the project record was deleted"
            ),
            Some(3)
        );
        assert_eq!(
            revoked_application("revoked tcp://x for y (policy revision 3); something else"),
            None
        );
    }

    #[test]
    fn a_refusal_feed_verdict_needs_the_same_ids_and_the_session_label() {
        let live = "\
1a2b3c4d 203.0.113.10:443     1 1s ago ab running
2b3c4d5e blocked.example:443  1 1s ago ab running";
        let after = "\
1a2b3c4d 203.0.113.10:443     1 2s ago ab ended
2b3c4d5e blocked.example:443  1 2s ago ab ended";
        let text = format!("{RF1_HINT}\nCASE RF1 BEGIN\n");
        assert_eq!(
            check_refusal_feed(&command("ipv4"), 0, &text, 0, live, 0, after),
            Vec::<String>::new()
        );
        // A row the live view never had is a rewritten ID, not a count.
        let renamed = after.replace("2b3c4d5e", "9f3c4d5e");
        let failures = check_refusal_feed(&command("ipv4"), 0, &text, 0, live, 0, &renamed);
        assert!(
            failures.iter().any(|failure| failure.contains("same IDs")),
            "{failures:?}"
        );
        // The hint twice, a non-zero access status and a missing destination are
        // each their own failure.
        let failures = check_refusal_feed(
            &command("ipv4"),
            0,
            &format!("{text}{RF1_HINT}\n"),
            1,
            "no rows",
            0,
            after,
        );
        assert_eq!(failures.len(), 5, "{failures:?}");
        // kill9: the unclean label and the kill status are the ones expected.
        let failures = check_refusal_feed(&command("kill9"), 0, &text, 0, live, 0, after);
        assert!(
            failures
                .iter()
                .any(|failure| failure.contains("launch status")),
            "{failures:?}"
        );
        assert!(
            failures
                .iter()
                .any(|failure| failure.contains("ended (unclean)")),
            "{failures:?}"
        );
    }

    #[test]
    fn a_live_allowance_verdict_cannot_pass_without_its_whole_join() {
        let work = scratch("allowance");
        let log = "PA2 PROBE 1 DENIED\nPA2 PROBE 2 OK\nPA2 PROBE 3 DENIED\nPA2 DONE\n";
        let failures = check_live_allowance(&work, "PA2-ipv4-7", log);
        assert!(
            failures
                .iter()
                .any(|failure| failure.contains("left no evidence")),
            "{failures:?}"
        );
        let evidence = json!({
            "destination": "tcp://192.168.1.2:18080",
            "steps": [{"step": "allow"}, {"step": "table"}, {"step": "allowances"}, {"step": "revoke"}],
            "failures": [],
            "store": "{\"records\":[{\"destination\":\"tcp://192.168.1.2:18080\"}]}",
            "store_after_revoke": "{\"records\":[]}",
            "grant_revision": 2,
            "revoke_revision": 3,
        });
        fs::write(work.join("PA2-witness.json"), evidence.to_string()).expect("evidence");
        // Everything but the fixture receipts is now in place: the allowed
        // probe must have reached the fixture, which nothing has yet.
        let failures = check_live_allowance(&work, "PA2-ipv4-7", log);
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(failures[0].contains("no fixture receipt"), "{failures:?}");
        fs::create_dir_all(work.join("fx")).expect("the fixture directory");
        fs::write(
            work.join("fx/receipts.log"),
            "tcp 18080 127.0.0.1 PA2-ipv4-7-p2\n",
        )
        .expect("receipts");
        assert_eq!(
            check_live_allowance(&work, "PA2-ipv4-7", log),
            Vec::<String>::new()
        );
        // A refused probe that reached the fixture is a policy leak, not a
        // surplus receipt.
        fs::write(
            work.join("fx/receipts.log"),
            "tcp 18080 127.0.0.1 PA2-ipv4-7-p2\nudp 19090 127.0.0.1 PA2-ipv4-7-p1\n",
        )
        .expect("receipts");
        let failures = check_live_allowance(&work, "PA2-ipv4-7", log);
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(failures[0].contains("refused probe p1"), "{failures:?}");
        let _ = fs::remove_dir_all(&work);
    }

    #[test]
    fn the_live_allowance_case_starts_with_no_record_and_no_signal() {
        let work = scratch("prepare");
        // A fresh work directory has nothing to remove.
        assert_eq!(prepare_live_allowance(&work, "PA2"), Vec::<String>::new());
        // A leftover store is reported *and* removed, and so is a stale signal.
        fs::create_dir_all(work.join("home/.config/agent-vm")).expect("the authority directory");
        fs::write(allowance_store(&work), "{}").expect("a leftover store");
        fs::write(work.join("proj").join(PA2_SIGNALS[0]), b"").expect("a stale signal");
        let failures = prepare_live_allowance(&work, "PA2");
        assert!(
            failures
                .iter()
                .any(|failure| failure.contains("left from an earlier case")),
            "{failures:?}"
        );
        assert!(!allowance_present(&work));
        assert!(!work.join("proj").join(PA2_SIGNALS[0]).exists());
        // Only PA2 has a live witness.
        assert!(
            prepare_live_allowance(&work, "PA1")
                .iter()
                .any(|failure| failure.contains("not the live-allowance case"))
        );
        let _ = fs::remove_dir_all(&work);
    }

    #[test]
    fn a_validation_snapshot_skips_the_sqlite_sidecars_and_sees_a_change() {
        let work = scratch("snapshot");
        for directory in ["home", "config", "state"] {
            fs::create_dir_all(work.join(directory)).expect("a private root");
        }
        fs::write(work.join("state/msb.db"), b"db").expect("a catalog");
        fs::write(work.join("state/msb.db-wal"), b"wal").expect("a sidecar");
        let before = snapshot_validation(&work).expect("a snapshot");
        assert!(before.contains_key("state/msb.db"));
        assert!(!before.contains_key("state/msb.db-wal"));
        // A rewrite of the sidecar alone is not a mutation.
        fs::write(work.join("state/msb.db-wal"), b"wal2").expect("a rewritten sidecar");
        assert_eq!(snapshot_validation(&work).expect("a snapshot"), before);
        // Anything else is.
        fs::write(work.join("home/x"), b"x").expect("a new file");
        assert_ne!(snapshot_validation(&work).expect("a snapshot"), before);
        let _ = fs::remove_dir_all(&work);
    }
}
