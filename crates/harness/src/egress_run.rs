//! `run`: the egress sweep's execution half (#692).
//!
//! Ported from `script/test/lib/egress-fixtures.py` (`orchestrate`, `hnc_ladder`,
//! `run_single_case`, `attempts_for`, `check_attempts`,
//! `check_attempt_inventory`, `cleanup_run`, `final_cleanup`,
//! `verified_archive`, `prepare_project`, `write_hook`, the credential seed and
//! the RJ1/HK/PXH1 verdicts). The plan is `egress_cases::print_plan`; this is
//! what runs it.
//!
//! The invariants this module owns, in the order they can be broken:
//!
//! * **Cleanup is the point.** A run that leaves a sandbox, a socket or a
//!   process behind is a failure, and a catalog that cannot be read is a cleanup
//!   failure rather than an empty catalog: "nothing is left" is a claim that has
//!   to be read back through the CLI, never assumed.
//! * **A row is a join, not a status.** Every case's verdict joins the launch
//!   status, the guest's own markers, the fixture's receipts and the host's
//!   observation; each of those is read from a different process.
//! * **A denial needs its positive control.** The control join at the end of the
//!   sweep is what stops a legal-looking skip from certifying a deny row.
//! * Every wait, read and subprocess in here is bounded, because a sweep that
//!   hangs cannot report the failure it was meant to find.
//!
//! The one thing this module deliberately does not do is adopt signals that
//! arrive outside a launch: `released_image_launch` turns an interrupt of the
//! launch into status `128 + N` and the sweep's own `finally` still runs, which
//! is the case that matters; a SIGTERM to the harness between cases ends the
//! process, and the next run's `cleanup_run` is what reports the leftover.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::{SocketAddr, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command as Process, Stdio},
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    egress_allowances::{allowance_present, cleanup_pa2, prepare_allowance, remove_allowances},
    egress_cases::{
        self as cases, ADMIN_GRACE, ALLOWANCE_CASES, BuildOptions, CLEANUP_BOUND, Case, Command,
        IMAGE, admin_command, append_owned, build_command, check_default_request_diagnostics,
        control_links, fixture_command, health_command, prepare_default_request_project, run_admin,
        selected_cases,
    },
    egress_fixtures::{
        self as fixtures, GateResult, HNC_STEP_C_REASON, HOSTNAME_PROXY_REFUSAL, OUTCOME_D,
        base_environment, monotonic_nanos, process_identity, signal_identity, wait_for_receipt,
    },
    egress_launch::{OwnedLaunch, list_catalog, socket_paths},
    egress_witness::{
        check_live_allowance, check_refusal_feed, prepare_live_allowance, receipt_lines,
        refusal_feed_query, snapshot_validation,
    },
};

/// The release manifest the archive is checked against, committed with the
/// candidate so "the assets are the pinned release" is not the asset's claim
/// about itself.
const RELEASE_MANIFEST: &str = "crates/agent-vm/tests/fixtures/standard-release/release.json";
/// Bound on the `agent-vm access` probe the RF1 verdict runs after the launch.
const FEED_QUERY_BOUND: Duration = Duration::from_secs(30);
/// Bound on the run's first private `list`, as in the Python's 12 s.
const INITIAL_LIST_BOUND: Duration = Duration::from_secs(12);

// --- The sweep's own request -------------------------------------------------

/// What `run` was asked to do, after the flags and the environment are merged.
pub struct RunRequest {
    pub binary: String,
    pub assets: String,
    pub lan: String,
    pub rebind: Option<String>,
    pub lan2: Option<String>,
    pub smoke: bool,
}

/// One case's verdict: the plan row, the attempts it produced and why it failed.
struct CaseResult {
    case: &'static Case,
    status: &'static str,
    failures: Vec<String>,
    attempts: Vec<Value>,
}

impl CaseResult {
    fn verdict(case: &'static Case, failures: Vec<String>, attempts: Vec<Value>) -> Self {
        Self {
            case,
            status: if failures.is_empty() { "PASS" } else { "FAIL" },
            failures,
            attempts,
        }
    }

    fn not_run(case: &'static Case, reason: String) -> Self {
        Self {
            case,
            status: "NOT RUN",
            failures: vec![reason],
            attempts: Vec::new(),
        }
    }
}

/// The host fixture cluster: one process, one identity, one readiness file.
pub struct Fixture {
    child: Child,
    identity: Value,
    start: Option<[u64; 2]>,
}

impl Fixture {
    /// Adopt a child the caller started as this run's fixture cluster.
    ///
    /// The boot-free controls start the cluster themselves (through
    /// `fixture_command`) so they can watch it be reaped; the cleanup path is
    /// the same one, and the start token comes from the identity it is given.
    pub fn adopt(child: Child, identity: Value) -> Self {
        let start = identity
            .get("start")
            .cloned()
            .and_then(|start| serde_json::from_value(start).ok());
        Self {
            child,
            identity,
            start,
        }
    }
}

/// Everything the sweep must hand to its `finally`: the launches it started, the
/// fixture cluster, and what it managed to decide. `orchestrate` owns the cleanup
/// so an error anywhere in `sweep` still reaches it.
struct RunState {
    launches: Vec<OwnedLaunch>,
    fixture: Option<Fixture>,
    results: Vec<CaseResult>,
    /// Attempt key -> the index of the case that produced it, so a control lookup
    /// sees a later status change, exactly as the Python's dict did.
    attempts: BTreeMap<String, usize>,
    answer: String,
    v6_available: bool,
    floor_available: bool,
    interrupted: Option<i32>,
    hnc_step: Option<char>,
}

impl RunState {
    fn new() -> Self {
        Self {
            launches: Vec::new(),
            fixture: None,
            results: Vec::new(),
            attempts: BTreeMap::new(),
            answer: String::new(),
            v6_available: false,
            floor_available: true,
            interrupted: None,
            hnc_step: None,
        }
    }

    fn remember(&mut self, result: CaseResult) {
        let index = self.results.len();
        for row in &result.attempts {
            if let Some(key) = row.get("key").and_then(Value::as_str) {
                self.attempts.insert(key.to_owned(), index);
            }
        }
        self.results.push(result);
    }
}

// --- orchestrate -------------------------------------------------------------

/// `run`: the whole sweep, from the image import to the verified cleanup.
///
/// The status is the launch failures' verdict, or 1 when a cleanup found
/// anything at all: a run that leaves a sandbox behind is not a pass.
pub fn orchestrate(request: &RunRequest) -> Result<i32, String> {
    let lan = check_request(request)?;
    let work = scratch_directory()?;
    println!(
        "{} evidence: {}",
        if request.smoke { "SMOKE" } else { "NATIVE" },
        work.display()
    );
    for directory in ["home", "config", "state", "fx"] {
        fs::create_dir_all(work.join(directory))
            .map_err(|error| format!("{}: {error}", work.join(directory).display()))?;
    }
    prepare_project(&work, &work.join("proj"))?;
    prepare_default_request_project(&work)?;
    fs::write(
        work.join("floor.json"),
        "{\"deployment_profile\":\"multi-tenant\"}\n",
    )
    .map_err(|error| error.to_string())?;

    let mut state = RunState::new();
    let primary = match sweep(&work, request, &lan, &mut state) {
        Ok(()) => {
            let (blocked, blockers) = certify(&mut state);
            if blocked {
                append_owned(&work, &json!({"phase": "hn-gate", "blockers": blockers}))?;
            }
            let failed = state.results.iter().any(|result| result.status == "FAIL");
            state
                .interrupted
                .unwrap_or(if blocked || failed { 1 } else { 0 })
        }
        Err(error) => {
            append_owned(
                &work,
                &json!({"phase": "run-primary-error", "error": error}),
            )?;
            eprintln!("harness: {error}");
            1
        }
    };

    // The `finally`: cleanup first, then the rows the run never reached, then the
    // summary that reports both.
    let fixture = state.fixture.take();
    let mut cleanup_errors = cleanup_run(&work, &request.binary, &state.launches, fixture);
    cleanup_errors.extend(final_cleanup(&work));
    let observed: BTreeSet<(&'static str, &'static str)> = state
        .results
        .iter()
        .map(|result| (result.case.case, result.case.variant))
        .collect();
    for case in selected_cases(request.smoke) {
        if !observed.contains(&(case.case, case.variant)) {
            state.results.push(CaseResult::not_run(
                case,
                "run aborted before case".to_owned(),
            ));
        }
    }
    write_summary(&work, request, primary, &state.results, &cleanup_errors)?;
    append_owned(
        &work,
        &json!({
            "phase": "run-result",
            "primary_status": primary,
            "cleanup_errors": cleanup_errors,
        }),
    )?;
    Ok(if primary != 0 {
        primary
    } else if cleanup_errors.is_empty() {
        0
    } else {
        1
    })
}

/// The pre-flight: an absolute candidate, the release assets, and a fixture LAN
/// that is RFC1918/CGN. Each of these is a refusal *before* a work directory
/// exists, so a mistyped run leaves nothing behind.
fn check_request(request: &RunRequest) -> Result<String, String> {
    if request.binary.is_empty() || !Path::new(&request.binary).is_absolute() {
        return Err(
            "native run requires absolute AGENT_VM_BIN, release assets and --lan/AGENT_VM_EGRESS_LAN"
                .to_owned(),
        );
    }
    if request.assets.is_empty() || request.lan.is_empty() {
        return Err(
            "native run requires absolute AGENT_VM_BIN, release assets and --lan/AGENT_VM_EGRESS_LAN"
                .to_owned(),
        );
    }
    let lan = request.lan.clone();
    if !is_private(&lan) {
        return Err("fixture LAN must be RFC1918/CGN IPv4".to_owned());
    }
    Ok(lan)
}

/// `10/8`, `172.16/12`, `192.168/16` and `100.64/10`: the addresses a fixture LAN
/// may claim. A public address here would have the run dial someone else's host.
fn is_private(lan: &str) -> bool {
    let Ok(address) = lan.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    let octets = address.octets();
    octets[0] == 10
        || (octets[0] == 172 && (16..32).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 168)
        || (octets[0] == 100 && (64..128).contains(&octets[1]))
}

/// A fresh work directory beside the guest's tmpfs, never *under* one: the
/// project is mounted into the guest, and `/tmp`, `/run`, `/dev/shm` and
/// `/var/run` are the guest's own scratch space.
fn scratch_directory() -> Result<PathBuf, String> {
    let parent = if cfg!(target_os = "macos") {
        "/tmp"
    } else {
        "/var/tmp"
    };
    let mut attempt = 0;
    let work = loop {
        let candidate = Path::new(parent).join(format!(
            "av302.{}.{}.{attempt}",
            std::process::id(),
            monotonic_nanos()
        ));
        match fs::create_dir(&candidate) {
            Ok(()) => break candidate,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && attempt < 8 => {
                attempt += 1;
            }
            Err(error) => return Err(format!("{}: {error}", candidate.display())),
        }
    };
    let work = work
        .canonicalize()
        .map_err(|error| format!("{}: {error}", work.display()))?;
    for forbidden in ["/tmp", "/run", "/dev/shm", "/var/run"] {
        let forbidden = Path::new(forbidden);
        if work == forbidden || work.ancestors().any(|parent| parent == forbidden) {
            return Err("canonical project would be under guest tmpfs".to_owned());
        }
    }
    Ok(work)
}

// --- The sweep ---------------------------------------------------------------

/// The Python's `orchestrate` body: import, fixture cluster, calibrations, the
/// case loop. `?` is its `raise`: the caller's `finally` is what cleans up.
fn sweep(work: &Path, request: &RunRequest, lan: &str, state: &mut RunState) -> Result<(), String> {
    let archive = verified_archive(Path::new(&request.assets))?;
    let archive_argument = archive.to_string_lossy().into_owned();
    let (status, _) = run_admin(
        work,
        &admin_command(
            work,
            &request.binary,
            "image-load",
            &[
                "image",
                "load",
                "--input",
                &archive_argument,
                "--tag",
                IMAGE,
            ],
            900.0,
        ),
        None,
    )?;
    if status != 0 {
        return Err(format!("image import failed: {status}"));
    }
    if !list_catalog(
        work,
        &request.binary,
        Some(Instant::now() + INITIAL_LIST_BOUND),
    )?
    .is_empty()
    {
        return Err("initial private catalog not empty".to_owned());
    }

    state.fixture = Some(start_fixture(work)?);
    // System resolver calibration, bounded in its own owned process.
    let rebind = request
        .rebind
        .clone()
        .unwrap_or_else(|| format!("{}.sslip.io", lan.replace('.', "-")));
    let calibration = resolve_command(work, &rebind, lan);
    let rebind_available = run_admin(work, &calibration, None)?.0 == 0;
    // --- #306 hostname tier calibration (ADR-0037 / plan §7.5) --------------
    // The smoke tier is the numeric subset; the ladder and the public/shared
    // calibrations are full-tier work, so they are skipped under --smoke.
    let lan2 = resolve_second_address(request.lan2.as_deref().unwrap_or_default());
    let mut hostname_skips: BTreeMap<&'static str, String> = BTreeMap::new();
    let mut hnc_result: Option<CaseResult> = None;
    if !request.smoke {
        let shared_pair = find_shared_public_pair();
        let public_ok = host_internet_available();
        let hnc_case = cases::CASES
            .iter()
            .find(|case| case.case == "HNc")
            .ok_or("the catalogue has no HNc row")?;
        let ladder = hnc_ladder(work, request, lan, &lan2, hnc_case, state)?;
        state.hnc_step = ladder.winner;
        append_owned(
            work,
            &json!({"phase": "hnc-ladder", "steps": ladder.steps, "winner": ladder.winner}),
        )?;
        let gate_reason = match ladder.winner {
            Some('a' | 'c') => "",
            Some(_) => {
                "HNc calibrated only via the diagnostic --allow-lan step (b); \
                 deny rows are confounded, so the name x port matrix has no evidence"
            }
            None => OUTCOME_D,
        };
        if !gate_reason.is_empty() {
            for name in fixtures::HN_GATE_CASES {
                hostname_skips.insert(name, gate_reason.to_owned());
            }
        }
        if lan2.is_empty() {
            hostname_skips.insert(
                "HN2",
                "no second test-owned address (--lan2/AGENT_VM_EGRESS_LAN2)".to_owned(),
            );
        }
        if shared_pair.is_none() {
            hostname_skips.insert(
                "HP4",
                "no shared public IP pair for the HP4 calibration".to_owned(),
            );
        }
        if !public_ok {
            for name in ["HP1", "HP2", "HP2c", "HP3", "HP4", "HP5", "HP6", "HP6c"] {
                hostname_skips.insert(name, "host internet/calibration unavailable".to_owned());
            }
        }
        hnc_result = Some(ladder.result);
    }

    for case in selected_cases(request.smoke) {
        if case.case == "HNc" {
            if let Some(result) = hnc_result.take() {
                state.remember(result);
            }
            continue;
        }
        let mut reason = String::new();
        if let Some(skip) = hostname_skips.get(case.case) {
            reason = skip.clone();
        } else if case.optional == "rebind" && !rebind_available {
            reason = "host resolver did not return fixture LAN A".to_owned();
        } else if case.optional == "ipv6" && !state.v6_available {
            reason = "paired IPv6 family/controls unavailable".to_owned();
        } else if case.case.starts_with("FL") && !state.floor_available {
            reason = "floor-unsupported (E-owned native evidence)".to_owned();
        }
        if !reason.is_empty() {
            state.remember(CaseResult::not_run(case, reason));
            continue;
        }
        // The fixture cluster is run-scoped: a dead one invalidates every row
        // after it, so it is an error and not a NOT RUN.
        check_fixture_alive(work, state)?;
        let health = run_admin(work, &health_command(work), None)?.0;
        if health != 0 {
            return Err(format!("host fixture health failed: {health}"));
        }
        let ident = format!("{}-{}-{}", case.case, case.variant, state.launches.len());
        if case.case.starts_with("HK") {
            write_hook(
                work,
                &case.case[..3],
                lan,
                &format!("{ident}-hook"),
                crate::egress_fixtures::TCP_RECEIPT_PORTS[0],
            );
        }
        let answer = if state.answer.is_empty() {
            "ANSWER_FROM_H1"
        } else {
            state.answer.as_str()
        };
        let command = build_command(
            case,
            work,
            &request.binary,
            lan,
            &BuildOptions {
                answer,
                rebind: &rebind,
                attempt: &ident,
                lan2: &lan2,
                hnc_step: match state.hnc_step {
                    Some('b') => "b",
                    _ => "a",
                },
            },
        );
        if case.tool == "egresscreds" {
            prepare_project(work, &work.join("creds"))?;
            seed_credentials(work)?;
        }
        // ADR-0065: the record is per case and per digest, and must not survive
        // into any other case in this shared `work/home`. A leftover store is
        // reported for *every* case, the allowance cases included: seeding over
        // one would otherwise erase the only evidence that an earlier case
        // leaked.
        let allowance_leaked = allowance_present(work);
        if ALLOWANCE_CASES.contains(&case.case) {
            let mut failures = prepare_allowance(work, case.case, lan);
            if !failures.is_empty() {
                // No launch: without its record PA1 would fail for the wrong
                // reason and PA1x would pass while proving nothing.
                failures.extend(remove_allowances(work));
                state.remember(CaseResult::verdict(case, failures, Vec::new()));
                continue;
            }
        }
        if case.case == "PA2" {
            // The opposite of a seed: PA2 must start with no record and no stale
            // signals, or its first, supposed-to-be-refused probe would pass (a
            // record) or its host commands would be skipped (a signal).
            let failures = prepare_live_allowance(work, case.case);
            if !failures.is_empty() {
                state.remember(CaseResult::verdict(case, failures, Vec::new()));
                continue;
            }
        }
        let before = if case.guest {
            None
        } else {
            Some(snapshot_validation(work)?)
        };
        let receipts_path = work.join("fx").join(fixtures::RECEIPTS_NAME);
        let proxy_before = fs::read_to_string(&receipts_path).unwrap_or_default();
        let receipt_offset = receipt_lines(work).len();
        let launched = OwnedLaunch::new(work, &command, ident.clone())?;
        state.launches.push(launched);
        let index = state.launches.len() - 1;
        let mut failures = Vec::new();
        if matches!(case.case, "IN1" | "IN2") {
            match spawn_ingress(work, case.case, &ident) {
                Ok((child, identity)) => state.launches[index].adopt(child, identity),
                Err(error) => failures.push(error),
            }
        }
        let status = state.launches[index].run()?;
        // The ingress driver is waited for before the launch's own cleanup: it is
        // polling a port the sandbox publishes, so it must not outlive the guest.
        match state.launches[index].join_auxiliaries(status != 0) {
            Ok(statuses) => {
                for ingress_status in statuses {
                    if ingress_status != 0 {
                        failures.push(format!("ingress driver status {ingress_status}"));
                    }
                }
            }
            Err(error) => failures.push(error),
        }
        let scored = score_case(
            work,
            &state.launches[index],
            &command,
            case,
            lan,
            status,
            receipt_offset,
            &proxy_before,
            before.as_ref(),
        );
        failures.extend(scored.failures);
        if !scored.answer.is_empty() {
            state.answer = scored.answer;
        }
        if let Some(v6) = scored.v6 {
            state.v6_available = v6;
        }
        if scored.floor_lost {
            state.floor_available = false;
        }
        let mut result = CaseResult::verdict(case, failures, scored.rows);
        if case.case == "FL0"
            && !state.floor_available
            && !scored.cleanup_found
            && result.status == "PASS"
        {
            result.status = "NOT RUN";
            result
                .failures
                .push("floor-unsupported (E-owned native evidence)".to_owned());
        }
        if allowance_leaked {
            result
                .failures
                .push("a project allowance record was left from an earlier case".to_owned());
            result.status = "FAIL";
        }
        state.remember(result);
        if matches!(status, 130 | 143) {
            state.interrupted = Some(status);
            break;
        }
    }
    Ok(())
}

/// Confirm the run-scoped fixture cluster is still the one that was started.
fn check_fixture_alive(work: &Path, state: &mut RunState) -> Result<(), String> {
    let Some(fixture) = state.fixture.as_mut() else {
        return Err("host fixtures not ready".to_owned());
    };
    let pid = fixture.identity["pid"].as_u64().unwrap_or_default();
    let pid = u32::try_from(pid).map_err(|_| "host fixture has no pid".to_owned())?;
    let alive = fixture
        .child
        .try_wait()
        .map_err(|error| error.to_string())?;
    if alive.is_some() || process_identity(pid)? != fixture.start {
        return Err("run-scoped host fixture died".to_owned());
    }
    // `work` is carried so the signature reads like the Python's; the readiness
    // file is the fixture's, and a cluster that rewrote it is a restart.
    if !work.join("fx").join(fixtures::READY_NAME).exists() {
        return Err("run-scoped host fixture died".to_owned());
    }
    Ok(())
}

/// Start the fixture cluster the whole run shares: one process, one identity, and
/// a readiness file that only a fully bound cluster writes.
fn start_fixture(work: &Path) -> Result<Fixture, String> {
    use std::os::unix::process::CommandExt;
    let command = fixture_command(work);
    append_owned(
        work,
        &json!({"phase": "fixture-command", "command": command.plan()}),
    )?;
    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(work.join("fixture.log"))
        .map_err(|error| format!("fixture.log: {error}"))?;
    let child = Process::new(&command.argv[0])
        .args(&command.argv[1..])
        .env_clear()
        .envs(command.env.iter().map(|(name, value)| (name, value)))
        .current_dir(&command.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::from(
            log.try_clone().map_err(|error| error.to_string())?,
        ))
        .stderr(Stdio::from(log))
        .process_group(0)
        .spawn()
        .map_err(|error| format!("{}: {error}", command.argv[0]))?;
    let pid = child.id();
    let start = process_identity(pid)?;
    let identity = json!({"pid": pid, "start": start});
    append_owned(work, &json!({"phase": "fixture", "identity": identity}))?;
    let fixture = Fixture {
        child,
        identity,
        start,
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    while !work.join("fx").join(fixtures::READY_NAME).exists() {
        if Instant::now() >= deadline {
            return Err("host fixtures not ready".to_owned());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(fixture)
}

/// The ingress driver as an adopted auxiliary: a separate process in the launch's
/// own environment, exactly as the CLI is told to run one.
fn spawn_ingress(work: &Path, case: &str, ident: &str) -> Result<(Child, Value), String> {
    use std::os::unix::process::CommandExt;
    let mut argv = vec![
        cases::program_path(),
        "egress-fixtures".to_owned(),
        "ingress".to_owned(),
        "--work".to_owned(),
        work.to_string_lossy().into_owned(),
        "--case".to_owned(),
        case.to_owned(),
        "--id".to_owned(),
        ident.to_owned(),
    ];
    let program = argv.remove(0);
    let child = Process::new(program)
        .args(&argv)
        .env_clear()
        .envs(
            base_environment(work)
                .iter()
                .map(|(name, value)| (name, value)),
        )
        .stdin(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|error| format!("ingress driver: {error}"))?;
    let identity = json!({"pid": child.id(), "start": process_identity(child.id())?});
    append_owned(
        work,
        &json!({"phase": "ingress-driver", "identity": identity}),
    )?;
    Ok((child, identity))
}

/// The resolver calibration: the harness's own `resolve` verb, in the run's
/// environment and bounded at 5 s like every other admin command.
fn resolve_command(work: &Path, name: &str, address: &str) -> Command {
    let mut command = admin_command(work, &cases::program_path(), "RB1", &[], 5.0);
    command.variant = "preflight".to_owned();
    command.argv = vec![
        cases::program_path(),
        "egress-fixtures".to_owned(),
        "resolve".to_owned(),
        name.to_owned(),
        address.to_owned(),
    ];
    command.grace = ADMIN_GRACE;
    command
}

// --- The HNc ladder ----------------------------------------------------------

struct Ladder {
    winner: Option<char>,
    result: CaseResult,
    steps: Vec<Value>,
}

/// ADR-0037 / plan §7.5: try the admission ladder in order until HNc succeeds,
/// recording every step.
///
/// Step (c) is always NOT RUN: the test-owned `<lan>:53` DNS listener is not
/// wired into the supervisor, so the step would query no listener and fail
/// misleadingly.
fn hnc_ladder(
    work: &Path,
    request: &RunRequest,
    lan: &str,
    lan2: &str,
    hnc_case: &'static Case,
    state: &mut RunState,
) -> Result<Ladder, String> {
    let mut steps = Vec::new();
    let mut last: Option<CaseResult> = None;
    for step in ['a', 'b'] {
        let ident = format!("HNc-{step}-{}", state.launches.len());
        let outcome = run_single_case(work, request, lan, lan2, hnc_case, &ident, step, state)?;
        steps.push(json!([step, outcome.status, outcome.failures]));
        if outcome.status == "PASS" {
            let result = CaseResult {
                case: hnc_case,
                status: outcome.status,
                failures: outcome.failures,
                attempts: outcome.attempts,
            };
            return Ok(Ladder {
                winner: Some(step),
                result,
                steps,
            });
        }
        last = last.or(Some(CaseResult {
            case: hnc_case,
            status: outcome.status,
            failures: outcome.failures,
            attempts: outcome.attempts,
        }));
    }
    steps.push(json!(["c", "NOT RUN", [HNC_STEP_C_REASON]]));
    Ok(Ladder {
        winner: None,
        result: last.unwrap_or_else(|| CaseResult {
            case: hnc_case,
            status: "NOT RUN",
            failures: Vec::new(),
            attempts: Vec::new(),
        }),
        steps,
    })
}

/// One ladder attempt: a launch plus its receipt/attempt check.
#[allow(clippy::too_many_arguments)]
fn run_single_case(
    work: &Path,
    request: &RunRequest,
    lan: &str,
    lan2: &str,
    case: &'static Case,
    ident: &str,
    step: char,
    state: &mut RunState,
) -> Result<CaseResult, String> {
    let hnc_step = if step == 'b' { "b" } else { "a" };
    let command = build_command(
        case,
        work,
        &request.binary,
        lan,
        &BuildOptions {
            answer: "ANSWER_FROM_H1",
            rebind: "",
            attempt: ident,
            lan2,
            hnc_step,
        },
    );
    let receipt_offset = receipt_lines(work).len();
    state
        .launches
        .push(OwnedLaunch::new(work, &command, ident.to_owned())?);
    let index = state.launches.len() - 1;
    let status = state.launches[index].run()?;
    let text = launch_text(work, ident);
    let rows = attempts_for(case, ident, &text)?;
    let mut failures = check_attempt_inventory(&command, &rows);
    if status != 0 {
        failures.push(format!("primary expected 0, actual {status}"));
    }
    let begin = format!("CASE {} BEGIN", case.case);
    let end = format!("CASE {} END", case.case);
    if !text.lines().any(|line| line == begin) {
        failures.push("guest BEGIN missing".to_owned());
    }
    if !text.lines().any(|line| line == end) {
        failures.push("guest END missing".to_owned());
    }
    failures.extend(check_attempts(work, case, &rows, receipt_offset));
    failures.extend(state.launches[index].cleanup(None));
    Ok(CaseResult {
        case,
        status: if failures.is_empty() { "PASS" } else { "FAIL" },
        failures,
        attempts: rows,
    })
}

// --- One case's verdict ------------------------------------------------------

/// What scoring one case produced, so the loop can apply it to the run state
/// without holding a borrow of the launch it read.
struct Scored {
    failures: Vec<String>,
    rows: Vec<Value>,
    answer: String,
    v6: Option<bool>,
    floor_lost: bool,
    cleanup_found: bool,
}

#[allow(clippy::too_many_arguments)]
fn score_case(
    work: &Path,
    owned: &OwnedLaunch,
    command: &Command,
    case: &'static Case,
    lan: &str,
    status: i32,
    receipt_offset: usize,
    proxy_before: &str,
    before: Option<&BTreeMap<String, (u32, u64, String)>>,
) -> Scored {
    let mut failures = Vec::new();
    let text = launch_text(work, owned.ident());
    let mut answer = String::new();
    let mut v6 = None;
    let mut floor_lost = false;
    if case.case == "RF1" {
        // The witness recorded what it saw while the launch ran; the verdict is a
        // join of those two files and a query of its own.
        let (mut live_status, mut live_output) = (1, String::new());
        if let Ok(recorded) = fs::read_to_string(work.join("RF1-live.txt")) {
            let (first, rest) = recorded.split_once('\n').unwrap_or((&recorded, ""));
            live_status = first
                .split_once('=')
                .and_then(|(_, value)| value.parse().ok())
                .unwrap_or(1);
            live_output = rest.to_owned();
        }
        let session = fs::read_to_string(work.join("RF1-session.txt"))
            .map(|session| session.trim().to_owned())
            .unwrap_or_default();
        let (after_status, after_output) =
            match refusal_feed_query(command, &session, FEED_QUERY_BOUND) {
                Ok(answer) => answer,
                Err(error) => {
                    failures.push(format!("live access failed: {error}"));
                    (1, String::new())
                }
            };
        failures.extend(check_refusal_feed(
            command,
            status,
            &text,
            live_status,
            &live_output,
            after_status,
            &after_output,
        ));
        failures.extend(observation_errors(owned));
    }
    if case.case == "PA2" {
        failures.extend(check_live_allowance(work, owned.ident(), &text));
        failures.extend(observation_errors(owned));
    }
    let rows = match attempts_for(case, owned.ident(), &text) {
        Ok(rows) => rows,
        Err(error) => {
            failures.push(error);
            Vec::new()
        }
    };
    failures.extend(check_attempt_inventory(command, &rows));
    let expected = if case.case == "CL1" {
        124
    } else if case.case == "HK2" {
        7
    } else if case.case == "RF1" && case.variant == "kill9" {
        -libc::SIGKILL
    } else {
        0
    };
    if matches!(case.case, "NR1" | "NR2" | "NR3") {
        failures.extend(check_default_request_diagnostics(case, status, &text));
    } else if case.guest {
        if status != expected {
            failures.push(format!("primary expected {expected}, actual {status}"));
        }
        if case.case != "HK2"
            && !text
                .lines()
                .any(|line| line == format!("CASE {} BEGIN", case.case))
        {
            failures.push("guest BEGIN missing".to_owned());
        }
        // A killed guest never prints its END marker (RF1's kill9 variant).
        let killed = case.case == "RF1" && case.variant == "kill9";
        if !matches!(case.case, "CL1" | "HK2")
            && !killed
            && !text
                .lines()
                .any(|line| line == format!("CASE {} END", case.case))
        {
            failures.push("guest END missing".to_owned());
        }
        if case.case == "HK2" && !strict_hook_rejected(&text) {
            failures.push("strict hook did not reject before tool execution".to_owned());
        }
        if case.case == "HK1" && !text.lines().any(|line| line == "HOOK_EGRESS_DENIED") {
            failures.push("recovered hook denial marker missing".to_owned());
        }
        if case.case == "D1"
            && !(text.contains("Egress policy: all guest egress denied")
                && text.contains("DNS: queries denied"))
        {
            failures.push("default-deny notice missing".to_owned());
        }
        if !matches!(case.case, "P0" | "CL1" | "RF1" | "PA2") && rows.is_empty() {
            failures.push("no attempts observed".to_owned());
        }
        failures.extend(check_attempts(work, case, &rows, receipt_offset));
    } else {
        if case.case == "PXH1" {
            // C8: the selected host HTTP proxy refuses the hostname launch with
            // fixed text and never echoes the input. Its positive control is PX1
            // (a numeric launch under the same proxy variables still launches).
            if matches!(status, 0 | 124 | 130 | 143)
                || text.contains("CASE ")
                || !text.contains(HOSTNAME_PROXY_REFUSAL)
            {
                failures.push("hostname proxy refusal oracle failed".to_owned());
            }
        } else if !validation_rejected(status, &text, case.variant) {
            failures.push("validation rejection oracle failed".to_owned());
        }
        match snapshot_validation(work) {
            Ok(after) => {
                if before.is_some_and(|before| *before != after) {
                    failures
                        .push("validation-only invocation mutated private launch state".to_owned());
                }
            }
            // An unreadable snapshot is not a mutation: a validation-only row must
            // not be failed for a claim the harness could not make.
            Err(error) => failures.push(format!("validation snapshot unreadable: {error}")),
        }
    }
    if text.contains("EXPECT_FAIL") || text.contains("command not found") {
        failures.push("probe/hook internal error".to_owned());
    }
    if case.case == "H1" {
        answer = text
            .lines()
            .filter_map(|line| line.strip_prefix("ANSWER "))
            .map(str::trim)
            .find(|value| !value.is_empty() && value.parse::<std::net::Ipv4Addr>().is_ok())
            .unwrap_or_default()
            .to_owned();
        if answer.is_empty() {
            failures.push("decoded H1 endpoint missing".to_owned());
        }
    }
    if case.case == "P0" {
        // The stored sandbox spec only pins a profile that some config layer set
        // explicitly; the default is single-tenant, so an absent spec field is the
        // private default. A host-wide multi-tenant managed policy would still
        // appear here as "multi-tenant" and must fail this row.
        match owned.effective_profile().as_deref() {
            None | Some("single-tenant") => {}
            Some(profile) => failures.push(format!(
                "effective private profile not established: {profile}"
            )),
        }
        v6 = Some(text.contains("ipv6=1") && host_has_ipv6());
        if !text.contains("PREFLIGHT gateway=") {
            failures.push("guest preflight missing".to_owned());
        }
    }
    let proxy_after =
        fs::read_to_string(work.join("fx").join(fixtures::RECEIPTS_NAME)).unwrap_or_default();
    let proxy_new: Vec<&str> = proxy_after
        .get(proxy_before.len()..)
        .unwrap_or_default()
        .lines()
        .filter(|line| line.starts_with("proxy "))
        .collect();
    if case.case == "PX1" {
        let expected = format!("proxy {lan}:18080");
        if proxy_new != [expected.as_str()] {
            failures.push("proxy route/deny receipt mismatch".to_owned());
        }
    }
    if matches!(case.case, "PX2" | "PX3") && !proxy_new.is_empty() {
        failures.push("unexpected proxy CONNECT".to_owned());
    }
    if case.case.starts_with("FL") && owned.effective_profile().as_deref() != Some("multi-tenant") {
        failures.push(format!(
            "floor profile not established: {:?}",
            owned.effective_profile()
        ));
        // A successful FL0 launch that does not pin the private floor in the
        // stored spec means this launcher path cannot establish the profile from
        // a private MSB_CONFIG_PATH; the plan defers the platform-floor native
        // evidence to E and prints NOT RUN.
        if case.case == "FL0" && status == 0 {
            floor_lost = true;
        }
    }
    let cleanup = owned.cleanup(None);
    let cleanup_found = !cleanup.is_empty();
    failures.extend(cleanup);
    if case.tool == "egresscreds" {
        failures.extend(remove_credentials(work));
    }
    if ALLOWANCE_CASES.contains(&case.case) {
        failures.extend(remove_allowances(work));
    }
    if case.case == "PA2" {
        failures.extend(cleanup_pa2(work));
    }
    if allowance_present(work) {
        failures.push("project allowance record survived its own case".to_owned());
    }
    if work.join("config/agent-vm/default-image.json").exists()
        || work
            .join("home/.config/agent-vm/default-image.json")
            .exists()
    {
        failures.push("explicit image adopted default".to_owned());
    }
    Scored {
        failures,
        rows,
        answer,
        v6,
        floor_lost,
        cleanup_found,
    }
}

fn observation_errors(owned: &OwnedLaunch) -> Vec<String> {
    let errors = owned.errors();
    if errors.is_empty() {
        Vec::new()
    } else {
        vec![format!("observation errors: {errors:?}")]
    }
}

fn launch_text(work: &Path, ident: &str) -> String {
    fs::read(work.join(format!("{ident}.log")))
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default()
}

/// Whether this host offers an IPv6 family, the host half of the P0 row's
/// `ipv6=1` conjunction. Python asked `socket.has_ipv6` (an interpreter build
/// flag); the honest local equivalent is whether a v6 socket can be bound.
fn host_has_ipv6() -> bool {
    let any = SocketAddr::from(([0u16; 8], 0));
    UdpSocket::bind(any).is_ok()
}

// --- Attempts ----------------------------------------------------------------

/// The guest's `ATTEMPT …` lines, plus the hook row an HK case implies.
///
/// The line protocol is `<kind> … <id>` with the id last and the label first, and
/// this parser is the *independent* inventory the case's own table is joined
/// against: a reordered, duplicated or renamed attempt is a failure here rather
/// than evidence.
pub fn attempts_for(case: &Case, ident: &str, text: &str) -> Result<Vec<Value>, String> {
    let mut rows: Vec<Value> = Vec::new();
    for line in text.lines() {
        if !rows.is_empty() && !line.starts_with("ATTEMPT ") {
            let index = rows.len() - 1;
            let mut output = rows[index]["output"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            output.push_str(line);
            output.push('\n');
            rows[index]["output"] = Value::String(output);
        }
        if !line.starts_with("ATTEMPT ") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 8 || parts[1] != case.case {
            return Err("malformed guest attempt".to_owned());
        }
        rows.push(json!({
            "key": format!("{}:{}:{}", case.case, case.variant, parts[2]),
            "label": parts[2],
            "protocol": parts[3],
            "endpoint": parts[4],
            "port": parts[5],
            "expectation": parts[6],
            "receipt": parts[7],
            "detail": parts[8..].join(" "),
            "output": "",
        }));
    }
    if case.case.starts_with("HK") {
        rows.push(json!({
            "key": format!("{}:{}:hook", case.case, case.variant),
            "label": "hook",
            "protocol": "tcp",
            "endpoint": "LAN",
            "port": "18080",
            "expectation": if case.case.ends_with('c') { "0" } else { "1" },
            "receipt": format!("{ident}-hook"),
            "detail": "",
            "output": text,
        }));
    }
    Ok(rows)
}

/// The guest's attempt inventory against the plan's independent table.
pub fn check_attempt_inventory(command: &Command, rows: &[Value]) -> Vec<String> {
    let mut errors = Vec::new();
    let labels: Vec<&str> = rows
        .iter()
        .map(|row| row["label"].as_str().unwrap_or_default())
        .collect();
    if labels != command.expected_attempts {
        errors.push("missing, duplicate or reordered guest attempts".to_owned());
    }
    for row in rows {
        let label = row["label"].as_str().unwrap_or_default();
        let expectation = row["expectation"].as_str().unwrap_or_default();
        if Some(expectation) != command_expectation(command, label) {
            errors.push(format!("attempt expectation changed: {label}"));
        }
        if Some(row["protocol"].as_str().unwrap_or_default()) != command_protocol(command, label) {
            errors.push(format!("attempt protocol changed: {label}"));
        }
    }
    errors
}

fn command_expectation<'a>(command: &'a Command, label: &str) -> Option<&'a str> {
    command
        .attempt_expectations
        .as_ref()?
        .iter()
        .find(|(key, _)| key == label)
        .map(|(_, value)| value.as_str())
}

fn command_protocol<'a>(command: &'a Command, label: &str) -> Option<&'a str> {
    command
        .attempt_protocols
        .as_ref()?
        .iter()
        .find(|(key, _)| key == label)
        .map(|(_, value)| value.as_str())
}

/// Join every attempt against what the fixtures and the guest reported.
///
/// Hostname-tier receipts are keyed by port and payload/SNI, not by attempt id,
/// so a control case's receipt can collide with the case under test (OP1c's
/// printable payload and OP1's are identical); every lookup in the receipt log is
/// therefore scoped to the lines written since this case began.
pub fn check_attempts(
    work: &Path,
    case: &Case,
    rows: &[Value],
    receipt_offset: usize,
) -> Vec<String> {
    let fx = work.join("fx");
    let mut records: Vec<String> = receipt_lines(work)
        .into_iter()
        .skip(receipt_offset)
        .collect();
    let mut failures = Vec::new();
    for row in rows {
        let expected = row["expectation"].as_str().unwrap_or_default();
        let receipt = row["receipt"].as_str().unwrap_or_default();
        let label = row["label"].as_str().unwrap_or_default();
        let port = row["port"].as_str().unwrap_or_default();
        let endpoint = row["endpoint"].as_str().unwrap_or_default();
        let output = row["output"].as_str().unwrap_or_default();
        let protocol = row["protocol"].as_str().unwrap_or_default();
        match protocol {
            "tcp" | "udp" => {
                let status = wait_for_receipt(&fx, receipt, Duration::from_secs(3));
                let marker = match (protocol, expected) {
                    ("tcp", "0") => "HTTP_OK ",
                    ("tcp", _) => "HTTP_FAIL ",
                    (_, "0") => "UDP_ACK ",
                    _ => "UDP_NOACK ",
                };
                let wanted = format!("{marker}{receipt}");
                if status != i32::from(expected != "0")
                    || !output.lines().any(|line| line == wanted)
                {
                    failures.push(format!("receipt/probe mismatch: {label}"));
                }
                if status == 0 {
                    records = receipt_lines(work);
                    let matched = records.iter().any(|line| {
                        let fields: Vec<&str> = line.split_whitespace().collect();
                        fields.get(..2) == Some(&[protocol, port][..])
                            && fields.last() == Some(&receipt)
                    });
                    if !matched {
                        failures.push(format!("wrong receipt protocol/port: {label}"));
                    }
                    if matches!(case.case, "HC1" | "H1" | "LH1") && label == "host-tcp80" {
                        let wanted = format!("tcp 18080 127.0.0.1 {receipt}");
                        if !receipt_lines(work).contains(&wanted) {
                            failures.push("host receipt peer is not loopback".to_owned());
                        }
                    }
                }
            }
            "public" => {
                let found = if expected == "0" {
                    output.lines().any(|line| {
                        line.strip_prefix("HTTP_STATUS ").is_some_and(|code| {
                            code.len() == 3 && code.bytes().all(|b| b.is_ascii_digit())
                        })
                    })
                } else {
                    let wanted = format!("HTTP_FAIL {endpoint}:{port}");
                    output.lines().any(|line| line == wanted)
                };
                if !found {
                    failures.push(format!("public status missing: {label}"));
                }
            }
            protocol if protocol.starts_with("dns-") => {
                let proto = &protocol[4..];
                let wanted = format!("DNS {proto} {endpoint} ");
                let rcode = if expected == "NX" { 3 } else { 0 };
                let found = output.lines().any(|line| {
                    line.starts_with(&wanted)
                        && line.contains(" id_ok=1 qr=1 question_ok=1 tc=0 ")
                        && line.contains(&format!(" rcode={rcode} "))
                });
                if !found {
                    failures.push(format!("validated DNS response missing: {label}"));
                }
            }
            "tls" | "opaque" | "banner" => {
                let detail = row["detail"].as_str().unwrap_or_default();
                let (present, wrong) = if protocol == "tls" {
                    let hits = records.iter().any(|line| {
                        let fields: Vec<&str> = line.split_whitespace().collect();
                        fields.get(..3) == Some(&["tls", port, endpoint][..])
                            && fields.last() == Some(&detail)
                    });
                    let plain = records.iter().any(|line| {
                        let fields: Vec<&str> = line.split_whitespace().collect();
                        fields.get(..3) == Some(&["tcp-plain", port, endpoint][..])
                    });
                    (hits, plain)
                } else {
                    let hits = records.iter().any(|line| {
                        let fields: Vec<&str> = line.split_whitespace().collect();
                        fields.len() == 4
                            && matches!(fields[0], "opaque" | "tcp-plain")
                            && fields[1] == port
                            && fields[2] == endpoint
                            && fields[3] == detail
                    });
                    (hits, false)
                };
                if expected == "0" && !present {
                    failures.push(format!("missing hostname receipt: {label}"));
                }
                if expected == "1" && (present || wrong) {
                    failures.push(format!("unexpected hostname receipt: {label}"));
                }
            }
            "https" => {
                let parsed = output.lines().find_map(|line| {
                    let rest = line.strip_prefix("HTTP_CODE ")?;
                    let (code, rc) = rest.split_once(" rc=")?;
                    let rc: i32 = rc.parse().ok()?;
                    Some((code.to_owned(), rc))
                });
                match parsed {
                    None => failures.push(format!("https status missing: {label}")),
                    Some((code, rc)) => {
                        let ok =
                            rc == 0 && !code.is_empty() && code.bytes().all(|b| b.is_ascii_digit());
                        let good = match expected {
                            "0" => ok && (200..300).contains(&code.parse::<u16>().unwrap_or(0)),
                            "1" => !(ok && (200..300).contains(&code.parse::<u16>().unwrap_or(0))),
                            other => ok && code == other,
                        };
                        if !good {
                            failures.push(format!("https status mismatch: {label}"));
                        }
                    }
                }
            }
            "held" => {
                let marker = if expected == "0" {
                    "HELD_OK"
                } else {
                    "HELD_DENIED"
                };
                if !output.contains(marker) {
                    failures.push(format!("held-connection marker missing: {label}"));
                }
            }
            other => failures.push(format!("unknown attempt protocol: {other}")),
        }
    }
    failures
}

// --- Calibrations ------------------------------------------------------------

/// A pair of public names sharing one non-gateway IPv4, for HP4.
fn find_shared_public_pair() -> Option<(String, String)> {
    use std::net::ToSocketAddrs;
    let candidates = [
        "example.com",
        "www.example.com",
        "example.org",
        "www.example.org",
        "example.net",
        "www.example.net",
    ];
    let mut by_address: BTreeMap<String, &str> = BTreeMap::new();
    for name in candidates {
        let Ok(rows) = (name, 443u16).to_socket_addrs() else {
            continue;
        };
        let addresses: BTreeSet<String> = rows
            .filter_map(|row| match row {
                SocketAddr::V4(address) => Some(address.ip().to_string()),
                SocketAddr::V6(_) => None,
            })
            .collect();
        for address in addresses {
            let Ok(parsed) = address.parse::<std::net::Ipv4Addr>() else {
                continue;
            };
            if !is_global(parsed) {
                continue;
            }
            match by_address.get(&address) {
                Some(previous) if *previous != name => {
                    return Some(((*previous).to_owned(), name.to_owned()));
                }
                Some(_) => {}
                None => {
                    by_address.insert(address, name);
                }
            }
        }
    }
    None
}

/// Whether an IPv4 address is globally routable, the question the HP4 calibration
/// asks: a documentation, private, shared, loopback or otherwise reserved
/// address is not a public endpoint, so a "shared public IP" pair made of one
/// would calibrate nothing.
fn is_global(address: std::net::Ipv4Addr) -> bool {
    let octets = address.octets();
    if address.is_loopback()
        || address.is_private()
        || address.is_link_local()
        || address.is_broadcast()
        || address.is_multicast()
        || address.is_unspecified()
        || address.is_documentation()
    {
        return false;
    }
    let shared = octets[0] == 100 && (64..128).contains(&octets[1]);
    let reserved = octets[0] >= 240;
    let benchmark = octets[0] == 198 && (18..20).contains(&octets[1]);
    !(shared || reserved || benchmark)
}

/// A bounded host-side check for the public HP tier; a failure means the rows are
/// NOT RUN, never a false denial.
fn host_internet_available() -> bool {
    use std::net::{TcpStream, ToSocketAddrs};
    let Ok(mut addresses) = ("example.com", 443u16).to_socket_addrs() else {
        return false;
    };
    let Some(address) = addresses.next() else {
        return false;
    };
    TcpStream::connect_timeout(&address, Duration::from_secs(4)).is_ok()
}

/// Accept `--lan2` only when it is a plain non-loopback IPv4 literal.
fn resolve_second_address(candidate: &str) -> String {
    if candidate.is_empty() {
        return String::new();
    }
    match candidate.parse::<std::net::Ipv4Addr>() {
        Ok(address) if !address.is_loopback() => candidate.to_owned(),
        _ => String::new(),
    }
}

// --- Cleanup -----------------------------------------------------------------

/// The run's cleanup: every launch, then the fixture cluster, then a verified
/// empty catalog.
///
/// A catalog that cannot be read is a cleanup *failure*, not an empty catalog:
/// "nothing is left" is only ever read back through the CLI.
pub fn cleanup_run(
    work: &Path,
    binary: &str,
    launches: &[OwnedLaunch],
    fixture: Option<Fixture>,
) -> Vec<String> {
    let deadline =
        Instant::now() + Duration::from_secs_f64(CLEANUP_BOUND * launches.len() as f64 + 20.0);
    let mut errors = Vec::new();
    for launch in launches {
        errors.extend(launch.cleanup(Some(deadline)));
    }
    if let Some(mut fixture) = fixture {
        let pid = fixture.identity["pid"].as_u64().unwrap_or_default();
        let pid = u32::try_from(pid).ok();
        let signalled = signal_identity(&fixture.identity, libc::SIGTERM);
        if let Err(error) = signalled {
            errors.push(error);
        }
        if wait_child(&mut fixture.child, Duration::from_secs(2)).is_none() {
            if let Err(error) = signal_identity(&fixture.identity, libc::SIGKILL) {
                errors.push(error);
            }
            if wait_child(&mut fixture.child, Duration::from_secs(2)).is_none() {
                errors.push("host fixture survived cleanup".to_owned());
            }
        }
        if let Some(pid) = pid
            && let Ok(Some(_)) = process_identity(pid)
        {
            errors.push("host fixture survived cleanup".to_owned());
        }
    }
    match list_catalog(work, binary, Some(deadline)) {
        Ok(remaining) if !remaining.is_empty() => errors.push(format!(
            "run catalog not empty (unowned entries retained): {remaining:?}"
        )),
        Ok(_) => {}
        Err(error) => errors.push(error),
    }
    for launch in launches {
        let live_auxiliaries = launch.auxiliaries().iter().any(|identity| {
            identity
                .get("pid")
                .and_then(Value::as_u64)
                .and_then(|pid| u32::try_from(pid).ok())
                .and_then(|pid| process_identity(pid).ok().flatten())
                .is_some()
        });
        if live_auxiliaries {
            errors.push(format!(
                "live launch auxiliary after run cleanup: {}",
                launch.ident()
            ));
        }
        match launch.alive() {
            Ok(live) if !live.is_empty() => errors.push(format!(
                "live identities after run cleanup: {}",
                launch.ident()
            )),
            Ok(_) => {}
            Err(error) => errors.push(error),
        }
        let sockets: Vec<PathBuf> = launch
            .names()
            .iter()
            .flat_map(|name| socket_paths(launch.root(), name))
            .collect();
        if sockets.iter().any(|path| path.exists()) {
            errors.push(format!(
                "owned sockets after run cleanup: {}",
                launch.ident()
            ));
        }
    }
    if let Err(error) = append_owned(
        work,
        &json!({"phase": "cleanup-run", "cleanup_errors": errors}),
    ) {
        errors.push(error);
    }
    errors
}

/// Wait for a child within a bound. `None` is the bound expiring.
fn wait_child(child: &mut Child, bound: Duration) -> Option<std::process::ExitStatus> {
    let until = Instant::now() + bound;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() >= until => return None,
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => return None,
        }
    }
}

/// The run's last cleanup, called from `orchestrate`'s `finally`.
///
/// A case removes its own record before it is scored, but an exception between a
/// PA case's seed and that removal would otherwise leave the file in
/// `work/home` — for a later case in this run to inherit, or for the operator to
/// find. It is `cleanup_pa2`, not `remove_allowances`, because PA2's writer
/// creates `allowances.lock` and never unlinks it.
pub fn final_cleanup(work: &Path) -> Vec<String> {
    let mut failures = remove_credentials(work);
    failures.extend(cleanup_pa2(work));
    failures
}

// --- Projects, hooks, credentials -------------------------------------------

/// The repository root, resolved from this crate, never from the cwd.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A case's project: the probe library and the fixture configuration the guest
/// reads. The tool catalog is discovered at `<cwd>/.agent-vm/config.toml`
/// (`config.rs`'s `PROJECT_CONFIG_RELATIVE`), not at a bare `.agent-vm.toml`.
pub fn prepare_project(work: &Path, project: &Path) -> Result<(), String> {
    let _ = work;
    fs::create_dir_all(project.join(".agent-vm"))
        .map_err(|error| format!("{}: {error}", project.display()))?;
    for (source, destination) in [
        ("egress-probe.sh", PathBuf::from("egress-probe.sh")),
        (
            "egress-config.toml",
            PathBuf::from(".agent-vm").join("config.toml"),
        ),
    ] {
        let from = repo_root().join("script/test/fixtures").join(source);
        let to = project.join(destination);
        fs::copy(&from, &to).map_err(|error| format!("{}: {error}", from.display()))?;
    }
    Ok(())
}

/// The HK cases' runtime hook: one probe through the fixture LAN, with the strict
/// variant's own failure command. `port` is the fixture port the hook dials, so a
/// boot-free control can hand it an ephemeral listener instead of 18080.
pub fn write_hook(work: &Path, name: &str, lan: &str, ident: &str, port: u16) {
    let project = work.join(name);
    let _ = prepare_project(work, &project);
    let failure = if name == "HK1" {
        "echo \"HOOK_EGRESS_DENIED\"; return 0"
    } else {
        "return 7"
    };
    // The two interpolated values are an IPv4 literal and a case ident; neither
    // can carry a shell metacharacter, so the Python's `shlex.quote` had nothing
    // to quote here.
    let hook = format!(
        "EGRESS_PROBE_LIB=1 . ./egress-probe.sh\n\
         if http_get {lan} {port} {ident}; then\n    \
         return 0\n\
         else\n    \
         rc=$?\n    \
         if [ \"$rc\" -eq 1 ]; then\n        \
         {failure}\n    \
         fi\n    \
         return \"$rc\"\n\
         fi\n"
    );
    let _ = fs::write(project.join(".agent-vm.runtime.sh"), hook);
}

/// The synthetic Anthropic OAuth seed the CR case launches with. It is never a
/// real credential: every value is fabricated and the file is mode 0600.
fn seed_credentials(work: &Path) -> Result<(), String> {
    let directory = work.join("home/.claude");
    fs::create_dir_all(&directory).map_err(|error| format!("{}: {error}", directory.display()))?;
    let seed = directory.join(".credentials.json");
    fs::write(
        &seed,
        json!({"claudeAiOauth": {
            "accessToken": "av302-synthetic-access",
            "refreshToken": "av302-synthetic-refresh",
            "expiresAt": 9_999_999_999_999u64,
            "scopes": ["user:inference"],
            "subscriptionType": "synthetic",
            "rateLimitTier": "synthetic",
        }})
        .to_string(),
    )
    .map_err(|error| format!("{}: {error}", seed.display()))?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&seed, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("{}: {error}", seed.display()))?;
    Ok(())
}

/// Remove the credential seed and the material a launch may have captured from
/// it. Only the CR project is touched, never another launch or the operator's
/// HOME.
pub fn remove_credentials(work: &Path) -> Vec<String> {
    let mut failures = Vec::new();
    let mut hasher = Sha256::new();
    hasher.update(work.join("creds").as_os_str().as_encoded_bytes());
    let digest: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let paths = [
        work.join("home/.claude/.credentials.json"),
        work.join("state")
            .join(format!("{}.secrets", &digest[..12]))
            .join("anthropic"),
    ];
    for path in paths {
        let removed = (|| -> Result<(), String> {
            // The captured material may never have existed: absence is the
            // expected state, so the containment check resolves the parent.
            crate::egress_witness::inside(&path, work)?;
            if path
                .symlink_metadata()
                .is_ok_and(|metadata| metadata.file_type().is_symlink())
            {
                return Err("credential material symlink refused".to_owned());
            }
            match fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(format!("{}: {error}", path.display())),
            }
        })();
        match removed {
            Ok(()) => {
                if path.exists() {
                    failures.push(format!("credential material remains: {}", path.display()));
                }
            }
            Err(error) => failures.push(error),
        }
    }
    failures
}

// --- Verdicts the validation-only rows read ---------------------------------

/// The exact `--allow-egress #1:` message for an RJ1 variant.
///
/// Mirrors `AllowanceError`'s Display and the host-side test
/// `allowance_rejections_report_exact_messages`; a native RJ1 pass therefore
/// cannot come from a clap error or an unrelated egress-worded failure.
pub const RJ1_VALUES: [(&str, &str); 7] = [
    ("udp-hostname", "udp://reject.invalid"),
    ("dns-port", "reject.invalid:53"),
    ("alias", "host.microsandbox.internal"),
    ("wildcard", "*.reject.invalid"),
    ("numeric-final", "1.2.3"),
    ("cidr-port", "{cidr}:18080"),
    ("scheme", "http://1.1.1.1:80"),
];

const NOT_A_HOSTNAME: &str = "not an IP address, CIDR or hostname (hostnames: one or more labels of \
ASCII letters, digits and '-', not ending in a numeric label; write non-ASCII names as A-labels; no \
wildcards)";

pub const RJ1_MESSAGES: [(&str, &str); 7] = [
    (
        "udp-hostname",
        "hostnames allow TLS over TCP only; use tcp://HOST:PORT, or an IP/CIDR for UDP",
    ),
    (
        "dns-port",
        "ports 53 and 853 carry the sandbox DNS path and cannot be hostname-allowed; use an IP/CIDR",
    ),
    (
        "alias",
        "host.microsandbox.internal is the sandbox host; use --allow-host",
    ),
    ("wildcard", NOT_A_HOSTNAME),
    ("numeric-final", NOT_A_HOSTNAME),
    (
        "cidr-port",
        "a port on a CIDR needs brackets, e.g. tcp://[10.0.0.0/24]:22",
    ),
    (
        "scheme",
        "unsupported scheme; use tcp:// or udp:// (or no scheme for all protocols)",
    ),
];

fn lookup<'a>(table: &'a [(&str, &str)], variant: &str) -> &'a str {
    table
        .iter()
        .find(|(key, _)| *key == variant)
        .map(|(_, value)| *value)
        .unwrap_or("")
}

pub fn rejection_diagnostic(variant: &str) -> String {
    format!("--allow-egress #1: {}", lookup(&RJ1_MESSAGES, variant))
}

/// A rejection is the exact diagnostic, a non-zero status, no guest output and no
/// echo of the value the operator supplied — except the alias message, which
/// legitimately names it.
pub fn validation_rejected(status: i32, text: &str, variant: &str) -> bool {
    let diagnostic = rejection_diagnostic(variant);
    let value = lookup(&RJ1_VALUES, variant);
    let echoed = !value.is_empty() && !diagnostic.contains(value) && text.contains(value);
    !matches!(status, 0 | 124 | 130 | 143)
        && !text.contains("CASE ")
        && text.contains(&diagnostic)
        && !echoed
}

/// HK2's strict hook must refuse *before* the tool runs, and say why.
pub fn strict_hook_rejected(text: &str) -> bool {
    !text.contains("CASE HK2 BEGIN") && text.contains(".agent-vm.runtime.sh failed (exit 7)")
}

// --- The archive -------------------------------------------------------------

/// The pinned release archive, by manifest identity and digest.
///
/// The manifest is the committed one, not the asset's copy of itself: an asset
/// directory whose `release.json` was edited to match a different archive would
/// otherwise verify against its own claim.
pub fn verified_archive(assets: &Path) -> Result<PathBuf, String> {
    let manifest_path = repo_root().join(RELEASE_MANIFEST);
    let manifest = fs::read(&manifest_path)
        .map_err(|error| format!("{}: {error}", manifest_path.display()))?;
    let supplied = fs::read(assets.join("release.json"))
        .map_err(|error| format!("{}: {error}", assets.join("release.json").display()))?;
    if supplied != manifest {
        return Err("release manifest differs from committed pin".to_owned());
    }
    let arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "amd64",
        other => return Err(format!("unsupported native architecture: {other}")),
    };
    let parsed: Value =
        serde_json::from_slice(&manifest).map_err(|error| format!("release manifest: {error}"))?;
    let platforms = parsed
        .get("platforms")
        .and_then(Value::as_array)
        .ok_or("release manifest has no platforms")?;
    let row = platforms
        .iter()
        .find(|row| {
            row.get("graph")
                .and_then(|graph| graph.get("architecture"))
                .and_then(Value::as_str)
                == Some(arch)
        })
        .ok_or_else(|| format!("release manifest has no {arch} platform"))?;
    let archive = row
        .get("archive")
        .ok_or("release manifest row has no archive")?;
    let name = archive
        .get("name")
        .and_then(Value::as_str)
        .ok_or("release manifest archive has no name")?;
    let path = assets.join(name);
    let mut hasher = Sha256::new();
    let mut file = fs::File::open(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut block = vec![0u8; 1 << 20];
    loop {
        use std::io::Read;
        let read = file
            .read(&mut block)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&block[..read]);
    }
    let digest: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let size = fs::metadata(&path)
        .map_err(|error| format!("{}: {error}", path.display()))?
        .len();
    let pinned = archive.get("sha256").and_then(Value::as_str);
    if pinned != Some(format!("sha256:{digest}").as_str())
        || archive.get("size").and_then(Value::as_u64) != Some(size)
    {
        return Err("pinned native archive digest/size mismatch".to_owned());
    }
    Ok(path)
}

// --- The verdict's joins -----------------------------------------------------

/// The candidate's post-loop control joins and the HN/OP gate. Returns whether a
/// blocker was found, with its rows, for the run's own receipt.
fn certify(state: &mut RunState) -> (bool, Vec<String>) {
    // Optional v6 denials never count without both exact positive controls.
    let v6_controls: Vec<usize> = state
        .results
        .iter()
        .enumerate()
        .filter(|(_, result)| matches!(result.case.case, "V6c" | "DNS6c"))
        .map(|(index, _)| index)
        .collect();
    let v6_sound = v6_controls.len() == 2
        && v6_controls
            .iter()
            .all(|index| state.results[*index].status == "PASS");
    for result in state.results.iter_mut() {
        if result.case.optional == "ipv6" && !v6_sound {
            result.status = "NOT RUN";
            result
                .failures
                .push("paired IPv6 positive controls unavailable".to_owned());
        }
    }
    // Optional rebind evidence is E-owned. If the guest forwarder returns no DNS
    // response at all for the rebind name (an indeterminate TIMEOUT, not a
    // denial), the group cannot be evaluated and is NOT RUN.
    let rebind_timeout = state
        .results
        .iter()
        .filter(|result| result.case.optional == "rebind")
        .flat_map(|result| result.attempts.iter())
        .filter_map(|row| row["output"].as_str())
        .flat_map(str::lines)
        .any(|line| line.starts_with("DNS ") && line.contains(" TIMEOUT"));
    if rebind_timeout {
        for result in state.results.iter_mut() {
            if result.case.optional == "rebind" {
                result.status = "NOT RUN";
                result.failures.push(
                    "guest forwarder returned no DNS response for the rebind name \
                     (rebind-unavailable; E-owned native evidence)"
                        .to_owned(),
                );
            }
        }
    }
    // Every deny needs its exact positive control, and a floor row needs both its
    // controls: a FAIL that came from a missing control is not a denial.
    let mut additions: Vec<(usize, Vec<String>)> = Vec::new();
    for (index, result) in state.results.iter().enumerate() {
        if result.status != "PASS" {
            continue;
        }
        let links = control_links(result.case);
        let mut failures = Vec::new();
        for row in &result.attempts {
            let expectation = row["expectation"].as_str().unwrap_or_default();
            if expectation != "1" && expectation != "NX" {
                continue;
            }
            let label = row["label"].as_str().unwrap_or_default();
            match links.iter().find(|(key, _)| key == label) {
                Some((_, target)) => {
                    let passed = state
                        .attempts
                        .get(target)
                        .is_some_and(|other| state.results[*other].status == "PASS");
                    if !passed {
                        failures.push(format!(
                            "missing/failed exact positive control: {label} -> {target}"
                        ));
                    }
                }
                None => failures.push(format!(
                    "missing/failed exact positive control: {label} -> -"
                )),
            }
        }
        if matches!(result.case.case, "FL1" | "FL2") {
            let mut targets = vec![
                links
                    .iter()
                    .find(|(key, _)| key == "floor")
                    .map(|(_, target)| target.clone())
                    .unwrap_or_default(),
            ];
            targets.push(
                if result.case.case == "FL2" {
                    "TP1:ipv4:lan-tcp80"
                } else {
                    "LC1:ipv4:lan-tcp80"
                }
                .to_owned(),
            );
            for target in targets {
                let passed = state
                    .attempts
                    .get(&target)
                    .is_some_and(|other| state.results[*other].status == "PASS");
                if !passed {
                    failures.push(format!("floor control failed: {target}"));
                }
            }
        }
        if !failures.is_empty() {
            additions.push((index, failures));
        }
    }
    for (index, failures) in additions {
        state.results[index].failures.extend(failures);
        state.results[index].status = "FAIL";
    }
    // ADR-0037 gate: a FAIL or NOT RUN in any OP row always blocks; in an HN row
    // only once HNc succeeds via the non-confounding admission (a)/(c).
    let rows: Vec<GateResult> = state
        .results
        .iter()
        .map(|result| GateResult {
            case: result.case.case,
            status: result.status,
        })
        .collect();
    fixtures::hostname_gate(state.hnc_step, &rows)
}

/// `summary.tsv`: one line per attempt, then the run's own two rows.
fn write_summary(
    work: &Path,
    request: &RunRequest,
    primary: i32,
    results: &[CaseResult],
    cleanup_errors: &[String],
) -> Result<(), String> {
    let mode = if request.smoke { "SMOKE" } else { "NATIVE" };
    let mut text =
        String::from("mode\tcase\tvariant\tattempt\tprotocol\tendpoint\tcontrol\tstatus\treason\n");
    for result in results {
        let links = control_links(result.case);
        let reason = result.failures.join("; ");
        if result.attempts.is_empty() {
            text.push_str(&format!(
                "{mode}\t{}\t{}\tcase\t-\t-\t-\t{}\t{reason}\n",
                result.case.case, result.case.variant, result.status
            ));
            continue;
        }
        for row in &result.attempts {
            let label = row["label"].as_str().unwrap_or_default();
            let control = links
                .iter()
                .find(|(key, _)| key == label)
                .map(|(_, target)| target.as_str())
                .unwrap_or("-");
            text.push_str(&format!(
                "{mode}\t{}\t{}\t{label}\t{}\t{}\t{control}\t{}\t{reason}\n",
                result.case.case,
                result.case.variant,
                row["protocol"].as_str().unwrap_or_default(),
                row["endpoint"].as_str().unwrap_or_default(),
                result.status
            ));
        }
    }
    text.push_str(&format!(
        "RUN\tprimary\t-\t-\t-\t-\t-\t{}\tstatus={primary}\n",
        if primary != 0 { "FAIL" } else { "PASS" }
    ));
    text.push_str(&format!(
        "RUN\tcleanup\t-\t-\t-\t-\t-\t{}\t{}\n",
        if cleanup_errors.is_empty() {
            "PASS"
        } else {
            "FAIL"
        },
        cleanup_errors.join("; ")
    ));
    fs::write(work.join("summary.tsv"), text).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress_cases::{CASES, IMAGE, SUPERVISOR};

    fn scratch(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("harness-run-{label}-{}", monotonic_nanos()));
        for directory in ["proj", "home", "config", "fx", "state/msb-home"] {
            fs::create_dir_all(path.join(directory)).expect("a scratch root");
        }
        path
    }

    fn case(name: &str, variant: &str) -> &'static Case {
        CASES
            .iter()
            .find(|case| case.case == name && case.variant == variant)
            .expect("a catalogue row")
    }

    fn command(work: &Path, name: &str, variant: &str) -> Command {
        Command {
            case: name.to_owned(),
            variant: variant.to_owned(),
            tool: None,
            kind: "guest".to_owned(),
            env: base_environment(work),
            argv: vec![work.join("fake-agent-vm").to_string_lossy().into_owned()],
            cwd: work.join("proj").to_string_lossy().into_owned(),
            timeout: 30.0,
            grace: 5.0,
            declared_extras: Vec::new(),
            prerequisites: Vec::new(),
            controls: None,
            setup: Vec::new(),
            expected_attempts: Vec::new(),
            attempt_expectations: None,
            attempt_protocols: None,
            supervisor: SUPERVISOR.to_owned(),
        }
    }

    #[test]
    fn the_guest_attempt_inventory_is_read_from_the_log_and_joined_to_the_plan() {
        let text = "\
CASE LC1 BEGIN
ATTEMPT LC1 lan-tcp80 tcp 192.168.1.2 18080 0 LC1-ipv4-0-receipt EXTRA detail
HTTP_OK LC1-ipv4-0-receipt
ATTEMPT LC1 lan-udp80 udp 192.168.1.2 18080 1 LC1-ipv4-1-receipt
UDP_NOACK LC1-ipv4-1-receipt
CASE LC1 END
";
        let rows = attempts_for(case("LC1", "ipv4"), "LC1-ipv4", text).expect("a good log");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["key"], "LC1:ipv4:lan-tcp80");
        assert_eq!(rows[0]["detail"], "EXTRA detail");
        // The row's output is its own block: what follows it, up to the next one.
        assert_eq!(rows[0]["output"], "HTTP_OK LC1-ipv4-0-receipt\n");
        // Everything after the last attempt belongs to it, the END marker too.
        assert_eq!(
            rows[1]["output"],
            "UDP_NOACK LC1-ipv4-1-receipt\nCASE LC1 END\n"
        );
        // A line that belongs to another case is malformed, not ignored.
        let wrong = text.replace("ATTEMPT LC1 lan-udp80", "ATTEMPT LC2 lan-udp80");
        assert_eq!(
            attempts_for(case("LC1", "ipv4"), "LC1-ipv4", &wrong),
            Err("malformed guest attempt".to_owned())
        );
        let truncated = "ATTEMPT LC1 lan-tcp80 tcp\n";
        assert!(attempts_for(case("LC1", "ipv4"), "LC1-ipv4", truncated).is_err());
        // An HK case also expects its hook row, which carries the whole log.
        let hook = attempts_for(case("HK1", "ipv4"), "HK1-ipv4", "CASE HK1 BEGIN\n").expect("rows");
        assert_eq!(hook[0]["label"], "hook");
        assert_eq!(hook[0]["expectation"], "1");
        assert_eq!(hook[0]["receipt"], "HK1-ipv4-hook");
        let recovered = attempts_for(case("HK1c", "ipv4"), "HK1-ipv4", "").expect("rows");
        assert_eq!(recovered[0]["expectation"], "0");
    }

    #[test]
    fn the_attempt_inventory_notices_a_missing_duplicate_or_renamed_attempt() {
        let work = scratch("inventory");
        let mut plan = command(&work, "LC1", "ipv4");
        plan.expected_attempts = vec!["lan-tcp80".to_owned(), "lan-udp80".to_owned()];
        plan.attempt_expectations = Some(vec![
            ("lan-tcp80".to_owned(), "0".to_owned()),
            ("lan-udp80".to_owned(), "1".to_owned()),
        ]);
        plan.attempt_protocols = Some(vec![
            ("lan-tcp80".to_owned(), "tcp".to_owned()),
            ("lan-udp80".to_owned(), "udp".to_owned()),
        ]);
        let row = |label: &str, protocol: &str, expectation: &str| {
            json!({
                "label": label, "protocol": protocol, "expectation": expectation,
                "endpoint": "192.168.1.2", "port": "18080", "receipt": "r", "detail": "",
                "key": label, "output": "",
            })
        };
        assert_eq!(
            check_attempt_inventory(
                &plan,
                &[row("lan-tcp80", "tcp", "0"), row("lan-udp80", "udp", "1")]
            ),
            Vec::<String>::new()
        );
        // Reordered, duplicated, renamed, and a changed expectation or protocol
        // are each their own finding: the plan is the independent inventory.
        let reordered = check_attempt_inventory(
            &plan,
            &[row("lan-udp80", "udp", "1"), row("lan-tcp80", "tcp", "0")],
        );
        assert_eq!(
            reordered,
            ["missing, duplicate or reordered guest attempts".to_owned()]
        );
        let renamed = check_attempt_inventory(
            &plan,
            &[row("lan-tcp80", "tcp", "0"), row("lan-udp81", "udp", "1")],
        );
        assert_eq!(renamed.len(), 3, "{renamed:?}");
        let changed = check_attempt_inventory(
            &plan,
            &[row("lan-tcp80", "udp", "1"), row("lan-udp80", "udp", "1")],
        );
        assert_eq!(
            changed,
            [
                "attempt expectation changed: lan-tcp80".to_owned(),
                "attempt protocol changed: lan-tcp80".to_owned()
            ]
        );
        let _ = fs::remove_dir_all(&work);
    }

    #[test]
    fn a_denial_needs_the_fixture_receipt_that_never_came() {
        let work = scratch("attempts");
        // A real deny: the guest saw no ack and the fixture has no receipt. The
        // absence is the whole bound (1), which is why the wait is not shortcut.
        let denied = json!({
            "label": "lan-udp80", "protocol": "udp", "endpoint": "192.168.1.2",
            "port": "18080", "expectation": "1", "receipt": "LC1-ipv4-1",
            "detail": "", "key": "k1", "output": "UDP_NOACK LC1-ipv4-1\n",
        });
        assert_eq!(
            check_attempts(&work, case("LC1", "ipv4"), &[denied], 0),
            Vec::<String>::new()
        );
        // The same absence claimed as an allow is a mismatch.
        let wrong = json!({
            "label": "lan-udp80", "protocol": "udp", "expectation": "0",
            "receipt": "LC1-ipv4-1", "output": "UDP_ACK LC1-ipv4-1\n",
            "endpoint": "192.168.1.2", "port": "18080", "detail": "", "key": "k1",
        });
        assert_eq!(
            check_attempts(&work, case("LC1", "ipv4"), &[wrong], 0),
            ["receipt/probe mismatch: lan-udp80".to_owned()]
        );
        // A hostname receipt is matched by port, peer and payload, and a plain
        // TCP record where a TLS one was expected is a failure of its own.
        fs::write(
            work.join("fx").join(fixtures::RECEIPTS_NAME),
            "tls 18443 127.0.0.1 hn1.fixture\n",
        )
        .expect("receipts");
        let matching = json!({
            "label": "hn1a-18443", "protocol": "tls", "endpoint": "127.0.0.1",
            "port": "18443", "expectation": "0", "receipt": "r",
            "detail": "hn1.fixture", "key": "k2", "output": "",
        });
        assert_eq!(
            check_attempts(
                &work,
                case("HN1", "ipv4"),
                std::slice::from_ref(&matching),
                0
            ),
            Vec::<String>::new()
        );
        let mut other = matching.clone();
        other["detail"] = json!("other.fixture");
        assert_eq!(
            check_attempts(&work, case("HN1", "ipv4"), &[other], 0),
            ["missing hostname receipt: hn1a-18443".to_owned()]
        );
        let matching_again = matching.clone();
        // Scoping is what keeps a control's identical payload out of this case.
        assert_eq!(
            check_attempts(&work, case("HN1", "ipv4"), &[matching_again], 1),
            ["missing hostname receipt: hn1a-18443".to_owned()]
        );
        let plain = json!({
            "label": "hn3-plain", "protocol": "tls", "endpoint": "127.0.0.1",
            "port": "18443", "expectation": "1", "receipt": "r",
            "detail": "x", "key": "k3", "output": "",
        });
        fs::write(
            work.join("fx").join(fixtures::RECEIPTS_NAME),
            "tcp-plain 18443 127.0.0.1 48656c6c6f\n",
        )
        .expect("receipts");
        assert_eq!(
            check_attempts(&work, case("HN3", "ipv4"), &[plain], 0),
            ["unexpected hostname receipt: hn3-plain".to_owned()]
        );
        // An unknown protocol is refused rather than passed.
        let unknown = json!({
            "label": "x", "protocol": "quic", "expectation": "0", "receipt": "r",
            "endpoint": "e", "port": "1", "detail": "", "key": "k4", "output": "",
        });
        assert_eq!(
            check_attempts(&work, case("LC1", "ipv4"), &[unknown], 0),
            ["unknown attempt protocol: quic".to_owned()]
        );
        let _ = fs::remove_dir_all(&work);
    }

    #[test]
    fn a_catalog_that_cannot_be_read_is_a_cleanup_failure() {
        let work = scratch("cleanup");
        let candidate = work.join("fake-agent-vm");
        // Every CLI verb fails, including the private `list`, so the cleanup
        // cannot read back what is left. That must be reported, never read as an
        // empty catalog.
        fs::write(
            &candidate,
            "#!/bin/sh\necho 'no such sandbox' >&2\nexit 1\n",
        )
        .expect("a candidate");
        let plan = command(&work, "LC1", "ipv4");
        let launch = OwnedLaunch::new(&work, &plan, "LC1-ipv4-0".to_owned()).expect("a launch");
        let errors = cleanup_run(&work, &plan.argv[0], std::slice::from_ref(&launch), None);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("status 1") || error.contains("list")),
            "{errors:?}"
        );
        // Every admin verb in this control fails before it runs (the shim is this
        // test binary, not the harness CLI), which is the point: the cleanup
        // cannot read the catalog back, so it says so instead of reporting an
        // empty one. The receipt the run's own report reads back carries them.
        assert!(
            errors
                .iter()
                .any(|error| error.contains("cleanup survivors")
                    || error.contains("private list")
                    || error.contains("exec-shim")
                    || error.contains("status 2")),
            "{errors:?}"
        );
        let receipts = fs::read_to_string(work.join("owned.jsonl")).expect("own receipts");
        assert!(receipts.contains("\"phase\":\"cleanup-run\""), "{receipts}");
        let _ = fs::remove_dir_all(&work);
    }

    #[test]
    fn the_run_finally_removes_a_credential_seed_and_a_leftover_allowance() {
        let work = scratch("final");
        seed_credentials(&work).expect("a synthetic seed");
        let seed = work.join("home/.claude/.credentials.json");
        assert!(seed.exists());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&seed).expect("the seed").permissions().mode() & 0o777,
            0o600
        );
        // A record left by a case that died between its seed and its removal, and
        // the lock PA2's own writer leaves, are both this cleanup's to remove.
        let store = work.join("home/.config/agent-vm");
        fs::create_dir_all(&store).expect("the authority directory");
        fs::write(store.join("allowances.json"), "{}").expect("a leftover record");
        fs::write(store.join("allowances.lock"), "").expect("the writer's lock");
        assert_eq!(final_cleanup(&work), Vec::<String>::new());
        assert!(!seed.exists());
        assert!(!store.join("allowances.json").exists());
        assert!(!store.join("allowances.lock").exists());
        let _ = fs::remove_dir_all(&work);
    }

    #[test]
    fn a_validation_rejection_is_the_exact_diagnostic_and_never_the_echoed_value() {
        // The alias message legitimately names the input; every other variant must
        // not echo it, so the input's disappearance is what makes the pass real.
        let text = rejection_diagnostic("alias");
        assert!(validation_rejected(1, &text, "alias"), "{text}");
        assert!(text.contains("--allow-egress #1: "));
        for variant in ["wildcard", "numeric-final", "cidr-port", "scheme"] {
            let diagnostic = rejection_diagnostic(variant);
            assert!(diagnostic.starts_with("--allow-egress #1: "), "{variant}");
            assert!(!lookup(&RJ1_VALUES, variant).is_empty(), "{variant}");
            // The right diagnostic passes; the same diagnostic next to the echoed
            // value does not, and neither does a different variant's message.
            assert!(validation_rejected(1, &diagnostic, variant), "{variant}");
            let echoed = format!("{diagnostic}\n{}", lookup(&RJ1_VALUES, variant));
            assert!(!validation_rejected(1, &echoed, variant), "{variant}");
            assert!(!validation_rejected(1, &diagnostic, "scheme") || variant == "scheme");
            // No guest ran, and a timeout or a signal is not a rejection.
            for status in [0, 124, 130, 143] {
                assert!(
                    !validation_rejected(status, &diagnostic, variant),
                    "{status}"
                );
            }
            assert!(!validation_rejected(
                1,
                &format!("{diagnostic}\nCASE RJ1"),
                variant
            ));
        }
        // The strict hook's refusal must predate the tool's own marker.
        assert!(!strict_hook_rejected(
            "CASE HK2 BEGIN\n.agent-vm.runtime.sh failed (exit 7)"
        ));
        assert!(strict_hook_rejected(".agent-vm.runtime.sh failed (exit 7)"));
        assert!(!strict_hook_rejected("CASE HK2 BEGIN"));
    }

    #[test]
    fn a_release_archive_must_be_the_pinned_one_not_the_assets_own_claim() {
        let assets = std::env::temp_dir().join(format!("harness-assets-{}", monotonic_nanos()));
        fs::create_dir_all(&assets).expect("an assets directory");
        // No manifest at all, and a manifest that is not the committed one, are
        // both refusals.
        assert!(verified_archive(&assets).is_err());
        fs::write(assets.join("release.json"), "{\"platforms\":[]}").expect("a manifest");
        assert_eq!(
            verified_archive(&assets),
            Err("release manifest differs from committed pin".to_owned())
        );
        // With the committed manifest in place, an archive whose bytes are not the
        // pinned ones is refused by digest and size.
        let manifest = fs::read(repo_root().join(RELEASE_MANIFEST)).expect("the committed pin");
        fs::write(assets.join("release.json"), &manifest).expect("the committed pin");
        let parsed: Value = serde_json::from_slice(&manifest).expect("JSON");
        let arch = if std::env::consts::ARCH == "aarch64" {
            "arm64"
        } else {
            "amd64"
        };
        let row = parsed["platforms"]
            .as_array()
            .expect("platforms")
            .iter()
            .find(|row| row["graph"]["architecture"] == arch)
            .expect("this host's platform");
        let name = row["archive"]["name"].as_str().expect("an archive name");
        fs::write(assets.join(name), b"not the pinned archive").expect("a wrong archive");
        assert_eq!(
            verified_archive(&assets),
            Err("pinned native archive digest/size mismatch".to_owned())
        );
        let _ = fs::remove_dir_all(&assets);
    }

    #[test]
    fn the_fixture_lan_and_the_second_address_are_narrowed_before_use() {
        for (lan, accepted) in [
            ("10.1.2.3", true),
            ("172.16.0.1", true),
            ("172.31.255.254", true),
            ("172.32.0.1", false),
            ("192.168.1.2", true),
            ("100.64.0.1", true),
            ("100.128.0.1", false),
            ("203.0.113.9", false),
            ("127.0.0.1", false),
            ("not-an-address", false),
        ] {
            assert_eq!(is_private(lan), accepted, "{lan}");
        }
        assert_eq!(resolve_second_address("192.0.2.2"), "192.0.2.2");
        assert_eq!(resolve_second_address("127.0.0.1"), "");
        assert_eq!(resolve_second_address("::1"), "");
        assert_eq!(resolve_second_address(""), "");
        // The HP4 calibration must not accept a reserved address as public.
        for (address, public) in [
            ("93.184.216.34", true),
            ("203.0.113.10", false),
            ("192.0.2.1", false),
            ("198.51.100.7", false),
            ("10.0.0.1", false),
            ("100.64.0.1", false),
            ("198.18.0.1", false),
            ("240.0.0.1", false),
            ("169.254.1.1", false),
        ] {
            assert_eq!(
                is_global(address.parse().expect("an address")),
                public,
                "{address}"
            );
        }
    }

    #[test]
    fn a_case_project_is_the_probe_library_and_the_discovered_catalog() {
        let work = scratch("project");
        let project = work.join("proj");
        prepare_project(&work, &project).expect("a project");
        // The catalog is discovered beside the probe, under `.agent-vm/`.
        assert!(project.join("egress-probe.sh").exists());
        assert!(project.join(".agent-vm/config.toml").exists());
        // The hook is one probe through the LAN with the strict variant's own
        // failure command.
        write_hook(&work, "HK2", "192.168.1.2", "HK2-ipv4-0-hook", 18080);
        let hook = fs::read_to_string(work.join("HK2/.agent-vm.runtime.sh")).expect("a hook");
        assert!(
            hook.contains("if http_get 192.168.1.2 18080 HK2-ipv4-0-hook; then"),
            "{hook}"
        );
        assert!(hook.contains("        return 7"), "{hook}");
        write_hook(&work, "HK1", "192.168.1.2", "HK1-ipv4-0-hook", 18080);
        let recovered = fs::read_to_string(work.join("HK1/.agent-vm.runtime.sh")).expect("a hook");
        assert!(
            recovered.contains("echo \"HOOK_EGRESS_DENIED\"; return 0"),
            "{recovered}"
        );
        let _ = fs::remove_dir_all(&work);
    }

    #[test]
    fn the_summary_reports_the_run_and_the_cleanup_separately() {
        let work = scratch("summary");
        let request = RunRequest {
            binary: "/absolute/bundle/bin/agent-vm".to_owned(),
            assets: "/assets".to_owned(),
            lan: "192.168.1.2".to_owned(),
            rebind: None,
            lan2: None,
            smoke: false,
        };
        let pass = CaseResult {
            case: case("LC1", "ipv4"),
            status: "PASS",
            failures: Vec::new(),
            attempts: vec![json!({
                "label": "lan-tcp80", "protocol": "tcp", "endpoint": "192.168.1.2",
            })],
        };
        let not_run = CaseResult::not_run(case("HN1", "ipv4"), "no evidence".to_owned());
        write_summary(
            &work,
            &request,
            1,
            &[pass, not_run],
            &["a survivor".to_owned()],
        )
        .expect("a summary");
        let summary = fs::read_to_string(work.join("summary.tsv")).expect("a summary");
        let lines: Vec<&str> = summary.lines().collect();
        assert_eq!(
            lines[0],
            "mode\tcase\tvariant\tattempt\tprotocol\tendpoint\tcontrol\tstatus\treason"
        );
        assert!(
            lines[1].starts_with("NATIVE\tLC1\tipv4\tlan-tcp80\ttcp\t192.168.1.2\t"),
            "{}",
            lines[1]
        );
        assert!(
            lines[2].starts_with("NATIVE\tHN1\tipv4\tcase\t-\t-\t-\tNOT RUN\tno evidence"),
            "{}",
            lines[2]
        );
        assert_eq!(lines[3], "RUN\tprimary\t-\t-\t-\t-\t-\tFAIL\tstatus=1");
        assert_eq!(lines[4], "RUN\tcleanup\t-\t-\t-\t-\t-\tFAIL\ta survivor");
        // The plan row's own image and supervisor are the ones this run used.
        assert_eq!(IMAGE, "av302:egress");
        let _ = fs::remove_dir_all(&work);
    }
}
