//! The ignored native driver for Phase 0 (plan P0-A..P0-F).
//!
//! Invoked only through `script/test/cpu-commitment-native.sh`, which owns the isolated build,
//! the explicit `MSB_PATH`/`MSB_LIBKRUNFW_PATH` pair, the fresh runtime `MSB_HOME` and the
//! retained evidence directory. This module performs one owned live sandbox at a time,
//! records every attempted read in original order, and writes `PASS` only when every declared
//! gate passed **and** owned cleanup succeeded.
//!
//! No production behaviour: `main.rs` declares the module under `#[cfg(test)]`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use microsandbox::MicrosandboxError;
use microsandbox::sandbox::{
    PullPolicy, ResourceConvergenceState, ResourceKind, Sandbox, SandboxMetrics,
    SandboxModificationPlan,
};
use microsandbox_runtime::control::{ControlRequest, ControlResponse, CpuControlState};
use microsandbox_runtime::ipc::RuntimeSocketPaths;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;

use super::analyze::{
    self, HostSample, PollRecord, ProcessDelta, SuiteVerdict, TrialSpec, WorkloadCheckpoint,
    WorkloadReport, calibration_matrix,
};

const METRICS_INTERVAL: Duration = Duration::from_millis(200);
const SETTLING_AND_COUNTED_ROWS: usize =
    analyze::SETTLING_DISTINCT_ROWS + analyze::COUNTED_DISTINCT_ROWS;
const IMAGE_ACQUIRE_DEADLINE: Duration = Duration::from_secs(300);
/// Readiness, convergence and lifecycle bounds (P0-B, §3.2).
const READY_DEADLINE: Duration = Duration::from_secs(10);
const CPU_CONVERGENCE_DEADLINE: Duration = Duration::from_secs(10);
const LIFECYCLE_TTL: Duration = Duration::from_secs(1);
const LIFECYCLE_TIMEOUT: Duration = Duration::from_millis(50);
const CONTROL_DEADLINE: Duration = Duration::from_secs(5);
const CONTROL_RESPONSE_BOUND: u64 = 1 << 20;
const COLLECTION_POLL_BUDGET: Duration = Duration::from_secs(240);
const HOST_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
const WORKLOAD_DURATION_SECONDS: u64 = 150;

pub(crate) struct NativeReport {
    pub verdict: &'static str,
    pub detail: String,
}

#[derive(Debug)]
enum Gate {
    /// A prerequisite is missing or a declared bound could not be established.
    Inconclusive(String),
    /// A qualified measurement violated a predeclared criterion.
    Fail(String),
    /// Invocation or evidence-directory misuse (exit 2).
    Misuse(String),
}

impl Gate {
    fn verdict(&self) -> &'static str {
        match self {
            Gate::Inconclusive(_) => "INCONCLUSIVE",
            Gate::Fail(_) => "FAIL",
            Gate::Misuse(_) => "MISUSE",
        }
    }

    fn detail(&self) -> &str {
        match self {
            Gate::Inconclusive(reason) | Gate::Fail(reason) | Gate::Misuse(reason) => reason,
        }
    }
}

impl From<anyhow::Error> for Gate {
    fn from(error: anyhow::Error) -> Self {
        Gate::Inconclusive(format!("{error:#}"))
    }
}

pub(crate) async fn run() -> NativeReport {
    let evidence = std::env::var_os("AGENT_VM_CPU_EVIDENCE_DIR").map(PathBuf::from);
    let outcome = run_attested(evidence.clone()).await;
    let report = match outcome {
        Ok(()) => NativeReport {
            verdict: "PASS",
            detail: "every declared Phase 0 gate passed".to_string(),
        },
        Err(gate) => NativeReport {
            verdict: gate.verdict(),
            detail: gate.detail().to_string(),
        },
    };
    if let Some(dir) = evidence {
        // Evidence retention outranks the harness exiting: a status file is written even when
        // the directory cannot hold `PASS`.
        let _ = write_status(&dir, &report);
    }
    report
}

/// The attested runtime pair and the evidence root. Loaded before any VM exists.
struct Config {
    evidence: PathBuf,
    mode: Mode,
    msb: PathBuf,
    firmware: PathBuf,
    runtime_identity: String,
    vendor_sha: String,
    agent_sha: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Calibration,
    Integrated,
}

#[derive(Deserialize)]
struct Manifest {
    msb_path: String,
    msb_sha256: String,
    firmware_path: String,
    firmware_sha256: String,
    agent_sha: String,
    vendor_sha: String,
    clean_firmware_rebuild: String,
}

async fn run_attested(evidence: Option<PathBuf>) -> Result<(), Gate> {
    let config = load_config(evidence)?;
    let evidence = Evidence::new(&config.evidence)?;
    evidence.write_json(
        "environment.json",
        &json!({
            "mode": match config.mode { Mode::Calibration => "calibration", Mode::Integrated => "integrated" },
            "msb_path": config.msb,
            "firmware_path": config.firmware,
            "vendor_sha": config.vendor_sha,
            "agent_sha": config.agent_sha,
            "image": crate::defaults::INITIAL_DEFAULT_IMAGE_REF,
            "metrics_interval_ms": METRICS_INTERVAL.as_millis(),
            "clean_firmware_rebuild": "UNPROVEN",
        }),
    )?;
    if config.mode == Mode::Integrated {
        return integrated_body(&config, &evidence).await;
    }
    verify_image_cache()?;
    let image_started = Instant::now();
    let mut gates: Vec<serde_json::Value> = Vec::new();
    let outcome = collect(&config, &evidence, &mut gates, image_started).await;
    evidence.write_json("gate-verdicts.json", &gates)?;
    outcome
}

// ---------------------------------------------------------------------------
// Integrated mode (plan §7.3): the production monitor against a real sandbox
// ---------------------------------------------------------------------------

/// Per-workload observation deadline. A real run is never a deterministic assertion, so a
/// missed step is reported with raw samples rather than retried or relaxed.
const INTEGRATED_BUDGET: Duration = Duration::from_secs(60);
const INTEGRATED_HIGH_WORKERS: u8 = 4;
const INTEGRATED_LOW_WORKERS: u8 = 1;
/// Low **positive** duty: enough to be a real measurement, low enough to reclaim.
const INTEGRATED_LOW_DUTY: u8 = 50;

/// Attach the production `ResourceCeiling::monitor` to a fresh 1-of-4 sandbox and observe the
/// enforced CPU commitment under a full-demand workload and then a low positive one.
async fn integrated_body(config: &Config, evidence: &Evidence) -> Result<(), Gate> {
    verify_image_cache()?;
    let name = format!("c647-integrated-{}", std::process::id());
    let vm = create_vm(config, &name, 1, 4, 512, 1024).await?;
    let observed = integrated_session(&vm, evidence).await;
    let cleanup = vm.shutdown().await;
    evidence.write_json(
        "integrated-cleanup.json",
        &json!({
            "sandbox": name,
            "cleanup": match &cleanup {
                Ok(()) => "ok".to_string(),
                Err(error) => error.clone(),
            },
        }),
    )?;
    if let Err(error) = cleanup {
        return Err(Gate::Fail(format!(
            "FAIL: the owned sandbox did not clean up: {error}"
        )));
    }
    observed
}

async fn integrated_session(vm: &LiveVm, evidence: &Evidence) -> Result<(), Gate> {
    install_workload(&vm.sandbox).await?;
    let boot_id_before =
        guest_exec(&vm.sandbox, "cat", &["/proc/sys/kernel/random/boot_id"]).await?;
    // The production eligibility path (`Sandbox::pause_state`) takes a transition guard and a
    // run-matched control session, so time it directly and record the result before any
    // conclusion is drawn from a silent axis.
    probe_pause_state(vm, evidence).await?;
    let ceiling = crate::resources::ResourceCeiling::from_launch_options(1, 4)
        .map_err(|error| Gate::Inconclusive(format!("INCONCLUSIVE: {error:#}")))?;
    install_poll_capture();
    let monitor = ceiling.monitor(&vm.sandbox);
    let session = async {
        let boot = control_cpu(&vm.sandbox).await?;
        start_workload(vm, "high", INTEGRATED_HIGH_WORKERS, 100).await?;
        let (high_sequence, high_samples, high_reached) = observe_enforced(vm, 4, "high").await?;
        stop_workers(&vm.sandbox, "high").await?;
        start_workload(vm, "low", INTEGRATED_LOW_WORKERS, INTEGRATED_LOW_DUTY).await?;
        let (low_sequence, low_samples, low_reached) = observe_enforced(vm, 1, "low").await?;
        stop_workers(&vm.sandbox, "low").await?;
        Ok::<_, Gate>((
            boot,
            high_sequence,
            high_samples,
            high_reached,
            low_sequence,
            low_samples,
            low_reached,
        ))
    }
    .await;
    monitor.stop().await;
    flush_poll_capture(evidence)?;
    let (boot, high_sequence, high_samples, high_reached, low_sequence, low_samples, low_reached) =
        session?;
    let boot_id_after =
        guest_exec(&vm.sandbox, "cat", &["/proc/sys/kernel/random/boot_id"]).await?;

    evidence.write_json(
        "integrated-high.json",
        &json!({
            "expected": [1, 2, 3, 4],
            "observed_enforced": high_sequence,
            "initial_possible": boot.possible,
            "initial_enforced": boot.enforced,
            "samples": high_samples,
        }),
    )?;
    evidence.write_json(
        "integrated-low.json",
        &json!({
            "expected": [4, 3, 2, 1],
            "observed_enforced": low_sequence,
            "duty_percent": INTEGRATED_LOW_DUTY,
            "samples": low_samples,
        }),
    )?;
    evidence.write_json(
        "integrated-identity.json",
        &json!({
            "runtime_identity": config_identity(&vm.name),
            "boot_id_before": boot_id_before.trim(),
            "boot_id_after": boot_id_after.trim(),
            "possible": boot.possible,
        }),
    )?;

    if boot_id_before.trim() != boot_id_after.trim() {
        return Err(Gate::Fail(
            "FAIL: the guest boot identity changed during the run (runtime replacement)".into(),
        ));
    }
    if !high_reached {
        return Err(Gate::Fail(format!(
            "FAIL: the high-demand workload did not reach 4 enforced vCPU within {} s; \
             observed {high_sequence:?} (raw samples retained)",
            INTEGRATED_BUDGET.as_secs()
        )));
    }
    if !low_reached {
        return Err(Gate::Fail(format!(
            "FAIL: the low-positive-demand workload did not reach 1 enforced vCPU within {} s; \
             observed {low_sequence:?} (raw samples retained)",
            INTEGRATED_BUDGET.as_secs()
        )));
    }
    expect_steps(&high_sequence, &[1, 2, 3, 4], "high-demand")?;
    expect_steps(&low_sequence, &[4, 3, 2, 1], "low-positive-demand")?;
    Ok(())
}

/// A stable label for the run: the sandbox name plus the ceiling this mode declares.
fn config_identity(name: &str) -> String {
    format!("{name}:1..=4cpus:512..=1024MiB")
}

/// Time five direct `pause_state()` calls and record result plus latency.
async fn probe_pause_state(vm: &LiveVm, evidence: &Evidence) -> Result<(), Gate> {
    let mut samples = Vec::new();
    for _ in 0..5 {
        let started = Instant::now();
        let reply = vm.sandbox.pause_state().await;
        let elapsed_us = started.elapsed().as_micros() as u64;
        let (result, detail) = match &reply {
            Ok(state) => (
                if state.paused || state.recovery_required {
                    "not_running"
                } else {
                    "running"
                },
                format!(
                    "paused={} recovery_required={}",
                    state.paused, state.recovery_required
                ),
            ),
            Err(error) => ("unavailable", format!("{error:#}")),
        };
        samples.push(json!({
            "elapsed_us": elapsed_us,
            "result": result,
            "detail": detail,
        }));
    }
    let slowest = samples
        .iter()
        .filter_map(|sample| sample["elapsed_us"].as_u64())
        .max()
        .unwrap_or_default();
    let all_running = samples
        .iter()
        .all(|sample| sample["result"] == json!("running"));
    evidence.write_json(
        "integrated-pause-state.json",
        &json!({
            "samples": samples,
            "slowest_us": slowest,
            "driver_bound_ms": 50,
            "all_running": all_running,
        }),
    )?;
    Ok(())
}

/// One debug record per driver poll, written to `integrated-polls.jsonl`.
struct PollCapture;

struct PollCaptureState {
    lines: std::sync::Mutex<Vec<serde_json::Value>>,
}

static POLL_CAPTURE: std::sync::OnceLock<&'static PollCaptureState> = std::sync::OnceLock::new();

impl tracing::Subscriber for PollCapture {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target() == "agent_vm::resources"
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        struct Visitor<'a>(&'a mut serde_json::Map<String, serde_json::Value>);
        impl tracing::field::Visit for Visitor<'_> {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                self.0
                    .insert(field.name().to_string(), json!(value.to_string()));
            }
            fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
                self.0.insert(field.name().to_string(), json!(value));
            }
            fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
                self.0.insert(field.name().to_string(), json!(value));
            }
            fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
                self.0.insert(field.name().to_string(), json!(value));
            }
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0
                    .insert(field.name().to_string(), json!(format!("{value:?}")));
            }
        }
        let mut record = serde_json::Map::new();
        let mut visitor = Visitor(&mut record);
        event.record(&mut visitor);
        record.insert("target".to_string(), json!(event.metadata().target()));
        if let Some(capture) = POLL_CAPTURE.get() {
            capture
                .lines
                .lock()
                .unwrap()
                .push(serde_json::Value::Object(record));
        }
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

fn install_poll_capture() {
    let state: &'static PollCaptureState = Box::leak(Box::new(PollCaptureState {
        lines: std::sync::Mutex::new(Vec::new()),
    }));
    let _ = POLL_CAPTURE.set(state);
    let _ = tracing::subscriber::set_global_default(PollCapture);
}

fn flush_poll_capture(evidence: &Evidence) -> Result<(), Gate> {
    let Some(state) = POLL_CAPTURE.get() else {
        return Ok(());
    };
    let lines = state.lines.lock().unwrap();
    for line in lines.iter() {
        evidence.append_jsonl("integrated-polls.jsonl", &line)?;
    }
    Ok(())
}

async fn start_workload(vm: &LiveVm, tag: &str, workers: u8, duty: u8) -> Result<(), Gate> {
    let dir = format!("{GUEST_DIR}/{tag}");
    guest_exec(&vm.sandbox, "mkdir", &["-p", &dir]).await?;
    let start = format!(
        "cd {GUEST_DIR} && python3 workload.py --daemonize --workers {workers} --duty {duty} \
         --duration {WORKLOAD_DURATION_SECONDS} --out {dir}/workload.jsonl \
         --ready {dir}/ready.json --pid {dir}/workload.pid --stop {GUEST_DIR}/stop \
         --log {dir}/workload.log"
    );
    guest_exec(&vm.sandbox, "sh", &["-c", &start]).await?;
    let deadline = Instant::now() + READY_DEADLINE;
    loop {
        let ready = guest_exec(
            &vm.sandbox,
            "sh",
            &[
                "-c",
                &format!("test -f {dir}/ready.json && echo ready || true"),
            ],
        )
        .await?;
        if ready.contains("ready") {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(Gate::Inconclusive(format!(
                "INCONCLUSIVE: {workers} {tag} workers never reported ready within {} s",
                READY_DEADLINE.as_secs()
            )));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Sample the runtime's enforced CPU count every nominal interval until it reaches `target`.
async fn observe_enforced(
    vm: &LiveVm,
    target: u32,
    _tag: &str,
) -> Result<(Vec<u32>, Vec<serde_json::Value>, bool), Gate> {
    let deadline = Instant::now() + INTEGRATED_BUDGET;
    let mut sequence: Vec<u32> = Vec::new();
    let mut samples = Vec::new();
    loop {
        let state = control_cpu(&vm.sandbox).await?;
        if sequence.last() != Some(&state.enforced) {
            sequence.push(state.enforced);
        }
        samples.push(json!({
            "at_ms": samples.len() as u64 * METRICS_INTERVAL.as_millis() as u64,
            "possible": state.possible,
            "requested_online": state.requested_online,
            "actual_online": state.actual_online,
            "enforced": state.enforced,
        }));
        if state.enforced == target {
            return Ok((sequence, samples, true));
        }
        if Instant::now() >= deadline {
            return Ok((sequence, samples, false));
        }
        tokio::time::sleep(METRICS_INTERVAL).await;
    }
}

/// Require exactly the declared one-step sequence, so a skipped or extra step is visible.
fn expect_steps(observed: &[u32], expected: &[u32], tag: &str) -> Result<(), Gate> {
    if observed == expected {
        Ok(())
    } else {
        Err(Gate::Fail(format!(
            "FAIL: {tag} enforced sequence {observed:?} is not exactly {expected:?}"
        )))
    }
}

fn load_config(evidence: Option<PathBuf>) -> Result<Config, Gate> {
    let evidence = evidence.ok_or_else(|| {
        Gate::Misuse(
            "AGENT_VM_CPU_EVIDENCE_DIR is required for the native evidence run".to_string(),
        )
    })?;
    let mode = match std::env::var("AGENT_VM_CPU_EVIDENCE_MODE").as_deref() {
        Ok("calibration") | Err(_) => Mode::Calibration,
        Ok("integrated") => Mode::Integrated,
        Ok(other) => {
            return Err(Gate::Misuse(format!(
                "unknown AGENT_VM_CPU_EVIDENCE_MODE {other:?}; expected calibration|integrated"
            )));
        }
    };
    let msb = required_path("MSB_PATH")?;
    let firmware = required_path("MSB_LIBKRUNFW_PATH")?;
    let manifest_path = evidence.join("runtime-manifest.json");
    let manifest: Manifest =
        serde_json::from_slice(&std::fs::read(&manifest_path).map_err(|error| {
            Gate::Inconclusive(format!(
                "INCONCLUSIVE: provenance manifest {} is unreadable: {error}",
                manifest_path.display()
            ))
        })?)
        .map_err(|error| {
            Gate::Inconclusive(format!(
                "INCONCLUSIVE: provenance manifest {} is malformed: {error}",
                manifest_path.display()
            ))
        })?;
    if manifest.clean_firmware_rebuild != "UNPROVEN" {
        return Err(Gate::Inconclusive(
            "INCONCLUSIVE: the manifest must state clean-from-source firmware rebuild UNPROVEN"
                .to_string(),
        ));
    }
    if manifest.agent_sha.len() != 40 || manifest.vendor_sha.len() != 40 {
        return Err(Gate::Inconclusive(
            "INCONCLUSIVE: the manifest lacks the pinned agent/vendor commits".to_string(),
        ));
    }
    for (label, path, declared) in [
        ("MSB_PATH", &msb, &manifest.msb_path),
        ("MSB_LIBKRUNFW_PATH", &firmware, &manifest.firmware_path),
    ] {
        let canonical = std::fs::canonicalize(path).map_err(|error| {
            Gate::Inconclusive(format!("INCONCLUSIVE: canonicalizing {label}: {error}"))
        })?;
        let declared_canonical = std::fs::canonicalize(declared).map_err(|error| {
            Gate::Inconclusive(format!(
                "INCONCLUSIVE: the manifest path {declared} is unusable: {error}"
            ))
        })?;
        if canonical != declared_canonical {
            return Err(Gate::Inconclusive(format!(
                "INCONCLUSIVE: {label} canonical path {} does not match the manifest {}",
                canonical.display(),
                declared_canonical.display()
            )));
        }
    }
    let msb_sha = sha256_file(&msb)?;
    let firmware_sha = sha256_file(&firmware)?;
    if msb_sha != manifest.msb_sha256.to_lowercase() {
        return Err(Gate::Inconclusive(format!(
            "INCONCLUSIVE: MSB_PATH {} has sha256 {msb_sha}, manifest says {}",
            msb.display(),
            manifest.msb_sha256
        )));
    }
    if firmware_sha != manifest.firmware_sha256.to_lowercase() {
        return Err(Gate::Inconclusive(format!(
            "INCONCLUSIVE: MSB_LIBKRUNFW_PATH {} has sha256 {firmware_sha}, manifest says {}",
            firmware.display(),
            manifest.firmware_sha256
        )));
    }
    Ok(Config {
        evidence,
        mode,
        msb,
        firmware,
        runtime_identity: format!("{msb_sha}:{firmware_sha}"),
        vendor_sha: manifest.vendor_sha,
        agent_sha: manifest.agent_sha,
    })
}

fn required_path(name: &str) -> Result<PathBuf, Gate> {
    let value = std::env::var_os(name).ok_or_else(|| {
        Gate::Inconclusive(format!(
            "INCONCLUSIVE: {name} is unset; the runtime pair must be explicit"
        ))
    })?;
    let path = PathBuf::from(value);
    if !path.is_file() {
        return Err(Gate::Inconclusive(format!(
            "INCONCLUSIVE: {name} points at {} which is not a file",
            path.display()
        )));
    }
    Ok(path)
}

fn verify_image_cache() -> Result<(), Gate> {
    let home = std::env::var_os("MSB_HOME").ok_or_else(|| {
        Gate::Inconclusive(
            "INCONCLUSIVE: MSB_HOME must point at the fresh runtime home".to_string(),
        )
    })?;
    let cache = PathBuf::from(home).join("cache");
    if !cache.is_dir() {
        return Err(Gate::Inconclusive(format!(
            "INCONCLUSIVE: the fresh MSB_HOME cache {} is missing; the operator-authorized cache \
             symlink was not created by the script",
            cache.display()
        )));
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, Gate> {
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("reading {}", path.display()))
        .map_err(Gate::from)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)
        .with_context(|| format!("hashing {}", path.display()))
        .map_err(Gate::from)?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn write_status(dir: &Path, report: &NativeReport) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let text = format!("{}: {}\n", report.verdict, report.detail);
    std::fs::write(dir.join("status.txt"), &text)?;
    if report.verdict == "PASS" {
        std::fs::write(dir.join("PASS"), &text)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Evidence writer
// ---------------------------------------------------------------------------

struct Evidence {
    root: PathBuf,
}

impl Evidence {
    fn new(root: &Path) -> Result<Self, Gate> {
        for sub in ["polls", "host", "workload", "analysis", "p0e"] {
            std::fs::create_dir_all(root.join(sub)).map_err(|error| {
                Gate::Misuse(format!(
                    "cannot create evidence subdirectory {sub} under {}: {error}",
                    root.display()
                ))
            })?;
        }
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    fn write_json<T: Serialize>(&self, name: &str, value: &T) -> Result<(), Gate> {
        let path = self.root.join(name);
        let text = serde_json::to_string_pretty(value)
            .with_context(|| format!("serializing {name}"))
            .map_err(Gate::from)?;
        std::fs::write(&path, text)
            .with_context(|| format!("writing {}", path.display()))
            .map_err(Gate::from)
    }

    fn append_jsonl<T: Serialize>(&self, relative: &str, value: &T) -> Result<(), Gate> {
        use std::io::Write as _;
        let path = self.root.join(relative);
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))
            .map_err(Gate::from)?;
        let line = serde_json::to_string(value)
            .with_context(|| format!("serializing a {}", relative))
            .map_err(Gate::from)?;
        writeln!(file, "{line}")
            .with_context(|| format!("appending to {}", path.display()))
            .map_err(Gate::from)
    }
}

// ---------------------------------------------------------------------------
// Live sandbox ownership
// ---------------------------------------------------------------------------

struct LiveVm {
    name: String,
    sandbox: Sandbox,
}

impl LiveVm {
    fn sandbox_ref(&self) -> &Sandbox {
        &self.sandbox
    }

    async fn shutdown(&self) -> Result<(), String> {
        let mut problems = Vec::new();
        match tokio::time::timeout(Duration::from_secs(60), self.sandbox.stop_and_wait()).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => problems.push(format!("stop: {error}")),
            Err(_) => problems.push("stop: timed out after 60 s".to_string()),
        }
        match tokio::time::timeout(Duration::from_secs(60), Sandbox::remove(&self.name)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => problems.push(format!("remove: {error}")),
            Err(_) => problems.push("remove: timed out after 60 s".to_string()),
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems.join("; "))
        }
    }
}

async fn create_vm(
    config: &Config,
    name: &str,
    cpus: u8,
    max_cpus: u8,
    memory_mib: u32,
    max_memory_mib: u32,
) -> Result<LiveVm, Gate> {
    let builder = Sandbox::builder(name)
        .image(crate::defaults::INITIAL_DEFAULT_IMAGE_REF)
        .pull_policy(PullPolicy::IfMissing)
        .cpus(cpus)
        .max_cpus(max_cpus)
        .memory(memory_mib)
        .max_memory(max_memory_mib)
        .metrics_sample_interval(METRICS_INTERVAL)
        .replace();
    let sandbox_config = builder
        .build()
        .await
        .map_err(|error| Gate::Inconclusive(format!("INCONCLUSIVE: preparing {name}: {error}")))?;
    let created =
        tokio::time::timeout(IMAGE_ACQUIRE_DEADLINE, Sandbox::create(sandbox_config)).await;
    let sandbox = match created {
        Ok(Ok(sandbox)) => sandbox,
        Ok(Err(error)) => {
            let _ = Sandbox::remove(name).await;
            return Err(Gate::Inconclusive(format!(
                "BLOCKED: creating {name} from {} failed after acquiring: {} \
                 (a pull/auth/network failure is blocked, not a capacity verdict)",
                crate::defaults::INITIAL_DEFAULT_IMAGE_REF,
                render_error(&error)
            )));
        }
        Err(_) => {
            let _ = Sandbox::remove(name).await;
            return Err(Gate::Inconclusive(format!(
                "BLOCKED: creating {name} exceeded the {} s acquisition deadline",
                IMAGE_ACQUIRE_DEADLINE.as_secs()
            )));
        }
    };
    let _ = config;
    Ok(LiveVm {
        name: name.to_string(),
        sandbox,
    })
}

fn render_error(error: &MicrosandboxError) -> String {
    format!("{error:#}")
}

async fn guest_exec(sandbox: &Sandbox, program: &str, args: &[&str]) -> Result<String, Gate> {
    let output = tokio::time::timeout(
        Duration::from_secs(30),
        sandbox.exec(program, args.iter().copied()),
    )
    .await
    .map_err(|_| Gate::Inconclusive(format!("INCONCLUSIVE: guest exec {program} timed out")))?
    .map_err(|error| {
        Gate::Inconclusive(format!(
            "INCONCLUSIVE: guest exec {program} failed: {error}"
        ))
    })?;
    if output.status().code != 0 {
        return Err(Gate::Inconclusive(format!(
            "INCONCLUSIVE: guest exec {program} exited {}: {}",
            output.status().code,
            output.stderr().unwrap_or_default()
        )));
    }
    Ok(output.stdout().unwrap_or_default())
}

/// Write the workload script through stdin so no guest base64/tooling is assumed.
async fn install_workload(sandbox: &Sandbox) -> Result<(), Gate> {
    guest_exec(sandbox, "mkdir", &["-p", GUEST_DIR]).await?;
    let output = tokio::time::timeout(
        Duration::from_secs(30),
        sandbox.exec_with("sh", |exec| {
            exec.args(["-c", &format!("cat > {GUEST_DIR}/workload.py")])
                .stdin_bytes(WORKLOAD_SCRIPT.as_bytes().to_vec())
        }),
    )
    .await
    .map_err(|_| Gate::Inconclusive("INCONCLUSIVE: writing the guest workload timed out".into()))?
    .map_err(|error| {
        Gate::Inconclusive(format!("INCONCLUSIVE: writing the guest workload: {error}"))
    })?;
    if output.status().code != 0 {
        return Err(Gate::Inconclusive(
            "INCONCLUSIVE: the guest shell could not store the workload".to_string(),
        ));
    }
    Ok(())
}

const GUEST_DIR: &str = "/tmp/c647";

// ---------------------------------------------------------------------------
// Read-only runtime control helper (P0-E)
// ---------------------------------------------------------------------------

async fn control_request(
    sandbox: &Sandbox,
    request: ControlRequest,
) -> Result<ControlResponse, Gate> {
    let local = sandbox.backend().as_local().ok_or_else(|| {
        Gate::Inconclusive("INCONCLUSIVE: the owned sandbox has no local backend".to_string())
    })?;
    let paths = RuntimeSocketPaths::new(&local.config().run_dir(), sandbox.name());
    let connect = tokio::time::timeout(CONTROL_DEADLINE, UnixStream::connect(&paths.control)).await;
    let stream = match connect {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            return Err(Gate::Inconclusive(format!(
                "INCONCLUSIVE: connecting to the control socket {}: {error}",
                paths.control.display()
            )));
        }
        Err(_) => {
            return Err(Gate::Inconclusive(format!(
                "INCONCLUSIVE: connecting to the control socket {} timed out",
                paths.control.display()
            )));
        }
    };
    let (mut read, mut write) = stream.into_split();
    let mut line = serde_json::to_vec(&request).map_err(|error| {
        Gate::Inconclusive(format!("INCONCLUSIVE: encoding a control request: {error}"))
    })?;
    line.push(b'\n');
    write.write_all(&line).await.map_err(|error| {
        Gate::Inconclusive(format!("INCONCLUSIVE: writing a control request: {error}"))
    })?;
    let mut bounded = tokio::io::BufReader::new(&mut read).take(CONTROL_RESPONSE_BOUND);
    let mut response = String::new();
    let read_result =
        tokio::time::timeout(CONTROL_DEADLINE, bounded.read_line(&mut response)).await;
    match read_result {
        Ok(Ok(n)) if n > 0 => {}
        Ok(Ok(_)) => {
            return Err(Gate::Inconclusive(
                "INCONCLUSIVE: the control socket closed without a reply".to_string(),
            ));
        }
        Ok(Err(error)) => {
            return Err(Gate::Inconclusive(format!(
                "INCONCLUSIVE: reading the control reply: {error}"
            )));
        }
        Err(_) => {
            return Err(Gate::Inconclusive(
                "INCONCLUSIVE: the control reply timed out".to_string(),
            ));
        }
    }
    let decoded: ControlResponse = serde_json::from_str(response.trim()).map_err(|error| {
        Gate::Inconclusive(format!("INCONCLUSIVE: decoding the control reply: {error}"))
    })?;
    if !decoded.ok {
        return Err(Gate::Inconclusive(format!(
            "INCONCLUSIVE: the control request was refused: {:?}",
            decoded.error
        )));
    }
    Ok(decoded)
}

async fn control_cpu(sandbox: &Sandbox) -> Result<CpuControlState, Gate> {
    let response = control_request(sandbox, ControlRequest::CpuState).await?;
    response.cpu.ok_or_else(|| {
        Gate::Inconclusive("INCONCLUSIVE: the CpuState reply carried no cpu fields".to_string())
    })
}

// ---------------------------------------------------------------------------
// Metrics and lifecycle
// ---------------------------------------------------------------------------

async fn read_row(sandbox: &Sandbox) -> Result<Option<SandboxMetrics>, String> {
    let Some(local) = sandbox.backend().as_local() else {
        return Err("the sandbox has no local backend".to_string());
    };
    let read = tokio::time::timeout(
        Duration::from_secs(5),
        microsandbox::sandbox::all_sandbox_metrics_local(local),
    )
    .await;
    match read {
        Ok(Ok(mut rows)) => Ok(rows.remove(sandbox.name())),
        Ok(Err(error)) => Err(format!("{error}")),
        Err(_) => Err("metrics read timed out after 5 s".to_string()),
    }
}

#[derive(Default)]
struct LifecycleCache {
    value: String,
    valid: bool,
    last_probe_start: Option<Instant>,
}

impl LifecycleCache {
    fn age(&self, now: Instant) -> Option<Duration> {
        self.last_probe_start
            .map(|start| now.saturating_duration_since(start))
    }

    fn running(&self, now: Instant) -> bool {
        self.valid
            && self.value == "running"
            && self.age(now).is_some_and(|age| age < LIFECYCLE_TTL)
    }
}

struct ProbeLog {
    started_ns: Option<u64>,
    ended_ns: Option<u64>,
    result: Option<String>,
    skipped: Option<String>,
}

/// One §3.2 lazy probe: only a distinct row with a usable positive rate needs eligibility,
/// at most one attempt per TTL, bounded at 50 ms. Not a pause fence.
async fn probe_lifecycle(
    sandbox: &Sandbox,
    cache: &mut LifecycleCache,
    needed: bool,
    now: Instant,
    monotonic_base: Instant,
) -> ProbeLog {
    if !needed {
        return ProbeLog {
            started_ns: None,
            ended_ns: None,
            result: None,
            skipped: Some("no CPU eligibility decision this poll".to_string()),
        };
    }
    if cache.age(now).is_some_and(|age| age < LIFECYCLE_TTL) {
        return ProbeLog {
            started_ns: None,
            ended_ns: None,
            result: None,
            skipped: Some(format!(
                "cached for {:?}",
                cache.age(now).unwrap_or_default()
            )),
        };
    }
    let start = Instant::now();
    let started_ns = start.saturating_duration_since(monotonic_base).as_nanos() as u64;
    let reply = tokio::time::timeout(LIFECYCLE_TIMEOUT, sandbox.pause_state()).await;
    let ended_ns = Instant::now()
        .saturating_duration_since(monotonic_base)
        .as_nanos() as u64;
    let result = match reply {
        Ok(Ok(state)) if !state.paused && !state.recovery_required => "running",
        Ok(Ok(_)) => "not_running",
        Ok(Err(_)) | Err(_) => "unavailable",
    };
    cache.value = result.to_string();
    cache.valid = true;
    cache.last_probe_start = Some(start);
    ProbeLog {
        started_ns: Some(started_ns),
        ended_ns: Some(ended_ns),
        result: Some(result.to_string()),
        skipped: None,
    }
}

// ---------------------------------------------------------------------------
// Host quietness sampling (P0-B)
// ---------------------------------------------------------------------------

fn now_unix_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or_default()
}

fn parse_percent_hundredths(text: &str) -> Option<u32> {
    let value = text.trim().trim_end_matches('%');
    let (whole, fraction) = match value.split_once('.') {
        Some((whole, fraction)) => (whole, fraction),
        None => (value, ""),
    };
    let whole: u32 = whole.parse().ok()?;
    let mut hundredths = 0u32;
    for (index, digit) in fraction.chars().take(2).enumerate() {
        let digit = digit.to_digit(10)?;
        hundredths += if index == 0 { digit * 10 } else { digit };
    }
    Some(whole * 100 + hundredths)
}

async fn host_idle_sample() -> Option<HostSample> {
    let output = tokio::process::Command::new("/usr/bin/top")
        .args(["-l", "2", "-n", "0", "-s", "1"])
        .output()
        .await
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let mut idle = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("CPU usage:")
            && let Some(position) = rest.rfind("idle")
            && let Some(last) = rest[..position].split(',').next_back()
        {
            idle = parse_percent_hundredths(last);
        }
    }
    Some(HostSample {
        kind: "pretrial".to_string(),
        at_ns: now_unix_ns(),
        idle_hundredths: idle?,
    })
}

/// Parse `ps` cumulative CPU time (`MM:SS.ss`, `HH:MM:SS`, `DD-HH:MM:SS`).
fn parse_cpu_time_ns(text: &str) -> Option<u64> {
    let (days, rest) = match text.split_once('-') {
        Some((days, rest)) => (days.parse::<u64>().ok()?, rest),
        None => (0, text),
    };
    let parts: Vec<&str> = rest.split(':').collect();
    let (hours, minutes, seconds) = match parts.as_slice() {
        [minutes, seconds] => (0u64, minutes.parse::<u64>().ok()?, *seconds),
        [hours, minutes, seconds] => (
            hours.parse::<u64>().ok()?,
            minutes.parse::<u64>().ok()?,
            *seconds,
        ),
        _ => return None,
    };
    let seconds = seconds.parse::<f64>().ok()?;
    let total = (days * 86_400 + hours * 3_600 + minutes * 60) as f64 + seconds;
    Some((total * 1_000_000_000.0) as u64)
}

fn process_snapshot() -> HashMap<u32, (String, u64)> {
    let output = std::process::Command::new("/bin/ps")
        .args(["-axo", "pid=,time=,command="])
        .output();
    let mut map = HashMap::new();
    let Ok(output) = output else {
        return map;
    };
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        // `ps` right-aligns its columns, so split on runs of whitespace; the command keeps its
        // remaining words (normalized spacing is enough for ownership matching).
        let mut parts = line.split_whitespace();
        let (Some(pid), Some(time)) = (parts.next(), parts.next()) else {
            continue;
        };
        let (Ok(pid), Some(ns)) = (pid.parse::<u32>(), parse_cpu_time_ns(time)) else {
            continue;
        };
        map.insert(pid, (parts.collect::<Vec<_>>().join(" "), ns));
    }
    map
}

fn is_excluded_process(command: &str, sandbox_name: &str) -> bool {
    let owned_msb = std::env::var("MSB_PATH").unwrap_or_default();
    (!owned_msb.is_empty() && command.contains(&owned_msb))
        || command.contains(sandbox_name)
        || command.starts_with("ps ")
        || command.contains("/bin/ps")
        || command.starts_with("top ")
        || command.contains("/usr/bin/top")
}

async fn sample_process_deltas(
    sandbox_name: &str,
    previous: &mut HashMap<u32, (String, u64)>,
    evidence: &Evidence,
    ledger: &mut Vec<serde_json::Value>,
    wall_ns: u64,
    sample_id: u64,
) -> Result<Vec<ProcessDelta>, Gate> {
    let current = process_snapshot();
    let mut deltas = Vec::new();
    for (pid, (command, cpu_ns)) in &current {
        let Some((_, before)) = previous.get(pid) else {
            continue;
        };
        let delta = cpu_ns.saturating_sub(*before);
        let excluded = is_excluded_process(command, sandbox_name) || *pid == std::process::id();
        if ledger.iter().all(|entry| entry["pid"] != *pid) {
            ledger.push(json!({
                "pid": pid,
                "command": command,
                "excluded": excluded,
                "reason": if excluded { "harness/owned/sampler" } else { "non-owned" },
            }));
        }
        deltas.push(ProcessDelta {
            sample_id,
            pid: *pid,
            command: command.clone(),
            cpu_ns: delta,
            wall_ns,
            excluded,
        });
        let _ = evidence;
    }
    *previous = current;
    Ok(deltas)
}

// ---------------------------------------------------------------------------
// Calibration collection
// ---------------------------------------------------------------------------

async fn collect(
    config: &Config,
    evidence: &Evidence,
    gates: &mut Vec<serde_json::Value>,
    image_started: Instant,
) -> Result<(), Gate> {
    let mut cleanup_rows = Vec::new();

    // P0-A order: the capacity/U1/U5/U3-combined/U4 class first, then the calibration matrix,
    // then the fresh 1-of-2 equality sandbox (inside `collect_capacity`).
    let capacity = collect_capacity(config, evidence, &mut cleanup_rows).await;
    match capacity {
        Ok(rows) => gates.extend(rows),
        Err(gate) => {
            evidence.write_json("cleanup.json", &cleanup_rows)?;
            return Err(gate);
        }
    }

    let mut all_specs: Vec<TrialSpec> = Vec::new();
    for memory in [1024u32, 8192] {
        all_specs.extend(calibration_matrix(memory));
    }
    let mut analyses = Vec::new();
    for memory in [1024u32, 8192] {
        let name = format!("c647-cal-{memory}-{}", std::process::id());
        let vm = create_vm(config, &name, 1, 4, memory, memory).await?;
        let outcome =
            collect_memory_calibration(config, evidence, &vm, memory, &mut analyses).await;
        let cleanup = vm.shutdown().await;
        cleanup_rows.push(
            json!({"sandbox": name, "phase": format!("calibration-M{memory}"), "result": cleanup}),
        );
        if let Err(problems) = cleanup {
            evidence.write_json("cleanup.json", &cleanup_rows)?;
            return Err(Gate::Inconclusive(format!(
                "INCONCLUSIVE: owned cleanup failed for {name}: {problems}"
            )));
        }
        if let Err(gate) = outcome {
            evidence.write_json("cleanup.json", &cleanup_rows)?;
            return Err(gate);
        }
    }

    let verdict = analyze::analyze_suite(&analyses, &all_specs);
    evidence.write_json("analysis/suite.json", &verdict)?;
    gates.push(json!({
        "gate": "P0-A/B/C/D calibration matrix (36 trials)",
        "verdict": verdict.verdict(),
        "failures": verdict.failures,
        "inconclusive": verdict.inconclusive,
        "elapsed_since_image_start_s": image_started.elapsed().as_secs(),
    }));
    evidence.write_json("cleanup.json", &cleanup_rows)?;
    if verdict.verdict() != "PASS" {
        return Err(suite_gate(&verdict));
    }
    Ok(())
}

fn suite_gate(verdict: &SuiteVerdict) -> Gate {
    if !verdict.inconclusive.is_empty() {
        Gate::Inconclusive(format!(
            "INCONCLUSIVE: {}",
            verdict.inconclusive.join(" | ")
        ))
    } else {
        Gate::Fail(format!("FAIL: {}", verdict.failures.join(" | ")))
    }
}

async fn collect_memory_calibration(
    config: &Config,
    evidence: &Evidence,
    vm: &LiveVm,
    memory: u32,
    analyses: &mut Vec<analyze::TrialAnalysis>,
) -> Result<(), Gate> {
    install_workload(&vm.sandbox).await?;
    let boot_marker = guest_exec(
        &vm.sandbox,
        "sh",
        &[
            "-c",
            &format!("cat /proc/sys/kernel/random/boot_id > {GUEST_DIR}/boot-id && cat {GUEST_DIR}/boot-id"),
        ],
    )
    .await?;
    let boot_id = boot_marker.trim().to_string();
    if boot_id.is_empty() {
        return Err(Gate::Inconclusive(
            "INCONCLUSIVE: the guest reported no boot id".to_string(),
        ));
    }
    for spec in calibration_matrix(memory) {
        let analysis = run_trial(config, evidence, vm, &spec, &boot_id).await?;
        analyses.push(analysis);
    }
    Ok(())
}

async fn resize_cpu(vm: &LiveVm, target: u8) -> Result<u8, Gate> {
    let plan = vm
        .sandbox
        .modify()
        .cpus(target)
        .apply()
        .await
        .map_err(|error| {
            Gate::Inconclusive(format!(
                "INCONCLUSIVE: prerequisite live CPU resize to {target} failed: {error}"
            ))
        })?;
    if !plan.applied {
        return Err(Gate::Inconclusive(format!(
            "INCONCLUSIVE: the CPU resize to {target} was not applied"
        )));
    }
    let statuses: Vec<&_> = plan
        .resize_status
        .iter()
        .filter(|status| status.resource == ResourceKind::Cpus)
        .collect();
    // An already-saved equal target plans no change, so no live status exists. The fixed
    // calibration commitment is then confirmed from the runtime's own CpuState, which is
    // test setup, never production authority.
    let enforced = match statuses.len() {
        1 => accepted_cpu(&plan, target)?,
        0 => {
            let state = control_cpu(&vm.sandbox).await?;
            if state.requested_online != u32::from(target) || state.enforced != u32::from(target) {
                return Err(Gate::Inconclusive(format!(
                    "INCONCLUSIVE: a statusless CPU apply left requested={} enforced={}                      (expected {target})",
                    state.requested_online, state.enforced
                )));
            }
            target
        }
        other => {
            return Err(Gate::Inconclusive(format!(
                "INCONCLUSIVE: the CPU resize to {target} reported {other} CPU statuses"
            )));
        }
    };
    await_online(vm, target).await?;
    Ok(enforced)
}

fn accepted_cpu(plan: &SandboxModificationPlan, requested: u8) -> Result<u8, Gate> {
    if !plan.applied {
        return Err(Gate::Inconclusive(format!(
            "INCONCLUSIVE: the CPU resize to {requested} was not applied"
        )));
    }
    let mut statuses = plan
        .resize_status
        .iter()
        .filter(|status| status.resource == ResourceKind::Cpus);
    let status = statuses.next().ok_or_else(|| {
        Gate::Inconclusive(format!(
            "INCONCLUSIVE: the CPU resize to {requested} reported no CPU status"
        ))
    })?;
    if statuses.next().is_some() {
        return Err(Gate::Inconclusive(
            "INCONCLUSIVE: the plan reported more than one CPU status".to_string(),
        ));
    }
    match status.state {
        ResourceConvergenceState::Accepted
        | ResourceConvergenceState::Converging
        | ResourceConvergenceState::Applied => {}
        ResourceConvergenceState::GuestRefused | ResourceConvergenceState::Failed => {
            return Err(Gate::Inconclusive(format!(
                "INCONCLUSIVE: the CPU resize to {requested} did not converge ({:?})",
                status.state
            )));
        }
    }
    let enforced: u8 = status.enforced.parse().map_err(|_| {
        Gate::Inconclusive(format!(
            "INCONCLUSIVE: the CPU receipt enforced {:?} is not a decimal count",
            status.enforced
        ))
    })?;
    if !(1..=4).contains(&enforced) {
        return Err(Gate::Inconclusive(format!(
            "INCONCLUSIVE: the CPU receipt enforced {enforced} is outside the declared bounds"
        )));
    }
    Ok(enforced)
}

async fn await_online(vm: &LiveVm, target: u8) -> Result<(), Gate> {
    let deadline = Instant::now() + CPU_CONVERGENCE_DEADLINE;
    loop {
        let state = control_cpu(&vm.sandbox).await?;
        if state.actual_online == u32::from(target) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(Gate::Inconclusive(format!(
                "INCONCLUSIVE: guest online count did not converge to {target} within {} s \
                 (requested={} actual={} enforced={})",
                CPU_CONVERGENCE_DEADLINE.as_secs(),
                state.requested_online,
                state.actual_online,
                state.enforced
            )));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn run_trial(
    config: &Config,
    evidence: &Evidence,
    vm: &LiveVm,
    spec: &TrialSpec,
    boot_id: &str,
) -> Result<analyze::TrialAnalysis, Gate> {
    // Stop any previous workload before changing the commitment.
    stop_workers(&vm.sandbox, &spec.trial).await?;
    let enforced = resize_cpu(vm, spec.cpus).await?;
    let cpu_state = control_cpu(&vm.sandbox).await?;

    let idle: Vec<HostSample> = {
        let mut samples = Vec::new();
        for _ in 0..analyze::HOST_IDLE_SAMPLES {
            if let Some(sample) = host_idle_sample().await {
                samples.push(sample);
            }
        }
        samples
    };
    for sample in &idle {
        evidence.append_jsonl(&format!("host/{}.idle.jsonl", spec.trial), sample)?;
    }

    let trial_dir = format!("{GUEST_DIR}/{}", spec.trial);
    guest_exec(&vm.sandbox, "mkdir", &["-p", &trial_dir]).await?;
    let stop_path = format!("{GUEST_DIR}/stop");
    let start = format!(
        "cd {GUEST_DIR} && python3 workload.py --daemonize --workers {} --duty {} \
         --duration {WORKLOAD_DURATION_SECONDS} --out {trial_dir}/workload.jsonl \
         --ready {trial_dir}/ready.json --pid {trial_dir}/workload.pid \
         --stop {stop_path} --log {trial_dir}/workload.log",
        spec.workers, spec.duty_percent
    );
    guest_exec(&vm.sandbox, "sh", &["-c", &start]).await?;
    let ready_deadline = Instant::now() + READY_DEADLINE;
    loop {
        let ready = guest_exec(
            &vm.sandbox,
            "sh",
            &[
                "-c",
                &format!("test -f {trial_dir}/ready.json && echo ready || true"),
            ],
        )
        .await?;
        if ready.contains("ready") {
            break;
        }
        if Instant::now() >= ready_deadline {
            return Err(Gate::Inconclusive(format!(
                "INCONCLUSIVE: {} workers never reported ready within {} s",
                spec.workers,
                READY_DEADLINE.as_secs()
            )));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let mut previous_processes = process_snapshot();
    let mut ledger: Vec<serde_json::Value> = Vec::new();
    let mut deltas: Vec<ProcessDelta> = Vec::new();
    let mut last_host_sample = Instant::now();
    let mut host_sample_id = 0u64;

    let monotonic_base = Instant::now();
    let mut lifecycle = LifecycleCache {
        value: "unavailable".to_string(),
        valid: false,
        last_probe_start: None,
    };
    let identity = format!(
        "{}:possible={}:boot={}",
        config.runtime_identity, cpu_state.possible, boot_id
    );
    let mut clock = analyze::ObservationClock::default();
    let mut distinct = 0usize;
    let mut poll_id = 0u64;
    let mut records: Vec<PollRecord> = Vec::new();
    let ticker_start = Instant::now() + METRICS_INTERVAL;
    let mut ticker = tokio::time::interval_at(
        tokio::time::Instant::from_std(ticker_start),
        METRICS_INTERVAL,
    );
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let deadline = Instant::now() + COLLECTION_POLL_BUDGET;
    let mut phase_done = spec.phase_ms == 0;
    let mut first_post_ready = false;
    while distinct < SETTLING_AND_COUNTED_ROWS && Instant::now() < deadline {
        ticker.tick().await;
        let scheduled_ns = Instant::now()
            .saturating_duration_since(monotonic_base)
            .as_nanos() as u64;
        let read_start = Instant::now();
        let read_start_ns = read_start
            .saturating_duration_since(monotonic_base)
            .as_nanos() as u64;
        let row = read_row(&vm.sandbox).await;
        let read_end_ns = Instant::now()
            .saturating_duration_since(monotonic_base)
            .as_nanos() as u64;
        let mut record = PollRecord {
            poll_id,
            trial: spec.trial.clone(),
            config: spec.config.clone(),
            scheduled_ns,
            read_start_ns,
            read_end_ns,
            runtime_identity: Some(identity.clone()),
            lifecycle_value: lifecycle.value.clone(),
            lifecycle_valid: lifecycle.valid,
            lifecycle_cache_age_ns: lifecycle.age(read_start).map(|age| age.as_nanos() as u64),
            ..PollRecord::default()
        };
        let observation = match &row {
            Ok(Some(metrics)) => {
                record.sdk_timestamp_ns =
                    metrics.timestamp.timestamp_nanos_opt().map(|ns| ns as i128);
                record.cpu_percent_bits = Some(metrics.cpu_percent.to_bits());
                record.vcpu_time_ns = Some(metrics.vcpu_time_ns);
                record.memory_limit_bytes = Some(metrics.memory_limit_bytes);
                record.memory_available_bytes = metrics.memory_available_bytes;
                record.residency_present = Some(metrics.memory_host_resident_bytes.is_some());
                let clock_now = clock.observe(record.sdk_timestamp_ns);
                if clock_now == analyze::Clock::Distinct && !first_post_ready {
                    first_post_ready = true;
                    if !phase_done {
                        tokio::time::sleep(Duration::from_millis(spec.phase_ms)).await;
                        phase_done = true;
                    }
                }
                let needed = clock_now == analyze::Clock::Distinct
                    && matches!(
                        record.cpu_percent_bits.map(analyze::decode_rate),
                        Some(analyze::Decoded::Positive(_))
                    );
                debug_assert_eq!(record.lifecycle_valid, lifecycle.valid);
                debug_assert_eq!(lifecycle.running(read_start), {
                    lifecycle.valid
                        && lifecycle.value == "running"
                        && lifecycle
                            .age(read_start)
                            .is_some_and(|age| age < LIFECYCLE_TTL)
                });
                let probe = probe_lifecycle(
                    &vm.sandbox,
                    &mut lifecycle,
                    needed,
                    read_start,
                    monotonic_base,
                )
                .await;
                record.lifecycle_value = lifecycle.value.clone();
                record.lifecycle_valid = lifecycle.valid;
                record.lifecycle_cache_age_ns =
                    lifecycle.age(read_start).map(|age| age.as_nanos() as u64);
                record.probe_started_ns = probe.started_ns;
                record.probe_ended_ns = probe.ended_ns;
                record.probe_result = probe.result;
                record.probe_skipped = probe.skipped;
                clock_now
            }
            Ok(None) => clock.observe(None),
            Err(error) => {
                record.error = Some(error.clone());
                clock.observe(None)
            }
        };
        if observation == analyze::Clock::Distinct {
            distinct += 1;
        }
        evidence.append_jsonl(&format!("polls/{}.jsonl", spec.trial), &record)?;
        records.push(record);
        poll_id += 1;
        if last_host_sample.elapsed() >= HOST_SAMPLE_INTERVAL {
            let sample_wall_ns = last_host_sample.elapsed().as_nanos() as u64;
            deltas.extend(
                sample_process_deltas(
                    &vm.name,
                    &mut previous_processes,
                    evidence,
                    &mut ledger,
                    sample_wall_ns,
                    host_sample_id,
                )
                .await?,
            );
            last_host_sample = Instant::now();
            host_sample_id += 1;
        }
    }

    stop_workers(&vm.sandbox, &spec.trial).await?;
    let workload = read_workload(&vm.sandbox, &trial_dir, spec.workers, spec.duty_percent).await?;
    evidence.write_json(&format!("workload/{}.analysis.json", spec.trial), &workload)?;

    let analysis = analyze::analyze_trial(spec, &records, &idle, &deltas, &workload);
    evidence.write_json(&format!("analysis/{}.json", spec.trial), &analysis)?;
    evidence.write_json(
        &format!("analysis/{}.host.json", spec.trial),
        &json!({"idle": idle, "deltas": deltas, "ledger": ledger, "enforced_cpus": enforced}),
    )?;
    if analysis.verdict() == "INCONCLUSIVE" {
        return Err(Gate::Inconclusive(format!(
            "INCONCLUSIVE: {}: {}",
            spec.trial,
            analysis.inconclusive.join(" | ")
        )));
    }
    Ok(analysis)
}

/// Stop every owned guest workload before the next commitment change.
///
/// The flag is shared across trials because the workers are one daemonized process group per
/// trial; waiting for them to disappear (not a fixed sleep) keeps a leftover worker out of the
/// next trial's delivered-CPU measurement.
async fn stop_workers(sandbox: &Sandbox, _trial: &str) -> Result<(), Gate> {
    guest_exec(sandbox, "sh", &["-c", &format!("touch {GUEST_DIR}/stop")]).await?;
    // The pid file names the daemon, which called setsid: its negative pid addresses the whole
    // owned process group (the daemon plus its workers). No pgrep dependency.
    let probe = format!(
        "for f in {GUEST_DIR}/*/workload.pid; do \
           [ -f \"$f\" ] || continue; \
           pid=$(cat \"$f\" 2>/dev/null) || continue; \
           kill -0 \"$pid\" 2>/dev/null && echo alive; \
           true; \
         done"
    );
    let kill = format!(
        "for f in {GUEST_DIR}/*/workload.pid; do \
           [ -f \"$f\" ] || continue; \
           pid=$(cat \"$f\" 2>/dev/null) || continue; \
           kill -TERM -\"$pid\" 2>/dev/null || kill -TERM \"$pid\" 2>/dev/null || true; \
         done"
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let alive = guest_exec(sandbox, "sh", &["-c", &probe]).await?;
        if !alive.contains("alive") {
            break;
        }
        if Instant::now() >= deadline {
            guest_exec(sandbox, "sh", &["-c", &kill]).await?;
            tokio::time::sleep(Duration::from_millis(500)).await;
            let still = guest_exec(sandbox, "sh", &["-c", &probe]).await?;
            if still.contains("alive") {
                return Err(Gate::Inconclusive(
                    "INCONCLUSIVE: the owned guest workload did not stop within 5 s".to_string(),
                ));
            }
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    guest_exec(
        sandbox,
        "sh",
        &[
            "-c",
            &format!("rm -f {GUEST_DIR}/stop {GUEST_DIR}/ready.json"),
        ],
    )
    .await?;
    Ok(())
}

async fn read_workload(
    sandbox: &Sandbox,
    trial_dir: &str,
    workers: u32,
    duty_percent: u32,
) -> Result<WorkloadReport, Gate> {
    let raw = guest_exec(
        sandbox,
        "sh",
        &[
            "-c",
            &format!("cat {trial_dir}/workload.jsonl 2>/dev/null || true"),
        ],
    )
    .await?;
    let ready = guest_exec(
        sandbox,
        "sh",
        &[
            "-c",
            &format!("test -f {trial_dir}/ready.json && echo yes || true"),
        ],
    )
    .await?;
    let mut checkpoints: Vec<WorkloadCheckpoint> = Vec::new();
    for line in raw.lines() {
        if let Ok(checkpoint) = serde_json::from_str::<WorkloadCheckpoint>(line) {
            checkpoints.push(checkpoint);
        }
    }
    Ok(WorkloadReport {
        workers,
        duty_percent,
        ready: ready.contains("yes"),
        checkpoints,
    })
}

// ---------------------------------------------------------------------------
// P0-E capacity, combined receipt, equality and lifecycle trials
// ---------------------------------------------------------------------------

async fn collect_capacity(
    config: &Config,
    evidence: &Evidence,
    cleanup_rows: &mut Vec<serde_json::Value>,
) -> Result<Vec<serde_json::Value>, Gate> {
    let mut gates = Vec::new();
    let name = format!("c647-cap-{}", std::process::id());
    let vm = create_vm(config, &name, 1, 4, 512, 1024).await?;
    let outcome = capacity_body(&vm, evidence, &mut gates).await;
    let cleanup = vm.shutdown().await;
    cleanup_rows.push(json!({"sandbox": name, "phase": "capacity U1/U5/U3/U4", "result": cleanup}));
    if let Err(problems) = cleanup {
        return Err(Gate::Inconclusive(format!(
            "INCONCLUSIVE: owned cleanup failed for {name}: {problems}"
        )));
    }
    outcome?;

    let equality_name = format!("c647-eq-{}", std::process::id());
    let equality = create_vm(config, &equality_name, 1, 2, 512, 1024).await?;
    let outcome = two_value_body(&equality, evidence, &mut gates).await;
    let cleanup = equality.shutdown().await;
    cleanup_rows
        .push(json!({"sandbox": equality_name, "phase": "U3-two-value", "result": cleanup}));
    if let Err(problems) = cleanup {
        return Err(Gate::Inconclusive(format!(
            "INCONCLUSIVE: owned cleanup failed for {equality_name}: {problems}"
        )));
    }
    outcome?;
    Ok(gates)
}

async fn observed_configs(
    sandbox: &Sandbox,
) -> Result<(SandboxConfigView, Option<SandboxConfigView>), Gate> {
    let handle = Sandbox::get_for_control(sandbox.name())
        .await
        .map_err(|error| {
            Gate::Inconclusive(format!("INCONCLUSIVE: fetching control handle: {error}"))
        })?;
    let desired = handle.config().map_err(|error| {
        Gate::Inconclusive(format!("INCONCLUSIVE: reading desired config: {error}"))
    })?;
    let active = handle
        .active_config()
        .map_err(|error| {
            Gate::Inconclusive(format!("INCONCLUSIVE: reading active config: {error}"))
        })?
        .ok_or_else(|| {
            Gate::Inconclusive("INCONCLUSIVE: no active config is available".to_string())
        })?;
    Ok((
        SandboxConfigView::from(&desired),
        Some(SandboxConfigView::from(&active)),
    ))
}

struct SandboxConfigView {
    cpus: u8,
    max_cpus: u8,
    memory_mib: u32,
    max_memory_mib: u32,
}

impl From<&microsandbox::sandbox::SandboxConfig> for SandboxConfigView {
    fn from(config: &microsandbox::sandbox::SandboxConfig) -> Self {
        let resources = &config.spec.resources;
        Self {
            cpus: resources.cpus,
            max_cpus: resources.max_cpus,
            memory_mib: resources.memory_mib,
            max_memory_mib: resources.max_memory_mib,
        }
    }
}

async fn capacity_body(
    vm: &LiveVm,
    evidence: &Evidence,
    gates: &mut Vec<serde_json::Value>,
) -> Result<(), Gate> {
    guest_exec(vm.sandbox_ref(), "mkdir", &["-p", GUEST_DIR]).await?;
    let mut observations = Vec::new();
    let state = control_cpu(&vm.sandbox).await?;
    let possible = state.possible;
    let guest_online = guest_exec(
        &vm.sandbox,
        "sh",
        &["-c", "cat /sys/devices/system/cpu/online"],
    )
    .await?;
    let guest_nproc = guest_exec(&vm.sandbox, "nproc", &[]).await?;
    let baseline = json!({
        "gate": "U1/U5 capacity and live CPU resize",
        "possible": possible,
        "initial": {"requested": state.requested_online, "actual": state.actual_online, "enforced": state.enforced},
        "guest_online": guest_online.trim(),
        "guest_nproc": guest_nproc.trim(),
    });
    observations.push(baseline);
    if possible != 4 {
        return Err(Gate::Inconclusive(format!(
            "INCONCLUSIVE: U1 requires possible=4, saw {possible}"
        )));
    }
    if state.requested_online != 1 || state.actual_online != 1 || state.enforced != 1 {
        return Err(Gate::Inconclusive(format!(
            "INCONCLUSIVE: U1 requires an initial 1/1/1 CPU state, saw {}/{}/{}",
            state.requested_online, state.actual_online, state.enforced
        )));
    }
    let boot_marker = guest_exec(
        &vm.sandbox,
        "sh",
        &["-c", &format!("cat /proc/sys/kernel/random/boot_id > {GUEST_DIR}/boot-id && cat {GUEST_DIR}/boot-id")],
    )
    .await?
    .trim()
    .to_string();
    for target in [2u8, 3, 2] {
        let enforced = resize_cpu(vm, target).await?;
        let state = control_cpu(&vm.sandbox).await?;
        let online = guest_exec(
            &vm.sandbox,
            "sh",
            &["-c", "cat /sys/devices/system/cpu/online"],
        )
        .await?;
        let marker = guest_exec(
            &vm.sandbox,
            "sh",
            &["-c", &format!("cat {GUEST_DIR}/boot-id")],
        )
        .await?;
        observations.push(json!({
            "target": target,
            "enforced_receipt": enforced,
            "runtime": {"possible": state.possible, "requested": state.requested_online,
                        "actual": state.actual_online, "enforced": state.enforced},
            "guest_online": online.trim(),
            "boot_marker_survived": marker.trim() == boot_marker,
        }));
        if marker.trim() != boot_marker {
            return Err(Gate::Inconclusive(
                "INCONCLUSIVE: the guest boot identity changed across a live CPU resize"
                    .to_string(),
            ));
        }
        if state.actual_online != u32::from(target) {
            return Err(Gate::Inconclusive(format!(
                "INCONCLUSIVE: guest online {} != {target} after convergence",
                state.actual_online
            )));
        }
    }
    evidence.write_json("p0e/u1-u5.json", &observations)?;

    // U3-combined: reset, then one combined builder for both axes.
    let seed = vm
        .sandbox
        .modify()
        .next_start()
        .cpus(2)
        .memory(640)
        .apply()
        .await
        .map_err(|error| {
            Gate::Inconclusive(format!("INCONCLUSIVE: U3 NextStart seed failed: {error}"))
        })?;
    if !seed.applied || !seed.resize_status.is_empty() {
        return Err(Gate::Inconclusive(
            "INCONCLUSIVE: U3 configuration-only seed reported a live resize".to_string(),
        ));
    }
    let (desired, active) = observed_configs(&vm.sandbox).await?;
    let _active =
        active.ok_or_else(|| Gate::Inconclusive("INCONCLUSIVE: no active config".to_string()))?;
    if desired.cpus != 2 || desired.memory_mib != 640 {
        return Err(Gate::Inconclusive(format!(
            "INCONCLUSIVE: U3 seed desired {} vCPU/{} MiB, expected 2/640",
            desired.cpus, desired.memory_mib
        )));
    }
    let reset = vm
        .sandbox
        .modify()
        .cpus(1)
        .memory(512)
        .apply()
        .await
        .map_err(|error| {
            Gate::Inconclusive(format!("INCONCLUSIVE: U3 reset apply failed: {error}"))
        })?;
    require_both_receipts(&reset, 1, 512)?;
    await_online(vm, 1).await?;
    let combined = vm
        .sandbox
        .modify()
        .cpus(2)
        .memory(768)
        .apply()
        .await
        .map_err(|error| {
            Gate::Inconclusive(format!("INCONCLUSIVE: U3 combined apply failed: {error}"))
        })?;
    require_both_receipts(&combined, 2, 768)?;
    await_online(vm, 2).await?;
    let (desired, active) = observed_configs(&vm.sandbox).await?;
    let Some(active) = active else {
        return Err(Gate::Inconclusive(
            "INCONCLUSIVE: no active config".to_string(),
        ));
    };
    if desired.cpus != 2
        || desired.memory_mib != 768
        || active.cpus != 2
        || active.memory_mib != 768
    {
        return Err(Gate::Inconclusive(format!(
            "INCONCLUSIVE: U3 combined desired {}/{} active {}/{} (expected 2/768)",
            desired.cpus, desired.memory_mib, active.cpus, active.memory_mib
        )));
    }
    if active.max_cpus != 4 || active.max_memory_mib != 1024 {
        return Err(Gate::Inconclusive(format!(
            "INCONCLUSIVE: U3 active maxima are {} vCPU/{} MiB, expected 4/1024",
            active.max_cpus, active.max_memory_mib
        )));
    }
    evidence.write_json(
        "p0e/u3-combined.json",
        &json!({
            "seed": {"applied": seed.applied, "statuses": seed.resize_status.len(), "desired": {"cpus": desired.cpus, "memory_mib": desired.memory_mib}},
            "combined": {"cpus": 2, "memory_mib": 768, "statuses": combined.resize_status.len()},
            "active_before": {"cpus": active.cpus, "memory_mib": active.memory_mib},
        }),
    )?;

    // U4: paused lifecycle observation with a positive workload.
    let u4_dir = format!("{GUEST_DIR}/u4");
    guest_exec(&vm.sandbox, "mkdir", &["-p", &u4_dir]).await?;
    install_workload(&vm.sandbox).await?;
    let u4_start = format!(
        "cd {GUEST_DIR} && python3 workload.py --daemonize --workers 1 --duty 100          --duration {WORKLOAD_DURATION_SECONDS} --out {u4_dir}/workload.jsonl          --ready {u4_dir}/ready.json --pid {u4_dir}/workload.pid          --stop {GUEST_DIR}/stop --log {u4_dir}/workload.log"
    );
    guest_exec(&vm.sandbox, "sh", &["-c", &u4_start]).await?;
    let u4_ready_deadline = Instant::now() + READY_DEADLINE;
    while Instant::now() < u4_ready_deadline {
        let ready = guest_exec(
            &vm.sandbox,
            "sh",
            &[
                "-c",
                &format!("test -f {u4_dir}/ready.json && echo ready || true"),
            ],
        )
        .await?;
        if ready.contains("ready") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(METRICS_INTERVAL * 3).await;
    vm.sandbox
        .pause()
        .await
        .map_err(|error| Gate::Inconclusive(format!("INCONCLUSIVE: U4 pause failed: {error}")))?;
    let paused = vm.sandbox.pause_state().await.map_err(|error| {
        Gate::Inconclusive(format!("INCONCLUSIVE: U4 pause_state failed: {error}"))
    })?;
    if !paused.paused {
        return Err(Gate::Inconclusive(
            "INCONCLUSIVE: U4 pause_state did not report paused".to_string(),
        ));
    }
    let mut paused_rows = Vec::new();
    let mut paused_clock = analyze::ObservationClock::default();
    for _ in 0..40 {
        if let Ok(Some(metrics)) = read_row(&vm.sandbox).await {
            let observation =
                paused_clock.observe(metrics.timestamp.timestamp_nanos_opt().map(|ns| ns as i128));
            if observation == analyze::Clock::Distinct {
                paused_rows.push(json!({
                    "timestamp_ns": metrics.timestamp.timestamp_nanos_opt(),
                    "cpu_percent_bits": metrics.cpu_percent.to_bits(),
                    "residency": metrics.memory_host_resident_bytes.is_some(),
                }));
                if paused_rows.len() == 5 {
                    break;
                }
            }
        }
        tokio::time::sleep(METRICS_INTERVAL).await;
    }
    let paused_modification = vm
        .sandbox
        .modify()
        .memory(640)
        .apply()
        .await
        .map(|plan| json!({"applied": plan.applied, "statuses": plan.resize_status.len()}))
        .unwrap_or_else(|error| json!({"error": format!("{error}")}));
    vm.sandbox
        .resume()
        .await
        .map_err(|error| Gate::Inconclusive(format!("INCONCLUSIVE: U4 resume failed: {error}")))?;
    let resumed = vm.sandbox.pause_state().await.map_err(|error| {
        Gate::Inconclusive(format!(
            "INCONCLUSIVE: U4 resumed pause_state failed: {error}"
        ))
    })?;
    if resumed.paused {
        return Err(Gate::Inconclusive(
            "INCONCLUSIVE: U4 resume did not clear paused".to_string(),
        ));
    }
    stop_workers(&vm.sandbox, "u4").await?;
    evidence.write_json(
        "p0e/u4-lifecycle.json",
        &json!({
            "paused": true,
            "paused_distinct_rows": paused_rows,
            "modification_while_paused": paused_modification,
            "resumed": !resumed.paused,
        }),
    )?;
    gates.push(json!({"gate": "U1/U5", "verdict": "PASS"}));
    gates.push(json!({"gate": "U3-combined", "verdict": "PASS"}));
    gates.push(json!({"gate": "U4", "verdict": "PASS"}));
    Ok(())
}

fn require_both_receipts(
    plan: &SandboxModificationPlan,
    cpus: u8,
    memory_mib: u32,
) -> Result<(), Gate> {
    if !plan.applied {
        return Err(Gate::Inconclusive(
            "INCONCLUSIVE: the combined apply was not applied".to_string(),
        ));
    }
    let cpu = plan
        .resize_status
        .iter()
        .find(|status| status.resource == ResourceKind::Cpus);
    let memory = plan
        .resize_status
        .iter()
        .find(|status| status.resource == ResourceKind::Memory);
    let (Some(cpu), Some(memory)) = (cpu, memory) else {
        return Err(Gate::Inconclusive(format!(
            "INCONCLUSIVE: the combined apply reported {} statuses, both axes are required",
            plan.resize_status.len()
        )));
    };
    if cpu.enforced.parse::<u8>().ok() != Some(cpus) {
        return Err(Gate::Inconclusive(format!(
            "INCONCLUSIVE: combined CPU enforced {:?} != {cpus}",
            cpu.enforced
        )));
    }
    let memory_enforced = memory.enforced.trim_end_matches(" MiB").parse::<u32>().ok();
    if memory_enforced != Some(memory_mib) {
        return Err(Gate::Inconclusive(format!(
            "INCONCLUSIVE: combined memory enforced {:?} != {memory_mib} MiB",
            memory.enforced
        )));
    }
    Ok(())
}

async fn two_value_body(
    vm: &LiveVm,
    evidence: &Evidence,
    gates: &mut Vec<serde_json::Value>,
) -> Result<(), Gate> {
    let state = control_cpu(&vm.sandbox).await?;
    if state.possible != 2 {
        return Err(Gate::Inconclusive(format!(
            "INCONCLUSIVE: the two-value sandbox must have possible=2, saw {}",
            state.possible
        )));
    }
    let (desired, active) = observed_configs(&vm.sandbox).await?;
    let active = active.ok_or_else(|| {
        Gate::Inconclusive("INCONCLUSIVE: no active config on the two-value sandbox".to_string())
    })?;
    if desired.cpus != 1
        || active.cpus != 1
        || active.max_cpus != 2
        || active.memory_mib != 512
        || active.max_memory_mib != 1024
    {
        return Err(Gate::Inconclusive(format!(
            "INCONCLUSIVE: the fresh two-value sandbox is {}/{} active {} max {}/{} MiB              (expected 1/512, max 2/1024)",
            desired.cpus, desired.memory_mib, active.cpus, active.max_cpus, active.max_memory_mib
        )));
    }
    let mut rows = Vec::new();
    for target in [1u8, 2] {
        let other = 3 - target;
        let seed = vm
            .sandbox
            .modify()
            .next_start()
            .cpus(other)
            .apply()
            .await
            .map_err(|error| {
                Gate::Inconclusive(format!("INCONCLUSIVE: equality seed failed: {error}"))
            })?;
        if !seed.applied || !seed.resize_status.is_empty() {
            return Err(Gate::Inconclusive(
                "INCONCLUSIVE: the equality seed produced a live status".to_string(),
            ));
        }
        let live = vm
            .sandbox
            .modify()
            .cpus(target)
            .apply()
            .await
            .map_err(|error| {
                Gate::Inconclusive(format!("INCONCLUSIVE: equality live apply failed: {error}"))
            })?;
        accepted_cpu(&live, target)?;
        await_online(vm, target).await?;
        let noop = vm
            .sandbox
            .modify()
            .cpus(target)
            .apply()
            .await
            .map_err(|error| {
                Gate::Inconclusive(format!(
                    "INCONCLUSIVE: equality no-op apply failed: {error}"
                ))
            })?;
        let cpu_statuses = noop
            .resize_status
            .iter()
            .filter(|status| status.resource == ResourceKind::Cpus)
            .count();
        if !noop.applied || cpu_statuses != 0 {
            return Err(Gate::Inconclusive(format!(
                "INCONCLUSIVE: the saved-desired equality apply was applied={} with {cpu_statuses} CPU statuses",
                noop.applied
            )));
        }
        rows.push(json!({
            "target": target,
            "seed": other,
            "seed_applied": seed.applied,
            "live_statuses": live.resize_status.len(),
            "noop_applied": noop.applied,
            "noop_cpu_statuses": cpu_statuses,
        }));
    }
    evidence.write_json("p0e/u3-two-value.json", &rows)?;
    gates.push(json!({"gate": "U3-two-value equality", "verdict": "PASS"}));
    Ok(())
}

// ---------------------------------------------------------------------------
// Guest workload
// ---------------------------------------------------------------------------

/// Python `multiprocessing` duty worker. Deliberately daemonizes itself: the exec session that
/// launches it may end, and the workers must outlive it.
const WORKLOAD_SCRIPT: &str = r#"
import argparse
import json
import multiprocessing as mp
import os
import sys
import time


def emit(path, record):
    with open(path, "a") as handle:
        handle.write(json.dumps(record, separators=(",", ":")) + "\n")


def worker(index, duty, duration, out, stop):
    pid = os.getpid()
    start = time.monotonic_ns()
    deadline = start + duration * 1_000_000_000
    period = 100_000_000
    value = index + 1
    iterations = 0
    emit(out, {"worker": index, "pid": pid, "kind": "start", "monotonic_ns": start,
               "process_time_ns": time.process_time_ns(), "iterations": 0})
    next_checkpoint = start + 1_000_000_000
    while True:
        now = time.monotonic_ns()
        if now >= deadline or os.path.exists(stop):
            break
        busy_until = now + period * duty // 100
        while time.monotonic_ns() < busy_until:
            value = (value * 1103515245 + 12345) & 0xFFFFFFFF
            iterations += 1
        remainder = now + period - time.monotonic_ns()
        if remainder > 0:
            time.sleep(remainder / 1_000_000_000)
        now = time.monotonic_ns()
        if now >= next_checkpoint:
            emit(out, {"worker": index, "pid": os.getpid(), "kind": "checkpoint",
                       "monotonic_ns": now, "process_time_ns": time.process_time_ns(),
                       "iterations": iterations})
            next_checkpoint = now + 1_000_000_000
    emit(out, {"worker": index, "pid": os.getpid(), "kind": "end",
               "monotonic_ns": time.monotonic_ns(),
               "process_time_ns": time.process_time_ns(), "iterations": iterations})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, required=True)
    parser.add_argument("--duty", type=int, required=True)
    parser.add_argument("--duration", type=int, required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--ready", required=True)
    parser.add_argument("--pid", required=True)
    parser.add_argument("--stop", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--daemonize", action="store_true")
    args = parser.parse_args()

    if args.daemonize:
        if os.fork() > 0:
            return
        os.setsid()
        devnull = os.open(os.devnull, os.O_RDWR)
        os.dup2(devnull, 0)
        log = os.open(args.log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        os.dup2(log, 1)
        os.dup2(log, 2)

    with open(args.pid, "w") as handle:
        handle.write(str(os.getpid()) + "\n")

    context = mp.get_context("fork")
    processes = []
    for index in range(args.workers):
        process = context.Process(target=worker,
                                  args=(index, args.duty, args.duration, args.out, args.stop))
        process.start()
        processes.append(process)

    ready_deadline = time.monotonic() + 30
    while time.monotonic() < ready_deadline:
        started = 0
        try:
            with open(args.out) as handle:
                for line in handle:
                    try:
                        record = json.loads(line)
                    except ValueError:
                        continue
                    if record.get("kind") == "start":
                        started += 1
        except FileNotFoundError:
            started = 0
        if started >= args.workers:
            with open(args.ready, "w") as handle:
                json.dump({"workers": args.workers, "ready": True}, handle)
            break
        time.sleep(0.05)

    for process in processes:
        process.join()


if __name__ == "__main__":
    main()
"#;
