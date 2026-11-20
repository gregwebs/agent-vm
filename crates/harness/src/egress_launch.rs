//! The owned launch supervisor: one candidate, one private state, one receipt
//! log, and a cleanup that is proven rather than assumed (#692).
//!
//! Ported from `script/test/lib/egress-fixtures.py` (`OwnedLaunch`,
//! `list_catalog`, `cleanup_launch`, `launch`, `socket_paths`, `within`).
//!
//! What this supervisor is for: the launch runs the candidate through
//! `exec-shim` (identity receipt, stdio redirected, environment replaced) inside
//! a group `released_image_launch::run_in_owned_group` owns, while a monitor
//! thread reads the launcher's banner, its identity receipt and the private
//! catalog. Cleanup then stops and removes **by name through the CLI**, never by
//! prefix kill, and only claims success once the catalog is empty of the names it
//! owned and no recorded process identity is still alive.
//!
//! Two parts of the Python's supervisor belong to `run`: `OwnedLaunch.auxiliaries`
//! (the ingress driver, whose identity the cleanup reaps first) and the RF1/PA2
//! live witnesses, which watch the launch's log from a thread of their own while
//! the candidate runs (`egress_witness`). Both live here, because a witness that
//! is not owned by the launch would be a claim about a sandbox nobody cleaned up.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use serde_json::{Value, json};

use crate::{
    egress_cases::{CLEANUP_BOUND, Command, SUPERVISOR, admin_command, append_owned, run_admin},
    egress_fixtures::{base_environment, monotonic_nanos, process_identity, signal_identity},
    egress_witness::LiveWitness,
    msb_catalog,
    released_image_launch::{Bounds, LaunchError, LaunchSpec, exit_code, run_in_owned_group},
};

/// `resolve(path)` must stay inside `root`; a symlinked project would put the
/// launch's state somewhere the cleanup does not own.
pub fn within(path: &Path, root: &Path) -> Result<PathBuf, String> {
    let resolved = path
        .canonicalize()
        .map_err(|error| format!("{path:?}: {error}"))?;
    let root = root
        .canonicalize()
        .map_err(|error| format!("{root:?}: {error}"))?;
    if !resolved.starts_with(&root) {
        return Err(format!("path outside owned root: {}", path.display()));
    }
    Ok(resolved)
}

/// The sockets a sandbox with this name would create, in the layout the runtime
/// uses. Cleanup removes a leftover socket only after checking it *is* one.
pub fn socket_paths(root: &Path, name: &str) -> Vec<PathBuf> {
    let digest = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(name.as_bytes());
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    vec![
        root.join("run/sandboxes")
            .join(&digest[..24])
            .join("agent.sock"),
        root.join("run/sandboxes")
            .join(&digest[..24])
            .join("control.sock"),
        root.join("run/agent")
            .join(format!("{}.sock", &digest[..32])),
        root.join("run/agent")
            .join(format!("{}.control.sock", &digest[..32])),
    ]
}

/// The names the private catalog holds, read through the CLI's own `list`.
pub(crate) fn list_catalog(
    work: &Path,
    binary: &str,
    deadline: Option<Instant>,
) -> Result<BTreeSet<String>, String> {
    let (status, text) = run_admin(
        work,
        &admin_command(work, binary, "list", &["list", "--format", "json"], 10.0),
        deadline,
    )?;
    if status != 0 {
        return Err(format!("private list failed: {status}"));
    }
    let rows: Value = serde_json::from_str(&text).map_err(|error| error.to_string())?;
    let Some(rows) = rows.as_array() else {
        return Err("private list JSON schema mismatch".to_owned());
    };
    let mut names = BTreeSet::new();
    for row in rows {
        match row.get("name").and_then(Value::as_str) {
            Some(name) => names.insert(name.to_owned()),
            None => return Err("private list JSON schema mismatch".to_owned()),
        };
    }
    Ok(names)
}

/// What the monitor observed. Behind one lock because it is written from the
/// monitor thread and read from the launch, the witness and cleanup.
#[derive(Default)]
pub(crate) struct Observed {
    pub(crate) launcher: Option<Value>,
    /// Whether the launcher's phase was already written to the receipt log.
    launcher_recorded: bool,
    names: BTreeSet<String>,
    runtimes: BTreeMap<String, Value>,
    primary: Option<i32>,
    effective_profile: Option<String>,
    pub(crate) errors: Vec<String>,
    cleanup_errors: Vec<String>,
    cleaned: bool,
}

/// A child of the run that is not the launch itself: today the ingress driver,
/// whose identity is reaped before anything else so a driver cannot outlive the
/// sandbox it was polling and report a status after cleanup.
pub struct Auxiliary {
    child: std::process::Child,
    identity: Value,
}

pub struct OwnedLaunch {
    work: PathBuf,
    command: Command,
    ident: String,
    root: PathBuf,
    project: PathBuf,
    project_hash: String,
    log: PathBuf,
    identity_file: PathBuf,
    observed: Arc<Mutex<Observed>>,
    auxiliaries: Mutex<Vec<Auxiliary>>,
}

impl OwnedLaunch {
    pub fn new(work: &Path, command: &Command, ident: String) -> Result<Self, String> {
        let work = work
            .canonicalize()
            .map_err(|error| format!("{work:?}: {error}"))?;
        let root = within(&work.join("state/msb-home"), &work)?;
        let project = within(Path::new(&command.cwd), &work)?;
        let project_hash = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(project.as_os_str().as_encoded_bytes());
            hasher
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        let owned = Self {
            log: work.join(format!("{ident}.log")),
            identity_file: work.join(format!("{ident}.identity.json")),
            work,
            command: command.clone(),
            ident,
            root,
            project,
            project_hash: project_hash[..12].to_owned(),
            observed: Arc::new(Mutex::new(Observed::default())),
            auxiliaries: Mutex::new(Vec::new()),
        };
        owned.record("prepared")?;
        Ok(owned)
    }

    pub fn ident(&self) -> &str {
        &self.ident
    }

    pub fn log(&self) -> &Path {
        &self.log
    }

    pub fn project_hash(&self) -> &str {
        &self.project_hash
    }

    /// The state directory this launch owns under the private root.
    pub fn state_dir(&self) -> PathBuf {
        self.work.join("state").join(&self.project_hash)
    }

    fn push_error(&self, error: String) {
        let mut observed = self.observed.lock().expect("the observation lock");
        if !observed.errors.contains(&error) {
            observed.errors.push(error);
        }
    }

    /// One receipt line for a phase, carrying everything known at that moment.
    fn receipt(&self, phase: &str) -> Value {
        let observed = self.observed.lock().expect("the observation lock");
        let mut sockets = Vec::new();
        for name in &observed.names {
            sockets.extend(
                socket_paths(&self.root, name)
                    .iter()
                    .map(|path| Value::String(path.to_string_lossy().into_owned())),
            );
        }
        json!({
            "phase": phase,
            "launch": self.ident,
            "command": self.command.plan_with(Some(&self.log), Some(&self.identity_file)),
            "project": self.project.to_string_lossy(),
            "msb_root": self.root.to_string_lossy(),
            "launcher": observed.launcher,
            "names": observed.names.iter().collect::<Vec<&String>>(),
            "runtimes": observed.runtimes.values().collect::<Vec<&Value>>(),
            // `run`'s orchestration adopts auxiliary processes; `launch` owns none.
            "auxiliaries": self.auxiliaries.lock().expect("the auxiliary lock").iter()
                .map(|auxiliary| auxiliary.identity.clone())
                .collect::<Vec<Value>>(),
            "primary_status": observed.primary,
            "effective_profile": observed.effective_profile,
            "sockets": sockets,
            "observation_errors": observed.errors,
            "cleanup_errors": observed.cleanup_errors,
        })
    }

    fn record(&self, phase: &str) -> Result<(), String> {
        append_owned(&self.work, &self.receipt(phase))
    }

    /// Read what the launcher and the catalog say right now.
    ///
    /// The launcher's banner names one sandbox and its private state; a banner
    /// that names a different sandbox or state is an ownership mismatch, not a
    /// row to ignore, because the cleanup would then stop someone else's sandbox.
    pub fn observe(&self) -> Result<(), String> {
        let launcher = {
            let mut observed = self.observed.lock().expect("the observation lock");
            if observed.launcher.is_none() && self.identity_file.exists() {
                let receipt: Value = serde_json::from_slice(
                    &fs::read(&self.identity_file).map_err(|error| error.to_string())?,
                )
                .map_err(|error| error.to_string())?;
                if receipt.get("start").is_none_or(Value::is_null) {
                    return Err("launcher lacks start identity".to_owned());
                }
                observed.launcher = Some(receipt);
            }
            observed.launcher.clone()
        };
        if launcher.is_none() {
            return Ok(());
        }
        if !self
            .observed
            .lock()
            .expect("the observation lock")
            .launcher_recorded
        {
            self.record("launcher")?;
            self.observed
                .lock()
                .expect("the observation lock")
                .launcher_recorded = true;
        }
        let expected = format!(
            "agent-vm-{}-{}",
            self.project_hash,
            launcher
                .as_ref()
                .and_then(|launcher| launcher.get("pid"))
                .and_then(Value::as_u64)
                .unwrap_or_default()
        );
        if self.log.exists() {
            let text = fs::read(&self.log)
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                .map_err(|error| error.to_string())?;
            for banner in banners(&text) {
                if banner.name != expected {
                    return Err("launch banner ownership mismatch".to_owned());
                }
                if Path::new(&banner.project)
                    .canonicalize()
                    .map_err(|error| format!("{}: {error}", banner.project))?
                    != self.project
                {
                    return Err("launch banner ownership mismatch".to_owned());
                }
                if within(Path::new(&banner.state), &self.work)? != self.state_dir() {
                    return Err("launch banner private state mismatch".to_owned());
                }
                self.observed
                    .lock()
                    .expect("the observation lock")
                    .names
                    .insert(banner.name);
            }
        }
        for row in msb_catalog::catalog_rows(&self.root)? {
            if row.name != expected {
                // Other recorded launches are the run-wide inventory's business.
                continue;
            }
            let mut observed = self.observed.lock().expect("the observation lock");
            observed.names.insert(expected.clone());
            if let Some(profile) = msb_catalog::config_profile(&row) {
                observed.effective_profile = Some(profile);
            }
            let Some(pid) = row.pid else { continue };
            if row.run_status.as_deref() != Some("Running") {
                continue;
            }
            let Ok(pid) = u32::try_from(pid) else {
                continue;
            };
            let token = process_identity(pid)?;
            let key = msb_catalog::run_key(&row).unwrap_or_else(|| pid.to_string());
            match observed.runtimes.get(&key) {
                Some(recorded) => {
                    let recorded_start = recorded.get("start").cloned().unwrap_or(Value::Null);
                    let current = token.map(|start| json!(start)).unwrap_or(Value::Null);
                    if current != recorded_start {
                        return Err("runtime identity changed during observation".to_owned());
                    }
                }
                None => {
                    if let Some(start) = token {
                        let relation = if pgid(pid) == launcher_pgid(&launcher) {
                            "launcher-group"
                        } else {
                            "separate-group"
                        };
                        observed.runtimes.insert(
                            key,
                            json!({
                                "pid": pid,
                                "start": start,
                                "run_id": msb_catalog::run_key(&row),
                                "pgid": pgid(pid),
                                "group_relation": relation,
                            }),
                        );
                        drop(observed);
                        self.record("runtime")?;
                        // The guard was released for the receipt write; the next
                        // row re-acquires it.
                        continue;
                    }
                }
            }
        }
        if self
            .observed
            .lock()
            .expect("the observation lock")
            .names
            .len()
            > 1
        {
            return Err("more than one owned sandbox".to_owned());
        }
        Ok(())
    }

    /// Launch the candidate and monitor it until it is gone.
    ///
    /// The monitor is a scoped thread: it stops on its next 50 ms tick once the
    /// launch returns, so there is no join timeout to get wrong, and the launch's
    /// own bound is what ends a stuck candidate (never a wait here).
    ///
    /// A live witness (RF1, PA2) is a thread of its own: it has an internal
    /// deadline and the shared stop flag, and the join is bounded at
    /// `WITNESS_JOIN`. A witness still waiting then is reported and left to its
    /// own deadline rather than blocking the cleanup that must follow it.
    pub fn run(&self) -> Result<i32, String> {
        let stop = Arc::new(AtomicBool::new(false));
        let witness = self.spawn_witness(&stop);
        let mut primary = 0;
        std::thread::scope(|scope| {
            let monitor = scope.spawn(|| {
                while !stop.load(Ordering::SeqCst) {
                    if let Err(error) = self.observe() {
                        self.push_error(error);
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            });
            primary = self.supervise();
            stop.store(true, Ordering::SeqCst);
            monitor.join().expect("the monitor cannot panic on its own");
        });
        if let Some(witness) = witness {
            let until = Instant::now() + WITNESS_JOIN;
            while !witness.is_finished() && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(50));
            }
            if !witness.is_finished() {
                self.push_error("live access did not finish within bound".to_owned());
            }
        }
        // One last read, now that nothing is racing it, and the ownership claim
        // that a launch without an identity receipt must not pass silently.
        if let Err(error) = self.observe() {
            self.push_error(error);
        }
        if self
            .observed
            .lock()
            .expect("the observation lock")
            .launcher
            .is_none()
        {
            self.push_error("launcher identity was never recorded".to_owned());
        }
        self.observed.lock().expect("the observation lock").primary = Some(primary);
        self.record("primary")?;
        Ok(primary)
    }

    /// Start the case's live witness, if it has one.
    ///
    /// The thread owns a copy of everything it reads, so it can outlive the
    /// borrow that started it; the shared observation is what RF1's kill9 variant
    /// needs to signal the launcher and what both report their errors through.
    fn spawn_witness(&self, stop: &Arc<AtomicBool>) -> Option<std::thread::JoinHandle<()>> {
        if !matches!(self.command.case.as_str(), "RF1" | "PA2") {
            return None;
        }
        let witness = LiveWitness {
            work: self.work.clone(),
            command: self.command.clone(),
            log: self.log.clone(),
            sessions: self
                .work
                .join("state")
                .join(format!("{}.sessions", self.project_hash)),
            stop: Arc::clone(stop),
            observed: Arc::clone(&self.observed),
        };
        let handle = std::thread::Builder::new()
            .name(format!("{}-witness", self.command.case))
            .spawn(move || {
                if witness.command.case == "RF1" {
                    witness.refusal_feed_while_running();
                } else {
                    witness.live_allowance_while_running();
                }
            });
        match handle {
            Ok(handle) => Some(handle),
            Err(error) => {
                self.push_error(format!("witness thread: {error}"));
                None
            }
        }
    }

    /// Adopt a child the run started beside the launch (the ingress driver).
    pub fn adopt(&self, child: std::process::Child, identity: Value) {
        self.auxiliaries
            .lock()
            .expect("the auxiliary lock")
            .push(Auxiliary { child, identity });
    }

    /// The identities of the adopted children, for the run-wide absence checks.
    pub fn auxiliaries(&self) -> Vec<Value> {
        self.auxiliaries
            .lock()
            .expect("the auxiliary lock")
            .iter()
            .map(|auxiliary| auxiliary.identity.clone())
            .collect()
    }

    /// Wait for the adopted children after their guest has finished: 12 s, then
    /// SIGTERM, 2 s, then SIGKILL, 2 s. One status per child that answered; a
    /// child that survives all three is an error, because the cleanup that
    /// follows must not race it.
    pub fn join_auxiliaries(&self, terminate: bool) -> Result<Vec<i32>, String> {
        let mut statuses = Vec::new();
        let mut auxiliaries = self.auxiliaries.lock().expect("the auxiliary lock");
        for auxiliary in auxiliaries.iter_mut() {
            if terminate {
                signal(&mut auxiliary.child, &auxiliary.identity, libc::SIGTERM)?;
            }
            if let Some(status) = wait_bound(&mut auxiliary.child, Duration::from_secs(12))? {
                statuses.push(status);
                continue;
            }
            signal(&mut auxiliary.child, &auxiliary.identity, libc::SIGTERM)?;
            if let Some(status) = wait_bound(&mut auxiliary.child, Duration::from_secs(2))? {
                statuses.push(status);
                continue;
            }
            signal(&mut auxiliary.child, &auxiliary.identity, libc::SIGKILL)?;
            match wait_bound(&mut auxiliary.child, Duration::from_secs(2))? {
                Some(status) => statuses.push(status),
                None => return Err("ingress driver survived its signals".to_owned()),
            }
        }
        Ok(statuses)
    }

    /// Reap the adopted children before anything else: SIGTERM, a short bound,
    /// then SIGKILL, a second bound. An auxiliary that outlives both is a
    /// failure, not a process the cleanup leaves behind.
    fn reap_auxiliaries(&self, limit: Instant) -> Vec<String> {
        let mut failures = Vec::new();
        let mut auxiliaries = self.auxiliaries.lock().expect("the auxiliary lock");
        for auxiliary in auxiliaries.iter_mut() {
            if let Ok(Some(_)) = auxiliary.child.try_wait() {
                continue;
            }
            let bound = limit
                .saturating_duration_since(Instant::now())
                .min(Duration::from_secs(2));
            if let Err(error) = signal(&mut auxiliary.child, &auxiliary.identity, libc::SIGTERM) {
                failures.push(error);
                continue;
            }
            match wait_bound(&mut auxiliary.child, bound) {
                Ok(Some(_)) => continue,
                Ok(None) => {}
                Err(error) => {
                    failures.push(error);
                    continue;
                }
            }
            if let Err(error) = signal(&mut auxiliary.child, &auxiliary.identity, libc::SIGKILL) {
                failures.push(error);
                continue;
            }
            let bound = limit
                .saturating_duration_since(Instant::now())
                .min(Duration::from_secs(2));
            match wait_bound(&mut auxiliary.child, bound) {
                Ok(Some(_)) => {}
                Ok(None) => failures.push("an auxiliary process survived both signals".to_owned()),
                Err(error) => failures.push(error),
            }
        }
        failures
    }

    /// The supervised candidate itself: `exec-shim` argv, the launch's own
    /// environment, and the bound from the command.
    fn supervise(&self) -> i32 {
        let bounds = match Bounds::new(self.command.timeout, self.command.grace) {
            Ok(bounds) => bounds,
            Err(error) => {
                self.push_error(error.to_string());
                return 2;
            }
        };
        let spec = LaunchSpec {
            argv: crate::egress_cases::shim_argv(
                &self.command.argv,
                &self.log,
                &self.command.env,
                Some(&self.identity_file),
            )
            .into_iter()
            .map(OsString::from)
            .collect(),
            env: self
                .command
                .env
                .iter()
                .map(|(name, value)| (OsString::from(name), OsString::from(value)))
                .collect(),
            cwd: Some(self.project.clone()),
        };
        match run_in_owned_group(&spec, bounds, &mut ()) {
            Ok(status) => exit_code(status),
            Err(LaunchError::TimedOut) => 124,
            Err(LaunchError::Interrupted(signal)) => 128 + signal.as_raw(),
            Err(error) => {
                self.push_error(error.to_string());
                2
            }
        }
    }

    /// The observation's own findings, for the caller that reports them.
    pub fn errors(&self) -> Vec<String> {
        self.observed
            .lock()
            .expect("the observation lock")
            .errors
            .clone()
    }

    /// The profile the stored sandbox spec pins, if the catalog recorded one.
    pub fn effective_profile(&self) -> Option<String> {
        self.observed
            .lock()
            .expect("the observation lock")
            .effective_profile
            .clone()
    }

    /// The sandbox names this launch owns.
    pub fn names(&self) -> BTreeSet<String> {
        self.observed
            .lock()
            .expect("the observation lock")
            .names
            .clone()
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn work(&self) -> &Path {
        &self.work
    }

    /// Every recorded identity that is still alive, and a refusal to guess when a
    /// pid was recycled: a reused pid is not absence evidence, and not presence.
    pub fn alive(&self) -> Result<Vec<Value>, String> {
        let observed = self.observed.lock().expect("the observation lock");
        let mut identities: Vec<Value> = Vec::new();
        if let Some(launcher) = &observed.launcher {
            identities.push(launcher.clone());
        }
        identities.extend(observed.runtimes.values().cloned());
        drop(observed);
        let mut live = Vec::new();
        for identity in identities {
            let Some(pid) = identity.get("pid").and_then(Value::as_u64) else {
                continue;
            };
            let Ok(pid) = u32::try_from(pid) else {
                continue;
            };
            if let Some(token) = process_identity(pid)? {
                let recorded = identity.get("start").cloned().unwrap_or(Value::Null);
                if json!(token) != recorded {
                    return Err("owned PID reused; no absence claim".to_owned());
                }
                live.push(identity);
            }
        }
        Ok(live)
    }

    /// Cleanup: CLI verbs for the owned names, then identity signals, then a
    /// verified empty catalog. Returns the failures it found; an empty vector is
    /// the only clean answer.
    pub fn cleanup(&self, deadline: Option<Instant>) -> Vec<String> {
        {
            let observed = self.observed.lock().expect("the observation lock");
            if observed.cleaned {
                return observed.cleanup_errors.clone();
            }
        }
        let limit = deadline.unwrap_or_else(|| Instant::now() + Duration::from_secs(86_400));
        let limit = limit.min(Instant::now() + Duration::from_secs_f64(CLEANUP_BOUND));
        let binary = self.command.argv.first().cloned().unwrap_or_default();
        if let Err(error) = self.observe() {
            self.push_error(error);
        }
        let mut failures = Vec::new();
        failures.extend(self.reap_auxiliaries(limit));
        let (names, errors) = {
            let observed = self.observed.lock().expect("the observation lock");
            (observed.names.clone(), observed.errors.clone())
        };
        let mut failures = errors;
        failures.extend(self.reap_auxiliaries(limit));
        let listed = match list_catalog(&self.work, &binary, Some(limit)) {
            Ok(listed) => listed,
            Err(error) => {
                failures.push(error);
                names.clone()
            }
        };
        for name in names.intersection(&listed) {
            let mut stop_status = None;
            for (verb, args, bound) in [
                ("stop", vec!["stop", "--timeout", "5", name.as_str()], 15.0),
                ("force-stop", vec!["stop", "--force", name.as_str()], 10.0),
                ("remove", vec!["remove", name.as_str()], 10.0),
            ] {
                if verb == "force-stop"
                    && stop_status == Some(0)
                    && self.alive().is_ok_and(|live| live.is_empty())
                {
                    continue;
                }
                let command = admin_command(&self.work, &binary, verb, &args, bound);
                let status = run_admin(&self.work, &command, Some(limit))
                    .map(|(status, _)| status)
                    .unwrap_or_else(|error| {
                        failures.push(error);
                        1
                    });
                if verb == "stop" {
                    stop_status = Some(status);
                }
                if let Err(error) = self.observe() {
                    failures.push(error);
                }
                if status != 0 {
                    failures.push(format!("{verb} {name}: status {status}"));
                }
            }
        }
        match self.alive() {
            Ok(live) => {
                for identity in live {
                    for signal in [libc::SIGTERM, libc::SIGKILL] {
                        if Instant::now() >= limit {
                            failures.push("cleanup identity deadline".to_owned());
                            break;
                        }
                        if let Err(error) = signal_identity(&identity, signal) {
                            failures.push(error);
                            break;
                        }
                        let pid = identity
                            .get("pid")
                            .and_then(Value::as_u64)
                            .and_then(|pid| u32::try_from(pid).ok());
                        let until = limit.min(Instant::now() + Duration::from_secs(1));
                        while Instant::now() < until {
                            let gone = match pid {
                                Some(pid) => match process_identity(pid) {
                                    Ok(token) => token.is_none(),
                                    Err(_) => false,
                                },
                                None => true,
                            };
                            if gone {
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(50));
                        }
                    }
                }
            }
            Err(error) => failures.push(error),
        }
        let verify_until = limit.min(Instant::now() + Duration::from_secs(10));
        loop {
            if let Err(error) = self.observe() {
                failures.push(error);
                break;
            }
            let remaining = match list_catalog(&self.work, &binary, Some(verify_until)) {
                Ok(listed) => listed
                    .intersection(&self.observed.lock().expect("the observation lock").names)
                    .cloned()
                    .collect::<BTreeSet<String>>(),
                Err(error) => {
                    failures.push(error);
                    break;
                }
            };
            let live = match self.alive() {
                Ok(live) => live,
                Err(error) => {
                    failures.push(error);
                    Vec::new()
                }
            };
            let mut paths = Vec::new();
            for name in self
                .observed
                .lock()
                .expect("the observation lock")
                .names
                .clone()
            {
                paths.extend(socket_paths(&self.root, &name));
            }
            let mut redirected = false;
            for path in &paths {
                let Ok(resolved) = within(path, &self.work) else {
                    failures.push(format!("owned socket path redirected: {}", path.display()));
                    redirected = true;
                    break;
                };
                if resolved != *path {
                    failures.push(format!("owned socket path redirected: {}", path.display()));
                    redirected = true;
                    break;
                }
            }
            if redirected {
                break;
            }
            if remaining.is_empty() && live.is_empty() {
                for path in &paths {
                    if path.exists() {
                        // Only a stale socket, never an arbitrary file or link.
                        let is_socket = path
                            .symlink_metadata()
                            .map(|metadata| {
                                use std::os::unix::fs::FileTypeExt;
                                metadata.file_type().is_socket()
                            })
                            .unwrap_or(false);
                        if !is_socket {
                            failures
                                .push(format!("owned socket is not a socket: {}", path.display()));
                            continue;
                        }
                        if let Err(error) = fs::remove_file(path) {
                            failures.push(format!("{}: {error}", path.display()));
                        } else {
                            let _ = append_owned(
                                &self.work,
                                &json!({"phase": "stale-socket-removed", "path": path.to_string_lossy()}),
                            );
                        }
                    }
                }
                break;
            }
            if Instant::now() >= verify_until {
                failures.push(format!(
                    "cleanup survivors: catalog={remaining:?} identities={live:?}"
                ));
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        {
            let mut observed = self.observed.lock().expect("the observation lock");
            observed.cleaned = true;
            observed.cleanup_errors.extend(failures.clone());
        }
        if let Err(error) = self.record("cleanup") {
            failures.push(error);
        }
        failures
    }
}

/// Bound on the join of a live witness thread; the witness's own deadlines are
/// what end it in practice, and a witness still running here is reported rather
/// than joined, so the cleanup that follows cannot be held up by it.
const WITNESS_JOIN: Duration = Duration::from_secs(30);

/// One signal to an adopted child: by identity while the token is known (a
/// recycled pid must never be signalled), by pid alone when the child was never
/// observed well enough to record one.
fn signal(child: &mut std::process::Child, identity: &Value, number: i32) -> Result<(), String> {
    if identity.get("start").is_none_or(Value::is_null) {
        let _ = child.kill();
        return Ok(());
    }
    signal_identity(identity, number).map(|_| ())
}

/// Wait for a child within a bound. `Ok(None)` is the bound expiring, which the
/// caller escalates; anything longer than `bound` would be the unbounded wait a
/// cleanup must never make.
fn wait_bound(child: &mut std::process::Child, bound: Duration) -> Result<Option<i32>, String> {
    let until = Instant::now() + bound;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(Some(exit_code(status))),
            Ok(None) if Instant::now() >= until => return Ok(None),
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => return Err(error.to_string()),
        }
    }
}

struct Banner {
    name: String,
    project: String,
    state: String,
}

/// The launcher's `==> agent-vm-<hash>-<pid> in <project> (state: <state>)`
/// banner. The Python matched it with a regex anywhere in the text; a banner is a
/// whole line, so line-anchored parsing finds the same ones.
fn banners(text: &str) -> Vec<Banner> {
    let mut found = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("==> ") else {
            continue;
        };
        let Some((name, rest)) = rest.split_once(" in ") else {
            continue;
        };
        let Some((project, state)) = rest.split_once(" (state: ") else {
            continue;
        };
        let Some(state) = state.strip_suffix(')') else {
            continue;
        };
        if name.starts_with("agent-vm-") && !name.contains(char::is_whitespace) {
            found.push(Banner {
                name: name.to_owned(),
                project: project.to_owned(),
                state: state.to_owned(),
            });
        }
    }
    found
}

fn pgid(pid: u32) -> Option<u32> {
    let pid = rustix::process::Pid::from_raw(i32::try_from(pid).ok()?)?;
    let pgid = rustix::process::getpgid(Some(pid)).ok()?;
    u32::try_from(pgid.as_raw_nonzero().get()).ok()
}

fn launcher_pgid(launcher: &Option<Value>) -> Option<u32> {
    launcher
        .as_ref()
        .and_then(|launcher| launcher.get("pgid"))
        .and_then(Value::as_u64)
        .and_then(|pgid| u32::try_from(pgid).ok())
}

/// `launch --work W --case C --timeout T --grace G [--env K=V] -- argv`.
///
/// The `--env` extras are whitelisted by case: proxy variables for `PX*`, the
/// floor config for `FL*`, nothing else. The Python raised `ValueError` here
/// (exit 1 with a traceback); this returns a refusal with the same status.
pub fn launch(
    work: &Path,
    case: &str,
    timeout: f64,
    grace: f64,
    envs: &[String],
    argv: &[String],
) -> Result<i32, String> {
    let work = work
        .canonicalize()
        .map_err(|error| format!("{work:?}: {error}"))?;
    let mut env = base_environment(&work);
    for item in envs {
        let Some((key, value)) = item.split_once('=') else {
            return Err("launch environment permits only PX/FL extras".to_owned());
        };
        let permitted: &[&str] = if case.starts_with("PX") {
            &["HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"]
        } else if case.starts_with("FL") {
            &["MSB_CONFIG_PATH"]
        } else {
            &[]
        };
        if !permitted.contains(&key) {
            return Err("launch environment permits only PX/FL extras".to_owned());
        }
        env.push((key.to_owned(), value.to_owned()));
    }
    let command = Command {
        case: case.to_owned(),
        variant: "manual".to_owned(),
        tool: None,
        kind: "guest".to_owned(),
        env,
        argv: argv.to_vec(),
        cwd: work.join("proj").to_string_lossy().into_owned(),
        timeout,
        grace,
        declared_extras: Vec::new(),
        prerequisites: Vec::new(),
        controls: None,
        setup: Vec::new(),
        expected_attempts: Vec::new(),
        attempt_expectations: None,
        attempt_protocols: None,
        supervisor: SUPERVISOR.to_owned(),
    };
    // A bound that cannot terminate is refused before anything is spawned.
    if timeout <= 0.0 || !timeout.is_finite() || grace <= 0.0 || !grace.is_finite() {
        return Err(format!(
            "usage: launch: timeout and grace must be finite and positive, got {timeout} and {grace}"
        ));
    }
    fs::create_dir_all(work.join("proj")).map_err(|error| error.to_string())?;
    let owned = OwnedLaunch::new(&work, &command, format!("{case}-{}", monotonic_nanos()))?;
    let status = owned.run()?;
    let failures = owned.cleanup(None);
    Ok(if status != 0 {
        status
    } else if failures.is_empty() {
        0
    } else {
        1
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn launch_command(work: &Path) -> Command {
        Command {
            case: "LC1".to_owned(),
            variant: "ipv4".to_owned(),
            tool: None,
            kind: "guest".to_owned(),
            env: base_environment(work),
            argv: vec!["/bin/true".to_owned()],
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

    fn scratch(label: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("harness-launch-{label}-{}", monotonic_nanos()));
        fs::create_dir_all(path.join("proj")).expect("a scratch project");
        fs::create_dir_all(path.join("home")).expect("a scratch home");
        fs::create_dir_all(path.join("state/msb-home")).expect("a private state root");
        path
    }

    #[test]
    fn an_environment_extra_outside_the_whitelist_is_refused() {
        let work = scratch("whitelist");
        let candidate = work.join("fake-agent-vm");
        fs::write(&candidate, "#!/bin/sh\nexit 0\n").expect("a candidate path");
        for (case, env) in [
            ("LC1", "HTTP_PROXY=http://127.0.0.1:18888"),
            ("PX1", "MSB_CONFIG_PATH=/tmp/floor.json"),
            ("FL1", "NO_PROXY=192.168.1.0/24"),
            ("PX1", "NOT_AN_ASSIGNMENT"),
        ] {
            let refused = launch(
                &work,
                case,
                30.0,
                5.0,
                &[env.to_owned()],
                &[candidate.to_string_lossy().into_owned()],
            )
            .expect_err("an unpermitted extra is refused");
            assert!(
                refused.contains("launch environment permits only PX/FL extras"),
                "{case}/{env}: {refused}"
            );
        }
        // Nothing was spawned, so there is no receipt log at all.
        assert!(!work.join("owned.jsonl").exists());
        let _ = fs::remove_dir_all(&work);
    }

    #[test]
    fn a_banner_names_the_owned_sandbox_or_it_is_a_mismatch() {
        let banner = |line: &str| {
            banners(line)
                .into_iter()
                .map(|banner| (banner.name, banner.project, banner.state))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            banner(
                "==> agent-vm-0123456789ab-4242 in /tmp/w/proj (state: /tmp/w/state/0123456789ab)"
            ),
            [(
                "agent-vm-0123456789ab-4242".to_owned(),
                "/tmp/w/proj".to_owned(),
                "/tmp/w/state/0123456789ab".to_owned()
            )]
        );
        // A line that is not a banner, a banner with no state, and a foreign name
        // are all ignored rather than read as ownership evidence.
        assert!(banner("starting agent-vm-x in /tmp (state: /tmp)").is_empty());
        assert!(banner("==> agent-vm-abc-1 in /tmp/w/proj").is_empty());
        assert!(banner("==> sandbox-abc in /tmp/w/proj (state: /tmp)").is_empty());
    }

    #[test]
    fn the_socket_paths_are_the_runtimes_layout() {
        let root = Path::new("/msb-home");
        let paths = socket_paths(root, "agent-vm-abc-4242");
        assert_eq!(paths.len(), 4);
        let digest = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(b"agent-vm-abc-4242");
            hasher
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        assert!(paths[0].ends_with(format!("run/sandboxes/{}/agent.sock", &digest[..24])));
        assert!(paths[1].ends_with(format!("run/sandboxes/{}/control.sock", &digest[..24])));
        assert!(paths[2].ends_with(format!("run/agent/{}.sock", &digest[..32])));
        assert!(paths[3].ends_with(format!("run/agent/{}.control.sock", &digest[..32])));
    }

    #[test]
    fn only_the_two_live_cases_start_a_witness_that_stops_and_leaves_evidence() {
        let work = scratch("witness");
        // Stopped before it starts, so each witness takes its own short path: the
        // point is that the thread exists, respects the stop flag, and writes what
        // the run reads back — not that a live sandbox was reachable.
        let stop = Arc::new(AtomicBool::new(true));
        for case in ["RF1", "PA2"] {
            let command = Command {
                case: case.to_owned(),
                variant: "ipv4".to_owned(),
                ..launch_command(&work)
            };
            let owned =
                OwnedLaunch::new(&work, &command, format!("{case}-control")).expect("a launch");
            let witness = owned
                .spawn_witness(&stop)
                .expect("the live cases have a witness");
            witness.join().expect("the stopped witness returns at once");
            // RF1's verdict reads the launch's own error list; PA2's reads the
            // evidence file, which is why that half is asserted below.
            if case == "RF1" {
                assert_eq!(
                    owned.errors(),
                    ["RF1 READY never appeared".to_owned()],
                    "a witness that saw nothing must say so"
                );
            }
        }
        assert!(
            work.join("PA2-witness.json").exists(),
            "the witness left no evidence"
        );
        let evidence: Value = serde_json::from_slice(
            &fs::read(work.join("PA2-witness.json")).expect("the evidence file"),
        )
        .expect("the evidence is JSON");
        assert!(
            !evidence["failures"]
                .as_array()
                .expect("a failure list")
                .is_empty(),
            "{evidence}"
        );
        // The signal files are released whether or not a step succeeded.
        for signal in crate::egress_allowances::PA2_SIGNALS {
            assert!(work.join("proj").join(signal).exists(), "{signal}");
        }
        // A case with no live claim starts no thread at all.
        let plain = Command {
            case: "LC1".to_owned(),
            variant: "ipv4".to_owned(),
            ..launch_command(&work)
        };
        let owned = OwnedLaunch::new(&work, &plain, "LC1-control".to_owned()).expect("a launch");
        assert!(owned.spawn_witness(&stop).is_none());
        let _ = fs::remove_dir_all(&work);
    }
}
