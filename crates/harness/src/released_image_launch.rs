//! The released-image launch helper (ADR-0072, #691).
//!
//! `script/test/released-image-launch.py` launched an installed released-image
//! candidate as an owned, bounded process group. `subprocess.run(timeout=...)`
//! kills and waits only for the direct child; on the npm route that child is
//! Node, which spawns the native launcher, so a timeout could leave the native
//! process -- and the VM it owns -- alive and mutating private test state after
//! the harness exited. The candidate therefore runs in its own session, and the
//! whole owned group is signalled (TERM, a bounded grace, then KILL) and reaped
//! on timeout *and* on parent interruption (Ctrl-C / SIGTERM), because a
//! new-session child does not get the terminal's signal.
//!
//! Only the process group this helper created is ever signalled. Both bounds
//! are validated before the child is spawned, so a NaN, infinite or
//! non-positive bound cannot disable termination, and a timeout is exit status
//! 124 -- the historical `subprocess.run(timeout=...)` mapping, so callers keep
//! treating a timeout as a bounded failure rather than a signal death.
//!
//! The Python copy stays on disk until its last importer is ported (#692),
//! under the bottom-up rule; there is no glue from it to here.

use std::{
    ffi::OsString,
    fmt, fs, io,
    os::unix::process::{CommandExt, ExitStatusExt},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::atomic::{AtomicI32, Ordering},
    thread,
    time::{Duration, Instant},
};

use clap::Args;
use rustix::process::{self, Pid, Signal};

use crate::Outcome;

/// Exit status of a launch that overran its bound. Matches `timeout(1)` and the
/// historical `subprocess.run(timeout=...)` refusal.
const TIMEOUT_EXIT: i32 = 124;

/// SIGKILL cannot be caught, so a direct child that is `SIGKILL`ed and still not
/// reapable within this bound is a host-level failure. Bounded so an escalation
/// that cannot complete surfaces as an error instead of blocking forever.
const KILL_REAP_TIMEOUT: Duration = Duration::from_secs(5);

/// Bound on the `ps` query that confirms an empty process group.
const PS_TIMEOUT: Duration = Duration::from_secs(5);

/// Wait-poll granularity. CPython's `Popen.wait(timeout=...)` polls the same way
/// (0.5 ms doubling to 50 ms). A 20 ms slice reacts to a signal or to the bound
/// within one slice, and costs 45 000 cheap wakeups over the default 900 s
/// bound -- the price of noticing a signal without a self-pipe.
const POLL_SLICE: Duration = Duration::from_millis(20);

#[derive(Debug, Args)]
pub struct ReleasedImageLaunchArgs {
    /// Per-route private state root for the isolated environment.
    #[arg(
        long,
        value_name = "PATH",
        required_unless_present_any = ["canonicalize", "self_test"],
        conflicts_with_all = ["canonicalize", "self_test"]
    )]
    root: Option<PathBuf>,

    /// Decoy PATH prefix the launched candidate sees.
    #[arg(long, value_name = "DIR", required_unless_present_any = ["canonicalize", "self_test"])]
    shim: Option<PathBuf>,

    /// Builder-decoy provenance log.
    #[arg(long, value_name = "PATH", required_unless_present_any = ["canonicalize", "self_test"])]
    log: Option<PathBuf>,

    /// Installed candidate path.
    #[arg(long, value_name = "PATH", required_unless_present_any = ["canonicalize", "self_test"])]
    binary: Option<PathBuf>,

    /// Vetted absolute Node interpreter for an npm dispatcher candidate.
    #[arg(long, value_name = "PATH", default_value = "")]
    interpreter: OsString,

    /// Bound on the launch, in seconds.
    #[arg(long, value_name = "SECONDS", default_value_t = 900.0)]
    timeout: f64,

    /// Grace between SIGTERM and SIGKILL, in seconds.
    #[arg(long, value_name = "SECONDS", default_value_t = 10.0)]
    grace: f64,

    /// Print the canonical form of PATH, resolving the symlinks of its existing
    /// prefix, instead of launching.
    #[arg(long, value_name = "PATH")]
    canonicalize: Option<PathBuf>,

    /// Run the boot-free launch, timeout and interruption controls.
    #[arg(long)]
    self_test: bool,

    /// Candidate argv; `--` separates it from the launch options.
    #[arg(
        value_name = "ARGS",
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    args: Vec<OsString>,
}

pub fn run(args: ReleasedImageLaunchArgs) -> Result<Outcome, String> {
    if args.self_test {
        self_test()?;
        return Ok(Outcome::Report(
            "released-image launch timeout/interruption/group controls passed".to_owned(),
        ));
    }
    if let Some(path) = args.canonicalize {
        return canonicalize(&path)
            .map(|canonical| Outcome::Report(canonical.display().to_string()))
            .map_err(|error| format!("released-image-launch: {error}"));
    }
    launch(args)
}

fn launch(args: ReleasedImageLaunchArgs) -> Result<Outcome, String> {
    // Validated before anything is spawned, so a bound that cannot terminate
    // fails as misuse (status 2) and leaves no child behind.
    let bounds = Bounds::new(args.timeout, args.grace)
        .map_err(|error| format!("usage: released-image-launch: {error}"))?;
    let (Some(root), Some(shim), Some(log), Some(binary)) =
        (args.root, args.shim, args.log, args.binary)
    else {
        return Err(
            "usage: released-image-launch needs --root, --shim, --log and --binary".to_owned(),
        );
    };

    let mut env = build_environment(&root, &shim, &log);
    let mut candidate = args.args;
    // The only override environment tested is explicit, not inherited.
    if let Some(tag) = candidate
        .first()
        .and_then(|word| word.to_str())
        .and_then(|word| word.strip_prefix("IMAGE_ENV="))
    {
        env.push(("AGENT_VM_IMAGE_TAG".into(), OsString::from(tag)));
        candidate.remove(0);
    }
    let mut argv = Vec::with_capacity(candidate.len() + 2);
    if !args.interpreter.is_empty() {
        argv.push(args.interpreter);
    }
    argv.push(binary.into_os_string());
    argv.extend(candidate);

    let spec = LaunchSpec {
        argv,
        env,
        cwd: None,
    };
    match run_in_owned_group(&spec, bounds, &mut ()) {
        Ok(status) => Ok(Outcome::Exit(exit_code(status))),
        Err(LaunchError::TimedOut) => Ok(Outcome::Exit(TIMEOUT_EXIT)),
        Err(LaunchError::Interrupted(signal)) => Ok(Outcome::Exit(128 + signal.as_raw())),
        Err(error) => Err(format!("released-image-launch: {error}")),
    }
}

/// The isolated environment for one installed-candidate launch. It replaces the
/// caller's environment rather than extending it, so an inherited secret cannot
/// reach a build decoy.
fn build_environment(root: &Path, shim: &Path, log: &Path) -> Vec<(OsString, OsString)> {
    let variables = [
        ("HOME", root.join("home").into_os_string()),
        ("XDG_CONFIG_HOME", root.join("config").into_os_string()),
        ("AGENT_VM_STATE_DIR", root.join("state").into_os_string()),
        ("AGENT_VM_SHARE_MSB_CACHE", OsString::from("0")),
        (
            "PATH",
            OsString::from(format!("{}:/usr/bin:/bin", shim.display())),
        ),
        ("LANG", OsString::from("C.UTF-8")),
        ("BUILDER_LOG", log.as_os_str().to_owned()),
    ];
    variables
        .into_iter()
        .map(|(name, value)| (OsString::from(name), value))
        .collect()
}

/// The canonical form of `path`, including the components that do not exist.
///
/// `realpath(2)` -- and the `os.path.realpath` this replaces -- resolve the
/// symlinks of an existing prefix and keep the missing tail, which is what makes
/// an absent-path comparison meaningful: `/tmp/...` on macOS canonicalizes to
/// `/private/tmp/...` whether or not the leaf exists.
pub fn canonicalize(path: &Path) -> io::Result<PathBuf> {
    match fs::canonicalize(path) {
        Ok(canonical) => return Ok(canonical),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut probe = std::path::absolute(path)?;
    let mut missing: Vec<OsString> = Vec::new();
    loop {
        if let Ok(mut canonical) = fs::canonicalize(&probe) {
            for component in missing.iter().rev() {
                canonical.push(component);
            }
            return Ok(canonical);
        }
        let Some(name) = probe.file_name().map(|name| name.to_owned()) else {
            return fs::canonicalize(path);
        };
        missing.push(name);
        if !probe.pop() {
            return fs::canonicalize(path);
        }
    }
}

/// A launch bound that cannot terminate was refused before any child existed.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct InvalidBound {
    name: &'static str,
    value: f64,
}

impl fmt::Display for InvalidBound {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} must be finite and positive, got {}",
            self.name, self.value
        )
    }
}

/// Validated timeout and grace bounds.
///
/// One type carries both so an invalid value cannot reach the spawn: the
/// Python checked its arguments at the top of `run_in_owned_group`, and a check
/// on the caller's side would be a second thing to keep in step.
#[derive(Debug, Clone, Copy)]
pub struct Bounds {
    timeout: Duration,
    grace: Duration,
}

impl Bounds {
    pub fn new(timeout: f64, grace: f64) -> Result<Self, InvalidBound> {
        Ok(Self {
            timeout: seconds("timeout", timeout)?,
            grace: seconds("grace", grace)?,
        })
    }
}

fn seconds(name: &'static str, value: f64) -> Result<Duration, InvalidBound> {
    if !value.is_finite() || value <= 0.0 {
        return Err(InvalidBound { name, value });
    }
    Ok(Duration::from_secs_f64(value))
}

/// Everything one launch needs to exec.
pub struct LaunchSpec {
    pub argv: Vec<OsString>,
    pub env: Vec<(OsString, OsString)>,
    pub cwd: Option<PathBuf>,
}

#[derive(Debug)]
pub enum LaunchError {
    /// The bound expired; the owned group was terminated and reaped.
    TimedOut,
    /// The parent was interrupted; the owned group was terminated and reaped.
    Interrupted(Signal),
    /// A terminated owned group could not be reaped within the bound.
    TerminationFailed(String),
    /// The candidate could not be spawned.
    Spawn(io::Error),
    /// Waiting for the candidate failed.
    Wait(io::Error),
    /// The owned group could not be signalled, or its state is unknown.
    Signal(String),
    /// The signal handlers could not be installed.
    Signals(io::Error),
}

impl fmt::Display for LaunchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TimedOut => write!(formatter, "launch timed out"),
            Self::Interrupted(signal) => write!(formatter, "interrupted by signal {signal:?}"),
            Self::TerminationFailed(detail) => write!(formatter, "{detail}"),
            Self::Spawn(error) => write!(formatter, "cannot spawn the candidate: {error}"),
            Self::Wait(error) => write!(formatter, "cannot wait for the candidate: {error}"),
            Self::Signal(detail) => write!(formatter, "{detail}"),
            Self::Signals(error) => write!(formatter, "cannot install signal handlers: {error}"),
        }
    }
}

/// A child's status as an exit code.
///
/// Python's `Popen.wait` returned a negative number for a signalled child, and
/// `sys.exit(-15)` became 241; `128 + N` is what the interruption path already
/// returns, so a signalled child and a signalled helper agree.
fn exit_code(status: ExitStatus) -> i32 {
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
}

/// The signal recorded by the handler, still pending for this launch.
///
/// Only an integer is stored: a handler may not allocate, lock or unwind.
static PENDING_SIGNAL: AtomicI32 = AtomicI32::new(0);

extern "C" fn record_signal(signal: libc::c_int) {
    PENDING_SIGNAL.store(signal, Ordering::SeqCst);
}

/// Saves the dispositions of the signals that interrupt a launch and restores
/// them when the launch is over.
///
/// rustix covers the process primitives but exposes no signal *handler*
/// registration, so the `sigaction` call comes from `libc`, the same escape
/// hatch `agent-vm` uses for `waitid` and `kill`. The handler itself is written
/// here rather than taken from `signal-hook` because the prior disposition has
/// to be restored: `signal-hook`'s unregister deliberately leaves its own
/// handler installed, which would make a later launch -- or a later SIGTERM to
/// this process -- silently ignored.
struct SignalGuard {
    previous: Vec<(libc::c_int, libc::sigaction)>,
}

impl SignalGuard {
    fn install() -> io::Result<Self> {
        let mut previous = Vec::with_capacity(2);
        for number in [libc::SIGTERM, libc::SIGINT] {
            // SAFETY: `sigaction` is initialised field by field below and the
            // mask is emptied by `sigemptyset`; `record_signal` only stores into
            // an atomic, which is async-signal-safe.
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = record_signal as *const () as usize;
            action.sa_flags = 0;
            unsafe { libc::sigemptyset(&mut action.sa_mask) };
            let mut replaced: libc::sigaction = unsafe { std::mem::zeroed() };
            if unsafe { libc::sigaction(number, &action, &mut replaced) } != 0 {
                let error = io::Error::last_os_error();
                for (done, replaced) in &previous {
                    unsafe { libc::sigaction(*done, replaced, std::ptr::null_mut()) };
                }
                return Err(error);
            }
            previous.push((number, replaced));
        }
        Ok(Self { previous })
    }
}

impl Drop for SignalGuard {
    fn drop(&mut self) {
        for (number, replaced) in &self.previous {
            unsafe { libc::sigaction(*number, replaced, std::ptr::null_mut()) };
        }
    }
}

fn take_pending_signal() -> Option<Signal> {
    let raw = PENDING_SIGNAL.swap(0, Ordering::SeqCst);
    (raw != 0).then(|| unsafe { Signal::from_raw_unchecked(raw) })
}

/// Run `spec` in a fresh session, and on timeout or interruption terminate the
/// whole group it created.
///
/// Returns the child's status. `hook` is called once per wait poll, *inside* the
/// wait and with the child alive: it is the seam the controls use to deliver a
/// SIGTERM where a real one would land (see `InjectSigterm`).
///
/// The signal state is process-wide, so one launch runs at a time per process:
/// the handler it installs is restored when the launch is over.
pub fn run_in_owned_group(
    spec: &LaunchSpec,
    bounds: Bounds,
    hook: &mut dyn WaitHook,
) -> Result<ExitStatus, LaunchError> {
    let _signals = SignalGuard::install().map_err(LaunchError::Signals)?;
    PENDING_SIGNAL.store(0, Ordering::SeqCst);
    let outcome = wait_for_child(spec, bounds, hook);
    // A signal that arrived during teardown is already answered. Clearing it
    // keeps the next launch in this process from reading as interrupted; the
    // Python scoped the same state to one call.
    PENDING_SIGNAL.store(0, Ordering::SeqCst);
    outcome
}

/// The point inside the wait where a control injects its SIGTERM.
///
/// The Python kept a seam so a control could deliver SIGTERM while the helper
/// sat in `Popen.wait` holding that function's `_waitpid_lock`: a handler that
/// tore the group down from there deadlocked. Rust's handler only records the
/// signal and the wait is a `try_wait` poll, so the deadlock is impossible by
/// construction. The seam stays because it is what lets a check land a signal
/// inside the wait rather than beside it.
pub trait WaitHook {
    fn poll(&mut self);
}

impl WaitHook for () {
    fn poll(&mut self) {}
}

fn wait_for_child(
    spec: &LaunchSpec,
    bounds: Bounds,
    hook: &mut dyn WaitHook,
) -> Result<ExitStatus, LaunchError> {
    let mut command = Command::new(&spec.argv[0]);
    command
        .args(&spec.argv[1..])
        .env_clear()
        .envs(spec.env.iter().map(|(name, value)| (name, value)));
    if let Some(cwd) = &spec.cwd {
        command.current_dir(cwd);
    }
    // SAFETY: `setsid` is a syscall and touches no allocator or lock, which is
    // all `pre_exec` allows. `setsid` rather than `process_group(0)`: the
    // Python used `start_new_session=True`, the child is a session leader as
    // well as a group leader, and a terminal Ctrl-C (delivered to the parent's
    // foreground group) therefore cannot reach it.
    unsafe {
        command.pre_exec(|| process::setsid().map(|_| ()).map_err(io::Error::from));
    }
    let mut child = command.spawn().map_err(LaunchError::Spawn)?;
    let deadline = Instant::now() + bounds.timeout;
    loop {
        hook.poll();
        if let Some(signal) = take_pending_signal() {
            terminate_group(&mut child, bounds.grace)?;
            return Err(LaunchError::Interrupted(signal));
        }
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            // An unwaitable child is reported, not torn down: `ECHILD` means the
            // child is already reaped, and anything else leaves the group to the
            // caller rather than signalling a pid this helper cannot vouch for.
            Err(error) => return Err(LaunchError::Wait(error)),
        }
        let now = Instant::now();
        if now >= deadline {
            terminate_group(&mut child, bounds.grace)?;
            return Err(LaunchError::TimedOut);
        }
        thread::sleep(POLL_SLICE.min(deadline - now));
    }
}

/// TERM the owned group, then KILL it if the direct child survives `grace`.
///
/// The KILL is unconditional once the child is gone, so a TERM-ignoring
/// grandchild cannot outlive the bounded launch either: a "successful" TERM on
/// the leader alone would leave it running.
fn terminate_group(child: &mut Child, grace: Duration) -> Result<(), LaunchError> {
    // The child called `setsid`, so it is its own group leader.
    let pgid = group_leader(child)?;
    signal_group(pgid, Signal::TERM)?;
    if wait_up_to(child, grace).is_some() {
        signal_group(pgid, Signal::KILL)?;
        return Ok(());
    }
    // Reap a leader that exited after the grace wait expired: a still-unreaped
    // zombie leader makes macOS `killpg` return EPERM for the (now empty) group
    // instead of ESRCH.
    let _ = child.try_wait();
    signal_group(pgid, Signal::KILL)?;
    reap_killed(child)
}

/// Reap a SIGKILLed direct child, bounded so a host stall cannot hang.
fn reap_killed(child: &mut Child) -> Result<(), LaunchError> {
    if wait_up_to(child, KILL_REAP_TIMEOUT).is_some() {
        return Ok(());
    }
    Err(LaunchError::TerminationFailed(format!(
        "owned child {} survived SIGKILL for {}s",
        child.id(),
        KILL_REAP_TIMEOUT.as_secs()
    )))
}

fn group_leader(child: &Child) -> Result<Pid, LaunchError> {
    Pid::from_raw(child.id() as i32)
        .ok_or_else(|| LaunchError::Signal(format!("{} is not a valid pid", child.id())))
}

/// The child's status if it exited within `limit`, else `None`.
fn wait_up_to(child: &mut Child, limit: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + limit;
    loop {
        // An unreadable status is treated as "still running": the caller
        // escalates and the bounded reap reports a real survivor.
        if let Ok(Some(status)) = child.try_wait() {
            return Some(status);
        }
        let now = Instant::now();
        if now >= deadline {
            return None;
        }
        thread::sleep(POLL_SLICE.min(deadline - now));
    }
}

/// Signal the owned group, and nothing else.
fn signal_group(pgid: Pid, signal: Signal) -> Result<(), LaunchError> {
    match process::kill_process_group(pgid, signal) {
        Ok(()) => Ok(()),
        // The whole group already exited between calls.
        Err(rustix::io::Errno::SRCH) => Ok(()),
        // macOS returns EPERM (not ESRCH) for `killpg` to a group whose leader
        // is an unreaped zombie with no live members. Tolerate it only when the
        // host positively confirms no live process remains in the group;
        // otherwise a real un-signalled survivor must surface.
        Err(rustix::io::Errno::PERM) => match live_group_members(pgid) {
            Some(members) if members.is_empty() => Ok(()),
            Some(members) => Err(LaunchError::Signal(format!(
                "could not signal group {}: {signal:?} refused and members {members:?} are live",
                pgid.as_raw_pid()
            ))),
            None => Err(LaunchError::Signal(format!(
                "could not signal group {}: {signal:?} refused and its members are unknown",
                pgid.as_raw_pid()
            ))),
        },
        Err(errno) => Err(LaunchError::Signal(format!(
            "cannot signal group {} with {signal:?}: {errno}",
            pgid.as_raw_pid()
        ))),
    }
}

/// PIDs of live (non-zombie) processes in this group, or `None` if unknown.
fn live_group_members(pgid: Pid) -> Option<Vec<u32>> {
    let listing = ps_listing()?;
    let wanted = pgid.as_raw_pid();
    let mut members = Vec::new();
    for line in listing.lines() {
        let mut fields = line.split_whitespace();
        let (Some(pid), Some(group)) = (fields.next(), fields.next()) else {
            continue;
        };
        if group.parse::<i32>() != Ok(wanted) {
            continue;
        }
        let state = fields.next().unwrap_or_default();
        if matches!(state.as_bytes().first(), Some(b'Z' | b'X' | b'x')) {
            continue;
        }
        if let Ok(pid) = pid.parse::<u32>() {
            members.push(pid);
        }
    }
    Some(members)
}

/// `ps -e -o pid=,pgid=,stat=`, bounded so a stalled `ps` cannot hang a launch.
fn ps_listing() -> Option<String> {
    let mut child = Command::new("ps")
        .args(["-e", "-o", "pid=,pgid=,stat="])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let stdout = child.stdout.take()?;
    // Read on a second thread: the listing is larger than a pipe buffer, so a
    // reader that only starts after the exit would deadlock on it.
    let reader = thread::spawn(move || io::read_to_string(stdout).ok());
    let deadline = Instant::now() + PS_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(None) => {}
            Ok(Some(_)) => break,
            Err(_) => return None,
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        thread::sleep(POLL_SLICE);
    }
    reader.join().ok()?
}

// --- Boot-free controls -----------------------------------------------------

/// A controlled child and grandchild which both ignore SIGTERM, so only the
/// escalation to SIGKILL can stop them. It records its two pids and then sits
/// there; the shutdown budget is what keeps a failed case from outliving the run.
const SCENARIO: &str =
    "#!/bin/sh\ntrap '' TERM\nsleep 300 &\nprintf '%s %s\\n' \"$$\" \"$!\" > \"$1\"\nsleep 300\n";

/// The boot-free controls behind `--self-test`.
///
/// Every case is one the Python suite had: a real short-lived child, no mocks,
/// no VM and no network. The Python suite's shipped-binary cases (the exit
/// statuses the shell callers read) live in `tests/cli.rs`, where the real
/// binary is the boundary rather than a library call.
fn self_test() -> Result<(), String> {
    let scratch = Scratch::new("released-image-launch").map_err(|error| error.to_string())?;
    let scenario = scratch.path.join("scenario.sh");
    fs::write(&scenario, SCENARIO).map_err(|error| error.to_string())?;
    fs::set_permissions(
        &scenario,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .map_err(|error| error.to_string())?;

    a_normal_launch_returns_the_child_status(&scratch)?;
    the_launch_replaces_the_environment_and_keeps_the_cwd(&scratch)?;
    a_timeout_stops_the_whole_owned_group(&scratch, &scenario)?;
    an_empty_owned_group_is_tolerated()?;
    a_live_owned_group_is_signalled()?;
    a_reentrant_sigterm_interrupts_the_wait(&scratch, &scenario)?;
    Ok(())
}

fn a_normal_launch_returns_the_child_status(scratch: &Scratch) -> Result<(), String> {
    let spec = shell_spec(scratch, &["-c", "exit 7"]);
    let bounds = Bounds::new(30.0, 2.0).map_err(|error| error.to_string())?;
    match run_in_owned_group(&spec, bounds, &mut ()) {
        Ok(status) if status.code() == Some(7) => Ok(()),
        Ok(status) => Err(format!("normal launch status {status}, expected 7")),
        Err(error) => Err(format!("normal launch raised {error}")),
    }
}

/// The launched candidate must see the isolated environment and nothing of the
/// caller's, and must keep the caller's working directory.
fn the_launch_replaces_the_environment_and_keeps_the_cwd(scratch: &Scratch) -> Result<(), String> {
    let root = scratch.path.join("root");
    let shim = scratch.path.join("shim");
    let log = scratch.path.join("builder.log");
    let spec = LaunchSpec {
        argv: ["/bin/sh", "-c", "{ env | sort; pwd; } > recorded"]
            .map(OsString::from)
            .to_vec(),
        env: build_environment(&root, &shim, &log),
        cwd: Some(scratch.path.clone()),
    };
    let bounds = Bounds::new(30.0, 2.0).map_err(|error| error.to_string())?;
    run_in_owned_group(&spec, bounds, &mut ())
        .map_err(|error| format!("isolated launch raised {error}"))?;
    let recorded = fs::read_to_string(scratch.path.join("recorded"))
        .map_err(|error| format!("the launched child recorded no environment: {error}"))?;
    let (environment, working_directory) = recorded
        .trim_end_matches('\n')
        .rsplit_once('\n')
        .ok_or_else(|| format!("the launched child recorded {recorded:?}"))?;

    let expected = [
        "AGENT_VM_SHARE_MSB_CACHE=0".to_owned(),
        format!("AGENT_VM_STATE_DIR={}/state", root.display()),
        format!("BUILDER_LOG={}", log.display()),
        format!("HOME={}/home", root.display()),
        "LANG=C.UTF-8".to_owned(),
        format!("PATH={}:/usr/bin:/bin", shim.display()),
        format!("XDG_CONFIG_HOME={}/config", root.display()),
    ];
    // A shell of its own adds `PWD`, `SHLVL` and `_`; nothing else may appear,
    // and in particular no variable inherited from the caller.
    let shell_supplied = ["PWD", "SHLVL", "_"];
    let mut seen = 0;
    for line in environment.lines() {
        let name = line
            .split_once('=')
            .map(|(name, _)| name)
            .unwrap_or_default();
        if expected.iter().any(|variable| variable == line) {
            seen += 1;
        } else if !shell_supplied.contains(&name) {
            return Err(format!(
                "the launched child saw {line:?}, which the isolated environment does not set"
            ));
        }
    }
    if seen != expected.len() {
        return Err(format!(
            "the launched child saw {environment:?}: {} of {} isolated variables, expected all",
            seen,
            expected.len()
        ));
    }
    let canonical = fs::canonicalize(&scratch.path).map_err(|error| error.to_string())?;
    if working_directory != canonical.display().to_string() {
        return Err(format!(
            "the launched child ran in {working_directory:?}, expected {}",
            canonical.display()
        ));
    }
    Ok(())
}

fn a_timeout_stops_the_whole_owned_group(scratch: &Scratch, scenario: &Path) -> Result<(), String> {
    let pidfile = scratch.path.join("timeout.pids");
    let spec = scenario_spec(scratch, scenario, &pidfile);
    let bounds = Bounds::new(0.5, 1.0).map_err(|error| error.to_string())?;
    let mut leadership = Leadership::new(&pidfile);
    let outcome = run_in_owned_group(&spec, bounds, &mut leadership);
    match outcome {
        Err(LaunchError::TimedOut) => {}
        Ok(status) => {
            stop_recorded_group(&pidfile);
            return Err(format!(
                "timed-out launch returned {status} instead of failing"
            ));
        }
        Err(error) => {
            stop_recorded_group(&pidfile);
            return Err(format!("timed-out launch raised {error}"));
        }
    }
    assert_stopped("timeout", &pidfile, &leadership)
}

fn a_reentrant_sigterm_interrupts_the_wait(
    scratch: &Scratch,
    scenario: &Path,
) -> Result<(), String> {
    let pidfile = scratch.path.join("reentrant.pids");
    let spec = scenario_spec(scratch, scenario, &pidfile);
    let bounds = Bounds::new(3600.0, 1.0).map_err(|error| error.to_string())?;
    let mut injector = InjectSigterm {
        leadership: Leadership::new(&pidfile),
        fired: false,
    };
    let outcome = run_in_owned_group(&spec, bounds, &mut injector);
    if !injector.fired {
        stop_recorded_group(&pidfile);
        return Err("reentrant-sigterm: the injected SIGTERM never fired".to_owned());
    }
    match outcome {
        Err(LaunchError::Interrupted(Signal::TERM)) => {}
        other => {
            stop_recorded_group(&pidfile);
            return Err(format!(
                "reentrant-sigterm: the launch returned {other:?} instead of an interruption"
            ));
        }
    }
    assert_stopped("reentrant-sigterm", &pidfile, &injector.leadership)
}

fn an_empty_owned_group_is_tolerated() -> Result<(), String> {
    // The `ps` oracle the EPERM tolerance rests on must actually find a live
    // member: on Linux the kernel answers the empty group directly, so without
    // this the parser would only ever run on macOS. Only the macOS EPERM path
    // needs the answer, so a host without `ps` is reported rather than failed.
    match live_group_members(process::getpgrp()) {
        Some(members) if members.contains(&(process::getpid().as_raw_pid() as u32)) => {}
        Some(members) => {
            return Err(format!(
                "the ps group listing {members:?} does not contain this control process"
            ));
        }
        None => eprintln!(
            "released-image launch: notice: no `ps` on PATH, so the process-group listing was not checked"
        ),
    }
    let mut child = session_child(&["-c", "exit 0"])
        .map_err(|error| format!("cannot spawn the empty-group fixture: {error}"))?;
    thread::sleep(Duration::from_millis(500));
    let pgid = Pid::from_raw(child.id() as i32)
        .ok_or_else(|| format!("{} is not a valid pid", child.id()))?;
    let verdict = signal_group(pgid, Signal::KILL);
    let _ = child.wait();
    verdict.map_err(|error| format!("zombie-leader empty group raised {error}"))
}

fn a_live_owned_group_is_signalled() -> Result<(), String> {
    let mut child = session_child(&["-c", "sleep 300"])
        .map_err(|error| format!("cannot spawn the live-group fixture: {error}"))?;
    let pgid = Pid::from_raw(child.id() as i32)
        .ok_or_else(|| format!("{} is not a valid pid", child.id()))?;
    signal_group(pgid, Signal::KILL).map_err(|error| format!("live group: {error}"))?;
    if wait_up_to(&mut child, Duration::from_secs(5)).is_some() {
        return Ok(());
    }
    let _ = child.kill();
    let _ = child.wait();
    Err("live owned group survived SIGKILL".to_owned())
}

/// A child in its own session, the way a launched candidate is.
fn session_child(arguments: &[&str]) -> io::Result<Child> {
    let mut command = Command::new("/bin/sh");
    command.args(arguments);
    // SAFETY: `setsid` only calls a syscall.
    unsafe {
        command.pre_exec(|| process::setsid().map(|_| ()).map_err(io::Error::from));
    }
    command.spawn()
}

fn shell_spec(scratch: &Scratch, arguments: &[&str]) -> LaunchSpec {
    let mut argv = vec![OsString::from("/bin/sh")];
    argv.extend(arguments.iter().map(OsString::from));
    LaunchSpec {
        argv,
        env: build_environment(
            &scratch.path.join("root"),
            &scratch.path.join("shim"),
            &scratch.path.join("builder.log"),
        ),
        cwd: Some(scratch.path.clone()),
    }
}

fn scenario_spec(scratch: &Scratch, scenario: &Path, pidfile: &Path) -> LaunchSpec {
    let mut spec = shell_spec(scratch, &[]);
    spec.argv.push(scenario.as_os_str().to_owned());
    spec.argv.push(pidfile.as_os_str().to_owned());
    spec
}

/// Reads the pids a scenario recorded, once it has recorded them.
fn read_pids(pidfile: &Path) -> Option<Vec<u32>> {
    let recorded = fs::read_to_string(pidfile).ok()?;
    let pids: Vec<u32> = recorded
        .split_whitespace()
        .filter_map(|field| field.parse().ok())
        .collect();
    (pids.len() == 2).then_some(pids)
}

/// Checks, from inside the wait, that the recorded child really is its own
/// group and session leader -- the property that makes "signal the group" mean
/// "signal exactly what this launch created".
struct Leadership<'a> {
    pidfile: &'a Path,
    verdict: std::cell::Cell<Option<bool>>,
}

impl<'a> Leadership<'a> {
    fn new(pidfile: &'a Path) -> Self {
        Self {
            pidfile,
            verdict: std::cell::Cell::new(None),
        }
    }

    fn record(&mut self) {
        if self.verdict.get().is_some() {
            return;
        }
        let Some(pids) = read_pids(self.pidfile) else {
            return;
        };
        let leader = Pid::from_raw(pids[0] as i32).is_some_and(|pid| {
            process::getpgid(Some(pid)).ok() == Some(pid)
                && process::getsid(Some(pid)).ok() == Some(pid)
        });
        self.verdict.set(Some(leader));
    }

    fn check(&self, label: &str) -> Result<(), String> {
        match self.verdict.get() {
            Some(true) => Ok(()),
            Some(false) => Err(format!(
                "{label}: the child is not an owned group and session leader"
            )),
            None => Err(format!("{label}: the scenario never recorded a child pid")),
        }
    }
}

impl WaitHook for Leadership<'_> {
    fn poll(&mut self) {
        self.record();
    }
}

/// Delivers SIGTERM from inside the wait, at the point a real one lands.
struct InjectSigterm<'a> {
    leadership: Leadership<'a>,
    fired: bool,
}

impl WaitHook for InjectSigterm<'_> {
    fn poll(&mut self) {
        if self.fired {
            return;
        }
        self.leadership.record();
        if self.leadership.verdict.get().is_none() {
            return;
        }
        self.fired = true;
        let _ = process::kill_process(process::getpid(), Signal::TERM);
    }
}

/// SIGKILL whatever the scenario recorded.
///
/// A case that gives up kills its launch, but the launched group is a separate
/// session: without this the TERM-ignoring fixture and its grandchild sleep on
/// for their full 300 s, outliving the run.
fn stop_recorded_group(pidfile: &Path) {
    let Some(pids) = read_pids(pidfile) else {
        return;
    };
    if let Some(pgid) = Pid::from_raw(pids[0] as i32) {
        let _ = signal_group(pgid, Signal::KILL);
    }
}

fn assert_stopped(label: &str, pidfile: &Path, leadership: &Leadership<'_>) -> Result<(), String> {
    let pids = read_pids(pidfile)
        .ok_or_else(|| format!("{label}: the scenario did not record child/grandchild pids"))?;
    leadership.check(label)?;
    if !wait_dead(pids[0], Duration::from_secs(5)) {
        stop_recorded_group(pidfile);
        return Err(format!("{label}: child {} survived", pids[0]));
    }
    if !wait_dead(pids[1], Duration::from_secs(5)) {
        stop_recorded_group(pidfile);
        return Err(format!("{label}: grandchild {} survived", pids[1]));
    }
    Ok(())
}

fn wait_dead(pid: u32, limit: Duration) -> bool {
    let Some(pid) = Pid::from_raw(pid as i32) else {
        return true;
    };
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if process::test_kill_process(pid).is_err() {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    process::test_kill_process(pid).is_err()
}

/// A directory the controls may write into, removed on drop.
struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new(label: &str) -> io::Result<Self> {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "agent-vm-harness-{label}-{}-{}",
            process::getpid().as_raw_pid(),
            NEXT.fetch_add(1, Ordering::Relaxed)
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
    use std::os::unix::fs::symlink;

    #[test]
    fn an_absent_path_keeps_its_tail_after_the_resolved_prefix() {
        let scratch = Scratch::new("canonicalize").expect("create the scratch directory");
        let real = scratch.path.join("real");
        fs::create_dir_all(real.join("nested")).expect("create the fixture tree");
        let link = scratch.path.join("link");
        symlink(&real, &link).expect("link the fixture tree");
        assert_eq!(
            canonicalize(&link.join("nested/file")).expect("canonicalize an absent path"),
            fs::canonicalize(&real)
                .expect("the fixture tree resolves")
                .join("nested/file")
        );
        assert_eq!(
            canonicalize(&link.join("nested")).expect("canonicalize an existing path"),
            fs::canonicalize(&real)
                .expect("the fixture tree resolves")
                .join("nested")
        );
    }

    #[test]
    fn a_relative_path_canonicalizes_to_an_absolute_one() {
        let canonical =
            canonicalize(Path::new("definitely-absent-relative-tail")).expect("canonicalize");
        assert!(
            canonical.is_absolute(),
            "{} is not absolute",
            canonical.display()
        );
        assert!(canonical.ends_with("definitely-absent-relative-tail"));
    }

    #[test]
    fn the_self_test_controls_pass() {
        self_test().expect("released-image launch controls pass");
    }

    #[test]
    fn a_bound_that_cannot_terminate_is_refused() {
        for value in [f64::NAN, f64::INFINITY, 0.0, -1.0] {
            assert!(Bounds::new(value, 1.0).is_err(), "timeout {value} accepted");
            assert!(Bounds::new(1.0, value).is_err(), "grace {value} accepted");
        }
        let bounds = Bounds::new(0.5, 2.0).expect("finite positive bounds are accepted");
        assert_eq!(bounds.timeout, Duration::from_millis(500));
        assert_eq!(bounds.grace, Duration::from_secs(2));
    }

    #[test]
    fn the_environment_is_exactly_the_isolated_one() {
        let environment = build_environment(
            Path::new("/root"),
            Path::new("/shim"),
            Path::new("/builder.log"),
        );
        let rendered: Vec<String> = environment
            .iter()
            .map(|(name, value)| format!("{}={}", name.to_string_lossy(), value.to_string_lossy()))
            .collect();
        assert_eq!(
            rendered,
            [
                "HOME=/root/home",
                "XDG_CONFIG_HOME=/root/config",
                "AGENT_VM_STATE_DIR=/root/state",
                "AGENT_VM_SHARE_MSB_CACHE=0",
                "PATH=/shim:/usr/bin:/bin",
                "LANG=C.UTF-8",
                "BUILDER_LOG=/builder.log",
            ]
        );
    }
}
