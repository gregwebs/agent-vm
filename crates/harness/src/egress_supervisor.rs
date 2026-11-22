//! Boot-free controls for the owned launch supervisor and its drivers (#694).
//!
//! Ported from `script/test/lib/egress-supervisor-contract.py`. The library that
//! suite exercised was already ported — `egress_launch`, `egress_run`,
//! `egress_cases`, `egress_allowances`, `egress_witness`, `msb_catalog`,
//! `egress_fixtures` — so what this module holds is the other half: one named
//! control per Python test method, each independently reported from
//! `harness egress-supervisor --self-test` and each also a
//! `cargo test -p agent-vm-harness` name.
//!
//! The Python suite drove a fake candidate of its own: a script that answered the
//! CLI's `msb` verbs, wrote a banner, a private catalog and the runtime's socket
//! layout, and started a detached runtime and a TERM-ignoring attached child.
//! That fake is here as this binary's hidden `--fake-candidate` and `--fake-idle`
//! modes, and the checks write a one-line `sh` wrapper for it, so a launch under
//! test is still an ordinary process the supervisor starts, observes and cleans
//! up.
//!
//! Three oracles are deliberately *not* thin copies of the code they grade:
//!
//! * The catalog fixtures are built with `rusqlite` (ADR-0072's choice), so "the
//!   observer reads the launcher's schema" is asked of a writer this crate does
//!   not share.
//! * The allowance record and the PA2 evidence are compared against values
//!   spelled in the control, never against a second call to the code that writes
//!   them.
//! * Two Python oracles had no Rust equivalent and are substituted, not dropped:
//!   `socket.getfqdn` cannot be poisoned in a Rust child, so the resolver control
//!   asserts the fixture's bind path names literal addresses only (a source
//!   oracle) *and* that `serve` publishes readiness inside a bound shorter than
//!   its own 5 s; and `process_identity` cannot be mocked, so the PID-reuse
//!   control tampers with a real child's recorded start and then requires that
//!   child to still be alive.
//!
//! Every socket read, accept, connect, subprocess wait and thread join here is
//! bounded: a hung fixture fails a gate instead of hanging it.
//!
//! The call-site controls read `egress_run.rs` from the repository root at run
//! time rather than through `include_str!`, because that is what lets
//! `harness egress-mutations` grade the deletions those rows own against a
//! prebuilt binary (`--repo-root` points at the mutated copy). The oracle is the fragment
//! list in the control, never the file it reads.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs,
    io::Write,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command as Process, Stdio},
    sync::{
        OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use serde_json::{Value, json};

use crate::{
    egress_allowances, egress_cases as cases, egress_fixtures, egress_launch,
    egress_launch::OwnedLaunch, egress_run, egress_witness, msb_catalog,
};

/// The launch bound the Python's `command()` used: 5 s with a 0.1 s grace. A
/// fake launcher never exits on its own, so every launch row here ends as 124.
const LAUNCH_TIMEOUT: f64 = 5.0;
const LAUNCH_GRACE: f64 = 0.1;
/// Bound on one `--self-test` subprocess: the plan, and an interrupted launch
/// whose own bound is 10 s.
const CLI_BOUND: Duration = Duration::from_secs(60);
/// Bound on a peer thread join.
const JOIN_BOUND: Duration = Duration::from_secs(8);

// --- The repository the source controls read --------------------------------

static ROOT: OnceLock<PathBuf> = OnceLock::new();

/// The repository the source controls read. A `#[test]` gets the checkout this
/// crate was compiled in; `--repo-root` points a CLI run at a disposable copy,
/// which is how the mutation suite grades a deleted call site.
pub fn set_repo_root(root: PathBuf) -> Result<(), String> {
    ROOT.set(root)
        .map_err(|_| "the repo root is set once".to_owned())
}

fn repo_root() -> PathBuf {
    ROOT.get()
        .cloned()
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
}

fn source(relative: &str) -> Result<String, String> {
    let path = repo_root().join(relative);
    fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))
}

/// The `harness` binary, whether the caller is the CLI or a `cargo test` process
/// whose own executable is the test harness (`egress_cases::harness_binary`).
fn harness_binary() -> Result<PathBuf, String> {
    let path = cases::harness_binary();
    if path.is_file() {
        return Ok(path);
    }
    Err(
        "the harness binary is not built: run cargo build --locked -p agent-vm-harness --bins"
            .to_owned(),
    )
}

fn harness_text() -> Result<String, String> {
    Ok(harness_binary()?.to_string_lossy().into_owned())
}

/// A work directory with the four private roots a launch needs.
///
/// It lives directly under `/tmp` on Darwin: a sandbox's unix socket is
/// `…/state/msb-home/run/sandboxes/<24 hex>/agent.sock`, and `sun_path` is 104
/// bytes there, so `TMPDIR`'s `/var/folders/…` would not fit.
fn scratch(_label: &str) -> Result<PathBuf, String> {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let base = if cfg!(target_os = "macos") {
        PathBuf::from("/tmp")
    } else {
        PathBuf::from("/var/tmp")
    };
    // The name stays short on purpose: `/tmp` resolves to `/private/tmp` on
    // Darwin, and the sandbox socket below it has to fit `sun_path`. The pid is
    // whole, not truncated: a name shared by two `harness` processes would let
    // one control delete the other's work directory.
    let path = base.join(format!(
        "a694-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    for directory in ["proj", "home", "config", "state", "state/msb-home", "fx"] {
        fs::create_dir_all(path.join(directory))
            .map_err(|error| format!("{}: {error}", path.join(directory).display()))?;
    }
    path.canonicalize().map_err(|error| error.to_string())
}

/// Run one control in its own work directory and remove it afterwards, whatever
/// the control decided.
fn control(label: &str, body: impl FnOnce(&Path) -> Result<(), String>) -> Result<(), String> {
    let work = scratch(label)?;
    let outcome = body(&work);
    let _ = fs::remove_dir_all(&work);
    outcome
}

fn case_row(name: &str, variant: &str) -> &'static cases::Case {
    cases::CASES
        .iter()
        .find(|case| case.case == name && case.variant == variant)
        .unwrap_or_else(|| panic!("no case {name}/{variant}"))
}

fn build(work: &Path, binary: &str, case: &cases::Case) -> cases::Command {
    cases::build_command(
        case,
        work,
        binary,
        "192.168.1.2",
        &cases::BuildOptions::default(),
    )
}

fn lookup(table: &[(String, String)], key: &str) -> String {
    table
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.clone())
        .unwrap_or_default()
}

// --- Subprocesses -----------------------------------------------------------

/// A child whose stdout and stderr are one log file, so a chatty child can never
/// fill a pipe the parent is not draining.
struct Logged {
    child: Child,
    log: PathBuf,
}

impl Logged {
    fn text(&self) -> String {
        fs::read(&self.log)
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default()
    }

    fn running(&mut self) -> Result<bool, String> {
        self.child
            .try_wait()
            .map(|status| status.is_none())
            .map_err(|error| error.to_string())
    }

    /// The exit status, or `128 + N` when a signal ended the child, and the
    /// bound is enforced by killing it rather than by waiting again.
    fn wait(&mut self, bound: Duration) -> Result<i32, String> {
        let until = Instant::now() + bound;
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => return Ok(exit_status(status)),
                Ok(None) if Instant::now() >= until => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    return Err(format!("a child outlived its {bound:?} bound"));
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                Err(error) => return Err(error.to_string()),
            }
        }
    }
}

fn exit_status(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or_default())
}

fn spawn_logged(mut command: Process, log: &Path) -> Result<Logged, String> {
    let file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
        .map_err(|error| format!("{}: {error}", log.display()))?;
    let stderr = file.try_clone().map_err(|error| error.to_string())?;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(file))
        .stderr(Stdio::from(stderr));
    let child = command.spawn().map_err(|error| error.to_string())?;
    Ok(Logged {
        child,
        log: log.to_path_buf(),
    })
}

/// Run one CLI invocation with the harness binary in a bounded, logged child.
fn run_cli(arguments: &[String], cwd: &Path, log: &Path) -> Result<(i32, String), String> {
    let mut command = Process::new(harness_binary()?);
    command.args(arguments).current_dir(cwd);
    let mut child = spawn_logged(command, log)?;
    let status = child.wait(CLI_BOUND)?;
    Ok((status, child.text()))
}

/// The same redirect without taking ownership of the child, for the fixture a
/// control hands to `cleanup_run`.
fn spawn_child_logged(mut command: Process, log: &Path) -> Result<Child, String> {
    let file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
        .map_err(|error| format!("{}: {error}", log.display()))?;
    let stderr = file.try_clone().map_err(|error| error.to_string())?;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(file))
        .stderr(Stdio::from(stderr));
    command.spawn().map_err(|error| error.to_string())
}

// --- The fake candidate -----------------------------------------------------

fn hex(bytes: impl AsRef<[u8]>) -> String {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(bytes);
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The candidate the launch controls drive: a one-line `sh` wrapper around this
/// binary's hidden `--fake-candidate` mode.
///
/// The wrapper is what makes `argv[0]` the path the plan names, so a recorded
/// argv can be compared with the plan's own; the behaviour it dispatches to is
/// Rust.
fn fake_candidate(work: &Path) -> Result<String, String> {
    let path = work.join("fake");
    let script = format!(
        "#!/bin/sh\nexec {} egress-supervisor --fake-candidate \"$0\" \"$@\"\n",
        harness_text()?
    );
    fs::write(&path, script).map_err(|error| format!("{}: {error}", path.display()))?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
        .map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(path.to_string_lossy().into_owned())
}

/// `--fake-candidate`: the candidate the supervisor starts, and the `msb` verbs a
/// cleanup calls. It is only ever reached through `fake_candidate`'s wrapper.
fn run_fake_candidate(argv: &[OsString]) -> Result<i32, String> {
    let argv: Vec<String> = argv
        .iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect();
    let (_, arguments) = argv
        .split_first()
        .ok_or("usage: fake-candidate ARGV0 ARGS")?;
    let first = arguments.first().cloned().unwrap_or_default();
    let cwd = std::env::current_dir().map_err(|error| error.to_string())?;
    let state = std::env::var("AGENT_VM_STATE_DIR").map_err(|error| error.to_string())?;
    let root = Path::new(&state).join("msb-home");
    fs::create_dir_all(root.join("db")).map_err(|error| error.to_string())?;
    let database =
        rusqlite::Connection::open(root.join("db/msb.db")).map_err(|error| error.to_string())?;
    // The pinned schema, as the launcher's first migration writes it.
    database
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS sandbox(id INTEGER PRIMARY KEY, name TEXT, config TEXT, status TEXT);\
             CREATE TABLE IF NOT EXISTS \"run\"(id INTEGER PRIMARY KEY, sandbox_id INTEGER, pid INTEGER, status TEXT);",
        )
        .map_err(|error| error.to_string())?;
    if first == "egressprobe" && cwd.join("startup-delay").is_file() {
        let delay: f64 = fs::read_to_string(cwd.join("startup-delay"))
            .map_err(|error| error.to_string())?
            .trim()
            .parse()
            .unwrap_or_default();
        std::thread::sleep(Duration::from_secs_f64(delay));
    }
    let argv: Vec<String> = argv.to_vec();
    if cwd.join("recorder-mode").exists() || first == "record" {
        let environment: BTreeMap<String, String> = std::env::vars().collect();
        fs::write(
            cwd.join("record.json"),
            json!({"argv": argv, "env": environment}).to_string(),
        )
        .map_err(|error| error.to_string())?;
        return Ok(0);
    }
    if first == "msb" {
        return fake_admin(&database, &root, arguments);
    }
    fake_launch(&database, &root, &cwd, Path::new(&state))
}

/// The CLI's `msb` verbs: `list`, `stop` and `remove`, with the fault files the
/// controls inject. Every call is recorded so a control can require the verbs the
/// cleanup used, never a prefix kill.
fn fake_admin(
    database: &rusqlite::Connection,
    root: &Path,
    arguments: &[String],
) -> Result<i32, String> {
    let mut calls = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join("calls"))
        .map_err(|error| error.to_string())?;
    writeln!(calls, "{}", json!(arguments)).map_err(|error| error.to_string())?;
    let verb = arguments.get(1).cloned().unwrap_or_default();
    match verb.as_str() {
        "list" => {
            if root.join("wedge-list").exists() {
                std::thread::sleep(Duration::from_secs(600));
            }
            let mut statement = database
                .prepare("SELECT name FROM sandbox")
                .map_err(|error| error.to_string())?;
            let names: Vec<Value> = statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(|error| error.to_string())?
                .filter_map(Result::ok)
                .map(|name| json!({"name": name}))
                .collect();
            println!("{}", Value::Array(names));
        }
        "stop" => {
            let force = arguments.iter().any(|argument| argument == "--force");
            if !force || root.join("fail-force").exists() {
                // The primary stop failure a cleanup must survive.
                return Ok(9);
            }
            let mut statement = database
                .prepare("SELECT pid FROM \"run\"")
                .map_err(|error| error.to_string())?;
            let pids: Vec<i64> = statement
                .query_map([], |row| row.get::<_, i64>(0))
                .map_err(|error| error.to_string())?
                .filter_map(Result::ok)
                .collect();
            for pid in pids {
                if let Ok(pid) = i32::try_from(pid) {
                    // SAFETY: a signal to a pid the catalog recorded; a pid that
                    // is already gone is the expected answer here.
                    unsafe { libc::kill(pid, libc::SIGKILL) };
                }
            }
        }
        "remove" => {
            if root.join("fail-remove").exists() {
                return Ok(8);
            }
            let Some(name) = arguments.last() else {
                return Ok(0);
            };
            database
                .execute("DELETE FROM sandbox WHERE name=?1", [name])
                .map_err(|error| error.to_string())?;
        }
        _ => {}
    }
    Ok(0)
}

/// The launcher role: a banner, the private catalog, two unix sockets, a detached
/// runtime and a TERM-ignoring attached child, then a sleep the supervisor's bound
/// ends. `no-ready` stops it before any of that, which is the launcher that timed
/// out without finishing its state initialization.
fn fake_launch(
    database: &rusqlite::Connection,
    root: &Path,
    cwd: &Path,
    state: &Path,
) -> Result<i32, String> {
    if cwd.join("no-ready").exists() {
        std::thread::sleep(Duration::from_secs(600));
        return Ok(0);
    }
    let project = cwd.canonicalize().map_err(|error| error.to_string())?;
    let project_hash = hex(project.as_os_str().as_encoded_bytes())[..12].to_owned();
    let name = format!("agent-vm-{project_hash}-{}", std::process::id());
    fs::create_dir_all(state.join(&project_hash)).map_err(|error| error.to_string())?;
    println!(
        "==> {name} in {} (state: {})",
        project.display(),
        state.join(&project_hash).display()
    );
    let _ = std::io::stdout().flush();
    let detached = spawn_idle(true)?;
    database
        .execute("INSERT INTO sandbox VALUES(1,?1,'{}','Running')", [&name])
        .map_err(|error| error.to_string())?;
    database
        .execute(
            "INSERT INTO \"run\" VALUES(1,1,?1,'Running')",
            [i64::from(detached.id())],
        )
        .map_err(|error| error.to_string())?;
    // The whole socket layout `egress_launch::socket_paths` names: the cleanup
    // removes a leftover socket only after checking it *is* one, so a launcher
    // that bound fewer would leave the paths it never created to be read as a
    // redirected path.
    let mut sockets = Vec::new();
    for path in egress_launch::socket_paths(root, &name) {
        fs::create_dir_all(path.parent().expect("a parent")).map_err(|error| error.to_string())?;
        sockets.push(
            std::os::unix::net::UnixListener::bind(&path)
                .map_err(|error| format!("{}: {error}", path.display()))?,
        );
    }
    let attached = spawn_idle(false)?;
    fs::write(project.join("attached.pid"), attached.id().to_string())
        .map_err(|error| error.to_string())?;
    fs::write(project.join("launcher-ready"), "").map_err(|error| error.to_string())?;
    // Every launch row these controls drive is a `CL1` launch, so the marker the
    // case log is scanned for is `CL1`'s, as the Python fake's was.
    println!("CASE CL1 BEGIN");
    let _ = std::io::stdout().flush();
    // `detached` and `attached` are deliberately leaked: they are the processes
    // the supervisor's cleanup has to find and reap, so this process must not
    // reap them first.
    std::mem::forget(detached);
    std::mem::forget(attached);
    std::mem::forget(sockets);
    std::thread::sleep(Duration::from_secs(600));
    Ok(0)
}

/// A child that ignores SIGTERM: the detached runtime is one, and so is the
/// attached child in the launch's own group, so only an identity-checked kill or
/// the group teardown's escalation ends them.
fn spawn_idle(new_session: bool) -> Result<Child, String> {
    let mut command = Process::new(harness_binary()?);
    command
        .args(["egress-supervisor", "--fake-idle", "600"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if new_session {
        // SAFETY: `setsid` is a syscall and touches no allocator or lock.
        unsafe {
            command.pre_exec(|| {
                rustix::process::setsid()
                    .map(|_| ())
                    .map_err(std::io::Error::from)
            });
        }
    }
    command.spawn().map_err(|error| error.to_string())
}

/// `--fake-idle SECONDS`: a child that ignores SIGTERM and then exits, so a
/// teardown has to escalate or signal it by identity.
fn run_fake_idle(seconds: f64) -> Result<i32, String> {
    if !seconds.is_finite() || seconds < 0.0 {
        return Err("usage: --fake-idle needs a finite, non-negative number of seconds".to_owned());
    }
    // SAFETY: ignoring a signal is a process-wide disposition, set before any
    // thread exists in this process.
    unsafe { libc::signal(libc::SIGTERM, libc::SIG_IGN) };
    std::thread::sleep(Duration::from_secs_f64(seconds));
    Ok(0)
}

// --- The owned launch helpers -----------------------------------------------

/// The Python's `command()`: a `CL1` launch whose argv is the candidate alone,
/// with a 5 s bound and a 0.1 s grace, in the scratch project.
fn launch_command(work: &Path, binary: &str) -> cases::Command {
    cases::Command {
        case: "CL1".to_owned(),
        variant: "ipv4".to_owned(),
        tool: Some("egressprobe".to_owned()),
        kind: "guest".to_owned(),
        env: egress_fixtures::base_environment(work),
        argv: vec![binary.to_owned(), "egressprobe".to_owned()],
        cwd: work.join("proj").to_string_lossy().into_owned(),
        timeout: LAUNCH_TIMEOUT,
        grace: LAUNCH_GRACE,
        declared_extras: Vec::new(),
        prerequisites: Vec::new(),
        controls: Some(Vec::new()),
        setup: Vec::new(),
        expected_attempts: Vec::new(),
        attempt_expectations: Some(Vec::new()),
        attempt_protocols: Some(Vec::new()),
        supervisor: cases::SUPERVISOR.to_owned(),
    }
}

/// A recorder launch: a candidate that records its argv and environment.
fn recorder_command(work: &Path, binary: &str) -> cases::Command {
    cases::Command {
        case: "record".to_owned(),
        variant: "admin".to_owned(),
        tool: None,
        kind: "guest".to_owned(),
        env: egress_fixtures::base_environment(work),
        argv: vec![binary.to_owned(), "record".to_owned()],
        cwd: work.join("proj").to_string_lossy().into_owned(),
        timeout: 3.0,
        grace: LAUNCH_GRACE,
        declared_extras: Vec::new(),
        prerequisites: Vec::new(),
        controls: Some(Vec::new()),
        setup: Vec::new(),
        expected_attempts: Vec::new(),
        attempt_expectations: Some(Vec::new()),
        attempt_protocols: Some(Vec::new()),
        supervisor: cases::SUPERVISOR.to_owned(),
    }
}

/// The Python's `run_until_timeout`: the launch must be ended by its own bound,
/// and the fake must have finished writing the state the observation needs.
fn run_until_timeout(work: &Path, owned: &OwnedLaunch, root: &Path) -> Result<(), String> {
    let _ = fs::remove_file(work.join("proj/launcher-ready"));
    assert_eq!(
        owned.run()?,
        124,
        "the fake launcher must outlive its bound"
    );
    if !work.join("proj/launcher-ready").is_file() {
        return Err(format!(
            "fake launcher did not finish state initialization within {LAUNCH_TIMEOUT}s; inspect {}",
            owned.log().display()
        ));
    }
    assert!(
        root.join("db/msb.db").is_file(),
        "ready launcher lacks catalog"
    );
    assert!(
        work.join("proj/attached.pid").is_file(),
        "ready launcher lacks attached PID"
    );
    Ok(())
}

/// The attached child ignores SIGTERM, so it may only be gone once the group
/// teardown has escalated.
fn assert_attached_disappeared(work: &Path) {
    let path = work.join("proj/attached.pid");
    assert!(
        path.is_file(),
        "fake launcher never recorded attached child PID"
    );
    let pid: u32 = fs::read_to_string(&path)
        .expect("the attached PID")
        .trim()
        .parse()
        .expect("a pid");
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if egress_fixtures::process_identity(pid)
            .expect("an identity lookup")
            .is_none()
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        egress_fixtures::process_identity(pid)
            .expect("an identity lookup")
            .is_none(),
        "TERM-ignoring attached child survived escalation"
    );
}

fn receipt_rows(work: &Path) -> Vec<Value> {
    fs::read_to_string(work.join("owned.jsonl"))
        .map(|text| {
            text.lines()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .collect()
        })
        .unwrap_or_default()
}

fn recorded(path: &Path) -> Result<Value, String> {
    serde_json::from_slice(&fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?)
        .map_err(|error| format!("{}: {error}", path.display()))
}

fn environment_of(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect()
}

// --- 1. The plan and the recorder -------------------------------------------

fn the_plan_and_the_recorder_agree() -> Result<(), String> {
    control("plan", |work| {
        let fake = fake_candidate(work)?;
        let lan = "192.168.1.2";
        let commands: Vec<cases::Command> = cases::CASES
            .iter()
            .map(|case| build(work, &fake, case))
            .collect();
        let mut keys: BTreeSet<(String, String)> = BTreeSet::new();
        for command in &commands {
            assert!(
                keys.insert((command.case.clone(), command.variant.clone())),
                "duplicate case {}:{}",
                command.case,
                command.variant
            );
        }
        assert_eq!(keys.len(), commands.len());
        let rb1: BTreeSet<&str> = commands
            .iter()
            .filter(|command| command.case == "RB1")
            .map(|command| command.variant.as_str())
            .collect();
        assert_eq!(
            rb1,
            BTreeSet::from([
                "internet", "address", "tcp", "udp", "port", "tcp-port", "udp-port"
            ])
        );
        assert_eq!(
            commands
                .iter()
                .filter(|command| command.case == "RJ1")
                .count(),
            7
        );
        assert_eq!(
            commands
                .iter()
                .filter(|command| command.case == "RB2")
                .count(),
            6
        );
        let expected_keys: BTreeSet<&str> = BTreeSet::from([
            "HOME",
            "XDG_CONFIG_HOME",
            "AGENT_VM_STATE_DIR",
            "PATH",
            "TERM",
            "AGENT_VM_SHARE_MSB_CACHE",
        ]);
        for (case, command) in cases::CASES.iter().zip(&commands) {
            let names: BTreeSet<&str> = command.env.iter().map(|(name, _)| name.as_str()).collect();
            let expected: BTreeSet<&str> = expected_keys
                .iter()
                .copied()
                .chain(case.extras.iter().copied())
                .collect();
            assert_eq!(names, expected, "{}/{}", case.case, case.variant);
            assert_eq!(
                command.tool.as_deref() == Some("egresscreds"),
                matches!(case.case, "CR1" | "CR1c"),
                "{}: the credential tool is the credential cases' alone",
                case.case
            );
            let head: Vec<&str> = command.argv.iter().take(4).map(String::as_str).collect();
            assert_eq!(head, [fake.as_str(), "--no-git", "--image", cases::IMAGE]);
            let validation_only = command.kind == "validation-only";
            assert_eq!(
                validation_only,
                matches!(case.case, "RJ1" | "PXH1"),
                "{}: a validation-only row dispatches nothing",
                case.case
            );
            assert!(
                !command.argv.iter().any(|argument| argument == "--"),
                "{}: argv carries no separator",
                case.case
            );
            let tool = command.tool.clone().expect("every case names a tool");
            let index = command
                .argv
                .iter()
                .position(|argument| *argument == tool)
                .expect("the tool is in argv");
            let tail = &command.argv[index + 1..];
            if matches!(case.case, "NR1" | "NR2" | "NR3") {
                let trailing: &[&str] = if case.case == "NR3" {
                    &["echo", "AGENT_VM_328_SHELL_STARTED"]
                } else {
                    &["--version"]
                };
                assert_eq!(tail, trailing, "{}: the trailing command", case.case);
                assert_eq!(
                    Path::new(&command.cwd),
                    work.join("requests"),
                    "{}: a default-request case runs in its own project",
                    case.case
                );
            } else {
                // A validation-only invocation validates its flags and never
                // dispatches, so nothing may follow the tool; a guest case's tail
                // is its dispatch, and its head names the case.
                let observed: &[String] = if validation_only { tail } else { &tail[..1] };
                let expected: &[&str] = if validation_only { &[] } else { &[case.case] };
                assert_eq!(observed, expected, "{}: the dispatch tail", case.case);
            }
            if case.case != "NR3" {
                assert!(
                    !command.argv.iter().any(|argument| argument == "shell"),
                    "{}: no shell verb",
                    case.case
                );
            }
            assert!(
                !command.argv.iter().any(|argument| argument == "-c"),
                "{}: no -c anywhere in argv",
                case.case
            );
            assert!(
                case.extras.is_empty()
                    || case.case.starts_with("PX")
                    || case.case.starts_with("FL"),
                "{}: extras are the proxy and floor cases' alone",
                case.case
            );
        }
        // ADR-0065: both allowance cases declare their seed and restore steps,
        // and run from the launched project, so neither can run without a record.
        for name in ["PA1", "PA1x"] {
            let command = commands
                .iter()
                .find(|command| command.case == name)
                .expect("an allowance case");
            assert!(!command.setup.is_empty(), "{name}");
            assert!(
                command.setup[0].contains("allowance record"),
                "{name}: {}",
                command.setup[0]
            );
            assert!(command.setup[0].contains("remove the record"), "{name}");
            assert_eq!(Path::new(&command.cwd), work.join("proj"), "{name}");
        }
        let with_setup: Vec<&str> = commands
            .iter()
            .filter(|command| !command.setup.is_empty())
            .map(|command| command.case.as_str())
            .collect();
        assert_eq!(with_setup, ["PA1", "PA1x", "PA2", "CR1c", "CR1"]);
        // PA2 declares the *opposite* of a seed, and owns the writer's
        // never-unlinked lock.
        assert!(!cases::ALLOWANCE_CASES.contains(&"PA2"));
        let pa2 = commands
            .iter()
            .find(|command| command.case == "PA2")
            .expect("PA2");
        assert!(pa2.setup[0].contains("no seed"), "{}", pa2.setup[0]);
        assert!(pa2.setup[0].contains("allowances.lock"));
        // The printed plan is the same inventory, from the CLI rather than this
        // process: a plan the binary cannot print is a plan the shell cannot read.
        let printed = run_cli(
            &[
                "egress-fixtures".to_owned(),
                "run".to_owned(),
                "--print-plan".to_owned(),
                "--work".to_owned(),
                work.to_string_lossy().into_owned(),
                "--binary".to_owned(),
                fake.clone(),
                "--lan".to_owned(),
                lan.to_owned(),
            ],
            Path::new("/"),
            &work.join("plan.log"),
        )?;
        assert_eq!(printed.0, 0, "{}", printed.1);
        let plan: Vec<Value> = printed
            .1
            .lines()
            .map(|line| serde_json::from_str(line).expect("each line is a JSON object"))
            .collect();
        let cases_in_plan: Vec<&str> = commands
            .iter()
            .map(|command| command.case.as_str())
            .collect();
        assert_eq!(
            cases_in_plan,
            plan[..commands.len()]
                .iter()
                .map(|row| row["case"].as_str().expect("a case"))
                .collect::<Vec<&str>>()
        );
        let planned: Vec<BTreeMap<String, String>> = plan[..commands.len()]
            .iter()
            .map(|row| {
                row["env"]
                    .as_object()
                    .expect("an env object")
                    .iter()
                    .map(|(name, value)| {
                        (name.clone(), value.as_str().expect("a string").to_owned())
                    })
                    .collect()
            })
            .collect();
        for ((command, row), env) in commands.iter().zip(&plan).zip(&planned) {
            assert_eq!(json!(command.argv), row["argv"], "{}", command.case);
            assert_eq!(
                &command
                    .env
                    .iter()
                    .cloned()
                    .collect::<BTreeMap<String, String>>(),
                env,
                "{}",
                command.case
            );
        }
        // The recorder: what the candidate is exec'd with is what the plan says.
        for ((command, row), env) in commands.iter().zip(&plan).zip(&planned) {
            let project = PathBuf::from(&command.cwd);
            if matches!(command.case.as_str(), "NR1" | "NR2" | "NR3") {
                cases::prepare_default_request_project(work)?;
            } else {
                egress_run::prepare_project(work, &project)?;
            }
            fs::write(project.join("recorder-mode"), "").map_err(|error| error.to_string())?;
            let (status, output) = cases::run_admin(work, command, None)?;
            assert_eq!(status, 0, "{}: {output}", command.case);
            let record = recorded(&project.join("record.json"))?;
            assert_eq!(record["argv"], row["argv"], "{}", command.case);
            let mut environment = command.clone();
            environment.argv = vec!["/usr/bin/env".to_owned()];
            environment.kind = "admin".to_owned();
            environment.tool = None;
            let (status, output) = cases::run_admin(work, &environment, None)?;
            assert_eq!(status, 0, "{}: {output}", command.case);
            assert_eq!(
                &environment_of(&output),
                env,
                "{}: the exec environment is the plan's",
                command.case
            );
            fs::remove_file(project.join("recorder-mode")).map_err(|error| error.to_string())?;
        }
        let admins: BTreeSet<&str> = plan[commands.len()..]
            .iter()
            .map(|row| row["case"].as_str().expect("a case"))
            .collect();
        assert_eq!(
            admins,
            BTreeSet::from([
                "image-load",
                "list",
                "stop",
                "force-stop",
                "remove",
                "IN1",
                "IN2",
                "fixture-health",
                "fixture-start"
            ])
        );
        // Pin the real discovery path (ADR-0073: `<home>/.config/agent-vm/
        // projects/<digest>/config.toml`). Computed inline, not with the shared
        // helper, so the fixture writer and this assertion cannot agree on a
        // wrong hash.
        egress_run::prepare_project(work, &work.join("proj"))?;
        let canonical = work
            .join("proj")
            .canonicalize()
            .map_err(|error| error.to_string())?;
        use sha2::Digest as _;
        let mut hex = String::with_capacity(64);
        for byte in sha2::Sha256::digest(std::os::unix::ffi::OsStrExt::as_bytes(
            canonical.as_os_str(),
        )) {
            use std::fmt::Write as _;
            write!(&mut hex, "{byte:02x}").expect("writing to a String cannot fail");
        }
        let discovered = work
            .join("home/.config/agent-vm/projects")
            .join(hex)
            .join("config.toml");
        let committed = repo_root().join("script/test/fixtures/egress-config.toml");
        assert_eq!(
            fs::read(&discovered).map_err(|error| error.to_string())?,
            fs::read(&committed).map_err(|error| format!("{}: {error}", committed.display()))?,
            "the project config is the committed fixture"
        );
        assert!(
            !work.join("proj/.agent-vm/config.toml").exists(),
            "an in-repo config is no longer a catalog"
        );
        // A shared command's exec argv and environment against its plan.
        let command = recorder_command(work, &fake);
        let (status, output) = cases::run_admin(work, &command, None)?;
        assert_eq!(status, 0, "{output}");
        let record = recorded(&work.join("proj/record.json"))?;
        assert_eq!(record["argv"], command.plan()["argv"]);
        let mut environment = command.clone();
        environment.argv = vec!["/usr/bin/env".to_owned()];
        let (status, output) = cases::run_admin(work, &environment, None)?;
        assert_eq!(status, 0, "{output}");
        assert_eq!(
            environment_of(&output),
            command
                .env
                .iter()
                .cloned()
                .collect::<BTreeMap<String, String>>()
        );
        Ok(())
    })
}

// --- 2. The allowance seed and restore lifecycle ----------------------------

fn the_allowance_seed_and_restore_lifecycle() -> Result<(), String> {
    control("allowance", |work| {
        // ADR-0065 AC13: the record each PA case launches under is written,
        // checked and removed by the same functions the boot harness calls.
        for (case, project) in [("PA1", "proj"), ("PA1x", "other")] {
            fs::create_dir_all(work.join(project)).map_err(|error| error.to_string())?;
            assert_eq!(
                egress_allowances::prepare_allowance(work, case, "192.168.1.2"),
                Vec::<String>::new()
            );
            egress_allowances::remove_allowances(work);
            egress_allowances::seed_allowances(work, case, "192.168.1.2")?;
            let stale = egress_allowances::prepare_allowance(work, case, "192.168.1.2");
            assert_eq!(stale.len(), 1, "{stale:?}");
            assert!(stale[0].contains("left from an earlier case"), "{stale:?}");
            // Reported and re-seeded: the case can still run, and it fails.
            assert_eq!(
                egress_allowances::check_allowance_seed(work, case, "192.168.1.2"),
                Vec::<String>::new()
            );
            // Independent of the seeder: the digest of the canonical path's bytes.
            let store = egress_allowances::allowance_store(work);
            let canonical = work
                .join(project)
                .canonicalize()
                .map_err(|error| error.to_string())?;
            assert_eq!(
                recorded(&store)?,
                json!({"v": 1, "records": [{
                    "project": hex(canonical.as_os_str().as_encoded_bytes()),
                    "path": canonical.to_string_lossy(),
                    "destination": "tcp://192.168.1.2:18080",
                    "recorded_ms": 1762680120000u64,
                }]})
            );
            use std::os::unix::fs::PermissionsExt;
            let mode = |path: &Path| {
                fs::metadata(path)
                    .map(|metadata| metadata.permissions().mode() & 0o777)
                    .unwrap_or_default()
            };
            assert_eq!(mode(&store), 0o600, "the store is private");
            assert_eq!(
                mode(store.parent().expect("a parent")),
                0o700,
                "the authority directory is private"
            );
            // The pre-launch check accepts the seed it just wrote ...
            assert_eq!(
                egress_allowances::check_allowance_seed(work, case, "192.168.1.2"),
                Vec::<String>::new()
            );
            // ... and refuses a seed that is missing, malformed, foreign or has
            // the wrong destination, which is what stops PA1x passing vacuously.
            let original = fs::read(&store).map_err(|error| error.to_string())?;
            let record = recorded(&store)?;
            fs::remove_file(&store).map_err(|error| error.to_string())?;
            assert!(!egress_allowances::check_allowance_seed(work, case, "192.168.1.2").is_empty());
            fs::write(&store, "not json").map_err(|error| error.to_string())?;
            assert!(!egress_allowances::check_allowance_seed(work, case, "192.168.1.2").is_empty());
            for (field, value) in [
                ("project", json!("0".repeat(64))),
                ("destination", json!("tcp://192.168.1.9:18080")),
            ] {
                let mut wrong = record.clone();
                wrong["records"][0][field] = value;
                fs::write(&store, wrong.to_string()).map_err(|error| error.to_string())?;
                fs::set_permissions(&store, fs::Permissions::from_mode(0o600))
                    .map_err(|error| error.to_string())?;
                assert!(
                    !egress_allowances::check_allowance_seed(work, case, "192.168.1.2").is_empty(),
                    "a {field} that is not the case's must be refused"
                );
            }
            fs::write(&store, &original).map_err(|error| error.to_string())?;
            fs::set_permissions(&store, fs::Permissions::from_mode(0o600))
                .map_err(|error| error.to_string())?;
            // A second seed over a live record is refused, never a silent
            // overwrite: the leftover is what the launcher reports.
            assert!(
                egress_allowances::seed_allowances(work, case, "192.168.1.2").is_err(),
                "a live record is never overwritten"
            );
            // The restore reports nothing left, and nothing of the store's own.
            assert_eq!(
                egress_allowances::remove_allowances(work),
                Vec::<String>::new()
            );
            assert!(!egress_allowances::allowance_store(work).exists());
            let siblings: Vec<PathBuf> = fs::read_dir(store.parent().expect("a parent"))
                .map(|entries| {
                    entries
                        .filter_map(Result::ok)
                        .map(|entry| entry.path())
                        .filter(|path| {
                            path.file_name().is_some_and(|name| {
                                name.to_string_lossy().starts_with("allowances.")
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            assert_eq!(siblings, Vec::<PathBuf>::new());
            // A lock left behind *is* reported.
            egress_allowances::seed_allowances(work, case, "192.168.1.2")?;
            let lock = egress_allowances::allowance_lock(work);
            fs::write(&lock, "").map_err(|error| error.to_string())?;
            let failures = egress_allowances::remove_allowances(work);
            assert_eq!(failures.len(), 1, "{failures:?}");
            assert!(failures[0].contains("allowances.lock"), "{failures:?}");
            fs::remove_file(&lock).map_err(|error| error.to_string())?;
            // A dangling symlink at the name is still a leftover, which
            // `Path::exists` would have read as absent.
            std::os::unix::fs::symlink(work.join("gone"), egress_allowances::allowance_store(work))
                .map_err(|error| error.to_string())?;
            assert!(egress_allowances::allowance_present(work));
            assert_eq!(egress_allowances::remove_allowances(work).len(), 1);
            fs::remove_file(egress_allowances::allowance_store(work))
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    })
}

// --- 3. The allowance call sites -------------------------------------------

fn the_launcher_runs_the_allowance_lifecycle() -> Result<(), String> {
    control("allowance-sites", |work| {
        // The call sites, not only the helpers: `orchestrate` is a whole boot
        // harness, so the boot-free proof is that the steps it must perform are
        // the ones it calls. `harness egress-mutations` deletes each call to
        // prove this control bites.
        let run_source = source("crates/harness/src/egress_run.rs")?;
        for fragment in [
            // The seed step, with its guard: the abort branch's recovery call
            // must not stand in for it.
            "if ALLOWANCE_CASES.contains(&case.case) {\n            let mut failures = prepare_allowance(work, case.case, lan);",
            // The per-case restore, likewise with its guard.
            "if ALLOWANCE_CASES.contains(&case.case) {\n        failures.extend(remove_allowances(work));",
            // The run's last cleanup, which is what survives an error.
            "cleanup_errors.extend(final_cleanup(&work));",
        ] {
            assert!(
                run_source.contains(fragment),
                "orchestrate no longer runs: {fragment}"
            );
        }
        // A case that raises between its seed and its own removal: the final
        // cleanup still removes the record.
        let case = "PA1";
        assert_eq!(
            egress_allowances::prepare_allowance(work, case, "192.168.1.2"),
            Vec::<String>::new()
        );
        assert_eq!(
            egress_run::final_cleanup(work),
            Vec::<String>::new(),
            "a case that aborts mid-way still leaves no record"
        );
        assert!(!egress_allowances::allowance_present(work));
        // The writer's lock is the one `allowances.*` name a *run* may own: PA2's
        // writer creates it and nothing unlinks it (ADR-0065 constraint 1), so
        // `final_cleanup` removes it and `remove_allowances` still reports it.
        assert_eq!(
            egress_allowances::prepare_allowance(work, case, "192.168.1.2"),
            Vec::<String>::new()
        );
        let lock = egress_allowances::allowance_lock(work);
        fs::write(&lock, "").map_err(|error| error.to_string())?;
        assert_eq!(
            egress_allowances::remove_allowances(work).len(),
            1,
            "a lock is a finding for PA1"
        );
        assert_eq!(egress_run::final_cleanup(work), Vec::<String>::new());
        assert!(
            !lock.exists(),
            "the final cleanup removes the writer's lock"
        );
        assert!(!egress_allowances::allowance_present(work));
        // Any other sibling of the store's own is still a failure: it means the
        // store was refused or set aside, never written.
        assert_eq!(
            egress_allowances::prepare_allowance(work, case, "192.168.1.2"),
            Vec::<String>::new()
        );
        let sibling = egress_allowances::allowance_store(work)
            .parent()
            .expect("a parent")
            .join("allowances.json.damaged");
        fs::write(&sibling, "").map_err(|error| error.to_string())?;
        let final_failures = egress_run::final_cleanup(work);
        assert_eq!(final_failures.len(), 1, "{final_failures:?}");
        assert!(
            final_failures[0].contains("allowances.json.damaged"),
            "{final_failures:?}"
        );
        fs::remove_file(&sibling).map_err(|error| error.to_string())?;
        Ok(())
    })
}

// --- 4. The live-allowance case --------------------------------------------

fn the_live_allowance_case_lifecycle() -> Result<(), String> {
    control("live-allowance", |work| {
        // ADR-0066 PA2: the opposite of a seed, and the writer's own lock.
        let project = work.join("proj");
        assert!(!cases::ALLOWANCE_CASES.contains(&"PA2"));
        // A PA2 launch is not gated on a seed: the seeder refuses the case, so a
        // PA2 case can never be given a record it did not write itself.
        let refused = egress_allowances::prepare_allowance(work, "PA2", "192.168.1.2");
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(
            refused[0].contains("PA2 has no allowance record"),
            "{refused:?}"
        );
        // ... and only PA2 has the live lifecycle.
        assert!(
            !egress_witness::prepare_live_allowance(work, "PA1").is_empty(),
            "PA1 is not the live-allowance case"
        );
        // A clean work directory needs nothing, and stale signals are cleared.
        for name in egress_allowances::PA2_SIGNALS {
            fs::write(project.join(name), "").map_err(|error| error.to_string())?;
        }
        assert_eq!(
            egress_witness::prepare_live_allowance(work, "PA2"),
            Vec::<String>::new()
        );
        for name in egress_allowances::PA2_SIGNALS {
            assert!(!project.join(name).exists(), "{name}");
        }
        // A leftover store is reported *and* removed: the case must run from the
        // default-deny state, and the leak is evidence about an earlier case.
        egress_allowances::seed_allowances(work, "PA1", "192.168.1.2")?;
        fs::write(egress_allowances::allowance_lock(work), "")
            .map_err(|error| error.to_string())?;
        let stale = egress_witness::prepare_live_allowance(work, "PA2");
        assert_eq!(stale.len(), 1, "{stale:?}");
        assert!(stale[0].contains("left from an earlier case"), "{stale:?}");
        assert!(!egress_allowances::allowance_present(work));
        assert!(!egress_allowances::allowance_lock(work).exists());
        // `cleanup_pa2` removes the record and the lock, and reports anything
        // else of the store's own: a set-aside store means the writer refused.
        egress_allowances::seed_allowances(work, "PA1", "192.168.1.2")?;
        let lock = egress_allowances::allowance_lock(work);
        fs::write(&lock, "").map_err(|error| error.to_string())?;
        assert_eq!(egress_allowances::cleanup_pa2(work), Vec::<String>::new());
        assert!(!egress_allowances::allowance_present(work));
        assert!(!lock.exists());
        assert_eq!(
            egress_allowances::cleanup_pa2(work),
            Vec::<String>::new(),
            "cleanup is idempotent"
        );
        let damaged = lock
            .parent()
            .expect("a parent")
            .join("allowances.json.damaged");
        fs::write(&damaged, "").map_err(|error| error.to_string())?;
        assert_eq!(egress_allowances::cleanup_pa2(work).len(), 1);
        fs::remove_file(&damaged).map_err(|error| error.to_string())?;
        // The call sites again: `check_live_allowance` is the verdict PA2's
        // evidence is judged by, and `cleanup_pa2` is what its restore runs.
        let run_source = source("crates/harness/src/egress_run.rs")?;
        for fragment in [
            "let failures = prepare_live_allowance(work, case.case);",
            "failures.extend(check_live_allowance(work, owned.ident(), &text));",
            "if case.case == \"PA2\" {\n        failures.extend(cleanup_pa2(work));",
            "cleanup_errors.extend(final_cleanup(&work));",
        ] {
            assert!(
                run_source.contains(fragment),
                "the run no longer performs: {fragment}"
            );
        }
        // The launch's own PA2 arm: the case is the one whose evidence is a live
        // witness, so dropping it here would leave the witness thread unstarted
        // while every assertion above still passed.
        let launch_source = source("crates/harness/src/egress_launch.rs")?;
        let witness_arm = "if !matches!(self.command.case.as_str(), \"RF1\" | \"PA2\") {";
        assert!(
            launch_source.contains(witness_arm),
            "the launch no longer starts PA2's witness: {witness_arm}"
        );
        Ok(())
    })
}

// --- 5. The live-allowance verdict ------------------------------------------

fn the_live_allowance_verdict_bites() -> Result<(), String> {
    control("live-verdict", |work| {
        let project = work.join("proj");
        let ident = "PA2-ipv4-0";
        let destination = "tcp://192.168.1.2/32:18080";
        let store = json!({"v": 1, "records": [{
            "project": "0".repeat(64),
            "path": project.to_string_lossy(),
            "destination": destination,
            "recorded_ms": 1762680120000u64,
        }]})
        .to_string();
        let steps: Vec<Value> = ["allow", "table", "allowances", "revoke"]
            .iter()
            .map(|step| json!({"step": step, "status": 0, "output": ""}))
            .collect();
        let evidence = json!({
            "refusal_id": "0e7e41fb",
            "session": "aaaaaaaa",
            "destination": destination,
            "steps": steps,
            "failures": [],
            "store": store,
            "store_after_revoke": json!({"v": 1, "records": []}).to_string(),
            "grant_revision": 2,
            "revoke_revision": 3,
        });
        // The case must be declared exactly once, without a probe inventory of
        // its own: its evidence is the transition. A second declaration would
        // double-run the case.
        assert_eq!(
            cases::CASES
                .iter()
                .filter(|case| case.case == "PA2")
                .count(),
            1
        );
        assert!(
            cases::expected_attempts(case_row("PA2", "ipv4")).is_empty(),
            "PA2 declares no probe inventory"
        );
        let text = format!(
            "{}\n",
            std::iter::once("CASE PA2 BEGIN")
                .chain(egress_witness::PA2_MARKERS)
                .chain(std::iter::once("CASE PA2 END"))
                .collect::<Vec<&str>>()
                .join("\n")
        );
        let receipts = work.join("fx/receipts.log");
        let verdict = |record: Option<Value>,
                       log: Option<String>,
                       receipt_lines: Option<String>| {
            fs::write(
                work.join("PA2-witness.json"),
                record.unwrap_or_else(|| evidence.clone()).to_string(),
            )
            .expect("the evidence file");
            fs::write(
                &receipts,
                receipt_lines.unwrap_or_else(|| format!("tcp 18080 127.0.0.1 {ident}-p2\n")),
            )
            .expect("the receipt log");
            egress_witness::check_live_allowance(work, ident, &log.unwrap_or_else(|| text.clone()))
        };
        assert_eq!(verdict(None, None, None), Vec::<String>::new());
        assert!(!verdict(None, Some(text.replace("PA2 PROBE 2 OK\n", "")), None).is_empty());
        assert!(
            !verdict(
                None,
                Some(format!("{text}PA2 PROBE 2 STILL DENIED\n")),
                None
            )
            .is_empty(),
            "a second denial is not a grant"
        );
        for (field, value) in [
            ("grant_revision", json!(1)),
            ("revoke_revision", json!(2)),
            ("failures", json!(["the grant failed"])),
            ("destination", json!("")),
        ] {
            let mut record = evidence.clone();
            record[field] = value;
            assert!(!verdict(Some(record), None, None).is_empty(), "{field}");
        }
        let mut short = evidence.clone();
        short["steps"] = json!(short["steps"].as_array().expect("steps")[..3].to_vec());
        assert!(!verdict(Some(short), None, None).is_empty(), "three steps");
        let mut malformed = evidence.clone();
        malformed["store"] = json!("not json");
        assert!(!verdict(Some(malformed), None, None).is_empty(), "store");
        let mut unchanged = evidence.clone();
        unchanged["store_after_revoke"] = json!(store);
        assert!(
            !verdict(Some(unchanged), None, None).is_empty(),
            "a revoke that left the record"
        );
        assert!(
            !verdict(None, None, Some(String::new())).is_empty(),
            "no receipt"
        );
        assert!(
            !verdict(
                None,
                None,
                Some(format!(
                    "tcp 18080 127.0.0.1 {ident}-p2\ntcp 18080 127.0.0.1 {ident}-p1\n"
                ))
            )
            .is_empty(),
            "a refused probe that reached the fixture"
        );
        fs::remove_file(work.join("PA2-witness.json")).map_err(|error| error.to_string())?;
        assert!(
            !egress_witness::check_live_allowance(work, ident, &text).is_empty(),
            "no evidence is not a pass"
        );
        Ok(())
    })
}

// --- 6. The required calibrations and their links ---------------------------

fn the_required_calibrations_and_links() -> Result<(), String> {
    control("calibrations", |work| {
        let fake = fake_candidate(work)?;
        // An independent endpoint/protocol inventory: deleting a calibration must
        // not delete its oracle along with it.
        let index: BTreeMap<(&str, &str), &cases::Case> = cases::CASES
            .iter()
            .map(|case| ((case.case, case.variant), case))
            .collect();
        let required: [((&str, &str), &[&str]); 4] = [
            (
                ("LC1", "ipv4"),
                &["lan-tcp80", "lan-tcp81", "lan-udp90", "lan-udp80"],
            ),
            (
                ("I1", "ipv4"),
                &[
                    "public-1111",
                    "public-1001",
                    "gateway-udp",
                    "gateway-tcp",
                    "explicit-udp",
                    "explicit-tcp",
                    "lan-tcp80",
                    "host-tcp80",
                ],
            ),
            (("V6c", "ipv6"), &["public-v6-1111", "public-v6-1001"]),
            (("DNS6c", "ipv6"), &["explicit-v6-udp", "explicit-v6-tcp"]),
        ];
        for (key, labels) in required {
            let case = index.get(&key).unwrap_or_else(|| panic!("no case {key:?}"));
            let actual: BTreeSet<&str> = cases::expected_attempts(case).into_iter().collect();
            let wanted: BTreeSet<&str> = labels.iter().copied().collect();
            assert_eq!(actual, wanted, "{key:?}");
        }
        for case in cases::CASES {
            let command = build(work, &fake, case);
            let Some(controls) = command.controls.as_ref() else {
                continue;
            };
            for (label, expectation) in command.attempt_expectations.clone().unwrap_or_default() {
                if expectation != "1" && expectation != "NX" {
                    continue;
                }
                let Some((_, link)) = controls.iter().find(|(name, _)| *name == label) else {
                    panic!("{}/{}: no control for {label}", case.case, case.variant);
                };
                let parts: Vec<&str> = link.split(':').collect();
                assert_eq!(parts.len(), 3, "{label}: {link}");
                let positive = index
                    .get(&(parts[0], parts[1]))
                    .unwrap_or_else(|| panic!("{label}: no case {}:{}", parts[0], parts[1]));
                assert!(
                    cases::expected_attempts(positive).contains(&parts[2]),
                    "{label}: {} has no attempt {}",
                    parts[0],
                    parts[2]
                );
                let value = lookup(&cases::attempt_expectations(positive), parts[2]);
                assert!(
                    value == "0" || value == "OK",
                    "{label}: the positive control is {value}"
                );
            }
        }
        Ok(())
    })
}

// --- 7. Missing attempts and reply markers ---------------------------------

fn missing_attempts_and_reply_markers_fail() -> Result<(), String> {
    control("attempts", |work| {
        let fake = fake_candidate(work)?;
        let case = case_row("D1", "ipv4");
        let command = build(work, &fake, case);
        let rows: Vec<Value> = command
            .expected_attempts
            .iter()
            .map(|label| {
                json!({
                    "label": label,
                    "expectation": lookup(
                        command.attempt_expectations.as_ref().expect("expectations"),
                        label,
                    ),
                    "protocol": lookup(
                        command.attempt_protocols.as_ref().expect("protocols"),
                        label,
                    ),
                })
            })
            .collect();
        assert_eq!(
            egress_run::check_attempt_inventory(&command, &rows),
            Vec::<String>::new()
        );
        let mut changed = rows.clone();
        changed[0]["expectation"] = json!("0");
        assert!(!egress_run::check_attempt_inventory(&command, &changed).is_empty());
        let mut relabelled = rows.clone();
        relabelled[0]["protocol"] = json!("public");
        assert!(!egress_run::check_attempt_inventory(&command, &relabelled).is_empty());
        assert!(
            !egress_run::check_attempt_inventory(&command, &rows[..rows.len() - 1]).is_empty(),
            "a missing attempt"
        );
        let mut duplicated = rows.clone();
        duplicated.push(rows[0].clone());
        assert!(
            !egress_run::check_attempt_inventory(&command, &duplicated).is_empty(),
            "a duplicated attempt"
        );
        let public = json!({
            "label": "public-1111",
            "protocol": "public",
            "endpoint": "1.1.1.1",
            "port": "80",
            "expectation": "1",
            "receipt": "-",
            "output": "HTTP_FAIL 1.1.1.1:80\n",
        });
        assert_eq!(
            egress_run::check_attempts(work, case, std::slice::from_ref(&public), 0),
            Vec::<String>::new()
        );
        let mut silent = public.clone();
        silent["output"] = json!("");
        assert!(!egress_run::check_attempts(work, case, &[silent], 0).is_empty());
        let dns = json!({
            "label": "public-1111",
            "protocol": "dns-udp",
            "endpoint": "1.1.1.1",
            "port": "80",
            "expectation": "NX",
            "receipt": "-",
            "output": "DNS udp 1.1.1.1 example.com id_ok=1 qr=1 question_ok=1 tc=0 rcode=3 ancount=0 a= ms=10\n",
        });
        assert_eq!(
            egress_run::check_attempts(work, case, std::slice::from_ref(&dns), 0),
            Vec::<String>::new()
        );
        let mut unidentified = dns.clone();
        unidentified["output"] = json!(
            dns["output"]
                .as_str()
                .expect("an output")
                .replace("id_ok=1", "id_ok=0")
        );
        assert!(
            !egress_run::check_attempts(work, case, &[unidentified], 0).is_empty(),
            "a reply whose id does not match the query"
        );
        Ok(())
    })
}

// --- 8. Timeout, detached catalog, sockets ---------------------------------

fn the_timeout_separates_the_launch_from_its_cleanup() -> Result<(), String> {
    control("timeout", |work| {
        let fake = fake_candidate(work)?;
        let owned = egress_launch::OwnedLaunch::new(
            work,
            &launch_command(work, &fake),
            "timeout".to_owned(),
        )?;
        let root = owned.root().to_path_buf();
        let outcome = (|| -> Result<(), String> {
            run_until_timeout(work, &owned, &root)?;
            assert_attached_disappeared(work);
            assert_eq!(owned.names().len(), 1, "one owned sandbox");
            let start = Instant::now();
            let errors = owned.cleanup(None);
            assert!(
                start.elapsed() < Duration::from_secs(15),
                "cleanup took {:?}",
                start.elapsed()
            );
            assert!(
                errors.iter().any(|error| error.contains("status 9")),
                "the primary stop failure is reported: {errors:?}"
            );
            let calls: Vec<Value> = fs::read_to_string(root.join("calls"))
                .map(|text| {
                    text.lines()
                        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                        .collect()
                })
                .unwrap_or_default();
            let name = owned.names().into_iter().next().expect("a name");
            for wanted in [
                json!(["msb", "stop", "--timeout", "5", name]),
                json!(["msb", "stop", "--force", name]),
                json!(["msb", "remove", name]),
            ] {
                assert!(calls.contains(&wanted), "{wanted} not in {calls:?}");
            }
            assert!(
                owned.alive()?.is_empty(),
                "no recorded identity is still alive"
            );
            assert!(
                msb_catalog::catalog_rows(&root)?.is_empty(),
                "the catalog is empty of the owned names"
            );
            for path in egress_launch::socket_paths(&root, &name) {
                assert!(!path.exists(), "owned socket left: {}", path.display());
            }
            let last = receipt_rows(work).pop().expect("a cleanup receipt");
            assert_eq!(last["primary_status"], json!(124));
            assert!(
                last["cleanup_errors"]
                    .as_array()
                    .is_some_and(|errors| !errors.is_empty()),
                "{last}"
            );
            Ok(())
        })();
        let _ = owned.cleanup(None);
        outcome
    })
}

// --- 9. Slow startup and the missing readiness diagnostic ------------------

fn a_launch_that_never_becomes_ready_is_diagnosed() -> Result<(), String> {
    control("readiness", |work| {
        let fake = fake_candidate(work)?;
        let root = work.join("state/msb-home");
        // A launcher that timed out without finishing its state initialization
        // must fail *with that diagnostic*, not as a bare "not 124".
        fs::write(work.join("proj/no-ready"), "").map_err(|error| error.to_string())?;
        let command = launch_command(work, &fake);
        let unready = egress_launch::OwnedLaunch::new(work, &command, "no-ready".to_owned())?;
        let failure = run_until_timeout(work, &unready, &root)
            .expect_err("a launcher that never wrote its readiness must not pass");
        assert!(
            failure.contains("fake launcher did not finish state initialization"),
            "{failure}"
        );
        let _ = unready.cleanup(None);
        fs::remove_file(work.join("proj/no-ready")).map_err(|error| error.to_string())?;
        // Exceeds the former 0.8 s bound even without CPU contention.
        fs::write(work.join("proj/startup-delay"), "1.2").map_err(|error| error.to_string())?;
        let owned = egress_launch::OwnedLaunch::new(work, &command, "slow-startup".to_owned())?;
        let outcome = (|| -> Result<(), String> {
            run_until_timeout(work, &owned, &root)?;
            assert_attached_disappeared(work);
            let errors = owned.cleanup(None);
            assert!(
                errors.iter().any(|error| error.contains("status 9")),
                "{errors:?}"
            );
            assert!(owned.alive()?.is_empty());
            assert!(msb_catalog::catalog_rows(&root)?.is_empty());
            Ok(())
        })();
        let _ = owned.cleanup(None);
        outcome
    })
}

// --- 10. A failed force stop ------------------------------------------------

fn a_failed_force_stop_falls_back_to_identities() -> Result<(), String> {
    control("force-fallback", |work| {
        let fake = fake_candidate(work)?;
        let root = work.join("state/msb-home");
        let owned = egress_launch::OwnedLaunch::new(
            work,
            &launch_command(work, &fake),
            "force-fallback".to_owned(),
        )?;
        let outcome = (|| -> Result<(), String> {
            run_until_timeout(work, &owned, &root)?;
            fs::write(root.join("fail-force"), "").map_err(|error| error.to_string())?;
            let errors = owned.cleanup(None);
            assert!(
                errors.iter().any(|error| error.contains("force-stop")),
                "the force-stop failure is reported: {errors:?}"
            );
            assert!(owned.alive()?.is_empty(), "the fallback reaped the runtime");
            assert!(msb_catalog::catalog_rows(&root)?.is_empty());
            Ok(())
        })();
        let _ = fs::remove_file(root.join("fail-force"));
        let _ = owned.cleanup(None);
        outcome
    })
}

// --- 11. The socket path derivation ----------------------------------------

fn the_socket_paths_are_the_pinned_layout() -> Result<(), String> {
    let paths = egress_launch::socket_paths(
        Path::new("/tmp/av302-msb-home"),
        "agent-vm-0123456789ab-4242",
    );
    let rendered: Vec<String> = paths
        .iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        rendered,
        [
            "/tmp/av302-msb-home/run/sandboxes/e6b31ea46b06a7e0865241dd/agent.sock",
            "/tmp/av302-msb-home/run/sandboxes/e6b31ea46b06a7e0865241dd/control.sock",
            "/tmp/av302-msb-home/run/agent/e6b31ea46b06a7e0865241dd3e4a49ac.sock",
            "/tmp/av302-msb-home/run/agent/e6b31ea46b06a7e0865241dd3e4a49ac.control.sock",
        ]
    );
    Ok(())
}

// --- 12. The catalog before its first migration ----------------------------

fn an_unmigrated_catalog_is_not_yet_initialized() -> Result<(), String> {
    control("catalog", |work| {
        let root = work.join("state/msb-home");
        // #449: the private file exists for ~3 ms before the first migration
        // commits its tables, and the observer polls every 50 ms. An absent table
        // is "not yet initialized" (no rows, keep polling); a table that exists
        // with the wrong columns is still a mismatch.
        assert_eq!(msb_catalog::catalog_rows(&root)?, Vec::new());
        fs::create_dir_all(root.join("db")).map_err(|error| error.to_string())?;
        rusqlite::Connection::open(root.join("db/msb.db")).map_err(|error| error.to_string())?;
        assert_eq!(msb_catalog::catalog_rows(&root)?, Vec::new());
        let database =
            || rusqlite::Connection::open(root.join("db/msb.db")).expect("the launcher's database");
        // Half-migrated: the run table is still absent.
        database()
            .execute(
                "CREATE TABLE sandbox (id INTEGER, name TEXT, config TEXT, status TEXT)",
                [],
            )
            .map_err(|error| error.to_string())?;
        assert_eq!(msb_catalog::catalog_rows(&root)?, Vec::new());
        let connection = database();
        connection
            .execute_batch(
                "CREATE TABLE \"run\" (id INTEGER, sandbox_id INTEGER, pid INTEGER, status TEXT);\
                 INSERT INTO sandbox VALUES (1, 'agent-vm-0123456789ab-1', '{}', 'Running');",
            )
            .map_err(|error| error.to_string())?;
        drop(connection);
        assert_eq!(
            msb_catalog::catalog_rows(&root)?
                .iter()
                .map(|row| row.name.as_str())
                .collect::<Vec<&str>>(),
            ["agent-vm-0123456789ab-1"]
        );
        let connection = database();
        connection
            .execute_batch(
                "DROP TABLE sandbox;\
                 CREATE TABLE sandbox (id INTEGER, name TEXT);",
            )
            .map_err(|error| error.to_string())?;
        drop(connection);
        let error = msb_catalog::catalog_rows(&root).expect_err("a schema mismatch is fatal");
        assert!(
            error.contains("private catalog schema mismatch: sandbox"),
            "{error}"
        );
        Ok(())
    })
}

// --- 13. PID reuse and paths outside the work root -------------------------

fn a_reused_pid_and_an_outside_path_are_refused() -> Result<(), String> {
    control("pid-reuse", |work| {
        // The Python patched `process_identity`; here the recorded start is
        // tampered with instead, so the refusal is asked of the real lookup and
        // the proof that nothing was signalled is the child still running.
        let mut idle = Process::new(harness_binary()?)
            .args(["egress-supervisor", "--fake-idle", "60"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| error.to_string())?;
        let pid = idle.id();
        let start = egress_fixtures::process_identity(pid).expect("an identity");
        let outcome = (|| -> Result<(), String> {
            let refused = egress_fixtures::signal_identity(
                &json!({"pid": pid, "start": [1, 0]}),
                libc::SIGKILL,
            )
            .expect_err("a recycled PID must be refused");
            assert!(refused.contains("PID reuse"), "{refused}");
            assert!(
                egress_fixtures::process_identity(pid)
                    .map_err(|error| error.to_string())?
                    .is_some(),
                "a refused signal must not have reached the process"
            );
            // The identity that *is* recorded may be signalled, which is what
            // makes the refusal above about the token and not about signalling.
            egress_fixtures::signal_identity(&json!({"pid": pid, "start": start}), libc::SIGKILL)?;
            // A signal is delivered asynchronously: give the process a bounded
            // moment to become absent before reading it as "not signalled".
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline
                && egress_fixtures::process_identity(pid)
                    .map_err(|error| error.to_string())?
                    .is_some()
            {
                std::thread::sleep(Duration::from_millis(20));
            }
            assert!(
                egress_fixtures::process_identity(pid)
                    .map_err(|error| error.to_string())?
                    .is_none(),
                "the identity-checked signal lands"
            );
            // A real directory outside the root, so the refusal is about
            // containment and not about the path being absent.
            let unowned = work.parent().expect("a parent").join(format!(
                "{}-unowned",
                work.file_name().expect("a name").to_string_lossy()
            ));
            fs::create_dir_all(&unowned).map_err(|error| error.to_string())?;
            let outside = egress_launch::within(&unowned, work)
                .expect_err("a path outside the work root is refused");
            assert!(outside.contains("outside owned root"), "{outside}");
            fs::remove_dir_all(&unowned).map_err(|error| error.to_string())?;
            Ok(())
        })();
        let _ = idle.kill();
        let _ = idle.wait();
        outcome
    })
}

// --- 14. A wedged list and a failed remove ---------------------------------

fn a_wedged_admin_call_cannot_outlive_the_cleanup_deadline() -> Result<(), String> {
    for fault in ["wedge-list", "fail-remove"] {
        control("wedge", |work| {
            let fake = fake_candidate(work)?;
            let root = work.join("state/msb-home");
            let owned = egress_launch::OwnedLaunch::new(
                work,
                &launch_command(work, &fake),
                "wedge".to_owned(),
            )?;
            let outcome = (|| -> Result<(), String> {
                run_until_timeout(work, &owned, &root)?;
                fs::write(root.join(fault), "").map_err(|error| error.to_string())?;
                let start = Instant::now();
                let errors = owned.cleanup(Some(start + Duration::from_secs(3)));
                assert!(!errors.is_empty(), "{fault}: the cleanup must report");
                assert!(
                    start.elapsed() < Duration::from_secs(4),
                    "{fault}: the cleanup took {:?}",
                    start.elapsed()
                );
                Ok(())
            })();
            // Keep teardown safe even when the intentionally wedged cleanup could
            // not finish: signal what the launch owned, then clear the rows.
            for identity in owned.alive().unwrap_or_default() {
                let _ = egress_fixtures::signal_identity(&identity, libc::SIGKILL);
            }
            let _ = fs::remove_file(root.join(fault));
            if let Ok(database) = rusqlite::Connection::open(root.join("db/msb.db")) {
                let _ = database.execute_batch("DELETE FROM sandbox; DELETE FROM \"run\";");
            }
            let _ = owned.cleanup(Some(Instant::now() + Duration::from_secs(30)));
            outcome
        })?;
    }
    Ok(())
}

// --- 15. Two launch cleanups and the run inventory -------------------------

fn a_fixture_survives_two_launch_cleanups_and_the_inventory_is_run_wide() -> Result<(), String> {
    control("inventory", |work| {
        let fake = fake_candidate(work)?;
        let root = work.join("state/msb-home");
        let mut fixture = Process::new(harness_binary()?)
            .args(["egress-supervisor", "--fake-idle", "600"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| error.to_string())?;
        let pid = fixture.id();
        let identity = json!({
            "pid": pid,
            "start": egress_fixtures::process_identity(pid).map_err(|error| error.to_string())?,
        });
        let outcome = (|| -> Result<(), String> {
            let mut launches = Vec::new();
            for index in 0..2 {
                let owned = egress_launch::OwnedLaunch::new(
                    work,
                    &recorder_command(work, &fake),
                    format!("success{index}"),
                )?;
                assert_eq!(owned.run()?, 0, "a recorder launch exits 0");
                assert_eq!(
                    owned.cleanup(None),
                    Vec::<String>::new(),
                    "a recorder launch leaves nothing"
                );
                assert!(
                    fixture
                        .try_wait()
                        .map_err(|error| error.to_string())?
                        .is_none(),
                    "the run-scoped fixture is not a launch's to reap"
                );
                launches.push(owned);
            }
            // An unexpected catalog object must fail and remain; never broad-killed.
            {
                let database = rusqlite::Connection::open(root.join("db/msb.db"))
                    .map_err(|error| error.to_string())?;
                database
                    .execute(
                        "INSERT INTO sandbox VALUES(99,'unowned','{}','Stopped')",
                        [],
                    )
                    .map_err(|error| error.to_string())?;
            }
            let errors = egress_run::cleanup_run(
                work,
                &fake,
                &launches,
                Some(egress_run::Fixture::adopt(fixture, identity.clone())),
            );
            assert!(
                errors.iter().any(|error| error.contains("unowned")),
                "{errors:?}"
            );
            assert!(
                egress_fixtures::process_identity(pid)
                    .map_err(|error| error.to_string())?
                    .is_none(),
                "the fixture cluster is reaped"
            );
            assert_eq!(
                msb_catalog::catalog_rows(&root)?
                    .first()
                    .map(|row| row.name.as_str()),
                Some("unowned"),
                "an unowned row is retained, not swept away"
            );
            Ok(())
        })();
        if let Ok(Some(_)) = egress_fixtures::process_identity(pid) {
            let _ = egress_fixtures::signal_identity(&identity, libc::SIGKILL);
        }
        let _ = fs::remove_file(root.join("fail-remove"));
        let _ = fs::remove_file(root.join("fail-force"));
        outcome
    })
}

// --- 16. The rejection diagnostics -----------------------------------------

fn the_rejection_diagnostics_are_specific() -> Result<(), String> {
    let messages = egress_run::RJ1_MESSAGES;
    for (variant, error) in messages {
        let diagnostic = format!("--allow-egress #1: {error}");
        assert!(
            egress_run::validation_rejected(1, &diagnostic, variant),
            "{variant}"
        );
        for status in [0, 124, 130, 143] {
            assert!(
                !egress_run::validation_rejected(status, &diagnostic, variant),
                "{variant}: {status}"
            );
        }
        let value = egress_run::RJ1_VALUES
            .iter()
            .find(|(name, _)| *name == variant)
            .map(|(_, value)| *value)
            .unwrap_or_default();
        let mut rejected: Vec<String> = vec![
            "unrelated egress failure".to_owned(),
            "clap: --allow-egress missing argument".to_owned(),
            diagnostic.replace("#1", "#2"),
            format!("{diagnostic} CASE RJ1 BEGIN"),
        ];
        if !error.contains(value) {
            rejected.push(format!("{diagnostic} {value}"));
        }
        rejected.extend(
            messages
                .iter()
                .filter(|(_, other)| *other != error)
                .map(|(_, other)| format!("--allow-egress #1: {other}")),
        );
        for text in rejected {
            assert!(
                !egress_run::validation_rejected(1, &text, variant),
                "{variant}: {text}"
            );
        }
    }
    let diagnostic = ".agent-vm.runtime.sh failed (exit 7)";
    assert!(egress_run::strict_hook_rejected(diagnostic));
    for text in [
        "127.0.0.1",
        "id=7",
        ".agent-vm.runtime.sh failed (exit 2)",
        ".agent-vm.runtime.sh failed (exit 7) CASE HK2 BEGIN",
    ] {
        assert!(
            !egress_run::strict_hook_rejected(text),
            "the strict hook must refuse before the tool runs: {text}"
        );
    }
    Ok(())
}

// --- 17. The validation snapshot and the SQLite sidecars -------------------

fn a_validation_snapshot_ignores_the_sqlite_sidecars() -> Result<(), String> {
    control("snapshot", |work| {
        // A read-only catalog observation (and SQLite itself) rewrites the
        // -shm/-wal sidecars whenever a connection attaches; those bytes are not
        // launch state and must not fail the validation-only mutation oracle.
        let directory = work.join("state/msb-home/db");
        fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
        let sidecars = [
            directory.join("msb.db-shm"),
            directory.join("msb.db-wal"),
            directory.join("msb.db-journal"),
        ];
        for path in &sidecars {
            fs::write(path, b"initial").map_err(|error| error.to_string())?;
        }
        let secrets = work.join("state/abc.secrets/token");
        fs::create_dir_all(secrets.parent().expect("a parent"))
            .map_err(|error| error.to_string())?;
        fs::write(&secrets, b"secret").map_err(|error| error.to_string())?;
        let before = egress_witness::snapshot_validation(work)?;
        for path in &sidecars {
            fs::write(path, b"rewritten sidecar payload").map_err(|error| error.to_string())?;
        }
        assert_eq!(
            before,
            egress_witness::snapshot_validation(work)?,
            "sidecar bytes are not launch state"
        );
        fs::write(&secrets, b"secret changed").map_err(|error| error.to_string())?;
        assert_ne!(
            before,
            egress_witness::snapshot_validation(work)?,
            "a changed secret is a change"
        );
        Ok(())
    })
}

// --- 18. Binding without the resolver --------------------------------------

fn the_fixture_binds_without_the_resolver() -> Result<(), String> {
    control("resolver", |work| {
        // `http.server.HTTPServer.server_bind` filled `server_name` from
        // `socket.getfqdn(host)`, which blocked for 30 s on a host whose resolver
        // stalls on `0.0.0.0` -- against the 5 s `serve` allows its listeners.
        // Rust has no such lookup to poison, so the property is graded twice: the
        // bind path may only name literal addresses (a source oracle), and the
        // whole `serve` role must publish readiness well inside its own bound.
        let fixture = source("crates/harness/src/egress_fixtures.rs")?;
        assert!(
            fixture.contains("SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)"),
            "the TCP listener binds a literal address"
        );
        assert!(
            fixture.contains("UdpSocket::bind((\"0.0.0.0\", port))"),
            "the UDP socket binds a literal address"
        );
        let bind_path = fixture
            .split_once("pub fn bind(directory: &Path, ephemeral: bool)")
            .map(|(_, rest)| rest)
            .expect("the bind path");
        let bind_path = bind_path
            .split_once("pub fn ports(&self)")
            .map(|(head, _)| head)
            .expect("the ports accessor follows the bind path");
        for forbidden in ["to_socket_addrs", "getaddrinfo", "getfqdn", "LookupHost"] {
            assert!(
                !bind_path.contains(forbidden),
                "binding must not consult the resolver: {forbidden}"
            );
        }
        let directory = work.join("fx-resolver");
        let log_path = work.join("fixture-resolver.log");
        let mut command = Process::new(harness_binary()?);
        command
            .args([
                "egress-fixtures".to_owned(),
                "serve".to_owned(),
                "--dir".to_owned(),
                directory.to_string_lossy().into_owned(),
                "--ephemeral-ports".to_owned(),
            ])
            .current_dir(work);
        let mut served = spawn_logged(command, &log_path)?;
        let outcome = (|| -> Result<(), String> {
            // Shorter than the 5 s the fixture allows itself: the claim is that
            // binding does not wait on a resolver at all, not that it wins a race.
            let deadline = Instant::now() + Duration::from_secs(3);
            while !directory.join("ready").exists() {
                if !served.running()? || Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            assert!(
                directory.join("ready").exists(),
                "`serve` did not become ready in 3 s: {}",
                served.text()
            );
            let ports = recorded(&directory.join("ports.json"))?;
            assert_eq!(ports["tcp"].as_array().map(Vec::len), Some(2));
            assert_eq!(ports["udp"].as_array().map(Vec::len), Some(2));
            assert!(served.running()?, "{}", served.text());
            Ok(())
        })();
        let pid = served.child.id();
        let identity = json!({
            "pid": pid,
            "start": egress_fixtures::process_identity(pid).unwrap_or_default(),
        });
        let _ = egress_fixtures::signal_identity(&identity, libc::SIGTERM);
        let status = served.wait(Duration::from_secs(10))?;
        assert_eq!(
            status,
            0,
            "{}",
            fs::read_to_string(&log_path).unwrap_or_default()
        );
        outcome
    })
}

// --- 19. The host fixture health and the ingress driver --------------------

fn the_host_fixture_health_and_ingress_driver_work() -> Result<(), String> {
    control("fixture", |work| {
        let fake = fake_candidate(work)?;
        let harness = harness_text()?;
        let directory = work.join("fx");
        let mut command = cases::fixture_command(work);
        command.argv[0] = harness.clone();
        command.argv.push("--ephemeral-ports".to_owned());
        let log_path = work.join("fixture.log");
        let mut fixture_command = Process::new(&command.argv[0]);
        fixture_command
            .args(&command.argv[1..])
            .current_dir(&command.cwd)
            .env_clear()
            .envs(command.env.clone());
        let mut fixture = spawn_child_logged(fixture_command, &log_path)?;
        let pid = fixture.id();
        let identity = json!({
            "pid": pid,
            "start": egress_fixtures::process_identity(pid).map_err(|error| error.to_string())?,
        });
        let outcome = (|| -> Result<(), String> {
            let deadline = Instant::now() + Duration::from_secs(5);
            while !directory.join("ready").exists() {
                let died = fixture
                    .try_wait()
                    .map_err(|error| error.to_string())?
                    .is_some();
                if died || Instant::now() >= deadline {
                    return Err("host-only fixture failed to bind owned ports".to_owned());
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let mut health = cases::health_command(work);
            health.argv[0] = harness.clone();
            assert_eq!(
                cases::run_admin(work, &health, None)?.0,
                0,
                "every listener answers and records"
            );
            let ports = recorded(&directory.join("ports.json"))?;
            let receipts = fs::read_to_string(directory.join("receipts.log")).unwrap_or_default();
            for protocol in ["tcp", "udp"] {
                let ports = ports[protocol].as_array().expect("a port list");
                assert_eq!(ports.len(), 2, "{protocol}");
                for port in ports {
                    let port = port.as_u64().expect("a port");
                    assert!(port > 0, "{protocol}");
                    assert!(
                        receipts
                            .lines()
                            .any(|line| line.starts_with(&format!("{protocol} {port} "))),
                        "{protocol} {port}: no receipt"
                    );
                }
            }
            assert!(
                fixture
                    .try_wait()
                    .map_err(|error| error.to_string())?
                    .is_none(),
                "{}",
                fs::read_to_string(&log_path).unwrap_or_default()
            );
            assert_eq!(
                egress_run::cleanup_run(
                    work,
                    &fake,
                    &[],
                    Some(egress_run::Fixture::adopt(fixture, identity.clone())),
                ),
                Vec::<String>::new()
            );
            assert_eq!(
                cases::run_admin(work, &health, None)?.0,
                1,
                "a reaped fixture no longer answers"
            );
            Ok(())
        })();
        if let Ok(Some(_)) = egress_fixtures::process_identity(pid) {
            let _ = egress_fixtures::signal_identity(&identity, libc::SIGKILL);
        }
        outcome?;
        // The ingress driver: the published port's body is the case id, and
        // anything else is a failure of the driver's own join.
        for (body, expected) in [
            (b"ingress ingress-test".to_vec(), 0),
            (b"wrong body".to_vec(), 1),
        ] {
            let server =
                std::net::TcpListener::bind(("127.0.0.1", 0)).map_err(|error| error.to_string())?;
            server
                .set_nonblocking(false)
                .map_err(|error| error.to_string())?;
            let port = server
                .local_addr()
                .map_err(|error| error.to_string())?
                .port();
            let peer = {
                let body = body.clone();
                std::thread::spawn(move || {
                    use std::io::{Read, Write};
                    if let Ok((mut connection, _)) = server.accept() {
                        let _ = connection.set_read_timeout(Some(Duration::from_secs(5)));
                        let mut buffer = [0u8; 4096];
                        let _ = connection.read(&mut buffer);
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            String::from_utf8_lossy(&body)
                        );
                        let _ = connection.write_all(response.as_bytes());
                    }
                })
            };
            fs::write(
                work.join("ingress-test.log"),
                "INGRESS_READY ingress-test 8000\n",
            )
            .map_err(|error| error.to_string())?;
            assert_eq!(
                cases::ingress_driver(work, "IN1", "ingress-test", Some(port))?,
                expected,
                "{}",
                String::from_utf8_lossy(&body)
            );
            let deadline = Instant::now() + JOIN_BOUND;
            while !peer.is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
            assert!(peer.is_finished(), "the peer is joined within its bound");
            peer.join().expect("the peer thread");
        }
        Ok(())
    })
}

// --- 20. An interrupted CLI outside its cwd --------------------------------

fn an_interrupted_launch_cleans_up_from_an_unrelated_cwd() -> Result<(), String> {
    control("interrupt", |work| {
        let fake = fake_candidate(work)?;
        for (signal, expected) in [(libc::SIGINT, 130), (libc::SIGTERM, 143)] {
            let log_path = work.join(format!("wrapper-{signal}.log"));
            let mut command = Process::new(harness_binary()?);
            command
                .args([
                    "egress-fixtures".to_owned(),
                    "launch".to_owned(),
                    "--work".to_owned(),
                    work.to_string_lossy().into_owned(),
                    "--case".to_owned(),
                    "CL1".to_owned(),
                    "--timeout".to_owned(),
                    "10".to_owned(),
                    "--grace".to_owned(),
                    "0.1".to_owned(),
                    "--".to_owned(),
                    fake.clone(),
                    "egressprobe".to_owned(),
                ])
                // An unrelated cwd must still reach every owning command.
                .current_dir("/");
            let mut wrapper = spawn_logged(command, &log_path)?;
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                let readable = fs::read_dir(work)
                    .map(|entries| {
                        entries
                            .filter_map(Result::ok)
                            .map(|entry| entry.path())
                            .filter(|path| {
                                path.file_name()
                                    .is_some_and(|name| name.to_string_lossy().starts_with("CL1-"))
                                    && path.extension().is_some_and(|ext| ext == "log")
                            })
                            .any(|path| {
                                fs::read_to_string(&path)
                                    .unwrap_or_default()
                                    .contains("CASE CL1 BEGIN")
                            })
                    })
                    .unwrap_or(false);
                if readable {
                    break;
                }
                if !wrapper.running()? || Instant::now() >= deadline {
                    return Err(format!(
                        "the fake guest never became ready: {}",
                        wrapper.text()
                    ));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let pid = wrapper.child.id();
            // SAFETY: the child this control just started, not reaped yet.
            unsafe { libc::kill(pid as i32, signal) };
            let status = wrapper.wait(Duration::from_secs(20))?;
            assert_eq!(
                status,
                expected,
                "{signal}: {}",
                fs::read_to_string(&log_path).unwrap_or_default()
            );
            assert!(msb_catalog::catalog_rows(&work.join("state/msb-home"))?.is_empty());
            assert_attached_disappeared(work);
            let receipts = receipt_rows(work);
            let cleanup = receipts
                .iter()
                .rfind(|row| row["phase"] == "cleanup")
                .expect("a cleanup receipt");
            assert_eq!(cleanup["primary_status"], json!(expected));
            assert!(
                cleanup["cleanup_errors"]
                    .as_array()
                    .is_some_and(|errors| !errors.is_empty()),
                "{cleanup}"
            );
            for path in cleanup["sockets"].as_array().expect("sockets") {
                let path = Path::new(path.as_str().expect("a path"));
                assert!(!path.exists(), "owned socket left: {}", path.display());
            }
            for identity in cleanup["runtimes"].as_array().expect("runtimes") {
                let pid = identity["pid"].as_u64().expect("a pid");
                let pid = u32::try_from(pid).map_err(|error| error.to_string())?;
                assert!(
                    egress_fixtures::process_identity(pid)
                        .map_err(|error| error.to_string())?
                        .is_none(),
                    "runtime {pid} survived"
                );
            }
            for entry in fs::read_dir(work).map_err(|error| error.to_string())? {
                let path = entry.map_err(|error| error.to_string())?.path();
                if path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with("CL1-"))
                    && path.extension().is_some_and(|ext| ext == "log")
                {
                    let _ = fs::remove_file(path);
                }
            }
            if let Ok(database) = rusqlite::Connection::open(work.join("state/msb-home/db/msb.db"))
            {
                let _ = database.execute("DELETE FROM \"run\"", []);
            }
        }
        Ok(())
    })
}

// --- The driver -------------------------------------------------------------

/// Every control, named and separately reported, in the order the Python suite
/// ran its methods. `only` narrows the run to the controls whose name contains
/// one of its strings, which is how the `cargo test` names below run one group in
/// a process of its own.
pub fn self_test(only: &[String]) -> Result<(), String> {
    type Control = (&'static str, fn() -> Result<(), String>);
    let controls: [Control; 20] = [
        (
            "the plan and the recorder agree",
            the_plan_and_the_recorder_agree,
        ),
        (
            "the allowance seed and restore lifecycle",
            the_allowance_seed_and_restore_lifecycle,
        ),
        (
            "the launcher runs the allowance lifecycle",
            the_launcher_runs_the_allowance_lifecycle,
        ),
        (
            "the live-allowance case lifecycle",
            the_live_allowance_case_lifecycle,
        ),
        (
            "the live-allowance verdict bites",
            the_live_allowance_verdict_bites,
        ),
        (
            "the required calibrations and their links",
            the_required_calibrations_and_links,
        ),
        (
            "missing attempts and reply markers fail",
            missing_attempts_and_reply_markers_fail,
        ),
        (
            "a timeout separates the launch from its cleanup",
            the_timeout_separates_the_launch_from_its_cleanup,
        ),
        (
            "a launch that never becomes ready is diagnosed",
            a_launch_that_never_becomes_ready_is_diagnosed,
        ),
        (
            "a failed force stop falls back to identities",
            a_failed_force_stop_falls_back_to_identities,
        ),
        (
            "the socket paths are the pinned layout",
            the_socket_paths_are_the_pinned_layout,
        ),
        (
            "an unmigrated catalog is not yet initialized",
            an_unmigrated_catalog_is_not_yet_initialized,
        ),
        (
            "a reused pid and an outside path are refused",
            a_reused_pid_and_an_outside_path_are_refused,
        ),
        (
            "a wedged admin call cannot outlive the cleanup deadline",
            a_wedged_admin_call_cannot_outlive_the_cleanup_deadline,
        ),
        (
            "a fixture survives two launch cleanups and the inventory is run-wide",
            a_fixture_survives_two_launch_cleanups_and_the_inventory_is_run_wide,
        ),
        (
            "the rejection diagnostics are specific",
            the_rejection_diagnostics_are_specific,
        ),
        (
            "a validation snapshot ignores the sqlite sidecars",
            a_validation_snapshot_ignores_the_sqlite_sidecars,
        ),
        (
            "the fixture binds without the resolver",
            the_fixture_binds_without_the_resolver,
        ),
        (
            "the host fixture health and ingress driver work",
            the_host_fixture_health_and_ingress_driver_work,
        ),
        (
            "an interrupted launch cleans up from an unrelated cwd",
            an_interrupted_launch_cleans_up_from_an_unrelated_cwd,
        ),
    ];
    let selected: Vec<Control> = controls
        .into_iter()
        .filter(|(name, _)| {
            only.is_empty() || only.iter().any(|wanted| name.contains(wanted.as_str()))
        })
        .collect();
    if selected.is_empty() {
        return Err(format!("usage: --only {only:?} matches no control"));
    }
    for (name, control) in selected {
        control()?;
        println!("ok: {name}");
    }
    Ok(())
}

pub fn run(args: EgressSupervisorArgs) -> Result<crate::Outcome, String> {
    if let Some(seconds) = args.fake_idle {
        return Ok(crate::Outcome::Exit(run_fake_idle(seconds)?));
    }
    if args.fake_candidate {
        return Ok(crate::Outcome::Exit(run_fake_candidate(&args.fake_argv)?));
    }
    if !args.self_test {
        return Err("usage: egress-supervisor --self-test".to_owned());
    }
    if let Some(root) = args.repo_root {
        set_repo_root(root)?;
    }
    self_test(&args.only)?;
    Ok(crate::Outcome::Report(
        "egress supervisor controls passed: the plan, the allowance lifecycle, the owned launch, its cleanup and the host drivers"
            .to_owned(),
    ))
}

#[derive(Debug, clap::Args)]
pub struct EgressSupervisorArgs {
    /// Run every control. Each one is also a `cargo test` name.
    #[arg(long)]
    self_test: bool,
    /// The fake candidate the launch controls drive; the checks' own wrapper
    /// calls it. Not an operator command.
    #[arg(long, hide = true)]
    fake_candidate: bool,
    /// The fake candidate's own argv, `argv[0]` first.
    #[arg(hide = true, trailing_var_arg = true, allow_hyphen_values = true)]
    fake_argv: Vec<OsString>,
    /// A child that ignores SIGTERM, for the launch controls. Not an operator
    /// command.
    #[arg(long, hide = true, value_name = "SECONDS")]
    fake_idle: Option<f64>,
    /// Run only the controls whose name contains this string. Repeatable.
    #[arg(long, value_name = "NAME")]
    only: Vec<String>,
    /// Repository root; `CARGO_MANIFEST_DIR/../..` when absent.
    #[arg(long, value_name = "PATH")]
    repo_root: Option<PathBuf>,
}

#[cfg(test)]
mod tests {
    //! Each group runs in a process of its own, through
    //! `harness egress-supervisor --self-test --only …`, rather than in this test
    //! binary. `PENDING_SIGNAL` (released_image_launch) is process-wide by
    //! design, so a launch in one thread sees a SIGTERM another thread raised for
    //! its own control; a supervisor check that shared this process with that
    //! control would read it as an interruption. The binary is single-threaded,
    //! which is also the shape the supervisor actually runs in.

    use super::*;

    fn run(names: &[&str]) {
        let mut arguments = vec!["egress-supervisor".to_owned(), "--self-test".to_owned()];
        for name in names {
            arguments.push("--only".to_owned());
            arguments.push((*name).to_owned());
        }
        let directory = std::env::temp_dir().join(format!(
            "harness-supervisor-test-{}-{}",
            std::process::id(),
            egress_fixtures::monotonic_nanos()
        ));
        fs::create_dir_all(&directory).expect("a scratch directory");
        let log = directory.join("self-test.log");
        let mut child = spawn_logged(
            {
                let mut command = Process::new(harness_binary().expect("the harness binary"));
                command.args(&arguments);
                command
            },
            &log,
        )
        .expect("the harness starts");
        let status = child.wait(CLI_BOUND * 4).expect("the controls finish");
        let text = child.text();
        let _ = fs::remove_dir_all(&directory);
        assert_eq!(status, 0, "{text}");
        for name in names {
            assert!(
                text.contains(&format!("ok: {name}")),
                "the control {name:?} did not report: {text}"
            );
        }
    }

    #[test]
    fn the_plan_and_the_recorder_are_one_inventory() {
        run(&["the plan and the recorder agree"]);
    }

    #[test]
    fn the_allowance_lifecycle_runs_at_its_call_sites() {
        run(&[
            "the allowance seed and restore lifecycle",
            "the launcher runs the allowance lifecycle",
            "the live-allowance case lifecycle",
            "the live-allowance verdict bites",
        ]);
    }

    #[test]
    fn the_case_table_keeps_its_calibrations_and_links() {
        run(&[
            "the required calibrations and their links",
            "missing attempts and reply markers fail",
        ]);
    }

    #[test]
    fn a_timed_out_launch_is_stopped_and_cleaned_up() {
        run(&[
            "a timeout separates the launch from its cleanup",
            "a launch that never becomes ready is diagnosed",
            "a failed force stop falls back to identities",
        ]);
    }

    #[test]
    fn a_wedged_cleanup_stays_inside_its_deadline() {
        run(&["a wedged admin call cannot outlive the cleanup deadline"]);
    }

    #[test]
    fn the_catalog_and_its_observer_agree_before_the_first_migration() {
        run(&[
            "the socket paths are the pinned layout",
            "an unmigrated catalog is not yet initialized",
            "a reused pid and an outside path are refused",
        ]);
    }

    #[test]
    fn a_run_scoped_fixture_outlives_its_launches() {
        run(&["a fixture survives two launch cleanups and the inventory is run-wide"]);
    }

    #[test]
    fn the_rejections_and_the_snapshot_keep_their_edges() {
        run(&[
            "the rejection diagnostics are specific",
            "a validation snapshot ignores the sqlite sidecars",
        ]);
    }

    #[test]
    fn the_host_drivers_bind_serve_and_drive_ingress() {
        run(&[
            "the fixture binds without the resolver",
            "the host fixture health and ingress driver work",
        ]);
    }

    #[test]
    fn an_interrupted_launch_is_cleaned_up() {
        run(&["an interrupted launch cleans up from an unrelated cwd"]);
    }

    #[test]
    fn an_unknown_control_name_is_misuse() {
        let refused = self_test(&["no such control".to_owned()])
            .expect_err("an unmatched --only must not read as a pass");
        assert!(refused.contains("matches no control"), "{refused}");
    }
}
