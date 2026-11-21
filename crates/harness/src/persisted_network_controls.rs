//! Host-only controls for the persisted-network suite (#696).
//!
//! Ported from `script/test/lib/persisted-network-contract.py`. The name avoids
//! "contract" on purpose: `CONTEXT.md` reserves that word for Verus boundary
//! contracts, and these are controls — host-only evidence, never native
//! enforcement or guest-authorship evidence.
//!
//! Three groups, each with its own scratch directory:
//!
//! * `probe` — the guest probe and write fixtures really do reach, deny and
//!   append what the rows claim, and the inventory snapshot has the semantics
//!   the rows' refusals depend on.
//! * `helper` — the shell helper's `awk` oracle and this crate's parser render
//!   the tracked fixture identically; `pn_launch` keeps the trapped PID equal to
//!   the driver's; every bounded wait and teardown seam reports and reaps a
//!   fixture that exits early, hangs or ignores TERM.
//! * `live-shell` — the live shell's provenance gate, its signal traps and its
//!   scratch ownership, including the races (publication, pre-handoff,
//!   unresolved ownership, failure before ownership capture) each control makes
//!   deterministic with a gate file.
//!
//! The stub driver is a shell script this crate writes, and the stub `harness`
//! dispatches `build-provenance` to the real binary and `persisted-network` to
//! that script with `exec`, so the trapped PID is the fixture's PID. Every wait,
//! socket read, accept and join is bounded: an unbounded wait here wedges the
//! gate rather than reporting it.

use std::{
    cell::Cell,
    fs,
    io::Read,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use clap::Args;

use crate::{egress_cases as cases, egress_fixtures as fixtures, persisted_network as pn};

/// Operational budgets shared by every control that waits on or tears down an
/// owned fixture. One place, so retuning the readiness deadline cannot leave a
/// teardown spelling a stale value.
const READINESS: Duration = Duration::from_secs(15);
const TEARDOWN: Duration = Duration::from_secs(15);
const POLL: Duration = Duration::from_millis(10);
/// A live shell run's own bound: it starts a VM-free driver, so it is quick, but
/// a wedged provenance gate must not hang the suite.
const LIVE_RUN: Duration = Duration::from_secs(180);
/// The one success line the live shell's provenance gate prints.
const PROVENANCE_OK: &str = "provenance: clean binary matches source HEAD";
const NO_ENV: &[(String, String)] = &[];
const NO_UNSET: &[&str] = &[];

#[derive(Debug, Args)]
pub struct PersistedNetworkControlsArgs {
    /// The checkout under test: its `script/test` tree is the subject.
    #[arg(long)]
    repo_root: PathBuf,

    /// Run only one group: probe, helper or live-shell.
    #[arg(long)]
    only: Option<String>,
}

pub fn run(args: PersistedNetworkControlsArgs) -> Result<String, String> {
    let repo = args.repo_root.canonicalize().map_err(|error| {
        format!(
            "{}: {error} (pass --repo-root with the checkout under test)",
            args.repo_root.display()
        )
    })?;
    let work = scratch("pn-controls")?;
    let mut result = Ok(());
    for group in ["probe", "helper", "live-shell"] {
        if args.only.as_deref().is_some_and(|only| only != group) {
            continue;
        }
        let directory = work.join(group);
        fs::create_dir_all(&directory)
            .map_err(|error| format!("{}: {error}", directory.display()))?;
        result = match group {
            "probe" => probe_controls(&repo, &directory),
            "helper" => helper_controls(&repo, &directory),
            _ => live_shell_controls(&repo, &directory),
        };
        if result.is_err() {
            break;
        }
    }
    if result.is_err() {
        // Keep the scratch: a failed control's fixtures are its evidence.
        eprintln!("controls scratch retained: {}", work.display());
    } else {
        let _ = fs::remove_dir_all(&work);
    }
    result?;
    Ok("persisted network host-only controls PASS".to_owned())
}

fn scratch(prefix: &str) -> Result<PathBuf, String> {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or_default();
    let path = std::env::temp_dir().join(format!("{prefix}-{}-{unique}", std::process::id()));
    fs::create_dir_all(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    // The scratch holds fixtures the controls own; a symlinked parent would let
    // a control delete outside it, so resolve once and use the real path.
    path.canonicalize()
        .map_err(|error| format!("{}: {error}", path.display()))
}

// --- Files, processes and signals -------------------------------------------

fn write_script(path: &Path, body: &str) -> Result<(), String> {
    fs::write(path, body).map_err(|error| format!("{}: {error}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .map_err(|error| format!("{}: {error}", path.display()))
}

fn copy_tree(from: &Path, to: &Path) -> Result<(), String> {
    fs::create_dir_all(to).map_err(|error| format!("{}: {error}", to.display()))?;
    let entries = fs::read_dir(from).map_err(|error| format!("{}: {error}", from.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("{}: {error}", from.display()))?;
        let source = entry.path();
        let destination = to.join(entry.file_name());
        if entry.file_name() == "__pycache__" {
            continue;
        }
        if entry
            .file_type()
            .map_err(|error| format!("{}: {error}", source.display()))?
            .is_dir()
        {
            copy_tree(&source, &destination)?;
        } else {
            fs::copy(&source, &destination)
                .map_err(|error| format!("{}: {error}", destination.display()))?;
        }
    }
    Ok(())
}

fn read_pid(path: &Path) -> Option<i32> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Liveness of a PID this test measured. A reaped PID reports not alive.
fn pid_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    // `kill(pid, 0)` is the only portable question: success or EPERM both mean
    // the PID exists, and ESRCH means it does not.
    let result = unsafe { libc::kill(pid, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn signal_owned(pid: i32, signal: i32) {
    if pid > 0 {
        // A dead PID is a race, not a teardown error.
        unsafe { libc::kill(pid, signal) };
    }
}

/// Whether a fixture this control launched is still alive.
fn owned_alive(child: &mut Child, pid: i32) -> bool {
    if u32::try_from(pid).ok() == Some(child.id()) {
        child
            .try_wait()
            .map(|status| status.is_none())
            .unwrap_or(false)
    } else {
        pid_alive(pid)
    }
}

/// Every scratch path the stub `mktemp` recorded, in allocation order.
fn allocations(events: &Path) -> Vec<PathBuf> {
    fs::read_to_string(events)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.strip_prefix("allocated "))
        .map(PathBuf::from)
        .collect()
}

struct Run {
    status: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Run a command with piped output, bounded.
///
/// Only for commands with no grandchildren: a surviving descendant that holds
/// the pipe would make draining it an unbounded wait, which is why every
/// live-shell run below sends its output to files instead.
fn run_bounded(
    argv: &[String],
    cwd: &Path,
    env: &[(String, String)],
    unset: &[&str],
    bound: Duration,
) -> Result<Run, String> {
    let mut command = Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in env {
        command.env(name, value);
    }
    for name in unset {
        command.env_remove(name);
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("{}: {error}", argv[0]))?;
    let mut stdout = child.stdout.take().expect("a piped stdout");
    let mut stderr = child.stderr.take().expect("a piped stderr");
    let out = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = stdout.read_to_end(&mut buffer);
        buffer
    });
    let err = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = stderr.read_to_end(&mut buffer);
        buffer
    });
    let deadline = Instant::now() + bound;
    let status;
    loop {
        match child.try_wait() {
            Ok(Some(exit)) => {
                status = exit.code();
                break;
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL),
            Ok(None) => {
                // A helper command that cannot finish inside its bound is a
                // failure, not an inconclusive status a control might read as a
                // refusal.
                let _ = child.kill();
                let _ = child.wait();
                let _ = out.join();
                let _ = err.join();
                return Err(format!("{}: no exit within {bound:?}", argv[0]));
            }
            Err(error) => return Err(format!("{}: {error}", argv[0])),
        }
    }
    Ok(Run {
        status,
        stdout: out.join().unwrap_or_default(),
        stderr: err.join().unwrap_or_default(),
    })
}

/// Start a command with its output in files, so a live descendant cannot hold a
/// pipe the control is draining.
fn spawn_to_files(
    argv: &[String],
    cwd: &Path,
    env: &[(String, String)],
    unset: &[&str],
    stdout: &Path,
    stderr: &Path,
) -> Result<Child, String> {
    let out = fs::File::create(stdout).map_err(|error| format!("{}: {error}", stdout.display()))?;
    let err = fs::File::create(stderr).map_err(|error| format!("{}: {error}", stderr.display()))?;
    let mut command = Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err));
    for (name, value) in env {
        command.env(name, value);
    }
    for name in unset {
        command.env_remove(name);
    }
    command
        .spawn()
        .map_err(|error| format!("{}: {error}", argv[0]))
}

/// Poll for a child's exit up to `bound`; `None` means it is still running.
fn wait_bounded(child: &mut Child, bound: Duration) -> Option<i32> {
    let deadline = Instant::now() + bound;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status.code().unwrap_or(-1)),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL),
            _ => return None,
        }
    }
}

/// Read a fixture's startup PID, published before readiness; `None` if unwritten.
fn read_owned_pid(path: &Path) -> Option<i32> {
    read_pid(path)
}

/// Read the driver PID the live shell records beside the scratch it hands over.
fn read_launch_pid(root: &Path) -> Option<i32> {
    read_owned_pid(&root.join("driver.pid"))
}

/// Wait for a fixture's readiness publication, bounded, and say why it failed.
///
/// The order is deliberate: a fixture that exited is reported as such, and only
/// a live fixture can be reported as a timeout.
fn wait_ready(child: &mut Child, ready: &Path) -> Result<(), String> {
    let deadline = Instant::now() + READINESS;
    loop {
        if ready.exists() {
            return Ok(());
        }
        match child.try_wait() {
            Ok(None) => {}
            _ => return Err("signal fixture exited before readiness".to_owned()),
        }
        if Instant::now() >= deadline {
            return Err("signal fixture readiness timeout".to_owned());
        }
        std::thread::sleep(POLL);
    }
}

/// The single seam through which this harness deletes owned scratch.
///
/// Removing owned scratch is only safe once the driver it was allocated for has
/// been established absent (and, for a live-shell control, the shell too). Every
/// removal path routes through here so that invariant has one home: unknown
/// ownership is not absence, and the scratch is retained as evidence instead.
/// `empty_only` reclaims with `remove_dir`, so a regression that left driver
/// state behind keeps failing loudly instead of being erased.
fn discard_owned_scratch(
    paths: &[PathBuf],
    driver_established_absent: bool,
    shell_established_absent: bool,
    empty_only: bool,
) -> Result<(), String> {
    if !(driver_established_absent && shell_established_absent) {
        return Err(format!(
            "refusing to remove owned scratch while ownership is unresolved; retained as evidence: {paths:?}"
        ));
    }
    let mut errors = Vec::new();
    for path in paths {
        if !path.is_dir() {
            continue;
        }
        let result = if empty_only {
            fs::remove_dir(path)
        } else {
            fs::remove_dir_all(path)
        };
        if let Err(error) = result {
            errors.push(format!("{}: {error}", path.display()));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// Bounded TERM -> KILL teardown of exactly the fixture this control launched.
///
/// Signalling only the owned child and the measured PID keeps unrelated
/// processes out of reach. Timeouts never raise, so cleanup cannot mask an
/// assertion already in flight; any PID still alive after the KILL grace is
/// returned so the caller can fail loudly instead of logging a survivor.
fn reap_owned_fixture(child: &mut Child, measured: Option<i32>) -> Vec<i32> {
    let owned = child.id() as i32;
    let mut pids = vec![owned];
    if let Some(measured) = measured
        && measured != owned
    {
        pids.push(measured);
    }
    for pid in &pids {
        if owned_alive(child, *pid) {
            signal_owned(*pid, libc::SIGTERM);
        }
    }
    await_owned_absent(child, measured, Instant::now() + TEARDOWN);
    for pid in &pids {
        if owned_alive(child, *pid) {
            signal_owned(*pid, libc::SIGKILL);
        }
    }
    await_owned_absent(child, measured, Instant::now() + TEARDOWN);
    pids.into_iter()
        .filter(|pid| owned_alive(child, *pid))
        .collect()
}

fn await_owned_absent(child: &mut Child, measured: Option<i32>, deadline: Instant) {
    if child
        .try_wait()
        .map(|status| status.is_none())
        .unwrap_or(false)
    {
        loop {
            if child.try_wait().ok().flatten().is_some() || Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(POLL);
        }
    }
    if let Some(measured) = measured
        && u32::try_from(measured).ok() != Some(child.id())
    {
        while pid_alive(measured) && Instant::now() < deadline {
            std::thread::sleep(POLL);
        }
    }
}

// --- Stub programs ----------------------------------------------------------

/// The stub `harness` a live-shell control puts on `HARNESS_BIN_DIR`.
///
/// `build-provenance` must be the real binary: the gate under test is the real
/// parser. `persisted-network` is the fixture, `exec`ed so the PID the shell
/// traps is the fixture's own PID — which is also what the no-exec control in
/// the helper group proves.
fn harness_stub() -> String {
    r#"#!/bin/sh
case "${1:-}" in
  build-provenance) exec "$REAL_HARNESS" "$@" ;;
  persisted-network)
    shift
    # The fixture owns the driver's own flag, so the rest of argv is the row's.
    if [ "${1:-}" = "--repo-root" ]; then shift 2; fi
    if [ "${PN_FAIL_STARTUP:-}" = 1 ]; then
      echo "persisted-network driver startup failed" >&2
      exit 29
    fi
    if [ -z "${PN_STUB_PROGRAM:-}" ]; then
      echo "stub harness: PN_STUB_PROGRAM is unset" >&2
      exit 64
    fi
    exec "$PN_STUB_PROGRAM" "$@"
    ;;
  *)
    echo "stub harness: unexpected subcommand ${1:-}" >&2
    exit 64
    ;;
esac
"#
    .to_owned()
}

/// A driver that starts, checks its receipt, reaps its scratch and exits.
fn driver_stub() -> String {
    format!(
        r#"#!/bin/sh
events="$PN_EVENTS"
note() {{ printf '%s\n' "$1" >> "$events"; }}
note driver
if [ ! -d "$1" ]; then echo "scratch missing" >&2; exit 65; fi
receipt=''
if [ -f "$AGENT_VM_PN_EVIDENCE/provenance-check.txt" ]; then
  receipt="$(cat "$AGENT_VM_PN_EVIDENCE/provenance-check.txt")"
fi
case "$receipt" in
  *"{PROVENANCE_OK}"*) ;;
  *) echo "receipt must precede scratch" >&2; exit 65 ;;
esac
if [ "${{STUB_CLEANUP_FAIL:-}}" = 1 ]; then
  note cleanup-failed
  exit 24
fi
rm -rf "$1"
note cleanup
exit "${{STUB_EXIT:-0}}"
"#
    )
}

/// The signal fixture: publishes its PID after installing its TERM handling,
/// optionally publishes readiness, optionally waits for a gate first, and either
/// cooperates with TERM or ignores it outright.
fn signal_stub() -> String {
    r#"#!/bin/sh
root="$1"
on_term() {
  printf '%s' "$$" > "$PN_TERM"
  if [ "${PN_REMOVE_SCRATCH:-}" = 1 ]; then rm -rf "$root"; fi
  exit 143
}
if [ "${PN_STUB_IGNORE_TERM:-}" = 1 ]; then
  trap '' TERM
else
  trap on_term TERM
fi
# Publication happens *after* registration, so an observed PID proves the
# handler (or SIG_IGN) is already installed.
if [ -n "${PN_PID:-}" ]; then
  if [ -n "${PN_STUB_GATE:-}" ]; then
    while [ ! -e "$PN_STUB_GATE" ]; do sleep 0.01; done
  fi
  printf '%s' "$$" > "$PN_PID"
fi
if [ "${PN_STUB_NO_READY:-}" != 1 ]; then
  printf '%s' "$$" > "$PN_READY.pending"
  mv "$PN_READY.pending" "$PN_READY"
fi
while :; do sleep 0.01; done
"#
    .to_owned()
}

// --- Group: probe -----------------------------------------------------------

fn probe_controls(repo: &Path, work: &Path) -> Result<(), String> {
    let fixtures = repo.join("script/test/fixtures");

    // The rows' refusals compare against this snapshot, so its semantics are
    // control material: sidecars skipped, a symlink recorded by target, a large
    // image hashed in blocks, and a change in any of them observed.
    let inventory = work.join("inventory");
    for root in ["home", "config", "proj"] {
        fs::create_dir_all(inventory.join(root))
            .map_err(|error| format!("{}: {error}", inventory.display()))?;
    }
    fs::create_dir_all(inventory.join("state/msb-home"))
        .map_err(|error| format!("{}: {error}", inventory.display()))?;
    fs::write(inventory.join("state/image"), vec![b'x'; 2 * 1024 * 1024])
        .map_err(|error| format!("{}: {error}", inventory.display()))?;
    std::os::unix::fs::symlink("image", inventory.join("state/link"))
        .map_err(|error| format!("{}: {error}", inventory.display()))?;
    fs::write(inventory.join("state/db-wal"), b"sidecar")
        .map_err(|error| format!("{}: {error}", inventory.display()))?;
    let snapshot = pn::snapshot_validation(&inventory)?;
    if snapshot != crate::egress_witness::snapshot_validation(&inventory)? {
        return Err("probe: the row snapshot and the witness snapshot disagree".to_owned());
    }
    if snapshot.keys().any(|name| name.ends_with("-wal")) {
        return Err("probe: a SQLite sidecar was inventoried".to_owned());
    }
    if snapshot.get("state/link").map(|entry| entry.2.as_str()) != Some("image") {
        return Err("probe: a symlink was not recorded by target".to_owned());
    }
    if snapshot.get("state/image").map(|entry| entry.1) != Some(2 * 1024 * 1024) {
        return Err("probe: the large image was not inventoried".to_owned());
    }
    let mut handle = fs::OpenOptions::new()
        .append(true)
        .open(inventory.join("state/image"))
        .map_err(|error| error.to_string())?;
    std::io::Write::write_all(&mut handle, b"changed").map_err(|error| error.to_string())?;
    drop(handle);
    if pn::snapshot_validation(&inventory)? == snapshot {
        return Err("probe: a changed image was not observed".to_owned());
    }
    println!("probe snapshot PASS: sidecars skipped, symlinks by target, change observed");

    // The write fixture appends exactly the persisted grant, byte for byte.
    fs::create_dir_all(work.join("dotfiles")).map_err(|error| error.to_string())?;
    let target = work.join("dotfiles/agent-vm.toml");
    fs::write(&target, b"# stand-in\n").map_err(|error| error.to_string())?;
    for source in [
        fixtures.join("persisted-network/guest-pn4-write.sh"),
        fixtures.join("persisted-network/guest-pn-probe.sh"),
        fixtures.join("egress-probe.sh"),
    ] {
        let name = source.file_name().expect("a fixture name");
        let destination = work.join(name);
        fs::copy(&source, &destination)
            .map_err(|error| format!("{}: {error}", destination.display()))?;
    }
    let probe =
        |argv: &[String]| run_bounded(argv, work, NO_ENV, NO_UNSET, Duration::from_secs(10));
    let result = probe(&["bash".to_owned(), "./guest-pn4-write.sh".to_owned()])?;
    if result.status != Some(0) || text(&result.stdout) != "PN4_WRITE_OK\n" {
        return Err(format!(
            "probe: guest-pn4-write.sh exited {:?} with {:?}",
            result.status,
            text(&result.stdout)
        ));
    }
    let written = fs::read(&target).map_err(|error| error.to_string())?;
    if written != b"# stand-in\n[network]\nallow_host = true\n" {
        return Err(format!(
            "probe: the write fixture appended {:?}",
            text(&written)
        ));
    }
    println!("probe write PASS: the guest appended exactly the persisted grant");

    // The probe fixture really distinguishes a reachable listener from a closed
    // port, so a row's denial is not an artifact of a broken probe.
    fs::create_dir_all(work.join("receipts")).map_err(|error| error.to_string())?;
    let listener = fixtures::bind_tcp(0).map_err(|error| format!("probe listener: {error}"))?;
    let port = listener
        .local_addr()
        .map_err(|error| error.to_string())?
        .port();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let server = {
        let directory = work.join("receipts");
        let stop = std::sync::Arc::clone(&stop);
        std::thread::Builder::new()
            .name("pn-probe-receipts".to_owned())
            .spawn(move || {
                let _ = fixtures::serve_tcp(listener, directory, stop);
            })
            .map_err(|error| format!("probe listener thread: {error}"))?
    };
    let reached = probe(&[
        "bash".to_owned(),
        "./guest-pn-probe.sh".to_owned(),
        port.to_string(),
        "marker".to_owned(),
        "127.0.0.1".to_owned(),
    ])?;
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let mut joined = false;
    let deadline = Instant::now() + TEARDOWN;
    while !server.is_finished() && Instant::now() < deadline {
        std::thread::sleep(POLL);
    }
    if server.is_finished() {
        let _ = server.join();
        joined = true;
    }
    if !joined {
        return Err("probe: the receipt listener did not stop within its bound".to_owned());
    }
    if reached.status != Some(0) || !text(&reached.stdout).contains("PN_REACHED marker") {
        return Err(format!(
            "probe: a reachable fixture reported {:?} / {:?}",
            reached.status,
            text(&reached.stdout)
        ));
    }

    // A bound, non-listening socket: no other process can steal this port, so
    // the denial below cannot be a busy-port accident.
    use rustix::net::{AddressFamily, SocketType, bind as socket_bind, getsockname, socket};
    let closed = socket(AddressFamily::INET, SocketType::STREAM, None)
        .map_err(|error| format!("probe closed socket: {error}"))?;
    socket_bind(&closed, &std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .map_err(|error| format!("probe closed socket: {error}"))?;
    let address: rustix::net::SocketAddrV4 = getsockname(&closed)
        .map_err(|error| format!("probe closed socket: {error}"))
        .and_then(|address| {
            address
                .try_into()
                .map_err(|error: rustix::io::Errno| format!("probe closed socket: {error}"))
        })?;
    let denied = probe(&[
        "bash".to_owned(),
        "./guest-pn-probe.sh".to_owned(),
        address.port().to_string(),
        "marker".to_owned(),
        "127.0.0.1".to_owned(),
    ])?;
    drop(closed);
    if denied.status != Some(0) || !text(&denied.stdout).contains("PN_DENIED marker") {
        return Err(format!(
            "probe: a closed port reported {:?} / {:?}",
            denied.status,
            text(&denied.stdout)
        ));
    }
    println!("probe guest PASS: a reachable fixture reaches and a closed port denies");
    Ok(())
}

// --- Group: helper ----------------------------------------------------------

fn helper_controls(repo: &Path, work: &Path) -> Result<(), String> {
    // A mirror of `script/test`, so the sentinel control rewrites a copy and a
    // crash cannot leave the tracked fixture mutated.
    let mirror = work.join("lookup");
    copy_tree(&repo.join("script/test"), &mirror.join("script/test"))?;
    let helper = mirror.join("script/test/lib/persisted-network.sh");
    let tsv = mirror.join("script/test/fixtures/persisted-network/expected-stderr.tsv");
    let tracked = fs::read(repo.join("script/test/fixtures/persisted-network/expected-stderr.tsv"))
        .map_err(|error| error.to_string())?;
    let original = fs::read_to_string(&tsv).map_err(|error| error.to_string())?;

    // Every row: the shell's `awk` rendering and this crate's parser agree,
    // character for character.
    let mut rows: Vec<(String, Vec<String>)> = Vec::new();
    for line in original.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((row, value)) = line.split_once('\t') else {
            return Err("helper: the tracked oracle has a line without a tab".to_owned());
        };
        match rows.iter_mut().find(|(name, _)| name == row) {
            Some((_, texts)) => texts.push(value.to_owned()),
            None => rows.push((row.to_owned(), vec![value.to_owned()])),
        }
    }
    if rows.is_empty() {
        return Err("helper: the tracked oracle has no rows".to_owned());
    }
    for (row, texts) in &rows {
        let rendered = run_bounded(
            &[
                "bash".to_owned(),
                "-c".to_owned(),
                "source \"$1\"; pn_expected \"$2\"".to_owned(),
                "pn".to_owned(),
                helper.to_string_lossy().into_owned(),
                row.clone(),
            ],
            work,
            NO_ENV,
            NO_UNSET,
            Duration::from_secs(10),
        )?;
        let wanted = texts
            .iter()
            .map(|text| format!("{text}\n"))
            .collect::<String>();
        if rendered.status != Some(0) || text(&rendered.stdout) != wanted {
            return Err(format!(
                "helper: pn_expected {row} rendered {:?}, not {wanted:?}",
                text(&rendered.stdout)
            ));
        }
        let parsed =
            pn::expected_stderr(&mirror.join("script/test/fixtures/persisted-network"), row)?;
        if parsed != *texts {
            return Err(format!("helper: {row} parse disagrees with the shell"));
        }
        // Missing-substring control: dropping any one line must be reported,
        // naming the line that is missing.
        for omitted in 0..texts.len() {
            let log = texts
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != omitted)
                .map(|(_, text)| text.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            match pn::require_shared_stderr_oracle(
                &mirror.join("script/test/fixtures/persisted-network"),
                row,
                &log,
                Some(row),
            ) {
                Err(error) if error.contains(&texts[omitted]) => {}
                Err(error) => {
                    return Err(format!(
                        "helper: {row} omitted-substring control named {error:?}"
                    ));
                }
                Ok(()) => {
                    return Err(format!(
                        "helper: {row} accepted a log missing {:?}",
                        texts[omitted]
                    ));
                }
            }
        }
        // Sentinel control: the checker reads the fixture. With a sentinel in
        // the first line, the unchanged log must be rejected *naming the
        // sentinel*, and a log carrying the sentinel must be accepted. A
        // hard-coded list of the old texts would pass the second check and fail
        // the first.
        let sentinel = format!("PN_SENTINEL_{row}");
        let fixed = texts.join("\n");
        fs::write(
            &tsv,
            original.replace(
                &format!("{row}\t{}", texts[0]),
                &format!("{row}\t{sentinel}"),
            ),
        )
        .map_err(|error| error.to_string())?;
        let control = (|| -> Result<(), String> {
            let tested = &mirror.join("script/test/fixtures/persisted-network");
            match pn::require_shared_stderr_oracle(tested, row, &fixed, Some(row)) {
                Err(error) if error.contains(&sentinel) => {}
                Err(error) => {
                    return Err(format!(
                        "helper: {row} sentinel control was not named: {error}"
                    ));
                }
                Ok(()) => {
                    return Err(format!(
                        "helper: {row} sentinel control accepted the unchanged log"
                    ));
                }
            }
            let updated = format!("{sentinel}\n{}", texts[1..].join("\n"));
            if let Err(error) = pn::require_shared_stderr_oracle(tested, row, &updated, Some(row)) {
                return Err(format!("helper: {row} rejected the sentinel log: {error}"));
            }
            Ok(())
        })();
        let restored = fs::write(&tsv, &original).map_err(|error| error.to_string());
        control?;
        restored?;
        println!("helper {row} oracle PASS: parsed from the fixture, not hard-coded");
    }
    if fs::read(&tsv).map_err(|error| error.to_string())? != original.as_bytes() {
        return Err("helper: the mirror oracle was not restored".to_owned());
    }
    if fs::read(repo.join("script/test/fixtures/persisted-network/expected-stderr.tsv"))
        .map_err(|error| error.to_string())?
        != tracked
    {
        return Err("helper: the tracked oracle changed".to_owned());
    }

    // An empty log conforms only when no oracle is named; an unknown row is an
    // error from both renderers.
    pn::require_shared_stderr_oracle(
        &mirror.join("script/test/fixtures/persisted-network"),
        "unchecked",
        "",
        None,
    )?;
    let unknown = run_bounded(
        &[
            "bash".to_owned(),
            "-c".to_owned(),
            "source \"$1\"; pn_expected absent".to_owned(),
            "pn".to_owned(),
            helper.to_string_lossy().into_owned(),
        ],
        work,
        &[],
        &[],
        Duration::from_secs(10),
    )?;
    if unknown.status == Some(0) {
        return Err("helper: the shell accepted an unknown oracle row".to_owned());
    }
    if pn::require_shared_stderr_oracle(
        &mirror.join("script/test/fixtures/persisted-network"),
        "unknown",
        "",
        Some("absent"),
    )
    .is_ok()
    {
        return Err("helper: an unknown oracle row was accepted".to_owned());
    }

    // --- pn_launch keeps the trapped PID equal to the driver's ----------------
    let tools = work.join("tools");
    fs::create_dir_all(&tools).map_err(|error| error.to_string())?;
    write_script(&tools.join("harness"), &harness_stub())?;
    let program = work.join("signal-stub.sh");
    write_script(&program, &signal_stub())?;
    let launch_env = |program: &Path, ready: &Path, receipt: &Path| {
        vec![
            (
                "HARNESS_BIN_DIR".to_owned(),
                tools.to_string_lossy().into_owned(),
            ),
            (
                "PN_STUB_PROGRAM".to_owned(),
                program.to_string_lossy().into_owned(),
            ),
            ("PN_READY".to_owned(), ready.to_string_lossy().into_owned()),
            ("PN_TERM".to_owned(), receipt.to_string_lossy().into_owned()),
        ]
    };
    let source = fs::read_to_string(&helper).map_err(|error| error.to_string())?;

    // The control asserts its own subject: with `exec`, the shell's trapped `$!`
    // is the fixture's PID; without `exec`, it is a child of the shell.
    let pid_control = |helper: &Path, expected_error: Option<&str>| -> Result<(), String> {
        let ready = work.join("ready");
        let receipt = work.join("term");
        for path in [&ready, &receipt] {
            let _ = fs::remove_file(path);
        }
        let mut child = spawn_to_files(
            &[
                "bash".to_owned(),
                "-c".to_owned(),
                "source \"$1\"; pn_launch unused".to_owned(),
                "pn".to_owned(),
                helper.to_string_lossy().into_owned(),
            ],
            work,
            &launch_env(&program, &ready, &receipt),
            NO_UNSET,
            &work.join("pid-stdout"),
            &work.join("pid-stderr"),
        )?;
        let mut measured = None;
        let mut outcome = (|| -> Result<(), String> {
            wait_ready(&mut child, &ready)?;
            let published = read_owned_pid(&ready).ok_or("pn_launch published no PID")?;
            measured = Some(published);
            if child.id() as i32 != published {
                return Err("pn_launch PID ownership mismatch".to_owned());
            }
            signal_owned(published, libc::SIGTERM);
            let status = wait_bounded(&mut child, TEARDOWN);
            let receipt_text = fs::read_to_string(&receipt).map_err(|error| error.to_string())?;
            if status.map(|code| code == 0).unwrap_or(true) || receipt_text != published.to_string()
            {
                return Err("pn_launch TERM cleanup missing".to_owned());
            }
            Ok(())
        })();
        let survivors = reap_owned_fixture(&mut child, measured);
        if !survivors.is_empty() {
            let error = format!("pn_launch fixture survived teardown: {survivors:?}");
            outcome = match outcome {
                Err(primary) => Err(primary),
                Ok(()) => Err(error),
            };
        }
        match (outcome, expected_error) {
            (Err(error), Some(wanted)) if error != wanted => Err(format!(
                "helper: no-exec control failed with {error:?}, not {wanted:?}"
            )),
            (Err(_), Some(_)) => {
                println!("no-exec negative control PASS: PID ownership mismatch");
                Ok(())
            }
            (Err(error), None) => Err(error),
            (Ok(()), Some(wanted)) => Err(format!(
                "helper: the no-exec control survived instead of reporting {wanted:?}"
            )),
            (Ok(()), None) => Ok(()),
        }
    };
    pid_control(&helper, None)?;

    // Without `exec` the trapped PID is the shell's, not the driver's, so the
    // control must fail. A control that cannot fail is not evidence.
    let no_exec = helper.with_file_name("persisted-network-noexec.sh");
    let unexecuted = source.replacen(
        "    exec \"$harness\" persisted-network --repo-root \"$PN_REPO_ROOT\" \"$@\"",
        "    \"$harness\" persisted-network --repo-root \"$PN_REPO_ROOT\" \"$@\"",
        1,
    );
    if unexecuted == source {
        return Err("helper: the pn_launch exec line was not found".to_owned());
    }
    fs::write(&no_exec, &unexecuted).map_err(|error| error.to_string())?;
    pid_control(&no_exec, Some("pn_launch PID ownership mismatch"))?;

    // --- Every bounded wait and teardown reports and reaps -------------------
    let dead = work.join("dead-stub.sh");
    let dead_control = |name: &str, body: &str, expected: &str| -> Result<(), String> {
        write_script(&dead, body)?;
        let ready = work.join(format!("ready-{name}"));
        let _ = fs::remove_file(&ready);
        let receipt = work.join(format!("term-{name}"));
        let mut child = spawn_to_files(
            &[
                "bash".to_owned(),
                "-c".to_owned(),
                "source \"$1\"; pn_launch unused".to_owned(),
                "pn".to_owned(),
                helper.to_string_lossy().into_owned(),
            ],
            work,
            &launch_env(&dead, &ready, &receipt),
            NO_UNSET,
            &work.join(format!("{name}-stdout")),
            &work.join(format!("{name}-stderr")),
        )?;
        let measured = None;
        let mut outcome = match wait_ready(&mut child, &ready) {
            Err(error) if error.contains(expected) => Ok(()),
            Err(error) => Err(format!("{name}: wait_ready reported {error:?}")),
            Ok(()) => Err(format!("{name}: wait_ready accepted a bad fixture")),
        };
        let survivors = reap_owned_fixture(&mut child, measured);
        if !survivors.is_empty() || child.try_wait().ok().flatten().is_none() {
            let error = format!("{name}: survivors {survivors:?}");
            outcome = match outcome {
                Err(primary) => Err(primary),
                Ok(()) => Err(error),
            };
        }
        outcome?;
        println!(
            "{name} control PASS: bounded wait reported and teardown reaped the owned fixture"
        );
        Ok(())
    };
    // Exit before readiness: a dead fixture is reported, not waited out.
    dead_control(
        "exit-before-readiness",
        "#!/bin/sh\nexit 0\n",
        "signal fixture exited before readiness",
    )?;
    // Readiness timeout: a live fixture that never signals is still bounded.
    dead_control(
        "readiness-timeout",
        "#!/bin/sh\nwhile :; do sleep 0.05; done\n",
        "signal fixture readiness timeout",
    )?;

    // Ignored TERM: the bounded wait must time out, then KILL must reap; a
    // survivor fails the control loudly instead of being logged.
    let ignored_env = {
        let mut env = launch_env(
            &program,
            &work.join("ready-ignored"),
            &work.join("term-ignored"),
        );
        env.push(("PN_STUB_IGNORE_TERM".to_owned(), "1".to_owned()));
        env
    };
    let _ = fs::remove_file(work.join("ready-ignored"));
    let _ = fs::remove_file(work.join("term-ignored"));
    let mut child = spawn_to_files(
        &[
            "bash".to_owned(),
            "-c".to_owned(),
            "source \"$1\"; pn_launch unused".to_owned(),
            "pn".to_owned(),
            helper.to_string_lossy().into_owned(),
        ],
        work,
        &ignored_env,
        NO_UNSET,
        &work.join("ignored-stdout"),
        &work.join("ignored-stderr"),
    )?;
    let mut measured = None;
    let mut outcome = (|| -> Result<(), String> {
        wait_ready(&mut child, &work.join("ready-ignored"))?;
        let published = read_owned_pid(&work.join("ready-ignored"))
            .ok_or("ignored-TERM fixture published no PID")?;
        measured = Some(published);
        if child.id() as i32 != published {
            return Err("ignored-TERM fixture PID ownership mismatch".to_owned());
        }
        signal_owned(published, libc::SIGTERM);
        if wait_bounded(&mut child, TEARDOWN).is_some() {
            return Err("ignored-TERM helper fixture exited on TERM".to_owned());
        }
        Ok(())
    })();
    let survivors = reap_owned_fixture(&mut child, measured);
    let exited = child.try_wait().ok().flatten().is_some();
    if !survivors.is_empty() || !exited || measured.is_some_and(pid_alive) {
        let error = format!("ignored-TERM helper left owned survivors {survivors:?}");
        outcome = match outcome {
            Err(primary) => Err(primary),
            Ok(()) => Err(error),
        };
    }
    outcome?;
    println!("ignored-TERM helper control PASS: KILL reaped the owned fixture");

    // Dead-PID race: reaping an already-exited owned fixture is a no-op.
    let mut finished = Command::new("true")
        .stdout(Stdio::null())
        .spawn()
        .map_err(|error| error.to_string())?;
    let _ = finished.wait();
    let finished_id = finished.id() as i32;
    if !reap_owned_fixture(&mut finished, Some(finished_id)).is_empty() {
        return Err("helper: reaping an exited PID reported a survivor".to_owned());
    }
    println!("already-exited PID control PASS: teardown treated the dead PID as absent");
    Ok(())
}

// --- Group: live shell ------------------------------------------------------

/// The environment and the stub tools one live-shell matrix runs against.
struct Live {
    work: PathBuf,
    repo: PathBuf,
    sha: String,
    tools: PathBuf,
    events: PathBuf,
    driver: PathBuf,
    counter: Cell<usize>,
}

impl Live {
    fn new(work: &Path) -> Result<Self, String> {
        let tools = work.join("tools");
        fs::create_dir_all(&tools).map_err(|error| error.to_string())?;
        let events = work.join("events.log");
        fs::write(&events, "").map_err(|error| error.to_string())?;
        Ok(Self {
            work: work.to_path_buf(),
            repo: work.join("A"),
            sha: String::new(),
            tools,
            events,
            driver: work.join("driver-stub.sh"),
            counter: Cell::new(0),
        })
    }

    /// Stub tools: `exec` through to the real program unless the control says
    /// otherwise, and record every scratch allocation.
    fn install_tools(&self) -> Result<(), String> {
        let real = |name: &str| -> Result<String, String> {
            which(name).ok_or_else(|| format!("live-shell: {name} is not on PATH"))
        };
        let real_git = real("git")?;
        let real_shasum = real("shasum")?;
        let real_mktemp = real("mktemp")?;
        write_script(
            &self.tools.join("git"),
            &format!(
                "#!/bin/sh\nif [ \"${{PN_FAIL_GIT:-}}\" = 1 ]; then exit 17; fi\nexec \"{real_git}\" \"$@\"\n"
            ),
        )?;
        write_script(
            &self.tools.join("shasum"),
            &format!(
                "#!/bin/sh\ncase \"${{PN_FAIL_HASH:-}}:$*\" in\n  binary:*bin-*|diff:*tree.diff) exit 19 ;;\nesac\nexec \"{real_shasum}\" \"$@\"\n"
            ),
        )?;
        write_script(
            &self.tools.join("uname"),
            "#!/bin/sh\ncase \"${1:-}\" in -s) echo Darwin ;; -m) echo arm64 ;; *) echo Darwin ;; esac\n",
        )?;
        write_script(&self.tools.join("pgrep"), "#!/bin/sh\nexit 1\n")?;
        let mktemp = r#"#!/bin/sh
out="$("__REAL_MKTEMP__" "$@")" || exit $?
case "$out" in
  /tmp/avm-pn.*|/private/tmp/avm-pn.*)
    printf 'allocated %s\n' "$out" >> "$PN_EVENTS"
    grep -Fxq "__OK__" "$AGENT_VM_PN_EVIDENCE/provenance-check.txt" 2>/dev/null || { echo "scratch allocated before provenance success" >&2; exit 66; }
    ;;
esac
printf '%s\n' "$out"
"#
        .replace("__REAL_MKTEMP__", &real_mktemp)
        .replace("__OK__", PROVENANCE_OK);
        write_script(&self.tools.join("mktemp"), &mktemp)?;
        write_script(&self.tools.join("harness"), &harness_stub())?;
        write_script(&self.driver, &driver_stub())?;
        Ok(())
    }

    fn env(&self, overrides: &[(&str, &str)]) -> Vec<(String, String)> {
        let mut env = vec![
            (
                "PATH".to_owned(),
                format!(
                    "{}:{}",
                    self.tools.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            ),
            (
                "PN_EVENTS".to_owned(),
                self.events.to_string_lossy().into_owned(),
            ),
            (
                "REAL_HARNESS".to_owned(),
                cases::harness_binary().to_string_lossy().into_owned(),
            ),
            (
                "AGENT_VM_LIVE_TEST_IMAGE".to_owned(),
                "fixture-image".to_owned(),
            ),
            (
                "HARNESS_BIN_DIR".to_owned(),
                self.tools.to_string_lossy().into_owned(),
            ),
        ];
        for (name, value) in overrides {
            env.push(((*name).to_owned(), (*value).to_owned()));
        }
        env
    }

    fn unset() -> [&'static str; 3] {
        [
            "AGENT_VM_BUILD_PROVENANCE_STRICT",
            "AGENT_VM_GIT_SHA",
            "GITHUB_SHA",
        ]
    }

    /// Write a candidate binary that prints one version line.
    fn binary(&self, name: &str, body: &str) -> Result<PathBuf, String> {
        let count = self.counter.get() + 1;
        self.counter.set(count);
        let path = self.work.join(format!("bin-{name}-{count}"));
        write_script(&path, body)?;
        Ok(path)
    }

    fn evidence(&self, name: &str) -> Result<PathBuf, String> {
        let count = self.counter.get();
        let path = self.work.join(format!("evidence-{name}-{count}"));
        fs::create_dir_all(&path).map_err(|error| error.to_string())?;
        Ok(path)
    }

    /// Run the live shell in `repo` with a candidate that prints `body`.
    fn run(
        &self,
        repo: &Path,
        body: &str,
        name: &str,
        extra: &[(&str, &str)],
    ) -> Result<(Run, PathBuf, String), String> {
        fs::write(&self.events, "").map_err(|error| error.to_string())?;
        let binary = self.binary(name, body)?;
        let evidence = self.evidence(name)?;
        let mut overrides: Vec<(String, String)> = vec![
            (
                "AGENT_VM_BIN".to_owned(),
                binary.to_string_lossy().into_owned(),
            ),
            (
                "AGENT_VM_PN_EVIDENCE".to_owned(),
                evidence.to_string_lossy().into_owned(),
            ),
            (
                "PN_STUB_PROGRAM".to_owned(),
                self.driver.to_string_lossy().into_owned(),
            ),
        ];
        for (key, value) in extra {
            overrides.push(((*key).to_owned(), (*value).to_owned()));
        }
        let refs: Vec<(String, String)> = overrides;
        let argv = vec![
            "bash".to_owned(),
            repo.join("script/test/persisted-network-live.sh")
                .to_string_lossy()
                .into_owned(),
        ];
        // Files, not pipes: a surviving driver would hold a pipe open, and
        // draining it would be an unbounded wait.
        let mut child = spawn_to_files(
            &argv,
            repo,
            &self.env(
                &refs
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect::<Vec<_>>(),
            ),
            &Self::unset(),
            &self.work.join(format!("{name}-stdout")),
            &self.work.join(format!("{name}-stderr")),
        )?;
        let status = wait_bounded(&mut child, LIVE_RUN);
        if status.is_none() {
            let survivors = reap_owned_fixture(&mut child, None);
            return Err(format!(
                "live shell run {name} did not finish within {LIVE_RUN:?}; survivors {survivors:?}"
            ));
        }
        let stdout = fs::read(self.work.join(format!("{name}-stdout"))).unwrap_or_default();
        let stderr = fs::read(self.work.join(format!("{name}-stderr"))).unwrap_or_default();
        let log = fs::read_to_string(&self.events).unwrap_or_default();
        Ok((
            Run {
                status,
                stdout,
                stderr,
            },
            evidence,
            log,
        ))
    }

    fn allocs(&self) -> Vec<PathBuf> {
        allocations(&self.events)
    }
}

fn which(name: &str) -> Option<String> {
    for directory in std::env::var("PATH").unwrap_or_default().split(':') {
        if directory.is_empty() {
            continue;
        }
        let candidate = Path::new(directory).join(name);
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

fn clean_binary(sha: &str) -> String {
    format!("#!/bin/sh\nprintf 'agent-vm 0.3.4 ({sha})\\n'\n")
}

fn live_shell_controls(repo: &Path, work: &Path) -> Result<(), String> {
    let live = Live::new(work)?;
    let git_env = [
        ("GIT_AUTHOR_NAME", "t"),
        ("GIT_AUTHOR_EMAIL", "t@example.invalid"),
        ("GIT_COMMITTER_NAME", "t"),
        ("GIT_COMMITTER_EMAIL", "t@example.invalid"),
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ];
    let routing = [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_COMMON_DIR",
        "GIT_NAMESPACE",
    ];
    let git = |path: &Path, args: &[&str]| -> Result<Run, String> {
        let argv = std::iter::once("git".to_owned())
            .chain(args.iter().map(|argument| (*argument).to_owned()))
            .collect::<Vec<_>>();
        run_bounded(&argv, path, &[], &routing, Duration::from_secs(120))
    };
    let git_repo = |path: &Path, message: &str| -> Result<String, String> {
        fs::create_dir_all(path).map_err(|error| error.to_string())?;
        for (args, what) in [
            (vec!["init", "-q", "-b", "main"], "git init"),
            (vec!["config", "core.filemode", "true"], "git config"),
            (vec!["add", "-A"], "git add"),
            (
                vec!["commit", "-q", "--no-gpg-sign", "-m", message],
                "git commit",
            ),
        ] {
            let argv = std::iter::once("git".to_owned())
                .chain(args.iter().map(|argument| (*argument).to_owned()))
                .collect::<Vec<_>>();
            let env = git_env
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect::<Vec<_>>();
            let run = run_bounded(&argv, path, &env, &routing, Duration::from_secs(120))?;
            if run.status != Some(0) {
                return Err(format!("live-shell: {what} failed: {:?}", run.stderr));
            }
        }
        let argv = vec!["git".to_owned(), "rev-parse".to_owned(), "HEAD".to_owned()];
        let env = git_env
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect::<Vec<_>>();
        let run = run_bounded(&argv, path, &env, &routing, Duration::from_secs(120))?;
        if run.status != Some(0) {
            return Err("live-shell: git rev-parse HEAD failed".to_owned());
        }
        Ok(text(&run.stdout).trim().to_owned())
    };

    // Repo A holds a committed copy of `script/test`; B is a different commit,
    // used only for routing; C holds the harness inside an untracked subdir.
    copy_tree(&repo.join("script/test"), &live.repo.join("script/test"))?;
    let sha_a = git_repo(&live.repo, "A")?;
    let live = Live {
        sha: sha_a.clone(),
        ..live
    };
    live.install_tools()?;
    let repo_b = work.join("B");
    fs::create_dir_all(&repo_b).map_err(|error| error.to_string())?;
    fs::write(repo_b.join("b.txt"), "b\n").map_err(|error| error.to_string())?;
    let sha_b = git_repo(&repo_b, "B")?;

    // --- Oracle preflight, with its own committed fixture -------------------
    // The oracle repo owns a separate commit: the controls never change A's
    // SHA or history to make a refusal happen.
    let oracle_repo = work.join("oracle-repo");
    copy_tree(&repo.join("script/test"), &oracle_repo.join("script/test"))?;
    let oracle_sha = git_repo(&oracle_repo, "oracle positive")?;
    {
        let (run, _, log) = live.run(
            &oracle_repo,
            &clean_binary(&oracle_sha),
            "oracle-positive",
            &[],
        )?;
        if run.status != Some(0) || !log.split_whitespace().any(|word| word == "driver") {
            return Err(format!(
                "oracle provenance prerequisites: rc={:?} log={log:?} stdout={:?}",
                run.status,
                text(&run.stdout)
            ));
        }
    }
    let oracle_tsv = oracle_repo.join("script/test/fixtures/persisted-network/expected-stderr.tsv");
    let text_tsv = fs::read_to_string(&oracle_tsv).map_err(|error| error.to_string())?;
    fs::write(
        &oracle_tsv,
        format!(
            "{}\n",
            text_tsv
                .lines()
                .filter(|line| !line.starts_with("PN3\t"))
                .collect::<Vec<_>>()
                .join("\n")
        ),
    )
    .map_err(|error| error.to_string())?;
    let oracle_sha = git_repo(&oracle_repo, "oracle missing row")?;
    {
        let (run, evidence, log) = live.run(
            &oracle_repo,
            &clean_binary(&oracle_sha),
            "oracle-missing",
            &[],
        )?;
        if run.status == Some(0)
            || !allocations(&live.events).is_empty()
            || log.split_whitespace().any(|word| word == "driver")
        {
            return Err("oracle preflight did not refuse before allocation".to_owned());
        }
        if evidence.join("provenance-check.txt").exists() {
            return Err("oracle refusal reached provenance".to_owned());
        }
    }
    for row in ["PN1", "PN2", "PN3", "PN4B", "PN5"] {
        let lookup = run_bounded(
            &[
                "bash".to_owned(),
                "-c".to_owned(),
                "source \"$1\"; pn_expected \"$2\"".to_owned(),
                "pn".to_owned(),
                oracle_repo
                    .join("script/test/lib/persisted-network.sh")
                    .to_string_lossy()
                    .into_owned(),
                row.to_owned(),
            ],
            work,
            NO_ENV,
            NO_UNSET,
            Duration::from_secs(10),
        )?;
        if (lookup.status != Some(0)) != (row == "PN3") {
            return Err(format!("oracle preflight row {row} answered wrongly"));
        }
    }
    let head = git(&live.repo, &["rev-parse", "HEAD"])?;
    if text(&head.stdout).trim() != sha_a {
        return Err("oracle control changed A's HEAD".to_owned());
    }
    println!("oracle preflight PASS: a missing row refuses before any scratch exists");

    // --- The signal controls -------------------------------------------------
    live_signals(&live, &program_for(&live)?)?;

    // --- P6: dirty, mismatched and unknown candidates -----------------------
    let flipped = format!(
        "{}{}",
        &sha_a[..sha_a.len() - 1],
        if sha_a.ends_with('0') { "1" } else { "0" }
    );
    rejected(&live, &clean_binary(&flipped), "mismatch-sha")?;
    rejected(
        &live,
        &format!("#!/bin/sh\nprintf 'agent-vm 0.3.4 ({sha_a}, dirty)\\n'\n"),
        "dirty-binary",
    )?;
    rejected(
        &live,
        &format!("#!/bin/sh\nprintf 'agent-vm 0.3.4 ({sha_a}, state unknown)\\n'\n"),
        "unknown-state",
    )?;
    rejected(
        &live,
        "#!/bin/sh\nprintf 'agent-vm 0.3.4 (unknown)\\n'\n",
        "unknown-revision",
    )?;
    fs::write(live.repo.join("script/test/README-dirt"), "dirt\n")
        .map_err(|error| error.to_string())?;
    let argv = vec![
        "git".to_owned(),
        "add".to_owned(),
        "script/test/README-dirt".to_owned(),
    ];
    let run = run_bounded(&argv, &live.repo, &[], &routing, Duration::from_secs(60))?;
    if run.status != Some(0) {
        return Err("P6: git add of the dirt file failed".to_owned());
    }
    rejected(&live, &clean_binary(&sha_a), "dirty-source-content")?;
    let reset = vec![
        "git".to_owned(),
        "reset".to_owned(),
        "-q".to_owned(),
        "--hard".to_owned(),
    ];
    run_bounded(&reset, &live.repo, &[], &routing, Duration::from_secs(60))?;
    let _ = fs::remove_file(live.repo.join("script/test/README-dirt"));
    let script_dirt = live.repo.join("script/test/persisted-network-live.sh");
    let mode = fs::metadata(&script_dirt)
        .map_err(|error| error.to_string())?
        .permissions()
        .mode();
    fs::set_permissions(&script_dirt, fs::Permissions::from_mode(mode & !0o111))
        .map_err(|error| error.to_string())?;
    rejected(&live, &clean_binary(&sha_a), "dirty-source-mode")?;
    fs::set_permissions(&script_dirt, fs::Permissions::from_mode(mode | 0o111))
        .map_err(|error| error.to_string())?;
    run_bounded(&reset, &live.repo, &[], &routing, Duration::from_secs(60))?;

    // --- P7: a matching clean candidate reaches one harmless driver ---------
    {
        let (run, evidence, log) = live.run(&live.repo, &clean_binary(&sha_a), "accept", &[])?;
        let owned = allocations(&live.events);
        if run.status != Some(0) {
            return Err(format!(
                "P7 rc={:?} stdout={:?} stderr={:?}",
                run.status,
                text(&run.stdout),
                text(&run.stderr)
            ));
        }
        let words = log.split_whitespace().collect::<Vec<_>>();
        if words.iter().filter(|word| **word == "driver").count() != 1
            || words.iter().filter(|word| **word == "cleanup").count() != 1
        {
            return Err(format!("P7 events {log:?}"));
        }
        if owned.len() != 1 || owned[0].exists() {
            return Err(format!("P7 allocations {owned:?}"));
        }
        if !evidence.join("binary.sha256").exists()
            || !evidence.join("provenance-check.txt").exists()
        {
            return Err("P7 evidence retained".to_owned());
        }
    }
    fs::write(live.repo.join("script/test/untracked-ok"), "u\n")
        .map_err(|error| error.to_string())?;
    {
        let (run, _, log) = live.run(&live.repo, &clean_binary(&sha_a), "accept-untracked", &[])?;
        if run.status != Some(0) || allocations(&live.events).len() != 1 {
            return Err(format!("P7 untracked: {log:?}"));
        }
    }
    let _ = fs::remove_file(live.repo.join("script/test/untracked-ok"));
    println!("P7 accept PASS: one driver, one cleanup, one reclaimed scratch");

    // --- P8: driver status propagation and cleanup semantics ----------------
    {
        let (run, _, log) = live.run(
            &live.repo,
            &clean_binary(&sha_a),
            "exit23",
            &[("STUB_EXIT", "23")],
        )?;
        if run.status != Some(23) {
            return Err(format!("P8 expected 23, got {:?}", run.status));
        }
        let words = log.split_whitespace().collect::<Vec<_>>();
        if words.iter().filter(|word| **word == "driver").count() != 1
            || !words.contains(&"cleanup")
        {
            return Err(format!("P8 exit23 events {log:?}"));
        }
        let owned = allocations(&live.events);
        if owned.is_empty() || owned[0].exists() {
            return Err(format!("P8 exit23 scratch {owned:?}"));
        }
    }
    {
        let (run, _, log) = live.run(
            &live.repo,
            &clean_binary(&sha_a),
            "cleanfail",
            &[("STUB_CLEANUP_FAIL", "1")],
        )?;
        if run.status != Some(24) {
            return Err(format!("P8 expected 24, got {:?}", run.status));
        }
        if !log.contains("cleanup-failed") {
            return Err(format!("P8 cleanfail events {log:?}"));
        }
        let owned = allocations(&live.events);
        if owned.len() != 1 || !owned[0].is_dir() {
            return Err("failed cleanup must preserve owned scratch".to_owned());
        }
        // The shell only exits after `wait "$driver"`, so the status-24 return
        // proves the driver is gone; confirm identity, not just unreadability.
        let driver = read_launch_pid(&owned[0])
            .ok_or("failed cleanup control: driver identity absent after the shell returned")?;
        if pid_alive(driver) {
            return Err("failed cleanup control: the driver outlived the shell".to_owned());
        }
        discard_owned_scratch(&owned, true, true, false)?;
    }

    // No cleanup-owning driver exists on exec/startup or canonicalization
    // failure, so those paths may only reclaim empty scratch.
    let bash_env = work.join("fail-scratch-cd.sh");
    fs::write(
        &bash_env,
        "cd() { case \"${1:-}\" in /tmp/avm-pn.*|/private/tmp/avm-pn.*) \
         echo \"scratch canonicalization failed\" >&2; return 33 ;; \
         *) builtin cd \"$@\" ;; esac; }\n",
    )
    .map_err(|error| error.to_string())?;
    for (name, extra, status, diagnostic) in [
        (
            "canonicalization-failure",
            vec![("BASH_ENV", bash_env.to_string_lossy().into_owned())],
            Some(33),
            "scratch canonicalization failed",
        ),
        (
            "startup-failure",
            vec![("PN_FAIL_STARTUP", "1".to_owned())],
            Some(29),
            "persisted-network driver startup failed",
        ),
    ] {
        let extra_refs = extra
            .iter()
            .map(|(key, value)| (*key, value.as_str()))
            .collect::<Vec<_>>();
        let (run, _, log) = live.run(&live.repo, &clean_binary(&sha_a), name, &extra_refs)?;
        let owned = allocations(&live.events);
        let outcome = (|| -> Result<(), String> {
            if run.status != status || !text(&run.stderr).contains(diagnostic) {
                return Err(format!(
                    "{name}: rc={:?} stderr={:?}",
                    run.status,
                    text(&run.stderr)
                ));
            }
            if owned.len() != 1 || owned[0].exists() {
                return Err(format!("{name}: scratch {owned:?}"));
            }
            let words = log.split_whitespace().collect::<Vec<_>>();
            for forbidden in ["driver", "cleanup", "cleanup-failed"] {
                if words.contains(&forbidden) {
                    return Err(format!("{name}: events {log:?}"));
                }
            }
            Ok(())
        })();
        // These paths never launch a driver, so driver and shell absence hold and
        // only empty scratch may be reclaimed; a regression that left driver
        // state behind still fails loudly.
        let reclaimed = discard_owned_scratch(&owned, true, true, true);
        outcome.and(reclaimed)?;
        println!("P8 {name} PASS: status {status:?}, scratch removed, no driver/cleanup");
    }

    // --- P9: inherited Git routing must not select checkout B ---------------
    let routing_env = [
        (
            "GIT_DIR",
            repo_b.join(".git").to_string_lossy().into_owned(),
        ),
        ("GIT_WORK_TREE", repo_b.to_string_lossy().into_owned()),
        (
            "GIT_INDEX_FILE",
            repo_b.join(".git/index").to_string_lossy().into_owned(),
        ),
        (
            "GIT_COMMON_DIR",
            repo_b.join(".git").to_string_lossy().into_owned(),
        ),
        ("GIT_NAMESPACE", "other".to_owned()),
    ];
    let routing_refs = routing_env
        .iter()
        .map(|(key, value)| (*key, value.as_str()))
        .collect::<Vec<_>>();
    {
        let (run, evidence, log) =
            live.run(&live.repo, &clean_binary(&sha_b), "routed-b", &routing_refs)?;
        if run.status == Some(0)
            || !allocations(&live.events).is_empty()
            || log.split_whitespace().any(|word| word == "driver")
        {
            return Err(format!("P9 routed B must refuse: {log:?}"));
        }
        let source =
            fs::read_to_string(evidence.join("source.txt")).map_err(|error| error.to_string())?;
        if !source.contains(&format!("commit: {sha_a}")) {
            return Err("P9 must record A's commit".to_owned());
        }
    }
    {
        let (run, _, log) =
            live.run(&live.repo, &clean_binary(&sha_a), "routed-a", &routing_refs)?;
        if run.status != Some(0) || allocations(&live.events).len() != 1 {
            return Err(format!("P9 routed A must accept: {log:?}"));
        }
    }

    // Wrong top level: the harness source lives in an unversioned subdirectory
    // of an outer repository, so it must not adopt the outer identity.
    let repo_c = work.join("C");
    fs::create_dir_all(repo_c.join("sub/script"))
        .map_err(|error| format!("{}: {error}", repo_c.display()))?;
    let init = vec![
        "git".to_owned(),
        "init".to_owned(),
        "-q".to_owned(),
        "-b".to_owned(),
        "main".to_owned(),
    ];
    let run = run_bounded(&init, &repo_c, NO_ENV, &routing, Duration::from_secs(60))?;
    if run.status != Some(0) {
        return Err("live-shell: git init for C failed".to_owned());
    }
    fs::write(repo_c.join("outer.txt"), "outer\n").map_err(|error| error.to_string())?;
    copy_tree(&repo.join("script/test"), &repo_c.join("sub/script/test"))?;
    {
        let (run, evidence, log) = live.run(
            &repo_c.join("sub"),
            &clean_binary(&sha_a),
            "wrong-root",
            &[],
        )?;
        if run.status == Some(0)
            || !allocations(&live.events).is_empty()
            || log.split_whitespace().any(|word| word == "driver")
        {
            return Err(format!("P9 wrong root must refuse: {log:?}"));
        }
        let receipt = fs::read_to_string(evidence.join("provenance-check.txt"))
            .map_err(|error| error.to_string())?;
        if receipt.is_empty() {
            return Err("root rejection receipt is empty".to_owned());
        }
        let source =
            fs::read_to_string(evidence.join("source.txt")).map_err(|error| error.to_string())?;
        if !source.contains("not yet validated") {
            return Err("root identity must not be trusted".to_owned());
        }
        for path in ["binary.sha256", "harness.sha256", "image.txt"] {
            if !evidence.join(path).exists() {
                return Err(format!("root rejection lost {path}"));
            }
        }
    }
    println!("P9 routing PASS: inherited Git routing and an outer checkout are both refused");

    // --- Fallible preflight: rejection manifests, no scratch or driver ------
    for (name, extra, body) in [
        (
            "git-failure",
            vec![("PN_FAIL_GIT", "1")],
            clean_binary(&sha_a),
        ),
        (
            "binary-hash-failure",
            vec![("PN_FAIL_HASH", "binary")],
            clean_binary(&sha_a),
        ),
        (
            "diff-hash-failure",
            vec![("PN_FAIL_HASH", "diff")],
            clean_binary(&sha_a),
        ),
        (
            "version-failure",
            Vec::new(),
            "#!/bin/sh\nprintf partial; exit 9\n".to_owned(),
        ),
    ] {
        let (run, evidence, log) = live.run(&live.repo, &body, name, &extra)?;
        if run.status == Some(0)
            || !allocations(&live.events).is_empty()
            || log.split_whitespace().any(|word| word == "driver")
        {
            return Err(format!("{name}: must refuse: {log:?}"));
        }
        let receipt = fs::read_to_string(evidence.join("provenance-check.txt"))
            .map_err(|error| error.to_string())?;
        if !receipt.contains("provenance:") || !receipt.contains("rebuild") {
            return Err(format!("{name}: receipt {receipt:?}"));
        }
        for path in ["source.txt", "image.txt"] {
            if !evidence.join(path).exists() {
                return Err(format!("{name}: lost {path}"));
            }
        }
        if name == "version-failure" {
            if fs::read(evidence.join("binary-version.txt")).unwrap_or_default() != b"partial" {
                return Err("version-failure must preserve partial stdout".to_owned());
            }
            for path in [
                "tree.diff",
                "tree.diff.sha256",
                "binary.sha256",
                "harness.sha256",
            ] {
                if !evidence.join(path).exists() {
                    return Err(format!("version-failure lost {path}"));
                }
            }
        }
        if name == "diff-hash-failure"
            && (!evidence.join("tree.diff").exists() || !evidence.join("binary.sha256").exists())
        {
            return Err("diff-hash-failure lost its artifacts".to_owned());
        }
    }

    // --- P10: the candidate's exact stdout bytes are preserved --------------
    for (name, body, expected) in [
        (
            "blank-lines",
            format!("#!/bin/sh\nprintf 'agent-vm 0.3.4 ({sha_a})\\n\\n\\n'\n"),
            format!("agent-vm 0.3.4 ({sha_a})\n\n\n"),
        ),
        (
            "second-line",
            format!("#!/bin/sh\nprintf 'agent-vm 0.3.4 ({sha_a})\\nnoise\\n'\n"),
            format!("agent-vm 0.3.4 ({sha_a})\nnoise\n"),
        ),
        (
            "no-final-lf",
            format!("#!/bin/sh\nprintf 'agent-vm 0.3.4 ({sha_a})'\n"),
            format!("agent-vm 0.3.4 ({sha_a})"),
        ),
        (
            "invalid-utf8",
            format!("#!/bin/sh\nprintf 'agent-vm 0.3.4 ({sha_a})\\377\\n'\n"),
            format!("agent-vm 0.3.4 ({sha_a})\u{fffd}"),
        ),
    ] {
        let (run, evidence, log) = live.run(&live.repo, &body, name, &[])?;
        let saved = fs::read(evidence.join("binary-version.txt")).unwrap_or_default();
        if run.status == Some(0)
            || !allocations(&live.events).is_empty()
            || log.split_whitespace().any(|word| word == "driver")
        {
            return Err(format!("P10 {name}: {log:?}"));
        }
        // The invalid-UTF-8 case is compared as bytes: a lossy comparison
        // would hide exactly the corruption this control exists to catch.
        let wanted = if name == "invalid-utf8" {
            let mut bytes = format!("agent-vm 0.3.4 ({sha_a})").into_bytes();
            bytes.push(0xff);
            bytes.push(b'\n');
            bytes
        } else {
            expected.into_bytes()
        };
        if saved != wanted {
            return Err(format!("P10 {name}: saved {saved:?} != {wanted:?}"));
        }
    }
    let partial = format!("agent-vm 0.3.4 ({})", &sha_a[..20]);
    {
        let (run, evidence, log) = live.run(
            &live.repo,
            &format!("#!/bin/sh\nprintf '{partial}'; exit 9\n"),
            "partial-exit",
            &[],
        )?;
        if run.status == Some(0)
            || !allocations(&live.events).is_empty()
            || log.split_whitespace().any(|word| word == "driver")
        {
            return Err(format!("P10 partial-exit: {log:?}"));
        }
        if fs::read(evidence.join("binary-version.txt")).unwrap_or_default() != partial.as_bytes() {
            return Err("P10 partial-exit: partial stdout was not preserved".to_owned());
        }
    }
    println!("P10 bytes PASS: the candidate's exact stdout is preserved and rejected");
    Ok(())
}

/// The one stub signal fixture the live-shell controls drive.
fn program_for(live: &Live) -> Result<PathBuf, String> {
    let path = live.work.join("signal-stub.sh");
    write_script(&path, &signal_stub())?;
    Ok(path)
}

/// A P6 rejection: refused before the driver, with the full manifest retained.
fn rejected(live: &Live, body: &str, name: &str) -> Result<(), String> {
    let (run, evidence, log) = live.run(&live.repo, body, name, &[])?;
    if run.status == Some(0)
        || log.split_whitespace().any(|word| word == "driver")
        || !allocations(&live.events).is_empty()
        || !evidence.join("provenance-check.txt").exists()
    {
        return Err(format!(
            "P6 {name}: rc={:?} log={log:?} stdout={:?}",
            run.status,
            text(&run.stdout)
        ));
    }
    for path in [
        "source.txt",
        "tree.diff",
        "tree.diff.sha256",
        "binary.sha256",
        "harness.sha256",
        "image.txt",
        "binary-version.txt",
    ] {
        if !evidence.join(path).exists() {
            return Err(format!("P6 {name}: missing rejection manifest {path}"));
        }
    }
    let receipt = fs::read_to_string(evidence.join("provenance-check.txt"))
        .map_err(|error| error.to_string())?;
    if !receipt.contains("rebuild") {
        return Err(format!("P6 {name}: receipt {receipt:?}"));
    }
    Ok(())
}

/// A control's assertion at the scratch-removal boundary: it is given the
/// scratch paths and the shell, and must fail if removal began while either the
/// shell or the driver was still alive.
type RemovalGuard<'a> = &'a dyn Fn(&[PathBuf], &mut Child) -> Result<(), String>;

/// The live shell's owned-scratch teardown, with its absence proof at the
/// removal boundary.
fn teardown_live(
    child: &mut Child,
    measured: Option<i32>,
    pidfile: &Path,
    events: &Path,
    in_flight: bool,
    before_removal: Option<RemovalGuard<'_>>,
) -> Result<(), String> {
    let owned_scratch = allocations(events);
    let mut driver = measured;
    if driver.is_none() {
        driver = read_owned_pid(pidfile);
    }
    if driver.is_none() {
        for path in &owned_scratch {
            driver = read_launch_pid(path);
            if driver.is_some() {
                break;
            }
        }
    }
    let Some(driver) = driver else {
        if owned_scratch.is_empty() {
            return Ok(());
        }
        // Fail closed: without an owned driver PID, driver absence cannot be
        // established, so scratch stays as evidence rather than being deleted
        // around a possibly-live driver.
        let survivors = reap_owned_fixture(child, None);
        if in_flight {
            return Ok(());
        }
        let _ = survivors;
        return Err(format!(
            "live shell ownership unresolved; retained scratch: {owned_scratch:?}"
        ));
    };
    let survivors = reap_owned_fixture(child, Some(driver));
    if !survivors.is_empty() {
        if in_flight {
            return Ok(());
        }
        return Err(format!("live shell left owned survivors: {survivors:?}"));
    }
    if !in_flight && let Some(before_removal) = before_removal {
        before_removal(&owned_scratch, child)?;
    }
    discard_owned_scratch(
        &owned_scratch,
        survivors.is_empty(),
        child.try_wait().ok().flatten().is_some(),
        false,
    )
}

/// Last-resort cleanup that owns scratch only through the seam.
///
/// Used by controls whose own tracking may never have run: a `None` snapshot is
/// unknown ownership, not absence, so identity is first recovered from the
/// launch record left in the owned scratch. If it stays unknown the seam refuses
/// to delete and the scratch survives as evidence.
fn emergency_reap(
    child: &mut Child,
    snapshot: Option<i32>,
    events: &Path,
) -> Result<Option<i32>, String> {
    if child.try_wait().ok().flatten().is_none() {
        reap_owned_fixture(child, None);
    }
    let owned = allocations(events);
    let mut recovered = snapshot;
    if recovered.is_none() {
        for path in &owned {
            recovered = read_launch_pid(path);
            if recovered.is_some() {
                break;
            }
        }
    }
    if let Some(pid) = recovered {
        signal_owned(pid, libc::SIGKILL);
        let deadline = Instant::now() + TEARDOWN;
        while pid_alive(pid) && Instant::now() < deadline {
            std::thread::sleep(POLL);
        }
    }
    discard_owned_scratch(
        &owned,
        recovered.is_some_and(|pid| !pid_alive(pid)),
        child.try_wait().ok().flatten().is_some(),
        false,
    )?;
    Ok(recovered)
}

/// The TERM, ignored-TERM, readiness, publication, pre-handoff, unresolved and
/// early-death controls: one function each, all sharing the seam above.
fn live_signals(live: &Live, program: &Path) -> Result<(), String> {
    let env = |ready: &Path, receipt: &Path, pid: &Path| -> Vec<(String, String)> {
        vec![
            (
                "PN_STUB_PROGRAM".to_owned(),
                program.to_string_lossy().into_owned(),
            ),
            ("PN_READY".to_owned(), ready.to_string_lossy().into_owned()),
            ("PN_TERM".to_owned(), receipt.to_string_lossy().into_owned()),
            ("PN_PID".to_owned(), pid.to_string_lossy().into_owned()),
            ("PN_REMOVE_SCRATCH".to_owned(), "1".to_owned()),
        ]
    };

    // --- TERM the actual live shell ----------------------------------------
    {
        let ready = live.work.join("live-ready");
        let receipt = live.work.join("live-term");
        let pidfile = live.work.join("live-driver-term.pid");
        let evidence = live.evidence("term")?;
        let binary = live.binary("term", &clean_binary(&live.sha))?;
        fs::write(&live.events, "").map_err(|error| error.to_string())?;
        let mut overrides = env(&ready, &receipt, &pidfile);
        overrides.push((
            "AGENT_VM_BIN".to_owned(),
            binary.to_string_lossy().into_owned(),
        ));
        overrides.push((
            "AGENT_VM_PN_EVIDENCE".to_owned(),
            evidence.to_string_lossy().into_owned(),
        ));
        let mut child = spawn_to_files(
            &[
                "bash".to_owned(),
                live.repo
                    .join("script/test/persisted-network-live.sh")
                    .to_string_lossy()
                    .into_owned(),
            ],
            &live.repo,
            &live.env(&refs(&overrides)),
            &Live::unset(),
            &live.work.join("term-stdout"),
            &live.work.join("term-stderr"),
        )?;
        let measured = Cell::new(None);
        let outcome = (|| -> Result<(), String> {
            wait_ready(&mut child, &ready)?;
            let driver = read_owned_pid(&ready).ok_or("live fixture published no PID")?;
            measured.set(Some(driver));
            signal_owned(child.id() as i32, libc::SIGTERM);
            let status = wait_bounded(&mut child, TEARDOWN);
            if status.map(|code| code == 0).unwrap_or(true) {
                return Err("live TERM unexpectedly succeeded".to_owned());
            }
            if fs::read_to_string(&receipt).unwrap_or_default() != driver.to_string() {
                return Err("live trap did not forward TERM to the measured driver".to_owned());
            }
            let owned = live.allocs();
            if owned.len() != 1 || owned[0].exists() {
                return Err(format!("live TERM did not clean owned scratch: {owned:?}"));
            }
            Ok(())
        })();
        let teardown = teardown_live(
            &mut child,
            measured.get(),
            &pidfile,
            &live.events,
            outcome.is_err(),
            None,
        );
        outcome.and(teardown)?;
        println!("live shell TERM PASS: forwarded signal and retained cleanup receipt");
    }

    // --- A driver that ignores TERM must not strand the shell --------------
    {
        let ready = live.work.join("live-ready-ignored");
        let receipt = live.work.join("live-term-ignored");
        let pidfile = live.work.join("live-driver-ignored.pid");
        let evidence = live.evidence("term-ignored")?;
        let binary = live.binary("term-ignored", &clean_binary(&live.sha))?;
        fs::write(&live.events, "").map_err(|error| error.to_string())?;
        let mut overrides = env(&ready, &receipt, &pidfile);
        overrides.push(("PN_STUB_IGNORE_TERM".to_owned(), "1".to_owned()));
        overrides.push((
            "AGENT_VM_BIN".to_owned(),
            binary.to_string_lossy().into_owned(),
        ));
        overrides.push((
            "AGENT_VM_PN_EVIDENCE".to_owned(),
            evidence.to_string_lossy().into_owned(),
        ));
        let mut child = spawn_to_files(
            &[
                "bash".to_owned(),
                live.repo
                    .join("script/test/persisted-network-live.sh")
                    .to_string_lossy()
                    .into_owned(),
            ],
            &live.repo,
            &live.env(&refs(&overrides)),
            &Live::unset(),
            &live.work.join("term-ignored-stdout"),
            &live.work.join("term-ignored-stderr"),
        )?;
        let measured = Cell::new(None);
        let timed_out = Cell::new(false);
        let outcome = (|| -> Result<(), String> {
            wait_ready(&mut child, &ready)?;
            let driver = read_owned_pid(&ready).ok_or("ignored-TERM fixture published no PID")?;
            measured.set(Some(driver));
            signal_owned(child.id() as i32, libc::SIGTERM);
            if wait_bounded(&mut child, TEARDOWN).is_none() {
                timed_out.set(true);
            }
            Ok(())
        })();
        let teardown = teardown_live(
            &mut child,
            measured.get(),
            &pidfile,
            &live.events,
            outcome.is_err(),
            None,
        );
        outcome.and(teardown)?;
        if !timed_out.get() {
            return Err("ignored-TERM live shell exited on TERM".to_owned());
        }
        if measured.get().is_some_and(pid_alive) {
            return Err("ignored-TERM live driver survived teardown".to_owned());
        }
        println!("ignored-TERM live-shell control PASS: KILL reaped driver without survivors");
    }

    // --- Pre-readiness ownership -------------------------------------------
    {
        let ready = live.work.join("live-ready-rf");
        let receipt = live.work.join("live-term-rf");
        let pidfile = live.work.join("live-driver-rf.pid");
        let evidence = live.evidence("term-rf")?;
        let binary = live.binary("term-rf", &clean_binary(&live.sha))?;
        fs::write(&live.events, "").map_err(|error| error.to_string())?;
        let mut overrides = env(&ready, &receipt, &pidfile);
        for (key, value) in [
            ("PN_STUB_IGNORE_TERM", "1"),
            ("PN_STUB_NO_READY", "1"),
            ("AGENT_VM_BIN", binary.to_string_lossy().as_ref()),
            ("AGENT_VM_PN_EVIDENCE", evidence.to_string_lossy().as_ref()),
        ] {
            overrides.push((key.to_owned(), value.to_owned()));
        }
        let mut child = spawn_to_files(
            &[
                "bash".to_owned(),
                live.repo
                    .join("script/test/persisted-network-live.sh")
                    .to_string_lossy()
                    .into_owned(),
            ],
            &live.repo,
            &live.env(&refs(&overrides)),
            &Live::unset(),
            &live.work.join("term-rf-stdout"),
            &live.work.join("term-rf-stderr"),
        )?;
        let measured = Cell::new(None);
        let outcome = (|| -> Result<(), String> {
            match wait_ready(&mut child, &ready) {
                Err(error) if error == "signal fixture readiness timeout" => {}
                Err(error) => return Err(format!("readiness-failure control: {error}")),
                Ok(()) => {
                    return Err(
                        "readiness-failure control: live driver unexpectedly became ready"
                            .to_owned(),
                    );
                }
            }
            let driver = read_owned_pid(&pidfile).ok_or(
                "readiness-failure control: driver PID was not published before readiness",
            )?;
            measured.set(Some(driver));
            if !pid_alive(driver) {
                return Err(
                    "readiness-failure control: driver was absent before teardown".to_owned(),
                );
            }
            let owned = live.allocs();
            if owned.is_empty() || !owned.iter().all(|path| path.is_dir()) {
                return Err(
                    "readiness-failure control: scratch was removed while the driver was alive"
                        .to_owned(),
                );
            }
            // TERM resistance: the fixture must survive a bounded TERM, keep its
            // scratch and write no cooperating receipt.
            signal_owned(driver, libc::SIGTERM);
            let deadline = Instant::now() + TEARDOWN;
            while pid_alive(driver) && Instant::now() < deadline {
                std::thread::sleep(POLL);
            }
            if !pid_alive(driver) {
                return Err("readiness-failure control: fixture cooperated with TERM".to_owned());
            }
            if receipt.exists() {
                return Err("readiness-failure control: fixture wrote a TERM receipt".to_owned());
            }
            if !live.allocs().iter().all(|path| path.is_dir()) {
                return Err(
                    "readiness-failure control: scratch was removed while the driver survived TERM"
                        .to_owned(),
                );
            }
            Ok(())
        })();
        let boundary = |owned: &[PathBuf], child: &mut Child| -> Result<(), String> {
            if child.try_wait().ok().flatten().is_none() {
                return Err(
                    "readiness-failure control: scratch removal began with the shell alive"
                        .to_owned(),
                );
            }
            if measured.get().is_some_and(pid_alive) {
                return Err(
                    "readiness-failure control: scratch removal began with the driver alive"
                        .to_owned(),
                );
            }
            if !owned.iter().all(|path| path.is_dir()) {
                return Err(
                    "readiness-failure control: scratch vanished before the removal boundary"
                        .to_owned(),
                );
            }
            Ok(())
        };
        let teardown = teardown_live(
            &mut child,
            measured.get(),
            &pidfile,
            &live.events,
            outcome.is_err(),
            Some(&boundary),
        );
        outcome.and(teardown)?;
        if measured.get().is_some_and(pid_alive) {
            return Err("readiness-failure control: driver survived teardown".to_owned());
        }
        if live.allocs().iter().any(|path| path.exists()) {
            return Err(
                "readiness-failure control: scratch was not removed after absence".to_owned(),
            );
        }
        println!(
            "live readiness-failure + ignored-TERM control PASS: TERM survived and absence established before scratch removal"
        );
    }

    // --- Publication race --------------------------------------------------
    {
        let gate = live.work.join("publication-race.release");
        let _ = fs::remove_file(&gate);
        let ready = live.work.join("live-ready-race");
        let receipt = live.work.join("live-term-race");
        let pidfile = live.work.join("live-driver-race.pid");
        let evidence = live.evidence("term-race")?;
        let binary = live.binary("term-race", &clean_binary(&live.sha))?;
        fs::write(&live.events, "").map_err(|error| error.to_string())?;
        let mut overrides = env(&ready, &receipt, &pidfile);
        for (key, value) in [
            ("PN_STUB_IGNORE_TERM", "1".to_owned()),
            ("PN_STUB_NO_READY", "1".to_owned()),
            ("PN_STUB_GATE", gate.to_string_lossy().into_owned()),
            ("AGENT_VM_BIN", binary.to_string_lossy().into_owned()),
            (
                "AGENT_VM_PN_EVIDENCE",
                evidence.to_string_lossy().into_owned(),
            ),
        ] {
            overrides.push((key.to_owned(), value));
        }
        let mut child = spawn_to_files(
            &[
                "bash".to_owned(),
                live.repo
                    .join("script/test/persisted-network-live.sh")
                    .to_string_lossy()
                    .into_owned(),
            ],
            &live.repo,
            &live.env(&refs(&overrides)),
            &Live::unset(),
            &live.work.join("term-race-stdout"),
            &live.work.join("term-race-stderr"),
        )?;
        let launch_pid = Cell::new(None);
        let outcome = (|| -> Result<(), String> {
            match wait_ready(&mut child, &ready) {
                Err(error) if error == "signal fixture readiness timeout" => {}
                Err(error) => return Err(format!("publication-race control: {error}")),
                Ok(()) => {
                    return Err(
                        "publication-race control: live driver unexpectedly became ready"
                            .to_owned(),
                    );
                }
            }
            if pidfile.exists() {
                return Err(
                    "publication-race control: PN_PID was published before readiness failed"
                        .to_owned(),
                );
            }
            let owned = live.allocs();
            if owned.is_empty() {
                return Err("publication-race control: no owned scratch was allocated".to_owned());
            }
            let driver = read_launch_pid(&owned[0])
                .ok_or("publication-race control: shell launch record was missing")?;
            launch_pid.set(Some(driver));
            if !pid_alive(driver) {
                return Err("publication-race control: launch-record driver was absent".to_owned());
            }
            if !owned.iter().all(|path| path.is_dir()) {
                return Err(
                    "publication-race control: scratch was removed while the driver was alive"
                        .to_owned(),
                );
            }
            Ok(())
        })();
        let boundary = |owned: &[PathBuf], child: &mut Child| -> Result<(), String> {
            if child.try_wait().ok().flatten().is_none() {
                return Err(
                    "publication-race control: scratch removal began with the shell alive"
                        .to_owned(),
                );
            }
            if launch_pid.get().is_none_or(pid_alive) {
                return Err(
                    "publication-race control: scratch removal began with the driver alive"
                        .to_owned(),
                );
            }
            if !owned.iter().all(|path| path.is_dir()) {
                return Err(
                    "publication-race control: scratch vanished before the removal boundary"
                        .to_owned(),
                );
            }
            Ok(())
        };
        // Hand teardown no snapshot at all: with PN_PID withheld it must refresh
        // ownership from the shell's launch record, not from the caller.
        let teardown = teardown_live(
            &mut child,
            None,
            &pidfile,
            &live.events,
            outcome.is_err(),
            Some(&boundary),
        );
        outcome.and(teardown)?;
        if launch_pid.get().is_none_or(pid_alive) {
            return Err("publication-race control: driver survived teardown".to_owned());
        }
        if live.allocs().iter().any(|path| path.exists()) {
            return Err(
                "publication-race control: scratch was not removed after absence".to_owned(),
            );
        }
        println!(
            "live publication-race + ignored-TERM control PASS: launch record owned and reaped the withheld driver"
        );
    }

    // --- Launch-to-handoff interruption ------------------------------------
    {
        let pause_record = live.work.join("prehandoff.paused");
        let pause_release = live.work.join("prehandoff.release");
        let _ = fs::remove_file(&pause_release);
        let pause_hook = live.work.join("prehandoff-pause.sh");
        fs::write(
            &pause_hook,
            "pn_prehandoff_pause() {\n    if [[ \"$BASH_COMMAND\" == \"shell_owns_scratch=0\" ]]; then\n        \
             printf \"%s\" \"$root\" > \"$PN_PAUSE_SCRATCH\"\n        \
             while [[ ! -e \"$PN_PAUSE_RELEASE\" ]]; do sleep \"$PN_PAUSE_INTERVAL\"; done\n    fi\n}\n\
             trap pn_prehandoff_pause DEBUG\n",
        )
        .map_err(|error| error.to_string())?;
        let ready = live.work.join("live-ready-prehandoff");
        let receipt = live.work.join("live-term-prehandoff");
        let pidfile = live.work.join("live-driver-prehandoff.pid");
        let evidence = live.evidence("prehandoff")?;
        let binary = live.binary("prehandoff", &clean_binary(&live.sha))?;
        fs::write(&live.events, "").map_err(|error| error.to_string())?;
        let mut overrides = env(&ready, &receipt, &pidfile);
        for (key, value) in [
            ("PN_STUB_IGNORE_TERM", "1".to_owned()),
            ("PN_STUB_NO_READY", "1".to_owned()),
            ("BASH_ENV", pause_hook.to_string_lossy().into_owned()),
            (
                "PN_PAUSE_SCRATCH",
                pause_record.to_string_lossy().into_owned(),
            ),
            (
                "PN_PAUSE_RELEASE",
                pause_release.to_string_lossy().into_owned(),
            ),
            ("PN_PAUSE_INTERVAL", "0.01".to_owned()),
            ("AGENT_VM_BIN", binary.to_string_lossy().into_owned()),
            (
                "AGENT_VM_PN_EVIDENCE",
                evidence.to_string_lossy().into_owned(),
            ),
        ] {
            overrides.push((key.to_owned(), value));
        }
        let mut child = spawn_to_files(
            &[
                "bash".to_owned(),
                live.repo
                    .join("script/test/persisted-network-live.sh")
                    .to_string_lossy()
                    .into_owned(),
            ],
            &live.repo,
            &live.env(&refs(&overrides)),
            &Live::unset(),
            &live.work.join("term-prehandoff-stdout"),
            &live.work.join("term-prehandoff-stderr"),
        )?;
        let launch_pid = Cell::new(None);
        let scratch = std::cell::RefCell::new(None::<PathBuf>);
        let timed_out = Cell::new(false);
        let outcome = (|| -> Result<(), String> {
            // Both the paused shell and the driver's own PID publication: the
            // fixture publishes only after registering SIG_IGN, so an observed
            // PID proves the TERM below will be ignored.
            let deadline = Instant::now() + READINESS;
            while !(pause_record.exists() && pidfile.exists()) && Instant::now() < deadline {
                std::thread::sleep(POLL);
            }
            if !pause_record.exists() {
                return Err(
                    "pre-handoff control: shell never reached the handoff boundary".to_owned(),
                );
            }
            if !pidfile.exists() {
                return Err(
                    "pre-handoff control: driver never registered TERM handling before handoff"
                        .to_owned(),
                );
            }
            let root = PathBuf::from(
                fs::read_to_string(&pause_record).map_err(|error| error.to_string())?,
            );
            *scratch.borrow_mut() = Some(root.clone());
            let driver = read_launch_pid(&root)
                .ok_or("pre-handoff control: launch record was absent before handoff")?;
            launch_pid.set(Some(driver));
            let published = read_owned_pid(&pidfile)
                .ok_or("pre-handoff control: published PID was unreadable")?;
            if driver != published {
                return Err(
                    "pre-handoff control: launch record and published PID disagreed".to_owned(),
                );
            }
            if !pid_alive(driver) {
                return Err("pre-handoff control: driver was absent before handoff".to_owned());
            }
            signal_owned(child.id() as i32, libc::SIGTERM);
            if wait_bounded(&mut child, TEARDOWN).is_none() {
                timed_out.set(true);
            }
            if !timed_out.get() {
                return Err(
                    "pre-handoff control: shell exited without reaping the ignored-TERM driver"
                        .to_owned(),
                );
            }
            if !root.is_dir() || !root.join("driver.pid").exists() {
                return Err(
                    "pre-handoff control: shell removed identity or scratch while the driver lived"
                        .to_owned(),
                );
            }
            if !pid_alive(driver) {
                return Err("pre-handoff control: driver was already absent".to_owned());
            }
            Ok(())
        })();
        let boundary = |owned: &[PathBuf], child: &mut Child| -> Result<(), String> {
            if child.try_wait().ok().flatten().is_none() {
                return Err(
                    "pre-handoff control: scratch removal began with the shell alive".to_owned(),
                );
            }
            if launch_pid.get().is_none_or(pid_alive) {
                return Err(
                    "pre-handoff control: scratch removal began with the driver alive".to_owned(),
                );
            }
            if !owned.iter().all(|path| path.is_dir()) {
                return Err(
                    "pre-handoff control: scratch vanished before the removal boundary".to_owned(),
                );
            }
            Ok(())
        };
        let teardown = teardown_live(
            &mut child,
            launch_pid.get(),
            &pidfile,
            &live.events,
            outcome.is_err(),
            Some(&boundary),
        );
        outcome.and(teardown)?;
        if child.try_wait().ok().flatten().is_none() {
            return Err("pre-handoff control: shell survived teardown".to_owned());
        }
        if launch_pid.get().is_none_or(pid_alive) {
            return Err("pre-handoff control: driver survived teardown".to_owned());
        }
        if live.allocs().iter().any(|path| path.exists()) {
            return Err("pre-handoff control: scratch was not removed after absence".to_owned());
        }
        println!(
            "live launch-to-handoff + ignored-TERM control PASS: identity and scratch retained until driver absence"
        );
    }

    // --- Unresolved ownership fails closed ---------------------------------
    {
        let gate = live.work.join("unresolved-owner.release");
        let _ = fs::remove_file(&gate);
        let ready = live.work.join("live-ready-unresolved");
        let receipt = live.work.join("live-term-unresolved");
        let pidfile = live.work.join("live-driver-unresolved.pid");
        let evidence = live.evidence("term-unresolved")?;
        let binary = live.binary("term-unresolved", &clean_binary(&live.sha))?;
        fs::write(&live.events, "").map_err(|error| error.to_string())?;
        let mut overrides = env(&ready, &receipt, &pidfile);
        for (key, value) in [
            ("PN_STUB_IGNORE_TERM", "1".to_owned()),
            ("PN_STUB_NO_READY", "1".to_owned()),
            ("PN_STUB_GATE", gate.to_string_lossy().into_owned()),
            ("AGENT_VM_BIN", binary.to_string_lossy().into_owned()),
            (
                "AGENT_VM_PN_EVIDENCE",
                evidence.to_string_lossy().into_owned(),
            ),
        ] {
            overrides.push((key.to_owned(), value));
        }
        let mut child = spawn_to_files(
            &[
                "bash".to_owned(),
                live.repo
                    .join("script/test/persisted-network-live.sh")
                    .to_string_lossy()
                    .into_owned(),
            ],
            &live.repo,
            &live.env(&refs(&overrides)),
            &Live::unset(),
            &live.work.join("term-unresolved-stdout"),
            &live.work.join("term-unresolved-stderr"),
        )?;
        let orphan = Cell::new(None);
        let outcome = (|| -> Result<(), String> {
            match wait_ready(&mut child, &ready) {
                Err(error) if error == "signal fixture readiness timeout" => {}
                Err(error) => return Err(format!("unresolved-ownership control: {error}")),
                Ok(()) => {
                    return Err(
                        "unresolved-ownership control: live driver unexpectedly became ready"
                            .to_owned(),
                    );
                }
            }
            if pidfile.exists() {
                return Err("unresolved-ownership control: PN_PID was published".to_owned());
            }
            let owned = live.allocs();
            if owned.is_empty() {
                return Err(
                    "unresolved-ownership control: no owned scratch was allocated".to_owned(),
                );
            }
            let root = owned[0].clone();
            let driver = read_launch_pid(&root)
                .ok_or("unresolved-ownership control: launch record was absent")?;
            if !pid_alive(driver) {
                return Err("unresolved-ownership control: launch record was stale".to_owned());
            }
            orphan.set(Some(driver));
            // Withhold every identity: the shell's launch record goes away, and
            // PN_PID was never published.
            fs::remove_file(root.join("driver.pid")).map_err(|error| error.to_string())?;
            match teardown_live(&mut child, None, &pidfile, &live.events, false, None) {
                Err(error) if error.contains("ownership unresolved") => {}
                Err(error) => {
                    return Err(format!("unresolved-ownership control: {error}"))
                }
                Ok(()) => {
                    return Err(
                        "unresolved-ownership control: teardown deleted scratch with ownership unresolved"
                            .to_owned(),
                    )
                }
            }
            if !pid_alive(driver) {
                return Err(
                    "unresolved-ownership control: driver was not preserved as evidence".to_owned(),
                );
            }
            if !root.is_dir() {
                return Err(
                    "unresolved-ownership control: scratch was removed while ownership was unresolved"
                        .to_owned(),
                );
            }
            Ok(())
        })();
        // Ownership was deliberately withheld: recover the recorded driver, or
        // the launch record if the shell died before it was captured, and remove
        // scratch only through the seam, which refuses while absence is unproven.
        let reaped = emergency_reap(&mut child, orphan.get(), &live.events);
        let reaped = match (outcome, reaped) {
            (Err(primary), _) => return Err(primary),
            (Ok(()), Err(error)) => return Err(error),
            (Ok(()), Ok(reaped)) => reaped,
        };
        if reaped.is_none() || reaped.is_some_and(pid_alive) {
            return Err("unresolved-ownership control: driver survived cleanup".to_owned());
        }
        println!("unresolved-ownership control PASS: fail-closed teardown kept scratch and raised");
    }

    // --- Failure before ownership capture ----------------------------------
    {
        let gate = live.work.join("early-exit.release");
        let _ = fs::remove_file(&gate);
        let ready = live.work.join("live-ready-early");
        let receipt = live.work.join("live-term-early");
        let pidfile = live.work.join("live-driver-early.pid");
        let evidence = live.evidence("term-early")?;
        let binary = live.binary("term-early", &clean_binary(&live.sha))?;
        fs::write(&live.events, "").map_err(|error| error.to_string())?;
        let mut overrides = env(&ready, &receipt, &pidfile);
        for (key, value) in [
            ("PN_STUB_IGNORE_TERM", "1".to_owned()),
            ("PN_STUB_NO_READY", "1".to_owned()),
            ("PN_STUB_GATE", gate.to_string_lossy().into_owned()),
            ("AGENT_VM_BIN", binary.to_string_lossy().into_owned()),
            (
                "AGENT_VM_PN_EVIDENCE",
                evidence.to_string_lossy().into_owned(),
            ),
        ] {
            overrides.push((key.to_owned(), value));
        }
        let mut child = spawn_to_files(
            &[
                "bash".to_owned(),
                live.repo
                    .join("script/test/persisted-network-live.sh")
                    .to_string_lossy()
                    .into_owned(),
            ],
            &live.repo,
            &live.env(&refs(&overrides)),
            &Live::unset(),
            &live.work.join("term-early-stdout"),
            &live.work.join("term-early-stderr"),
        )?;
        let observed = Cell::new(None);
        let scratch = std::cell::RefCell::new(None::<PathBuf>);
        let outcome = (|| -> Result<(), String> {
            // Wait for the shell to record its driver identity, then release the
            // gate so the fixture publishes its PID after installing SIG_IGN.
            let deadline = Instant::now() + READINESS;
            while Instant::now() < deadline {
                let allocated = live.allocs();
                if let Some(first) = allocated.first()
                    && let Some(driver) = read_launch_pid(first)
                {
                    *scratch.borrow_mut() = Some(first.clone());
                    observed.set(Some(driver));
                    break;
                }
                std::thread::sleep(POLL);
            }
            if scratch.borrow().is_none() {
                return Err(
                    "failure-before-ownership control: shell never recorded its driver".to_owned(),
                );
            }
            fs::write(&gate, "release").map_err(|error| error.to_string())?;
            let registration = Instant::now() + READINESS;
            while !pidfile.exists() && Instant::now() < registration {
                std::thread::sleep(POLL);
            }
            if !pidfile.exists() {
                return Err(
                    "failure-before-ownership control: fixture never registered TERM handling"
                        .to_owned(),
                );
            }
            let published = read_owned_pid(&pidfile)
                .ok_or("failure-before-ownership control: published PID was unreadable")?;
            let driver = observed.get().expect("a recorded driver");
            if published != driver {
                return Err(
                    "failure-before-ownership control: launch record and published PID disagreed"
                        .to_owned(),
                );
            }
            if !pid_alive(driver) {
                return Err("failure-before-ownership control: driver was absent".to_owned());
            }
            fs::remove_file(&pidfile).map_err(|error| error.to_string())?;
            signal_owned(child.id() as i32, libc::SIGKILL);
            match wait_ready(&mut child, &ready) {
                Err(error) if error == "signal fixture exited before readiness" => {}
                Err(error) => return Err(format!("failure-before-ownership control: {error}")),
                Ok(()) => {
                    return Err(
                        "failure-before-ownership control: shell was KILLed but readiness arrived"
                            .to_owned(),
                    );
                }
            }
            // The bounded failure is not absence: identity and scratch survive
            // it, and the seam must refuse while either is unproven.
            let root = scratch.borrow().clone().expect("a recorded scratch");
            if !root.is_dir() || !root.join("driver.pid").exists() {
                return Err(
                    "failure-before-ownership control: shell death erased driver identity or scratch"
                        .to_owned(),
                );
            }
            if !pid_alive(driver) {
                return Err(
                    "failure-before-ownership control: driver did not outlive the shell".to_owned(),
                );
            }
            for (driver_absent, shell_absent) in [(false, true), (true, false)] {
                match discard_owned_scratch(&live.allocs(), driver_absent, shell_absent, false) {
                    Err(error) if error.contains("ownership is unresolved") => {}
                    Err(error) => return Err(format!("failure-before-ownership control: {error}")),
                    Ok(()) => {
                        return Err(format!(
                            "failure-before-ownership control: seam removed scratch with driver_absent={driver_absent} shell_absent={shell_absent}"
                        ));
                    }
                }
            }
            if !root.is_dir() || !root.join("driver.pid").exists() {
                return Err(
                    "failure-before-ownership control: seam removed scratch with unknown ownership"
                        .to_owned(),
                );
            }
            Ok(())
        })();
        // The control hands cleanup no snapshot, exactly as if the shell had
        // died before readiness: recovery must come from the scratch.
        let recovered = emergency_reap(&mut child, None, &live.events);
        let recovered = match (outcome, recovered) {
            (Err(primary), _) => return Err(primary),
            (Ok(()), Err(error)) => return Err(error),
            (Ok(()), Ok(recovered)) => recovered,
        };
        if recovered != observed.get() || recovered.is_some_and(pid_alive) {
            return Err("failure-before-ownership control: driver survived cleanup".to_owned());
        }
        if live.allocs().iter().any(|path| path.exists()) {
            return Err(
                "failure-before-ownership control: scratch was not removed after absence"
                    .to_owned(),
            );
        }
        println!(
            "live failure-before-ownership control PASS: recovered identity and reaped before scratch removal"
        );
    }
    Ok(())
}

fn refs(overrides: &[(String, String)]) -> Vec<(&str, &str)> {
    overrides
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect()
}
