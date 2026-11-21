//! The persisted-network native rows (#696).
//!
//! Ported from `script/test/lib/persisted-network.py`, which was the last host
//! Python in this suite. The rows are native evidence: each one launches the
//! real `agent-vm` binary against a persisted `[network]` grant and checks what
//! the guest actually reached. `persisted-network-live.sh` owns the provenance
//! gate and the launch record; this command owns the rows, their oracle
//! comparisons and their teardown.
//!
//! Four properties are load-bearing and easy to lose in a port:
//!
//! * The fixture port is bound once, up front, before any row can run. A busy
//!   port must fail the run rather than let a denial count as evidence, which is
//!   why there is no `SO_REUSEPORT` and no retry.
//! * Every wait, accept, socket read and thread join here is bounded. The
//!   receipt server accepts with a poll interval and a stop flag; the absence
//!   proof connects with a timeout instead of trusting a joined thread.
//! * A validation-only refusal is compared against a full
//!   `snapshot_validation` of the row's private roots, so a refusal that still
//!   wrote launch state fails.
//! * Inventory hashing streams the file. A native cache may hold a whole disk
//!   image, and a snapshot that reads it into memory is not an observation the
//!   host can afford.
//!
//! The stderr oracle is the tracked fixture `expected-stderr.tsv`, rendered here
//! with this module's own parser. `script/test/lib/persisted-network.sh` renders
//! the same file with `awk`; the controls in `persisted_network_controls` hold
//! the two renderings equal so a change to one cannot silently drift.

use std::{
    collections::BTreeMap,
    fs::{self, File, Permissions},
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use clap::Args;
use sha2::{Digest, Sha256};

use crate::{
    egress_cases as cases, egress_fixtures as fixtures, egress_launch as launch, egress_run,
};

/// The port the guest probe dials on the host.
pub const FIXTURE_PORT: u16 = 18090;
/// The marker id every row requests; the receipt server answers `receipt marker`.
const MARKER: &str = "marker";
/// The guest's reach line is `PN_REACHED marker`; a denial is `PN_DENIED marker`.
const REACHED: &str = "PN_REACHED marker";
const DENIED: &str = "PN_DENIED marker";
const WROTE: &str = "PN4_WRITE_OK";
/// Scratch-owned roots, in the order `snapshot_validation` walks them.
const ROOTS: [&str; 4] = ["home", "config", "state", "proj"];
/// Bounded join and absence probe for the receipt server.
const FIXTURE_TEARDOWN: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(5);
/// `sockaddr_un.sun_path` is 104 bytes on macOS (103 usable) and 108 on Linux.
const SUN_PATH_USABLE: usize = if cfg!(target_os = "macos") { 103 } else { 107 };

#[derive(Debug, Args)]
pub struct PersistedNetworkArgs {
    /// The checkout whose `script/test/fixtures` the rows copy from.
    #[arg(long)]
    repo_root: PathBuf,

    #[arg(value_names = ["ROOT", "EVIDENCE", "BINARY", "IMAGE"])]
    inputs: Vec<PathBuf>,
}

/// What a row expects the guest to observe.
#[derive(Clone, Copy, PartialEq)]
enum Expected {
    /// The guest runs and reports `PN_DENIED marker`; no receipt may arrive.
    Deny,
    /// The guest runs and reports `PN_REACHED marker`; exactly one receipt.
    Reach,
    /// The launch refuses before the guest runs, and must mutate nothing.
    Refuse,
}

/// What one row asserts about the guest, the launch and the shared oracle.
#[derive(Clone, Copy)]
struct RowSpec {
    guest: Guest,
    expected: Expected,
    /// The stderr oracle row whose substrings the log must carry.
    oracle: Option<&'static str>,
}

#[derive(Clone, Copy, PartialEq)]
enum Guest {
    Probe,
    Write,
}

fn canonical(path: &Path) -> Result<PathBuf, String> {
    path.canonicalize()
        .map_err(|error| format!("{}: {error}", path.display()))
}

fn write_json(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    let mut text = serde_json::to_string_pretty(value).map_err(|error| error.to_string())?;
    text.push('\n');
    fs::write(path, text).map_err(|error| format!("{}: {error}", path.display()))
}

/// Every row of the tracked stderr oracle that names `row`.
///
/// One parser, used by the driver and by the controls that hold it equal to the
/// shell's `awk` rendering. A row with no line is an error, not an empty oracle:
/// an oracle that silently matches nothing would make every log conform.
pub fn expected_stderr(fixtures: &Path, row: &str) -> Result<Vec<String>, String> {
    let path = fixtures.join("expected-stderr.tsv");
    let text = fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut texts = Vec::new();
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, value)) = line.split_once('\t') else {
            return Err(format!("{}: not a row<TAB>text line", path.display()));
        };
        if name == row {
            texts.push(value.to_owned());
        }
    }
    if texts.is_empty() {
        return Err(format!("{}: no row {row}", path.display()));
    }
    Ok(texts)
}

/// Refuse a log that is missing any substring the shared oracle requires.
///
/// `oracle` names the row whose substrings apply; `None` asserts nothing, which
/// is what a row with no shared diagnostic needs.
pub fn require_shared_stderr_oracle(
    fixtures: &Path,
    row: &str,
    text: &str,
    oracle: Option<&str>,
) -> Result<(), String> {
    let Some(oracle) = oracle else {
        return Ok(());
    };
    for substring in expected_stderr(fixtures, oracle)? {
        if !text.contains(&substring) {
            return Err(format!("{row}: missing shared stderr oracle {substring:?}"));
        }
    }
    Ok(())
}

/// The authoritative-observation snapshot of one row's private roots.
///
/// SQLite rewrites WAL/SHM/journal sidecars whenever a connection attaches, so
/// they are skipped by name; a symlink is recorded by its target; everything
/// else by mode, size and a streamed SHA-256. Reading a block at a time is the
/// point: a native cache can hold a disk image far larger than the host should
/// map to hash it.
pub fn snapshot_validation(work: &Path) -> Result<BTreeMap<String, (u32, u64, String)>, String> {
    let mut snapshot = BTreeMap::new();
    for root in ROOTS {
        let directory = work.join(root);
        let mut paths = Vec::new();
        collect(&directory, &mut paths)?;
        paths.sort();
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
                digest(&path)?
            } else {
                String::new()
            };
            snapshot.insert(name, (metadata.mode(), metadata.size(), detail));
        }
    }
    Ok(snapshot)
}

fn collect(directory: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("{}: {error}", directory.display())),
    };
    for entry in entries {
        let entry = entry.map_err(|error| format!("{}: {error}", directory.display()))?;
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

/// One MiB at a time, so the peak allocation does not follow the file size.
fn digest(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut block = vec![0u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut block)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&block[..read]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// The `sockaddr_un` budget for a state dir, the check `pn_fresh_state` made.
///
/// A row whose state dir cannot produce the runtime's control socket would fail
/// later with a truncated path, so it is refused here by name.
pub fn state_dir_fits(state: &Path) -> Result<(), String> {
    let hex = "0".repeat(24);
    let socket = format!(
        "{}/msb-home/run/sandboxes/{hex}/control.sock",
        state.display()
    );
    // Bytes, not characters: a multibyte state path is measured in bytes.
    let length = socket.len();
    if length > SUN_PATH_USABLE {
        return Err(format!(
            "state directory does not fit the control socket budget ({length} > {SUN_PATH_USABLE}): {}",
            state.display()
        ));
    }
    Ok(())
}

fn snapshot_json(snapshot: &BTreeMap<String, (u32, u64, String)>) -> serde_json::Value {
    let mut object = serde_json::Map::new();
    for (name, (mode, size, detail)) in snapshot {
        object.insert(name.clone(), serde_json::json!([mode, size, detail]));
    }
    serde_json::Value::Object(object)
}

fn relative_listing(root: &Path) -> Result<Vec<String>, String> {
    let mut paths = Vec::new();
    collect(root, &mut paths)?;
    let mut names = Vec::new();
    for path in paths {
        names.push(
            path.strip_prefix(root)
                .map_err(|error| error.to_string())?
                .to_string_lossy()
                .into_owned(),
        );
    }
    names.sort();
    Ok(names)
}

/// The host receipt server: bound once, served until stopped, absence proven.
struct Receipts {
    directory: PathBuf,
    stop: Arc<AtomicBool>,
    alive: Arc<AtomicBool>,
    server: Option<JoinHandle<()>>,
}

impl Receipts {
    fn start(evidence: &Path) -> Result<Self, String> {
        // No `SO_REUSEPORT` and no retry: if another fixture holds the port, a
        // denial would be indistinguishable from a busy host, so refuse now.
        let listener = fixtures::bind_tcp(FIXTURE_PORT).map_err(|error| {
            format!("cannot bind the fixture port {FIXTURE_PORT} before any row: {error}")
        })?;
        let directory = evidence.join("fixture");
        fs::create_dir_all(&directory)
            .map_err(|error| format!("{}: {error}", directory.display()))?;
        let stop = Arc::new(AtomicBool::new(false));
        let alive = Arc::new(AtomicBool::new(true));
        let server = {
            let directory = directory.clone();
            let stop = Arc::clone(&stop);
            let alive = Arc::clone(&alive);
            std::thread::Builder::new()
                .name("pn-receipts".to_owned())
                .spawn(move || {
                    let _ = fixtures::serve_tcp(listener, directory, stop);
                    alive.store(false, Ordering::SeqCst);
                })
                .map_err(|error| format!("receipt server thread: {error}"))?
        };
        let identity = fixtures::process_identity(std::process::id())?
            .ok_or("fixture identity unavailable")?;
        write_json(
            &evidence.join("fixture.identity.json"),
            &serde_json::json!({
                "pid": std::process::id(),
                "start": [identity[0], identity[1]],
            }),
        )?;
        Ok(Self {
            directory,
            stop,
            alive,
            server: Some(server),
        })
    }

    /// Receipts naming the marker, whole file. The caller takes a delta.
    fn receipts(&self) -> Result<Vec<String>, String> {
        let path = self.directory.join(fixtures::RECEIPTS_NAME);
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(format!("{}: {error}", path.display())),
        };
        Ok(text.lines().map(str::to_owned).collect())
    }

    /// Receipts for the marker that arrived after `from`.
    fn marker_dialects(&self, from: usize) -> Result<usize, String> {
        let lines = self.receipts()?;
        Ok(lines
            .iter()
            .skip(from)
            .filter(|line| {
                let mut fields = line.split_whitespace();
                fields.next() == Some("tcp")
                    && fields.next() == Some("18090")
                    && fields.last() == Some(MARKER)
            })
            .count())
    }

    fn assert_alive(&self) -> Result<(), String> {
        if self.alive.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err("the receipt server stopped during a row".to_owned())
        }
    }

    /// Stop accepting, join bounded, then prove the port answers nothing.
    ///
    /// A joined thread is not absence: the guarantee a row needs is that no
    /// process still answers on the fixture port.
    fn stop(mut self) -> Result<(), String> {
        self.stop.store(true, Ordering::SeqCst);
        let mut errors = Vec::new();
        let Some(server) = self.server.take() else {
            return Ok(());
        };
        let deadline = Instant::now() + FIXTURE_TEARDOWN;
        while !server.is_finished() && Instant::now() < deadline {
            std::thread::sleep(POLL);
        }
        if server.is_finished() {
            let _ = server.join();
        } else {
            errors.push("the receipt server did not stop within its bound".to_owned());
        }
        let address = std::net::SocketAddr::from(([127, 0, 0, 1], FIXTURE_PORT));
        if std::net::TcpStream::connect_timeout(&address, FIXTURE_TEARDOWN).is_ok() {
            errors.push(format!(
                "the fixture port {FIXTURE_PORT} still answers after teardown"
            ));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

/// One row's owned scratch and the launches recorded against it.
struct Row {
    work: PathBuf,
    launches: Vec<launch::OwnedLaunch>,
}

struct Driver {
    root: PathBuf,
    evidence: PathBuf,
    fixtures: PathBuf,
    binary: String,
    image: String,
    rows: Vec<Row>,
    receipts: Option<Receipts>,
}

pub fn run(args: PersistedNetworkArgs) -> Result<String, String> {
    if args.inputs.len() != 4 {
        return Err(
            "usage: persisted-network --repo-root DIR ROOT EVIDENCE BINARY IMAGE".to_owned(),
        );
    }
    let root = canonical(&args.inputs[0])?;
    let evidence = canonical(&args.inputs[1])?;
    let fixtures = args
        .repo_root
        .join("script/test/fixtures")
        .canonicalize()
        .map_err(|error| format!("{}: {error}", args.repo_root.display()))?;
    let mut driver = Driver {
        receipts: Some(Receipts::start(&evidence)?),
        root,
        evidence,
        fixtures,
        binary: args.inputs[2].to_string_lossy().into_owned(),
        image: args.inputs[3].to_string_lossy().into_owned(),
        rows: Vec::new(),
    };
    let errors = driver.drive();
    if errors.is_empty() {
        Ok("persisted network: all rows passed".to_owned())
    } else {
        Err(errors.join("\n"))
    }
}

impl Driver {
    /// Run every row, then clean up whatever happened. Errors are collected, not
    /// raised, so teardown always runs and the caller sees every failure at once.
    fn drive(&mut self) -> Vec<String> {
        let mut errors = Vec::new();
        let outcome = self.rows();
        if let Err(error) = outcome {
            errors.push(error);
        }
        errors.extend(self.finish());
        errors
    }

    fn rows(&mut self) -> Result<(), String> {
        for (row, expected, saved, flags) in [
            ("PN1", Expected::Deny, false, Vec::new()),
            ("PN2", Expected::Reach, true, Vec::new()),
            (
                "PN3",
                Expected::Deny,
                true,
                vec!["--allow-host=false".to_owned()],
            ),
        ] {
            let index = self.fresh(row)?;
            let config = saved.then(|| {
                self.config(
                    index,
                    &fs::read_to_string(
                        self.fixtures.join("persisted-network/user-allow-host.toml"),
                    )
                    .expect("the tracked grant fixture"),
                )
            });
            let before = config
                .as_ref()
                .map(|path| fs::read(path).expect("a readable config"));
            let project = self.rows[index].work.join("proj");
            self.launch(
                row,
                index,
                &project,
                &flags,
                RowSpec {
                    guest: Guest::Probe,
                    expected,
                    oracle: Some(row),
                },
            )?;
            if let (Some(config), Some(before)) = (config, before) {
                let after =
                    fs::read(&config).map_err(|error| format!("{}: {error}", config.display()))?;
                if after != before {
                    return Err(format!("{row}: the launch rewrote the user config.toml"));
                }
            }
        }

        let index = self.fresh("PN4")?;
        let work = self.rows[index].work.clone();
        let p1 = work.join("proj");
        let p2 = work.join("p2");
        fs::create_dir_all(&p2).map_err(|error| format!("{}: {error}", p2.display()))?;
        for name in ["egress-probe.sh", "guest-pn-probe.sh"] {
            fs::copy(p1.join(name), p2.join(name))
                .map_err(|error| format!("{}: {error}", p2.join(name).display()))?;
        }
        let target = p1.join("dotfiles/agent-vm.toml");
        fs::create_dir_all(target.parent().expect("a parent"))
            .map_err(|error| format!("{}: {error}", target.display()))?;
        fs::write(&target, "# tools/image dotfile without authority\n")
            .map_err(|error| format!("{}: {error}", target.display()))?;
        fs::set_permissions(&target, Permissions::from_mode(0o600))
            .map_err(|error| format!("{}: {error}", target.display()))?;
        let config = work.join("home/.config/agent-vm/config.toml");
        std::os::unix::fs::symlink(&target, &config)
            .map_err(|error| format!("{}: {error}", config.display()))?;
        self.launch(
            "PN4-A",
            index,
            &p1,
            &[],
            RowSpec {
                guest: Guest::Write,
                expected: Expected::Reach,
                oracle: None,
            },
        )?;
        let written = fs::read_to_string(&target)
            .map_err(|error| format!("{}: {error}", target.display()))?;
        if !written.ends_with("[network]\nallow_host = true\n") {
            return Err("PN4-A: the dotfile target did not gain the persisted grant".to_owned());
        }
        self.launch(
            "PN4-B",
            index,
            &p2,
            &[],
            RowSpec {
                guest: Guest::Probe,
                expected: Expected::Refuse,
                oracle: Some("PN4B"),
            },
        )?;
        fs::remove_file(&config).map_err(|error| format!("{}: {error}", config.display()))?;
        fs::copy(&target, &config).map_err(|error| format!("{}: {error}", config.display()))?;
        fs::set_permissions(&config, Permissions::from_mode(0o600))
            .map_err(|error| format!("{}: {error}", config.display()))?;
        self.launch(
            "PN4c",
            index,
            &p2,
            &[],
            RowSpec {
                guest: Guest::Probe,
                expected: Expected::Reach,
                oracle: None,
            },
        )?;

        let index = self.fresh("PN5")?;
        let grant =
            fs::read_to_string(self.fixtures.join("persisted-network/user-allow-host.toml"))
                .map_err(|error| error.to_string())?;
        self.config(index, &grant);
        let home = self.rows[index].work.join("home");
        self.launch(
            "PN5",
            index,
            &home,
            &[],
            RowSpec {
                guest: Guest::Probe,
                expected: Expected::Refuse,
                oracle: Some("PN5"),
            },
        )
    }

    /// Create one row's scratch: the four private roots, the guest fixtures and
    /// the state-dir budget check `pn_fresh_state` performed.
    fn fresh(&mut self, name: &str) -> Result<usize, String> {
        let work = self.root.join(name);
        for root in ROOTS {
            let path = work.join(root);
            fs::create_dir_all(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        }
        let config = work.join("home/.config/agent-vm");
        fs::create_dir_all(&config).map_err(|error| format!("{}: {error}", config.display()))?;
        fs::set_permissions(&config, Permissions::from_mode(0o700))
            .map_err(|error| format!("{}: {error}", config.display()))?;
        state_dir_fits(&work.join("state"))?;
        let project = work.join("proj");
        for (source, name) in [
            (self.fixtures.join("egress-probe.sh"), "egress-probe.sh"),
            (
                self.fixtures.join("persisted-network/guest-pn-probe.sh"),
                "guest-pn-probe.sh",
            ),
            (
                self.fixtures.join("persisted-network/guest-pn4-write.sh"),
                "guest-pn4-write.sh",
            ),
        ] {
            let destination = project.join(name);
            fs::copy(&source, &destination)
                .map_err(|error| format!("{}: {error}", destination.display()))?;
            let mut permissions = fs::metadata(&destination)
                .map_err(|error| format!("{}: {error}", destination.display()))?
                .permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&destination, permissions)
                .map_err(|error| format!("{}: {error}", destination.display()))?;
        }
        self.rows.push(Row {
            work,
            launches: Vec::new(),
        });
        Ok(self.rows.len() - 1)
    }

    fn config(&self, index: usize, text: &str) -> PathBuf {
        let path = self.rows[index]
            .work
            .join("home/.config/agent-vm/config.toml");
        fs::write(&path, text).expect("the row's config dir");
        fs::set_permissions(&path, Permissions::from_mode(0o600)).expect("a writable config");
        path
    }

    /// Launch one row and check everything the row claims.
    fn launch(
        &mut self,
        row: &str,
        index: usize,
        project: &Path,
        flags: &[String],
        spec: RowSpec,
    ) -> Result<(), String> {
        let RowSpec {
            guest,
            expected,
            oracle,
        } = spec;
        let work = self.rows[index].work.clone();
        let receipts = self
            .receipts
            .as_ref()
            .ok_or("the receipt server is no longer running")?;
        let offset = receipts.receipts()?.len();
        let before = snapshot_validation(&work)?;
        let state_before = relative_listing(&work.join("state"))?;
        write_json(
            &self.evidence.join(format!("{row}-before.json")),
            &serde_json::json!({
                "receipts_offset": offset,
                "snapshot": snapshot_json(&before),
                "state": state_before,
            }),
        )?;

        let mut env = fixtures::base_environment(&work);
        env.push(("AGENT_VM_BIN".to_owned(), self.binary.clone()));
        env.push(("AGENT_VM_LIVE_TEST_IMAGE".to_owned(), self.image.clone()));
        let snippet = match guest {
            Guest::Write => "echo GUEST_EXECUTED; bash ./guest-pn4-write.sh".to_owned(),
            Guest::Probe => {
                format!("echo GUEST_EXECUTED; bash ./guest-pn-probe.sh {FIXTURE_PORT} {MARKER}")
            }
        };
        let mut argv = vec![
            self.binary.clone(),
            "--no-git".to_owned(),
            "--image".to_owned(),
            self.image.clone(),
        ];
        argv.extend(flags.iter().cloned());
        argv.extend([
            "shell".to_owned(),
            "bash".to_owned(),
            "-c".to_owned(),
            snippet,
        ]);
        let command = cases::Command {
            case: row.to_owned(),
            variant: "native".to_owned(),
            tool: Some("shell".to_owned()),
            kind: if expected == Expected::Refuse {
                "validation-only".to_owned()
            } else {
                "guest".to_owned()
            },
            env,
            argv,
            cwd: project.to_string_lossy().into_owned(),
            timeout: 300.0,
            grace: 10.0,
            declared_extras: Vec::new(),
            prerequisites: Vec::new(),
            controls: None,
            setup: Vec::new(),
            expected_attempts: Vec::new(),
            attempt_expectations: None,
            attempt_protocols: None,
            supervisor: cases::SUPERVISOR.to_owned(),
        };
        let owned = launch::OwnedLaunch::new(&work, &command, row.to_owned())?;
        let status = owned.run()?;
        let text = fs::read_to_string(owned.log())
            .map_err(|error| format!("{}: {error}", owned.log().display()))?;
        let errors = owned.errors();
        if status == 124 || status == 130 || status == 143 || !errors.is_empty() {
            return Err(format!(
                "{row}: timeout/interrupt/observation error: {status} {errors:?}"
            ));
        }
        require_shared_stderr_oracle(&self.fixtures.join("persisted-network"), row, &text, oracle)?;
        receipts.assert_alive()?;
        let count = receipts.marker_dialects(offset)?;
        match expected {
            Expected::Refuse => {
                if status == 0 {
                    return Err(format!("{row}: refusal launch exited 0"));
                }
                for forbidden in ["GUEST_EXECUTED", "PN_REACHED"] {
                    if text.contains(forbidden) {
                        return Err(format!("{row}: refusal log contains {forbidden}"));
                    }
                }
                if count != 0 {
                    return Err(format!("{row}: refusal produced {count} marker receipt(s)"));
                }
                let state = work.join("state").join(owned.project_hash());
                if state.exists() {
                    return Err(format!(
                        "{row}: refusal created launch state {}",
                        state.display()
                    ));
                }
                if snapshot_validation(&work)? != before {
                    return Err(format!("{row}: refusal mutated the private roots"));
                }
            }
            _ => {
                if status != 0 {
                    return Err(format!("{row}: launch exited {status}"));
                }
                match guest {
                    Guest::Write => {
                        if !text.contains(WROTE) {
                            return Err(format!("{row}: the guest did not report {WROTE}"));
                        }
                    }
                    Guest::Probe => {
                        let wanted = if expected == Expected::Reach {
                            REACHED
                        } else {
                            DENIED
                        };
                        if !text.contains(wanted) {
                            return Err(format!("{row}: the guest did not report {wanted}"));
                        }
                        let want = usize::from(expected == Expected::Reach);
                        if count != want {
                            return Err(format!(
                                "{row}: expected {want} marker receipt(s), saw {count}"
                            ));
                        }
                    }
                }
            }
        }
        write_json(
            &self.evidence.join(format!("{row}-after.json")),
            &serde_json::json!({
                "marker_receipts": count,
                "snapshot": snapshot_json(&snapshot_validation(&work)?),
                "status": status,
            }),
        )?;
        let cleanup = owned.cleanup(None);
        if !cleanup.is_empty() {
            return Err(format!("{row}: cleanup {cleanup:?}"));
        }
        self.rows[index].launches.push(owned);
        let mut summary = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.evidence.join("summary.tsv"))
            .map_err(|error| error.to_string())?;
        writeln!(summary, "{row}\tPASS").map_err(|error| error.to_string())?;
        println!("PASS {row}");
        Ok(())
    }

    /// Reap every row, prove the fixture is gone, keep the evidence.
    fn finish(&mut self) -> Vec<String> {
        let mut errors = Vec::new();
        let rows = std::mem::take(&mut self.rows);
        for row in &rows {
            errors.extend(egress_run::cleanup_run(
                &row.work,
                &self.binary,
                &row.launches,
                None,
            ));
        }
        let receipts = self.receipts.take();
        let identity = fs::read(self.evidence.join("fixture.identity.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .unwrap_or(serde_json::Value::Null);
        match receipts.map(Receipts::stop).unwrap_or(Ok(())) {
            Ok(()) => {
                let _ = write_json(
                    &self.evidence.join("fixture.cleaned.json"),
                    &serde_json::json!({"identity": identity, "absent": true}),
                );
            }
            Err(error) => {
                let _ = write_json(
                    &self.evidence.join("fixture.cleaned.json"),
                    &serde_json::json!({"identity": identity, "absent": false, "error": error}),
                );
                errors.push(error);
            }
        }
        // Receipts and logs survive a failing row; they are what a failure is
        // diagnosed from. Configs are copied too, since a refusal's unchanged
        // bytes are part of the evidence.
        for row in &rows {
            let name = row
                .work
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            let destination = self.evidence.join(&name);
            if let Err(error) = fs::create_dir_all(&destination) {
                errors.push(format!("{}: {error}", destination.display()));
                continue;
            }
            let Ok(entries) = fs::read_dir(&row.work) else {
                errors.push(format!("{}: unreadable", row.work.display()));
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file()
                    && let Err(error) = fs::copy(&path, destination.join(entry.file_name()))
                {
                    errors.push(format!("{}: {error}", path.display()));
                }
            }
        }
        let _ = write_json(
            &self.evidence.join("errors.json"),
            &serde_json::json!(errors),
        );
        if errors.is_empty() {
            if let Err(error) = fs::remove_dir_all(&self.root) {
                errors.push(format!("{}: {error}", self.root.display()));
            }
        } else {
            eprintln!(
                "Owned scratch retained after failure: {}",
                self.root.display()
            );
        }
        errors
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The oracle parser refuses what the shell renderer refuses.
    #[test]
    fn the_stderr_oracle_requires_a_row() {
        let work = std::env::temp_dir().join(format!("pn-oracle-{}", std::process::id()));
        fs::create_dir_all(&work).expect("a scratch dir");
        fs::write(
            work.join("expected-stderr.tsv"),
            "PN1\tone\nPN2\ttwo\nPN2\tthree\n# PN9\tcommented\n\n",
        )
        .expect("the fixture");
        assert_eq!(
            expected_stderr(&work, "PN2").expect("row PN2"),
            vec!["two".to_owned(), "three".to_owned()]
        );
        assert!(
            expected_stderr(&work, "PN9").is_err(),
            "a comment is not a row"
        );
        assert!(expected_stderr(&work, "absent").is_err(), "unknown row");
        assert!(
            require_shared_stderr_oracle(&work, "PN2", "two", Some("PN2")).is_err(),
            "a partial log must fail"
        );
        assert!(require_shared_stderr_oracle(&work, "PN2", "x", None).is_ok());
        fs::remove_dir_all(&work).expect("scratch removed");
    }

    /// A state dir that would truncate the control socket is refused by name.
    #[test]
    fn an_over_long_state_dir_is_refused() {
        let long = PathBuf::from(format!("/tmp/{}", "s".repeat(SUN_PATH_USABLE)));
        let error = state_dir_fits(&long).expect_err("over the budget");
        assert!(error.contains("control socket budget"), "{error}");
        assert!(state_dir_fits(Path::new("/tmp/pn-state")).is_ok());
    }
}
