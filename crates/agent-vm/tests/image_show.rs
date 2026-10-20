//! Boot-free black-box proof for `agent-vm image show` (#373).
//!
//! The contract is the compiled executable: argv and environment in, text,
//! exit status, filesystem state and process/network observations out. These
//! tests therefore never import the selector or assert on its private types —
//! the one exception is the unit-level classifier truth table in
//! `boot_image`'s own module, which ADR-0018 requires.
//!
//! Every case runs with a cleared environment and a private `HOME`, project,
//! state, cache and `TMPDIR`, because the operation under test promises to
//! create none of them and to consult no runtime. `PATH` holds only
//! test-owned decoys that log **every** invocation (including `msb --version`)
//! and fail; a case that succeeds with an empty `PATH` still cannot prove the
//! checkout/bundled runtime fallback was not consulted, so the logging decoys —
//! not the empty path — are the discovery oracle.
//!
//! The project root lives under `CARGO_TARGET_TMPDIR` (via
//! `support::project_tempdir`) so it is off the guest tmpfs prefixes.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::net::{TcpListener, TcpStream};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

mod support;

const ENV_REF: &str = "127.0.0.1:1/env:dev";
const USER_REF: &str = "127.0.0.1:1/user:dev";
const PROJECT_REF: &str = "127.0.0.1:1/project:dev";
const RETAINED_A: &str =
    "127.0.0.1:1/private-a@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const RECOMMENDATION_B: &str =
    "127.0.0.1:1/offer-b@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// The shipped recommendation. `show` must report it, not acquire it, so no
/// availability oracle is needed. This is the only release-specific literal.
const PRODUCTION_RECOMMENDATION: &str = "ghcr.io/gregwebs/agent-vm-standard@sha256:04701db70ef6c2c75078ca39a85ce4b4c15b04cacfea47836c2e5d113c4d42de";

const TIMEOUT: Duration = Duration::from_secs(20);

/// The documented byte policy, reimplemented here so expected text never comes
/// from the production renderer: double backslashes, escape double quotes,
/// leave other printable ASCII, render every other byte as `\xNN`.
fn escape(bytes: &[u8]) -> String {
    let mut out = String::new();
    for &byte in bytes {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            0x20..=0x7e => out.push(char::from(byte)),
            _ => out.push_str(&format!("\\x{byte:02x}")),
        }
    }
    out
}

fn expected(reference: &str, label: &str, file: Option<&Path>) -> String {
    let mut text = format!("Image: {}\nSource: {label}\n", escape(reference.as_bytes()));
    if let Some(file) = file {
        text.push_str(&format!("File: {}\n", escape(file.as_os_str().as_bytes())));
    }
    text
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[track_caller]
fn assert_success(output: &Output, expected_stdout: &str) {
    assert!(
        output.status.success(),
        "show must succeed: status {:?}\nstderr: {}",
        output.status.code(),
        stderr(output)
    );
    assert_eq!(stdout(output), expected_stdout);
    assert_eq!(stderr(output), "", "a successful show is silent on stderr");
}

/// Every failure: nonzero, safe contextual stderr, and **no** stdout at all, so
/// no partial `Image:` line can be mistaken for a selection.
#[track_caller]
fn assert_failure(output: &Output) -> String {
    assert!(
        !output.status.success(),
        "expected failure, got success with stdout: {}",
        stdout(output)
    );
    assert_eq!(stdout(output), "", "a failed show must print no report");
    let message = stderr(output);
    assert!(
        !message.is_empty(),
        "a failure must explain itself on stderr"
    );
    message
}

/// A named fixture-arrangement step: the privileged setup a case needs before
/// the invocation under test.
type Arrangement = Box<dyn Fn(&Fixture)>;

/// `(case name, arrangement, whether the environment is also set)`.
type EscalationCase = (&'static str, Arrangement, bool);

/// A recursive description of an owned tree: entry type, mode, symlink target
/// and file bytes. Access time is excluded — reads may update it.
#[derive(Debug, PartialEq, Eq)]
struct Snapshot(BTreeMap<String, String>);

fn collect(root: &Path, prefix: &str, meta: &fs::Metadata, out: &mut BTreeMap<String, String>) {
    assert!(meta.is_dir(), "snapshot root must be a directory: {root:?}");
    let entries = fs::read_dir(root).expect("read fixture directory");
    out.insert(prefix.to_string(), format!("dir {:o}", meta.mode()));
    for entry in entries {
        let entry = entry.expect("read fixture directory entry");
        let path = entry.path();
        let key = format!("{prefix}/{}", path.file_name().unwrap().to_string_lossy());
        let meta = fs::symlink_metadata(&path).expect("stat fixture entry");
        let kind = meta.file_type();
        let description = if kind.is_symlink() {
            format!(
                "symlink {:o} {:?}",
                meta.mode(),
                fs::read_link(&path).unwrap()
            )
        } else if kind.is_dir() {
            collect(&path, &key, &meta, out);
            continue;
        } else if kind.is_file() {
            match fs::read(&path) {
                Ok(bytes) => format!("file {:o} {bytes:?}", meta.mode()),
                // A deliberately unreadable fixture (mode 000) still snapshots
                // by existence and mode; permission denial is the fixture.
                Err(error)
                    if error.kind() == std::io::ErrorKind::PermissionDenied
                        && meta.mode() & 0o777 == 0 =>
                {
                    format!("file {:o} unreadable", meta.mode())
                }
                Err(error) => panic!("read fixture file {path:?}: {error}"),
            }
        } else {
            // A FIFO/socket/device would block a read with no peer. The
            // adversarial record fixtures *are* FIFOs, so describe them by
            // metadata only.
            format!("special {:o}", meta.mode())
        };
        out.insert(key, description);
    }
}

const DECOY_NAMES: [&str; 4] = ["msb", "docker", "buildx", "curl"];
const CALIBRATION_ARG: &str = "--calibration";

/// Ten total launches, 1ms apart. A Linux stress matrix of 10,000 fresh
/// parallel fixtures had 291 fixtures lose a marker without it and none with
/// it. This is a harness bound for a transient local condition, not a claim
/// that ten milliseconds covers every host.
const CALIBRATION_ATTEMPTS: usize = 10;
const CALIBRATION_RETRY_DELAY: Duration = Duration::from_millis(1);

/// The final launch error and the number of launches the bound allowed; the
/// count separates an exhaustion from an error that was never retried.
#[derive(Debug)]
struct AttemptFailure {
    error: io::Error,
    attempts: usize,
}

impl AttemptFailure {
    /// The decoy path and concrete kind/errno belong in the failure: the
    /// discarded `status()` this replaced swallowed the error, so CI failed on
    /// a missing marker with nothing to say whether or why the launch failed. The
    /// complete diagnostic must never degrade into `Option::None` either, which
    /// reads as "this filesystem cannot do that".
    fn message(&self, path: &Path) -> String {
        format!(
            "the decoy executable {} could not be launched after {} attempt(s): {} (kind {:?}, errno {:?})",
            path.display(),
            self.attempts,
            self.error,
            self.error.kind(),
            self.error.raw_os_error()
        )
    }
}

/// Retry only a busy executable inode, and only within the measured bound.
///
/// Linux refuses `execve` with `ETXTBSY` while any process still holds a
/// writable reference to the file. The fixture writes, chmods and immediately
/// executes each decoy, and parallel Linux stress reproduced both the busy
/// launch and the lost marker, which is what the bound removes. The hosted CI
/// errno and the owner of any competing writable reference were never
/// measured, so this explains a plausible failure mode rather than proving the
/// CI failure's cause. Every other launch error (missing interpreter,
/// permission, ...) is final, as is any child that did run: retrying those
/// would hide a broken fixture.
fn retry_executable_file_busy<T>(
    mut attempt: impl FnMut() -> io::Result<T>,
) -> Result<T, AttemptFailure> {
    let mut attempts = 0;
    loop {
        attempts += 1;
        match attempt() {
            Ok(value) => return Ok(value),
            Err(error)
                if error.raw_os_error() == Some(libc::ETXTBSY)
                    && attempts < CALIBRATION_ATTEMPTS =>
            {
                std::thread::sleep(CALIBRATION_RETRY_DELAY);
            }
            Err(error) => return Err(AttemptFailure { error, attempts }),
        }
    }
}

fn run_decoy(path: &Path) -> io::Result<Output> {
    Command::new(path)
        .arg(CALIBRATION_ARG)
        .stdin(Stdio::null())
        .output()
}

/// Execute a freshly written decoy directly, capturing its status and output.
fn launch_decoy(path: &Path) -> Result<Output, AttemptFailure> {
    retry_executable_file_busy(|| run_decoy(path))
}

/// The exact bytes the decoy's `printf '%s %s\n' "$0" "$*"` appends. The
/// whole line is the oracle: matching `contains(name)` let a name that merely
/// occurs elsewhere in the log satisfy it.
fn calibration_line(path: &Path) -> Vec<u8> {
    let mut line = path.as_os_str().as_bytes().to_vec();
    line.push(b' ');
    line.extend_from_slice(CALIBRATION_ARG.as_bytes());
    line.push(b'\n');
    line
}

/// The decoy exits 1 on purpose, so success is the wrong check, and a child
/// that ran is final and never relaunched. Status 1 plus silence is necessary
/// but not sufficient: a shell can exit 1 silently on its way to the append, so
/// the exact log line checked in `calibrate_decoys` stays required.
fn validate_decoy_output(path: &Path, output: &Output) -> Result<(), String> {
    if output.status.code() != Some(1) {
        return Err(format!(
            "the decoy executable {} must exit 1 after logging; got {:?}\nstdout: {}\nstderr: {}",
            path.display(),
            output.status.code(),
            stdout(output),
            stderr(output)
        ));
    }
    if !output.stdout.is_empty() || !output.stderr.is_empty() {
        return Err(format!(
            "the decoy executable {} must be silent; stdout: {:?}\nstderr: {}",
            path.display(),
            String::from_utf8_lossy(&output.stdout),
            stderr(output)
        ));
    }
    Ok(())
}

/// The log is the discovery oracle for every later "no runtime ran" case, so
/// the fixture proves it byte for byte before the product is invoked.
fn validate_calibration_log(actual: &[u8], expected: &[u8]) -> Result<(), String> {
    if actual == expected {
        return Ok(());
    }
    Err(format!(
        "the decoy calibration log is not exactly the expected invocation lines\nexpected: {:?}\nactual: {:?}",
        String::from_utf8_lossy(expected),
        String::from_utf8_lossy(actual)
    ))
}

/// A decoy that logs its exact argv and then fails like an absent runtime.
fn write_decoy(path: &Path, trap_log: &Path) {
    fs::write(
        path,
        format!(
            "#!/bin/sh\nprintf '%s %s\\n' \"$0\" \"$*\" >> '{}'\nexit 1\n",
            trap_log.display()
        ),
    )
    .expect("write decoy");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("chmod decoy");
}

/// Absence is the expected outcome when no child ran. Any other read error is
/// not absence: treating it as an empty log would let the negative assertion
/// pass while hiding a real fixture problem.
#[cfg(target_os = "linux")]
fn read_log_absent_or_bytes(path: &Path) -> Vec<u8> {
    match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => panic!("read the decoy calibration log {}: {error}", path.display()),
    }
}

/// Write the four decoys, execute each directly, and require the log to be
/// exactly their invocation lines. The `Err` is the complete diagnostic: a
/// launch failure keeps its path and concrete kind/errno, an executed child
/// keeps its status and stderr, and a log mismatch keeps both byte strings.
fn calibrate_decoys(decoys: &Path, trap_log: &Path) -> Result<(), String> {
    let mut expected_log = Vec::new();
    for name in DECOY_NAMES {
        let path = decoys.join(name);
        write_decoy(&path, trap_log);
        // Calibrate the oracle before any negative assertion: the decoy must
        // actually run and log when invoked directly.
        let output = launch_decoy(&path).map_err(|failure| failure.message(&path))?;
        validate_decoy_output(&path, &output)?;
        expected_log.extend(calibration_line(&path));
    }
    let calibration = fs::read(trap_log).map_err(|error| {
        format!(
            "read the decoy calibration log {}: {error}",
            trap_log.display()
        )
    })?;
    validate_calibration_log(&calibration, &expected_log)
}

/// One private host: every directory the product might touch, plus the decoy
/// executables. Nothing under `home`/`project` is pre-created beyond the roots
/// themselves, so "did it create `.config/agent-vm`?" stays observable.
struct Fixture {
    _root: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    project: PathBuf,
    state: PathBuf,
    cache: PathBuf,
    tmp: PathBuf,
    decoys: PathBuf,
    trap_log: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        Self::with_dir_names(OsStr::new("home"), OsStr::new("project"))
    }

    /// Names are parameters so a case can put control characters or invalid
    /// bytes in the paths the report must escape.
    fn with_dir_names(home: &OsStr, project: &OsStr) -> Self {
        Self::try_with_dir_names(home, project).expect("the filesystem accepts these names")
    }

    fn try_with_dir_names(home: &OsStr, project: &OsStr) -> Option<Self> {
        let root = support::project_tempdir();
        let root_path = root.path().canonicalize().expect("canonicalize fixture");
        let home = root_path.join(home);
        let project = root_path.join(project);
        let state = root_path.join("state");
        let cache = root_path.join("cache");
        let tmp = root_path.join("tmp");
        let decoys = root_path.join("decoys");
        for dir in [&home, &project, &tmp, &decoys] {
            // Only a filesystem that refuses these names (the non-UTF-8 probe)
            // skips the case. Every later fixture failure is a real failure.
            fs::create_dir_all(dir).ok()?;
        }
        let trap_log = decoys.join("invocations.log");
        calibrate_decoys(&decoys, &trap_log).unwrap_or_else(|message| panic!("{message}"));
        fs::remove_file(&trap_log).expect("clear calibration log");
        Some(Self {
            _root: root,
            root: root_path,
            home,
            project,
            state,
            cache,
            tmp,
            decoys,
            trap_log,
        })
    }

    fn user_config(&self) -> PathBuf {
        self.home.join(".config/agent-vm/config.toml")
    }

    fn project_config(&self) -> PathBuf {
        self.project.join(".agent-vm/config.toml")
    }

    fn record(&self) -> PathBuf {
        self.home.join(".config/agent-vm/default-image.json")
    }

    fn write_file(&self, path: &Path, contents: impl AsRef<[u8]>) {
        fs::create_dir_all(path.parent().unwrap()).expect("create parent");
        fs::write(path, contents).expect("write fixture file");
    }

    fn write_user_config(&self, contents: &str) {
        self.write_file(&self.user_config(), contents);
    }

    fn write_project_config(&self, contents: &str) {
        self.write_file(&self.project_config(), contents);
    }

    fn write_user_image(&self, reference: &str) {
        self.write_user_config(&format!("image = \"{reference}\"\n"));
    }

    fn write_project_image(&self, reference: &str) {
        self.write_project_config(&format!("image = \"{reference}\"\n"));
    }

    /// Byte-exact so unusual JSON spacing/newlines stay under test.
    fn write_record(&self, contents: &str) {
        self.write_file(&self.record(), contents);
    }

    fn write_record_ref(&self, reference: &str) {
        self.write_record(&format!("{{\"version\":1,\"image\":\"{reference}\"}}\n"));
    }

    /// A prepared invocation: cleared environment, decoy-only `PATH`, private
    /// `HOME`/cwd/state/cache/`TMPDIR`, and the msb decoy as `MSB_PATH` so the
    /// checkout/bundled fallback cannot hide a runtime probe.
    fn command(&self, argv: &[&str]) -> Command {
        let mut command = Command::new(agent_vm_bin());
        command
            .env_clear()
            .env("PATH", &self.decoys)
            .env("HOME", &self.home)
            .env("TMPDIR", &self.tmp)
            .env("AGENT_VM_STATE_DIR", &self.state)
            .env("XDG_CACHE_HOME", &self.cache)
            .env("MSB_PATH", self.decoys.join("msb"))
            .current_dir(&self.project)
            .args(argv);
        command
    }

    fn show(&self) -> Output {
        self.run(self.command(&["image", "show"]))
    }

    fn show_with_env(&self, variables: &[(&str, &str)]) -> Output {
        let mut command = self.command(&["image", "show"]);
        for (key, value) in variables {
            command.env(key, value);
        }
        self.run(command)
    }

    /// Bounded: a wedged child (a FIFO read, a synchronous registry fetch) is a
    /// failure of the case, never a hung suite.
    fn run(&self, mut command: Command) -> Output {
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn agent-vm");
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if child.try_wait().expect("poll child").is_some() {
                return child.wait_with_output().expect("collect output");
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let output = child.wait_with_output().expect("collect killed output");
                panic!(
                    "agent-vm did not exit within {TIMEOUT:?}\nstdout: {}\nstderr: {}",
                    stdout(&output),
                    stderr(&output)
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn snapshot(&self) -> Snapshot {
        let mut entries = BTreeMap::new();
        for (name, root) in [
            ("home", &self.home),
            ("project", &self.project),
            ("state", &self.state),
            ("cache", &self.cache),
            ("tmp", &self.tmp),
        ] {
            match fs::symlink_metadata(root) {
                Ok(meta) => collect(root, name, &meta, &mut entries),
                // State/cache roots intentionally start absent. Traversal
                // errors inside an existing root must not look like absence.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    entries.insert(name.to_string(), "absent".to_string());
                }
                Err(error) => panic!("stat fixture root {root:?}: {error}"),
            }
        }
        Snapshot(entries)
    }

    /// Decoy invocations are observed separately from the immutability
    /// snapshot: the log is the oracle, not product state.
    fn trap_calls(&self) -> String {
        fs::read_to_string(&self.trap_log).unwrap_or_default()
    }

    fn assert_no_trap_calls(&self) {
        let calls = self.trap_calls();
        assert!(calls.is_empty(), "no runtime may be invoked:\n{calls}");
    }
}

fn agent_vm_bin() -> PathBuf {
    let path = PathBuf::from(env!("CARGO_BIN_EXE_agent-vm"));
    assert!(path.is_absolute(), "the harness spawns an absolute path");
    path
}

fn read(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

#[test]
fn snapshot_detects_directory_mode_changes() {
    let fixture = Fixture::new();
    let nested = fixture.home.join("nested");
    fs::create_dir(&nested).unwrap();
    for directory in [&fixture.home, &nested] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o755)).unwrap();
        let before = fixture.snapshot();
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        assert_ne!(fixture.snapshot(), before, "chmod must change the snapshot");
        fs::set_permissions(directory, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(fixture.snapshot(), before, "restored mode must match");
    }
}

#[test]
#[should_panic(expected = "read fixture directory")]
fn snapshot_rejects_a_disappeared_directory() {
    let root = support::project_tempdir();
    let directory = root.path().join("removed");
    fs::create_dir(&directory).unwrap();
    let meta = fs::symlink_metadata(&directory).unwrap();
    fs::remove_dir(&directory).unwrap();
    collect(&directory, "removed", &meta, &mut BTreeMap::new());
}

// ---------------------------------------------------------------------------
// Fixture calibration: the decoy oracle must survive a freshly written exec
// ---------------------------------------------------------------------------

/// Linux refuses `execve` while a process holds a writable reference to the
/// file. The reference is released only after the real error was observed, so
/// this proves the retry relaunches the same fresh decoy rather than masking a
/// launch that never ran; the marker afterwards is the real recovery signal.
/// Concurrent writers on the same host can add more busy launches after the
/// release, so a bounded prefix is accepted but any other errno is not.
#[cfg(target_os = "linux")]
#[test]
fn calibration_recovers_after_the_writable_reference_is_released() {
    let root = support::project_tempdir();
    let decoy = root.path().join("held-writer");
    let log = root.path().join("invocations.log");
    write_decoy(&decoy, &log);
    let mut writer = Some(
        fs::OpenOptions::new()
            .write(true)
            .open(&decoy)
            .expect("hold a writable reference"),
    );
    let mut busy_prefix = Vec::new();
    let output = retry_executable_file_busy(|| {
        let outcome = run_decoy(&decoy);
        if let Err(error) = &outcome {
            busy_prefix.push(error.raw_os_error());
            if error.raw_os_error() == Some(libc::ETXTBSY) {
                writer.take();
            }
        }
        outcome
    })
    .expect("the released decoy launches");
    assert!(
        !busy_prefix.is_empty() && busy_prefix.len() < CALIBRATION_ATTEMPTS,
        "the writer must block at least one launch and the recovery must fit the bound: {busy_prefix:?}"
    );
    assert!(
        busy_prefix
            .iter()
            .all(|errno| *errno == Some(libc::ETXTBSY)),
        "only a busy executable inode may be retried: {busy_prefix:?}"
    );
    validate_decoy_output(&decoy, &output).unwrap();
    assert_eq!(
        fs::read(&log).unwrap(),
        calibration_line(&decoy),
        "the recovered launch must append exactly one real marker"
    );
}

/// A reference that is never released stays red: the bound is a recovery
/// window, not permission to hang, and the diagnostic must keep the decoy path
/// with the concrete errno instead of looking like an unusable filesystem.
#[cfg(target_os = "linux")]
#[test]
fn calibration_gives_up_after_the_bounded_attempts() {
    let root = support::project_tempdir();
    let decoys = root.path().join("decoys");
    fs::create_dir(&decoys).expect("create decoys");
    let log = decoys.join("invocations.log");
    let msb = decoys.join("msb");
    write_decoy(&msb, &log);
    let writer = fs::OpenOptions::new()
        .write(true)
        .open(&msb)
        .expect("hold a writable reference");

    let failure = launch_decoy(&msb).expect_err("a retained writable reference blocks exec");
    assert_eq!(failure.attempts, CALIBRATION_ATTEMPTS);
    assert_eq!(failure.error.raw_os_error(), Some(libc::ETXTBSY));

    let message = calibrate_decoys(&decoys, &log).unwrap_err();
    assert!(message.contains(&msb.display().to_string()), "{message}");
    assert!(message.contains("os error 26"), "{message}");
    assert!(
        message.contains(&format!("after {CALIBRATION_ATTEMPTS} attempt")),
        "{message}"
    );
    assert_eq!(
        read_log_absent_or_bytes(&log),
        b"",
        "a launch that never ran must not log a marker"
    );
    drop(writer);
}

/// The decoy exits 1 whether or not its append worked, so a launch that ran is
/// final: an unusable log target must fail calibration on the child's own
/// stderr, with no relaunch, rather than pass on the expected exit code. Only
/// busy launches may precede that single child.
#[test]
fn calibration_rejects_an_executed_decoy_that_could_not_log() {
    let root = support::project_tempdir();
    let log = root.path().join("invocations.log");
    fs::create_dir(&log).expect("an unusable log target");
    let decoy = root.path().join("append-failure");
    write_decoy(&decoy, &log);

    let mut launches = 0;
    let mut busy_prefix = Vec::new();
    let output = retry_executable_file_busy(|| {
        launches += 1;
        let outcome = run_decoy(&decoy);
        if let Err(error) = &outcome {
            busy_prefix.push(error.raw_os_error());
        }
        outcome
    })
    .expect("the shell still starts");
    assert_eq!(
        launches - busy_prefix.len(),
        1,
        "exactly one executed child, never relaunched: {busy_prefix:?}"
    );
    assert!(
        launches <= CALIBRATION_ATTEMPTS,
        "the bound applies to the wait for a free inode: {launches} launches"
    );
    assert!(
        busy_prefix
            .iter()
            .all(|errno| *errno == Some(libc::ETXTBSY)),
        "only a busy executable inode may be retried: {busy_prefix:?}"
    );
    assert_eq!(output.status.code(), Some(1), "the decoy exits 1 by design");
    assert!(
        !output.stderr.is_empty(),
        "the failed append must explain itself on stderr"
    );

    let message = validate_decoy_output(&decoy, &output).unwrap_err();
    assert!(message.contains(&decoy.display().to_string()), "{message}");
    assert!(message.contains("stderr"), "{message}");
    assert!(
        fs::read_dir(&log).unwrap().next().is_none(),
        "no marker can reach a directory"
    );
}

/// Only a busy executable inode is transient. A missing interpreter or a
/// non-executable file must be final once it appears, so the retry cannot mask
/// a broken fixture as a timing problem. Busy launches may precede it, but
/// nothing may follow it.
#[test]
fn non_retryable_launch_errors_are_reported_immediately() {
    let root = support::project_tempdir();
    let missing_interpreter = root.path().join("missing-interpreter");
    fs::write(&missing_interpreter, "#!/nonexistent/interpreter\n").unwrap();
    fs::set_permissions(&missing_interpreter, fs::Permissions::from_mode(0o755)).unwrap();
    let not_executable = root.path().join("not-executable");
    fs::write(&not_executable, "#!/bin/sh\nexit 1\n").unwrap();
    fs::set_permissions(&not_executable, fs::Permissions::from_mode(0o644)).unwrap();

    for (path, errno) in [
        (&missing_interpreter, libc::ENOENT),
        (&not_executable, libc::EACCES),
    ] {
        let mut errnos = Vec::new();
        let failure = retry_executable_file_busy(|| {
            let outcome = run_decoy(path);
            if let Err(error) = &outcome {
                errnos.push(error.raw_os_error());
            }
            outcome
        })
        .expect_err("the launch cannot succeed");
        assert_eq!(
            failure.attempts,
            errnos.len(),
            "every launch either yields the terminal error or a recorded busy prefix: {errnos:?}"
        );
        assert!(failure.attempts <= CALIBRATION_ATTEMPTS);
        assert_eq!(errnos.last(), Some(&Some(errno)), "{}", path.display());
        assert!(
            errnos[..errnos.len() - 1]
                .iter()
                .all(|errno| *errno == Some(libc::ETXTBSY)),
            "a terminal error is never retried: {errnos:?}"
        );
        assert_eq!(
            failure.error.raw_os_error(),
            Some(errno),
            "{}",
            path.display()
        );
    }
}

/// The oracle is the exact invocation line. The replaced `contains(name)`
/// predicate accepted a line that merely mentioned the decoy; an extra line
/// must not pass either.
#[test]
fn calibration_log_requires_the_exact_invocation_lines() {
    let root = support::project_tempdir();
    let decoy = root.path().join("docker");
    let expected = calibration_line(&decoy);
    assert!(validate_calibration_log(&expected, &expected).is_ok());

    let impostor = format!(
        "{}/unrelated docker {CALIBRATION_ARG}\n",
        root.path().display()
    );
    assert!(
        impostor.contains("docker") && impostor.contains(CALIBRATION_ARG),
        "the impostor line must be the one the replaced predicate accepted"
    );
    let message = validate_calibration_log(impostor.as_bytes(), &expected).unwrap_err();
    assert!(message.contains("docker"), "{message}");

    let mut with_extra = expected.clone();
    with_extra.extend_from_slice(impostor.as_bytes());
    assert!(
        validate_calibration_log(&with_extra, &expected).is_err(),
        "an extra invocation must not pass"
    );
}

/// The bound is a policy, so pin the concrete numbers rather than the constant:
/// ten total launches, each separated by at least one millisecond, never an
/// eleventh. A silent relaxation of either value must fail here.
#[test]
fn retry_policy_is_bounded_and_waits_between_attempts() {
    let mut launches = Vec::new();
    let failure = retry_executable_file_busy::<()>(|| {
        launches.push(Instant::now());
        Err(io::Error::from_raw_os_error(libc::ETXTBSY))
    })
    .expect_err("a permanently busy inode exhausts the bound");

    assert_eq!(
        launches.len(),
        10,
        "the harness bound is ten total launches"
    );
    assert_eq!(failure.attempts, 10);
    assert_eq!(failure.error.raw_os_error(), Some(libc::ETXTBSY));
    assert!(
        launches
            .windows(2)
            .all(|pair| pair[1].duration_since(pair[0]) >= Duration::from_millis(1)),
        "every retry must wait at least the retry delay: {launches:?}"
    );
}

/// A busy prefix may precede a final error, but the final error itself must end
/// the sequence: retrying it would hide a broken fixture as a timing problem.
#[test]
fn a_terminal_error_after_a_busy_prefix_is_never_retried() {
    for terminal in [libc::ENOENT, libc::EACCES] {
        let mut launches = 0;
        let failure = retry_executable_file_busy::<()>(|| {
            launches += 1;
            Err(io::Error::from_raw_os_error(if launches < 3 {
                libc::ETXTBSY
            } else {
                terminal
            }))
        })
        .expect_err("the terminal error must surface");

        assert_eq!(launches, 3, "the terminal error ends the sequence");
        assert_eq!(failure.attempts, 3);
        assert_eq!(failure.error.raw_os_error(), Some(terminal));
    }
}

/// A child that executed is final even when it is the last launch the bound
/// allows: the retry covers launches, not the child's own work.
#[test]
fn an_executed_child_after_a_busy_prefix_is_never_relaunched() {
    let mut launches = 0;
    let marker = retry_executable_file_busy(|| {
        launches += 1;
        if launches < CALIBRATION_ATTEMPTS {
            Err(io::Error::from_raw_os_error(libc::ETXTBSY))
        } else {
            Ok("the executed child")
        }
    })
    .expect("the last allowed launch succeeds");

    assert_eq!(launches, CALIBRATION_ATTEMPTS);
    assert_eq!(marker, "the executed child");
}

/// The output oracle is only as good as its rejection of the near misses that
/// a silently failed append produces: any other exit code, a signal, or output.
#[test]
fn validate_decoy_output_rejects_any_status_but_a_silent_one() {
    use std::os::unix::process::ExitStatusExt as _;

    let decoy = Path::new("/calibration/decoy");
    for raw_status in [0, 2 << 8, 9] {
        let output = Output {
            status: ExitStatus::from_raw(raw_status),
            stdout: Vec::new(),
            stderr: Vec::new(),
        };
        assert!(
            validate_decoy_output(decoy, &output).is_err(),
            "raw status {raw_status} must be rejected"
        );
    }
    for (stdout, stderr) in [
        (b"unexpected".to_vec(), Vec::new()),
        (Vec::new(), b"unexpected".to_vec()),
    ] {
        let output = Output {
            status: ExitStatus::from_raw(1 << 8),
            stdout,
            stderr,
        };
        assert!(
            validate_decoy_output(decoy, &output).is_err(),
            "a decoy that speaks is not silent"
        );
    }

    let silent = Output {
        status: ExitStatus::from_raw(1 << 8),
        stdout: Vec::new(),
        stderr: Vec::new(),
    };
    validate_decoy_output(decoy, &silent).expect("exit 1 with silence is the accepted shape");
    assert!(
        validate_calibration_log(b"", &calibration_line(decoy)).is_err(),
        "a silent exit 1 still needs the real marker"
    );
}

/// The deterministic controls above pin the mechanism; this reproduces the
/// original symptom itself, with many threads calibrating fresh decoys at
/// once. With a single attempt per launch, Linux lost markers within a few
/// hundred fixtures; the bound is what closes that window.
#[cfg(target_os = "linux")]
#[test]
fn parallel_fresh_decoys_all_calibrate() {
    const THREADS: usize = 8;
    const FIXTURES_PER_THREAD: usize = 50;
    std::thread::scope(|scope| {
        for _ in 0..THREADS {
            scope.spawn(|| {
                for _ in 0..FIXTURES_PER_THREAD {
                    let root = support::project_tempdir();
                    let decoys = root.path().join("decoys");
                    fs::create_dir(&decoys).expect("create decoys");
                    let log = decoys.join("invocations.log");
                    calibrate_decoys(&decoys, &log).expect("calibrate fresh decoys");
                }
            });
        }
    });
}

// ---------------------------------------------------------------------------
// S1–S6: precedence and provenance
// ---------------------------------------------------------------------------

#[test]
fn s1_environment_wins_over_every_other_source() {
    let fixture = Fixture::new();
    fixture.write_user_image(USER_REF);
    fixture.write_project_image(PROJECT_REF);
    fixture.write_record_ref(RETAINED_A);
    let before = fixture.snapshot();

    let output = fixture.show_with_env(&[
        ("AGENT_VM_IMAGE_TAG", ENV_REF),
        // Proves the lower default origin is never consulted either.
        ("AGENT_VM_TEST_DEFAULT_IMAGE", RECOMMENDATION_B),
    ]);

    assert_success(&output, &expected(ENV_REF, "AGENT_VM_IMAGE_TAG", None));
    assert_eq!(
        fixture.snapshot(),
        before,
        "show must create and change nothing"
    );
    fixture.assert_no_trap_calls();
}

#[test]
fn s2_user_config_wins_and_names_only_its_own_file() {
    let fixture = Fixture::new();
    fixture.write_user_image(USER_REF);
    fixture.write_project_image(PROJECT_REF);
    fixture.write_record_ref(RETAINED_A);
    let before = fixture.snapshot();

    let output = fixture.show();

    assert_success(
        &output,
        &expected(USER_REF, "user config", Some(&fixture.user_config())),
    );
    assert!(!stdout(&output).contains(PROJECT_REF));
    assert!(!stdout(&output).contains("/default-image.json"));
    assert_eq!(fixture.snapshot(), before);
    fixture.assert_no_trap_calls();
}

#[test]
fn s3_project_config_is_the_last_explicit_source() {
    let fixture = Fixture::new();
    // The user tier is readable but declares tools only: it must not become
    // the provenance of a project image.
    fixture.write_user_config("[[tools]]\nname = \"solo\"\ncommand = \"/bin/echo\"\n");
    fixture.write_project_image(PROJECT_REF);
    fixture.write_record_ref(RETAINED_A);
    let before = fixture.snapshot();

    let output = fixture.show();

    assert_success(
        &output,
        &expected(
            PROJECT_REF,
            "project config",
            Some(&fixture.project_config()),
        ),
    );
    assert!(!stdout(&output).contains("/.config/agent-vm/config.toml"));
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn s4_retained_default_is_disclosed_with_its_exact_file() {
    let fixture = Fixture::new();
    // Unusual spacing and no trailing newline: the bytes must survive verbatim.
    let contents = format!("{{ \"image\" :  \"{RETAINED_A}\" , \"version\": 1 }}");
    fixture.write_record(&contents);
    let before = read(&fixture.record());

    let output = fixture.show_with_env(&[("AGENT_VM_TEST_DEFAULT_IMAGE", RECOMMENDATION_B)]);

    assert_success(
        &output,
        &expected(RETAINED_A, "retained default", Some(&fixture.record())),
    );
    assert!(!stdout(&output).contains(&RECOMMENDATION_B[..30]));
    assert_eq!(
        read(&fixture.record()),
        before,
        "the record is never rewritten"
    );
}

#[test]
fn s5_absent_record_offers_the_recommendation_and_creates_nothing() {
    let fixture = Fixture::new();
    // The state/cache roots are absent from the start; `.config/agent-vm` is
    // absent too (the fixture creates neither).
    let before = fixture.snapshot();

    let output = fixture.show_with_env(&[("AGENT_VM_TEST_DEFAULT_IMAGE", RECOMMENDATION_B)]);

    assert_success(
        &output,
        &expected(RECOMMENDATION_B, "initial recommendation", None),
    );
    assert!(!stdout(&output).contains("File:"));
    assert_eq!(fixture.snapshot(), before, "no record, lock or directory");
    fixture.assert_no_trap_calls();
}

/// The release-independent half of S5: with no debug seam at all, the shipped
/// recommendation is what an uninitialized host is offered.
#[test]
fn s5_shipped_recommendation_without_the_debug_seam() {
    let fixture = Fixture::new();
    let output = fixture.show();
    assert_success(
        &output,
        &expected(PRODUCTION_RECOMMENDATION, "initial recommendation", None),
    );
    assert!(!Path::new(&fixture.home.join(".config/agent-vm")).exists());
}

#[test]
fn s6_empty_environment_is_unset() {
    let fixture = Fixture::new();
    fixture.write_user_image(USER_REF);
    fixture.write_project_image(PROJECT_REF);
    fixture.write_record_ref(RETAINED_A);

    let with_config = fixture.show_with_env(&[("AGENT_VM_IMAGE_TAG", "")]);
    assert_success(
        &with_config,
        &expected(USER_REF, "user config", Some(&fixture.user_config())),
    );

    fs::remove_file(fixture.user_config()).unwrap();
    fs::remove_file(fixture.project_config()).unwrap();
    let retained = fixture.show_with_env(&[("AGENT_VM_IMAGE_TAG", "")]);
    assert_success(
        &retained,
        &expected(RETAINED_A, "retained default", Some(&fixture.record())),
    );
}

// ---------------------------------------------------------------------------
// S7–S9: non-Unicode environment and invalid configuration
// ---------------------------------------------------------------------------

#[test]
fn s7_non_unicode_environment_fails_without_a_value() {
    let fixture = Fixture::new();
    fixture.write_user_config("[[tools]]\nname = \"solo\"\ncommand = \"/bin/echo\"\n");
    fixture.write_record_ref(RETAINED_A);
    let before = fixture.snapshot();

    let mut command = fixture.command(&["image", "show"]);
    command.env("AGENT_VM_IMAGE_TAG", OsString::from_vec(vec![0xff, b'x']));
    let output = fixture.run(command);

    let message = assert_failure(&output);
    assert!(message.contains("AGENT_VM_IMAGE_TAG"), "{message}");
    assert!(!message.contains("\\xff"), "{message}");
    assert_eq!(fixture.snapshot(), before, "no fallback may be selected");
}

#[test]
fn s8_environment_values_pass_through_unescaped_and_unvalidated() {
    let fixture = Fixture::new();

    // A local rootfs path is accepted by the permissive override rule; it does
    // not need to exist.
    let local = fixture.show_with_env(&[("AGENT_VM_IMAGE_TAG", "./rootfs")]);
    assert_success(&local, &expected("./rootfs", "AGENT_VM_IMAGE_TAG", None));

    // Whitespace is present, not trimmed — the existing permissive rule keeps
    // it, and the report escapes only for display.
    let spaced = fixture.show_with_env(&[("AGENT_VM_IMAGE_TAG", " 127.0.0.1:1/x:dev ")]);
    assert_success(
        &spaced,
        &expected(" 127.0.0.1:1/x:dev ", "AGENT_VM_IMAGE_TAG", None),
    );
    fixture.assert_no_trap_calls();
}

#[test]
fn s9_invalid_configuration_is_fatal_even_with_a_valid_environment() {
    let marker = "sk-REJECTED-IMAGE-MARKER";
    let raw_marker = "RAW-TOML-MARKER";
    let cases: Vec<EscalationCase> = vec![
        (
            "local path in config",
            Box::new(|f: &Fixture| f.write_user_image("./rootfs")),
            true,
        ),
        (
            "whitespace-padded value",
            Box::new(move |f: &Fixture| f.write_user_config(&format!("image = \" {marker} \"\n"))),
            true,
        ),
        (
            "wrong type",
            Box::new(|f: &Fixture| f.write_user_config("image = 5\n")),
            true,
        ),
        (
            "malformed toml",
            Box::new(move |f: &Fixture| f.write_user_config(&format!("image = \"{raw_marker}\n"))),
            true,
        ),
        (
            "config path is a directory",
            Box::new(|f: &Fixture| {
                fs::create_dir_all(f.user_config().parent().unwrap()).unwrap();
                fs::create_dir(f.user_config()).unwrap();
            }),
            true,
        ),
        (
            "config path is a dangling symlink",
            Box::new(|f: &Fixture| {
                fs::create_dir_all(f.user_config().parent().unwrap()).unwrap();
                std::os::unix::fs::symlink("/nonexistent/agent-vm-config", f.user_config())
                    .unwrap();
            }),
            true,
        ),
        // A lower (project) tier that is damaged must fail show even though a
        // valid user image would win.
        (
            "invalid lower project config",
            Box::new(move |f: &Fixture| {
                f.write_user_image(USER_REF);
                f.write_project_config(&format!("image = \"{marker}\"\n"));
            }),
            false,
        ),
    ];

    for (name, arrange, with_env) in cases {
        let fixture = Fixture::new();
        arrange(&fixture);
        let before = fixture.snapshot();
        let output = if with_env {
            fixture.show_with_env(&[("AGENT_VM_IMAGE_TAG", ENV_REF)])
        } else {
            fixture.show()
        };
        let message = assert_failure(&output);
        assert!(
            message.contains("config"),
            "case `{name}`: the diagnostic must name configuration:\n{message}"
        );
        assert!(
            !message.contains(marker),
            "case `{name}`: a rejected image value must not be echoed:\n{message}"
        );
        assert!(
            !message.contains(raw_marker),
            "case `{name}`: raw parser text must not be echoed:\n{message}"
        );
        assert_eq!(fixture.snapshot(), before, "case `{name}` changed state");
    }
}

/// A permissive mode-000 fixture is only a denial if the test user is not root,
/// which bypasses the permission check; report the limitation rather than claim
/// a check that did not happen.
#[test]
fn s9_unreadable_config_fails_closed() {
    use std::os::unix::fs::PermissionsExt as _;
    if unsafe { libc::geteuid() } == 0 {
        eprintln!(
            "SKIPPED: root bypasses mode-based denial; the directory and symlink cases in s9 still cover refusal"
        );
        return;
    }
    let fixture = Fixture::new();
    fixture.write_user_image(USER_REF);
    fs::set_permissions(fixture.user_config(), fs::Permissions::from_mode(0o0)).unwrap();
    let before = fixture.snapshot();
    let output = fixture.show_with_env(&[("AGENT_VM_IMAGE_TAG", ENV_REF)]);
    let message = assert_failure(&output);
    assert!(message.contains("config"), "{message}");
    assert_eq!(fixture.snapshot(), before);
    fs::set_permissions(fixture.user_config(), fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn s10_deferred_catalog_failure_fails_show_with_safe_identifiers() {
    let fixture = Fixture::new();
    fixture.write_user_config(
        "image = \"127.0.0.1:1/user:dev\"\n\
         [[tools]]\nname = \"solo\"\ncommand = \"/bin/echo\"\n\
         tools = [\"missing-available-tool\"]\n",
    );
    let before = fixture.snapshot();

    for output in [
        fixture.show(),
        fixture.show_with_env(&[("AGENT_VM_IMAGE_TAG", ENV_REF)]),
    ] {
        let message = assert_failure(&output);
        // The existing safe identifiers stay useful…
        assert!(message.contains("missing-available-tool"), "{message}");
        assert!(message.contains("solo"), "{message}");
        // …while the untrusted declaration text does not.
        assert!(!message.contains("[[tools]]"), "{message}");
        assert!(!message.contains(ENV_REF), "{message}");
    }
    assert_eq!(fixture.snapshot(), before);
}

// ---------------------------------------------------------------------------
// S11–S12: damaged fallback vs. lazy higher sources
// ---------------------------------------------------------------------------

#[test]
fn s11_a_damaged_record_fails_the_fallback_without_repair() {
    let marker = "sk-CORRUPT-RECORD-MARKER";
    let fixtures: Vec<(&'static str, Arrangement)> = vec![
        (
            "malformed json",
            Box::new(move |f: &Fixture| {
                f.write_record(&format!("{{ \"image\": \"{marker}\""));
            }),
        ),
        (
            "tag-only image",
            Box::new(|f: &Fixture| f.write_record_ref("127.0.0.1:1/private-a:latest")),
        ),
        (
            "fifo",
            Box::new(|f: &Fixture| {
                fs::create_dir_all(f.record().parent().unwrap()).unwrap();
                let path = std::ffi::CString::new(f.record().as_os_str().as_bytes()).unwrap();
                let made = unsafe { libc::mkfifo(path.as_ptr(), 0o600) };
                assert_eq!(made, 0, "mkfifo the record fixture");
            }),
        ),
        (
            "dangling symlink",
            Box::new(|f: &Fixture| {
                fs::create_dir_all(f.record().parent().unwrap()).unwrap();
                std::os::unix::fs::symlink("/nonexistent/record", f.record()).unwrap();
            }),
        ),
    ];
    for (name, arrange) in fixtures {
        let fixture = Fixture::new();
        arrange(&fixture);
        let before = fixture.snapshot();
        let output = fixture.show();
        let message = assert_failure(&output);
        assert!(
            message.contains("default-image.json") || message.contains("default"),
            "case `{name}`: the diagnostic must name the record safely:\n{message}"
        );
        assert!(
            !message.contains(marker) && !message.contains("private-a"),
            "case `{name}`: record contents must not leak:\n{message}"
        );
        assert_eq!(fixture.snapshot(), before, "case `{name}` must not repair");
        fixture.assert_no_trap_calls();
    }
}

#[test]
fn s12_a_damaged_unused_record_never_affects_a_higher_winner() {
    // Environment wins: a malformed record is not even read.
    let environment = Fixture::new();
    environment.write_record("{\"image\":\"sk-UNUSED-RECORD-MARKER\"");
    let before = environment.snapshot();
    let output = environment.show_with_env(&[("AGENT_VM_IMAGE_TAG", ENV_REF)]);
    assert_success(&output, &expected(ENV_REF, "AGENT_VM_IMAGE_TAG", None));
    assert!(!stderr(&output).contains("sk-UNUSED-RECORD-MARKER"));
    assert_eq!(environment.snapshot(), before);

    // User config wins: a FIFO record would hang an eager read.
    let user = Fixture::new();
    user.write_user_image(USER_REF);
    fs::create_dir_all(user.record().parent().unwrap()).unwrap();
    let path = std::ffi::CString::new(user.record().as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    let before = user.snapshot();
    let output = user.show();
    assert_success(
        &output,
        &expected(USER_REF, "user config", Some(&user.user_config())),
    );
    assert_eq!(user.snapshot(), before);

    // Project config wins: a dangling symlink record is never followed.
    let project = Fixture::new();
    project.write_project_image(PROJECT_REF);
    fs::create_dir_all(project.record().parent().unwrap()).unwrap();
    std::os::unix::fs::symlink("/nonexistent/record", project.record()).unwrap();
    let before = project.snapshot();
    let output = project.show();
    assert_success(
        &output,
        &expected(
            PROJECT_REF,
            "project config",
            Some(&project.project_config()),
        ),
    );
    assert_eq!(project.snapshot(), before);
}

#[test]
fn s13_the_recommendation_is_lazy_too() {
    let fixture = Fixture::new();
    // A tag-only seam is rejected by the immutable-reference rule; it is a
    // damaged recommendation, and only the fallback branch may notice.
    let invalid_seam = &[("AGENT_VM_TEST_DEFAULT_IMAGE", "127.0.0.1:1/offer-b:latest")];
    let failure = fixture.show_with_env(invalid_seam);
    let message = assert_failure(&failure);
    assert!(!message.contains("offer-b"), "{message}");

    fixture.write_project_image(PROJECT_REF);
    let success = fixture.show_with_env(invalid_seam);
    assert_success(
        &success,
        &expected(
            PROJECT_REF,
            "project config",
            Some(&fixture.project_config()),
        ),
    );
    assert!(
        !Path::new(&fixture.record()).exists(),
        "no adoption occurred"
    );

    // A retained record also outranks the recommendation, so its damage must
    // stay unread: the fallback is needed only when no record exists.
    let retained = Fixture::new();
    retained.write_record_ref(RETAINED_A);
    let output = retained.show_with_env(invalid_seam);
    assert_success(
        &output,
        &expected(RETAINED_A, "retained default", Some(&retained.record())),
    );
}

// ---------------------------------------------------------------------------
// S14–S15: escaping
// ---------------------------------------------------------------------------

#[test]
fn s14_the_report_escapes_reference_bytes_and_never_trims() {
    let fixture = Fixture::new();
    let hostile = "\u{1b}[31m\"q\\ \n\r\t\u{7f}é";
    let output = fixture.show_with_env(&[("AGENT_VM_IMAGE_TAG", hostile)]);
    assert_success(&output, &expected(hostile, "AGENT_VM_IMAGE_TAG", None));
    assert_eq!(
        stdout(&output).matches('\n').count(),
        2,
        "the report is exactly two logical lines"
    );
    assert!(
        !stdout(&output).contains('\u{1b}') && !stdout(&output).contains('\u{7f}'),
        "no terminal control bytes may survive: {:?}",
        stdout(&output)
    );
    assert!(
        stdout(&output).contains("\\x1b"),
        "ESC is rendered as a byte escape"
    );
}

#[test]
fn s14_the_file_line_escapes_host_path_bytes() {
    let hostile_home = OsString::from_vec("h\u{1b}o\"m\\e\n\u{e9}".as_bytes().to_vec());
    let fixture = Fixture::with_dir_names(&hostile_home, OsStr::new("project"));
    fixture.write_user_image(USER_REF);
    let output = fixture.show();
    assert_success(
        &output,
        &expected(USER_REF, "user config", Some(&fixture.user_config())),
    );
    assert!(
        !stdout(&output).contains('\u{1b}'),
        "the path is escaped, not raw: {:?}",
        stdout(&output)
    );
}

#[test]
fn s14_an_invalid_utf8_home_path_is_escaped_bytewise() {
    // APFS/HFS+ and ext4 accept non-UTF-8 names; if the filesystem refuses,
    // the byte-level policy is still covered by s14 above.
    let mut name = b"h\xffome".to_vec();
    name.push(b'1');
    let home = OsString::from_vec(name);
    let Some(fixture) = Fixture::try_with_dir_names(&home, OsStr::new("project")) else {
        eprintln!("SKIPPED: this filesystem refuses a non-UTF-8 directory name");
        return;
    };
    fixture.write_user_image(USER_REF);
    let output = fixture.show();
    assert_success(
        &output,
        &expected(USER_REF, "user config", Some(&fixture.user_config())),
    );
    assert!(stdout(&output).contains("\\xff"), "{:?}", stdout(&output));
}

#[test]
fn s15_control_characters_in_paths_are_escaped_in_failures() {
    let fixture = Fixture::with_dir_names(
        &OsString::from("h\u{1b}\u{7f}ome"),
        &OsString::from("p\nroject"),
    );
    let marker = "sk-CONTROL-PATH-MARKER";
    fixture.write_user_config(&format!("image = \" {marker} \"\n"));
    let output = fixture.show();
    let message = assert_failure(&output);
    let body = message.trim_end_matches('\n');
    assert!(
        !body.contains('\u{1b}') && !body.contains('\u{7f}') && !body.contains('\n'),
        "paths must be escaped, not raw:\n{message:?}"
    );
    assert!(!message.contains(marker), "{message}");
    assert!(message.contains("config.toml"), "{message}");
}

// ---------------------------------------------------------------------------
// S16–S18: no runtime, no cache, no network
// ---------------------------------------------------------------------------

#[test]
fn s16_no_runtime_is_invoked_and_state_is_untouched() {
    for selection in [
        "environment",
        "user",
        "project",
        "retained",
        "recommendation",
    ] {
        let fixture = Fixture::new();
        // Prepopulate state and cache with sentinels: show must not read,
        // rewrite or delete them either.
        fixture.write_file(&fixture.state.join("sentinel"), b"state");
        fixture.write_file(&fixture.cache.join("sentinel"), b"cache");
        let env: Vec<(&str, &str)> = match selection {
            "environment" => vec![("AGENT_VM_IMAGE_TAG", ENV_REF)],
            "user" => {
                fixture.write_user_image(USER_REF);
                vec![]
            }
            "project" => {
                fixture.write_project_image(PROJECT_REF);
                vec![]
            }
            "retained" => {
                fixture.write_record_ref(RETAINED_A);
                vec![]
            }
            _ => vec![("AGENT_VM_TEST_DEFAULT_IMAGE", RECOMMENDATION_B)],
        };
        let before = fixture.snapshot();
        let output = fixture.show_with_env(&env);
        assert!(
            output.status.success(),
            "case `{selection}` must succeed: {}",
            stderr(&output)
        );
        assert_eq!(
            fixture.snapshot(),
            before,
            "case `{selection}` changed state"
        );
        fixture.assert_no_trap_calls();
    }
}

#[test]
fn s17_a_selected_registry_endpoint_is_never_contacted() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let address = listener.local_addr().unwrap();

    // Calibrate: a real connection must be observable, so an empty queue below
    // means "no connection", not "broken oracle".
    let probe = TcpStream::connect(address).expect("calibrate connect");
    accept_within(&listener, Duration::from_secs(5)).expect("calibration connection accepted");
    drop(probe);
    drain(&listener);

    let repository = format!("{address}/private-image");

    let environment = Fixture::new();
    let output = environment.show_with_env(&[("AGENT_VM_IMAGE_TAG", &format!("{repository}:dev"))]);
    assert_success(
        &output,
        &expected(&format!("{repository}:dev"), "AGENT_VM_IMAGE_TAG", None),
    );
    assert!(
        accept_within(&listener, Duration::from_millis(300)).is_none(),
        "show must not contact the selected registry"
    );

    let retained = Fixture::new();
    retained.write_record_ref(&format!("{repository}@sha256:{}", "c".repeat(64)));
    let output = retained.show();
    assert_success(
        &output,
        &expected(
            &format!("{repository}@sha256:{}", "c".repeat(64)),
            "retained default",
            Some(&retained.record()),
        ),
    );
    assert!(
        accept_within(&listener, Duration::from_millis(300)).is_none(),
        "show must not contact the retained registry"
    );
}

fn accept_within(listener: &TcpListener, timeout: Duration) -> Option<TcpStream> {
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Some(stream),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("accept on the calibration listener: {error}"),
        }
    }
}

fn drain(listener: &TcpListener) {
    while accept_within(listener, Duration::from_millis(10)).is_some() {}
}

#[test]
fn s18_a_copied_binary_works_with_an_empty_path_and_no_runtime() {
    let fixture = Fixture::new();
    let copy = fixture.root.join("agent-vm-copy");
    fs::copy(agent_vm_bin(), &copy).expect("copy the binary");
    let empty_path = fixture.root.join("empty-path");
    fs::create_dir_all(&empty_path).unwrap();

    let mut command = Command::new(&copy);
    command
        .env_clear()
        .env("PATH", &empty_path)
        .env("HOME", &fixture.home)
        .env("TMPDIR", &fixture.tmp)
        .env("AGENT_VM_STATE_DIR", &fixture.state)
        .env("XDG_CACHE_HOME", &fixture.cache)
        .env("AGENT_VM_TEST_DEFAULT_IMAGE", RECOMMENDATION_B)
        .current_dir(&fixture.project)
        .args(["image", "show"]);
    let output = fixture.run(command);
    assert_success(
        &output,
        &expected(RECOMMENDATION_B, "initial recommendation", None),
    );
    assert!(!fixture.home.join(".cache").exists());
    assert!(!fixture.home.join(".config").exists());
}

// ---------------------------------------------------------------------------
// S19–S20: help and rejected arguments
// ---------------------------------------------------------------------------

#[test]
fn s19_help_is_available_and_distinguishes_show() {
    let fixture = Fixture::new();
    // A broken configuration must not take help down with it.
    fixture.write_user_config("image = \"not a reference\"\n");
    fixture.write_record_ref(RETAINED_A);

    for argv in [
        vec!["image", "show", "--help"],
        vec!["image", "show", "-h"],
        vec!["help", "image", "show"],
        vec!["image", "--help"],
    ] {
        let output = fixture.run(fixture.command(&argv));
        let text = stdout(&output) + &stderr(&output);
        assert!(
            output.status.success(),
            "`{argv:?}` must print help: {}",
            stderr(&output)
        );
        assert!(
            text.to_lowercase().contains("boot image"),
            "`{argv:?}` must describe the selected boot image:\n{text}"
        );
        if argv.contains(&"show") {
            // `-h` prints the short about by design; the long form carries the
            // read-only/offline promise and the disclosed fields.
            if argv.contains(&"--help") {
                assert!(
                    text.contains("full reference") || text.contains("provenance"),
                    "`{argv:?}` must describe reference and provenance:\n{text}"
                );
            }
            assert!(
                !text
                    .lines()
                    .any(|line| line.trim_start().starts_with("--image")),
                "show must not advertise a --image option:\n{text}"
            );
        }
    }

    // Help evaluates no default: the retained record is untouched and no
    // runtime was consulted.
    let before = fixture.snapshot();
    let output = fixture.run(fixture.command(&["image", "show", "--help"]));
    assert!(output.status.success());
    assert_eq!(fixture.snapshot(), before);
    fixture.assert_no_trap_calls();
    let top = fixture.run(fixture.command(&["--help"]));
    assert!(top.status.success());
    let text = stdout(&top);
    assert!(
        text.contains("image"),
        "the top-level help must list the image group:\n{text}"
    );
}

#[test]
fn s20_no_extra_argument_surface_is_accepted() {
    let fixture = Fixture::new();
    fixture.write_user_image(USER_REF);
    fixture.write_record_ref(RETAINED_A);
    let before = fixture.snapshot();

    for argv in [
        vec!["image", "show", "--image", ENV_REF],
        vec!["image", "show", "--image=REF"],
        vec!["image", "--image", ENV_REF, "show"],
        vec!["image", "--image=REF", "show"],
        vec!["--image", ENV_REF, "image", "show"],
        vec!["image", "show", "extra-positional"],
        vec!["image", "show", "--json"],
        vec!["image", "show", "--tag", "127.0.0.1:1/x:dev"],
        vec!["image", "show", "--memory-gib", "2"],
    ] {
        let output = fixture.run(fixture.command(&argv));
        assert!(
            !output.status.success(),
            "`{argv:?}` must be rejected, got: {}",
            stdout(&output)
        );
        assert_eq!(stdout(&output), "", "`{argv:?}` printed image output");
    }
    assert_eq!(
        fixture.snapshot(),
        before,
        "a rejected argv selects nothing"
    );
    fixture.assert_no_trap_calls();
}

// ---------------------------------------------------------------------------
// S21–S22: disclosure is confined; provenance is consistent
// ---------------------------------------------------------------------------

#[test]
fn s21_tracing_and_debug_output_stay_redacted() {
    let fixture = Fixture::new();
    fixture.write_record_ref(RETAINED_A);

    let show = fixture.show_with_env(&[("RUST_LOG", "trace"), ("AGENT_VM_DEBUG_CONFIG", "1")]);
    assert_success(
        &show,
        &expected(RETAINED_A, "retained default", Some(&fixture.record())),
    );
    assert!(
        !stderr(&show).contains("private-a"),
        "show's logs must not carry the reference:\n{}",
        stderr(&show)
    );

    let doctor = fixture.run(fixture.command(&["doctor"]));
    let text = stdout(&doctor) + &stderr(&doctor);
    assert!(
        !text.contains("private-a"),
        "doctor must stay redacted:\n{text}"
    );
    assert!(
        text.contains("the default boot image") || text.contains("retained default ["),
        "doctor still reports the default safely:\n{text}"
    );
}

#[test]
fn s22_each_output_is_one_consistent_selection() {
    let fixture = Fixture::new();
    let seam = &[("AGENT_VM_TEST_DEFAULT_IMAGE", RECOMMENDATION_B)];

    // absent -> A -> B -> absent, all from parent fixture operations.
    let absent_first = fixture.show_with_env(seam);
    assert_success(
        &absent_first,
        &expected(RECOMMENDATION_B, "initial recommendation", None),
    );
    assert!(!fixture.record().exists(), "show created the record");

    fixture.write_record_ref(RETAINED_A);
    let a = fixture.show_with_env(seam);
    assert_success(
        &a,
        &expected(RETAINED_A, "retained default", Some(&fixture.record())),
    );

    let retained_b = "127.0.0.1:1/private-b@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    fixture.write_record_ref(retained_b);
    let b = fixture.show_with_env(seam);
    assert_success(
        &b,
        &expected(retained_b, "retained default", Some(&fixture.record())),
    );

    fs::remove_file(fixture.record()).unwrap();
    let absent_last = fixture.show_with_env(seam);
    assert_success(
        &absent_last,
        &expected(RECOMMENDATION_B, "initial recommendation", None),
    );
    assert!(!fixture.record().exists());
}

// ---------------------------------------------------------------------------
// S23–S24: HOME discovery and discovery-path provenance
// ---------------------------------------------------------------------------

#[test]
fn s23_home_discovery_is_safe_and_lazy() {
    // A higher source needs no default read, so an unset HOME still succeeds.
    let fixture = Fixture::new();
    let mut command = fixture.command(&["image", "show"]);
    command
        .env("AGENT_VM_IMAGE_TAG", ENV_REF)
        .env_remove("HOME");
    let output = fixture.run(command);
    assert_success(&output, &expected(ENV_REF, "AGENT_VM_IMAGE_TAG", None));

    // A project-config winner also needs no default read, so HOME is irrelevant.
    let fixture = Fixture::new();
    fixture.write_project_image(PROJECT_REF);
    let mut command = fixture.command(&["image", "show"]);
    command.env_remove("HOME");
    let output = fixture.run(command);
    assert_success(
        &output,
        &expected(
            PROJECT_REF,
            "project config",
            Some(&fixture.project_config()),
        ),
    );

    // With no higher source the default slot cannot be located: fail with no
    // stdout rather than guess a home directory or select a lower "source".
    let fixture = Fixture::new();
    let before = fixture.snapshot();
    let mut command = fixture.command(&["image", "show"]);
    command.env_remove("HOME");
    let output = fixture.run(command);
    let message = assert_failure(&output);
    assert!(message.contains("HOME"), "{message}");
    assert_eq!(fixture.snapshot(), before, "no state may be created");

    // Set but empty or relative is a hard error, not a silent fallback.
    for home in ["", "relative/home"] {
        let fixture = Fixture::new();
        let mut command = fixture.command(&["image", "show"]);
        command.env("HOME", home);
        let output = fixture.run(command);
        let message = assert_failure(&output);
        assert!(message.contains("HOME"), "HOME={home:?}: {message}");
    }

    // A missing absolute HOME is an ordinary uninitialized host.
    let fixture = Fixture::new();
    let missing = fixture.root.join("missing-home");
    let mut command = fixture.command(&["image", "show"]);
    command.env("HOME", &missing);
    let output = fixture.run(command);
    assert_success(
        &output,
        &expected(PRODUCTION_RECOMMENDATION, "initial recommendation", None),
    );
    assert!(!missing.exists(), "show created a missing HOME");
}

#[test]
fn s24_provenance_paths_follow_discovery() {
    // The project path is the canonical current directory: a symlinked cwd
    // names the real config file.
    let fixture = Fixture::new();
    let real = fixture.root.join("project-real");
    fs::create_dir(&real).unwrap();
    fixture.write_file(
        &real.join(".agent-vm/config.toml"),
        format!("image = \"{PROJECT_REF}\"\n"),
    );
    let link = fixture.root.join("project-link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let mut command = fixture.command(&["image", "show"]);
    command.current_dir(&link);
    let output = fixture.run(command);
    let canonical = real.canonicalize().unwrap().join(".agent-vm/config.toml");
    assert_success(
        &output,
        &expected(PROJECT_REF, "project config", Some(&canonical)),
    );

    // The user path is the literal $HOME location: it is not canonicalized.
    let mut fixture = Fixture::new();
    let real_home = fixture.root.join("home-real");
    fs::create_dir(&real_home).unwrap();
    fixture.write_file(
        &real_home.join(".config/agent-vm/config.toml"),
        format!("image = \"{USER_REF}\"\n"),
    );
    let home_link = fixture.root.join("home-link");
    std::os::unix::fs::symlink(&real_home, &home_link).unwrap();
    fixture.home = home_link.clone();
    let output = fixture.show();
    assert_success(
        &output,
        &expected(
            USER_REF,
            "user config",
            Some(&home_link.join(".config/agent-vm/config.toml")),
        ),
    );

    // Discovery is the current directory only, not an upward search.
    let fixture = Fixture::new();
    fixture.write_project_image(PROJECT_REF);
    let nested = fixture.project.join("sub/dir");
    fs::create_dir_all(&nested).unwrap();
    let mut command = fixture.command(&["image", "show"]);
    command.current_dir(&nested);
    let output = fixture.run(command);
    assert_success(
        &output,
        &expected(PRODUCTION_RECOMMENDATION, "initial recommendation", None),
    );
}
