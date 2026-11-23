//! `agent-vm _notify-click` as a process: what a banner click really does.
//!
//! The hidden verb is spawned by the macOS notification helper hours after the
//! launch that raised the banner, so it is held to the same rule `access` is: no
//! `msb`, no image, no user config. What it *writes* is the contract: one
//! `.command` file under `$HOME/.cache/agent-vm/notify-click`, whose operands are
//! all launcher-originated and whose only human-readable line is escaped
//! (issue #501 slice 4, B7/B8/R8/S3).
//!
//! The `/usr/bin/open` on a click's end exists only through LaunchServices, which
//! no CI host has, so a debug build honours `AGENT_VM_TEST_OPEN`
//! (`notify/terminal.rs::TEST_OPEN_SETTING`). Under `--release` that seam is
//! compiled out and these tests **fail loudly** rather than skip — the same rule
//! `tests/secret_pty.rs` states, and CI never runs the release test profile.

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The session a click names: eight lowercase hex digits, as the helper validates.
const SESSION: &str = "3f9a12c4";

/// The refusal ID a seeded session log answers with, so a report proves it read
/// that log rather than a decoy.
const ENTRY: &str = "0e7e41fb";

fn agent_vm() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-vm"))
}

fn mode_of(path: &Path) -> u32 {
    fs::symlink_metadata(path)
        .unwrap_or_else(|error| panic!("statistics {}: {error}", path.display()))
        .permissions()
        .mode()
        & 0o777
}

/// One host as a click sees it: a `$HOME`, a state root, a project, and the
/// program that stands in for `/usr/bin/open` so the argv is observable.
struct Host {
    /// Held so the directory outlives every use and is removed on drop.
    root: tempfile::TempDir,
    home: PathBuf,
    state: PathBuf,
    project: PathBuf,
    open: PathBuf,
    open_log: PathBuf,
}

impl Host {
    fn new() -> Self {
        let root = tempfile::Builder::new()
            .prefix("notify-click-")
            .tempdir()
            .expect("a temp directory");
        let home = root.path().join("home");
        let state = root.path().join("state");
        let project = root.path().join("project");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&project).unwrap();
        let project = project.canonicalize().unwrap();
        let open = root.path().join("open-stub");
        fs::write(
            &open,
            concat!(
                "#!/bin/sh\n",
                "printf '%s\\n' \"$@\" > \"$OPEN_ARGS\"\n",
                "exit \"${OPEN_STATUS:-0}\"\n",
            ),
        )
        .unwrap();
        fs::set_permissions(&open, fs::Permissions::from_mode(0o755)).unwrap();
        let open_log = root.path().join("open-args");
        Self {
            root,
            home,
            state,
            project,
            open,
            open_log,
        }
    }

    /// A user config that cannot be parsed and a `MSB_PATH` that does not exist:
    /// neither may cost the click (S3).
    fn with_broken_config(self) -> Self {
        let dir = self.home.join(".config/agent-vm");
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(dir.join("config.toml"), "this is not = valid [ toml\n").unwrap();
        fs::set_permissions(dir.join("config.toml"), fs::Permissions::from_mode(0o600)).unwrap();
        self
    }

    /// Run `agent-vm` with only what a click may depend on, plus `env`.
    fn run(&self, env: &[(&str, &str)], args: &[String]) -> Output {
        let mut command = self.command();
        for (key, value) in env {
            command.env(key, value);
        }
        command.args(args).output().expect("running agent-vm")
    }

    /// The environment a click may depend on and nothing else: no ambient `PATH`
    /// beyond the system one, no `XDG_*`, no `AGENT_VM_*`.
    fn command(&self) -> Command {
        let mut command = Command::new(agent_vm());
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.home)
            .env("MSB_PATH", self.home.join("no-such-msb"))
            .env("AGENT_VM_TEST_OPEN", &self.open)
            .env("OPEN_ARGS", &self.open_log)
            .current_dir(&self.project);
        command
    }

    /// The operands every click names: this host's project and state root.
    fn click_args(&self) -> Vec<String> {
        click_args(&self.project, &self.state)
    }

    /// One click on this host's banner, with `env` and `extra` added.
    fn click(&self, env: &[(&str, &str)], extra: &[&str]) -> Output {
        let mut args = self.click_args();
        args.extend(extra.iter().map(|argument| (*argument).to_owned()));
        self.run(env, &args)
    }

    fn click_dir(&self) -> PathBuf {
        self.home.join(".cache/agent-vm/notify-click")
    }

    /// The operands the click handed the program in place of `/usr/bin/open`.
    fn open_argv(&self) -> Vec<String> {
        fs::read_to_string(&self.open_log)
            .expect("the open stand-in recorded its argv")
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn scripts(&self) -> BTreeSet<String> {
        fs::read_dir(self.click_dir())
            .map(|entries| {
                entries
                    .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// The operands one click names, spelled in the order the helper writes them.
fn click_args(project: &Path, state: &Path) -> Vec<String> {
    [
        "_notify-click",
        "--session",
        SESSION,
        "--project",
        project.to_str().expect("the project path is UTF-8"),
        "--state-dir",
        state.to_str().expect("the state root is UTF-8"),
    ]
    .map(str::to_owned)
    .to_vec()
}

/// The script a click wrote: its path, its text, and the mode macOS will execute
/// it with.
fn only_script(host: &Host) -> (PathBuf, String) {
    let names: Vec<String> = host.scripts().into_iter().collect();
    assert_eq!(names.len(), 1, "one click writes one script: {names:?}");
    let name = &names[0];
    assert!(
        name.starts_with(&format!("click-{SESSION}-")) && name.ends_with(".command"),
        "the name is click-<session>-<8 hex>.command: {name}"
    );
    let path = host.click_dir().join(name);
    assert_eq!(mode_of(&path), 0o700, "the script is 0700: {name}");
    let text = fs::read_to_string(&path).expect("the script is UTF-8");
    (path, text)
}

/// Run a written `.command` file the way macOS does: `sh` on the file, from a
/// directory that is not the project, under `env -i HOME=…` — the environment a
/// LaunchServices relaunch or a reused Terminal.app window leaves behind, with no
/// `PATH`, no `XDG_*` and no `AGENT_VM_*` from the launch that wrote the file.
///
/// `SHELL` is the last thing the script runs (`exec "${SHELL:-/bin/zsh}"`), so it
/// is pointed at a program that exits at once instead of starting a shell that
/// would wait on a terminal no test has.
fn run_script(script: &Path, host: &Host) -> Output {
    Command::new("/bin/sh")
        .arg(script)
        .env_clear()
        .env("HOME", &host.home)
        .env("SHELL", "/usr/bin/true")
        .current_dir(host.root.path())
        .output()
        .expect("running the click script")
}

// --- A click that works ------------------------------------------------------

/// The click is dispatched before credential preflight, the MSB prologue and the
/// runtime, so it has to work with a broken user config and no `msb` at all.
#[test]
fn a_click_works_with_a_broken_config_and_no_runtime() {
    let host = Host::new().with_broken_config();
    let out = host.click(&[], &[]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stderr), "", "a click is quiet");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "");

    let (path, text) = only_script(&host);
    assert!(
        text.starts_with("#!/bin/sh\n"),
        "the shell is the file itself: {text}"
    );
    let bin_dir = agent_vm().parent().unwrap().to_str().unwrap().to_owned();
    assert!(
        text.contains(&format!(
            "export AGENT_VM_STATE_DIR='{}'\n",
            host.state.to_str().unwrap()
        )),
        "the state root is pinned: {text}"
    );
    assert!(
        text.contains(&format!(
            "'{}' access --session '{SESSION}'\n",
            agent_vm().to_str().unwrap()
        )),
        "the report is this binary's `access`: {text}"
    );
    assert!(
        text.contains(&format!("export PATH='{bin_dir}':\"$PATH\"\n")),
        "the guest's PATH cannot shadow this binary: {text}"
    );
    assert!(
        text.contains(&format!(
            "if cd '{}' 2>/dev/null; then\n",
            host.project.to_str().unwrap()
        )),
        "the project is the directory entered: {text}"
    );
    assert!(text.ends_with("exec \"${SHELL:-/bin/zsh}\"\n"), "{text}");

    // The default terminal is the `.command` file itself, which LaunchServices
    // runs in Terminal.app: no Apple-events permission and no named app.
    assert_eq!(
        host.open_argv(),
        [
            "-a".to_owned(),
            "Terminal".to_owned(),
            path.display().to_string()
        ]
    );
}

/// Each terminal is named explicitly, with the flags that make a new window
/// instead of resurrecting the previous session's state.
#[test]
fn every_terminal_is_opened_with_its_own_arguments() {
    let host = Host::new().with_broken_config();
    let expected: [(&str, &[&str]); 4] = [
        ("terminal", &["-a", "Terminal"]),
        (
            "ghostty",
            &[
                "-na",
                "Ghostty",
                "--args",
                "--window-save-state=never",
                "--quit-after-last-window-closed=true",
                "-e",
            ],
        ),
        (
            "wezterm",
            &[
                "-na",
                "WezTerm",
                "--args",
                "start",
                "--always-new-process",
                "--",
            ],
        ),
        ("alacritty", &["-na", "Alacritty", "--args", "-e"]),
    ];
    for (terminal, prefix) in expected {
        let out = host.click(&[], &["--terminal", terminal]);
        assert!(
            out.status.success(),
            "{terminal}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let argv = host.open_argv();
        let (script, rest) = argv.split_last().expect("open is given a script");
        assert!(
            script.starts_with(&format!("{}/click-{SESSION}-", host.click_dir().display())),
            "{terminal}: {argv:?}"
        );
        assert_eq!(rest, prefix, "{terminal} argv");
    }

    // An unknown terminal is refused rather than guessed: a substitution would
    // open a terminal the operator did not ask for.
    let out = host.click(&[], &["--terminal", "kitty"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("accepts terminal, ghostty, wezterm or alacritty"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A terminal that would not open is a failing click, and its status is the one
/// the program gave: nothing is silently substituted, and no second terminal is
/// tried.
#[test]
fn a_failing_open_is_a_failing_click() {
    let host = Host::new();
    let out = host.click(&[("OPEN_STATUS", "7")], &[]);
    assert_eq!(out.status.code(), Some(7));

    // A program that cannot be run at all names itself and the reason.
    let missing = host.root.path().join("no-such-open");
    let out = host.click(&[("AGENT_VM_TEST_OPEN", missing.to_str().unwrap())], &[]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("to open the terminal") && stderr.contains("no-such-open"),
        "{stderr}"
    );
}

// --- The state root the script carries ---------------------------------------

/// A click is written once and run later, from a launch environment nobody
/// controls, so the state root is an operand in the script rather than something
/// the script re-derives from `XDG_STATE_HOME` (B8).
#[test]
fn the_state_root_is_pinned_in_the_script_not_inherited() {
    let host = Host::new();
    let decoy = host.root.path().join("decoy-state");
    let decoy_env = decoy.to_str().unwrap();
    let out = host.click(
        &[
            ("XDG_STATE_HOME", decoy_env),
            ("AGENT_VM_STATE_DIR", decoy_env),
        ],
        &[],
    );
    assert!(out.status.success());
    let (_, text) = only_script(&host);
    assert!(
        text.contains(&format!(
            "export AGENT_VM_STATE_DIR='{}'\n",
            host.state.to_str().unwrap()
        )),
        "{text}"
    );
    assert!(
        !text.contains("decoy-state"),
        "an ambient state root reached the script: {text}"
    );

    // The script says what the run proves: the pinned log answers even though the
    // ambient `XDG_STATE_HOME` names somewhere else entirely.
    seed_logged_session(&host.state, &host.project);
    let decoy_state = decoy.join("agent-vm");
    fs::create_dir_all(decoy_state.join("sessions")).unwrap();
    let (script, _) = only_script(&host);
    let out = run_script(&script, &host);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains(ENTRY), "the pinned log answered: {stdout}");
}

/// `XDG_CACHE_HOME` can be set per launch, so a guest-writable value would
/// redirect a file macOS then executes. The click directory is built from `$HOME`
/// alone.
#[test]
fn a_guest_writable_cache_directory_is_ignored() {
    let host = Host::new();
    let cache = host.project.join("cache");
    fs::create_dir_all(&cache).unwrap();
    let out = host.click(&[("XDG_CACHE_HOME", cache.to_str().unwrap())], &[]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        fs::read_dir(&cache).unwrap().count(),
        0,
        "nothing was written under the guest-writable cache"
    );
    let (path, _) = only_script(&host);
    assert!(
        path.starts_with(&host.home),
        "the script lives under $HOME: {}",
        path.display()
    );
}

// --- What a click refuses ----------------------------------------------------

/// A directory inside the project is what the guest can write, so it is refused
/// before anything is created: not even the two empty parents appear.
#[test]
fn a_click_directory_inside_the_project_is_refused() {
    let host = Host::new();
    let home = host.project.join("home");
    fs::create_dir_all(&home).unwrap();
    let out = host.click(&[("HOME", home.to_str().unwrap())], &[]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to write a click script inside the project"),
        "{stderr}"
    );
    assert!(
        !home.join(".cache").exists(),
        "a refused click creates nothing inside the project"
    );
}

/// A symlinked parent is an error, never a redirection to whatever it points at.
#[test]
fn a_symlinked_parent_is_refused() {
    let host = Host::new();
    let elsewhere = host.root.path().join("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    symlink(&elsewhere, host.home.join(".cache")).unwrap();
    let out = host.click(&[], &[]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("is a symlink or not a directory"),
        "{stderr}"
    );
    assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);
}

/// The click directory itself is the last component that must not be a link: a
/// symlink there would put the file macOS executes wherever it points.
#[test]
fn a_symlinked_click_directory_is_refused() {
    let host = Host::new();
    let target = host.root.path().join("target");
    fs::create_dir_all(&target).unwrap();
    let app = host.home.join(".cache/agent-vm");
    fs::create_dir_all(&app).unwrap();
    symlink(&target, app.join("notify-click")).unwrap();
    let out = host.click(&[], &[]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("is a symlink or not a directory"),
        "{stderr}"
    );
    assert_eq!(
        fs::read_dir(&target).unwrap().count(),
        0,
        "the link's target was never written through"
    );
}

/// The session ID becomes an operand of a command the script runs, so it is
/// validated here instead of being passed on to open a different session.
#[test]
fn a_session_that_is_not_eight_hex_digits_is_refused() {
    let host = Host::new();
    for session in ["abcd", "3f9a12c", "3f9a12c4a", "3F9A12C4", "3f9a12cg"] {
        let out = host.run(
            &[],
            &[
                "_notify-click".to_owned(),
                "--session".to_owned(),
                session.to_owned(),
                "--project".to_owned(),
                host.project.to_str().unwrap().to_owned(),
                "--state-dir".to_owned(),
                host.state.to_str().unwrap().to_owned(),
            ],
        );
        assert_eq!(out.status.code(), Some(1), "{session}");
        assert!(
            String::from_utf8_lossy(&out.stderr)
                .contains("a session ID is exactly 8 lowercase hex digits"),
            "{session}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    assert!(
        !host.click_dir().exists(),
        "a refused session writes no click directory"
    );
}

/// A relative operand would be resolved against whatever directory the script
/// happens to run in, which for a click is nobody's choice.
#[test]
fn relative_paths_are_refused() {
    let host = Host::new();
    for (flag, value) in [("--project", "project"), ("--state-dir", "state")] {
        let mut args = host.click_args();
        let index = args.iter().position(|arg| arg == flag).unwrap() + 1;
        args[index] = value.to_owned();
        let out = host.run(&[], &args);
        assert_eq!(out.status.code(), Some(1), "{flag}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("must be an absolute path"),
            "{flag}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    assert!(!host.click_dir().exists());
}

// --- Pruning -----------------------------------------------------------------

/// Back-date an entry so the click directory's pruner sees it as expired.
fn age(path: &Path, seconds: i64) {
    use std::os::unix::ffi::OsStrExt as _;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let when = now - seconds;
    let times = [
        libc::timespec {
            tv_sec: when,
            tv_nsec: 0,
        },
        libc::timespec {
            tv_sec: when,
            tv_nsec: 0,
        },
    ];
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: `c_path` is a valid NUL-terminated path and `times` two timespecs.
    let status = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            c_path.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    assert_eq!(status, 0, "aging {}", path.display());
}

/// A banner can outlive its launcher, so a script is kept for a day rather than
/// deleted on use. Pruning stats without following and unlinks only regular
/// files, so nothing another process substituted can redirect the deletion.
#[test]
fn old_scripts_are_pruned_and_nothing_else_is_touched() {
    let host = Host::new();
    let dir = host.click_dir();
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();

    let old = dir.join(format!("click-{SESSION}-deadbeef.command"));
    let fresh = dir.join(format!("click-{SESSION}-feedface.command"));
    let short = dir.join("click-.command");
    let other = dir.join("notes.txt");
    for path in [&old, &fresh, &short, &other] {
        fs::write(path, b"#!/bin/sh\n").unwrap();
    }
    let target = host.root.path().join("link-target");
    fs::write(&target, b"kept\n").unwrap();
    let link = dir.join(format!("click-{SESSION}-cafebabe.command"));
    symlink(&target, &link).unwrap();

    // Two days old: past `SCRIPT_RETENTION`, which is one.
    for path in [&old, &short, &other, &link] {
        age(path, 2 * 24 * 60 * 60);
    }
    age(&target, 2 * 24 * 60 * 60);

    let out = host.click(&[], &[]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(!old.exists(), "an expired script is removed");
    assert!(fresh.exists(), "a fresh script is kept");
    assert!(
        short.exists(),
        "a name that is not click-<id>.command is kept"
    );
    assert!(other.exists(), "a file this verb did not write is kept");
    assert!(
        fs::symlink_metadata(&link).is_ok(),
        "a symlink is never unlinked as if it were a script"
    );
    assert!(target.exists(), "the symlink's target is never followed");
    // The click's own script is one more entry.
    assert_eq!(host.scripts().len(), 5, "{:?}", host.scripts());
}

// --- A hostile project path --------------------------------------------------

/// Every byte a project path can hold is legal in a `cd` operand, and none of it
/// may reach the terminal: the raw path is one quoted word, and the one line a
/// human reads comes from `one_line::path`.
#[test]
fn a_hostile_project_path_is_one_quoted_word_and_one_safe_line() {
    let hostile = "pro ject 'q' $(touch pwned) \u{1b}[31m\nend";
    let host = Host::new();
    let project = host.root.path().join(hostile);
    fs::create_dir_all(&project).unwrap();
    let project = project.canonicalize().unwrap();

    let out = host.run(&[], &click_args(&project, &host.state));
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let (script, text) = only_script(&host);

    // The raw bytes are one single-quoted word, so `'`, `$()` and the newline are
    // all inert: `/bin/sh -n` parses the file without executing it.
    let raw = project.to_str().expect("the hostile path is UTF-8");
    let word = format!("'{}'", raw.replace('\'', "'\\''"));
    assert!(
        text.contains(&format!("if cd {word} 2>/dev/null; then\n")),
        "{text}"
    );
    let syntax = Command::new("/bin/sh")
        .args(["-n"])
        .arg(&script)
        .output()
        .expect("running /bin/sh -n");
    assert!(
        syntax.status.success(),
        "/bin/sh -n: {}",
        String::from_utf8_lossy(&syntax.stderr)
    );

    // The project exists, so `cd` reaches it: the session log is found and the
    // fallback line is never printed.
    seed_logged_session(&host.state, &project);
    let out = run_script(&script, &host);
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stderr), "", "the cd succeeded");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains(ENTRY),
        "the report ran in the project: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    // The project is gone: the one line that says so is escaped, so no ESC and no
    // newline in the path can forge a second line or move the cursor.
    fs::rename(&project, host.root.path().join("moved-away")).unwrap();
    let out = run_script(&script, &host);
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("agent-vm: project directory is no longer available: "),
        "{stderr}"
    );
    assert!(
        stderr.contains("$(touch pwned) \\x1b[31m\\x0aend"),
        "the path is escaped: {stderr}"
    );
    assert!(
        !stderr.contains('\u{1b}'),
        "no raw ESC reached the terminal"
    );
    assert_eq!(stderr.lines().count(), 1, "one line, not two: {stderr}");
    assert!(
        !host.root.path().join("pwned").exists() && !host.project.join("pwned").exists(),
        "`$()` in the path never ran"
    );
}

// --- A seeded session log ----------------------------------------------------

/// The project hash `access` looks under: the 12-hex prefix of SHA-256 over the
/// canonical project directory.
fn hash_project(project: &Path) -> String {
    use sha2::{Digest, Sha256};
    use std::os::unix::ffi::OsStrExt as _;
    let path = project.canonicalize().unwrap();
    Sha256::digest(path.as_os_str().as_bytes())[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// One logged session carrying one refusal, in the shape the launcher persists.
///
/// Seeded rather than produced: a click is read-only, so a report that names this
/// entry proves the script reached both the project and the state root the
/// launcher pinned.
fn seed_logged_session(state: &Path, project: &Path) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let entry = serde_json::json!({
        "id": ENTRY,
        "key": {"kind": "network_denial", "destination": {
            "variant": "address", "protocol": "tcp", "ip": "203.0.113.10", "port": 443}},
        "layer": "tenant", "last_site": "tcp-syn", "last_ip": "203.0.113.10",
        "name": null, "last_revision": 1, "count": 1,
        "first_ms": now - 1_000, "last_ms": now - 1_000
    });
    let session = serde_json::json!({
        "info": {"id": SESSION, "pid": 1, "started_ms": now - 60_000, "socket": true},
        "rev": 2,
        "ended_ms": now - 30_000,
        "heartbeat_ms": now - 30_000,
        "suppressed": 0, "lost": 0, "gap": false,
        "entries": [entry]
    });
    let sessions = state.join(format!("{}.sessions", hash_project(project)));
    fs::create_dir_all(&sessions).unwrap();
    fs::set_permissions(&sessions, fs::Permissions::from_mode(0o700)).unwrap();
    let record = sessions.join("refusals.json");
    fs::write(
        &record,
        serde_json::json!({"v": 1, "evicted_sessions": 0, "sessions": [session]}).to_string(),
    )
    .unwrap();
    fs::set_permissions(&record, fs::Permissions::from_mode(0o600)).unwrap();
}
