//! Boot-free integration tests for the #90 protected-host-file contract
//! (ADR-0020): a host Pi credential file must be unreachable from the guest in
//! every mount mode.
//!
//! Modeled on `tests/mount_fork.rs` — same controlled
//! `$HOME`/`AGENT_VM_STATE_DIR`/cwd, fake patched `msb`, deliberately-bogus
//! `localhost:1/...` registry, and `AGENT_VM_DEBUG_CONFIG` `SandboxConfig` JSON
//! dump. Hermetic and fast: no DNS, no image pull, no Hypervisor.framework.
//! Everything here is a *rejection* or a *pre-pull build*, so no VM ever boots.

use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

/// Never resolves; only used to drive execution far enough into `launch()` to
/// prove `builder.build()` already ran (its debug JSON dump happens right
/// before the pull, which is what fails here).
const BOGUS_IMAGE: &str = "localhost:1/does-not-exist:latest";

/// Subcommands `build_command` registers that are not launch verbs
/// (`cli::BUILTIN_SUBCOMMANDS`, which integration tests cannot import).
const BUILTIN_SUBCOMMANDS: &[&str] = &[
    "setup",
    "pull",
    "msb",
    "clipboard",
    "doctor",
    "secret",
    "_intercept-hook",
    "help",
];

fn agent_vm_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-vm"))
}

/// Base directory for harness `$HOME`/project dirs on the real workspace
/// filesystem rather than under a guest tmpfs prefix: `run::guest_path_is_safe`
/// remaps any project below `/tmp` to `/workspace`, which breaks tests that
/// reason about the project's guest path. Cargo creates `CARGO_TARGET_TMPDIR`
/// before running integration tests.
fn harness_tmpdir() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
}

fn write_fake_msb(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("msb");
    std::fs::write(&path, "#!/bin/sh\necho 'msb 0.6.15'\nexit 0\n").unwrap();
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).unwrap();
    path
}

/// Run `child` to completion, killing it if it doesn't exit within `timeout`.
/// Reads stdout/stderr on separate threads so a full pipe can't deadlock.
fn run_with_timeout(mut cmd: Command, timeout: Duration) -> Output {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("failed to spawn agent-vm");
    let mut stdout_pipe = child.stdout.take().unwrap();
    let mut stderr_pipe = child.stderr.take().unwrap();
    let stdout_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buf);
        buf
    });
    let stderr_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf);
        buf
    });

    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait failed") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("agent-vm did not exit within {timeout:?} (possible hang)");
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    Output {
        status,
        stdout: stdout_handle.join().unwrap(),
        stderr: stderr_handle.join().unwrap(),
    }
}

/// One isolated `$HOME` + `AGENT_VM_STATE_DIR` + project dir (cwd) + fake
/// `MSB_PATH`.
struct Harness {
    home: tempfile::TempDir,
    state: tempfile::TempDir,
    project: tempfile::TempDir,
    fake_msb: PathBuf,
}

impl Harness {
    fn new() -> Self {
        // The relay socket lives below the state directory, so keep that one
        // under `/tmp` for the Unix socket-path limit. `$HOME` and the project
        // dir stay on the workspace filesystem.
        let home = tempfile::tempdir_in(harness_tmpdir()).unwrap();
        let state = tempfile::tempdir_in("/tmp").unwrap();
        let project = tempfile::tempdir_in(harness_tmpdir()).unwrap();
        let fake_msb = write_fake_msb(home.path());
        Self {
            home,
            state,
            project,
            fake_msb,
        }
    }

    fn home_path(&self) -> PathBuf {
        self.home.path().canonicalize().unwrap()
    }

    /// Create the host Pi home (and both protected files) under this harness's
    /// `$HOME`.
    fn seed_pi_home(&self) -> PathBuf {
        let pi_home = self.home_path().join(".pi");
        std::fs::create_dir_all(pi_home.join("agent")).unwrap();
        std::fs::write(pi_home.join("agent/auth.json"), "{\"token\":\"host\"}").unwrap();
        std::fs::write(pi_home.join("agent/models.json"), "{}").unwrap();
        std::fs::write(pi_home.join("settings.json"), "{}").unwrap();
        std::fs::create_dir_all(pi_home.join("extensions")).unwrap();
        std::fs::write(pi_home.join("extensions/x.js"), "x").unwrap();
        pi_home
    }

    fn run_shell(&self, mounts: &[&str]) -> Output {
        self.run_verb("shell", mounts, true, self.project.path())
    }

    fn run_shell_from(&self, mounts: &[&str], project: &Path) -> Output {
        self.run_verb("shell", mounts, true, project)
    }

    fn run_verb(&self, verb: &str, mounts: &[&str], set_home: bool, project: &Path) -> Output {
        let mut cmd = Command::new(agent_vm_bin());
        cmd.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env(
                "AGENT_VM_STATE_DIR",
                self.state.path().canonicalize().unwrap(),
            )
            .env("MSB_PATH", &self.fake_msb)
            .env("AGENT_VM_DEBUG_CONFIG", "1")
            .current_dir(project)
            .arg(verb);
        if set_home {
            cmd.env("HOME", self.home.path());
        } else {
            // `--root` is the only mode that reaches `mount::prepare` with no
            // `$HOME` at all (non-root fails earlier, resolving guest
            // identity).
            cmd.arg("--root");
        }
        for mount in mounts {
            cmd.arg("--mount").arg(mount);
        }
        cmd.args(["--image", BOGUS_IMAGE]);
        run_with_timeout(cmd, Duration::from_secs(15))
    }

    fn fork_store(&self) -> PathBuf {
        // `<state>/<project-hash>.mounts`, found by name rather than by
        // re-deriving the project hash.
        let entry = std::fs::read_dir(self.state.path().canonicalize().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap())
            .find(|entry| entry.file_name().to_string_lossy().ends_with(".mounts"))
            .expect("a seeded fork must have created the mount store");
        entry.path()
    }

    fn fork_data(&self) -> Option<PathBuf> {
        let forks = self.fork_store().join("forks");
        let entry = std::fs::read_dir(&forks).ok()?.next()?.ok()?;
        Some(entry.path().join("data"))
    }
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Extract the `SandboxConfig` JSON that `AGENT_VM_DEBUG_CONFIG=1` dumps to
/// stderr right after `builder.build()`.
fn debug_config_json(stderr: &str) -> serde_json::Value {
    const MARKER: &str = "[debug] sandbox config JSON: ";
    let idx = stderr
        .find(MARKER)
        .unwrap_or_else(|| panic!("no debug config JSON found in stderr:\n{stderr}"));
    let rest = &stderr[idx + MARKER.len()..];
    serde_json::Deserializer::from_str(rest)
        .into_iter::<serde_json::Value>()
        .next()
        .unwrap_or_else(|| panic!("no JSON value found after debug marker in stderr:\n{stderr}"))
        .unwrap_or_else(|e| panic!("debug config JSON failed to parse: {e}\nstderr:\n{stderr}"))
}

/// The `(host, guest, readonly)` triples of a dumped config's `Bind` mounts.
fn bind_mounts(config: &serde_json::Value) -> Vec<(String, String, bool)> {
    config["mounts"]
        .as_array()
        .expect("config.mounts must be an array")
        .iter()
        .filter(|m| m["type"] == "Bind")
        .map(|m| {
            (
                m["host"].as_str().expect("host").to_string(),
                m["guest"].as_str().expect("guest").to_string(),
                m["options"]["readonly"].as_bool().expect("readonly"),
            )
        })
        .collect()
}

/// A rejected plan must leave no session, fork, credential or builder state —
/// the discipline `mount_fork.rs` already pins.
fn assert_no_launch_side_effects(harness: &Harness, stderr: &str) {
    for notice in [
        "[debug] sandbox config JSON:",
        "==> agent-vm-",
        "GitHub repo scope",
        "Initialized fork",
        "Reusing fork",
        "==> Mounting",
    ] {
        assert!(
            !stderr.contains(notice),
            "a rejected plan must not emit {notice:?}: {stderr}"
        );
    }
    let entries = std::fs::read_dir(harness.state.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    assert!(
        entries.is_empty(),
        "a rejected plan must not create session, fork, credential, or builder state: {entries:?}"
    );
}

/// The launch verbs, read from `agent-vm --help` rather than hardcoded, so
/// this keeps holding when `pi` lands with #96.
fn launch_verbs(harness: &Harness) -> Vec<String> {
    let mut cmd = Command::new(agent_vm_bin());
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", harness.home.path())
        .env(
            "AGENT_VM_STATE_DIR",
            harness.state.path().canonicalize().unwrap(),
        )
        .env("MSB_PATH", &harness.fake_msb)
        .arg("--help");
    let out = run_with_timeout(cmd, Duration::from_secs(15));
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let commands = stdout
        .split("Commands:")
        .nth(1)
        .unwrap_or_else(|| panic!("no Commands section in --help:\n{stdout}"));
    let commands = commands.split("\nOptions:").next().unwrap_or(commands);
    let verbs: Vec<String> = commands
        .lines()
        .filter_map(|line| {
            // Continuation lines are indented under a long help string.
            if line.starts_with("  ") && !line.starts_with("   ") {
                Some(line.split_whitespace().next()?.to_string())
            } else {
                None
            }
        })
        .filter(|name| !BUILTIN_SUBCOMMANDS.contains(&name.as_str()))
        .collect();
    assert!(
        verbs.contains(&"shell".to_string()),
        "the verb list must be derived correctly, got {verbs:?}"
    );
    verbs
}

#[test]
fn shell_refuses_a_ro_mount_of_the_host_pi_home() {
    let h = Harness::new();
    let pi_home = h.seed_pi_home();
    let mount = format!("{}:ro", pi_home.display());

    let refused = h.run_shell(&[&mount]);
    assert!(!refused.status.success(), "{}", stderr_of(&refused));
    let stderr = stderr_of(&refused);
    assert!(
        stderr.contains(&pi_home.join("agent/auth.json").display().to_string()),
        "{stderr}"
    );
    assert!(stderr.contains(":fork"), "{stderr}");
    assert_no_launch_side_effects(&h, &stderr);
}

#[test]
fn every_launch_verb_refuses_the_same_mount() {
    let h = Harness::new();
    let pi_home = h.seed_pi_home();
    let mount = format!("{}:/pi:ro", pi_home.display());

    for verb in launch_verbs(&h) {
        let refused = h.run_verb(&verb, &[&mount], true, h.project.path());
        let stderr = stderr_of(&refused);
        assert!(!refused.status.success(), "{verb}: {stderr}");
        assert!(stderr.contains("would expose"), "{verb}: {stderr}");
        assert!(stderr.contains(":fork"), "{verb}: {stderr}");
        assert_no_launch_side_effects(&h, &stderr);
    }
}

#[test]
fn fork_of_the_host_pi_home_boots_with_credentials_omitted() {
    let h = Harness::new();
    let pi_home = h.seed_pi_home();
    let mount = format!("{}:fork", pi_home.display());

    let launched = h.run_shell(&[&mount]);
    let stderr = stderr_of(&launched);
    assert!(
        stderr.contains("Initialized fork"),
        "the fork must seed before the (expected) pull failure: {stderr}"
    );
    assert!(
        stderr.contains("Omitted host Pi credential file agent/auth.json"),
        "{stderr}"
    );
    assert!(
        stderr.contains("Omitted host Pi provider-configuration file agent/models.json"),
        "{stderr}"
    );
    assert!(
        stderr.contains("may not run in the Linux guest"),
        "{stderr}"
    );

    let data = h.fork_data().expect("a seeded fork must publish `data`");
    assert!(data.join("settings.json").is_file());
    assert!(data.join("extensions/x.js").is_file());
    assert!(!data.join("agent/auth.json").exists());
    assert!(!data.join("agent/models.json").exists());
    // The host copy is untouched: only the fork's copy omits the files.
    assert!(pi_home.join("agent/auth.json").is_file());

    let config = debug_config_json(&stderr);
    let binds = bind_mounts(&config);
    assert!(
        binds
            .iter()
            .any(|(host, _, _)| Path::new(host) == data.as_path()),
        "the guest must bind the committed fork data, got {binds:?}"
    );
    assert!(
        !binds.iter().any(|(host, _, _)| host.contains("auth.json")),
        "{binds:?}"
    );
}

/// `$HOME` unset does **not** make the home unknowable: `run.rs` falls back
/// to the account record (`getpwuid_r(geteuid()).pw_dir`), so the launch has a
/// home to compare a declared `--mount` against even when the environment does
/// not carry `$HOME`. The dumped config proves the launch got past
/// `mount::prepare` and `builder.build()` ran.
#[test]
fn unset_home_with_a_mount_uses_the_account_record() {
    let h = Harness::new();
    let source = h.home_path().join("notes");
    std::fs::create_dir(&source).unwrap();
    let mount = format!("{}:ro", source.display());

    let launched = h.run_verb(
        "shell",
        &[&mount],
        /* set_home */ false,
        h.project.path(),
    );
    let stderr = stderr_of(&launched);
    assert!(!stderr.contains("$HOME is not set"), "{stderr}");
    assert!(
        !stderr.contains("neither $HOME nor the account record"),
        "{stderr}"
    );
    assert!(stderr.contains("[debug] sandbox config JSON"), "{stderr}");
}

/// The other half of MF1: with `$HOME` unset the account record still supplies
/// the route set, so a bind of an ancestor of *that* home is refused (or
/// advised) rather than silently greeted with `==> Booting sandbox`.
///
/// `/` is an ancestor of every home, so this pins the fix without knowing the
/// machine's account record: it is exactly the case the old code failed open
/// on, because an empty route set matched nothing.
#[test]
fn unset_home_still_protects_an_ancestor_of_the_account_record_home() {
    let h = Harness::new();

    let out = h.run_verb(
        "shell",
        &["/:/host-root:ro"],
        /* set_home */ false,
        h.project.path(),
    );
    let stderr = stderr_of(&out);
    assert!(stderr.contains("would expose"), "{stderr}");
    assert!(!stderr.contains("$HOME is not set"), "{stderr}");
}

#[test]
fn mount_of_an_unrelated_home_subdir_still_works() {
    let h = Harness::new();
    let pi_home = h.seed_pi_home();
    let notes = h.home_path().join("notes");
    std::fs::create_dir(&notes).unwrap();
    std::fs::write(notes.join("note.md"), "note").unwrap();
    let mount = format!("{}:ro", notes.display());

    let launched = h.run_shell(&[&mount]);
    let stderr = stderr_of(&launched);
    let binds = bind_mounts(&debug_config_json(&stderr));
    let expected = notes.canonicalize().unwrap();
    assert!(
        binds
            .iter()
            .any(|(host, _, readonly)| Path::new(host) == expected.as_path() && *readonly),
        "an unrelated $HOME subdir must bind read-only, got {binds:?}"
    );
    // No Pi advisory: the mount is not inside the Pi home and exposes nothing.
    assert!(!stderr.contains("host Pi state"), "{stderr}");
    // The stronger boot-free substitute for the mid-session TOCTOU: an allowed
    // launch binds *nothing* under the Pi home, so nothing there can change
    // under the guest's feet.
    assert!(
        !binds
            .iter()
            .any(|(host, _, _)| Path::new(host).starts_with(&pi_home)),
        "an allowed launch must not bind anything under {}: {binds:?}",
        pi_home.display()
    );
}

#[test]
fn launching_from_the_home_directory_is_refused() {
    let h = Harness::new();
    let pi_home = h.seed_pi_home();

    // No `--mount` at all: the project bind is the canonicalized cwd, so being
    // *in* `$HOME` is the exposure route.
    let refused = h.run_shell_from(&[], &h.home_path());
    let stderr = stderr_of(&refused);
    assert!(!refused.status.success(), "{stderr}");
    assert!(stderr.contains("project directory"), "{stderr}");
    assert!(
        stderr.contains(&pi_home.join("agent/auth.json").display().to_string()),
        "{stderr}"
    );
    assert_no_launch_side_effects(&h, &stderr);
}
