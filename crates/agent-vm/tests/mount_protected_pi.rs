//! Boot-free integration tests for the #90 protected-host-file contract
//! (ADR-0020): a host Pi credential file must be unreachable from the guest in
//! every mount mode.
//!
//! Modeled on `tests/mount_fork.rs` — same controlled
//! `$HOME`/`AGENT_VM_STATE_DIR`/cwd, fake patched `msb`, and
//! `AGENT_VM_DEBUG_CONFIG` `SandboxConfig` JSON dump. Launch now prepares OCI
//! selections before the builder, so the harness imports genuine host-valid
//! bytes through the public `image import` verb first. Hermetic and fast: no
//! DNS, no registry, no Hypervisor.framework. Everything here is a *rejection*
//! or a *pre-create build*, so no VM ever boots.

use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

mod support;

#[path = "support/image_archive.rs"]
mod image_archive;

/// Subcommands `build_command` registers that are not launch verbs
/// (`cli::BUILTIN_SUBCOMMANDS`, which integration tests cannot import).
const BUILTIN_SUBCOMMANDS: &[&str] = &[
    "image",
    "setup",
    "msb",
    "clipboard",
    "doctor",
    "secret",
    "_intercept-hook",
    // The direct runner (#398) is a fixed built-in name whose target is
    // user-supplied argv; `every_launch_verb_refuses_the_same_mount` runs each
    // *catalog* verb, and the direct route's own case is asserted separately.
    "run",
    "help",
];

fn agent_vm_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-vm"))
}

#[path = "support/fake_msb.rs"]
mod fake_msb;

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
    /// The imported fixture reference every launch selects.
    image: String,
    /// State entries the harness's own fixture import created.
    seeded_state: std::collections::BTreeSet<std::ffi::OsString>,
    fake_msb: PathBuf,
}

impl Harness {
    /// A harness whose launches select a genuine host-valid image imported
    /// through the public CLI, so preparation succeeds and `builder.build()` is
    /// reachable without a registry.
    fn new() -> Self {
        let h = Self::bare();
        let archive = h.home.path().join("fixture-boot.tar");
        image_archive::write(&archive, &image_archive::ArchiveSpec::default());
        let mut import = Command::new(agent_vm_bin());
        import
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", h.home.path())
            .env("AGENT_VM_STATE_DIR", h.state.path())
            .env("MSB_PATH", &h.fake_msb)
            .current_dir(h.project.path())
            .args([
                "image",
                "import",
                "--input",
                archive.to_str().unwrap(),
                "--tag",
                &h.image,
            ]);
        let out = run_with_timeout(import, Duration::from_secs(60));
        assert!(
            out.status.success(),
            "fixture import failed: {}",
            stderr_of(&out)
        );
        let mut h = h;
        h.seeded_state = state_entries(&h.state.path().canonicalize().unwrap());
        h
    }

    fn bare() -> Self {
        // The relay socket lives below the state directory, so keep that one
        // under `/tmp` for the Unix socket-path limit. `$HOME` stays on the
        // workspace filesystem, and the project helper fails fast if
        // `CARGO_TARGET_DIR` pushed the project under a guest tmpfs prefix
        // (where the guest would remap it to `/workspace`).
        let home = tempfile::tempdir_in(support::workspace_tmpdir()).unwrap();
        let state = tempfile::tempdir_in("/tmp").unwrap();
        let project = support::project_tempdir();
        let fake_msb = fake_msb::write(home.path());
        Self {
            home,
            state,
            project,
            image: "fixture:boot".to_string(),
            seeded_state: std::collections::BTreeSet::new(),
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

    /// `agent-vm [options…] run PROGRAM` (#398): the direct route, which must
    /// keep the same mount protections as a catalog verb.
    fn run_direct(&self, mounts: &[&str]) -> Output {
        let mut cmd = Command::new(agent_vm_bin());
        cmd.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env(
                "AGENT_VM_STATE_DIR",
                self.state.path().canonicalize().unwrap(),
            )
            .env("MSB_PATH", &self.fake_msb)
            .env("AGENT_VM_DEBUG_CONFIG", "1")
            .env("HOME", self.home.path())
            .current_dir(self.project.path());
        for mount in mounts {
            cmd.arg("--mount").arg(mount);
        }
        cmd.args(["--image", &self.image, "run", "probe"]);
        run_with_timeout(cmd, Duration::from_secs(15))
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
            .current_dir(project);
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
        cmd.args(["--image", &self.image]).arg(verb);
        run_with_timeout(cmd, Duration::from_secs(15))
    }

    /// Write `~/.config/agent-vm/config.toml` in the shape the verified-read
    /// policy expects: a 0600 file in a 0700 directory.
    fn write_user(&self, contents: &str) {
        use std::os::unix::fs::PermissionsExt;
        let path = self.home_path().join(".config/agent-vm/config.toml");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, contents).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(
            path.parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }

    /// [`Self::run_verb`] in root mode *with* `$HOME` set, which is the only way a
    /// user-declared verb can be reached under `--root` (the verb list comes from
    /// the user config, which is discovered through `$HOME`).
    fn run_verb_root(&self, verb: &str, mounts: &[&str], project: &Path) -> Output {
        let mut cmd = Command::new(agent_vm_bin());
        cmd.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", self.home.path())
            .env(
                "AGENT_VM_STATE_DIR",
                self.state.path().canonicalize().unwrap(),
            )
            .env("MSB_PATH", &self.fake_msb)
            .env("AGENT_VM_DEBUG_CONFIG", "1")
            .current_dir(project);
        cmd.arg("--root");
        for mount in mounts {
            cmd.arg("--mount").arg(mount);
        }
        cmd.args(["--image", &self.image]).arg(verb);
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

fn state_entries(state: &Path) -> std::collections::BTreeSet<std::ffi::OsString> {
    std::fs::read_dir(state)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect()
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
    let entries = state_entries(&harness.state.path().canonicalize().unwrap());
    assert_eq!(
        entries, harness.seeded_state,
        "a rejected plan must not create session, fork, credential, or builder state"
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

/// The direct route inherits the shared mount protections: the same protected
/// host path is refused before any state is created.
#[test]
fn the_direct_runner_refuses_the_same_mount() {
    let h = Harness::new();
    let pi_home = h.seed_pi_home();
    let mount = format!("{}:/pi:ro", pi_home.display());
    let refused = h.run_direct(&[&mount]);
    let stderr = stderr_of(&refused);
    assert!(!refused.status.success(), "{stderr}");
    assert!(stderr.contains("would expose"), "{stderr}");
    assert!(stderr.contains(":fork"), "{stderr}");
    assert_no_launch_side_effects(&h, &stderr);
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
    // Host-wide approval lives at `$HOME/.config/agent-vm`, so a launch with no
    // `$HOME` fails closed before the builder rather than proceeding unapproved.
    assert!(!launched.status.success(), "{stderr}");
    assert!(stderr.contains("image pin authority"), "{stderr}");
    assert!(!stderr.contains("[debug] sandbox config JSON"), "{stderr}");
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

/// #396 AC-guards: a `~/.pi:fork` declared by a **user tool** — own or inherited —
/// omits the protected Pi auth and models files exactly as a `--mount` fork does,
/// so tool lists cannot become a route around the Pi protection.
///
/// Boot-free: the committed copy is inspected on the host after preparation, which
/// is the whole deliverable — the guest would see the same bytes.
#[test]
fn tool_declared_pi_fork_omits_auth_and_models() {
    for inherited in [false, true] {
        let h = Harness::new();
        let pi_home = h.seed_pi_home();
        // A file under the Pi home that is not protected, so "omits everything"
        // cannot pass this row.
        std::fs::write(pi_home.join("innocuous.txt"), "kept").unwrap();
        if inherited {
            h.write_user(
                "[[tools]]\nname = \"t\"\ncommand = \"/bin/echo\"\ntools = [\"inner\"]\n\
                 mounts = []\n\
                 [[tools]]\nname = \"inner\"\ncommand = \"/bin/echo\"\nmounts = [\"~/.pi:fork\"]\n",
            );
        } else {
            h.write_user(
                "[[tools]]\nname = \"t\"\ncommand = \"/bin/echo\"\nmounts = [\"~/.pi:fork\"]\n",
            );
        }
        let launched = h.run_verb("t", &[], true, h.project.path());
        let stderr = stderr_of(&launched);
        assert!(
            stderr.contains("[debug] sandbox config JSON:"),
            "inherited={inherited}: the launch must reach builder wiring: {stderr}"
        );
        let data = h
            .fork_data()
            .unwrap_or_else(|| panic!("inherited={inherited}: the fork must be published"));
        // Protected files are absent from the committed copy.
        for protected in ["agent/auth.json", "agent/models.json"] {
            assert!(
                !data.join(protected).exists(),
                "inherited={inherited}: {protected} must be omitted from a tool-declared fork"
            );
        }
        // The rest of the Pi home is a real copy, so the exclusions are selective.
        assert_eq!(
            std::fs::read_to_string(data.join("innocuous.txt")).unwrap(),
            "kept",
            "inherited={inherited}: an unprotected file must be copied"
        );
        assert!(data.join("settings.json").exists(), "inherited={inherited}");
        // The source is untouched.
        assert_eq!(
            std::fs::read_to_string(pi_home.join("agent/auth.json")).unwrap(),
            "{\"token\":\"host\"}"
        );
    }
}

/// #396 AC-guards: a *live* bind of the Pi home is refused through a tool
/// declaration in both guest modes, naming the tool origin, before any launch
/// side effect.
#[test]
fn tool_declared_live_pi_home_is_refused_in_both_guest_modes() {
    for root in [false, true] {
        let h = Harness::new();
        let pi_home = h.seed_pi_home();
        h.write_user(
            "[[tools]]\nname = \"t\"\ncommand = \"/bin/echo\"\nmounts = [\"~/.pi:/pi-live:ro\"]\n",
        );
        let launched = if root {
            h.run_verb_root("t", &[], h.project.path())
        } else {
            h.run_verb("t", &[], true, h.project.path())
        };
        let stderr = stderr_of(&launched);
        assert!(
            !launched.status.success(),
            "root={root}: a live Pi bind must be refused: {stderr}"
        );
        assert!(
            stderr.contains("tools[0].mounts[0] in"),
            "root={root}: the refusal must name the tool field: {stderr}"
        );
        assert!(
            stderr.contains(&pi_home.join("agent/auth.json").display().to_string())
                || stderr.contains("host Pi state"),
            "root={root}: the refusal must name what it protects: {stderr}"
        );
        assert_no_launch_side_effects(&h, &stderr);
    }
}
