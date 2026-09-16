//! Boot-free regression proving config is **not** read on any launch path
//! (#80's central non-goal).
//!
//! `mount_follow_links.rs` established the technique: drive `agent-vm
//! shell`/`claude` with a controlled `HOME`/`AGENT_VM_STATE_DIR`/cwd, a fake
//! version-only `MSB_PATH`, and `AGENT_VM_DEBUG_CONFIG=1`, against a bogus
//! loopback image. Execution runs all the way to `builder.build()` — which
//! dumps the real `SandboxConfig` JSON to stderr just before the (expected)
//! registry failure — so reaching that dump *is* proof that config parsing
//! did not run and did not change the sandbox.
//!
//! The same tool is launched three times against the same state root with the
//! project config absent, conflicting, and syntactically invalid. If any of
//! those changed the sandbox or the captured credentials, the serialized
//! configuration or the state-file snapshot would differ.

use std::{
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

/// Bogus-but-well-formed image ref: never resolves, so the run fails *after*
/// the debug JSON dump (its pull is what fails), which is exactly the stage
/// these tests need.
const BOGUS_IMAGE: &str = "localhost:1/does-not-exist:latest";
const MARKER: &str = "[debug] sandbox config JSON: ";

fn agent_vm_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-vm"))
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

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[derive(Clone, Copy, Debug)]
enum ConfigVariant {
    Absent,
    Conflict,
    Invalid,
}

struct Harness {
    _home: tempfile::TempDir,
    state: tempfile::TempDir,
    _project: tempfile::TempDir,
    home_root: PathBuf,
    project_root: PathBuf,
    fake_msb: PathBuf,
}

impl Harness {
    fn new() -> Self {
        let home = tempfile::tempdir_in("/tmp").unwrap();
        let state = tempfile::tempdir_in("/tmp").unwrap();
        let project = tempfile::tempdir_in("/tmp").unwrap();
        let home_root = home.path().canonicalize().unwrap();
        let project_root = project.path().canonicalize().unwrap();
        let fake_msb = write_fake_msb(home.path());
        // A usable Anthropic host credential so `claude` does not fail its
        // missing-login bail *before* the debug-config stage, which would
        // mask the config-isolation signal.
        let claude_cred = home_root.join(".claude/.credentials.json");
        std::fs::create_dir_all(claude_cred.parent().unwrap()).unwrap();
        std::fs::write(&claude_cred, br#"{"claudeAiOauth":{"accessToken":"fake"}}"#).unwrap();
        Self {
            _home: home,
            state,
            _project: project,
            home_root,
            project_root,
            fake_msb,
        }
    }

    fn user_config(&self) -> PathBuf {
        self.home_root.join(".config/agent-vm/config.toml")
    }

    fn project_config(&self) -> PathBuf {
        self.project_root.join(".agent-vm/config.toml")
    }

    fn base_command(&self) -> Command {
        let mut cmd = Command::new(agent_vm_bin());
        cmd.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", &self.home_root)
            .env(
                "AGENT_VM_STATE_DIR",
                self.state.path().canonicalize().unwrap(),
            )
            .env("MSB_PATH", &self.fake_msb)
            .env("AGENT_VM_DEBUG_CONFIG", "1")
            .current_dir(&self.project_root);
        cmd
    }

    fn apply(&self, variant: ConfigVariant) {
        let _ = std::fs::remove_file(self.user_config());
        let _ = std::fs::remove_file(self.project_config());
        match variant {
            ConfigVariant::Absent => {}
            ConfigVariant::Conflict => {
                write(
                    &self.user_config(),
                    "[[tools]]\nname = \"t\"\ncommand = \"a\"\n",
                );
                write(
                    &self.project_config(),
                    "[[tools]]\nname = \"t\"\ncommand = \"b\"\n",
                );
            }
            ConfigVariant::Invalid => write(&self.project_config(), "this is not = = toml\n"),
        }
    }

    fn launch(&self, tool: &str) -> Output {
        let mut cmd = self.base_command();
        cmd.arg(tool).args(["--image", BOGUS_IMAGE]);
        run_with_timeout(cmd, Duration::from_secs(20))
    }
}

fn write(path: &Path, contents: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

/// The `SandboxConfig` JSON dumped right after `builder.build()`.
fn debug_config_json(stderr: &str) -> serde_json::Value {
    let index = stderr
        .find(MARKER)
        .unwrap_or_else(|| panic!("no debug config JSON; stderr:\n{stderr}"));
    let rest = &stderr[index + MARKER.len()..];
    serde_json::Deserializer::from_str(rest)
        .into_iter::<serde_json::Value>()
        .next()
        .unwrap_or_else(|| panic!("no JSON after marker; stderr:\n{stderr}"))
        .unwrap_or_else(|error| panic!("debug JSON parse failed: {error}\nstderr:\n{stderr}"))
}

/// `... (state: /path/to/<hash>)` from the launch banner.
fn state_dir(stderr: &str) -> PathBuf {
    let marker = "(state: ";
    let start = stderr
        .find(marker)
        .unwrap_or_else(|| panic!("no state dir in banner; stderr:\n{stderr}"))
        + marker.len();
    let end = stderr[start..]
        .find(')')
        .unwrap_or_else(|| panic!("unterminated state dir; stderr:\n{stderr}"));
    PathBuf::from(&stderr[start..start + end])
}

/// Deterministic credential/config bytes plus every guest-HOME symlink
/// target. Sorted so comparison is order-independent.
fn snapshot(state: &Path) -> BTreeMap<String, String> {
    let mut entries = BTreeMap::new();
    let secrets = PathBuf::from(format!("{}.secrets", state.display()));
    let files = [
        ("secrets/anthropic", secrets.join("anthropic")),
        (
            "claude/.credentials.json",
            state.join("claude/.credentials.json"),
        ),
        ("codex/config.toml", state.join("codex/config.toml")),
        (
            "opencode-config/opencode.json",
            state.join("opencode-config/opencode.json"),
        ),
    ];
    for (label, path) in files {
        let value = std::fs::read(&path)
            .map(|bytes| format!("{bytes:?}"))
            .unwrap_or_else(|error| format!("absent:{}", error.kind()));
        entries.insert(label.to_string(), value);
    }
    collect_symlinks(&state.join("home"), &state.join("home"), &mut entries);
    entries
}

fn collect_symlinks(root: &Path, dir: &Path, out: &mut BTreeMap<String, String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let file_type = entry.file_type().unwrap();
        if file_type.is_symlink() {
            let target = std::fs::read_link(&path).unwrap();
            out.insert(
                format!("link:{relative}"),
                target.to_string_lossy().into_owned(),
            );
        } else if file_type.is_dir() {
            collect_symlinks(root, &path, out);
        }
    }
}

#[test]
fn config_variants_never_change_the_launch_or_captured_state() {
    for tool in ["shell", "claude"] {
        let harness = Harness::new();
        let mut baseline_config: Option<serde_json::Value> = None;
        let mut baseline_state: Option<BTreeMap<String, String>> = None;

        for variant in [
            ConfigVariant::Absent,
            ConfigVariant::Conflict,
            ConfigVariant::Invalid,
        ] {
            harness.apply(variant);
            let out = harness.launch(tool);
            let stderr = stderr_of(&out);

            // Reaching the debug dump proves config parsing did not run and
            // did not short-circuit the launch.
            let mut config = debug_config_json(&stderr);
            // Only the sandbox name carries a per-launch PID.
            config["name"] = serde_json::json!("normalized");
            if let Some(expected) = &baseline_config {
                assert_eq!(
                    &config, expected,
                    "sandbox config changed for {tool} under {variant:?}\nstderr:\n{stderr}"
                );
            } else {
                baseline_config = Some(config);
            }

            let files = snapshot(&state_dir(&stderr));
            if let Some(expected) = &baseline_state {
                assert_eq!(
                    &files, expected,
                    "captured state changed for {tool} under {variant:?}"
                );
            } else {
                baseline_state = Some(files);
            }

            assert!(
                !stderr.contains("invalid TOML"),
                "launch parsed config ({tool}, {variant:?})"
            );
        }
    }
}
