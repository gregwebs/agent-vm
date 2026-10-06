//! Boot-free end-to-end proof that the **tool catalog drives the CLI** (issue
//! #82).
//!
//! `mount_follow_links.rs` established the technique: drive the real binary
//! with a controlled `HOME`/`AGENT_VM_STATE_DIR`/cwd, a fake version-only
//! `MSB_PATH`, `AGENT_VM_DEBUG_CONFIG=1`, and a bogus loopback image.
//! Execution runs all the way to `builder.build()`, which dumps the real
//! `SandboxConfig` JSON to stderr, then a `[debug] guest command:` line, and
//! only then fails (expectedly) pulling the bogus image. Reaching those lines
//! is proof the launch was wired end to end without booting a VM.
//!
//! ## E1 goldens
//!
//! `tests/fixtures/config-launch/<tool>.golden` records, for each of the seven
//! default tools, the `SandboxConfig` JSON (normalized) and a snapshot of the
//! per-project state dir. They now record each verb's **declared provisioning
//! set** (#118): `codex` provisions `{openai}`, `claude` `{anthropic}`, and so
//! on, so the proxy secret set, the intercept rules and the written guest
//! placeholders differ per verb. `UPDATE_LAUNCH_GOLDENS=1` reproduces them from
//! any host (see [`assert_matches_golden`]).
//!
//! `intercept.hook` is now verb-dependent: it is present exactly when a verb
//! has a proxied route (`Plan::configure_network` only calls `.intercept()`
//! when the route list is non-empty), so `copilot` keeps the serde-default
//! intercept body.
//!
//! #119 moved `CODEX_HOME` off the every-launch generic env
//! (`credential_provider::GENERIC_GUEST_ENV`) onto the `codex` (and `shell`)
//! tool's own config `env`, so `opencode`/`claude`/`copilot` emit no
//! `CODEX_HOME` entry. That is an intentional divergence from the `bb299d1`
//! capture, **hand-edited** in exactly those three fixtures rather than
//! bulk-regenerated — it is not drift, and must not be "fixed" by re-running
//! `UPDATE_LAUNCH_GOLDENS=1` on a developer host.
//!
//! The project's temp root lives under `CARGO_TARGET_TMPDIR` (inside `target/`),
//! deliberately *off* the guest's tmpfs prefixes (`/tmp`, `/run`, …), so the
//! guest mirrors the project path on macOS and Linux alike — the shape every
//! real user gets. `support::project_tempdir` enforces that precondition,
//! failing fast rather than letting a tmpfs-prefixed `CARGO_TARGET_DIR` surface
//! here as a product-looking assertion failure. That is what lets the goldens
//! pin `runtime.workdir` and the project mount's `guest` at the real `$PROJECT`
//! value `main` produces, instead of collapsing two platform-dependent shapes
//! to one token.
//!
//! The comparison is deliberately **not** byte-for-byte on every field. The
//! remaining host-dependent values are normalized (or dropped) so the fixtures
//! are CI-portable across this macOS/arm64 host and the ubuntu x86_64 CI leg:
//!
//! - absolute temp paths, the per-launch PID in the sandbox name, and the
//!   built binary path are tokenized (`$PROJECT`, `$STATE_DIR`, `$AGENT_VM_BIN`,
//!   …);
//! - `mounts` are sorted by content — the builder emits them in a hash-ordered,
//!   run-dependent order — so the mount *set* and every mount's fields are
//!   pinned, but not the ordering;
//! - the non-root guest identity (`runtime.user`, `USER`/`LOGNAME`, the
//!   `/etc/passwd` append) is tokenized, and the `Mkdir` patches — a
//!   mechanical function of the project path's ancestors, which differ by
//!   platform — are dropped;
//! - the `/etc/group` append is dropped: it is emitted only when the *host*
//!   gid is ≥ 1000 (`user.rs`), so it is present on the Linux runner and absent
//!   on a macOS developer account. See [`drop_host_gid_group_append`].
//!
//! Everything else — every network rule, proxy secret, and the captured state
//! files under the project state dir — is pinned byte-for-byte. The state-dir
//! snapshot is the acceptance criterion's "files written under the project
//! state dir are identical to `main`"; `config::tests` and `run::tests` are
//! the unit half. If a residual platform delta ever surfaces in a mount option
//! or another field, narrow the comparison to the tool-dependent fields rather
//! than weakening it globally.

use std::{
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

mod support;

/// Bogus-but-well-formed image ref: never resolves, so the run fails *after*
/// the debug dumps (its pull is what fails), which is exactly the stage these
/// tests need.
const BOGUS_IMAGE: &str = "localhost:1/does-not-exist:latest";
const CONFIG_MARKER: &str = "[debug] sandbox config JSON: ";
const GUEST_CMD_MARKER: &str = "[debug] guest command: ";

/// The seven shipped default tools, in `default-tools.toml` order.
const DEFAULT_TOOLS: [&str; 7] = [
    "dsh", "pi", "codex", "opencode", "claude", "copilot", "shell",
];

/// The tool-independent guest `PATH` every default tool launches with. Pinned
/// both by the goldens and by [`assert_tool_dependent_content`].
const PATH_VALUE: &str = "/usr/local/bin:/usr/bin:/usr/sbin:/bin";

/// The resolved guest command line each default tool must produce with no user
/// args (`command` + `argv`). Transcribed by hand from `run::Agent`'s
/// `command()`/`default_args()` as of `bb299d1` — the pre-#82 binary has no
/// debug line for this, so it cannot be captured; see the module docs.
const LEGACY_GUEST_COMMANDS: [(&str, &str); 6] = [
    ("codex", "codex"),
    ("opencode", "opencode"),
    ("claude", "claude --dangerously-skip-permissions"),
    ("copilot", "copilot --allow-all-tools"),
    ("dsh", "dsh web"),
    ("shell", "bash -O histappend"),
];

fn agent_vm_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-vm"))
}

#[path = "support/fake_msb.rs"]
mod fake_msb;

fn write_fake_msb(dir: &Path) -> PathBuf {
    let path = dir.join("msb");
    // A credential-bearing launch makes the SDK probe `<msb> __launch-protocol`
    // and require `header_credentials: true` in the JSON reply (microsandbox
    // 0.7.x replaced the 0.6.x `__capabilities` + `header-credential-launch-v1`
    // line; see the vendored sdk/rust/lib/runtime/launch_contract.rs).
    // `protocols` must contain 2 for a restore-backed launch. Any other argv
    // must still answer with the version line, BYTE FOR BYTE as before, or
    // `msb_install`'s patched-build check would start refusing the fake and
    // every launch golden here would fail for the wrong reason.
    //
    // Every invocation is appended to a sibling log so a test can assert the
    // probe *actually happened* rather than inferring it from the absence of an
    // error (agent-vm #161 review, M4).
    fake_msb::write_executable(
        &path,
        &format!(
            "#!/bin/sh\n\
             echo \"$*\" >> \"$(dirname \"$0\")/msb-invocations.log\"\n\
             if [ \"$1\" = \"__launch-protocol\" ]; then\n\
             \x20 echo '{{\"protocols\":[1,2],\"required_restore_backing\":true,\"header_credentials\":true}}'\n\
             \x20 exit 0\n\
             fi\n\
             echo '{}'\nexit 0\n",
            fake_msb::VERSION_LINE
        ),
    );
    // 0.7.4's runtime resolver refuses an `msb` with no adjacent libkrunfw
    // ("has no matching libkrunfw"), so the fixture has to be a complete pair.
    // The name is platform-specific (`libkrunfw.5.dylib` on macOS,
    // `libkrunfw.so.<version>` elsewhere), hence the vendored helper rather
    // than a literal. Nothing reads the file's contents here -- the resolver
    // only checks that it exists.
    let library = dir.join(microsandbox_utils::libkrunfw_filename(std::env::consts::OS));
    std::fs::write(&library, b"fixture").unwrap();
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

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn write(path: &Path, contents: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

/// The decoy directory prepended to the host `PATH`: the exact search path the
/// launcher (and the wiring control) runs with.
fn decoys_path(decoys: &Path) -> String {
    let host = std::env::var("PATH").unwrap_or_default();
    format!("{}:{host}", decoys.display())
}

/// One isolated `$HOME`, state root, and project cwd, plus a fake `msb` and a
/// usable host credential for every provider a default tool selects, so each
/// tool reaches the debug dumps instead of its pre-boot "sign in on the host"
/// bail.
struct Harness {
    _home: tempfile::TempDir,
    _state: tempfile::TempDir,
    _project: tempfile::TempDir,
    home_root: PathBuf,
    project_root: PathBuf,
    state_root: PathBuf,
    fake_msb: PathBuf,
}

impl Harness {
    fn new() -> Self {
        let home = tempfile::tempdir_in("/tmp").unwrap();
        let state = tempfile::tempdir_in("/tmp").unwrap();
        // `support::project_tempdir` keeps the project off the guest's tmpfs
        // prefixes so `run::resolve_project_guest_path` mirrors it in the guest
        // on every platform — the shape every real user gets — instead of
        // falling back to `/workspace`, and fails fast if `CARGO_TARGET_DIR`
        // pushed it under one. `HOME` and `AGENT_VM_STATE_DIR` stay under
        // `/tmp`: a shorter state path keeps the sandbox's control socket inside
        // the `sun_path` limit (CONTRIBUTING.md).
        let project = support::project_tempdir();
        let home_root = home.path().canonicalize().unwrap();
        let project_root = project.path().canonicalize().unwrap();
        let state_root = state.path().canonicalize().unwrap();
        let fake_msb = write_fake_msb(home.path());
        // Fake-but-well-formed credentials for every provider. `claude` and
        // `copilot` hard-bail without a usable one; codex/opencode/shell do
        // not, but are given them anyway so every tool sees the same host.
        write(
            &home_root.join(".claude/.credentials.json"),
            r#"{"claudeAiOauth":{"accessToken":"fake"}}"#,
        );
        write(
            &home_root.join(".cache/claude-vm/copilot-token.json"),
            r#"{"access_token":"fake"}"#,
        );
        write(
            &home_root.join(".codex/auth.json"),
            r#"{"tokens":{"access_token":"fake","refresh_token":"fake","account_id":"00000000-0000-0000-0000-000000000000"}}"#,
        );
        write(
            &home_root.join(".local/share/opencode/auth.json"),
            r#"{"openai":{"access":"fake","refresh":"fake"}}"#,
        );
        Self {
            _home: home,
            _state: state,
            _project: project,
            home_root,
            project_root,
            state_root,
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
            .env("AGENT_VM_STATE_DIR", &self.state_root)
            .env("MSB_PATH", &self.fake_msb)
            .env("AGENT_VM_DEBUG_CONFIG", "1")
            // The project root lives in `target/tmp`, i.e. *inside this git
            // checkout*. Tell git's discovery to stop before it can ascend to
            // the repository: otherwise `run::detect_github_repos` would pick
            // up this checkout's remotes and put them in the GitHub allow-list,
            // making the goldens depend on the clone. A `/tmp` project (the
            // pre-#82 harness, and a real user's non-repo project) is not in
            // any repo, so this restores that shape.
            .env("GIT_CEILING_DIRECTORIES", env!("CARGO_TARGET_TMPDIR"))
            .current_dir(&self.project_root);
        cmd
    }

    fn write_user(&self, contents: &str) {
        write(&self.user_config(), contents);
    }

    fn write_project(&self, contents: &str) {
        write(&self.project_config(), contents);
    }

    /// Launch `tool` against the bogus image with the given extra argv.
    /// `--image` is passed *before* `extra` so a trailing `-- <agent args>`
    /// (absorbed by the tool's `trailing_var_arg`) cannot swallow it.
    fn launch(&self, tool: &str, extra: &[&str]) -> Output {
        self.launch_with_env(tool, extra, &[])
    }

    /// [`Self::launch`] with extra host environment variables set for the
    /// child (the base command starts from `env_clear`).
    fn launch_with_env(&self, tool: &str, extra: &[&str], envs: &[(&str, &str)]) -> Output {
        // `--image` is passed *before* `extra` so a trailing `-- <agent args>`
        // (absorbed by the tool's `trailing_var_arg`) cannot swallow it.
        let mut argv: Vec<&str> = vec!["--image", BOGUS_IMAGE];
        argv.extend_from_slice(extra);
        self.launch_argv(tool, &argv, envs)
    }

    /// Run `tool` with exactly `argv` (after the verb) and `envs` set on top of
    /// the cleared environment. [`Self::launch_with_env`] is the common case;
    /// this is for a test that must control image selection itself (e.g. pass
    /// `--image` or nothing at all, so config/env/default precedence is
    /// observable).
    fn launch_argv(&self, tool: &str, argv: &[&str], envs: &[(&str, &str)]) -> Output {
        let mut cmd = self.base_command();
        for (key, value) in envs {
            cmd.env(key, value);
        }
        cmd.arg(tool).args(argv);
        run_with_timeout(cmd, Duration::from_secs(20))
    }

    /// Every argv the fake `msb` was invoked with, in order. Empty when it was
    /// never invoked.
    fn msb_log(&self) -> String {
        std::fs::read_to_string(self.fake_msb.with_file_name("msb-invocations.log"))
            .unwrap_or_default()
    }

    /// Whether the fake `msb` was probed for the header-credential capability.
    fn saw_capability_probe(&self) -> bool {
        self.msb_log()
            .lines()
            .any(|line| line.starts_with("__launch-protocol"))
    }

    /// Launch a default tool with no extra args.
    fn launch_default(&self, tool: &str) -> Output {
        self.launch(tool, &[])
    }

    /// The location-dependent host paths to tokenize, longest first
    /// (`state_dir` is `state_root/<hash>`, so it must be replaced before its
    /// `state_root` prefix).
    fn location_tokens(&self, state_dir: &Path) -> [(String, &'static str); 5] {
        [
            (state_dir.to_string_lossy().into_owned(), "$STATE_DIR"),
            (
                self.state_root.to_string_lossy().into_owned(),
                "$STATE_ROOT",
            ),
            (self.home_root.to_string_lossy().into_owned(), "$HOME"),
            (self.project_root.to_string_lossy().into_owned(), "$PROJECT"),
            (
                agent_vm_bin().to_string_lossy().into_owned(),
                "$AGENT_VM_BIN",
            ),
        ]
    }

    /// Replace every location-dependent token so a golden is reproducible.
    fn normalize(&self, state_dir: &Path, text: &str) -> String {
        let mut out = text.to_string();
        for (from, to) in self.location_tokens(state_dir) {
            out = out.replace(&from, to);
        }
        out
    }

    fn normalize_json(&self, state_dir: &Path, value: &serde_json::Value) -> String {
        // Normalize the paths *before* sorting, or the sort key would itself be
        // a raw temp path and the ordering would stay run-dependent below.
        let text = self.normalize(state_dir, &serde_json::to_string_pretty(value).unwrap());
        let mut value: serde_json::Value = serde_json::from_str(&text).unwrap();
        normalize_host_identity(&mut value);
        drop_host_gid_group_append(&mut value);
        // Drop the project-path `Mkdir` patches: they are a mechanical
        // function of the project path's ancestors, which differ by platform
        // (macOS canonicalizes `/tmp` -> `/private/tmp`, Linux does not, and
        // the checkout path itself differs). **Root-mode dotfile mkdirs
        // (`/root/...`) are kept** — #83's `persist` links need `/root/.cache`
        // and friends, and their presence is the assertion, so filtering them
        // out would weaken the check rather than stabilize it. Non-root emits
        // no `/root/...` mkdir, so the goldens do not move.
        if let Some(patches) = value
            .get_mut("patches")
            .and_then(|patches| patches.as_array_mut())
        {
            patches.retain(|patch| match patch.get("Mkdir") {
                None => true,
                Some(mkdir) => mkdir
                    .get("path")
                    .and_then(|path| path.as_str())
                    .is_some_and(|path| path.starts_with("/root/")),
            });
        }
        // The microsandbox builder stores mounts in a hash-ordered collection,
        // so `mounts` come out in a run-dependent order (it varies even for
        // the same tool across runs, because the hash keys are the temp paths).
        // Sort by content so the fixture pins the mount *set* and every field,
        // but not the runtime's unstable ordering.
        if let Some(mounts) = value.get_mut("mounts").and_then(|m| m.as_array_mut()) {
            mounts.sort_by_key(|mount| serde_json::to_string(mount).unwrap());
        }
        serde_json::to_string_pretty(&value).unwrap()
    }

    /// Run a fixed built-in verb (`doctor`, `pull`, `setup`, top-level `help`)
    /// with `args` and `envs` on the base command.
    fn builtin(&self, args: &[&str], envs: &[(&str, &str)]) -> Output {
        let mut cmd = self.base_command();
        for (key, value) in envs {
            cmd.env(key, value);
        }
        cmd.args(args);
        run_with_timeout(cmd, Duration::from_secs(20))
    }

    /// A fresh directory holding executable `docker` and `buildx` decoys that
    /// append `basename argv` to `calls.log` and exit 97. The launcher must
    /// never invoke either (issue #259: no launch builds an image).
    ///
    /// Wiring control: a decoy is evidence only if a child on the **exact PATH**
    /// used for the launch reaches it, it logs the exact argv, and it exits 97.
    /// Both are invoked once through that PATH and the log is checked, then
    /// truncated, so a decoy that is unreachable or silently succeeds cannot
    /// make every zero-builder observation vacuous (Spec S2).
    fn builder_decoys(&self) -> PathBuf {
        let dir = self.home_root.join("builder-decoys");
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("calls.log");
        std::fs::write(&log, "").unwrap();
        for name in ["docker", "buildx"] {
            let script = format!(
                "#!/bin/sh\nprintf '%s %s\\n' \"$(basename \"$0\")\" \"$*\" >> '{}'\nexit 97\n",
                log.display()
            );
            let path = dir.join(name);
            fake_msb::write_executable(&path, &script);
        }
        for name in ["docker", "buildx"] {
            let output = std::process::Command::new(name)
                .arg("wiring-probe")
                .env("PATH", decoys_path(&dir))
                .output()
                .unwrap_or_else(|error| panic!("run the {name} decoy: {error}"));
            assert_eq!(
                output.status.code(),
                Some(97),
                "the {name} decoy must exit 97, not {}",
                output.status
            );
        }
        assert_eq!(
            std::fs::read_to_string(&log).unwrap(),
            "docker wiring-probe\nbuildx wiring-probe\n",
            "the decoys must log the exact argv through the launch PATH"
        );
        std::fs::write(&log, "").unwrap();
        dir
    }

    /// The decoys' invocation log. A missing/unreadable log is a failure, never
    /// a vacuous zero.
    fn decoy_log(&self, decoys: &Path) -> String {
        std::fs::read_to_string(decoys.join("calls.log"))
            .unwrap_or_else(|error| panic!("read the decoy log: {error}"))
    }

    /// `base_command` with the decoy directory prepended to `PATH`.
    fn command_with_decoys(&self, decoys: &Path) -> Command {
        let mut cmd = self.base_command();
        cmd.env("PATH", decoys_path(decoys));
        cmd
    }

    /// Run a tool verb (with `argv`) or a built-in on a prepared command.
    fn run_on(cmd: Command, args: &[&str]) -> Output {
        let mut cmd = cmd;
        cmd.args(args);
        run_with_timeout(cmd, Duration::from_secs(20))
    }
}

/// Erase the one genuinely host-dependent part of the dump: the non-root
/// guest's uid/gid/username, which is derived from the *host* account and so
/// differs between a developer Mac (`claude`, 502:20) and a CI runner
/// (`runner`, 1001:…). Everything else is fixed by the image or already
/// path-normalized. The identity mapping itself is covered by `user.rs` tests;
/// this fixture is about which tool selected which mounts/providers.
///
/// Gap this normalization accepts: the tokenization erases the *value* of the
/// uid/gid and username, so a non-root identity change (e.g. 502:20 → 501:20)
/// would not trip E1. The root-vs-non-root *mode* is still caught — root mode
/// leaves a literal `/root` in the `HOME` env / home mount (not the tokenized
/// host path) and a different `/etc/passwd` patch shape. `user.rs` owns the
/// exact identity.
fn normalize_host_identity(value: &mut serde_json::Value) {
    if let Some(user) = value
        .get_mut("runtime")
        .and_then(|runtime| runtime.get_mut("user"))
        && user.is_string()
    {
        *user = serde_json::json!("$GUEST_UID:$GUEST_GID");
    }
    if let Some(env) = value.get_mut("env").and_then(|env| env.as_array_mut()) {
        for entry in env {
            if matches!(
                entry.get("key").and_then(|key| key.as_str()),
                Some("USER" | "LOGNAME")
            ) {
                entry["value"] = serde_json::json!("$GUEST_USER");
            }
        }
    }
    if let Some(patches) = value
        .get_mut("patches")
        .and_then(|patches| patches.as_array_mut())
    {
        for patch in patches {
            let Some(append) = patch.get_mut("Append") else {
                continue;
            };
            if append.get("path").and_then(|path| path.as_str()) == Some("/etc/passwd") {
                append["content"] =
                    serde_json::json!("$GUEST_USER:x:$GUEST_UID:$GUEST_GID::$HOME:/bin/bash\n");
            }
        }
    }
}

/// Drop the host-gid-dependent `/etc/group` append.
///
/// `user::group_append_line` emits it only when the guest gid is ≥ 1000, and
/// that gid comes straight from the *host* account (`libc::getgid()`). So its
/// very presence differs between a macOS developer (staff = 20, none) and a
/// Linux CI runner (gid ≥ 1000, one), and it is not decided by the launched
/// tool. The gid-range rule and the append's exact content are pinned by
/// `user::group_append_line_skips_system_reserved_range` (user.rs).
///
/// Narrow by construction: it removes only `/etc/group` appends. Every other
/// field is left untouched — see
/// `host_environment_normalization_drops_only_the_host_gid_group_append`.
fn drop_host_gid_group_append(value: &mut serde_json::Value) {
    if let Some(patches) = value.get_mut("patches").and_then(|p| p.as_array_mut()) {
        patches.retain(|patch| {
            patch
                .get("Append")
                .and_then(|append| append.get("path"))
                .and_then(|path| path.as_str())
                != Some("/etc/group")
        });
    }
}

/// The `SandboxConfig` JSON dumped right after `builder.build()`.
fn debug_config_json(stderr: &str) -> serde_json::Value {
    let index = stderr
        .find(CONFIG_MARKER)
        .unwrap_or_else(|| panic!("no debug config JSON; stderr:\n{stderr}"));
    let rest = &stderr[index + CONFIG_MARKER.len()..];
    serde_json::Deserializer::from_str(rest)
        .into_iter::<serde_json::Value>()
        .next()
        .unwrap_or_else(|| panic!("no JSON after marker; stderr:\n{stderr}"))
        .unwrap_or_else(|error| panic!("debug JSON parse failed: {error}\nstderr:\n{stderr}"))
}

/// The `[debug] guest command:` line, or a panic if the launch never reached
/// it (which is itself the failure worth reporting).
fn debug_guest_command(stderr: &str) -> String {
    let index = stderr
        .find(GUEST_CMD_MARKER)
        .unwrap_or_else(|| panic!("no debug guest command; stderr:\n{stderr}"));
    let line = &stderr[index + GUEST_CMD_MARKER.len()..];
    line.lines().next().unwrap_or_default().to_string()
}

/// The dumped `SandboxConfig`'s `env` array as `(key, value)` pairs, in
/// emission order. Shared by the #119 ordering tests and
/// [`assert_tool_dependent_content`]; callers that care about *which* of two
/// same-key entries is later use `rposition` on the returned `Vec`.
fn env_pairs(config: &serde_json::Value) -> Vec<(&str, &str)> {
    config["env"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            (
                entry["key"].as_str().unwrap(),
                entry["value"].as_str().unwrap(),
            )
        })
        .collect()
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
        ("secrets/openai", secrets.join("openai")),
        ("secrets/copilot", secrets.join("copilot")),
        (
            "claude/.credentials.json",
            state.join("claude/.credentials.json"),
        ),
        ("codex/auth.json", state.join("codex/auth.json")),
        ("codex/config.toml", state.join("codex/config.toml")),
        ("copilot/config.json", state.join("copilot/config.json")),
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

/// The full normalized observation for one launch: the `SandboxConfig` JSON
/// with the sandbox name elided (it carries the per-launch PID) and the
/// host-state snapshot.
fn observation(harness: &Harness, out: &Output) -> String {
    let stderr = stderr_of(out);
    let state = state_dir(&stderr);
    let mut config = debug_config_json(&stderr);
    config["name"] = serde_json::json!("agent-vm-normalized");
    let mut lines = vec![harness.normalize_json(&state, &config)];
    lines.push("--- state ---".to_string());
    for (key, value) in snapshot(&state) {
        lines.push(format!("{key}\t{}", harness.normalize(&state, &value)));
    }
    lines.join("\n")
}

/// Just the normalized `SandboxConfig` (the JSON half of [`observation`]), as a
/// value, so a test can assert the tool-dependent subset directly.
fn normalized_config(harness: &Harness, out: &Output) -> serde_json::Value {
    let stderr = stderr_of(out);
    let state = state_dir(&stderr);
    let mut config = debug_config_json(&stderr);
    config["name"] = serde_json::json!("agent-vm-normalized");
    serde_json::from_str(&harness.normalize_json(&state, &config)).unwrap()
}

/// Assert the tool-dependent content the goldens pin *directly*, so a future
/// widening of the normalizer cannot quietly stop pinning it. Every field here
/// is decided by the launched tool (or is a constant of the launch contract),
/// never by the host environment.
fn assert_tool_dependent_content(tool: &str, config: &serde_json::Value) {
    // The mount *set* is fixed; only its runtime order is run-dependent.
    let mounts: std::collections::BTreeSet<(&str, &str)> = config["mounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|mount| {
            (
                mount["host"].as_str().unwrap(),
                mount["guest"].as_str().unwrap(),
            )
        })
        .collect();
    let expected_mounts: std::collections::BTreeSet<(&str, &str)> = [
        ("$PROJECT", "$PROJECT"),
        ("$STATE_DIR", "/agent-vm-state"),
        ("$STATE_DIR/home", "$HOME"),
    ]
    .into_iter()
    .collect();
    assert_eq!(mounts, expected_mounts, "mount set changed for {tool}");

    let env = env_pairs(config);
    let env_of = |key: &str| env.iter().find(|(k, _)| *k == key).map(|(_, v)| *v);
    // #258: the launcher no longer publishes `PATH` into the sandbox config. The
    // acquired image's OCI `PATH` is preserved, and the effective value is read
    // back from the created sandbox and applied as the per-exec override — the
    // boot-free config dump stops before acquisition, so it carries no `PATH`.
    assert_eq!(
        env_of("PATH"),
        None,
        "PATH must not be published by config for {tool}"
    );
    let expects_codex_home = matches!(tool, "codex" | "shell");
    assert_eq!(
        env_of("CODEX_HOME"),
        expects_codex_home.then_some("/agent-vm-state/codex"),
        "CODEX_HOME must be emitted only for the tools that declare it ({tool})"
    );

    // The credential secret set follows the verb's provisioning set. `dsh`
    // provisions nothing, so the whole `secrets` object is absent for it; every
    // other verb provisions at least one provider and must carry
    // it. Assert the presence explicitly rather than defaulting the array for
    // every verb (a structurally missing object would otherwise pass for an
    // empty-expectation verb such as `copilot`).
    if matches!(tool, "dsh") {
        assert!(
            config["network"].get("secrets").is_none(),
            "{tool} provisions nothing, so it must not carry a `secrets` object"
        );
    } else {
        assert!(
            config["network"]["secrets"]["secrets"].is_array(),
            "{tool} provisions at least one provider and must carry a `secrets` object"
        );
    }
    let secrets = config["network"]["secrets"]["secrets"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let env_vars: Vec<&str> = secrets
        .iter()
        .map(|secret| secret["env_var"].as_str().unwrap())
        .collect();
    let expected_env_vars: &[&str] = match tool {
        "dsh" => &[],
        "codex" => &["MSB_AGENT_VM_OPENAI_UNUSED"],
        "opencode" => &[
            "MSB_AGENT_VM_OPENAI_UNUSED",
            "MSB_AGENT_VM_OPENCODE_OPENAI_UNUSED",
        ],
        "pi" | "claude" => &["MSB_AGENT_VM_ANTHROPIC_UNUSED"],
        "copilot" => &["MSB_AGENT_VM_COPILOT_UNUSED"],
        "shell" => &[
            "MSB_AGENT_VM_ANTHROPIC_UNUSED",
            "MSB_AGENT_VM_OPENAI_UNUSED",
            "MSB_AGENT_VM_OPENCODE_OPENAI_UNUSED",
            "MSB_AGENT_VM_COPILOT_UNUSED",
        ],
        other => panic!("unknown default tool {other}"),
    };
    assert_eq!(env_vars, expected_env_vars, "secret set changed for {tool}");
    for secret in &secrets {
        assert!(
            !secret["placeholder"].as_str().unwrap().is_empty(),
            "{tool}: empty secret placeholder"
        );
        assert!(
            !secret["allowed_hosts"].as_array().unwrap().is_empty(),
            "{tool}: empty secret allowlist"
        );
        assert!(
            secret["source"]["path"]
                .as_str()
                .unwrap()
                .starts_with("$STATE_DIR.secrets/"),
            "{tool}: secret source path is not tokenized"
        );
    }

    // `COPILOT_GITHUB_TOKEN` follows the provisioning set *and* a successful
    // capture: the harness seeds the device-flow cache, so `copilot` and
    // `shell` (which provisions Copilot) get it, and no other verb does.
    let expects_copilot_token = matches!(tool, "copilot" | "shell");
    assert_eq!(
        env_of("COPILOT_GITHUB_TOKEN"),
        expects_copilot_token.then_some("msb-copilot-placeholder-v2"),
        "COPILOT_GITHUB_TOKEN must follow the provisioning set and a successful capture ({tool})"
    );

    // The intercept hook is now verb-dependent, present **exactly when** a verb
    // has a proxied route: `Plan::configure_network` only calls `.intercept()`
    // when the route list is non-empty, so `copilot` (no `oauth_token_route`,
    // no GitHub egress) keeps the serde-default body. Losing the hook on a
    // no-route launch is acceptable — the hook only fires on a matched route
    // (`InterceptConfig`'s docs), and the `--allowed-repo` push restriction
    // rides the GitHub-egress routes, which are unaffected.
    // `dsh` has no proxied route, so the whole `intercept` object is
    // absent for it; every other verb keeps it (copilot keeps the
    // serde-default body).
    // Assert the object's presence explicitly rather than defaulting for every
    // verb, so a structurally missing object cannot pass.
    if matches!(tool, "dsh") {
        assert!(
            config["network"].get("intercept").is_none(),
            "{tool} has no proxied route, so it must not carry an `intercept` object"
        );
    } else {
        assert!(
            config["network"]["intercept"].is_object(),
            "{tool} must carry the `intercept` object"
        );
    }
    let rules = config["network"]["intercept"]["rules"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let hook = &config["network"]["intercept"]["hook"];
    if rules.is_empty() {
        assert!(hook.is_null(), "hook present with no routes ({tool})");
    } else {
        assert_eq!(
            hook,
            &serde_json::json!([
                "$AGENT_VM_BIN",
                "_intercept-hook",
                "--state-dir",
                "$STATE_DIR"
            ]),
            "intercept hook argv changed for {tool}"
        );
    }

    // The leak this ticket closes: the intercept rule set per verb.
    let actual_rules: Vec<(&str, &str)> = rules
        .iter()
        .map(|rule| {
            (
                rule["host"].as_str().unwrap(),
                rule["path_prefix"].as_str().unwrap(),
            )
        })
        .collect();
    let expected_rules: &[(&str, &str)] = match tool {
        "dsh" => &[],
        "codex" | "opencode" => &[("auth.openai.com", "/oauth/token")],
        "pi" | "claude" => &[("platform.claude.com", "/v1/oauth/token")],
        "copilot" => &[],
        "shell" => &[
            ("platform.claude.com", "/v1/oauth/token"),
            ("auth.openai.com", "/oauth/token"),
        ],
        other => panic!("unknown default tool {other}"),
    };
    assert_eq!(
        actual_rules, expected_rules,
        "intercept rules changed for {tool}"
    );
    if tool == "copilot" {
        assert_eq!(
            config["network"]["intercept"]["max_request_bytes"],
            serde_json::json!(65536),
            "copilot's intercept object must degrade to the serde default body"
        );
    }
}

// -- #161: credentials.yaml -------------------------------------------------

/// Write a `~/.config/agent-vm/credentials.yaml` with 0600 mode (the loader
/// warns above 0644 and refuses group/other *write*).
fn write_credentials(home_root: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    let path = home_root.join(".config/agent-vm/credentials.yaml");
    write(&path, body);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

const ONE_YAML_TOOL: &str =
    "[[tools]]\nname = \"t\"\ncommand = \"t\"\ncredentials = [\"my-service\"]\n";

#[test]
fn requested_name_without_an_authorization_fails_the_launch() {
    let harness = Harness::new();
    harness.write_user(ONE_YAML_TOOL);
    let out = harness.launch("t", &[]);
    assert!(!out.status.success(), "{}", stdout_of(&out));
    let stderr = stderr_of(&out);
    assert!(stderr.contains("my-service"), "{stderr}");
    assert!(stderr.contains("credentials.yaml"), "{stderr}");
    assert!(stderr.contains("built-in credential provider"), "{stderr}");
}

#[test]
fn a_launch_that_requests_no_credential_never_reads_the_authorization_file() {
    // The file is read only when the launch's credential closure requests
    // something, so a tool that requests none is unaffected by a broken one.
    // `shell` is deliberately NOT that tool: its default `tools = ["*"]` pulls
    // in every built-in provider, so it does request credentials.
    let harness = Harness::new();
    harness.write_user("[[tools]]\nname = \"t\"\ncommand = \"t\"\ntools = []\ncredentials = []\n");
    write_credentials(
        &harness.home_root,
        "credentials: [this is not a list of entries\n",
    );
    let out = harness.launch("t", &[]);
    let rendered = format!("{}{}", stderr_of(&out), stdout_of(&out));
    assert!(
        !rendered.contains("credentials.yaml"),
        "the authorization file was read for a launch that requests nothing: {rendered}"
    );
    // Positive progress marker (agent-vm #161 review, N4/M4): silence about the
    // file proves nothing unless the launch actually reached the phase-1
    // resolution that would have read it (`resolve_credentials`). That runs
    // before the debug `SandboxConfig` dump, so reaching the dump means a
    // broken file *would* have been reported here. A launch that died earlier
    // for an unrelated reason (a bad tool config, a pre-resolution failure)
    // would otherwise also satisfy the absence assertion.
    assert!(
        rendered.contains(CONFIG_MARKER),
        "the launch never reached the credential-resolution stage, so its silence \
         about credentials.yaml proves nothing: {rendered}"
    );
}

#[test]
fn malformed_credentials_yaml_fails_the_launch_with_a_redacted_message() {
    let harness = Harness::new();
    harness.write_user(ONE_YAML_TOOL);
    let canary = "sk-CANARY-6f2a1b3c4d5e6071829304a5b6c7d8e9";
    write_credentials(
        &harness.home_root,
        &format!(
            "credentials:\n  - service: my-service\n    apiKey:\n      name: MY_SERVICE_KEY\n      inject:\n        - domain: \"{canary}/x\"\n          header: x-api-key\n          format: \"%s\"\n"
        ),
    );
    let out = harness.launch("t", &[]);
    assert!(!out.status.success());
    let rendered = format!("{}{}", stderr_of(&out), stdout_of(&out));
    assert!(rendered.contains("credentials.yaml"), "{rendered}");
    // A positive assertion, not "my-service or domain": the specific rule the
    // canary tripped must be named, so ignoring the file entirely cannot
    // satisfy this test (agent-vm #161 review, M4).
    assert!(
        rendered.contains("credentials[0].apiKey.inject[0].domain")
            && rendered.contains("must not contain a path"),
        "{rendered}"
    );
    assert!(
        !rendered.contains(canary),
        "the launch echoed file content: {rendered}"
    );
}

#[test]
fn a_credential_bearing_launch_runs_the_capability_probe() {
    // A *genuinely* credential-bearing create (a durable `header_credentials`
    // entry) must make the SDK run `<msb> __launch-protocol`. The subprocess has no
    // fake OS keychain, so the credential is made ready through the debug-only
    // `AGENT_VM_TEST_CREDENTIAL` seam. Two independent positive controls: the
    // fake msb logged the probe, and the launch's outcome is the bogus-image
    // failure rather than the capability refusal. Replacing the fake's
    // capability answer with anything invalid flips the outcome and fails this
    // test (agent-vm #161 review, M4).
    let harness = Harness::new();
    harness.write_user(ONE_YAML_TOOL);
    write_credentials(
        &harness.home_root,
        "credentials:\n  - service: my-service\n    apiKey:\n      name: MY_SERVICE_KEY\n      sentinelEnv: true\n      inject:\n        - domain: api.my-service.example\n          header: x-api-key\n          format: \"%s\"\n",
    );
    let out = harness.launch_with_env(
        "t",
        &[],
        &[("AGENT_VM_TEST_CREDENTIAL", "my-service=sk-test-probe-value")],
    );
    let rendered = format!("{}{}", stderr_of(&out), stdout_of(&out));
    assert!(
        harness.saw_capability_probe(),
        "a credential-bearing create never probed the runtime: {rendered}\nmsb log:\n{}",
        harness.msb_log()
    );
    assert!(
        !rendered.contains("does not support origin-scoped header credentials"),
        "the fake msb failed the capability probe: {rendered}"
    );
}

#[test]
fn an_owned_credential_name_is_never_forwarded_from_the_host() {
    // AC2: an authorized credential owns its guest variable, so the host's real
    // `OPENAI_API_KEY` must not be forwarded into the guest - and the
    // credential-owned sentinel must be what the guest sees. This pins the
    // `run::launch` emission wiring, not only the ownership decision: if the
    // raw-forwarding suppression or the sentinel publication were removed, the
    // host canary would appear in the dumped environment (agent-vm #161 M1/M4).
    let harness = Harness::new();
    harness.write_user(ONE_YAML_TOOL);
    write_credentials(
        &harness.home_root,
        "credentials:\n  - service: my-service\n    apiKey:\n      name: OPENAI_API_KEY\n      sentinelEnv: true\n      inject: [{domain: api.my-service.example, header: x-api-key, format: \"%s\"}]\n",
    );
    let canary = "sk-host-real-canary-3f1a2b4c5d6e7f8091a2b3c4d5e6f708";
    let out = harness.launch_with_env(
        "t",
        &[],
        &[
            ("AGENT_VM_TEST_CREDENTIAL", "my-service=sk-test-owned-value"),
            ("OPENAI_API_KEY", canary),
        ],
    );
    let stderr = stderr_of(&out);
    let config = debug_config_json(&stderr);
    let env = env_pairs(&config);
    assert!(
        env.iter()
            .any(|(key, value)| *key == "OPENAI_API_KEY" && *value == "proxy-managed"),
        "the sentinel was not published last: {env:?}"
    );
    assert!(
        !env.iter().any(|(_, value)| *value == canary),
        "the host's real key was forwarded: {env:?}"
    );
    assert!(
        !stderr.contains(canary),
        "the value leaked to stderr: {stderr}"
    );
}

#[test]
fn a_sentinel_false_credential_fails_closed_when_image_metadata_is_unreadable() {
    // Policy: when the boot image's own environment cannot be read, an
    // authorization that must leave its variable *unset* is refused with a
    // recovery instruction rather than warned about and continued - logging is
    // not handling an error (CODING_STANDARDS, agent-vm #161 M1).
    let harness = Harness::new();
    harness.write_user(ONE_YAML_TOOL);
    write_credentials(
        &harness.home_root,
        "credentials:\n  - service: my-service\n    apiKey:\n      name: MY_SERVICE_KEY\n      inject:\n        - domain: api.my-service.example\n          header: x-api-key\n          format: \"%s\"\n",
    );
    let out = harness.launch("t", &[]);
    assert!(!out.status.success());
    let rendered = format!("{}{}", stderr_of(&out), stdout_of(&out));
    // Assert the command it prints is *runnable*, not a substring of prose:
    // the earlier assertion (`"Pull or inspect the image"`) passed while the
    // printed command (`agent-vm pull {image}`) failed with "unexpected
    // argument", because `pull` takes `--image REF` (agent-vm #161 review,
    // N1). The exact ref must appear so the instruction is pasteable.
    assert!(
        rendered.contains(&format!("agent-vm pull --image {BOGUS_IMAGE}")),
        "the launch did not offer a runnable pull command: {rendered}"
    );
}

// -- #162: precedence and the availability override --------------------------

/// A same-named authorization for the built-in `anthropic` provider: the
/// `credentials.yaml` entry #162 makes precedence-setting.
const YAML_ANTHROPIC: &str = "\
credentials:
  - service: anthropic
    apiKey:
      name: ANTHROPIC_API_KEY
      sentinelEnv: true
      inject:
        - domain: api.anthropic.com
          header: x-api-key
          format: \"%s\"
";

/// A valid authorization for the `my-service` name `ONE_YAML_TOOL` requests,
/// with `sentinelEnv: true` so the launch needs no image-metadata read.
const VALID_MY_SERVICE_YAML: &str = "\
credentials:
  - service: my-service
    apiKey:
      name: MY_SERVICE_KEY
      sentinelEnv: true
      inject: [{domain: api.my-service.example, header: x-api-key, format: \"%s\"}]
";

/// The hosts of this launch's registered TLS-intercept rules.
fn intercept_rule_hosts(config: &serde_json::Value) -> Vec<&str> {
    config["network"]["intercept"]["rules"]
        .as_array()
        .map(|rules| {
            rules
                .iter()
                .map(|rule| rule["host"].as_str().unwrap())
                .collect()
        })
        .unwrap_or_default()
}

/// AC1 + AC2, end to end: a same-named authorization replaces the built-in's
/// *credential* facets and leaves its *configuration and persistence* alone.
#[test]
fn a_same_named_authorization_replaces_the_built_in_but_not_its_configuration() {
    let harness = Harness::new(); // seeds ~/.claude/.credentials.json
    write_credentials(&harness.home_root, YAML_ANTHROPIC);
    let out = harness.launch_with_env(
        "claude",
        &[],
        &[
            ("AGENT_VM_TEST_CREDENTIAL", "anthropic=sk-test-replacement"),
            ("ANTHROPIC_API_KEY", "sk-host-raw-must-not-reach-the-guest"),
        ],
    );
    let stderr = stderr_of(&out);
    // Panics unless `CONFIG_MARKER` is present, so "the launch died early"
    // cannot masquerade as a pass.
    let config = debug_config_json(&stderr);
    let state = state_dir(&stderr);

    // -- credential facets: gone -------------------------------------------
    assert!(
        !registered_secret_env_vars(&config).contains(&"MSB_AGENT_VM_ANTHROPIC_UNUSED"),
        "the built-in substitution entry must not be registered"
    );
    assert!(
        !state.join("claude/.credentials.json").exists(),
        "the built-in placeholder must not be provisioned"
    );
    assert!(
        !intercept_rule_hosts(&config).contains(&"platform.claude.com"),
        "the built-in OAuth refresh route must not be registered"
    );

    // -- the authorization's own facets: present ---------------------------
    let creds = &config["network"]["secrets"]["header_credentials"];
    assert_eq!(creds[0]["reference"], "anthropic");
    assert_eq!(creds[0]["origin"]["host"], "api.anthropic.com");
    assert_eq!(creds[0]["header"], "x-api-key");
    let env = env_pairs(&config);
    assert_eq!(
        env.iter()
            .find(|(key, _)| *key == "ANTHROPIC_API_KEY")
            .map(|(_, value)| *value),
        Some("proxy-managed"),
        "D10: the sentinel, never the host's raw value"
    );
    assert!(
        !env.iter()
            .any(|(_, value)| *value == "sk-host-raw-must-not-reach-the-guest"),
        "the host's raw key reached the guest env: {env:?}"
    );
    // §4.8 step 4, automated at the harness boundary: neither the
    // authorization's value nor the host's raw key is observable anywhere
    // under the project state dir or its host-only `<state>.secrets/` sibling.
    // The sandbox DB and `ps auxww` are host-global and remain a manual sweep.
    let host_secrets = PathBuf::from(format!("{}.secrets", state.display()));
    for root in [&state, &host_secrets] {
        assert_no_file_contains(root, "sk-test-replacement");
        assert_no_file_contains(root, "sk-host-raw-must-not-reach-the-guest");
    }

    // -- configuration + persistence: untouched (AC2) ----------------------
    assert!(read_json(&state.join("claude/settings.json")).is_some());
    assert!(read_json(&state.join("claude.json")).is_some());
    assert!(
        std::fs::symlink_metadata(state.join("home/.claude"))
            .unwrap()
            .file_type()
            .is_symlink(),
        "the `.claude` guest-HOME link is furniture and must remain"
    );
}

/// D4: the built-in placeholder a previous launch left is cleared once the
/// authorization takes over (ADR-0017: no placeholder without its substitution
/// entry). One shared state dir across both launches.
#[test]
fn replacing_a_built_in_clears_the_placeholder_an_earlier_launch_left() {
    let harness = Harness::new();
    let first = harness.launch_default("claude");
    let state = state_dir(&stderr_of(&first));
    assert!(
        state.join("claude/.credentials.json").exists(),
        "launch 1 wires the built-in placeholder: {}",
        stderr_of(&first)
    );
    let host_secrets = PathBuf::from(format!("{}.secrets", state.display()));
    assert!(
        host_secrets.join("anthropic").exists(),
        "launch 1 captured the real host credential to disk (S6/R8)"
    );

    write_credentials(&harness.home_root, YAML_ANTHROPIC);
    let second = harness.launch_with_env(
        "claude",
        &[],
        &[("AGENT_VM_TEST_CREDENTIAL", "anthropic=sk-test-replacement")],
    );
    let stderr = stderr_of(&second);
    assert!(stderr.contains(CONFIG_MARKER), "{stderr}");
    assert!(
        !state.join("claude/.credentials.json").exists(),
        "the stale built-in placeholder must be cleared (ADR-0017): {stderr}"
    );
    // S6/R8: the real host token copy is deliberately **left in place** —
    // deleting it would be new destructive behaviour on data a concurrent
    // launch may hold, so the guest-visible placeholder is cleared and the
    // host copy is not. USAGE.md tells the user to remove the state dir.
    assert!(
        host_secrets.join("anthropic").exists(),
        "a replacement must not delete the earlier launch's host token copy (S6): {stderr}"
    );
}

/// AC2/AC5: an authorization nobody requests is inert. `codex` requests only
/// `openai`, so an `anthropic` authorization changes nothing — the observed
/// launch is byte-identical to the untouched `codex` golden.
#[test]
fn an_unrequested_authorization_leaves_the_built_in_alone() {
    let harness = Harness::new();
    write_credentials(&harness.home_root, YAML_ANTHROPIC);
    let out = harness.launch_default("codex");
    assert_matches_golden("codex", &observation(&harness, &out));
}

// -- #162: the override cannot bypass configuration or security errors ------

/// Run the same input twice, with and without `--allow-missing-credentials`,
/// and assert **both** refuse for the row's own stated reason. The reason must
/// be specific to the row: a bare `contains("credentials.yaml")` would let two
/// unrelated failures satisfy the pairing.
fn assert_the_override_does_not_bypass(
    harness: &Harness,
    tool: &str,
    envs: &[(&str, &str)],
    reason: &str,
) {
    for extra in [&[][..], &["--allow-missing-credentials"][..]] {
        let out = harness.launch_with_env(tool, extra, envs);
        let rendered = format!("{}{}", stderr_of(&out), stdout_of(&out));
        assert!(
            !out.status.success(),
            "flag={extra:?} must still refuse: {rendered}"
        );
        assert!(
            rendered.contains(reason),
            "flag={extra:?} did not name this row's reason {reason:?}: {rendered}"
        );
        assert!(
            !rendered.contains(CONFIG_MARKER),
            "flag={extra:?} booted anyway: {rendered}"
        );
    }
}

/// Row 1: an unsupported destination in the authorization file. Carries the
/// positive control for the whole pairing template.
#[test]
fn the_override_does_not_bypass_a_malformed_authorization_file() {
    let canary = "sk-CANARY-6f2a1b3c4d5e6071829304a5b6c7d8e9";
    let harness = Harness::new();
    harness.write_user(ONE_YAML_TOOL);
    write_credentials(
        &harness.home_root,
        &format!(
            "credentials:\n  - service: my-service\n    apiKey:\n      name: MY_SERVICE_KEY\n      inject:\n        - domain: \"{canary}/x\"\n          header: x-api-key\n          format: \"%s\"\n"
        ),
    );
    assert_the_override_does_not_bypass(
        &harness,
        "t",
        &[],
        "credentials[0].apiKey.inject[0].domain",
    );

    // Positive control: the same harness with the problem removed boots all the
    // way to the sandbox build, so "both runs refused" cannot be satisfied by a
    // harness that could never boot at all.
    let control = Harness::new();
    control.write_user(ONE_YAML_TOOL);
    write_credentials(&control.home_root, VALID_MY_SERVICE_YAML);
    let out = control.launch_with_env(
        "t",
        &[],
        &[("AGENT_VM_TEST_CREDENTIAL", "my-service=sk-control-value")],
    );
    let rendered = format!("{}{}", stderr_of(&out), stdout_of(&out));
    assert!(
        rendered.contains(CONFIG_MARKER),
        "the positive control never booted: {rendered}"
    );
}

/// Row 2: a recognized-but-unsupported field (`source`; #163 is not landed).
#[test]
fn the_override_does_not_bypass_an_unsupported_field() {
    let harness = Harness::new();
    harness.write_user(ONE_YAML_TOOL);
    write_credentials(
        &harness.home_root,
        "credentials:\n  - service: my-service\n    source: env\n    apiKey:\n      name: MY_SERVICE_KEY\n      inject: [{domain: api.my-service.example, header: x-api-key, format: \"%s\"}]\n",
    );
    assert_the_override_does_not_bypass(&harness, "t", &[], "`source` is not supported");
}

/// Row 3: a wildcard destination can never be expanded by the override.
#[test]
fn the_override_does_not_bypass_a_wildcard_destination() {
    let harness = Harness::new();
    harness.write_user(ONE_YAML_TOOL);
    write_credentials(
        &harness.home_root,
        "credentials:\n  - service: my-service\n    apiKey:\n      name: MY_SERVICE_KEY\n      inject: [{domain: \"*.example.com\", header: x-api-key, format: \"%s\"}]\n",
    );
    assert_the_override_does_not_bypass(&harness, "t", &[], "wildcards are not supported");
}

/// Row 4: a group-writable authorization file is a security refusal, not an
/// availability one.
#[test]
fn the_override_does_not_bypass_a_group_writable_authorization_file() {
    use std::os::unix::fs::PermissionsExt as _;
    let harness = Harness::new();
    harness.write_user(ONE_YAML_TOOL);
    write_credentials(&harness.home_root, VALID_MY_SERVICE_YAML);
    let path = harness.home_root.join(".config/agent-vm/credentials.yaml");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).unwrap();
    assert_the_override_does_not_bypass(
        &harness,
        "t",
        &[],
        "group- or other-writable; refusing to trust it",
    );
}

/// Row 5: present-but-invalid is a configuration error, not an unavailable
/// source. A trailing space is rejected by `SecretValue`.
#[test]
fn the_override_does_not_bypass_a_rejected_stored_value() {
    let harness = Harness::new();
    harness.write_user(ONE_YAML_TOOL);
    write_credentials(&harness.home_root, VALID_MY_SERVICE_YAML);
    assert_the_override_does_not_bypass(
        &harness,
        "t",
        &[("AGENT_VM_TEST_CREDENTIAL", "my-service=sk-trailing-space ")],
        "cannot be used",
    );
}

/// Row 6: unreadable boot-image metadata for a `sentinelEnv: false` credential
/// fails closed regardless of the flag.
#[test]
fn the_override_does_not_bypass_unreadable_image_metadata() {
    let harness = Harness::new();
    harness.write_user(ONE_YAML_TOOL);
    write_credentials(
        &harness.home_root,
        "credentials:\n  - service: my-service\n    apiKey:\n      name: MY_SERVICE_KEY\n      inject:\n        - domain: api.my-service.example\n          header: x-api-key\n          format: \"%s\"\n",
    );
    assert_the_override_does_not_bypass(
        &harness,
        "t",
        &[],
        &format!("agent-vm pull --image {BOGUS_IMAGE}"),
    );
}

/// Row 7: a tool-declared `env` key for an owned name is a hard error under both
/// policies. The value is ready so the launch reaches `assemble_guest_env`.
#[test]
fn the_override_does_not_bypass_a_tool_env_conflict() {
    let harness = Harness::new();
    harness.write_user(
        "[[tools]]\nname = \"t\"\ncommand = \"t\"\ncredentials = [\"my-service\"]\nenv = { MY_SERVICE_KEY = \"x\" }\n",
    );
    write_credentials(&harness.home_root, VALID_MY_SERVICE_YAML);
    assert_the_override_does_not_bypass(
        &harness,
        "t",
        &[("AGENT_VM_TEST_CREDENTIAL", "my-service=sk-value")],
        "`MY_SERVICE_KEY`, which is owned by an authorized credential",
    );
}

/// Row 8: the flag does **not** reach a built-in provider's own
/// missing-credential bail (decision D). This pins the flag's scope as a
/// contract rather than an unstated omission.
#[test]
fn the_override_does_not_bypass_a_built_in_missing_credential() {
    let harness = Harness::new();
    std::fs::remove_file(harness.home_root.join(".claude/.credentials.json")).unwrap();
    assert_the_override_does_not_bypass(
        &harness,
        "claude",
        &[],
        "no usable Claude credential found on the host",
    );
}

// -- #162: the override's positive paths, and built-in requirement semantics --

/// The `NotAuthorized` path owns no guest variable, so it does not trip the
/// image-env check and the launch really boots.
#[test]
fn the_override_skips_an_unauthorized_request_and_still_boots() {
    let harness = Harness::new();
    harness.write_user(ONE_YAML_TOOL); // `credentials = ["my-service"]`, no YAML file
    let out = harness.launch("t", &["--allow-missing-credentials"]);
    let rendered = format!("{}{}", stderr_of(&out), stdout_of(&out));
    assert!(rendered.contains("my-service"), "{rendered}");
    assert!(
        rendered.contains("--allow-missing-credentials"),
        "{rendered}"
    );
    assert!(
        rendered.contains(CONFIG_MARKER),
        "the launch must reach the sandbox build, not merely warn: {rendered}"
    );
}

/// The authorized-but-unavailable override path. The launch owns a guest
/// variable, so with `sentinelEnv: false` it stops at the image-metadata stage —
/// which is exactly the proof that it got *past* credential resolution.
#[test]
fn the_override_warns_and_proceeds_for_an_unavailable_required_credential() {
    let harness = Harness::new();
    harness.write_user(ONE_YAML_TOOL);
    write_credentials(
        &harness.home_root,
        "credentials:\n  - service: my-service\n    required: true\n    apiKey:\n      name: MY_SERVICE_KEY\n      inject: [{domain: api.my-service.example, header: x-api-key, format: \"%s\"}]\n",
    );
    // `AGENT_VM_TEST_CREDENTIAL` names a *different* service, so
    // `TestCredentialSource::resolve` returns `Missing` deterministically.
    let out = harness.launch_with_env(
        "t",
        &["--allow-missing-credentials"],
        &[("AGENT_VM_TEST_CREDENTIAL", "my-other-service=sk-x")],
    );
    let rendered = format!("{}{}", stderr_of(&out), stdout_of(&out));
    // Assert the complete warning envelope, not the absence of the remediation
    // text: `Withheld::notice()` wraps `reason()` verbatim, and `reason()`'s
    // `Missing` arm contains exactly that instruction.
    assert!(
        rendered.contains("warning: no value is stored in the system keychain for `my-service`"),
        "{rendered}"
    );
    assert!(
        rendered.contains("; continuing without it because --allow-missing-credentials was passed"),
        "the withheld credential must be rendered as a warning, not a fatal error: {rendered}"
    );
    assert!(
        rendered.contains("agent-vm pull --image"),
        "the launch must have got past credential resolution to the image-metadata stage: {rendered}"
    );
}

/// D7: a replaced provider does not inherit the built-in requirement. Anthropic
/// is `required` by the `claude` tool, but the authorization is not, so the
/// launch proceeds instead of bailing.
#[test]
fn a_replaced_provider_does_not_inherit_the_built_in_requirement() {
    let harness = Harness::new();
    std::fs::remove_file(harness.home_root.join(".claude/.credentials.json")).unwrap();
    write_credentials(&harness.home_root, YAML_ANTHROPIC);
    let out = harness.launch_with_env(
        "claude",
        &[],
        &[("AGENT_VM_TEST_CREDENTIAL", "anthropic=sk-test-replacement")],
    );
    let rendered = format!("{}{}", stderr_of(&out), stdout_of(&out));
    assert!(
        !rendered.contains("no usable Claude credential found on the host"),
        "a replaced provider must not inherit the built-in requirement: {rendered}"
    );
    assert!(rendered.contains(CONFIG_MARKER), "{rendered}");
}

/// C6 (#162): a replacement that owns a *differently named* variable leaves the
/// host's raw key forwarded. Warn, and never render the value.
#[test]
fn a_renamed_replacement_warns_that_the_hosts_raw_key_is_still_forwarded() {
    let harness = Harness::new();
    write_credentials(
        &harness.home_root,
        "credentials:\n  - service: anthropic\n    apiKey:\n      name: MY_KEY\n      sentinelEnv: true\n      inject: [{domain: api.anthropic.example, header: x-api-key, format: \"%s\"}]\n",
    );
    let canary = "sk-host-real-canary-1a2b3c4d5e6f70819203a4b5c6d7e8f9";
    let out = harness.launch_with_env(
        "claude",
        &[],
        &[
            ("AGENT_VM_TEST_CREDENTIAL", "anthropic=sk-test-replacement"),
            ("ANTHROPIC_API_KEY", canary),
        ],
    );
    let rendered = format!("{}{}", stderr_of(&out), stdout_of(&out));
    assert!(
        rendered.contains("the host's `ANTHROPIC_API_KEY` is still forwarded"),
        "the silent security downgrade must be reported: {rendered}"
    );
    // The notice is about a *real* exposure: the host's raw value really is in
    // the guest env, which is exactly why the warning exists.
    let config = debug_config_json(&stderr_of(&out));
    assert!(
        env_pairs(&config)
            .iter()
            .any(|(key, value)| *key == "ANTHROPIC_API_KEY" && *value == canary),
        "the warning must describe the actual environment: {:?}",
        env_pairs(&config)
    );
    // The *authorization's* stored value is never rendered anywhere (ADR-0024).
    assert!(
        !rendered.contains("sk-test-replacement"),
        "the stored value leaked: {rendered}"
    );
}

/// The asymmetric partner of the test above: when the authorization owns the
/// host's own variable name, nothing is forwarded and no notice fires.
#[test]
fn a_same_named_replacement_does_not_warn_about_raw_forwarding() {
    let harness = Harness::new();
    write_credentials(&harness.home_root, YAML_ANTHROPIC);
    let out = harness.launch_with_env(
        "claude",
        &[],
        &[
            ("AGENT_VM_TEST_CREDENTIAL", "anthropic=sk-test-replacement"),
            ("ANTHROPIC_API_KEY", "sk-host-canary-must-not-be-forwarded"),
        ],
    );
    let rendered = format!("{}{}", stderr_of(&out), stdout_of(&out));
    assert!(!rendered.contains("is still forwarded"), "{rendered}");
    let config = debug_config_json(&stderr_of(&out));
    assert_eq!(
        env_pairs(&config)
            .iter()
            .find(|(key, _)| *key == "ANTHROPIC_API_KEY")
            .map(|(_, value)| *value),
        Some("proxy-managed")
    );
}

/// **R5/S4 (#162).** `openai` and `opencode-static` both forward the *same*
/// variable, `OPENAI_API_KEY`. When both are replaced and neither authorization
/// owns that name, the raw-forwarding notice must fire **once**, naming the
/// variable once and listing both providers — not twice with advice
/// (`apiKey.name: OPENAI_API_KEY`) that only one of the two entries could
/// follow.
#[test]
fn a_shared_forwarded_variable_is_warned_about_once() {
    let harness = Harness::new();
    write_credentials(
        &harness.home_root,
        "credentials:\n  - service: openai\n    apiKey:\n      name: MY_OPENAI_KEY\n      sentinelEnv: true\n      inject: [{domain: api.openai.example, header: x-api-key, format: \"%s\"}]\n  - service: opencode-static\n    apiKey:\n      name: MY_OPENCODE_KEY\n      sentinelEnv: true\n      inject: [{domain: api.opencode.example, header: x-api-key, format: \"%s\"}]\n",
    );
    harness.write_project(
        "[[tools]]\nname = \"dual\"\ncommand = \"/bin/echo\"\ncredentials = [\"openai\", \"opencode-static\"]\n",
    );
    let out = harness.launch_with_env("dual", &[], &[("OPENAI_API_KEY", "sk-host-canary")]);
    let rendered = format!("{}{}", stderr_of(&out), stdout_of(&out));
    let notices = rendered.matches("still forwarded").count();
    assert_eq!(
        notices, 1,
        "the shared OPENAI_API_KEY must produce exactly one notice: {rendered}"
    );
    let notice = rendered
        .lines()
        .find(|line| line.contains("still forwarded"))
        .expect("a notice");
    assert!(notice.contains("`openai`"), "{notice}");
    assert!(notice.contains("`opencode-static`"), "{notice}");
    assert!(notice.contains("`OPENAI_API_KEY`"), "{notice}");
    // The canary value is a real host value and must never be rendered.
    assert!(
        !rendered.contains("sk-host-canary"),
        "a host value leaked: {rendered}"
    );
}

/// **R3/S2 (#162).** The replacement shape ADR-0025's own examples use: an
/// `opencode-static` authorization that names `OPENAI_API_KEY` and injects at
/// `api.openai.com`. The guest *does* get a working OpenAI key through the proxy
/// (the sentinel is published), yet agent-vm's capture gate captured no OpenAI
/// host credential, so it retires the `model` pin. That is the open decision S2
/// records; this test pins the observed behaviour so any change to the pin's
/// gate has to update it deliberately rather than by accident.
#[test]
fn a_sentinel_opencode_replacement_publishes_the_key_but_retires_the_model_pin() {
    let harness = Harness::new();
    write_credentials(
        &harness.home_root,
        "credentials:\n  - service: opencode-static\n    apiKey:\n      name: OPENAI_API_KEY\n      sentinelEnv: true\n      inject: [{domain: api.openai.com, header: authorization, format: \"Bearer %s\"}]\n",
    );
    harness.write_project(
        "[[tools]]\nname = \"oc\"\ncommand = \"/bin/echo\"\ncredentials = [\"opencode-static\"]\n",
    );
    let out = harness.launch_with_env(
        "oc",
        &[],
        &[(
            "AGENT_VM_TEST_CREDENTIAL",
            "opencode-static=sk-test-replacement",
        )],
    );
    let stderr = stderr_of(&out);
    assert!(stderr.contains(CONFIG_MARKER), "{stderr}");
    let config = debug_config_json(&stderr);
    // The sentinel really is published: the guest can use OpenAI through the
    // proxy even though agent-vm captured no OpenAI host credential.
    assert_eq!(
        env_pairs(&config)
            .iter()
            .find(|(key, _)| *key == "OPENAI_API_KEY")
            .map(|(_, value)| *value),
        Some("proxy-managed"),
        "the authorization owns OPENAI_API_KEY, so the sentinel must be published: {:?}",
        env_pairs(&config)
    );
    // ... and yet the `model` pin is retired (the S2 open decision).
    let state = state_dir(&stderr);
    let opencode: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(state.join("opencode-config/opencode.json")).unwrap(),
    )
    .unwrap();
    assert!(
        opencode.get("model").is_none(),
        "the pin is retired for a replaced provider: {opencode}"
    );
    assert_eq!(opencode["autoupdate"], serde_json::json!(false));
}

/// **D11 (#162).** The launch-side half of the fresh-state-dir Copilot trust
/// behaviour, through the real binary: a same-named `copilot` authorization
/// still gets the non-secret trust configuration (`trusted_folders`), so the
/// CLI's first run is pre-approved, while every credential facet is
/// suppressed — no `github_token` placeholder, no `COPILOT_GITHUB_TOKEN`, no
/// substitution entry. The in-guest "do you trust this folder?" prompt itself
/// needs a boot and a live CLI (§4.8 step 7); this pins the launch decision it
/// depends on, which `secrets.rs`'s in-process test alone does not exercise
/// end to end. `Harness::new()` seeds the host device-flow token, so the
/// absence below is the replacement's doing, not a missing host credential.
#[test]
fn a_replaced_copilot_still_gets_its_trust_configuration_and_no_token() {
    let harness = Harness::new();
    write_credentials(
        &harness.home_root,
        "credentials:\n  - service: copilot\n    apiKey:\n      name: COPILOT_TOKEN\n      sentinelEnv: true\n      inject: [{domain: api.githubcopilot.com, scheme: bearer}]\n",
    );
    let out = harness.launch_with_env(
        "copilot",
        &[],
        &[("AGENT_VM_TEST_CREDENTIAL", "copilot=sk-test-replacement")],
    );
    let stderr = stderr_of(&out);
    // Panics unless `CONFIG_MARKER` is present, so "the launch died early"
    // cannot masquerade as a pass.
    assert!(stderr.contains(CONFIG_MARKER), "{stderr}");
    let config = debug_config_json(&stderr);
    let state = state_dir(&stderr);

    // -- configuration facet: written on a fresh state dir (AC2, D11) -------
    let copilot = read_json(&state.join("copilot/config.json"))
        .expect("a replaced Copilot must still get its trust configuration");
    assert_eq!(copilot["trusted_folders"], serde_json::json!(["/"]));
    assert!(
        copilot.get("github_token").is_none(),
        "no placeholder may be written for a replaced provider: {copilot}"
    );
    // The guest-HOME link is furniture and survives, like every provider's.
    assert!(
        std::fs::symlink_metadata(state.join("home/.copilot"))
            .unwrap()
            .file_type()
            .is_symlink(),
        "the `.copilot` guest-HOME link must remain"
    );

    // -- credential facets: suppressed (AC1) --------------------------------
    assert!(
        !registered_secret_env_vars(&config).contains(&"MSB_AGENT_VM_COPILOT_UNUSED"),
        "the built-in substitution entry must not be registered"
    );
    let env = env_pairs(&config);
    assert!(
        !env.iter().any(|(key, _)| *key == "COPILOT_GITHUB_TOKEN"),
        "the built-in placeholder bearer must not be exported: {env:?}"
    );
    // The authorization's own sentinel is published instead.
    assert_eq!(
        env.iter()
            .find(|(key, _)| *key == "COPILOT_TOKEN")
            .map(|(_, value)| *value),
        Some("proxy-managed"),
        "the authorization owns COPILOT_TOKEN, so its sentinel must be published"
    );
}

fn golden_path(tool: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/config-launch")
        .join(format!("{tool}.golden"))
}

/// `UPDATE_LAUNCH_GOLDENS=1` rewrites the fixtures instead of asserting, so a
/// future intentional default change has a mechanical update path. The
/// fixtures in-tree were regenerated for #118 (the provisioning-set change)
/// and again for the microsandbox 0.7.4 sync (`injection` -> `substitution`
/// with `basic_auth` folded into `headers`, `on_violation` ->
/// `violation_action`, and the new `network.strict` /
/// `external_mount_policy` fields).
fn assert_matches_golden(tool: &str, actual: &str) {
    let path = golden_path(tool);
    if std::env::var_os("UPDATE_LAUNCH_GOLDENS").is_some() {
        write(&path, actual);
        return;
    }
    let expected = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
    assert_eq!(
        actual, expected,
        "launch observation for {tool} changed vs the {tool} golden\n\
         (rerun with UPDATE_LAUNCH_GOLDENS=1 only if the change is intentional)"
    );
}

// ---------------------------------------------------------------------------
// E1 / E2 — the headline acceptance criterion
// ---------------------------------------------------------------------------

#[test]
fn default_tools_launch_with_their_declared_provisioning() {
    for tool in DEFAULT_TOOLS {
        let harness = Harness::new();
        let out = harness.launch_default(tool);
        // Pin the tool-dependent subset directly as well as via the golden, so
        // a future widening of the normalizer cannot stop pinning it.
        assert_tool_dependent_content(tool, &normalized_config(&harness, &out));
        assert_matches_golden(tool, &observation(&harness, &out));
    }
}

/// The normalizer must not hide a tool-dependent field. Its only removal now is
/// the host-gid-dependent `/etc/group` append, so a difference anywhere else
/// must survive.
#[test]
fn host_environment_normalization_drops_only_the_host_gid_group_append() {
    // The same launch observed on a host whose gid appends `/etc/group` (top)
    // and one whose gid does not (bottom).
    let with_group = serde_json::json!({
        "patches": [
            { "Append": { "path": "/etc/passwd", "content": "p" } },
            { "Append": { "path": "/etc/group", "content": "agent:x:1001:" } },
        ],
        "env": [ { "key": "PATH", "value": PATH_VALUE } ],
    });
    let without_group = serde_json::json!({
        "patches": [ { "Append": { "path": "/etc/passwd", "content": "p" } } ],
        "env": [ { "key": "PATH", "value": PATH_VALUE } ],
    });
    let mut a = with_group.clone();
    let mut b = without_group.clone();
    drop_host_gid_group_append(&mut a);
    drop_host_gid_group_append(&mut b);
    assert_eq!(a, b, "the two host-gid shapes must normalize identically");

    // A difference in a tool-dependent field must survive normalization.
    let mut changed = with_group.clone();
    changed["env"][0]["value"] = serde_json::json!("/somewhere/else");
    drop_host_gid_group_append(&mut changed);
    assert_ne!(
        changed, b,
        "a tool-dependent change must not be normalized away"
    );
}

#[test]
fn default_tools_emit_the_legacy_guest_command_line() {
    for (tool, expected) in LEGACY_GUEST_COMMANDS {
        let harness = Harness::new();
        let out = harness.launch_default(tool);
        let stderr = stderr_of(&out);
        assert_eq!(
            debug_guest_command(&stderr),
            expected,
            "guest command line changed for {tool}\nstderr:\n{stderr}"
        );
    }
}

// ---------------------------------------------------------------------------
// E3 — a config declaring only `claude`
// ---------------------------------------------------------------------------

const CLAUDE_ONLY: &str = "[[tools]]\nname = \"claude\"\ncommand = \"claude\"\n\
     args = [\"--dangerously-skip-permissions\"]\ncredentials = [\"anthropic\"]\n";

#[test]
fn claude_only_config_registers_claude_and_the_shell_fallback() {
    let harness = Harness::new();
    harness.write_user(CLAUDE_ONLY);

    // `claude` is registered and launches.
    let claude = harness.launch_default("claude");
    assert!(
        claude.status.code().is_some(),
        "claude did not run to the debug stage"
    );
    assert!(
        stderr_of(&claude).contains(CONFIG_MARKER),
        "claude did not reach the debug dump: {}",
        stderr_of(&claude)
    );

    // `codex` is NOT registered — clap's "unrecognized subcommand".
    let codex = harness.launch_default("codex");
    assert!(!codex.status.success(), "codex should not be registered");
    let codex_err = stderr_of(&codex);
    assert!(
        codex_err.contains("unrecognized subcommand"),
        "expected clap unrecognized-subcommand, got: {codex_err}"
    );
    assert!(
        codex_err.contains("codex"),
        "the error should name the offending verb: {codex_err}"
    );

    // `shell` is not declared, so the built-in fallback registers it.
    let shell = harness.launch_default("shell");
    assert!(
        stderr_of(&shell).contains(CONFIG_MARKER),
        "shell fallback did not launch: {}",
        stderr_of(&shell)
    );
}

// ---------------------------------------------------------------------------
// E4 — a bespoke project tool
// ---------------------------------------------------------------------------

#[test]
fn a_project_declared_tool_launches_its_own_command() {
    let harness = Harness::new();
    harness.write_project(
        "[[tools]]\nname = \"mytool\"\ncommand = \"/bin/echo\"\nargs = [\"--fast\"]\n",
    );

    let out = harness.launch("mytool", &["--", "hi"]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(CONFIG_MARKER),
        "mytool did not reach the debug dump: {stderr}"
    );
    assert_eq!(
        debug_guest_command(&stderr),
        "/bin/echo --fast hi",
        "guest command line for the project-declared tool\nstderr:\n{stderr}"
    );
}

// ---------------------------------------------------------------------------
// E2 / E2b / E2c / E3 — tool-declared guest env (#119)
// ---------------------------------------------------------------------------

/// **E2 (#119 D3a, amended #258).** `PATH` is launcher/image-owned, so a
/// tool-declared `PATH` is dropped at the assembly seam and never reaches the
/// guest env; the acquired image's OCI `PATH` (applied as the per-exec
/// override) is the only default. The tool's other `env` is still published.
/// This is the footgun guard that stops a project config from *accidentally*
/// redirecting the launcher's own environment — defence in depth on top of
/// ADR-0015's trust boundary (a declaration that sets `env` can already set
/// `command` and `args`, i.e. run arbitrary guest code), not a substitute for
/// it. Previously the launcher republished its own `PATH` after the tool's via
/// guest last-wins; now it omits both and the OCI value stands (#258).
///
/// Deliberately does **not** call [`assert_tool_dependent_content`] (M1): its
/// `env_of` is a first-match `.find()`, so it would read the *first* `PATH`
/// here — the declared `/evil` — and fail. E2 defines its own assertions
/// instead; the shared helper's `.find()` stays correct for the shipped tools,
/// which declare no colliding key.
#[test]
fn project_tool_env_path_is_dropped_by_the_launcher() {
    let harness = Harness::new();
    harness.write_project(
        "[[tools]]\nname = \"envtool\"\ncommand = \"/bin/echo\"\nenv = { AVM_TEST = \"ok\", PATH = \"/evil\" }\n",
    );
    let out = harness.launch("envtool", &[]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(CONFIG_MARKER),
        "envtool did not reach the debug dump: {stderr}"
    );
    let config = debug_config_json(&stderr);
    let env = env_pairs(&config);

    let avm_test = env
        .iter()
        .position(|(key, _)| *key == "AVM_TEST")
        .expect("the tool's own AVM_TEST must be published");
    assert_eq!(env[avm_test].1, "ok");

    // #258: the launcher drops the tool's `PATH` rather than republishing its
    // own value after it; the acquired image's OCI `PATH` is the only default.
    assert!(
        env.iter().all(|(key, _)| *key != "PATH"),
        "a tool-declared PATH must not reach the guest env: {env:?}"
    );
}

/// **E2b (#119 D3c, M2).** `HOME`/`USER`/`LOGNAME` are refused at the config
/// seam in *every* mode — including `--root`, the mode where emission position
/// would not have protected them (agent-vm publishes the identity triple only
/// in non-root mode). The refusal happens at config load, before `run.rs`
/// computes `root_mode`, so it never reaches `builder.build()` (`CONFIG_MARKER`
/// absent) — exactly like `a_broken_config_fails_a_launch_with_the_config_error`
/// asserts for malformed TOML. All three keys are exercised, each in both
/// modes — the `--root` half is the case position would not have covered.
#[test]
fn a_tool_declaring_the_guest_identity_is_refused_in_every_mode() {
    for key in ["HOME", "USER", "LOGNAME"] {
        for extra in [vec!["--root"], vec![]] {
            let harness = Harness::new();
            harness.write_project(&format!(
                "[[tools]]\nname = \"envtool\"\ncommand = \"/bin/echo\"\nenv = {{ {key} = \"/evil\" }}\n"
            ));
            let out = harness.launch("envtool", &extra);
            // Every launch in this harness exits nonzero — it ends by pulling
            // `BOGUS_IMAGE` — so `out.status` carries no signal here. The
            // rejection is proven by the stderr assertions below, and the
            // absent `CONFIG_MARKER` shows it never reached `builder.build()`.
            let stderr = stderr_of(&out);
            assert!(
                stderr.contains(&format!("env key \"{key}\"")),
                "{key} {extra:?}: the diagnostic must name the rejected key: {stderr}"
            );
            assert!(
                stderr.contains(
                    "must not be declared by a tool (agent-vm owns the guest identity environment)"
                ),
                "{key} {extra:?}: {stderr}"
            );
            assert!(
                !stderr.contains(CONFIG_MARKER),
                "{key} {extra:?}: the launch must not reach builder.build(): {stderr}"
            );
        }
    }
}

/// **E2c (#119 D3b, amended #258).** The launcher's *unconditional* env —
/// `IS_SANDBOX`, `LANG` (see `run::GUEST_ALWAYS_ENV`) — really is published on
/// every launch, root mode included. This is the premise that licenses leaving
/// those keys *out* of `check_env_key`'s rejection set: position, not
/// validation, protects them. **If this test ever fails, either restore the
/// unconditional emission or add that key to `check_env_key`'s rejection set —
/// D3b.** Root mode is the case that removed `HOME`/`USER`/`LOGNAME` and so the
/// case that could plausibly remove these. `PATH` is deliberately *not*
/// published here: it is image-owned and applied as the per-exec override
/// (#258), so the debug dump carries no `PATH` in either mode.
#[test]
fn the_launchers_unconditional_env_is_published_in_both_modes() {
    for extra in [vec![], vec!["--root"]] {
        let harness = Harness::new();
        harness.write_project("[[tools]]\nname = \"plain\"\ncommand = \"/bin/echo\"\n");
        let out = harness.launch("plain", &extra);
        let stderr = stderr_of(&out);
        assert!(
            stderr.contains(CONFIG_MARKER),
            "plain did not reach the debug dump ({extra:?}): {stderr}"
        );
        let config = debug_config_json(&stderr);
        let env = env_pairs(&config);
        let env_of = |key: &str| env.iter().find(|(k, _)| *k == key).map(|(_, v)| *v);
        assert_eq!(env_of("PATH"), None, "PATH is image-owned now: {extra:?}");
        assert_eq!(env_of("IS_SANDBOX"), Some("1"), "{extra:?}");
        assert_eq!(env_of("LANG"), Some("C.UTF-8"), "{extra:?}");
        // Root mode pins the numeric 0:0 identity and the root triple so an
        // OCI `USER`/`ENV HOME` cannot leak in (#258).
        if extra.contains(&"--root") {
            assert_eq!(
                config["runtime"]["user"].as_str(),
                Some("0:0"),
                "root mode must set the sandbox user to 0:0"
            );
            assert_eq!(env_of("HOME"), Some("/root"), "{extra:?}");
            assert_eq!(env_of("USER"), Some("root"), "{extra:?}");
            assert_eq!(env_of("LOGNAME"), Some("root"), "{extra:?}");
        }
    }
}

/// **E3 (#119).** A user-declared tool that declares no `env` launches with no
/// `CODEX_HOME` — the general rule, where E1 covers the shipped tools.
#[test]
fn a_user_declared_tool_without_env_gets_no_codex_home() {
    let harness = Harness::new();
    harness.write_project("[[tools]]\nname = \"plain\"\ncommand = \"/bin/echo\"\n");
    let out = harness.launch("plain", &[]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(CONFIG_MARKER),
        "plain did not reach the debug dump: {stderr}"
    );
    let config = debug_config_json(&stderr);
    let env = env_pairs(&config);
    let keys: Vec<&str> = env.iter().map(|(key, _)| *key).collect();
    assert!(
        !keys.contains(&"CODEX_HOME"),
        "a tool that declares no env must get no CODEX_HOME: {keys:?}"
    );
}

/// **#119.** A tool's own `env` is published in `--root` mode too, and the
/// value crosses into the emitted `SandboxConfig` byte-for-byte — including an
/// embedded `=`. The identity triple is rejected (E2b) precisely *because* the
/// launcher publishes it only in non-root mode; this pins that the tool's own
/// env is not accidentally made mode-conditional the same way (behaviour must
/// not silently differ between modes), and that nothing re-splits the value on
/// its `=` (only the `KEY=VALUE` delimiter is the first one).
#[test]
fn tool_declared_env_is_published_in_both_modes_and_keeps_equals_signs() {
    for extra in [vec![], vec!["--root"]] {
        let harness = Harness::new();
        harness.write_project(
            "[[tools]]\nname = \"envtool\"\ncommand = \"/bin/echo\"\nenv = { AVM_TEST = \"ok=still=ok\" }\n",
        );
        let out = harness.launch("envtool", &extra);
        let stderr = stderr_of(&out);
        assert!(
            stderr.contains(CONFIG_MARKER),
            "envtool {extra:?} did not reach the debug dump: {stderr}"
        );
        let config = debug_config_json(&stderr);
        let env = env_pairs(&config);
        assert_eq!(
            env.iter()
                .find(|(key, _)| *key == "AVM_TEST")
                .map(|(_, value)| *value),
            Some("ok=still=ok"),
            "the tool's env value must reach the guest intact ({extra:?})"
        );
    }
}

/// **#119 (F8).** `codex` and `shell` are the only shipped tools that declare
/// `CODEX_HOME` (V5). A user who shadows either in `~/.config/agent-vm/config.toml`
/// replaces its definition **wholesale**, so the shipped `env` is not inherited
/// and the tool gets no `CODEX_HOME` unless the user re-declares it — the
/// upgrade regression `USAGE.md` / ADR-0016 warn about. This pins both halves:
/// the loss (the warning's premise) and the documented remedy (re-declaring the
/// pair restores it).
#[test]
fn a_shadowed_shipped_tool_does_not_inherit_the_shipped_env() {
    // Each definition mirrors the shipped tool minus its `env`. `shell` must be
    // interactive so the shadow registers as the shell verb, exactly as the
    // built-in does.
    let cases: [(&str, &str); 2] = [
        ("codex", "command = \"codex\"\ncredentials = [\"openai\"]\n"),
        (
            "shell",
            "command = \"bash\"\nargs = [\"-O\", \"histappend\"]\ninteractive_shell = true\ncredentials = [\"openai\", \"opencode-static\"]\n",
        ),
    ];
    for (name, definition) in cases {
        // Shadowed *without* `env`: the shipped CODEX_HOME is not inherited.
        let harness = Harness::new();
        harness.write_user(&format!("[[tools]]\nname = \"{name}\"\n{definition}"));
        let out = harness.launch_default(name);
        let stderr = stderr_of(&out);
        assert!(
            stderr.contains(CONFIG_MARKER),
            "shadowed {name} did not reach the debug dump: {stderr}"
        );
        let config = debug_config_json(&stderr);
        let keys: Vec<&str> = env_pairs(&config).into_iter().map(|(key, _)| key).collect();
        assert!(
            !keys.contains(&"CODEX_HOME"),
            "a shadowed {name} must not inherit the shipped CODEX_HOME: {keys:?}"
        );

        // Re-declaring the pair is the documented remedy.
        let harness = Harness::new();
        harness.write_user(&format!(
            "[[tools]]\nname = \"{name}\"\n{definition}env = {{ CODEX_HOME = \"/agent-vm-state/codex\" }}\n"
        ));
        let out = harness.launch_default(name);
        let stderr = stderr_of(&out);
        assert!(
            stderr.contains(CONFIG_MARKER),
            "{name} with the remedy did not reach the debug dump: {stderr}"
        );
        let config = debug_config_json(&stderr);
        let env = env_pairs(&config);
        assert_eq!(
            env.iter()
                .find(|(key, _)| *key == "CODEX_HOME")
                .map(|(_, value)| *value),
            Some("/agent-vm-state/codex"),
            "the documented remedy must restore CODEX_HOME for a shadowed {name}"
        );
    }
}

// ---------------------------------------------------------------------------
// #96 — `pi` launches with no host credential
// ---------------------------------------------------------------------------

/// #96: `pi` declares no `credentials`, so a host with NO agent logins at all
/// must still launch it. The shared harness seeds fake credentials for every
/// provider, so this test removes them first -- otherwise it proves nothing.
#[test]
fn pi_launches_with_no_host_credentials_while_claude_still_bails() {
    let harness = Harness::new();
    // Deleting the seeds must be *checked*: a silently-failed removal would
    // let this test pass on a host that still has a credential.
    for relative in [
        ".claude/.credentials.json",
        ".cache/claude-vm/copilot-token.json",
        ".codex/auth.json",
        ".local/share/opencode/auth.json",
    ] {
        let path = harness.home_root.join(relative);
        std::fs::remove_file(&path)
            .unwrap_or_else(|error| panic!("removing seeded credential {relative}: {error}"));
        assert!(!path.exists(), "{relative} must be gone before the launch");
    }

    let out = harness.launch_default("pi");
    let pi_stderr = stderr_of(&out);
    assert!(
        pi_stderr.contains(CONFIG_MARKER),
        "pi must launch with no host credential: {pi_stderr}"
    );

    // The contrast that makes the assertion meaningful: a tool that DOES
    // declare `credentials` still hard-bails on the same host. Assert the
    // *specific* missing-credential diagnostic and that the debug-config seam
    // was never reached, so this cannot pass via the harness's inevitable
    // bogus-image pull failure alone (S2).
    let claude = harness.launch_default("claude");
    let claude_stderr = stderr_of(&claude);
    assert!(
        !claude.status.success(),
        "claude must still bail without its credential"
    );
    assert!(
        claude_stderr.contains("no usable Claude credential found on the host"),
        "claude must bail with its missing-credential diagnostic: {claude_stderr}"
    );
    assert!(
        !claude_stderr.contains(CONFIG_MARKER),
        "claude must not reach the debug-config seam without its credential: {claude_stderr}"
    );
}

// ---------------------------------------------------------------------------
// `pi -> claude` provisioning (the bridge's credential)
// ---------------------------------------------------------------------------

/// **V4.** A *real* credential a guest wrote into the project's persistent
/// `~/.claude/.credentials.json` is untouched by a `pi` launch on a host with
/// **no** Claude login. `pi` now provisions Anthropic, so capture is attempted
/// and fails; the content-scoped clearer must then leave the real bytes alone.
/// The unit half is `secrets::tests::the_stale_clearer_spares_a_guest_authored_credential`;
/// this drives the same property through the real binary.
#[test]
fn a_pi_launch_spares_a_guest_authored_claude_credential() {
    let harness = Harness::new();
    // No host Claude login. Deleting the seed must be checked: a
    // silently-failed removal would let this pass on a host that has one.
    let host_credential = harness.home_root.join(".claude/.credentials.json");
    std::fs::remove_file(&host_credential).unwrap();
    assert!(
        !host_credential.exists(),
        "the host credential must be gone"
    );

    let state = probe_state_dir(&harness, "pi");
    let guest_credential = r#"{"claudeAiOauth":{"accessToken":"sk-ant-guest-real-canary"}}"#;
    write(&state.join("claude/.credentials.json"), guest_credential);

    let out = harness.launch_default("pi");
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(CONFIG_MARKER),
        "pi must still launch with no host credential: {stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(state.join("claude/.credentials.json")).unwrap(),
        guest_credential,
        "a guest-authored Claude credential must survive a pi launch"
    );
}

/// **V7.** The one inherited side effect with real user impact and no direct
/// test: when capture *succeeds* (the host has a Claude credential),
/// `refresh_anthropic` **overwrites** a guest-authored
/// `~/.claude/.credentials.json` with the placeholder -- so a user who logged
/// Claude Code in inside the guest, then acquires a host credential, silently
/// switches to the host one. `pi` now provisions Anthropic, so this is true of a
/// `pi` launch too. (V4 above is the converse: capture *fails*, and the
/// content-scoped clearer spares the same file.)
#[test]
fn a_pi_launch_overwrites_a_guest_authored_claude_credential_with_the_placeholder() {
    let harness = Harness::new();
    // The harness ships a usable host Claude credential; assert it, because a
    // missing one would make capture fail and this test pass vacuously.
    assert!(
        harness.home_root.join(".claude/.credentials.json").exists(),
        "this test needs the harness's host Claude credential"
    );

    let state = probe_state_dir(&harness, "pi");
    let guest_credential = r#"{"claudeAiOauth":{"accessToken":"sk-ant-guest-real-canary"}}"#;
    write(&state.join("claude/.credentials.json"), guest_credential);

    let out = harness.launch_default("pi");
    let stderr = stderr_of(&out);
    assert!(stderr.contains(CONFIG_MARKER), "pi must launch: {stderr}");

    let after = std::fs::read_to_string(state.join("claude/.credentials.json")).unwrap();
    assert!(
        after.contains(GUEST_PLACEHOLDER),
        "a pi launch must overwrite a guest-authored credential with the proxy placeholder: {after}"
    );
    assert!(
        !after.contains("sk-ant-guest-real-canary"),
        "the guest-authored credential must be gone after capture: {after}"
    );
}

/// **V5.** The stale-placeholder ordering: before this change a `shell`-
/// written Anthropic placeholder was deleted by the next launch that did not
/// wire Anthropic (`clear_unwired_placeholders`), and `pi` was such a launch.
/// `pi` now re-wires Anthropic, so the placeholder survives.
#[test]
fn a_shell_placeholder_survives_the_next_pi_launch() {
    let harness = Harness::new();
    let shell = harness.launch_default("shell");
    let state = state_dir(&stderr_of(&shell));
    let placeholder = std::fs::read(state.join("claude/.credentials.json"))
        .expect("the shell launch writes the Anthropic placeholder");
    assert!(
        String::from_utf8_lossy(&placeholder).contains("msb-anthropic-placeholder"),
        "expected the proxy placeholder, got: {placeholder:?}"
    );

    let pi = harness.launch_default("pi");
    assert!(
        stderr_of(&pi).contains(CONFIG_MARKER),
        "pi must launch: {}",
        stderr_of(&pi)
    );
    assert_eq!(
        std::fs::read(state.join("claude/.credentials.json"))
            .expect("a pi launch must not delete the placeholder it re-wires"),
        placeholder,
        "a pi launch must leave the shell-written placeholder in place"
    );
}

/// **V6.** An inherited side effect of naming `claude`: `write_bypass_configs`
/// follows the **provisioning set**, not capture, so a `pi` launch now writes
/// the Anthropic onboarding/permission bypass files even on a host with no
/// Claude login. The shared golden `snapshot()` deliberately does not list
/// them (widening it would churn all seven goldens), so record the behaviour
/// here rather than leaving it silent. They hold no credential bytes.
#[test]
fn a_pi_launch_writes_the_anthropic_bypass_configs_without_a_host_credential() {
    let harness = Harness::new();
    std::fs::remove_file(harness.home_root.join(".claude/.credentials.json")).unwrap();

    let out = harness.launch_default("pi");
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(CONFIG_MARKER),
        "pi must still launch: {stderr}"
    );
    let state = state_dir(&stderr);

    let settings_text = std::fs::read_to_string(state.join("claude/settings.json"))
        .expect("a pi launch writes claude/settings.json even without capture");
    let settings: serde_json::Value = serde_json::from_str(&settings_text).unwrap();
    assert_eq!(settings["hasCompletedOnboarding"], serde_json::json!(true));

    let root_text = std::fs::read_to_string(state.join("claude.json"))
        .expect("a pi launch writes claude.json even without capture");
    let root: serde_json::Value = serde_json::from_str(&root_text).unwrap();
    assert_eq!(root["hasCompletedOnboarding"], serde_json::json!(true));
    assert_eq!(
        root["bypassPermissionsModeAccepted"],
        serde_json::json!(true)
    );
    // The bypass files carry onboarding/permission state only -- never a
    // credential. The harness's host credential is the sentinel `fake`, so a
    // leak would be visible here.
    assert!(!settings_text.contains("fake"), "{settings_text}");
    assert!(!root_text.contains("fake"), "{root_text}");
}

// ---------------------------------------------------------------------------
// Q1 (#96) — the migration must never follow a guest-planted HOME ancestor
// ---------------------------------------------------------------------------

/// Q1: a previous guest can leave `<state>/home` as a symlink to the host HOME.
/// Driving the *real* root-mode launch path (the mode where the HOME bind is
/// absent from `core_host_sources`, so the mount preflight cannot catch this)
/// must refuse at the migration instead of renaming the host's real `~/.pi`
/// into guest-visible state.
#[test]
fn root_launch_refuses_a_guest_planted_home_symlink() {
    let harness = Harness::new();

    // A first root-mode launch learns the exact state dir from the banner and
    // creates it, without provisioning `<state>/home` (root mode has no guest
    // HOME bind).
    let probe = harness.launch("pi", &["--root"]);
    let state = state_dir(&stderr_of(&probe));

    // The fake host HOME a previous guest pointed `<state>/home` at.
    let fake_host = tempfile::tempdir().unwrap();
    let fake_host = fake_host.path().canonicalize().unwrap();
    write(&fake_host.join(".pi/agent/auth.json"), "HOST-AUTH-SENTINEL");
    write(
        &fake_host.join(".pi/agent/models.json"),
        "HOST-MODELS-SENTINEL",
    );
    std::os::unix::fs::symlink(&fake_host, state.join("home")).unwrap();

    let attacked = harness.launch("pi", &["--root"]);
    let stderr = stderr_of(&attacked);
    assert!(
        !attacked.status.success(),
        "a guest-planted HOME symlink must fail the launch: {stderr}"
    );
    assert!(
        !stderr.contains(CONFIG_MARKER),
        "the refusal must happen before the debug-config/boot seam: {stderr}"
    );
    assert!(
        stderr.contains(&state.join("home").display().to_string()),
        "the refusal must name the redirected ancestor: {stderr}"
    );

    // The host home is unchanged and still in place.
    assert_eq!(
        std::fs::read(fake_host.join(".pi/agent/auth.json")).unwrap(),
        b"HOST-AUTH-SENTINEL"
    );
    assert_eq!(
        std::fs::read(fake_host.join(".pi/agent/models.json")).unwrap(),
        b"HOST-MODELS-SENTINEL"
    );
    assert!(fake_host.join(".pi").is_dir());
    assert_eq!(std::fs::read_link(state.join("home")).unwrap(), fake_host);
    // No sentinel entered guest state.
    assert!(!state.join("pi/agent/auth.json").exists());
    assert!(!state.join("pi/agent/models.json").exists());
}

/// Root-first upgrade rehearsal (verifications item 4): a pre-#96 real
/// `<state>/home/.pi` is moved by a `--root` launch, and a later non-root
/// launch finds the same bytes and materializes the compiled link.
#[test]
fn root_first_upgrade_moves_the_legacy_pi_home() {
    let harness = Harness::new();

    let probe = harness.launch("pi", &["--root"]);
    let state = state_dir(&stderr_of(&probe));

    // A pre-#96 non-root guest left a real `.pi` directory in the persistent
    // guest HOME.
    let legacy = state.join("home/.pi/agent");
    std::fs::create_dir_all(&legacy).unwrap();
    std::fs::write(legacy.join("auth.json"), b"pre-96-sentinel").unwrap();

    // A root-mode launch must move it (and bake `/root/.pi`), even though root
    // mode never wrote the host-side directory itself.
    let root_out = harness.launch("pi", &["--root"]);
    let root_stderr = stderr_of(&root_out);
    assert!(
        root_stderr.contains(CONFIG_MARKER),
        "the root launch must reach the debug dump: {root_stderr}"
    );
    assert_eq!(
        std::fs::read(state.join("pi/agent/auth.json")).unwrap(),
        b"pre-96-sentinel"
    );
    assert!(!state.join("home/.pi").exists());
    let root_config = normalized_config(&harness, &root_out).to_string();
    assert!(
        root_config.contains("/agent-vm-state/pi"),
        "the root launch must bake /root/.pi -> /agent-vm-state/pi: {root_config}"
    );

    // An independent, later non-root launch migrates nothing new and
    // materializes the compiled link over the same bytes.
    let nonroot_out = harness.launch_default("pi");
    assert!(
        stderr_of(&nonroot_out).contains(CONFIG_MARKER),
        "the non-root launch must reach the debug dump: {}",
        stderr_of(&nonroot_out)
    );
    assert_eq!(
        std::fs::read_link(state.join("home/.pi")).unwrap(),
        PathBuf::from("/agent-vm-state/pi")
    );
    assert_eq!(
        std::fs::read(state.join("pi/agent/auth.json")).unwrap(),
        b"pre-96-sentinel"
    );
}

/// Non-root-first upgrade rehearsal (#96 verification pass). Unlike
/// [`root_first_upgrade_moves_the_legacy_pi_home`], which only reaches the
/// non-root launch path *after* a root launch already migrated, this drives a
/// real non-root launch as the first migrator: it owns the persistent
/// `<state>/home`, so it is the mode the migration exists for. The unit tests
/// call `migrate_legacy_pi_home` directly; this proves the launch path wires it
/// before `<state>/home/.pi` provisioning, which would otherwise abort on the
/// real directory `force_symlink` refuses to replace.
#[test]
fn nonroot_first_upgrade_moves_the_legacy_pi_home() {
    let harness = Harness::new();

    // A first non-root launch materializes `<state>/home` and the compiled
    // `.pi` symlink (provisioning runs before the bogus-image pull fails).
    let probe = harness.launch_default("pi");
    let state = state_dir(&stderr_of(&probe));
    assert_eq!(
        std::fs::read_link(state.join("home/.pi")).unwrap(),
        PathBuf::from("/agent-vm-state/pi")
    );

    // Rewind to the pre-#96 shape: a real `<state>/home/.pi` directory holding
    // the bytes a previous guest left behind, as it would be before the first
    // launch on the new version.
    std::fs::remove_file(state.join("home/.pi")).unwrap();
    let legacy = state.join("home/.pi/agent");
    std::fs::create_dir_all(&legacy).unwrap();
    std::fs::write(legacy.join("auth.json"), b"nonroot-pre-96").unwrap();

    // The next non-root launch must move the directory and re-provision the
    // compiled link over it, without aborting on the real directory.
    let migrated = harness.launch_default("pi");
    let stderr = stderr_of(&migrated);
    assert!(
        stderr.contains(CONFIG_MARKER),
        "the non-root launch must reach the debug dump: {stderr}"
    );
    assert_eq!(
        std::fs::read_link(state.join("home/.pi")).unwrap(),
        PathBuf::from("/agent-vm-state/pi")
    );
    assert_eq!(
        std::fs::read(state.join("pi/agent/auth.json")).unwrap(),
        b"nonroot-pre-96"
    );
}

// ---------------------------------------------------------------------------
// E5–E8 — the broken-config behaviour table (plan D1)
// ---------------------------------------------------------------------------

const BROKEN: &str = "this is not = = toml\n";

#[test]
fn a_broken_config_fails_a_launch_with_the_config_error() {
    let harness = Harness::new();
    harness.write_project(BROKEN);

    let out = harness.launch_default("claude");
    assert!(
        !out.status.success(),
        "a broken config must fail the launch"
    );
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("config:"),
        "the config error must be reported: {stderr}"
    );
    assert!(
        !stderr.contains("unrecognized subcommand"),
        "a broken config must never degrade into clap's unrecognized-subcommand: {stderr}"
    );
    assert!(
        !stderr.contains(CONFIG_MARKER),
        "the launch must not proceed past a broken config: {stderr}"
    );
}

#[test]
fn a_broken_config_still_renders_every_doctor_section() {
    let harness = Harness::new();
    harness.write_project(BROKEN);

    let out = harness.base_command().arg("doctor").output().unwrap();
    assert!(!out.status.success(), "doctor must exit nonzero");
    let stdout = stdout_of(&out);
    for heading in [
        "==> active microsandbox home",
        "==> host agent credentials",
        "==> tool configuration",
        "==> agent-vm doctor: available operations",
    ] {
        assert!(stdout.contains(heading), "missing {heading}: {stdout}");
    }
    assert!(
        stdout.contains("error: config:"),
        "the config section must render the failure: {stdout}"
    );
}

#[test]
fn clipboard_help_ignores_a_broken_project_config() {
    // `clipboard` runs *inside* the guest, where a project config exists and a
    // `?` on the config result would brick the command.
    let harness = Harness::new();
    harness.write_project(BROKEN);

    let out = harness
        .base_command()
        .args(["clipboard", "--help"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "clipboard --help must succeed despite a broken project config; stderr: {}",
        stderr_of(&out)
    );
}

#[test]
fn top_level_help_with_a_broken_config_exits_zero_on_stdout() {
    let harness = Harness::new();
    harness.write_project(BROKEN);

    let out = harness.base_command().arg("--help").output().unwrap();
    assert!(
        out.status.success(),
        "--help must exit 0; stderr: {}",
        stderr_of(&out)
    );
    let stdout = stdout_of(&out);
    assert!(
        stdout.contains("setup") && stdout.contains("doctor"),
        "the built-ins must still be listed: {stdout}"
    );
    assert!(
        stdout.contains("could not be read") && stdout.contains("agent-vm doctor"),
        "the help must note the broken config and point at doctor: {stdout}"
    );
    assert!(
        !stderr_of(&out).contains("could not be read"),
        "help must not be on stderr: {}",
        stderr_of(&out)
    );
}

#[test]
fn a_misspelled_builtin_under_a_broken_config_reports_the_config_error_with_a_doctor_hint() {
    let harness = Harness::new();
    harness.write_project(BROKEN);

    let out = harness.base_command().arg("doctro").output().unwrap();
    assert!(!out.status.success(), "`doctro` must fail");
    let stderr = stderr_of(&out);
    // Issue #82's acceptance criterion: the config error is the primary
    // message, never clap's "unrecognized subcommand". The did-you-mean is
    // appended as a hint after the real error.
    assert!(
        stderr.contains("config:"),
        "the config error must be reported: {stderr}"
    );
    assert!(
        stderr.contains("tip: a similar subcommand exists: 'doctor'"),
        "the did-you-mean hint must name `doctor`: {stderr}"
    );
    assert!(
        !stderr.contains("unrecognized subcommand"),
        "a broken config must never degrade into unrecognized-subcommand: {stderr}"
    );
}

/// A plausible *tool* name within edit distance 2 of a built-in (`docker` /
/// `doctor`, `mcp` / `msb`) is exactly the case issue #82 forbids: the config
/// error must stay primary. Before the fix, `agent-vm docker` under a broken
/// config printed clap's "unrecognized subcommand 'docker'" and even suggested
/// "did you mean doctor?".
#[test]
fn a_tool_like_verb_under_a_broken_config_reports_the_config_error() {
    let harness = Harness::new();
    harness.write_project(BROKEN);

    for verb in ["docker", "mcp", "vector", "web"] {
        let out = harness.base_command().arg(verb).output().unwrap();
        assert!(!out.status.success(), "`{verb}` must fail");
        let stderr = stderr_of(&out);
        assert!(stderr.contains("config:"), "{verb}: {stderr}");
        assert!(
            !stderr.contains("unrecognized subcommand"),
            "{verb} must not degrade into unrecognized-subcommand: {stderr}"
        );
    }
}

/// clap's synthesized `help <verb>` validates its positional before
/// `parse_from`'s dispatch, so on the broken path it must still report the
/// config error (issue #82's acceptance criterion) rather than "unrecognized
/// subcommand".
#[test]
fn help_for_a_launch_verb_under_a_broken_config_reports_the_config_error() {
    let harness = Harness::new();
    harness.write_project(BROKEN);

    let out = harness
        .base_command()
        .args(["help", "claude"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "`help claude` must fail");
    let stderr = stderr_of(&out);
    assert!(stderr.contains("config:"), "{stderr}");
    assert!(
        !stderr.contains("unrecognized subcommand"),
        "`help <verb>` must not degrade into unrecognized-subcommand: {stderr}"
    );
}

/// `help` with no argument is not a failure: it prints the top-level help on
/// stdout and exits 0, even with a broken config.
#[test]
fn help_with_no_argument_still_prints_help_and_exits_zero() {
    let harness = Harness::new();
    harness.write_project(BROKEN);

    let out = harness.base_command().arg("help").output().unwrap();
    assert!(
        out.status.success(),
        "bare `help` must exit 0; stderr: {}",
        stderr_of(&out)
    );
    let stdout = stdout_of(&out);
    assert!(stdout.contains("Usage: agent-vm"), "{stdout}");
    assert!(stdout.contains("doctor"), "{stdout}");
    assert!(stderr_of(&out).is_empty(), "{}", stderr_of(&out));
}

// ---------------------------------------------------------------------------
// Verification-phase additions (issue #82): cases first probed by hand
// against the real binary, then promoted to boot-free integration tests so a
// regression fails here rather than at a manual step.
// ---------------------------------------------------------------------------

/// The acceptance criterion "`agent-vm shell` works with an empty `tools`
/// list". A config that exists but declares no tools falls back to the
/// compiled-in defaults — `shell` among them — and the launch reaches the
/// debug dumps as usual. T4c/T4d pin the resolved catalog; this pins the
/// whole CLI/launch path.
#[test]
fn an_empty_tools_list_still_registers_and_launches_shell() {
    let harness = Harness::new();
    harness.write_project("tools = []\n");

    let help = harness.base_command().arg("--help").output().unwrap();
    assert!(
        help.status.success(),
        "--help must succeed; stderr: {}",
        stderr_of(&help)
    );
    let help_text = stdout_of(&help);
    for tool in DEFAULT_TOOLS {
        assert!(
            help_text.contains(tool),
            "`{tool}` must be registered from the built-in defaults: {help_text}"
        );
    }

    let out = harness.launch_default("shell");
    assert!(
        stderr_of(&out).contains(CONFIG_MARKER),
        "the fallback shell must launch with an empty tools list: {}",
        stderr_of(&out)
    );
}

/// A broken **user-tier** config behaves exactly like a broken project one:
/// the launch reports the config error (never clap's unrecognized-subcommand),
/// while `--help` and `doctor` still work. E5/E7 cover the project tier; this
/// pins the user tier, which the harness can break independently.
#[test]
fn a_broken_user_config_fails_a_launch_and_still_allows_help_and_doctor() {
    let harness = Harness::new();
    harness.write_user(BROKEN);

    let launch = harness.launch_default("claude");
    assert!(
        !launch.status.success(),
        "a broken user config must fail a launch"
    );
    let launch_err = stderr_of(&launch);
    assert!(
        launch_err.contains("config:"),
        "the config error must be reported: {launch_err}"
    );
    assert!(
        !launch_err.contains("unrecognized subcommand"),
        "a broken config must never degrade into unrecognized-subcommand: {launch_err}"
    );

    let help = harness.base_command().arg("--help").output().unwrap();
    assert!(
        help.status.success(),
        "--help must still exit 0; stderr: {}",
        stderr_of(&help)
    );
    assert!(
        stdout_of(&help).contains("could not be read"),
        "the help must note the broken config: {}",
        stdout_of(&help)
    );

    let doctor = harness.base_command().arg("doctor").output().unwrap();
    assert!(!doctor.status.success(), "doctor must exit nonzero");
    assert!(
        stdout_of(&doctor).contains("error: config:"),
        "doctor must render the config failure: {}",
        stdout_of(&doctor)
    );
}

/// The interactive-shell `-c` join, observed end to end and boot-free: the
/// `[debug] guest command:` line for a launch verb with trailing args is
/// exactly what `run::inner_argv` produces, with each user arg shell-escaped
/// so quoting survives the `bash -c` boundary. `run::tests` pins the pure
/// function; this pins the wiring that emits it for a real invocation.
#[test]
fn shell_user_args_are_joined_and_escaped_in_the_guest_command_line() {
    let harness = Harness::new();
    let out = harness.launch("shell", &["--", "a b", "c'd"]);

    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(CONFIG_MARKER),
        "shell did not reach the debug stage: {stderr}"
    );
    assert_eq!(
        debug_guest_command(&stderr),
        r#"bash -O histappend -c 'a b' 'c'\''d'"#,
        "the interactive-shell join must shell-escape each arg\nstderr:\n{stderr}"
    );
}

// ---------------------------------------------------------------------------
// #118 — the provisioning set gates every provider-owned facet
// ---------------------------------------------------------------------------

/// The `MSB_AGENT_VM_*` secret env vars registered in a dumped `SandboxConfig`.
fn registered_secret_env_vars(config: &serde_json::Value) -> Vec<&str> {
    config["network"]["secrets"]["secrets"]
        .as_array()
        .map(|secrets| {
            secrets
                .iter()
                .map(|secret| secret["env_var"].as_str().unwrap())
                .collect()
        })
        .unwrap_or_default()
}

fn read_json(path: &Path) -> Option<serde_json::Value> {
    std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
}

/// Assert no regular file under `root` contains `needle` (a value canary).
/// Files are read as lossy UTF-8 so a binary blob (a sqlite DB, a JWT-shaped
/// placeholder) never panics the scan.
fn assert_no_file_contains(root: &Path, needle: &str) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let file_type = entry.file_type().unwrap();
        if file_type.is_dir() {
            assert_no_file_contains(&path, needle);
        } else if file_type.is_file() {
            let bytes = std::fs::read(&path).unwrap();
            assert!(
                !String::from_utf8_lossy(&bytes).contains(needle),
                "canary {needle:?} leaked into {}",
                path.display()
            );
        }
    }
}

/// **The #118 acceptance criterion.** A `codex` guest holds no Anthropic
/// capability: no host secret, no intercept rule, no guest placeholder — while
/// the `.claude` symlink is deliberately still there (furniture is not a
/// capability; narrowing it would collide with a real `~/.claude` next launch).
#[test]
fn a_codex_launch_provisions_openai_only() {
    let harness = Harness::new();
    let out = harness.launch_default("codex");
    let stderr = stderr_of(&out);
    let config = debug_config_json(&stderr);
    let state = state_dir(&stderr);

    assert!(
        !registered_secret_env_vars(&config).contains(&"MSB_AGENT_VM_ANTHROPIC_UNUSED"),
        "a codex launch must not register the Anthropic secret"
    );
    let rules = config["network"]["intercept"]["rules"].as_array().unwrap();
    assert!(
        rules
            .iter()
            .all(|rule| rule["host"].as_str() != Some("platform.claude.com")),
        "a codex launch must not register an Anthropic intercept route"
    );
    assert!(
        !state.join("claude/.credentials.json").exists(),
        "a codex launch must not write the Claude placeholder"
    );
    let host_secrets = PathBuf::from(format!("{}.secrets", state.display()));
    assert!(
        !host_secrets.join("anthropic").exists(),
        "the host's Anthropic token must never be captured for codex"
    );
    // Furniture stays: the `.claude` symlink is unconditional.
    assert!(
        std::fs::symlink_metadata(state.join("home/.claude"))
            .unwrap()
            .file_type()
            .is_symlink(),
        "the `.claude` guest-HOME link must remain (furniture is not a capability)"
    );
}

/// A `shell` guest gets all four, and Copilot is *working*: substitution entry,
/// placeholder config and env var all present together.
#[test]
fn a_shell_launch_provisions_all_four_with_a_working_copilot() {
    let harness = Harness::new();
    let out = harness.launch_default("shell");
    let stderr = stderr_of(&out);
    let config = debug_config_json(&stderr);
    let state = state_dir(&stderr);

    let env_vars = registered_secret_env_vars(&config);
    for expected in [
        "MSB_AGENT_VM_ANTHROPIC_UNUSED",
        "MSB_AGENT_VM_OPENAI_UNUSED",
        "MSB_AGENT_VM_OPENCODE_OPENAI_UNUSED",
        "MSB_AGENT_VM_COPILOT_UNUSED",
    ] {
        assert!(
            env_vars.contains(&expected),
            "shell missing {expected}: {env_vars:?}"
        );
    }
    let env = env_pairs(&config);
    assert_eq!(
        env.iter()
            .find(|(key, _)| *key == "COPILOT_GITHUB_TOKEN")
            .map(|(_, value)| *value),
        Some("msb-copilot-placeholder-v2")
    );
    let copilot = read_json(&state.join("copilot/config.json")).expect("copilot config present");
    assert_eq!(copilot["github_token"], "msb-copilot-placeholder-v2");
}

/// Placeholder ⇒ substitution entry, for every default verb. The general form
/// of the two above, so a future provider cannot be added without it.
#[test]
fn no_default_verb_provisions_a_placeholder_without_its_substitution_entry() {
    for tool in DEFAULT_TOOLS {
        let harness = Harness::new();
        let out = harness.launch_default(tool);
        let stderr = stderr_of(&out);
        let config = debug_config_json(&stderr);
        let state = state_dir(&stderr);
        let registered = registered_secret_env_vars(&config);
        let placeholder_requires_its_entry = [
            (
                state.join("claude/.credentials.json").exists(),
                "MSB_AGENT_VM_ANTHROPIC_UNUSED",
                "claude/.credentials.json",
            ),
            (
                state.join("codex/auth.json").exists(),
                "MSB_AGENT_VM_OPENAI_UNUSED",
                "codex/auth.json",
            ),
            (
                read_json(&state.join("copilot/config.json"))
                    .and_then(|value| value.get("github_token").cloned())
                    .is_some(),
                "MSB_AGENT_VM_COPILOT_UNUSED",
                "copilot/config.json",
            ),
            (
                read_json(&state.join("opencode/auth.json"))
                    .and_then(|value| value.get("openai").cloned())
                    .is_some(),
                "MSB_AGENT_VM_OPENCODE_OPENAI_UNUSED",
                "opencode/auth.json",
            ),
        ];
        for (placeholder_present, entry, file) in placeholder_requires_its_entry {
            assert_eq!(
                placeholder_present,
                registered.contains(&entry),
                "for {tool}: a placeholder in {file} must exist iff {entry} is registered",
            );
        }
    }
}

/// A failed Copilot capture on a `shell` launch removes the stale placeholder a
/// previous `copilot` launch left behind (the exact scenario the criterion
/// names). Both launches share one state dir.
#[test]
fn a_failed_copilot_capture_clears_the_stale_shell_placeholder() {
    let harness = Harness::new();

    // (a) A successful copilot launch writes the placeholder config.
    let first = harness.launch_default("copilot");
    let state = state_dir(&stderr_of(&first));
    let copilot = read_json(&state.join("copilot/config.json")).expect("copilot config written");
    assert_eq!(copilot["github_token"], "msb-copilot-placeholder-v2");

    // (b) Remove the device-flow cache so the next capture fails.
    std::fs::remove_file(
        harness
            .home_root
            .join(".cache/claude-vm/copilot-token.json"),
    )
    .unwrap();

    // (c) A shell launch provisions Copilot but cannot capture it.
    let second = harness.launch_default("shell");
    let stderr = stderr_of(&second);
    assert!(
        stderr.contains(CONFIG_MARKER),
        "the shell launch must not bail on a failed, non-required Copilot capture: {stderr}"
    );
    let config = debug_config_json(&stderr);
    assert!(
        !registered_secret_env_vars(&config).contains(&"MSB_AGENT_VM_COPILOT_UNUSED"),
        "no substitution entry was registered, so no secret may be"
    );
    let env = env_pairs(&config);
    assert!(
        !env.iter().any(|(key, _)| *key == "COPILOT_GITHUB_TOKEN"),
        "an unsubstituted placeholder bearer must not be exported"
    );
    let copilot = read_json(&state.join("copilot/config.json")).unwrap();
    assert!(
        copilot.get("github_token").is_none(),
        "the stale placeholder must be cleared: {copilot}"
    );
}

/// A dangling `tools` reference is reported as a config error by a launch verb
/// while `doctor` still renders every section (a deferred config failure).
#[test]
fn a_dangling_tools_reference_fails_a_launch_but_not_doctor() {
    let harness = Harness::new();
    harness.write_project("[[tools]]\nname = \"t\"\ncommand = \"/bin/echo\"\ntools = [\"nope\"]\n");

    let launch = harness.launch_default("t");
    assert!(
        !launch.status.success(),
        "a dangling reference must fail the launch"
    );
    let launch_err = stderr_of(&launch);
    assert!(launch_err.contains("config:"), "{launch_err}");
    assert!(
        launch_err.contains("names no tool in the resolved catalog"),
        "{launch_err}"
    );
    assert!(
        !launch_err.contains("unrecognized subcommand"),
        "it must not degrade into clap's unrecognized-subcommand: {launch_err}"
    );
    assert!(!launch_err.contains(CONFIG_MARKER), "{launch_err}");

    let doctor = harness.base_command().arg("doctor").output().unwrap();
    assert!(!doctor.status.success(), "doctor must exit nonzero");
    let stdout = stdout_of(&doctor);
    for heading in [
        "==> active microsandbox home",
        "==> host agent credentials",
        "==> tool configuration",
        "==> agent-vm doctor: available operations",
    ] {
        assert!(stdout.contains(heading), "missing {heading}: {stdout}");
    }
    assert!(
        stdout.contains("names no tool in the resolved catalog"),
        "the config section must render the failure: {stdout}"
    );
}

/// A declared `shell` that opts out (`tools = []`) provisions nothing, and the
/// launch still boots — with **no TLS overlay**, because `apply_to` returns the
/// builder untouched when `secrets` is empty. The shape is newly reachable.
#[test]
fn a_zero_provisioning_launch_boots_with_no_tls_overlay() {
    let harness = Harness::new();
    harness.write_project(
        "[[tools]]\nname = \"shell\"\ncommand = \"bash\"\ninteractive_shell = true\ntools = []\n",
    );
    let out = harness.launch_default("shell");
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(CONFIG_MARKER),
        "a zero-provisioning launch must still boot: {stderr}"
    );
    let config = debug_config_json(&stderr);
    assert!(
        registered_secret_env_vars(&config).is_empty(),
        "no provider is provisioned"
    );
    let tls_enabled = config["network"]["tls"]["enabled"]
        .as_bool()
        .unwrap_or(false);
    assert!(
        !tls_enabled,
        "no TLS overlay when there is nothing to substitute"
    );
    let intercept = &config["network"]["intercept"];
    if !intercept.is_null() {
        assert!(
            intercept["rules"].as_array().unwrap().is_empty(),
            "`.intercept()` must not run: {intercept}"
        );
    }
    // A zero-provisioning launch never calls `.network()` at all
    // (`credential_injection::Plan::apply_to` early-returns, and `network::Plan`
    // has no egress policy to apply here), so the dumped spec carries **no**
    // `policy` subdocument. Pin that observed shape too, so a future change that
    // starts emitting a policy here is noticed rather than silently absorbed.
    assert!(
        config["network"].get("policy").is_none(),
        "a zero-provisioning launch carries no explicit policy"
    );
    // "No explicit policy" is not an *open* policy, but it is not a narrower
    // egress either: the engine materializes an unset policy as
    // `NetworkPolicy::default()` — `default_egress: deny` plus the public-profile
    // allow — which is exactly what a wired launch's `.network()` overlay
    // materializes (ADR-0017). A zero-provisioning launch is therefore exactly
    // as open as a wired one. Compare the *whole* materialized policy (via its
    // serialized form, since `NetworkPolicy` has no `PartialEq`) so a rule-level
    // relaxation — an added allow, a flipped `default_ingress` — is caught, not
    // just the default action.
    let materialized: microsandbox_network::config::NetworkConfig =
        serde_json::from_value(config["network"].clone())
            .expect("the engine accepts a spec with no policy subdocument");
    let wired_default = microsandbox_network::config::NetworkConfig::default();
    assert_eq!(
        serde_json::to_value(&materialized.policy).unwrap(),
        serde_json::to_value(&wired_default.policy).unwrap(),
        "a zero-provisioning launch materializes the same default policy as a wired launch"
    );
}

/// Under a **custom** catalog the fallback `shell` provisions **nothing** — the
/// old always-on capture must not come back as a "fix" for a failing
/// user-config test.
#[test]
fn a_fallback_shell_under_a_custom_catalog_provisions_nothing() {
    let harness = Harness::new();
    harness.write_user("[[tools]]\nname = \"solo\"\ncommand = \"/bin/echo\"\n");
    let out = harness.launch_default("shell");
    let stderr = stderr_of(&out);
    assert!(stderr.contains(CONFIG_MARKER), "{stderr}");
    let config = debug_config_json(&stderr);
    let env_vars = registered_secret_env_vars(&config);
    assert!(
        !env_vars.contains(&"MSB_AGENT_VM_ANTHROPIC_UNUSED")
            && !env_vars.contains(&"MSB_AGENT_VM_OPENAI_UNUSED"),
        "the built-in fallback shell closes over its own file only: {env_vars:?}"
    );
    let state = state_dir(&stderr);
    assert!(!state.join("claude/.credentials.json").exists());
    let host_secrets = PathBuf::from(format!("{}.secrets", state.display()));
    assert!(!host_secrets.join("anthropic").exists());
}

/// **The other half of "a guest cannot spend a credential its verb did not
/// provision."** The pre-#118 leak was a substitution entry the verb never
/// declared; this pins the floor beneath it — the host's real tokens live in
/// the `<state>.secrets` *sibling*, which is never bind-mounted, so a
/// non-provisioned provider is not merely unsubstitutable, it is unreadable.
/// A `shell` launch captures all three, which keeps the "no such mount"
/// assertion load-bearing instead of vacuous.
#[test]
fn host_credentials_are_never_bind_mounted_into_the_guest() {
    let harness = Harness::new();
    let out = harness.launch_default("shell");
    let stderr = stderr_of(&out);
    let config = debug_config_json(&stderr);
    let state = state_dir(&stderr);
    let secrets = PathBuf::from(format!("{}.secrets", state.display()));

    for provider in ["anthropic", "openai", "copilot"] {
        assert!(
            secrets.join(provider).exists(),
            "a shell launch must capture the host {provider} token, else this test proves nothing"
        );
    }

    let mut mounted_hosts: Vec<&str> = Vec::new();
    for mount in config["mounts"].as_array().unwrap() {
        let host = mount["host"].as_str().unwrap();
        mounted_hosts.push(host);
        assert!(
            !Path::new(host).starts_with(&secrets),
            "the host secret dir must never be bind-mounted; got {host}"
        );
    }
    // The state dir itself *is* mounted (at `/agent-vm-state`); it holds
    // placeholders only. Anything else the guest sees is furniture.
    assert!(
        mounted_hosts
            .iter()
            .any(|host| *host == state.to_string_lossy()),
        "the state dir must be a mount source: {mounted_hosts:?}"
    );
}

/// Copilot is not repo-scoped, so `--no-git` (which suppresses *GitHub egress*)
/// must not suppress its capture: the device-flow cache is still read and
/// `COPILOT_GITHUB_TOKEN` is still exported. #118 moved Copilot's capture onto
/// the provisioning set and deleted the `WhenSelectedOrGithubEgress`
/// disjunction; this pins that `--no-git` stays orthogonal to it.
#[test]
fn copilot_is_captured_despite_no_git() {
    for tool in ["copilot", "shell"] {
        let harness = Harness::new();
        let out = harness.launch(tool, &["--no-git"]);
        let stderr = stderr_of(&out);
        let config = debug_config_json(&stderr);
        let env_vars = registered_secret_env_vars(&config);
        assert!(
            env_vars.contains(&"MSB_AGENT_VM_COPILOT_UNUSED"),
            "{tool} --no-git must still capture Copilot from the device-flow cache: {env_vars:?}"
        );
        assert_eq!(
            env_pairs(&config)
                .iter()
                .find(|(key, _)| *key == "COPILOT_GITHUB_TOKEN")
                .map(|(_, value)| *value),
            Some("msb-copilot-placeholder-v2"),
            "{tool} --no-git must still export COPILOT_GITHUB_TOKEN"
        );
    }
}

/// A **required** provider with no host credential fails loudly *before boot*;
/// a provider with no [`missing_credential_error`] degrades quietly. The bail
/// loop reads the tool's `credentials` (the requirement set), never its
/// provisioning set, so `codex` still launches — degraded — with no OpenAI
/// login, while `claude` refuses.
#[test]
fn a_missing_required_host_credential_bails_before_boot() {
    let harness = Harness::new();
    std::fs::remove_file(harness.home_root.join(".claude/.credentials.json")).unwrap();
    let out = harness.launch_default("claude");
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("no usable Claude credential found on the host"),
        "claude must hard-bail with the actionable message:\n{stderr}"
    );
    assert!(
        !stderr.contains(CONFIG_MARKER),
        "the bail must happen before the sandbox is built:\n{stderr}"
    );

    let harness = Harness::new();
    std::fs::remove_file(harness.home_root.join(".codex/auth.json")).unwrap();
    let out = harness.launch_default("codex");
    let stderr = stderr_of(&out);
    let config = debug_config_json(&stderr);
    assert!(
        registered_secret_env_vars(&config).is_empty(),
        "no OpenAI credential means nothing to register"
    );
    let state = state_dir(&stderr);
    assert!(
        !state.join("codex/auth.json").exists(),
        "a placeholder must not appear without its substitution entry"
    );
}

/// The broadest verb with **no** host credential at all: `shell` provisions all
/// four, requires none, so it boots with an empty wire and the placeholder
/// invariant holds at its zero-boundary.
#[test]
fn a_shell_launch_with_no_host_credentials_wires_nothing() {
    let harness = Harness::new();
    for relative in [
        ".claude/.credentials.json",
        ".codex/auth.json",
        ".cache/claude-vm/copilot-token.json",
    ] {
        std::fs::remove_file(harness.home_root.join(relative)).unwrap();
    }
    let out = harness.launch_default("shell");
    let stderr = stderr_of(&out);
    let config = debug_config_json(&stderr);
    assert!(
        registered_secret_env_vars(&config).is_empty(),
        "nothing was captured, so nothing may be registered"
    );
    assert!(
        !env_pairs(&config)
            .iter()
            .any(|(key, _)| *key == "COPILOT_GITHUB_TOKEN"),
        "an unwired Copilot must not export a placeholder bearer"
    );
    let state = state_dir(&stderr);
    // AC2: with *no* `credentials.yaml`, built-in behaviour is unchanged, so a
    // provisioned Copilot whose capture failed writes nothing — `copilot/
    // config.json` did not exist here before #162 and must not now. (A replaced
    // Copilot *does* get its non-secret `trusted_folders`; that case is covered
    // by the unit tests in `credential_provider.rs` / `secrets.rs`.)
    for rel in [
        "claude/.credentials.json",
        "codex/auth.json",
        "copilot/config.json",
    ] {
        assert!(!state.join(rel).exists(), "{rel} must not exist");
    }
    let secrets = PathBuf::from(format!("{}.secrets", state.display()));
    for provider in ["anthropic", "openai", "copilot"] {
        assert!(
            !secrets.join(provider).exists(),
            "{provider} must not be captured"
        );
    }
}

// ---------------------------------------------------------------------------
// #83 — per-tool persisted guest paths
// ---------------------------------------------------------------------------

/// A project tool that adds no credential provider, only `persist` paths — the
/// headline case from issue #83.
const AIDER_PERSIST: &str = "[[tools]]\nname = \"aider\"\ncommand = \"/bin/echo\"\n\
     credentials = []\npersist = [\".aider.conf.yml\", \".cache/aider\"]\n";

/// The same tool declared *without* `persist`, to land the state dir before the
/// migration case rewrites the config.
const AIDER_PLAIN: &str =
    "[[tools]]\nname = \"aider\"\ncommand = \"/bin/echo\"\ncredentials = []\n";

/// The eight compiled-in guest-HOME links, always provisioned.
const COMPILED_LINKS: [&str; 8] = [
    ".claude",
    ".claude.json",
    ".local/share/opencode",
    ".config/opencode",
    ".copilot",
    ".gitconfig",
    ".config/gh",
    ".bash_history",
];

/// **V10 (AC1, AC2).** A tool with no credential provider gets its `persist`
/// entries linked into the project state dir under the `persist/` namespace,
/// and the eight compiled links remain — additive, not replacing.
#[test]
fn a_declared_persist_tool_links_into_state_and_stays_additive() {
    let harness = Harness::new();
    harness.write_project(AIDER_PERSIST);

    let out = harness.launch("aider", &[]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(CONFIG_MARKER),
        "aider did not launch: {stderr}"
    );
    let state = state_dir(&stderr);
    let snap = snapshot(&state);

    assert_eq!(
        snap.get("link:.aider.conf.yml").map(String::as_str),
        Some("/agent-vm-state/persist/.aider.conf.yml")
    );
    assert_eq!(
        snap.get("link:.cache/aider").map(String::as_str),
        Some("/agent-vm-state/persist/.cache/aider")
    );
    assert!(
        state.join("persist/.cache").is_dir(),
        "the declared target's parent must exist"
    );
    for compiled in COMPILED_LINKS {
        assert!(
            snap.contains_key(&format!("link:{compiled}")),
            "the compiled link {compiled} must remain: {snap:?}"
        );
    }
}

/// **V11 (AC1).** In `--root` mode the same list is baked into the rootfs: the
/// declared links become `/root/...` symlink patches, a `/root/.cache` mkdir is
/// emitted for the ancestor, and the compiled symlink steps are unchanged.
#[test]
fn root_mode_bakes_declared_persist_links_into_the_rootfs() {
    let harness = Harness::new();
    harness.write_project(AIDER_PERSIST);

    let out = harness.launch("aider", &["--root"]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(CONFIG_MARKER),
        "aider --root did not launch: {stderr}"
    );
    let config = debug_config_json(&stderr);
    let patches = config["patches"].as_array().unwrap();

    let symlinks: Vec<(&str, &str)> = patches
        .iter()
        .filter_map(|patch| {
            patch.get("Symlink").map(|link| {
                (
                    link["target"].as_str().unwrap(),
                    link["link"].as_str().unwrap(),
                )
            })
        })
        .collect();
    let mkdirs: Vec<&str> = patches
        .iter()
        .filter_map(|patch| patch.get("Mkdir").and_then(|mkdir| mkdir["path"].as_str()))
        .collect();

    for expected in [
        (
            "/agent-vm-state/persist/.aider.conf.yml",
            "/root/.aider.conf.yml",
        ),
        ("/agent-vm-state/persist/.cache/aider", "/root/.cache/aider"),
        // A compiled link, unchanged.
        ("/agent-vm-state/claude", "/root/.claude"),
    ] {
        assert!(
            symlinks.contains(&expected),
            "missing {expected:?}: {symlinks:?}"
        );
    }
    assert!(
        mkdirs.contains(&"/root/.cache"),
        "missing /root/.cache: {mkdirs:?}"
    );
}

/// **V12 (AC2).** `persist` is additive with a tool's credential links: a tool
/// declaring `credentials = ["anthropic"]` and `persist = [".x"]` keeps
/// `.claude`/`.claude.json` without restating them.
#[test]
fn persist_is_additive_with_credential_links() {
    let harness = Harness::new();
    harness.write_project(
        "[[tools]]\nname = \"mytool\"\ncommand = \"/bin/echo\"\ncredentials = [\"anthropic\"]\npersist = [\".x\"]\n",
    );

    let out = harness.launch("mytool", &[]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(CONFIG_MARKER),
        "mytool did not launch: {stderr}"
    );
    let snap = snapshot(&state_dir(&stderr));
    assert!(snap.contains_key("link:.claude"), "{snap:?}");
    assert!(snap.contains_key("link:.claude.json"), "{snap:?}");
    assert_eq!(
        snap.get("link:.x").map(String::as_str),
        Some("/agent-vm-state/persist/.x")
    );
}

/// **V13 (AC4).** The link survives a second launch: after the guest writes the
/// real file through the link (simulated host-side), a relaunch neither errors
/// nor migrates it — the link still resolves to the persist namespace and the
/// content is intact. A survival-only assertion would pass with the feature
/// deleted, so this asserts the link target.
#[test]
fn a_declared_persist_link_survives_a_second_launch() {
    let harness = Harness::new();
    harness.write_project(AIDER_PERSIST);

    let first = harness.launch("aider", &[]);
    let state = state_dir(&stderr_of(&first));
    // The guest's `open(O_CREAT)` through the dangling link creates the real
    // file host-side; simulate it.
    std::fs::write(state.join("persist/.aider.conf.yml"), "guest wrote this").unwrap();

    let second = harness.launch("aider", &[]);
    assert!(
        stderr_of(&second).contains(CONFIG_MARKER),
        "second launch failed: {}",
        stderr_of(&second)
    );
    let link = state.join("home/.aider.conf.yml");
    assert_eq!(
        std::fs::read_link(&link).unwrap(),
        PathBuf::from("/agent-vm-state/persist/.aider.conf.yml"),
        "the link must still resolve to the persist namespace"
    );
    // The real file is host-side under the state dir, never overwritten or
    // migrated by the relaunch.
    assert_eq!(
        std::fs::read_to_string(state.join("persist/.aider.conf.yml")).unwrap(),
        "guest wrote this"
    );
}

/// **V13b (migration).** A real file already in the (persistent, non-root) guest
/// HOME is *moved* into the state dir the first time the tool declares it —
/// never deleted.
#[test]
fn a_pre_existing_home_file_is_migrated_into_the_persist_namespace() {
    let harness = Harness::new();
    harness.write_project(AIDER_PLAIN);
    let first = harness.launch("aider", &[]);
    let state = state_dir(&stderr_of(&first));

    std::fs::write(state.join("home/.aider.conf.yml"), "old home content").unwrap();

    harness.write_project(AIDER_PERSIST);
    let second = harness.launch("aider", &[]);
    assert!(
        stderr_of(&second).contains(CONFIG_MARKER),
        "second launch failed: {}",
        stderr_of(&second)
    );
    assert_eq!(
        std::fs::read_to_string(state.join("persist/.aider.conf.yml")).unwrap(),
        "old home content",
        "the pre-existing content must be moved, not deleted"
    );
    assert_eq!(
        std::fs::read_link(state.join("home/.aider.conf.yml")).unwrap(),
        PathBuf::from("/agent-vm-state/persist/.aider.conf.yml")
    );
}

/// **V13b (mount check).** A `persist` path that would be shadowed by a mount
/// under HOME is rejected before boot — no debug config dump, no provisioning.
#[test]
fn a_persist_path_shadowing_a_mount_under_home_is_rejected_before_boot() {
    let harness = Harness::new();
    harness.write_project(
        "[[tools]]\nname = \"aider\"\ncommand = \"/bin/echo\"\ncredentials = []\npersist = [\"code\"]\n",
    );
    // A `--mount` whose guest path is under the mirrored HOME and overlaps the
    // declared `code` path.
    let guest = format!("{}/code", harness.home_root.display());
    let mount = format!("{}:{guest}", harness.project_root.display());

    let out = harness.launch("aider", &["--mount", &mount]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("would collide with the guest mount point"),
        "expected the mount-shadowing rejection: {stderr}"
    );
    assert!(
        !stderr.contains(CONFIG_MARKER),
        "the launch must be rejected before boot: {stderr}"
    );
}

/// **Q1 guard, end to end.** A symlink the in-guest agent planted at an
/// ancestor of a declared `persist` path must be refused, not followed. The
/// non-root guest HOME is a bind mount the agent writes freely, so
/// `create_dir_all` through `~/.cache -> /etc` would redirect host-side
/// provisioning (and `link_declared_persist`'s `rename`) outside the state dir.
/// `session::create_dir_all_beneath` is the guard; this drives it through the
/// real binary.
#[test]
fn a_guest_planted_symlinked_ancestor_is_refused_before_boot() {
    let harness = Harness::new();
    // First launch mostly to materialize the per-project state dir (the
    // provisioning runs before the bogus-image pull fails). Only the file
    // entry, so `.cache` is *not* created as a real directory.
    harness.write_project(
        "[[tools]]\nname = \"aider\"\ncommand = \"/bin/echo\"\ncredentials = []\npersist = [\".aider.conf.yml\"]\n",
    );
    let first = harness.launch("aider", &[]);
    let state = state_dir(&stderr_of(&first));

    // The agent plants `~/.cache` as a symlink out of the state dir.
    let planted = harness.project_root.join("planted");
    std::fs::create_dir_all(&planted).unwrap();
    std::fs::create_dir_all(state.join("home")).unwrap();
    std::os::unix::fs::symlink(&planted, state.join("home/.cache")).unwrap();

    // The second launch declares `persist = [".cache/aider"]`, so provisioning
    // walks the planted `.cache` ancestor.
    harness.write_project(
        "[[tools]]\nname = \"aider\"\ncommand = \"/bin/echo\"\ncredentials = []\npersist = [\".cache/aider\"]\n",
    );
    let second = harness.launch("aider", &[]);
    let stderr = stderr_of(&second);
    assert!(stderr.contains("symlink"), "expected the refusal: {stderr}");
    assert!(
        !stderr.contains(CONFIG_MARKER),
        "must be refused before boot: {stderr}"
    );
    assert!(
        std::fs::read_dir(&planted).unwrap().next().is_none(),
        "provisioning followed the planted symlink"
    );
}

// ---------------------------------------------------------------------------
// #93 — every launch reports guest-managed Pi credentials, read-only
// ---------------------------------------------------------------------------

/// The fixed launch warning header, and the exact placeholder constant the
/// built-in `pi`/`claude` provisioners write (`secrets.rs`).
const PI_WARN_HEADER: &str = "==> WARNING: potentially sensitive guest-managed Pi credentials";
const GUEST_PLACEHOLDER: &str = "msb-anthropic-placeholder-a-v2";

/// Seed the project-scoped guest Pi `auth.json` (and optionally `models.json`).
fn seed_pi(state_dir: &Path, auth: &str, models: Option<&str>) {
    let agent = state_dir.join("pi/agent");
    std::fs::create_dir_all(&agent).unwrap();
    std::fs::write(agent.join("auth.json"), auth).unwrap();
    if let Some(models) = models {
        std::fs::write(agent.join("models.json"), models).unwrap();
    }
}

/// Learn the project state dir from a launch banner. The banner is emitted
/// before the scan, so a probe with no seeded Pi state is also a quiet control.
fn probe_state_dir(harness: &Harness, tool: &str) -> PathBuf {
    let probe = harness.launch_default(tool);
    let stderr = stderr_of(&probe);
    assert!(
        !stderr.contains(PI_WARN_HEADER),
        "unseeded state must be quiet:\n{stderr}"
    );
    state_dir(&stderr)
}

/// V4: one shared `run::launch` hook covers every tool and both guest modes.
/// The warning must be emitted **before** the image build/host resolution, so
/// the inspection is reached even when the launch later fails on the bogus
/// image (this is not "assert nonzero and hope").
#[test]
fn every_launch_warns_on_guest_managed_pi_credentials() {
    let harness = Harness::new();
    let state = probe_state_dir(&harness, "shell");
    seed_pi(
        &state,
        r#"{"anthropic":{"type":"api_key","key":"guest-managed"}}"#,
        None,
    );

    for tool in DEFAULT_TOOLS {
        let out = harness.launch_default(tool);
        let stderr = stderr_of(&out);
        assert!(
            stderr.contains(PI_WARN_HEADER),
            "{tool} must warn:\n{stderr}"
        );
        assert!(
            stderr.contains("auth.json: provider=anthropic type=api_key fields=key"),
            "{tool} must name the field:\n{stderr}"
        );
        let warn_at = stderr.find(PI_WARN_HEADER).expect("warning");
        let build_at = stderr
            .find(CONFIG_MARKER)
            .unwrap_or_else(|| panic!("{tool} never reached the build seam:\n{stderr}"));
        assert!(
            warn_at < build_at,
            "{tool}: the warning must precede host resolution/build:\n{stderr}"
        );
    }

    // Root-mode Pi is covered by the same hook.
    let root = harness.launch("pi", &["--root"]);
    let root_stderr = stderr_of(&root);
    assert!(
        root_stderr.contains(PI_WARN_HEADER),
        "root-mode pi must warn:\n{root_stderr}"
    );

    // A second invocation is not suppressed or cached.
    let again = harness.launch_default("pi");
    assert!(stderr_of(&again).contains(PI_WARN_HEADER));
}

/// V4 quiet controls: placeholder-only state, and a tool with no Pi relevance,
/// must produce no new structural warning in either guest mode.
#[test]
fn quiet_pi_state_produces_no_structural_warning() {
    let harness = Harness::new();
    let state = probe_state_dir(&harness, "pi");
    std::fs::create_dir_all(state.join("pi/agent")).unwrap();
    std::fs::write(
        state.join("pi/agent/auth.json"),
        format!(r#"{{"anthropic":{{"type":"api_key","key":"{GUEST_PLACEHOLDER}"}}}}"#),
    )
    .unwrap();

    for (tool, extra) in [("pi", vec![]), ("pi", vec!["--root"]), ("shell", vec![])] {
        let out = harness.launch(tool, &extra);
        let stderr = stderr_of(&out);
        assert!(
            !stderr.contains(PI_WARN_HEADER),
            "{tool} {extra:?} must be quiet with placeholder-only state:\n{stderr}"
        );
    }
}

/// V4: a malformed auth file becomes one fixed potentially-sensitive line
/// (never the raw input), and a models-only credential is still reported.
#[test]
fn malformed_and_models_only_pi_state_still_warn() {
    let harness = Harness::new();
    let state = probe_state_dir(&harness, "pi");
    seed_pi(
        &state,
        "not json at all",
        Some(r#"{"providers":{"demo":{"apiKey":"guest-managed"}}}"#),
    );

    let out = harness.launch_default("pi");
    let stderr = stderr_of(&out);
    assert!(stderr.contains(PI_WARN_HEADER), "{stderr}");
    assert!(
        stderr.contains("auth.json: potentially sensitive; unrecognized or malformed structure"),
        "{stderr}"
    );
    assert!(
        stderr.contains("models.json: provider=demo type=configuration fields=apiKey"),
        "{stderr}"
    );
    // The raw input is not echoed.
    assert!(!stderr.contains("not json at all"), "{stderr}");
}

/// V4: #96's migration runs before the scan, so a real pre-#96 `home/.pi`
/// directory is reported at its canonical location, not as legacy state.
#[test]
fn legacy_pi_home_is_migrated_before_the_scan() {
    let harness = Harness::new();
    let state = probe_state_dir(&harness, "pi");
    // The probe provisioned the compiled `<state>/home/.pi` symlink; rewind to
    // the pre-#96 shape (a real directory a previous guest left behind).
    std::fs::remove_file(state.join("home/.pi")).unwrap();
    let legacy = state.join("home/.pi/agent");
    std::fs::create_dir_all(&legacy).unwrap();
    std::fs::write(
        legacy.join("auth.json"),
        r#"{"anthropic":{"type":"api_key","key":"guest-managed"}}"#,
    )
    .unwrap();

    let out = harness.launch_default("pi");
    let stderr = stderr_of(&out);
    assert!(stderr.contains(PI_WARN_HEADER), "{stderr}");
    assert!(
        stderr.contains("auth.json: provider=anthropic type=api_key fields=key"),
        "canonical location expected after migration:\n{stderr}"
    );
    assert!(
        !stderr.contains("legacy pre-#96"),
        "a launch migrates, so it must not report legacy state:\n{stderr}"
    );
    assert!(
        !state.join("home/.pi").exists(),
        "migration left the legacy dir"
    );
    assert!(state.join("pi/agent/auth.json").exists());
}

/// S-2: the acceptance criterion names *both* surfaces — "sentinel resolvers
/// to prove doctor **and warning scans** execute nothing". The doctor half
/// lives in `pi_credential_reporting.rs`; this is the launch half. A live
/// sentinel is placed on the launch's `PATH` (and referenced by absolute path,
/// so a resolver that bypassed `PATH` would still be caught) and named from a
/// `!command` in guest `auth.json`/`models.json`. The launch reaches the build
/// seam and then fails on the bogus image, but the credential sentinel must
/// never have appended its marker.
#[test]
fn every_launch_scan_resolves_nothing() {
    let harness = Harness::new();
    let state = probe_state_dir(&harness, "shell");

    let sentinel_dir = harness.home_root.join("credential-sentinels");
    std::fs::create_dir_all(&sentinel_dir).unwrap();
    let marker = harness.home_root.join(".credential-sentinel-marker");
    let sentinel = sentinel_dir.join("credential-sentinel");
    fake_msb::write_executable(
        &sentinel,
        "#!/bin/sh\nprintf 'ran\\n' >> \"$CREDENTIAL_SENTINEL_MARKER\"\nexit 1\n",
    );

    // Prove the sentinel is live before relying on its silence: without this
    // control, a non-executable or off-PATH sentinel would make the launch
    // assertion vacuous.
    let control = Command::new(&sentinel)
        .env("CREDENTIAL_SENTINEL_MARKER", &marker)
        .status()
        .expect("sentinel should spawn");
    assert!(!control.success(), "the sentinel must exit nonzero");
    assert!(
        marker.exists(),
        "the live sentinel did not append its marker"
    );
    std::fs::remove_file(&marker).unwrap();

    seed_pi(
        &state,
        &format!(
            r#"{{"anthropic":{{"type":"api_key","key":"!{sentinel} --auth"}},
                 "envprov":{{"type":"api_key","key":"","env":{{"TOKEN":"$SECRET"}}}}}}"#,
            sentinel = sentinel.display(),
        ),
        Some(&format!(
            r#"{{"providers":{{"demo":{{"apiKey":"!{sentinel} --models"}}}}}}"#,
            sentinel = sentinel.display(),
        )),
    );

    let mut cmd = harness.base_command();
    cmd.env(
        "PATH",
        format!(
            "{}:{}",
            sentinel_dir.display(),
            std::env::var("PATH").unwrap_or_default()
        ),
    )
    .env("CREDENTIAL_SENTINEL_MARKER", &marker)
    .env("SECRET", "should-not-be-read")
    .arg("shell")
    .args(["--image", BOGUS_IMAGE]);
    let out = run_with_timeout(cmd, Duration::from_secs(20));
    let stderr = stderr_of(&out);

    // The scan ran on the critical path and classified the guest files
    // field-only: the `!command` is a non-placeholder `key`, and the signed-in
    // `env` map warns. Reaching the build seam proves the hook was reached.
    assert!(stderr.contains(PI_WARN_HEADER), "{stderr}");
    assert!(
        stderr.contains("auth.json: provider=anthropic type=api_key fields=key"),
        "{stderr}"
    );
    assert!(
        stderr.contains("auth.json: provider=envprov type=api_key fields=env"),
        "{stderr}"
    );
    assert!(
        stderr.contains("models.json: provider=demo type=configuration fields=apiKey"),
        "{stderr}"
    );
    assert!(stderr.contains(CONFIG_MARKER), "{stderr}");

    // Nothing resolved the command or read the environment, and no command,
    // path or env name reached either stream.
    assert!(
        !marker.exists(),
        "the launch executed a guest credential command: {:?}",
        std::fs::read_to_string(&marker)
    );
    let combined = format!("{}{}", stdout_of(&out), stderr);
    assert!(
        !combined.contains("credential-sentinel"),
        "the sentinel path leaked:\n{combined}"
    );
    assert!(
        !combined.contains("--auth"),
        "a command leaked:\n{combined}"
    );
    assert!(
        !combined.contains("SECRET"),
        "an env name leaked:\n{combined}"
    );
}

// ===========================================================================
// #259 — boot-image selection
// ===========================================================================
//
// One image per session, chosen independently of the launched tool:
// `--image` > `AGENT_VM_IMAGE_TAG` (empty = unset) > user config `image` >
// project config `image` > default boot image. These tests drive the real
// binary through every boundary. `AGENT_VM_TEST_DEFAULT_IMAGE` (debug-only)
// gives the default slot a distinct, immediately unreachable loopback ref so a
// default fallthrough does not start a real multi-GB pull.

const CLI_REF: &str = "localhost:1/cli:latest";
const ENV_REF: &str = "localhost:1/env:latest";
const USER_REF: &str = "localhost:1/user:latest";
const PROJECT_REF: &str = "localhost:1/project:latest";
/// The default-slot seam value: an immutable (digest-pinned) loopback ref, so a
/// default fallthrough does not start a real multi-GB pull. `AGENT_VM_TEST_DEFAULT_IMAGE`
/// is an *initial recommendation* only, so it must be a valid immutable reference.
const DEFAULT_REF: &str =
    "localhost:1/default@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
/// A second immutable recommendation, for tests that change what a launcher
/// offers *after* a default was already retained.
const RECOMMENDATION_B: &str =
    "localhost:1/other@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

/// A custom runtime tool the project can declare; its command exists as a guest
/// command name only, so the launch reaches `builder.build()`.
const PROBE_TOOL: &str = "[[tools]]\nname = \"probe\"\ncommand = \"/bin/echo\"\n";

/// The `Oci` reference of the dumped `SandboxConfig`.
fn oci_reference(config: &serde_json::Value) -> String {
    config["image"]["Oci"]["reference"]
        .as_str()
        .unwrap_or("<none>")
        .to_string()
}

/// The fixed marker the **display copy** of a redacted (default-tier) debug
/// config shows instead of the record/recommendation reference. Kept in sync
/// with `debug_config::REDACTED_REFERENCE`.
const REDACTED_DEFAULT_MARKER: &str = "<redacted default boot image>";

/// The reference an acquisition-config oracle may observe for `expected`: an
/// explicit source (CLI/env/user/project) is exact and visible; the default tier
/// is redacted in the debug dump, so its exact reference is asserted in memory
/// (`boot_image` unit tests) and here only the marker is observable.
fn observable_reference(expected: &str) -> &str {
    if expected == DEFAULT_REF {
        REDACTED_DEFAULT_MARKER
    } else {
        expected
    }
}

/// The two tiers' `image` settings (and, when `declares_tool`, the project's
/// `probe` tool). Named fields rather than two adjacent `Option<&str>`
/// parameters, so a user/project swap cannot compile
/// (`CODING_STANDARDS.md` → *Types*).
struct ImageTiers<'a> {
    user: Option<&'a str>,
    project: Option<&'a str>,
    declares_tool: bool,
}

/// Write the two tiers' `image` settings (and, when `declares_tool`, the
/// project's `probe` tool).
fn write_image_tiers(harness: &Harness, tiers: ImageTiers) {
    let ImageTiers {
        user,
        project,
        declares_tool,
    } = tiers;
    if let Some(user) = user {
        harness.write_user(&format!("image = \"{user}\"\n"));
    }
    let mut body = String::new();
    if let Some(project) = project {
        body.push_str(&format!("image = \"{project}\"\n"));
    }
    if declares_tool {
        body.push_str(PROBE_TOOL);
    }
    if !body.is_empty() {
        harness.write_project(&body);
    }
}

/// Every `[debug] sandbox config JSON:` dump in `stderr`, decoded as complete
/// JSON objects. Trailing notice/progress text between dumps is tolerated.
/// Malformed JSON after a marker is an error, never a silently dropped dump.
fn acquisition_configs(stderr: &str) -> Result<Vec<serde_json::Value>, String> {
    let mut out = Vec::new();
    let mut rest = stderr;
    while let Some(index) = rest.find(CONFIG_MARKER) {
        let after = &rest[index + CONFIG_MARKER.len()..];
        let mut stream = serde_json::Deserializer::from_str(after).into_iter::<serde_json::Value>();
        let value = stream
            .next()
            .ok_or_else(|| "no JSON after a dump marker".to_string())?;
        let value = value.map_err(|error| format!("malformed debug JSON: {error}"))?;
        let offset = stream.byte_offset();
        out.push(value);
        rest = &after[offset..];
    }
    Ok(out)
}

/// The single config dump named `name`, or an error naming how many were found.
fn acquisition_config<'a>(
    configs: &'a [serde_json::Value],
    name: &str,
) -> Result<&'a serde_json::Value, String> {
    let matches: Vec<&serde_json::Value> = configs
        .iter()
        .filter(|config| config["name"].as_str() == Some(name))
        .collect();
    match matches.len() {
        0 => Err(format!("no `{name}` config dump")),
        1 => Ok(matches[0]),
        n => Err(format!("{n} `{name}` config dumps")),
    }
}

/// The whole pull oracle: exactly one `agent-vm-pull` dump whose reference is
/// `expected`.
fn check_pull_acquisition(stderr: &str, expected: &str) -> Result<(), String> {
    let configs = acquisition_configs(stderr)?;
    let config = acquisition_config(&configs, "agent-vm-pull")?;
    let reference = oci_reference(config);
    let expected = observable_reference(expected);
    if reference != expected {
        return Err(format!(
            "the acquisition config boots {reference}, expected {expected}"
        ));
    }
    Ok(())
}

#[test]
fn acquisition_config_oracle_rejects_notice_only_and_wrong_reference() {
    // Control: a real pull run parses and names the exact reference.
    let harness = Harness::new();
    harness.write_project(&format!("image = \"{PROJECT_REF}\"\n"));
    let out = harness.builtin(&["pull"], &[("AGENT_VM_TEST_DEFAULT_IMAGE", DEFAULT_REF)]);
    let stderr = stderr_of(&out);
    check_pull_acquisition(&stderr, PROJECT_REF).expect("the real pull config is observable");

    // Rejected captures.
    let notice_only = format!(
        "==> {PROJECT_REF} (from project config /x) is the image this configuration boots from\n"
    );
    assert!(
        check_pull_acquisition(&notice_only, PROJECT_REF).is_err(),
        "a notice with no JSON dump must fail"
    );

    let wrong = format!(
        "{CONFIG_MARKER}{{\"name\":\"agent-vm-pull\",\"image\":{{\"Oci\":{{\"reference\":\"localhost:1/wrong:latest\"}}}}}}\n==> {PROJECT_REF} (from project config /x) is the image this configuration boots from\n"
    );
    assert!(
        check_pull_acquisition(&wrong, PROJECT_REF).is_err(),
        "a config with the wrong reference must fail on equality"
    );

    let malformed = format!("{CONFIG_MARKER}{{not json\n");
    assert!(
        check_pull_acquisition(&malformed, PROJECT_REF).is_err(),
        "malformed JSON after a marker must fail"
    );

    let duplicate = format!(
        "{CONFIG_MARKER}{{\"name\":\"agent-vm-pull\",\"image\":{{\"Oci\":{{\"reference\":\"{PROJECT_REF}\"}}}}}}\n{CONFIG_MARKER}{{\"name\":\"agent-vm-pull\",\"image\":{{\"Oci\":{{\"reference\":\"{PROJECT_REF}\"}}}}}}\n"
    );
    assert!(
        check_pull_acquisition(&duplicate, PROJECT_REF).is_err(),
        "two dumps for one name must fail"
    );
}

/// One precedence row. `source` is the prefix the launch/pull notice renders
/// after `(from `; the file-backed sources carry a path suffix.
struct Precedence {
    name: &'static str,
    cli: Option<&'static str>,
    env: Option<&'static str>,
    user: Option<&'static str>,
    project: Option<&'static str>,
    expected: &'static str,
    source: &'static str,
}

fn precedence_rows() -> [Precedence; 10] {
    [
        Precedence {
            name: "typed beats all",
            cli: Some(CLI_REF),
            env: Some(ENV_REF),
            user: Some(USER_REF),
            project: Some(PROJECT_REF),
            expected: CLI_REF,
            source: "command line",
        },
        Precedence {
            name: "env beats user",
            cli: None,
            env: Some(ENV_REF),
            user: Some(USER_REF),
            project: Some(PROJECT_REF),
            expected: ENV_REF,
            source: "AGENT_VM_IMAGE_TAG",
        },
        Precedence {
            name: "user beats project",
            cli: None,
            env: None,
            user: Some(USER_REF),
            project: Some(PROJECT_REF),
            expected: USER_REF,
            source: "user config",
        },
        Precedence {
            name: "project beats default",
            cli: None,
            env: None,
            user: None,
            project: Some(PROJECT_REF),
            expected: PROJECT_REF,
            source: "project config",
        },
        Precedence {
            name: "default fallthrough",
            cli: None,
            env: None,
            user: None,
            project: None,
            expected: DEFAULT_REF,
            source: "default",
        },
        Precedence {
            name: "empty env is unset (user)",
            cli: None,
            env: Some(""),
            user: Some(USER_REF),
            project: Some(PROJECT_REF),
            expected: USER_REF,
            source: "user config",
        },
        Precedence {
            name: "empty env does not mask project",
            cli: None,
            env: Some(""),
            user: None,
            project: Some(PROJECT_REF),
            expected: PROJECT_REF,
            source: "project config",
        },
        Precedence {
            name: "empty env does not mask default",
            cli: None,
            env: Some(""),
            user: None,
            project: None,
            expected: DEFAULT_REF,
            source: "default",
        },
        Precedence {
            name: "empty env cannot erase a typed flag",
            cli: Some(CLI_REF),
            env: Some(""),
            user: Some(USER_REF),
            project: Some(PROJECT_REF),
            expected: CLI_REF,
            source: "command line",
        },
        Precedence {
            name: "typed beats whitespace env",
            cli: Some(CLI_REF),
            env: Some(" "),
            user: Some(USER_REF),
            project: Some(PROJECT_REF),
            expected: CLI_REF,
            source: "command line",
        },
    ]
}

#[test]
fn image_precedence_at_every_cli_boundary() {
    for row in precedence_rows() {
        // --- launch (a declared custom verb and the shipped `shell`) ---
        let harness = Harness::new();
        write_image_tiers(
            &harness,
            ImageTiers {
                user: row.user,
                project: row.project,
                declares_tool: true,
            },
        );
        let decoys = harness.builder_decoys();
        for tool in ["probe", "shell"] {
            let mut cmd = harness.command_with_decoys(&decoys);
            cmd.env("AGENT_VM_TEST_DEFAULT_IMAGE", DEFAULT_REF);
            if let Some(env) = row.env {
                cmd.env("AGENT_VM_IMAGE_TAG", env);
            }
            let mut argv: Vec<&str> = vec![tool];
            if let Some(cli) = row.cli {
                argv.push("--image");
                argv.push(cli);
            }
            let out = Harness::run_on(cmd, &argv);
            let stderr = stderr_of(&out);
            assert!(
                !out.status.success(),
                "{} ({tool}): the bogus image must fail acquisition, stderr:\n{stderr}",
                row.name
            );
            if row.expected == DEFAULT_REF {
                assert!(
                    stderr.contains("==> Boot image: the default boot image"),
                    "{} ({tool}): default notice missing:\n{stderr}",
                    row.name
                );
            } else {
                assert!(
                    stderr.contains(&format!(
                        "==> Boot image: {} (from {}",
                        row.expected, row.source
                    )),
                    "{} ({tool}): notice missing/wrong:\n{stderr}",
                    row.name
                );
            }
            assert_eq!(
                oci_reference(&debug_config_json(&stderr)),
                observable_reference(row.expected),
                "{} ({tool})",
                row.name
            );
            if tool == "probe" {
                assert_eq!(debug_guest_command(&stderr), "/bin/echo", "{}", row.name);
            }
            assert!(
                !stderr.contains("Build project tooling layer"),
                "{} ({tool}): a confirmation prompt appeared:\n{stderr}",
                row.name
            );
        }
        assert_eq!(
            harness.decoy_log(&decoys),
            "",
            "{}: no builder calls",
            row.name
        );

        // --- pull and setup (initial acquisition) ---
        for verb in ["pull", "setup"] {
            let harness = Harness::new();
            write_image_tiers(
                &harness,
                ImageTiers {
                    user: row.user,
                    project: row.project,
                    declares_tool: false,
                },
            );
            let decoys = harness.builder_decoys();
            let mut cmd = harness.command_with_decoys(&decoys);
            cmd.env("AGENT_VM_TEST_DEFAULT_IMAGE", DEFAULT_REF);
            if let Some(env) = row.env {
                cmd.env("AGENT_VM_IMAGE_TAG", env);
            }
            let mut argv: Vec<&str> = vec![verb];
            if let Some(cli) = row.cli {
                argv.push("--image");
                argv.push(cli);
            }
            let out = Harness::run_on(cmd, &argv);
            let stderr = stderr_of(&out);
            let stdout = stdout_of(&out);
            assert!(
                !out.status.success(),
                "{} ({verb}): the bogus image must fail, stderr:\n{stderr}",
                row.name
            );
            if row.expected == DEFAULT_REF {
                let safe = if verb == "pull" {
                    "==> the default boot image is the image this configuration boots from"
                } else {
                    "==> Pulling the default boot image into the microsandbox cache"
                };
                assert!(
                    stdout.contains(safe),
                    "{} ({verb}): default notice missing:\n{stdout}",
                    row.name
                );
            } else if verb == "pull" {
                assert!(
                    stdout.contains(&format!("==> {} (from {}", row.expected, row.source)),
                    "{} ({verb}): selection notice missing:\n{stdout}",
                    row.name
                );
            } else {
                assert!(
                    stdout.contains(&format!(
                        "==> Pulling {} into the microsandbox cache",
                        row.expected
                    )),
                    "{} ({verb}): pull notice missing:\n{stdout}",
                    row.name
                );
            }
            check_pull_acquisition(&stderr, row.expected)
                .unwrap_or_else(|problem| panic!("{} ({verb}): {problem}\n{stderr}", row.name));
            // setup's unreachable ref fails at its initial pull, so there must
            // be no verification dump.
            let configs = acquisition_configs(&stderr).expect("dumps parse");
            assert!(
                acquisition_config(&configs, "agent-vm-setup-verify").is_err(),
                "{} ({verb}): no verification dump may appear for an unreachable ref:\n{stderr}",
                row.name
            );
            assert_eq!(
                harness.decoy_log(&decoys),
                "",
                "{} ({verb}): no builder calls",
                row.name
            );
        }

        // --- doctor (no `--image`): rows without a typed override only ---
        if row.cli.is_none() {
            let harness = Harness::new();
            write_image_tiers(
                &harness,
                ImageTiers {
                    user: row.user,
                    project: row.project,
                    declares_tool: false,
                },
            );
            let mut envs: Vec<(&str, &str)> = vec![("AGENT_VM_TEST_DEFAULT_IMAGE", DEFAULT_REF)];
            if let Some(env) = row.env {
                envs.push(("AGENT_VM_IMAGE_TAG", env));
            }
            let out = harness.builtin(&["doctor"], &envs);
            let stdout = stdout_of(&out);
            if row.expected == DEFAULT_REF {
                assert!(
                    stdout.contains(
                        "selected (without --image): not selected; initial recommendation ["
                    ),
                    "{} (doctor): default selected row missing:\n{stdout}",
                    row.name
                );
            } else {
                assert!(
                    stdout.contains(&format!(
                        "selected (without --image): {} (from {}",
                        row.expected, row.source
                    )),
                    "{} (doctor): selected row missing:\n{stdout}",
                    row.name
                );
            }
        }
    }
}

#[test]
fn image_whitespace_and_empty_values_do_not_fall_through() {
    // Whitespace env values are PRESENT, not unset or trimmed: they are
    // retained as the environment override, and acquisition/parsing may fail
    // before a JSON dump. There must be no fallback to U/P/D and no builder.
    for present in [" ", "\t", " localhost:1/env:latest "] {
        let harness = Harness::new();
        write_image_tiers(
            &harness,
            ImageTiers {
                user: Some(USER_REF),
                project: Some(PROJECT_REF),
                declares_tool: true,
            },
        );
        let decoys = harness.builder_decoys();
        let mut cmd = harness.command_with_decoys(&decoys);
        cmd.env("AGENT_VM_TEST_DEFAULT_IMAGE", DEFAULT_REF)
            .env("AGENT_VM_IMAGE_TAG", present);
        let out = Harness::run_on(cmd, &["probe"]);
        let stderr = stderr_of(&out);
        assert!(
            !out.status.success(),
            "{present:?} must fail acquisition:\n{stderr}"
        );
        assert!(
            !stderr.contains(USER_REF)
                && !stderr.contains(PROJECT_REF)
                && !stderr.contains(DEFAULT_REF),
            "{present:?} fell through to a lower tier:\n{stderr}"
        );
        assert!(
            harness.decoy_log(&decoys).is_empty(),
            "{present:?}: no builder calls"
        );

        // pull and setup treat it the same way.
        for verb in ["pull", "setup"] {
            let harness = Harness::new();
            write_image_tiers(
                &harness,
                ImageTiers {
                    user: Some(USER_REF),
                    project: Some(PROJECT_REF),
                    declares_tool: false,
                },
            );
            let decoys = harness.builder_decoys();
            let mut cmd = harness.command_with_decoys(&decoys);
            cmd.env("AGENT_VM_TEST_DEFAULT_IMAGE", DEFAULT_REF)
                .env("AGENT_VM_IMAGE_TAG", present);
            let out = Harness::run_on(cmd, &[verb]);
            let stderr = stderr_of(&out);
            assert!(
                !out.status.success(),
                "{present:?} ({verb}) must fail:\n{stderr}"
            );
            assert!(
                harness.decoy_log(&decoys).is_empty(),
                "{present:?} ({verb}): no builder calls"
            );
        }

        // doctor reports the retained env override, not a lower tier.
        let harness = Harness::new();
        write_image_tiers(
            &harness,
            ImageTiers {
                user: Some(USER_REF),
                project: Some(PROJECT_REF),
                declares_tool: false,
            },
        );
        let out = harness.builtin(
            &["doctor"],
            &[
                ("AGENT_VM_TEST_DEFAULT_IMAGE", DEFAULT_REF),
                ("AGENT_VM_IMAGE_TAG", present),
            ],
        );
        let stdout = stdout_of(&out);
        assert!(
            stdout.contains("(from AGENT_VM_IMAGE_TAG)"),
            "{present:?} (doctor): env override not selected:\n{stdout}"
        );
    }

    // A typed `--image ' ref '` retains the exact argument, not a trimmed ref.
    let harness = Harness::new();
    harness.write_project(&format!("image = \"{PROJECT_REF}\"\n{PROBE_TOOL}"));
    let spaced = " localhost:1/cli:latest ";
    let out = harness.launch_argv(
        "probe",
        &["--image", spaced],
        &[("AGENT_VM_TEST_DEFAULT_IMAGE", DEFAULT_REF)],
    );
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(spaced),
        "the typed value must be retained exactly:\n{stderr}"
    );
    assert!(
        !stderr.contains("(from project config"),
        "must not fall through:\n{stderr}"
    );

    // A typed empty `--image ''` fails at the override boundary even with valid
    // lower tiers.
    let harness = Harness::new();
    write_image_tiers(
        &harness,
        ImageTiers {
            user: Some(USER_REF),
            project: Some(PROJECT_REF),
            declares_tool: true,
        },
    );
    let out = harness.launch_argv(
        "probe",
        &["--image", ""],
        &[("AGENT_VM_TEST_DEFAULT_IMAGE", DEFAULT_REF)],
    );
    assert!(!out.status.success(), "a typed empty --image must fail");
    let stderr = stderr_of(&out);
    assert!(stderr.contains("must not be empty"), "{stderr}");
    assert!(
        !stderr.contains(CONFIG_MARKER),
        "must fail before building a config:\n{stderr}"
    );
}

#[test]
fn config_images_reject_local_paths_and_empty_values() {
    // The values are TOML literals, so a tab/newline is expressed with escapes.
    let bad_values = [
        "\"\"",
        "\" \"",
        "\"\\t\"",
        "\" localhost:1/user:latest \"",
        "\"/\"",
        "\"./rootfs\"",
        "\"../rootfs\"",
        "\".\"",
        "\"..\"",
        "\"/tmp/img.disk\"",
        "\"a\\nb\"",
    ];
    for value in bad_values {
        // user tier
        let harness = Harness::new();
        harness.write_user(&format!("image = {value}\n"));
        let out = harness.launch_argv("shell", &[], &[]);
        let stderr = stderr_of(&out);
        assert!(
            !out.status.success(),
            "user image {value} must fail:\n{stderr}"
        );
        assert!(stderr.contains("image"), "user image {value}: {stderr}");
        assert!(
            !stderr.contains("==> Boot image"),
            "user image {value} must not select an image:\n{stderr}"
        );

        // project tier
        let harness = Harness::new();
        harness.write_project(&format!("image = {value}\n"));
        let out = harness.launch_argv("shell", &[], &[]);
        let stderr = stderr_of(&out);
        assert!(
            !out.status.success(),
            "project image {value} must fail:\n{stderr}"
        );
        assert!(stderr.contains("image"), "project image {value}: {stderr}");

        // doctor still renders its sections and exits nonzero.
        let harness = Harness::new();
        harness.write_project(&format!("image = {value}\n"));
        let out = harness.builtin(&["doctor"], &[]);
        let stdout = stdout_of(&out);
        assert!(
            !out.status.success(),
            "doctor must exit nonzero for image {value}"
        );
        assert!(
            stdout.contains("==> boot image"),
            "doctor sections render for {value}:\n{stdout}"
        );
        assert!(
            stdout.contains("could not be read"),
            "doctor explains the load failure for {value}:\n{stdout}"
        );
    }

    // An invalid lower tier is still an error when a higher source is set:
    // precedence is not permission to skip config validation.
    let harness = Harness::new();
    harness.write_project("image = \"/\"\n");
    let out = harness.launch_argv(
        "shell",
        &["--image", CLI_REF],
        &[("AGENT_VM_TEST_DEFAULT_IMAGE", DEFAULT_REF)],
    );
    assert!(
        !out.status.success(),
        "an invalid project image must still fail with a higher source"
    );
}

/// The tool rows `doctor` renders, in order (`  1. dsh -> "dsh"; …`).
fn doctor_tool_order(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let rest = line.trim_start().split_once(". ")?.1;
            let name = rest.split_whitespace().next()?;
            rest.contains("->").then(|| name.to_string())
        })
        .collect()
}

/// The launch verbs listed in a clap `Commands:` block, in order, excluding
/// the fixed built-ins. Command entries start with exactly two spaces;
/// wrapped description lines are indented further.
fn help_tool_order(text: &str) -> Vec<String> {
    const BUILTINS: [&str; 9] = [
        "setup",
        "pull",
        "upgrade",
        "msb",
        "clipboard",
        "doctor",
        "secret",
        "build",
        "help",
    ];
    let mut out = Vec::new();
    let mut in_commands = false;
    for line in text.lines() {
        let trimmed = line.trim_end();
        if trimmed == "Commands:" {
            in_commands = true;
            continue;
        }
        if in_commands && trimmed == "Options:" {
            break;
        }
        if !in_commands || !line.starts_with("  ") || line.starts_with("   ") {
            continue;
        }
        let token = line.split_whitespace().next().unwrap_or("");
        if !token.is_empty() && !BUILTINS.contains(&token) {
            out.push(token.to_string());
        }
    }
    out
}

#[test]
fn image_only_config_keeps_all_shipped_runtime_tools() {
    // Baseline: the shipped defaults, booting a named image via `--image`.
    let baseline_harness = Harness::new();
    let baseline_out = baseline_harness.launch_argv(
        "claude",
        &["--image", PROJECT_REF],
        &[("AGENT_VM_TEST_DEFAULT_IMAGE", DEFAULT_REF)],
    );
    let baseline = normalized_config(&baseline_harness, &baseline_out);
    assert_eq!(oci_reference(&baseline), PROJECT_REF);

    // Every image-only shape keeps the shipped tools and changes only the image.
    let variants: [(&str, Option<&str>, Option<&str>, bool); 4] = [
        ("user only", Some(PROJECT_REF), None, false),
        ("project only", None, Some(PROJECT_REF), false),
        ("both tiers", Some(PROJECT_REF), Some(PROJECT_REF), false),
        ("project with tools=[]", None, Some(PROJECT_REF), true),
    ];
    for (name, user, project, explicit_empty) in variants {
        let harness = Harness::new();
        if let Some(user) = user {
            harness.write_user(&format!("image = \"{user}\"\n"));
        }
        let mut body = String::new();
        if let Some(project) = project {
            body.push_str(&format!("image = \"{project}\"\n"));
        }
        if explicit_empty {
            body.push_str("tools = []\n");
        }
        if !body.is_empty() {
            harness.write_project(&body);
        }

        let out = harness.launch_argv(
            "claude",
            &[],
            &[("AGENT_VM_TEST_DEFAULT_IMAGE", DEFAULT_REF)],
        );
        let config = normalized_config(&harness, &out);
        assert_eq!(oci_reference(&config), PROJECT_REF, "{name}");
        assert_eq!(config, baseline, "{name}: only the image field may change");

        // Help and doctor still list all seven shipped verbs, in order.
        let help = harness.builtin(&["--help"], &[]);
        assert_eq!(
            help_tool_order(&stdout_of(&help)),
            DEFAULT_TOOLS,
            "{name}: help verb order"
        );
        let doctor = harness.builtin(&["doctor"], &[]);
        assert_eq!(
            doctor_tool_order(&stdout_of(&doctor)),
            DEFAULT_TOOLS,
            "{name}: doctor verb order"
        );
    }

    // A user image-only tier plus project custom tools: the project tools still
    // replace the shipped tools (ADR-0015), and the user image still wins.
    let harness = Harness::new();
    harness.write_user(&format!("image = \"{USER_REF}\"\n"));
    harness.write_project(&format!(
        "image = \"{PROJECT_REF}\"\n[[tools]]\nname = \"hello\"\ncommand = \"hello-258\"\n"
    ));
    let out = harness.launch_argv(
        "hello",
        &[],
        &[("AGENT_VM_TEST_DEFAULT_IMAGE", DEFAULT_REF)],
    );
    let config = normalized_config(&harness, &out);
    assert_eq!(
        oci_reference(&config),
        USER_REF,
        "the user image outranks the project's"
    );
    let claude = harness.launch_argv(
        "claude",
        &[],
        &[("AGENT_VM_TEST_DEFAULT_IMAGE", DEFAULT_REF)],
    );
    assert!(
        stderr_of(&claude).contains("unrecognized subcommand"),
        "project tools replace the shipped tools"
    );
}

#[test]
fn custom_catalog_and_tool_edits_do_not_change_the_boot_image() {
    let harness = Harness::new();
    harness.write_project(
        "[[tools]]\nname = \"hello\"\ncommand = \"hello-258\"\nargs = [\"probe\", \"two words\"]\n",
    );

    // No image configured: both the custom verb and the shell fallback choose
    // the default boot image.
    for tool in ["hello", "shell"] {
        let out = harness.launch_argv(tool, &[], &[("AGENT_VM_TEST_DEFAULT_IMAGE", DEFAULT_REF)]);
        assert_eq!(
            oci_reference(&debug_config_json(&stderr_of(&out))),
            REDACTED_DEFAULT_MARKER,
            "{tool}"
        );
    }
    let hello = harness.launch_argv(
        "hello",
        &[],
        &[("AGENT_VM_TEST_DEFAULT_IMAGE", DEFAULT_REF)],
    );
    assert_eq!(
        debug_guest_command(&stderr_of(&hello)),
        "hello-258 probe two words"
    );

    // Select the project image: both verbs choose it.
    harness.write_project(
        "image = \"localhost:1/project:latest\"\n[[tools]]\nname = \"hello\"\ncommand = \"hello-258\"\nargs = [\"probe\", \"two words\"]\n",
    );
    for tool in ["hello", "shell"] {
        let out = harness.launch_argv(tool, &[], &[("AGENT_VM_TEST_DEFAULT_IMAGE", DEFAULT_REF)]);
        assert_eq!(
            oci_reference(&debug_config_json(&stderr_of(&out))),
            PROJECT_REF,
            "{tool}"
        );
    }

    // Edit the declaration (command/args/env), add and reorder tools: the
    // selection stays P, and the changed tool behavior is observable.
    harness.write_project(
        "image = \"localhost:1/project:latest\"\n\
         [[tools]]\nname = \"second\"\ncommand = \"second-258\"\n\
         [[tools]]\nname = \"hello\"\ncommand = \"hello-edited\"\nargs = [\"one\"]\nenv = { AVM_EDIT = \"yes\" }\n",
    );
    let edited = harness.launch_argv(
        "hello",
        &[],
        &[("AGENT_VM_TEST_DEFAULT_IMAGE", DEFAULT_REF)],
    );
    let stderr = stderr_of(&edited);
    assert_eq!(oci_reference(&debug_config_json(&stderr)), PROJECT_REF);
    assert_eq!(debug_guest_command(&stderr), "hello-edited one");
    let config = debug_config_json(&stderr);
    assert!(
        env_pairs(&config).contains(&("AVM_EDIT", "yes")),
        "the edited env must be published"
    );

    // Remove the second tool; selection is unchanged.
    harness.write_project(
        "image = \"localhost:1/project:latest\"\n[[tools]]\nname = \"hello\"\ncommand = \"hello-edited\"\n",
    );
    let out = harness.launch_argv(
        "hello",
        &[],
        &[("AGENT_VM_TEST_DEFAULT_IMAGE", DEFAULT_REF)],
    );
    assert_eq!(
        oci_reference(&debug_config_json(&stderr_of(&out))),
        PROJECT_REF
    );
}

#[test]
fn help_doctor_pull_setup_and_launch_agree_on_image_selection() {
    let harness = Harness::new();
    harness.write_user(&format!("image = \"{USER_REF}\"\n"));
    harness.write_project(&format!(
        "image = \"{PROJECT_REF}\"\n[[tools]]\nname = \"hello\"\ncommand = \"hello-258\"\n"
    ));

    // The verb list agrees between `--help` and `doctor` (hello then shell, no
    // shipped agent verbs, since the project replaced the defaults).
    let help = stdout_of(&harness.builtin(&["--help"], &[]));
    let doctor = stdout_of(&harness.builtin(&["doctor"], &[]));
    assert_eq!(
        help_tool_order(&help),
        vec!["hello".to_string(), "shell".to_string()],
        "help verbs"
    );
    assert_eq!(
        doctor_tool_order(&doctor),
        vec!["hello".to_string(), "shell".to_string()],
        "doctor verbs"
    );

    // Every launch/builtin help path exposes the same precedence text and env
    // binding, and none of the removed image/build flags.
    let mut paths: Vec<(&str, Output)> = vec![
        ("help hello", harness.builtin(&["help", "hello"], &[])),
        (
            "hello --help",
            harness.launch_argv("hello", &["--help"], &[]),
        ),
        (
            "shell --help",
            harness.launch_argv("shell", &["--help"], &[]),
        ),
        ("pull --help", harness.builtin(&["pull", "--help"], &[])),
        ("setup --help", harness.builtin(&["setup", "--help"], &[])),
    ];
    for (what, out) in paths.drain(..) {
        let text = stdout_of(&out);
        assert!(
            out.status.success(),
            "{what} must exit 0:\n{text}\n{}",
            stderr_of(&out)
        );
        assert!(
            text.contains("--image"),
            "{what} must document --image:\n{text}"
        );
        assert!(
            text.contains("AGENT_VM_IMAGE_TAG"),
            "{what} must bind AGENT_VM_IMAGE_TAG:\n{text}"
        );
        for removed in ["--base-image", "--layer", "--yes"] {
            assert!(
                !text.contains(removed),
                "{what} must not mention {removed}:\n{text}"
            );
        }
    }
}

/// `doctor` reports the boot image but has no `--image` of its own: a launch's
/// typed override must not become reachable through it, so the flag stays an
/// ordinary clap usage error (exit 2) and neither `doctor --help` nor the
/// doctor command advertises it. This pins the "no `doctor --image` API"
/// boundary that the shared `ImageArgs` flatten would silently break if it were
/// added to `doctor`.
#[test]
fn doctor_does_not_accept_an_image_flag() {
    let harness = Harness::new();
    let out = harness.builtin(&["doctor", "--image", CLI_REF], &[]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "doctor must reject --image as a usage error:\nstdout:\n{}\nstderr:\n{}",
        stdout_of(&out),
        stderr_of(&out)
    );
    let help = stdout_of(&harness.builtin(&["doctor", "--help"], &[]));
    assert!(
        !help.contains("--image"),
        "doctor --help must not advertise --image:\n{help}"
    );
    assert!(
        !help.contains("AGENT_VM_IMAGE_TAG"),
        "doctor does not bind AGENT_VM_IMAGE_TAG through clap:\n{help}"
    );
}

#[test]
fn pull_and_setup_reject_removed_composition_flags_as_usage_errors() {
    // `pull`/`setup` have no trailing positional, so every removed composition
    // flag is an ordinary clap usage error (exit 2) on both builtins.
    for verb in ["pull", "setup"] {
        for argv in [
            vec!["--layer", "/tmp/x"],
            vec!["--base-image", "x"],
            vec!["--yes"],
            vec!["-y"],
        ] {
            let harness = Harness::new();
            let mut full = vec![verb];
            full.extend_from_slice(&argv);
            let out = harness.builtin(&full, &[]);
            assert_eq!(
                out.status.code(),
                Some(2),
                "{verb} {argv:?} must exit 2:\n{}",
                stderr_of(&out)
            );
            assert!(
                stderr_of(&out).contains("unexpected argument"),
                "{verb} {argv:?}: {}",
                stderr_of(&out)
            );
        }
    }
}

/// Pins the **forwarding** behavior, not a rejection: launch verbs carry a
/// `trailing_var_arg` positional with `allow_hyphen_values`, so - like any
/// unregistered hyphen token - the removed flags reach the tool as agent args
/// rather than being rejected by clap. This is the pre-existing `agent_args`
/// contract; the launcher registers no legacy handling and never probes a former
/// `.agent-vm/layers/` directory (a documented deviation from the plan, which
/// expected exit 2 here). The exact forwarded guest command is asserted, so a
/// change that silently discards the args cannot pass as "forwarded".
#[test]
fn launch_forwards_removed_composition_flags_as_agent_args() {
    // (argv after the verb, the exact forwarded guest command)
    let cases: [(Vec<&str>, &str); 5] = [
        (vec!["--layer", "/tmp/x"], "/bin/echo --layer /tmp/x"),
        (vec!["--base-image", "x"], "/bin/echo --base-image x"),
        (vec!["--yes"], "/bin/echo --yes"),
        (vec!["-y"], "/bin/echo -y"),
        // `--` is clap's escape: it is absorbed before the tool's
        // `trailing_var_arg` positional, so the flags after it reach the tool
        // identically. This pins that the escape is not silently dropped.
        (vec!["--", "--layer", "/tmp/x"], "/bin/echo --layer /tmp/x"),
    ];
    for (argv, expected) in cases {
        let harness = Harness::new();
        harness.write_project(&format!("image = \"{PROJECT_REF}\"\n{PROBE_TOOL}"));
        let decoys = harness.builder_decoys();
        let mut cmd = harness.command_with_decoys(&decoys);
        cmd.env("AGENT_VM_TEST_DEFAULT_IMAGE", DEFAULT_REF);
        let mut full = vec!["probe"];
        full.extend_from_slice(&argv);
        let out = Harness::run_on(cmd, &full);
        let stderr = stderr_of(&out);
        assert_ne!(
            out.status.code(),
            Some(2),
            "probe {argv:?} must not be a usage error:\n{stderr}"
        );
        assert!(
            !stderr.contains("no longer supported") && !stderr.contains("migrat"),
            "probe {argv:?} must emit no migration advice:\n{stderr}"
        );
        assert_eq!(oci_reference(&debug_config_json(&stderr)), PROJECT_REF);
        assert_eq!(
            debug_guest_command(&stderr),
            expected,
            "probe {argv:?} must forward its args verbatim to the tool:\n{stderr}"
        );
        assert!(
            harness.decoy_log(&decoys).is_empty(),
            "probe {argv:?}: no builder calls"
        );
    }
}

#[test]
fn the_removed_layer_config_field_is_a_schema_error() {
    // The removed `layer` config field fails ordinary schema parsing, with
    // redacted guidance (no value echoed, no migration advice).
    for body in [
        "[[tools]]\nname = \"t\"\ncommand = \"t\"\nlayer = { builtin = \"claude\" }\n",
        "[[tools]]\nname = \"t\"\ncommand = \"t\"\nlayer = { path = \"x\" }\n",
    ] {
        let harness = Harness::new();
        harness.write_project(body);
        let out = harness.launch_argv("t", &[], &[]);
        let stderr = stderr_of(&out);
        assert!(
            !out.status.success(),
            "a `layer` field must fail the launch"
        );
        assert!(
            stderr.contains("invalid TOML or tool schema"),
            "a `layer` field must fail as a schema error:\n{stderr}"
        );
        assert!(
            !stderr.contains("migrat") && !stderr.contains("no longer supported"),
            "no migration advice:\n{stderr}"
        );
    }
}

#[test]
fn broken_config_pull_and_setup_explain_the_image_fallback() {
    // A malformed user config leaves the configured image tiers unknown. The
    // recovery builtins select the explicit source or the default, warn, and
    // never fabricate a user/project image.
    let broken = "this is not = = toml\n";
    for (cli, env, expected) in [
        (Some(CLI_REF), None, CLI_REF),
        (None, Some(ENV_REF), ENV_REF),
        (None, None, DEFAULT_REF),
    ] {
        for verb in ["pull", "setup"] {
            let harness = Harness::new();
            harness.write_user(broken);
            let mut envs: Vec<(&str, &str)> = vec![("AGENT_VM_TEST_DEFAULT_IMAGE", DEFAULT_REF)];
            if let Some(env) = env {
                envs.push(("AGENT_VM_IMAGE_TAG", env));
            }
            let mut args: Vec<&str> = vec![verb];
            if let Some(cli) = cli {
                args.push("--image");
                args.push(cli);
            }
            let out = harness.builtin(&args, &envs);
            let stderr = stderr_of(&out);
            let stdout = stdout_of(&out);
            assert!(
                stdout.contains("configured image settings could not be read"),
                "{verb} must warn about the unreadable image config:\n{stdout}\n{stderr}"
            );
            check_pull_acquisition(&stderr, expected)
                .unwrap_or_else(|problem| panic!("{verb}: {problem}\n{stderr}"));
            assert!(
                !stdout.contains(USER_REF) && !stdout.contains(PROJECT_REF),
                "{verb} must not fabricate a configured image:\n{stdout}"
            );
        }
    }

    // A dangling `tools` reference is a catalog error, but a readable `image`
    // must survive for pull/setup/doctor.
    let harness = Harness::new();
    harness.write_project(&format!(
        "image = \"{PROJECT_REF}\"\n[[tools]]\nname = \"t\"\ncommand = \"t\"\ntools = [\"nope\"]\n"
    ));
    for verb in ["pull", "setup"] {
        let out = harness.builtin(&[verb], &[("AGENT_VM_TEST_DEFAULT_IMAGE", DEFAULT_REF)]);
        let stderr = stderr_of(&out);
        check_pull_acquisition(&stderr, PROJECT_REF)
            .unwrap_or_else(|problem| panic!("{verb}: {problem}\n{stderr}"));
    }
    let doctor =
        stdout_of(&harness.builtin(&["doctor"], &[("AGENT_VM_TEST_DEFAULT_IMAGE", DEFAULT_REF)]));
    assert!(
        doctor.contains(&format!("selected (without --image): {PROJECT_REF}")),
        "doctor keeps the readable image:\n{doctor}"
    );
    // The launch still reports the tool-resolution error.
    let launch = harness.launch_argv("t", &[], &[("AGENT_VM_TEST_DEFAULT_IMAGE", DEFAULT_REF)]);
    let launch_stderr = stderr_of(&launch);
    assert!(!launch.status.success());
    assert!(
        launch_stderr.contains("names no tool in the resolved catalog"),
        "{launch_stderr}"
    );
}

#[test]
fn failed_image_acquisition_never_invokes_a_builder() {
    // Each source selects a distinct bogus loopback ref; the launch exits
    // nonzero after the config dump, the dump has the exact reference, and the
    // builder decoys were never called.
    struct ImgSource {
        name: &'static str,
        cli: Option<&'static str>,
        env: Option<&'static str>,
        user: Option<&'static str>,
        project: Option<&'static str>,
    }
    let sources = [
        ImgSource {
            name: "command line",
            cli: Some(CLI_REF),
            env: None,
            user: None,
            project: None,
        },
        ImgSource {
            name: "env",
            cli: None,
            env: Some(ENV_REF),
            user: None,
            project: None,
        },
        ImgSource {
            name: "user",
            cli: None,
            env: None,
            user: Some(USER_REF),
            project: None,
        },
        ImgSource {
            name: "project",
            cli: None,
            env: None,
            user: None,
            project: Some(PROJECT_REF),
        },
        ImgSource {
            name: "default",
            cli: None,
            env: None,
            user: None,
            project: None,
        },
    ];
    for ImgSource {
        name,
        cli,
        env,
        user,
        project,
    } in sources
    {
        let expected = cli.or(env).or(user).or(project).unwrap_or(DEFAULT_REF);
        let harness = Harness::new();
        write_image_tiers(
            &harness,
            ImageTiers {
                user,
                project,
                declares_tool: true,
            },
        );
        let decoys = harness.builder_decoys();
        let mut cmd = harness.command_with_decoys(&decoys);
        cmd.env("AGENT_VM_TEST_DEFAULT_IMAGE", DEFAULT_REF);
        if let Some(env) = env {
            cmd.env("AGENT_VM_IMAGE_TAG", env);
        }
        let mut argv = vec!["probe"];
        if let Some(cli) = cli {
            argv.push("--image");
            argv.push(cli);
        }
        let out = Harness::run_on(cmd, &argv);
        let stderr = stderr_of(&out);
        assert!(
            !out.status.success(),
            "{name}: must exit nonzero after the dump"
        );
        assert_eq!(
            oci_reference(&debug_config_json(&stderr)),
            observable_reference(expected),
            "{name}"
        );
        // Absence of a prompt and of any fallback image are supplemental.
        assert!(
            !stderr.contains("Build project tooling layer"),
            "{name}: no prompt"
        );
        assert!(
            harness.decoy_log(&decoys).is_empty(),
            "{name}: no builder calls"
        );
    }
}

#[test]
fn former_layer_directories_are_inert() {
    let harness = Harness::new();
    harness.write_project(&format!("image = \"{PROJECT_REF}\"\n{PROBE_TOOL}"));
    let decoys = harness.builder_decoys();

    let run = |envs: &[(&str, &str)]| {
        let mut cmd = harness.command_with_decoys(&decoys);
        cmd.env("AGENT_VM_TEST_DEFAULT_IMAGE", DEFAULT_REF);
        for (key, value) in envs {
            cmd.env(key, value);
        }
        Harness::run_on(cmd, &["probe"])
    };

    let baseline = run(&[]);
    assert_eq!(
        oci_reference(&debug_config_json(&stderr_of(&baseline))),
        PROJECT_REF
    );
    let baseline_config = normalized_config(&harness, &baseline);

    // Deliberately invalid Dockerfiles: accidental parsing/discovery cannot
    // silently succeed.
    let poison = harness
        .project_root
        .join(".agent-vm/layers/10-poison/Dockerfile");
    let nested = harness
        .project_root
        .join(".agent-vm/layers/10-poison/sub/deeper/Dockerfile");
    let legacy = harness.project_root.join(".agent-vm/layer/Dockerfile");
    write(&poison, "!! not a dockerfile\n");
    write(&nested, "&& also not\n");
    write(&legacy, "?? legacy\n");
    let dangling = harness
        .project_root
        .join(".agent-vm/layers/10-poison/dangling");
    std::os::unix::fs::symlink("nowhere-at-all", &dangling).unwrap();

    let poisoned = run(&[]);
    assert_eq!(
        oci_reference(&debug_config_json(&stderr_of(&poisoned))),
        PROJECT_REF
    );
    assert_eq!(
        normalized_config(&harness, &poisoned),
        baseline_config,
        "former layer directories must not change the launch"
    );
    assert!(
        harness.decoy_log(&decoys).is_empty(),
        "former dirs: no builder calls"
    );

    // The former directory content is byte-identical afterward (no cleanup or
    // migration ran).
    assert_eq!(
        std::fs::read_to_string(&poison).unwrap(),
        "!! not a dockerfile\n"
    );
    assert_eq!(std::fs::read_to_string(&legacy).unwrap(), "?? legacy\n");
    assert!(dangling.is_symlink());

    // Stale env vars no longer affect selection or error.
    for (key, value) in [
        ("AGENT_VM_BASE_IMAGE", "ghcr.io/x/y:z"),
        ("AGENT_VM_LAYER", ""),
        ("AGENT_VM_LAYER", "/tmp/x"),
        ("AGENT_VM_YES", "1"),
    ] {
        let out = run(&[(key, value)]);
        let stderr = stderr_of(&out);
        assert_eq!(
            oci_reference(&debug_config_json(&stderr)),
            PROJECT_REF,
            "{key}={value:?} must not change selection"
        );
        assert!(
            !stderr.contains("no longer supported"),
            "{key}={value:?} must not error:\n{stderr}"
        );
    }
    assert!(
        harness.decoy_log(&decoys).is_empty(),
        "stale env: no builder calls"
    );
}

/// Run one `pull`/`setup` precedence row and return its stderr, or an error if
/// the actual acquisition config's reference is not the selected one. Used by
/// the two independent mutation targets below (they run separately so a pull
/// failure cannot hide a setup failure).
fn run_builtin_acquisition(row: &Precedence, verb: &str) -> Result<String, String> {
    let harness = Harness::new();
    write_image_tiers(
        &harness,
        ImageTiers {
            user: row.user,
            project: row.project,
            declares_tool: false,
        },
    );
    let decoys = harness.builder_decoys();
    let mut cmd = harness.command_with_decoys(&decoys);
    cmd.env("AGENT_VM_TEST_DEFAULT_IMAGE", DEFAULT_REF);
    if let Some(env) = row.env {
        cmd.env("AGENT_VM_IMAGE_TAG", env);
    }
    let mut argv = vec![verb];
    if let Some(cli) = row.cli {
        argv.push("--image");
        argv.push(cli);
    }
    let out = Harness::run_on(cmd, &argv);
    let stderr = stderr_of(&out);
    if out.status.success() {
        return Err(format!("{verb} unexpectedly succeeded:\n{stderr}"));
    }
    check_pull_acquisition(&stderr, row.expected)?;
    let log = harness.decoy_log(&decoys);
    if !log.is_empty() {
        return Err(format!("{verb} invoked a builder: {log}"));
    }
    Ok(stderr)
}

#[test]
fn pull_uses_the_actual_selected_reference() {
    for row in precedence_rows() {
        run_builtin_acquisition(&row, "pull")
            .unwrap_or_else(|problem| panic!("{} (pull): {problem}", row.name));
    }
}

#[test]
fn setup_pull_uses_the_actual_selected_reference() {
    for row in precedence_rows() {
        run_builtin_acquisition(&row, "setup")
            .unwrap_or_else(|problem| panic!("{} (setup): {problem}", row.name));
    }
}

/// A present but non-Unicode `AGENT_VM_IMAGE_TAG` is a real override value that
/// no verb can interpret. `doctor` in particular must not report it as absence
/// and print a selection launch would never make (Spec S1); the acquisition and
/// launch verbs already fail through clap's `String` binding.
#[cfg(unix)]
#[test]
fn a_non_unicode_image_override_fails_every_verb_that_reads_it() {
    use std::os::unix::ffi::OsStrExt;
    for verb in ["doctor", "pull", "setup", "shell"] {
        let harness = Harness::new();
        let mut cmd = harness.base_command();
        cmd.env("AGENT_VM_IMAGE_TAG", std::ffi::OsStr::from_bytes(b"\xff"));
        let out = Harness::run_on(cmd, &[verb]);
        let stdout = stdout_of(&out);
        let stderr = stderr_of(&out);
        assert_ne!(
            out.status.code(),
            Some(0),
            "{verb} must fail on a non-Unicode override:\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        assert!(
            !stdout.contains("AGENT_VM_IMAGE_TAG: <unset>"),
            "{verb}: an invalid override must not be reported as unset:\n{stdout}"
        );
        assert!(
            !stdout.contains("selected (without --image):"),
            "{verb}: no selection may be printed for an invalid override:\n{stdout}"
        );
        if verb == "doctor" {
            // doctor must say *why* it refuses, naming the value as present but
            // unreadable rather than pretending it is unset.
            assert!(
                stdout.contains("AGENT_VM_IMAGE_TAG: <present but not valid Unicode"),
                "doctor must explain an unreadable override:\n{stdout}"
            );
        }
    }
}

// ===========================================================================
//
// The retained default (issue #261): a user-scoped, immutable bookmark, adopted
// only after the image was actually acquired. These are boot-free CLI checks:
// they observe selection, the record's bytes and the failure paths. The
// *successful-adoption* path needs a real acquisition and lives in the native
// `script/test/e2e.sh` retained-default group.

impl Harness {
    /// The retained-default record under this harness's isolated `$HOME`.
    fn selection_record(&self) -> PathBuf {
        self.home_root.join(".config/agent-vm/default-image.json")
    }

    fn selection_lock(&self) -> PathBuf {
        self.home_root.join(".config/agent-vm/default-image.lock")
    }

    fn write_selection(&self, contents: &str) {
        write(&self.selection_record(), contents);
    }

    fn write_selection_ref(&self, reference: &str) {
        self.write_selection(&format!("{{\"version\":1,\"image\":\"{reference}\"}}\n"));
    }

    /// The record's exact bytes, or `None` when it does not exist.
    fn selection_bytes(&self) -> Option<Vec<u8>> {
        std::fs::read(self.selection_record()).ok()
    }

    fn assert_no_selection(&self, context: &str) {
        assert!(
            self.selection_bytes().is_none(),
            "{context}: a selection record was created"
        );
        assert!(
            !self.selection_lock().exists(),
            "{context}: a selection lock was created"
        );
    }
}

#[test]
fn diagnostics_and_help_never_create_a_selection() {
    let harness = Harness::new();
    let envs = [("AGENT_VM_TEST_DEFAULT_IMAGE", DEFAULT_REF)];

    let doctor = harness.builtin(&["doctor"], &envs);
    let stdout = stdout_of(&doctor);
    assert!(
        doctor.status.success(),
        "doctor on a healthy host must exit 0:\n{stdout}\n{}",
        stderr_of(&doctor)
    );
    assert!(
        stdout.contains("default: not selected; initial recommendation ["),
        "doctor must report an uninitialized recommendation, not a retained selection:\n{stdout}"
    );
    assert!(
        !stdout.contains(DEFAULT_REF),
        "doctor must not echo the recommendation reference:\n{stdout}"
    );
    harness.assert_no_selection("doctor");

    for args in [
        vec!["--help"],
        vec!["help", "shell"],
        vec!["shell", "--help"],
        vec!["pull", "--help"],
    ] {
        let out = harness.builtin(&args, &envs);
        assert!(out.status.success(), "{args:?} must exit 0");
        harness.assert_no_selection(&format!("{args:?}"));
    }

    let reset = harness.builtin(&["doctor", "--reset-msb-db"], &envs);
    assert!(
        reset.status.success(),
        "doctor --reset-msb-db must exit 0:\n{}",
        stderr_of(&reset)
    );
    harness.assert_no_selection("doctor --reset-msb-db");
}

#[test]
fn a_failed_initial_acquisition_leaves_the_selection_absent() {
    // Success-before-adoption (M1): an unreachable recommendation must leave no
    // record, so a later compatible recommendation can still rescue the user.
    for (verb, argv) in [
        ("probe", vec!["probe"]),
        ("pull", vec!["pull"]),
        ("setup", vec!["setup"]),
    ] {
        let harness = Harness::new();
        harness.write_project(PROBE_TOOL);
        let out = harness.builtin(&argv, &[("AGENT_VM_TEST_DEFAULT_IMAGE", DEFAULT_REF)]);
        assert!(
            !out.status.success(),
            "{verb}: an unreachable default must fail:\n{}",
            stderr_of(&out)
        );
        harness.assert_no_selection(verb);
        let doctor = stdout_of(
            &harness.builtin(&["doctor"], &[("AGENT_VM_TEST_DEFAULT_IMAGE", DEFAULT_REF)]),
        );
        assert!(
            doctor.contains("not selected; initial recommendation"),
            "{verb}: doctor must still report an uninitialized default:\n{doctor}"
        );
    }
}

#[test]
fn a_retained_selection_survives_a_changed_recommendation() {
    // The saved bookmark, not the launcher's current recommendation, decides a
    // default launch. Changing the seam (a simulated launcher upgrade) and then
    // removing it must not move the selection or rewrite the record.
    let harness = Harness::new();
    harness.write_project(PROBE_TOOL);
    harness.write_selection_ref(DEFAULT_REF);
    let before = harness.selection_bytes().unwrap();

    for envs in [
        vec![("AGENT_VM_TEST_DEFAULT_IMAGE", RECOMMENDATION_B)],
        vec![],
    ] {
        let out = harness.launch_argv("probe", &[], &envs);
        let stderr = stderr_of(&out);
        assert!(
            !out.status.success(),
            "the bogus retained image must fail acquisition:\n{stderr}"
        );
        assert_eq!(
            oci_reference(&debug_config_json(&stderr)),
            REDACTED_DEFAULT_MARKER,
            "the retained image, not the recommendation, must be booted:\n{stderr}"
        );
        assert!(
            !stderr.contains(DEFAULT_REF) && !stderr.contains(RECOMMENDATION_B),
            "neither the retained record nor the recommendation may leak:\n{stderr}"
        );
        assert_eq!(
            harness.selection_bytes().unwrap(),
            before,
            "the retained record must be byte-identical"
        );

        let doctor = stdout_of(&harness.builtin(&["doctor"], &envs));
        assert!(
            doctor.contains("default: retained default ["),
            "doctor must report the retained selection safely:\n{doctor}"
        );
        assert!(
            doctor.contains("selected (without --image): retained default ["),
            "doctor must select the retained image safely:\n{doctor}"
        );
        assert!(
            !doctor.contains(DEFAULT_REF) && !doctor.contains(RECOMMENDATION_B),
            "doctor must not echo a default-tier reference:\n{doctor}"
        );
    }

    // A *separate* fresh HOME initialized with B yields B: the recommendation is
    // still what an uninitialized host is offered.
    let other = Harness::new();
    other.write_project(PROBE_TOOL);
    let out = other.launch_argv(
        "probe",
        &[],
        &[("AGENT_VM_TEST_DEFAULT_IMAGE", RECOMMENDATION_B)],
    );
    assert_eq!(
        oci_reference(&debug_config_json(&stderr_of(&out))),
        REDACTED_DEFAULT_MARKER
    );
    assert!(
        !stderr_of(&out).contains(RECOMMENDATION_B),
        "an uninitialized recommendation must not leak either"
    );
}

#[test]
fn explicit_sources_leave_the_selection_untouched() {
    // Neither an absent nor a present record may be read, adopted or rewritten
    // by a higher-precedence source.
    for (name, cli, env, user, project, expected) in [
        ("cli", Some(CLI_REF), None, None, None, CLI_REF),
        ("env", None, Some(ENV_REF), None, None, ENV_REF),
        ("user", None, None, Some(USER_REF), None, USER_REF),
        ("project", None, None, None, Some(PROJECT_REF), PROJECT_REF),
    ] {
        let harness = Harness::new();
        write_image_tiers(
            &harness,
            ImageTiers {
                user,
                project,
                declares_tool: true,
            },
        );
        harness.write_selection_ref(DEFAULT_REF);
        let before = harness.selection_bytes().unwrap();
        let mut envs: Vec<(&str, &str)> = vec![("AGENT_VM_TEST_DEFAULT_IMAGE", RECOMMENDATION_B)];
        if let Some(env) = env {
            envs.push(("AGENT_VM_IMAGE_TAG", env));
        }
        let mut argv: Vec<&str> = Vec::new();
        if let Some(cli) = cli {
            argv.push("--image");
            argv.push(cli);
        }
        let out = harness.launch_argv("probe", &argv, &envs);
        let stderr = stderr_of(&out);
        assert_eq!(
            oci_reference(&debug_config_json(&stderr)),
            expected,
            "{name}: the higher source must win"
        );
        assert_eq!(
            harness.selection_bytes().unwrap(),
            before,
            "{name}: the retained record must be untouched"
        );
    }

    // With the record absent, an explicit source must not create one.
    let harness = Harness::new();
    write_image_tiers(
        &harness,
        ImageTiers {
            user: None,
            project: Some(PROJECT_REF),
            declares_tool: true,
        },
    );
    let out = harness.launch_argv(
        "probe",
        &[],
        &[("AGENT_VM_TEST_DEFAULT_IMAGE", DEFAULT_REF)],
    );
    assert_eq!(
        oci_reference(&debug_config_json(&stderr_of(&out))),
        PROJECT_REF
    );
    harness.assert_no_selection("explicit project image with an absent record");
}

#[test]
fn a_corrupt_selection_fails_closed_and_never_repairs() {
    const CORRUPT: &str = "{\"version\":1,\"image\":\"sk-SENSITIVE-TOKEN\"}\n";
    let harness = Harness::new();
    harness.write_project(PROBE_TOOL);
    harness.write_selection(CORRUPT);
    let before = harness.selection_bytes().unwrap();

    // No higher source: the damaged record is a hard error *before* any
    // acquisition or config dump, and its bytes are never repaired.
    let out = harness.launch_argv(
        "probe",
        &[],
        &[("AGENT_VM_TEST_DEFAULT_IMAGE", RECOMMENDATION_B)],
    );
    let stderr = stderr_of(&out);
    assert!(
        !out.status.success(),
        "a corrupt record must fail the launch:\n{stderr}"
    );
    assert!(
        stderr.contains("default-image.json") && stderr.contains("restore the intended digest"),
        "the error must name the escaped path and a recovery:\n{stderr}"
    );
    assert!(
        !stderr.contains(CONFIG_MARKER),
        "a corrupt record must fail before any acquisition:\n{stderr}"
    );
    // M2: neither the token nor the record bytes may appear anywhere.
    assert!(
        !stderr.contains("sk-SENSITIVE-TOKEN") && !stderr.contains("sk-SENSITIVE"),
        "the diagnostic leaked the record contents:\n{stderr}"
    );
    assert_eq!(harness.selection_bytes().unwrap(), before);

    // A valid explicit override still works, without parsing or rewriting it.
    let out = harness.launch_argv(
        "probe",
        &["--image", CLI_REF],
        &[("AGENT_VM_TEST_DEFAULT_IMAGE", DEFAULT_REF)],
    );
    let stderr = stderr_of(&out);
    assert_eq!(oci_reference(&debug_config_json(&stderr)), CLI_REF);
    assert_eq!(harness.selection_bytes().unwrap(), before);

    // Doctor reports the damage and exits nonzero while still rendering every
    // section it can.
    let doctor = harness.builtin(&["doctor"], &[("AGENT_VM_TEST_DEFAULT_IMAGE", DEFAULT_REF)]);
    let stdout = stdout_of(&doctor);
    assert!(
        !doctor.status.success(),
        "doctor must exit nonzero for a damaged default:\n{stdout}"
    );
    assert!(
        stdout.contains("==> boot image") && stdout.contains("default: error:"),
        "doctor must render the section and the error:\n{stdout}"
    );
    assert!(
        !stdout.contains("sk-SENSITIVE"),
        "doctor's message leaked the record contents:\n{stdout}"
    );
}

/// M2 tracing: a default-tier invocation must not let the *dependency* image
/// stack (`oci_client`, `microsandbox`, `reqwest`, `hyper`) log the
/// record-sourced reference under `RUST_LOG=trace`. The explicit-source control
/// proves dependency tracing is otherwise enabled, so the assertion is
/// discriminating and explicit-source behavior is unchanged.
#[test]
fn a_default_tier_invocation_suppresses_dependency_image_tracing() {
    const SENSITIVE_REPO: &str = "followup-private-retained-token";
    const SENSITIVE: &str = "localhost:1/followup-private-retained-token@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    let harness = Harness::new();
    harness.write_selection_ref(SENSITIVE);
    let mut cmd = harness.base_command();
    cmd.env("RUST_LOG", "trace")
        .env("AGENT_VM_TEST_DEFAULT_IMAGE", RECOMMENDATION_B);
    let out = Harness::run_on(cmd, &["pull"]);
    assert!(
        !out.status.success(),
        "the bogus retained ref must fail the pull"
    );
    let combined = format!("{}{}", stdout_of(&out), stderr_of(&out));
    assert!(
        !combined.contains(SENSITIVE_REPO) && !combined.contains(SENSITIVE),
        "dependency tracing leaked the default-tier reference:\n{combined}"
    );
    assert!(
        combined.contains(REDACTED_DEFAULT_MARKER),
        "the debug-config display copy must still be redacted:\n{combined}"
    );
    assert!(
        combined.contains("pulling the default boot image failed"),
        "the failure must stay a fixed stage reason:\n{combined}"
    );

    // Positive control: an explicit source keeps dependency tracing. If this
    // control did not see the log, the redaction assertion above would prove
    // nothing.
    let explicit = Harness::new();
    let mut cmd = explicit.base_command();
    cmd.env("RUST_LOG", "trace")
        .env("AGENT_VM_IMAGE_TAG", "localhost:1/cli-explicit:latest");
    let out = Harness::run_on(cmd, &["pull"]);
    assert!(
        !out.status.success(),
        "the explicit bogus ref must fail too"
    );
    let combined = format!("{}{}", stdout_of(&out), stderr_of(&out));
    assert!(
        combined.contains("oci_client::client") && combined.contains("cli-explicit"),
        "explicit-source dependency tracing must stay enabled (positive control):\n{combined}"
    );
}

/// The defect this pins: a *valid* higher source must not mask a damaged
/// default in `doctor`. The launch still honours the override, but the
/// diagnosis of the full state is nonzero after printing every section.
#[test]
fn doctor_reports_a_damaged_default_even_with_a_valid_override() {
    let harness = Harness::new();
    harness.write_selection("{\"version\":1,\"image\":\"sk-CORRUPT-TOKEN\"}\n");
    let before = harness.selection_bytes().unwrap();

    let doctor = harness.builtin(&["doctor"], &[("AGENT_VM_IMAGE_TAG", ENV_REF)]);
    let stdout = stdout_of(&doctor);
    assert!(
        !doctor.status.success(),
        "a damaged default must fail doctor even when a valid override wins the \
         launch:\n{stdout}"
    );
    assert!(stdout.contains("==> boot image"), "{stdout}");
    assert!(stdout.contains("default: error:"), "{stdout}");
    assert!(
        stdout.contains(&format!(
            "selected (without --image): {ENV_REF} (from AGENT_VM_IMAGE_TAG)"
        )),
        "the valid override must still be shown:\n{stdout}"
    );
    assert!(
        !stdout.contains("sk-CORRUPT"),
        "the damaged record must not leak:\n{stdout}"
    );
    assert_eq!(harness.selection_bytes().unwrap(), before);
}

/// M2: a record-sourced reference never reaches a notice, the debug-config
/// display copy, progress, or an acquisition error chain — even when valid.
#[test]
fn a_default_tier_reference_is_redacted_across_output() {
    const SENSITIVE: &str = "localhost:1/private-retained-token@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let harness = Harness::new();
    harness.write_project(PROBE_TOOL);
    harness.write_selection_ref(SENSITIVE);
    let before = harness.selection_bytes().unwrap();

    // A default-tier launch: notice, debug dump and failure are all redacted.
    let out = harness.launch_argv(
        "probe",
        &[],
        &[("AGENT_VM_TEST_DEFAULT_IMAGE", RECOMMENDATION_B)],
    );
    let stderr = stderr_of(&out);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains("==> Boot image: the default boot image"),
        "the default notice must be a fixed label:\n{stderr}"
    );
    assert_eq!(
        oci_reference(&debug_config_json(&stderr)),
        REDACTED_DEFAULT_MARKER,
        "the display copy must redact the image reference:\n{stderr}"
    );
    assert!(
        stderr.contains("booting a sandbox from the default boot image failed"),
        "acquisition failure must be a fixed, stage-specific reason:\n{stderr}"
    );
    assert!(
        !stderr.contains(SENSITIVE) && !stderr.contains(RECOMMENDATION_B),
        "neither the retained record nor the recommendation may leak:\n{stderr}"
    );
    assert_eq!(harness.selection_bytes().unwrap(), before);

    // `pull` writes its selection notice to stdout and the dump/error to stderr.
    let pull = harness.builtin(
        &["pull"],
        &[("AGENT_VM_TEST_DEFAULT_IMAGE", RECOMMENDATION_B)],
    );
    assert!(!pull.status.success());
    let combined = format!("{}{}", stdout_of(&pull), stderr_of(&pull));
    assert!(
        combined.contains("the default boot image is the image this configuration boots from"),
        "pull must name the default safely:\n{combined}"
    );
    assert!(
        combined.contains(REDACTED_DEFAULT_MARKER),
        "pull's display copy must redact the reference:\n{combined}"
    );
    assert!(
        !combined.contains(SENSITIVE) && !combined.contains(RECOMMENDATION_B),
        "pull leaked a default-tier reference:\n{combined}"
    );

    // An *uninitialized* host (recommendation only) is redacted too.
    let fresh = Harness::new();
    fresh.write_project(PROBE_TOOL);
    let out = fresh.launch_argv("probe", &[], &[("AGENT_VM_TEST_DEFAULT_IMAGE", SENSITIVE)]);
    let stderr = stderr_of(&out);
    assert!(
        !stderr.contains(SENSITIVE),
        "the initial recommendation leaked:\n{stderr}"
    );
    assert_eq!(
        oci_reference(&debug_config_json(&stderr)),
        REDACTED_DEFAULT_MARKER
    );
}

#[test]
fn the_selection_is_scoped_to_user_home_not_state_or_cwd() {
    let harness = Harness::new();
    harness.write_project(PROBE_TOOL);
    harness.write_selection_ref(DEFAULT_REF);
    let before = harness.selection_bytes().unwrap();

    // A different project cwd and a different state root must not move the
    // bookmark: it is user-scoped, not cache- or project-scoped. The state root
    // stays short, or the sandbox control socket exceeds `sun_path`.
    let elsewhere = tempfile::tempdir_in("/tmp").unwrap();
    let mut cmd = harness.base_command();
    cmd.env("AGENT_VM_TEST_DEFAULT_IMAGE", RECOMMENDATION_B)
        .env("AGENT_VM_STATE_DIR", elsewhere.path())
        .current_dir(elsewhere.path());
    let out = Harness::run_on(cmd, &["shell"]);
    let stderr = stderr_of(&out);
    assert_eq!(
        oci_reference(&debug_config_json(&stderr)),
        REDACTED_DEFAULT_MARKER,
        "the retained default must not follow the state root or cwd:\n{stderr}"
    );
    assert_eq!(harness.selection_bytes().unwrap(), before);

    // A different HOME is genuinely independent.
    let other = Harness::new();
    other.assert_no_selection("a different HOME");
}
