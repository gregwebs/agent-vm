//! Boot-free end-to-end proof that the **tool catalog drives the CLI** (issue
//! #82), replacing #80's `config_launch_unchanged.rs` (whose premise — "config
//! is inert on every launch path" — #82 inverts).
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
//! `tests/fixtures/config-launch/<tool>.golden` records, for each of the five
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
//! real user gets. That is what lets the goldens pin `runtime.workdir` and the
//! project mount's `guest` at the real `$PROJECT` value `main` produces,
//! instead of collapsing two platform-dependent shapes to one token.
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

/// Bogus-but-well-formed image ref: never resolves, so the run fails *after*
/// the debug dumps (its pull is what fails), which is exactly the stage these
/// tests need.
const BOGUS_IMAGE: &str = "localhost:1/does-not-exist:latest";
const CONFIG_MARKER: &str = "[debug] sandbox config JSON: ";
const GUEST_CMD_MARKER: &str = "[debug] guest command: ";

/// The five shipped default tools, in `default-tools.toml` order.
const DEFAULT_TOOLS: [&str; 5] = ["codex", "opencode", "claude", "copilot", "shell"];

/// The tool-independent guest `PATH` every default tool launches with. Pinned
/// both by the goldens and by [`assert_tool_dependent_content`].
const PATH_VALUE: &str = "/opt/agent/.local/bin:/opt/agent/.claude/local/bin:/opt/agent/.opencode/bin:/usr/local/bin:/usr/bin:/usr/sbin:/bin";

/// The resolved guest command line each default tool must produce with no user
/// args (`command` + `argv`). Transcribed by hand from `run::Agent`'s
/// `command()`/`default_args()` as of `bb299d1` — the pre-#82 binary has no
/// debug line for this, so it cannot be captured; see the module docs.
const LEGACY_GUEST_COMMANDS: [(&str, &str); 5] = [
    ("codex", "codex"),
    ("opencode", "opencode"),
    ("claude", "claude --dangerously-skip-permissions"),
    ("copilot", "copilot --allow-all-tools"),
    ("shell", "bash -O histappend"),
];

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

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn write(path: &Path, contents: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
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
        // The project root deliberately lives off the guest's tmpfs prefixes
        // (`/tmp`, `/run`, `/dev/shm`, `/var/run`) so `run::resolve_project_guest_path`
        // mirrors it in the guest on every platform — the shape every real user
        // gets — instead of falling back to `/workspace`. Cargo sets
        // `CARGO_TARGET_TMPDIR` (under `target/`) for exactly this. `HOME` and
        // `AGENT_VM_STATE_DIR` stay under `/tmp`: a shorter state path keeps the
        // sandbox's control socket inside the `sun_path` limit (CONTRIBUTING.md).
        let project = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
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
        let mut cmd = self.base_command();
        cmd.arg(tool).args(["--image", BOGUS_IMAGE]).args(extra);
        run_with_timeout(cmd, Duration::from_secs(20))
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
        // Drop the `Mkdir` patches: they are a mechanical function of the
        // project path's ancestors, which differ by platform (macOS
        // canonicalizes `/tmp` -> `/private/tmp`, Linux does not, and the
        // checkout path itself differs). They are not what this fixture guards;
        // every other patch (the `/etc/passwd` identity append, already
        // tokenized) is kept.
        if let Some(patches) = value
            .get_mut("patches")
            .and_then(|patches| patches.as_array_mut())
        {
            patches.retain(|patch| patch.get("Mkdir").is_none());
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
    assert_eq!(
        env_of("PATH"),
        Some(PATH_VALUE),
        "PATH env changed for {tool}"
    );
    let expects_codex_home = matches!(tool, "codex" | "shell");
    assert_eq!(
        env_of("CODEX_HOME"),
        expects_codex_home.then_some("/agent-vm-state/codex"),
        "CODEX_HOME must be emitted only for the tools that declare it ({tool})"
    );

    // The credential secret set follows the verb's provisioning set.
    let secrets = config["network"]["secrets"]["secrets"].as_array().unwrap();
    let env_vars: Vec<&str> = secrets
        .iter()
        .map(|secret| secret["env_var"].as_str().unwrap())
        .collect();
    let expected_env_vars: &[&str] = match tool {
        "codex" => &["MSB_AGENT_VM_OPENAI_UNUSED"],
        "opencode" => &[
            "MSB_AGENT_VM_OPENAI_UNUSED",
            "MSB_AGENT_VM_OPENCODE_OPENAI_UNUSED",
        ],
        "claude" => &["MSB_AGENT_VM_ANTHROPIC_UNUSED"],
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
    for secret in secrets {
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
    let rules = config["network"]["intercept"]["rules"].as_array().unwrap();
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
        "codex" | "opencode" => &[("auth.openai.com", "/oauth/token")],
        "claude" => &[("platform.claude.com", "/v1/oauth/token")],
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

fn golden_path(tool: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/config-launch")
        .join(format!("{tool}.golden"))
}

/// `UPDATE_LAUNCH_GOLDENS=1` rewrites the fixtures instead of asserting, so a
/// future intentional default change has a mechanical update path. The
/// fixtures in-tree were regenerated for #118 (the provisioning-set change).
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
        "launch observation for {tool} changed vs the {tool} golden regenerated for #118\n\
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
     args = [\"--dangerously-skip-permissions\"]\nlayer = { builtin = \"claude\" }\n\
     credentials = [\"anthropic\"]\n";

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

/// **E2 (#119 D3a).** The launched tool's own `env` is published *before* the
/// launcher's, and the guest applies the array last-wins, so a config that
/// declares `PATH` cannot redirect the guest: the launcher's later emission
/// wins. This is the footgun guard that stops a project config from
/// *accidentally* redirecting the launcher's own env — defence in depth on top
/// of ADR-0015's trust boundary (a declaration that sets `env` can already set
/// `command` and `args`, i.e. run arbitrary guest code), not a substitute for
/// it.
///
/// Deliberately does **not** call [`assert_tool_dependent_content`] (M1): its
/// `env_of` is a first-match `.find()`, so it would read the *first* `PATH`
/// here — the declared `/evil` — and fail. E2 defines its own last-match helper
/// instead; the shared helper's `.find()` stays correct for the shipped tools,
/// which declare no colliding key.
#[test]
fn project_tool_env_is_overridden_by_the_launchers_own_env() {
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

    let last_path = env
        .iter()
        .rposition(|(key, _)| *key == "PATH")
        .expect("PATH must be published");
    assert_eq!(
        env[last_path].1, PATH_VALUE,
        "the launcher's PATH must win over the tool's declaration"
    );
    assert!(
        avm_test < last_path,
        "the tool's env must be published before the launcher's PATH"
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

/// **E2c (#119 D3b).** The launcher's *unconditional* env — `PATH`,
/// `IS_SANDBOX`, `LANG` (see `run::GUEST_ALWAYS_ENV`, `run.rs:49`) — really is
/// published on every launch, root mode included. This is the premise that
/// licenses leaving those three *out* of `check_env_key`'s rejection set:
/// position, not validation, protects them. **If this test ever fails, either
/// restore the unconditional emission or add that key to `check_env_key`'s
/// rejection set — D3b.** Root mode is the case that removed
/// `HOME`/`USER`/`LOGNAME` and so the case that could plausibly remove these.
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
        assert_eq!(env_of("PATH"), Some(PATH_VALUE), "{extra:?}");
        assert_eq!(env_of("IS_SANDBOX"), Some("1"), "{extra:?}");
        assert_eq!(env_of("LANG"), Some("C.UTF-8"), "{extra:?}");
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
