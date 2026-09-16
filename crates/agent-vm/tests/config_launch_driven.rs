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
//! per-project state dir. The contents were captured from the pre-#82 binary
//! at commit `bb299d1` (the mechanical capture path is
//! `UPDATE_LAUNCH_GOLDENS=1`, see [`assert_matches_golden`]).
//!
//! The comparison is deliberately **not** byte-for-byte on every field. Three
//! classes of value are host- or platform-dependent and are normalized (or
//! dropped) so the fixtures are CI-portable across this macOS/arm64 host and
//! the ubuntu x86_64 CI leg:
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
//!   platform (macOS canonicalizes `/tmp` → `/private/tmp`) — are dropped.
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
        let project = tempfile::tempdir_in("/tmp").unwrap();
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

    /// Replace every location-dependent token so a golden is reproducible.
    fn normalize(&self, state_dir: &Path, text: &str) -> String {
        // Longest path first: `state_dir` is `state_root/<hash>`, so it must
        // be replaced before its `state_root` prefix.
        let replacements = [
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
        ];
        let mut out = text.to_string();
        for (from, to) in replacements {
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
        // Drop the `Mkdir` patches: they are a mechanical function of the
        // project path's ancestors, which differ by platform (macOS
        // canonicalizes `/tmp` -> `/private/tmp`, Linux does not). They are not
        // what this fixture guards; every other patch (the `/etc/passwd`
        // identity append, already tokenized) is kept.
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

fn golden_path(tool: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/config-launch")
        .join(format!("{tool}.golden"))
}

/// `UPDATE_LAUNCH_GOLDENS=1` rewrites the fixtures instead of asserting, so a
/// future intentional default change has a mechanical update path. The
/// fixtures in-tree were captured from `bb299d1` (pre-#82 `main`).
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
        "launch observation for {tool} changed vs the {tool} golden captured at bb299d1\n\
         (rerun with UPDATE_LAUNCH_GOLDENS=1 only if the change is intentional)"
    );
}

// ---------------------------------------------------------------------------
// E1 / E2 — the headline acceptance criterion
// ---------------------------------------------------------------------------

#[test]
fn default_tools_launch_identically_to_main() {
    for tool in DEFAULT_TOOLS {
        let harness = Harness::new();
        let out = harness.launch_default(tool);
        assert_matches_golden(tool, &observation(&harness, &out));
    }
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
fn a_misspelled_builtin_under_a_broken_config_reports_the_typo_not_the_config() {
    let harness = Harness::new();
    harness.write_project(BROKEN);

    let out = harness.base_command().arg("doctro").output().unwrap();
    assert!(!out.status.success(), "`doctro` must fail");
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("unrecognized subcommand"),
        "a near-miss on a built-in must defer to clap: {stderr}"
    );
    assert!(
        stderr.contains("doctor"),
        "the did-you-mean must name `doctor`: {stderr}"
    );
    assert!(
        !stderr.contains("config:"),
        "the config error must not mask the verb typo: {stderr}"
    );
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
