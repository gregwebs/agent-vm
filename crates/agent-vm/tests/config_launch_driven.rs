//! Boot-free end-to-end proof that the **tool catalog drives the CLI** (issue
//! #82).
//!
//! `mount_follow_links.rs` established the technique: drive the real binary
//! with a controlled `HOME`/`AGENT_VM_STATE_DIR`/cwd, a fake version-only
//! `MSB_PATH`, `AGENT_VM_DEBUG_CONFIG=1`, and a CLI-imported native image.
//! Execution runs all the way to `builder.build()`, which dumps the real
//! `SandboxConfig` JSON to stderr, then a `[debug] guest command:` line, and
//! only then fails at the deliberately nonfunctional runtime. Reaching those lines
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

/// A loopback spelling imported only by builder-dependent tests. Cold tests
/// deliberately leave it absent to exercise acquisition refusal.
const BOGUS_IMAGE: &str = "localhost:1/does-not-exist:latest";
const CONFIG_MARKER: &str = "[debug] sandbox config JSON: ";
const GUEST_CMD_MARKER: &str = "[debug] guest command: ";

/// The cause-and-fix tail of a `tools` miss whose name nothing retained declares
/// (a typo, or an agent a custom catalog dropped).
const TYPO_REFERENCE_SENTENCE: &str =
    "names no tool in this configuration file; declare it in this file or remove the entry";

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

#[path = "support/acquisition_gate.rs"]
mod acquisition_gate;
#[path = "support/fake_msb.rs"]
mod fake_msb;
#[path = "support/image_archive.rs"]
mod image_archive;
#[path = "support/oci_registry.rs"]
mod oci_registry;

fn write_fake_msb(dir: &Path) -> PathBuf {
    // A credential-bearing launch makes the SDK probe `<msb> __launch-protocol`
    // and require `header_credentials: true` in the JSON reply (microsandbox
    // 0.7.x replaced the 0.6.x `__capabilities` + `header-credential-launch-v1`
    // line; see the vendored sdk/rust/lib/runtime/launch_contract.rs).
    // `protocols` must contain 2 for a restore-backed launch. Every invocation
    // is logged (argv and environment) by the shared installer, so a test can
    // assert the probe actually happened rather than inferring it from the
    // absence of an error. The pair fixture is complete: 0.7.4's resolver
    // refuses an `msb` with no adjacent libkrunfw, and a version-only script is
    // not a launch seam.
    fake_msb::install_pair(dir, fake_msb::Mode::LaunchSeam).path
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

fn assert_cold_preparation_failure(h: &Harness, out: &Output) {
    let text = stderr_of(out);
    assert!(!out.status.success(), "{text}");
    assert!(text.contains("preparing the boot image"), "{text}");
    assert!(!text.contains(CONFIG_MARKER), "builder ran: {text}");
    assert!(
        !text.contains(GUEST_CMD_MARKER),
        "guest command was built: {text}"
    );
    assert!(
        !h.home_root
            .join(".config/agent-vm/image-pins.json")
            .exists()
    );
    h.assert_no_selection("failed acquisition");
    assert!(
        h.msb_log().lines().all(|line| line == "--version"),
        "{}",
        h.msb_log()
    );
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
/// Which spelling of the direct route (#398) a launch uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Form {
    /// `agent-vm [launch options] run PROGRAM [ARG...]`
    Run,
    /// `agent-vm [launch options] -- PROGRAM [ARG...]`
    Separator,
}

const DIRECT_FORMS: [Form; 2] = [Form::Run, Form::Separator];

/// One direct launch: the spelling, the launch options before it, the guest
/// command vector after it, and any extra host environment.
struct DirectInvocation<'a> {
    form: Form,
    options: &'a [&'a str],
    vector: &'a [&'a str],
    envs: &'a [(&'a str, &'a str)],
}

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

    /// Import genuine host-valid bytes through the public CLI. Import alone
    /// must not create approval/default records; first launch still proves that.
    fn warm() -> Self {
        let h = Self::new();
        let archive = h.home_root.join("builder-image.tar");
        image_archive::write(&archive, &image_archive::ArchiveSpec::default());
        let aliases = [
            BOGUS_IMAGE,
            CLI_REF,
            ENV_REF,
            USER_REF,
            PROJECT_REF,
            default_ref(),
            recommendation_b(),
        ];
        let mut input = tar::Archive::new(std::fs::File::open(&archive).unwrap());
        let mut output = tar::Builder::new(Vec::new());
        for entry in input.entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().into_owned();
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            if path == Path::new("index.json") {
                let mut index: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                let descriptor = index["manifests"][0].clone();
                index["manifests"] = aliases
                    .iter()
                    .map(|alias| {
                        let mut descriptor = descriptor.clone();
                        descriptor["annotations"] = serde_json::json!({
                            "org.opencontainers.image.ref.name": alias
                        });
                        descriptor
                    })
                    .collect();
                bytes = serde_json::to_vec(&index).unwrap();
            }
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            output
                .append_data(&mut header, path, bytes.as_slice())
                .unwrap();
        }
        std::fs::write(&archive, output.into_inner().unwrap()).unwrap();
        let out = h.builtin(
            &[
                "image",
                "import",
                "--input",
                archive.to_str().unwrap(),
                "--tag",
                BOGUS_IMAGE,
            ],
            &[],
        );
        assert!(
            out.status.success(),
            "fixture import failed: {}",
            stderr_of(&out)
        );
        assert!(
            !h.home_root
                .join(".config/agent-vm/image-pins.json")
                .exists()
        );
        h.assert_no_selection("fixture import");
        h
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

    /// Replace the shell fixture with a real compiled runtime binary so the
    /// SDK selects its modern launch contract and `create` reaches native cache
    /// consumption. See `fake_msb::install_launch_binary` for why a script is
    /// not sufficient.
    fn use_launch_runtime(&mut self) {
        let dir = self.fake_msb.parent().unwrap();
        let fixture = fake_msb::install_launch_binary(
            dir,
            &self.fake_msb.with_file_name("msb-invocations.log"),
            &self.fake_msb.with_file_name("msb-environ.log"),
        );
        self.fake_msb = fixture.path;
    }

    /// The ambient cache a shared-cache launch uses.
    fn shared_command(&self, cache: &Path) -> Command {
        let mut cmd = self.base_command();
        cmd.env("AGENT_VM_SHARE_MSB_CACHE", "1")
            .env("AGENT_VM_MSB_CACHE_DIR", cache);
        cmd
    }

    /// Run a boot-free image verb against an explicit shared cache.
    fn run_shared(&self, cache: &Path, args: &[&str]) -> Output {
        let mut cmd = self.shared_command(cache);
        cmd.args(args);
        run_with_timeout(cmd, Duration::from_secs(60))
    }

    fn image(&self, spec: &image_archive::ArchiveSpec) -> oci_registry::Image {
        let path = self.home_root.join(format!("{}.tar", spec.marker));
        oci_registry::Image::from_archive(&path, spec)
    }

    fn write_user(&self, contents: &str) {
        write(&self.user_config(), contents);
    }

    fn write_user_mode(&self, contents: &str, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        self.write_user(contents);
        std::fs::set_permissions(self.user_config(), std::fs::Permissions::from_mode(mode))
            .unwrap();
        std::fs::set_permissions(
            self.user_config().parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }
    fn symlink_user_config(&self, target: &Path) {
        std::fs::create_dir_all(self.user_config().parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(target, self.user_config()).unwrap();
    }

    fn write_project(&self, contents: &str) {
        write(&self.project_config(), contents);
    }

    /// Launch `tool` against the bogus image with the given launch options.
    fn launch(&self, tool: &str, options: &[&str]) -> Output {
        self.launch_with_env(tool, options, &[])
    }

    /// [`Self::launch`] with extra host environment variables.
    fn launch_with_env(&self, tool: &str, options: &[&str], envs: &[(&str, &str)]) -> Output {
        let mut argv: Vec<&str> = vec!["--image", BOGUS_IMAGE];
        argv.extend_from_slice(options);
        self.launch_argv(tool, &argv, envs)
    }

    /// Exact launch options, so image-selection tests can omit the typed override.
    fn launch_argv(&self, tool: &str, options: &[&str], envs: &[(&str, &str)]) -> Output {
        self.launch_with_tool_args(tool, options, &[], envs)
    }

    /// `agent-vm [options…] run PROGRAM [ARG…]` or `… -- PROGRAM [ARG…]`
    /// (issue #398). Both spellings are the same direct route. Named fields
    /// because the launch options and the guest vector are both `&[&str]`.
    fn direct(&self, invocation: DirectInvocation<'_>) -> Output {
        let DirectInvocation {
            form,
            options,
            vector,
            envs,
        } = invocation;
        let mut cmd = self.base_command();
        for (key, value) in envs {
            cmd.env(key, value);
        }
        cmd.args(options);
        cmd.arg(match form {
            Form::Run => "run",
            Form::Separator => "--",
        });
        cmd.args(vector);
        run_with_timeout(cmd, Duration::from_secs(20))
    }

    /// `agent-vm <options…> <tool> <tool_args…>`: the full launch shape.
    fn launch_with_tool_args(
        &self,
        tool: &str,
        options: &[&str],
        tool_args: &[&str],
        envs: &[(&str, &str)],
    ) -> Output {
        let mut cmd = self.base_command();
        for (key, value) in envs {
            cmd.env(key, value);
        }
        cmd.args(options).arg(tool).args(tool_args);
        run_with_timeout(cmd, Duration::from_secs(20))
    }

    /// Every argv the fake `msb` was invoked with, in order. Empty when it was
    /// never invoked.
    fn msb_log(&self) -> String {
        std::fs::read_to_string(self.fake_msb.with_file_name("msb-invocations.log"))
            .unwrap_or_default()
    }

    /// Whether the fake `msb` was probed for the header-credential capability.
    fn msb_environ(&self) -> String {
        std::fs::read_to_string(self.fake_msb.with_file_name("msb-environ.log")).unwrap_or_default()
    }

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
        out.replace(fixture_digest(), "$FIXTURE_DIGEST")
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

/// The frozen sparse network an unconfigured builder carries — the pre-change
/// `dsh.golden` shape, from `88ea07b`. This is the *input* to the independent
/// dense materialization below, never a value read back from a launch.
fn sparse_default_network() -> serde_json::Value {
    serde_json::json!({
        "enabled": true,
        "ports": [],
        "strict": true,
        "max_connections": null,
        "trust_host_cas": false
    })
}

/// The launcher's default-deny egress policy (§3.1): every rule must be an
/// explicit allow, so the unconfigured default is the empty list.
fn default_deny_policy() -> serde_json::Value {
    serde_json::json!({"default_egress": "deny", "default_ingress": "allow", "rules": []})
}

/// Independently materialize the engine's dense network for a sparse input:
/// sparse -> engine `NetworkConfig` (dependency serde defaults) -> wire
/// `NetworkSpec`, with the launcher's default-deny policy substituted in place.
///
/// This mirrors `network::tests::default_plan_denies_all_egress_and_preserves_\
/// non_policy_network_config`'s oracle. It never calls `.network()`, the
/// credential overlay, or reads actual launch output, so it cannot bless a
/// non-policy mutation introduced by the builder closure.
fn dense_default_network() -> serde_json::Value {
    let dense: microsandbox_network::config::NetworkConfig =
        serde_json::from_value(sparse_default_network()).expect("sparse default network decodes");
    let wire: microsandbox::sandbox::NetworkSpec =
        serde_json::from_value(serde_json::to_value(&dense).unwrap()).unwrap();
    let mut value = serde_json::to_value(&wire).unwrap();
    // Replace, never `Value::remove` — with `preserve_order` that swap-removes
    // and relocates the last key.
    value["policy"] = default_deny_policy();
    value
}

/// Assert a launch that provisions nothing and requests no egress carries the
/// engine's dense defaults with only the launcher's default-deny policy. Pins
/// the empty authorization sets and disabled TLS from the engine's source
/// values, not from observed output.
fn assert_default_deny_zero_provision_network(network: &serde_json::Value, context: &str) {
    assert_eq!(
        network["policy"],
        default_deny_policy(),
        "{context}: policy"
    );
    assert_eq!(
        *network,
        dense_default_network(),
        "{context}: non-policy network mutated"
    );
    assert_eq!(
        network["tls"]["enabled"],
        serde_json::json!(false),
        "{context}"
    );
    assert_eq!(
        network["tls"]["intercepted_ports"],
        serde_json::json!([443]),
        "{context}"
    );
    assert_eq!(
        network["secrets"]["secrets"],
        serde_json::json!([]),
        "{context}"
    );
    assert!(
        network["secrets"].get("header_credentials").is_none(),
        "{context}: an empty header-credential set is wire-omitted"
    );
    assert_eq!(
        network["intercept"]["rules"],
        serde_json::json!([]),
        "{context}"
    );
    assert_eq!(
        network["intercept"]["hook"],
        serde_json::Value::Null,
        "{context}"
    );
    assert_eq!(
        network["intercept"]["max_request_bytes"],
        serde_json::json!(65536),
        "{context}"
    );
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

    // The credential secret set follows the verb's provisioning set. Every
    // launch now installs the launcher's default-deny policy via
    // `Plan::apply_to`, so `.network()` materializes the engine's dense
    // `secrets` subdocument for **every** tool, `dsh` included. `dsh` declares
    // no provider, so its resulting authorization set is an empty, **present**
    // object (never a missing one). Require a real array: a structurally
    // missing or malformed object must fail rather than default to empty.
    if matches!(tool, "dsh") {
        assert_default_deny_zero_provision_network(&config["network"], "dsh");
    }
    assert!(
        config["network"]["secrets"]["secrets"].is_array(),
        "{tool} must carry a present `secrets.secrets` array"
    );
    let secrets = config["network"]["secrets"]["secrets"]
        .as_array()
        .expect("secrets.secrets is an array")
        .clone();
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
        "pi" => &[
            "MSB_AGENT_VM_ANTHROPIC_UNUSED",
            "MSB_AGENT_VM_OPENAI_UNUSED",
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
    // `dsh` has no proxied route, so its intercept body is the serde default;
    // because `.network()` now always runs, that **inactive** body is present
    // rather than absent. Assert its presence explicitly, and require a real
    // rules array rather than defaulting a missing field to empty.
    assert!(
        config["network"]["intercept"].is_object(),
        "{tool} must carry the `intercept` object"
    );
    let rules = config["network"]["intercept"]["rules"]
        .as_array()
        .expect("intercept.rules is an array")
        .clone();
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
        "claude" => &[("platform.claude.com", "/v1/oauth/token")],
        "pi" => &[
            ("platform.claude.com", "/v1/oauth/token"),
            ("auth.openai.com", "/oauth/token"),
        ],
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
    if matches!(tool, "dsh" | "copilot") {
        assert_eq!(
            config["network"]["intercept"],
            serde_json::json!({"rules": [], "hook": null, "max_request_bytes": 65536}),
            "{tool}'s intercept object must be the inactive serde default body"
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
    let harness = Harness::warm();
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
    let harness = Harness::warm();
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
    let harness = Harness::warm();
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
    assert!(rendered.contains("preparing the boot image"), "{rendered}");
    assert_cold_preparation_failure(&harness, &out);
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
    let harness = Harness::warm(); // seeds ~/.claude/.credentials.json
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
    let harness = Harness::warm();
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
    let harness = Harness::warm();
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
    let harness = Harness::warm();
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
    let control = Harness::warm();
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

/// Unsupported functionality remains refused under the override.
#[test]
fn the_override_does_not_bypass_an_unsupported_field() {
    let harness = Harness::new();
    harness.write_user(ONE_YAML_TOOL);
    write_credentials(
        &harness.home_root,
        "credentials:\n  - service: my-service\n    permissions:\n      network: [x]\n    apiKey:\n      name: MY_SERVICE_KEY\n      inject: [{domain: api.my-service.example, header: x-api-key, format: \"%s\"}]\n",
    );
    assert_the_override_does_not_bypass(&harness, "t", &[], "`permissions` is not supported");
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
    assert_the_override_does_not_bypass(&harness, "t", &[], "preparing the boot image");
}

/// Row 7: a tool-declared `env` key for an owned name is a hard error under both
/// policies. The value is ready so the launch reaches `assemble_guest_env`.
#[test]
fn the_override_does_not_bypass_a_tool_env_conflict() {
    let harness = Harness::warm();
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
    let harness = Harness::warm();
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
    let harness = Harness::warm();
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
        rendered.contains(CONFIG_MARKER),
        "the launch must have got past credential resolution past validated image preparation: {rendered}"
    );
}

/// D7: a replaced provider does not inherit the built-in requirement. Anthropic
/// is `required` by the `claude` tool, but the authorization is not, so the
/// launch proceeds instead of bailing.
#[test]
fn a_replaced_provider_does_not_inherit_the_built_in_requirement() {
    let harness = Harness::warm();
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

/// A renamed replacement never publishes the host's raw key (#163).
#[test]
fn a_renamed_replacement_does_not_forward_the_hosts_raw_key() {
    let harness = Harness::warm();
    write_credentials(
        &harness.home_root,
        "credentials:\n  - service: anthropic\n    apiKey:\n      name: MY_KEY\n      sentinelEnv: true\n      inject: [{domain: api.anthropic.example, header: x-api-key, format: \"%s\"}]\n",
    );
    let canary = "sk-CANARY-163-renamed";
    let out = harness.launch_with_env(
        "claude",
        &[],
        &[
            ("AGENT_VM_TEST_CREDENTIAL", "anthropic=sk-test-replacement"),
            ("ANTHROPIC_API_KEY", canary),
        ],
    );
    let rendered = format!("{}{}", stderr_of(&out), stdout_of(&out));
    assert!(!rendered.contains(canary));
    assert!(!rendered.contains("still forwarded"));
    let config = debug_config_json(&stderr_of(&out));
    assert!(
        !env_pairs(&config)
            .iter()
            .any(|(name, _)| *name == "ANTHROPIC_API_KEY")
    );
}

/// The asymmetric partner of the test above: when the authorization owns the
/// host's own variable name, nothing is forwarded and no notice fires.
#[test]
fn a_same_named_replacement_does_not_warn_about_raw_forwarding() {
    let harness = Harness::warm();
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

/// **R3/S2 (#162).** The replacement shape ADR-0025's own examples use: an
/// `opencode-static` authorization that names `OPENAI_API_KEY` and injects at
/// `api.openai.com`. The guest *does* get a working OpenAI key through the proxy
/// (the sentinel is published), yet agent-vm's capture gate captured no OpenAI
/// host credential, so it retires the `model` pin. That is the open decision S2
/// records; this test pins the observed behaviour so any change to the pin's
/// gate has to update it deliberately rather than by accident.
#[test]
fn a_sentinel_opencode_replacement_publishes_the_key_but_retires_the_model_pin() {
    let harness = Harness::warm();
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
/// end to end. `Harness::warm()` seeds the host device-flow token, so the
/// absence below is the replacement's doing, not a missing host credential.
#[test]
fn a_replaced_copilot_still_gets_its_trust_configuration_and_no_token() {
    let harness = Harness::warm();
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
        let harness = Harness::warm();
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
        let harness = Harness::warm();
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
    let harness = Harness::warm();
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
    let harness = Harness::warm();
    harness.write_project(
        "[[tools]]\nname = \"mytool\"\ncommand = \"/bin/echo\"\nargs = [\"--fast\"]\n",
    );

    let out = harness.launch_with_tool_args("mytool", &["--image", BOGUS_IMAGE], &["hi"], &[]);
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
    let harness = Harness::warm();
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
        let harness = Harness::warm();
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
    let harness = Harness::warm();
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
        let harness = Harness::warm();
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
        let harness = Harness::warm();
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
        let harness = Harness::warm();
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
    let harness = Harness::warm();
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
    let harness = Harness::warm();
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
    let harness = Harness::warm();
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
    let harness = Harness::warm();
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
    let harness = Harness::warm();
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
// `pi -> codex` provisioning (#360, the agent-vm-codex extension's credential)
// ---------------------------------------------------------------------------

/// T4 (#360): naming `codex` from `pi` follows ADR-0017 alternative 2, so
/// `openai` is provisioned but never required. A host with no Codex login must
/// therefore still get a `pi` launch, with no secret, no refresh route and no
/// guest placeholder. The removal is checked: a silently-failed `remove_file`
/// would let this pass on a host that still has a login.
#[test]
fn pi_without_a_host_codex_login_launches_and_wires_no_openai() {
    let harness = Harness::warm();
    let host_credential = harness.home_root.join(".codex/auth.json");
    std::fs::remove_file(&host_credential).unwrap();
    assert!(
        !host_credential.exists(),
        "the host Codex credential must be gone before the launch"
    );

    let out = harness.launch_default("pi");
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(CONFIG_MARKER),
        "pi must launch with no host Codex login: {stderr}"
    );
    let config = debug_config_json(&stderr);
    let state = state_dir(&stderr);

    assert!(
        !registered_secret_env_vars(&config).contains(&"MSB_AGENT_VM_OPENAI_UNUSED"),
        "a failed capture must register no OpenAI secret"
    );
    assert!(
        !intercept_rule_hosts(&config).contains(&"auth.openai.com"),
        "a failed capture must register no OpenAI refresh route"
    );
    assert!(
        !state.join("codex/auth.json").exists(),
        "a failed capture must write no guest Codex placeholder"
    );
}

/// T5 (#360). A successful capture **overwrites** a guest-authored
/// `codex/auth.json` with the placeholder -- the OpenAI provider's existing
/// `refresh_openai` behaviour, now reachable from a `pi` launch. The user impact
/// is documented in USAGE.md; this is the executable statement of it.
#[test]
fn a_pi_launch_overwrites_a_guest_authored_codex_credential_with_the_placeholder() {
    let harness = Harness::warm();
    // Assert the capture precondition explicitly; without it the guest credential
    // would remain and the placeholder assertion below would fail.
    assert!(
        harness.home_root.join(".codex/auth.json").exists(),
        "this test needs the harness's host Codex credential"
    );

    let state = probe_state_dir(&harness, "pi");
    let guest_credential = r#"{"tokens":{"access_token":"guest-codex-real-canary","refresh_token":"guest-codex-real-refresh-canary","account_id":"11111111-1111-1111-1111-111111111111"}}"#;
    write(&state.join("codex/auth.json"), guest_credential);

    let out = harness.launch_default("pi");
    let stderr = stderr_of(&out);
    assert!(stderr.contains(CONFIG_MARKER), "pi must launch: {stderr}");

    let after = std::fs::read_to_string(state.join("codex/auth.json")).unwrap();
    assert!(
        after.contains("msb-openai-placeholder-a-v2"),
        "a pi launch must overwrite a guest-authored Codex credential with the proxy placeholder: {after}"
    );
    assert!(
        !after.contains("guest-codex-real-canary"),
        "the guest-authored access token must be gone after capture: {after}"
    );
    assert!(
        !after.contains("guest-codex-real-refresh-canary"),
        "the guest-authored refresh token must be gone after capture: {after}"
    );
}

/// T6 (#360). The converse of T5, and the reason the overwrite is content-scoped:
/// when capture fails, the stale-placeholder clearer must leave a guest-authored
/// `codex/auth.json` byte-identical. An absent host credential is never licence
/// to delete a guest's own login.
#[test]
fn a_pi_launch_with_no_host_codex_login_spares_a_guest_authored_codex_credential() {
    let harness = Harness::warm();
    let host_credential = harness.home_root.join(".codex/auth.json");
    std::fs::remove_file(&host_credential).unwrap();
    assert!(
        !host_credential.exists(),
        "the host Codex credential must be gone before the launch"
    );

    let state = probe_state_dir(&harness, "pi");
    let guest_credential = r#"{"tokens":{"access_token":"guest-codex-real-spared-canary","refresh_token":"guest-codex-real-spared-refresh","account_id":"33333333-3333-3333-3333-333333333333"}}"#;
    write(&state.join("codex/auth.json"), guest_credential);

    let out = harness.launch_default("pi");
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(CONFIG_MARKER),
        "pi must still launch with no host Codex login: {stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(state.join("codex/auth.json")).unwrap(),
        guest_credential,
        "a guest-authored Codex credential must survive a pi launch that captured nothing"
    );
}

/// T7 (#360). The stale-placeholder ordering: `pi` now re-wires OpenAI, so the
/// placeholder a `codex` launch wrote is kept rather than deleted as unwired.
#[test]
fn a_codex_placeholder_survives_the_next_pi_launch() {
    let harness = Harness::warm();
    let codex = harness.launch_default("codex");
    let state = state_dir(&stderr_of(&codex));
    let placeholder = std::fs::read(state.join("codex/auth.json"))
        .expect("the codex launch writes the Codex placeholder");
    assert!(
        String::from_utf8_lossy(&placeholder).contains("msb-openai-placeholder-a-v2"),
        "expected the proxy placeholder, got: {placeholder:?}"
    );

    let pi = harness.launch_default("pi");
    assert!(
        stderr_of(&pi).contains(CONFIG_MARKER),
        "pi must launch: {}",
        stderr_of(&pi)
    );
    assert_eq!(
        std::fs::read(state.join("codex/auth.json"))
            .expect("a pi launch must not delete the placeholder it re-wires"),
        placeholder,
        "a pi launch must leave the codex-written placeholder in place"
    );
}

/// T8 (#360). The non-disclosure acceptance criterion, driven through the real
/// binary: three distinct canaries in the host Codex login must not appear in
/// anything the guest can read.
///
/// Three positive controls keep this from passing vacuously: the seeded host
/// document really holds all three canaries, capture really wrote the *access*
/// canary to the host-only `$STATE.secrets/openai`, and the guest document holds
/// the placeholders instead. Only `$STATE` is scanned -- `.secrets` is its
/// sibling, never a guest mount -- so a failure means launcher assembly leaked,
/// not that the scan was pointed at the wrong tree. This is not evidence about
/// Pi's runtime transport or the real backend (that is a manual credentialed
/// run).
#[test]
fn a_pi_launch_discloses_no_host_openai_token_bytes() {
    const ACCESS: &str = "canary-360-access-do-not-leak";
    const REFRESH: &str = "canary-360-refresh-do-not-leak";
    const ID_TOKEN: &str = "canary-360-id-token-do-not-leak";
    const ACCOUNT: &str = "22222222-2222-2222-2222-222222222222";

    let harness = Harness::warm();
    let host_path = harness.home_root.join(".codex/auth.json");
    write(
        &host_path,
        &format!(
            r#"{{"tokens":{{"access_token":"{ACCESS}","refresh_token":"{REFRESH}","id_token":"{ID_TOKEN}","account_id":"{ACCOUNT}"}}}}"#
        ),
    );

    let out = harness.launch_default("pi");
    let stdout = stdout_of(&out);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(CONFIG_MARKER),
        "pi must reach the real config assembly: {stderr}"
    );
    let config = debug_config_json(&stderr);
    let state = state_dir(&stderr);
    let secrets_sibling = PathBuf::from(format!("{}.secrets", state.display()));

    // -- positive controls: capture was exercised ---------------------------
    let seeded = std::fs::read_to_string(&host_path).unwrap();
    for canary in [ACCESS, REFRESH, ID_TOKEN] {
        assert!(
            seeded.contains(canary),
            "the seeded host document must hold {canary}"
        );
    }
    let captured = std::fs::read_to_string(secrets_sibling.join("openai"))
        .expect("capture must write the host-only OpenAI token file");
    assert!(
        captured.contains(ACCESS),
        "the host-only secret file must hold the access token -- without this the scan proves nothing"
    );
    let guest = std::fs::read_to_string(state.join("codex/auth.json"))
        .expect("a successful capture writes the guest Codex placeholder");
    for placeholder in [
        "msb-openai-placeholder-a-v2",
        "msb-openai-placeholder-r-v2",
        "msb-openai-placeholder-id-v2",
    ] {
        assert!(
            guest.contains(placeholder),
            "the guest document must hold {placeholder} instead: {guest}"
        );
    }
    assert!(
        guest.contains(ACCOUNT),
        "the account id is not a secret and must survive for codex: {guest}"
    );

    // -- (a) every regular file the guest can read under $STATE -------------
    let mut scanned = 0usize;
    for (path, bytes) in state_regular_files(&state) {
        scanned += 1;
        let text = String::from_utf8_lossy(&bytes);
        for canary in [ACCESS, REFRESH, ID_TOKEN] {
            assert!(!text.contains(canary), "{} leaks {canary}", path.display());
        }
    }
    assert!(
        scanned > 0,
        "the leak scan must have read guest-visible files"
    );

    // -- (b) the assembled guest environment --------------------------------
    for (key, value) in env_pairs(&config) {
        for canary in [ACCESS, REFRESH, ID_TOKEN] {
            assert!(
                !key.contains(canary) && !value.contains(canary),
                "{key} leaks {canary}"
            );
        }
    }

    // -- (c) and (d) the raw streams ----------------------------------------
    for canary in [ACCESS, REFRESH, ID_TOKEN] {
        assert!(!stdout.contains(canary), "stdout leaks {canary}");
        assert!(!stderr.contains(canary), "stderr leaks {canary}");
    }

    // -- no guest mount exposes the host-only secret directory --------------
    assert_secret_mount_isolation(&config, &secrets_sibling);
}

fn assert_secret_mount_isolation(config: &serde_json::Value, secrets_sibling: &Path) {
    // Resolve fixture aliases (notably macOS /var) before component-wise checks.
    let secrets_sibling = secrets_sibling.canonicalize().unwrap();
    for mount in config["mounts"].as_array().unwrap() {
        let host = Path::new(mount["host"].as_str().unwrap())
            .canonicalize()
            .unwrap();
        assert!(
            !host.starts_with(&secrets_sibling) && !secrets_sibling.starts_with(&host),
            "{} exposes the host-only secret directory",
            host.display()
        );
    }
}

#[test]
fn secrets_mount_isolation_rejects_overlaps() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    let secrets = root.join("state/project.secrets");
    write(&secrets.join("openai"), "test-only-token");
    for relative in [
        "project",
        "state/project",
        "state/project/home",
        "state/unrelated",
        "state/project.secrets-other",
    ] {
        std::fs::create_dir_all(root.join(relative)).unwrap();
    }
    for (relative, rejected) in [
        ("state/project.secrets", true),
        ("state/project.secrets/openai", true),
        ("state", true),
        ("project", false),
        ("state/project", false),
        ("state/project/home", false),
        ("state/unrelated", false),
        ("state/project.secrets-other", false),
    ] {
        let config = serde_json::json!({"mounts": [{"host": root.join(relative)}]});
        assert_eq!(
            std::panic::catch_unwind(|| assert_secret_mount_isolation(&config, &secrets)).is_err(),
            rejected,
            "mount isolation control: {relative}"
        );
    }
}

/// Every regular file under `root`, recursively. Skip symlinks to avoid following
/// guest-namespace aliases and cycles on the host; in-tree targets are walked
/// through their regular paths.
fn state_regular_files(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn walk(dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
        let entries = std::fs::read_dir(dir)
            .unwrap_or_else(|error| panic!("read {}: {error}", dir.display()));
        for entry in entries {
            let path = entry.unwrap().path();
            let file_type = std::fs::symlink_metadata(&path).unwrap().file_type();
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                walk(&path, out);
            } else if file_type.is_file() {
                let bytes = std::fs::read(&path)
                    .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
                out.push((path, bytes));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, &mut out);
    out
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
    let harness = Harness::warm();

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
    let harness = Harness::warm();

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
    let harness = Harness::warm();
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
/// `[debug] guest command:` line for a launch verb with tool arguments is
/// exactly what `run::inner_argv` produces, with each user arg shell-escaped
/// so quoting survives the `bash -c` boundary. `run::tests` pins the pure
/// function; this pins the wiring that emits it for a real invocation.
#[test]
fn shell_user_args_are_joined_and_escaped_in_the_guest_command_line() {
    let harness = Harness::warm();
    let out =
        harness.launch_with_tool_args("shell", &["--image", BOGUS_IMAGE], &["a b", "c'd"], &[]);

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
    let harness = Harness::warm();
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
    let harness = Harness::warm();
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
        let harness = Harness::warm();
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
    let harness = Harness::warm();

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
    assert!(launch_err.contains(TYPO_REFERENCE_SENTENCE), "{launch_err}");
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
        stdout.contains(TYPO_REFERENCE_SENTENCE),
        "the config section must render the failure: {stdout}"
    );
}

/// A declared `shell` that opts out (`tools = []`) provisions nothing, and the
/// launch still boots — with no TLS overlay and no egress (default-deny).
#[test]
fn a_zero_provisioning_launch_boots_with_no_tls_overlay() {
    let harness = Harness::warm();
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

    // `Plan::apply_to` now always installs the launcher's policy, so even a
    // zero-provisioning launch carries an explicit, closed `policy`; TLS stays
    // disabled and the credential sets stay empty. Compare the whole dense
    // network to the independent engine-derived baseline (G1's helper), never
    // to anything the launch printed.
    assert_default_deny_zero_provision_network(&config["network"], "zero-provisioning shell");

    // The launcher policy is deliberately **not** the SDK default. Pin both
    // sides so a change to either the launcher's decision or the dependency
    // default is noticed: the SDK default still admits the public group.
    let sdk_default_policy =
        serde_json::to_value(&microsandbox_network::config::NetworkConfig::default().policy)
            .unwrap();
    assert_ne!(
        config["network"]["policy"], sdk_default_policy,
        "the launcher must not inherit the SDK default policy"
    );
    assert!(
        sdk_default_policy["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|rule| rule["destination"]["group"] == "public"),
        "the SDK default policy must still carry a public group"
    );
}

/// Under a **custom** catalog the fallback `shell` provisions **nothing** — the
/// old always-on capture must not come back as a "fix" for a failing
/// user-config test.
#[test]
fn a_fallback_shell_under_a_custom_catalog_provisions_nothing() {
    let harness = Harness::warm();
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
    // A custom-catalog fallback shell also requests no egress, so it too gets
    // the dense default-deny network — pin it here so this shape is covered
    // without a golden.
    assert_default_deny_zero_provision_network(&config["network"], "fallback shell");
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
    let harness = Harness::warm();
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
        let harness = Harness::warm();
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
    let harness = Harness::warm();
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

    let harness = Harness::warm();
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
    let harness = Harness::warm();
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
    let harness = Harness::warm();
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
    let harness = Harness::warm();
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
    let harness = Harness::warm();
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
    let harness = Harness::warm();
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
    let harness = Harness::warm();
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
    let harness = Harness::warm();
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
    let harness = Harness::warm();
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
    .args(["--image", BOGUS_IMAGE])
    .arg("shell");
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
fn default_ref() -> &'static str {
    static REFERENCE: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| format!("localhost:1/default@{}", fixture_digest()));
    &REFERENCE
}
/// A second immutable recommendation, for tests that change what a launcher
/// offers *after* a default was already retained.
fn recommendation_b() -> &'static str {
    static REFERENCE: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| format!("localhost:1/other@{}", fixture_digest()));
    &REFERENCE
}

fn fixture_digest() -> &'static str {
    static DIGEST: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        let dir = tempfile::tempdir().unwrap();
        image_archive::write(
            &dir.path().join("fixture.tar"),
            &image_archive::ArchiveSpec::default(),
        )
        .manifest_digest
    });
    &DIGEST
}

fn fixture_sdk_reference(source: &str) -> String {
    if source == default_ref() || source == recommendation_b() {
        return REDACTED_DEFAULT_MARKER.to_owned();
    }
    format!(
        "{}@{}",
        source.strip_suffix(":latest").unwrap_or(source),
        fixture_digest()
    )
}

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
    if expected == default_ref() {
        REDACTED_DEFAULT_MARKER
    } else {
        expected
    }
}

/// The two acquisition verbs as argv prefixes: boot-free `image refresh` and
/// `setup`'s initial acquisition step (#389).
const ACQUISITION_VERBS: [&[&str]; 2] = [&["image", "refresh"], &["setup"]];

/// One argv prefix as a printable verb name, for assertion messages.
fn verb_name(argv: &[&str]) -> String {
    argv.join(" ")
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

/// The fixed marker of a boot-free native acquisition record. Kept in sync with
/// `debug_config::native_acquisition`.
const NATIVE_MARKER: &str = "[debug] native image acquisition JSON: ";

/// Every native-acquisition record in `stderr`, decoded as complete JSON
/// objects. Malformed JSON after a marker is an error, never silently dropped.
fn native_acquisitions(stderr: &str) -> Result<Vec<serde_json::Value>, String> {
    let mut out = Vec::new();
    let mut rest = stderr;
    while let Some(index) = rest.find(NATIVE_MARKER) {
        let after = &rest[index + NATIVE_MARKER.len()..];
        let mut stream = serde_json::Deserializer::from_str(after).into_iter::<serde_json::Value>();
        let value = stream
            .next()
            .ok_or_else(|| "no JSON after a native acquisition marker".to_string())?;
        let value = value.map_err(|error| format!("malformed native acquisition JSON: {error}"))?;
        let offset = stream.byte_offset();
        out.push(value);
        rest = &after[offset..];
    }
    Ok(out)
}

/// The whole acquisition oracle: exactly one `native-image-acquire` record whose
/// reference is `expected`, acquired with `Always`/`force: false`.
///
/// A selector notice, a `SandboxConfig` (launch or setup verification) or a
/// second record is not an acquisition, so all three fail this check.
fn check_pull_acquisition(stderr: &str, expected: &str) -> Result<(), String> {
    let records = native_acquisitions(stderr)?;
    let [record] = records.as_slice() else {
        return Err(format!(
            "{} native acquisition records, expected exactly one",
            records.len()
        ));
    };
    if record["kind"].as_str() != Some("native-image-acquire") {
        return Err(format!("not a native acquisition record: {record}"));
    }
    if record["pull_policy"].as_str() != Some("always") {
        return Err(format!("the record did not acquire Always: {record}"));
    }
    if record["force"].as_bool() != Some(false) {
        return Err(format!("the record forced the acquisition: {record}"));
    }
    let reference = record["reference"]
        .as_str()
        .ok_or_else(|| format!("no reference in the native acquisition record: {record}"))?;
    let expected = observable_reference(expected);
    if reference != expected {
        return Err(format!(
            "the native acquisition targets {reference}, expected {expected}"
        ));
    }
    Ok(())
}

#[test]
fn acquisition_config_oracle_rejects_notice_only_and_wrong_reference() {
    // Control: a real refresh parses and names the exact reference.
    let harness = Harness::new();
    harness.write_project(&format!("image = \"{PROJECT_REF}\"\n"));
    let out = harness.builtin(
        &["image", "refresh"],
        &[("AGENT_VM_TEST_DEFAULT_IMAGE", default_ref())],
    );
    let stderr = stderr_of(&out);
    check_pull_acquisition(&stderr, PROJECT_REF).expect("the real refresh is observable");

    // A setup verification `SandboxConfig` alone is not an acquisition.
    let verification_only = format!(
        "{CONFIG_MARKER}{{\"name\":\"agent-vm-setup-verify\",\"image\":{{\"Oci\":{{\"reference\":\"{PROJECT_REF}\"}}}}}}\n"
    );
    assert!(
        check_pull_acquisition(&verification_only, PROJECT_REF).is_err(),
        "a sandbox config with no native record must fail"
    );

    // Rejected captures.
    let notice_only = format!(
        "==> {PROJECT_REF} (from project config /x) is the image this configuration boots from\n"
    );
    assert!(
        check_pull_acquisition(&notice_only, PROJECT_REF).is_err(),
        "a notice with no JSON dump must fail"
    );

    let record = |reference: &str| {
        format!(
            "{NATIVE_MARKER}{{\"kind\":\"native-image-acquire\",\"reference\":\"{reference}\",\"pull_policy\":\"always\",\"force\":false}}"
        )
    };
    let wrong = format!(
        "{}\n==> {PROJECT_REF} (from project config /x) is the image this configuration boots from\n",
        record("localhost:1/wrong:latest")
    );
    assert!(
        check_pull_acquisition(&wrong, PROJECT_REF).is_err(),
        "a record with the wrong reference must fail on equality"
    );
    let suffix = record(&format!("{PROJECT_REF}-suffix"));
    assert!(
        check_pull_acquisition(&suffix, PROJECT_REF).is_err(),
        "a reference that merely extends the expected one must fail"
    );
    let forced = record(PROJECT_REF).replace("\"force\":false", "\"force\":true");
    assert!(
        check_pull_acquisition(&forced, PROJECT_REF).is_err(),
        "a forced acquisition must fail"
    );

    let malformed = format!("{NATIVE_MARKER}{{not json\n");
    assert!(
        check_pull_acquisition(&malformed, PROJECT_REF).is_err(),
        "malformed JSON after a marker must fail"
    );

    let duplicate = format!("{}\n{}\n", record(PROJECT_REF), record(PROJECT_REF));
    assert!(
        check_pull_acquisition(&duplicate, PROJECT_REF).is_err(),
        "two native acquisition records must fail"
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
            source: "env AGENT_VM_IMAGE_TAG",
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
            expected: default_ref(),
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
            expected: default_ref(),
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
        let harness = Harness::warm();
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
            cmd.env("AGENT_VM_TEST_DEFAULT_IMAGE", default_ref());
            if let Some(env) = row.env {
                cmd.env("AGENT_VM_IMAGE_TAG", env);
            }
            let mut argv: Vec<&str> = vec![];
            if let Some(cli) = row.cli {
                argv.push("--image");
                argv.push(cli);
            }
            argv.push(tool);
            let out = Harness::run_on(cmd, &argv);
            let stderr = stderr_of(&out);
            assert!(
                !out.status.success(),
                "{} ({tool}): the bogus image must fail acquisition, stderr:\n{stderr}",
                row.name
            );
            if row.expected == default_ref() {
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
                fixture_sdk_reference(row.expected),
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

        // --- image refresh and setup (initial acquisition) ---
        for verb in ACQUISITION_VERBS {
            let harness = Harness::warm();
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
            cmd.env("AGENT_VM_TEST_DEFAULT_IMAGE", default_ref());
            if let Some(env) = row.env {
                cmd.env("AGENT_VM_IMAGE_TAG", env);
            }
            let mut argv: Vec<&str> = verb.to_vec();
            if let Some(cli) = row.cli {
                argv.push("--image");
                argv.push(cli);
            }
            let out = Harness::run_on(cmd, &argv);
            let stderr = stderr_of(&out);
            let stdout = stdout_of(&out);
            let verb = verb_name(verb);
            assert!(
                !out.status.success(),
                "{} ({verb}): the bogus image must fail, stderr:\n{stderr}",
                row.name
            );
            if row.expected == default_ref() {
                let safe = if verb == "image refresh" {
                    "==> the default boot image is the image this configuration boots from"
                } else {
                    "==> Acquiring the default boot image into the microsandbox image cache"
                };
                assert!(
                    stdout.contains(safe),
                    "{} ({verb}): default notice missing:\n{stdout}",
                    row.name
                );
            } else if verb == "image refresh" {
                assert!(
                    stdout.contains(&format!("==> {} (from {}", row.expected, row.source)),
                    "{} ({verb}): selection notice missing:\n{stdout}",
                    row.name
                );
            } else {
                assert!(
                    stdout.contains(&format!(
                        "==> Acquiring {} into the microsandbox image cache",
                        row.expected
                    )),
                    "{} ({verb}): acquisition notice missing:\n{stdout}",
                    row.name
                );
            }
            // Imported content lets setup prepare successfully and verify the
            // acquired child; refresh still explicitly probes the selected source.
            let configs = acquisition_configs(&stderr).expect("dumps parse");
            if verb == "setup" {
                let config = acquisition_config(&configs, "agent-vm-setup-verify")
                    .unwrap_or_else(|problem| panic!("{}: {problem}\n{stderr}", row.name));
                assert_eq!(oci_reference(config), fixture_sdk_reference(row.expected));
                assert!(
                    stderr.contains("booting verify sandbox")
                        || stderr.contains(
                            "booting the verification sandbox from the default boot image failed"
                        ),
                    "{stderr}"
                );
            } else {
                check_pull_acquisition(&stderr, row.expected)
                    .unwrap_or_else(|problem| panic!("{} ({verb}): {problem}\n{stderr}", row.name));
                assert!(
                    configs.is_empty(),
                    "refresh must not build a sandbox: {stderr}"
                );
            }
            assert_eq!(
                harness.decoy_log(&decoys),
                "",
                "{} ({verb}): no builder calls",
                row.name
            );
        }

        // --- doctor (no `--image`): rows without a typed override only ---
        if row.cli.is_none() {
            let harness = Harness::warm();
            write_image_tiers(
                &harness,
                ImageTiers {
                    user: row.user,
                    project: row.project,
                    declares_tool: false,
                },
            );
            let mut envs: Vec<(&str, &str)> = vec![("AGENT_VM_TEST_DEFAULT_IMAGE", default_ref())];
            if let Some(env) = row.env {
                envs.push(("AGENT_VM_IMAGE_TAG", env));
            }
            let out = harness.builtin(&["doctor"], &envs);
            let stdout = stdout_of(&out);
            if row.expected == default_ref() {
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
        cmd.env("AGENT_VM_TEST_DEFAULT_IMAGE", default_ref())
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
                && !stderr.contains(default_ref()),
            "{present:?} fell through to a lower tier:\n{stderr}"
        );
        assert!(
            harness.decoy_log(&decoys).is_empty(),
            "{present:?}: no builder calls"
        );

        // image refresh and setup treat it the same way.
        for verb in ACQUISITION_VERBS {
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
            cmd.env("AGENT_VM_TEST_DEFAULT_IMAGE", default_ref())
                .env("AGENT_VM_IMAGE_TAG", present);
            let out = Harness::run_on(cmd, verb);
            let verb = verb_name(verb);
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
                ("AGENT_VM_TEST_DEFAULT_IMAGE", default_ref()),
                ("AGENT_VM_IMAGE_TAG", present),
            ],
        );
        let stdout = stdout_of(&out);
        assert!(
            stdout.contains("(from env AGENT_VM_IMAGE_TAG)"),
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
        &[("AGENT_VM_TEST_DEFAULT_IMAGE", default_ref())],
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
        &[("AGENT_VM_TEST_DEFAULT_IMAGE", default_ref())],
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
        &[("AGENT_VM_TEST_DEFAULT_IMAGE", default_ref())],
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
    // Fixed built-ins, including the direct runner (`run`, #398): the point of
    // this helper is the *catalog* launch verbs and their order.
    const BUILTINS: [&str; 8] = [
        "setup",
        "msb",
        "clipboard",
        "doctor",
        "secret",
        "image",
        "run",
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
    // Normalized SDK dumps tokenize the acquired digest, not the selected tag.
    // Baseline: the shipped defaults, booting a named image via `--image`.
    let baseline_harness = Harness::warm();
    let baseline_out = baseline_harness.launch_argv(
        "claude",
        &["--image", PROJECT_REF],
        &[("AGENT_VM_TEST_DEFAULT_IMAGE", default_ref())],
    );
    let baseline = normalized_config(&baseline_harness, &baseline_out);
    assert_eq!(
        oci_reference(&baseline),
        "localhost:1/project@$FIXTURE_DIGEST"
    );

    // Every image-only shape keeps the shipped tools and changes only the image.
    let variants: [(&str, Option<&str>, Option<&str>, bool); 4] = [
        ("user only", Some(PROJECT_REF), None, false),
        ("project only", None, Some(PROJECT_REF), false),
        ("both tiers", Some(PROJECT_REF), Some(PROJECT_REF), false),
        ("project with tools=[]", None, Some(PROJECT_REF), true),
    ];
    for (name, user, project, explicit_empty) in variants {
        let harness = Harness::warm();
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
            &[("AGENT_VM_TEST_DEFAULT_IMAGE", default_ref())],
        );
        let config = normalized_config(&harness, &out);
        assert_eq!(
            oci_reference(&config),
            "localhost:1/project@$FIXTURE_DIGEST",
            "{name}"
        );
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
    let harness = Harness::warm();
    harness.write_user(&format!("image = \"{USER_REF}\"\n"));
    harness.write_project(&format!(
        "image = \"{PROJECT_REF}\"\n[[tools]]\nname = \"hello\"\ncommand = \"hello-258\"\n"
    ));
    let out = harness.launch_argv(
        "hello",
        &[],
        &[("AGENT_VM_TEST_DEFAULT_IMAGE", default_ref())],
    );
    let config = normalized_config(&harness, &out);
    assert_eq!(
        oci_reference(&config),
        "localhost:1/user@$FIXTURE_DIGEST",
        "the user image outranks the project's"
    );
    let claude = harness.launch_argv(
        "claude",
        &[],
        &[("AGENT_VM_TEST_DEFAULT_IMAGE", default_ref())],
    );
    assert!(
        stderr_of(&claude).contains("unrecognized subcommand"),
        "project tools replace the shipped tools"
    );
}

#[test]
fn custom_catalog_and_tool_edits_do_not_change_the_boot_image() {
    let harness = Harness::warm();
    harness.write_project(
        "[[tools]]\nname = \"hello\"\ncommand = \"hello-258\"\nargs = [\"probe\", \"two words\"]\n",
    );

    // No image configured: both the custom verb and the shell fallback choose
    // the default boot image.
    for tool in ["hello", "shell"] {
        let out = harness.launch_argv(tool, &[], &[("AGENT_VM_TEST_DEFAULT_IMAGE", default_ref())]);
        assert_eq!(
            oci_reference(&debug_config_json(&stderr_of(&out))),
            REDACTED_DEFAULT_MARKER,
            "{tool}"
        );
    }
    let hello = harness.launch_argv(
        "hello",
        &[],
        &[("AGENT_VM_TEST_DEFAULT_IMAGE", default_ref())],
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
        let out = harness.launch_argv(tool, &[], &[("AGENT_VM_TEST_DEFAULT_IMAGE", default_ref())]);
        assert_eq!(
            oci_reference(&debug_config_json(&stderr_of(&out))),
            fixture_sdk_reference(PROJECT_REF),
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
        &[("AGENT_VM_TEST_DEFAULT_IMAGE", default_ref())],
    );
    let stderr = stderr_of(&edited);
    assert_eq!(
        oci_reference(&debug_config_json(&stderr)),
        fixture_sdk_reference(PROJECT_REF)
    );
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
        &[("AGENT_VM_TEST_DEFAULT_IMAGE", default_ref())],
    );
    assert_eq!(
        oci_reference(&debug_config_json(&stderr_of(&out))),
        fixture_sdk_reference(PROJECT_REF)
    );
}

#[test]
fn help_doctor_pull_setup_and_launch_agree_on_image_selection() {
    let harness = Harness::warm();
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
    let tool_help = harness.builtin(&["help", "hello"], &[]);
    assert!(tool_help.status.success());
    assert!(stdout_of(&tool_help).contains("tool arguments are forwarded verbatim"));
    let mut paths: Vec<(&str, Output)> = vec![
        ("--help", harness.builtin(&["--help"], &[])),
        (
            "image refresh --help",
            harness.builtin(&["image", "refresh", "--help"], &[]),
        ),
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
        for removed in ["--base-image", "--layer"] {
            assert!(
                !text.contains(removed),
                "{what} must not mention {removed}:\n{text}"
            );
        }
    }
}

/// S3: `image refresh` is a boot-free acquisition verb, so its `--image` help
/// must describe acquisition. The flattened `boot_image::ImageArgs` help wins
/// unless the refresh subcommand overrides it, so both help spellings are
/// pinned here, together with the `set-default` control that keeps its own
/// acquisition wording.
#[test]
fn image_refresh_help_describes_acquisition_not_booting() {
    let harness = Harness::new();
    for args in [
        vec!["image", "refresh", "-h"],
        vec!["image", "refresh", "--help"],
        vec!["help", "image", "refresh"],
    ] {
        let out = harness.builtin(&args, &[]);
        let text = stdout_of(&out);
        assert!(
            out.status.success(),
            "{args:?} must exit 0:\n{text}\n{}",
            stderr_of(&out)
        );
        assert!(
            text.contains("OCI image to acquire"),
            "{args:?} must describe acquisition:\n{text}"
        );
        assert!(
            text.contains("instead of the configured selection"),
            "{args:?} must distinguish the refresh override:\n{text}"
        );
        assert!(
            !text.contains("Boot this image"),
            "{args:?} must not describe refresh as a launch:\n{text}"
        );
        if args.contains(&"--help") || args[0] == "help" {
            assert!(
                text.contains("OCI image to acquire into the image cache"),
                "{args:?} must use the refresh-specific long help:\n{text}"
            );
            assert!(
                text.contains("Precedence: this flag (or `AGENT_VM_IMAGE_TAG`)"),
                "{args:?} must retain the precedence text:\n{text}"
            );
        }
    }
    let set_default = stdout_of(&harness.builtin(&["image", "set-default", "--help"], &[]));
    assert!(
        set_default.contains("OCI image to acquire and retain for future default-image sessions"),
        "set-default's own help must not change:\n{set_default}"
    );
    assert!(
        !set_default.contains("instead of the configured selection"),
        "set-default must not inherit refresh's override wording:\n{set_default}"
    );
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
fn refresh_and_setup_reject_removed_composition_flags_as_usage_errors() {
    // `image refresh`/`setup` have no trailing positional, so every removed
    // composition flag is an ordinary clap usage error (exit 2) on both verbs.
    for verb in ACQUISITION_VERBS {
        for argv in [
            vec!["--layer", "/tmp/x"],
            vec!["--base-image", "x"],
            // `--yes` is a nested consent flag of the two explicit update verbs;
            // `setup` still has none, and the old global `-y` remains gone.
            // (`image refresh --yes` is asserted below as an accepted parse.)
            vec!["-y"],
        ] {
            if verb_name(verb) == "setup" && argv == ["-y"] {
                // covered by the loop body; `setup --yes` is asserted below
            }
            let harness = Harness::new();
            let mut full = verb.to_vec();
            full.extend_from_slice(&argv);
            let out = harness.builtin(&full, &[]);
            let verb = verb_name(verb);
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
    // The nested consent flag: `image refresh --yes` parses (asserted through
    // `--help`, so no registry work happens); `setup --yes` does not.
    let harness = Harness::new();
    let accepted = harness.builtin(&["image", "refresh", "--yes", "--help"], &[]);
    assert_eq!(accepted.status.code(), Some(0), "{}", stderr_of(&accepted));
    assert!(stdout_of(&accepted).contains("--yes"));
    let refused = harness.builtin(&["setup", "--yes"], &[]);
    assert_eq!(refused.status.code(), Some(2), "{}", stderr_of(&refused));
}

/// Every token after the verb is forwarded verbatim (ADR-0042).
#[test]
fn launch_forwards_tool_arguments_verbatim() {
    let cases: [(Vec<&str>, &str); 6] = [
        (vec!["--layer", "/tmp/x"], "/bin/echo --layer /tmp/x"),
        (vec!["--base-image", "x"], "/bin/echo --base-image x"),
        (vec!["--yes"], "/bin/echo --yes"),
        (vec!["-y"], "/bin/echo -y"),
        (
            vec!["--mount", "/x", "--help"],
            "/bin/echo --mount /x --help",
        ),
        (
            vec!["--", "--layer", "/tmp/x"],
            "/bin/echo -- --layer /tmp/x",
        ),
    ];
    for (argv, expected) in cases {
        let harness = Harness::warm();
        harness.write_project(&format!("image = \"{PROJECT_REF}\"\n{PROBE_TOOL}"));
        let decoys = harness.builder_decoys();
        let mut cmd = harness.command_with_decoys(&decoys);
        cmd.env("AGENT_VM_TEST_DEFAULT_IMAGE", default_ref());
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
        assert_eq!(
            oci_reference(&debug_config_json(&stderr)),
            fixture_sdk_reference(PROJECT_REF)
        );
        assert_eq!(
            // Image preparation rewrites the image only, never tool arguments.
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
        (None, None, default_ref()),
    ] {
        for verb in ACQUISITION_VERBS {
            let harness = Harness::new();
            harness.write_user(broken);
            let mut envs: Vec<(&str, &str)> = vec![("AGENT_VM_TEST_DEFAULT_IMAGE", default_ref())];
            if let Some(env) = env {
                envs.push(("AGENT_VM_IMAGE_TAG", env));
            }
            let mut args: Vec<&str> = verb.to_vec();
            if let Some(cli) = cli {
                args.push("--image");
                args.push(cli);
            }
            let out = harness.builtin(&args, &envs);
            let verb = verb_name(verb);
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
    // must survive for refresh/setup/doctor.
    let harness = Harness::new();
    harness.write_project(&format!(
        "image = \"{PROJECT_REF}\"\n[[tools]]\nname = \"t\"\ncommand = \"t\"\ntools = [\"nope\"]\n"
    ));
    for verb in ACQUISITION_VERBS {
        let out = harness.builtin(verb, &[("AGENT_VM_TEST_DEFAULT_IMAGE", default_ref())]);
        let stderr = stderr_of(&out);
        check_pull_acquisition(&stderr, PROJECT_REF)
            .unwrap_or_else(|problem| panic!("{}: {problem}\n{stderr}", verb_name(verb)));
    }
    let doctor = stdout_of(&harness.builtin(
        &["doctor"],
        &[("AGENT_VM_TEST_DEFAULT_IMAGE", default_ref())],
    ));
    assert!(
        doctor.contains(&format!("selected (without --image): {PROJECT_REF}")),
        "doctor keeps the readable image:\n{doctor}"
    );
    // The launch still reports the tool-resolution error.
    let launch = harness.launch_argv("t", &[], &[("AGENT_VM_TEST_DEFAULT_IMAGE", default_ref())]);
    let launch_stderr = stderr_of(&launch);
    assert!(!launch.status.success());
    assert!(
        launch_stderr.contains(TYPO_REFERENCE_SENTENCE),
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
        cmd.env("AGENT_VM_TEST_DEFAULT_IMAGE", default_ref());
        if let Some(env) = env {
            cmd.env("AGENT_VM_IMAGE_TAG", env);
        }
        let mut argv = vec![];
        if let Some(cli) = cli {
            argv.push("--image");
            argv.push(cli);
        }
        argv.push("probe");
        let out = Harness::run_on(cmd, &argv);
        let stderr = stderr_of(&out);
        assert_cold_preparation_failure(&harness, &out);
        assert!(
            stderr.contains("preparing the boot image"),
            "{name}: {stderr}"
        );
        assert!(
            harness.decoy_log(&decoys).is_empty(),
            "{name}: no builder calls"
        );
    }
}

#[test]
fn former_layer_directories_are_inert() {
    let harness = Harness::warm();
    harness.write_project(&format!("image = \"{PROJECT_REF}\"\n{PROBE_TOOL}"));
    let decoys = harness.builder_decoys();

    let run = |envs: &[(&str, &str)]| {
        let mut cmd = harness.command_with_decoys(&decoys);
        cmd.env("AGENT_VM_TEST_DEFAULT_IMAGE", default_ref());
        for (key, value) in envs {
            cmd.env(key, value);
        }
        Harness::run_on(cmd, &["probe"])
    };

    let baseline = run(&[]);
    assert_eq!(
        oci_reference(&debug_config_json(&stderr_of(&baseline))),
        fixture_sdk_reference(PROJECT_REF)
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
        fixture_sdk_reference(PROJECT_REF)
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
            fixture_sdk_reference(PROJECT_REF),
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

/// Run one acquisition precedence row and return its stderr, or an error if the
/// actual native acquisition's reference is not the selected one. Used by the
/// two independent mutation targets below (they run separately so a refresh
/// failure cannot hide a setup failure).
fn run_builtin_acquisition(row: &Precedence, verb: &[&str]) -> Result<String, String> {
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
    cmd.env("AGENT_VM_TEST_DEFAULT_IMAGE", default_ref());
    if let Some(env) = row.env {
        cmd.env("AGENT_VM_IMAGE_TAG", env);
    }
    let mut argv = verb.to_vec();
    if let Some(cli) = row.cli {
        argv.push("--image");
        argv.push(cli);
    }
    let verb = verb_name(verb);
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
fn refresh_uses_the_actual_selected_reference() {
    for row in precedence_rows() {
        run_builtin_acquisition(&row, &["image", "refresh"])
            .unwrap_or_else(|problem| panic!("{} (image refresh): {problem}", row.name));
    }
}

#[test]
fn setup_pull_uses_the_actual_selected_reference() {
    for row in precedence_rows() {
        run_builtin_acquisition(&row, &["setup"])
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
    for verb in [
        &["doctor"][..],
        &["image", "refresh"][..],
        &["setup"][..],
        &["shell"][..],
    ] {
        let harness = Harness::new();
        let mut cmd = harness.base_command();
        cmd.env("AGENT_VM_IMAGE_TAG", std::ffi::OsStr::from_bytes(b"\xff"));
        let out = Harness::run_on(cmd, verb);
        let verb = verb_name(verb);
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

/// R13: setup's documented OCI-only acquisition policy is explicit. A CLI/env
/// local rootfs or disk target is refused with the local-launch advice — with
/// and without `--no-verify` — before the native acquisition, so it produces no
/// registry request, verification guest, marker or retained default.
///
/// Setup may already have run its runtime admission by then; only `image
/// refresh` promises pre-prologue rejection.
#[test]
fn setup_refuses_local_cli_env_targets_either_way() {
    for no_verify in [false, true] {
        for (source, cli, env) in [
            ("cli", Some("../rootfs"), None),
            ("env", None, Some("/private/tmp/disk.img")),
        ] {
            let harness = Harness::new();
            let mut argv = vec!["setup"];
            let mut envs: Vec<(&str, &str)> = vec![("AGENT_VM_TEST_DEFAULT_IMAGE", default_ref())];
            let target;
            if let Some(cli) = cli {
                argv.push("--image");
                target = cli;
                argv.push(target);
            } else {
                target = env.unwrap();
                envs.push(("AGENT_VM_IMAGE_TAG", target));
            }
            if no_verify {
                argv.push("--no-verify");
            }
            let out = harness.builtin(&argv, &envs);
            let stderr = stderr_of(&out);
            let context = format!("{source} (no_verify: {no_verify})");
            assert!(!out.status.success(), "{context}: must fail:\n{stderr}");
            assert!(
                stderr.contains("agent-vm --image PATH <tool>"),
                "{context}: the fixed local-launch advice must be offered:\n{stderr}"
            );
            assert!(
                !stderr.contains(target),
                "{context}: the rejected local target must not be echoed:\n{stderr}"
            );
            // No acquisition, no verification sandbox, no retained default.
            assert!(
                !stderr.contains(NATIVE_MARKER),
                "{context}: a rejected target must not acquire:\n{stderr}"
            );
            assert!(
                acquisition_configs(&stderr).unwrap().is_empty(),
                "{context}: no sandbox config may be built:\n{stderr}"
            );
            harness.assert_no_selection(&context);
        }
    }
}

/// S5: malformed OCI references and local paths are different input classes.
/// Every acquisition verb refuses each from input alone with its own fixed,
/// value-free wording: local-launch advice only for a local path, and “not a
/// valid OCI image reference” for malformed reference text (never the rejected
/// value). No acquisition record, registry marker, verification guest or
/// retained default may be produced by either class.
#[test]
fn malformed_oci_references_are_refused_value_free_while_local_paths_keep_their_advice() {
    const MALFORMED: [&str; 3] = ["Foo/Bar:tag", "repo:bad tag", "repo@sha256:short"];
    for raw in MALFORMED {
        // `image refresh`, CLI and env overrides.
        for (source, argv, envs) in [
            (
                "refresh cli",
                vec!["image", "refresh", "--image", raw],
                vec![],
            ),
            (
                "refresh env",
                vec!["image", "refresh"],
                vec![("AGENT_VM_IMAGE_TAG", raw)],
            ),
        ] {
            let harness = Harness::new();
            let out = harness.builtin(&argv, &envs);
            let stderr = stderr_of(&out);
            assert!(!out.status.success(), "{source}: {stderr}");
            assert!(
                stderr.contains("`agent-vm image refresh` needs a valid OCI image reference"),
                "{source} {raw:?}: the invalid-reference wording must be used:\n{stderr}"
            );
            assert!(
                !stderr.contains(raw),
                "{source}: the rejected value must not be echoed:\n{stderr}"
            );
            assert!(
                !stderr.contains("agent-vm --image PATH <tool>"),
                "{source}: a malformed reference must not get local-launch advice:\n{stderr}"
            );
            assert!(!stderr.contains(NATIVE_MARKER), "{source}: {stderr}");
            assert!(
                acquisition_configs(&stderr).unwrap().is_empty(),
                "{source}: no acquisition may be built:\n{stderr}"
            );
            assert!(!harness.state_root.join("pulled-digests").exists());
            harness.assert_no_selection(source);
        }
        // `setup`, with and without `--no-verify`.
        for no_verify in [false, true] {
            let harness = Harness::new();
            let mut argv = vec!["setup", "--image", raw];
            if no_verify {
                argv.push("--no-verify");
            }
            let out = harness.builtin(&argv, &[("AGENT_VM_TEST_DEFAULT_IMAGE", default_ref())]);
            let stderr = stderr_of(&out);
            let context = format!("setup {raw:?} (no_verify: {no_verify})");
            assert!(!out.status.success(), "{context}: {stderr}");
            assert!(
                stderr.contains("`agent-vm setup` needs a valid OCI image reference"),
                "{context}: the invalid-reference wording must be used:\n{stderr}"
            );
            assert!(!stderr.contains(raw), "{context}: {stderr}");
            assert!(
                !stderr.contains("agent-vm --image PATH <tool>"),
                "{context}: a malformed reference must not get local-launch advice:\n{stderr}"
            );
            assert!(!stderr.contains(NATIVE_MARKER), "{context}: {stderr}");
            assert!(
                acquisition_configs(&stderr).unwrap().is_empty(),
                "{context}: no verification guest may be built:\n{stderr}"
            );
            assert!(!harness.state_root.join("pulled-digests").exists());
            harness.assert_no_selection(&context);
        }
        // `image set-default` uses its own clap value parser, so the refusal is
        // a usage error and the raw argv value must not be echoed by clap.
        let harness = Harness::new();
        let out = harness.builtin(&["image", "set-default", "--image", raw], &[]);
        let stderr = stderr_of(&out);
        assert_eq!(out.status.code(), Some(2), "set-default {raw:?}: {stderr}");
        assert!(
            stderr.contains("set-default needs a valid OCI image reference"),
            "set-default {raw:?}: the invalid-reference wording must be used:\n{stderr}"
        );
        assert!(
            !stderr.contains(raw),
            "set-default: the rejected value must not be echoed:\n{stderr}"
        );
        assert!(
            !stderr.contains("agent-vm --image PATH <tool>"),
            "set-default: a malformed reference must not get local-launch advice:\n{stderr}"
        );
        harness.assert_no_selection("set-default invalid");
    }

    // Local-path controls: the same verbs keep the local-launch advice and do
    // not claim the text was a malformed reference.
    let harness = Harness::new();
    let out = harness.builtin(&["image", "refresh", "--image", "../rootfs"], &[]);
    let stderr = stderr_of(&out);
    assert!(stderr.contains("agent-vm --image PATH <tool>"), "{stderr}");
    assert!(
        !stderr.contains("needs a valid OCI image reference"),
        "{stderr}"
    );
    harness.assert_no_selection("refresh local control");
    let out = harness.builtin(&["image", "set-default", "--image", "/path"], &[]);
    let stderr = stderr_of(&out);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("agent-vm --image PATH <tool>"), "{stderr}");
    assert!(
        !stderr.contains("needs a valid OCI image reference"),
        "{stderr}"
    );
    harness.assert_no_selection("set-default local control");
    assert!(!harness.saw_capability_probe());
    assert!(
        harness.msb_log().lines().all(|line| line == "--version"),
        "{}",
        harness.msb_log()
    );
}

#[test]
fn diagnostics_and_help_never_create_a_selection() {
    let harness = Harness::new();
    let envs = [("AGENT_VM_TEST_DEFAULT_IMAGE", default_ref())];

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
        !stdout.contains(default_ref()),
        "doctor must not echo the recommendation reference:\n{stdout}"
    );
    harness.assert_no_selection("doctor");

    for args in [
        vec!["--help"],
        vec!["help", "shell"],
        vec!["image", "refresh", "--help"],
        vec!["image", "set-default", "--help"],
        vec!["help", "image", "refresh"],
        vec!["help", "image", "set-default"],
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
        ("image refresh", vec!["image", "refresh"]),
        ("setup", vec!["setup"]),
    ] {
        let harness = Harness::new();
        harness.write_project(PROBE_TOOL);
        let out = harness.builtin(&argv, &[("AGENT_VM_TEST_DEFAULT_IMAGE", default_ref())]);
        assert!(
            !out.status.success(),
            "{verb}: an unreachable default must fail:\n{}",
            stderr_of(&out)
        );
        harness.assert_no_selection(verb);
        let doctor = stdout_of(&harness.builtin(
            &["doctor"],
            &[("AGENT_VM_TEST_DEFAULT_IMAGE", default_ref())],
        ));
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
    let harness = Harness::warm();
    harness.write_project(PROBE_TOOL);
    harness.write_selection_ref(default_ref());
    let before = harness.selection_bytes().unwrap();

    for envs in [
        vec![("AGENT_VM_TEST_DEFAULT_IMAGE", recommendation_b())],
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
            !stderr.contains(default_ref()) && !stderr.contains(recommendation_b()),
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
            !doctor.contains(default_ref()) && !doctor.contains(recommendation_b()),
            "doctor must not echo a default-tier reference:\n{doctor}"
        );
    }

    // A *separate* fresh HOME initialized with B yields B: the recommendation is
    // still what an uninitialized host is offered.
    let other = Harness::warm();
    other.write_project(PROBE_TOOL);
    let out = other.launch_argv(
        "probe",
        &[],
        &[("AGENT_VM_TEST_DEFAULT_IMAGE", recommendation_b())],
    );
    assert_eq!(
        oci_reference(&debug_config_json(&stderr_of(&out))),
        REDACTED_DEFAULT_MARKER
    );
    assert!(
        !stderr_of(&out).contains(recommendation_b()),
        "an uninitialized recommendation must not leak either"
    );
}

#[test]
fn the_historical_interim_selection_survives_the_standard_recommendation() {
    // Observation must not acquire the historic published image: ordinary Cargo
    // tests remain boot-free and never download production image content.
    const HISTORIC: &str = "ghcr.io/wirenboard/agent-vm-template@sha256:fd05aaa697c2488e9f7384d069ba2244078faf6b5320998b546c93f98f8d5f18";
    let harness = Harness::warm();
    harness.write_selection_ref(HISTORIC);
    let before = harness.selection_bytes().unwrap();
    for envs in [
        vec![("AGENT_VM_TEST_DEFAULT_IMAGE", recommendation_b())],
        vec![],
    ] {
        let out = harness.builtin(&["doctor"], &envs);
        let doctor = stdout_of(&out);
        assert!(doctor.contains("selected (without --image): retained default ["));
        assert!(!doctor.contains(HISTORIC));
        assert_eq!(harness.selection_bytes().unwrap(), before);
    }
    for (cli, env, user, project, expected) in [
        (Some(CLI_REF), None, None, None, CLI_REF),
        (None, Some(ENV_REF), None, None, ENV_REF),
        (None, None, Some(USER_REF), None, USER_REF),
        (None, None, None, Some(PROJECT_REF), PROJECT_REF),
    ] {
        let harness = Harness::warm();
        harness.write_selection_ref(HISTORIC);
        let before = harness.selection_bytes().unwrap();
        write_image_tiers(
            &harness,
            ImageTiers {
                user,
                project,
                declares_tool: true,
            },
        );
        let mut envs = vec![("AGENT_VM_TEST_DEFAULT_IMAGE", recommendation_b())];
        if let Some(env) = env {
            envs.push(("AGENT_VM_IMAGE_TAG", env));
        }
        let mut argv = Vec::new();
        if let Some(cli) = cli {
            argv.extend(["--image", cli]);
        }
        let out = harness.launch_argv("probe", &argv, &envs);
        assert_eq!(
            oci_reference(&debug_config_json(&stderr_of(&out))),
            fixture_sdk_reference(expected)
        );
        assert_eq!(harness.selection_bytes().unwrap(), before);
    }
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
        let harness = Harness::warm();
        write_image_tiers(
            &harness,
            ImageTiers {
                user,
                project,
                declares_tool: true,
            },
        );
        harness.write_selection_ref(default_ref());
        let before = harness.selection_bytes().unwrap();
        let mut envs: Vec<(&str, &str)> = vec![("AGENT_VM_TEST_DEFAULT_IMAGE", recommendation_b())];
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
            fixture_sdk_reference(expected),
            "{name}: the higher source must win"
        );
        assert_eq!(
            harness.selection_bytes().unwrap(),
            before,
            "{name}: the retained record must be untouched"
        );
    }

    // With the record absent, an explicit source must not create one.
    let harness = Harness::warm();
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
        &[("AGENT_VM_TEST_DEFAULT_IMAGE", default_ref())],
    );
    assert_eq!(
        oci_reference(&debug_config_json(&stderr_of(&out))),
        fixture_sdk_reference(PROJECT_REF)
    );
    harness.assert_no_selection("explicit project image with an absent record");
}

#[test]
fn a_corrupt_selection_fails_closed_and_never_repairs() {
    const CORRUPT: &str = "{\"version\":1,\"image\":\"sk-SENSITIVE-TOKEN\"}\n";
    let harness = Harness::warm();
    harness.write_project(PROBE_TOOL);
    harness.write_selection(CORRUPT);
    let before = harness.selection_bytes().unwrap();

    // No higher source: the damaged record is a hard error *before* any
    // acquisition or config dump, and its bytes are never repaired.
    let out = harness.launch_argv(
        "probe",
        &[],
        &[("AGENT_VM_TEST_DEFAULT_IMAGE", recommendation_b())],
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
        &[("AGENT_VM_TEST_DEFAULT_IMAGE", default_ref())],
    );
    let stderr = stderr_of(&out);
    assert_eq!(
        oci_reference(&debug_config_json(&stderr)),
        fixture_sdk_reference(CLI_REF)
    );
    assert_eq!(harness.selection_bytes().unwrap(), before);

    // Doctor reports the damage and exits nonzero while still rendering every
    // section it can.
    let doctor = harness.builtin(
        &["doctor"],
        &[("AGENT_VM_TEST_DEFAULT_IMAGE", default_ref())],
    );
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
        .env("AGENT_VM_TEST_DEFAULT_IMAGE", recommendation_b());
    let out = Harness::run_on(cmd, &["image", "refresh"]);
    assert!(
        !out.status.success(),
        "the bogus retained ref must fail the refresh"
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
    let out = Harness::run_on(cmd, &["image", "refresh"]);
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
            "selected (without --image): {ENV_REF} (from env AGENT_VM_IMAGE_TAG)"
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
        &[("AGENT_VM_TEST_DEFAULT_IMAGE", recommendation_b())],
    );
    let stderr = stderr_of(&out);
    assert!(!out.status.success(), "{stderr}");
    assert!(!stderr.contains("agent-vm image import") && !stderr.contains("hint:"));
    assert!(
        stderr.contains("==> Boot image: the default boot image"),
        "the default notice must be a fixed label:\n{stderr}"
    );
    assert!(!stderr.contains(CONFIG_MARKER));
    assert!(
        stderr.contains("pulling the default boot image failed"),
        "acquisition failure must be a fixed, stage-specific reason:\n{stderr}"
    );
    assert!(
        !stderr.contains(SENSITIVE) && !stderr.contains(recommendation_b()),
        "neither the retained record nor the recommendation may leak:\n{stderr}"
    );
    assert_eq!(harness.selection_bytes().unwrap(), before);

    // `image refresh` writes its selection notice to stdout and the dump/error
    // to stderr.
    let refresh = harness.builtin(
        &["image", "refresh"],
        &[("AGENT_VM_TEST_DEFAULT_IMAGE", recommendation_b())],
    );
    assert!(!refresh.status.success());
    let combined = format!("{}{}", stdout_of(&refresh), stderr_of(&refresh));
    assert!(!combined.contains("agent-vm image import") && !combined.contains("hint:"));
    assert!(
        combined.contains("the default boot image is the image this configuration boots from"),
        "refresh must name the default safely:\n{combined}"
    );
    assert!(
        combined.contains(REDACTED_DEFAULT_MARKER),
        "refresh's display copy must redact the reference:\n{combined}"
    );
    assert!(
        !combined.contains(SENSITIVE) && !combined.contains(recommendation_b()),
        "refresh leaked a default-tier reference:\n{combined}"
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
    assert!(!stderr.contains(CONFIG_MARKER));
}

#[test]
fn the_selection_is_scoped_to_user_home_not_state_or_cwd() {
    let harness = Harness::warm();
    harness.write_project(PROBE_TOOL);
    harness.write_selection_ref(default_ref());
    let before = harness.selection_bytes().unwrap();

    // A different project cwd and a different state root must not move the
    // bookmark: it is user-scoped, not cache- or project-scoped. The state root
    // stays short, or the sandbox control socket exceeds `sun_path`.
    let elsewhere = tempfile::tempdir_in("/tmp").unwrap();
    let mut cmd = harness.shared_command(&harness.state_root.join("msb-home/cache"));
    cmd.env("AGENT_VM_TEST_DEFAULT_IMAGE", recommendation_b())
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
    let other = Harness::warm();
    other.assert_no_selection("a different HOME");
}

// ---------------------------------------------------------------------------
// G3–G7 — the launcher egress policy reached through the real CLI
// ---------------------------------------------------------------------------

/// The `state_root/<hash>` project key the launcher derives, so a launch can be
/// inspected without parsing a banner it never printed.
fn project_hash(project: &Path) -> String {
    use sha2::{Digest, Sha256};
    let canonical = project.canonicalize().expect("canonicalize project");
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_os_str().as_encoded_bytes());
    let digest = hasher.finalize();
    let mut out = String::new();
    for byte in &digest[..6] {
        use std::fmt::Write;
        write!(&mut out, "{byte:02x}").unwrap();
    }
    out
}

/// Whether any file named `name` under `root` holds `contents` — used to prove
/// a `:fork` seed actually captured its source.
fn dir_contains(root: &Path, name: &str, contents: &str) -> bool {
    let Ok(entries) = std::fs::read_dir(root) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if dir_contains(&path, name, contents) {
                return true;
            }
        } else if path.file_name().is_some_and(|n| n == name)
            && std::fs::read_to_string(&path).is_ok_and(|body| body == contents)
        {
            return true;
        }
    }
    false
}

/// G3: the network flags reach the dumped `SandboxConfig`. A malformed
/// allowance fails before any egress is installed; the accepted set emits
/// exactly the §3.1 rule list, in order.
#[test]
fn network_flags_reach_the_sandbox_config() {
    // The bracketed-CIDR typo is rejected at parse time, so this launch never
    // reaches the builder and creates no launch state.
    let harness = Harness::warm();
    let out = harness.launch(
        "shell",
        &[
            "--allow-internet-egress",
            "--allow-lan",
            "--allow-egress",
            "tcp://[10.0.0.0/24]:22",
            "--allow-egress",
            "10.0.0.0/24:22",
        ],
    );
    assert!(
        !out.status.success(),
        "a rejected allowance must fail the launch"
    );
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("--allow-egress #2: a port on a CIDR needs brackets"),
        "{stderr}"
    );
    assert!(
        !stderr.contains(CONFIG_MARKER),
        "a rejected allowance must not reach builder wiring: {stderr}"
    );

    // The accepted set emits the documented rules, in order.
    let harness = Harness::warm();
    let out = harness.launch(
        "shell",
        &[
            "--allow-internet-egress",
            "--allow-lan",
            "--allow-egress",
            "tcp://[10.0.0.0/24]:22",
            "--allow-egress",
            "api.example.com",
            "--allow-egress",
            "tcp://git.example.com:8443",
        ],
    );
    let config = normalized_config(&harness, &out);
    assert_eq!(config["network"]["policy"]["default_egress"], "deny");
    assert_eq!(config["network"]["policy"]["default_ingress"], "allow");
    assert_eq!(
        config["network"]["policy"]["rules"],
        serde_json::json!([
            {"direction":"egress","destination":{"cidr":"10.0.0.0/24"},"protocols":["tcp"],"ports":[{"start":22,"end":22}],"action":"allow"},
            {"direction":"egress","destination":{"group":"host"},"protocols":["udp","tcp"],"ports":[{"start":53,"end":53}],"action":"allow"},
            {"direction":"egress","destination":{"group":"public"},"protocols":[],"ports":[],"action":"allow"},
            {"direction":"egress","destination":{"group":"private"},"protocols":[],"ports":[],"action":"allow"},
            {"direction":"egress","destination":{"domain":"api.example.com"},"protocols":["tcp"],"ports":[{"start":443,"end":443},{"start":8443,"end":8443}],"action":"allow"},
            {"direction":"egress","destination":{"domain":"git.example.com"},"protocols":["tcp"],"ports":[{"start":8443,"end":8443}],"action":"allow"}
        ])
    );
    assert_eq!(config["network"]["tls"]["enabled"], true);
    assert_eq!(
        config["network"]["tls"]["intercepted_ports"],
        serde_json::json!([443, 8443])
    );
}

/// G4: a rejected UDP hostname allowance fails before *any* launch state is created;
/// a valid hostname control reaches the expected bogus-image failure with its
/// fork, credential and MSB state already on disk.
#[test]
fn rejected_allowance_is_refused_before_launch_state_is_created() {
    let mount_source = support::project_tempdir();
    std::fs::write(mount_source.path().join("sentinel"), "seed").unwrap();

    // Rejected: the hostname allowance stops the launch at parse time.
    let rejected = Harness::new();
    let mount = format!("{}:/forked:fork", mount_source.path().display());
    let out = rejected.launch(
        "claude",
        &["--mount", &mount, "--allow-egress", "udp://api.example.com"],
    );
    assert!(!out.status.success());
    assert!(
        !rejected
            .home_root
            .join(".config/agent-vm/image-pins.json")
            .exists()
    );
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("hostnames allow TLS over TCP only"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("api.example.com"),
        "the raw hostname must not be echoed: {stderr}"
    );
    assert_eq!(
        rejected.msb_log(),
        "--version\n",
        "a rejected launch must not make any runtime call beyond the identity probe"
    );
    let hash = project_hash(&rejected.project_root);
    assert!(
        !rejected.state_root.join(&hash).exists(),
        "a rejected launch must not create the project state dir"
    );
    assert!(
        !rejected.state_root.join(format!("{hash}.mounts")).exists(),
        "a rejected launch must not create the fork store"
    );
    assert!(
        !rejected.state_root.join(format!("{hash}.secrets")).exists(),
        "a rejected launch must not capture credentials"
    );
    assert!(
        !rejected.state_root.join("msb-home").exists(),
        "a rejected launch must not initialize MSB launch state"
    );

    // Positive control: the same launch with a TLS hostname allowance reaches the
    // (expected) bogus-image failure, having created the state the rejection
    // must avoid.
    let control = Harness::warm();
    let mount = format!("{}:/forked:fork", mount_source.path().display());
    let out = control.launch(
        "claude",
        &["--mount", &mount, "--allow-egress", "api.example.com"],
    );
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(CONFIG_MARKER),
        "the control must reach builder wiring: {stderr}"
    );
    let hash = project_hash(&control.project_root);
    let mounts = control.state_root.join(format!("{hash}.mounts"));
    assert!(mounts.exists(), "the fork store must be created");
    assert!(
        dir_contains(&mounts, "sentinel", "seed"),
        "the fork seed must contain the sentinel"
    );
    assert!(
        control
            .state_root
            .join(format!("{hash}.secrets"))
            .join("anthropic")
            .exists(),
        "the control must capture the host credential before the image pull fails"
    );
    assert!(
        control.state_root.join(&hash).join("home").exists(),
        "the control must provision the guest home"
    );
    assert!(
        control.state_root.join("msb-home").exists(),
        "the control must initialize MSB launch state"
    );
}

/// G5: a `[network]` table in the project tier is refused with a named
/// diagnostic that points at the setting and the tier; the project tier can
/// never grant egress.
#[test]
fn project_network_table_fails_every_launch() {
    let harness = Harness::new();
    harness.write_project("[network]\nallow_lan = true\n");
    let out = harness.launch_default("shell");
    assert!(!out.status.success(), "a project [network] table must fail");
    let stderr = stderr_of(&out);
    assert!(stderr.contains("network.allow_lan"), "{stderr}");
    assert!(
        stderr.contains("network access cannot be granted by the project config"),
        "{stderr}"
    );
}

/// RJ1: each rejected allowance reports the exact `--allow-egress #1:`
/// diagnostic and never echoes the rejected input. This is the host-side oracle
/// the native harness's `rejection_diagnostic` mirrors; keeping them equal
/// means a native RJ1 pass cannot come from a clap or unrelated error.
#[test]
fn allowance_rejections_report_exact_messages() {
    let harness = Harness::new();
    for (value, expected) in [
        (
            "udp://reject.invalid",
            "--allow-egress #1: hostnames allow TLS over TCP only; use tcp://HOST:PORT, or an IP/CIDR for UDP",
        ),
        (
            "reject.invalid:53",
            "--allow-egress #1: ports 53 and 853 carry the sandbox DNS path and cannot be hostname-allowed; use an IP/CIDR",
        ),
        (
            "host.microsandbox.internal",
            "--allow-egress #1: host.microsandbox.internal is the sandbox host; use --allow-host",
        ),
        (
            "*.reject.invalid",
            "--allow-egress #1: not an IP address, CIDR or hostname (hostnames: one or more labels of ASCII letters, digits and '-', not ending in a numeric label; write non-ASCII names as A-labels; no wildcards)",
        ),
        (
            "1.2.3",
            "--allow-egress #1: not an IP address, CIDR or hostname (hostnames: one or more labels of ASCII letters, digits and '-', not ending in a numeric label; write non-ASCII names as A-labels; no wildcards)",
        ),
        (
            "10.0.0.0/24:18080",
            "--allow-egress #1: a port on a CIDR needs brackets, e.g. tcp://[10.0.0.0/24]:22",
        ),
        (
            "http://1.1.1.1:80",
            "--allow-egress #1: unsupported scheme; use tcp:// or udp:// (or no scheme for all protocols)",
        ),
    ] {
        let out = harness.launch("shell", &["--allow-egress", value]);
        assert!(!out.status.success(), "{value} must be rejected");
        let stderr = stderr_of(&out);
        assert!(stderr.contains(expected), "{value}: {stderr}");
        assert!(
            (value == "host.microsandbox.internal" || !stderr.contains(value)),
            "{value} must not be echoed: {stderr}"
        );
    }
}

/// T10: doctor renders authority refusal; detects hidden deferred errors.
#[test]
fn user_network_refusal_is_rendered_in_doctor_tool_configuration() {
    let harness = Harness::new();
    harness.write_user_mode("[network]\nallow_lan = true\n", 0o600);
    let target = harness.project_root.join("dotfile");
    std::fs::rename(harness.user_config(), &target).unwrap();
    harness.symlink_user_config(&target);
    let out = harness.base_command().arg("doctor").output().unwrap();
    assert!(!out.status.success(), "doctor must report config failure");
    let stdout = stdout_of(&out);
    let section = stdout
        .split("==> tool configuration")
        .nth(1)
        .unwrap()
        .split("\n==>")
        .next()
        .unwrap();
    assert!(section.contains("error: config:"), "{stdout}");
    assert!(
        section.contains("reached through a symbolic link"),
        "{stdout}"
    );
}

/// G6: credential provisioning installs no egress (story 33). The credential
/// overlay is present, but the launcher's policy is still the empty
/// default-deny list.
#[test]
fn credential_provisioning_adds_no_egress() {
    let harness = Harness::warm();
    let out = harness.launch_default("claude");
    let config = normalized_config(&harness, &out);
    assert_eq!(config["network"]["policy"]["default_egress"], "deny");
    assert_eq!(
        config["network"]["policy"]["rules"],
        serde_json::json!([]),
        "credential provisioning must not add egress"
    );
    assert!(
        !config["network"]["secrets"]["secrets"]
            .as_array()
            .unwrap()
            .is_empty(),
        "the credential overlay must still be present"
    );
    assert_eq!(config["network"]["tls"]["enabled"], true);
    assert!(config["network"]["intercept"].is_object());
}

/// G7: the harness's committed two-tool config drives a real non-interactive
/// launch whose tool arguments land verbatim in the guest command, with the
/// default-deny policy and the dense zero-provision network.
#[test]
fn harness_probe_tool_launches_with_its_tool_arguments() {
    let harness = Harness::warm();
    harness.write_project(include_str!(
        "../../../script/test/fixtures/egress-config.toml"
    ));
    let out = harness.launch_with_tool_args(
        "egressprobe",
        &["--image", BOGUS_IMAGE, "--no-git"],
        &["D1", "id-1"],
        &[],
    );
    let stderr = stderr_of(&out);
    assert!(stderr.contains(CONFIG_MARKER), "{stderr}");
    assert_eq!(
        debug_guest_command(&stderr),
        "bash ./egress-probe.sh D1 id-1",
        "the tool arguments must reach the guest command verbatim"
    );
    let config = debug_config_json(&stderr);
    assert_default_deny_zero_provision_network(&config["network"], "egressprobe");
}

#[test]
fn hostname_with_host_proxy_is_refused_before_launch_state_is_created() {
    let harness = Harness::new();
    let out = harness.launch_with_env(
        "shell",
        &["--allow-egress", "api.example.com"],
        &[("HTTPS_PROXY", "http://127.0.0.1:9")],
    );
    let stderr = stderr_of(&out);
    assert!(!out.status.success());
    assert!(
        !harness
            .home_root
            .join(".config/agent-vm/image-pins.json")
            .exists()
    );
    assert!(stderr.contains("hostname allowances cannot be enforced through the host HTTP proxy (HTTPS_PROXY/HTTP_PROXY/ALL_PROXY): the proxy resolves the name, so the address scope is not checked; unset the proxy, use an IP/CIDR allowance, or use --allow-internet-egress"), "{stderr}");
    assert!(!stderr.contains(CONFIG_MARKER));
    assert!(!stderr.contains("api.example.com"));
    assert!(!stderr.contains("127.0.0.1:9"));
    assert!(
        !harness
            .state_root
            .join(project_hash(&harness.project_root))
            .exists()
    );
    assert!(!harness.state_root.join("msb-home").exists());
    let control = Harness::warm();
    let out = control.launch("shell", &["--allow-egress", "api.example.com"]);
    assert!(stderr_of(&out).contains(CONFIG_MARKER));
}

#[test]
fn zero_provision_hostname_launch_enables_interception() {
    let harness = Harness::warm();
    harness.write_user("[[tools]]\nname = \"plain\"\ncommand = \"/bin/echo\"\ntools = []\n");
    let out = harness.launch("plain", &["--allow-egress", "api.example.com"]);
    let config = normalized_config(&harness, &out);
    let network = &config["network"];
    assert_eq!(network["tls"]["enabled"], true);
    assert_eq!(network["strict"], true);
    assert_eq!(
        network["tls"]["intercepted_ports"],
        serde_json::json!([443])
    );
    assert_eq!(network["secrets"]["secrets"], serde_json::json!([]));
    assert!(
        network["secrets"].get("header_credentials").is_none(),
        "an empty header-credential set is wire-omitted"
    );
    assert_eq!(
        network["policy"]["rules"],
        serde_json::json!([
            {"direction":"egress","destination":{"domain":"api.example.com"},"protocols":["tcp"],"ports":[{"start":443,"end":443}],"action":"allow"}
        ])
    );
}

#[test]
fn hostname_allowance_survives_the_credential_overlay() {
    let harness = Harness::warm();
    harness.write_user(ONE_YAML_TOOL);
    write_credentials(
        &harness.home_root,
        "credentials:\n  - service: my-service\n    apiKey:\n      name: MY_SERVICE_KEY\n      sentinelEnv: true\n      inject: [{domain: 'api.my-service.example:9443', header: x-api-key, format: '%s'}]\n",
    );
    let out = harness.launch_with_env(
        "t",
        &[
            "--allow-egress",
            "api.example.com",
            "--allow-egress",
            "tcp://git.example.com:8443",
        ],
        &[(
            "AGENT_VM_TEST_CREDENTIAL",
            "my-service=sk-test-overlay-value",
        )],
    );
    let config = normalized_config(&harness, &out);
    let network = &config["network"];
    assert_eq!(network["tls"]["enabled"], true);
    assert_eq!(
        network["tls"]["intercepted_ports"],
        serde_json::json!([443, 8443, 9443])
    );
    assert_eq!(
        network["policy"],
        serde_json::json!({"default_egress":"deny","default_ingress":"allow","rules":[
            {"direction":"egress","destination":{"domain":"api.example.com"},"protocols":["tcp"],"ports":[{"start":443,"end":443},{"start":8443,"end":8443}],"action":"allow"},
            {"direction":"egress","destination":{"domain":"git.example.com"},"protocols":["tcp"],"ports":[{"start":8443,"end":8443}],"action":"allow"}
        ]})
    );
}

// #307 — tool network requests
const REQUEST_SCOPE: &str =
    "public or same-name grants (no lookup; DNS, private-answer and TLS client limits still apply)";
const REQUEST_HINT: &str = "==>   to grant: --allow-egress HOST or tcp://HOST:PORT, or --allow-internet-egress; IP/CIDR, --allow-lan and --allow-host grants are not matched to names";
const FETCHER: &str = "[[tools]]\nname = \"fetcher\"\ncommand = \"/bin/echo\"\ntools = []\n";
const FETCH_REQUESTS: &str =
    "network_requests = [\"api.example.com\",\"tcp://git.corp.example:8443\"]\n";
fn request_block(stderr: &str) -> Vec<&str> {
    stderr
        .lines()
        .skip_while(|l| !l.starts_with("==> Tool network requests"))
        .take_while(|l| l.starts_with("==> Tool network requests") || l.starts_with("==>   "))
        .collect()
}
#[test]
fn requests_unmet_launch_continues_and_proxy_order() {
    for proxy in [false, true] {
        let h = Harness::warm();
        h.write_project(&format!("{FETCHER}{FETCH_REQUESTS}"));
        let out = h.launch_with_env(
            "fetcher",
            &[],
            if proxy {
                &[("HTTPS_PROXY", "http://127.0.0.1:9")]
            } else {
                &[]
            },
        );
        let stderr = stderr_of(&out);
        assert!(stderr.contains(CONFIG_MARKER), "{stderr}");
        let expected = vec![
            format!(
                "==> Tool network requests (project config): 2 of 2 not covered by this launch's {REQUEST_SCOPE}; requests never grant access and the launch continues"
            ),
            "==>   unmet: api.example.com".into(),
            "==>   unmet: tcp://git.corp.example:8443".into(),
            REQUEST_HINT.into(),
        ];
        assert_eq!(request_block(&stderr), expected);
        let start = stderr.find("==> Egress policy:").unwrap();
        let lines: Vec<_> = stderr[start..]
            .lines()
            .take(if proxy { 7 } else { 6 })
            .collect();
        assert_eq!(
            lines[0],
            "==> Egress policy: all guest egress denied (opt in with --allow-internet-egress, --allow-egress, --allow-lan or --allow-host)"
        );
        assert_eq!(
            lines[1],
            "==> Egress DNS: queries denied (NXDOMAIN when forwarder is available; use IP or hostname allowances)"
        );
        if proxy {
            assert!(lines[2].starts_with("==> Guest egress proxy:"));
        }
        assert_eq!(&lines[if proxy { 3 } else { 2 }..], expected);
        assert_default_deny_zero_provision_network(
            &debug_config_json(&stderr)["network"],
            "requests",
        );
        assert_eq!(
            stderr
                .lines()
                .filter(|l| l.contains("Tool network requests"))
                .count(),
            1
        );
        assert_eq!(stderr.lines().filter(|l| l.contains("unmet:")).count(), 2);
    }
}
#[test]
fn requests_user_partial_and_public_coverage() {
    let h = Harness::warm();
    h.write_user(&format!("{FETCHER}{FETCH_REQUESTS}"));
    for (flags, unmet) in [
        (vec!["--allow-egress", "api.example.com"], true),
        (vec!["--allow-internet-egress"], false),
    ] {
        let stderr = stderr_of(&h.launch("fetcher", &flags));
        assert!(stderr.contains(CONFIG_MARKER));
        let expected = if unmet {
            vec![
                format!(
                    "==> Tool network requests (user config): 1 of 2 not covered by this launch's {REQUEST_SCOPE}; requests never grant access and the launch continues"
                ),
                "==>   unmet: tcp://git.corp.example:8443".into(),
                REQUEST_HINT.into(),
            ]
        } else {
            vec![format!(
                "==> Tool network requests (user config): all 2 covered by this launch's {REQUEST_SCOPE}; requests never grant access"
            )]
        };
        assert_eq!(request_block(&stderr), expected);
        assert_eq!(stderr.matches("unmet:").count(), usize::from(unmet));
    }
}
#[test]
fn requests_rejected_before_state_both_tiers() {
    for user in [false, true] {
        for (raw, reason) in [
            (
                "udp://SENTINEL-9c1f.example",
                "requests name TLS over TCP; udp:// is not accepted",
            ),
            (
                "10.0.0.0/8",
                "an IP address or CIDR is network authority, not a request; name the host (HOST, tcp://HOST or tcp://HOST:PORT)",
            ),
            (
                "SENTINEL-9c1f.example\n==> Egress policy: allowing everything",
                "port must be a decimal number 1-65535",
            ),
        ] {
            let h = Harness::new();
            let body = format!(
                "{FETCHER}network_requests = [{}]\n",
                serde_json::to_string(raw).unwrap()
            );
            if user {
                h.write_user(&body);
            } else {
                h.write_project(&body);
            }
            let out = h.launch("fetcher", &[]);
            assert!(!out.status.success());
            let stderr = stderr_of(&out);
            let (tier, path) = if user {
                ("user config", h.user_config())
            } else {
                ("project config", h.project_config())
            };
            assert_eq!(
                stderr
                    .lines()
                    .find_map(|l| l
                        .strip_prefix("Error: ")
                        .filter(|l| l.starts_with("config:")))
                    .unwrap(),
                format!(
                    "config: {tier} \"{}\" declaration [0] tool \"fetcher\": network_requests[0]: {reason}",
                    path.display()
                )
            );
            for forbidden in [
                "SENTINEL-9c1f",
                "sentinel-9c1f",
                "allowing everything",
                CONFIG_MARKER,
            ] {
                assert!(!stderr.contains(forbidden), "{stderr}");
            }
            assert!(h.msb_log().is_empty());
            assert!(!h.state_root.join(project_hash(&h.project_root)).exists());
            assert!(!h.state_root.join("msb-home").exists());
            assert!(!h.state_root.join(".secrets").exists());
        }
    }
}
#[test]
fn requests_report_cap_network_refusal_and_own_tool_only() {
    let h = Harness::warm();
    let names: Vec<_> = (0..64).map(|i| format!("\"n{i:02}.example\"")).collect();
    h.write_project(&format!(
        "{FETCHER}network_requests = [{}]\n",
        names.join(",")
    ));
    let stderr = stderr_of(&h.launch("fetcher", &[]));
    assert!(stderr.contains(CONFIG_MARKER));
    let mut expected = vec![format!(
        "==> Tool network requests (project config): 64 of 64 not covered by this launch's {REQUEST_SCOPE}; requests never grant access and the launch continues"
    )];
    expected.extend((0..8).map(|i| format!("==>   unmet: n{i:02}.example")));
    expected.push("==>   … and 56 more not shown".into());
    expected.push(REQUEST_HINT.into());
    assert_eq!(request_block(&stderr), expected);
    assert_eq!(stderr.matches("unmet:").count(), 8);
    let h = Harness::warm();
    h.write_project(&format!("[network]\n{FETCHER}{FETCH_REQUESTS}"));
    let stderr = stderr_of(&h.launch("fetcher", &[]));
    assert!(
        stderr.contains("[network]")
            && stderr.contains("network access cannot be granted by the project config"),
        "{stderr}"
    );
    assert!(!stderr.contains(CONFIG_MARKER) && request_block(&stderr).is_empty());
    let h = Harness::warm();
    h.write_user("[[tools]]\nname = \"a\"\ncommand = \"a\"\nnetwork_requests = [\"a.example\"]\n[[tools]]\nname = \"shell\"\ncommand = \"bash\"\n");
    let stderr = stderr_of(&h.launch("shell", &[]));
    assert!(stderr.contains(CONFIG_MARKER));
    assert!(request_block(&stderr).is_empty());
}
#[test]
fn requests_runtime_input_noninterference() {
    for tier in 0..3 {
        for flags in [
            vec![],
            vec!["--allow-egress", "api.example.com"],
            vec!["--allow-internet-egress"],
            vec![
                "--allow-egress",
                "tcp://git.corp.example:8443",
                "--allow-lan",
            ],
        ] {
            let mut captures = Vec::new();
            for with in [false, true] {
                let h = Harness::warm();
                let requests = if with {
                    "network_requests = [\"api.example.com\",\"tcp://git.corp.example:8443\",\"other.example\"]\n"
                } else {
                    ""
                };
                if tier == 0 {
                    h.write_user(&format!("{FETCHER}{requests}"));
                } else if tier == 1 {
                    h.write_project(&format!("{FETCHER}{requests}"));
                } else {
                    // The winning (user) definition carries both the requests
                    // and the credential-bearing provisioning; the discarded
                    // project shadow differs in credentials and tools, so it
                    // cannot supply either facet.
                    h.write_user(&format!("[[tools]]\nname = \"t\"\ncommand = \"/bin/echo\"\ncredentials = [\"anthropic\"]\ntools = []\n{requests}"));
                    h.write_project("[[tools]]\nname = \"t\"\ncommand = \"/bin/echo\"\ncredentials = [\"openai\"]\ntools = [\"*\"]\n");
                }
                let out = h.launch(if tier == 2 { "t" } else { "fetcher" }, &flags);
                let stderr = stderr_of(&out);
                assert!(stderr.contains(CONFIG_MARKER), "{stderr}");
                let config = normalized_config(&h, &out);
                let state = snapshot(&h.state_root.join(project_hash(&h.project_root)));
                if tier == 2 {
                    // Built-in providers publish no guest env, so the observed
                    // provisioning facets are the proxy secret env var and the
                    // credential state dir. Anthropic is the merge winner; the
                    // discarded project definition names OpenAI.
                    let secrets = registered_secret_env_vars(&config);
                    assert!(
                        secrets.contains(&"MSB_AGENT_VM_ANTHROPIC_UNUSED"),
                        "the winning definition must provision the Anthropic proxy secret"
                    );
                    assert!(
                        !secrets.contains(&"MSB_AGENT_VM_OPENAI_UNUSED"),
                        "the discarded project definition must not provision the OpenAI proxy secret"
                    );
                    assert!(
                        !state["claude/.credentials.json"].starts_with("absent"),
                        "the winning definition must write the Claude credential state"
                    );
                    assert!(
                        state["codex/auth.json"].starts_with("absent"),
                        "the discarded project definition must not write Codex state"
                    );
                    // The report must come from the winning user definition, so
                    // request reporting and the credential overlay are
                    // exercised in the same launch.
                    let block = request_block(&stderr);
                    if with {
                        assert!(
                            block.first().is_some_and(
                                |line| line.contains("Tool network requests (user config)")
                            ),
                            "the winning user definition's requests must be reported: {block:?}"
                        );
                    } else {
                        assert!(block.is_empty(), "no requests declared: {block:?}");
                    }
                }
                let notices: Vec<String> = stderr
                    .lines()
                    .filter(|l| {
                        l.starts_with("==> Egress policy:")
                            || l.starts_with("==> TLS interception:")
                            || l.starts_with("==> Egress DNS:")
                    })
                    .map(str::to_owned)
                    .collect();
                captures.push((config, state, notices));
            }
            // Compare without rendering the observed values: the state snapshot
            // holds raw credential-file bytes, so a failure message would be a
            // cleartext log of them. Name only what changed.
            let (config_a, state_a, notices_a) = &captures[0];
            let (config_b, state_b, notices_b) = &captures[1];
            assert!(
                config_a == config_b,
                "tier {tier} flags {flags:?}: requests changed the normalized config"
            );
            if state_a != state_b {
                let mut keys: Vec<&str> = Vec::new();
                for key in state_a.keys().chain(state_b.keys()) {
                    if state_a.get(key) != state_b.get(key) && !keys.contains(&key.as_str()) {
                        keys.push(key.as_str());
                    }
                }
                panic!("tier {tier} flags {flags:?}: requests changed state entries {keys:?}");
            }
            assert_eq!(
                notices_a, notices_b,
                "tier {tier} flags {flags:?}: requests changed the egress notices"
            );
        }
    }
}
#[test]
fn requests_numeric_lan_host_stay_unmet_and_port_scope_is_exact() {
    // Documented false-unmet case: IP/CIDR, --allow-lan and --allow-host are
    // never matched to names, so the report still calls every request unmet;
    // the hint line says so explicitly.
    let expected_block = |tier: &str, total: usize, unmet: &[&str]| -> Vec<String> {
        if unmet.is_empty() {
            return vec![format!(
                "==> Tool network requests ({tier}): all {total} covered by this launch's {REQUEST_SCOPE}; requests never grant access"
            )];
        }
        let mut lines = vec![format!(
            "==> Tool network requests ({tier}): {} of {total} not covered by this launch's {REQUEST_SCOPE}; requests never grant access and the launch continues",
            unmet.len()
        )];
        lines.extend(unmet.iter().map(|name| format!("==>   unmet: {name}")));
        lines.push(REQUEST_HINT.into());
        lines
    };

    let h = Harness::warm();
    h.write_project(&format!("{FETCHER}{FETCH_REQUESTS}"));
    let stderr = stderr_of(&h.launch(
        "fetcher",
        &[
            "--allow-lan",
            "--allow-host",
            "--allow-egress",
            "10.0.0.0/8",
        ],
    ));
    assert!(stderr.contains(CONFIG_MARKER), "{stderr}");
    assert_eq!(
        request_block(&stderr),
        expected_block(
            "project config",
            2,
            &["api.example.com", "tcp://git.corp.example:8443"]
        )
    );

    // A same-name allowance covers only the port it names: a bare grant does
    // not cover the explicit 8443 request, and the explicit grant does not
    // cover the bare (443) request.
    let h = Harness::warm();
    h.write_user(
        "[[tools]]\nname = \"fetcher\"\ncommand = \"/bin/echo\"\ntools = []\nnetwork_requests = [\"tcp://api.example.com:8443\",\"api.example.com\"]\n",
    );
    for (flags, unmet) in [
        (
            vec!["--allow-egress", "api.example.com"],
            vec!["tcp://api.example.com:8443"],
        ),
        (
            vec!["--allow-egress", "tcp://api.example.com:8443"],
            vec!["api.example.com"],
        ),
        (
            vec![
                "--allow-egress",
                "api.example.com",
                "--allow-egress",
                "tcp://api.example.com:8443",
            ],
            vec![],
        ),
    ] {
        let stderr = stderr_of(&h.launch("fetcher", &flags));
        assert!(stderr.contains(CONFIG_MARKER), "{stderr}");
        assert_eq!(
            request_block(&stderr),
            expected_block("user config", 2, &unmet)
        );
        assert_eq!(stderr.matches("unmet:").count(), unmet.len());
    }
}

const PN_ORACLES: &str =
    include_str!("../../../script/test/fixtures/persisted-network/expected-stderr.tsv");

const PN_HOST: &str =
    include_str!("../../../script/test/fixtures/persisted-network/user-allow-host.toml");

/// T1: persisted grants reach policy; detects dropped authority.
#[test]
fn user_network_table_reaches_the_sandbox_policy() {
    let h = Harness::warm();
    h.write_user_mode("[network]\nallow_lan = true\nallow_egress = [\"10.0.0.0/24\",\"tcp://[192.168.10.0/24]:22\",\"api.example.com\"]\n", 0o600);
    let out = h.launch_default("shell");
    let config = normalized_config(&h, &out);
    assert_eq!(
        config["network"]["policy"]["rules"],
        serde_json::json!([
            {"direction":"egress","destination":{"cidr":"10.0.0.0/24"},"protocols":[],"ports":[],"action":"allow"},
            {"direction":"egress","destination":{"cidr":"192.168.10.0/24"},"protocols":["tcp"],"ports":[{"start":22,"end":22}],"action":"allow"},
            {"direction":"egress","destination":{"group":"private"},"protocols":[],"ports":[],"action":"allow"},
            {"direction":"egress","destination":{"domain":"api.example.com"},"protocols":["tcp"],"ports":[{"start":443,"end":443}],"action":"allow"}
        ])
    );
    assert_eq!(
        config["network"]["tls"]["intercepted_ports"],
        serde_json::json!([443])
    );
    let stderr = stderr_of(&out);
    for text in [
        "==> Egress authority: persisted grants from",
        "allowing 10.0.0.0/24 (persisted grants)",
        "allowing tcp://[192.168.10.0/24]:22 (persisted grants)",
        "==> Egress policy: allowing TLS to api.example.com on ports 443 (persisted grants)",
        "==> Egress policy: hostname allowances are TLS-only (SNI and DNS verified; no plain HTTP)",
    ] {
        assert!(stderr.contains(text), "{stderr}");
    }
}

/// One grouped grant line for seven persisted hostnames, one shared security
/// clause, and unchanged rules: detects per-name repetition returning.
#[test]
fn grouped_hostname_egress_notices_preserve_policy_and_saved_config() {
    const NAMES: [&str; 7] = [
        "api.deepseek.com",
        "api.anthropic.com",
        "platform.claude.com",
        "api.openai.com",
        "auth.openai.com",
        "chatgpt.com",
        "models.opencode.ai",
    ];
    let h = Harness::warm();
    let table: Vec<String> = NAMES.iter().map(|name| format!("\"{name}\"")).collect();
    h.write_user_mode(
        &format!("[network]\nallow_egress = [{}]\n", table.join(",")),
        0o600,
    );
    let file = h.user_config();
    let bytes = std::fs::read(&file).unwrap();
    let mtime = std::fs::metadata(&file).unwrap().modified().unwrap();
    let inventory = || {
        let mut entries: Vec<_> = std::fs::read_dir(file.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        entries.sort();
        entries
    };
    // First launch legitimately creates host approval files; subsequent launches
    // must not save network allowances or alter the configuration inventory.
    let first = h.launch_default("shell");
    assert!(stderr_of(&first).contains(CONFIG_MARKER));
    let before = inventory();
    let out = h.launch_default("shell");
    let config = normalized_config(&h, &out);
    let rules: Vec<serde_json::Value> = NAMES
        .iter()
        .map(|name| {
            serde_json::json!(
                {"direction":"egress","destination":{"domain":name},"protocols":["tcp"],"ports":[{"start":443,"end":443}],"action":"allow"}
            )
        })
        .collect();
    assert_eq!(
        config["network"]["policy"]["rules"],
        serde_json::Value::Array(rules)
    );
    assert_eq!(
        config["network"]["tls"]["intercepted_ports"],
        serde_json::json!([443])
    );
    let stderr = stderr_of(&out);
    let grant = format!(
        "==> Egress policy: allowing TLS to {} on ports 443 (persisted grants)",
        NAMES.join(", ")
    );
    assert!(stderr.contains(&grant), "{stderr}");
    assert_eq!(
        stderr.matches("==> Egress policy: allowing TLS to").count(),
        1
    );
    assert_eq!(
        stderr
            .matches("==> Egress policy: hostname allowances are TLS-only (SNI and DNS verified; no plain HTTP)")
            .count(),
        1,
        "{stderr}"
    );
    assert_eq!(std::fs::read(&file).unwrap(), bytes);
    assert_eq!(std::fs::metadata(&file).unwrap().modified().unwrap(), mtime);
    assert_eq!(inventory(), before);
}

/// T2: explicit false wins; detects reversed precedence.
#[test]
fn cli_false_overrides_a_saved_true() {
    for (setting, flag, group) in [
        (
            "allow_internet_egress",
            "--allow-internet-egress=false",
            "public",
        ),
        ("allow_lan", "--allow-lan=false", "private"),
        ("allow_host", "--allow-host=false", "host"),
    ] {
        for override_flag in [false, true] {
            let h = Harness::warm();
            h.write_user_mode(&format!("[network]\n{setting} = true\n"), 0o600);
            let extra: &[&str] = if override_flag { &[flag] } else { &[] };
            let out = h.launch("shell", extra);
            let config = normalized_config(&h, &out);
            let found = config["network"]["policy"]["rules"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["destination"]["group"] == group);
            assert_eq!(found, !override_flag);
            if override_flag {
                assert!(stderr_of(&out).contains(&format!(
                    "{flag} overrides persisted grant {setting} = true"
                )));
            }
        }
    }
}

/// T3: canonical union is launch-only; detects dropped or saved flags.
#[test]
fn cli_allowances_union_with_saved_ones_and_nothing_is_saved() {
    let h = Harness::warm();
    h.write_user_mode(
        "[network]\nallow_egress = [\"10.0.0.5\",\"api.example.com\"]\n",
        0o600,
    );
    let file = h.user_config();
    let bytes = std::fs::read(&file).unwrap();
    let mtime = std::fs::metadata(&file).unwrap().modified().unwrap();
    let inventory = || {
        let mut entries: Vec<_> = std::fs::read_dir(file.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        entries.sort();
        entries
    };
    // First launch legitimately creates host approval files; subsequent launches
    // must not save network allowances or alter the configuration inventory.
    let first = h.launch_default("shell");
    assert!(stderr_of(&first).contains(CONFIG_MARKER));
    let before = inventory();
    let out = h.launch(
        "shell",
        &[
            "--allow-egress",
            "10.0.0.5/32",
            "--allow-egress",
            "192.168.1.0/24",
        ],
    );
    let config = normalized_config(&h, &out);
    assert_eq!(
        config["network"]["policy"]["rules"],
        serde_json::json!([
            {"direction":"egress","destination":{"cidr":"10.0.0.5/32"},"protocols":[],"ports":[],"action":"allow"},
            {"direction":"egress","destination":{"cidr":"192.168.1.0/24"},"protocols":[],"ports":[],"action":"allow"},
            {"direction":"egress","destination":{"domain":"api.example.com"},"protocols":["tcp"],"ports":[{"start":443,"end":443}],"action":"allow"}
        ])
    );
    assert!(stderr_of(&out).contains("10.0.0.5/32 (persisted grants and --allow-egress)"));
    assert_eq!(std::fs::read(&file).unwrap(), bytes);
    assert_eq!(std::fs::metadata(&file).unwrap().modified().unwrap(), mtime);
    assert_eq!(inventory(), before);
}

/// T11: a Boolean `=false` cannot subtract persisted allowances; detects an
/// override path that discards the persisted union.
#[test]
fn cli_false_keeps_persisted_allowances() {
    for (setting, flag, group) in [
        (
            "allow_internet_egress",
            "--allow-internet-egress=false",
            "public",
        ),
        ("allow_lan", "--allow-lan=false", "private"),
        ("allow_host", "--allow-host=false", "host"),
    ] {
        let h = Harness::warm();
        h.write_user_mode(
            &format!("[network]\n{setting} = true\nallow_egress = [\"10.0.0.9\"]\n"),
            0o600,
        );
        let out = h.launch("shell", &[flag]);
        let config = normalized_config(&h, &out);
        let rules = config["network"]["policy"]["rules"].as_array().unwrap();
        assert!(
            rules
                .iter()
                .any(|r| r["destination"]["cidr"] == "10.0.0.9/32"),
            "{flag} dropped a persisted allowance: {rules:?}"
        );
        assert!(
            !rules.iter().any(|r| r["destination"]["group"] == group),
            "{flag} left the {group} group enabled: {rules:?}"
        );
        let stderr = stderr_of(&out);
        assert!(
            stderr.contains(&format!(
                "{flag} overrides persisted grant {setting} = true"
            )),
            "{stderr}"
        );
        assert!(
            stderr.contains("10.0.0.9/32 (persisted grants)"),
            "{stderr}"
        );
    }
}

/// Refusals must not create launch state.
fn assert_saved_refusal(h: &Harness, out: &Output, reason: &str, msb_untouched: bool) {
    assert!(!out.status.success());
    let stderr = stderr_of(out);
    assert!(stderr.contains(reason), "{stderr}");
    assert!(
        stderr.contains(&h.user_config().display().to_string()),
        "{stderr}"
    );
    assert!(!stderr.contains("sk-live-SENTINEL-305"));
    assert!(!stderr.contains(CONFIG_MARKER));
    assert!(
        !h.home_root
            .join(".config/agent-vm/image-pins.json")
            .exists()
    );
    assert!(!h.state_root.join(project_hash(&h.project_root)).exists());
    assert!(!h.state_root.join("msb-home").exists());
    if msb_untouched {
        assert!(h.msb_log().is_empty());
    }
}

/// T4: unsafe authority refuses before state; detects skipped verification.
#[test]
fn unsafe_user_network_is_refused_before_launch_state() {
    use std::os::unix::fs::PermissionsExt;
    for shape in [
        "group",
        "other",
        "directory",
        "hardlink",
        "symlink",
        "safe",
        "readable",
    ] {
        let h = if matches!(shape, "safe" | "readable") {
            Harness::warm()
        } else {
            Harness::new()
        };
        h.write_user_mode(
            "# sk-live-SENTINEL-305\n[network]\nallow_host = true\n",
            0o600,
        );
        let file = h.user_config();
        let reason = match shape {
            "group" => {
                std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o664)).unwrap();
                "group- or other-writable config.toml"
            }
            "other" => {
                std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o646)).unwrap();
                "group- or other-writable config.toml"
            }
            "directory" => {
                std::fs::set_permissions(
                    file.parent().unwrap(),
                    std::fs::Permissions::from_mode(0o775),
                )
                .unwrap();
                "directory is group- or other-writable"
            }
            "hardlink" => {
                std::fs::hard_link(&file, h.project_root.join("alias")).unwrap();
                "2 hard links"
            }
            "symlink" => {
                let target = h.project_root.join("dotfile");
                std::fs::rename(&file, &target).unwrap();
                h.symlink_user_config(&target);
                "reached through a symbolic link"
            }
            "readable" => {
                std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
                ""
            }
            _ => "",
        };
        let out = h.launch_default("shell");
        if reason.is_empty() {
            assert!(stderr_of(&out).contains(CONFIG_MARKER));
        } else {
            assert_saved_refusal(&h, &out, reason, true);
        }
    }
}

// Read-route coverage for #305 — the config-directory symlink, a directory at
// the config path, an unreadable file and value safety at the integration
// boundary, using the existing fake `msb` harness.
// ---------------------------------------------------------------------------

/// RA: a `config.toml` that carries `[network]` but cannot be read fails the
/// launch closed (a read error), rather than silently treating the unreadable
/// authority as absent. The failure precedes any launch state, so the fake
/// `msb` is never invoked.
#[test]
fn unreadable_user_network_config_fails_closed() {
    use std::os::unix::fs::PermissionsExt;
    let h = Harness::new();
    h.write_user_mode("[network]\nallow_host = true\n", 0o000);
    let out = h.launch_default("shell");
    let stderr = stderr_of(&out);
    assert!(
        !out.status.success(),
        "an unreadable config must fail the launch"
    );
    assert!(stderr.contains("config"), "{stderr}");
    assert!(!stderr.contains(CONFIG_MARKER), "{stderr}");
    assert!(!h.state_root.join("msb-home").exists());
    assert!(
        h.msb_log().is_empty(),
        "msb must not be touched: {}",
        h.msb_log()
    );
    // Restore the mode so the `TempDir` guard can remove the tree.
    std::fs::set_permissions(h.user_config(), std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// RB: the config path is a directory, not a regular file: refused, with no
/// launch state created. (The T4 `directory` row is a group-writable *parent*,
/// not a directory at the path itself.)
#[test]
fn directory_at_the_user_config_path_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let h = Harness::new();
    let dir = h.user_config();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let out = h.launch_default("shell");
    let stderr = stderr_of(&out);
    assert!(!out.status.success(), "{stderr}");
    assert!(!stderr.contains(CONFIG_MARKER), "{stderr}");
    assert!(h.msb_log().is_empty(), "msb log: {}", h.msb_log());
}

/// RC: the config **directory** (`~/.config/agent-vm`) is itself a symlink to
/// another directory holding a normal `0600`, singly-linked `[network]` file.
/// The final component is a regular file, so the `O_NOFOLLOW` first open does
/// not refuse it, and the parent check resolves the link to a user-owned,
/// non-`go-w` directory: the table is **accepted**. This is the documented
/// ADR-0040 route — a symlinked *directory* is followed under the stable-route
/// assumption, and ADR-0038 still refuses the exposing launch that could plant
/// the link. Contrast the final-component symlink (`config.toml -> ...`),
/// which is refused.
#[test]
fn symlinked_user_config_directory_is_followed() {
    use std::os::unix::fs::PermissionsExt;
    let h = Harness::warm();
    let real = h.home_root.join("realcfg");
    write(&real.join("config.toml"), "[network]\nallow_host = true\n");
    std::fs::set_permissions(
        real.join("config.toml"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
    let link = h.user_config().parent().unwrap().to_path_buf();
    std::fs::create_dir_all(link.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let out = h.launch_default("shell");
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(CONFIG_MARKER),
        "a symlinked config directory is an accepted, documented ADR-0040 route: {stderr}"
    );
}

/// RD: `[network]` type and unknown-key errors are value-safe at the
/// integration boundary: the launch is refused, the sentinel value never
/// reaches stderr, and the fake `msb` is untouched. The unit tests pin the
/// message text; this pins that the real binary's rendering never echoes the
/// value.
#[test]
fn user_network_type_errors_are_value_safe() {
    const SENTINEL: &str = "sk-live-SENTINEL-305";
    for text in [
        format!("[network]\nallow_egress = \"{SENTINEL}\"\n"),
        format!("[network]\nallow_host = \"{SENTINEL}\"\n"),
        format!("[network]\n{SENTINEL} = true\n"),
        "[network]\nallow_egress = [\"10.0.0.1\", 7]\n".to_string(),
    ] {
        let h = Harness::new();
        h.write_user_mode(&text, 0o600);
        let out = h.launch_default("shell");
        let stderr = stderr_of(&out);
        assert!(!out.status.success(), "must refuse: {text}");
        assert!(!stderr.contains(SENTINEL), "value leaked: {stderr}");
        assert!(h.msb_log().is_empty(), "msb log: {}", h.msb_log());
    }
}

/// T5: tools-only symlinks remain compatible; detects unconditional refusal.
#[test]
fn symlinked_user_config_without_network_still_launches() {
    let h = Harness::warm();
    h.write_user_mode("# no authority\n", 0o600);
    let target = h.project_root.join("dotfile");
    std::fs::rename(h.user_config(), &target).unwrap();
    h.symlink_user_config(&target);
    assert!(stderr_of(&h.launch_default("shell")).contains(CONFIG_MARKER));
}

/// T6: persisted hostnames refuse proxies before state; detects late refusal.
#[test]
fn saved_hostname_with_host_proxy_is_refused_before_state() {
    for extra in [
        vec![],
        vec!["--allow-lan=false", "--allow-egress", "10.0.0.1"],
    ] {
        let h = Harness::new();
        h.write_user_mode(
            "# sk-live-SENTINEL-305\n[network]\nallow_egress = [\"api.example.com\"]\n",
            0o600,
        );
        let out = h.launch_with_env("shell", &extra, &[("HTTPS_PROXY", "http://127.0.0.1:9")]);
        assert_saved_refusal(
            &h,
            &out,
            "hostname allowances cannot be enforced through the host HTTP proxy",
            false,
        );
        assert!(stderr_of(&out).contains(&format!("hostname allowances cannot be enforced through the host HTTP proxy (HTTPS_PROXY/HTTP_PROXY/ALL_PROXY): the proxy resolves the name, so the address scope is not checked; unset the proxy, use an IP/CIDR allowance, or use --allow-internet-egress (persisted hostname grants from \"{}\" [network] apply to every launch; remove them there)", h.user_config().display())));
    }
    let h = Harness::warm();
    h.write_user_mode("[network]\n", 0o600);
    assert!(
        stderr_of(&h.launch_with_env("shell", &[], &[("HTTPS_PROXY", "http://127.0.0.1:9")]))
            .contains(CONFIG_MARKER)
    );
}

/// T7: persisted hostname grants cover requests; detects missing coverage.
#[test]
fn saved_hostname_grant_covers_tool_requests() {
    for saved in [false, true] {
        let h = Harness::warm();
        h.write_project(&format!(
            "{FETCHER}network_requests = [\"api.example.com\"]\n"
        ));
        if saved {
            h.write_user_mode("[network]\nallow_egress = [\"api.example.com\"]\n", 0o600);
        }
        let out = h.launch_default("fetcher");
        let stderr = stderr_of(&out);
        assert!(stderr.contains(CONFIG_MARKER));
        assert_eq!(stderr.contains("unmet:"), !saved);
        if saved {
            assert!(stderr.contains("all 1 covered"), "{stderr}");
        }
    }
}

/// T8: credential overlays preserve grants; detects policy replacement.
#[test]
fn saved_grants_survive_the_credential_overlay() {
    let h = Harness::warm();
    h.write_user_mode(&format!("{ONE_YAML_TOOL}\n[network]\nallow_lan = true\nallow_egress = [\"api.example.com\",\"tcp://git.example.com:8443\"]\n"), 0o600);
    write_credentials(
        &h.home_root,
        "credentials:\n  - service: my-service\n    apiKey:\n      name: MY_SERVICE_KEY\n      sentinelEnv: true\n      inject: [{domain: 'api.my-service.example:9443', header: x-api-key, format: '%s'}]\n",
    );
    let out = h.launch_with_env(
        "t",
        &[],
        &[(
            "AGENT_VM_TEST_CREDENTIAL",
            "my-service=sk-test-overlay-value",
        )],
    );
    let config = normalized_config(&h, &out);
    assert_eq!(
        config["network"]["tls"]["intercepted_ports"],
        serde_json::json!([443, 8443, 9443])
    );
    assert_eq!(
        config["network"]["policy"]["rules"],
        serde_json::json!([
            {"direction":"egress","destination":{"group":"private"},"protocols":[],"ports":[],"action":"allow"},
            {"direction":"egress","destination":{"domain":"api.example.com"},"protocols":["tcp"],"ports":[{"start":443,"end":443},{"start":8443,"end":8443}],"action":"allow"},
            {"direction":"egress","destination":{"domain":"git.example.com"},"protocols":["tcp"],"ports":[{"start":8443,"end":8443}],"action":"allow"}
        ])
    );
    assert!(
        !config["network"]["secrets"]["header_credentials"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

/// T9: PN diagnostics match shared oracles; detects harness drift.
#[test]
fn native_row_oracles_are_rendered_diagnostics() {
    let rows: std::collections::BTreeSet<_> = PN_ORACLES
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(|l| l.split_once('\t').unwrap().0)
        .collect();
    assert_eq!(
        rows,
        ["PN1", "PN2", "PN3", "PN4B", "PN5"].into_iter().collect()
    );
    for row in ["PN1", "PN2", "PN3", "PN4B"] {
        let h = Harness::warm();
        if row != "PN1" {
            h.write_user_mode(PN_HOST, 0o600);
        }
        if row == "PN4B" {
            let target = h.project_root.join("dotfile");
            std::fs::rename(h.user_config(), &target).unwrap();
            h.symlink_user_config(&target);
        }
        let extra: &[&str] = if row == "PN3" {
            &["--allow-host=false"]
        } else {
            &[]
        };
        let out = h.launch("shell", extra);
        let stderr = stderr_of(&out);
        for (_, text) in PN_ORACLES
            .lines()
            .filter_map(|l| l.split_once('\t'))
            .filter(|(key, _)| *key == row)
        {
            assert!(stderr.contains(text), "{row}: {stderr}");
        }
    }
}

// Hand-transcribed evidence oracle; never derived from the embedded catalog.
const SHIPPED_REQUESTS: [(&str, &[&str]); 7] = [
    ("dsh", &[]),
    (
        "pi",
        &[
            "api.anthropic.com",
            "auth.openai.com",
            "chatgpt.com",
            "mcp-proxy.anthropic.com",
            "platform.claude.com",
        ],
    ),
    (
        "codex",
        &["api.openai.com", "auth.openai.com", "chatgpt.com"],
    ),
    (
        "opencode",
        &[
            "api.openai.com",
            "auth.openai.com",
            "chatgpt.com",
            "models.opencode.ai",
        ],
    ),
    (
        "claude",
        &[
            "api.anthropic.com",
            "mcp-proxy.anthropic.com",
            "platform.claude.com",
        ],
    ),
    // Known incomplete inventory, deferred to #340; empty does not mean offline.
    ("copilot", &[]),
    ("shell", &[]),
];

fn shipped_request_block(tier: &str, total: usize, unmet: &[&str]) -> Vec<String> {
    if total == 0 {
        return vec![];
    }
    if unmet.is_empty() {
        return vec![format!(
            "==> Tool network requests ({tier}): all {total} covered by this launch's {REQUEST_SCOPE}; requests never grant access"
        )];
    }
    let mut lines = vec![format!(
        "==> Tool network requests ({tier}): {} of {total} not covered by this launch's {REQUEST_SCOPE}; requests never grant access and the launch continues",
        unmet.len()
    )];
    lines.extend(unmet.iter().map(|name| format!("==>   unmet: {name}")));
    lines.push(REQUEST_HINT.into());
    lines
}

#[test]
fn shipped_default_network_requests_default_deny() {
    for (tool, names) in SHIPPED_REQUESTS {
        let h = Harness::warm();
        let out = h.launch_default(tool);
        let text = stderr_of(&out);
        assert!(
            text.contains(CONFIG_MARKER) && text.contains("guest command"),
            "{tool}: {text}"
        );
        assert_eq!(
            request_block(&text),
            shipped_request_block("built-in defaults", names.len(), names),
            "{tool}"
        );
        if !names.is_empty() {
            let report = text.find("==> Tool network requests").unwrap();
            for notice in ["==> Egress policy:", "==> Egress DNS:"] {
                assert!(text.find(notice).unwrap() < report, "{text}");
            }
            for notice in ["==> TLS interception:", "==> Guest egress proxy:"] {
                if let Some(pos) = text.find(notice) {
                    assert!(pos < report, "{text}");
                }
            }
            assert!(report < text.find(CONFIG_MARKER).unwrap());
        }
    }
    let h = Harness::warm();
    let text =
        stderr_of(&h.launch_with_env("claude", &[], &[("HTTPS_PROXY", "http://127.0.0.1:9")]));
    assert!(text.contains(CONFIG_MARKER));
    assert_eq!(
        request_block(&text),
        shipped_request_block("built-in defaults", 3, SHIPPED_REQUESTS[4].1)
    );
    assert!(
        text.find("==> Guest egress proxy:").unwrap()
            < text.find("==> Tool network requests").unwrap()
    );
}

#[test]
fn shipped_default_network_requests_partial_and_public_coverage() {
    let names = SHIPPED_REQUESTS[4].1;
    for (flags, unmet) in [
        (vec![], names),
        (vec!["--allow-egress", "api.anthropic.com:443"], &names[1..]),
        (vec!["--allow-egress", "api.anthropic.com:8443"], names),
        (vec!["--allow-internet-egress"], &[][..]),
    ] {
        let h = Harness::warm();
        let text = stderr_of(&h.launch("claude", &flags));
        assert!(text.contains(CONFIG_MARKER), "{text}");
        assert_eq!(
            request_block(&text),
            shipped_request_block("built-in defaults", 3, unmet)
        );
        assert_eq!(text.matches("Tool network requests (").count(), 1);
    }
    for (tool, names) in SHIPPED_REQUESTS
        .into_iter()
        .filter(|(_, names)| !names.is_empty())
    {
        let h = Harness::warm();
        let text = stderr_of(&h.launch(tool, &["--allow-internet-egress"]));
        assert!(text.contains(CONFIG_MARKER));
        assert_eq!(
            request_block(&text),
            shipped_request_block("built-in defaults", names.len(), &[])
        );
    }
    let h = Harness::warm();
    h.write_user("[[tools]]\nname = \"claude\"\ncommand = \"claude\"\n");
    h.write_project(
        "[[tools]]\nname = \"other\"\ncommand = \"echo\"\nnetwork_requests = [\"other.example\"]\n",
    );
    for tool in ["claude", "shell"] {
        let text = stderr_of(&h.launch_default(tool));
        assert!(text.contains(CONFIG_MARKER));
        assert!(request_block(&text).is_empty());
    }
    let text = stderr_of(&h.launch_default("other"));
    assert!(text.contains(CONFIG_MARKER));
    assert_eq!(
        request_block(&text),
        shipped_request_block("project config", 1, &["other.example"])
    );
}

#[test]
fn shipped_default_network_requests_noninterference() {
    let mut stripped: toml::Value =
        toml::from_str(include_str!("../src/default-tools.toml")).unwrap();
    for tool in stripped["tools"].as_array_mut().unwrap() {
        tool.as_table_mut().unwrap().remove("network_requests");
    }
    // toml's production dependency is parse-only. These shipped field values
    // use strings, booleans, arrays and inline env tables; no serializer feature needed.
    fn field(value: &toml::Value) -> String {
        match value {
            toml::Value::Table(table) => format!(
                "{{ {} }}",
                table
                    .iter()
                    .map(|(key, value)| format!("{key} = {}", field(value)))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            _ => serde_json::to_string(value).unwrap(),
        }
    }
    let stripped = stripped["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| {
            format!(
                "[[tools]]\n{}\n",
                tool.as_table()
                    .unwrap()
                    .iter()
                    .map(|(key, value)| format!("{key} = {}", field(value)))
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        })
        .collect::<String>();
    for (tool, _) in SHIPPED_REQUESTS {
        let mut captures = Vec::new();
        for project in [false, true] {
            let h = Harness::warm();
            if project {
                h.write_project(&stripped);
            }
            let out = h.launch_default(tool);
            let text = stderr_of(&out);
            assert!(text.contains(CONFIG_MARKER));
            let config = normalized_config(&h, &out);
            let state = snapshot(&h.state_root.join(project_hash(&h.project_root)));
            let notices: Vec<_> = text
                .lines()
                .filter(|line| {
                    line.starts_with("==> Egress policy:")
                        || line.starts_with("==> Egress DNS:")
                        || line.starts_with("==> TLS interception:")
                })
                .map(str::to_owned)
                .collect();
            captures.push((config, state, notices));
        }
        // Fixed-list snapshot includes credential bytes: never print values on failure.
        assert!(
            captures[0].0 == captures[1].0,
            "{tool}: normalized SandboxConfig changed"
        );
        assert!(
            captures[0].1 == captures[1].1,
            "{tool}: fixed-list state or HOME symlinks changed"
        );
        assert_eq!(
            captures[0].2, captures[1].2,
            "{tool}: authority notices changed"
        );
    }
}

const IMAGE_METADATA_REFUSAL: &str = "the boot image's environment could not be read, so agent-vm cannot verify that a `sentinelEnv: false` variable is unset in the guest";
const ENV_UNSET_REASON: &str = "the host environment variable `MY_SERVICE_KEY` selected by `my-service` (`source: env`) was unset or empty when agent-vm started; export it before launching";

fn env_yaml(required: bool, sentinel: bool) -> String {
    format!(
        "credentials:\n  - service: my-service\n    source: env\n    required: {required}\n    apiKey:\n      name: MY_SERVICE_KEY\n      sentinelEnv: {sentinel}\n      inject: [{{domain: api.my-service.example, scheme: bearer}}]\n"
    )
}

fn env_harness(required: bool, sentinel: bool) -> Harness {
    let h = if sentinel {
        Harness::warm()
    } else {
        Harness::new()
    };
    h.write_user(ONE_YAML_TOOL);
    write_credentials(&h.home_root, &env_yaml(required, sentinel));
    h
}

fn rendered_output(out: &Output) -> String {
    format!("{}{}", stdout_of(out), stderr_of(out))
}

fn assert_no_canary_files(path: &Path, canary: &str) {
    if !path.exists() {
        return;
    }
    for entry in std::fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            assert_no_canary_files(&entry.path(), canary);
        } else if entry.file_type().unwrap().is_file() {
            assert!(
                !std::fs::read(entry.path())
                    .unwrap()
                    .windows(canary.len())
                    .any(|bytes| bytes == canary.as_bytes()),
                "canary in durable file"
            );
        }
    }
}

#[test]
fn an_env_sourced_credential_is_registered_and_its_value_reaches_no_guest_file_output_or_child() {
    let h = env_harness(false, true);
    let canary = "sk-CANARY-163-s1";
    let out = h.launch_with_env(
        "t",
        &[],
        &[
            ("MY_SERVICE_KEY", canary),
            ("PRESENT_CONTROL", "visible-163"),
        ],
    );
    let rendered = rendered_output(&out);
    assert!(h.saw_capability_probe(), "{rendered}");
    let config = debug_config_json(&stderr_of(&out));
    let def = &config["network"]["secrets"]["header_credentials"][0];
    assert_eq!(def["reference"], "my-service");
    assert_eq!(def["origin"]["host"], "api.my-service.example");
    assert_eq!(def["header"], "authorization");
    assert!(env_pairs(&config).contains(&("MY_SERVICE_KEY", "proxy-managed")));
    assert!(!rendered.contains(canary));
    assert_no_canary_files(&h.state_root, canary);
    let state = state_dir(&stderr_of(&out));
    assert_no_canary_files(
        &PathBuf::from(format!("{}.secrets", state.display())),
        canary,
    );
    let child = h.msb_environ();
    assert!(
        child
            .lines()
            .any(|line| line == "PRESENT_CONTROL=visible-163")
    );
    assert!(!child.contains(canary));
    assert!(
        !child
            .lines()
            .any(|line| line.starts_with("MY_SERVICE_KEY="))
    );
}

#[test]
fn an_env_source_with_sentinel_false_fails_closed_on_unreadable_image_metadata_without_echo() {
    let h = env_harness(false, false);
    let canary = "sk-CANARY-163-s2";
    let out = h.launch_with_env("t", &[], &[("MY_SERVICE_KEY", canary)]);
    let rendered = rendered_output(&out);
    assert!(!out.status.success());
    assert_cold_preparation_failure(&h, &out);
    assert!(!rendered.contains(canary));
    // Control: an OCI target keeps the runnable refresh suggestion.
    assert!(
        rendered.contains("preparing the boot image"),
        "the OCI control must still suggest refresh: {rendered}"
    );

    // S4: `image refresh` acquires OCI references only, so recommending it for
    // a local rootfs/disk launch names a command that always refuses the
    // user's own image. The refusal and the `sentinelEnv: true` alternative
    // stay; the refresh suggestion does not. Both selection sources are pinned.
    for (source, argv, envs) in [
        ("cli", vec!["--image", "../rootfs"], vec![]),
        ("env", vec![], vec![("AGENT_VM_IMAGE_TAG", "../rootfs")]),
    ] {
        let out = h.launch_argv("t", &argv, &envs);
        let rendered = rendered_output(&out);
        assert!(!out.status.success(), "{source}: must fail closed");
        assert!(
            rendered.contains(IMAGE_METADATA_REFUSAL),
            "{source}: {rendered}"
        );
        assert!(
            rendered.contains("Alternatively declare") && rendered.contains("`sentinelEnv: true`"),
            "{source}: the alternative must be offered: {rendered}"
        );
        assert!(
            !rendered.contains("agent-vm image refresh"),
            "{source}: a local launch must not recommend refresh: {rendered}"
        );
        assert!(!rendered.contains(canary), "{source}: {rendered}");
        // No VM: no capability probe and no launch invocation (the fake msb
        // still answers its version probe).
        assert!(!h.saw_capability_probe(), "{source}");
        assert!(
            h.msb_log().lines().all(|line| line == "--version"),
            "{source}: no VM may be launched: {}",
            h.msb_log()
        );
    }
}

fn assert_unset_stage(required: bool, extra: &[&str], envs: &[(&str, &str)]) {
    let h = env_harness(required, true);
    let out = h.launch_with_env("t", extra, envs);
    let rendered = rendered_output(&out);
    let rescued = !extra.is_empty();
    assert!(!out.status.success());
    if !required || rescued {
        let suffix = if required {
            "; continuing without it because --allow-missing-credentials was passed"
        } else {
            "; continuing without it"
        };
        assert!(
            rendered.contains(&format!("warning: {ENV_UNSET_REASON}{suffix}")),
            "{rendered}"
        );
        assert!(rendered.contains(CONFIG_MARKER), "{rendered}");
    } else {
        assert!(rendered.contains(ENV_UNSET_REASON), "{rendered}");
        assert!(!rendered.contains(&format!("warning: {ENV_UNSET_REASON}")));
        assert!(!rendered.contains(IMAGE_METADATA_REFUSAL));
    }
    assert_eq!(rendered.contains(CONFIG_MARKER), !required || rescued);
    assert!(!rendered.contains("sk-CANARY-163-s3"));
}

#[test]
fn an_unset_optional_env_source_warns_and_proceeds_to_the_image_metadata_guard() {
    assert_unset_stage(
        false,
        &[],
        &[("AGENT_VM_TEST_CREDENTIAL", "my-service=sk-CANARY-163-s3")],
    );
}
#[test]
fn an_unset_required_env_source_fails_before_the_image_stage() {
    assert_unset_stage(
        true,
        &[],
        &[("AGENT_VM_TEST_CREDENTIAL", "my-service=sk-CANARY-163-s3")],
    );
}
#[test]
fn an_unset_required_env_source_with_the_override_warns_and_proceeds_to_the_image_metadata_guard() {
    assert_unset_stage(
        true,
        &["--allow-missing-credentials"],
        &[("AGENT_VM_TEST_CREDENTIAL", "my-service=sk-CANARY-163-s3")],
    );
}
/// An empty selected variable is a *selected* value: it must be removed from
/// agent-vm's environment just like a non-empty one, so no child inherits an
/// `MY_SERVICE_KEY=` binding (set-but-empty differs from unset for a child and
/// for the guest). The non-empty case is covered by
/// `an_env_sourced_credential_is_registered_…`; the empty case only reached the
/// in-process adapter (E2/E4), never an actual child environment, so a change
/// that moved `remove_var` behind the non-empty branch would pass every
/// existing test. This drives the real binary and inspects the fake `msb`'s
/// environment.
#[test]
fn an_empty_env_value_is_removed_from_the_child_environment() {
    let h = env_harness(false, true);
    let out = h.launch_with_env(
        "t",
        &[],
        &[("MY_SERVICE_KEY", ""), ("PRESENT_CONTROL", "visible-163")],
    );
    let child = h.msb_environ();
    // Positive control: the child env dump was actually captured, so the
    // absence assertion below cannot pass on an unreadable/empty log.
    assert!(
        child
            .lines()
            .any(|line| line == "PRESENT_CONTROL=visible-163"),
        "child environment was not captured: {child:?}"
    );
    assert!(
        !child
            .lines()
            .any(|line| line.starts_with("MY_SERVICE_KEY=")),
        "an empty selected variable was inherited by a child: {child:?}"
    );
    // Same documented stage as an unset value: warn, then the image guard.
    let rendered = rendered_output(&out);
    assert!(rendered.contains(ENV_UNSET_REASON), "{rendered}");
}

#[test]
fn an_empty_env_value_is_unset_but_a_malformed_one_is_refused() {
    assert_unset_stage(false, &[], &[("MY_SERVICE_KEY", "")]);
    for extra in [&[][..], &["--allow-missing-credentials"][..]] {
        let h = env_harness(false, true);
        let out = h.launch_with_env("t", extra, &[("MY_SERVICE_KEY", " sk-CANARY-163-s4")]);
        let rendered = rendered_output(&out);
        assert!(!out.status.success());
        assert!(rendered.contains("MY_SERVICE_KEY"));
        assert!(rendered.contains("leading or trailing space"));
        assert!(!rendered.contains("sk-CANARY-163-s4"));
        assert!(!rendered.contains(IMAGE_METADATA_REFUSAL));
        assert!(!rendered.contains(CONFIG_MARKER));
        assert!(!h.saw_capability_probe());
    }
}
#[test]
fn an_unset_env_source_does_not_fall_back_to_a_stored_value() {
    let h = env_harness(false, true);
    h.write_user(&ONE_YAML_TOOL.replace("[\"my-service\"]", "[\"my-service\", \"other-service\"]"));
    write_credentials(
        &h.home_root,
        &(env_yaml(false, true)
            + "  - service: other-service\n    apiKey:\n      name: OTHER_SERVICE_KEY\n      inject: [{domain: api.other.example, scheme: bearer}]\n"),
    );
    let out = h.launch_with_env(
        "t",
        &[],
        &[(
            "AGENT_VM_TEST_CREDENTIAL",
            "my-service=sk-CANARY-163-keychain",
        )],
    );
    let rendered = rendered_output(&out);
    assert!(
        rendered.contains(&format!(
            "warning: {ENV_UNSET_REASON}; continuing without it"
        )),
        "{rendered}"
    );
    assert!(
        rendered.contains("warning: no value is stored in the system keychain for `other-service`"),
        "{rendered}"
    );
    assert!(rendered.contains(CONFIG_MARKER));
    assert!(!rendered.contains("sk-CANARY-163-keychain"));
}
#[test]
fn host_api_key_variables_are_never_forwarded() {
    let h = Harness::warm();
    let out = h.launch_with_env(
        "claude",
        &[],
        &[
            ("ANTHROPIC_API_KEY", "sk-CANARY-163-anthropic"),
            ("OPENAI_API_KEY", "sk-CANARY-163-openai"),
        ],
    );
    let rendered = rendered_output(&out);
    assert!(!rendered.contains("sk-CANARY-163-"));
    let config = debug_config_json(&stderr_of(&out));
    assert!(
        !env_pairs(&config)
            .iter()
            .any(|(name, _)| ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"].contains(name))
    );
    assert!(registered_secret_env_vars(&config).contains(&"MSB_AGENT_VM_ANTHROPIC_UNUSED"));
}
#[test]
fn an_unrequested_env_authorization_is_inert() {
    let h = Harness::new();
    h.write_user(ONE_YAML_TOOL);
    write_credentials(
        &h.home_root,
        &env_yaml(false, true)
            .replace("my-service", "other")
            .replace("MY_SERVICE_KEY", "OTHER_KEY"),
    );
    let out = h.launch_with_env("t", &[], &[("OTHER_KEY", "visible-163-inert")]);
    assert!(rendered_output(&out).contains("neither a built-in"));
    assert!(
        h.msb_environ()
            .lines()
            .any(|line| line == "OTHER_KEY=visible-163-inert")
    );
}
#[test]
fn a_requested_keychain_authorization_does_not_capture_its_host_variable() {
    let h = env_harness(false, true);
    write_credentials(
        &h.home_root,
        &env_yaml(false, true).replace("    source: env\n", ""),
    );
    let out = h.launch_with_env(
        "t",
        &[],
        &[
            ("MY_SERVICE_KEY", "visible-163-keychain-name"),
            ("AGENT_VM_TEST_CREDENTIAL", "my-service=sk-CANARY-163-store"),
        ],
    );
    assert!(h.saw_capability_probe());
    assert!(
        h.msb_environ()
            .lines()
            .any(|line| line == "MY_SERVICE_KEY=visible-163-keychain-name")
    );
    assert!(!rendered_output(&out).contains("sk-CANARY-163-store"));
}
#[test]
fn the_override_does_not_bypass_an_unknown_source() {
    let h = env_harness(false, true);
    write_credentials(
        &h.home_root,
        &env_yaml(false, true).replace("source: env", "source: keychain"),
    );
    assert_the_override_does_not_bypass(&h, "t", &[], "`source` must be `env`");
}

#[test]
fn a_launch_option_before_a_builtin_is_a_usage_error() {
    let harness = Harness::new();
    for (argv, option) in [
        (vec!["--mount", "/x", "doctor"], "--mount"),
        (vec!["--image", CLI_REF, "image", "refresh"], "--image"),
        (vec!["--image", CLI_REF, "setup"], "--image"),
    ] {
        let out = harness.builtin(&argv, &[]);
        assert_eq!(out.status.code(), Some(2));
        assert!(stderr_of(&out).contains(&format!("'{option}'")));
    }
}

#[test]
fn bare_argv_keeps_help_independent_of_launch_env() {
    use std::os::unix::ffi::OsStringExt;
    for broken in [false, true] {
        let harness = Harness::new();
        if broken {
            harness.write_project(BROKEN);
        }
        for (name, value) in [
            ("AGENT_VM_MEMORY_GIB", std::ffi::OsString::from("4")),
            ("AGENT_VM_MEMORY_GIB", "abc".into()),
            ("AGENT_VM_CPUS", "abc".into()),
            (
                "AGENT_VM_IMAGE_TAG",
                std::ffi::OsString::from_vec(vec![0xff]),
            ),
        ] {
            let out = harness.base_command().env(name, value).output().unwrap();
            assert_eq!(out.status.code(), Some(2));
            let text = stderr_of(&out);
            for expected in ["Usage:", "doctor", "Sandbox resources", "Mounts & ports"] {
                assert!(text.contains(expected), "{text}");
            }
            for forbidden in ["requires a subcommand", "invalid value", "invalid UTF-8"] {
                assert!(!text.contains(forbidden), "{text}");
            }
        }
    }
}

#[test]
fn a_registry_miss_for_an_explicit_tag_hints_the_import() {
    let harness = Harness::new();
    harness.write_project(PROBE_TOOL);
    let decoys = harness.builder_decoys();
    let out = Harness::run_on(
        harness.command_with_decoys(&decoys),
        &["--image", BOGUS_IMAGE, "probe"],
    );
    let stderr = stderr_of(&out);
    assert!(!out.status.success(), "{stderr}");
    assert!(stderr.contains("registry error"), "{stderr}");
    assert!(
        stderr.contains(&format!(
            "agent-vm image import --docker {BOGUS_IMAGE} --tag {BOGUS_IMAGE}"
        )),
        "{stderr}"
    );
    assert!(
        stderr.contains("hint: an image that exists only in your local Docker daemon"),
        "{stderr}"
    );
    assert!(harness.decoy_log(&decoys).is_empty());
}

#[test]
fn a_non_ascii_tag_hint_is_copy_pasteable() {
    let harness = Harness::new();
    harness.write_project(PROBE_TOOL);
    let out = harness.launch_argv("probe", &["--image", "localhost:1/does-not-exist:é"], &[]);
    let stderr = stderr_of(&out);
    assert!(!out.status.success());
    assert!(stderr.contains("registry error"), "{stderr}");
    assert!(stderr.contains("agent-vm image import --docker $'localhost:1/does-not-exist:\\xc3\\xa9' --tag $'localhost:1/does-not-exist:\\xc3\\xa9'"), "{stderr}");
    // `$'…'` is not POSIX, so the hint names the shells that read it.
    assert!(
        stderr.contains("The commands above are quoted for bash or zsh."),
        "{stderr}"
    );
    for line in stderr
        .lines()
        .filter(|line| line.contains("agent-vm image import"))
    {
        assert!(!line.contains('é'));
    }
}

#[test]
fn refresh_and_setup_give_the_same_hint() {
    let harness = Harness::new();
    harness.write_project(PROBE_TOOL);
    for verb in ACQUISITION_VERBS {
        let mut argv = verb.to_vec();
        argv.extend_from_slice(&["--image", CLI_REF]);
        let out = harness.builtin(&argv, &[]);
        let verb = verb_name(verb);
        let stderr = stderr_of(&out);
        assert!(!out.status.success(), "{stderr}");
        // The registry chain stays beneath the hint: the two must not trade
        // places (the shared `pull.rs` path, story 14).
        assert!(stderr.contains("registry error"), "{verb}: {stderr}");
        assert!(
            stderr.contains("hint: an image that exists only in your local Docker daemon"),
            "{verb}: {stderr}"
        );
        assert!(
            stderr.contains(&format!(
                "agent-vm image import --docker {CLI_REF} --tag {CLI_REF}"
            )),
            "{verb}: {stderr}"
        );
        // A plain reference needs no quoting, so no shell is named.
        assert!(
            !stderr.contains("quoted for bash or zsh"),
            "{verb}: {stderr}"
        );
    }
}

#[test]
fn a_digest_pinned_registry_miss_has_no_hint() {
    let harness = Harness::new();
    harness.write_project(PROBE_TOOL);
    let raw = format!("localhost:1/does-not-exist@sha256:{}", "b".repeat(64));
    let out = harness.launch_argv("probe", &["--image", &raw], &[]);
    let stderr = stderr_of(&out);
    assert!(!out.status.success());
    assert!(stderr.contains("registry error"), "{stderr}");
    assert!(!stderr.contains("agent-vm image import"), "{stderr}");
    // The same suppression at the shared refresh/setup call site (`pull.rs`),
    // not only at launch: a digest there is equally not an import target.
    for verb in ACQUISITION_VERBS {
        let mut argv = verb.to_vec();
        argv.extend_from_slice(&["--image", &raw]);
        let out = harness.builtin(&argv, &[]);
        let verb = verb_name(verb);
        let stderr = stderr_of(&out);
        assert!(!out.status.success(), "{verb}: {stderr}");
        assert!(stderr.contains("registry error"), "{verb}: {stderr}");
        assert!(!stderr.contains("hint:"), "{verb}: {stderr}");
        assert!(
            !stderr.contains("agent-vm image import"),
            "{verb}: {stderr}"
        );
    }
}

// ---------------------------------------------------------------------------
// The shared/exclusive publication barrier and the launcher's cache validation
// ---------------------------------------------------------------------------

use acquisition_gate::{AcquisitionGate, AcquisitionStage, GateReply, Peer};
use oci_registry::Server;

/// The barrier's lock file in `cache`.
fn publication_lock(cache: &Path) -> PathBuf {
    cache.join(".agent-vm-publication.lock")
}

/// Assert a real `flock` attempt on the publication lock finds it held.
fn assert_barrier_held(cache: &Path) {
    let path = publication_lock(cache);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .unwrap_or_else(|error| panic!("open {}: {error}", path.display()));
    match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
        Err(rustix::io::Errno::WOULDBLOCK) => {}
        Ok(()) => panic!("the publication lock was free while a preparation held it"),
        Err(error) => panic!("probe {}: {error}", path.display()),
    }
}

/// Assert a real `flock` attempt on the publication lock can be taken *shared*:
/// the holder is a preparation, not an exclusive publisher, and another reader
/// would coexist with it.
fn assert_barrier_held_shared(cache: &Path) {
    let path = publication_lock(cache);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .unwrap_or_else(|error| panic!("open {}: {error}", path.display()));
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockShared).unwrap_or_else(
        |error| {
            panic!(
                "{} was not held in a mode a reader may share: {error}",
                path.display()
            )
        },
    );
}

/// Hold the exclusive publication lock in this test process (a faithful
/// publisher stand-in using the real syscall).
fn hold_exclusive_publication(cache: &Path) -> std::fs::File {
    std::fs::create_dir_all(cache).unwrap();
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(publication_lock(cache))
        .unwrap();
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .expect("the test must take the exclusive publication lock");
    file
}

fn status_ok(out: &Output, context: &str) {
    assert!(
        out.status.success(),
        "{context}:\nstdout: {}\nstderr: {}",
        stdout_of(out),
        stderr_of(out)
    );
}

fn cache_metadata(cache: &Path, raw: &str) -> PathBuf {
    microsandbox_image::GlobalCache::new(cache)
        .unwrap()
        .image_metadata_path(&raw.parse().unwrap())
}

/// The manifest digest the native cache currently holds for `raw`'s key.
fn cached_manifest_digest(cache: &Path, raw: &str) -> String {
    let path = cache_metadata(cache, raw);
    let metadata: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
    .unwrap();
    metadata["manifest_digest"]
        .as_str()
        .unwrap_or_else(|| panic!("no manifest digest in {metadata}"))
        .to_owned()
}

/// A cold acquisition stalled in a registry stream holds the **shared** barrier
/// (proved by an independent shared `flock` that succeeds); an unrelated warm
/// launch on the same cache still reaches the SDK's cache consumption (create),
/// with zero registry traffic of its own measured after the create attempt.
#[test]
fn unrelated_stall_does_not_block_a_warm_launch() {
    let cache = support::project_tempdir();
    let cache = cache.path();
    let server = Server::new();

    // Two projects: distinct HOME/state, one shared cache.
    let x = Harness::new();
    let y = Harness::new();
    let x_image = x.image(&image_archive::ArchiveSpec {
        marker: "a06-x".into(),
        ..Default::default()
    });
    let x_tag = format!("{}/repo:x", server.host);
    server.image("repo", "x", &x_image);
    let y_image = y.image(&image_archive::ArchiveSpec {
        marker: "a06-y".into(),
        ..Default::default()
    });
    let y_tag = format!("{}/repo:y", server.host);
    server.image("repo", "y", &y_image);
    status_ok(
        &x.run_shared(cache, &["image", "refresh", "--image", &y_tag]),
        "warming Y in the shared cache",
    );

    // Calibrate Y independently: no X exists to mask a missing launch hold.
    let mut y = y;
    y.use_launch_runtime();
    let mut solo_gate = AcquisitionGate::new(y._home.path());
    let mut solo_cmd = y.shared_command(cache);
    solo_cmd.args(["--image", &y_tag, "--root", "shell"]);
    let solo = Peer::spawn(solo_cmd, &solo_gate, &[]);
    let parked = solo_gate.expect(AcquisitionStage::BeforeSdkConsume);
    assert_barrier_held(cache);
    assert_barrier_held_shared(cache);
    parked.reply(GateReply::Continue);
    solo_gate
        .expect(AcquisitionStage::CreateReturned)
        .reply(GateReply::Continue);
    assert!(!solo.wait().status.success());

    // Cold X stalls mid-blob, holding the shared barrier.
    let ready = server.stall_blob(&format!("/v2/repo/blobs/{}", x_image.written.layer_digest));
    let mut x_cmd = x.shared_command(cache);
    x_cmd
        .args(["image", "refresh", "--image", &x_tag])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let x_child = x_cmd.spawn().expect("spawn the stalled acquisition");
    ready
        .recv_timeout(Duration::from_secs(30))
        .expect("the stalled blob handshake must arrive");
    assert_barrier_held(cache);

    // Warm Y launch with a real runtime pair: it must reach the SDK
    // consumption gate while X is still stalled.
    let mut gate = AcquisitionGate::new(y._home.path());
    let mut y_cmd = y.shared_command(cache);
    // Root mode skips the non-root identity append, which the tiny fixture
    // rootfs cannot satisfy; the launch still consumes the cached image.
    y_cmd.args(["--image", &y_tag, "--root", "shell"]);
    let requests_before = server.count();
    let consumed_before = y
        .msb_log()
        .lines()
        .filter(|line| line.starts_with("machine "))
        .count();
    let launch = Peer::spawn(y_cmd, &gate, &[]);
    let parked = gate.expect(AcquisitionStage::BeforeSdkConsume);
    // Still stalled. The barrier is held in a mode this reader may share, which
    // an exclusive holder (or a launched create that took EX) could not offer.
    assert_barrier_held(cache);
    assert_barrier_held_shared(cache);

    parked.reply(GateReply::Continue);

    // Let create run (the fake runtime fails 93 by design) and release. The
    // request delta is read *after* the create attempt, because create is the
    // only step that could reach the registry.
    gate.expect(AcquisitionStage::CreateReturned)
        .reply(GateReply::Continue);
    let launch_out = launch.wait();
    assert_eq!(
        server.count(),
        requests_before,
        "a warm launch must not query the registry (delta measured after create)"
    );
    assert!(
        !launch_out.status.success(),
        "the fixture runtime never fakes a successful VM"
    );
    // X is still stalled: Y progressed while X legitimately owns the shared
    // barrier. The stalled stream is abandoned (the fixture's release closes
    // it), so reap it rather than pretend it can complete.
    let mut x_child = x_child;
    assert!(
        x_child.try_wait().unwrap().is_none(),
        "the unrelated acquisition finished without being released"
    );
    let _ = x_child.kill();
    let _ = x_child.wait();
    server.release_blob();

    // The launch reached native cache consumption: the runtime was invoked
    // with something other than the version/protocol probes.
    let log = y.msb_log();
    let consumed = log
        .lines()
        .filter(|line| line.starts_with("machine "))
        .count()
        > consumed_before;
    assert!(
        consumed,
        "the SDK never invoked the runtime for a warm cache; log: {log}; stderr: {}",
        stderr_of(&launch_out)
    );
}

/// Archive publication cannot cross a validated SDK consumption.
///
/// A launch parked after its cache validation and before the SDK consumes the
/// cache holds the barrier shared. Independent `flock` probes show that (shared
/// succeeds, exclusive contends), an import's exclusive publication cannot
/// proceed, and the aliases stay byte-identical until create returns. Only
/// release lets the import complete and the alias actually change. The reverse
/// order also holds: a held exclusive publisher blocks preparation before its
/// first cache read.
#[test]
fn archive_publication_cannot_cross_validated_sdk_consumption() {
    let cache = support::project_tempdir();
    let cache = cache.path();
    let server = Server::new();
    let h = Harness::new();
    let a = h.image(&image_archive::ArchiveSpec {
        marker: "a07-a".into(),
        ..Default::default()
    });
    let tag = format!("{}/repo:tag", server.host);
    server.image("repo", "tag", &a);
    status_ok(
        &h.run_shared(cache, &["image", "refresh", "--image", &tag]),
        "warming A",
    );
    let mut h = h;
    h.use_launch_runtime();
    let a_digest = a.written.manifest_digest.clone();
    let canonical_a = format!("{}/repo@{a_digest}", server.host);
    let tag_bytes = std::fs::read(cache_metadata(cache, &tag)).unwrap();
    let canonical_bytes = std::fs::read(cache_metadata(cache, &canonical_a)).unwrap();

    // Launch paused after validation, before the SDK consumes the cache.
    let mut gate = AcquisitionGate::new(h._home.path());
    let mut launch_cmd = h.shared_command(cache);
    launch_cmd.args(["--image", &tag, "--root", "shell"]);
    let launch = Peer::spawn(launch_cmd, &gate, &[]);
    let before_consume = gate.expect(AcquisitionStage::BeforeSdkConsume);
    assert_barrier_held(cache);
    assert_barrier_held_shared(cache);

    assert!(
        !h.msb_log().lines().any(|line| line.starts_with("machine ")),
        "the SDK must not have consumed the cache while parked before consumption"
    );

    // Import B under the same tag AND the digest-spelled alias of A. The
    // publisher must block on the exclusive barrier, leaving both aliases
    // untouched while the launcher still owns its validated snapshot.
    let save = image_archive::write_docker_save(
        &h.home_root.join("a07-b.tar"),
        &[image_archive::DockerSaveImage {
            marker: "a07-b".into(),
            repo_tags: Some(vec![tag.clone(), canonical_a.clone()]),
        }],
    );
    let import_tag = format!("{}/repo:imported", server.host);
    let mut import_gate = AcquisitionGate::new(h._home.path());
    let mut import_cmd = h.shared_command(cache);
    import_cmd
        .args([
            "image",
            "import",
            "--input",
            &save[0].path.to_string_lossy(),
            "--tag",
            &import_tag,
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let import_child = Peer::spawn(import_cmd, &import_gate, &[]);
    let waiting = import_gate.expect(AcquisitionStage::PublicationContended);
    assert_barrier_held(cache);
    assert_barrier_held_shared(cache);
    assert_eq!(
        std::fs::read(cache_metadata(cache, &tag)).unwrap(),
        tag_bytes
    );
    assert_eq!(
        std::fs::read(cache_metadata(cache, &canonical_a)).unwrap(),
        canonical_bytes
    );
    waiting.reply(GateReply::Continue);
    before_consume.reply(GateReply::Continue);

    // Create consumes the cache and fails (fixture runtime), releasing.
    gate.expect(AcquisitionStage::CreateReturned)
        .reply(GateReply::Continue);
    let launch_out = launch.wait();
    assert!(!launch_out.status.success());
    let import_out = import_child.wait();
    status_ok(
        &import_out,
        "the import after the launch released the barrier",
    );
    let log = h.msb_log();
    assert!(
        log.lines().any(|line| {
            let first = line.split_whitespace().next().unwrap_or("");
            !first.is_empty() && first != "--version" && first != "__launch-protocol"
        }),
        "the SDK never consumed the cache before the import ran; log: {log}"
    );
    // The alias overwrite really happened (the test is not vacuous) and the
    // next explicit preparation repairs canonical A.
    assert_ne!(
        std::fs::read(cache_metadata(cache, &canonical_a)).unwrap(),
        canonical_bytes,
        "the import fixture must overwrite the digest-spelled alias"
    );
    let requests_before = server.count();
    let mut repair_gate = AcquisitionGate::new(h._home.path());
    let mut repair_cmd = h.shared_command(cache);
    repair_cmd.args(["--image", &canonical_a, "--root", "shell"]);
    let repair = Peer::spawn(repair_cmd, &repair_gate, &[]);
    repair_gate
        .expect(AcquisitionStage::BeforeSdkConsume)
        .reply(GateReply::Continue);
    repair_gate
        .expect(AcquisitionStage::CreateReturned)
        .reply(GateReply::Continue);
    assert!(!repair.wait().status.success());
    assert_eq!(
        server.count(),
        requests_before,
        "receipt repair must be offline"
    );
    let receipt = std::fs::read_dir(cache.join("agent-vm-content-metadata"))
        .unwrap()
        .map(|entry| {
            serde_json::from_slice::<serde_json::Value>(
                &std::fs::read(entry.unwrap().path()).unwrap(),
            )
            .unwrap()
        })
        .find(|value| value["acquired_reference"] == canonical_a)
        .unwrap();
    assert_eq!(receipt["metadata"]["manifest_digest"], a_digest);
    assert_eq!(
        receipt["metadata"]["config_digest"],
        a.written.config_digest
    );
    assert_eq!(
        receipt["content_identity"]["config_digest"],
        receipt["metadata"]["config_digest"]
    );
    let repaired: serde_json::Value =
        serde_json::from_slice(&std::fs::read(cache_metadata(cache, &canonical_a)).unwrap())
            .unwrap();
    assert_eq!(repaired["manifest_digest"], a_digest);
    assert_eq!(repaired["config_digest"], a.written.config_digest);

    // Reverse order: an exclusive publisher blocks shared preparation before
    // its first cache read (no acquisition checkpoint at all).
    let held = hold_exclusive_publication(cache);
    let mut gate = AcquisitionGate::new(h._home.path());
    let mut blocked_cmd = h.shared_command(cache);
    blocked_cmd.args(["image", "refresh", "--image", &tag]);
    let blocked = Peer::spawn(blocked_cmd, &gate, &[]);
    let waiting = gate.expect(AcquisitionStage::PublicationContended);
    // The real shared attempt contended while our independent exclusive fd holds.
    waiting.reply(GateReply::Continue);
    drop(held);
    gate.expect(AcquisitionStage::BeforeLock)
        .reply(GateReply::Continue);
    gate.expect(AcquisitionStage::Snapshot)
        .reply(GateReply::Continue);
    gate.expect(AcquisitionStage::NativeOk)
        .reply(GateReply::Continue);
    let blocked_out = blocked.wait();
    status_ok(
        &blocked_out,
        "preparation after the exclusive publisher released",
    );
}

/// The uppercase-hex spelling of `pin`'s digest: a real OCI reference the native
/// parser accepts that canonicalizes to `pin`. It stands in for an entry an old
/// launcher wrote under its own spelling.
fn upper_hex_spelling(pin: &str) -> String {
    let (head, hex) = pin.rsplit_once(':').expect("repo@algorithm:hex");
    format!("{head}:{}", hex.to_ascii_uppercase())
}

/// A warm cache entry written under an old spelling is reused offline: the
/// launcher validates it, republishes it under the canonical key, and the SDK's
/// `IfMissing` create therefore makes no registry request at all.
#[test]
fn an_old_spelling_warm_cache_launch_is_registry_free() {
    for kind in ["child", "tag", "index"] {
        let cache = support::project_tempdir();
        let cache = cache.path();
        let server = Server::new();
        let mut h = Harness::new();
        let seed = Harness::new();
        let a = h.image(&image_archive::ArchiveSpec {
            marker: format!("old-spelling-{kind}"),
            ..Default::default()
        });
        let child = server.image("repo", "old", &a);
        let index = server.index("repo", "index", a.index.clone());
        let local_host = format!("localhost:{}", server.host.rsplit_once(':').unwrap().1);
        let source = match kind {
            "child" => child,
            "index" => index,
            _ => format!("{}/repo:old", server.host),
        }
        .replace(&server.host, &local_host);
        let old_source = if kind == "tag" {
            source.replace("localhost", "LOCALHOST")
        } else {
            upper_hex_spelling(&source)
        };
        assert_ne!(old_source, source);
        status_ok(
            &seed.run_shared(cache, &["image", "refresh", "--image", &source]),
            "warming canonical source",
        );
        let canonical_path = cache_metadata(cache, &source);
        let old_path = cache_metadata(cache, &old_source);
        std::fs::rename(&canonical_path, &old_path).unwrap();
        h.use_launch_runtime();
        let requests_before = server.count();
        // The original spelling provides the bounded compatibility key; the
        // SDK consumes its canonical form, then later canonical-only launches
        // no longer need that compatibility spelling.
        for selected in [&old_source, &source] {
            let mut gate = AcquisitionGate::new(h._home.path());
            let mut cmd = h.shared_command(cache);
            cmd.args(["--image", selected, "--root", "shell"]);
            let launch = Peer::spawn(cmd, &gate, &[]);
            gate.expect(AcquisitionStage::BeforeSdkConsume)
                .reply(GateReply::Continue);
            assert!(
                canonical_path.exists(),
                "{kind}: canonical source must be republished"
            );
            gate.expect(AcquisitionStage::CreateReturned)
                .reply(GateReply::Continue);
            assert!(!launch.wait().status.success());
            assert_eq!(
                server.count(),
                requests_before,
                "{kind}: warm create must be registry-free"
            );
        }
        let receipts = cache.join("agent-vm-content-metadata");
        if kind == "tag" {
            // A native warm entry is usable without a receipt, but must not
            // invent fresh registry evidence while migrating cache metadata.
            for entry in std::fs::read_dir(&receipts).unwrap() {
                std::fs::remove_file(entry.unwrap().path()).unwrap();
            }
        }
        drop(server);
        // Registry is now unavailable, not merely returning a cache-friendly response.
        let mut gate = AcquisitionGate::new(h._home.path());
        let mut cmd = h.shared_command(cache);
        cmd.args(["--image", &source, "--root", "shell"]);
        let launch = Peer::spawn(cmd, &gate, &[]);
        gate.expect(AcquisitionStage::BeforeSdkConsume)
            .reply(GateReply::Continue);
        gate.expect(AcquisitionStage::CreateReturned)
            .reply(GateReply::Continue);
        assert!(!launch.wait().status.success());
        if kind == "tag" {
            assert_eq!(
                std::fs::read_dir(&receipts).unwrap().count(),
                0,
                "cache-only validation must not invent a source binding"
            );
        }
        assert!(
            h.msb_log()
                .lines()
                .filter(|line| line.starts_with("machine "))
                .count()
                >= 3,
            "{kind}: each warm launch must reach the fake runtime, including offline"
        );
    }
}

/// A warm tag hit must not republish the tag key from metadata it read before a
/// concurrent `image refresh` moved the tag.
///
/// Both live exactly once in the window between the launcher's validated read and
/// its return, and both hold the barrier shared, so nothing else excludes them.
/// Only the pre-canonical migration may publish a source key, which is what makes
/// this a deterministic interleaving instead of a race report.
#[test]
fn a_concurrent_tag_move_is_not_reverted_by_a_warm_launch() {
    let cache = support::project_tempdir();
    let cache = cache.path();
    let server = Server::new();
    let mut h = Harness::new();
    let a = h.image(&image_archive::ArchiveSpec {
        marker: "n1-a".into(),
        ..Default::default()
    });
    let b = h.image(&image_archive::ArchiveSpec {
        marker: "n1-b".into(),
        ..Default::default()
    });
    let tag = format!("{}/repo:tag", server.host);
    let moved = format!("{}/repo:moved", server.host);
    server.image("repo", "tag", &a);
    server.image("repo", "moved", &b);
    assert_ne!(a.written.manifest_digest, b.written.manifest_digest);
    status_ok(
        &h.run_shared(cache, &["image", "refresh", "--image", &tag]),
        "warming A under the tag",
    );
    status_ok(
        &h.run_shared(cache, &["image", "refresh", "--image", &moved]),
        "warming B under another tag",
    );
    assert_eq!(
        cached_manifest_digest(cache, &tag),
        a.written.manifest_digest
    );
    h.use_launch_runtime();

    // Park the launcher once it has validated A for this selection, before it
    // publishes anything.
    let mut gate = AcquisitionGate::new(h._home.path());
    let mut cmd = h.shared_command(cache);
    cmd.env("AGENT_VM_TEST_ACQUIRE_GATE_DETAIL", "1");
    cmd.args(["--image", &tag, "--root", "shell"]);
    let launch = Peer::spawn(cmd, &gate, &[]);
    let validated = gate.expect(AcquisitionStage::CacheValidated);
    assert_eq!(
        cached_manifest_digest(cache, &tag),
        a.written.manifest_digest,
        "the parked launcher must have read A"
    );
    // The tag moves to B exactly as a concurrent `image refresh` would leave it.
    let moved_bytes = std::fs::read(cache_metadata(cache, &moved)).unwrap();
    std::fs::write(cache_metadata(cache, &tag), &moved_bytes).unwrap();
    validated.reply(GateReply::Continue);
    gate.expect_eventually(AcquisitionStage::BeforeSdkConsume)
        .reply(GateReply::Continue);
    assert_eq!(
        cached_manifest_digest(cache, &tag),
        b.written.manifest_digest,
        "a warm launch reverted the tag to A"
    );
    gate.expect_eventually(AcquisitionStage::CreateReturned)
        .reply(GateReply::Continue);
    assert!(!launch.wait().status.success());

    // The next warm launch consumes B: it validates the tag key that names B and
    // reaches the fake runtime with no registry traffic at all.
    let requests_before = server.count();
    let consumed_before = h
        .msb_log()
        .lines()
        .filter(|line| line.starts_with("machine "))
        .count();
    let mut gate = AcquisitionGate::new(h._home.path());
    let mut cmd = h.shared_command(cache);
    cmd.args(["--image", &tag, "--root", "shell"]);
    let launch = Peer::spawn(cmd, &gate, &[]);
    gate.expect(AcquisitionStage::BeforeSdkConsume)
        .reply(GateReply::Continue);
    assert_eq!(
        cached_manifest_digest(cache, &tag),
        b.written.manifest_digest,
        "the launch must validate the entry the tag now names"
    );
    gate.expect(AcquisitionStage::CreateReturned)
        .reply(GateReply::Continue);
    let out = launch.wait();
    assert!(
        !out.status.success(),
        "the fixture runtime never boots a VM"
    );
    assert_eq!(
        cached_manifest_digest(cache, &tag),
        b.written.manifest_digest,
        "consuming B must leave the tag naming B"
    );
    assert_eq!(
        server.count(),
        requests_before,
        "a warm launch of B must be registry-free"
    );
    assert!(
        h.msb_log()
            .lines()
            .filter(|line| line.starts_with("machine "))
            .count()
            > consumed_before,
        "the launch never reached the runtime: {}",
        stderr_of(&out)
    );
}

/// The pre-canonical migration publishes the canonical source key only while it is
/// still absent.
///
/// The canonical key is re-checked under its own guard, so a peer that published
/// it after this launch missed it is kept when validated. An incomplete entry
/// requires source reacquisition; if unavailable, failure preserves the entry
/// and cannot approve its content or reach create.
#[test]
fn an_old_spelling_migration_keeps_a_concurrent_publication() {
    for concurrent in ["validated", "incomplete", "incomplete-existing-records"] {
        let cache = support::project_tempdir();
        let cache = cache.path();
        let server = Server::new();
        let mut h = Harness::new();
        let seed = Harness::new();
        let a = h.image(&image_archive::ArchiveSpec {
            marker: format!("n1-migrate-a-{concurrent}"),
            ..Default::default()
        });
        let b = h.image(&image_archive::ArchiveSpec {
            marker: format!("n1-migrate-b-{concurrent}"),
            ..Default::default()
        });
        // The loopback spelling the acquisition cache is honestly keyed by; the
        // uppercase host is a real OCI reference that canonicalizes to it.
        let local_host = format!("localhost:{}", server.host.rsplit_once(':').unwrap().1);
        let source = format!("{local_host}/repo:old");
        let moved = format!("{local_host}/repo:moved");
        server.image("repo", "old", &a);
        server.image("repo", "moved", &b);
        status_ok(
            &seed.run_shared(cache, &["image", "refresh", "--image", &source]),
            "warming the canonical source",
        );
        status_ok(
            &seed.run_shared(cache, &["image", "refresh", "--image", &moved]),
            "warming another tag",
        );
        let old_source = source.replace("localhost", "LOCALHOST");
        assert_ne!(old_source, source);
        // An old launcher's entry: only the original spelling can find it.
        std::fs::rename(
            cache_metadata(cache, &source),
            cache_metadata(cache, &old_source),
        )
        .unwrap();
        assert!(!cache_metadata(cache, &source).exists());
        if concurrent == "incomplete-existing-records" {
            status_ok(
                &h.run_shared(cache, &["image", "set-default", "--image", &moved]),
                "establishing unrelated approval and fallback to preserve",
            );
        }
        h.use_launch_runtime();
        let requests_before = server.count();

        let mut gate = AcquisitionGate::new(h._home.path());
        let mut cmd = h.shared_command(cache);
        cmd.env("AGENT_VM_TEST_ACQUIRE_GATE_DETAIL", "1");
        cmd.args(["--image", &old_source, "--root", "shell"]);
        let launch = Peer::spawn(cmd, &gate, &[]);
        let migrating = gate.expect(AcquisitionStage::CacheValidated);
        // The peer's publication lands after this launch missed the canonical key
        // but before the migration would publish it.
        let published = match concurrent {
            "validated" => std::fs::read(cache_metadata(cache, &moved)).unwrap(),
            _ => b"{}".to_vec(),
        };
        std::fs::write(cache_metadata(cache, &source), &published).unwrap();
        let pins = h.home_root.join(".config/agent-vm/image-pins.json");
        let default = h.home_root.join(".config/agent-vm/default-image.json");
        let previous_pins = std::fs::read(&pins).ok();
        let previous_default = std::fs::read(&default).ok();
        if concurrent != "validated" {
            server.remove("/v2/repo/manifests/old");
        }
        migrating.reply(GateReply::Continue);

        match concurrent {
            "validated" => {
                gate.expect_eventually(AcquisitionStage::BeforeSdkConsume)
                    .reply(GateReply::Continue);
                assert_eq!(
                    cached_manifest_digest(cache, &source),
                    b.written.manifest_digest,
                    "the migration overwrote a concurrent publication"
                );
                gate.expect_eventually(AcquisitionStage::CreateReturned)
                    .reply(GateReply::Continue);
                let out = launch.wait();
                assert!(!out.status.success(), "the fixture runtime never boots");
                assert_eq!(
                    std::fs::read(cache_metadata(cache, &source)).unwrap(),
                    published,
                    "the peer's entry must survive byte-for-byte"
                );
                assert_eq!(
                    server.count(),
                    requests_before,
                    "using the peer's entry must stay registry-free"
                );
            }
            _ => {
                gate.expect(AcquisitionStage::BeforeLock)
                    .reply(GateReply::Continue);
                gate.expect(AcquisitionStage::Snapshot)
                    .reply(GateReply::Continue);
                let out = launch.wait();
                let stderr = stderr_of(&out);
                assert!(!out.status.success(), "{stderr}");
                assert_eq!(std::fs::read(&pins).ok(), previous_pins);
                assert_eq!(std::fs::read(&default).ok(), previous_default);
                assert_eq!(
                    std::fs::read(cache_metadata(cache, &source)).unwrap(),
                    published,
                    "the closed failure must not repair over the peer's entry"
                );
                assert_eq!(
                    &server.requests()[requests_before..],
                    &[
                        ("GET".to_owned(), "/v2/".to_owned()),
                        ("GET".to_owned(), "/v2/repo/manifests/old".to_owned()),
                    ],
                    "reacquisition must request only the source, never adopt the incomplete entry"
                );
                let log = h.msb_log();
                assert!(
                    log.lines().all(|line| {
                        let first = line.split_whitespace().next().unwrap_or("");
                        first.is_empty() || first == "--version" || first == "__launch-protocol"
                    }),
                    "a closed launch created a sandbox; log: {log}"
                );
            }
        }
    }
}

/// A warm digest launch rewrites nothing: the entry that validated is the entry
/// the launch consumes, and rewriting a validated file is not a repair.
///
/// The oracle is the inode of the preserved metadata and of its receipt. Both are
/// published by atomic rename, so any write replaces the inode; nothing else in
/// the launch does.
#[test]
fn a_warm_digest_launch_repairs_nothing() {
    use std::os::unix::fs::MetadataExt;

    let cache = support::project_tempdir();
    let cache = cache.path();
    let server = Server::new();
    let mut h = Harness::new();
    let a = h.image(&image_archive::ArchiveSpec::default());
    let pin = server.image("repo", "digest", &a);
    status_ok(
        &h.run_shared(cache, &["image", "refresh", "--image", &pin]),
        "warming the immutable digest",
    );
    let metadata_path = cache_metadata(cache, &pin);
    let receipt_path = std::fs::read_dir(cache.join("agent-vm-content-metadata"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            serde_json::from_slice::<serde_json::Value>(&std::fs::read(path).unwrap())
                .unwrap()
                .get("acquired_reference")
                .and_then(|value| value.as_str())
                .is_some_and(|reference| reference == pin)
        })
        .unwrap_or_else(|| panic!("no receipt for {pin}"));
    let metadata_inode = std::fs::metadata(&metadata_path).unwrap().ino();
    let receipt_inode = std::fs::metadata(&receipt_path).unwrap().ino();

    h.use_launch_runtime();
    let requests_before = server.count();
    let mut gate = AcquisitionGate::new(h._home.path());
    let mut cmd = h.shared_command(cache);
    cmd.args(["--image", &pin, "--root", "shell"]);
    let launch = Peer::spawn(cmd, &gate, &[]);
    // A write would have needed a checkpoint-free readback, but the launch is
    // parked only at the SDK boundary either way: the inode is the proof.
    gate.expect(AcquisitionStage::BeforeSdkConsume)
        .reply(GateReply::Continue);
    gate.expect(AcquisitionStage::CreateReturned)
        .reply(GateReply::Continue);
    let out = launch.wait();
    assert!(
        !out.status.success(),
        "the fixture runtime never boots a VM"
    );
    assert_eq!(
        std::fs::metadata(&metadata_path).unwrap().ino(),
        metadata_inode,
        "a warm digest launch rewrote validated cache metadata"
    );
    assert_eq!(
        std::fs::metadata(&receipt_path).unwrap().ino(),
        receipt_inode,
        "a warm digest launch rewrote its own receipt"
    );
    assert_eq!(
        server.count(),
        requests_before,
        "a warm digest launch must be registry-free"
    );
}

/// A retained *index* digest whose cached entry is the resolved host child, with
/// no receipt proving that association, still boots offline. A launch *consumes*
/// the cache: the entry it validates is the entry the SDK's `IfMissing` create
/// would boot, so it claims nothing new about where the entry came from.
///
/// This is the state a cold launch leaves behind -- the acquisition went through
/// the SDK, which stores the resolved child under the stated index key and writes
/// no receipt -- and dropping the receipt of an otherwise complete acquisition
/// reproduces exactly it. Without consumption, the launch refuses the entry as
/// "not the immutable identity" before any create, which is the regression.
#[test]
fn a_warm_index_launch_without_a_receipt_consumes_the_child() {
    let cache = support::project_tempdir();
    let cache = cache.path();
    let server = Server::new();
    let mut h = Harness::new();
    let a = h.image(&image_archive::ArchiveSpec::default());
    let child = server.image("repo", "child", &a);
    let index = server.index("repo", "indexed", a.index.clone());
    assert_ne!(
        index.rsplit('@').next().unwrap(),
        child,
        "the stated index digest must be the envelope, not the child"
    );
    status_ok(
        &h.run_shared(cache, &["image", "refresh", "--image", &index]),
        "establishing the index association",
    );
    let receipts = cache.join("agent-vm-content-metadata");
    assert!(
        receipts.is_dir(),
        "the acquisition must have written the receipt this test removes"
    );
    std::fs::remove_dir_all(&receipts).unwrap();

    // Offline: the association is unprovable, and the launch must still consume
    // the entry the SDK would. `BeforeSdkConsume` is only reachable through a
    // preparation that accepted the cached entry.
    drop(server);
    h.use_launch_runtime();
    let mut gate = AcquisitionGate::new(h._home.path());
    let mut cmd = h.shared_command(cache);
    cmd.args(["--image", &index, "--root", "shell"]);
    let launch = Peer::spawn(cmd, &gate, &[]);
    gate.expect(AcquisitionStage::BeforeSdkConsume)
        .reply(GateReply::Continue);
    gate.expect(AcquisitionStage::CreateReturned)
        .reply(GateReply::Continue);
    let out = launch.wait();
    let stderr = stderr_of(&out);
    assert!(
        !out.status.success(),
        "the fixture runtime never boots a VM: {stderr}"
    );
    assert!(
        !stderr.contains("usable immutable identity"),
        "a launch consuming an unprovable association must not refuse it: {stderr}"
    );
    assert!(
        !receipts.exists(),
        "consuming the cache must record no new identity claim"
    );
}

/// Remove the materialized content behind a cached entry, keeping its metadata and
/// receipt: the entry is then present, validated by its receipt, and incomplete.
fn drop_materialized_content(cache: &Path, digest: &str) {
    let handle = microsandbox_image::GlobalCache::new(cache).unwrap();
    let manifest = digest.parse().unwrap();
    for path in [
        handle.vmdk_path(&manifest),
        handle.fsmeta_erofs_path(&manifest),
    ] {
        std::fs::remove_file(&path)
            .unwrap_or_else(|error| panic!("remove {}: {error}", path.display()));
    }
    let now = microsandbox_image::Registry::pull_cached(
        &handle,
        &digest_reference(digest),
        &microsandbox_image::PullOptions {
            pull_policy: microsandbox_image::PullPolicy::Never,
            ..Default::default()
        },
    );
    assert!(
        !matches!(now, Ok(Some(_))),
        "the fixture must really leave the entry incomplete"
    );
}

fn digest_reference(digest: &str) -> microsandbox_image::Reference {
    format!("localhost:1/x@{digest}").parse().unwrap()
}

/// A digest entry whose content the cache no longer holds is the *completeness*
/// failure, not the generic immutable-identity one: the receipt proves what the
/// key should hold, and the layers behind it are gone.
#[test]
fn an_incomplete_digest_entry_reports_completeness() {
    let cache = support::project_tempdir();
    let cache = cache.path();
    let server = Server::new();
    let mut h = Harness::new();
    let a = h.image(&image_archive::ArchiveSpec::default());
    let pin = server.image("repo", "gapped", &a);
    status_ok(
        &h.run_shared(cache, &["image", "refresh", "--image", &pin]),
        "warming the immutable digest",
    );
    drop_materialized_content(cache, &a.written.manifest_digest);
    h.use_launch_runtime();
    let requests_before = server.count();
    server.remove(&format!("/v2/repo/manifests/{}", a.written.manifest_digest));
    let mut cmd = h.shared_command(cache);
    cmd.args(["--image", &pin, "--root", "shell"]);
    let out = run_with_timeout(cmd, Duration::from_secs(60));
    let stderr = stderr_of(&out);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains("approved image content is not available"),
        "an unrepaired digest entry must report completeness: {stderr}"
    );
    assert!(
        !stderr.contains("usable immutable identity"),
        "it must not report a generic identity failure: {stderr}"
    );
    assert!(
        server.count() > requests_before,
        "reacquisition must request the digest"
    );
    assert!(
        server.requests()[requests_before..]
            .iter()
            .all(|request| !request.1.ends_with("/gapped"))
    );
    let log = h.msb_log();
    assert!(
        log.lines().all(|line| {
            let first = line.split_whitespace().next().unwrap_or("");
            first.is_empty() || first == "--version" || first == "__launch-protocol"
        }),
        "an incomplete entry must not create a sandbox; log: {log}"
    );
}

/// Two independently acquired sources of one child share preservation without
/// evicting either association. The immutable index is checked again after the
/// tag, so an implementation that only remembers the last source is rejected.
#[test]
fn multiple_sources_of_one_child_remain_launchable_offline() {
    for tag_first in [true, false] {
        let cache = support::project_tempdir();
        let cache = cache.path();
        let server = Server::new();
        let mut h = Harness::new();
        let image = h.image(&image_archive::ArchiveSpec::default());
        let child = server.image("repo", "tag", &image);
        let tag = format!("{}/repo:tag", server.host);
        let index = server.index("repo", "index", image.index.clone());
        let sources = if tag_first {
            [&tag, &index]
        } else {
            [&index, &tag]
        };
        // Acquire S1 -> C, then S2 -> C; the very next preparation of S1 is
        // offline, with no intervening refresh that could recreate its binding.
        for source in sources {
            status_ok(
                &h.run_shared(cache, &["image", "refresh", "--image", source]),
                "acquiring another source of C",
            );
        }
        let records: Vec<serde_json::Value> =
            std::fs::read_dir(cache.join("agent-vm-content-metadata"))
                .unwrap()
                .map(|entry| {
                    serde_json::from_slice(&std::fs::read(entry.unwrap().path()).unwrap()).unwrap()
                })
                .collect();
        assert_eq!(records.len(), 1, "content preservation is child-keyed");
        assert_eq!(records[0]["acquired_reference"], child);
        // Only the immutable source records a binding: the association check never
        // consults one for a mutable tag, so the tag must not spend a slot.
        let bindings = records[0]["source_bindings"].as_array().unwrap();
        assert_eq!(bindings.len(), 1, "one immutable source, one binding");
        assert_eq!(bindings[0]["reference"], index.as_str());
        assert!(
            !bindings
                .iter()
                .any(|binding| binding["reference"] == tag.as_str()),
            "a mutable tag has no association to prove"
        );
        h.use_launch_runtime();
        drop(server);
        for source in sources {
            let mut gate = AcquisitionGate::new(h._home.path());
            let mut cmd = h.shared_command(cache);
            cmd.args(["--image", source, "--root", "shell"]);
            let launch = Peer::spawn(cmd, &gate, &[]);
            gate.expect(AcquisitionStage::BeforeSdkConsume)
                .reply(GateReply::Continue);
            gate.expect(AcquisitionStage::CreateReturned)
                .reply(GateReply::Continue);
            assert!(!launch.wait().status.success());
        }
        assert_eq!(
            h.msb_log()
                .lines()
                .filter(|line| line.starts_with("machine "))
                .count(),
            2
        );
    }
}

/// A receipt that describes a different identity under this key is corruption.
///
/// A receipt copied from another identity's position is internally consistent,
/// so only the key comparison can reject it. A launch consuming an unequal
/// immutable association must report the corrupt receipt — not treat the entry
/// as an unproven association — and must not create, repair or query anything.
#[test]
fn a_receipt_for_another_identity_fails_the_launch_closed() {
    let cache = support::project_tempdir();
    let cache = cache.path();
    let server = Server::new();
    let mut h = Harness::new();
    let x = h.image(&image_archive::ArchiveSpec {
        marker: "receipt-x".into(),
        ..Default::default()
    });
    let y = h.image(&image_archive::ArchiveSpec {
        marker: "receipt-y".into(),
        ..Default::default()
    });
    // Two immutable index sources resolving to different host children: the
    // cached entry's digest legitimately differs from the stated one, so only a
    // receipt can prove each association.
    let x_child = server.image("repo", "x-child", &x);
    let x_index = server.index("repo", "x-index", x.index.clone());
    let y_child = server.image("repo", "y-child", &y);
    let y_index = server.index("repo", "y-index", y.index.clone());
    assert_ne!(x_child, y_child);
    for index in [&x_index, &y_index] {
        status_ok(
            &h.run_shared(cache, &["image", "refresh", "--image", index]),
            "warming an index association",
        );
    }
    let receipts = cache.join("agent-vm-content-metadata");
    let receipt_for = |pin: &str| {
        std::fs::read_dir(&receipts)
            .unwrap()
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .find(|path| {
                serde_json::from_slice::<serde_json::Value>(&std::fs::read(path).unwrap())
                    .unwrap()
                    .get("acquired_reference")
                    .and_then(|value| value.as_str())
                    .is_some_and(|reference| reference == pin)
            })
            .unwrap_or_else(|| panic!("no receipt for {pin}"))
    };
    let x_receipt = receipt_for(&x_child);
    let y_receipt = receipt_for(&y_child);
    // Same file position, different (internally consistent) identity.
    std::fs::copy(&x_receipt, &y_receipt).unwrap();

    h.use_launch_runtime();
    let mut gate = AcquisitionGate::new(h._home.path());
    let mut launch_cmd = h.shared_command(cache);
    launch_cmd.args(["--image", &y_index, "--root", "shell"]);
    let requests_before = server.count();
    let launch = Peer::spawn(launch_cmd, &gate, &[]);
    let output = launch.wait();
    assert!(
        !output.status.success(),
        "a corrupt receipt must fail the launch: {}",
        stderr_of(&output)
    );
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("receipt is corrupt"),
        "the receipt's own key must be what fails, not an unproven association: {stderr}"
    );
    assert!(
        !stderr.contains("not the immutable identity"),
        "a mis-keyed receipt is corruption, not a plain association mismatch: {stderr}"
    );
    assert_eq!(
        server.count(),
        requests_before,
        "a corrupt receipt must not be repaired by a registry request"
    );
    // No create: the only runtime invocations are the version/protocol probes.
    let log = h.msb_log();
    assert!(
        log.lines().all(|line| {
            let first = line.split_whitespace().next().unwrap_or("");
            first.is_empty() || first == "--version" || first == "__launch-protocol"
        }),
        "the launch created a sandbox despite the corrupt receipt; log: {log}"
    );
    gate.expect_none(Duration::from_millis(200));
}

// ---------------------------------------------------------------------------
// #398 — the direct runner provisions nothing and inherits no catalog entry
// ---------------------------------------------------------------------------

/// The exact generic HOME furniture of every launch: `(link name, guest
/// target)`. The set is asserted both ways — every one of these links must
/// exist with exactly this target, and no other symlink may appear under the
/// guest HOME tree — so a catalog-declared persist link or a provider link this
/// oracle does not expect is a failure rather than "some state path".
///
/// Identical to the `link:` rows of `direct-run.golden`; the golden is compared
/// separately and is not the oracle for isolation.
const GENERIC_HOME_LINKS: [(&str, &str); 9] = [
    (".bash_history", "/agent-vm-state/bash_history"),
    (".claude", "/agent-vm-state/claude"),
    (".claude.json", "/agent-vm-state/claude.json"),
    (".config/gh", "/agent-vm-state/gh-config"),
    (".config/opencode", "/agent-vm-state/opencode-config"),
    (".copilot", "/agent-vm-state/copilot"),
    (".gitconfig", "/agent-vm-state/gitconfig"),
    (".local/share/opencode", "/agent-vm-state/opencode"),
    (".pi", "/agent-vm-state/pi"),
];

/// Provider-owned credential, placeholder and bypass files, relative to the
/// project state dir. A direct launch writes none of them: they exist only for
/// a catalog tool's declared provisioning.
///
/// Two provider files are **not** in this list because they are written on
/// every launch for a different reason, and are asserted on their own terms
/// instead: `claude.json` (image-owned Chrome MCP entry, and the user's own
/// file) and `opencode/auth.json` (OpenCode's stale-placeholder clearer runs
/// even when nothing is captured, and writes an empty object).
const FORBIDDEN_PROVIDER_STATE: [&str; 6] = [
    "claude/.credentials.json",
    "claude/settings.json",
    "codex/auth.json",
    "codex/config.toml",
    "copilot/config.json",
    "opencode-config/opencode.json",
];

/// The `persist` declarations of this suite's hostile custom catalog, and the
/// state namespace every declared persist link targets. Both the link name under
/// the guest HOME and the state-side path must stay absent.
const FORBIDDEN_DECLARED_PERSIST: [&str; 2] = ["probe-state", "shell-state"];
const DECLARED_PERSIST_NAMESPACE: &str = "persist";

/// Proof that a path does not exist that distinguishes *absence* from a failed
/// observation: only `NotFound` is evidence, any other error is a failed test.
fn assert_path_absent(path: &Path, context: &str) {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!(
            "{context}: could not observe {} ({}); absence not proven",
            path.display(),
            error
        ),
        Ok(_) => panic!("{context}: {} must not exist", path.display()),
    }
}

/// Every symlink under `dir`, recursively.
fn collect_symlink_paths(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries {
        let entry = entry.unwrap_or_else(|error| panic!("{}: {error}", dir.display()));
        let path = entry.path();
        let file_type = entry.file_type().unwrap();
        if file_type.is_symlink() {
            out.push(path);
        } else if file_type.is_dir() {
            collect_symlink_paths(&path, out);
        }
    }
}

/// Create the generic furniture tree for the negative control below. Never the
/// oracle itself: [`assert_direct_state_is_unprovisioned`] is.
fn write_generic_home_furniture(state: &Path) {
    for (name, target) in GENERIC_HOME_LINKS {
        let path = state.join("home").join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(target, &path).unwrap();
    }
}

/// The launcher-owned Chrome MCP entry is image-capability furniture, not
/// catalog provisioning. The file may exist (it is also the user's own
/// `~/.claude.json`); what must not appear is the entry the launcher owns when
/// the image cannot provide it. Any other content is out of scope here.
fn assert_chrome_mcp_entry_not_provisioned(state: &Path, context: &str) {
    let path = state.join("claude.json");
    match std::fs::read(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!(
            "{context}: could not observe {} ({}); absence not proven",
            path.display(),
            error
        ),
        Ok(bytes) => {
            let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_else(|error| {
                panic!("{context}: {} is not JSON: {error}", path.display())
            });
            assert!(
                json.pointer("/mcpServers/chrome-devtools").is_none(),
                "{context}: the launcher-owned Chrome MCP entry must not be provisioned: {json}"
            );
        }
    }
}

/// OpenCode's `auth.json` is rewritten by the launcher's stale-placeholder
/// clearer on *every* launch, including one that captures nothing, so absence is
/// not the invariant. The invariant is content: an existing file must hold no
/// provider entry at all (the clearer's empty object), never a placeholder or a
/// value.
fn assert_opencode_auth_cleared(state: &Path, context: &str) {
    let path = state.join("opencode/auth.json");
    match std::fs::read(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!(
            "{context}: could not observe {} ({}); absence not proven",
            path.display(),
            error
        ),
        Ok(bytes) => {
            let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_else(|error| {
                panic!("{context}: {} is not JSON: {error}", path.display())
            });
            let object = json.as_object().unwrap_or_else(|| {
                panic!("{context}: {} is not a JSON object: {json}", path.display())
            });
            assert!(
                object.is_empty(),
                "{context}: no OpenCode provider entry may be provisioned: {json}"
            );
        }
    }
}

/// The state-side zero-provisioning oracle for one launch's state dir: exact
/// generic furniture, no declared persist link or state path, no provider
/// token/placeholder/bypass file, no owned Chrome entry and a cleared OpenCode
/// auth file. Reused by its negative control, so each assertion is proved able
/// to fail.
fn assert_direct_state_is_unprovisioned(state: &Path, context: &str) {
    let mut expected: Vec<PathBuf> = Vec::new();
    for (name, target) in GENERIC_HOME_LINKS {
        let path = state.join("home").join(name);
        match std::fs::read_link(&path) {
            Ok(actual) => assert_eq!(
                actual.to_string_lossy(),
                target,
                "{context}: home link {name} must target {target}"
            ),
            Err(error) => panic!(
                "{context}: home link {name} is missing or unreadable ({}); the furniture oracle \
                 cannot pass vacuously",
                error
            ),
        }
        expected.push(path);
    }
    let mut found = Vec::new();
    collect_symlink_paths(&state.join("home"), &mut found);
    found.sort();
    for path in &found {
        assert!(
            expected.contains(path),
            "{context}: unexpected guest HOME link {} (generic furniture is exact)",
            path.display()
        );
    }
    for name in FORBIDDEN_DECLARED_PERSIST {
        assert_path_absent(&state.join("home").join(name), context);
        assert_path_absent(&state.join(DECLARED_PERSIST_NAMESPACE).join(name), context);
    }
    for relative in FORBIDDEN_PROVIDER_STATE {
        assert_path_absent(&state.join(relative), context);
    }
    // The host-only token files sit beside the state dir, never inside it.
    let host_secrets = PathBuf::from(format!("{}.secrets", state.display()));
    for provider in ["anthropic", "openai", "copilot"] {
        assert_path_absent(&host_secrets.join(provider), context);
    }
    assert_chrome_mcp_entry_not_provisioned(state, context);
    assert_opencode_auth_cleared(state, context);
}

/// Everything a direct launch must not inherit from any catalog entry,
/// asserted independently of the golden.
///
/// The golden records only the normalized config/state observation; argv,
/// notices, stdout and the process status are asserted here.
fn assert_direct_zero_provision(out: &Output, context: &str) {
    let stderr = stderr_of(out);
    let config = debug_config_json(&stderr);

    // 2. Exact default-deny authority, unchanged by any declared request.
    assert_default_deny_zero_provision_network(&config["network"], context);
    assert!(
        registered_secret_env_vars(&config).is_empty(),
        "{context}: no provider is provisioned"
    );

    // 3. No provider/tool/shell environment.
    let keys: Vec<&str> = env_pairs(&config).into_iter().map(|(key, _)| key).collect();
    for forbidden in [
        "CODEX_HOME",
        "COPILOT_GITHUB_TOKEN",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_BASE_URL",
        "CLAUDE_CONFIG_DIR",
        "OPENCODE_CONFIG",
    ] {
        assert!(
            !keys.contains(&forbidden),
            "{context}: {forbidden} must not reach the guest: {keys:?}"
        );
    }

    // 3. No provider token, placeholder, bypass configuration or catalog-declared
    //    persist file: one exact state-side oracle, shared with its negative
    //    control so it cannot decay into "anything under the state dir".
    assert_direct_state_is_unprovisioned(&state_dir(&stderr), context);

    // 4. `--no-git`: no agent credentials, and no request-report lines.
    assert!(
        stderr.contains("==> Agent credentials: <none>"),
        "{context}: {stderr}"
    );
    assert!(
        !stderr.contains("request(s) allowed"),
        "{context}: no declared request report: {stderr}"
    );
}

/// A direct launch's program is literal: a catalog tool name selects no entry,
/// so no default argument, environment or provisioning applies — and the
/// failed runtime is a direct launcher failure (125), not anyhow's 1.
#[test]
fn direct_run_of_a_catalog_tool_name_provisions_nothing() {
    let harness = Harness::warm();
    let options = ["--image", BOGUS_IMAGE, "--no-git"];
    let out = harness.direct(DirectInvocation {
        form: Form::Run,
        options: &options,
        vector: &["claude", "--x"],
        envs: &[],
    });
    assert_direct_zero_provision(&out, "run claude --x");

    // 1. The exact debug guest command line, with the catalog's default
    //    argument absent.
    let command = debug_guest_command(&stderr_of(&out));
    assert_eq!(
        command, "claude --x",
        "the guest command must be the literal program and argv"
    );
    assert!(
        !command.contains("--dangerously-skip-permissions"),
        "the claude catalog default must not be inserted: {command}"
    );

    // 5. Empty stdout and the direct launcher failure status.
    assert!(stdout_of(&out).is_empty(), "{}", stdout_of(&out));
    assert_eq!(out.status.code(), Some(125), "{}", stderr_of(&out));
    assert_matches_golden("direct-run", &observation(&harness, &out));
}

/// Both spellings reach the same config and state, and each one independently
/// satisfies the zero-provisioning expectations.
#[test]
fn both_direct_spellings_share_one_observation() {
    let mut observations = Vec::new();
    for form in DIRECT_FORMS {
        let harness = Harness::warm();
        let out = harness.direct(DirectInvocation {
            form,
            options: &["--image", BOGUS_IMAGE, "--memory", "3", "--no-git"],
            vector: &["claude", "--x"],
            envs: &[],
        });
        assert_direct_zero_provision(&out, &format!("{form:?}"));
        assert_eq!(out.status.code(), Some(125), "{form:?}");
        let config = normalized_config(&harness, &out);
        assert_eq!(
            debug_guest_command(&stderr_of(&out)),
            "claude --x",
            "{form:?}"
        );
        assert_eq!(
            config["resources"]["memory_mib"],
            serde_json::json!(3 * 1024),
            "{form:?}"
        );
        observations.push(observation(&harness, &out));
    }
    assert_eq!(observations[0], observations[1]);
}

/// The failed runtime is a direct launcher failure for the direct route and
/// keeps anyhow's status 1 for a catalog tool, in the same harness.
#[test]
fn only_the_direct_route_maps_a_failed_runtime_to_125() {
    let harness = Harness::warm();
    let direct = harness.direct(DirectInvocation {
        form: Form::Separator,
        options: &["--image", BOGUS_IMAGE, "--no-git"],
        vector: &["probe"],
        envs: &[],
    });
    assert_eq!(direct.status.code(), Some(125), "{}", stderr_of(&direct));
    let tool = harness.launch_argv("claude", &["--image", BOGUS_IMAGE, "--no-git"], &[]);
    assert_eq!(tool.status.code(), Some(1), "{}", stderr_of(&tool));
}

/// A launch that fails before the guest exec must not consume host stdin
/// (#399, I1). The reader is only started once the lifecycle owns an exec
/// handle, so a failed image/acquisition path leaves the caller's bytes — and
/// its still-open writer — untouched.
#[test]
fn a_direct_launch_that_fails_before_exec_reads_no_host_stdin() {
    use std::io::{Read as _, Write as _};
    for (vector, expected_status) in [(vec!["cat"], 125), (vec![""], 2)] {
        for form in DIRECT_FORMS {
            let mut harness = Harness::warm();
            // The fixture runtime fails every actual launch.
            harness.use_launch_runtime();
            let (reader, mut writer) = std::io::pipe().unwrap();
            writer.write_all(b"hello").unwrap();
            writer.flush().unwrap();
            // The test keeps its own copy of the read end, so it can prove
            // nothing was consumed even after the launcher exits.
            let mut proof = reader.try_clone().unwrap();
            let mut cmd = harness.base_command();
            cmd.args(["--image", BOGUS_IMAGE, "--no-git"]);
            cmd.arg(match form {
                Form::Run => "run",
                Form::Separator => "--",
            });
            cmd.args(&vector);
            cmd.stdin(std::process::Stdio::from(reader));
            let out = run_with_timeout(cmd, Duration::from_secs(60));
            assert_eq!(
                out.status.code(),
                Some(expected_status),
                "{form:?} {vector:?}: {}",
                stderr_of(&out)
            );
            // Close the writer **now**, after the bounded exit observation, and
            // read to EOF. Reading five bytes while the writer is still open
            // would block forever exactly when the regression consumed one of
            // them, which is the only case this oracle exists for.
            drop(writer);
            let mut remaining = Vec::new();
            proof
                .read_to_end(&mut remaining)
                .expect("the launcher consumed host stdin before the guest exec");
            assert_eq!(
                remaining, b"hello",
                "{form:?} {vector:?}: the launcher consumed host stdin before the \
                 guest exec"
            );
        }
    }
}

/// A custom catalog — and a hostile configured `shell` — grants a direct launch
/// nothing: no command, default arguments, environment, provider, network
/// request, transitive tool or persist declaration is inherited.
#[test]
fn a_hostile_custom_catalog_grants_a_direct_launch_nothing() {
    let harness = Harness::warm();
    harness.write_user(
        "[[tools]]\n\
         name = \"probe\"\n\
         command = \"probe-from-catalog\"\n\
         args = [\"--from-catalog\"]\n\
         env = { PROBE_CATALOG_ENV = \"yes\" }\n\
         credentials = [\"anthropic\"]\n\
         tools = [\"probe-helper\"]\n\
         persist = [\"probe-state\"]\n\
         network_requests = [\"api.example.test\"]\n\
         \n\
         [[tools]]\n\
         name = \"probe-helper\"\n\
         command = \"probe-helper\"\n\
         \n\
         [[tools]]\n\
         name = \"shell\"\n\
         command = \"hostile-shell\"\n\
         args = [\"--hostile\"]\n\
         interactive_shell = true\n\
         env = { SHELL_CATALOG_ENV = \"yes\" }\n\
         credentials = [\"anthropic\"]\n\
         network_requests = [\"api.example.test\"]\n\
         persist = [\"shell-state\"]\n",
    );
    for form in DIRECT_FORMS {
        let out = harness.direct(DirectInvocation {
            form,
            options: &["--image", BOGUS_IMAGE, "--no-git"],
            vector: &["probe", "a"],
            envs: &[],
        });
        assert_direct_zero_provision(&out, &format!("hostile catalog {form:?}"));
        let command = debug_guest_command(&stderr_of(&out));
        // The catalog's `probe` command and default argument appear nowhere,
        // and neither does a fallback shell lookup.
        assert_eq!(command, "probe a", "{form:?}");
        for absent in [
            "probe-from-catalog",
            "--from-catalog",
            "hostile-shell",
            "--hostile",
        ] {
            assert!(!command.contains(absent), "{form:?}: {absent} in {command}");
        }
        let config = normalized_config(&harness, &out);
        let keys: Vec<&str> = env_pairs(&config).into_iter().map(|(key, _)| key).collect();
        for absent in ["PROBE_CATALOG_ENV", "SHELL_CATALOG_ENV"] {
            assert!(!keys.contains(&absent), "{form:?}: {keys:?}");
        }
        // And a hostile catalog changes nothing observable at all: the whole
        // config/state observation equals a default-catalog direct launch's.
        assert_matches_golden("direct-run", &observation(&harness, &out));
    }
}

/// A test oracle that cannot fail is not evidence. The zero-provisioning state
/// oracle is driven here against the two leaks it exists to catch — a
/// catalog-declared persist link and a provider bypass file — and against the
/// image-owned Chrome entry it must treat separately, then re-checked on the
/// clean furniture so the control is not simply "always fails".
#[test]
fn the_direct_state_oracle_rejects_a_persist_link_a_bypass_file_and_an_owned_chrome_entry() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path();
    write_generic_home_furniture(state);
    assert_direct_state_is_unprovisioned(state, "clean furniture control");

    // The custom catalog's forbidden `persist = ["probe-state"]` link, whose
    // target is the state-side persist namespace.
    let persist_link = state.join("home/probe-state");
    std::os::unix::fs::symlink("/agent-vm-state/persist/probe-state", &persist_link).unwrap();
    let leaked = std::panic::catch_unwind(|| {
        assert_direct_state_is_unprovisioned(state, "persist link leak")
    });
    assert!(
        leaked.is_err(),
        "the oracle accepted a catalog-declared persist link"
    );
    std::fs::remove_file(&persist_link).unwrap();

    // ...and its state-side counterpart without the link, so neither half of
    // the persist claim can pass alone.
    std::fs::create_dir_all(state.join("persist/probe-state")).unwrap();
    let leaked = std::panic::catch_unwind(|| {
        assert_direct_state_is_unprovisioned(state, "persist state leak")
    });
    assert!(
        leaked.is_err(),
        "the oracle accepted a catalog-declared persist state path"
    );
    std::fs::remove_dir_all(state.join("persist")).unwrap();

    // A provider bypass file that a catalog tool's provisioning would write.
    let bypass = state.join("claude/settings.json");
    std::fs::create_dir_all(bypass.parent().unwrap()).unwrap();
    std::fs::write(&bypass, br#"{"skipDangerousModePermissionPrompt":true}"#).unwrap();
    let leaked = std::panic::catch_unwind(|| {
        assert_direct_state_is_unprovisioned(state, "bypass file leak")
    });
    assert!(
        leaked.is_err(),
        "the oracle accepted a provider bypass file"
    );
    std::fs::remove_file(&bypass).unwrap();

    // The host-only captured provider token.
    let token = PathBuf::from(format!("{}.secrets/anthropic", state.display()));
    std::fs::create_dir_all(token.parent().unwrap()).unwrap();
    std::fs::write(&token, "sk-ant-synthetic").unwrap();
    let leaked = std::panic::catch_unwind(|| {
        assert_direct_state_is_unprovisioned(state, "captured token leak")
    });
    assert!(
        leaked.is_err(),
        "the oracle accepted a captured provider token"
    );
    std::fs::remove_file(&token).unwrap();

    // OpenCode's cleared file is allowed; a provider entry inside it is not.
    let opencode_auth = state.join("opencode/auth.json");
    std::fs::create_dir_all(opencode_auth.parent().unwrap()).unwrap();
    std::fs::write(&opencode_auth, b"{}").unwrap();
    assert_direct_state_is_unprovisioned(state, "cleared opencode auth control");
    std::fs::write(
        &opencode_auth,
        br#"{"openai":{"type":"api","key":"msb-opencode-placeholder"}}"#,
    )
    .unwrap();
    let leaked = std::panic::catch_unwind(|| {
        assert_direct_state_is_unprovisioned(state, "opencode placeholder leak")
    });
    assert!(
        leaked.is_err(),
        "the oracle accepted an OpenCode provider entry"
    );
    std::fs::remove_file(&opencode_auth).unwrap();

    // The image-owned Chrome MCP entry: `claude.json` itself is allowed (it is
    // also the user's file), the launcher-owned entry inside it is not.
    let claude_json = state.join("claude.json");
    std::fs::write(
        &claude_json,
        br#"{"mcpServers":{"user-owned":{"command":"x"}}}"#,
    )
    .unwrap();
    assert_direct_state_is_unprovisioned(state, "user-owned claude.json control");
    std::fs::write(
        &claude_json,
        br#"{"mcpServers":{"chrome-devtools":{"command":"/usr/local/bin/agent-vm-chrome-mcp"}}}"#,
    )
    .unwrap();
    let leaked = std::panic::catch_unwind(|| {
        assert_direct_state_is_unprovisioned(state, "owned chrome entry leak")
    });
    assert!(
        leaked.is_err(),
        "the oracle accepted the launcher-owned Chrome MCP entry"
    );
    std::fs::remove_file(&claude_json).unwrap();

    // Back to the clean control: every failure above came from the injected
    // leak, not from the oracle rejecting the furniture itself.
    assert_direct_state_is_unprovisioned(state, "clean furniture control after");
}

/// GitHub handling stays orthogonal: `--repo` widens the GitHub allow-list for a
/// direct launch exactly as for a tool, without granting any catalog request.
#[test]
fn a_direct_launch_keeps_independent_github_handling() {
    let harness = Harness::warm();
    let out = harness.direct(DirectInvocation {
        form: Form::Run,
        options: &["--image", BOGUS_IMAGE, "--repo", "owner/other-repo"],
        vector: &["probe"],
        envs: &[],
    });
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("owner/other-repo"),
        "the GitHub allow-list notice names the repo: {stderr}"
    );
    assert_default_deny_zero_provision_network(
        &debug_config_json(&stderr)["network"],
        "direct --repo",
    );
}

/// An invalid *unused* tool still blocks a direct launch before any boot, while
/// `doctor` keeps diagnosing and a usage error stays status 2.
#[test]
fn an_invalid_unused_tool_blocks_a_direct_launch_before_the_banner() {
    let harness = Harness::warm();
    harness.write_user("[[tools]]\nname = \"run\"\ncommand = \"x\"\n");
    let out = harness.direct(DirectInvocation {
        form: Form::Run,
        options: &["--image", BOGUS_IMAGE],
        vector: &["probe"],
        envs: &[],
    });
    assert_eq!(out.status.code(), Some(125), "{}", stderr_of(&out));
    let stderr = stderr_of(&out);
    assert!(stderr.contains("name `run` is reserved"), "{stderr}");
    assert!(stdout_of(&out).is_empty());
    // No launch banner and no runtime launch.
    assert!(!stderr.contains("==> agent-vm-"), "{stderr}");
    assert!(
        harness.msb_log().lines().all(|line| line == "--version"),
        "{}",
        harness.msb_log()
    );
    // The same broken catalog still lets `doctor` diagnose.
    let doctor = harness.builtin(&["doctor"], &[]);
    assert!(
        stderr_of(&doctor).contains("name `run` is reserved")
            || stdout_of(&doctor).contains("name `run` is reserved"),
        "{}",
        stderr_of(&doctor)
    );
    // A usage error is 2, before any of this.
    let usage = harness.direct(DirectInvocation {
        form: Form::Run,
        options: &["--image", BOGUS_IMAGE],
        vector: &[],
        envs: &[],
    });
    assert_eq!(usage.status.code(), Some(2), "{}", stderr_of(&usage));
}

/// A missing host credential is never the reason a direct launch fails: the
/// direct target requests no service, so an unreadable `credentials.yaml` is
/// inert here while a catalog tool that requests the same name still fails.
#[test]
fn a_malformed_credentials_file_is_inert_for_a_direct_launch() {
    let harness = Harness::warm();
    harness.write_user(
        "[[tools]]\nname = \"wants\"\ncommand = \"wants\"\ncredentials = [\"same-name\"]\n",
    );
    write(
        &harness.home_root.join(".config/agent-vm/credentials.yaml"),
        "this: is: not: yaml: [\n",
    );
    for form in DIRECT_FORMS {
        let out = harness.direct(DirectInvocation {
            form,
            options: &["--image", BOGUS_IMAGE],
            vector: &["probe"],
            envs: &[],
        });
        let stderr = stderr_of(&out);
        // It reaches the runtime failure, not a YAML failure.
        assert!(
            stderr.contains(CONFIG_MARKER),
            "{form:?}: the launch reached the debug config: {stderr}"
        );
        assert_eq!(out.status.code(), Some(125), "{form:?}: {stderr}");
    }
    // Positive control: a catalog tool that *requests* the name does fail on
    // the malformed YAML.
    let requested = harness.launch_argv("wants", &["--image", BOGUS_IMAGE], &[]);
    assert_ne!(
        requested.status.code(),
        Some(125),
        "a requested catalog credential must fail like before: {}",
        stderr_of(&requested)
    );
    assert!(
        stderr_of(&requested).contains("credentials.yaml"),
        "{}",
        stderr_of(&requested)
    );
}

/// The B5 audit's binary half (#398): a known-direct route's usage failures are
/// status 2 with a value-free message, on both spellings, and no launch, state
/// or stdout is produced. A genuine administrative route keeps its legacy
/// outcome.
#[test]
fn direct_usage_failures_are_status_2_and_value_free() {
    let harness = Harness::warm();
    let cases: [(&str, &[&str], &[&str], &str); 5] = [
        (
            "invalid launch env",
            &["--image", BOGUS_IMAGE],
            &["run", "secret"],
            "abc",
        ),
        (
            // A typed value is echoed by clap's own message (legacy behavior for
            // every verb); only a scrubbed route promises value-free text.
            "invalid typed value",
            &["--image", BOGUS_IMAGE, "--memory", "abc"],
            &["run", "p"],
            "",
        ),
        (
            "unknown option with a canary",
            &["--image", BOGUS_IMAGE, "--unknown=CANARY-398"],
            &["--", "p"],
            "CANARY-398",
        ),
        (
            "repeated conflicting scalar",
            &["--image", BOGUS_IMAGE, "--memory", "4", "--memory", "8"],
            &["run", "image", "import"],
            "CANARY",
        ),
        // `run --` is the program `--` by the raw-escape rule, so an absent
        // program is the zero-value vector, not a literal separator.
        ("missing program", &["--image", BOGUS_IMAGE], &[], ""),
    ];
    for (context, options, vector, canary) in cases {
        for form in DIRECT_FORMS {
            let mut envs: Vec<(&str, &str)> = Vec::new();
            if context == "invalid launch env" {
                envs.push(("AGENT_VM_MEMORY_GIB", "abc"));
            }
            let out = harness.direct(DirectInvocation {
                form,
                options,
                vector,
                envs: &envs,
            });
            assert_eq!(
                out.status.code(),
                Some(2),
                "{context} {form:?}: {}",
                stderr_of(&out)
            );
            assert!(stdout_of(&out).is_empty(), "{context} {form:?}");
            let text = stderr_of(&out);
            if !canary.is_empty() {
                assert!(!text.contains(canary), "{context} {form:?}: {text}");
            }
            // No launch banner: nothing booted.
            assert!(
                !text.contains("==> agent-vm-"),
                "{context} {form:?}: {text}"
            );
        }
    }
    // The same malformed environment is not a usage error for the legacy
    // administrative route, and a genuine `secret` scrub keeps status 1.
    let secret = harness.builtin(&["secret", "set", "svc", "--help=CANARY-398"], &[]);
    assert_eq!(secret.status.code(), Some(1), "{}", stderr_of(&secret));
    assert!(!stderr_of(&secret).contains("CANARY-398"));
}

// ---------------------------------------------------------------------------
// #395 — a launch provisions its own configuration file's closure
// ---------------------------------------------------------------------------

/// The user tier: `pi` owns the verb, OpenAI and `.user-pi`.
const TIER_LOCAL_USER_PI: &str = "[[tools]]\nname = \"pi\"\ncommand = \"user-pi\"\n\
     credentials = [\"openai\"]\npersist = [\".user-pi\"]\n";

/// The project tier: a `pi` hidden by the user's name conflict, owning Anthropic
/// and `.project-pi`, reached from `helper` through `bridge`.
const TIER_LOCAL_PROJECT: &str = "[[tools]]\nname = \"pi\"\ncommand = \"project-pi\"\n\
     credentials = [\"anthropic\"]\npersist = [\".project-pi\"]\n\
     [[tools]]\nname = \"bridge\"\ncommand = \"bridge\"\ntools = [\"pi\"]\npersist = [\".bridge\"]\n\
     [[tools]]\nname = \"helper\"\ncommand = \"helper\"\ntools = [\"bridge\"]\npersist = [\".helper\"]\n";

/// The same two tiers plus one named credential per tier, so a *provisionable*
/// credential exists on both sides and the exclusion cannot be explained by an
/// inert authorization.
const TIER_SERVICE_USER_PI: &str = "[[tools]]\nname = \"pi\"\ncommand = \"user-pi\"\n\
     credentials = [\"openai\", \"user-service\"]\npersist = [\".user-pi\"]\n";

const TIER_SERVICE_PROJECT: &str = "[[tools]]\nname = \"pi\"\ncommand = \"project-pi\"\n\
     credentials = [\"anthropic\", \"project-service\"]\npersist = [\".project-pi\"]\n\
     [[tools]]\nname = \"bridge\"\ncommand = \"bridge\"\ntools = [\"pi\"]\npersist = [\".bridge\"]\n\
     [[tools]]\nname = \"helper\"\ncommand = \"helper\"\ntools = [\"bridge\"]\npersist = [\".helper\"]\n";

/// Both named services authorized, both `source: env` and `required: true`, so
/// either one really is provisionable when its variable is present.
const TIER_SERVICES_YAML: &str = "\
credentials:
  - service: user-service
    source: env
    required: true
    apiKey:
      name: USER_SERVICE_KEY
      sentinelEnv: true
      inject: [{domain: api.user-service.example, scheme: bearer}]
  - service: project-service
    source: env
    required: true
    apiKey:
      name: PROJECT_SERVICE_KEY
      sentinelEnv: true
      inject: [{domain: api.project-service.example, scheme: bearer}]
";

const TIER_USER_CANARY: &str = "sk-CANARY-395-user";
const TIER_PROJECT_CANARY: &str = "sk-CANARY-395-project";

fn tier_launch_env() -> [(&'static str, &'static str); 3] {
    [
        ("USER_SERVICE_KEY", TIER_USER_CANARY),
        ("PROJECT_SERVICE_KEY", TIER_PROJECT_CANARY),
        ("PRESENT_CONTROL", "visible-395"),
    ]
}

/// Assert exactly one header-credential record for `service`, and that the
/// other side's host is nowhere in the launch's network policy.
fn assert_only_header_credential(
    config: &serde_json::Value,
    service: &str,
    host: &str,
    absent_host: &str,
) {
    let records = config["network"]["secrets"]["header_credentials"]
        .as_array()
        .unwrap_or_else(|| panic!("no header_credentials array"));
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["reference"], service);
    assert_eq!(records[0]["origin"]["host"], host);
    assert_eq!(records[0]["header"], "authorization");
    assert!(
        !intercept_rule_hosts(config).contains(&absent_host),
        "the other tier's host must not be registered: {:?}",
        intercept_rule_hosts(config)
    );
}

/// The selected named service's sentinel is in the guest env and the other
/// tier's is not.
fn assert_only_service_sentinel(config: &serde_json::Value, selected: &str, absent: &str) {
    let env = env_pairs(config);
    assert!(
        env.contains(&(selected, "proxy-managed")),
        "{selected} must be provisioned as a proxy sentinel: {env:?}"
    );
    assert!(
        !env.iter().any(|(key, _)| *key == absent),
        "{absent} must not reach the guest env: {env:?}"
    );
}

/// **L1.** A launch of a project helper provisions the *project* `pi`'s
/// provider, substitution allowlist, OAuth route, placeholder and persisted
/// paths — never the user's, even though the user's `pi` owns the verb. Both
/// directions run on fresh, identically configured harnesses, so a stale link or
/// placeholder cannot make an absence assertion pass.
#[test]
fn a_hidden_project_definition_supplies_the_selected_credentials_and_links() {
    let project = Harness::warm();
    project.write_user(TIER_LOCAL_USER_PI);
    project.write_project(TIER_LOCAL_PROJECT);
    let out = project.launch_default("helper");
    let stderr = stderr_of(&out);
    let config = debug_config_json(&stderr);
    assert_eq!(debug_guest_command(&stderr), "helper");

    // Anthropic only: the hidden project `pi`'s requirement set, provisioned.
    assert!(
        registered_secret_env_vars(&config).contains(&"MSB_AGENT_VM_ANTHROPIC_UNUSED"),
        "{:?}",
        registered_secret_env_vars(&config)
    );
    assert!(
        !registered_secret_env_vars(&config).contains(&"MSB_AGENT_VM_OPENAI_UNUSED"),
        "the user `pi`'s OpenAI must not be provisioned"
    );
    assert!(
        intercept_rule_hosts(&config).contains(&"platform.claude.com"),
        "the Anthropic OAuth route follows the same closure: {:?}",
        intercept_rule_hosts(&config)
    );
    // The whole substitution subdocument — env vars, placeholders, source paths
    // and host allowlists — names Anthropic and nothing OpenAI.
    let secrets = serde_json::to_string(&config["network"]["secrets"]).unwrap();
    assert!(secrets.contains("anthropic"), "{secrets}");
    assert!(
        !secrets.to_lowercase().contains("openai"),
        "no OpenAI substitution facet may be registered: {secrets}"
    );

    let state = state_dir(&stderr);
    assert!(state.join("claude/.credentials.json").exists());
    assert!(
        !state.join("codex/auth.json").exists(),
        "no OpenAI-side placeholder may be written"
    );
    assert!(
        !PathBuf::from(format!("{}.secrets", state.display()))
            .join("openai")
            .exists()
    );
    let snap = snapshot(&state);
    for (link, target) in [
        (".project-pi", "/agent-vm-state/persist/.project-pi"),
        (".bridge", "/agent-vm-state/persist/.bridge"),
        (".helper", "/agent-vm-state/persist/.helper"),
    ] {
        assert_eq!(
            snap.get(&format!("link:{link}")).map(String::as_str),
            Some(target),
            "{snap:?}"
        );
    }
    assert!(
        !snap.contains_key("link:.user-pi"),
        "the user definition's persisted path must not be linked: {snap:?}"
    );
    for compiled in COMPILED_LINKS {
        assert!(
            snap.contains_key(&format!("link:{compiled}")),
            "the compiled link {compiled} must remain: {snap:?}"
        );
    }

    // The inverse selection, proving each direction selects its own tier.
    let user = Harness::warm();
    user.write_user(TIER_LOCAL_USER_PI);
    user.write_project(TIER_LOCAL_PROJECT);
    let out = user.launch_default("pi");
    let stderr = stderr_of(&out);
    let config = debug_config_json(&stderr);
    assert_eq!(debug_guest_command(&stderr), "user-pi");
    assert!(registered_secret_env_vars(&config).contains(&"MSB_AGENT_VM_OPENAI_UNUSED"));
    assert!(!registered_secret_env_vars(&config).contains(&"MSB_AGENT_VM_ANTHROPIC_UNUSED"));
    assert!(!intercept_rule_hosts(&config).contains(&"platform.claude.com"));
    let snap = snapshot(&state_dir(&stderr));
    assert_eq!(
        snap.get("link:.user-pi").map(String::as_str),
        Some("/agent-vm-state/persist/.user-pi")
    );
    for absent in [".project-pi", ".bridge", ".helper"] {
        assert!(
            !snap.contains_key(&format!("link:{absent}")),
            "the project closure must not be linked on a user launch: {snap:?}"
        );
    }
}

/// **L2.** A named credential request follows the same tier-local closure as the
/// built-in providers. Both services are authorized and *usable* (env-sourced,
/// `required`, one bearer injection each) and both variables are supplied to
/// every launch, so the exclusion is real provisioning rather than an inert
/// authorization.
#[test]
fn a_named_request_follows_the_hidden_closure_and_excludes_the_usable_other_tier() {
    let project = Harness::warm();
    project.write_user(TIER_SERVICE_USER_PI);
    project.write_project(TIER_SERVICE_PROJECT);
    write_credentials(&project.home_root, TIER_SERVICES_YAML);
    let out = project.launch_with_env("helper", &[], &tier_launch_env());
    let stderr = stderr_of(&out);
    let rendered = rendered_output(&out);
    let config = debug_config_json(&stderr);
    assert!(project.saw_capability_probe(), "{rendered}");
    assert_eq!(debug_guest_command(&stderr), "helper");

    assert_only_header_credential(
        &config,
        "project-service",
        "api.project-service.example",
        "api.user-service.example",
    );
    assert_only_service_sentinel(&config, "PROJECT_SERVICE_KEY", "USER_SERVICE_KEY");
    // L1's project facets, on the same launch.
    assert!(registered_secret_env_vars(&config).contains(&"MSB_AGENT_VM_ANTHROPIC_UNUSED"));
    let snap = snapshot(&state_dir(&stderr));
    assert_eq!(
        snap.get("link:.project-pi").map(String::as_str),
        Some("/agent-vm-state/persist/.project-pi")
    );
    assert!(!snap.contains_key("link:.user-pi"));

    // Value controls: neither canary is rendered, stored, or handed to the fake
    // runtime as the *selected* credential's value.
    for canary in [TIER_USER_CANARY, TIER_PROJECT_CANARY] {
        assert!(!rendered.contains(canary), "{canary} leaked: {rendered}");
        assert_no_canary_files(&project.state_root, canary);
        let state = state_dir(&stderr);
        assert_no_canary_files(
            &PathBuf::from(format!("{}.secrets", state.display())),
            canary,
        );
    }
    let child = project.msb_environ();
    assert!(
        child
            .lines()
            .any(|line| line == "PRESENT_CONTROL=visible-395"),
        "the control variable must reach the runtime child"
    );
    assert!(
        !child
            .lines()
            .any(|line| line.starts_with("PROJECT_SERVICE_KEY=")),
        "the captured source must be removed from the runtime child:\n{child}"
    );

    // The paired positive control: an otherwise identical *user* launch selects
    // the user service, proving the helper excluded a genuinely usable credential.
    let user = Harness::warm();
    user.write_user(TIER_SERVICE_USER_PI);
    user.write_project(TIER_SERVICE_PROJECT);
    write_credentials(&user.home_root, TIER_SERVICES_YAML);
    let out = user.launch_with_env("pi", &[], &tier_launch_env());
    let stderr = stderr_of(&out);
    let rendered = rendered_output(&out);
    let config = debug_config_json(&stderr);
    assert!(user.saw_capability_probe(), "{rendered}");
    assert_eq!(debug_guest_command(&stderr), "user-pi");
    assert_only_header_credential(
        &config,
        "user-service",
        "api.user-service.example",
        "api.project-service.example",
    );
    assert_only_service_sentinel(&config, "USER_SERVICE_KEY", "PROJECT_SERVICE_KEY");
    assert!(registered_secret_env_vars(&config).contains(&"MSB_AGENT_VM_OPENAI_UNUSED"));
    assert!(!registered_secret_env_vars(&config).contains(&"MSB_AGENT_VM_ANTHROPIC_UNUSED"));
    let snap = snapshot(&state_dir(&stderr));
    assert_eq!(
        snap.get("link:.user-pi").map(String::as_str),
        Some("/agent-vm-state/persist/.user-pi")
    );
    for canary in [TIER_USER_CANARY, TIER_PROJECT_CANARY] {
        assert!(!rendered.contains(canary), "{canary} leaked: {rendered}");
    }

    // Authorization failure control: without the project authorization the user
    // one cannot satisfy the project request.
    let unauthorized = Harness::warm();
    unauthorized.write_user(TIER_SERVICE_USER_PI);
    unauthorized.write_project(TIER_SERVICE_PROJECT);
    write_credentials(
        &unauthorized.home_root,
        &TIER_SERVICES_YAML.replace("project-service", "unrelated-service"),
    );
    let out = unauthorized.launch_with_env("helper", &[], &tier_launch_env());
    let rendered = rendered_output(&out);
    assert!(!out.status.success(), "{rendered}");
    assert!(rendered.contains("neither a built-in"), "{rendered}");
    assert!(rendered.contains("project-service"), "{rendered}");
    assert!(!rendered.contains(CONFIG_MARKER), "{rendered}");
}

/// **L3.** Wildcard references stay in their own tier, and a wildcard that closes
/// over a cycle still contributes each definition once. The paired controls are
/// the same usable two-service authorizations as L2.
#[test]
fn a_wildcard_root_reaches_only_its_own_tier_and_fixed_point() {
    // The project `pi` and `bridge` close a cycle, and the wildcard root sweeps
    // the whole project tier.
    let project_tier = "[[tools]]\nname = \"pi\"\ncommand = \"project-pi\"\n\
         credentials = [\"anthropic\", \"project-service\"]\npersist = [\".project-pi\"]\ntools = [\"bridge\"]\n\
         [[tools]]\nname = \"bridge\"\ncommand = \"bridge\"\ntools = [\"pi\"]\npersist = [\".bridge\"]\n\
         [[tools]]\nname = \"helper\"\ncommand = \"helper\"\ntools = [\"*\"]\npersist = [\".helper\"]\n";
    let project = Harness::warm();
    project.write_user(TIER_SERVICE_USER_PI);
    project.write_project(project_tier);
    write_credentials(&project.home_root, TIER_SERVICES_YAML);
    let out = project.launch_with_env("helper", &[], &tier_launch_env());
    let stderr = stderr_of(&out);
    let rendered = rendered_output(&out);
    let config = debug_config_json(&stderr);
    assert!(project.saw_capability_probe(), "{rendered}");
    assert_only_header_credential(
        &config,
        "project-service",
        "api.project-service.example",
        "api.user-service.example",
    );
    assert_only_service_sentinel(&config, "PROJECT_SERVICE_KEY", "USER_SERVICE_KEY");
    assert!(registered_secret_env_vars(&config).contains(&"MSB_AGENT_VM_ANTHROPIC_UNUSED"));
    assert!(!registered_secret_env_vars(&config).contains(&"MSB_AGENT_VM_OPENAI_UNUSED"));
    let snap = snapshot(&state_dir(&stderr));
    for (link, target) in [
        (".project-pi", "/agent-vm-state/persist/.project-pi"),
        (".bridge", "/agent-vm-state/persist/.bridge"),
        (".helper", "/agent-vm-state/persist/.helper"),
    ] {
        assert_eq!(
            snap.get(&format!("link:{link}")).map(String::as_str),
            Some(target),
            "the cycle must contribute each definition once: {snap:?}"
        );
    }
    assert!(!snap.contains_key("link:.user-pi"));

    // The inverse: the user `pi` verb, same files and inputs.
    let user = Harness::warm();
    user.write_user(TIER_SERVICE_USER_PI);
    user.write_project(project_tier);
    write_credentials(&user.home_root, TIER_SERVICES_YAML);
    let out = user.launch_with_env("pi", &[], &tier_launch_env());
    let config = debug_config_json(&stderr_of(&out));
    assert_only_header_credential(
        &config,
        "user-service",
        "api.user-service.example",
        "api.project-service.example",
    );
    assert_only_service_sentinel(&config, "USER_SERVICE_KEY", "PROJECT_SERVICE_KEY");

    // A user-declared `shell` with omitted `tools` closes over its own tier only.
    let shell = Harness::warm();
    shell.write_user(&format!(
        "[[tools]]\nname = \"shell\"\ncommand = \"bash\"\npersist = [\".shell\"]\n{TIER_SERVICE_USER_PI}"
    ));
    shell.write_project(TIER_SERVICE_PROJECT);
    write_credentials(&shell.home_root, TIER_SERVICES_YAML);
    let out = shell.launch_with_env("shell", &[], &tier_launch_env());
    let stderr = stderr_of(&out);
    let config = debug_config_json(&stderr);
    assert_only_header_credential(
        &config,
        "user-service",
        "api.user-service.example",
        "api.project-service.example",
    );
    let snap = snapshot(&state_dir(&stderr));
    assert_eq!(
        snap.get("link:.shell").map(String::as_str),
        Some("/agent-vm-state/persist/.shell")
    );
    assert_eq!(
        snap.get("link:.user-pi").map(String::as_str),
        Some("/agent-vm-state/persist/.user-pi"),
        "the omitted wildcard reaches this tier's sibling"
    );
    assert!(!snap.contains_key("link:.project-pi"), "{snap:?}");

    // An explicit `tools = []` inherits nothing.
    let empty = Harness::warm();
    empty.write_user(&format!(
        "[[tools]]\nname = \"shell\"\ncommand = \"bash\"\ntools = []\npersist = [\".shell\"]\n{TIER_SERVICE_USER_PI}"
    ));
    empty.write_project(TIER_SERVICE_PROJECT);
    write_credentials(&empty.home_root, TIER_SERVICES_YAML);
    let out = empty.launch_with_env("shell", &[], &tier_launch_env());
    let stderr = stderr_of(&out);
    let config = debug_config_json(&stderr);
    assert!(
        config["network"]["secrets"]["header_credentials"]
            .as_array()
            .map(|records| records.is_empty())
            .unwrap_or(true),
        "an explicit empty list inherits no named request"
    );
    let snap = snapshot(&state_dir(&stderr));
    assert!(!snap.contains_key("link:.user-pi"), "{snap:?}");
}

/// **L3b.** A custom catalog that declares no `shell` gets the synthesized
/// fallback: no shipped provider, no named request, no declared persist — and no
/// restored shipped agent.
#[test]
fn a_custom_catalog_fallback_shell_provisions_nothing() {
    let harness = Harness::warm();
    harness.write_user(TIER_SERVICE_USER_PI);
    harness.write_project("[[tools]]\nname = \"solo\"\ncommand = \"solo\"\n");
    write_credentials(&harness.home_root, TIER_SERVICES_YAML);
    let out = harness.launch_with_env("shell", &[], &tier_launch_env());
    let stderr = stderr_of(&out);
    let config = debug_config_json(&stderr);
    assert_eq!(debug_guest_command(&stderr), "bash -O histappend");
    assert!(
        registered_secret_env_vars(&config).is_empty(),
        "the fallback provisions no provider: {:?}",
        registered_secret_env_vars(&config)
    );
    assert!(
        config["network"]["secrets"]
            .get("header_credentials")
            .and_then(|records| records.as_array())
            .map(|records| records.is_empty())
            .unwrap_or(true),
        "the fallback requests no named credential"
    );
    let env = env_pairs(&config);
    assert!(
        !env.iter().any(|(key, _)| key.contains("SERVICE_KEY")),
        "{env:?}"
    );
    let state = state_dir(&stderr);
    let snap = snapshot(&state);
    for absent in [
        "link:.user-pi",
        "link:.project-pi",
        "link:.dsh",
        "link:.aider.conf.yml",
    ] {
        assert!(
            !snap.contains_key(absent),
            "the fallback must restore no declared or shipped persist link: {snap:?}"
        );
    }
    for compiled in COMPILED_LINKS {
        assert!(snap.contains_key(&format!("link:{compiled}")), "{snap:?}");
    }
}

/// **L4.** An invalid reference fails before any launch effect: no config dump,
/// no guest command, no runtime invocation, no project state allocation — and
/// the diagnostic keeps the tier, file, declaration, tool and field. Recovery
/// (`--help`, `doctor`) and a readable configured image survive.
#[test]
fn an_invalid_reference_fails_before_any_launch_effect() {
    // The last fragment is the cause-and-fix sentence, so a typo is never
    // reported as the cross-tier rule (and vice versa).
    let cases: [(&str, &str, &str, [&str; 6]); 4] = [
        (
            "unknown",
            "[[tools]]\nname = \"w\"\ncommand = \"w\"\ntools = [\"nope\"]\n",
            "",
            [
                "user config",
                "declaration [0]",
                "tool \"w\"",
                "tools[0]",
                "\"nope\" names no tool",
                TYPO_REFERENCE_SENTENCE,
            ],
        ),
        (
            "cross-tier",
            "[[tools]]\nname = \"w\"\ncommand = \"w\"\ntools = [\"p\"]\n",
            "[[tools]]\nname = \"p\"\ncommand = \"p\"\n",
            [
                "user config",
                "declaration [0]",
                "tool \"w\"",
                "tools[0]",
                "\"p\" names no tool",
                "it is declared in project config ",
            ],
        ),
        (
            "hidden dangling",
            "[[tools]]\nname = \"dup\"\ncommand = \"user-dup\"\n",
            "[[tools]]\nname = \"dup\"\ncommand = \"project-dup\"\ntools = [\"missing\"]\n",
            [
                "project config",
                "declaration [0]",
                "tool \"dup\"",
                "tools[0]",
                "\"missing\" names no tool",
                TYPO_REFERENCE_SENTENCE,
            ],
        ),
        (
            "fallback shell",
            "",
            "[[tools]]\nname = \"w\"\ncommand = \"w\"\ntools = [\"shell\"]\n",
            [
                "project config",
                "declaration [0]",
                "tool \"w\"",
                "tools[0]",
                "\"shell\" names no tool",
                TYPO_REFERENCE_SENTENCE,
            ],
        ),
    ];
    for (label, user, project, expected) in cases {
        let harness = Harness::new();
        harness.write_user(user);
        harness.write_project(project);
        let out = harness.launch_default("shell");
        let stderr = stderr_of(&out);
        let rendered = rendered_output(&out);
        assert!(!out.status.success(), "{label}: {rendered}");
        for fragment in expected {
            assert!(
                stderr.contains(fragment),
                "{label}: missing {fragment} in {stderr}"
            );
        }
        if label == "cross-tier" {
            assert!(
                stderr.contains(&format!(
                    "it is declared in project config \"{}\"",
                    harness.project_config().display()
                )),
                "{label}: the message must name the file that declares the tool: {stderr}"
            );
        }
        assert!(!stderr.contains(CONFIG_MARKER), "{label}: {stderr}");
        assert!(!stderr.contains(GUEST_CMD_MARKER), "{label}: {stderr}");
        assert!(
            harness.msb_log().is_empty(),
            "{label}: the runtime must never be invoked: {}",
            harness.msb_log()
        );
        let allocated = std::fs::read_dir(&harness.state_root)
            .map(|entries| entries.count())
            .unwrap_or(0);
        assert_eq!(allocated, 0, "{label}: no project state may be allocated");

        // Recovery stays usable, and the launch failure is never clap's.
        assert!(
            !stderr.contains("unrecognized subcommand"),
            "{label}: {stderr}"
        );
        let help = harness.builtin(&["--help"], &[]);
        assert!(help.status.success(), "{label}: {}", stderr_of(&help));
    }

    // Positive control: correcting the local declaration launches the same verb.
    let harness = Harness::warm();
    harness.write_user("");
    harness.write_project("[[tools]]\nname = \"w\"\ncommand = \"w\"\ntools = [\"shell\"]\n");
    harness.write_project(
        "[[tools]]\nname = \"shell\"\ncommand = \"bash\"\n\
         [[tools]]\nname = \"w\"\ncommand = \"w\"\ntools = [\"shell\"]\n",
    );
    let out = harness.launch_default("w");
    assert!(
        stderr_of(&out).contains(CONFIG_MARKER),
        "the corrected config must launch: {}",
        stderr_of(&out)
    );
}

/// **L5.** An inherited provider is provisioned but never *required*: without the
/// host Anthropic credential, a helper that reaches a hidden Anthropic-requiring
/// definition still gets to construction, while the same requirement on the
/// launched tool itself still bails.
#[test]
fn an_inherited_provider_never_imposes_its_missing_login_bail() {
    let harness = Harness::warm();
    std::fs::remove_file(harness.home_root.join(".claude/.credentials.json")).unwrap();
    harness.write_user(
        "[[tools]]\nname = \"pi\"\ncommand = \"user-pi\"\ncredentials = [\"anthropic\"]\n",
    );
    harness.write_project(
        "[[tools]]\nname = \"pi\"\ncommand = \"project-pi\"\ncredentials = [\"anthropic\"]\n\
         [[tools]]\nname = \"helper\"\ncommand = \"helper\"\ntools = [\"pi\"]\n",
    );

    let out = harness.launch_default("helper");
    let stderr = stderr_of(&out);
    let config = debug_config_json(&stderr);
    assert!(
        !registered_secret_env_vars(&config).contains(&"MSB_AGENT_VM_ANTHROPIC_UNUSED"),
        "an uncaptured provider registers no substitution entry"
    );

    // The launched tool's *own* requirement still bails, before the config dump.
    let out = harness.launch_default("pi");
    let stderr = stderr_of(&out);
    assert!(!out.status.success(), "{stderr}");
    assert!(stderr.contains("no usable Claude credential"), "{stderr}");
    assert!(!stderr.contains(CONFIG_MARKER), "{stderr}");
}

/// **L6.** A hidden definition's persisted paths provision in both guest modes,
/// migrate pre-existing content rather than deleting it, and refuse to resolve
/// two sources of truth.
#[test]
fn hidden_persisted_paths_provision_in_both_guest_modes() {
    // Non-root: the exact link target, plus the compiled furniture.
    let harness = Harness::warm();
    harness.write_user(TIER_LOCAL_USER_PI);
    harness.write_project(TIER_LOCAL_PROJECT);
    let out = harness.launch_default("helper");
    let stderr = stderr_of(&out);
    assert!(stderr.contains(CONFIG_MARKER), "{stderr}");
    let snap = snapshot(&state_dir(&stderr));
    assert_eq!(
        snap.get("link:.project-pi").map(String::as_str),
        Some("/agent-vm-state/persist/.project-pi")
    );
    for compiled in COMPILED_LINKS {
        assert!(snap.contains_key(&format!("link:{compiled}")), "{snap:?}");
    }

    // Root: the same list baked into the rootfs, with the ancestor mkdir for a
    // nested hidden path.
    let root = Harness::warm();
    root.write_user(TIER_LOCAL_USER_PI);
    root.write_project(
        "[[tools]]\nname = \"pi\"\ncommand = \"project-pi\"\npersist = [\".cache/persist-pi\"]\n\
         [[tools]]\nname = \"helper\"\ncommand = \"helper\"\ntools = [\"pi\"]\n",
    );
    let out = root.launch("helper", &["--root"]);
    let stderr = stderr_of(&out);
    assert!(stderr.contains(CONFIG_MARKER), "{stderr}");
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
    assert!(
        symlinks.contains(&(
            "/agent-vm-state/persist/.cache/persist-pi",
            "/root/.cache/persist-pi"
        )),
        "{symlinks:?}"
    );
    assert!(mkdirs.contains(&"/root/.cache"), "{mkdirs:?}");
    assert!(
        symlinks.contains(&("/agent-vm-state/claude", "/root/.claude")),
        "compiled furniture remains: {symlinks:?}"
    );

    // Migration: content a previous launch wrote into the persistent non-root
    // HOME is moved into the persist namespace when the hidden edge appears.
    let migrate = Harness::warm();
    migrate.write_user(TIER_LOCAL_USER_PI);
    migrate.write_project(
        "[[tools]]\nname = \"pi\"\ncommand = \"project-pi\"\n\
         [[tools]]\nname = \"helper\"\ncommand = \"helper\"\ntools = [\"pi\"]\n",
    );
    let first = migrate.launch_default("helper");
    let state = state_dir(&stderr_of(&first));
    std::fs::write(state.join("home/.project-pi"), "old hidden content").unwrap();
    migrate.write_project(
        "[[tools]]\nname = \"pi\"\ncommand = \"project-pi\"\npersist = [\".project-pi\"]\n\
         [[tools]]\nname = \"helper\"\ncommand = \"helper\"\ntools = [\"pi\"]\n",
    );
    let second = migrate.launch_default("helper");
    assert!(
        stderr_of(&second).contains(CONFIG_MARKER),
        "{}",
        stderr_of(&second)
    );
    assert_eq!(
        std::fs::read_to_string(state.join("persist/.project-pi")).unwrap(),
        "old hidden content"
    );
    assert_eq!(
        std::fs::read_link(state.join("home/.project-pi")).unwrap(),
        PathBuf::from("/agent-vm-state/persist/.project-pi")
    );

    // Two sources of truth are refused rather than overwritten. The link holds a
    // *guest* target, so it is replaced by real content first.
    std::fs::remove_file(state.join("home/.project-pi")).unwrap();
    std::fs::write(state.join("home/.project-pi"), "second source").unwrap();
    let third = migrate.launch_default("helper");
    let stderr = stderr_of(&third);
    assert!(
        stderr.contains("holds real content and its persist target"),
        "{stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(state.join("persist/.project-pi")).unwrap(),
        "old hidden content",
        "the existing target must not be overwritten"
    );
}

/// **L7.** The hidden path keeps the same safety checks as a declared one: a
/// guest mount overlapping it is refused before boot, and a guest-planted
/// symlinked ancestor is refused without writing outside the state dir.
#[test]
fn hidden_persisted_paths_keep_the_mount_and_symlink_guards() {
    // A mount under the mirrored HOME overlapping the hidden path.
    for root in [false, true] {
        let harness = Harness::new();
        harness.write_user(TIER_LOCAL_USER_PI);
        harness.write_project(
            "[[tools]]\nname = \"pi\"\ncommand = \"project-pi\"\npersist = [\"code\"]\n\
             [[tools]]\nname = \"helper\"\ncommand = \"helper\"\ntools = [\"pi\"]\n",
        );
        let home = if root {
            PathBuf::from("/root")
        } else {
            harness.home_root.clone()
        };
        let mount = format!("{}:{}/code", harness.project_root.display(), home.display());
        let options: Vec<&str> = if root {
            vec!["--root", "--mount", &mount]
        } else {
            vec!["--mount", &mount]
        };
        let out = harness.launch("helper", &options);
        let stderr = stderr_of(&out);
        assert!(
            stderr.contains("would collide with the guest mount point"),
            "root={root}: {stderr}"
        );
        assert!(!stderr.contains(CONFIG_MARKER), "root={root}: {stderr}");
    }

    // A guest-planted symlink at an ancestor of the hidden path.
    let harness = Harness::new();
    harness.write_user(TIER_LOCAL_USER_PI);
    harness.write_project(
        "[[tools]]\nname = \"pi\"\ncommand = \"project-pi\"\npersist = [\".aider.conf.yml\"]\n\
         [[tools]]\nname = \"helper\"\ncommand = \"helper\"\ntools = [\"pi\"]\n",
    );
    let first = harness.launch_default("helper");
    let state = state_dir(&stderr_of(&first));
    let planted = harness.project_root.join("planted");
    std::fs::create_dir_all(&planted).unwrap();
    std::fs::create_dir_all(state.join("home")).unwrap();
    std::os::unix::fs::symlink(&planted, state.join("home/.cache")).unwrap();
    harness.write_project(
        "[[tools]]\nname = \"pi\"\ncommand = \"project-pi\"\npersist = [\".cache/persist-pi\"]\n\
         [[tools]]\nname = \"helper\"\ncommand = \"helper\"\ntools = [\"pi\"]\n",
    );
    let second = harness.launch_default("helper");
    let stderr = stderr_of(&second);
    assert!(stderr.contains("symlink"), "{stderr}");
    assert!(!stderr.contains(CONFIG_MARKER), "{stderr}");
    assert!(
        std::fs::read_dir(&planted).unwrap().next().is_none(),
        "provisioning followed the planted symlink"
    );
}

/// **L8.** Exactly three facets cross a `tools` reference: built-in providers,
/// requested credential names and `persist` paths. The provisioned definition's
/// guest `env` and `network_requests` are *declaration metadata*, not
/// provisioning, so a helper that names the hidden project `pi` gets that
/// definition's credential and persisted path but neither its environment pair
/// nor its declared destinations. Each of the three absence assertions sits next
/// to a positive control on the same launch, so a launch that simply dropped the
/// closure could not make this pass.
#[test]
fn a_provisioned_definition_supplies_credentials_and_paths_but_no_metadata() {
    let harness = Harness::warm();
    harness.write_user(TIER_LOCAL_USER_PI);
    harness.write_project(
        "[[tools]]\nname = \"pi\"\ncommand = \"project-pi\"\ncredentials = [\"anthropic\"]\n\
         persist = [\".project-pi\"]\nenv = { PI_INHERITED_ENV = \"must-not-leak\" }\n\
         network_requests = [\"api.pi-inherited.example\"]\n\
         [[tools]]\nname = \"helper\"\ncommand = \"helper\"\ntools = [\"pi\"]\n\
         persist = [\".helper\"]\nenv = { HELPER_OWN_ENV = \"present\" }\n\
         network_requests = [\"api.helper-own.example\"]\n",
    );
    let out = harness.launch_default("helper");
    let stderr = stderr_of(&out);
    let config = debug_config_json(&stderr);
    assert_eq!(debug_guest_command(&stderr), "helper");

    // Positive controls: the closure was really folded into this launch.
    assert!(
        registered_secret_env_vars(&config).contains(&"MSB_AGENT_VM_ANTHROPIC_UNUSED"),
        "{:?}",
        registered_secret_env_vars(&config)
    );
    assert_eq!(
        snapshot(&state_dir(&stderr))
            .get("link:.project-pi")
            .map(String::as_str),
        Some("/agent-vm-state/persist/.project-pi")
    );

    // The launched tool's own metadata is published and reported.
    let published_env = env_pairs(&config);
    assert!(
        published_env.contains(&("HELPER_OWN_ENV", "present")),
        "{published_env:?}"
    );
    let requests = request_block(&stderr);
    assert!(
        requests
            .iter()
            .any(|line| line.contains("api.helper-own.example")),
        "the helper's own request must still be reported: {requests:?}"
    );

    // The provisioned definition's metadata is not.
    assert!(
        !published_env
            .iter()
            .any(|(key, _)| *key == "PI_INHERITED_ENV"),
        "a provisioned definition's env pair must not reach the guest: {published_env:?}"
    );
    assert!(
        !requests
            .iter()
            .any(|line| line.contains("api.pi-inherited.example")),
        "a provisioned definition's network_requests must not be reported: {requests:?}"
    );
    assert!(
        !serde_json::to_string(&config)
            .unwrap()
            .contains("pi-inherited"),
        "no provisioned-definition metadata may appear in the sandbox config"
    );
}

// ---------------------------------------------------------------------------
// Named mount sets (#397) reach every launch route and change nothing else
// ---------------------------------------------------------------------------

/// **#397.** A named mount set is a mount-selection input on all three launch
/// routes — a project tool, the builtin `shell`, and a direct command — and it is
/// the *only* thing it changes: the resolved guest command line, the credential
/// files under the project state dir and every persisted guest-HOME link are
/// identical with the set selected as a default, selected explicitly under the
/// opt-out, and with no set at all.
///
/// The facet pair is the point: a mount that quietly reordered provisioning, or
/// an opt-out that dropped a persisted link, would show up here rather than in a
/// mount-specific assertion.
#[test]
fn named_mount_sets_join_every_launch_route_without_touching_provisioning() {
    /// One route's observables: the guest command line, the sandbox's serialized
    /// `(host, guest, readonly)` binds, and the provisioning snapshot.
    type Facets = (
        String,
        Vec<(String, String, bool)>,
        BTreeMap<String, String>,
    );

    fn facets(route: &str, options: &[&str], with_sets: bool) -> Facets {
        let h = Harness::warm();
        let source = h.home_root.join("fm");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("marker"), "marker").unwrap();
        if with_sets {
            h.write_user(
                "mounts = [\"fm-set\"]\n[mount_sets]\n\
                 fm-set = [\"~/fm:/fm:ro\"]\n\
                 other = [\"/nonexistent-agent-vm-launch-probe:/probe:ro\"]\n",
            );
        }
        h.write_project(
            "[[tools]]\nname = \"proj\"\ncommand = \"/bin/echo\"\ncredentials = [\"anthropic\"]\n\
             persist = [\"code\"]\n",
        );
        let out = match route {
            "tool" => h.launch("proj", options),
            "shell" => h.launch("shell", options),
            _ => {
                let mut argv = vec!["--image", BOGUS_IMAGE];
                argv.extend_from_slice(options);
                h.direct(DirectInvocation {
                    form: Form::Run,
                    options: &argv,
                    vector: &["/bin/echo", "direct"],
                    envs: &[],
                })
            }
        };
        let stderr = stderr_of(&out);
        let state = state_dir(&stderr);
        // Two independent observables, asserted apart: the sandbox's serialized
        // bind list (what the guest would see) and the provisioning snapshot (the
        // credential files and persisted guest-HOME links under the state dir).
        let binds: Vec<(String, String, bool)> = debug_config_json(&stderr)["mounts"]
            .as_array()
            .expect("config.mounts must be an array")
            .iter()
            .filter(|mount| mount["type"] == "Bind")
            .map(|mount| {
                (
                    mount["host"].as_str().expect("host").to_string(),
                    mount["guest"].as_str().expect("guest").to_string(),
                    mount["options"]["readonly"].as_bool().expect("readonly"),
                )
            })
            .collect();
        (debug_guest_command(&stderr), binds, snapshot(&state))
    }

    for route in ["tool", "shell", "direct"] {
        let (baseline_command, baseline_binds, baseline_snapshot) = facets(route, &[], false);
        assert_eq!(
            baseline_command,
            match route {
                "tool" => "/bin/echo",
                "shell" => "bash -O histappend",
                _ => "/bin/echo direct",
            },
            "{route}: the baseline route must be the expected one"
        );
        assert!(
            !baseline_binds.iter().any(|(_, guest, _)| guest == "/fm"),
            "{route}: the control must not mount the set's source: {baseline_binds:?}"
        );
        // A named default, and the same set selected explicitly under the opt-out.
        for (label, options) in [
            ("default", vec![]),
            (
                "opt-out plus explicit set",
                vec!["--no-config-mounts", "--mount", "fm-set"],
            ),
        ] {
            let (command, binds, snapshot) = facets(route, &options, true);
            // The mount join itself, against the serialized bind list: the selected
            // set's leaf is bound read-only at its guest path on *every* route, and
            // the unrelated definition in the same table is not bound at all.
            let source = binds.iter().find(|(_, guest, _)| guest == "/fm");
            assert!(
                source.is_some_and(|(_, _, readonly)| *readonly),
                "{route} ({label}): the selected set must bind /fm read-only: {binds:?}"
            );
            assert!(
                !binds.iter().any(|(_, guest, _)| guest == "/probe"),
                "{route} ({label}): an unselected set must bind nothing: {binds:?}"
            );
            // Provisioning is a separate facet: the guest command line, the
            // credential files and every persisted HOME link are unchanged.
            assert_eq!(
                command, baseline_command,
                "{route} ({label}): guest command"
            );
            assert_eq!(
                snapshot, baseline_snapshot,
                "{route} ({label}): provisioning and persisted paths"
            );
        }
    }
}

/// #396 AC-union/AC-opt-out: inheriting a tool's `mounts` adds exactly the bind
/// facet. Every other provisioning rule — the closure's providers, requested
/// names, persisted paths, the launching tool's own env and its own network
/// requests — is unchanged by the mount list and by the automatic opt-out.
///
/// The contrast is the point: `mounts` is inherited like `credentials` and
/// `persist`, but unlike `env` and `network_requests`, which stay own-only. A row
/// that only compared mount sets would pass if inheritance leaked every facet.
#[test]
fn tool_mount_inheritance_changes_binds_not_other_provisioning_rules() {
    let harness = Harness::warm();
    let own = harness.home_root.join("own");
    let inherited = harness.home_root.join("inherited");
    for dir in [&own, &inherited] {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join("marker"),
            dir.file_name().unwrap().to_str().unwrap(),
        )
        .unwrap();
    }
    harness.write_user(
        "[[tools]]\nname = \"t\"\ncommand = \"/bin/echo\"\ntools = [\"u\"]\n\
         env = { T_ONLY = \"t-value\" }\n\
         network_requests = [\"t.example\"]\n\
         mounts = [\"~/own:/own:ro\"]\n\
         [[tools]]\nname = \"u\"\ncommand = \"/bin/echo\"\ntools = []\n\
         env = { U_ONLY = \"u-value\" }\n\
         network_requests = [\"u.example\"]\n\
         credentials = [\"anthropic\"]\n\
         persist = [\"u-state\"]\n\
         mounts = [\"~/inherited:/inherited:ro\"]\n",
    );

    let applied = harness.launch("t", &[]);
    let applied_stderr = stderr_of(&applied);
    assert!(applied_stderr.contains(CONFIG_MARKER), "{applied_stderr}");
    // The first launch's provisioning state is captured *before* the second one
    // starts. Both share a project, so the state path is one directory and only a
    // retained before-image can show that the suppressed launch left every
    // credential file and persisted link as it found it; two snapshots taken after
    // both launches would compare that directory with itself.
    let state = state_dir(&applied_stderr);
    let after_applied = snapshot(&state);
    let suppressed = harness.launch("t", &["--no-config-mounts"]);
    let suppressed_stderr = stderr_of(&suppressed);
    assert!(
        suppressed_stderr.contains(CONFIG_MARKER),
        "{suppressed_stderr}"
    );
    assert_eq!(
        state_dir(&suppressed_stderr),
        state,
        "the two launches must share the state directory the comparison is about"
    );

    // Observation 1: the serialized bind list. Every automatic declaration is
    // inherited — the launched tool's own leaf and the referenced tool's — and
    // suppressing the automatic facet removes exactly those and nothing else.
    let binds = |stderr: &str| {
        let mut binds: Vec<(String, String, bool)> = debug_config_json(stderr)["mounts"]
            .as_array()
            .expect("config.mounts must be an array")
            .iter()
            .filter(|mount| mount["type"] == "Bind")
            .map(|mount| {
                (
                    mount["host"].as_str().expect("host").to_string(),
                    mount["guest"].as_str().expect("guest").to_string(),
                    mount["options"]["readonly"].as_bool().expect("readonly"),
                )
            })
            .collect();
        binds.sort();
        binds
    };
    let applied_binds = binds(&applied_stderr);
    for (dir, guest) in [(&own, "/own"), (&inherited, "/inherited")] {
        assert!(
            applied_binds
                .iter()
                .any(|(host, path, readonly)| Path::new(host) == dir.as_path()
                    && path == guest
                    && *readonly),
            "{guest} must bind {} read-only: {applied_binds:?}",
            dir.display()
        );
    }
    let without_automatic: Vec<_> = applied_binds
        .iter()
        .filter(|(_, guest, _)| guest != "/own" && guest != "/inherited")
        .cloned()
        .collect();
    assert_eq!(
        without_automatic,
        binds(&suppressed_stderr),
        "the opt-out must remove only the inherited tool mounts"
    );

    // Observation 2: the whole normalized sandbox config apart from `mounts`, and
    // the provider-produced state as the *first* launch left it.
    let strip = |out: &Output| {
        let mut config = normalized_config(&harness, out);
        config["mounts"] = serde_json::json!([]);
        config
    };
    assert_eq!(
        strip(&applied),
        strip(&suppressed),
        "only `mounts` may differ between the applied and suppressed launches"
    );
    assert_eq!(
        snapshot(&state),
        after_applied,
        "the suppressed launch must leave every provisioning artifact as the applied \
         launch left it"
    );

    // Observation 3: the inherited facets really are active in both launches, so
    // the equality above is not the equality of two empty observations. The
    // referenced tool's persist link and captured provider survive the mount
    // opt-out, which is what makes `mounts` the only facet it changes.
    assert!(
        after_applied.contains_key("link:u-state"),
        "the referenced tool's persist link is inherited: {after_applied:?}"
    );
    assert!(
        snapshot(&state).contains_key("link:u-state"),
        "the mount opt-out must not drop the inherited persist link"
    );
    let config = debug_config_json(&applied_stderr);
    assert!(
        registered_secret_env_vars(&config).contains(&"MSB_AGENT_VM_ANTHROPIC_UNUSED"),
        "the referenced tool's provider is inherited and captured"
    );
    assert!(
        registered_secret_env_vars(&debug_config_json(&suppressed_stderr))
            .contains(&"MSB_AGENT_VM_ANTHROPIC_UNUSED"),
        "the mount opt-out must not drop the inherited provider"
    );

    // Observation 4: env and network requests stay own-only. The launching tool's
    // own pair is present; the referenced tool's is not leaked into the sandbox or
    // into the request report.
    let env = env_pairs(&config);
    assert!(env.contains(&("T_ONLY", "t-value")), "{env:?}");
    assert!(
        !env.iter().any(|(name, _)| *name == "U_ONLY"),
        "a referenced tool's env must not reach the guest: {env:?}"
    );
    let expected_requests = vec![
        format!(
            "==> Tool network requests (user config): 1 of 1 not covered by this launch's \
             {REQUEST_SCOPE}; requests never grant access and the launch continues"
        ),
        "==>   unmet: t.example".to_string(),
        REQUEST_HINT.to_string(),
    ];
    assert_eq!(request_block(&applied_stderr), expected_requests);
    assert_eq!(
        request_block(&suppressed_stderr),
        expected_requests,
        "the opt-out must not change the request report either"
    );
}

/// #396 AC-opt-out/AC-shell: a declared `shell` reaching same-tier tools through
/// its omitted `tools` wildcard keeps their whole provisioning set when the mount
/// facet is suppressed — and loses it when the *tool* inheritance switch is turned
/// off, which is the opposite control.
#[test]
fn shell_tool_mount_opt_out_does_not_disable_inherited_provisioning() {
    let shell = |tail: &str| {
        format!(
            "[[tools]]\nname = \"shell\"\ncommand = \"bash\"\ninteractive_shell = true\n{tail}\
             [[tools]]\nname = \"agent\"\ncommand = \"/bin/echo\"\ntools = []\n\
             credentials = [\"anthropic\"]\npersist = [\"agent-state\"]\n\
             mounts = [\"~/own:/own:ro\"]\n"
        )
    };
    // `(tail, options, expected inheritance)` rows.
    for (label, tail, options, inherited) in [
        ("wildcard", "", Vec::new(), true),
        (
            "wildcard under the opt-out",
            "",
            vec!["--no-config-mounts"],
            true,
        ),
        ("explicit empty", "tools = []\n", Vec::new(), false),
        (
            "explicit empty under the opt-out",
            "tools = []\n",
            vec!["--no-config-mounts"],
            false,
        ),
    ] {
        let harness = Harness::warm();
        harness.write_user(&shell(tail));
        std::fs::create_dir_all(harness.home_root.join("own")).unwrap();
        std::fs::write(harness.home_root.join("own/marker"), "own").unwrap();
        let out = harness.launch("shell", &options);
        let stderr = stderr_of(&out);
        assert!(stderr.contains(CONFIG_MARKER), "{label}: {stderr}");
        let state = state_dir(&stderr);
        let config = debug_config_json(&stderr);
        let env_vars = registered_secret_env_vars(&config);
        assert_eq!(
            env_vars.contains(&"MSB_AGENT_VM_ANTHROPIC_UNUSED"),
            inherited,
            "{label}: the wildcard, not the mount selection, governs providers: {env_vars:?}"
        );
        assert_eq!(
            snapshot(&state).contains_key("link:agent-state"),
            inherited,
            "{label}: the same switch governs inherited persistence"
        );
        let binds: Vec<String> = config["mounts"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|mount| mount["type"] == "Bind")
            .map(|mount| mount["guest"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            binds.iter().any(|guest| guest == "/own"),
            inherited && options.is_empty(),
            "{label}: the mount facet follows both switches: {binds:?}"
        );
    }

    // The fallback singleton: no declared shell, so the shipped one is synthesized
    // in its own scope and inherits nothing — with or without the mount opt-out.
    for options in [Vec::new(), vec!["--no-config-mounts"]] {
        let harness = Harness::warm();
        harness.write_user(
            "[[tools]]\nname = \"agent\"\ncommand = \"/bin/echo\"\ntools = []\n\
             credentials = [\"anthropic\"]\npersist = [\"agent-state\"]\n\
             mounts = [\"~/own:/own:ro\"]\n",
        );
        std::fs::create_dir_all(harness.home_root.join("own")).unwrap();
        std::fs::write(harness.home_root.join("own/marker"), "own").unwrap();
        let out = harness.launch("shell", &options);
        let stderr = stderr_of(&out);
        assert!(stderr.contains(CONFIG_MARKER), "{options:?}: {stderr}");
        let config = debug_config_json(&stderr);
        assert!(
            !registered_secret_env_vars(&config).contains(&"MSB_AGENT_VM_ANTHROPIC_UNUSED"),
            "{options:?}: the fallback provisions nothing"
        );
        assert!(
            !snapshot(&state_dir(&stderr)).contains_key("link:agent-state"),
            "{options:?}: the fallback inherits no persisted path"
        );
        assert!(
            !config["mounts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|mount| mount["guest"] == "/own"),
            "{options:?}: the fallback inherits no mount"
        );
    }
}

/// #396 AC-guards: a selected topology error — a closure mount colliding with an
/// inherited declared `persist` link — is decided before the common launch effects,
/// even with an otherwise valid fork in the same closure.
#[test]
fn tool_mount_invalid_topology_precedes_common_launch_effects() {
    let harness = Harness::warm();
    std::fs::create_dir_all(harness.home_root.join("live")).unwrap();
    std::fs::create_dir_all(harness.home_root.join("fork-src")).unwrap();
    std::fs::write(harness.home_root.join("fork-src/marker"), "seed").unwrap();
    let shadow = format!("{}/x-state", harness.home_root.display());
    harness.write_user(&format!(
        "[[tools]]\nname = \"t\"\ncommand = \"/bin/echo\"\ntools = [\"u\"]\n\
         mounts = [\"~/fork-src:/f:fork\", \"~/live:{shadow}:ro\"]\n\
         [[tools]]\nname = \"u\"\ncommand = \"/bin/echo\"\ntools = []\npersist = [\"x-state\"]\n"
    ));
    // Everything the launch could have written, before it is even started.
    let files_before = state_regular_files(&harness.state_root);
    let names_before = top_level_state(&harness);
    let out = harness.launch("t", &[]);
    let stderr = stderr_of(&out);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains("would collide with the guest mount point"),
        "the inherited persist collision must be named: {stderr}"
    );
    assert!(
        !stderr.contains(CONFIG_MARKER),
        "no sandbox config may be built: {stderr}"
    );
    assert!(
        !stderr.contains(GUEST_CMD_MARKER),
        "no guest command may be built: {stderr}"
    );
    assert!(
        !stderr.contains("Initialized fork"),
        "the valid fork in the same closure must not be published: {stderr}"
    );
    assert_eq!(state_regular_files(&harness.state_root), files_before);
    assert_eq!(top_level_state(&harness), names_before);
    assert!(
        harness.msb_log().lines().all(|line| line == "--version"),
        "the runtime may only be version-probed: {}",
        harness.msb_log()
    );
}

/// The state root's top-level entry names, so a refused launch cannot have created
/// a project state directory or a fork store even if it wrote no regular file.
fn top_level_state(harness: &Harness) -> Vec<std::ffi::OsString> {
    let mut names: Vec<std::ffi::OsString> = std::fs::read_dir(&harness.state_root)
        .map(|entries| entries.map(|entry| entry.unwrap().file_name()).collect())
        .unwrap_or_default();
    names.sort();
    names
}
