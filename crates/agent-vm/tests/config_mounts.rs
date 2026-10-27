//! Boot-free integration harness for verified user config mounts
//! (issue #394 / ADR-0046) and for the launch-order guarantees they share with
//! `--mount`.
//!
//! Rust compiles each file in `tests/` as its own crate, so the helpers below
//! are duplicated per test binary on purpose — the same rule `tests/mount_fork.rs`
//! documents. Only a genuine cross-harness precondition lives in `tests/support/`.
//!
//! The file starts with the two **CLI-only** persisted-guest-HOME cases for
//! ADR-0046 Decision 6: a mount that shadows a declared `persist` path must be
//! refused *inside* `mount::prepare`, i.e. before any fork is published. They
//! are CLI-only so the boundary they assert — which does not depend on which
//! source declared the mount — stays pinned independently of the config rows
//! that follow them.
//!
//! Every refusal assertion goes through
//! [`Harness::assert_refused_before_launch_state`], whose oracle is calibrated by
//! `refusal_oracle_is_calibrated` below: a launch that is merely failing for some
//! other reason would not change the snapshot or reach the runtime, so an
//! uncalibrated "nothing changed" assertion is vacuous.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

mod support;

#[path = "support/image_archive.rs"]
mod image_archive;

#[path = "support/fake_msb.rs"]
mod fake_msb;

/// The `AGENT_VM_DEBUG_CONFIG` marker: it prints immediately before the
/// builder's registry pull, so its presence proves the launch got past every
/// preflight boundary these tests are about.
const CONFIG_MARKER: &str = "[debug] sandbox config JSON: ";

/// The banner line emitted after `mount::prepare` returns. A refused plan must
/// never print it, so its absence is a second, independent ordering signal
/// (a `--mount` notice could in principle be emitted by a helper the refusal
/// boundary reuses; the banner cannot).
const BOOT_BANNER: &str = "==> Boot image: ";

fn agent_vm_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-vm"))
}

/// Run `cmd` to completion, killing it if it does not exit within `timeout`.
/// Reads stdout/stderr on separate threads so a full pipe cannot deadlock the
/// wait. Duplicated from `tests/mount_fork.rs` for the reason in this file's
/// module comment.
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

/// Everything a refused launch could possibly have written, as
/// `(labelled relative path → description)`.
///
/// A description is `directory`, `symlink:<target>`, or
/// `file:<length>:<digest>`. Digests rather than bytes because the state root
/// really does hold multi-megabyte image blobs, and an equality failure should
/// print the paths that differ, not those blobs. Sorted, so comparison is
/// order-independent.
type Snapshot = BTreeMap<String, String>;

/// Walk `root` recursively into `out`, prefixing every key with `label`. A
/// missing root contributes nothing — several of these trees legitimately do
/// not exist before a launch.
fn tree_of(label: &str, root: &Path, out: &mut Snapshot) {
    let Ok(read) = std::fs::read_dir(root) else {
        return;
    };
    for entry in read {
        let entry = entry.unwrap();
        let relative = entry.path().strip_prefix(root).unwrap().to_path_buf();
        let key = if label.is_empty() {
            relative.display().to_string()
        } else {
            format!("{label}/{}", relative.display())
        };
        let metadata = std::fs::symlink_metadata(entry.path()).unwrap();
        let description = if metadata.is_dir() {
            tree_of(label, &entry.path(), out);
            "directory".to_string()
        } else if metadata.file_type().is_symlink() {
            let target = std::fs::read_link(entry.path()).unwrap();
            // `OsStr`'s `Debug` renders the raw bytes, so a non-UTF-8 target
            // still compares exactly instead of collapsing to U+FFFD.
            format!("symlink:{:?}", target.as_os_str())
        } else {
            let bytes = std::fs::read(entry.path()).unwrap();
            format!("file:{}:{:016x}", bytes.len(), digest(&bytes))
        };
        out.insert(key, description);
    }
}

fn digest(bytes: &[u8]) -> u64 {
    use std::hash::{Hash as _, Hasher as _};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut hasher);
    hasher.finish()
}

/// One isolated `$HOME` + `AGENT_VM_STATE_DIR` + project dir (cwd) + fake
/// runtime pair, plus the helpers every declaration-source test needs.
struct Harness {
    /// The child's `HOME`. The fake runtime deliberately lives *outside* it (see
    /// [`Harness::runtime`]) so `snapshot()` can cover `$HOME` whole.
    _home: tempfile::TempDir,
    _state: tempfile::TempDir,
    _project: tempfile::TempDir,
    /// The fake runtime's directory. Its invocation log changes on every launch,
    /// so it must not be inside a snapshotted tree.
    _runtime: tempfile::TempDir,
    home_root: PathBuf,
    project_root: PathBuf,
    state_root: PathBuf,
    /// The imported fixture reference the harness's launches select.
    image: String,
    fake_msb: fake_msb::FakeMsb,
}

impl Harness {
    /// A harness whose state root holds one genuinely host-valid image imported
    /// through the public CLI, so a launch that gets past mount preparation has
    /// something to approve.
    fn new() -> Self {
        // `$HOME` and the project dir live on the workspace filesystem;
        // `CARGO_TARGET_DIR` on a guest tmpfs prefix is refused by
        // `support::project_tempdir`, because the guest would remap it.
        let home = tempfile::tempdir_in(support::workspace_tmpdir()).unwrap();
        // The state root stays under `/tmp` to keep the sandbox's control socket
        // inside the `sun_path` limit.
        let state = tempfile::tempdir_in("/tmp").unwrap();
        let project = support::project_tempdir();
        let runtime = tempfile::tempdir_in("/tmp").unwrap();
        let home_root = home.path().canonicalize().unwrap();
        let project_root = project.path().canonicalize().unwrap();
        let state_root = state.path().canonicalize().unwrap();
        // `LaunchSeam`, not `VersionOnly`: a version-only script answers and
        // logs nothing useful, and these tests need to prove that *only* the
        // version probe ran.
        let fake_msb = fake_msb::install_pair(runtime.path(), fake_msb::Mode::LaunchSeam);
        let harness = Self {
            _home: home,
            _state: state,
            _project: project,
            _runtime: runtime,
            home_root,
            project_root,
            state_root,
            image: "fixture:boot".to_string(),
            fake_msb,
        };
        harness.import_fixture_image();
        harness
    }

    /// Import a host-valid image archive into this harness's state root under
    /// [`Self::image`]. Import alone must not create approval/pin records.
    fn import_fixture_image(&self) {
        let archive = self.home_root.join("fixture-boot.tar");
        image_archive::write(&archive, &image_archive::ArchiveSpec::default());
        let mut import = Command::new(agent_vm_bin());
        import
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", &self.home_root)
            .env("AGENT_VM_STATE_DIR", &self.state_root)
            .env("MSB_PATH", &self.fake_msb.path)
            .current_dir(&self.project_root)
            .args([
                "image",
                "import",
                "--input",
                archive.to_str().unwrap(),
                "--tag",
                &self.image,
            ]);
        let out = run_with_timeout(import, Duration::from_secs(60));
        assert!(
            out.status.success(),
            "fixture import failed: {}",
            stderr_of(&out)
        );
        assert!(
            !self
                .home_root
                .join(".config/agent-vm/image-pins.json")
                .exists(),
            "import must not record a pin"
        );
    }

    fn project_config(&self) -> PathBuf {
        self.project_root.join(".agent-vm/config.toml")
    }

    fn write_project(&self, contents: &str) {
        write_file(&self.project_config(), contents);
    }

    /// `~/.config/agent-vm/config.toml` — the only file that may declare
    /// `mounts`.
    fn user_config(&self) -> PathBuf {
        self.home_root.join(".config/agent-vm/config.toml")
    }

    /// Write the user config in the shape the verified-read policy expects to
    /// find it: a 0600 file in a 0700 directory. Every test that starts from a
    /// *trusted* file uses this; the refusal matrix deliberately breaks one
    /// fact at a time on top of it.
    fn write_user(&self, contents: &str) {
        self.write_user_mode(contents, 0o600);
    }

    fn write_user_mode(&self, contents: &str, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        let path = self.user_config();
        write_file(&path, contents);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        std::fs::set_permissions(
            path.parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }

    /// Replace `config.toml` with a symlink to `target`, the ordinary
    /// dotfile-manager layout.
    fn symlink_user_config(&self, target: &Path) {
        std::fs::create_dir_all(self.user_config().parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(target, self.user_config()).unwrap();
    }

    fn base_command(&self) -> Command {
        let mut cmd = Command::new(agent_vm_bin());
        cmd.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", &self.home_root)
            .env("AGENT_VM_STATE_DIR", &self.state_root)
            .env("MSB_PATH", &self.fake_msb.path)
            .env("AGENT_VM_DEBUG_CONFIG", "1")
            // The project root lives under this checkout's `target/tmp`, so tell
            // git's discovery to stop before it can ascend to the repository:
            // otherwise `run::detect_github_repos` would put this clone's remotes
            // in the GitHub allow-list and the launch shape would depend on where
            // the checkout lives.
            .env("GIT_CEILING_DIRECTORIES", env!("CARGO_TARGET_TMPDIR"))
            .current_dir(&self.project_root);
        cmd
    }

    /// `agent-vm [options…] --image <fixture> <verb> [args…]`.
    fn launch(&self, options: &[&str], verb: &str, args: &[&str]) -> Output {
        self.launch_with_env(options, verb, args, &[])
    }

    /// [`Self::launch`] with extra host environment variables.
    fn launch_with_env(
        &self,
        options: &[&str],
        verb: &str,
        args: &[&str],
        envs: &[(&str, &str)],
    ) -> Output {
        let mut cmd = self.base_command();
        for (key, value) in envs {
            cmd.env(key, value);
        }
        cmd.arg("--image").arg(&self.image);
        cmd.args(options);
        cmd.arg(verb);
        cmd.args(args);
        run_with_timeout(cmd, Duration::from_secs(60))
    }

    /// [`Self::launch`] with `HOME` pointing at `home` instead of this
    /// harness's canonical home — the symlinked-home spelling test.
    fn launch_with_home(&self, home: &Path, options: &[&str], verb: &str, args: &[&str]) -> Output {
        let mut cmd = self.base_command();
        cmd.env("HOME", home);
        cmd.arg("--image").arg(&self.image);
        cmd.args(options);
        cmd.arg(verb);
        cmd.args(args);
        run_with_timeout(cmd, Duration::from_secs(60))
    }

    /// `agent-vm doctor`, which takes no launch options (so no `--image`).
    fn doctor(&self) -> Output {
        let mut cmd = self.base_command();
        cmd.arg("doctor");
        run_with_timeout(cmd, Duration::from_secs(60))
    }

    /// Top-level `--help`, which must work even when the config is broken.
    fn help(&self) -> Output {
        let mut cmd = self.base_command();
        cmd.arg("--help");
        run_with_timeout(cmd, Duration::from_secs(60))
    }

    /// The project's mount store (`<state>/<hash>.mounts`), if one exists.
    /// Its existence is the observable "a fork was published / the store was
    /// created" signal; a refused plan must leave it absent.
    fn mount_store(&self) -> Option<PathBuf> {
        let mut stores: Vec<PathBuf> = std::fs::read_dir(&self.state_root)
            .ok()?
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with(".mounts"))
            })
            .collect();
        stores.sort();
        assert!(
            stores.len() <= 1,
            "one project has at most one mount store: {stores:?}"
        );
        stores.pop()
    }

    /// Every published fork directory, sorted.
    fn fork_dirs(&self) -> Vec<PathBuf> {
        let Some(store) = self.mount_store() else {
            return Vec::new();
        };
        let mut forks: Vec<PathBuf> = std::fs::read_dir(store.join("forks"))
            .map(|entries| entries.map(|entry| entry.unwrap().path()).collect())
            .unwrap_or_default();
        forks.sort();
        forks
    }

    /// Every argv the fake runtime was invoked with, one per line.
    fn msb_log(&self) -> String {
        std::fs::read_to_string(&self.fake_msb.invocations).unwrap_or_default()
    }

    /// Everything a refused launch must have left untouched: the state root
    /// (fork store, provisioning, `msb-home`, image cache), the sibling
    /// `<state>.secrets` credential directory (a refused plan must not refresh
    /// credentials), and `$HOME` whole (user config, pins, credential files and
    /// every fixture source).
    ///
    /// `<state>.secrets` is a *sibling* of the state dir, so the recursive walk
    /// cannot find it — it is listed separately for exactly that reason.
    fn snapshot(&self) -> Snapshot {
        let mut entries = Snapshot::new();
        tree_of("state", &self.state_root, &mut entries);
        tree_of(
            "secrets",
            &PathBuf::from(format!("{}.secrets", self.state_root.display())),
            &mut entries,
        );
        tree_of("home", &self.home_root, &mut entries);
        entries
    }

    /// The refusal oracle. See the module comment: `refusal_oracle_is_calibrated`
    /// is what keeps it from being vacuous.
    fn assert_refused_before_launch_state(&self, out: &Output, before: &Snapshot, needle: &str) {
        let stderr = stderr_of(out);
        assert!(!out.status.success(), "the launch must fail: {stderr}");
        assert!(
            stderr.contains(needle),
            "expected {needle:?} in the refusal: {stderr}"
        );
        assert!(
            !stderr.contains(CONFIG_MARKER),
            "the refusal must precede builder wiring: {stderr}"
        );
        assert!(
            !stderr.contains(BOOT_BANNER),
            "the refusal must precede the launch banner: {stderr}"
        );
        assert_eq!(
            self.snapshot(),
            *before,
            "a refused plan must not create or mutate launch state: {stderr}"
        );
        for line in self.msb_log().lines() {
            let first = line.split_whitespace().next().unwrap_or_default();
            assert_eq!(
                first, "--version",
                "a refused plan may only probe the runtime version, saw {line:?}"
            );
        }
    }
}

fn write_file(path: &Path, contents: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

/// Extract the `SandboxConfig` JSON that `AGENT_VM_DEBUG_CONFIG=1` dumps to
/// stderr right after `builder.build()`: find the marker and parse the first
/// complete JSON value that follows it. Duplicated from `tests/mount_fork.rs`
/// for the reason in this file's module comment.
fn debug_config_json(stderr: &str) -> serde_json::Value {
    let idx = stderr
        .find(CONFIG_MARKER)
        .unwrap_or_else(|| panic!("no debug config JSON found in stderr:\n{stderr}"));
    let rest = &stderr[idx + CONFIG_MARKER.len()..];
    serde_json::Deserializer::from_str(rest)
        .into_iter::<serde_json::Value>()
        .next()
        .unwrap_or_else(|| panic!("no JSON value found after debug marker in stderr:\n{stderr}"))
        .unwrap_or_else(|e| panic!("debug config JSON failed to parse: {e}\nstderr:\n{stderr}"))
}

/// The `Bind` mounts of a dumped `SandboxConfig` as `(host, guest, readonly)`
/// triples — the guest's observable volume set, independent of notice text.
fn bind_mounts(config: &serde_json::Value) -> Vec<(String, String, bool)> {
    config["mounts"]
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
        .collect()
}

/// The `[debug] guest command: …` line's payload: what the runtime would have
/// executed, so a forwarded tool argument is visible without a boot.
fn guest_command(stderr: &str) -> String {
    const MARKER: &str = "[debug] guest command: ";
    stderr
        .lines()
        .find_map(|line| line.strip_prefix(MARKER))
        .unwrap_or_else(|| panic!("no guest command in stderr:\n{stderr}"))
        .to_string()
}

/// `… (state: /path/to/<hash>)` from the launch banner.
fn state_dir(stderr: &str) -> PathBuf {
    const MARKER: &str = "(state: ";
    let start = stderr
        .find(MARKER)
        .unwrap_or_else(|| panic!("no state dir in the banner; stderr:\n{stderr}"))
        + MARKER.len();
    let end = stderr[start..]
        .find(')')
        .unwrap_or_else(|| panic!("unterminated state dir; stderr:\n{stderr}"));
    PathBuf::from(&stderr[start..start + end])
}

/// A project tool with one declared `persist` path — the only way to declare a
/// guest-HOME link, and the collision target of the two tests below.
const PERSIST_CODE: &str = "[[tools]]\nname = \"aider\"\ncommand = \"/bin/echo\"\ncredentials = []\npersist = [\"code\"]\n";

/// The persisted-guest-HOME refusal, byte for byte, for a `persist = ["code"]`
/// link under `guest_home`. Both paths take the one-line policy, and the
/// harness's temp dirs contain no bytes it would rewrite.
fn persist_collision_message(guest_home: &str) -> String {
    format!(
        "Error: config: persist path code would collide with the guest mount point \
         {guest_home}/code; rename the persist path or move the mount"
    )
}

// ---------------------------------------------------------------------------
// ADR-0046 Decision 6 — a plan that would shadow a persist link publishes no fork
// ---------------------------------------------------------------------------

/// A `:fork` declaration whose guest path shadows a declared `persist` link must
/// be refused *before* the fork is published. Published forks are host state
/// (`<state>/<hash>.mounts/forks/<id>/data`) — a copy of the user's directory —
/// so refusing afterwards would leave that copy behind for a launch that never
/// happened.
#[test]
fn a_cli_fork_shadowing_a_persist_path_publishes_no_fork() {
    let h = Harness::new();
    h.write_project(PERSIST_CODE);
    let source = h.home_root.join("src");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("seed"), "seed").unwrap();
    let guest = format!("{}/code", h.home_root.display());
    let mount = format!("{}:{guest}:fork", source.display());

    let before = h.snapshot();
    let out = h.launch(&["--mount", &mount], "aider", &[]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("would collide with the guest mount point"),
        "expected the persisted-HOME refusal: {stderr}"
    );
    // Byte-exact and *unwrapped*: `prepare`'s caller must not add its
    // `preparing --mount` context, because this collision can equally be caused
    // by the core project bind, which is not a `--mount` at all.
    assert_eq!(
        stderr.lines().next().unwrap_or_default(),
        persist_collision_message(&h.home_root.display().to_string()),
        "{stderr}"
    );
    assert!(
        !stderr.contains("preparing --mount"),
        "the persisted-HOME refusal must not be wrapped in a --mount context: {stderr}"
    );
    assert!(
        !stderr.contains("Initialized fork"),
        "the fork must not be published before the collision is refused: {stderr}"
    );
    h.assert_refused_before_launch_state(&out, &before, "would collide with the guest mount point");
}

/// The same guarantee when the collision is caused by an unrelated live bind and
/// the *fork* is a different declaration: nothing about the plan is invalid in
/// isolation, so only a check over the complete normalized destination set (in
/// `prepare`, ahead of `prepare_forks`) can refuse it without publishing `/f`.
#[test]
fn an_unrelated_fork_with_a_colliding_live_mount_publishes_no_fork() {
    let h = Harness::new();
    h.write_project(PERSIST_CODE);
    let other = h.home_root.join("other");
    std::fs::create_dir(&other).unwrap();
    std::fs::write(other.join("seed"), "seed").unwrap();
    let live = h.home_root.join("live");
    std::fs::create_dir(&live).unwrap();
    std::fs::write(live.join("content"), "content").unwrap();
    let guest = format!("{}/code", h.home_root.display());
    let fork = format!("{}:/f:fork", other.display());
    let bind = format!("{}:{guest}:ro", live.display());

    let before = h.snapshot();
    let out = h.launch(&["--mount", &fork, "--mount", &bind], "aider", &[]);
    let stderr = stderr_of(&out);
    assert_eq!(
        stderr.lines().next().unwrap_or_default(),
        persist_collision_message(&h.home_root.display().to_string()),
        "{stderr}"
    );
    assert!(
        !stderr.contains("Initialized fork"),
        "the unrelated fork must not be published before the collision is refused: {stderr}"
    );
    h.assert_refused_before_launch_state(&out, &before, "would collide with the guest mount point");
}

/// A `persist` entry is config-chosen text, but this refusal names one file to
/// rename, not two entries to compare, so it takes the one-line policy: a
/// non-ASCII persist path prints as itself instead of `\xd0\xba\xd0\xbe\xd0\xb4`
/// (issue #422). A control byte is still escaped — `a_config_source_spelling_cannot_forge_a_diagnostic_line`
/// and the `persist` unit test in `session` cover that half.
#[test]
fn a_non_ascii_persist_path_is_printed_as_itself() {
    let h = Harness::new();
    h.write_project(
        "[[tools]]\nname = \"aider\"\ncommand = \"/bin/echo\"\ncredentials = []\npersist = [\"код\"]\n",
    );
    let source = h.home_root.join("src");
    std::fs::create_dir(&source).unwrap();
    let guest = format!("{}/код", h.home_root.display());
    let mount = format!("{}:{guest}:fork", source.display());

    let out = h.launch(&["--mount", &mount], "aider", &[]);
    let stderr = stderr_of(&out);
    assert_eq!(
        stderr.lines().next().unwrap_or_default(),
        format!(
            "Error: config: persist path код would collide with the guest mount point {guest}; \
             rename the persist path or move the mount"
        ),
        "{stderr}"
    );
    assert!(!stderr.contains("\\xd0"), "byte-escaped: {stderr}");
}

/// The oracle above is only meaningful if an accepted launch in the same harness
/// really does reach the builder and mutate the state root. If either stops
/// happening, every "nothing changed" assertion in this file would pass for the
/// wrong reason.
#[test]
fn refusal_oracle_is_calibrated() {
    let h = Harness::new();
    h.write_project(PERSIST_CODE);
    let source = h.home_root.join("src");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("seed"), "seed").unwrap();
    // The same fork mount, but at a guest path that shadows nothing.
    let mount = format!("{}:/f:fork", source.display());
    let before = h.snapshot();
    let out = h.launch(&["--mount", &mount], "aider", &[]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(CONFIG_MARKER),
        "an accepted plan must reach builder wiring: {stderr}"
    );
    assert_ne!(
        h.snapshot(),
        before,
        "an accepted plan must mutate launch state: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Config authority: presence-not-contents, and the verified-read matrix
// ---------------------------------------------------------------------------

/// A value that must never reach a diagnostic: the file it is written into is
/// the one a reader is being asked to trust, so its bytes are not quotable.
const SENTINEL: &str = "sk-live-SENTINEL-394";

/// A body whose *presence* is authority-bearing and whose content selects one
/// mount. The comment carries the sentinel: comments are legal TOML, so a
/// leaked file body would show up here and nowhere else.
fn sentinel_mounts_body() -> String {
    format!("# {SENTINEL}\nmounts = [\"~/a:ro\"]\n")
}

fn sorted_binds(config: &serde_json::Value) -> Vec<(String, String, bool)> {
    let mut binds = bind_mounts(config);
    // The builder stores mounts in a hash-ordered collection, so the order is
    // run-dependent; the mount *set* is what a test may compare.
    binds.sort();
    binds
}

/// Empty-present authority: `mounts = []` still makes the file
/// authority-bearing, so it must pass the verified-read policy — and then
/// select nothing. Presence, not contents, is the trigger.
#[test]
fn empty_mounts_still_requires_a_verified_file() {
    let h = Harness::new();
    h.write_user("mounts = []\n");
    let accepted = h.launch(&[], "shell", &[]);
    let stderr = stderr_of(&accepted);
    assert!(
        stderr.contains(CONFIG_MARKER),
        "an empty list is authority that passes: {stderr}"
    );
    assert!(
        !stderr.contains("==> Config mounts:"),
        "an empty selection must not print a count-of-zero notice: {stderr}"
    );
    let with_empty = sorted_binds(&debug_config_json(&stderr));

    // Differential: the same launch with no `mounts` key at all must produce
    // exactly the same guest volume set, so "selects nothing" is observed, not
    // assumed.
    std::fs::remove_file(h.user_config()).unwrap();
    let without = sorted_binds(&debug_config_json(&stderr_of(&h.launch(&[], "shell", &[]))));
    assert_eq!(
        with_empty, without,
        "an empty mounts list must add and remove no bind"
    );

    // Presence, not contents: the same bytes reached through a final-component
    // symlink are refused before any launch state.
    let h = Harness::new();
    let target = h.home_root.join("dotfiles/config.toml");
    write_file(&target, "mounts = []\n");
    h.symlink_user_config(&target);
    let before = h.snapshot();
    let out = h.launch(&[], "shell", &[]);
    h.assert_refused_before_launch_state(
        &out,
        &before,
        "mounts requires config.toml to be a regular file",
    );
    assert!(
        stderr_of(&out).contains("a symlinked config without mounts still works"),
        "the refusal must say what the rule is not about: {}",
        stderr_of(&out)
    );

    // Positive control: the same symlinked file *without* `mounts` loads, and
    // its tool is registered. Without this row the refusal above could be a
    // blanket refusal of symlinked configs.
    let h = Harness::new();
    let target = h.home_root.join("dotfiles/config.toml");
    write_file(
        &target,
        "[[tools]]\nname = \"probe\"\ncommand = \"/bin/probe\"\ncredentials = []\n",
    );
    h.symlink_user_config(&target);
    let out = h.launch(&[], "probe", &[]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(CONFIG_MARKER),
        "a symlinked config without mounts still works: {stderr}"
    );
    assert_eq!(guest_command(&stderr), "/bin/probe", "{stderr}");
}

/// Every way the verified-read policy can be violated, refused before any
/// launch state, plus the two modes that must stay accepted (0600 and 0644: the
/// policy refuses group/other *write*, never readability).
///
/// Owner refusals cannot be fabricated as a non-root user; they are covered by
/// `config_authority::tests::refusal_matches_independent_oracle_table` and
/// `verify_verdicts_on_real_files` (which prints `NOT RUN` as root).
#[test]
fn unsafe_user_mounts_are_refused_before_launch_state() {
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
        let h = Harness::new();
        let source = h.home_root.join("a");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("content"), "content").unwrap();
        // Every row starts from the accepted shape; the untrusted rows break
        // exactly one fact on top of it.
        h.write_user(&sentinel_mounts_body());
        let file = h.user_config();
        let reason = match shape {
            "group" => {
                std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o664)).unwrap();
                "mounts refuses a group- or other-writable config.toml"
            }
            "other" => {
                std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o646)).unwrap();
                "mounts refuses a group- or other-writable config.toml"
            }
            "directory" => {
                std::fs::set_permissions(
                    file.parent().unwrap(),
                    std::fs::Permissions::from_mode(0o775),
                )
                .unwrap();
                "mounts refuses a config.toml whose directory is group- or other-writable"
            }
            "hardlink" => {
                std::fs::hard_link(&file, h.project_root.join("alias")).unwrap();
                "mounts refuses a config.toml with 2 hard links"
            }
            "symlink" => {
                let target = h.project_root.join("dotfile");
                std::fs::rename(&file, &target).unwrap();
                h.symlink_user_config(&target);
                "mounts requires config.toml to be a regular file"
            }
            "readable" => {
                std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
                ""
            }
            _ => "",
        };

        let before = h.snapshot();
        let out = h.launch(&[], "shell", &[]);
        let stderr = stderr_of(&out);
        if reason.is_empty() {
            assert!(
                stderr.contains(CONFIG_MARKER),
                "{shape}: an accepted file must reach builder wiring: {stderr}"
            );
            let binds = bind_mounts(&debug_config_json(&stderr));
            assert!(
                binds.iter().any(|(host, guest, readonly)| {
                    *host == source.display().to_string()
                        && *guest == source.display().to_string()
                        && *readonly
                }),
                "{shape}: the declared mount must be applied: {binds:?}"
            );
            assert!(
                stderr.contains(&format!("==> Config mounts: 1 from \"{}\"", file.display())),
                "{shape}: {stderr}"
            );
        } else {
            assert!(
                stderr.contains(reason),
                "{shape}: expected {reason:?}: {stderr}"
            );
            assert!(
                stderr.contains(&file.display().to_string()),
                "{shape}: the refusal must name the user file: {stderr}"
            );
            assert!(
                !stderr.contains(SENTINEL),
                "{shape}: the refusal echoed file content: {stderr}"
            );
            h.assert_refused_before_launch_state(&out, &before, reason);
            assert!(
                h.mount_store().is_none(),
                "{shape}: no mount store may be created"
            );
        }
    }
}

/// ADR-0040's documented stable route: the *config directory* may be a symlink
/// to a user-owned directory, as long as the final component is a regular file.
/// This is the counterpart to the final-component-symlink refusal above and
/// proves the policy was reused rather than re-invented with a stricter rule.
#[test]
fn symlinked_user_config_directory_with_mounts_is_followed() {
    use std::os::unix::fs::PermissionsExt;
    let h = Harness::new();
    let source = h.home_root.join("a");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("content"), "content").unwrap();
    let real = h.home_root.join("realcfg");
    write_file(&real.join("config.toml"), &sentinel_mounts_body());
    std::fs::set_permissions(
        real.join("config.toml"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
    let link = h.user_config().parent().unwrap().to_path_buf();
    std::fs::create_dir_all(link.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&real, &link).unwrap();

    let out = h.launch(&[], "shell", &[]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(CONFIG_MARKER),
        "a symlinked config directory is an accepted route: {stderr}"
    );
    let binds = bind_mounts(&debug_config_json(&stderr));
    assert!(
        binds
            .iter()
            .any(|(host, _, readonly)| *host == source.display().to_string() && *readonly),
        "the mount from the followed directory must be applied: {binds:?}"
    );
}

/// The ordinary dotfile layout most users have: a `tools`-only (or
/// image-only) config reached through a final-component symlink. It declares no
/// mount authority, so it must keep working exactly as before.
#[test]
fn symlinked_user_config_without_mounts_still_launches() {
    let h = Harness::new();
    h.write_user("[[tools]]\nname = \"probe\"\ncommand = \"/bin/probe\"\ncredentials = []\n");
    let target = h.project_root.join("dotfile");
    std::fs::rename(h.user_config(), &target).unwrap();
    h.symlink_user_config(&target);

    let out = h.launch(&[], "probe", &[]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(CONFIG_MARKER),
        "a tools-only symlinked config must launch: {stderr}"
    );
    assert_eq!(
        guest_command(&stderr),
        "/bin/probe",
        "the user tool must be registered from the symlinked file: {stderr}"
    );
    // A config with no mounts must add nothing: the bind set is exactly the
    // three core binds (state, persisted home, project).
    let binds = sorted_binds(&debug_config_json(&stderr));
    let state = state_dir(&stderr);
    for guest in [
        PathBuf::from("/agent-vm-state"),
        h.home_root.clone(),
        h.project_root.clone(),
    ] {
        assert!(
            binds
                .iter()
                .any(|(_, bind_guest, _)| *bind_guest == guest.display().to_string()),
            "the core bind at {guest:?} is missing: {binds:?} (state {})",
            state.display()
        );
    }
    assert_eq!(
        binds.len(),
        3,
        "a config with no mounts selects no bind: {binds:?}"
    );
}

// ---------------------------------------------------------------------------
// Selection: both declaration sources, dedup, normalized guest collisions
// ---------------------------------------------------------------------------

/// A `mounts` notice naming this harness's user file.
fn config_notice(h: &Harness, count: usize) -> String {
    format!(
        "==> Config mounts: {count} from \"{}\"",
        h.user_config().display()
    )
}

/// How a launch-time refusal names the config declaration at `index`, the same
/// rendering `config::load`'s diagnostics use for one: the label a config author
/// searches their file with, not just `--mount` and the outer file context.
fn config_declaration(h: &Harness, index: usize) -> String {
    format!("mounts[{index}] in \"{}\"", h.user_config().display())
}

/// Source-tree fixture: `$HOME/<name>/content` = `<name>`, so a bind's host
/// path identifies which source was selected.
fn seed_source(h: &Harness, name: &str) -> PathBuf {
    let path = h.home_root.join(name);
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(path.join("content"), name).unwrap();
    path
}

/// Config declarations and `--mount` declarations reach the same planner: both
/// are applied, with their own modes, and the notice reports the config half.
#[test]
fn config_and_cli_mounts_are_both_applied() {
    let h = Harness::new();
    let a = seed_source(&h, "a");
    let b = seed_source(&h, "b");
    h.write_user("mounts = [\"~/a:ro\"]\n");

    let out = h.launch(&["--mount", &format!("{}:/b", b.display())], "shell", &[]);
    let stderr = stderr_of(&out);
    let binds = bind_mounts(&debug_config_json(&stderr));
    let a_text = a.display().to_string();
    let b_text = b.display().to_string();
    assert!(
        binds
            .iter()
            .any(|(host, guest, readonly)| *host == a_text && *guest == a_text && *readonly),
        "the config mount must be a read-only mirror: {binds:?}"
    );
    assert!(
        binds
            .iter()
            .any(|(host, guest, readonly)| *host == b_text && guest == "/b" && !*readonly),
        "the CLI mount must be writable at its guest: {binds:?}"
    );
    assert!(
        stderr.contains(&config_notice(&h, 1)),
        "the notice must count only the config half: {stderr}"
    );
}

/// Equivalent declarations from the two sources are one declaration: the same
/// host, guest and mode must not become two binds or a conflict.
#[test]
fn identical_config_and_cli_declarations_merge() {
    let h = Harness::new();
    let a = seed_source(&h, "a");
    h.write_user("mounts = [\"~/a:/a:ro\"]\n");

    let out = h.launch(
        &["--mount", &format!("{}:/a:ro", a.display())],
        "shell",
        &[],
    );
    let stderr = stderr_of(&out);
    let binds = bind_mounts(&debug_config_json(&stderr));
    let at_a: Vec<_> = binds.iter().filter(|(_, guest, _)| guest == "/a").collect();
    assert_eq!(
        at_a.len(),
        1,
        "identical declarations must merge into one bind: {binds:?}"
    );
    assert_eq!(at_a[0].0, a.display().to_string(), "{binds:?}");
    assert!(at_a[0].2, "the merged declaration keeps :ro: {binds:?}");
}

/// Guest spellings are normalized before claiming, so `/g//./x` and `/g/x` are
/// one guest path in either direction — and a *different* host at that
/// normalized guest is a conflict, not a second bind.
#[test]
fn normalized_guest_spellings_merge_and_conflict_across_sources() {
    for (config, cli) in [
        ("~/a:/g//./x:ro", ":/g/x:ro"),
        ("~/a:/g/x:ro", ":/g//./x:ro"),
    ] {
        let h = Harness::new();
        let a = seed_source(&h, "a");
        let cli = format!("{}{cli}", a.display());
        h.write_user(&format!("mounts = [\"{config}\"]\n"));
        let out = h.launch(&["--mount", &cli], "shell", &[]);
        let stderr = stderr_of(&out);
        let binds = bind_mounts(&debug_config_json(&stderr));
        assert_eq!(
            binds.iter().filter(|(_, guest, _)| guest == "/g/x").count(),
            1,
            "config {config:?} + CLI {cli:?} must be one claim: {binds:?}"
        );
    }

    // A differing host at the normalized guest is refused, naming both sources.
    let h = Harness::new();
    seed_source(&h, "a");
    let b = seed_source(&h, "b");
    h.write_user("mounts = [\"~/a:/g//./x:ro\"]\n");
    let before = h.snapshot();
    let out = h.launch(
        &["--mount", &format!("{}:/g/x:ro", b.display())],
        "shell",
        &[],
    );
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("guest path /g/x is claimed by different declarations"),
        "the normalized guest must be named once: {stderr}"
    );
    assert!(
        stderr.contains(&format!("mounts[0] in \"{}\"", h.user_config().display())),
        "the config origin must be named: {stderr}"
    );
    assert!(
        stderr.contains("and --mount)"),
        "the CLI origin must be named: {stderr}"
    );
    h.assert_refused_before_launch_state(&out, &before, "is claimed by different declarations");
}

/// A config declaration and a `--mount` at one guest path with different hosts
/// are refused — never last-wins, never a CLI override. The refusal names both
/// origins and the opt-out that resolves it.
#[test]
fn config_and_cli_conflicts_are_refused_naming_both() {
    // The conflicting declaration is run first and last: the config half is
    // always claimed first, so argv order cannot change the verdict.
    for conflict_first in [true, false] {
        let h = Harness::new();
        seed_source(&h, "a");
        let b = seed_source(&h, "b");
        h.write_user("mounts = [\"~/a:/g:ro\"]\n");
        let conflicting = format!("{}:/g:ro", b.display());
        let unrelated = format!("{}:/other:ro", b.display());
        let argv = if conflict_first {
            [conflicting.as_str(), unrelated.as_str()]
        } else {
            [unrelated.as_str(), conflicting.as_str()]
        };
        let options: Vec<&str> = argv.iter().flat_map(|mount| ["--mount", *mount]).collect();
        let before = h.snapshot();
        let out = h.launch(&options, "shell", &[]);
        let stderr = stderr_of(&out);
        assert!(
            stderr.contains("guest path /g is claimed by different declarations"),
            "{argv:?}: {stderr}"
        );
        assert!(
            stderr.contains(&format!("mounts[0] in \"{}\"", h.user_config().display())),
            "{argv:?}: the config origin must be named: {stderr}"
        );
        assert!(stderr.contains("and --mount)"), "{argv:?}: {stderr}");
        assert!(
            stderr.contains("--no-config-mounts skips them"),
            "{argv:?}: the opt-out must be offered: {stderr}"
        );
        h.assert_refused_before_launch_state(&out, &before, "is claimed by different declarations");
        assert!(
            h.mount_store().is_none(),
            "{argv:?}: a conflict must not create the store"
        );
    }
}

/// Same host and guest, different mode: still a conflict (equivalence includes
/// the mode), so no silent mode upgrade.
#[test]
fn config_cli_mode_conflict_is_refused() {
    let h = Harness::new();
    let a = seed_source(&h, "a");
    h.write_user("mounts = [\"~/a:/g:ro\"]\n");
    let before = h.snapshot();
    let out = h.launch(
        &["--mount", &format!("{}:/g:rw", a.display())],
        "shell",
        &[],
    );
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("guest path /g is claimed by different declarations"),
        "{stderr}"
    );
    assert!(stderr.contains("and --mount)"), "{stderr}");
    h.assert_refused_before_launch_state(&out, &before, "is claimed by different declarations");
}

/// A self-contradictory `mounts` list is a *load* error, so `--no-config-mounts`
/// cannot bypass it: the flag skips selection, not the file.
#[test]
fn a_self_conflicting_mounts_list_fails_even_with_opt_out() {
    let h = Harness::new();
    h.write_user("mounts = [\"~/a:/g:ro\", \"~/b:/g:ro\"]\n");
    for options in [vec![], vec!["--no-config-mounts"]] {
        let before = h.snapshot();
        let out = h.launch(&options, "shell", &[]);
        let stderr = stderr_of(&out);
        assert!(
            stderr.contains("mounts[1]: claims the same guest path as mounts[0]"),
            "{options:?}: {stderr}"
        );
        assert!(
            stderr.contains(&h.user_config().display().to_string()),
            "{options:?}: the file must be named: {stderr}"
        );
        h.assert_refused_before_launch_state(&out, &before, "claims the same guest path");
    }
}

/// Parent and child guest paths are distinct claims: the config may mount a
/// directory and a `--mount` a path inside it.
#[test]
fn config_parent_and_cli_child_mounts_coexist() {
    let h = Harness::new();
    let p = seed_source(&h, "p");
    let c = p.join("c");
    std::fs::create_dir(&c).unwrap();
    std::fs::write(c.join("inner"), "inner").unwrap();
    h.write_user("mounts = [\"~/p:/p:ro\"]\n");

    let out = h.launch(
        &["--mount", &format!("{}:/p/c:ro", c.display())],
        "shell",
        &[],
    );
    let stderr = stderr_of(&out);
    let binds = bind_mounts(&debug_config_json(&stderr));
    assert!(
        binds
            .iter()
            .any(|(host, guest, readonly)| host == &p.display().to_string()
                && guest == "/p"
                && *readonly),
        "the parent config mount must be present: {binds:?}"
    );
    assert!(
        binds
            .iter()
            .any(|(host, guest, readonly)| host == &c.display().to_string()
                && guest == "/p/c"
                && *readonly),
        "the child CLI mount must be present: {binds:?}"
    );
}

// ---------------------------------------------------------------------------
// Existing protections apply to config declarations unchanged
// ---------------------------------------------------------------------------

/// A config declaration cannot replace agent-vm's own project bind.
#[test]
fn config_mount_onto_a_core_path_is_refused() {
    let h = Harness::new();
    seed_source(&h, "a");
    let project = h.project_root.display().to_string();
    h.write_user(&format!("mounts = [\"~/a:{project}:ro\"]\n"));
    let before = h.snapshot();
    let out = h.launch(&[], "shell", &[]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(&format!(
            "guest path {project} collides with an agent-vm core mount"
        )),
        "{stderr}"
    );
    assert!(
        stderr.contains(&format!("mounts[0] in \"{}\"", h.user_config().display())),
        "the refusal must name the config origin: {stderr}"
    );
    h.assert_refused_before_launch_state(&out, &before, "collides with an agent-vm core mount");
}

/// ADR-0038: a writable mount that contains the protected config directory
/// would let the guest rewrite the authority the next launch trusts.
#[test]
fn writable_config_mount_containing_the_config_dir_is_refused() {
    let h = Harness::new();
    h.write_user("mounts = [\"~/.config:rw\"]\n");
    let config_dir = h.home_root.join(".config/agent-vm");
    let before = h.snapshot();
    let out = h.launch(&[], "shell", &[]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("would let the guest change what"),
        "{stderr}"
    );
    assert!(
        stderr.contains(&config_dir.display().to_string()),
        "{stderr}"
    );
    h.assert_refused_before_launch_state(&out, &before, &config_declaration(&h, 0));
}

/// A config live bind of the host Pi home would expose real credentials.
#[test]
fn live_config_mount_of_pi_home_is_refused() {
    let h = Harness::new();
    let auth = h.home_root.join(".pi/agent/auth.json");
    write_file(&auth, "{\"token\":\"host\"}");
    h.write_user("mounts = [\"~/.pi:ro\"]\n");
    let before = h.snapshot();
    let out = h.launch(&[], "shell", &[]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(&format!(
            "would expose the host Pi credential file {}",
            auth.display()
        )),
        "{stderr}"
    );
    h.assert_refused_before_launch_state(&out, &before, &config_declaration(&h, 0));
    assert_eq!(
        std::fs::read_to_string(&auth).unwrap(),
        "{\"token\":\"host\"}",
        "the refusal must not touch the host credential"
    );
}

/// File mounts stay read-only whichever source declared them.
#[test]
fn writable_config_file_mount_is_refused() {
    let h = Harness::new();
    let file = h.home_root.join("bare");
    std::fs::write(&file, "bare").unwrap();
    h.write_user(&format!("mounts = [\"~/bare:{}\"]\n", file.display()));
    let before = h.snapshot();
    let out = h.launch(&[], "shell", &[]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("a file can only be mounted read-only"),
        "{stderr}"
    );
    h.assert_refused_before_launch_state(&out, &before, &config_declaration(&h, 0));
}

/// A config `:fork` over a regular file names its declaration, not only the
/// file: `--mount …` in a config launch would point at the wrong entry, and the
/// author has a `mounts[N]` to fix.
#[test]
fn config_fork_of_a_file_names_the_declaration() {
    let h = Harness::new();
    let file = h.home_root.join("bare");
    std::fs::write(&file, "bare").unwrap();
    h.write_user("mounts = [\"~/bare:/guest:fork\"]\n");
    let before = h.snapshot();
    let out = h.launch(&[], "shell", &[]);
    let stderr = stderr_of(&out);
    h.assert_refused_before_launch_state(&out, &before, &config_declaration(&h, 0));
    let refusal = stderr
        .lines()
        .map(str::trim)
        .find(|line| line.contains(":fork source must be a directory"))
        .unwrap_or_else(|| panic!("no :fork refusal in:\n{stderr}"));
    assert_eq!(
        refusal,
        format!(
            // The config's `~/` expansion is a literal concatenation of `$HOME`,
            // so the refusal spells the source exactly as the mount will.
            "{} \"{}\": a :fork source must be a directory.",
            config_declaration(&h, 0),
            file.display()
        ),
        "a config refusal names the declaration and no bare --mount:\n{stderr}"
    );
    assert!(!stderr.contains("--mount "), "{stderr}");
    assert!(h.mount_store().is_none());
}

/// A source that is neither a regular file nor a directory (a FIFO) is refused
/// by the kind check; a config entry names its declaration there too, instead of
/// printing a bare host path under a launch that mentions only the file.
///
/// The FIFO lives outside `$HOME` and outside the state root on purpose: the
/// refusal oracle's snapshot reads every non-directory, non-symlink entry as a
/// file, and `read(2)` on a FIFO blocks until a writer appears. Production never
/// opens the source — `canonicalize` and `symlink_metadata` classify it without a
/// descriptor — so an absolute spelling outside the snapshotted trees tests the
/// same sentence without making the harness able to hang.
#[test]
fn config_fifo_source_names_the_declaration() {
    let h = Harness::new();
    let outside = tempfile::tempdir_in(support::workspace_tmpdir()).unwrap();
    let fifo = outside.path().canonicalize().unwrap().join("fifo");
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
    // The classification input is the same one a `~/` spelling gives: a path that
    // exists and is a FIFO.
    use std::os::unix::fs::FileTypeExt as _;
    assert!(
        std::fs::symlink_metadata(&fifo)
            .unwrap()
            .file_type()
            .is_fifo()
    );
    h.write_user(&format!("mounts = [\"{}:/guest:ro\"]\n", fifo.display()));
    let before = h.snapshot();
    let out = h.launch(&[], "shell", &[]);
    let stderr = stderr_of(&out);
    h.assert_refused_before_launch_state(&out, &before, &config_declaration(&h, 0));
    let refusal = stderr
        .lines()
        .map(str::trim)
        .find(|line| line.contains("must be a regular file or directory"))
        .unwrap_or_else(|| panic!("no kind refusal in:\n{stderr}"));
    assert_eq!(
        refusal,
        format!(
            "{} \"{}\" must be a regular file or directory",
            config_declaration(&h, 0),
            fifo.display()
        ),
        "{stderr}"
    );
    assert!(h.mount_store().is_none());
}

/// A prepared volume's host path is *measured* — the canonicalized path of
/// whatever the declaration resolved to — so the launch notice escapes it. A
/// directory whose name carries a newline would otherwise end the notice and
/// start a line the reader would take for agent-vm's own output.
#[test]
fn a_mount_notice_escapes_the_measured_host_path() {
    let h = Harness::new();
    let dir = h.home_root.join("ok\nFORGED-MOUNT");
    std::fs::create_dir(&dir).unwrap();
    h.write_user("mounts = [\"~/ok\\nFORGED-MOUNT:/g/x:rw\"]\n");
    let out = h.launch(&[], "shell", &[]);
    let stderr = stderr_of(&out);
    // A forged continuation does not contain `==> Mounting`, so counting lines
    // that do would count one either way. What sees the forgery is the exact
    // string below plus the two absence checks: the raw newline, and the forged
    // second line it would have produced.
    assert!(
        !stderr.contains("\nFORGED-MOUNT"),
        "the notice ended at the newline in the directory name:\n{stderr}"
    );
    let notice = stderr
        .lines()
        .find(|line| line.contains("==> Mounting"))
        .unwrap_or_else(|| panic!("no mount notice in:\n{stderr}"));
    assert_eq!(
        notice.trim(),
        format!(
            "==> Mounting {}/ok\\x0aFORGED-MOUNT -> /g/x",
            h.home_root.display()
        ),
        "the measured host path is escaped, not interpolated raw:\n{stderr}"
    );
    assert!(
        !stderr
            .lines()
            .any(|line| line.trim() == "FORGED-MOUNT -> /g/x"),
        "a directory name forged a launch notice:\n{stderr}"
    );
}

/// The other half of the policy: escaping exists to keep a notice on one line,
/// not to make it unreadable. This repository supports non-ASCII project and
/// mount paths, so a Cyrillic directory must print as itself — escaping it to
/// `\xd0\xbf…` would hand a user a path they cannot read or copy.
#[test]
fn a_non_ascii_mount_path_is_printed_as_itself() {
    let h = Harness::new();
    let dir = h.home_root.join("проект-тест");
    std::fs::create_dir(&dir).unwrap();
    h.write_user("mounts = [\"~/проект-тест:/g/п:rw\"]\n");
    let out = h.launch(&[], "shell", &[]);
    let stderr = stderr_of(&out);
    let notice = stderr
        .lines()
        .find(|line| line.contains("==> Mounting"))
        .unwrap_or_else(|| panic!("no mount notice in:\n{stderr}"));
    assert_eq!(
        notice.trim(),
        format!("==> Mounting {}/проект-тест -> /g/п", h.home_root.display()),
        "a non-ASCII path must be byte-identical, not escaped:\n{stderr}"
    );
}

/// A config source spelling can carry a newline (TOML basic strings escape
/// one), and the refusal must still be one diagnostic: the value is rendered
/// with the config module's escaping, so it cannot forge a second line that the
/// reader would take for agent-vm's own output.
#[test]
fn a_config_source_spelling_cannot_forge_a_diagnostic_line() {
    let h = Harness::new();
    let forged = h.home_root.join("bad\nFORGED-LINE");
    std::fs::write(&forged, "x").unwrap();
    h.write_user("mounts = [\"~/bad\\nFORGED-LINE:/guest:rw\"]\n");
    let before = h.snapshot();
    let out = h.launch(&[], "shell", &[]);
    let stderr = stderr_of(&out);
    h.assert_refused_before_launch_state(&out, &before, &config_declaration(&h, 0));
    let lines: Vec<&str> = stderr.lines().map(str::trim).collect();
    let index = lines
        .iter()
        .position(|line| line.contains("a file can only be mounted read-only"))
        .unwrap_or_else(|| panic!("no file refusal in:\n{stderr}"));
    assert_eq!(
        lines[index],
        format!(
            "{} \"{}/bad\\x0aFORGED-LINE\": a file can only be mounted read-only.",
            config_declaration(&h, 0),
            h.home_root.display()
        ),
        "the spelling must be escaped, not interpolated raw:\n{stderr}"
    );
    assert!(
        lines[index + 1].starts_with("Use :ro, or :fork"),
        "a value forged a diagnostic line:\n{stderr}"
    );
    assert!(
        !lines.contains(&"FORGED-LINE: a file can only be mounted read-only."),
        "{stderr}"
    );
}

/// `:follow-links` discovery applies to a config declaration too: each
/// discovered real directory is bound read-only at its own host path.
#[test]
fn config_follow_links_discovers_targets() {
    let h = Harness::new();
    let skills = h.home_root.join("skills");
    std::fs::create_dir_all(skills.join("real")).unwrap();
    std::fs::write(skills.join("real/marker"), "marker").unwrap();
    std::os::unix::fs::symlink("real", skills.join("link")).unwrap();
    h.write_user("mounts = [\"~/skills:ro:follow-links\"]\n");

    let out = h.launch(&[], "shell", &[]);
    let stderr = stderr_of(&out);
    let binds = bind_mounts(&debug_config_json(&stderr));
    let real = skills.join("real").display().to_string();
    assert!(
        binds
            .iter()
            .any(|(host, guest, readonly)| host == &real && guest == &real && *readonly),
        "the discovered target must be bound read-only at its real path: {binds:?}"
    );
    assert!(
        binds
            .iter()
            .any(|(host, guest, _)| host == &skills.display().to_string()
                && guest == &skills.display().to_string()),
        "the declared root must stay bound: {binds:?}"
    );
    assert!(
        !binds
            .iter()
            .any(|(host, _, _)| host == &skills.join("link").display().to_string()),
        "a symlink is not itself a bind source: {binds:?}"
    );
}

// ---------------------------------------------------------------------------
// Repo-scan parity: a config mount's remotes widen the allow-list
// ---------------------------------------------------------------------------

/// A git checkout under `$HOME` whose `origin` is a GitHub remote. That remote
/// is the only input [`run::detect_github_repos`] reads, so it is what makes a
/// mounted root widen the launch's allow-list.
fn seed_github_checkout(h: &Harness, name: &str, slug: &str) -> PathBuf {
    let path = seed_source(h, name);
    let git = |args: &[&str]| {
        let out = Command::new("git")
            .arg("-C")
            .arg(&path)
            .args(args)
            .output()
            .expect("git must be runnable");
        assert!(out.status.success(), "git {args:?}: {out:?}");
    };
    git(&["init", "-q"]);
    git(&[
        "remote",
        "add",
        "origin",
        &format!("https://github.com/{slug}.git"),
    ]);
    path
}

/// The launch's `==> GitHub repo scope` line — the allow-list as the launch
/// reports and uses it, rather than a plan internal.
fn repo_scope(stderr: &str) -> String {
    stderr
        .lines()
        .find(|line| line.starts_with("==> GitHub repo scope"))
        .unwrap_or_else(|| panic!("no repo scope line in stderr:\n{stderr}"))
        .to_string()
}

/// A config mount's git remotes widen the GitHub allow-list exactly as the
/// equivalent `--mount` does (ADR-0046's accepted *repo-scan parity* gap). The
/// comparison is the two launches' scope lines, byte for byte: a config route
/// that scanned less, or under a different rule, would be a second policy.
#[test]
fn a_config_mount_widens_the_github_allow_list_like_its_cli_twin() {
    let h = Harness::new();
    let checkout = seed_github_checkout(&h, "checkout", "example/visible");

    h.write_user("mounts = [\"~/checkout:ro\"]\n");
    let configured = stderr_of(&h.launch(&[], "shell", &[]));
    assert!(
        configured.contains(CONFIG_MARKER),
        "the launch must get past preparation: {configured}"
    );
    let from_config = repo_scope(&configured);
    assert_eq!(
        from_config, "==> GitHub repo scope (1): example/visible",
        "a config mount's remote must reach the allow-list"
    );

    // The same directory declared as an argv mount, with no config in play.
    std::fs::remove_file(h.user_config()).unwrap();
    let cli = h.launch(
        &["--mount", &format!("{}:ro", checkout.display())],
        "shell",
        &[],
    );
    let cli = stderr_of(&cli);
    assert!(
        cli.contains(CONFIG_MARKER),
        "the launch must get past preparation: {cli}"
    );
    assert_eq!(
        repo_scope(&cli),
        from_config,
        "the config mount and its --mount twin must widen the allow-list identically"
    );
}

/// The opt-out removes that widening too: the unselected declaration contributes
/// no scan root, so the launch reaches no repository the file named.
#[test]
fn opt_out_removes_a_config_mounts_github_scope() {
    let h = Harness::new();
    seed_github_checkout(&h, "checkout", "example/visible");
    h.write_user("mounts = [\"~/checkout:ro\"]\n");

    let stderr = stderr_of(&h.launch(&["--no-config-mounts"], "shell", &[]));
    assert!(
        stderr.contains(CONFIG_MARKER),
        "the launch must get past preparation: {stderr}"
    );
    assert_eq!(
        repo_scope(&stderr),
        "==> GitHub repo scope: <none> (no api.github.com access)",
        "a suppressed config mount must not widen the allow-list: {stderr}"
    );
    assert!(
        stderr.contains("==> Config mounts: skipped 1 from"),
        "the launch must say the declaration was skipped: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Forks: exclusions, Pi omission, identity, READY reuse, persist collision
// ---------------------------------------------------------------------------

/// Seed `$HOME/src/{visible,hidden,cache}` where `hidden` and `cache` are what
/// the exclusion list names.
fn seed_excludable_source(h: &Harness) -> PathBuf {
    let src = h.home_root.join("src");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("visible"), "visible").unwrap();
    std::fs::write(src.join("hidden"), "hidden").unwrap();
    std::fs::create_dir(src.join("cache")).unwrap();
    std::fs::write(src.join("cache/entry"), "entry").unwrap();
    src
}

/// The one published fork's `data` directory.
fn only_fork_data(h: &Harness) -> PathBuf {
    let forks = h.fork_dirs();
    assert_eq!(forks.len(), 1, "expected exactly one fork: {forks:?}");
    forks[0].join("data")
}

/// The `==> Initialized fork …` notice for a **config** declaration: the declared
/// spelling is escaped and quoted the way every config-facing message renders
/// one, so a source carrying a newline cannot forge a notice line. (An argv fork
/// keeps its historical bare spelling; that text is byte-pinned.) The fixtures
/// below contain no byte the escaper would rewrite, so quoting is the whole
/// difference.
fn initialized_fork(spelling: &str) -> String {
    format!("==> Initialized fork \"{spelling}\" ")
}

/// `:exclude` on a config fork omits the named paths from the committed copy
/// only; the host source keeps them.
#[test]
fn config_fork_omits_excluded_files() {
    let h = Harness::new();
    let src = seed_excludable_source(&h);
    h.write_user("mounts = [\"~/src:/f:fork:exclude=hidden:exclude=cache\"]\n");

    let out = h.launch(&[], "shell", &[]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(&initialized_fork(&src.display().to_string())),
        "{stderr}"
    );
    let data = only_fork_data(&h);
    assert!(
        data.join("visible").exists(),
        "an unexcluded file must be copied: {}",
        data.display()
    );
    assert!(
        !data.join("hidden").exists(),
        "an excluded file must not be copied: {}",
        data.display()
    );
    assert!(
        !data.join("cache").exists(),
        "an excluded directory must not be copied: {}",
        data.display()
    );
    assert!(
        src.join("hidden").exists() && src.join("cache/entry").exists(),
        "exclusions apply to the copy, never to the host source"
    );
}

/// A config fork of the host Pi home omits the credential files exactly like a
/// `--mount` fork does, and leaves the host copies intact.
#[test]
fn config_fork_of_the_pi_home_omits_credentials() {
    let h = Harness::new();
    let pi = h.home_root.join(".pi");
    write_file(&pi.join("agent/auth.json"), "{\"token\":\"host-auth\"}");
    write_file(&pi.join("agent/models.json"), "{\"models\":[]}");
    write_file(&pi.join("settings.json"), "{\"theme\":\"dark\"}");
    h.write_user("mounts = [\"~/.pi:/pi-fork:fork\"]\n");

    let out = h.launch(&[], "shell", &[]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("Omitted host Pi credential file agent/auth.json"),
        "{stderr}"
    );
    let data = only_fork_data(&h);
    for omitted in ["agent/auth.json", "agent/models.json"] {
        assert!(
            !data.join(omitted).exists(),
            "{omitted} must be omitted from the fork: {}",
            data.display()
        );
    }
    assert!(
        data.join("settings.json").exists(),
        "a non-credential file must still be copied: {}",
        data.display()
    );
    assert_eq!(
        std::fs::read_to_string(pi.join("agent/auth.json")).unwrap(),
        "{\"token\":\"host-auth\"}",
        "the host credential must be untouched"
    );
}

/// A config `:fork` that would shadow a declared `persist` link is refused
/// before the fork store exists, with the persisted-HOME message bytes and
/// without the config-mount context wrapping them.
#[test]
fn a_config_fork_shadowing_a_persist_path_is_refused_before_any_fork() {
    let h = Harness::new();
    h.write_project(PERSIST_CODE);
    let src = h.home_root.join("src");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("seed"), "seed").unwrap();
    h.write_user(&format!(
        "mounts = [\"~/src:{}/code:fork\"]\n",
        h.home_root.display()
    ));

    let before = h.snapshot();
    let out = h.launch(&[], "aider", &[]);
    let stderr = stderr_of(&out);
    assert_eq!(
        stderr.lines().next().unwrap_or_default(),
        persist_collision_message(&h.home_root.display().to_string()),
        "{stderr}"
    );
    assert!(
        !stderr.contains("preparing"),
        "the persisted-HOME refusal must not be wrapped: {stderr}"
    );
    assert!(
        !stderr.contains("Initialized fork"),
        "no fork may be published before the collision is refused: {stderr}"
    );
    h.assert_refused_before_launch_state(&out, &before, "would collide with the guest mount point");
    assert!(
        h.mount_store().is_none(),
        "the mount store must not exist after a refused plan"
    );

    // Positive control: the same config and the same fork publish once nothing
    // shadows the persist link. Without this, the refusal above could be caused
    // by `:fork` being broken rather than by the collision.
    h.write_project("[[tools]]\nname = \"aider\"\ncommand = \"/bin/echo\"\ncredentials = []\npersist = [\"other\"]\n");
    let accepted = h.launch(&[], "aider", &[]);
    let accepted_stderr = stderr_of(&accepted);
    assert!(
        accepted_stderr.contains(&initialized_fork(&src.display().to_string())),
        "the control must publish the fork: {accepted_stderr}"
    );
    assert_eq!(h.fork_dirs().len(), 1);
}

/// The same refusal under `--root`, where the guest home is `/root` and the
/// collision target is a config-declared `/root/code`.
#[test]
fn a_root_mode_config_fork_shadowing_a_persist_path_is_refused_before_any_fork() {
    let h = Harness::new();
    h.write_project(PERSIST_CODE);
    let src = h.home_root.join("src");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("seed"), "seed").unwrap();
    h.write_user("mounts = [\"~/src:/root/code:fork\"]\n");

    let before = h.snapshot();
    let out = h.launch(&["--root"], "aider", &[]);
    let stderr = stderr_of(&out);
    assert_eq!(
        stderr.lines().next().unwrap_or_default(),
        persist_collision_message("/root"),
        "{stderr}"
    );
    h.assert_refused_before_launch_state(&out, &before, "would collide with the guest mount point");
    assert!(h.mount_store().is_none());
}

/// Config provenance is not part of fork identity: a `--mount` and a config
/// declaration that expand to the same spelling and guest are one fork, and the
/// committed copy is reused after its source disappears.
#[test]
fn cli_then_config_equivalent_fork_reuses_one_store() {
    let h = Harness::new();
    let src = h.home_root.join("src");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("seed"), "seed").unwrap();

    let seeded = h.launch(
        &["--mount", &format!("{}:/f:fork", src.display())],
        "shell",
        &[],
    );
    let seeded_stderr = stderr_of(&seeded);
    assert!(
        seeded_stderr.contains("==> Initialized fork"),
        "{seeded_stderr}"
    );
    let committed = only_fork_data(&h);
    let seeded_binds = bind_mounts(&debug_config_json(&seeded_stderr));
    assert!(
        seeded_binds
            .iter()
            .any(|(host, guest, _)| { Path::new(host) == committed && guest == "/f" }),
        "the CLI declaration must bind the committed copy: {seeded_binds:?}"
    );

    std::fs::remove_file(src.join("seed")).unwrap();
    std::fs::remove_dir(&src).unwrap();
    h.write_user("mounts = [\"~/src:/f:fork\"]\n");
    let reused = h.launch(&[], "shell", &[]);
    let stderr = stderr_of(&reused);
    assert!(stderr.contains("==> Reusing fork"), "{stderr}");
    let binds = bind_mounts(&debug_config_json(&stderr));
    assert!(
        binds
            .iter()
            .any(|(host, guest, _)| Path::new(host) == committed && guest == "/f"),
        "the config declaration must reuse the same committed copy: {binds:?}"
    );
    assert_eq!(
        h.fork_dirs(),
        vec![committed.parent().unwrap().to_path_buf()],
        "one project-scoped fork, not two"
    );
}

/// A config fork stays reusable after its original source is removed: READY
/// wins over a vanished source.
#[test]
fn config_fork_is_reused_after_its_source_is_removed() {
    let h = Harness::new();
    let src = h.home_root.join("src");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("seed"), "seed").unwrap();
    h.write_user("mounts = [\"~/src:/f:fork\"]\n");

    let seeded = h.launch(&[], "shell", &[]);
    let seeded_stderr = stderr_of(&seeded);
    assert!(
        seeded_stderr.contains(&initialized_fork(&src.display().to_string())),
        "{seeded_stderr}"
    );
    let committed = only_fork_data(&h);
    assert_eq!(
        std::fs::read_to_string(committed.join("seed")).unwrap(),
        "seed"
    );

    std::fs::remove_file(src.join("seed")).unwrap();
    std::fs::remove_dir(&src).unwrap();
    let reused = h.launch(&[], "shell", &[]);
    let stderr = stderr_of(&reused);
    assert!(stderr.contains("==> Reusing fork"), "{stderr}");
    let binds = bind_mounts(&debug_config_json(&stderr));
    assert!(
        binds
            .iter()
            .any(|(host, guest, _)| Path::new(host) == committed && guest == "/f"),
        "{binds:?}"
    );
    assert!(!src.exists(), "the source stays gone");
}

/// `~/` expansion is a literal concatenation of the captured `$HOME`, so the
/// fork identity depends on the spelling the user's shell had — not on a
/// canonicalized path. A canonical spelling is therefore a *different* fork.
#[test]
fn config_fork_identity_keeps_the_home_spelling() {
    let h = Harness::new();
    let src = h.home_root.join("src");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("seed"), "seed").unwrap();
    h.write_user("mounts = [\"~/src:/f:fork\"]\n");

    let alias_parent = tempfile::tempdir_in(support::workspace_tmpdir()).unwrap();
    let alias = alias_parent
        .path()
        .canonicalize()
        .unwrap()
        .join("home-alias");
    std::os::unix::fs::symlink(&h.home_root, &alias).unwrap();

    let out = h.launch_with_home(&alias, &[], "shell", &[]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(&initialized_fork(&format!("{}/src", alias.display()))),
        "the notice must keep the expanded spelling: {stderr}"
    );
    let manifest = |fork: &Path| -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(fork.join("manifest.json")).unwrap()).unwrap()
    };
    let forks = h.fork_dirs();
    assert_eq!(forks.len(), 1, "{forks:?}");
    let expanded = format!("{}/src", alias.display());
    assert_eq!(
        manifest(&forks[0])["source"],
        expanded,
        "the manifest records the literal expanded spelling, never the canonical one"
    );

    // The canonical spelling is a different declaration, hence a different fork.
    let out = h.launch_with_home(
        &alias,
        &[
            "--no-config-mounts",
            "--mount",
            &format!("{}:/f:fork", src.display()),
        ],
        "shell",
        &[],
    );
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("==> Initialized fork"),
        "the canonical spelling must seed its own fork: {stderr}"
    );
    let forks = h.fork_dirs();
    assert_eq!(forks.len(), 2, "{forks:?}");
    let canonical = src.display().to_string();
    let sources: Vec<String> = forks
        .iter()
        .map(|fork| manifest(fork)["source"].as_str().unwrap().to_string())
        .collect();
    assert!(
        sources.contains(&expanded) && sources.contains(&canonical),
        "both spellings keep their own identity: {sources:?}"
    );
}

// ---------------------------------------------------------------------------
// Source availability: selected fails, suppressed cannot block
// ---------------------------------------------------------------------------

/// A selected declaration whose source is missing fails in mount preparation,
/// naming the file it came from — never silently skipped.
#[test]
fn a_selected_missing_config_source_fails_before_state() {
    let h = Harness::new();
    h.write_user("mounts = [\"~/missing:ro\"]\n");
    let missing = h.home_root.join("missing");
    let before = h.snapshot();
    let out = h.launch(&[], "shell", &[]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(&format!(
            "preparing mounts (including mounts from \"{}\"; --no-config-mounts skips them)",
            h.user_config().display()
        )),
        "the refusal must name the file the declaration came from: {stderr}"
    );
    assert!(
        stderr.contains(&missing.display().to_string()),
        "the refusal must name the missing source: {stderr}"
    );
    h.assert_refused_before_launch_state(&out, &before, &config_declaration(&h, 0));
    assert!(h.mount_store().is_none());
}

/// The same missing source is harmless when the declaration is suppressed: the
/// config never stats a mount source, so an unselected one cannot block a
/// launch, `doctor` or `--help`.
#[test]
fn opt_out_ignores_an_unused_missing_config_source() {
    let h = Harness::new();
    h.write_user("mounts = [\"~/missing:ro\"]\n");
    let out = h.launch(&["--no-config-mounts"], "shell", &[]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(CONFIG_MARKER),
        "an unselected missing source must not block the launch: {stderr}"
    );
    assert!(
        stderr.contains(&format!(
            "==> Config mounts: skipped 1 from \"{}\" (--no-config-mounts)",
            h.user_config().display()
        )),
        "{stderr}"
    );
    // Boot-free built-ins read the config but never select a mount.
    let doctor = h.doctor();
    assert!(
        doctor.status.success(),
        "doctor must ignore an unselected missing source: {}",
        stderr_of(&doctor)
    );
    let help = h.help();
    assert!(
        help.status.success(),
        "help must ignore an unselected missing source: {}",
        stderr_of(&help)
    );
}

// ---------------------------------------------------------------------------
// The opt-out's limits: everything except automatic mount selection stays
// ---------------------------------------------------------------------------

/// `--no-config-mounts` drops only the config declarations. Explicit
/// `--mount`, the core state/home/project binds and the persisted-path links
/// are unchanged.
#[test]
fn opt_out_keeps_cli_core_and_persisted_paths() {
    let h = Harness::new();
    let a = seed_source(&h, "a");
    let b = seed_source(&h, "b");
    h.write_user("mounts = [\"~/a:ro\"]\n");
    h.write_project(
        "[[tools]]\nname = \"aider\"\ncommand = \"/bin/echo\"\ncredentials = []\npersist = [\"code\"]\n",
    );

    let out = h.launch(
        &[
            "--no-config-mounts",
            "--mount",
            &format!("{}:/b", b.display()),
        ],
        "aider",
        &[],
    );
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(&format!(
            "==> Config mounts: skipped 1 from \"{}\" (--no-config-mounts)",
            h.user_config().display()
        )),
        "{stderr}"
    );
    let binds = bind_mounts(&debug_config_json(&stderr));
    let state = state_dir(&stderr);
    assert!(
        binds
            .iter()
            .any(|(host, guest, readonly)| host == &b.display().to_string()
                && guest == "/b"
                && !*readonly),
        "the explicit --mount must still apply: {binds:?}"
    );
    assert!(
        !binds
            .iter()
            .any(|(host, _, _)| host == &a.display().to_string()),
        "the config declaration must be absent: {binds:?}"
    );
    for (host, guest) in [
        (state.clone(), PathBuf::from("/agent-vm-state")),
        (state.join("home"), h.home_root.clone()),
        (h.project_root.clone(), h.project_root.clone()),
    ] {
        assert!(
            binds
                .iter()
                .any(|(b_host, b_guest, _)| *b_host == host.display().to_string()
                    && *b_guest == guest.display().to_string()),
            "the core bind {host:?} -> {guest:?} must survive the opt-out: {binds:?}"
        );
    }
    let link = state.join("home/code");
    assert_eq!(
        std::fs::read_link(&link).unwrap(),
        PathBuf::from("/agent-vm-state/persist/code"),
        "the persisted-path link must survive the opt-out"
    );
}

/// Write `~/.config/agent-vm/credentials.yaml` with the loader's 0600 mode.
fn write_credentials(h: &Harness, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    let path = h.home_root.join(".config/agent-vm/credentials.yaml");
    write_file(&path, body);
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

const MY_SERVICE_YAML: &str = "\
credentials:
  - service: my-service
    apiKey:
      name: MY_SERVICE_KEY
      sentinelEnv: true
      inject: [{domain: api.my-service.example, header: x-api-key, format: \"%s\"}]
";

/// The opt-out skips mount preparation only: a requested credential is still
/// resolved into a header-credential entry, and a *missing* authorization still
/// fails the launch.
#[test]
fn opt_out_keeps_requested_credentials() {
    let h = Harness::new();
    seed_source(&h, "a");
    h.write_user("mounts = [\"~/a:ro\"]\n");
    h.write_project(
        "[[tools]]\nname = \"t\"\ncommand = \"/bin/true\"\ncredentials = [\"my-service\"]\n",
    );
    write_credentials(&h, MY_SERVICE_YAML);

    let out = h.launch_with_env(
        &["--no-config-mounts"],
        "t",
        &[],
        // The debug-only seam the credential loader reads in a boot-free
        // harness: a synthetic value, never a real host credential.
        &[("AGENT_VM_TEST_CREDENTIAL", "my-service=synthetic")],
    );
    let stderr = stderr_of(&out);
    let config = debug_config_json(&stderr);
    let references: Vec<&str> = config["network"]["secrets"]["header_credentials"]
        .as_array()
        .expect("header_credentials must be an array")
        .iter()
        .map(|entry| entry["reference"].as_str().expect("reference"))
        .collect();
    assert!(
        references.contains(&"my-service"),
        "the requested credential must still be resolved under the opt-out: {references:?}\n{stderr}"
    );

    // Negative: without the authorization entry the same launch fails, naming
    // the service and the file — the opt-out does not turn credential checks
    // off.
    std::fs::remove_file(h.home_root.join(".config/agent-vm/credentials.yaml")).unwrap();
    let out = h.launch_with_env(
        &["--no-config-mounts"],
        "t",
        &[],
        // The debug-only seam the credential loader reads in a boot-free
        // harness: a synthetic value, never a real host credential.
        &[("AGENT_VM_TEST_CREDENTIAL", "my-service=synthetic")],
    );
    let stderr = stderr_of(&out);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains("my-service") && stderr.contains("credentials.yaml"),
        "the missing authorization must be reported: {stderr}"
    );
    assert!(!stderr.contains(CONFIG_MARKER), "{stderr}");
}

/// Persisted `[network]` authority is not mount selection: the opt-out keeps
/// the grants, and the verified-read policy still covers both fields.
#[test]
fn opt_out_keeps_persisted_network_grants() {
    let body = "mounts = [\"~/a:ro\"]\n[network]\nallow_host = true\n";
    let h = Harness::new();
    seed_source(&h, "a");
    h.write_user(body);
    let out = h.launch(&["--no-config-mounts"], "shell", &[]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("==> Egress authority: persisted grants"),
        "the opt-out must not drop persisted network grants: {stderr}"
    );

    // The same file through a final-component symlink is refused, and the
    // subject names both fields the file now carries.
    let h = Harness::new();
    seed_source(&h, "a");
    let target = h.home_root.join("dotfiles/config.toml");
    write_file(&target, body);
    h.symlink_user_config(&target);
    let before = h.snapshot();
    let out = h.launch(&["--no-config-mounts"], "shell", &[]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("[network] and mounts requires config.toml to be a regular file"),
        "{stderr}"
    );
    h.assert_refused_before_launch_state(
        &out,
        &before,
        "[network] and mounts requires config.toml to be a regular file",
    );
}

/// The opt-out skips *selection*; it cannot skip the config load. A broken or
/// untrusted `mounts` file fails every route with the config error — never an
/// "unrecognized subcommand" failure.
#[test]
fn opt_out_does_not_bypass_an_untrusted_or_broken_mounts_config() {
    // Untrusted: presence-bearing bytes reached through a final symlink.
    let h = Harness::new();
    let target = h.home_root.join("dotfiles/config.toml");
    write_file(&target, "mounts = [\"~/a:ro\"]\n");
    h.symlink_user_config(&target);
    for (verb, args) in [("shell", vec![]), ("run", vec!["true"])] {
        let out = h.launch(&["--no-config-mounts"], verb, &args);
        let stderr = stderr_of(&out);
        assert!(!out.status.success(), "{verb}: {stderr}");
        assert!(
            stderr.contains("mounts requires config.toml to be a regular file"),
            "{verb}: {stderr}"
        );
        assert!(
            !stderr.contains("unrecognized subcommand"),
            "{verb}: the config error must not become a CLI dispatch error: {stderr}"
        );
    }

    // Broken: a schema error at the declaration list.
    let h = Harness::new();
    h.write_user("mounts = [1]\n");
    for (verb, args) in [("shell", vec![]), ("run", vec!["true"])] {
        let out = h.launch(&["--no-config-mounts"], verb, &args);
        let stderr = stderr_of(&out);
        assert!(!out.status.success(), "{verb}: {stderr}");
        assert!(
            stderr.contains("mounts[0]: must be a string"),
            "{verb}: {stderr}"
        );
        assert!(
            stderr.contains(&h.user_config().display().to_string()),
            "{verb}: the file must be named: {stderr}"
        );
        assert!(
            !stderr.contains("unrecognized subcommand"),
            "{verb}: {stderr}"
        );
    }
}

// ---------------------------------------------------------------------------
// Routes, flag placement, and the unchanged catalog
// ---------------------------------------------------------------------------

/// `--no-config-mounts` after the tool verb is a tool argument, forwarded
/// verbatim: the config mounts still apply.
#[test]
fn opt_out_after_the_verb_is_a_tool_argument() {
    let h = Harness::new();
    let a = seed_source(&h, "a");
    h.write_user("mounts = [\"~/a:ro\"]\n");

    let out = h.launch(&[], "shell", &["--no-config-mounts"]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(&config_notice(&h, 1)),
        "a post-verb flag is not the launch option: {stderr}"
    );
    let command = guest_command(&stderr);
    assert!(
        command.ends_with("-c '--no-config-mounts'"),
        "the flag must be forwarded to the tool verbatim, saw {command:?}"
    );
    let binds = bind_mounts(&debug_config_json(&stderr));
    assert!(
        binds
            .iter()
            .any(|(host, _, _)| host == &a.display().to_string()),
        "the config mount must still apply: {binds:?}"
    );
}

/// The direct route (`run PROG` and `-- PROG`) selects config mounts exactly
/// like a tool verb, and the flag suppresses them there too.
#[test]
fn config_mounts_apply_to_direct_commands() {
    let h = Harness::new();
    let a = seed_source(&h, "a");
    h.write_user("mounts = [\"~/a:ro\"]\n");

    for verb in ["run", "--"] {
        let out = h.launch(&[], verb, &["true"]);
        let stderr = stderr_of(&out);
        assert_eq!(guest_command(&stderr), "true", "{verb}: {stderr}");
        let binds = bind_mounts(&debug_config_json(&stderr));
        assert!(
            binds
                .iter()
                .any(|(host, _, _)| host == &a.display().to_string()),
            "{verb}: the config mount must reach a direct launch: {binds:?}"
        );
    }

    let out = h.launch(&["--no-config-mounts"], "run", &["true"]);
    let stderr = stderr_of(&out);
    let binds = bind_mounts(&debug_config_json(&stderr));
    assert!(
        !binds
            .iter()
            .any(|(host, _, _)| host == &a.display().to_string()),
        "the flag must suppress config mounts on the direct route too: {binds:?}"
    );
}

/// TOML scopes a key to the most recent table header, so a `mounts` written
/// after `[network]` lands in that table. The refusal says exactly that instead
/// of accepting the list as network configuration.
#[test]
fn mounts_after_a_network_header_is_refused_with_a_hint() {
    let h = Harness::new();
    h.write_user("[network]\nallow_host = true\nmounts = []\n");
    let before = h.snapshot();
    let out = h.launch(&[], "shell", &[]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(
            "[network]: mounts is not a network setting; a top-level mounts list must be \
             written before the first table header"
        ),
        "{stderr}"
    );
    h.assert_refused_before_launch_state(&out, &before, "is not a network setting");
    // The hint survives the opt-out: the file never loaded, so there is nothing
    // to skip.
    let out = h.launch(&["--no-config-mounts"], "shell", &[]);
    assert!(
        stderr_of(&out).contains("is not a network setting"),
        "{}",
        stderr_of(&out)
    );
}

/// The seven shipped tools plus the `shell` fallback: a `mounts`-only user file
/// declares no tools, so the default catalog stands.
const SHIPPED_TOOLS: [&str; 7] = [
    "dsh", "pi", "codex", "opencode", "claude", "copilot", "shell",
];

/// A config that only selects mounts must not disturb the default catalog.
#[test]
fn a_mounts_only_user_config_keeps_the_shipped_tools() {
    let h = Harness::new();
    seed_source(&h, "a");
    h.write_user("mounts = [\"~/a:ro\"]\n");

    let help = h.help();
    assert!(help.status.success(), "{}", stderr_of(&help));
    let help_text = String::from_utf8_lossy(&help.stdout).into_owned();
    for tool in SHIPPED_TOOLS {
        assert!(
            help_text.contains(&format!("\n  {tool} ")),
            "the mounts-only config changed the help catalog, {tool:?} missing:\n{help_text}"
        );
    }

    let doctor = h.doctor();
    assert!(doctor.status.success(), "{}", stderr_of(&doctor));
    let doctor_text = String::from_utf8_lossy(&doctor.stdout).into_owned();
    for tool in SHIPPED_TOOLS {
        assert!(
            doctor_text.contains(&format!("{tool} -> ")),
            "doctor must resolve the shipped {tool:?}:\n{doctor_text}"
        );
    }
}

/// The selection is not limited to built-ins: config mounts reach a
/// project-declared tool and `shell` alike.
#[test]
fn config_mounts_reach_project_tools_and_shell() {
    let h = Harness::new();
    let a = seed_source(&h, "a");
    h.write_user("mounts = [\"~/a:ro\"]\n");
    h.write_project("[[tools]]\nname = \"probe\"\ncommand = \"/bin/probe\"\ncredentials = []\n");

    for verb in ["probe", "shell"] {
        let out = h.launch(&[], verb, &[]);
        let stderr = stderr_of(&out);
        let binds = bind_mounts(&debug_config_json(&stderr));
        assert!(
            binds
                .iter()
                .any(|(host, guest, readonly)| host == &a.display().to_string()
                    && *guest == a.display().to_string()
                    && *readonly),
            "{verb}: the config mount must reach this verb: {binds:?}"
        );
    }
}

/// A project file may not grant mounts, empty or not, and a project file that
/// tries to grant both network and mounts keeps today's `[network]` refusal.
#[test]
fn project_mounts_fail_every_launch() {
    let h = Harness::new();
    for (verb, args) in [("shell", vec![]), ("run", vec!["true"])] {
        h.write_project("mounts = []\n");
        let out = h.launch(&[], verb, &args);
        let stderr = stderr_of(&out);
        assert!(!out.status.success(), "{verb}: {stderr}");
        assert!(
            stderr.contains(&format!(
                "config: \"{}\": mounts cannot be declared by the project config",
                h.project_config().display()
            )),
            "{verb}: {stderr}"
        );
        assert!(
            !stderr.contains("unrecognized subcommand"),
            "{verb}: {stderr}"
        );
    }

    // `[network]` is checked first, so a file declaring both keeps the network
    // bytes this release already shipped.
    h.write_project("mounts = []\n[network]\nallow_host = true\n");
    let out = h.launch(&[], "shell", &[]);
    let stderr = stderr_of(&out);
    assert!(
        stderr
            .contains("network.allow_host: network access cannot be granted by the project config"),
        "{stderr}"
    );
    assert!(!stderr.contains("mounts cannot be declared"), "{stderr}");
}

/// A broken `mounts` config is a deferred catalog error: every launch route and
/// `doctor` reports it, and `help` still works.
#[test]
fn broken_mounts_config_reports_through_launch_and_doctor() {
    let h = Harness::new();
    h.write_user("mounts = [1]\n");
    let expected = format!(
        "config: \"{}\": mounts[0]: must be a string",
        h.user_config().display()
    );

    let out = h.launch(&[], "shell", &[]);
    let stderr = stderr_of(&out);
    assert!(!out.status.success(), "{stderr}");
    assert!(stderr.contains(&expected), "{stderr}");
    assert!(!stderr.contains("unrecognized subcommand"), "{stderr}");

    for verb in ["run", "--"] {
        let out = h.launch(&[], verb, &["true"]);
        assert_eq!(
            out.status.code(),
            Some(125),
            "{verb}: a direct launch reports configuration usage as 125: {}",
            stderr_of(&out)
        );
        assert!(stderr_of(&out).contains(&expected), "{}", stderr_of(&out));
    }

    let doctor = h.doctor();
    assert!(
        !doctor.status.success(),
        "doctor must report the broken config"
    );
    let doctor_text = String::from_utf8_lossy(&doctor.stdout).into_owned();
    assert!(
        doctor_text.contains("==> tool configuration"),
        "doctor must render the error under tool configuration:\n{doctor_text}"
    );
    assert!(doctor_text.contains(&expected), "{doctor_text}");
    assert!(
        stderr_of(&doctor).contains(&expected),
        "{}",
        stderr_of(&doctor)
    );

    let help = h.help();
    assert!(
        help.status.success(),
        "help must stay available under a broken config: {}",
        stderr_of(&help)
    );
}

// ---------------------------------------------------------------------------
// Named mount sets (#397 / ADR-0048)
// ---------------------------------------------------------------------------

/// How a launch-time refusal names entry `index` of the user set `set`: the same
/// attribution a config entry gets, with the set's escaped name in place of the
/// `mounts[N]` index.
fn set_declaration(h: &Harness, set: &str, index: usize) -> String {
    format!(
        "mount_sets[\"{set}\"][{index}] in \"{}\"",
        h.user_config().display()
    )
}

/// The `[mount_sets]` body the rows below share: one set per mode, an outer set
/// that composes them, and a repeated reference.
const SETS_BODY: &str = "\
[mount_sets]
ro-set = [\"~/ro:/ro:ro\"]
rw-set = [\"~/rw:/rw:rw\"]
fork-set = [\"~/fork:/fork:fork\"]
all-set = [\"ro-set\", \"rw-set\", \"fork-set\", \"ro-set\"]
";

/// A `mounts`/`[mount_sets]` document: the defaults line must precede the table.
fn with_defaults(defaults: &str) -> String {
    format!("mounts = [{defaults}]\n{SETS_BODY}")
}

/// Seed `$HOME/{ro,rw,fork}` so each declared set has a real source.
fn seed_set_sources(h: &Harness) {
    for name in ["ro", "rw", "fork"] {
        let path = seed_source(h, name);
        std::fs::write(path.join("marker"), format!("seed-{name}")).unwrap();
    }
}

/// Definitions alone mount nothing. The differential control is the same launch
/// with no user config at all, so "declaring a set starts access" would show up
/// as an extra bind rather than as an assertion about notices.
#[test]
fn named_mount_sets_definitions_alone_select_nothing() {
    let h = Harness::new();
    seed_set_sources(&h);
    h.write_user(SETS_BODY);
    let declared = stderr_of(&h.launch(&[], "shell", &[]));
    assert!(
        declared.contains(CONFIG_MARKER),
        "a sets-only file must still launch: {declared}"
    );
    assert!(
        !declared.contains("==> Config mounts:"),
        "definitions select nothing, so there is no count to report: {declared}"
    );
    let with_sets = sorted_binds(&debug_config_json(&declared));

    std::fs::remove_file(h.user_config()).unwrap();
    let without = stderr_of(&h.launch(&[], "shell", &[]));
    assert_eq!(
        with_sets,
        sorted_binds(&debug_config_json(&without)),
        "declaring [mount_sets] must add no bind at all"
    );
}

/// A defaults entry names a set, and a set may name sets declared after it: the
/// selected leaves are exactly the declared hosts, guests and modes.
#[test]
fn named_mount_sets_defaults_select_forward_and_nested_names() {
    let h = Harness::new();
    seed_set_sources(&h);
    h.write_user(&with_defaults("\"all-set\""));

    let stderr = stderr_of(&h.launch(&[], "shell", &[]));
    let binds = bind_mounts(&debug_config_json(&stderr));
    let home = h.home_root.display().to_string();
    for (name, guest, readonly) in [("ro", "/ro", true), ("rw", "/rw", false)] {
        let host = format!("{home}/{name}");
        assert!(
            binds
                .iter()
                .any(|(bind_host, bind_guest, ro)| bind_host == &host
                    && bind_guest == guest
                    && *ro == readonly),
            "{name} must be bound at {guest} with readonly={readonly}: {binds:?}"
        );
    }
    // The fork leaf binds the committed copy, not the source.
    let fork = only_fork_data(&h);
    assert!(
        binds
            .iter()
            .any(|(host, guest, _)| Path::new(host) == fork && guest == "/fork"),
        "the fork leaf must bind its committed copy: {binds:?}"
    );
    // Three declared leaves, one per set; the repeated reference adds nothing.
    assert!(
        stderr.contains(&config_notice(&h, 3)),
        "the notice counts claimed leaves: {stderr}"
    );
}

/// `--no-config-mounts` withholds the defaults and nothing else: an explicit set
/// name still selects that same set, and no unrelated default rides along.
#[test]
fn named_mount_sets_opt_out_keeps_an_explicit_selection() {
    let h = Harness::new();
    seed_set_sources(&h);
    h.write_user(&with_defaults("\"rw-set\""));
    // Positive control first: the defaults select `rw`.
    let automatic = stderr_of(&h.launch(&[], "shell", &[]));
    assert!(
        bind_mounts(&debug_config_json(&automatic))
            .iter()
            .any(|(_, guest, _)| guest == "/rw"),
        "the control must select the default set: {automatic}"
    );

    let stderr = stderr_of(&h.launch(&["--no-config-mounts", "--mount", "all-set"], "shell", &[]));
    let binds = bind_mounts(&debug_config_json(&stderr));
    let home = h.home_root.display().to_string();
    for (name, guest) in [("ro", "/ro"), ("rw", "/rw")] {
        assert!(
            binds
                .iter()
                .any(|(host, bind_guest, _)| host == &format!("{home}/{name}")
                    && bind_guest == guest),
            "the explicitly selected set must still apply: {binds:?}"
        );
    }
    assert!(
        stderr.contains("skipped 1 from"),
        "the skipped defaults are still reported: {stderr}"
    );
    // The context says which half the opt-out skips, and never claims it removes
    // the explicit selection.
    assert!(
        !stderr.contains("--no-config-mounts skips them"),
        "{stderr}"
    );
}

/// A `[mount_sets]`-only file is authority-bearing by presence: an untrusted file
/// that declares nothing but an empty table is refused before any launch state,
/// exactly as `mounts = []` is.
#[test]
fn named_mount_sets_unsafe_file_is_refused_before_launch_state() {
    for body in [
        "[mount_sets]\n",
        "[mount_sets]\nagent = []\n",
        "mount_sets = 7\n",
    ] {
        let h = Harness::new();
        h.write_user_mode(body, 0o664);
        let before = h.snapshot();
        let out = h.launch(&[], "shell", &[]);
        let stderr = stderr_of(&out);
        assert!(
            stderr.contains("[mount_sets] refuses a group- or other-writable config.toml"),
            "{body}: {stderr}"
        );
        h.assert_refused_before_launch_state(&out, &before, "[mount_sets]");
    }
    // The compatibility control: the same file with no authority-bearing field is
    // accepted, so the refusal above is about the table and not about the mode.
    let h = Harness::new();
    h.write_user_mode("[[tools]]\nname = \"t\"\ncommand = \"/bin/echo\"\n", 0o664);
    let stderr = stderr_of(&h.launch(&[], "t", &[]));
    assert!(stderr.contains(CONFIG_MARKER), "{stderr}");
}

/// A bare name is an exact user-set lookup: an existing cwd directory of that
/// name and a project tool of that name change nothing, and nothing falls back to
/// a relative path or a directory.
#[test]
fn named_mount_sets_unknown_names_never_fall_back() {
    let h = Harness::new();
    // Both plausible fallbacks exist: a cwd directory called `agent`, and a tool
    // called `agent`.
    std::fs::create_dir(h.project_root.join("agent")).unwrap();
    h.write_project("[[tools]]\nname = \"agent\"\ncommand = \"/bin/echo\"\ncredentials = []\n");
    h.write_user("[mount_sets]\nother = []\n");

    let before = h.snapshot();
    let out = h.launch(&["--mount", "agent"], "shell", &[]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(&format!(
            "mount set \"agent\" is not defined by any [mount_sets] in \"{}\"",
            h.user_config().display()
        )),
        "{stderr}"
    );
    h.assert_refused_before_launch_state(&out, &before, "parsing --mount");

    // Positive control: the definition that *does* exist is selected by name.
    seed_set_sources(&h);
    h.write_user(&with_defaults("\"all-set\""));
    let stderr = stderr_of(&h.launch(&["--no-config-mounts", "--mount", "all-set"], "shell", &[]));
    assert!(
        bind_mounts(&debug_config_json(&stderr))
            .iter()
            .any(|(_, guest, _)| guest == "/ro"),
        "a declared set resolves by name: {stderr}"
    );
}

/// A per-selection modifier is refused for a name that exists and for one that
/// does not: `agent:ro` is never a modified set, and never a relative path.
#[test]
fn named_mount_sets_refuse_per_selection_modifiers() {
    let h = Harness::new();
    seed_set_sources(&h);
    h.write_user(SETS_BODY);
    for (selection, needle) in [
        ("ro-set:ro", "a mount-set name is a bare name"),
        ("all-set:fork", "a mount-set name is a bare name"),
        ("all-set:/guest", "a mount-set name is a bare name"),
        ("all-set:exclude=x", "a mount-set name is a bare name"),
        ("unknown:ro", "a mount-set name is a bare name"),
    ] {
        let before = h.snapshot();
        let out = h.launch(&["--mount", selection], "shell", &[]);
        let stderr = stderr_of(&out);
        assert!(stderr.contains(needle), "{selection}: {stderr}");
        h.assert_refused_before_launch_state(&out, &before, "parsing --mount");
    }
    // An ordinary absolute path keeps the historical grammar, `:ro` and all.
    let stderr = stderr_of(&h.launch(
        &[
            "--no-config-mounts",
            "--mount",
            &format!("{}:/abs:ro", h.home_root.join("ro").display()),
        ],
        "shell",
        &[],
    ));
    assert!(
        bind_mounts(&debug_config_json(&stderr))
            .iter()
            .any(|(_, guest, readonly)| guest == "/abs" && *readonly),
        "{stderr}"
    );
}

/// Every reference error is a load error: unknown names and set-reference cycles
/// are refused even in a set nothing selects and even under the opt-out, while
/// `doctor` reports them and `--help` stays usable.
#[test]
fn named_mount_sets_reference_errors_refuse_load_under_every_option() {
    for (body, needle) in [
        (
            "mounts = [\"nope\"]\n[mount_sets]\nunused = []\n",
            "mounts[0]: unknown mount set name",
        ),
        (
            "[mount_sets]\nunused = [\"nope\"]\n",
            "mount_sets[0][0]: unknown mount set name",
        ),
        (
            "[mount_sets]\na = [\"a\"]\n",
            "mount_sets[0][0]: mount-set reference cycle",
        ),
        (
            "[mount_sets]\na = [\"b\"]\nb = [\"a\"]\n",
            "mount_sets[1][0]: mount-set reference cycle",
        ),
        (
            "[mount_sets]\nisland = [\"island\"]\nroot = []\n",
            "mount_sets[0][0]: mount-set reference cycle",
        ),
    ] {
        let h = Harness::new();
        h.write_user(body);
        for options in [vec![], vec!["--no-config-mounts"]] {
            let before = h.snapshot();
            let out = h.launch(&options, "shell", &[]);
            let stderr = stderr_of(&out);
            assert!(stderr.contains(needle), "{body}: {options:?}: {stderr}");
            assert!(
                stderr.contains(&h.user_config().display().to_string()),
                "{body}: the file must be named: {stderr}"
            );
            h.assert_refused_before_launch_state(&out, &before, needle);
        }
        let doctor = h.doctor();
        let text = String::from_utf8_lossy(&doctor.stdout).into_owned();
        assert!(
            text.contains(needle),
            "{body}: doctor must report it: {text}"
        );
        assert!(
            h.help().status.success(),
            "{body}: help must stay available"
        );
    }
}

/// The pathological one-new-leaf-per-set chain is refused by the load budget
/// rather than by a hang: the child never reaches builder wiring, in either
/// option set, and `doctor` reports the same limit.
///
/// The harness's 60-second subprocess bound is the regression: a per-closure
/// quadratic claim made this document cubic, so it could only be observed as a
/// hang before the bound existed.
#[test]
fn named_mount_sets_expansion_chain_refuses_before_state() {
    fn chain_document(length: usize) -> String {
        let mut body = String::from("[mount_sets]\n");
        for index in 0..length {
            if index + 1 < length {
                body.push_str(&format!(
                    "s{index:04} = [\"/h/{index:04}:/g/{index:04}:ro\", \"s{:04}\"]\n",
                    index + 1
                ));
            } else {
                body.push_str(&format!(
                    "s{index:04} = [\"/h/{index:04}:/g/{index:04}:ro\"]\n"
                ));
            }
        }
        body
    }
    const LIMIT: &str = "mount_sets: expansion work exceeds limit of 65536 leaf visits";

    let h = Harness::new();
    h.write_user(&chain_document(4_000));
    for options in [vec![], vec!["--no-config-mounts"]] {
        let before = h.snapshot();
        let out = h.launch(&options, "shell", &[]);
        let stderr = stderr_of(&out);
        assert!(stderr.contains(LIMIT), "{options:?}: {stderr}");
        h.assert_refused_before_launch_state(&out, &before, LIMIT);
    }
    let doctor = h.doctor();
    let text = String::from_utf8_lossy(&doctor.stdout).into_owned();
    assert!(text.contains(LIMIT), "doctor must report the limit: {text}");

    // Positive control: the same shape one leaf shorter than the budget loads.
    h.write_user(&chain_document(361));
    let stderr = stderr_of(&h.launch(&[], "shell", &[]));
    assert!(
        stderr.contains(CONFIG_MARKER),
        "a chain inside the budget must launch: {stderr}"
    );
}

/// Source availability is a question about *selected* mounts: an unused set may
/// name a path that does not exist, and selecting it fails at the usual
/// pre-preparation boundary.
#[test]
fn named_mount_sets_unused_missing_source_is_never_checked() {
    let h = Harness::new();
    seed_set_sources(&h);
    let missing = h.home_root.join("absent");
    h.write_user(&format!(
        "{SETS_BODY}absent-set = [\"~/absent:/absent:ro\"]\nmissing-set = [\"{}:/missing:ro\"]\n",
        missing.display()
    ));
    let stderr = stderr_of(&h.launch(&["--mount", "ro-set"], "shell", &[]));
    assert!(
        stderr.contains(CONFIG_MARKER),
        "an unselected set's missing source must not block the launch: {stderr}"
    );
    assert!(
        !bind_mounts(&debug_config_json(&stderr))
            .iter()
            .any(|(_, guest, _)| guest == "/absent" || guest == "/missing"),
        "{stderr}"
    );

    for name in ["absent-set", "missing-set"] {
        let before = h.snapshot();
        let out = h.launch(&["--mount", name], "shell", &[]);
        let stderr = stderr_of(&out);
        assert!(!out.status.success(), "{name}: {stderr}");
        h.assert_refused_before_launch_state(&out, &before, "canonicalizing");
        assert!(
            stderr.contains(&format!("mount_sets[\"{name}\"][0]")),
            "{name}: the refusing declaration must be named: {stderr}"
        );
    }
}

/// Repeated names, a set named twice and a shared nested set all reach exactly
/// one bind per declaration.
#[test]
fn named_mount_sets_duplicate_selections_bind_once() {
    let h = Harness::new();
    seed_set_sources(&h);
    h.write_user(&format!(
        "mounts = [\"all-set\", \"ro-set\", \"all-set\"]\n{SETS_BODY}"
    ));
    let stderr = stderr_of(&h.launch(&["--mount", "all-set", "--mount", "ro-set"], "shell", &[]));
    let binds = bind_mounts(&debug_config_json(&stderr));
    for guest in ["/ro", "/rw", "/fork"] {
        let count = binds.iter().filter(|(_, bind, _)| bind == guest).count();
        assert_eq!(count, 1, "{guest} must be bound once: {binds:?}");
    }
}

/// Conflicting declarations are refused in both orders and across all three
/// sources: defaults versus set, set versus set, and explicit CLI versus set.
#[test]
fn named_mount_sets_conflicts_are_refused_in_both_orders() {
    let h = Harness::new();
    let a = seed_source(&h, "a");
    let b = seed_source(&h, "b");
    let conflict = |body: &str, options: &[&str]| {
        let h2 = Harness::new();
        seed_source(&h2, "a");
        seed_source(&h2, "b");
        h2.write_user(body);
        let before = h2.snapshot();
        let out = h2.launch(options, "shell", &[]);
        let stderr = stderr_of(&out);
        assert!(
            stderr.contains("claims the same guest path"),
            "{body}: {options:?}: {stderr}"
        );
        h2.assert_refused_before_launch_state(&out, &before, "claims the same guest path");
    };
    let _ = (&a, &b);
    // Defaults versus a selected set, both orders.
    conflict(
        "mounts = [\"~/a:/g:ro\", \"s\"]\n[mount_sets]\ns = [\"~/b:/g:ro\"]\n",
        &[],
    );
    conflict(
        "mounts = [\"s\", \"~/b:/g:rw\"]\n[mount_sets]\ns = [\"~/a:/g:ro\"]\n",
        &[],
    );
    // Set versus set, both orders.
    conflict(
        "mounts = [\"one\", \"two\"]\n[mount_sets]\none = [\"~/a:/g:ro\"]\ntwo = [\"~/b:/g:ro\"]\n",
        &[],
    );
    conflict(
        "mounts = [\"two\", \"one\"]\n[mount_sets]\none = [\"~/a:/g:ro\"]\ntwo = [\"~/b:/g:ro\"]\n",
        &[],
    );
    // Explicit CLI versus an explicitly selected set, both orders.
    for reversed in [false, true] {
        let h2 = Harness::new();
        let a = seed_source(&h2, "a");
        seed_source(&h2, "b");
        h2.write_user("[mount_sets]\ns = [\"~/b:/g:ro\"]\n");
        let direct = format!("{}:/g:ro", a.display());
        let argv: Vec<&str> = if reversed {
            vec!["--no-config-mounts", "--mount", "s", "--mount", &direct]
        } else {
            vec!["--no-config-mounts", "--mount", &direct, "--mount", "s"]
        };
        let before = h2.snapshot();
        let out = h2.launch(&argv, "shell", &[]);
        let stderr = stderr_of(&out);
        assert!(
            stderr.contains("guest path /g is claimed by different declarations"),
            "{argv:?}: {stderr}"
        );
        assert!(
            stderr.contains(&set_declaration(&h2, "s", 0)),
            "the set entry must be named: {stderr}"
        );
        h2.assert_refused_before_launch_state(&out, &before, "claimed by different declarations");
    }
}

/// A writable parent with a read-only child is an allowed topology, and the
/// child's own mode is what the guest sees. (This does not claim the read-only
/// child blocks writable aliases through its parent — it does not.)
#[test]
fn named_mount_sets_allow_a_readwrite_parent_with_a_readonly_child() {
    let h = Harness::new();
    let parent = seed_source(&h, "tree");
    let child = parent.join("child");
    std::fs::create_dir(&child).unwrap();
    std::fs::write(child.join("inner"), "inner").unwrap();
    h.write_user("[mount_sets]\ntree = [\"~/tree:/tree:rw\", \"~/tree/child:/tree/child:ro\"]\n");
    let stderr = stderr_of(&h.launch(&["--mount", "tree"], "shell", &[]));
    let binds = bind_mounts(&debug_config_json(&stderr));
    assert!(
        binds
            .iter()
            .any(|(host, guest, ro)| host == &parent.display().to_string()
                && guest == "/tree"
                && !*ro),
        "{binds:?}"
    );
    assert!(
        binds
            .iter()
            .any(|(host, guest, ro)| host == &child.display().to_string()
                && guest == "/tree/child"
                && *ro),
        "{binds:?}"
    );
}

/// Every shared protection applies to a set leaf exactly as to a direct config
/// entry, and the refusal names the set entry rather than `mounts[N]`.
#[test]
fn named_mount_sets_respect_the_shared_protections() {
    // A writable config-directory ancestor.
    let h = Harness::new();
    h.write_user("[mount_sets]\ncfg = [\"~/.config:rw\"]\n");
    let before = h.snapshot();
    let out = h.launch(&["--mount", "cfg"], "shell", &[]);
    h.assert_refused_before_launch_state(&out, &before, &set_declaration(&h, "cfg", 0));

    // A live bind of the host Pi credential file.
    let h = Harness::new();
    let auth = h.home_root.join(".pi/agent/auth.json");
    write_file(&auth, "{\"token\":\"host\"}");
    h.write_user("[mount_sets]\npi-live = [\"~/.pi:ro\"]\n");
    let before = h.snapshot();
    let out = h.launch(&["--mount", "pi-live"], "shell", &[]);
    h.assert_refused_before_launch_state(
        &out,
        &before,
        &format!(
            "would expose the host Pi credential file {}",
            auth.display()
        ),
    );

    // A writable regular file.
    let h = Harness::new();
    let file = h.home_root.join("bare");
    std::fs::write(&file, "bare").unwrap();
    h.write_user(&format!(
        "[mount_sets]\nfile = [\"~/bare:{}\"]\n",
        file.display()
    ));
    let before = h.snapshot();
    let out = h.launch(&["--mount", "file"], "shell", &[]);
    h.assert_refused_before_launch_state(&out, &before, "a file can only be mounted read-only");

    // An agent-vm core guest path: refused with set-specific advice, and never
    // the opt-out hint an explicit selection ignores.
    let h = Harness::new();
    seed_source(&h, "a");
    h.write_user("[mount_sets]\ncore = [\"~/a:/agent-vm-state:ro\"]\n");
    let before = h.snapshot();
    let out = h.launch(&["--mount", "core"], "shell", &[]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("collides with an agent-vm core mount"),
        "{stderr}"
    );
    assert!(
        stderr.contains("remove it from that mount set"),
        "an explicit set must not be told to use --no-config-mounts: {stderr}"
    );
    h.assert_refused_before_launch_state(&out, &before, &set_declaration(&h, "core", 0));

    // A fork shadowing a persisted guest-HOME link, refused before publication.
    let h = Harness::new();
    h.write_project(PERSIST_CODE);
    seed_source(&h, "src");
    h.write_user(&format!(
        "[mount_sets]\nfork = [\"~/src:{}/code:fork\"]\n",
        h.home_root.display()
    ));
    let before = h.snapshot();
    let out = h.launch(&["--mount", "fork"], "aider", &[]);
    assert_eq!(
        stderr_of(&out).lines().next().unwrap_or_default(),
        persist_collision_message(&h.home_root.display().to_string())
    );
    h.assert_refused_before_launch_state(&out, &before, "would collide with the guest mount point");
    assert!(h.mount_store().is_none());
}

/// Modes, follow-links and fork seed options belong to the paths inside a set and
/// keep their exact behaviour: an independent fork copy that honours `:exclude`
/// and omits the protected Pi files.
#[test]
fn named_mount_sets_keep_modes_follow_links_and_fork_seeding() {
    let h = Harness::new();
    let skills = h.home_root.join("skills");
    std::fs::create_dir_all(skills.join("real")).unwrap();
    std::fs::write(skills.join("real/marker"), "marker").unwrap();
    std::os::unix::fs::symlink("real", skills.join("link")).unwrap();
    let src = seed_excludable_source(&h);
    let pi = h.home_root.join(".pi");
    write_file(&pi.join("agent/auth.json"), "{\"token\":\"host-auth\"}");
    write_file(&pi.join("settings.json"), "{\"theme\":\"dark\"}");
    h.write_user(
        "[mount_sets]\n\
         skills = [\"~/skills:/skills:ro:follow-links\"]\n\
         seed = [\"~/src:/f:fork:exclude=hidden\"]\n\
         pi = [\"~/.pi:/pi-fork:fork\"]\n",
    );

    let stderr = stderr_of(&h.launch(&["--mount", "skills"], "shell", &[]));
    let binds = bind_mounts(&debug_config_json(&stderr));
    let real = skills.join("real").display().to_string();
    assert!(
        binds
            .iter()
            .any(|(host, guest, ro)| host == &real && guest == &real && *ro),
        "a follow-links target inside a set is discovered read-only: {binds:?}"
    );

    let stderr = stderr_of(&h.launch(&["--mount", "seed"], "shell", &[]));
    assert!(
        stderr.contains(&initialized_fork(&src.display().to_string())),
        "{stderr}"
    );
    let data = only_fork_data(&h);
    assert!(data.join("visible").exists(), "{}", data.display());
    assert!(
        !data.join("hidden").exists(),
        "an exclusion inside a set must omit the path: {}",
        data.display()
    );

    let stderr = stderr_of(&h.launch(&["--mount", "pi"], "shell", &[]));
    assert!(
        stderr.contains("Omitted host Pi credential file agent/auth.json"),
        "{stderr}"
    );
    let pi_data = h
        .fork_dirs()
        .into_iter()
        .map(|fork| fork.join("data"))
        .find(|data| data.join("settings.json").exists())
        .expect("the Pi fork must exist");
    assert!(!pi_data.join("agent/auth.json").exists());
    assert_eq!(
        std::fs::read_to_string(pi.join("agent/auth.json")).unwrap(),
        "{\"token\":\"host-auth\"}",
        "the host credential must be untouched"
    );
}

/// A set selection never changes credential provisioning or persisted paths: the
/// same project tool, with and without a selection, resolves the same facets.
///
/// The two facets are the ones a mount could plausibly interfere with: the
/// header-credential the tool requests, and the `persist` link the provisioning
/// closure creates inside the project state dir.
#[test]
fn named_mount_sets_do_not_change_provisioning() {
    fn facets(options: &[&str], with_sets: bool) -> (Vec<String>, String) {
        let h = Harness::new();
        if with_sets {
            seed_source(&h, "a");
            h.write_user("mounts = [\"a-set\"]\n[mount_sets]\na-set = [\"~/a:/a:ro\"]\n");
        }
        h.write_project(
            "[[tools]]\nname = \"t\"\ncommand = \"/bin/true\"\ncredentials = [\"my-service\"]\n\
             persist = [\"code\"]\n",
        );
        write_credentials(&h, MY_SERVICE_YAML);
        let out = h.launch_with_env(
            options,
            "t",
            &[],
            &[("AGENT_VM_TEST_CREDENTIAL", "my-service=synthetic")],
        );
        let stderr = stderr_of(&out);
        let config = debug_config_json(&stderr);
        let references: Vec<String> = config["network"]["secrets"]["header_credentials"]
            .as_array()
            .expect("header_credentials must be an array")
            .iter()
            .map(|entry| entry["reference"].as_str().expect("reference").to_string())
            .collect();
        let link = std::fs::read_link(state_dir(&stderr).join("home/code"))
            .expect("the persist link must exist")
            .display()
            .to_string();
        (references, link)
    }

    let baseline = facets(&[], false);
    assert_eq!(
        baseline.0,
        ["my-service"],
        "the control must resolve the request"
    );
    assert_eq!(
        baseline.1, "/agent-vm-state/persist/code",
        "the control must create the persisted link"
    );
    for options in [
        vec![],
        vec!["--no-config-mounts"],
        vec!["--no-config-mounts", "--mount", "a-set"],
    ] {
        assert_eq!(
            facets(&options, true),
            baseline,
            "{options:?}: a set selection must not change provisioning or persisted paths"
        );
    }
}

/// Repo-scan parity: a set leaf widens the GitHub allow-list exactly as its
/// direct twin, a suppressed default contributes nothing, and an explicitly
/// selected set still contributes under the opt-out.
#[test]
fn named_mount_sets_scan_repos_like_their_direct_twin() {
    let h = Harness::new();
    let checkout = seed_github_checkout(&h, "checkout", "example/visible");
    h.write_user("mounts = [\"s\"]\n[mount_sets]\ns = [\"~/checkout:ro\"]\n");
    let configured = stderr_of(&h.launch(&[], "shell", &[]));
    assert_eq!(
        repo_scope(&configured),
        "==> GitHub repo scope (1): example/visible",
        "a set leaf's remote must reach the allow-list"
    );

    // The same directory as a bare `--mount` with no config in play.
    std::fs::remove_file(h.user_config()).unwrap();
    let cli = stderr_of(&h.launch(
        &["--mount", &format!("{}:ro", checkout.display())],
        "shell",
        &[],
    ));
    assert_eq!(repo_scope(&cli), repo_scope(&configured));

    // Suppression is proved from *one* document that has both a defaults entry
    // selecting the set and the definition it selects: only the option changes
    // between these two launches, so neither the absent nor the present scope can
    // come from different bytes.
    h.write_user(&format!(
        "mounts = [\"scan\"]\n{SETS_BODY}scan = [\"~/checkout:ro\"]\n"
    ));
    let unsuppressed = stderr_of(&h.launch(&[], "shell", &[]));
    assert_eq!(
        repo_scope(&unsuppressed),
        "==> GitHub repo scope (1): example/visible",
        "the same bytes select the set without the opt-out: {unsuppressed}"
    );
    assert!(
        unsuppressed.contains("==> Config mounts: 1 from"),
        "the defaults entry is what selects it: {unsuppressed}"
    );
    let suppressed = stderr_of(&h.launch(&["--no-config-mounts"], "shell", &[]));
    assert_eq!(
        repo_scope(&suppressed),
        "==> GitHub repo scope: <none> (no api.github.com access)",
        "{suppressed}"
    );
    assert!(
        suppressed.contains("skipped 1 from"),
        "the opt-out must say what it skipped: {suppressed}"
    );
    // ...and the explicit name still contributes under the same opt-out.
    let explicit = stderr_of(&h.launch(&["--no-config-mounts", "--mount", "scan"], "shell", &[]));
    assert_eq!(
        repo_scope(&explicit),
        "==> GitHub repo scope (1): example/visible",
        "an explicit set still contributes its scan roots: {explicit}"
    );
}

/// Fork identity is untouched by set names, nesting, order and provenance: one
/// project-scoped fork, reached from every declaration form, with the committed
/// marker surviving a removed source.
#[test]
fn named_mount_sets_fork_identity_survives_every_declaration_form() {
    let h = Harness::new();
    let src = h.home_root.join("src");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("seed"), "seed").unwrap();

    // 1. Direct CLI seeds the fork.
    let seeded = stderr_of(&h.launch(
        &["--mount", &format!("{}:/f:fork", src.display())],
        "shell",
        &[],
    ));
    assert!(seeded.contains("==> Initialized fork"), "{seeded}");
    let committed = only_fork_data(&h);
    // A host-side marker in the committed copy: boot-free evidence that this
    // exact copy is what later launches bind, never guest evidence.
    std::fs::write(committed.join("marker"), "committed").unwrap();
    // Change the host seed and remove it: only a reused copy can still hold both
    // the old `seed` and the marker.
    std::fs::write(src.join("seed"), "host-later").unwrap();
    std::fs::remove_file(src.join("seed")).unwrap();
    std::fs::remove_dir(&src).unwrap();

    let forms: [(&str, Vec<&str>); 4] = [
        (
            // 2. Direct default.
            "mounts = [\"~/src:/f:fork\"]\n",
            vec![],
        ),
        (
            // 3. Named default.
            "mounts = [\"s\"]\n[mount_sets]\ns = [\"~/src:/f:fork\"]\n",
            vec![],
        ),
        (
            // 4. Nested named default through a renamed, reordered set.
            "mounts = [\"outer\"]\n[mount_sets]\nouter = [\"zzz\", \"s\"]\n\
             s = [\"~/src:/f:fork\"]\nzzz = []\n",
            vec![],
        ),
        (
            // 5. Explicit set under the opt-out.
            "[mount_sets]\ns = [\"~/src:/f:fork\"]\n",
            vec!["--no-config-mounts", "--mount", "s"],
        ),
    ];
    for (body, options) in forms {
        h.write_user(body);
        let stderr = stderr_of(&h.launch(&options, "shell", &[]));
        assert!(
            stderr.contains("==> Reusing fork"),
            "{body}: only reuse is allowed after the first launch: {stderr}"
        );
        assert!(
            !stderr.contains("Initialized"),
            "{body}: a reseed would be a new identity: {stderr}"
        );
        let binds = bind_mounts(&debug_config_json(&stderr));
        assert!(
            binds
                .iter()
                .any(|(host, guest, _)| Path::new(host) == committed && guest == "/f"),
            "{body}: the same committed copy must be bound: {binds:?}"
        );
        assert_eq!(
            std::fs::read_to_string(committed.join("marker")).unwrap(),
            "committed",
            "{body}: the committed copy must be the same one"
        );
        assert_eq!(
            h.fork_dirs().len(),
            1,
            "{body}: one project-scoped fork, not two"
        );
    }

    // 6. The reverse route: a fresh project seeded from a set, then reached by a
    // direct `--mount`.
    let second = Harness::new();
    let src = second.home_root.join("src");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("seed"), "seed").unwrap();
    second.write_user("[mount_sets]\ns = [\"~/src:/f:fork\"]\n");
    let seeded = stderr_of(&second.launch(&["--mount", "s"], "shell", &[]));
    assert!(seeded.contains("==> Initialized fork"), "{seeded}");
    let set_committed = only_fork_data(&second);
    std::fs::remove_file(src.join("seed")).unwrap();
    std::fs::remove_dir(&src).unwrap();
    let direct = stderr_of(&second.launch(
        &["--mount", &format!("{}:/f:fork", src.display())],
        "shell",
        &[],
    ));
    assert!(direct.contains("==> Reusing fork"), "{direct}");
    let binds = bind_mounts(&debug_config_json(&direct));
    assert!(
        binds
            .iter()
            .any(|(host, guest, _)| Path::new(host) == set_committed && guest == "/f"),
        "{binds:?}"
    );

    // The store is project-scoped by `ProjectSession` alone — no set name,
    // nesting or origin reaches `fork_id` — so a second project's store is the
    // unchanged `mount_fork` machinery and is not re-driven here. What this test
    // must show is the single-store invariant across every declaration form.
    assert_eq!(second.fork_dirs().len(), 1, "one fork for this project");
}

/// No implicit `agent` group and no inference from tool names: a set whose name
/// matches the launch verb (or a shipped tool's name) is not selected by it.
/// `--mount` is the only selector, and a name that is a tool/route word is an
/// exact set lookup (decision A1), never a tool selection.
///
/// The differential control is the same document plus the explicit selection: if
/// verb-named sets were inferred, the first launch would show a bind the control
/// proves only the name can produce.
#[test]
fn named_mount_sets_are_never_inferred_from_tool_names() {
    let h = Harness::new();
    seed_set_sources(&h);
    // Two names that collide with real words: `pi` is a shipped launch verb and
    // `pi-agent` is the canonical example set the issue uses.
    h.write_user(
        "[[tools]]\nname = \"pi\"\ncommand = \"/bin/true\"\n\n\
         [mount_sets]\npi = [\"~/ro:/ro:ro\"]\npi-agent = [\"~/rw:/rw\"]\n",
    );

    let inferred = stderr_of(&h.launch(&[], "pi", &[]));
    assert!(
        inferred.contains(CONFIG_MARKER),
        "launching the tool must still work: {inferred}"
    );
    let unsolicited = sorted_binds(&debug_config_json(&inferred));
    assert!(
        !unsolicited
            .iter()
            .any(|(_, guest, _)| guest == "/ro" || guest == "/rw"),
        "launching a tool must not select a set named after it: {unsolicited:?}"
    );
    assert!(
        !inferred.contains("==> Config mounts:"),
        "definitions alone report no config selection: {inferred}"
    );

    // The control: the very same document does select both names explicitly, so
    // the absence above is the *selection rule*, not an unreadable set.
    let named = stderr_of(&h.launch(&["--mount", "pi", "--mount", "pi-agent"], "shell", &[]));
    let binds = bind_mounts(&debug_config_json(&named));
    for guest in ["/ro", "/rw"] {
        assert!(
            binds.iter().any(|(_, bind, _)| bind == guest),
            "{guest} must be bound when its set is named: {binds:?}"
        );
    }
    // ...and `--mount pi` selected the *set*, not the tool: the verb is still
    // `shell`, and the tool's own command never ran.
    assert!(
        named.contains("==> agent-vm-") && !named.contains("/bin/true"),
        "the selection must not turn into a tool launch: {named}"
    );
}

/// Two separately valid sets that disagree at one guest path are a *selection*
/// conflict, not a config error: the file loads, `doctor` is clean, neither
/// selected and each alone are fine, and only selecting both (either order)
/// fails. Decision A2's second half — nothing claims unrelated sets against
/// each other at load.
#[test]
fn named_mount_sets_fail_only_when_a_launch_selects_both() {
    let h = Harness::new();
    let a = seed_source(&h, "a");
    let b = seed_source(&h, "b");
    h.write_user("[mount_sets]\nx = [\"~/a:/g:ro\"]\ny = [\"~/b:/g:ro\"]\n");

    assert!(
        h.doctor().status.success(),
        "two valid sets that disagree must not fail load: {}",
        stderr_of(&h.doctor())
    );

    let neither = stderr_of(&h.launch(&[], "shell", &[]));
    assert!(
        !bind_mounts(&debug_config_json(&neither))
            .iter()
            .any(|(_, guest, _)| guest == "/g"),
        "selecting neither must bind neither: {neither}"
    );

    for (name, source) in [("x", &a), ("y", &b)] {
        let stderr = stderr_of(&h.launch(&["--mount", name], "shell", &[]));
        let binds = bind_mounts(&debug_config_json(&stderr));
        assert!(
            binds
                .iter()
                .any(|(host, guest, _)| guest == "/g" && Path::new(host) == source),
            "selecting {name} alone must bind its own declaration: {binds:?}"
        );
    }

    for order in [["x", "y"], ["y", "x"]] {
        let before = h.snapshot();
        let out = h.launch(&["--mount", order[0], "--mount", order[1]], "shell", &[]);
        let stderr = stderr_of(&out);
        assert!(
            stderr.contains("guest path /g is claimed by different declarations"),
            "{order:?}: {stderr}"
        );
        // Both declared sites are named, the first-selected first.
        let (first, second) = (
            set_declaration(&h, order[0], 0),
            set_declaration(&h, order[1], 0),
        );
        assert!(
            stderr.contains(&first),
            "{order:?} must name {first}: {stderr}"
        );
        assert!(
            stderr.contains(&second),
            "{order:?} must name {second}: {stderr}"
        );
        assert!(
            stderr.find(&first) < stderr.find(&second),
            "{order:?} must name the first-selected site first: {stderr}"
        );
        h.assert_refused_before_launch_state(&out, &before, "claimed by different declarations");
    }
}

/// An empty `[mount_sets]` table and an empty named set are authority-bearing by
/// *presence* (their file must pass the verified read) and select nothing — a
/// launch with one is ordinary, not an error, and `--mount` on an empty set is a
/// legal no-op selection.
#[test]
fn named_mount_sets_empty_table_and_empty_set_select_nothing() {
    let h = Harness::new();
    seed_set_sources(&h);

    // A control bind from the defaults, so "nothing from the sets" is measured
    // on a launch that otherwise selects something.
    h.write_user("mounts = [\"~/ro:/ro:ro\"]\n[mount_sets]\n");
    let empty_table = stderr_of(&h.launch(&[], "shell", &[]));
    let binds = sorted_binds(&debug_config_json(&empty_table));
    assert_eq!(
        binds.iter().filter(|(_, guest, _)| guest == "/ro").count(),
        1,
        "only the defaults entry binds: {binds:?}"
    );
    assert!(
        empty_table.contains(&config_notice(&h, 1)),
        "an empty table adds no declaration to the notice: {empty_table}"
    );

    h.write_user("mounts = []\n[mount_sets]\nempty = []\n");
    let empty_set = stderr_of(&h.launch(&[], "shell", &[]));
    assert!(
        empty_set.contains(CONFIG_MARKER),
        "an empty set is valid: {empty_set}"
    );
    assert!(
        !sorted_binds(&debug_config_json(&empty_set))
            .iter()
            .any(|(_, guest, _)| guest == "/ro" || guest == "/rw"),
        "an empty set selects nothing: {empty_set}"
    );

    let selected = stderr_of(&h.launch(&["--mount", "empty"], "shell", &[]));
    assert!(
        selected.contains(CONFIG_MARKER),
        "`--mount` on an empty set is a legal no-op: {selected}"
    );
    assert!(
        !sorted_binds(&debug_config_json(&selected))
            .iter()
            .any(|(_, guest, _)| guest == "/ro" || guest == "/rw"),
        "{selected}"
    );
}

/// Set names are case-sensitive lookups (decision A1): `A` and `a` are two
/// sets, and `--mount agent` never finds `Agent`.
#[test]
fn named_mount_sets_look_up_names_case_sensitively() {
    let h = Harness::new();
    seed_set_sources(&h);
    h.write_user("[mount_sets]\nA = [\"~/ro:/ro:ro\"]\na = [\"~/rw:/rw\"]\n");

    let upper = stderr_of(&h.launch(&["--mount", "A"], "shell", &[]));
    let binds = bind_mounts(&debug_config_json(&upper));
    assert!(
        binds.iter().any(|(_, guest, _)| guest == "/ro"),
        "`--mount A` selects the `A` set: {binds:?}"
    );
    assert!(
        !binds.iter().any(|(_, guest, _)| guest == "/rw"),
        "`A` must not resolve to `a`: {binds:?}"
    );

    let lower = stderr_of(&h.launch(&["--mount", "a"], "shell", &[]));
    let binds = bind_mounts(&debug_config_json(&lower));
    assert!(
        binds.iter().any(|(_, guest, _)| guest == "/rw"),
        "`--mount a` selects the `a` set: {binds:?}"
    );

    let before = h.snapshot();
    let out = h.launch(&["--mount", "Agent"], "shell", &[]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(&format!(
            "mount set \"Agent\" is not defined by any [mount_sets] in \"{}\"",
            h.user_config().display()
        )),
        "{stderr}"
    );
    h.assert_refused_before_launch_state(&out, &before, "parsing --mount");
}

/// The project tier cannot introduce a mount-set namespace: it may neither
/// define `[mount_sets]` (empty or not) nor select a user name from `mounts`.
/// The refusal is the same project-tier rule `mounts` already had, so a project
/// file cannot shadow a user set — or plant one in a checkout the guest writes.
#[test]
fn named_mount_sets_cannot_be_declared_or_selected_by_the_project() {
    // A real user set of that name, so "the project defined it" and "the project
    // selected the user's" are both live possibilities the refusal must exclude.
    let h = Harness::new();
    seed_set_sources(&h);
    h.write_user("[mount_sets]\nagent = [\"~/ro:/ro:ro\"]\n");

    for (body, needle) in [
        (
            "[mount_sets]\n",
            "mount_sets cannot be declared by the project config",
        ),
        (
            "[mount_sets]\nagent = []\n",
            "mount_sets cannot be declared by the project config",
        ),
        (
            "[mount_sets]\nagent = [\"~/rw:/rw\"]\n",
            "mount_sets cannot be declared by the project config",
        ),
        (
            "mounts = [\"agent\"]\n",
            "mounts cannot be declared by the project config",
        ),
        (
            "mounts = []\n",
            "mounts cannot be declared by the project config",
        ),
    ] {
        h.write_project(body);
        let before = h.snapshot();
        let out = h.launch(&[], "shell", &[]);
        let stderr = stderr_of(&out);
        assert!(
            stderr.contains(&format!(
                "config: \"{}\": {needle}",
                h.project_config().display()
            )),
            "{body}: {stderr}"
        );
        h.assert_refused_before_launch_state(&out, &before, needle);
    }

    // The user tier is untouched by the project's attempt: the same launch with
    // no project file selects the user's set by name.
    h.write_project("");
    let stderr = stderr_of(&h.launch(&["--mount", "agent"], "shell", &[]));
    assert!(
        bind_mounts(&debug_config_json(&stderr))
            .iter()
            .any(|(_, guest, _)| guest == "/ro"),
        "the user set must still be the one that resolves: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Tool-specific config mounts (#396)
//
// A full user `[[tools]]` may declare `mounts`, and a launch of that tool selects
// its own list plus the lists of every definition in its transitive same-file
// `tools` closure — never another tool's, never a project tool's. Every row below
// launches the *real* CLI through the fake runtime and reads the guest volume set
// out of the dumped `SandboxConfig`, so a notice alone can never make a row pass.
// ---------------------------------------------------------------------------

/// The launched verb's bind set as sorted `(host, guest, readonly)` triples.
fn verb_binds(h: &Harness, options: &[&str], verb: &str) -> Vec<(String, String, bool)> {
    let stderr = stderr_of(&h.launch(options, verb, &[]));
    assert!(
        stderr.contains(CONFIG_MARKER),
        "{verb} must reach builder wiring: {stderr}"
    );
    sorted_binds(&debug_config_json(&stderr))
}

/// The guests a launch binds, so a row can assert *which* paths appeared without
/// pinning the generated host spelling of a mirror.
fn verb_guests(h: &Harness, options: &[&str], verb: &str) -> Vec<String> {
    verb_binds(h, options, verb)
        .into_iter()
        .map(|(_, guest, _)| guest)
        .collect()
}

/// A directory that must exist for its declaration to be selected.
fn seed_dir(h: &Harness, name: &str) -> PathBuf {
    let path = h.home_root.join(name);
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(path.join("marker"), name).unwrap();
    path
}

/// #396 AC-selector/AC-union: a verb selects **its own** list plus its transitive
/// closure's, and an unrelated (even missing) declaration never joins it.
#[test]
fn user_tool_own_mounts_select_only_its_verb() {
    let h = Harness::new();
    let _own = seed_dir(&h, "own");
    let _inherited = seed_dir(&h, "inherited");
    let _other = seed_dir(&h, "other");
    // `other` declares a source that does not exist: it must not be inspected
    // unless `other` is the launched verb.
    h.write_user(
        "[[tools]]\nname = \"root\"\ncommand = \"/bin/echo\"\ntools = [\"child\"]\n\
         mounts = [\"~/own:/own:ro\"]\n\
         [[tools]]\nname = \"child\"\ncommand = \"/bin/echo\"\n\
         mounts = [\"~/inherited:/inherited:rw\"]\n\
         [[tools]]\nname = \"other\"\ncommand = \"/bin/echo\"\n\
         mounts = [\"/nonexistent-agent-vm-396:/gone:ro\"]\n",
    );
    let binds = verb_binds(&h, &[], "root");
    let our_guests: Vec<&str> = binds
        .iter()
        .map(|(_, guest, _)| guest.as_str())
        .filter(|guest| ["/own", "/inherited", "/gone"].contains(guest))
        .collect();
    assert_eq!(our_guests, ["/inherited", "/own"], "{binds:?}");
    // Exact modes, not just presence: the own leaf is read-only, the inherited one
    // writable.
    let mode = |guest: &str| {
        binds
            .iter()
            .find(|(_, path, _)| path == guest)
            .map(|(_, _, readonly)| *readonly)
            .unwrap_or_else(|| panic!("{guest} missing from {binds:?}"))
    };
    assert!(mode("/own"), "the own leaf is :ro: {binds:?}");
    assert!(!mode("/inherited"), "the inherited leaf is :rw: {binds:?}");
    // A verb that declares no list of its own binds neither of root's, so the
    // inheritance is directional rather than "any launch sees any tool's mounts".
    let child_guests = verb_guests(&h, &[], "child");
    assert!(child_guests.iter().any(|guest| guest == "/inherited"));
    assert!(
        !child_guests.iter().any(|guest| guest == "/own"),
        "{child_guests:?}"
    );
    assert!(!child_guests.iter().any(|guest| guest == "/gone"));
    // And the direct runner sees none of it.
    let direct = stderr_of(&h.launch(&[], "run", &["/bin/echo", "hi"]));
    assert!(direct.contains(CONFIG_MARKER), "{direct}");
    let direct_binds = sorted_binds(&debug_config_json(&direct));
    assert!(
        !direct_binds
            .iter()
            .any(|(_, guest, _)| guest == "/own" || guest == "/inherited"),
        "a direct command must receive no tool mounts: {direct_binds:?}"
    );
}

/// #396 AC-selector: a tool list accepts mount-set names through the *same*
/// selector as the defaults list, and a set whose name matches a tool or the cwd
/// is still only a set.
///
/// The catalog deliberately contains a tool named exactly like the set, with three
/// independently observable provisioning facts of its own: a bind, a requested
/// name and a persisted guest-HOME link. Selecting the set must produce the set's
/// declarations and none of those three; launching the tool itself is the
/// positive control that each observable is live.
#[test]
fn tool_mounts_select_shared_named_sets_without_tool_inference() {
    let h = Harness::new();
    let _agent = seed_dir(&h, "agents");
    let _nested = seed_dir(&h, "nested");
    let _tool = seed_dir(&h, "agent-tool");
    h.write_user(
        "[mount_sets]\nagent = [\"~/agents:/agents:rw\", \"nested\"]\n\
         nested = [\"~/nested:/nested:ro\"]\nempty = []\n\
         [[tools]]\nname = \"pi\"\ncommand = \"/bin/echo\"\nmounts = [\"agent\", \"empty\"]\n\
         [[tools]]\nname = \"plain\"\ncommand = \"/bin/echo\"\n\
         [[tools]]\nname = \"agent\"\ncommand = \"/bin/echo\"\n\
         mounts = [\"~/agent-tool:/agent-tool:ro\"]\n\
         network_requests = [\"agent-tool.example\"]\n\
         persist = [\"agent-tool-state\"]\n",
    );
    let guests = verb_guests(&h, &[], "pi");
    assert!(guests.iter().any(|guest| guest == "/agents"));
    assert!(guests.iter().any(|guest| guest == "/nested"));
    assert!(
        !guests.iter().any(|guest| guest == "/agent-tool"),
        "the tool's own leaf is not selected by a set name: {guests:?}"
    );

    // A set name is never provisioned as a tool: `--mount agent` selects the set,
    // and the same-named tool's bind, requested name and persisted link all stay
    // out of the launch.
    let stored = stderr_of(&h.launch(&["--mount", "agent"], "plain", &[]));
    let binds = sorted_binds(&debug_config_json(&stored));
    assert!(
        binds.iter().any(|(_, guest, _)| guest == "/agents"),
        "the explicit set must resolve: {binds:?}"
    );
    assert!(binds.iter().any(|(_, guest, _)| guest == "/nested"));
    assert!(
        !binds
            .iter()
            .any(|(_, guest, readonly)| guest == "/agent-tool" && *readonly),
        "selecting the set must not provision the same-named tool: {binds:?}"
    );
    assert!(
        !stored.contains("agent-tool.example"),
        "the same-named tool's requested name must stay unrequested: {stored}"
    );
    // The guest-HOME link `persist = ["agent-tool-state"]` provisions, as the
    // state tree shows it: present only when that declaration was selected.
    let persisted = |h: &Harness| {
        h.snapshot()
            .into_iter()
            .any(|(key, value)| key.ends_with("agent-tool-state") && value.starts_with("symlink:"))
    };
    assert!(
        !persisted(&h),
        "selecting the set must not provision the same-named tool's persist link"
    );

    // Positive control for all three observables: the tool itself, launched.
    let direct = stderr_of(&h.launch(&[], "agent", &[]));
    let direct_binds = sorted_binds(&debug_config_json(&direct));
    assert!(
        direct_binds
            .iter()
            .any(|(_, guest, readonly)| guest == "/agent-tool" && *readonly),
        "the same-named tool's own leaf binds when it is the launch: {direct_binds:?}"
    );
    assert!(
        direct.contains("agent-tool.example"),
        "the same-named tool's requested name is reported when it is the launch: {direct}"
    );
    assert!(
        persisted(&h),
        "the same-named tool's persist link appears when it is the launch"
    );
}

/// #396 AC-selector/AC-union at the CLI boundary: the issue's own accepted shape —
/// one tool list mixing a set name and a `~/` direct entry — reaches the guest,
/// and a declaration repeated across the two automatic *inputs* (the user-wide
/// defaults and the tool facet) and inside the selected set is one bind, not
/// three.
///
/// The defaults/tool split is the seam this row exists for: `materialize`
/// concatenates the two inputs and relies on the one shared claim to merge them,
/// and the notice counts *distinct guest paths*, not occurrences. A second claim
/// per input, a dropped direct entry after a set name, or an occurrence count all
/// fail here, and the per-guest `1` counts are calibrated by the four guests that
/// must each be present.
#[test]
fn tool_list_mixes_set_and_direct_and_merges_with_defaults() {
    let h = Harness::new();
    let _own = seed_dir(&h, "own");
    let _shared = seed_dir(&h, "shared");
    let _default = seed_dir(&h, "default");
    let _agents = seed_dir(&h, "agents");
    h.write_user(
        // The defaults and the tool list declare the *same* guest path with the
        // same declaration; the set names it a third time.
        "mounts = [\"~/default:/default:ro\", \"~/shared:/shared:ro\"]\n\
         [mount_sets]\nagent = [\"~/agents:/agents:rw\", \"~/shared:/shared:ro\"]\n\
         [[tools]]\nname = \"pi\"\ncommand = \"/bin/echo\"\ntools = []\n\
         mounts = [\"agent\", \"~/own:/own:ro\", \"~/shared:/shared:ro\"]\n",
    );
    let stderr = stderr_of(&h.launch(&[], "pi", &[]));
    assert!(
        stderr.contains(CONFIG_MARKER),
        "the launch must reach builder wiring: {stderr}"
    );
    let binds = sorted_binds(&debug_config_json(&stderr));
    for (guest, readonly) in [
        ("/agents", false),
        ("/own", true),
        ("/shared", true),
        ("/default", true),
    ] {
        let matching: Vec<_> = binds.iter().filter(|(_, path, _)| path == guest).collect();
        assert_eq!(matching.len(), 1, "{guest} must bind once: {binds:?}");
        assert_eq!(matching[0].2, readonly, "{guest}: {binds:?}");
    }
    // Distinct guest paths across both inputs: 2 defaults (one of them the
    // duplicate) + 3 tool-facet entries (one of them the duplicate again).
    assert!(
        stderr.contains("==> Config mounts: 4 from"),
        "the notice counts distinct guest paths, not occurrences: {stderr}"
    );
}

/// #396 AC-union: a chain, a cycle and a diamond each bind every declaration once,
/// and an equivalent spelling reached twice merges rather than conflicting.
#[test]
fn tool_mount_chain_cycle_and_diamond_bind_each_declaration_once() {
    let h = Harness::new();
    let _a = seed_dir(&h, "a");
    let _b = seed_dir(&h, "b");
    let _c = seed_dir(&h, "c");
    h.write_user(
        "[[tools]]\nname = \"top\"\ncommand = \"/bin/echo\"\ntools = [\"left\", \"right\"]\n\
         mounts = [\"~/a:/a:ro\", \"~/a:/a//./:ro\"]\n\
         [[tools]]\nname = \"left\"\ncommand = \"/bin/echo\"\ntools = [\"shared\"]\n\
         mounts = [\"~/b:/b:ro\"]\n\
         [[tools]]\nname = \"right\"\ncommand = \"/bin/echo\"\ntools = [\"shared\", \"top\"]\n\
         mounts = [\"~/c:/c:ro\"]\n\
         [[tools]]\nname = \"shared\"\ncommand = \"/bin/echo\"\ntools = [\"top\"]\n\
         mounts = [\"~/a:/a:ro\"]\n",
    );
    let binds = verb_binds(&h, &[], "top");
    for guest in ["/a", "/b", "/c"] {
        let count = binds.iter().filter(|(_, path, _)| path == guest).count();
        assert_eq!(count, 1, "{guest} must bind once: {binds:?}");
    }
}

/// #396 AC-union: a conflict between two lists **the same launch's closure**
/// selects is a load error, naming both declaring sites and offering no
/// override — in either list order.
#[test]
fn tool_mount_conflicts_name_both_sites_without_overrides() {
    // Both orders: which declaration is `tools[0]` decides which site is named
    // first, and neither may be silently preferred.
    for reversed in [false, true] {
        let h = Harness::new();
        let _p = seed_dir(&h, "p");
        let _q = seed_dir(&h, "q");
        let (own, inherited) = if reversed {
            ("~/q:/g:rw", "~/p:/g:ro")
        } else {
            ("~/p:/g:ro", "~/q:/g:rw")
        };
        h.write_user(&format!(
            "[[tools]]\nname = \"launch\"\ncommand = \"/bin/echo\"\ntools = [\"other\"]\n\
             mounts = [\"{own}\"]\n\
             [[tools]]\nname = \"other\"\ncommand = \"/bin/echo\"\nmounts = [\"{inherited}\"]\n"
        ));
        let before = h.snapshot();
        let out = h.launch(&[], "launch", &[]);
        h.assert_refused_before_launch_state(
            &out,
            &before,
            "tools[1].mounts[0]: claims the same guest path as tools[0].mounts[0] with a \
             different declaration",
        );
        // The opt-out cannot hide it: the closure is a load-time fact, and the flag
        // only removes automatic *selection*.
        let before = h.snapshot();
        let out = h.launch(&["--no-config-mounts"], "launch", &[]);
        h.assert_refused_before_launch_state(&out, &before, "claims the same guest path");
    }
}

/// #396 AC-union: every pair of *declaration sources* has its own refusal, and the
/// two mechanisms keep their deliberately different contexts — a pair inside one
/// closure's fold is a load error naming both sites, while a pair across facets
/// (defaults, tool closure, argv) is the shared preparation claim that names each
/// declaration and offers the opt-out.
///
/// The six rows are the six pairs of the four sources a launch can receive a mount
/// from: `--mount`, the defaults list, a tool list and a mount-set leaf. Covering
/// only own-versus-inherited would leave three of the four renderings untested.
#[test]
fn tool_mount_conflicts_name_every_opposing_declaration_pair() {
    /// One fixture: the launch route, the needle its own mechanism prints, and the
    /// two exact declaration names the sentence must carry. `{file}` is the harness's
    /// user config path.
    type Build =
        fn(&Harness, &Path) -> (&'static str, Vec<String>, &'static str, [&'static str; 2]);
    let rows: [(&str, Build); 6] = [
        // argv × defaults
        ("argv/defaults", |h, b| {
            h.write_user("mounts = [\"~/a:/g:ro\"]\n");
            (
                "shell",
                vec!["--mount".to_string(), format!("{}:/g:ro", b.display())],
                "is claimed by different declarations",
                ["mounts[0] in \"{file}\"", "--mount"],
            )
        }),
        // argv × set leaf
        ("argv/set", |h, b| {
            h.write_user(
                "[mount_sets]\ns = [\"~/a:/g:ro\"]\n[[tools]]\nname = \"t\"\n\
                     command = \"/bin/echo\"\ntools = []\nmounts = [\"s\"]\n",
            );
            (
                "t",
                vec!["--mount".to_string(), format!("{}:/g:ro", b.display())],
                "is claimed by different declarations",
                ["mount_sets[\"s\"][0] in \"{file}\"", "--mount"],
            )
        }),
        // argv × tool list
        ("argv/tool", |h, b| {
            h.write_user(
                "[[tools]]\nname = \"t\"\ncommand = \"/bin/echo\"\ntools = []\n\
                     mounts = [\"~/a:/g:ro\"]\n",
            );
            (
                "t",
                vec!["--mount".to_string(), format!("{}:/g:ro", b.display())],
                "is claimed by different declarations",
                ["tools[0].mounts[0] in \"{file}\"", "--mount"],
            )
        }),
        // defaults × set leaf
        ("defaults/set", |h, _| {
            h.write_user(
                "mounts = [\"~/a:/g:ro\"]\n[mount_sets]\ns = [\"~/b:/g:ro\"]\n\
                     [[tools]]\nname = \"t\"\ncommand = \"/bin/echo\"\ntools = []\n\
                     mounts = [\"s\"]\n",
            );
            (
                "t",
                vec![],
                "is claimed by different declarations",
                [
                    "mounts[0] in \"{file}\"",
                    "mount_sets[\"s\"][0] in \"{file}\"",
                ],
            )
        }),
        // defaults × tool list
        ("defaults/tool", |h, _| {
            h.write_user(
                "mounts = [\"~/a:/g:ro\"]\n[[tools]]\nname = \"t\"\n\
                     command = \"/bin/echo\"\ntools = []\nmounts = [\"~/b:/g:ro\"]\n",
            );
            (
                "t",
                vec![],
                "is claimed by different declarations",
                [
                    "mounts[0] in \"{file}\"",
                    "tools[0].mounts[0] in \"{file}\"",
                ],
            )
        }),
        // set leaf × tool list, one closure: the fold merges them at load. The sites
        // are rendered by the fold's own sentence, which numbers the set because it
        // is a load-site pointer rather than the leaf's declaration.
        ("set/tool", |h, _| {
            h.write_user(
                "[mount_sets]\ns = [\"~/a:/g:ro\"]\n[[tools]]\nname = \"t\"\n\
                     command = \"/bin/echo\"\ntools = [\"u\"]\nmounts = [\"s\"]\n\
                     [[tools]]\nname = \"u\"\ncommand = \"/bin/echo\"\ntools = []\n\
                     mounts = [\"~/b:/g:ro\"]\n",
            );
            (
                "t",
                vec![],
                "claims the same guest path",
                ["mount_sets[0][0]", "tools[1].mounts[0]"],
            )
        }),
    ];
    for (label, build) in rows {
        let h = Harness::new();
        seed_dir(&h, "a");
        let b = seed_dir(&h, "b");
        let (verb, argv, needle, names) = build(&h, &b);
        let options: Vec<&str> = argv.iter().map(String::as_str).collect();
        let before = h.snapshot();
        let out = h.launch(&options, verb, &[]);
        let stderr = stderr_of(&out);
        let claim = stderr
            .lines()
            .find(|line| {
                line.contains("claimed by different declarations")
                    || line.contains("claims the same guest path")
            })
            .unwrap_or_else(|| panic!("{label}: no claim sentence: {stderr}"));
        let file = h.user_config().display().to_string();
        for name in names {
            let name = name.replace("{file}", &file);
            assert!(
                claim.contains(&name),
                "{label}: the sentence must name {name:?}: {claim}"
            );
        }
        h.assert_refused_before_launch_state(&out, &before, needle);
    }
}

/// #396 AC-union: declaration identity includes every field two declarations agree
/// or disagree on — host, policy, follow-links, fork exclusions and the fork mode
/// itself — so no pair of same-guest declarations is silently merged.
#[test]
fn tool_mount_conflicts_cover_each_differing_declaration_field() {
    for (label, defaults, tool_list) in [
        ("host", "~/a:/g:ro", "~/b:/g:ro"),
        ("policy", "~/a:/g:ro", "~/a:/g:rw"),
        ("follow-links", "~/a:/g:ro", "~/a:/g:ro:follow-links"),
        (
            "fork exclusions",
            "~/a:/g:fork:exclude=one",
            "~/a:/g:fork:exclude=two",
        ),
        ("fork mode", "~/a:/g:fork", "~/a:/g:rw"),
    ] {
        let h = Harness::new();
        seed_dir(&h, "a");
        seed_dir(&h, "b");
        let file = h.user_config().display().to_string();
        h.write_user(&format!(
            "mounts = [\"{defaults}\"]\n[[tools]]\nname = \"t\"\ncommand = \"/bin/echo\"\n\
             tools = []\nmounts = [\"{tool_list}\"]\n"
        ));
        let before = h.snapshot();
        let out = h.launch(&[], "t", &[]);
        let stderr = stderr_of(&out);
        let clause = format!("mounts[0] in \"{file}\"");
        assert!(
            stderr.contains(&format!(
                "guest path /g is claimed by different declarations ({clause} and "
            )) && stderr.contains(&format!("tools[0].mounts[0] in \"{file}\"")),
            "{label}: both declarations must be named: {stderr}"
        );
        h.assert_refused_before_launch_state(&out, &before, "is claimed by different declarations");
        assert!(
            h.fork_dirs().is_empty(),
            "{label}: no fork may be published before the claim is refused"
        );
    }
}

/// #396 AC-authority: a project tool's `mounts` field is a load error by presence,
/// including when the project definition is hidden by a user name and when the
/// list is empty.
#[test]
fn project_tool_mount_presence_is_a_load_error_even_when_hidden() {
    for body in [
        "[[tools]]\nname = \"hidden\"\ncommand = \"/bin/echo\"\nmounts = []\n".to_string(),
        "[[tools]]\nname = \"hidden\"\ncommand = \"/bin/echo\"\nmounts = 7\n".to_string(),
        "[[tools]]\nname = \"hidden\"\ncommand = \"/bin/echo\"\nmounts = [\"~/x:/x:ro\"]\n"
            .to_string(),
    ] {
        let h = Harness::new();
        // A user declaration of the same name makes the project definition a
        // hidden loser — refused all the same, because the field is authority.
        h.write_user("[[tools]]\nname = \"hidden\"\ncommand = \"/bin/echo\"\n");
        h.write_project(&body);
        let before = h.snapshot();
        let out = h.launch(&[], "hidden", &[]);
        h.assert_refused_before_launch_state(
            &out,
            &before,
            "tools[0].mounts: mounts cannot be declared by the project config",
        );
        // `doctor` reports it and `--help` still works: the recovery path is
        // intact.
        let doctor = stderr_of(&h.doctor());
        assert!(doctor.contains("tools[0].mounts"), "{doctor}");
        assert!(
            h.help().status.success(),
            "a broken config must not break --help"
        );
    }
    // Anchor: removing the field launches.
    let h = Harness::new();
    h.write_user("[[tools]]\nname = \"hidden\"\ncommand = \"/bin/echo\"\n");
    h.write_project("[[tools]]\nname = \"hidden\"\ncommand = \"/bin/echo\"\n");
    assert!(stderr_of(&h.launch(&[], "hidden", &[])).contains(CONFIG_MARKER));
}

/// #396 AC-tier: a project launch never acquires user mount authority, by naming
/// a user tool, by a wildcard, or transitively — while user-wide defaults and
/// explicit `--mount` still reach it deliberately.
#[test]
fn project_tool_edges_never_select_user_mounts() {
    let h = Harness::new();
    let _pi = seed_dir(&h, "pi-home");
    let _default = seed_dir(&h, "default");
    h.write_user(
        "mounts = [\"~/default:/default:ro\"]\n\
         [[tools]]\nname = \"pi\"\ncommand = \"/bin/echo\"\nmounts = [\"~/pi-home:/pi:ro\"]\n",
    );
    // The project names a tool only the project declares; a project wildcard shell
    // covers only project definitions.
    h.write_project(
        "[[tools]]\nname = \"local\"\ncommand = \"/bin/echo\"\ntools = [\"bridge\"]\n\
         [[tools]]\nname = \"bridge\"\ncommand = \"/bin/echo\"\n\
         [[tools]]\nname = \"shell\"\ncommand = \"bash\"\ninteractive_shell = true\n",
    );
    let guests = verb_guests(&h, &[], "local");
    assert!(
        !guests.iter().any(|guest| guest == "/pi"),
        "a project launch must not acquire the user's Pi mount: {guests:?}"
    );
    // The user-wide default *is* deliberately selected for a project launch.
    assert!(
        guests.iter().any(|guest| guest == "/default"),
        "user-wide defaults still reach a project launch: {guests:?}"
    );
    // The project shell's wildcard likewise sees no user definition.
    let shell_guests = verb_guests(&h, &[], "shell");
    assert!(!shell_guests.iter().any(|guest| guest == "/pi"));
    // A project reference to a name only the user declares is the exact
    // cross-tier error, not a mount source.
    h.write_project("[[tools]]\nname = \"local\"\ncommand = \"/bin/echo\"\ntools = [\"pi\"]\n");
    let before = h.snapshot();
    let out = h.launch(&[], "local", &[]);
    h.assert_refused_before_launch_state(
        &out,
        &before,
        "cross-tier tool references are not allowed",
    );
}

/// #396 AC-authority: a present-empty tool list still requires the verified read,
/// and the refusal names the tool field when the file has no top-level list.
#[test]
fn empty_present_tool_mounts_require_authority_before_any_launch() {
    // Compatibility anchor: no mount field, so an ordinary (group-writable) mode
    // is irrelevant and the launch proceeds.
    let h = Harness::new();
    h.write_user_mode("[[tools]]\nname = \"t\"\ncommand = \"/bin/echo\"\n", 0o664);
    assert!(stderr_of(&h.launch(&[], "t", &[])).contains(CONFIG_MARKER));

    // The same file with `mounts = []` is authority-bearing, so the writable mode
    // is refused — before any launch state.
    for body in [
        "[[tools]]\nname = \"t\"\ncommand = \"/bin/echo\"\nmounts = []\n",
        // A wrong type is authority-bearing before the schema is decided.
        "[[tools]]\nname = \"t\"\ncommand = \"/bin/echo\"\nmounts = 7\n",
    ] {
        let h = Harness::new();
        h.write_user_mode(body, 0o664);
        let before = h.snapshot();
        let out = h.launch(&[], "t", &[]);
        h.assert_refused_before_launch_state(
            &out,
            &before,
            "tools[0].mounts: mounts refuses a group- or other-writable config.toml",
        );
    }

    // Through a final-component symlink, with the tool field as the only authority
    // trigger.
    let h = Harness::new();
    let target = h.home_root.join("dotfiles/config.toml");
    write_file(
        &target,
        "[[tools]]\nname = \"t\"\ncommand = \"/bin/echo\"\nmounts = []\n",
    );
    h.symlink_user_config(&target);
    let before = h.snapshot();
    let out = h.launch(&[], "t", &[]);
    h.assert_refused_before_launch_state(
        &out,
        &before,
        "tools[0].mounts: mounts requires config.toml to be a regular file",
    );
}

/// #396 AC-shell: omitted `tools` is the existing wildcard (so it inherits
/// same-tier mounts), `tools = []` suppresses only the inheritance, and the
/// built-in fallback references no user tool.
#[test]
fn declared_shell_mounts_follow_omitted_empty_and_fallback_scopes() {
    let h = Harness::new();
    let _agent = seed_dir(&h, "agent");
    let _own = seed_dir(&h, "shell-own");
    let shell = |tail: &str| {
        format!(
            "[[tools]]\nname = \"agent\"\ncommand = \"/bin/echo\"\nmounts = [\"~/agent:/agent:ro\"]\n\
             [[tools]]\nname = \"shell\"\ncommand = \"bash\"\ninteractive_shell = true\n\
             mounts = [\"~/shell-own:/shell-own:ro\"]\n{tail}"
        )
    };
    // Omitted: the wildcard covers the same file, so the agent's list is inherited.
    h.write_user(&shell(""));
    let guests = verb_guests(&h, &[], "shell");
    assert!(guests.iter().any(|guest| guest == "/agent"), "{guests:?}");
    assert!(guests.iter().any(|guest| guest == "/shell-own"));
    // `tools = []`: own list only.
    h.write_user(&shell("tools = []\n"));
    let guests = verb_guests(&h, &[], "shell");
    assert!(!guests.iter().any(|guest| guest == "/agent"), "{guests:?}");
    assert!(guests.iter().any(|guest| guest == "/shell-own"));
    // The fallback: no declared shell, so the shipped one is synthesized in a scope
    // of its own and inherits nothing — it still receives user-wide defaults.
    h.write_user(
        "mounts = [\"~/default:/default:ro\"]\n\
         [[tools]]\nname = \"agent\"\ncommand = \"/bin/echo\"\nmounts = [\"~/agent:/agent:ro\"]\n",
    );
    let _default = seed_dir(&h, "default");
    let guests = verb_guests(&h, &[], "shell");
    assert!(!guests.iter().any(|guest| guest == "/agent"), "{guests:?}");
    assert!(
        guests.iter().any(|guest| guest == "/default"),
        "the fallback still gets user-wide defaults: {guests:?}"
    );
}

/// #396 AC-opt-out: the flag removes the defaults **and** the whole tool facet,
/// and an explicit `--mount` still applies.
#[test]
fn opt_out_removes_defaults_own_and_inherited_mounts_but_keeps_cli() {
    let h = Harness::new();
    let _default = seed_dir(&h, "default");
    let _own = seed_dir(&h, "own");
    let _inherited = seed_dir(&h, "inherited");
    let _cli = seed_dir(&h, "cli");
    h.write_user(
        "mounts = [\"~/default:/default:ro\"]\n[mount_sets]\ns = [\"~/cli:/cli:ro\"]\n\
         [[tools]]\nname = \"t\"\ncommand = \"/bin/echo\"\ntools = [\"u\"]\n\
         mounts = [\"~/own:/own:ro\"]\n\
         [[tools]]\nname = \"u\"\ncommand = \"/bin/echo\"\nmounts = [\"~/inherited:/inherited:ro\"]\n",
    );
    // Apply: all three automatic sources appear.
    let applied = verb_guests(&h, &[], "t");
    for guest in ["/default", "/own", "/inherited"] {
        assert!(
            applied.iter().any(|path| path == guest),
            "{guest}: {applied:?}"
        );
    }
    // Suppress: none of them, and no automatic fork publication.
    let suppressed = verb_guests(&h, &["--no-config-mounts"], "t");
    for guest in ["/default", "/own", "/inherited"] {
        assert!(
            !suppressed.iter().any(|path| path == guest),
            "{guest} must be suppressed: {suppressed:?}"
        );
    }
    // The notice names what it skipped, and the count covers both automatic inputs.
    let stderr = stderr_of(&h.launch(&["--no-config-mounts"], "t", &[]));
    assert!(
        stderr.contains("==> Config mounts: skipped 3 from"),
        "the skipped count covers defaults and the tool facet: {stderr}"
    );
    // An explicit direct path and an explicit set still apply.
    let cli_only = verb_guests(
        &h,
        &[
            "--no-config-mounts",
            "--mount",
            "s",
            "--mount",
            &format!("{}:/direct:ro", h.home_root.join("cli").display()),
        ],
        "t",
    );
    assert!(cli_only.iter().any(|guest| guest == "/cli"), "{cli_only:?}");
    assert!(
        cli_only.iter().any(|guest| guest == "/direct"),
        "{cli_only:?}"
    );
}

/// #396 AC-opt-out: everything that is not a mount selection keeps working.
#[test]
fn tool_mount_opt_out_keeps_all_nonmount_facets_and_checks() {
    let h = Harness::new();
    let _own = seed_dir(&h, "own");
    // An inherited persist path reaches the guest HOME whether or not the mounts
    // are suppressed.
    h.write_user(
        "[[tools]]\nname = \"t\"\ncommand = \"/bin/echo\"\ntools = [\"u\"]\n\
         mounts = [\"~/own:/own:ro\"]\n\
         [[tools]]\nname = \"u\"\ncommand = \"/bin/echo\"\npersist = [\"inherited-state\"]\n",
    );
    for options in [vec![], vec!["--no-config-mounts"]] {
        let stderr = stderr_of(&h.launch(&options, "t", &[]));
        assert!(
            stderr.contains(CONFIG_MARKER),
            "{options:?} must reach builder wiring: {stderr}"
        );
        let config = debug_config_json(&stderr);
        let binds = sorted_binds(&config);
        assert_eq!(
            binds.iter().any(|(_, guest, _)| guest == "/own"),
            options.is_empty(),
            "{options:?}: only the mount facet is gated: {binds:?}"
        );
        // The inherited `persist` link is a host-side provisioning fact, so observe
        // it where it is created: `<state>/<hash>/home/inherited-state`.
        let state = state_dir(&stderr);
        // The link is a host-side symlink into project state; `symlink_metadata`
        // observes the link itself, so a link whose target is created on first use
        // is still an observable provisioning fact.
        let link = state.join("home/inherited-state");
        assert!(
            std::fs::symlink_metadata(&link).is_ok_and(|meta| meta.file_type().is_symlink()),
            "{options:?}: an inherited persist link must survive the opt-out (checked {})",
            link.display()
        );
        let _ = config;
    }

    // A broken mount declaration still refuses under the opt-out: schema, set
    // cycles and closure conflicts are load facts, not selections.
    h.write_user(
        "mounts = []\n[mount_sets]\ncyc = [\"cyc\"]\n\
         [[tools]]\nname = \"t\"\ncommand = \"/bin/echo\"\nmounts = []\n",
    );
    let before = h.snapshot();
    let out = h.launch(&["--no-config-mounts"], "t", &[]);
    h.assert_refused_before_launch_state(&out, &before, "mount-set reference cycle");
    // A selected declaration whose source is missing refuses too.
    h.write_user(
        "[[tools]]\nname = \"t\"\ncommand = \"/bin/echo\"\n\
         mounts = [\"/nonexistent-agent-vm-396:/gone:ro\"]\n",
    );
    let before = h.snapshot();
    let out = h.launch(&[], "t", &[]);
    h.assert_refused_before_launch_state(&out, &before, "tools[0].mounts[0]");
}

/// #396 AC-full-definition: a mount-only setting never patches a shipped tool, and
/// declaring a tool replaces the shipped catalog whole.
#[test]
fn tool_mount_only_definition_never_patches_shipped_catalog() {
    // Without a `command` the entry is the fixed schema error, so a mount field
    // cannot be a partial override.
    let h = Harness::new();
    h.write_user("[[tools]]\nname = \"pi\"\nmounts = [\"/a:/a:ro\"]\n");
    let before = h.snapshot();
    let out = h.launch(&[], "pi", &[]);
    h.assert_refused_before_launch_state(&out, &before, "invalid TOML or tool schema");

    // A full custom tool replaces the shipped catalog: shipped verbs are gone, and
    // the shipped `shell` becomes the fallback rather than a declaration.
    let h = Harness::new();
    let _a = seed_dir(&h, "a");
    h.write_user("[[tools]]\nname = \"solo\"\ncommand = \"/bin/echo\"\nmounts = [\"~/a:/a:ro\"]\n");
    let stderr = stderr_of(&h.launch(&[], "solo", &[]));
    assert!(stderr.contains(CONFIG_MARKER), "{stderr}");
    let help = String::from_utf8_lossy(&h.help().stdout).into_owned();
    assert!(help.contains("solo"), "{help}");
    assert!(
        !help
            .lines()
            .any(|line| line.trim_start().starts_with("claude")),
        "a custom catalog must not keep shipped verbs: {help}"
    );
}

/// #396 AC-identity: an unselected tool's source is never inspected, and a
/// *selected* missing source fails — the asymmetry that proves selection, not
/// configuration, decides inspection.
#[test]
fn unselected_tool_sources_are_not_inspected_and_selected_missing_fails() {
    let h = Harness::new();
    let _real = seed_dir(&h, "real");
    h.write_user(
        "[[tools]]\nname = \"good\"\ncommand = \"/bin/echo\"\nmounts = [\"~/real:/real:ro\"]\n\
         [[tools]]\nname = \"broken\"\ncommand = \"/bin/echo\"\n\
         mounts = [\"/nonexistent-agent-vm-396:/gone:ro\"]\n",
    );
    // The unselected tool's missing source cannot block the good launch.
    let stderr = stderr_of(&h.launch(&[], "good", &[]));
    assert!(stderr.contains(CONFIG_MARKER), "{stderr}");
    assert!(
        !sorted_binds(&debug_config_json(&stderr))
            .iter()
            .any(|(_, guest, _)| guest == "/gone")
    );
    // Selected, the same declaration fails at preparation and names its site.
    let before = h.snapshot();
    let out = h.launch(&[], "broken", &[]);
    h.assert_refused_before_launch_state(&out, &before, "tools[1].mounts[0]");
    // Under the opt-out the automatic selection is gone, so the once-failing verb
    // reaches the config dump.
    assert!(stderr_of(&h.launch(&["--no-config-mounts"], "broken", &[])).contains(CONFIG_MARKER));
}

/// #396 AC-identity: a fork's identity is its *declaration*, never the route that
/// selected it. Seeding once and then selecting the same source through the
/// defaults, a tool's own list, an inherited list, a set, a nested set and the
/// equivalent `--mount` — with the tools and sets renamed and their edges
/// reordered between launches — always reaches the same committed copy.
///
/// The source is deleted after seeding, so only a reused fork can satisfy the
/// binding, and the committed bytes are mutated in between so a reseed would be
/// visible as data, not just as a second directory.
#[test]
fn tool_and_inherited_forks_preserve_identity_across_every_selector() {
    let h = Harness::new();
    let src = seed_dir(&h, "src");
    h.write_user("mounts = [\"~/src:/f:fork\"]\n");
    let seeded = stderr_of(&h.launch(&[], "shell", &[]));
    assert_eq!(
        seeded.matches("==> Initialized fork").count(),
        1,
        "the first launch seeds exactly once: {seeded}"
    );
    let committed = only_fork_data(&h);
    std::fs::write(committed.join("marker"), "committed").unwrap();
    let manifest = committed.parent().unwrap().join("manifest.json");
    let identity = std::fs::read(&manifest).unwrap();
    // Remove the host source: only a reused copy can still be bound.
    std::fs::remove_file(src.join("marker")).unwrap();
    std::fs::remove_dir(&src).unwrap();

    let cli = format!("{}:/f:fork", src.display());
    // Every selector, each with different tool and set names and a different edge
    // order. The declaration itself is identical in all of them.
    let selectors: Vec<(&str, String, Vec<String>)> = vec![
        (
            "defaults",
            "mounts = [\"~/src:/f:fork\"]\n\
             [[tools]]\nname = \"solo\"\ncommand = \"/bin/echo\"\ntools = []\n"
                .to_string(),
            vec![],
        ),
        (
            "own tool list",
            "[[tools]]\nname = \"solo\"\ncommand = \"/bin/echo\"\ntools = []\n\
             mounts = [\"~/src:/f:fork\"]\n"
                .to_string(),
            vec![],
        ),
        (
            "inherited tool list",
            "[[tools]]\nname = \"solo\"\ncommand = \"/bin/echo\"\ntools = [\"helper\"]\n\
             mounts = []\n\
             [[tools]]\nname = \"helper\"\ncommand = \"/bin/echo\"\ntools = []\n\
             mounts = [\"~/src:/f:fork\"]\n"
                .to_string(),
            vec![],
        ),
        (
            "set",
            "[mount_sets]\nrenamed-set = [\"~/src:/f:fork\"]\n\
             [[tools]]\nname = \"solo\"\ncommand = \"/bin/echo\"\ntools = []\n\
             mounts = [\"renamed-set\"]\n"
                .to_string(),
            vec![],
        ),
        (
            "nested set, reordered edges",
            "[mount_sets]\ninner = [\"~/src:/f:fork\"]\nouter = [\"inner\"]\n\
             [[tools]]\nname = \"solo\"\ncommand = \"/bin/echo\"\ntools = [\"helper\"]\n\
             mounts = [\"outer\"]\n\
             [[tools]]\nname = \"helper\"\ncommand = \"/bin/echo\"\ntools = [\"leaf\"]\nmounts = []\n\
             [[tools]]\nname = \"leaf\"\ncommand = \"/bin/echo\"\ntools = []\nmounts = []\n"
                .to_string(),
            vec![],
        ),
        (
            "equivalent --mount",
            "[[tools]]\nname = \"solo\"\ncommand = \"/bin/echo\"\ntools = []\nmounts = []\n"
                .to_string(),
            vec!["--no-config-mounts".to_string(), "--mount".to_string(), cli.clone()],
        ),
    ];
    for (label, body, cli_options) in selectors {
        h.write_user(&body);
        let options: Vec<&str> = cli_options.iter().map(String::as_str).collect();
        let launch = h.launch(&options, "solo", &[]);
        let stderr = stderr_of(&launch);
        assert!(
            stderr.contains("==> Reusing fork"),
            "{label}: only reuse is allowed: {stderr}"
        );
        assert!(
            !stderr.contains("Initialized"),
            "{label}: a READY fork must not reseed: {stderr}"
        );
        assert!(
            bind_mounts(&debug_config_json(&stderr))
                .iter()
                .any(|(host, guest, _)| Path::new(host) == committed && guest == "/f"),
            "{label}: the committed copy must be bound"
        );
        assert_eq!(
            std::fs::read_to_string(committed.join("marker")).unwrap(),
            "committed",
            "{label}: the same committed copy"
        );
        assert_eq!(h.fork_dirs().len(), 1, "{label}: one fork, not two");
        assert_eq!(
            std::fs::read(&manifest).unwrap(),
            identity,
            "{label}: the manifest is unchanged"
        );
    }
}

/// #396 AC-guards: inherited mounts and declared persistence collide before any
/// fork is published, in both directions — own mount against inherited persist and
/// the converse — with an unrelated valid fork in the same closure so a
/// publish-then-check bug cannot pass.
#[test]
fn inherited_mounts_and_persist_collide_before_any_fork() {
    // The collide-able guest path is inside the guest HOME, which is what a
    // declared `persist = ["x-state"]` links under — only the running host knows
    // that prefix, so each row builds its declaration from it.
    for mount_on_launcher in [true, false] {
        let h = Harness::new();
        let _live = seed_dir(&h, "live");
        let _fork = seed_dir(&h, "fork-src");
        let shadow = format!("{}/x-state", h.home_root.display());
        let mount_list = format!("[\"~/live:{shadow}:ro\"]");
        let (launcher_mounts, other_mounts, launcher_persist, other_persist) = if mount_on_launcher
        {
            (mount_list.as_str(), "[]", "[]", "[\"x-state\"]")
        } else {
            ("[]", mount_list.as_str(), "[\"x-state\"]", "[]")
        };
        h.write_user(&format!(
            "[[tools]]\nname = \"t\"\ncommand = \"/bin/echo\"\ntools = [\"u\"]\n\
             mounts = {launcher_mounts}\npersist = {launcher_persist}\n\
             [[tools]]\nname = \"u\"\ncommand = \"/bin/echo\"\n\
             mounts = {other_mounts}\npersist = {other_persist}\n"
        ));
        let before = h.snapshot();
        let out = h.launch(&[], "t", &[]);
        let stderr = stderr_of(&out);
        assert!(
            stderr.contains("would collide with the guest mount point"),
            "mount_on_launcher={mount_on_launcher}: inherited mounts must be checked against \
             declared persistence: {stderr}"
        );
        assert!(
            !stderr.contains("Initialized fork"),
            "no fork may be published before the collision is refused: {stderr}"
        );
        assert!(!stderr.contains(CONFIG_MARKER), "{stderr}");
        assert_eq!(h.snapshot(), before, "{stderr}");
        assert!(h.fork_dirs().is_empty(), "{stderr}");
    }

    // An unrelated, otherwise valid fork in the same closure is *also* not
    // published: the check precedes every fork.
    let h = Harness::new();
    let _live = seed_dir(&h, "live");
    let _fork = seed_dir(&h, "fork-src");
    let shadow = format!("{}/x-state", h.home_root.display());
    h.write_user(&format!(
        "[[tools]]\nname = \"t\"\ncommand = \"/bin/echo\"\ntools = [\"u\"]\n\
         mounts = [\"~/fork-src:/f:fork\", \"~/live:{shadow}:ro\"]\n\
         [[tools]]\nname = \"u\"\ncommand = \"/bin/echo\"\npersist = [\"x-state\"]\n"
    ));
    let before = h.snapshot();
    let out = h.launch(&[], "t", &[]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("would collide with the guest mount point"),
        "{stderr}"
    );
    assert!(!stderr.contains("Initialized fork"), "{stderr}");
    assert!(h.fork_dirs().is_empty(), "{stderr}");
    assert_eq!(h.snapshot(), before, "{stderr}");
}

/// #396 AC-guards: every core, config-directory, protected-Pi, file and follow-link
/// guard runs for a tool-declared mount exactly as it does for `--mount`, and a
/// positive twin proves each guard is selective rather than "refuse every tool
/// mount".
#[test]
fn tool_mount_routes_retain_core_config_file_and_follow_guards() {
    // A core guest destination: refused, naming the tool origin, before any state.
    let h = Harness::new();
    let _src = seed_dir(&h, "src");
    h.write_user(
        "[[tools]]\nname = \"t\"\ncommand = \"/bin/echo\"\n\
         mounts = [\"~/src:/agent-vm-state:ro\"]\n",
    );
    let before = h.snapshot();
    let out = h.launch(&[], "t", &[]);
    h.assert_refused_before_launch_state(&out, &before, "tools[0].mounts[0] in");

    // A writable mount that would let the guest rewrite the config it was read
    // from: refused, and the tool's own site is named.
    let h = Harness::new();
    h.write_user(
        "[[tools]]\nname = \"t\"\ncommand = \"/bin/echo\"\ntools = []\n\
         mounts = [\"~/.config:rw\"]\n",
    );
    let before = h.snapshot();
    let out = h.launch(&[], "t", &[]);
    h.assert_refused_before_launch_state(&out, &before, "would let the guest change what");
    assert!(
        stderr_of(&out).contains(&h.user_config().parent().unwrap().display().to_string()),
        "{}",
        stderr_of(&out)
    );

    // A *live* bind of the host Pi home would disclose the real credentials; only
    // the `:fork` form omits them, and that is the positive twin below.
    let h = Harness::new();
    let auth = h.home_root.join(".pi/agent/auth.json");
    write_file(&auth, "{\"token\":\"host\"}");
    h.write_user("[[tools]]\nname = \"t\"\ncommand = \"/bin/echo\"\nmounts = [\"~/.pi:ro\"]\n");
    let before = h.snapshot();
    let out = h.launch(&[], "t", &[]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains(&format!(
            "would expose the host Pi credential file {}",
            auth.display()
        )),
        "{stderr}"
    );
    h.assert_refused_before_launch_state(&out, &before, "tools[0].mounts[0] in");
    assert_eq!(
        std::fs::read_to_string(&auth).unwrap(),
        "{\"token\":\"host\"}",
        "the refusal must not touch the host credential"
    );

    // A regular file mounted writable is refused (naming the tool site); the
    // read-only twin is accepted and bound read-only.
    let h = Harness::new();
    let file = h.home_root.join("plain.txt");
    std::fs::write(&file, "content").unwrap();
    h.write_user(&format!(
        "[[tools]]\nname = \"t\"\ncommand = \"/bin/echo\"\nmounts = [\"{}:/file:rw\"]\n",
        file.display()
    ));
    let before = h.snapshot();
    let out = h.launch(&[], "t", &[]);
    h.assert_refused_before_launch_state(&out, &before, "a file can only be mounted read-only");
    h.write_user(&format!(
        "[[tools]]\nname = \"t\"\ncommand = \"/bin/echo\"\nmounts = [\"{}:/file:ro\"]\n",
        file.display()
    ));
    let binds = verb_binds(&h, &[], "t");
    assert!(
        binds
            .iter()
            .any(|(_, guest, readonly)| guest == "/file" && *readonly),
        "{binds:?}"
    );

    // A `:fork` of a regular file is refused by the same sentence as a config
    // default's, naming the tool's site.
    let h = Harness::new();
    let file = h.home_root.join("plain.txt");
    std::fs::write(&file, "content").unwrap();
    h.write_user(&format!(
        "[[tools]]\nname = \"t\"\ncommand = \"/bin/echo\"\nmounts = [\"{}:/f:fork\"]\n",
        file.display()
    ));
    let before = h.snapshot();
    let out = h.launch(&[], "t", &[]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("a :fork source must be a directory"),
        "{stderr}"
    );
    assert!(stderr.contains("tools[0].mounts[0] in"), "{stderr}");
    h.assert_refused_before_launch_state(&out, &before, "a :fork source must be a directory");

    // Fork exclusions are a *seed* filter, not a mount: accepted through a tool
    // route, absent from the committed copy, present on the host.
    let h = Harness::new();
    let source = seed_excludable_source(&h);
    h.write_user(
        "[[tools]]\nname = \"t\"\ncommand = \"/bin/echo\"\n\
         mounts = [\"~/src:/f:fork:exclude=hidden\"]\n",
    );
    let stderr = stderr_of(&h.launch(&[], "t", &[]));
    assert!(stderr.contains("Initialized fork"), "{stderr}");
    let committed = only_fork_data(&h);
    assert_eq!(
        std::fs::read_to_string(committed.join("visible")).unwrap(),
        "visible"
    );
    assert!(
        !committed.join("hidden").exists(),
        "the excluded file must not be committed"
    );
    assert!(
        source.join("hidden").exists(),
        "the host source keeps the excluded file"
    );

    // `:follow-links` discovery through a tool route: the target is appended
    // read-only at the literal path the guest will `readlink`, and a target
    // outside `$HOME` is refused with the tool's own escaping.
    let h = Harness::new();
    let farm = seed_dir(&h, "farm");
    let real = seed_dir(&h, "real");
    std::os::unix::fs::symlink(&real, farm.join("link")).unwrap();
    h.write_user(
        "[[tools]]\nname = \"t\"\ncommand = \"/bin/echo\"\n\
         mounts = [\"~/farm:/farm:ro:follow-links\"]\n",
    );
    let binds = verb_binds(&h, &[], "t");
    assert!(
        binds.iter().any(
            |(host, guest, readonly)| *host == real.display().to_string()
                && *guest == real.display().to_string()
                && *readonly
        ),
        "the discovered target must be bound read-only at its real path: {binds:?}"
    );

    // A control character in a discovered *link* name cannot forge a diagnostic
    // line: the outside-`$HOME` refusal escapes it.
    let h = Harness::new();
    let farm = seed_dir(&h, "farm");
    let outside = tempfile::tempdir_in(support::workspace_tmpdir()).unwrap();
    let outside = outside.path().canonicalize().unwrap().join("target");
    std::fs::create_dir(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, farm.join("bad\nname")).unwrap();
    h.write_user(
        "[[tools]]\nname = \"t\"\ncommand = \"/bin/echo\"\n\
         mounts = [\"~/farm:/farm:ro:follow-links\"]\n",
    );
    let before = h.snapshot();
    let out = h.launch(&[], "t", &[]);
    let stderr = stderr_of(&out);
    assert!(stderr.contains("which is outside your $HOME"), "{stderr}");
    assert!(
        stderr.contains("bad\\x0aname"),
        "the discovered link name must be escaped: {stderr}"
    );
    assert!(
        !stderr
            .lines()
            .any(|line| line.trim() == "name\" resolves to"),
        "the name forged a diagnostic line: {stderr}"
    );
    h.assert_refused_before_launch_state(&out, &before, "which is outside your $HOME");
}

/// #396 AC-guards: an inherited read-write parent with a read-only child keeps both
/// modes in either declaration order, with the two leaves split across tools and
/// reached through a named set as well as directly.
///
/// This boot-free assertion is not the native write-denial oracle (no VM boots
/// here); it proves only that the planned modes survive the tool route.
#[test]
fn inherited_rw_parent_and_ro_child_keep_both_modes_in_either_order() {
    const PARENT: &str = "\"~/parent:/p\"";
    const CHILD: &str = "\"~/parent/child:/p/child:ro\"";
    // Every combination the plan names: both declaration orders, and the set leaf
    // carrying the parent or the child.
    for (order, parent_in_set) in [(0usize, false), (0, true), (1, false), (1, true)] {
        let h = Harness::new();
        let parent = seed_dir(&h, "parent");
        std::fs::create_dir(parent.join("child")).unwrap();
        std::fs::write(parent.join("child/marker"), "child").unwrap();
        std::fs::write(parent.join("marker"), "parent").unwrap();
        let declared = if order == 0 {
            [PARENT, CHILD]
        } else {
            [CHILD, PARENT]
        };
        // One leaf is direct on the launched tool, the other the same tool's set
        // reference; the referenced tool declares no mounts of its own.
        let direct = if parent_in_set {
            declared[1]
        } else {
            declared[0]
        };
        let in_set = if parent_in_set {
            declared[0]
        } else {
            declared[1]
        };
        h.write_user(&format!(
            "[mount_sets]\nleaf = [{in_set}]\n\
             [[tools]]\nname = \"t\"\ncommand = \"/bin/echo\"\ntools = [\"u\"]\n\
             mounts = [{direct}, \"leaf\"]\n\
             [[tools]]\nname = \"u\"\ncommand = \"/bin/echo\"\ntools = []\nmounts = []\n"
        ));
        let binds = verb_binds(&h, &[], "t");
        let mode = |guest: &str| {
            binds
                .iter()
                .find(|(_, path, _)| path == guest)
                .map(|(_, _, readonly)| *readonly)
                .unwrap_or_else(|| panic!("{guest} missing: {binds:?}"))
        };
        assert!(
            !mode("/p"),
            "order {order} set={parent_in_set}: the parent stays writable: {binds:?}"
        );
        assert!(
            mode("/p/child"),
            "order {order} set={parent_in_set}: the child stays read-only: {binds:?}"
        );
    }
}

/// #396 AC-guards: a **direct** command receives the user-wide defaults and an
/// explicit `--mount`, but never a tool's inherited closure — even when the
/// requested program has the same path as a tool's `command`.
///
/// Both direct spellings are covered, because they are one route with two
/// syntactic forms (issue #398).
#[test]
fn direct_commands_receive_no_tool_mounts() {
    let h = Harness::new();
    let _own = seed_dir(&h, "pi-home");
    let _default = seed_dir(&h, "default");
    let _cli = seed_dir(&h, "cli");
    h.write_user(
        "mounts = [\"~/default:/default:ro\"]\n\
         [[tools]]\nname = \"pi\"\ncommand = \"/bin/echo\"\ntools = []\n\
         mounts = [\"~/pi-home:/pi:ro\"]\n",
    );
    for form in ["run", "--"] {
        // The token is the *tool's* command, so a launcher that inferred a tool
        // from the program name would add the Pi closure here.
        let out = h.launch(&[], form, &["/bin/echo", "direct"]);
        let stderr = stderr_of(&out);
        assert!(
            stderr.contains(CONFIG_MARKER),
            "{form}: a direct command must still launch: {stderr}"
        );
        let guests: Vec<String> = sorted_binds(&debug_config_json(&stderr))
            .into_iter()
            .map(|(_, guest, _)| guest)
            .collect();
        assert!(
            guests.iter().any(|guest| guest == "/default"),
            "{form}: the user-wide default applies: {guests:?}"
        );
        assert!(
            !guests.iter().any(|guest| guest == "/pi"),
            "{form}: a tool's inherited mount must not reach a direct command: {guests:?}"
        );
    }
    // An explicit declaration still applies, so the negative above is not "the
    // direct route ignores every mount".
    let out = h.launch(
        &[
            "--mount",
            &format!("{}:/explicit:ro", h.home_root.join("cli").display()),
        ],
        "run",
        &["/bin/echo", "direct"],
    );
    let stderr = stderr_of(&out);
    assert!(
        sorted_binds(&debug_config_json(&stderr))
            .iter()
            .any(|(_, guest, _)| guest == "/explicit"),
        "an explicit --mount reaches a direct command: {stderr}"
    );
}
