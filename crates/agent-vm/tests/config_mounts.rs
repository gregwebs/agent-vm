//! Boot-free integration harness for verified user-wide default mounts
//! (issue #394 / ADR-0046) and for the launch-order guarantees they share with
//! `--mount`.
//!
//! Rust compiles each file in `tests/` as its own crate, so the helpers below
//! are duplicated per test binary on purpose — the same rule `tests/mount_fork.rs`
//! documents. Only a genuine cross-harness precondition lives in `tests/support/`.
//!
//! The file starts with the two **CLI-only** persisted-guest-HOME cases from
//! review finding B1 / decision D4: a mount that shadows a declared `persist`
//! path must be refused *inside* `mount::prepare`, i.e. before any fork is
//! published. They are CLI-only so they can be written (and observed failing)
//! before the config route exists at all; the config-mount rows land with it.
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
/// link under `guest_home`. Escaping is the config module's (`escape_path`), and
/// the harness's temp dirs contain no bytes it would rewrite.
fn persist_collision_message(guest_home: &str) -> String {
    format!(
        "Error: config: persist path code would collide with the guest mount point \
         {guest_home}/code; rename the persist path or move the mount"
    )
}

// ---------------------------------------------------------------------------
// B1 / D4 — a plan that would shadow a persist link never publishes a fork
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
    let binds = sorted_binds(&debug_config_json(&stderr));
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
        assert!(
            !stderr.contains(CONFIG_MARKER),
            "{argv:?}: no conflict may reach builder wiring: {stderr}"
        );
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
    h.assert_refused_before_launch_state(&out, &before, "would let the guest change what");
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
    h.assert_refused_before_launch_state(&out, &before, "would expose the host Pi credential file");
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
    h.assert_refused_before_launch_state(&out, &before, "a file can only be mounted read-only");
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
        stderr.contains(&format!("==> Initialized fork {}", src.display())),
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
        accepted_stderr.contains(&format!("==> Initialized fork {}", src.display())),
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
        seeded_stderr.contains(&format!("==> Initialized fork {}", src.display())),
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
        stderr.contains(&format!("==> Initialized fork {}/src", alias.display())),
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
    h.assert_refused_before_launch_state(&out, &before, "canonicalizing --mount host");
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
                "config: \"{}\": mounts: mounts cannot be declared by the project config",
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
