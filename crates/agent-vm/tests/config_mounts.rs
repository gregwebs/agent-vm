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
        let mut cmd = self.base_command();
        cmd.arg("--image").arg(&self.image);
        cmd.args(options);
        cmd.arg(verb);
        cmd.args(args);
        run_with_timeout(cmd, Duration::from_secs(60))
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
