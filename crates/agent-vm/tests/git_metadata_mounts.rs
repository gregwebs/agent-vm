//! Boot-free real-CLI seam for automatic Git metadata mounts (issue #535,
//! ADR-0062).
//!
//! Every row drives the compiled `agent-vm` binary against a *real* Git linked
//! worktree built by `git` itself, and reads the `SandboxConfig` the launch would
//! have booted. No VM, no approval store, no prompts: `stdin` is `/dev/null` in
//! every launch, so a row that needed a terminal or an approval would fail rather
//! than hang.
//!
//! Rust compiles each file in `tests/` as its own crate, so the harness helpers
//! below are duplicated per test binary on purpose — the same rule
//! `tests/config_mounts.rs` documents.
//!
//! Every fixture `git` invocation goes through [`fixture_git`], which clears the
//! environment and rebuilds an allow-list. A developer's
//! `worktree.useRelativePaths=true`, `GIT_DIR`, `GIT_COMMON_DIR`,
//! `GIT_CONFIG_PARAMETERS` or `GIT_INDEX_FILE` would otherwise change the shape
//! of the fixture or redirect Git despite `-C`, and every row here is about the
//! exact shape of `.git`.
//!
//! Every refusal assertion goes through
//! [`Harness::assert_refused_before_launch_state`], calibrated by
//! [`refusal_oracle_is_calibrated`].

use std::collections::BTreeMap;
use std::io::Read;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

mod support;

#[path = "support/image_archive.rs"]
mod image_archive;

#[path = "support/fake_msb.rs"]
mod fake_msb;

/// The `AGENT_VM_DEBUG_CONFIG` marker: printed immediately before the builder's
/// registry pull, so its presence proves the launch got past every preflight
/// boundary these rows are about.
const CONFIG_MARKER: &str = "[debug] sandbox config JSON: ";

/// The banner line emitted after `mount::prepare` returns; a refused plan must
/// never print it.
const BOOT_BANNER: &str = "==> Boot image: ";

/// The notice every row about an accepted plan asserts.
const NOTICE_RO: &str =
    "==> Git metadata: linked worktree, read-only (--git-mount=rw|off to change)";
const NOTICE_RW: &str = "==> Git metadata: linked worktree, writable:";
/// The two notices a launch prints when the guest already reaches the metadata
/// and no automatic mount was added. Neither may say "read-only": the metadata is
/// writable through the route that carries it.
const NOTICE_IN_PROJECT: &str = "==> Git metadata: linked worktree, inside the project bind \
                                (writable); no automatic mount was added";
const NOTICE_ENCLOSING: &str = "==> Git metadata: linked worktree, reachable through ";

fn agent_vm_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-vm"))
}

/// Run `cmd` to completion, killing it if it does not exit within `timeout`.
/// Duplicated from `tests/config_mounts.rs` for the reason in this file's module
/// comment.
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

// ---------------------------------------------------------------------------
// Fixture Git: a cleared environment and nothing else
// ---------------------------------------------------------------------------

/// Run `git` in `dir` under the fixture allow-list.
///
/// The allow-list is exhaustive on purpose: `env_clear()` plus the four names Git
/// cannot run without (`PATH`, `HOME`, and the two config overrides that pin
/// global and system config to `/dev/null`). The `-c` set makes a commit
/// reproducible without inheriting signing, hooks or an initial-branch policy,
/// and the repo-local identity is written with `git config` before the first
/// commit, never only through `-c`, so the *repository* is self-describing.
fn fixture_git(dir: &Path, home: &Path, args: &[&str]) -> Output {
    let mut cmd = Command::new("git");
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CEILING_DIRECTORIES", env!("CARGO_TARGET_TMPDIR"))
        .current_dir(dir)
        .stdin(Stdio::null())
        .args([
            "-c",
            "init.defaultBranch=main",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "protocol.file.allow=always",
        ])
        .args(args);
    cmd.output()
        .expect("git must be installed to run this harness")
}

/// [`fixture_git`] that panics with the fixture's own stderr on failure, so a
/// broken fixture is never reported as a product failure.
fn git_ok(dir: &Path, home: &Path, args: &[&str]) -> String {
    let out = fixture_git(dir, home, args);
    assert!(
        out.status.success(),
        "fixture git {args:?} failed in {}: {}",
        dir.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// `to` expressed relative to the directory `from`, component-wise. Enough for
/// the fixture rewrites; no filesystem access, so it works on paths that do not
/// exist yet.
fn relative_path(from: &Path, to: &Path) -> PathBuf {
    let from_components: Vec<_> = from.components().collect();
    let to_components: Vec<_> = to.components().collect();
    let shared = from_components
        .iter()
        .zip(&to_components)
        .take_while(|(a, b)| a == b)
        .count();
    let mut out = PathBuf::new();
    for _ in shared..from_components.len() {
        out.push("..");
    }
    for component in &to_components[shared..] {
        out.push(component.as_os_str());
    }
    out
}

// ---------------------------------------------------------------------------
// Snapshot: everything a refused launch must leave untouched
// ---------------------------------------------------------------------------

type Snapshot = BTreeMap<String, String>;

/// The pre-launch state a refused plan must leave untouched, plus the watermark
/// for the fake runtime's invocation log.
///
/// That log accumulates across every launch in one test binary, and a preceding
/// *successful* launch legitimately logs the launch-protocol probe and the
/// machine invocation. A refusal can only answer for the invocations it runs
/// itself, so the oracle compares [`Before::entries`] and inspects only the
/// lines appended after [`Before::invocation_lines`].
struct Before {
    entries: Snapshot,
    invocation_lines: usize,
}

fn tree_of(label: &str, root: &Path, out: &mut Snapshot) {
    let Ok(read) = std::fs::read_dir(root) else {
        return;
    };
    for entry in read {
        let entry = entry.unwrap();
        let relative = entry.path().strip_prefix(root).unwrap().to_path_buf();
        // The key is the *root-relative* path, built from the key of the directory
        // being read: two files with the same basename in different directories
        // must not collapse into one entry, which is what made a nested change
        // invisible to every refusal row.
        let key = if label.is_empty() {
            relative.display().to_string()
        } else {
            format!("{label}/{}", relative.display())
        };
        let metadata = std::fs::symlink_metadata(entry.path()).unwrap();
        // Mode is part of the snapshot: a `chmod` changes what a launch left
        // behind even when every byte is identical.
        let mode = metadata.mode() & 0o7777;
        let description = if metadata.is_dir() {
            tree_of(&key, &entry.path(), out);
            format!("directory:{mode:o}")
        } else if metadata.file_type().is_symlink() {
            let target = std::fs::read_link(entry.path()).unwrap();
            format!("symlink:{mode:o}:{:?}", target.as_os_str())
        } else {
            let bytes = std::fs::read(entry.path()).unwrap();
            format!("file:{mode:o}:{}:{:016x}", bytes.len(), digest(&bytes))
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

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct Harness {
    _home: tempfile::TempDir,
    _state: tempfile::TempDir,
    _project: tempfile::TempDir,
    _runtime: tempfile::TempDir,
    home_root: PathBuf,
    project_root: PathBuf,
    state_root: PathBuf,
    image: String,
    fake_msb: fake_msb::FakeMsb,
}

impl Harness {
    fn new() -> Self {
        let home = tempfile::tempdir_in(support::workspace_tmpdir()).unwrap();
        let state = tempfile::tempdir_in("/tmp").unwrap();
        let project = support::project_tempdir();
        let runtime = tempfile::tempdir_in("/tmp").unwrap();
        let home_root = home.path().canonicalize().unwrap();
        let project_root = project.path().canonicalize().unwrap();
        let state_root = state.path().canonicalize().unwrap();
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

    /// Import a host-valid image under this harness's state root, with a
    /// throwaway HOME so the fixture never approves anything for the real one.
    fn import_fixture_image(&self) {
        let archive = self.home_root.join("fixture-boot.tar");
        image_archive::write(&archive, &image_archive::ArchiveSpec::default());
        let seed_home = tempfile::Builder::new()
            .prefix("av-seed-home-")
            .tempdir()
            .unwrap();
        let mut import = Command::new(agent_vm_bin());
        import
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", seed_home.path())
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
    }

    fn project_config(&self) -> PathBuf {
        self.project_root.join(".agent-vm/config.toml")
    }

    fn write_project(&self, contents: &str) {
        write_file(&self.project_config(), contents);
    }

    fn user_config(&self) -> PathBuf {
        self.home_root.join(".config/agent-vm/config.toml")
    }

    /// The shape the verified-read policy expects: a 0600 file in a 0700 dir.
    fn write_user(&self, contents: &str) {
        use std::os::unix::fs::PermissionsExt;
        let path = self.user_config();
        write_file(&path, contents);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(
            path.parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }

    fn base_command(&self) -> Command {
        let mut cmd = Command::new(agent_vm_bin());
        cmd.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", &self.home_root)
            .env("AGENT_VM_STATE_DIR", &self.state_root)
            .env("MSB_PATH", &self.fake_msb.path)
            .env("AGENT_VM_DEBUG_CONFIG", "1")
            .env("GIT_CEILING_DIRECTORIES", env!("CARGO_TARGET_TMPDIR"))
            // No terminal and no prompt: a row that needed one would fail here
            // rather than wait, which is the "no prompt, no approval" evidence.
            .stdin(Stdio::null())
            .current_dir(&self.project_root);
        cmd
    }

    fn launch(&self, options: &[&str], verb: &str, args: &[&str]) -> Output {
        self.launch_in(&self.project_root, options, verb, args)
    }

    /// [`Self::launch_in`] with the state root overridden, for a row whose point is
    /// that agent-vm's own state lives inside the metadata directory.
    fn launch_in_with_state(
        &self,
        dir: &Path,
        state: &Path,
        options: &[&str],
        verb: &str,
        args: &[&str],
    ) -> Output {
        let mut cmd = self.base_command();
        cmd.env("AGENT_VM_STATE_DIR", state);
        cmd.current_dir(dir);
        cmd.arg("--image").arg(&self.image);
        cmd.args(options);
        cmd.arg(verb);
        cmd.args(args);
        run_with_timeout(cmd, Duration::from_secs(90))
    }

    fn launch_in(&self, dir: &Path, options: &[&str], verb: &str, args: &[&str]) -> Output {
        let mut cmd = self.base_command();
        cmd.current_dir(dir);
        cmd.arg("--image").arg(&self.image);
        cmd.args(options);
        cmd.arg(verb);
        cmd.args(args);
        run_with_timeout(cmd, Duration::from_secs(90))
    }

    /// The mount store (`<state>/<hash>.mounts`), if one exists. Its absence is
    /// the observable "no fork was published / nothing was staged" signal.
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

    /// Capture the pre-launch state for [`Harness::assert_refused_before_launch_state`].
    fn before(&self) -> Before {
        Before {
            entries: self.snapshot(),
            invocation_lines: self.msb_log().lines().count(),
        }
    }

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

    /// The refusal oracle. [`refusal_oracle_is_calibrated`] is what keeps it from
    /// being vacuous.
    fn assert_refused_before_launch_state(&self, out: &Output, before: &Before, needle: &str) {
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
            before.entries,
            "a refused plan must not create or mutate launch state: {stderr}"
        );
        // Only what this launch appended: an earlier accepted launch in the
        // same test already logged its own probes.
        for line in self.msb_log().lines().skip(before.invocation_lines) {
            let first = line.split_whitespace().next().unwrap_or_default();
            assert_eq!(
                first, "--version",
                "a refused plan may only probe the runtime version, saw {line:?}"
            );
        }
    }

    fn msb_log(&self) -> String {
        std::fs::read_to_string(&self.fake_msb.invocations).unwrap_or_default()
    }
}

fn write_file(path: &Path, contents: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

// ---------------------------------------------------------------------------
// The fixture layouts
// ---------------------------------------------------------------------------

/// A fixture step that starts from a cleared project root.
type Setup = Box<dyn Fn(&Harness)>;

/// A fixture step that breaks one fact of a built [`Repo`].
type Breaker = Box<dyn Fn(&Repo)>;

/// One real Git linked worktree, plus the two directories the feature is about.
struct Repo {
    /// `$HOME/repos/main` — the main checkout, inside the snapshotted HOME so a
    /// launch that rewrote it would be caught.
    main: PathBuf,
    /// The harness project root: a linked worktree of `main`.
    worktree: PathBuf,
    /// `main/.git` — the common directory.
    common: PathBuf,
    /// `main/.git/worktrees/<id>` — this worktree's own metadata.
    per_worktree: PathBuf,
}

impl Repo {
    fn dot_git(&self) -> PathBuf {
        self.worktree.join(".git")
    }

    fn write_pointer(&self, text: &str) {
        std::fs::write(self.dot_git(), text).unwrap();
    }

    fn write_back_pointer(&self, text: &str) {
        std::fs::write(self.per_worktree.join("gitdir"), text).unwrap();
    }

    fn write_commondir(&self, text: &str) {
        std::fs::write(self.per_worktree.join("commondir"), text).unwrap();
    }

    /// The tree digest of the common directory, for "no pointer or config file
    /// was rewritten".
    fn common_tree(&self) -> Snapshot {
        let mut out = Snapshot::new();
        tree_of("git", &self.common, &mut out);
        out
    }
}

/// Build a real linked worktree at `harness.project_root`, from a real main
/// checkout at `$HOME/repos/main`. Everything happens before any snapshot.
fn build_worktree(harness: &Harness) -> Repo {
    let repos = harness.home_root.join("repos");
    let _ = std::fs::remove_dir_all(&repos);
    clear_dir(&harness.project_root);
    std::fs::create_dir_all(&repos).unwrap();
    let main = repos.join("main");
    std::fs::create_dir(&main).unwrap();
    git_ok(&main, &harness.home_root, &["init", "-q"]);
    // Repo-local identity, signing and hooks *before* the first commit: the
    // fixture must be able to commit without whatever the host or image config
    // says, and `-c` alone would leave the repository depending on the caller.
    for (key, value) in [
        ("user.name", "gm"),
        ("user.email", "gm@example.invalid"),
        ("commit.gpgsign", "false"),
        ("tag.gpgsign", "false"),
        ("core.hooksPath", "/dev/null"),
    ] {
        git_ok(&main, &harness.home_root, &["config", key, value]);
    }
    std::fs::write(main.join("tracked.txt"), "seed\n").unwrap();
    git_ok(&main, &harness.home_root, &["add", "tracked.txt"]);
    git_ok(&main, &harness.home_root, &["commit", "-q", "-m", "seed"]);
    let worktree = harness.project_root.clone();
    git_ok(
        &main,
        &harness.home_root,
        &[
            "worktree",
            "add",
            "-q",
            worktree.to_str().unwrap(),
            "-b",
            "wt",
        ],
    );
    let common = main.join(".git");
    let per_worktree = only_worktree_dir(&common);
    Repo {
        main,
        worktree,
        common,
        per_worktree,
    }
}

/// The one `worktrees/<id>` a fixture has, so a rename or a re-run cannot leave
/// the tests guessing.
fn only_worktree_dir(common: &Path) -> PathBuf {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(common.join("worktrees"))
        .expect("a linked worktree registers one directory")
        .map(|entry| entry.unwrap().path())
        .collect();
    entries.sort();
    assert_eq!(entries.len(), 1, "one worktree: {entries:?}");
    entries.pop().unwrap()
}

fn clear_dir(dir: &Path) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if std::fs::symlink_metadata(&path).unwrap().is_dir() {
            std::fs::remove_dir_all(&path).unwrap();
        } else {
            std::fs::remove_file(&path).unwrap();
        }
    }
}

/// A bare repository at `dir` with one commit on `main`, then a worktree of it at
/// the harness project root. The bind for a bare repository is the whole
/// directory, which is why the protection rows can put one at `$HOME/.pi`.
fn build_bare_worktree(harness: &Harness, dir: &Path) {
    clear_dir(&harness.project_root);
    std::fs::create_dir_all(dir).unwrap();
    git_ok(dir, &harness.home_root, &["init", "-q", "--bare"]);
    let scratch = harness.home_root.join("scratch");
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir(&scratch).unwrap();
    git_ok(&scratch, &harness.home_root, &["init", "-q"]);
    for (key, value) in [
        ("user.name", "gm"),
        ("user.email", "gm@example.invalid"),
        ("commit.gpgsign", "false"),
        ("core.hooksPath", "/dev/null"),
    ] {
        git_ok(&scratch, &harness.home_root, &["config", key, value]);
    }
    std::fs::write(scratch.join("tracked.txt"), "seed\n").unwrap();
    git_ok(&scratch, &harness.home_root, &["add", "tracked.txt"]);
    git_ok(
        &scratch,
        &harness.home_root,
        &["commit", "-q", "-m", "seed"],
    );
    git_ok(
        &scratch,
        &harness.home_root,
        &["push", "-q", dir.to_str().unwrap(), "HEAD:main"],
    );
    git_ok(
        dir,
        &harness.home_root,
        &[
            "--git-dir",
            dir.to_str().unwrap(),
            "worktree",
            "add",
            "-q",
            harness.project_root.to_str().unwrap(),
            "main",
        ],
    );
    let _ = std::fs::remove_dir_all(&scratch);
}

/// A `$HOME/.pi` that is a bare repository *and* holds a protected Pi credential
/// file, which is what makes the automatic bind a Pi refusal.
fn build_bare_pi(harness: &Harness) {
    build_bare_worktree(harness, &harness.home_root.join(".pi"));
    write_file(
        &harness.home_root.join(".pi/agent/auth.json"),
        "{\"token\":\"SENTINEL-535\"}\n",
    );
}

// ---------------------------------------------------------------------------
// Reading a launch
// ---------------------------------------------------------------------------

/// The `Bind` mounts of a dumped `SandboxConfig` as `(host, guest, readonly)`.
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

fn sorted_binds(config: &serde_json::Value) -> Vec<(String, String, bool)> {
    let mut binds = bind_mounts(config);
    // The builder stores mounts in a hash-ordered collection, so the order is
    // run-dependent; the mount *set* is what a row may compare.
    binds.sort();
    binds
}

/// The automatic Git metadata binds: every bind whose guest lives under the
/// fixture's `$HOME` and is not one of the three core binds. Identifying them by
/// the fixture's own root is what keeps a core bind out while any metadata
/// spelling — including a symlinked one — stays visible.
fn automatic_binds(harness: &Harness, config: &serde_json::Value) -> Vec<(String, String, bool)> {
    let home = harness.home_root.display().to_string();
    // The three core binds are never automatic, whatever their guest path looks
    // like; excluding them by identity is what keeps a `$HOME`-shaped automatic
    // bind visible while the guest-HOME bind stays out.
    let core = [
        home.clone(),
        harness.project_root.display().to_string(),
        "/agent-vm-state".to_string(),
    ];
    let mut found: Vec<(String, String, bool)> = bind_mounts(config)
        .into_iter()
        .filter(|(_, guest, _)| !core.contains(guest))
        .filter(|(_, guest, _)| guest == &home || guest.starts_with(&format!("{home}/")))
        .collect();
    found.sort();
    found
}

/// Parse the dumped config, asserting the launch reached builder wiring.
fn reached_builder(out: &Output) -> (serde_json::Value, String) {
    let stderr = stderr_of(out);
    assert!(
        stderr.contains(CONFIG_MARKER),
        "expected the launch to reach builder wiring: {stderr}"
    );
    let idx = stderr.find(CONFIG_MARKER).unwrap() + CONFIG_MARKER.len();
    let config = serde_json::Deserializer::from_str(&stderr[idx..])
        .into_iter::<serde_json::Value>()
        .next()
        .unwrap_or_else(|| panic!("no JSON value after the debug marker: {stderr}"))
        .unwrap_or_else(|e| panic!("debug config JSON failed to parse: {e}\n{stderr}"));
    (config, stderr)
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

/// The `[debug] guest command: …` payload: what the runtime would have executed.
fn guest_command(stderr: &str) -> String {
    const MARKER: &str = "[debug] guest command: ";
    stderr
        .lines()
        .find_map(|line| line.strip_prefix(MARKER))
        .unwrap_or_else(|| panic!("no guest command in stderr:\n{stderr}"))
        .to_string()
}

/// `(canonical host, guest, readonly)` for the one bind a fixture's common
/// directory should carry.
fn common_bind(repo: &Repo, readonly: bool) -> (String, String, bool) {
    let host = repo.common.canonicalize().unwrap();
    (
        host.display().to_string(),
        host.display().to_string(),
        readonly,
    )
}

fn tool_without_persist() -> &'static str {
    "[[tools]]\nname = \"aider\"\ncommand = \"/bin/echo\"\ncredentials = []\n"
}

// ---------------------------------------------------------------------------
// T0 — the refusal oracle is calibrated
// ---------------------------------------------------------------------------

/// T0. A refused and an accepted launch must differ in snapshot *and* in whether
/// the runtime was reached; otherwise every "nothing changed" assertion in this
/// file would pass for the wrong reason.
#[test]
fn refusal_oracle_is_calibrated() {
    let h = Harness::new();
    let repo = build_worktree(&h);
    // Refused: `off` is not it — a broken pointer is.
    repo.write_pointer("not a gitdir line\n");
    let before = h.before();
    let refused = h.launch(&[], "shell", &[]);
    h.assert_refused_before_launch_state(&refused, &before, "git worktree repair");

    // Accepted: the real layout.
    let repo = build_worktree(&h);
    let _ = repo;
    let before = h.before();
    let accepted = h.launch(&[], "shell", &[]);
    let (_, stderr) = reached_builder(&accepted);
    assert!(stderr.contains(NOTICE_RO), "{stderr}");
    assert_ne!(
        h.snapshot(),
        before.entries,
        "an accepted plan must mutate launch state: {stderr}"
    );

    // The snapshot itself: a nested path keeps its ancestors, and the mode is
    // part of the record. Without either, "nothing changed" could be true of a
    // launch that rewrote one of two same-named files or `chmod`ed what it found.
    let nested = h.home_root.join("nested");
    write_file(&nested.join("a/same.txt"), "one\n");
    write_file(&nested.join("b/same.txt"), "one\n");
    write_file(&nested.join("a/b/c/depth3.txt"), "deep\n");
    let before = h.before();
    std::fs::write(nested.join("b/same.txt"), "two\n").unwrap();
    assert_ne!(
        h.snapshot(),
        before.entries,
        "a change to one of two same-named files in different directories"
    );
    let before = h.before();
    std::fs::write(nested.join("a/b/c/depth3.txt"), "deeper\n").unwrap();
    assert_ne!(h.snapshot(), before.entries, "a depth-3 change");
    use std::os::unix::fs::PermissionsExt as _;
    let before = h.before();
    std::fs::set_permissions(
        nested.join("a/same.txt"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert_ne!(h.snapshot(), before.entries, "a mode-only change");
}

// ---------------------------------------------------------------------------
// T1, T2 — layout A: one read-only bind for the common directory
// ---------------------------------------------------------------------------

/// T1. The default mode binds the common directory once, at its host paths,
/// read-only, with a notice; nothing in the repository is rewritten.
#[test]
fn default_mode_binds_the_common_directory_once() {
    let h = Harness::new();
    let repo = build_worktree(&h);
    let tree_before = repo.common_tree();

    let out = h.launch(&[], "shell", &[]);
    let (config, stderr) = reached_builder(&out);
    assert_eq!(
        automatic_binds(&h, &config),
        vec![common_bind(&repo, true)],
        "{stderr}"
    );
    assert!(stderr.contains(NOTICE_RO), "{stderr}");
    assert_eq!(
        repo.common_tree(),
        tree_before,
        "the launch must not rewrite the pointer, `commondir` or any config file"
    );

    // T1b: the explicit spelling of the same policy is the identical plan.
    let explicit = h.launch(&["--git-mount=ro"], "shell", &[]);
    let (explicit_config, explicit_stderr) = reached_builder(&explicit);
    assert_eq!(
        sorted_binds(&explicit_config),
        sorted_binds(&config),
        "an explicit `--git-mount=ro` must not change the plan: {explicit_stderr}"
    );
    assert!(explicit_stderr.contains(NOTICE_RO), "{explicit_stderr}");
}

/// T2. Only `.git` metadata directories are bound — never the checkout that
/// contains them, and never a path outside the two metadata directories.
#[test]
fn only_metadata_directories_are_bound() {
    let h = Harness::new();
    let repo = build_worktree(&h);
    let out = h.launch(&[], "shell", &[]);
    let (config, stderr) = reached_builder(&out);
    let common = repo.common.canonicalize().unwrap();
    for (host, guest, _) in automatic_binds(&h, &config) {
        assert_eq!(host, guest, "spelled at its host path: {stderr}");
        let path = PathBuf::from(&host);
        assert!(
            path.starts_with(&common),
            "every automatic bind is inside the common directory: {host} in {stderr}"
        );
        let relative = path.strip_prefix(&common).unwrap();
        let first = relative.components().next();
        assert_ne!(
            first.map(|component| component.as_os_str().to_str().unwrap().to_string()),
            Some("tracked.txt".to_string()),
            "never a worktree file: {host}"
        );
    }
    // The main checkout itself is never a bind.
    assert!(
        !bind_mounts(&config)
            .iter()
            .any(|(host, _, _)| host == &repo.main.display().to_string()),
        "the main checkout is never bound: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// T2b — the common directory must not contain another checkout
// ---------------------------------------------------------------------------

/// A bare repository at `bare` with the launch worktree at the harness project
/// root, plus one **registered** worktree *inside* `bare`, which is ordinary Git
/// and not a forgery. Returns the inner checkout's directory.
fn build_bare_with_inner_worktree(h: &Harness, bare: &Path) -> PathBuf {
    build_bare_worktree(h, bare);
    let inner = bare.join("other");
    git_ok(
        bare,
        &h.home_root,
        &[
            "--git-dir",
            bare.to_str().unwrap(),
            "worktree",
            "add",
            "-q",
            inner.to_str().unwrap(),
            "-b",
            "other",
        ],
    );
    write_file(&inner.join("SECRET-OTHER.txt"), "SENTINEL-OTHER\n");
    inner
}

/// The `worktrees/<id>` entry whose `gitdir` back-pointer names `checkout`'s
/// `.git`, so a row can spell that registration through an alias without
/// guessing Git's id. The bare fixture already has two registrations.
fn registration_of(common: &Path, checkout: &Path) -> PathBuf {
    let wanted = checkout.join(".git").canonicalize().unwrap();
    for entry in std::fs::read_dir(common.join("worktrees")).unwrap() {
        let path = entry.unwrap().path();
        let Ok(text) = std::fs::read_to_string(path.join("gitdir")) else {
            continue;
        };
        if Path::new(text.trim()).canonicalize().ok().as_deref() == Some(wanted.as_path()) {
            return path;
        }
    }
    panic!("no registration names {}", wanted.display());
}

/// T2b. A bare common directory is all metadata, so it is bound whole — which is
/// only safe while no other checkout lives inside it. Two Git-produced layouts
/// put one there, and both must be refused in `ro` *and* `rw` rather than handed
/// over:
///
/// - a worktree created inside the bare directory;
/// - the same, reached through a symlinked alias of the bare directory, where the
///   guest spelling hides both the containment and the project.
///
/// The positive control is the same bare layout with every worktree outside it:
/// that bind is the feature working, not an oversight.
#[test]
fn a_common_directory_containing_another_checkout_is_refused() {
    for options in [&[][..], &["--git-mount=rw"][..]] {
        // (a) A registered worktree inside the bare directory.
        let h = Harness::new();
        let bare = h.home_root.join("repos/bare");
        let inner = build_bare_with_inner_worktree(&h, &bare);
        let before = h.before();
        let out = h.launch(options, "shell", &[]);
        let stderr = stderr_of(&out);
        h.assert_refused_before_launch_state(&out, &before, "contains the checkout");
        assert!(
            stderr.contains(&format!("{}", inner.canonicalize().unwrap().display())),
            "(a) {options:?}: the refusal names the checkout it found: {stderr}"
        );
        assert!(
            stderr.contains("--git-mount=off"),
            "(a) {options:?}: the refusal names the opt-out: {stderr}"
        );
        assert!(
            !stderr.contains("git worktree repair"),
            "(a) {options:?}: a layout refusal, not a relationship one: {stderr}"
        );
        // No other checkout's source text reaches the plan.
        assert!(
            !stderr.contains("SECRET-OTHER"),
            "(a) {options:?}: {stderr}"
        );

        // (b) The same layout, spelled through a symlink to the bare directory:
        //     the guest path looks like an unrelated alias, so neither the
        //     nested checkout nor the project's own position is visible lexically.
        let h = Harness::new();
        let bare = h.home_root.join("repos/bare");
        let inner = build_bare_with_inner_worktree(&h, &bare);
        let alias = h.home_root.join("alias");
        std::os::unix::fs::symlink(bare.canonicalize().unwrap(), &alias).unwrap();
        let id = registration_of(&bare, &inner);
        let id = id.file_name().unwrap().to_os_string();
        let mut spelled = alias.join("worktrees");
        spelled.push(&id);
        std::fs::write(
            inner.join(".git"),
            format!("gitdir: {}\n", spelled.display()),
        )
        .unwrap();
        let before = h.before();
        let out = h.launch_in(&inner, options, "shell", &[]);
        h.assert_refused_before_launch_state(&out, &before, "contains the checkout");

        // (c) `off` still launches both, which is what makes the refusal a mount
        //     decision rather than a broken repository. The project bind here is
        //     the inner checkout, not the harness root, so the observable is "the
        //     bare directory is not bound under any spelling".
        let bare_path = bare.canonicalize().unwrap().display().to_string();
        let off = h.launch_in(&inner, &["--git-mount=off"], "shell", &[]);
        let (config, off_stderr) = reached_builder(&off);
        assert!(
            !bind_mounts(&config)
                .iter()
                .any(|(host, guest, _)| host == &bare_path || guest == &bare_path),
            "(c) {options:?}: `off` binds no metadata: {off_stderr}"
        );
        assert!(
            !off_stderr.contains("==> Git metadata:"),
            "(c) {options:?}: `off` prints no Git metadata notice: {off_stderr}"
        );
    }

    // (d) The positive control: a bare common directory whose every worktree is
    //     outside it is the accepted layout, in both modes.
    for (options, readonly) in [(Vec::new(), true), (vec!["--git-mount=rw"], false)] {
        let h = Harness::new();
        let bare = h.home_root.join("repos/bare");
        build_bare_worktree(&h, &bare);
        let bare = bare.canonicalize().unwrap();
        let out = h.launch(&options, "shell", &[]);
        let (config, stderr) = reached_builder(&out);
        let host = bare.display().to_string();
        assert_eq!(
            automatic_binds(&h, &config),
            vec![(host.clone(), host, readonly)],
            "(d) {options:?}: a bare repository with no checkout inside it is all metadata: \
             {stderr}"
        );
    }
}

// ---------------------------------------------------------------------------
// T2c — the common directory must not contain agent-vm's own host sources
// ---------------------------------------------------------------------------

/// T2c. The containment also has to hold for agent-vm's **own** binds, measured on
/// their canonical host paths: a guest spelling can make a metadata directory look
/// unrelated to the directory it really exposes. Here the pointer goes through a
/// symlinked alias of a bare directory whose only worktree is outside it, and the
/// launcher's state lives *inside* that bare directory, so `covers_core` is true
/// only on the host half — and under `rw` the whole extra route, state included,
/// would be writable.
#[test]
fn a_common_directory_containing_the_state_source_is_refused() {
    for options in [&[][..], &["--git-mount=rw"][..]] {
        let h = Harness::new();
        let bare = h.home_root.join("b");
        build_bare_worktree(&h, &bare);
        let bare_host = bare.canonicalize().unwrap();
        // The guest spelling names neither the bare directory nor the project.
        let alias = h.home_root.join("core-alias");
        std::os::unix::fs::symlink(&bare_host, &alias).unwrap();
        let id = registration_of(&bare, &h.project_root);
        let id = id.file_name().unwrap().to_os_string();
        let mut spelled = alias.join("worktrees");
        spelled.push(&id);
        std::fs::write(
            h.project_root.join(".git"),
            format!("gitdir: {}\n", spelled.display()),
        )
        .unwrap();
        // The state source the guest would get at `/agent-vm-state`.
        let state = h.home_root.join("b/s");

        let before = h.before();
        let out = h.launch_in_with_state(&h.project_root, &state, options, "shell", &[]);
        let stderr = stderr_of(&out);
        h.assert_refused_before_launch_state(
            &out,
            &before,
            "contains one of agent-vm's own mounts",
        );
        assert!(
            stderr.contains(&bare_host.display().to_string()),
            "{options:?}: the refusal names the directory: {stderr}"
        );
        assert!(
            stderr.contains("--git-mount=off") && !stderr.contains("git worktree repair"),
            "{options:?}: a layout refusal with its own remedy: {stderr}"
        );

        // `off` still launches it: the registration is intact, and what refused the
        // plan was where the bind would have reached. This row uses the harness's
        // own state root — the point is the layout, and a nested state path under
        // `$TMPDIR` would exceed the platform's control-socket budget first.
        let off = h.launch_in(&h.project_root, &["--git-mount=off"], "shell", &[]);
        let (config, off_stderr) = reached_builder(&off);
        assert!(
            !bind_mounts(&config).iter().any(|(host, guest, _)| {
                host == &bare_host.display().to_string()
                    || guest == &bare_host.display().to_string()
            }),
            "{options:?}: `off` binds no metadata: {off_stderr}"
        );
    }
}

// ---------------------------------------------------------------------------
// T3, T4 — `rw` is per launch; `off` skips discovery
// ---------------------------------------------------------------------------

/// T3. `--git-mount=rw` binds writable, and the next launch with no option is
/// read-only again: nothing about the mode is persisted.
#[test]
fn writable_mode_is_per_launch_and_never_persisted() {
    let h = Harness::new();
    let repo = build_worktree(&h);

    let rw = h.launch(&["--git-mount=rw"], "shell", &[]);
    let (rw_config, rw_stderr) = reached_builder(&rw);
    assert_eq!(
        automatic_binds(&h, &rw_config),
        vec![common_bind(&repo, false)],
        "{rw_stderr}"
    );
    assert!(rw_stderr.contains(NOTICE_RW), "{rw_stderr}");

    let plain = h.launch(&[], "shell", &[]);
    let (plain_config, plain_stderr) = reached_builder(&plain);
    assert_eq!(
        automatic_binds(&h, &plain_config),
        vec![common_bind(&repo, true)],
        "the next launch is read-only again: {plain_stderr}"
    );
    assert!(plain_stderr.contains(NOTICE_RO), "{plain_stderr}");

    // No store, notice or config file records the mode.
    for root in [h.home_root.join(".config/agent-vm"), h.state_root.clone()] {
        // `--git-mount` and `git_mount`, not the bare `git-mount`: this
        // checkout is called `agent-vm-git-mount`, and every generated guest
        // config records the project path.
        assert_no_file_mentions(&root, "--git-mount");
        assert_no_file_mentions(&root, "git_mount");
    }
}

/// Walk `root` and assert no regular file's bytes contain `needle`.
fn assert_no_file_mentions(root: &Path, needle: &str) {
    let Ok(read) = std::fs::read_dir(root) else {
        return;
    };
    for entry in read {
        let path = entry.unwrap().path();
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        if metadata.is_dir() {
            assert_no_file_mentions(&path, needle);
        } else if metadata.file_type().is_file() {
            let bytes = std::fs::read(&path).unwrap();
            let text = String::from_utf8_lossy(&bytes);
            assert!(
                !text.contains(needle),
                "{} records {needle:?}",
                path.display()
            );
        }
    }
}

/// T4. `--git-mount=off` adds nothing and says nothing, so the plan is the core
/// plan an ordinary launch gets.
#[test]
fn off_mode_adds_no_bind_and_no_notice() {
    let h = Harness::new();
    let _repo = build_worktree(&h);
    let out = h.launch(&["--git-mount=off"], "shell", &[]);
    let (config, stderr) = reached_builder(&out);
    assert!(
        automatic_binds(&h, &config).is_empty(),
        "`off` adds no bind: {stderr}"
    );
    assert!(
        !stderr.contains("==> Git metadata:"),
        "`off` prints no notice: {stderr}"
    );
    assert_eq!(
        sorted_binds(&config).len(),
        3,
        "only the three core binds remain: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// T5, T6 — spelled pointers and symlinked spellings
// ---------------------------------------------------------------------------

/// T5. A relative `.git` pointer and a relative back-pointer resolve to the same
/// bind as the absolute spelling.
#[test]
fn relative_pointers_resolve_to_the_same_bind() {
    let h = Harness::new();
    let repo = build_worktree(&h);
    let relative = relative_path(&repo.worktree, &repo.per_worktree);
    repo.write_pointer(&format!("gitdir: {}\n", relative.display()));
    let back = relative_path(&repo.per_worktree, &repo.worktree.join(".git"));
    repo.write_back_pointer(&format!("{}\n", back.display()));

    let out = h.launch(&[], "shell", &[]);
    let (config, stderr) = reached_builder(&out);
    assert_eq!(
        automatic_binds(&h, &config),
        vec![common_bind(&repo, true)],
        "{stderr}"
    );
}

/// T6. An absolute `commondir`, and a per-worktree directory reached through a
/// symlinked spelling: the guest path is the spelling Git computed, and the host
/// is the canonical directory.
#[test]
fn absolute_commondir_and_symlinked_spelling_are_both_bindable() {
    let h = Harness::new();

    // (a) an absolute `commondir`.
    let repo = build_worktree(&h);
    repo.write_commondir(&format!("{}\n", repo.common.display()));
    let out = h.launch(&[], "shell", &[]);
    let (config, stderr) = reached_builder(&out);
    assert_eq!(
        automatic_binds(&h, &config),
        vec![common_bind(&repo, true)],
        "(a) {stderr}"
    );

    // (b) layout C: the pointer names a symlinked spelling of the main checkout.
    let repo = build_worktree(&h);
    let link = h.home_root.join("link");
    std::os::unix::fs::symlink(&repo.main, &link).unwrap();
    let id = repo.per_worktree.file_name().unwrap().to_os_string();
    let mut spelled = link.join(".git/worktrees");
    spelled.push(&id);
    repo.write_pointer(&format!("gitdir: {}\n", spelled.display()));
    let expected_guest = link.join(".git");
    let host = repo.common.canonicalize().unwrap();

    let out = h.launch(&[], "shell", &[]);
    let (config, stderr) = reached_builder(&out);
    assert_eq!(
        automatic_binds(&h, &config),
        vec![(
            host.display().to_string(),
            expected_guest.display().to_string(),
            true
        )],
        "(b) the guest keeps the symlinked spelling, the host is canonical: {stderr}"
    );

    // (c) Both binds: a per-worktree directory the common one does not contain,
    //     reached through a symlinked `worktrees` directory with an absolute
    //     `commondir`. `Coverage::Separate` is the one placement path that adds two
    //     requests, so both triples are asserted in both modes.
    for (options, readonly) in [(Vec::new(), true), (vec!["--git-mount=rw"], false)] {
        let repo = build_worktree(&h);
        let wts = h.home_root.join(format!("wts-{readonly}"));
        std::os::unix::fs::symlink(repo.common.join("worktrees"), &wts).unwrap();
        let id = repo.per_worktree.file_name().unwrap().to_os_string();
        let mut spelled = wts.clone();
        spelled.push(&id);
        repo.write_pointer(&format!("gitdir: {}\n", spelled.display()));
        repo.write_commondir(&format!(
            "{}\n",
            repo.common.canonicalize().unwrap().display()
        ));

        let out = h.launch(&options, "shell", &[]);
        let (config, stderr) = reached_builder(&out);
        let common = repo.common.canonicalize().unwrap().display().to_string();
        let mut expected = vec![
            (common.clone(), common, readonly),
            (
                repo.per_worktree
                    .canonicalize()
                    .unwrap()
                    .display()
                    .to_string(),
                spelled.display().to_string(),
                readonly,
            ),
        ];
        expected.sort();
        assert_eq!(
            automatic_binds(&h, &config),
            expected,
            "(c) {options:?}: the common directory and the per-worktree directory are two binds, \
             at the guest spellings Git computed: {stderr}"
        );
    }
}

// ---------------------------------------------------------------------------
// T7, T8, T9, T10 — unchanged plans and unchanged sources
// ---------------------------------------------------------------------------

/// T7. An ordinary checkout, a non-repo directory and a symlinked `.git` gitfile
/// are not a linked worktree, so the plan is byte-equal to `--git-mount=off`.
#[test]
fn non_linked_layouts_are_byte_equal_to_off() {
    let h = Harness::new();
    let cases: Vec<(&str, Setup)> = vec![
        (
            "ordinary checkout",
            Box::new(|h: &Harness| {
                git_ok(&h.project_root, &h.home_root, &["init", "-q"]);
                std::fs::write(h.project_root.join("tracked.txt"), "seed\n").unwrap();
            }),
        ),
        ("non-repo dir", Box::new(|_: &Harness| {})),
        (
            "symlinked .git",
            Box::new(|h: &Harness| {
                let target = h.home_root.join("gitfile-target");
                write_file(&target, "gitdir: /nonexistent/gitdir\n");
                std::os::unix::fs::symlink(&target, h.project_root.join(".git")).unwrap();
            }),
        ),
    ];
    for (name, setup) in cases {
        clear_dir(&h.project_root);
        setup(&h);
        let plain = h.launch(&[], "shell", &[]);
        let (plain_config, plain_stderr) = reached_builder(&plain);
        let off = h.launch(&["--git-mount=off"], "shell", &[]);
        let (off_config, off_stderr) = reached_builder(&off);
        assert_eq!(
            sorted_binds(&plain_config),
            sorted_binds(&off_config),
            "{name}: default and `off` must produce one plan\n{plain_stderr}\n{off_stderr}"
        );
        assert!(
            !plain_stderr.contains("==> Git metadata:"),
            "{name}: no notice\n{plain_stderr}"
        );
    }
}

/// T8. A launch from a worktree *subdirectory* discovers nothing: no ancestor
/// bind, and the project-state identity is the subdirectory's.
#[test]
fn a_worktree_subdirectory_discovers_nothing() {
    let h = Harness::new();
    let _repo = build_worktree(&h);
    let root_run = h.launch(&[], "shell", &[]);
    let (_, root_stderr) = reached_builder(&root_run);

    let sub = h.project_root.join("sub");
    std::fs::create_dir(&sub).unwrap();
    let out = h.launch_in(&sub, &[], "shell", &[]);
    let (config, stderr) = reached_builder(&out);
    assert!(
        automatic_binds(&h, &config).is_empty(),
        "no ancestor bind: {stderr}"
    );
    assert!(!stderr.contains("==> Git metadata:"), "{stderr}");
    assert_ne!(
        state_dir(&stderr),
        state_dir(&root_stderr),
        "the subdirectory has its own project state"
    );
}

/// T9. `objects/info/alternates` and a nested gitfile repository are neither
/// discovered nor bound.
#[test]
fn alternates_and_nested_repositories_are_not_discovered() {
    let h = Harness::new();
    let repo = build_worktree(&h);
    let alt = h.home_root.join("alt");
    std::fs::create_dir_all(alt.join("objects")).unwrap();
    write_file(
        &repo.common.join("objects/info/alternates"),
        &format!("{}\n", alt.display()),
    );
    let other = h.home_root.join("othergit");
    std::fs::create_dir_all(&other).unwrap();
    let nested = h.project_root.join("nested");
    std::fs::create_dir(&nested).unwrap();
    write_file(
        &nested.join(".git"),
        &format!("gitdir: {}\n", other.display()),
    );

    let out = h.launch(&[], "shell", &[]);
    let (config, stderr) = reached_builder(&out);
    let binds = bind_mounts(&config);
    for excluded in [&alt, &other] {
        assert!(
            !binds
                .iter()
                .any(|(host, _, _)| Path::new(host) == excluded.as_path()),
            "{} must not be bound: {stderr}",
            excluded.display()
        );
    }
    assert_eq!(automatic_binds(&h, &config), vec![common_bind(&repo, true)]);
}

/// T10. A `.git` pointer at a plain directory with no linked-worktree evidence is
/// not a linked worktree: the launch proceeds and adds nothing.
#[test]
fn a_pointer_to_a_plain_directory_is_not_linked() {
    let h = Harness::new();
    let _repo = build_worktree(&h);
    let secret = h.home_root.join("secret");
    std::fs::create_dir(&secret).unwrap();
    std::fs::write(
        h.project_root.join(".git"),
        format!("gitdir: {}\n", secret.display()),
    )
    .unwrap();

    let out = h.launch(&[], "shell", &[]);
    let (config, stderr) = reached_builder(&out);
    assert!(
        automatic_binds(&h, &config).is_empty(),
        "a plain directory never yields a bind: {stderr}"
    );
    assert!(!stderr.contains("==> Git metadata:"), "{stderr}");
}

// ---------------------------------------------------------------------------
// T11 — the broken-relationship refusal matrix
// ---------------------------------------------------------------------------

/// T11. One fact broken at a time on the real layout-A fixture: each row is a
/// pre-boot refusal that names `git worktree repair` and `--git-mount=off`, and
/// leaves zero launch state.
#[test]
fn broken_relationships_are_refused_before_launch_state() {
    let h = Harness::new();
    let cases: Vec<(&str, Breaker)> = vec![
        (
            "pointer without the prefix",
            Box::new(|r: &Repo| std::fs::write(r.dot_git(), "/x/y\n").unwrap()),
        ),
        (
            "pointer with a NUL",
            Box::new(|r: &Repo| std::fs::write(r.dot_git(), b"gitdir: /a\0b\n").unwrap()),
        ),
        (
            "pointer over the size limit",
            Box::new(|r: &Repo| {
                std::fs::write(r.dot_git(), format!("gitdir: /{}\n", "a".repeat(5000))).unwrap()
            }),
        ),
        (
            "relative pointer climbing above /",
            Box::new(|r: &Repo| r.write_pointer(&format!("gitdir: {}\n", "../".repeat(60)))),
        ),
        (
            "pointer at a missing directory",
            Box::new(|r: &Repo| {
                r.write_pointer(&format!(
                    "gitdir: {}\n",
                    r.worktree.join("missing").display()
                ))
            }),
        ),
        (
            "commondir that is only a newline",
            Box::new(|r: &Repo| std::fs::write(r.per_worktree.join("commondir"), "\n").unwrap()),
        ),
        (
            "commondir at a missing directory",
            Box::new(|r: &Repo| r.write_commondir("../../../missing\n")),
        ),
        (
            "common without objects",
            Box::new(|r: &Repo| {
                std::fs::remove_dir_all(r.common.join("objects")).unwrap();
            }),
        ),
        (
            "common HEAD that is not a ref",
            Box::new(|r: &Repo| {
                std::fs::write(r.common.join("HEAD"), "garbage\n").unwrap();
            }),
        ),
        (
            "common without config",
            Box::new(|r: &Repo| {
                std::fs::remove_file(r.common.join("config")).unwrap();
            }),
        ),
        (
            "common holding a .git entry",
            Box::new(|r: &Repo| {
                std::fs::create_dir_all(r.common.join(".git")).unwrap();
            }),
        ),
        (
            "per-worktree HEAD removed",
            Box::new(|r: &Repo| {
                std::fs::remove_file(r.per_worktree.join("HEAD")).unwrap();
            }),
        ),
        (
            "per-worktree HEAD garbage",
            Box::new(|r: &Repo| {
                std::fs::write(r.per_worktree.join("HEAD"), "garbage\n").unwrap();
            }),
        ),
        (
            "gitdir not registered under worktrees",
            Box::new(|r: &Repo| {
                let elsewhere = r.common.join("elsewhere");
                std::fs::rename(&r.per_worktree, &elsewhere).unwrap();
                r.write_pointer(&format!("gitdir: {}\n", elsewhere.display()));
            }),
        ),
        (
            "back-pointer naming another directory",
            Box::new(|r: &Repo| r.write_back_pointer("/tmp/not-this-worktree/.git\n")),
        ),
    ];

    for (name, break_it) in cases {
        let repo = build_worktree(&h);
        break_it(&repo);
        let before = h.before();
        let out = h.launch(&[], "shell", &[]);
        let stderr = stderr_of(&out);
        h.assert_refused_before_launch_state(&out, &before, "git worktree repair");
        assert!(
            stderr.contains("--git-mount=off"),
            "{name}: the refusal must name the opt-out: {stderr}"
        );
        assert!(
            stderr.contains("is unusable"),
            "{name}: a relationship refusal, not a layout one: {stderr}"
        );
        // R3: `off` still launches every one of these fixtures.
        let repo = build_worktree(&h);
        break_it(&repo);
        let off = h.launch(&["--git-mount=off"], "shell", &[]);
        let (config, off_stderr) = reached_builder(&off);
        assert!(
            automatic_binds(&h, &config).is_empty(),
            "{name}: `off` adds nothing: {off_stderr}"
        );
    }
}

// ---------------------------------------------------------------------------
// T12 — unmountable layouts
// ---------------------------------------------------------------------------

/// T12. A `..` that crosses a symlink reaches a different directory in the guest
/// than on the host, so the layout cannot be mounted at its host paths. `off`
/// still launches it.
#[test]
fn a_symlink_dependent_layout_is_refused() {
    let h = Harness::new();
    let repo = build_worktree(&h);
    let link = h.home_root.join("al");
    std::os::unix::fs::symlink(repo.common.join("worktrees"), &link).unwrap();
    let id = repo.per_worktree.file_name().unwrap().to_os_string();
    let mut spelled = link.clone();
    spelled.push(&id);
    repo.write_pointer(&format!("gitdir: {}\n", spelled.display()));

    let before = h.before();
    let out = h.launch(&[], "shell", &[]);
    let stderr = stderr_of(&out);
    h.assert_refused_before_launch_state(&out, &before, "cannot be mounted at its host paths");
    assert!(stderr.contains("--git-mount=off"), "{stderr}");

    let off = h.launch(&["--git-mount=off"], "shell", &[]);
    let (config, off_stderr) = reached_builder(&off);
    assert!(automatic_binds(&h, &config).is_empty(), "{off_stderr}");
}

// ---------------------------------------------------------------------------
// T12b — a worktree created inside the common directory
// ---------------------------------------------------------------------------

/// T12b. `git worktree add` accepts a target inside the common directory, and the
/// host Git opens it, so this is a *layout* the feature must refuse rather than a
/// broken relationship: the common bind would contain the project's own core
/// mount. `off` still launches it.
#[test]
fn a_worktree_inside_the_common_directory_is_refused() {
    let h = Harness::new();
    let repo = build_worktree(&h);
    let inside = repo.common.join("wt");
    git_ok(
        &repo.main,
        &h.home_root,
        &[
            "worktree",
            "add",
            "-q",
            inside.to_str().unwrap(),
            "-b",
            "inside",
        ],
    );

    let before = h.before();
    let out = h.launch_in(&inside, &[], "shell", &[]);
    let stderr = stderr_of(&out);
    h.assert_refused_before_launch_state(&out, &before, "contains one of agent-vm's own mounts");
    assert!(stderr.contains("--git-mount=off"), "{stderr}");

    // `off` still launches, so the fixture is a real worktree and not a broken
    // one: what refused it was the placement.
    let bare_path = repo.common.canonicalize().unwrap().display().to_string();
    let off = h.launch_in(&inside, &["--git-mount=off"], "shell", &[]);
    let (config, off_stderr) = reached_builder(&off);
    assert!(
        !bind_mounts(&config)
            .iter()
            .any(|(host, guest, _)| host == &bare_path || guest == &bare_path),
        "`off` binds no metadata: {off_stderr}"
    );
}

// ---------------------------------------------------------------------------
// T12c — metadata the guest already reaches through the project bind
// ---------------------------------------------------------------------------

/// Move the main checkout inside the worktree, so the common directory lives
/// inside the project bind, and let `git worktree repair` rewrite the pointer the
/// way it would for a moved checkout. The worktree is then valid and its metadata
/// is reachable through the writable project bind.
fn build_worktree_containing_its_metadata(h: &Harness) {
    let repo = build_worktree(h);
    let moved = h.project_root.join("main");
    std::fs::create_dir(&moved).unwrap();
    for entry in std::fs::read_dir(&repo.main).unwrap() {
        let entry = entry.unwrap();
        std::fs::rename(entry.path(), moved.join(entry.file_name())).unwrap();
    }
    std::fs::remove_dir(&repo.main).unwrap();
    git_ok(
        &moved,
        &h.home_root,
        &["worktree", "repair", h.project_root.to_str().unwrap()],
    );
}

/// T12c. Metadata inside the project bind is *skipped*, not bound: an `ro` bind
/// there would carve a read-only hole in the writable project. The notice has to
/// say that, and it must not call the metadata read-only — through the project
/// bind the guest can write it (story 20).
#[test]
fn metadata_inside_the_project_bind_is_reported_as_reachable() {
    let h = Harness::new();
    build_worktree_containing_its_metadata(&h);
    let inside = h.project_root.join("main/.git");
    let inside_path = inside.canonicalize().unwrap().display().to_string();

    for options in [&[][..], &["--git-mount=rw"][..]] {
        let out = h.launch(options, "shell", &[]);
        let (config, stderr) = reached_builder(&out);
        assert!(
            !bind_mounts(&config)
                .iter()
                .any(|(host, guest, _)| host == &inside_path || guest == &inside_path),
            "{options:?}: no automatic bind inside the project: {stderr}"
        );
        assert!(
            stderr.contains(NOTICE_IN_PROJECT),
            "{options:?}: the notice says where the metadata is: {stderr}"
        );
        assert!(
            !stderr.contains("read-only"),
            "{options:?}: nothing about this launch is read-only: {stderr}"
        );
    }

    // The other half of the same invariant: a `prepare` failure on a launch with
    // no automatic requests must not be framed with `--git-mount=off`.
    let before = h.before();
    let out = h.launch(&["--mount", "/a", "--mount", "/a:ro"], "shell", &[]);
    let stderr = stderr_of(&out);
    h.assert_refused_before_launch_state(&out, &before, "claimed by different declarations");
    assert!(
        !stderr.contains("--git-mount=off"),
        "an unrelated failure carries no Git metadata frame: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// T12d — the project is remapped to `/workspace`
// ---------------------------------------------------------------------------

/// T12d. A project the launcher remaps to `/workspace` gets no metadata bind: Git's
/// relative pointers would resolve against `/workspace`, so the relationship Git
/// wrote on the host names a different directory in the guest. `off` still launches
/// it and *announces the remap*, so the refusal is known to be about the remap and
/// not about a broken fixture.
///
/// The remap trigger is a control character in the launch directory, which is the
/// one `resolve_project_guest_path` remap this platform can reach: a host path under
/// `/tmp` canonicalizes to `/private/tmp`, which is not under the `/tmp` guest
/// prefix, so such a project mirrors at its real path instead (T12e reaches the
/// tmpfs arm through the guest spelling). Both triggers hand discovery the same
/// `project_guest`, which is the fact this arm decides on (ADR-0062 D6).
///
/// The fixture spells the back-pointer through a symlink that has no control byte
/// in its path. That is not a trick to dodge the feature: the pointer parser refuses
/// a control byte *itself*, so a tabbed launch directory would otherwise answer
/// `BackPointerMismatch` before the placement is ever measured. What the row has to
/// exercise is the placement refusal, and which host spelling names the same
/// directory does not change it — the symlink resolves to exactly the tabbed
/// `.git` the row's worktree has.
#[test]
fn a_remapped_project_is_refused_before_launch_state() {
    let h = Harness::new();
    let repo = build_worktree(&h);
    let remapped = h.project_root.join("w\tk");
    git_ok(
        &repo.main,
        &h.home_root,
        &[
            "worktree",
            "add",
            "-q",
            remapped.to_str().unwrap(),
            "-b",
            "remapped",
        ],
    );
    let per_worktree = String::from_utf8(
        std::fs::read(remapped.join(".git"))
            .unwrap()
            .strip_prefix(b"gitdir: ")
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    let alias = h.home_root.join("tabbed-alias");
    let _ = std::fs::remove_file(&alias);
    std::os::unix::fs::symlink(&remapped, &alias).unwrap();
    write_file(
        &Path::new(per_worktree.trim()).join("gitdir"),
        &format!("{}\n", alias.join(".git").display()),
    );

    let before = h.before();
    let out = h.launch_in(&remapped, &[], "shell", &[]);
    let stderr = stderr_of(&out);
    h.assert_refused_before_launch_state(&out, &before, "cannot be mounted at its host paths");
    assert!(
        stderr.contains(
            "Git's relative pointers would resolve against the guest project path \"/workspace\""
        ),
        "the refusal names the remapped base: {stderr}"
    );
    assert!(stderr.contains("--git-mount=off"), "{stderr}");
    assert!(
        !stderr.contains("==> Git metadata:"),
        "a refused layout prints no notice: {stderr}"
    );

    // `off` launches the same worktree, and says why it is at `/workspace`.
    let off = h.launch_in(&remapped, &["--git-mount=off"], "shell", &[]);
    let (config, off_stderr) = reached_builder(&off);
    assert!(
        off_stderr.contains("contains control characters")
            && off_stderr.contains("mounting at /workspace instead"),
        "the fixture really is remapped: {off_stderr}"
    );
    assert!(automatic_binds(&h, &config).is_empty(), "{off_stderr}");
}

// ---------------------------------------------------------------------------
// T12e — the metadata guest path is under a guest tmpfs prefix
// ---------------------------------------------------------------------------

/// T12e. The runtime tmpfs-mounts `/tmp` (and `/run`, `/dev/shm`, `/var/run`) in the
/// guest at boot, so a metadata directory the guest would see there is wiped before
/// Git runs: the bind would be gone. `off` still launches the same fixture, and the
/// canonical spelling of the same directory *does* bind, so the row is about the
/// guest path and not about the fixture.
///
/// The main checkout is created under `/tmp` and the pointer spells it there, which
/// is byte for byte the layout Git writes on a host where `/tmp` is a real
/// directory. On macOS `/tmp` is a symlink to `/private/tmp`: the host canonicalizes
/// and the guest spelling stays `/tmp/…` — the path the guest would really
/// tmpfs-mount, and the one the decision is measured on. No prefix list is patched
/// to make this row run.
#[test]
fn metadata_under_a_guest_tmpfs_prefix_is_refused_before_launch_state() {
    let h = Harness::new();
    let tmp = tempfile::tempdir_in("/tmp").unwrap();
    assert_eq!(
        tmp.path().parent(),
        Some(Path::new("/tmp")),
        "the fixture spells its metadata under /tmp"
    );
    let main = tmp.path().join("main");
    std::fs::create_dir(&main).unwrap();
    git_ok(&main, &h.home_root, &["init", "-q"]);
    for (key, value) in [
        ("user.name", "gm"),
        ("user.email", "gm@example.invalid"),
        ("commit.gpgsign", "false"),
        ("tag.gpgsign", "false"),
        ("core.hooksPath", "/dev/null"),
    ] {
        git_ok(&main, &h.home_root, &["config", key, value]);
    }
    std::fs::write(main.join("tracked.txt"), "seed\n").unwrap();
    git_ok(&main, &h.home_root, &["add", "tracked.txt"]);
    git_ok(&main, &h.home_root, &["commit", "-q", "-m", "seed"]);
    git_ok(
        &main,
        &h.home_root,
        &[
            "worktree",
            "add",
            "-q",
            h.project_root.to_str().unwrap(),
            "-b",
            "wt",
        ],
    );
    let common = main.join(".git");
    let per_worktree = only_worktree_dir(&common);
    // Git writes the canonical spelling of the per-worktree directory. Spell the
    // same directory the way the `/tmp` host path reads, which is the guest path
    // the pointer asks for (on a host without the symlink the two are identical).
    let spelled_pointer = common
        .join("worktrees")
        .join(per_worktree.file_name().unwrap());
    write_file(
        &h.project_root.join(".git"),
        &format!("gitdir: {}\n", spelled_pointer.display()),
    );
    let metadata = common.display().to_string();

    let before = h.before();
    let out = h.launch(&[], "shell", &[]);
    let stderr = stderr_of(&out);
    h.assert_refused_before_launch_state(
        &out,
        &before,
        "is under a guest tmpfs mount, which is wiped at boot",
    );
    assert!(
        stderr.contains(&format!("\"{metadata}\"")),
        "the refusal names the guest path: {stderr}"
    );
    assert!(stderr.contains("--git-mount=off"), "{stderr}");

    // `off` launches it: the layout is a valid worktree, and only the automatic
    // plan is what refuses it.
    let off = h.launch(&["--git-mount=off"], "shell", &[]);
    let (off_config, off_stderr) = reached_builder(&off);
    assert!(
        !bind_mounts(&off_config)
            .iter()
            .any(|(host, guest, _)| host == &metadata || guest == &metadata),
        "`off` binds no metadata: {off_stderr}"
    );

    // Calibration, only where the two spellings differ: the canonical spelling of
    // the same directory is not under a guest tmpfs prefix, so that launch binds.
    // The refusal therefore follows the *guest* spelling.
    let canonical_pointer = per_worktree.canonicalize().unwrap();
    if canonical_pointer != spelled_pointer {
        write_file(
            &h.project_root.join(".git"),
            &format!("gitdir: {}\n", canonical_pointer.display()),
        );
        let output = h.launch(&[], "shell", &[]);
        let (config, canonical_stderr) = reached_builder(&output);
        let canonical_metadata = common.canonicalize().unwrap().display().to_string();
        assert!(
            bind_mounts(&config).iter().any(|(host, guest, readonly)| {
                host == &canonical_metadata && guest == &canonical_metadata && *readonly
            }),
            "the canonical spelling binds read-only: {canonical_stderr}"
        );
        assert!(canonical_stderr.contains(NOTICE_RO), "{canonical_stderr}");
        // The bind's own line: host and guest are the same path, so there is no
        // arrow to read (#551). The config above already proves they are equal.
        let mounting = canonical_stderr
            .lines()
            .find(|line| line.starts_with("==> Mounting ") && line.contains(&canonical_metadata))
            .unwrap_or_else(|| panic!("no mount notice: {canonical_stderr}"));
        assert_eq!(
            mounting,
            format!("==> Mounting {canonical_metadata} (read-only)"),
            "a bind at its own path needs no arrow: {canonical_stderr}"
        );
    }
}

// ---------------------------------------------------------------------------
// T13 — `off` bypasses discovery and nothing else
// ---------------------------------------------------------------------------

/// T13. `--git-mount=off` skips discovery, so a broken pointer does not block the
/// launch — while every other check still runs.
#[test]
fn off_bypasses_discovery_only() {
    let h = Harness::new();
    let repo = build_worktree(&h);
    std::fs::write(repo.dot_git(), "not a gitdir line\n").unwrap();

    let out = h.launch(&["--git-mount=off"], "shell", &[]);
    let (config, stderr) = reached_builder(&out);
    assert!(automatic_binds(&h, &config).is_empty(), "{stderr}");

    // The unrelated `--mount` validation still refuses a self-contradictory plan.
    let before = h.before();
    let out = h.launch(
        &["--git-mount=off", "--mount", "/a", "--mount", "/a:ro"],
        "shell",
        &[],
    );
    h.assert_refused_before_launch_state(&out, &before, "claimed by different declarations");
}

// ---------------------------------------------------------------------------
// T14 — the claim keeps first-seen, so an equivalent declaration merges
// ---------------------------------------------------------------------------

/// T14. An equivalent explicit or config declaration merges into one bind and
/// keeps its own origin; a different one is refused naming both origins.
#[test]
fn equivalent_declarations_merge_and_different_ones_are_refused() {
    let h = Harness::new();
    let repo = build_worktree(&h);
    let common = repo.common.canonicalize().unwrap().display().to_string();

    // (a) An explicit read-only declaration is the same declaration.
    let out = h.launch(&["--mount", &format!("{common}:ro")], "shell", &[]);
    let (config, stderr) = reached_builder(&out);
    assert_eq!(automatic_binds(&h, &config), vec![common_bind(&repo, true)]);
    let mounting: Vec<&str> = stderr
        .lines()
        .filter(|line| line.starts_with("==> Mounting ") && line.contains(&common))
        .collect();
    assert_eq!(
        mounting.len(),
        1,
        "the merged bind is announced once: {stderr}"
    );
    // The declared spelling is the canonical path, so the two sides are one
    // path: no arrow to read (#551).
    assert_eq!(
        mounting[0],
        format!("==> Mounting {common} (read-only)"),
        "a bind at its own path needs no arrow: {stderr}"
    );

    // (b) A config `mounts` entry keeps its own origin, so the file is still
    //     reported.
    h.write_user(&format!("mounts = [\"{common}:ro\"]\n"));
    let out = h.launch(&[], "shell", &[]);
    let (config, stderr) = reached_builder(&out);
    assert_eq!(automatic_binds(&h, &config), vec![common_bind(&repo, true)]);
    assert!(
        stderr.contains("==> Config mounts: 1 from "),
        "the config origin is kept: {stderr}"
    );

    // (c) A differing explicit declaration is refused naming both origins. The
    //     config entry from (b) is removed first, so the pair under test is argv
    //     against the automatic request.
    std::fs::remove_file(h.user_config()).unwrap();
    let before = h.before();
    let out = h.launch(&["--mount", &common], "shell", &[]);
    let stderr = stderr_of(&out);
    h.assert_refused_before_launch_state(&out, &before, "claimed by different declarations");
    assert!(stderr.contains("--mount"), "{stderr}");
    assert!(
        stderr.contains("automatic Git metadata mount (common directory)"),
        "the automatic origin is named: {stderr}"
    );

    // (d) A differing config declaration names its own site.
    h.write_user(&format!("mounts = [\"{common}:rw\"]\n"));
    let before = h.before();
    let out = h.launch(&[], "shell", &[]);
    let stderr = stderr_of(&out);
    h.assert_refused_before_launch_state(&out, &before, "claimed by different declarations");
    assert!(
        stderr.contains("mounts[0] in "),
        "the config site is named: {stderr}"
    );
}

/// T14b. The 0.7.36 workaround — a writable `mounts` entry or `--mount` naming
/// the metadata directory — merges under `--git-mount=rw`: same spelling, same
/// host, same access, so `claim` keeps the first-seen declaration and the plan has
/// one bind. That is what makes "add `--git-mount=rw`" an honest upgrade remedy for
/// a user who needs to write, rather than advice to edit the config as well.
#[test]
fn a_writable_workaround_declaration_merges_under_rw() {
    let h = Harness::new();
    let repo = build_worktree(&h);
    let common = repo.common.canonicalize().unwrap().display().to_string();

    for via_config in [false, true] {
        if via_config {
            h.write_user(&format!("mounts = [\"{common}\"]\n"));
        }
        let options: &[&str] = if via_config {
            &["--git-mount=rw"]
        } else {
            &["--git-mount=rw", "--mount", &common]
        };
        let out = h.launch(options, "shell", &[]);
        let (config, stderr) = reached_builder(&out);
        assert_eq!(
            automatic_binds(&h, &config),
            vec![common_bind(&repo, false)],
            "via_config={via_config}: one writable bind, merged: {stderr}"
        );
        let mounting = stderr
            .lines()
            .filter(|line| line.starts_with("==> Mounting ") && line.contains(&common))
            .count();
        assert_eq!(
            mounting, 1,
            "via_config={via_config}: the merged bind is announced once: {stderr}"
        );
        assert!(stderr.contains(NOTICE_RW), "{stderr}");
        std::fs::remove_file(h.user_config()).ok();
    }
}

// ---------------------------------------------------------------------------
// T14b — an enclosing declaration is never shadowed
// ---------------------------------------------------------------------------

/// T14b. The automatic requests are appended *after* the argv and config ones,
/// and the runtime mounts a parent before its child, so an automatic bind inside
/// a route the user declared would silently outrank the access they asked for.
/// Each row is the same metadata, reached through one enclosing declaration:
///
/// - a plain live bind of the same host directory merges (no automatic request at
///   all, in either mode) and the declaration keeps its own access;
/// - anything else — a different host directory, `:fork` — is refused before boot
///   naming both origins.
#[test]
fn an_enclosing_declaration_is_never_shadowed() {
    let h = Harness::new();
    let repos = h.home_root.join("repos");

    // (a) An `rw` parent via argv: no automatic bind, and the parent stays
    //     writable, so a guest commit through it still works. The metadata guest
    //     path is the observable, not `automatic_binds`: the enclosing declaration
    //     is itself a `$HOME`-shaped bind.
    let repo = build_worktree(&h);
    let common = repo.common.canonicalize().unwrap().display().to_string();
    let no_metadata_bind = |config: &serde_json::Value| {
        !bind_mounts(config)
            .iter()
            .any(|(_, guest, _)| guest == &common)
    };
    let out = h.launch(
        &["--mount", &format!("{}:rw", repos.display())],
        "shell",
        &[],
    );
    let (config, stderr) = reached_builder(&out);
    assert!(
        no_metadata_bind(&config),
        "(a) no automatic bind below a declared ancestor: {stderr}"
    );
    assert!(
        !stderr.contains(NOTICE_RO),
        "(a) the read-only notice must not print when nothing was bound: {stderr}"
    );
    assert!(
        stderr.contains(&format!("{NOTICE_ENCLOSING}--mount;")),
        "(a) the notice names the declaration that carries the metadata: {stderr}"
    );
    assert!(
        sorted_binds(&config).contains(&(
            repos.display().to_string(),
            repos.display().to_string(),
            false
        )),
        "(a) the declaration keeps its own writable access: {stderr}"
    );

    // (b) The same declaration through the verified user config.
    h.write_user(&format!("mounts = [\"{}:rw\"]\n", repos.display()));
    let out = h.launch(&[], "shell", &[]);
    let (config, stderr) = reached_builder(&out);
    assert!(no_metadata_bind(&config), "(b) {stderr}");
    assert!(
        stderr.contains("==> Config mounts: 1 from "),
        "(b) the config origin is still reported: {stderr}"
    );
    assert!(
        stderr.contains(NOTICE_ENCLOSING),
        "(b) the notice says where the metadata is reachable: {stderr}"
    );
    std::fs::remove_file(h.user_config()).unwrap();

    // (c) `--git-mount=rw` below a declared `:ro` parent must not add a writable
    //     child: the declaration's access governs.
    let out = h.launch(
        &[
            "--git-mount=rw",
            "--mount",
            &format!("{}:ro", repos.display()),
        ],
        "shell",
        &[],
    );
    let (config, stderr) = reached_builder(&out);
    assert!(
        no_metadata_bind(&config),
        "(c) no writable child under a read-only declaration: {stderr}"
    );
    assert!(
        sorted_binds(&config).contains(&(
            repos.display().to_string(),
            repos.display().to_string(),
            true
        )),
        "(c) the declaration stays read-only: {stderr}"
    );

    // (d) An enclosing declaration of a *different* host directory: the automatic
    //     bind would map part of that route somewhere else, so the launch is
    //     refused pre-boot, naming both origins.
    let elsewhere = h.home_root.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let before = h.before();
    let out = h.launch(
        &[
            "--mount",
            &format!("{}:{}:ro", elsewhere.display(), repos.display()),
        ],
        "shell",
        &[],
    );
    let stderr = stderr_of(&out);
    h.assert_refused_before_launch_state(&out, &before, "would shadow --mount");
    assert!(
        stderr.contains("automatic Git metadata mount (common directory)"),
        "(d) the automatic origin is named: {stderr}"
    );
    assert!(
        stderr.contains("--git-mount=off") && !stderr.contains("git worktree repair"),
        "(d) a layout refusal with its own remedy: {stderr}"
    );

    // (e) An enclosing `:fork` hands the guest a copy, so a same-host match proves
    //     nothing: refused rather than merged.
    let before = h.before();
    let out = h.launch(
        &[
            "--mount",
            &format!("{}:{}:fork", repos.display(), repos.display()),
        ],
        "shell",
        &[],
    );
    let stderr = stderr_of(&out);
    h.assert_refused_before_launch_state(&out, &before, "would shadow --mount");
    assert!(
        stderr.contains("automatic Git metadata mount (common directory)"),
        "(e) named: {stderr}"
    );

    // (f) Mixed placements: with two metadata directories (the two-bind layout of
    //     T6(c)), the declaration carries the common one and the per-worktree one
    //     still needs a bind. The notice describes what was *added*, and only the
    //     directory that needed it is bound.
    let repo = build_worktree(&h);
    let wts = h.home_root.join("wts");
    std::os::unix::fs::symlink(repo.common.join("worktrees"), &wts).unwrap();
    let id = repo.per_worktree.file_name().unwrap().to_os_string();
    let mut spelled = wts.clone();
    spelled.push(&id);
    repo.write_pointer(&format!("gitdir: {}\n", spelled.display()));
    repo.write_commondir(&format!(
        "{}\n",
        repo.common.canonicalize().unwrap().display()
    ));
    let out = h.launch(
        &["--mount", &format!("{}:rw", repos.display())],
        "shell",
        &[],
    );
    let (config, stderr) = reached_builder(&out);
    let binds = automatic_binds(&h, &config);
    assert!(
        binds.contains(&(
            repo.per_worktree
                .canonicalize()
                .unwrap()
                .display()
                .to_string(),
            spelled.display().to_string(),
            true
        )),
        "(f) the per-worktree directory is still bound: {stderr}"
    );
    assert!(
        !binds.iter().any(|(_, guest, _)| guest == &common),
        "(f) the common directory is carried by the declaration: {stderr}"
    );
    assert!(
        stderr.contains(NOTICE_RO),
        "(f) the notice describes the bind that was added: {stderr}"
    );

    // (g) An enclosing declaration whose source is missing is skipped, so the
    //     launch reports the problem that is actually there — `prepare` refusing to
    //     canonicalize `--mount` — instead of a shadow refusal pointing at the
    //     wrong declaration. Both modes, because the decision does not depend on
    //     the mode.
    for options in [&["--git-mount=ro"][..], &["--git-mount=rw"][..]] {
        let missing = h.home_root.join("missing-source");
        let before = h.before();
        let out = h.launch(
            &[
                options[0],
                "--mount",
                &format!("{}:{}:ro", missing.display(), repos.display()),
            ],
            "shell",
            &[],
        );
        let stderr = stderr_of(&out);
        assert!(!out.status.success(), "(g) {options:?}: {stderr}");
        assert!(
            stderr.contains("canonicalizing --mount host"),
            "(g) {options:?}: the pre-existing error is the one reported: {stderr}"
        );
        assert!(
            !stderr.contains("would shadow"),
            "(g) {options:?}: no shadow refusal for a declaration that cannot mount: {stderr}"
        );
        assert!(
            !stderr.contains(CONFIG_MARKER) && !stderr.contains(BOOT_BANNER),
            "(g) {options:?}: before builder wiring: {stderr}"
        );
        assert_eq!(
            h.snapshot(),
            before.entries,
            "(g) {options:?}: no launch state: {stderr}"
        );
    }
}

// ---------------------------------------------------------------------------
// T16 — independent of `--no-git` and `--no-config-mounts`
// ---------------------------------------------------------------------------

/// T16. `--no-git` and `--no-config-mounts` do not change the automatic Git
/// mounts, and the GitHub allow-list is the same with the feature on and off.
#[test]
fn the_opt_outs_do_not_change_git_metadata_mounts() {
    let h = Harness::new();
    let repo = build_worktree(&h);

    let out = h.launch(&["--no-git"], "shell", &[]);
    let (config, stderr) = reached_builder(&out);
    assert_eq!(
        automatic_binds(&h, &config),
        vec![common_bind(&repo, true)],
        "--no-git is about GitHub credentials: {stderr}"
    );

    let cfg_dir = h.home_root.join("cfgdir");
    std::fs::create_dir(&cfg_dir).unwrap();
    h.write_user("mounts = [\"~/cfgdir:ro\"]\n");
    let out = h.launch(&["--no-config-mounts"], "shell", &[]);
    let (config, stderr) = reached_builder(&out);
    assert_eq!(
        automatic_binds(&h, &config),
        vec![common_bind(&repo, true)],
        "--no-config-mounts does not touch discovery: {stderr}"
    );
    assert!(
        !sorted_binds(&config)
            .iter()
            .any(|(_, guest, _)| guest.ends_with("/cfgdir")),
        "the config mount is the only thing `--no-config-mounts` removes: {stderr}"
    );

    // The GitHub allow-list notice is byte-identical with the feature on and off.
    let on = h.launch(&[], "shell", &[]);
    let (_, on_stderr) = reached_builder(&on);
    let off = h.launch(&["--git-mount=off"], "shell", &[]);
    let (_, off_stderr) = reached_builder(&off);
    let scope = |stderr: &str| {
        stderr
            .lines()
            .find(|line| line.starts_with("==> GitHub repo scope:"))
            .unwrap_or("<no scope line>")
            .to_string()
    };
    assert_eq!(
        scope(&on_stderr),
        scope(&off_stderr),
        "{on_stderr}\n{off_stderr}"
    );
}

// ---------------------------------------------------------------------------
// T17 — every route carries the option
// ---------------------------------------------------------------------------

/// T17. The mode reaches the launch on all four routes, and the same token after
/// the verb is the tool's own argument.
#[test]
fn the_mode_reaches_every_route() {
    let h = Harness::new();
    let repo = build_worktree(&h);
    h.write_project(tool_without_persist());

    for (verb, args) in [
        ("aider", Vec::new()),
        ("shell", Vec::new()),
        ("run", vec!["/bin/true"]),
        ("--", vec!["/bin/true"]),
    ] {
        let out = h.launch(&["--git-mount=rw"], verb, &args);
        let (config, stderr) = reached_builder(&out);
        assert_eq!(
            automatic_binds(&h, &config),
            vec![common_bind(&repo, false)],
            "{verb} {args:?}: {stderr}"
        );
        assert!(stderr.contains(NOTICE_RW), "{verb} {args:?}: {stderr}");
    }

    // After the verb it is the tool's argument, so the launch stays read-only.
    let out = h.launch(&[], "shell", &["--git-mount=off"]);
    let (config, stderr) = reached_builder(&out);
    assert_eq!(automatic_binds(&h, &config), vec![common_bind(&repo, true)]);
    assert!(
        guest_command(&stderr).contains("--git-mount=off"),
        "the token reached the guest command: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// T15 — the existing protections refuse an automatic bind exactly as `--mount`
// ---------------------------------------------------------------------------

/// T15. Every protection that applies to `--mount` applies to an automatic bind,
/// because they are the same kind of declaration: Pi credential files, the
/// writable config directory, a core collision and a `persist` shadow.
#[test]
fn protections_refuse_automatic_binds_exactly_as_mount() {
    let h = Harness::new();

    // (a) A bare repository at `$HOME/.pi` holding a protected Pi credential file.
    build_bare_pi(&h);
    let before = h.before();
    let out = h.launch(&[], "shell", &[]);
    h.assert_refused_before_launch_state(&out, &before, "auth.json");

    // (b) A bare repository at `$HOME/.config`, which is the writable config
    //     directory: `rw` is refused, `ro` is accepted.
    build_bare_worktree(&h, &h.home_root.join(".config"));
    std::fs::create_dir_all(h.home_root.join(".config/agent-vm")).unwrap();
    let before = h.before();
    let out = h.launch(&["--git-mount=rw"], "shell", &[]);
    h.assert_refused_before_launch_state(&out, &before, "would let the guest change what");
    let accepted = h.launch(&[], "shell", &[]);
    let (config, stderr) = reached_builder(&accepted);
    let config_dir = h.home_root.join(".config").canonicalize().unwrap();
    assert!(
        automatic_binds(&h, &config)
            .iter()
            .any(
                |(host, guest, readonly)| host == &config_dir.display().to_string()
                    && guest == &config_dir.display().to_string()
                    && *readonly
            ),
        "read-only is accepted: {stderr}"
    );

    // (c) A bare repository at `$HOME` collides with the guest HOME core mount.
    build_bare_worktree(&h, &h.home_root);
    let before = h.before();
    let out = h.launch(&[], "shell", &[]);
    let stderr = stderr_of(&out);
    h.assert_refused_before_launch_state(&out, &before, "collides with an agent-vm core mount");
    assert!(
        stderr.contains("pass --git-mount=off to launch without automatic Git metadata mounts"),
        "the automatic origin names its own remedy: {stderr}"
    );

    // (d) A bare repository at `$HOME/code` shadows a declared `persist` link.
    //     The project config is written last: the fixture builder owns the
    //     project root and clears it.
    build_bare_worktree(&h, &h.home_root.join("code"));
    h.write_project(
        "[[tools]]\nname = \"aider\"\ncommand = \"/bin/echo\"\ncredentials = []\npersist = [\"code\"]\n",
    );
    let before = h.before();
    let out = h.launch(&[], "aider", &[]);
    let stderr = stderr_of(&out);
    h.assert_refused_before_launch_state(&out, &before, "would collide with the guest mount point");
    assert!(
        stderr.contains("automatic Git metadata mounts"),
        "the launch names the automatic requests too: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// T18 — the B1 forgery: every relationship fact true, no Git directory
// ---------------------------------------------------------------------------

/// A hand-built "registration" whose relationship facts all hold: the pointer,
/// `commondir` and back-pointer are exactly what Git writes. What is missing is
/// the Git directory itself, which is the fact the validity contract measures.
fn build_forgery(h: &Harness, _name: &str) -> (PathBuf, PathBuf) {
    let forged = h.home_root.join("forged");
    let _ = std::fs::remove_dir_all(&forged);
    std::fs::create_dir_all(forged.join("objects")).unwrap();
    std::fs::create_dir_all(forged.join("refs")).unwrap();
    std::fs::create_dir_all(forged.join("worktrees/f")).unwrap();
    write_file(
        &forged.join("config"),
        "[core]\n\trepositoryformatversion = 0\n",
    );
    write_file(&forged.join("worktrees/f/commondir"), "../..\n");
    write_file(
        &forged.join("worktrees/f/gitdir"),
        &format!("{}\n", h.project_root.join(".git").display()),
    );
    write_file(&forged.join("secret.txt"), "SENTINEL-535\n");
    write_file(&forged.join("src/main.rs"), "fn main() {}\n");
    std::fs::write(
        h.project_root.join(".git"),
        format!("gitdir: {}\n", forged.join("worktrees/f").display()),
    )
    .unwrap();
    (forged, h.project_root.join(".git"))
}

/// T18. A forged registration that satisfies every relationship fact is still
/// refused, because neither directory passes the Git-directory validity
/// contract. The host `git` oracle is recorded alongside so the refusal is known
/// to be about a real repository-shaped input.
#[test]
fn a_fully_cross_linked_forgery_is_refused() {
    let h = Harness::new();
    let _ = build_worktree(&h);

    // (a) no `HEAD` anywhere.
    let (forged, _) = build_forgery(&h, "a");
    let before = h.before();
    let out = h.launch(&[], "shell", &[]);
    let stderr = stderr_of(&out);
    h.assert_refused_before_launch_state(&out, &before, "not a Git directory");
    assert!(!stderr.contains("==> Git metadata:"), "{stderr}");
    assert!(
        !stderr.contains(&format!("==> Mounting {0}", forged.display())),
        "the forgery is never named as a bind: {stderr}"
    );
    assert_eq!(host_rev_parse(&h), None, "(a) git rejects the forgery");

    // (b) common `HEAD` valid, per-worktree `HEAD` garbage.
    let (forged, _) = build_forgery(&h, "b");
    write_file(&forged.join("HEAD"), "ref: refs/heads/main\n");
    write_file(&forged.join("worktrees/f/HEAD"), "garbage\n");
    let before = h.before();
    let out = h.launch(&[], "shell", &[]);
    let stderr = stderr_of(&out);
    h.assert_refused_before_launch_state(&out, &before, "not a Git directory");
    assert!(stderr.contains("(no valid HEAD)"), "{stderr}");
    assert_eq!(host_rev_parse(&h), None, "(b) git rejects the forgery");

    // (c) per-worktree `HEAD` valid, common `HEAD` missing: Git accepts this one,
    //     and agent-vm refuses it by its stricter common-`HEAD` rule (ADR-0062 D2).
    let (forged, _) = build_forgery(&h, "c");
    write_file(&forged.join("worktrees/f/HEAD"), "ref: refs/heads/main\n");
    assert!(
        host_rev_parse(&h).is_some(),
        "(c) the oracle: host git accepts this layout, so the refusal is agent-vm's \
         stricter rule and not a different error"
    );
    let before = h.before();
    let out = h.launch(&[], "shell", &[]);
    let stderr = stderr_of(&out);
    h.assert_refused_before_launch_state(&out, &before, "is not a Git directory");
    assert!(
        !stderr.contains("==> Git metadata:"),
        "no notice for a refused forgery: {stderr}"
    );
    // The sentinels are still exactly the bytes the fixture wrote, and no
    // automatic bind names the forged directory.
    assert_eq!(
        std::fs::read_to_string(forged.join("secret.txt")).unwrap(),
        "SENTINEL-535\n"
    );
}

/// The host `git`'s verdict for the fixture: `Some(object id)` when it opens the
/// directory at all, `None` when it refuses. `None` with a printed reason when
/// `git` is absent, never silently.
fn host_rev_parse(h: &Harness) -> Option<String> {
    let out = fixture_git(&h.project_root, &h.home_root, &["rev-parse", "--git-dir"]);
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

// ---------------------------------------------------------------------------
// T18b — the accepted trade-off, pinned: a fully Git-valid forgery binds `ro`
// ---------------------------------------------------------------------------

/// A **fully Git-valid** forgery: a second, real repository whose common directory
/// passes the whole contract, plus the one thing the forgery adds — a
/// `worktrees/x` registration whose back-pointer names this launch directory.
///
/// Writing that registration inside another repository's Git directory is exactly
/// the prior write access the accepted trade-off assumes, which is why the fixture
/// (not the product) is what makes the layout.
fn build_valid_forgery(h: &Harness) -> (PathBuf, PathBuf) {
    let victim = h.home_root.join("victim");
    let _ = std::fs::remove_dir_all(&victim);
    std::fs::create_dir(&victim).unwrap();
    git_ok(&victim, &h.home_root, &["init", "-q"]);
    for (key, value) in [
        ("user.name", "gm"),
        ("user.email", "gm@example.invalid"),
        ("commit.gpgsign", "false"),
        ("core.hooksPath", "/dev/null"),
    ] {
        git_ok(&victim, &h.home_root, &["config", key, value]);
    }
    std::fs::write(victim.join("secret.txt"), "SENTINEL-535\n").unwrap();
    git_ok(&victim, &h.home_root, &["add", "secret.txt"]);
    git_ok(&victim, &h.home_root, &["commit", "-q", "-m", "seed"]);
    let common = victim.join(".git");
    // Both `HEAD`s, `objects/`, `refs/` and a regular `config` are already there
    // because a real `git init` made them; the registration is the forgery.
    let registration = common.join("worktrees/x");
    std::fs::create_dir_all(&registration).unwrap();
    write_file(&registration.join("commondir"), "../..\n");
    write_file(
        &registration.join("gitdir"),
        &format!("{}\n", h.project_root.join(".git").display()),
    );
    write_file(&registration.join("HEAD"), "ref: refs/heads/main\n");
    std::fs::write(
        h.project_root.join(".git"),
        format!("gitdir: {}\n", registration.display()),
    )
    .unwrap();
    (common, registration)
}

/// T18b. The documented boundary, characterized instead of wished away: a forgery
/// that satisfies the **whole** Git-directory contract is accepted, and it binds
/// **read-only**. The contract proves Git would open the target as this worktree's
/// repository; it cannot prove the user may read that repository (ADR-0062 D2b).
/// Constructing the layout takes write access *inside* the target Git directory —
/// the registration is absent from Git's own `worktree list` here — so the forgery
/// grants nothing the forger did not already have. That is the accepted trade-off.
///
/// The row is a characterization on purpose: hardening `git_dir_contract` past this
/// boundary must fail here, so the ADR sentence that promises it changes with the
/// code instead of quietly becoming false.
#[test]
fn a_fully_git_valid_forgery_binds_read_only() {
    let h = Harness::new();
    let (common, registration) = build_valid_forgery(&h);

    // The prior write access, made observable: Git lists this checkout as a worktree
    // of the victim repository *only because the fixture wrote the registration*, so
    // from Git's point of view the forgery is indistinguishable from a real
    // registration — which is exactly why the contract accepts it, and why that is a
    // documented trade-off rather than a defect.
    let listed = git_ok(
        &h.home_root.join("victim"),
        &h.home_root,
        &["worktree", "list", "--porcelain"],
    );
    assert!(
        listed.contains(h.project_root.to_str().unwrap()),
        "the fixture's registration is what Git sees: {listed}"
    );
    // The oracle for "fully Git-valid": unlike T18's hand-built directories, the
    // host Git opens this one as a repository, which is why it is accepted.
    assert!(
        host_rev_parse(&h).is_some(),
        "the forgery is a real repository from Git's point of view"
    );

    let out = h.launch(&[], "shell", &[]);
    let (config, stderr) = reached_builder(&out);
    let metadata = common.canonicalize().unwrap().display().to_string();
    assert_eq!(
        automatic_binds(&h, &config),
        vec![(metadata.clone(), metadata.clone(), true)],
        "accepted, one bind, read-only: {stderr}"
    );
    assert!(stderr.contains(NOTICE_RO), "{stderr}");
    // Nothing but the metadata comes with it: the victim's source stays out of the
    // plan, so `ro` is the whole of the exposure (R6).
    let source = h.home_root.join("victim").canonicalize().unwrap();
    assert!(
        !bind_mounts(&config)
            .iter()
            .any(|(host, guest, _)| host == &source.display().to_string()
                || guest == &source.display().to_string()),
        "the victim's source is not bound: {stderr}"
    );
    // And the `ro` bind is what keeps the target intact, not the layout: the
    // per-worktree directory the notice names is real and was not rewritten.
    assert!(std::fs::symlink_metadata(&registration).unwrap().is_dir());
    assert_eq!(
        std::fs::read_to_string(h.home_root.join("victim/secret.txt")).unwrap(),
        "SENTINEL-535\n"
    );
}

// ---------------------------------------------------------------------------
// T19 — B5: a missing `commondir`, and the layouts that must stay unchanged
// ---------------------------------------------------------------------------

/// T19. A deleted `commondir` is a *damaged linked worktree*, not a submodule, so
/// it is refused; `off` still launches it; and the two layouts that genuinely
/// have no `commondir` keep their unchanged plan.
#[test]
fn a_missing_commondir_is_refused_and_other_gitfiles_are_unchanged() {
    let h = Harness::new();

    // (a) `commondir` deleted from the real layout A.
    let repo = build_worktree(&h);
    std::fs::remove_file(repo.per_worktree.join("commondir")).unwrap();
    let before = h.before();
    let out = h.launch(&[], "shell", &[]);
    let stderr = stderr_of(&out);
    h.assert_refused_before_launch_state(&out, &before, "git worktree repair");
    assert!(stderr.contains("is missing"), "{stderr}");
    assert!(stderr.contains("--git-mount=off"), "{stderr}");

    // (b) The same fixture with `--git-mount=off` reaches the builder.
    let off = h.launch(&["--git-mount=off"], "shell", &[]);
    let (config, off_stderr) = reached_builder(&off);
    assert!(automatic_binds(&h, &config).is_empty(), "{off_stderr}");

    // (e) Both `commondir` and the back-pointer deleted, with the directory still
    //     under `<common>/worktrees` — the second evidence route.
    let repo = build_worktree(&h);
    std::fs::remove_file(repo.per_worktree.join("commondir")).unwrap();
    std::fs::remove_file(repo.per_worktree.join("gitdir")).unwrap();
    let before = h.before();
    let out = h.launch(&[], "shell", &[]);
    h.assert_refused_before_launch_state(&out, &before, "git worktree repair");

    // (c) A real submodule has a gitfile and no linked-worktree evidence: the
    //     plan is the `off` plan.
    clear_dir(&h.project_root);
    let child = h.home_root.join("repos/child");
    let _ = std::fs::remove_dir_all(&child);
    std::fs::create_dir_all(&child).unwrap();
    git_ok(&child, &h.home_root, &["init", "-q"]);
    git_ok(&child, &h.home_root, &["config", "user.name", "gm"]);
    git_ok(
        &child,
        &h.home_root,
        &["config", "user.email", "gm@example.invalid"],
    );
    write_file(&child.join("tracked.txt"), "child\n");
    git_ok(&child, &h.home_root, &["add", "tracked.txt"]);
    git_ok(&child, &h.home_root, &["commit", "-q", "-m", "child"]);
    git_ok(&h.project_root, &h.home_root, &["init", "-q"]);
    git_ok(
        &h.project_root,
        &h.home_root,
        &["submodule", "add", child.to_str().unwrap(), "nested"],
    );
    let submodule = h.project_root.join("nested");
    assert!(
        submodule.join(".git").is_file(),
        "a submodule's `.git` is a gitfile"
    );
    let plain = h.launch_in(&submodule, &[], "shell", &[]);
    let (plain_config, plain_stderr) = reached_builder(&plain);
    let off = h.launch_in(&submodule, &["--git-mount=off"], "shell", &[]);
    let (off_config, off_stderr) = reached_builder(&off);
    assert_eq!(
        sorted_binds(&plain_config),
        sorted_binds(&off_config),
        "a submodule keeps the `off` plan\n{plain_stderr}\n{off_stderr}"
    );
    assert!(
        !plain_stderr.contains("==> Git metadata:"),
        "{plain_stderr}"
    );

    // (d) `--separate-git-dir` also leaves no `commondir` and no evidence.
    let repo = build_worktree(&h);
    let _ = repo;
    clear_dir(&h.project_root);
    let separate = h.home_root.join("sep");
    let _ = std::fs::remove_dir_all(&separate);
    git_ok(
        &h.home_root,
        &h.home_root,
        &[
            "init",
            "-q",
            &format!("--separate-git-dir={}", separate.display()),
            h.project_root.to_str().unwrap(),
        ],
    );
    assert!(h.project_root.join(".git").is_file());
    let plain = h.launch(&[], "shell", &[]);
    let (plain_config, plain_stderr) = reached_builder(&plain);
    let off = h.launch(&["--git-mount=off"], "shell", &[]);
    let (off_config, off_stderr) = reached_builder(&off);
    assert_eq!(
        sorted_binds(&plain_config),
        sorted_binds(&off_config),
        "`--separate-git-dir` keeps the `off` plan\n{plain_stderr}\n{off_stderr}"
    );
}

// ---------------------------------------------------------------------------
// T20 — B4: a fork at risk is never published before an automatic refusal
// ---------------------------------------------------------------------------

/// T20. A valid but unpublished `:fork` declared *before* the automatic requests
/// is not published when the plan is refused, and controls prove it would have
/// been.
#[test]
fn a_refused_plan_publishes_no_fork() {
    let h = Harness::new();
    let fork_source = h.home_root.join("forksrc");
    std::fs::create_dir(&fork_source).unwrap();
    write_file(&fork_source.join("seed"), "seed\n");
    let fork = format!("{}:/forks:fork", fork_source.display());

    // (a) a differing explicit declaration at the automatic guest path.
    let repo = build_worktree(&h);
    let common = repo.common.canonicalize().unwrap().display().to_string();
    let before = h.before();
    let out = h.launch(&["--mount", &fork, "--mount", &common], "shell", &[]);
    let stderr = stderr_of(&out);
    h.assert_refused_before_launch_state(&out, &before, "claimed by different declarations");
    assert!(
        !stderr.contains("Initialized fork"),
        "no fork may be published: {stderr}"
    );
    assert!(
        h.mount_store().is_none(),
        "no store, lock or staging: {stderr}"
    );

    // (b) a Pi protection refusal.
    build_bare_pi(&h);
    let before = h.before();
    let out = h.launch(&["--mount", &fork], "shell", &[]);
    let stderr = stderr_of(&out);
    h.assert_refused_before_launch_state(&out, &before, "auth.json");
    assert!(!stderr.contains("Initialized fork"), "{stderr}");
    assert!(h.mount_store().is_none(), "{stderr}");

    // (c) a `persist` collision.
    build_bare_worktree(&h, &h.home_root.join("code"));
    h.write_project(
        "[[tools]]\nname = \"aider\"\ncommand = \"/bin/echo\"\ncredentials = []\npersist = [\"code\"]\n",
    );
    let before = h.before();
    let out = h.launch(&["--mount", &fork], "aider", &[]);
    let stderr = stderr_of(&out);
    h.assert_refused_before_launch_state(&out, &before, "would collide with the guest mount point");
    assert!(!stderr.contains("Initialized fork"), "{stderr}");
    assert!(h.mount_store().is_none(), "{stderr}");

    // (d) the control: the same fork on a clean layout-A worktree is published.
    std::fs::remove_file(h.project_config()).unwrap();
    let _repo = build_worktree(&h);
    let out = h.launch(&["--mount", &fork], "shell", &[]);
    let (_, stderr) = reached_builder(&out);
    assert!(
        stderr.contains("Initialized fork"),
        "the control must publish: {stderr}"
    );
    let store = h.mount_store().expect("the control creates the store");
    let forks: Vec<PathBuf> = std::fs::read_dir(store.join("forks"))
        .expect("a forks directory")
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(forks.len(), 1, "{forks:?}");
    assert!(
        forks[0].join("data/seed").is_file(),
        "the fork holds the copy"
    );
}
