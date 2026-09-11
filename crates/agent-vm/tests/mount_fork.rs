//! Boot-free integration test for `--mount HOST:ro:follow-links` (issue #11,
//! sub-issue of #9).
//!
//! Modeled on `tests/msb_cache_share.rs`, but that harness drives
//! `agent-vm setup --no-verify`, which never enters `launch()` — the
//! `--mount` parse/expand path and the `AGENT_VM_DEBUG_CONFIG` `SandboxConfig`
//! JSON dump only run under a launch subcommand (`shell`/`claude`/...). So
//! this harness drives `agent-vm shell` instead, with a controlled `HOME` /
//! `AGENT_VM_STATE_DIR` / cwd (project dir) / fake patched `MSB_PATH`, against
//! the same deliberately-bogus `localhost:1/...` registry used there: the
//! bogus pull fails late, well after `builder.build()` has already printed
//! the `SandboxConfig` JSON to stderr (run.rs:1117-1123) — which is what
//! these tests assert on, not the (expected) failure itself. Hermetic and
//! fast: no DNS, no external network, no Hypervisor.framework.
//!
//! Confirmed empirically (see the PR description / implementation notes) that
//! `VolumeMount::Bind`'s custom `Serialize` impl emits `host` and
//! `options.readonly` by field name, so parsing the dumped JSON and reading
//! `mounts[].host` / `mounts[].options.readonly` is a stable, non-brittle
//! signal — more direct than scraping the `==> Mounting … (read-only)`
//! stderr lines, though those are also present and could serve as a
//! secondary check.

use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

/// A bogus-but-well-formed image ref. Never resolves; only used to drive
/// execution far enough into `launch()` to prove `builder.build()` already
/// ran (its debug JSON dump happens right before the pull, which is what
/// fails here).
const BOGUS_IMAGE: &str = "localhost:1/does-not-exist:latest";

fn agent_vm_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-vm"))
}

/// Base directory for harness `$HOME`/project dirs that is on the real
/// workspace filesystem rather than a host path under a guest tmpfs prefix.
///
/// `run::guest_path_is_safe` remaps any project below `/tmp` (and the other
/// `TMPFS_GUEST_PREFIXES`) to `/workspace`. On macOS `tempdir_in("/tmp")`
/// canonicalizes to `/private/tmp`, which escapes that prefix, but on Linux
/// `/tmp` is a real directory, so a `/tmp` project is remapped and its guest
/// path stops equalling its host path. Cargo creates `CARGO_TARGET_TMPDIR`
/// (`<target>/tmp`) before running integration tests, so dirs created there
/// keep host and guest paths identical on both platforms.
fn harness_tmpdir() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
}

/// Write a fake `msb` that always reports the official version this
/// agent-vm build vendors, satisfying `point_at_msb`'s `--version` check
/// regardless of subcommand or args. Mirrors `msb_cache_share.rs`'s
/// helper of the same name.
fn write_fake_msb(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("msb");
    std::fs::write(&path, "#!/bin/sh\necho 'msb 0.6.15'\nexit 0\n").unwrap();
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).unwrap();
    path
}

/// Run `child` to completion, killing it if it doesn't exit within
/// `timeout`. Reads stdout/stderr on separate threads so a full pipe can't
/// deadlock the wait. Duplicated from `msb_cache_share.rs` rather than
/// shared — Rust integration tests are separate binaries and there's no
/// `tests/support/` module in this crate yet to hang a shared helper off.
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

fn state_tree(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn visit(root: &Path, path: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
        for entry in std::fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let relative = entry.path().strip_prefix(root).unwrap().to_path_buf();
            let metadata = std::fs::symlink_metadata(entry.path()).unwrap();
            if metadata.is_dir() {
                out.push((relative.clone(), b"directory".to_vec()));
                visit(root, &entry.path(), out);
            } else if metadata.file_type().is_symlink() {
                use std::os::unix::ffi::OsStrExt;
                out.push((
                    relative,
                    std::fs::read_link(entry.path())
                        .unwrap()
                        .as_os_str()
                        .as_bytes()
                        .to_vec(),
                ));
            } else {
                out.push((relative, std::fs::read(entry.path()).unwrap()));
            }
        }
    }

    let mut entries = Vec::new();
    visit(root, root, &mut entries);
    entries.sort();
    entries
}

/// One isolated `$HOME` + `AGENT_VM_STATE_DIR` + project dir (cwd) + fake
/// `MSB_PATH`, plus a helper to invoke `agent-vm shell --mount ... --image
/// <bogus>` with a fully-controlled environment (no inherited vars beyond
/// `PATH`) and `AGENT_VM_DEBUG_CONFIG=1` set.
struct Harness {
    home: tempfile::TempDir,
    state: tempfile::TempDir,
    project: tempfile::TempDir,
    fake_msb: PathBuf,
}

impl Harness {
    fn new() -> Self {
        // The relay socket lives below the state directory, so keep that one
        // under `/tmp` to stay within Unix's socket-path limit. `$HOME` and
        // the project dir live on the workspace filesystem instead: a project
        // under `/tmp` is remapped to `/workspace` on Linux, breaking tests
        // that reason about the project's guest path.
        let home = tempfile::tempdir_in(harness_tmpdir()).unwrap();
        let state = tempfile::tempdir_in("/tmp").unwrap();
        let project = tempfile::tempdir_in(harness_tmpdir()).unwrap();
        let fake_msb = write_fake_msb(home.path());
        Self {
            home,
            state,
            project,
            fake_msb,
        }
    }

    fn home_path(&self) -> PathBuf {
        self.home.path().canonicalize().unwrap()
    }

    fn project_path(&self) -> PathBuf {
        self.project.path().canonicalize().unwrap()
    }

    /// Run `agent-vm shell --mount <m> [--mount <m>...] --image <bogus>`
    /// with `HOME`/`AGENT_VM_STATE_DIR`/cwd pinned to this harness's
    /// tempdirs, `MSB_PATH` pinned to the fake patched msb, and
    /// `AGENT_VM_DEBUG_CONFIG=1` set so `launch()` dumps the built
    /// `SandboxConfig` JSON to stderr right before the (expected-to-fail)
    /// pull.
    fn run_shell(&self, mounts: &[&str]) -> Output {
        self.run_shell_at_state(mounts, &self.state.path().canonicalize().unwrap())
    }

    fn run_shell_at_state(&self, mounts: &[&str], state: &Path) -> Output {
        self.run_shell_opts_from_state(mounts, false, true, self.project.path(), state)
    }

    fn run_shell_from(&self, mounts: &[&str], project: &Path) -> Output {
        self.run_shell_opts_from(mounts, false, true, project)
    }

    /// Like `run_shell`, but additionally lets a test pass `--root` and/or
    /// omit `HOME` from the child's environment entirely (as opposed to
    /// setting it to an empty string). Both knobs exist to exercise the
    /// `$HOME` guardrail's interaction with `--root`: in non-root mode,
    /// `launch()` fails earlier — inside guest-identity resolution
    /// (`user.rs::resolve_host_home`) — whenever `$HOME` is unset, before
    /// `expand_follow_links`'s own guardrail ever runs; `--root` mode skips
    /// guest-identity resolution's `$HOME` requirement entirely
    /// (`resolve_guest_identity(true)` returns `None` unconditionally), so
    /// it is the only reachable path that actually exercises
    /// `expand_follow_links`'s own "$HOME is not set" error, and the only
    /// path that proves the guardrail's `$HOME` value — read directly from
    /// the env var, independent of `guest_identity` — is actually wired
    /// into `launch()` rather than silently no-op'ing under `--root`.
    fn run_shell_opts(&self, mounts: &[&str], root: bool, set_home: bool) -> Output {
        self.run_shell_opts_from(mounts, root, set_home, self.project.path())
    }

    fn run_shell_opts_from(
        &self,
        mounts: &[&str],
        root: bool,
        set_home: bool,
        project: &Path,
    ) -> Output {
        self.run_shell_opts_from_state(
            mounts,
            root,
            set_home,
            project,
            &self.state.path().canonicalize().unwrap(),
        )
    }

    fn run_shell_opts_from_state(
        &self,
        mounts: &[&str],
        root: bool,
        set_home: bool,
        project: &Path,
        state: &Path,
    ) -> Output {
        let mut cmd = Command::new(agent_vm_bin());
        cmd.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("AGENT_VM_STATE_DIR", state)
            .env("MSB_PATH", &self.fake_msb)
            .env("AGENT_VM_DEBUG_CONFIG", "1")
            .current_dir(project)
            .arg("shell");
        if set_home {
            cmd.env("HOME", self.home.path());
        }
        if root {
            cmd.arg("--root");
        }
        for m in mounts {
            cmd.arg("--mount").arg(m);
        }
        cmd.args(["--image", BOGUS_IMAGE]);
        run_with_timeout(cmd, Duration::from_secs(15))
    }
}

/// Extract the `SandboxConfig` JSON that `AGENT_VM_DEBUG_CONFIG=1` dumps to
/// stderr right after `builder.build()` (run.rs:1117-1123): find the
/// `[debug] sandbox config JSON: ` marker and parse the first complete JSON
/// value that follows it, ignoring whatever prints after (the pull-progress
/// output, then the expected registry-connect error).
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

/// The `Bind` mounts in a dumped `SandboxConfig`'s `mounts` array, as
/// `(host, guest, readonly)` triples. See `VolumeMount`'s hand-written
/// `Serialize` impl in vendor/microsandbox (packages/microsandbox-types/
/// rust/lib/domain.rs) — confirmed to emit `host`, `guest` and
/// `options.readonly` by field name for `Bind` mounts.
fn bind_mounts(config: &serde_json::Value) -> Vec<(String, String, bool)> {
    config["mounts"]
        .as_array()
        .expect("config.mounts must be an array")
        .iter()
        .filter(|m| m["type"] == "Bind")
        .map(|m| {
            (
                m["host"]
                    .as_str()
                    .expect("Bind mount host must be a string")
                    .to_string(),
                m["guest"]
                    .as_str()
                    .expect("Bind mount guest must be a string")
                    .to_string(),
                m["options"]["readonly"]
                    .as_bool()
                    .expect("Bind mount options.readonly must be a bool"),
            )
        })
        .collect()
}

#[test]
fn absent_state_root_supports_directory_fork_seed_and_reuse() {
    let h = Harness::new();
    let state_parent = tempfile::tempdir_in("/tmp").unwrap();
    let state = state_parent
        .path()
        .canonicalize()
        .unwrap()
        .join("absent/state-root");
    let source = h.home.path().join("directory-source");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("seed"), "seed").unwrap();
    let mount = format!("{}:/guest:fork", source.display());

    let seeded = h.run_shell_at_state(&[&mount], &state);
    let seeded_stderr = stderr_of(&seeded);
    assert!(
        seeded_stderr.contains("Initialized fork"),
        "{seeded_stderr}"
    );
    assert!(
        seeded_stderr.contains("[debug] sandbox config JSON:"),
        "{seeded_stderr}"
    );

    let reused = h.run_shell_at_state(&[&mount], &state);
    let reused_stderr = stderr_of(&reused);
    assert!(reused_stderr.contains("Reusing fork"), "{reused_stderr}");
    assert!(
        reused_stderr.contains("[debug] sandbox config JSON:"),
        "{reused_stderr}"
    );
}

#[test]
fn ready_file_fork_with_explicit_child_is_rejected_before_launch_effects_in_either_order() {
    for fork_first in [false, true] {
        let h = Harness::new();
        let source = h.home.path().join("source-file");
        let child = h.home.path().join("child-directory");
        std::fs::write(&source, "seed").unwrap();
        std::fs::create_dir(&child).unwrap();
        let fork = format!("{}:/guest/file:fork", source.display());

        // First launch seeds the file fork. The deliberately bogus image
        // fails only after builder configuration, so this proves the seed is
        // committed before the second launch's side-effect-free rejection.
        let seeded = h.run_shell(&[&fork]);
        assert!(stderr_of(&seeded).contains("Initialized fork"));
        std::fs::remove_file(&source).unwrap();

        let child_mount = format!("{}:/guest/file/child:ro", child.display());
        let mounts = if fork_first {
            vec![fork.as_str(), child_mount.as_str()]
        } else {
            vec![child_mount.as_str(), fork.as_str()]
        };
        let before = state_tree(h.state.path());
        let rejected = h.run_shell(&mounts);
        assert!(!rejected.status.success());
        let stderr = stderr_of(&rejected);
        assert!(stderr.contains("below file mount"), "{stderr}");
        assert!(
            !stderr.contains("[debug] sandbox config JSON:")
                && !stderr.contains("Initialized fork")
                && !stderr.contains("Reusing fork")
                && !stderr.contains("==> Mounting")
                && !stderr.contains("==> Masking"),
            "a rejected complete plan must not emit notices or builder output: {stderr}"
        );
        assert_eq!(
            state_tree(h.state.path()),
            before,
            "a rejected complete plan must not mutate state"
        );
    }
}

#[test]
fn absent_state_root_supports_file_fork() {
    let h = Harness::new();
    let state_parent = tempfile::tempdir_in("/tmp").unwrap();
    let state = state_parent
        .path()
        .canonicalize()
        .unwrap()
        .join("absent/state-root");
    let source = h.home.path().join("file-source");
    std::fs::write(&source, "seed").unwrap();
    let mount = format!("{}:/guest-file:fork", source.display());

    let output = h.run_shell_at_state(&[&mount], &state);
    let stderr = stderr_of(&output);
    assert!(stderr.contains("Initialized fork"), "{stderr}");
    assert!(stderr.contains("[debug] sandbox config JSON:"), "{stderr}");
}

#[test]
fn absent_state_root_supports_live_file_and_directory_exclusions() {
    let h = Harness::new();
    let state_parent = tempfile::tempdir_in("/tmp").unwrap();
    let state = state_parent
        .path()
        .canonicalize()
        .unwrap()
        .join("absent/state-root");
    let source = h.home.path().join("live-source");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("hidden-file"), "secret").unwrap();
    std::fs::create_dir(source.join("hidden-directory")).unwrap();
    let mount = format!(
        "{}:/guest:ro:exclude=hidden-file:exclude=hidden-directory",
        source.display()
    );

    let output = h.run_shell_at_state(&[&mount], &state);
    let stderr = stderr_of(&output);
    let mounts = bind_mounts(&debug_config_json(&stderr));
    assert!(
        mounts
            .iter()
            .any(|(_, guest, readonly)| guest == "/guest/hidden-file" && *readonly),
        "expected a readonly file mask, got: {mounts:?}"
    );
    assert!(stderr.contains("[debug] sandbox config JSON:"), "{stderr}");
    assert!(
        state.exists(),
        "valid masks must create their required store hierarchy"
    );
}

#[test]
fn file_fork_above_core_fails_before_mount_or_launch_side_effects() {
    let h = Harness::new();
    let state_parent = tempfile::tempdir_in("/tmp").unwrap();
    let state = state_parent
        .path()
        .canonicalize()
        .unwrap()
        .join("absent/state-root");
    let source = h.home.path().join("source-file");
    std::fs::write(&source, "seed").unwrap();
    let project = h.project_path();
    let guest = project.parent().unwrap();
    let mount = format!("{}:{}:fork", source.display(), guest.display());

    let output = h.run_shell_at_state(&[&mount], &state);
    assert!(!output.status.success());
    let stderr = stderr_of(&output);
    assert!(stderr.contains("below file mount"), "{stderr}");
    assert!(
        !stderr.contains("[debug] sandbox config JSON:")
            && !stderr.contains("Initialized fork")
            && !stderr.contains("Reusing fork")
            && !stderr.contains("==> Mounting"),
        "a rejected topology must not emit builder or mount side effects: {stderr}"
    );
    assert!(
        !state.exists(),
        "a rejected topology must not create even an absent state root"
    );
}

#[test]
fn exact_core_explicit_collision_fails_before_launch_side_effects() {
    let h = Harness::new();
    let source = h.home.path().join("fork-source");
    std::fs::create_dir(&source).unwrap();
    let project = h.project_path();
    let mount = format!("{}:{}:fork", source.display(), project.display());

    let output = h.run_shell(&[&mount]);
    assert!(!output.status.success());
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("collides with an agent-vm core mount"),
        "{stderr}"
    );
    assert_no_launch_side_effects(&h, &stderr);
}

#[test]
fn exact_core_followed_collision_fails_before_launch_side_effects() {
    let h = Harness::new();
    let home = h.home_path();
    let project = home.join("project");
    let source = home.join("follow-source");
    std::fs::create_dir(&project).unwrap();
    std::fs::create_dir(&source).unwrap();
    std::os::unix::fs::symlink(&project, source.join("project-alias")).unwrap();
    let mount = format!("{}:/guest:ro:follow-links", source.display());

    let output = h.run_shell_from(&[&mount], &project);
    assert!(!output.status.success());
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("mount plan collides with an agent-vm core mount"),
        "{stderr}"
    );
    assert_no_launch_side_effects(&h, &stderr);
}

fn assert_no_launch_side_effects(harness: &Harness, stderr: &str) {
    assert!(
        !stderr.contains("[debug] sandbox config JSON:")
            && !stderr.contains("Initialized fork")
            && !stderr.contains("Reusing fork")
            && !stderr.contains("==> Mounting")
            && !stderr.contains("==> Masking"),
        "a rejected topology must not emit builder or mount notices: {stderr}"
    );
    let state_entries = std::fs::read_dir(harness.state.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    assert!(
        state_entries.is_empty(),
        "a rejected topology must not create session, fork, mask, credential, or builder state: {state_entries:?}"
    );
}

#[test]
fn conflicting_declarations_fail_before_mount_or_launch_side_effects_in_either_order() {
    // `launch` calls mount::prepare before notices, repository scanning,
    // credential refresh, or builder wiring. Exercise that ordering through
    // the process boundary rather than inferring it from the unit seam.
    for fork_first in [true, false] {
        let h = Harness::new();
        let fork_source = h.home.path().join("fork-source");
        let live_source = h.home.path().join("live-source");
        std::fs::create_dir(&fork_source).unwrap();
        std::fs::create_dir(&live_source).unwrap();
        let fork = format!("{}:/collision:fork", fork_source.display());
        let live = format!("{}:/collision:ro", live_source.display());
        let mounts = if fork_first {
            vec![fork.as_str(), live.as_str()]
        } else {
            vec![live.as_str(), fork.as_str()]
        };

        let output = h.run_shell(&mounts);
        assert!(!output.status.success());
        let stderr = stderr_of(&output);
        assert!(
            stderr.contains("claimed by different declarations"),
            "{stderr}"
        );
        assert!(
            !stderr.contains("[debug] sandbox config JSON:"),
            "a rejected mount plan must not reach builder wiring: {stderr}"
        );
        assert!(
            !stderr.contains("Initialized fork")
                && !stderr.contains("Reusing fork")
                && !stderr.contains("Masking "),
            "a rejected mount plan must not emit mount notices: {stderr}"
        );
        assert!(
            std::fs::read_dir(h.state.path())
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".mounts")),
            "a rejected plan must not create a fork/mask store"
        );
        assert!(
            std::fs::read_dir(h.state.path())
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".secrets")),
            "a rejected plan must not refresh credentials"
        );
    }
}

#[test]
fn follow_links_discovers_transitive_targets_readonly() {
    let h = Harness::new();
    let home = h.home_path();

    // A symlink farm entirely under $HOME (required by the guardrail):
    //   HOST/link_to_a -> A            (direct)
    //   A/link_to_b    -> B            (transitive — proves the walk recurses)
    let host_mount = home.join("skills");
    let a = home.join("dev-a");
    let b = home.join("dev-b");
    std::fs::create_dir_all(&host_mount).unwrap();
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();
    std::fs::write(a.join("marker.txt"), "a").unwrap();
    std::fs::write(b.join("marker.txt"), "b").unwrap();
    std::os::unix::fs::symlink(&a, host_mount.join("link_to_a")).unwrap();
    std::os::unix::fs::symlink(&b, a.join("link_to_b")).unwrap();

    let mount_arg = format!("{}:ro:follow-links", host_mount.display());
    let out = h.run_shell(&[&mount_arg]);

    let err = stderr_of(&out);
    let config = debug_config_json(&err);
    let mounts = bind_mounts(&config);

    let a_str = a.to_str().unwrap();
    let b_str = b.to_str().unwrap();
    let host_mount_str = host_mount.to_str().unwrap();

    let find = |needle: &str| mounts.iter().find(|(h, _, _)| h == needle);
    assert!(
        find(host_mount_str).is_some(),
        "expected the HOST bind itself among the mounts, got: {mounts:?}"
    );
    let (_, _, a_ro) = find(a_str).unwrap_or_else(|| {
        panic!("expected the direct discovered target {a_str} among the mounts, got: {mounts:?}")
    });
    assert!(a_ro, "discovered mount for {a_str} must be read-only");
    let (_, _, b_ro) = find(b_str).unwrap_or_else(|| {
        panic!(
            "expected the transitively discovered target {b_str} among the mounts (proves the \
             walk recursed), got: {mounts:?}"
        )
    });
    assert!(
        b_ro,
        "transitively discovered mount for {b_str} must be read-only"
    );

    // Sanity: the process still failed on the bogus pull, as expected —
    // these assertions are about what happened before that, not this exit.
    assert!(!out.status.success());
}

#[test]
fn follow_links_binds_target_at_the_literal_path_the_guest_will_readlink() {
    let h = Harness::new();
    let home = h.home_path();

    // The layout a real `~/.claude/skills` farm has, and the one plain
    // canonicalization gets wrong:
    //
    //   HOST/implement          -> $HOME/conf/.agents/skills/implement  (raw text)
    //   $HOME/conf/.agents/skills -> ../skills                          (parent link)
    //
    // The guest reads `HOST/implement` through the HOST bind, so its
    // `readlink()` yields the raw text — the `.agents/…` path — while the
    // host canonicalizes that to `$HOME/conf/skills/implement`. Binding
    // only the canonical path leaves the link dangling in the guest.
    let host_mount = home.join("skills");
    let conf = home.join("conf");
    let real_skills = conf.join("skills");
    let real_implement = real_skills.join("implement");
    let literal_implement = conf.join(".agents").join("skills").join("implement");
    std::fs::create_dir_all(&host_mount).unwrap();
    std::fs::create_dir_all(&real_implement).unwrap();
    std::fs::create_dir_all(conf.join(".agents")).unwrap();
    std::fs::write(real_implement.join("SKILL.md"), "skill").unwrap();
    std::os::unix::fs::symlink("../skills", conf.join(".agents").join("skills")).unwrap();
    std::os::unix::fs::symlink(&literal_implement, host_mount.join("implement")).unwrap();

    let mount_arg = format!("{}:ro:follow-links", host_mount.display());
    let out = h.run_shell(&[&mount_arg]);

    let err = stderr_of(&out);
    let mounts = bind_mounts(&debug_config_json(&err));

    let real_str = real_implement.to_str().unwrap();
    let literal_str = literal_implement.to_str().unwrap();
    assert!(
        mounts
            .iter()
            .any(|(host, guest, ro)| host == real_str && guest == real_str && *ro),
        "expected the canonical target {real_str} bound read-only at its own path, \
         got: {mounts:?}"
    );
    assert!(
        mounts
            .iter()
            .any(|(host, guest, ro)| host == real_str && guest == literal_str && *ro),
        "expected {real_str} ALSO bound read-only at {literal_str} — the path the \
         guest's own readlink() names — got: {mounts:?}"
    );

    assert!(!out.status.success());
}

#[test]
fn follow_links_handles_a_host_that_is_itself_a_symlink() {
    let h = Harness::new();
    let home = h.home_path();

    // The exact shape of `--mount ~/.claude/skills:follow-links` when
    // `~/.claude/skills` is a symlink: `parse_extra_mounts` canonicalizes
    // the HOST but leaves GUEST as typed, so the two sides of the root
    // differ. A *relative* link under it then resolves one directory
    // level away from where the host resolves it.
    //
    //   $HOME/skills             -> deep/realskills
    //   $HOME/deep/realskills/foo -> ../shared
    //   host resolves  -> $HOME/deep/shared
    //   guest resolves -> $HOME/shared
    let real = home.join("deep").join("realskills");
    let shared = home.join("deep").join("shared");
    let host_arg = home.join("skills");
    std::fs::create_dir_all(&real).unwrap();
    std::fs::create_dir_all(&shared).unwrap();
    std::fs::write(shared.join("marker.txt"), "shared").unwrap();
    std::os::unix::fs::symlink("deep/realskills", &host_arg).unwrap();
    std::os::unix::fs::symlink("../shared", real.join("foo")).unwrap();

    let mount_arg = format!("{}:ro:follow-links", host_arg.display());
    let out = h.run_shell(&[&mount_arg]);

    let err = stderr_of(&out);
    let mounts = bind_mounts(&debug_config_json(&err));

    let real_str = real.to_str().unwrap();
    let host_arg_str = host_arg.to_str().unwrap();
    assert!(
        mounts
            .iter()
            .any(|(host, guest, _)| host == real_str && guest == host_arg_str),
        "the HOST bind should carry the canonicalized host {real_str} at the guest \
         path as typed {host_arg_str}, got: {mounts:?}"
    );

    let shared_str = shared.to_str().unwrap();
    let want_guest = home.join("shared");
    let want_guest_str = want_guest.to_str().unwrap();
    assert!(
        mounts
            .iter()
            .any(|(host, guest, ro)| host == shared_str && guest == want_guest_str && *ro),
        "expected {shared_str} bound read-only at {want_guest_str} — where the guest \
         resolves `../shared` from the root's guest path — got: {mounts:?}"
    );

    assert!(!out.status.success());
}

#[test]
fn rw_follow_links_is_a_hard_parse_error_before_boot() {
    let h = Harness::new();
    let host_mount = h.project.path().join("m");
    std::fs::create_dir_all(&host_mount).unwrap();
    let mount_arg = format!("{}:rw:follow-links", host_mount.display());

    let out = h.run_shell(&[&mount_arg]);

    assert!(!out.status.success());
    let err = stderr_of(&out);
    assert!(err.contains("conflicting"), "stderr:\n{err}");
    assert!(
        err.contains("rw") && err.contains("follow-links"),
        "stderr:\n{err}"
    );
    assert!(
        !err.contains("[debug] sandbox config JSON"),
        "a parse error must fail before builder.build() runs, stderr:\n{err}"
    );
}

#[test]
fn follow_links_target_outside_home_is_a_hard_error() {
    let h = Harness::new();
    let home = h.home_path();
    // HOST lives under $HOME; the symlink target does not.
    let host_mount = home.join("skills");
    std::fs::create_dir_all(&host_mount).unwrap();
    let outside = h.project.path().join("outside-home-target");
    std::fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, host_mount.join("escape")).unwrap();

    let mount_arg = format!("{}:ro:follow-links", host_mount.display());
    let out = h.run_shell(&[&mount_arg]);

    assert!(!out.status.success());
    let err = stderr_of(&out);
    assert!(err.contains("outside your"), "stderr:\n{err}");
    assert!(err.contains("$HOME"), "stderr:\n{err}");
    assert!(
        !err.contains("[debug] sandbox config JSON"),
        "the guardrail must fail before builder.build() runs, stderr:\n{err}"
    );
}

/// Closes a verification gap found only by manually driving the real CLI
/// under `--root`: without this test, nothing at the integration level
/// proves the `$HOME` guardrail actually fires in root mode — only that
/// `expand_follow_links` behaves correctly as a pure function when handed
/// `home: Some(...)` directly (the mount.rs unit tests), and that the
/// non-root CLI path enforces it (the sibling test above). `--root` mode
/// takes a different code path to get `$HOME` (guest-identity resolution is
/// skipped entirely — see `run_shell_opts`'s doc comment), so this is the
/// one test that actually exercises `run.rs`'s `mount_home =
/// env::var("HOME")...` wiring end to end.
#[test]
fn follow_links_root_mode_enforces_home_guardrail() {
    let h = Harness::new();
    let home = h.home_path();
    let host_mount = home.join("skills");
    std::fs::create_dir_all(&host_mount).unwrap();
    let outside = h.project.path().join("outside-home-target");
    std::fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, host_mount.join("escape")).unwrap();

    let mount_arg = format!("{}:ro:follow-links", host_mount.display());
    let out = h.run_shell_opts(
        &[&mount_arg],
        /* root */ true,
        /* set_home */ true,
    );

    assert!(!out.status.success());
    let err = stderr_of(&out);
    assert!(err.contains("outside your"), "stderr:\n{err}");
    assert!(err.contains("$HOME"), "stderr:\n{err}");
    assert!(
        !err.contains("[debug] sandbox config JSON"),
        "the guardrail must fail before builder.build() runs even under --root, stderr:\n{err}"
    );
}

/// The other half of the `--root` gap: `--root` with `$HOME` unset entirely
/// must still hard-error (not silently mount everything unguarded) — this is
/// the one CLI-reachable path that actually exercises
/// `expand_follow_links`'s own "$HOME is not set — required for --mount
/// follow-links" message, since non-root mode fails earlier for an unrelated
/// reason (`user.rs::resolve_host_home`, required to mirror the guest's
/// HOME) whenever `$HOME` is unset.
#[test]
fn follow_links_root_mode_without_home_is_a_hard_error() {
    let h = Harness::new();
    let host_mount = h.project.path().join("m");
    std::fs::create_dir_all(&host_mount).unwrap();
    let mount_arg = format!("{}:ro:follow-links", host_mount.display());

    let out = h.run_shell_opts(
        &[&mount_arg],
        /* root */ true,
        /* set_home */ false,
    );

    assert!(!out.status.success());
    let err = stderr_of(&out);
    assert!(err.contains("--mount follow-links"), "stderr:\n{err}");
    assert!(err.contains("HOME"), "stderr:\n{err}");
    assert!(
        !err.contains("[debug] sandbox config JSON"),
        "the guardrail must fail before builder.build() runs, stderr:\n{err}"
    );
}

#[test]
fn ready_directory_fork_reuses_committed_anchor_for_nested_exclusion_in_either_order() {
    for child_follow_links in [false, true] {
        for fork_first in [false, true] {
            let h = Harness::new();
            let source = h.home_path().join("fork-source");
            let child = h.home_path().join("child-source");
            std::fs::create_dir(&source).unwrap();
            std::fs::create_dir(&child).unwrap();
            std::fs::write(child.join("secret"), "host secret").unwrap();
            if child_follow_links {
                std::fs::create_dir(child.join("linked")).unwrap();
                std::os::unix::fs::symlink("linked", child.join("alias")).unwrap();
            }
            // The fork preserves this nested link. On reuse, physical alias
            // validation must project the mask through committed `data`, not the
            // deleted declaration root.
            std::os::unix::fs::symlink(&child, source.join("child")).unwrap();
            let fork = format!("{}:/fork:fork", source.display());

            let seeded = h.run_shell(&[&fork]);
            let seeded_binds = bind_mounts(&debug_config_json(&stderr_of(&seeded)));
            let committed = seeded_binds
                .iter()
                .find(|(_, guest, _)| guest == "/fork")
                .map(|(host, _, _)| PathBuf::from(host))
                .expect("seeded fork bind");
            std::fs::remove_file(source.join("child")).unwrap();
            std::fs::remove_dir(&source).unwrap();

            let child_mount = format!(
                "{}:/fork/child:ro{}:exclude=secret",
                child.display(),
                if child_follow_links {
                    ":follow-links"
                } else {
                    ""
                },
            );
            let mounts = if fork_first {
                vec![fork.as_str(), child_mount.as_str()]
            } else {
                vec![child_mount.as_str(), fork.as_str()]
            };
            let reused = h.run_shell(&mounts);
            let stderr = stderr_of(&reused);
            assert!(stderr.contains("Reusing fork"), "{stderr}");
            let config = debug_config_json(&stderr);
            let binds = bind_mounts(&config);
            assert!(
                binds.iter().any(|(host, guest, readonly)| {
                    PathBuf::from(host) == committed && guest == "/fork" && !readonly
                }),
                "expected committed fork bind, got: {binds:?}"
            );
            assert!(
                binds.iter().any(|(host, guest, readonly)| {
                    host == &child.display().to_string() && guest == "/fork/child" && *readonly
                }),
                "expected child bind, got: {binds:?}"
            );
            assert!(
                binds.iter().any(|(host, guest, readonly)| {
                    host.ends_with(".mounts/.mask-file")
                        && guest == "/fork/child/secret"
                        && *readonly
                }),
                "expected readonly opaque file mask, got: {config}"
            );
            if child_follow_links {
                assert!(
                    binds.iter().any(|(host, guest, readonly)| {
                        host == &child.join("linked").display().to_string()
                            && guest == &child.join("linked").display().to_string()
                            && *readonly
                    }),
                    "expected followed child bind, got: {binds:?}"
                );
            }
            assert!(
                !source.exists(),
                "the deleted declaration source must not be needed after READY reuse"
            );
        }
    }
}

#[test]
fn fork_debug_config_uses_committed_data_not_source_and_reuses_it() {
    let h = Harness::new();
    let source = h.home_path().join("fork-source");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("visible"), "seed").unwrap();
    std::fs::write(source.join("hidden"), "secret").unwrap();
    let mount = format!("{}:/fork:fork:exclude=hidden", source.display());

    let first = h.run_shell(&[&mount]);
    let first_config = debug_config_json(&stderr_of(&first));
    let first_binds = bind_mounts(&first_config);
    let (_, _, readonly) = first_binds
        .iter()
        .find(|(_, guest, _)| guest == "/fork")
        .unwrap_or_else(|| panic!("missing fork bind: {first_binds:?}"));
    assert!(!readonly);
    let (host, _, _) = first_binds
        .iter()
        .find(|(_, guest, _)| guest == "/fork")
        .unwrap();
    assert_ne!(host, &source.display().to_string());
    let committed = PathBuf::from(host);
    assert_eq!(
        std::fs::read_to_string(committed.join("visible")).unwrap(),
        "seed"
    );
    assert!(!committed.join("hidden").exists());

    std::fs::write(source.join("visible"), "host-change").unwrap();
    std::fs::write(committed.join("visible"), "fork-change").unwrap();
    std::fs::remove_dir_all(&source).unwrap();
    let second = h.run_shell(&[&mount]);
    let second_config = debug_config_json(&stderr_of(&second));
    let second_binds = bind_mounts(&second_config);
    let (reused, _, _) = second_binds
        .iter()
        .find(|(_, guest, _)| guest == "/fork")
        .unwrap();
    assert_eq!(reused, host);
    assert_eq!(
        std::fs::read_to_string(committed.join("visible")).unwrap(),
        "fork-change"
    );
}
