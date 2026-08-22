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

/// Write a fake `msb` that always reports the patched-build marker,
/// satisfying `point_at_msb`'s `--version` check regardless of subcommand or
/// args. Mirrors `msb_cache_share.rs`'s helper of the same name.
fn write_fake_msb(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("msb");
    std::fs::write(
        &path,
        "#!/bin/sh\necho 'msb 0.4.6+agent-vm.phase4'\nexit 0\n",
    )
    .unwrap();
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
        // The relay socket lives below the state directory. macOS's default
        // temporary root is long enough to exceed Unix's socket-path limit.
        let home = tempfile::tempdir_in("/tmp").unwrap();
        let state = tempfile::tempdir_in("/tmp").unwrap();
        let project = tempfile::tempdir_in("/tmp").unwrap();
        let fake_msb = write_fake_msb(home.path());
        Self { home, state, project, fake_msb }
    }

    fn home_path(&self) -> PathBuf {
        self.home.path().canonicalize().unwrap()
    }

    /// Run `agent-vm shell --mount <m> [--mount <m>...] --image <bogus>`
    /// with `HOME`/`AGENT_VM_STATE_DIR`/cwd pinned to this harness's
    /// tempdirs, `MSB_PATH` pinned to the fake patched msb, and
    /// `AGENT_VM_DEBUG_CONFIG=1` set so `launch()` dumps the built
    /// `SandboxConfig` JSON to stderr right before the (expected-to-fail)
    /// pull.
    fn run_shell(&self, mounts: &[&str]) -> Output {
        self.run_shell_opts(mounts, false, true)
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
        let mut cmd = Command::new(agent_vm_bin());
        cmd.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("AGENT_VM_STATE_DIR", self.state.path())
            .env("MSB_PATH", &self.fake_msb)
            .env("AGENT_VM_DEBUG_CONFIG", "1")
            .current_dir(self.project.path())
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
/// `(host, readonly)` pairs. See `VolumeMount`'s hand-written `Serialize`
/// impl in vendor/microsandbox (packages/microsandbox-types/rust/lib/
/// domain.rs) — confirmed to emit `host` and `options.readonly` by field
/// name for `Bind` mounts.
fn bind_mounts(config: &serde_json::Value) -> Vec<(String, bool)> {
    config["mounts"]
        .as_array()
        .expect("config.mounts must be an array")
        .iter()
        .filter(|m| m["type"] == "Bind")
        .map(|m| {
            (
                m["host"].as_str().expect("Bind mount host must be a string").to_string(),
                m["options"]["readonly"].as_bool().expect("Bind mount options.readonly must be a bool"),
            )
        })
        .collect()
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

    let find = |needle: &str| mounts.iter().find(|(h, _)| h == needle);
    assert!(
        find(host_mount_str).is_some(),
        "expected the HOST bind itself among the mounts, got: {mounts:?}"
    );
    let (_, a_ro) = find(a_str).unwrap_or_else(|| {
        panic!("expected the direct discovered target {a_str} among the mounts, got: {mounts:?}")
    });
    assert!(a_ro, "discovered mount for {a_str} must be read-only");
    let (_, b_ro) = find(b_str).unwrap_or_else(|| {
        panic!(
            "expected the transitively discovered target {b_str} among the mounts (proves the \
             walk recursed), got: {mounts:?}"
        )
    });
    assert!(b_ro, "transitively discovered mount for {b_str} must be read-only");

    // Sanity: the process still failed on the bogus pull, as expected —
    // these assertions are about what happened before that, not this exit.
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
    assert!(err.contains("rw") && err.contains("follow-links"), "stderr:\n{err}");
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
    let out = h.run_shell_opts(&[&mount_arg], /* root */ true, /* set_home */ true);

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

    let out = h.run_shell_opts(&[&mount_arg], /* root */ true, /* set_home */ false);

    assert!(!out.status.success());
    let err = stderr_of(&out);
    assert!(err.contains("--mount follow-links"), "stderr:\n{err}");
    assert!(err.contains("HOME"), "stderr:\n{err}");
    assert!(
        !err.contains("[debug] sandbox config JSON"),
        "the guardrail must fail before builder.build() runs, stderr:\n{err}"
    );
}
