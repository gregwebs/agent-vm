//! Shared helpers for agent-vm's boot-free integration-test harnesses.
//!
//! Rust compiles each file in `tests/` as its own crate, so this module is
//! rebuilt per test binary. It exists to keep cross-harness preconditions — the
//! project root, the keychain stub, the bounded-child runner — in one place
//! rather than copied into every harness that needs them.
//!
//! Each harness uses a different subset of it, so unused items here are
//! expected — the same allowance `support/fake_msb.rs` and friends take.
#![allow(dead_code)]

use std::{
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

#[path = "../../src/guest_paths.rs"]
mod guest_paths;

/// Where agent-vm reads `project`'s host-managed config under `home` (ADR-0073).
///
/// The digest is computed here, independently of the product, so a wrong id in
/// `project_config::path` fails every harness instead of agreeing with itself.
/// `home` must be the exact `HOME` the child gets: neither tier is canonicalized
/// from it.
pub fn project_config_path(home: &Path, project: &Path) -> PathBuf {
    use sha2::{Digest as _, Sha256};
    use std::os::unix::ffi::OsStrExt as _;
    let canonical = project
        .canonicalize()
        .expect("canonicalize the project root");
    let hex: String = Sha256::digest(canonical.as_os_str().as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    home.join(".config/agent-vm/projects")
        .join(hex)
        .join("config.toml")
}

/// Cargo's per-target scratch directory (`<target>/tmp`), which lives on the
/// workspace filesystem rather than under a guest tmpfs prefix — unless the
/// caller pointed `CARGO_TARGET_DIR` at one.
pub fn workspace_tmpdir() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
}

/// Create a harness's project root under [`workspace_tmpdir`], failing fast
/// with an actionable message if that lands under a guest tmpfs prefix.
///
/// The boot-free harnesses deliberately place the project root under
/// `CARGO_TARGET_TMPDIR` so `run::resolve_project_guest_path` mirrors it into
/// the guest at its real path — the shape every real user gets — instead of
/// falling back to `/workspace`; their assertions pin that mirrored path. When
/// `CARGO_TARGET_DIR` is itself under `/tmp` (a common container/CI pattern),
/// `CARGO_TARGET_TMPDIR` inherits the prefix, the guest remaps the project to
/// `/workspace`, and those assertions fail as if the product were broken.
/// Refusing to run turns that mystifying failure into a self-explaining one.
///
/// The check is on the *canonicalized* dir, matching the runtime: on macOS
/// `/tmp` canonicalizes to `/private/tmp`, which is not under the `/tmp`
/// prefix, so such a run does mirror correctly and is allowed.
pub fn project_tempdir() -> tempfile::TempDir {
    let dir = tempfile::tempdir_in(workspace_tmpdir()).expect("create project temp dir");
    let canonical = dir
        .path()
        .canonicalize()
        .expect("canonicalize project temp dir");
    assert_off_tmpfs(&canonical);
    dir
}

/// A `PATH` whose `security` finds nothing, plus the handle that keeps the stub
/// alive for the child's lifetime.
///
/// For a harness that runs agent-vm with **no `$HOME`**: macOS resolves the
/// login keychain from the passwd entry rather than from `$HOME` there, so a
/// developer's real Claude Code login item would otherwise be read — and a
/// usable one would change the launch path the test is asserting (#492, R12).
/// A harness with a temp `$HOME` does not need this: `security` resolves
/// `$HOME/Library/Keychains/login.keychain-db` and misses.
///
/// Inert off macOS, where nothing reads a keychain.
pub fn path_without_host_keychain() -> (tempfile::TempDir, String) {
    use std::os::unix::fs::PermissionsExt as _;

    let root = tempfile::tempdir_in(workspace_tmpdir()).expect("create no-keychain stub dir");
    let bin = root.path().join("no-keychain-bin");
    std::fs::create_dir(&bin).expect("create no-keychain bin");
    let stub = bin.join("security");
    // 44 is `errSecItemNotFound`, which the reader treats as "no item" rather
    // than as a failure.
    std::fs::write(&stub, "#!/bin/sh\nexit 44\n").expect("write no-keychain stub");
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755))
        .expect("make the no-keychain stub executable");
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    (root, path)
}

/// Run `cmd` to completion, killing it if it doesn't exit within `timeout`.
///
/// Reads both pipes on threads so a full pipe cannot deadlock the wait, and
/// bounds the wait at `timeout` — a hung child fails the test instead of
/// stalling the suite. See [`run_with_input`] for stdin and the drain-error
/// policy.
pub fn run_with_timeout(cmd: Command, timeout: Duration) -> Output {
    run_with_input(cmd, None, timeout)
}

/// [`run_with_timeout`], plus optional text written to the child's stdin, which
/// is then closed. One implementation, so the hang bound is the same whether or
/// not a test speaks to its child; a caller that set its own stdin keeps it.
///
/// A failed drain — the `read_to_end` on either pipe — is fatal. It means the
/// harness lost the child's output, and every assertion in these suites reads
/// that output's text: a `contains` assertion would then fail for the wrong
/// reason, and a `!contains` assertion would pass for one. Naming the cause
/// beats both. A plain pipe signals end-of-stream as `Ok(0)`, not as an error,
/// so this only fires on a genuine read failure.
pub fn run_with_input(mut cmd: Command, input: Option<&str>, timeout: Duration) -> Output {
    if input.is_some() {
        cmd.stdin(Stdio::piped());
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("failed to spawn agent-vm");
    if let Some(text) = input {
        // Dropping the pipe closes the child's stdin, so an endpoint that reads
        // to EOF terminates instead of waiting for a second frame.
        let mut pipe = child.stdin.take().expect("piped stdin");
        pipe.write_all(text.as_bytes()).expect("write the frame");
    }
    let stdout_pipe = child.stdout.take().unwrap();
    let stderr_pipe = child.stderr.take().unwrap();
    let stdout_handle = std::thread::spawn(move || drain(stdout_pipe));
    let stderr_handle = std::thread::spawn(move || drain(stderr_pipe));

    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait failed") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            // Deliberately no join here: a descendant that inherited either
            // pipe would keep both drains blocked and turn a bounded hang into
            // an unbounded one.
            panic!("agent-vm did not exit within {timeout:?} (possible hang)");
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    Output {
        status,
        stdout: stdout_handle
            .join()
            .expect("the stdout drain thread panicked")
            .expect("drain stdout"),
        stderr: stderr_handle
            .join()
            .expect("the stderr drain thread panicked")
            .expect("drain stderr"),
    }
}

/// Read `pipe` to end-of-stream, returning what it produced or why the read
/// failed. Run on its own thread so the parent cannot block on a full pipe.
fn drain(mut pipe: impl Read) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    pipe.read_to_end(&mut buf).map(|_| buf)
}

/// Panic if `path` is under a guest tmpfs prefix, so the caller gets an
/// actionable message instead of a product-looking assertion failure.
fn assert_off_tmpfs(path: &Path) {
    let Some(s) = path.to_str() else {
        return;
    };
    if let Some(prefix) = guest_paths::TMPFS_GUEST_PREFIXES
        .iter()
        .copied()
        .find(|p| s == *p || s.starts_with(&format!("{p}/")))
    {
        panic!(
            "test harness precondition violated: the project root {} is under the guest \
             tmpfs prefix `{prefix}`. These boot-free tests put the project under \
             CARGO_TARGET_TMPDIR so the guest mirrors its host path instead of falling back \
             to /workspace, and assert on that mirrored path. Point CARGO_TARGET_DIR at a \
             path off tmpfs (not /tmp, /run, /dev/shm or /var/run) and re-run, e.g. \
             `CARGO_TARGET_DIR=/build/target cargo test -p agent-vm`. See CONTRIBUTING.md, \
             \"`CARGO_TARGET_DIR` must not be on a tmpfs prefix\".",
            path.display()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::assert_off_tmpfs;
    use std::path::Path;

    #[test]
    #[should_panic(expected = "CARGO_TARGET_DIR")]
    fn tmpfs_prefixed_project_root_is_refused() {
        // A Linux-style `/tmp` project: the guest would remap it to
        // `/workspace`, so the harness must refuse it.
        assert_off_tmpfs(Path::new("/tmp/lt/tmp/project"));
    }

    #[test]
    fn off_tmpfs_project_roots_are_allowed() {
        // macOS canonicalizes `/tmp` to `/private/tmp`, which is *not* under
        // the `/tmp` prefix and does get mirrored — so it must be allowed.
        for path in [
            "/private/tmp/lt/tmp/project",
            "/build/target/tmp/project",
            "/tmpfoo/project",
            "/run-extra/project",
        ] {
            assert_off_tmpfs(Path::new(path));
        }
    }
}
