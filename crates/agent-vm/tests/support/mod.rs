//! Shared helpers for agent-vm's boot-free integration-test harnesses.
//!
//! Rust compiles each file in `tests/` as its own crate, so this module is
//! rebuilt per test binary. It exists to keep a cross-harness precondition in
//! one place rather than copied into every harness that needs it.

use std::path::{Path, PathBuf};

#[path = "../../src/guest_paths.rs"]
mod guest_paths;

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
