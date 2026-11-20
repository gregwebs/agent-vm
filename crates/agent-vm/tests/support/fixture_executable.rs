//! Executable fixtures for the integration-test harnesses.
//!
//! A fixture that a test writes and then `exec`s must not leave a writable
//! descriptor in this process. `fork` duplicates the whole descriptor table
//! into the child, and Linux refuses to `execve` an inode while any process
//! still holds a write descriptor for it — reported as `ETXTBSY`
//! (`Text file busy`, os error 26). With hundreds of tests forking in
//! parallel, a `fork` lands inside the write window often enough to fail an
//! unrelated test (issue #357), and no write-then-`rename` sequence narrows
//! that window: `rename` keeps the inode the duplicated descriptor points at.
//! Writing the fixture from a child process keeps the descriptor out of this
//! process, so no sibling test can inherit it.
//!
//! Integration tests are separate crates, so they cannot reach the identical
//! `#[cfg(test)]` helper in `crate::test_fixtures`; this file is that helper
//! for `tests/`, included per binary with `#[path]`.

use std::path::Path;

/// Write `contents` to `path` as a mode-0755 executable.
///
/// `contents` and `path` travel as arguments, so quoting and spacing in either
/// reach the file byte-for-byte. Failing to write is a harness error, not an
/// assertion under test, so it panics.
pub fn write_executable(path: &Path, contents: &str) {
    let status = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("printf '%s' \"$1\" > \"$2\"")
        .arg("write-test-executable")
        .arg(contents)
        .arg(path)
        .status()
        .unwrap_or_else(|error| panic!("spawning /bin/sh to write {}: {error}", path.display()));
    assert!(
        status.success(),
        "writing the executable fixture {} failed: {status}",
        path.display()
    );

    use std::os::unix::fs::PermissionsExt as _;
    let mut perms = std::fs::metadata(path)
        .unwrap_or_else(|error| panic!("stat {}: {error}", path.display()))
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms)
        .unwrap_or_else(|error| panic!("chmod {}: {error}", path.display()));
}
