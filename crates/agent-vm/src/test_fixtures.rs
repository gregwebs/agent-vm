//! Executable fixtures for `#[cfg(test)]` unit tests.
//!
//! A fixture that a test writes and then `exec`s must not leave a writable
//! descriptor in this process. `fork` duplicates the whole descriptor table
//! into the child, and Linux refuses to `execve` an inode while any process
//! still holds a write descriptor for it — reported as `ETXTBSY`. With over a
//! thousand tests forking in parallel, a `fork` lands inside the write window
//! often enough to fail CI on an unrelated PR (issue #315), and no
//! write-then-`rename` sequence narrows that window: `rename` keeps the inode
//! the duplicated descriptor points at. Writing the fixture from a child
//! process keeps the descriptor out of this process, so no other test can
//! inherit it.

use std::path::Path;

/// Write `contents` to `path` as a mode-0755 executable.
///
/// `contents` and `path` travel as arguments, so quoting and spacing in either
/// reach the file byte-for-byte. Failing to write is a harness error, not an
/// assertion under test, so it panics.
pub(crate) fn write_executable(path: &Path, contents: &str) {
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
