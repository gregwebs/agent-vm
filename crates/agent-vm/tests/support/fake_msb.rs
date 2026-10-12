//! A fake `msb` for agent-vm's boot-free integration-test harnesses.
//!
//! Harnesses include this with `#[path = "support/fake_msb.rs"] mod fake_msb;`
//! rather than through `support`, so only the test crates that spawn a fake
//! runtime compile it. Each crate uses a different subset (the specialised
//! fakes in `config_launch_driven.rs` and `msb_passthrough.rs` need only
//! [`VERSION_LINE`] and [`write_executable`]), hence the `dead_code` allowance.
#![allow(dead_code)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// What the vendored runtime prints for `msb --version`. `point_at_msb`
/// refuses any other version, so this is the one literal to change when the
/// `vendor/microsandbox` pin moves to a new version. It cannot come from
/// `msb_install::expected_msb_version()`: these are black-box tests that spawn
/// the compiled binary and do not link the crate. If it drifts, every harness
/// fails at `point_at_msb`.
pub const VERSION_LINE: &str = "msb 0.7.4";

/// Write `contents` to `path` as a mode-0755 executable.
///
/// Writes a uniquely named temporary and renames it into place. The rename is
/// atomic replacement, so a reader never sees a half-written script and a test
/// can rewrite a running shim without the writer side failing on `ETXTBSY`. It
/// does not narrow the `execve` race: `ETXTBSY` checks the inode's write count,
/// and `rename` keeps the inode, so a concurrent `fork` that duplicates the
/// temporary's write descriptor still blocks an immediate `exec` of `path`.
/// That race is kernel timing, so a caller that immediately `exec`s the result
/// retries on `ExecutableFileBusy`.
pub fn write_executable(path: &Path, contents: &str) {
    let temp = temp_path(path);
    let result = (|| -> std::io::Result<()> {
        std::fs::write(&temp, contents)?;
        let mut perms = std::fs::metadata(&temp)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&temp, perms)?;
        std::fs::rename(&temp, path)
    })();
    if let Err(error) = result {
        let _ = std::fs::remove_file(&temp);
        panic!("write_executable({}) failed: {error}", path.display());
    }
}

/// A process-unique sibling of `path`, so parallel tests writing the same
/// fixture name cannot collide on the temporary.
fn temp_path(path: &Path) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "fixture".to_owned());
    name.push_str(&format!(".{}.{unique}.tmp", std::process::id()));
    path.with_file_name(name)
}

/// Write `dir/msb`, a fake that answers every invocation with
/// [`VERSION_LINE`], which is enough for `point_at_msb`'s `--version` check.
pub fn write(dir: &Path) -> PathBuf {
    let path = dir.join("msb");
    write_executable(
        &path,
        &format!("#!/bin/sh\necho '{VERSION_LINE}'\nexit 0\n"),
    );
    path
}
