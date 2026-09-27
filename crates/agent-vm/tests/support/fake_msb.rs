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

/// What the vendored runtime prints for `msb --version`. `point_at_msb`
/// refuses any other version, so this is the one literal to change when the
/// `vendor/microsandbox` pin moves to a new version. It cannot come from
/// `msb_install::expected_msb_version()`: these are black-box tests that spawn
/// the compiled binary and do not link the crate. If it drifts, every harness
/// fails at `point_at_msb`.
pub const VERSION_LINE: &str = "msb 0.7.4";

/// Write `contents` to `path` as a mode-0755 executable.
pub fn write_executable(path: &Path, contents: &str) {
    std::fs::write(path, contents).unwrap();
    let mut perms = std::fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).unwrap();
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
