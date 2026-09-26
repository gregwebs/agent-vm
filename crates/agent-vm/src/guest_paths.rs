//! Guest paths the runtime tmpfs-mounts at boot.
//!
//! Shared, via `#[path]`, between the runtime (`run.rs`) and the boot-free test
//! harness (`tests/support/mod.rs`) so the harness's "is this project root off
//! tmpfs?" precondition can never drift from the runtime's actual remap policy.
//! Integration tests link the `agent-vm` binary, which exposes no library, so a
//! plain `pub` item could not reach them.

/// Paths that the guest will tmpfs-mount at boot, wiping anything our
/// `patch` builder baked into the rootfs underneath them. We refuse to mirror
/// a host project rooted here and fall back to `/workspace` instead.
pub(crate) const TMPFS_GUEST_PREFIXES: &[&str] = &["/tmp", "/run", "/dev/shm", "/var/run"];
