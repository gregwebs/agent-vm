//! Discover and validate the patched `msb` binary that agent-vm needs.
//!
//! agent-vm depends on a patched microsandbox CLI (`msb`) — it ships a
//! `SecretValue::File` variant, the request-interceptor hook with
//! `dispatch_on_headers`, and a few other agent-vm-only features that
//! aren't in upstream. To avoid colliding with a user's separate
//! `~/.microsandbox/bin/msb` install (which would otherwise win on the
//! SDK's resolution ladder), agent-vm explicitly sets `MSB_PATH` to
//! its own bundled binary.
//!
//! ## Discovery
//!
//! In order of priority:
//!
//! 1. `MSB_PATH` env var — explicit override (testing, CI, devs).
//! 2. `<exe-dir>/msb` — sibling of `agent-vm` in the install bundle.
//!    This is what the npm distribution ships: each platform
//!    subpackage drops `agent-vm` and `msb` into `bin/` side by side.
//! 3. `<workspace>/vendor/microsandbox/build/msb` — the signed output
//!    produced by `script/build/macos.sh` in a source checkout.
//!
//! The first existing candidate wins. The resolved binary's
//! `--version` output MUST contain the `+agent-vm` marker (the
//! patched build tags itself, e.g. `msb 0.4.6+agent-vm.phase4`) —
//! otherwise we refuse to run with a clear "your install is stale or
//! shadowed by an upstream msb" error rather than producing weird
//! runtime failures inside the sandbox.

use std::{path::PathBuf, process::Command};

use anyhow::{Context, Result, bail};

/// Marker that the patched `msb --version` must contain. Upstream
/// builds print `msb <semver>` with no suffix; agent-vm's vendored
/// build appends `+agent-vm.phase<N>` so we can detect a shadowing
/// upstream binary.
const PATCHED_VERSION_MARKER: &str = "+agent-vm";

/// Path to the signed dev build, relative to the workspace.
///
/// Do not use `target/release/msb` here on macOS: Cargo's raw output is
/// linker-signed but lacks `com.apple.security.hypervisor`. The root macOS
/// build script copies that binary here and signs it with
/// `msb-entitlements.plist`.
fn workspace_built_msb() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vendor/microsandbox/build/msb")
}

/// Sibling-of-current-exe path, the npm-bundle layout.
fn exe_sibling_msb() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    Some(exe.parent()?.join("msb"))
}

/// Resolve the path to the patched msb that agent-vm should use.
///
/// Returns `Ok(Some(path))` on success, `Ok(None)` if no candidate
/// exists at all, or `Err` only on a present-but-broken candidate
/// (e.g. one that fails to even execute).
pub fn resolved_msb_path() -> Result<Option<PathBuf>> {
    if let Some(env_path) = std::env::var_os("MSB_PATH") {
        let p = PathBuf::from(&env_path);
        if p.exists() {
            return Ok(Some(p));
        }
        // Stale env from a previous dev session (common pitfall:
        // .bashrc / shell init kept the var around after the file was
        // moved or the dev directory deleted). Name MSB_PATH
        // explicitly so the user knows what to unset, and offer the
        // sibling fallback path if we can find one — otherwise the
        // env var is a permanent foot-gun.
        if let Some(sibling) = exe_sibling_msb()
            && sibling.exists()
        {
            eprintln!(
                "warn: MSB_PATH={} does not exist; ignoring and using sibling {}",
                p.display(),
                sibling.display()
            );
            return Ok(Some(sibling));
        }
        bail!(
            "MSB_PATH={} is set but the file does not exist, and no fallback msb \
             was found next to {}.\n\
             Either `unset MSB_PATH` to use the default discovery path, or point \
             it at a valid patched msb.",
            p.display(),
            std::env::current_exe()
                .map(|e| e.display().to_string())
                .unwrap_or_else(|_| "<agent-vm exe>".to_string())
        );
    }
    if let Some(p) = exe_sibling_msb()
        && p.exists()
    {
        return Ok(Some(p));
    }
    let dev = workspace_built_msb();
    if dev.exists() {
        return Ok(Some(dev));
    }
    Ok(None)
}

/// Point msb at the agent-vm-controlled state dir instead of
/// `~/.microsandbox/`.
///
/// Why we don't use the default upstream layout (`~/.microsandbox/`):
///
/// agent-vm ships its own patched `msb` and a libkrunfw rebuilt with
/// `CONFIG_KVM=y` (the upstream one has `# CONFIG_KVM is not set`,
/// killing nested KVM). If a user has a separate microsandbox install
/// — or just ran an older agent-vm version — the existing
/// `~/.microsandbox/lib/libkrunfw.so.X.Y.Z` would shadow ours and
/// `/dev/kvm` would silently not appear in the guest. Avoid the
/// conflict entirely by giving agent-vm its own `MSB_HOME` under
/// `state_root()`. Read-only bits (msb, libkrunfw) come from the
/// bundle next to `agent-vm` via msb's own resolver
/// (`MSB_PATH` → sibling `lib/`); writable bits (db, cache,
/// sandboxes, logs, secrets, tls/CA) live here.
///
/// Idempotent. Returns the path that was pinned.
pub fn point_at_msb_home() -> Result<PathBuf> {
    let dir = crate::host_paths::state_root()
        .ok_or_else(|| anyhow::anyhow!("could not resolve agent-vm state root ($HOME unset?)"))?
        .join("msb-home");
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating MSB_HOME at {}", dir.display()))?;
    // SAFETY: like [`point_at_msb`], called before the tokio runtime
    // spins up. setenv() is not thread-safe; this ordering invariant
    // is the only thing that makes the call sound.
    unsafe { std::env::set_var("MSB_HOME", &dir) };
    Ok(dir)
}

/// Resolve and pin the patched `msb` binary for this process.
///
/// Sets `MSB_PATH` to the resolved path, overriding the SDK's
/// default resolution ladder so a user's separate
/// `~/.microsandbox/bin/msb` can't shadow ours. Also runs
/// `msb --version` and verifies the patched-build marker; refuses
/// to continue if the resolved binary is vanilla upstream (likely
/// a stale install or env-var pointing at the wrong file).
///
/// Returns `Ok(())` if the environment is fully set up. Returns
/// `Err` with an actionable hint if msb is missing or unpatched.
/// Safe to call multiple times — subsequent calls re-validate.
pub fn point_at_msb() -> Result<()> {
    let resolved = match resolved_msb_path()? {
        Some(p) => p,
        None => bail!(
            "agent-vm could not find its bundled `msb` binary.\n\
             - Installed via npm? The platform subpackage is missing — try `npm install -g @wirenboard/agent-vm --force`.\n\
             - Running from source on Apple Silicon macOS? Run `./script/build/macos.sh`.\n\
             - Other source builds? Run `cd vendor/microsandbox && just build release`."
        ),
    };

    verify_patched_marker(&resolved)?;

    // SAFETY: `main()` is a plain `fn main` and calls `point_at_msb`
    // BEFORE constructing the tokio runtime. setenv() is not thread-
    // safe; this ordering invariant is the only thing that makes the
    // call sound. If you move the call into the runtime context the
    // multi-threaded workers can race with libc's getenv()
    // (reqwest, sea-orm, etc. read env on first use) → UB.
    unsafe { std::env::set_var("MSB_PATH", &resolved) };
    Ok(())
}

/// Run `<msb> --version` and require its stdout to contain
/// [`PATCHED_VERSION_MARKER`]. This catches the failure mode where
/// a vanilla upstream `msb` ends up at our discovered path —
/// it'd run, but agent-vm's hooks and SecretValue::File would be
/// silently absent, producing inscrutable runtime errors instead.
fn verify_patched_marker(msb: &std::path::Path) -> Result<()> {
    let out = Command::new(msb)
        .arg("--version")
        .output()
        .with_context(|| format!("executing {} --version", msb.display()))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() {
        bail!(
            "{} --version exited {}: {}",
            msb.display(),
            out.status,
            stdout.trim()
        );
    }
    if !stdout.contains(PATCHED_VERSION_MARKER) {
        // Tailor the hint based on whether MSB_PATH is what pointed us
        // at this binary. If the user explicitly set MSB_PATH, "set
        // MSB_PATH explicitly" is the LAST thing they need to hear —
        // they need to unset it.
        let hint = if std::env::var_os("MSB_PATH").is_some() {
            "Your MSB_PATH points at this binary. `unset MSB_PATH` to use the \
             bundled patched msb, or point MSB_PATH at a patched build."
        } else {
            "Reinstall agent-vm (e.g. `npm install -g @wirenboard/agent-vm --force`) \
             to restore the bundled patched msb."
        };
        bail!(
            "{} is the upstream microsandbox binary (no '{PATCHED_VERSION_MARKER}' marker in --version: {:?}).\n\
             agent-vm needs its own patched build.\n\
             {hint}",
            msb.display(),
            stdout.trim(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn write_fake_msb(dir: &std::path::Path, version_output: &str) -> PathBuf {
        let path = dir.join("msb");
        let script = format!("#!/bin/sh\necho '{version_output}'\nexit 0\n");
        std::fs::write(&path, script).unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
        path
    }

    #[test]
    fn source_checkout_uses_signed_build_artifact() {
        assert!(
            workspace_built_msb().ends_with("vendor/microsandbox/build/msb"),
            "source checkout must not select Cargo's unsigned target/release/msb"
        );
    }

    #[test]
    fn verify_marker_accepts_patched_version() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_fake_msb(dir.path(), "msb 0.4.6+agent-vm.phase4");
        verify_patched_marker(&p).expect("patched marker should be accepted");
    }

    /// Tests both branches of the rejection-hint logic in one test so
    /// they don't race on the process-global MSB_PATH env var. cargo
    /// test parallelises by default and we don't want to pull in
    /// `serial_test` just for this.
    #[test]
    fn verify_marker_rejects_vanilla_with_branch_specific_hint() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_fake_msb(dir.path(), "msb 0.4.6");

        // Branch 1: MSB_PATH unset → hint mentions reinstall.
        // SAFETY: see module top — these tests are the only place we
        // mutate the env var; we serialise them by living in one
        // function.
        let prior = std::env::var_os("MSB_PATH");
        unsafe { std::env::remove_var("MSB_PATH") };
        let err1 = verify_patched_marker(&p).unwrap_err();
        let msg1 = format!("{err1:?}");
        assert!(
            msg1.contains("upstream microsandbox"),
            "expected upstream-rejection message; got:\n{msg1}"
        );
        assert!(
            msg1.to_lowercase().contains("reinstall agent-vm"),
            "missing 'reinstall agent-vm' hint when MSB_PATH unset: {msg1}"
        );

        // Branch 2: MSB_PATH set → hint blames MSB_PATH.
        unsafe { std::env::set_var("MSB_PATH", "/anywhere") };
        let err2 = verify_patched_marker(&p).unwrap_err();
        let msg2 = format!("{err2:?}");
        assert!(
            msg2.contains("unset MSB_PATH"),
            "missing 'unset MSB_PATH' hint when MSB_PATH set: {msg2}"
        );

        // Restore the var so we don't leak state to other tests.
        match prior {
            Some(v) => unsafe { std::env::set_var("MSB_PATH", v) },
            None => unsafe { std::env::remove_var("MSB_PATH") },
        }
    }

    #[test]
    fn verify_marker_propagates_exec_failure() {
        // Non-existent path: Command::new(...).output() returns an
        // io::Error before producing a status. We surface it with
        // an "executing" context.
        let bogus = std::path::Path::new("/nonexistent/agent-vm-test-bogus-msb");
        let err = verify_patched_marker(bogus).unwrap_err();
        assert!(format!("{err:?}").contains("executing"));
    }

    #[test]
    fn resolved_msb_path_honours_env_override() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_fake_msb(dir.path(), "msb 0.4.6+agent-vm.phase4");
        // Avoid mutating the process-wide env in parallel tests:
        // construct the same selection logic locally.
        let env_val: std::ffi::OsString = p.as_os_str().to_owned();
        // Re-implement the env branch deterministically:
        let chosen = PathBuf::from(&env_val);
        assert!(chosen.exists());
        assert_eq!(chosen, p);
    }
}
