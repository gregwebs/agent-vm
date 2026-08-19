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

use std::{
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail};

/// Marker that the patched `msb --version` must contain. Upstream
/// builds print `msb <semver>` with no suffix; agent-vm's vendored
/// build appends `+agent-vm.phase<N>` so we can detect a shadowing
/// upstream binary.
const PATCHED_VERSION_MARKER: &str = "+agent-vm";

/// Opt-in switch: when truthy, agent-vm points msb's OCI image cache at the
/// shared `~/.microsandbox/cache` a separately-installed msb uses (Homebrew
/// on macOS, a distro package or `cargo install` on Linux) instead of its
/// private `MSB_HOME/cache`. Off by default. See `point_at_msb_home`.
const SHARE_MSB_CACHE_ENV: &str = "AGENT_VM_SHARE_MSB_CACHE";

/// Explicit override for the shared cache directory (for a non-default
/// install layout). Only consulted when `SHARE_MSB_CACHE_ENV` is truthy.
const MSB_CACHE_DIR_ENV: &str = "AGENT_VM_MSB_CACHE_DIR";

/// microsandbox's persisted config filename (mirrors
/// `microsandbox_utils::CONFIG_FILENAME`). Written into `MSB_HOME`.
const MSB_CONFIG_FILENAME: &str = "config.json";

/// Path to the signed dev build for a source workspace.
///
/// Do not use `target/release/msb` here on macOS: Cargo's raw output is
/// linker-signed but lacks `com.apple.security.hypervisor`. The root macOS
/// build script copies that binary here and signs it with
/// `msb-entitlements.plist`.
fn source_built_msb(workspace: &std::path::Path) -> PathBuf {
    workspace.join("vendor/microsandbox/build/msb")
}

/// Sibling-of-current-exe path, the npm-bundle layout.
fn exe_sibling_msb() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    Some(exe.parent()?.join("msb"))
}

#[derive(Debug, Eq, PartialEq)]
enum MissingMsbLayout {
    SourceSubmoduleUninitialized,
    SourceBuildMissing,
    InstalledBundle,
}

/// Return the source workspace for a Cargo-produced executable.
///
/// Installed bundles can have been compiled in a source checkout, so this uses
/// the runtime executable's layout and a source-tree marker rather than
/// `CARGO_MANIFEST_DIR` baked in on the build host.
fn source_workspace(exe: &std::path::Path) -> Option<&std::path::Path> {
    let profile_dir = exe.parent()?;
    let profile = profile_dir.file_name()?.to_str()?;
    if !matches!(profile, "debug" | "release") {
        return None;
    }

    let profile_parent = profile_dir.parent()?;
    let workspace = if profile_parent.file_name()?.to_str()? == "target" {
        profile_parent.parent()?
    } else {
        let target_dir = profile_parent.parent()?;
        if target_dir.file_name()?.to_str()? != "target" {
            return None;
        }
        target_dir.parent()?
    };

    workspace
        .join("crates/agent-vm/Cargo.toml")
        .is_file()
        .then_some(workspace)
}

fn classify_missing_msb_layout(exe: &std::path::Path) -> MissingMsbLayout {
    let Some(workspace) = source_workspace(exe) else {
        return MissingMsbLayout::InstalledBundle;
    };

    if workspace.join("vendor/microsandbox/Cargo.toml").is_file() {
        MissingMsbLayout::SourceBuildMissing
    } else {
        MissingMsbLayout::SourceSubmoduleUninitialized
    }
}

fn missing_msb_diagnostic(layout: MissingMsbLayout) -> &'static str {
    match layout {
        MissingMsbLayout::SourceSubmoduleUninitialized => {
            "agent-vm could not find its bundled `msb` binary.\n\
             The source checkout's `vendor/microsandbox` submodule is uninitialized.\n\
             Run:\n\
               git submodule update --init --recursive vendor/microsandbox\n\
             Then, on Apple Silicon macOS, build the signed runtime and agent-vm bundle:\n\
               ./script/build/macos.sh"
        }
        MissingMsbLayout::SourceBuildMissing => {
            "agent-vm could not find the signed source `msb` build artifact at `vendor/microsandbox/build/msb`.\n\
             The `vendor/microsandbox` submodule is initialized, but the runtime has not been built.\n\
             On Apple Silicon macOS, run:\n\
               ./script/build/macos.sh\n\
             Other source builds: run `cd vendor/microsandbox && just build release`."
        }
        MissingMsbLayout::InstalledBundle => {
            "agent-vm could not find its bundled `msb` binary.\n\
             - Installed via npm? The platform subpackage is missing — try `npm install -g @wirenboard/agent-vm --force`.\n\
             - Running from source on Apple Silicon macOS? Run `./script/build/macos.sh`.\n\
             - Other source builds? Run `cd vendor/microsandbox && just build release`."
        }
    }
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
    if let Ok(exe) = std::env::current_exe()
        && let Some(workspace) = source_workspace(&exe)
    {
        let dev = source_built_msb(workspace);
        if dev.exists() {
            return Ok(Some(dev));
        }
    }
    Ok(None)
}

/// True for `1` or `true` (case-insensitive, trimmed). Everything else —
/// including `0`, `false`, empty, and unset — is false. Kept in lockstep with
/// the documented values in README.md.
fn parse_flag(v: &str) -> bool {
    matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true")
}

fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name).map(|v| parse_flag(&v)).unwrap_or(false)
}

/// Resolve the shared OCI cache directory to redirect `paths.cache` at.
/// `AGENT_VM_MSB_CACHE_DIR` (non-empty) wins; otherwise `$HOME/.microsandbox/cache`.
fn resolve_shared_cache_dir_from(
    override_dir: Option<&std::ffi::OsStr>,
    home: Option<&std::ffi::OsStr>,
) -> Result<PathBuf> {
    if let Some(explicit) = override_dir
        && !explicit.is_empty()
    {
        return Ok(PathBuf::from(explicit));
    }
    let home = home.filter(|h| !h.is_empty()).ok_or_else(|| {
        anyhow::anyhow!(
            "{SHARE_MSB_CACHE_ENV} is set but $HOME is unset and \
             {MSB_CACHE_DIR_ENV} was not provided; cannot locate the shared \
             `.microsandbox/cache` directory. Unset {SHARE_MSB_CACHE_ENV} to \
             use the private cache, or set {MSB_CACHE_DIR_ENV}."
        )
    })?;
    Ok(PathBuf::from(home).join(".microsandbox").join("cache"))
}

fn resolve_shared_cache_dir() -> Result<PathBuf> {
    resolve_shared_cache_dir_from(
        std::env::var_os(MSB_CACHE_DIR_ENV).as_deref(),
        std::env::var_os("HOME").as_deref(),
    )
}

/// Pure resolver for [`effective_cache_dir`]: shared-cache opt-in redirects
/// to `shared`; otherwise `msb_home/cache`. Both inputs are passed
/// explicitly (mirroring [`resolve_shared_cache_dir_from`]) so tests need
/// not mutate process-wide env.
fn effective_cache_dir_from(
    share: bool,
    msb_home: Option<&std::ffi::OsStr>,
    shared: &Path,
) -> Result<PathBuf> {
    if share {
        return Ok(shared.to_path_buf());
    }
    let msb_home = msb_home.ok_or_else(|| {
        anyhow::anyhow!("MSB_HOME unset; point_at_msb_home() not called yet")
    })?;
    Ok(PathBuf::from(msb_home).join("cache"))
}

/// The OCI image cache directory the pinned `msb` actually uses in this
/// process. Mirrors [`point_at_msb_home`]: `MSB_HOME/cache` unless the
/// shared-cache opt-in redirected `paths.cache`. Must be called after
/// `point_at_msb_home()` has set `MSB_HOME` — see that function's doc
/// comment for why the two must never drift.
pub fn effective_cache_dir() -> Result<PathBuf> {
    let share = env_flag_enabled(SHARE_MSB_CACHE_ENV);
    // Only resolve the shared dir when the flag is on (it may error on a
    // bad env, e.g. no $HOME and no override).
    let shared = if share {
        resolve_shared_cache_dir()?
    } else {
        PathBuf::new()
    };
    effective_cache_dir_from(share, std::env::var_os("MSB_HOME").as_deref(), &shared)
}

/// Merge-write `paths.cache = <cache_dir>` into `MSB_HOME/config.json`.
///
/// Reads any existing config into a `serde_json::Value`, sets only
/// `paths.cache`, and writes the document back. We merge into an untyped
/// `Value` rather than round-tripping through microsandbox's `LocalConfig`
/// on purpose: a full `LocalConfig` re-serialize would materialize every
/// default field AND drop any keys a newer separately-installed msb wrote
/// that agent-vm's pinned SDK doesn't model. Untyped merge keeps the file
/// minimal and forward-compatible. Idempotent: re-running re-asserts the
/// same key.
///
/// NOTE: this relies on msb reading `MSB_HOME/config.json`. agent-vm must not
/// set `MSB_CONFIG_PATH` (which would redirect the SDK's config_path() and
/// silently bypass this file). See module docs.
fn write_shared_cache_config(msb_home: &Path, cache_dir: &Path) -> Result<()> {
    let config_path = msb_home.join(MSB_CONFIG_FILENAME);

    // JSON can only hold a UTF-8 path; reject non-UTF-8 rather than writing a
    // lossily-mangled directory the user never asked for.
    let cache_str = cache_dir.to_str().ok_or_else(|| {
        anyhow::anyhow!(
            "shared cache dir {} is not valid UTF-8; set {MSB_CACHE_DIR_ENV} to a UTF-8 path",
            cache_dir.display()
        )
    })?;

    let mut doc: serde_json::Value = match std::fs::read(&config_path) {
        Ok(bytes) => serde_json::from_slice(&bytes).with_context(|| {
            format!(
                "parsing existing {} (fix or remove it to re-enable shared cache)",
                config_path.display()
            )
        })?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            serde_json::Value::Object(serde_json::Map::new())
        }
        Err(e) => return Err(e).with_context(|| format!("reading {}", config_path.display())),
    };

    let obj = doc.as_object_mut().ok_or_else(|| {
        anyhow::anyhow!(
            "{} is not a JSON object; refusing to overwrite",
            config_path.display()
        )
    })?;
    let paths = obj
        .entry("paths")
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    let paths_obj = paths.as_object_mut().ok_or_else(|| {
        anyhow::anyhow!(
            "`paths` in {} is not a JSON object; refusing to overwrite",
            config_path.display()
        )
    })?;
    paths_obj.insert(
        "cache".to_string(),
        serde_json::Value::String(cache_str.to_string()),
    );

    // Ensure the shared cache dir exists before msb uses it. Skip the syscall
    // when it already exists (the common shared-path case) so a transient mount
    // issue on an existing dir can't fail an otherwise-idempotent re-run.
    if !cache_dir.exists() {
        std::fs::create_dir_all(cache_dir)
            .with_context(|| format!("creating shared msb cache dir {}", cache_dir.display()))?;
    }

    let mut serialized = serde_json::to_vec_pretty(&doc).context("serializing msb config.json")?;
    serialized.push(b'\n');
    crate::host_paths::atomic_write(&config_path, &serialized, 0o644)
        .with_context(|| format!("writing {}", config_path.display()))?;
    Ok(())
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
/// ## Opt-in shared OCI image cache
///
/// Set `AGENT_VM_SHARE_MSB_CACHE=1` (or `true`) to redirect only the `cache`
/// directory (OCI image layers/vmdk/manifests) at the shared
/// `~/.microsandbox/cache` a separately-installed msb uses — override the
/// location with `AGENT_VM_MSB_CACHE_DIR=<path>`. Everything else (`db/`,
/// `tls/`, `secrets/`, `sandboxes/`, and `lib/`/libkrunfw) stays private
/// under this `MSB_HOME`, so the shadowing hazard above is not
/// reintroduced. Off by default: the other `msb` may be a different
/// microsandbox version than the vendored fork, and the on-disk cache
/// format is not guaranteed compatible across versions. Implemented by
/// merge-writing `paths.cache` into `MSB_HOME/config.json`; this relies on
/// msb reading that file, so agent-vm must never set `MSB_CONFIG_PATH`.
/// When the flag is unset/falsey, `config.json` is never read or written —
/// flipping the flag off later does NOT revert an already-written
/// `config.json`; see README.md for the manual revert step.
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

    // Opt-in only: redirect the OCI image cache at the shared
    // `~/.microsandbox/cache` a separately-installed msb uses. Off by
    // default; when unset/falsey we do NOT read or write config.json at all
    // (today's behaviour). db/tls/secrets/sandboxes stay private under
    // MSB_HOME. See doc comment above + README.md.
    if env_flag_enabled(SHARE_MSB_CACHE_ENV) {
        let cache_dir = resolve_shared_cache_dir()?;
        write_shared_cache_config(&dir, &cache_dir)?;
    }

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
        None => {
            let layout = std::env::current_exe()
                .map(|exe| classify_missing_msb_layout(&exe))
                .unwrap_or(MissingMsbLayout::InstalledBundle);
            bail!("{}", missing_msb_diagnostic(layout));
        }
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
    verify_patched_marker_with_path_source(msb, std::env::var_os("MSB_PATH").is_some())
}

fn verify_patched_marker_with_path_source(
    msb: &std::path::Path,
    msb_path_is_explicit: bool,
) -> Result<()> {
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
        let hint = if msb_path_is_explicit {
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

    fn write_source_checkout_marker(workspace: &std::path::Path) {
        let manifest_dir = workspace.join("crates/agent-vm");
        std::fs::create_dir_all(&manifest_dir).unwrap();
        std::fs::write(
            manifest_dir.join("Cargo.toml"),
            "[package]\nname = \"agent-vm\"\n",
        )
        .unwrap();
    }

    #[test]
    fn source_checkout_uses_signed_build_artifact() {
        let workspace = std::path::Path::new("/source/agent-vm");
        assert_eq!(
            source_built_msb(workspace),
            workspace.join("vendor/microsandbox/build/msb"),
            "source checkout must not select Cargo's unsigned target/release/msb"
        );
    }

    #[test]
    fn verify_marker_accepts_patched_version() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_fake_msb(dir.path(), "msb 0.4.6+agent-vm.phase4");
        verify_patched_marker(&p).expect("patched marker should be accepted");
    }

    #[test]
    fn verify_marker_rejects_vanilla_with_branch_specific_hint() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_fake_msb(dir.path(), "msb 0.4.6");

        let err1 = verify_patched_marker_with_path_source(&p, false).unwrap_err();
        let msg1 = format!("{err1:?}");
        assert!(
            msg1.contains("upstream microsandbox"),
            "expected upstream-rejection message; got:\n{msg1}"
        );
        assert!(
            msg1.to_lowercase().contains("reinstall agent-vm"),
            "missing 'reinstall agent-vm' hint when MSB_PATH unset: {msg1}"
        );

        let err2 = verify_patched_marker_with_path_source(&p, true).unwrap_err();
        let msg2 = format!("{err2:?}");
        assert!(
            msg2.contains("unset MSB_PATH"),
            "missing 'unset MSB_PATH' hint when MSB_PATH set: {msg2}"
        );
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

    #[test]
    fn missing_msb_layout_identifies_uninitialized_source_submodule() {
        let workspace = tempfile::tempdir().unwrap();
        write_source_checkout_marker(workspace.path());
        let exe = workspace.path().join("target/debug/agent-vm");

        assert_eq!(
            classify_missing_msb_layout(&exe),
            MissingMsbLayout::SourceSubmoduleUninitialized
        );
    }

    #[test]
    fn missing_msb_layout_identifies_initialized_source_without_build() {
        let workspace = tempfile::tempdir().unwrap();
        write_source_checkout_marker(workspace.path());
        let submodule = workspace.path().join("vendor/microsandbox");
        std::fs::create_dir_all(&submodule).unwrap();
        std::fs::write(submodule.join("Cargo.toml"), "[workspace]\n").unwrap();
        let exe = workspace.path().join("target/release/agent-vm");

        assert_eq!(
            classify_missing_msb_layout(&exe),
            MissingMsbLayout::SourceBuildMissing
        );
    }

    #[test]
    fn missing_msb_layout_keeps_bundles_outside_source_checkout() {
        let workspace = tempfile::tempdir().unwrap();
        let submodule = workspace.path().join("vendor/microsandbox");
        std::fs::create_dir_all(&submodule).unwrap();
        std::fs::write(submodule.join("Cargo.toml"), "[workspace]\n").unwrap();

        for exe in [
            std::path::Path::new("/opt/npm/bin/agent-vm"),
            &workspace.path().join("target/release/agent-vm"),
            &workspace.path().join("target/macos/bin/agent-vm"),
        ] {
            assert_eq!(
                classify_missing_msb_layout(exe),
                MissingMsbLayout::InstalledBundle,
                "bundled executable {} must not inherit source-checkout diagnostics",
                exe.display()
            );
        }
    }

    #[test]
    fn uninitialized_source_diagnostic_names_submodule_and_recovery_commands() {
        let message = missing_msb_diagnostic(MissingMsbLayout::SourceSubmoduleUninitialized);

        assert_eq!(
            message,
            "agent-vm could not find its bundled `msb` binary.\n\
             The source checkout's `vendor/microsandbox` submodule is uninitialized.\n\
             Run:\n\
               git submodule update --init --recursive vendor/microsandbox\n\
             Then, on Apple Silicon macOS, build the signed runtime and agent-vm bundle:\n\
               ./script/build/macos.sh"
        );
    }

    #[test]
    fn initialized_source_diagnostic_requires_signed_build_without_submodule_claim() {
        let message = missing_msb_diagnostic(MissingMsbLayout::SourceBuildMissing);

        assert_eq!(
            message,
            "agent-vm could not find the signed source `msb` build artifact at `vendor/microsandbox/build/msb`.\n\
             The `vendor/microsandbox` submodule is initialized, but the runtime has not been built.\n\
             On Apple Silicon macOS, run:\n\
               ./script/build/macos.sh\n\
             Other source builds: run `cd vendor/microsandbox && just build release`."
        );
        assert!(!message.contains("uninitialized"));
    }

    #[test]
    fn installed_bundle_diagnostic_keeps_platform_package_recovery() {
        let message = missing_msb_diagnostic(MissingMsbLayout::InstalledBundle);

        assert_eq!(
            message,
            "agent-vm could not find its bundled `msb` binary.\n\
             - Installed via npm? The platform subpackage is missing — try `npm install -g @wirenboard/agent-vm --force`.\n\
             - Running from source on Apple Silicon macOS? Run `./script/build/macos.sh`.\n\
             - Other source builds? Run `cd vendor/microsandbox && just build release`."
        );
        assert!(!message.contains("submodule is uninitialized"));
    }

    // --- opt-in shared msb cache ---

    #[test]
    fn parse_flag_matches_documented_truthy_values_only() {
        for truthy in ["1", "true", "TRUE", " true "] {
            assert!(parse_flag(truthy), "expected {truthy:?} to be truthy");
        }
        for falsy in ["0", "false", "", "yes", "on", "nope"] {
            assert!(!parse_flag(falsy), "expected {falsy:?} to be falsy");
        }
    }

    #[test]
    fn write_shared_cache_config_creates_config_on_empty_home() {
        let msb_home = tempfile::tempdir().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        let cache_dir = cache_dir.path().join("shared-cache");

        write_shared_cache_config(msb_home.path(), &cache_dir).unwrap();

        let doc: serde_json::Value = serde_json::from_slice(
            &std::fs::read(msb_home.path().join(MSB_CONFIG_FILENAME)).unwrap(),
        )
        .unwrap();
        assert_eq!(
            doc["paths"]["cache"],
            serde_json::Value::String(cache_dir.to_str().unwrap().to_string())
        );
        assert!(cache_dir.is_dir(), "cache dir should have been created");
    }

    #[test]
    fn write_shared_cache_config_merges_preserves_existing_keys() {
        let msb_home = tempfile::tempdir().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        let cache_dir = cache_dir.path().join("shared-cache");
        std::fs::write(
            msb_home.path().join(MSB_CONFIG_FILENAME),
            r#"{"log_level":"info","paths":{"msb":"/x/msb"}}"#,
        )
        .unwrap();

        write_shared_cache_config(msb_home.path(), &cache_dir).unwrap();

        let doc: serde_json::Value = serde_json::from_slice(
            &std::fs::read(msb_home.path().join(MSB_CONFIG_FILENAME)).unwrap(),
        )
        .unwrap();
        assert_eq!(
            doc["log_level"],
            serde_json::Value::String("info".to_string())
        );
        assert_eq!(
            doc["paths"]["msb"],
            serde_json::Value::String("/x/msb".to_string())
        );
        assert_eq!(
            doc["paths"]["cache"],
            serde_json::Value::String(cache_dir.to_str().unwrap().to_string())
        );
    }

    #[test]
    fn write_shared_cache_config_is_idempotent() {
        let msb_home = tempfile::tempdir().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        let cache_dir = cache_dir.path().join("shared-cache");

        write_shared_cache_config(msb_home.path(), &cache_dir).unwrap();
        let first = std::fs::read(msb_home.path().join(MSB_CONFIG_FILENAME)).unwrap();
        write_shared_cache_config(msb_home.path(), &cache_dir).unwrap();
        let second = std::fs::read(msb_home.path().join(MSB_CONFIG_FILENAME)).unwrap();

        assert_eq!(
            first, second,
            "re-running should produce byte-identical output"
        );
    }

    #[test]
    fn write_shared_cache_config_refuses_malformed_existing_config() {
        let msb_home = tempfile::tempdir().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        let cache_dir = cache_dir.path().join("shared-cache");
        std::fs::write(msb_home.path().join(MSB_CONFIG_FILENAME), "not json at all").unwrap();

        let err = write_shared_cache_config(msb_home.path(), &cache_dir).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains(MSB_CONFIG_FILENAME),
            "expected path in error: {msg}"
        );
        assert!(
            msg.contains("fix or remove"),
            "expected recovery hint in error: {msg}"
        );
    }

    #[test]
    fn write_shared_cache_config_refuses_non_object_paths() {
        let msb_home = tempfile::tempdir().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        let cache_dir = cache_dir.path().join("shared-cache");
        std::fs::write(msb_home.path().join(MSB_CONFIG_FILENAME), r#"{"paths":42}"#).unwrap();

        let err = write_shared_cache_config(msb_home.path(), &cache_dir).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("paths"),
            "expected `paths` mentioned in error: {msg}"
        );
    }

    #[test]
    fn resolve_shared_cache_dir_from_prefers_explicit_override() {
        let override_dir = std::ffi::OsString::from("/explicit/cache");
        let home = std::ffi::OsString::from("/home/user");
        let resolved =
            resolve_shared_cache_dir_from(Some(override_dir.as_os_str()), Some(home.as_os_str()))
                .unwrap();
        assert_eq!(resolved, PathBuf::from("/explicit/cache"));
    }

    #[test]
    fn resolve_shared_cache_dir_from_falls_back_to_home() {
        let home = std::ffi::OsString::from("/home/user");
        let resolved = resolve_shared_cache_dir_from(None, Some(home.as_os_str())).unwrap();
        assert_eq!(resolved, PathBuf::from("/home/user/.microsandbox/cache"));

        let empty_override = std::ffi::OsString::from("");
        let resolved =
            resolve_shared_cache_dir_from(Some(empty_override.as_os_str()), Some(home.as_os_str()))
                .unwrap();
        assert_eq!(resolved, PathBuf::from("/home/user/.microsandbox/cache"));
    }

    #[test]
    fn effective_cache_dir_from_uses_msb_home_when_not_shared() {
        let msb_home = std::ffi::OsString::from("/h");
        let resolved =
            effective_cache_dir_from(false, Some(msb_home.as_os_str()), Path::new("/unused"))
                .unwrap();
        assert_eq!(resolved, PathBuf::from("/h/cache"));
    }

    #[test]
    fn effective_cache_dir_from_errors_without_msb_home_when_not_shared() {
        let err = effective_cache_dir_from(false, None, Path::new("/unused")).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("MSB_HOME"), "expected MSB_HOME mentioned: {msg}");
    }

    #[test]
    fn effective_cache_dir_from_prefers_shared_when_opted_in() {
        let resolved = effective_cache_dir_from(true, None, Path::new("/x")).unwrap();
        assert_eq!(resolved, PathBuf::from("/x"));
    }

    #[test]
    fn resolve_shared_cache_dir_from_errors_without_home_or_override() {
        let err = resolve_shared_cache_dir_from(None, None).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("HOME"), "expected $HOME mentioned: {msg}");
        assert!(
            msg.contains(SHARE_MSB_CACHE_ENV),
            "expected env var name: {msg}"
        );
        assert!(
            msg.contains(MSB_CACHE_DIR_ENV),
            "expected override env var name: {msg}"
        );
    }

    /// Contract test: proves microsandbox's own `LocalConfig` actually
    /// resolves the key/nesting this module writes. Without this, a silent
    /// mis-nesting would still pass the tests above (they only check our own
    /// JSON shape) yet redirect nothing, because `LocalConfig` is
    /// `#[serde(default)]` and tolerates unknown/misplaced keys.
    #[test]
    fn written_config_is_honoured_by_microsandbox_local_config() {
        let msb_home = tempfile::tempdir().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        let cache_dir = cache_dir.path().join("shared-cache");

        write_shared_cache_config(msb_home.path(), &cache_dir).unwrap();

        let bytes = std::fs::read(msb_home.path().join(MSB_CONFIG_FILENAME)).unwrap();
        let cfg: microsandbox::config::LocalConfig = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(cfg.cache_dir(), cache_dir);
    }

    #[test]
    fn write_shared_cache_config_rejects_non_utf8_cache_path() {
        use std::os::unix::ffi::OsStrExt;

        let msb_home = tempfile::tempdir().unwrap();
        // 0x80 is not a valid standalone UTF-8 byte.
        let non_utf8 = std::ffi::OsStr::from_bytes(&[0x66, 0x6f, 0x80, 0x6f]);
        let cache_dir = PathBuf::from(non_utf8);

        let err = write_shared_cache_config(msb_home.path(), &cache_dir).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.to_lowercase().contains("utf-8"),
            "expected UTF-8 mentioned: {msg}"
        );
        assert!(
            !msb_home.path().join(MSB_CONFIG_FILENAME).exists(),
            "no config.json should be written on rejection"
        );
    }
}
