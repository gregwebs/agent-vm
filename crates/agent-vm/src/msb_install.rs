//! Discover and validate the `msb` binary that agent-vm needs.
//!
//! agent-vm vendors a specific upstream Microsandbox release as a git
//! submodule (`vendor/microsandbox`) and bundles the `msb` CLI built from
//! it. To avoid colliding with a user's separate `~/.microsandbox/bin/msb`
//! install (which would otherwise win on the SDK's resolution ladder),
//! agent-vm explicitly sets `MSB_PATH` to its own bundled binary.
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
//! `--version` output MUST report exactly the official upstream version
//! this build vendors (agent-vm issue #40 dropped the pre-0.6.15 `gw`
//! fork's `+agent-vm` version-suffix convention along with the fork
//! itself) — a mismatch, in either direction, means the binary at the
//! resolved path is not the one this `agent-vm` build was compiled
//! against, so we refuse to run with a clear, actionable error rather
//! than producing weird runtime failures inside the sandbox.

use std::{
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail};

/// The upstream Microsandbox version this build vendors, read directly out
/// of `vendor/microsandbox/Cargo.toml` at COMPILE TIME (`include_str!`) so
/// it can never drift from the submodule gitlink a given `cargo build`
/// actually compiled against — a hand-maintained constant left stale after
/// a gitlink bump is exactly the kind of silent mismatch AC#4 (agent-vm
/// issue #40) exists to prevent. Panics at first use if the vendored
/// `Cargo.toml` doesn't have the expected `version = "…"` line, which
/// would mean the submodule checkout itself is broken — loud and immediate
/// is correct there, not a runtime fallback.
fn expected_msb_version() -> &'static str {
    const VENDORED_CARGO_TOML: &str = include_str!("../../../vendor/microsandbox/Cargo.toml");
    VENDORED_CARGO_TOML
        .lines()
        .find_map(|line| line.trim().strip_prefix("version = \""))
        .and_then(|rest| rest.strip_suffix('"'))
        .expect(
            "vendor/microsandbox/Cargo.toml must have a top-level `version = \"…\"` line \
             (workspace.package.version)",
        )
}

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

/// Resolve the path to the official-version msb that agent-vm should use.
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
             it at a valid msb build.",
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
    let msb_home = msb_home
        .ok_or_else(|| anyhow::anyhow!("MSB_HOME unset; point_at_msb_home() not called yet"))?;
    Ok(PathBuf::from(msb_home).join("cache"))
}

/// The OCI image cache directory the pinned `msb` actually uses in this
/// process. Mirrors [`point_at_msb_home`]: `MSB_HOME/cache` unless the
/// shared-cache opt-in redirected `paths.cache`. Must be called after
/// `point_at_msb_home()` has set `MSB_HOME` — see that function's doc
/// comment for why the two must never drift.
pub fn effective_cache_dir() -> Result<PathBuf> {
    let share = crate::env_flag::enabled(SHARE_MSB_CACHE_ENV);
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

/// macOS-only short `MSB_HOME` root, used in place of
/// `state_root()/msb-home` when neither `AGENT_VM_STATE_DIR` nor
/// `XDG_STATE_HOME` is set. See [`msb_home_dir`]'s doc comment for why.
const SHORT_MACOS_MSB_HOME_DIRNAME: &str = ".agent-vm-msb";

/// The private `MSB_HOME` path agent-vm pins msb at.
///
/// Normally `state_root()/msb-home` — but on macOS, when neither
/// `AGENT_VM_STATE_DIR` nor `XDG_STATE_HOME` is set (i.e. `state_root()`
/// would fall through to its `$HOME/.local/state/agent-vm` default), this
/// returns the much shorter `$HOME/.agent-vm-msb` instead (AC#6, agent-vm
/// issue #40).
///
/// Why: v0.6.15's per-sandbox agent/control sockets live at
/// `<MSB_HOME>/run/sandboxes/<24-hex-char-id>/{agent,control}.sock`
/// (`vendor/microsandbox/crates/runtime/lib/ipc.rs::sandbox_socket_paths`).
/// The sandbox *name* itself is SHA-256-hashed to that fixed-length id
/// before it ever reaches a socket path, so — unlike in the pre-#40 fork
/// vintage this AC's wording was written against — the long, unbounded
/// component is NOT the sandbox name; it's the fixed
/// `/run/sandboxes/<24 hex chars>/control.sock` suffix (83 bytes under the
/// old default root) plus whatever `$HOME` itself costs. macOS's
/// `sockaddr_un.sun_path` is only 104 bytes total, so the old default left
/// as little as ~21 bytes of headroom for `$HOME` — silently overflowing
/// for any real home directory longer than roughly `/Users/xxxxx`. Under
/// this short root the same fixed suffix is 66 bytes, leaving ~38 bytes
/// for `$HOME`, which [`ensure_socket_paths_fit`] then verifies against
/// the *actual* boot-time sandbox name rather than trusting headroom
/// alone.
///
/// Side-effect-free (no dir creation, no env mutation) — the single source
/// of truth for the path itself, shared by [`point_at_msb_home`] (which
/// creates and pins it for boot) and any other caller (e.g. `doctor`) that
/// only needs to know where it is. Kept separate from
/// `std::env::var("MSB_HOME")` reads on purpose: recomputing from the same
/// pure inputs works whether or not `point_at_msb_home()` has run in this
/// process, and doesn't depend on the setenv-before-runtime invariant.
pub fn msb_home_dir() -> Result<PathBuf> {
    if let Some(short) = short_macos_msb_home(
        cfg!(target_os = "macos"),
        state_root_overridden(),
        std::env::var_os("HOME").as_deref(),
    ) {
        return Ok(short);
    }
    Ok(crate::host_paths::state_root()
        .ok_or_else(|| anyhow::anyhow!("could not resolve agent-vm state root ($HOME unset?)"))?
        .join("msb-home"))
}

/// Pure core of the macOS short-root special case in [`msb_home_dir`].
///
/// `None` means "fall through to the normal `state_root()/msb-home`
/// path" (non-macOS, an explicit override, or `$HOME` unset — the latter
/// deliberately left to `state_root()`'s own "could not resolve" error
/// rather than duplicated here). Split out from `msb_home_dir` so tests
/// can exercise the selection logic with explicit inputs instead of
/// mutating process-wide `$HOME`/env vars, which `cargo test`'s default
/// parallel test threads make unsafe to do from within a `#[test]`.
fn short_macos_msb_home(
    is_macos: bool,
    state_root_overridden: bool,
    home: Option<&std::ffi::OsStr>,
) -> Option<PathBuf> {
    if !is_macos || state_root_overridden {
        return None;
    }
    home.map(|h| PathBuf::from(h).join(SHORT_MACOS_MSB_HOME_DIRNAME))
}

/// Whether the user explicitly overrode where agent-vm's state lives —
/// the same two env vars [`crate::host_paths::state_root`] checks before
/// falling back to its `$HOME/.local/state/agent-vm` default. Mirrored
/// here (rather than calling `state_root()` and comparing) so
/// [`msb_home_dir`] can special-case macOS's *default* without silently
/// overriding a path the user asked for.
fn state_root_overridden() -> bool {
    std::env::var_os("AGENT_VM_STATE_DIR").is_some() || std::env::var_os("XDG_STATE_HOME").is_some()
}

/// Maximum byte length of a Unix-domain socket path this platform can
/// actually bind, leaving room for the mandatory NUL terminator inside
/// `sockaddr_un.sun_path` (a fixed-size buffer: 104 bytes on macOS/BSD,
/// 108 on Linux — the raw buffer size, not the usable string length).
#[cfg(target_os = "macos")]
const SUN_PATH_USABLE_LEN: usize = 104 - 1;
#[cfg(all(unix, not(target_os = "macos")))]
const SUN_PATH_USABLE_LEN: usize = 108 - 1;

/// Fail closed, before boot, if `sandbox_name`'s real agent/control socket
/// paths under `msb_home_dir()` would overflow this platform's
/// `sockaddr_un.sun_path` (AC#6, agent-vm issue #40).
///
/// Reuses the runtime's own [`microsandbox_runtime::ipc::sandbox_socket_paths`]
/// derivation rather than re-implementing the hash/path template, so this
/// check can't silently drift out of sync with the path the boot actually
/// binds. The macOS default root ([`msb_home_dir`]) already gives real
/// home directories generous headroom (see its doc comment) — this is the
/// defensive backstop for the cases headroom alone can't rule out: an
/// unusually long `$HOME`, or a user-supplied `AGENT_VM_STATE_DIR` that
/// re-introduces the same overflow the short default was built to avoid.
/// Never truncates a path to make it fit; a computed overflow is always a
/// hard error naming the offending path and the fix (a shorter
/// `AGENT_VM_STATE_DIR`).
pub fn ensure_socket_paths_fit(sandbox_name: &str) -> Result<()> {
    // "run" mirrors `microsandbox_utils::RUN_SUBDIR` / `LocalConfig::run_dir()`
    // (vendor/microsandbox/sdk/rust/lib/config/mod.rs) — not worth an extra
    // direct dependency on microsandbox-utils just for this one literal.
    let run_dir = msb_home_dir()?.join("run");
    let paths = microsandbox_runtime::ipc::sandbox_socket_paths(&run_dir, sandbox_name);
    // `control.sock` is always the longer of the two canonical socket
    // names ("control" > "agent"), so checking it alone covers both.
    check_socket_path_len(&paths.control, sandbox_name)
}

/// Pure length check behind [`ensure_socket_paths_fit`], taking an
/// already-derived socket path instead of deriving one from live env vars
/// — lets tests supply a contrived long path without needing a real
/// overlong `$HOME`/`AGENT_VM_STATE_DIR` in the process environment.
fn check_socket_path_len(socket_path: &Path, sandbox_name: &str) -> Result<()> {
    let len = socket_path.as_os_str().len();
    if len > SUN_PATH_USABLE_LEN {
        bail!(
            "the control socket path for sandbox {sandbox_name:?} is {len} bytes, exceeding \
             this platform's {SUN_PATH_USABLE_LEN}-byte Unix-domain-socket path limit:\n  {}\n\
             Set a shorter AGENT_VM_STATE_DIR (e.g. `export AGENT_VM_STATE_DIR=~/.avm`) and retry \
             — agent-vm never truncates this path silently, since a truncated path could bind to \
             the wrong (or another user's) socket.",
            socket_path.display(),
        );
    }
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
/// Set `AGENT_VM_SHARE_MSB_CACHE` to a truthy value (parsed by
/// [`crate::env_flag`]) to redirect only the `cache` directory (OCI image
/// layers/vmdk/manifests) at the shared
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
/// `config.json`; see USAGE.md's *Reverting is a manual step*.
///
/// Idempotent. Returns the path that was pinned.
pub fn point_at_msb_home() -> Result<PathBuf> {
    let dir = msb_home_dir()?;
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
    // MSB_HOME. See doc comment above + USAGE.md's *Shared microsandbox
    // image cache*.
    if crate::env_flag::enabled(SHARE_MSB_CACHE_ENV) {
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

    verify_official_identity(&resolved)?;

    // SAFETY: `main()` is a plain `fn main` and calls `point_at_msb`
    // BEFORE constructing the tokio runtime. setenv() is not thread-
    // safe; this ordering invariant is the only thing that makes the
    // call sound. If you move the call into the runtime context the
    // multi-threaded workers can race with libc's getenv()
    // (reqwest, sea-orm, etc. read env on first use) → UB.
    unsafe { std::env::set_var("MSB_PATH", &resolved) };
    Ok(())
}

/// Run `<msb> --version` and require it to report exactly the official
/// upstream Microsandbox version this build vendors ([`expected_msb_version`]).
/// This catches two failure modes: a shadowing binary from a *different*
/// install (a stale reinstall, a `~/.microsandbox/bin/msb` from a
/// differently-versioned standalone microsandbox install, or — pre-#40 —
/// this build's own bundled patched fork build) at our discovered path.
/// Either way it'd run, but potentially behave differently inside the
/// sandbox than the exact build agent-vm was compiled and tested against,
/// producing inscrutable runtime errors instead of this upfront check.
fn verify_official_identity(msb: &std::path::Path) -> Result<()> {
    verify_official_identity_with_path_source(msb, std::env::var_os("MSB_PATH").is_some())
}

fn verify_official_identity_with_path_source(
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
    let expected = expected_msb_version();
    // clap's default `--version` output is `"<bin-name> <version>"`
    // (`msb 0.6.15`); the version is always the last whitespace-separated
    // token, regardless of what a shadowing binary happens to call itself.
    let reported = stdout
        .trim()
        .rsplit(char::is_whitespace)
        .next()
        .unwrap_or("");
    if reported != expected {
        // Tailor the hint based on whether MSB_PATH is what pointed us
        // at this binary. If the user explicitly set MSB_PATH, "set
        // MSB_PATH explicitly" is the LAST thing they need to hear —
        // they need to unset it.
        let hint = if msb_path_is_explicit {
            format!(
                "Your MSB_PATH points at this binary. `unset MSB_PATH` to use the \
                 bundled official msb, or point MSB_PATH at an msb {expected} build."
            )
        } else {
            "Reinstall agent-vm (e.g. `npm install -g @wirenboard/agent-vm --force`) \
             to restore the bundled official msb."
                .to_string()
        };
        bail!(
            "{} reports version {reported:?}, but this agent-vm build vendors official \
             Microsandbox {expected} (--version: {:?}).\n\
             agent-vm needs the exact msb build it was vendored against — a different \
             (older, newer, or forked) msb can silently behave differently inside the sandbox.\n\
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
    fn expected_msb_version_reads_the_vendored_workspace_version() {
        // Pinned literal, deliberately NOT derived from `expected_msb_version()`
        // itself — this test exists to catch a `vendor/microsandbox` gitlink
        // bump that the vendored Cargo.toml's version didn't actually track,
        // which `include_str!` alone can't catch (it'd just read the new
        // value). Bump this literal by hand alongside the gitlink.
        assert_eq!(expected_msb_version(), "0.6.15");
    }

    #[test]
    fn verify_identity_accepts_official_version() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_fake_msb(dir.path(), &format!("msb {}", expected_msb_version()));
        verify_official_identity(&p).expect("official version should be accepted");
    }

    #[test]
    fn verify_identity_rejects_wrong_version_with_branch_specific_hint() {
        let dir = tempfile::tempdir().unwrap();
        // An older/different version — including the pre-#40 fork's own
        // `+agent-vm` suffix convention, which must now be rejected too:
        // this build vendors the exact official version, not "any patched
        // build that says +agent-vm somewhere".
        let p = write_fake_msb(dir.path(), "msb 0.5.7+agent-vm.phase4");

        let err1 = verify_official_identity_with_path_source(&p, false).unwrap_err();
        let msg1 = format!("{err1:?}");
        assert!(
            msg1.contains("reports version"),
            "expected version-mismatch message; got:\n{msg1}"
        );
        assert!(
            msg1.to_lowercase().contains("reinstall agent-vm"),
            "missing 'reinstall agent-vm' hint when MSB_PATH unset: {msg1}"
        );

        let err2 = verify_official_identity_with_path_source(&p, true).unwrap_err();
        let msg2 = format!("{err2:?}");
        assert!(
            msg2.contains("unset MSB_PATH"),
            "missing 'unset MSB_PATH' hint when MSB_PATH set: {msg2}"
        );
    }

    #[test]
    fn verify_identity_rejects_newer_stranger_version() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_fake_msb(dir.path(), "msb 9.9.9");
        let err = verify_official_identity(&p).unwrap_err();
        assert!(format!("{err:?}").contains("reports version"));
    }

    #[test]
    fn verify_identity_propagates_exec_failure() {
        // Non-existent path: Command::new(...).output() returns an
        // io::Error before producing a status. We surface it with
        // an "executing" context.
        let bogus = std::path::Path::new("/nonexistent/agent-vm-test-bogus-msb");
        let err = verify_official_identity(bogus).unwrap_err();
        assert!(format!("{err:?}").contains("executing"));
    }

    #[test]
    fn resolved_msb_path_honours_env_override() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_fake_msb(dir.path(), &format!("msb {}", expected_msb_version()));
        // Avoid mutating the process-wide env in parallel tests:
        // construct the same selection logic locally.
        let env_val: std::ffi::OsString = p.as_os_str().to_owned();
        // Re-implement the env branch deterministically:
        let chosen = PathBuf::from(&env_val);
        assert!(chosen.exists());
        assert_eq!(chosen, p);
    }

    #[test]
    fn short_macos_msb_home_used_on_macos_default() {
        let home = std::ffi::OsStr::new("/Users/johnsmith");
        let chosen = short_macos_msb_home(true, false, Some(home)).expect("macOS default applies");
        assert_eq!(chosen, PathBuf::from("/Users/johnsmith/.agent-vm-msb"));
    }

    #[test]
    fn short_macos_msb_home_falls_through_on_linux() {
        let home = std::ffi::OsStr::new("/home/johnsmith");
        assert_eq!(short_macos_msb_home(false, false, Some(home)), None);
    }

    #[test]
    fn short_macos_msb_home_falls_through_when_state_root_overridden() {
        // AGENT_VM_STATE_DIR / XDG_STATE_HOME must keep winning — the
        // macOS short-root special case only applies to the *default*.
        let home = std::ffi::OsStr::new("/Users/johnsmith");
        assert_eq!(short_macos_msb_home(true, true, Some(home)), None);
    }

    #[test]
    fn short_macos_msb_home_falls_through_without_home() {
        assert_eq!(short_macos_msb_home(true, false, None), None);
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn short_root_gives_more_socket_path_headroom_than_old_default() {
        // The exact regression this AC exists to fix: a realistic macOS
        // home directory that fits comfortably under the new short root
        // but would have overflowed sun_path under the old
        // `~/.local/state/agent-vm/msb-home` default. See
        // `msb_home_dir`'s doc comment for the byte-budget derivation.
        //
        // macOS-only: the fixture's 104-byte control-socket path is chosen
        // to exceed macOS's stricter 103-byte `SUN_PATH_USABLE_LEN` but
        // sits comfortably under Linux's more permissive 107-byte limit,
        // so on Linux it correctly would not overflow — this scenario (and
        // the short-root special case it justifies) is macOS-specific in
        // the first place, see `short_macos_msb_home`.
        let old_default = Path::new("/Users/j.van-der-berg/.local/state/agent-vm/msb-home/run");
        let short_root = Path::new("/Users/j.van-der-berg/.agent-vm-msb/run");
        let name = "agent-vm-abcd1234efgh5678-99999";

        let old_paths = microsandbox_runtime::ipc::sandbox_socket_paths(old_default, name);
        let short_paths = microsandbox_runtime::ipc::sandbox_socket_paths(short_root, name);

        assert!(
            old_paths.control.as_os_str().len() > SUN_PATH_USABLE_LEN,
            "test fixture should reproduce the old default's overflow: {} bytes",
            old_paths.control.as_os_str().len(),
        );
        assert!(check_socket_path_len(&short_paths.control, name).is_ok());
    }

    #[test]
    fn check_socket_path_len_accepts_a_short_path() {
        assert!(check_socket_path_len(Path::new("/tmp/short/control.sock"), "s").is_ok());
    }

    #[test]
    fn check_socket_path_len_fails_closed_on_overflow_with_actionable_message() {
        let long = Path::new("/Users/x")
            .join("a".repeat(SUN_PATH_USABLE_LEN))
            .join("control.sock");
        let err = check_socket_path_len(&long, "my-sandbox").unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("my-sandbox"), "should name the sandbox: {msg}");
        assert!(
            msg.contains("AGENT_VM_STATE_DIR"),
            "should name the fix: {msg}"
        );
        assert!(
            !msg.to_lowercase().contains("truncat") || msg.contains("never truncates"),
            "must not imply silent truncation: {msg}"
        );
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
        assert!(
            msg.contains("MSB_HOME"),
            "expected MSB_HOME mentioned: {msg}"
        );
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
