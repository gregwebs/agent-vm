//! Per-project session state.
//!
//! Each project directory gets a stable hash → state directory under
//! `${XDG_STATE_HOME:-~/.local/state}/agent-vm/<hash>/`. Agent-specific
//! subdirectories under that root are bind-mounted into the guest at the
//! standard paths under `$HOME` (`.claude`, `.codex`,
//! `.local/share/opencode`) so session history survives across runs —
//! `$HOME` is `/root` in `--root` mode, `/agent-vm-state/home` in the
//! non-root default (see [`GUEST_HOME_LINKS`] and
//! [`ProjectSession::provision_guest_home`]).
//!
//! The sandbox *name* additionally carries the launcher PID
//! (`agent-vm-<hash>-<pid>`) so two concurrent `agent-vm` invocations
//! from the same project boot independent VMs. Without this, the second
//! launch's `Sandbox::create` would SIGTERM/SIGKILL the first one's VMM
//! (we used to set `.replace()` to handle the same-name collision; now
//! there is no collision to handle). Per-project bind-mounted state
//! (claude/, codex/, opencode/, bash_history) is still shared between
//! the two — running two agents that mutate the same session files at
//! once is the user's call.

use std::{
    env,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

/// `(dotfile path relative to $HOME, target name relative to
/// `/agent-vm-state`)` pairs for every agent's persisted dotfile. Shared
/// source-of-truth for both guest-user modes so they can't drift:
///
/// - root mode wires these up as `/root/<suffix> -> /agent-vm-state/<target>`
///   rootfs symlinks baked by `run.rs`'s `.patch()` block (un-shadowed
///   rootfs, so `.patch()` is the right place).
/// - non-root mode wires the *same* mapping up host-side via
///   [`ProjectSession::provision_guest_home`], because non-root's HOME lives
///   under the `/agent-vm-state` runtime bind mount, which shadows anything
///   `.patch()` bakes at that path.
///
/// Codex is deliberately absent: it locates its config via the
/// `CODEX_HOME` env var (set unconditionally in `run.rs`), not a dotfile
/// symlink.
pub const GUEST_HOME_LINKS: &[(&str, &str)] = &[
    (".claude", "claude"),
    // Onboarding-state file lives at $HOME root, not in .claude/. Without
    // persistence the in-VM Claude re-runs the theme picker every launch.
    (".claude.json", "claude.json"),
    (".local/share/opencode", "opencode"),
    // OpenCode reads its config from $XDG_CONFIG_HOME/opencode/
    // (=~/.config/opencode/), file opencode.json. Distinct from the data
    // dir above — wired separately.
    (".config/opencode", "opencode-config"),
    // D1: GitHub Copilot CLI reads/writes ~/.copilot/ (config.json with
    // trusted_folders + the placeholder token, plus its session state).
    (".copilot", "copilot"),
    // gh/git config: secrets::write_guest_gh_config writes both into
    // state_dir; these symlinks expose them at the standard paths. The
    // gh-config link dangles when no gh token was captured — nothing
    // references it in that case.
    (".gitconfig", "gitconfig"),
    (".config/gh", "gh-config"),
    // Persistent per-project bash history. secrets::refresh touches
    // `<state>/bash_history` so the symlink target exists on first launch.
    (".bash_history", "bash_history"),
];

/// Everything Phase 2 needs to know about a project invocation.
pub struct ProjectSession {
    pub project_dir: PathBuf,
    pub project_hash: String,
    pub state_dir: PathBuf,
    pub sandbox_name: String,
}

impl ProjectSession {
    /// Build a session rooted at the current working directory.
    pub fn for_cwd() -> Result<Self> {
        let project_dir = env::current_dir()
            .context("reading current directory")?
            .canonicalize()
            .context("canonicalizing current directory")?;
        Self::for_dir(project_dir)
    }

    fn for_dir(project_dir: PathBuf) -> Result<Self> {
        let project_hash = hash_path(&project_dir);
        let state_dir = state_root()?.join(&project_hash);
        // Per-launch PID suffix so two concurrent invocations in the same
        // project boot independent sandboxes (the first one stays alive
        // instead of being SIGTERMed by the second's create()). The PID
        // is unique across currently-running processes on the host, which
        // is the only collision window we need to handle — a leftover
        // sandbox from a crashed launcher is cleaned up by the
        // Sandbox::remove call at end of launch().
        let sandbox_name = format!("agent-vm-{project_hash}-{}", std::process::id());
        Ok(Self {
            project_dir,
            project_hash,
            state_dir,
            sandbox_name,
        })
    }

    /// Create the state subdirectories that will be bind-mounted into the
    /// guest. Called before sandbox creation so virtiofs has somewhere real to
    /// point at.
    pub fn ensure_dirs(&self) -> Result<()> {
        for dir in [
            &self.state_dir,
            &self.claude_home(),
            &self.codex_home(),
            &self.opencode_data(),
        ] {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("creating {}", dir.display()))?;
        }
        Ok(())
    }

    pub fn claude_home(&self) -> PathBuf {
        self.state_dir.join("claude")
    }

    pub fn codex_home(&self) -> PathBuf {
        self.state_dir.join("codex")
    }

    pub fn opencode_data(&self) -> PathBuf {
        self.state_dir.join("opencode")
    }

    /// Host-absolute HOME for the non-root guest — `<state_dir>/home`,
    /// bind-mounted into the guest at `/agent-vm-state/home`.
    pub fn guest_home_dir(&self) -> PathBuf {
        self.state_dir.join("home")
    }

    /// Create the non-root guest's HOME directory and dotfile symlinks,
    /// host-side, in `<state_dir>/home`.
    ///
    /// Why host-side rather than via `.patch()` (as root mode's `/root/...`
    /// symlinks are): `/agent-vm-state` is a *runtime bind mount*, and
    /// `.patch()` bakes into the rootfs's `upper.ext4` before the VM boots —
    /// the bind mount then shadows anything a patch wrote under that path.
    /// So the non-root HOME has to be materialized on the host, in
    /// `state_dir`, exactly like `secrets::refresh` already does for the
    /// symlink *targets* (`state_dir/claude`, `state_dir/gitconfig`, …).
    ///
    /// Every link target is written as the guest-absolute string
    /// `/agent-vm-state/<name>` — a symlink stores its target string
    /// verbatim, so these resolve correctly inside the guest even though
    /// they're dangling on the host (there is no `/agent-vm-state` here).
    /// Dangling is harmless and pre-existing behavior: the gh/gitconfig
    /// links already dangle host-side when no gh token was captured.
    ///
    /// Call only in non-root mode, any time after [`Self::ensure_dirs`].
    pub fn provision_guest_home(&self) -> Result<()> {
        let home = self.guest_home_dir();
        for dir in [&home, &home.join(".local/share"), &home.join(".config")] {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("creating {}", dir.display()))?;
        }
        for (link, target) in guest_home_symlinks(&home) {
            // force_symlink already attributes failures to the specific
            // link/target pair; add distinct, higher-altitude context here
            // instead of repeating that same string.
            force_symlink(&target, &link)
                .with_context(|| format!("provisioning guest home in {}", home.display()))?;
        }
        Ok(())
    }
}

/// Pure mapping from [`GUEST_HOME_LINKS`] to `(host link path, guest target
/// string)` pairs rooted at `home`. Split out from
/// [`ProjectSession::provision_guest_home`] so the link→target mapping is
/// unit-testable without touching the filesystem.
fn guest_home_symlinks(home: &Path) -> Vec<(PathBuf, String)> {
    GUEST_HOME_LINKS
        .iter()
        .map(|(suffix, target_name)| {
            (home.join(suffix), format!("/agent-vm-state/{target_name}"))
        })
        .collect()
}

/// Create a symlink at `link` pointing at `target`, replacing whatever
/// (if anything) already occupies `link`. Idempotent across repeated
/// launches — a bare `std::os::unix::fs::symlink` errors `AlreadyExists`
/// on the second launch in the same project otherwise.
///
/// Only ever removes a *file or symlink* at `link` — never a real
/// directory. A directory at a mapped link path is unexpected (nothing in
/// `provision_guest_home` creates one there) and is left alone with a
/// clear error rather than silently `remove_dir_all`'d: recursing into an
/// unknown directory on every relaunch is a destructive-by-default footgun
/// (e.g. stale/corrupted state, or something a user put there deliberately)
/// with no upside — nothing in this codebase intentionally puts a directory
/// at one of these paths.
fn force_symlink(target: &str, link: &Path) -> Result<()> {
    match std::fs::symlink_metadata(link) {
        Ok(meta) if meta.is_dir() => anyhow::bail!(
            "{} is a real directory, not a symlink or file — refusing to \
             remove it automatically; move or delete it manually and re-run",
            link.display()
        ),
        Ok(_) => std::fs::remove_file(link)
            .with_context(|| format!("removing existing {}", link.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("stat {}", link.display())),
    }
    std::os::unix::fs::symlink(target, link)
        .with_context(|| format!("symlinking {} -> {target}", link.display()))
}

fn state_root() -> Result<PathBuf> {
    if let Some(dir) = env::var_os("AGENT_VM_STATE_DIR") {
        return Ok(PathBuf::from(dir));
    }
    if let Some(dir) = env::var_os("XDG_STATE_HOME") {
        return Ok(PathBuf::from(dir).join("agent-vm"));
    }
    let home = env::var_os("HOME").context("no $HOME set")?;
    Ok(PathBuf::from(home).join(".local/state/agent-vm"))
}

/// 12-hex-char prefix of SHA256(canonical_path). Short enough to keep sandbox
/// names readable; long enough that two project dirs are very unlikely to
/// collide on the same host.
fn hash_path(path: &Path) -> String {
    let mut h = Sha256::new();
    h.update(path.as_os_str().as_encoded_bytes());
    let digest = h.finalize();
    let mut s = String::with_capacity(12);
    for byte in &digest[..6] {
        use std::fmt::Write;
        write!(&mut s, "{byte:02x}").unwrap();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_stable_and_short() {
        let h = hash_path(Path::new("/some/project"));
        assert_eq!(h.len(), 12);
        assert_eq!(h, hash_path(Path::new("/some/project")));
        assert_ne!(h, hash_path(Path::new("/other/project")));
    }

    #[test]
    fn sandbox_name_carries_pid_for_concurrent_safety() {
        // Two ProjectSession values for the same dir must share state
        // (so per-project history etc. survives) but produce distinct
        // sandbox names within the same process (PID disambiguator —
        // and across processes the PIDs differ by definition).
        let dir = std::env::temp_dir();
        let a = ProjectSession::for_dir(dir.clone()).expect("for_dir a");
        let b = ProjectSession::for_dir(dir.clone()).expect("for_dir b");
        assert_eq!(a.state_dir, b.state_dir);
        assert_eq!(a.project_hash, b.project_hash);
        // Same process → same PID → same name within-process. The
        // concurrent-launch guarantee comes from PIDs differing across
        // processes; assert the name format encodes the PID so a future
        // refactor that drops it from the format trips the test.
        let pid = std::process::id().to_string();
        assert!(
            a.sandbox_name.ends_with(&format!("-{pid}")),
            "sandbox_name {:?} must end with -<pid>",
            a.sandbox_name
        );
        assert_eq!(a.sandbox_name, b.sandbox_name);
    }

    // ── non-root guest HOME provisioning ───────────────────────────

    #[test]
    fn guest_home_symlinks_map_matches_guest_home_links() {
        let home = Path::new("/state/home");
        let links = guest_home_symlinks(home);
        assert_eq!(links.len(), GUEST_HOME_LINKS.len());
        assert!(
            links
                .iter()
                .any(|(l, t)| l == &home.join(".claude") && t == "/agent-vm-state/claude"),
        );
        assert!(links.iter().any(|(l, t)| l
            == &home.join(".local/share/opencode")
            && t == "/agent-vm-state/opencode"));
        assert!(
            links
                .iter()
                .any(|(l, t)| l == &home.join(".config/gh") && t == "/agent-vm-state/gh-config"),
        );
        // Codex is deliberately absent — it uses CODEX_HOME, not a symlink.
        assert!(!links.iter().any(|(l, _)| l.ends_with("codex")));
    }

    fn throwaway_session() -> ProjectSession {
        let unique = format!(
            "agent-vm-provision-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let root = std::env::temp_dir().join(unique);
        ProjectSession {
            project_dir: root.clone(),
            project_hash: "deadbeef0000".into(),
            state_dir: root.join("state"),
            sandbox_name: "agent-vm-test".into(),
        }
    }

    #[test]
    fn provision_guest_home_creates_dirs_and_dangling_symlinks() {
        let session = throwaway_session();
        session
            .provision_guest_home()
            .expect("provision_guest_home");

        let home = session.guest_home_dir();
        assert!(home.is_dir());
        assert!(home.join(".local/share").is_dir());
        assert!(home.join(".config").is_dir());

        let target = std::fs::read_link(home.join(".claude")).expect("readlink .claude");
        assert_eq!(target, PathBuf::from("/agent-vm-state/claude"));
        // Dangling on the host (no /agent-vm-state here) is expected —
        // the target only resolves inside the guest.
        assert!(!home.join(".claude").exists());

        std::fs::remove_dir_all(&session.project_dir).ok();
    }

    #[test]
    fn provision_guest_home_is_idempotent() {
        let session = throwaway_session();
        session.provision_guest_home().expect("first provision");
        // A stray real file where a symlink should go must not abort a
        // re-launch in the same project.
        std::fs::remove_file(session.guest_home_dir().join(".gitconfig")).ok();
        std::fs::write(session.guest_home_dir().join(".gitconfig"), "stray").unwrap();
        session
            .provision_guest_home()
            .expect("second provision must replace the stray file, not fail");
        let target =
            std::fs::read_link(session.guest_home_dir().join(".gitconfig")).expect("readlink");
        assert_eq!(target, PathBuf::from("/agent-vm-state/gitconfig"));

        std::fs::remove_dir_all(&session.project_dir).ok();
    }

    #[test]
    fn force_symlink_refuses_to_remove_a_real_directory() {
        // A real directory occupying a link path is unexpected and must be
        // left alone (not silently `remove_dir_all`'d) — see the doc
        // comment on `force_symlink`.
        let session = throwaway_session();
        let home = session.guest_home_dir();
        std::fs::create_dir_all(&home).unwrap();
        let link = home.join(".gitconfig");
        std::fs::create_dir_all(link.join("nested")).unwrap();
        std::fs::write(link.join("nested/real-file"), "do not delete me").unwrap();

        let err = force_symlink("/agent-vm-state/gitconfig", &link)
            .expect_err("must refuse to remove a real directory");
        assert!(
            err.to_string().contains("real directory"),
            "unexpected error: {err}"
        );
        // The directory and its contents must still be there.
        assert!(link.join("nested/real-file").is_file());

        std::fs::remove_dir_all(&session.project_dir).ok();
    }
}
