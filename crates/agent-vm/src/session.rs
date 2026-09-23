//! Per-project session state.
//!
//! Each project directory gets a stable hash → state directory under
//! `${XDG_STATE_HOME:-~/.local/state}/agent-vm/<hash>/`. Agent-specific
//! subdirectories under that root are bind-mounted into the guest at the
//! standard paths under `$HOME` (`.claude`, `.codex`,
//! `.local/share/opencode`) so session history survives across runs —
//! `$HOME` is `/root` in `--root` mode; in the non-root default it's the
//! *mirrored host* `$HOME` path (e.g. `/Users/claude`), bind-mounted from
//! this host-owned `<state_dir>/home` (see
//! [`crate::credential_provider::guest_home_links`],
//! [`ProjectSession::provision_guest_home`], `user.rs`'s `core_dir_volumes`,
//! and `docs/adr/0002-mirror-host-home-and-username.md`).
//!
//! The sandbox *name* additionally carries the launcher PID
//! (`agent-vm-<hash>-<pid>`) so two concurrent `agent-vm` invocations
//! from the same project boot independent VMs. Without this, the second
//! launch's `Sandbox::create` would SIGTERM/SIGKILL the first one's VMM.
//! Per-project bind-mounted state
//! (claude/, codex/, opencode/, bash_history) is still shared between
//! the two — running two agents that mutate the same session files at
//! once is the user's call.

use std::{
    env,
    io::ErrorKind,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::guest_home::{self, GuestHomeLink, LinkSource};
use crate::host_paths::{EntryType, GuestStateDir};

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

    /// Move a pre-#96 real `<state>/home/.pi` directory to `<state>/pi`, once.
    ///
    /// Before #96 the non-root guest HOME (`<state>/home`, persistent) held
    /// Pi's user state as a real directory, because nothing mapped it. #96
    /// maps `.pi` as a *compiled* link, and [`force_symlink`] deliberately
    /// refuses to remove a real directory -- so without this, the first launch
    /// after the upgrade would fail on EVERY verb (including the `shell` a
    /// user would reach for to fix it) for any project where Pi had ever run.
    ///
    /// `rename` within the project state dir is same-filesystem and atomic,
    /// and it never destroys: an already-populated `<state>/pi` is reported,
    /// not merged. An *empty* `<state>/pi` is treated as absent because
    /// `ensure_dirs` (and `agent-vm clipboard`, which also calls it) eagerly
    /// creates it as a placeholder.
    ///
    /// Every path is resolved through an opened state-root descriptor with
    /// every ancestor opened `O_NOFOLLOW`, so a guest that left `<state>/home`
    /// as a symlink to the host `$HOME` cannot make this move the host's real
    /// `~/.pi`; a redirected ancestor is a hard error. See
    /// `docs/adr/0021-project-scoped-pi-home-and-wrapper-parity.md`.
    ///
    /// Root mode never wrote a host-side `~/.pi` (`/root` is rebaked per
    /// boot), but this runs in both modes on purpose: a user who upgrades and
    /// then launches with `--root` first still gets their old non-root Pi
    /// state moved into the shared `<state>/pi`, instead of silently seeing an
    /// empty one.
    ///
    /// Delete this method once no supported state dir can predate #96.
    pub fn migrate_legacy_pi_home(&self) -> Result<()> {
        self.migrate_legacy_pi_home_impl(|| {}, || {})
    }

    fn migrate_legacy_pi_home_impl(
        &self,
        about_to_lock: impl FnOnce(),
        after_inspect: impl FnOnce(),
    ) -> Result<()> {
        // A project that has never launched has no `<state>` at all, so there
        // is nothing that could predate #96 -- skip without creating anything.
        match std::fs::symlink_metadata(&self.state_dir) {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("stat {}", crate::config::escape_path(&self.state_dir))
                });
            }
        }

        // Host-only synchronization: the guest can see and write `<state>`,
        // but `<state>.secrets/` is a sibling that is never bind-mounted, so
        // it can neither delete nor replace this lock. Two launchers that both
        // observe the populated legacy directory must not both `rename` it --
        // the loser would otherwise abort with ENOENT or mis-report "two
        // populated homes". Everything below re-reads source and target under
        // the lock, so a peer's completed migration is recognized as a no-op.
        // Test-only observation point: fires once this caller has started and
        // is about to contend for the lock, so a deterministic concurrency
        // test can prove a second caller actually reached (and blocked on) it.
        about_to_lock();
        let _lock = crate::secrets::ProjectLock::acquire(&self.state_dir, MIGRATION_LOCK)?;

        // Anchor every check and the rename in one opened state-root
        // descriptor, with every ancestor (including `home`, which a previous
        // guest can turn into a symlink to the host HOME) opened `O_NOFOLLOW`.
        // A redirected ancestor is a hard error, never silently followed.
        let guest = GuestStateDir::open(&self.state_dir).with_context(|| {
            format!(
                "migrating the pre-#96 Pi home for {}",
                crate::config::escape_path(&self.state_dir)
            )
        })?;

        let legacy = Path::new("home/.pi");
        let target = Path::new("pi");
        let legacy_path = self.guest_home_dir().join(".pi");
        let target_path = self.state_dir.join("pi");

        // Only a REAL directory needs moving. A symlink means the migration
        // already ran (or a peer just completed it); a regular file is
        // `force_symlink`'s existing business.
        if guest.entry_type(legacy)? != Some(EntryType::Directory) {
            return Ok(());
        }

        match guest.entry_type(target)? {
            None => {}
            // The eagerly-created placeholder is a REAL empty directory.
            Some(EntryType::Directory) => {
                if !guest.dir_is_empty(target)? {
                    anyhow::bail!(
                        "{} is a pre-upgrade Pi home and {} already holds Pi state; agent-vm \
                         will not merge them. Move one aside on the host, e.g. \
                         `mv {} {}.pre-96`, then re-run",
                        crate::config::escape_path(&legacy_path),
                        crate::config::escape_path(&target_path),
                        crate::config::escape_path(&legacy_path),
                        crate::config::escape_path(&legacy_path)
                    );
                }
            }
            // Anything else at the destination (a symlink, a file) is
            // unexpected and must never be silently merged.
            Some(_) => anyhow::bail!(
                "{} is not a directory; agent-vm will not move the pre-upgrade Pi home {} \
                 onto it. Move it aside on the host, e.g. \
                 `mv {} {}.pre-96`, then re-run",
                crate::config::escape_path(&target_path),
                crate::config::escape_path(&legacy_path),
                crate::config::escape_path(&target_path),
                crate::config::escape_path(&target_path)
            ),
        }

        // Both inspections are complete: this is the "about to publish" point,
        // where deterministic-concurrency tests swap a guest-controlled
        // ancestor to prove the rename does not follow it.
        after_inspect();

        // Re-read the destination immediately before publication. The lock
        // makes a peer interleave impossible, but keeping the emptiness check
        // adjacent to the rename means it cannot drift from the publication it
        // guards.
        if guest.entry_type(target)? == Some(EntryType::Directory) {
            guest.remove_empty_dir(target)?;
        }
        guest.rename_entry(legacy, target)?;
        tracing::info!(
            "moved the pre-#96 Pi home {} to {} (issue #96)",
            crate::config::escape_path(&legacy_path),
            crate::config::escape_path(&target_path)
        );
        Ok(())
    }

    /// Test-only seam: `after_inspect` fires once the migration has inspected
    /// source and target but before it publishes (removes/renames).
    #[cfg(test)]
    fn migrate_legacy_pi_home_with_checkpoint(&self, after_inspect: impl FnOnce()) -> Result<()> {
        self.migrate_legacy_pi_home_impl(|| {}, after_inspect)
    }

    /// Test-only seam: `about_to_lock` fires once the migration has started and
    /// is about to acquire the project lock, so a test can establish that a
    /// contending caller reached the lock rather than merely not being
    /// scheduled yet.
    #[cfg(test)]
    fn migrate_legacy_pi_home_with_lock_checkpoint(
        &self,
        about_to_lock: impl FnOnce(),
    ) -> Result<()> {
        self.migrate_legacy_pi_home_impl(about_to_lock, || {})
    }

    /// Create the state subdirectories that will be bind-mounted into the
    /// guest. Called before sandbox creation so virtiofs has somewhere real to
    /// point at.
    ///
    /// `state_dir` itself is created **first** (it is not one of the provider
    /// dirs `eager_state_dirs` returns); dropping that would break first-launch
    /// provisioning for a brand-new project. Afterwards every link target's
    /// parent is created (see the loop below).
    pub fn ensure_dirs(&self, links: &[GuestHomeLink]) -> Result<()> {
        std::fs::create_dir_all(&self.state_dir)
            .with_context(|| format!("creating {}", self.state_dir.display()))?;
        for name in crate::credential_provider::eager_state_dirs() {
            let dir = self.state_dir.join(name);
            std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        // Every link's target parent, so a dangling `persist` symlink resolves
        // to a creatable path in the guest (the guest's `open(O_CREAT)` through
        // the link creates the real file host-side). For a compiled link the
        // parent is the state dir itself — already created above — so this loop
        // is uniform, adds no special case, and moves no existing golden. It
        // runs in **both** modes: root mode does not call
        // `provision_guest_home`, but its `.patch()`-baked symlinks still need
        // their targets' parents to exist on the host.
        for link in links {
            let target = self.state_dir.join(&link.state_relative);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", crate::config::escape_path(parent)))?;
            }
        }
        Ok(())
    }

    /// Host-managed fork state, deliberately a sibling of the guest-visible
    /// state directory so locks and manifests can never be mounted in a VM.
    pub fn mount_store_dir(&self) -> PathBuf {
        self.state_dir
            .with_file_name(format!("{}.mounts", self.project_hash))
    }

    /// Host-absolute HOME for the non-root guest — `<state_dir>/home`. This
    /// is the *host-side bind source*; the guest-visible mount path is the
    /// mirrored host `$HOME` (e.g. `/Users/claude`), not this path — see
    /// `user.rs`'s `core_dir_volumes` and
    /// `docs/adr/0002-mirror-host-home-and-username.md`.
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
    pub fn provision_guest_home(&self, links: &[GuestHomeLink]) -> Result<()> {
        let home = self.guest_home_dir();
        std::fs::create_dir_all(&home).with_context(|| format!("creating {}", home.display()))?;
        for dir in guest_home::link_parent_dirs(links) {
            let dir = home.join(dir);
            create_dir_all_beneath(&home, &dir)?;
        }
        for (link, (link_path, target)) in links.iter().zip(guest_home_symlinks(&home, links)) {
            match link.source {
                LinkSource::Compiled => {
                    force_symlink(&target, &link_path).with_context(|| {
                        format!("provisioning guest home in {}", home.display())
                    })?;
                }
                LinkSource::Declared => {
                    let target_path = self.state_dir.join(&link.state_relative);
                    link_declared_persist(&target_path, &target, &link_path).with_context(
                        || format!("provisioning guest home in {}", home.display()),
                    )?;
                }
            }
        }
        Ok(())
    }
}

/// Create `dir` and its parents, refusing to descend through a symlink at or
/// below `home`. [`std::fs::create_dir_all`] follows symlinks in *parent*
/// components, so a guest-planted symlink (the non-root guest HOME is a bind
/// mount the in-guest agent writes to freely) could redirect host-side
/// provisioning outside the state dir — e.g. `~/.cache -> /etc`. This is the
/// guard that makes [`link_declared_persist`]'s "both paths are under the
/// project state dir" argument true rather than assumed, and it also covers the
/// compiled links' ancestors (`.local`, `.config`).
fn create_dir_all_beneath(home: &Path, dir: &Path) -> Result<()> {
    let relative = dir.strip_prefix(home).unwrap_or(dir);
    let mut current = home.to_path_buf();
    for component in relative.components() {
        current.push(component);
        if std::fs::symlink_metadata(&current).is_ok_and(|meta| meta.file_type().is_symlink()) {
            anyhow::bail!(
                "refusing to provision {}: {} is a symlink, not a directory; a \
                 symlinked path under the guest HOME must not redirect host-side provisioning",
                crate::config::escape_path(dir),
                crate::config::escape_path(&current)
            );
        }
    }
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating {}", crate::config::escape_path(dir)))
}

/// Pure mapping from the resolved [`GuestHomeLink`] list to
/// `(host link path, guest target string)` pairs rooted at `home`. Split out
/// from [`ProjectSession::provision_guest_home`] so the link→target mapping is
/// unit-testable without touching the filesystem.
fn guest_home_symlinks(home: &Path, links: &[GuestHomeLink]) -> Vec<(PathBuf, String)> {
    links
        .iter()
        .map(|link| (home.join(&link.home_relative), link.guest_target()))
        .collect()
}

/// Link a tool-declared `persist` path, migrating whatever is already there.
///
/// A regular file or directory at the path is the user's data: in non-root mode
/// the guest HOME is itself persistent, so the first launch after adding a
/// `persist` entry finds real content that a previous launch wrote. It is
/// *moved* into the state dir rather than deleted (`force_symlink`'s
/// file-replacing behaviour would be data loss here) and rather than refused
/// (a hard error would fail every launch whose provisioning closure reaches
/// this tool — including the `shell` a user would reach for to fix it).
///
/// `rename` never destroys: both paths are under the project state dir, so it
/// is same-filesystem and atomic, and a destination that already exists is an
/// ambiguity (two sources of truth) that is reported, not resolved.
fn link_declared_persist(target_path: &Path, target: &str, link: &Path) -> Result<()> {
    // Every path in a diagnostic below is config-derived (it embeds a `persist`
    // entry, which may legally contain ESC/ANSI bytes), so it is escaped with
    // the same rule `config`'s own diagnostics use — never printed raw.
    match std::fs::symlink_metadata(link) {
        Ok(meta) if meta.file_type().is_symlink() => {
            // Idempotent relaunch, or a retarget: replace the link.
            std::fs::remove_file(link).with_context(|| {
                format!("removing existing {}", crate::config::escape_path(link))
            })?;
        }
        Ok(_) => {
            if std::fs::symlink_metadata(target_path).is_ok() {
                anyhow::bail!(
                    "guest home path {} holds real content and its persist target {} also exists; \
                     move or remove one of them",
                    crate::config::escape_path(link),
                    crate::config::escape_path(target_path)
                );
            }
            std::fs::rename(link, target_path).with_context(|| {
                format!(
                    "migrating {} into {}",
                    crate::config::escape_path(link),
                    crate::config::escape_path(target_path)
                )
            })?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("stat {}", crate::config::escape_path(link)));
        }
    }
    std::os::unix::fs::symlink(target, link).with_context(|| {
        format!(
            "symlinking {} -> {}",
            crate::config::escape_path(link),
            crate::config::escape_str(target)
        )
    })
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

/// Basename of the host-only advisory lock serializing the one-shot #96
/// Pi-home migration within one project (see [`crate::secrets::ProjectLock`]).
/// It lives in the sibling `<hash>.secrets/` directory, which is never
/// bind-mounted into the guest, so the guest can neither delete nor replace the
/// synchronization point. Two concurrent launchers that both observe a
/// populated legacy `<state>/home/.pi` must not both `rename` it: the loser
/// would otherwise fail with ENOENT or mis-report "two populated homes".
const MIGRATION_LOCK: &str = ".pi-migration.lock";

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
    use std::sync::Arc;

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

    // ── characterization goldens captured on the pre-refactor tree ──
    //
    // These pin today's behaviour so the credential-provider extraction
    // (#81) is provably zero-behaviour-change. The golden literals below
    // were transcribed from the unrefactored source, not from the new
    // module — if the extraction changes any of them, that is a
    // regression, not a test to update.

    /// V12: `ensure_dirs` eagerly creates the state root plus exactly the
    /// three per-tool subdirectories; a dropped one breaks first-launch
    /// provisioning (virtiofs has nowhere real to point at). The golden dir
    /// list itself is asserted in `credential_provider`.
    #[test]
    fn ensure_dirs_creates_state_root_and_legacy_subdirs() {
        let session = throwaway_session();
        session
            .ensure_dirs(&guest_home::links(&[]))
            .expect("ensure_dirs");
        assert!(session.state_dir.is_dir(), "state root must be created");
        for sub in ["claude", "codex", "opencode", "pi"] {
            assert!(
                session.state_dir.join(sub).is_dir(),
                "ensure_dirs must create state_dir/{sub}"
            );
        }
        std::fs::remove_dir_all(&session.project_dir).ok();
    }

    /// V6: a declared `persist` path's target *parent* is created (so the guest
    /// can create the file through the dangling link), while the target itself
    /// is deliberately left absent — pre-creating it would break a
    /// file-valued entry.
    #[test]
    fn ensure_dirs_creates_declared_target_parents() {
        let session = throwaway_session();
        let links = guest_home::links(&[
            crate::config::PersistPath::for_test(".aider.conf.yml"),
            crate::config::PersistPath::for_test(".cache/aider"),
        ]);
        session.ensure_dirs(&links).expect("ensure_dirs");
        for sub in ["claude", "codex", "opencode", "pi"] {
            assert!(session.state_dir.join(sub).is_dir());
        }
        assert!(session.state_dir.join("persist").is_dir());
        assert!(session.state_dir.join("persist/.cache").is_dir());
        assert!(!session.state_dir.join("persist/.aider.conf.yml").exists());
        std::fs::remove_dir_all(&session.project_dir).ok();
    }

    // ── non-root guest HOME provisioning ───────────────────────────

    #[test]
    fn guest_home_symlinks_map_matches_guest_home_links() {
        let home = Path::new("/state/home");
        let links = guest_home_symlinks(home, &guest_home::links(&[]));
        assert_eq!(
            links.len(),
            crate::credential_provider::guest_home_links().len()
        );
        assert!(
            links
                .iter()
                .any(|(l, t)| l == &home.join(".claude") && t == "/agent-vm-state/claude"),
        );
        assert!(
            links
                .iter()
                .any(|(l, t)| l == &home.join(".local/share/opencode")
                    && t == "/agent-vm-state/opencode")
        );
        assert!(
            links
                .iter()
                .any(|(l, t)| l == &home.join(".config/gh") && t == "/agent-vm-state/gh-config"),
        );
        // Codex is deliberately absent — it uses CODEX_HOME, not a symlink.
        assert!(!links.iter().any(|(l, _)| l.ends_with("codex")));
    }

    /// V5 (#96): after provisioning, `<state>/home/.pi` is a symlink whose
    /// target string is exactly `/agent-vm-state/pi` — `read_link`, not
    /// `canonicalize`, because it dangles on the host by design.
    #[test]
    fn provision_guest_home_links_pi_at_the_state_dir() {
        let session = throwaway_session();
        session
            .provision_guest_home(&guest_home::links(&[]))
            .expect("provision");
        let link = session.guest_home_dir().join(".pi");
        assert_eq!(
            std::fs::read_link(&link).expect("readlink .pi"),
            PathBuf::from("/agent-vm-state/pi")
        );
        std::fs::remove_dir_all(&session.project_dir).ok();
    }

    // ── U1-U6 (#96): the pre-#96 Pi home migration ────────────────

    /// Create the real `<state>/home/.pi` directory a pre-#96 non-root guest
    /// left behind, with a sentinel credential inside the agent dir.
    fn seed_legacy_pi_home(session: &ProjectSession) {
        let legacy = session.guest_home_dir().join(".pi");
        std::fs::create_dir_all(legacy.join("agent")).unwrap();
        std::fs::write(legacy.join("agent/auth.json"), b"sentinel").unwrap();
    }

    /// U1: the pre-#96 real directory is moved, not lost, and the compiled
    /// link then replaces it.
    #[test]
    fn migrate_legacy_pi_home_moves_a_pre_96_directory() {
        let session = throwaway_session();
        seed_legacy_pi_home(&session);

        let links = guest_home::links(&[]);
        session.migrate_legacy_pi_home().expect("migrate");
        session.ensure_dirs(&links).expect("ensure_dirs");
        session.provision_guest_home(&links).expect("provision");

        assert_eq!(
            std::fs::read_link(session.guest_home_dir().join(".pi")).unwrap(),
            PathBuf::from("/agent-vm-state/pi")
        );
        assert_eq!(
            std::fs::read(session.state_dir.join("pi/agent/auth.json")).unwrap(),
            b"sentinel"
        );
        std::fs::remove_dir_all(&session.project_dir).ok();
    }

    /// U2: a second launch is a no-op (`.pi` is a symlink now) and the bytes
    /// survive.
    #[test]
    fn migrate_legacy_pi_home_is_idempotent_across_launches() {
        let session = throwaway_session();
        seed_legacy_pi_home(&session);

        let links = guest_home::links(&[]);
        for _ in 0..2 {
            session.migrate_legacy_pi_home().expect("migrate");
            session.ensure_dirs(&links).expect("ensure_dirs");
            session.provision_guest_home(&links).expect("provision");
        }

        assert_eq!(
            std::fs::read(session.state_dir.join("pi/agent/auth.json")).unwrap(),
            b"sentinel"
        );
        std::fs::remove_dir_all(&session.project_dir).ok();
    }

    /// U3: the empty `<state>/pi` placeholder `agent-vm clipboard` eagerly
    /// creates is tolerated, and the real content still moves.
    #[test]
    fn migrate_legacy_pi_home_tolerates_an_eagerly_created_empty_target() {
        let session = throwaway_session();
        seed_legacy_pi_home(&session);
        std::fs::create_dir_all(session.state_dir.join("pi")).unwrap();

        let links = guest_home::links(&[]);
        session.migrate_legacy_pi_home().expect("migrate");
        session.ensure_dirs(&links).expect("ensure_dirs");
        session.provision_guest_home(&links).expect("provision");

        assert_eq!(
            std::fs::read(session.state_dir.join("pi/agent/auth.json")).unwrap(),
            b"sentinel"
        );
        std::fs::remove_dir_all(&session.project_dir).ok();
    }

    /// U4: two populated Pi homes are reported, never merged, and nothing is
    /// destroyed.
    #[test]
    fn migrate_legacy_pi_home_refuses_to_merge_two_populated_homes() {
        let session = throwaway_session();
        let legacy = session.guest_home_dir().join(".pi");
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::write(legacy.join("x"), b"legacy").unwrap();
        let target = session.state_dir.join("pi");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("y"), b"state").unwrap();

        let err = session
            .migrate_legacy_pi_home()
            .expect_err("must refuse to merge two populated Pi homes");
        let message = err.to_string();
        assert!(
            message.contains(&legacy.to_string_lossy().into_owned()),
            "message must name the legacy path: {message}"
        );
        assert!(
            message.contains(&target.to_string_lossy().into_owned()),
            "message must name the target path: {message}"
        );
        // Non-destructive: both files still exist.
        assert!(legacy.join("x").is_file());
        assert!(target.join("y").is_file());
        std::fs::remove_dir_all(&session.project_dir).ok();
    }

    /// U5: a regular file at `.pi` is not the migration's business —
    /// `force_symlink`'s existing file-replacing behaviour handles it.
    #[test]
    fn migrate_legacy_pi_home_leaves_a_file_to_force_symlink() {
        let session = throwaway_session();
        let home = session.guest_home_dir();
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(home.join(".pi"), b"a stray file").unwrap();

        let links = guest_home::links(&[]);
        session.migrate_legacy_pi_home().expect("no-op on a file");
        session.ensure_dirs(&links).expect("ensure_dirs");
        session.provision_guest_home(&links).expect("provision");

        assert_eq!(
            std::fs::read_link(home.join(".pi")).unwrap(),
            PathBuf::from("/agent-vm-state/pi")
        );
        std::fs::remove_dir_all(&session.project_dir).ok();
    }

    /// U6: a fresh project migrates nothing and still ends up linked with a
    /// real `<state>/pi` directory.
    #[test]
    fn migrate_legacy_pi_home_is_a_noop_on_a_fresh_project() {
        let session = throwaway_session();
        let links = guest_home::links(&[]);

        session.migrate_legacy_pi_home().expect("no-op");
        session.ensure_dirs(&links).expect("ensure_dirs");
        session.provision_guest_home(&links).expect("provision");

        assert!(session.state_dir.join("pi").is_dir());
        assert_eq!(
            std::fs::read_link(session.guest_home_dir().join(".pi")).unwrap(),
            PathBuf::from("/agent-vm-state/pi")
        );
        std::fs::remove_dir_all(&session.project_dir).ok();
    }

    // ── Q1 (#96): the migration must never follow a guest-planted ancestor ──

    /// Point `<state>/home` at a fake host HOME holding sentinel Pi bytes.
    /// Returns the fake home so the test can prove it was never touched.
    fn plant_home_symlink(session: &ProjectSession) -> PathBuf {
        let fake_host_home = session.project_dir.join("fake-host-home");
        std::fs::create_dir_all(fake_host_home.join(".pi/agent")).unwrap();
        std::fs::write(
            fake_host_home.join(".pi/agent/auth.json"),
            b"HOST-AUTH-SENTINEL",
        )
        .unwrap();
        std::fs::write(
            fake_host_home.join(".pi/agent/models.json"),
            b"HOST-MODELS-SENTINEL",
        )
        .unwrap();
        std::fs::create_dir_all(&session.state_dir).unwrap();
        std::os::unix::fs::symlink(&fake_host_home, session.guest_home_dir()).unwrap();
        fake_host_home
    }

    /// Q1: a previous guest can leave `<state>/home` as a symlink to the host
    /// HOME. The migration must fail closed rather than treat the host's real
    /// `~/.pi` as the legacy directory and move it into guest-visible state.
    #[test]
    fn migrate_legacy_pi_home_refuses_a_guest_planted_home_symlink() {
        let session = throwaway_session();
        let fake_host_home = plant_home_symlink(&session);

        let error = session
            .migrate_legacy_pi_home()
            .expect_err("a symlinked `home` ancestor must fail the migration closed");
        assert!(
            error
                .to_string()
                .contains(&session.guest_home_dir().display().to_string()),
            "the diagnostic must name the redirected ancestor: {error}"
        );

        // The host home is untouched and still in place.
        assert_eq!(
            std::fs::read(fake_host_home.join(".pi/agent/auth.json")).unwrap(),
            b"HOST-AUTH-SENTINEL"
        );
        assert_eq!(
            std::fs::read(fake_host_home.join(".pi/agent/models.json")).unwrap(),
            b"HOST-MODELS-SENTINEL"
        );
        assert!(fake_host_home.join(".pi").is_dir());
        assert_eq!(
            std::fs::read_link(session.guest_home_dir()).unwrap(),
            fake_host_home
        );
        // No sentinel entered guest state.
        assert!(!session.state_dir.join("pi").exists());
        std::fs::remove_dir_all(&session.project_dir).ok();
    }

    /// Q1: after the migration has already validated `home` as a real
    /// directory, a swap to a symlink must still be refused -- the check is
    /// not a one-time preflight pathname test.
    #[test]
    fn migrate_legacy_pi_home_refuses_a_swapped_ancestor_after_validation() {
        let session = throwaway_session();
        seed_legacy_pi_home(&session);
        let fake_host_home = session.project_dir.join("fake-host-home");
        std::fs::create_dir_all(fake_host_home.join(".pi/agent")).unwrap();
        std::fs::write(
            fake_host_home.join(".pi/agent/auth.json"),
            b"HOST-AUTH-SENTINEL",
        )
        .unwrap();

        let home = session.guest_home_dir();
        let moved = session.project_dir.join("home-moved-by-attacker");
        let error = session
            .migrate_legacy_pi_home_with_checkpoint(|| {
                // Validation has passed; swap the ancestor in the window
                // before publication.
                std::fs::rename(&home, &moved).unwrap();
                std::os::unix::fs::symlink(&fake_host_home, &home).unwrap();
            })
            .expect_err("a redirected ancestor after validation must fail closed");
        let _ = error;

        assert_eq!(
            std::fs::read(fake_host_home.join(".pi/agent/auth.json")).unwrap(),
            b"HOST-AUTH-SENTINEL"
        );
        assert!(!session.state_dir.join("pi").exists());
        // The legacy bytes were not lost either -- they are still under the
        // original (renamed-aside) home, not in guest state.
        assert_eq!(
            std::fs::read(moved.join(".pi/agent/auth.json")).unwrap(),
            b"sentinel"
        );
        std::fs::remove_dir_all(&session.project_dir).ok();
    }

    // ── S1 (#96): concurrent migrations must converge ──────────────

    /// Drive `first` to its post-inspection checkpoint while it holds the
    /// project lock, then start `second`, prove the second actually reached
    /// the lock and cannot finish (`recv_timeout` returns `Timeout`), then
    /// release `first` and join both. Deterministic: no sleeps, and the
    /// `Timeout` is a liveness assertion about the lock rather than a timing
    /// guess. Returns `(first, second)` so each caller can assert its outcome.
    fn contended_migration_round(session: &Arc<ProjectSession>) -> (Result<()>, Result<()>) {
        use std::sync::mpsc;
        use std::time::Duration;

        let (inspected_tx, inspected_rx) = mpsc::channel();
        let (proceed_tx, proceed_rx) = mpsc::channel();
        let first = {
            let session = Arc::clone(session);
            std::thread::spawn(move || {
                session.migrate_legacy_pi_home_with_checkpoint(|| {
                    inspected_tx.send(()).unwrap();
                    proceed_rx.recv().unwrap();
                })
            })
        };
        // The first now holds the lock and has inspected both sides.
        inspected_rx.recv().unwrap();

        let (about_to_lock_tx, about_to_lock_rx) = mpsc::channel();
        let (second_done_tx, second_done_rx) = mpsc::channel();
        let second = {
            let session = Arc::clone(session);
            std::thread::spawn(move || {
                let result = session.migrate_legacy_pi_home_with_lock_checkpoint(|| {
                    about_to_lock_tx.send(()).unwrap();
                });
                second_done_tx.send(()).unwrap();
                result
            })
        };
        // The second caller has started and reached the lock. While the first
        // still holds it the second must not be able to finish: requiring
        // `Timeout` establishes the contended ordering deterministically.
        about_to_lock_rx.recv().unwrap();
        assert_eq!(
            second_done_rx.recv_timeout(Duration::from_secs(2)),
            Err(mpsc::RecvTimeoutError::Timeout),
            "a contending migration must block on the project lock, not race past it"
        );

        proceed_tx.send(()).unwrap();
        let first_result = first.join().unwrap();
        assert_eq!(
            second_done_rx.recv_timeout(Duration::from_secs(10)),
            Ok(()),
            "the second migration must finish once the lock is released"
        );
        let second_result = second.join().unwrap();
        (first_result, second_result)
    }

    /// S1: two launchers that both observe a populated legacy dir must not
    /// both rename it. The first holds the host-only lock at the "inspected,
    /// about to publish" checkpoint; the second is proven to have reached and
    /// blocked on the lock, then released; it re-reads and recognizes the
    /// completed move as a no-op instead of failing with ENOENT.
    #[test]
    fn concurrent_migrations_converge_on_one_move() {
        let session = Arc::new(throwaway_session());
        seed_legacy_pi_home(&session);

        let (first, second) = contended_migration_round(&session);
        first.expect("first migration must move the legacy home");
        second.expect("second migration must recognize the completed move, not fail with ENOENT");
        assert_eq!(
            std::fs::read(session.state_dir.join("pi/agent/auth.json")).unwrap(),
            b"sentinel"
        );
        assert!(!session.guest_home_dir().join(".pi").exists());
        std::fs::remove_dir_all(&session.project_dir).ok();
    }

    /// S1: the same deterministic contention when the eagerly-created
    /// (clipboard-first) `<state>/pi` placeholder already exists and is empty.
    #[test]
    fn concurrent_migrations_converge_with_an_eager_empty_target() {
        let session = Arc::new(throwaway_session());
        seed_legacy_pi_home(&session);
        std::fs::create_dir_all(session.state_dir.join("pi")).unwrap();

        let (first, second) = contended_migration_round(&session);
        first.expect("first migration");
        second.expect("second migration");
        assert_eq!(
            std::fs::read(session.state_dir.join("pi/agent/auth.json")).unwrap(),
            b"sentinel"
        );
        std::fs::remove_dir_all(&session.project_dir).ok();
    }

    /// S1 control: a genuine two-populated-homes conflict must still be
    /// refused under concurrency -- never degraded into a spurious ENOENT.
    #[test]
    fn concurrent_migrations_still_refuse_two_populated_homes() {
        use std::sync::Arc;
        let session = Arc::new(throwaway_session());
        seed_legacy_pi_home(&session);
        let target = session.state_dir.join("pi");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("state-only"), b"state").unwrap();

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let session = Arc::clone(&session);
                std::thread::spawn(move || session.migrate_legacy_pi_home())
            })
            .collect();
        for handle in handles {
            let error = handle
                .join()
                .unwrap()
                .expect_err("two populated homes must always be refused");
            assert!(
                error.to_string().contains("will not merge"),
                "a concurrent refusal must keep its message, not become ENOENT: {error}"
            );
        }
        assert!(
            session
                .guest_home_dir()
                .join(".pi/agent/auth.json")
                .is_file()
        );
        assert!(target.join("state-only").is_file());
        std::fs::remove_dir_all(&session.project_dir).ok();
    }

    /// S1: many parallel callers still move the legacy home exactly once.
    #[test]
    fn parallel_migrations_move_the_legacy_home_exactly_once() {
        use std::sync::Arc;
        let session = Arc::new(throwaway_session());
        seed_legacy_pi_home(&session);

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let session = Arc::clone(&session);
                std::thread::spawn(move || session.migrate_legacy_pi_home())
            })
            .collect();
        for handle in handles {
            handle
                .join()
                .unwrap()
                .expect("every concurrent migration must converge");
        }
        assert_eq!(
            std::fs::read(session.state_dir.join("pi/agent/auth.json")).unwrap(),
            b"sentinel"
        );
        assert!(!session.guest_home_dir().join(".pi").exists());
        std::fs::remove_dir_all(&session.project_dir).ok();
    }

    /// Root-first upgrade rehearsal: migration runs in both modes, so a user
    /// who upgrades and launches `--root` first still has their old non-root
    /// state moved into the shared `<state>/pi`; a later non-root launch finds
    /// the same bytes and materializes the compiled link.
    #[test]
    fn migrate_legacy_pi_home_rehearses_a_root_first_upgrade() {
        let session = throwaway_session();
        seed_legacy_pi_home(&session);
        let links = guest_home::links(&[]);

        // First launch after the upgrade runs `--root`: no host-side guest
        // HOME provisioning happens, but the move must still occur.
        session
            .migrate_legacy_pi_home()
            .expect("root-first migration");
        session.ensure_dirs(&links).expect("ensure_dirs");
        assert_eq!(
            std::fs::read(session.state_dir.join("pi/agent/auth.json")).unwrap(),
            b"sentinel"
        );

        // A later non-root launch migrates nothing new and materializes the
        // compiled link over the same state.
        session
            .migrate_legacy_pi_home()
            .expect("no-op on the second mode");
        session.ensure_dirs(&links).expect("ensure_dirs");
        session.provision_guest_home(&links).expect("provision");
        assert_eq!(
            std::fs::read_link(session.guest_home_dir().join(".pi")).unwrap(),
            PathBuf::from("/agent-vm-state/pi")
        );
        assert_eq!(
            std::fs::read(session.state_dir.join("pi/agent/auth.json")).unwrap(),
            b"sentinel"
        );
        std::fs::remove_dir_all(&session.project_dir).ok();
    }

    fn throwaway_session() -> ProjectSession {
        // The PID and the clock alone are not unique: macOS's clock resolution
        // lets two parallel tests read the same nanosecond and collide on one
        // temp dir (the new #96 migration tests, run as a focused subset, hit
        // this). A process-wide counter makes the name unique regardless of
        // clock resolution.
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let unique = format!(
            "agent-vm-provision-test-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed),
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
    fn mount_store_is_a_private_sibling_of_project_state() {
        let session = throwaway_session();
        let store = session.mount_store_dir();
        assert_eq!(store, session.project_dir.join("deadbeef0000.mounts"));
        assert_eq!(store.parent(), session.state_dir.parent());
        assert!(!store.starts_with(&session.state_dir));

        let same_project = ProjectSession {
            project_dir: session.project_dir.clone(),
            project_hash: session.project_hash.clone(),
            state_dir: session.state_dir.clone(),
            sandbox_name: "other".into(),
        };
        assert_eq!(same_project.mount_store_dir(), store);
        let different_project = ProjectSession {
            project_dir: session.project_dir.clone(),
            project_hash: "otherhash000".into(),
            state_dir: session.project_dir.join("other-state"),
            sandbox_name: "other".into(),
        };
        assert_ne!(different_project.mount_store_dir(), store);
    }

    #[test]
    fn provision_guest_home_creates_dirs_and_dangling_symlinks() {
        let session = throwaway_session();
        session
            .provision_guest_home(&guest_home::links(&[]))
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
        session
            .provision_guest_home(&guest_home::links(&[]))
            .expect("first provision");
        // A stray real file where a symlink should go must not abort a
        // re-launch in the same project.
        std::fs::remove_file(session.guest_home_dir().join(".gitconfig")).ok();
        std::fs::write(session.guest_home_dir().join(".gitconfig"), "stray").unwrap();
        session
            .provision_guest_home(&guest_home::links(&[]))
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

    // ── V7: declared `persist` link provisioning ──────────────────

    const DECLARED_GUEST_TARGET: &str = "/agent-vm-state/persist/.aider.conf.yml";

    /// A session with a `persist/` target parent already created (what
    /// `ensure_dirs` does in production), plus the link path for the headline
    /// `.aider.conf.yml` entry.
    fn declared_persist_fixture() -> (ProjectSession, PathBuf, PathBuf) {
        let session = throwaway_session();
        let home = session.guest_home_dir();
        std::fs::create_dir_all(&home).unwrap();
        let target = session.state_dir.join("persist/.aider.conf.yml");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        let link = home.join(".aider.conf.yml");
        (session, link, target)
    }

    #[test]
    fn link_declared_persist_creates_a_dangling_link_when_absent() {
        let (session, link, target) = declared_persist_fixture();
        link_declared_persist(&target, DECLARED_GUEST_TARGET, &link).expect("create");
        assert_eq!(
            std::fs::read_link(&link).unwrap(),
            PathBuf::from(DECLARED_GUEST_TARGET)
        );
        // Dangling on the host: the guest creates the real file through it.
        assert!(!target.exists());
        std::fs::remove_dir_all(&session.project_dir).ok();
    }

    #[test]
    fn link_declared_persist_replaces_a_symlink_idempotently() {
        let (session, link, target) = declared_persist_fixture();
        link_declared_persist(&target, DECLARED_GUEST_TARGET, &link).expect("first");
        // A second launch (retarget) must not fail on `AlreadyExists`.
        link_declared_persist(&target, DECLARED_GUEST_TARGET, &link).expect("second");
        assert_eq!(
            std::fs::read_link(&link).unwrap(),
            PathBuf::from(DECLARED_GUEST_TARGET)
        );
        std::fs::remove_dir_all(&session.project_dir).ok();
    }

    #[test]
    fn link_declared_persist_migrates_a_real_file() {
        let (session, link, target) = declared_persist_fixture();
        std::fs::write(&link, "host content").unwrap();
        link_declared_persist(&target, DECLARED_GUEST_TARGET, &link).expect("migrate");
        // The content moved into the state dir (never deleted) and the link
        // now resolves host-side.
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "host content");
        assert_eq!(
            std::fs::read_link(&link).unwrap(),
            PathBuf::from(DECLARED_GUEST_TARGET)
        );
        std::fs::remove_dir_all(&session.project_dir).ok();
    }

    #[test]
    fn link_declared_persist_migrates_a_real_directory() {
        let (session, link, target) = declared_persist_fixture();
        std::fs::create_dir_all(link.join("nested")).unwrap();
        std::fs::write(link.join("nested/file"), "kept").unwrap();
        link_declared_persist(&target, DECLARED_GUEST_TARGET, &link).expect("migrate");
        assert_eq!(
            std::fs::read_to_string(target.join("nested/file")).unwrap(),
            "kept"
        );
        assert!(link.is_symlink());
        std::fs::remove_dir_all(&session.project_dir).ok();
    }

    #[test]
    fn link_declared_persist_errors_when_both_sides_hold_real_content() {
        let (session, link, target) = declared_persist_fixture();
        std::fs::write(&link, "home copy").unwrap();
        std::fs::write(&target, "state copy").unwrap();
        let err = link_declared_persist(&target, DECLARED_GUEST_TARGET, &link)
            .expect_err("two real copies is an ambiguity, not a migration");
        let message = err.to_string();
        assert!(message.contains(&link.display().to_string()), "{message}");
        assert!(message.contains(&target.display().to_string()), "{message}");
        // Neither side was touched.
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "home copy");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "state copy");
        std::fs::remove_dir_all(&session.project_dir).ok();
    }

    #[test]
    fn link_declared_persist_escapes_control_bytes_in_its_diagnostic() {
        // A `persist` entry may legally contain ESC/ANSI bytes (`normalize_persist`
        // rejects only empty/NUL/absolute/`..`), so the error must render them
        // escaped, exactly as `config`'s own diagnostics do — otherwise a
        // project config could drive the terminal.
        let session = throwaway_session();
        let home = session.guest_home_dir();
        std::fs::create_dir_all(&home).unwrap();
        let relative = ".aider\u{1b}[31m.conf.yml";
        let target = session.state_dir.join("persist").join(relative);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        let link = home.join(relative);
        std::fs::write(&link, "home copy").unwrap();
        std::fs::write(&target, "state copy").unwrap();

        let err = link_declared_persist(&target, "ignored", &link)
            .expect_err("two real copies is an ambiguity, not a migration");
        let message = err.to_string();
        assert!(
            !message.contains('\u{1b}'),
            "raw ESC reached the diagnostic: {message:?}"
        );
        assert!(
            message.contains("\\x1b"),
            "the byte was not escaped: {message:?}"
        );
        std::fs::remove_dir_all(&session.project_dir).ok();
    }

    #[test]
    fn provision_guest_home_refuses_a_symlinked_ancestor() {
        // `create_dir_all` follows symlinks in parent components, so a symlink
        // the in-guest agent planted in the persistent HOME (`~/.cache -> /etc`)
        // would redirect host-side provisioning outside the state dir. The walk
        // must refuse it rather than follow it.
        let session = throwaway_session();
        let home = session.guest_home_dir();
        std::fs::create_dir_all(&home).unwrap();
        let elsewhere = session.project_dir.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, home.join(".cache")).unwrap();

        let links = guest_home::links(&[crate::config::PersistPath::for_test(".cache/aider")]);
        let err = session
            .provision_guest_home(&links)
            .expect_err("a symlinked ancestor must be refused, not followed");
        assert!(
            err.to_string().contains("symlink"),
            "unexpected error: {err}"
        );
        // The symlink was not traversed: nothing was created under its target.
        assert!(
            std::fs::read_dir(&elsewhere).unwrap().next().is_none(),
            "provisioning followed the planted symlink"
        );
        std::fs::remove_dir_all(&session.project_dir).ok();
    }

    /// The launch scanner and the session's computed state path must agree on
    /// where project-scoped Pi state lives. `session.rs` owns the path
    /// (`state_dir` → the `pi/agent` tree); `pi_credential_inspection` derives
    /// the same files from `ProtectedFile`. This pins the agreement without
    /// adding a one-line forwarding method merely to touch the path.
    #[test]
    fn scanner_reads_the_session_state_dir_pi_home() {
        let session = throwaway_session();
        session
            .ensure_dirs(&guest_home::links(&[]))
            .expect("ensure_dirs");
        let pi_agent = session.state_dir.join("pi/agent");
        std::fs::create_dir_all(&pi_agent).unwrap();
        std::fs::write(
            pi_agent.join("auth.json"),
            br#"{"anthropic":{"type":"api_key","key":"guest-managed"}}"#,
        )
        .unwrap();

        let report = crate::pi_credential_inspection::inspect_project(&session.state_dir);
        let warning = report
            .launch_warning()
            .expect("a real credential must warn");
        assert!(
            warning.contains("auth.json: provider=anthropic type=api_key fields=key"),
            "{warning}"
        );
        std::fs::remove_dir_all(&session.project_dir).ok();
    }
}
