//! Create-or-replace a project's host-managed `config.toml` under
//! `$HOME/.config/agent-vm/projects/<64-hex-id>/` (#737 `image set-default`,
//! #739 `agent-vm config`).
//!
//! This module owns the *bytes-out* half of a project config write: a verified
//! route, a permanent coordination inode, a raw snapshot, a
//! compare-and-publish that refuses a base which is no longer live, and the pure
//! editor that computes the exact bytes of a root `image` edit from the snapshot's
//! bytes ([`plan_image_edit`]).
//!
//! # The root `image` is spliced, never re-serialised (ADR-0078 D4)
//!
//! [`plan_image_edit`] parses the current bytes **immutably** and copies
//! everything except one byte range: the value token of the root `image`, or a
//! single inserted assignment in the root prelude. A mutable document round trip was
//! measured and rejected: on the versions `Cargo.lock` pins,
//! `toml_edit::DocumentMut::to_string` normalises CRLF to LF, adds a missing final
//! newline and moves a leading comment below an inserted root key. Decoding the
//! old value and comparing parsed tables would therefore pass while the file was
//! rewritten, so the oracle is the exact output bytes and the planner reports which
//! range it touched instead of leaving a caller to infer it.
//!
//! # One permanent directory, stale saves refused (ADR-0078 D1)
//!
//! The coordination inode is `projects/<id>/config.lock`, never the `config.toml`
//! inode: #737 never replaces or renames a project directory, so a writer that
//! lost its base cannot "win" by publishing into whatever now occupies the name.
//! A **raw snapshot** ([`ProjectConfigStore::snapshot`]) is a read: it creates
//! nothing, and it carries the route identity (the directories that existed, the
//! opened `projects/` and store directories), the lock identity **if the store has
//! one**, and either the file's identity plus its bytes or **explicit absence**.
//! Absence is not "empty" and not "unreadable". The **locked** state is what a
//! publication carries: [`ProjectConfigStore::save`] is the one transition that may
//! bootstrap — our own absent store, its lock, or the first lock in a store that
//! already exists — and there the lock identity is required, because that is the
//! inode the compare-and-publish is actually serialized on.
//!
//! [`ConfigSave::Refused`] is the typed answer for a base that moved: a different
//! file identity, different bytes, absent→present, present→absent, or a displaced
//! directory or lock. Bootstrap is allowed in exactly two places, both of which are
//! the verified-creation walk: our own absent store (and its lock), and the first
//! lock in a store that already exists.
//!
//! # A descriptor set is not a route (ADR-0078 D1)
//!
//! A descriptor keeps naming the inode it was opened on after that name moves, so
//! verifying `projects/<id>/` *inside* a held `projects/` descriptor proves nothing
//! about whether `projects/` is still `agent-vm/projects`: replacing `projects/`
//! after the walk would leave every held relationship true inside a detached tree.
//! The walk therefore keeps all five descriptors, and a fence states every admitted
//! name again from the descriptor above it, at the under-lock check and immediately
//! before the rename. The same fence re-measures each descriptor's authority, and
//! the destination check re-applies the whole project-file boundary to the inode the
//! rename would replace, because a `chmod` changes no identity, link count or size.
//!
//! # One descriptor walk (ADR-0078 D2)
//!
//! [`ProjectConfigStore::existing_bytes`] and [`ProjectConfigStore::snapshot`]
//! share one walk: it opens `$HOME`, `.config`, `agent-vm`, `projects/` and
//! `projects/<id>/` step by step from the descriptor above, measures each one by
//! `fstat` on the descriptor it just opened, and classifies only a genuine absence
//! as missing. There is deliberately no path classifier followed by a second,
//! unbound walk: the directory that gets written into is the directory that was
//! measured, and [`ProjectConfigStore::save`] continues from the same walk.
//!
//! An `ENOENT` from a link-following open has two meanings, and only one of them is
//! a slot a save may create: the name is absent, or the name exists and only its
//! *target* is missing. The second is a dangling link and is refused, because the
//! `mkdirat` that would follow it fails `EEXIST` after acquisition instead of
//! creating the name.
//!
//! `.config` and `agent-vm` may be reached through a stable, user-owned dotfile
//! alias outside the active checkout — the canonical spelling must name the very
//! inode the descriptor holds, must not resolve inside the active project, and its
//! whole **ancestry** must pass the reader's own per-directory rule
//! ([`crate::project_config::ancestry_controlled`], walked
//! [`crate::project_config::uncontrolled_ancestor`]) — a safe leaf under a
//! replaceable parent is not a safe route. `projects/` and `projects/<id>/` are
//! opened `O_NOFOLLOW`: a symlinked store is how a route would redirect the write.
//! An `EEXIST` winner of a concurrent `mkdirat` is re-opened and verified, never
//! `chmod`ed; a directory this walk created is set to its exact mode through the
//! **parent** descriptor, before it is opened, so a umask that masks the owner's own
//! read or search bit is repaired rather than discovered after acquisition.
//!
//! "Inside the active project" is decided against the identity this command
//! **captured** ([`crate::project::ProjectDir::identity`]), not against a path a
//! replacement could have taken over: the captured root's own entry must still carry
//! the captured `(dev, ino)` ([`crate::project_config::captured_root_is_live`]).
//!
//! Traversal and authority are checked on every level; **mutation** permission only
//! on the deepest existing directory that must change. A `0500 projects/` with a
//! writable `projects/<id>/` therefore works, while the same parent with
//! `projects/<id>/` absent refuses before anything is created.
//!
//! # What atomicity is promised (ADR-0078 D6)
//!
//! The commit point is the descriptor-relative rename of a completely written
//! `0600` sibling temporary. An ordinary pre-publication error leaves `config.toml`
//! with its old bytes, identity, mode and mtime, or absent if it was absent. Not
//! promised: power-loss durability (`File::flush` is not `fsync`, and the pinned
//! `TempEntry` unlink is best-effort), or that the final check and the rename are
//! one syscall — a same-user in-place write landing between them is out of
//! contract.

// `image set-default` consumes the write path ([`ProjectConfigStore::existing_bytes`],
// [`ProjectConfigStore::snapshot`], [`ProjectConfigStore::save`] and
// [`plan_image_edit`]). The rest — the edit descriptions a caller reports from and
// the interleaving seams — is test-only and marked so where it is declared; there is
// no module-wide dead-code allowance, so a retired verb cannot hide here.

use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::ops::Range;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;

use crate::boot_image::ImageRef;
use crate::config_authority::{DirFacts, authority_dir_refusal, raw_mode_u32};
use crate::host_paths::{
    FileIdentity, FinalComponent, FlockWait, HostFileFacts, OpenNoFollowOutcome, OpenedDirFacts,
    OpenedLock, ReadBoundedError, atomic_write_at_with_prefix_and_pre_rename, current_euid,
    flock_exclusive_within, open_regular_no_follow_at_classified_checkpointed,
    open_verified_lock_at, open_verified_lock_if_present_at, opened_dir_facts,
};
use crate::one_line::quoted_path;
use crate::project::ProjectDir;
use crate::project_config::{CONFIG_FILE, CONFIG_LOCK_FILE, ProjectTierPaths, RouteAnchor};

/// How long a save waits for another agent-vm config writer. Long enough for a
/// peer's single-file publication, short enough that a stuck peer is a failed
/// command rather than a hung one.
const LOCK_WAIT: Duration = Duration::from_secs(5);

/// The temporary namespace a config replacement uses. The pin store writes
/// `.agent-vm-pin-tmp-*` in the same directory, so a stray temporary says which
/// store abandoned it.
const TEMP_PREFIX: &str = ".agent-vm-tmp-";

const DIR_MODE: Mode = Mode::RWXU;
const FILE_MODE: u32 = 0o600;

/// One `(home, project)` project config store: the writer's handle on the file
/// [`crate::config::ConfigPaths::discover`] reads.
///
/// Built from the same captured `$HOME` and [`crate::project::ProjectDir`] as the
/// read path ([`crate::project_config::path`] and the captured route anchor), so a
/// write cannot target a different store than the load measured.
pub(crate) struct ProjectConfigStore {
    route: ProjectTierPaths,
    /// The 64-hex store directory name, taken from the same capture that produced
    /// the path rather than parsed back out of it.
    project_id: OsString,
}

impl ProjectConfigStore {
    pub(crate) fn for_project(home: &Path, project: &ProjectDir) -> Self {
        Self {
            project_id: project.digest_hex().into(),
            route: ProjectTierPaths {
                config: crate::project_config::path(home, project),
                route: RouteAnchor::Captured {
                    home: home.to_path_buf(),
                    root: project.path().to_path_buf(),
                    root_id: project.identity(),
                },
            },
        }
    }

    pub(crate) fn config_path(&self) -> &Path {
        &self.route.config
    }

    /// Read-only: would there be bytes to compute a replacement from? Creates no
    /// directory, no lock and no file, so it runs before acquisition and says
    /// nothing about whether a later save may bootstrap.
    pub(crate) fn existing_bytes(&self) -> Result<Option<String>> {
        let walk = self.walk(WalkMode::Open, DIR_MODE, &Seams::default())?;
        let Some(store) = walk.store() else {
            return Ok(None);
        };
        // Read-only: an existing lock is verified with the same checks a save
        // applies, but this must never perform the first-lock bootstrap.
        let _verified_existing_lock = self.open_lock(store, false)?;
        Ok(self.read_config(store, &Seams::default())?.into_option())
    }

    /// Capture the raw state a replacement is computed from. **A read**: it creates
    /// no directory, no lock and no file.
    ///
    /// Nothing is locked here either: a lock is never held across image acquisition,
    /// an editor or user review (ADR-0078 D1). What this does record is the only two
    /// identities a publication is compared against — the route levels that existed
    /// and the lock, **if the store already has one** — and an explicit absence when
    /// the route or the file does not exist. Bootstrap belongs to the publication
    /// transition ([`Self::save`]), which is the one place a lock identity is
    /// required.
    pub(crate) fn snapshot(&self) -> Result<ConfigSnapshot> {
        self.snapshot_with(&Seams::default())
    }

    fn snapshot_with(&self, seams: &Seams<'_>) -> Result<ConfigSnapshot> {
        let walk = self.walk(WalkMode::Open, DIR_MODE, seams)?;
        let Some(store) = walk.store() else {
            return Ok(ConfigSnapshot {
                route: RouteIdentity {
                    levels: walk.levels.iter().map(DirLevel::identity).collect(),
                    lock: None,
                },
                file: ConfigFileState::Absent,
            });
        };
        let lock = self.open_lock(store, false)?;
        Ok(ConfigSnapshot {
            route: RouteIdentity {
                levels: walk.levels.iter().map(DirLevel::identity).collect(),
                lock: lock.as_ref().map(|lock| lock.identity),
            },
            file: self.read_config(store, seams)?,
        })
    }

    /// Publish `new_bytes` for the store `snapshot` observed.
    ///
    /// This is the verified publish transition, and therefore the one walk that may
    /// **create**: an absent store, its lock, or the first lock in a store that
    /// already exists. Everything it creates is created inside the same
    /// descriptor-bound walk that verified every level above it, and every level the
    /// snapshot measured must still name the same inode afterwards. From then on the
    /// lock identity is required: it takes the exclusive lock, re-reads under it, and
    /// publishes through it. Equal live bytes are [`ConfigSave::Unchanged`] — no
    /// temporary and no rename. Anything else outranks that comparison: a snapshot
    /// that no longer describes the live file is [`ConfigConflict::Stale`] even if
    /// the live bytes happen to be what we were about to write.
    pub(crate) fn save(&self, snapshot: &ConfigSnapshot, new_bytes: &[u8]) -> Result<ConfigSave> {
        self.save_with(snapshot, new_bytes, &Seams::default())
    }

    fn save_with(
        &self,
        snapshot: &ConfigSnapshot,
        new_bytes: &[u8],
        seams: &Seams<'_>,
    ) -> Result<ConfigSave> {
        let config = self.config_path();
        if new_bytes.len() as u64 > crate::config::MAX_CONFIG_FILE_BYTES {
            return Err(anyhow!(
                "config: {}: the replacement exceeds {} byte(s), which this store's readers refuse; nothing was written",
                quoted_path(config),
                crate::config::MAX_CONFIG_FILE_BYTES,
            ));
        }
        let euid = current_euid();
        // Two passes of the **same** walk, and only when the first one agrees with the
        // observation: a save may not recreate a store the read found and a peer then
        // removed, and it may not create anything at all before the route the read
        // measured is known to be live.
        let open = self.walk(WalkMode::Open, DIR_MODE, seams)?;
        if !snapshot.route.still_describes(&open) {
            return Ok(ConfigSave::Refused(ConfigConflict::Displaced));
        }
        let walk = if open.store().is_some() {
            open
        } else {
            // The read stopped above the store, so this is the bootstrap the publish
            // transition owns: the rest of the route, every level above it included, is
            // created by the same verified walk.
            let created = self.walk(
                WalkMode::Create,
                seams.create_mode.unwrap_or(DIR_MODE),
                seams,
            )?;
            if !snapshot.route.still_describes(&created) {
                return Ok(ConfigSave::Refused(ConfigConflict::Displaced));
            }
            created
        };
        let Some(store) = walk.store() else {
            return Err(anyhow!(
                "config: {}: the project store directory is missing after the walk created it",
                quoted_path(config),
            ));
        };
        // A snapshot that observed a lock may not create one: the lock it named is
        // the inode this publication must be serialized on.
        let lock = match snapshot.route.lock {
            Some(_) => self.open_lock(store, false)?,
            None => self.open_lock(store, true)?,
        };
        let Some(lock) = lock else {
            return Ok(ConfigSave::Refused(ConfigConflict::Displaced));
        };
        if snapshot
            .route
            .lock
            .is_some_and(|observed| observed != lock.identity)
        {
            return Ok(ConfigSave::Refused(ConfigConflict::Displaced));
        }
        let steps = route_steps(&self.project_id)?;
        let locked = LockedRoute {
            levels: walk.levels.iter().map(DirLevel::identity).collect(),
            lock: lock.identity,
        };
        if verify_anchored(&walk, &steps, &locked, euid).is_err() {
            return Ok(ConfigSave::Refused(ConfigConflict::Displaced));
        }
        let wait = seams.lock_wait.unwrap_or(LOCK_WAIT);
        match flock_exclusive_within(&lock.file, wait, |_| {}).map_err(|error| {
            error.context(format!(
                "config: {}: locking {CONFIG_LOCK_FILE} failed",
                quoted_path(config)
            ))
        })? {
            FlockWait::Acquired => {}
            FlockWait::TimedOut => {
                return Err(anyhow!(
                    "config: {}: timed out after {wait:?} waiting for another agent-vm config writer; nothing was written",
                    quoted_path(config),
                ));
            }
        }
        // Before the lock the descriptors only proved they had been opened from the
        // verified route; under it they must also still be the live names.
        if verify_anchored(&walk, &steps, &locked, euid).is_err() {
            return Ok(ConfigSave::Refused(ConfigConflict::Displaced));
        }
        if let Some(checkpoint) = seams.after_lock_before_read {
            checkpoint();
        }
        let live = self.read_config(store, seams)?;
        let stale = match (&snapshot.file, &live) {
            (ConfigFileState::Absent, ConfigFileState::Absent) => false,
            (
                ConfigFileState::Present { identity, bytes },
                ConfigFileState::Present {
                    identity: live_identity,
                    bytes: live_bytes,
                },
            ) => identity != live_identity || bytes != live_bytes,
            // Absent→present and present→absent are the same failure from the
            // snapshot's point of view: the file it described is not this file.
            _ => true,
        };
        if stale {
            return Ok(ConfigSave::Refused(ConfigConflict::Stale));
        }
        if let ConfigFileState::Present { bytes, .. } = &live
            && bytes.as_bytes() == new_bytes
        {
            return Ok(ConfigSave::Unchanged);
        }
        let veto: std::cell::Cell<Option<ConfigConflict>> = std::cell::Cell::new(None);
        let published = self.write_config(store, new_bytes, seams, || {
            if let Some(checkpoint) = seams.just_before_rename {
                checkpoint();
            }
            // The last check before the rename: the whole admitted chain, the lock
            // and the destination name are still what the under-lock read observed.
            // A failure here leaves the temporary for `TempEntry` to unlink and the
            // destination untouched.
            let parent = match verify_anchored(&walk, &steps, &locked, euid) {
                Ok(parent) => parent,
                Err(conflict) => {
                    veto.set(Some(conflict));
                    return Err(anyhow!(
                        "config: {}: {}",
                        quoted_path(config),
                        conflict.reason(),
                    ));
                }
            };
            match final_name_matches(parent, store, &live, config)? {
                true => Ok(()),
                false => {
                    veto.set(Some(ConfigConflict::Stale));
                    Err(anyhow!(
                        "config: {}: {}",
                        quoted_path(config),
                        ConfigConflict::Stale.reason(),
                    ))
                }
            }
        });
        match published {
            Ok(()) => Ok(match live {
                ConfigFileState::Absent => ConfigSave::Created,
                ConfigFileState::Present { .. } => ConfigSave::Replaced,
            }),
            // A conflict the final check observed is a typed answer, not an error:
            // #739 keeps the edited bytes and re-snapshots on it.
            Err(error) => match veto.get() {
                Some(conflict) => Ok(ConfigSave::Refused(conflict)),
                None => Err(error),
            },
        }
    }

    /// Publish the replacement through the one `host_paths` writer core.
    ///
    /// Under `#[cfg(test)]` a seam substitutes one failing step of that same
    /// algorithm, so the state a fault leaves behind is production's state.
    fn write_config(
        &self,
        store: &DirLevel,
        data: &[u8],
        seams: &Seams<'_>,
        before_rename: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let config = self.config_path();
        let name = OsStr::new(CONFIG_FILE);
        #[cfg(test)]
        if let Some(fault) = seams.write_fault {
            return crate::host_paths::atomic_write_at_with_prefix_and_fault(
                &store.fd,
                TEMP_PREFIX,
                name,
                data,
                FILE_MODE,
                config,
                fault,
            );
        }
        let _ = seams;
        atomic_write_at_with_prefix_and_pre_rename(
            &store.fd,
            TEMP_PREFIX,
            name,
            data,
            FILE_MODE,
            config,
            before_rename,
        )
    }

    /// Open the store's permanent coordination lock; `create` performs the
    /// first-lock bootstrap of an already-verified store.
    fn open_lock(&self, store: &DirLevel, create: bool) -> Result<Option<OpenedLock>> {
        let euid = current_euid();
        let name = OsStr::new(CONFIG_LOCK_FILE);
        let path = store.path.join(CONFIG_LOCK_FILE);
        // `flock(LOCK_EX)` needs no write access, so a read-only open is enough for
        // every use this writer makes of the lock — which is also exactly what the
        // read-only probe can check without creating one.
        if let Some(lock) = open_verified_lock_if_present_at(&store.fd, name, euid, &path)? {
            return Ok(Some(lock));
        }
        if !create {
            return Ok(None);
        }
        // Never a silent `chmod` of a peer's inode: a create that loses the race
        // opens the winner read-write and takes the branch above on the next call.
        open_verified_lock_at(&store.fd, name, euid, &path).map(Some)
    }

    /// Read `config.toml` through the verified store descriptor.
    ///
    /// Every branch is measured on the descriptor: the file's ownership, its
    /// writability and its bytes cannot describe one inode while the write
    /// replaces another.
    /// Stating the same size twice, on the descriptor the bytes came from, is what
    /// makes a bounded read a measured one: the read length must be the size the
    /// descriptor had when it was opened **and** the size it has now.
    fn read_config(&self, store: &DirLevel, seams: &Seams<'_>) -> Result<ConfigFileState> {
        let config = self.config_path();
        let opened = match open_regular_no_follow_at_classified_checkpointed(
            &store.fd,
            OsStr::new(CONFIG_FILE),
            config,
            || {},
            || {},
        )? {
            OpenNoFollowOutcome::File(opened) => opened,
            OpenNoFollowOutcome::Symlink => {
                return Err(crate::config::project_tier_error(
                    config,
                    &crate::config_authority::project_symlink_refusal(),
                ));
            }
            OpenNoFollowOutcome::NotRegular(kind) => {
                return Err(anyhow!(
                    "config: {}: the project config is not a regular file ({kind:?}); nothing was written",
                    quoted_path(config),
                ));
            }
            OpenNoFollowOutcome::NotFound => return Ok(ConfigFileState::Absent),
        };
        let facts = opened.facts();
        crate::config_authority::verify_project_file_at(
            store.dir_facts(),
            &FinalComponent::Regular(facts),
        )
        .map_err(|refusal| crate::config::project_tier_error(config, &refusal))?;
        if crate::config_authority::raw_mode_u32(facts.mode) & 0o200 == 0 {
            // A rename into the directory would succeed over it, which is exactly
            // why this is refused: the user's own bytes stay where they are.
            return Err(anyhow!(
                "config: {}: the project config is read-only; make it writable (chmod u+w) before running image set-default",
                quoted_path(config),
            ));
        }
        let identity = facts.identity();
        if let Some(checkpoint) = seams.read_config_after_measure {
            checkpoint();
        }
        let measured_size = facts.size;
        let (bytes, size_now) =
            match opened.read_bounded_measured(crate::config::MAX_CONFIG_FILE_BYTES) {
                Ok(measured) => measured,
                Err(ReadBoundedError::TooLarge) => {
                    return Err(anyhow!(
                        "config: {}: the project config exceeds {} byte(s); refusing to read it",
                        quoted_path(config),
                        crate::config::MAX_CONFIG_FILE_BYTES,
                    ));
                }
                Err(ReadBoundedError::Io(error)) => return Err(error),
            };
        // Growth below the reader's ceiling is still a file this writer did not
        // measure, so the read length must agree with the size the descriptor had when
        // it was opened **and** with its size now. The refusal is fixed text: the
        // numbers are this file's own bytes.
        if size_now != Some(measured_size) || bytes.len() as u64 != measured_size {
            return Err(anyhow!(
                "config: {}: {CHANGED_WHILE_READ}",
                quoted_path(config),
            ));
        }
        let bytes = String::from_utf8(bytes).map_err(|_| {
            anyhow!(
                "config: {}: the project config is not valid UTF-8; nothing was written",
                quoted_path(config),
            )
        })?;
        Ok(ConfigFileState::Present { identity, bytes })
    }

    /// The one descriptor walk, serving the read-only probe and the
    /// create-if-missing snapshot.
    fn walk(&self, mode: WalkMode, create_mode: Mode, seams: &Seams<'_>) -> Result<RouteWalk> {
        let (home, root, root_id) = self.anchor()?;
        let config = self.config_path();
        let euid = current_euid();
        // The canonical spelling of `$HOME` anchors everything below it: every level
        // is opened relative to the descriptor above, and every alias answer is
        // stated in this spelling, so an answer cannot describe a different
        // directory than the one the write uses.
        let base = std::fs::canonicalize(home).map_err(|error| {
            anyhow!(
                "config: {}: resolving $HOME failed ({})",
                quoted_path(config),
                error.kind()
            )
        })?;
        let home_fd = rustix::fs::open(
            &base,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| anyhow!(error))
        .with_context(|| format!("config: {}: opening $HOME", quoted_path(config)))?;
        let home_level = level_with_facts(Level::Home, home_fd, base, config)?;
        verify_level(&home_level, root, root_id, euid, config)?;
        let mut walk = RouteWalk {
            levels: vec![home_level],
        };
        for step in route_steps(&self.project_id)? {
            let path = walk.deepest().path.join(&step.name);
            match open_child(walk.deepest(), &step, config)? {
                Some(fd) => {
                    let level = level_with_facts(step.level, fd, path, config)?;
                    if let Some(swap) = seams.after_open_level {
                        swap(&level.path);
                    }
                    verify_level(&level, root, root_id, euid, config)?;
                    walk.levels.push(level);
                }
                None => {
                    // The deepest existing directory is the one a save would change,
                    // even when what it changes is only a child directory. Checked in
                    // both modes, so a refusal a save would hit is reported by the
                    // read before acquisition instead of being discovered after it.
                    require_owner_write(walk.deepest(), config)?;
                    if mode == WalkMode::Open {
                        return Ok(walk);
                    }
                    let level =
                        create_child(walk.deepest(), &step, &path, create_mode, seams, config)?;
                    verify_level(&level, root, root_id, euid, config)?;
                    walk.levels.push(level);
                }
            }
        }
        // Everything exists: replacing `config.toml` changes the store directory.
        require_owner_write(walk.deepest(), config)?;
        Ok(walk)
    }

    fn anchor(&self) -> Result<(&Path, &Path, FileIdentity)> {
        match &self.route.route {
            RouteAnchor::Captured {
                home,
                root,
                root_id,
            } => Ok((home, root, *root_id)),
            RouteAnchor::Uncaptured => Err(anyhow!(
                "config: {}: the project config writer needs the captured $HOME and project root, and this tier has neither",
                quoted_path(self.config_path()),
            )),
        }
    }
}

/// The fixed reason a project config that changed under its reader gives.
const CHANGED_WHILE_READ: &str = "the project config changed while it was being read, so nothing was written; read it again and repeat";

/// What a read-only observation found, as the state a save replaces or creates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConfigSnapshot {
    route: RouteIdentity,
    file: ConfigFileState,
}

impl ConfigSnapshot {
    /// The identity of the coordination lock this observation found, if the store
    /// already had one. `None` is a store whose first lock the save will create.
    #[cfg_attr(not(test), allow(dead_code))] // read by the writer's own tests
    pub(crate) fn lock_identity(&self) -> Option<FileIdentity> {
        self.route.lock
    }

    /// The bytes a replacement must be computed from, or `None` when the file does
    /// not exist yet (a save then creates it).
    pub(crate) fn bytes(&self) -> Option<&str> {
        match &self.file {
            ConfigFileState::Absent => None,
            ConfigFileState::Present { bytes, .. } => Some(bytes),
        }
    }
}

/// What a save did to `config.toml`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConfigSave {
    /// The file was absent and now holds the new bytes.
    Created,
    /// The file was replaced by a descriptor-relative rename of a `0600` temporary.
    Replaced,
    /// The live bytes already equalled the new bytes: no temporary, no rename. Reached
    /// only after the snapshot was found still live under the lock.
    Unchanged,
    /// Nothing was written, and the base is no longer live.
    Refused(ConfigConflict),
}

/// The two ways a base can stop being live, as values rather than messages: a
/// caller that must keep its edited bytes and re-snapshot has to branch on them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConfigConflict {
    /// The bytes, identity or authority of `config.toml` changed after the snapshot,
    /// in either direction (absent→present, present→absent, different inode,
    /// different bytes, no longer the file D8 trusts), or it changed between the
    /// under-lock read and the rename.
    Stale,
    /// An admitted directory of the route, or `config.lock`, is no longer the inode
    /// the snapshot measured, or an admitted directory left the authority the walk
    /// requires.
    Displaced,
}

impl ConfigConflict {
    /// The fixed one-line reason, ready for a caller's `config: <path>: ` prefix.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::Stale => {
                "the project config changed after it was read, so nothing was written; read it again and repeat"
            }
            Self::Displaced => {
                "the project config store or its config.lock changed after it was read, so nothing was written"
            }
        }
    }
}

/// The directory identities one **observation** is bound to.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RouteIdentity {
    /// One identity per directory the read admitted, in walk order from `$HOME`
    /// down to the deepest directory that existed. Kept per level rather than as
    /// the store alone, because a descriptor keeps naming the inode it was opened
    /// on after that name moves: only stating every name again from the descriptor
    /// above it can tell a detached tree from the live one.
    levels: Vec<FileIdentity>,
    /// The coordination inode **if the store had one** when this was observed. A
    /// read creates nothing, so a first save of an existing store legitimately
    /// observes no lock; the publication transition is where one is created, and
    /// [`LockedRoute`] is where it becomes required.
    lock: Option<FileIdentity>,
}

impl RouteIdentity {
    /// Does `walk` still contain the route this observation measured, name by name?
    ///
    /// A read may stop above the store (the store or one of its parents did not
    /// exist); the save continues from the same walk and may create the levels the
    /// read did not find. An observation is therefore live exactly when every level
    /// it measured is the level the walk opened at the same depth — a level that was
    /// replaced, or an ancestor that moved, is a displaced base.
    fn still_describes(&self, walk: &RouteWalk) -> bool {
        self.levels.len() <= walk.levels.len()
            && self
                .levels
                .iter()
                .zip(&walk.levels)
                .all(|(expected, level)| level.identity() == *expected)
    }
}

/// The route a **publication** is bound to, once the lock identity is known.
///
/// Separate from [`RouteIdentity`] rather than an `Option` inside it: a save that
/// created the lock must state it, and one that found a lock must be serialized on
/// that inode, so there is no publication state without one.
#[derive(Clone, Debug, PartialEq, Eq)]
struct LockedRoute {
    levels: Vec<FileIdentity>,
    lock: FileIdentity,
}

/// The raw state of `config.toml` as read through the verified store descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ConfigFileState {
    /// The name does not exist in the store directory. Not "empty": an empty
    /// existing file is [`ConfigFileState::Present`] with no bytes.
    Absent,
    Present {
        identity: FileIdentity,
        bytes: String,
    },
}

impl ConfigFileState {
    /// The bytes, or `None` for explicit absence.
    fn into_option(self) -> Option<String> {
        match self {
            Self::Absent => None,
            Self::Present { bytes, .. } => Some(bytes),
        }
    }
}

/// Whether a walk may create the directories it finds missing.
#[derive(Clone, Copy, PartialEq, Eq)]
enum WalkMode {
    /// Never create: report the route as far as it exists.
    Open,
    /// Create every missing directory `0700` and verify each one.
    Create,
}

/// Each directory the store route descends through, so a refusal can name the
/// level that failed instead of only the file it was reached for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Level {
    Home,
    Config,
    AgentVm,
    Projects,
    Store,
}

impl Level {
    fn label(self) -> &'static str {
        match self {
            Self::Home => "$HOME",
            Self::Config => "the .config directory",
            Self::AgentVm => "the agent-vm config directory",
            Self::Projects => "the projects directory",
            Self::Store => "the project store directory",
        }
    }
}

/// One step of the fixed route: the name inside the parent, the level it is, and
/// whether a link at that name may be followed.
struct RouteStep {
    level: Level,
    name: OsString,
    no_follow: bool,
}

impl RouteStep {
    /// How this name is stated from the descriptor above it: a link is followed
    /// exactly where the walk was allowed to follow one.
    fn at_flags(&self) -> AtFlags {
        if self.no_follow {
            AtFlags::SYMLINK_NOFOLLOW
        } else {
            AtFlags::empty()
        }
    }
}

/// The names between the canonical `$HOME` and the store, derived from the same
/// constants [`crate::project_config::path`] joins, so the walk cannot visit a
/// different route than the file it writes.
fn route_steps(project_id: &OsStr) -> Result<Vec<RouteStep>> {
    let user_config: Vec<OsString> = Path::new(crate::config::USER_CONFIG_DIR_RELATIVE)
        .components()
        .map(|component| component.as_os_str().to_os_string())
        .collect();
    let [config, agent_vm] = user_config.as_slice() else {
        return Err(anyhow!(
            "config: USER_CONFIG_DIR_RELATIVE is not two components, so the project config store route cannot be walked"
        ));
    };
    Ok(vec![
        // ADR-0040's dotfile compatibility: these two may be links, and the alias
        // answer is stated below.
        RouteStep {
            level: Level::Config,
            name: config.clone(),
            no_follow: false,
        },
        RouteStep {
            level: Level::AgentVm,
            name: agent_vm.clone(),
            no_follow: false,
        },
        // ADR-0073: a symlinked store is how a route would redirect the write.
        RouteStep {
            level: Level::Projects,
            name: OsString::from(crate::project_config::PROJECTS_DIR),
            no_follow: true,
        },
        RouteStep {
            level: Level::Store,
            name: project_id.to_os_string(),
            no_follow: true,
        },
    ])
}

/// One route directory: the descriptor this walk opened and `fstat` measured.
struct DirLevel {
    level: Level,
    fd: OwnedFd,
    path: PathBuf,
    facts: OpenedDirFacts,
}

impl DirLevel {
    fn identity(&self) -> FileIdentity {
        FileIdentity {
            dev: self.facts.dev,
            ino: self.facts.ino,
        }
    }

    fn dir_facts(&self) -> DirFacts {
        dir_authority(&self.facts)
    }
}

/// The route as far as it exists, outermost first.
struct RouteWalk {
    levels: Vec<DirLevel>,
}

impl RouteWalk {
    fn deepest(&self) -> &DirLevel {
        self.levels
            .last()
            .expect("the walk always opens $HOME first")
    }

    fn store(&self) -> Option<&DirLevel> {
        self.levels.iter().find(|level| level.level == Level::Store)
    }
}

/// Open one route name inside the descriptor of the directory above it.
///
/// `Ok(None)` is a genuine absence: the name does not exist in this directory. A
/// link where links are not followed (`ELOOP`) and a name that is not a directory
/// (`ENOTDIR`) are refusals, so a route that exists but is the wrong shape can never
/// be read as missing and created over. An `ENOENT` from a link-following open is
/// classified rather than trusted: it means the name is absent **or** that the name
/// exists and only its target is missing, and only the first is a slot a save may
/// create.
fn open_child(parent: &DirLevel, step: &RouteStep, config: &Path) -> Result<Option<OwnedFd>> {
    let mut flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
    if step.no_follow {
        flags |= OFlags::NOFOLLOW;
    }
    match rustix::fs::openat(&parent.fd, &step.name, flags, Mode::empty()) {
        Ok(fd) => Ok(Some(fd)),
        Err(Errno::NOENT) => classify_missing_child(parent, step, config),
        Err(Errno::LOOP) | Err(Errno::NOTDIR) => Err(refuse_child(parent, step, config)),
        Err(error) => Err(anyhow!(error)).with_context(|| {
            format!(
                "config: {}: opening {} at {}",
                quoted_path(config),
                step.level.label(),
                quoted_path(&parent.path.join(&step.name))
            )
        }),
    }
}

/// Decide what an `ENOENT` from [`open_child`] means, by a no-follow `stat` of the
/// name itself.
///
/// An absent name is the only answer a save may create. A name that exists is a
/// route that cannot be descended — a *dangling* link at `.config` or `agent-vm`
/// resolves to nothing, so the open reports the target's absence while `mkdirat` on
/// the name would report `EEXIST` after acquisition — and the refusal says which of
/// the two shapes it is.
fn classify_missing_child(
    parent: &DirLevel,
    step: &RouteStep,
    config: &Path,
) -> Result<Option<OwnedFd>> {
    let path = parent.path.join(&step.name);
    match rustix::fs::statat(&parent.fd, &step.name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(Errno::NOENT) => Ok(None),
        Ok(entry) => {
            let refusal = if FileType::from_raw_mode(entry.st_mode) == FileType::Symlink {
                format!(
                    "config: {}: the project config store refuses {} reached through a symbolic link whose target does not exist",
                    quoted_path(config),
                    step.level.label(),
                )
            } else {
                format!(
                    "config: {}: {} is not a directory, so the project config cannot be created inside it",
                    quoted_path(config),
                    quoted_path(&path),
                )
            };
            Err(anyhow!(refusal))
        }
        Err(error) => Err(anyhow!(error)).with_context(|| {
            format!(
                "config: {}: stating {} at {}",
                quoted_path(config),
                step.level.label(),
                quoted_path(&path)
            )
        }),
    }
}

/// Classify a route name that cannot be descended.
///
/// `openat` reports a link where links are not followed as `ELOOP` on Linux and as
/// `ENOTDIR` on macOS, so the sentence is decided by a no-follow `stat` of the name
/// rather than by the errno: a link says it is a link, and anything else says it is
/// not a directory.
fn refuse_child(parent: &DirLevel, step: &RouteStep, config: &Path) -> anyhow::Error {
    let is_link = matches!(
        rustix::fs::statat(&parent.fd, &step.name, AtFlags::SYMLINK_NOFOLLOW),
        Ok(entry) if FileType::from_raw_mode(entry.st_mode) == FileType::Symlink
    );
    if is_link {
        anyhow!(
            "config: {}: the project config store refuses {} reached through a symbolic link",
            quoted_path(config),
            step.level.label(),
        )
    } else {
        anyhow!(
            "config: {}: {} is not a directory, so the project config cannot be created inside it",
            quoted_path(config),
            step.level.label(),
        )
    }
}

/// Create one missing route directory `DIR_MODE` inside a verified parent.
fn create_child(
    parent: &DirLevel,
    step: &RouteStep,
    path: &Path,
    create_mode: Mode,
    seams: &Seams<'_>,
    config: &Path,
) -> Result<DirLevel> {
    if let Some(peer) = seams.just_before_create {
        peer(path);
    }
    match rustix::fs::mkdirat(&parent.fd, &step.name, create_mode) {
        Ok(()) => {}
        Err(Errno::EXIST) => {
            // A peer created it while this walk was deciding. Re-open and verify the
            // winner; never `chmod` a directory this walk did not create.
            let fd = open_child(parent, step, config)?.ok_or_else(|| {
                anyhow!(
                    "config: {}: {} disappeared after a peer created it",
                    quoted_path(config),
                    quoted_path(path),
                )
            })?;
            return level_with_facts(step.level, fd, path.to_path_buf(), config);
        }
        Err(error) => {
            return Err(anyhow!(error)).with_context(|| {
                format!(
                    "config: {}: creating {}",
                    quoted_path(config),
                    quoted_path(path)
                )
            });
        }
    }
    // A masking umask can create the entry without the owner's own read or search
    // bit, which would make the very next `openat` fail — after acquisition, and
    // with the directory already on disk. It is repaired here, on the **name**,
    // through the parent descriptor this walk holds and in a directory this walk has
    // already verified it exclusively owns: `chmod` needs ownership, not access to
    // the entry it changes. Nothing later compensates, and the descriptor's own mode
    // is re-applied once it can be opened.
    rustix::fs::chmodat(&parent.fd, &step.name, DIR_MODE, AtFlags::empty())
        .map_err(|error| anyhow!(error))
        .with_context(|| {
            format!(
                "config: {}: making {} owner-only failed",
                quoted_path(config),
                quoted_path(path)
            )
        })?;
    let fd = open_child(parent, step, config)?.ok_or_else(|| {
        anyhow!(
            "config: {}: {} disappeared after it was created",
            quoted_path(config),
            quoted_path(path),
        )
    })?;
    rustix::fs::fchmod(&fd, DIR_MODE)
        .map_err(|error| anyhow!(error))
        .with_context(|| {
            format!(
                "config: {}: making {} owner-only failed",
                quoted_path(config),
                quoted_path(path)
            )
        })?;
    let level = level_with_facts(step.level, fd, path.to_path_buf(), config)?;
    // Only a directory this walk created may be judged by its exact mode; a peer's
    // winner was verified as it is, in the branch above.
    require_created_mode(&level, config)?;
    Ok(level)
}

fn level_with_facts(level: Level, fd: OwnedFd, path: PathBuf, config: &Path) -> Result<DirLevel> {
    let facts = opened_dir_facts(&fd, &quoted_path(&path)).with_context(|| {
        format!(
            "config: {}: measuring {}",
            quoted_path(config),
            quoted_path(&path)
        )
    })?;
    Ok(DirLevel {
        level,
        fd,
        path,
        facts,
    })
}

/// Verify one opened directory: this user exclusively owns it, it is searchable by
/// its owner, the active project is still the capture this command measured, its
/// canonical spelling names the inode the descriptor holds, that spelling does not
/// land inside the active project, and — when the level was reached through a link —
/// its whole ancestry passes the reader's own rule.
///
/// The identity tie is what makes the alias answer trustworthy: it is computed from
/// a canonical path, and a canonical path that does not name this descriptor could
/// describe a directory this walk will never write into. The ancestry pass is what
/// makes an **admitted** alias trustworthy: a leaf inside a directory another user
/// may rename is a route, not a destination.
fn verify_level(
    level: &DirLevel,
    root: &Path,
    root_id: FileIdentity,
    euid: u32,
    config: &Path,
) -> Result<()> {
    if let Some(refusal) = authority_dir_refusal(level.dir_facts(), euid) {
        return Err(anyhow!(
            "config: {}: the project config refuses {} that {}; make it owned by you and not group- or other-writable",
            quoted_path(config),
            level.level.label(),
            crate::allowances::refusal_clause(&refusal),
        ));
    }
    if level.facts.mode & 0o100 == 0 {
        return Err(anyhow!(
            "config: {}: {} has no owner search permission, so nothing inside it can be opened",
            quoted_path(config),
            level.level.label(),
        ));
    }
    // "Inside the active project" is a statement about a directory, and the project
    // this command captured is one identity, not a spelling: a root replaced after
    // the capture makes every route answer below it describe a directory nothing
    // measured.
    if !crate::project_config::captured_root_is_live(root, root_id) {
        return Err(anyhow!(
            "config: {}: the active project is no longer the directory this command captured, so the project config route cannot be checked; start agent-vm again from the project",
            quoted_path(config),
        ));
    }
    let canonical = std::fs::canonicalize(&level.path).map_err(|error| {
        anyhow!(
            "config: {}: resolving {} failed ({})",
            quoted_path(config),
            level.level.label(),
            error.kind(),
        )
    })?;
    let measured = std::fs::metadata(&canonical).map_err(|error| {
        anyhow!(
            "config: {}: measuring {} failed ({})",
            quoted_path(config),
            level.level.label(),
            error.kind(),
        )
    })?;
    if (measured.dev(), measured.ino()) != level.facts.identity() {
        return Err(anyhow!(
            "config: {}: {} changed while it was being opened, so the project config cannot be written through it",
            quoted_path(config),
            level.level.label(),
        ));
    }
    if crate::project_config::resolves_inside_project(&canonical, Some(&level.path), root) {
        return Err(anyhow!(
            "config: {}: the project config refuses {} that resolves inside the active project",
            quoted_path(config),
            level.level.label(),
        ));
    }
    if canonical != level.path {
        // A link was followed to reach this level, so the level's own descriptor is
        // only half the answer: the directory it lives in is a name another process
        // may replace, and the reader refuses exactly that (`ancestry_controlled`).
        let ancestor = crate::project_config::uncontrolled_ancestor(&canonical, euid).map_err(
            |error| {
                anyhow!(
                    "config: {}: the project config refuses {} reached through a symbolic link whose ancestry cannot be verified ({error:#})",
                    quoted_path(config),
                    level.level.label(),
                )
            },
        )?;
        if let Some(ancestor) = ancestor {
            return Err(anyhow!(
                "config: {}: the project config refuses {} reached through a symbolic link inside {}, which is not a directory this user controls exclusively",
                quoted_path(config),
                level.level.label(),
                quoted_path(&ancestor),
            ));
        }
    }
    Ok(())
}

/// Owner write and search: the deepest existing directory a save must change needs
/// both, and directories it only passes through need neither.
fn require_owner_write(level: &DirLevel, config: &Path) -> Result<()> {
    if level.facts.mode & 0o300 != 0o300 {
        return Err(anyhow!(
            "config: {}: {} is not writable by its owner, so the project config cannot be created or replaced there",
            quoted_path(config),
            level.level.label(),
        ));
    }
    Ok(())
}

/// A directory this walk created is exactly `0700`: no group or other access at
/// all, whatever the process umask asked for.
fn require_created_mode(level: &DirLevel, config: &Path) -> Result<()> {
    let want = raw_mode_u32(DIR_MODE.bits());
    if level.facts.mode & 0o7777 != want {
        return Err(anyhow!(
            "config: {}: the {} this write created has mode {:o}, not {want:o}; nothing was written",
            quoted_path(config),
            level.level.label(),
            level.facts.mode & 0o7777,
        ));
    }
    Ok(())
}

/// Does this walk still name the live chain the snapshot measured?
///
/// Descriptors alone cannot answer that: they keep naming the inode they were
/// opened on even after that name moved, so a store replaced after the walk still
/// looks like the store. One walk-shaped pass therefore states **every** admitted
/// name again from the descriptor above it — `projects/` and `projects/<id>/` are
/// then as falsifiable as `.config` and `agent-vm` — and re-measures every
/// descriptor, because a `chmod` changes authority without changing identity. The
/// deepest level is the one publication changes, so its owner-write permission is
/// part of the same pass, and its authority is returned for the destination check
/// that needs a parent.
fn verify_anchored(
    walk: &RouteWalk,
    steps: &[RouteStep],
    expected: &LockedRoute,
    euid: u32,
) -> Result<DirFacts, ConfigConflict> {
    if walk.levels.len() != expected.levels.len() || steps.len() + 1 != walk.levels.len() {
        return Err(ConfigConflict::Displaced);
    }
    let mut deepest = None;
    for (index, level) in walk.levels.iter().enumerate() {
        let current = current_dir_facts(level)?;
        let identity = FileIdentity {
            dev: current.dev,
            ino: current.ino,
        };
        if identity != expected.levels[index]
            || authority_dir_refusal(dir_authority(&current), euid).is_some()
            || current.mode & 0o100 == 0
        {
            return Err(ConfigConflict::Displaced);
        }
        if index == 0 {
            // `$HOME` is the anchor of the walk: it has no admitted parent.
            continue;
        }
        let step = &steps[index - 1];
        let entry = rustix::fs::statat(&walk.levels[index - 1].fd, &step.name, step.at_flags())
            .map_err(|_| ConfigConflict::Displaced)?;
        if FileType::from_raw_mode(entry.st_mode) != FileType::Directory
            || entry_identity(&entry) != identity
        {
            return Err(ConfigConflict::Displaced);
        }
        if index + 1 == walk.levels.len() && current.mode & 0o300 != 0o300 {
            return Err(ConfigConflict::Displaced);
        }
        deepest = Some(dir_authority(&current));
    }
    let store = walk.deepest();
    let lock = rustix::fs::statat(
        &store.fd,
        OsStr::new(CONFIG_LOCK_FILE),
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|_| ConfigConflict::Displaced)?;
    if FileType::from_raw_mode(lock.st_mode) != FileType::RegularFile
        || entry_identity(&lock) != expected.lock
        || lock.st_uid != euid
        || crate::config_authority::raw_mode_u32(lock.st_mode) & 0o022 != 0
        || entry_nlink(&lock) != 1
    {
        return Err(ConfigConflict::Displaced);
    }
    deepest.ok_or(ConfigConflict::Displaced)
}

/// The facts of an already-open route directory as they are **now**.
///
/// [`DirLevel::facts`] is what the walk measured at open time; authority can change
/// without identity changing, so a fence re-measures instead of trusting it.
fn current_dir_facts(level: &DirLevel) -> Result<OpenedDirFacts, ConfigConflict> {
    opened_dir_facts(&level.fd, &quoted_path(&level.path)).map_err(|_| ConfigConflict::Displaced)
}

fn dir_authority(facts: &OpenedDirFacts) -> DirFacts {
    DirFacts {
        is_dir: true,
        uid: facts.uid,
        mode: facts.mode,
    }
}

/// Whether the destination name is still the state the under-lock read observed,
/// checked immediately before the rename.
///
/// The bytes are not re-read here because the under-lock read already compared
/// them. Everything else the boundary is made of is re-measured on what the rename
/// would replace, and `parent` is the authority of the directory it publishes
/// through, measured by the fence immediately before this call: type, identity,
/// link count, size, current owner, current mode and the owner-write the read
/// requires. A same-inode in-place write of the same length that lands between these
/// syscalls is out of contract (ADR-0078 D1).
fn final_name_matches(
    parent: DirFacts,
    store: &DirLevel,
    live: &ConfigFileState,
    config: &Path,
) -> Result<bool> {
    match rustix::fs::statat(
        &store.fd,
        OsStr::new(CONFIG_FILE),
        AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Ok(entry) => Ok(match live {
            ConfigFileState::Absent => false,
            ConfigFileState::Present { identity, bytes } => {
                destination_within_boundary(parent, &entry, *identity, bytes.len())
            }
        }),
        Err(Errno::NOENT) => Ok(matches!(live, ConfigFileState::Absent)),
        Err(error) => Err(anyhow!(error)).with_context(|| {
            format!(
                "config: {}: stating {CONFIG_FILE} failed",
                quoted_path(config)
            )
        }),
    }
}

/// Is the inode the rename would replace still inside ADR-0078 D8's boundary?
///
/// The same [`crate::config_authority::verify_project_file_at`] kernel the
/// under-lock read used answers owner, group/other-writable and the one-name rule
/// for this measurement, so a file that left the boundary is refused with the text
/// that kernel already owns. Identity and size come from the read; `0400` is refused
/// even though a rename over it would succeed, exactly as it is on the read.
fn destination_within_boundary(
    parent: DirFacts,
    entry: &rustix::fs::Stat,
    identity: FileIdentity,
    len: usize,
) -> bool {
    if FileType::from_raw_mode(entry.st_mode) != FileType::RegularFile {
        return false;
    }
    let facts = entry_facts(entry);
    if crate::config_authority::verify_project_file_at(parent, &FinalComponent::Regular(facts))
        .is_err()
    {
        return false;
    }
    facts.identity() == identity
        && facts.size == len as u64
        && crate::config_authority::raw_mode_u32(facts.mode) & 0o200 != 0
}

/// The [`HostFileFacts`] of a `statat` result, so the shared authority kernel can
/// judge the entry the rename would replace.
fn entry_facts(stat: &rustix::fs::Stat) -> HostFileFacts {
    HostFileFacts {
        uid: stat.st_uid,
        mode: stat.st_mode,
        size: stat.st_size.max(0) as u64,
        nlink: entry_nlink(stat),
        dev: entry_identity(stat).dev,
        ino: stat.st_ino,
    }
}

#[allow(clippy::useless_conversion)] // `st_dev` is narrower on macOS than on Linux
fn entry_identity(stat: &rustix::fs::Stat) -> FileIdentity {
    FileIdentity {
        dev: u64::try_from(stat.st_dev).unwrap_or(0),
        ino: stat.st_ino,
    }
}

// `nlink_t` is u16 on macOS, u32 on Linux aarch64 and u64 on Linux x86_64.
#[allow(clippy::useless_conversion)]
fn entry_nlink(stat: &rustix::fs::Stat) -> u64 {
    u64::from(stat.st_nlink)
}

/// The interleavings a test must be able to stage, because the process cannot be
/// paused inside the transaction. Production passes [`Seams::default`], whose
/// every field is `None`.
#[derive(Default)]
struct Seams<'a> {
    /// Runs while the exclusive lock is held and before the under-lock read.
    after_lock_before_read: Option<&'a dyn Fn()>,
    /// Runs after the temporary is written and before the final verification.
    just_before_rename: Option<&'a dyn Fn()>,
    /// The mode the walk asks for when it creates a directory, so a masking umask's
    /// outcome can be staged without changing the process umask (which cannot be
    /// done inside the test binary without racing parallel tests).
    create_mode: Option<Mode>,
    /// The lock budget, so a contention test need not wait the production budget.
    lock_wait: Option<Duration>,
    /// Runs immediately before a directory is created, so a test can stage the peer
    /// that wins the `mkdirat` race.
    just_before_create: Option<&'a dyn Fn(&Path)>,
    /// Runs after a route directory is opened and before it is verified, so a test
    /// can stage a directory replaced between the two measurements.
    after_open_level: Option<&'a dyn Fn(&Path)>,
    /// Runs after the project config's descriptor was measured and before its bytes
    /// are read, so a test can stage a file that grows under the reader.
    read_config_after_measure: Option<&'a dyn Fn()>,
    /// Replaces a publication step with one that fails at a fixed point.
    #[cfg(test)]
    write_fault: Option<crate::host_paths::WriteFault>,
}

// ---------------------------------------------------------------------------
// The pure editor: exact bytes for the root `image`, or a typed refusal
// ---------------------------------------------------------------------------

/// The exact bytes of setting a project config's root `image`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ImageEditPlan {
    /// `config.toml` was absent: the seed bytes for a new project config.
    Create { bytes: Vec<u8> },
    /// The file existed, and `edit` says which byte range of it the plan touched.
    Update { bytes: Vec<u8>, edit: ImageEdit },
    /// The root `image` already decodes to exactly this reference, so no new bytes
    /// are planned: a rename would replace the file, its inode and its mtime to
    /// store the bytes it already holds. This is a statement about the bytes only —
    /// a caller must still compare-and-publish the snapshot it planned from, and only
    /// that publication may report the no-op as `Unchanged`.
    Unchanged,
}

impl ImageEditPlan {
    /// The bytes to publish, or `None` for [`Self::Unchanged`].
    pub(crate) fn bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Create { bytes } | Self::Update { bytes, .. } => Some(bytes),
            Self::Unchanged => None,
        }
    }
}

/// What the plan changed, so the caller reports an observed edit instead of
/// guessing one from the two byte strings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ImageEdit {
    /// The root `image` value token occupied this range of the original bytes and
    /// was replaced by an encoded string holding the reference.
    ReplacedValue { span: Range<usize> },
    /// `len` bytes were inserted at `at` in the original bytes: one splice point.
    Inserted { at: usize, len: usize },
}

/// A 1-based line and column in the config text, for a refusal that can say where
/// the problem is without quoting the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Position {
    line: usize,
    column: usize,
}

/// Why the root `image` could not be planned. Nothing was written when this is
/// returned, and the text never quotes the file: config bytes are untrusted input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ImageEditRefusal {
    kind: ImageRefusal,
    location: Option<Position>,
}

/// What a table a stray `image` was found in is, named the way the user wrote it.
///
/// The set of tables, and their spellings, belongs to the config schema
/// ([`crate::config::IMAGE_OWNER_FIELDS`]); the label comes from
/// [`crate::config::ImageOwner::label`] so one rename cannot leave two vocabularies
/// behind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MisplacedSite {
    Sources,
    Network,
    Tools,
    MountSets,
    EgressSets,
}

impl From<crate::config::ImageOwner> for MisplacedSite {
    fn from(owner: crate::config::ImageOwner) -> Self {
        match owner {
            crate::config::ImageOwner::Sources => Self::Sources,
            crate::config::ImageOwner::Network => Self::Network,
            crate::config::ImageOwner::Tools => Self::Tools,
            crate::config::ImageOwner::MountSets => Self::MountSets,
            crate::config::ImageOwner::EgressSets => Self::EgressSets,
        }
    }
}

impl MisplacedSite {
    fn owner(self) -> crate::config::ImageOwner {
        match self {
            Self::Sources => crate::config::ImageOwner::Sources,
            Self::Network => crate::config::ImageOwner::Network,
            Self::Tools => crate::config::ImageOwner::Tools,
            Self::MountSets => crate::config::ImageOwner::MountSets,
            Self::EgressSets => crate::config::ImageOwner::EgressSets,
        }
    }

    fn label(self) -> &'static str {
        self.owner().label()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ImageRefusal {
    NotUtf8,
    /// `edited` distinguishes the file that is already too large from the edit that
    /// would make it so; both are the reader's ceiling, and neither was written.
    TooLarge {
        bytes: usize,
        edited: bool,
    },
    InvalidToml,
    NotAString,
    MisplacedImage(MisplacedSite),
    NoValueSpan,
    WouldNotRead,
}

impl ImageEditRefusal {
    fn new(kind: ImageRefusal) -> Self {
        Self {
            kind,
            location: None,
        }
    }

    fn at(kind: ImageRefusal, location: Position) -> Self {
        Self {
            kind,
            location: Some(location),
        }
    }

    fn write_location(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.location {
            Some(position) => write!(
                formatter,
                " (line {}, column {})",
                position.line, position.column
            ),
            None => Ok(()),
        }
    }
}

impl std::fmt::Display for ImageEditRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let limit = crate::config::MAX_CONFIG_FILE_BYTES;
        match self.kind {
            ImageRefusal::NotUtf8 => formatter.write_str(
                "the project config is not valid UTF-8, so its root \"image\" cannot be \
                 located; nothing was written",
            ),
            ImageRefusal::TooLarge {
                bytes,
                edited: false,
            } => write!(
                formatter,
                "the project config is {bytes} byte(s), above the {limit}-byte limit this reader \
                 accepts; nothing was written"
            ),
            ImageRefusal::TooLarge {
                bytes,
                edited: true,
            } => write!(
                formatter,
                "the edited project config would be {bytes} byte(s), above the {limit}-byte limit \
                 this reader accepts; nothing was written"
            ),
            ImageRefusal::InvalidToml => {
                formatter.write_str(
                    "the project config is not valid TOML (a syntax error or a repeated key), so \
                     its root \"image\" cannot be located",
                )?;
                self.write_location(formatter)
            }
            ImageRefusal::NotAString => {
                formatter.write_str(
                    "the root \"image\" is not a string value, so it cannot name an image; nothing \
                     was written",
                )?;
                self.write_location(formatter)
            }
            ImageRefusal::MisplacedImage(site) => {
                write!(
                    formatter,
                    "found an \"image\" inside {} that belongs to that table rather than to the \
                     root config; move it above the first table header and repeat",
                    site.label()
                )?;
                self.write_location(formatter)
            }
            ImageRefusal::NoValueSpan => formatter.write_str(
                "the TOML parser reported no byte range for the root \"image\" value, so it cannot \
                 be replaced without rewriting the file; nothing was written",
            ),
            ImageRefusal::WouldNotRead => formatter.write_str(
                "the edited project config would not read the new reference as its root \"image\", \
                 so the edit was abandoned; nothing was written",
            ),
        }
    }
}

/// Plan the exact bytes that make `reference` the root `image` of a project config
/// holding `existing` (or of a new one when it is absent).
///
/// Pure: no filesystem, no `$HOME`, no parser state escapes this call. `existing`
/// is bytes rather than `&str` so the two refusals a reader can hand over — not
/// UTF-8, above the size ceiling — are answered here, where a test can reach them,
/// instead of relying on the caller having read the file a particular way.
///
/// The three outcomes are the three things a caller may do: create the seed, publish
/// [`ImageEditPlan::bytes`], or publish nothing. Every refusal is fixed text with a
/// location when the parser supplied one.
pub(crate) fn plan_image_edit(
    existing: Option<&[u8]>,
    reference: &ImageRef,
) -> Result<ImageEditPlan, ImageEditRefusal> {
    let encoded = encode_toml_string(reference.as_str());
    let Some(existing) = existing else {
        let bytes = format!(
            "image = {encoded}\n\n{}",
            crate::project_config::HOME_SOURCES_SEED
        )
        .into_bytes();
        return Ok(ImageEditPlan::Create { bytes });
    };
    if existing.len() as u64 > crate::config::MAX_CONFIG_FILE_BYTES {
        return Err(ImageEditRefusal::new(ImageRefusal::TooLarge {
            bytes: existing.len(),
            edited: false,
        }));
    }
    let text =
        std::str::from_utf8(existing).map_err(|_| ImageEditRefusal::new(ImageRefusal::NotUtf8))?;
    let document = toml_edit::Document::parse(text).map_err(|error| ImageEditRefusal {
        kind: ImageRefusal::InvalidToml,
        location: error
            .span()
            .map(|span| position(text, span.start.min(text.len()))),
    })?;
    let root = document.as_table();
    let (bytes, edit) = match root.get("image") {
        Some(toml_edit::Item::Value(toml_edit::Value::String(current)))
            if current.value() == reference.as_str() =>
        {
            return Ok(ImageEditPlan::Unchanged);
        }
        Some(toml_edit::Item::Value(toml_edit::Value::String(current))) => {
            // Never fall back to re-serialising the document: without a span the
            // value's location is unknown, so the only honest answer is to stop.
            let span = current
                .span()
                .filter(|span| span.start <= span.end && span.end <= existing.len())
                .ok_or_else(|| ImageEditRefusal::new(ImageRefusal::NoValueSpan))?;
            let mut bytes = Vec::with_capacity(text.len() + encoded.len());
            bytes.extend_from_slice(&existing[..span.start]);
            bytes.extend_from_slice(encoded.as_bytes());
            bytes.extend_from_slice(&existing[span.end..]);
            (bytes, ImageEdit::ReplacedValue { span })
        }
        // `[image]` and `[[image]]` too: a table is not a string, and rewriting a
        // key of another type would be a repair, not a narrow edit. The key's own span
        // is the position the parser gave, so the refusal says where the value it
        // cannot use is.
        Some(_) => {
            let location = root
                .key("image")
                .and_then(|key| key.span())
                .map(|span| position(text, span.start));
            return Err(match location {
                Some(location) => ImageEditRefusal::at(ImageRefusal::NotAString, location),
                None => ImageEditRefusal::new(ImageRefusal::NotAString),
            });
        }
        None => {
            if let Some(misplaced) = misplaced_image(root, text) {
                return Err(ImageEditRefusal::at(
                    ImageRefusal::MisplacedImage(misplaced.site),
                    position(text, misplaced.offset),
                ));
            }
            insert_assignment(
                text,
                first_header_start(root),
                root_values_end(root),
                &encoded,
            )
        }
    };
    check_rendered(&bytes, reference)?;
    Ok(ImageEditPlan::Update { bytes, edit })
}

/// The output is the byte construction; this is the one property bytes alone cannot
/// show — that the file the loader reads now selects the reference at the root. It
/// deliberately checks only the root image: structural equality of parsed tables
/// would reject a preserved `nan` and prove nothing about the bytes.
fn check_rendered(bytes: &[u8], reference: &ImageRef) -> Result<(), ImageEditRefusal> {
    if bytes.len() as u64 > crate::config::MAX_CONFIG_FILE_BYTES {
        return Err(ImageEditRefusal::new(ImageRefusal::TooLarge {
            bytes: bytes.len(),
            edited: true,
        }));
    }
    let read = std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| toml::from_str::<toml::Table>(text).ok())
        .and_then(|table| {
            table
                .get("image")
                .and_then(toml::Value::as_str)
                .map(str::to_owned)
        });
    match read {
        Some(image) if image == reference.as_str() => Ok(()),
        _ => Err(ImageEditRefusal::new(ImageRefusal::WouldNotRead)),
    }
}

fn position(text: &str, offset: usize) -> Position {
    let (line, column) = crate::config::line_column(text, offset);
    Position { line, column }
}

/// A TOML basic string holding `value` exactly: the characters TOML singles out are
/// escaped and everything else is copied, so the reference cannot end the string or
/// start a new construct. [`check_rendered`] proves the decoded value.
///
/// Written here rather than delegated to `toml_edit`'s display: that feature is not
/// enabled (it is the re-serialising door this module keeps shut), and a one-token
/// encoder is the smallest thing whose output a test can pin byte for byte.
fn encode_toml_string(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len() + 2);
    encoded.push('"');
    for character in value.chars() {
        match character {
            '"' => encoded.push_str("\\\""),
            '\\' => encoded.push_str("\\\\"),
            '\u{8}' => encoded.push_str("\\b"),
            '\t' => encoded.push_str("\\t"),
            '\n' => encoded.push_str("\\n"),
            '\u{c}' => encoded.push_str("\\f"),
            '\r' => encoded.push_str("\\r"),
            control if control.is_control() => {
                let _ = write!(encoded, "\\u{:04X}", u32::from(control));
            }
            character => encoded.push(character),
        }
    }
    encoded.push('"');
    encoded
}

/// `image = <encoded>` inserted into the root prelude of `text` at exactly one byte
/// boundary, and the edit that says where.
///
/// The inserted line's EOL is the one ending the line above the boundary; when the
/// boundary is the start of the file, the one ending the header line below it; and
/// LF when the file has no EOL at all. Mixed line endings are never normalised —
/// only the new line picks a side, and the fallback is LF rather than the dominant
/// ending so a file cannot change character because one line was added.
///
/// A **zero-byte existing file** keeps its convention too: it has no final newline,
/// so the assignment does not add one. (The absent-file seed is a different case and
/// carries its own trailing LF.)
fn insert_assignment(
    text: &str,
    header_start: Option<usize>,
    root_values_end: usize,
    encoded: &str,
) -> (Vec<u8>, ImageEdit) {
    let assignment = format!("image = {encoded}");
    if text.is_empty() {
        let bytes = assignment.into_bytes();
        let len = bytes.len();
        return (bytes, ImageEdit::Inserted { at: 0, len });
    }
    let boundary = match header_start {
        Some(header_start) => prelude_boundary(text, header_start, root_values_end),
        None => text.len(),
    };
    let mut bytes = Vec::with_capacity(text.len() + assignment.len() + 2);
    if boundary == text.len() && !text.ends_with('\n') {
        // Appending keeps the file's missing final newline: the assignment needs a
        // separator, not a trailing EOL.
        bytes.extend_from_slice(text.as_bytes());
        bytes.extend_from_slice(last_eol(text).as_bytes());
        bytes.extend_from_slice(assignment.as_bytes());
    } else {
        bytes.extend_from_slice(&text.as_bytes()[..boundary]);
        bytes.extend_from_slice(assignment.as_bytes());
        bytes.extend_from_slice(inserted_eol(text, boundary).as_bytes());
        bytes.extend_from_slice(&text.as_bytes()[boundary..]);
    }
    let len = bytes.len() - text.len();
    (bytes, ImageEdit::Inserted { at: boundary, len })
}

/// Where in the root prelude the assignment goes: the first table header's line,
/// moved up over the comment block that introduces that table (and over the blank
/// line separating the block from the file heading).
///
/// The file heading stays above the assignment and a table's own note stays below
/// it, next to its table. Without a blank separator, comments that reach the start
/// of the file are the file heading; a comment block above a root key is a table
/// note, so the assignment goes above it and the root key stays first.
///
/// The scan is bounded below by the end of the **last root value**
/// (`root_values_end`): a physical line that begins inside a root value is part of
/// that value, so a `#` at its start is not a comment and a multiline string's
/// closing line must never be moved. `header_start` bounds it above, because the
/// lines between the two are exactly the prelude being looked at.
fn prelude_boundary(text: &str, header_start: usize, root_values_end: usize) -> usize {
    let header_line = line_start(text, header_start);
    let mut block_start = header_line;
    while let Some(previous) = previous_line_start(text, block_start) {
        if previous < root_values_end {
            // This line starts inside a root value: not a comment, not a blank line,
            // and nothing this edit may move.
            break;
        }
        let line = line_content(text, previous, block_start);
        if line.trim().is_empty() {
            // The blank line above the comment block separates the file heading from
            // the note; insert before it so the note keeps introducing its table. A
            // blank line directly above the header has no note to keep, so the
            // assignment goes just above the header instead.
            return if block_start == header_line {
                header_line
            } else {
                previous
            };
        }
        if !line.trim_start().starts_with('#') {
            break;
        }
        block_start = previous;
    }
    if block_start == first_line_start(text) && block_start < header_line {
        header_line
    } else {
        block_start
    }
}

fn line_start(text: &str, offset: usize) -> usize {
    match text[..offset].rfind('\n') {
        Some(newline) => newline + 1,
        None => first_line_start(text),
    }
}

/// The first line's start, which is after a byte-order mark: an insertion before it
/// would move the mark into the middle of the file.
fn first_line_start(text: &str) -> usize {
    if text.starts_with('\u{feff}') {
        '\u{feff}'.len_utf8()
    } else {
        0
    }
}

fn previous_line_start(text: &str, line: usize) -> Option<usize> {
    if line <= first_line_start(text) {
        return None;
    }
    let newline = line - 1;
    Some(match text[..newline].rfind('\n') {
        Some(previous_newline) => previous_newline + 1,
        None => first_line_start(text),
    })
}

fn line_content(text: &str, start: usize, end: usize) -> &str {
    text[start..end].trim_end_matches(['\r', '\n'])
}

fn inserted_eol(text: &str, boundary: usize) -> &'static str {
    if boundary > 0 {
        return eol_ending_at(text.as_bytes(), boundary);
    }
    match text.find('\n') {
        Some(newline) => eol_ending_at(text.as_bytes(), newline + 1),
        None => "\n",
    }
}

fn last_eol(text: &str) -> &'static str {
    match text.rfind('\n') {
        Some(newline) => eol_ending_at(text.as_bytes(), newline + 1),
        None => "\n",
    }
}

fn eol_ending_at(bytes: &[u8], end: usize) -> &'static str {
    if end >= 2 && bytes[end - 1] == b'\n' && bytes[end - 2] == b'\r' {
        "\r\n"
    } else {
        "\n"
    }
}

/// The earliest byte offset of an explicit `[table]` or `[[array-of-tables]]`
/// header anywhere in the document.
///
/// Implicit tables have no header of their own — `[a.b]`'s `a` and a dotted key's
/// parent are named by the span of their key, not by a header — so they are
/// descended into for the explicit header below them, and their own span is ignored.
/// Bracket text inside a value or a comment is never a header because this reads the
/// parse tree, not the text.
fn first_header_start(table: &toml_edit::Table) -> Option<usize> {
    let mut earliest = None;
    for (_, item) in table.iter() {
        match item {
            toml_edit::Item::Table(child) => {
                if !child.is_implicit() {
                    keep_earliest(&mut earliest, child.span().map(|span| span.start));
                }
                keep_earliest(&mut earliest, first_header_start(child));
            }
            toml_edit::Item::ArrayOfTables(arrays) => {
                keep_earliest(&mut earliest, arrays.span().map(|span| span.start));
                for element in arrays.iter() {
                    keep_earliest(&mut earliest, first_header_start(element));
                }
            }
            _ => {}
        }
    }
    earliest
}

fn keep_earliest(earliest: &mut Option<usize>, candidate: Option<usize>) {
    if let Some(candidate) = candidate
        && earliest.is_none_or(|current| candidate < current)
    {
        *earliest = Some(candidate);
    }
}

/// The end of the last **root-level value** in the document, or `0` when the root
/// holds no value at all.
///
/// Only root values bound the backward comment scan: a real `[table]`'s span starts
/// at its own header (which is at or after the insertion point, so it cannot bound
/// anything below it), while a dotted key's children are still root values and are
/// descended into. A multiline string `"""…\n#…"""` therefore bounds the scan at the
/// byte after its closing delimiter, not at the `#` inside it.
fn root_values_end(table: &toml_edit::Table) -> usize {
    fn value_end(item: &toml_edit::Item) -> Option<usize> {
        match item {
            toml_edit::Item::Value(value) => value.span().map(|span| span.end),
            // `a.b = 1` is a dotted table whose leaves are root values; a real
            // `[a]` header is not, and its span must not be read here.
            toml_edit::Item::Table(child) if child.is_dotted() => table_end(child),
            _ => None,
        }
    }
    fn table_end(table: &toml_edit::Table) -> Option<usize> {
        table.iter().filter_map(|(_, item)| value_end(item)).max()
    }
    table_end(table).unwrap_or(0)
}

struct MisplacedImage {
    site: MisplacedSite,
    offset: usize,
}

/// An `image` written where the root one cannot be: inside a table that owns its
/// keys. TOML scopes a key to the last header, so `image = "ref"` after
/// `[[sources]]` means that source's `image` — and `#748`'s source entries refuse an
/// `image` key, so the file does not read either. Silent insertion above the header
/// would leave the line the user wrote as dead weight, so this is a refusal.
///
/// The shape is the semantic one (header tables, `[[...]]` elements, inline tables
/// and dotted keys all arrive here as tables), never a scan for the text `image`, and
/// only a *direct* key of a definition counts: an `image` inside a tool's `env` table
/// is that variable's name, not a misplaced boot image.
fn misplaced_image(root: &toml_edit::Table, text: &str) -> Option<MisplacedImage> {
    // The *site* question is the shared classifier's (#749 F2): one table-aware
    // walk answers it for the reader and for this writer, and each caller keeps
    // its own policy — this one only refuses what its narrow root assignment
    // cannot express. Re-parsing the same text the caller already parsed is what
    // lets one `toml::Table` classifier answer for a `toml_edit` document; a
    // document that parsed must parse again unchanged.
    let document: toml::Table = text.parse().ok()?;
    let owner = image_owner(crate::config_schema::misplaced_key(&document, "image")?)?;
    let field = owner_field(owner);
    let item = root.get(field)?;
    // The classifier proved a direct `image` exists in this field, so the local
    // walk is only locating it for the line/column. `0` keeps an inconsistency a
    // refusal (at the file's start) rather than an edit.
    let offset = image_in_field(item, owner).unwrap_or(0);
    Some(MisplacedImage {
        site: MisplacedSite::from(owner),
        offset,
    })
}

/// Which image-owning table a classified site is, or `None` for the root — whose
/// `image` is the one this edit reads and replaces.
fn image_owner(site: crate::config_schema::Site) -> Option<crate::config::ImageOwner> {
    use crate::config::ImageOwner;
    match site {
        crate::config_schema::Site::Root => None,
        crate::config_schema::Site::Tool(_) => Some(ImageOwner::Tools),
        crate::config_schema::Site::Source(_) => Some(ImageOwner::Sources),
        crate::config_schema::Site::Network => Some(ImageOwner::Network),
        crate::config_schema::Site::MountSet(_) => Some(ImageOwner::MountSets),
        crate::config_schema::Site::EgressSet(_) => Some(ImageOwner::EgressSets),
    }
}

/// The top-level key of an image-owning table, from the one vocabulary
/// ([`crate::config::IMAGE_OWNER_FIELDS`]) so a rename cannot leave two lists.
fn owner_field(owner: crate::config::ImageOwner) -> &'static str {
    crate::config::IMAGE_OWNER_FIELDS
        .iter()
        .find_map(|(field, candidate)| (*candidate == owner).then_some(*field))
        .expect("every ImageOwner has a field in IMAGE_OWNER_FIELDS")
}

fn image_in_field(item: &toml_edit::Item, owner: crate::config::ImageOwner) -> Option<usize> {
    use crate::config::ImageOwner;
    match owner {
        ImageOwner::Sources | ImageOwner::Tools => {
            if let Some(arrays) = item.as_array_of_tables() {
                return arrays.iter().find_map(direct_image_offset);
            }
            if let Some(elements) = item.as_value().and_then(toml_edit::Value::as_array) {
                return elements.iter().find_map(|element| {
                    element
                        .as_inline_table()
                        .and_then(direct_image_offset_inline)
                });
            }
            table_image_offset(item)
        }
        ImageOwner::Network => table_image_offset(item),
        ImageOwner::MountSets | ImageOwner::EgressSets => {
            if let Some(sets) = item.as_table() {
                return sets
                    .iter()
                    .find_map(|(_, set)| set.as_table().and_then(direct_image_offset));
            }
            let sets = item
                .as_value()
                .and_then(toml_edit::Value::as_inline_table)?;
            sets.iter()
                .find_map(|(_, set)| set.as_inline_table().and_then(direct_image_offset_inline))
        }
    }
}

fn table_image_offset(item: &toml_edit::Item) -> Option<usize> {
    if let Some(table) = item.as_table() {
        return direct_image_offset(table);
    }
    item.as_value()
        .and_then(toml_edit::Value::as_inline_table)
        .and_then(direct_image_offset_inline)
}

fn direct_image_offset(table: &toml_edit::Table) -> Option<usize> {
    table
        .key("image")
        .and_then(|key| key.span())
        .map(|span| span.start)
}

fn direct_image_offset_inline(table: &toml_edit::InlineTable) -> Option<usize> {
    table
        .key("image")
        .and_then(|key| key.span())
        .map(|span| span.start)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    struct Fixture {
        _home: tempfile::TempDir,
        home: PathBuf,
        _project: tempfile::TempDir,
        project: ProjectDir,
    }

    impl Fixture {
        fn new() -> Self {
            let home = tempfile::tempdir().unwrap();
            let project = tempfile::tempdir().unwrap();
            let captured = ProjectDir::from_path_for_tests(project.path()).unwrap();
            let home_path = home.path().to_path_buf();
            Self {
                _home: home,
                home: home_path,
                _project: project,
                project: captured,
            }
        }

        fn store(&self) -> ProjectConfigStore {
            ProjectConfigStore::for_project(&self.home, &self.project)
        }

        fn store_dir(&self) -> PathBuf {
            crate::project_config::project_dir(&self.home, &self.project)
        }

        fn config(&self) -> PathBuf {
            crate::project_config::path(&self.home, &self.project)
        }

        fn lock(&self) -> PathBuf {
            self.store_dir().join(CONFIG_LOCK_FILE)
        }

        /// A scratch path beside the fixture's own roots, for a fixture that needs to
        /// place a link target outside `$HOME` and outside the project.
        fn root_path(&self) -> PathBuf {
            self.project
                .path()
                .parent()
                .expect("the project root has a parent")
                .to_path_buf()
        }

        /// The store directory exists at `0700` with its permanent lock and **no**
        /// `config.toml`: the state a first save creates the file in.
        fn with_store_only(&self) {
            std::fs::create_dir_all(self.store_dir()).unwrap();
            std::fs::set_permissions(self.store_dir(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            std::fs::write(self.lock(), b"").unwrap();
            std::fs::set_permissions(self.lock(), std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        /// The store directory exists at `0700` with its lock and a `config.toml`
        /// holding `bytes`, the state a second save starts from.
        fn with_config(&self, bytes: &str) {
            self.with_store_only();
            std::fs::write(self.config(), bytes).unwrap();
            std::fs::set_permissions(self.config(), std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
    }

    const OLD: &str = "image = \"example.com/old:1\"\n";
    const NEW: &str = "image = \"example.com/new:2\"\n";
    /// What a fresh live store holds while the save's descriptors name a detached
    /// one.
    const PEER: &str = "image = \"example.com/peer:7\"\n";

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().mode() & 0o7777
    }

    fn identity_of(path: &Path) -> FileIdentity {
        let meta = std::fs::metadata(path).unwrap();
        FileIdentity {
            dev: meta.dev(),
            ino: meta.ino(),
        }
    }

    fn mtime_of(path: &Path) -> (i64, i64) {
        let meta = std::fs::metadata(path).unwrap();
        (meta.mtime(), meta.mtime_nsec())
    }

    fn no_temporaries(dir: &Path) -> bool {
        std::fs::read_dir(dir).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(TEMP_PREFIX)
        })
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// Everything an ordinary pre-publication error must leave exactly as it was.
    fn assert_untouched(fixture: &Fixture, before: (&FileIdentity, (i64, i64), u32)) {
        let config = fixture.config();
        assert_eq!(
            std::fs::read(&config).unwrap(),
            OLD.as_bytes(),
            "the old bytes must survive a failed save"
        );
        assert_eq!(identity_of(&config), *before.0, "the inode must not change");
        assert_eq!(mtime_of(&config), before.1, "the mtime must not change");
        assert_eq!(mode_of(&config), before.2, "the mode must not change");
        assert!(
            no_temporaries(&fixture.store_dir()),
            "a failed save must unlink its temporary"
        );
    }

    fn snapshot_state(fixture: &Fixture) -> (FileIdentity, (i64, i64), u32) {
        (
            identity_of(&fixture.config()),
            mtime_of(&fixture.config()),
            mode_of(&fixture.config()),
        )
    }

    // -- the route and the first save ---------------------------------------

    #[test]
    fn a_first_save_creates_the_store_and_the_file() {
        let fixture = Fixture::new();
        let store = fixture.store();

        assert_eq!(
            store.existing_bytes().unwrap(),
            None,
            "the read-only observation reports no bytes"
        );
        assert!(
            !fixture.home.join(".config").exists(),
            "a read-only observation must create nothing"
        );

        let snapshot = store.snapshot().unwrap();
        assert_eq!(snapshot.bytes(), None);
        assert_eq!(
            snapshot.route.lock, None,
            "a snapshot of a route that does not exist carries no lock identity"
        );
        assert!(
            !fixture.home.join(".config").exists(),
            "the snapshot is a read, so it creates nothing either: the store exists only \
             after the verified publish transition"
        );
        assert_eq!(
            store.save(&snapshot, NEW.as_bytes()).unwrap(),
            ConfigSave::Created
        );

        assert_eq!(std::fs::read(fixture.config()).unwrap(), NEW.as_bytes());
        assert_eq!(mode_of(&fixture.config()), 0o600);
        assert_eq!(mode_of(&fixture.store_dir()), 0o700);
        assert_eq!(
            mode_of(fixture.store_dir().parent().unwrap()),
            0o700,
            "every created level is owner-only"
        );
        assert_eq!(mode_of(&fixture.lock()), 0o600);
        assert_eq!(
            entries(&fixture.store_dir()),
            vec![CONFIG_LOCK_FILE.to_owned(), CONFIG_FILE.to_owned()]
        );
        assert_eq!(
            fixture
                .store_dir()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            fixture.project.digest_hex(),
            "the store directory is named by the captured project digest"
        );
    }

    #[test]
    fn a_second_save_replaces_the_file_through_a_rename() {
        let fixture = Fixture::new();
        fixture.with_config(OLD);
        let store = fixture.store();
        let before = identity_of(&fixture.config());

        let snapshot = store.snapshot().unwrap();
        assert_eq!(snapshot.bytes(), Some(OLD));
        assert_eq!(
            store.save(&snapshot, NEW.as_bytes()).unwrap(),
            ConfigSave::Replaced
        );

        assert_eq!(std::fs::read(fixture.config()).unwrap(), NEW.as_bytes());
        assert_eq!(mode_of(&fixture.config()), 0o600);
        assert_ne!(
            identity_of(&fixture.config()),
            before,
            "a replacement is a rename of a new inode, never an in-place rewrite"
        );
        assert!(no_temporaries(&fixture.store_dir()));
    }

    #[test]
    fn a_save_of_the_live_bytes_publishes_nothing() {
        let fixture = Fixture::new();
        fixture.with_config(OLD);
        let store = fixture.store();
        let snapshot = store.snapshot().unwrap();
        let before = snapshot_state(&fixture);

        assert_eq!(
            store.save(&snapshot, OLD.as_bytes()).unwrap(),
            ConfigSave::Unchanged
        );
        assert_untouched(&fixture, (&before.0, before.1, before.2));
    }

    #[test]
    fn the_lock_inode_is_permanent_across_saves() {
        let fixture = Fixture::new();
        let store = fixture.store();
        let first = store.snapshot().unwrap();
        store.save(&first, OLD.as_bytes()).unwrap();
        let lock_identity = identity_of(&fixture.lock());

        let second = store.snapshot().unwrap();
        store.save(&second, NEW.as_bytes()).unwrap();
        assert_eq!(identity_of(&fixture.lock()), lock_identity);
    }

    #[test]
    fn a_masking_umask_is_fixed_on_the_directory_this_walk_created() {
        let fixture = Fixture::new();
        let store = fixture.store();
        let snapshot = store.snapshot().unwrap();
        // A `0600` directory is what `umask 0177` makes of `mkdir(0700)`: it can be
        // opened, so the fix belongs on this walk's own entry and nothing later may
        // compensate for it.
        let outcome = store
            .save_with(
                &snapshot,
                NEW.as_bytes(),
                &Seams {
                    create_mode: Some(Mode::from_raw_mode(0o600)),
                    ..Seams::default()
                },
            )
            .unwrap();
        assert_eq!(outcome, ConfigSave::Created);
        assert_eq!(mode_of(&fixture.store_dir()), 0o700);
        assert_eq!(std::fs::read(fixture.config()).unwrap(), NEW.as_bytes());
    }

    /// The case the readable `0600` directory above never reaches: a umask that masks
    /// the owner's own **search** bit makes the directory this walk just created
    /// unopenable, so a fix applied after the open would fail *after* acquisition with
    /// the entry already on disk. It is repaired through the parent descriptor, which
    /// needs no access to the entry itself.
    #[test]
    fn an_unopenable_creation_mode_is_repaired_before_the_entry_is_opened() {
        let fixture = Fixture::new();
        let store = fixture.store();
        let snapshot = store.snapshot().unwrap();
        let outcome = store
            .save_with(
                &snapshot,
                NEW.as_bytes(),
                &Seams {
                    // What `umask 0777` (or `0776`) leaves of `mkdir(0700)`.
                    create_mode: Some(Mode::from_raw_mode(0o000)),
                    ..Seams::default()
                },
            )
            .unwrap();
        assert_eq!(outcome, ConfigSave::Created);
        assert_eq!(
            mode_of(store.config_path().parent().unwrap()),
            0o700,
            "the created entry is exactly owner-only, not left as the mask made it"
        );
        assert_eq!(mode_of(&fixture.store_dir()), 0o700);
        assert_eq!(mode_of(&fixture.lock()), 0o600);
        assert_eq!(std::fs::read(fixture.config()).unwrap(), NEW.as_bytes());
    }

    #[test]
    fn an_existing_directory_that_wins_the_creation_race_is_verified_not_chmodded() {
        let fixture = Fixture::new();
        let store = fixture.store();
        // A peer's directory, not this walk's: world-readable, and so not ours to
        // make owner-only. `0700` would pass the created-mode check, `0755` proves
        // it did not run.
        // The walk builds its own canonical spellings, so the winner is recognised
        // by the store's name rather than by a path this fixture spelled.
        let store_name = OsString::from(fixture.project.digest_hex());
        let snapshot = store.snapshot().unwrap();
        let outcome = store
            .save_with(
                &snapshot,
                NEW.as_bytes(),
                &Seams {
                    just_before_create: Some(&|path: &Path| {
                        if path.file_name() == Some(store_name.as_os_str()) {
                            std::fs::create_dir(path).unwrap();
                            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
                                .unwrap();
                        }
                    }),
                    ..Seams::default()
                },
            )
            .unwrap();
        assert_eq!(mode_of(&fixture.store_dir()), 0o755);
        assert_eq!(outcome, ConfigSave::Created);
        assert_eq!(std::fs::read(fixture.config()).unwrap(), NEW.as_bytes());
    }

    #[test]
    fn a_created_config_lock_is_owner_only_whatever_the_creation_mode() {
        let fixture = Fixture::new();
        std::fs::create_dir_all(fixture.store_dir()).unwrap();
        let store_fd = rustix::fs::open(
            fixture.store_dir(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        // The mode a masking umask could have produced for a `0600` create.
        crate::host_paths::open_verified_lock_at_with_create_mode(
            &store_fd,
            OsStr::new(CONFIG_LOCK_FILE),
            current_euid(),
            &fixture.lock(),
            Mode::empty(),
        )
        .unwrap();
        assert_eq!(mode_of(&fixture.lock()), 0o600);
    }

    #[test]
    fn a_route_directory_replaced_after_it_was_opened_is_refused() {
        let fixture = Fixture::new();
        fixture.with_config(OLD);
        let store = fixture.store();
        let store_name = OsString::from(fixture.project.digest_hex());
        let moved = fixture.store_dir().with_extension("moved");

        let error = store
            .snapshot_with(&Seams {
                after_open_level: Some(&|path: &Path| {
                    if path.file_name() == Some(store_name.as_os_str()) {
                        // The descriptor still names the old directory; this name now
                        // names a different one.
                        std::fs::rename(path, &moved).unwrap();
                        std::fs::create_dir(path).unwrap();
                    }
                }),
                ..Seams::default()
            })
            .expect_err("a directory replaced after it was opened must refuse");
        assert!(
            format!("{error:#}").contains("changed while it was being opened"),
            "{error:#}"
        );
        assert_eq!(
            std::fs::read(moved.join(CONFIG_FILE)).unwrap(),
            OLD.as_bytes(),
            "the replaced-away store keeps its bytes"
        );
        assert!(entries(&fixture.store_dir()).is_empty());
    }

    #[test]
    fn a_non_directory_on_the_route_is_refused_not_treated_as_missing() {
        let fixture = Fixture::new();
        let projects = crate::project_config::projects_dir(&fixture.home);
        std::fs::create_dir_all(projects.parent().unwrap()).unwrap();
        std::fs::write(&projects, b"not a directory").unwrap();

        let error = fixture
            .store()
            .existing_bytes()
            .expect_err("a file where a route directory belongs must refuse");
        assert!(
            format!("{error:#}").contains("is not a directory"),
            "{error:#}"
        );
        assert_eq!(
            std::fs::read(&projects).unwrap(),
            b"not a directory",
            "a name that is not a directory is never a missing one"
        );
        assert!(!fixture.store_dir().exists());
    }

    /// D2: `~/.config` is a link whose target does not exist. `openat` follows the
    /// link and reports the *target's* absence, so a walk that trusted `ENOENT` would
    /// treat the link itself as a missing slot and discover `EEXIST` from `mkdirat`
    /// after acquisition.
    #[test]
    fn a_dangling_dotfile_alias_is_refused_rather_than_created_over() {
        let fixture = Fixture::new();
        let missing = fixture.root_path().join("dotfiles-not-cloned/config");
        std::os::unix::fs::symlink(&missing, fixture.home.join(".config")).unwrap();
        let store = fixture.store();

        for error in [
            store.existing_bytes().map(|bytes| bytes.is_some()),
            store.snapshot().map(|snapshot| snapshot.bytes().is_some()),
            store
                .snapshot()
                .and_then(|snapshot| store.save(&snapshot, NEW.as_bytes()))
                .map(|saved| saved == ConfigSave::Created),
        ] {
            let error = error.expect_err("a dangling alias must refuse");
            assert!(
                format!("{error:#}").contains("symbolic link whose target does not exist"),
                "{error:#}"
            );
        }
        assert!(
            std::fs::symlink_metadata(fixture.home.join(".config"))
                .unwrap()
                .is_symlink(),
            "the link is never replaced by a directory"
        );
        assert!(
            !missing.exists(),
            "nothing may be created at the link's target either"
        );
    }

    /// The same classification one level down: `~/.config/agent-vm` is the dangling
    /// name, and the walk must not read it as a missing directory to create.
    #[test]
    fn a_dangling_agent_vm_alias_is_refused_rather_than_created_over() {
        let fixture = Fixture::new();
        let config = fixture.home.join(".config");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o700)).unwrap();
        let missing = fixture.root_path().join("agent-vm-not-cloned");
        std::os::unix::fs::symlink(&missing, config.join("agent-vm")).unwrap();

        let error = fixture
            .store()
            .existing_bytes()
            .expect_err("a dangling alias must refuse");
        assert!(
            format!("{error:#}").contains("symbolic link whose target does not exist"),
            "{error:#}"
        );
        assert!(
            std::fs::symlink_metadata(config.join("agent-vm"))
                .unwrap()
                .is_symlink()
        );
        assert!(!missing.exists());
    }

    /// D2: an admitted dotfile alias is only as good as the directories above it. A
    /// leaf this user owns inside a directory group or other users may write is a name
    /// another process can replace, and the reader refuses exactly that ancestry.
    #[test]
    fn a_dotfile_alias_inside_an_ancestry_another_user_controls_is_refused() {
        let fixture = Fixture::new();
        let shared = tempfile::tempdir().unwrap();
        let writable = shared.path().join("shared");
        let target = writable.join("config");
        std::fs::create_dir_all(target.join("agent-vm")).unwrap();
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o777)).unwrap();
        std::os::unix::fs::symlink(&target, fixture.home.join(".config")).unwrap();

        let error = fixture
            .store()
            .snapshot()
            .expect_err("a replaceable ancestor must refuse");
        assert!(
            format!("{error:#}").contains("not a directory this user controls exclusively"),
            "{error:#}"
        );
        assert!(
            entries(&target.join("agent-vm")).is_empty(),
            "a refused route creates nothing"
        );
    }

    /// D2: "inside the active project" is a statement about an **identity**. The tree
    /// this command captured is replaced before the write, so the spelling the walk
    /// compares against now names a directory nothing measured.
    #[test]
    fn a_project_root_replaced_after_the_capture_is_refused() {
        let fixture = Fixture::new();
        fixture.with_config(OLD);
        let store = fixture.store();
        let before = snapshot_state(&fixture);
        let moved = fixture.project.path().with_extension("captured");
        std::fs::rename(fixture.project.path(), &moved).unwrap();
        std::fs::create_dir(fixture.project.path()).unwrap();

        let error = store
            .existing_bytes()
            .expect_err("a replaced project root must refuse");
        assert!(
            format!("{error:#}").contains("no longer the directory this command captured"),
            "{error:#}"
        );
        assert_eq!(std::fs::read(fixture.config()).unwrap(), OLD.as_bytes());
        assert_eq!(identity_of(&fixture.config()), before.0);
        assert!(no_temporaries(&fixture.store_dir()));
        std::fs::remove_dir(fixture.project.path()).unwrap();
        std::fs::rename(&moved, fixture.project.path()).unwrap();
    }

    #[test]
    fn an_unopenable_route_directory_is_refused_rather_than_replaced() {
        let fixture = Fixture::new();
        let config_dir = fixture.home.join(".config/agent-vm");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::set_permissions(&config_dir, std::fs::Permissions::from_mode(0o000)).unwrap();

        let probe = fixture.store().existing_bytes();
        // Restore access before asserting, so the temporary directory can be removed.
        std::fs::set_permissions(&config_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let error = probe.expect_err("a route level that cannot be opened must refuse");
        assert!(
            format!("{error:#}").contains("agent-vm config directory"),
            "the refusal must name the level that failed: {error:#}"
        );
        assert!(!fixture.store_dir().exists());
    }

    // -- stale saves are refused -------------------------------------------

    #[test]
    fn a_stale_save_is_refused_when_the_bytes_changed() {
        let fixture = Fixture::new();
        fixture.with_config(OLD);
        let store = fixture.store();
        let snapshot = store.snapshot().unwrap();

        let peer = fixture.config();
        std::fs::write(&peer, "image = \"example.com/peer:3\"\n").unwrap();
        std::fs::set_permissions(&peer, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert_eq!(
            store.save(&snapshot, NEW.as_bytes()).unwrap(),
            ConfigSave::Refused(ConfigConflict::Stale)
        );
        assert_eq!(
            std::fs::read(fixture.config()).unwrap(),
            b"image = \"example.com/peer:3\"\n",
            "the peer's bytes must survive the refused save"
        );
        assert!(no_temporaries(&fixture.store_dir()));
    }

    #[test]
    fn a_stale_save_is_refused_when_the_bytes_were_replaced_with_the_same_ones() {
        let fixture = Fixture::new();
        fixture.with_config(OLD);
        let store = fixture.store();
        let snapshot = store.snapshot().unwrap();
        let before = identity_of(&fixture.config());

        // Same bytes, new inode: only the identity distinguishes this from a no-op.
        let replacement = fixture.store_dir().join("replacement");
        std::fs::write(&replacement, OLD).unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::rename(&replacement, fixture.config()).unwrap();
        let peer_identity = identity_of(&fixture.config());
        assert_ne!(peer_identity, before);

        assert_eq!(
            store.save(&snapshot, NEW.as_bytes()).unwrap(),
            ConfigSave::Refused(ConfigConflict::Stale)
        );
        assert_eq!(std::fs::read(fixture.config()).unwrap(), OLD.as_bytes());
        assert_eq!(identity_of(&fixture.config()), peer_identity);
    }

    #[test]
    fn an_absent_snapshot_is_refused_when_a_peer_creates_the_file() {
        let fixture = Fixture::new();
        fixture.with_store_only();
        let store = fixture.store();
        let snapshot = store.snapshot().unwrap();
        assert_eq!(snapshot.bytes(), None);
        assert_eq!(
            snapshot.lock_identity(),
            Some(identity_of(&fixture.lock())),
            "the observation names the lock the publish transition will serialize on"
        );

        std::fs::write(fixture.config(), OLD).unwrap();
        std::fs::set_permissions(fixture.config(), std::fs::Permissions::from_mode(0o600)).unwrap();

        assert_eq!(
            store.save(&snapshot, NEW.as_bytes()).unwrap(),
            ConfigSave::Refused(ConfigConflict::Stale)
        );
        assert_eq!(
            std::fs::read(fixture.config()).unwrap(),
            OLD.as_bytes(),
            "absent→present must never be published over"
        );
    }

    #[test]
    fn a_present_snapshot_is_refused_when_the_file_disappears() {
        let fixture = Fixture::new();
        fixture.with_config(OLD);
        let store = fixture.store();
        let snapshot = store.snapshot().unwrap();

        std::fs::remove_file(fixture.config()).unwrap();

        assert_eq!(
            store.save(&snapshot, NEW.as_bytes()).unwrap(),
            ConfigSave::Refused(ConfigConflict::Stale)
        );
        assert!(
            !fixture.config().exists(),
            "present→absent must never publish the old base over a removal"
        );
    }

    #[test]
    fn a_displaced_store_directory_is_refused() {
        let fixture = Fixture::new();
        fixture.with_config(OLD);
        let store = fixture.store();
        let snapshot = store.snapshot().unwrap();

        let displaced = fixture.store_dir().with_extension("displaced");
        std::fs::rename(fixture.store_dir(), &displaced).unwrap();
        // A whole new store, with its own lock: the same path, a different store.
        // Built beside the path and renamed over it, so its inode existed while
        // the displaced one did and cannot be a reused number.
        let replacement = fixture.store_dir().with_extension("replacement");
        std::fs::create_dir(&replacement).unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::rename(&replacement, fixture.store_dir()).unwrap();
        std::fs::write(fixture.config(), "image = \"example.com/peer:4\"\n").unwrap();
        std::fs::write(fixture.lock(), b"").unwrap();

        assert_eq!(
            store.save(&snapshot, NEW.as_bytes()).unwrap(),
            ConfigSave::Refused(ConfigConflict::Displaced)
        );
        assert_eq!(
            std::fs::read(displaced.join(CONFIG_FILE)).unwrap(),
            OLD.as_bytes(),
            "the store the snapshot verified must be untouched"
        );
        assert_eq!(
            std::fs::read(fixture.config()).unwrap(),
            b"image = \"example.com/peer:4\"\n",
            "the replacement store must be untouched"
        );
    }

    #[test]
    fn a_displaced_lock_is_refused() {
        let fixture = Fixture::new();
        fixture.with_config(OLD);
        let store = fixture.store();
        let snapshot = store.snapshot().unwrap();
        let before = snapshot_state(&fixture);

        // Build the replacement while the old lock still exists, then rename it
        // over: two files that existed together cannot share an inode, so the
        // fixture proves a *different* lock rather than depending on whether the
        // filesystem reuses the number of the one just unlinked.
        let replacement = fixture.store_dir().join("lock.replacement");
        std::fs::write(&replacement, b"").unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::rename(&replacement, fixture.lock()).unwrap();

        assert_eq!(
            store.save(&snapshot, NEW.as_bytes()).unwrap(),
            ConfigSave::Refused(ConfigConflict::Displaced)
        );
        assert_untouched(&fixture, (&before.0, before.1, before.2));
    }

    #[test]
    fn a_lock_replaced_after_the_under_lock_read_is_refused() {
        let fixture = Fixture::new();
        fixture.with_config(OLD);
        let store = fixture.store();
        let snapshot = store.snapshot().unwrap();
        let before = snapshot_state(&fixture);

        let outcome = store
            .save_with(
                &snapshot,
                NEW.as_bytes(),
                &Seams {
                    // The interval after the under-lock read: a peer replaces the
                    // coordination inode, so a second writer could take the new one
                    // while this one still held the old.
                    after_lock_before_read: Some(&|| {
                        std::fs::remove_file(fixture.lock()).unwrap();
                        std::fs::write(fixture.lock(), b"").unwrap();
                        std::fs::set_permissions(
                            fixture.lock(),
                            std::fs::Permissions::from_mode(0o600),
                        )
                        .unwrap();
                    }),
                    ..Seams::default()
                },
            )
            .unwrap();
        assert_eq!(outcome, ConfigSave::Refused(ConfigConflict::Displaced));
        assert_untouched(&fixture, (&before.0, before.1, before.2));
    }

    #[test]
    fn a_save_never_recreates_a_missing_store() {
        let fixture = Fixture::new();
        fixture.with_config(OLD);
        let store = fixture.store();
        let snapshot = store.snapshot().unwrap();

        std::fs::remove_dir_all(fixture.store_dir()).unwrap();

        assert_eq!(
            store.save(&snapshot, NEW.as_bytes()).unwrap(),
            ConfigSave::Refused(ConfigConflict::Displaced)
        );
        assert!(
            !fixture.store_dir().exists(),
            "a save may never perform the bootstrap again"
        );
    }

    #[test]
    fn a_peer_save_between_snapshot_and_publish_is_refused() {
        let fixture = Fixture::new();
        fixture.with_config(OLD);
        let store = fixture.store();
        let first = store.snapshot().unwrap();
        let second = store.snapshot().unwrap();

        assert_eq!(
            store.save(&first, NEW.as_bytes()).unwrap(),
            ConfigSave::Replaced
        );
        assert_eq!(
            store
                .save(&second, "image = \"example.com/second:5\"\n".as_bytes())
                .unwrap(),
            ConfigSave::Refused(ConfigConflict::Stale)
        );
        assert_eq!(std::fs::read(fixture.config()).unwrap(), NEW.as_bytes());
    }

    #[test]
    fn the_lock_is_held_across_the_read_and_the_rename() {
        let fixture = Fixture::new();
        fixture.with_config(OLD);
        let store = fixture.store();
        let snapshot = store.snapshot().unwrap();
        let contended = std::cell::Cell::new(0_u32);
        let observe = || {
            let independent = std::fs::File::open(fixture.lock()).unwrap();
            if crate::host_paths::try_flock(&independent, crate::host_paths::FlockMode::Exclusive)
                .unwrap()
                == crate::host_paths::FlockAttempt::Contended
            {
                contended.set(contended.get() + 1);
            }
        };

        let outcome = store
            .save_with(
                &snapshot,
                NEW.as_bytes(),
                &Seams {
                    after_lock_before_read: Some(&observe),
                    just_before_rename: Some(&observe),
                    ..Seams::default()
                },
            )
            .unwrap();
        assert_eq!(outcome, ConfigSave::Replaced);
        assert_eq!(
            contended.get(),
            2,
            "config.lock must be held from before the read until after the rename"
        );
    }

    #[test]
    fn a_timed_out_lock_writes_nothing() {
        let fixture = Fixture::new();
        fixture.with_config(OLD);
        let store = fixture.store();
        let snapshot = store.snapshot().unwrap();
        let before = snapshot_state(&fixture);

        let holder = std::fs::File::open(fixture.lock()).unwrap();
        assert_eq!(
            crate::host_paths::try_flock(&holder, crate::host_paths::FlockMode::Exclusive).unwrap(),
            crate::host_paths::FlockAttempt::Acquired
        );
        let error = store
            .save_with(
                &snapshot,
                NEW.as_bytes(),
                &Seams {
                    lock_wait: Some(Duration::from_millis(50)),
                    ..Seams::default()
                },
            )
            .expect_err("a lock a peer holds must fail the save");
        assert!(
            format!("{error:#}").contains("waiting for another agent-vm config writer"),
            "{error:#}"
        );
        assert_untouched(&fixture, (&before.0, before.1, before.2));
    }

    // -- existing material the file must not disturb ------------------------

    #[test]
    fn a_preexisting_pin_store_without_a_config_is_bootstrapped() {
        let fixture = Fixture::new();
        std::fs::create_dir_all(fixture.store_dir()).unwrap();
        std::fs::set_permissions(fixture.store_dir(), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let pins = fixture.store_dir().join("pins.json");
        let pins_lock = fixture.store_dir().join("pins.lock");
        std::fs::write(&pins, b"{\"version\":1}").unwrap();
        std::fs::write(&pins_lock, b"header").unwrap();
        let before = (identity_of(&pins), mtime_of(&pins));
        let lock_before = (identity_of(&pins_lock), mtime_of(&pins_lock));

        let store = fixture.store();
        assert_eq!(
            store.existing_bytes().unwrap(),
            None,
            "the store exists and holds no config"
        );
        let snapshot = store.snapshot().unwrap();
        assert_eq!(snapshot.bytes(), None);
        assert_eq!(
            store.save(&snapshot, NEW.as_bytes()).unwrap(),
            ConfigSave::Created
        );

        assert_eq!(std::fs::read(fixture.config()).unwrap(), NEW.as_bytes());
        assert_eq!(
            (identity_of(&pins), mtime_of(&pins)),
            before,
            "the source pin store keeps its bytes, inode and mtime"
        );
        assert_eq!(
            (identity_of(&pins_lock), mtime_of(&pins_lock)),
            lock_before,
            "the pin lock is a different inode from config.lock and is untouched"
        );
        assert_eq!(mode_of(&fixture.lock()), 0o600);
    }

    /// D8/B6: the cap-plus-one read catches growth *past* the ceiling. A file that
    /// grows by a byte below it was still not the file this writer measured, and
    /// publishing the edit would rewrite bytes nobody read.
    #[test]
    fn a_config_that_grows_below_the_cap_is_refused() {
        let fixture = Fixture::new();
        fixture.with_config(OLD);
        let store = fixture.store();
        let snapshot = store.snapshot().unwrap();
        let before = snapshot_state(&fixture);
        let path = fixture.config();

        let error = store
            .save_with(
                &snapshot,
                NEW.as_bytes(),
                &Seams {
                    // The interval after the descriptor was measured and before its
                    // bytes are read: a peer appends one byte, well under the cap.
                    read_config_after_measure: Some(&|| {
                        use std::io::Write as _;
                        std::fs::OpenOptions::new()
                            .append(true)
                            .open(&path)
                            .unwrap()
                            .write_all(b"#")
                            .unwrap();
                    }),
                    ..Seams::default()
                },
            )
            .expect_err("growth below the cap must refuse");
        assert!(
            format!("{error:#}").contains(CHANGED_WHILE_READ),
            "{error:#}"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            format!("{OLD}#").as_bytes(),
            "the peer's bytes are the file's own and are left alone"
        );
        assert_eq!(identity_of(&path), before.0, "and so is its inode");
        assert!(no_temporaries(&fixture.store_dir()));
    }

    /// The refusal above is fixed text, so a reader cannot leak a config file's size
    /// (or any other byte it measured) through the message.
    #[test]
    fn the_growth_refusal_is_fixed_text() {
        assert_eq!(
            CHANGED_WHILE_READ,
            "the project config changed while it was being read, so nothing was written; read it again and repeat"
        );
    }

    /// D1/B5: the raw observation is a **read**. A store that exists without a lock
    /// must still have no lock after a snapshot — creating it is the publish
    /// transition's job, and only there does the lock identity become required.
    #[test]
    fn a_snapshot_of_a_store_without_a_lock_creates_nothing() {
        let fixture = Fixture::new();
        std::fs::create_dir_all(fixture.store_dir()).unwrap();
        std::fs::set_permissions(fixture.store_dir(), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let store = fixture.store();

        let snapshot = store.snapshot().unwrap();
        assert_eq!(snapshot.bytes(), None);
        assert_eq!(
            snapshot.lock_identity(),
            None,
            "a store without a lock observes no lock identity"
        );
        assert!(
            entries(&fixture.store_dir()).is_empty(),
            "the snapshot created {:?}",
            entries(&fixture.store_dir())
        );

        // The bootstrap is the save's, and it happens exactly once.
        assert_eq!(
            store.save(&snapshot, NEW.as_bytes()).unwrap(),
            ConfigSave::Created
        );
        assert_eq!(
            entries(&fixture.store_dir()),
            vec![CONFIG_LOCK_FILE.to_owned(), CONFIG_FILE.to_owned()]
        );
        // A snapshot of the resulting store carries the lock, and a save refuses to
        // proceed if that inode is gone.
        let snapshot = store.snapshot().unwrap();
        assert_eq!(snapshot.lock_identity(), Some(identity_of(&fixture.lock())));
    }

    // -- refusals that must create nothing ---------------------------------

    #[test]
    fn a_read_only_projects_directory_refuses_before_the_store_is_created() {
        let fixture = Fixture::new();
        let projects = crate::project_config::projects_dir(&fixture.home);
        std::fs::create_dir_all(&projects).unwrap();
        std::fs::set_permissions(&projects, std::fs::Permissions::from_mode(0o500)).unwrap();

        let probe = fixture.store().existing_bytes();
        let snapshot = fixture.store().snapshot();
        std::fs::set_permissions(&projects, std::fs::Permissions::from_mode(0o700)).unwrap();

        let error = probe.expect_err("a read-only projects directory cannot be added to");
        assert!(
            format!("{error:#}").contains("not writable by its owner"),
            "{error:#}"
        );
        snapshot.expect_err("the snapshot must refuse the same route");
        assert!(
            !fixture.store_dir().exists(),
            "the refusal must come before anything is created"
        );
    }

    #[test]
    fn a_read_only_projects_directory_still_allows_an_existing_store() {
        let fixture = Fixture::new();
        fixture.with_config(OLD);
        let projects = crate::project_config::projects_dir(&fixture.home);
        std::fs::set_permissions(&projects, std::fs::Permissions::from_mode(0o500)).unwrap();

        let store = fixture.store();
        let snapshot = store.snapshot();
        let outcome = snapshot.map(|snapshot| store.save(&snapshot, NEW.as_bytes()));
        std::fs::set_permissions(&projects, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert_eq!(outcome.unwrap().unwrap(), ConfigSave::Replaced);
        assert_eq!(std::fs::read(fixture.config()).unwrap(), NEW.as_bytes());
    }

    #[test]
    fn a_symlinked_store_directory_is_refused() {
        let fixture = Fixture::new();
        let elsewhere = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(crate::project_config::projects_dir(&fixture.home)).unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), fixture.store_dir()).unwrap();

        let error = fixture
            .store()
            .existing_bytes()
            .expect_err("a symlinked store must refuse");
        assert!(
            format!("{error:#}").contains("reached through a symbolic link"),
            "{error:#}"
        );
        assert_eq!(
            std::fs::read_dir(elsewhere.path()).unwrap().count(),
            0,
            "nothing may be created through the link"
        );
    }

    #[test]
    fn a_checkout_alias_route_is_refused_before_anything_is_created() {
        let fixture = Fixture::new();
        // `~/.config` is a link into the active checkout, and the rest of the route
        // does not exist: the alias must be refused even though the tail is missing.
        let checkout_config = fixture.project.path().join(".config");
        std::fs::create_dir_all(&checkout_config).unwrap();
        std::os::unix::fs::symlink(&checkout_config, fixture.home.join(".config")).unwrap();

        let error = fixture
            .store()
            .snapshot()
            .expect_err("a checkout alias must refuse");
        assert!(
            format!("{error:#}").contains("resolves inside the active project"),
            "{error:#}"
        );
        assert!(
            entries(&checkout_config).is_empty(),
            "a refused alias must create nothing inside the checkout: {:?}",
            entries(&checkout_config)
        );
    }

    #[test]
    fn a_dotfile_alias_outside_the_checkout_is_kept() {
        let fixture = Fixture::new();
        let dotfiles = tempfile::tempdir().unwrap();
        let real_config = dotfiles.path().join("config");
        std::fs::create_dir_all(real_config.join("agent-vm")).unwrap();
        std::os::unix::fs::symlink(&real_config, fixture.home.join(".config")).unwrap();

        let store = fixture.store();
        let snapshot = store.snapshot().unwrap();
        assert_eq!(
            store.save(&snapshot, NEW.as_bytes()).unwrap(),
            ConfigSave::Created
        );

        let through_alias = real_config.join("agent-vm/projects");
        assert_eq!(
            std::fs::read(
                through_alias
                    .join(fixture.project.digest_hex())
                    .join(CONFIG_FILE)
            )
            .unwrap(),
            NEW.as_bytes(),
            "a stable, user-owned alias outside the checkout is written through"
        );
    }

    // -- existing files that must not be replaced ---------------------------

    #[test]
    fn a_read_only_config_is_refused_on_the_read_and_at_publish() {
        let fixture = Fixture::new();
        fixture.with_config(OLD);
        std::fs::set_permissions(fixture.config(), std::fs::Permissions::from_mode(0o400)).unwrap();
        let store = fixture.store();
        let before = snapshot_state(&fixture);

        assert!(
            store.existing_bytes().is_err(),
            "a read-only file must refuse"
        );
        assert!(store.snapshot().is_err(), "and so must the snapshot");
        assert_untouched(&fixture, (&before.0, before.1, before.2));
        assert_eq!(mode_of(&fixture.config()), 0o400);
    }

    #[test]
    fn an_untrusted_config_is_refused_without_being_read_or_replaced() {
        // Group-writable, hard-linked, symlinked, a directory, oversized and
        // non-UTF-8: every shape ADR-0040 refuses on the descriptor.
        for case in [
            "group-writable",
            "hard-linked",
            "symlinked",
            "not-a-file",
            "too-large",
            "not-utf8",
        ] {
            let fixture = Fixture::new();
            fixture.with_config(OLD);
            let config = fixture.config();
            let store = fixture.store();
            match case {
                "group-writable" => {
                    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o620))
                        .unwrap()
                }
                "hard-linked" => {
                    std::fs::hard_link(&config, fixture.store_dir().join("second-name")).unwrap()
                }
                "symlinked" => {
                    let target = fixture.store_dir().join("target.toml");
                    std::fs::write(&target, OLD).unwrap();
                    std::fs::remove_file(&config).unwrap();
                    std::os::unix::fs::symlink(&target, &config).unwrap();
                }
                "not-a-file" => {
                    std::fs::remove_file(&config).unwrap();
                    std::fs::create_dir(&config).unwrap();
                }
                "too-large" => {
                    std::fs::write(
                        &config,
                        "x".repeat(crate::config::MAX_CONFIG_FILE_BYTES as usize + 1),
                    )
                    .unwrap();
                    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                }
                "not-utf8" => {
                    std::fs::write(&config, [0xff, 0xfe, 0x00]).unwrap();
                    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                store.existing_bytes().is_err(),
                "{case}: the read-only observation must refuse an untrusted project config"
            );
            assert!(
                store.snapshot().is_err(),
                "{case}: the snapshot must refuse an untrusted project config"
            );
            if case != "not-a-file" && case != "symlinked" {
                assert!(
                    std::fs::symlink_metadata(&config)
                        .unwrap()
                        .file_type()
                        .is_file(),
                    "{case}: the file must be left in place"
                );
            }
        }
    }

    #[test]
    fn an_untrusted_config_lock_is_refused() {
        let fixture = Fixture::new();
        fixture.with_config(OLD);
        std::fs::write(fixture.lock(), b"").unwrap();
        std::fs::set_permissions(fixture.lock(), std::fs::Permissions::from_mode(0o660)).unwrap();

        let error = fixture
            .store()
            .existing_bytes()
            .expect_err("a group-writable config.lock must refuse");
        assert!(
            format!("{error:#}").contains("group- or other-writable"),
            "{error:#}"
        );
    }

    // -- ordinary-error atomicity on the real writer path -------------------

    #[test]
    fn a_healthy_save_is_the_control_for_the_fault_rows() {
        let fixture = Fixture::new();
        fixture.with_config(OLD);
        let store = fixture.store();
        let snapshot = store.snapshot().unwrap();
        assert_eq!(
            store.save(&snapshot, NEW.as_bytes()).unwrap(),
            ConfigSave::Replaced
        );
        assert_eq!(std::fs::read(fixture.config()).unwrap(), NEW.as_bytes());
        assert_eq!(mode_of(&fixture.config()), 0o600);
        assert!(no_temporaries(&fixture.store_dir()));
    }

    /// The stage and errno an injected fault must report, read from the error chain
    /// rather than from its rendered text, so a fault that moves to another step or
    /// carries another errno fails the row.
    fn assert_stage(
        error: &anyhow::Error,
        expected_stage: crate::host_paths::WriteStage,
        expected_errno: i32,
    ) {
        let failure = crate::host_paths::write_stage(error)
            .unwrap_or_else(|| panic!("no publication stage in {error:#}"));
        assert_eq!(
            (failure.stage(), failure.errno()),
            (expected_stage, Some(expected_errno)),
            "{error:#}"
        );
    }

    /// One fault, injected through the production writer core, on both the create and
    /// the update path — each with its own healthy control, so a create that always
    /// failed (or an update that never wrote) could not pass the fault expectations.
    fn fault_pair(
        fault: crate::host_paths::WriteFault,
        expected: &str,
        stage: crate::host_paths::WriteStage,
        errno: i32,
    ) {
        // -- update: the injected fault, then the same save without it ----------
        let fixture = Fixture::new();
        fixture.with_config(OLD);
        let store = fixture.store();
        let snapshot = store.snapshot().unwrap();
        let before = snapshot_state(&fixture);
        let error = store
            .save_with(
                &snapshot,
                NEW.as_bytes(),
                &Seams {
                    write_fault: Some(fault),
                    ..Seams::default()
                },
            )
            .expect_err("an injected publication fault must fail the save");
        assert!(
            format!("{error:#}").contains(expected),
            "{fault:?}: expected {expected:?}, got {error:#}"
        );
        assert_stage(&error, stage, errno);
        assert_untouched(&fixture, (&before.0, before.1, before.2));
        assert_eq!(
            store.save(&snapshot, NEW.as_bytes()).unwrap(),
            ConfigSave::Replaced,
            "{fault:?}: the healthy update control replaces the file"
        );
        assert_eq!(std::fs::read(fixture.config()).unwrap(), NEW.as_bytes());
        assert!(no_temporaries(&fixture.store_dir()));

        // -- create: the injected fault, then the same save without it ----------
        let fixture = Fixture::new();
        let store = fixture.store();
        let snapshot = store.snapshot().unwrap();
        let error = store
            .save_with(
                &snapshot,
                NEW.as_bytes(),
                &Seams {
                    write_fault: Some(fault),
                    ..Seams::default()
                },
            )
            .expect_err("an injected publication fault must fail the save");
        assert!(
            format!("{error:#}").contains(expected),
            "{fault:?}: expected {expected:?}, got {error:#}"
        );
        assert_stage(&error, stage, errno);
        assert!(
            !fixture.config().exists(),
            "{fault:?}: a failed create must leave the file absent"
        );
        assert!(
            no_temporaries(&fixture.store_dir()),
            "{fault:?}: a failed create must unlink its temporary"
        );
        assert!(
            entries(&fixture.store_dir()) == vec![CONFIG_LOCK_FILE.to_owned()],
            "{fault:?}: only the coordination lock survives a failed create: {:?}",
            entries(&fixture.store_dir())
        );
        assert_eq!(
            store.save(&snapshot, NEW.as_bytes()).unwrap(),
            ConfigSave::Created,
            "{fault:?}: the healthy create control creates the file"
        );
        assert_eq!(std::fs::read(fixture.config()).unwrap(), NEW.as_bytes());
    }

    #[test]
    fn a_partial_write_then_enospc_leaves_a_create_absent_and_an_update_intact() {
        fault_pair(
            crate::host_paths::WriteFault::PartialWriteThenNoSpace,
            "No space left on device",
            crate::host_paths::WriteStage::Write,
            libc::ENOSPC,
        );
    }

    #[test]
    fn a_chmod_failure_leaves_a_create_absent_and_an_update_intact() {
        fault_pair(
            crate::host_paths::WriteFault::ChmodRefused,
            "Operation not permitted",
            crate::host_paths::WriteStage::Chmod,
            libc::EPERM,
        );
    }

    #[test]
    fn a_rename_failure_leaves_a_create_absent_and_an_update_intact() {
        fault_pair(
            crate::host_paths::WriteFault::RenameFailed,
            "Input/output error",
            crate::host_paths::WriteStage::Rename,
            libc::EIO,
        );
    }

    #[test]
    fn a_pre_rename_veto_from_a_displaced_store_leaves_the_old_bytes() {
        let fixture = Fixture::new();
        fixture.with_config(OLD);
        let store = fixture.store();
        let snapshot = store.snapshot().unwrap();
        let before = snapshot_state(&fixture);
        let displaced = fixture.store_dir().with_extension("displaced");

        let outcome = store
            .save_with(
                &snapshot,
                NEW.as_bytes(),
                &Seams {
                    // The interval after the temporary is written and before the
                    // final check: the store the snapshot verified moves away.
                    just_before_rename: Some(&|| {
                        std::fs::rename(fixture.store_dir(), &displaced).unwrap();
                        std::fs::create_dir(fixture.store_dir()).unwrap();
                        std::fs::write(fixture.config(), OLD).unwrap();
                    }),
                    ..Seams::default()
                },
            )
            .unwrap();
        assert_eq!(outcome, ConfigSave::Refused(ConfigConflict::Displaced));
        let moved = displaced.join(CONFIG_FILE);
        assert_eq!(
            std::fs::read(&moved).unwrap(),
            OLD.as_bytes(),
            "the moved store keeps its bytes"
        );
        assert_eq!(identity_of(&moved), before.0, "and its inode");
        assert_eq!(mtime_of(&moved), before.1, "and its mtime");
        assert_eq!(mode_of(&moved), before.2, "and its mode");
        assert!(
            no_temporaries(&displaced),
            "the temporary the veto armed is unlinked from the store that held it"
        );
    }

    #[test]
    fn a_pre_rename_veto_from_a_changed_file_is_a_stale_refusal() {
        let fixture = Fixture::new();
        fixture.with_config(OLD);
        let store = fixture.store();
        let snapshot = store.snapshot().unwrap();
        let peer_bytes = "image = \"example.com/peer:6\"\n";

        let outcome = store
            .save_with(
                &snapshot,
                NEW.as_bytes(),
                &Seams {
                    // The interval after the temporary is written and before the
                    // final check: a same-user editor replaces the file in place.
                    just_before_rename: Some(&|| {
                        let replacement = fixture.store_dir().join("in-place");
                        std::fs::write(&replacement, peer_bytes).unwrap();
                        std::fs::set_permissions(
                            &replacement,
                            std::fs::Permissions::from_mode(0o600),
                        )
                        .unwrap();
                        std::fs::rename(&replacement, fixture.config()).unwrap();
                    }),
                    ..Seams::default()
                },
            )
            .unwrap();
        assert_eq!(outcome, ConfigSave::Refused(ConfigConflict::Stale));
        assert_eq!(
            std::fs::read(fixture.config()).unwrap(),
            peer_bytes.as_bytes()
        );
        assert!(no_temporaries(&fixture.store_dir()));
    }

    /// E3/D6: the same veto on the **create** path — the destination the temporary
    /// would be renamed onto does not exist, and the store it belongs to moves after
    /// the temporary is written. No destination, no temporary, a typed conflict.
    #[test]
    fn a_pre_rename_veto_on_an_absent_target_is_a_displaced_refusal() {
        let fixture = Fixture::new();
        fixture.with_store_only();
        let store = fixture.store();
        let snapshot = store.snapshot().unwrap();
        assert_eq!(snapshot.bytes(), None);
        let displaced = fixture.store_dir().with_extension("displaced");

        let outcome = store
            .save_with(
                &snapshot,
                NEW.as_bytes(),
                &Seams {
                    just_before_rename: Some(&|| {
                        std::fs::rename(fixture.store_dir(), &displaced).unwrap();
                        std::fs::create_dir(fixture.store_dir()).unwrap();
                        std::fs::set_permissions(
                            fixture.store_dir(),
                            std::fs::Permissions::from_mode(0o700),
                        )
                        .unwrap();
                    }),
                    ..Seams::default()
                },
            )
            .unwrap();
        assert_eq!(
            outcome,
            ConfigSave::Refused(ConfigConflict::Displaced),
            "a store that moved under an absent destination must not be created into"
        );
        assert!(
            !displaced.join(CONFIG_FILE).exists(),
            "the store the snapshot measured stays without a config"
        );
        assert!(
            !fixture.config().exists(),
            "and the live store gains no destination"
        );
        assert!(
            no_temporaries(&displaced),
            "the temporary the veto armed is unlinked from the store that held it"
        );
        assert!(no_temporaries(&fixture.store_dir()));
    }

    // -- the chain and the boundary, rechecked before publication ------------

    /// The reproducer [#737's correctness review] staged: the whole `projects/`
    /// entry moves after the save's walk, and a fresh live store takes its place.
    /// Every descriptor the save holds still names the detached tree, and every
    /// name inside that tree still agrees with the identity the snapshot recorded,
    /// so only stating `projects/` again from `agent-vm` can notice.
    fn move_projects_and_install_a_live_store(fixture: &Fixture) -> PathBuf {
        let projects = crate::project_config::projects_dir(&fixture.home);
        let detached = projects.with_extension("old");
        let live = projects.join(fixture.project.digest_hex());
        std::fs::rename(&projects, &detached).unwrap();
        std::fs::create_dir(&projects).unwrap();
        std::fs::set_permissions(&projects, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir(&live).unwrap();
        std::fs::set_permissions(&live, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(live.join(CONFIG_FILE), PEER).unwrap();
        std::fs::set_permissions(
            live.join(CONFIG_FILE),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        std::fs::write(live.join(CONFIG_LOCK_FILE), b"").unwrap();
        std::fs::set_permissions(
            live.join(CONFIG_LOCK_FILE),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        detached
    }

    /// A save that published here would report success while the live
    /// `projects/<id>/config.toml` still lacks the reference.
    fn assert_nothing_published_into_a_detached_store(
        fixture: &Fixture,
        detached: &Path,
        before: &(FileIdentity, (i64, i64), u32),
    ) {
        let detached_config = detached
            .join(fixture.project.digest_hex())
            .join(CONFIG_FILE);
        assert_eq!(
            std::fs::read(&detached_config).unwrap(),
            OLD.as_bytes(),
            "the detached tree the descriptors still name must keep its bytes"
        );
        assert_eq!(
            identity_of(&detached_config),
            before.0,
            "the detached file must keep its inode"
        );
        assert_eq!(
            std::fs::read(fixture.config()).unwrap(),
            PEER.as_bytes(),
            "the live file must not gain the new bytes"
        );
        assert!(
            no_temporaries(&detached.join(fixture.project.digest_hex())),
            "nothing may be left behind in the detached store"
        );
    }

    #[test]
    fn a_moved_projects_directory_before_the_rename_is_a_displaced_refusal() {
        let fixture = Fixture::new();
        fixture.with_config(OLD);
        let store = fixture.store();
        let snapshot = store.snapshot().unwrap();
        let before = snapshot_state(&fixture);
        let detached = std::cell::RefCell::new(None);

        let outcome = store
            .save_with(
                &snapshot,
                NEW.as_bytes(),
                &Seams {
                    // The interval after the temporary is written and before the
                    // final check.
                    just_before_rename: Some(&|| {
                        *detached.borrow_mut() =
                            Some(move_projects_and_install_a_live_store(&fixture));
                    }),
                    ..Seams::default()
                },
            )
            .expect("a moved ancestor is a typed refusal, not an error");
        assert_eq!(
            outcome,
            ConfigSave::Refused(ConfigConflict::Displaced),
            "a snapshot whose projects/ entry moved is displaced"
        );
        let detached = detached
            .borrow_mut()
            .take()
            .expect("the seam must have moved projects/");
        assert_nothing_published_into_a_detached_store(&fixture, &detached, &before);
    }

    #[test]
    fn a_moved_projects_directory_under_the_lock_is_a_displaced_refusal() {
        let fixture = Fixture::new();
        fixture.with_config(OLD);
        let store = fixture.store();
        let snapshot = store.snapshot().unwrap();
        let before = snapshot_state(&fixture);
        let detached = std::cell::RefCell::new(None);

        let outcome = store
            .save_with(
                &snapshot,
                NEW.as_bytes(),
                &Seams {
                    // The under-lock check's own interval: the same move, one
                    // checkpoint earlier.
                    after_lock_before_read: Some(&|| {
                        *detached.borrow_mut() =
                            Some(move_projects_and_install_a_live_store(&fixture));
                    }),
                    ..Seams::default()
                },
            )
            .expect("a moved ancestor is a typed refusal, not an error");
        assert_eq!(
            outcome,
            ConfigSave::Refused(ConfigConflict::Displaced),
            "a snapshot whose projects/ entry moved is displaced"
        );
        let detached = detached
            .borrow_mut()
            .take()
            .expect("the seam must have moved projects/");
        assert_nothing_published_into_a_detached_store(&fixture, &detached, &before);
    }

    #[test]
    fn a_config_made_group_writable_before_the_rename_is_a_stale_refusal() {
        let fixture = Fixture::new();
        fixture.with_config(OLD);
        let store = fixture.store();
        let snapshot = store.snapshot().unwrap();
        let before = snapshot_state(&fixture);

        let outcome = store
            .save_with(
                &snapshot,
                NEW.as_bytes(),
                &Seams {
                    // A `chmod` changes no identity, link count or size, so the
                    // boundary has to be measured again rather than compared.
                    just_before_rename: Some(&|| {
                        std::fs::set_permissions(
                            fixture.config(),
                            std::fs::Permissions::from_mode(0o660),
                        )
                        .unwrap();
                    }),
                    ..Seams::default()
                },
            )
            .unwrap();
        assert_eq!(
            outcome,
            ConfigSave::Refused(ConfigConflict::Stale),
            "a destination that left the trusted boundary must not be replaced"
        );
        assert_eq!(std::fs::read(fixture.config()).unwrap(), OLD.as_bytes());
        assert_eq!(identity_of(&fixture.config()), before.0);
        assert_eq!(mtime_of(&fixture.config()), before.1);
        assert_eq!(
            mode_of(&fixture.config()),
            0o660,
            "the authority the peer changed is the file's own, and nothing was published"
        );
        assert!(no_temporaries(&fixture.store_dir()));
    }

    #[test]
    fn a_store_made_group_writable_before_the_rename_is_a_displaced_refusal() {
        let fixture = Fixture::new();
        fixture.with_config(OLD);
        let store = fixture.store();
        let snapshot = store.snapshot().unwrap();
        let before = snapshot_state(&fixture);

        let outcome = store
            .save_with(
                &snapshot,
                NEW.as_bytes(),
                &Seams {
                    // The directory the write publishes through loses its
                    // authority, keeping its identity and its owner's write bit.
                    just_before_rename: Some(&|| {
                        std::fs::set_permissions(
                            fixture.store_dir(),
                            std::fs::Permissions::from_mode(0o770),
                        )
                        .unwrap();
                    }),
                    ..Seams::default()
                },
            )
            .unwrap();
        assert_eq!(
            outcome,
            ConfigSave::Refused(ConfigConflict::Displaced),
            "a directory that left the trusted boundary must not publish"
        );
        assert_untouched(&fixture, (&before.0, before.1, before.2));
        assert_eq!(
            mode_of(&fixture.store_dir()),
            0o770,
            "the authority the peer changed is the directory's own"
        );
    }

    #[test]
    fn the_conflict_reasons_are_fixed_text() {
        assert_eq!(
            ConfigConflict::Stale.reason(),
            "the project config changed after it was read, so nothing was written; read it again and repeat"
        );
        assert_eq!(
            ConfigConflict::Displaced.reason(),
            "the project config store or its config.lock changed after it was read, so nothing was written"
        );
    }

    /// The pure editor and the two ways a planned edit reaches the writer.
    ///
    /// Every expectation here is the **complete** output byte string, never a parsed
    /// comparison: a re-serialising editor returns a document that decodes identically
    /// while having rewritten CRLF, a final newline or a comment. The fixtures are
    /// written by hand for the same reason — deriving one with the editor under test
    /// would make the oracle agree with the bug.
    #[cfg(test)]
    mod image_edit {
        use super::*;

        const OLD: &str = "example.com/app:old";
        const NEW: &str = "example.com/app:new";

        fn image(reference: &str) -> ImageRef {
            ImageRef::from_config(reference).expect("a valid OCI reference")
        }

        fn plan(existing: &str) -> Result<ImageEditPlan, ImageEditRefusal> {
            plan_image_edit(Some(existing.as_bytes()), &image(NEW))
        }

        /// The plan's bytes and edit, asserting it is an update and that the edit's
        /// description of the splice matches the two byte strings.
        fn update(existing: &str, expected: &str) -> ImageEdit {
            let ImageEditPlan::Update { bytes, edit } = plan(existing).expect("an update") else {
                panic!("expected an update, got {:?}", plan(existing));
            };
            assert_eq!(
                bytes,
                expected.as_bytes(),
                "the whole file, byte for byte, after an update"
            );
            match &edit {
                ImageEdit::ReplacedValue { span } => {
                    let encoded = format!("\"{NEW}\"");
                    assert_eq!(
                        &expected.as_bytes()[..span.start],
                        &existing.as_bytes()[..span.start],
                        "every byte before the span is unchanged"
                    );
                    assert_eq!(
                        &expected.as_bytes()[span.start..span.start + encoded.len()],
                        encoded.as_bytes(),
                        "the span now holds the encoded reference"
                    );
                    assert_eq!(
                        &expected.as_bytes()[span.start + encoded.len()..],
                        &existing.as_bytes()[span.end..],
                        "every byte after the span is unchanged"
                    );
                }
                ImageEdit::Inserted { at, len } => {
                    assert_eq!(
                        *len,
                        expected.len() - existing.len(),
                        "the inserted byte count is the difference"
                    );
                    assert_eq!(
                        &expected.as_bytes()[..*at],
                        &existing.as_bytes()[..*at],
                        "every byte before the insertion is unchanged"
                    );
                    assert_eq!(
                        &expected.as_bytes()[*at + *len..],
                        &existing.as_bytes()[*at..],
                        "every byte after the insertion is unchanged"
                    );
                }
            }
            edit
        }

        fn inserted(existing: &str, expected: &str) -> ImageEdit {
            let edit = update(existing, expected);
            assert!(
                matches!(edit, ImageEdit::Inserted { .. }),
                "an existing file with no root image is inserted into, not replaced: {edit:?}"
            );
            edit
        }

        fn refusal(existing: &str) -> (ImageRefusal, Option<Position>) {
            match plan(existing) {
                Err(refusal) => (refusal.kind, refusal.location),
                Ok(plan) => panic!("expected a refusal, got {plan:?}"),
            }
        }

        // -- the update path: only the value token changes -----------------------

        #[test]
        fn an_update_replaces_only_the_value_token() {
            let edit = update(
                "image = \"example.com/app:old\"\n",
                "image = \"example.com/app:new\"\n",
            );
            let ImageEdit::ReplacedValue { span } = edit else {
                panic!("the value token was replaced");
            };
            assert_eq!(span.start, 8, "the span starts at the value token");
            assert_eq!(span.end, 8 + OLD.len() + 2, "and ends after its quote");
        }

        #[test]
        fn a_quoted_or_escaped_image_key_keeps_its_own_spelling() {
            update(
                "\"image\" = 'example.com/app:old' # keep\n",
                "\"image\" = \"example.com/app:new\" # keep\n",
            );
            update(
                "\"\\u0069mage\" = 'example.com/app:old'\n",
                "\"\\u0069mage\" = \"example.com/app:new\"\n",
            );
            update(
                "'image' = \"example.com/app:old\"\n",
                "'image' = \"example.com/app:new\"\n",
            );
        }

        #[test]
        fn a_literal_value_with_tabs_and_an_inline_comment_is_replaced() {
            update(
                "image\t=\t'example.com/app:old'\t# kept\tcomment\n",
                "image\t=\t\"example.com/app:new\"\t# kept\tcomment\n",
            );
        }

        #[test]
        fn a_multiline_value_is_replaced_by_one_line() {
            update(
                "image = \"\"\"\nexample.com/app:old\"\"\" # note\n",
                "image = \"example.com/app:new\" # note\n",
            );
            update(
                "image = '''example.com/app:old''' # note\n",
                "image = \"example.com/app:new\" # note\n",
            );
        }

        #[test]
        fn crlf_and_mixed_line_endings_are_never_normalised() {
            update(
                "# project\r\nimage = 'example.com/app:old'\r\n",
                "# project\r\nimage = \"example.com/app:new\"\r\n",
            );
            update(
                "# heading\nimage = \"example.com/app:old\"\r\n[network]\n",
                "# heading\nimage = \"example.com/app:new\"\r\n[network]\n",
            );
        }

        #[test]
        fn a_missing_final_newline_stays_missing() {
            update(
                "image = \"example.com/app:old\"",
                "image = \"example.com/app:new\"",
            );
        }

        #[test]
        fn non_ascii_before_the_value_is_preserved() {
            let existing = "# caf\u{e9} \u{2192} \u{4e2d}\u{6587}\nimage = 'example.com/app:old'\n";
            let expected =
                "# caf\u{e9} \u{2192} \u{4e2d}\u{6587}\nimage = \"example.com/app:new\"\n";
            update(existing, expected);
        }

        #[test]
        fn an_unknown_nan_value_is_preserved_exactly() {
            update(
                "future_flag = nan\nimage = \"example.com/app:old\"\n",
                "future_flag = nan\nimage = \"example.com/app:new\"\n",
            );
        }

        #[test]
        fn a_root_image_beside_a_source_image_is_replaced_at_the_root() {
            update(
                "image = \"example.com/app:old\"\n\n[[sources]]\nname = \"home\"\npath = \"~/.config/agent-vm/config.toml\"\ntrust = true\nallow = true\nimage = \"example.com/source:1\"\n",
                "image = \"example.com/app:new\"\n\n[[sources]]\nname = \"home\"\npath = \"~/.config/agent-vm/config.toml\"\ntrust = true\nallow = true\nimage = \"example.com/source:1\"\n",
            );
        }

        // -- the insert path: one assignment in the root prelude -----------------

        /// An existing zero-byte file keeps the convention it has: no final newline,
        /// so the assignment adds none. (The absent file's seed is a different case
        /// and carries its own.)
        #[test]
        fn an_empty_file_gets_only_the_assignment_and_no_final_newline() {
            inserted("", "image = \"example.com/app:new\"");
        }

        #[test]
        fn a_comments_only_file_keeps_its_final_newline_convention() {
            inserted("# note\n", "# note\nimage = \"example.com/app:new\"\n");
            inserted("# note", "# note\nimage = \"example.com/app:new\"");
            inserted(
                "# one\n# two\n",
                "# one\n# two\nimage = \"example.com/app:new\"\n",
            );
        }

        #[test]
        fn a_root_only_file_is_appended_to() {
            inserted(
                "tools = []\n",
                "tools = []\nimage = \"example.com/app:new\"\n",
            );
            inserted("tools = []", "tools = []\nimage = \"example.com/app:new\"");
            inserted(
                "tools = []\n\n",
                "tools = []\n\nimage = \"example.com/app:new\"\n",
            );
        }

        #[test]
        fn an_indented_sources_header_gets_the_assignment_above_it() {
            inserted(
                "  [[sources]]\nname = \"home\"\npath = \"~/.config/agent-vm/config.toml\"\ntrust = true\nallow = true\n",
                "image = \"example.com/app:new\"\n  [[sources]]\nname = \"home\"\npath = \"~/.config/agent-vm/config.toml\"\ntrust = true\nallow = true\n",
            );
        }

        #[test]
        fn a_nested_first_header_is_found_through_its_implicit_parent() {
            inserted(
                "[outer.inner]\nx = 1\n",
                "image = \"example.com/app:new\"\n[outer.inner]\nx = 1\n",
            );
            inserted(
                "tools = []\n[a.b.c]\nx = 1\n",
                "tools = []\nimage = \"example.com/app:new\"\n[a.b.c]\nx = 1\n",
            );
        }

        #[test]
        fn a_file_heading_and_a_table_note_keep_their_places() {
            inserted(
                "# Project settings\n# two heading lines\n\n# The home source.\n[[sources]]\nname = \"home\"\npath = \"~/.config/agent-vm/config.toml\"\ntrust = true\nallow = true\n",
                "# Project settings\n# two heading lines\nimage = \"example.com/app:new\"\n\n# The home source.\n[[sources]]\nname = \"home\"\npath = \"~/.config/agent-vm/config.toml\"\ntrust = true\nallow = true\n",
            );
        }

        #[test]
        fn a_root_key_above_a_table_note_keeps_both() {
            inserted(
                "tools = []\n# note for the table\n[[sources]]\nname = \"home\"\npath = \"~/.config/agent-vm/config.toml\"\ntrust = true\nallow = true\n",
                "tools = []\nimage = \"example.com/app:new\"\n# note for the table\n[[sources]]\nname = \"home\"\npath = \"~/.config/agent-vm/config.toml\"\ntrust = true\nallow = true\n",
            );
        }

        /// D4/AC3: a valid multiline root value whose last line begins with `#` is
        /// the tail of that value, not a comment introducing the next table. A scan
        /// that reads physical lines moves the assignment into the middle of the
        /// string, which is a refusal at best and a corrupted value at worst.
        #[test]
        fn a_multiline_root_value_ending_on_a_comment_looking_line_is_not_a_note() {
            inserted(
                "description = \"\"\"\ntwo\n# tail\"\"\"\n[network]\nallow = []\n",
                "description = \"\"\"\ntwo\n# tail\"\"\"\nimage = \"example.com/app:new\"\n[network]\nallow = []\n",
            );
            // The same shape with CRLF, where the value's last line is `# tail\"\"\"`.
            inserted(
                "description = \"\"\"\r\ntwo\r\n# tail\"\"\"\r\n[network]\r\nallow = []\r\n",
                "description = \"\"\"\r\ntwo\r\n# tail\"\"\"\r\nimage = \"example.com/app:new\"\r\n[network]\r\nallow = []\r\n",
            );
        }

        /// The control for the test above: a real table note below a multiline root
        /// value still moves with its table, so fixing the false positive did not
        /// produce a false negative.
        #[test]
        fn a_table_note_below_a_multiline_root_value_still_stays_with_its_table() {
            inserted(
                "description = \"\"\"\ntwo\n# tail\"\"\"\n\n# The network table.\n[network]\nallow = []\n",
                "description = \"\"\"\ntwo\n# tail\"\"\"\nimage = \"example.com/app:new\"\n\n# The network table.\n[network]\nallow = []\n",
            );
        }

        #[test]
        fn a_heading_without_a_note_keeps_its_blank_separator() {
            inserted(
                "# Project settings\n\n[[sources]]\nname = \"home\"\npath = \"~/.config/agent-vm/config.toml\"\ntrust = true\nallow = true\n",
                "# Project settings\n\nimage = \"example.com/app:new\"\n[[sources]]\nname = \"home\"\npath = \"~/.config/agent-vm/config.toml\"\ntrust = true\nallow = true\n",
            );
        }

        #[test]
        fn a_header_inside_a_comment_or_a_string_is_not_a_header() {
            // No real header: the file is only comments, root keys and a lookalike.
            inserted(
                "# [[fake]]\nnote = \"[[fake]]\"\n",
                "# [[fake]]\nnote = \"[[fake]]\"\nimage = \"example.com/app:new\"\n",
            );
            // A real header after both lookalikes, which is where the assignment goes.
            inserted(
                "# [[fake]]\nnote = \"[[fake]]\"\n[network]\nx = 1\n",
                "# [[fake]]\nnote = \"[[fake]]\"\nimage = \"example.com/app:new\"\n[network]\nx = 1\n",
            );
        }

        #[test]
        fn an_inserted_line_uses_the_adjacent_eol() {
            // The header is the first line, so the line below it decides.
            inserted(
                "[[sources]]\r\nname = \"home\"\r\npath = \"~/.config/agent-vm/config.toml\"\r\ntrust = true\r\nallow = true\r\n",
                "image = \"example.com/app:new\"\r\n[[sources]]\r\nname = \"home\"\r\npath = \"~/.config/agent-vm/config.toml\"\r\ntrust = true\r\nallow = true\r\n",
            );
            // Mixed file: the line above the insertion point decides, and the other
            // endings keep theirs.
            inserted(
                "tools = []\r\n[network]\r\n",
                "tools = []\r\nimage = \"example.com/app:new\"\r\n[network]\r\n",
            );
            inserted(
                "tools = []\n[network]\r\n",
                "tools = []\nimage = \"example.com/app:new\"\n[network]\r\n",
            );
            inserted(
                "# heading\r\n\r\n[[sources]]\nname = \"home\"\npath = \"~/.config/agent-vm/config.toml\"\ntrust = true\nallow = true\n",
                "# heading\r\n\r\nimage = \"example.com/app:new\"\r\n[[sources]]\nname = \"home\"\npath = \"~/.config/agent-vm/config.toml\"\ntrust = true\nallow = true\n",
            );
        }

        #[test]
        fn a_byte_order_mark_stays_at_the_start_of_the_file() {
            update(
                "\u{feff}image = 'example.com/app:old'\n",
                "\u{feff}image = \"example.com/app:new\"\n",
            );
            inserted(
                "\u{feff}[[sources]]\nname = \"home\"\npath = \"~/.config/agent-vm/config.toml\"\ntrust = true\nallow = true\n",
                "\u{feff}image = \"example.com/app:new\"\n[[sources]]\nname = \"home\"\npath = \"~/.config/agent-vm/config.toml\"\ntrust = true\nallow = true\n",
            );
        }

        #[test]
        fn no_eol_anywhere_falls_back_to_lf() {
            inserted(
                "[[sources]]",
                "image = \"example.com/app:new\"\n[[sources]]",
            );
        }

        // -- the absent file -----------------------------------------------------

        #[test]
        fn an_absent_file_gets_the_issue_seed_byte_for_byte() {
            let plan = plan_image_edit(None, &image(NEW)).expect("the seed");
            let ImageEditPlan::Create { bytes } = plan else {
                panic!("an absent file is seeded, not updated: {plan:?}");
            };
            assert_eq!(
            bytes,
            "image = \"example.com/app:new\"\n\n[[sources]]\nname = \"home\"\npath = \"~/.config/agent-vm/config.toml\"\ntrust = true\nallow = true\n"
                .as_bytes(),
            "the creation bytes are the issue's seed, not the loader's implicit default"
        );
        }

        // -- the no-op -----------------------------------------------------------

        #[test]
        fn an_identical_root_reference_is_unchanged() {
            for existing in [
                "image = \"example.com/app:new\"\n",
                "image = 'example.com/app:new'\r\n",
                "image = \"example.com/app:new\"",
                "image = \"\"\"example.com/app:new\"\"\"\n",
            ] {
                let plan = plan(existing).expect("a no-op");
                assert_eq!(plan, ImageEditPlan::Unchanged, "{existing:?}");
                assert_eq!(
                    plan.bytes(),
                    None,
                    "nothing to publish, so the caller cannot rewrite the file"
                );
            }
        }

        // -- refusals ------------------------------------------------------------

        #[test]
        fn invalid_toml_is_refused_with_a_location_and_no_file_text() {
            let (kind, location) = refusal("tools = []\n\nimage = 1 2\n");
            assert_eq!(kind, ImageRefusal::InvalidToml);
            assert_eq!(
                location,
                Some(Position { line: 3, column: 9 }),
                "the parser's own offset, as a 1-based line and column"
            );
            let message = plan("image = \"SECRET-737\n").unwrap_err().to_string();
            assert!(message.contains("line 1, column 20"), "{message}");
            assert!(
                !message.contains("SECRET-737"),
                "a refusal must never echo config bytes: {message}"
            );
        }

        #[test]
        fn a_duplicate_key_is_refused_where_it_repeats() {
            let (kind, location) =
                refusal("image = \"example.com/app:old\"\nimage = \"example.com/app:new\"\n");
            assert_eq!(kind, ImageRefusal::InvalidToml);
            assert_eq!(location, Some(Position { line: 2, column: 1 }));
        }

        #[test]
        fn a_non_string_root_image_is_refused_at_its_own_position() {
            // The parser gives a span for every one of these, so the refusal can say
            // where the value it cannot use is instead of only what is wrong.
            for existing in [
                "image = 123\n",
                "image = []\n",
                "image = { a = 1 }\n",
                "image = true\n",
                "image.a = \"example.com/app:old\"\n",
            ] {
                let (kind, location) = refusal(existing);
                assert_eq!(kind, ImageRefusal::NotAString, "{existing:?}");
                assert_eq!(
                    location,
                    Some(Position { line: 1, column: 1 }),
                    "{existing:?}: the root key's own position"
                );
            }
            // A table header is not a value either: the parser's span names the key
            // inside the brackets, so only the line is asserted here.
            for (existing, line) in [("[image]\nx = 1\n", 1), ("\n\n[[image]]\nx = 1\n", 3)] {
                let (kind, location) = refusal(existing);
                assert_eq!(kind, ImageRefusal::NotAString, "{existing:?}");
                assert_eq!(
                    location.map(|position| position.line),
                    Some(line),
                    "{existing:?}"
                );
            }
            let message = plan("image = 123\n").unwrap_err().to_string();
            assert!(
                message.ends_with("(line 1, column 1)"),
                "the fixed reason carries the position: {message}"
            );
        }

        #[test]
        fn a_mis_scoped_image_is_refused_naming_its_table() {
            let cases: [(&str, MisplacedSite); 10] = [
                (
                    "[[sources]]\nname = \"home\"\npath = \"~/.config/agent-vm/config.toml\"\ntrust = true\nallow = true\nimage = \"example.com/app:old\"\n",
                    MisplacedSite::Sources,
                ),
                (
                    "sources = [{ name = \"home\", path = \"~/.config/agent-vm/config.toml\", image = \"example.com/app:old\" }]\n",
                    MisplacedSite::Sources,
                ),
                (
                    "sources.image = \"example.com/app:old\"\n",
                    MisplacedSite::Sources,
                ),
                (
                    "[network]\nimage = \"example.com/app:old\"\n",
                    MisplacedSite::Network,
                ),
                (
                    "network = { image = \"example.com/app:old\" }\n",
                    MisplacedSite::Network,
                ),
                (
                    "network.image = \"example.com/app:old\"\n",
                    MisplacedSite::Network,
                ),
                (
                    "[[tools]]\nname = \"t\"\ncommand = \"t\"\nimage = \"example.com/app:old\"\n",
                    MisplacedSite::Tools,
                ),
                (
                    "tools = [{ name = \"t\", command = \"t\", image = \"example.com/app:old\" }]\n",
                    MisplacedSite::Tools,
                ),
                (
                    "[mount_sets.dev]\nallow = []\nimage = \"example.com/app:old\"\n",
                    MisplacedSite::MountSets,
                ),
                (
                    "egress_sets = { dev = { image = \"example.com/app:old\" } }\n",
                    MisplacedSite::EgressSets,
                ),
            ];
            for (existing, site) in cases {
                let (kind, location) = refusal(existing);
                assert_eq!(kind, ImageRefusal::MisplacedImage(site), "{existing:?}");
                assert!(
                    location.is_some(),
                    "{existing:?}: where it was found is part of the refusal"
                );
                let message = plan(existing).unwrap_err().to_string();
                assert!(
                    message.contains(site.label()),
                    "the refusal names {}: {message}",
                    site.label()
                );
            }
            let (_, location) = refusal(
                "[[sources]]\nname = \"home\"\npath = \"~/.config/agent-vm/config.toml\"\ntrust = true\nallow = true\nimage = \"example.com/app:old\"\n",
            );
            assert_eq!(
                location,
                Some(Position { line: 6, column: 1 }),
                "the misplaced key's own line and column"
            );
        }

        #[test]
        fn an_image_inside_a_tool_environment_is_not_misplaced() {
            // `env.image` is an environment variable's name: a direct key of the tool
            // table is what a misplaced root key produces, not a nested one.
            inserted(
                "[[tools]]\nname = \"t\"\ncommand = \"t\"\nenv = { image = \"debug\" }\n",
                "image = \"example.com/app:new\"\n[[tools]]\nname = \"t\"\ncommand = \"t\"\nenv = { image = \"debug\" }\n",
            );
        }

        #[test]
        fn invalid_utf8_and_an_oversized_file_are_refused() {
            let error = plan_image_edit(Some(&[0x69, 0xff, 0xfe]), &image(NEW)).unwrap_err();
            assert_eq!(error.kind, ImageRefusal::NotUtf8);

            let oversized = vec![b'a'; crate::config::MAX_CONFIG_FILE_BYTES as usize + 1];
            let error = plan_image_edit(Some(&oversized), &image(NEW)).unwrap_err();
            assert_eq!(
                error.kind,
                ImageRefusal::TooLarge {
                    bytes: oversized.len(),
                    edited: false
                }
            );
        }

        #[test]
        fn the_refusals_are_fixed_text() {
            assert_eq!(
                ImageEditRefusal::new(ImageRefusal::NotAString).to_string(),
                "the root \"image\" is not a string value, so it cannot name an image; nothing was written"
            );
            assert_eq!(
                ImageEditRefusal::at(
                    ImageRefusal::MisplacedImage(MisplacedSite::Sources),
                    Position { line: 6, column: 1 }
                )
                .to_string(),
                "found an \"image\" inside [[sources]] that belongs to that table rather than to the root \
             config; move it above the first table header and repeat (line 6, column 1)"
            );
        }

        // -- the plan reaches the real writer and the real loader ----------------

        const LOAD_FIXTURE: &str = "image = \"example.com/app:old\"\nallow_tools = [\"probe\"]\n\n[[sources]]\nname = \"home\"\npath = \"~/.config/agent-vm/config.toml\"\ntrust = true\nallow = true\n\n[[tools]]\nname = \"probe\"\ncommand = \"/bin/true\"\n";

        #[test]
        fn an_unchanged_plan_publishes_nothing() {
            let fixture = Fixture::new();
            fixture.with_config("image = \"example.com/app:new\"\ntools = []\n");
            let store = fixture.store();
            let snapshot = store.snapshot().unwrap();
            let before = snapshot_state(&fixture);

            let plan = plan_image_edit(snapshot.bytes().map(str::as_bytes), &image(NEW)).unwrap();
            assert_eq!(plan, ImageEditPlan::Unchanged);
            assert_eq!(plan.bytes(), None);

            // Even handed the identical bytes, the writer publishes nothing: no rename,
            // so no new inode, mode or mtime.
            assert_eq!(
                store
                    .save(&snapshot, snapshot.bytes().unwrap().as_bytes())
                    .unwrap(),
                ConfigSave::Unchanged
            );
            assert_eq!(
                std::fs::read(fixture.config()).unwrap(),
                "image = \"example.com/app:new\"\ntools = []\n".as_bytes()
            );
            assert_eq!(
                identity_of(&fixture.config()),
                before.0,
                "the inode is kept"
            );
            assert_eq!(mtime_of(&fixture.config()), before.1, "the mtime is kept");
            assert_eq!(mode_of(&fixture.config()), before.2, "the mode is kept");
            assert!(no_temporaries(&fixture.store_dir()));
        }

        /// F1 (#737 × #749): the writer's narrow edit succeeds on a file carrying
        /// the retired key, leaves those bytes alone, and the **loader** then
        /// refuses the file with the migration. The insert and replace controls
        /// below are the pair: neither edit needs the key to be understood.
        #[test]
        fn a_planned_update_preserves_a_retired_key_and_the_loader_refuses_it() {
            let fixture = Fixture::new();
            fixture.with_config(LOAD_FIXTURE);
            let store = fixture.store();
            let snapshot = store.snapshot().unwrap();

            let plan = plan_image_edit(snapshot.bytes().map(str::as_bytes), &image(NEW)).unwrap();
            let ImageEditPlan::Update { bytes, .. } = &plan else {
                panic!("a different root image is an update: {plan:?}");
            };
            assert_eq!(
            bytes,
            "image = \"example.com/app:new\"\nallow_tools = [\"probe\"]\n\n[[sources]]\nname = \"home\"\npath = \"~/.config/agent-vm/config.toml\"\ntrust = true\nallow = true\n\n[[tools]]\nname = \"probe\"\ncommand = \"/bin/true\"\n".as_bytes()
        );
            assert_eq!(
                store.save(&snapshot, plan.bytes().unwrap()).unwrap(),
                ConfigSave::Replaced
            );
            assert_eq!(std::fs::read(fixture.config()).unwrap(), *bytes);

            // The saved bytes keep the retired key verbatim, and the image is the
            // narrow edit: nothing else moved.
            let saved = std::fs::read_to_string(fixture.config()).unwrap();
            assert_eq!(saved, *String::from_utf8(bytes.clone()).unwrap());
            assert!(saved.contains("allow_tools = [\"probe\"]\n"));

            // Then the loader refuses exactly that key, with the migration.
            let error = crate::config::load(&crate::config::ConfigPaths::for_test_captured(
                fixture.home.clone(),
                &fixture.project,
            ))
            .expect_err("the retired key is refused on the next read");
            assert_eq!(
                error.to_string(),
                format!(
                    "config: {:?}: allow_tools: allow_tools is retired: every [[tools]] \
                     declaration is launchable, so there is no launch allow list to replace it. \
                     Delete the key, or set allow = false on a source that must supply nothing \
                     automatically; move the automatic grants you still want to default_tools = \
                     [...] before the first table header (the shell always gets them, a direct \
                     command only when you write the key); settle a bare name two sources \
                     declare with use_tools in the project config; launch one file's tool as \
                     <alias>:<tool>; and after editing a pinned source, approve its changed bytes \
                     again",
                    fixture.config()
                )
            );
        }

        /// The insert half of F1's pair: a file with no root `image` gains one and
        /// keeps its retired key byte-identically.
        #[test]
        fn an_inserted_image_preserves_a_retired_key_and_the_loader_refuses_it() {
            let fixture = Fixture::new();
            fixture.with_config("allow_tools = [\"probe\"]\n\n[[tools]]\nname = \"probe\"\ncommand = \"/bin/true\"\n");
            let store = fixture.store();
            let snapshot = store.snapshot().unwrap();

            let plan = plan_image_edit(snapshot.bytes().map(str::as_bytes), &image(NEW)).unwrap();
            let ImageEditPlan::Update { bytes, .. } = &plan else {
                panic!("an absent root image is an insertion: {plan:?}");
            };
            assert_eq!(
                std::str::from_utf8(bytes).unwrap(),
                // The narrow edit inserts the root key after the file's last
                // top-level key; the retired line's own bytes are untouched.
                format!(
                    "allow_tools = [\"probe\"]\n\nimage = {NEW:?}\n[[tools]]\nname = \"probe\"\ncommand = \"/bin/true\"\n"
                )
            );
            assert_eq!(
                store.save(&snapshot, plan.bytes().unwrap()).unwrap(),
                ConfigSave::Replaced
            );
            assert_eq!(std::fs::read(fixture.config()).unwrap(), *bytes);

            let error = crate::config::load(&crate::config::ConfigPaths::for_test_captured(
                fixture.home.clone(),
                &fixture.project,
            ))
            .expect_err("the retired key is refused on the next read");
            assert!(
                error.to_string().contains("allow_tools is retired"),
                "{error}"
            );
        }

        #[test]
        fn an_inserted_image_loads_with_the_new_root_reference() {
            let fixture = Fixture::new();
            fixture.with_config("tools = []\n\n[[sources]]\nname = \"home\"\npath = \"~/.config/agent-vm/config.toml\"\ntrust = true\nallow = true\n");
            let store = fixture.store();
            let snapshot = store.snapshot().unwrap();

            let plan = plan_image_edit(snapshot.bytes().map(str::as_bytes), &image(NEW)).unwrap();
            let ImageEditPlan::Update { bytes, edit } = &plan else {
                panic!("an absent root image is an insert: {plan:?}");
            };
            assert!(matches!(edit, ImageEdit::Inserted { .. }), "{edit:?}");
            assert_eq!(
            bytes,
            "tools = []\n\nimage = \"example.com/app:new\"\n[[sources]]\nname = \"home\"\npath = \"~/.config/agent-vm/config.toml\"\ntrust = true\nallow = true\n".as_bytes()
        );
            assert_eq!(
                store.save(&snapshot, plan.bytes().unwrap()).unwrap(),
                ConfigSave::Replaced
            );
            assert_eq!(std::fs::read(fixture.config()).unwrap(), *bytes);

            let report = crate::config::load(&crate::config::ConfigPaths::for_test_captured(
                fixture.home.clone(),
                &fixture.project,
            ))
            .expect("the planned file loads");
            assert_eq!(report.images().project().unwrap().reference().as_str(), NEW);
            assert_eq!(report.sources().entries().len(), 1);
        }

        #[test]
        fn a_seeded_create_loads_with_the_new_root_reference() {
            let fixture = Fixture::new();
            let store = fixture.store();
            let snapshot = store.snapshot().unwrap();
            assert_eq!(snapshot.bytes(), None);

            let plan = plan_image_edit(snapshot.bytes().map(str::as_bytes), &image(NEW)).unwrap();
            assert!(matches!(plan, ImageEditPlan::Create { .. }), "{plan:?}");
            assert_eq!(
                store.save(&snapshot, plan.bytes().unwrap()).unwrap(),
                ConfigSave::Created
            );
            let report = crate::config::load(&crate::config::ConfigPaths::for_test_captured(
                fixture.home.clone(),
                &fixture.project,
            ))
            .expect("the seeded file loads");
            assert_eq!(report.images().project().unwrap().reference().as_str(), NEW);
            assert_eq!(report.sources().entries().len(), 1);
        }
    }
}
