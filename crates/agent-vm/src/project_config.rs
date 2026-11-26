//! Where a **project config** lives (ADR-0073): host-managed, inside the
//! protected config directory, keyed by the project's full digest, and never
//! in the repository.
//!
//! # Why not `<cwd>/.agent-vm/config.toml`
//!
//! Who can write the repository, or a branch the user merely checks out,
//! wrote that file, so loading it let viewing someone else's code change the
//! user's agent-vm configuration (#732). The legacy path is only ever
//! `lstat`ed, by `doctor`, to say it is ignored — unless the project config
//! explicitly sources it, in which case the notice is suppressed (ADR-0074).
//!
//! # Why the full digest
//!
//! The same 64-hex id as `image-pins.json` and `allowances.json`
//! ([`ProjectDir::digest_hex`]): authority must not depend on a truncated hash.

use std::path::{Path, PathBuf};

use crate::project::ProjectDir;

/// Inside [`crate::config::USER_CONFIG_DIR_RELATIVE`]; one directory per project id.
pub(crate) const PROJECTS_DIR: &str = "projects";
pub(crate) const CONFIG_FILE: &str = "config.toml";
/// The `[[sources]]` seed a new project config is created with (#737), below the
/// root `image` the command writes.
///
/// Explicit rather than the loader's implicit single `home` source: a file created
/// by a command should say which files it reads. It is the same source the loader
/// would have assumed, so a seeded project reads the host's user config exactly as
/// a project config that omits `sources` does, and a later `sources = []` stays the
/// user's decision to remove it.
pub(crate) const HOME_SOURCES_SEED: &str = concat!(
    "[[sources]]\n",
    "name = \"home\"\n",
    "path = \"~/.config/agent-vm/config.toml\"\n",
    "trust = true\n",
    "allow = true\n",
);

/// The permanent coordination inode inside one project store that serializes
/// `config.toml` writers (#737 `image set-default`, #739 `agent-vm config`).
///
/// Separate from the pin store's `pins.lock`: the two stores never share a lock
/// edge, so a peer holding `pins.lock` cannot block a config write and a config
/// writer never takes a lock under `pins.lock` (ADR-0078).
pub(crate) const CONFIG_LOCK_FILE: &str = "config.lock";
/// Where the project tier used to be read from, relative to the project.
pub(crate) const LEGACY_RELATIVE: &str = ".agent-vm/config.toml";

pub(crate) fn projects_dir(home: &Path) -> PathBuf {
    home.join(crate::config::USER_CONFIG_DIR_RELATIVE)
        .join(PROJECTS_DIR)
}

/// Single project-store directory seam for #733 (`config.toml`), #736
/// (`pins.json`), #737 (`image set-default`), and #739 (`agent-vm config`).
pub(crate) fn project_dir(home: &Path, project: &ProjectDir) -> PathBuf {
    projects_dir(home).join(project.digest_hex())
}

pub(crate) fn path(home: &Path, project: &ProjectDir) -> PathBuf {
    project_dir(home, project).join(CONFIG_FILE)
}

/// The project tier as discovery found it: the file, plus everything the
/// ADR-0073 store route is measured against.
///
/// A named value rather than the three positional arguments a reader would
/// otherwise take (`config`, `home`, `project_root`, two of them paths the
/// callee could not tell apart from each other or from the file it reads), and
/// one value so the bytes read are always the bytes whose route was checked.
/// The state with no root is therefore not an omitted field but
/// [`RouteAnchor::Uncaptured`].
#[derive(Clone, Debug)]
pub(crate) struct ProjectTierPaths {
    pub(crate) config: PathBuf,
    pub(crate) route: RouteAnchor,
}

impl ProjectTierPaths {
    /// A hand-built tier for this crate's own tests, which predate the store and
    /// have no captured root: [`check_store_route`] then reports
    /// [`StoreRoute::Unchecked`]. Production builds [`RouteAnchor::Captured`].
    #[cfg(test)]
    pub(crate) fn uncaptured(config: PathBuf) -> Self {
        Self {
            config,
            route: RouteAnchor::Uncaptured,
        }
    }
}

/// What the store route is checked against.
#[derive(Clone, Debug)]
pub(crate) enum RouteAnchor {
    /// The `$HOME` the config path was derived from, the canonical project
    /// root from the command's single [`crate::project::ProjectDir`] capture
    /// (ADR-0073 D5), and that capture's `(dev, ino)`. All three travel with the
    /// path so a check cannot be run against one home while the file is read
    /// through another, and a checkout-confined read can refuse a project root
    /// replaced after capture instead of trusting the replacement.
    Captured {
        home: PathBuf,
        root: PathBuf,
        #[cfg_attr(not(test), allow(dead_code))] // read by the untrusted route walker
        root_id: crate::host_paths::FileIdentity,
    },
    /// No captured root: only tests build it, and no production caller does.
    /// Named rather than an `Option` field so that a reader which acquires this
    /// state must write it, and see the cost stated on
    /// [`StoreRoute::Unchecked`].
    #[cfg_attr(not(test), allow(dead_code))]
    Uncaptured,
}

impl RouteAnchor {
    /// The checkout boundary this anchor admits, or `None` for a route with no
    /// captured root.
    ///
    /// The root identity the walk checks and the root identity in the boundary
    /// are the same captured `(dev, ino)`, so the two cannot disagree when the
    /// path is replaced between the capture and this call.
    pub(crate) fn checkout_boundary(&self) -> anyhow::Result<Option<CheckoutBoundary>> {
        match self {
            Self::Captured { root, root_id, .. } => {
                Ok(Some(CheckoutBoundary::measure(root, *root_id)?))
            }
            Self::Uncaptured => Ok(None),
        }
    }
}

/// Whether the host project-config store exists and is safe to descend into
/// before opening `config.toml` (ADR-0073).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum StoreRoute {
    /// `projects/` or `projects/<id>` does not exist (`NotFound`).
    Absent,
    /// `projects/` and `projects/<id>` are real directories and do not alias
    /// into the active checkout.
    Present,
    /// Nothing was checked, because the tier carried no root: reachable only
    /// through [`RouteAnchor::Uncaptured`]. Neither the symlinked-store refusal
    /// nor the alias refusal ran, so the caller must let the file's own
    /// measurement decide. An outcome this module reports, not a branch the
    /// reader could skip without saying so.
    Unchecked,
}

/// Reject store-route symlinks (`projects/` or `projects/<id>`) and any
/// ancestor alias (e.g. `~/.config/agent-vm -> <checkout>/...`) that redirects
/// the project store inside the active project before opening `config.toml`.
///
/// Running from `$HOME`, `$HOME/.config` or `/` is not exempt. It stays allowed
/// only where the store is reached unaliased — `canonicalize(parent)` equal to
/// `canonicalize(home)/.config/agent-vm/projects/<id>` — so a dotfile-managed
/// `~/.config/agent-vm` symlink refuses the project tier there too (ADR-0073
/// Decision 3). Under the ADR-0040 stable-route assumption this is not a
/// race-free lookup; concurrent host-side directory swaps remain out of scope.
pub(crate) fn check_store_route(project: &ProjectTierPaths) -> anyhow::Result<StoreRoute> {
    let RouteAnchor::Captured { home, root, .. } = &project.route else {
        return Ok(StoreRoute::Unchecked);
    };
    let config_path = &project.config;
    let projects = projects_dir(home);
    match std::fs::symlink_metadata(&projects) {
        Ok(meta) if meta.file_type().is_symlink() => anyhow::bail!(
            "config: {}: the project config refuses a projects directory reached through a symbolic link",
            crate::one_line::quoted_path(config_path),
        ),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(StoreRoute::Absent),
        Err(e) => anyhow::bail!(
            "config: {}: reading metadata for {}: {}",
            crate::one_line::quoted_path(config_path),
            crate::one_line::quoted_path(&projects),
            e.kind(),
        ),
    }
    // Descriptor-first directory trust, before the store child is looked up (or
    // declared absent): a `projects/` directory this user does not exclusively
    // own could redirect a later child lookup, even while the child is missing
    // now. This deliberately tightens the project-config read path, which
    // previously trusted `projects/` only by its spelling.
    let projects_fd = match rustix::fs::open(
        &projects,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(StoreRoute::Absent),
        Err(error) => anyhow::bail!(
            "config: {}: opening {}: {error}",
            crate::one_line::quoted_path(config_path),
            crate::one_line::quoted_path(&projects),
        ),
    };
    let projects_facts =
        crate::host_paths::opened_dir_facts(&projects_fd, &crate::one_line::quoted_path(&projects))
            .map_err(|error| {
                anyhow::anyhow!(
                    "config: {}: {error:#}",
                    crate::one_line::quoted_path(config_path)
                )
            })?;
    if let Some(refusal) = crate::config_authority::authority_dir_refusal(
        crate::config_authority::DirFacts {
            is_dir: true,
            uid: projects_facts.uid,
            mode: projects_facts.mode,
        },
        crate::host_paths::current_euid(),
    ) {
        anyhow::bail!(
            "config: {}: the project config refuses a projects directory that {}; make it owned by you and not group- or other-writable",
            crate::one_line::quoted_path(config_path),
            crate::allowances::refusal_clause(&refusal),
        );
    }
    let Some(parent) = config_path.parent() else {
        anyhow::bail!(
            "config: {}: the project config has no parent directory",
            crate::one_line::quoted_path(config_path),
        );
    };
    match std::fs::symlink_metadata(parent) {
        Ok(meta) if meta.file_type().is_symlink() => anyhow::bail!(
            "config: {}: the project config refuses a project store directory reached through a symbolic link",
            crate::one_line::quoted_path(config_path),
        ),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(StoreRoute::Absent),
        Err(e) => anyhow::bail!(
            "config: {}: reading metadata for {}: {}",
            crate::one_line::quoted_path(config_path),
            crate::one_line::quoted_path(parent),
            e.kind(),
        ),
    }
    let canonical_parent = std::fs::canonicalize(parent).map_err(|e| {
        anyhow::anyhow!(
            "config: {}: resolving project store directory failed ({:?})",
            crate::one_line::quoted_path(config_path),
            e.kind(),
        )
    })?;
    let expected_canonical_parent = std::fs::canonicalize(home).ok().and_then(|canon_home| {
        parent.file_name().map(|id| {
            canon_home
                .join(crate::config::USER_CONFIG_DIR_RELATIVE)
                .join(PROJECTS_DIR)
                .join(id)
        })
    });
    if resolves_inside_project(
        &canonical_parent,
        expected_canonical_parent.as_deref(),
        root,
    ) {
        anyhow::bail!(
            "config: {}: the project config refuses a store directory that resolves inside the active project",
            crate::one_line::quoted_path(config_path),
        );
    }
    Ok(StoreRoute::Present)
}

/// True when `canonical` lands inside the active checkout `root`, excluding the
/// normal unaliased `$HOME` layout (`expected`).
///
/// Shared by the project store check (ADR-0073), the `:trust` user-config route
/// checks (ADR-0074) and the project config writer's route walk, so the three
/// cannot disagree about what "aliased into the active project" means.
pub(crate) fn resolves_inside_project(
    canonical: &Path,
    expected: Option<&Path>,
    root: &Path,
) -> bool {
    canonical.starts_with(root) && expected != Some(canonical)
}

/// The reader's ancestry rule for one traversed directory (ADR-0076 R2.2), stated
/// once so the project config writer can apply the same one:
///
/// a directory on an admitted route is **controlled** when this user owns it with
/// neither group nor other write permission, or root owns it with neither. A
/// root-owned sticky parent is judged on its child by the caller, which is why that
/// clause is not part of this predicate.
pub(crate) fn ancestry_controlled(facts: &crate::host_paths::OpenedDirFacts, euid: u32) -> bool {
    (facts.uid == euid || facts.uid == 0) && facts.mode & 0o022 == 0
}

/// The highest ancestor of `path` that the reader's ancestry rule refuses, walking
/// **down from `/`** with one no-follow directory descriptor per component.
///
/// Descriptor-bound for the reason the ADR-0076 route walker is: each component is
/// judged by `fstat` on the descriptor that was opened from the descriptor above
/// it, so a name swapped after it was spelled cannot substitute a directory this
/// walk already passed. `Ok(None)` means every ancestor could be opened, is a
/// directory, and is controlled; the final component (`path` itself) is the
/// caller's to measure. An ancestor that cannot be opened is not a pass: it is the
/// refusal, because a route whose ancestry cannot be measured cannot be trusted.
pub(crate) fn uncontrolled_ancestor(path: &Path, euid: u32) -> anyhow::Result<Option<PathBuf>> {
    use rustix::fs::{Mode, OFlags};

    let mut ancestors: Vec<PathBuf> = path.ancestors().skip(1).map(Path::to_path_buf).collect();
    ancestors.reverse();
    let mut current: Option<(std::os::fd::OwnedFd, PathBuf)> = None;
    for ancestor in ancestors {
        let opened = match &current {
            None => rustix::fs::open(
                &ancestor,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ),
            Some((fd, _)) => rustix::fs::openat(
                fd,
                ancestor
                    .file_name()
                    .expect("an ancestor below `/` has a name"),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ),
        }
        .map_err(|error| {
            anyhow::anyhow!(
                "the ancestry of the admitted route directory could not be measured ({error})"
            )
        })?;
        let facts = crate::host_paths::opened_dir_facts(&opened, &"an ancestor directory")?;
        if !ancestry_controlled(&facts, euid) {
            return Ok(Some(ancestor));
        }
        current = Some((opened, ancestor));
    }
    Ok(None)
}

/// Is the captured project root still the directory its own name in its captured
/// parent names?
///
/// One `open` of the parent and one `statat(SYMLINK_NOFOLLOW)` of the root's own
/// entry, compared to the captured `(dev, ino)`: spelling-free, so a case variant or
/// a Unicode normalization variant is decided by the same identity, and a *sibling*
/// of the root is untouched because only the root's own entry is named. Shared by
/// the ADR-0076 route walker and the #737 config writer, so neither decides what
/// "the active project" is from a path a replacement could have taken over. A root
/// at `/` has no parent entry and returns `true`.
pub(crate) fn captured_root_is_live(root: &Path, root_id: crate::host_paths::FileIdentity) -> bool {
    let (Some(parent), Some(name)) = (root.parent(), root.file_name()) else {
        return true;
    };
    let Ok(parent_fd) = rustix::fs::open(
        parent,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) else {
        return false;
    };
    require_captured_root_entry(&parent_fd, name, (root_id.dev, root_id.ino)).is_ok()
}

/// The shared refusal of U1/U2, once a canonicalized route is known to land
/// inside the active checkout. `what` is the refused clause and `remedy` what the
/// user can do about it; the canonical path is never echoed, as the route checks
/// never validate the bytes they canonicalized.
fn refuse_inside_project(
    user_config: &Path,
    canonical: &Path,
    expected: Option<&Path>,
    root: &Path,
    what: &str,
    remedy: &str,
) -> anyhow::Result<()> {
    if resolves_inside_project(canonical, expected, root) {
        anyhow::bail!(
            "config: {}: the user config refuses {what}: the working directory is an ancestor of \
             it; {remedy}",
            crate::one_line::quoted_path(user_config),
        );
    }
    Ok(())
}

/// ADR-0074 D3: the `:trust` read's **parent/ancestor** route check, run before
/// `config.toml` is opened.
///
/// A `~/.config` or `~/.config/agent-vm` symlink into the checkout would let
/// repository-controlled bytes pass the file's own measurement, so it is refused
/// first. A missing or unresolvable parent on an *existing* file fails closed: the
/// caller only gets here after `lstat` found the file, so a parent that cannot be
/// canonicalized is a route this module will not vouch for.
pub(crate) fn check_user_parent_route(
    user_config: &Path,
    route: &RouteAnchor,
) -> anyhow::Result<()> {
    let RouteAnchor::Captured { home, root, .. } = route else {
        return Ok(());
    };
    let parent = user_config.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "config: {}: the user config has no parent directory",
            crate::one_line::quoted_path(user_config),
        )
    })?;
    let canonical_parent = std::fs::canonicalize(parent).map_err(|error| {
        anyhow::anyhow!(
            "config: {}: resolving the user config directory failed ({:?})",
            crate::one_line::quoted_path(user_config),
            error.kind(),
        )
    })?;
    let expected = std::fs::canonicalize(home)
        .ok()
        .map(|canon_home| canon_home.join(crate::config::USER_CONFIG_DIR_RELATIVE));
    refuse_inside_project(
        user_config,
        &canonical_parent,
        expected.as_deref(),
        root,
        "a config directory that resolves inside the active project",
        "run agent-vm from a directory that does not contain it, or change the link to name a \
         directory outside the active project",
    )
}

/// ADR-0074 D3: the `:trust` read's **final component** route check, called only
/// when the no-follow open reported a symlink and before its target is opened.
///
/// Outside-checkout dotfile symlinks keep ADR-0040's behaviour; one resolving
/// inside `root` (and not the unaliased home file) is refused, so a checkout alias
/// contributes neither tools, image nor authority. A dangling or looping link fails
/// closed without echoing the target.
pub(crate) fn check_user_symlink_target(
    user_config: &Path,
    route: &RouteAnchor,
) -> anyhow::Result<()> {
    let RouteAnchor::Captured { home, root, .. } = route else {
        return Ok(());
    };
    let canonical_target = std::fs::canonicalize(user_config).map_err(|error| {
        anyhow::anyhow!(
            "config: {}: resolving the user config symbolic link failed ({:?})",
            crate::one_line::quoted_path(user_config),
            error.kind(),
        )
    })?;
    let expected = std::fs::canonicalize(home)
        .ok()
        .map(|canon_home| canon_home.join(crate::config::USER_CONFIG_RELATIVE));
    refuse_inside_project(
        user_config,
        &canonical_target,
        expected.as_deref(),
        root,
        "a symbolic link whose target resolves inside the active project",
        "run agent-vm from a directory that does not contain its target, or replace the link with \
         a regular file",
    )
}

/// The checkout-controlled boundary a non-default `trust = true` route may never
/// enter (ADR-0076 R2.2).
///
/// Unions the captured canonical working directory (`project_root`) with EVERY
/// enclosing Git worktree above it, all the way up to `/` (every ancestor
/// directory containing a `.git` marker), with no `$HOME/.git` exclusion: a nearer
/// `.git` can never shrink the boundary, and a file inside a dotfile worktree is
/// repository-controlled and therefore not eligible for a non-default `trust =
/// true` source. The isolated `~/.config/agent-vm/config.toml` branch keeps its
/// own ADR-0074/ADR-0040 compatibility.
///
/// Stores BOTH canonical paths and `(dev, ino)` descriptor identities so an
/// alternate spelling (case variant on a case-insensitive filesystem, an
/// uncollapsed or symlinked spelling) cannot step into a boundary directory
/// without matching an identity.
///
/// The captured root's own identity is one of those identities by construction,
/// not by re-measuring the path: see [`Self::measure`].
pub(crate) struct CheckoutBoundary {
    boundary_ids: std::collections::BTreeSet<(u64, u64)>,
    boundary_roots: Vec<PathBuf>,
}

impl CheckoutBoundary {
    /// Measure the boundary of the **captured** project root `root`, whose
    /// identity the command captured once in
    /// [`crate::project::ProjectDir::identity`].
    ///
    /// `root_id` is inserted as the root's identity, and the root's path is
    /// never re-`stat`ed for that purpose. A load captures the project, then
    /// measures this boundary, and one `RENAME_SWAP` between the two
    /// observations left the captured root outside its own boundary: a
    /// `trust = false` source read from it was classified `external` and the
    /// checkout hard-link rule did not apply (17 of 2000 runs at this change's
    /// parent; the instrumented leak had the walk's captured `(dev, ino)`
    /// differ from the single id this function measured). Authority for the
    /// root therefore comes from the capture, which no later look at the path
    /// can disagree with.
    ///
    /// Everything *above* the root is still discovered from the path, because
    /// the enclosing worktrees that widen the boundary have no captured
    /// identity; they can only add directories to the boundary, and replacing an
    /// ancestor is the stable-route assumption ADR-0040 already states. Every
    /// ancestor is inspected from the filesystem root downwards so a nearer
    /// `.git` never hides a farther one, and an unstatable ancestor fails
    /// closed: a boundary that cannot be measured is a boundary that cannot be
    /// trusted.
    pub(crate) fn measure(
        root: &Path,
        root_id: crate::host_paths::FileIdentity,
    ) -> anyhow::Result<Self> {
        let mut boundary_ids = std::collections::BTreeSet::new();
        boundary_ids.insert((root_id.dev, root_id.ino));
        let mut boundary_roots = vec![root.to_path_buf()];
        let fail = |kind: std::io::ErrorKind| {
            anyhow::anyhow!("config: refusing to measure the active checkout's boundary ({kind:?})")
        };
        let mut ancestor = root.parent();
        while let Some(dir) = ancestor {
            if std::fs::symlink_metadata(dir.join(".git")).is_ok() {
                let meta = std::fs::metadata(dir).map_err(|error| fail(error.kind()))?;
                use std::os::unix::fs::MetadataExt as _;
                boundary_ids.insert((meta.dev(), meta.ino()));
                boundary_roots.push(dir.to_path_buf());
            }
            ancestor = dir.parent();
        }
        Ok(Self {
            boundary_ids,
            boundary_roots,
        })
    }

    /// A boundary assembled from identities and roots, for the route tests that
    /// must place `/` itself inside a boundary.
    #[cfg(test)]
    pub(crate) fn for_tests(ids: &[(u64, u64)], roots: &[PathBuf]) -> Self {
        Self {
            boundary_ids: ids.iter().copied().collect(),
            boundary_roots: roots.to_vec(),
        }
    }

    /// True when the opened directory (identity) or its cursor path is inside the
    /// boundary. IDs are checked first because an opened component cannot lie
    /// about its own descriptor, while a spelling can.
    fn contains(&self, dir_id: (u64, u64), cursor: &Path) -> bool {
        self.boundary_ids.contains(&dir_id)
            || self
                .boundary_roots
                .iter()
                .any(|boundary| cursor.starts_with(boundary))
    }
}

/// A non-default `trust = true` source whose whole route was walked and whose
/// final component was opened with `openat(O_NOFOLLOW)` from the verified parent
/// descriptor (ADR-0076 R2.2).
///
#[derive(Debug)]
pub(crate) struct OpenedTrustedSource {
    /// The `fstat` facts of the exact parent directory descriptor the final
    /// component was opened from.
    pub(crate) parent_dir: crate::config_authority::DirFacts,
    pub(crate) final_component: crate::host_paths::FinalComponent,
    /// `Some` iff the final component opened as a regular file.
    pub(crate) opened: Option<crate::host_paths::OpenedRegularFile>,
}

/// One queue entry of a route walk: a normal component, `.`, or `..`.
#[derive(Clone)]
enum RouteStep {
    Name(std::ffi::OsString),
    Here,
    Up,
}

/// A route walk's symlink budget. A loop is a route this module will not
/// follow; 40 matches the kernel's own limit for one path resolution.
const MAX_SYMLINK_HOPS: usize = 40;

/// Split a path into route steps, prepending them to `queue` in order.
///
/// Never echoes component bytes: route checks validate paths, not values.
fn push_path_steps(queue: &mut std::collections::VecDeque<RouteStep>, path: &Path) {
    let mut steps = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {}
            std::path::Component::CurDir => steps.push(RouteStep::Here),
            std::path::Component::ParentDir => steps.push(RouteStep::Up),
            std::path::Component::Normal(name) => steps.push(RouteStep::Name(name.to_os_string())),
        }
    }
    for step in steps.into_iter().rev() {
        queue.push_front(step);
    }
}

/// B1's spelling-independent half: is the captured root still the directory its
/// on-disk name in its captured parent named?
///
/// One `open` of the parent and one `statat` of the root's own entry, compared
/// to the captured `(dev, ino)` — no walk step and no comparison of the route's
/// spelling, so a case-variant (or Unicode-normalization) alias of a replaced
/// root is refused exactly like the exact spelling. A *sibling* of the root is
/// untouched: this names the root's own entry, never some other child of the
/// parent. A root at `/` has no parent entry and its routes are already inside
/// the boundary.
#[cfg_attr(not(test), allow(dead_code))] // Phase 4's untrusted route walker
fn check_captured_root_entry(
    root: &Path,
    root_id: (u64, u64),
) -> std::result::Result<(), UntrustedReadError> {
    use rustix::fs::{Mode, OFlags};
    let (Some(parent), Some(name)) = (root.parent(), root.file_name()) else {
        return Ok(());
    };
    let parent_fd = rustix::fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| UntrustedReadError::RootReplaced)?;
    require_captured_root_entry(&parent_fd, name, root_id)
}

/// The walk step's spelling-free checkpoint: in the directory descriptor a step
/// is about to open a child from, the captured root's own entry name must still
/// resolve to the captured `(dev, ino)`.
///
/// Identity plus the root's *on-disk* name is spelling-independent, which is what
/// B1 asks for; a lexical test is not. A route can reach this directory through
/// an alias of the root's name — a case variant, a Unicode normalization variant,
/// or a differently-cased prefix above it — and a `starts_with` comparison on the
/// spelling the route wrote matches none of them, so no checkpoint arms and a
/// swap landing before the walk opens the root's own component is classified by
/// where the route ends up instead of being refused. This check asks the
/// filesystem's own directory, from the descriptor the walk already holds, for the
/// entry that must carry the captured identity: every one of those spellings is
/// decided by the same `(dev, ino)`. Because it names the captured root's entry
/// and not the child being opened, a genuine sibling of the root stays admitted.
fn require_captured_root_entry(
    parent_fd: &std::os::fd::OwnedFd,
    name: &std::ffi::OsStr,
    root_id: (u64, u64),
) -> std::result::Result<(), UntrustedReadError> {
    let entry = match rustix::fs::statat(parent_fd, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(entry) => entry,
        Err(rustix::io::Errno::NOENT) => return Err(UntrustedReadError::RootReplaced),
        Err(error) => return Err(UntrustedReadError::Io(anyhow::anyhow!(error))),
    };
    // `st_dev` is already `u64` on Linux and narrower on macOS, so the
    // conversion is useless on exactly one platform (see `host_paths`).
    #[allow(clippy::useless_conversion)]
    let identity = (u64::try_from(entry.st_dev).unwrap_or(0), entry.st_ino);
    if rustix::fs::FileType::from_raw_mode(entry.st_mode) != rustix::fs::FileType::Directory
        || identity != root_id
    {
        return Err(UntrustedReadError::RootReplaced);
    }
    Ok(())
}

/// A step's own name as the step's own `statat` saw it, immediately before the
/// step opened that name.
#[derive(Clone, Copy, Debug)]
struct StepEntry {
    identity: (u64, u64),
    kind: rustix::fs::FileType,
}

impl StepEntry {
    fn of(stat: &rustix::fs::Stat) -> Self {
        Self {
            // Useless on Linux only; see `require_captured_root_entry`.
            #[allow(clippy::useless_conversion)]
            identity: (u64::try_from(stat.st_dev).unwrap_or(0), stat.st_ino),
            kind: rustix::fs::FileType::from_raw_mode(stat.st_mode),
        }
    }
}

/// The step invariant: the identity a step's own name carried in its own
/// `statat`, immediately before its `openat`, must be the identity that
/// `openat` returned.
///
/// This is the check that sees a rename which starts and ends inside one step.
/// Two `renamex_np(RENAME_SWAP)`es defeat every checkpoint that compares a name
/// against the *captured* identity: the pre-open stat of the captured root's
/// entry sees the captured root, the first swap puts the replacement at the
/// name, the `openat` opens it, and the second swap restores the captured root
/// before the closing stat, so both captured-identity checkpoints pass and the
/// walk descends into the replacement. Here they cannot: one identity was seen
/// before the open, the opened descriptor carries another, and a descriptor's
/// identity cannot be swapped after it is open. No name comparison and no case
/// folding is involved — a legitimately admitted sibling has its own stat and
/// its own open agree.
fn require_step_identity(
    seen: StepEntry,
    opened: (u64, u64),
) -> std::result::Result<(), UntrustedReadError> {
    if seen.identity != opened {
        return Err(UntrustedReadError::RootReplaced);
    }
    Ok(())
}

/// `statat(SYMLINK_NOFOLLOW)` a step's own name: the identity its `openat` must
/// then produce. A missing entry has nothing to open and is reported here.
fn stat_step_entry(
    dir_fd: &std::os::fd::OwnedFd,
    name: &std::ffi::OsStr,
) -> std::result::Result<StepEntry, UntrustedReadError> {
    let entry = match rustix::fs::statat(dir_fd, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(entry) => entry,
        Err(rustix::io::Errno::NOENT) => return Err(UntrustedReadError::NotFound),
        Err(error) => return Err(UntrustedReadError::Io(anyhow::anyhow!(error))),
    };
    Ok(StepEntry::of(&entry))
}

/// A symlink step opens no descriptor to compare, so its `statat` is paired with
/// a second one around the `readlinkat`: the link text the walk follows must
/// belong to the entry the first stat saw. A `..` step and a missing entry open
/// nothing at all and are decided where they occur (see the walk).
fn require_entry_unchanged(
    dir_fd: &std::os::fd::OwnedFd,
    name: &std::ffi::OsStr,
    seen: StepEntry,
) -> std::result::Result<(), UntrustedReadError> {
    require_step_identity(seen, stat_step_entry(dir_fd, name)?.identity)
}

/// A directory's own change stamps. Every `rename` of an entry in a directory
/// updates that directory's `mtime` and `ctime`, so a snapshot that is unchanged
/// across one step proves no entry of that directory was renamed inside the step.
#[derive(Clone, Copy, PartialEq, Eq)]
struct DirChangeStamp {
    changed: (i64, i64, i64, i64),
}

fn dir_change_stamp(
    fd: &std::os::fd::OwnedFd,
) -> std::result::Result<DirChangeStamp, UntrustedReadError> {
    let stat =
        rustix::fs::fstat(fd).map_err(|error| UntrustedReadError::Io(anyhow::anyhow!(error)))?;
    Ok(DirChangeStamp {
        changed: (
            stat.st_mtime as i64,
            stat.st_mtime_nsec as i64,
            stat.st_ctime as i64,
            stat.st_ctime_nsec as i64,
        ),
    })
}

/// The captured-root checkpoint re-read is only meaningful if nothing renamed an
/// entry of that directory between it and the use of the opened child. A step's
/// own stat and its open can agree on the replacement while that checkpoint saw
/// the captured root before the rename and sees it again after another — the
/// window the race harness finds (1 in 4 000 runs before this check). Directory
/// stamps close it without a name: if the directory's `mtime` and `ctime` are
/// unchanged, no entry was renamed, so every observation inside the step saw one
/// state and an aliased step could only have opened the captured root. The stamp
/// is only taken on the captured root's own parent, so an unrelated rename in a
/// busy directory elsewhere on the route cannot refuse a read. A filesystem whose
/// timestamps are too coarse to separate two renames inside one step would miss
/// them; APFS and ext4 carry nanoseconds.
fn require_dir_unchanged(
    fd: &std::os::fd::OwnedFd,
    stamp: DirChangeStamp,
) -> std::result::Result<(), UntrustedReadError> {
    if dir_change_stamp(fd)? != stamp {
        return Err(UntrustedReadError::RootReplaced);
    }
    Ok(())
}

/// Read a symlink's target without following it.
#[cfg_attr(not(test), allow(dead_code))] // Phase 4's untrusted route walker
fn read_link_target(
    dir_fd: &std::os::fd::OwnedFd,
    name: &std::ffi::OsStr,
) -> std::result::Result<PathBuf, UntrustedReadError> {
    let target = rustix::fs::readlinkat(dir_fd, name, Vec::new())
        .map_err(|error| UntrustedReadError::Io(anyhow::anyhow!(error)))?;
    Ok(PathBuf::from(
        <std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(target.as_bytes()),
    ))
}

/// ADR-0076 R2.2: validate the **entire traversed route** of a non-default
/// `trust = true` source and open it no-follow from the validated parent.
///
/// The route is walked from `/` with a synchronized directory-descriptor stack:
/// every component is opened `openat(O_RDONLY | O_DIRECTORY | O_NOFOLLOW)` and
/// judged from `fstat` on the descriptor that was opened, so verification and the
/// eventual file open are bound to the same descriptors rather than to a path
/// that could be swapped in between. `..` pops the stack (descriptor, cursor and
/// facts together); an absolute symlink target resets it to `/`.
///
/// Refuses, before any byte of the file is read: an untrusted or group/world-
/// writable ancestor, a foreign-owned symlink, a symlink hop budget overrun, any
/// directory inside the [`CheckoutBoundary`], a missing file, and a final symlink
/// whose target resolves inside the checkout (that last one is refused with the
/// inside-checkout wording, not as a generic symlink).
pub(crate) fn open_trusted_source_route(
    path: &Path,
    decl: crate::config_sources::Declaration,
    route: &RouteAnchor,
) -> anyhow::Result<OpenedTrustedSource> {
    open_trusted_source_route_checkpointed(path, decl, route, |_| {})
}

/// [`open_trusted_source_route`] with a checkpoint after each traversed
/// directory, so a test can swap a component mid-walk and prove the walk stays
/// anchored to the descriptors it opened.
pub(crate) fn open_trusted_source_route_checkpointed(
    path: &Path,
    decl: crate::config_sources::Declaration,
    route: &RouteAnchor,
    mut after_step: impl FnMut(&Path),
) -> anyhow::Result<OpenedTrustedSource> {
    use crate::host_paths::{OpenedDirFacts, opened_dir_facts};
    use rustix::fs::{Mode, OFlags};

    let boundary = route.checkout_boundary()?;
    let euid = crate::host_paths::current_euid();
    let refuse = |what: &str| {
        anyhow::anyhow!(
            "config: {}: trusted source ({decl}) refuses {what}; move the file somewhere the host \
             user controls exclusively, outside the active project, or drop trust = true so the \
             source is pinned instead",
            crate::one_line::quoted_path(path),
        )
    };
    let not_found = || {
        anyhow::anyhow!(
            "config: {}: not found; the project config sources it as {decl}",
            crate::one_line::quoted_path(path),
        )
    };

    struct OpenDir {
        fd: std::os::fd::OwnedFd,
        path: PathBuf,
        facts: OpenedDirFacts,
    }

    let root_fd = rustix::fs::open(
        Path::new("/"),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| anyhow::anyhow!(error))
    .map_err(|error| refuse(&format!("a route it cannot start ({error})")))?;
    let root_facts = opened_dir_facts(&root_fd, &"the filesystem root")?;
    let mut stack: Vec<OpenDir> = vec![OpenDir {
        fd: root_fd,
        path: PathBuf::from("/"),
        facts: root_facts,
    }];

    let mut queue: std::collections::VecDeque<RouteStep> = std::collections::VecDeque::new();
    let mut hops = 0usize;

    if !path.is_absolute() {
        return Err(refuse("a path that is not absolute"));
    }
    push_path_steps(&mut queue, path);

    while let Some(step) = queue.pop_front() {
        let last = queue.is_empty();
        match step {
            RouteStep::Here => {
                if last {
                    return Err(refuse("a path whose final component is `.`"));
                }
            }
            RouteStep::Up => {
                let top = stack.last().expect("the descriptor stack starts at `/`");
                if let Some(boundary) = &boundary
                    && boundary.contains(top.facts.identity(), &top.path)
                {
                    return Err(refuse(
                        "a path that traverses the active checkout or an enclosing Git worktree",
                    ));
                }
                if stack.len() > 1 {
                    stack.pop();
                }
                if last {
                    return Err(refuse("a path whose final component is `..`"));
                }
            }
            RouteStep::Name(name) => {
                let cur = stack.last().expect("the descriptor stack starts at `/`");
                let opened = rustix::fs::openat(
                    &cur.fd,
                    &name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                );
                let child_fd = if last {
                    // The final component: open it as a file, never as a
                    // directory, and classify a symlink instead of following it.
                    match rustix::fs::openat(
                        &cur.fd,
                        &name,
                        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                        Mode::empty(),
                    ) {
                        Ok(fd) => {
                            let parent_dir = crate::config_authority::DirFacts {
                                is_dir: true,
                                uid: cur.facts.uid,
                                mode: cur.facts.mode,
                            };
                            let opened =
                                crate::host_paths::opened_regular_from_descriptor(fd, path)?;
                            return Ok(OpenedTrustedSource {
                                parent_dir,
                                final_component: crate::host_paths::FinalComponent::Regular(
                                    opened.facts(),
                                ),
                                opened: Some(opened),
                            });
                        }
                        Err(rustix::io::Errno::NOENT) => return Err(not_found()),
                        Err(rustix::io::Errno::LOOP) | Err(rustix::io::Errno::NOTDIR) => {
                            let parent_dir = crate::config_authority::DirFacts {
                                is_dir: true,
                                uid: cur.facts.uid,
                                mode: cur.facts.mode,
                            };
                            check_trusted_symlink_target_against_boundary(path, boundary.as_ref())?;
                            return Ok(OpenedTrustedSource {
                                parent_dir,
                                final_component: crate::host_paths::FinalComponent::Symlink,
                                opened: None,
                            });
                        }
                        Err(error) => {
                            return Err(anyhow::anyhow!(
                                "config: {}: trusted source ({decl}) could not be opened ({error})",
                                crate::one_line::quoted_path(path),
                            ));
                        }
                    }
                } else {
                    opened
                };
                match child_fd {
                    Ok(child_fd) => {
                        let child_facts = opened_dir_facts(&child_fd, &"a traversed directory")?;
                        // A root-owned sticky parent lets a non-owner unlink or
                        // rename a child it does not own, so the child must be ours.
                        if cur.facts.uid == 0
                            && cur.facts.mode & 0o1000 != 0
                            && child_facts.uid != euid
                        {
                            return Err(refuse("a directory another user controls"));
                        }
                        let controlled = ancestry_controlled(&child_facts, euid)
                            || (child_facts.uid == 0 && child_facts.mode & 0o1000 != 0);
                        if !controlled {
                            return Err(refuse(
                                "a path with an untrusted or writable ancestor directory",
                            ));
                        }
                        let child_path = cur.path.join(&name);
                        if let Some(boundary) = &boundary
                            && boundary.contains(child_facts.identity(), &child_path)
                        {
                            return Err(refuse(
                                "a path inside the active checkout or an enclosing Git worktree",
                            ));
                        }
                        let step_path = child_path.clone();
                        stack.push(OpenDir {
                            fd: child_fd,
                            path: child_path,
                            facts: child_facts,
                        });
                        after_step(&step_path);
                    }
                    Err(rustix::io::Errno::LOOP) | Err(rustix::io::Errno::NOTDIR) => {
                        let stat = rustix::fs::statat(
                            &cur.fd,
                            &name,
                            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                        )
                        .map_err(|error| anyhow::anyhow!(error))?;
                        if rustix::fs::FileType::from_raw_mode(stat.st_mode)
                            != rustix::fs::FileType::Symlink
                        {
                            return Err(refuse("a path component that is not a directory"));
                        }
                        // A writable parent lets anyone replace the link itself.
                        if cur.facts.mode & 0o022 != 0 {
                            return Err(refuse("a symbolic link inside a writable directory"));
                        }
                        if stat.st_uid != 0 && stat.st_uid != euid {
                            return Err(refuse("a symbolic link owned by another user"));
                        }
                        hops += 1;
                        if hops > MAX_SYMLINK_HOPS {
                            return Err(refuse("a route with too many symbolic links"));
                        }
                        let target = rustix::fs::readlinkat(&cur.fd, &name, Vec::new())
                            .map_err(|error| anyhow::anyhow!(error))?;
                        let target = PathBuf::from(
                            <std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(
                                target.as_bytes(),
                            ),
                        );
                        if target.is_absolute() {
                            stack.truncate(1);
                        }
                        push_path_steps(&mut queue, &target);
                    }
                    Err(rustix::io::Errno::NOENT) => return Err(not_found()),
                    Err(error) => {
                        return Err(anyhow::anyhow!(
                            "config: {}: trusted source ({decl}) has a route this refuses ({error})",
                            crate::one_line::quoted_path(path),
                        ));
                    }
                }
            }
        }
    }
    Err(refuse("a path with no final component"))
}

/// ADR-0076 R2.2: a final symlink is refused first when its **target** resolves
/// inside the checkout, so the diagnostic names the route rather than the link.
///
/// Canonicalizing here can only choose the wording: the caller keeps
/// `opened = None`, so `verify_trusted_source_at` still refuses the symlink and no
/// byte of the target is ever read. A dangling or looping link fails closed.
fn check_trusted_symlink_target_against_boundary(
    path: &Path,
    boundary: Option<&CheckoutBoundary>,
) -> anyhow::Result<()> {
    let Some(boundary) = boundary else {
        return Ok(());
    };
    let canonical = std::fs::canonicalize(path).map_err(|error| {
        anyhow::anyhow!(
            "config: {}: resolving a trusted source symbolic link failed ({:?})",
            crate::one_line::quoted_path(path),
            error.kind(),
        )
    })?;
    if boundary
        .boundary_roots
        .iter()
        .any(|root| canonical.starts_with(root))
    {
        anyhow::bail!(
            "config: {}: the trusted source refuses a symbolic link whose target resolves inside \
             the active project: the working directory is an ancestor of it; move the file outside \
             the active project or set trust = false so the source is pinned instead",
            crate::one_line::quoted_path(path),
        );
    }
    Ok(())
}

/// One `trust = false` source read through a single descriptor walk
/// (ADR-0076 R2.4, #736).
#[cfg_attr(not(test), allow(dead_code))] // Phase 4's untrusted route walker
pub(crate) struct UntrustedSourceRead {
    pub(crate) scope: crate::config_sources::SourceScope,
    /// The exact bytes read once from the opened descriptor. The caller charges
    /// these to its own source budget and hashes this buffer; the file is never
    /// reopened.
    pub(crate) bytes: Vec<u8>,
    pub(crate) identity: crate::host_paths::FileIdentity,
}

/// Why an untrusted route did not produce bytes.
///
/// Values rather than messages: the caller renders the user-facing refusal with
/// the entry's alias, declaration and project config, which this walker does
/// not have. `Debug` is safe to log — no component or target bytes are held.
#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))] // Phase 4's untrusted route walker
pub(crate) enum UntrustedReadError {
    NotFound,
    /// The captured root's entry no longer carries the captured identity, or a
    /// step's name resolved to one identity and opened as another: the path
    /// changed while it was being read. Named for the root because that is the
    /// case with a checkpoint of its own; an intermediate directory swapped
    /// under the walk is the same defect and the same refusal.
    RootReplaced,
    EscapesCheckout,
    CheckoutHardLinked(u64),
    TooLarge,
    NotRegular,
    Io(anyhow::Error),
}

#[cfg_attr(not(test), allow(dead_code))] // Phase 4's untrusted route walker
fn untrusted_dir_facts(
    fd: &std::os::fd::OwnedFd,
    display: &impl std::fmt::Display,
) -> std::result::Result<crate::host_paths::OpenedDirFacts, UntrustedReadError> {
    crate::host_paths::opened_dir_facts(fd, display).map_err(UntrustedReadError::Io)
}

/// Walk a `trust = false` source's whole route from `/` by descriptor and read
/// it **once**, reporting the scope the walk actually earned (ADR-0076 R2.4).
///
/// Unlike the `trust = true` walk, entering a [`CheckoutBoundary`] is not a
/// refusal: a checkout source is admitted and confined. Every directory is
/// opened `O_NOFOLLOW` from the descriptor above it, so a replaced name between
/// steps can never change which directory is read. A relative entry starts at
/// the captured root, which must still carry the identity capture verified.
///
/// `boundary` is `None` only for routes with no captured root (test fixtures);
/// production callers pass [`RouteAnchor::checkout_boundary`], whose root
/// identity is the capture's.
#[cfg_attr(not(test), allow(dead_code))] // Phase 4's untrusted route walker
pub(crate) fn read_untrusted_source_route(
    entry: &crate::config_sources::SourceEntry,
    route: &RouteAnchor,
    boundary: Option<&CheckoutBoundary>,
    max_bytes: u64,
) -> std::result::Result<UntrustedSourceRead, UntrustedReadError> {
    read_untrusted_source_route_checkpointed(entry, route, boundary, max_bytes, |_| {})
}

/// Where inside one walk step a test seam may act. A production walk passes a
/// closure that discards both, so no rename can be injected into a shipped
/// build.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum StepMoment {
    /// After the captured-root checkpoint on this step's parent and before the
    /// step's own `statat`: the window a directory stamp closes.
    AfterCapturedRootCheckpoint,
    /// After the step's own `statat`, before its `openat`: the window the step
    /// invariant closes.
    BeforeOpen,
    /// After the step's `openat`, before any checkpoint re-reads the name: where
    /// a test puts back what it swapped in, i.e. the second swap.
    AfterOpen,
}

/// [`read_untrusted_source_route`] with a checkpoint after each traversed
/// directory, so a test can swap a component mid-walk and prove the walk stays
/// anchored to the descriptors it already opened.
#[cfg_attr(not(test), allow(dead_code))] // Phase 4's untrusted route walker
pub(crate) fn read_untrusted_source_route_checkpointed(
    entry: &crate::config_sources::SourceEntry,
    route: &RouteAnchor,
    boundary: Option<&CheckoutBoundary>,
    max_bytes: u64,
    after_step: impl FnMut(&Path),
) -> std::result::Result<UntrustedSourceRead, UntrustedReadError> {
    read_untrusted_source_route_inner(entry, route, boundary, max_bytes, after_step, |_, _| {})
}

/// [`read_untrusted_source_route`] with a seam inside the step that opens a
/// descriptor, so a test can rename the step's own name between its `statat`
/// and its `openat` ([`StepMoment::BeforeOpen`]) and, on a tree without the step
/// invariant, put the original back before the closing checkpoint
/// ([`StepMoment::AfterOpen`]) — the double swap that closes the window only the
/// stat-then-open agreement can see.
#[cfg(test)]
pub(crate) fn read_untrusted_source_route_with_seam(
    entry: &crate::config_sources::SourceEntry,
    route: &RouteAnchor,
    boundary: Option<&CheckoutBoundary>,
    max_bytes: u64,
    seam: impl FnMut(&Path, StepMoment),
) -> std::result::Result<UntrustedSourceRead, UntrustedReadError> {
    read_untrusted_source_route_inner(entry, route, boundary, max_bytes, |_| {}, seam)
}

#[cfg_attr(not(test), allow(dead_code))] // Phase 4's untrusted route walker
fn read_untrusted_source_route_inner(
    entry: &crate::config_sources::SourceEntry,
    route: &RouteAnchor,
    boundary: Option<&CheckoutBoundary>,
    max_bytes: u64,
    mut after_step: impl FnMut(&Path),
    mut seam: impl FnMut(&Path, StepMoment),
) -> std::result::Result<UntrustedSourceRead, UntrustedReadError> {
    use rustix::fs::{Mode, OFlags};

    let (root, root_id) = match route {
        RouteAnchor::Captured { root, root_id, .. } => {
            (Some(root.as_path()), Some((root_id.dev, root_id.ino)))
        }
        RouteAnchor::Uncaptured => (None, None),
    };
    if entry.is_spelled_relative() && root.is_none() {
        return Err(UntrustedReadError::Io(anyhow::anyhow!(
            "internal: a relative trust = false source without a captured project root"
        )));
    }

    struct WalkDir {
        fd: std::os::fd::OwnedFd,
        path: PathBuf,
        facts: crate::host_paths::OpenedDirFacts,
        in_boundary: bool,
    }

    let slash_fd = rustix::fs::open(
        Path::new("/"),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| UntrustedReadError::Io(anyhow::anyhow!(error)))?;
    let slash_facts = untrusted_dir_facts(&slash_fd, &"the filesystem root")?;
    // `/` is already open before any step runs, so a boundary that *is* `/`
    // (a project or worktree rooted at the filesystem root) has to be entered
    // here rather than observed from a parent step that will never happen.
    let slash_in_boundary =
        boundary.is_some_and(|b| b.contains(slash_facts.identity(), Path::new("/")));
    let mut entered_boundary = slash_in_boundary;
    let mut stack = vec![WalkDir {
        fd: slash_fd,
        path: PathBuf::from("/"),
        facts: slash_facts,
        in_boundary: slash_in_boundary,
    }];

    // B1: the captured root is one entry of one directory — its own on-disk
    // name in its captured parent — and that entry must still carry the captured
    // identity. Decided *before* the walk and independently of the route's
    // spelling, so no alias of the name can hide a replacement, and no walk step
    // can mistake a sibling of the root for one.
    if let (Some(root), Some(root_id)) = (root, root_id) {
        check_captured_root_entry(root, root_id)?;
    }

    // The same check, repeated at the walk step itself and for **every** route,
    // so it covers the window between the check above and the step that opens the
    // captured root's own component. Two halves, neither of them lexical:
    //
    // - *when*: the walk's current directory is the captured root's parent, by
    //   descriptor identity. That is true however the route spells its way there
    //   — relative, absolute, or through a case/normalization alias — because it
    //   is the opened directory that is compared, not a path.
    // - *what*: the captured root's own on-disk entry name, re-read from that
    //   same parent descriptor, must still carry the captured identity. Naming the
    //   root's entry rather than the child being opened is what keeps a sibling of
    //   the root admitted (`a_sibling_of_the_captured_root_is_an_external_source`).
    //
    // The relative descent below keeps its own identity checkpoint as belt and
    // braces: there the child *is* the root's own component, so the opened child
    // must carry the captured identity, which is exact rather than a re-read.
    let root_entry = match (root.and_then(Path::file_name), root_id) {
        (Some(name), Some(root_id)) => Some((name.to_os_string(), root_id)),
        _ => None,
    };
    // `None` for a root at `/`, which has no parent entry: its routes are already
    // inside the boundary.
    let root_parent_id = match root {
        Some(root) => match root.parent() {
            Some(parent) => {
                let fd = rustix::fs::open(
                    parent,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|error| UntrustedReadError::Io(anyhow::anyhow!(error)))?;
                Some(untrusted_dir_facts(&fd, &crate::one_line::quoted_path(parent))?.identity())
            }
            None => None,
        },
        None => None,
    };

    let mut queue: std::collections::VecDeque<RouteStep> = std::collections::VecDeque::new();
    let mut hops = 0usize;

    if entry.is_spelled_relative() {
        let root = root.expect("a relative entry was checked to have a root");
        let root_id = root_id.expect("a relative entry was checked to have a root identity");
        for name in root.components().filter_map(|component| match component {
            std::path::Component::Normal(name) => Some(name.to_os_string()),
            _ => None,
        }) {
            let cur = stack.last().expect("the descriptor stack starts at `/`");
            let child_path = cur.path.join(&name);
            // The same stat-then-open agreement every step below runs; here a
            // missing component means the captured root itself is gone, which is
            // the replacement refusal rather than `NotFound`.
            let seen = stat_step_entry(&cur.fd, &name).map_err(|error| match error {
                UntrustedReadError::NotFound => UntrustedReadError::RootReplaced,
                error => error,
            })?;
            seam(&child_path, StepMoment::BeforeOpen);
            let child_fd = rustix::fs::openat(
                &cur.fd,
                &name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| UntrustedReadError::RootReplaced)?;
            seam(&child_path, StepMoment::AfterOpen);
            let child_facts =
                untrusted_dir_facts(&child_fd, &crate::one_line::quoted_path(&child_path))?;
            require_step_identity(seen, child_facts.identity())?;
            if root_parent_id == Some(cur.facts.identity()) && child_facts.identity() != root_id {
                return Err(UntrustedReadError::RootReplaced);
            }
            let in_boundary = cur.in_boundary
                || boundary.is_some_and(|b| b.contains(child_facts.identity(), &child_path));
            entered_boundary |= in_boundary;
            stack.push(WalkDir {
                fd: child_fd,
                path: child_path.clone(),
                facts: child_facts,
                in_boundary,
            });
            after_step(&child_path);
        }
        let suffix = entry.path().strip_prefix(root).map_err(|_| {
            UntrustedReadError::Io(anyhow::anyhow!(
                "internal: a relative source resolved outside its captured project root"
            ))
        })?;
        push_path_steps(&mut queue, suffix);
    } else {
        push_path_steps(&mut queue, entry.path());
    }

    while let Some(step) = queue.pop_front() {
        let last = queue.is_empty();
        match step {
            RouteStep::Here => {
                if last {
                    return Err(UntrustedReadError::NotRegular);
                }
            }
            RouteStep::Up => {
                // A `..` step opens no name: it pops the descriptor stack, so the
                // identity the walk continues from is one a descriptor already
                // reported, never a name re-resolved between two syscalls.
                if stack.len() > 1 {
                    stack.pop();
                }
                if last {
                    return Err(UntrustedReadError::NotRegular);
                }
            }
            RouteStep::Name(name) => {
                let cur = stack.last().expect("the descriptor stack starts at `/`");
                // Before opening a child of the captured root's parent, the root's
                // own entry must still be the captured directory. After the open
                // below it is re-read once more, so a swap that lands between this
                // read and the `openat` is refused too. Both are identity checks on
                // the root's entry, never on the route's spelling.
                let at_root_parent = match (&root_entry, root_parent_id) {
                    (Some((root_name, root_id)), Some(parent_id))
                        if parent_id == cur.facts.identity() =>
                    {
                        require_captured_root_entry(&cur.fd, root_name, *root_id)?;
                        true
                    }
                    _ => false,
                };
                // The step invariant, first half: stat this step's own name
                // immediately before opening it. The seams around it are where a
                // test injects a rename; a shipped build's seams are no-ops.
                let step_path = cur.path.join(&name);
                // The captured root's own entry is the one entry whose identity
                // decides a source's scope, and a rename of any entry in this
                // parent directory changes the parent's own stamps. Take the
                // stamp after the checkpoint above and require it unchanged
                // before the opened child is used: then the checkpoint, the step's
                // stat and its open all saw one state.
                let parent_stamp = if at_root_parent {
                    Some(dir_change_stamp(&cur.fd)?)
                } else {
                    None
                };
                if at_root_parent {
                    seam(&step_path, StepMoment::AfterCapturedRootCheckpoint);
                }
                let seen = stat_step_entry(&cur.fd, &name)?;
                seam(&step_path, StepMoment::BeforeOpen);
                if last {
                    if entered_boundary && !cur.in_boundary {
                        return Err(UntrustedReadError::EscapesCheckout);
                    }
                    match rustix::fs::openat(
                        &cur.fd,
                        &name,
                        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                        Mode::empty(),
                    ) {
                        Ok(fd) => {
                            seam(&step_path, StepMoment::AfterOpen);
                            let display = step_path;
                            let flagged = rustix::fs::fstat(&fd)
                                .map_err(|error| UntrustedReadError::Io(anyhow::anyhow!(error)))?;
                            // The invariant's second half, before any byte is read:
                            // the descriptor this step opened is the entry this
                            // step's own stat saw.
                            require_step_identity(seen, StepEntry::of(&flagged).identity)?;
                            // …and the captured root's own entry, re-read from the
                            // parent descriptor: a replacement already in place at
                            // the stat above (so stat and open agree) is still not
                            // the captured root. It names the root's entry, so it
                            // needs no comparison of the route's spelling with a
                            // name.
                            if at_root_parent {
                                let (root_name, root_id) =
                                    root_entry.as_ref().expect("an armed checkpoint");
                                require_captured_root_entry(&cur.fd, root_name, *root_id)?;
                            }
                            if let Some(stamp) = parent_stamp {
                                require_dir_unchanged(&cur.fd, stamp)?;
                            }
                            if rustix::fs::FileType::from_raw_mode(flagged.st_mode)
                                != rustix::fs::FileType::RegularFile
                            {
                                return Err(UntrustedReadError::NotRegular);
                            }
                            let opened =
                                crate::host_paths::opened_regular_from_descriptor(fd, &display)
                                    .map_err(UntrustedReadError::Io)?;
                            let facts = opened.facts();
                            if entered_boundary && facts.nlink != 1 {
                                return Err(UntrustedReadError::CheckoutHardLinked(facts.nlink));
                            }
                            let identity = opened.identity();
                            let bytes =
                                opened.read_bounded_classified(max_bytes).map_err(|error| {
                                    match error {
                                        crate::host_paths::ReadBoundedError::TooLarge => {
                                            UntrustedReadError::TooLarge
                                        }
                                        crate::host_paths::ReadBoundedError::Io(error) => {
                                            UntrustedReadError::Io(error)
                                        }
                                    }
                                })?;
                            return Ok(UntrustedSourceRead {
                                scope: if entered_boundary {
                                    crate::config_sources::SourceScope::Checkout
                                } else {
                                    crate::config_sources::SourceScope::External
                                },
                                bytes,
                                identity,
                            });
                        }
                        Err(rustix::io::Errno::LOOP) => {
                            // No descriptor was opened, so the stat is paired with
                            // the `readlinkat` instead: the step's own stat saw a
                            // symlink, and the link text followed must be that same
                            // entry's.
                            if seen.kind != rustix::fs::FileType::Symlink {
                                return Err(UntrustedReadError::RootReplaced);
                            }
                            hops += 1;
                            if hops > MAX_SYMLINK_HOPS {
                                return Err(UntrustedReadError::EscapesCheckout);
                            }
                            let target = read_link_target(&cur.fd, &name)?;
                            require_entry_unchanged(&cur.fd, &name, seen)?;
                            if target.is_absolute() {
                                stack.truncate(1);
                            }
                            push_path_steps(&mut queue, &target);
                        }
                        Err(rustix::io::Errno::NOENT) => return Err(UntrustedReadError::NotFound),
                        Err(rustix::io::Errno::NOTDIR) => {
                            return Err(UntrustedReadError::NotRegular);
                        }
                        Err(error) => {
                            return Err(UntrustedReadError::Io(anyhow::anyhow!(error)));
                        }
                    }
                    continue;
                }

                match rustix::fs::openat(
                    &cur.fd,
                    &name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                ) {
                    Ok(child_fd) => {
                        seam(&step_path, StepMoment::AfterOpen);
                        let child_facts = untrusted_dir_facts(
                            &child_fd,
                            &crate::one_line::quoted_path(&step_path),
                        )?;
                        // The invariant, before the walk descends: the child
                        // descriptor is the entry this step's own stat saw. Two
                        // swaps inside this step therefore refuse here even when
                        // the captured root's entry is restored before the
                        // checkpoint below reads it again.
                        require_step_identity(seen, child_facts.identity())?;
                        // The root's own entry, read again now that the child is
                        // open: the same identity the step began with, so a
                        // replacement that landed while the child was being opened
                        // and is still there is refused before the walk descends
                        // into it.
                        if at_root_parent {
                            let (root_name, root_id) =
                                root_entry.as_ref().expect("an armed checkpoint");
                            require_captured_root_entry(&cur.fd, root_name, *root_id)?;
                        }
                        if let Some(stamp) = parent_stamp {
                            require_dir_unchanged(&cur.fd, stamp)?;
                        }
                        let child_path = step_path;
                        let in_boundary = cur.in_boundary
                            || boundary
                                .is_some_and(|b| b.contains(child_facts.identity(), &child_path));
                        entered_boundary |= in_boundary;
                        stack.push(WalkDir {
                            fd: child_fd,
                            path: child_path.clone(),
                            facts: child_facts,
                            in_boundary,
                        });
                        after_step(&child_path);
                    }
                    Err(rustix::io::Errno::LOOP) | Err(rustix::io::Errno::NOTDIR) => {
                        // The same pairing as the final step's symlink arm: the
                        // stat saw a symlink, else the open refused a name the
                        // step's own stat already knew was not a directory.
                        if seen.kind != rustix::fs::FileType::Symlink {
                            return Err(UntrustedReadError::NotRegular);
                        }
                        hops += 1;
                        if hops > MAX_SYMLINK_HOPS {
                            return Err(UntrustedReadError::EscapesCheckout);
                        }
                        let target = read_link_target(&cur.fd, &name)?;
                        require_entry_unchanged(&cur.fd, &name, seen)?;
                        if target.is_absolute() {
                            stack.truncate(1);
                        }
                        push_path_steps(&mut queue, &target);
                    }
                    Err(rustix::io::Errno::NOENT) => return Err(UntrustedReadError::NotFound),
                    Err(error) => {
                        return Err(UntrustedReadError::Io(anyhow::anyhow!(error)));
                    }
                }
            }
        }
    }
    Err(UntrustedReadError::NotFound)
}

/// What `doctor` found at the legacy in-repo location.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LegacyProjectConfig {
    Absent,
    /// Anything `lstat` can see: a file, a directory or a dangling link.
    Present(PathBuf),
    /// The project config explicitly lists it in `sources` (ADR-0074), so it is
    /// read, not ignored.
    Sourced,
    Unexaminable {
        path: PathBuf,
        kind: std::io::ErrorKind,
    },
}

/// `listed` is the project config's own `sources = [...]` entries, from a
/// successful load — never the implicit `home:trust` default (ADR-0074 D9).
pub(crate) fn legacy(project: &ProjectDir, listed: &[&Path]) -> LegacyProjectConfig {
    legacy_at(project.path().join(LEGACY_RELATIVE), listed, |p| {
        std::fs::symlink_metadata(p)
    })
}

/// The injected `lstat` is the test seam for the unexaminable arm, which a
/// permission fixture cannot produce when the suite runs as root.
/// Only `NotFound` is silent (spec R7); every other error — including
/// `NotADirectory` when `.agent-vm` is a regular file — reports `Unexaminable`.
fn legacy_at(
    path: PathBuf,
    listed: &[&Path],
    lstat: impl Fn(&Path) -> std::io::Result<std::fs::Metadata>,
) -> LegacyProjectConfig {
    // Lexical membership first, with no filesystem access: the common case is the
    // exact spelling the user wrote.
    if listed.iter().any(|source| *source == path) {
        return LegacyProjectConfig::Sourced;
    }
    match lstat(&path) {
        Ok(_) if names_same_file(&path, listed) => LegacyProjectConfig::Sourced,
        Ok(_) => LegacyProjectConfig::Present(path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => LegacyProjectConfig::Absent,
        Err(e) => LegacyProjectConfig::Unexaminable {
            path,
            kind: e.kind(),
        },
    }
}

/// D9's fallback: an explicitly listed source spelled through a symlinked
/// directory. Short-circuits before `canonicalize` when `listed` is empty
/// (implicit sourcing or a failed load), so an in-repo symlink to the user config
/// can never hide the notice.
///
/// Canonical equality is used *only* here: never to widen `:trust` admission or
/// source deduplication.
fn names_same_file(path: &Path, listed: &[&Path]) -> bool {
    if listed.is_empty() {
        return false;
    }
    let Ok(canonical) = std::fs::canonicalize(path) else {
        return false;
    };
    listed
        .iter()
        .any(|source| std::fs::canonicalize(source).is_ok_and(|c| c == canonical))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project::digest_hex_of;
    use sha2::{Digest as _, Sha256};
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::symlink;

    /// The id must be the full 64-hex SHA-256 of the canonical path's raw
    /// bytes: not lossy UTF-8, not the 12-hex state name, not a symlink's
    /// spelling. Both oracles below are computed outside this module's code.
    #[test]
    fn path_is_home_projects_full_digest_config_toml() {
        assert_eq!(
            digest_hex_of(Path::new("/a/b")),
            "662b7b62a798bb2d53e67cad9778e12e48297c79eae98d3aae7197be825d768f"
        );
        // A path a `&str` cannot spell still hashes as its own bytes.
        assert_eq!(
            digest_hex_of(Path::new(OsStr::from_bytes(b"/a/\xff"))),
            "7c83ed9afbe4f45264a1bae418eaec47444a63fbcb68b96818bb0f6bd1b4b608"
        );

        let root = tempfile::tempdir().unwrap();
        let project = ProjectDir::from_path_for_tests(root.path()).unwrap();
        let canonical = project.path();
        let hex: String = Sha256::digest(canonical.as_os_str().as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(hex.len(), 64);
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "{hex}"
        );
        let home = Path::new("/home/someone");
        let expected_dir = home.join(".config/agent-vm/projects").join(&hex);
        assert_eq!(project_dir(home, &project), expected_dir);
        assert_eq!(
            path(home, &project),
            expected_dir.join("config.toml"),
            "the file name is part of the location"
        );
        assert_eq!(projects_dir(home), home.join(".config/agent-vm/projects"));
    }

    /// A symlinked cwd resolves to the real directory, so it names the same
    /// project — and therefore the same config — as the real path.
    #[test]
    fn a_symlink_alias_names_the_same_project_config() {
        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let alias = root.path().join("alias");
        symlink(&real, &alias).unwrap();
        let home = Path::new("/home/someone");
        assert_eq!(
            path(home, &ProjectDir::from_path_for_tests(&alias).unwrap()),
            path(home, &ProjectDir::from_path_for_tests(&real).unwrap())
        );
    }

    #[test]
    fn check_store_route_rejects_symlinks_and_checkout_aliases() {
        let root = tempfile::tempdir().unwrap();
        let base = root.path().join("base");
        let home = base.join("home");
        let checkout = base.join("checkout");
        std::fs::create_dir_all(home.join(".config/agent-vm")).unwrap();
        std::fs::create_dir_all(&checkout).unwrap();
        let project = ProjectDir::from_path_for_tests(&checkout).unwrap();
        let config = path(&home, &project);

        // Nothing created yet.
        assert_eq!(
            check_store_route(&tier(&home, &project, project.path())).unwrap(),
            StoreRoute::Absent
        );

        // A real store with no `config.toml` is still a route to descend.
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        assert_eq!(
            check_store_route(&tier(&home, &project, project.path())).unwrap(),
            StoreRoute::Present
        );

        // `projects/<id>` itself a symlink, including into the checkout.
        std::fs::remove_dir_all(home.join(".config/agent-vm/projects")).unwrap();
        std::fs::create_dir_all(checkout.join(".agent-vm")).unwrap();
        std::fs::create_dir_all(home.join(".config/agent-vm/projects")).unwrap();
        symlink(
            checkout.join(".agent-vm"),
            home.join(".config/agent-vm/projects")
                .join(project.digest_hex()),
        )
        .unwrap();
        assert!(check_store_route(&tier(&home, &project, project.path())).is_err());
        std::fs::remove_dir_all(home.join(".config/agent-vm/projects")).unwrap();

        // `projects/` itself a symlink.
        symlink(
            checkout.join(".agent-vm"),
            home.join(".config/agent-vm/projects"),
        )
        .unwrap();
        assert!(check_store_route(&tier(&home, &project, project.path())).is_err());
        std::fs::remove_file(home.join(".config/agent-vm/projects")).unwrap();

        // An ancestor alias that redirects the whole authority dir into the
        // active checkout.
        std::fs::remove_dir(home.join(".config/agent-vm")).unwrap();
        std::fs::create_dir_all(checkout.join("evil/projects")).unwrap();
        symlink(checkout.join("evil"), home.join(".config/agent-vm")).unwrap();
        std::fs::create_dir(checkout.join("evil/projects").join(project.digest_hex())).unwrap();
        assert!(check_store_route(&tier(&home, &project, project.path())).is_err());
        std::fs::remove_file(home.join(".config/agent-vm")).unwrap();

        // A dotfile-symlinked `~/.config/agent-vm` pointing outside the
        // checkout stays allowed.
        let outside = base.join("outside");
        std::fs::create_dir_all(outside.join("projects")).unwrap();
        std::fs::create_dir(outside.join("projects").join(project.digest_hex())).unwrap();
        symlink(&outside, home.join(".config/agent-vm")).unwrap();
        assert_eq!(
            check_store_route(&tier(&home, &project, project.path())).unwrap(),
            StoreRoute::Present,
            "an alias outside the checkout does not auto-load the legacy file"
        );
        std::fs::remove_file(home.join(".config/agent-vm")).unwrap();

        // The store reached unaliased from a `$HOME` project root is not an
        // alias: the canonical store path is the one the route names. (On macOS
        // `/var` is a symlink to `/private/var`, which is why both sides are
        // canonicalized.)
        let home_project = ProjectDir::from_path_for_tests(&home).unwrap();
        std::fs::create_dir_all(path(&home, &home_project).parent().unwrap()).unwrap();
        assert_eq!(
            check_store_route(&tier(&home, &home_project, home_project.path())).unwrap(),
            StoreRoute::Present
        );
        // The same run with a dotfile-managed `~/.config/agent-vm` living inside
        // `$HOME` is refused: `$HOME` as the project root is not an exemption
        // (ADR-0073 Decision 3).
        std::fs::remove_dir_all(home.join(".config/agent-vm")).unwrap();
        let dotfiles = home.join("dotfiles/agent-vm");
        std::fs::create_dir_all(dotfiles.join("projects").join(home_project.digest_hex())).unwrap();
        symlink(&dotfiles, home.join(".config/agent-vm")).unwrap();
        assert!(
            check_store_route(&tier(&home, &home_project, home_project.path())).is_err(),
            "a dotfile symlink inside $HOME is refused when the project root is $HOME"
        );
    }

    /// ADR-0073: `projects/` itself is verified by descriptor, before the store
    /// child is looked up — a writable parent could redirect a later child.
    #[test]
    fn a_writable_projects_parent_is_refused_before_the_child_lookup() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let home = root.join("home");
        let projects = crate::project_config::projects_dir(&home);
        std::fs::create_dir_all(&projects).unwrap();
        let project_root = root.join("project");
        std::fs::create_dir(&project_root).unwrap();
        let project = ProjectDir::from_path_for_tests(&project_root).unwrap();
        std::fs::set_permissions(&projects, std::fs::Permissions::from_mode(0o770)).unwrap();
        // The child directory is absent: the refusal must still be the parent's.
        let error = check_store_route(&tier(&home, &project, &project_root))
            .expect_err("a writable projects/ parent is refused");
        assert!(
            format!("{error:#}").contains("group- or other-writable"),
            "{error:#}"
        );
        std::fs::set_permissions(&projects, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            check_store_route(&tier(&home, &project, &project_root)).unwrap(),
            StoreRoute::Absent
        );
    }

    /// The `(dev, ino)` a captured root has on disk, for test-built anchors.
    fn identity_at(path: &Path) -> crate::host_paths::FileIdentity {
        use std::os::unix::fs::MetadataExt as _;
        let metadata = std::fs::metadata(path).unwrap();
        crate::host_paths::FileIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
        }
    }

    /// A tier as discovery builds it: the path from `home`, checked against the
    /// project root. Named fields, so no two paths can be swapped.
    fn tier(home: &Path, project: &ProjectDir, root: &Path) -> ProjectTierPaths {
        ProjectTierPaths {
            config: path(home, project),
            route: RouteAnchor::Captured {
                home: home.to_path_buf(),
                root: root.to_path_buf(),
                root_id: identity_at(root),
            },
        }
    }

    #[test]
    fn legacy_at_classifies_every_lstat_outcome() {
        let root = tempfile::tempdir().unwrap();
        let project_root = root.path().join("project");
        std::fs::create_dir(&project_root).unwrap();
        let project = ProjectDir::from_path_for_tests(&project_root).unwrap();
        let legacy_path = project.path().join(LEGACY_RELATIVE);

        assert_eq!(legacy(&project, &[]), LegacyProjectConfig::Absent);

        std::fs::create_dir_all(project.path().join(".agent-vm")).unwrap();
        std::fs::write(&legacy_path, "[image]\n").unwrap();
        assert_eq!(
            legacy(&project, &[]),
            LegacyProjectConfig::Present(legacy_path.clone())
        );
        std::fs::remove_dir_all(project.path().join(".agent-vm")).unwrap();

        // A directory there is "present" too: it is what the user must clean up.
        std::fs::create_dir_all(&legacy_path).unwrap();
        assert_eq!(
            legacy(&project, &[]),
            LegacyProjectConfig::Present(legacy_path.clone())
        );
        std::fs::remove_dir_all(project.path().join(".agent-vm")).unwrap();

        // A dangling link is present: `lstat` succeeds, the target does not.
        std::fs::create_dir_all(project.path().join(".agent-vm")).unwrap();
        symlink(root.path().join("missing"), &legacy_path).unwrap();
        assert_eq!(
            legacy(&project, &[]),
            LegacyProjectConfig::Present(legacy_path.clone())
        );
        std::fs::remove_dir_all(project.path().join(".agent-vm")).unwrap();

        // `.agent-vm` is a regular file: `NotADirectory` is never silent (R7).
        let not_a_directory = root.path().join("not-a-directory");
        std::fs::write(&not_a_directory, "").unwrap();
        assert_eq!(
            legacy_at(not_a_directory.clone(), &[], |p| std::fs::symlink_metadata(
                p
            )),
            LegacyProjectConfig::Present(not_a_directory.clone()),
            "a regular file at the path is present, not absent"
        );
        let nested = not_a_directory.join(".agent-vm/config.toml");
        assert_eq!(
            legacy_at(nested.clone(), &[], |p| std::fs::symlink_metadata(p)),
            LegacyProjectConfig::Unexaminable {
                path: nested,
                kind: std::io::ErrorKind::NotADirectory
            }
        );

        // The injected seam: a permission failure a root-owned suite could not
        // produce on a real fixture.
        let injected = root.path().join("injected");
        assert_eq!(
            legacy_at(injected.clone(), &[], |_| Err(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied
            ))),
            LegacyProjectConfig::Unexaminable {
                path: injected,
                kind: std::io::ErrorKind::PermissionDenied
            }
        );
    }

    /// V16 (ADR-0074 D9): an explicitly listed legacy file is *sourced*, so the
    /// notice is suppressed; an implicit list changes nothing.
    #[test]
    fn v16_an_explicitly_listed_legacy_file_is_sourced_not_ignored() {
        let root = tempfile::tempdir().unwrap();
        let base = root.path().canonicalize().unwrap();
        let checkout = base.join("checkout");
        std::fs::create_dir_all(&checkout).unwrap();
        let project = ProjectDir::from_path_for_tests(&checkout).unwrap();
        let legacy_path = project.path().join(LEGACY_RELATIVE);

        // Lexical membership is decided without touching the filesystem.
        assert_eq!(
            legacy_at(legacy_path.clone(), &[legacy_path.as_path()], |_| panic!(
                "a lexical match must not lstat"
            )),
            LegacyProjectConfig::Sourced
        );

        // A listed file spelled through a symlinked directory: canonical equality.
        std::fs::create_dir_all(project.path().join(".agent-vm")).unwrap();
        std::fs::write(&legacy_path, "").unwrap();
        let alias = project.path().join("link/config.toml");
        symlink(
            project.path().join(".agent-vm"),
            project.path().join("link"),
        )
        .unwrap();
        assert_eq!(
            legacy(&project, &[alias.as_path()]),
            LegacyProjectConfig::Sourced
        );

        // A listed *different* file does not suppress the notice.
        let other = base.join("other.toml");
        std::fs::write(&other, "").unwrap();
        assert_eq!(
            legacy(&project, &[other.as_path()]),
            LegacyProjectConfig::Present(legacy_path.clone())
        );

        // An empty list — implicit sourcing, or a failed load — keeps #733's
        // answer even when the legacy entry links at the user config.
        let user_dir = base.join("home/.config/agent-vm");
        std::fs::create_dir_all(&user_dir).unwrap();
        std::fs::write(user_dir.join("config.toml"), "").unwrap();
        std::fs::remove_file(&legacy_path).unwrap();
        symlink(user_dir.join("config.toml"), &legacy_path).unwrap();
        assert_eq!(
            legacy(&project, &[]),
            LegacyProjectConfig::Present(legacy_path.clone()),
            "an implicit source may not hide the notice"
        );
    }

    // ---- ADR-0076 R2.2: the whole-route trusted-source walk ----

    use crate::config_sources::Declaration;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    /// A captured route whose checkout is `base/project`.
    fn route_at(base: &Path) -> RouteAnchor {
        let root = base.join("project");
        RouteAnchor::Captured {
            home: base.join("home"),
            root_id: identity_at(&root),
            root,
        }
    }

    fn owner_only_file(path: &Path) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::write(path, b"[[tools]]\nname = \"x\"\ncommand = \"true\"\n").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn walk(path: &Path, base: &Path) -> anyhow::Result<OpenedTrustedSource> {
        open_trusted_source_route(path, Declaration::Entry(0), &route_at(base))
    }

    #[test]
    fn an_owner_only_file_outside_the_checkout_opens() {
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        std::fs::create_dir(base.join("project")).unwrap();
        std::fs::create_dir(base.join("home")).unwrap();
        let file = base.join("team/agent-vm.toml");
        owner_only_file(&file);
        let opened = walk(&file, &base).expect("a safe route loads");
        assert!(opened.opened.is_some(), "the regular file is open");
        assert!(matches!(
            opened.final_component,
            crate::host_paths::FinalComponent::Regular(_)
        ));
        assert!(opened.parent_dir.is_dir);
        assert_eq!(opened.parent_dir.uid, crate::host_paths::current_euid());
    }

    #[test]
    fn a_file_inside_the_checkout_is_refused() {
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        std::fs::create_dir(base.join("home")).unwrap();
        let file = base.join("project/conf/agent-vm.toml");
        owner_only_file(&file);
        let error = walk(&file, &base).expect_err("an in-checkout route is refused");
        let message = format!("{error:#}");
        assert!(
            message.contains("inside the active checkout"),
            "the refusal must name the route: {message}"
        );
        assert!(message.contains("sources[0]"), "{message}");
        assert!(
            message.contains(&format!("\"{}\"", file.display())),
            "{message}"
        );
    }

    #[test]
    fn a_parent_component_that_reenters_the_checkout_is_refused() {
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        std::fs::create_dir(base.join("home")).unwrap();
        let file = base.join("project/sub/../conf/agent-vm.toml");
        owner_only_file(&base.join("project/conf/agent-vm.toml"));
        std::fs::create_dir(base.join("project/sub")).unwrap();
        let error = walk(&file, &base).expect_err("`..` from inside the checkout is refused");
        assert!(
            format!("{error:#}").contains("active checkout"),
            "{error:#}"
        );
    }

    #[test]
    fn a_symlinked_ancestor_pointing_into_the_checkout_is_refused() {
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        std::fs::create_dir(base.join("home")).unwrap();
        owner_only_file(&base.join("project/conf/agent-vm.toml"));
        std::fs::create_dir(base.join("outside")).unwrap();
        symlink(base.join("project"), base.join("outside/link")).unwrap();
        let error = walk(&base.join("outside/link/conf/agent-vm.toml"), &base)
            .expect_err("a checkout symlink is refused");
        assert!(
            format!("{error:#}").contains("inside the active checkout"),
            "{error:#}"
        );
    }

    #[test]
    fn a_group_writable_ancestor_is_refused() {
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        std::fs::create_dir(base.join("home")).unwrap();
        std::fs::create_dir(base.join("project")).unwrap();
        let writable = base.join("shared");
        owner_only_file(&writable.join("inner/agent-vm.toml"));
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o775)).unwrap();
        let error = walk(&writable.join("inner/agent-vm.toml"), &base)
            .expect_err("a replaceable ancestor is refused");
        assert!(
            format!("{error:#}").contains("untrusted or writable ancestor"),
            "{error:#}"
        );
    }

    #[test]
    fn a_missing_file_names_the_declaration() {
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        std::fs::create_dir(base.join("home")).unwrap();
        std::fs::create_dir(base.join("project")).unwrap();
        std::fs::create_dir(base.join("team")).unwrap();
        let error = walk(&base.join("team/absent.toml"), &base).expect_err("missing is an error");
        let message = format!("{error:#}");
        assert!(message.contains("not found"), "{message}");
        assert!(message.contains("sources[0]"), "{message}");
    }

    #[test]
    fn a_final_symlink_reports_the_route_its_target_takes() {
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        std::fs::create_dir(base.join("home")).unwrap();
        std::fs::create_dir(base.join("project")).unwrap();
        let safe = base.join("team/real.toml");
        owner_only_file(&safe);
        symlink(&safe, base.join("team/link.toml")).unwrap();
        let opened = walk(&base.join("team/link.toml"), &base).expect("classified, not followed");
        assert!(opened.opened.is_none(), "a final symlink is never opened");
        assert_eq!(
            opened.final_component,
            crate::host_paths::FinalComponent::Symlink
        );

        let inside = base.join("project/conf.toml");
        owner_only_file(&inside);
        symlink(&inside, base.join("team/into-checkout.toml")).unwrap();
        let error = walk(&base.join("team/into-checkout.toml"), &base)
            .expect_err("a target inside the checkout is refused");
        let message = format!("{error:#}");
        assert!(
            message.contains("symbolic link whose target resolves inside"),
            "the route wording, not the generic symlink refusal: {message}"
        );
    }

    #[test]
    fn a_home_worktree_file_is_not_trusted_eligible() {
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        let home = base.join("home");
        std::fs::create_dir_all(home.join(".git")).unwrap();
        std::fs::create_dir_all(home.join("work/app")).unwrap();
        let file = home.join("team/agent-vm.toml");
        owner_only_file(&file);
        let root = home.join("work/app");
        let route = RouteAnchor::Captured {
            home: home.clone(),
            root_id: identity_at(&root),
            root,
        };
        let error = open_trusted_source_route(&file, Declaration::Entry(0), &route)
            .expect_err("a dotfiles worktree is repository-controlled");
        assert!(
            format!("{error:#}").contains("inside the active checkout"),
            "{error:#}"
        );
    }

    #[test]
    fn a_nearer_git_directory_never_shrinks_the_boundary() {
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        std::fs::create_dir(base.join("home")).unwrap();
        std::fs::create_dir_all(base.join("outer/.git")).unwrap();
        std::fs::create_dir_all(base.join("outer/nested/.git")).unwrap();
        let sub = base.join("outer/nested/sub");
        std::fs::create_dir_all(&sub).unwrap();
        let route = RouteAnchor::Captured {
            home: base.join("home"),
            root_id: identity_at(&sub),
            root: sub.clone(),
        };
        for file in [
            base.join("outer/shared.toml"),
            base.join("outer/nested/conf.toml"),
            base.join("outer/nested/sub/conf.toml"),
        ] {
            owner_only_file(&file);
            let error = open_trusted_source_route(&file, Declaration::Entry(0), &route)
                .expect_err("every enclosing worktree is inside the boundary");
            assert!(
                format!("{error:#}").contains("inside the active checkout"),
                "{}: {error:#}",
                file.display()
            );
        }
    }

    #[test]
    fn an_alternate_spelling_of_a_boundary_directory_is_refused() {
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        std::fs::create_dir(base.join("home")).unwrap();
        let inside = base.join("project/conf");
        owner_only_file(&inside.join("agent-vm.toml"));
        symlink(&inside, base.join("alias")).unwrap();
        let error = walk(&base.join("alias/agent-vm.toml"), &base)
            .expect_err("the opened descriptor identity is what decides");
        assert!(
            format!("{error:#}").contains("inside the active checkout"),
            "{error:#}"
        );
        // An uncollapsed spelling of the same file is the same route.
        let uncollapsed = base.join("project/conf/./agent-vm.toml");
        assert!(walk(&uncollapsed, &base).is_err());
    }

    /// The descriptor the walk verified is the descriptor it opened: swapping the
    /// directory at a checkpoint cannot redirect the open.
    #[test]
    fn the_verified_directory_descriptor_is_the_one_opened() {
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        std::fs::create_dir(base.join("home")).unwrap();
        std::fs::create_dir(base.join("project")).unwrap();
        let team = base.join("team");
        owner_only_file(&team.join("agent-vm.toml"));
        let target = base.join("team/agent-vm.toml");
        let mut swaps_left = 1;
        let opened = open_trusted_source_route_checkpointed(
            &target,
            Declaration::Entry(0),
            &route_at(&base),
            |step| {
                if step == team && swaps_left == 1 {
                    swaps_left = 0;
                    // Same spelling, a different directory: the pinned descriptor
                    // still names the original.
                    let moved = base.join("team-moved");
                    std::fs::rename(&team, &moved).unwrap();
                    std::fs::create_dir(&team).unwrap();
                    std::fs::set_permissions(&team, std::fs::Permissions::from_mode(0o700))
                        .unwrap();
                    owner_only_file(&team.join("agent-vm.toml"));
                }
            },
        )
        .expect("the walk stays anchored to its descriptors");
        let swapped = std::fs::metadata(team.join("agent-vm.toml")).unwrap();
        let pinned = std::fs::metadata(base.join("team-moved/agent-vm.toml")).unwrap();
        assert_ne!((swapped.dev(), swapped.ino()), (pinned.dev(), pinned.ino()));
        let opened = opened.opened.expect("a regular file was opened");
        assert_eq!(
            (opened.facts().dev, opened.facts().ino),
            (pinned.dev(), pinned.ino()),
            "the bytes read are the ones the verified descriptor names"
        );
    }

    // ---- #736 phase 1: the untrusted route walker ----

    use crate::config_sources::{SourceEntry, SourceScope};
    use crate::host_paths::FileIdentity;

    fn identity_of(path: &Path) -> FileIdentity {
        let metadata = std::fs::metadata(path).unwrap();
        FileIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
        }
    }

    fn owner_only_bytes(path: &Path, body: &[u8]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::set_permissions(
            path.parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// An entry shaped exactly as `SourceEntry::parse` resolves one: the
    /// lexical join of the captured root and the relative suffix.
    fn relative_entry(root: &Path, suffix: &str) -> SourceEntry {
        SourceEntry::for_tests(true, root.join(suffix))
    }

    /// `Result::expect_err` needs `Debug` on the success value; the read holds
    /// source bytes, so it deliberately has none.
    fn route_error(
        result: std::result::Result<UntrustedSourceRead, UntrustedReadError>,
    ) -> UntrustedReadError {
        match result {
            Ok(read) => panic!("expected a refusal, got {} byte(s)", read.bytes.len()),
            Err(error) => error,
        }
    }

    fn captured_route(home: &Path, root: &Path) -> RouteAnchor {
        RouteAnchor::Captured {
            home: home.to_path_buf(),
            root: root.to_path_buf(),
            root_id: identity_at(root),
        }
    }

    fn boundary_of(root: &Path) -> CheckoutBoundary {
        CheckoutBoundary::measure(root, identity_at(root)).unwrap()
    }

    fn route_with_boundary(base: &Path) -> (RouteAnchor, CheckoutBoundary) {
        let root = base.join("project");
        (
            captured_route(&base.join("home"), &root),
            boundary_of(&root),
        )
    }

    #[test]
    fn a_relative_source_is_admitted_as_checkout_with_one_read() {
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        std::fs::create_dir(base.join("home")).unwrap();
        let root = base.join("project");
        std::fs::create_dir(&root).unwrap();
        let file = root.join("conf/agent-vm.toml");
        owner_only_bytes(&file, b"[[tools]]\nname = \"x\"\ncommand = \"true\"\n");
        let (route, boundary) = route_with_boundary(&base);

        let read = read_untrusted_source_route(
            &relative_entry(&root, "conf/agent-vm.toml"),
            &route,
            Some(&boundary),
            4096,
        )
        .expect("a checkout source is admitted");
        assert_eq!(read.scope, SourceScope::Checkout);
        assert_eq!(read.bytes, b"[[tools]]\nname = \"x\"\ncommand = \"true\"\n");
        assert_eq!(read.identity, identity_of(&file));
    }

    #[test]
    fn an_explicit_external_source_never_enters_the_boundary() {
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        std::fs::create_dir(base.join("home")).unwrap();
        let root = base.join("project");
        std::fs::create_dir(&root).unwrap();
        // Outside the captured root's parent, so the parent checkpoint cannot
        // fire at all; the sibling case is
        // `a_sibling_of_the_captured_root_is_an_external_source`.
        let elsewhere = tempfile::tempdir().unwrap();
        let external = elsewhere.path().canonicalize().unwrap().join("team.toml");
        owner_only_bytes(&external, b"[[tools]]\nname = \"t\"\ncommand = \"true\"\n");
        let (route, boundary) = route_with_boundary(&base);

        let read = read_untrusted_source_route(
            &SourceEntry::for_tests(false, external.clone()),
            &route,
            Some(&boundary),
            4096,
        )
        .expect("an external route is admitted");
        assert_eq!(read.scope, SourceScope::External);
        assert_eq!(read.identity, identity_of(&external));
    }

    /// `..` is resolved through the descriptor stack, so the scope is the route
    /// actually walked: an enclosing worktree admits it, its parent does not.
    #[test]
    fn dot_dot_is_admitted_inside_an_enclosing_worktree_and_refused_above_it() {
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        std::fs::create_dir(base.join("home")).unwrap();
        std::fs::create_dir_all(base.join("repo/.git")).unwrap();
        let root = base.join("repo/sub");
        std::fs::create_dir(&root).unwrap();
        let shared = base.join("repo/shared.toml");
        owner_only_bytes(&shared, b"[[tools]]\n");
        let above = base.join("outside.toml");
        owner_only_bytes(&above, b"[[tools]]\n");
        let route = captured_route(&base.join("home"), &root);
        let boundary = boundary_of(&root);

        let read = read_untrusted_source_route(
            &relative_entry(&root, "../shared.toml"),
            &route,
            Some(&boundary),
            4096,
        )
        .expect("the enclosing worktree is inside the boundary");
        assert_eq!(read.scope, SourceScope::Checkout);
        assert_eq!(read.bytes, b"[[tools]]\n");

        let error = route_error(read_untrusted_source_route(
            &relative_entry(&root, "../../outside.toml"),
            &route,
            Some(&boundary),
            4096,
        ));
        assert!(
            matches!(error, UntrustedReadError::EscapesCheckout),
            "{error:?}"
        );
    }

    /// A final symlink that leaves the admitted region is refused before any
    /// outside byte is opened for reading.
    #[test]
    fn a_final_symlink_that_leaves_the_boundary_is_refused_without_reading() {
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        std::fs::create_dir(base.join("home")).unwrap();
        let root = base.join("project");
        std::fs::create_dir(&root).unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside = outside.path().canonicalize().unwrap();
        let sentinel = outside.join("sentinel.toml");
        std::fs::write(&sentinel, b"SECRET-SENTINEL-736").unwrap();
        symlink(&sentinel, root.join("link.toml")).unwrap();
        let (route, boundary) = route_with_boundary(&base);

        let error = route_error(read_untrusted_source_route(
            &relative_entry(&root, "link.toml"),
            &route,
            Some(&boundary),
            4096,
        ));
        assert!(
            matches!(error, UntrustedReadError::EscapesCheckout),
            "{error:?}"
        );
        // The sentinel was never read: its bytes are only in the refusal's
        // negative space, and the test would need the error to carry them.
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"SECRET-SENTINEL-736");
    }

    /// A multiply-linked checkout file is refused before it is read: its second
    /// name can be outside the checkout, so its bytes are not provably confined.
    #[test]
    fn a_checkout_hard_link_is_refused_at_the_admitted_file() {
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        std::fs::create_dir(base.join("home")).unwrap();
        let root = base.join("project");
        std::fs::create_dir(&root).unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("host.toml");
        std::fs::write(&target, b"SECRET-SENTINEL-736").unwrap();
        std::fs::hard_link(&target, root.join("hard.toml")).unwrap();
        assert_eq!(
            std::fs::symlink_metadata(root.join("hard.toml"))
                .unwrap()
                .nlink(),
            2
        );
        let (route, boundary) = route_with_boundary(&base);

        let error = route_error(read_untrusted_source_route(
            &relative_entry(&root, "hard.toml"),
            &route,
            Some(&boundary),
            4096,
        ));
        assert!(
            matches!(error, UntrustedReadError::CheckoutHardLinked(2)),
            "{error:?}"
        );
    }

    /// A relative entry and an absolute one spelled exactly both meet the parent
    /// checkpoint, and the spelling-free re-read of the root's own entry decides
    /// both; a sibling is still admitted (see
    /// `a_sibling_of_the_captured_root_is_an_external_source`).
    #[test]
    fn a_replaced_root_is_detected_by_the_captured_parent_identity() {
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        std::fs::create_dir(base.join("home")).unwrap();
        let root = base.join("project");
        std::fs::create_dir(&root).unwrap();
        let file = root.join("conf/agent-vm.toml");
        owner_only_bytes(&file, b"[[tools]]\n");
        let route = route_at(&base);
        let boundary = boundary_of(&root);

        // Relative entry: the root itself no longer carries the captured
        // identity, so the walk refuses at its last descent step.
        std::fs::rename(&root, base.join("project-moved")).unwrap();
        std::fs::create_dir(&root).unwrap();
        owner_only_bytes(&file, b"[[tools]]\n");
        let error = route_error(read_untrusted_source_route(
            &relative_entry(&root, "conf/agent-vm.toml"),
            &route,
            Some(&boundary),
            4096,
        ));
        assert!(
            matches!(error, UntrustedReadError::RootReplaced),
            "{error:?}"
        );

        // Absolute entry: the same checkpoint fires when the walk crosses the
        // captured root's name, not only for relative spellings.
        let error = route_error(read_untrusted_source_route(
            &SourceEntry::for_tests(false, file.clone()),
            &route,
            Some(&boundary),
            4096,
        ));
        assert!(
            matches!(error, UntrustedReadError::RootReplaced),
            "{error:?}"
        );
    }

    /// The combined checkpoint the reviewer asked for: replace the captured
    /// root *after* its parent descriptor is open, under an alias of the name.
    /// The walk has no name comparison to consult; only the parent identity and
    /// the child identity decide it.
    #[test]
    fn a_replacement_under_an_alias_is_detected_mid_walk() {
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        std::fs::create_dir(base.join("home")).unwrap();
        let parent = base.join("work");
        std::fs::create_dir(&parent).unwrap();
        let root = parent.join("app");
        std::fs::create_dir(&root).unwrap();
        let file = root.join("conf/agent-vm.toml");
        owner_only_bytes(&file, b"[[tools]]\n");
        let route = captured_route(&base.join("home"), &root);
        let boundary = boundary_of(&root);

        let mut swapped = false;
        let error = route_error(read_untrusted_source_route_checkpointed(
            &relative_entry(&root, "conf/agent-vm.toml"),
            &route,
            Some(&boundary),
            4096,
            |step| {
                if step == parent && !swapped {
                    swapped = true;
                    // The parent descriptor stays open; its child name now names
                    // a different inode, as a case/normalization alias would on
                    // a case-insensitive filesystem.
                    std::fs::rename(&root, parent.join("app-moved")).unwrap();
                    std::fs::create_dir(&root).unwrap();
                    owner_only_bytes(&file, b"[[tools]]\n");
                }
            },
        ));
        assert!(
            matches!(error, UntrustedReadError::RootReplaced),
            "{error:?}"
        );
        assert_eq!(
            std::fs::read(&file).unwrap(),
            b"[[tools]]\n",
            "the replacement is what a spellable check would have read"
        );
    }

    /// The window `a_replacement_under_an_alias_is_detected_mid_walk` cannot
    /// reach: the replacement lands *after* the start-of-walk check and *before*
    /// the walk opens the captured root's own component, and the route spells the
    /// root through a case-variant alias, so no lexical test matches it. The step's
    /// own checkpoint decides it by naming the root's entry in the parent
    /// descriptor the walk already holds.
    #[test]
    fn a_replacement_under_an_alias_is_detected_before_the_root_is_opened() {
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        std::fs::create_dir(base.join("home")).unwrap();
        let parent = base.join("work");
        std::fs::create_dir(&parent).unwrap();
        let root = parent.join("app");
        std::fs::create_dir(&root).unwrap();
        let file = root.join("conf/agent-vm.toml");
        owner_only_bytes(&file, b"[[tools]]\nname = \"aaa\"\n");
        let route = captured_route(&base.join("home"), &root);
        let boundary = boundary_of(&root);
        if !folds_case(&parent) {
            eprintln!(
                "note: {parent:?} does not fold case, so a case-variant alias of the \
                 replaced root cannot resolve; this row asserts nothing here"
            );
            return;
        }
        let alias = parent.join("APP").join("conf/agent-vm.toml");
        let replacement = b"[[tools]]\nname = \"bbb\"\n";

        let mut swapped = false;
        let error = route_error(read_untrusted_source_route_checkpointed(
            &SourceEntry::for_tests(false, alias),
            &route,
            Some(&boundary),
            4096,
            |step| {
                // The parent is open; the walk has not opened the root's own
                // component yet. This is the prologue window, not the mid-walk
                // one.
                if step == parent && !swapped {
                    swapped = true;
                    std::fs::rename(&root, parent.join("app-moved")).unwrap();
                    std::fs::create_dir(&root).unwrap();
                    owner_only_bytes(&file, replacement);
                }
            },
        ));
        assert!(swapped, "the row reached the checkpoint it needs");
        assert!(
            matches!(error, UntrustedReadError::RootReplaced),
            "{error:?}"
        );
        assert_eq!(
            std::fs::read(&file).unwrap(),
            replacement,
            "the alias resolves to the replacement, so a spelling-free-read-free \
             walk would have read it"
        );
    }

    /// The stat-then-open agreement, deterministically, at a step that is not
    /// the captured root's own step (that one also has the parent's change stamp,
    /// so this row could not tell the two guards apart). The seam swaps two
    /// directories inside the captured root between the step's own `statat` and
    /// its `openat`, and swaps them back immediately after the open. Nothing is
    /// left renamed, so every check that looks at a name afterwards passes; only
    /// the agreement refuses, because a descriptor's identity cannot be renamed
    /// after it is open.
    #[test]
    fn a_double_swap_inside_one_step_is_refused_by_the_stat_then_open_agreement() {
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        std::fs::create_dir(base.join("home")).unwrap();
        let root = base.join("project");
        owner_only_bytes(
            &root.join("conf/agent-vm.toml"),
            b"[[tools]]\nname = \"aaa\"\n",
        );
        owner_only_bytes(
            &root.join("conf-alt/agent-vm.toml"),
            b"[[tools]]\nname = \"bbb\"\n",
        );
        let route = captured_route(&base.join("home"), &root);
        let boundary = boundary_of(&root);
        let step = root.join("conf");
        let alt = root.join("conf-alt");
        let mut alt_id = None;

        let mut swapped = false;
        let mut restored = false;
        let result = read_untrusted_source_route_with_seam(
            &SourceEntry::for_tests(false, root.join("conf/agent-vm.toml")),
            &route,
            Some(&boundary),
            4096,
            |path, moment| match moment {
                StepMoment::BeforeOpen if path == step && !swapped => {
                    swapped = true;
                    swap_names(&step, &alt);
                    alt_id = Some(identity_of(&step.join("agent-vm.toml")));
                }
                StepMoment::AfterOpen if path == step && !restored => {
                    restored = true;
                    swap_names(&step, &alt);
                }
                _ => {}
            },
        );
        assert!(swapped, "the seam reached the swapped step");
        assert!(restored, "the seam put the step's name back after the open");
        let alt_id = alt_id.expect("the other directory was at the name");
        match result {
            Err(UntrustedReadError::RootReplaced) => {}
            Ok(read) => {
                assert_eq!(
                    read.identity, alt_id,
                    "the bytes are the swapped-in file's, which is the leak"
                );
                panic!(
                    "expected a refusal, read the swapped-in file's {} byte(s): {:?}",
                    read.bytes.len(),
                    String::from_utf8_lossy(&read.bytes)
                );
            }
            Err(error) => panic!("expected the replacement refusal, got {error:?}"),
        }
        // The double swap completed: the name ends where it started, so no
        // checkpoint that looked at it afterwards could have seen the other one.
        // The captured root itself never moved; only its children swapped.
        let root_now = identity_of(&root);
        assert_eq!(
            (root_now.dev, root_now.ino),
            route_root_id(&route),
            "the captured root is back at its own name"
        );
    }

    /// The window the race harness actually found (1 leak in 4 000 runs at the
    /// parent of this change): a rename between the captured-root checkpoint and
    /// the step's own `statat`, undone after the open. The step's stat and its
    /// open agree (both saw the replacement) and the closing checkpoint sees the
    /// captured root again, so the agreement and both captured-identity checks
    /// pass. Only the parent's change stamp refuses: a rename of any entry there
    /// updates the directory's own `mtime` and `ctime`.
    #[test]
    fn a_swap_before_the_captured_root_step_is_refused_by_the_parent_change_stamp() {
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        std::fs::create_dir(base.join("home")).unwrap();
        let parent = base.join("work");
        std::fs::create_dir(&parent).unwrap();
        let root = parent.join("app");
        let repl = parent.join("rpl");
        owner_only_bytes(
            &root.join("conf/agent-vm.toml"),
            b"[[tools]]\nname = \"aaa\"\n",
        );
        owner_only_bytes(
            &repl.join("conf/agent-vm.toml"),
            b"[[tools]]\nname = \"bbb\"\n",
        );
        let route = captured_route(&base.join("home"), &root);
        let boundary = boundary_of(&root);
        let mut replacement_id = None;

        let mut swapped = false;
        let mut restored = false;
        let result = read_untrusted_source_route_with_seam(
            &SourceEntry::for_tests(false, root.join("conf/agent-vm.toml")),
            &route,
            Some(&boundary),
            4096,
            |path, moment| match moment {
                StepMoment::AfterCapturedRootCheckpoint if path == root && !swapped => {
                    swapped = true;
                    swap_names(&root, &repl);
                    replacement_id = Some(identity_of(&root.join("conf/agent-vm.toml")));
                }
                StepMoment::AfterOpen if path == root && !restored => {
                    restored = true;
                    swap_names(&root, &repl);
                }
                _ => {}
            },
        );
        assert!(
            swapped,
            "the seam reached the step that opens the captured root"
        );
        assert!(
            restored,
            "the seam put the captured root back after the open"
        );
        let replacement_id = replacement_id.expect("the replacement was at the name");
        match result {
            Err(UntrustedReadError::RootReplaced) => {}
            Ok(read) => {
                assert_eq!(
                    read.identity, replacement_id,
                    "the bytes are the replacement's, which is the leak the harness found"
                );
                panic!(
                    "expected a refusal, read the replacement's {} byte(s): {:?}",
                    read.bytes.len(),
                    String::from_utf8_lossy(&read.bytes)
                );
            }
            Err(error) => panic!("expected the replacement refusal, got {error:?}"),
        }
        // The captured root is back at its own name, so every checkpoint on that
        // name passes; the stamp is the only observation that disagrees.
        let restored = identity_of(&root);
        assert_eq!(
            (restored.dev, restored.ino),
            route_root_id(&route),
            "the captured root is back at its own name"
        );
    }

    /// Exchange two names, as `renamex_np(RENAME_SWAP)` does: each keeps its own
    /// contents and both stay linked, which is what makes the replacement readable
    /// through the descriptor a walk opened for it.
    fn swap_names(left: &Path, right: &Path) {
        let temp = left.with_file_name("swap-tmp");
        std::fs::rename(left, &temp).unwrap();
        std::fs::rename(right, left).unwrap();
        std::fs::rename(&temp, right).unwrap();
    }

    fn route_root_id(route: &RouteAnchor) -> (u64, u64) {
        match route {
            RouteAnchor::Captured { root_id, .. } => (root_id.dev, root_id.ino),
            RouteAnchor::Uncaptured => panic!("a captured route"),
        }
    }

    /// Whether this filesystem folds ASCII case, so the alias row below can fail
    /// at all. APFS folds by default; ext4 and most Linux mounts do not.
    fn folds_case(dir: &Path) -> bool {
        let upper = dir.join("CaseFoldingProbe");
        std::fs::write(&upper, b"probe").unwrap();
        let folded = dir.join("casefoldingprobe").exists();
        std::fs::remove_file(&upper).unwrap();
        folded
    }

    /// The B1 identity guarantee must not depend on how the route spells the
    /// captured root. A case-variant alias of a *replaced* root resolves to the
    /// replacement on a case-insensitive filesystem, matches no lexical
    /// `starts_with`, and is offered for approval as an external host source —
    /// bypassing the checkout classification a replaced checkout must refuse.
    #[test]
    fn a_case_variant_alias_of_a_replaced_root_is_refused() {
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        std::fs::create_dir(base.join("home")).unwrap();
        let parent = base.join("work");
        std::fs::create_dir(&parent).unwrap();
        let root = parent.join("app");
        std::fs::create_dir(&root).unwrap();
        let file = root.join("conf/agent-vm.toml");
        owner_only_bytes(&file, b"[[tools]]\n");
        let route = captured_route(&base.join("home"), &root);
        let boundary = boundary_of(&root);
        // The root is replaced under its own name: new inode, same spelling.
        std::fs::rename(&root, parent.join("app-moved")).unwrap();
        std::fs::create_dir(&root).unwrap();
        owner_only_bytes(&file, b"[[tools]]\n");

        if !folds_case(&parent) {
            eprintln!(
                "note: {parent:?} does not fold case, so a case-variant alias of the \
                 replaced root cannot resolve; this row asserts nothing here"
            );
            return;
        }
        let alias = parent.join("APP").join("conf/agent-vm.toml");
        assert_eq!(
            std::fs::read(&alias).unwrap(),
            b"[[tools]]\n",
            "the alias reaches the replacement, so the walk would read it"
        );
        let error = route_error(read_untrusted_source_route(
            &SourceEntry::for_tests(false, alias),
            &route,
            Some(&boundary),
            4096,
        ));
        assert!(
            matches!(error, UntrustedReadError::RootReplaced),
            "{error:?}"
        );
    }

    /// The capture and the boundary are two observations of one path, and the
    /// load makes them at different moments. One `RENAME_SWAP` between them left
    /// the captured root outside its own boundary (`root_in_boundary=false` in the
    /// instrumented trace), so a file the checkout rule refuses was read and
    /// reviewed as an `external` source. Reproduced here without a race: the
    /// boundary is measured while the path names a different directory, the path
    /// then holds the captured root again, and the read goes through the walker.
    ///
    /// Both halves matter: the boundary must contain the captured root by
    /// identity, and the walk must therefore refuse the captured root's own
    /// multiply-linked file instead of handing it over as external bytes.
    #[test]
    fn a_boundary_measured_through_a_replaced_path_still_contains_the_captured_root() {
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        std::fs::create_dir(base.join("home")).unwrap();
        let parent = base.join("work");
        std::fs::create_dir(&parent).unwrap();
        let root = parent.join("repo");
        std::fs::create_dir(&root).unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("outside.toml");
        owner_only_bytes(&target, b"[[tools]]\nname = \"bbb\"\n");
        std::fs::create_dir_all(root.join("conf")).unwrap();
        std::fs::hard_link(&target, root.join("conf/target.toml")).unwrap();
        let root_id = identity_at(&root);
        // The command's single capture, taken while the path names the root.
        let route = captured_route(&base.join("home"), &root);

        // The load measures the boundary after that capture. One swap is enough
        // to make the path name a different directory at this instant.
        std::fs::rename(&root, parent.join("repo-moved")).unwrap();
        std::fs::create_dir(&root).unwrap();
        let boundary = route
            .checkout_boundary()
            .unwrap()
            .expect("a captured route has a boundary");
        std::fs::remove_dir(&root).unwrap();
        std::fs::rename(parent.join("repo-moved"), &root).unwrap();

        // A cursor path no measured root can match: only the captured identity
        // can put the walk inside its own checkout. This half needs no case
        // folding, so it asserts everywhere.
        assert!(
            boundary.contains(
                (root_id.dev, root_id.ino),
                Path::new("/elsewhere/conf/x.toml")
            ),
            "the boundary must contain the captured root by identity, not by a re-read path"
        );

        // The relative read through the same boundary: the captured root's own
        // file has two links, so the checkout rule must refuse it. A boundary
        // that had kept the other directory's identity returned its bytes as an
        // external source.
        let error = route_error(read_untrusted_source_route(
            &relative_entry(&root, "conf/target.toml"),
            &route,
            Some(&boundary),
            4096,
        ));
        assert!(
            matches!(error, UntrustedReadError::CheckoutHardLinked(2)),
            "{error:?}"
        );

        // …and the same read spelled through a case-variant alias of the root,
        // whose cursor path matches the boundary root only by identity.
        if !folds_case(&parent) {
            eprintln!(
                "note: {parent:?} does not fold case, so the alias half of this row \
                 cannot resolve; the identity assertions above still ran"
            );
            return;
        }
        let alias = parent.join("REPO").join("conf/target.toml");
        assert_eq!(
            std::fs::read(&alias).unwrap(),
            b"[[tools]]\nname = \"bbb\"\n"
        );
        let error = route_error(read_untrusted_source_route(
            &SourceEntry::for_tests(false, alias),
            &route,
            Some(&boundary),
            4096,
        ));
        assert!(
            matches!(error, UntrustedReadError::CheckoutHardLinked(2)),
            "{error:?}"
        );
    }

    /// A relative entry with no captured root is a programming error, and it is
    /// reported as one rather than guessed at.
    #[test]
    fn a_relative_entry_without_a_captured_root_is_an_io_refusal() {
        let entry = relative_entry(Path::new("/tmp"), "team.toml");
        let error = route_error(read_untrusted_source_route(
            &entry,
            &RouteAnchor::Uncaptured,
            None,
            4096,
        ));
        let UntrustedReadError::Io(error) = error else {
            panic!("expected an internal I/O refusal");
        };
        assert!(
            error.to_string().contains("captured project root"),
            "{error}"
        );
    }

    /// The regression the route half of B1 exists for: a `trust = false` source
    /// beside the project root. The sibling here is a directory, so the walk
    /// descends into a child of the captured root's parent that is not the root;
    /// no checkpoint is armed, and the route earns `External` with its bytes read
    /// rather than merely a scope.
    #[test]
    fn a_sibling_of_the_captured_root_is_an_external_source() {
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        std::fs::create_dir(base.join("home")).unwrap();
        let parent = base.join("work");
        std::fs::create_dir(&parent).unwrap();
        let root = parent.join("app");
        std::fs::create_dir(&root).unwrap();
        let shared = parent.join("shared/team.toml");
        owner_only_bytes(&shared, b"[[tools]]\nname = \"team\"\n");
        let route = captured_route(&base.join("home"), &root);
        let boundary = boundary_of(&root);

        let read = read_untrusted_source_route(
            &SourceEntry::for_tests(false, shared.clone()),
            &route,
            Some(&boundary),
            4096,
        )
        .expect("a sibling of the captured root is an external source");
        assert_eq!(read.scope, SourceScope::External);
        assert_eq!(read.bytes, b"[[tools]]\nname = \"team\"\n");
        assert_eq!(read.identity, identity_of(&shared));
    }

    /// The same sibling spelled relative to the root descends through the root
    /// first, so the separate rule — a route that entered the boundary must
    /// finish inside it — decides it. Unchanged by the admission above, and kept
    /// here so a later edit cannot widen it silently.
    #[test]
    fn a_sibling_reached_through_the_root_stays_a_boundary_refusal() {
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        std::fs::create_dir(base.join("home")).unwrap();
        let parent = base.join("work");
        std::fs::create_dir(&parent).unwrap();
        let root = parent.join("app");
        std::fs::create_dir(&root).unwrap();
        let shared = parent.join("shared/team.toml");
        owner_only_bytes(&shared, b"[[tools]]\nname = \"team\"\n");
        let route = captured_route(&base.join("home"), &root);
        let boundary = boundary_of(&root);

        let error = route_error(read_untrusted_source_route(
            &relative_entry(&root, "../shared/team.toml"),
            &route,
            Some(&boundary),
            4096,
        ));
        assert!(
            matches!(error, UntrustedReadError::EscapesCheckout),
            "{error:?}"
        );
    }

    /// `/` is opened before any step runs, so a boundary that *is* `/` must be
    /// entered from that descriptor rather than from a parent step.
    #[test]
    fn the_open_root_descriptor_enters_a_root_boundary() {
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        let file = base.join("team.toml");
        owner_only_bytes(&file, b"[[tools]]\n");
        let slash = identity_of(Path::new("/"));
        let boundary =
            CheckoutBoundary::for_tests(&[(slash.dev, slash.ino)], &[PathBuf::from("/")]);
        let route = RouteAnchor::Uncaptured;
        let read = read_untrusted_source_route(
            &SourceEntry::for_tests(false, file.clone()),
            &route,
            Some(&boundary),
            4096,
        )
        .expect("a root boundary admits the route");
        assert_eq!(read.scope, SourceScope::Checkout);
        assert_eq!(read.identity, identity_of(&file));
    }
}
