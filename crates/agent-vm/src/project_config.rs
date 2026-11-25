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
#[derive(Debug)]
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
#[derive(Debug)]
pub(crate) enum RouteAnchor {
    /// The `$HOME` the config path was derived from, and the canonical project
    /// root from the command's single [`crate::project::ProjectDir`] capture
    /// (ADR-0073 D5). Both travel with the path so a check cannot be run
    /// against one home while the file is read through another.
    Captured { home: PathBuf, root: PathBuf },
    /// No captured root: only tests build it, and no production caller does.
    /// Named rather than an `Option` field so that a reader which acquires this
    /// state must write it, and see the cost stated on
    /// [`StoreRoute::Unchecked`].
    #[cfg_attr(not(test), allow(dead_code))]
    Uncaptured,
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
    let RouteAnchor::Captured { home, root } = &project.route else {
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
/// Shared by the project store check (ADR-0073) and the `:trust` user-config route
/// checks (ADR-0074), so the three cannot disagree about what "aliased into the
/// active project" means.
fn resolves_inside_project(canonical: &Path, expected: Option<&Path>, root: &Path) -> bool {
    canonical.starts_with(root) && expected != Some(canonical)
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
    let RouteAnchor::Captured { home, root } = route else {
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
    let RouteAnchor::Captured { home, root } = route else {
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
pub(crate) struct CheckoutBoundary {
    boundary_ids: std::collections::BTreeSet<(u64, u64)>,
    boundary_roots: Vec<PathBuf>,
}

impl CheckoutBoundary {
    /// Measure the boundary from the captured canonical project root.
    ///
    /// Every ancestor is inspected from the filesystem root downwards so a nearer
    /// `.git` never hides a farther one, and an unstatable ancestor fails closed:
    /// a boundary that cannot be measured is a boundary that cannot be trusted.
    fn measure(root: &Path) -> anyhow::Result<Self> {
        let mut boundary_ids = std::collections::BTreeSet::new();
        let mut boundary_roots = Vec::new();
        let fail = |kind: std::io::ErrorKind| {
            anyhow::anyhow!("config: refusing to measure the active checkout's boundary ({kind:?})")
        };
        let mut ancestor = Some(root);
        while let Some(dir) = ancestor {
            let is_worktree = std::fs::symlink_metadata(dir.join(".git")).is_ok();
            if dir == root || is_worktree {
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

/// One queue entry of the route walk: a normal component, `.`, or `..`.
#[derive(Clone)]
enum RouteStep {
    Name(std::ffi::OsString),
    Here,
    Up,
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

    let boundary = match route {
        RouteAnchor::Captured { root, .. } => Some(CheckoutBoundary::measure(root)?),
        RouteAnchor::Uncaptured => None,
    };
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
    const MAX_SYMLINK_HOPS: usize = 40;

    // Never echo component bytes: the route checks validate paths, not values.
    fn push_path_steps(queue: &mut std::collections::VecDeque<RouteStep>, path: &Path) {
        let mut steps = Vec::new();
        for component in path.components() {
            match component {
                std::path::Component::RootDir | std::path::Component::Prefix(_) => {}
                std::path::Component::CurDir => steps.push(RouteStep::Here),
                std::path::Component::ParentDir => steps.push(RouteStep::Up),
                std::path::Component::Normal(name) => {
                    steps.push(RouteStep::Name(name.to_os_string()))
                }
            }
        }
        for step in steps.into_iter().rev() {
            queue.push_front(step);
        }
    }

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
                        let controlled = (child_facts.uid == euid && child_facts.mode & 0o022 == 0)
                            || (child_facts.uid == 0
                                && (child_facts.mode & 0o022 == 0
                                    || child_facts.mode & 0o1000 != 0));
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

    /// A tier as discovery builds it: the path from `home`, checked against the
    /// project root. Named fields, so no two paths can be swapped.
    fn tier(home: &Path, project: &ProjectDir, root: &Path) -> ProjectTierPaths {
        ProjectTierPaths {
            config: path(home, project),
            route: RouteAnchor::Captured {
                home: home.to_path_buf(),
                root: root.to_path_buf(),
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
        RouteAnchor::Captured {
            home: base.join("home"),
            root: base.join("project"),
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
        let route = RouteAnchor::Captured {
            home: home.clone(),
            root: home.join("work/app"),
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
}
