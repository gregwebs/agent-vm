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
}
