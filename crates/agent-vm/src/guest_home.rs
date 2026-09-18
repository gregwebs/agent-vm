//! The one guest-HOME symlink list, shared by both guest-user modes.
//!
//! `persist` extends [`crate::credential_provider::guest_home_links`] with
//! config-declared paths, and both provisioning sites consume the *same* list:
//! root mode bakes it into the rootfs via `run.rs`'s `.patch()` block, and the
//! non-root default wires it up host-side in
//! [`crate::session::ProjectSession::provision_guest_home`]. That shared list is
//! the only thing stopping the two from drifting (CONTEXT.md → *Guest HOME*,
//! ADR-0002).
//!
//! This module is pure: it computes the link list, the ancestor directories
//! that must exist, and the mount-shadowing conflicts, and does no I/O. It
//! lives here rather than in `credential_provider` because `config` already
//! depends on `credential_provider`; the reverse edge would cycle.

use std::path::{Path, PathBuf};

use crate::config::{PersistPath, guest_paths_overlap};

/// Namespace under the project state dir for tool-declared `persist` paths.
/// Disjoint from every provider state entry (asserted by a test, not by this
/// comment), so a `persist` path can never land on provider state.
pub(crate) const PERSIST_STATE_DIR: &str = "persist";

/// Who declared a link.
///
/// Read by the **non-root** site only: root mode force-symlinks both variants,
/// because `/root` is rebaked into a fresh rootfs every boot so nothing real is
/// ever at a link path there. Do not read this asymmetry as the two sites
/// drifting — they consume the same list, which is the invariant this module
/// exists to hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinkSource {
    Compiled,
    Declared,
}

/// One guest `$HOME`-relative symlink and the state-dir entry it points at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GuestHomeLink {
    pub(crate) home_relative: PathBuf,
    pub(crate) state_relative: PathBuf,
    pub(crate) source: LinkSource,
}

impl GuestHomeLink {
    /// The guest-absolute target string a symlink stores verbatim. Persist
    /// paths come from UTF-8 TOML and compiled links are `&'static str`, so the
    /// rendering cannot fail.
    pub(crate) fn guest_target(&self) -> String {
        format!("/agent-vm-state/{}", self.state_relative.display())
    }
}

/// Compiled-in provider + generic links first, in `guest_home_links()` order
/// (unchanged), then one `Declared` link per declared path under
/// `<state>/persist/`.
///
/// Takes the paths, not a `CatalogEntry`: `CatalogEntry`'s fields are private
/// to `config` and it has no constructor outside it, so the narrower parameter
/// is both a smaller interface and the difference between a table-driven unit
/// test and one that has to build a config fixture.
pub(crate) fn links(persist: &[PersistPath]) -> Vec<GuestHomeLink> {
    let mut links: Vec<GuestHomeLink> = crate::credential_provider::guest_home_links()
        .into_iter()
        .map(|link| GuestHomeLink {
            home_relative: PathBuf::from(link.home_relative),
            state_relative: PathBuf::from(link.state_relative),
            source: LinkSource::Compiled,
        })
        .collect();
    for path in persist {
        links.push(GuestHomeLink {
            home_relative: path.as_path().to_path_buf(),
            state_relative: Path::new(PERSIST_STATE_DIR).join(path.as_path()),
            source: LinkSource::Declared,
        });
    }
    links
}

/// Every ancestor directory of a link's `home_relative`, deduped, **with every
/// directory's parent ahead of it** — the ordering the root-mode `.patch()`
/// mkdir chain needs. For the compiled-in list this is exactly
/// `[".local", ".local/share", ".config"]`, the literal triple both sites
/// hard-code today.
pub(crate) fn link_parent_dirs(links: &[GuestHomeLink]) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    for link in links {
        let components: Vec<_> = link.home_relative.components().collect();
        // Every component but the last is a directory the link path sits in.
        let mut ancestor = PathBuf::new();
        for component in &components[..components.len().saturating_sub(1)] {
            ancestor.push(component.as_os_str());
            if !dirs.contains(&ancestor) {
                dirs.push(ancestor.clone());
            }
        }
    }
    dirs
}

/// Declared links that would shadow (or be shadowed by) a guest mount point.
/// Pure: takes the already-resolved guest-absolute mount paths, so the
/// env/mount-plan I/O stays in `run::launch`. Empty means no conflict.
///
/// **Precondition:** every entry of `guest_mount_paths` must be a normalized
/// guest path — its HOME-relative rendering is components joined by single `/`
/// — because [`config::guest_paths_overlap`] is byte-level and assumes exactly
/// that (ADR-0018). This holds for the callers: core volumes come from
/// [`crate::user::core_dir_volumes`] over a canonicalized project dir and
/// `--mount` guest paths are rebuilt by `mount::normalize_guest`. A future
/// caller that passes an unnormalized path would *miss* conflicts rather than
/// fail, so re-normalize before calling.
///
/// Needed because the guest `$HOME` namespace also holds the project bind and
/// any `--mount` under HOME, and agentd creates those mountpoints *inside* the
/// already-mounted HOME (ADR-0002). A config cannot see the project path, so
/// this axis cannot be checked at parse time.
pub(crate) fn mount_conflicts<'a>(
    links: &'a [GuestHomeLink],
    guest_home: &Path,
    guest_mount_paths: &[PathBuf],
) -> Vec<(&'a GuestHomeLink, PathBuf)> {
    let mut conflicts = Vec::new();
    for mount in guest_mount_paths {
        // Only mounts *under* HOME can collide with a HOME-relative link. The
        // HOME mount itself is the namespace, not a path inside it, so it is
        // skipped (its HOME-relative rendering is empty).
        let Ok(relative) = mount.strip_prefix(guest_home) else {
            continue;
        };
        if relative.as_os_str().is_empty() {
            continue;
        }
        for link in links
            .iter()
            .filter(|link| link.source == LinkSource::Declared)
        {
            if guest_paths_overlap(&link.home_relative, relative) {
                conflicts.push((link, mount.clone()));
            }
        }
    }
    conflicts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn persist(path: &str) -> PersistPath {
        PersistPath::for_test(path)
    }

    fn declared(home_relative: &str) -> GuestHomeLink {
        GuestHomeLink {
            home_relative: PathBuf::from(home_relative),
            state_relative: Path::new(PERSIST_STATE_DIR).join(home_relative),
            source: LinkSource::Declared,
        }
    }

    // -- V4: the compiled list is unchanged -------------------------------

    #[test]
    fn compiled_links_are_unchanged_and_in_order() {
        let links = links(&[]);
        let compiled = crate::credential_provider::guest_home_links();
        assert_eq!(links.len(), compiled.len());
        for (link, golden) in links.iter().zip(compiled.iter()) {
            assert_eq!(link.home_relative, PathBuf::from(golden.home_relative));
            assert_eq!(link.state_relative, PathBuf::from(golden.state_relative));
            assert_eq!(link.source, LinkSource::Compiled);
        }
    }

    #[test]
    fn compiled_parent_dirs_match_the_literal_triple_and_are_parents_first() {
        let dirs = link_parent_dirs(&links(&[]));
        assert_eq!(
            dirs,
            vec![
                PathBuf::from(".local"),
                PathBuf::from(".local/share"),
                PathBuf::from(".config"),
            ]
        );
        // The invariant the root `.patch()` chain needs: a directory's parent
        // is always inserted before it.
        for (index, dir) in dirs.iter().enumerate() {
            if let Some(parent) = dir.parent()
                && !parent.as_os_str().is_empty()
            {
                let parent_index = dirs
                    .iter()
                    .position(|candidate| candidate == parent)
                    .expect("every parent directory must be present");
                assert!(
                    parent_index < index,
                    "{parent:?} must precede {dir:?} in {dirs:?}"
                );
            }
        }
    }

    // -- V4b: the namespace claim is tested, not asserted in prose ---------

    #[test]
    fn persist_namespace_is_disjoint_from_every_provider_state_entry() {
        assert!(
            !crate::credential_provider::eager_state_dirs().contains(&PERSIST_STATE_DIR),
            "PERSIST_STATE_DIR collides with an eager provider state dir"
        );
        for link in crate::credential_provider::guest_home_links() {
            assert_ne!(
                link.state_relative, PERSIST_STATE_DIR,
                "the persist namespace collides with a provider link's state entry"
            );
        }
    }

    // -- V5: declared links -----------------------------------------------

    #[test]
    fn declared_links_target_the_persist_namespace() {
        let links = links(&[persist(".aider.conf.yml"), persist(".cache/aider")]);
        let compiled_len = crate::credential_provider::guest_home_links().len();
        let declared = &links[compiled_len..];
        assert_eq!(
            declared[0].state_relative,
            PathBuf::from("persist/.aider.conf.yml")
        );
        assert_eq!(
            declared[0].guest_target(),
            "/agent-vm-state/persist/.aider.conf.yml"
        );
        assert_eq!(
            declared[1].state_relative,
            PathBuf::from("persist/.cache/aider")
        );
        assert_eq!(
            declared[1].guest_target(),
            "/agent-vm-state/persist/.cache/aider"
        );
        assert_eq!(declared[0].source, LinkSource::Declared);
    }

    #[test]
    fn nested_declared_paths_add_their_ancestors_deduped_parents_first() {
        let dirs = link_parent_dirs(&links(&[
            persist(".cache/aider"),
            persist(".cache/aider/nested"),
            persist(".aider.conf.yml"),
        ]));
        // The compiled triple first, then the declared ancestors (`.cache`
        // before `.cache/aider`), deduped.
        assert_eq!(
            dirs,
            vec![
                PathBuf::from(".local"),
                PathBuf::from(".local/share"),
                PathBuf::from(".config"),
                PathBuf::from(".cache"),
                PathBuf::from(".cache/aider"),
            ]
        );
    }

    // -- V5b: mount_conflicts ---------------------------------------------

    #[test]
    fn a_mount_under_home_conflicts_on_either_overlap_direction() {
        let home = Path::new("/Users/claude");
        // The project itself, mounted at its mirrored guest path.
        let project_mount = PathBuf::from("/Users/claude/code/agent-vm");

        // `persist = ["code"]` is an ancestor of the project mount.
        let ancestor = vec![declared("code")];
        assert_eq!(
            mount_conflicts(&ancestor, home, std::slice::from_ref(&project_mount)).len(),
            1
        );

        // `persist = ["code/agent-vm/x"]` is inside the project mount.
        let inside = vec![declared("code/agent-vm/x")];
        assert_eq!(
            mount_conflicts(&inside, home, std::slice::from_ref(&project_mount)).len(),
            1
        );

        // A sibling sharing a string prefix but no component does not overlap.
        let sibling = vec![declared("codex-cache")];
        assert!(mount_conflicts(&sibling, home, std::slice::from_ref(&project_mount)).is_empty());
    }

    #[test]
    fn a_mount_outside_home_never_conflicts() {
        let home = Path::new("/Users/claude");
        let outside = vec![declared("code")];
        let payload = PathBuf::from("/opt/data");
        assert!(mount_conflicts(&outside, home, &[payload]).is_empty());
    }

    #[test]
    fn the_home_mount_itself_is_not_a_conflict() {
        let home = Path::new("/Users/claude");
        let links = vec![declared(".aider.conf.yml")];
        assert!(mount_conflicts(&links, home, &[home.to_path_buf()]).is_empty());
    }

    #[test]
    fn root_mode_home_does_not_conflict_with_a_project_elsewhere() {
        let links = vec![declared("code")];
        assert!(
            mount_conflicts(
                &links,
                Path::new("/root"),
                &[PathBuf::from("/Users/claude/code/agent-vm")]
            )
            .is_empty()
        );
    }

    #[test]
    fn compiled_links_are_never_reported_as_mount_conflicts() {
        let home = Path::new("/Users/claude");
        let links = links(&[]);
        // A project mounted at `~/.claude` would overlap the compiled link, but
        // the compiled list is config-time checked and deliberately not
        // reported here.
        let project = PathBuf::from("/Users/claude/.claude");
        assert!(mount_conflicts(&links, home, &[project]).is_empty());
    }
}
