//! The one `==> Mounts:` section a launch prints about the host paths it
//! exposes beyond the binds every launch has (guest HOME, the project, agent-vm
//! state, the credential store).
//!
//! One section, in one place: a reader should not have to find a config count
//! line near the banner, per-bind lines a hundred lines later and a fork's
//! lifecycle line in between. The header names the count and the sources that
//! supplied it (the verified user config's contributing `[mount_sets]` names,
//! and/or `--mount`); the bind lines follow while a reader can still hold them
//! in mind; preparation's own notices (fork lifecycle, seed omissions,
//! `:follow-links` warnings) close the block.
//!
//! The list is bounded by [`MAX_LISTED_MOUNTS`]. Past it the section names the
//! sources and points at the one command that reads the whole plan back
//! (`agent-vm msb inspect`), because a `:follow-links` walk is bounded by the
//! host tree rather than by agent-vm. A **fork** is the exception either way: its
//! stored copy is not derivable from the declaration, so its lifecycle line
//! always prints.

use crate::{
    mount::{PreparedMountPlan, PreparedVolume, PreparedVolumeSource, VolumeRole},
    one_line,
};
use std::path::PathBuf;

/// How many declared mounts a launch lists one by one.
///
/// Three is what a hand-written config usually declares, and the point past
/// which the lines stop being readable as a set. Unlike the capped classes in
/// `mount`, this cap hides nothing permanently: the section always says where the
/// complete list is.
const MAX_LISTED_MOUNTS: usize = 3;

/// Where this launch's declared mounts came from, for the section's header.
///
/// Built by `mount_selection` from what it selected — the config file, the
/// `[mount_sets]` names that actually supplied a declaration, whether argv
/// declared any, and what `--no-config-mounts` withheld. Deliberately not the
/// *selecting* names: naming `pi-agent`'s nested `agent` needs no new tracking,
/// because each config declaration already carries the set it was written in,
/// while the name a tool list used to reach it is not retained.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct MountSources {
    /// The verified file(s) that supplied a listed declaration or withheld one,
    /// deduplicated in first-seen order: the user defaults file, then the file
    /// that declared the launched tool's own list when it is distinct (#735).
    files: Vec<PathBuf>,
    /// Contributing set names, first-seen order, deduplicated.
    sets: Vec<String>,
    /// Whether argv declared at least one mount (a path or a set name).
    cli: bool,
    /// How many declarations `--no-config-mounts` withheld, when it withheld any.
    skipped: Option<usize>,
}

impl MountSources {
    pub(crate) fn new(
        files: Vec<PathBuf>,
        sets: Vec<String>,
        cli: bool,
        skipped: Option<usize>,
    ) -> Self {
        Self {
            files,
            sets,
            cli,
            skipped,
        }
    }

    /// The contributing files through [`one_line::quoted_paths`], the one
    /// rendering the preparation notice uses too.
    fn quoted_files(&self) -> String {
        one_line::quoted_paths(&self.files)
    }

    /// The `==> Mounts: …` header, or `None` when the launch declared nothing and
    /// withheld nothing — a launch with no extra mounts prints no section.
    ///
    /// `total` is the number of binds the section is about, which the caller
    /// counts from the prepared plan: a set list is a selection, not a count, and
    /// duplicated or nested declarations collapse into one bind.
    pub(crate) fn header(&self, total: usize) -> Option<String> {
        match (total, self.skipped, self.files.is_empty()) {
            // Nothing was mounted: the one thing to report is what the opt-out
            // withheld, and a bare "0 mounts" would not say it.
            (0, Some(skipped), false) => Some(format!(
                "==> Mounts: skipped {skipped} from {} (--no-config-mounts)",
                self.quoted_files()
            )),
            (0, _, _) => None,
            (total, skipped, no_files) => {
                let mut provenance: Vec<String> = Vec::new();
                if !no_files {
                    let mut config = format!("config {}", self.quoted_files());
                    match self.sets.as_slice() {
                        [] => {}
                        [only] => config.push_str(&format!(", set {only}")),
                        several => config.push_str(&format!(", sets {}", several.join(", "))),
                    }
                    if let Some(skipped) = skipped {
                        config.push_str(&format!(": {skipped} skipped by --no-config-mounts"));
                    }
                    provenance.push(config);
                }
                if self.cli {
                    provenance.push("--mount".to_owned());
                }
                Some(if provenance.is_empty() {
                    format!("==> Mounts: {total}")
                } else {
                    format!("==> Mounts: {total} ({})", provenance.join("; "))
                })
            }
        }
    }
}

/// This launch's whole mount section: header, the binds, then preparation's
/// notices.
pub(crate) fn lines(
    sources: &MountSources,
    plan: &PreparedMountPlan,
    sandbox_name: &str,
) -> Vec<String> {
    let total = plan.volumes.len();
    let mut lines = Vec::new();
    if let Some(header) = sources.header(total) {
        lines.push(header);
    }
    // A fork's stored copy is named by its lifecycle notice in `plan.notices`,
    // not here: one message per fork mount, and the lifecycle line carries the
    // fork and what to delete to reset it.
    // Declarations before the targets a `:follow-links` walk discovered: the
    // mounts themselves keep their order, only this report reorders.
    let mut listed: Vec<&PreparedVolume> = plan
        .volumes
        .iter()
        .filter(|volume| !matches!(volume.source, PreparedVolumeSource::Fork(_)))
        .collect();
    listed.sort_by_key(|volume| match volume.role {
        VolumeRole::Explicit => 0,
        VolumeRole::Followed => 1,
    });
    if listed.len() > MAX_LISTED_MOUNTS {
        // Nothing is listed: the pointer replaces the list rather than following a
        // truncated one, so the reader is never shown an arbitrary prefix of it.
        lines.push(
            one_line::text(&format!(
                "==>   view all {total} mounts: agent-vm msb inspect {}",
                one_line::text(sandbox_name)
            ))
            .to_string(),
        );
    } else {
        lines.extend(listed.into_iter().filter_map(PreparedVolume::mount_notice));
    }
    lines.extend(plan.notices.iter().cloned());
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mount::{PreparedMountPlan, PreparedNodeKind, PreparedVolume, VolumeRole};
    use std::path::PathBuf;

    fn bind(guest: &str, host: &str, role: VolumeRole) -> PreparedVolume {
        PreparedVolume {
            guest: PathBuf::from(guest),
            source: PreparedVolumeSource::ReadOnlyBind(PathBuf::from(host)),
            node_kind: PreparedNodeKind::Directory,
            role,
        }
    }

    fn fork(guest: &str) -> PreparedVolume {
        PreparedVolume {
            guest: PathBuf::from(guest),
            source: PreparedVolumeSource::Fork(PathBuf::from("/state/forks/abc/data")),
            node_kind: PreparedNodeKind::Directory,
            role: VolumeRole::Explicit,
        }
    }

    fn prepared(volumes: Vec<PreparedVolume>, notices: Vec<&str>) -> PreparedMountPlan {
        PreparedMountPlan {
            volumes,
            repo_scan_roots: Vec::new(),
            notices: notices.into_iter().map(str::to_string).collect(),
        }
    }

    fn sources(sets: &[&str], cli: bool) -> MountSources {
        MountSources::new(
            vec![PathBuf::from("/home/a/.config/agent-vm/config.toml")],
            sets.iter().map(|set| set.to_string()).collect(),
            cli,
            None,
        )
    }

    /// Up to the cap every bind is listed, and the header says where they came
    /// from: the file, the sets that supplied a declaration, and `--mount`.
    #[test]
    fn a_short_list_is_printed_in_full() {
        let plan = prepared(
            vec![
                bind(
                    "/home/a/.agents/skills",
                    "/home/a/.agents/skills",
                    VolumeRole::Explicit,
                ),
                bind(
                    "/home/a/.config/github-app",
                    "/home/a/.config/github-app",
                    VolumeRole::Explicit,
                ),
            ],
            Vec::new(),
        );
        assert_eq!(
            lines(&sources(&["agent"], false), &plan, "agent-vm-abc-42"),
            [
                "==> Mounts: 2 (config \"/home/a/.config/agent-vm/config.toml\", set agent)",
                "==> Mounting /home/a/.agents/skills (read-only)",
                "==> Mounting /home/a/.config/github-app (read-only)",
            ]
        );
        // A lone set is `set`; several are `sets`, in first-seen order.
        assert_eq!(
            lines(
                &sources(&["pi-agent", "agent"], true),
                &plan,
                "agent-vm-abc-42"
            )[0],
            "==> Mounts: 2 (config \"/home/a/.config/agent-vm/config.toml\", sets pi-agent, agent; \
             --mount)"
        );
    }

    /// Past the cap nothing is listed: the header keeps the sets, and one pointer
    /// replaces the list rather than following a truncated one.
    #[test]
    fn a_long_list_names_its_sources_and_the_way_to_read_it_back() {
        let plan = prepared(
            (0..4)
                .map(|i| {
                    bind(
                        &format!("/guest-{i}"),
                        &format!("/source-{i}"),
                        VolumeRole::Explicit,
                    )
                })
                .collect(),
            Vec::new(),
        );
        assert_eq!(
            lines(&sources(&["rust"], false), &plan, "agent-vm-abc-42"),
            [
                "==> Mounts: 4 (config \"/home/a/.config/agent-vm/config.toml\", set rust)",
                "==>   view all 4 mounts: agent-vm msb inspect agent-vm-abc-42",
            ]
        );
        // The sandbox name is generated, so the pointer goes through the one-line
        // policy like every other notice: no source of it may forge a line.
        let long = prepared(
            (0..4)
                .map(|i| bind(&format!("/g{i}"), &format!("/s{i}"), VolumeRole::Explicit))
                .collect(),
            Vec::new(),
        );
        assert_eq!(
            lines(&sources(&[], true), &long, "agent-vm-a\n==> forged")[1],
            "==>   view all 4 mounts: agent-vm msb inspect agent-vm-a\\x0a==> forged"
        );
    }

    /// A fork's stored copy is not derivable from the declaration, so its one
    /// message prints either way — and it is *one* message: the bind line is
    /// suppressed for it, and the lifecycle notice is the one that names the fork
    /// and what to delete to reset it.
    #[test]
    fn a_fork_always_prints_exactly_one_line() {
        let plan = prepared(
            vec![fork("/home/a/.pi/agent")],
            vec!["==> Reusing fork /home/a/.pi/agent: delete /state/forks/abc to reset"],
        );
        assert_eq!(
            lines(&sources(&["pi-agent"], false), &plan, "agent-vm-abc-42"),
            [
                "==> Mounts: 1 (config \"/home/a/.config/agent-vm/config.toml\", set pi-agent)",
                "==> Reusing fork /home/a/.pi/agent: delete /state/forks/abc to reset",
            ]
        );

        // Over the cap, the forks are what still gets named.
        let mut volumes = vec![fork("/home/a/.pi/agent")];
        volumes.extend((0..4).map(|i| {
            bind(
                &format!("/guest-{i}"),
                &format!("/source-{i}"),
                VolumeRole::Explicit,
            )
        }));
        let long = prepared(
            volumes,
            vec![
                "==> Initialized fork /home/a/.pi/agent -> /state/forks/def/data; delete \
                 /state/forks/def to reset",
            ],
        );
        assert_eq!(
            lines(&sources(&["pi-agent"], false), &long, "agent-vm-abc-42"),
            [
                "==> Mounts: 5 (config \"/home/a/.config/agent-vm/config.toml\", set pi-agent)",
                "==>   view all 5 mounts: agent-vm msb inspect agent-vm-abc-42",
                "==> Initialized fork /home/a/.pi/agent -> /state/forks/def/data; delete \
                 /state/forks/def to reset",
            ]
        );
    }

    /// A declaration before the targets a `:follow-links` walk discovered, in the
    /// order the mounts were declared within each group.
    #[test]
    fn declarations_are_listed_before_followed_targets() {
        let plan = prepared(
            vec![
                bind("/t0", "/target-0", VolumeRole::Followed),
                bind("/decl", "/source", VolumeRole::Explicit),
                bind("/t1", "/target-1", VolumeRole::Followed),
            ],
            Vec::new(),
        );
        assert_eq!(
            lines(
                &MountSources::new(Vec::new(), Vec::new(), true, None),
                &plan,
                "agent-vm-abc-42"
            ),
            [
                "==> Mounts: 3 (--mount)",
                "==> Mounting /source -> /decl (read-only)",
                "==> Mounting /target-0 -> /t0 (read-only)",
                "==> Mounting /target-1 -> /t1 (read-only)",
            ]
        );
    }

    /// No declared mounts and nothing withheld: no section at all, so an ordinary
    /// launch prints none of it.
    #[test]
    fn a_launch_with_no_declared_mounts_prints_no_header() {
        let none = prepared(Vec::new(), Vec::new());
        assert!(lines(&MountSources::default(), &none, "agent-vm-abc-42").is_empty());
        // A preparation notice of its own still prints: it is the only thing this
        // launch has to say about mounts.
        let advisory = prepared(
            Vec::new(),
            vec!["==> A fork from an earlier agent-vm build is no longer used: /state/x"],
        );
        assert_eq!(
            lines(&MountSources::default(), &advisory, "agent-vm-abc-42"),
            ["==> A fork from an earlier agent-vm build is no longer used: /state/x"]
        );
    }
}
