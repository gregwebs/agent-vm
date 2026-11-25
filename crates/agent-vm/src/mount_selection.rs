//! Which mount declarations one launch asks [`crate::mount::prepare`] for.
//!
//! Three sources, one order: the verified user config first — its top-level
//! `mounts` defaults, then the launched tool's own declarations plus those of its
//! transitive same-file `tools` closure (#396, already folded into one resolved
//! facet by `config`) — and then `--mount` in argv order. The order is a contract,
//! not a convenience — `mount::claim` keeps the *first-seen* declaration when two
//! claims at one guest path are identical, so a conflict diagnostic names the
//! ambient declaration before the launch's own. Nothing here can make one source
//! win: a differing claim at a shared guest path is refused by the same
//! `claim_decision` kernel whichever list it came from (ADR-0046).
//!
//! **No I/O.** `select` reads the already-verified [`UserMounts`] and parses
//! argv; whether a selected source exists is `prepare`'s question. That split is
//! what lets an *unselected* declaration — or an unused set — name a missing path
//! without blocking a launch, `doctor` or `--help`.
//!
//! `--no-config-mounts` is read once, here, and suppresses **every automatic
//! input** ([`config_mounts_selected`]): both the defaults list and the whole tool
//! mount facet, own and inherited. An explicit `--mount NAME` still selects that
//! set, and credentials, persisted paths, agent-vm's own mounts, the tool
//! reference / named-credential / persistence facets and every load-time check are
//! untouched, so a broken or untrusted mount configuration still fails the launch
//! before this module runs.
//!
//! One grammar decides what an argv entry is: [`crate::config_mounts::parse_selector`],
//! the same function config load uses. A bare name is an exact set lookup in the
//! verified user namespace and never a cwd-relative path, a directory or a tool;
//! every absolute (and `~/`-free) path keeps the historical `--mount` grammar.

use crate::{
    config_mounts::{MountSelector, MountSetName, ResolvedMountList, UserMounts, parse_selector},
    mount::{HostSyntax, MountOrigin, MountRequest, MountRequests},
};
use anyhow::{Result, anyhow};
use std::{
    collections::BTreeSet,
    mem,
    path::{Path, PathBuf},
};
use vstd::prelude::*;

verus! {
/// The two facts that decide whether the user config's *automatic* declarations
/// reach the guest. Named fields rather than two adjacent booleans, so a call site
/// cannot swap "declared" for "suppressed" — they differ in polarity.
#[derive(Clone, Copy, Debug)]
pub struct ConfigSelectionFacts { pub declared: bool, pub suppressed: bool }

/// ADR-0046: `--no-config-mounts` withholds the user config's declarative default
/// selection and nothing else. A file that declared `mounts` or `[mount_sets]` is
/// still authority-bearing and is still verified — this decides selection, never
/// trust — and an explicit `--mount NAME` is not part of what it decides.
pub fn config_mounts_selected(f: ConfigSelectionFacts) -> (r: bool)
    ensures r == (f.declared && !f.suppressed),
{
    if f.suppressed { false } else { f.declared }
}
} // verus!

/// `--no-config-mounts`, read once from the launch options (the
/// `MissingCredentialPolicy` precedent: one policy value, derived at one site).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConfigMountPolicy {
    /// Select the user config's defaults for this launch (the default).
    Apply,
    /// Skip this launch's automatic selection; `--mount` still applies.
    Suppress,
}

impl ConfigMountPolicy {
    // `matches!` rather than a two-arm `match`: the flag has exactly one
    // meaning, and a future variant that means "select more" is the safe
    // direction (a suppression must be spelled out).
    fn suppressed(self) -> bool {
        matches!(self, Self::Suppress)
    }
}

/// The launch's complete declaration list plus what the mount section's header
/// and the error context need to say about the config half.
#[derive(Debug)]
pub(crate) struct Selection {
    requests: MountRequests,
    config: ConfigUse,
    /// The header of the launch's one `==> Mounts:` section.
    ///
    /// Built here because this is the only place that knows what was selected
    /// and from which file; the section prints it with the prepared plan's own
    /// bind count, so neither half can describe a launch the other did not see.
    sources: crate::mount_section::MountSources,
    /// The verified file that supplied at least one nonempty explicitly selected
    /// set, if any. Kept apart from [`ConfigUse`] because `--no-config-mounts` does
    /// *not* suppress that contribution, so a sentence about "skipped" mounts must
    /// not be allowed to claim it.
    explicit_sets: Option<PathBuf>,
}

/// The two automatic mount inputs one launch may select from.
///
/// A named bundle rather than two `&`-parameters: `user` is the *namespace* a
/// `--mount NAME` also resolves against and `tool` is one resolved facet, so a
/// transposed call site would silently suppress the wrong one.
#[derive(Clone, Copy)]
pub(crate) struct AutomaticMounts<'a> {
    /// The verified user mount model, when the file declares any mount field —
    /// present-empty included, because an explicit `--mount NAME` may still need
    /// its namespace.
    pub(crate) user: Option<&'a UserMounts>,
    /// The launched tool's own plus inherited declarations, already folded by
    /// `config`. Empty for a direct launch and for anything the built-in catalog
    /// supplies.
    pub(crate) tool: &'a ResolvedMountList,
}

/// What one launch did with the user config's automatic mount inputs.
///
/// `Selected` and `Skipped` carry the file and the count so the section's header
/// and the error context can name both without re-reading the report;
/// `NotDeclared` is "the file selects nothing automatically", which is
/// deliberately distinct from a present-but-empty list (the authority rule turns
/// on presence, the header on declarations). A file that declares only
/// `[mount_sets]` is `NotDeclared` *for the automatic header*: it selected no
/// access, so there is nothing to report and nothing to skip. A file whose only
/// selection is a tool's own list is **not** `NotDeclared` — that is access, and
/// the opt-out has to be able to say it skipped it.
#[derive(Debug)]
enum ConfigUse {
    NotDeclared,
    /// The config file(s) that supplied what was selected, deduplicated in
    /// first-seen order: the user defaults file when it declared defaults, then
    /// the file that declared the launched tool's own list when it is distinct
    /// (#735). One path is the shipped shape; two arise when a tool comes from a
    /// project config or a source while the defaults come from the user file.
    Selected {
        files: Vec<PathBuf>,
        count: usize,
    },
    Skipped {
        files: Vec<PathBuf>,
        count: usize,
    },
}

/// Collect this launch's declarations: config defaults, then the launched tool's
/// own plus inherited list, then argv.
///
/// An argv entry keeps `parse_extra_mounts`' error chain byte-identically
/// (`parsing --mount`) because that is the only error an ordinary path can add and
/// its text is pinned. A set selection adds two errors of its own: an unknown name
/// and a forbidden per-selection modifier, both contextual and both before any
/// filesystem work.
///
/// One [`config_mounts_selected`] call gates *both* automatic inputs, so the two
/// cannot diverge: an opt-out that suppressed one and not the other is exactly the
/// class of bug that would leave a tool's inherited host paths mounted under
/// `--no-config-mounts`. The CLI half is deliberately outside the gate.
pub(crate) fn select(
    automatic: AutomaticMounts<'_>,
    policy: ConfigMountPolicy,
    cli: &[String],
) -> Result<Selection> {
    let AutomaticMounts { user, tool } = automatic;
    // Declarations, not authority: presence already made the file trusted, and
    // an empty list is a selection of nothing rather than something to report.
    let declared = user.is_some_and(UserMounts::has_defaults) || !tool.is_empty();
    let selected = config_mounts_selected(ConfigSelectionFacts {
        declared,
        suppressed: policy.suppressed(),
    });
    let count = automatic_unique_guest_count(user, tool);
    let (config, automatic_requests) = if !declared {
        (ConfigUse::NotDeclared, Vec::new())
    } else if selected {
        (
            ConfigUse::Selected {
                files: automatic_files(user, tool),
                count,
            },
            materialize(user, tool),
        )
    } else {
        (
            ConfigUse::Skipped {
                files: automatic_files(user, tool),
                count,
            },
            Vec::new(),
        )
    };
    let mut requests: Vec<MountRequest> = automatic_requests;
    let mut explicit_sets = None;
    for entry in cli {
        match parse_selector(entry, HostSyntax::AbsoluteOnly) {
            // `from_cli` is the one place an argv declaration is tagged as `Cli`,
            // so the `MountRequests` round-trip is deliberate: the config half must
            // precede it, and a second copy of the tagging rule is exactly what
            // this avoids.
            Ok(MountSelector::Direct(mount)) => {
                requests.extend(MountRequests::from_cli(vec![mount]).into_inner());
            }
            Ok(MountSelector::Set(name)) => {
                let selected = explicit_set(user, &name)?;
                if !selected.is_empty() {
                    if let Some(user) = user {
                        explicit_sets = Some(user.sets_file().unwrap_or(user.file()).to_path_buf());
                    }
                    requests.extend(selected.requests().cloned());
                }
            }
            Err(error) => return Err(error.into_cli(entry).context("parsing --mount")),
        }
    }
    let sources = crate::mount_section::MountSources::new(
        config_files(&config),
        contributing_sets(&requests),
        !cli.is_empty(),
        skipped_count(&config),
    );
    Ok(Selection {
        requests: MountRequests::new(requests),
        config,
        sources,
        explicit_sets,
    })
}

/// How many *distinct guest paths* the two automatic inputs select.
///
/// The number the opt-out's `skipped N` reports, computed without materializing
/// either list: it must not pay a payload clone to say what it withheld. Membership is plain normalized-guest-path
/// equality — a decision *equivalence* question is `claim`'s, and answering it
/// here would be a second policy. A set-only file contributes nothing, because its
/// definitions select nothing.
fn automatic_unique_guest_count(user: Option<&UserMounts>, tool: &ResolvedMountList) -> usize {
    let mut guests: BTreeSet<&Path> = BTreeSet::new();
    if let Some(defaults) = user.and_then(UserMounts::defaults) {
        guests.extend(
            defaults
                .requests()
                .map(|request| request.mount.guest.as_path()),
        );
    }
    guests.extend(tool.requests().map(|request| request.mount.guest.as_path()));
    guests.len()
}

/// The verified file(s) the mount section names, when the config contributed or
/// withheld declarations.
fn config_files(config: &ConfigUse) -> Vec<PathBuf> {
    match config {
        ConfigUse::NotDeclared => Vec::new(),
        ConfigUse::Selected { files, .. } | ConfigUse::Skipped { files, .. } => files.clone(),
    }
}

/// The file(s) an automatic selection came from, deduplicated in first-seen
/// order.
///
/// The user defaults file first, when it declared defaults, then the file that
/// declared the launched tool's own list when it is a different one. A tool's
/// list may live in a project config or a sourced file (#735), and those are
/// exactly the cases where `user` is `None` and the tool facet is still non-empty
/// — the case the pre-#735 selector silently dropped.
fn automatic_files(user: Option<&UserMounts>, tool: &ResolvedMountList) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = Vec::new();
    if let Some(user) = user.filter(|user| user.has_defaults()) {
        // ADR-0076 R4.2: every file whose top-level `mounts` contributed, in
        // adoption order; one file for a single-file load, so the notice's bytes
        // are unchanged there.
        files.extend(user.files().iter().cloned());
    }
    if let Some(file) = tool
        .requests()
        .find_map(|request| request.origin.config_file())
        && !files.iter().any(|seen| seen == file)
    {
        files.push(file.to_path_buf());
    }
    files
}

/// The `[mount_sets]` names that supplied at least one of this launch's
/// declarations, first-seen order, deduplicated.
///
/// Read off the declarations' own origins: a traversal that recorded the names
/// each list *used* would be a second expansion, and a set reached through
/// another one (`pi-agent = ["agent", …]`) already names itself on its own
/// leaves. A declaration written straight into the defaults list or a tool list
/// has no name here, which is what makes the header's `set`/`sets` suffix
/// truthful rather than a list of everything the file defines.
fn contributing_sets(requests: &[MountRequest]) -> Vec<String> {
    let mut sets: Vec<String> = Vec::new();
    for request in requests {
        if let MountOrigin::UserSet { set, .. } = &request.origin
            && !sets.iter().any(|seen| seen == &**set)
        {
            sets.push(set.to_string());
        }
    }
    sets
}

/// What `--no-config-mounts` withheld, when it withheld anything: an empty
/// automatic list printed no count before this change either.
fn skipped_count(config: &ConfigUse) -> Option<usize> {
    match config {
        ConfigUse::Skipped { count, .. } if *count > 0 => Some(*count),
        _ => None,
    }
}

/// The automatic declarations in selection order: defaults first, then the tool
/// facet, each keeping the origin that declared it.
///
/// Materialized once per launch, deliberately: the cached lists stay shared
/// handles, and only `mount::prepare` (`via `Selection::take_requests`) needs owned
/// values. Nothing is deduplicated here — that is the shared claim's job, and a
/// second merge rule here could disagree with it.
fn materialize(user: Option<&UserMounts>, tool: &ResolvedMountList) -> Vec<MountRequest> {
    let mut requests = Vec::new();
    if let Some(defaults) = user.and_then(UserMounts::defaults) {
        requests.extend(defaults.requests().cloned());
    }
    requests.extend(tool.requests().cloned());
    requests
}

/// One explicit `--mount NAME`, resolved against the verified user namespace and
/// nothing else.
///
/// An empty set is a legitimate selection that contributes no declaration, so this
/// returns an empty vector rather than an error. An unknown name is contextual: it
/// names the selection with `config`'s escaping (argv is user-typed text, but a
/// spelling that carries a newline must not forge a second line) and the file that
/// was searched, and it never falls back to a relative path, a directory or a tool.
fn explicit_set(user: Option<&UserMounts>, name: &MountSetName) -> Result<ResolvedMountList> {
    let selected = user.and_then(|user| user.requests_for_set(name));
    match (selected, user) {
        (Some(requests), _) => Ok(requests),
        (None, Some(user)) => Err(anyhow!(
            "mount set {} is not defined by any [mount_sets] in {}",
            crate::config::quoted_str(name.as_str()),
            crate::one_line::quoted_path(user.file())
        )
        .context("parsing --mount")),
        (None, None) => Err(anyhow!(
            "mount set {} is not defined; no user config declares [mount_sets]",
            crate::config::quoted_str(name.as_str())
        )
        .context("parsing --mount")),
    }
}

impl Selection {
    /// The declarations as selected, borrowed before `prepare` consumes them.
    ///
    /// `git_metadata::discover` runs between selection and preparation and must
    /// see them: an automatic bind that lands inside one of these routes would
    /// otherwise silently outrank it (ADR-0062 D5).
    pub(crate) fn requests(&self) -> &[MountRequest] {
        self.requests.as_slice()
    }

    /// Hand the declarations to `prepare`. Fallible-free because selection has
    /// already done everything but I/O.
    pub(crate) fn take_requests(&mut self) -> MountRequests {
        mem::take(&mut self.requests)
    }

    /// The header input for the launch's one `==> Mounts:` section.
    ///
    /// Distinct from the count in [`Selection::preparation_context`]: this names
    /// sources, while the prepared plan supplies the number of binds they became.
    pub(crate) fn sources(&self) -> &crate::mount_section::MountSources {
        &self.sources
    }

    /// The `mount::prepare` error context.
    ///
    /// `"preparing --mount"` whenever no config declaration reached `prepare` —
    /// including `mounts = []`, a sets-only file that contributed nothing and the
    /// opt-out — so an argv-only launch's error bytes do not change. Otherwise it
    /// names the file, because a failure may be about a declaration the reader did
    /// not type on this command line, and it distinguishes the skippable defaults
    /// from an explicitly selected set (`--no-config-mounts` does not remove the
    /// latter, so it must never say it does).
    pub(crate) fn preparation_context(&self) -> String {
        let selected_automatic = matches!(
            &self.config,
            ConfigUse::Selected { count, .. } if *count > 0
        );
        match (&self.config, &self.explicit_sets) {
            (ConfigUse::Selected { files, .. }, Some(_)) if selected_automatic => format!(
                "preparing mounts (including mounts and explicitly selected mount sets from {}; \
                 --no-config-mounts skips only the mounts)",
                crate::one_line::quoted_paths(files)
            ),
            (ConfigUse::Selected { files, count }, _) if *count > 0 => format!(
                "preparing mounts (including mounts from {}; --no-config-mounts skips them)",
                crate::one_line::quoted_paths(files)
            ),
            (_, Some(file)) => format!(
                "preparing mounts (including mount sets from {}; explicitly selected sets are \
                 not skipped by --no-config-mounts)",
                crate::one_line::quoted_path(file)
            ),
            _ => "preparing --mount".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_authority::{self, AuthorityTriggers, verify};
    use crate::config_mounts::{MountValues, from_verified_value_fresh};
    use crate::host_paths::read_bounded_regular_file_noting_symlink;
    use crate::mount::{MountOrigin, Spelling};
    use std::{fs, os::unix::fs::PermissionsExt, path::Path};

    const HOME: &str = "/home/selection";

    /// Selection input built through the real verified-read path: a selection test
    /// must not be able to conjure a [`UserMounts`] no launch could have.
    fn user_mounts_from(body: &str) -> UserMounts {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let file = root.path().join("config.toml");
        fs::write(&file, body).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let read = read_bounded_regular_file_noting_symlink(&file, 4096).unwrap();
        let table: toml::Table = body.parse().unwrap();
        let tool_values: Vec<crate::config_mounts::ToolMountValue<'_>> = table
            .get("tools")
            .and_then(toml::Value::as_array)
            .map(|tools| {
                tools
                    .iter()
                    .enumerate()
                    .filter_map(|(declaration, tool)| {
                        tool.as_table()
                            .and_then(|table| table.get("mounts"))
                            .map(|value| crate::config_mounts::ToolMountValue {
                                declaration,
                                value,
                            })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let authorized = verify(
            &read,
            AuthorityTriggers {
                network: false,
                mounts: config_authority::mount_authority_present(
                    config_authority::MountAuthorityFacts {
                        top_level: table.get("mounts").is_some(),
                        tool_field: !tool_values.is_empty(),
                    },
                ),
                mount_sets: table.get("mount_sets").is_some(),
                egress_sets: table.get("egress_sets").is_some(),
                allow_tools: false,
            },
        )
        .unwrap()
        .authorized
        .expect("a present mount field is authority-bearing");
        from_verified_value_fresh(
            &authorized,
            MountValues {
                defaults: table.get("mounts"),
                sets: table.get("mount_sets"),
                tools: &tool_values,
            },
            Some(Path::new(HOME)),
        )
        .expect("the fixture parses")
    }

    /// A defaults-only file, the shape every pre-#397 test used.
    fn user_mounts(entries: &[&str]) -> UserMounts {
        let list = entries
            .iter()
            .map(|entry| format!("\"{entry}\""))
            .collect::<Vec<_>>()
            .join(", ");
        user_mounts_from(&format!("mounts = [{list}]\n"))
    }

    /// The automatic inputs for a defaults-only fixture: no tool facet. The
    /// launch path always supplies one, so this is test scaffolding rather than a
    /// production constructor.
    fn automatic(user: Option<&UserMounts>) -> AutomaticMounts<'_> {
        static EMPTY: std::sync::LazyLock<ResolvedMountList> =
            std::sync::LazyLock::new(ResolvedMountList::empty);
        AutomaticMounts { user, tool: &EMPTY }
    }

    fn described(selection: &mut Selection) -> Vec<(MountOrigin, Spelling)> {
        selection
            .take_requests()
            .into_inner()
            .into_iter()
            .map(|request| (request.origin, request.mount.source_spelling))
            .collect()
    }

    fn sources(selection: &mut Selection) -> Vec<Spelling> {
        selection
            .take_requests()
            .into_inner()
            .into_iter()
            .map(|request| request.mount.source_spelling)
            .collect()
    }

    /// The selection rule, against an independent table.
    ///
    /// The oracle is an explicit `match` on the four rows rather than the
    /// contract expression, so a body computing something else (for example
    /// ignoring `suppressed`) can only be caught by a reader or the proof.
    #[test]
    fn config_mounts_selected_matches_the_four_rows() {
        for (declared, suppressed) in [(false, false), (false, true), (true, false), (true, true)] {
            let expected = match (declared, suppressed) {
                (false, false) => false,
                (false, true) => false,
                (true, false) => true,
                (true, true) => false,
            };
            assert_eq!(
                config_mounts_selected(ConfigSelectionFacts {
                    declared,
                    suppressed
                }),
                expected,
                "declared={declared} suppressed={suppressed}"
            );
        }
    }

    /// Config declarations precede argv, and keep their own origins.
    #[test]
    fn config_declarations_come_before_argv() {
        let user = user_mounts(&["~/ref:ro", "/srv/data:/data:rw"]);
        let mut selection = select(
            automatic(Some(&user)),
            ConfigMountPolicy::Apply,
            &["/cli".to_owned(), "/cli2:ro".to_owned()],
        )
        .unwrap();
        let config_origin = |index| MountOrigin::UserConfig {
            file: user.file().to_path_buf(),
            index,
        };
        assert_eq!(
            described(&mut selection),
            [
                (config_origin(0), Spelling::new(format!("{HOME}/ref"))),
                (config_origin(1), Spelling::new("/srv/data")),
                (MountOrigin::Cli, Spelling::new("/cli")),
                (MountOrigin::Cli, Spelling::new("/cli2")),
            ]
        );
    }

    /// The opt-out withholds the config half and nothing else.
    #[test]
    fn suppress_keeps_argv_and_drops_config() {
        let user = user_mounts(&["~/ref:ro"]);
        let mut selection = select(
            automatic(Some(&user)),
            ConfigMountPolicy::Suppress,
            &["/cli".to_owned()],
        )
        .unwrap();
        assert_eq!(
            described(&mut selection),
            [(MountOrigin::Cli, Spelling::new("/cli"))]
        );
    }

    /// The verified model and its first tool's own list, from **one** parse: the
    /// two must share a file, and a test must not be able to conjure a list no
    /// launch could carry.
    fn pair(body: &str) -> (UserMounts, ResolvedMountList) {
        let mut mounts = user_mounts_from(body);
        let tool = mounts.take_tool_lists().get(0);
        (mounts, tool)
    }

    /// #396 AC-union: the two automatic inputs precede argv, and each declaration
    /// keeps the origin that declared it.
    #[test]
    fn automatic_defaults_then_tool_closure_then_cli_keep_origins() {
        let document = "mounts = [\"/d:/d:ro\"]\n[mount_sets]\ns = [\"/s:/s:ro\"]\n                        [[tools]]\nname = \"t\"\ncommand = \"t\"\nmounts = [\"s\", \"/o:/o:ro\"]\n";
        let (user, tool) = pair(document);
        let mut selection = select(
            AutomaticMounts {
                user: Some(&user),
                tool: &tool,
            },
            ConfigMountPolicy::Apply,
            &["/cli:ro".to_owned()],
        )
        .unwrap();
        let described: Vec<(MountOrigin, Spelling)> = described(&mut selection);
        assert_eq!(
            described,
            [
                (
                    MountOrigin::UserConfig {
                        file: user.file().to_path_buf(),
                        index: 0
                    },
                    Spelling::new("/d")
                ),
                (
                    MountOrigin::UserSet {
                        file: user.file().to_path_buf(),
                        set: std::sync::Arc::from("s"),
                        index: 0
                    },
                    Spelling::new("/s")
                ),
                (
                    MountOrigin::Tool {
                        file: user.file().to_path_buf(),
                        declaration: 0,
                        index: 1
                    },
                    Spelling::new("/o")
                ),
                (MountOrigin::Cli, Spelling::new("/cli")),
            ]
        );
    }

    /// #396 AC-opt-out: the option removes **both** automatic inputs and nothing
    /// else. An explicit set name still resolves against the same namespace.
    #[test]
    fn suppression_drops_both_automatic_inputs_but_not_cli_sets() {
        let document = "mounts = [\"/d:/d:ro\"]\n[mount_sets]\ns = [\"/s:/s:ro\"]\n                        [[tools]]\nname = \"t\"\ncommand = \"t\"\nmounts = [\"/o:/o:ro\"]\n";
        let (user, tool) = pair(document);
        let mut selection = select(
            AutomaticMounts {
                user: Some(&user),
                tool: &tool,
            },
            ConfigMountPolicy::Suppress,
            &[],
        )
        .unwrap();
        assert!(
            described(&mut selection).is_empty(),
            "neither automatic input may survive the opt-out"
        );
        let mut selection = select(
            AutomaticMounts {
                user: Some(&user),
                tool: &tool,
            },
            ConfigMountPolicy::Suppress,
            &["s".to_owned()],
        )
        .unwrap();
        assert_eq!(
            sources(&mut selection),
            [Spelling::new("/s")],
            "an explicit set survives, and nothing automatic returns with it"
        );
        // Apply selects both automatic inputs, so the row above is a real
        // suppression rather than an empty fixture.
        let mut selection = select(
            AutomaticMounts {
                user: Some(&user),
                tool: &tool,
            },
            ConfigMountPolicy::Apply,
            &[],
        )
        .unwrap();
        assert_eq!(
            sources(&mut selection),
            [Spelling::new("/d"), Spelling::new("/o"),]
        );
    }

    /// The header names the file, and the *skipped* count is distinct normalized
    /// guest paths across both automatic inputs: an identical declaration
    /// selected twice is one mount, and a tool-only file still reports what the
    /// opt-out withheld.
    #[test]
    fn the_header_names_config_provenance_and_the_skipped_count() {
        // The same declaration in both the defaults list and the tool list.
        let document = "mounts = [\"/a:/g:ro\"]\n                        [[tools]]\nname = \"t\"\ncommand = \"t\"\nmounts = [\"/a:/g//./:ro\", \"/b:/h:ro\"]\n";
        let (user, tool) = pair(document);
        let selection = select(
            AutomaticMounts {
                user: Some(&user),
                tool: &tool,
            },
            ConfigMountPolicy::Apply,
            &[],
        )
        .unwrap();
        assert_eq!(
            selection.sources().header(2),
            Some(format!(
                "==> Mounts: 2 (config {})",
                crate::one_line::quoted_path(user.file())
            ))
        );
        assert_eq!(
            select(
                AutomaticMounts {
                    user: Some(&user),
                    tool: &tool,
                },
                ConfigMountPolicy::Suppress,
                &[],
            )
            .unwrap()
            .sources()
            .header(0),
            Some(format!(
                "==> Mounts: skipped 2 from {} (--no-config-mounts)",
                crate::one_line::quoted_path(user.file())
            ))
        );

        // Defaults only: the file alone, no set to name.
        let user = user_mounts(&["~/ref:ro"]);
        let selection = select(automatic(Some(&user)), ConfigMountPolicy::Apply, &[]).unwrap();
        assert_eq!(
            selection.sources().header(1),
            Some(format!(
                "==> Mounts: 1 (config {})",
                crate::one_line::quoted_path(user.file())
            ))
        );

        // A tool-only file selects access, so it is named too.
        let document =
            "mounts = []\n[[tools]]\nname = \"t\"\ncommand = \"t\"\nmounts = [\"/o:/o:ro\"]\n";
        let (user, tool) = pair(document);
        let selection = select(
            AutomaticMounts {
                user: Some(&user),
                tool: &tool,
            },
            ConfigMountPolicy::Apply,
            &[],
        )
        .unwrap();
        assert_eq!(
            selection.sources().header(1),
            Some(format!(
                "==> Mounts: 1 (config {})",
                crate::one_line::quoted_path(user.file())
            ))
        );

        // An empty tool list contributes nothing, so an authority-bearing file
        // with no access keeps silent.
        let document = "mounts = []\n[[tools]]\nname = \"t\"\ncommand = \"t\"\nmounts = []\n";
        let (user, tool) = pair(document);
        assert_eq!(
            select(
                AutomaticMounts {
                    user: Some(&user),
                    tool: &tool,
                },
                ConfigMountPolicy::Apply,
                &[],
            )
            .unwrap()
            .sources()
            .header(0),
            None
        );
    }

    /// A tool-only file still gives `prepare` config-attributed context, and the
    /// opt-out sentence names the automatic mounts it skipped.
    #[test]
    fn tool_only_mounts_have_config_preparation_context() {
        let document = "[[tools]]\nname = \"t\"\ncommand = \"t\"\nmounts = [\"/o:/o:ro\"]\n";
        let (user, tool) = pair(document);
        let file = crate::one_line::quoted_path(user.file());
        assert_eq!(
            select(
                AutomaticMounts {
                    user: Some(&user),
                    tool: &tool,
                },
                ConfigMountPolicy::Apply,
                &[],
            )
            .unwrap()
            .preparation_context(),
            format!(
                "preparing mounts (including mounts from {file}; --no-config-mounts skips them)"
            )
        );
        // Under the opt-out the tool list contributes nothing, so the sentence
        // falls back to the historical argv-only text.
        assert_eq!(
            select(
                AutomaticMounts {
                    user: Some(&user),
                    tool: &tool,
                },
                ConfigMountPolicy::Suppress,
                &[],
            )
            .unwrap()
            .preparation_context(),
            "preparing --mount"
        );
        // Both automatic inputs plus an explicit set keep the "skips only the
        // mounts" wording, because the opt-out cannot remove the set.
        let document = "mounts = [\"/d:/d:ro\"]\n[mount_sets]\ns = [\"/s:/s:ro\"]\n\
                        [[tools]]\nname = \"t\"\ncommand = \"t\"\nmounts = [\"/o:/o:ro\"]\n";
        let (user, tool) = pair(document);
        let file = crate::one_line::quoted_path(user.file());
        assert_eq!(
            select(
                AutomaticMounts {
                    user: Some(&user),
                    tool: &tool,
                },
                ConfigMountPolicy::Apply,
                &["s".to_owned()],
            )
            .unwrap()
            .preparation_context(),
            format!(
                "preparing mounts (including mounts and explicitly selected mount sets from \
                 {file}; --no-config-mounts skips only the mounts)"
            )
        );
    }

    /// An argv-only launch keeps today's context text byte-for-byte, whether the
    /// file declared nothing or the launch opted out.
    #[test]
    fn preparation_context_is_argv_only_when_nothing_from_config_is_selected() {
        let empty = user_mounts(&[]);
        let sets_only = user_mounts_from("[mount_sets]\na = []\n");
        let user = user_mounts(&["~/ref:ro"]);
        let cases = [
            (None, ConfigMountPolicy::Apply, "preparing --mount"),
            (Some(&empty), ConfigMountPolicy::Apply, "preparing --mount"),
            (
                Some(&sets_only),
                ConfigMountPolicy::Apply,
                "preparing --mount",
            ),
            (
                Some(&user),
                ConfigMountPolicy::Suppress,
                "preparing --mount",
            ),
        ];
        for (mounts, policy, expected) in cases {
            let selection = select(automatic(mounts), policy, &[]).unwrap();
            assert_eq!(selection.preparation_context(), expected);
        }
        let selection = select(automatic(Some(&user)), ConfigMountPolicy::Apply, &[]).unwrap();
        assert_eq!(
            selection.preparation_context(),
            format!(
                "preparing mounts (including mounts from {}; --no-config-mounts skips them)",
                crate::one_line::quoted_path(user.file())
            )
        );
    }

    /// Silence when the file contributes nothing, and the plain count when it does.
    #[test]
    fn the_header_is_silent_unless_the_file_contributes() {
        let empty = user_mounts(&[]);
        let sets_only = user_mounts_from("[mount_sets]\na = [\"/h/x:/x:ro\"]\n");
        for (mounts, policy) in [
            (None, ConfigMountPolicy::Apply),
            // A sets-only file is not "skipped": the opt-out does not affect it,
            // and its definitions select nothing automatically.
            (Some(&sets_only), ConfigMountPolicy::Suppress),
            (Some(&sets_only), ConfigMountPolicy::Apply),
            (Some(&empty), ConfigMountPolicy::Apply),
            (Some(&empty), ConfigMountPolicy::Suppress),
        ] {
            assert_eq!(
                select(automatic(mounts), policy, &[])
                    .unwrap()
                    .sources()
                    .header(0),
                None
            );
        }

        let user = user_mounts(&["~/ref:ro", "/srv/data:/data:rw"]);
        assert_eq!(
            select(automatic(Some(&user)), ConfigMountPolicy::Apply, &[])
                .unwrap()
                .sources()
                .header(2),
            Some(format!(
                "==> Mounts: 2 (config {})",
                crate::one_line::quoted_path(user.file())
            ))
        );
        assert_eq!(
            select(automatic(Some(&user)), ConfigMountPolicy::Suppress, &[])
                .unwrap()
                .sources()
                .header(0),
            Some(format!(
                "==> Mounts: skipped 2 from {} (--no-config-mounts)",
                crate::one_line::quoted_path(user.file())
            ))
        );
    }

    /// An explicit set name resolves in the verified namespace whether or not the
    /// defaults are suppressed, and it is not a path, a directory or a tool.
    #[test]
    fn explicit_set_names_survive_the_opt_out() {
        let user = user_mounts_from(
            "mounts = [\"defaults\"]\n[mount_sets]\nagent = [\"~/.agents\", \"~/.config/github-app:ro\"]\n\
             pi-agent = [\"agent\", \"~/.pi:fork\"]\nempty = []\ndefaults = [\"/h/def:/def:ro\"]\n",
        );
        let mut selection = select(
            automatic(Some(&user)),
            ConfigMountPolicy::Suppress,
            &["pi-agent".to_owned()],
        )
        .unwrap();
        assert_eq!(
            sources(&mut selection),
            [
                Spelling::new(format!("{HOME}/.agents")),
                Spelling::new(format!("{HOME}/.config/github-app")),
                Spelling::new(format!("{HOME}/.pi")),
            ]
        );
        let mut selection = select(
            automatic(Some(&user)),
            ConfigMountPolicy::Apply,
            &["empty".to_owned()],
        )
        .unwrap();
        assert_eq!(sources(&mut selection), [Spelling::new("/h/def")]);
        // Both kinds contribute: the defaults first, then the set's leaves.
        let mut selection = select(
            automatic(Some(&user)),
            ConfigMountPolicy::Apply,
            &["agent".to_owned(), "agent".to_owned()],
        )
        .unwrap();
        // A repeated name repeats its leaves here on purpose: deduplication is the
        // shared claim's job (`claim`/`prepare`), so selection must not invent a
        // second merge rule that could disagree with it. Two identical selections
        // of one set collapse there, to one bind.
        let repeated = selection.take_requests().into_inner();
        assert_eq!(repeated.len(), 5);
        let merged = crate::mount::claim(repeated, &[]).expect("identical declarations merge");
        assert_eq!(merged.len(), 3);
    }

    /// A missing or unknown name is refused with the escaping policy and names
    /// what was searched; there is no fallback of any kind.
    #[test]
    fn unknown_names_are_contextual_and_never_a_path() {
        let user = user_mounts_from("[mount_sets]\nagent = []\n");
        let error = format!(
            "{:#}",
            select(
                automatic(Some(&user)),
                ConfigMountPolicy::Apply,
                &["nope".to_owned()]
            )
            .unwrap_err()
        );
        assert_eq!(
            error,
            format!(
                "parsing --mount: mount set \"nope\" is not defined by any [mount_sets] in {}",
                crate::one_line::quoted_path(user.file())
            )
        );
        let error = format!(
            "{:#}",
            select(
                automatic(None),
                ConfigMountPolicy::Apply,
                &["agent".to_owned()]
            )
            .unwrap_err()
        );
        assert_eq!(
            error,
            "parsing --mount: mount set \"agent\" is not defined; no user config declares \
             [mount_sets]"
        );
        // A name that needs escaping is escaped, so it cannot forge a line.
        let forged = "no\npe";
        let error = format!(
            "{:#}",
            select(
                automatic(None),
                ConfigMountPolicy::Apply,
                &[forged.to_owned()]
            )
            .unwrap_err()
        );
        assert!(!error.contains('\n'), "{error}");
        // A per-selection modifier never becomes a set nor a path.
        let error = format!(
            "{:#}",
            select(
                automatic(Some(&user)),
                ConfigMountPolicy::Apply,
                &["agent:ro".to_owned()]
            )
            .unwrap_err()
        );
        assert!(error.starts_with("parsing --mount:"), "{error}");
        assert!(error.contains("bare name"), "{error}");
        // Ordinary argv path failures keep their historical bytes.
        let error = format!(
            "{:#}",
            select(
                automatic(None),
                ConfigMountPolicy::Apply,
                &["rel".to_owned()]
            )
            .unwrap_err()
        );
        assert_eq!(
            error,
            "parsing --mount: mount set \"rel\" is not defined; no user config declares \
             [mount_sets]"
        );
        let error = format!(
            "{:#}",
            select(
                automatic(None),
                ConfigMountPolicy::Apply,
                &["./rel".to_owned()]
            )
            .unwrap_err()
        );
        assert_eq!(
            error,
            "parsing --mount: --mount host path \"./rel\" must be absolute"
        );
    }

    /// The preparation context distinguishes skippable defaults from an explicitly
    /// selected set, and never claims the opt-out removes the latter.
    #[test]
    fn preparation_context_attributes_explicit_sets() {
        let user = user_mounts_from(
            "mounts = [\"/h/def:/def:ro\"]\n[mount_sets]\nagent = [\"/h/a:/a:ro\"]\nempty = []\n",
        );
        let file = crate::one_line::quoted_path(user.file());
        // Defaults only: the historical sentence, byte for byte.
        let selection = select(automatic(Some(&user)), ConfigMountPolicy::Apply, &[]).unwrap();
        assert_eq!(
            selection.preparation_context(),
            format!(
                "preparing mounts (including mounts from {file}; --no-config-mounts skips them)"
            )
        );
        // A set that contributed nothing leaves the sentence alone.
        let selection = select(
            automatic(Some(&user)),
            ConfigMountPolicy::Suppress,
            &["empty".to_owned()],
        )
        .unwrap();
        assert_eq!(selection.preparation_context(), "preparing --mount");
        // An explicit set under the opt-out is attributed, and the sentence says the
        // opt-out does not skip it.
        let selection = select(
            automatic(Some(&user)),
            ConfigMountPolicy::Suppress,
            &["agent".to_owned()],
        )
        .unwrap();
        assert_eq!(
            selection.preparation_context(),
            format!(
                "preparing mounts (including mount sets from {file}; explicitly selected sets are \
                 not skipped by --no-config-mounts)"
            )
        );
        // Both kinds: defaults are named as the skippable half.
        let selection = select(
            automatic(Some(&user)),
            ConfigMountPolicy::Apply,
            &["agent".to_owned()],
        )
        .unwrap();
        assert_eq!(
            selection.preparation_context(),
            format!(
                "preparing mounts (including mounts and explicitly selected mount sets from \
                 {file}; --no-config-mounts skips only the mounts)"
            )
        );
    }
}
