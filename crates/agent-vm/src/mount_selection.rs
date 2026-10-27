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
    mount::{HostSyntax, MountRequest, MountRequests},
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

/// The launch's complete declaration list plus what the notice and the error
/// context need to say about the config half.
#[derive(Debug)]
pub(crate) struct Selection {
    requests: MountRequests,
    config: ConfigUse,
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
/// `Selected` and `Skipped` carry the file and the count so the notice can name
/// both without re-reading the report; `NotDeclared` is "the file selects nothing
/// automatically", which is deliberately distinct from a present-but-empty list
/// (the authority rule turns on presence, the notice on declarations). A file that
/// declares only `[mount_sets]` is `NotDeclared` *for the automatic notice*: it
/// selected no access, so there is nothing to report and nothing to skip. A file
/// whose only selection is a tool's own list is **not** `NotDeclared` — that is
/// access, and the opt-out has to be able to say it skipped it.
#[derive(Debug)]
enum ConfigUse {
    NotDeclared,
    Selected { file: PathBuf, count: usize },
    Skipped { file: PathBuf, count: usize },
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
    let (config, automatic_requests) = match user {
        Some(_) if !declared => (ConfigUse::NotDeclared, Vec::new()),
        Some(user) if selected => (
            ConfigUse::Selected {
                file: user.file().to_path_buf(),
                count,
            },
            materialize(user, tool),
        ),
        Some(user) => (
            ConfigUse::Skipped {
                file: user.file().to_path_buf(),
                count,
            },
            Vec::new(),
        ),
        // A tool facet without a verified user model is unreachable: only the
        // verified user file can declare one. Naming it rather than folding it
        // keeps a future construction bug fail-closed.
        None => (ConfigUse::NotDeclared, Vec::new()),
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
                        explicit_sets = Some(user.file().to_path_buf());
                    }
                    requests.extend(selected.requests().cloned());
                }
            }
            Err(error) => return Err(error.into_cli(entry).context("parsing --mount")),
        }
    }
    Ok(Selection {
        requests: MountRequests::new(requests),
        config,
        explicit_sets,
    })
}

/// How many *distinct guest paths* the two automatic inputs select.
///
/// The same number the notice must print, computed without materializing either
/// list: an opt-out launch prints the count of what it skipped, and it must not
/// pay a payload clone to do so. Membership is plain normalized-guest-path
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

/// The automatic declarations in selection order: defaults first, then the tool
/// facet, each keeping the origin that declared it.
///
/// Materialized once per launch, deliberately: the cached lists stay shared
/// handles, and only `mount::prepare` (`via `Selection::take_requests`) needs owned
/// values. Nothing is deduplicated here — that is the shared claim's job, and a
/// second merge rule here could disagree with it.
fn materialize(user: &UserMounts, tool: &ResolvedMountList) -> Vec<MountRequest> {
    let mut requests = Vec::new();
    if let Some(defaults) = user.defaults() {
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
    /// Hand the declarations to `prepare`. Fallible-free because selection has
    /// already done everything but I/O.
    pub(crate) fn take_requests(&mut self) -> MountRequests {
        mem::take(&mut self.requests)
    }

    /// One line naming the file and how many declarations it contributed.
    ///
    /// The count is the number of distinct guest paths across the defaults and the
    /// launched tool's own plus inherited list, so a tool-only file reports its
    /// access and an opt-out reports what it skipped. `None` when there is nothing
    /// to report: no automatic input at all, an empty one, or a sets-only file.
    /// list, or a sets-only file (whose definitions select nothing). A launch with
    /// nothing automatic from the config must not print a "0" row on every run. A
    /// non-empty defaults list the opt-out skipped still reports, as `skipped N` —
    /// that is the one case where the reader has to be told the file declared
    /// mounts and this launch ignored them, and it deliberately does not mention
    /// named sets, which the opt-out does not affect.
    pub(crate) fn notice(&self) -> Option<String> {
        let (file, count, skipped) = match &self.config {
            ConfigUse::NotDeclared => return None,
            ConfigUse::Selected { file, count } => (file, *count, false),
            ConfigUse::Skipped { file, count } => (file, *count, true),
        };
        if count == 0 {
            return None;
        }
        Some(if skipped {
            format!(
                "==> Config mounts: skipped {count} from {} (--no-config-mounts)",
                crate::one_line::quoted_path(file)
            )
        } else {
            format!(
                "==> Config mounts: {count} from {}",
                crate::one_line::quoted_path(file)
            )
        })
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
            (ConfigUse::Selected { file, .. }, Some(_)) if selected_automatic => format!(
                "preparing mounts (including mounts and explicitly selected mount sets from {}; \
                 --no-config-mounts skips only the mounts)",
                crate::one_line::quoted_path(file)
            ),
            (ConfigUse::Selected { file, count }, _) if *count > 0 => format!(
                "preparing mounts (including mounts from {}; --no-config-mounts skips them)",
                crate::one_line::quoted_path(file)
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
    use crate::config_mounts::{MountValues, from_verified_value};
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
            },
        )
        .unwrap()
        .expect("a present mount field is authority-bearing");
        from_verified_value(
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
                    MountOrigin::UserTool {
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

    /// The notice counts *distinct normalized guest paths* across both automatic
    /// inputs, so an identical declaration selected twice is one mount, and a
    /// tool-only file still reports what it selected.
    #[test]
    fn combined_automatic_notice_counts_unique_guests() {
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
            selection.notice(),
            Some(format!(
                "==> Config mounts: 2 from {}",
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
            .notice(),
            Some(format!(
                "==> Config mounts: skipped 2 from {} (--no-config-mounts)",
                crate::one_line::quoted_path(user.file())
            ))
        );

        // Defaults only: the historical bytes, unchanged.
        let user = user_mounts(&["~/ref:ro"]);
        let selection = select(automatic(Some(&user)), ConfigMountPolicy::Apply, &[]).unwrap();
        assert_eq!(
            selection.notice(),
            Some(format!(
                "==> Config mounts: 1 from {}",
                crate::one_line::quoted_path(user.file())
            ))
        );

        // A tool-only file selects access, so it is neither silent nor reported as
        // a defaults list it does not have.
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
            selection.notice(),
            Some(format!(
                "==> Config mounts: 1 from {}",
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
            .notice(),
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

    /// Both lines, and silence when the file contributes nothing.
    #[test]
    fn notice_names_the_file_and_the_skipped_count() {
        let empty = user_mounts(&[]);
        let sets_only = user_mounts_from("[mount_sets]\na = [\"/h/x:/x:ro\"]\n");
        assert_eq!(
            select(automatic(None), ConfigMountPolicy::Apply, &[])
                .unwrap()
                .notice(),
            None
        );
        // A sets-only file is not "skipped": the opt-out does not affect it, and
        // its definitions select nothing automatically.
        assert_eq!(
            select(
                automatic(Some(&sets_only)),
                ConfigMountPolicy::Suppress,
                &[]
            )
            .unwrap()
            .notice(),
            None
        );
        assert_eq!(
            select(automatic(Some(&sets_only)), ConfigMountPolicy::Apply, &[])
                .unwrap()
                .notice(),
            None
        );
        assert_eq!(
            select(automatic(Some(&empty)), ConfigMountPolicy::Apply, &[])
                .unwrap()
                .notice(),
            None
        );
        assert_eq!(
            select(automatic(Some(&empty)), ConfigMountPolicy::Suppress, &[])
                .unwrap()
                .notice(),
            None
        );

        let user = user_mounts(&["~/ref:ro", "/srv/data:/data:rw"]);
        assert_eq!(
            select(automatic(Some(&user)), ConfigMountPolicy::Apply, &[])
                .unwrap()
                .notice(),
            Some(format!(
                "==> Config mounts: 2 from {}",
                crate::one_line::quoted_path(user.file())
            ))
        );
        assert_eq!(
            select(automatic(Some(&user)), ConfigMountPolicy::Suppress, &[])
                .unwrap()
                .notice(),
            Some(format!(
                "==> Config mounts: skipped 2 from {} (--no-config-mounts)",
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
