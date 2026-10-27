//! Which mount declarations one launch asks [`crate::mount::prepare`] for.
//!
//! Two sources, one order: the verified user config first — its `mounts`
//! defaults, then whatever the argv names — and then `--mount` in argv order. The
//! order is a contract, not a convenience — `mount::claim` keeps the *first-seen*
//! declaration when two claims at one guest path are identical, so a conflict
//! diagnostic names the ambient declaration before the launch's own. Nothing here
//! can make one source win: a differing claim at a shared guest path is refused by
//! the same `claim_decision` kernel whichever list it came from (ADR-0046).
//!
//! **No I/O.** `select` reads the already-verified [`UserMounts`] and parses
//! argv; whether a selected source exists is `prepare`'s question. That split is
//! what lets an *unselected* declaration — or an unused set — name a missing path
//! without blocking a launch, `doctor` or `--help`.
//!
//! `--no-config-mounts` is read once, here, and suppresses **the defaults list
//! only** ([`config_mounts_selected`]): an explicit `--mount NAME` still selects
//! that set, and credentials, persisted paths, agent-vm's own mounts and every
//! load-time check are untouched, so a broken or untrusted mount configuration
//! still fails the launch before this module runs.
//!
//! One grammar decides what an argv entry is: [`crate::config_mounts::parse_selector`],
//! the same function config load uses. A bare name is an exact set lookup in the
//! verified user namespace and never a cwd-relative path, a directory or a tool;
//! every absolute (and `~/`-free) path keeps the historical `--mount` grammar.

use crate::{
    config_mounts::{MountSelector, MountSetName, UserMounts, parse_selector},
    mount::{HostSyntax, MountRequest, MountRequests},
};
use anyhow::{Result, anyhow};
use std::{mem, path::PathBuf};
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

/// What one launch did with the user config's automatic defaults.
///
/// `Selected` and `Skipped` carry the file and the declared count so the notice
/// can name both without re-reading the report; `NotDeclared` is "the file has no
/// `mounts` key", which is deliberately distinct from a present-but-empty list
/// (the authority rule turns on presence, the notice on declarations). A file that
/// declares only `[mount_sets]` is `NotDeclared` *for the automatic notice*: it
/// selected no access, so there is nothing to report and nothing to skip.
#[derive(Debug)]
enum ConfigUse {
    NotDeclared,
    Selected { file: PathBuf, count: usize },
    Skipped { file: PathBuf, count: usize },
}

/// Collect this launch's declarations: config defaults, then argv.
///
/// An argv entry keeps `parse_extra_mounts`' error chain byte-identically
/// (`parsing --mount`) because that is the only error an ordinary path can add and
/// its text is pinned. A set selection adds two errors of its own: an unknown name
/// and a forbidden per-selection modifier, both contextual and both before any
/// filesystem work.
pub(crate) fn select(
    user: Option<&UserMounts>,
    policy: ConfigMountPolicy,
    cli: &[String],
) -> Result<Selection> {
    let declared = user.is_some_and(UserMounts::has_defaults);
    let selected = config_mounts_selected(ConfigSelectionFacts {
        declared,
        suppressed: policy.suppressed(),
    });
    let (config, config_requests): (ConfigUse, &[MountRequest]) = match (user, selected) {
        (None, _) => (ConfigUse::NotDeclared, &[]),
        (Some(_), _) if !declared => (ConfigUse::NotDeclared, &[]),
        (Some(user), true) => (
            ConfigUse::Selected {
                file: user.file().to_path_buf(),
                count: user.len(),
            },
            user.requests(),
        ),
        (Some(user), false) => (
            ConfigUse::Skipped {
                file: user.file().to_path_buf(),
                count: user.len(),
            },
            &[],
        ),
    };
    let mut requests: Vec<MountRequest> = config_requests.to_vec();
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
                    requests.extend(selected);
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

/// One explicit `--mount NAME`, resolved against the verified user namespace and
/// nothing else.
///
/// An empty set is a legitimate selection that contributes no declaration, so this
/// returns an empty vector rather than an error. An unknown name is contextual: it
/// names the selection with `config`'s escaping (argv is user-typed text, but a
/// spelling that carries a newline must not forge a second line) and the file that
/// was searched, and it never falls back to a relative path, a directory or a tool.
fn explicit_set(user: Option<&UserMounts>, name: &MountSetName) -> Result<Vec<MountRequest>> {
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
    /// `None` only when the defaults contribute nothing: no `mounts` key, an empty
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
        let selected_defaults = matches!(
            &self.config,
            ConfigUse::Selected { count, .. } if *count > 0
        );
        match (&self.config, &self.explicit_sets) {
            (ConfigUse::Selected { file, .. }, Some(_)) if selected_defaults => format!(
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
    use crate::config_authority::{AuthorityTriggers, verify};
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
        let authorized = verify(
            &read,
            AuthorityTriggers {
                network: false,
                mounts: table.get("mounts").is_some(),
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
            Some(&user),
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
            Some(&user),
            ConfigMountPolicy::Suppress,
            &["/cli".to_owned()],
        )
        .unwrap();
        assert_eq!(
            described(&mut selection),
            [(MountOrigin::Cli, Spelling::new("/cli"))]
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
            let selection = select(mounts, policy, &[]).unwrap();
            assert_eq!(selection.preparation_context(), expected);
        }
        let selection = select(Some(&user), ConfigMountPolicy::Apply, &[]).unwrap();
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
            select(None, ConfigMountPolicy::Apply, &[])
                .unwrap()
                .notice(),
            None
        );
        // A sets-only file is not "skipped": the opt-out does not affect it, and
        // its definitions select nothing automatically.
        assert_eq!(
            select(Some(&sets_only), ConfigMountPolicy::Suppress, &[])
                .unwrap()
                .notice(),
            None
        );
        assert_eq!(
            select(Some(&sets_only), ConfigMountPolicy::Apply, &[])
                .unwrap()
                .notice(),
            None
        );
        assert_eq!(
            select(Some(&empty), ConfigMountPolicy::Apply, &[])
                .unwrap()
                .notice(),
            None
        );
        assert_eq!(
            select(Some(&empty), ConfigMountPolicy::Suppress, &[])
                .unwrap()
                .notice(),
            None
        );

        let user = user_mounts(&["~/ref:ro", "/srv/data:/data:rw"]);
        assert_eq!(
            select(Some(&user), ConfigMountPolicy::Apply, &[])
                .unwrap()
                .notice(),
            Some(format!(
                "==> Config mounts: 2 from {}",
                crate::one_line::quoted_path(user.file())
            ))
        );
        assert_eq!(
            select(Some(&user), ConfigMountPolicy::Suppress, &[])
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
            Some(&user),
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
        let mut selection =
            select(Some(&user), ConfigMountPolicy::Apply, &["empty".to_owned()]).unwrap();
        assert_eq!(sources(&mut selection), [Spelling::new("/h/def")]);
        // Both kinds contribute: the defaults first, then the set's leaves.
        let mut selection = select(
            Some(&user),
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
            select(Some(&user), ConfigMountPolicy::Apply, &["nope".to_owned()]).unwrap_err()
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
            select(None, ConfigMountPolicy::Apply, &["agent".to_owned()]).unwrap_err()
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
            select(None, ConfigMountPolicy::Apply, &[forged.to_owned()]).unwrap_err()
        );
        assert!(!error.contains('\n'), "{error}");
        // A per-selection modifier never becomes a set nor a path.
        let error = format!(
            "{:#}",
            select(
                Some(&user),
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
            select(None, ConfigMountPolicy::Apply, &["rel".to_owned()]).unwrap_err()
        );
        assert_eq!(
            error,
            "parsing --mount: mount set \"rel\" is not defined; no user config declares \
             [mount_sets]"
        );
        let error = format!(
            "{:#}",
            select(None, ConfigMountPolicy::Apply, &["./rel".to_owned()]).unwrap_err()
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
        let selection = select(Some(&user), ConfigMountPolicy::Apply, &[]).unwrap();
        assert_eq!(
            selection.preparation_context(),
            format!(
                "preparing mounts (including mounts from {file}; --no-config-mounts skips them)"
            )
        );
        // A set that contributed nothing leaves the sentence alone.
        let selection = select(
            Some(&user),
            ConfigMountPolicy::Suppress,
            &["empty".to_owned()],
        )
        .unwrap();
        assert_eq!(selection.preparation_context(), "preparing --mount");
        // An explicit set under the opt-out is attributed, and the sentence says the
        // opt-out does not skip it.
        let selection = select(
            Some(&user),
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
        let selection =
            select(Some(&user), ConfigMountPolicy::Apply, &["agent".to_owned()]).unwrap();
        assert_eq!(
            selection.preparation_context(),
            format!(
                "preparing mounts (including mounts and explicitly selected mount sets from \
                 {file}; --no-config-mounts skips only the mounts)"
            )
        );
    }
}
