//! Which mount declarations one launch asks [`crate::mount::prepare`] for.
//!
//! Two sources, one order: the verified user config's `mounts` first (file
//! order), then `--mount` (argv order). The order is a contract, not a
//! convenience — `mount::claim` keeps the *first-seen* declaration when two
//! claims at one guest path are identical, so a conflict diagnostic names the
//! ambient declaration before the launch's own. Nothing here can make one
//! source win: a differing claim at a shared guest path is refused by the same
//! `claim_decision` kernel whichever list it came from (ADR-0046).
//!
//! **No I/O.** `select` reads the already-verified [`UserMounts`] and parses
//! argv; whether a selected source exists is `prepare`'s question. That split is
//! what lets an *unselected* declaration name a missing path without blocking a
//! launch, `doctor` or `--help`.
//!
//! `--no-config-mounts` is read once, here, and suppresses **selection only**
//! ([`config_mounts_selected`]): explicit `--mount`, credentials, persisted
//! paths, agent-vm's own mounts and every load-time check are untouched, so a
//! broken or untrusted `mounts` config still fails the launch before this module
//! runs.

use crate::{
    config::quoted_path,
    config_mounts::UserMounts,
    mount::{MountRequest, MountRequests, parse_extra_mounts},
};
use anyhow::{Context, Result};
use std::{mem, path::PathBuf};
use vstd::prelude::*;

verus! {
/// The two facts that decide whether the user config's declarations reach the
/// guest. Named fields rather than two adjacent booleans, so a call site cannot
/// swap "declared" for "suppressed" — they differ in polarity.
#[derive(Clone, Copy, Debug)]
pub struct ConfigSelectionFacts { pub declared: bool, pub suppressed: bool }

/// ADR-0046: `--no-config-mounts` withholds the user config's declarations and
/// nothing else. A file that declared `mounts` is still authority-bearing and is
/// still verified — this decides selection, never trust.
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
    /// Select the user config's declarations for this launch (the default).
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
}

/// What one launch did with the user config's `mounts`.
///
/// `Selected` and `Skipped` carry the file and the declared count so the notice
/// can name both without re-reading the report; `NotDeclared` is "the file has
/// no `mounts` key", which is deliberately distinct from a present-but-empty
/// list (the authority rule turns on presence, the notice on declarations).
#[derive(Debug)]
enum ConfigUse {
    NotDeclared,
    Selected { file: PathBuf, count: usize },
    Skipped { file: PathBuf, count: usize },
}

/// Collect this launch's declarations: user-config, then argv.
///
/// The argv half keeps `parse_extra_mounts`' error chain byte-identical
/// (`parsing --mount`), because that is the only error this function can add and
/// its text is pinned.
pub(crate) fn select(
    user: Option<&UserMounts>,
    policy: ConfigMountPolicy,
    cli: &[String],
) -> Result<Selection> {
    let selected = config_mounts_selected(ConfigSelectionFacts {
        declared: user.is_some(),
        suppressed: policy.suppressed(),
    });
    let (config, config_requests): (ConfigUse, &[MountRequest]) = match (user, selected) {
        (None, _) => (ConfigUse::NotDeclared, &[]),
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
    // `from_cli` is the one place an argv declaration is tagged as `Cli`, so the
    // `MountRequests` round-trip is deliberate: the config half must precede it,
    // and a second copy of the tagging rule is exactly what this avoids.
    requests.extend(
        MountRequests::from_cli(parse_extra_mounts(cli).context("parsing --mount")?).into_inner(),
    );
    Ok(Selection {
        requests: MountRequests::new(requests),
        config,
    })
}

impl Selection {
    /// Hand the declarations to `prepare`. Fallible-free because selection has
    /// already done everything but I/O.
    pub(crate) fn take_requests(&mut self) -> MountRequests {
        mem::take(&mut self.requests)
    }

    /// One line naming the file and how many declarations it contributed.
    ///
    /// `None` only when the file contributes nothing: no `mounts` key, or an
    /// empty list. A launch with nothing from the config must not print a "0"
    /// row on every run. A non-empty list the opt-out skipped still reports, as
    /// `skipped N` — that is the one case where the reader has to be told the
    /// file declared mounts and this launch ignored them.
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
                quoted_path(file)
            )
        } else {
            format!("==> Config mounts: {count} from {}", quoted_path(file))
        })
    }

    /// The `mount::prepare` error context.
    ///
    /// `"preparing --mount"` whenever no config declaration reached `prepare` —
    /// including `mounts = []` and the opt-out — so an argv-only launch's error
    /// bytes do not change. Otherwise it names the file, because a failure may
    /// be about a declaration the reader did not type on this command line.
    pub(crate) fn preparation_context(&self) -> String {
        match &self.config {
            ConfigUse::Selected { file, count } if *count > 0 => format!(
                "preparing mounts (including mounts from {}; --no-config-mounts skips them)",
                quoted_path(file)
            ),
            ConfigUse::NotDeclared | ConfigUse::Selected { .. } | ConfigUse::Skipped { .. } => {
                "preparing --mount".to_owned()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_authority::{AuthorityTriggers, verify};
    use crate::config_mounts::from_verified_value;
    use crate::host_paths::read_bounded_regular_file_noting_symlink;
    use crate::mount::{MountOrigin, Spelling};
    use std::{fs, os::unix::fs::PermissionsExt, path::Path};

    const HOME: &str = "/home/selection";

    /// Selection input built through the real verified-read path: a selection
    /// test must not be able to conjure a [`UserMounts`] no launch could have.
    /// `entries` are the `mounts` array elements, exactly as `config` stores them.
    fn user_mounts(entries: &[&str]) -> UserMounts {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let file = root.path().join("config.toml");
        fs::write(&file, "mounts = []\n").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let read = read_bounded_regular_file_noting_symlink(&file, 4096).unwrap();
        let authorized = verify(
            &read,
            AuthorityTriggers {
                network: false,
                mounts: true,
            },
        )
        .unwrap()
        .expect("a present `mounts` key is authority-bearing");
        let value = toml::Value::Array(
            entries
                .iter()
                .map(|entry| toml::Value::String((*entry).to_owned()))
                .collect(),
        );
        from_verified_value(&authorized, &value, Some(Path::new(HOME)))
            .expect("the fixture entries parse")
    }

    fn described(selection: &mut Selection) -> Vec<(MountOrigin, Spelling)> {
        selection
            .take_requests()
            .into_inner()
            .into_iter()
            .map(|request| (request.origin, request.mount.source_spelling))
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
        let user = user_mounts(&["~/ref:ro"]);
        let cases = [
            (None, ConfigMountPolicy::Apply, "preparing --mount"),
            (Some(&empty), ConfigMountPolicy::Apply, "preparing --mount"),
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
                quoted_path(user.file())
            )
        );
    }

    /// Both lines, and silence when the file contributes nothing.
    #[test]
    fn notice_names_the_file_and_the_skipped_count() {
        let empty = user_mounts(&[]);
        assert_eq!(
            select(None, ConfigMountPolicy::Apply, &[])
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
                quoted_path(user.file())
            ))
        );
        assert_eq!(
            select(Some(&user), ConfigMountPolicy::Suppress, &[])
                .unwrap()
                .notice(),
            Some(format!(
                "==> Config mounts: skipped 2 from {} (--no-config-mounts)",
                quoted_path(user.file())
            ))
        );
    }
}
