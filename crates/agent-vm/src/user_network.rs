//! The persisted `[network]` table: which egress grants a user config carries.
//!
//! Whether the *file* may be trusted at all is [`crate::config_authority`]'s
//! decision, taken before this module sees a table and only when an
//! authority-bearing field is present — which is what keeps a tools/image-only
//! dotfile config working through a symlink (ADR-0040). ADR-0038 separately
//! guards directory exposure at the launch that could plant the bytes.
//!
//! Nothing here decides trust: [`from_verified_table`] demands the
//! `AuthorizedConfig` token, so a table cannot be parsed from an unverified
//! read.

use crate::{
    config_authority::AdoptedAuthority,
    egress_policy::UserEgress,
    egress_reference::{
        AllowanceEntry, EgressNamespace, EntryError, EntryFailure, ResolvedAllowances,
    },
};
use std::{
    fmt,
    path::{Path, PathBuf},
};

const INTERNET_SETTING: &str = "allow_internet_egress";
const LAN_SETTING: &str = "allow_lan";
const HOST_SETTING: &str = "allow_host";
const EGRESS_SETTING: &str = "allow_egress";
/// Not a setting: the one key whose presence here means the user wrote a
/// top-level `mounts` *after* a table header, so TOML scoped it into this table.
const MOUNTS_KEY: &str = "mounts";
pub(crate) const SETTINGS: [&str; 4] =
    [INTERNET_SETTING, LAN_SETTING, HOST_SETTING, EGRESS_SETTING];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct SavedGroups {
    pub(crate) internet: Option<bool>,
    pub(crate) lan: Option<bool>,
    pub(crate) host: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UserNetwork {
    file: PathBuf,
    /// Every file whose `[network]` contributed, in adoption order (ADR-0076
    /// R4.3). One entry for a single-file load, so its notices are byte-identical.
    files: Vec<PathBuf>,
    /// The file whose `[network]` supplied the `set:NAME` references this launch
    /// resolves. Only the default user config may declare `[egress_sets]`, so a
    /// merged table names that file, not the first contributor (ADR-0076 R5.2).
    reference_file: Option<PathBuf>,
    groups: SavedGroups,
    allowances: ResolvedAllowances,
}

impl UserNetwork {
    /// The first contributing file. Production reads [`Self::files`] or
    /// [`Self::reference_file`]; this stays as the single-file accessor later
    /// tests compare against.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn file(&self) -> &Path {
        &self.file
    }

    /// Every contributing file, in adoption order.
    pub(crate) fn files(&self) -> &[PathBuf] {
        &self.files
    }

    /// The file whose `[network]` supplied the declared `set:NAME` references, so
    /// `doctor`'s reference block names the declaring file even after a merge.
    /// Falls back to the first contributor, which is the single-file case byte
    /// for byte.
    pub(crate) fn reference_file(&self) -> &Path {
        self.reference_file.as_deref().unwrap_or(&self.file)
    }

    pub(crate) fn egress(&self) -> UserEgress<'_> {
        UserEgress {
            files: self.files(),
            internet: self.groups.internet,
            lan: self.groups.lan,
            host: self.groups.host,
            allowances: &self.allowances,
        }
    }

    /// Union adopted `[network]` tables in adoption order (ADR-0076 R4.3):
    /// `adopted_sources` in `[[sources]]` order, then the project config.
    ///
    /// Allowances union in that same order (first occurrence keeps its position,
    /// `set:NAME` attributions preserved); group booleans OR-union across the
    /// adopted sources, and any explicit project value overrides them, so the
    /// project config still outranks what it sourced.
    pub(crate) fn merge(
        adopted_sources: Vec<UserNetwork>,
        project: Option<UserNetwork>,
    ) -> Option<UserNetwork> {
        if adopted_sources.is_empty() && project.is_none() {
            return None;
        }
        let mut files = Vec::new();
        for network in adopted_sources.iter().chain(project.iter()) {
            for file in network.files() {
                if !files.contains(file) {
                    files.push(file.clone());
                }
            }
        }
        let mut allowances = ResolvedAllowances::default();
        for network in adopted_sources.iter().chain(project.iter()) {
            allowances.extend_from(&network.allowances);
        }
        let group = |pick: fn(&SavedGroups) -> Option<bool>| {
            let mut from_sources: Option<bool> = None;
            for network in &adopted_sources {
                if let Some(value) = pick(&network.groups) {
                    from_sources = match from_sources {
                        Some(true) => Some(true),
                        _ => Some(value),
                    };
                }
            }
            project
                .as_ref()
                .and_then(|project| pick(&project.groups))
                .or(from_sources)
        };
        let file = files
            .first()
            .cloned()
            .expect("a merged network has at least one file");
        let reference_file = adopted_sources
            .iter()
            .chain(project.iter())
            .find(|network| network.allowances.expansions().next().is_some())
            .map(|network| network.file.clone());
        Some(UserNetwork {
            file,
            files,
            reference_file,
            groups: SavedGroups {
                internet: group(|groups| groups.internet),
                lan: group(|groups| groups.lan),
                host: group(|groups| groups.host),
            },
            allowances,
        })
    }
    /// Every allowance this table grants, with its reference attributions.
    /// Read by `doctor` for the persisted-reference block.
    pub(crate) fn allowances(&self) -> &ResolvedAllowances {
        &self.allowances
    }
    #[cfg(test)]
    pub(crate) fn for_test(
        file: impl Into<PathBuf>,
        groups: SavedGroups,
        allowances: &[&str],
    ) -> Self {
        Self::resolved(file, groups, allowances, None)
    }
    /// A saved table whose entries may include egress references.
    #[cfg(test)]
    pub(crate) fn for_test_with_tools(
        file: impl Into<PathBuf>,
        groups: SavedGroups,
        allowances: &[&str],
        user_tools: &EgressNamespace,
    ) -> Self {
        Self::resolved(file, groups, allowances, Some(user_tools))
    }
    #[cfg(test)]
    fn resolved(
        file: impl Into<PathBuf>,
        groups: SavedGroups,
        allowances: &[&str],
        user_tools: Option<&EgressNamespace>,
    ) -> Self {
        let entries = allowances
            .iter()
            .map(|text| AllowanceEntry::parse(text).unwrap())
            .collect();
        let file = file.into();
        Self {
            files: vec![file.clone()],
            file,
            reference_file: None,
            groups,
            allowances: crate::egress_reference::resolve(entries, user_tools).unwrap(),
        }
    }
}

#[derive(Debug)]
pub(crate) enum UserNetworkError {
    Setting {
        setting: SettingPath,
        reason: SettingReason,
    },
}
#[derive(Debug)]
pub(crate) enum SettingPath {
    Table,
    Key(&'static str),
    EgressEntry(usize),
}
#[derive(Debug)]
pub(crate) enum SettingReason {
    NotBool,
    /// `network` was present but not a table.
    NotTable,
    NotArray,
    NotString,
    Unknown,
    /// `mounts` landed inside `[network]` because TOML assigns keys to the most
    /// recent table header. Names the fix instead of calling it an unknown
    /// setting; the value is never read, let alone echoed.
    TopLevelMounts,
    /// An entry's own reason: an allowance-grammar error, or an egress
    /// reference that could not be resolved.
    Entry(EntryError),
}

impl UserNetworkError {
    /// One reference failure, positioned inside `allow_egress`.
    fn unresolved(failure: EntryFailure) -> Self {
        Self::Setting {
            setting: SettingPath::EgressEntry(failure.index),
            reason: SettingReason::Entry(failure.error),
        }
    }
}

impl fmt::Display for UserNetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Trust refusals live in `config_authority`, which also names the
        // authority-bearing field(s) it refused: this module's own errors are
        // about the table's contents only.
        match self {
            Self::Setting { setting, reason } => {
                match setting {
                    SettingPath::Table => f.write_str("[network]: ")?,
                    SettingPath::Key(key) => write!(f, "network.{key}: ")?,
                    SettingPath::EgressEntry(index) => {
                        write!(f, "network.allow_egress[{index}]: ")?
                    }
                }
                match reason {
                    SettingReason::NotBool => f.write_str("must be true or false"),
                    SettingReason::NotTable => f.write_str("must be a table"),
                    SettingReason::NotArray => f.write_str("must be an array of strings"),
                    SettingReason::NotString => f.write_str("must be a string"),
                    SettingReason::Unknown => write!(
                        f,
                        "unknown setting; supported settings are {} and {}",
                        SETTINGS[..3].join(", "),
                        SETTINGS[3]
                    ),
                    SettingReason::TopLevelMounts => write!(
                        f,
                        "{MOUNTS_KEY} is not a network setting; a top-level mounts list must be \
                         written before the first table header (keys after [network] belong to it)"
                    ),
                    SettingReason::Entry(error) => error.fmt(f),
                }
            }
        }
    }
}

/// The `[network]` table of a verified file, parsed but not yet resolved.
///
/// Two steps, because a reference's *resolution* error must come after tool
/// validation while its *syntax* error must come before it (R14): the entries are
/// classified here, where the table is parsed, and turned into allowances by
/// [`Self::resolve`], which `config::read_file_tier` calls once the tier's tools
/// are validated.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ParsedUserNetwork {
    file: PathBuf,
    groups: SavedGroups,
    entries: Vec<AllowanceEntry>,
}

impl ParsedUserNetwork {
    /// Resolve with **no** set namespace: a project config or an `allow = true`
    /// source may grant literals only until #738 adds `set:` selectors for them
    /// (ADR-0076 R3), so a reference there is refused for the file rather than
    /// resolved against another file's names.
    pub(crate) fn resolve_without_sets(self) -> Result<UserNetwork, UserNetworkError> {
        Ok(UserNetwork {
            files: vec![self.file.clone()],
            file: self.file,
            reference_file: None,
            groups: self.groups,
            allowances: crate::egress_reference::resolve(self.entries, None)
                .map_err(UserNetworkError::unresolved)?,
        })
    }

    pub(crate) fn resolve(
        self,
        user_tools: &EgressNamespace,
    ) -> Result<UserNetwork, UserNetworkError> {
        Ok(UserNetwork {
            files: vec![self.file.clone()],
            file: self.file,
            reference_file: None,
            groups: self.groups,
            allowances: crate::egress_reference::resolve(self.entries, Some(user_tools))
                .map_err(UserNetworkError::unresolved)?,
        })
    }
}

/// Parse a `[network]` value whose file's top-level authority was established
/// (ADR-0076 R4.3): the project config or an `allow = true` source.
///
/// The [`AdoptedAuthority`] token replaces the [`AuthorizedConfig`] one because a
/// verified *read* is not the only way to adopt now — approved source content
/// (#736) is the other — while both demand that some authority was measured.
/// Value-safe on shape: a non-table `network = 42` is refused by presence, never
/// echoed.
pub(crate) fn from_authorized_value(
    authority: &AdoptedAuthority<'_>,
    value: &toml::Value,
) -> Result<ParsedUserNetwork, UserNetworkError> {
    let table = value.as_table().ok_or(UserNetworkError::Setting {
        setting: SettingPath::Table,
        reason: SettingReason::NotTable,
    })?;
    parse_table(authority.file(), table)
}

fn parse_bool(setting: &'static str, value: &toml::Value) -> Result<bool, UserNetworkError> {
    value.as_bool().ok_or(UserNetworkError::Setting {
        setting: SettingPath::Key(setting),
        reason: SettingReason::NotBool,
    })
}

fn parse_table(file: &Path, table: &toml::Table) -> Result<ParsedUserNetwork, UserNetworkError> {
    let mut groups = SavedGroups::default();
    let mut parsed_entries = Vec::new();
    for (key, value) in table {
        match key.as_str() {
            INTERNET_SETTING => groups.internet = Some(parse_bool(INTERNET_SETTING, value)?),
            LAN_SETTING => groups.lan = Some(parse_bool(LAN_SETTING, value)?),
            HOST_SETTING => groups.host = Some(parse_bool(HOST_SETTING, value)?),
            EGRESS_SETTING => {
                let entries = value.as_array().ok_or(UserNetworkError::Setting {
                    setting: SettingPath::Key(SETTINGS[3]),
                    reason: SettingReason::NotArray,
                })?;
                for (index, value) in entries.iter().enumerate() {
                    let text = value.as_str().ok_or(UserNetworkError::Setting {
                        setting: SettingPath::EgressEntry(index),
                        reason: SettingReason::NotString,
                    })?;
                    let entry =
                        AllowanceEntry::parse(text).map_err(|error| UserNetworkError::Setting {
                            setting: SettingPath::EgressEntry(index),
                            reason: SettingReason::Entry(error),
                        })?;
                    parsed_entries.push(entry);
                }
            }
            _ => {
                let reason = if key.as_str() == MOUNTS_KEY {
                    SettingReason::TopLevelMounts
                } else {
                    SettingReason::Unknown
                };
                return Err(UserNetworkError::Setting {
                    setting: SettingPath::Table,
                    reason,
                });
            }
        }
    }
    Ok(ParsedUserNetwork {
        file: file.to_owned(),
        groups,
        entries: parsed_entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(text: &str) -> toml::Table {
        text.parse().unwrap()
    }

    #[test]
    fn boolean_settings_route_independently() {
        for (setting, field) in [
            ("allow_internet_egress", 0),
            ("allow_lan", 1),
            ("allow_host", 2),
        ] {
            for value in [false, true] {
                let parsed = parse_table(
                    Path::new("config.toml"),
                    &table(&format!("{setting} = {value}")),
                )
                .unwrap();
                let mut expected = [None; 3];
                expected[field] = Some(value);
                assert_eq!(
                    [
                        parsed.groups.internet,
                        parsed.groups.lan,
                        parsed.groups.host
                    ],
                    expected
                );
            }
        }
        let mixed = parse_table(
            Path::new("config.toml"),
            &table("allow_internet_egress = false\nallow_lan = true\nallow_host = false"),
        )
        .unwrap();
        assert_eq!(
            mixed.groups,
            SavedGroups {
                internet: Some(false),
                lan: Some(true),
                host: Some(false)
            }
        );
        assert_eq!(
            parse_table(Path::new("config.toml"), &table(""))
                .unwrap()
                .groups,
            SavedGroups::default()
        );
    }

    /// The set-less namespace every accepting test resolves against: a literal
    /// entry needs no sets, and no accepting test here uses a reference.
    fn no_sets() -> EgressNamespace {
        EgressNamespace::new(
            crate::config_authority::ReferenceTrust::verified_for_test(Path::new("user.toml")),
            None,
        )
        .unwrap()
    }

    #[test]
    fn parse_accepts_settings_and_canonicalizes() {
        let parsed = parse_table(
            Path::new("user.toml"),
            &table(
                r#"
allow_internet_egress = false
allow_lan = true
allow_host = true
allow_egress = ["10.0.0.5", "10.0.0.5/32", "API.example.com.", "api.example.com"]
"#,
            ),
        )
        .unwrap()
        .resolve(&no_sets())
        .unwrap();
        assert_eq!(
            parsed,
            UserNetwork::for_test(
                "user.toml",
                SavedGroups {
                    internet: Some(false),
                    lan: Some(true),
                    host: Some(true),
                },
                &["10.0.0.5/32", "api.example.com"]
            )
        );
        let empty = parse_table(Path::new("user.toml"), &table(""))
            .unwrap()
            .resolve(&no_sets())
            .unwrap();
        assert_eq!(empty.groups, SavedGroups::default());
        assert!(empty.allowances().allowances().next().is_none());
        let view = parsed.egress();
        assert_eq!(
            (view.internet, view.lan, view.host),
            (Some(false), Some(true), Some(true))
        );
        assert_eq!(view.allowances.allowances().count(), 2);
    }

    /// TOML scopes `mounts` into `[network]` when it is written after that
    /// header. The hint names the fix; every other unknown key keeps the
    /// unknown-setting text, and neither echoes the value.
    #[test]
    fn mounts_key_in_network_table_gets_the_top_level_hint() {
        const SENTINEL: &str = "sk-live-SENTINEL-mounts";
        let error = parse_table(
            Path::new("user.toml"),
            &table(&format!("mounts = \"{SENTINEL}\"")),
        )
        .unwrap_err()
        .to_string();
        assert_eq!(
            error,
            "[network]: mounts is not a network setting; a top-level mounts list must be \
             written before the first table header (keys after [network] belong to it)"
        );
        assert!(!error.contains(SENTINEL));
        // Any other key, and a sentinel key, keep today's bytes.
        for key in ["mount", "mounts2", SENTINEL] {
            assert_eq!(
                parse_table(Path::new("user.toml"), &table(&format!("{key} = true")))
                    .unwrap_err()
                    .to_string(),
                "[network]: unknown setting; supported settings are allow_internet_egress, \
                 allow_lan, allow_host and allow_egress"
            );
        }
    }

    #[test]
    fn parse_errors_name_the_setting_and_never_echo_values() {
        let sentinel = "sk-live-SENTINEL";
        for setting in &SETTINGS[..3] {
            let error = parse_table(
                Path::new("user.toml"),
                &table(&format!("{setting} = \"{sentinel}\"")),
            )
            .unwrap_err()
            .to_string();
            assert_eq!(error, format!("network.{setting}: must be true or false"));
        }
        for (text, expected) in [
            (
                format!("allow_egress = \"{sentinel}\""),
                "network.allow_egress: must be an array of strings",
            ),
            (
                "allow_egress = [\"10.0.0.1\", 7]".into(),
                "network.allow_egress[1]: must be a string",
            ),
            (
                format!("\"{sentinel}\" = true"),
                "[network]: unknown setting; supported settings are allow_internet_egress, allow_lan, allow_host and allow_egress",
            ),
            (
                format!("allow_egress = [\"10.0.0.1\", \"https://{sentinel}\"]"),
                "network.allow_egress[1]: unsupported scheme; use tcp:// or udp:// (or no scheme for all protocols)",
            ),
        ] {
            let error = parse_table(Path::new("user.toml"), &table(&text))
                .unwrap_err()
                .to_string();
            assert_eq!(error, expected);
            assert!(!error.contains(sentinel));
        }
    }

    /// A31 and R22/R28: a `set:` failure in a persisted entry keeps the same
    /// position prefix a `tool:` failure does, and echoes neither the entry nor
    /// the name inside it.
    #[test]
    fn set_reference_failures_keep_the_entry_prefix_and_echo_nothing() {
        const SENTINEL: &str = "SENTINEL7";
        let sets = EgressNamespace::new(
            crate::config_authority::ReferenceTrust::verified_for_test(Path::new("user.toml")),
            None,
        )
        .unwrap();
        for (text, expected) in [
            (
                format!("allow_egress = [\"10.0.0.1\", \"SET:{SENTINEL}\"]"),
                "network.allow_egress[1]: an egress reference must name a set declared in the user config's own [egress_sets]; project and built-in configs cannot declare sets",
            ),
            (
                "allow_egress = [\"set:a b\"]".to_owned(),
                "network.allow_egress[0]: an egress reference must be set:NAME with a valid egress-set name ([A-Za-z0-9_] first, then [A-Za-z0-9_.-])",
            ),
            (
                format!("allow_egress = [\"set:{SENTINEL}\\u0000\"]"),
                "network.allow_egress[0]: an egress reference must be set:NAME with a valid egress-set name ([A-Za-z0-9_] first, then [A-Za-z0-9_.-])",
            ),
        ] {
            let error = parse_table(Path::new("user.toml"), &table(&text))
                .and_then(|parsed| parsed.resolve(&sets))
                .unwrap_err()
                .to_string();
            assert_eq!(error, expected, "{text}");
            assert!(!error.contains(SENTINEL), "{error}");
        }
    }

    /// V12: `tool:NAME` is no longer a reference, so it keeps this module's
    /// setting prefix while the *grammar* refuses it — and the sentence never
    /// echoes the entry. A numeric `tool:PORT` reverts to the literal hostname
    /// `tool`, which is the pre-#506 meaning.
    #[test]
    fn tool_names_are_ordinary_allowance_text_again() {
        const SENTINEL: &str = "sk-live-SENTINEL";
        let sets = EgressNamespace::new(
            crate::config_authority::ReferenceTrust::verified_for_test(Path::new("user.toml")),
            None,
        )
        .unwrap();
        for (text, expected) in [
            (
                format!("allow_egress = [\"10.0.0.1\", \"tool:{SENTINEL}\"]"),
                "network.allow_egress[1]: port must be a decimal number 1-65535",
            ),
            (
                "allow_egress = [\"tool:\"]".to_owned(),
                "network.allow_egress[0]: port must be a decimal number 1-65535",
            ),
        ] {
            let error = parse_table(Path::new("user.toml"), &table(&text))
                .and_then(|parsed| parsed.resolve(&sets))
                .unwrap_err()
                .to_string();
            assert_eq!(error, expected);
            assert!(!error.contains(SENTINEL));
        }
        let resolved = parse_table(
            Path::new("user.toml"),
            &table("allow_egress = [\"tool:443\"]"),
        )
        .unwrap()
        .resolve(&sets)
        .unwrap();
        let rendered: Vec<String> = resolved
            .allowances()
            .allowances()
            .map(ToString::to_string)
            .collect();
        assert_eq!(rendered, ["tcp://tool:443"]);
    }
}
