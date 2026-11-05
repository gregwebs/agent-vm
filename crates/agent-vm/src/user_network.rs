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
    config_authority::AuthorizedConfig,
    egress_policy::UserEgress,
    egress_reference::{
        AllowanceEntry, EntryError, EntryFailure, ResolvedAllowances, UserToolRequests,
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
    groups: SavedGroups,
    allowances: ResolvedAllowances,
}

impl UserNetwork {
    pub(crate) fn file(&self) -> &Path {
        &self.file
    }
    pub(crate) fn egress(&self) -> UserEgress<'_> {
        UserEgress {
            file: self.file(),
            internet: self.groups.internet,
            lan: self.groups.lan,
            host: self.groups.host,
            allowances: &self.allowances,
        }
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
        user_tools: &UserToolRequests,
    ) -> Self {
        Self::resolved(file, groups, allowances, Some(user_tools))
    }
    #[cfg(test)]
    fn resolved(
        file: impl Into<PathBuf>,
        groups: SavedGroups,
        allowances: &[&str],
        user_tools: Option<&UserToolRequests>,
    ) -> Self {
        let entries = allowances
            .iter()
            .map(|text| AllowanceEntry::parse(text).unwrap())
            .collect();
        Self {
            file: file.into(),
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
    pub(crate) fn resolve(
        self,
        user_tools: &UserToolRequests,
    ) -> Result<UserNetwork, UserNetworkError> {
        Ok(UserNetwork {
            file: self.file,
            groups: self.groups,
            allowances: crate::egress_reference::resolve(self.entries, Some(user_tools))
                .map_err(UserNetworkError::unresolved)?,
        })
    }
}

/// Parse a `[network]` table whose file has already been verified.
///
/// The token is the point: ADR-0040's checks and this parse cannot be reached
/// independently, so there is no order in which a table is read unverified.
pub(crate) fn from_verified_table(
    authorized: &AuthorizedConfig<'_>,
    table: &toml::Table,
) -> Result<ParsedUserNetwork, UserNetworkError> {
    parse_table(authorized.file(), table)
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

    /// The literal-only namespace every accepting test resolves against: a
    /// literal entry needs no tools, and no test here uses a reference.
    fn no_tools() -> UserToolRequests {
        UserToolRequests::new(
            crate::config_authority::ReferenceTrust::verified_for_test(Path::new("user.toml")),
            &[],
        )
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
        .resolve(&no_tools())
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
            .resolve(&no_tools())
            .unwrap();
        assert_eq!(empty.groups, SavedGroups::default());
        assert!(empty.allowances().allowances().next().is_none());
        let view = parsed.egress();
        assert_eq!(view.file, parsed.file());
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

    /// A resolved reference failure keeps this module's setting prefix, so the
    /// load error reads `config: "<file>": network.allow_egress[N]: <reason>`
    /// (R15) — and never echoes the entry or the name it named (R17).
    #[test]
    fn reference_failures_keep_the_entry_prefix_and_echo_nothing() {
        const SENTINEL: &str = "sk-live-SENTINEL";
        let tools = UserToolRequests::new(
            crate::config_authority::ReferenceTrust::verified_for_test(Path::new("user.toml")),
            &[],
        );
        for (text, expected) in [
            (
                format!("allow_egress = [\"10.0.0.1\", \"TOOL:{SENTINEL}\"]"),
                "network.allow_egress[1]: an egress reference must name a tool declared in the user config's own [[tools]]; built-in and project tools are never used (`agent-vm tools print` prints the shipped tools to copy there)",
            ),
            (
                "allow_egress = [\"tool:a b\"]".to_owned(),
                "network.allow_egress[0]: an egress reference must be tool:NAME with a valid tool name (no whitespace, control characters or '/', not starting with '-', and not `.`, `..`, `*` or a reserved subcommand name)",
            ),
        ] {
            let error = parse_table(Path::new("user.toml"), &table(&text))
                .and_then(|parsed| parsed.resolve(&tools))
                .unwrap_err()
                .to_string();
            assert_eq!(error, expected);
            assert!(!error.contains(SENTINEL));
        }
    }
}
