//! A guest-written dotfile target can grant a later project's egress unless the
//! authority read rejects final-component symlinks. ADR-0040 keeps tools/image-only
//! dotfile configs compatible; ADR-0038 separately guards directory exposure.

use crate::protected_config_dir::authority_file_singly_linked;
use vstd::prelude::*;

verus! {
#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub enum AuthorityRefusal { DirNotDirectory, DirOwner, DirWritable, ThroughSymlink, FileOwner, FileWritable, FileLinks(u64) }

#[derive(Clone, Copy, Debug)]
pub struct FileFacts { pub uid: u32, pub mode: u32, pub nlink: u64 }
#[derive(Clone, Copy, Debug)]
pub struct DirFacts { pub is_dir: bool, pub uid: u32, pub mode: u32 }
#[derive(Clone, Copy, Debug)]
pub enum Reached { ThroughSymlink, Direct(FileFacts) }

pub open spec fn others_may_write(mode: u32) -> bool { mode & 0o022u32 != 0u32 }
pub open spec fn dir_ok(d: DirFacts, euid: u32) -> bool { d.is_dir && d.uid == euid && !others_may_write(d.mode) }
pub open spec fn file_ok(f: FileFacts, euid: u32) -> bool { f.uid == euid && !others_may_write(f.mode) && crate::protected_config_dir::authority_file_singly_linked_spec(f.nlink) }

/// Precedence mirrors credential_yaml::load: directory first, then the file.
pub fn network_authority_refusal(reached: Reached, dir: DirFacts, euid: u32) -> (r: Option<AuthorityRefusal>)
    ensures
        r.is_none() == (dir_ok(dir, euid) && match reached { Reached::Direct(f) => file_ok(f, euid), Reached::ThroughSymlink => false }),
        !dir.is_dir ==> r == Some(AuthorityRefusal::DirNotDirectory),
        dir.is_dir && dir.uid != euid ==> r == Some(AuthorityRefusal::DirOwner),
        dir.is_dir && dir.uid == euid && others_may_write(dir.mode) ==> r == Some(AuthorityRefusal::DirWritable),
        dir_ok(dir, euid) ==> match reached {
            Reached::ThroughSymlink => r == Some(AuthorityRefusal::ThroughSymlink),
            Reached::Direct(f) =>
                (f.uid != euid ==> r == Some(AuthorityRefusal::FileOwner))
                && (f.uid == euid && others_may_write(f.mode) ==> r == Some(AuthorityRefusal::FileWritable))
                && (f.uid == euid && !others_may_write(f.mode) && !crate::protected_config_dir::authority_file_singly_linked_spec(f.nlink) ==> r == Some(AuthorityRefusal::FileLinks(f.nlink))),
        },
{
    if !dir.is_dir { return Some(AuthorityRefusal::DirNotDirectory); }
    if dir.uid != euid { return Some(AuthorityRefusal::DirOwner); }
    if dir.mode & 0o022 != 0 { return Some(AuthorityRefusal::DirWritable); }
    match reached {
        Reached::ThroughSymlink => Some(AuthorityRefusal::ThroughSymlink),
        Reached::Direct(f) => {
            if f.uid != euid { Some(AuthorityRefusal::FileOwner) }
            else if f.mode & 0o022 != 0 { Some(AuthorityRefusal::FileWritable) }
            // The one-name rule is ADR-0038's, shared with the launch-time check.
            else if !authority_file_singly_linked(f.nlink) { Some(AuthorityRefusal::FileLinks(f.nlink)) }
            else { None }
        }
    }
}
} // verus!

use crate::{
    egress_grammar::AllowanceError,
    egress_policy::{Allowance, UserEgress},
    host_paths::FinalComponent,
};
use std::{
    fmt,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

const INTERNET_SETTING: &str = "allow_internet_egress";
const LAN_SETTING: &str = "allow_lan";
const HOST_SETTING: &str = "allow_host";
const EGRESS_SETTING: &str = "allow_egress";
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
    allowances: Vec<Allowance>,
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
    #[cfg(test)]
    pub(crate) fn for_test(
        file: impl Into<PathBuf>,
        groups: SavedGroups,
        allowances: &[&str],
    ) -> Self {
        let mut entries = Vec::new();
        for text in allowances {
            let entry = Allowance::parse(text).unwrap();
            if !entries.contains(&entry) {
                entries.push(entry);
            }
        }
        Self {
            file: file.into(),
            groups,
            allowances: entries,
        }
    }
}

#[derive(Debug)]
pub(crate) enum UserNetworkError {
    /// The refusal variant itself carries the one extra datum that is valid for
    /// it (`FileLinks`), so a symlink refusal cannot also hold a link count.
    Untrusted(AuthorityRefusal),
    DirUnexaminable(std::io::ErrorKind),
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
    Allowance(AllowanceError),
}

impl fmt::Display for UserNetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Untrusted(refusal) => {
                use AuthorityRefusal::*;
                // These refusals fire where a guest or another account may have
                // authored the bytes, so none advises making the file trusted
                // before its [network] table has been reviewed.
                match refusal {
                    ThroughSymlink => f.write_str("[network] requires config.toml to be a regular file, but it is reached through a symbolic link; its target may be writable by a guest or project, so review the [network] table before trusting the file (a symlinked config without [network] still works)"),
                    FileOwner => f.write_str("[network] refuses a config.toml owned by another user; review the [network] table before trusting the file"),
                    FileWritable => f.write_str("[network] refuses a group- or other-writable config.toml; a guest or another account may have written its [network] table, so review the [network] table before trusting the file (fixing the mode does not establish authorship)"),
                    FileLinks(nlink) => write!(f, "[network] refuses a config.toml with {nlink} hard links; another name for it may be guest- or project-writable, so review the [network] table before trusting the file"),
                    DirNotDirectory => f.write_str("[network] refuses a config.toml whose directory is not a directory"),
                    DirOwner => f.write_str("[network] refuses a config.toml whose directory is owned by another user; review the [network] table before trusting the file"),
                    DirWritable => f.write_str("[network] refuses a config.toml whose directory is group- or other-writable; a guest or another account may be able to replace the file, so review the [network] table before trusting it"),
                }
            }
            Self::DirUnexaminable(kind) => write!(
                f,
                "[network] requires examining the config directory, which failed ({kind:?})"
            ),
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
                    SettingReason::Allowance(error) => error.fmt(f),
                }
            }
        }
    }
}

pub(crate) fn from_user_tier(
    read: &crate::host_paths::VerifiedRead,
    table: &toml::Table,
) -> Result<UserNetwork, UserNetworkError> {
    let file = read.path();
    // Separate path observation, not anchored to the read descriptor; ancestors remain trusted (A2).
    let parent = file.parent().ok_or(UserNetworkError::DirUnexaminable(
        std::io::ErrorKind::NotFound,
    ))?;
    let meta =
        std::fs::metadata(parent).map_err(|e| UserNetworkError::DirUnexaminable(e.kind()))?;
    let dir = DirFacts {
        is_dir: meta.is_dir(),
        uid: meta.uid(),
        mode: meta.mode(),
    };
    let reached = match read.final_component() {
        FinalComponent::Symlink => Reached::ThroughSymlink,
        FinalComponent::Regular(f) => Reached::Direct(FileFacts {
            uid: f.uid,
            mode: raw_mode_u32(f.mode),
            nlink: f.nlink,
        }),
    };
    if let Some(refusal) =
        network_authority_refusal(reached, dir, crate::host_paths::current_euid())
    {
        return Err(UserNetworkError::Untrusted(refusal));
    }
    parse_table(file, table)
}

fn raw_mode_u32(mode: rustix::fs::RawMode) -> u32 {
    // RawMode is u16 on macOS, u32 on Linux.
    #[allow(clippy::useless_conversion)]
    u32::from(mode)
}

fn parse_bool(setting: &'static str, value: &toml::Value) -> Result<bool, UserNetworkError> {
    value.as_bool().ok_or(UserNetworkError::Setting {
        setting: SettingPath::Key(setting),
        reason: SettingReason::NotBool,
    })
}

fn parse_table(file: &Path, table: &toml::Table) -> Result<UserNetwork, UserNetworkError> {
    let mut groups = SavedGroups::default();
    let mut allowances = Vec::new();
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
                    let entry = Allowance::parse(text).map_err(|e| UserNetworkError::Setting {
                        setting: SettingPath::EgressEntry(index),
                        reason: SettingReason::Allowance(e),
                    })?;
                    if !allowances.contains(&entry) {
                        allowances.push(entry);
                    }
                }
            }
            _ => {
                return Err(UserNetworkError::Setting {
                    setting: SettingPath::Table,
                    reason: SettingReason::Unknown,
                });
            }
        }
    }
    Ok(UserNetwork {
        file: file.to_owned(),
        groups,
        allowances,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

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
        let empty = parse_table(Path::new("user.toml"), &table("")).unwrap();
        assert_eq!(empty.groups, SavedGroups::default());
        assert!(empty.allowances.is_empty());
        let view = parsed.egress();
        assert_eq!(view.file, parsed.file());
        assert_eq!(
            (view.internet, view.lan, view.host),
            (Some(false), Some(true), Some(true))
        );
        assert_eq!(view.allowances.len(), 2);
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

    #[test]
    fn from_user_tier_verdicts_on_real_files() {
        use std::{fs, os::unix::fs::PermissionsExt};
        if crate::host_paths::current_euid() == 0 {
            eprintln!(
                "foreign ownership fixture NOT RUN: running as root; kernel oracle covers ownership"
            );
        }
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("config.toml");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&file, b"[network]\n").unwrap();
        let load = || {
            let read =
                crate::host_paths::read_bounded_regular_file_noting_symlink(&file, 100).unwrap();
            assert_eq!(read.path(), file);
            assert_eq!(read.bytes(), b"[network]\n");
            from_user_tier(&read, &table(""))
        };
        for mode in [0o600, 0o644, 0o664, 0o646] {
            fs::set_permissions(&file, fs::Permissions::from_mode(mode)).unwrap();
            if mode == 0o600 || mode == 0o644 {
                assert!(load().is_ok());
            } else {
                assert!(
                    load()
                        .unwrap_err()
                        .to_string()
                        .contains("group- or other-writable config.toml")
                );
            }
        }
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let alias = root.path().join("alias");
        fs::hard_link(&file, &alias).unwrap();
        assert!(load().unwrap_err().to_string().contains("2 hard links"));
        fs::remove_file(&alias).unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o775)).unwrap();
        assert!(
            load()
                .unwrap_err()
                .to_string()
                .contains("directory is group- or other-writable")
        );
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::rename(&file, &alias).unwrap();
        std::os::unix::fs::symlink(&alias, &file).unwrap();
        assert!(
            load()
                .unwrap_err()
                .to_string()
                .contains("reached through a symbolic link")
        );
    }

    /// The pinned `Display` text of every refusal variant, and whether that
    /// variant can fire on guest- or project-authored bytes (so it must carry
    /// the review caveat).
    ///
    /// The `match` is exhaustive, so adding an `AuthorityRefusal` variant fails
    /// to compile here until its row is added. Pinning the whole string — not a
    /// denylist of removed phrasings — is what makes the test fail on a
    /// paraphrased reintroduction of "make this file trusted" advice, not only a
    /// `git revert`.
    fn pinned_refusal_display(refusal: AuthorityRefusal) -> (String, bool) {
        use AuthorityRefusal::*;
        match refusal {
            DirNotDirectory => ("[network] refuses a config.toml whose directory is not a directory".to_string(), false),
            DirOwner => ("[network] refuses a config.toml whose directory is owned by another user; review the [network] table before trusting the file".to_string(), true),
            DirWritable => ("[network] refuses a config.toml whose directory is group- or other-writable; a guest or another account may be able to replace the file, so review the [network] table before trusting it".to_string(), true),
            ThroughSymlink => ("[network] requires config.toml to be a regular file, but it is reached through a symbolic link; its target may be writable by a guest or project, so review the [network] table before trusting the file (a symlinked config without [network] still works)".to_string(), true),
            FileOwner => ("[network] refuses a config.toml owned by another user; review the [network] table before trusting the file".to_string(), true),
            FileWritable => ("[network] refuses a group- or other-writable config.toml; a guest or another account may have written its [network] table, so review the [network] table before trusting the file (fixing the mode does not establish authorship)".to_string(), true),
            FileLinks(nlink) => (format!("[network] refuses a config.toml with {nlink} hard links; another name for it may be guest- or project-writable, so review the [network] table before trusting the file"), true),
        }
    }

    #[test]
    fn untrusted_refusals_never_advise_adopting_a_guests_file() {
        const REVIEW_CAVEAT: &str = "review the [network] table before trusting";
        use AuthorityRefusal::*;
        // One row per variant; `pinned_refusal_display` is exhaustive, so a new
        // variant is a compile error there and a row must be added here too.
        for refusal in [
            DirNotDirectory,
            DirOwner,
            DirWritable,
            ThroughSymlink,
            FileOwner,
            FileWritable,
            FileLinks(3),
        ] {
            let text = UserNetworkError::Untrusted(refusal).to_string();
            let (pinned, carries_caveat) = pinned_refusal_display(refusal);
            // Exact pin: any reintroduced advice — verbatim or paraphrased —
            // changes the text and fails here.
            assert_eq!(text, pinned, "refusal advice changed for {refusal:?}");
            // The durable positive half: a refusal that can fire on
            // guest-authored bytes must tell the reader to review first.
            if carries_caveat {
                assert!(text.contains(REVIEW_CAVEAT), "{text}");
            } else {
                assert!(!text.contains(REVIEW_CAVEAT), "{text}");
            }
        }
    }

    fn oracle(reached: Reached, dir: DirFacts, euid: u32) -> Option<AuthorityRefusal> {
        use AuthorityRefusal::*;
        if !dir.is_dir {
            return Some(DirNotDirectory);
        }
        if dir.uid != euid {
            return Some(DirOwner);
        }
        if dir.mode & (0o020 | 0o002) != 0 {
            return Some(DirWritable);
        }
        match reached {
            Reached::ThroughSymlink => Some(ThroughSymlink),
            Reached::Direct(f) => {
                if f.uid != euid {
                    Some(FileOwner)
                } else if f.mode & (0o020 | 0o002) != 0 {
                    Some(FileWritable)
                } else if f.nlink == 1 {
                    None
                } else {
                    Some(FileLinks(f.nlink))
                }
            }
        }
    }

    #[test]
    fn refusal_matches_independent_oracle_table() {
        for is_dir in [false, true] {
            for dir_uid in [7, 8] {
                for dir_mode in [0o700, 0o720, 0o702, 0o775] {
                    for file_uid in [7, 8] {
                        for file_mode in [0o600, 0o620, 0o602, 0o664] {
                            for nlink in [0, 1, 2, u64::MAX] {
                                for reached in [
                                    Reached::ThroughSymlink,
                                    Reached::Direct(FileFacts {
                                        uid: file_uid,
                                        mode: file_mode,
                                        nlink,
                                    }),
                                ] {
                                    let dir = DirFacts {
                                        is_dir,
                                        uid: dir_uid,
                                        mode: dir_mode,
                                    };
                                    assert_eq!(
                                        network_authority_refusal(reached, dir, 7),
                                        oracle(reached, dir, 7)
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    proptest! {
        #[test]
        fn refusal_mode_mask_is_exactly_group_and_other_write(mode in any::<u32>()) {
            let writable = mode & 0o020 != 0 || mode & 0o002 != 0;
            let file = Reached::Direct(FileFacts { uid: 7, mode, nlink: 1 });
            let dir = DirFacts { is_dir: true, uid: 7, mode: 0o700 };
            prop_assert_eq!(network_authority_refusal(file, dir, 7),
                if writable { Some(AuthorityRefusal::FileWritable) } else { None });
            let file = Reached::Direct(FileFacts { uid: 7, mode: 0o600, nlink: 1 });
            let dir = DirFacts { mode, ..dir };
            prop_assert_eq!(network_authority_refusal(file, dir, 7),
                if writable { Some(AuthorityRefusal::DirWritable) } else { None });
        }
    }
}
