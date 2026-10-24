//! The config mounts a verified user config selects for every launch.
//!
//! ADR-0046 accepts one top-level `mounts` array in the *user* config. It is a
//! declaration list, not a trust source of its own: the file must first pass
//! ADR-0040's verified-read policy, and [`from_verified_value`] demands the
//! [`AuthorizedConfig`] token that only [`crate::config_authority::verify`] can
//! mint — so a `mounts` list cannot be parsed from an unverified read, and there
//! is no second, laxer path to these declarations.
//!
//! Two rules shape everything here:
//!
//! * **Presence, not contents.** `mounts = []` still makes the file
//!   authority-bearing (that is `config_authority`'s trigger, decided before
//!   this module runs); an empty list simply selects nothing.
//! * **No filesystem access.** Parsing, `~/` expansion, guest normalization and
//!   the intra-config claim are pure. Whether a source exists is a launch-time
//!   question about *selected* mounts only, so a config naming a path that does
//!   not exist still loads (an opt-out launch must not care).
//!
//! Load-time diagnostics name the field and the index and never the value: a
//! `mounts` entry can carry an attacker-chosen path, and the sentence is printed
//! to a user deciding whether to trust the file. A *launch-time* refusal is a
//! different question — it has to name the host or guest path it could not
//! prepare, or the user cannot fix it — so those sentences name the declaration
//! as `mounts[N] in "<file>"` and render the **declared host spelling** with
//! `config`'s escaping (`quoted_str`/`quoted_path`), never raw. That is what keeps
//! a refusal, a fork notice or an error context to one line when a spelling
//! carries a newline: the value is echoed escaped, so a config cannot forge a
//! second diagnostic. (`--mount` keeps its historical unescaped renderings on
//! purpose; they are byte-pinned and a shell's argv is not a trusted-file
//! question. A guest path is escaped-or-refused by the shared grammar, which
//! rejects control characters, and paths taken from the host's own measurement
//! are not config text at all.)

use crate::{
    config_authority::AuthorizedConfig,
    mount::{
        ClaimError, HostSyntax, MountOrigin, MountRequest, MountSpecErrorKind, claim,
        parse_mount_spec,
    },
};
use std::{
    fmt,
    path::{Path, PathBuf},
};

/// One verified user file's `mounts`: the file it came from and its claimed
/// declarations in file order.
///
/// [`Self::requests`] is already normalized and deduplicated (identical
/// declarations at one guest path merged into the first), so a later claim
/// against `--mount` needs no second pass over this list.
#[derive(Clone, Debug)]
pub(crate) struct UserMounts {
    file: PathBuf,
    requests: Vec<MountRequest>,
}

impl UserMounts {
    pub(crate) fn file(&self) -> &Path {
        &self.file
    }

    pub(crate) fn requests(&self) -> &[MountRequest] {
        &self.requests
    }

    /// How many declarations this file selects after intra-file merging — the
    /// number a launch notice reports, not the number of `mounts` entries.
    pub(crate) fn len(&self) -> usize {
        self.requests.len()
    }
}

/// Parse a present `mounts` value from a file that has already been verified.
///
/// `home` is the `$HOME` the user path was discovered from
/// ([`crate::config::ConfigPaths::home`]), never a fresh environment read: a
/// launch must expand `~/` to the same directory whose `config.toml` it read.
/// It is `None` when the host has no UTF-8 home, which only a `~/` entry cares
/// about.
pub(crate) fn from_verified_value(
    authorized: &AuthorizedConfig<'_>,
    value: &toml::Value,
    home: Option<&Path>,
) -> Result<UserMounts, UserMountsError> {
    let file = authorized.file().to_path_buf();
    let entries = value.as_array().ok_or(UserMountsError::NotArray)?;
    let syntax = HostSyntax::AbsoluteOrHome {
        home: home.and_then(Path::to_str),
    };
    let mut requests = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let text = entry.as_str().ok_or(UserMountsError::NotString { index })?;
        let mount = parse_mount_spec(text, syntax).map_err(|error| UserMountsError::Entry {
            index,
            kind: error.kind(),
        })?;
        requests.push(MountRequest {
            origin: MountOrigin::UserConfig {
                file: file.clone(),
                index,
            },
            mount,
        });
    }
    // The claim runs here, with no core paths, so a self-contradictory file is a
    // *load* error rather than a launch-time surprise after host state exists.
    // Core collisions stay launch-time because they depend on the launch's own
    // project/state paths.
    let requests = claim(requests, &[]).map_err(UserMountsError::from_claim)?;
    Ok(UserMounts { file, requests })
}

/// Why a `mounts` value was rejected. Every variant renders without echoing any
/// config text; `config` adds the file name around it.
#[derive(Debug)]
pub(crate) enum UserMountsError {
    NotArray,
    NotString {
        index: usize,
    },
    /// One entry failed the shared `HOST[:GUEST][:MODE]...` grammar.
    Entry {
        index: usize,
        kind: MountSpecErrorKind,
    },
    /// The claim refused a guest spelling (`/`, relative, `..`, `:`).
    GuestNotMountable {
        index: usize,
    },
    /// Unreachable from config load, which passes no core paths — stated rather
    /// than assumed so the sentence stays value-free if it ever fires.
    CoreCollision {
        index: usize,
    },
    /// Two entries claim one guest path and do not agree.
    Conflict {
        index: usize,
        other: usize,
    },
}

impl UserMountsError {
    fn from_claim(error: ClaimError) -> Self {
        match error {
            // The grammar's own sentence names the guest spelling, so only the
            // kind survives to the config route.
            ClaimError::Guest { origin, .. } => Self::GuestNotMountable {
                index: index_of(&origin),
            },
            ClaimError::Core { origin, .. } => Self::CoreCollision {
                index: index_of(&origin),
            },
            ClaimError::Conflict { first, second, .. } => Self::Conflict {
                index: index_of(&second),
                other: index_of(&first),
            },
        }
    }
}

/// The `mounts` index behind a claim error's origin.
///
/// [`from_verified_value`] tags every request `UserConfig`, so this is the index
/// in the file. The `Cli` arm cannot be reached from here; `0` names a real
/// entry, so even then the sentence stays well-formed and value-free instead of
/// panicking on a report path.
fn index_of(origin: &MountOrigin) -> usize {
    match origin {
        MountOrigin::UserConfig { index, .. } => *index,
        MountOrigin::Cli => 0,
    }
}

impl fmt::Display for UserMountsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotArray => f.write_str("mounts: must be an array of strings"),
            Self::NotString { index } => write!(f, "mounts[{index}]: must be a string"),
            Self::Entry { index, kind } => write!(f, "mounts[{index}]: {kind}"),
            Self::GuestNotMountable { index } => write!(
                f,
                "mounts[{index}]: guest path must be absolute, must not be /, and must not \
                 contain `..`, `:`, `;`, `,` or control characters"
            ),
            Self::CoreCollision { index } => write!(
                f,
                "mounts[{index}]: guest path collides with an agent-vm core mount"
            ),
            Self::Conflict { index, other } => write!(
                f,
                "mounts[{index}]: claims the same guest path as mounts[{other}] with a \
                 different declaration"
            ),
        }
    }
}

impl std::error::Error for UserMountsError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_authority::{AuthorityTriggers, verify};
    use crate::host_paths::read_bounded_regular_file_noting_symlink;
    use crate::mount::{MountPolicy, Spelling};
    use std::{fs, os::unix::fs::PermissionsExt};

    const GUEST_NOT_MOUNTABLE: &str = "mounts[0]: guest path must be absolute, must not be /, and \
                                       must not contain `..`, `:`, `;`, `,` or control characters";

    /// A verified read of a throwaway `config.toml`, handed to `f`.
    ///
    /// These tests go through the real token path rather than a forged one:
    /// the point of [`from_verified_value`]'s signature is that no other way to
    /// call it exists, and a test able to bypass it would not be testing that.
    fn with_authorized<T>(f: impl FnOnce(&AuthorizedConfig<'_>, &Path) -> T) -> T {
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
        .expect("a mounts-bearing file is authority-bearing");
        f(&authorized, &file)
    }

    /// The `mounts` value of a one-line document, so each row reads as TOML.
    fn value(text: &str) -> toml::Value {
        format!("mounts = {text}\n")
            .parse::<toml::Table>()
            .unwrap()
            .remove("mounts")
            .unwrap()
    }

    fn parse(text: &str, home: Option<&Path>) -> Result<UserMounts, UserMountsError> {
        with_authorized(|authorized, _| from_verified_value(authorized, &value(text), home))
    }

    fn sources(mounts: &UserMounts) -> Vec<Spelling> {
        mounts
            .requests()
            .iter()
            .map(|request| request.mount.source_spelling.clone())
            .collect()
    }

    fn guests(mounts: &UserMounts) -> Vec<String> {
        mounts
            .requests()
            .iter()
            .map(|request| request.mount.guest.display().to_string())
            .collect()
    }

    fn rendered(result: Result<UserMounts, UserMountsError>) -> String {
        result.unwrap_err().to_string()
    }

    /// ADR-0046 Decision 3's spelling table: `~/` is plain concatenation onto
    /// the captured home, `//` is preserved, nothing else is expanded, and every
    /// other relative spelling is refused. The oracle is `starts_with` plus
    /// `format!`, not the kernel's own predicate.
    #[test]
    fn home_expansion_cases() {
        let plain = Path::new("/h");
        let trailing = Path::new("/h/");
        for (text, home, expected) in [
            // Absolute hosts pass through byte-for-byte: no variable expansion.
            (r#"["/abs/ref"]"#, Some(plain), "/abs/ref"),
            (r#"["/abs/$HOME/x"]"#, Some(plain), "/abs/$HOME/x"),
            // `~/` expands by concatenation; a trailing-slash HOME keeps `//`.
            (r#"["~/ref"]"#, Some(plain), "/h/ref"),
            (r#"["~/ref"]"#, Some(trailing), "/h//ref"),
            (r#"["~//ref"]"#, Some(plain), "/h//ref"),
            (r#"["~/ref/"]"#, Some(plain), "/h/ref/"),
            // Surrounding whitespace is the shared grammar's to trim.
            (r#"["  ~/ref  "]"#, Some(plain), "/h/ref"),
        ] {
            assert_eq!(
                sources(&parse(text, home).expect("row parses")),
                [expected],
                "{text}"
            );
        }
        let refused = "mounts[0]: host path must be absolute or start with ~/ (environment \
                       variables and other relative paths are not expanded)";
        for text in [
            r#"["~"]"#,
            r#"["~user/ref"]"#,
            r#"["$HOME/ref"]"#,
            r#"["${HOME}/ref"]"#,
            r#"["./ref"]"#,
            r#"["ref"]"#,
        ] {
            assert_eq!(rendered(parse(text, Some(plain))), refused, "{text}");
        }
        // No UTF-8 home rejects only the `~/` spellings.
        assert_eq!(
            rendered(parse(r#"["~/ref"]"#, None)),
            "mounts[0]: a ~/ host path needs a UTF-8 $HOME"
        );
        assert_eq!(
            sources(&parse(r#"["/abs/ref"]"#, None).unwrap()),
            ["/abs/ref"]
        );
        // A non-UTF-8 home is unusable for `~/` and irrelevant to an absolute
        // host: the capture is a path, the grammar takes `&str`.
        use std::os::unix::ffi::OsStrExt;
        let non_utf8 = Path::new(std::ffi::OsStr::from_bytes(b"/h/\xff"));
        assert_eq!(
            rendered(parse(r#"["~/ref"]"#, Some(non_utf8))),
            "mounts[0]: a ~/ host path needs a UTF-8 $HOME"
        );
        assert_eq!(
            sources(&parse(r#"["/abs/ref"]"#, Some(non_utf8)).unwrap()),
            ["/abs/ref"]
        );
    }

    /// The mirror guest is the *expanded* host — the spelling fork identity
    /// depends on — and argv never expands `~`.
    #[test]
    fn a_mirror_guest_is_the_expanded_host() {
        let mounts = parse(r#"["~/ref/"]"#, Some(Path::new("/h"))).unwrap();
        assert_eq!(guests(&mounts), ["/h/ref"]);
        assert_eq!(sources(&mounts), ["/h/ref/"]);
        assert_eq!(
            parse_mount_spec("~/ref", HostSyntax::AbsoluteOnly)
                .unwrap_err()
                .kind(),
            MountSpecErrorKind::HostNotAccepted
        );
    }

    /// Guest rules are the `--mount` rules, with the grammar's sentences
    /// rendered without the spelling.
    #[test]
    fn guest_rules_match_the_cli() {
        let home = Some(Path::new("/h"));
        for (text, expected) in [
            (
                r#"["/abs:./rel"]"#,
                "mounts[0]: guest path must be absolute",
            ),
            (
                r#"["/abs:rel"]"#,
                "mounts[0]: unknown mode keyword (expected ro, rw, fork, follow-links, or \
                 exclude=REL)",
            ),
            (r#"["/abs:/"]"#, GUEST_NOT_MOUNTABLE),
            (r#"["/abs:/a/../b"]"#, GUEST_NOT_MOUNTABLE),
        ] {
            assert_eq!(rendered(parse(text, home)), expected, "{text:?}");
        }
        // A control character in the guest cannot cross the boot-params frame,
        // so the grammar refuses it before the claim sees the declaration.
        assert_eq!(
            rendered(parse("[\"/abs:/a\tb\"]", home)),
            "mounts[0]: guest path contains control characters that can't be carried into the guest"
        );
        // The same `:ro`/`:rw` grammar, and a normalized guest reaches the claim.
        let mounts = parse(r#"["/abs:/g//./x:ro"]"#, None).unwrap();
        assert_eq!(guests(&mounts), ["/g/x"]);
        assert!(matches!(
            mounts.requests()[0].mount.policy,
            MountPolicy::BindReadOnly { .. }
        ));
        assert!(matches!(
            parse(r#"["/abs:/g:rw"]"#, None).unwrap().requests()[0]
                .mount
                .policy,
            MountPolicy::BindReadWrite
        ));
    }

    /// Every rejection names `mounts` and the index, and never echoes the value.
    #[test]
    fn errors_are_value_free_and_index_named() {
        const SENTINEL: &str = "s3cr3t-SENTINEL";
        let home = Some(Path::new("/h"));
        for (text, expected) in [
            (
                r#"["/abs:ro:rw"]"#,
                "mounts[0]: conflicting modes `ro` and `rw`",
            ),
            (
                r#"["/abs:exclude=hidden"]"#,
                "mounts[0]: :exclude is only supported on :fork mounts",
            ),
            (
                r#"["/abs:fork:exclude="]"#,
                "mounts[0]: exclude must be a non-empty relative path of normal components",
            ),
            (
                r#"["/abs::ro"]"#,
                "mounts[0]: empty segment (stray `:`); expected HOST[:GUEST][:MODE]...",
            ),
            (
                r#"[""]"#,
                "mounts[0]: mount declaration must be HOST[:GUEST][:MODE]... (non-empty)",
            ),
            (
                r#"[":/g"]"#,
                "mounts[0]: mount declaration must be HOST[:GUEST][:MODE]... (non-empty)",
            ),
            (r#"["/a", 7]"#, "mounts[1]: must be a string"),
            (r#"["/a", ["/b"]]"#, "mounts[1]: must be a string"),
            (r#""/a""#, "mounts: must be an array of strings"),
            (r#"["/a", "/b:/g", "/c:/g:fork"]"#, CONFLICT),
        ] {
            assert_eq!(rendered(parse(text, home)), expected, "{text}");
        }
        // The sentinel sits in the invalid position of an otherwise valid
        // declaration, so any echo would put it in the sentence.
        for text in [
            format!(r#"["{SENTINEL}"]"#),
            format!(r#"["/a:{SENTINEL}"]"#),
            format!(r#"["/a:/g:{SENTINEL}"]"#),
            format!(r#"["/a:/g:exclude={SENTINEL}/../x"]"#),
            format!(r#"["/a", "{SENTINEL}"]"#),
            format!(r#"[1, "{SENTINEL}"]"#),
            format!(r#"["/a", {{ {SENTINEL} = 1 }}]"#),
        ] {
            let error = rendered(parse(&text, home));
            assert!(!error.contains(SENTINEL), "{text} echoed a value: {error}");
            assert!(
                error.starts_with("mounts:") || error.starts_with("mounts["),
                "{text}: {error}"
            );
        }
        assert_eq!(
            rendered(parse(&format!(r#"{{ "{SENTINEL}" = 1 }}"#), home)),
            "mounts: must be an array of strings"
        );
    }

    const CONFLICT: &str =
        "mounts[2]: claims the same guest path as mounts[1] with a different declaration";

    /// Identical declarations merge into one request; differing ones at one
    /// guest path are a load error naming both indices.
    #[test]
    fn intra_config_claims_merge_and_conflict() {
        let mounts = parse(r#"["/a:/g:ro", "/a:/g//./:ro"]"#, None).unwrap();
        assert_eq!(mounts.len(), 1);
        assert_eq!(guests(&mounts), ["/g"]);
        // Distinct guest paths keep file order.
        let mounts = parse(r#"["/a:/a", "/b:/b", "/c:/c:fork"]"#, None).unwrap();
        assert_eq!(guests(&mounts), ["/a", "/b", "/c"]);
        assert_eq!(
            rendered(parse(r#"["/a:/g:ro", "/b:/g:ro"]"#, None)),
            "mounts[1]: claims the same guest path as mounts[0] with a different declaration"
        );
        // A host *spelling* difference is a difference, exactly as between two
        // `--mount`s: `~/ref` and `~/ref/` are one guest path, two declarations.
        assert_eq!(
            rendered(parse(r#"["~/ref:/g", "~/ref/:/g"]"#, Some(Path::new("/h")))),
            "mounts[1]: claims the same guest path as mounts[0] with a different declaration"
        );
        // Parent/child guest paths are distinct claims, not a conflict.
        assert_eq!(
            guests(&parse(r#"["/p:/p", "/p/c:/p/c"]"#, None).unwrap()),
            ["/p", "/p/c"]
        );
    }

    /// Load is pure: a source that does not exist still parses, because whether
    /// it exists is a launch-time question about *selected* mounts only.
    #[test]
    fn parsing_never_touches_the_filesystem() {
        let missing = "/nonexistent-agent-vm-config-mounts-probe";
        assert!(!Path::new(missing).exists());
        let mounts = parse(
            &format!(r#"["{missing}:ro", "{missing}/nested:fork"]"#),
            None,
        )
        .unwrap();
        assert_eq!(mounts.len(), 2);
        assert_eq!(
            sources(&mounts),
            [missing.to_string(), format!("{missing}/nested")]
        );
    }

    /// The record carries the verified file, because a launch-time conflict
    /// names both origins.
    #[test]
    fn the_file_is_the_verified_one() {
        with_authorized(|authorized, file| {
            let mounts = from_verified_value(authorized, &value(r#"["/a"]"#), None).unwrap();
            assert_eq!(mounts.file(), file);
            assert_eq!(
                mounts.requests()[0].origin.to_string(),
                format!("mounts[0] in {file:?}")
            );
        });
    }
}
