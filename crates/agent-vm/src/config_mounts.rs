//! The config mounts a verified user config selects, and the named mount sets it
//! may declare.
//!
//! ADR-0046 accepts one top-level `mounts` array in the *user* config; ADR-0048
//! adds a `[mount_sets]` table whose entries may be selected by name from that
//! array and from `--mount`. Neither is a trust source of its own: the file must
//! first pass ADR-0040's verified-read policy, and [`from_verified_value`]
//! demands the [`AuthorizedConfig`] token that only
//! [`crate::config_authority::verify`] can mint — so no mount declaration can be
//! parsed from an unverified read, and there is no second, laxer path to these
//! declarations.
//!
//! Four rules shape everything here:
//!
//! * **Presence, not contents.** `mounts = []` and `[mount_sets]` (even an empty
//!   table, even an empty set) still make the file authority-bearing; that is
//!   `config_authority`'s trigger, decided before this module runs. An empty list
//!   or table simply selects nothing.
//! * **Declarations are inert.** A definition mounts nothing. Only the defaults
//!   list, or an explicit `--mount NAME`, selects filesystem access.
//! * **The whole graph is validated at load.** Every declared set's transitive
//!   closure is resolved and checked — unknown names, set-reference cycles and a
//!   closure that claims one guest path twice with differing declarations are
//!   config errors even in an unused set and under `--no-config-mounts`. That is
//!   the same rule that already made a self-contradictory `mounts` list a load
//!   error; `config_mounts::sets` owns the graph and bounds its cost.
//! * **No source access.** Parsing, `~/` expansion, guest normalization and the
//!   closure claims read no mount source: nothing in this module opens, stats or
//!   canonicalizes a declared path. Whether a source exists is a launch-time
//!   question about *selected* mounts only, so a config naming a path that does
//!   not exist — or one that cannot be reached — still loads (an opt-out launch
//!   must not care). That is also why an unused set's absent source cannot block
//!   an unrelated tool.
//!
//! Load-time diagnostics name the field and the numeric position and never the
//! value: a `mounts` entry or `mount_sets` key can carry attacker-chosen text,
//! and the sentence is printed to a user deciding whether to trust the file.
//! Set-entry sites are `mount_sets[DEFINITION][INDEX]` with both numbers, so even
//! an invalid *key* is named without echoing it. A *launch-time* refusal is a
//! different question — it has to name the host or guest path it could not
//! prepare, or the user cannot fix it — so those sentences name the declaration
//! as `mounts[N] in "<file>"` or `mount_sets["NAME"][I] in "<file>"` and render
//! the **declared host spelling** with `config`'s escaping
//! (`quoted_str`/`quoted_path`), never raw. That is what keeps a refusal, a fork
//! notice or an error context to one line when a spelling carries a newline: the
//! value is echoed escaped, so a config cannot forge a second diagnostic.
//! (`--mount` keeps its historical unescaped renderings on purpose; they are
//! byte-pinned and a shell's argv is not a trusted-file question. A guest path is
//! escaped-or-refused by the shared grammar, which rejects control characters,
//! and paths taken from the host's own measurement are not config text at all.)

mod sets;

pub(crate) use sets::UserMounts;

use crate::{
    config_authority::AuthorizedConfig,
    mount::{ExtraMount, HostSyntax, MountSpecError, MountSpecErrorKind, parse_mount_spec},
};
use std::{fmt, path::Path};
use vstd::prelude::*;

verus! {
/// Bytes an accepted mount-set name may start with: ASCII letter, digit or `_`.
///
/// Deliberately **not** `ToolName`'s alphabet: a leading `-` would read as a flag
/// to an outer script, `/` and `:` would make a name look like a path or a
/// modifier, and reserving launch-verb words would forbid `--mount pi` selecting
/// the set a user named `pi`.
pub open spec fn mount_set_name_first_byte_ok(byte: u8) -> bool {
    (b'a' <= byte && byte <= b'z')
        || (b'A' <= byte && byte <= b'Z')
        || (b'0' <= byte && byte <= b'9')
        || byte == b'_'
}

/// Bytes an accepted mount-set name may contain after its first byte: the same
/// alphabet plus `.` and `-`.
pub open spec fn mount_set_name_byte_ok(byte: u8) -> bool {
    mount_set_name_first_byte_ok(byte) || byte == b'.' || byte == b'-'
}

/// The whole name decision (decision A1): accepted iff the bytes are nonempty,
/// the first byte is `[A-Za-z0-9_]`, and every remaining byte is
/// `[A-Za-z0-9_.-]`.
///
/// "Not all dots" needs no clause of its own: `.`, `..` and any all-dot sequence
/// fail at byte zero. Case is significant and there is no folding, so `A` and `a`
/// are two names. Every non-ASCII byte, being outside all three ranges, fails —
/// so a Unicode name is rejected at its first non-ASCII byte rather than folded
/// into an ASCII one.
pub open spec fn mount_set_name_spec(bytes: Seq<u8>) -> bool {
    bytes.len() >= 1
        && mount_set_name_first_byte_ok(bytes[0])
        && forall|i: int| 1 <= i < bytes.len() ==> mount_set_name_byte_ok(bytes[i])
}

// The `<=` spelling (rather than clippy's suggested `(b'a'..=b'z').contains`) is
// kept so the exec bytes stay syntactically the predicate the `verus!` spec fn
// unfolds to — the same allow and the same reason as
// `secret_store::service_name_is_valid_bytes`.
#[allow(clippy::manual_range_contains)]
pub fn mount_set_name_bytes(bytes: &[u8]) -> (r: bool)
    ensures r == mount_set_name_spec(bytes@),
{
    let len = bytes.len();
    if len == 0 {
        return false;
    }
    let first = bytes[0];
    if !((b'a' <= first && first <= b'z')
        || (b'A' <= first && first <= b'Z')
        || (b'0' <= first && first <= b'9')
        || first == b'_')
    {
        return false;
    }
    let mut i: usize = 1;
    while i < len
        invariant
            i <= len,
            len == bytes@.len(),
            len >= 1,
            mount_set_name_first_byte_ok(bytes@[0]),
            forall|j: int| 1 <= j < i ==> mount_set_name_byte_ok(bytes@[j]),
        decreases len - i,
    {
        let byte = bytes[i];
        if !((b'a' <= byte && byte <= b'z')
            || (b'A' <= byte && byte <= b'Z')
            || (b'0' <= byte && byte <= b'9')
            || byte == b'_'
            || byte == b'.'
            || byte == b'-')
        {
            return false;
        }
        i += 1;
    }
    true
}
} // verus!

/// One user-declared mount-set name, in its exact spelling.
///
/// The only constructor is [`MountSetName::parse`], so a name that reached a
/// lookup, a diagnostic or [`crate::mount::MountOrigin::UserSet`] has passed
/// decision A1. Case is preserved: `A` and `a` are different sets.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct MountSetName(String);

impl MountSetName {
    /// Decision A1 over one key or selector host segment. No trimming, folding or
    /// other normalization: a definition key with surrounding spaces is invalid
    /// rather than silently a different name.
    pub(crate) fn parse(raw: &str) -> Result<Self, InvalidMountSetName> {
        if !mount_set_name_bytes(raw.as_bytes()) {
            return Err(InvalidMountSetName);
        }
        Ok(Self(raw.to_owned()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// A name that failed decision A1. Carries no bytes: the caller's sentence names
/// the numeric site instead of the rejected text.
#[derive(Debug)]
pub(crate) struct InvalidMountSetName;

impl fmt::Display for InvalidMountSetName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "a mount-set name is one or more ASCII characters: [A-Za-z0-9_] first, then \
             [A-Za-z0-9_.-]",
        )
    }
}

/// Where one defaults entry or one set entry sits in the file.
///
/// Two variants, not an index plus a flag, so a defaults site can never print a
/// set's coordinates. Load-time sites are numeric on purpose: a `mount_sets` key
/// is attacker-chosen text, so an invalid key is named by its sorted position and
/// a valid one by the same number rather than by its own bytes. A *launch-time*
/// refusal renders [`crate::mount::MountOrigin::UserSet`] instead, where the name
/// is escaped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EntrySite {
    /// Entry `index` of the top-level `mounts` array.
    Defaults { index: usize },
    /// Entry `index` of the `definition`th `[mount_sets]` definition, ordered by
    /// name so the number does not depend on TOML's key order.
    SetEntry { definition: usize, index: usize },
}

impl fmt::Display for EntrySite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Defaults { index } => write!(f, "mounts[{index}]"),
            Self::SetEntry { definition, index } => {
                write!(f, "mount_sets[{definition}][{index}]")
            }
        }
    }
}

/// The set table and the defaults list from one already-verified read.
///
/// A named bundle rather than two positional arguments: both are untyped
/// `toml::Value`s at this seam (presence has already decided authority, and the
/// shape is decided here), so the callee cannot tell them apart by type.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MountValues<'a> {
    pub(crate) defaults: Option<&'a toml::Value>,
    pub(crate) sets: Option<&'a toml::Value>,
}

/// One entry of a defaults list or a set definition, once its name is bound.
pub(crate) enum MountSelector {
    /// An ordinary `HOST[:GUEST][:MODE]...` declaration.
    Direct(ExtraMount),
    /// A reference to the user-defined set of this name. Selected only when this
    /// entry is; the definition itself mounts nothing.
    Set(MountSetName),
}

/// Why one entry was not a usable selector.
///
/// A direct path keeps the whole [`MountSpecError`], because the two consumers
/// need different halves of it: `--mount` prints its historical byte-pinned
/// chain, and config load prints the value-free
/// [`MountSpecErrorKind`].
#[derive(Debug)]
pub(crate) enum SelectorError {
    Direct(MountSpecError),
    /// A valid set name followed by `:` — `agent:ro`, `agent:fork`,
    /// `agent:/guest`. Modes, guest paths and exclusions belong to the path
    /// declarations *inside* a set, so this is refused rather than reinterpreted.
    SetModifier,
}

impl SelectorError {
    /// The `--mount` rendering. A historic grammar refusal keeps its exact bytes;
    /// the set-reference refusal is new text, so it can only add.
    pub(crate) fn into_cli(self, entry: &str) -> anyhow::Error {
        match self {
            Self::Direct(error) => error.into_cli(),
            Self::SetModifier => anyhow::anyhow!(
                "--mount value {entry:?}: a mount-set name is a bare name; modes, a guest path \
                 or exclusions belong to the paths declared inside the set"
            ),
        }
    }
}

verus! {
/// The three measured facts the selector classification needs.
///
/// Named fields rather than three adjacent booleans: two of them (`path` and
/// `name`) are both "this host segment looks like something we know", and a call
/// site that transposed them would turn a set lookup into a path lookup.
#[derive(Clone, Copy, Debug)]
pub struct SelectorFacts {
    /// The trimmed host segment starts with `/` or `~/`.
    pub path_spelling: bool,
    /// The trimmed host segment satisfies decision A1.
    pub name_spelling: bool,
    /// The entry has at least one `:` after the host segment.
    pub has_modifier: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub enum SelectorKind { Path, Set, ModifiedName, Other }

/// ADR-0018 kernel: which grammar one entry belongs to.
///
/// Total over the three facts, with path spelling taking precedence, so an
/// absolute (or `~/`) host can never be reclassified as a set name — the
/// compatibility rule that keeps every working `--mount /abs:...` a path. A valid
/// bare name is a set; the same name with a `:` is a refused modifier, whichever
/// name it is; anything else goes to the direct parser, which refuses relative
/// host spellings itself.
pub fn selector_kind(f: SelectorFacts) -> (k: SelectorKind)
    ensures
        f.path_spelling ==> k == SelectorKind::Path,
        (!f.path_spelling && f.name_spelling && !f.has_modifier) ==> k == SelectorKind::Set,
        (!f.path_spelling && f.name_spelling && f.has_modifier) ==> k == SelectorKind::ModifiedName,
        (!f.path_spelling && !f.name_spelling) ==> k == SelectorKind::Other,
{
    if f.path_spelling {
        SelectorKind::Path
    } else if f.name_spelling {
        if f.has_modifier { SelectorKind::ModifiedName } else { SelectorKind::Set }
    } else {
        SelectorKind::Other
    }
}
} // verus!

/// Classify and parse one entry of the defaults list, of a set definition, or of
/// `--mount`. One function for all three, so CLI and config cannot disagree about
/// what a name is (ADR-0048).
///
/// `syntax` is the caller's grammar: `--mount` refuses a literal `~/`, config
/// expands it against the captured host home. The classification measures the
/// **trimmed** host segment, exactly as the shared parser does, but the original
/// full text is what reaches that parser, so no spelling is rebuilt.
pub(crate) fn parse_selector(
    text: &str,
    syntax: HostSyntax<'_>,
) -> Result<MountSelector, SelectorError> {
    let host = text.split(':').next().unwrap_or_default().trim();
    let name = MountSetName::parse(host).ok();
    let kind = selector_kind(SelectorFacts {
        path_spelling: host.starts_with('/') || host.starts_with("~/"),
        name_spelling: name.is_some(),
        has_modifier: text.contains(':'),
    });
    match kind {
        SelectorKind::Set => match name {
            Some(name) => Ok(MountSelector::Set(name)),
            // Unreachable: the kernel only says `Set` for a measured name.
            // Falling through to the path grammar keeps a wrong kernel
            // fail-closed instead of accepting text nothing validated.
            None => parse_direct(text, syntax),
        },
        SelectorKind::ModifiedName => Err(SelectorError::SetModifier),
        SelectorKind::Path | SelectorKind::Other => parse_direct(text, syntax),
    }
}

fn parse_direct(text: &str, syntax: HostSyntax<'_>) -> Result<MountSelector, SelectorError> {
    parse_mount_spec(text, syntax)
        .map(MountSelector::Direct)
        .map_err(SelectorError::Direct)
}

/// Parse both present mount fields of a file that has already been verified.
///
/// `home` is the `$HOME` the user path was discovered from
/// ([`crate::config::ConfigPaths::home`]), never a fresh environment read: a
/// launch must expand `~/` to the same directory whose `config.toml` it read.
/// It is `None` when the host has no UTF-8 home, which only a `~/` entry cares
/// about.
pub(crate) fn from_verified_value(
    authorized: &AuthorizedConfig<'_>,
    values: MountValues<'_>,
    home: Option<&Path>,
) -> Result<UserMounts, UserMountsError> {
    UserMounts::parse(authorized.file().to_path_buf(), values, host_syntax(home))
}

/// [`from_verified_value`], also reporting the leaf visits it admitted — even when
/// it refuses, where the counter is otherwise observable only as the refusal.
///
/// Test-only, and it still demands the token: the budget's behaviour is a
/// property of the authorized path, so a test must not be able to measure a
/// construction no launch could reach.
#[cfg(test)]
pub(crate) fn from_verified_value_with_work(
    authorized: &AuthorizedConfig<'_>,
    values: MountValues<'_>,
    home: Option<&Path>,
) -> (Result<UserMounts, UserMountsError>, usize) {
    UserMounts::parse_with_work(authorized.file().to_path_buf(), values, host_syntax(home))
}

/// The host grammar one verified file's entries are parsed with: `~/` expands
/// against the `$HOME` its path was discovered from, never a fresh environment
/// read, and `None` means the host has no UTF-8 home.
fn host_syntax(home: Option<&Path>) -> HostSyntax<'_> {
    HostSyntax::AbsoluteOrHome {
        home: home.and_then(Path::to_str),
    }
}

/// Why a `mounts` list or a `[mount_sets]` table was rejected. Every variant
/// renders without echoing any config text; `config` adds the file name around it.
#[derive(Debug)]
pub(crate) enum UserMountsError {
    /// `mounts` was present but not an array.
    NotArray,
    /// One `mounts` entry was not a string.
    NotString { index: usize },
    /// One entry failed the shared `HOST[:GUEST][:MODE]...` grammar.
    Entry {
        site: EntrySite,
        kind: MountSpecErrorKind,
    },
    /// The claim refused a guest spelling (`/`, relative, `..`, `:`).
    GuestNotMountable { site: EntrySite },
    /// Unreachable from config load, which passes no core paths — stated rather
    /// than assumed so the sentence stays value-free if it ever fires.
    CoreCollision { site: EntrySite },
    /// Two entries claim one guest path and do not agree. At config load both
    /// sites are in this file; at launch the same kernel reports origins.
    Conflict { site: EntrySite, other: EntrySite },
    /// `mount_sets` was present but not a table.
    SetsNotTable,
    /// The `definition`th `[mount_sets]` key is not a valid name.
    SetName { definition: usize },
    /// The `definition`th set's value is not an array of strings.
    SetNotArray { definition: usize },
    /// One entry of the `definition`th set is not a string.
    SetNotString { definition: usize, index: usize },
    /// A set name was written with a `:` — modes, a guest path or an exclusion.
    SetReferenceModified { site: EntrySite },
    /// A reference names no declared set. Never a path lookup fallback.
    UnknownSet { site: EntrySite },
    /// A set reference cycle. `tools` cycles stay legal; this is the mount half.
    Cycle { site: EntrySite },
    /// The admitted leaf-visit budget for validating every declared closure is
    /// exhausted. A value-free resource refusal, not a conflict or source error.
    ExpansionWorkLimit,
    /// Unreachable: a dependency's closure was not compiled before its
    /// dependent's. Refused rather than skipped, so a wrong traversal order can
    /// never silently drop a set from validation.
    ReferenceOrder,
}

impl UserMountsError {
    /// Map a claim failure about one entry of this file onto the entry's site.
    fn from_claim(error: crate::mount::ClaimError, site: &EntrySite) -> Self {
        match error {
            // The grammar's own sentence names the guest spelling, so only the
            // kind survives to the config route.
            crate::mount::ClaimError::Guest { .. } => {
                Self::GuestNotMountable { site: site.clone() }
            }
            crate::mount::ClaimError::Core { .. } => Self::CoreCollision { site: site.clone() },
            // A single-entry claim cannot conflict with anything.
            crate::mount::ClaimError::Conflict { .. } => Self::Conflict {
                site: site.clone(),
                other: site.clone(),
            },
        }
    }
}

impl fmt::Display for UserMountsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotArray => f.write_str("mounts: must be an array of strings"),
            Self::NotString { index } => write!(f, "mounts[{index}]: must be a string"),
            Self::Entry { site, kind } => write!(f, "{site}: {kind}"),
            Self::GuestNotMountable { site } => write!(
                f,
                "{site}: guest path must be absolute, must not be /, and must not contain `..`, \
                 `:`, `;`, `,` or control characters"
            ),
            Self::CoreCollision { site } => {
                write!(f, "{site}: guest path collides with an agent-vm core mount")
            }
            Self::Conflict { site, other } => write!(
                f,
                "{site}: claims the same guest path as {other} with a different declaration"
            ),
            Self::SetsNotTable => {
                f.write_str("mount_sets: must be a table of named arrays of mount declarations")
            }
            // One statement of the name grammar: [`InvalidMountSetName`] owns the
            // sentence, so the key-level refusal cannot drift from the parse.
            Self::SetName { definition } => write!(
                f,
                "mount_sets: definition {definition} has an invalid name; {InvalidMountSetName}"
            ),
            Self::SetNotArray { definition } => write!(
                f,
                "mount_sets[{definition}]: must be an array of mount declarations or set names"
            ),
            Self::SetNotString { definition, index } => {
                write!(f, "mount_sets[{definition}][{index}]: must be a string")
            }
            Self::SetReferenceModified { site } => write!(
                f,
                "{site}: a mount-set reference is a bare name; modes, a guest path and exclusions \
                 belong to the paths declared inside the set"
            ),
            Self::UnknownSet { site } => write!(f, "{site}: unknown mount set name"),
            Self::Cycle { site } => write!(f, "{site}: mount-set reference cycle"),
            Self::ExpansionWorkLimit => write!(
                f,
                "mount_sets: expansion work exceeds limit of {} leaf visits",
                sets::MAX_MOUNT_SET_EXPANSION_WORK
            ),
            Self::ReferenceOrder => {
                f.write_str("mount_sets: internal reference order was not resolved (agent-vm bug)")
            }
        }
    }
}

impl std::error::Error for UserMountsError {}

#[cfg(test)]
mod tests {
    // The graph's tests are `sets::tests`, a sibling module: the filter that runs
    // both is `config_mounts::`, *not* `config_mounts::tests`, which matches this
    // module only.
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
                mount_sets: false,
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
        with_authorized(|authorized, _| {
            from_verified_value(
                authorized,
                MountValues {
                    defaults: Some(&value(text)),
                    sets: None,
                },
                home,
            )
        })
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
    ///
    /// `["ref"]` is deliberately **not** in the refusal table (decision R3): a
    /// valid bare name is now a set reference, so it has its own row in
    /// `reclassified_bare_default_is_unknown_reference`.
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
            r#"["."]"#,
            r#"[".."]"#,
            r#"["..."]"#,
            r#"["../ref"]"#,
        ] {
            assert_eq!(rendered(parse(text, Some(plain))), refused, "{text}");
        }
        // The index is part of the sentence, not a fixed `[0]`.
        assert_eq!(
            rendered(parse(r#"["/abs", "./rel"]"#, Some(plain))),
            refused.replace("mounts[0]", "mounts[1]")
        );
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
            format!(r#"["./{SENTINEL}"]"#),
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
            let mounts = from_verified_value(
                authorized,
                MountValues {
                    defaults: Some(&value(r#"["/a"]"#)),
                    sets: None,
                },
                None,
            )
            .unwrap();
            assert_eq!(mounts.file(), file);
            assert_eq!(
                mounts.requests()[0].origin.to_string(),
                format!("mounts[0] in {file:?}")
            );
        });
    }
}
