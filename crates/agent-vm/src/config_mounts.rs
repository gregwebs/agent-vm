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
//! * **Presence, not contents.** `mounts = []`, a full `[[tools]]`'s
//!   `mounts = []` and `[mount_sets]` (even an empty table, even an empty set)
//!   still make the file authority-bearing; that is `config_authority`'s
//!   trigger, decided before this module runs. An empty list or table simply
//!   selects nothing.
//! * **Declarations are inert.** A definition mounts nothing. Only the defaults
//!   list, a *selected* tool's own list (plus the lists its transitive
//!   same-file `tools` closure declares) and an explicit `--mount NAME` select
//!   filesystem access. A tool list is therefore a selection source only for a
//!   launch of that tool; a `[mount_sets]` definition is never one.
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
//! an invalid *key* is named without echoing it, and a tool list is
//! `tools[DECLARATION].mounts[INDEX]` — never the tool's name, which is not yet
//! validated when presence is decided. The one word a sentence may name is a
//! *fixed vocabulary*, never the file: a `[mount_sets]` key equal to one of the
//! config's top-level field names is refused by that name, because it is a
//! TOML-scoping mistake rather than a set, and [`crate::config::top_level_field`]
//! can only ever return those five spellings. A *launch-time* refusal is a
//! different question — it has to name the host or guest path it could not
//! prepare, or the user cannot fix it — so those sentences name the declaration
//! as `mounts[N] in "<file>"`, `tools[N].mounts[I] in "<file>"` or
//! `mount_sets["NAME"][I] in "<file>"` and render
//! the **declared host spelling** with `config`'s escaping
//! (`quoted_str`/`quoted_path`), never raw. That is what keeps a refusal, a fork
//! notice or an error context to one line when a spelling carries a newline: the
//! value is echoed escaped, so a config cannot forge a second diagnostic.
//! (`--mount` keeps its historical unescaped renderings on purpose; they are
//! byte-pinned and a shell's argv is not a trusted-file question. A guest path is
//! escaped-or-refused by the shared grammar, which rejects control characters,
//! and paths taken from the host's own measurement are not config text at all.)

mod sets;

#[cfg(test)]
pub(crate) use sets::MAX_MOUNT_SET_EXPANSION_WORK;
pub(crate) use sets::{MountExpansionWork, UserMounts, merge_tool_mounts};

use crate::{
    config_authority::AuthorizedConfig,
    mount::{
        ExtraMount, HostSyntax, MountRequest, MountSpecError, MountSpecErrorKind, parse_mount_spec,
        same_declaration,
    },
};
use std::{fmt, path::Path, sync::Arc};
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

/// Where one entry sits in the file.
///
/// Three variants, not an index plus a flag, so a defaults site can never print a
/// set's coordinates or a tool's. Load-time sites are numeric on purpose: a
/// `mount_sets` key is attacker-chosen text, so an invalid key is named by its
/// sorted position and a valid one by the same number rather than by its own
/// bytes, and a tool's own name is not yet validated when presence decided
/// authority. A *launch-time* refusal renders the equivalent [`crate::mount::MountOrigin`]
/// instead, where the set name is escaped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EntrySite {
    /// Entry `index` of the top-level `mounts` array.
    Defaults { index: usize },
    /// Entry `index` of the `definition`th `[mount_sets]` definition, ordered by
    /// name so the number does not depend on TOML's key order.
    SetEntry { definition: usize, index: usize },
    /// Entry `index` of declaration `declaration`'s own `mounts` list. The tool
    /// name is deliberately absent: this site is built before `validate_tools`
    /// runs, and a numeric file/field pointer cannot echo a malicious name.
    ToolEntry { declaration: usize, index: usize },
}

impl fmt::Display for EntrySite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Defaults { index } => write!(f, "mounts[{index}]"),
            Self::SetEntry { definition, index } => {
                write!(f, "mount_sets[{definition}][{index}]")
            }
            Self::ToolEntry { declaration, index } => {
                write!(f, "tools[{declaration}].mounts[{index}]")
            }
        }
    }
}

/// One declaration once it is bound to the site that declared it.
///
/// A shared handle, not a copied payload: a tool list may select a large set, and
/// many catalog entries may inherit the same leaves, so every cached list, every
/// entry's facet and every clone of the model share these allocations rather than
/// multiplying the request bytes by their occurrence count. The site travels with
/// the request so a conflict can name both declarations without a parallel
/// provenance cache.
#[derive(Debug)]
pub(crate) struct ConfigMountLeaf {
    pub(crate) request: MountRequest,
    pub(crate) site: EntrySite,
}

/// An ordered, deduplicated list of declarations: one selected list, or the
/// union folded over one launch's tool closure.
///
/// Cloning is an `Arc` bump, which is what makes a defaults list, a set closure,
/// a tool list and a catalog facet safe to hand to four consumers. Semantic
/// equality ([`Self::same_declarations`]) compares the six declaration fields in
/// order and deliberately ignores the origin, exactly as [`same_declaration`]
/// does — origin is diagnostics, never identity.
#[derive(Clone, Debug)]
pub(crate) struct ResolvedMountList(Arc<[Arc<ConfigMountLeaf>]>);

impl ResolvedMountList {
    pub(crate) fn empty() -> Self {
        Self(Arc::from(Vec::new()))
    }

    pub(super) fn from_leaves(leaves: Vec<Arc<ConfigMountLeaf>>) -> Self {
        Self(Arc::from(leaves))
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    /// The declarations in selection order, borrowed. A caller that needs owned
    /// values (a launch handing them to `prepare`) clones at that boundary, once
    /// per launch, never per cache occurrence.
    pub(crate) fn requests(&self) -> impl ExactSizeIterator<Item = &MountRequest> + '_ {
        self.0.iter().map(|leaf| &leaf.request)
    }

    pub(super) fn leaves(&self) -> &[Arc<ConfigMountLeaf>] {
        &self.0
    }

    /// The shared leaf handles themselves, for the storage-shape tests that assert
    /// payloads are shared rather than copied per cache occurrence.
    #[cfg(test)]
    pub(crate) fn shared_leaves_for_test(&self) -> &[Arc<ConfigMountLeaf>] {
        &self.0
    }

    /// Declaration-list equality: same length, same six fields per position.
    /// Provenance and the declaring site are excluded, so moving a declaration
    /// between defaults, a set and a tool list does not make two tools' mount
    /// facets differ.
    pub(crate) fn same_declarations(&self, other: &ResolvedMountList) -> bool {
        self.0.len() == other.0.len()
            && self
                .0
                .iter()
                .zip(other.0.iter())
                .all(|(a, b)| same_declaration(&a.request.mount, &b.request.mount))
    }
}

impl Default for ResolvedMountList {
    fn default() -> Self {
        Self::empty()
    }
}

// Semantic equality, so a `Tool` and a `CatalogEntry` can derive it without
// exposing the shared handle's address — the same rule as `same_declaration`.
impl PartialEq for ResolvedMountList {
    fn eq(&self, other: &Self) -> bool {
        self.same_declarations(other)
    }
}

impl Eq for ResolvedMountList {}

/// Every full `[[tools]]` definition's own mount list, indexed by declaration
/// position.
///
/// Taken out of [`UserMounts`] once, so the CLI's namespace clone does not retain
/// a second declaration map, and so a project or built-in tier can be handed the
/// empty map *after* its own refusal — a tier that cannot declare mounts cannot
/// accidentally be given any.
#[derive(Clone, Debug, Default)]
pub(crate) struct ToolMountLists {
    /// Sparse on purpose: only definitions that declare `mounts` appear, so a
    /// tier handed the empty map and a file with a thousand mount-free tools cost
    /// nothing.
    lists: std::collections::BTreeMap<usize, ResolvedMountList>,
}

impl ToolMountLists {
    /// The map a tier that may not carry tool mounts gets.
    pub(crate) fn empty() -> Self {
        Self::default()
    }

    pub(super) fn set(&mut self, declaration: usize, list: ResolvedMountList) {
        self.lists.insert(declaration, list);
    }

    /// Declaration `declaration`'s own list; empty for an absent or out-of-range
    /// position, so a tier with no tool mounts answers every lookup without a
    /// second code path.
    pub(crate) fn get(&self, declaration: usize) -> ResolvedMountList {
        self.lists.get(&declaration).cloned().unwrap_or_default()
    }
}

/// One full `[[tools]]` definition's raw `mounts` value and where it sits.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ToolMountValue<'a> {
    pub(crate) declaration: usize,
    pub(crate) value: &'a toml::Value,
}

/// The set table, the defaults list and every tool's own list from one
/// already-verified read.
///
/// A named bundle rather than positional arguments: all three are untyped
/// `toml::Value`s at this seam (presence has already decided authority, and the
/// shape is decided here), so the callee cannot tell them apart by type.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MountValues<'a> {
    pub(crate) defaults: Option<&'a toml::Value>,
    pub(crate) sets: Option<&'a toml::Value>,
    /// Every tool with a `mounts` field, in declaration order. Empty when no
    /// tool declares one, which is also what a project or built-in tier passes
    /// after its refusal.
    pub(crate) tools: &'a [ToolMountValue<'a>],
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

/// Parse every present mount field of a file that has already been verified: the
/// `[mount_sets]` namespace, the top-level defaults list and each full
/// `[[tools]]` definition's own list.
///
/// `home` is the `$HOME` the user path was discovered from
/// ([`crate::config::ConfigPaths::home`]), never a fresh environment read: a
/// launch must expand `~/` to the same directory whose `config.toml` it read.
/// It is `None` when the host has no UTF-8 home, which only a `~/` entry cares
/// about.
///
/// A tool list alone is enough to call this: the caller must not gate the call on
/// the top-level fields, or a file whose only authority is a tool's `mounts`
/// would reach `validate_tools` without ever being parsed here.
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
    /// Declaration `declaration`'s own `mounts` field was not an array. A
    /// separate variant rather than a site-carrying `NotArray` so every existing
    /// top-level sentence keeps its bytes.
    ToolListNotArray { declaration: usize },
    /// One entry of declaration `declaration`'s own list was not a string.
    ToolListNotString { declaration: usize, index: usize },
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
    /// The `definition`th `[mount_sets]` key is one of the user config's own
    /// top-level field names, so a top-level key was written after the `[mount_sets]`
    /// header and TOML scoped it into this table. `key` is a `'static` member of that
    /// fixed vocabulary — [`crate::config::top_level_field`] is how it is produced —
    /// so the sentence names the mistake without echoing the file.
    TopLevelKey {
        definition: usize,
        key: &'static str,
    },
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
    /// The same shared budget, exhausted while admitting a tool list or folding a
    /// launch's tool closure. Its own sentence because the stages differ: a set
    /// stage refusal can only be fixed by shrinking set declarations, while this
    /// one may be a tool list repeatedly selecting an already-compiled set.
    ToolExpansionWorkLimit,
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
            Self::ToolListNotArray { declaration } => write!(
                f,
                "tools[{declaration}].mounts: must be an array of strings"
            ),
            Self::ToolListNotString { declaration, index } => {
                write!(f, "tools[{declaration}].mounts[{index}]: must be a string")
            }
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
            Self::TopLevelKey { definition, key } => write!(
                f,
                "mount_sets[{definition}]: {key} is not a mount set; a top-level {key} must be \
                 written before the first table header (keys after [mount_sets] belong to it)"
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
            Self::ToolExpansionWorkLimit => write!(
                f,
                "mounts: expansion work exceeds limit of {} leaf visits across mount sets and \
                 tool mounts",
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
                    tools: &[],
                },
                home,
            )
        })
    }

    fn sources(mounts: &UserMounts) -> Vec<Spelling> {
        defaults_requests(mounts)
            .into_iter()
            .map(|request| request.mount.source_spelling.clone())
            .collect()
    }

    fn guests(mounts: &UserMounts) -> Vec<String> {
        defaults_requests(mounts)
            .into_iter()
            .map(|request| request.mount.guest.display().to_string())
            .collect()
    }

    /// The defaults list's declarations, or nothing. A test fixture helper: a
    /// launch also carries the tool facet, so production reads `defaults()`.
    fn defaults_requests(mounts: &UserMounts) -> Vec<&MountRequest> {
        mounts
            .defaults()
            .map(|list| list.requests().collect())
            .unwrap_or_default()
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
            defaults_requests(&mounts)[0].mount.policy,
            MountPolicy::BindReadOnly { .. }
        ));
        assert!(matches!(
            defaults_requests(&parse(r#"["/abs:/g:rw"]"#, None).unwrap())[0]
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

    /// The same declarations, whether they sit in a tool's own list or the
    /// defaults list, produce the same parsed mount: one selector, one `~/` rule,
    /// one normalization. A second parser would show up as a differing
    /// `ExtraMount`.
    #[test]
    fn tool_lists_share_selector_grammar_and_home_spelling() {
        let home = Some(Path::new("/h"));
        let tool_value = |text: &str| -> toml::Value {
            format!("mounts = {text}\n")
                .parse::<toml::Table>()
                .unwrap()
                .remove("mounts")
                .unwrap()
        };
        for text in [
            r#"["/abs/ref"]"#,
            r#"["/abs/ref:/g:ro"]"#,
            r#"["/abs/ref:/g/fork:fork"]"#,
            r#"["~/ref"]"#,
            r#"["~/ref/:/g//./x:rw"]"#,
            r#"["  ~/ref  "]"#,
        ] {
            let value = tool_value(text);
            with_authorized(|authorized, _| {
                let defaults = from_verified_value(
                    authorized,
                    MountValues {
                        defaults: Some(&value),
                        sets: None,
                        tools: &[],
                    },
                    home,
                )
                .expect("the defaults list parses");
                let tools = [ToolMountValue {
                    declaration: 0,
                    value: &value,
                }];
                let mut tool_only = from_verified_value(
                    authorized,
                    MountValues {
                        defaults: None,
                        sets: None,
                        tools: &tools,
                    },
                    home,
                )
                .expect("the tool list parses");
                let from_tool = tool_only.take_tool_lists().get(0);
                let from_defaults = defaults.defaults().expect("the defaults list");
                assert_eq!(from_tool.len(), from_defaults.len(), "{text}");
                for (tool, default) in from_tool.requests().zip(from_defaults.requests()) {
                    assert!(
                        same_declaration(&tool.mount, &default.mount),
                        "{text}: the two sites must parse identically"
                    );
                }
            });
        }
        // A name with a `:` is refused identically from either site; only the
        // site's coordinates differ.
        let value = tool_value(r#"["agent:ro"]"#);
        with_authorized(|authorized, _| {
            assert_eq!(
                from_verified_value(
                    authorized,
                    MountValues {
                        defaults: Some(&value),
                        sets: None,
                        tools: &[],
                    },
                    home,
                )
                .unwrap_err()
                .to_string(),
                "mounts[0]: a mount-set reference is a bare name; modes, a guest path and \
                 exclusions belong to the paths declared inside the set"
            );
            let tools = [ToolMountValue {
                declaration: 2,
                value: &value,
            }];
            assert_eq!(
                from_verified_value(
                    authorized,
                    MountValues {
                        defaults: None,
                        sets: None,
                        tools: &tools,
                    },
                    home,
                )
                .unwrap_err()
                .to_string(),
                "tools[2].mounts[0]: a mount-set reference is a bare name; modes, a guest path \
                 and exclusions belong to the paths declared inside the set"
            );
        });
    }

    /// Every tool-list rejection names the numeric declaration and entry, and never
    /// echoes a value or a key.
    #[test]
    fn tool_list_errors_name_numeric_sites_without_values() {
        const SENTINEL: &str = "s3cr3t-SENTINEL-396";
        let home = Some(Path::new("/h"));
        let rows: Vec<(String, &str)> = vec![
            (
                "7".to_string(),
                "tools[1].mounts: must be an array of strings",
            ),
            (
                r#"["/a", 7]"#.to_string(),
                "tools[1].mounts[1]: must be a string",
            ),
            (
                format!("[\"./{SENTINEL}\"]"),
                "tools[1].mounts[0]: host path must be absolute",
            ),
            (
                format!("[\"/a:/g:{SENTINEL}\"]"),
                "tools[1].mounts[0]: unknown mode keyword",
            ),
            (
                format!("[\"/a:/g:exclude={SENTINEL}/../x\"]"),
                "tools[1].mounts[0]: exclude must be a non-empty relative path of normal \
                 components",
            ),
            // A sentinel that *is* a valid mount-set name reaches the set
            // grammar, not the path grammar: one selector decides both sites.
            (
                format!("[\"/a\", \"{SENTINEL}\"]"),
                "tools[1].mounts[1]: unknown mount set name",
            ),
        ];
        let value = |text: &str| -> toml::Value {
            format!("mounts = {text}\n")
                .parse::<toml::Table>()
                .unwrap()
                .remove("mounts")
                .unwrap()
        };
        for (text, expected) in rows {
            let parsed = value(&text);
            with_authorized(|authorized, _| {
                let tools = [ToolMountValue {
                    declaration: 1,
                    value: &parsed,
                }];
                let error = from_verified_value(
                    authorized,
                    MountValues {
                        defaults: None,
                        sets: None,
                        tools: &tools,
                    },
                    home,
                )
                .unwrap_err()
                .to_string();
                assert!(!error.contains(SENTINEL), "{text}: value echoed: {error}");
                assert!(error.starts_with(expected), "{text}: {error}");
            });
        }
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
                    tools: &[],
                },
                None,
            )
            .unwrap();
            assert_eq!(mounts.file(), file);
            assert_eq!(
                defaults_requests(&mounts)[0].origin.to_string(),
                format!("mounts[0] in {file:?}")
            );
        });
    }
}
