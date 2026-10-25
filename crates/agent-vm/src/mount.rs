//! `--mount HOST[:GUEST][:MODE][:MODE]...` parsing and the volume-builder
//! preparation it feeds. [`parse_extra_mounts`] and [`prepare`] are the
//! entry points `run.rs`'s `launch()` calls; everything else here is a
//! private implementation detail of the mount contract.
//!
//! The grammar ([`parse_mount_spec`]) and the claim rule ([`claim`]) are shared
//! with verified user-config `mounts` (ADR-0046), which is why they are separate
//! from the CLI wrapper and carry an origin: the same rejection must be able to
//! render as `--mount …` for argv and as `mounts[N] in "…"` for a config file
//! without either route owning a second copy of the rules.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
#[cfg(test)]
use microsandbox::sandbox::MountBuilder;

use crate::config::{quoted_path, quoted_str};
use crate::host_paths::flock_exclusive;
#[cfg(test)]
use crate::protected_host_files::CoreBind;
use crate::protected_host_files::{
    CoreHostSource, ProtectedFile, ProtectedHostFiles, ResolvedRoot, Severity,
};
use crate::run::guest_path_is_mountable;
use vstd::prelude::*;

/// A recognized `--mount` mode keyword: `ro`, `rw`, `fork`, or `follow-links`
/// (issue #11 — auto-discover and bind-mount the real directories that
/// symlinks under `HOST` transitively resolve to; see
/// [`discover_followed_targets`]/[`expand_follow_links`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MountMode {
    ReadOnly,
    ReadWrite,
    FollowLinks,
    Fork,
}

impl MountMode {
    /// Classify one trailing suffix segment as a mode keyword.
    /// `None` = not a known keyword (caller raises "unknown mode").
    fn from_keyword(kw: &str) -> Option<MountMode> {
        match kw {
            "ro" => Some(MountMode::ReadOnly),
            "rw" => Some(MountMode::ReadWrite),
            "follow-links" => Some(MountMode::FollowLinks),
            "fork" => Some(MountMode::Fork),
            _ => None,
        }
    }

    /// The canonical keyword, for error messages that name the offending
    /// token (matches the `parse_publish_args` idiom).
    fn keyword(self) -> &'static str {
        match self {
            MountMode::ReadOnly => "ro",
            MountMode::ReadWrite => "rw",
            MountMode::FollowLinks => "follow-links",
            MountMode::Fork => "fork",
        }
    }
}

/// Mode-keyword pairs that cannot appear together on one mount. This is the
/// single place the conflict policy lives. Note `ro`+`follow-links` is
/// intentionally NOT listed, because they coexist (follow-links implies
/// read-only) — which is precisely why a single mutually-exclusive
/// `Option<MountMode>` slot would be wrong.
const INCOMPATIBLE_MODES: &[(MountMode, MountMode)] = &[
    (MountMode::ReadOnly, MountMode::ReadWrite),
    (MountMode::ReadWrite, MountMode::FollowLinks),
    (MountMode::Fork, MountMode::ReadOnly),
    (MountMode::Fork, MountMode::ReadWrite),
];

/// True iff `a` and `b` may not appear on the same mount (order-independent).
fn modes_conflict(a: MountMode, b: MountMode) -> bool {
    INCOMPATIBLE_MODES
        .iter()
        .any(|&(x, y)| (x, y) == (a, b) || (x, y) == (b, a))
}

/// The closed set of valid mount policies. Parsing is the only place that
/// constructs it, so contradictory combinations never reach preparation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MountPolicy {
    BindReadWrite,
    BindReadOnly { follow_links: bool },
    Fork { follow_links: bool },
}

/// A declaration's host spelling, exactly as its author wrote it: after the one
/// expansion the grammar allows a config entry (`~/` → `$HOME/`), and never
/// canonicalized, because it is part of fork identity.
///
/// Deliberately not a `String`. Turning a spelling into text is a *policy*
/// decision that depends on which declaration it came from — an `--mount`
/// diagnostic is byte-pinned (ADR-0018), while a config entry is
/// attacker-chosen text that must be escaped *and* attributed to
/// `mounts[N] in "<file>"` — so [`Spelling::render`] is the only conversion this
/// type offers, and it takes the [`Declaration`] that decides. While the field
/// was a `String`, `format!("{}", mount.source_spelling)` compiled silently, and
/// every site that did it dropped the attribution and let a newline in a
/// filename forge a diagnostic line. Such a site no longer compiles.
///
/// The raw bytes stay reachable, because fork identity needs them, through three
/// accessors named for their one legitimate use — [`Spelling::stored_str`] (the
/// manifest), [`Spelling::stored_bytes`] (the fork hash) and
/// [`Spelling::as_source_path`] (this declaration's own path). `clippy.toml`
/// bans all three as `disallowed-methods`; each of the five call sites carries
/// an explicit `#[allow]` with its reason, so a new one cannot be added quietly.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Spelling(String);

impl Spelling {
    pub(crate) fn new(spelling: impl Into<String>) -> Self {
        Self(spelling.into())
    }

    /// The spelling as `declaration`'s diagnostics print it: unquoted for an argv
    /// `--mount`, quoted and attributed for a config entry.
    pub(crate) fn render(&self, declaration: Declaration<'_>) -> String {
        declaration.spelling(&self.0)
    }

    /// The spelling quoted the way the sentence that prints it has always quoted
    /// it: `{:?}` for argv, `quoted_str` for a config entry.
    pub(crate) fn render_quoted(&self, declaration: Declaration<'_>) -> String {
        declaration.spelling_quoted(&self.0)
    }

    /// The stored bytes, for the fork manifest only. Never a diagnostic.
    pub(crate) fn stored_str(&self) -> &str {
        &self.0
    }

    /// The stored bytes, for the fork hash only. Never a diagnostic.
    pub(crate) fn stored_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// This declaration's own source path, for filesystem calls and for
    /// `quoted_path`, which escapes. Never `display`ed into a message.
    pub(crate) fn as_source_path(&self) -> &Path {
        Path::new(&self.0)
    }
}

// Comparison against the bytes is comparison, not rendering: tests and the
// fork-identity check may ask whether a spelling *is* `"/srv/x"` without owning
// a rendering policy, so these impls add no way to print one.
impl PartialEq<str> for Spelling {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}
impl PartialEq<&str> for Spelling {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}
impl PartialEq<String> for Spelling {
    fn eq(&self, other: &String) -> bool {
        self.0 == *other
    }
}

/// One `--mount HOST[:GUEST][:MODE][:MODE]...` argument resolved into
/// separate paths plus its validated policy.
#[derive(Clone, Debug)]
pub(crate) struct ExtraMount {
    /// Exact source spelling. It is part of fork identity, deliberately not
    /// canonicalized, and never rendered without a [`Declaration`].
    pub(crate) source_spelling: Spelling,
    pub(crate) host: PathBuf,
    pub(crate) spelled_host: PathBuf,
    pub(crate) guest: PathBuf,
    pub(crate) policy: MountPolicy,
    /// Normalized relative entries omitted from a `:fork` seed. Empty for
    /// every live bind: `:exclude` is fork-only (issue #113).
    pub(crate) exclusions: Vec<PathBuf>,
}

impl ExtraMount {
    fn is_readonly(&self) -> bool {
        matches!(self.policy, MountPolicy::BindReadOnly { .. })
    }
    fn follows_links(&self) -> bool {
        matches!(
            self.policy,
            MountPolicy::BindReadOnly { follow_links: true }
                | MountPolicy::Fork { follow_links: true }
        )
    }
    fn is_fork(&self) -> bool {
        matches!(self.policy, MountPolicy::Fork { .. })
    }
}

/// Where a declaration came from.
///
/// Diagnostics only: never part of [`same_declaration`] or [`fork_id`]. A config
/// mount that a shell-expanded `--mount` declares identically is the *same*
/// declaration, so provenance must not be able to change the fork a launch
/// reuses (ADR-0046).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MountOrigin {
    Cli,
    /// A verified user `mounts` entry: the file it came from and its index.
    /// Built only by [`crate::config_mounts`], from the verified read that
    /// authority was measured on.
    UserConfig {
        file: PathBuf,
        index: usize,
    },
}

/// The *name* of an origin, for text that has no rendering policy to choose.
/// [`prepare`]'s refusals go through [`Declaration`] instead, because they must
/// also pick between the byte-pinned argv spelling and the escaped config one;
/// this impl is the `--mount` / `mounts[N] in "<file>"` half alone.
impl fmt::Display for MountOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cli => f.write_str("--mount"),
            // Rendering the file through `quoted_path` escapes it the way the
            // rest of the config diagnostics do, so an entry point cannot forge
            // the rest of the sentence and one launch never shows two escapings
            // of the same file.
            Self::UserConfig { file, index } => {
                write!(f, "mounts[{index}] in {}", quoted_path(file))
            }
        }
    }
}

/// One declaration a launch asks [`prepare`] for, with the provenance its
/// diagnostics need.
#[derive(Clone, Debug)]
pub(crate) struct MountRequest {
    pub(crate) origin: MountOrigin,
    pub(crate) mount: ExtraMount,
}

/// The ordered declarations one launch asks [`prepare`] for: config selections
/// first, then argv, in the order the launch decided (see
/// `mount_selection::select`).
///
/// A newtype rather than a bare `Vec<MountRequest>`: `impl Into<MountRequests>`
/// needs one concrete target to hang the `#[cfg(test)] From<Vec<ExtraMount>>` on,
/// and the type name is where the invariant lives — every element names the
/// source it came from.
#[derive(Debug, Default)]
pub(crate) struct MountRequests(Vec<MountRequest>);

impl MountRequests {
    pub(crate) fn new(requests: Vec<MountRequest>) -> Self {
        Self(requests)
    }

    /// Every declaration in `mounts` is an argv entry.
    ///
    /// Two callers, one meaning: `mount_selection::select` tags the argv half of
    /// a launch's declarations here (the config half arrives tagged by
    /// `config_mounts`), and `#[cfg(test)] From<Vec<ExtraMount>>` lets a test
    /// hand `prepare` a plan with no config provenance at all.
    pub(crate) fn from_cli(mounts: Vec<ExtraMount>) -> Self {
        Self::new(
            mounts
                .into_iter()
                .map(|mount| MountRequest {
                    origin: MountOrigin::Cli,
                    mount,
                })
                .collect(),
        )
    }

    pub(crate) fn into_inner(self) -> Vec<MountRequest> {
        self.0
    }
}

#[cfg(test)]
impl From<Vec<ExtraMount>> for MountRequests {
    fn from(mounts: Vec<ExtraMount>) -> Self {
        Self::from_cli(mounts)
    }
}

/// Which declaration each explicit mount of one `prepare` came from, keyed by
/// the guest path it claimed.
///
/// A guest path names exactly one declaration: `claim` has already merged
/// identical declarations at one guest path and refused differing ones, which is
/// what makes the lookup total for the declarations `prepare` was given. The
/// key is the normalized guest path, so a later stage that reassigns `host` (fork
/// preflight) keeps its origin.
///
/// A `:follow-links`-discovered bind is appended after the declarations and has
/// no entry — it is not a declaration, and the launching context names the config
/// file for it — so [`declaration_origin`] falls back to `--mount` there and the
/// refusal keeps its historical text.
///
/// That fallback is only the *lookup's* answer. A discovered target can land on a
/// guest path a declaration already claimed — that is exactly the conflict
/// `expand_follow_links` refuses — and then the map would name the declaring
/// entry for a bind it did not discover. A caller that knows the split (the
/// declarations are the elements it passed in; everything after is discovered)
/// must say so itself rather than ask this map.
type DeclaredOrigins = BTreeMap<PathBuf, MountOrigin>;

/// How one preparation refusal names the declaration it is about, together with
/// the rendering policy that declaration's source requires.
///
/// Two renderings, because the two sources have different contracts. An argv
/// `--mount` diagnostic is byte-pinned (ADR-0018: `cli_claim_errors_are_pinned`),
/// so every argv site below prints exactly the text it printed before
/// declarations could come from a file: the debug rendering where the old text
/// used it, `Path::display` where it printed a resolved host, and the bare
/// declared spelling where the old text had no quotes. A config entry is
/// attacker-chosen text that also has to stay one line, so those sites escape it
/// with the config module's [`quoted_path`]/[`quoted_str`].
///
/// This is the argument [`Spelling::render`] demands, so a site cannot print a
/// declared spelling without having decided which source it belongs to.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Declaration<'a> {
    /// An argv `--mount`.
    Argv,
    /// A verified user `mounts` entry: index `index` of `file`.
    UserConfig { file: &'a Path, index: usize },
}

impl Declaration<'_> {
    /// `--mount` or `mounts[N] in "<file>"`: the name a refusal starts with.
    fn subject(self) -> String {
        match self {
            Self::Argv => "--mount".to_string(),
            Self::UserConfig { file, index } => {
                format!("mounts[{index}] in {}", quoted_path(file))
            }
        }
    }

    /// A declared spelling as this source's refusal prints it: bare for argv (the
    /// two sentences that print one never quoted it), quoted and attributed for a
    /// config entry.
    ///
    /// Both arms escape control characters, so a spelling can never end the line
    /// it is printed on. The argv arm used to be verbatim, on the theory that argv
    /// is text the user typed; but a spelling is the *expanded* value — `~/repo`
    /// becomes `$HOME/repo` — so it inherits whatever bytes the environment
    /// carries, and `discovered by --mount …` printed such a path raw. For an
    /// ordinary path the bytes are unchanged, which is the part ADR-0018 pins.
    ///
    /// Private on purpose: every caller goes through [`Spelling::render`], which
    /// is the only way to reach it from a declaration's own bytes.
    fn spelling(self, spelling: &str) -> String {
        match self {
            Self::Argv => crate::one_line::text(spelling),
            Self::UserConfig { .. } => quoted_str(spelling),
        }
    }

    /// The same spelling in the *quoted* form one context sentence (and one argv
    /// sentence) has always used: `{:?}` for argv, which is quoted with Rust's
    /// escapes and is byte-pinned, and `quoted_str` for a config entry, which is
    /// quoted with the config module's escapes and cannot forge a line.
    fn spelling_quoted(self, spelling: &str) -> String {
        match self {
            Self::Argv => format!("{spelling:?}"),
            Self::UserConfig { .. } => quoted_str(spelling),
        }
    }

    /// A host path as this source's diagnostics print it: one line for argv, and
    /// `quoted_path` for a config entry, whose path is derived from
    /// attacker-chosen text and must not break the line.
    ///
    /// The argv arm escapes control characters too. It used to be `display()`,
    /// which is not a declaration rendering at all: the follow-links walk passes
    /// **measured** names through this function — a directory entry, a symlink
    /// target — and nobody chose those bytes. A symlink named
    /// `l<LF>==> Mounting /etc -> /etc` in a cloned repo forged a notice under an
    /// `--mount …:follow-links` root. Ordinary paths are unchanged, so the argv
    /// diagnostics ADR-0018 pins stay byte-identical.
    fn host_path(self, path: &Path) -> String {
        match self {
            Self::Argv => crate::one_line::path(path),
            Self::UserConfig { .. } => quoted_path(path),
        }
    }

    /// What `resolving fork root …` prints in place of the root path.
    ///
    /// That sentence never carried a flag name, so an argv entry stays unquoted;
    /// it is escaped by the one-line policy, because the path handed here is the
    /// *canonicalized* fork root, which `protected_host_files` measured. A config
    /// entry has to name itself —
    /// otherwise the author of `mounts = [...]` cannot tell which entry failed —
    /// and has to escape the path, which at this point is the *expanded* spelling
    /// and therefore carries the attacker-chosen bytes.
    ///
    /// Exposed to [`crate::protected_host_files`], which owns the resolve step.
    pub(crate) fn fork_root(self, path: &Path) -> String {
        match self {
            Self::Argv => crate::one_line::path(path),
            Self::UserConfig { file, index } => format!(
                "mounts[{index}] in {} {}",
                quoted_path(file),
                quoted_path(path)
            ),
        }
    }
}

/// The declaration a preparation refusal names for `mount`: its own declaration,
/// or `--mount` for a `:follow-links`-discovered bind (see [`DeclaredOrigins`]).
fn declaration_origin<'a>(mount: &ExtraMount, origins: &'a DeclaredOrigins) -> Declaration<'a> {
    match origins.get(&mount.guest) {
        Some(MountOrigin::UserConfig { file, index }) => Declaration::UserConfig {
            file,
            index: *index,
        },
        // A discovered bind is not a declaration, and `MountOrigin::Cli` is an
        // argv one; both keep the historical `--mount` text.
        Some(MountOrigin::Cli) | None => Declaration::Argv,
    }
}

/// The `canonicalizing …` context for a source [`expand_follow_links`] could not
/// resolve. Named so the argv rendering (`{:?}`) and the config rendering
/// (escaped, so `café` stays one word) can be pinned without a filesystem race.
fn canonicalizing_context(declaration: Declaration<'_>, spelling: &Spelling) -> String {
    format!(
        "canonicalizing {} host {}",
        declaration.subject(),
        spelling.render_quoted(declaration)
    )
}

/// The `validating … source` context for a source `prepare` could not classify.
/// Same split as [`canonicalizing_context`]: unquoted on the argv side, because
/// this sentence never quoted the path, and escaped there by the one-line policy
/// — `expanded` includes `:follow-links`-discovered binds, whose paths the walk
/// measured. Ordinary paths are byte-identical, so the pinned argv sentence holds.
fn validating_source_context(declaration: Declaration<'_>, host: &Path) -> String {
    match declaration {
        Declaration::Argv => {
            format!("validating --mount source {}", crate::one_line::path(host))
        }
        _ => format!(
            "validating {} source {}",
            declaration.subject(),
            quoted_path(host)
        ),
    }
}

/// The `resolving … fork root` / `validating … fork root` context for a `:fork`
/// source that could not be canonicalized or classified. The argv sentence has
/// never named `--mount` and never quoted the path, so that half stays
/// byte-identical; a config entry names itself and escapes the host path it
/// expanded to, because the path is the entry's text and a newline in it would
/// otherwise forge a second diagnostic line.
fn fork_root_context(verb: &str, declaration: Declaration<'_>, source: &Path) -> String {
    match declaration {
        Declaration::Argv => format!("{verb} fork root {}", source.display()),
        Declaration::UserConfig { .. } => format!(
            "{verb} {} fork root {}",
            declaration.subject(),
            quoted_path(source)
        ),
    }
}

// The pure decisions this module makes about a declaration. Three of them decide
// what a launch is allowed to do — which host spelling the grammar accepts, and
// whether two claims at one guest path merge or are refused — so per ADR-0018
// they are kernels and every byte outside them is a trusted adapter. A kernel
// body is written in a shape its `ensures` clause does not use, so a mutation
// control can name the body alone (see `script/test/egress-mutations.py`);
// `host_spelling` is the one documented exception, just below.
verus! {
/// Which host spellings a grammar accepts.
///
/// `--mount` gets `Disabled`: the shell already expanded `~`, so a quoted `~/x`
/// is a relative path and must stay "must be absolute" (ADR-0046 pins that).
/// User-config `mounts` gets `Enabled`, which is the only place `~/` means HOME.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub enum HomeExpansion { Disabled, Enabled }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub enum HostSpelling { Literal, ExpandHome, Refused }

pub open spec fn starts_slash(b: Seq<u8>) -> bool { b.len() >= 1 && b[0] == 0x2fu8 }
pub open spec fn starts_tilde_slash(b: Seq<u8>) -> bool {
    b.len() >= 2 && b[0] == 0x7eu8 && b[1] == 0x2fu8 }

// The exception to the shape rule above: this body is deliberately spelled the
// way `starts_slash` is, so the proof is a case split rather than a lemma about a
// different formulation; the same allow and the same reason as
// `credential_yaml::header_name_is_valid_bytes`. A mutation control therefore
// anchors on the home-expansion arm's own byte tests rather than on a single
// expression the `ensures` also spells.
#[allow(clippy::len_zero)]
pub fn host_spelling(bytes: &[u8], home: HomeExpansion) -> (d: HostSpelling)
    ensures
        (d == HostSpelling::Literal) == starts_slash(bytes@),
        (d == HostSpelling::ExpandHome) == (home == HomeExpansion::Enabled && starts_tilde_slash(bytes@)),
        home == HomeExpansion::Disabled ==> d != HostSpelling::ExpandHome,
{
    if bytes.len() >= 1 && bytes[0] == 0x2f { HostSpelling::Literal }
    else if home == HomeExpansion::Enabled && bytes.len() >= 2 && bytes[0] == 0x7e && bytes[1] == 0x2f { HostSpelling::ExpandHome }
    else { HostSpelling::Refused }
}

/// The six facts [`same_declaration`] measures. Named fields rather than six
/// adjacent booleans, so a call site cannot transpose two of them and merge
/// declarations that differ in policy.
#[derive(Clone, Copy, Debug)]
pub struct DeclarationFacts {
    pub spelling: bool,
    pub host: bool,
    pub readonly: bool,
    pub follow: bool,
    pub fork: bool,
    pub exclusions: bool,
}

pub fn declarations_equivalent(f: DeclarationFacts) -> (r: bool)
    ensures r == (f.spelling && f.host && f.readonly && f.follow && f.fork && f.exclusions),
{
    if !f.spelling { return false; }
    if !f.host { return false; }
    if !f.readonly { return false; }
    if !f.follow { return false; }
    if !f.fork { return false; }
    f.exclusions
}

#[derive(Clone, Copy, Debug)]
pub struct ClaimFacts { pub same_guest: bool, pub equivalent: bool }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub enum ClaimDecision { Distinct, Merge, Conflict }

/// ADR-0046: identical declarations merge, and differing ones at one guest path
/// are refused whatever their origins. There is no third outcome, so no caller
/// can implement a last-wins override of a config or project declaration.
pub fn claim_decision(f: ClaimFacts) -> (d: ClaimDecision)
    ensures
        (d == ClaimDecision::Distinct) == !f.same_guest,
        (d == ClaimDecision::Merge) == (f.same_guest && f.equivalent),
        (d == ClaimDecision::Conflict) == (f.same_guest && !f.equivalent),
{
    if !f.same_guest { ClaimDecision::Distinct }
    else if f.equivalent { ClaimDecision::Merge }
    else { ClaimDecision::Conflict }
}
} // verus!

/// A `GUEST` segment must start with `/` or `.`; anything trailing that
/// doesn't is a mode keyword. This is the sole rule that disambiguates
/// `HOST:GUEST` from `HOST:MODE` (e.g. `HOST:ro`) since both are a single
/// segment right after `HOST`.
fn segment_is_guest_path(seg: &str) -> bool {
    seg.starts_with('/') || seg.starts_with('.')
}

/// Which host spellings one caller's grammar accepts.
///
/// Three states, not a bool: `--mount` is absolute-only, user-config `mounts`
/// also accepts `~/`, and a `~/` entry is only decidable once `$HOME` is known
/// (`None` = the host has no usable home, which is a rejection, not a silent
/// relative path).
#[derive(Clone, Copy, Debug)]
pub(crate) enum HostSyntax<'a> {
    /// `--mount`: absolute host paths only (the shell already expanded `~`).
    AbsoluteOnly,
    /// Verified user config: absolute, or `~/` + `home`. [`crate::config_mounts`]
    /// is the only caller; `None` means the host has no UTF-8 home, so only a
    /// `~/` entry is refused.
    AbsoluteOrHome { home: Option<&'a str> },
}

impl HostSyntax<'_> {
    fn expansion(&self) -> HomeExpansion {
        match self {
            Self::AbsoluteOnly => HomeExpansion::Disabled,
            Self::AbsoluteOrHome { .. } => HomeExpansion::Enabled,
        }
    }

    fn home(&self) -> Option<&str> {
        match self {
            Self::AbsoluteOnly => None,
            Self::AbsoluteOrHome { home } => *home,
        }
    }
}

/// Why a declaration was rejected, without any value from the declaration.
///
/// The CLI renders [`MountSpecError::into_cli`] and keeps today's bytes (pinned
/// by `cli_parse_errors_are_pinned`). A config route renders the kind instead,
/// because echoing a `mounts` entry could print an attacker-chosen path into a
/// diagnostic the user is asked to trust.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MountSpecErrorKind {
    EmptyHost,
    HostNotAccepted,
    HomeUnavailable,
    GuestNotAbsolute,
    GuestUnmountable,
    EmptySegment,
    UnknownMode,
    ConflictingModes(&'static str, &'static str),
    BadExclusion,
    ExcludeOnLiveBind,
}

/// The kind, plus the `anyhow` chain `--mount` has always reported for it.
#[derive(Debug)]
pub(crate) struct MountSpecError {
    kind: MountSpecErrorKind,
    cli: anyhow::Error,
}

impl MountSpecError {
    fn new(kind: MountSpecErrorKind, cli: anyhow::Error) -> Self {
        Self { kind, cli }
    }

    /// The `--mount` rendering: character for character what `bail!` produced
    /// at this point before the grammar was shared, including the outer
    /// `--mount "…"` frame a `.with_context(..)` contributes.
    pub(crate) fn into_cli(self) -> anyhow::Error {
        self.cli
    }

    /// The config route renders this instead of the CLI sentence, so a `mounts`
    /// entry's value never reaches a diagnostic.
    pub(crate) fn kind(&self) -> MountSpecErrorKind {
        self.kind
    }
}

impl fmt::Display for MountSpecErrorKind {
    /// The config route's sentence for one rejection: the *kind*, never the
    /// declaration text. A `mounts` entry can carry an attacker-chosen path, so
    /// it must not reach a diagnostic the user is asked to trust; `--mount`
    /// keeps [`MountSpecError::into_cli`]'s bytes instead.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyHost => {
                f.write_str("mount declaration must be HOST[:GUEST][:MODE]... (non-empty)")
            }
            Self::HostNotAccepted => f.write_str(
                "host path must be absolute or start with ~/ (environment variables and other \
                 relative paths are not expanded)",
            ),
            Self::HomeUnavailable => f.write_str("a ~/ host path needs a UTF-8 $HOME"),
            Self::GuestNotAbsolute => f.write_str("guest path must be absolute"),
            Self::GuestUnmountable => f.write_str(
                "guest path contains control characters that can't be carried into the guest",
            ),
            Self::EmptySegment => {
                f.write_str("empty segment (stray `:`); expected HOST[:GUEST][:MODE]...")
            }
            Self::UnknownMode => f.write_str(
                "unknown mode keyword (expected ro, rw, fork, follow-links, or exclude=REL)",
            ),
            Self::ConflictingModes(first, second) => {
                write!(f, "conflicting modes `{first}` and `{second}`")
            }
            Self::BadExclusion => {
                f.write_str("exclude must be a non-empty relative path of normal components")
            }
            Self::ExcludeOnLiveBind => f.write_str(":exclude is only supported on :fork mounts"),
        }
    }
}

/// One declaration string, in whichever syntax the caller's source allows.
///
/// Grammar: `HOST[:GUEST][:MODE][:MODE]...`. `HOST` alone defaults `GUEST`
/// to the same path (mirror), read-write. `GUEST`, if present,
/// must be the segment immediately after `HOST` and must start with `/` or
/// `.` (see [`segment_is_guest_path`]); everything after that is a mode
/// keyword (`ro`/`rw` — see [`MountMode`]). Path validity is checked before
/// mode keywords so `relativehost:bogus` reports the host error, not
/// "unknown mode". `ro`+`rw` together, and any keyword `MountMode` doesn't
/// recognize, are hard parse-time errors.
///
/// Colon-bearing guest paths are undocumented/pathological: the grammar splits
/// on every colon, so a trailing token is read as a mode keyword and fails as
/// "unknown mode keyword \"x\"" (`/h:/g:x`). A relative `GUEST` segment is
/// likewise classified as a mode keyword and fails as "unknown mode keyword
/// \"relative-guest\"" rather than "guest path must be absolute" — still a hard
/// error, just a different message. Both are pinned by
/// `parse_extra_mounts_colon_in_guest_now_mode_error` and
/// `parse_extra_mounts_rejects_relative_paths`.
pub(crate) fn parse_mount_spec(
    entry: &str,
    syntax: HostSyntax<'_>,
) -> Result<ExtraMount, MountSpecError> {
    let mut segs = entry.split(':').map(str::trim);
    let host_s = segs.next().unwrap_or_default().to_string();
    let mut tail: Vec<&str> = segs.collect();

    // --- Path validation first, so path errors beat mode errors. ---
    if host_s.is_empty() {
        return Err(MountSpecError::new(
            MountSpecErrorKind::EmptyHost,
            anyhow::anyhow!("--mount value {entry:?} must be HOST[:GUEST] (non-empty)"),
        ));
    }
    // The host decision, before `GUEST` mirrors it: a mirror must be the path
    // the mount really names, so `~/ref` mirrors the *expanded* host.
    let host_s = match host_spelling(host_s.as_bytes(), syntax.expansion()) {
        HostSpelling::Literal => host_s,
        HostSpelling::ExpandHome => match syntax.home() {
            // Replace exactly the one leading `~`; the rest (starting with `/`)
            // is kept byte-for-byte, so a trailing-slash HOME keeps its `//`.
            Some(home) => format!("{home}{}", &host_s[1..]),
            None => {
                return Err(MountSpecError::new(
                    MountSpecErrorKind::HomeUnavailable,
                    anyhow::anyhow!(
                        "--mount host path {host_s:?} needs a UTF-8 $HOME to expand `~`"
                    ),
                ));
            }
        },
        HostSpelling::Refused => {
            return Err(MountSpecError::new(
                MountSpecErrorKind::HostNotAccepted,
                anyhow::anyhow!("--mount host path {host_s:?} must be absolute"),
            ));
        }
    };

    // Optional GUEST: only the first tail segment, and only if it
    // looks like a path. Otherwise GUEST mirrors HOST (today's default).
    let guest_s = if tail.first().is_some_and(|s| segment_is_guest_path(s)) {
        tail.remove(0).to_string()
    } else {
        host_s.clone()
    };

    let host = PathBuf::from(&host_s);
    let guest = PathBuf::from(&guest_s);
    // Unreachable for `--mount`, and for a config `~/` only if the caller hands
    // us a relative HOME: kept so a relative host can never be constructed by
    // trusting the caller.
    if !host.is_absolute() {
        return Err(MountSpecError::new(
            MountSpecErrorKind::HostNotAccepted,
            anyhow::anyhow!("--mount host path {host_s:?} must be absolute"),
        ));
    }
    if !guest.is_absolute() {
        return Err(MountSpecError::new(
            MountSpecErrorKind::GuestNotAbsolute,
            anyhow::anyhow!("--mount guest path {guest_s:?} must be absolute"),
        ));
    }
    // The guest mount point reaches agentd via the boot-params side
    // channel (not the kernel command line), so non-ASCII and spaces
    // are fine — but a control character (TAB/newline) would break the
    // `KEY\tVALUE\n` framing, so reject those. See
    // `guest_path_is_mountable`.
    if !guest_path_is_mountable(&guest_s) {
        return Err(MountSpecError::new(
            MountSpecErrorKind::GuestUnmountable,
            anyhow::anyhow!(
                "--mount guest path {guest_s:?} contains control characters that can't be \
                 carried into the guest; pass a guest path without tabs/newlines"
            ),
        ));
    }

    // --- Then classify the remaining tail segments as mode keywords. ---
    let mut modes: Vec<MountMode> = Vec::new();
    for kw in tail {
        if kw.is_empty() {
            // e.g. `/h::ro` — a stray `::`. Point at it rather than
            // reporting "unknown mode keyword \"\"".
            return Err(MountSpecError::new(
                MountSpecErrorKind::EmptySegment,
                anyhow::anyhow!(
                    "--mount {entry:?}: empty segment (stray `:`); expected \
                     HOST[:GUEST][:MODE]..."
                ),
            ));
        }
        if kw.strip_prefix("exclude=").is_some() {
            continue;
        }
        let mode = MountMode::from_keyword(kw).ok_or_else(|| {
            MountSpecError::new(
                MountSpecErrorKind::UnknownMode,
                anyhow::anyhow!(
                    "--mount {entry:?}: unknown mode keyword {kw:?} \
                     (expected `ro`, `rw`, `fork`, `follow-links`, or `exclude=REL`)"
                ),
            )
        })?;
        if let Some(&prev) = modes.iter().find(|&&prev| modes_conflict(prev, mode)) {
            return Err(MountSpecError::new(
                MountSpecErrorKind::ConflictingModes(prev.keyword(), mode.keyword()),
                anyhow::anyhow!(
                    "--mount {entry:?}: conflicting modes `{}` and `{}` — pick one",
                    prev.keyword(),
                    mode.keyword()
                ),
            ));
        }
        modes.push(mode);
    }
    let follow_links = modes.contains(&MountMode::FollowLinks);
    // follow-links implies read-only; bare follow-links behaves as ro.
    let readonly = modes.contains(&MountMode::ReadOnly) || follow_links;

    let fork = modes.contains(&MountMode::Fork);
    let mut exclusions = Vec::new();
    // Exclusion values share the suffix list with modes.  They are parsed
    // here (before any source I/O) so an already READY fork can be reused
    // after its source has disappeared.
    for suffix in entry.split(':').skip(
        if segment_is_guest_path(entry.split(':').nth(1).unwrap_or("")) {
            2
        } else {
            1
        },
    ) {
        let suffix = suffix.trim();
        if let Some(value) = suffix.strip_prefix("exclude=") {
            exclusions.push(
                normalize_exclusion(value)
                    .with_context(|| format!("--mount {entry:?}"))
                    .map_err(|error| {
                        MountSpecError::new(MountSpecErrorKind::BadExclusion, error)
                    })?,
            );
        }
    }
    exclusions.sort();
    exclusions.dedup();
    let mut collapsed = Vec::new();
    for path in exclusions {
        if !collapsed
            .iter()
            .any(|parent: &PathBuf| path.starts_with(parent))
        {
            collapsed.push(path);
        }
    }
    let exclusions = collapsed;
    let policy = if fork {
        MountPolicy::Fork { follow_links }
    } else if readonly {
        MountPolicy::BindReadOnly { follow_links }
    } else {
        MountPolicy::BindReadWrite
    };
    // `:exclude` omits entries from a fork seed. On a live bind there is
    // no seed to omit from, and the old opaque-mask substitute is removed
    // (issue #113), so reject the declaration here — after normalization
    // and mode-conflict precedence, but before any source I/O.
    if !exclusions.is_empty() && !matches!(policy, MountPolicy::Fork { .. }) {
        return Err(MountSpecError::new(
            MountSpecErrorKind::ExcludeOnLiveBind,
            anyhow::anyhow!(
                "--mount {entry}: :exclude is only supported on :fork mounts;\n\
                 live binds cannot hide nested paths."
            ),
        ));
    }
    Ok(ExtraMount {
        source_spelling: Spelling::new(host_s),
        spelled_host: host.clone(),
        host,
        guest,
        policy,
        exclusions,
    })
}

/// Parse the raw `--mount` argv strings into `ExtraMount`s.
pub(crate) fn parse_extra_mounts(raw: &[String]) -> Result<Vec<ExtraMount>> {
    raw.iter()
        .map(|entry| {
            parse_mount_spec(entry, HostSyntax::AbsoluteOnly).map_err(MountSpecError::into_cli)
        })
        .collect()
}

/// Validate an exclusion without allowing Path's lexical normalization to
/// hide an escaping or empty component.
fn normalize_exclusion(raw: &str) -> Result<PathBuf> {
    if raw.is_empty() || raw.contains(':') || raw.chars().any(char::is_control) {
        anyhow::bail!("exclude must be a non-empty relative path");
    }
    let mut out = PathBuf::new();
    for component in raw.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            anyhow::bail!("exclude must contain only normal relative components");
        }
        out.push(component);
    }
    Ok(out)
}

/// Configure a bind-mount `MountBuilder` for an `ExtraMount`: bind the host
/// path and apply `.readonly()` when the mount was parsed `:ro`. Factored
/// out of the `.volume(...)` closure so the readonly wiring has a boot-free
/// unit seam (see `extra_mount_ro_propagates_readonly_into_built_volume`).
#[cfg(test)]
pub(crate) fn configure_extra_mount(
    m: MountBuilder,
    host: PathBuf,
    readonly: bool,
) -> MountBuilder {
    let m = m.bind(host);
    if readonly { m.readonly() } else { m }
}

/// Depth cap on symlink-*follow* chains specifically — NOT on plain
/// directory nesting under `HOST` or a discovered target (see the
/// `link_depth` bookkeeping in [`discover_followed_targets`], which only
/// increments when a symlink is followed). The `visited` set stops the
/// walk revisiting a host/guest pair, which alone bounds every layout
/// whose guest paths come from a finite set — but a literal alias derives
/// a *new* guest path from link text, so a pathological chain of relative
/// links could keep minting pairs. This cap is what bounds that; 40 is
/// deep enough for any real skill farm while still stopping a runaway.
const MAX_LINK_DEPTH: usize = 40;

/// A directory in both the worlds the follow-links walk straddles: where
/// it really lives on the host, and the path the guest reaches it by.
///
/// The two coincide for an ordinary mirror bind. They diverge inside a
/// *literal alias* — a second bind of one host directory at the path some
/// link's raw text names (see [`literal_guest_path`]) — and the walk has
/// to carry both, because a relative symlink found inside that directory
/// resolves against whichever path the guest entered by, not against the
/// host's canonical one.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BindPath {
    host: PathBuf,
    guest: PathBuf,
    /// Exclusions projected into this bind root's logical tree. A followed
    /// directory receives only the suffixes below the link that reached it.
    exclusions: Vec<PathBuf>,
}

impl BindPath {
    /// One host directory bound at its own real path — the ordinary case.
    #[cfg(test)]
    fn mirrored(path: PathBuf) -> BindPath {
        BindPath {
            host: path.clone(),
            guest: path,
            exclusions: Vec::new(),
        }
    }

    /// Descend into `name` on both sides at once.
    fn join(&self, name: &std::ffi::OsStr) -> BindPath {
        BindPath {
            host: self.host.join(name),
            guest: self.guest.join(name),
            exclusions: self.exclusions.clone(),
        }
    }
}

impl From<BindPath> for ExtraMount {
    /// Discovered binds retain their read-only follow policy. They are
    /// appended after discovery, so the marker cannot trigger another pass.
    fn from(p: BindPath) -> ExtraMount {
        ExtraMount {
            // A discovered bind is not a declaration: this is a canonical target
            // the walk measured. It carries no declaration text at all, which is why
            // every renderer escapes control characters rather than trusting that
            // the bytes here were typed by someone.
            source_spelling: Spelling::new(p.host.display().to_string()),
            spelled_host: p.host.clone(),
            host: p.host,
            guest: p.guest,
            policy: MountPolicy::BindReadOnly { follow_links: true },
            exclusions: p.exclusions,
        }
    }
}

/// Join a symlink's raw target text against the directory holding the link
/// and fold `.`/`..` *lexically*, i.e. as pure string surgery with no
/// filesystem lookups.
///
/// Folding this way models a kernel's resolution only while no `..`
/// crosses a symlinked component — the kernel expands a symlink *before*
/// applying the `..` that follows it, so the two answers part company
/// exactly there. [`literal_guest_path`] is what detects that divergence;
/// this function's contract is only the string operation. `None` when the
/// link has no parent or a `..` escapes above the root.
fn lexical_link_path(link: &Path, raw_target: &Path) -> Option<PathBuf> {
    use std::path::Component;

    let joined = if raw_target.is_absolute() {
        raw_target.to_path_buf()
    } else {
        link.parent()?.join(raw_target)
    };
    let mut out = PathBuf::new();
    for comp in joined.components() {
        match comp {
            Component::Prefix(p) => out.push(p.as_os_str()),
            Component::RootDir => out.push(Component::RootDir.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    return None;
                }
            }
            Component::Normal(seg) => out.push(seg),
        }
    }
    Some(out)
}

/// What [`literal_guest_path`] concluded about one symlink's raw target
/// text. `Declined` is not a failure — the walk carries on and surfaces
/// the warning — which is why this is an enum and not a `Result`.
enum LiteralPath {
    /// The mirror bind at the canonical path already covers this link:
    /// the guest resolves the text to exactly the directory the host did.
    AlreadyCovered,
    /// The guest resolves the text to this path instead, so the same host
    /// directory needs a second bind here.
    MirrorAt(PathBuf),
    /// Cannot be mirrored safely; carries the warning to surface.
    Declined(String),
}

/// One `Declined` warning, phrased alike for every reason: name the
/// symlink, give the reason, state what it costs the user. Every path in it is
/// rendered for `declaration`, so a newline in a config-mount path cannot forge
/// a warning line.
fn declined(declaration: Declaration<'_>, link: &Path, reason: String) -> String {
    format!(
        "not mirroring symlink {} — {reason}; it may not resolve inside the sandbox",
        declaration.host_path(link)
    )
}

/// Where the guest will look when it resolves the symlink `link`, given
/// that the host resolves it to `canonical`.
///
/// The guest sees the link verbatim through an enclosing bind, so its
/// `readlink()` returns the raw target text and the guest kernel resolves
/// *that*, starting from `link.guest`'s parent. The host's canonicalized
/// answer names the same directory only when every component of the text
/// is already a real directory the guest can walk. When an intermediate
/// component is itself a symlink, the guest never reaches the canonical
/// path at all:
///
/// ```text
/// ~/.claude/skills/implement -> ~/code/conf/.agents/skills/implement   (raw text)
/// ~/code/conf/.agents/skills -> ../skills                              (parent link)
/// canonical                   = ~/code/conf/skills/implement
/// ```
///
/// Binding only `~/code/conf/skills/implement` leaves the guest looking up
/// `~/code/conf/.agents/…`, which nothing is mounted at. A second bind of
/// the same real directory at the literal path closes the gap: agentd
/// creates a mount point's missing ancestors before binding it, so the
/// `.agents/skills` directories come into being on the way. (Ancestors
/// that would land inside an already-read-only bind cannot be created;
/// that surfaces as a boot error rather than as silent breakage.)
///
/// [`LiteralPath::Declined`] covers text we will not mirror:
/// - text whose `..` cannot be folded without consulting the filesystem,
///   because a `..` crosses a symlinked component. The kernel expands the
///   symlink first, so no single mount point reproduces its answer and
///   the honest move is to warn rather than bind somewhere merely
///   plausible. Detected by folding on the host side, where the result
///   can be checked against `canonical`.
/// - a mount point outside `home`, which would let a link inside `$HOME`
///   place a bind anywhere in the guest's filesystem.
fn literal_guest_path(
    link: &BindPath,
    canonical: &Path,
    home: &Path,
    declaration: Declaration<'_>,
) -> LiteralPath {
    let raw = match fs::read_link(&link.host) {
        Ok(r) => r,
        Err(e) => {
            return LiteralPath::Declined(declined(
                declaration,
                &link.host,
                format!("its target text could not be read: {e}"),
            ));
        }
    };
    // The same fold applied twice: on the host side purely so the result
    // can be checked against `canonical`, on the guest side for the answer
    // we actually want. Agreement on the host therefore transfers to the
    // guest, which is what lets an alias deep inside the walk be trusted.
    let (Some(on_host), Some(on_guest)) = (
        lexical_link_path(&link.host, &raw),
        lexical_link_path(&link.guest, &raw),
    ) else {
        return LiteralPath::Declined(declined(
            declaration,
            &link.host,
            format!(
                "its target {} folds above the filesystem root",
                declaration.host_path(&raw)
            ),
        ));
    };
    if on_guest == canonical {
        return LiteralPath::AlreadyCovered;
    }
    if on_host.canonicalize().ok().as_deref() != Some(canonical) {
        return LiteralPath::Declined(declined(
            declaration,
            &link.host,
            format!(
                "its target text does not name {} on the host",
                declaration.host_path(canonical)
            ),
        ));
    }
    if !on_guest.starts_with(home) {
        return LiteralPath::Declined(declined(
            declaration,
            &link.host,
            format!(
                "the guest would look it up at {}, outside your $HOME ({})",
                declaration.host_path(&on_guest),
                declaration.host_path(home)
            ),
        ));
    }
    LiteralPath::MirrorAt(on_guest)
}

/// Walk `root` (already canonicalized) on the host side and return the
/// binds needed to make the symlinks it transitively contains resolve
/// inside the guest, plus warnings for anything skipped along the way
/// (symlink-to-file, dangling symlink, unreadable subdirectory, depth-cap
/// hit, un-mirrorable literal path).
///
/// Every canonicalized *directory* target gets a mirror bind at its own
/// real path, and a target whose link text reaches it through a symlinked
/// parent gets a second bind at that literal path as well — the guest
/// resolves link text, not canonical paths (see [`literal_guest_path`]).
/// A target bound at such an alias is then walked *again* under that
/// alias, because a relative symlink inside it resolves against the path
/// the guest entered by. Entries are distinct by guest path.
///
/// `root` carries both sides for the same reason: the mount it came from
/// may name a guest path that differs from the host directory — either
/// explicitly (`--mount HOST:GUEST:follow-links`) or, far more commonly,
/// because `HOST` was itself a symlink and `parse_extra_mounts`
/// canonicalized it while leaving `GUEST` as typed. A relative link
/// directly under such a root resolves against the guest side, so that is
/// what the walk has to track.
///
/// Returning warnings as data instead of `eprintln!`ing them keeps this
/// function side-effect-free so tests can assert on the warning text, not
/// just on what got left out of the returned target list — see
/// `discover_file_target_skipped`/`discover_dangling_skipped`. The caller
/// (`expand_follow_links`, and ultimately `launch()`) decides how/whether
/// to print them.
///
/// `home` is the invoking user's already-canonicalized `$HOME`. A resolved
/// directory target outside it is a hard error naming both the symlink and
/// the target (safety guardrail — see issue #9/#11).
///
/// `declaration` is the mount this walk expanded: every path in a warning or in
/// that refusal is rendered for it, so a config entry's spelling — which is the
/// text its paths are built from — cannot forge a line. The warnings carry no
/// attribution of their own: they describe what the walk skipped, not a
/// declaration, and a launch prints them inside the context naming the file.
fn discover_followed_targets(
    root: &BindPath,
    home: &Path,
    declaration: Declaration<'_>,
) -> Result<(Vec<BindPath>, Vec<String>)> {
    let mut visited: std::collections::HashSet<BindPath> = std::collections::HashSet::new();
    let mut out: Vec<BindPath> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    // (directory to scan — host side, plus the guest path it is reached
    // by — and the symlink-follow depth so far).
    let mut worklist: Vec<(BindPath, PathBuf, usize)> = vec![(root.clone(), PathBuf::new(), 0)];

    while let Some((dir, logical_relative, link_depth)) = worklist.pop() {
        // Keyed on the host/guest pair, not the host path alone: one real
        // directory reached by two different guest paths has to be walked
        // twice, since a relative symlink inside it resolves against the
        // path the guest entered by. Two symlinks resolving to the same
        // pair (or a symlink back to an already-walked ancestor) collapse
        // to one entry here, which is what actually terminates cycles —
        // the depth cap above is a secondary bound.
        if !visited.insert(dir.clone()) {
            continue;
        }
        let entries = match fs::read_dir(&dir.host) {
            Ok(e) => e,
            Err(e) => {
                // A permission-denied (or otherwise unreadable) subdir must
                // not abort the whole launch — warn and move on.
                warnings.push(format!(
                    "skipping unreadable directory {}: {e}",
                    declaration.host_path(&dir.host)
                ));
                continue;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    warnings.push(format!(
                        "skipping unreadable entry under {}: {e}",
                        declaration.host_path(&dir.host)
                    ));
                    continue;
                }
            };
            let path = dir.join(&entry.file_name());
            // Exclusions are evaluated in the declaration's logical tree
            // before metadata or link resolution.  In particular, a hidden
            // symlink cannot cause a follow-links bind to widen visibility.
            let child_relative = logical_relative.join(entry.file_name());
            if is_excluded(&child_relative, &dir.exclusions) {
                continue;
            }
            // lstat (no follow) so we can tell "is a symlink" from "is a
            // real dir/file" without resolving anything yet.
            let meta = match fs::symlink_metadata(&path.host) {
                Ok(m) => m,
                Err(e) => {
                    warnings.push(format!(
                        "skipping {}: {e}",
                        declaration.host_path(&path.host)
                    ));
                    continue;
                }
            };
            if !meta.file_type().is_symlink() {
                if meta.is_dir() {
                    // Already visible via the HOST bind (or a discovered
                    // parent's own bind) — don't add it to `out`, just
                    // descend to find symlinks nested further down.
                    // Directory nesting does not consume `link_depth`.
                    worklist.push((path, child_relative.clone(), link_depth));
                }
                // A plain file is already visible via the HOST bind too;
                // nothing to do.
                continue;
            }
            if link_depth >= MAX_LINK_DEPTH {
                warnings.push(format!(
                    "skipping symlink {} — exceeded max follow depth ({MAX_LINK_DEPTH}); \
                     possible pathological symlink chain",
                    declaration.host_path(&path.host)
                ));
                continue;
            }
            let target = match path.host.canonicalize() {
                Ok(t) => t,
                Err(_) => {
                    warnings.push(format!(
                        "skipping dangling symlink {}",
                        declaration.host_path(&path.host)
                    ));
                    continue;
                }
            };
            let target_meta = match fs::metadata(&target) {
                Ok(m) => m,
                Err(e) => {
                    warnings.push(format!(
                        "skipping symlink {} -> {}: {e}",
                        declaration.host_path(&path.host),
                        declaration.host_path(&target)
                    ));
                    continue;
                }
            };
            if !target_meta.is_dir() {
                warnings.push(format!(
                    "skipping symlink {} -> {} (not a directory)",
                    declaration.host_path(&path.host),
                    declaration.host_path(&target)
                ));
                continue;
            }
            if !target.starts_with(home) {
                anyhow::bail!(
                    "{} follow-links: symlink {} resolves to {}, which is outside your \
                     $HOME ({}); refusing to mount it",
                    declaration.subject(),
                    declaration.host_path(&path.host),
                    declaration.host_path(&target),
                    declaration.host_path(home)
                );
            }
            // Dedup within this walk on the guest path — the one thing
            // that has to be unique, since it is the mount point. Note
            // this does not special-case a target that lands *inside*
            // `root` or another already-discovered target (see
            // `expand_follow_links` doc) — that's a redundant-but-harmless
            // extra bind at its own real path, not a correctness issue.
            let mut push_unique_guest = |b: BindPath| {
                if let Some(existing) = out.iter_mut().find(|d| d.guest == b.guest) {
                    // One target can be reached through more than one
                    // logical link. Keep the union: dropping the later
                    // projected exclusion would let that alias bypass its
                    // opaque mask.
                    for exclusion in b.exclusions {
                        if !existing.exclusions.contains(&exclusion) {
                            existing.exclusions.push(exclusion);
                        }
                    }
                    existing.exclusions.sort();
                    existing.exclusions.dedup();
                } else {
                    out.push(b);
                }
            };
            let projected_exclusions = project_exclusions(&dir.exclusions, &child_relative);
            let mirror = BindPath {
                host: target.clone(),
                guest: target.clone(),
                exclusions: projected_exclusions.clone(),
            };
            push_unique_guest(mirror.clone());
            worklist.push((mirror, PathBuf::new(), link_depth + 1));
            // …and again at the path the guest's own `readlink()` will
            // name, when a symlinked parent makes that differ. The alias
            // is walked too: a relative symlink inside `target` resolves
            // against whichever of the two paths the guest came in by, so
            // the alias needs its own pass to discover its own aliases.
            match literal_guest_path(&path, &target, home, declaration) {
                LiteralPath::AlreadyCovered => {}
                LiteralPath::MirrorAt(guest) => {
                    let alias = BindPath {
                        host: target,
                        guest,
                        exclusions: projected_exclusions,
                    };
                    push_unique_guest(alias.clone());
                    worklist.push((alias, PathBuf::new(), link_depth + 1));
                }
                LiteralPath::Declined(w) => warnings.push(w),
            }
        }
    }
    Ok((out, warnings))
}

/// The refusal for a guest path two different declarations claim.
///
/// Two argv declarations keep the historical sentence (`--mount: guest path …
/// (host and host)`), rendering each path through the one-line policy: for an
/// ordinary path that is byte-for-byte the old `Path::display`, and a control
/// character can no longer end the line — one side may be a followed bind, whose
/// paths the walk measured. As soon as one
/// side is a config entry the sentence names each side's declaration and renders
/// each spelling for its own source, because a config spelling is
/// attacker-chosen text: printed bare, the host it expands to could forge a
/// second diagnostic line, and the entry would go unnamed.
///
/// A `:follow-links`-discovered bind is appended after the declarations and is
/// not one, so the caller passes [`Declaration::Argv`] for that side and this
/// sentence names it `--mount "<discovered path>"`. That is deliberate: naming a
/// candidate declaration could blame one that did not contribute the bind — the
/// same reason [`discovered_by`] names no single entry when there are several.
fn claim_conflict(
    existing: &ExtraMount,
    other: &ExtraMount,
    origins: &DeclaredOrigins,
    other_declaration: Declaration<'_>,
) -> anyhow::Error {
    let existing_declaration = declaration_origin(existing, origins);
    match (existing_declaration, other_declaration) {
        (Declaration::Argv, Declaration::Argv) => anyhow::anyhow!(
            "--mount: guest path {} is claimed by different declarations ({} and {})",
            crate::one_line::path(&other.guest),
            crate::one_line::path(&existing.host),
            crate::one_line::path(&other.host)
        ),
        _ => anyhow::anyhow!(
            "guest path {} is claimed by different declarations ({} and {})",
            other.guest.display(),
            claim_clause(existing_declaration, existing),
            claim_clause(other_declaration, other)
        ),
    }
}

/// One side of a claim conflict: the declaration that made it and the spelling it
/// made it with.
///
/// Both sides are escaped here, whichever source they came from: this sentence
/// only exists in mixed or config form, so there are no argv bytes to preserve,
/// and even the argv side may be a `:follow-links`-discovered bind, whose
/// spelling is a path the walk measured rather than text a user typed.
fn claim_clause(declaration: Declaration<'_>, mount: &ExtraMount) -> String {
    #[allow(clippy::disallowed_methods)] // `quoted_path` escapes; nothing is printed raw.
    let spelling = mount.source_spelling.as_source_path();
    format!("{} {}", declaration.subject(), quoted_path(spelling))
}

/// Given the parsed mounts, append the auto-discovered read-only mounts for
/// every `follow_links` entry, then dedup identical mounts and reject
/// guest-path collisions. `home` is the invoking user's `$HOME` (or `None`
/// when unset). If any entry has `follow_links` and `home` is `None`, this
/// is a hard error (the guardrail can't run without a `$HOME`); when no
/// entry follows links, `home` is unused and `None` is fine. Pure w.r.t.
/// the sandbox; touches only the filesystem under the mounted trees.
///
/// Returns the finalized mount list plus every warning collected while
/// discovering targets, for the caller to print (see `launch()`).
///
/// Each walk is rooted at the entry's host *and* guest path, so relative
/// link text under a root whose two sides differ — a remapped
/// `--mount HOST:GUEST`, or a `HOST` that was itself a symlink — resolves
/// the way the guest will resolve it.
///
/// `origins` is [`prepare`]'s declaration map, read to name the declaration a
/// canonicalization failure or a guest-path conflict belongs to, and to pick the
/// rendering each walk's diagnostics use.
pub(crate) fn expand_follow_links(
    mounts: Vec<ExtraMount>,
    origins: &DeclaredOrigins,
    home: Option<&Path>,
) -> Result<(Vec<ExtraMount>, Vec<String>)> {
    let mut mounts = mounts;
    // Live bind roots retain historical canonical-path behavior. Fork data
    // is already an owned committed path and is intentionally not resolved.
    for mount in mounts.iter_mut().filter(|m| !m.is_fork()) {
        mount.host = mount.host.canonicalize().with_context(|| {
            canonicalizing_context(declaration_origin(mount, origins), &mount.source_spelling)
        })?;
    }
    if !mounts.iter().any(|m| m.follows_links() && !m.is_fork()) {
        return Ok((mounts, Vec::new()));
    }
    let home = home.context(
        "$HOME is not set — required for --mount follow-links (pass --root to run as root \
         instead, or drop follow-links)",
    )?;
    // Canonicalize once so the guardrail's `starts_with` comparison is
    // real-path vs. real-path (macOS `/var` vs `/private/var`, etc.).
    let home_canon = home.canonicalize().unwrap_or_else(|_| home.to_path_buf());

    let mut warnings = Vec::new();
    // Every element so far is a declaration; everything appended below is a
    // discovered bind, which is not one (see the finalize loop).
    let declared_count = mounts.len();
    let mut expanded = mounts;
    let mut discovered_targets: Vec<BindPath> = Vec::new();
    for m in &expanded {
        if !m.follows_links() || m.is_fork() {
            continue;
        }
        let root = BindPath {
            host: m.host.clone(),
            guest: m.guest.clone(),
            exclusions: m.exclusions.clone(),
        };
        let (targets, mut w) =
            discover_followed_targets(&root, &home_canon, declaration_origin(m, origins))?;
        warnings.append(&mut w);
        discovered_targets.extend(targets);
    }
    // The original follow-links mount (the HOST bind itself) stays in the
    // list unchanged; this appends one read-only mount per distinct
    // discovered guest path — the target's own real path, plus the literal
    // path a symlinked parent makes the guest look up (see
    // `literal_guest_path`).
    expanded.extend(discovered_targets.into_iter().map(ExtraMount::from));

    // Finalize across the whole resulting list: dedup a guest path that
    // repeats with the *same* host (two symlinks resolving to the same
    // real path, or the same target discovered from two separate
    // `--mount …:follow-links` entries); hard-error a guest path claimed
    // by two *different* hosts. Preserve first-seen order for stable,
    // testable output and stable `==> Mounting …` log ordering.
    let mut finalized = Vec::with_capacity(expanded.len());
    for (index, mount) in expanded.into_iter().enumerate() {
        // A discovered bind is not a declaration. `origin` is keyed by guest
        // path and a discovered target can land on a *declared* one — that is
        // exactly the conflict below — so asking the map would attribute the
        // bind to an entry that did not discover it. Those elements are appended
        // after the declarations, so the split is positional.
        let declaration = if index < declared_count {
            declaration_origin(&mount, origins)
        } else {
            Declaration::Argv
        };
        if let Some(existing) = finalized
            .iter_mut()
            .find(|existing: &&mut ExtraMount| existing.guest == mount.guest)
        {
            // A target can be both an explicit declaration and a discovered
            // canonical/literal alias.  Keep the logical exclusions from
            // every route: dropping those on the already-present explicit
            // declaration lets an alias bypass an opaque mask.  `ro` and
            // discovered `ro:follow-links` have the same bind access; retain
            // follow-links if either route needs its safe alias behavior.
            if existing.host == mount.host && existing.is_readonly() && mount.is_readonly() {
                existing.policy = MountPolicy::BindReadOnly {
                    follow_links: existing.follows_links() || mount.follows_links(),
                };
                merge_exclusions(&mut existing.exclusions, mount.exclusions);
                continue;
            }
            if existing.host == mount.host && existing.policy == mount.policy {
                merge_exclusions(&mut existing.exclusions, mount.exclusions);
                continue;
            }
            return Err(claim_conflict(existing, &mount, origins, declaration));
        }
        finalized.push(mount);
    }
    Ok((finalized, warnings))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_extra_mounts ───────────────────────────────────────

    #[test]
    fn parse_extra_mounts_mirror_form() {
        // Mirror form: HOST alone → guest = host. Resolve against
        // cwd so the host path canonicalize succeeds in the test.
        // Use `/` which always exists.
        let parsed = parse_extra_mounts(&["/".into()]).expect("ok");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].host, std::path::Path::new("/"));
        assert_eq!(parsed[0].guest, std::path::Path::new("/"));
    }

    #[test]
    fn parse_extra_mounts_remap_form() {
        let parsed = parse_extra_mounts(&["/:/guest-mount".into()]).expect("ok");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].host, std::path::Path::new("/"));
        assert_eq!(parsed[0].guest, std::path::Path::new("/guest-mount"));
    }

    #[test]
    fn parse_extra_mounts_rejects_relative_paths() {
        assert!(parse_extra_mounts(&["relative-host".into()]).is_err());
        assert!(parse_extra_mounts(&["/abs-host:relative-guest".into()]).is_err());
        assert!(parse_extra_mounts(&["relative-host:/abs-guest".into()]).is_err());
    }

    #[test]
    fn parse_extra_mounts_rejects_empty_side() {
        assert!(parse_extra_mounts(&[":/guest".into()]).is_err());
        assert!(parse_extra_mounts(&["/host:".into()]).is_err());
        assert!(parse_extra_mounts(&["".into()]).is_err());
    }

    #[test]
    fn parse_extra_mounts_defers_missing_source_for_ready_fork_reuse() {
        // Parsing is intentionally source-I/O free: a READY fork can be
        // reused after its original source disappears.
        let r = parse_extra_mounts(&["/this/path/does/not/exist/anywhere:fork".into()]);
        assert!(r.is_ok());
    }

    #[test]
    fn parse_extra_mounts_allows_non_ascii_guest_rejects_control_chars() {
        // A non-ASCII guest mount point now travels via the boot-params
        // side channel (not the cmdline), so it is accepted and mirrored.
        // Host `/` exists so canonicalize succeeds.
        let parsed = parse_extra_mounts(&["/:/монтаж".into()]).expect("non-ASCII guest is ok");
        assert_eq!(parsed[0].guest, std::path::Path::new("/монтаж"));
        // Plain ASCII guest path still works.
        assert!(parse_extra_mounts(&["/:/mnt/ref".into()]).is_ok());
        // A control char (TAB) would break the KEY\tVALUE boot-params
        // framing, so it's rejected with guidance.
        let err = parse_extra_mounts(&["/:/mnt/a\tb".into()])
            .expect_err("control char in guest path must be rejected")
            .to_string();
        assert!(
            err.contains("control characters"),
            "error should call out control characters, got: {err}"
        );
    }

    // ── parse_extra_mounts: `[:ro|:rw]` mode suffixes ─────────────

    #[test]
    fn parse_extra_mounts_mode_defaults_readwrite() {
        // AC-1: unchanged behavior for the pre-existing forms, plus the
        // new `readonly` field defaulting false.
        let parsed = parse_extra_mounts(&["/".into()]).expect("ok");
        assert!(!parsed[0].is_readonly());
        let parsed = parse_extra_mounts(&["/:/g".into()]).expect("ok");
        assert_eq!(parsed[0].guest, std::path::Path::new("/g"));
        assert!(!parsed[0].is_readonly());
    }

    #[test]
    fn parse_extra_mounts_ro_no_guest() {
        let parsed = parse_extra_mounts(&["/:ro".into()]).expect("ok");
        assert_eq!(parsed[0].guest, std::path::Path::new("/"));
        assert!(parsed[0].is_readonly());
    }

    #[test]
    fn parse_extra_mounts_rw_no_guest() {
        let parsed = parse_extra_mounts(&["/:rw".into()]).expect("ok");
        assert_eq!(parsed[0].guest, std::path::Path::new("/"));
        assert!(!parsed[0].is_readonly());
    }

    #[test]
    fn parse_extra_mounts_guest_and_ro() {
        let parsed = parse_extra_mounts(&["/:/g:ro".into()]).expect("ok");
        assert_eq!(parsed[0].guest, std::path::Path::new("/g"));
        assert!(parsed[0].is_readonly());
    }

    #[test]
    fn parse_extra_mounts_guest_and_rw() {
        let parsed = parse_extra_mounts(&["/:/g:rw".into()]).expect("ok");
        assert_eq!(parsed[0].guest, std::path::Path::new("/g"));
        assert!(!parsed[0].is_readonly());
    }

    #[test]
    fn parse_extra_mounts_conflicting_modes_ro_then_rw() {
        let err = parse_extra_mounts(&["/:ro:rw".into()])
            .expect_err("ro:rw must conflict")
            .to_string();
        assert!(err.contains("conflicting"), "got: {err}");
        assert!(err.contains("ro") && err.contains("rw"), "got: {err}");
    }

    #[test]
    fn parse_extra_mounts_conflicting_modes_rw_then_ro() {
        // Same assertion, reversed order — proves order-independence.
        let err = parse_extra_mounts(&["/:rw:ro".into()])
            .expect_err("rw:ro must conflict")
            .to_string();
        assert!(err.contains("conflicting"), "got: {err}");
        assert!(err.contains("ro") && err.contains("rw"), "got: {err}");
    }

    #[test]
    fn parse_extra_mounts_unknown_mode() {
        let err = parse_extra_mounts(&["/:bogus-mode".into()])
            .expect_err("unknown mode must error")
            .to_string();
        assert!(err.contains("bogus-mode"), "got: {err}");
        assert!(err.contains("unknown"), "got: {err}");
    }

    #[test]
    fn parse_extra_mounts_guest_vs_mode_disambiguation() {
        // Leading '/' -> classified as GUEST, then ':ro' is a mode.
        let parsed = parse_extra_mounts(&["/:/mnt/ref:ro".into()]).expect("ok");
        assert_eq!(parsed[0].guest, std::path::Path::new("/mnt/ref"));
        assert!(parsed[0].is_readonly());

        // Leading '.' -> classified as GUEST too, then rejected by the
        // existing absolute-path check (not "unknown mode").
        let err = parse_extra_mounts(&["/:./rel:ro".into()])
            .expect_err("relative GUEST must be rejected")
            .to_string();
        assert!(err.contains("absolute"), "got: {err}");
        assert!(!err.contains("unknown mode"), "got: {err}");
    }

    #[test]
    fn parse_extra_mounts_extra_path_in_mode_position() {
        // Only one GUEST segment is accepted (the first); a second
        // path-shaped segment in mode position is an unknown keyword.
        let err = parse_extra_mounts(&["/:/g:/g2".into()])
            .expect_err("second path segment must be rejected")
            .to_string();
        assert!(err.contains("unknown mode keyword"), "got: {err}");
    }

    #[test]
    fn parse_extra_mounts_empty_middle_segment() {
        // A stray `::` should not surface as `unknown mode keyword ""`.
        let err = parse_extra_mounts(&["/::ro".into()])
            .expect_err("empty middle segment must be rejected")
            .to_string();
        assert!(!err.contains("unknown mode keyword \"\""), "got: {err}");
    }

    #[test]
    fn parse_extra_mounts_colon_in_guest_now_mode_error() {
        // Deliberate, documented deviation from the old first-colon-only
        // split: a trailing colon-separated token on a GUEST path is now
        // parsed as a mode separator, not kept literal in the guest path.
        let err = parse_extra_mounts(&["/:/mnt/ref:x".into()])
            .expect_err("trailing 'x' must be an unknown mode")
            .to_string();
        assert!(err.contains("unknown mode"), "got: {err}");
    }

    #[test]
    fn parse_fork_and_normalizes_exclusions() {
        // Both fork policies accept exclusions, regardless of suffix order.
        for entry in [
            "/:/guest:fork:exclude=cache:exclude=cache/a",
            "/:exclude=cache:exclude=cache/a:fork",
            "/:/guest:exclude=cache:fork",
        ] {
            let parsed = parse_extra_mounts(&[entry.into()]).expect("fork syntax");
            assert!(parsed[0].is_fork(), "{entry}");
            assert!(!parsed[0].is_readonly(), "{entry}");
            // Ancestor collapse keeps only `cache`.
            assert_eq!(
                parsed[0].exclusions,
                vec![PathBuf::from("cache")],
                "{entry}"
            );
        }
        // Duplicate and sibling entries dedup/sort without swallowing siblings.
        let parsed =
            parse_extra_mounts(&["/:fork:exclude=b:exclude=a:exclude=b:exclude=a/b".into()])
                .unwrap();
        assert_eq!(
            parsed[0].exclusions,
            vec![PathBuf::from("a"), PathBuf::from("b")]
        );
        // A nonexistent source never reaches the filesystem at parse time.
        assert!(parse_extra_mounts(&["/no/such/source:fork:exclude=x".into()]).is_ok());
        // Mode conflicts still win over exclusion validity.
        assert!(parse_extra_mounts(&["/:fork:rw:exclude=x".into()]).is_err());
        assert!(parse_extra_mounts(&["/:rw:follow-links:exclude=x".into()]).is_err());
        // Invalid REL values are rejected with the normalization error.
        for bad in [
            "exclude=",
            "exclude=/abs",
            "exclude=..",
            "exclude=a/../b",
            "exclude=.",
        ] {
            let error = parse_extra_mounts(&[format!("/:fork:{bad}")]).unwrap_err();
            assert!(error.to_string().contains("exclude"), "{bad}: {error:#}");
        }
    }

    #[test]
    fn parse_extra_mounts_rejects_live_exclusions_before_any_io() {
        // `:exclude` is fork-only. Every live-bind form rejects at parse,
        // including a nonexistent source (proving no filesystem lookup), and
        // regardless of where the suffix lands.
        for entry in [
            "/no/such/source:exclude=x",
            "/no/such/source:rw:exclude=x",
            "/no/such/source:ro:exclude=x",
            "/no/such/source:follow-links:exclude=x",
            "/no/such/source:exclude=x:ro",
            "/no/such/source:/guest:ro:exclude=x",
        ] {
            let error = parse_extra_mounts(&[entry.into()]).unwrap_err().to_string();
            assert!(
                error.contains(":exclude is only supported on :fork mounts"),
                "{entry}: {error}"
            );
        }
    }

    #[test]
    fn fork_is_seeded_once_and_exclusions_are_not_copied() {
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("visible"), "one").unwrap();
        fs::write(source.path().join("secret"), "no").unwrap();
        let store = tempfile::tempdir().unwrap();
        let raw = format!("{}:/guest:fork:exclude=secret", source.path().display());
        let mut mounts = parse_extra_mounts(&[raw]).unwrap();
        prepare_forks(
            &mut mounts,
            store.path(),
            &std::collections::HashMap::new(),
            &ProtectedHostFiles::measure(None).unwrap(),
            &DeclaredOrigins::new(),
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(mounts[0].host.join("visible")).unwrap(),
            "one"
        );
        assert!(!mounts[0].host.join("secret").exists());
        fs::write(source.path().join("visible"), "two").unwrap();
        let mut again = parse_extra_mounts(&[format!(
            "{}:/guest:fork:exclude=secret",
            source.path().display()
        )])
        .unwrap();
        prepare_forks(
            &mut again,
            store.path(),
            &std::collections::HashMap::new(),
            &ProtectedHostFiles::measure(None).unwrap(),
            &DeclaredOrigins::new(),
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(again[0].host.join("visible")).unwrap(),
            "one"
        );
    }

    // ── AC-5: parsed `ro` reaches the volume builder (boot-free) ──

    fn built_readonly(host: &str, ro: bool) -> bool {
        use microsandbox::sandbox::VolumeMount;
        let vm = configure_extra_mount(MountBuilder::new("/g"), host.into(), ro)
            .build()
            .expect("bind mount builds");
        match vm {
            VolumeMount::Bind { options, .. } => options.readonly,
            other => panic!("expected Bind mount, got {other:?}"),
        }
    }

    #[test]
    fn extra_mount_ro_propagates_readonly_into_built_volume() {
        let em = &parse_extra_mounts(&["/:ro".into()]).unwrap()[0];
        assert!(em.is_readonly());
        assert!(built_readonly(em.host.to_str().unwrap(), em.is_readonly()));

        let em_rw = &parse_extra_mounts(&["/:rw".into()]).unwrap()[0];
        assert!(!em_rw.is_readonly());
        assert!(!built_readonly(
            em_rw.host.to_str().unwrap(),
            em_rw.is_readonly()
        ));

        let em_def = &parse_extra_mounts(&["/".into()]).unwrap()[0];
        assert!(!built_readonly(
            em_def.host.to_str().unwrap(),
            em_def.is_readonly()
        ));
    }

    // ── follow-links: grammar/parse (issue #11) ────────────────────

    #[test]
    fn parse_follow_links_implies_readonly() {
        let parsed = parse_extra_mounts(&["/:follow-links".into()]).expect("ok");
        assert!(parsed[0].is_readonly());
        assert!(parsed[0].follows_links());
    }

    #[test]
    fn parse_follow_links_with_ro_ok() {
        let parsed =
            parse_extra_mounts(&["/:ro:follow-links".into()]).expect("ok, ro+follow-links coexist");
        assert!(parsed[0].is_readonly());
        assert!(parsed[0].follows_links());
    }

    #[test]
    fn parse_rw_follow_links_conflicts() {
        for entry in ["/:rw:follow-links", "/:follow-links:rw"] {
            let err = parse_extra_mounts(&[entry.into()])
                .expect_err("rw+follow-links must conflict")
                .to_string();
            assert!(err.contains("conflicting"), "got: {err}");
            assert!(
                err.contains("rw") && err.contains("follow-links"),
                "got: {err}"
            );
        }
    }

    #[test]
    fn parse_follow_links_with_guest() {
        let parsed = parse_extra_mounts(&["/:/g:follow-links".into()]).expect("ok");
        assert_eq!(parsed[0].guest, std::path::Path::new("/g"));
        assert!(parsed[0].is_readonly());
        assert!(parsed[0].follows_links());
    }

    #[test]
    fn parse_unknown_mode_lists_follow_links() {
        let err = parse_extra_mounts(&["/:bogus-mode".into()])
            .expect_err("unknown mode must error")
            .to_string();
        assert!(err.contains("follow-links"), "got: {err}");
    }

    // ── follow-links: discovery / expand (issue #11) ────────────────

    use std::os::unix::fs::symlink;

    /// Canonicalize a freshly-created tempdir's path up front — macOS
    /// resolves `/var` -> `/private/var`, so anything compared against
    /// `discover_followed_targets`'s (canonicalized) output needs to start
    /// from a canonical base.
    fn canon(p: &Path) -> PathBuf {
        p.canonicalize().expect("canonicalize")
    }

    /// Walk a root whose two sides coincide — the shape almost every
    /// discovery test wants. Tests about a root that was itself a symlink
    /// call `discover_followed_targets` with an explicit [`BindPath`].
    fn walk(host: &Path, home: &Path) -> Result<(Vec<BindPath>, Vec<String>)> {
        discover_followed_targets(
            &BindPath::mirrored(host.to_path_buf()),
            home,
            Declaration::Argv,
        )
    }

    /// The real host directories a walk found. Most discovery tests only
    /// care about that set; the ones about literal guest paths assert on
    /// [`BindPath::guest`] directly instead.
    fn hosts(found: &[BindPath]) -> Vec<PathBuf> {
        found.iter().map(|d| d.host.clone()).collect()
    }

    #[test]
    fn discover_direct_dir_symlink() {
        let home = tempfile::tempdir().unwrap();
        let home_path = canon(home.path());
        let host = home_path.join("host");
        let outside = home_path.join("outside_dir");
        fs::create_dir_all(&host).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, host.join("foo")).unwrap();

        let (found, warnings) = walk(&host, &home_path).expect("ok");
        assert_eq!(hosts(&found), vec![outside]);
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
    }

    #[test]
    fn discover_transitive() {
        let home = tempfile::tempdir().unwrap();
        let home_path = canon(home.path());
        let host = home_path.join("host");
        let a = home_path.join("a");
        let b = home_path.join("b");
        fs::create_dir_all(&host).unwrap();
        fs::create_dir_all(&a).unwrap();
        fs::create_dir_all(&b).unwrap();
        symlink(&a, host.join("foo")).unwrap();
        symlink(&b, a.join("bar")).unwrap();

        let (found, warnings) = walk(&host, &home_path).expect("ok");
        let mut targets = hosts(&found);
        targets.sort();
        let mut expected = vec![a, b];
        expected.sort();
        assert_eq!(
            targets, expected,
            "both the direct and transitive target must be discovered"
        );
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
    }

    // ── lexical_link_path: properties ───────────────────────────────

    proptest::proptest! {
        /// Whatever text a symlink holds, a folded path is usable as a
        /// mount point: absolute, and free of the `.`/`..` components a
        /// bind target cannot carry. Folding is also a fixed point, which
        /// is the property that makes it safe to fold the same raw text
        /// against two different directories (host and guest) and trust
        /// that agreement on one transfers to the other.
        #[test]
        fn lexical_link_path_folds_to_a_clean_absolute_fixed_point(
            link_segs in proptest::collection::vec("[a-z]{1,4}", 1..5),
            raw_segs in proptest::collection::vec("[a-z]{1,4}|\\.|\\.\\.", 0..6),
            raw_is_absolute in proptest::bool::ANY,
        ) {
            use proptest::prop_assert;
            use std::path::Component;

            let link = link_segs.iter().fold(PathBuf::from("/"), |a, s| a.join(s));
            let base = if raw_is_absolute { PathBuf::from("/") } else { PathBuf::new() };
            let raw = raw_segs.iter().fold(base, |a, s| a.join(s));

            if let Some(folded) = lexical_link_path(&link, &raw) {
                prop_assert!(folded.is_absolute(), "{folded:?}");
                prop_assert!(
                    folded
                        .components()
                        .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
                    "{folded:?} still carries . or .. components"
                );
                prop_assert!(
                    lexical_link_path(&link, &folded).as_ref() == Some(&folded),
                    "folding {folded:?} again changed it"
                );
            }
        }
    }

    #[test]
    fn discover_binds_literal_path_through_a_symlinked_parent() {
        // The `~/.claude/skills` shape: the link's raw target text runs
        // through `.agents/skills`, which is itself a symlink, so the
        // canonical path the host resolves to is NOT the path the guest
        // will look up.
        let home = tempfile::tempdir().unwrap();
        let home_path = canon(home.path());
        let host = home_path.join("host");
        let conf = home_path.join("conf");
        let real_dir = conf.join("skills").join("implement");
        let literal = conf.join(".agents").join("skills").join("implement");
        fs::create_dir_all(&host).unwrap();
        fs::create_dir_all(&real_dir).unwrap();
        fs::create_dir_all(conf.join(".agents")).unwrap();
        symlink("../skills", conf.join(".agents").join("skills")).unwrap();
        symlink(&literal, host.join("implement")).unwrap();

        let (found, warnings) = walk(&host, &home_path).expect("ok");
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        assert!(
            found
                .iter()
                .any(|d| d.host == real_dir && d.guest == real_dir),
            "the canonical target must still be bound at its own path, got: {found:?}"
        );
        assert!(
            found
                .iter()
                .any(|d| d.host == real_dir && d.guest == literal),
            "the same real directory must ALSO be bound at the literal path the \
             guest's readlink() names, got: {found:?}"
        );
    }

    #[test]
    fn discover_binds_relative_link_nested_inside_a_literal_alias() {
        // The same defect one level down: `implement` is reached through a
        // symlinked parent (so it gets an alias bind), and inside it a
        // *relative* link points out to a sibling. Entering via the alias,
        // the guest resolves `../shared` against the alias's parent — a
        // path the canonical binds never cover.
        //
        //   HOST/implement            -> $HOME/conf/.agents/skills/implement
        //   $HOME/conf/.agents/skills -> ../skills
        //   $HOME/conf/skills/implement/ref -> ../shared
        let home = tempfile::tempdir().unwrap();
        let home_path = canon(home.path());
        let host = home_path.join("host");
        let conf = home_path.join("conf");
        let implement = conf.join("skills").join("implement");
        let shared = conf.join("skills").join("shared");
        let alias_skills = conf.join(".agents").join("skills");
        fs::create_dir_all(&host).unwrap();
        fs::create_dir_all(&implement).unwrap();
        fs::create_dir_all(&shared).unwrap();
        fs::create_dir_all(conf.join(".agents")).unwrap();
        symlink("../skills", &alias_skills).unwrap();
        symlink(alias_skills.join("implement"), host.join("implement")).unwrap();
        symlink("../shared", implement.join("ref")).unwrap();

        let (found, warnings) = walk(&host, &home_path).expect("ok");
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        assert!(
            found
                .iter()
                .any(|d| d.host == shared && d.guest == alias_skills.join("shared")),
            "the sibling must be bound where the guest resolves `../shared` from \
             inside the alias ({}), got: {found:?}",
            alias_skills.join("shared").display()
        );
    }

    #[test]
    fn discover_resolves_relative_links_against_a_root_whose_guest_path_differs() {
        // The shape of the user's own invocation: `--mount ~/.claude/skills`
        // where `~/.claude/skills` is itself a symlink, so
        // `parse_extra_mounts` canonicalizes the host while the guest keeps
        // the path as typed. A relative link directly under that root
        // resolves against the *guest* side, one directory level away from
        // where the host resolves it.
        //
        //   root  host = $HOME/deep/realskills   guest = $HOME/skills
        //   $HOME/deep/realskills/foo -> ../shared
        //   host resolves  -> $HOME/deep/shared
        //   guest resolves -> $HOME/shared
        let home = tempfile::tempdir().unwrap();
        let home_path = canon(home.path());
        let real_dir = home_path.join("deep").join("realskills");
        let shared = home_path.join("deep").join("shared");
        fs::create_dir_all(&real_dir).unwrap();
        fs::create_dir_all(&shared).unwrap();
        symlink("../shared", real_dir.join("foo")).unwrap();

        let root = BindPath {
            host: real_dir.clone(),
            guest: home_path.join("skills"),
            exclusions: Vec::new(),
        };
        let (found, warnings) =
            discover_followed_targets(&root, &home_path, Declaration::Argv).expect("ok");
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        assert!(
            found
                .iter()
                .any(|d| d.host == shared && d.guest == home_path.join("shared")),
            "the target must be bound where the guest resolves `../shared` from the \
             root's guest path ({}), got: {found:?}",
            home_path.join("shared").display()
        );
    }

    #[test]
    fn discover_skips_literal_path_that_disagrees_with_host_resolution() {
        // Raw target `…/p/q/../target` where `p/q` is itself a symlink:
        // the kernel resolves `q` first, so `..` climbs out of `r`, not
        // out of `p`. Folding `..` lexically would name `…/p/target`,
        // which is a different (here: nonexistent) place — so we must
        // skip it with a warning rather than bind the directory there.
        let home = tempfile::tempdir().unwrap();
        let home_path = canon(home.path());
        let host = home_path.join("host");
        let target = home_path.join("target");
        let r = home_path.join("r");
        let p = home_path.join("p");
        fs::create_dir_all(&host).unwrap();
        fs::create_dir_all(&target).unwrap();
        fs::create_dir_all(&r).unwrap();
        fs::create_dir_all(&p).unwrap();
        symlink("../r", p.join("q")).unwrap();
        symlink(p.join("q").join("..").join("target"), host.join("x")).unwrap();

        let (found, warnings) = walk(&host, &home_path).expect("ok");
        assert_eq!(
            hosts(&found),
            vec![target.clone()],
            "the canonical target is still discovered"
        );
        assert!(
            found.iter().all(|d| d.guest == target),
            "no bind at the lexically-folded path, got: {found:?}"
        );
        assert!(
            warnings.iter().any(|w| w.contains("does not name")),
            "expected a warning that the literal path names something else, got: {warnings:?}"
        );
    }

    #[test]
    fn discover_skips_literal_path_outside_home() {
        // Canonical target is inside `$HOME` (so the hard guardrail is
        // happy), but the literal path the guest would look up is not —
        // binding there would let a link inside `$HOME` place a mount
        // anywhere in the guest.
        let root = tempfile::tempdir().unwrap();
        let root_path = canon(root.path());
        let home_path = root_path.join("h");
        let host = home_path.join("host");
        let real_dir = home_path.join("real");
        let outside = root_path.join("outside");
        fs::create_dir_all(&host).unwrap();
        fs::create_dir_all(&real_dir).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink("../h/real", outside.join("skills")).unwrap();
        symlink(outside.join("skills"), host.join("x")).unwrap();

        let (found, warnings) = walk(&host, &home_path).expect("ok");
        assert_eq!(hosts(&found), vec![real_dir.clone()]);
        assert!(
            found.iter().all(|d| d.guest == real_dir),
            "no bind at the outside-$HOME literal path, got: {found:?}"
        );
        assert!(
            warnings.iter().any(|w| w.contains("outside your $HOME")),
            "expected an outside-$HOME warning for the literal path, got: {warnings:?}"
        );
    }

    #[test]
    fn discover_terminates_on_cycle() {
        let home = tempfile::tempdir().unwrap();
        let home_path = canon(home.path());
        let host = home_path.join("host");
        let a = home_path.join("a");
        let b = home_path.join("b");
        fs::create_dir_all(&host).unwrap();
        fs::create_dir_all(&a).unwrap();
        fs::create_dir_all(&b).unwrap();
        symlink(&a, host.join("into_a")).unwrap();
        symlink(&b, a.join("x")).unwrap();
        symlink(&a, b.join("y")).unwrap();

        let (found, _warnings) = walk(&host, &home_path).expect("must terminate, not hang");
        let mut targets = hosts(&found);
        targets.sort();
        let mut expected = vec![a, b];
        expected.sort();
        assert_eq!(
            targets, expected,
            "each real path discovered exactly once despite the cycle"
        );
    }

    #[test]
    fn discover_self_referential_symlink() {
        let home = tempfile::tempdir().unwrap();
        let home_path = canon(home.path());
        let host = home_path.join("host");
        fs::create_dir_all(&host).unwrap();
        symlink(&host, host.join("loop")).unwrap();

        let (found, _warnings) = walk(&host, &home_path).expect("must terminate, not hang");
        assert_eq!(hosts(&found), vec![host]);
    }

    #[test]
    fn discover_file_target_skipped() {
        let home = tempfile::tempdir().unwrap();
        let home_path = canon(home.path());
        let host = home_path.join("host");
        fs::create_dir_all(&host).unwrap();
        let file = home_path.join("some_file");
        fs::write(&file, "hi").unwrap();
        symlink(&file, host.join("f")).unwrap();

        let (found, warnings) = walk(&host, &home_path).expect("ok, not an error");
        assert!(found.is_empty());
        assert!(
            warnings.iter().any(|w| w.contains("not a directory")),
            "expected a 'not a directory' warning, got: {warnings:?}"
        );
    }

    #[test]
    fn discover_dangling_skipped() {
        let home = tempfile::tempdir().unwrap();
        let home_path = canon(home.path());
        let host = home_path.join("host");
        fs::create_dir_all(&host).unwrap();
        symlink(home_path.join("nonexistent"), host.join("d")).unwrap();

        let (found, warnings) = walk(&host, &home_path).expect("ok, not an error");
        assert!(found.is_empty());
        assert!(
            warnings.iter().any(|w| w.contains("dangling")),
            "expected a dangling-symlink warning, got: {warnings:?}"
        );
    }

    #[test]
    fn discover_outside_home_errors() {
        let home = tempfile::tempdir().unwrap();
        let home_path = canon(home.path());
        // `home` for the guardrail is a *subdir*, so the symlink target
        // (a sibling of that subdir) resolves outside it.
        let narrow_home = home_path.join("subhome");
        let host = home_path.join("host");
        let outside = home_path.join("outside_dir");
        fs::create_dir_all(&narrow_home).unwrap();
        fs::create_dir_all(&host).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, host.join("foo")).unwrap();

        let err = walk(&host, &narrow_home)
            .expect_err("target outside $HOME must be a hard error")
            .to_string();
        assert!(
            err.contains(&host.join("foo").display().to_string()),
            "got: {err}"
        );
        assert!(err.contains(&outside.display().to_string()), "got: {err}");
    }

    #[test]
    fn expand_roots_the_walk_at_the_mounts_guest_path_not_just_its_host() {
        // Wiring test for the seam above `discover_followed_targets`: an
        // `ExtraMount` whose guest path differs from its host — which is
        // what `--mount ~/.claude/skills:follow-links` produces whenever
        // that path is itself a symlink — must have BOTH sides handed to
        // the walk, or relative link text is resolved against the wrong
        // directory and the discovered bind lands where the guest never
        // looks.
        let home = tempfile::tempdir().unwrap();
        let home_path = canon(home.path());
        let real_dir = home_path.join("deep").join("realskills");
        let shared = home_path.join("deep").join("shared");
        fs::create_dir_all(&real_dir).unwrap();
        fs::create_dir_all(&shared).unwrap();
        symlink("../shared", real_dir.join("foo")).unwrap();

        let mounts = vec![ExtraMount {
            source_spelling: Spelling::new(""),
            spelled_host: (real_dir).clone(),
            host: real_dir,
            guest: home_path.join("skills"),
            policy: MountPolicy::BindReadOnly { follow_links: true },
            exclusions: Vec::new(),
        }];
        let (expanded, warnings) =
            expand_follow_links(mounts, &DeclaredOrigins::new(), Some(&home_path)).expect("ok");
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        let want_guest = home_path.join("shared");
        assert!(
            expanded
                .iter()
                .any(|m| m.host == shared && m.guest == want_guest && m.is_readonly()),
            "expected {} bound read-only at {}, got: {:?}",
            shared.display(),
            want_guest.display(),
            expanded
                .iter()
                .map(|m| (&m.host, &m.guest))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn expand_dedups_same_realpath() {
        let home = tempfile::tempdir().unwrap();
        let home_path = canon(home.path());
        let host = home_path.join("host");
        let target = home_path.join("target");
        fs::create_dir_all(&host).unwrap();
        fs::create_dir_all(&target).unwrap();
        symlink(&target, host.join("a")).unwrap();
        symlink(&target, host.join("b")).unwrap();

        let mounts = vec![ExtraMount {
            source_spelling: Spelling::new(""),
            spelled_host: host.clone(),
            host: host.clone(),
            guest: host,
            policy: MountPolicy::BindReadOnly { follow_links: true },
            exclusions: Vec::new(),
        }];
        let (expanded, warnings) =
            expand_follow_links(mounts, &DeclaredOrigins::new(), Some(&home_path)).expect("ok");
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        let target_mounts: Vec<_> = expanded.iter().filter(|m| m.host == target).collect();
        assert_eq!(
            target_mounts.len(),
            1,
            "two symlinks resolving to the same real path must dedup to one mount"
        );
    }

    #[test]
    fn expand_guest_collision_errors() {
        let home = tempfile::tempdir().unwrap();
        let home_path = canon(home.path());
        let host = home_path.join("host");
        let target = home_path.join("target");
        let explicit_host = home_path.join("explicit-host");
        fs::create_dir_all(&host).unwrap();
        fs::create_dir_all(&target).unwrap();
        fs::create_dir_all(&explicit_host).unwrap();
        symlink(&target, host.join("a")).unwrap();

        let mounts = vec![
            ExtraMount {
                source_spelling: Spelling::new(""),
                spelled_host: host.clone(),
                host: host.clone(),
                guest: host,
                policy: MountPolicy::BindReadOnly { follow_links: true },
                exclusions: Vec::new(),
            },
            ExtraMount {
                // An explicit mount claims the discovered target's real
                // path as its GUEST, from a different HOST.
                source_spelling: Spelling::new(""),
                spelled_host: explicit_host.clone(),
                host: explicit_host.clone(),
                guest: target.clone(),
                policy: MountPolicy::BindReadWrite,
                exclusions: Vec::new(),
            },
        ];
        let err = expand_follow_links(mounts, &DeclaredOrigins::new(), Some(&home_path))
            .expect_err("two different hosts claiming the same guest must be a hard error")
            .to_string();
        assert!(err.contains(&target.display().to_string()), "got: {err}");
        assert!(
            err.contains(&explicit_host.display().to_string()),
            "got: {err}"
        );
    }

    #[test]
    fn expand_leaves_non_follow_mounts_untouched() {
        let mounts = vec![ExtraMount {
            source_spelling: Spelling::new(""),
            spelled_host: PathBuf::from("/"),
            host: "/".into(),
            guest: "/g".into(),
            policy: MountPolicy::BindReadWrite,
            exclusions: Vec::new(),
        }];
        let (expanded, warnings) = expand_follow_links(mounts, &DeclaredOrigins::new(), None)
            .expect("no follow-links entries, $HOME unneeded");
        assert_eq!(expanded.len(), 1);
        assert_eq!(expanded[0].guest, std::path::Path::new("/g"));
        assert!(warnings.is_empty());
    }

    #[test]
    fn expand_without_home_errors_only_when_follow_links_present() {
        let mounts = vec![ExtraMount {
            source_spelling: Spelling::new(""),
            spelled_host: PathBuf::from("/"),
            host: "/".into(),
            guest: "/".into(),
            policy: MountPolicy::BindReadOnly { follow_links: true },
            exclusions: Vec::new(),
        }];
        let err = expand_follow_links(mounts, &DeclaredOrigins::new(), None)
            .expect_err("follow-links with no $HOME must be a hard error")
            .to_string();
        assert!(err.contains("HOME"), "got: {err}");
    }

    #[test]
    fn discovered_mount_builds_readonly_bind_volume() {
        let home = tempfile::tempdir().unwrap();
        let home_path = canon(home.path());
        let host = home_path.join("host");
        let target = home_path.join("target");
        fs::create_dir_all(&host).unwrap();
        fs::create_dir_all(&target).unwrap();
        symlink(&target, host.join("a")).unwrap();

        let mounts = vec![ExtraMount {
            source_spelling: Spelling::new(""),
            spelled_host: host.clone(),
            host: host.clone(),
            guest: host,
            policy: MountPolicy::BindReadOnly { follow_links: true },
            exclusions: Vec::new(),
        }];
        let (expanded, _warnings) =
            expand_follow_links(mounts, &DeclaredOrigins::new(), Some(&home_path)).expect("ok");
        let discovered = expanded
            .iter()
            .find(|m| m.host == target)
            .expect("discovered target present in expanded list");
        assert!(discovered.is_readonly());
        assert!(built_readonly(
            discovered.host.to_str().unwrap(),
            discovered.is_readonly()
        ));
    }

    /// Every rejection `--mount` can produce today, byte for byte.
    ///
    /// The declaration grammar is about to be shared with user-config `mounts`
    /// (which must render value-free, index-named text for the same failures),
    /// so the parse moves behind a typed error. These pins are what prove that
    /// refactor cannot reword a CLI diagnostic: the other `--mount` parse tests
    /// only assert `contains`, which cannot see a changed sentence.
    ///
    /// The rendering pinned is `{:#}`, the full `anyhow` chain, because the
    /// `exclude=` context adds an outer frame that `Display` (`{}`) drops.
    /// An exhaustive pin is also what makes `HostSyntax` honest: a `~/x` host
    /// stays "must be absolute" on the CLI, so only the config route may ever
    /// expand it.
    #[test]
    fn cli_parse_errors_are_pinned() {
        const CASES: &[(&str, &str)] = &[
            (
                ":/guest",
                "--mount value \":/guest\" must be HOST[:GUEST] (non-empty)",
            ),
            ("", "--mount value \"\" must be HOST[:GUEST] (non-empty)"),
            (
                "relative-host",
                "--mount host path \"relative-host\" must be absolute",
            ),
            ("~/x", "--mount host path \"~/x\" must be absolute"),
            (
                "/host:./rel",
                "--mount guest path \"./rel\" must be absolute",
            ),
            (
                "/abs-host:relative-guest",
                "--mount \"/abs-host:relative-guest\": unknown mode keyword \"relative-guest\" (expected `ro`, `rw`, `fork`, `follow-links`, or `exclude=REL`)",
            ),
            (
                "/:/mnt/a\tb",
                "--mount guest path \"/mnt/a\\tb\" contains control characters that can't be carried into the guest; pass a guest path without tabs/newlines",
            ),
            (
                "/host:",
                "--mount \"/host:\": empty segment (stray `:`); expected HOST[:GUEST][:MODE]...",
            ),
            (
                "/h::ro",
                "--mount \"/h::ro\": empty segment (stray `:`); expected HOST[:GUEST][:MODE]...",
            ),
            (
                "/:bogus-mode",
                "--mount \"/:bogus-mode\": unknown mode keyword \"bogus-mode\" (expected `ro`, `rw`, `fork`, `follow-links`, or `exclude=REL`)",
            ),
            (
                "/:ro:rw",
                "--mount \"/:ro:rw\": conflicting modes `ro` and `rw` — pick one",
            ),
            (
                "/:rw:ro",
                "--mount \"/:rw:ro\": conflicting modes `rw` and `ro` — pick one",
            ),
            (
                "/x:fork:ro",
                "--mount \"/x:fork:ro\": conflicting modes `fork` and `ro` — pick one",
            ),
            (
                "/x:fork:follow-links:rw",
                "--mount \"/x:fork:follow-links:rw\": conflicting modes `fork` and `rw` — pick one",
            ),
            (
                "/x:fork:exclude=",
                "--mount \"/x:fork:exclude=\": exclude must be a non-empty relative path",
            ),
            (
                "/x:fork:exclude=..",
                "--mount \"/x:fork:exclude=..\": exclude must contain only normal relative components",
            ),
            (
                "/x:fork:exclude=./hidden",
                "--mount \"/x:fork:exclude=./hidden\": exclude must contain only normal relative components",
            ),
            (
                "/x:fork:exclude=a::b",
                "--mount \"/x:fork:exclude=a::b\": empty segment (stray `:`); expected HOST[:GUEST][:MODE]...",
            ),
            (
                "/x:exclude=hidden",
                "--mount /x:exclude=hidden: :exclude is only supported on :fork mounts;\nlive binds cannot hide nested paths.",
            ),
            (
                "/x:ro:exclude=hidden",
                "--mount /x:ro:exclude=hidden: :exclude is only supported on :fork mounts;\nlive binds cannot hide nested paths.",
            ),
        ];
        for (input, pinned) in CASES {
            let error = parse_extra_mounts(&[(*input).to_string()]).expect_err(input);
            assert_eq!(&format!("{error:#}"), pinned, "for --mount {input:?}");
            // A stray `:` in a whole-entry rejection must not be mistaken for
            // the excluded-path shape: only the exclusion contexts drop the
            // quoted entry from the outer frame.
            if !pinned.contains("exclude must") {
                assert_eq!(&format!("{error}"), pinned, "for --mount {input:?}");
            }
        }
        // The `exclude=` context is the outer frame, and the reason is the
        // cause: a refactor that returned the bare reason would keep `{:#}`
        // identical only by accident, so pin both frames separately.
        for (input, cause) in [
            (
                "/x:fork:exclude=",
                "exclude must be a non-empty relative path",
            ),
            (
                "/x:fork:exclude=..",
                "exclude must contain only normal relative components",
            ),
        ] {
            let error = parse_extra_mounts(&[(*input).to_string()]).expect_err(input);
            assert_eq!(format!("{error}"), format!("--mount {input:?}"));
            let mut chain = error.chain();
            assert_eq!(
                chain.next().map(ToString::to_string),
                Some(format!("--mount {input:?}"))
            );
            assert_eq!(
                chain.next().map(ToString::to_string),
                Some(cause.to_string())
            );
        }
    }

    // ── shared grammar and claim kernels ─────────────────────────

    /// `host_spelling` against an oracle written from the specification, not from
    /// the kernel: `Literal` exactly for a leading `/`, `ExpandHome` exactly for a
    /// leading `~/` *when expansion is enabled*, and `Refused` otherwise. The
    /// specs erase under a plain build, so this table is what says the decision
    /// is the right one.
    #[test]
    fn host_spelling_matches_the_oracle_table() {
        fn oracle(home: HomeExpansion, text: &str) -> HostSpelling {
            match (home, text.starts_with('/'), text.starts_with("~/")) {
                (_, true, _) => HostSpelling::Literal,
                (HomeExpansion::Enabled, false, true) => HostSpelling::ExpandHome,
                _ => HostSpelling::Refused,
            }
        }
        const TEXTS: &[&str] = &[
            "", "/", "//", "/x", "/ ", "~", "~/", "~/x", "~x", "x", "./x", "foo/bar", "~//x",
            "/~/x",
        ];
        for home in [HomeExpansion::Disabled, HomeExpansion::Enabled] {
            for text in TEXTS {
                assert_eq!(
                    host_spelling(text.as_bytes(), home),
                    oracle(home, text),
                    "for {home:?} {text:?}"
                );
            }
        }
    }

    /// `--mount` is absolute-only, so the `~/` expansion cannot be reached from
    /// argv at all: replacing the `home == HomeExpansion::Enabled` guard with a
    /// bare length check would turn a quoted `~/x` into an expansion instead of
    /// the "must be absolute" the shell contract promises.
    #[test]
    fn only_the_config_syntax_may_expand_a_tilde() {
        assert_eq!(
            parse_mount_spec("/x", HostSyntax::AbsoluteOnly)
                .expect("an absolute host is accepted")
                .source_spelling,
            "/x"
        );
        let error =
            parse_mount_spec("~/x", HostSyntax::AbsoluteOnly).expect_err("argv never expands `~`");
        assert_eq!(error.kind(), MountSpecErrorKind::HostNotAccepted);
        // The same text on the config route expands, and only there.
        let mount = parse_mount_spec(
            "~/x",
            HostSyntax::AbsoluteOrHome {
                home: Some("/home/u"),
            },
        )
        .expect("the config syntax expands `~/`");
        assert_eq!(mount.source_spelling, "/home/u/x");
    }

    /// A non-UTF-8 (or otherwise unusable) HOME is a rejection, never a silent
    /// relative path, and a caller cannot smuggle a relative host through the
    /// config syntax either.
    #[test]
    fn a_tilde_host_without_a_usable_home_is_refused() {
        // No usable HOME is its own kind — the config route tells the user the
        // entry needs a UTF-8 `$HOME` rather than blaming the path.
        let error = parse_mount_spec("~/x", HostSyntax::AbsoluteOrHome { home: None })
            .expect_err("a `~/` host cannot be expanded without a home");
        assert_eq!(error.kind(), MountSpecErrorKind::HomeUnavailable);
        // A *relative* home is a caller bug, not a user error: it must not produce
        // a relative host, so it falls back to the absolute-host rejection.
        let error = parse_mount_spec("~/x", HostSyntax::AbsoluteOrHome { home: Some("rel") })
            .expect_err("a relative home cannot make a relative host absolute");
        assert_eq!(error.kind(), MountSpecErrorKind::HostNotAccepted);
        let mount = parse_mount_spec(
            "~/x",
            HostSyntax::AbsoluteOrHome {
                home: Some("/home/u"),
            },
        )
        .expect("a usable home expands");
        assert_eq!(mount.source_spelling, "/home/u/x");
    }

    proptest::proptest! {
        /// `~/` is one substitution and nothing else: the expanded host is the
        /// caller's HOME followed by the declaration from the slash on, byte for
        /// byte. Canonicalizing, joining or substituting `$` would change the
        /// spelling `fork_id` hashes, i.e. silently switch forks.
        #[test]
        fn home_expansion_is_exact_concatenation(
            home_tail in proptest::collection::vec("[a-z]{1,6}", 1..4),
            rest in "[a-zA-Z0-9._/$-]{1,20}",
        ) {
            use proptest::prop_assert_eq;
            let home = format!("/home/{}", home_tail.join("/"));
            let mount = parse_mount_spec(
                &format!("~/{rest}"),
                HostSyntax::AbsoluteOrHome { home: Some(&home) },
            )
            .expect("a `~/` host is accepted by the config syntax");
            let expanded = format!("{home}/{rest}");
            prop_assert_eq!(&mount.source_spelling, &expanded);
            prop_assert_eq!(&mount.spelled_host, &PathBuf::from(&expanded));
            prop_assert_eq!(&mount.host, &mount.spelled_host);
            prop_assert_eq!(&mount.guest, &mount.host, "the mirror guest is the expanded host");
        }

        /// Differential: a config declaration and the argv declaration the
        /// *shell* would produce from it are one declaration. They merge rather
        /// than conflict, and they name one fork — which is the property that
        /// keeps provenance out of fork identity.
        #[test]
        fn config_and_shell_expanded_cli_declarations_are_identical(
            home_tail in proptest::collection::vec("[a-z]{1,6}", 1..4),
            rest in "[a-zA-Z0-9._/$-]{1,12}",
            guest in proptest::option::of("[a-z]{1,6}(/[a-z]{1,6}){0,2}"),
            mode in proptest::sample::select(vec!["ro", "rw", "fork", "follow-links"]),
            exclusion in proptest::option::of("[a-z]{1,6}"),
        ) {
            use proptest::prop_assert;
            use proptest::prop_assert_eq;
            let home = format!("/home/{}", home_tail.join("/"));
            let mut suffix = String::new();
            if let Some(guest) = &guest {
                suffix.push_str(&format!(":/{guest}"));
            }
            suffix.push_str(&format!(":{mode}"));
            // `:exclude` is fork-only, so it may only be generated there.
            if mode == "fork"
                && let Some(exclusion) = &exclusion
            {
                suffix.push_str(&format!(":exclude={exclusion}"));
            }
            let config_text = format!("~/{rest}{suffix}");
            let cli_text = format!("{home}/{rest}{suffix}");
            let from_config = parse_mount_spec(
                &config_text,
                HostSyntax::AbsoluteOrHome { home: Some(&home) },
            )
            .expect("the config syntax accepts it");
            let from_cli = parse_extra_mounts(std::slice::from_ref(&cli_text))
                .expect("argv accepts the shell-expanded text");
            prop_assert!(
                same_declaration(&from_config, &from_cli[0]),
                "{config_text:?} and {cli_text:?} are one declaration"
            );
            prop_assert_eq!(
                fork_id(&from_config, IDENTITY_VERSION),
                fork_id(&from_cli[0], IDENTITY_VERSION)
            );
        }
    }

    /// The merge/refuse rule, exhaustively: only a *shared guest path* with an
    /// equivalent declaration merges, and nothing but a shared path is distinct.
    /// This is the machine-checked "no last-wins, no CLI override" rule.
    #[test]
    fn claim_decision_matches_the_oracle_table() {
        for same_guest in [false, true] {
            for equivalent in [false, true] {
                let expected = match (same_guest, equivalent) {
                    (false, false) => ClaimDecision::Distinct,
                    (false, true) => ClaimDecision::Distinct,
                    (true, true) => ClaimDecision::Merge,
                    (true, false) => ClaimDecision::Conflict,
                };
                assert_eq!(
                    claim_decision(ClaimFacts {
                        same_guest,
                        equivalent
                    }),
                    expected,
                    "for same_guest={same_guest} equivalent={equivalent}"
                );
            }
        }
    }

    /// All 64 fact combinations, with the oracle counting the facts rather than
    /// restating the conjunction, so a transposed or dropped fact cannot pass.
    #[test]
    fn declarations_equivalent_matches_the_oracle_table() {
        for bits in 0u8..64 {
            let facts = [
                bits & 1 != 0,
                bits & 2 != 0,
                bits & 4 != 0,
                bits & 8 != 0,
                bits & 16 != 0,
                bits & 32 != 0,
            ];
            let [spelling, host, readonly, follow, fork, exclusions] = facts;
            assert_eq!(
                declarations_equivalent(DeclarationFacts {
                    spelling,
                    host,
                    readonly,
                    follow,
                    fork,
                    exclusions,
                }),
                facts.iter().all(|fact| *fact),
                "for {facts:?}"
            );
        }
    }

    /// One row per rejection `--mount` can produce, asserting the *kind* rather
    /// than the bytes (the bytes are pinned above). The config route renders its
    /// value-free sentence from the kind, so a mis-mapped rejection would send a
    /// user looking at the wrong field of their `mounts` list.
    #[test]
    fn every_rejection_reports_its_own_kind() {
        const CASES: &[(&str, MountSpecErrorKind)] = &[
            (":/guest", MountSpecErrorKind::EmptyHost),
            ("", MountSpecErrorKind::EmptyHost),
            ("relative-host", MountSpecErrorKind::HostNotAccepted),
            ("~/x", MountSpecErrorKind::HostNotAccepted),
            ("/host:./rel", MountSpecErrorKind::GuestNotAbsolute),
            ("/abs-host:relative-guest", MountSpecErrorKind::UnknownMode),
            ("/:/mnt/a\tb", MountSpecErrorKind::GuestUnmountable),
            ("/host:", MountSpecErrorKind::EmptySegment),
            ("/h::ro", MountSpecErrorKind::EmptySegment),
            ("/:bogus-mode", MountSpecErrorKind::UnknownMode),
            ("/:ro:rw", MountSpecErrorKind::ConflictingModes("ro", "rw")),
            (
                "/x:fork:ro",
                MountSpecErrorKind::ConflictingModes("fork", "ro"),
            ),
            ("/x:fork:exclude=", MountSpecErrorKind::BadExclusion),
            ("/x:fork:exclude=..", MountSpecErrorKind::BadExclusion),
            ("/x:fork:exclude=a::b", MountSpecErrorKind::EmptySegment),
            ("/x:exclude=hidden", MountSpecErrorKind::ExcludeOnLiveBind),
        ];
        for (entry, kind) in CASES {
            let error = parse_mount_spec(entry, HostSyntax::AbsoluteOnly)
                .expect_err("argv rejects it, so the shared grammar does too");
            assert_eq!(error.kind(), *kind, "for --mount {entry:?}");
            // The argv wrapper consumes exactly this error, so a rejection here is
            // a rejection on the `--mount` route.
            assert!(parse_extra_mounts(&[(*entry).to_string()]).is_err());
        }
    }

    fn config_origin(index: usize) -> MountOrigin {
        MountOrigin::UserConfig {
            file: PathBuf::from("/home/u/.config/agent-vm/config.toml"),
            index,
        }
    }

    fn request(origin: MountOrigin, entry: &str) -> MountRequest {
        MountRequest {
            origin,
            mount: parse_mount_spec(entry, HostSyntax::AbsoluteOnly)
                .expect("the test declaration parses"),
        }
    }

    /// The claim rule across sources, in the launch order (config first, then
    /// argv): identical declarations merge into the first-seen origin, differing
    /// ones are refused naming both origins, and distinct guest paths keep their
    /// order. The kept request carries the normalized guest.
    #[test]
    fn claim_merges_identical_and_refuses_differing_across_origins() {
        let merged = claim(
            vec![
                request(config_origin(0), "/host:/g:ro"),
                request(MountOrigin::Cli, "/host:/g//./:ro"),
            ],
            &[],
        )
        .expect("identical declarations merge");
        assert_eq!(merged.len(), 1);
        assert_eq!(
            merged[0].origin,
            config_origin(0),
            "the first-seen declaration is the one kept"
        );
        assert_eq!(merged[0].mount.guest, PathBuf::from("/g"));

        let error = claim(
            vec![
                request(config_origin(2), "/host:/g:ro"),
                request(MountOrigin::Cli, "/other:/g:ro"),
            ],
            &[],
        )
        .expect_err("differing declarations at one guest path are refused");
        assert_eq!(
            format!("{error}"),
            "guest path /g is claimed by different declarations \
             (mounts[2] in \"/home/u/.config/agent-vm/config.toml\" and --mount); \
             identical declarations are merged and different ones are refused"
        );

        let ordered = claim(
            vec![
                request(config_origin(0), "/a:/one:ro"),
                request(MountOrigin::Cli, "/b:/two:ro"),
                request(config_origin(1), "/c:/three:ro"),
            ],
            &[],
        )
        .expect("distinct guest paths are distinct claims");
        assert_eq!(
            ordered
                .iter()
                .map(|request| request.mount.guest.clone())
                .collect::<Vec<_>>(),
            vec![
                PathBuf::from("/one"),
                PathBuf::from("/two"),
                PathBuf::from("/three")
            ]
        );
    }

    /// A core path is refused before any claim is adjudicated, and the config
    /// rendering names the escape hatch while the argv rendering keeps today's
    /// sentence.
    #[test]
    fn a_core_collision_is_refused_by_origin() {
        let core = vec![PathBuf::from("/core")];
        let error = claim(vec![request(MountOrigin::Cli, "/host:/core:ro")], &core)
            .expect_err("a core path is not claimable");
        assert_eq!(
            format!("{error}"),
            "--mount guest path /core collides with an agent-vm core mount"
        );
        let error = claim(vec![request(config_origin(1), "/host:/core:ro")], &core)
            .expect_err("a core path is not claimable");
        assert_eq!(
            format!("{error}"),
            "mounts[1] in \"/home/u/.config/agent-vm/config.toml\": guest path /core \
             collides with an agent-vm core mount; pass --no-config-mounts to launch \
             without it"
        );
    }
}

/// A classified source used by the launch layer.  `prepare` is the only
/// operation which turns a request into one of these instructions; launch
/// must not restat or reinterpret it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PreparedVolumeSource {
    WritableBind(PathBuf),
    ReadOnlyBind(PathBuf),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PreparedNodeKind {
    File,
    Directory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VolumeRole {
    Explicit,
    Followed,
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedVolume {
    pub(crate) guest: PathBuf,
    pub(crate) source: PreparedVolumeSource,
    pub(crate) node_kind: PreparedNodeKind,
    pub(crate) role: VolumeRole,
}

#[derive(Clone, Debug)]
pub(crate) struct RepoScanRoot {
    pub(crate) host: PathBuf,
}

#[derive(Debug)]
pub(crate) struct PreparedMountPlan {
    pub(crate) volumes: Vec<PreparedVolume>,
    pub(crate) repo_scan_roots: Vec<RepoScanRoot>,
    pub(crate) notices: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct MountContext {
    pub(crate) mount_store: PathBuf,
    pub(crate) host_home: Option<PathBuf>,
    /// Raw authority HOME is distinct from Pi's UTF-8/account fallback.
    pub(crate) authority_home: Option<PathBuf>,
    pub(crate) account_home: Option<PathBuf>,
    /// Guest paths owned by agent-vm itself.  An explicit mount may not
    /// replace one: that would silently change HOME/project/state semantics.
    pub(crate) core_guest_mounts: Vec<PathBuf>,
    /// Host sources of agent-vm's own binds (guest HOME, project dir, state
    /// dir) with the role each one plays. Checked for Pi-file and config-directory exposure
    /// exactly like an explicit mount, because the project bind is the
    /// canonicalized cwd and is writable (`session.rs:45`): `cd ~ && agent-vm
    /// shell` would hand the guest the whole host `$HOME`.
    pub(crate) core_host_sources: Vec<CoreHostSource>,
    /// Declared `persist` links and the guest HOME they live under; checked
    /// against every destination before any fork is published
    /// ([`crate::guest_home::PersistedHome`]).
    pub(crate) persisted_home: crate::guest_home::PersistedHome,
}

/// Normalize the guest spelling before it participates in identity or
/// collision detection.  This mirrors Microsandbox's path contract rather
/// than relying on its later builder validation after host state was touched.
fn normalize_guest(raw: &str) -> Result<PathBuf> {
    use std::path::Component;
    if raw == "/" || raw.contains([':', ';', ',']) || !crate::run::guest_path_is_mountable(raw) {
        anyhow::bail!("--mount guest path {raw:?} is not mountable");
    }
    let path = Path::new(raw);
    if !path.is_absolute() {
        anyhow::bail!("--mount guest path {raw:?} must be absolute");
    }
    let mut out = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(part) => out.push(part),
            Component::ParentDir | Component::Prefix(_) => {
                anyhow::bail!("--mount guest path {raw:?} must not contain `..`")
            }
        }
    }
    if out == Path::new("/") {
        anyhow::bail!("--mount guest path must not be /");
    }
    Ok(out)
}

/// Why a set of declarations could not be claimed, named by origin.
///
/// `Display` is the whole diagnostic: no caller wraps it, because a config mount
/// refused before launch must not read as a `--mount` failure. Every variant's
/// argv-only rendering is byte-identical to the `bail!` it replaced (pinned by
/// `cli_claim_errors_are_pinned`).
///
/// `source()` is deliberately `None` (the default): `Guest` already renders the
/// grammar's sentence into its own message, and a source frame would print it
/// twice for a `{:#}` reader.
#[derive(Debug)]
pub(crate) enum ClaimError {
    /// The guest spelling itself is unusable.
    Guest {
        origin: MountOrigin,
        error: anyhow::Error,
    },
    /// The guest would replace one of agent-vm's own mounts.
    Core { origin: MountOrigin, guest: PathBuf },
    /// Two declarations named one guest path and did not agree.
    Conflict {
        first: MountOrigin,
        second: MountOrigin,
        guest: PathBuf,
    },
}

impl fmt::Display for ClaimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Guest { origin, error } => match origin {
                // The grammar's own sentence, unchanged: a config entry was
                // already normalized at load, so only argv reaches here.
                MountOrigin::Cli => write!(f, "{error}"),
                config => write!(f, "{config}: {error}"),
            },
            Self::Core { origin, guest } => {
                let guest = guest.display();
                match origin {
                    MountOrigin::Cli => write!(
                        f,
                        "--mount guest path {guest} collides with an agent-vm core mount"
                    ),
                    config => write!(
                        f,
                        "{config}: guest path {guest} collides with an agent-vm core mount; \
                         pass --no-config-mounts to launch without it"
                    ),
                }
            }
            Self::Conflict {
                first,
                second,
                guest,
            } => {
                let guest = guest.display();
                match (first, second) {
                    (MountOrigin::Cli, MountOrigin::Cli) => write!(
                        f,
                        "--mount guest path {guest} is claimed by different declarations"
                    ),
                    _ => write!(
                        f,
                        "guest path {guest} is claimed by different declarations ({first} and \
                         {second}); identical declarations are merged and different ones are \
                         refused"
                    ),
                }
            }
        }
    }
}

impl std::error::Error for ClaimError {}

/// Normalize every guest spelling, then adjudicate the claims in first-seen
/// order: a core collision is refused, an identical re-declaration merges into
/// the first one, and a differing one is refused naming both origins.
///
/// The order is the contract, not an accident. Normalizing first is what makes
/// `/g//./x` and `/g/x` one claim; core-before-merge is what keeps today's
/// message for a core path that is also declared twice; and keeping the first
/// request is what makes the *first-seen* origin the one a conflict names.
/// Nothing here touches the filesystem, so config load can call it on its own
/// `mounts` list to reject a self-contradictory file before any launch.
pub(crate) fn claim(
    requests: Vec<MountRequest>,
    core: &[PathBuf],
) -> Result<Vec<MountRequest>, ClaimError> {
    let mut normalized = Vec::with_capacity(requests.len());
    for request in requests {
        let MountRequest { origin, mount } = request;
        let spelling = mount.guest.to_str().ok_or_else(|| ClaimError::Guest {
            origin: origin.clone(),
            error: anyhow::anyhow!("--mount guest path must be UTF-8"),
        })?;
        let guest = normalize_guest(spelling).map_err(|error| ClaimError::Guest {
            origin: origin.clone(),
            error,
        })?;
        normalized.push(MountRequest {
            origin,
            mount: ExtraMount { guest, ..mount },
        });
    }

    let mut unique: Vec<MountRequest> = Vec::with_capacity(normalized.len());
    for request in normalized {
        if core.iter().any(|core| core == &request.mount.guest) {
            return Err(ClaimError::Core {
                origin: request.origin,
                guest: request.mount.guest,
            });
        }
        let Some(index) = unique
            .iter()
            .position(|earlier| earlier.mount.guest == request.mount.guest)
        else {
            unique.push(request);
            continue;
        };
        let first = &unique[index];
        // `same_guest` is true by construction — `position` just found the
        // earlier claim — so the kernel's remaining choice is merge or refuse.
        let decision = claim_decision(ClaimFacts {
            same_guest: true,
            equivalent: same_declaration(&first.mount, &request.mount),
        });
        match decision {
            ClaimDecision::Merge => continue,
            // `Distinct` is unreachable for a shared guest; treating it as a
            // refusal keeps a wrong kernel fail-closed instead of last-wins.
            ClaimDecision::Conflict | ClaimDecision::Distinct => {
                return Err(ClaimError::Conflict {
                    first: first.origin.clone(),
                    second: request.origin,
                    guest: request.mount.guest,
                });
            }
        }
    }
    Ok(unique)
}

/// Prepare a complete, closed mount plan.  This is deliberately the only
/// boundary allowed to inspect mount sources or create fork state. The
/// Pi-file, config-directory and persisted-guest-HOME guards all run before any
/// fork/session mutation.
///
/// Declarations arrive as [`MountRequests`] so every one names the source it
/// came from, whichever route produced it; from here on a config mount and a
/// `--mount` are the same kind of thing.
pub(crate) fn prepare(
    requests: impl Into<MountRequests>,
    context: &MountContext,
) -> Result<PreparedMountPlan> {
    // Measure the protected host-file route set once, then refuse to launch a
    // core bind that would hand one over. The project bind is the
    // canonicalized cwd, so `cd ~ && agent-vm shell` is an exposure route even
    // with no `--mount` at all.
    let protected = ProtectedHostFiles::measure(context.host_home.as_deref())?;
    let mut notices = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for source in &context.core_host_sources {
        // The Pi advisories fire for one of agent-vm's *own* binds too, not
        // just for `--mount`s: `~/.pi/extensions` as the canonicalized cwd is
        // a writable live window onto host Pi state with no `--mount` at all
        // (issue #90's warning deliverable).
        for advisory in protected.core_advisories(source) {
            push_notice(&mut notices, &mut seen, advisory);
        }
        let Some(exposure) = protected.exposure(&source.path)? else {
            continue;
        };
        match exposure.severity {
            Severity::Refuse => anyhow::bail!("{}", protected.core_message(source, &exposure)),
            Severity::Advise => {
                // Pre-existing text for an agent-vm bind, kept byte-identical:
                // this advisory is not about a declaration, so its subject is
                // the historical `--mount` prefix; naming the bind instead is a
                // separate wording decision.
                let advisory = protected.message(
                    "--mount",
                    &crate::one_line::path(&source.path),
                    &exposure,
                    None,
                );
                push_notice(&mut notices, &mut seen, advisory);
            }
        }
    }

    let homes: Vec<PathBuf> = context
        .authority_home
        .iter()
        .chain(context.account_home.iter())
        .cloned()
        .collect();
    let cwd = std::env::current_dir().context("reading the launch directory")?;
    let config_dir = crate::protected_config_dir::ProtectedConfigDir::measure(&homes, &cwd)?;
    config_dir.check_authority_links()?;
    for source in &context.core_host_sources {
        config_dir.check_core_bind(source)?;
    }

    // Reject and deduplicate explicit claims before touching the store/source.
    // The origins are kept beside the declarations, not thrown away with them:
    // a source failure here is about one declaration, and a config entry has to
    // be identifiable by `mounts[N]`, not only by the file context the launch
    // wraps around the error.
    let claimed = claim(requests.into().into_inner(), &context.core_guest_mounts)
        .map_err(anyhow::Error::from)?;
    let origins: DeclaredOrigins = claimed
        .iter()
        .map(|request| (request.mount.guest.clone(), request.origin.clone()))
        .collect();
    let mut unique: Vec<ExtraMount> = claimed.into_iter().map(|request| request.mount).collect();

    // Every fork is validated READY-first here, before any live-bind
    // discovery or state mutation. A READY entry is reused from its
    // committed `data` without reading the original source; an
    // uninitialized fork whose root is a file (or a symlink to one) is
    // rejected before discovery/transaction. A missing source is left for
    // the locked transaction, so a waiter can still reuse a fork another
    // initializer publishes while it waits.
    let known_fork_kinds = preflight_forks(&mut unique, &context.mount_store, &origins)?;

    // Live binds are the only sources that can contribute followed links, so
    // discovery runs after fork preflight and never over a fork.
    let explicit_count = unique.len();
    let (mut expanded, warnings) =
        expand_follow_links(unique.clone(), &origins, context.host_home.as_deref())?;
    sync_fork_representations(&unique, &mut expanded)?;

    let mut volumes = Vec::new();
    for (index, mount) in expanded.iter().enumerate() {
        let explicit = index < explicit_count;
        // Only a missing source remains unclassified after preflight. Its
        // provisional directory kind permits a waiter to reach the locked
        // READY recheck without requiring the original source to survive.
        let kind = if mount.is_fork() {
            known_fork_kinds
                .get(&mount.guest)
                .copied()
                // An uninitialized fork is always directory-or-rejected; the
                // locked transaction rechecks before it publishes.
                .unwrap_or(PreparedNodeKind::Directory)
        } else {
            let declaration = declaration_origin(mount, &origins);
            let metadata = fs::symlink_metadata(&mount.host)
                .with_context(|| validating_source_context(declaration, &mount.host))?;
            node_kind(&metadata, &mount.host, declaration)?
        };
        // A regular file cannot be a writable bind: the runtime's writable
        // file staging is intentionally unreachable from agent-vm (issue
        // #113). Reject here, after canonicalization, so a symlink-to-file
        // root is caught too.
        if kind == PreparedNodeKind::File && !mount.is_readonly() {
            let declaration = declaration_origin(mount, &origins);
            anyhow::bail!(
                "{} {}: a file can only be mounted read-only.\n\
                 Use :ro, or :fork its containing directory for a writable copy.",
                declaration.subject(),
                mount.source_spelling.render(declaration)
            );
        }
        let source = if mount.is_readonly() {
            PreparedVolumeSource::ReadOnlyBind(mount.host.clone())
        } else {
            PreparedVolumeSource::WritableBind(mount.host.clone())
        };
        volumes.push(PreparedVolume {
            guest: mount.guest.clone(),
            source,
            node_kind: kind,
            role: if explicit {
                VolumeRole::Explicit
            } else {
                VolumeRole::Followed
            },
        });
    }
    // Refuse a live bind that would hand a protected host file to the guest,
    // and collect the Pi advisories. Runs after `expand_follow_links` (so a
    // followed alias is an ordinary discovered bind) and before
    // `validate_plan`/`prepare_forks` (so a refusal has no side effects).
    enforce_protected_files(
        &expanded,
        explicit_count,
        &origins,
        &protected,
        &mut notices,
    )?;
    for mount in expanded.iter().filter(|m| !m.is_readonly() && !m.is_fork()) {
        config_dir.check_writable_mount(
            &declaration_origin(mount, &origins).subject(),
            &mount.source_spelling,
            &mount.spelled_host,
            &mount.host,
        )?;
    }
    // A fork seeded by a pre-#90 build may already contain a copy of a
    // protected file, and a READY fork is reused *without* reading its source,
    // so no source-side check catches it. Report the orphaned directory that
    // the v3 identity no longer reuses.
    for mount in unique.iter().filter(|mount| mount.is_fork()) {
        if let Some(orphan) = legacy_fork_dir(mount, &context.mount_store) {
            notices.push(format!(
                "==> A fork from an earlier agent-vm build is no longer used: {}. It may \
                 contain a copy of a host credential file — remove it.",
                crate::one_line::path(&orphan)
            ));
        }
    }
    validate_plan(&mut volumes, &context.core_guest_mounts)?;

    // ADR-0046 Decision 6: a mount that shadows a declared persist path is
    // refused here, over the complete normalized core + explicit + followed
    // destinations, so a rejected plan never publishes a fork.
    let destinations: Vec<PathBuf> = context
        .core_guest_mounts
        .iter()
        .cloned()
        .chain(volumes.iter().map(|volume| volume.guest.clone()))
        .collect();
    context.persisted_home.refuse_conflicts(&destinations)?;

    // Only a validated complete set of core, explicit, and followed claims
    // may publish any host-managed state. The first state mutation happens
    // inside `prepare_forks`; everything above is rejection or classification.
    notices.extend(prepare_forks(
        &mut unique,
        &context.mount_store,
        &known_fork_kinds,
        &protected,
        &origins,
    )?);
    sync_fork_representations(&unique, &mut expanded)?;
    notices.extend(warnings.into_iter().map(|warning| format!("==> {warning}")));

    // Fork initialization changes only the explicit source path. Discovery
    // was already complete (forks do not produce live followed binds), so
    // patch the validated instruction rather than re-discovering anything.
    for mount in unique.iter().filter(|mount| mount.is_fork()) {
        let Some(volume) = volumes
            .iter_mut()
            .find(|volume| volume.role == VolumeRole::Explicit && volume.guest == mount.guest)
        else {
            anyhow::bail!(
                "prepared fork at {} lost its explicit claim",
                crate::one_line::path(&mount.guest)
            );
        };
        volume.source = PreparedVolumeSource::WritableBind(mount.host.clone());
        let metadata = fs::symlink_metadata(&mount.host).with_context(|| {
            format!(
                "validating committed fork {}",
                crate::one_line::path(&mount.host)
            )
        })?;
        volume.node_kind = node_kind(&metadata, &mount.host, declaration_origin(mount, &origins))?;
    }

    // The prepared explicit declarations in order: live binds carry their
    // canonical source (after `expand_follow_links`), and forks carry their
    // committed `data` (after `sync_fork_representations`), never the original
    // source. Followed aliases are not scanned as separate roots.
    let repo_scan_roots = expanded
        .iter()
        .take(explicit_count)
        .map(|mount| RepoScanRoot {
            host: mount.host.clone(),
        })
        .collect();
    Ok(PreparedMountPlan {
        volumes,
        repo_scan_roots,
        notices,
    })
}

/// Refuse any live bind that would hand a protected host file to the guest,
/// and collect the Pi advisories. Forks are exempt from the refusal on
/// purpose: their *content* is decided by the copy engine (`copy_opened`),
/// not by this root-level check.
///
/// Precedence is honest, not "security first": `normalize_guest`, the core
/// collision/dedup pass, `preflight_forks` and the per-mount `file`+`rw`
/// rejection all run earlier and can bail. Every one of them is read-only, so a
/// leaky-*and*-invalid plan is still refused with **no side effects** — only
/// the message the user sees is the earlier one.
fn enforce_protected_files(
    expanded: &[ExtraMount],
    explicit_count: usize,
    origins: &DeclaredOrigins,
    protected: &ProtectedHostFiles,
    notices: &mut Vec<String>,
) -> Result<()> {
    // Not at the top of `prepare`: `expand_follow_links`'s more specific
    // "$HOME is not set — required for --mount follow-links" must still win for
    // a `follow-links` mount with no `$HOME`.
    protected.require_home(expanded.len())?;
    if expanded.is_empty() {
        return Ok(());
    }
    let declarations: Vec<(Declaration<'_>, String)> = expanded[..explicit_count]
        .iter()
        .filter(|mount| mount.follows_links() && !mount.is_fork())
        .map(|mount| {
            let declaration = declaration_origin(mount, origins);
            (declaration, mount.source_spelling.render(declaration))
        })
        .collect();
    let mut seen: Vec<String> = Vec::new();
    for (index, mount) in expanded.iter().enumerate() {
        // Advisories are evaluated against the *declaration*, never
        // `mount.host`: `preflight_forks` repoints a READY fork's host at
        // `<store>/forks/<id>/data`, so a notice keyed on `mount.host` would
        // silently stop firing on every launch after the first.
        let declaration = declaration_path(mount);
        if !mount.is_fork()
            && let Some(exposure) = protected.exposure(&mount.host)?
        {
            let discovered = (index >= explicit_count).then(|| discovered_by(&declarations));
            let declaring = declaration_origin(mount, origins);
            let message = protected.message(
                &declaring.subject(),
                &mount.source_spelling.render(declaring),
                &exposure,
                discovered.as_deref(),
            );
            match exposure.severity {
                // A live window onto host bytes cannot be made safe by any
                // overlay: `pi auth login` on the host can create
                // `auth.json` inside a bind that is already open.
                Severity::Refuse => anyhow::bail!("{message}"),
                Severity::Advise => push_notice(notices, &mut seen, message),
            }
        }
        // A fork needs only the platform-artifact advisory: its content is the
        // copy engine's decision, and `:fork` is what it already is.
        let live_bind = !mount.is_fork();
        let declaring = declaration_origin(mount, origins);
        let advisories = protected.mount_advisories(
            &declaration,
            &mount.source_spelling.render(declaring),
            live_bind,
        );
        for advisory in advisories {
            push_notice(notices, &mut seen, advisory);
        }
    }
    Ok(())
}

/// The provenance phrase for a `follow-links`-discovered bind, for the refusal
/// message. `expand_follow_links` does not carry the originating declaration
/// per discovered target — two `:follow-links` declarations can discover the
/// same bind — so naming every candidate would blame declarations that did not
/// contribute it. Naming the sole candidate, or naming none of them, is never
/// wrong.
///
/// `declarations` is `(declaration, rendered spelling)` pairs. The
/// multi-candidate sentence names the *sources* that are present rather than a
/// fixed `--mount`: an argv-only launch keeps the historical phrase, and a
/// config entry's `mounts` is never mislabelled as a `--mount`. It still names
/// no single entry, on purpose — the launch's outer context names the file.
fn discovered_by(declarations: &[(Declaration<'_>, String)]) -> String {
    match declarations {
        [(declaration, only)] => format!("{} {only}:follow-links", declaration.subject()),
        _ => {
            let mut sources: Vec<String> = Vec::new();
            for (declaration, _) in declarations {
                let source = match declaration {
                    Declaration::Argv => "--mount".to_string(),
                    Declaration::UserConfig { file, .. } => {
                        format!("mounts in {}", quoted_path(file))
                    }
                };
                if !sources.contains(&source) {
                    sources.push(source);
                }
            }
            format!(
                "one of your {} …:follow-links declarations",
                sources.join(" or ")
            )
        }
    }
}

/// The path a declaration actually names, for advisories. A missing source (a
/// fork reused after its source was removed) falls back to the literal
/// spelling rather than failing the launch.
fn declaration_path(mount: &ExtraMount) -> PathBuf {
    #[allow(clippy::disallowed_methods)] // a filesystem call, never a message.
    let spelling = mount.source_spelling.as_source_path();
    spelling
        .canonicalize()
        .unwrap_or_else(|_| spelling.to_path_buf())
}

fn push_notice(notices: &mut Vec<String>, seen: &mut Vec<String>, message: String) {
    if seen.contains(&message) {
        return;
    }
    seen.push(message.clone());
    notices.push(message);
}

/// A pre-#90 fork directory that the v3 identity no longer reuses, if one
/// exists. Reported, never deleted: it may hold valuable guest state (and a
/// copy of a protected file).
fn legacy_fork_dir(mount: &ExtraMount, mount_store: &Path) -> Option<PathBuf> {
    let path = mount_store
        .join("forks")
        .join(fork_id(mount, LEGACY_IDENTITY_VERSION_V2));
    fs::symlink_metadata(&path).is_ok().then_some(path)
}

/// Validate every fork without creating its store or inspecting an
/// uninitialized source beyond its kind. READY is checked first, so a fork
/// stays reusable after its original source disappears or changes type.
fn preflight_forks(
    mounts: &mut [ExtraMount],
    mount_store: &Path,
    origins: &DeclaredOrigins,
) -> Result<std::collections::HashMap<PathBuf, PreparedNodeKind>> {
    let mut kinds = std::collections::HashMap::new();
    for mount in mounts.iter_mut().filter(|mount| mount.is_fork()) {
        let declaration = declaration_origin(mount, origins);
        let id = fork_id(mount, IDENTITY_VERSION);
        let final_dir = mount_store.join("forks").join(&id);
        if final_dir_exists(&final_dir)? {
            let kind = validate_ready(&final_dir, mount, &id)?;
            // READY wins over whatever the original source now is; the
            // committed copy is the mount source from here on.
            mount.host = final_dir.join("data");
            kinds.insert(mount.guest.clone(), kind);
            continue;
        }
        // Uninitialized: reject a file root now, before discovery or any
        // store/lock side effect. A vanished source is deliberately deferred:
        // a concurrent initializer may publish READY while this waiter blocks
        // on the per-fork lock (see the process tests).
        let Some(kind) = try_fork_source_kind(&mount.host, declaration)? else {
            continue;
        };
        require_fork_directory(kind, declaration, &mount.source_spelling)?;
        kinds.insert(mount.guest.clone(), kind);
    }
    Ok(kinds)
}

/// A `:fork` root is always a directory (issue #113). Shared between the
/// preflight classification and the locked recheck so both emit one message.
fn require_fork_directory(
    kind: PreparedNodeKind,
    declaration: Declaration<'_>,
    source: &Spelling,
) -> Result<()> {
    if kind != PreparedNodeKind::Directory {
        anyhow::bail!(
            "{} {}: a :fork source must be a directory.\n\
             Fork the containing directory, or bind the file read-only with :ro.",
            declaration.subject(),
            source.render(declaration)
        );
    }
    Ok(())
}

fn try_fork_source_kind(
    source: &Path,
    declaration: Declaration<'_>,
) -> Result<Option<PreparedNodeKind>> {
    match fs::symlink_metadata(source) {
        Ok(_) => fork_source_kind(source, declaration).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| fork_root_context("validating", declaration, source))
        }
    }
}

fn fork_source_kind(source: &Path, declaration: Declaration<'_>) -> Result<PreparedNodeKind> {
    let resolved = source
        .canonicalize()
        .with_context(|| fork_root_context("resolving", declaration, source))?;
    let metadata = fs::symlink_metadata(&resolved)
        .with_context(|| fork_root_context("validating", declaration, source))?;
    node_kind(&metadata, source, declaration)
}

/// Keep the follow-link-expanded representation aligned with the declaration
/// that owns fork transaction state. A READY preflight replaces only
/// `unique`; every later consumer (volumes and repository
/// scanning) must therefore use this committed path rather than the original
/// declaration source.
fn sync_fork_representations(unique: &[ExtraMount], expanded: &mut [ExtraMount]) -> Result<()> {
    for mount in expanded.iter_mut().filter(|mount| mount.is_fork()) {
        let prepared = unique
            .iter()
            .find(|candidate| {
                candidate.is_fork()
                    && candidate.guest == mount.guest
                    && candidate.source_spelling == mount.source_spelling
                    && candidate.follows_links() == mount.follows_links()
                    && candidate.exclusions == mount.exclusions
            })
            .with_context(|| {
                format!(
                    "prepared fork at {} lost its declaration representation",
                    crate::one_line::path(&mount.guest)
                )
            })?;
        mount.host = prepared.host.clone();
    }
    Ok(())
}

/// The trusted adapter for [`declarations_equivalent`]: it measures the six
/// equalities and lets the kernel decide. Host spelling and the measured `host`
/// are separate facts on purpose — `~/ref` and `~/ref/` can name one guest path
/// while exposing different bytes, so spelling participates.
fn same_declaration(a: &ExtraMount, b: &ExtraMount) -> bool {
    declarations_equivalent(DeclarationFacts {
        spelling: a.source_spelling == b.source_spelling,
        host: a.host == b.host,
        readonly: a.is_readonly() == b.is_readonly(),
        follow: a.follows_links() == b.follows_links(),
        fork: a.is_fork() == b.is_fork(),
        exclusions: a.exclusions == b.exclusions,
    })
}

fn node_kind(
    metadata: &fs::Metadata,
    path: &Path,
    declaration: Declaration<'_>,
) -> Result<PreparedNodeKind> {
    if metadata.is_file() {
        Ok(PreparedNodeKind::File)
    } else if metadata.is_dir() {
        Ok(PreparedNodeKind::Directory)
    } else {
        // This sentence has never named `--mount` for an argv source, so that
        // half stays byte-identical; a config entry is named, because otherwise
        // the launch context mentions only the file.
        anyhow::bail!(
            "{} must be a regular file or directory",
            match declaration {
                Declaration::Argv => crate::one_line::path(path),
                Declaration::UserConfig { .. } => {
                    format!("{} {}", declaration.subject(), quoted_path(path))
                }
            }
        )
    }
}

fn validate_plan(volumes: &mut Vec<PreparedVolume>, core: &[PathBuf]) -> Result<()> {
    // Identical claims are harmless; distinct claims at the same guest path
    // are ambiguous and must fail before builder side effects.
    let mut unique = Vec::new();
    for volume in volumes.drain(..) {
        if unique
            .iter()
            .any(|v: &PreparedVolume| same_volume(v, &volume))
        {
            continue;
        }
        if unique
            .iter()
            .any(|v: &PreparedVolume| v.guest == volume.guest)
        {
            anyhow::bail!(
                "mount plan has conflicting claims at {}",
                crate::one_line::path(&volume.guest)
            );
        }
        unique.push(volume);
    }

    for volume in &unique {
        for file in unique
            .iter()
            .filter(|candidate| candidate.node_kind == PreparedNodeKind::File)
        {
            if volume.guest != file.guest && volume.guest.starts_with(&file.guest) {
                anyhow::bail!(
                    "mount at {} is below file mount {}",
                    crate::one_line::path(&volume.guest),
                    crate::one_line::path(&file.guest)
                );
            }
        }
        if core.iter().any(|path| path == &volume.guest) {
            anyhow::bail!(
                "mount plan collides with an agent-vm core mount at {}",
                crate::one_line::path(&volume.guest)
            );
        }
        if core.iter().any(|path| path.starts_with(&volume.guest))
            && volume.node_kind == PreparedNodeKind::File
            && core
                .iter()
                .any(|path| path != &volume.guest && path.starts_with(&volume.guest))
        {
            anyhow::bail!(
                "core mount is below file mount {}",
                crate::one_line::path(&volume.guest)
            );
        }
    }
    *volumes = unique;
    Ok(())
}

fn same_volume(a: &PreparedVolume, b: &PreparedVolume) -> bool {
    a.guest == b.guest && a.source == b.source && a.node_kind == b.node_kind && a.role == b.role
}

const MANIFEST_VERSION: u32 = 2;
/// v3 because a READY fork is reused *without* reading its source, so a fork
/// seeded by a pre-#90 build may already contain a copied protected file and no
/// source-side check could catch it. Bumping the identity makes every reusable
/// fork one that was seeded *under* protection — a structural invariant instead
/// of a runtime scan. Forks had never shipped in a release, so no released
/// user has one to orphan (ADR-0020).
const IDENTITY_VERSION: &[u8] = b"agent-vm-fork-identity-v3";
/// Only to report the orphaned directory the v3 identity leaves behind
/// ([`legacy_fork_dir`]); never used to reuse or validate a fork.
const LEGACY_IDENTITY_VERSION_V2: &[u8] = b"agent-vm-fork-identity-v2";
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const FORK_MAX_LINK_DEPTH: usize = 40;

// The copy engine deliberately exposes only test-only checkpoints.  They let
// tests swap a just-classified pathname before its descriptor is opened,
// proving that O_NOFOLLOW/fstat rather than timing protects the traversal.
//
// The callback is scoped to the canonical root being copied so it can only
// fire for the copy its test armed it for. Cargo runs unit tests in parallel,
// so an unscoped process-global hook would run inside a stranger's copy and
// mutate that other test's tree.
//
// The tuple is `(scope, callback)`; the alias keeps it readable and out of
// clippy's `type_complexity` lint, which `--all-targets` now gates on.
#[cfg(test)]
type CopyCheckpoint = (PathBuf, Box<dyn Fn(&Path) + Send>);

#[cfg(test)]
static COPY_CHECKPOINT: std::sync::Mutex<Option<CopyCheckpoint>> = std::sync::Mutex::new(None);

#[cfg(test)]
thread_local! {
    // The canonical root of the copy running on this thread. The armed
    // callback's scope is compared against it, so a hook fires only for its
    // own copy even while parallel tests copy other trees.
    static COPY_CHECKPOINT_ROOT: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
struct CopyCheckpointScope;

#[cfg(test)]
impl CopyCheckpointScope {
    fn enter(source: &Path) -> Self {
        COPY_CHECKPOINT_ROOT.with(|root| *root.borrow_mut() = Some(source.to_path_buf()));
        Self
    }
}

#[cfg(test)]
impl Drop for CopyCheckpointScope {
    fn drop(&mut self) {
        COPY_CHECKPOINT_ROOT.with(|root| *root.borrow_mut() = None);
    }
}

// Only one callback can be armed at a time, so tests that arm/clear it
// serialize on this lock. Scoping (above) handles the other direction: a
// parallel test that copies must not fire an armed callback at all.
#[cfg(test)]
static COPY_CHECKPOINT_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
fn set_copy_checkpoint(source: &Path, callback: Box<dyn Fn(&Path) + Send>) {
    let scope = source
        .canonicalize()
        .unwrap_or_else(|_| source.to_path_buf());
    *COPY_CHECKPOINT
        .lock()
        .unwrap_or_else(|poison| poison.into_inner()) = Some((scope, callback));
}

#[cfg(test)]
fn clear_copy_checkpoint() {
    *COPY_CHECKPOINT
        .lock()
        .unwrap_or_else(|poison| poison.into_inner()) = None;
}

#[cfg(test)]
fn copy_checkpoint(path: &Path) {
    let root = COPY_CHECKPOINT_ROOT.with(|root| root.borrow().clone());
    let guard = COPY_CHECKPOINT
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    if let (Some(root), Some((scope, callback))) = (root.as_ref(), guard.as_ref())
        && scope == root
    {
        callback(path);
    }
    drop(guard);
    // A child-only pause lets the transaction test kill an actual
    // initializer mid-copy. This is compiled only into the test binary.
    if std::env::var_os("AGENT_VM_FORK_KILL_CHECKPOINT")
        .is_some_and(|checkpoint| path == Path::new(&checkpoint))
    {
        std::fs::write(
            std::env::var_os("AGENT_VM_FORK_KILL_READY").unwrap(),
            "ready",
        )
        .unwrap();
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
}

#[cfg(not(test))]
fn copy_checkpoint(_: &Path) {}

// A second test-only hook, with its own callback slot and the same scope/lock as
// `copy_checkpoint`. It fires **between `copy_root`'s root resolve (T1) and the
// copy-point measurement (T2)** — the interval S3-A/S3-B use to suppress a
// competing measured route, and the interval R4.7's lost-association residual
// is about (R4.4.2). Production compiles it away.
#[cfg(test)]
static RESOLVE_CHECKPOINT: std::sync::Mutex<Option<CopyCheckpoint>> = std::sync::Mutex::new(None);

#[cfg(test)]
fn set_resolve_checkpoint(source: &Path, callback: Box<dyn Fn(&Path) + Send>) {
    let scope = source
        .canonicalize()
        .unwrap_or_else(|_| source.to_path_buf());
    *RESOLVE_CHECKPOINT
        .lock()
        .unwrap_or_else(|poison| poison.into_inner()) = Some((scope, callback));
}

#[cfg(test)]
fn clear_resolve_checkpoint() {
    *RESOLVE_CHECKPOINT
        .lock()
        .unwrap_or_else(|poison| poison.into_inner()) = None;
}

/// Test-only RAII guard: arms the resolve hook and clears it on drop, so a
/// panicking test cannot leave a callback armed for another test that shares
/// the slot. The caller must hold `COPY_CHECKPOINT_TEST_LOCK` for the whole
/// arm → copy → drop lifetime, so the arm/clear pair cannot interleave with
/// another hook user.
#[cfg(test)]
struct ResolveCheckpointGuard;

#[cfg(test)]
impl ResolveCheckpointGuard {
    fn arm(source: &Path, callback: Box<dyn Fn(&Path) + Send>) -> Self {
        set_resolve_checkpoint(source, callback);
        Self
    }
}

#[cfg(test)]
impl Drop for ResolveCheckpointGuard {
    fn drop(&mut self) {
        clear_resolve_checkpoint();
    }
}

/// Test-only RAII guard for the copy hook, symmetric with
/// [`ResolveCheckpointGuard`]. The caller must hold
/// `COPY_CHECKPOINT_TEST_LOCK` for the whole arm → copy → drop lifetime.
#[cfg(test)]
struct CopyCheckpointGuard;

#[cfg(test)]
impl CopyCheckpointGuard {
    fn arm(source: &Path, callback: Box<dyn Fn(&Path) + Send>) -> Self {
        set_copy_checkpoint(source, callback);
        Self
    }
}

#[cfg(test)]
impl Drop for CopyCheckpointGuard {
    fn drop(&mut self) {
        clear_copy_checkpoint();
    }
}

#[cfg(test)]
fn resolve_checkpoint(path: &Path) {
    let root = COPY_CHECKPOINT_ROOT.with(|root| root.borrow().clone());
    // Only the slot's own lock: `COPY_CHECKPOINT_TEST_LOCK` is held by the test
    // that armed this hook, so re-acquiring it here would self-deadlock. The
    // test lock serializes arm/clear; this lock serializes the read.
    let guard = RESOLVE_CHECKPOINT
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    if let (Some(root), Some((scope, callback))) = (root.as_ref(), guard.as_ref())
        && scope == root
    {
        callback(path);
    }
}

#[cfg(not(test))]
fn resolve_checkpoint(_: &Path) {}

#[derive(serde::Serialize, serde::Deserialize)]
struct ForkManifest {
    version: u32,
    id: String,
    source: String,
    guest: String,
    follow_links: bool,
    exclusions: Vec<String>,
    kind: String,
}

/// Initialize each fork through one lock-protected state transition. READY is
/// validated before source access, so a seeded fork is usable after removal.
///
/// `protected` is the measurement taken at the top of `prepare`. The copier
/// resolves each root itself and re-measures under the lock, unioning the two
/// over identities (see `refreshed`), so it never forgets a credential identity
/// an earlier snapshot positively identified (R4.4.4).
pub(crate) fn prepare_forks(
    mounts: &mut [ExtraMount],
    mount_store: &Path,
    expected_kinds: &std::collections::HashMap<PathBuf, PreparedNodeKind>,
    protected: &ProtectedHostFiles,
    origins: &DeclaredOrigins,
) -> Result<Vec<String>> {
    let mut notices = Vec::new();
    for mount in mounts.iter_mut().filter(|mount| mount.is_fork()) {
        let declaration = declaration_origin(mount, origins);
        let id = fork_id(mount, IDENTITY_VERSION);
        let final_dir = mount_store.join("forks").join(&id);
        ensure_store(mount_store)?;
        let lock_path = mount_store.join("locks").join(format!("{id}.lock"));
        let lock = open_regular_lock(&lock_path)?;
        flock_exclusive(&lock).context("locking fork initialization")?;
        if final_dir_exists(&final_dir)? {
            let kind = validate_ready(&final_dir, mount, &id)?;
            mount.host = final_dir.join("data");
            notices.push(format!(
                "==> Reusing fork at {} (reset: {})",
                crate::one_line::path(&mount.host),
                crate::one_line::path(&final_dir)
            ));
            let _ = kind;
            continue;
        }
        clean_stale_staging(&mount_store.join("staging"), &id)?;
        // The root kind is source-dependent, so resolve it only after the
        // waiter has acquired the transaction lock and rechecked READY.
        let source_kind = fork_source_kind(&mount.host, declaration)?;
        require_fork_directory(source_kind, declaration, &mount.source_spelling)?;
        if let Some(expected) = expected_kinds.get(&mount.guest)
            && *expected != source_kind
        {
            anyhow::bail!(
                "fork root kind changed while preparing {}; retry the launch",
                mount.source_spelling.render(declaration)
            );
        }
        let staging_parent = mount_store.join("staging");
        let stage = tempfile::Builder::new()
            .prefix(&format!("{id}.stage-"))
            .tempdir_in(&staging_parent)
            .context("creating fork staging directory")?;
        let staged_data = stage.path().join("data");
        // The omission signals are derived at the copier's own resolve point,
        // from a **fresh** measurement taken there under this lock, not from
        // the one taken at the top of `prepare`: the original route set cannot
        // see a fork root that did not exist then (e.g. `--mount ~/.pi:fork`
        // where `~/.pi` is created between `measure` and this point). The fresh
        // snapshot is **unioned** with the original over identities, never a
        // replacement: an atomic credential replacement can make the fresh
        // snapshot forget an inode the original positively identified (a
        // surviving hardlink still holds the old bytes). Routes and both
        // Pi-home paths are the copy point's (R3.5). The measurement is a
        // handful of stats, once per fork; `copy_root` takes it.
        let policy = CopyPolicy {
            exclusions: &mount.exclusions,
            follow: mount.follows_links(),
            protected,
        };
        let mut report = CopyReport::default();
        let kind = copy_root(&mount.host, &staged_data, &policy, declaration, &mut report)
            .with_context(|| {
                format!(
                    "initializing fork from {}",
                    mount.source_spelling.render(declaration)
                )
            })?;
        for (relative, file) in &report.omitted {
            notices.push(format!(
                "==> Omitted {} {} from the fork of {}",
                file.description(),
                crate::one_line::path(relative),
                mount.source_spelling.render(declaration)
            ));
        }
        // The manifest records the spelling's exact bytes: it is fork identity,
        // and it is never printed.
        #[allow(clippy::disallowed_methods)]
        let source = mount.source_spelling.stored_str().to_owned();
        let manifest = ForkManifest {
            version: MANIFEST_VERSION,
            id: id.clone(),
            source,
            guest: mount.guest.display().to_string(),
            follow_links: mount.follows_links(),
            exclusions: mount
                .exclusions
                .iter()
                .map(|path| path.display().to_string())
                .collect(),
            kind: match kind {
                PreparedNodeKind::File => "file",
                PreparedNodeKind::Directory => "directory",
            }
            .into(),
        };
        write_manifest(&stage.path().join("manifest.json"), &manifest)?;
        let stage_path = stage.keep();
        match fs::rename(&stage_path, &final_dir) {
            Ok(()) => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("publishing fork {}", crate::one_line::path(&final_dir))
                });
            }
        }
        mount.host = final_dir.join("data");
        notices.push(format!(
            "==> Initialized fork {} -> {} (reset: {})",
            mount.source_spelling.render(declaration),
            crate::one_line::path(&mount.host),
            crate::one_line::path(&final_dir)
        ));
    }
    Ok(notices)
}

fn fork_id(mount: &ExtraMount, version: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(version);
    // The hash is the spelling's exact bytes: identity, not a message.
    #[allow(clippy::disallowed_methods)]
    for value in std::iter::once(mount.source_spelling.stored_bytes())
        .chain(std::iter::once(mount.guest.as_os_str().as_encoded_bytes()))
        .chain(std::iter::once(if mount.follows_links() {
            b"follow".as_slice()
        } else {
            b"preserve".as_slice()
        }))
        .chain(
            mount
                .exclusions
                .iter()
                .map(|path| path.as_os_str().as_encoded_bytes()),
        )
    {
        hash.update((value.len() as u64).to_le_bytes());
        hash.update(value);
    }
    format!("{:x}", hash.finalize())
}

fn ensure_store(store: &Path) -> Result<()> {
    let parent = store
        .parent()
        .context("mount store must have a state-root parent")?;
    // `prepare` intentionally runs before session initialization. Create
    // only the missing state-root ancestry needed by a plan that has already
    // passed every topology check; do not pull generic session setup earlier.
    ensure_private_parent_tree(parent)?;

    for path in [
        store.to_path_buf(),
        store.join("locks"),
        store.join("staging"),
        store.join("forks"),
    ] {
        ensure_private_store_directory(&path)?;
    }
    Ok(())
}

/// Materialize missing state-root ancestors without `create_dir_all`. Each
/// requested existing/created leaf is opened with `O_NOFOLLOW`, so a
/// configured state root cannot redirect host-managed fork state through a
/// final symlink. Existing user-owned ancestors retain their modes; every
/// directory created for this state root is private.
fn ensure_private_parent_tree(parent: &Path) -> Result<()> {
    match fs::symlink_metadata(parent) {
        Ok(_) => return validate_private_directory(parent, "mount store parent"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "validating mount store parent {}",
                    crate::one_line::path(parent)
                )
            });
        }
    }

    // Recursing to the nearest existing ancestor leaves existing user-owned
    // directories untouched. Every state-root component created here is its
    // own no-follow final component, and a configured final symlink fails
    // closed.
    let ancestor = parent
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .context("missing mount store parent has no existing ancestor")?;
    ensure_private_parent_tree(ancestor)?;
    let created = match fs::create_dir(parent) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "creating mount store parent {}",
                    crate::one_line::path(parent)
                )
            });
        }
    };
    validate_private_directory(parent, "mount store parent")?;
    if created {
        secure_directory(parent, "mount store parent")?;
    }
    Ok(())
}

fn ensure_private_store_directory(path: &Path) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("creating mount store {}", crate::one_line::path(path)));
        }
    }
    validate_private_directory(path, "mount store")?;
    // Do not let a restrictive umask make the invariant depend on the first
    // initializer. These host-managed directories remain private on reuse.
    secure_directory(path, "mount store")
}

fn validate_private_directory(path: &Path, description: &str) -> Result<()> {
    use rustix::fs::{self as rfs, FileType, Mode, OFlags};

    // Opening the entry as a directory is the validation: unlike a
    // metadata-only check, this cannot hand a later operation a symlink.
    let dir = rfs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("validating {description} {}", crate::one_line::path(path)))?;
    if FileType::from_raw_mode(rfs::fstat(&dir)?.st_mode) != FileType::Directory {
        anyhow::bail!(
            "{description} entry {} must be a real directory",
            crate::one_line::path(path)
        );
    }
    Ok(())
}

fn secure_directory(path: &Path, description: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("securing {description} {}", crate::one_line::path(path)))
}
fn final_dir_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                anyhow::bail!(
                    "corrupt fork {}; remove it to reset",
                    crate::one_line::path(path)
                )
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}
fn open_regular_lock(path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("opening fork lock {}", crate::one_line::path(path)))?;
    if !file.metadata()?.is_file() {
        anyhow::bail!("fork lock {} is not regular", crate::one_line::path(path));
    }
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("securing fork lock {}", crate::one_line::path(path)))?;
    Ok(file)
}
fn clean_stale_staging(staging: &Path, id: &str) -> Result<()> {
    for entry in fs::read_dir(staging)? {
        let entry = entry?;
        let name = entry.file_name();
        if name.to_string_lossy().starts_with(&format!("{id}.stage-")) {
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                anyhow::bail!(
                    "unsafe stale fork staging entry {}",
                    crate::one_line::path(&entry.path())
                );
            }
            fs::remove_dir_all(entry.path())?;
        }
    }
    Ok(())
}
fn write_manifest(path: &Path, manifest: &ForkManifest) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    serde_json::to_writer(&mut file, manifest)?;
    file.flush()?;
    Ok(())
}
fn validate_ready(dir: &Path, mount: &ExtraMount, id: &str) -> Result<PreparedNodeKind> {
    let reset = || {
        format!(
            "corrupt fork {}; remove it to reset",
            crate::one_line::path(dir)
        )
    };
    let metadata = fs::symlink_metadata(dir).map_err(|_| anyhow::anyhow!(reset()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!("{}", reset());
    }
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(dir.join("manifest.json"))
        .map_err(|_| anyhow::anyhow!(reset()))?;
    let metadata = file.metadata().map_err(|_| anyhow::anyhow!(reset()))?;
    if !metadata.is_file() || metadata.len() > MAX_MANIFEST_BYTES {
        anyhow::bail!("{}", reset());
    }
    let manifest: ForkManifest =
        serde_json::from_reader(file).map_err(|_| anyhow::anyhow!(reset()))?;
    // Same bytes the fork was published under: identity, never printed.
    #[allow(clippy::disallowed_methods)]
    let source = mount.source_spelling.stored_str().to_owned();
    let expected = ForkManifest {
        version: MANIFEST_VERSION,
        id: id.into(),
        source,
        guest: mount.guest.display().to_string(),
        follow_links: mount.follows_links(),
        exclusions: mount
            .exclusions
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
        kind: manifest.kind.clone(),
    };
    if manifest.version != expected.version
        || manifest.id != expected.id
        || manifest.source != expected.source
        || manifest.guest != expected.guest
        || manifest.follow_links != expected.follow_links
        || manifest.exclusions != expected.exclusions
    {
        anyhow::bail!("{}", reset());
    }
    let data = fs::symlink_metadata(dir.join("data")).map_err(|_| anyhow::anyhow!(reset()))?;
    if data.file_type().is_symlink() {
        anyhow::bail!("{}", reset());
    }
    // Only directory forks are published now (issue #113). A legacy
    // `kind: "file"` entry (or any other/unknown kind) is a hard, actionable
    // stop that names the exact final directory: never reseed, migrate,
    // truncate, rename, delete, or bypass it.
    match (manifest.kind.as_str(), data.is_file(), data.is_dir()) {
        ("directory", false, true) => Ok(PreparedNodeKind::Directory),
        ("file", true, false) => anyhow::bail!(
            "unsupported file fork {} (this build mounts directory forks only); \
             remove it to reset",
            crate::one_line::path(dir)
        ),
        _ => anyhow::bail!("{}", reset()),
    }
}

fn is_excluded(relative: &Path, exclusions: &[PathBuf]) -> bool {
    exclusions
        .iter()
        .any(|excluded| relative == excluded || relative.starts_with(excluded))
}
/// Keep only exclusions that are reachable through a followed directory,
/// expressed relative to that directory.  The link itself remains visible;
/// its hidden children must be masked at every bind alias of its target.
fn project_exclusions(exclusions: &[PathBuf], link_relative: &Path) -> Vec<PathBuf> {
    let mut projected = exclusions
        .iter()
        .filter_map(|excluded| excluded.strip_prefix(link_relative).ok())
        .filter(|remaining| !remaining.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .collect::<Vec<_>>();
    projected.sort();
    projected.dedup();
    projected
}

/// Union projected exclusions when multiple logical routes produce the same
/// bind. Keep the normalized ancestor-collapse invariant from parsing: a
/// mask for `a` makes a later `a/b` mask redundant.
fn merge_exclusions(existing: &mut Vec<PathBuf>, additions: Vec<PathBuf>) {
    existing.extend(additions);
    existing.sort();
    existing.dedup();
    let mut collapsed = Vec::with_capacity(existing.len());
    for exclusion in existing.drain(..) {
        if !collapsed
            .iter()
            .any(|parent: &PathBuf| exclusion.starts_with(parent))
        {
            collapsed.push(exclusion);
        }
    }
    *existing = collapsed;
}
/// What the *declaration* says, plus the launch's measurement. Carries no
/// resolved path: the copier resolves the root itself and builds a
/// [`NodePolicy`] at that point (R4.4.2). Bundled because these are adjacent
/// same-typed arguments (CODING_STANDARDS: do not repeat a type in a row).
struct CopyPolicy<'a> {
    exclusions: &'a [PathBuf],
    follow: bool,
    protected: &'a ProtectedHostFiles,
}

/// What each node is judged by, bound to one resolved root. Owns its snapshot
/// so every signal in it comes from the single measurement taken at the resolve
/// point (R4.4.2).
struct NodePolicy<'a> {
    declaration: &'a CopyPolicy<'a>,
    protected: ProtectedHostFiles,
    /// Fork-root-relative paths of protected files, **even ones that do not
    /// exist yet**. The second omission signal: identity alone cannot catch a
    /// protected file created between the measurement and the copy.
    protected_relative: Vec<(PathBuf, ProtectedFile)>,
}

impl<'a> CopyPolicy<'a> {
    /// T2-T3 of R3.1. **One** copy-point measurement, taken immediately after
    /// the root resolve, unioned with the launch snapshot over **identities**
    /// (R1): an atomic credential replacement can make a fresh snapshot forget
    /// an inode the launch positively identified. Routes and both Pi-home paths
    /// come from the copy point (R3.5). There is deliberately no second
    /// observation to reconcile — see R4.1.
    fn resolve(&'a self, root: &ResolvedRoot) -> Result<NodePolicy<'a>> {
        let protected = self.protected.refreshed()?;
        let protected_relative = protected.relatives_under(root);
        Ok(NodePolicy {
            declaration: self,
            protected,
            protected_relative,
        })
    }
}

impl NodePolicy<'_> {
    /// The two signals, in one place: `fstat` identity first, then the
    /// fork-root-relative path.
    fn omits(&self, dev: u64, ino: u64, relative: &Path) -> Option<ProtectedFile> {
        self.protected.identities().matched(dev, ino).or_else(|| {
            self.protected_relative
                .iter()
                .find(|(path, _)| path == relative)
                .map(|(_, file)| *file)
        })
    }
}

/// What the copier refused to copy, for notices.
#[derive(Default)]
struct CopyReport {
    omitted: Vec<(PathBuf, ProtectedFile)>,
}

/// A node the copier either published or deliberately did not. The enum forces
/// `copy_root` to answer the root-omitted case instead of silently publishing
/// an empty fork.
enum CopiedNode {
    Copied(PreparedNodeKind),
    Omitted,
}

/// Copy a directory root via verified descriptors. Nested links are never
/// followed in the default policy, so a swap cannot turn an untrusted leaf
/// into a read of an external target. Explicit follow mode is deliberately
/// opt-in. Nested regular files are still copied by [`copy_opened`]; only the
/// root is directory-only (issue #113).
///
/// `declaration` decides how the root path is rendered in the three messages
/// below. Nested paths stay `display`ed for both sources: they are the copied
/// tree's own names, not text from the declaration.
fn copy_root(
    source: &Path,
    destination: &Path,
    policy: &CopyPolicy<'_>,
    declaration: Declaration<'_>,
    report: &mut CopyReport,
) -> Result<PreparedNodeKind> {
    use rustix::fs::{self as rfs, FileType, Mode, OFlags};
    // T1: one `canonicalize` plus one `metadata`. The canonicalized pathname is
    // the only thing the copier opens (T4), so a declaration spelling cannot
    // reach the omission signal (R4.4.1-3).
    let root = ResolvedRoot::resolve(source, declaration)?;
    #[cfg(test)]
    let _checkpoint_scope = CopyCheckpointScope::enter(root.path());
    // Test-only race in (T1, T2): the interval S3-A/S3-B use to suppress a
    // competing measured route, and the interval R4.7's residual is about.
    // (A no-op outside test builds, exactly like `copy_checkpoint`.)
    resolve_checkpoint(root.path());
    // T2-T3: the measurement is *immediately* after the resolve and before
    // `copy_checkpoint`. After, so the relatives are derived from a canonical
    // root; immediately after, because it is now the only observation of Pi's
    // home; before `copy_checkpoint`, so
    // `fork_omits_a_protected_file_created_after_measurement` still isolates
    // relative-vs-identity (R4.4.3).
    let policy = policy.resolve(&root)?;
    copy_checkpoint(root.path());
    // T4: `O_DIRECTORY` is the load-bearing enforcement: a root that was a
    // directory at preflight but is now a file or a symlink to one fails
    // here, at the descriptor actually copied from, rather than silently
    // publishing a file-root fork.
    let fd = rfs::open(
        root.path(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening fork root {}", declaration.host_path(root.path())))?;
    if FileType::from_raw_mode(rfs::fstat(&fd)?.st_mode) != FileType::Directory {
        anyhow::bail!(
            "fork root {} must be a directory",
            declaration.host_path(root.path())
        );
    }
    match copy_opened(
        &fd,
        destination,
        Path::new(""),
        &policy,
        0,
        &mut Vec::new(),
        report,
    )? {
        CopiedNode::Copied(kind) => Ok(kind),
        // Unreachable today: protected entries are files and a fork root is
        // `O_DIRECTORY`-enforced. Answered anyway so a future change cannot
        // publish an empty fork in place of a protected host file.
        CopiedNode::Omitted => {
            anyhow::bail!(
                "fork root {} is a protected host file",
                declaration.host_path(root.path())
            )
        }
    }
}
fn copy_opened(
    fd: &rustix::fd::OwnedFd,
    destination: &Path,
    relative: &Path,
    policy: &NodePolicy<'_>,
    depth: usize,
    active: &mut Vec<(u64, u64)>,
    report: &mut CopyReport,
) -> Result<CopiedNode> {
    use rustix::fs::{self as rfs, FileType, Mode, OFlags};
    use std::os::unix::fs::PermissionsExt;
    // Callers skip an excluded child before they open it; this is the
    // defensive restatement of the same rule for the root itself. An excluded
    // node is not an *omitted* one: nothing is reported and nothing is written.
    if is_excluded(relative, policy.declaration.exclusions) {
        return Ok(CopiedNode::Copied(PreparedNodeKind::Directory));
    }
    let stat = rfs::fstat(fd)?;
    // Before the destination is created, so an omitted node writes nothing at
    // all — no empty file, no placeholder (an overlay would be a mask, and
    // ADR-0014 removed mask machinery).
    if let Some(file) = policy.omits(stat.st_dev as u64, stat.st_ino as u64, relative) {
        report.omitted.push((relative.to_path_buf(), file));
        return Ok(CopiedNode::Omitted);
    }
    let ty = FileType::from_raw_mode(stat.st_mode);
    if ty == FileType::RegularFile {
        let mut source = std::fs::File::from(rustix::io::dup(fd)?);
        let mut target = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)?;
        std::io::copy(&mut source, &mut target)?;
        target.set_permissions(std::fs::Permissions::from_mode(
            stat.st_mode as u32 & 0o7777,
        ))?;
        return Ok(CopiedNode::Copied(PreparedNodeKind::File));
    }
    if ty != FileType::Directory {
        anyhow::bail!(
            "{} is not a regular file or directory",
            crate::one_line::path(relative)
        );
    }
    let identity = (stat.st_dev as u64, stat.st_ino as u64);
    if active.contains(&identity) {
        anyhow::bail!(
            "symlink cycle while copying {}",
            crate::one_line::path(relative)
        );
    }
    active.push(identity);
    fs::create_dir(destination)?;
    let entries = rfs::Dir::read_from(fd)?;
    for entry in entries {
        let entry = entry?;
        let name = std::ffi::OsStr::from_bytes(entry.file_name().to_bytes());
        // libc's directory stream includes the self/parent entries on Unix.
        // They are not source children and descending into either would turn
        // a valid directory into a false active-stack cycle.
        if name == std::ffi::OsStr::new(".") || name == std::ffi::OsStr::new("..") {
            continue;
        }
        let child_relative = relative.join(name);
        if is_excluded(&child_relative, policy.declaration.exclusions) {
            continue;
        }
        let child_stat = rfs::statat(fd, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)?;
        let child_ty = FileType::from_raw_mode(child_stat.st_mode);
        let child_dst = destination.join(name);
        copy_checkpoint(&child_relative);
        if child_ty == FileType::Symlink {
            if !policy.declaration.follow {
                let raw = rfs::readlinkat(fd, name, Vec::new())?;
                std::os::unix::fs::symlink(std::ffi::OsStr::from_bytes(raw.as_bytes()), child_dst)?;
            } else {
                if depth >= FORK_MAX_LINK_DEPTH {
                    anyhow::bail!(
                        "maximum symlink follow depth exceeded at {}",
                        crate::one_line::path(&child_relative)
                    );
                }
                // openat resolves the link relative to the already-pinned
                // parent descriptor.  Unlike synthesizing /dev/fd paths it
                // works on macOS as well as Linux and keeps relative links
                // inside the directory that contained their raw text. Without
                // `NOFOLLOW`, a followed target is classified by its own
                // `fstat`, so an omitted protected file is not materialized.
                let target = rfs::openat(
                    fd,
                    name,
                    OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .with_context(|| format!("following {}", crate::one_line::path(&child_relative)))?;
                copy_opened(
                    &target,
                    &child_dst,
                    &child_relative,
                    policy,
                    depth + 1,
                    active,
                    report,
                )?;
            }
        } else {
            let child = rfs::openat(
                fd,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            copy_opened(
                &child,
                &child_dst,
                &child_relative,
                policy,
                depth,
                active,
                report,
            )?;
        }
    }
    fs::set_permissions(
        destination,
        std::fs::Permissions::from_mode(stat.st_mode as u32 & 0o7777),
    )?;
    active.pop();
    Ok(CopiedNode::Copied(PreparedNodeKind::Directory))
}

#[cfg(test)]
mod prepare_tests {
    use super::*;

    /// A real, empty `$HOME` shared by every test in this binary. `measure`
    /// needs a locatable home for `require_home`; with no `~/.pi` it yields
    /// `Severity::Advise` and no exposure for a test source that is not an
    /// ancestor of the home. Held in a `OnceLock` so the directory outlives
    /// every `MountContext` without each call leaking its own.
    fn test_home() -> PathBuf {
        static HOME: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
        HOME.get_or_init(|| tempfile::tempdir().unwrap())
            .path()
            .to_path_buf()
    }

    fn context(store: &Path) -> MountContext {
        context_with_home(store, test_home())
    }

    fn context_with_home(store: &Path, home: PathBuf) -> MountContext {
        MountContext {
            mount_store: store.to_path_buf(),
            authority_home: Some(home.clone()),
            account_home: None,
            host_home: Some(home),
            core_guest_mounts: Vec::new(),
            core_host_sources: Vec::new(),
            persisted_home: crate::guest_home::PersistedHome::none(),
        }
    }

    /// A context whose guest HOME is `home` and which declares `persist =
    /// ["code"]` under it — the one way a `persist` link can exist, and the
    /// collision target of `persist_collision_refuses_before_any_fork_store`.
    fn persisted_context(store: &Path, home: &Path) -> MountContext {
        MountContext {
            persisted_home: crate::guest_home::PersistedHome::new(
                home.to_path_buf(),
                &crate::guest_home::links(&[crate::config::PersistPath::for_test("code")]),
            ),
            ..context_with_home(store, home.to_path_buf())
        }
    }

    /// The fail-closed `$HOME`-unset case (`ProtectedHostFiles::require_home`).
    fn context_without_home(store: &Path) -> MountContext {
        MountContext {
            mount_store: store.to_path_buf(),
            authority_home: None,
            account_home: None,
            host_home: None,
            core_guest_mounts: Vec::new(),
            core_host_sources: Vec::new(),
            persisted_home: crate::guest_home::PersistedHome::none(),
        }
    }

    /// ADR-0046 Decision 6: the persisted-guest-HOME refusal is a *pre-fork*
    /// boundary. The store path is deliberately absent, so "the store still
    /// does not exist" is a real assertion about `prepare` rather than about an
    /// empty directory: a plan that published first would leave
    /// `<store>/forks/<id>` behind.
    #[test]
    fn persist_collision_refuses_before_any_fork_store() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().canonicalize().unwrap().join("home");
        fs::create_dir(&home).unwrap();
        let source = home.join("src");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("seed"), "seed").unwrap();
        let live = home.join("live");
        fs::create_dir(&live).unwrap();
        let store = root.path().join("store");
        assert!(!store.exists(), "the store path must start absent");
        let mount_context = persisted_context(&store, &home);

        // 1. A `:fork` whose own guest path is the declared `persist` link.
        let shadowing = format!("{}:{}/code:fork", source.display(), home.display());
        let error = prepare(parse_extra_mounts(&[shadowing]).unwrap(), &mount_context)
            .expect_err("a fork that shadows a persist link is not a valid plan");
        assert!(
            error.is::<crate::guest_home::PersistCollision>(),
            "{error:#}"
        );
        assert_eq!(
            error.to_string(),
            format!(
                "config: persist path code would collide with the guest mount point {}/code; \
                 rename the persist path or move the mount",
                home.display()
            )
        );
        assert!(
            !store.exists(),
            "a refused plan must not publish a fork store"
        );

        // 2. An unrelated fork at `/f` plus a *live* bind that shadows the link.
        // Neither declaration is invalid alone, so only a check over the
        // complete normalized destination set can refuse this before `/f`'s
        // fork is published.
        let fork = format!("{}:/f:fork", source.display());
        let live_bind = format!("{}:{}/code:ro", live.display(), home.display());
        let error = prepare(
            parse_extra_mounts(&[fork, live_bind]).unwrap(),
            &mount_context,
        )
        .expect_err("the live bind's guest path shadows the persist link");
        assert!(
            error.is::<crate::guest_home::PersistCollision>(),
            "{error:#}"
        );
        assert!(
            !store.exists(),
            "the unrelated fork must not have been published"
        );
    }

    fn store_tree(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        fn visit(root: &Path, path: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
            for entry in fs::read_dir(path).unwrap() {
                let entry = entry.unwrap();
                let relative = entry.path().strip_prefix(root).unwrap().to_path_buf();
                let metadata = fs::symlink_metadata(entry.path()).unwrap();
                if metadata.is_dir() {
                    out.push((relative.clone(), b"directory".to_vec()));
                    visit(root, &entry.path(), out);
                } else if metadata.file_type().is_symlink() {
                    use std::os::unix::ffi::OsStrExt;
                    out.push((
                        relative,
                        fs::read_link(entry.path())
                            .unwrap()
                            .as_os_str()
                            .as_bytes()
                            .to_vec(),
                    ));
                } else {
                    out.push((relative, fs::read(entry.path()).unwrap()));
                }
            }
        }

        let mut entries = Vec::new();
        visit(root, root, &mut entries);
        entries.sort();
        entries
    }

    /// The two claim verdicts `--mount` reports today, byte for byte.
    ///
    /// `prepare`'s normalize/claim head is about to be extracted so user-config
    /// `mounts` share it; those two refusals are the ones that must stay
    /// identical for a CLI-only launch while gaining an origin for the config
    /// route. The positive controls below pin the other half of the same rule —
    /// identical declarations merge, and only the *normalized* guest spelling
    /// participates — so a refactor cannot trade one for the other.
    #[test]
    fn cli_claim_errors_are_pinned() {
        let root = tempfile::tempdir().unwrap();
        let first = root.path().join("first");
        let second = root.path().join("second");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        let store = tempfile::tempdir().unwrap();

        let mut with_core = context(store.path());
        with_core.core_guest_mounts = vec![PathBuf::from("/core")];
        let error = prepare(
            parse_extra_mounts(&[format!("{}:/core:ro", first.display())]).unwrap(),
            &with_core,
        )
        .unwrap_err();
        assert_eq!(
            format!("{error:#}"),
            "--mount guest path /core collides with an agent-vm core mount"
        );

        let error = prepare(
            parse_extra_mounts(&[
                format!("{}:/g//./x:ro", first.display()),
                format!("{}:/g/x:ro", second.display()),
            ])
            .unwrap(),
            &context(store.path()),
        )
        .unwrap_err();
        assert_eq!(
            format!("{error:#}"),
            "--mount guest path /g/x is claimed by different declarations"
        );

        // Identical declarations merge: one volume, and the guest spelling is
        // the normalized one for both routes into it.
        let plan = prepare(
            parse_extra_mounts(&[
                format!("{}:/g//./x:ro", first.display()),
                format!("{}:/g/x:ro", first.display()),
            ])
            .unwrap(),
            &context(store.path()),
        )
        .unwrap();
        assert_eq!(plan.volumes.len(), 1);
        assert_eq!(plan.volumes[0].guest, PathBuf::from("/g/x"));
    }

    /// One refusal, two renderings: the argv half of every sentence the config
    /// route rewrote, and the config half it gained.
    ///
    /// Two spellings are pinned because they are easy to "unify": `{:?}` for a
    /// declared spelling in the canonicalization context and `Path::display` for
    /// a resolved host. Neither may become the config escape policy, which turns
    /// `café` into `caf\xc3\xa9` and would silently change every argv launch's
    /// wording.
    #[test]
    fn refusal_contexts_are_pinned_per_declaration_source() {
        let config = Declaration::UserConfig {
            file: Path::new("/home/u/.config/agent-vm/config.toml"),
            index: 2,
        };
        // argv: `{:?}` quotes and keeps non-ASCII; `display()` prints it bare.
        assert_eq!(
            canonicalizing_context(Declaration::Argv, &Spelling::new("/srv/café")),
            "canonicalizing --mount host \"/srv/café\""
        );
        assert_eq!(
            validating_source_context(Declaration::Argv, Path::new("/srv/café")),
            "validating --mount source /srv/café"
        );
        // config: named by index and file, value escaped.
        assert_eq!(
            canonicalizing_context(config, &Spelling::new("/srv/café")),
            "canonicalizing mounts[2] in \"/home/u/.config/agent-vm/config.toml\" host \
             \"/srv/caf\\xc3\\xa9\""
        );
        assert_eq!(
            validating_source_context(config, Path::new("/srv/café")),
            "validating mounts[2] in \"/home/u/.config/agent-vm/config.toml\" source \
             \"/srv/caf\\xc3\\xa9\""
        );
        assert_eq!(
            config.subject(),
            "mounts[2] in \"/home/u/.config/agent-vm/config.toml\""
        );
        assert_eq!(
            Spelling::new("/srv/café").render(config),
            "\"/srv/caf\\xc3\\xa9\""
        );
        // The same spelling stays one line in a config refusal.
        assert_eq!(
            Spelling::new("/srv/a\nb").render(config),
            "\"/srv/a\\x0ab\""
        );
        // A `:fork` root context: argv has never named `--mount` here and never
        // quoted the path; a config entry names itself and escapes it, so a
        // newline in the entry cannot forge a diagnostic line.
        for verb in ["resolving", "validating"] {
            assert_eq!(
                fork_root_context(verb, Declaration::Argv, Path::new("/srv/café")),
                format!("{verb} fork root /srv/café")
            );
            assert_eq!(
                fork_root_context(verb, config, Path::new("/srv/café")),
                format!(
                    "{verb} mounts[2] in \"/home/u/.config/agent-vm/config.toml\" fork root \
                     \"/srv/caf\\xc3\\xa9\""
                )
            );
            assert_eq!(
                fork_root_context(verb, config, Path::new("/srv/a\nb")),
                format!(
                    "{verb} mounts[2] in \"/home/u/.config/agent-vm/config.toml\" fork root \
                     \"/srv/a\\x0ab\""
                )
            );
        }
    }

    /// The argv sentences end to end: a non-ASCII source spelling reaches the
    /// user exactly as typed, and each keeps the quoting it has always had.
    ///
    /// The `validating … source` sentence is deliberately absent: it is reachable
    /// only when a source vanishes between canonicalization and the kind check, so
    /// both of its renderings are pinned through
    /// [`refusal_contexts_are_pinned_per_declaration_source`] instead of through a
    /// filesystem race.
    #[test]
    fn argv_refusals_print_a_non_ascii_source_as_typed() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().canonicalize().unwrap();
        let store = tempfile::tempdir().unwrap();

        // A missing source: `{:?}` on the declared spelling, quotes and all.
        let missing = home.join("café-missing");
        let spelling = missing.display().to_string();
        let error = prepare(
            parse_extra_mounts(&[format!("{spelling}:/g:ro")]).unwrap(),
            &context(store.path()),
        )
        .unwrap_err();
        let rendered = format!("{error:#}");
        assert!(
            rendered.starts_with(&format!("canonicalizing --mount host {spelling:?}")),
            "{rendered}"
        );
        assert!(!rendered.contains(r"\xc3"), "{rendered}");

        // A regular file mounted writable: the bare spelling, no quotes.
        let file = home.join("café-file");
        fs::write(&file, "seed").unwrap();
        let error = prepare(
            parse_extra_mounts(&[format!("{}:/f:rw", file.display())]).unwrap(),
            &context(store.path()),
        )
        .unwrap_err();
        assert_eq!(
            format!("{error:#}"),
            format!(
                "--mount {}: a file can only be mounted read-only.\n\
                 Use :ro, or :fork its containing directory for a writable copy.",
                file.display()
            )
        );

        // A `:fork` over a regular file: the bare spelling again.
        let error = prepare(
            parse_extra_mounts(&[format!("{}:/fk:fork", file.display())]).unwrap(),
            &context(store.path()),
        )
        .unwrap_err();
        assert_eq!(
            format!("{error:#}"),
            format!(
                "--mount {}: a :fork source must be a directory.\n\
                 Fork the containing directory, or bind the file read-only with :ro.",
                file.display()
            )
        );

        // A FIFO: this sentence has never named `--mount`, and still does not, so
        // the argv text is unchanged even though the config route now names
        // `mounts[N]` here.
        let fifo = home.join("café-fifo");
        let c_path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        let error = prepare(
            parse_extra_mounts(&[format!("{}:/p:ro", fifo.display())]).unwrap(),
            &context(store.path()),
        )
        .unwrap_err();
        assert_eq!(
            format!("{error:#}"),
            format!("{} must be a regular file or directory", fifo.display())
        );
    }

    #[test]
    fn prepare_normalizes_guest_before_fork_identity() {
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("visible"), "seed").unwrap();
        let store = tempfile::tempdir().unwrap();
        let first = parse_extra_mounts(&[format!("{}:/guest//path:fork", source.path().display())])
            .unwrap();
        let second =
            parse_extra_mounts(&[format!("{}:/guest/./path:fork", source.path().display())])
                .unwrap();
        let first = prepare(first, &context(store.path())).unwrap();
        let second = prepare(second, &context(store.path())).unwrap();
        let first_host = match &first.volumes[0].source {
            PreparedVolumeSource::WritableBind(path) => path,
            _ => panic!("fork is writable"),
        };
        let second_host = match &second.volumes[0].source {
            PreparedVolumeSource::WritableBind(path) => path,
            _ => panic!("fork is writable"),
        };
        assert_eq!(first.volumes[0].guest, PathBuf::from("/guest/path"));
        assert_eq!(first_host, second_host);
    }

    #[test]
    fn ready_fork_reuses_after_source_removal() {
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("visible"), "seed").unwrap();
        let spelling = source.path().display().to_string();
        let store = tempfile::tempdir().unwrap();
        let request = format!("{spelling}:/guest:fork");
        let seeded = prepare(
            parse_extra_mounts(std::slice::from_ref(&request)).unwrap(),
            &context(store.path()),
        )
        .unwrap();
        let data = match &seeded.volumes[0].source {
            PreparedVolumeSource::WritableBind(path) => path.clone(),
            _ => panic!("fork is writable"),
        };
        fs::remove_dir_all(source.path()).unwrap();
        let reused = prepare(
            parse_extra_mounts(&[request]).unwrap(),
            &context(store.path()),
        )
        .unwrap();
        let reused_data = match &reused.volumes[0].source {
            PreparedVolumeSource::WritableBind(path) => path,
            _ => panic!("fork is writable"),
        };
        assert_eq!(reused_data, &data);
        assert_eq!(fs::read_to_string(data.join("visible")).unwrap(), "seed");
    }

    #[test]
    fn rejection_precedence_fork_source_then_canonicalization_then_file_rw() {
        // A bad fork root is rejected in preflight, before live-bind
        // canonicalization: the fork-source error wins over a missing live
        // source in the same argv.
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("file");
        fs::write(&file, "x").unwrap();
        let missing = root.path().join("missing");
        let store = tempfile::tempdir().unwrap();
        let error = prepare(
            parse_extra_mounts(&[
                format!("{}:/fork:fork", file.display()),
                format!("{}:/live:ro", missing.display()),
            ])
            .unwrap(),
            &context(store.path()),
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("a :fork source must be a directory"),
            "{error}"
        );

        // A missing live source is reported during canonicalization, before
        // the file-rw rejection in live-volume assembly.
        let file2 = root.path().join("file2");
        fs::write(&file2, "x").unwrap();
        let store = tempfile::tempdir().unwrap();
        let error = prepare(
            parse_extra_mounts(&[
                format!("{}:/file:rw", file2.display()),
                format!("{}:/missing:ro", missing.display()),
            ])
            .unwrap(),
            &context(store.path()),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("canonicalizing --mount host"), "{error}");
    }

    #[test]
    fn legacy_ready_file_kind_fails_closed_without_mutation() {
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("seed"), "seed").unwrap();
        let store = tempfile::tempdir().unwrap();
        let request = format!("{}:/guest:fork", source.path().display());
        let plan = prepare(
            parse_extra_mounts(std::slice::from_ref(&request)).unwrap(),
            &context(store.path()),
        )
        .unwrap();
        let data = match &plan.volumes[0].source {
            PreparedVolumeSource::WritableBind(path) => path.clone(),
            _ => panic!("fork is writable"),
        };
        let final_dir = data.parent().unwrap().to_path_buf();
        let manifest_path = final_dir.join("manifest.json");

        // Negative controls: `kind: directory` paired with non-directory data,
        // and a legacy `kind: file` with a valuable regular file.
        for (kind, make_file) in [("directory", true), ("file", true), ("file", false)] {
            if make_file {
                fs::remove_dir_all(&data)
                    .or_else(|_| fs::remove_file(&data))
                    .unwrap();
                fs::write(&data, "valuable bytes").unwrap();
            }
            let mut manifest: serde_json::Value =
                serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
            manifest["kind"] = serde_json::Value::String(kind.into());
            fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
            let before = store_tree(store.path());

            // The original source is removed to prove the failure does not
            // depend on it.
            fs::remove_dir_all(source.path()).ok();
            let error = prepare(
                parse_extra_mounts(std::slice::from_ref(&request)).unwrap(),
                &context(store.path()),
            )
            .unwrap_err()
            .to_string();
            assert!(
                error.contains(&final_dir.display().to_string()),
                "error must name the exact final directory: {error}"
            );
            assert!(error.contains("reset"), "{error}");
            assert_eq!(
                store_tree(store.path()),
                before,
                "a legacy/bad manifest must be retained unchanged (kind={kind})"
            );
            if make_file {
                assert_eq!(fs::read_to_string(&data).unwrap(), "valuable bytes");
            }
        }
    }

    #[test]
    fn exact_core_fork_collision_is_rejected_before_fork_store_creation() {
        // An explicit fork and a core mount at the same guest path is an exact
        // collision; the fork identity is otherwise valid.
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("hidden"), "secret").unwrap();
        let store = tempfile::tempdir().unwrap();
        let request = parse_extra_mounts(&[format!(
            "{}:/guest:fork:exclude=hidden",
            source.path().display()
        )])
        .unwrap();
        let mut context = context(store.path());
        context.core_guest_mounts.push(PathBuf::from("/guest"));
        assert!(prepare(request, &context).is_err());
        assert!(fs::read_dir(store.path()).unwrap().next().is_none());
    }

    #[test]
    fn exact_core_explicit_collision_has_no_store_side_effects() {
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("seed"), "seed").unwrap();
        let store = tempfile::tempdir().unwrap();
        let request =
            parse_extra_mounts(&[format!("{}:/core:fork", source.path().display())]).unwrap();
        let mut mount_context = context(store.path());
        mount_context.core_guest_mounts.push(PathBuf::from("/core"));

        let error = prepare(request, &mount_context).unwrap_err();
        assert!(error.to_string().contains("core mount"), "{error:#}");
        assert!(
            fs::read_dir(store.path()).unwrap().next().is_none(),
            "an exact explicit/core collision must not create fork state"
        );
    }

    #[test]
    fn exact_core_followed_collision_has_no_store_side_effects_in_either_order() {
        use std::os::unix::fs::symlink;

        for fork_first in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let root_path = root.path().canonicalize().unwrap();
            let home = root_path.join("home");
            let live = home.join("live");
            let target = home.join("core-target");
            let fork_source = root_path.join("fork-source");
            fs::create_dir_all(&live).unwrap();
            fs::create_dir(&target).unwrap();
            fs::create_dir(&fork_source).unwrap();
            symlink(&target, live.join("core-alias")).unwrap();
            let followed = format!("{}:/guest:ro:follow-links", live.display());
            let fork = format!("{}:/fork:fork", fork_source.display());
            let declarations = if fork_first {
                vec![fork, followed]
            } else {
                vec![followed, fork]
            };
            let store = tempfile::tempdir().unwrap();
            let mount_context = MountContext {
                mount_store: store.path().to_path_buf(),
                authority_home: Some(home.clone()),
                account_home: None,
                host_home: Some(home),
                core_guest_mounts: vec![target],
                core_host_sources: Vec::new(),
                persisted_home: crate::guest_home::PersistedHome::none(),
            };

            let error =
                prepare(parse_extra_mounts(&declarations).unwrap(), &mount_context).unwrap_err();
            assert!(error.to_string().contains("core mount"), "{error:#}");
            assert!(
                fs::read_dir(store.path()).unwrap().next().is_none(),
                "an exact followed/core collision must not create fork state (fork_first={fork_first})"
            );
        }
    }

    #[test]
    fn file_rw_rejection_precedes_fork_store_creation_in_either_order() {
        let fork_source = tempfile::tempdir().unwrap();
        fs::create_dir(fork_source.path().join("seed")).unwrap();
        let file_source = tempfile::tempdir().unwrap();
        let file = file_source.path().join("plain-file");
        fs::write(&file, "content").unwrap();

        for declarations in [
            vec![
                format!("{}:/fork:fork", fork_source.path().display()),
                format!("{}:/live/file", file.display()),
            ],
            vec![
                format!("{}:/live/file", file.display()),
                format!("{}:/fork:fork", fork_source.path().display()),
            ],
        ] {
            // An absent mount-store path must stay absent: the file-rw
            // rejection is a policy error, not a fork transaction.
            let store = file_source.path().join("absent-store");
            let error =
                prepare(parse_extra_mounts(&declarations).unwrap(), &context(&store)).unwrap_err();
            assert!(
                error.to_string().contains("can only be mounted read-only"),
                "{error:#}"
            );
            assert!(!store.exists(), "rejection must not create the mount store");
        }
    }

    #[test]
    fn file_ro_parent_topology_rejection_is_side_effect_free_in_either_order() {
        let fork_source = tempfile::tempdir().unwrap();
        fs::create_dir(fork_source.path().join("seed")).unwrap();
        let file_source = tempfile::tempdir().unwrap();
        let file = file_source.path().join("plain-file");
        fs::write(&file, "content").unwrap();
        let child_source = tempfile::tempdir().unwrap();

        for declarations in [
            vec![
                format!("{}:/fork:fork", fork_source.path().display()),
                format!("{}:/live/file:ro", file.display()),
                format!("{}:/live/file/child:ro", child_source.path().display()),
            ],
            vec![
                format!("{}:/live/file/child:ro", child_source.path().display()),
                format!("{}:/live/file:ro", file.display()),
                format!("{}:/fork:fork", fork_source.path().display()),
            ],
        ] {
            let store = file_source.path().join("absent-store");
            assert!(!store.exists());
            let error =
                prepare(parse_extra_mounts(&declarations).unwrap(), &context(&store)).unwrap_err();
            assert!(error.to_string().contains("below file mount"), "{error:#}");
            assert!(!store.exists(), "rejection must be side-effect free");
        }
    }

    #[test]
    fn file_fork_roots_reject_before_store_creation_and_retry_after_becoming_directory() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        fs::write(&source, "seed").unwrap();
        let store = tempfile::tempdir().unwrap();

        // Plain, excluded, and follow-links file forks all reject before the
        // store exists; the old plain-file fork success path is gone.
        for request in [
            format!("{}:/guest:fork", source.display()),
            format!("{}:/guest:fork:exclude=hidden", source.display()),
            format!("{}:/guest:fork:follow-links", source.display()),
        ] {
            let error = prepare(
                parse_extra_mounts(&[request]).unwrap(),
                &context(store.path()),
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("must be a directory"), "{error}");
            assert!(fs::read_dir(store.path()).unwrap().next().is_none());
        }

        // Turning the same spelling into a directory makes the same identity
        // resolvable on retry (the file rejection did not poison it).
        fs::remove_file(&source).unwrap();
        fs::create_dir(&source).unwrap();
        fs::write(source.join("visible"), "seed").unwrap();
        let valid = format!("{}:/guest:fork", source.display());
        assert!(
            prepare(
                parse_extra_mounts(&[valid]).unwrap(),
                &context(store.path())
            )
            .is_ok()
        );
    }

    #[test]
    fn first_use_fork_kind_validates_core_explicit_and_followed_descendants() {
        use std::os::unix::fs::symlink;

        // A directory fork keeps accepting descendant claims (explicit,
        // followed, and core) in either declaration order.
        for fork_first in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let source = root.path().join("source");
            fs::create_dir(&source).unwrap();
            let child = root.path().join("child");
            fs::create_dir(&child).unwrap();
            let live = root.path().join("live");
            fs::create_dir(&live).unwrap();
            symlink(&child, live.join("followed-child")).unwrap();
            let fork = format!("{}:{}:fork", source.display(), root.path().display());
            let explicit = format!("{}:{}:ro", child.display(), child.display());
            let followed = format!("{}:ro:follow-links", live.display());

            for child_claim in [&explicit, &followed] {
                let declarations = if fork_first {
                    vec![fork.clone(), child_claim.to_string()]
                } else {
                    vec![child_claim.to_string(), fork.clone()]
                };
                let store = tempfile::tempdir().unwrap();
                let result = prepare(
                    parse_extra_mounts(&declarations).unwrap(),
                    &MountContext {
                        mount_store: store.path().to_path_buf(),
                        authority_home: Some(root.path().to_path_buf()),
                        account_home: None,
                        host_home: Some(root.path().to_path_buf()),
                        core_guest_mounts: vec![root.path().join("core-child")],
                        core_host_sources: Vec::new(),
                        persisted_home: crate::guest_home::PersistedHome::none(),
                    },
                );
                assert!(
                    result.is_ok(),
                    "directory fork must allow child: {result:?}"
                );
            }
        }

        // A file fork root is rejected with the directory-only diagnostic,
        // never a `below file mount` topology error, even with descendants.
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source-file");
        fs::write(&source, "seed").unwrap();
        let child = root.path().join("child");
        fs::create_dir(&child).unwrap();
        let store = tempfile::tempdir().unwrap();
        let error = prepare(
            parse_extra_mounts(&[
                format!("{}:/guest:fork", source.display()),
                format!("{}:/guest/child:ro", child.display()),
            ])
            .unwrap(),
            &context(store.path()),
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("a :fork source must be a directory"),
            "{error}"
        );
        assert!(fs::read_dir(store.path()).unwrap().next().is_none());
    }

    #[test]
    fn readonly_file_bind_rejects_explicit_followed_and_core_descendants() {
        use std::os::unix::fs::symlink;

        // Explicit child below a read-only file bind, both orders.
        for file_first in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let file = root.path().join("plain-file");
            fs::write(&file, "content").unwrap();
            let child_source = root.path().join("explicit-child");
            fs::create_dir(&child_source).unwrap();
            let file_mount = format!("{}:/guest/file:ro", file.display());
            let child = format!("{}:/guest/file/child:ro", child_source.display());
            let declarations = if file_first {
                vec![file_mount.clone(), child]
            } else {
                vec![child, file_mount.clone()]
            };
            let store = tempfile::tempdir().unwrap();
            let error = prepare(
                parse_extra_mounts(&declarations).unwrap(),
                &context(store.path()),
            )
            .unwrap_err();
            assert!(error.to_string().contains("below file mount"), "{error:#}");
            assert!(fs::read_dir(store.path()).unwrap().next().is_none());
        }

        // A followed target whose discovered guest path is below the file
        // bind is rejected. The file is mounted at the guest spelling of a
        // real directory `D`; the live root is elsewhere and links into `D`.
        let home = tempfile::tempdir().unwrap();
        let home_path = home.path().canonicalize().unwrap();
        let file = home_path.join("plain-file");
        fs::write(&file, "content").unwrap();
        let live = home_path.join("live");
        let d = home_path.join("d");
        let sub = d.join("sub");
        fs::create_dir_all(&sub).unwrap();
        fs::create_dir(&live).unwrap();
        symlink(&sub, live.join("link")).unwrap();
        let file_mount = format!("{}:{}:ro", file.display(), d.display());
        let followed = format!("{}:ro:follow-links", live.display());
        let store = tempfile::tempdir().unwrap();
        let error = prepare(
            parse_extra_mounts(&[file_mount, followed]).unwrap(),
            &MountContext {
                mount_store: store.path().to_path_buf(),
                authority_home: Some(home_path.clone()),
                account_home: None,
                host_home: Some(home_path.clone()),
                core_guest_mounts: Vec::new(),
                core_host_sources: Vec::new(),
                persisted_home: crate::guest_home::PersistedHome::none(),
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("below file mount"), "{error:#}");
        assert!(fs::read_dir(store.path()).unwrap().next().is_none());

        // Core child below a read-only file bind.
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("plain-file");
        fs::write(&file, "content").unwrap();
        let store = tempfile::tempdir().unwrap();
        let mut mount_context = context(store.path());
        mount_context
            .core_guest_mounts
            .push(PathBuf::from("/guest/file/core-child"));
        let error = prepare(
            parse_extra_mounts(&[format!("{}:/guest/file:ro", file.display())]).unwrap(),
            &mount_context,
        )
        .unwrap_err();
        assert!(error.to_string().contains("below file mount"), "{error:#}");
        assert!(fs::read_dir(store.path()).unwrap().next().is_none());
    }

    #[test]
    fn ready_directory_fork_allows_explicit_child_in_either_declaration_order() {
        for fork_first in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let source = root.path().join("source-directory");
            let child = root.path().join("child-directory");
            fs::create_dir(&source).unwrap();
            fs::create_dir(&child).unwrap();
            let store = tempfile::tempdir().unwrap();
            let fork = format!("{}:/guest/directory:fork", source.display());
            prepare(
                parse_extra_mounts(std::slice::from_ref(&fork)).unwrap(),
                &context(store.path()),
            )
            .expect("first launch seeds the directory fork");
            fs::remove_dir(&source).unwrap();

            let child_mount = format!("{}:/guest/directory/child:ro", child.display());
            let declarations = if fork_first {
                vec![fork, child_mount]
            } else {
                vec![child_mount, fork]
            };
            prepare(
                parse_extra_mounts(&declarations).unwrap(),
                &context(store.path()),
            )
            .expect("a READY directory fork permits a nested mount");
        }
    }

    #[test]
    fn file_ro_below_core_is_rejected_before_store_or_launch_work() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source-file");
        fs::write(&source, "seed").unwrap();
        let store = tempfile::tempdir().unwrap();
        let mut mount_context = context(store.path());
        mount_context
            .core_guest_mounts
            .push(PathBuf::from("/tmp/project"));

        let error = prepare(
            parse_extra_mounts(&[format!("{}:/tmp:ro", source.display())]).unwrap(),
            &mount_context,
        )
        .expect_err("a core directory below a read-only file bind cannot be mounted");
        assert!(error.to_string().contains("below file mount"), "{error:#}");
        assert!(
            fs::read_dir(store.path()).unwrap().next().is_none(),
            "topology validation must precede fork-store creation"
        );
    }

    #[test]
    fn concurrent_initializer_waits_for_ready_after_source_is_removed() {
        // Re-exec this exact unit test for the second initializer. `flock`
        // is process-scoped, so threads would incorrectly share the lock.
        if std::env::var_os("AGENT_VM_FORK_WAITER").is_some() {
            let store = PathBuf::from(std::env::var_os("AGENT_VM_FORK_STORE").unwrap());
            let request = std::env::var("AGENT_VM_FORK_REQUEST").unwrap();
            let result = prepare(parse_extra_mounts(&[request]).unwrap(), &context(&store))
                .expect("waiter must reuse READY");
            let data = match &result.volumes[0].source {
                PreparedVolumeSource::WritableBind(path) => path,
                _ => panic!("fork is writable"),
            };
            std::fs::write(
                std::env::var_os("AGENT_VM_FORK_RESULT").unwrap(),
                format!("{}\n{}", data.display(), result.notices.join("\n")),
            )
            .unwrap();
            return;
        }

        let _checkpoint_guard = COPY_CHECKPOINT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
            mpsc,
        };

        let source_root = tempfile::tempdir().unwrap();
        let source = source_root.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("waiter-stage-marker"), "initial").unwrap();
        fs::write(source.join("excluded"), "never copied").unwrap();
        let store = tempfile::tempdir().unwrap();
        let request = format!("{}:/guest:fork:exclude=excluded", source.display());
        let (staged_tx, staged_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let paused = Arc::new(AtomicBool::new(false));
        let checkpoint_paused = Arc::clone(&paused);
        set_copy_checkpoint(
            &source,
            Box::new(move |path| {
                // `waiter-stage-marker` is reached after copy_root has opened the root through
                // its pinned descriptor, so renaming the declaration path cannot
                // disrupt the first initializer's already-staged traversal.
                if path == Path::new("waiter-stage-marker")
                    && !checkpoint_paused.swap(true, Ordering::SeqCst)
                {
                    staged_tx.send(()).unwrap();
                    resume_rx.recv().unwrap();
                }
            }),
        );

        let first_store = store.path().to_path_buf();
        let first_request = request.clone();
        let first = std::thread::spawn(move || {
            prepare(
                parse_extra_mounts(&[first_request]).unwrap(),
                &context(&first_store),
            )
            .unwrap()
        });
        staged_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("first initializer must stage while holding its fork lock");
        fs::rename(&source, source_root.path().join("source-moved")).unwrap();

        let waiter_result = source_root.path().join("waiter-result");
        let mut second = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "mount::prepare_tests::concurrent_initializer_waits_for_ready_after_source_is_removed",
                "--nocapture",
            ])
            .env("AGENT_VM_FORK_WAITER", "1")
            .env("AGENT_VM_FORK_STORE", store.path())
            .env("AGENT_VM_FORK_REQUEST", &request)
            .env("AGENT_VM_FORK_RESULT", &waiter_result)
            .spawn()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(
            second.try_wait().unwrap().is_none(),
            "second initializer must wait for the lock instead of preflighting the removed source"
        );
        resume_tx.send(()).unwrap();
        let first_plan = first.join().unwrap();
        assert!(second.wait().unwrap().success(), "waiter must reuse READY");
        clear_copy_checkpoint();

        let fork_path = match &first_plan.volumes[0].source {
            PreparedVolumeSource::WritableBind(path) => path.clone(),
            _ => panic!("fork is writable"),
        };
        let waiter = fs::read_to_string(waiter_result).unwrap();
        assert!(
            waiter.starts_with(&fork_path.display().to_string()),
            "{waiter}"
        );
        assert_eq!(
            fs::read_to_string(fork_path.join("waiter-stage-marker")).unwrap(),
            "initial"
        );
        assert!(waiter.contains("Reusing fork"), "{waiter}");
    }

    #[test]
    fn killed_initializer_leaves_only_retryable_staging() {
        if std::env::var_os("AGENT_VM_FORK_KILLED_INITIALIZER").is_some() {
            let store = PathBuf::from(std::env::var_os("AGENT_VM_FORK_STORE").unwrap());
            let request = std::env::var("AGENT_VM_FORK_REQUEST").unwrap();
            prepare(parse_extra_mounts(&[request]).unwrap(), &context(&store)).unwrap();
            return;
        }

        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("kill-here"), "seed").unwrap();
        let store = tempfile::tempdir().unwrap();
        let request = format!("{}:/guest:fork", source.display());
        let ready = root.path().join("copy-started");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "mount::prepare_tests::killed_initializer_leaves_only_retryable_staging",
                "--nocapture",
            ])
            .env("AGENT_VM_FORK_KILLED_INITIALIZER", "1")
            .env("AGENT_VM_FORK_STORE", store.path())
            .env("AGENT_VM_FORK_REQUEST", &request)
            .env("AGENT_VM_FORK_KILL_CHECKPOINT", "kill-here")
            .env("AGENT_VM_FORK_KILL_READY", &ready)
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !ready.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "initializer did not reach copy"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());

        let retry = prepare(
            parse_extra_mounts(&[request]).unwrap(),
            &context(store.path()),
        )
        .expect("a killed initializer must be retryable");
        let data = match &retry.volumes[0].source {
            PreparedVolumeSource::WritableBind(path) => path,
            _ => panic!("fork is writable"),
        };
        assert_eq!(fs::read_to_string(data.join("kill-here")).unwrap(), "seed");
        assert_eq!(
            fs::read_dir(store.path().join("staging")).unwrap().count(),
            0
        );
        assert_eq!(fs::read_dir(store.path().join("forks")).unwrap().count(), 1);
    }

    #[test]
    fn concurrent_initializers_publish_one_reusable_fork() {
        use std::sync::{Arc, Barrier};

        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("seed"), "initial").unwrap();
        let store = tempfile::tempdir().unwrap();
        let request = format!("{}:/guest:fork", source.path().display());
        let barrier = Arc::new(Barrier::new(2));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let barrier = Arc::clone(&barrier);
            let store = store.path().to_path_buf();
            let request = request.clone();
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                prepare(parse_extra_mounts(&[request]).unwrap(), &context(&store)).unwrap()
            }));
        }
        let plans: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        let paths: Vec<_> = plans
            .iter()
            .map(|plan| match &plan.volumes[0].source {
                PreparedVolumeSource::WritableBind(path) => path.clone(),
                _ => panic!("fork must be writable"),
            })
            .collect();
        assert_eq!(paths[0], paths[1]);
        assert!(paths[0].is_dir());
        assert_eq!(
            fs::read_to_string(paths[0].join("seed")).unwrap(),
            "initial"
        );
        assert_eq!(
            fs::read_dir(store.path().join("forks")).unwrap().count(),
            1,
            "only one READY directory may be published"
        );
        assert_eq!(
            fs::read_dir(store.path().join("staging")).unwrap().count(),
            0,
            "a waiter must never observe or publish staging"
        );
    }

    #[test]
    fn excluded_symlink_is_not_followed_or_planned() {
        use std::os::unix::fs::symlink;

        let home = tempfile::tempdir().unwrap();
        let source = home.path().join("source");
        let target = home.path().join("target");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&target).unwrap();
        symlink(&target, source.join("hidden-link")).unwrap();
        let (targets, _) = discover_followed_targets(
            &BindPath {
                host: source,
                guest: PathBuf::from("/guest"),
                exclusions: vec![PathBuf::from("hidden-link")],
            },
            home.path(),
            Declaration::Argv,
        )
        .unwrap();
        assert!(targets.iter().all(|target_plan| target_plan.host != target));
    }

    #[test]
    fn descriptor_swap_at_root_nested_file_directory_and_link_fails_closed() {
        let _checkpoint_guard = COPY_CHECKPOINT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        use std::os::unix::fs::symlink;

        // The root case starts as a real directory and is swapped for both a
        // symlink-to-external-directory and a regular file: this is exactly
        // what `copy_root`'s `O_DIRECTORY` descriptor open must reject. Nested
        // file/directory/link swaps stay as they were.
        for (victim, root_replacement) in [
            ("root", "symlink"),
            ("root", "file"),
            ("file", "symlink"),
            ("directory", "symlink"),
            ("link", "symlink"),
        ] {
            let swapped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let root = tempfile::tempdir().unwrap();
            let source = root.path().join("source");
            let external_file = root.path().join("external-file");
            let external_dir = root.path().join("external-dir");
            fs::create_dir(&source).unwrap();
            fs::write(source.join("kept"), "inside").unwrap();
            fs::write(&external_file, "outside").unwrap();
            fs::create_dir(&external_dir).unwrap();
            fs::write(external_dir.join("outside"), "outside").unwrap();
            match victim {
                "root" => {}
                "file" => fs::write(source.join("file"), "inside").unwrap(),
                "directory" => {
                    fs::create_dir(source.join("directory")).unwrap();
                    fs::write(source.join("directory/item"), "inside").unwrap();
                }
                "link" => symlink(&external_file, source.join("link")).unwrap(),
                _ => unreachable!(),
            }
            let swap = if victim == "root" {
                source.clone()
            } else {
                source.join(victim)
            };
            let root_source = source.clone();
            let checkpoint = PathBuf::from(victim);
            let external_file_capture = external_file.clone();
            let external_dir_capture = external_dir.clone();
            let swapping_link = victim == "link";
            let root_replacement_kind = root_replacement.to_string();
            let swapped_at_checkpoint = std::sync::Arc::clone(&swapped);
            set_copy_checkpoint(
                &source,
                Box::new(move |seen| {
                    let root_checkpoint =
                        swap == root_source && seen == root_source.canonicalize().unwrap();
                    if root_checkpoint || seen == checkpoint {
                        swapped_at_checkpoint.store(true, std::sync::atomic::Ordering::SeqCst);
                        let replacement = swap.with_extension("swapped");
                        // A rename makes the check/open window deterministic.
                        fs::rename(&swap, &replacement).unwrap();
                        if swapping_link {
                            fs::hard_link(&external_file_capture, &swap).unwrap();
                        } else if root_checkpoint && root_replacement_kind == "file" {
                            fs::write(&swap, "swapped").unwrap();
                        } else if root_checkpoint {
                            symlink(&external_dir_capture, &swap).unwrap();
                        } else {
                            symlink(&external_file_capture, &swap).unwrap();
                        }
                    }
                }),
            );
            let store = tempfile::tempdir().unwrap();
            let request = format!("{}:/guest:fork", source.display());
            assert!(
                prepare(
                    parse_extra_mounts(&[request]).unwrap(),
                    &context(store.path())
                )
                .is_err(),
                "swap at {victim}/{root_replacement} was accepted"
            );
            clear_copy_checkpoint();
            assert!(
                swapped.load(std::sync::atomic::Ordering::SeqCst),
                "checkpoint at {victim}/{root_replacement} did not run"
            );
            assert!(
                fs::read_dir(store.path().join("forks"))
                    .unwrap()
                    .next()
                    .is_none()
            );
            assert_eq!(
                fs::read_to_string(external_dir.join("outside")).unwrap(),
                "outside",
                "external content must not be mutated"
            );
        }
    }

    #[test]
    fn follow_copy_rejects_cycles_and_depth_but_materializes_two_aliases() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap();
        symlink(".", source.join("cycle")).unwrap();
        let store = tempfile::tempdir().unwrap();
        let request = format!("{}:/guest:fork:follow-links", source.display());
        let error = prepare(
            parse_extra_mounts(std::slice::from_ref(&request)).unwrap(),
            &context(store.path()),
        )
        .unwrap_err()
        .chain()
        .map(|cause| cause.to_string())
        .collect::<Vec<_>>()
        .join(": ");
        assert!(error.contains("cycle"), "{error}");
        assert!(
            fs::read_dir(store.path().join("forks"))
                .unwrap()
                .next()
                .is_none()
        );

        fs::remove_file(source.join("cycle")).unwrap();
        let target = root.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("value"), "copied").unwrap();
        symlink(&target, source.join("one")).unwrap();
        symlink(&target, source.join("two")).unwrap();
        let plan = prepare(
            parse_extra_mounts(&[request]).unwrap(),
            &context(store.path()),
        )
        .unwrap();
        let data = match &plan.volumes[0].source {
            PreparedVolumeSource::WritableBind(path) => path,
            _ => unreachable!(),
        };
        assert_eq!(
            fs::read_to_string(data.join("one/value")).unwrap(),
            "copied"
        );
        assert_eq!(
            fs::read_to_string(data.join("two/value")).unwrap(),
            "copied"
        );
    }

    #[test]
    fn follow_copy_accepts_deep_links_and_rejects_an_overlong_chain() {
        use std::os::unix::fs::symlink;

        fn seed_through_chain(link_count: usize) -> Result<String> {
            let root = tempfile::tempdir().unwrap();
            let source = root.path().join("source");
            let target = root.path().join("target");
            fs::create_dir(&source).unwrap();
            fs::create_dir(&target).unwrap();
            fs::write(target.join("value"), "copied").unwrap();
            for index in (0..link_count).rev() {
                let destination = target.join(format!("link-{index}"));
                let raw_target = if index + 1 == link_count {
                    PathBuf::from("value")
                } else {
                    PathBuf::from(format!("link-{}", index + 1))
                };
                symlink(raw_target, destination).unwrap();
            }
            symlink(target.join("link-0"), source.join("link")).unwrap();
            let store = tempfile::tempdir().unwrap();
            let plan = prepare(
                parse_extra_mounts(&[format!("{}:/guest:fork:follow-links", source.display())])
                    .unwrap(),
                &context(store.path()),
            )?;
            let data = match &plan.volumes[0].source {
                PreparedVolumeSource::WritableBind(path) => path,
                _ => unreachable!(),
            };
            fs::read_to_string(data.join("link")).map_err(Into::into)
        }

        // Darwin rejects a chain at its lower kernel limit, before a
        // descriptor can expose every individual link. Exercise a deep chain
        // below that portable limit, then prove the declared overlong chain
        // fails cleanly rather than recursing or publishing a fork.
        let deep =
            seed_through_chain(FORK_MAX_LINK_DEPTH / 2).unwrap_or_else(|error| panic!("{error:#}"));
        assert_eq!(deep, "copied");
        let error = format!("{:#}", seed_through_chain(FORK_MAX_LINK_DEPTH).unwrap_err());
        assert!(
            error.contains("maximum symlink follow depth") || error.contains("Too many levels"),
            "{error}"
        );
    }

    #[test]
    fn transaction_retries_stale_stage_and_rejects_ready_corruption() {
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("value"), "seed").unwrap();
        let store = tempfile::tempdir().unwrap();
        let request =
            parse_extra_mounts(&[format!("{}:/guest:fork", source.path().display())]).unwrap();
        let id = fork_id(&request[0], IDENTITY_VERSION);
        ensure_store(store.path()).unwrap();
        fs::create_dir(
            store
                .path()
                .join("staging")
                .join(format!("{id}.stage-crashed")),
        )
        .unwrap();
        let plan = prepare(request, &context(store.path())).unwrap();
        assert!(store.path().join("forks").join(&id).join("data").exists());
        assert!(
            store
                .path()
                .join("staging")
                .read_dir()
                .unwrap()
                .next()
                .is_none()
        );
        let data = match &plan.volumes[0].source {
            PreparedVolumeSource::WritableBind(path) => path,
            _ => unreachable!(),
        };
        fs::remove_dir_all(data).unwrap();
        let error = prepare(
            parse_extra_mounts(&[format!("{}:/guest:fork", source.path().display())]).unwrap(),
            &context(store.path()),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("remove it to reset"), "{error}");
    }

    #[test]
    fn root_symlink_seeds_a_real_directory_and_reuses_after_target_changes() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("seed"), "first").unwrap();
        let declaration = root.path().join("declaration");
        symlink(&target, &declaration).unwrap();
        let store = tempfile::tempdir().unwrap();
        let request = format!("{}:/guest:fork", declaration.display());
        let seeded = prepare(
            parse_extra_mounts(std::slice::from_ref(&request)).unwrap(),
            &context(store.path()),
        )
        .unwrap();
        let data = match &seeded.volumes[0].source {
            PreparedVolumeSource::WritableBind(path) => path.clone(),
            _ => panic!("fork must be writable"),
        };
        assert!(fs::symlink_metadata(&data).unwrap().is_dir());
        fs::remove_dir_all(&target).unwrap();
        let reused = prepare(
            parse_extra_mounts(&[request]).unwrap(),
            &context(store.path()),
        )
        .unwrap();
        let reused_data = match &reused.volumes[0].source {
            PreparedVolumeSource::WritableBind(path) => path,
            _ => panic!("fork must be writable"),
        };
        assert_eq!(reused_data, &data);
        assert_eq!(fs::read_to_string(data.join("seed")).unwrap(), "first");
    }

    // ── protected host files (issue #90) ─────────────────────────────

    /// A `$HOME` with a real `~/.pi`, and a context pointed at it. The
    /// `TempDir` is returned so it outlives the context.
    fn pi_home() -> (tempfile::TempDir, PathBuf) {
        let home = tempfile::tempdir().unwrap();
        let canonical = home.path().canonicalize().unwrap();
        fs::create_dir_all(canonical.join(".pi/agent")).unwrap();
        fs::write(canonical.join(".pi/agent/auth.json"), "{\"token\":\"t\"}").unwrap();
        fs::write(canonical.join(".pi/agent/models.json"), "{}").unwrap();
        fs::write(canonical.join(".pi/settings.json"), "{}").unwrap();
        (home, canonical)
    }

    fn fork_data(plan: &PreparedMountPlan) -> PathBuf {
        match &plan.volumes[0].source {
            PreparedVolumeSource::WritableBind(path) => path.clone(),
            other => panic!("fork must be writable, got {other:?}"),
        }
    }

    #[test]
    fn ro_and_rw_mounts_of_pi_home_are_refused_before_store_creation() {
        let (_home, home) = pi_home();
        for declaration in [
            format!("{}:ro", home.join(".pi").display()),
            format!("{}:rw", home.join(".pi").display()),
            format!("{}:ro", home.display()),
            format!("{}:/mnt/pi:ro", home.join(".pi").display()),
        ] {
            let store = tempfile::tempdir().unwrap();
            let error = prepare(
                parse_extra_mounts(std::slice::from_ref(&declaration)).unwrap(),
                &context_with_home(store.path(), home.clone()),
            )
            .unwrap_err()
            .to_string();
            assert!(
                error.contains(&home.join(".pi/agent/auth.json").display().to_string()),
                "{declaration}: {error}"
            );
            assert!(error.contains(":fork"), "{declaration}: {error}");
            assert!(
                store_tree(store.path()).is_empty(),
                "a refused plan must not create fork state: {declaration}"
            );
        }
    }

    #[test]
    fn followed_symlink_alias_to_pi_home_is_refused() {
        use std::os::unix::fs::symlink;

        let (_home, home) = pi_home();
        let live = tempfile::tempdir().unwrap();
        let link = live.path().join("pi-link");
        symlink(home.join(".pi"), &link).unwrap();
        let declaration = format!("{}:ro:follow-links", live.path().display());
        let store = tempfile::tempdir().unwrap();

        let error = prepare(
            parse_extra_mounts(std::slice::from_ref(&declaration)).unwrap(),
            &context_with_home(store.path(), home.clone()),
        )
        .unwrap_err()
        .to_string();
        // The *discovered* bind is the leak; the message names the declaration
        // it came from, because the user never typed that path.
        assert!(error.contains("discovered by --mount"), "{error}");
        assert!(
            error.contains(&live.path().display().to_string()),
            "{error}"
        );
        assert!(store_tree(store.path()).is_empty(), "{error}");
    }

    /// With two `:follow-links` declarations, `expand_follow_links` does not
    /// record which one discovered a target (and legitimately merges the two
    /// when both do), so the refusal must not blame both — let alone the one
    /// that contributed nothing.
    #[test]
    fn a_discovered_leak_with_two_follow_links_declarations_blames_neither() {
        use std::os::unix::fs::symlink;

        let (_home, home) = pi_home();
        let leak = home.join("leak");
        let innocent = home.join("innocent");
        fs::create_dir_all(&leak).unwrap();
        fs::create_dir_all(&innocent).unwrap();
        symlink(home.join(".pi"), leak.join("pi-link")).unwrap();
        let declarations = [
            format!("{}:ro:follow-links", leak.display()),
            format!("{}:ro:follow-links", innocent.display()),
        ];
        let store = tempfile::tempdir().unwrap();

        let error = prepare(
            parse_extra_mounts(&declarations).unwrap(),
            &context_with_home(store.path(), home.clone()),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("would expose"), "{error}");
        assert!(
            error.contains("discovered by one of your --mount"),
            "{error}"
        );
        assert!(!error.contains("discovered by --mount"), "{error}");
        assert!(store_tree(store.path()).is_empty(), "{error}");
    }

    // ── The argv sites that render a spelling themselves, printed whole ──

    /// The user config file every config-declaration fixture names.
    const CONFIG_FILE: &str = "/home/u/.config/agent-vm/config.toml";

    /// One config entry as a `prepare` request, built the way
    /// `config_mounts::from_verified_value` builds it: the entry's own origin
    /// and the shared grammar.
    fn config_request(index: usize, entry: &str) -> MountRequest {
        MountRequest {
            origin: MountOrigin::UserConfig {
                file: PathBuf::from(CONFIG_FILE),
                index,
            },
            mount: parse_mount_spec(entry, HostSyntax::AbsoluteOnly)
                .expect("the test declaration parses"),
        }
    }

    /// Three argv messages render a declared spelling themselves — the
    /// Pi-credential refusal, the `Omitted` notice and the `Initialized fork`
    /// notice — and each is asserted as a whole line, with a spelling the config
    /// escape policy would rewrite. A regression at any one of those sites
    /// (`mount.rs`'s `protected.message` caller, `prepare_forks`'s two notices)
    /// changes a line here; a `contains` would not notice.
    #[test]
    fn argv_notices_and_refusals_print_a_spelling_as_typed() {
        use std::os::unix::fs::symlink;

        let (_home, home) = pi_home();
        // A symlink so the *declared* spelling differs from the canonical source
        // the exposure is measured on; `café` is what the config escape policy
        // would rewrite, so an argv site that switched to it fails below.
        let alias = home.join("café-pi");
        symlink(home.join(".pi"), &alias).unwrap();
        let spelling = alias.display().to_string();

        // 1. The refusal. One line, and the spelling as typed.
        let store = tempfile::tempdir().unwrap();
        let error = prepare(
            parse_extra_mounts(&[format!("{spelling}:ro")]).unwrap(),
            &context_with_home(store.path(), home.clone()),
        )
        .unwrap_err()
        .to_string();
        let first = error.lines().next().expect("a refusal sentence");
        assert_eq!(
            first,
            format!(
                "--mount {spelling} would expose the host Pi credential file {} \
                 (as agent/auth.json inside {})",
                home.join(".pi/agent/auth.json").display(),
                home.join(".pi").display()
            ),
            "{error}"
        );

        // 2. The two notices. The store path is read back, so the only free
        // variable left in either line is the rendering under test.
        let store = tempfile::tempdir().unwrap();
        let plan = prepare(
            parse_extra_mounts(&[format!("{spelling}:/pi:fork")]).unwrap(),
            &context_with_home(store.path(), home.clone()),
        )
        .unwrap();
        let fork_dir = fs::read_dir(store.path().join("forks"))
            .unwrap()
            .next()
            .expect("a published fork")
            .unwrap()
            .path();
        let initialized = plan
            .notices
            .iter()
            .find(|notice| notice.starts_with("==> Initialized fork "))
            .unwrap_or_else(|| panic!("no initialization notice: {:?}", plan.notices));
        assert_eq!(
            initialized,
            &format!(
                "==> Initialized fork {spelling} -> {} (reset: {})",
                fork_dir.join("data").display(),
                fork_dir.display()
            )
        );
        let omitted = plan
            .notices
            .iter()
            .find(|notice| notice.starts_with("==> Omitted") && notice.contains("auth.json"))
            .unwrap_or_else(|| panic!("no omission notice: {:?}", plan.notices));
        assert_eq!(
            omitted,
            &format!(
                "==> Omitted host Pi credential file agent/auth.json from the fork of {spelling}"
            )
        );
    }

    /// The provenance phrase for a config-discovered leak: one candidate names
    /// the entry, and several name the *sources* present — never a `--mount` the
    /// launch did not make.
    #[test]
    fn a_config_discovered_leak_names_config_sources_not_argv() {
        use std::os::unix::fs::symlink;

        let (_home, home) = pi_home();
        let leak = home.join("leak");
        let innocent = home.join("innocent");
        fs::create_dir_all(&leak).unwrap();
        fs::create_dir_all(&innocent).unwrap();
        symlink(home.join(".pi"), leak.join("pi-link")).unwrap();

        // One candidate: the phrase names the entry that made the bind
        // discoverable. The *subject* stays `--mount`: a discovered bind is not a
        // declaration, and `expand_follow_links` does not record which
        // declaration discovered it (see `DeclaredOrigins`), so the entry is
        // named where it is known — in the phrase — and pinned here.
        let store = tempfile::tempdir().unwrap();
        let error = prepare(
            MountRequests::new(vec![config_request(
                0,
                &format!("{}:ro:follow-links", leak.display()),
            )]),
            &context_with_home(store.path(), home.clone()),
        )
        .unwrap_err()
        .to_string();
        assert_eq!(
            error.lines().next().expect("a refusal sentence"),
            format!(
                "--mount {pi} would expose the host Pi credential file {auth} \
                 (as agent/auth.json inside {pi}) (discovered by mounts[0] in \
                 \"{CONFIG_FILE}\" \"{leak}\":follow-links)",
                pi = home.join(".pi").display(),
                auth = home.join(".pi/agent/auth.json").display(),
                leak = leak.display()
            )
        );
        assert!(store_tree(store.path()).is_empty(), "{error}");

        // Two candidates: no single entry is blamed, and the phrase names the
        // sources present — never a `--mount` this launch did not make.
        let store = tempfile::tempdir().unwrap();
        let error = prepare(
            MountRequests::new(vec![
                config_request(0, &format!("{}:ro:follow-links", leak.display())),
                config_request(1, &format!("{}:ro:follow-links", innocent.display())),
            ]),
            &context_with_home(store.path(), home.clone()),
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains(&format!(
                "(discovered by one of your mounts in \"{CONFIG_FILE}\" …:follow-links \
                 declarations)"
            )),
            "{error}"
        );
        assert!(
            !error.contains("discovered by one of your --mount"),
            "{error}"
        );
        assert!(!error.contains("discovered by mounts[0]"), "{error}");
    }

    /// A `:fork` source the entry expanded to and could not resolve: the context
    /// names the entry and escapes the path, so a newline in the name cannot
    /// forge a diagnostic line.
    #[test]
    fn a_config_fork_root_refusal_names_the_entry_and_stays_one_line() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let home = root.path().canonicalize().unwrap();
        let store = tempfile::tempdir().unwrap();
        // A dangling symlink: `canonicalize` fails, which is the `resolving`
        // context. The name carries the newline.
        let source = home.join("dang\nFORGED-LINE");
        symlink(home.join("gone"), &source).unwrap();

        let error = prepare(
            MountRequests::new(vec![config_request(
                0,
                &format!("{}:/g:fork", source.display()),
            )]),
            &context_with_home(store.path(), home.clone()),
        )
        .unwrap_err();

        assert_eq!(
            error.chain().next().expect("the context").to_string(),
            format!(
                "resolving mounts[0] in \"{CONFIG_FILE}\" fork root \
                 \"{}/dang\\x0aFORGED-LINE\"",
                home.display()
            )
        );
        assert!(!error.to_string().contains('\n'), "{error}");
        assert!(
            store_tree(store.path()).is_empty(),
            "a refused fork must not publish state"
        );
    }

    /// A `:follow-links` walk that finds a link escaping `$HOME`: the refusal
    /// names the entry and escapes every path in it, including the link whose
    /// name carries the newline.
    #[test]
    fn a_config_follow_links_refusal_names_the_entry_and_stays_one_line() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let home = root.path().canonicalize().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside = outside.path().canonicalize().unwrap();
        let source = home.join("tree");
        fs::create_dir(&source).unwrap();
        symlink(&outside, source.join("escape\nFORGED2")).unwrap();
        let store = tempfile::tempdir().unwrap();

        let error = prepare(
            MountRequests::new(vec![config_request(
                0,
                &format!("{}:/g:ro:follow-links", source.display()),
            )]),
            &context_with_home(store.path(), home.clone()),
        )
        .unwrap_err()
        .to_string();

        assert_eq!(
            error,
            format!(
                "mounts[0] in \"{CONFIG_FILE}\" follow-links: symlink \
                 \"{home}/tree/escape\\x0aFORGED2\" resolves to \"{outside}\", which is outside \
                 your $HOME (\"{home}\"); refusing to mount it",
                home = home.display(),
                outside = outside.display()
            )
        );
        assert!(!error.contains('\n'), "{error}");
    }

    /// Two declarations claim one guest path and one of them is a config entry:
    /// the refusal renders each side for its own source. The explicit entry here
    /// carries a newline in the name, so the historical bare-host text would have
    /// forged a line; the discovered side has no declaring entry, which is why it
    /// still reads `--mount`.
    #[test]
    fn a_config_claim_conflict_escapes_the_entry_and_stays_one_line() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let home = root.path().canonicalize().unwrap();
        let target = home.join("tgt");
        let walked = home.join("walked");
        let forged = home.join("b\nFORGED3");
        fs::create_dir(&target).unwrap();
        fs::create_dir(&walked).unwrap();
        fs::create_dir(&forged).unwrap();
        // The walk discovers `tgt` at its own path, which the second entry also
        // claims by guest path — with a different host.
        symlink(&target, walked.join("link")).unwrap();
        let store = tempfile::tempdir().unwrap();

        let error = prepare(
            MountRequests::new(vec![
                config_request(0, &format!("{}:/g:ro:follow-links", walked.display())),
                config_request(1, &format!("{}:{}:ro", forged.display(), target.display())),
            ]),
            &context_with_home(store.path(), home.clone()),
        )
        .unwrap_err()
        .to_string();

        assert_eq!(
            error,
            format!(
                "guest path {tgt} is claimed by different declarations (mounts[1] in \
                 \"{CONFIG_FILE}\" \"{home}/b\\x0aFORGED3\" and --mount \"{tgt}\")",
                tgt = target.display(),
                home = home.display()
            )
        );
        assert!(!error.contains('\n'), "{error}");
        assert!(store_tree(store.path()).is_empty(), "{error}");
    }

    /// The A3 regression guard at the site that was actually wrong: a
    /// `:follow-links` target inside the Pi home is refused, and that refusal
    /// prints the discovered bind's own spelling — which the walk measured. When
    /// that spelling is filed as argv text it renders verbatim, and a `$HOME`
    /// whose name carries a newline forges a diagnostic line.
    #[test]
    fn a_discovered_binds_spelling_is_escaped_in_a_refusal() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("ho\nme");
        fs::create_dir_all(home.join(".pi/agent")).unwrap();
        fs::write(home.join(".pi/agent/auth.json"), "{\"token\":\"t\"}").unwrap();
        let home = home.canonicalize().unwrap();
        let repo = home.join("repo");
        fs::create_dir(&repo).unwrap();
        // The symlink's target is the Pi home itself, so the discovered bind is a
        // live bind of host Pi state and preparation refuses it.
        symlink(home.join(".pi"), repo.join("link")).unwrap();
        let store = tempfile::tempdir().unwrap();

        let error = prepare(
            parse_extra_mounts(&[format!("{}:/r:ro:follow-links", repo.display())]).unwrap(),
            &context_with_home(store.path(), home.clone()),
        )
        .unwrap_err();

        let rendered = format!("{error:#}");
        // The refusal is three lines by construction: the finding, the
        // explanation, and the remedy. A newline in `$HOME` must add none.
        assert_eq!(
            rendered.lines().count(),
            3,
            "the refusal's own three lines, and no forged one: {rendered}"
        );
        assert!(
            rendered.contains("ho\\x0ame"),
            "the measured spelling is escaped: {rendered}"
        );
        assert!(
            !rendered
                .lines()
                .any(|line| line.trim_start().starts_with("me/")),
            "the spelling forged a line: {rendered}"
        );
    }

    /// A spelling is the *expanded* value (`~/repo` becomes `$HOME/repo`), so it
    /// carries whatever bytes the environment has, and a `:follow-links` bind's
    /// spelling is a canonical target nobody typed at all. Both renderers escape
    /// control characters, so no spelling can end the line it is printed on.
    /// Ordinary and non-ASCII paths are unchanged, which is what the pinned
    /// diagnostics hold to.
    #[test]
    fn a_spelling_cannot_end_the_line_it_is_printed_on() {
        let spelling = Spelling::new("/srv/ok\nFORGED-SPELLING");
        assert_eq!(
            spelling.render(Declaration::Argv),
            "/srv/ok\\x0aFORGED-SPELLING"
        );
        // The quoted form was already line-safe: `{:?}` renders a control
        // character as Rust's escape (`\n`), not as the byte.
        assert_eq!(
            spelling.render_quoted(Declaration::Argv),
            "\"/srv/ok\\nFORGED-SPELLING\""
        );
        assert_eq!(
            Spelling::new("/srv/ok").render(Declaration::Argv),
            "/srv/ok"
        );
        assert_eq!(
            Spelling::new("/srv/проект").render(Declaration::Argv),
            "/srv/проект"
        );
    }

    /// The copier reports the name it *measured*, which no declaration check has
    /// seen: a fork source is a directory, so anything inside it — including a
    /// FIFO whose name carries a newline — is named by the walk itself. It is
    /// escaped for the same reason declared spellings are, or the refusal ends
    /// and everything after the newline starts at column 0.
    #[test]
    fn a_fork_copy_refusal_escapes_the_measured_name() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().canonicalize().unwrap();
        let store = tempfile::tempdir().unwrap();
        let source = home.join("tree");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("kept"), "seed").unwrap();
        // A FIFO rather than a socket or device: cheap, and a non-directory
        // non-regular node is exactly what the walk refuses. The copier opens
        // with NONBLOCK, so a reader that never arrives cannot hang it.
        let fifo = source.join("p\nFORGED5");
        let c_path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

        let error = prepare(
            parse_extra_mounts(&[format!("{}:/g:fork", source.display())]).unwrap(),
            &context_with_home(store.path(), home.clone()),
        )
        .unwrap_err();

        let rendered = format!("{error:#}");
        assert_eq!(
            rendered.lines().count(),
            1,
            "one line, never a forged second: {rendered}"
        );
        assert!(rendered.contains("p\\x0aFORGED5"), "{rendered}");
        assert!(
            !rendered.lines().any(|line| line.trim() == "FORGED5"),
            "the measured name is escaped, not printed as a line: {rendered}"
        );
    }

    #[test]
    fn fork_of_pi_home_omits_both_files_and_copies_everything_else() {
        let (_home, home) = pi_home();
        fs::create_dir_all(home.join(".pi/extensions")).unwrap();
        fs::write(home.join(".pi/extensions/x.js"), "x").unwrap();
        let store = tempfile::tempdir().unwrap();
        let plan = prepare(
            parse_extra_mounts(&[format!("{}:/pi:fork", home.join(".pi").display())]).unwrap(),
            &context_with_home(store.path(), home.clone()),
        )
        .unwrap();
        let data = fork_data(&plan);

        assert!(data.join("settings.json").is_file());
        assert!(data.join("extensions/x.js").is_file());
        // The containing directory stays; only the protected files are absent.
        assert!(data.join("agent").is_dir());
        assert!(!data.join("agent/auth.json").exists());
        assert!(!data.join("agent/models.json").exists());
        let notices = plan.notices.join("\n");
        assert!(
            notices.contains("Omitted host Pi credential file agent/auth.json"),
            "{notices}"
        );
        assert!(
            notices.contains("Omitted host Pi provider-configuration file agent/models.json"),
            "{notices}"
        );
    }

    #[test]
    fn fork_follow_links_does_not_materialize_a_protected_target() {
        use std::os::unix::fs::symlink;

        let (_home, home) = pi_home();
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("keep"), "keep").unwrap();
        symlink(home.join(".pi/agent/auth.json"), source.path().join("link")).unwrap();
        let store = tempfile::tempdir().unwrap();
        let plan = prepare(
            parse_extra_mounts(&[format!(
                "{}:/guest:fork:follow-links",
                source.path().display()
            )])
            .unwrap(),
            &context_with_home(store.path(), home.clone()),
        )
        .unwrap();
        let data = fork_data(&plan);

        assert!(data.join("keep").is_file());
        // Not a symlink, and not the materialized target: nothing at all.
        assert!(!data.join("link").exists());
        assert!(
            plan.notices
                .join("\n")
                .contains("Omitted host Pi credential file link"),
            "{:?}",
            plan.notices
        );
    }

    #[test]
    fn fork_omits_a_hardlink_to_a_protected_file() {
        let (_home, home) = pi_home();
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("keep"), "keep").unwrap();
        fs::hard_link(
            home.join(".pi/agent/auth.json"),
            source.path().join("copy.json"),
        )
        .unwrap();
        let store = tempfile::tempdir().unwrap();
        let plan = prepare(
            parse_extra_mounts(&[format!("{}:/guest:fork", source.path().display())]).unwrap(),
            &context_with_home(store.path(), home.clone()),
        )
        .unwrap();
        let data = fork_data(&plan);

        assert!(data.join("keep").is_file());
        assert!(!data.join("copy.json").exists());
        assert!(
            plan.notices
                .join("\n")
                .contains("Omitted host Pi credential file copy.json"),
            "{:?}",
            plan.notices
        );
    }

    /// The identity signal alone fails this: the file does not exist when
    /// `measure` runs, so it has no measured inode. Only the fork-root-relative
    /// path signal catches it. It isolates *relative vs. identity* — **not**
    /// static vs. measured route (R3.4): the path signal here is the measured
    /// route set, and the assertion would hold identically if the static table
    /// were empty. It also pins the ordering precondition that the measurement
    /// stays **before** `copy_checkpoint` (§4.4.3): move the measurement after
    /// the checkpoint and it sees the file the checkpoint just created, so
    /// identity rescues the omission and the fixture silently stops isolating
    /// anything.
    #[test]
    fn fork_omits_a_protected_file_created_after_measurement() {
        let _checkpoint_guard = COPY_CHECKPOINT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let source = tempfile::tempdir().unwrap();
        let canonical = source.path().canonicalize().unwrap();
        fs::write(canonical.join("keep"), "keep").unwrap();
        // Arming on the *root* fires before the directory is enumerated, so
        // the new file is deterministically mid-copy rather than racing
        // readdir.
        let target = canonical.clone();
        set_copy_checkpoint(
            &canonical,
            Box::new(move |path| {
                if path == target {
                    fs::create_dir_all(target.join(".pi/agent")).unwrap();
                    fs::write(target.join(".pi/agent/auth.json"), "{\"token\":\"t\"}").unwrap();
                }
            }),
        );
        let store = tempfile::tempdir().unwrap();
        let result = prepare(
            parse_extra_mounts(&[format!("{}:/guest:fork", canonical.display())]).unwrap(),
            // No `~/.pi` at measure time: the fork root is this home.
            &context_with_home(store.path(), canonical.clone()),
        );
        clear_copy_checkpoint();
        let plan = result.unwrap();
        let data = fork_data(&plan);

        assert!(data.join("keep").is_file());
        assert!(!data.join(".pi/agent/auth.json").exists());
        assert!(
            plan.notices
                .join("\n")
                .contains("Omitted host Pi credential file .pi/agent/auth.json"),
            "{:?}",
            plan.notices
        );
        assert!(canonical.join(".pi/agent/auth.json").is_file());
    }

    #[test]
    fn protected_refusal_precedes_validate_plan_topology_errors() {
        let (_home, home) = pi_home();
        let file = tempfile::tempdir().unwrap();
        let plain = file.path().join("plain");
        fs::write(&plain, "plain").unwrap();

        // Both orders: a leaky plan that is *also* invalid still reports the
        // leak, because every pass before this one is read-only.
        for declarations in [
            vec![
                format!("{}:/leak:ro", home.join(".pi").display()),
                format!("{}:/leak/f:ro", plain.display()),
            ],
            vec![
                format!("{}:/leak/f:ro", plain.display()),
                format!("{}:/leak:ro", home.join(".pi").display()),
            ],
        ] {
            let store = tempfile::tempdir().unwrap();
            let error = prepare(
                parse_extra_mounts(&declarations).unwrap(),
                &context_with_home(store.path(), home.clone()),
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("would expose"), "{error}");
            assert!(store_tree(store.path()).is_empty(), "{error}");
        }

        // The companion: an earlier-stage rejection still wins, pinning the
        // honest precedence (side-effect freedom, not "security message
        // first").
        let store = tempfile::tempdir().unwrap();
        let error = prepare(
            parse_extra_mounts(&[
                format!("{}:/fork:fork", plain.display()),
                format!("{}:/leak:ro", home.join(".pi").display()),
            ])
            .unwrap(),
            &context_with_home(store.path(), home.clone()),
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("a :fork source must be a directory"),
            "{error}"
        );
    }

    #[test]
    fn core_project_bind_that_is_home_is_refused() {
        let (_home, home) = pi_home();
        let store = tempfile::tempdir().unwrap();
        let mut ctx = context_with_home(store.path(), home.clone());
        ctx.core_host_sources = vec![CoreHostSource::new(CoreBind::ProjectDir, home.clone())];

        let error = prepare(Vec::new(), &ctx).unwrap_err().to_string();
        assert!(error.contains("project directory"), "{error}");
        assert!(
            error.contains(&home.join(".pi/agent/auth.json").display().to_string()),
            "{error}"
        );
        assert!(error.contains("instead of $HOME"), "{error}");
        assert!(store_tree(store.path()).is_empty(), "{error}");
    }

    #[test]
    fn core_project_bind_inside_pi_home_is_refused() {
        let (_home, home) = pi_home();
        let store = tempfile::tempdir().unwrap();
        let mut ctx = context_with_home(store.path(), home.clone());
        ctx.core_host_sources = vec![CoreHostSource::new(CoreBind::ProjectDir, home.join(".pi"))];

        let error = prepare(Vec::new(), &ctx).unwrap_err().to_string();
        assert!(error.contains("project directory"), "{error}");
        assert!(
            error.contains(&format!("outside {}", home.join(".pi").display())),
            "{error}"
        );

        // An unrelated core source is untouched by the same check.
        ctx.core_host_sources = vec![CoreHostSource::new(
            CoreBind::ProjectDir,
            home.join("elsewhere"),
        )];
        fs::create_dir(home.join("elsewhere")).unwrap();
        assert!(prepare(Vec::new(), &ctx).is_ok());
    }

    /// A *below-`agent`* cwd inside the Pi home exposes no protected file, so
    /// it is allowed — but it is a writable live window onto host Pi state, so
    /// both advisories must fire with no `--mount` at all (issue #90's warning
    /// deliverable, which the core binds were missing).
    #[test]
    fn core_project_bind_inside_pi_home_below_agent_warns() {
        let (_home, home) = pi_home();
        fs::create_dir_all(home.join(".pi/extensions")).unwrap();
        fs::write(home.join(".pi/extensions/x.js"), "x").unwrap();
        let store = tempfile::tempdir().unwrap();
        let mut ctx = context_with_home(store.path(), home.clone());
        ctx.core_host_sources = vec![CoreHostSource::new(
            CoreBind::ProjectDir,
            home.join(".pi/extensions"),
        )];

        let plan = prepare(Vec::new(), &ctx).unwrap();
        let notices = plan.notices.join("\n");
        assert!(
            notices.contains("is a live bind of host Pi state"),
            "{notices}"
        );
        assert!(
            notices.contains("may be built for this host's OS/arch"),
            "{notices}"
        );
        assert!(
            notices.contains("run agent-vm from a project directory outside"),
            "{notices}"
        );
    }

    #[test]
    fn pi_home_advisories_repeat_on_a_reused_fork() {
        let (_home, home) = pi_home();
        let store = tempfile::tempdir().unwrap();
        let declaration = format!("{}:/pi:fork", home.join(".pi").display());
        let declaration = parse_extra_mounts(&[declaration]).unwrap();

        let seeded = prepare(
            declaration.clone(),
            &context_with_home(store.path(), home.clone()),
        )
        .unwrap();
        assert!(seeded.notices.join("\n").contains("Initialized fork"));
        assert!(
            seeded
                .notices
                .join("\n")
                .contains("may not run in the Linux guest"),
            "{:?}",
            seeded.notices
        );

        // `preflight_forks` repoints the fork at its committed data, so a
        // notice keyed on `mount.host` would silently stop firing here.
        let reused = prepare(declaration, &context_with_home(store.path(), home.clone())).unwrap();
        assert!(reused.notices.join("\n").contains("Reusing fork"));
        assert!(
            reused
                .notices
                .join("\n")
                .contains("may not run in the Linux guest"),
            "{:?}",
            reused.notices
        );
    }

    /// A fork's own notices name paths this run *measured* — the store's fork
    /// directory and its committed data. `AGENT_VM_STATE_DIR` is the user's to
    /// choose, so a newline in it must not end a notice and start a forged one.
    /// (The legacy-fork warning is a third such notice; it has its own test.)
    #[test]
    fn a_fork_notice_escapes_the_measured_store_path() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().canonicalize().unwrap();
        let store = home.join("st\ngore");
        fs::create_dir_all(&store).unwrap();
        let source = home.join("tree");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("visible"), "seed").unwrap();
        let requests = || parse_extra_mounts(&[format!("{}:/g:fork", source.display())]).unwrap();

        let seeded = prepare(requests(), &context_with_home(&store, home.clone())).unwrap();
        let reused = prepare(requests(), &context_with_home(&store, home.clone())).unwrap();
        let notices = seeded
            .notices
            .iter()
            .chain(reused.notices.iter())
            .filter(|notice| notice.contains("fork at") || notice.contains("Initialized fork"))
            .collect::<Vec<_>>();
        assert_eq!(notices.len(), 2, "both fork notices: {:?}", notices);
        for notice in notices {
            assert!(!notice.contains('\n'), "one line: {notice}");
            assert!(notice.contains("st\\x0agore"), "escaped: {notice}");
        }
    }

    #[test]
    fn pi_extensions_live_bind_warns_and_is_allowed() {
        let (_home, home) = pi_home();
        fs::create_dir_all(home.join(".pi/extensions")).unwrap();
        fs::write(home.join(".pi/extensions/x.js"), "x").unwrap();
        let store = tempfile::tempdir().unwrap();
        let plan = prepare(
            parse_extra_mounts(&[format!("{}:ro", home.join(".pi/extensions").display())]).unwrap(),
            &context_with_home(store.path(), home.clone()),
        )
        .unwrap();

        let notices = plan.notices.join("\n");
        assert!(
            notices.contains("is a live bind of host Pi state"),
            "{notices}"
        );
        assert!(
            notices.contains("may be built for this host's OS/arch"),
            "{notices}"
        );
        assert!(!notices.contains("Omitted"), "{notices}");
    }

    #[test]
    fn non_pi_mounts_and_forks_are_unchanged() {
        let (_home, home) = pi_home();
        for (label, home_home) in [("pi home present", Some(home.clone())), ("no .pi", None)] {
            let home_home = home_home.unwrap_or_else(test_home);
            let source = tempfile::tempdir().unwrap();
            fs::write(source.path().join("seed"), "seed").unwrap();
            let store = tempfile::tempdir().unwrap();
            let plan = prepare(
                parse_extra_mounts(&[format!("{}:ro", source.path().display())]).unwrap(),
                &context_with_home(store.path(), home_home.clone()),
            )
            .unwrap();
            assert!(plan.notices.is_empty(), "{label}: {:?}", plan.notices);

            let store = tempfile::tempdir().unwrap();
            let fork = prepare(
                parse_extra_mounts(&[format!("{}:/guest:fork", source.path().display())]).unwrap(),
                &context_with_home(store.path(), home_home),
            )
            .unwrap();
            let notices = fork.notices.join("\n");
            assert!(!notices.contains("Omitted"), "{label}: {notices}");
            assert!(!notices.contains("host Pi state"), "{label}: {notices}");
        }
    }

    /// M13: the per-fork lock coordinates fork *initializers*, not host Pi
    /// writers. A host process replaces the whole fork root — credential and
    /// all — after the source kind is checked, before the copy. The copier
    /// resolves the recreated root at T1 and measures it at T2, so its routes
    /// name the credential; the omission is an outcome regression, not a
    /// signal-isolating test (R3.4).
    #[test]
    fn fork_omission_survives_a_fork_root_recreated_after_measurement() {
        let home = tempfile::tempdir().unwrap();
        let home = home.path().canonicalize().unwrap();
        let source = home.join(".pi");
        fs::create_dir(&source).unwrap();
        let store = tempfile::tempdir().unwrap();
        // The lock `prepare_forks` holds; no host writer is obliged to take it.
        let data = fork_data_with_one_resolution_point(
            &home,
            &source,
            || {},
            || {
                // The host replaces the tree, with both protected files, before
                // the copy point's resolve/measurement.
                fs::remove_dir_all(&source).unwrap();
                fs::create_dir_all(source.join("agent")).unwrap();
                fs::write(source.join("agent/auth.json"), "synthetic-secret").unwrap();
                fs::write(source.join("agent/models.json"), "synthetic-models").unwrap();
            },
            store.path(),
        );
        assert!(data.join("agent").is_dir());
        assert!(
            !data.join("agent/auth.json").exists(),
            "the recreated credential was copied"
        );
        assert!(!data.join("agent/models.json").exists());
    }

    /// R1: an ordinary atomic credential replacement must not make the copier
    /// forget an inode the launch's first measurement positively identified.
    /// `backup-*.json` are hardlinks to the *old* credential bytes; the fresh
    /// measurement sees only the replacement, so omission has to union the
    /// preflight identities with the fresh ones rather than replace them.
    #[test]
    fn fork_omission_retains_a_preflight_credential_identity() {
        use std::os::unix::fs::MetadataExt;

        let (_home, home) = pi_home();
        let source = home.join("unrelated-fork");
        fs::create_dir(&source).unwrap();
        fs::hard_link(
            home.join(".pi/agent/auth.json"),
            source.join("backup-auth.json"),
        )
        .unwrap();
        fs::hard_link(
            home.join(".pi/agent/models.json"),
            source.join("backup-models.json"),
        )
        .unwrap();
        // The same measurement `prepare` takes before expanding/validating.
        let original = ProtectedHostFiles::measure(Some(&home)).unwrap();
        let backup = fs::metadata(source.join("backup-auth.json")).unwrap();
        assert!(
            original
                .identities()
                .matched(backup.dev(), backup.ino())
                .is_some(),
            "the preflight measurement must know the hardlink's inode"
        );

        // Ordinary atomic replacements of both protected files.
        for (path, body) in [
            (home.join(".pi/agent/auth.json"), "replacement-auth"),
            (home.join(".pi/agent/models.json"), "replacement-models"),
        ] {
            let replacement = path.with_extension("replacement");
            fs::write(&replacement, body).unwrap();
            fs::rename(&replacement, &path).unwrap();
        }

        let store = tempfile::tempdir().unwrap();
        let mut mounts = parse_extra_mounts(&[format!("{}:/fork:fork", source.display())]).unwrap();
        prepare_forks(
            &mut mounts,
            store.path(),
            &std::collections::HashMap::new(),
            &original,
            &DeclaredOrigins::new(),
        )
        .unwrap();
        assert!(
            !mounts[0].host.join("backup-auth.json").exists(),
            "the fresh measurement discarded a known credential inode and copied it"
        );
        assert!(!mounts[0].host.join("backup-models.json").exists());
    }

    /// A fork root that did not exist at the top of `prepare` still gets the
    /// omission signals: the copier re-measures at its own resolve point and
    /// loses no knowledge the earlier snapshot had, and the static path table
    /// names the protected files under the root even when no measurement saw
    /// it.
    #[test]
    fn fork_root_created_after_measure_is_still_omitted() {
        let home = tempfile::tempdir().unwrap();
        let home = home.path().canonicalize().unwrap();
        let source = home.join(".pi");
        let store = tempfile::tempdir().unwrap();
        let mut mounts = parse_extra_mounts(&[format!("{}:/pi:fork", source.display())]).unwrap();
        // `prepare`'s measurement happens first, and `~/.pi` does not exist
        // yet, so that snapshot knows nothing of the fork root.
        let stale = ProtectedHostFiles::measure(Some(&home)).unwrap();

        // …then `~/.pi` and its credential appear, before `prepare_forks`.
        fs::create_dir_all(source.join("agent")).unwrap();
        fs::write(source.join("agent/auth.json"), "{\"token\":\"t\"}").unwrap();
        fs::write(source.join("settings.json"), "{}").unwrap();

        prepare_forks(
            &mut mounts,
            store.path(),
            &std::collections::HashMap::new(),
            &stale,
            &DeclaredOrigins::new(),
        )
        .unwrap();
        let data = &mounts[0].host;

        assert!(data.join("settings.json").is_file());
        assert!(data.join("agent").is_dir());
        assert!(!data.join("agent/auth.json").exists());
    }

    // ── The fork copier's single resolution point (Revision 4) ────────

    /// Drive the copier through its single resolve point with R3.4's corrected
    /// chronology: measure the launch → `after_launch_measurement()` (restore
    /// what the launch must **not** have seen) → the per-fork lock and the
    /// source-kind check → `at_the_resolve_point()` → `copy_root`, which
    /// resolves the root (T1), measures there (T2) and copies. Returns the
    /// staged fork data.
    fn fork_data_with_one_resolution_point(
        home_for_measure: &Path,
        root_spelling: &Path,
        after_launch_measurement: impl FnOnce(),
        at_the_resolve_point: impl FnOnce(),
        store: &Path,
    ) -> PathBuf {
        let launch = ProtectedHostFiles::measure(Some(home_for_measure)).unwrap();
        after_launch_measurement();
        let lock = open_regular_lock(&store.join("fork.lock")).unwrap();
        flock_exclusive(&lock).unwrap();
        require_fork_directory(
            fork_source_kind(root_spelling, Declaration::Argv).unwrap(),
            Declaration::Argv,
            &Spelling::new(root_spelling.display().to_string()),
        )
        .unwrap();
        at_the_resolve_point();
        let policy = CopyPolicy {
            exclusions: &[],
            follow: false,
            protected: &launch,
        };
        let data = store.join("data");
        let mut report = CopyReport::default();
        copy_root(
            root_spelling,
            &data,
            &policy,
            Declaration::Argv,
            &mut report,
        )
        .unwrap();
        data
    }

    /// The armed hooks for the M13 rename window plus the run flags. Dropping it
    /// clears both callback slots, so a panicking test cannot leave one armed.
    struct MissingRootRace {
        hid: std::sync::Arc<std::sync::atomic::AtomicBool>,
        restored: std::sync::Arc<std::sync::atomic::AtomicBool>,
        _resolve: ResolveCheckpointGuard,
        _copy: CopyCheckpointGuard,
    }

    impl MissingRootRace {
        fn assert_ran(&self) {
            use std::sync::atomic::Ordering;
            assert!(
                self.hid.load(Ordering::SeqCst),
                "the resolve hook did not run"
            );
            assert!(
                self.restored.load(Ordering::SeqCst),
                "the copy hook did not run"
            );
        }
    }

    /// Arm both of R4's hooks so `pi_directory` is hidden across the copy-point
    /// measurement (T2) and the pure relatives derivation (T3), then restored
    /// with both credentials between T3 and the open (T4) — the M13 rename
    /// window, replayed through the real ordering (MF1). `canonical_root` is the
    /// path the copier resolves to, and the scope both hooks match. The caller
    /// must hold `COPY_CHECKPOINT_TEST_LOCK` for the whole lifetime.
    fn hide_the_pi_directory_across_the_copy_point(
        canonical_root: &Path,
        pi_directory: &Path,
        stash: &Path,
    ) -> MissingRootRace {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let hid = Arc::new(AtomicBool::new(false));
        let restored = Arc::new(AtomicBool::new(false));

        let pi_hide = pi_directory.to_path_buf();
        let stash_hide = stash.to_path_buf();
        let hid_flag = Arc::clone(&hid);
        let resolve = ResolveCheckpointGuard::arm(
            canonical_root,
            Box::new(move |_| {
                fs::rename(&pi_hide, &stash_hide).unwrap();
                assert!(
                    !pi_hide.exists(),
                    "the resolve hook did not hide the Pi directory"
                );
                hid_flag.store(true, Ordering::SeqCst);
            }),
        );

        let pi_restore = pi_directory.to_path_buf();
        let stash_restore = stash.to_path_buf();
        let root_match = canonical_root.to_path_buf();
        let restored_flag = Arc::clone(&restored);
        let copy = CopyCheckpointGuard::arm(
            canonical_root,
            Box::new(move |path| {
                if path == root_match && !restored_flag.swap(true, Ordering::SeqCst) {
                    assert!(
                        !pi_restore.exists(),
                        "the Pi directory reappeared before the copy point's open"
                    );
                    fs::rename(&stash_restore, &pi_restore).unwrap();
                    fs::create_dir_all(pi_restore.join("agent")).unwrap();
                    fs::write(pi_restore.join("agent/auth.json"), "synthetic-secret").unwrap();
                    fs::write(pi_restore.join("agent/models.json"), "synthetic-models").unwrap();
                }
            }),
        );
        MissingRootRace {
            hid,
            restored,
            _resolve: resolve,
            _copy: copy,
        }
    }

    /// Outcome-regression control through the real M13 rename window (MF1): the
    /// root resolves at T1, the real Pi directory is hidden across the T2
    /// measurement and T3 relatives, and it is restored with both credentials
    /// just before the T4 open. The canonical spelling is the control — its
    /// literal spelling still equals the configured Pi home.
    #[test]
    fn fork_omits_through_a_canonical_root_spelling() {
        let _guard = COPY_CHECKPOINT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let home = tempfile::tempdir().unwrap();
        let home = home.path().canonicalize().unwrap();
        let root = home.join(".pi");
        fs::create_dir_all(root.join("agent")).unwrap();
        fs::write(root.join("settings.json"), "{}").unwrap();
        let race =
            hide_the_pi_directory_across_the_copy_point(&root, &root, &home.join("stashed-pi"));
        let store = tempfile::tempdir().unwrap();
        let data = fork_data_with_one_resolution_point(&home, &root, || {}, || {}, store.path());

        race.assert_ran();
        assert!(
            root.join("agent/auth.json").is_file(),
            "the credential must exist at the open, or the omission is vacuous"
        );
        assert!(
            data.join("settings.json").is_file(),
            "ordinary content must be copied"
        );
        assert!(
            !data.join("agent/auth.json").exists(),
            "the canonical control copied the credential"
        );
        assert!(!data.join("agent/models.json").exists());
    }

    /// F1 #1 through the same M13 window: `$HOME`, and therefore the
    /// `--mount ~/.pi:fork` spelling, is reached through a symlink. The copier
    /// canonicalizes the root itself, so the alias is folded (N1a/N1b are the
    /// sibling spellings).
    #[test]
    fn fork_omits_through_a_symlinked_home_spelling() {
        use std::os::unix::fs::symlink;
        let _guard = COPY_CHECKPOINT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        let home = base.join("home");
        fs::create_dir(&home).unwrap();
        let alias = base.join("home-alias");
        symlink(&home, &alias).unwrap();
        let real_root = home.join(".pi");
        fs::create_dir_all(real_root.join("agent")).unwrap();
        fs::write(real_root.join("settings.json"), "{}").unwrap();
        let race = hide_the_pi_directory_across_the_copy_point(
            &real_root,
            &real_root,
            &home.join("stashed-pi"),
        );
        let store = tempfile::tempdir().unwrap();
        let data = fork_data_with_one_resolution_point(
            &alias,
            &alias.join(".pi"),
            || {},
            || {},
            store.path(),
        );

        race.assert_ran();
        assert!(real_root.join("agent/auth.json").is_file());
        assert!(data.join("settings.json").is_file());
        assert!(
            !data.join("agent/auth.json").exists(),
            "a symlinked-home fork-root spelling copied the credential"
        );
        assert!(!data.join("agent/models.json").exists());
    }

    /// N1a through the same M13 window: `$HOME` reached through one alias, the
    /// `--mount` spelled through a second. Before the copier canonicalized the
    /// root, the static half compared the literal spelling and missed it.
    #[test]
    fn fork_omits_through_a_second_home_alias_spelling() {
        use std::os::unix::fs::symlink;
        let _guard = COPY_CHECKPOINT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        let home = base.join("home");
        fs::create_dir(&home).unwrap();
        let alias1 = base.join("alias1");
        let alias2 = base.join("alias2");
        symlink(&home, &alias1).unwrap();
        symlink(&home, &alias2).unwrap();
        let real_root = home.join(".pi");
        fs::create_dir_all(real_root.join("agent")).unwrap();
        fs::write(real_root.join("settings.json"), "{}").unwrap();
        let race = hide_the_pi_directory_across_the_copy_point(
            &real_root,
            &real_root,
            &home.join("stashed-pi"),
        );
        let store = tempfile::tempdir().unwrap();
        let data = fork_data_with_one_resolution_point(
            &alias1,
            &alias2.join(".pi"),
            || {},
            || {},
            store.path(),
        );

        race.assert_ran();
        assert!(real_root.join("agent/auth.json").is_file());
        assert!(data.join("settings.json").is_file());
        assert!(
            !data.join("agent/auth.json").exists(),
            "a second home alias spelling copied the credential"
        );
        assert!(!data.join("agent/models.json").exists());
    }

    /// N1b through the same M13 window: `--mount ~/pi-link:fork` where
    /// `~/pi-link -> ~/.pi`. The link spelling is disjoint from the configured
    /// Pi home, so only resolving the root at its own point names the
    /// credential.
    #[test]
    fn fork_omits_through_a_link_to_the_pi_home() {
        use std::os::unix::fs::symlink;
        let _guard = COPY_CHECKPOINT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let home = tempfile::tempdir().unwrap();
        let home = home.path().canonicalize().unwrap();
        let pi_home = home.join(".pi");
        fs::create_dir_all(pi_home.join("agent")).unwrap();
        fs::write(pi_home.join("settings.json"), "{}").unwrap();
        let link = home.join("pi-link");
        symlink(&pi_home, &link).unwrap();
        let race = hide_the_pi_directory_across_the_copy_point(
            &pi_home,
            &pi_home,
            &home.join("stashed-pi"),
        );
        let store = tempfile::tempdir().unwrap();
        let data = fork_data_with_one_resolution_point(&home, &link, || {}, || {}, store.path());

        race.assert_ran();
        assert!(pi_home.join("agent/auth.json").is_file());
        assert!(data.join("settings.json").is_file());
        assert!(
            !data.join("agent/auth.json").exists(),
            "a link to the Pi home copied the credential"
        );
        assert!(!data.join("agent/models.json").exists());
    }

    /// F1 #2 with the corrected chronology: the launch measures with no `~/.pi`;
    /// `after_launch_measurement` creates the link; the credential is created
    /// before the copy point, which measures the recreated target.
    #[test]
    fn fork_omits_a_symlinked_pi_home_recreated_after_the_launch_measurement() {
        use std::os::unix::fs::symlink;
        let home = tempfile::tempdir().unwrap();
        let home = home.path().canonicalize().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let elsewhere = elsewhere.path().canonicalize().unwrap();
        let root = home.join(".pi");
        let store = tempfile::tempdir().unwrap();
        let data = fork_data_with_one_resolution_point(
            &home,
            &root,
            || symlink(&elsewhere, &root).unwrap(),
            || {
                fs::create_dir_all(elsewhere.join("agent")).unwrap();
                fs::write(elsewhere.join("agent/auth.json"), "synthetic-secret").unwrap();
                fs::write(elsewhere.join("agent/models.json"), "synthetic-models").unwrap();
            },
            store.path(),
        );
        assert!(!data.join("agent/auth.json").exists());
        assert!(!data.join("agent/models.json").exists());
    }

    /// reviewer5's probe, as an omission: the launch measures with no `~/.pi`;
    /// `after_launch_measurement` creates `~/.pi -> /ext`; the copy checkpoint
    /// removes the link, restores it, and writes the credentials (which did not
    /// exist at T2/T3). The route measured at T2 already named `/ext`, so both
    /// files are omitted and an ordinary sibling is copied (RULING 3).
    #[test]
    fn fork_omits_when_the_pi_home_link_is_removed_after_the_measurement() {
        use std::os::unix::fs::symlink;
        let _guard = COPY_CHECKPOINT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let home = tempfile::tempdir().unwrap();
        let home = home.path().canonicalize().unwrap();
        let ext = tempfile::tempdir().unwrap();
        let ext = ext.path().canonicalize().unwrap();
        let root = home.join(".pi");
        let store = tempfile::tempdir().unwrap();

        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let target = ext.clone();
        let root_for_callback = root.clone();
        let ran_flag = std::sync::Arc::clone(&ran);
        let _copy_guard = CopyCheckpointGuard::arm(
            &ext,
            Box::new(move |path| {
                if path == target && !ran_flag.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    // The credentials must not exist yet, or T2/T3 could have
                    // named them by identity instead of by the resolved route.
                    assert!(!target.join("agent/auth.json").exists());
                    fs::remove_file(&root_for_callback).unwrap();
                    symlink(&target, &root_for_callback).unwrap();
                    fs::create_dir_all(target.join("agent")).unwrap();
                    fs::write(target.join("agent/auth.json"), "synthetic-secret").unwrap();
                    fs::write(target.join("agent/models.json"), "synthetic-models").unwrap();
                    fs::write(target.join("notes.txt"), "ordinary").unwrap();
                }
            }),
        );
        let data = fork_data_with_one_resolution_point(
            &home,
            &root,
            || symlink(&ext, &root).unwrap(),
            || {},
            store.path(),
        );
        assert!(
            ran.load(std::sync::atomic::Ordering::SeqCst),
            "the copy hook did not run"
        );
        assert!(ext.join("agent/auth.json").is_file());
        assert!(
            data.join("notes.txt").is_file(),
            "the ordinary file must be copied"
        );
        assert!(!data.join("agent/auth.json").exists());
        assert!(!data.join("agent/models.json").exists());
    }

    /// A nested `:fork` of a subdirectory of the Pi home under the same race:
    /// the static table must strip down to the bare filenames.
    #[test]
    fn fork_of_a_nested_pi_home_subdirectory_still_omits() {
        let home = tempfile::tempdir().unwrap();
        let home = home.path().canonicalize().unwrap();
        let root = home.join(".pi/agent");
        fs::create_dir_all(&root).unwrap();
        let store = tempfile::tempdir().unwrap();
        let data = fork_data_with_one_resolution_point(
            &home,
            &root,
            || {},
            || {
                fs::write(root.join("auth.json"), "synthetic-secret").unwrap();
                fs::write(root.join("models.json"), "synthetic-models").unwrap();
            },
            store.path(),
        );
        assert!(!data.join("auth.json").exists());
        assert!(!data.join("models.json").exists());
    }

    // ── Signal-isolating tests (§7.7.3) ───────────────────────────────

    /// S1: both halves of the identity union. `backup-*.json` are hardlinks to
    /// the **launch** inodes; `replacement-*.json` are hardlinks to the
    /// **copy-point** inodes. Dropping either half of `union` copies one pair.
    #[test]
    fn fork_omission_unions_preflight_and_copy_point_identities() {
        use std::os::unix::fs::MetadataExt;

        let (_home, home) = pi_home();
        let source = home.join("unrelated-fork");
        fs::create_dir(&source).unwrap();
        fs::hard_link(
            home.join(".pi/agent/auth.json"),
            source.join("backup-auth.json"),
        )
        .unwrap();
        fs::hard_link(
            home.join(".pi/agent/models.json"),
            source.join("backup-models.json"),
        )
        .unwrap();
        let launch = ProtectedHostFiles::measure(Some(&home)).unwrap();
        let old_auth = fs::metadata(source.join("backup-auth.json")).unwrap();
        let old_models = fs::metadata(source.join("backup-models.json")).unwrap();
        assert!(
            launch
                .identities()
                .matched(old_auth.dev(), old_auth.ino())
                .is_some(),
            "the launch snapshot must know the old credential inodes"
        );
        assert!(
            launch
                .identities()
                .matched(old_models.dev(), old_models.ino())
                .is_some()
        );

        // Atomically replace both credential files.
        for (path, body) in [
            (home.join(".pi/agent/auth.json"), "replacement-auth"),
            (home.join(".pi/agent/models.json"), "replacement-models"),
        ] {
            let replacement = path.with_extension("replacement");
            fs::write(&replacement, body).unwrap();
            fs::rename(&replacement, &path).unwrap();
        }
        // After the replacement, hardlink the *new* inodes into the same fork.
        fs::hard_link(
            home.join(".pi/agent/auth.json"),
            source.join("replacement-auth.json"),
        )
        .unwrap();
        fs::hard_link(
            home.join(".pi/agent/models.json"),
            source.join("replacement-models.json"),
        )
        .unwrap();
        fs::write(source.join("ordinary.txt"), "keep").unwrap();

        // The launch snapshot must not know the replacement inodes; otherwise
        // dropping `other`'s identities could be rescued by the launch half.
        let new_auth = fs::metadata(source.join("replacement-auth.json")).unwrap();
        let new_models = fs::metadata(source.join("replacement-models.json")).unwrap();
        assert!(
            launch
                .identities()
                .matched(new_auth.dev(), new_auth.ino())
                .is_none(),
            "the launch snapshot must not know the replacement inodes"
        );
        assert!(
            launch
                .identities()
                .matched(new_models.dev(), new_models.ino())
                .is_none()
        );

        // Precondition: the fresh measurement does not know the old inodes, and
        // no Pi pathname names anything under `unrelated-fork`.
        let fresh = ProtectedHostFiles::measure(Some(&home)).unwrap();
        assert!(
            fresh
                .identities()
                .matched(old_auth.dev(), old_auth.ino())
                .is_none(),
            "the fresh snapshot must have forgotten the old inode"
        );
        assert!(
            launch
                .union(&fresh)
                .relatives_under(&ResolvedRoot::resolve(&source, Declaration::Argv).unwrap())
                .is_empty(),
            "no Pi path names anything under an unrelated fork root"
        );

        let store = tempfile::tempdir().unwrap();
        let mut mounts = parse_extra_mounts(&[format!("{}:/fork:fork", source.display())]).unwrap();
        prepare_forks(
            &mut mounts,
            store.path(),
            &std::collections::HashMap::new(),
            &launch,
            &DeclaredOrigins::new(),
        )
        .unwrap();
        let data = &mounts[0].host;
        assert!(data.join("ordinary.txt").is_file());
        for name in [
            "backup-auth.json",
            "backup-models.json",
            "replacement-auth.json",
            "replacement-models.json",
        ] {
            assert!(!data.join(name).exists(), "{name} survived the copy");
        }
    }

    /// S4: fresh-wins on the **configured** `pi_home`. The `$HOME` link is
    /// re-pointed between the launch and the copy, so first-wins would name the
    /// old home and copy the credential.
    #[test]
    fn fork_of_a_repointed_home_link_uses_the_fresh_configured_pi_home() {
        use std::os::unix::fs::symlink;
        let _guard = COPY_CHECKPOINT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        let home_a = base.join("homeA");
        let home_b = base.join("homeB");
        fs::create_dir(&home_a).unwrap();
        fs::create_dir(&home_b).unwrap();
        let ext = tempfile::tempdir().unwrap();
        let ext = ext.path().canonicalize().unwrap();
        fs::create_dir(ext.join("pi")).unwrap();
        symlink(ext.join("pi"), home_b.join(".pi")).unwrap();
        let home_link = base.join("home-link");
        symlink(&home_a, &home_link).unwrap();

        let launch = ProtectedHostFiles::measure(Some(&home_link)).unwrap();
        // Re-point `$HOME` at `homeB` between the launch and the copy.
        fs::remove_file(&home_link).unwrap();
        symlink(&home_b, &home_link).unwrap();

        let pi = ext.join("pi");
        let target = pi.clone();
        set_copy_checkpoint(
            &home_b,
            Box::new(move |path| {
                if path == Path::new(".pi") {
                    fs::create_dir_all(target.join("agent")).unwrap();
                    fs::write(target.join("agent/auth.json"), "synthetic-secret").unwrap();
                    fs::write(target.join("agent/models.json"), "synthetic-models").unwrap();
                    fs::write(target.join("notes.txt"), "ordinary").unwrap();
                }
            }),
        );
        let mut mounts =
            parse_extra_mounts(&[format!("{}:/guest:fork:follow-links", home_link.display())])
                .unwrap();
        let store = tempfile::tempdir().unwrap();
        let result = prepare_forks(
            &mut mounts,
            store.path(),
            &std::collections::HashMap::new(),
            &launch,
            &DeclaredOrigins::new(),
        );
        clear_copy_checkpoint();

        result.unwrap_or_else(|error| panic!("unexpected Pi-home refusal: {error:?}"));
        let data = &mounts[0].host;
        assert!(data.join(".pi/notes.txt").is_file());
        assert!(
            !data.join(".pi/agent/auth.json").exists(),
            "first-wins on pi_home copied the credential"
        );
        assert!(!data.join(".pi/agent/models.json").exists());
    }

    /// S5: the copy-point measured routes. The credential is a symlinked target
    /// that exists only from the copy point, reached through the fresh route
    /// `(/ext, "secrets/auth.json")`; the launch knew nothing of `/ext`.
    #[test]
    fn fork_omits_a_symlinked_credential_target_named_only_by_the_fresh_routes() {
        use std::os::unix::fs::symlink;
        let _guard = COPY_CHECKPOINT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let (_home, home) = home_dir_with_pi_home_minus_credential();
        let ext = tempfile::tempdir().unwrap();
        let ext = ext.path().canonicalize().unwrap();
        fs::create_dir_all(ext.join("secrets")).unwrap();
        fs::write(ext.join("secrets/auth.json"), "old").unwrap();
        fs::write(ext.join("secrets/notes.txt"), "ordinary").unwrap();
        let launch = ProtectedHostFiles::measure(Some(&home)).unwrap();
        // The credential alias appears only after the launch measurement.
        symlink(
            ext.join("secrets/auth.json"),
            home.join(".pi/agent/auth.json"),
        )
        .unwrap();

        let outside = tempfile::tempdir().unwrap();
        let auth = ext.join("secrets/auth.json");
        let auth_cb = auth.clone();
        let outside_path = outside.path().join("old-auth.json");
        set_copy_checkpoint(
            &ext,
            Box::new(move |path| {
                if path == Path::new("secrets/auth.json") {
                    // Replace the inode the copy-point identity saw; keep the
                    // old bytes reachable outside `/ext`.
                    fs::hard_link(&auth_cb, &outside_path).unwrap();
                    let replacement = auth_cb.with_extension("replacement");
                    fs::write(&replacement, "replacement").unwrap();
                    fs::rename(&replacement, &auth_cb).unwrap();
                }
            }),
        );
        let mut mounts = parse_extra_mounts(&[format!("{}:/guest:fork", ext.display())]).unwrap();
        let store = tempfile::tempdir().unwrap();
        let result = prepare_forks(
            &mut mounts,
            store.path(),
            &std::collections::HashMap::new(),
            &launch,
            &DeclaredOrigins::new(),
        );
        clear_copy_checkpoint();

        result.unwrap_or_else(|error| panic!("unexpected Pi-home refusal: {error:?}"));
        let data = &mounts[0].host;
        assert!(
            data.join("secrets/notes.txt").is_file(),
            "the ordinary sibling must be copied"
        );
        assert!(
            !data.join("secrets/auth.json").exists(),
            "a fresh route must omit the credential"
        );
    }

    /// S3-A: the **resolved** `pi_home` static entry. The root is
    /// `~/.pi/agent`, so at the copy point the resolved spelling `/ext/pi` must
    /// name `agent/auth.json` while the configured `$HOME/.pi` spelling does
    /// not strip under it.
    #[test]
    fn fork_of_a_pi_home_subdirectory_omits_through_the_resolved_spelling() {
        use std::os::unix::fs::symlink;
        let _guard = COPY_CHECKPOINT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        let home = base.join("home");
        fs::create_dir(&home).unwrap();
        let ext = tempfile::tempdir().unwrap();
        let ext = ext.path().canonicalize().unwrap();
        fs::create_dir_all(ext.join("pi/agent")).unwrap();
        symlink(ext.join("pi"), home.join(".pi")).unwrap();
        let root = home.join(".pi/agent");
        let stashed = ext.join("pi/stashed-agent");
        let agent = ext.join("pi/agent");

        let stashed_cb = stashed.clone();
        let root_cb = root.clone();
        set_resolve_checkpoint(
            &root,
            Box::new(move |_| fs::rename(&root_cb, &stashed_cb).unwrap()),
        );
        let agent_cb = agent.clone();
        let stashed_restore = stashed.clone();
        set_copy_checkpoint(
            &root,
            Box::new(move |path| {
                if path == agent_cb {
                    fs::rename(&stashed_restore, &agent_cb).unwrap();
                    fs::write(agent_cb.join("auth.json"), "synthetic-secret").unwrap();
                    fs::write(agent_cb.join("notes.txt"), "ordinary").unwrap();
                }
            }),
        );
        let mut mounts = parse_extra_mounts(&[format!("{}:/guest:fork", root.display())]).unwrap();
        let store = tempfile::tempdir().unwrap();
        let result = prepare_forks(
            &mut mounts,
            store.path(),
            &std::collections::HashMap::new(),
            &ProtectedHostFiles::measure(Some(&home)).unwrap(),
            &DeclaredOrigins::new(),
        );
        clear_resolve_checkpoint();
        clear_copy_checkpoint();

        result.unwrap_or_else(|error| panic!("unexpected Pi-home refusal: {error:?}"));
        let data = &mounts[0].host;
        assert_eq!(
            fs::read_to_string(data.join("notes.txt")).unwrap(),
            "ordinary"
        );
        assert!(
            !data.join("auth.json").exists(),
            "resolved_pi_home must name the credential under a Pi-home subdirectory"
        );
    }

    /// S3-B: fresh-wins on the **resolved** `pi_home`. Same shape as S3-A, but
    /// `~/.pi` is re-pointed to `piB` before the copy point, so first-wins would
    /// name `piA` and copy the credential. Asserts an explicit successful result
    /// first, so a reintroduced fail-closed check dies on a named assertion.
    #[test]
    fn fork_of_a_repointed_pi_home_subdirectory_uses_the_fresh_resolution() {
        use std::os::unix::fs::symlink;
        let _guard = COPY_CHECKPOINT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        let home = base.join("home");
        fs::create_dir(&home).unwrap();
        let ext = tempfile::tempdir().unwrap();
        let ext = ext.path().canonicalize().unwrap();
        fs::create_dir_all(ext.join("piA/agent")).unwrap();
        fs::create_dir_all(ext.join("piB/agent")).unwrap();
        symlink(ext.join("piA"), home.join(".pi")).unwrap();

        let launch = ProtectedHostFiles::measure(Some(&home)).unwrap();
        // Re-point `~/.pi` to `piB` before the copy point.
        fs::remove_file(home.join(".pi")).unwrap();
        symlink(ext.join("piB"), home.join(".pi")).unwrap();

        let root = home.join(".pi/agent");
        let stashed = ext.join("piB/stashed-agent");
        let agent = ext.join("piB/agent");
        let stashed_cb = stashed.clone();
        let root_cb = root.clone();
        set_resolve_checkpoint(
            &root,
            Box::new(move |_| fs::rename(&root_cb, &stashed_cb).unwrap()),
        );
        let agent_cb = agent.clone();
        let stashed_restore = stashed.clone();
        set_copy_checkpoint(
            &root,
            Box::new(move |path| {
                if path == agent_cb {
                    fs::rename(&stashed_restore, &agent_cb).unwrap();
                    fs::write(agent_cb.join("auth.json"), "synthetic-secret").unwrap();
                    fs::write(agent_cb.join("notes.txt"), "ordinary").unwrap();
                }
            }),
        );
        let mut mounts = parse_extra_mounts(&[format!("{}:/guest:fork", root.display())]).unwrap();
        let store = tempfile::tempdir().unwrap();
        let result = prepare_forks(
            &mut mounts,
            store.path(),
            &std::collections::HashMap::new(),
            &launch,
            &DeclaredOrigins::new(),
        );
        clear_resolve_checkpoint();
        clear_copy_checkpoint();

        result.unwrap_or_else(|error| panic!("unexpected Pi-home refusal: {error:?}"));
        let data = &mounts[0].host;
        assert_eq!(
            fs::read_to_string(data.join("notes.txt")).unwrap(),
            "ordinary"
        );
        assert!(
            !data.join("auth.json").exists(),
            "first-wins on resolved_pi_home copied the credential"
        );

        // No competing static entry covers the fixture: the configured
        // `$HOME/.pi` spelling cannot name a file under the canonical root, so
        // only the fresh `resolved_pi_home` can answer. (The competing measured
        // route is suppressed by the resolve-hook rename and the credential is
        // created later, so no identity names it either.)
        let canonical_root = root.canonicalize().unwrap();
        assert_eq!(canonical_root, agent);
        assert!(
            home.join(".pi/agent/auth.json")
                .strip_prefix(&canonical_root)
                .is_err(),
            "the configured pi_home spelling must not cover the fixture"
        );
        assert!(
            ext.join("piB/agent/auth.json")
                .strip_prefix(&canonical_root)
                .is_ok(),
            "the fresh resolved_pi_home must name the credential"
        );
    }

    /// S2 (integration): the **configured** `pi_home` static entry and the
    /// `follow-links` materialization. `~/.pi -> /ext/pi`; the credential is
    /// created by the copy checkpoint, so no identity names it and no measured
    /// route is under `$HOME`.
    #[test]
    fn fork_follow_links_of_home_omits_a_credential_created_after_the_measurement() {
        use std::os::unix::fs::symlink;
        let _guard = COPY_CHECKPOINT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let home = tempfile::tempdir().unwrap();
        let home = home.path().canonicalize().unwrap();
        let ext = tempfile::tempdir().unwrap();
        let ext = ext.path().canonicalize().unwrap();
        fs::create_dir(ext.join("pi")).unwrap();
        symlink(ext.join("pi"), home.join(".pi")).unwrap();
        let store = tempfile::tempdir().unwrap();

        let pi = ext.join("pi");
        let target = pi.clone();
        set_copy_checkpoint(
            &home,
            Box::new(move |path| {
                if path == Path::new(".pi") {
                    fs::create_dir_all(target.join("agent")).unwrap();
                    fs::write(target.join("agent/auth.json"), "synthetic-secret").unwrap();
                    fs::write(target.join("agent/models.json"), "synthetic-models").unwrap();
                    fs::write(target.join("notes.txt"), "ordinary").unwrap();
                }
            }),
        );
        let result = prepare(
            parse_extra_mounts(&[format!("{}:/guest:fork:follow-links", home.display())]).unwrap(),
            &context_with_home(store.path(), home.clone()),
        );
        clear_copy_checkpoint();

        let plan = result.unwrap_or_else(|error| panic!("unexpected Pi-home refusal: {error:?}"));
        let data = fork_data(&plan);
        assert!(data.join(".pi/notes.txt").is_file());
        assert!(
            !data.join(".pi/agent/auth.json").exists(),
            "the configured pi_home must name the followed credential"
        );
        assert!(!data.join(".pi/agent/models.json").exists());
    }

    /// Drop-ruling control: a new, unrelated inode at a former credential
    /// pathname is **copied** — historical routes are deliberately not retained
    /// (R3.5, §6.8 item 5).
    #[test]
    fn a_new_unrelated_inode_at_a_former_credential_path_is_copied() {
        use std::os::unix::fs::symlink;
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        let home = base.join("home");
        fs::create_dir(&home).unwrap();
        let ext = tempfile::tempdir().unwrap();
        let ext = ext.path().canonicalize().unwrap();
        fs::create_dir_all(ext.join("piA/agent")).unwrap();
        fs::create_dir_all(ext.join("piB/agent")).unwrap();
        fs::write(ext.join("piA/agent/auth.json"), "old-credential").unwrap();
        symlink(ext.join("piA"), home.join(".pi")).unwrap();

        let launch = ProtectedHostFiles::measure(Some(&home)).unwrap();
        // Keep the old inode alive outside `/ext`, then replace it with an
        // ordinary new inode at the same pathname.
        let outside = tempfile::tempdir().unwrap();
        fs::hard_link(
            ext.join("piA/agent/auth.json"),
            outside.path().join("old-auth.json"),
        )
        .unwrap();
        fs::remove_file(ext.join("piA/agent/auth.json")).unwrap();
        fs::write(ext.join("piA/agent/auth.json"), "ordinary-new").unwrap();
        // Re-point `~/.pi` at `piB` and give it a credential.
        fs::remove_file(home.join(".pi")).unwrap();
        symlink(ext.join("piB"), home.join(".pi")).unwrap();
        fs::write(ext.join("piB/agent/auth.json"), "fresh-credential").unwrap();

        let mut mounts = parse_extra_mounts(&[format!("{}:/guest:fork", ext.display())]).unwrap();
        let store = tempfile::tempdir().unwrap();
        prepare_forks(
            &mut mounts,
            store.path(),
            &std::collections::HashMap::new(),
            &launch,
            &DeclaredOrigins::new(),
        )
        .unwrap();
        let data = &mounts[0].host;
        assert!(
            !data.join("piB/agent/auth.json").exists(),
            "fresh routes must omit the current credential"
        );
        assert_eq!(
            fs::read_to_string(data.join("piA/agent/auth.json")).unwrap(),
            "ordinary-new",
            "a new unrelated inode at a former credential path must be copied"
        );
    }

    /// Control: a nested `:fork` of `~/.pi/extensions` keeps its own harmless
    /// `agent/auth.json` even while `~/.pi` is removed across the copy point.
    /// No relevance decision is made, so nothing is refused or over-omitted
    /// (R4.1, medium 1). The shared test lock and the post-hoc assertion keep
    /// the arm/copy/clear lifetime exclusive and prove the race executed.
    #[test]
    fn a_nested_extensions_fork_survives_a_concurrent_pi_home_change() {
        use std::os::unix::fs::symlink;
        let _lock = COPY_CHECKPOINT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        let home = base.join("home");
        fs::create_dir(&home).unwrap();
        let ext = tempfile::tempdir().unwrap();
        let ext = ext.path().canonicalize().unwrap();
        let extensions = ext.join("pi/extensions");
        fs::create_dir_all(extensions.join("agent")).unwrap();
        fs::write(extensions.join("agent/auth.json"), "extension-own-config").unwrap();
        fs::write(extensions.join("plugin.js"), "x").unwrap();
        symlink(ext.join("pi"), home.join(".pi")).unwrap();

        let root = home.join(".pi/extensions");
        let home_cb = home.clone();
        let _resolve = ResolveCheckpointGuard::arm(
            &root,
            Box::new(move |_| fs::remove_file(home_cb.join(".pi")).unwrap()),
        );
        let mut mounts = parse_extra_mounts(&[format!("{}:/guest:fork", root.display())]).unwrap();
        let store = tempfile::tempdir().unwrap();
        let result = prepare_forks(
            &mut mounts,
            store.path(),
            &std::collections::HashMap::new(),
            &ProtectedHostFiles::measure(Some(&home)).unwrap(),
            &DeclaredOrigins::new(),
        );

        result.unwrap_or_else(|error| panic!("unexpected Pi-home refusal: {error:?}"));
        assert!(
            !home.join(".pi").exists(),
            "the nested concurrent-change hook did not run"
        );
        let data = &mounts[0].host;
        assert_eq!(
            fs::read_to_string(data.join("agent/auth.json")).unwrap(),
            "extension-own-config",
            "a nested extension's own agent/auth.json must be copied"
        );
        assert!(data.join("plugin.js").is_file());
    }

    /// Control: an entirely unrelated fork is not refused and copies normally
    /// while `~/.pi` is re-pointed at a **different** target across the copy
    /// point. Kills an unconditional fail-closed check at the resolve point and
    /// a change-triggered, root-unconditional refusal (M2).
    #[test]
    fn an_unrelated_fork_survives_a_concurrent_pi_home_change() {
        use std::os::unix::fs::symlink;
        let _lock = COPY_CHECKPOINT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        let home = base.join("home");
        fs::create_dir(&home).unwrap();
        let ext = tempfile::tempdir().unwrap();
        let ext = ext.path().canonicalize().unwrap();
        let pi_a = ext.join("piA");
        let pi_b = ext.join("piB");
        fs::create_dir_all(pi_a.join("agent")).unwrap();
        fs::create_dir_all(pi_b.join("agent")).unwrap();
        fs::write(pi_a.join("agent/auth.json"), "credential-a").unwrap();
        fs::write(pi_b.join("agent/auth.json"), "credential-b").unwrap();
        symlink(&pi_a, home.join(".pi")).unwrap();
        let unrelated = tempfile::tempdir().unwrap();
        let unrelated = unrelated.path().canonicalize().unwrap();
        fs::write(unrelated.join("notes.txt"), "ordinary").unwrap();

        let home_cb = home.clone();
        let pi_b_cb = pi_b.clone();
        let _resolve = ResolveCheckpointGuard::arm(
            &unrelated,
            Box::new(move |_| {
                // A genuinely different association, unlike removing and
                // recreating the same target.
                fs::remove_file(home_cb.join(".pi")).unwrap();
                symlink(&pi_b_cb, home_cb.join(".pi")).unwrap();
            }),
        );
        let mut mounts =
            parse_extra_mounts(&[format!("{}:/guest:fork", unrelated.display())]).unwrap();
        let store = tempfile::tempdir().unwrap();
        let result = prepare_forks(
            &mut mounts,
            store.path(),
            &std::collections::HashMap::new(),
            &ProtectedHostFiles::measure(Some(&home)).unwrap(),
            &DeclaredOrigins::new(),
        );

        result.unwrap_or_else(|error| panic!("unexpected Pi-home refusal: {error:?}"));
        assert_eq!(
            fs::read_link(home.join(".pi")).unwrap(),
            pi_b,
            "the unrelated concurrent-change hook did not re-point the Pi home"
        );
        let data = &mounts[0].host;
        assert_eq!(
            fs::read_to_string(data.join("notes.txt")).unwrap(),
            "ordinary"
        );
    }

    /// S6′ (integration): a root spelled through the macOS data-volume firmlink
    /// canonicalizes to a **different** string than the measured route while
    /// sharing `(dev, ino)`, so only the identity arm names the credential.
    /// Skipped where the firmlink does not exist or does not fold (a platform
    /// fact, not a code property).
    #[cfg(target_os = "macos")]
    #[test]
    fn fork_through_a_firmlink_spelling_omits_a_credential_created_after_the_measurement() {
        use std::os::unix::fs::symlink;
        let firmlink_root = Path::new("/System/Volumes/Data");
        if !firmlink_root.exists() {
            return;
        }
        let _guard = COPY_CHECKPOINT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let home = tempfile::tempdir().unwrap();
        let home = home.path().canonicalize().unwrap();
        let pi = tempfile::tempdir().unwrap();
        let pi = pi.path().canonicalize().unwrap();
        let launch = ProtectedHostFiles::measure(Some(&home)).unwrap();
        // `~/.pi -> P` appears after the launch measurement.
        symlink(&pi, home.join(".pi")).unwrap();

        let alias = firmlink_root.join(pi.strip_prefix("/").unwrap());
        let alias_canonical = alias.canonicalize().unwrap();
        let canonical = pi.canonicalize().unwrap();
        if alias_canonical == canonical {
            return; // the firmlink is not folding on this host
        }
        use std::os::unix::fs::MetadataExt;
        if fs::metadata(&alias).unwrap().ino() != fs::metadata(&canonical).unwrap().ino() {
            return;
        }

        let pi_cb = pi.clone();
        let home_cb = home.clone();
        let alias_scope = alias_canonical.clone();
        let alias_scope_cb = alias_canonical.clone();
        set_copy_checkpoint(
            &alias_scope,
            Box::new(move |path| {
                if path == alias_scope_cb {
                    fs::remove_file(home_cb.join(".pi")).unwrap();
                    symlink(&pi_cb, home_cb.join(".pi")).unwrap();
                    fs::create_dir_all(pi_cb.join("agent")).unwrap();
                    fs::write(pi_cb.join("agent/auth.json"), "synthetic-secret").unwrap();
                    fs::write(pi_cb.join("agent/models.json"), "synthetic-models").unwrap();
                    fs::write(pi_cb.join("notes.txt"), "ordinary").unwrap();
                }
            }),
        );
        let mut mounts = parse_extra_mounts(&[format!("{}:/guest:fork", alias.display())]).unwrap();
        let store = tempfile::tempdir().unwrap();
        let result = prepare_forks(
            &mut mounts,
            store.path(),
            &std::collections::HashMap::new(),
            &launch,
            &DeclaredOrigins::new(),
        );
        clear_copy_checkpoint();

        result.unwrap_or_else(|error| panic!("unexpected Pi-home refusal: {error:?}"));
        let data = &mounts[0].host;
        assert!(pi.join("agent/auth.json").is_file());
        assert!(data.join("notes.txt").is_file());
        assert!(
            !data.join("agent/auth.json").exists(),
            "the identity fold must omit the credential under a firmlink spelling"
        );
        assert!(!data.join("agent/models.json").exists());
        // No competing static entry covers the fixture: neither the configured
        // `$HOME/.pi` spelling nor the resolved `P` names a file under the
        // disjoint aliased root, so the identity fold is the only answer.
        assert!(
            home.join(".pi/agent/auth.json")
                .strip_prefix(&alias_canonical)
                .is_err(),
            "the configured pi_home spelling must not cover the aliased root"
        );
        assert!(
            pi.join("agent/auth.json")
                .strip_prefix(&alias_canonical)
                .is_err(),
            "the resolved pi_home spelling must not cover the aliased root"
        );
    }

    /// A `$HOME` with a real `~/.pi` whose `agent/auth.json` is absent — the
    /// launch fixture for S5's "alias appears later".
    fn home_dir_with_pi_home_minus_credential() -> (tempfile::TempDir, PathBuf) {
        let home = tempfile::tempdir().unwrap();
        let canonical = home.path().canonicalize().unwrap();
        fs::create_dir_all(canonical.join(".pi/agent")).unwrap();
        (home, canonical)
    }

    /// Anti-over-omission control: an unrelated fork root that happens to
    /// contain its own `agent/auth.json` keeps it. The extra root/Pi-home
    /// spellings must not turn every root containing that name into a hit.
    #[test]
    fn fork_of_an_unrelated_root_keeps_its_own_agent_auth_json() {
        let (_home, home) = pi_home();
        let source = tempfile::tempdir().unwrap();
        let source = source.path().canonicalize().unwrap();
        fs::create_dir_all(source.join("agent")).unwrap();
        fs::write(source.join("agent/auth.json"), "not-pi").unwrap();
        let store = tempfile::tempdir().unwrap();
        let plan = prepare(
            parse_extra_mounts(&[format!("{}:/guest:fork", source.display())]).unwrap(),
            &context_with_home(store.path(), home.clone()),
        )
        .unwrap();
        let data = fork_data(&plan);
        assert!(
            data.join("agent/auth.json").is_file(),
            "an unrelated root's own agent/auth.json must survive"
        );
    }

    /// The omission is derived from the host root, not the guest path, so a
    /// remapped guest spelling changes nothing.
    #[test]
    fn remapped_guest_path_does_not_change_fork_omission() {
        let (_home, home) = pi_home();
        let store = tempfile::tempdir().unwrap();
        let plan = prepare(
            parse_extra_mounts(&[format!(
                "{}:/somewhere/else:fork",
                home.join(".pi").display()
            )])
            .unwrap(),
            &context_with_home(store.path(), home.clone()),
        )
        .unwrap();
        let data = fork_data(&plan);
        assert!(data.join("settings.json").is_file());
        assert!(!data.join("agent/auth.json").exists());
        assert!(!data.join("agent/models.json").exists());
    }

    #[test]
    fn identity_version_v3_reseeds_a_v2_fork_and_reports_the_orphan() {
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("seed"), "seed").unwrap();
        let store = tempfile::tempdir().unwrap();
        let request =
            parse_extra_mounts(&[format!("{}:/guest:fork", source.path().display())]).unwrap();
        let legacy = store
            .path()
            .join("forks")
            .join(fork_id(&request[0], LEGACY_IDENTITY_VERSION_V2));
        fs::create_dir_all(legacy.join("data")).unwrap();
        fs::write(legacy.join("data/agent-auth.json"), "old credential copy").unwrap();

        let plan = prepare(request, &context(store.path())).unwrap();
        let data = fork_data(&plan);

        assert_ne!(data, legacy.join("data"), "a v2 fork must not be reused");
        assert_eq!(fs::read_to_string(data.join("seed")).unwrap(), "seed");
        assert!(
            legacy.join("data/agent-auth.json").is_file(),
            "the orphan is reported, never deleted"
        );
        let notices = plan.notices.join("\n");
        assert!(
            notices.contains("A fork from an earlier agent-vm build is no longer used"),
            "{notices}"
        );
        assert!(notices.contains(&legacy.display().to_string()), "{notices}");
    }

    #[test]
    fn no_home_refuses_a_declared_mount_but_not_an_empty_plan() {
        let source = tempfile::tempdir().unwrap();
        let store = tempfile::tempdir().unwrap();
        let ctx = context_without_home(store.path());
        assert!(prepare(Vec::new(), &ctx).is_ok());

        let error = prepare(
            parse_extra_mounts(&[format!("{}:ro", source.path().display())]).unwrap(),
            &ctx,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("neither $HOME nor the account record"),
            "{error}"
        );
        assert!(store_tree(store.path()).is_empty(), "{error}");
    }
}

#[cfg(test)]
mod config_dir_guard_tests {
    use super::*;
    use std::os::unix::fs::symlink;

    struct Fixture {
        _root: tempfile::TempDir,
        home: PathBuf,
        project: PathBuf,
        store: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let base = root.path().canonicalize().unwrap();
            let home = base.join("home");
            let project = base.join("project");
            let store = base.join("store");
            for path in [&home, &project, &store] {
                fs::create_dir(path).unwrap();
            }
            Self {
                _root: root,
                home,
                project,
                store,
            }
        }
        fn context(&self, sources: Vec<CoreHostSource>) -> MountContext {
            MountContext {
                mount_store: self.store.clone(),
                host_home: Some(self.home.clone()),
                authority_home: Some(self.home.clone()),
                account_home: None,
                core_guest_mounts: vec![],
                core_host_sources: sources,
                persisted_home: crate::guest_home::PersistedHome::none(),
            }
        }
        fn refused(&self, requests: Vec<ExtraMount>, context: &MountContext, text: &str) {
            let e = prepare(requests, context).unwrap_err();
            assert!(e.to_string().contains(text), "{e:#}");
            assert!(fs::read_dir(&self.store).unwrap().next().is_none());
        }
    }
    #[test]
    fn config_guard_core_sources_and_precedence() {
        let f = Fixture::new();
        fs::create_dir(f.home.join(".config")).unwrap();
        for path in [&f.home, &f.home.join(".config")] {
            f.refused(
                vec![],
                &f.context(vec![CoreHostSource::new(
                    CoreBind::ProjectDir,
                    path.clone(),
                )]),
                "launch authority",
            );
        }
        let project = f.home.join("code/p");
        fs::create_dir_all(&project).unwrap();
        assert!(
            prepare(
                vec![],
                &f.context(vec![CoreHostSource::new(CoreBind::ProjectDir, project)])
            )
            .is_ok()
        );
        f.refused(
            vec![],
            &f.context(vec![CoreHostSource::new(
                CoreBind::StateDir,
                f.home.clone(),
            )]),
            "AGENT_VM_STATE_DIR",
        );
        fs::create_dir_all(f.home.join(".pi/agent")).unwrap();
        f.refused(
            vec![],
            &f.context(vec![CoreHostSource::new(
                CoreBind::ProjectDir,
                f.home.clone(),
            )]),
            "host Pi credential file",
        );
    }
    #[test]
    fn config_guard_writable_mounts_and_exemptions() {
        let f = Fixture::new();
        fs::create_dir_all(f.home.join(".config/agent-vm")).unwrap();
        for raw in [
            f.home.display().to_string(),
            format!("{}:/h:rw", f.home.display()),
            format!("{}:/cfg", f.home.join(".config/agent-vm").display()),
        ] {
            f.refused(
                parse_extra_mounts(&[raw]).unwrap(),
                &f.context(vec![]),
                "launch authority",
            );
        }
        for mode in ["ro", "fork"] {
            let raw = format!("{}:/cfg:{mode}", f.home.join(".config/agent-vm").display());
            assert!(prepare(parse_extra_mounts(&[raw]).unwrap(), &f.context(vec![])).is_ok());
        }
    }
    #[test]
    fn config_guard_followed_readonly_target_is_allowed() {
        let f = Fixture::new();
        let links = f.home.join("code/p/links");
        fs::create_dir_all(&links).unwrap();
        fs::create_dir_all(f.home.join(".config/agent-vm")).unwrap();
        symlink(f.home.join(".config/agent-vm"), links.join("cfg")).unwrap();
        let raw = format!("{}:/links:follow-links", links.display());
        assert!(prepare(parse_extra_mounts(&[raw]).unwrap(), &f.context(vec![])).is_ok());
    }
    #[test]
    fn config_guard_missing_state_and_home_refuse_before_mutation() {
        for bind in [CoreBind::StateDir, CoreBind::GuestHome] {
            let f = Fixture::new();
            let path = f.store.join("ab12");
            let source = if bind == CoreBind::GuestHome {
                path.join("home")
            } else {
                path
            };
            symlink(source.join(".config"), f.home.join(".config")).unwrap();
            f.refused(
                vec![],
                &f.context(vec![CoreHostSource::new(bind, source)]),
                "does not exist yet",
            );
        }
    }
    #[test]
    fn config_guard_hard_links_are_checked_in_prepare() {
        let f = Fixture::new();
        let file = f.home.join(".config/agent-vm/config.toml");
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, "# no network").unwrap();
        fs::hard_link(file, f.project.join("alias")).unwrap();
        f.refused(vec![], &f.context(vec![]), "has 2 hard links");
    }
    #[test]
    fn config_guard_raw_authority_home_is_distinct_from_pi_home() {
        let f = Fixture::new();
        let raw = f.project.parent().unwrap().join("raw-home");
        let account = f.project.parent().unwrap().join("account-home");
        fs::create_dir(&raw).unwrap();
        fs::create_dir(&account).unwrap();
        symlink(f.project.join(".config"), raw.join(".config")).unwrap();
        let mut context = f.context(vec![CoreHostSource::new(
            CoreBind::ProjectDir,
            f.project.clone(),
        )]);
        context.authority_home = Some(raw);
        context.account_home = Some(account);
        f.refused(vec![], &context, "launch authority");
    }
    /// A launch with `HOME` unset reads no user config but must still protect
    /// the *account* home a later launch would use (ADR-0038, "Both homes").
    /// This plan is exposing only through `account_home`, so dropping that
    /// input or measuring the Pi home in its place would let it through.
    #[test]
    fn config_guard_account_home_is_measured_without_an_authority_home() {
        let f = Fixture::new();
        fs::create_dir_all(f.home.join(".config/agent-vm")).unwrap();
        let source = CoreHostSource::new(CoreBind::ProjectDir, f.home.clone());
        let mut exposing = f.context(vec![source.clone()]);
        exposing.authority_home = None;
        exposing.account_home = Some(f.home.clone());
        f.refused(vec![], &exposing, "launch authority");
        // Control: with neither home measured the same plan is accepted, so
        // the refusal above is caused by the account-home input, not the
        // fixture (the Pi advisory path does not cover it).
        let mut control = f.context(vec![source]);
        control.authority_home = None;
        control.account_home = None;
        assert!(prepare(vec![], &control).is_ok());
    }
}
