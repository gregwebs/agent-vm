//! Read-only **tool configuration**: discovery, strict parsing, validation,
//! and the ordered user/project merge that `agent-vm doctor` previews.
//!
//! A **tool declaration** (`[[tools]]` in a config file) is *data*: a guest
//! command, its default argv, the credential providers it needs, extra
//! guest-HOME-relative paths to persist, guest env pairs, and network requests.
//! Requests never grant network access. This module
//! never executes a command, creates guest state, builds an image, or captures
//! a credential. A top-level `image` key selects the **boot image**
//! independently of the tools (see [`crate::boot_image`]).
//!
//! # Two ordered catalogs, not an overlay
//!
//! The user file (`$HOME/.config/agent-vm/config.toml`) and the project file
//! (`<cwd>/.agent-vm/config.toml`) are two ordered *catalogs*. The project may
//! add whole tool definitions the user did not write; a name the user did
//! write is authoritative and the entire user definition wins (never a
//! field-by-field merge). Resolved order is user declarations first, then
//! project-only declarations. Only when **both** lists are empty do the seven
//! compiled-in defaults (embedded from `default-tools.toml`) apply.
//!
//! ```
//! user file --------> parse + validate --+--> retained definitions --> launch
//! project file -----> parse + validate --+    every tier, hidden       verbs
//!                                             same-name losers too
//! both empty? -> embedded defaults ------+
//! ```
//!
//! Every tier is parsed and validated *before* merging, so an invalid
//! project declaration fails even when the user shadowed its name.
//!
//! # Launch selection is not reference resolution
//!
//! Two questions have two different answers, and keeping them apart is what
//! stops a project from activating a user's provider or persisted path by
//! naming it:
//!
//! * *Which definition does `agent-vm pi` launch?* [`merge`] answers it: whole-
//!   definition user-wins precedence picks the launch verbs.
//! * *Which definition does a `tools = [...]` entry name?* the referencing
//!   tool's **tool reference scope** answers it — the one configuration file
//!   that declares it. A name that scope does not declare is a config error,
//!   even when the other tier declares a *winning* verb of that name (#395).
//!
//! So the loser of a launch-name conflict is retained and stays resolvable from
//! its own file; it is only ever a *verb* that it loses. Resolution therefore
//! happens before launch selection: `ConfigReport::into_launch_catalog` folds
//! each launch winner's closure — providers, credential names and `persist`
//! paths over one visited mask — across the retained definitions, and only then
//! yields the launch entries.
//!
//! Persist ownership is checked twice, deliberately. [`load`] checks the launch
//! winners, as it always has, so an invalid catalog stays a load error. The
//! catalog then checks each launch winner's *own* closure, which is the only
//! way a conflict between two definitions hidden from verb selection is caught
//! without also rejecting two tiers' mutually exclusive closures: those never
//! link together in one launch.
//!
//! # Why the current module shape
//!
//! Construction of [`ConfigReport`] is private: callers get validated values
//! through read-only accessors, never raw serde/TOML documents. The parser
//! and resolver are private pure functions; [`ConfigPaths::discover`] is the
//! only environment adapter and [`load`] takes explicit named paths so tests
//! never depend on the process `HOME`/cwd and callers cannot reverse
//! precedence.
//!
//! No config filesystem trait exists on purpose: real temp files are
//! sufficient for this small seam and avoid a speculative abstraction.
//!
//! # Diagnostics are value-safe by construction
//!
//! Two distinct hazards are handled differently:
//!
//! * **Secrets.** A TOML/serde error's text can quote an argument a user
//!   mistook for a credential. [`deserialize_error`] therefore *discards* the
//!   dependency message entirely and emits a fixed schema-repair message
//!   plus a numeric line/column — never the rendered source or the error as
//!   an anyhow source. Semantic validators likewise describe a bad field by
//!   name/index, never by value.
//! * **Terminal control injection.** Paths and free-form reason strings may
//!   contain newlines, ESC/ANSI bytes, or invalid UTF-8. [`escape_bytes`]
//!   renders every non-printable byte as a printable `\xNN` escape, and the
//!   filesystem boundary ([`safe_io_error`]/[`safe_anyhow_error`]) escapes the
//!   *entire* reason chain of a reused reader before returning a fresh error
//!   with no raw source attached.
//!
//! # Consumed by launch
//!
//! [`ConfigReport::into_launch_catalog`] is what `cli` (to register
//! subcommands) and `doctor` (to render them) both start from: the retained
//! definitions resolved into entry provisioning, then the built-in `shell`
//! fallback (see [`LaunchCatalog`]).
//! [`ConfigReport::images`] carries the two tiers' boot-image settings, which
//! `cli` reads before consuming the report so a catalog error cannot erase a
//! readable image. Persisted-path overlap safety is defined here (#83):
//! [`guest_paths_overlap`] backs the within-tool, cross-tool and reserved-link
//! checks, and `guest_home::links` turns the surviving paths into the one
//! guest-HOME link list both guest-user modes provision from.
//! # Network and mount authority are user-tier only
//!
//! ADR-0040 permits verified user [network] tables and ADR-0046 a verified user
//! top-level `mounts` list; project and built-in tiers cannot declare either.
//! Whether the file holding one may be trusted is [`crate::config_authority`]'s
//! decision, taken here once per user file from the *presence* of either key, so
//! this module and [`crate::config_mounts`] only decide *what* a trusted file
//! says.

use crate::config_authority::{self, AuthorityTriggers};
use crate::config_mounts::{self, UserMounts};
use crate::user_network::{self, UserNetwork};

use crate::network_requests::{NetworkRequests, RequestTier};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

use anyhow::{Result, anyhow};
use serde::Deserialize;
use vstd::prelude::*;

use crate::boot_image::ImageRef;
use crate::credential_provider::{CredentialProvider, ProviderSet};
use crate::secret_store::ServiceName;

/// Ceiling on a config file read. A project config is possibly untrusted
/// input, so a huge or special file must not be able to hang or exhaust
/// `doctor`. Deliberately a *config* policy constant, not the credential
/// file's limit.
const MAX_CONFIG_FILE_BYTES: u64 = 1024 * 1024;

const USER_CONFIG_RELATIVE: &str = concat!(".config/agent-vm", "/config.toml");
const PROJECT_CONFIG_RELATIVE: &str = ".agent-vm/config.toml";

/// The user-scoped agent-vm config directory under `$HOME` — the directory
/// `USER_CONFIG_RELATIVE` sits in, and the one [`crate::secret_store`] and
/// #161's `credentials.yaml` share. Deliberately **not** `XDG_CONFIG_HOME`
/// overridable: host credential state is host-wide, so it must not move with a
/// per-session environment variable.
pub(crate) const USER_CONFIG_DIR_RELATIVE: &str = ".config/agent-vm";

/// Subcommands `agent-vm` reserves for itself. A tool named after one would be
/// unreachable through the CLI, so it is rejected at validation. The launch
/// verbs **are** the tools (a tool named `claude` is the normal case), so the
/// reserved set is exactly the fixed built-ins plus clap's synthesized
/// `help`, and `cli::BUILTIN_SUBCOMMANDS` is asserted equal to it as a set
/// (`cli.rs`'s `every_builtin_subcommand_is_reserved_from_tool_names`), so a
/// name cannot be reserved-but-unreachable or reachable-but-shadowable.
pub(crate) const RESERVED_TOOL_NAMES: &[&str] = &[
    "setup",
    "msb",
    "clipboard",
    "doctor",
    "secret",
    "image",
    "_intercept-hook",
    // The direct runner (issue #398). Reserved in every config tier, like a
    // built-in: a tool by that name could not be reached, and the runner is
    // the escape hatch from catalog launches.
    "run",
    // clap synthesizes a `help` subcommand unconditionally. A second one
    // panics in debug builds and silently shadows clap's in release.
    "help",
];

/// The compiled-in fallback catalog (see the file's own header for the order
/// and the empty-argv rationale). Parsed through the same raw-to-validated
/// path as user input, so a typo here is a test-detected programming error.
const DEFAULT_TOOLS_TOML: &str = include_str!("default-tools.toml");

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

/// Where the two config files live. `user` is `None` only when `$HOME` is
/// unavailable; the project path is always the canonical cwd plus the fixed
/// relative location (consistent with [`crate::session::ProjectSession::for_cwd`]).
pub(crate) struct ConfigPaths {
    pub(crate) user: Option<PathBuf>,
    pub(crate) project: PathBuf,
    /// The `$HOME` [`Self::user`] was derived from: the only base a `~/` in that
    /// file's `mounts` may expand against (ADR-0046). Captured once, with the
    /// path, so a launch cannot read one `config.toml` and expand `~/` against a
    /// different home.
    pub(crate) home: Option<PathBuf>,
}

impl ConfigPaths {
    /// The environment adapter: resolve `$HOME` and the canonical cwd.
    ///
    /// There is deliberately no `XDG_CONFIG_HOME` or override variable in
    /// this PR — the ticket names the literal `$HOME` location.
    pub(crate) fn discover() -> Result<Self> {
        let home = discover_home()?;
        Ok(Self {
            user: home.as_ref().map(|home| home.join(USER_CONFIG_RELATIVE)),
            project: discover_project_path()?,
            home,
        })
    }
}

/// The resolved catalog plus the facts `doctor` renders. Construction is
/// private to this module.
#[derive(Debug)]
pub(crate) struct ConfigReport {
    user: TierReport,
    project: TierReport,
    resolved: ResolvedTools,
    images: ConfiguredImages,
    user_network: Option<UserNetwork>,
    user_mounts: Option<UserMounts>,
    uses_defaults: bool,
    conflicts: Vec<ConfigConflict>,
}

impl ConfigReport {
    pub(crate) fn user(&self) -> &TierReport {
        &self.user
    }

    pub(crate) fn project(&self) -> &TierReport {
        &self.project
    }

    /// The retained definitions and the launch winners, without the fallback.
    /// Test-only: launch and `doctor` both consume
    /// [`ConfigReport::into_launch_catalog`] so their verb lists cannot
    /// disagree.
    #[cfg(test)]
    pub(crate) fn resolved(&self) -> &ResolvedTools {
        &self.resolved
    }

    /// The two tiers' `image` settings, read *before* the report is consumed by
    /// [`ConfigReport::into_launch_catalog`] so a dangling `tools` reference (or
    /// any catalog error) cannot erase a readable image choice.
    pub(crate) fn images(&self) -> &ConfiguredImages {
        &self.images
    }

    /// Read before into_launch_catalog consumes the report, like images.
    pub(crate) fn user_network(&self) -> Option<&UserNetwork> {
        self.user_network.as_ref()
    }

    /// The verified user `mounts`, `Some` even when the list is empty: a file
    /// that declared the key is authority-bearing and its declarations (zero or
    /// more) belong to every launch. Read before `into_launch_catalog` consumes
    /// the report, like [`Self::images`].
    pub(crate) fn user_mounts(&self) -> Option<&UserMounts> {
        self.user_mounts.as_ref()
    }

    /// True when neither file declared a tool and the compiled-in defaults
    /// supplied the catalog.
    pub(crate) fn uses_defaults(&self) -> bool {
        self.uses_defaults
    }

    /// Cross-tier conflicts in project declaration order; empty for a clean
    /// dedupe.
    pub(crate) fn conflicts(&self) -> &[ConfigConflict] {
        &self.conflicts
    }

    /// The catalog a launch actually offers: the merge result, plus the
    /// built-in `shell` appended when no declared tool claims that name.
    /// Consumed by both `cli::build_command` and `doctor`, so `--help` and
    /// `agent-vm doctor` cannot disagree about the verb list.
    ///
    /// Deliberately *not* folded into [`ResolvedTools`]: that type means "the
    /// merge result", and the fallback is not a declaration.
    pub(crate) fn into_launch_catalog(self) -> Result<LaunchCatalog> {
        let ConfigReport { resolved, .. } = self;
        catalog_from_tools(resolved)
    }
}

/// Resolve every retained definition, then select the launch verbs and append
/// the built-in `shell` fallback when no launch winner claims that name. The one
/// constructor for both a loaded config ([`ConfigReport::into_launch_catalog`])
/// and the compiled-in defaults ([`default_launch_catalog`]), so the fallback
/// cannot differ between them.
///
/// Resolution runs *before* selection because a hidden definition still supplies
/// its own file's references (#395). The fallback is resolved from a singleton
/// scope holding only the one shipped `shell`: reusing the whole shipped catalog
/// would restore the shipped agents' providers and `.dsh` persistence under a
/// custom catalog, which declaring any tools must replace.
fn catalog_from_tools(tools: ResolvedTools) -> Result<LaunchCatalog> {
    let shell_fallback_added = !tools
        .launch_tools()
        .any(|tool| tool.name() == SHELL_TOOL_NAME);
    let mut entries = resolve_provisioning(tools)?;
    let declared_len = entries.len();
    if shell_fallback_added {
        entries.extend(resolve_provisioning(ResolvedTools::from_defaults(vec![
            builtin_shell()?,
        ]))?);
    }
    Ok(LaunchCatalog {
        entries,
        declared_len,
    })
}

/// The compiled-in default launch catalog, resolved without touching the
/// environment. Used by `setup` to verify the shipped tools when a project or
/// user config is broken (a missing default entry is already a hard error, so
/// this cannot itself fail on the shipped catalog), and by tests.
pub(crate) fn default_launch_catalog() -> Result<LaunchCatalog> {
    catalog_from_tools(ResolvedTools::from_defaults(default_tools()?))
}

/// The outcome of loading the tool config, as data. One value rather than a
/// `LaunchCatalog` plus a parallel `Option<Error>`, so the catalog and the
/// deferred error cannot disagree about which state the process is in.
///
/// Lives here, not in `cli`, because the `Broken` arm is a *config* error and
/// `setup` needs to read it without depending on `cli`.
pub(crate) enum Catalog {
    Ready(LaunchCatalog),
    Broken(anyhow::Error),
}

/// The name the built-in `shell` fallback claims, and the one tool name whose
/// omitted `tools` defaults to the wildcard. One const so the catalog's
/// fallback and the `tools` default cannot drift apart.
pub(crate) const SHELL_TOOL_NAME: &str = "shell";

/// The reserved wildcard spelling in `tools = [...]`. Also rejected as a tool
/// *name* ([`validate_name`]) so the wildcard is unambiguous rather than merely
/// conventional.
const ALL_TOOLS_WILDCARD: &str = "*";

/// The verbs a launch actually offers, in chain order: the resolved merge
/// result, plus the built-in `shell` appended when no declared tool claims
/// that name. A config that omits `shell` — or typos it — must never leave the
/// user without a way into the guest to debug that config.
#[derive(Debug)]
pub(crate) struct LaunchCatalog {
    entries: Vec<CatalogEntry>,
    /// How many leading entries are declarations *right now*: the prefix
    /// describes the catalog's current contents, not a historical record. When
    /// dispatch removes one through [`Self::take_entry`], the prefix shrinks
    /// with it, so it always states what is still declared. The synthesized
    /// `shell` fallback, when present, is the single entry after this prefix.
    /// `cli` and `doctor` render all of `entries` ([`Self::as_slice`]); `setup`
    /// verifies only the declarations ([`Self::declarations`]), because the
    /// fallback "is not a declaration".
    declared_len: usize,
}

/// One launch-catalog entry: a tool plus the provisioning set resolved for it.
/// The set is computed once, here, because every consumer (launch, the proxy,
/// the guest env, `doctor`) must agree on it exactly.
#[derive(Debug)]
pub(crate) struct CatalogEntry {
    tool: Tool,
    provisioned: ProviderSet,
    /// Every credential name this entry's closure requests, folded and
    /// deduplicated over the same closure as [`Self::provisioned`]. A request,
    /// never an authorization: [`crate::credential_resolver`] decides which of
    /// these the user has actually authorized.
    requested_names: BTreeSet<ServiceName>,
    /// Every `persist` path this launch provisions: the union over its
    /// provisioning closure, in catalog then declaration order. Deterministic
    /// because it folds over the catalog, not the closure's traversal order.
    persist: Vec<PersistPath>,
}

impl CatalogEntry {
    pub(crate) fn tool(&self) -> &Tool {
        &self.tool
    }

    /// Everything a launch of this tool provisions: its own `credentials`
    /// unioned with the transitive closure over its `tools`. **Not** the
    /// requirement set — the pre-boot hard bail still reads `credentials`.
    pub(crate) fn provisioned(&self) -> ProviderSet {
        self.provisioned
    }

    /// Every credential name this launch requests, from its own `credentials`
    /// and its `tools` closure.
    pub(crate) fn requested_names(&self) -> &BTreeSet<ServiceName> {
        &self.requested_names
    }

    /// Every `persist` path this launch provisions, as the guest-HOME link
    /// list needs them. Parallel to [`Self::provisioned`]: both are facets of
    /// the one launch closure.
    pub(crate) fn persist(&self) -> &[PersistPath] {
        &self.persist
    }
}

impl LaunchCatalog {
    pub(crate) fn as_slice(&self) -> &[CatalogEntry] {
        &self.entries
    }

    /// Only the entries the configuration declares, as the catalog currently
    /// stands. `as_slice` is the full verb list — the built-in `shell` fallback
    /// included — for `cli` and `doctor`; `setup`'s verification scope is exactly
    /// the declarations, because a fallback is a launch affordance, not
    /// something the user asked to verify. The prefix length is maintained in
    /// one place ([`Self::take_entry`]), so this is not index arithmetic at the
    /// call site.
    pub(crate) fn declarations(&self) -> &[CatalogEntry] {
        &self.entries[..self.declared_len]
    }

    /// True when the entry after the declaration prefix is the built-in
    /// `shell` fallback — that is, `shell` is currently a launch affordance
    /// rather than a declaration. Derived from the current prefix (not from the
    /// historical fact that a fallback was appended), so `doctor` labels the row
    /// and `setup` scopes verification for what the catalog holds now.
    pub(crate) fn has_shell_fallback(&self) -> bool {
        self.declared_len < self.entries.len()
    }

    /// Remove just the named entry from the catalog and hand it on for
    /// dispatch, leaving the rest of the catalog usable. Removing one entry
    /// (rather than consuming the whole catalog, as the pre-#83 `into_entry`
    /// did) is what lets `cli::parse_from` pass the catalog on to a built-in
    /// verb — `setup` reads it to decide what to verify. The entry is handed on
    /// intact (rather than split into `(Tool, ProviderSet, Vec<PersistPath>)`)
    /// so the facts cannot be mismatched at any of the call sites (`cli.rs`
    /// dispatch, `main.rs`, `run::launch`).
    pub(crate) fn take_entry(&mut self, name: &str) -> Option<CatalogEntry> {
        let index = self
            .entries
            .iter()
            .position(|entry| entry.tool.name() == name)?;
        // Keep the prefix describing the catalog's *current* contents: a
        // removed declaration is no longer declared, so the prefix shrinks with
        // it. Removing the `shell` fallback (the entry at `declared_len`) leaves
        // the prefix — and every declaration in it — alone.
        if index < self.declared_len {
            self.declared_len -= 1;
        }
        Some(self.entries.remove(index))
    }
}

/// The shipped `shell` definition, re-parsed from `default-tools.toml` so
/// there is exactly one source of it. A missing entry is a programming error
/// (guarded by a test over [`default_tools`]), so it is a hard error rather
/// than a silent skip.
fn builtin_shell() -> Result<Tool> {
    default_tools()?
        .into_iter()
        .find(|tool| tool.name() == SHELL_TOOL_NAME)
        .ok_or_else(|| {
            anyhow!("config: the built-in defaults have no `{SHELL_TOOL_NAME}` tool; this is a bug")
        })
}

/// One entry of the retained definition arena. Private: it indexes
/// [`ResolvedTools::definitions`] and is neither a CLI identity nor a service
/// name, so holding one says nothing about what a launch offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct DefinitionId(usize);

/// Every retained tool definition plus which of them are launch verbs.
///
/// Retaining the losers is what makes a tier-local reference resolvable: a
/// project definition hidden by a user name conflict still supplies that
/// project file's `tools` references (#395). Hidden definitions are dropped once
/// their facets are folded, so nothing downstream can mistake one for a verb. No
/// mutator exists, and both constructors live here.
#[derive(Debug)]
pub(crate) struct ResolvedTools {
    /// Complete user declarations, then complete project declarations (hidden
    /// same-name losers included); on the defaults path, every shipped
    /// definition.
    definitions: Vec<Tool>,
    /// The launch winners' arena positions, unique and strictly increasing, in
    /// launch order: user declarations first, then project-only declarations.
    launches: Vec<DefinitionId>,
}

impl ResolvedTools {
    /// A catalog whose every definition is a launch verb: the shipped defaults,
    /// and the singleton fallback scope.
    fn from_defaults(tools: Vec<Tool>) -> Self {
        let launches = (0..tools.len()).map(DefinitionId).collect();
        Self {
            definitions: tools,
            launches,
        }
    }

    /// The launch-verb definitions, in launch order — never a retained hidden
    /// one. The merge tests and the load-time ownership check read this;
    /// launch and `doctor` go through [`ConfigReport::into_launch_catalog`]
    /// instead.
    pub(crate) fn launch_tools(&self) -> impl ExactSizeIterator<Item = &Tool> + '_ {
        self.launches.iter().map(|id| &self.definitions[id.0])
    }
}

/// What one config tier turned out to be. `path` is the attempted location
/// (`None` only for an unavailable `$HOME`).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TierReport {
    path: Option<PathBuf>,
    status: TierStatus,
}

impl TierReport {
    pub(crate) fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub(crate) fn status(&self) -> &TierStatus {
        &self.status
    }
}

/// Presence and declaration count are distinct: a found empty file is
/// `Found { declared_tools: 0 }`, not `Absent`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TierStatus {
    Absent,
    Found {
        declared_tools: usize,
    },
    /// `$HOME` was missing, so the user tier could not be located at all.
    UnavailableHome,
}

/// Where a resolved tool came from. File-backed variants retain the declaring
/// file for diagnostics; provenance is deliberately excluded from definition
/// equality. The exact variant *and* path are also the tool reference scope's
/// identity, which is why `Hash` is derived: a reference binds by
/// `(origin, name)`, never by bare name.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum ToolOrigin {
    BuiltIn,
    User(PathBuf),
    Project(PathBuf),
}

impl From<&ToolOrigin> for RequestTier {
    fn from(origin: &ToolOrigin) -> Self {
        match origin {
            ToolOrigin::BuiltIn => Self::BuiltIn,
            ToolOrigin::User(_) => Self::User,
            ToolOrigin::Project(_) => Self::Project,
        }
    }
}

/// One validated tool definition. All fields are private; readers use the
/// accessors below.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Tool {
    name: ToolName,
    command: String,
    argv: Vec<String>,
    /// The **built-in** providers this tool requires, in declaration order.
    /// Kept separate from [`Self::credential_names`] because every existing
    /// consumer (the provisioning closure, `run::launch`'s hard bail, every
    /// golden) is defined over built-ins only, and #161 must not change them.
    credentials: Vec<CredentialProvider>,
    /// Every name this tool's `credentials = [...]` declared, folded to the
    /// canonical [`ServiceName`] and deduplicated, in declaration order. A
    /// *source-neutral request*: whether a name is a built-in provider or a
    /// `credentials.yaml` authorization is a launch-resolution decision, not a
    /// config-parse one (#162 resolves it in `credential_resolver`).
    credential_names: Vec<ServiceName>,
    /// The catalog tools this tool wants available in its guest (a
    /// **provisioning** input), distinct from `credentials` (the
    /// **requirement** set).
    tools: DeclaredTools,
    persist: Vec<PersistPath>,
    interactive_shell: bool,
    /// This tool's own guest env, key-sorted. Keys are validated at
    /// construction ([`validate_env`]); values are arbitrary and may be
    /// secrets, so the field is private and `doctor` only ever sees
    /// [`Self::env_count`] — the same rule as `argv`.
    env: BTreeMap<String, String>,
    /// Declaration only: never authority and not folded over provisioning.
    network_requests: NetworkRequests,
    origin: ToolOrigin,
    /// The tool's position in its declaring file's `[[tools]]` list. Provenance
    /// like `origin`, not a config field: excluded from definition equality and
    /// from [`ToolField`], and carried only so [`resolve_provisioning`] can emit
    /// the repo's fixed `declaration [i]` diagnostic for a dangling reference
    /// (a shadowed same-file tool makes a re-derived count wrong).
    declaration_index: usize,
}

impl Tool {
    pub(crate) fn name(&self) -> &str {
        self.name.as_str()
    }

    /// The guest command **name** only — never its argv.
    pub(crate) fn command(&self) -> &str {
        &self.command
    }

    /// Count only. Argument *values* are never surfaced to callers, so a
    /// user who mistakenly put a secret in `args` cannot leak it through
    /// `doctor`. Launch reads [`Self::argv`] instead; diagnostics must not.
    pub(crate) fn arg_count(&self) -> usize {
        self.argv.len()
    }

    /// The tool's default argv, prepended to the user's own args by
    /// `run::launch`. Distinct from [`Self::arg_count`], which exists so
    /// `doctor` can report a tool without echoing a value a user mistook for
    /// a credential (#80): launch needs the values, diagnostics must not.
    pub(crate) fn argv(&self) -> &[String] {
        &self.argv
    }

    /// The credential subsystems this tool depends on, as the bitset
    /// `run::launch` threads into `secrets::refresh`.
    pub(crate) fn credential_providers(&self) -> ProviderSet {
        ProviderSet::new(self.credentials.iter().copied())
    }

    /// True when the tool arguments must be joined into a single bash
    /// `-c` command line instead of appended as separate `argv` entries (see
    /// `run::inner_argv`). A first-class config field rather than a
    /// `command == "bash"` check, which would silently misbehave for a
    /// user-declared `zsh`, `/bin/bash`, or `sh`.
    pub(crate) fn is_interactive_shell(&self) -> bool {
        self.interactive_shell
    }

    pub(crate) fn credentials(&self) -> &[CredentialProvider] {
        &self.credentials
    }

    /// Every credential name the tool declared, folded and deduplicated.
    /// [`Self::credential_providers`] stays the built-in-only projection.
    pub(crate) fn credential_names(&self) -> &[ServiceName] {
        &self.credential_names
    }

    /// The catalog tools this tool wants available in its guest, resolved
    /// within **this tool's own configuration file** (its tool reference
    /// scope), never across tiers.
    pub(crate) fn declared_tools(&self) -> &DeclaredTools {
        &self.tools
    }

    pub(crate) fn persist_count(&self) -> usize {
        self.persist.len()
    }

    /// The tool's own declared paths, in declaration order. `persist_count`
    /// stays for `doctor`, which must not grow a second way to read the same
    /// field.
    pub(crate) fn persist(&self) -> &[PersistPath] {
        &self.persist
    }

    /// This tool's own guest environment, sorted by key (a `BTreeMap`
    /// contract, which is why nothing tests declaration-order insensitivity).
    /// Published by `run::launch` *before* the launcher's own env, so a
    /// declaration colliding with `PATH`/`IS_SANDBOX`/`LANG` is overridden
    /// rather than honoured; the guest applies the pairs last-wins.
    /// `HOME`/`USER`/`LOGNAME` cannot appear here at all — [`validate_env`]
    /// rejects them, because the launcher owns the whole identity triple and
    /// publishes it *after* this map in both modes (`user::guest_identity_env`
    /// in default mode, `user::root_identity_env` under `--root`), so a
    /// declaration could only be silently inert. Validation cannot be
    /// mode-aware, so the rejection is unconditional. See ADR-0016.
    pub(crate) fn guest_env(&self) -> &BTreeMap<String, String> {
        &self.env
    }

    /// Count only, for the same reason as [`Self::arg_count`]: a value may be
    /// a credential a user pasted here by mistake.
    pub(crate) fn env_count(&self) -> usize {
        self.env.len()
    }

    pub(crate) fn network_requests(&self) -> &NetworkRequests {
        &self.network_requests
    }

    pub(crate) fn origin(&self) -> &ToolOrigin {
        &self.origin
    }

    /// Definition equality for cross-tier dedupe: every configurable non-name
    /// field, after empty defaults and persist normalization. Vector order is
    /// significant (argv is *not* a set). Provenance is excluded.
    fn same_definition(&self, other: &Tool) -> bool {
        self.command == other.command
            && self.argv == other.argv
            && self.credentials == other.credentials
            && self.credential_names == other.credential_names
            && self.tools == other.tools
            && self.persist == other.persist
            && self.interactive_shell == other.interactive_shell
            && self.env == other.env
            && self.network_requests == other.network_requests
    }

    /// The differing fields, in the fixed schema order the warning renders.
    fn differing_fields(&self, other: &Tool) -> Vec<ToolField> {
        let mut fields = Vec::new();
        if self.command != other.command {
            fields.push(ToolField::Command);
        }
        if self.argv != other.argv {
            fields.push(ToolField::Args);
        }
        if self.credentials != other.credentials || self.credential_names != other.credential_names
        {
            fields.push(ToolField::Credentials);
        }
        if self.tools != other.tools {
            fields.push(ToolField::Tools);
        }
        if self.persist != other.persist {
            fields.push(ToolField::Persist);
        }
        // Appended last so the fixed-order warnings keep their ordering.
        if self.interactive_shell != other.interactive_shell {
            fields.push(ToolField::InteractiveShell);
        }
        // Appended last for the same reason as `interactive_shell` above.
        if self.env != other.env {
            fields.push(ToolField::Env);
        }
        if self.network_requests != other.network_requests {
            fields.push(ToolField::NetworkRequests);
        }
        fields
    }
}

/// A tool name: a nonempty command-name token with no whitespace/control
/// characters, no `/` (it names one command, not a path), not an all-`.`
/// spelling (`.`/`..`/`...`), no leading `-`, and not a reserved `agent-vm`
/// subcommand. Case-sensitive; never trimmed or lowercased.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ToolName(String);

impl ToolName {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// The catalog tools a tool wants available in its guest. These name **tools**,
/// not credential providers: the transitive closure over them, unioned with
/// each visited tool's own `credentials`, is the tool's provisioning set.
///
/// An enum rather than a `Vec<ToolName>` plus a `bool`: `"*"` must be the sole
/// entry, and making the mixed form unrepresentable after validation means no
/// consumer has to re-check it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DeclaredTools {
    /// `tools = ["*"]`, and the default for a tool named [`SHELL_TOOL_NAME`].
    /// Closes over every retained definition in the **same configuration file**
    /// as this tool (origin equality; `BuiltIn` = the embedded
    /// `default-tools.toml`) — never the merged catalog, and including
    /// definitions hidden from launch-verb selection.
    All,
    /// Declaration order preserved (definition equality is order-significant,
    /// exactly like `credentials`). May be empty; may name the tool itself.
    Named(Vec<ToolName>),
}

/// One config tier's `image`, with the file that declared it (for diagnostics
/// and `doctor`). Both fields are private; the accessors are the only readers,
/// so a caller cannot pair a reference with the wrong declaring file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfiguredImage {
    reference: ImageRef,
    file: PathBuf,
}

impl ConfiguredImage {
    pub(crate) fn reference(&self) -> &ImageRef {
        &self.reference
    }

    pub(crate) fn file(&self) -> &Path {
        &self.file
    }

    /// A configured image built for tests outside this module (which cannot
    /// name the private fields). Uses the permissive override parser so a test
    /// fixture need not be a fully valid OCI reference.
    #[cfg(test)]
    pub(crate) fn for_test(reference: &str, file: impl Into<PathBuf>) -> Self {
        Self {
            reference: ImageRef::from_override(reference.to_string())
                .expect("valid test image reference"),
            file: file.into(),
        }
    }
}

/// Both tiers' `image` settings. `Default` (neither set) is also what `image refresh`
/// and `setup` use when the configuration could not be read at all: the
/// configured tiers are then unknown, and the recovery builtins fall back to
/// `--image`/env or the default boot image.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ConfiguredImages {
    user: Option<ConfiguredImage>,
    project: Option<ConfiguredImage>,
}

impl ConfiguredImages {
    pub(crate) fn user(&self) -> Option<&ConfiguredImage> {
        self.user.as_ref()
    }

    pub(crate) fn project(&self) -> Option<&ConfiguredImage> {
        self.project.as_ref()
    }

    /// A fixture for tests outside this module (which cannot name the private
    /// fields). Named fields rather than two adjacent `Option<ConfiguredImage>`
    /// parameters, so a user/project swap cannot compile
    /// (`CODING_STANDARDS.md` → *Types*).
    #[cfg(test)]
    pub(crate) fn for_test(fixture: ImageTierFixture) -> Self {
        Self {
            user: fixture.user,
            project: fixture.project,
        }
    }
}

/// Named image tiers for test fixtures built through
/// [`ConfiguredImages::for_test`].
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct ImageTierFixture {
    pub(crate) user: Option<ConfiguredImage>,
    pub(crate) project: Option<ConfiguredImage>,
}

/// A validated, normalized guest-HOME-relative persist path. The inner path
/// is a relative sequence of normal components (no `.`, no `..`, no
/// absolute/root form).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PersistPath(PathBuf);

impl PersistPath {
    pub(crate) fn as_path(&self) -> &Path {
        &self.0
    }

    /// A persist path built through the same normalization the parser uses, for
    /// unit tests outside `config` (which cannot name the private inner field).
    #[cfg(test)]
    pub(crate) fn for_test(declaration: &str) -> Self {
        PersistPath(normalize_persist(declaration).expect("valid test persist path"))
    }
}

/// A configurable tool field, used to name the fields a cross-tier shadow
/// differs in. `as_str` is the canonical spelling in warnings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ToolField {
    Command,
    Args,
    Credentials,
    Tools,
    Persist,
    // Appended last: `each_differing_field_is_reported_individually_in_fixed_order`
    // and the multi-field ordering test depend on this sequence.
    InteractiveShell,
    Env,
    NetworkRequests,
}

impl ToolField {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ToolField::Command => "command",
            ToolField::Args => "args",
            ToolField::Credentials => "credentials",
            ToolField::Tools => "tools",
            ToolField::Persist => "persist",
            ToolField::InteractiveShell => "interactive_shell",
            ToolField::Env => "env",
            ToolField::NetworkRequests => "network_requests",
        }
    }
}

/// One cross-tier shadow: a project declaration of a name the user also
/// declared, whose definition differs. Returned as data; `doctor` renders it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ConfigConflict {
    tool: ToolName,
    user_file: PathBuf,
    project_file: PathBuf,
    fields: Vec<ToolField>,
}

impl ConfigConflict {
    pub(crate) fn tool(&self) -> &str {
        self.tool.as_str()
    }

    pub(crate) fn user_file(&self) -> &Path {
        &self.user_file
    }

    pub(crate) fn project_file(&self) -> &Path {
        &self.project_file
    }

    /// Nonempty; in fixed schema order.
    pub(crate) fn fields(&self) -> &[ToolField] {
        &self.fields
    }
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// Discover both tiers, parse and validate each, merge, and check persist
/// ownership. Any read/parse/validation failure is a contextual hard error —
/// there is no fallback to defaults.
pub(crate) fn load(paths: &ConfigPaths) -> Result<ConfigReport> {
    let (user, user_contents) = match &paths.user {
        Some(path) => read_file_tier(TierSource {
            path,
            kind: FileTierKind::User,
            home: paths.home.as_deref(),
        })?,
        None => (
            TierReport {
                path: None,
                status: TierStatus::UnavailableHome,
            },
            TierContents::empty(),
        ),
    };
    // The project tier can declare no `mounts` (refused), so it has no `~/` base.
    let (project, project_contents) = read_file_tier(TierSource {
        path: &paths.project,
        kind: FileTierKind::Project,
        home: None,
    })?;
    let mounts = user_contents.mounts;

    let (resolved, uses_defaults, conflicts) =
        if user_contents.tools.is_empty() && project_contents.tools.is_empty() {
            (
                ResolvedTools::from_defaults(default_tools()?),
                true,
                Vec::new(),
            )
        } else {
            let (merged, conflicts) = merge(user_contents.tools, project_contents.tools);
            (merged, false, conflicts)
        };

    validate_persist_ownership(resolved.launch_tools())?;

    Ok(ConfigReport {
        user,
        project,
        resolved,
        images: ConfiguredImages {
            user: user_contents.image,
            project: project_contents.image,
        },
        user_network: user_contents.network,
        user_mounts: mounts,
        uses_defaults,
        conflicts,
    })
}

/// What one parsed tier supplied: its tools and its optional `image`. Kept as
/// one value so the tool count and the image cannot be read from two different
/// parses.
struct TierContents {
    network: Option<UserNetwork>,
    /// The user tier's verified `mounts`, present-empty included.
    mounts: Option<UserMounts>,
    tools: Vec<Tool>,
    image: Option<ConfiguredImage>,
}

impl TierContents {
    fn empty() -> Self {
        Self {
            tools: Vec::new(),
            image: None,
            network: None,
            mounts: None,
        }
    }
}

#[derive(Clone, Copy)]
enum FileTierKind {
    User,
    Project,
}

impl FileTierKind {
    fn origin(self, file: &Path) -> ToolOrigin {
        match self {
            FileTierKind::User => ToolOrigin::User(file.to_path_buf()),
            FileTierKind::Project => ToolOrigin::Project(file.to_path_buf()),
        }
    }
}

/// One file-backed tier to read: its path, which tier it is, and — for the user
/// tier — the `$HOME` a `~/` in its `mounts` expands against.
///
/// A named bundle rather than three positional arguments, because two of them
/// would be an `Option<&Path>` the callee could not tell apart from the file it
/// reads.
struct TierSource<'a> {
    path: &'a Path,
    kind: FileTierKind,
    home: Option<&'a Path>,
}

/// Read, decode, and validate one file-backed tier. Only a `NotFound` from
/// the initial `symlink_metadata` means absent; a present-but-dangling
/// symlink or a file that vanishes before the read is an error, not a quiet
/// fallback.
fn read_file_tier(source: TierSource<'_>) -> Result<(TierReport, TierContents)> {
    let TierSource { path, kind, home } = source;
    match std::fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((
                TierReport {
                    path: Some(path.to_path_buf()),
                    status: TierStatus::Absent,
                },
                TierContents::empty(),
            ));
        }
        Err(error) => return Err(safe_io_error("reading metadata for", path, &error)),
    }

    let read =
        crate::host_paths::read_bounded_regular_file_noting_symlink(path, MAX_CONFIG_FILE_BYTES)
            .map_err(|error| safe_anyhow_error("reading", path, &error))?;
    let path = read.path();
    let text = std::str::from_utf8(read.bytes()).map_err(|_| utf8_error(path))?;
    let raw: RawConfig =
        toml::from_str(text).map_err(|error| deserialize_error(path, text, &error))?;
    // Authority is decided by the *presence* of an authority-bearing field, from
    // the same verified read the bytes came from, before any of it is parsed.
    // Presence, not contents: `mounts = []` and an empty `[network]` grant
    // nothing yet are exactly the bytes an attacker would plant.
    let triggers = AuthorityTriggers {
        network: raw.network.is_some(),
        mounts: raw.mounts.is_some(),
    };
    let authorized = match kind {
        FileTierKind::User => config_authority::verify(&read, triggers)
            .map_err(|error| anyhow!("config: {}: {error}", crate::one_line::quoted_path(path)))?,
        FileTierKind::Project => {
            refuse_project_authority(&raw, path)?;
            None
        }
    };
    let network = match raw.network.as_ref() {
        Some(table) => {
            // A present field always produced a token above (presence *is* the
            // trigger), so this arm cannot be reached with `None`. Refusing
            // rather than skipping keeps that invariant load-bearing: dropping
            // the grants a file declares must never be the quiet outcome.
            let Some(authorized) = authorized.as_ref() else {
                return Err(anyhow!(
                    "config: {}: [network]: authority was not measured",
                    crate::one_line::quoted_path(path)
                ));
            };
            Some(
                user_network::from_verified_table(authorized, table).map_err(|error| {
                    anyhow!("config: {}: {error}", crate::one_line::quoted_path(path))
                })?,
            )
        }
        None => None,
    };
    let mounts = match raw.mounts.as_ref() {
        Some(value) => {
            // The same invariant as `[network]`: a present `mounts` is a
            // trigger, so the token exists.
            let Some(authorized) = authorized.as_ref() else {
                return Err(anyhow!(
                    "config: {}: mounts: authority was not measured",
                    crate::one_line::quoted_path(path)
                ));
            };
            Some(
                config_mounts::from_verified_value(authorized, value, home).map_err(|error| {
                    anyhow!("config: {}: {error}", crate::one_line::quoted_path(path))
                })?,
            )
        }
        None => None,
    };
    let image = validate_image(raw.image.as_deref(), path)?;
    let tools = validate_tools(raw.tools, kind.origin(path))?;

    Ok((
        TierReport {
            path: Some(path.to_path_buf()),
            status: TierStatus::Found {
                declared_tools: tools.len(),
            },
        },
        TierContents {
            tools,
            image,
            network,
            mounts,
        },
    ))
}

/// A project file may not grant anything. Network is checked first so a file
/// that declares both keeps today's `[network]` bytes.
fn refuse_project_authority(raw: &RawConfig, path: &Path) -> Result<()> {
    if let Some(table) = raw.network.as_ref() {
        return Err(network_refusal(table, path, RefusingTier::Project));
    }
    if raw.mounts.is_some() {
        return Err(mounts_refusal(path, RefusingTier::Project));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum RefusingTier {
    Project,
    BuiltIn,
}

fn network_refusal(table: &toml::Table, file: &Path, tier: RefusingTier) -> anyhow::Error {
    let settings: Vec<_> = user_network::SETTINGS
        .iter()
        .filter(|key| table.contains_key(**key))
        .map(|key| format!("network.{key}"))
        .collect();
    let setting = if settings.is_empty() {
        "[network]".to_owned()
    } else {
        settings.join(", ")
    };
    let reason = match tier {
        RefusingTier::Project => "network access cannot be granted by the project config",
        RefusingTier::BuiltIn => "network access cannot be granted by the built-in config",
    };
    anyhow!(
        "config: {}: {setting}: {reason}; use --allow-* launch flags, or [network] in the user config",
        crate::one_line::quoted_path(file)
    )
}

/// The `mounts` twin of [`network_refusal`], for the two tiers that may not
/// declare one.
fn mounts_refusal(file: &Path, tier: RefusingTier) -> anyhow::Error {
    let reason = match tier {
        RefusingTier::Project => "mounts cannot be declared by the project config",
        RefusingTier::BuiltIn => "mounts cannot be declared by the built-in config",
    };
    anyhow!(
        "config: {}: {reason}; use --mount launch options, or mounts in the user config",
        crate::one_line::quoted_path(file)
    )
}

/// Validate one tier's top-level `image` into an [`ImageRef`]. The reason comes
/// from [`ImageRef::from_config`] and names no value, so untrusted config text
/// is never echoed (see the module's diagnostics policy).
fn validate_image(raw: Option<&str>, file: &Path) -> Result<Option<ConfiguredImage>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    match ImageRef::from_config(raw) {
        Ok(reference) => Ok(Some(ConfiguredImage {
            reference,
            file: file.to_path_buf(),
        })),
        Err(reason) => Err(anyhow!(
            "config: {}: image: {reason}",
            crate::one_line::quoted_path(file)
        )),
    }
}

/// Parse the embedded fallback catalog through the same validated path.
fn default_tools() -> Result<Vec<Tool>> {
    tools_from_builtin_text(DEFAULT_TOOLS_TOML)
}

fn tools_from_builtin_text(text: &str) -> Result<Vec<Tool>> {
    let path = Path::new("default-tools.toml");
    let raw: RawConfig =
        toml::from_str(text).map_err(|error| deserialize_error(path, text, &error))?;
    if let Some(table) = raw.network.as_ref() {
        return Err(network_refusal(table, path, RefusingTier::BuiltIn));
    }
    if raw.mounts.is_some() {
        return Err(mounts_refusal(path, RefusingTier::BuiltIn));
    }
    validate_tools(raw.tools, ToolOrigin::BuiltIn)
}

fn discover_home() -> Result<Option<PathBuf>> {
    host_home_dir().map_err(|error| {
        anyhow!(
            "config: {error}; cannot locate {}",
            quoted_str(USER_CONFIG_RELATIVE)
        )
    })
}

/// `$HOME` as an absolute, non-empty path, or `None` when it is unset. The
/// single statement of agent-vm's `$HOME` discipline — a *set but empty* or
/// *relative* `$HOME` is a hard error rather than a silently wrong location —
/// shared by the user config path here and [`crate::secret_store`]'s inventory
/// path. Callers add their own context naming what could not be located.
pub(crate) fn host_home_dir() -> Result<Option<PathBuf>> {
    let Some(home) = std::env::var_os("HOME") else {
        return Ok(None);
    };
    let home = PathBuf::from(home);
    if home.as_os_str().is_empty() {
        return Err(anyhow!("$HOME is set but empty"));
    }
    if !home.is_absolute() {
        return Err(anyhow!(
            "$HOME {} is not absolute",
            crate::one_line::quoted_path(&home)
        ));
    }
    Ok(Some(home))
}

fn discover_project_path() -> Result<PathBuf> {
    let cwd = std::env::current_dir()
        .map_err(|error| safe_io_error("resolving current directory", Path::new("."), &error))?;
    let canonical = cwd
        .canonicalize()
        .map_err(|error| safe_io_error("canonicalizing current directory", &cwd, &error))?;
    Ok(canonical.join(PROJECT_CONFIG_RELATIVE))
}

// ---------------------------------------------------------------------------
// Merge and ownership
// ---------------------------------------------------------------------------

/// Whole-definition union: user order first, then project-only tools in
/// project order. A name present in both keeps the entire user definition;
/// if it differs, one conflict is recorded. Uses a name index for membership
/// but never iterates it, so neither tool nor warning order can drift.
///
/// Every project definition is retained in [`ResolvedTools::definitions`] even
/// when it loses its launch verb, because the project file's other definitions
/// may still reference it (#395). Only the winners enter
/// [`ResolvedTools::launches`].
///
/// Both declaring files come from the tools' provenance rather than the
/// caller, so a conflict warning never fabricates a placeholder path.
fn merge(user_tools: Vec<Tool>, project_tools: Vec<Tool>) -> (ResolvedTools, Vec<ConfigConflict>) {
    let index: HashMap<String, usize> = user_tools
        .iter()
        .enumerate()
        .map(|(position, tool)| (tool.name.as_str().to_string(), position))
        .collect();

    let mut launches: Vec<DefinitionId> = (0..user_tools.len()).map(DefinitionId).collect();
    let mut definitions = user_tools;
    let mut conflicts = Vec::new();
    for project_tool in project_tools {
        match index.get(project_tool.name.as_str()) {
            Some(&position) => {
                let winner = &definitions[position];
                // A conflict is necessarily cross-tier: the winner comes from
                // the user tier (the index only holds user names), the loser
                // from the project tier. Naming both files from provenance
                // keeps `merge` from taking two indistinguishable `&Path`s.
                if !winner.same_definition(&project_tool)
                    && let (ToolOrigin::User(user_file), ToolOrigin::Project(project_file)) =
                        (&winner.origin, &project_tool.origin)
                {
                    conflicts.push(ConfigConflict {
                        tool: winner.name.clone(),
                        user_file: user_file.clone(),
                        project_file: project_file.clone(),
                        fields: winner.differing_fields(&project_tool),
                    });
                }
            }
            // Same-tier duplicate project names are rejected before merging,
            // so an absent name only ever appears here once.
            None => launches.push(DefinitionId(definitions.len())),
        }
        definitions.push(project_tool);
    }
    (
        ResolvedTools {
            definitions,
            launches,
        },
        conflicts,
    )
}

/// Overlap ownership across one launch: two distinct tools may not claim the
/// same guest-HOME-relative location, nor an ancestor/descendant pair (linking
/// both would leave one path a dangling symlink and make the other
/// uncreatable). Called twice by design (see the module docs): once over the
/// launch winners in [`load`], and once per launch winner's own closure in
/// [`resolve_provisioning`], which is where a conflict between definitions
/// hidden from verb selection is caught. The compiled-in link list is checked
/// separately, per tool, in [`validate_persist`]; the launch's guest mount
/// points are checked in `run::launch` because the project path is not a config
/// fact.
fn validate_persist_ownership<'a>(tools: impl IntoIterator<Item = &'a Tool>) -> Result<()> {
    // (path, tool) in catalog then declaration order, so the diagnostic names
    // the earlier claimant as "already claimed by" and the later tool as the
    // offender.
    let mut claimed: Vec<(&Path, &Tool)> = Vec::new();
    for tool in tools {
        for path in &tool.persist {
            for (existing_path, existing_tool) in &claimed {
                if !guest_paths_overlap(path.as_path(), existing_path) {
                    continue;
                }
                if *existing_path == path.as_path() {
                    return Err(anyhow!(
                        "config: guest persist path {} is claimed by tool {} ({}) and tool {} ({}); remove or rename one claim",
                        quoted_path(path.as_path()),
                        quoted_str(existing_tool.name.as_str()),
                        describe_origin(&existing_tool.origin),
                        quoted_str(tool.name.as_str()),
                        describe_origin(&tool.origin),
                    ));
                }
                return Err(anyhow!(
                    "config: guest persist path {} declared by tool {} ({}) overlaps {} claimed by tool {} ({}); one would shadow the other",
                    quoted_path(path.as_path()),
                    quoted_str(tool.name.as_str()),
                    describe_origin(&tool.origin),
                    quoted_path(existing_path),
                    quoted_str(existing_tool.name.as_str()),
                    describe_origin(&existing_tool.origin),
                ));
            }
            claimed.push((path.as_path(), tool));
        }
    }
    Ok(())
}

/// A tool's provenance for a declaration or persist-ownership diagnostic: the
/// tier label followed by the escaped, quoted declaring file. It is the sole
/// renderer of provenance in those messages — callers pass an origin, never a
/// pre-rendered file — so the named file can never disagree with the tier.
///
/// `BuiltIn` still names a file so declaration errors keep the
/// `default-tools.toml` they printed before the tier was added; the
/// persist-ownership diagnostics share this renderer and intentionally name it
/// too.
fn describe_origin(origin: &ToolOrigin) -> String {
    let tier = match origin {
        ToolOrigin::BuiltIn => "built-in defaults",
        ToolOrigin::User(_) => "user config",
        ToolOrigin::Project(_) => "project config",
    };
    format!(
        "{tier} {}",
        crate::one_line::quoted_path(origin_file(origin))
    )
}

/// The declaring file a diagnostic names. `BuiltIn` stores no path because
/// there is exactly one built-in file; name it here, matching the string
/// [`default_tools`] passes to the parser.
fn origin_file(origin: &ToolOrigin) -> &Path {
    match origin {
        ToolOrigin::BuiltIn => Path::new("default-tools.toml"),
        ToolOrigin::User(file) | ToolOrigin::Project(file) => file,
    }
}

/// A tool reference's scope identity: the declaring file's origin variant and
/// path, plus the case-sensitive tool name. Built from every retained
/// definition, hidden ones included.
type ScopedToolIndex<'a> = HashMap<(&'a ToolOrigin, &'a str), DefinitionId>;

/// The two origins one reference crosses — named fields rather than adjacent
/// `&ToolOrigin` arguments, which a call site could swap
/// (`CODING_STANDARDS.md` → *Types*).
struct ReferenceOrigins<'a> {
    declaring: &'a ToolOrigin,
    candidate: &'a ToolOrigin,
}

/// Measure the two facts [`reference_scope_matches`] decides on. The trusted
/// adapter of an ADR-0018 pair: variant equality and declaring-path equality are
/// measured here, the conjunction is proved. `BuiltIn` has exactly one embedded
/// file, so the path half names it and `BuiltIn`/`BuiltIn` measures as one scope.
fn same_reference_scope(origins: ReferenceOrigins<'_>) -> bool {
    let facts = ReferenceScopeFacts {
        same_tier: std::mem::discriminant(origins.declaring)
            == std::mem::discriminant(origins.candidate),
        same_file: origin_file(origins.declaring) == origin_file(origins.candidate),
    };
    reference_scope_matches(facts)
}

/// Index every retained definition by `(origin, name)`.
///
/// The exact origin — never the bare name — is what keeps a reference tier-local:
/// a project `helper` that names `pi` finds the project's `pi`, whatever the
/// launch catalog selected for the verb. A duplicate key would make one reference
/// depend on arena order, so it is refused instead of last-wins. `validate_tools`
/// already rejects duplicate names within one file, so this is a construction
/// invariant rather than user-input validation.
fn scoped_tool_index(definitions: &[Tool]) -> Result<ScopedToolIndex<'_>> {
    let mut index = ScopedToolIndex::new();
    for (position, tool) in definitions.iter().enumerate() {
        if index
            .insert((tool.origin(), tool.name()), DefinitionId(position))
            .is_some()
        {
            return Err(tool_error(
                &tool.origin,
                tool.declaration_index,
                &tool.name,
                "internal tool-reference index already holds this file and name; \
                 report this as an agent-vm bug",
            ));
        }
    }
    Ok(index)
}

/// The other retained file that declares a reference's name, if one does.
/// [`describe_origin`] renders it for the diagnostic; nothing else from that file
/// is printed.
///
/// A miss in the scoped index has two causes, and the advice differs by which
/// one this returns: another retained file declares the name (the reference
/// crossed a file boundary), or nothing retained declares it (a typo, or an agent
/// the catalog replaced the shipped defaults to drop). Diagnostics only — the
/// scoped lookup already decided validity, and this never feeds a resolution.
///
/// One scope is the whole answer: the retained arena holds the built-in file
/// alone or the user and project files, and `scoped_tool_index` refuses a
/// duplicate `(origin, name)`, so at most one file besides the declaring one can
/// hold the name.
fn reference_declared_elsewhere<'a>(
    definitions: &'a [Tool],
    declaring: &ToolOrigin,
    reference: &ToolName,
) -> Option<&'a ToolOrigin> {
    definitions
        .iter()
        .find(|tool| {
            tool.name() == reference.as_str()
                && !same_reference_scope(ReferenceOrigins {
                    declaring,
                    candidate: tool.origin(),
                })
        })
        .map(Tool::origin)
}

/// The error for a `tools` entry the scoped index cannot satisfy — the one place
/// a reference miss reaches the user. Both wordings keep the tier, file,
/// declaration index, tool name and field; only the cause and its fix differ, so
/// a typo is never blamed on the cross-tier rule. The other declaring file is
/// rendered by [`describe_origin`] and nothing else from it is printed.
fn unresolved_tools_reference(
    tool: &Tool,
    position: usize,
    reference: &ToolName,
    elsewhere: Option<&ToolOrigin>,
) -> anyhow::Error {
    let (declared, advice) = match elsewhere {
        Some(origin) => (
            format!("; it is declared in {}", describe_origin(origin)),
            "cross-tier tool references are not allowed; copy or redeclare the tool in this file, or remove the entry",
        ),
        None => (String::new(), "declare it in this file or remove the entry"),
    };
    tool_error(
        &tool.origin,
        tool.declaration_index,
        &tool.name,
        format!(
            "tools[{position}]: {} names no tool in this configuration file{declared}; {advice}",
            quoted_str(reference.as_str())
        ),
    )
}

/// The error for a reference the scoped index cannot satisfy *during a closure
/// walk*. Every explicit reference is checked before any closure is walked, so
/// reaching this means the index and the traversal disagree — a construction bug,
/// not user input.
fn unresolved_reference(tool: &Tool, reference: &ToolName) -> anyhow::Error {
    tool_error(
        &tool.origin,
        tool.declaration_index,
        &tool.name,
        format!(
            "tools: {} passed validation but is absent from this file's tool-reference \
             index; report this as an agent-vm bug",
            quoted_str(reference.as_str())
        ),
    )
}

/// Resolve every launch winner's provisioning set as the least fixed point of
///
/// ```text
/// provisioning(t) = credentials(t) ∪ ⋃ { provisioning(u) | u ∈ tools(t) }
/// ```
///
/// where `tools(t)` names retained definitions in `t`'s **tool reference scope** —
/// the one configuration file that declares `t` — and a `"*"` entry expands to
/// every definition in that scope, hidden ones included. Providers, credential
/// names and `persist` paths are folded over one visited mask, so the three facets
/// cannot disagree about what a launch provisions.
///
/// Every retained definition's explicit references are checked first, *including*
/// definitions no launch verb reaches: a dangling reference is an error in the
/// file that contains it, and another file's winning definition of that name
/// neither satisfies it nor hides it. Each launch winner's closure is then
/// checked for persist ownership *before* its paths escape, and the facets fold in
/// arena order, so the result never depends on traversal order.
fn resolve_provisioning(tools: ResolvedTools) -> Result<Vec<CatalogEntry>> {
    let ResolvedTools {
        definitions,
        launches,
    } = tools;
    let index = scoped_tool_index(&definitions)?;

    for tool in &definitions {
        let DeclaredTools::Named(names) = tool.declared_tools() else {
            continue;
        };
        for (position, reference) in names.iter().enumerate() {
            if index.contains_key(&(tool.origin(), reference.as_str())) {
                continue;
            }
            return Err(unresolved_tools_reference(
                tool,
                position,
                reference,
                reference_declared_elsewhere(&definitions, tool.origin(), reference),
            ));
        }
    }

    let closures: Vec<Vec<bool>> = launches
        .iter()
        .map(|start| launch_closure(&definitions, &index, *start))
        .collect::<Result<_>>()?;
    drop(index);

    // Ownership before any facet escapes: two definitions selected by the same
    // launch may not claim one guest path or an ancestor/descendant pair, even
    // when one of them lost its launch verb. Unguarded here, a hidden loser's
    // paths would reach the guest-HOME link list unvalidated.
    for visited in &closures {
        validate_persist_ownership(closure_definitions(&definitions, visited))?;
    }

    let facets: Vec<(ProviderSet, BTreeSet<ServiceName>, Vec<PersistPath>)> = closures
        .iter()
        .map(|visited| {
            let mut provisioned = ProviderSet::default();
            let mut requested_names = BTreeSet::new();
            let mut persist = Vec::new();
            for tool in closure_definitions(&definitions, visited) {
                provisioned = provisioned.union(tool.credential_providers());
                requested_names.extend(tool.credential_names().iter().cloned());
                persist.extend(tool.persist().iter().cloned());
            }
            (provisioned, requested_names, persist)
        })
        .collect();

    // Retention ends here: only the launch winners survive. Their arena positions
    // are found by ordered filtering, never by index arithmetic, so the strictly
    // increasing `launches` invariant alone keeps the pairing correct.
    Ok(definitions
        .into_iter()
        .enumerate()
        .filter(|(position, _)| launches.binary_search(&DefinitionId(*position)).is_ok())
        .zip(facets)
        .map(
            |((_, tool), (provisioned, requested_names, persist))| CatalogEntry {
                tool,
                provisioned,
                requested_names,
                persist,
            },
        )
        .collect())
}

/// The retained definitions one launch selects, in arena order. The closure's
/// membership is one fact: the ownership check and every folded facet read it
/// through this function so they cannot disagree about what the launch covers.
fn closure_definitions<'a>(
    definitions: &'a [Tool],
    visited: &'a [bool],
) -> impl Iterator<Item = &'a Tool> + 'a {
    definitions
        .iter()
        .zip(visited)
        .filter(|(_, seen)| **seen)
        .map(|(tool, _)| tool)
}

/// One retained definition's closure: which arena positions a launch of `start`
/// visits, as a visited-position mask. The least fixed point of `tools`, with `"*"`
/// closing over every definition in the declaring tool's own reference scope. A
/// cycle is harmless rather than an error: `visited` admits each definition at
/// most once, so the walk terminates at the fixed point. (`shell`'s wildcard
/// necessarily includes `shell` itself.)
///
/// Isolation comes from the two lookups: the wildcard measures the scope pair, and
/// a named edge uses the exact `(origin, name)` key with no bare-name retry. After
/// that exact lookup the scope measurement on a named edge is redundant; it stays
/// as local defence so an index built wrong cannot silently cross tiers.
fn launch_closure(
    tools: &[Tool],
    index: &ScopedToolIndex<'_>,
    start: DefinitionId,
) -> Result<Vec<bool>> {
    let mut visited = vec![false; tools.len()];
    let mut stack = vec![start];
    while let Some(id) = stack.pop() {
        if std::mem::replace(&mut visited[id.0], true) {
            continue;
        }
        let tool = &tools[id.0];
        match tool.declared_tools() {
            // `"*"` closes over the declaring tool's **own configuration file** —
            // the retained definitions that share its reference scope, hidden ones
            // included. In the shipped default catalog every tool is `BuiltIn`
            // (the embedded `default-tools.toml`), so this is all seven; under a
            // custom catalog the fallback shell is a scope of its own, so it closes
            // over itself alone and provisions only its own (empty) `credentials`.
            DeclaredTools::All => {
                for (position, candidate) in tools.iter().enumerate() {
                    if same_reference_scope(ReferenceOrigins {
                        declaring: tool.origin(),
                        candidate: candidate.origin(),
                    }) {
                        stack.push(DefinitionId(position));
                    }
                }
            }
            // Every name was proven present by `resolve_provisioning` above.
            DeclaredTools::Named(names) => {
                for reference in names {
                    let Some(&target) = index.get(&(tool.origin(), reference.as_str())) else {
                        return Err(unresolved_reference(tool, reference));
                    };
                    if !same_reference_scope(ReferenceOrigins {
                        declaring: tool.origin(),
                        candidate: tools[target.0].origin(),
                    }) {
                        return Err(unresolved_reference(tool, reference));
                    }
                    stack.push(target);
                }
            }
        }
    }
    Ok(visited)
}

// ---------------------------------------------------------------------------
// Raw schema and validation
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    // User tier: verified by config_authority; project/built-in: value-safe refusal.
    #[serde(default)]
    network: Option<toml::Table>,
    // User tier: verified (ADR-0046) when present, even `[]`; project/built-in:
    // refused. A `toml::Value`, not `Vec<String>`, so presence survives to the
    // authority decision — the value may be a table or a number, and deciding
    // *that* is a value-free `mounts[N]` diagnostic rather than a serde message.
    #[serde(default)]
    mounts: Option<toml::Value>,
    /// The session's **boot image**, an OCI reference (D4). Optional: an
    /// image-only file declares no tools and keeps the shipped defaults.
    #[serde(default)]
    image: Option<String>,
    #[serde(default)]
    tools: Vec<RawTool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTool {
    name: String,
    command: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    credentials: Vec<String>,
    /// `None` (omitted) is **not** the same as `Some(vec![])`: omitted defaults
    /// by name (`["*"]` for `shell`, `[]` otherwise), while an explicit
    /// `tools = []` always means "no other tools" — including for `shell`.
    /// No `#[serde(default)]`: serde already treats an `Option` field as
    /// optional, and the attribute would read as load-bearing.
    tools: Option<Vec<String>>,
    #[serde(default)]
    persist: Vec<String>,
    #[serde(default)]
    interactive_shell: bool,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    network_requests: Vec<String>,
}

/// Validate the raw `[[tools]]` entries into a catalog, rejecting duplicate
/// names and reporting the exact field that failed. Sequentially applying
/// focused validators keeps each diagnosis specific instead of collapsing the
/// whole entry into one generic parse error.
fn validate_tools(raw: Vec<RawTool>, origin: ToolOrigin) -> Result<Vec<Tool>> {
    let mut tools = Vec::with_capacity(raw.len());
    let mut first_index: HashMap<String, usize> = HashMap::new();
    for (index, tool) in raw.into_iter().enumerate() {
        let name = validate_name(&tool.name, &origin, index)?;
        if let Some(&first) = first_index.get(name.as_str()) {
            return Err(declaration_error(
                &origin,
                index,
                Some(name.as_str()),
                format!(
                    "duplicate tool name; already declared at declaration [{first}]. Tool names must be unique within a config file"
                ),
            ));
        }
        first_index.insert(name.as_str().to_string(), index);

        let command = validate_command(&tool.command, &origin, index, &name)?;
        let argv = validate_argv(tool.args, &origin, index, &name)?;
        let (credentials, credential_names) =
            validate_credentials(tool.credentials, &origin, index, &name)?;
        let tools_field = validate_tool_refs(tool.tools, &origin, index, &name)?;
        let persist = validate_persist(tool.persist, &origin, index, &name)?;
        let env = validate_env(tool.env, &origin, index, &name)?;
        let network_requests = NetworkRequests::parse(&tool.network_requests)
            .map_err(|error| tool_error(&origin, index, &name, error))?;

        tools.push(Tool {
            name,
            command,
            argv,
            credentials,
            credential_names,
            tools: tools_field,
            persist,
            interactive_shell: tool.interactive_shell,
            env,
            network_requests,
            origin: origin.clone(),
            declaration_index: index,
        });
    }
    Ok(tools)
}

fn validate_name(raw: &str, origin: &ToolOrigin, index: usize) -> Result<ToolName> {
    if raw.is_empty() {
        return Err(declaration_error(
            origin,
            index,
            None,
            "name must not be empty",
        ));
    }
    if raw
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(declaration_error(
            origin,
            index,
            Some(raw),
            "name must not contain whitespace or control characters",
        ));
    }
    if raw.starts_with('-') {
        return Err(declaration_error(
            origin,
            index,
            Some(raw),
            "name must not start with '-'",
        ));
    }
    if raw.contains('/') {
        return Err(declaration_error(
            origin,
            index,
            Some(raw),
            "name must be a single command-name token, not a path",
        ));
    }
    if raw.chars().all(|character| character == '.') {
        return Err(declaration_error(
            origin,
            index,
            Some(raw),
            "name must not be `.` or `..`",
        ));
    }
    if raw == ALL_TOOLS_WILDCARD {
        return Err(declaration_error(
            origin,
            index,
            Some(raw),
            "name `*` is reserved: it is the wildcard in a tool's `tools` list",
        ));
    }
    // `run` is reserved for the direct runner, and a generic "reserved"
    // message would leave the user with no migration path (issue #398). This
    // precedes the set check so the rename advice is specific.
    if raw == crate::launch_target::DIRECT_RUN_VERB {
        return Err(declaration_error(
            origin,
            index,
            Some(raw),
            "name `run` is reserved: `agent-vm run PROGRAM [ARG...]` runs a guest \
             program directly. Rename this tool (for example `run-tool`) and launch \
             it by the new name.",
        ));
    }
    if RESERVED_TOOL_NAMES.contains(&raw) {
        return Err(declaration_error(
            origin,
            index,
            Some(raw),
            "name is reserved for an agent-vm subcommand; choose another name",
        ));
    }
    Ok(ToolName(raw.to_string()))
}

fn validate_command(
    raw: &str,
    origin: &ToolOrigin,
    index: usize,
    name: &ToolName,
) -> Result<String> {
    if raw.is_empty() {
        return Err(tool_error(origin, index, name, "command must not be empty"));
    }
    if raw.contains('\0') {
        return Err(tool_error(
            origin,
            index,
            name,
            "command must not contain NUL",
        ));
    }
    Ok(raw.to_string())
}

fn validate_argv(
    raw: Vec<String>,
    origin: &ToolOrigin,
    index: usize,
    name: &ToolName,
) -> Result<Vec<String>> {
    for (position, argument) in raw.iter().enumerate() {
        if argument.contains('\0') {
            // Index and remedy only: never echo the argument's value.
            return Err(tool_error(
                origin,
                index,
                name,
                format!("args[{position}] must not contain NUL"),
            ));
        }
    }
    Ok(raw)
}

/// Validate `credentials = [...]` into (built-in providers, every declared
/// name).
///
/// #161 widened what a name may be: it is accepted if it is a valid
/// [`ServiceName`], which is the same rule the keychain uses, so a name can no
/// longer be rejected at config time merely because no compiled-in provider
/// claims it. Resolution (built-in vs. `credentials.yaml`, and #162's
/// precedence between them) is a launch decision, deliberately not a parse one.
fn validate_credentials(
    raw: Vec<String>,
    origin: &ToolOrigin,
    index: usize,
    name: &ToolName,
) -> Result<(Vec<CredentialProvider>, Vec<ServiceName>)> {
    let mut providers = Vec::new();
    let mut names: Vec<ServiceName> = Vec::new();
    for provider_name in raw {
        let service = ServiceName::parse(&provider_name).map_err(|error| {
            tool_error(
                origin,
                index,
                name,
                // The supplied name is deliberately NOT echoed: this is a
                // name slot and a realistic mistake is pasting the key into
                // it (`ServiceName`'s own rule is careful for the same
                // reason). The tool name and declaration index identify the
                // entry.
                format!(
                    "credentials: an entry is not a valid name: {error:#}. A name must be 1-64 \
                     characters from [a-zA-Z0-9._-] starting with a letter or digit (letters are \
                     folded to lowercase), or one of the built-in providers: {}",
                    supported_provider_names()
                ),
            )
        })?;
        if let Some(provider) = CredentialProvider::from_config_name(service.as_str()) {
            providers.push(provider);
        }
        if !names.contains(&service) {
            names.push(service);
        }
    }
    Ok((providers, names))
}

/// Validate one tool's `tools` declaration *within its tier*. Name binding is
/// deliberately **not** here: it is a catalog fact, resolved by
/// [`resolve_provisioning`], so that a reference error can be a deferred catalog
/// error (a readable `image` survives it) rather than a load failure.
fn validate_tool_refs(
    raw: Option<Vec<String>>,
    origin: &ToolOrigin,
    index: usize,
    name: &ToolName,
) -> Result<DeclaredTools> {
    let Some(raw) = raw else {
        return Ok(if name.as_str() == SHELL_TOOL_NAME {
            DeclaredTools::All
        } else {
            DeclaredTools::Named(Vec::new())
        });
    };
    if raw.iter().any(|entry| entry == ALL_TOOLS_WILDCARD) {
        if raw.len() != 1 {
            return Err(tool_error(
                origin,
                index,
                name,
                "tools: `*` must be the only entry; it already means every tool \
                 declared in this configuration file",
            ));
        }
        return Ok(DeclaredTools::All);
    }
    let mut names = Vec::with_capacity(raw.len());
    for (position, entry) in raw.into_iter().enumerate() {
        if entry.is_empty() {
            return Err(tool_error(
                origin,
                index,
                name,
                format!("tools[{position}]: must not be empty"),
            ));
        }
        if entry.contains('\0') {
            return Err(tool_error(
                origin,
                index,
                name,
                format!("tools[{position}]: must not contain NUL"),
            ));
        }
        names.push(ToolName(entry));
    }
    Ok(DeclaredTools::Named(names))
}

verus! {

/// The one byte a path uses to separate components — host and guest alike.
/// Named for the path, not the guest, because the two contracts below now
/// serve both domains: [`byte_paths_overlap`] decides guest-path overlap, and
/// [`byte_path_contains`] decides host-path containment for the protected
/// Pi files (ADR-0020). Declared inside the `verus!` block because Verus cannot
/// read a `const` declared outside it (see `defaults.rs`).
pub const PATH_SEPARATOR: u8 = b'/';

/// `p` is a whole **component-wise** prefix of `q`: `q` begins with `p` followed
/// by the separator, so `a/b` is one of `a/b/c` but `a/b` is *not* one of
/// `a/bc`. Byte-level so the decision is translatable; the `Path` → bytes
/// measurement is the trusted adapter ([`guest_paths_overlap`]).
pub open spec fn is_separator_prefix(p: Seq<u8>, q: Seq<u8>) -> bool {
    p.len() < q.len()
        && q.subrange(0, p.len() as int) =~= p
        && q[p.len() as int] == PATH_SEPARATOR
}

/// The **directional** kernel: `a` is `b` itself, or a whole component-wise
/// prefix of it — `a/b` is one of `a/b/c`, but `a/b` is *not* one of `a/bc`.
/// Byte-level so the decision is translatable; the `Path` → bytes measurement
/// is the trusted adapter (`guest_paths_overlap` here, and
/// `protected_host_files`'s `matches` for host paths).
///
/// Two contracts share this body: [`byte_paths_overlap`] is its symmetric
/// wrapper (ADR-0018), and it *is* the containment half of ADR-0020's exposure
/// decision. One loop, one `ensures`, two callers.
pub fn byte_path_contains(a: &[u8], b: &[u8]) -> (result: bool)
    ensures
        result == (a@ =~= b@ || is_separator_prefix(a@, b@)),
{
    let alen = a.len();
    let blen = b.len();
    assert(alen == a@.len());
    assert(blen == b@.len());
    // A longer "ancestor" is never a prefix of its descendant.
    if alen > blen {
        assert(a@ != b@);
        assert(!is_separator_prefix(a@, b@));
        return false;
    }
    let mut i: usize = 0;
    while i < alen
        invariant
            i <= alen,
            alen <= blen,
            alen == a@.len(),
            blen == b@.len(),
            forall|j: int| 0 <= j < i ==> a@[j] == b@[j],
        decreases alen - i,
    {
        if a[i] != b[i] {
            assert(a@ != b@);
            assert(!is_separator_prefix(a@, b@));
            return false;
        }
        i += 1;
    }
    if alen == blen {
        assert(a@ =~= b@);
        true
    } else {
        assert(forall|j: int| 0 <= j < alen ==> a@[j] == b@[j]);
        b[alen] == PATH_SEPARATOR
    }
}

/// Two `/`-joined relative guest paths overlap iff they are equal or one is a
/// component-wise ancestor of the other — the symmetric wrapper around
/// [`byte_path_contains`]. This is the single predicate behind four call sites
/// (within-tool, across-tool, against the compiled-in link list, and against
/// the launch's guest mount points) — see ADR-0018.
pub fn byte_paths_overlap(a: &[u8], b: &[u8]) -> (result: bool)
    ensures result == (a@ =~= b@
        || is_separator_prefix(a@, b@)
        || is_separator_prefix(b@, a@)),
{
    byte_path_contains(a, b) || byte_path_contains(b, a)
}

/// The two already-measured facts [`same_reference_scope`] decides on: the two
/// definitions come from the same **tool config tier** and name the same
/// declaring file. Named fields rather than adjacent `bool` parameters, so an
/// argument swap cannot make a cross-tier reference look local.
pub(crate) struct ReferenceScopeFacts {
    pub(crate) same_tier: bool,
    pub(crate) same_file: bool,
}

/// The tool-reference locality decision (#395), contracted (ADR-0018): a
/// reference is in scope **iff** the candidate is in the declaring tool's tier
/// *and* in its declaring file. Total over all four Boolean combinations; in
/// scope never happens when either measured fact fails.
///
/// This proves the conjunction only. What actually keeps a reference tier-local
/// is that the index is keyed by the exact `(origin, name)` pair and that the
/// closure walk folds one visited mask; the measurement above, the index, the
/// traversal and the fold are behaviour-tested trusted adapters.
pub(crate) fn reference_scope_matches(facts: ReferenceScopeFacts) -> (matches: bool)
    ensures
        matches == (facts.same_tier && facts.same_file),
        matches ==> facts.same_tier && facts.same_file,
{
    facts.same_tier && facts.same_file
}

} // verus!

/// `true` when linking both `a` and `b` into the guest HOME would make one
/// shadow the other. Both must be normalized relative paths (`PersistPath`'s
/// invariant, or a compiled-in `HomeLink::home_relative`).
///
/// The trusted half of [`byte_paths_overlap`]: `OsStr::as_bytes`, plus the
/// *invariant* that a normalized persist path's `Path` rendering is its
/// components joined by single `/` (established by [`normalize_persist`], not
/// proved). Recorded in ADR-0018's trusted-boundary list.
pub(crate) fn guest_paths_overlap(a: &Path, b: &Path) -> bool {
    byte_paths_overlap(a.as_os_str().as_bytes(), b.as_os_str().as_bytes())
}

fn validate_persist(
    raw: Vec<String>,
    origin: &ToolOrigin,
    index: usize,
    name: &ToolName,
) -> Result<Vec<PersistPath>> {
    let mut persist: Vec<PersistPath> = Vec::with_capacity(raw.len());
    for (position, declaration) in raw.into_iter().enumerate() {
        let normalized = normalize_persist(&declaration).map_err(|reason| {
            tool_error(
                origin,
                index,
                name,
                format!("persist[{position}]: {reason}"),
            )
        })?;
        // O(n²) over a handful of declared paths, deliberately: the predicate is
        // overlap, not equality, so a `HashSet` cannot answer it. Two distinct
        // normalized spellings of the same path are impossible
        // (`normalize_persist`), so `==` identifies the exact-duplicate case and
        // keeps today's message byte-for-byte.
        for existing in &persist {
            if !guest_paths_overlap(existing.as_path(), &normalized) {
                continue;
            }
            if existing.as_path() == normalized.as_path() {
                return Err(tool_error(
                    origin,
                    index,
                    name,
                    format!(
                        "persist[{position}]: duplicate declaration; this tool already claims the normalized path"
                    ),
                ));
            }
            return Err(tool_error(
                origin,
                index,
                name,
                format!(
                    "persist[{position}]: overlaps this tool's persist path {}; one would shadow the other",
                    quoted_path(existing.as_path())
                ),
            ));
        }
        // The compiled-in link list is derived from `guest_home_links()`, never
        // a hand-copied list, so a provider added later is covered
        // automatically. A `persist` entry that is an ancestor *or* descendant
        // of a reserved path would silently shadow a credential dir or be
        // shadowed by it.
        for link in crate::credential_provider::guest_home_links() {
            if guest_paths_overlap(&normalized, Path::new(link.home_relative)) {
                return Err(tool_error(
                    origin,
                    index,
                    name,
                    format!(
                        "persist[{position}]: {} overlaps the reserved guest HOME path {}, which agent-vm links to the project state dir",
                        quoted_path(&normalized),
                        link.home_relative
                    ),
                ));
            }
        }
        persist.push(PersistPath(normalized));
    }
    Ok(persist)
}

/// Validate guest **Unix** path components before normalization. Returns a
/// relative path of normal components, or a static reason (never the value).
fn normalize_persist(declaration: &str) -> std::result::Result<PathBuf, &'static str> {
    if declaration.is_empty() {
        return Err("must not be empty");
    }
    if declaration.contains('\0') {
        return Err("must not contain NUL");
    }
    if declaration.starts_with('/') {
        return Err("must be relative to the guest HOME, not absolute");
    }

    let mut normalized = PathBuf::new();
    let mut has_component = false;
    for component in declaration.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                return Err("must not contain a `..` component, even one that could cancel out");
            }
            normal => {
                normalized.push(normal);
                has_component = true;
            }
        }
    }
    if !has_component {
        return Err("must name a path below the guest HOME, not HOME itself");
    }
    Ok(normalized)
}

/// Validate guest env declarations. `BTreeMap` iteration is key-sorted, which
/// is both the order the pairs are published in and the order definition
/// equality compares — so two configs that differ only in declaration order
/// are the same tool.
fn validate_env(
    raw: BTreeMap<String, String>,
    origin: &ToolOrigin,
    index: usize,
    name: &ToolName,
) -> Result<BTreeMap<String, String>> {
    for (key, value) in &raw {
        if let Err(reason) = check_env_key(key) {
            return Err(tool_error(
                origin,
                index,
                name,
                format!("env key {}: {reason}", quoted_str(key)),
            ));
        }
        // Key only, never the value: a user may have mistaken this for a
        // place to put a credential (same rule as `args`).
        if value.contains('\0') {
            return Err(tool_error(
                origin,
                index,
                name,
                format!("env {}: value must not contain NUL", quoted_str(key)),
            ));
        }
    }
    Ok(raw)
}

/// An env entry crosses `execve` as a NUL-terminated `KEY=VALUE` string, so a
/// key carrying `=` or NUL would re-split or truncate somewhere downstream
/// instead of failing. Whitespace/control keys are unreachable from any shell
/// and are almost certainly a typo. Returns a static reason, never the value.
fn check_env_key(key: &str) -> std::result::Result<(), &'static str> {
    if key.is_empty() {
        return Err("must not be empty");
    }
    if key.contains('=') {
        return Err("must not contain '='");
    }
    if key.contains('\0') {
        return Err("must not contain NUL");
    }
    if key
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err("must not contain whitespace or control characters");
    }
    // Rejected here, not for safety, but for the *diagnostic*: the vendored SDK
    // rejects this prefix too (`SandboxBuilder::env`,
    // vendor/microsandbox/sdk/rust/lib/sandbox/builder.rs:917-924, re-checked at
    // build() by validate_env, .../sandbox/mod.rs:1565-1574) — but it surfaces
    // as a late `preparing sandbox config: …` with no file and no declaration
    // index. One vendored prefix with one owner is not a deny-list (D3d).
    if key.starts_with("MSB_") {
        return Err("must not use the reserved MSB_ prefix (microsandbox owns it)");
    }
    // The guest identity triple, and only it. The launcher owns all three
    // names in both modes and publishes the triple after the tool map
    // (`user::guest_identity_env` in default mode, `user::root_identity_env`
    // under `--root`), so a declaration here could only be silently inert.
    // Validation cannot be mode-aware (this module knows nothing about
    // launch), so the rejection is unconditional. D3c.
    if matches!(key, "HOME" | "USER" | "LOGNAME") {
        return Err(
            "must not be declared by a tool (agent-vm owns the guest identity environment)",
        );
    }
    Ok(())
}

fn supported_provider_names() -> String {
    CredentialProvider::ALL
        .into_iter()
        .map(|provider| provider.config_name())
        .collect::<Vec<_>>()
        .join(", ")
}

// ---------------------------------------------------------------------------
// Diagnostics: value-safe and control-byte-safe
// ---------------------------------------------------------------------------

/// A validation error that names the tier, file and declaration, never a value.
fn declaration_error(
    origin: &ToolOrigin,
    index: usize,
    name: Option<&str>,
    detail: impl fmt::Display,
) -> anyhow::Error {
    let label = match name {
        Some(name) => format!("tool {}", quoted_str(name)),
        None => "tool".to_string(),
    };
    anyhow!(
        "config: {} declaration [{index}] {label}: {detail}",
        describe_origin(origin)
    )
}

fn tool_error(
    origin: &ToolOrigin,
    index: usize,
    name: &ToolName,
    detail: impl fmt::Display,
) -> anyhow::Error {
    declaration_error(origin, index, Some(name.as_str()), detail)
}

/// **R1.** The TOML/serde error text is untrusted (a wrong-type message can
/// echo an argument secret), so the entire dependency message is replaced by
/// a fixed schema-repair message plus a numeric span location. The original
/// error is not retained as a source.
fn deserialize_error(file: &Path, text: &str, error: &toml::de::Error) -> anyhow::Error {
    let location = match error.span() {
        Some(span) => {
            let (line, column) = line_column(text, span.start);
            format!(":{line}:{column}")
        }
        None => String::new(),
    };
    anyhow!(
        "config: {}{location}: invalid TOML or tool schema; check syntax and field types. \
         Required: a string `name` and `command`; `args`, `credentials`, `tools`, `persist` and `network_requests` are \
         arrays of strings; `env` is a table of string values; the top-level `image` and each \
         tool's `command` are strings. A top-level `mounts` is an array of strings and is accepted \
         only at the top of the user file; TOML assigns keys to the most recent `[table]` header, \
         so write it before the first one.",
        crate::one_line::quoted_path(file)
    )
}

fn utf8_error(file: &Path) -> anyhow::Error {
    anyhow!(
        "config: {} is not valid UTF-8; config files must be UTF-8-encoded TOML",
        crate::one_line::quoted_path(file)
    )
}

/// **R2.** Reused-reader errors interpolate a raw `path.display()` and may
/// carry a whole cause chain. Escape every link and return a fresh error with
/// no original attached, preserving the operation and the reasons.
///
/// The links are *measured* text — `host_paths` builds them from a path the user
/// named — so they take the one-line policy, not [`escape_bytes`]: control
/// characters are escaped, which is what keeps a cause from forging a line, while
/// a non-ASCII directory stays readable. Byte-escaping them spelled the same
/// `$HOME` two ways in one sentence, the outer copy quoted and the cause not.
fn safe_anyhow_error(operation: &str, path: &Path, error: &anyhow::Error) -> anyhow::Error {
    let reasons = error
        .chain()
        .map(|cause| crate::one_line::text(&cause.to_string()).to_string())
        .collect::<Vec<_>>()
        .join(": ");
    anyhow!(
        "config: {operation} {}: {reasons}",
        crate::one_line::quoted_path(path)
    )
}

/// The same boundary for direct `std::io::Error`s (HOME/cwd discovery).
fn safe_io_error(operation: &str, path: &Path, error: &std::io::Error) -> anyhow::Error {
    anyhow!(
        "config: {operation} {}: {}",
        crate::one_line::quoted_path(path),
        crate::one_line::text(&error.to_string())
    )
}

fn line_column(text: &str, offset: usize) -> (usize, usize) {
    let clamped = offset.min(text.len());
    let mut line = 1;
    let mut column = 1;
    for (index, character) in text.char_indices() {
        if index >= clamped {
            break;
        }
        if character == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    (line, column)
}

/// Render untrusted bytes (path components, reason text) so no terminal
/// control byte can reach the screen: printable ASCII passes through,
/// backslash is doubled for reverse-readability, and every other byte —
/// including DEL, invalid UTF-8, newline, and ESC — becomes `\xNN`.
fn escape_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &byte in bytes {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            0x20..=0x7e => out.push(byte as char),
            _ => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\x{byte:02x}");
            }
        }
    }
    out
}

/// Render a **config-chosen** path double-quoted with [`escape_bytes`]'s
/// byte-escaping: every non-ASCII byte becomes `\xNN`, and `\` and `"` are
/// doubled. `mount` renders a declaration's origin through this rather than
/// `{:?}`, so one launch cannot show two escapings of the same config entry.
///
/// A **measured** path — a config file's own location, `$HOME`, a reader's cause
/// text — uses [`crate::one_line::quoted_path`] instead: same quoting, but
/// non-ASCII prints as itself, because the reader has to recognise the directory
/// they named. The two are not interchangeable: the byte policy is for text a
/// config file *chose* and a report may compare, and every path the reports and
/// runtime messages converted so far render through [`crate::one_line`] (issues
/// #410, #414, #419, #420, #422). Not the whole crate: `clipboard`,
/// `embedded_runtime`, `msb_install` and others still interpolate
/// `Path::display()` into their own error contexts, and the ratchet in
/// [`crate::one_line`] records how many each module has left.
///
/// Two kinds of caller straddle the line on purpose. `mount::claim_clause` quotes
/// both sides of a config-origin claim conflict through this function, so an argv
/// or follow-links-discovered spelling gets the byte policy when it shares a
/// sentence with a config entry; the sentence only exists in mixed or config form,
/// and a conflict must not read as two different paths. And every
/// `mount::Declaration` sentence that *attributes* an entry (`host_path`,
/// `fork_root`, `node_kind`, `validating_source_context`, `fork_root_context`)
/// byte-escapes the path it names, so that one sentence never carries two
/// renderings of a path and an attributed entry cannot read as two entries. There
/// the path may be the entry's own text (a declared spelling) or something the
/// declaration was resolved to (a canonicalized target); both keep the byte
/// policy. A sentence that reports an operation on a file (`unable to stat …`,
/// `creating …`) is not a declaration rendering and takes [`crate::one_line`]
/// instead.
pub(crate) fn quoted_path(path: &Path) -> String {
    format!("\"{}\"", escape_bytes(path.as_os_str().as_bytes()))
}

/// Wrap a value in double quotes with the same control-byte escaping as
/// [`quoted_path`]. Exposed so `doctor`'s config warnings quote tool names
/// exactly the way config's own diagnostics do.
pub(crate) fn quoted_str(text: &str) -> String {
    format!("\"{}\"", escape_bytes(text.as_bytes()))
}

/// Escape every non-ASCII byte as `\xNN`: the policy for **config-chosen text** —
/// tool names, commands, image references — where two values that differ only
/// outside ASCII must not look identical in one report.
///
/// [`crate::one_line`] is the other policy — control characters only — and it is
/// the one the modules [`crate::one_line`] lists use for every path they print,
/// because a path a user has to read back and perhaps copy
/// (`/home/boger/проект`) must print as itself. The two are not interchangeable: what stays here is text a config file
/// chose and a report may compare, which is [`quoted_str`] and [`quoted_path`]'s
/// job for the quoted forms, plus the *declaration* sentences [`quoted_path`]
/// documents. `doctor`'s module doc lists the channels that print validated names
/// raw instead.
pub(crate) fn escape_str(text: &str) -> String {
    escape_bytes(text.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::collections::HashSet;
    use std::fs;

    #[test]
    fn network_table_is_refused_in_the_project_tier_naming_setting_and_tier() {
        let f = Fixture::new();
        f.project("[network]\nallow_lan = true\nallow_egress = [\"10.0.0.0/8\"]");
        let message = f.load().unwrap_err().to_string();
        for expected in [
            crate::one_line::quoted_path(&f.project).to_string(),
            "network.allow_lan".into(),
            "network.allow_egress".into(),
            "project config".into(),
            "; use --allow-* launch flags, or [network] in the user config".into(),
        ] {
            assert!(message.contains(&expected), "{message}");
        }
    }

    #[test]
    fn user_network_table_is_parsed_and_reported() {
        let f = Fixture::new();
        f.user("[network]\nallow_lan = true\nallow_egress = [\"10.0.0.0/8\"]");
        let report = f.load().unwrap();
        assert_eq!(
            report.user_network(),
            Some(&UserNetwork::for_test(
                &f.user,
                user_network::SavedGroups {
                    lan: Some(true),
                    ..Default::default()
                },
                &["10.0.0.0/8"]
            ))
        );
        assert_eq!(report.user_network().unwrap().file(), f.user);
    }

    #[test]
    fn network_refusal_never_echoes_values_or_unknown_keys() {
        for user in [false, true] {
            let f = Fixture::new();
            let text = "[network]\nsk_live_abc = \"hunter2\"\nother = \"10.9.8.7\"";
            if user {
                f.user(text);
            } else {
                f.project(text);
            }
            let message = f.load().unwrap_err().to_string();
            assert!(message.contains("[network]"));
            for secret in ["sk_live_abc", "hunter2", "10.9.8.7", "other"] {
                assert!(!message.contains(secret));
            }
        }
    }

    #[test]
    fn empty_network_table_is_still_refused() {
        let f = Fixture::new();
        f.project("[network]");
        assert!(f.load().unwrap_err().to_string().contains("[network]"));
    }

    #[test]
    fn shipped_defaults_declare_no_network_table() {
        let raw: RawConfig = toml::from_str(DEFAULT_TOOLS_TOML).unwrap();
        assert!(raw.network.is_none());
        assert!(default_tools().is_ok());
    }

    #[test]
    fn builtin_network_table_is_refused_naming_setting_and_tier() {
        for text in [
            "[network]\n",
            "[network]\nallow_lan = true\nallow_egress = [\"sk-live-SENTINEL-305\"]\n",
        ] {
            let message = tools_from_builtin_text(text).unwrap_err().to_string();
            assert!(message.contains("default-tools.toml"));
            assert!(message.contains("network access cannot be granted by the built-in config"));
            assert!(!message.contains("sk-live-SENTINEL-305"));
            if text.contains("allow_lan") {
                assert!(message.contains("network.allow_lan, network.allow_egress"));
            } else {
                assert!(message.contains("[network]"));
            }
        }
        assert_eq!(
            tools_from_builtin_text(DEFAULT_TOOLS_TOML).unwrap(),
            default_tools().unwrap()
        );
    }

    #[test]
    fn empty_user_network_table_is_verified_and_grants_nothing() {
        use std::os::unix::fs::PermissionsExt;
        let f = Fixture::new();
        f.user("[network]\n");
        assert_eq!(
            f.load().unwrap().user_network(),
            Some(&UserNetwork::for_test(&f.user, Default::default(), &[]))
        );
        fs::set_permissions(&f.user, fs::Permissions::from_mode(0o664)).unwrap();
        assert!(
            f.load()
                .unwrap_err()
                .to_string()
                .contains("group- or other-writable")
        );
    }

    #[test]
    fn symlinked_user_config_without_network_still_loads() {
        let f = Fixture::new();
        let target = f.user.with_file_name("dotfile");
        write_file(&target, &one_tool("custom"));
        std::os::unix::fs::symlink(&target, &f.user).unwrap();
        assert!(f.load().is_ok());
        write_file(&target, "[network]\n");
        assert!(
            f.load()
                .unwrap_err()
                .to_string()
                .contains("reached through a symbolic link")
        );
    }

    #[test]
    fn symlinked_user_config_with_network_is_refused() {
        let f = Fixture::new();
        let target = f.user.with_file_name("dotfile");
        write_file(&target, "[network]\nallow_host = true\n");
        std::os::unix::fs::symlink(&target, &f.user).unwrap();
        assert!(
            f.load()
                .unwrap_err()
                .to_string()
                .contains("reached through a symbolic link")
        );
    }

    #[test]
    fn user_network_in_a_tools_only_file_does_not_change_the_catalog() {
        let f = Fixture::new();
        f.user(&one_tool("custom"));
        let before_report = f.load().unwrap();
        let before: Vec<_> = before_report
            .resolved()
            .launch_tools()
            .map(tool_summary)
            .collect();
        f.user(&format!(
            "{}\n[network]\nallow_lan = true\n",
            one_tool("custom")
        ));
        let after_report = f.load().unwrap();
        let after: Vec<_> = after_report
            .resolved()
            .launch_tools()
            .map(tool_summary)
            .collect();
        assert_eq!(after, before);
    }

    // -- user mounts (#394 / ADR-0046) -------------------------------------

    /// A mount-bearing file is authority-bearing even when the list is empty:
    /// presence, not contents, is what makes it so. The positive control (the
    /// same symlink without the key) is what proves the refusal is about the
    /// key rather than about symlinks.
    #[test]
    fn present_empty_mounts_through_a_symlink_is_refused() {
        let f = Fixture::new();
        f.symlinked_user("mounts = []\n");
        let error = f.load().unwrap_err().to_string();
        assert!(
            error.contains("mounts requires config.toml to be a regular file"),
            "{error}"
        );
        assert!(error.contains("review the mounts list"), "{error}");
        assert!(!error.contains("[network]"), "{error}");

        let f = Fixture::new();
        f.symlinked_user("");
        let report = f.load().unwrap();
        assert!(report.user_mounts().is_none());
        // The same file, once it declares `mounts`, is refused.
        write_file(&f.user.with_file_name("dotfile"), "mounts = []\n");
        assert!(
            f.load()
                .unwrap_err()
                .to_string()
                .contains("mounts requires config.toml to be a regular file")
        );
    }

    /// Omitted and present-empty are different facts, and both are readable
    /// before the report is consumed.
    #[test]
    fn omitted_mounts_are_none_and_present_empty_selects_nothing() {
        let f = Fixture::new();
        let report = f.user(&one_tool("custom")).load().unwrap();
        assert!(report.user_mounts().is_none());
        assert!(!report.uses_defaults());

        let report = f
            .user(&format!("mounts = []\n{}", one_tool("custom")))
            .load()
            .unwrap();
        let mounts = report.user_mounts().expect("present-empty is present");
        assert_eq!(mounts.len(), 0);
        assert_eq!(mounts.file(), f.user.as_path());
        assert!(mounts.requests().is_empty());
        // A mounts-only file declares no tools, so the shipped defaults stand.
        let report = f.user("mounts = [\"/a\"]\n").load().unwrap();
        assert!(report.uses_defaults());
        assert_eq!(report.user_mounts().map(UserMounts::len), Some(1));
    }

    /// `[network]` diagnostics keep their pre-#394 bytes; the subject only
    /// changes when `mounts` is the field that made the file authority-bearing.
    #[test]
    fn refusal_subject_names_exactly_the_declared_fields() {
        for (body, label, object, without) in [
            (
                "[network]\n",
                "[network]",
                "review the [network] table",
                "without [network] still",
            ),
            (
                "mounts = []\n",
                "mounts",
                "review the mounts list",
                "without mounts still",
            ),
            (
                "mounts = []\n[network]\n",
                "[network] and mounts",
                "review the [network] table and mounts list",
                "without [network] or mounts still",
            ),
        ] {
            let f = Fixture::new();
            f.symlinked_user(body);
            let error = f.load().unwrap_err().to_string();
            assert!(
                error.contains(&format!(
                    ": {label} requires config.toml to be a regular file"
                )),
                "{label}: {error}"
            );
            assert!(error.contains(object), "{label}: {error}");
            assert!(error.contains(without), "{label}: {error}");
        }
    }

    /// A project file may not grant mounts, empty or not, and `[network]` is
    /// still the field named when the file declares both.
    #[test]
    fn project_mounts_are_refused_even_when_empty() {
        for body in ["mounts = []\n", "mounts = [\"/a\"]\n", "mounts = \"x\"\n"] {
            let f = Fixture::new();
            f.project(body);
            let error = f.load().unwrap_err().to_string();
            assert!(
                error.contains(&format!(
                    "config: {:?}: mounts cannot be declared by the project config; use \
                     --mount launch options, or mounts in the user config",
                    f.project
                )),
                "{body}: {error}"
            );
        }
        let f = Fixture::new();
        f.project("mounts = []\n[network]\nallow_host = true\n");
        let error = f.load().unwrap_err().to_string();
        assert!(
            error.contains("network access cannot be granted by the project config"),
            "{error}"
        );
        assert!(!error.contains("mounts cannot be declared"), "{error}");
    }

    /// The built-in catalog cannot declare mounts either, and `[network]` still
    /// wins on a body that declares both.
    #[test]
    fn builtin_mounts_are_refused() {
        for body in ["mounts = []\n", "mounts = [\"/a\"]\n", "[mounts]\n"] {
            let error = tools_from_builtin_text(body).unwrap_err().to_string();
            assert!(
                error.contains(
                    "config: \"default-tools.toml\": mounts cannot be declared by the \
                     built-in config; use --mount launch options, or mounts in the user config"
                ),
                "{body}: {error}"
            );
        }
        let error =
            tools_from_builtin_text("mounts = []\n[network]\nallow_host = true\n").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("network access cannot be granted by the built-in config")
        );
    }

    /// A `mounts`-only user file keeps the seven shipped tools (and `shell`),
    /// because declaring no tool is not the same as declaring an empty list.
    #[test]
    fn a_mounts_only_user_config_keeps_the_defaults() {
        let f = Fixture::new();
        let report = f.user("mounts = [\"/a\"]\n").load().unwrap();
        assert!(report.uses_defaults());
        let names: Vec<String> = report
            .into_launch_catalog()
            .unwrap()
            .as_slice()
            .iter()
            .map(|entry| entry.tool.name().to_string())
            .collect();
        let shipped: Vec<String> = default_launch_catalog()
            .unwrap()
            .as_slice()
            .iter()
            .map(|entry| entry.tool.name().to_string())
            .collect();
        assert_eq!(names, shipped);
        assert_eq!(names.len(), 7, "the seven shipped tools, `shell` included");
    }

    /// `~/` expands against [`ConfigPaths::home`] and nothing else: not the
    /// process `HOME`, and never the config file's parent directory.
    #[test]
    fn user_mount_home_comes_from_config_paths() {
        let root = tempfile::tempdir().unwrap();
        let user = root.path().join("cfg/config.toml");
        write_file(&user, "mounts = [\"~/ref\", \"/abs/ref\"]\n");
        let project = root.path().join("absent.toml");
        let with_home = |home: Option<PathBuf>| ConfigPaths {
            user: Some(user.clone()),
            project: project.clone(),
            home,
        };

        // `/h/` keeps its trailing slash (`//`), and the process `HOME` is not
        // involved: it is the real home, not `/h/`.
        let report = load(&with_home(Some(PathBuf::from("/h/")))).unwrap();
        let spellings: Vec<crate::mount::Spelling> = report
            .user_mounts()
            .unwrap()
            .requests()
            .iter()
            .map(|request| request.mount.source_spelling.clone())
            .collect();
        assert_eq!(spellings, ["/h//ref", "/abs/ref"]);
        assert_ne!(std::env::var("HOME").ok(), Some("/h/".to_string()));

        // No captured home: `~/` is refused rather than derived from the user
        // path's parent (`<tmp>/cfg`), and an absolute entry still loads.
        assert_eq!(
            load(&with_home(None)).unwrap_err().to_string(),
            format!(
                "config: {:?}: mounts[0]: a ~/ host path needs a UTF-8 $HOME",
                user
            )
        );
        write_file(&user, "mounts = [\"/abs/ref\"]\n");
        let report = load(&with_home(None)).unwrap();
        assert_eq!(report.user_mounts().map(UserMounts::len), Some(1));

        // A non-UTF-8 home refuses only the `~/` entry.
        use std::os::unix::ffi::OsStrExt;
        write_file(&user, "mounts = [\"~/ref\"]\n");
        let non_utf8 = PathBuf::from(std::ffi::OsStr::from_bytes(b"/h/\xff"));
        assert!(
            load(&with_home(Some(non_utf8)))
                .unwrap_err()
                .to_string()
                .contains("mounts[0]: a ~/ host path needs a UTF-8 $HOME")
        );
    }

    /// A self-contradictory `mounts` list is a *load* error: the claim runs
    /// before any launch state exists, and identical declarations merge.
    #[test]
    fn conflicting_user_mounts_are_a_load_error() {
        let f = Fixture::new();
        f.user("mounts = [\"/a:/g:ro\", \"/b:/g:ro\"]\n");
        let error = f.load().unwrap_err().to_string();
        assert_eq!(
            error,
            format!(
                "config: {:?}: mounts[1]: claims the same guest path as mounts[0] with a \
                 different declaration",
                f.user
            )
        );
        f.user("mounts = [\"/a:/g:ro\", \"/a:/g//./:ro\"]\n");
        assert_eq!(
            f.load().unwrap().user_mounts().map(UserMounts::len),
            Some(1)
        );
    }

    #[test]
    fn user_mount_exclude_on_a_live_bind_is_a_load_error() {
        let f = Fixture::new();
        f.user("mounts = [\"/a:/g:exclude=hidden\"]\n");
        let error = f.load().unwrap_err().to_string();
        assert_eq!(
            error,
            format!(
                "config: {:?}: mounts[0]: :exclude is only supported on :fork mounts",
                f.user
            )
        );
    }

    /// No mount value ever reaches a diagnostic, and every message names the
    /// index and the file.
    #[test]
    fn user_mounts_errors_name_the_index_and_never_echo_values() {
        const SENTINEL: &str = "s3cr3t-SENTINEL-305";
        for body in [
            format!("mounts = [\"{SENTINEL}\"]\n"),
            format!("mounts = [\"{SENTINEL}\", \"/a\"]\n"),
            format!("mounts = [\"/a:{SENTINEL}\"]\n"),
            format!("mounts = [\"/a:/g:{SENTINEL}\"]\n"),
            format!("mounts = [\"/a:/g:exclude={SENTINEL}/../x\"]\n"),
            format!("mounts = [\"/a:/g\", \"{SENTINEL}:/g\"]\n"),
            format!("mounts = [1, \"{SENTINEL}\"]\n"),
            format!("mounts = {{ {SENTINEL} = 1 }}\n"),
        ] {
            let f = Fixture::new();
            f.user(&body);
            let error = f.load().unwrap_err().to_string();
            assert!(!error.contains(SENTINEL), "value echoed: {error}");
            assert!(error.contains("mounts"), "{error}");
            assert!(error.contains(&format!("{:?}", f.user)), "{error}");
        }
        // The index is the entry's position, not a constant.
        let f = Fixture::new();
        f.user("mounts = [\"/a\", \"/b\", 7]\n");
        assert!(
            f.load()
                .unwrap_err()
                .to_string()
                .contains("mounts[2]: must be a string")
        );
    }

    /// Load needs no source: it neither requires a mount source to exist nor to
    /// be reachable, so a config naming a path you have not created still loads
    /// — which is what an opt-out launch must not care about.
    ///
    /// This is the strongest claim a black-box row can support, and no stronger.
    /// A *missing* path alone is a weak probe: it also passes for a loader that
    /// stats sources and ignores the failure. The second row therefore seals the
    /// source's directory with mode `000`, so a `stat` of the source fails
    /// `EACCES` for a non-root user and a loader that *propagates* the error
    /// cannot succeed here; the calibration assertion keeps that from being
    /// vacuous. It still cannot tell "inspected and tolerated" from "not
    /// inspected": `exists()` and `canonicalize().unwrap_or(..)` are inspections
    /// that pass this row too. "Never inspects" is a property of the code, not
    /// something this test measures.
    #[test]
    fn user_mounts_load_needs_no_source_to_exist_or_be_reachable() {
        let f = Fixture::new();
        f.user("mounts = [\"/nonexistent-agent-vm-config-mounts:/g:ro\"]\n");
        let report = f.load().unwrap();
        assert_eq!(report.user_mounts().map(UserMounts::len), Some(1));

        // Root ignores the mode, so the sealed row proves nothing there.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("SKIPPED EACCES: running as root cannot seal a directory");
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let sealed_dir = tempfile::tempdir().unwrap();
        let parent = sealed_dir.path().canonicalize().unwrap().join("sealed");
        std::fs::create_dir(&parent).unwrap();
        let source = parent.join("source");
        std::fs::write(&source, "x").unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o000)).unwrap();
        assert!(
            std::fs::symlink_metadata(&source).is_err(),
            "the sealed directory must deny stat, or this row proves nothing"
        );
        let f = Fixture::new();
        f.user(&format!("mounts = [\"{}:/g:ro\"]\n", source.display()));
        // Load first, restore the mode second: an assertion failure inside
        // `load` must not leave an unreadable directory behind for the tempdir
        // drop (nor hide the failure itself).
        let loaded = f.load();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            loaded.unwrap().user_mounts().map(UserMounts::len),
            Some(1),
            "load must not require the source to be reachable"
        );
    }

    /// `[[tools]]` keeps `deny_unknown_fields`, so a per-tool `mounts` stays a
    /// schema error — value-free, and pointing at TOML's scoping rule.
    #[test]
    fn a_tool_level_mounts_field_is_a_schema_error() {
        for body in [
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\nmounts = []\n",
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\nmounts = [\"s3cr3t-SENTINEL-305\"]\n",
        ] {
            let f = Fixture::new();
            f.user(body);
            let error = f.load().unwrap_err().to_string();
            assert!(error.contains("invalid TOML or tool schema"), "{error}");
            assert!(
                error.contains("so write it before the first one"),
                "{error}"
            );
            assert!(!error.contains("s3cr3t-SENTINEL-305"), "{error}");
        }
    }

    /// TOML assigns keys to the most recent table header, so *where* a `mounts`
    /// key is written decides which construct it lands in. One row per shape.
    #[test]
    fn mounts_toml_scoping_is_characterized() {
        enum Expected {
            /// Loads, and the user tier declared this many claimed mounts.
            Mounts(usize),
            /// Loads with no user `mounts` at all.
            Absent,
            /// Refused, with this text in the message.
            Refused(&'static str),
        }
        for (label, body, expected) in [
            ("top-level", "mounts = []\n", Expected::Mounts(0)),
            (
                "top-level after dotted keys",
                "network.allow_host = false\nmounts = []\n",
                Expected::Mounts(0),
            ),
            (
                "after [network]",
                "[network]\nallow_host = true\nmounts = []\n",
                Expected::Refused(
                    "[network]: mounts is not a network setting; a top-level mounts list must be \
                     written before the first table header",
                ),
            ),
            (
                "after [[tools]]",
                "[[tools]]\nname = \"t\"\ncommand = \"t\"\nmounts = []\n",
                Expected::Refused("invalid TOML or tool schema"),
            ),
            (
                "[tools.env] array",
                "[[tools]]\nname = \"t\"\ncommand = \"t\"\n[tools.env]\nmounts = []\n",
                Expected::Refused("invalid TOML or tool schema"),
            ),
            (
                "table form",
                "[mounts]\npath = \"/a\"\n",
                Expected::Refused("mounts: must be an array of strings"),
            ),
            (
                "[tools.env] string is an ordinary env value",
                "[[tools]]\nname = \"t\"\ncommand = \"t\"\n[tools.env]\nmounts = \"~/private:ro\"\n",
                Expected::Absent,
            ),
        ] {
            let f = Fixture::new();
            f.user(body);
            match (f.load(), expected) {
                (Ok(report), Expected::Mounts(len)) => {
                    assert_eq!(
                        report.user_mounts().map(UserMounts::len),
                        Some(len),
                        "{label}"
                    );
                }
                (Ok(report), Expected::Absent) => {
                    assert!(report.user_mounts().is_none(), "{label}");
                    assert_eq!(report.user_network(), None, "{label}");
                    let tool = first_launch(&report);
                    assert_eq!(
                        tool.guest_env().get("mounts").map(String::as_str),
                        Some("~/private:ro"),
                        "{label}"
                    );
                }
                (Err(error), Expected::Refused(needle)) => assert!(
                    error.to_string().contains(needle),
                    "{label}: {needle} not in {error}"
                ),
                (result, _) => panic!("{label}: unexpected outcome {result:?}"),
            }
        }

        // `[tools.env] mounts` is an ordinary env value, so it triggers no
        // authority policy at all: the same body works through a symlink.
        let f = Fixture::new();
        f.symlinked_user(
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\n[tools.env]\nmounts = \"~/private:ro\"\n",
        );
        assert!(f.load().is_ok());
        // `[mounts]` is top-level and present, so its presence alone triggers
        // the authority check.
        let f = Fixture::new();
        f.symlinked_user("[mounts]\npath = \"/a\"\n");
        assert!(
            f.load()
                .unwrap_err()
                .to_string()
                .contains("mounts requires config.toml to be a regular file")
        );
    }

    // -- fixture helpers ---------------------------------------------------

    fn write_file(path: &Path, contents: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn write_bytes(path: &Path, contents: &[u8]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    /// A user path in its own tempdir plus a project path in another; the
    /// caller writes whichever files it wants.
    struct Fixture {
        _user_dir: tempfile::TempDir,
        _project_dir: tempfile::TempDir,
        user: PathBuf,
        project: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let user_dir = tempfile::tempdir().unwrap();
            let project_dir = tempfile::tempdir().unwrap();
            let user = user_dir.path().join("config.toml");
            let project = project_dir.path().join("config.toml");
            Self {
                _user_dir: user_dir,
                _project_dir: project_dir,
                user,
                project,
            }
        }

        fn paths(&self) -> ConfigPaths {
            ConfigPaths {
                user: Some(self.user.clone()),
                project: self.project.clone(),
                home: None,
            }
        }

        fn load(&self) -> Result<ConfigReport> {
            load(&self.paths())
        }

        /// The user config as a same-directory dotfile symlink — the shape a
        /// guest- or project-authored file is planted through.
        fn symlinked_user(&self, contents: &str) -> &Self {
            let target = self.user.with_file_name("dotfile");
            write_file(&target, contents);
            std::os::unix::fs::symlink(&target, &self.user).unwrap();
            self
        }

        fn user(&self, contents: &str) -> &Self {
            write_file(&self.user, contents);
            self
        }

        fn project(&self, contents: &str) -> &Self {
            write_file(&self.project, contents);
            self
        }
    }

    /// The first launch winner. Hidden definitions are deliberately absent: a
    /// loser of a launch-name conflict stays resolvable from its own file, but it
    /// is never a verb.
    fn first_launch(report: &ConfigReport) -> &Tool {
        report
            .resolved()
            .launch_tools()
            .next()
            .expect("the catalog has a launch winner")
    }

    fn one_tool(name: &str) -> String {
        format!("[[tools]]\nname = \"{name}\"\ncommand = \"{name}\"\ncredentials = [\"openai\"]\n")
    }

    fn tool_summary(tool: &Tool) -> (String, String, usize, Vec<&'static str>, usize) {
        (
            tool.name().to_string(),
            tool.command().to_string(),
            tool.arg_count(),
            tool.credentials()
                .iter()
                .map(|provider| provider.config_name())
                .collect(),
            tool.persist_count(),
        )
    }

    // -- defaults and schema ----------------------------------------------

    #[test]
    fn absent_tiers_yield_the_seven_defaults_in_order() {
        let fixture = Fixture::new();
        let report = fixture.load().unwrap();

        assert!(report.uses_defaults());
        assert!(report.conflicts().is_empty());
        assert_eq!(report.user().status(), &TierStatus::Absent);
        assert!(matches!(
            report.project().status(),
            TierStatus::Found { declared_tools: 0 } | TierStatus::Absent
        ));

        let tools: Vec<&Tool> = report.resolved().launch_tools().collect();
        assert_eq!(tools.len(), 7);
        let names: Vec<_> = tools.iter().map(|tool| tool.name()).collect();
        assert_eq!(
            names,
            [
                "dsh", "pi", "codex", "opencode", "claude", "copilot", "shell"
            ]
        );

        let expected = [
            ("dsh", "dsh", 1, vec![], 1),
            ("pi", "pi", 0, vec![], 0),
            ("codex", "codex", 0, vec!["openai"], 0),
            (
                "opencode",
                "opencode",
                0,
                vec!["openai", "opencode-static"],
                0,
            ),
            ("claude", "claude", 1, vec!["anthropic"], 0),
            ("copilot", "copilot", 1, vec!["copilot"], 0),
            ("shell", "bash", 2, vec![], 0),
        ];
        for (tool, (name, command, arg_count, providers, persist)) in tools.iter().zip(expected) {
            assert_eq!(
                tool_summary(tool),
                (
                    name.to_string(),
                    command.to_string(),
                    arg_count,
                    providers,
                    persist
                ),
            );
            assert_eq!(tool.origin(), &ToolOrigin::BuiltIn);
        }
    }

    #[test]
    fn shell_argv_keeps_two_elements_and_agents_carry_no_invented_flag() {
        let fixture = Fixture::new();
        let report = fixture.load().unwrap();
        let tools: Vec<&Tool> = report.resolved().launch_tools().collect();

        let shell = tools.iter().find(|tool| tool.name() == "shell").unwrap();
        assert_eq!(shell.argv, ["-O", "histappend"]);
        // codex/opencode configure bypass via provider-written files, not argv.
        for agent in ["codex", "opencode"] {
            let tool = tools.iter().find(|tool| tool.name() == agent).unwrap();
            assert!(tool.argv.is_empty(), "{agent} must have empty argv");
        }
        let claude = tools.iter().find(|tool| tool.name() == "claude").unwrap();
        assert_eq!(claude.argv, ["--dangerously-skip-permissions"]);
    }

    #[test]
    fn empty_comment_only_and_tools_empty_tiers_all_yield_defaults() {
        for (user, project) in [("", "# just a comment\n"), ("tools = []\n", ""), ("", "")] {
            let fixture = Fixture::new();
            fixture.user(user).project(project);
            let report = fixture.load().unwrap();
            assert!(report.uses_defaults(), "user={user:?} project={project:?}");
            assert_eq!(report.resolved().launch_tools().len(), 7);
            assert_eq!(
                report.user().status(),
                &TierStatus::Found { declared_tools: 0 }
            );
        }
    }

    #[test]
    fn a_found_empty_tier_is_found_not_absent() {
        let fixture = Fixture::new();
        fixture.user("");
        let report = fixture.load().unwrap();
        assert_eq!(
            report.user().status(),
            &TierStatus::Found { declared_tools: 0 }
        );
        assert_eq!(report.user().path(), Some(fixture.user.as_path()));
    }

    #[test]
    fn one_tool_catalog_does_not_add_defaults_or_shell() {
        let fixture = Fixture::new();
        fixture.user(&one_tool("solo"));
        let report = fixture.load().unwrap();
        assert!(!report.uses_defaults());
        let tools: Vec<&Tool> = report.resolved().launch_tools().collect();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name(), "solo");
    }

    // -- the legacy `run::Agent` characterization table -------------------

    #[test]
    fn shipped_default_network_requests_match_documented_baselines() {
        // Independent transcription of the reviewed endpoint evidence, not proxy hosts.
        let expected: [(&str, &[&str]); 7] = [
            ("dsh", &[]),
            (
                "pi",
                &[
                    "api.anthropic.com",
                    "auth.openai.com",
                    "chatgpt.com",
                    "mcp-proxy.anthropic.com",
                    "platform.claude.com",
                ],
            ),
            (
                "codex",
                &["api.openai.com", "auth.openai.com", "chatgpt.com"],
            ),
            (
                "opencode",
                &[
                    "api.openai.com",
                    "auth.openai.com",
                    "chatgpt.com",
                    "models.opencode.ai",
                ],
            ),
            (
                "claude",
                &[
                    "api.anthropic.com",
                    "mcp-proxy.anthropic.com",
                    "platform.claude.com",
                ],
            ),
            // Copilot is a pending inventory (#340), not an offline tool.
            ("copilot", &[]),
            ("shell", &[]),
        ];
        let tools = default_tools().unwrap();
        assert_eq!(tools.len(), 7);
        for (tool, (name, names)) in tools.iter().zip(expected) {
            assert_eq!(tool.name(), name);
            assert_eq!(tool.origin(), &ToolOrigin::BuiltIn);
            assert_eq!(
                tool.network_requests()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
                names,
                "{name}"
            );
            assert!(
                tool.network_requests()
                    .iter()
                    .all(|request| request.port().get() == 443)
            );
        }
    }

    /// **T1.** The compiled-in defaults, transcribed *verbatim* from
    /// `run::Agent`'s `command()`/`default_args()`/`credential_providers()` and
    /// `matches!(agent, Agent::Shell)` as of `bb299d1` (the pre-#82 `main`).
    /// This is the only thing between a typo in `default-tools.toml` and a
    /// silently wrong default launch. The provider column is the **requirement**
    /// set (`credentials`), not the provisioning set: `shell` declares none, so
    /// it rows as `&[]` (see
    /// `default_catalog_provisioning_sets_are_exactly_the_spec_table` for the
    /// provisioning side).
    #[test]
    fn default_tools_match_the_legacy_agent_table() {
        use CredentialProvider::*;
        type Case<'a> = (
            &'a str,
            &'a str,
            &'a [&'a str],
            &'a [CredentialProvider],
            bool,
        );
        let tools = default_tools().unwrap();
        let cases: [Case; 7] = [
            ("dsh", "dsh", &["web"], &[], false),
            ("pi", "pi", &[], &[], false),
            ("codex", "codex", &[], &[OpenAi], false),
            (
                "opencode",
                "opencode",
                &[],
                &[OpenAi, OpencodeStatic],
                false,
            ),
            (
                "claude",
                "claude",
                &["--dangerously-skip-permissions"],
                &[Anthropic],
                false,
            ),
            (
                "copilot",
                "copilot",
                &["--allow-all-tools"],
                &[Copilot],
                false,
            ),
            ("shell", "bash", &["-O", "histappend"], &[], true),
        ];
        assert_eq!(tools.len(), cases.len());
        for (tool, (name, command, argv, providers, interactive_shell)) in tools.iter().zip(cases) {
            assert_eq!(tool.name(), name);
            assert_eq!(tool.command(), command, "{name}");
            let expected_argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
            assert_eq!(tool.argv(), expected_argv.as_slice(), "{name}");
            let expected: Vec<CredentialProvider> = providers.to_vec();
            let actual: Vec<CredentialProvider> = tool.credential_providers().iter().collect();
            // `iter()` yields in `CredentialProvider::ALL` order, so compare
            // as a set to keep the table's per-tool intent, not its spelling.
            for provider in expected {
                assert!(
                    tool.credential_providers().contains(provider),
                    "{name} must select {provider:?}"
                );
            }
            assert_eq!(actual.len(), providers.len(), "{name}");
            assert_eq!(tool.is_interactive_shell(), interactive_shell, "{name}");
        }
    }

    /// **T1.** The provisioning set of each shipped verb, transcribed from
    /// ADR-0017's per-verb table. The acceptance criterion written as an
    /// assertion; fails on *any* closure or default bug. `credentials` is the
    /// *requirement* set and is asserted separately, so an implementation that
    /// conflates the two fails here. `pi` is the one shipped verb whose two
    /// sets differ: it declares `tools = ["claude", "codex"]`, so the
    /// `pi -> claude` and `pi -> codex` edges provision Anthropic and OpenAI
    /// without requiring either.
    #[test]
    fn default_catalog_provisioning_sets_are_exactly_the_spec_table() {
        use CredentialProvider::*;
        let catalog = Fixture::new()
            .load()
            .unwrap()
            .into_launch_catalog()
            .unwrap();
        let expected: [(&str, &[CredentialProvider], &[CredentialProvider]); 7] = [
            //  verb        credentials (required)     provisioned
            ("dsh", &[], &[]),
            ("pi", &[], &[Anthropic, OpenAi]),
            ("codex", &[OpenAi], &[OpenAi]),
            (
                "opencode",
                &[OpenAi, OpencodeStatic],
                &[OpenAi, OpencodeStatic],
            ),
            ("claude", &[Anthropic], &[Anthropic]),
            ("copilot", &[Copilot], &[Copilot]),
            ("shell", &[], &[Anthropic, OpenAi, OpencodeStatic, Copilot]),
        ];
        assert_eq!(catalog.as_slice().len(), expected.len());
        for (name, credentials, provisioned) in expected {
            let entry = catalog
                .as_slice()
                .iter()
                .find(|entry| entry.tool().name() == name)
                .unwrap_or_else(|| panic!("{name} missing from the default catalog"));
            assert_eq!(
                entry.tool().credentials(),
                credentials,
                "requirement set for {name}"
            );
            let actual: Vec<CredentialProvider> = entry.provisioned().iter().collect();
            assert_eq!(actual, provisioned, "provisioning set for {name}");
        }
    }

    /// **T3.** `help` is reserved: clap synthesizes it unconditionally, so a
    /// tool of that name would panic in debug and shadow clap's in release.
    #[test]
    fn the_name_help_is_rejected_as_reserved() {
        let fixture = Fixture::new();
        fixture.user(&one_tool("help"));
        let error = fixture.load().unwrap_err();
        let rendered = format!("{error:#}");
        assert!(rendered.contains("reserved"), "{rendered}");
    }

    // -- LaunchCatalog (the shell fallback) -------------------------------

    /// **T4a.** A config declaring one non-shell tool gets the built-in
    /// `shell` appended, with built-in provenance, and the flag set.
    #[test]
    fn a_one_tool_catalog_gains_the_builtin_shell_fallback() {
        let fixture = Fixture::new();
        fixture.user(&one_tool("solo"));
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        let names: Vec<&str> = catalog
            .as_slice()
            .iter()
            .map(|entry| entry.tool().name())
            .collect();
        assert_eq!(names, ["solo", "shell"]);
        assert!(catalog.has_shell_fallback());
        let shell = catalog
            .as_slice()
            .iter()
            .find(|entry| entry.tool().name() == "shell")
            .unwrap()
            .tool();
        assert_eq!(shell.origin(), &ToolOrigin::BuiltIn);
        assert_eq!(shell.command(), "bash");
        assert!(shell.is_interactive_shell());
    }

    /// **T4b.** A config that *declares* `shell` (here as `zsh`) keeps its
    /// own definition and suppresses the fallback.
    #[test]
    fn a_declared_shell_suppresses_the_fallback() {
        let fixture = Fixture::new();
        fixture.user("[[tools]]\nname = \"shell\"\ncommand = \"zsh\"\n");
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert!(!catalog.has_shell_fallback());
        assert_eq!(catalog.as_slice().len(), 1);
        assert_eq!(catalog.as_slice()[0].tool().name(), "shell");
        assert_eq!(catalog.as_slice()[0].tool().command(), "zsh");
    }

    /// **T4c/T4d.** The default path (both tiers empty, or `tools = []`) does
    /// not double-append `shell`. This goes through `load`'s both-empty
    /// branch, not the fallback.
    #[test]
    fn the_default_catalog_does_not_append_a_second_shell() {
        for (user, project) in [("", ""), ("tools = []\n", "")] {
            let fixture = Fixture::new();
            fixture.user(user).project(project);
            let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
            assert!(!catalog.has_shell_fallback());
            let names: Vec<&str> = catalog
                .as_slice()
                .iter()
                .map(|entry| entry.tool().name())
                .collect();
            assert_eq!(
                names,
                [
                    "dsh", "pi", "codex", "opencode", "claude", "copilot", "shell"
                ]
            );
        }
    }

    /// **T4e.** `ResolvedTools` is the pure merge result and is untouched by
    /// the fallback: one declared tool, even after a catalog is built.
    #[test]
    fn the_fallback_never_leaks_into_resolved_tools() {
        let fixture = Fixture::new();
        fixture.user(&one_tool("solo"));
        let report = fixture.load().unwrap();
        assert_eq!(report.resolved().launch_tools().len(), 1);
        let catalog = report.into_launch_catalog().unwrap();
        assert_eq!(catalog.as_slice().len(), 2);
    }

    /// `take_entry` moves exactly the named entry out, leaving the catalog
    /// usable — the property `cli::parse_from` needs to hand the catalog on to
    /// a built-in verb (`setup` reads it).
    #[test]
    fn launch_catalog_take_entry_returns_the_named_entry() {
        let fixture = Fixture::new();
        fixture.user(&one_tool("solo"));
        let mut catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        let solo = catalog.take_entry("solo").expect("solo is in the catalog");
        assert_eq!(solo.tool().name(), "solo");
        // The rest of the catalog survives, including the `shell` fallback.
        assert!(
            catalog
                .as_slice()
                .iter()
                .any(|entry| entry.tool().name() == "shell")
        );
        assert!(catalog.take_entry("solo").is_none(), "removed once");
        assert!(catalog.take_entry("absent").is_none());
    }

    /// Removing a declaration while the built-in `shell` fallback is present:
    /// the prefix shrinks, so `shell` stays the fallback rather than being
    /// promoted to a declaration.
    #[test]
    fn take_entry_decrements_the_prefix_for_a_declaration_with_a_fallback() {
        let fixture = Fixture::new();
        fixture.user(&one_tool("solo"));
        let mut catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert!(catalog.has_shell_fallback());

        let solo = catalog.take_entry("solo").expect("solo is in the catalog");
        assert_eq!(solo.tool().name(), "solo");
        assert!(
            catalog.declarations().is_empty(),
            "solo is no longer declared"
        );
        assert!(catalog.has_shell_fallback(), "shell stays the fallback");
        assert_eq!(catalog.as_slice().len(), 1);
    }

    /// Removing a declaration from the compiled-in default catalog (where
    /// `shell` is itself declared, so no fallback is appended) must keep the
    /// prefix within `entries` — the arithmetic bug that made `declarations()`
    /// panic here — and leave `shell` a declaration.
    #[test]
    fn take_entry_decrements_the_prefix_for_a_default_declaration() {
        let mut catalog = default_launch_catalog().unwrap();
        assert!(!catalog.has_shell_fallback());
        let declared_before = catalog.declarations().len();

        let dsh = catalog.take_entry("dsh").expect("dsh is a default tool");
        assert_eq!(dsh.tool().name(), "dsh");
        assert_eq!(catalog.declarations().len(), declared_before - 1);
        assert!(
            !catalog
                .declarations()
                .iter()
                .any(|entry| entry.tool().name() == "dsh"),
            "the removed declaration is gone from the prefix"
        );
        assert!(
            catalog
                .declarations()
                .iter()
                .any(|entry| entry.tool().name() == "shell"),
            "shell is still declared, not a fallback"
        );
        assert!(!catalog.has_shell_fallback());
    }

    /// Removing the `shell` fallback itself leaves the declaration prefix
    /// untouched, and the flag clears because nothing sits after the prefix.
    #[test]
    fn take_entry_of_the_fallback_leaves_the_prefix_untouched() {
        let fixture = Fixture::new();
        fixture.user(&one_tool("solo"));
        let mut catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        let declared_before = catalog.declarations().len();
        assert!(catalog.has_shell_fallback());

        let shell = catalog
            .take_entry("shell")
            .expect("shell is in the catalog");
        assert_eq!(shell.tool().name(), "shell");
        assert_eq!(catalog.declarations().len(), declared_before);
        assert_eq!(catalog.as_slice().len(), declared_before);
        assert!(!catalog.has_shell_fallback());
    }

    /// The provisioning set of `name` in `catalog`, in `CredentialProvider::ALL`
    /// order.
    fn provisioned_of(catalog: &LaunchCatalog, name: &str) -> Vec<CredentialProvider> {
        catalog
            .as_slice()
            .iter()
            .find(|entry| entry.tool().name() == name)
            .unwrap_or_else(|| panic!("{name} missing from the catalog"))
            .provisioned()
            .iter()
            .collect()
    }

    /// The catalog entry named `name` — a launch verb or the appended fallback.
    fn entry_of<'a>(catalog: &'a LaunchCatalog, name: &str) -> &'a CatalogEntry {
        catalog
            .as_slice()
            .iter()
            .find(|entry| entry.tool().name() == name)
            .unwrap_or_else(|| panic!("{name} missing from the catalog"))
    }

    /// The entry's provisioned paths, in fold order, rendered guest-relative.
    fn persist_of(catalog: &LaunchCatalog, name: &str) -> Vec<String> {
        entry_of(catalog, name)
            .persist()
            .iter()
            .map(|path| path.as_path().to_string_lossy().into_owned())
            .collect()
    }

    /// The entry's requested credential names, in declaration order.
    fn names_of(catalog: &LaunchCatalog, name: &str) -> Vec<String> {
        entry_of(catalog, name)
            .requested_names()
            .iter()
            .map(|service| service.as_str().to_string())
            .collect()
    }

    /// The catalog's verb names, in launch order.
    fn verbs_of(catalog: &LaunchCatalog) -> Vec<String> {
        catalog
            .as_slice()
            .iter()
            .map(|entry| entry.tool().name().to_string())
            .collect()
    }

    /// [`provisioned_of`] as an order-independent set, for the proptests.
    fn provisioned_set(catalog: &LaunchCatalog, name: &str) -> BTreeSet<CredentialProvider> {
        provisioned_of(catalog, name).into_iter().collect()
    }

    fn provider_from_u8(value: u8) -> CredentialProvider {
        CredentialProvider::ALL[(value as usize) % CredentialProvider::ALL.len()]
    }

    /// Build a one-file catalog from `(credentials, tool-edges)` specs, named
    /// `t0..t{n-1}`. Edges are reduced modulo the tool count so references are
    /// never dangling (T7's generators produce indices).
    fn single_file_catalog(specs: &[(Vec<u8>, Vec<usize>)]) -> LaunchCatalog {
        let n = specs.len();
        let mut body = String::new();
        for (index, (credentials, edges)) in specs.iter().enumerate() {
            body.push_str("[[tools]]\n");
            body.push_str(&format!("name = \"t{index}\"\ncommand = \"t{index}\"\n"));
            if !credentials.is_empty() {
                let names: Vec<String> = credentials
                    .iter()
                    .map(|c| format!("\"{}\"", provider_from_u8(*c).config_name()))
                    .collect();
                body.push_str(&format!("credentials = [{}]\n", names.join(", ")));
            }
            if !edges.is_empty() {
                let names: Vec<String> = edges
                    .iter()
                    .map(|edge| format!("\"t{}\"", edge % n))
                    .collect();
                body.push_str(&format!("tools = [{}]\n", names.join(", ")));
            }
        }
        let fixture = Fixture::new();
        fixture.user(&body);
        fixture.load().unwrap().into_launch_catalog().unwrap()
    }

    /// **T2.** Omitted `tools` defaults to the wildcard for a tool named
    /// [`SHELL_TOOL_NAME`] and to none for every other name. Row 4 (an explicit
    /// `tools = []` on a declared `shell`) is the asymmetric pair that a
    /// `Vec<String>` + `#[serde(default)]` implementation would fail.
    #[test]
    fn omitted_tools_defaults_to_the_wildcard_only_for_the_shell_name() {
        use CredentialProvider::*;

        // Row 1: a user config declaring one non-shell tool. The appended
        // fallback `shell` is BuiltIn and closes over its own file only.
        let fixture = Fixture::new();
        fixture.user(
            "[[tools]]\nname = \"claude\"\ncommand = \"claude\"\ncredentials = [\"anthropic\"]\n",
        );
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(
            provisioned_of(&catalog, "shell"),
            Vec::<CredentialProvider>::new()
        );
        assert_eq!(provisioned_of(&catalog, "claude"), vec![Anthropic]);

        // Row 3: a declared `shell` in the *same file* as `claude` closes over
        // it (omitted `tools` => the wildcard).
        let fixture = Fixture::new();
        fixture.user(
            "[[tools]]\nname = \"shell\"\ncommand = \"zsh\"\n[[tools]]\nname = \"claude\"\ncommand = \"claude\"\ncredentials = [\"anthropic\"]\n",
        );
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(provisioned_of(&catalog, "shell"), vec![Anthropic]);

        // Row 4: `tools = []` opts a declared `shell` out entirely.
        let fixture = Fixture::new();
        fixture.user(
            "[[tools]]\nname = \"shell\"\ncommand = \"zsh\"\ntools = []\n[[tools]]\nname = \"claude\"\ncommand = \"claude\"\ncredentials = [\"anthropic\"]\n",
        );
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(
            provisioned_of(&catalog, "shell"),
            Vec::<CredentialProvider>::new()
        );

        // Row 5: a non-shell name defaults to none, over the appended fallback.
        let fixture = Fixture::new();
        fixture.user(
            "[[tools]]\nname = \"notshell\"\ncommand = \"notshell\"\ncredentials = [\"copilot\"]\n",
        );
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(provisioned_of(&catalog, "notshell"), vec![Copilot]);
        let notshell = catalog
            .as_slice()
            .iter()
            .find(|entry| entry.tool().name() == "notshell")
            .unwrap()
            .tool();
        assert_eq!(notshell.declared_tools(), &DeclaredTools::Named(Vec::new()));
    }

    /// **T3.** A tool that declares another tool is *provisioned* with that
    /// tool's credentials (transitively) but not *required* to have them.
    #[test]
    fn a_declared_tool_contributes_its_credentials_transitively() {
        use CredentialProvider::*;
        let fixture = Fixture::new();
        fixture.user(
            "[[tools]]\nname = \"pi\"\ncommand = \"pi\"\ncredentials = [\"openai\"]\ntools = [\"bridge\"]\n\
             [[tools]]\nname = \"bridge\"\ncommand = \"bridge\"\ntools = [\"claude\"]\n\
             [[tools]]\nname = \"claude\"\ncommand = \"claude\"\ncredentials = [\"anthropic\"]\n",
        );
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(provisioned_of(&catalog, "pi"), vec![Anthropic, OpenAi]);
        let pi = catalog
            .as_slice()
            .iter()
            .find(|entry| entry.tool().name() == "pi")
            .unwrap()
            .tool();
        let requirement: Vec<CredentialProvider> = pi.credential_providers().iter().collect();
        assert_eq!(requirement, vec![OpenAi], "pi only *requires* openai");
    }

    /// **T3.** A cycle is a fixed point, not an error; a self-reference is
    /// legal. A naive recursion without a visited set *hangs* here.
    #[test]
    fn a_tools_cycle_resolves_instead_of_hanging_or_erroring() {
        use CredentialProvider::*;
        let fixture = Fixture::new();
        fixture.user(
            "[[tools]]\nname = \"a\"\ncommand = \"a\"\ncredentials = [\"anthropic\"]\ntools = [\"b\"]\npersist = [\".a\"]\n\
             [[tools]]\nname = \"b\"\ncommand = \"b\"\ncredentials = [\"openai\"]\ntools = [\"a\", \"a\"]\npersist = [\".b\"]\n\
             [[tools]]\nname = \"c\"\ncommand = \"c\"\ncredentials = [\"copilot\"]\ntools = [\"c\"]\npersist = [\".c\"]\n\
             [[tools]]\nname = \"all\"\ncommand = \"all\"\ntools = [\"*\"]\n",
        );
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(provisioned_of(&catalog, "a"), vec![Anthropic, OpenAi]);
        assert_eq!(provisioned_of(&catalog, "b"), vec![Anthropic, OpenAi]);
        assert_eq!(provisioned_of(&catalog, "c"), vec![Copilot]);
        // A cycle, a repeated edge and a wildcard that includes itself each add
        // one contribution per definition, and the paths fold in arena order.
        assert_eq!(persist_of(&catalog, "a"), [".a", ".b"]);
        assert_eq!(
            persist_of(&catalog, "b"),
            [".a", ".b"],
            "a repeated edge is not a repeated claim"
        );
        assert_eq!(persist_of(&catalog, "c"), [".c"]);
        assert_eq!(persist_of(&catalog, "all"), [".a", ".b", ".c"]);
        assert_eq!(
            names_of(&catalog, "all"),
            ["anthropic", "copilot", "openai"]
        );

        // The same shape across tiers: a hidden project `a` closes a cycle with
        // the project `b` it names, never with the user's winning `a`.
        let fixture = Fixture::new();
        fixture
            .user("[[tools]]\nname = \"a\"\ncommand = \"user-a\"\ncredentials = [\"anthropic\"]\n")
            .project(
                "[[tools]]\nname = \"a\"\ncommand = \"project-a\"\ncredentials = [\"openai\"]\ntools = [\"b\"]\n\
                 [[tools]]\nname = \"b\"\ncommand = \"b\"\ncredentials = [\"copilot\"]\ntools = [\"a\"]\n",
            );
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(
            provisioned_of(&catalog, "a"),
            vec![Anthropic],
            "the user verb is its own closure"
        );
        assert_eq!(
            provisioned_of(&catalog, "b"),
            vec![OpenAi, Copilot],
            "the project's `b` closes over the hidden project `a`, not the user's"
        );
        assert_eq!(names_of(&catalog, "b"), ["copilot", "openai"]);
    }

    /// **T3 / §A1.** The wildcard closes over the declaring tool's **own
    /// configuration file**, not the merged catalog. Two same-file tools group;
    /// a tool in the other tier does not.
    #[test]
    fn the_wildcard_closes_over_its_own_file_only() {
        use CredentialProvider::*;
        let fixture = Fixture::new();
        fixture
            .user(
                "[[tools]]\nname = \"w\"\ncommand = \"w\"\ncredentials = [\"copilot\"]\ntools = [\"*\"]\n\
                 [[tools]]\nname = \"u\"\ncommand = \"u\"\ncredentials = [\"openai\"]\n",
            )
            .project(
                "[[tools]]\nname = \"p\"\ncommand = \"p\"\ncredentials = [\"anthropic\"]\n",
            );
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(provisioned_of(&catalog, "w"), vec![OpenAi, Copilot]);
        assert!(
            !provisioned_of(&catalog, "w").contains(&Anthropic),
            "the project tier is a different file and must not be swept in by `*`"
        );
    }

    // -- #395: tier-local tool references ----------------------------------

    /// **U4 / §A1.** A name the other tier declares is a config error, not a
    /// cross-file opt-in — in both directions, for a name only the shipped
    /// catalog declares, and for the synthesized fallback. The positive control
    /// redeclares the target in the referencing file, which is the documented
    /// migration.
    #[test]
    fn explicit_cross_tier_references_are_rejected_in_both_directions() {
        use CredentialProvider::*;

        // (a) the user tier naming a project-only tool.
        let fixture = Fixture::new();
        fixture
            .user("[[tools]]\nname = \"w\"\ncommand = \"w\"\ntools = [\"p\"]\n")
            .project("[[tools]]\nname = \"p\"\ncommand = \"p\"\ncredentials = [\"anthropic\"]\n");
        let report = fixture
            .load()
            .expect("a cross-tier reference is valid schema");
        assert_eq!(
            format!("{:#}", report.into_launch_catalog().unwrap_err()),
            format!(
                "config: user config {} declaration [0] tool \"w\": tools[0]: \"p\" names no tool in this configuration file; it is declared in project config {}; cross-tier tool references are not allowed; copy or redeclare the tool in this file, or remove the entry",
                crate::one_line::quoted_path(&fixture.user),
                crate::one_line::quoted_path(&fixture.project)
            )
        );

        // (b) the project tier naming a user-only tool, naming the project file.
        let fixture = Fixture::new();
        fixture
            .user("[[tools]]\nname = \"p\"\ncommand = \"p\"\ncredentials = [\"anthropic\"]\n")
            .project("[[tools]]\nname = \"w\"\ncommand = \"w\"\ntools = [\"p\"]\n");
        let error = format!(
            "{:#}",
            fixture.load().unwrap().into_launch_catalog().unwrap_err()
        );
        assert!(
            error.contains(&format!(
                "project config {} declaration [0] tool \"w\"",
                crate::one_line::quoted_path(&fixture.project)
            )),
            "{error}"
        );

        // (c) a custom catalog replaces the shipped one, so its names are gone:
        // the name is declared nowhere retained, so nothing is cross-tier and the
        // message must not say otherwise.
        let fixture = Fixture::new();
        fixture
            .user("[[tools]]\nname = \"u\"\ncommand = \"u\"\n")
            .project("[[tools]]\nname = \"w\"\ncommand = \"w\"\ntools = [\"claude\"]\n");
        assert_eq!(
            format!(
                "{:#}",
                fixture.load().unwrap().into_launch_catalog().unwrap_err()
            ),
            format!(
                "config: project config {} declaration [0] tool \"w\": tools[0]: \"claude\" names no tool in this configuration file; declare it in this file or remove the entry",
                crate::one_line::quoted_path(&fixture.project)
            )
        );

        // (d) the synthesized fallback `shell` is a launch affordance, not a
        // declaration in the referencing file, and it is declared nowhere
        // retained either.
        let fixture = Fixture::new();
        fixture.project("[[tools]]\nname = \"w\"\ncommand = \"w\"\ntools = [\"shell\"]\n");
        assert_eq!(
            format!(
                "{:#}",
                fixture.load().unwrap().into_launch_catalog().unwrap_err()
            ),
            format!(
                "config: project config {} declaration [0] tool \"w\": tools[0]: \"shell\" names no tool in this configuration file; declare it in this file or remove the entry",
                crate::one_line::quoted_path(&fixture.project)
            )
        );

        // Positive control: the target redeclared in the referencing file.
        let fixture = Fixture::new();
        fixture
            .user(
                "[[tools]]\nname = \"w\"\ncommand = \"w\"\ntools = [\"p\"]\n\
                   [[tools]]\nname = \"p\"\ncommand = \"p\"\ncredentials = [\"anthropic\"]\n",
            )
            .project("[[tools]]\nname = \"p\"\ncommand = \"p\"\ncredentials = [\"copilot\"]\n");
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(provisioned_of(&catalog, "w"), vec![Anthropic]);
        assert_eq!(
            provisioned_of(&catalog, "p"),
            vec![Anthropic],
            "the user's `p` is the winning verb and the referenced definition"
        );
    }

    /// **U1 / §A2.** A hidden project definition supplies **its own** facets: user
    /// `pi` wins the verb `agent-vm pi`, but the project's `helper` provisions the
    /// *project* `pi`'s provider, requested name and persisted path, never the
    /// user's. Commands, providers, names and paths are asymmetric on purpose, so
    /// selecting the wrong tier — or both — cannot pass.
    #[test]
    fn hidden_project_definition_supplies_only_its_own_facets() {
        use CredentialProvider::*;
        let fixture = Fixture::new();
        fixture
            .user(
                "[[tools]]\nname = \"pi\"\ncommand = \"user-pi\"\n\
                 credentials = [\"openai\", \"user-service\"]\npersist = [\".user-pi\"]\n",
            )
            .project(
                "[[tools]]\nname = \"pi\"\ncommand = \"project-pi\"\n\
                 credentials = [\"anthropic\", \"project-service\"]\npersist = [\".project-pi\"]\n\
                 [[tools]]\nname = \"bridge\"\ncommand = \"bridge\"\ntools = [\"pi\"]\npersist = [\".bridge\"]\n\
                 [[tools]]\nname = \"helper\"\ncommand = \"helper\"\ntools = [\"bridge\"]\npersist = [\".helper\"]\n",
            );
        let report = fixture.load().unwrap();
        assert_eq!(
            report.conflicts().len(),
            1,
            "a whole-definition user-wins conflict is still reported once"
        );
        assert_eq!(report.conflicts()[0].tool(), "pi");
        let catalog = report.into_launch_catalog().unwrap();

        assert_eq!(verbs_of(&catalog), ["pi", "bridge", "helper", "shell"]);

        // The verb is the user definition, unchanged.
        assert_eq!(entry_of(&catalog, "pi").tool().command(), "user-pi");
        assert_eq!(
            entry_of(&catalog, "pi").tool().origin(),
            &ToolOrigin::User(fixture.user.clone())
        );
        assert_eq!(provisioned_of(&catalog, "pi"), vec![OpenAi]);
        assert_eq!(names_of(&catalog, "pi"), ["openai", "user-service"]);
        assert_eq!(persist_of(&catalog, "pi"), [".user-pi"]);

        // The hidden project definition supplies the project closure.
        assert_eq!(entry_of(&catalog, "helper").tool().command(), "helper");
        assert_eq!(provisioned_of(&catalog, "helper"), vec![Anthropic]);
        assert_eq!(
            names_of(&catalog, "helper"),
            ["anthropic", "project-service"]
        );
        assert_eq!(
            persist_of(&catalog, "helper"),
            [".project-pi", ".bridge", ".helper"]
        );
        assert!(
            entry_of(&catalog, "helper")
                .tool()
                .credential_providers()
                .iter()
                .next()
                .is_none(),
            "an available tool contributes provisioning, never a requirement"
        );
        assert!(
            !persist_of(&catalog, "helper").contains(&".user-pi".to_string()),
            "a hidden project definition must never contribute the user's persisted path"
        );

        // Reverse direction: a user tool naming `pi` gets the user definition.
        let fixture = Fixture::new();
        fixture
            .user(
                "[[tools]]\nname = \"pi\"\ncommand = \"user-pi\"\ncredentials = [\"openai\"]\npersist = [\".user-pi\"]\n\
                 [[tools]]\nname = \"caller\"\ncommand = \"caller\"\ntools = [\"pi\"]\n",
            )
            .project(
                "[[tools]]\nname = \"pi\"\ncommand = \"project-pi\"\n\
                 credentials = [\"anthropic\"]\npersist = [\".project-pi\"]\n",
            );
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(provisioned_of(&catalog, "caller"), vec![OpenAi]);
        assert_eq!(persist_of(&catalog, "caller"), [".user-pi"]);
    }

    /// The body shared by U2's rows: a hidden project `pi`, a `bridge` that closes
    /// a cycle with it, a `helper` two edges away and a project wildcard.
    const PROJECT_CYCLE_BODY: &str = "[[tools]]\nname = \"pi\"\ncommand = \"project-pi\"\n\
         credentials = [\"anthropic\", \"project-service\"]\npersist = [\".project-pi\"]\ntools = [\"bridge\"]\n\
         [[tools]]\nname = \"bridge\"\ncommand = \"bridge\"\ncredentials = [\"bridge-service\"]\n\
         persist = [\".bridge\"]\ntools = [\"pi\"]\n\
         [[tools]]\nname = \"helper\"\ncommand = \"helper\"\ntools = [\"bridge\"]\npersist = [\".helper\"]\n\
         [[tools]]\nname = \"wide\"\ncommand = \"wide\"\ntools = [\"*\"]\npersist = [\".wide\"]\n";

    /// **U2 / §A3.** The rule holds transitively and through a wildcard, and all
    /// three facets fold over the *same* visited mask. Different service names and
    /// disjoint paths per definition make a shallow-only walk fail; the hidden
    /// cycle makes a wrong visited mask show up as a duplicated path.
    #[test]
    fn hidden_transitive_and_wildcard_closures_share_all_facets() {
        use CredentialProvider::*;
        let fixture = Fixture::new();
        fixture
            .user("[[tools]]\nname = \"pi\"\ncommand = \"user-pi\"\ncredentials = [\"openai\"]\npersist = [\".user-pi\"]\n")
            .project(PROJECT_CYCLE_BODY);
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();

        // `helper -> bridge -> pi -> bridge`: the cycle terminates and every
        // definition contributes exactly once, in arena order.
        assert_eq!(provisioned_of(&catalog, "helper"), vec![Anthropic]);
        assert_eq!(
            names_of(&catalog, "helper"),
            ["anthropic", "bridge-service", "project-service"]
        );
        assert_eq!(
            persist_of(&catalog, "helper"),
            [".project-pi", ".bridge", ".helper"]
        );

        // The wildcard closes over every project definition, hidden `pi` included,
        // and reaches neither the user tier nor the shipped agents.
        assert_eq!(provisioned_of(&catalog, "wide"), vec![Anthropic]);
        assert_eq!(
            names_of(&catalog, "wide"),
            ["anthropic", "bridge-service", "project-service"]
        );
        assert_eq!(
            persist_of(&catalog, "wide"),
            [".project-pi", ".bridge", ".helper", ".wide"],
            "a wildcard that includes itself still contributes each definition once"
        );

        // Edge order and duplicate edges cannot change the folded facets.
        let reordered = PROJECT_CYCLE_BODY.replace(
            "name = \"helper\"\ncommand = \"helper\"\ntools = [\"bridge\"]",
            "name = \"helper\"\ncommand = \"helper\"\ntools = [\"bridge\", \"bridge\", \"wide\"]",
        );
        let fixture = Fixture::new();
        fixture
            .user("[[tools]]\nname = \"pi\"\ncommand = \"user-pi\"\ncredentials = [\"openai\"]\npersist = [\".user-pi\"]\n")
            .project(&reordered);
        let reordered_catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(
            persist_of(&reordered_catalog, "helper"),
            [".project-pi", ".bridge", ".helper", ".wide"],
            "a repeated edge and a second path to `wide` add one contribution each"
        );
        assert_eq!(
            provisioned_of(&reordered_catalog, "helper"),
            vec![Anthropic]
        );
    }

    /// **U3 / §A3.** A hidden definition's reference error keeps its **original**
    /// declaration index, declaring file and field, and fails even when no launch
    /// verb reaches it. Escaped control bytes never reach the terminal, while a
    /// non-ASCII declaring directory still prints as itself.
    #[test]
    fn hidden_definition_errors_keep_original_declaration_index() {
        // Project declaration 0 is hidden by the user's `pi`; declaration 2's
        // `tools[1]` is the bad edge.
        let fixture = Fixture::new();
        fixture
            .user("[[tools]]\nname = \"pi\"\ncommand = \"user-pi\"\ncredentials = [\"openai\"]\n")
            .project(
                "[[tools]]\nname = \"pi\"\ncommand = \"project-pi\"\ncredentials = [\"anthropic\"]\n\
                 [[tools]]\nname = \"bridge\"\ncommand = \"bridge\"\n\
                 [[tools]]\nname = \"helper\"\ncommand = \"helper\"\ntools = [\"bridge\", \"nope\"]\n",
            );
        assert_eq!(
            format!(
                "{:#}",
                fixture.load().unwrap().into_launch_catalog().unwrap_err()
            ),
            format!(
                "config: project config {} declaration [2] tool \"helper\": tools[1]: \"nope\" names no tool in this configuration file; declare it in this file or remove the entry",
                crate::one_line::quoted_path(&fixture.project)
            )
        );

        // A bad edge inside a hidden declaration with no incoming edge from any
        // winner still fails: shadowing a name is not a way to ignore its
        // references.
        let fixture = Fixture::new();
        fixture
            .user("[[tools]]\nname = \"dup\"\ncommand = \"user-dup\"\n")
            .project(
                "[[tools]]\nname = \"dup\"\ncommand = \"project-dup\"\ntools = [\"missing\"]\n",
            );
        let error = format!(
            "{:#}",
            fixture.load().unwrap().into_launch_catalog().unwrap_err()
        );
        assert!(
            error.contains(&format!(
                "project config {} declaration [0] tool \"dup\": tools[0]:",
                crate::one_line::quoted_path(&fixture.project)
            )),
            "{error}"
        );

        // A reference carrying a control byte is byte-escaped (config-chosen
        // text), while the declaring directory is a measured path and prints as
        // itself.
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("проект").join(".agent-vm");
        let project = directory.join("config.toml");
        write_file(
            &project,
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\ntools = [\"a\\nb\"]\n",
        );
        let paths = ConfigPaths {
            user: None,
            project,
            home: None,
        };
        let error = format!(
            "{:#}",
            load(&paths).unwrap().into_launch_catalog().unwrap_err()
        );
        assert!(error.contains("проект"), "{error}");
        assert!(error.contains("\"a\\x0ab\""), "{error}");
        assert!(!error.contains("a\nb"), "{error:?}");
    }

    /// **U6 / §A4.** An available tool adds provisioning, never a requirement: the
    /// launched tool's own `credentials` stay the whole required set, so an
    /// inherited provider's missing-login bail cannot fire. Named requests fold
    /// over exactly the same closure as the built-in providers.
    #[test]
    fn inherited_providers_are_provisioned_but_never_required() {
        use CredentialProvider::*;
        let fixture = Fixture::new();
        fixture.user(
            "[[tools]]\nname = \"caller\"\ncommand = \"caller\"\ncredentials = [\"openai\"]\n\
             tools = [\"claude\", \"copilot\"]\n\
             [[tools]]\nname = \"claude\"\ncommand = \"claude\"\ncredentials = [\"anthropic\"]\n\
             [[tools]]\nname = \"copilot\"\ncommand = \"copilot\"\ncredentials = [\"copilot\"]\n",
        );
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(
            provisioned_of(&catalog, "caller"),
            vec![Anthropic, OpenAi, Copilot]
        );
        let requirement: Vec<CredentialProvider> = entry_of(&catalog, "caller")
            .tool()
            .credential_providers()
            .iter()
            .collect();
        assert_eq!(
            requirement,
            vec![OpenAi],
            "only the launched tool's own credentials are required"
        );
        assert_eq!(
            names_of(&catalog, "caller"),
            ["anthropic", "copilot", "openai"],
            "named requests fold over the same closure as the providers"
        );

        // The shipped `pi` provisions both providers and requires neither.
        let defaults = Fixture::new()
            .load()
            .unwrap()
            .into_launch_catalog()
            .unwrap();
        assert_eq!(provisioned_of(&defaults, "pi"), vec![Anthropic, OpenAi]);
        assert!(
            entry_of(&defaults, "pi")
                .tool()
                .credential_providers()
                .iter()
                .next()
                .is_none()
        );
    }

    /// **U7 / §A5.** A hidden definition's persisted paths are validated as part of
    /// the closure that selects them, before any path reaches the guest-HOME link
    /// list: exact and ancestor/descendant conflicts fail, naming both declaring
    /// origins; raw per-tool path validation still applies to hidden declarations;
    /// and a cycle revisiting one owner is not a duplicate claim.
    #[test]
    fn hidden_persist_conflicts_are_rejected_inside_the_selecting_closure() {
        // Exact duplicate claim between two project definitions the same launch
        // selects, one of them hidden from verb selection.
        let fixture = Fixture::new();
        fixture
            .user("[[tools]]\nname = \"pi\"\ncommand = \"user-pi\"\n")
            .project(
                "[[tools]]\nname = \"pi\"\ncommand = \"project-pi\"\npersist = [\".cache\"]\n\
                 [[tools]]\nname = \"bridge\"\ncommand = \"bridge\"\npersist = [\"./.cache//\"]\n\
                 [[tools]]\nname = \"helper\"\ncommand = \"helper\"\ntools = [\"pi\", \"bridge\"]\n",
            );
        let error = format!(
            "{:#}",
            fixture.load().unwrap().into_launch_catalog().unwrap_err()
        );
        assert!(
            error.contains("is claimed by tool \"pi\"")
                && error.contains("tool \"bridge\"")
                && error.contains("project config"),
            "{error}"
        );
        assert_eq!(
            error
                .matches(&crate::one_line::quoted_path(&fixture.project).to_string())
                .count(),
            2,
            "both claimants name their declaring file: {error}"
        );

        // Ancestor/descendant variant.
        let fixture = Fixture::new();
        fixture
            .user("[[tools]]\nname = \"pi\"\ncommand = \"user-pi\"\n")
            .project(
                "[[tools]]\nname = \"pi\"\ncommand = \"project-pi\"\npersist = [\".cache\"]\n\
                 [[tools]]\nname = \"inner\"\ncommand = \"inner\"\npersist = [\".cache/x\"]\n\
                 [[tools]]\nname = \"helper\"\ncommand = \"helper\"\ntools = [\"pi\", \"inner\"]\n",
            );
        let error = format!(
            "{:#}",
            fixture.load().unwrap().into_launch_catalog().unwrap_err()
        );
        assert!(
            error.contains("overlaps") && error.contains("tool \"inner\""),
            "{error}"
        );

        // Raw per-tool path validation still applies to a hidden declaration: a
        // reserved link, an absolute path, a traversal and a within-tool overlap
        // are all load errors even though the definition has no verb.
        for body in [
            "persist = [\".pi\"]",
            "persist = [\"/absolute\"]",
            "persist = [\"../escape\"]",
            "persist = [\".a\", \".a/b\"]",
        ] {
            let fixture = Fixture::new();
            fixture
                .user("[[tools]]\nname = \"dup\"\ncommand = \"user-dup\"\n")
                .project(&format!(
                    "[[tools]]\nname = \"dup\"\ncommand = \"project-dup\"\n{body}\n"
                ));
            assert!(
                fixture.load().is_err(),
                "a hidden declaration's own paths are still validated: {body}"
            );
        }

        // A cycle revisiting one owner is one claim, not two.
        let fixture = Fixture::new();
        fixture.user(
            "[[tools]]\nname = \"pi\"\ncommand = \"pi\"\npersist = [\".cache\"]\ntools = [\"bridge\"]\n\
             [[tools]]\nname = \"bridge\"\ncommand = \"bridge\"\npersist = [\".bridge\"]\ntools = [\"pi\"]\n",
        );
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(persist_of(&catalog, "pi"), [".cache", ".bridge"]);
    }

    /// **U8 / §A5.** The ownership partition: winners and each *selected* closure
    /// are checked, so two tier-local closures that each own a path alone are not
    /// simultaneous owners, and an unreachable hidden closure's internal overlap
    /// does not fail the catalog — until a winning tool selects it.
    #[test]
    fn ownership_checks_cover_winners_and_each_selected_closure_only() {
        // User `pi` and hidden project `pi` claim the same path; each is alone in
        // its own tier-local closure, so no launch ever links both.
        let fixture = Fixture::new();
        fixture
            .user("[[tools]]\nname = \"pi\"\ncommand = \"user-pi\"\npersist = [\".shared\"]\n")
            .project(
                "[[tools]]\nname = \"pi\"\ncommand = \"project-pi\"\npersist = [\".shared\"]\n",
            );
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(persist_of(&catalog, "pi"), [".shared"]);

        // An unreachable hidden pair whose *joint* closure overlaps stays valid:
        // the user's `a`/`b` have no edges and no paths, project `a` owns `cache`
        // and references project `b` owning `cache/x`, and both project names are
        // hidden.
        const USER: &str =
            "[[tools]]\nname = \"a\"\ncommand = \"a\"\n[[tools]]\nname = \"b\"\ncommand = \"b\"\n";
        const PROJECT: &str = "[[tools]]\nname = \"a\"\ncommand = \"project-a\"\npersist = [\"cache\"]\ntools = [\"b\"]\n\
             [[tools]]\nname = \"b\"\ncommand = \"project-b\"\npersist = [\"cache/x\"]\n";
        let fixture = Fixture::new();
        fixture.user(USER).project(PROJECT);
        let catalog = fixture
            .load()
            .expect("no winner selects the overlapping closure")
            .into_launch_catalog()
            .expect("an unreachable hidden closure's ownership is not checked");
        assert_eq!(verbs_of(&catalog), ["a", "b", "shell"]);
        assert_eq!(
            entry_of(&catalog, "a").tool().command(),
            "a",
            "the hidden project definition is not a verb"
        );

        // The paired rejection control: a project helper selecting that closure.
        let fixture = Fixture::new();
        fixture.user(USER).project(&format!(
            "{PROJECT}[[tools]]\nname = \"helper\"\ncommand = \"helper\"\ntools = [\"a\"]\n"
        ));
        let error = format!(
            "{:#}",
            fixture.load().unwrap().into_launch_catalog().unwrap_err()
        );
        assert!(
            error.contains("overlaps")
                && error.contains("tool \"a\"")
                && error.contains("tool \"b\""),
            "{error}"
        );
    }

    /// **U9 / §A6–A7.** The shipped catalog, the isolated fallback and a declared
    /// `shell` keep three distinct contracts.
    #[test]
    fn shipped_fallback_and_declared_shell_keep_their_own_scopes() {
        // The shipped catalog keeps its seven verbs and exact facets.
        let defaults = Fixture::new()
            .load()
            .unwrap()
            .into_launch_catalog()
            .unwrap();
        assert_eq!(
            verbs_of(&defaults),
            [
                "dsh", "pi", "codex", "opencode", "claude", "copilot", "shell"
            ]
        );
        assert!(!defaults.has_shell_fallback());
        assert_eq!(persist_of(&defaults, "dsh"), [".dsh"]);

        // The custom-catalog fallback provisions nothing at all — no shipped
        // provider, no requested name, no declared persist, and no shipped agent.
        let fixture = Fixture::new();
        fixture.user("[[tools]]\nname = \"solo\"\ncommand = \"solo\"\n");
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert!(catalog.has_shell_fallback());
        let shell = entry_of(&catalog, "shell");
        assert!(shell.provisioned().iter().next().is_none());
        assert!(shell.requested_names().is_empty());
        assert!(shell.persist().is_empty());
        assert_eq!(shell.tool().command(), "bash");
        assert_eq!(verbs_of(&catalog), ["solo", "shell"]);
        assert_eq!(
            catalog.declarations().len(),
            1,
            "the fallback is a launch affordance, not a declaration"
        );

        // A declared `shell` with an omitted `tools` reaches its own tier's
        // siblings — including hidden ones — and nothing from the other tier.
        let fixture = Fixture::new();
        fixture
            .user(
                "[[tools]]\nname = \"shell\"\ncommand = \"bash\"\npersist = [\".u\"]\n\
                 [[tools]]\nname = \"sibling\"\ncommand = \"sibling\"\npersist = [\".s\"]\n",
            )
            .project("[[tools]]\nname = \"sibling\"\ncommand = \"project-sibling\"\npersist = [\".p\"]\n");
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(
            persist_of(&catalog, "shell"),
            [".u", ".s"],
            "the omitted wildcard sees this tier's siblings, hidden ones included"
        );
        assert!(!catalog.has_shell_fallback());

        // `tools = []` stays empty.
        let fixture = Fixture::new();
        fixture.user(
            "[[tools]]\nname = \"shell\"\ncommand = \"bash\"\ntools = []\npersist = [\".u\"]\n\
             [[tools]]\nname = \"sibling\"\ncommand = \"sibling\"\npersist = [\".s\"]\n",
        );
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(persist_of(&catalog, "shell"), [".u"]);
    }

    /// **Scope contract / ADR-0018.** The measured conjunction is total over its
    /// four Boolean rows, and a real origin pair is in scope only when both the
    /// tier and the declaring file match — so scope is never bare-name equality.
    #[test]
    fn reference_scope_is_the_tier_and_file_conjunction() {
        use ReferenceScopeFacts as Facts;
        for (facts, expected) in [
            (
                Facts {
                    same_tier: false,
                    same_file: false,
                },
                false,
            ),
            (
                Facts {
                    same_tier: false,
                    same_file: true,
                },
                false,
            ),
            (
                Facts {
                    same_tier: true,
                    same_file: false,
                },
                false,
            ),
            (
                Facts {
                    same_tier: true,
                    same_file: true,
                },
                true,
            ),
        ] {
            assert_eq!(reference_scope_matches(facts), expected);
        }

        let user = ToolOrigin::User(PathBuf::from("/home/u/config.toml"));
        let other_user = ToolOrigin::User(PathBuf::from("/home/u/other.toml"));
        let project = ToolOrigin::Project(PathBuf::from("/home/u/config.toml"));
        let builtin = ToolOrigin::BuiltIn;
        let scope = |declaring: &ToolOrigin, candidate: &ToolOrigin| {
            same_reference_scope(ReferenceOrigins {
                declaring,
                candidate,
            })
        };
        assert!(scope(&user, &user));
        assert!(!scope(&user, &other_user), "one tier, two declaring files");
        assert!(
            !scope(&user, &project),
            "equal declaring paths, different tiers"
        );
        assert!(!scope(&builtin, &user));
        assert!(scope(&builtin, &builtin));
    }

    /// **T3 / §A1.** The synthesized fallback `shell` (BuiltIn) is the only
    /// BuiltIn tool under a custom catalog, so its wildcard closes over itself
    /// alone and it provisions nothing.
    #[test]
    fn the_fallback_shell_under_a_custom_catalog_provisions_nothing() {
        let fixture = Fixture::new();
        fixture.user("[[tools]]\nname = \"solo\"\ncommand = \"solo\"\n");
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(
            provisioned_of(&catalog, "shell"),
            Vec::<CredentialProvider>::new()
        );
    }

    /// **T3 / §A1.** In the shipped default catalog every tool is BuiltIn, so
    /// `shell`'s wildcard still closes over all seven — the spec table is
    /// unchanged by the file-scoped rule. This pins the *reason* (origin
    /// equality), so a change to `default-tools.toml` or the fallback's origin
    /// is caught here.
    #[test]
    fn the_shipped_default_wildcard_covers_all_seven_builtin_tools() {
        use CredentialProvider::*;
        let catalog = Fixture::new()
            .load()
            .unwrap()
            .into_launch_catalog()
            .unwrap();
        assert_eq!(
            provisioned_of(&catalog, "shell"),
            vec![Anthropic, OpenAi, OpencodeStatic, Copilot]
        );
    }

    /// **T3 / §A1, the review's B3 inverted.** A project tool must **not** widen
    /// the user's wildcard `shell`: with each file scoped to itself, a project
    /// `credentials = ["copilot"]` cannot reach the user's shell. The user's
    /// shell also declares no `credentials`, and its `"*"` closes over its own
    /// file — which declares only `shell` itself — so the exact provisioned set
    /// is empty (review M1: the old `!contains(Copilot)` assertion passed for
    /// both `{}` and the pre-change `{anthropic, openai, opencode-static}`).
    #[test]
    fn a_project_tool_does_not_widen_the_users_wildcard_shell() {
        let fixture = Fixture::new();
        fixture
            .user("[[tools]]\nname = \"shell\"\ncommand = \"bash\"\n")
            .project("[[tools]]\nname = \"p\"\ncommand = \"p\"\ncredentials = [\"copilot\"]\n");
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(
            provisioned_of(&catalog, "shell"),
            Vec::<CredentialProvider>::new(),
            "a file whose only tool is `shell` provisions nothing"
        );
        let shell = catalog
            .as_slice()
            .iter()
            .find(|entry| entry.tool().name() == "shell")
            .unwrap()
            .tool();
        assert!(
            shell.credential_providers().iter().next().is_none(),
            "the user shell declares no credentials"
        );
    }

    /// **T4.** The `tools` validation rules, all rejections. The dangling rows
    /// assert the **full rendered string** (the diagnostic that drops the tier,
    /// file or declaration index is the regression this catches).
    #[test]
    fn tools_validation_rejects_the_malformed_shapes() {
        // `*` mixed with another entry.
        let fixture = Fixture::new();
        fixture.user("[[tools]]\nname = \"t\"\ncommand = \"t\"\ntools = [\"*\", \"claude\"]\n");
        let rendered = format!("{:#}", fixture.load().unwrap_err());
        assert!(rendered.contains("must be the only entry"), "{rendered}");

        // A dangling name in the *user* tier: the full string.
        let fixture = Fixture::new();
        fixture
            .user("[[tools]]\nname = \"t\"\ncommand = \"t\"\ntools = [\"nope\"]\n")
            .project("");
        let error = fixture.load().unwrap().into_launch_catalog().unwrap_err();
        assert_eq!(
            format!("{error:#}"),
            format!(
                "config: user config {} declaration [0] tool \"t\": tools[0]: \"nope\" names no tool in this configuration file; declare it in this file or remove the entry",
                crate::one_line::quoted_path(&fixture.user)
            )
        );

        // The same in the project tier names the *project* file.
        let fixture = Fixture::new();
        fixture.project("[[tools]]\nname = \"t\"\ncommand = \"t\"\ntools = [\"nope\"]\n");
        let error = fixture.load().unwrap().into_launch_catalog().unwrap_err();
        assert_eq!(
            format!("{error:#}"),
            format!(
                "config: project config {} declaration [0] tool \"t\": tools[0]: \"nope\" names no tool in this configuration file; declare it in this file or remove the entry",
                crate::one_line::quoted_path(&fixture.project)
            )
        );

        // `name = "*"` is reserved.
        let fixture = Fixture::new();
        fixture.user("[[tools]]\nname = \"*\"\ncommand = \"t\"\n");
        let rendered = format!("{:#}", fixture.load().unwrap_err());
        assert!(rendered.contains("reserved"), "{rendered}");

        // An empty entry names its index.
        let fixture = Fixture::new();
        fixture.user("[[tools]]\nname = \"t\"\ncommand = \"t\"\ntools = [\"\"]\n");
        let rendered = format!("{:#}", fixture.load().unwrap_err());
        assert!(rendered.contains("tools[0]"), "{rendered}");
        assert!(rendered.contains("must not be empty"), "{rendered}");
    }

    /// #329: one failure reads differently per tier, including the built-in
    /// catalog and the unnamed-declaration form.
    #[test]
    fn declaration_errors_name_the_tier() {
        let body = "[[tools]]\nname = \"t\"\ncommand = \"\"\n";
        let user = Fixture::new();
        user.user(body);
        let project = Fixture::new();
        project.project(body);
        for (rendered, origin) in [
            (
                user.load().unwrap_err().to_string(),
                format!("user config {}", crate::one_line::quoted_path(&user.user)),
            ),
            (
                project.load().unwrap_err().to_string(),
                format!(
                    "project config {}",
                    crate::one_line::quoted_path(&project.project)
                ),
            ),
            (
                tools_from_builtin_text(body).unwrap_err().to_string(),
                "built-in defaults \"default-tools.toml\"".to_string(),
            ),
        ] {
            assert_eq!(
                rendered,
                format!("config: {origin} declaration [0] tool \"t\": command must not be empty")
            );
        }

        let unnamed = Fixture::new();
        unnamed.project("[[tools]]\nname = \"\"\ncommand = \"t\"\n");
        assert_eq!(
            unnamed.load().unwrap_err().to_string(),
            format!(
                "config: project config {} declaration [0] tool: name must not be empty",
                crate::one_line::quoted_path(&unnamed.project)
            )
        );
    }

    /// #329: the built-in tier's deferred (dangling-reference) diagnostic is
    /// reachable only by editing the shipped catalog, so pin its exact text.
    #[test]
    fn built_in_deferred_declaration_error_is_pinned() {
        let tools = tools_from_builtin_text(
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\ntools = [\"nope\"]\n",
        )
        .unwrap();
        assert_eq!(
            resolve_provisioning(ResolvedTools::from_defaults(tools))
                .unwrap_err()
                .to_string(),
            "config: built-in defaults \"default-tools.toml\" declaration [0] tool \"t\": tools[0]: \"nope\" names no tool in this configuration file; declare it in this file or remove the entry"
        );
    }

    /// #329: the built-in tier's persist-ownership diagnostic names the tier
    /// and file for both claimants; reachable only by editing the catalog.
    #[test]
    fn built_in_persist_ownership_error_is_pinned() {
        let tools = tools_from_builtin_text(
            "[[tools]]\nname = \"a\"\ncommand = \"a\"\npersist = [\".x\"]\n\
             [[tools]]\nname = \"b\"\ncommand = \"b\"\npersist = [\".x\"]\n",
        )
        .unwrap();
        assert_eq!(
            validate_persist_ownership(tools.iter())
                .unwrap_err()
                .to_string(),
            "config: guest persist path \".x\" is claimed by tool \"a\" (built-in defaults \"default-tools.toml\") and tool \"b\" (built-in defaults \"default-tools.toml\"); remove or rename one claim"
        );
    }

    /// #329 F1: the ancestor/descendant *overlap* ownership template is a
    /// distinct branch from the equal-path one above; pin its full text — tier
    /// and file for both claimants — in both declaration orders. Reachable only
    /// by editing the shipped catalog.
    #[test]
    fn built_in_persist_ownership_overlap_error_is_pinned() {
        // Ancestor declared first, descendant second: the later tool offends.
        let tools = tools_from_builtin_text(
            "[[tools]]\nname = \"a\"\ncommand = \"a\"\npersist = [\".x\"]\n\
             [[tools]]\nname = \"b\"\ncommand = \"b\"\npersist = [\".x/a\"]\n",
        )
        .unwrap();
        assert_eq!(
            validate_persist_ownership(tools.iter())
                .unwrap_err()
                .to_string(),
            "config: guest persist path \".x/a\" declared by tool \"b\" (built-in defaults \"default-tools.toml\") overlaps \".x\" claimed by tool \"a\" (built-in defaults \"default-tools.toml\"); one would shadow the other"
        );

        // Reverse declaration order: descendant first, ancestor second.
        let tools = tools_from_builtin_text(
            "[[tools]]\nname = \"b\"\ncommand = \"b\"\npersist = [\".x/a\"]\n\
             [[tools]]\nname = \"a\"\ncommand = \"a\"\npersist = [\".x\"]\n",
        )
        .unwrap();
        assert_eq!(
            validate_persist_ownership(tools.iter())
                .unwrap_err()
                .to_string(),
            "config: guest persist path \".x\" declared by tool \"a\" (built-in defaults \"default-tools.toml\") overlaps \".x/a\" claimed by tool \"b\" (built-in defaults \"default-tools.toml\"); one would shadow the other"
        );
    }

    // -- interactive_shell ------------------------------------------------

    /// **T5.** `interactive_shell` round-trips, defaults to false, and
    /// participates in the conflict machinery, ordered last.
    #[test]
    fn interactive_shell_round_trips_defaults_false_and_orders_last() {
        let omitted = Fixture::new();
        omitted.user("[[tools]]\nname = \"t\"\ncommand = \"t\"\n");
        let explicit_false = Fixture::new();
        explicit_false
            .user("[[tools]]\nname = \"t\"\ncommand = \"t\"\ninteractive_shell = false\n");
        let a = omitted.load().unwrap();
        let b = explicit_false.load().unwrap();
        assert!(!first_launch(&a).is_interactive_shell());
        assert!(first_launch(&a).same_definition(first_launch(&b)));
        assert!(a.conflicts().is_empty());

        // A differing interactive_shell is a conflict, and is reported *last*
        // in the fixed field order even alongside another differing field.
        let base = "[[tools]]\nname = \"t\"\ncommand = \"t\"\nargs = [\"a\"]\ncredentials = [\"openai\"]\n";
        let fixture = Fixture::new();
        fixture.user(base).project(
            &format!("{base}interactive_shell = true\n")
                .replace("command = \"t\"", "command = \"t2\""),
        );
        let report = fixture.load().unwrap();
        assert_eq!(report.conflicts().len(), 1);
        assert_eq!(
            report.conflicts()[0].fields(),
            &[ToolField::Command, ToolField::InteractiveShell]
        );
        assert_eq!(ToolField::InteractiveShell.as_str(), "interactive_shell");
        // The user's definition (interactive_shell = false) wins.
        assert!(!first_launch(&report).is_interactive_shell());
    }

    #[test]
    fn omitted_and_explicit_empty_optional_lists_are_equivalent() {
        let omitted = Fixture::new();
        omitted.user("[[tools]]\nname = \"t\"\ncommand = \"t\"\n");
        let explicit = Fixture::new();
        explicit.user(
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\nargs = []\ncredentials = []\npersist = []\nnetwork_requests = []\n",
        );
        let a = omitted.load().unwrap();
        let b = explicit.load().unwrap();
        let (left, right) = (
            a.resolved().launch_tools().collect::<Vec<_>>(),
            b.resolved().launch_tools().collect::<Vec<_>>(),
        );
        assert!(left[0].same_definition(right[0]));
    }

    // -- env --------------------------------------------------------------

    /// **V1.** `env` round-trips key-sorted despite its declaration order (a
    /// `BTreeMap`, D4), counts entries for `doctor` without exposing them, and
    /// defaults to empty.
    #[test]
    fn env_round_trips_key_sorted_and_defaults_empty() {
        let fixture = Fixture::new();
        fixture.user("[[tools]]\nname = \"t\"\ncommand = \"t\"\nenv = { B = \"2\", A = \"1\" }\n");
        let report = fixture.load().unwrap();
        let tool = first_launch(&report);
        let pairs: Vec<(&str, &str)> = tool
            .guest_env()
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        assert_eq!(pairs, [("A", "1"), ("B", "2")]);
        assert_eq!(tool.env_count(), 2);

        let fixture = Fixture::new();
        fixture.user("[[tools]]\nname = \"t\"\ncommand = \"t\"\n");
        let report = fixture.load().unwrap();
        let tool = first_launch(&report);
        assert!(tool.guest_env().is_empty());
        assert_eq!(tool.env_count(), 0);
    }

    /// **V2.** Both sides of every `check_env_key` boundary, plus the value
    /// check. The accept cases for `PATH`/`IS_SANDBOX`/`LANG`/`TERM` are as
    /// load-bearing as the reject cases: they are the executable form of D3's
    /// split between "rejected at the config seam" (conditional launcher env)
    /// and "governed by emission position" (unconditional launcher env), and
    /// they fail if someone later hardens `check_env_key` into a general
    /// deny-list without reading D3 (F4c).
    #[test]
    fn env_key_and_value_validation_boundaries() {
        const IDENTITY: &str =
            "must not be declared by a tool (agent-vm owns the guest identity environment)";
        for (key, reason) in [
            ("", "must not be empty"),
            ("A=B", "must not contain '='"),
            ("A\u{0}B", "must not contain NUL"),
            ("A B", "must not contain whitespace or control characters"),
            (
                "A\u{1}B",
                "must not contain whitespace or control characters",
            ),
            (
                "MSB_FOO",
                "must not use the reserved MSB_ prefix (microsandbox owns it)",
            ),
            ("HOME", IDENTITY),
            ("USER", IDENTITY),
            ("LOGNAME", IDENTITY),
        ] {
            assert_eq!(check_env_key(key), Err(reason), "key {key:?}");
        }
        for key in [
            // Ordinary names, a leading digit, and lowercase are all fine: the
            // key is a passthrough, not a shell identifier.
            "A_1",
            "lowercase",
            "1LEADINGDIGIT",
            // Only the `MSB_` *prefix* is reserved — not a substring.
            "MSBX",
            "XMSB_",
            // The identity rejection is exact and case-sensitive, not a
            // substring or prefix match.
            "HOMEDIR",
            "MY_HOME",
            "home",
            // Launcher-owned but position-protected: deliberately accepted.
            "PATH",
            "IS_SANDBOX",
            "LANG",
            "TERM",
            // Ordinary tool-declarable keys: automatic host forwarding was
            // removed by #163. A declaration can already set `command`.
            "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY",
        ] {
            assert_eq!(check_env_key(key), Ok(()), "key {key:?}");
        }

        // An empty value, and one containing spaces, `=` and a newline, are
        // all legitimate ("set but empty" is meaningful).
        let ok = Fixture::new();
        ok.user(
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\nenv = { FOO = \"\", BAR = \"a b=c\\n\" }\n",
        );
        assert!(ok.load().is_ok());

        // A NUL in the *value* is rejected, and the value is never echoed (D6).
        const SENTINEL: &str = "SENTINEL_SECRET_abc123";
        let nul = Fixture::new();
        nul.user(&format!(
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\nenv = {{ FOO = \"{SENTINEL}\\u0000end\" }}\n"
        ));
        let error = nul.load().unwrap_err();
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("env \"FOO\": value must not contain NUL"),
            "{rendered}"
        );
        for rendered in [
            format!("{error}"),
            format!("{error:#}"),
            format!("{error:?}"),
        ] {
            assert!(!rendered.contains(SENTINEL), "secret leaked: {rendered}");
        }
    }

    /// **V2b (M3).** The `MSB_` prefix is rejected at the *config seam*, with
    /// the config file and the declaration index, exactly like every other
    /// `env` error — not as the vendored SDK's late, contextless `preparing
    /// sandbox config: …` failure. That diagnostic shape is the whole point of
    /// D3d; without the seam check the late error is all the user sees.
    #[test]
    fn env_key_with_msb_prefix_is_rejected_at_the_config_seam() {
        let fixture = Fixture::new();
        fixture.user("[[tools]]\nname = \"t\"\ncommand = \"t\"\nenv = { MSB_FOO = \"1\" }\n");
        let error = fixture.load().unwrap_err();
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("must not use the reserved MSB_ prefix (microsandbox owns it)"),
            "{rendered}"
        );
        assert!(rendered.contains("declaration [0]"), "{rendered}");
        assert!(
            rendered.contains(&fixture.user.to_string_lossy().into_owned()),
            "the diagnostic must name the config file: {rendered}"
        );
    }

    /// **V2c (D3c).** `HOME`/`USER`/`LOGNAME` are rejected in every mode, with
    /// the same `tool_error` shape as every other `env` error (file +
    /// declaration index), and the declared value is never echoed (D6). The
    /// rejection is unconditional because config validation cannot know about
    /// `--root`, where emission position would not protect these keys.
    #[test]
    fn env_key_naming_the_guest_identity_is_rejected() {
        for key in ["HOME", "USER", "LOGNAME"] {
            let fixture = Fixture::new();
            fixture.user(&format!(
                "[[tools]]\nname = \"t\"\ncommand = \"t\"\nenv = {{ {key} = \"/x\" }}\n"
            ));
            let error = fixture.load().unwrap_err();
            let rendered = format!("{error:#}");
            assert!(
                rendered.contains(
                    "must not be declared by a tool (agent-vm owns the guest identity environment)"
                ),
                "key={key}: {rendered}"
            );
            assert!(
                rendered.contains("declaration [0]"),
                "key={key}: {rendered}"
            );
            assert!(
                rendered.contains(&fixture.user.to_string_lossy().into_owned()),
                "key={key}: the diagnostic must name the config file: {rendered}"
            );
            assert!(
                !rendered.contains("/x"),
                "key={key}: the value must not be echoed: {rendered}"
            );
        }
    }

    /// **V5.** The shipped catalog declares `CODEX_HOME` on exactly `codex`
    /// and `shell`; `pi`, `opencode`, `claude` and `copilot` declare no env.
    /// This is the single assertion a future edit to `default-tools.toml` must
    /// consciously update (D2, F1).
    #[test]
    fn shipped_catalog_declares_codex_home_only_for_codex_and_shell() {
        for tool in default_tools().unwrap() {
            let pairs: Vec<(&str, &str)> = tool
                .guest_env()
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str()))
                .collect();
            match tool.name() {
                "codex" | "shell" => assert_eq!(
                    pairs,
                    [("CODEX_HOME", "/agent-vm-state/codex")],
                    "{}",
                    tool.name()
                ),
                "pi" | "opencode" | "claude" | "copilot" | "dsh" => {
                    assert!(pairs.is_empty(), "{} must declare no env", tool.name())
                }
                other => panic!("unexpected default tool {other}"),
            }
        }
    }

    #[test]
    fn unknown_keys_and_wrong_types_are_hard_errors() {
        for body in [
            "tool = []\n",                                              // typo of tools
            "tools = 3\n",                                              // wrong top-level type
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\nbogus = 1\n",    // unknown tool field
            "[[tools]]\nname = \"t\"\n",                                // missing command
            "[[tools]]\ncommand = \"t\"\n",                             // missing name
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\nargs = \"x\"\n", // wrong args type
            // AC4 (#162): pins that `allow_missing_credentials` is not a
            // config field at either level, so a config that tries to set it
            // is refused as an unknown key. This is the schema half of
            // "host-only"; it says nothing about any *other* way to reach the
            // flag (`--allow-missing-credentials` is a launch flag on
            // `run::Args`).
            "allow_missing_credentials = true\n",
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\nallow_missing_credentials = true\n",
        ] {
            let fixture = Fixture::new();
            fixture.user(body);
            let error = fixture.load().unwrap_err();
            let rendered = format!("{error:#}");
            assert!(
                rendered.contains("invalid TOML or tool schema"),
                "body={body:?} rendered={rendered}"
            );
        }
    }

    #[test]
    fn deserialize_errors_never_leak_values_and_include_location() {
        const SENTINEL: &str = "SENTINEL_SECRET_abc123";
        for body in [
            format!("[[tools]]\nname = \"t\"\ncommand = \"t\"\nargs = \"--api-key={SENTINEL}\"\n"),
            format!(
                "[[tools]]\nname = \"t\"\ncommand = \"t\"\nargs = [{{ token = \"{SENTINEL}\" }}]\n"
            ),
            format!("[[tools]]\nname = \"t\"\ncommand = \"t\"\nargs = [{SENTINEL}\n"),
        ] {
            let fixture = Fixture::new();
            fixture.user(&body);
            let error = fixture.load().unwrap_err();
            for rendered in [
                format!("{error}"),
                format!("{error:#}"),
                format!("{error:?}"),
            ] {
                assert!(!rendered.contains(SENTINEL), "secret leaked: {rendered}");
            }
            // Source location is the required discriminator for these errors.
            let rendered = format!("{error:#}");
            let location = rendered.split('"').nth(2).unwrap_or("");
            assert!(
                location.starts_with(':')
                    && location[1..].starts_with(|c: char| c.is_ascii_digit()),
                "expected file:line:col, got {rendered}"
            );
        }
    }

    #[test]
    fn invalid_utf8_is_rejected_with_fixed_guidance() {
        let fixture = Fixture::new();
        write_bytes(&fixture.user, &[0x74, 0x6f, 0x00, 0xff, 0xfe]);
        let error = fixture.load().unwrap_err();
        let rendered = format!("{error:#}");
        assert!(rendered.contains("not valid UTF-8"), "{rendered}");
    }

    // -- boot image --------------------------------------------------------

    #[test]
    fn a_top_level_image_is_parsed_in_each_tier_and_keeps_the_defaults() {
        let fixture = Fixture::new();
        fixture.user("image = \"localhost:1/user:latest\"\n");
        let report = fixture.load().unwrap();
        assert!(
            report.uses_defaults(),
            "an image-only file keeps the shipped tools"
        );
        assert_eq!(
            report.images().user().unwrap().reference().as_str(),
            "localhost:1/user:latest"
        );
        assert!(report.images().project().is_none());

        let fixture = Fixture::new();
        fixture.project("image = \"localhost:1/project:latest\"\ntools = []\n");
        let report = fixture.load().unwrap();
        assert!(
            report.uses_defaults(),
            "explicit tools=[] also keeps the defaults"
        );
        assert_eq!(
            report.images().project().unwrap().reference().as_str(),
            "localhost:1/project:latest"
        );
    }

    #[test]
    fn config_image_rejects_local_paths_naming_the_file_and_field() {
        for value in [
            "\"\"",
            "\" \"",
            "\"\\t\"",
            "\"/\"",
            "\"../rootfs\"",
            "\".\"",
        ] {
            let fixture = Fixture::new();
            fixture.user(&format!("image = {value}\n"));
            let rendered = format!("{:#}", fixture.load().unwrap_err());
            assert!(rendered.contains("image"), "value={value}: {rendered}");
            assert!(
                !rendered.contains("rootfs\"") && !rendered.contains("used value"),
                "value must not be echoed: {rendered}"
            );
        }
    }

    /// **#329.** The tier is promised only for *tool declaration* diagnostics
    /// (USAGE.md, "tool configuration"). The two other config-error shapes name
    /// the file but must not be decorated with a tier: a syntax error carries a
    /// line/column, and an image error has no declaration at all. Pinning the
    /// absence keeps that reference from over-claiming if either is ever routed
    /// through `describe_origin`.
    #[test]
    fn non_declaration_config_errors_name_no_tier() {
        for (label, body, expected) in [
            (
                "syntax",
                "this is not = = toml\n",
                "invalid TOML or tool schema",
            ),
            (
                "image",
                "image = \"not a valid image!!\"\n",
                "must be an OCI image reference",
            ),
        ] {
            let fixture = Fixture::new();
            fixture.user(body);
            let rendered = format!("{:#}", fixture.load().unwrap_err());
            assert!(rendered.contains(expected), "{label}: {rendered}");
            for tier in ["user config", "project config", "built-in defaults"] {
                assert!(
                    !rendered.contains(tier),
                    "{label} error names the {tier} tier: {rendered}"
                );
            }
        }
    }

    #[test]
    fn a_removed_layer_field_is_an_ordinary_schema_error() {
        for body in [
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\nlayer = { builtin = \"claude\" }\n",
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\nlayer = { path = \"x\" }\n",
        ] {
            let fixture = Fixture::new();
            fixture.user(body);
            let rendered = format!("{:#}", fixture.load().unwrap_err());
            assert!(
                rendered.contains("invalid TOML"),
                "body={body:?}: {rendered}"
            );
            assert!(!rendered.contains("migrat"), "{rendered}");
        }
    }

    // -- names, commands, providers ---------------------------------------

    #[test]
    fn every_reserved_name_is_rejected_but_launch_verbs_are_allowed() {
        for reserved in RESERVED_TOOL_NAMES {
            let fixture = Fixture::new();
            fixture.user(&one_tool(reserved));
            let error = fixture.load().unwrap_err();
            assert!(format!("{error:#}").contains("reserved"), "{reserved}");
        }
        for allowed in ["claude", "shell", "copilot", "custom", "build"] {
            let fixture = Fixture::new();
            fixture.user(&one_tool(allowed));
            assert!(fixture.load().is_ok(), "{allowed} should be allowed");
        }
    }

    #[test]
    fn unusable_names_are_rejected() {
        for name in [
            "",
            " ",
            "-x",
            "a b",
            "a\tb",
            "a\nb",
            "a/b",
            "/abs",
            "../..",
            "../../evil",
            ".",
            "..",
            "...",
        ] {
            let fixture = Fixture::new();
            let body = format!(
                "[[tools]]\nname = \"{}\"\ncommand = \"x\"\n",
                name.escape_debug()
            );
            fixture.user(&body);
            assert!(fixture.load().is_err(), "name={name:?} should be rejected");
        }
    }

    /// #161 widened this validator: a name is accepted if it is a valid
    /// keychain service name, because whether it is a built-in provider or a
    /// `credentials.yaml` authorization is a *launch* decision (and #162's
    /// precedence is resolved there, not here). What stays a config-parse error
    /// is a name that could not select a keychain item at all.
    #[test]
    fn credential_names_are_validated_as_service_names() {
        for valid in [
            "anthropic",
            "openai",
            "opencode-static",
            "copilot",
            "my-service",
        ] {
            let fixture = Fixture::new();
            fixture.user(&format!(
                "[[tools]]\nname = \"t\"\ncommand = \"t\"\ncredentials = [\"{valid}\"]\n"
            ));
            let report = fixture.load().unwrap_or_else(|error| {
                panic!("{valid} should be valid: {error:#}");
            });
            let tool = first_launch(&report);
            // Every declared name is carried forward for launch resolution,
            // whether or not a compiled-in provider claims it.
            assert_eq!(
                tool.credential_names()
                    .iter()
                    .map(|name| name.as_str())
                    .collect::<Vec<_>>(),
                vec![valid]
            );
            // The built-in projection is unchanged, and is what the
            // provisioning closure still consumes.
            assert_eq!(
                tool.credential_providers()
                    .iter()
                    .map(|provider| provider.config_name())
                    .collect::<Vec<_>>(),
                crate::credential_provider::CredentialProvider::from_config_name(valid)
                    .map(|provider| vec![provider.config_name()])
                    .unwrap_or_default()
            );
        }
        // The doctor label `opencode` is still not the config name; it is
        // simply now a valid *request* that launch resolution will refuse with
        // the both-lookup-locations message. What fails here is a name that
        // cannot be a keychain item.
        for invalid in ["opencode!", "-nope", "", "a b"] {
            let fixture = Fixture::new();
            fixture.user(&format!(
                "[[tools]]\nname = \"t\"\ncommand = \"t\"\ncredentials = [\"{invalid}\"]\n"
            ));
            let error = fixture.load().unwrap_err();
            let rendered = format!("{error:#}");
            assert!(
                rendered.contains("not a valid name"),
                "{invalid}: {rendered}"
            );
            assert!(
                rendered.contains("opencode-static"),
                "{invalid}: {rendered}"
            );
        }
    }

    // -- persist normalization --------------------------------------------

    #[test]
    fn persist_accepts_and_normalizes_safe_relative_paths() {
        let fixture = Fixture::new();
        fixture.user("[[tools]]\nname = \"t\"\ncommand = \"t\"\npersist = [\"a\", \"b\"]\n");
        let report = fixture.load().unwrap();
        assert_eq!(first_launch(&report).persist_count(), 2);

        let fixture = Fixture::new();
        fixture.user(
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\npersist = [\"./.cache//mytool/\", \"a..b\"]\n",
        );
        let report = fixture.load().unwrap();
        let tool = first_launch(&report);
        assert_eq!(tool.persist[0].as_path(), Path::new(".cache/mytool"));
        assert_eq!(tool.persist[1].as_path(), Path::new("a..b"));
    }

    #[test]
    fn persist_rejects_traversal_absolute_and_root_equivalent_paths() {
        for path in [
            "/tmp/token",
            "../token",
            "x/../token",
            "a/..",
            ".",
            "./",
            "",
            "a/./..",
        ] {
            let fixture = Fixture::new();
            fixture.user(&format!(
                "[[tools]]\nname = \"t\"\ncommand = \"t\"\npersist = [\"{path}\"]\n"
            ));
            assert!(
                fixture.load().is_err(),
                "persist={path:?} should be rejected"
            );
        }
    }

    #[test]
    fn a_repeated_persist_entry_within_one_tool_is_rejected() {
        let fixture = Fixture::new();
        fixture.user(
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\npersist = [\"cache/x\", \"./cache/x/\"]\n",
        );
        let error = fixture.load().unwrap_err();
        assert!(format!("{error:#}").contains("duplicate"), "{error:#}");
    }

    // -- merge -------------------------------------------------------------

    #[test]
    fn order_is_user_then_project_only_never_alphabetical() {
        let fixture = Fixture::new();
        fixture
            .user("[[tools]]\nname = \"z\"\ncommand = \"z\"\n[[tools]]\nname = \"a\"\ncommand = \"a\"\n")
            .project(
                "[[tools]]\nname = \"b\"\ncommand = \"b\"\n[[tools]]\nname = \"a\"\ncommand = \"a\"\n[[tools]]\nname = \"c\"\ncommand = \"c\"\n",
            );
        let report = fixture.load().unwrap();
        let names: Vec<_> = report.resolved().launch_tools().map(Tool::name).collect();
        assert_eq!(names, ["z", "a", "b", "c"]);
    }

    #[test]
    fn identical_cross_tier_definitions_dedupe_silently() {
        let fixture = Fixture::new();
        fixture.user(&one_tool("dup")).project(&one_tool("dup"));
        let report = fixture.load().unwrap();
        assert!(report.conflicts().is_empty());
        let tools: Vec<&Tool> = report.resolved().launch_tools().collect();
        assert_eq!(tools.len(), 1);
        // The winner keeps user provenance.
        assert_eq!(tools[0].origin(), &ToolOrigin::User(fixture.user.clone()));
    }

    #[test]
    fn each_differing_field_is_reported_individually_in_fixed_order() {
        let base = "[[tools]]\nname = \"t\"\ncommand = \"cmd\"\nargs = [\"a\"]\ncredentials = [\"openai\"]\ntools = [\"base\"]\npersist = [\"p\"]\ninteractive_shell = false\nenv = { A = \"1\" }\nnetwork_requests = [\"a.example\"]\n";
        let cases = [
            ("command = \"other\"", ToolField::Command),
            ("args = [\"b\"]", ToolField::Args),
            ("credentials = [\"anthropic\"]", ToolField::Credentials),
            ("tools = [\"other\"]", ToolField::Tools),
            ("persist = [\"q\"]", ToolField::Persist),
            ("interactive_shell = true", ToolField::InteractiveShell),
            ("env = { A = \"2\" }", ToolField::Env),
            (
                "network_requests = [\"b.example\"]",
                ToolField::NetworkRequests,
            ),
        ];
        for (mutated, expected) in cases {
            let project_body = base.replace(
                match expected {
                    ToolField::Command => "command = \"cmd\"",
                    ToolField::Args => "args = [\"a\"]",
                    ToolField::Credentials => "credentials = [\"openai\"]",
                    ToolField::Tools => "tools = [\"base\"]",
                    ToolField::Persist => "persist = [\"p\"]",
                    ToolField::InteractiveShell => "interactive_shell = false",
                    ToolField::Env => "env = { A = \"1\" }",
                    ToolField::NetworkRequests => "network_requests = [\"a.example\"]",
                },
                mutated,
            );
            let fixture = Fixture::new();
            fixture.user(base).project(&project_body);
            let report = fixture.load().unwrap();
            let conflicts = report.conflicts();
            assert_eq!(conflicts.len(), 1, "case {expected:?}");
            assert_eq!(conflicts[0].fields(), &[expected]);
            // User definition (whole) wins.
            assert_eq!(report.resolved().launch_tools().len(), 1);
            assert_eq!(
                first_launch(&report).origin(),
                &ToolOrigin::User(fixture.user.clone())
            );
        }

        // New fields stay last so existing warning ordering does not change.
        let project_body = base
            .replace("interactive_shell = false", "interactive_shell = true")
            .replace("env = { A = \"1\" }", "env = { A = \"2\" }")
            .replace(
                "network_requests = [\"a.example\"]",
                "network_requests = [\"b.example\"]",
            );
        let fixture = Fixture::new();
        fixture.user(base).project(&project_body);
        let report = fixture.load().unwrap();
        assert_eq!(report.conflicts().len(), 1);
        assert_eq!(
            report.conflicts()[0].fields(),
            &[
                ToolField::InteractiveShell,
                ToolField::Env,
                ToolField::NetworkRequests
            ],
            "network_requests must be reported last"
        );
        assert_eq!(ToolField::Env.as_str(), "env");
    }

    #[test]
    fn multiple_differing_fields_are_ordered_and_project_order_is_preserved() {
        let fixture = Fixture::new();
        fixture
            .user("[[tools]]\nname = \"a\"\ncommand = \"a\"\nargs = [\"1\"]\n[[tools]]\nname = \"b\"\ncommand = \"b\"\n")
            .project(
                "[[tools]]\nname = \"b\"\ncommand = \"b2\"\n[[tools]]\nname = \"a\"\ncommand = \"a2\"\nargs = [\"1\"]\ncredentials = [\"anthropic\"]\n",
            );
        let report = fixture.load().unwrap();
        let conflicts = report.conflicts();
        assert_eq!(conflicts.len(), 2);
        assert_eq!(conflicts[0].tool(), "b");
        assert_eq!(conflicts[0].fields(), &[ToolField::Command]);
        assert_eq!(conflicts[1].tool(), "a");
        assert_eq!(
            conflicts[1].fields(),
            &[ToolField::Command, ToolField::Credentials]
        );
    }

    #[test]
    fn a_repo_cannot_fill_in_an_omitted_user_field() {
        // User omits credentials/persist; the project supplying them is
        // a conflict, not a merge — the user's empty values are authoritative.
        let fixture = Fixture::new();
        fixture
            .user("[[tools]]\nname = \"t\"\ncommand = \"t\"\n")
            .project("[[tools]]\nname = \"t\"\ncommand = \"t\"\ncredentials = [\"anthropic\"]\n");
        let report = fixture.load().unwrap();
        assert_eq!(report.conflicts().len(), 1);
        assert_eq!(report.conflicts()[0].fields(), &[ToolField::Credentials]);
    }

    #[test]
    fn same_tier_duplicate_names_fail_even_when_identical() {
        let fixture = Fixture::new();
        fixture.user(&format!("{}{}", one_tool("dup"), one_tool("dup")));
        let error = fixture.load().unwrap_err();
        assert!(format!("{error:#}").contains("duplicate"), "{error:#}");
    }

    #[test]
    fn reversed_argv_is_an_args_conflict() {
        let fixture = Fixture::new();
        fixture
            .user("[[tools]]\nname = \"t\"\ncommand = \"t\"\nargs = [\"a\", \"b\"]\n")
            .project("[[tools]]\nname = \"t\"\ncommand = \"t\"\nargs = [\"b\", \"a\"]\n");
        let report = fixture.load().unwrap();
        assert_eq!(report.conflicts()[0].fields(), &[ToolField::Args]);
    }

    // -- persist ownership -------------------------------------------------

    #[test]
    fn two_tools_claiming_one_normalized_path_fail_naming_both() {
        let fixture = Fixture::new();
        fixture.user(
            "[[tools]]\nname = \"one\"\ncommand = \"one\"\npersist = [\"./cache//x/\"]\n[[tools]]\nname = \"two\"\ncommand = \"two\"\npersist = [\"cache/x\"]\n",
        );
        let error = fixture.load().unwrap_err();
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("one") && rendered.contains("two"),
            "{rendered}"
        );
        assert!(rendered.contains("cache/x"), "{rendered}");
    }

    #[test]
    fn project_winner_colliding_with_user_winner_fails() {
        let fixture = Fixture::new();
        fixture
            .user("[[tools]]\nname = \"u\"\ncommand = \"u\"\npersist = [\"shared/x\"]\n")
            .project("[[tools]]\nname = \"p\"\ncommand = \"p\"\npersist = [\"shared/x\"]\n");
        assert!(fixture.load().is_err());
    }

    #[test]
    fn a_shadowed_losers_persist_claim_does_not_conflict() {
        // The project's `dup` loses to the user's `dup`, so its (would-be)
        // claim on `shared/x` is abandoned; only `other` claims it.
        let fixture = Fixture::new();
        fixture
            .user("[[tools]]\nname = \"dup\"\ncommand = \"dup\"\npersist = [\"p\"]\n[[tools]]\nname = \"other\"\ncommand = \"other\"\npersist = [\"shared/x\"]\n")
            .project("[[tools]]\nname = \"dup\"\ncommand = \"dup-different\"\npersist = [\"shared/x\"]\n");
        let report = fixture.load().unwrap();
        assert_eq!(report.resolved().launch_tools().len(), 2);
    }

    #[test]
    fn an_invalid_shadowed_project_declaration_still_fails() {
        let fixture = Fixture::new();
        fixture
            .user("[[tools]]\nname = \"dup\"\ncommand = \"dup\"\npersist = [\"p\"]\n")
            .project("[[tools]]\nname = \"dup\"\ncommand = \"dup\"\npersist = [\"../escape\"]\n");
        assert!(fixture.load().is_err(), "the loser must still be validated");
    }

    // -- overlap predicate and the #83 rejections -------------------------

    /// **V1.** The overlap predicate, by table. Component-wise, not
    /// string-prefix: `.cache` overlaps `.cache/x` but not `.cachex`.
    #[test]
    fn overlap_predicate_matches_the_table() {
        let cases: &[(&str, &str, bool)] = &[
            (".cache", ".cache/x", true),
            (".cache/x", ".cache", true),
            (".cache", ".cachex", false),
            (".cache", ".cache", true),
            ("a/b/c", "a/b", true),
            ("a", "b", false),
            ("a/b", "a/bc", false),
        ];
        for (a, b, expected) in cases {
            assert_eq!(
                guest_paths_overlap(Path::new(a), Path::new(b)),
                *expected,
                "overlap({a}, {b})"
            );
            // Symmetry is part of the contract.
            assert_eq!(
                guest_paths_overlap(Path::new(b), Path::new(a)),
                *expected,
                "overlap({b}, {a})"
            );
        }
    }

    /// **V3 (ADR-0020's containment half).** The kernel is *directional*, by
    /// table. `/a/pi` contains `/a/pi` and `/a/pi/x`, but not `/a/pistachio`
    /// (the separator rule) and not its own parent. `/` is deliberately *not*
    /// a containment hit for an unrelated path — `measure` records `/` itself
    /// as a route, so the identity half is what covers it.
    #[test]
    fn byte_path_contains_is_directional_and_component_wise() {
        let cases: &[(&str, &str, bool)] = &[
            ("/a/pi", "/a/pi", true),
            ("/a/pi", "/a/pi/x", true),
            ("/a/pi", "/a/pistachio", false),
            ("/a/pi/x", "/a/pi", false),
            ("/", "/a", false),
            ("/a", "/", false),
            ("/a", "/a", true),
            // A *relative* path must hit the separator check too: the kernel
            // must not require a leading `/` (a mutant that does survives only
            // the independent-draw proptest; see the correlated oracle below).
            ("a", "a/a", true),
            ("a", "a", true),
            ("a/a", "a", false),
            ("a/b/c", "a/b", false),
        ];
        for (a, b, expected) in cases {
            assert_eq!(
                byte_path_contains(a.as_bytes(), b.as_bytes()),
                *expected,
                "contains({a}, {b})"
            );
        }
    }

    /// **V2.** The overlap rejections surface through `load`, each naming the
    /// offending `persist` index and the mechanism, never a secret.
    #[test]
    fn persist_overlap_rejections_surface_through_load() {
        // (a) Both paths in one tool: ancestor first, descendant second.
        let fixture = Fixture::new();
        fixture.user(
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\npersist = [\".cache\", \".cache/x\"]\n",
        );
        let rendered = format!("{:#}", fixture.load().unwrap_err());
        assert!(rendered.contains("persist[1]"), "{rendered}");
        assert!(
            rendered.contains("overlaps this tool's persist path"),
            "{rendered}"
        );

        // (b) Across two tools: the later claimant names both tools.
        let fixture = Fixture::new();
        fixture.user(
            "[[tools]]\nname = \"one\"\ncommand = \"one\"\npersist = [\".cache\"]\n[[tools]]\nname = \"two\"\ncommand = \"two\"\npersist = [\".cache/x\"]\n",
        );
        let rendered = format!("{:#}", fixture.load().unwrap_err());
        assert!(
            rendered.contains("one") && rendered.contains("two"),
            "{rendered}"
        );
        assert!(rendered.contains("overlaps"), "{rendered}");

        // (c)-(e) Reserved compiled-in links: equal, ancestor, descendant.
        for path in [".claude", ".config", ".local/share/opencode/sub"] {
            let fixture = Fixture::new();
            fixture.user(&format!(
                "[[tools]]\nname = \"t\"\ncommand = \"t\"\npersist = [\"{path}\"]\n"
            ));
            let rendered = format!("{:#}", fixture.load().unwrap_err());
            assert!(
                rendered.contains("overlaps the reserved guest HOME path"),
                "persist={path:?}: {rendered}"
            );
        }

        // The negative: a string prefix that is not a component prefix loads.
        let fixture = Fixture::new();
        fixture.user(
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\npersist = [\".cache\", \".cachex\"]\n",
        );
        assert!(fixture.load().is_ok(), ".cachex must not overlap .cache");

        // A path sharing a compiled link's *parent* is allowed: `.config/mytool`
        // sits beside `.config/gh`/`.config/opencode`, not inside either.
        let fixture = Fixture::new();
        fixture.user(
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\npersist = [\".config/mytool\", \".local/share/mytool\"]\n",
        );
        assert!(
            fixture.load().is_ok(),
            "sibling-of-a-compiled-link must load"
        );
    }

    /// V6 (#96): the new compiled `.pi` link turns both `.pi` and `.pi/agent`
    /// into hard errors, component-wise. `.pix` shares only a string prefix
    /// and must still load.
    #[test]
    fn persist_claiming_the_compiled_pi_link_is_rejected() {
        for path in [".pi", ".pi/agent"] {
            let fixture = Fixture::new();
            fixture.user(&format!(
                "[[tools]]\nname = \"t\"\ncommand = \"t\"\npersist = [\"{path}\"]\n"
            ));
            let rendered = format!("{:#}", fixture.load().unwrap_err());
            assert!(
                rendered.contains("overlaps the reserved guest HOME path .pi"),
                "persist={path:?}: {rendered}"
            );
        }

        let fixture = Fixture::new();
        fixture.user("[[tools]]\nname = \"t\"\ncommand = \"t\"\npersist = [\".pix\"]\n");
        assert!(
            fixture.load().is_ok(),
            ".pix must not overlap .pi (component-wise, not string-prefix)"
        );
    }

    /// **V3.** `provisioned()` is unchanged for every embedded default entry by
    /// the `launch_closure` refactor. Two deliberate exceptions are both on
    /// `pi`: `tools = ["claude"]` (the image-owned pi-claude-bridge extension
    /// needs Claude Code's own credential) and `tools = ["codex"]` (the
    /// image-owned agent-vm-codex extension needs the `codex/auth.json`
    /// placeholder, ADR-0044), so it now provisions Anthropic and OpenAI while
    /// still requiring nothing.
    #[test]
    fn default_catalog_provisioning_is_unchanged() {
        use CredentialProvider::*;
        let catalog = Fixture::new()
            .load()
            .unwrap()
            .into_launch_catalog()
            .unwrap();
        let observed: Vec<(&str, Vec<CredentialProvider>)> = catalog
            .as_slice()
            .iter()
            .map(|entry| (entry.tool().name(), entry.provisioned().iter().collect()))
            .collect();
        assert_eq!(
            observed,
            vec![
                ("dsh", vec![]),
                ("pi", vec![Anthropic, OpenAi]),
                ("codex", vec![OpenAi]),
                ("opencode", vec![OpenAi, OpencodeStatic]),
                ("claude", vec![Anthropic]),
                ("copilot", vec![Copilot]),
                ("shell", vec![Anthropic, OpenAi, OpencodeStatic, Copilot]),
            ]
        );
    }

    /// **V3.** `persist` folds over the same closure, in **catalog** not
    /// traversal order, and a cycle is a fixed point.
    #[test]
    fn persist_paths_fold_over_the_closure_in_catalog_order() {
        let fixture = Fixture::new();
        fixture.user(
            "[[tools]]\nname = \"a\"\ncommand = \"a\"\npersist = [\"x\"]\n\
             [[tools]]\nname = \"b\"\ncommand = \"b\"\ntools = [\"a\"]\npersist = [\"y\"]\n\
             [[tools]]\nname = \"shell\"\ncommand = \"bash\"\n",
        );
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(persist_of(&catalog, "a"), vec!["x"]);
        assert_eq!(persist_of(&catalog, "b"), vec!["x", "y"]);
        // `shell`'s omitted `tools` is the wildcard over its own file, which
        // declares `a`, `b` and `shell`.
        assert_eq!(persist_of(&catalog, "shell"), vec!["x", "y"]);

        // A cycle is a fixed point, and the union still folds in catalog order.
        let fixture = Fixture::new();
        fixture.user(
            "[[tools]]\nname = \"a\"\ncommand = \"a\"\ntools = [\"b\"]\npersist = [\"x\"]\n\
             [[tools]]\nname = \"b\"\ncommand = \"b\"\ntools = [\"a\"]\npersist = [\"y\"]\n",
        );
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(persist_of(&catalog, "a"), vec!["x", "y"]);
        assert_eq!(persist_of(&catalog, "b"), vec!["x", "y"]);
    }

    // -- filesystem limits and special files ------------------------------

    #[test]
    fn a_file_at_the_size_cap_is_readable_and_one_over_fails() {
        let at_cap = Fixture::new();
        write_file(
            &at_cap.user,
            &padded_config_to(MAX_CONFIG_FILE_BYTES as usize),
        );
        assert_eq!(
            fs::metadata(&at_cap.user).unwrap().len(),
            MAX_CONFIG_FILE_BYTES
        );
        assert!(at_cap.load().is_ok());

        let over = Fixture::new();
        write_file(
            &over.user,
            &padded_config_to(MAX_CONFIG_FILE_BYTES as usize + 1),
        );
        let error = over.load().unwrap_err();
        assert!(format!("{error:#}").contains("size limit"), "{error:#}");
    }

    /// A valid config padded with comment bytes to exactly `size` bytes.
    fn padded_config_to(size: usize) -> String {
        let mut body = one_tool("t");
        assert!(body.len() < size);
        body.push_str(&"#".repeat(size - body.len() - 1));
        body.push('\n');
        assert_eq!(body.len(), size);
        body
    }

    #[test]
    fn directories_fifos_and_dangling_symlinks_fail_promptly() {
        let dir_case = Fixture::new();
        fs::create_dir_all(&dir_case.user).unwrap();
        assert!(dir_case.load().is_err());

        let fifo_case = Fixture::new();
        fs::create_dir_all(fifo_case.user.parent().unwrap()).unwrap();
        let c_path = std::ffi::CString::new(fifo_case.user.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        let error = fifo_case.load().unwrap_err();
        assert!(
            format!("{error:#}").contains("not a regular file"),
            "{error:#}"
        );

        let dangling = Fixture::new();
        fs::create_dir_all(dangling.user.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink("/nonexistent/target", &dangling.user).unwrap();
        assert!(dangling.load().is_err());
    }

    #[test]
    fn a_symlink_to_a_regular_file_is_accepted() {
        let fixture = Fixture::new();
        let target = fixture.user.with_extension("real.toml");
        write_file(&target, &one_tool("t"));
        fs::create_dir_all(fixture.user.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&target, &fixture.user).unwrap();
        assert!(fixture.load().is_ok());
    }

    // -- the filesystem diagnostic boundary --------------------------------

    #[test]
    fn control_bytes_in_a_project_path_are_escaped_in_every_error_chain() {
        let root = tempfile::tempdir().unwrap();
        let evil = root.path().join("proj\n\x1b[31mred");
        fs::create_dir_all(&evil).unwrap();
        fs::create_dir_all(evil.join(".agent-vm/config.toml")).unwrap();
        let paths = ConfigPaths {
            user: None,
            project: evil.join(".agent-vm/config.toml"),

            home: None,
        };
        let error = load(&paths).unwrap_err();
        for rendered in [
            format!("{error}"),
            format!("{error:#}"),
            format!("{error:?}"),
        ] {
            assert!(!rendered.contains('\x1b'), "raw ESC leaked: {rendered:?}");
            assert!(
                !rendered.contains("proj\n"),
                "raw newline leaked: {rendered:?}"
            );
        }
        let rendered = format!("{error:#}");
        assert!(rendered.contains("not a regular file"), "{rendered}");
        assert!(
            rendered.contains("\\x1b"),
            "ESC should be escaped: {rendered}"
        );
        assert!(
            rendered.contains("\\x0a") || rendered.contains("proj\\x0a"),
            "{rendered}"
        );
    }

    /// **#329.** `describe_origin` is now the only place declaration errors
    /// render the path, so a hostile project path must still be escaped there
    /// (the sibling "not a regular file" test never reaches a declaration).
    #[test]
    fn control_bytes_are_escaped_in_a_declaration_error() {
        let root = tempfile::tempdir().unwrap();
        let evil = root.path().join("proj\n\x1b[31mred");
        write_file(
            &evil.join(".agent-vm/config.toml"),
            "[[tools]]\nname = \"t\"\ncommand = \"\"\n",
        );
        let paths = ConfigPaths {
            user: None,
            project: evil.join(".agent-vm/config.toml"),

            home: None,
        };
        let rendered = format!("{:#}", load(&paths).unwrap_err());
        assert!(!rendered.contains('\x1b'), "raw ESC leaked: {rendered:?}");
        assert!(!rendered.contains('\n'), "raw newline leaked: {rendered:?}");
        assert!(
            rendered.contains("project config"),
            "tier missing: {rendered}"
        );
        assert!(
            rendered.contains("\\x1b"),
            "ESC should be escaped: {rendered}"
        );
        assert!(
            rendered.contains("\\x0a"),
            "newline should be escaped: {rendered}"
        );
    }

    /// Both halves of a read failure keep the measured path legible: the quoted
    /// file the message is about, and the cause text that repeats it (issue #420).
    /// `safe_io_error` covers metadata discovery, `safe_anyhow_error` the reader's
    /// cause chain; neither has another path through a test fixture.
    #[test]
    fn a_read_failure_names_its_non_ascii_path_once_per_copy() {
        let path = Path::new("/home/boger/дом/.config/agent-vm/config.toml");
        let rendered = path.display().to_string();

        let io = safe_io_error(
            "reading metadata for",
            path,
            &std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("{rendered} is not a regular file"),
            ),
        )
        .to_string();
        let read = safe_anyhow_error(
            "reading",
            path,
            &anyhow::anyhow!("{rendered} is not a regular file"),
        )
        .to_string();

        for (site, message) in [("safe_io_error", io), ("safe_anyhow_error", read)] {
            assert_eq!(
                message.matches("дом").count(),
                2,
                "{site} should print both copies as themselves: {message}"
            );
            assert!(!message.contains("\\xd0"), "{site} byte-escaped: {message}");
        }
    }

    /// The sanitizers still have to do their original job: a cause carrying a
    /// newline or ESC must not end the line or reach the terminal.
    #[test]
    fn a_read_failure_cause_cannot_forge_a_line() {
        let path = Path::new("/home/boger/config.toml");
        let hostile = "x\nFORGED: config: user config /etc\u{1b}[31m";

        let io = safe_io_error(
            "reading metadata for",
            path,
            &std::io::Error::other(hostile),
        )
        .to_string();
        let read = safe_anyhow_error("reading", path, &anyhow::anyhow!(hostile)).to_string();

        for message in [io, read] {
            assert!(!message.contains('\n'), "newline survived: {message:?}");
            assert!(!message.contains('\u{1b}'), "ESC survived: {message:?}");
            assert!(message.contains("\\x0a"), "newline escaped: {message:?}");
            assert_eq!(message.lines().count(), 1, "one line: {message:?}");
        }
    }

    #[test]
    fn non_utf8_bytes_in_a_config_chosen_path_are_escaped() {
        // macOS filesystems reject invalid-UTF-8 filenames, so exercise the
        // escape policy directly. A *measured* path with the same bytes is
        // `one_line::path`'s business, which escapes them without quoting;
        // a config-chosen one is quoted and byte-escaped, so two entries that
        // differ only here cannot print alike.
        let path = PathBuf::from(std::ffi::OsStr::from_bytes(b"proj\xff\xfe\x1b"));
        let rendered = quoted_path(&path);
        assert_eq!(rendered, "\"proj\\xff\\xfe\\x1b\"");
        assert!(!rendered.contains('\u{fffd}'));
        assert!(!rendered.contains('\x1b'));
    }

    // -- discovery ---------------------------------------------------------

    #[test]
    fn discover_uses_the_canonical_cwd_and_literal_home_relative_path() {
        // Discovery reads real env; assert only the composition the code
        // documents. The env-dependent path is exercised end-to-end by the
        // subprocess tests.
        let project = discover_project_path().unwrap();
        assert!(project.ends_with(PROJECT_CONFIG_RELATIVE));
        assert!(project.is_absolute());
    }

    // -- properties --------------------------------------------------------

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(48))]

        /// Generated unique vs overlapping names: the result is exactly the
        /// user order followed by project-only names, and every overlap keeps
        /// the user's definition.
        #[test]
        fn merge_order_and_precedence_are_exact(
            user_names in proptest::collection::vec("[a-z]{1,6}", 0..5),
            project_names in proptest::collection::vec("[a-z]{1,6}", 0..5),
        ) {
            let unique_user = dedupe(user_names);
            let unique_project = dedupe(project_names);
            // Both empty activates the compiled-in defaults, a different path
            // than the merge this property characterizes.
            proptest::prop_assume!(!(unique_user.is_empty() && unique_project.is_empty()));

            let user_body: String = unique_user.iter().map(|name| format!("[[tools]]\nname = \"{name}\"\ncommand = \"user-{name}\"\n")).collect();
            let project_body: String = unique_project.iter().map(|name| format!("[[tools]]\nname = \"{name}\"\ncommand = \"proj-{name}\"\n")).collect();

            let fixture = Fixture::new();
            fixture.user(&user_body).project(&project_body);
            let report = fixture.load().unwrap();

            let mut expected: Vec<String> = unique_user.clone();
            for name in &unique_project {
                if !unique_user.contains(name) {
                    expected.push(name.clone());
                }
            }
            let actual: Vec<String> = report.resolved().launch_tools().map(|t| t.name().to_string()).collect();
            proptest::prop_assert_eq!(actual, expected);

            // Every overlap's definition must equal the user's.
            for name in &unique_user {
                if unique_project.contains(name) {
                    let tool = report.resolved().launch_tools().find(|t| t.name() == name).unwrap();
                    proptest::prop_assert_eq!(tool.command(), &format!("user-{name}"));
                }
            }
        }

        /// Duplicating a catalog across both tiers is an idempotent dedupe.
        #[test]
        fn duplicating_a_catalog_across_tiers_is_idempotent(
            names in proptest::collection::vec("[a-z]{1,6}", 1..5),
        ) {
            let unique = dedupe(names);
            let body: String = unique.iter().map(|name| format!("[[tools]]\nname = \"{name}\"\ncommand = \"{name}\"\n")).collect();
            let fixture = Fixture::new();
            fixture.user(&body).project(&body);
            let report = fixture.load().unwrap();
            let actual: Vec<String> = report.resolved().launch_tools().map(|t| t.name().to_string()).collect();
            proptest::prop_assert_eq!(actual, unique);
            proptest::prop_assert!(report.conflicts().is_empty());
        }

        /// Normalized persist identity is invariant under harmless `./` and
        /// separator spellings.
        #[test]
        fn persist_normalization_is_invariant(
            first in "[a-z]{1,5}",
            second in "[a-z]{1,5}",
        ) {
            let spellings = [
                format!("{first}/{second}"),
                format!("./{first}/{second}/"),
                format!("{first}//{second}"),
                format!("{first}/{second}"),
            ];
            let normalized: Vec<_> = spellings.iter().map(|s| normalize_persist(s).unwrap()).collect();
            for path in &normalized {
                proptest::prop_assert_eq!(path, &normalized[0]);
            }
        }

        /// **T7.1 / T7.4.** Every generated catalog resolves (termination,
        /// including the self-edges and cycles unconstrained indices produce)
        /// and `credentials(t) ⊆ provisioning(t)` for every tool.
        #[test]
        fn credentials_are_a_subset_of_provisioning_and_resolution_terminates(
            specs in proptest::collection::vec(
                (
                    proptest::collection::vec(0u8..4, 0..3),
                    proptest::collection::vec(0usize..5, 0..3),
                ),
                1..5,
            ),
        ) {
            let catalog = single_file_catalog(&specs);
            for (index, (credentials, _edges)) in specs.iter().enumerate() {
                let provisioned = provisioned_set(&catalog, &format!("t{index}"));
                for credential in credentials {
                    let provider = provider_from_u8(*credential);
                    proptest::prop_assert!(
                        provisioned.contains(&provider),
                        "t{index} lost {provider:?}"
                    );
                }
            }
        }

        /// **T7.2.** Adding a `tools` edge `t0 → t{target}` never shrinks `t0`'s
        /// provisioning set, and the result is a superset of the target's.
        #[test]
        fn adding_a_tools_edge_never_shrinks_provisioning(
            specs in proptest::collection::vec(
                (
                    proptest::collection::vec(0u8..4, 0..3),
                    proptest::collection::vec(0usize..5, 0..3),
                ),
                1..5,
            ),
            target in 0usize..5,
        ) {
            let n = specs.len();
            let target = target % n;
            let before = single_file_catalog(&specs);
            let mut extended = specs.clone();
            extended[0].1.push(target);
            let after = single_file_catalog(&extended);
            let before_set = provisioned_set(&before, "t0");
            let after_set = provisioned_set(&after, "t0");
            proptest::prop_assert!(after_set.is_superset(&before_set));
            let target_set = provisioned_set(&after, &format!("t{target}"));
            proptest::prop_assert!(after_set.is_superset(&target_set));
        }

        /// **T7.3.** With every generated tool in one file, a wildcard tool's
        /// provisioning set is the union of the whole file's `credentials` — an
        /// independent re-derivation that never walks the closure. Covers both
        /// the omission path (a tool named `shell`) and the literal `["*"]`
        /// spelling, and asserts the two agree.
        #[test]
        fn a_single_file_wildcard_provisions_the_whole_files_credentials(
            creds in proptest::collection::vec(proptest::collection::vec(0u8..4, 0..3), 2..5),
        ) {
            let mut body = String::new();
            for (index, credentials) in creds.iter().enumerate() {
                let name = if index == 0 {
                    "shell".to_string()
                } else {
                    format!("t{index}")
                };
                body.push_str("[[tools]]\n");
                body.push_str(&format!("name = \"{name}\"\ncommand = \"{name}\"\n"));
                if !credentials.is_empty() {
                    let names: Vec<String> = credentials
                        .iter()
                        .map(|c| format!("\"{}\"", provider_from_u8(*c).config_name()))
                        .collect();
                    body.push_str(&format!("credentials = [{}]\n", names.join(", ")));
                }
                if index == 1 {
                    body.push_str("tools = [\"*\"]\n");
                }
            }
            let fixture = Fixture::new();
            fixture.user(&body);
            let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
            let union: BTreeSet<CredentialProvider> = creds
                .iter()
                .flatten()
                .map(|credential| provider_from_u8(*credential))
                .collect();
            proptest::prop_assert_eq!(provisioned_set(&catalog, "shell"), union.clone());
            proptest::prop_assert_eq!(provisioned_set(&catalog, "t1"), union);
        }

        /// **P1.** The scoped fixed point against an independent
        /// relation-saturation oracle. The generator duplicates every name across
        /// the tiers and may point any edge at a same-named definition, so a
        /// bare-name index, a winners-only arena, a wildcard over visible verbs,
        /// a shallow fold or a duplicate contribution through a cycle all change
        /// the result.
        #[test]
        fn scoped_fixed_point_matches_a_saturation_oracle(
            user in proptest::collection::vec(generated_definition(), 1..5),
            project in proptest::collection::vec(generated_definition(), 0..5),
        ) {
            let user: Vec<GeneratedDefinition> = user.into_iter().collect();
            let project: Vec<GeneratedDefinition> = project.into_iter().collect();
            let fixture = Fixture::new();
            fixture.user(&render_tier('u', &user));
            if !project.is_empty() {
                fixture.project(&render_tier('p', &project));
            }
            let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();

            let user_reach = saturation_reach(&user);
            let project_reach = saturation_reach(&project);

            let mut verbs: Vec<String> = (0..user.len()).map(|index| format!("t{index}")).collect();
            for index in user.len()..project.len() {
                verbs.push(format!("t{index}"));
            }
            verbs.push("shell".to_string());
            proptest::prop_assert_eq!(verbs_of(&catalog), verbs);

            for (index, reach) in user_reach.iter().enumerate() {
                let name = format!("t{index}");
                let (providers, names, persist) = expected_facets('u', &user, reach);
                proptest::prop_assert_eq!(
                    provisioned_set(&catalog, &name),
                    providers,
                    "user {}",
                    name
                );
                proptest::prop_assert_eq!(
                    names_of(&catalog, &name).into_iter().collect::<BTreeSet<_>>(),
                    names,
                    "user {} requested names",
                    name
                );
                proptest::prop_assert_eq!(persist_of(&catalog, &name), persist, "user {}", name);
            }
            for (index, reach) in project_reach.iter().enumerate().skip(user.len()) {
                let name = format!("t{index}");
                let (providers, names, persist) = expected_facets('p', &project, reach);
                proptest::prop_assert_eq!(
                    provisioned_set(&catalog, &name),
                    providers,
                    "project {}",
                    name
                );
                proptest::prop_assert_eq!(
                    names_of(&catalog, &name).into_iter().collect::<BTreeSet<_>>(),
                    names,
                    "project {} requested names",
                    name
                );
                proptest::prop_assert_eq!(persist_of(&catalog, &name), persist, "project {}", name);
            }
        }

        /// **P2.** Arbitrary user definitions that shadow *every* project dependency
        /// name cannot change a still-winning project root's facets, and a user
        /// wildcard reaches only this tier's definitions.
        #[test]
        fn shadowing_project_names_cannot_change_a_winning_project_root(
            dependencies in proptest::collection::vec(
                (
                    proptest::collection::vec(0u8..4, 0..3),
                    proptest::collection::vec(0usize..4, 0..3),
                ),
                1..5,
            ),
            first_user in proptest::collection::vec(0u8..4, 0..3),
            second_user in proptest::collection::vec(0u8..4, 0..3),
        ) {
            // `t0..t{n-1}` are the dependencies; `t{n}` is the root that names the
            // first one. Every user definition shadows one dependency name, and the
            // root's own name stays free, so the project root stays a verb.
            let n = dependencies.len();
            let mut project: Vec<GeneratedDefinition> = dependencies
                .iter()
                .map(|(providers, edges)| GeneratedDefinition {
                    providers: providers.clone(),
                    edges: edges.iter().map(|edge| edge % (n + 1)).collect(),
                    wildcard: false,
                })
                .collect();
            project.push(GeneratedDefinition {
                providers: Vec::new(),
                edges: vec![0],
                wildcard: false,
            });
            let root_name = format!("t{n}");
            let project_body = render_tier('p', &project);
            let root_reach = saturation_reach(&project)[n].clone();
            let expected = expected_facets('p', &project, &root_reach);

            for (variant, credentials, wildcard) in [
                ("plain", &first_user, false),
                ("wildcard", &second_user, true),
            ] {
                let user: Vec<GeneratedDefinition> = (0..n)
                    .map(|index| GeneratedDefinition {
                        providers: credentials.clone(),
                        edges: vec![0],
                        // One variant makes the first user definition a wildcard, so
                        // the check also proves the wildcard cannot reach the other
                        // tier even when it covers this one.
                        wildcard: wildcard && index == 0,
                    })
                    .collect();
                let fixture = Fixture::new();
                fixture
                    .user(&render_tier('u', &user))
                    .project(&project_body);
                let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
                proptest::prop_assert_eq!(
                    provisioned_set(&catalog, &root_name),
                    expected.0.clone(),
                    "{} providers",
                    variant
                );
                proptest::prop_assert_eq!(
                    names_of(&catalog, &root_name)
                        .into_iter()
                        .collect::<BTreeSet<_>>(),
                    expected.1.clone(),
                    "{} names",
                    variant
                );
                proptest::prop_assert_eq!(
                    persist_of(&catalog, &root_name),
                    expected.2.clone(),
                    "{} paths",
                    variant
                );
                if wildcard {
                    let (providers, _, persist) =
                        expected_facets('u', &user, &saturation_reach(&user)[0]);
                    proptest::prop_assert_eq!(provisioned_set(&catalog, "t0"), providers);
                    proptest::prop_assert_eq!(persist_of(&catalog, "t0"), persist);
                }
            }
        }

        /// **P2b.** A declared `shell`'s omitted `tools` is exactly its own tier's
        /// declared union; an explicit `[]` is its own definition only. A project
        /// declaration of the same name is a shadowed target, not something the
        /// user wildcard sweeps in.
        #[test]
        fn declared_shell_wildcard_is_its_own_tier_union(
            credentials in proptest::collection::vec(proptest::collection::vec(0u8..4, 0..3), 2..5),
            empty in proptest::bool::ANY,
        ) {
            let mut body = String::new();
            for (index, providers) in credentials.iter().enumerate() {
                let name = if index == 0 {
                    "shell".to_string()
                } else {
                    format!("t{index}")
                };
                body.push_str(&format!(
                    "[[tools]]\nname = \"{name}\"\ncommand = \"{name}\"\npersist = [\"u-path-{index}\"]\n"
                ));
                if index == 0 && empty {
                    body.push_str("tools = []\n");
                }
                let names: Vec<String> = providers
                    .iter()
                    .map(|provider| format!("\"{}\"", provider_from_u8(*provider).config_name()))
                    .collect();
                if !names.is_empty() {
                    body.push_str(&format!("credentials = [{}]\n", names.join(", ")));
                }
            }
            let fixture = Fixture::new();
            fixture
                .user(&body)
                .project("[[tools]]\nname = \"sibling\"\ncommand = \"project-sibling\"\ncredentials = [\"copilot\"]\npersist = [\"p-path-0\"]\n");
            let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();

            let mut provisioned = BTreeSet::new();
            let mut persist = Vec::new();
            for (index, providers) in credentials.iter().enumerate() {
                if empty && index != 0 {
                    continue;
                }
                for provider in providers {
                    provisioned.insert(provider_from_u8(*provider));
                }
                persist.push(format!("u-path-{index}"));
            }
            proptest::prop_assert_eq!(provisioned_set(&catalog, "shell"), provisioned);
            proptest::prop_assert_eq!(persist_of(&catalog, "shell"), persist);
            proptest::prop_assert!(!catalog.has_shell_fallback());
        }

        /// **P3.** A locally absent target that only the other tier declares is a
        /// config error, never an empty success or that other definition's facets.
        /// Redeclaring the target and its local graph in the referencing tier
        /// succeeds with the tier-local closure, cycles included.
        #[test]
        fn locally_absent_targets_fail_until_redeclared_locally(
            specs in proptest::collection::vec(generated_definition(), 1..5),
        ) {
            let definitions: Vec<GeneratedDefinition> = specs.into_iter().collect();

            // The user tier references a project-only `t0`.
            let fixture = Fixture::new();
            fixture
                .user("[[tools]]\nname = \"root\"\ncommand = \"root\"\ntools = [\"t0\"]\n")
                .project(&render_tier('p', &definitions));
            let error = format!(
                "{:#}",
                fixture.load().unwrap().into_launch_catalog().unwrap_err()
            );
            proptest::prop_assert!(
                error.contains("names no tool in this configuration file"),
                "{}",
                error
            );
            proptest::prop_assert!(
                error.contains(&crate::one_line::quoted_path(&fixture.user).to_string()),
                "{}",
                error
            );

            proptest::prop_assert!(
                error.contains(&format!(
                    "it is declared in project config {}",
                    crate::one_line::quoted_path(&fixture.project)
                )),
                "a name the other tier declares is a cross-tier reference: {}",
                error
            );

            // The project tier references a user-only `t0`.
            let fixture = Fixture::new();
            fixture
                .user(&render_tier('u', &definitions))
                .project("[[tools]]\nname = \"root\"\ncommand = \"root\"\ntools = [\"t0\"]\n");
            let error = format!(
                "{:#}",
                fixture.load().unwrap().into_launch_catalog().unwrap_err()
            );
            proptest::prop_assert!(
                error.contains("names no tool in this configuration file"),
                "{}",
                error
            );
            proptest::prop_assert!(
                error.contains(&crate::one_line::quoted_path(&fixture.project).to_string()),
                "{}",
                error
            );
            proptest::prop_assert!(
                error.contains(&format!(
                    "it is declared in user config {}",
                    crate::one_line::quoted_path(&fixture.user)
                )),
                "a name the other tier declares is a cross-tier reference: {}",
                error
            );

            // Redeclared locally, the same graph resolves to exactly the oracle's
            // tier-local closure.
            let fixture = Fixture::new();
            fixture.user(&format!(
                "[[tools]]\nname = \"root\"\ncommand = \"root\"\ntools = [\"t0\"]\n{}",
                render_tier('u', &definitions)
            ));
            let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
            let (providers, _, persist) =
                expected_facets('u', &definitions, &saturation_reach(&definitions)[0]);
            proptest::prop_assert_eq!(provisioned_set(&catalog, "root"), providers);
            proptest::prop_assert_eq!(persist_of(&catalog, "root"), persist);
        }

        /// **V1 (the erased-build half).** The overlap predicate is symmetric,
        /// and `overlap(a, b)` holds iff `a`'s components are a prefix of
        /// `b`'s (or vice versa) — restated over `Vec<String>` components, an
        /// independent re-derivation of the Verus `ensures`.
        #[test]
        fn overlap_is_symmetric_and_component_prefixes(
            a in proptest::collection::vec("[a-z]{1,4}", 1..4),
            b in proptest::collection::vec("[a-z]{1,4}", 1..4),
        ) {
            let pa = a.join("/");
            let pb = b.join("/");
            let left = guest_paths_overlap(Path::new(&pa), Path::new(&pb));
            let right = guest_paths_overlap(Path::new(&pb), Path::new(&pa));
            proptest::prop_assert_eq!(left, right);

            let expected = component_prefix(&a, &b) || component_prefix(&b, &a);
            proptest::prop_assert_eq!(left, expected);
        }

        /// **V3 (the erased-build half of ADR-0020's containment).** The
        /// directional kernel holds iff `a`'s components are a prefix of
        /// `b`'s, restated over `Vec<String>` components by the same
        /// independent oracle — direction included, so a swapped argument
        /// order is caught.
        #[test]
        fn byte_path_contains_is_a_directional_component_prefix(
            a in proptest::collection::vec("[a-z]{1,4}", 1..4),
            b in proptest::collection::vec("[a-z]{1,4}", 1..4),
        ) {
            let pa = a.join("/");
            let pb = b.join("/");
            proptest::prop_assert_eq!(
                byte_path_contains(pa.as_bytes(), pb.as_bytes()),
                component_prefix(&a, &b),
                "contains({:?}, {:?})", a, b
            );
        }

        /// **V3 (correlated).** The oracle above draws `a` and `b`
        /// independently, so it almost never produces an ancestor/descendant
        /// pair and cannot falsify a kernel that mishandles the *positive*
        /// case — one that requires a leading `/`, say. This builds
        /// `descendant = ancestor ++ extra` (guaranteed correlated) and also
        /// checks an unrelated vector and a sibling-prefix string, all against
        /// the independent `Path::starts_with` oracle. Both spellings are
        /// exercised, because the separator check must fire for a *relative*
        /// path too (`"a"` contains `"a/a"`).
        #[test]
        fn byte_path_contains_matches_the_correlated_path_oracle(
            ancestor in proptest::collection::vec("[a-z]{1,3}", 1..4),
            extra in proptest::collection::vec("[a-z]{1,3}", 0..3),
            other in proptest::collection::vec("[a-z]{1,3}", 1..4),
        ) {
            use std::ffi::OsStr;
            use std::os::unix::ffi::OsStrExt;
            let descendant = ancestor
                .iter()
                .chain(&extra)
                .cloned()
                .collect::<Vec<_>>()
                .join("/");
            let ancestor_path = ancestor.join("/");
            let sibling = format!("{}x", ancestor_path);
            let unrelated = other.join("/");
            for lead in ["", "/"] {
                let left = format!("{lead}{ancestor_path}");
                let a_path = Path::new(OsStr::from_bytes(left.as_bytes()));
                for candidate in [descendant.as_str(), unrelated.as_str(), sibling.as_str()] {
                    let right = format!("{lead}{candidate}");
                    let d_path = Path::new(OsStr::from_bytes(right.as_bytes()));
                    proptest::prop_assert_eq!(
                        byte_path_contains(left.as_bytes(), right.as_bytes()),
                        d_path.starts_with(a_path),
                        "contains({:?}, {:?})", left, right
                    );
                }
            }
        }
    }

    /// One generated definition for the scoped-reference properties. `edges` holds
    /// *local* indices; both tiers use the same `t0..` names, so a bare-name index
    /// would silently bind an edge to the other tier's definition.
    #[derive(Debug, Clone)]
    struct GeneratedDefinition {
        providers: Vec<u8>,
        edges: Vec<usize>,
        wildcard: bool,
    }

    fn generated_definition() -> impl proptest::strategy::Strategy<Value = GeneratedDefinition> {
        use proptest::strategy::Strategy as _;
        (
            proptest::collection::vec(0u8..4, 0..3),
            proptest::collection::vec(0usize..5, 0..3),
            proptest::bool::ANY,
        )
            .prop_map(|(providers, edges, wildcard)| GeneratedDefinition {
                providers,
                edges,
                wildcard,
            })
    }

    /// Render one generated tier as TOML. `tier` is the letter distinguishing the
    /// tiers' service names and persisted paths, so a wrong-tier facet is visible
    /// in the assertion rather than coincidentally equal.
    fn render_tier(tier: char, definitions: &[GeneratedDefinition]) -> String {
        let count = definitions.len();
        let mut body = String::new();
        for (index, definition) in definitions.iter().enumerate() {
            body.push_str("[[tools]]\n");
            body.push_str(&format!(
                "name = \"t{index}\"\ncommand = \"{tier}-t{index}\"\n"
            ));
            let mut names: Vec<String> = definition
                .providers
                .iter()
                .map(|provider| format!("\"{}\"", provider_from_u8(*provider).config_name()))
                .collect();
            names.dedup();
            names.push(format!("\"{tier}-service-{index}\""));
            body.push_str(&format!("credentials = [{}]\n", names.join(", ")));
            body.push_str(&format!("persist = [\"{tier}-path-{index}\"]\n"));
            if definition.wildcard {
                body.push_str("tools = [\"*\"]\n");
            } else if !definition.edges.is_empty() {
                let edges: Vec<String> = definition
                    .edges
                    .iter()
                    .map(|edge| format!("\"t{}\"", edge % count))
                    .collect();
                body.push_str(&format!("tools = [{}]\n", edges.join(", ")));
            }
        }
        body
    }

    /// Every definition's tier-local reachable set, by *saturating* the edge
    /// relation until a round adds nothing — an independent re-derivation that
    /// never shares the production traversal.
    fn saturation_reach(definitions: &[GeneratedDefinition]) -> Vec<Vec<usize>> {
        let count = definitions.len();
        (0..count)
            .map(|start| {
                let mut reached = vec![false; count];
                reached[start] = true;
                loop {
                    let mut grew = false;
                    for (index, definition) in definitions.iter().enumerate() {
                        if !reached[index] {
                            continue;
                        }
                        let targets: Vec<usize> = if definition.wildcard {
                            (0..count).collect()
                        } else {
                            definition.edges.iter().map(|edge| edge % count).collect()
                        };
                        for target in targets {
                            if !reached[target] {
                                reached[target] = true;
                                grew = true;
                            }
                        }
                    }
                    if !grew {
                        break;
                    }
                }
                (0..count).filter(|index| reached[*index]).collect()
            })
            .collect()
    }

    /// The facets one tier-local closure must produce, folded in index (= arena)
    /// order.
    fn expected_facets(
        tier: char,
        definitions: &[GeneratedDefinition],
        reached: &[usize],
    ) -> (BTreeSet<CredentialProvider>, BTreeSet<String>, Vec<String>) {
        let mut providers = BTreeSet::new();
        let mut names = BTreeSet::new();
        let mut persist = Vec::new();
        for index in reached {
            for provider in &definitions[*index].providers {
                providers.insert(provider_from_u8(*provider));
                names.insert(provider_from_u8(*provider).config_name().to_string());
            }
            names.insert(format!("{tier}-service-{index}"));
            persist.push(format!("{tier}-path-{index}"));
        }
        (providers, names, persist)
    }

    /// `a`'s components are a prefix of `b`'s (component-wise), the independent
    /// re-derivation of `guest_paths_overlap` the proptest compares against.
    fn component_prefix(a: &[String], b: &[String]) -> bool {
        a.len() <= b.len() && a.iter().zip(b).all(|(x, y)| x == y)
    }

    fn dedupe(names: Vec<String>) -> Vec<String> {
        let mut seen = HashSet::new();
        names
            .into_iter()
            .filter(|name| {
                !RESERVED_TOOL_NAMES.contains(&name.as_str()) && seen.insert(name.clone())
            })
            .collect()
    }
    #[test]
    fn network_requests_tiers_validation_and_provenance() {
        for user in [true, false] {
            let f = Fixture::new();
            let body = "[[tools]]\nname = \"t\"\ncommand = \"t\"\nnetwork_requests = [\"B.example.\", \"a.example:443\"]\n";
            if user {
                f.user(body);
            } else {
                f.project(body);
            }
            assert_eq!(
                first_launch(&f.load().unwrap())
                    .network_requests()
                    .bounded_display(),
                "a.example,b.example"
            );
            let body = "[[tools]]\nname = \"t\"\ncommand = \"t\"\nnetwork_requests = [\"a.example\", \"SENTINEL-9c1f.example:0\"]\n";
            if user {
                f.user(body);
            } else {
                f.project(body);
            }
            let (tier, path) = if user {
                ("user config", &f.user)
            } else {
                ("project config", &f.project)
            };
            assert_eq!(
                f.load().unwrap_err().to_string(),
                format!(
                    "config: {tier} {} declaration [0] tool \"t\": network_requests[1]: port must be a decimal number 1-65535",
                    crate::one_line::quoted_path(path)
                )
            );
            let body =
                "[[tools]]\nname = \"t\"\ncommand = \"t\"\nnetwork_requests = \"a.example\"\n";
            if user {
                f.user(body);
            } else {
                f.project(body);
            }
            assert!(
                f.load()
                    .unwrap_err()
                    .to_string()
                    .contains("`network_requests`")
            );
        }
        let f = Fixture::new();
        f.user("[[tools]]\nname = \"t\"\ncommand = \"t\"\nnetwork_requests = [\"a.example\",\"b.example\"]\n")
            .project("[[tools]]\nname = \"t\"\ncommand = \"t\"\nnetwork_requests = [\"B.example.\",\"a.example\",\"a.example:443\"]\n");
        assert!(f.load().unwrap().conflicts().is_empty());
        f.user("[[tools]]\nname = \"t\"\ncommand = \"t\"\n");
        let report = f.load().unwrap();
        assert_eq!(
            report.conflicts()[0].fields(),
            &[ToolField::NetworkRequests]
        );
        assert!(first_launch(&report).network_requests().is_empty());
        assert_eq!(
            first_launch(&report).origin(),
            &ToolOrigin::User(f.user.clone())
        );
        f.project(
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\nnetwork_requests = [\"udp://a.example\"]\n",
        );
        assert!(f.load().is_err());
        assert_eq!(ToolField::NetworkRequests.as_str(), "network_requests");
    }
    #[test]
    fn network_requests_provisioning_noninterference() {
        for tier in 0..3 {
            let f = Fixture::new();
            let body = "[[tools]]\nname = \"a\"\ncommand = \"a\"\ncredentials = [\"anthropic\"]\npersist = [\"x\"]\n[[tools]]\nname = \"shell\"\ncommand = \"bash\"\n";
            if tier != 1 {
                f.user(body);
            }
            let project_body = if tier == 2 {
                body.replace("anthropic", "openai")
                    .replace("command = \"bash\"", "command = \"bash\"\ntools = []")
            } else {
                body.to_owned()
            };
            if tier != 0 {
                f.project(&project_body);
            }
            let before = f.load().unwrap().into_launch_catalog().unwrap();
            let with = body
                .replace(
                    "command = \"a\"",
                    "command = \"a\"\nnetwork_requests = [\"api.example.com\"]",
                )
                .replace(
                    "command = \"bash\"",
                    "command = \"bash\"\nnetwork_requests = [\"other.example\"]",
                );
            if tier != 1 {
                f.user(&with);
            }
            if tier != 0 {
                let project_with = project_body
                    .replace(
                        "command = \"a\"",
                        "command = \"a\"\nnetwork_requests = [\"api.example.com\"]",
                    )
                    .replace(
                        "command = \"bash\"",
                        "command = \"bash\"\nnetwork_requests = [\"other.example\"]",
                    );
                f.project(&project_with);
            }
            let after = f.load().unwrap().into_launch_catalog().unwrap();
            assert_eq!(before.entries.len(), after.entries.len());
            for (a, b) in before.entries.iter().zip(&after.entries) {
                assert_eq!(a.provisioned(), b.provisioned());
                assert_eq!(a.requested_names(), b.requested_names());
                assert_eq!(a.persist(), b.persist());
            }
        }
    }
}
