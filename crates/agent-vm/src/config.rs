//! Read-only **tool configuration**: discovery, strict parsing, validation,
//! and the ordered catalog merge that `agent-vm doctor` previews.
//!
//! A **tool declaration** (`[[tools]]` in a config file) is *data*: a guest
//! command, its default argv, the credential providers it needs, extra
//! guest-HOME-relative paths to persist, guest env pairs, and network requests.
//! Requests never grant network access. This module
//! never executes a command, creates guest state, builds an image, or captures
//! a credential. A top-level `image` key selects the **boot image**
//! independently of the tools (see [`crate::boot_image`]).
//!
//! # Ordered catalogs, not an overlay
//!
//! The project file (`$HOME/.config/agent-vm/projects/<project-id>/config.toml`,
//! ADR-0073) and the files it **sources** (ADR-0074) are ordered *catalogs*.
//! Nothing in a repository is read unless the project config names it. A
//! project-side file may add whole tool definitions the user did not write; a name
//! the user did write is authoritative and the entire user definition wins (never a
//! field-by-field merge). Resolved order is user declarations first, then
//! project-side declarations in source order. Only when **every** list is empty do
//! the seven compiled-in defaults (embedded from `default-tools.toml`) apply.
//!
//! ```text
//! :trust source -----> parse + validate --+--> retained definitions --> launch
//! project config ----> parse + validate --+    every tier, hidden       verbs
//! each other source -> parse + validate --+    same-name losers too
//! all empty? -> embedded defaults --------+
//! ```
//!
//! Every tier is parsed and validated *before* merging, so an invalid
//! project declaration fails even when the user shadowed its name.
//!
//! # Sources (ADR-0074)
//!
//! The project config may declare `sources = ["<alias>[:trust] <path>", …]`. An
//! omitted key means the single implicit `home:trust
//! ~/.config/agent-vm/config.toml`; an explicit list — `[]` included — replaces it,
//! so the user file is read only when a `:trust` entry names it. Sourcing is flat
//! (only the project config may declare `sources`) and trust is a property of the
//! verified route, not of the path spelling: `:trust` is accepted only for the
//! discovered user config, whose read is checked against the active checkout first
//! (`crate::project_config::check_user_parent_route`,
//! `check_user_symlink_target`). Every other source is declarations-only: it may add
//! tools and declare an `image`, and it cannot grant network, mounts or sets.
//! [`crate::config_sources`] owns the grammar and path resolution;
//! [`crate::boot_image`] owns how a declared image becomes the boot image.
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
//! ADR-0040 permits verified user [network] tables, ADR-0046 a verified user
//! top-level `mounts` list and ADR-0048 a verified user `[mount_sets]` table;
//! project and built-in tiers cannot declare any of them. Whether the file
//! holding one may be trusted is [`crate::config_authority`]'s decision, taken
//! here once per user file from the *presence* of any of those keys, so this
//! module and [`crate::config_mounts`] only decide *what* a trusted file says.
//! The project file is nevertheless verified unconditionally via a no-follow
//! open and store-route check before bytes are read (ADR-0073); it still may
//! not declare any of them.

use crate::config_authority::{self, AuthorityTriggers};
use crate::config_mounts::{self, ResolvedMountList, UserMounts};
use crate::egress_reference::{self, EgressNamespace};
use crate::host_paths::FinalComponent;
use crate::user_network::{self, UserNetwork};

use crate::network_requests::{NetworkRequests, RequestTier};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    ffi::OsStr,
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

pub(crate) mod builtin_print;
pub(crate) use builtin_print::builtin_tools_toml;

/// Ceiling on a config file read. A project config is possibly untrusted
/// input, so a huge or special file must not be able to hang or exhaust
/// `doctor`. Deliberately a *config* policy constant, not the credential
/// file's limit.
const MAX_CONFIG_FILE_BYTES: u64 = 1024 * 1024;

pub(crate) const USER_CONFIG_RELATIVE: &str = concat!(".config/agent-vm", "/config.toml");

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
    // `tools print` (#510) re-emits the built-in catalog, so the word belongs to
    // the CLI even though no shipped tool is named it.
    "tools",
    // `access` (ADR-0064) is the one verb that answers what a sandbox refused, so
    // a tool by that name could not be reached.
    "access",
    "_intercept-hook",
    // `_notify-click` is spawned by the macOS notification helper, so a tool by
    // that name could never be reached either.
    "_notify-click",
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

/// Where the two config files live. Both are `None` only when `$HOME` is
/// unavailable: the project tier is host-managed under it (ADR-0073), keyed by
/// the captured project's digest, and never read from the project directory.
/// Literal `$HOME` spelling is preserved for diagnostics and [`TierReport`].
pub(crate) struct ConfigPaths {
    pub(crate) user: Option<PathBuf>,
    pub(crate) project: Option<crate::project_config::ProjectTierPaths>,
    /// The `$HOME` [`Self::user`] was derived from: the only base a `~/` in that
    /// file's `mounts` may expand against (ADR-0046). Captured once, with the
    /// path, so a launch cannot read one `config.toml` and expand `~/` against a
    /// different home.
    pub(crate) home: Option<PathBuf>,
}

impl ConfigPaths {
    /// The environment adapter: `$HOME`, plus the command's one project capture.
    ///
    /// There is deliberately no `XDG_CONFIG_HOME` or override variable in
    /// this PR — the ticket names the literal `$HOME` location.
    pub(crate) fn discover(project: &crate::project::ProjectDir) -> Result<Self> {
        Ok(Self::with_home(discover_home()?, project))
    }

    /// The pure core of [`Self::discover`]: every path is derived from one `$HOME`
    /// capture and one project capture, so [`Self::discover`] cannot check one home
    /// while a read uses another. Tests build it directly to get a captured route
    /// without touching the process environment.
    fn with_home(home: Option<PathBuf>, project: &crate::project::ProjectDir) -> Self {
        Self {
            user: home.as_ref().map(|home| home.join(USER_CONFIG_RELATIVE)),
            project: home
                .as_ref()
                .map(|home| crate::project_config::ProjectTierPaths {
                    config: crate::project_config::path(home, project),
                    // The route check's anchor, from the same capture as the path:
                    // a caller can neither check one home and read another nor
                    // reach a project tier with no root to check against.
                    route: crate::project_config::RouteAnchor::Captured {
                        home: home.clone(),
                        root: project.path().to_path_buf(),
                    },
                }),
            home,
        }
    }

    /// The anchor a `:trust` read is checked against (ADR-0074 D3): always
    /// [`crate::project_config::RouteAnchor::Captured`] in production, because a
    /// project tier exists only with a home.
    pub(crate) fn route(&self) -> &crate::project_config::RouteAnchor {
        self.project
            .as_ref()
            .map_or(&crate::project_config::RouteAnchor::Uncaptured, |project| {
                &project.route
            })
    }

    /// A hand-built pair for this crate's tests, which predate the store: no
    /// `$HOME`, and a project tier with no captured root
    /// ([`crate::project_config::RouteAnchor::Uncaptured`]), so the ADR-0073
    /// store route is not checked. Named rather than a struct literal so the
    /// skipped check is one visible decision instead of a field a new fixture
    /// could omit.
    #[cfg(test)]
    pub(crate) fn for_test(user: Option<PathBuf>, project: PathBuf) -> Self {
        Self::for_test_with_home(user, project, None)
    }

    /// [`Self::with_home`] for another module's tests: a *captured* project, so a
    /// fixture can declare `sources` at all.
    #[cfg(test)]
    pub(crate) fn for_test_captured(home: PathBuf, project: &crate::project::ProjectDir) -> Self {
        Self::with_home(Some(home), project)
    }

    /// [`Self::for_test`] with the `~/` base some user-tier fixtures expand
    /// against.
    #[cfg(test)]
    pub(crate) fn for_test_with_home(
        user: Option<PathBuf>,
        project: PathBuf,
        home: Option<PathBuf>,
    ) -> Self {
        Self {
            user,
            project: Some(crate::project_config::ProjectTierPaths::uncaptured(project)),
            home,
        }
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
    /// The user file's own tools as an egress-reference namespace (ADR-0059).
    user_tools: Option<EgressNamespace>,
    uses_defaults: bool,
    conflicts: Vec<ConfigConflict>,
    /// What the project config sourced (ADR-0074), in declaration order.
    sources: SourcesReport,
    /// Every arena position that is neither authorized nor an overridden `:trust`
    /// definition, in arena order: `doctor`'s `inert tools` block (#735).
    inert_tools: Vec<InertTool>,
    /// The load's **one** leaf-visit counter, from `read_project_tier` through
    /// every source read and into the single catalog build (#735, D6).
    mount_work: config_mounts::MountExpansionWork,
}

impl ConfigReport {
    pub(crate) fn user(&self) -> &TierReport {
        &self.user
    }

    pub(crate) fn project(&self) -> &TierReport {
        &self.project
    }

    /// What the project config sourced, so `doctor` can render the source list and
    /// decide whether the legacy in-repo notice still applies (ADR-0074).
    pub(crate) fn sources(&self) -> &SourcesReport {
        &self.sources
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

    /// The namespace a CLI `set:NAME` resolves against: the **user tier's own**
    /// `[egress_sets]`, from the same read as their trust verdict, captured before
    /// the cross-tier merge (ADR-0059).
    ///
    /// `None` when there is no user file at all, which is why a reference then
    /// reports "no user config file was found" rather than an unknown set. Read
    /// before `into_launch_catalog` consumes the report, like [`Self::images`].
    pub(crate) fn user_tool_requests(&self) -> Option<&EgressNamespace> {
        self.user_tools.as_ref()
    }

    /// The verified user mount configuration, `Some` when the file declares
    /// `mounts` or `[mount_sets]` — present-empty and definitions-only included:
    /// a file that declared either key is authority-bearing, and its namespace is
    /// what an explicit `--mount NAME` resolves against. Read before
    /// `into_launch_catalog` consumes the report, like [`Self::images`].
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

    /// Declared tools no `allow_tools` entry authorizes, in arena order: what
    /// `doctor` lists with the exact spelling that would activate each one.
    pub(crate) fn inert_tools(&self) -> &[InertTool] {
        &self.inert_tools
    }

    /// The launch verbs the project's own `allow_tools` list decided, with the entry
    /// that decided each, so `doctor` can advise *replacing* one instead of adding a
    /// second, refused entry (#735 review D2).
    pub(crate) fn project_claims(&self) -> &BTreeMap<String, String> {
        self.resolved.project_claim_entries()
    }

    /// Leaf visits this load admitted. Test-only: the resource rule is otherwise
    /// observable only as the refusal.
    #[cfg(test)]
    pub(crate) fn mount_work_used(&self) -> usize {
        self.mount_work.used()
    }

    /// The catalog a launch actually offers: the merge result, plus the
    /// built-in `shell` appended when no declared tool claims that name.
    /// Consumed by both `cli::build_command` and `doctor`, so `--help` and
    /// `agent-vm doctor` cannot disagree about the verb list.
    ///
    /// Deliberately *not* folded into [`ResolvedTools`]: that type means "the
    /// merge result", and the fallback is not a declaration.
    pub(crate) fn into_launch_catalog(self) -> Result<LaunchCatalog> {
        self.catalog_with_work().0
    }

    /// [`Self::into_launch_catalog`], also reporting the leaf-visit budget the
    /// build left the shared counter at — even when it refuses.
    ///
    /// Test-only: on the error path the counter is otherwise observable only as
    /// the refusal, and the continuity contract is precisely how far it got.
    #[cfg(test)]
    pub(crate) fn into_launch_catalog_with_work(
        self,
    ) -> (Result<LaunchCatalog>, config_mounts::MountExpansionWork) {
        self.catalog_with_work()
    }

    fn catalog_with_work(self) -> (Result<LaunchCatalog>, config_mounts::MountExpansionWork) {
        let ConfigReport {
            resolved,
            mount_work,
            ..
        } = self;
        // The catalog fold continues the load's one leaf-visit budget rather than
        // starting a fresh one: tool lists and an inherited closure amplify the
        // same leaves the parse already admitted, so a per-launch or per-tier
        // counter would be a second, unbounded budget for the same load. The report
        // is consumed by value, so one load funds exactly one catalog build.
        let mut work = mount_work;
        let catalog = catalog_from_tools(resolved, &mut work);
        (catalog, work)
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
fn catalog_from_tools(
    tools: ResolvedTools,
    work: &mut config_mounts::MountExpansionWork,
) -> Result<LaunchCatalog> {
    let shell_fallback_added = !tools
        .launch_tools()
        .any(|tool| tool.name() == SHELL_TOOL_NAME);
    let mut entries = resolve_provisioning(tools, work)?;
    let declared_len = entries.len();
    if shell_fallback_added {
        // The fallback scope holds only the shipped `shell`, which cannot carry
        // mounts, so it contributes no candidate — but it shares the same
        // continued budget rather than getting one of its own.
        entries.extend(resolve_provisioning(
            ResolvedTools::from_defaults(vec![builtin_shell()?]),
            work,
        )?);
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
    catalog_from_tools(
        ResolvedTools::from_defaults(default_tools()?),
        &mut config_mounts::MountExpansionWork::fresh(),
    )
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
    /// The union of this tool's own mount declarations and those of every
    /// definition in its transitive same-file `tools` closure (#396), in arena
    /// then list order, deduplicated by the shared claim.
    ///
    /// The fourth facet of the same closure [`Self::provisioned`],
    /// [`Self::requested_names`] and [`Self::persist`] describe, and resolved over
    /// the same one visited mask. Empty for a direct launch and for anything the
    /// built-in catalog supplies.
    mounts: ResolvedMountList,
    /// True iff an `allow_tools` entry (or a `:trust` inheritance) selected this
    /// verb: the one condition under which its own `network_requests` are granted
    /// as egress on launch (#735, R5). False for the compiled-in defaults and for
    /// the synthesized `shell` fallback, which keep ADR-0036 default-deny.
    authorized_egress: bool,
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

    /// The config mount declarations a launch of this tool selects
    /// automatically, own plus inherited. `--no-config-mounts` withholds them at
    /// selection; it never changes what is resolved here.
    pub(crate) fn mounts(&self) -> &ResolvedMountList {
        &self.mounts
    }

    /// Whether this entry was explicitly authorized, which is what makes its own
    /// `network_requests` authoritative egress (#735).
    pub(crate) fn is_authorized_egress(&self) -> bool {
        self.authorized_egress
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
pub(crate) struct DefinitionId(usize);

/// Every retained tool definition plus which of them are launch verbs.
///
/// Retaining the losers is what makes a tier-local reference resolvable: a
/// project definition no `allow_tools` entry authorizes still supplies that
/// project file's `tools` references (#395). Hidden definitions are dropped once
/// their facets are folded, so nothing downstream can mistake one for a verb. No
/// mutator exists, and every constructor lives here.
#[derive(Debug)]
pub(crate) struct ResolvedTools {
    /// Complete user declarations, then complete project declarations, then each
    /// source's declarations in `sources` order (inert ones included); on the
    /// defaults path, every shipped definition followed by every source
    /// definition, so their references are still validated (#735, V22).
    definitions: Vec<Tool>,
    /// The launch winners' arena positions: unique, in launch (**authorization**)
    /// order, and never assumed to be arena order. A project override replaces an
    /// inherited `:trust` verb in place, so the sequence may decrease.
    launches: Vec<DefinitionId>,
    /// The same launches as a set, so the closure-authorization rule checks an
    /// exact `DefinitionId` rather than a name (#735, R6).
    authorized: BTreeSet<DefinitionId>,
    /// True when an `allow_tools` entry or a `:trust` inheritance selected these
    /// verbs. False for the compiled-in defaults and the singleton `shell`
    /// fallback, whose tools are never `allow_tools`-authorized: their
    /// `network_requests` stay non-authoritative metadata (ADR-0036/ADR-0039).
    authorized_explicitly: bool,
    /// Declared definitions that are neither authorized nor an overridden
    /// `:trust` one, in arena order: what `doctor` reports as inert.
    inert: Vec<InertTool>,
    /// The verbs the **project's own** `allow_tools` list decided in Step B, each
    /// with the entry spelling that decided it (`<alias>:<name>` or bare), so
    /// `doctor` can advise *replacing* a claim instead of adding a second, refused
    /// entry for the same verb (#735 review D2). Empty when the project writes no
    /// list, and on both defaults paths.
    project_claims: BTreeMap<String, String>,
}

impl ResolvedTools {
    /// A catalog whose every definition is a launch verb: the shipped defaults,
    /// and the singleton fallback scope.
    fn from_defaults(tools: Vec<Tool>) -> Self {
        let launches: Vec<DefinitionId> = (0..tools.len()).map(DefinitionId).collect();
        let authorized = launches.iter().copied().collect();
        Self {
            definitions: tools,
            launches,
            authorized,
            authorized_explicitly: false,
            inert: Vec::new(),
            project_claims: BTreeMap::new(),
        }
    }

    /// The compiled-in defaults, **retaining** every source definition beside
    /// them (#735, D4/finding 2).
    ///
    /// The defaults apply because neither the user nor the project file
    /// configures tools, but a sourced file may still declare one — and a
    /// dangling `tools = [...]` reference is an error in the file that contains
    /// it even when nothing authorizes it. Keeping those definitions in the arena
    /// means `resolve_provisioning`'s one explicit-reference loop validates them,
    /// with no second validator to drift. Only the shipped positions are verbs.
    fn from_defaults_retaining(defaults: Vec<Tool>, sources: Vec<Tool>) -> Self {
        let shipped = defaults.len();
        let mut definitions = defaults;
        definitions.extend(sources);
        let launches: Vec<DefinitionId> = (0..shipped).map(DefinitionId).collect();
        let authorized = launches.iter().copied().collect();
        let inert = definitions[shipped..]
            .iter()
            .map(|tool| InertTool {
                name: tool.name.clone(),
                origin: tool.origin.clone(),
            })
            .collect();
        Self {
            definitions,
            launches,
            authorized,
            authorized_explicitly: false,
            inert,
            project_claims: BTreeMap::new(),
        }
    }

    /// The launch-verb definitions, in launch order — never a retained hidden
    /// one. The merge tests and the load-time ownership check read this;
    /// launch and `doctor` go through [`ConfigReport::into_launch_catalog`]
    /// instead.
    pub(crate) fn launch_tools(&self) -> impl ExactSizeIterator<Item = &Tool> + '_ {
        self.launches.iter().map(|id| &self.definitions[id.0])
    }

    /// The launch verbs the **project's own** `allow_tools` list claims, with the
    /// entry that claims each — the literal spelling the list wrote, so a verb
    /// claimed by `home:claude` is reported as `home:claude` even when the resolved
    /// definition dedupes to the user tier (#735 review D2).
    ///
    /// `doctor` uses this to advise *replacing* a claim instead of adding a second
    /// entry for the same verb, which R3 refuses.
    pub(crate) fn project_claim_entries(&self) -> &BTreeMap<String, String> {
        &self.project_claims
    }

    /// Declared tools nothing authorized, in arena order.
    pub(crate) fn inert_tools(&self) -> &[InertTool] {
        &self.inert
    }
}

/// One declared tool no `allow_tools` entry authorizes (#735).
///
/// Holds the provenance as well as the name so `doctor` can name the file and the
/// exact `allow_tools` spelling without re-deriving either, and so a source's
/// alias is available for a qualified entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InertTool {
    name: ToolName,
    origin: ToolOrigin,
}

impl InertTool {
    pub(crate) fn name(&self) -> &str {
        self.name.as_str()
    }

    pub(crate) fn origin(&self) -> &ToolOrigin {
        &self.origin
    }

    /// The exact `allow_tools` entry that would authorize this tool: qualified
    /// for a sourced definition, bare for a user or project one.
    pub(crate) fn allow_tools_entry(&self) -> String {
        match &self.origin {
            ToolOrigin::Source { alias, .. } => format!("{alias}:{}", self.name.as_str()),
            // Nothing can authorize a built-in definition; it is never inert.
            ToolOrigin::BuiltIn | ToolOrigin::User(_) | ToolOrigin::Project(_) => {
                self.name.as_str().to_owned()
            }
        }
    }
}

/// What one config tier turned out to be. `path` is the attempted location
/// (`None` only for an unavailable `$HOME`).
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TierStatus {
    Absent,
    Found {
        declared_tools: usize,
    },
    /// `$HOME` was missing, so this tier could not be located at all.
    UnavailableHome,
    /// The project config lists sources and none is `:trust`, so the user file
    /// was not read (ADR-0074).
    NotSourced,
}

/// What the project config sourced (ADR-0074), in declaration order.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SourcesReport {
    sourcing: crate::config_sources::Sourcing,
    entries: Vec<SourceReport>,
}

impl SourcesReport {
    pub(crate) fn sourcing(&self) -> crate::config_sources::Sourcing {
        self.sourcing
    }

    pub(crate) fn entries(&self) -> &[SourceReport] {
        &self.entries
    }

    /// The paths the project config **explicitly listed**, which is all that may
    /// suppress `doctor`'s legacy in-repo notice (ADR-0074 D9).
    ///
    /// Empty for implicit sourcing, so an in-repo symlink pointing at the user
    /// config never hides the notice when no project config exists.
    pub(crate) fn listed_files(&self) -> Vec<&Path> {
        match self.sourcing {
            crate::config_sources::Sourcing::Implicit => Vec::new(),
            crate::config_sources::Sourcing::Listed => self
                .entries
                .iter()
                .filter_map(|entry| entry.tier.path())
                .collect(),
        }
    }
}

/// One source and what reading it produced. The tier is the same report shape the
/// user tier uses, so `doctor` renders a source row with one renderer.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SourceReport {
    alias: crate::config_sources::SourceAlias,
    trust: crate::config_sources::SourceTrust,
    tier: TierReport,
}

impl SourceReport {
    pub(crate) fn alias(&self) -> &crate::config_sources::SourceAlias {
        &self.alias
    }

    pub(crate) fn trust(&self) -> crate::config_sources::SourceTrust {
        self.trust
    }

    pub(crate) fn tier(&self) -> &TierReport {
        &self.tier
    }
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
    /// A file the project config sources without `:trust` (ADR-0074): its own
    /// reference scope, and the alias #735 will qualify tools with.
    Source {
        alias: crate::config_sources::SourceAlias,
        file: PathBuf,
    },
}

impl From<&ToolOrigin> for RequestTier {
    fn from(origin: &ToolOrigin) -> Self {
        match origin {
            ToolOrigin::BuiltIn => Self::BuiltIn,
            ToolOrigin::User(_) => Self::User,
            ToolOrigin::Project(_) => Self::Project,
            ToolOrigin::Source { .. } => Self::Source,
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
    /// This definition's **own** mount selection, already parsed, normalized,
    /// set-expanded and deduplicated by [`crate::config_mounts`] (#396).
    ///
    /// A resolved facet, not raw selectors: reaching a launch must never have to
    /// re-parse a string or re-expand a set, and a shared list handle keeps the
    /// payloads single-instance across the tool, its entry and every clone of the
    /// model. Omission and present-empty are both the empty list *here* — the
    /// trust difference between them was decided from the raw field's presence
    /// before this list existed, and must not be re-derived from its length.
    mounts: ResolvedMountList,
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
    /// stays for `doctor`, which reports this count *beside* the resolved one
    /// ([`CatalogEntry::persist`]) rather than deriving both from this slice
    /// (#429).
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

    /// This definition's own mount declarations, a **selection source** for a
    /// launch of this tool (never for another tool's launch). Empty for a project
    /// or built-in definition, which cannot declare one, and for the built-in
    /// `shell` fallback, whose scope contains only itself.
    pub(crate) fn mounts(&self) -> &ResolvedMountList {
        &self.mounts
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
            && self.mounts.same_declarations(&other.mounts)
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
        // Appended after `network_requests` for the same reason as the two
        // fields above: every existing differing-field sequence keeps its order.
        // An empty-present list and an omitted one are the *same* list, so their
        // difference never warns — presence is an authority fact, not access.
        if !self.mounts.same_declarations(&other.mounts) {
            fields.push(ToolField::Mounts);
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
    /// The validated constructor for an `allow_tools` entry name: `None` for a
    /// name [`tool_name_rejection`] refuses.
    ///
    /// It is not the type's only constructor. `validate_name` builds one after the
    /// same rejection, and a `tools = [...]` reference builds one after checking
    /// only for empty and NUL (#735 review D6).
    pub(crate) fn parse(raw: &str) -> Option<Self> {
        tool_name_rejection(raw)
            .is_none()
            .then(|| Self(raw.to_owned()))
    }

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

/// One config file's `image`, with the file that declared it (for diagnostics and
/// `doctor`). Both fields are private; the accessors are the only readers, so a
/// caller cannot pair a reference with the wrong declaring file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfiguredImage {
    reference: ImageRef,
    file: PathBuf,
    /// `Some` when the project config authorized it as `ALIAS:image` (ADR-0074):
    /// the reference is the source's, the authorization is the project config's.
    via: Option<crate::config_sources::SourceAlias>,
}

impl ConfiguredImage {
    pub(crate) fn reference(&self) -> &ImageRef {
        &self.reference
    }

    pub(crate) fn file(&self) -> &Path {
        &self.file
    }

    /// The alias the project config named, for an `ALIAS:image` selection.
    pub(crate) fn via(&self) -> Option<&crate::config_sources::SourceAlias> {
        self.via.as_ref()
    }

    /// The same declared image, authorized by the project config's `ALIAS:image`.
    fn authorized_by(mut self, alias: &crate::config_sources::SourceAlias) -> Self {
        self.via = Some(alias.clone());
        self
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
            via: None,
        }
    }

    /// [`Self::for_test`] authorized by the project config as `ALIAS:image`.
    #[cfg(test)]
    pub(crate) fn for_test_via(reference: &str, file: impl Into<PathBuf>, alias: &str) -> Self {
        Self::for_test(reference, file)
            .authorized_by(&crate::config_sources::SourceAlias::for_test(alias))
    }
}

/// Both image tiers plus the images the project config did *not* select.
///
/// `Default` (neither set) is also what `image pull`
/// and `setup` use when the configuration could not be read at all: the
/// configured tiers are then unknown, and the recovery builtins fall back to
/// `--image`/env or the default boot image.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ConfiguredImages {
    /// The `:trust` source's image: the fallback (ADR-0074 R9).
    user: Option<ConfiguredImage>,
    /// The project config's selection: its own `OCI_REF`, or a source's image via
    /// `ALIAS:image`.
    project: Option<ConfiguredImage>,
    /// Images declared by untrusted sources and not selected, in `sources` order.
    inert: Vec<InertImage>,
}

impl ConfiguredImages {
    pub(crate) fn user(&self) -> Option<&ConfiguredImage> {
        self.user.as_ref()
    }

    pub(crate) fn project(&self) -> Option<&ConfiguredImage> {
        self.project.as_ref()
    }

    /// Source images the project config did not select, for `doctor` (ADR-0074
    /// R11): they change nothing until an `ALIAS:image` selects one.
    pub(crate) fn inert(&self) -> &[InertImage] {
        &self.inert
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
            inert: fixture.inert,
        }
    }
}

/// One untrusted source's declared image that the project config did not select.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InertImage {
    alias: crate::config_sources::SourceAlias,
    image: ConfiguredImage,
}

impl InertImage {
    pub(crate) fn alias(&self) -> &crate::config_sources::SourceAlias {
        &self.alias
    }

    pub(crate) fn image(&self) -> &ConfiguredImage {
        &self.image
    }

    #[cfg(test)]
    pub(crate) fn for_test(reference: &str, file: impl Into<PathBuf>, alias: &str) -> Self {
        Self {
            alias: crate::config_sources::SourceAlias::for_test(alias),
            image: ConfiguredImage::for_test(reference, file),
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
    pub(crate) inert: Vec<InertImage>,
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
    /// Appended last, like the three before it.
    Mounts,
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
            ToolField::Mounts => "mounts",
        }
    }
}

/// One cross-tier shadow: a project declaration of a name the user also
/// declared, whose definition differs. Returned as data; `doctor` renders it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ConfigConflict {
    tool: ToolName,
    /// The file whose definition the launch offers.
    winner_file: PathBuf,
    /// The file whose definition lost the verb — a `:trust` authorization
    /// overridden by the project config (#735), or a project declaration replaced
    /// by the user file's.
    overridden_file: PathBuf,
    fields: Vec<ToolField>,
}

impl ConfigConflict {
    pub(crate) fn tool(&self) -> &str {
        self.tool.as_str()
    }

    pub(crate) fn winner_file(&self) -> &Path {
        &self.winner_file
    }

    pub(crate) fn overridden_file(&self) -> &Path {
        &self.overridden_file
    }

    /// Nonempty; in fixed schema order.
    pub(crate) fn fields(&self) -> &[ToolField] {
        &self.fields
    }
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// Discover the project config and the files it sources, parse and validate each,
/// merge, and check persist ownership. Any read/parse/validation failure is a
/// contextual hard error — there is no fallback to defaults.
///
/// The project config is read first: it decides which other files are read at all
/// (ADR-0074). A project config that lists no `sources` behaves exactly as the
/// implicit `home:trust <user config>`, which is #733's shipped two-tier load.
pub(crate) fn load(paths: &ConfigPaths) -> Result<ConfigReport> {
    // One leaf-visit counter for the whole load (#735, D6): project tool lists,
    // then each source in `sources` order (the `:trust` user file at its own
    // position). It is moved into the report so the single catalog build
    // continues from exactly here.
    let mut work = config_mounts::MountExpansionWork::fresh();
    let ProjectRead {
        report: project,
        contents: project_contents,
        declared,
    } = match &paths.project {
        Some(project) => read_project_tier(project, paths.home.as_deref(), &mut work)?,
        None => ProjectRead::unavailable(),
    };
    let (sources, project_image) = match &paths.project {
        Some(project) => {
            let sources = declared_sources(paths, declared.sources.as_deref(), &project.config)?;
            let image =
                classify_project_image(declared.image.as_deref(), &sources, &project.config)?;
            (sources, image)
        }
        // A missing project tier carries no declarations, so both tiers are
        // `UnavailableHome` and nothing is sourced.
        None => (crate::config_sources::DeclaredSources::implicit(None), None),
    };
    let project_config_path = paths
        .project
        .as_ref()
        .map(|project| project.config.as_path());

    // The user tier is the `:trust` source and nothing else: a list without one
    // never reads `~/.config/agent-vm/config.toml`.
    let mut user = not_sourced_tier(paths.user.as_deref());
    let mut user_contents = TierContents::empty();
    let mut reports = Vec::new();
    let mut source_tools: Vec<Vec<Tool>> = Vec::new();
    let mut source_images: Vec<(&crate::config_sources::SourceEntry, Option<ConfiguredImage>)> =
        Vec::new();
    for entry in sources.entries() {
        let (tier, contents) = match entry.trust() {
            crate::config_sources::SourceTrust::Trusted => {
                // D3: trust is bound to the discovered `paths.user` and its verified
                // route, never to `entry.path()`'s spelling.
                let user_path = paths.user.as_deref().ok_or_else(|| {
                    anyhow!("internal: trusted source without a discovered user config path")
                })?;
                read_user_tier(user_path, paths.route(), paths.home.as_deref(), &mut work)?
            }
            crate::config_sources::SourceTrust::Untrusted => {
                read_source_tier(entry, paths.home.as_deref(), &mut work)?
            }
        };
        reports.push(SourceReport {
            alias: entry.alias().clone(),
            trust: entry.trust(),
            tier: tier.clone(),
        });
        match entry.trust() {
            crate::config_sources::SourceTrust::Trusted => {
                user = tier;
                user_contents = contents;
            }
            crate::config_sources::SourceTrust::Untrusted => {
                source_images.push((entry, contents.image));
                source_tools.push(contents.tools);
            }
        }
    }

    let trusted_image = match user_contents.image.as_ref() {
        Some(image) => TrustedImage::Declared(image),
        None if *user.status() == TierStatus::Absent => TrustedImage::Absent,
        None => TrustedImage::NoImage,
    };
    let images = resolve_images(
        project_image,
        trusted_image,
        &sources,
        &source_images,
        project_config_path,
    )?;

    let project_side_tools = project_contents.tools;
    let (resolved, conflicts) = authorize_tools(AuthorizationInputs {
        user: user_contents.tools,
        project: project_side_tools,
        sources: source_tools,
        user_allow: user_contents.allow_tools.as_ref(),
        project_allow: declared.allow_tools.as_deref(),
        user_trust: user_contents.reference_trust.as_ref(),
        declared: &sources,
        user_status: user.status(),
        user_file: paths.user.as_deref(),
        project_file: paths
            .project
            .as_ref()
            .map(|project| project.config.as_path()),
    })?;
    let uses_defaults = !resolved.authorized_explicitly;

    validate_persist_ownership(resolved.launch_tools())?;

    let inert_tools = resolved.inert_tools().to_vec();
    Ok(ConfigReport {
        user,
        project,
        resolved,
        images,
        user_network: user_contents.network,
        user_mounts: user_contents.mounts,
        user_tools: user_contents.reference_tools,
        uses_defaults,
        conflicts,
        sources: SourcesReport {
            sourcing: sources.sourcing(),
            entries: reports,
        },
        inert_tools,
        mount_work: work,
    })
}

/// What one parsed tier supplied: its tools and its optional `image`. Kept as
/// one value so the tool count and the image cannot be read from two different
/// parses.
struct TierContents {
    network: Option<UserNetwork>,
    /// The user tier's verified mount configuration (defaults and/or named
    /// sets), present-empty included.
    mounts: Option<UserMounts>,
    tools: Vec<Tool>,
    image: Option<ConfiguredImage>,
    /// The user tier's egress-reference namespace, built from these sets. `None`
    /// for the project tier and for an absent user file.
    reference_tools: Option<EgressNamespace>,
    /// The `:trust` file's own `allow_tools`, admitted only through the ADR-0040
    /// token (#735, D5).
    allow_tools: Option<crate::config_allow_tools::UserAllowTools>,
    /// The same read's measurement, for a project `allow_tools` entry that
    /// selects a definition out of this file.
    reference_trust: Option<crate::config_authority::ReferenceTrust>,
}

impl TierContents {
    fn empty() -> Self {
        Self {
            tools: Vec::new(),
            image: None,
            network: None,
            mounts: None,
            reference_tools: None,
            allow_tools: None,
            reference_trust: None,
        }
    }
}

/// Which tier a file is, where provenance matters: a tool declaration keeps the
/// tier it was written in for diagnostics, conflict warnings and the egress
/// reference scope's identity.
#[derive(Clone, Copy)]
enum FileTierKind<'a> {
    User,
    Project,
    Source(&'a crate::config_sources::SourceAlias),
}

impl FileTierKind<'_> {
    fn origin(self, file: &Path) -> ToolOrigin {
        match self {
            FileTierKind::User => ToolOrigin::User(file.to_path_buf()),
            FileTierKind::Project => ToolOrigin::Project(file.to_path_buf()),
            FileTierKind::Source(alias) => ToolOrigin::Source {
                alias: alias.clone(),
                file: file.to_path_buf(),
            },
        }
    }
}

fn unavailable_home_tier() -> (TierReport, TierContents) {
    (
        TierReport {
            path: None,
            status: TierStatus::UnavailableHome,
        },
        TierContents::empty(),
    )
}

fn absent_tier(path: &Path) -> (TierReport, TierContents) {
    (
        TierReport {
            path: Some(path.to_path_buf()),
            status: TierStatus::Absent,
        },
        TierContents::empty(),
    )
}

/// The user tier when the project config sources no `:trust` file: present but
/// deliberately not read (ADR-0074). `UnavailableHome` still wins when there is no
/// `$HOME` at all, because then the tier cannot even be located.
fn not_sourced_tier(user: Option<&Path>) -> TierReport {
    TierReport {
        path: user.map(Path::to_path_buf),
        status: match user {
            Some(_) => TierStatus::NotSourced,
            None => TierStatus::UnavailableHome,
        },
    }
}

/// Decode and parse one tier's bytes: the half every file tier shares once its
/// bytes are in hand. Diagnostics never echo a value, and invalid UTF-8 is its
/// own error (see the module's value-safe rules).
///
/// The placement refusal runs before the schema for a reason: a top-level key
/// swallowed by a table header is a *well-typed* document (or a field serde rejects
/// with its fixed, generic sentence), so only a look at the document as written can
/// say which table took it and where the line belongs.
fn parse_tier(path: &Path, bytes: &[u8]) -> Result<RawConfig> {
    let text = std::str::from_utf8(bytes).map_err(|_| utf8_error(path))?;
    if let Some(diagnostic) = misplaced_top_level_keys(text) {
        return Err(anyhow!(
            "config: {}: {diagnostic}",
            crate::one_line::quoted_path(path)
        ));
    }
    toml::from_str(text).map_err(|error| deserialize_error(path, text, &error))
}

/// The top-level keys whose meaning is lost the moment a `[table]` header
/// swallows them: `sources`, and `allow_tools` (#735). Both are read from the
/// document's root only, so a later assignment is a different key to every reader.
const ORDER_SENSITIVE_TOP_LEVEL: [&str; 2] = ["sources", "allow_tools"];

/// A top-level key written after a table header becomes a member of that table,
/// where no reader looks for it, so the file silently sources nothing — or
/// authorizes nothing.
///
/// The document is only syntax-checked: a `sources` or `allow_tools` member is a
/// *shape* no tool and no `[network]` setting can legally have, so finding one is
/// proof of the misplacement, never of an intent about its contents, and nothing is
/// echoed from the file beyond the canonical table spelling and an index.
///
/// `[mount_sets]` and `[egress_sets]` are deliberately not examined: a key there
/// is reserved by [`TOP_LEVEL_FIELDS`] and refused by the set parsers with the same
/// placement rule in their own words.
fn misplaced_top_level_keys(text: &str) -> Option<String> {
    let document: toml::Table = toml::from_str(text).ok()?;
    if let Some(network) = document.get("network").and_then(toml::Value::as_table) {
        for key in ORDER_SENSITIVE_TOP_LEVEL {
            if network.contains_key(key) {
                return Some(format!(
                    "[network]: {key} is not a network setting; a top-level {key} must be written \
                     before the first table header (keys after [network] belong to it)"
                ));
            }
        }
    }
    let tools = document.get("tools").and_then(toml::Value::as_array);
    for (index, tool) in tools.into_iter().flatten().enumerate() {
        let Some(tool) = tool.as_table() else {
            continue;
        };
        for key in ORDER_SENSITIVE_TOP_LEVEL {
            if tool.contains_key(key) {
                return Some(format!(
                    "tools[{index}]: {key} is not a tool field; a top-level {key} must be written \
                     before the first table header (keys after [[tools]] belong to the last tool)"
                ));
            }
        }
    }
    None
}

/// What one tier's *measured* read established, before its bytes are
/// interpreted. The two tiers are measured differently and must not be
/// confusable, so they are separate arms rather than an `Option` of tokens.
enum TierAuthority<'a> {
    /// ADR-0040's verified read: the verdict is unconditional, but the token it
    /// mints is `Some` only for a file that declares an authority-bearing field.
    User(config_authority::Verification<'a>),
    /// ADR-0073: measured unconditionally, and may declare no authority field at
    /// all — so there is no token to mint.
    Project,
    /// A file sourced without `:trust` (ADR-0074): no measurement, unpinned until
    /// #736; refuses every authority field.
    Source,
}

/// Read, verify, decode, and validate the **user** tier, which is the `:trust`
/// source (ADR-0074).
///
/// Only a `NotFound` from the initial `symlink_metadata` means absent, so a host
/// without a user config never fails; a present-but-dangling symlink or a file that
/// vanishes before the read is an error, not a quiet fallback. A final symlink is
/// followed (ADR-0040's dotfile compatibility), and the bytes are read before the
/// verdict: that is the user tier's shipped rule and it is unchanged.
///
/// What *is* new (ADR-0074 D3) is that the **route** is checked first: a parent or
/// final symlink resolving into the active checkout is refused before any byte is
/// read, so repository-controlled bytes can contribute neither tools, image nor
/// authority. Both the implicit `home:trust` default and an explicit
/// `<alias>:trust ~/.config/agent-vm/config.toml` arrive here with the discovered
/// path, never the entry's spelling.
fn read_user_tier(
    path: &Path,
    route: &crate::project_config::RouteAnchor,
    home: Option<&Path>,
    work: &mut config_mounts::MountExpansionWork,
) -> Result<(TierReport, TierContents)> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(absent_tier(path));
        }
        Err(error) => return Err(safe_io_error("reading metadata for", path, &error)),
    }

    // Before `config.toml` is opened: a `~/.config` or `~/.config/agent-vm` symlink
    // into the checkout would pass the file's own measurement.
    crate::project_config::check_user_parent_route(path, route)?;
    let read = match crate::host_paths::open_regular_no_follow_checkpointed(path, || {})
        .map_err(|error| safe_anyhow_error("reading", path, &error))?
    {
        Some(opened) => opened
            .into_verified_read(MAX_CONFIG_FILE_BYTES)
            .map_err(|error| safe_anyhow_error("reading", path, &error))?,
        None => {
            // A final symlink: decide about its target before opening it. Outside
            // the checkout this keeps ADR-0040's dotfile compatibility; an alias of
            // a checkout file is refused here (U2).
            crate::project_config::check_user_symlink_target(path, route)?;
            crate::host_paths::read_bounded_symlink_target(path, MAX_CONFIG_FILE_BYTES)
                .map_err(|error| safe_anyhow_error("reading", path, &error))?
        }
    };
    let path = read.path();
    let raw = parse_tier(path, read.bytes())?;
    // Authority is decided by the *presence* of an authority-bearing field, from
    // the same verified read the bytes came from, before any of it is parsed.
    // Presence, not contents: `mounts = []`, an empty `[network]`, an empty
    // `[mount_sets]`, an empty `[egress_sets]` and a tool's `mounts = []` grant
    // nothing yet are exactly the bytes an attacker would plant.
    //
    // A tool list is measured from the raw configuration, *before* tool
    // validation: a definition with a malformed or missing `command` cannot be an
    // accepted or partially patched tool, so its mount field must not be able to
    // skip the check by making the definition invalid somewhere else.
    let first_tool_mounts = raw.tools.iter().position(|tool| tool.mounts.is_some());
    let triggers = AuthorityTriggers {
        network: raw.network.is_some(),
        mounts: config_authority::mount_authority_present(config_authority::MountAuthorityFacts {
            top_level: raw.mounts.is_some(),
            tool_field: first_tool_mounts.is_some(),
        }),
        mount_sets: raw.mount_sets.is_some(),
        egress_sets: raw.egress_sets.is_some(),
        // #735: the fifth trigger. Presence, not contents, so `allow_tools = []`
        // and `allow_tools = 123` both require the verified read — the file
        // decides which declarations become launch verbs.
        allow_tools: raw.allow_tools.is_some(),
    };
    let verification = config_authority::verify(&read, triggers).map_err(|error| {
        // A refusal caused by a tool's own field names that field first: the
        // reader has to find the list they must review, and a file with no
        // top-level `mounts` has nothing else pointing at it. The numeric site
        // is echoed, never the tool's name or the list's contents.
        let pointer = match first_tool_mounts {
            Some(declaration) if raw.mounts.is_none() => {
                format!("tools[{declaration}].mounts: ")
            }
            _ => String::new(),
        };
        anyhow!(
            "config: {}: {pointer}{error}",
            crate::one_line::quoted_path(path)
        )
    })?;
    build_tier(
        path,
        raw,
        TierAuthority::User(verification),
        FileTierKind::User,
        home,
        work,
    )
}

/// Read, verify, decode, and validate the **project** tier (ADR-0073).
///
/// Deliberately not the user tier's read path:
///
/// 1. the store route is checked before anything is opened, so a symlinked
///    `projects/` or `projects/<id>` — or an ancestor alias into the active
///    checkout — cannot quietly redirect the read to an in-repo file;
/// 2. the file is opened without following a final symlink, and the directory
///    and file facts are measured **before** one byte is read, so untrusted
///    bytes are never decoded;
/// 3. the verdict is unconditional: the project tier is the root of a project's
///    trust, not a file that becomes authority-bearing only when it declares a
///    field.
fn read_project_tier(
    project: &crate::project_config::ProjectTierPaths,
    home: Option<&Path>,
    work: &mut config_mounts::MountExpansionWork,
) -> Result<ProjectRead> {
    // Every store-route outcome is named, including the one that checks nothing
    // (`Unchecked`, reachable only from a hand-built test tier).
    match crate::project_config::check_store_route(project)? {
        crate::project_config::StoreRoute::Absent => {
            return Ok(ProjectRead::absent(&project.config));
        }
        crate::project_config::StoreRoute::Present
        | crate::project_config::StoreRoute::Unchecked => {}
    }
    let path = project.config.as_path();
    match std::fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ProjectRead::absent(path));
        }
        Err(error) => return Err(safe_io_error("reading metadata for", path, &error)),
    }

    let opened = crate::host_paths::open_regular_no_follow_checkpointed(path, || {})
        .map_err(|error| safe_anyhow_error("reading", path, &error))?;
    let Some(opened) = opened else {
        // A final symlink: refused from the no-follow open's own verdict, so
        // the target is never opened or read. `verify_project` refuses
        // `ThroughSymlink` whenever the directory is acceptable and the
        // directory error otherwise, so `Ok` here cannot happen; it is still a
        // load error rather than a panic.
        return match config_authority::verify_project(path, &FinalComponent::Symlink) {
            Err(error) => Err(project_tier_error(path, &error)),
            Ok(()) => Err(anyhow!(
                "config: {}: config.toml is a symbolic link; agent-vm will not follow it",
                crate::one_line::quoted_path(path)
            )),
        };
    };
    let final_component = FinalComponent::Regular(opened.facts());
    // Measured before its bytes are read, and whatever the file declares.
    config_authority::verify_project(path, &final_component)
        .map_err(|error| project_tier_error(path, &error))?;
    let bytes = opened
        .read_bounded(MAX_CONFIG_FILE_BYTES)
        .map_err(|error| safe_anyhow_error("reading", path, &error))?;
    let mut raw = parse_tier(path, &bytes)?;
    // Taken before `build_tier`, which would refuse `sources` (flat sourcing) and
    // read `ALIAS:image` as an OCI reference: both need the declared source list,
    // which is only known after this read.
    //
    // `allow_tools` is parsed here too, right after the verified read: its
    // *syntax* is the project file's own, and reporting it before any source is
    // opened keeps a typo from being blamed on the file it never reached.
    let allow_tools = match raw.allow_tools.take() {
        Some(value) => Some(crate::config_allow_tools::parse(
            &value,
            path,
            crate::config_allow_tools::AllowToolScope::ProjectConfig,
        )?),
        None => None,
    };
    let declared = ProjectDeclarations {
        sources: raw.sources.take(),
        image: raw.image.take(),
        allow_tools,
    };
    let (report, contents) = build_tier(
        path,
        raw,
        TierAuthority::Project,
        FileTierKind::Project,
        home,
        work,
    )?;
    Ok(ProjectRead {
        report,
        contents,
        declared,
    })
}

/// Read, verify, decode, and validate a file the project config sources
/// **without** `:trust` (ADR-0074 D4): declarations only, today unpinned.
///
/// Nothing read from it can grant authority, so the final symlink is followed
/// (`read_bounded_regular_file_noting_symlink`, the pre-ADR-0073 project read):
/// repository files are commonly symlinked. A missing file is an error, because
/// the user explicitly asked for it and a quietly empty source would hide a typo.
///
/// #736 inserts its content-hash check between the read and `parse_tier`: the bytes
/// are in hand there and nothing has been interpreted yet.
fn read_source_tier(
    entry: &crate::config_sources::SourceEntry,
    home: Option<&Path>,
    work: &mut config_mounts::MountExpansionWork,
) -> Result<(TierReport, TierContents)> {
    let path = entry.path();
    match std::fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(anyhow!(
                "config: {}: not found; the project config sources it as {}",
                crate::one_line::quoted_path(path),
                entry.declared(),
            ));
        }
        Err(error) => return Err(safe_io_error("reading metadata for", path, &error)),
    }
    let read =
        crate::host_paths::read_bounded_regular_file_noting_symlink(path, MAX_CONFIG_FILE_BYTES)
            .map_err(|error| safe_anyhow_error("reading", path, &error))?;
    let raw = parse_tier(read.path(), read.bytes())?;
    build_tier(
        read.path(),
        raw,
        TierAuthority::Source,
        FileTierKind::Source(entry.alias()),
        home,
        work,
    )
}

/// The project config's read: the tier report and contents every tier shares, plus
/// the two fields only the project config may own, taken out of the raw config
/// after its verified read and before `build_tier`.
struct ProjectRead {
    report: TierReport,
    contents: TierContents,
    declared: ProjectDeclarations,
}

/// The project file's own sourcing and image fields. Both need the declared source
/// list to be interpreted, which only exists once this read has finished.
#[derive(Default)]
struct ProjectDeclarations {
    sources: Option<Vec<String>>,
    image: Option<String>,
    /// The project's `allow_tools`, syntax-checked but not yet resolved: a name
    /// resolves only once every source has been read (#735).
    allow_tools: Option<Vec<crate::config_allow_tools::AllowToolEntry>>,
}

impl ProjectRead {
    fn absent(path: &Path) -> Self {
        let (report, contents) = absent_tier(path);
        Self {
            report,
            contents,
            declared: ProjectDeclarations::default(),
        }
    }

    fn unavailable() -> Self {
        let (report, contents) = unavailable_home_tier();
        Self {
            report,
            contents,
            declared: ProjectDeclarations::default(),
        }
    }
}

/// Resolve the project config's own `sources` list, or the implicit single
/// `home:trust <user config>` entry (ADR-0074 D2/R5).
fn declared_sources(
    paths: &ConfigPaths,
    listed: Option<&[String]>,
    project_config: &Path,
) -> Result<crate::config_sources::DeclaredSources> {
    use crate::config_sources::{DeclaredSources, ResolveContext};

    let Some(raw) = listed else {
        return Ok(DeclaredSources::implicit(paths.user.as_deref()));
    };
    let (Some(project), Some(user)) = (&paths.project, &paths.user) else {
        return Err(sources_unresolvable(project_config));
    };
    let crate::project_config::RouteAnchor::Captured { home, root } = &project.route else {
        return Err(sources_unresolvable(project_config));
    };
    DeclaredSources::listed(
        raw,
        &ResolveContext {
            project_config: &project.config,
            home,
            project_root: root,
            user_config: user,
        },
    )
}

/// E13: a listed `sources` on a tier with no captured project — reachable only
/// through a hand-built test fixture.
fn sources_unresolvable(project_config: &Path) -> anyhow::Error {
    anyhow!(
        "config: {}: sources: cannot be resolved without a captured project",
        crate::one_line::quoted_path(project_config)
    )
}

/// The project config's `image`, classified as an OCI reference or an
/// `ALIAS:image` source selection (ADR-0074 D6/R9).
enum ProjectImage {
    Direct(ConfiguredImage),
    Source(crate::config_sources::SourceAlias),
}

fn classify_project_image(
    raw: Option<&str>,
    sources: &crate::config_sources::DeclaredSources,
    project_config: &Path,
) -> Result<Option<ProjectImage>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    if let Some(alias) = crate::config_sources::image_alias(raw) {
        // Shape first, then declaration: falling back to OCI for an *undeclared*
        // alias would turn the typo `image = "rpeo:image"` into a pull of
        // `docker.io/library/rpeo:image`.
        if sources.by_alias(&alias).is_none() {
            return Err(anyhow!(
                "config: {}: image: names a source alias that sources does not declare; declare \
                 that source, or spell an image tagged \"image\" with its registry (for example \
                 docker.io/library/NAME:image)",
                crate::one_line::quoted_path(project_config)
            ));
        }
        return Ok(Some(ProjectImage::Source(alias)));
    }
    Ok(validate_image(Some(raw), project_config)?.map(ProjectImage::Direct))
}

/// The `:trust` tier's image, as an `ALIAS:image` selection sees it.
enum TrustedImage<'a> {
    /// The trusted file does not exist, which is not an error until selected.
    Absent,
    /// Declared, with its own `image`.
    Declared(&'a ConfiguredImage),
    /// Declared without an `image`.
    NoImage,
}

/// Build the image tiers and the inert list (ADR-0074 D7/R9).
///
/// A project-side image either selects a source's own `image` or is a direct OCI
/// reference; the `:trust` tier's image is the fallback, and every untrusted
/// source image the project did not select is recorded as inert for `doctor`.
fn resolve_images(
    project: Option<ProjectImage>,
    trusted: TrustedImage<'_>,
    declared: &crate::config_sources::DeclaredSources,
    source_images: &[(&crate::config_sources::SourceEntry, Option<ConfiguredImage>)],
    project_config: Option<&Path>,
) -> Result<ConfiguredImages> {
    let project = match project {
        None => None,
        Some(ProjectImage::Direct(image)) => Some(image),
        Some(ProjectImage::Source(alias)) => {
            let file = project_config.ok_or_else(|| {
                anyhow!("internal: a source image selection without a project config")
            })?;
            let entry = declared
                .by_alias(&alias)
                .ok_or_else(|| anyhow!("internal: a source image selection was not classified"))?;
            let image = match entry.trust() {
                crate::config_sources::SourceTrust::Trusted => match trusted {
                    TrustedImage::Declared(image) => Some(image.clone()),
                    TrustedImage::NoImage => {
                        return Err(image_selection_missing(
                            file,
                            entry,
                            MissingImage::DeclaresNone,
                        ));
                    }
                    TrustedImage::Absent => {
                        return Err(image_selection_missing(
                            file,
                            entry,
                            MissingImage::FileAbsent,
                        ));
                    }
                },
                crate::config_sources::SourceTrust::Untrusted => source_images
                    .iter()
                    .find(|(source, _)| source.alias() == entry.alias())
                    .and_then(|(_, image)| image.clone()),
            };
            let Some(image) = image else {
                return Err(image_selection_missing(
                    file,
                    entry,
                    MissingImage::DeclaresNone,
                ));
            };
            Some(image.authorized_by(&alias))
        }
    };
    let selected = project.as_ref().and_then(ConfiguredImage::via);
    let inert = source_images
        .iter()
        .filter_map(|(source, image)| {
            let image = image.as_ref()?;
            (selected != Some(source.alias())).then(|| InertImage {
                alias: source.alias().clone(),
                image: image.clone(),
            })
        })
        .collect();
    Ok(ConfiguredImages {
        user: match trusted {
            TrustedImage::Declared(image) => Some(image.clone()),
            TrustedImage::Absent | TrustedImage::NoImage => None,
        },
        project,
        inert,
    })
}

/// Why an `ALIAS:image` selection resolved to no image.
enum MissingImage {
    /// The file exists but declares no `image` key.
    DeclaresNone,
    /// The trusted file does not exist at all.
    FileAbsent,
}

/// I2: the project config selected a source that cannot supply an image.
fn image_selection_missing(
    project_config: &Path,
    entry: &crate::config_sources::SourceEntry,
    why: MissingImage,
) -> anyhow::Error {
    let ending = match why {
        MissingImage::DeclaresNone => "but that file declares no image",
        MissingImage::FileAbsent => "but that file does not exist",
    };
    anyhow!(
        "config: {}: image: selects the image of {}, {ending}",
        crate::one_line::quoted_path(project_config),
        entry.declared(),
    )
}

fn project_tier_error(path: &Path, error: &config_authority::UntrustedConfig) -> anyhow::Error {
    anyhow!("config: {}: {error}", crate::one_line::quoted_path(path))
}

/// Interpret and validate one tier's parsed bytes, given what its measured read
/// established. Shared by both tiers so validation, provenance and diagnostics
/// cannot drift between them.
fn build_tier(
    path: &Path,
    raw: RawConfig,
    authority: TierAuthority<'_>,
    kind: FileTierKind<'_>,
    home: Option<&Path>,
    work: &mut config_mounts::MountExpansionWork,
) -> Result<(TierReport, TierContents)> {
    // ADR-0074: flat sourcing. `read_project_tier` has already taken the project's
    // own `sources`, so a remaining key is a sourced file's own.
    if raw.sources.is_some() {
        return Err(sources_refusal(path));
    }
    let tool_mount_values: Vec<config_mounts::ToolMountValue<'_>> = raw
        .tools
        .iter()
        .enumerate()
        .filter_map(|(declaration, tool)| {
            tool.mounts
                .as_ref()
                .map(|value| config_mounts::ToolMountValue { declaration, value })
        })
        .collect();
    let authorized: Option<config_authority::AuthorizedConfig<'_>>;
    let reference_trust: Option<crate::config_authority::ReferenceTrust>;
    match authority {
        TierAuthority::User(verification) => {
            authorized = verification.authorized;
            // The same read's verdict for a CLI egress reference, which argv
            // parsing learns about only after this read is gone (ADR-0059).
            reference_trust = Some(verification.references);
        }
        TierAuthority::Project => {
            refuse_project_authority(&raw, path)?;
            authorized = None;
            reference_trust = None;
        }
        TierAuthority::Source => {
            refuse_non_user_authority(&raw, path, RefusingTier::Source)?;
            // Unpinned until #736: there is no content measurement to mint an
            // authority or a reference trust from.
            authorized = None;
            reference_trust = None;
        }
    }
    let parsed_network = match raw.network.as_ref() {
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
    let parsed_sets = match raw.egress_sets.as_ref() {
        Some(value) => {
            // As for `[network]` and `mounts`: presence *is* the trigger, so a
            // present field always produced a token. Refusing rather than skipping
            // keeps that invariant load-bearing — dropping definitions a file
            // declares must never be the quiet outcome.
            let Some(authorized) = authorized.as_ref() else {
                return Err(anyhow!(
                    "config: {}: [egress_sets]: authority was not measured",
                    crate::one_line::quoted_path(path)
                ));
            };
            Some(
                egress_reference::parse_sets(authorized, value).map_err(|error| {
                    anyhow!("config: {}: {error}", crate::one_line::quoted_path(path))
                })?,
            )
        }
        None => None,
    };
    // Only the *user* tier's tool `mounts` are authority (#735): a project or
    // sourced file's are inert declarations parsed by
    // `parse_declared_tool_mounts` below, with no verified read of their own — the
    // project store is verified separately (ADR-0073) and a sourced file is
    // unpinned until #736. Demanding the ADR-0040 token for them here would refuse
    // a shape the project tier is now allowed to declare.
    let tool_mounts_need_a_token =
        matches!(kind, FileTierKind::User) && !tool_mount_values.is_empty();
    let mut mounts = if raw.mounts.is_some() || raw.mount_sets.is_some() || tool_mounts_need_a_token
    {
        // One parser for all three fields: a sets-only file still needs the
        // verified token, because a `--mount NAME` may select one of its sets, and
        // a file whose only mount field is inside a tool must still be parsed here
        // or its declarations would reach `validate_tools` unparsed.
        let Some(authorized) = authorized.as_ref() else {
            return Err(anyhow!(
                "config: {}: mounts: authority was not measured",
                crate::one_line::quoted_path(path)
            ));
        };
        Some(
            config_mounts::from_verified_value(
                authorized,
                config_mounts::MountValues {
                    defaults: raw.mounts.as_ref(),
                    sets: raw.mount_sets.as_ref(),
                    tools: &tool_mount_values,
                },
                home,
                work,
            )
            .map_err(|error| anyhow!("config: {}: {error}", crate::one_line::quoted_path(path)))?,
        )
    } else {
        // Not a dropped declaration: every arm above returns an error rather than
        // silently skipping the definitions a file carries.
        None
    };
    let image = validate_image(raw.image.as_deref(), path)?;
    // A project or sourced file's tool `mounts` are **inert** until `allow_tools`
    // authorizes the tool (ADR-0075): validated here, with zero host-path I/O and
    // charged to the load's one counter, and activated only by an authorization.
    // The built-in tier's refusal already fired by presence.
    let tool_lists = match (kind, mounts.as_mut()) {
        (FileTierKind::User, Some(mounts)) => mounts.take_tool_lists(),
        (FileTierKind::User, None) => config_mounts::ToolMountLists::empty(),
        (FileTierKind::Project | FileTierKind::Source(_), _) if tool_mount_values.is_empty() => {
            config_mounts::ToolMountLists::empty()
        }
        (FileTierKind::Project | FileTierKind::Source(_), _) => {
            config_mounts::parse_declared_tool_mounts(path, &tool_mount_values, home, work)
                .map_err(|error| {
                    anyhow!("config: {}: {error}", crate::one_line::quoted_path(path))
                })?
        }
    };
    let tools = validate_tools(raw.tools, kind.origin(path), tool_lists)?;
    // This tier's own validated tools, before `merge` and from the same read as
    // the verdict: the only namespace an egress reference may resolve against
    // (ADR-0059). The project tier gets `None`, so it can never be one.
    let allow_tools = match raw.allow_tools.as_ref() {
        Some(value) => {
            // Presence *is* the trigger, so a present list always produced a
            // token. Refusing rather than skipping keeps that invariant
            // load-bearing: inheriting nothing from a file that declared
            // authorizations must never be the quiet outcome.
            let Some(authorized) = authorized.as_ref() else {
                return Err(anyhow!(
                    "config: {}: allow_tools: authority was not measured",
                    crate::one_line::quoted_path(path)
                ));
            };
            Some(crate::config_allow_tools::UserAllowTools::from_verified(
                authorized, value,
            )?)
        }
        None => None,
    };
    let reference_tools = match &reference_trust {
        Some(trust) => {
            let namespace = EgressNamespace::new(trust.clone(), parsed_sets).map_err(|error| {
                anyhow!("config: {}: {error}", crate::one_line::quoted_path(path))
            })?;
            Some(namespace)
        }
        None => None,
    };
    let network = match parsed_network {
        Some(parsed) => {
            // A `[network]` table is authority-bearing, so the user arm always
            // produced a namespace. Refusing rather than skipping keeps that
            // invariant load-bearing.
            let Some(user_tools) = reference_tools.as_ref() else {
                return Err(anyhow!(
                    "config: {}: [network]: authority was not measured",
                    crate::one_line::quoted_path(path)
                ));
            };
            Some(parsed.resolve(user_tools).map_err(|error| {
                anyhow!("config: {}: {error}", crate::one_line::quoted_path(path))
            })?)
        }
        None => None,
    };

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
            reference_tools,
            allow_tools,
            reference_trust,
        },
    ))
}

/// A project file may not grant anything. Network is checked first so a file
/// that declares both keeps today's `[network]` bytes, then the top-level mount
/// fields, then the first tool's own list.
fn refuse_project_authority(raw: &RawConfig, path: &Path) -> Result<()> {
    refuse_non_user_authority(raw, path, RefusingTier::Project)
}

/// ADR-0074 flat sourcing: only the project config decides which files a launch
/// reads, so any other tier that declares `sources` — `sources = []` included —
/// is refused by its presence alone.
fn sources_refusal(file: &Path) -> anyhow::Error {
    anyhow!(
        "config: {}: sources: only the project config may declare sources; a sourced file cannot \
         source another file",
        crate::one_line::quoted_path(file)
    )
}

/// The one refusal order both non-user tiers share: network, top-level `mounts`,
/// `[mount_sets]`, `[egress_sets]`, then the first tool's `mounts` in declaration
/// order.
///
/// A tool field is refused by **presence alone** — empty, a table, a number, on a
/// shadowed or otherwise unreachable definition: asking for a mount is what
/// authority means, so there is no shape of request this tier may make.
fn refuse_non_user_authority(raw: &RawConfig, path: &Path, tier: RefusingTier) -> Result<()> {
    if let Some(table) = raw.network.as_ref() {
        return Err(network_refusal(table, path, tier));
    }
    if raw.mounts.is_some() {
        return Err(mounts_refusal(path, tier));
    }
    if raw.mount_sets.is_some() {
        return Err(mount_sets_refusal(path, tier));
    }
    if raw.egress_sets.is_some() {
        return Err(egress_sets_refusal(path, tier));
    }
    // #735: a declaration is inert data, so a tool's own `mounts` is legal in a
    // sourced file (validated, and inert until `allow_tools` authorizes the tool).
    // The compiled-in defaults are the one tier that may not carry one: a shipped
    // definition is not something a launch can authorize.
    if matches!(tier, RefusingTier::BuiltIn)
        && let Some(declaration) = raw.tools.iter().position(|tool| tool.mounts.is_some())
    {
        return Err(tool_mounts_refusal(path, tier, declaration));
    }
    // `allow_tools` is refused by *presence* in a sourced file and in the
    // built-ins: `[]` and a wrong type alike, because deciding which declarations
    // become launch verbs is authority a non-`:trust` tier does not have.
    if matches!(tier, RefusingTier::Source | RefusingTier::BuiltIn) && raw.allow_tools.is_some() {
        return Err(allow_tools_refusal(path, tier));
    }
    Ok(())
}

/// A non-`:trust` tier declared `allow_tools`. The fix names the tier that may.
fn allow_tools_refusal(file: &Path, tier: RefusingTier) -> anyhow::Error {
    let reason = match tier {
        RefusingTier::Source => {
            "tools cannot be authorized by a source without :trust; authorize them with \
             allow_tools in the project config"
        }
        RefusingTier::BuiltIn => {
            "tools cannot be authorized by the built-in config; authorize them with allow_tools \
             in the user or project config"
        }
        // Unreachable: the project config is the tier that may declare it.
        RefusingTier::Project => "allow_tools cannot be declared by the project config",
    };
    anyhow!(
        "config: {}: allow_tools: {reason}",
        crate::one_line::quoted_path(file)
    )
}

#[derive(Clone, Copy)]
enum RefusingTier {
    Project,
    /// A file the project config sources without `:trust` (ADR-0074).
    Source,
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
        RefusingTier::Source => "network access cannot be granted by a source without :trust",
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
    anyhow!(
        "config: {}: {}; use --mount launch options, or mounts in the user config",
        crate::one_line::quoted_path(file),
        mounts_refusal_reason(tier)
    )
}

/// The one sentence a non-user tier's mount refusal states, shared by the
/// top-level field and a tool's own so the two cannot drift.
fn mounts_refusal_reason(tier: RefusingTier) -> &'static str {
    match tier {
        RefusingTier::Project => "mounts cannot be declared by the project config",
        RefusingTier::Source => "mounts cannot be declared by a source without :trust",
        RefusingTier::BuiltIn => "mounts cannot be declared by the built-in config",
    }
}

/// A tool's own `mounts` field refused in a tier that may not declare mount
/// authority.
///
/// The subject is the numeric file/field pointer, never the tool's name: this is
/// decided before tool-name validation, so a malicious name cannot reach the
/// terminal through it.
fn tool_mounts_refusal(file: &Path, tier: RefusingTier, declaration: usize) -> anyhow::Error {
    anyhow!(
        "config: {}: tools[{declaration}].mounts: {}; use --mount launch options, or mounts in the \
         user config",
        crate::one_line::quoted_path(file),
        mounts_refusal_reason(tier)
    )
}

/// `[mount_sets]` is user-only for the same reason `mounts` is, and a project
/// table of definitions could otherwise tempt a launch into resolving a project
/// name against the user namespace. There is deliberately no such shadowing: the
/// field is refused by its presence alone, empty table included.
fn mount_sets_refusal(file: &Path, tier: RefusingTier) -> anyhow::Error {
    let reason = match tier {
        RefusingTier::Project => "mount_sets cannot be declared by the project config",
        RefusingTier::Source => "mount_sets cannot be declared by a source without :trust",
        RefusingTier::BuiltIn => "mount_sets cannot be declared by the built-in config",
    };
    anyhow!(
        "config: {}: {reason}; declare mount sets in the user config and select them with \
         --mount NAME",
        crate::one_line::quoted_path(file)
    )
}

/// `[egress_sets]` is user-only for the same reason `[mount_sets]` is: a project
/// table of definitions could otherwise tempt a launch into resolving a project
/// name against the user namespace. There is deliberately no such shadowing — the
/// field is refused by its presence alone, empty table included.
fn egress_sets_refusal(file: &Path, tier: RefusingTier) -> anyhow::Error {
    let reason = match tier {
        RefusingTier::Project => "egress_sets cannot be declared by the project config",
        RefusingTier::Source => "egress_sets cannot be declared by a source without :trust",
        RefusingTier::BuiltIn => "egress_sets cannot be declared by the built-in config",
    };
    anyhow!(
        "config: {}: {reason}; declare egress sets in the user config and select them with \
         set:NAME",
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
            via: None,
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
    let raw = builtin_raw_config(text)?;
    validate_tools(
        raw.tools,
        ToolOrigin::BuiltIn,
        config_mounts::ToolMountLists::empty(),
    )
}

/// The built-in text as raw declarations, through the deserialization and tier
/// refusal every built-in read applies. [`builtin_print`] starts here so the
/// printed declarations come through the same read, minus `validate_tools`:
/// printing re-emits raw declarations rather than re-deriving the validated
/// model, and a semantically invalid shipped declaration is a programming error
/// the launch and printer round-trip tests catch.
fn builtin_raw_config(text: &str) -> Result<RawConfig> {
    let path = Path::new("default-tools.toml");
    let raw: RawConfig =
        toml::from_str(text).map_err(|error| deserialize_error(path, text, &error))?;
    refuse_non_user_authority(&raw, path, RefusingTier::BuiltIn)?;
    if raw.sources.is_some() {
        return Err(sources_refusal(path));
    }
    Ok(raw)
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
/// shared by the user config path here, [`crate::secret_store`]'s inventory
/// path and [`crate::host_paths::state_root`]'s default. Callers add their own
/// context naming what could not be located.
pub(crate) fn host_home_dir() -> Result<Option<PathBuf>> {
    absolute_home_from(std::env::var_os("HOME").as_deref())
}

/// Pure core of [`host_home_dir`]: the discipline without the environment read,
/// so [`crate::host_paths::state_root`] can apply the same rule to the value it
/// already holds instead of restating it.
pub(crate) fn absolute_home_from(home: Option<&OsStr>) -> Result<Option<PathBuf>> {
    let Some(home) = home else {
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

// ---------------------------------------------------------------------------
// Merge and ownership
// ---------------------------------------------------------------------------

/// The inputs one authorization decision needs, as a named struct.
///
/// Three adjacent `Vec<Tool>` arguments would be transposable without the
/// compiler noticing, and they mean very different things (the user's own
/// declarations, the project config's, and each source's), so every field is
/// named at the call site.
struct AuthorizationInputs<'a> {
    user: Vec<Tool>,
    project: Vec<Tool>,
    /// Each sourced file's declarations, in `sources` order.
    sources: Vec<Vec<Tool>>,
    /// The `:trust` file's own authorizations, admitted only through the ADR-0040
    /// token (D5).
    user_allow: Option<&'a crate::config_allow_tools::UserAllowTools>,
    /// The project config's authorizations, already syntax-checked.
    project_allow: Option<&'a [crate::config_allow_tools::AllowToolEntry]>,
    /// The same read's measurement, for a project entry selecting a `:trust`
    /// definition.
    user_trust: Option<&'a crate::config_authority::ReferenceTrust>,
    declared: &'a crate::config_sources::DeclaredSources,
    user_status: &'a TierStatus,
    user_file: Option<&'a Path>,
    project_file: Option<&'a Path>,
}

/// Decide which declared tools become launch verbs (#735).
///
/// Declaration and authorization are two steps. Every `[[tools]]` block is inert
/// data; an `allow_tools` entry — or a `:trust` file's own list, inherited, or
/// the compiled-in defaults when neither file configures tools — selects the
/// verbs. The returned [`ResolvedTools`] keeps every definition, because an inert
/// one still supplies its own file's `tools` references and `doctor` reports it.
///
/// Ordering is **authorization** order, not arena order: inherited `:trust` verbs
/// in that file's `allow_tools` order (with a project override replaced in place),
/// then project-added verbs in project `allow_tools` order. Uniqueness by
/// `DefinitionId` is the only invariant, so the sequence may decrease — a
/// reversed list such as `["b", "a"]` is legal.
fn authorize_tools(
    inputs: AuthorizationInputs<'_>,
) -> Result<(ResolvedTools, Vec<ConfigConflict>)> {
    let AuthorizationInputs {
        user,
        project,
        sources,
        user_allow,
        project_allow,
        user_trust,
        declared,
        user_status,
        user_file,
        project_file,
    } = inputs;

    // R4: the compiled-in defaults apply iff neither file declares a tool *and*
    // neither writes an `allow_tools` key. A sourced file's inert declarations
    // therefore no longer displace them (ADR-0074 G6).
    if user.is_empty() && project.is_empty() && user_allow.is_none() && project_allow.is_none() {
        let sourced: Vec<Tool> = sources.into_iter().flatten().collect();
        return Ok((
            ResolvedTools::from_defaults_retaining(default_tools()?, sourced),
            Vec::new(),
        ));
    }

    // Arena order: user, project, then each source in `sources` order. It is the
    // order a definition's diagnostic names and nothing else.
    let mut definitions: Vec<Tool> = user;
    definitions.extend(project);
    for file in sources {
        definitions.extend(file);
    }
    let index = scoped_tool_index(&definitions)?;

    let mut launches: Vec<DefinitionId> = Vec::new();
    let mut verb_slots: BTreeMap<String, DefinitionId> = BTreeMap::new();
    let mut conflicts = Vec::new();
    let mut overridden: BTreeSet<DefinitionId> = BTreeSet::new();

    // Step A: the `:trust` file's own authorizations, inherited.
    if let Some(allow) = user_allow {
        let file = allow.file();
        for (entry_index, name) in allow.names() {
            let origin = ToolOrigin::User(file.to_path_buf());
            let Some(&target) = index.get(&(&origin, name)) else {
                return Err(allow_tools_error(
                    file,
                    entry_index,
                    "no tool of that name is declared in this file; declare it in a [[tools]] \
                     block above allow_tools"
                        .to_owned(),
                ));
            };
            if verb_slots.contains_key(name) {
                continue;
            }
            launches.push(target);
            verb_slots.insert(name.to_owned(), target);
        }
    }
    // The verbs this project list has already named, with the definition it named and
    // the entry spelling it wrote. A list is a *decision*, so its first entry for a
    // verb settles it: naming the very same target twice is idempotent, and naming a
    // different one afterwards collides even when the first entry happened to be a
    // no-op against the inherited slot (`["home:pi", "repo:pi"]`, R3). The spelling
    // is what `doctor` names when it advises replacing a claim (#735 review D2).
    let mut project_claims: BTreeMap<String, (DefinitionId, String)> = BTreeMap::new();

    // Step B: the project config's authorizations, local and `<alias>:<name>`.
    if let Some(entries) = project_allow {
        let file = project_file.ok_or_else(|| {
            anyhow!("internal: project allow_tools without a project config path")
        })?;
        for (entry_index, entry) in entries.iter().enumerate() {
            let target = resolve_allow_tool_entry(
                entry,
                &EntryContext {
                    entry_index,
                    file,
                    index: &index,
                    definitions: &definitions,
                    declared,
                    user_trust,
                    user_status,
                    user_file,
                    project_file,
                },
            )?;
            let name = definitions[target.0].name().to_owned();
            if let Some(&(claimed, _)) = project_claims.get(&name) {
                if claimed == target {
                    // The exact same target twice in one list: idempotent.
                    continue;
                }
                return Err(second_tool_for_verb_error(
                    file,
                    entry_index,
                    &name,
                    &definitions[claimed.0],
                ));
            }
            project_claims.insert(
                name.clone(),
                (
                    target,
                    match entry.alias() {
                        Some(alias) => format!("{alias}:{}", entry.name()),
                        None => entry.name().to_owned(),
                    },
                ),
            );
            match verb_slots.get(&name).copied() {
                // Idempotent: an inherited `:trust` tool named explicitly.
                Some(existing) if existing == target => continue,
                // The project config outranks the `:trust` file's own
                // authorization, as it outranks its image (ADR-0074 D5). The
                // overridden definition stays in the arena so the trusted file's
                // other tools keep resolving it. `project_claims` above has
                // already ruled out a slot this same list established, so
                // `existing` is always the inherited one.
                Some(existing) => {
                    if let Some(slot) = launches.iter_mut().find(|id| **id == existing) {
                        *slot = target;
                    }
                    overridden.insert(existing);
                    verb_slots.insert(name.clone(), target);
                    let winner = &definitions[target.0];
                    let loser = &definitions[existing.0];
                    if !winner.same_definition(loser) {
                        conflicts.push(ConfigConflict {
                            tool: winner.name.clone(),
                            winner_file: origin_file(winner.origin()).to_path_buf(),
                            overridden_file: origin_file(loser.origin()).to_path_buf(),
                            fields: loser.differing_fields(winner),
                        });
                    }
                }
                None => {
                    launches.push(target);
                    verb_slots.insert(name, target);
                }
            }
        }
    }

    let authorized: BTreeSet<DefinitionId> = launches.iter().copied().collect();
    let inert: Vec<InertTool> = definitions
        .iter()
        .enumerate()
        .filter(|(position, _)| {
            let id = DefinitionId(*position);
            !authorized.contains(&id) && !overridden.contains(&id)
        })
        .map(|(_, tool)| InertTool {
            name: tool.name.clone(),
            origin: tool.origin.clone(),
        })
        .collect();
    Ok((
        ResolvedTools {
            definitions,
            launches,
            authorized,
            authorized_explicitly: true,
            inert,
            project_claims: project_claims
                .into_iter()
                .map(|(name, (_, entry))| (name, entry))
                .collect(),
        },
        conflicts,
    ))
}

/// The frame one `allow_tools` entry is resolved in: the file that wrote the
/// list and its index in that list, plus the loaded tiers the lookup reads.
///
/// A struct rather than ten positional parameters, three of them adjacent
/// `&Path`s and two more adjacent `Option<&Path>`s, which a call site could
/// transpose without the compiler noticing (`CODING_STANDARDS.md` → *Types*).
struct EntryContext<'a> {
    entry_index: usize,
    /// The file that wrote the list, for the `allow_tools[N]` diagnostic.
    file: &'a Path,
    index: &'a ScopedToolIndex<'a>,
    definitions: &'a [Tool],
    declared: &'a crate::config_sources::DeclaredSources,
    user_trust: Option<&'a crate::config_authority::ReferenceTrust>,
    user_status: &'a TierStatus,
    user_file: Option<&'a Path>,
    project_file: Option<&'a Path>,
}

/// Resolve one project `allow_tools` entry to the definition it authorizes.
///
/// Unqualified names resolve strictly against the project config's own
/// `[[tools]]`; a qualified `<alias>:<name>` against the source bound to
/// `<alias>` — and, when that source is `:trust`, only after its own read's
/// verdict vouches for the definition the project would activate (D5).
fn resolve_allow_tool_entry(
    entry: &crate::config_allow_tools::AllowToolEntry,
    context: &EntryContext<'_>,
) -> Result<DefinitionId> {
    use crate::config_sources::SourceTrust;
    let EntryContext {
        entry_index,
        file,
        index,
        definitions,
        declared,
        user_trust,
        user_status,
        user_file,
        project_file,
    } = *context;

    let (origin, declaration) = match entry.alias() {
        None => {
            let project_file = project_file.ok_or_else(|| {
                anyhow!("internal: project allow_tools without a project config path")
            })?;
            let origin = ToolOrigin::Project(project_file.to_path_buf());
            let advice = declared_elsewhere_advice(definitions, &origin, entry.name());
            let Some(&target) = index.get(&(&origin, entry.name())) else {
                return Err(allow_tools_error(
                    file,
                    entry_index,
                    format!(
                        "no tool of that name is declared in this file{advice}; declare it in a \
                         [[tools]] block here, or qualify it as <alias>:<name>"
                    ),
                ));
            };
            return Ok(target);
        }
        Some(alias) => {
            let Some(source) = declared.by_alias(alias) else {
                return Err(allow_tools_error(
                    file,
                    entry_index,
                    "names a source alias that sources does not declare".to_owned(),
                ));
            };
            match source.trust() {
                SourceTrust::Trusted => {
                    // The file's own read is the one that counts, and it may have
                    // declared none of the five triggers — a tools-only symlink
                    // loads through ADR-0040's compatibility rule. The project's
                    // selection is what needs its verdict, attributed to the
                    // definition rather than to a list the file may not have.
                    if *user_status == TierStatus::Absent {
                        return Err(allow_tools_error(
                            file,
                            entry_index,
                            format!(
                                "selects a tool from {}, but that file does not exist",
                                source.declared()
                            ),
                        ));
                    }
                    let trust = user_trust.ok_or_else(|| {
                        anyhow!("internal: a :trust source read without its verdict")
                    })?;
                    trust.require_for_trusted_tool().map_err(|refusal| {
                        allow_tools_error(
                            file,
                            entry_index,
                            format!("{refusal} (selecting a tool from {})", source.declared()),
                        )
                    })?;
                    let user_file = user_file.ok_or_else(|| {
                        anyhow!("internal: a :trust source without a discovered user path")
                    })?;
                    (ToolOrigin::User(user_file.to_path_buf()), source.declared())
                }
                // Unpinned until #736: the named definition's own fields are
                // activated exactly as the file declares them now.
                SourceTrust::Untrusted => (
                    ToolOrigin::Source {
                        alias: alias.clone(),
                        file: source.path().to_path_buf(),
                    },
                    source.declared(),
                ),
            }
        }
    };
    let Some(&target) = index.get(&(&origin, entry.name())) else {
        let advice = declared_elsewhere_advice(definitions, &origin, entry.name());
        return Err(allow_tools_error(
            file,
            entry_index,
            format!("no tool of that name is declared by {declaration}{advice}"),
        ));
    };
    Ok(target)
}

/// The `; it is declared in …` advice for a local `allow_tools` name that this
/// file does not declare.
///
/// Diagnostics only: the scoped lookup already decided validity, and crossing
/// files is never a fallback — it is only ever advice, naming the alias the
/// reader would have to write.
fn declared_elsewhere_advice(definitions: &[Tool], wanted: &ToolOrigin, name: &str) -> String {
    let Some(other) = definitions.iter().find(|tool| {
        tool.name() == name
            && !same_reference_scope(ReferenceOrigins {
                declaring: wanted,
                candidate: tool.origin(),
            })
    }) else {
        return String::new();
    };
    match other.origin() {
        ToolOrigin::Source { alias, .. } => format!(
            "; it is declared in {} — qualify it as {}",
            describe_origin(other.origin()),
            quoted_str(&format!("{alias}:{name}"))
        ),
        origin => format!("; it is declared in {}", describe_origin(origin)),
    }
}

/// The refusal for a project `allow_tools` list that authorizes a second, different
/// definition for a launch verb the list already settled.
fn second_tool_for_verb_error(
    file: &Path,
    entry_index: usize,
    name: &str,
    claimant: &Tool,
) -> anyhow::Error {
    allow_tools_error(
        file,
        entry_index,
        format!(
            "authorizes a second tool named {}; {} already claims that launch verb. Authorize one \
             of them, or rename one definition",
            quoted_str(name),
            describe_origin(claimant.origin()),
        ),
    )
}

/// The one `allow_tools` diagnostic shape: file, entry index, message. Nothing
/// from the entry is echoed.
fn allow_tools_error(file: &Path, index: usize, message: String) -> anyhow::Error {
    anyhow!(
        "config: {}: allow_tools[{index}]: {message}",
        crate::one_line::quoted_path(file)
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
pub(crate) fn describe_origin(origin: &ToolOrigin) -> String {
    let tier = match origin {
        ToolOrigin::BuiltIn => "built-in defaults".to_owned(),
        ToolOrigin::User(_) => "user config".to_owned(),
        ToolOrigin::Project(_) => "project config".to_owned(),
        // The alias is validated lowercase ASCII, so it prints raw.
        ToolOrigin::Source { alias, .. } => format!("source {alias}"),
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
        ToolOrigin::Source { file, .. } => file,
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

/// One launch winner's resolved facets: the four things one visited mask supplies.
///
/// A named struct rather than a fourth positional tuple element: three of these
/// are collections and two are ordered, so an opaque four-tuple is exactly where a
/// caller transposes two facets without the compiler noticing. Pairing this with
/// its winner happens in one place, by ordered filtering.
struct ResolvedFacets {
    provisioned: ProviderSet,
    requested_names: BTreeSet<ServiceName>,
    persist: Vec<PersistPath>,
    mounts: ResolvedMountList,
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
/// names, `persist` paths and mount declarations are four facets folded over *one*
/// visited mask, so they cannot disagree about what a launch provisions. Tool
/// environment and `network_requests` stay out of the fold on purpose: they are
/// the launched tool's own, not its references'.
///
/// Every retained definition's explicit references are checked first, *including*
/// definitions no launch verb reaches: a dangling reference is an error in the
/// file that contains it, and another file's winning definition of that name
/// neither satisfies it nor hides it. Each launch winner's closure is then
/// checked for persist ownership *before* its paths escape, and the facets fold in
/// arena order, so the result never depends on traversal order.
///
/// `work` is the leaf-visit budget **continued** from the verified parse
/// ([`ConfigReport::into_launch_catalog`]); the mount facet is the only thing that
/// spends it here, because it is the only facet whose size can be amplified by a
/// repeated inherited list. One visited mask exists at a time — the mask is
/// dropped before the next launch is resolved — so retained memory does not grow
/// with the square of the catalog.
fn resolve_provisioning(
    tools: ResolvedTools,
    work: &mut config_mounts::MountExpansionWork,
) -> Result<Vec<CatalogEntry>> {
    let ResolvedTools {
        definitions,
        launches,
        authorized,
        authorized_explicitly,
        ..
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

    // Each entry is built from its exact `DefinitionId`, in launch order. The
    // `(DefinitionId, ResolvedFacets)` pair is formed where the facets are folded,
    // so a tool can only ever be joined with its own closure's facets — the
    // order is a launch (authorization) order and is never assumed to be arena
    // order (#735, finding 1).
    let mut resolved: Vec<(DefinitionId, ResolvedFacets)> = Vec::with_capacity(launches.len());
    for start in &launches {
        let visited = launch_closure(&definitions, &index, *start)?;
        // R6: a non-`:trust` (future-pinned) source's `tools = [...]` closure must
        // be authorized in full. Exact `DefinitionId`s, so a same-named authorized
        // tool in `home` or the project config can never satisfy a source's edge.
        enforce_closure_authorization(&definitions, &visited, *start, &authorized)?;
        // Ownership before any facet escapes: two definitions selected by the
        // same launch may not claim one guest path or an ancestor/descendant
        // pair, even when one of them lost its launch verb. Unguarded here, a
        // hidden loser's paths would reach the guest-HOME link list unvalidated.
        validate_persist_ownership(closure_definitions(&definitions, &visited))?;
        let mut provisioned = ProviderSet::default();
        let mut requested_names = BTreeSet::new();
        let mut persist = Vec::new();
        let mut lists: Vec<&ResolvedMountList> = Vec::new();
        for tool in closure_definitions(&definitions, &visited) {
            provisioned = provisioned.union(tool.credential_providers());
            requested_names.extend(tool.credential_names().iter().cloned());
            persist.extend(tool.persist().iter().cloned());
            // Arena order, so the union is the deterministic fold the other three
            // facets use. An empty list is skipped rather than folded: it can
            // contribute nothing and must not spend a budget visit.
            if !tool.mounts().is_empty() {
                lists.push(tool.mounts());
            }
        }
        let mounts = config_mounts::merge_tool_mounts(lists, work).map_err(|error| {
            // A closure conflict is a catalog error for *this* launch: the two
            // lists agree with themselves and only disagree when one launch
            // selects both. Naming the launching declaration is what makes that
            // fixable, and the file comes from `tool_error`'s origin.
            let launcher = &definitions[start.0];
            tool_error(
                &launcher.origin,
                launcher.declaration_index,
                &launcher.name,
                error,
            )
        })?;
        resolved.push((
            *start,
            ResolvedFacets {
                provisioned,
                requested_names,
                persist,
                mounts,
            },
        ));
    }
    drop(index);

    // Retention ends here: only the launch winners survive, each taken from its
    // own arena slot so a definition can be handed on exactly once.
    let mut slots: Vec<Option<Tool>> = definitions.into_iter().map(Some).collect();
    resolved
        .into_iter()
        .map(|(id, facets)| {
            let tool = slots.get_mut(id.0).and_then(Option::take).ok_or_else(|| {
                anyhow!(
                    "internal: launch entry {} is out of range or selected twice; report this \
                     as an agent-vm bug",
                    id.0
                )
            })?;
            Ok(CatalogEntry {
                tool,
                provisioned: facets.provisioned,
                requested_names: facets.requested_names,
                persist: facets.persist,
                mounts: facets.mounts,
                authorized_egress: authorized_explicitly,
            })
        })
        .collect()
}

/// Whether a launch of a definition from this origin requires every tool in its
/// `tools = [...]` closure to be authorized too (#735, R6).
///
/// True for a non-`:trust` source only: it is a file outside the user's host
/// configs, so authorizing one of its tools must not silently pull its helpers
/// in. The three user-authored tiers may keep private helper declarations — a
/// local `pi` naming a local `claude` is one file the user wrote. When #736 turns
/// a source into a pinned one this predicate is unchanged: pinning is about the
/// bytes, not about who authorized the tool.
fn requires_explicit_closure_authorization(origin: &ToolOrigin) -> bool {
    matches!(origin, ToolOrigin::Source { .. })
}

/// Refuse a launch whose `tools` closure visits a definition nothing authorized.
///
/// Names the launching tool, its file, the unauthorized referenced tool and the
/// exact fix, because the fix is one entry in one list.
fn enforce_closure_authorization(
    definitions: &[Tool],
    visited: &[bool],
    start: DefinitionId,
    authorized: &BTreeSet<DefinitionId>,
) -> Result<()> {
    let launcher = &definitions[start.0];
    if !requires_explicit_closure_authorization(launcher.origin()) {
        return Ok(());
    }
    for (position, seen) in visited.iter().enumerate() {
        if !seen || position == start.0 {
            continue;
        }
        let id = DefinitionId(position);
        if authorized.contains(&id) {
            continue;
        }
        let referenced = &definitions[position];
        let qualifier = match referenced.origin() {
            ToolOrigin::Source { alias, .. } => {
                format!("{alias}:{}", referenced.name())
            }
            _ => referenced.name().to_owned(),
        };
        return Err(tool_error(
            &launcher.origin,
            launcher.declaration_index,
            &launcher.name,
            format!(
                "tools closure references {} which is not authorized in allow_tools; add {} to \
                 allow_tools in the project config",
                quoted_str(referenced.name()),
                quoted_str(&qualifier),
            ),
        ));
    }
    Ok(())
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

/// A config file's top-level field names, which are therefore the **reserved**
/// mount-set names.
///
/// TOML assigns a bare key to the most recent `[table]` header, so a top-level key
/// written after `[mount_sets]` becomes a set definition — and not every such value
/// has a shape that betrays it: `image = "ref"` is refused only as an unexplained
/// `mount_sets[N]` type error, while `mounts = [...]` is a well-shaped set named
/// `mounts` that selects nothing, the defaults silently gone. Reserving these five
/// names turns both into one sentence that names the key and the fix. Tool, route
/// and subcommand words stay unreserved (`pi`, `shell`), because none of them can
/// be a top-level key.
///
/// `egress_sets` is the sixth (#511) and is reserved for the same reason: a
/// `[network]` table written after `[egress_sets]` would become a set named
/// `network` that grants nothing. `sources` (#734) and `allow_tools` (#735) are
/// reserved for the same reason.
///
/// Held here rather than in `config_mounts` because this module owns the schema the
/// names come from: the test beside `RawConfig` proves each one is still accepted at
/// the top level, so a renamed field cannot leave a stale reservation behind.
pub(crate) const TOP_LEVEL_FIELDS: [&str; 8] = [
    "allow_tools",
    "egress_sets",
    "image",
    "mounts",
    "mount_sets",
    "network",
    "sources",
    "tools",
];

/// The canonical spelling of `name` when it is a top-level field name.
///
/// `Option<&'static str>` rather than a `bool`: the diagnostic prints the spelling
/// returned here, so a mount-set or egress-set sentence can only ever contain one
/// of these six words and never bytes read from the file.
pub(crate) fn top_level_field(name: &str) -> Option<&'static str> {
    TOP_LEVEL_FIELDS
        .iter()
        .copied()
        .find(|field| *field == name)
}

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
    // User tier only (ADR-0048): the named **mount sets**. Untyped at this narrow
    // seam for the same reason as `mounts` — an empty table, a wrong type and a
    // named empty array must all reach the authority decision before the schema
    // complains, because presence is what makes the file authority-bearing.
    #[serde(default)]
    mount_sets: Option<toml::Value>,
    // User tier only (#511): the named **egress sets**. Untyped at this narrow
    // seam for the same reason as `mount_sets` — an empty table, a number and a
    // wrongly shaped definition must all reach the authority decision before the
    // schema complains, because presence is what makes the file authority-bearing.
    #[serde(default)]
    egress_sets: Option<toml::Value>,
    /// The session's **boot image**, an OCI reference (D4). Optional: an
    /// image-only file declares no tools and keeps the shipped defaults.
    #[serde(default)]
    image: Option<String>,
    /// Project config only (ADR-0074): the files this project sources. Every other
    /// tier refuses the key by presence (flat sourcing, S2). Strings, parsed by
    /// `config_sources` only after the project file's verified read.
    #[serde(default)]
    sources: Option<Vec<String>>,
    /// #735: which declared tools become launch verbs. A `toml::Value`, not
    /// `Vec<String>`, for the same reason `mounts` is: presence makes a `:trust`
    /// file authority-bearing, so `[]`, a table and a number must all reach the
    /// authority decision before the schema complains. Legal only in the project
    /// config and the `:trust` user config.
    #[serde(default)]
    allow_tools: Option<toml::Value>,
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
    /// This definition's own mount selection (#396), user tier only.
    ///
    /// A `toml::Value`, not `Vec<String>`, for exactly the reason the top-level
    /// field is one: presence is what makes the file authority-bearing, so
    /// `[]`, a table and a number must all survive to the authority decision
    /// before any schema complaint. Project and built-in tiers refuse the field by
    /// presence alone.
    ///
    /// Deliberately **not** honoured for a built-in tool as a patch: a mount-only
    /// setting never modifies a shipped definition. It is a field of a full
    /// definition, so declaring one at all replaces the catalog.
    #[serde(default)]
    mounts: Option<toml::Value>,
}

/// Validate the raw `[[tools]]` entries into a catalog, rejecting duplicate
/// names and reporting the exact field that failed. Sequentially applying
/// focused validators keeps each diagnosis specific instead of collapsing the
/// whole entry into one generic parse error.
fn validate_tools(
    raw: Vec<RawTool>,
    origin: ToolOrigin,
    mounts: config_mounts::ToolMountLists,
) -> Result<Vec<Tool>> {
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
            // Already parsed and validated from the verified read, so this is a
            // shared handle, not a second parse. Whole-definition merging needs no
            // special case here: a user winner keeps all of its own fields, and a
            // project definition's mount field was refused before this point.
            mounts: mounts.get(index),
            origin: origin.clone(),
            declaration_index: index,
        });
    }
    Ok(tools)
}

fn validate_name(raw: &str, origin: &ToolOrigin, index: usize) -> Result<ToolName> {
    if let Some(rejection) = tool_name_rejection(raw) {
        return Err(declaration_error(
            origin,
            index,
            rejection.echoes_name().then_some(raw),
            rejection.reason(),
        ));
    }
    Ok(ToolName(raw.to_string()))
}

/// Why one string cannot be a tool name, and nowhere else.
///
/// An enum rather than a `Result<ToolName, &'static str>`, because a second
/// caller decides a different thing from the same rule: #735's `allow_tools`
/// parser accepts a name iff this predicate is `None`, and its refusal needs a
/// *fixed* text, never the declaration diagnostic. The reasons are the same
/// strings `[[tools]]` has always printed, so a declaration and an authorization
/// cannot disagree about what a name is — and `:` is refused by both, which is
/// what keeps `<alias>:<name>` unambiguous.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ToolNameRejection {
    Empty,
    WhitespaceOrControl,
    LeadingDash,
    Path,
    /// #735: `:` separates a source alias from a tool name in `allow_tools`, so no
    /// declaration may contain one and every `<alias>:<name>` is unambiguous.
    Colon,
    Dots,
    Wildcard,
    DirectRun,
    Reserved,
}

impl ToolNameRejection {
    /// The declaration diagnostic, byte-identical to what `validate_name` printed
    /// before this rule was extracted.
    fn reason(self) -> &'static str {
        match self {
            Self::Empty => "name must not be empty",
            Self::WhitespaceOrControl => "name must not contain whitespace or control characters",
            Self::LeadingDash => "name must not start with '-'",
            Self::Path => "name must be a single command-name token, not a path",
            Self::Colon => {
                "name must not contain ':' (':' separates a source alias from a tool name)"
            }
            Self::Dots => "name must not be `.` or `..`",
            Self::Wildcard => "name `*` is reserved: it is the wildcard in a tool's `tools` list",
            // `run` is reserved for the direct runner, and a generic "reserved"
            // message would leave the user with no migration path (issue #398).
            // This precedes the set check so the rename advice is specific.
            Self::DirectRun => {
                "name `run` is reserved: `agent-vm run PROGRAM [ARG...]` runs a guest \
                 program directly. Rename this tool (for example `run-tool`) and launch \
                 it by the new name."
            }
            Self::Reserved => "name is reserved for an agent-vm subcommand; choose another name",
        }
    }

    /// Whether the declaration diagnostic quotes the name it refused. Only an
    /// empty name is unquotable — it would render as `""` and blame nothing.
    fn echoes_name(self) -> bool {
        !matches!(self, Self::Empty)
    }
}

/// The one tool-name rule, shared by `[[tools]]` validation and #735's
/// `allow_tools` entries.
///
/// Order matters only for *which* reason is reported; every check is independent
/// of the others.
pub(crate) fn tool_name_rejection(raw: &str) -> Option<ToolNameRejection> {
    if raw.is_empty() {
        return Some(ToolNameRejection::Empty);
    }
    if raw
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Some(ToolNameRejection::WhitespaceOrControl);
    }
    if raw.starts_with('-') {
        return Some(ToolNameRejection::LeadingDash);
    }
    if raw.contains('/') {
        return Some(ToolNameRejection::Path);
    }
    if raw.contains(':') {
        return Some(ToolNameRejection::Colon);
    }
    if raw.chars().all(|character| character == '.') {
        return Some(ToolNameRejection::Dots);
    }
    if raw == ALL_TOOLS_WILDCARD {
        return Some(ToolNameRejection::Wildcard);
    }
    if raw == crate::launch_target::DIRECT_RUN_VERB {
        return Some(ToolNameRejection::DirectRun);
    }
    if RESERVED_TOOL_NAMES.contains(&raw) {
        return Some(ToolNameRejection::Reserved);
    }
    None
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
         Required: a string `name` and `command`; `args`, `credentials`, `tools`, `persist`, \
         `mounts` and `network_requests` are arrays of strings; `env` is a table of string values; \
         the top-level `image` and each tool's `command` are strings; the top-level \
         `sources`, accepted only in the project tier, is an array of strings; the top-level \
         `mounts` and each `[[tools]]`'s `mounts` are arrays of mount declarations or mount-set \
         names; `[mount_sets]` is a table of named arrays of those mount declarations or mount-set \
         names, and `[egress_sets]` is a table of named arrays of egress allowances or `set:NAME` \
         egress references — not mount syntax. Both tables are user-tier only; a project or \
         sourced declaration is refused. TOML assigns keys to the most recent `[table]` header, so \
         write the top-level `mounts` before the first header and give each tool or set its entries \
         in its own array. Nested tables are not mount sets or egress sets.",
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

/// Fixture helpers other modules' tests share (#735). The device lives beside the
/// config model it imitates, and this module is the only door to it, so the
/// `tests` module itself stays private.
#[cfg(test)]
pub(crate) mod test_support {
    pub(crate) use super::tests::authorized_fixture;
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
        assert!(mounts.defaults().is_none_or(ResolvedMountList::is_empty));
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
            (
                "[mount_sets]\n",
                "[mount_sets]",
                "review the [mount_sets] table",
                "without [mount_sets] still",
            ),
            (
                "mounts = []\n[mount_sets]\n",
                "mounts and [mount_sets]",
                "review the mounts list and [mount_sets] table",
                "without mounts or [mount_sets] still",
            ),
            (
                "[mount_sets]\n[network]\n",
                "[network] and [mount_sets]",
                "review the [network] table and [mount_sets] table",
                "without [network] or [mount_sets] still",
            ),
            (
                "mounts = []\n[mount_sets]\n[network]\n",
                "[network], mounts and [mount_sets]",
                "review the [network] table, mounts list and [mount_sets] table",
                "without [network], mounts or [mount_sets] still",
            ),
            // #511: the fourth field names itself, alone and in the full
            // combination, and never borrows `[network]`'s words.
            (
                "[egress_sets]\n",
                "[egress_sets]",
                "review the [egress_sets] table",
                "without [egress_sets] still",
            ),
            (
                "mounts = []\n[egress_sets]\n",
                "mounts and [egress_sets]",
                "review the mounts list and [egress_sets] table",
                "without mounts or [egress_sets] still",
            ),
            (
                "mounts = []\n[mount_sets]\n[network]\n[egress_sets]\n",
                "[network], mounts, [mount_sets] and [egress_sets]",
                "review the [network] table, mounts list, [mount_sets] table and [egress_sets] table",
                "without [network], mounts, [mount_sets] or [egress_sets] still",
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

    /// `[mount_sets]` is authority-bearing by presence alone: an empty table, an
    /// empty named list and a wrong type all trigger the verified read, exactly as
    /// `mounts = []` does. The positive control is the same symlink without the
    /// table.
    #[test]
    fn mount_sets_presence_requires_a_verified_file() {
        for body in [
            "[mount_sets]\n",
            "[mount_sets]\nagent = []\n",
            "mount_sets = 7\n",
            "mount_sets = []\n",
        ] {
            let f = Fixture::new();
            f.symlinked_user(body);
            let error = f.load().unwrap_err().to_string();
            assert!(
                error.contains("[mount_sets] requires config.toml to be a regular file"),
                "{body}: {error}"
            );
            assert!(
                error.contains("review the [mount_sets] table"),
                "{body}: {error}"
            );
            // A file without any authority-bearing field is still accepted through
            // a symlink, so the refusal above is about this table.
            assert!(!error.contains("[network]"), "{body}: {error}");
        }
        let f = Fixture::new();
        f.symlinked_user("");
        assert!(f.load().unwrap().user_mounts().is_none());
        write_file(&f.user.with_file_name("dotfile"), "[mount_sets]\n");
        assert!(
            f.load()
                .unwrap_err()
                .to_string()
                .contains("[mount_sets] requires config.toml to be a regular file")
        );
    }

    /// A sets-only user file is a verified namespace with no automatic selection,
    /// and it keeps the shipped tools: definitions mount nothing by themselves.
    #[test]
    fn mount_sets_definitions_alone_select_nothing() {
        let f = Fixture::new();
        let report = f
            .user("[mount_sets]\nempty = []\nagent = [\"/a:/g:ro\"]\n")
            .load()
            .unwrap();
        assert!(report.uses_defaults());
        let mounts = report.user_mounts().expect("a sets-only file is present");
        assert!(!mounts.has_defaults());
        assert!(mounts.defaults().is_none());
        let name = crate::config_mounts::MountSetName::parse("agent").unwrap();
        assert_eq!(mounts.requests_for_set(&name).map(|r| r.len()), Some(1));
        assert_eq!(
            mounts
                .requests_for_set(&crate::config_mounts::MountSetName::parse("empty").unwrap())
                .map(|requests| requests.len()),
            Some(0)
        );
    }

    /// A top-level key written after a `[mount_sets]` header is scoped into that
    /// table, so the reserved fields are refused by name. `mounts` is the one that
    /// used to load — a well-shaped set named `mounts` that selected nothing — and
    /// `image` the one that failed as an unexplained `mount_sets[1]` type error.
    #[test]
    fn mount_sets_refuse_the_top_level_field_names() {
        for (name, value) in [
            ("image", "\"agent-vm-standard:local\""),
            ("mounts", "[\"/a:/g:ro\"]"),
            ("mount_sets", "{}"),
            ("network", "{}"),
            ("tools", "[]"),
        ] {
            let f = Fixture::new();
            let error = f
                .user(&format!("[mount_sets]\n{name} = {value}\n"))
                .load()
                .unwrap_err()
                .to_string();
            assert_eq!(
                error,
                format!(
                    "config: {:?}: mount_sets[0]: {name} is not a mount set; a top-level {name} \
                     must be written before the first table header (keys after [mount_sets] \
                     belong to it)",
                    f.user
                ),
                "{name}"
            );
        }
    }

    /// The reserved set names are the top-level field names. Each one still loads as
    /// a top-level key — `deny_unknown_fields` refuses anything else, so acceptance
    /// is membership — and the fixture list is the struct's own field list, so a
    /// field removed from `RawConfig` cannot leave a stale reservation behind. (A
    /// *new* field needs a matching reservation in `TOP_LEVEL_FIELDS`; nothing here
    /// can see that omission, which is why reserving is a documented review step.)
    #[test]
    fn reserved_set_names_are_the_top_level_fields() {
        let fields = [
            ("allow_tools", "[]"),
            ("egress_sets", "{}"),
            ("image", "\"agent-vm-standard:local\""),
            ("mounts", "[]"),
            ("mount_sets", "{}"),
            ("network", "{}"),
            ("sources", "[]"),
            ("tools", "[]"),
        ];
        assert_eq!(fields.map(|(name, _)| name), TOP_LEVEL_FIELDS);
        for (name, value) in fields {
            // `sources` is the project config's own key (flat sourcing, ADR-0074)
            // and `allow_tools` is legal in both authorizing tiers; every other
            // field still loads in the user tier.
            let result = if name == "sources" {
                SourcesFixture::new().with_project(&format!("{name} = {value}\n"))
            } else {
                Fixture::new().user(&format!("{name} = {value}\n")).load()
            };
            result.unwrap_or_else(|error| panic!("{name} must be a top-level field: {error:#}"));
        }
    }

    /// A8 and R7: `[egress_sets]` is user-only, and presence alone is the reason —
    /// an empty table, a number and a well-shaped definition are all refused the
    /// same way, so a project or shipped file cannot even suggest a set name.
    #[test]
    fn project_egress_sets_are_refused_even_when_empty() {
        for body in [
            "[egress_sets]\n",
            "[egress_sets]\ncorp = []\n",
            "egress_sets = 7\n",
        ] {
            let f = Fixture::new();
            f.project(body);
            let error = f.load().unwrap_err().to_string();
            assert_eq!(
                error,
                format!(
                    "config: {:?}: egress_sets cannot be declared by the project config; declare \
                     egress sets in the user config and select them with set:NAME",
                    f.project
                ),
                "{body}"
            );
        }
        // The refusal order is still `[network]`, `mounts`, `[mount_sets]`,
        // `[egress_sets]`, the first tool's `mounts`.
        for (body, expected) in [
            (
                "[egress_sets]\n[network]\nallow_host = true\n",
                "network access cannot be granted by the project config",
            ),
            (
                "mounts = []\n[egress_sets]\n",
                "mounts cannot be declared by the project config",
            ),
            (
                "[mount_sets]\n[egress_sets]\n",
                "mount_sets cannot be declared by the project config",
            ),
            // `[egress_sets]` precedes the first tool's `mounts`, so a file that
            // declares both is refused for the table, not for the tool field.
            (
                "[[tools]]\nname = \"t\"\ncommand = \"t\"\nmounts = []\n[egress_sets]\n",
                "egress_sets cannot be declared by the project config",
            ),
            // The remaining authority fields keep their precedence over a tool's
            // own `mounts`, which #735 made legal (inert) in the project tier.
            (
                "[network]\nallow_lan = true\n[[tools]]\nname = \"t\"\ncommand = \"t\"\nmounts = []\n",
                "network.allow_lan",
            ),
            (
                "mounts = []\n[[tools]]\nname = \"t\"\ncommand = \"t\"\nmounts = []\n",
                "mounts cannot be declared by the project config",
            ),
        ] {
            let f = Fixture::new();
            f.project(body);
            let error = f.load().unwrap_err().to_string();
            assert!(error.contains(expected), "{body}: {error}");
        }
    }

    #[test]
    fn builtin_egress_sets_are_refused() {
        for body in [
            "[egress_sets]\n",
            "[egress_sets]\na = []\n",
            "egress_sets = 7\n",
        ] {
            let error = tools_from_builtin_text(body).unwrap_err().to_string();
            assert_eq!(
                error,
                "config: \"default-tools.toml\": egress_sets cannot be declared by the built-in \
                 config; declare egress sets in the user config and select them with set:NAME",
                "{body}"
            );
        }
    }

    /// A12 and Q6: an empty `[egress_sets]` through a symlink is refused at load
    /// with the `[egress_sets]` subject, with nothing referencing it.
    #[test]
    fn egress_sets_presence_requires_a_verified_file() {
        for body in [
            "[egress_sets]\n",
            "[egress_sets]\ncorp = [\"10.0.0.5\"]\n",
            "egress_sets = 7\n",
        ] {
            let f = Fixture::new();
            f.symlinked_user(body);
            let error = f.load().unwrap_err().to_string();
            assert!(
                error.contains("[egress_sets] requires config.toml to be a regular file"),
                "{body}: {error}"
            );
            assert!(error.contains("review the [egress_sets] table"), "{error}");
            assert!(
                error.contains("(a symlinked config without [egress_sets] still works)"),
                "{error}"
            );
            assert!(!error.contains("[network]"), "{error}");
        }
        // The same file without the table keeps loading, so the refusal above is
        // about this field and not about symlinks in general.
        let f = Fixture::new();
        f.symlinked_user("[[tools]]\nname = \"custom\"\ncommand = \"custom\"\n");
        assert!(f.load().is_ok());
    }

    /// A21 and R20, restated for #735: `tool:NAME` no longer exists, so a set body
    /// reaches **no** tool at all — not this file's, not the project tier's, not the
    /// shipped catalog's — and the only cross-file shape left is `set:NAME`.
    #[test]
    fn egress_set_bodies_reach_no_tool_entries() {
        let f = Fixture::new();
        f.user(
            "[[tools]]\nname = \"codex\"\ncommand = \"codex\"\n\
             network_requests = [\"api.openai.com\"]\n\
             [egress_sets]\ncorp = [\"tcp://api.openai.com:443\", \"10.0.0.5\"]\n\
             [network]\nallow_egress = [\"set:corp\"]\n",
        );
        // The project declares a same-named tool reaching somewhere else: a
        // resolution that consulted the merged catalog would grant this too.
        f.project(
            "[[tools]]\nname = \"codex\"\ncommand = \"codex\"\n\
             network_requests = [\"project.example\"]\n",
        );
        let report = f.load().unwrap();
        let allowances = report.user_network().unwrap().allowances();
        assert_eq!(
            allowances
                .allowances()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["tcp://api.openai.com:443", "10.0.0.5/32"]
        );
        assert_eq!(
            allowances
                .references()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["set:corp"]
        );
        // `tool:NAME` is gone (#735), so a set body cannot reach any tool — and the
        // project's same-named definition contributes nothing to the user file's
        // authority either way. A `set:` naming a set only the project declares is
        // the surviving cross-file shape, and it is an unknown set.
        let f = Fixture::new();
        f.user("[egress_sets]\ncorp = [\"set:project-only\"]\n");
        f.project(
            "[[tools]]\nname = \"project-only\"\ncommand = \"c\"\n\
             network_requests = [\"project.example\"]\n",
        );
        let error = f.load().unwrap_err().to_string();
        assert!(error.contains("egress_sets[0][0]:"), "{error}");
        assert!(
            error.contains("must name a set declared in the user config's own [egress_sets]"),
            "{error}"
        );
        assert!(!error.contains("project.example"), "{error}");
    }

    /// A26(a) and R19: every load stage reports before every later one, so each
    /// pair of the five stages is exercised with a fixture where both defects are
    /// present and only the earlier one may surface.
    ///
    /// Each expectation is the **complete** error sentence, written out here
    /// rather than assembled from the production constants, so a rewording is a
    /// failure here. `{file}` is the fixture's own scratch path, the one byte
    /// sequence that cannot be a literal.
    ///
    /// The stages are 1 `[network]` parse, 2 `[egress_sets]` parse, 3 mounts,
    /// image and tool validation, 4 set compile, 5 `[network]` resolution. The
    /// pairs are (1,2) (1,3) (1,4) (1,5) (2,3) (2,4) (2,5) (3,4) (3,5) (4,5).
    ///
    /// (2,4) is listed for completeness rather than because a plausible edit
    /// reverses it: `parse` returns the typed value `compile` consumes, so no
    /// load path can report a compile error before a parse error without a
    /// per-definition streaming redesign — which is exactly what this row would
    /// catch. The reorderings that *are* available (mounts before the tables,
    /// sets after tool validation) are killed by the (1,3), (2,3) and (4,5) rows,
    /// measured as mutants.
    #[test]
    fn egress_set_errors_surface_in_load_order() {
        const MALFORMED: &str = "not an IP address, CIDR or hostname (hostnames: one or more \
             labels of ASCII letters, digits and '-', not ending in a numeric label; write \
             non-ASCII names as A-labels; no wildcards)";
        const UNKNOWN_SET: &str = "an egress reference must name a set declared in the user \
             config's own [egress_sets]; project and built-in configs cannot declare sets";
        const NOT_ARRAY: &str = "must be an array of strings";
        const BAD_TOOL_NAME: &str = "name must be a single command-name token, not a path";
        // #735 removed the `tool:` claim, so a set entry no longer has a
        // *compile* stage that can fail on a name (ADR-0075); the stages below are
        // the ones that remain, and their relative order is what this pins.
        for (body, expected) in [
            // (1,2): `[network]` parse before `[egress_sets]` parse.
            (
                "[network]\nallow_egress = [\"not an allowance\"]\n[egress_sets]\nv = 7\n",
                format!("config: {{file}}: network.allow_egress[0]: {MALFORMED}"),
            ),
            // (1,3): a genuinely top-level `mounts` value. It is a mount error on
            // its own, so this pair really does reach the mounts stage — which is
            // why it may not sit after `[network]`, where TOML would scope it in.
            (
                "mounts = 7\n[network]\nallow_egress = [\"not an allowance\"]\n",
                format!("config: {{file}}: network.allow_egress[0]: {MALFORMED}"),
            ),
            // (2,3): set parse before tool validation.
            (
                "[egress_sets]\nv = [\"a b\"]\n\
                 [[tools]]\nname = \"a/b\"\ncommand = \"c\"\n",
                format!("config: {{file}}: egress_sets[0][0]: {MALFORMED}"),
            ),
            // (2,4): within parse, declaration order decides once names are bound.
            (
                "[egress_sets]\na = 7\nw = [\"set:nope\"]\n",
                format!("config: {{file}}: egress_sets[0]: {NOT_ARRAY}"),
            ),
            // (2,5): set parse before `[network]` resolution.
            (
                "[egress_sets]\nv = 7\n[network]\nallow_egress = [\"set:nope\"]\n",
                format!("config: {{file}}: egress_sets[0]: {NOT_ARRAY}"),
            ),
            // (3,4): tool validation precedes `[network]` resolution, so a bad
            // declaration is reported before an undefined set.
            (
                "[network]\nallow_egress = [\"set:nope\"]\n\
                 [[tools]]\nname = \"a/b\"\ncommand = \"c\"\n",
                format!(
                    "config: user config {{file}} declaration [0] tool \"a/b\": {BAD_TOOL_NAME}"
                ),
            ),
        ] {
            let f = Fixture::new();
            f.user(body);
            let error = f.load().unwrap_err().to_string();
            let expected = expected.replace("{file}", &format!("{:?}", f.user));
            assert_eq!(error, expected, "{body:?}");
        }

        // A set reference that names nothing is a *resolution* error, and it is
        // reported after every parse stage.
        let f = Fixture::new();
        f.user("[network]\nallow_egress = [\"set:nope\"]\n");
        assert_eq!(
            f.load().unwrap_err().to_string(),
            format!(
                "config: {:?}: network.allow_egress[0]: {UNKNOWN_SET}",
                f.user
            )
        );

        // Inside stage 2 the order is not "definition by definition": every name
        // is checked before any value, so a bad key in the *later* definition is
        // reported while the *earlier* one still holds a schema error. R19 says
        // "names, schema, entry syntax and unknown sets", and this is what that
        // reading means (plan Q3: two passes, names first).
        let f = Fixture::new();
        f.user("[egress_sets]\na = 7\n\"z bad\" = []\n");
        let error = f.load().unwrap_err().to_string();
        assert_eq!(
            error,
            "config: {file}: egress_sets: definition 1 has an invalid name; an egress-set name \
             is one or more ASCII characters: [A-Za-z0-9_] first, then [A-Za-z0-9_.-]"
                .replace("{file}", &format!("{:?}", f.user)),
            "names are checked for every definition before any definition's value"
        );
    }

    /// TOML assigns keys to the most recent table header, so *where* a
    /// `allow_egress` key is written decides which construct it lands in — the
    /// trap USAGE's "TOML scoping trap" bullet documents. One row per shape.
    ///
    /// The silent row is the one worth pinning: `[network]`, then `[egress_sets]`,
    /// then a bare `allow_egress = [...]` is a valid set *named* `allow_egress`.
    /// Nothing is refused and nothing is granted, so a regression here would be
    /// invisible without this test — and a reader told the trap loads when it in
    /// fact refused would be sent to the wrong fix.
    #[test]
    fn egress_sets_toml_scoping_is_characterized() {
        // The scoped assignment: valid, unselected, granting nothing.
        let f = Fixture::new();
        f.user("[network]\n[egress_sets]\nallow_egress = [\"10.0.0.5\"]\n");
        let report = f
            .load()
            .expect("the scoping trap is a valid file, not an error");
        let network = report.user_network().expect("the file declares [network]");
        assert_eq!(network.allowances().allowances().count(), 0);
        assert_eq!(network.allowances().references().count(), 0);

        // `set:allow_egress` is what selects it, so the trap is silent, not silent
        // *and* unfixable.
        let f = Fixture::new();
        f.user(
            "[egress_sets]\nallow_egress = [\"10.0.0.5\"]\n\
             [network]\nallow_egress = [\"set:allow_egress\"]\n",
        );
        let report = f.load().unwrap();
        let network = report.user_network().unwrap();
        assert_eq!(
            network
                .allowances()
                .allowances()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["10.0.0.5/32"]
        );
        assert_eq!(
            network
                .allowances()
                .references()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["set:allow_egress"]
        );
    }

    /// A project or built-in `[mount_sets]` is refused by presence alone — empty
    /// table, wrong type and named list alike — and a project *selection* of a
    /// user set name is refused before any lookup, so a project can never reach the
    /// user namespace.
    #[test]
    fn project_mount_sets_are_refused_even_when_empty() {
        for body in [
            "[mount_sets]\n",
            "[mount_sets]\nagent = []\n",
            "mount_sets = 7\n",
        ] {
            let f = Fixture::new();
            f.project(body);
            let error = f.load().unwrap_err().to_string();
            assert!(
                error.contains(&format!(
                    "config: {:?}: mount_sets cannot be declared by the project config; declare \
                     mount sets in the user config and select them with --mount NAME",
                    f.project
                )),
                "{body}: {error}"
            );
        }
        // A project `mounts = [\"agent\"]` is a `mounts` refusal, which precedes any
        // resolution — even when the user config really does define `agent`.
        let f = Fixture::new();
        f.user("[mount_sets]\nagent = [\"/a:/g:ro\"]\n");
        f.project("mounts = [\"agent\"]\n");
        let error = f.load().unwrap_err().to_string();
        assert!(
            error.contains("mounts cannot be declared by the project config"),
            "{error}"
        );
        // `[network]` still wins when a project declares both.
        let f = Fixture::new();
        f.project("[mount_sets]\n[network]\nallow_host = true\n");
        let error = f.load().unwrap_err().to_string();
        assert!(
            error.contains("network access cannot be granted by the project config"),
            "{error}"
        );
    }

    #[test]
    fn builtin_mount_sets_are_refused() {
        for body in [
            "[mount_sets]\n",
            "[mount_sets]\na = []\n",
            "mount_sets = 7\n",
        ] {
            let error = tools_from_builtin_text(body).unwrap_err().to_string();
            assert!(
                error.contains(
                    "config: \"default-tools.toml\": mount_sets cannot be declared by the \
                     built-in config"
                ),
                "{body}: {error}"
            );
        }
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
        let with_home = |home: Option<PathBuf>| {
            ConfigPaths::for_test_with_home(Some(user.clone()), project.clone(), home)
        };

        // `/h/` keeps its trailing slash (`//`), and the process `HOME` is not
        // involved: it is the real home, not `/h/`.
        let report = load(&with_home(Some(PathBuf::from("/h/")))).unwrap();
        let spellings: Vec<crate::mount::Spelling> = report
            .user_mounts()
            .unwrap()
            .defaults()
            .expect("the file declares defaults")
            .requests()
            .map(|request| request.mount.source_spelling.clone())
            .collect();
        assert_eq!(spellings, ["/h//ref", "/abs/ref"]);
        assert_ne!(std::env::var("HOME").ok(), Some("/h/".to_string()));

        // A guest `~/` is the same captured home (#530), expanded before the
        // claim so `~/g` and `/h/g` are one declaration.
        write_file(&user, "mounts = [\"/abs:~/g\"]\n");
        let report = load(&with_home(Some(PathBuf::from("/h/")))).unwrap();
        let guests: Vec<String> = report
            .user_mounts()
            .unwrap()
            .defaults()
            .expect("the file declares defaults")
            .requests()
            .map(|request| request.mount.guest.display().to_string())
            .collect();
        assert_eq!(guests, ["/h/g"]);

        // No captured home: `~/` is refused rather than derived from the user
        // path's parent (`<tmp>/cfg`), and an absolute entry still loads.
        write_file(&user, "mounts = [\"~/ref\", \"/abs/ref\"]\n");
        assert_eq!(
            load(&with_home(None)).unwrap_err().to_string(),
            format!(
                "config: {:?}: mounts[0] \"~/ref\": a ~/ host or guest path needs a UTF-8 $HOME",
                user
            )
        );
        // The guest field is refused by the same sentence, and only when it is a
        // field that needed expanding.
        write_file(&user, "mounts = [\"/abs:~/g\"]\n");
        assert_eq!(
            load(&with_home(None)).unwrap_err().to_string(),
            format!(
                "config: {:?}: mounts[0] \"/abs:~/g\": a ~/ host or guest path needs a UTF-8 $HOME",
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
                .contains("mounts[0] \"~/ref\": a ~/ host or guest path needs a UTF-8 $HOME")
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
                "config: {:?}: mounts[0] \"/a:/g:exclude=hidden\": :exclude is only supported on \
                 :fork mounts",
                f.user
            )
        );
    }

    /// Every mount load error names the file and the site, and quotes the entry
    /// that failed, escaped. The two shape errors — a non-string entry and a
    /// non-array list — have no entry text of their own and name the site only;
    /// neither echoes the key or the value it refused.
    #[test]
    fn user_mount_errors_name_the_file_site_and_quote_the_entry() {
        const SENTINEL: &str = "s3cr3t-SENTINEL-305";
        for (body, entry) in [
            (format!("mounts = [\"{SENTINEL}\"]\n"), SENTINEL.to_string()),
            (
                format!("mounts = [\"{SENTINEL}\", \"/a\"]\n"),
                SENTINEL.to_string(),
            ),
            (
                format!("mounts = [\"/a:{SENTINEL}\"]\n"),
                format!("/a:{SENTINEL}"),
            ),
            (
                format!("mounts = [\"/a:/g:{SENTINEL}\"]\n"),
                format!("/a:/g:{SENTINEL}"),
            ),
            (
                format!("mounts = [\"/a:/g:exclude={SENTINEL}/../x\"]\n"),
                format!("/a:/g:exclude={SENTINEL}/../x"),
            ),
            (
                format!("mounts = [\"/a:/g\", \"{SENTINEL}:/g\"]\n"),
                format!("{SENTINEL}:/g"),
            ),
        ] {
            let f = Fixture::new();
            f.user(&body);
            let error = f.load().unwrap_err().to_string();
            assert!(error.contains("mounts"), "{error}");
            assert!(error.contains(&format!("{:?}", f.user)), "{error}");
            assert!(
                error.contains(&crate::config::quoted_str(&entry)),
                "{body}: the entry is quoted back escaped: {error}"
            );
        }
        // No entry text exists for these two, so neither the value nor the key
        // may appear.
        for body in [
            format!("mounts = [1, \"{SENTINEL}\"]\n"),
            format!("mounts = {{ {SENTINEL} = 1 }}\n"),
        ] {
            let f = Fixture::new();
            f.user(&body);
            let error = f.load().unwrap_err().to_string();
            assert!(!error.contains(SENTINEL), "{body}: value echoed: {error}");
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

    /// **#396 reversal.** A full user `[[tools]]` may declare `mounts`; that is the
    /// feature, so the pre-#396 negative row is replaced by positive coverage plus
    /// the project/built-in refusals that now carry the negative half.
    ///
    /// The row also pins the *ordering* the reversal must not disturb: a malformed
    /// or mount-less tool still produces the fixed schema sentence, so a mount field
    /// can neither be an accepted partial patch nor a way to skip the shape check.
    #[test]
    fn user_tool_mounts_are_accepted_and_still_require_a_full_definition() {
        let f = Fixture::new();
        let report = f
            .user("[[tools]]\nname = \"t\"\ncommand = \"t\"\nmounts = []\n")
            .load()
            .unwrap();
        // Present-empty is present: the file is authority-bearing and parsed, but
        // the tool selects nothing.
        let mounts = report.user_mounts().expect("a tool list is a mount field");
        assert!(!mounts.has_defaults());
        assert!(first_launch(&report).mounts().is_empty());

        let f = Fixture::new();
        let report = f
            .user("[[tools]]\nname = \"t\"\ncommand = \"t\"\nmounts = [\"/a:/g:ro\"]\n")
            .load()
            .unwrap();
        assert_eq!(first_launch(&report).mounts().len(), 1);

        // One mount-only setting never patches a shipped definition: without a
        // `command` the whole entry is still the fixed schema error, and the
        // sentinel proves the value is never echoed.
        const SENTINEL: &str = "s3cr3t-SENTINEL-396";
        let refused = [
            format!("[[tools]]\nname = \"t\"\nmounts = [\"{SENTINEL}\"]\n"),
            format!("[[tools]]\nname = \"t\"\ncommand = \"t\"\nmounts = \"{SENTINEL}\"\n"),
            format!("[[tools]]\nname = \"t\"\ncommand = \"t\"\nmounts = [{{ {SENTINEL} = 1 }}]\n"),
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\nmounts = 7\n".to_string(),
        ];
        for body in refused {
            let f = Fixture::new();
            f.user(&body);
            let error = f.load().unwrap_err().to_string();
            assert!(!error.contains(SENTINEL), "{body}: value echoed: {error}");
        }
        // A present but wrongly typed tool list reaches the parser, not serde, so
        // the sentence names the field rather than the fixed schema paragraph.
        for (body, expected) in [
            (
                "[[tools]]\nname = \"t\"\ncommand = \"t\"\nmounts = 7\n",
                "tools[0].mounts: must be an array of strings",
            ),
            (
                "[[tools]]\nname = \"t\"\ncommand = \"t\"\nmounts = [7]\n",
                "tools[0].mounts[0]: must be a string",
            ),
        ] {
            let f = Fixture::new();
            f.user(body);
            let error = f.load().unwrap_err().to_string();
            assert!(error.contains(expected), "{error}");
        }
    }

    /// A tool's own mount field is **authority**, and #735 changed *which* tier
    /// may declare it: the project config may — the declaration is inert until
    /// the project's own `allow_tools` authorizes the tool — while the compiled-in
    /// defaults still may not, because a shipped definition is not something a
    /// launch can authorize.
    ///
    /// Where the field *is* refused, the subject is the numeric file/field
    /// pointer, so the refusal cannot echo a tool name before tool-name validation
    /// runs.
    #[test]
    fn project_tool_mounts_are_inert_until_authorized_and_builtin_ones_are_refused() {
        // A project tool's `mounts` is *inert data* until the project config
        // authorizes the tool: every shape below loads, and none of it reaches a
        // launch while `t` is not a verb.
        // `# no allow_tools` keeps the fixture-authorization device away: these
        // declarations must really be unauthorized, or the row measures nothing.
        for body in [
            "# no allow_tools\n[[tools]]\nname = \"t\"\ncommand = \"t\"\nmounts = []\n",
            "# no allow_tools\n[[tools]]\nname = \"t\"\ncommand = \"t\"\nmounts = [\"/a:/g:ro\"]\n",
            "# no allow_tools\n[[tools]]\nname = \"t\"\ncommand = \"t\"\n\
             mounts = [\"/a:/g:ro\", \"/b:/h:rw\"]\n",
            "# no allow_tools\n[[tools]]\nname = \"a\"\ncommand = \"a\"\n\
             [[tools]]\nname = \"b\"\ncommand = \"b\"\nmounts = []\n",
        ] {
            let f = Fixture::new();
            f.project(body);
            let report = f.load().unwrap_or_else(|error| panic!("{body}: {error}"));
            assert!(
                report
                    .resolved()
                    .launch_tools()
                    .all(|tool| tool.name() != "t"),
                "{body}: an unauthorized project tool is not a verb"
            );
        }

        // A wrong type is still a schema error, and still a *tool* error: the
        // parser now runs for the project tier too.
        let f = Fixture::new();
        f.project("[[tools]]\nname = \"t\"\ncommand = \"t\"\nmounts = 7\n");
        let error = f.load().unwrap_err().to_string();
        assert!(
            error.contains("tools[0].mounts: must be an array"),
            "{error}"
        );

        // Authorizing the tool makes its declaration real: the same bytes that
        // were inert above now produce a mount on the winning definition.
        let f = Fixture::new();
        f.project(&format!(
            "allow_tools = [\"t\"]\n[[tools]]\nname = \"t\"\ncommand = \"t\"\n\
             mounts = [\"{}/a:/g:ro\"]\n",
            f.project.parent().unwrap().join("host").display()
        ));
        let report = f.load().expect("an authorized project tool's mounts load");
        assert_eq!(
            first_launch(&report)
                .mounts()
                .requests()
                .map(|request| request.mount.guest.clone())
                .collect::<Vec<_>>(),
            [std::path::PathBuf::from("/g")],
            "the authorized declaration is the launch's mount"
        );

        // A hidden project definition — same name as a user tool, and the project
        // does not authorize it — stays inert rather than refused.
        let f = Fixture::new();
        f.user(&one_tool("t"))
            .project("[[tools]]\nname = \"t\"\ncommand = \"t\"\npersist = [\"p\"]\nmounts = []\n");
        assert!(f.load().is_ok());

        // Old authority fields keep their precedence and their bytes.
        let f = Fixture::new();
        f.project(
            "[network]\nallow_lan = true\n[[tools]]\nname = \"t\"\ncommand = \"t\"\nmounts = []\n",
        );
        let error = f.load().unwrap_err().to_string();
        assert!(error.contains("network.allow_lan"), "{error}");
        assert!(!error.contains("tools[0].mounts"), "{error}");
        let f = Fixture::new();
        f.project("mounts = []\n[[tools]]\nname = \"t\"\ncommand = \"t\"\nmounts = []\n");
        let error = f.load().unwrap_err().to_string();
        assert_eq!(
            error,
            format!(
                "config: {:?}: mounts cannot be declared by the project config; use --mount \
                 launch options, or mounts in the user config",
                f.project
            )
        );
        let f = Fixture::new();
        f.project("[mount_sets]\na = []\n[[tools]]\nname = \"t\"\ncommand = \"t\"\nmounts = []\n");
        assert!(
            f.load()
                .unwrap_err()
                .to_string()
                .contains("mount_sets cannot be declared by the project config")
        );

        // The built-in tier is refused by the same routine, naming its own file.
        let error =
            tools_from_builtin_text("[[tools]]\nname = \"t\"\ncommand = \"t\"\nmounts = []\n")
                .unwrap_err()
                .to_string();
        assert_eq!(
            error,
            "config: \"default-tools.toml\": tools[0].mounts: mounts cannot be declared by the \
             built-in config; use --mount launch options, or mounts in the user config"
        );
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
            /// Loads, the file declares no top-level list, and its full `[[tools]]`
            /// definition owns the `mounts` field.
            ToolMounts,
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
            // #396 reversal: the same bytes are now a full user tool's own
            // mount list, which is a supported construct rather than a scoping
            // mistake. The row keeps distinguishing it from the top-level list.
            (
                "after [[tools]]",
                "[[tools]]\nname = \"t\"\ncommand = \"t\"\nmounts = []\n",
                Expected::ToolMounts,
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
                (Ok(report), Expected::ToolMounts) => {
                    let mounts = report
                        .user_mounts()
                        .unwrap_or_else(|| panic!("{label}: a tool list is a mount field"));
                    assert!(!mounts.has_defaults(), "{label}");
                    let tool = first_launch(&report);
                    assert!(tool.mounts().is_empty(), "{label}");
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

    // -- tool mounts as a closure facet (#396) ------------------------------

    /// One launch entry's mount facet as `(declared spelling, guest, read-only,
    /// fork)`, so a row asserts the access rather than only a count.
    fn entry_mounts(
        catalog: &LaunchCatalog,
        name: &str,
    ) -> Vec<(crate::mount::Spelling, String, bool, bool)> {
        use crate::mount::MountPolicy;
        entry_of(catalog, name)
            .mounts()
            .requests()
            .map(|request| {
                (
                    request.mount.source_spelling.clone(),
                    request.mount.guest.display().to_string(),
                    matches!(request.mount.policy, MountPolicy::BindReadOnly { .. }),
                    matches!(request.mount.policy, MountPolicy::Fork { .. }),
                )
            })
            .collect()
    }

    /// A guest-path list only, for rows that do not care about the policy.
    fn guest_mounts(catalog: &LaunchCatalog, name: &str) -> Vec<String> {
        entry_mounts(catalog, name)
            .into_iter()
            .map(|(_, guest, _, _)| guest)
            .collect()
    }

    /// A full user tool definition with one field appended.
    fn tool(body: &str) -> String {
        format!("[[tools]]\n{body}")
    }

    /// #396 AC-authority: a **tool's** `mounts` field is authority-bearing from its
    /// presence alone, decided on the same verified read as the top-level list.
    ///
    /// The positive controls matter as much as the refusals: the same symlinked
    /// file without the field still loads (ADR-0040's compatibility rule), and a
    /// `[tools.env] mounts` entry is an ordinary environment variable that triggers
    /// no mount policy at all.
    #[test]
    fn tool_mounts_presence_requires_verified_read_even_empty() {
        // An empty list on a tool no launch verb necessarily reaches.
        for body in [
            tool("name = \"t\"\ncommand = \"t\"\nmounts = []\n"),
            tool("name = \"unused\"\ncommand = \"unused\"\nmounts = [\"/a:/g:ro\"]\n")
                + &tool("name = \"t\"\ncommand = \"t\"\n"),
            // A wrong type is authority-bearing before the schema is decided.
            tool("name = \"t\"\ncommand = \"t\"\nmounts = 7\n"),
            tool("name = \"t\"\ncommand = \"t\"\nmounts = [1]\n"),
        ] {
            let f = Fixture::new();
            f.symlinked_user(&body);
            // No top-level mount field, so the refusal names the tool's own site
            // first: the reader has to find the list they must review.
            assert_eq!(
                f.load().unwrap_err().to_string(),
                format!(
                    "config: {:?}: tools[0].mounts: mounts requires config.toml to be a regular \
                     file, but it is reached through a symbolic link; its target may be writable \
                     by a guest or project, so review the mounts list before trusting the file (a \
                     symlinked config without mounts still works)",
                    f.user
                ),
                "{body}"
            );
        }

        // Compatibility anchor: the same symlink without a mount field loads, and
        // reports no mount model at all.
        let f = Fixture::new();
        f.symlinked_user(&tool("name = \"t\"\ncommand = \"t\"\n"));
        let report = f.load().unwrap();
        assert!(report.user_mounts().is_none());
        // `t` declares no `allow_tools` entry of its own, so it is inert (ADR-0075)
        // and nothing about it reaches a launch.
        assert!(
            report
                .resolved()
                .launch_tools()
                .all(|tool| tool.name() != "t"),
            "an unauthorized tool is not a verb"
        );

        // `[tools.env] mounts` is an ordinary env value: no authority trigger.
        let f = Fixture::new();
        f.symlinked_user(&tool(
            "name = \"t\"\ncommand = \"t\"\n[tools.env]\nmounts = \"~/private:ro\"\n",
        ));
        let report = f.load().unwrap();
        assert!(report.user_mounts().is_none());
        // And the pair really is an env value, not a mount: the same bytes in a
        // regular file, authorized, publish it to the guest.
        let f = Fixture::new();
        f.user(&format!(
            "allow_tools = [\"t\"]\n{}",
            tool("name = \"t\"\ncommand = \"t\"\n[tools.env]\nmounts = \"~/private:ro\"\n")
        ));
        let report = f.load().unwrap();
        assert!(report.user_mounts().is_none());
        assert_eq!(
            first_launch(&report)
                .guest_env()
                .get("mounts")
                .map(String::as_str),
            Some("~/private:ro")
        );

        // A combined subject still names the field composition after the pointer.
        let f = Fixture::new();
        f.symlinked_user(&format!(
            "[network]\nallow_lan = true\n{}",
            tool("name = \"t\"\ncommand = \"t\"\nmounts = []\n")
        ));
        let error = f.load().unwrap_err().to_string();
        assert!(
            error.contains("tools[0].mounts: [network] and mounts requires config.toml"),
            "{error}"
        );

        // A file whose only authority field is the old top-level list keeps its
        // pre-#396 bytes: no pointer is prefixed.
        let f = Fixture::new();
        f.symlinked_user("mounts = []\n");
        assert_eq!(
            f.load().unwrap_err().to_string(),
            format!(
                "config: {:?}: mounts requires config.toml to be a regular file, but it is \
                 reached through a symbolic link; its target may be writable by a guest or \
                 project, so review the mounts list before trusting the file (a symlinked \
                 config without mounts still works)",
                f.user
            )
        );

        // The other verified-read facts apply identically to a tool-only file.
        if crate::host_paths::current_euid() != 0 {
            use std::os::unix::fs::PermissionsExt;
            let f = Fixture::new();
            // `# no allow_tools` keeps the fixture device away so the refusal
            // names the tool's own field, which is this row's subject.
            f.user(&format!(
                "# no allow_tools\n{}",
                tool("name = \"t\"\ncommand = \"t\"\nmounts = []\n")
            ));
            fs::set_permissions(&f.user, fs::Permissions::from_mode(0o664)).unwrap();
            assert!(
                f.load()
                    .unwrap_err()
                    .to_string()
                    .contains("tools[0].mounts: mounts refuses a group- or other-writable"),
            );
            fs::set_permissions(&f.user, fs::Permissions::from_mode(0o600)).unwrap();
            let alias = f.user.with_file_name("alias");
            fs::hard_link(&f.user, &alias).unwrap();
            assert!(
                f.load()
                    .unwrap_err()
                    .to_string()
                    .contains("tools[0].mounts: mounts refuses a config.toml with 2 hard links"),
            );
            fs::remove_file(&alias).unwrap();
            fs::set_permissions(f.user.parent().unwrap(), fs::Permissions::from_mode(0o775))
                .unwrap();
            assert!(f.load().unwrap_err().to_string().contains(
                "tools[0].mounts: mounts refuses a config.toml whose directory is \
                               group- or other-writable"
            ),);
            fs::set_permissions(f.user.parent().unwrap(), fs::Permissions::from_mode(0o700))
                .unwrap();
        }
    }

    /// #396 AC-full-definition: a mount-only setting never patches a shipped tool,
    /// and a full custom definition still replaces the whole catalog.
    #[test]
    fn user_tool_mounts_are_not_partial_builtin_overrides() {
        // A full custom `pi` replaces the shipped catalog, so its absent
        // Claude/Codex edges are a dangling reference rather than a silent reuse of
        // the shipped ones. That is the ordinary full-definition rule, unchanged by
        // the mount field.
        let f = Fixture::new();
        f.user(&tool(
            "name = \"pi\"\ncommand = \"pi\"\ntools = [\"claude\", \"codex\"]\nmounts = [\"/a:/g:ro\"]\n",
        ));
        let error = f
            .load()
            .unwrap()
            .into_launch_catalog()
            .unwrap_err()
            .to_string();
        assert!(error.contains("tools[0]"), "{error}");
        assert!(
            error.contains("names no tool in this configuration file"),
            "{error}"
        );

        // With the referenced definitions present it resolves, and no shipped tool
        // leaks into the catalog: the mount field neither added nor preserved one.
        let f = Fixture::new();
        f.user(&format!(
            "{}{}{}",
            tool("name = \"pi\"\ncommand = \"pi\"\ntools = [\"claude\", \"codex\"]\nmounts = [\"/a:/g:ro\"]\n"),
            tool("name = \"claude\"\ncommand = \"claude\"\n"),
            tool("name = \"codex\"\ncommand = \"codex\"\nmounts = [\"/b:/g2:ro\"]\n")
        ));
        let catalog = f.load().unwrap().into_launch_catalog().unwrap();
        let names: Vec<&str> = catalog
            .as_slice()
            .iter()
            .map(|entry| entry.tool().name())
            .collect();
        assert_eq!(names, ["pi", "claude", "codex", "shell"]);
        assert_eq!(guest_mounts(&catalog, "pi"), ["/g", "/g2"]);
        // The isolated fallback shell sees no user tool.
        assert!(guest_mounts(&catalog, "shell").is_empty());
    }

    /// #396 AC-one-closure: mounts join the same visited mask that supplies
    /// providers, requested names and persist paths — while env and network
    /// requests keep their own-only rule.
    #[test]
    fn tool_mounts_are_a_facet_of_the_same_tier_local_closure() {
        let f = Fixture::new();
        f.user(&format!(
            "{}{}{}{}",
            tool("name = \"root\"\ncommand = \"root\"\ntools = [\"left\", \"right\"]\nmounts = [\"/r:/r:ro\"]\ncredentials = [\"openai\"]\nenv = { R = \"1\" }\nnetwork_requests = [\"r.example\"]\n"),
            tool("name = \"left\"\ncommand = \"left\"\ntools = [\"shared\"]\nmounts = [\"/l:/l:ro\"]\ncredentials = [\"anthropic\"]\npersist = [\"left\"]\nenv = { L = \"1\" }\nnetwork_requests = [\"l.example\"]\n"),
            tool("name = \"right\"\ncommand = \"right\"\ntools = [\"shared\", \"root\"]\nmounts = [\"/g:/g:rw\"]\npersist = [\"right\"]\n"),
            tool("name = \"shared\"\ncommand = \"shared\"\nmounts = [\"/s:/s:fork\"]\ncredentials = [\"copilot\"]\npersist = [\"shared\"]\n"),
        ));
        let catalog = f.load().unwrap().into_launch_catalog().unwrap();
        let entry = entry_of(&catalog, "root");
        // Arena (file) order, not traversal order: root, left, right, shared.
        assert_eq!(guest_mounts(&catalog, "root"), ["/r", "/l", "/g", "/s"]);
        // Providers and persist paths come from the same closure.
        let provisioned: Vec<&str> = entry
            .provisioned()
            .iter()
            .map(|provider| provider.config_name())
            .collect();
        assert_eq!(provisioned, ["anthropic", "openai", "copilot"]);
        let persist: Vec<String> = entry
            .persist()
            .iter()
            .map(|path| path.as_path().display().to_string())
            .collect();
        assert!(persist.contains(&"right".to_string()), "{persist:?}");
        assert!(persist.contains(&"shared".to_string()), "{persist:?}");
        // Environment and network requests are **not** folded: the launched
        // tool's own only.
        assert_eq!(entry.tool().guest_env().len(), 1);
        assert_eq!(
            entry.tool().guest_env().get("R").map(String::as_str),
            Some("1")
        );

        // A tool reference cycle is a harmless fixed point: each declaration once.
        let f = Fixture::new();
        f.user(&format!(
            "{}{}",
            tool("name = \"a\"\ncommand = \"a\"\ntools = [\"b\"]\nmounts = [\"/a:/a:ro\"]\n"),
            tool("name = \"b\"\ncommand = \"b\"\ntools = [\"a\"]\nmounts = [\"/b:/b:ro\"]\n")
        ));
        let catalog = f.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(guest_mounts(&catalog, "a"), ["/a", "/b"]);
        assert_eq!(guest_mounts(&catalog, "b"), ["/a", "/b"]);

        // A diamond declares one leaf once, whichever path reached it, and a
        // normalized duplicate merges rather than conflicting.
        let f = Fixture::new();
        f.user(&format!(
            "{}{}{}{}",
            tool("name = \"top\"\ncommand = \"top\"\ntools = [\"l\", \"r\"]\nmounts = [\"/t:/t:ro\"]\n"),
            tool("name = \"l\"\ncommand = \"l\"\ntools = [\"leaf\"]\n"),
            tool("name = \"r\"\ncommand = \"r\"\ntools = [\"leaf\"]\nmounts = [\"/t:/t//./:ro\"]\n"),
            tool("name = \"leaf\"\ncommand = \"leaf\"\nmounts = [\"/x:/x:ro\"]\n"),
        ));
        let catalog = f.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(guest_mounts(&catalog, "top"), ["/t", "/x"]);
        // The kept declaration is the first in *file* order, which is `top`'s own
        // list here — attribution follows file order, never the launch's edges.
        let origin = entry_of(&catalog, "top")
            .mounts()
            .requests()
            .next()
            .map(|request| request.origin.to_string())
            .unwrap();
        assert!(origin.starts_with("tools[0].mounts[0]"), "{origin}");
    }

    /// #396 AC-tier: a project definition cannot reach a user's mount list by
    /// naming a user tool, by a wildcard, or transitively.
    #[test]
    fn project_closures_cannot_reach_user_mounts() {
        // The user's `pi` carries a fork. The project declares its own `pi` (a
        // hidden loser of the launch verb), a `bridge` that names it, and a
        // wildcard shell.
        let f = Fixture::new();
        f.user(&tool(
            "name = \"pi\"\ncommand = \"pi\"\nmounts = [\"~/.pi:fork\"]\n",
        ));
        f.project(&format!(
            "{}{}{}",
            tool("name = \"pi\"\ncommand = \"pi\"\nmounts = []\n"),
            tool("name = \"bridge\"\ncommand = \"bridge\"\ntools = [\"pi\"]\n"),
            tool("name = \"shell\"\ncommand = \"bash\"\ninteractive_shell = true\n")
        ));
        // The project's mount field is itself a refusal, so this row is about the
        // *edges* once that field is gone.
        f.project(&format!(
            "{}{}",
            tool("name = \"pi\"\ncommand = \"pi\"\n"),
            tool("name = \"bridge\"\ncommand = \"bridge\"\ntools = [\"pi\"]\n")
        ));
        let home = Path::new("/synthetic-home");
        let catalog = f
            .load_with_home(home)
            .unwrap()
            .into_launch_catalog()
            .unwrap();
        // The project `bridge` provisions the *project* `pi`, which declares no
        // mount: nothing of the user's crosses the tier boundary.
        assert!(guest_mounts(&catalog, "bridge").is_empty());
        // Launching the user's `pi` verb still selects the user list.
        assert_eq!(guest_mounts(&catalog, "pi"), ["/synthetic-home/.pi"]);

        // A project reference to a name only the user declares is the exact
        // cross-tier error, never a mount source.
        let f = Fixture::new();
        f.user(&tool(
            "name = \"user-only\"\ncommand = \"u\"\nmounts = [\"/a:/a:ro\"]\n",
        ));
        f.project(&tool(
            "name = \"p\"\ncommand = \"p\"\ntools = [\"user-only\"]\n",
        ));
        let error = f
            .load()
            .unwrap()
            .into_launch_catalog()
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("cross-tier tool references are not allowed"),
            "{error}"
        );
    }

    /// #396 AC-shell: a declared shell's omitted `tools` is the existing wildcard
    /// (so it inherits same-tier mounts), `tools = []` suppresses only the
    /// inheritance, and the built-in fallback is a scope of its own.
    #[test]
    fn shell_mount_closure_distinguishes_omitted_empty_and_fallback() {
        let declared = |shell_tail: &str| {
            format!(
                "{}{}",
                tool("name = \"agent\"\ncommand = \"agent\"\nmounts = [\"/a:/a:ro\"]\n"),
                tool(&format!(
                    "name = \"shell\"\ncommand = \"bash\"\ninteractive_shell = true\n\
                     mounts = [\"/s:/s:ro\"]\n{shell_tail}"
                ))
            )
        };
        // Omitted: the wildcard over this file, so the agent's list is inherited.
        let f = Fixture::new();
        f.user(&declared(""));
        let catalog = f.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(guest_mounts(&catalog, "shell"), ["/a", "/s"]);
        // The shell wildcard deliberately includes itself and every same-file
        // definition — that is the pre-existing rule, unchanged.
        assert!(!catalog.has_shell_fallback());

        // `tools = []`: its own list only.
        let f = Fixture::new();
        f.user(&declared("tools = []\n"));
        let catalog = f.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(guest_mounts(&catalog, "shell"), ["/s"]);

        // The fallback: a custom catalog with no declared `shell` gets the shipped
        // one, whose scope is itself alone, so it inherits nothing from the user's
        // tools — but it is still an entry that can receive user-wide defaults.
        // A mounts-only file declares no tools, so the shipped catalog stands and
        // `shell` is a declaration rather than the fallback.
        let f = Fixture::new();
        f.user("mounts = [\"/d:/d:ro\"]\n");
        let catalog = f.load().unwrap().into_launch_catalog().unwrap();
        assert!(!catalog.has_shell_fallback());
        assert!(guest_mounts(&catalog, "shell").is_empty());
        // A custom catalog that declares an agent but no shell: the synthesized
        // fallback closes over itself alone, so it inherits nothing from the user's
        // definitions — the proof the isolation is real and not an accident of the
        // shipped catalog's contents.
        let f = Fixture::new();
        f.user(&tool(
            "name = \"agent\"\ncommand = \"agent\"\nmounts = [\"/a:/a:ro\"]\n",
        ));
        let catalog = f.load().unwrap().into_launch_catalog().unwrap();
        assert!(catalog.has_shell_fallback());
        assert!(guest_mounts(&catalog, "shell").is_empty());

        // A project shell's wildcard covers only project definitions, which cannot
        // carry mounts.
        let f = Fixture::new();
        f.user(&tool(
            "name = \"agent\"\ncommand = \"agent\"\nmounts = [\"/a:/a:ro\"]\n",
        ));
        f.project(&tool(
            "name = \"shell\"\ncommand = \"bash\"\ninteractive_shell = true\n",
        ));
        let catalog = f.load().unwrap().into_launch_catalog().unwrap();
        assert!(guest_mounts(&catalog, "shell").is_empty());
    }

    /// A closure conflict is a *catalog* error for the launch that selects both
    /// lists: value-free, deterministic, and naming the launching declaration as
    /// well as both leaf sites.
    #[test]
    fn tool_mount_closure_conflict_is_value_free_and_deterministic() {
        const SENTINEL: &str = "s3cr3t-SENTINEL-396";
        let f = Fixture::new();
        f.user(&format!(
            "{}{}",
            tool(&format!(
                "name = \"launch\"\ncommand = \"launch\"\ntools = [\"other\"]\nmounts = [\"/p:/g:ro\", \"/{SENTINEL}:/{SENTINEL}:ro\"]\n"
            )),
            tool("name = \"other\"\ncommand = \"other\"\nmounts = [\"/q:/g:rw\", \"/q2:/q2:ro\"]\n")
        ));
        let error = f.load().unwrap().into_launch_catalog().unwrap_err();
        assert!(!format!("{error:#}").contains(SENTINEL), "{error:#}");
        assert_eq!(
            format!("{error:#}"),
            format!(
                "config: user config {:?} declaration [0] tool \"launch\": tools[1].mounts[0]: \
                 claims the same guest path as tools[0].mounts[0] with a different declaration",
                f.user
            )
        );
        // The other tool launches alone, so the pair never shares a closure and the
        // file still has a usable catalog: only the conflicting launch is refused.
        let f = Fixture::new();
        f.user(&format!(
            "{}{}",
            tool("name = \"launch\"\ncommand = \"launch\"\ntools = [\"other\"]\nmounts = [\"/p:/g:ro\"]\n"),
            tool("name = \"other\"\ncommand = \"other\"\ntools = []\nmounts = [\"/q:/g:rw\"]\n")
        ));
        // Same file, but `other` now has `tools = []`, so it does not join
        // `launch`'s closure through the reverse edge... `launch` still names it.
        let error = f
            .load()
            .unwrap()
            .into_launch_catalog()
            .unwrap_err()
            .to_string();
        assert!(error.contains("tools[1].mounts[0]"), "{error}");

        // Two tools that never share a closure need not agree.
        let f = Fixture::new();
        f.user(&format!(
            "{}{}",
            tool("name = \"one\"\ncommand = \"one\"\nmounts = [\"/p:/g:ro\"]\n"),
            tool("name = \"two\"\ncommand = \"two\"\nmounts = [\"/q:/g:rw\"]\n")
        ));
        let catalog = f.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(guest_mounts(&catalog, "one"), ["/g"]);
        assert_eq!(guest_mounts(&catalog, "two"), ["/g"]);
        // A set leaf keeps its load-time site in the same sentence.
        let f = Fixture::new();
        f.user(&format!(
            "mounts = [\"/d:/g:ro\"]\n[mount_sets]\ns = [\"/s:/g:rw\"]\n{}",
            tool("name = \"t\"\ncommand = \"t\"\ntools = []\nmounts = [\"s\"]\n")
        ));
        let catalog = f.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(guest_mounts(&catalog, "t"), ["/g"]);
    }

    /// The one budget continues from verified parsing into catalog construction:
    /// a file may spend exactly the limit across both stages, and the next
    /// candidate is refused by the tool-stage sentence — even under an opt-out
    /// launch, because the catalog is built either way.
    #[test]
    fn tool_mount_work_continues_the_verified_parser_budget() {
        const LIMIT: usize = crate::config_mounts::MAX_MOUNT_SET_EXPANSION_WORK;
        let document = |count: usize| {
            let entries = (0..count)
                .map(|index| format!("\"/s:/g{index}:ro\""))
                .collect::<Vec<_>>()
                .join(", ");
            tool(&format!(
                "name = \"solo\"\ncommand = \"solo\"\ntools = []\nmounts = [{entries}]\n"
            ))
        };

        // Exactly the limit: a tool list of B/2 entries is admitted by the parser
        // and again by the catalog fold, with no reset in between.
        let f = Fixture::new();
        f.user(&document(LIMIT / 2));
        let (catalog, work) = f.load().unwrap().into_launch_catalog_with_work();
        let catalog = catalog.expect("exactly the limit is admitted");
        assert_eq!(work.used(), LIMIT);
        assert_eq!(guest_mounts(&catalog, "solo").len(), LIMIT / 2);

        // One more candidate in either stage is refused, and the report says how
        // far the shared counter got.
        let f = Fixture::new();
        f.user(&document(LIMIT / 2 + 1));
        let (catalog, work) = f.load().unwrap().into_launch_catalog_with_work();
        let error = format!("{:#}", catalog.unwrap_err());
        assert!(
            error.contains(&format!(
                "mounts: expansion work exceeds limit of {LIMIT} leaf visits across mount sets \
                 and tool mounts"
            )),
            "{error}"
        );
        assert!(error.contains("tool \"solo\""), "{error}");
        assert_eq!(
            work.used(),
            LIMIT,
            "the refusal happens after every admission"
        );

        // The refusal is not conditional on the launch's opt-out: building the
        // catalog is a load-time step, and the budget is spent before the policy is
        // read. (The policy is consumed at selection, downstream of this report.)
        let f = Fixture::new();
        f.user(&document(LIMIT / 2 + 1));
        let (catalog, _) = f.load().unwrap().into_launch_catalog_with_work();
        assert!(catalog.is_err());

        // A cloned model's continuation starts where the parse stopped, and a
        // second build from the same report cannot mint a fresh budget.
        let f = Fixture::new();
        f.user(&document(2));
        let report = f.load().unwrap();
        assert_eq!(report.mount_work_used(), 2);
    }

    /// #396's budget is charged **per launch winner**, not once per catalog: the
    /// inherited list of a referenced tool is re-admitted for every entry whose
    /// closure selects it, and the same counter continues from the parse.
    ///
    /// The oracle is the exact admission count through the real catalog build, not
    /// a hand-folded boundary sample: an implementation that folded each distinct
    /// list once ("once per catalog") would report 3 here, and one that minted a
    /// fresh counter per entry would report the last entry's 2. Both are wrong for
    /// the resource contract, which bounds the *whole* launch catalog's expansion
    /// with the one parser budget.
    #[test]
    fn tool_mount_fold_admissions_are_charged_per_launch_winner() {
        let f = Fixture::new();
        f.user(&format!(
            "mounts = [\"/d1:/d1:ro\", \"/d2:/d2:ro\"]\n{}{}{}",
            // `a` inherits `b`'s two leaves on top of its own one.
            tool("name = \"a\"\ncommand = \"a\"\ntools = [\"b\"]\nmounts = [\"/a1:/a1:ro\"]\n"),
            tool("name = \"b\"\ncommand = \"b\"\ntools = []\nmounts = [\"/b1:/b1:ro\", \"/b2:/b2:ro\"]\n"),
            // `c` selects only `b`'s list; it declares none of its own.
            tool("name = \"c\"\ncommand = \"c\"\ntools = [\"b\"]\n"),
        ));
        let (catalog, work) = f.load().unwrap().into_launch_catalog_with_work();
        let catalog = catalog.expect("the fixture is inside the budget");
        // Parse: 1 (a) + 2 (b) + 0 (c) = 3; the defaults list is exempt by
        // design, so it spends nothing. Catalog: a's closure {a,b} = 3, b's = 2,
        // c's closure {c,b} = 2, and the appended fallback shell carries no list
        // = 0. 3 + 7 = 10.
        assert_eq!(
            work.used(),
            10,
            "every launch winner's closure re-admits its lists on the one counter"
        );
        // The facets are still right, so the count is not reached by refusing: the
        // inherited list is present on all three winners and absent from nothing.
        assert_eq!(guest_mounts(&catalog, "a"), ["/a1", "/b1", "/b2"]);
        assert_eq!(guest_mounts(&catalog, "b"), ["/b1", "/b2"]);
        assert_eq!(guest_mounts(&catalog, "c"), ["/b1", "/b2"]);
        assert!(guest_mounts(&catalog, "shell").is_empty());
    }

    /// #396's retention contract: many catalog entries inheriting one long leaf
    /// and one long set name share the *payloads*, so the cost of an inherited
    /// declaration is one handle per entry rather than one copy per entry.
    ///
    /// The oracle is the allocation itself — `Arc::ptr_eq` on the set name and on
    /// the leaf — plus the count of distinct payloads against the count of handles
    /// held across the namespace clone, the catalog entry and the launch grant.
    /// This is a storage-shape assertion on purpose: retained sharing *is* the
    /// memory contract, and behaviour tests cannot see it.
    #[test]
    fn tool_closures_share_leaf_payloads_across_catalog_entries() {
        const TOOLS: usize = 40;
        let set_name = "n".repeat(18_000);
        type Leaf = std::sync::Arc<crate::config_mounts::ConfigMountLeaf>;
        fn leaf_of(list: &ResolvedMountList) -> Leaf {
            // The public accessor borrows; a handle is what sharing is measured on,
            // so go through the origin-bearing request and re-find it by identity
            // through the iterator's own `Arc` via `Arc::clone` of the list.
            list.shared_leaves_for_test()
                .first()
                .expect("the list has a leaf")
                .clone()
        }
        let mut body = format!(
            "[mount_sets]\n{set_name} = [\"/srv/a-very-long-shared-source:/shared:ro\", \
             \"/srv/other:/other:ro\"]\n"
        );
        for index in 0..TOOLS {
            body.push_str(&format!(
                "[[tools]]\nname = \"t{index:02}\"\ncommand = \"t\"\nmounts = [\"{set_name}\"]\n"
            ));
        }
        assert!(
            body.len() < 1 << 20,
            "the fixture stays inside the file bound"
        );
        let f = Fixture::new();
        f.user(&body);
        let report = f.load().unwrap();
        // The CLI clones the namespace for the launch; the clone must share.
        let cloned = report.user_mounts().unwrap().clone();
        let catalog = report.into_launch_catalog().unwrap();
        let first = leaf_of(entry_of(&catalog, "t00").mounts());
        for index in 0..TOOLS {
            let handle = leaf_of(entry_of(&catalog, &format!("t{index:02}")).mounts());
            assert!(
                std::sync::Arc::ptr_eq(&first, &handle),
                "t{index:02} must share t00's retained leaf handle"
            );
        }
        // The set's long name is one allocation, shared by every leaf and both
        // models.
        let name_of = |list: &ResolvedMountList| match &leaf_of(list).request.origin {
            crate::mount::MountOrigin::UserSet { set, .. } => std::sync::Arc::clone(set),
            other => panic!("a set leaf must carry a set origin: {other:?}"),
        };
        let shared_name = name_of(entry_of(&catalog, "t00").mounts());
        assert_eq!(shared_name.len(), set_name.len());
        assert!(std::sync::Arc::ptr_eq(
            &shared_name,
            &name_of(entry_of(&catalog, "t39").mounts())
        ));
        let from_clone = cloned
            .requests_for_set(&crate::config_mounts::MountSetName::parse(&set_name).unwrap())
            .expect("the cloned namespace still resolves the set");
        assert!(std::sync::Arc::ptr_eq(&shared_name, &name_of(&from_clone)));
        // 40 entries hold 40 handles on 2 distinct leaves: the count is what
        // proves the payloads are not copied per entry.
        let handles: usize = (0..TOOLS)
            .map(|index| entry_of(&catalog, &format!("t{index:02}")).mounts().len())
            .sum();
        assert_eq!(handles, TOOLS * 2);
        assert_eq!(entry_of(&catalog, "t00").mounts().len(), 2);
    }

    /// #396 AC-authority, positive twin: a full user tool's list is parsed by the
    /// same selector as the defaults list, so a set name, a `~/` spelling and a
    /// direct path all behave identically in either position.
    #[test]
    fn tool_mounts_toml_sites_are_distinct_from_env_and_defaults() {
        let f = Fixture::new();
        f.user(&format!(
            "[mount_sets]\nagent = [\"~/agents:/agents:rw\"]\n{}",
            tool("name = \"t\"\ncommand = \"t\"\nmounts = [\"agent\", \"~/own:/own:ro\"]\n")
        ));
        let catalog = f
            .load_with_home(Path::new("/synthetic-home"))
            .unwrap()
            .into_launch_catalog()
            .unwrap();
        assert_eq!(guest_mounts(&catalog, "t"), ["/agents", "/own"]);
        // The entries keep the origin of the site that declared them.
        let origins: Vec<String> = entry_of(&catalog, "t")
            .mounts()
            .requests()
            .map(|request| request.origin.to_string())
            .collect();
        assert!(
            origins[0].starts_with("mount_sets[\"agent\"][0]"),
            "{origins:?}"
        );
        assert!(origins[1].starts_with("tools[0].mounts[1]"), "{origins:?}");

        // Numeric sites, and the entry quoted back when the entry's own grammar
        // is what refused it.
        const SENTINEL: &str = "s3cr3t-SENTINEL-396";
        for (body, expected) in [
            (
                tool(&format!(
                    "name = \"t\"\ncommand = \"t\"\nmounts = [\"./{SENTINEL}:/g\"]\n"
                )),
                format!("tools[0].mounts[0] \"./{SENTINEL}:/g\": host path must be absolute"),
            ),
            (
                tool(&format!(
                    "name = \"t\"\ncommand = \"t\"\nmounts = [\"/a:/g:exclude={SENTINEL}\"]\n"
                )),
                format!(
                    "tools[0].mounts[0] \"/a:/g:exclude={SENTINEL}\": :exclude is only supported"
                ),
            ),
            (
                tool("name = \"t\"\ncommand = \"t\"\nmounts = [\"nope\"]\n"),
                "tools[0].mounts[0] \"nope\": unknown mount set name".to_string(),
            ),
            (
                tool("name = \"t\"\ncommand = \"t\"\nmounts = [\"agent:ro\"]\n"),
                "tools[0].mounts[0] \"agent:ro\": a mount-set reference is a bare name".to_string(),
            ),
        ] {
            let f = Fixture::new();
            f.user(&body);
            let error = f.load().unwrap_err().to_string();
            assert!(
                error.contains(&expected),
                "{body}: {expected} not in {error}"
            );
        }
        // A claim conflict names both sites and no entry text.
        let f = Fixture::new();
        f.user("mounts = [\"/a:/g:ro\", \"/a:/g:rw\"]\n");
        assert!(
            f.load()
                .unwrap_err()
                .to_string()
                .contains("mounts[1]: claims"),
        );
    }

    /// Whole-definition merging never fills an omission in **either** direction: an
    /// authorized project definition replaces the user's whole definition, so the
    /// user's mount list is not grafted onto it, and the differing fields are
    /// reported with `mounts` last.
    #[test]
    fn whole_definition_merge_never_fills_user_omissions() {
        // The user tool declares a mount list; the project's same-name definition
        // declares none but authorizes the verb, so it wins whole — and the user's
        // mount list is not filled in.
        let f = Fixture::new();
        f.user(&tool(
            "name = \"t\"\ncommand = \"cmd\"\nmounts = [\"/a:/a:ro\"]\nnetwork_requests = [\"a.example\"]\n",
        ));
        f.project(&format!(
            "allow_tools = [\"t\"]\n{}",
            tool("name = \"t\"\ncommand = \"cmd\"\nnetwork_requests = [\"b.example\"]\n")
        ));
        let report = f.load().unwrap();
        assert_eq!(report.conflicts().len(), 1);
        assert_eq!(
            report.conflicts()[0].fields(),
            &[ToolField::NetworkRequests, ToolField::Mounts]
        );
        let catalog = report.into_launch_catalog().unwrap();
        assert_eq!(
            guest_mounts(&catalog, "t"),
            Vec::<String>::new(),
            "the winner declares no mounts, and the loser's are never grafted on"
        );

        // Omitting the user's mount list is *not* a difference: presence is an
        // authority fact, not access. The project entry is explicit, so the
        // identical-definition override is what `same_definition` compares (#735
        // review S10).
        let f = Fixture::new();
        f.user(&tool("name = \"t\"\ncommand = \"cmd\"\n"));
        f.project(&format!(
            "allow_tools = [\"t\"]\n{}",
            tool("name = \"t\"\ncommand = \"cmd\"\n")
        ));
        assert!(f.load().unwrap().conflicts().is_empty());

        // A project cannot fill an omitted user `tools`/`env`/`persist` either.
        let f = Fixture::new();
        f.user(&tool("name = \"t\"\ncommand = \"cmd\"\n"));
        // `tools = []` would be the same value as the user's omitted field (both
        // are "no other tools"), so the wildcard is what makes the field differ.
        f.project(&format!(
            "allow_tools = [\"t\"]\n{}",
            tool("name = \"t\"\ncommand = \"cmd\"\ntools = [\"*\"]\npersist = [\"p\"]\n[tools.env]\nA = \"1\"\n")
        ));
        let report = f.load().unwrap();
        assert_eq!(
            report.conflicts()[0].fields(),
            &[ToolField::Tools, ToolField::Persist, ToolField::Env]
        );
        // The project authorizes `t`, so its definition wins whole (D3) — and the
        // *user's* omissions are not filled, because the user's definition is not
        // the winner at all. The named property is unchanged: a merge never
        // splices one definition's fields onto another's.
        let winner = first_launch(&report);
        assert_eq!(winner.persist_count(), 1);
        assert_eq!(winner.env_count(), 1);
        assert_eq!(
            winner.declared_tools(),
            &DeclaredTools::All,
            "the winner's own fields, never a splice of the loser's"
        );
    }

    // -----------------------------------------------------------------------
    // #735 V21–V25: the authorisation oracles the mutation rows point at.
    // -----------------------------------------------------------------------

    /// V21(a), R3 verb order: each authorized entry keeps **its own** definition
    /// and facets. A catalog built by pairing authorisation *position* with
    /// definition *arena position* still produces the right names here, so every
    /// field is asymmetric on purpose.
    #[test]
    fn authorized_entries_keep_their_own_definition_and_facets() {
        use CredentialProvider::*;
        let f = Fixture::new();
        f.user(
            "allow_tools = [\"second\", \"first\"]\n\
             [[tools]]\nname = \"first\"\ncommand = \"first-cmd\"\ncredentials = [\"openai\"]\n\
             persist = [\".first\"]\nmounts = [\"/f:/f:ro\"]\ntools = []\n\
             [[tools]]\nname = \"second\"\ncommand = \"second-cmd\"\ncredentials = [\"anthropic\"]\n\
             persist = [\".second\"]\nmounts = [\"/s:/s:ro\"]\ntools = []\n",
        );
        let catalog = f
            .load()
            .unwrap()
            .into_launch_catalog()
            .expect("both tools are authorized");
        assert_eq!(verbs_of(&catalog), ["second", "first", "shell"]);
        for (name, command, provider, path, guest) in [
            ("second", "second-cmd", Anthropic, ".second", "/s"),
            ("first", "first-cmd", OpenAi, ".first", "/f"),
        ] {
            let entry = entry_of(&catalog, name);
            assert_eq!(entry.tool().command(), command, "{name}");
            assert_eq!(entry.provisioned().iter().collect::<Vec<_>>(), [provider]);
            assert_eq!(
                entry
                    .persist()
                    .iter()
                    .map(|path| path.as_path().display().to_string())
                    .collect::<Vec<_>>(),
                [path],
                "{name}"
            );
            assert_eq!(guest_mounts(&catalog, name), [guest], "{name}");
        }
    }

    /// V21(b), R3: a project authorization overrides the `:trust` file's verb
    /// **in place**, so the inherited order survives, the source definition is the
    /// winner, and the `:trust` file's own `pi` still resolves its own `claude`
    /// through the closure.
    #[test]
    fn an_authorized_override_keeps_the_inherited_order_and_the_trusted_closure() {
        use CredentialProvider::*;
        let f = SourcesFixture::new();
        f.write_user(
            "allow_tools = [\"claude\", \"pi\"]\n\
             [[tools]]\nname = \"pi\"\ncommand = \"pi\"\ntools = [\"claude\"]\npersist = [\".pi-state\"]\n\
             [[tools]]\nname = \"claude\"\ncommand = \"claude\"\ncredentials = [\"anthropic\"]\n\
             persist = [\".claude-home\"]\nmounts = [\"/hc:/hc:ro\"]\ntools = []\n",
        );
        f.write_repo(
            "r.toml",
            "[[tools]]\nname = \"claude\"\ncommand = \"repo-claude\"\ncredentials = [\"openai\"]\n\
             persist = [\".repo-claude\"]\nmounts = [\"/rc:/rc:ro\"]\ntools = []\n",
        );
        f.write_project(&format!(
            "{}\nallow_tools = [\"repo:claude\"]\n",
            sources_block(&[HOME_SOURCE, "repo ./r.toml"])
        ));
        let report = f.load().expect("the override loads");
        let catalog = report.into_launch_catalog().expect("catalog");
        assert_eq!(verbs_of(&catalog), ["claude", "pi", "shell"]);
        let claude = entry_of(&catalog, "claude");
        assert_eq!(claude.tool().command(), "repo-claude");
        assert_eq!(claude.provisioned().iter().collect::<Vec<_>>(), [OpenAi]);
        assert_eq!(guest_mounts(&catalog, "claude"), ["/rc"]);
        // The `:trust` file's `pi` is untouched and still inherits the *home*
        // `claude`, not the overridden verb: the closure resolves per file.
        let pi = entry_of(&catalog, "pi");
        assert_eq!(pi.provisioned().iter().collect::<Vec<_>>(), [Anthropic]);
        assert_eq!(guest_mounts(&catalog, "pi"), ["/hc"]);
    }

    /// V6, R3: the project's override applies **once per verb**. A second project
    /// entry naming a verb the project has already replaced collides, because the
    /// project's list is one decision per verb (#735 review B1).
    #[test]
    fn v6_a_second_project_entry_for_an_inherited_verb_collides() {
        // A `:trust` file that authorizes `claude`, and a repo that declares its
        // own `claude`, so both project spellings below can name a replacement.
        let fixture = || {
            let f = SourcesFixture::new();
            f.write_user(
                "allow_tools = [\"claude\"]\n\
                 [[tools]]\nname = \"claude\"\ncommand = \"user-claude\"\n\
                 credentials = [\"anthropic\"]\ntools = []\n",
            );
            f.write_repo(
                "r.toml",
                "[[tools]]\nname = \"claude\"\ncommand = \"repo-claude\"\ncredentials = [\"openai\"]\n\
                 tools = []\n",
            );
            f
        };
        let project = |allow: &str| {
            format!(
                "{}\nallow_tools = [{allow}]\n{}",
                sources_block(&[HOME_SOURCE, "repo ./r.toml"]),
                one_tool("claude")
            )
        };

        // Idempotent: `home:claude` *is* the definition `:trust` inherited, so the
        // slot already holds the target and the entry changes nothing.
        let f = fixture();
        let catalog = f
            .with_project(&project("\"home:claude\""))
            .expect("naming the inherited definition is idempotent")
            .into_launch_catalog()
            .expect("catalog");
        assert_eq!(verbs_of(&catalog), ["claude", "shell"]);
        assert_eq!(
            entry_of(&catalog, "claude").tool().command(),
            "user-claude",
            "the inherited definition is still the verb"
        );

        // A single override still replaces the inherited verb in place; if this
        // stops loading, the fix has disabled the precedence it is about.
        let f = fixture();
        let catalog = f
            .with_project(&project("\"repo:claude\""))
            .expect("one override loads")
            .into_launch_catalog()
            .expect("catalog");
        assert_eq!(entry_of(&catalog, "claude").tool().command(), "repo-claude");

        // Two different definitions for the one verb: the first may override, the
        // second must collide whichever spelling it uses.
        for second in ["\"claude\"", "\"home:claude\""] {
            let f = fixture();
            let error = format!(
                "{:#}",
                f.with_project(&project(&format!("\"repo:claude\", {second}")))
                    .expect_err("the second project entry is a collision")
            );
            assert!(
                error.contains("authorizes a second tool named"),
                "{second}: {error}"
            );
            assert!(error.contains("allow_tools[1]"), "{second}: {error}");
        }
    }

    /// V6, R3: deduplication is by target, in first-seen order. The same name twice
    /// in one list is one verb; two *different* targets for one verb are a
    /// collision whatever the earlier entry resolved to — including the inherited
    /// definition named explicitly before a replacement (`["home:pi", "repo:pi"]`,
    /// which a check against the inherited slot alone would wave through).
    #[test]
    fn v6_repeating_a_target_is_idempotent_and_two_targets_collide() {
        // The user file's own list: `a` twice is one verb, first-seen.
        let f = Fixture::new();
        f.user(
            "allow_tools = [\"a\", \"a\"]\n[[tools]]\nname = \"a\"\ncommand = \"a\"\n\
             [[tools]]\nname = \"b\"\ncommand = \"b\"\n",
        );
        let report = f.load().expect("a repeated name is idempotent");
        assert_eq!(launch_names(&report), ["a"]);
        assert_eq!(
            report
                .inert_tools()
                .iter()
                .map(|tool| tool.name())
                .collect::<Vec<_>>(),
            ["b"]
        );

        // The project list: naming the inherited definition and then replacing it
        // is two decisions about one verb, so the second is refused.
        let f = SourcesFixture::new();
        f.write_user(
            "allow_tools = [\"pi\"]\n[[tools]]\nname = \"pi\"\ncommand = \"pi\"\ntools = []\n",
        );
        f.write_repo(
            "r.toml",
            "[[tools]]\nname = \"pi\"\ncommand = \"repo-pi\"\ntools = []\n",
        );
        let error = format!(
            "{:#}",
            f.with_project(&format!(
                "{}\nallow_tools = [\"home:pi\", \"repo:pi\"]\n",
                sources_block(&[HOME_SOURCE, "repo ./r.toml"])
            ))
            .expect_err("two targets for one verb")
        );
        assert!(error.contains("authorizes a second tool named"), "{error}");
        assert!(error.contains("allow_tools[1]"), "{error}");
        // The earlier claimant is the inherited definition, named by its file.
        assert!(error.contains("user config"), "{error}");
    }

    /// V5, R3: the four resolution refusals a project entry can hit, each naming
    /// `allow_tools[N]` and the file/tool that would have made it work.
    #[test]
    fn v5_allow_tools_resolution_errors_name_the_entry() {
        // (a) An alias `sources` does not declare.
        let f = SourcesFixture::new();
        f.write_repo("r.toml", &one_tool("x"));
        let error = format!(
            "{:#}",
            f.with_project(&format!(
                "{}\nallow_tools = [\"nope:x\"]\n",
                sources_block(&["repo ./r.toml"])
            ))
            .expect_err("undeclared alias")
        );
        assert!(error.contains("allow_tools[0]"), "{error}");
        assert!(
            error.contains("names a source alias that sources does not declare"),
            "{error}"
        );
        assert!(!error.contains("nope:x"), "the entry was echoed: {error}");

        // (b) A `:trust` source whose file does not exist.
        let f = SourcesFixture::new();
        let error = format!(
            "{:#}",
            f.with_project(&format!(
                "{}\nallow_tools = [\"home:x\"]\n",
                sources_block(&[HOME_SOURCE])
            ))
            .expect_err("absent :trust file")
        );
        assert!(error.contains("allow_tools[0]"), "{error}");
        assert!(error.contains("but that file does not exist"), "{error}");

        // (c) A source that declares no tool of that name.
        let f = SourcesFixture::new();
        f.write_repo("r.toml", &one_tool("x"));
        let error = format!(
            "{:#}",
            f.with_project(&format!(
                "{}\nallow_tools = [\"repo:missing\"]\n",
                sources_block(&["repo ./r.toml"])
            ))
            .expect_err("undeclared source tool")
        );
        assert!(error.contains("allow_tools[0]"), "{error}");
        assert!(
            error.contains("no tool of that name is declared by"),
            "{error}"
        );
        assert!(!error.contains("missing"), "the entry was echoed: {error}");

        // (d) A local entry naming a tool only a source declares: the advice is the
        // qualified spelling, never a silent cross-file resolution.
        let f = SourcesFixture::new();
        f.write_repo("r.toml", &one_tool("x"));
        let error = format!(
            "{:#}",
            f.with_project(&format!(
                "{}\nallow_tools = [\"x\"]\n",
                sources_block(&["repo ./r.toml"])
            ))
            .expect_err("cross-file local entry")
        );
        assert!(error.contains("allow_tools[0]"), "{error}");
        assert!(
            error.contains("no tool of that name is declared in this file"),
            "{error}"
        );
        assert!(error.contains("qualify it as \"repo:x\""), "{error}");
    }

    /// V11, R4: a non-`:trust` source's `tools` closure must be authorized in
    /// full — explicit, wildcard, implicit wildcard and transitive — and a
    /// same-named authorized tool elsewhere never satisfies an edge.
    #[test]
    fn tool_closure_authorization_is_explicit() {
        let loads = |repo: &str, allow: &str| -> Result<(), String> {
            let f = SourcesFixture::new();
            f.write_repo("r.toml", repo);
            f.write_project(&format!(
                "{}\nallow_tools = [{allow}]\n",
                sources_block(&["repo ./r.toml"])
            ));
            // The closure is checked while the catalog is built, so both stages
            // are in scope for this row.
            let report = f.load().map_err(|error| format!("{error:#}"))?;
            report
                .into_launch_catalog()
                .map(|_| ())
                .map_err(|error| format!("{error:#}"))
        };

        // An explicit edge must be listed.
        let error = loads(
            "[[tools]]\nname = \"a\"\ncommand = \"a\"\ntools = [\"b\"]\n\
             [[tools]]\nname = \"b\"\ncommand = \"b\"\ntools = []\n",
            "\"repo:a\"",
        )
        .expect_err("an unauthorized edge is refused");
        assert!(error.contains("not authorized in allow_tools"), "{error}");
        assert!(error.contains("repo:b"), "{error}");
        assert!(
            loads(
                "[[tools]]\nname = \"a\"\ncommand = \"a\"\ntools = [\"b\"]\n\
             [[tools]]\nname = \"b\"\ncommand = \"b\"\ntools = []\n",
                "\"repo:a\", \"repo:b\"",
            )
            .is_ok()
        );

        // An explicit wildcard reaches the same sibling.
        let error = loads(
            "[[tools]]\nname = \"a\"\ncommand = \"a\"\ntools = [\"*\"]\n\
             [[tools]]\nname = \"b\"\ncommand = \"b\"\ntools = []\n",
            "\"repo:a\"",
        )
        .expect_err("an explicit wildcard is refused");
        assert!(error.contains("not authorized in allow_tools"), "{error}");

        // An omitted `tools` on a declared `shell` is the same wildcard.
        let error = loads(
            "[[tools]]\nname = \"shell\"\ncommand = \"bash\"\ninteractive_shell = true\n\
             [[tools]]\nname = \"b\"\ncommand = \"b\"\ntools = []\n",
            "\"repo:shell\"",
        )
        .expect_err("the implicit wildcard is refused");
        assert!(error.contains("not authorized in allow_tools"), "{error}");
        assert!(error.contains("repo:b"), "{error}");

        // Transitively: authorizing `a` and `b` is not authorizing `c`.
        let error = loads(
            "[[tools]]\nname = \"a\"\ncommand = \"a\"\ntools = [\"b\"]\n\
             [[tools]]\nname = \"b\"\ncommand = \"b\"\ntools = [\"c\"]\n\
             [[tools]]\nname = \"c\"\ncommand = \"c\"\ntools = []\n",
            "\"repo:a\", \"repo:b\"",
        )
        .expect_err("the transitive edge is refused");
        assert!(error.contains("repo:c"), "{error}");

        // A same-named user tool is a different `DefinitionId`, so it never
        // satisfies a source edge.
        let f = SourcesFixture::new();
        f.write_user(
            "allow_tools = [\"b\"]\n[[tools]]\nname = \"b\"\ncommand = \"b\"\ntools = []\n",
        );
        f.write_repo(
            "r.toml",
            "[[tools]]\nname = \"a\"\ncommand = \"a\"\ntools = [\"b\"]\n\
             [[tools]]\nname = \"b\"\ncommand = \"b\"\ntools = []\n",
        );
        f.write_project(&format!(
            "{}\nallow_tools = [\"repo:a\"]\n",
            sources_block(&[HOME_SOURCE, "repo ./r.toml"])
        ));
        let error = format!(
            "{:#}",
            f.load()
                .expect("the load itself is fine")
                .into_launch_catalog()
                .expect_err("wrong origin")
        );
        assert!(error.contains("not authorized in allow_tools"), "{error}");
    }

    /// V22, R6: a retained-but-inert definition is still validated, so a dangling
    /// reference cannot survive by never being authorized.
    #[test]
    fn defaults_path_still_validates_inert_source_references() {
        // (a) The dangling name is refused, naming the source file.
        let f = SourcesFixture::new();
        f.write_repo(
            "r.toml",
            "[[tools]]\nname = \"a\"\ncommand = \"a\"\ntools = [\"missing\"]\n",
        );
        f.write_project(&sources_block(&["repo ./r.toml"]));
        let report = f.load().expect("no authorization, so no verb");
        assert!(report.uses_defaults());
        let error = format!("{:#}", report.into_launch_catalog().unwrap_err());
        assert!(
            error.contains("names no tool in this configuration file"),
            "{error}"
        );

        // (b) Sibling control: a resolvable pair builds, and both stay inert.
        let f = SourcesFixture::new();
        f.write_repo(
            "r.toml",
            "[[tools]]\nname = \"a\"\ncommand = \"a\"\ntools = [\"b\"]\n\
             [[tools]]\nname = \"b\"\ncommand = \"b\"\ntools = []\n",
        );
        f.write_project(&sources_block(&["repo ./r.toml"]));
        let report = f.load().expect("a resolvable inert pair");
        assert!(report.uses_defaults());
        let catalog = report.into_launch_catalog().expect("the shipped catalog");
        assert_eq!(
            verbs_of(&catalog),
            [
                "dsh", "pi", "codex", "opencode", "claude", "copilot", "shell"
            ]
        );

        // (c) Cross-tier: the shipped `pi` is never a fallback for a source file.
        let f = SourcesFixture::new();
        f.write_repo(
            "r.toml",
            "[[tools]]\nname = \"a\"\ncommand = \"a\"\ntools = [\"pi\"]\n",
        );
        f.write_project(&sources_block(&["repo ./r.toml"]));
        let error = format!("{:#}", f.load().unwrap().into_launch_catalog().unwrap_err());
        assert!(error.contains("cross-tier"), "{error}");
    }

    /// V23(a), D6: one leaf-visit budget spans the project, the sources and the
    /// user config — each tier alone loads, both together refuse.
    #[test]
    fn mount_budget_spans_project_source_and_user_tiers() {
        const LIMIT: usize = config_mounts::MAX_MOUNT_SET_EXPANSION_WORK;
        let entries = |count: usize, prefix: &str| -> String {
            (0..count)
                .map(|index| format!("\"{prefix}{index}:/l{index}:ro\""))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let half = LIMIT / 2;

        // Each tier alone is admitted.
        let f = Fixture::new();
        f.user("# no allow_tools\n");
        f.project(&format!(
            "# no allow_tools\n[[tools]]\nname = \"p\"\ncommand = \"p\"\n\
             mounts = [{}]\n",
            entries(half + 1, "/a/")
        ));
        assert!(f.load().is_ok(), "the project tier alone fits");

        let f = Fixture::new();
        f.user(&format!(
            "allow_tools = [\"u\"]\n[[tools]]\nname = \"u\"\ncommand = \"u\"\n\
             mounts = [{}]\n",
            entries(half, "/b/")
        ));
        f.project("# no allow_tools\n");
        assert!(f.load().is_ok(), "the user tier alone fits");

        // Together they exceed it, and the refusal names the user file.
        let f = Fixture::new();
        f.user(&format!(
            "allow_tools = [\"u\"]\n[[tools]]\nname = \"u\"\ncommand = \"u\"\n\
             mounts = [{}]\n",
            entries(half, "/b/")
        ));
        f.project(&format!(
            "# no allow_tools\n[[tools]]\nname = \"p\"\ncommand = \"p\"\n\
             mounts = [{}]\n",
            entries(half + 1, "/a/")
        ));
        let error = format!("{:#}", f.load().expect_err("the tiers share one budget"));
        assert!(error.contains("work"), "{error}");
        assert!(error.contains(&f.user.display().to_string()), "{error}");

        // V23(a): the third contributor is a real `repo` source. Its authorized
        // tool's leaves are charged to the same counter, so user + project +
        // source exceeding it is refused where user + project alone fits.
        let f = SourcesFixture::new();
        f.write_user(&format!(
            "allow_tools = [\"u\"]\n[[tools]]\nname = \"u\"\ncommand = \"u\"\n\
             mounts = [{}]\n",
            entries(half, "/b/")
        ));
        f.write_repo(
            "r.toml",
            &format!(
                "[[tools]]\nname = \"s\"\ncommand = \"s\"\nmounts = [{}]\n",
                entries(half, "/s/")
            ),
        );
        let project = format!(
            "allow_tools = [\"repo:s\", \"p\"]\n{}\n[[tools]]\nname = \"p\"\ncommand = \
             \"p\"\nmounts = [{}]\n",
            // The user file must be sourced by the project config, or the third
            // tier is present but deliberately unread (ADR-0074).
            sources_block(&[HOME_SOURCE, "repo ./r.toml"]),
            entries(2, "/a/")
        );
        // Two tiers of `half` plus the project's two leaves: one over the limit
        // whichever parity the limit has.
        let error = format!(
            "{:#}",
            f.with_project(&project)
                .expect_err("three tiers share one budget")
        );
        assert!(error.contains("work"), "{error}");
        // The refusal names the tier whose declaration crossed the limit: here,
        // the sourced file, read last.
        assert!(
            error.contains(&f.repo("r.toml").display().to_string()),
            "{error}"
        );
    }

    /// V23(b), D6: the load's counter is handed to the catalog build, so a
    /// continuation that starts fresh would admit a second budget.
    #[test]
    fn mount_budget_continues_from_combined_tiers_into_the_catalog() {
        const LIMIT: usize = config_mounts::MAX_MOUNT_SET_EXPANSION_WORK;
        let entries = |count: usize, prefix: &str| -> String {
            (0..count)
                .map(|index| format!("\"{prefix}{index}:/l{index}:ro\""))
                .collect::<Vec<_>>()
                .join(", ")
        };
        // The load charges each declared leaf once and the catalog fold charges the
        // same leaves again, so half the budget at load lands exactly on the limit
        // when the catalog continues from it. A fresh counter at the handoff would
        // stop at half and admit the extra entry below.
        let k = 2;
        let m = LIMIT / 2 - k;

        let f = Fixture::new();
        f.project(&format!(
            "allow_tools = [\"p\"]\n[[tools]]\nname = \"p\"\ncommand = \"p\"\ntools = []\n\
             mounts = [{}]\n",
            entries(k, "/p/")
        ));
        f.user(&format!(
            "allow_tools = [\"u\"]\n[[tools]]\nname = \"u\"\ncommand = \"u\"\ntools = []\n\
             mounts = [{}]\n",
            entries(m, "/u/")
        ));
        let report = f.load().expect("both tiers fit");
        let (catalog, work) = report.into_launch_catalog_with_work();
        assert!(catalog.is_ok(), "{catalog:?}");
        assert_eq!(work.used(), LIMIT);

        let f = Fixture::new();
        f.project(&format!(
            "allow_tools = [\"p\"]\n[[tools]]\nname = \"p\"\ncommand = \"p\"\ntools = []\n\
             mounts = [{}]\n",
            entries(k, "/p/")
        ));
        f.user(&format!(
            "allow_tools = [\"u\"]\n[[tools]]\nname = \"u\"\ncommand = \"u\"\ntools = []\n\
             mounts = [{}]\n",
            entries(m + 1, "/u/")
        ));
        let report = f.load().expect("the load itself still fits");
        let (catalog, work) = report.into_launch_catalog_with_work();
        let error = format!("{:#}", catalog.expect_err("the catalog fold exceeds"));
        assert!(error.contains("tool \"p\""), "{error}");
        assert_eq!(work.used(), LIMIT);
    }

    /// V24(a), R1: `allow_tools` is authority-bearing by **presence**, and the
    /// refusal is the ADR-0040 sentence for that subject — not "authority was not
    /// measured" and not a schema error.
    #[test]
    fn allow_tools_presence_requires_the_verified_read() {
        for body in [
            "allow_tools = []\n",
            "allow_tools = 7\n",
            "allow_tools = [\"t\"]\n[[tools]]\nname = \"t\"\ncommand = \"t\"\n",
        ] {
            let f = Fixture::new();
            let target = f.user.with_file_name("dotfile");
            write_file(&target, body);
            std::os::unix::fs::symlink(&target, &f.user).unwrap();
            let error = format!("{:#}", f.load().expect_err(body));
            assert!(
                error.contains("allow_tools requires config.toml to be a regular file"),
                "{body}: {error}"
            );
            assert!(
                !error.contains("authority was not measured"),
                "{body}: {error}"
            );
        }

        // Presence is refused by the *measurement*, so the two shapes a symlink
        // was only one of are pinned whole: a group- or other-writable file, and a
        // file with a second hard link.
        let f = Fixture::new();
        write_file(
            &f.user,
            "allow_tools = [\"t\"]\n[[tools]]\nname = \"t\"\ncommand = \"t\"\n",
        );
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&f.user, std::fs::Permissions::from_mode(0o664)).unwrap();
        assert_eq!(
            format!("{:#}", f.load().expect_err("group-writable")),
            format!(
                "config: {}: allow_tools refuses a group- or other-writable config.toml; a guest \
                 or another account may have written its allow_tools list, so review the \
                 allow_tools list before trusting the file (fixing the mode does not establish \
                 authorship)",
                crate::one_line::quoted_path(&f.user)
            )
        );

        let f = Fixture::new();
        write_file(
            &f.user,
            "allow_tools = [\"t\"]\n[[tools]]\nname = \"t\"\ncommand = \"t\"\n",
        );
        std::fs::hard_link(&f.user, f.user.with_file_name("alias.toml")).unwrap();
        assert_eq!(
            format!("{:#}", f.load().expect_err("two hard links")),
            format!(
                "config: {}: allow_tools refuses a config.toml with 2 hard links; another name \
                 for it may be guest- or project-writable, so review the allow_tools list before \
                 trusting the file",
                crate::one_line::quoted_path(&f.user)
            )
        );

        // Positive: the same bytes in a regular 0600 file load — `[]` leaves only
        // the shell fallback, and a listed name becomes the verb.
        let f = Fixture::new();
        f.user("allow_tools = []\n[[tools]]\nname = \"t\"\ncommand = \"t\"\n");
        let report = f.load().expect("a regular file needs no verdict");
        assert!(report.resolved().launch_tools().next().is_none());
        let catalog = report.into_launch_catalog().unwrap();
        assert_eq!(verbs_of(&catalog), ["shell"]);

        let f = Fixture::new();
        f.user("allow_tools = [\"t\"]\n[[tools]]\nname = \"t\"\ncommand = \"t\"\n");
        let catalog = f
            .load()
            .expect("a regular file needs no verdict")
            .into_launch_catalog()
            .unwrap();
        assert_eq!(verbs_of(&catalog), ["t", "shell"]);
    }

    /// V24(b), R1: a project `allow_tools` entry selecting a `:trust` tool needs
    /// that file's own verdict, and the refusal names the project file's position.
    #[test]
    fn project_selected_trust_tool_requires_the_user_files_verdict() {
        let tools_only =
            "[[tools]]\nname = \"x\"\ncommand = \"x\"\nnetwork_requests = [\"x.example\"]\n";
        let f = Fixture::new();
        let target = f.user.with_file_name("dotfile");
        write_file(&target, tools_only);
        std::fs::create_dir_all(f.user.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&target, &f.user).unwrap();
        f.project("allow_tools = [\"home:x\"]\n");
        let error = format!("{:#}", f.load().expect_err("unverified :trust tool"));
        assert!(
            error.contains(&format!("config: {:?}: allow_tools[0]: ", f.project)),
            "{error}"
        );
        assert!(
            error.contains("authorizing a :trust tool from the project config requires"),
            "{error}"
        );
        assert!(!error.contains("x.example"), "{error}");

        // Control: an empty project list loads with the shell fallback only.
        let f = Fixture::new();
        let target = f.user.with_file_name("dotfile");
        write_file(&target, tools_only);
        std::fs::create_dir_all(f.user.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&target, &f.user).unwrap();
        f.project("allow_tools = []\n");
        let catalog = f.load().expect("empty list").into_launch_catalog().unwrap();
        assert_eq!(verbs_of(&catalog), ["shell"]);

        // Control: the same bytes as a regular file authorize `x`.
        let f = Fixture::new();
        f.user(tools_only);
        f.project("allow_tools = [\"home:x\"]\n");
        let catalog = f.load().expect("verified").into_launch_catalog().unwrap();
        assert_eq!(verbs_of(&catalog), ["x", "shell"]);
        assert!(matches!(
            entry_of(&catalog, "x").tool().origin(),
            ToolOrigin::User(_)
        ));
    }

    /// The published guidance cannot drift from the shipped catalog.
    ///
    /// The block between the markers in `USAGE.md` is a **complete** replacement
    /// catalog, so every non-mount field must still equal the compiled default for
    /// that tool: dropping a credential, an argv flag, an env pair or the shell's
    /// `interactive_shell` would let a reader paste a config that silently changes
    /// what their agents do. The mounts are the only intended difference, and their
    /// shape is asserted too.
    ///
    /// Deliberately loaded through the ordinary verified fixture path — never by
    /// reading the documented paths on the host, which would make a doc test depend
    /// on the operator's filesystem.
    #[test]
    fn documented_tool_mount_catalog_preserves_shipped_nonmount_fields() {
        const USAGE: &str = include_str!("../../../USAGE.md");
        const START: &str = "<!-- tool-mount-catalog -->";
        const END: &str = "<!-- /tool-mount-catalog -->";
        let start = USAGE.find(START).expect("the documented catalog marker") + START.len();
        let end = start + USAGE[start..].find(END).expect("the closing marker");
        let block = USAGE[start..end].trim();
        // The markers wrap one fenced TOML block; strip the fence so the assertion
        // below is about the catalog alone.
        let block = block
            .strip_prefix("```toml")
            .expect("the documented catalog is a ```toml block")
            .strip_suffix("```")
            .expect("the fenced block is closed")
            .trim();
        let _: toml::Table = block
            .parse()
            .unwrap_or_else(|error| panic!("the documented catalog is not TOML: {error}"));

        let f = Fixture::new();
        f.user(block);
        let home = Path::new("/synthetic-home");
        let report = f
            .load_with_home(home)
            .expect("the documented catalog loads");
        // Every non-mount semantic field equals the shipped definition.
        let documented: Vec<&Tool> = report.resolved().launch_tools().collect();
        let shipped = default_tools().unwrap();
        assert_eq!(documented.len(), shipped.len(), "seven tools, in order");
        for (documented, shipped) in documented.iter().zip(shipped.iter()) {
            assert_eq!(documented.name(), shipped.name());
            assert_eq!(documented.command, shipped.command, "{}", shipped.name());
            assert_eq!(documented.argv, shipped.argv, "{}", shipped.name());
            assert_eq!(
                documented.credentials,
                shipped.credentials,
                "{}",
                shipped.name()
            );
            assert_eq!(
                documented.credential_names,
                shipped.credential_names,
                "{}",
                shipped.name()
            );
            assert_eq!(documented.tools, shipped.tools, "{}", shipped.name());
            assert_eq!(documented.persist, shipped.persist, "{}", shipped.name());
            assert_eq!(
                documented.interactive_shell,
                shipped.interactive_shell,
                "{}",
                shipped.name()
            );
            assert_eq!(documented.env, shipped.env, "{}", shipped.name());
            assert_eq!(
                documented.network_requests,
                shipped.network_requests,
                "{}",
                shipped.name()
            );
        }
        // The mounts are the intended difference: the six agent tools select the
        // `agent` set, Pi adds the fork, and the declared shell's wildcard inherits
        // all of them.
        let catalog = report.into_launch_catalog().unwrap();
        let agent = |name: &str| guest_mounts(&catalog, name);
        for name in ["dsh", "codex", "opencode", "claude", "copilot"] {
            assert_eq!(
                agent(name),
                [
                    "/synthetic-home/.agents",
                    "/synthetic-home/.agents/skills",
                    "/synthetic-home/.config/github-app"
                ],
                "{name}"
            );
        }
        assert_eq!(
            agent("pi"),
            [
                "/synthetic-home/.agents",
                "/synthetic-home/.agents/skills",
                "/synthetic-home/.config/github-app",
                "/synthetic-home/.pi",
            ]
        );
        // The declared shell's omitted `tools` is the wildcard, so it inherits the
        // agent set and the Pi fork — the behaviour the warning above the block
        // describes. It is a declaration here, not the fallback.
        assert!(!catalog.has_shell_fallback());
        let shell = agent("shell");
        assert!(
            shell.contains(&"/synthetic-home/.pi".to_string()),
            "{shell:?}"
        );
        assert!(
            shell.contains(&"/synthetic-home/.agents".to_string()),
            "{shell:?}"
        );
        // Client-visible mounts only: the set's read-only leaf keeps its mode.
        let read_only = entry_of(&catalog, "codex")
            .mounts()
            .requests()
            .find(|request| request.mount.guest.ends_with("github-app"))
            .map(|request| {
                matches!(
                    request.mount.policy,
                    crate::mount::MountPolicy::BindReadOnly { .. }
                )
            })
            .expect("the read-only leaf is selected");
        assert!(read_only);
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
            ConfigPaths::for_test(Some(self.user.clone()), self.project.clone())
        }

        fn load(&self) -> Result<ConfigReport> {
            load(&self.paths())
        }

        /// The same load with a captured `$HOME`, which is what a `~/` mount
        /// spelling expands against (never the process environment).
        fn load_with_home(&self, home: &Path) -> Result<ConfigReport> {
            load(&ConfigPaths::for_test_with_home(
                Some(self.user.clone()),
                self.project.clone(),
                Some(home.to_path_buf()),
            ))
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
            write_file(&self.user, &authorized_fixture(contents, &[]));
            self
        }

        /// The project config's tools are authorized **unless the user file
        /// already declares that name**: a project-side authorization overrides
        /// the user's verb (ADR-0075 D3), and the pre-#735 merge tests exist to
        /// pin the *shadowed* shape, where the user definition wins and the
        /// project one stays in its own reference scope.
        fn project(&self, contents: &str) -> &Self {
            let user_body = std::fs::read_to_string(&self.user).unwrap_or_default();
            let declared: Vec<String> = tool_names(&user_body);
            write_file(&self.project, &authorized_fixture(contents, &declared));
            self
        }
    }

    /// #735 fixture migration: authorize exactly the tools a fixture declares.
    ///
    /// Before #735 a `[[tools]]` block *was* a launch verb, so a hundred fixtures
    /// declared one and expected it to launch. Authorizing is now a separate step,
    /// and those fixtures are not about authorization — so this prepends
    /// `allow_tools` listing every name the body declares.
    ///
    /// A body that mentions `allow_tools` at all is left untouched, which is how a
    /// test states its own authorization (or deliberately states none). The
    /// #735 suite writes that key explicitly, so this helper can never mask the
    /// behaviour those tests measure.
    pub(crate) fn authorized_fixture(contents: &str, skip: &[String]) -> String {
        if contents.contains("allow_tools") {
            return contents.to_owned();
        }
        let names: Vec<String> = tool_names(contents)
            .into_iter()
            .filter(|name| !skip.contains(name))
            .collect();
        if names.is_empty() {
            return contents.to_owned();
        }
        let listed = names
            .iter()
            .map(|name| format!("{name:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        format!("allow_tools = [{listed}]\n{contents}")
    }

    /// Every `[[tools]] name = "…"` in one config body, in declaration order.
    fn tool_names(contents: &str) -> Vec<String> {
        let mut names: Vec<String> = Vec::new();
        for line in contents.lines() {
            let Some(rest) = line.trim().strip_prefix("name = ") else {
                continue;
            };
            if let Some(name) = rest
                .trim()
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                && !names.iter().any(|seen| seen == name)
            {
                names.push(name.to_owned());
            }
        }
        names
    }

    /// A real host-managed project store (ADR-0073) plus a checkout and a
    /// `$HOME`, all under one canonical temp base.
    ///
    /// The ADR-0073 store route and the ADR-0074 `:trust` route checks are real
    /// filesystem observations, so a fixture that skipped them (`ConfigPaths::
    /// for_test`) could not reach the interesting cases at all: it would fail with
    /// the captured-project refusal first.
    struct SourcesFixture {
        _root: tempfile::TempDir,
        base: PathBuf,
        home: PathBuf,
        project: crate::project::ProjectDir,
        config: PathBuf,
    }

    impl SourcesFixture {
        fn new() -> Self {
            Self::with_checkout(false)
        }

        /// `cwd == $HOME`, the layout ADR-0073 Decision 3 and ADR-0074 D3 have to
        /// keep working when it is unaliased.
        fn at_home() -> Self {
            Self::with_checkout(true)
        }

        fn with_checkout(home_is_project: bool) -> Self {
            let root = tempfile::tempdir().unwrap();
            let base = root.path().canonicalize().unwrap();
            let home = base.join("home");
            let checkout = if home_is_project {
                home.clone()
            } else {
                base.join("checkout")
            };
            fs::create_dir_all(&home).unwrap();
            fs::create_dir_all(&checkout).unwrap();
            let project = crate::project::ProjectDir::from_path_for_tests(&checkout).unwrap();
            let config = crate::project_config::path(&home, &project);
            Self {
                _root: root,
                base,
                home,
                project,
                config,
            }
        }

        fn home(&self) -> &Path {
            &self.home
        }

        fn base(&self) -> &Path {
            &self.base
        }

        fn checkout(&self) -> &Path {
            self.project.path()
        }

        fn user_config(&self) -> PathBuf {
            self.home.join(".config/agent-vm/config.toml")
        }

        fn project_config(&self) -> &Path {
            &self.config
        }

        fn repo(&self, relative: &str) -> PathBuf {
            self.project.path().join(relative)
        }

        /// Write the project config at the store path, creating the store with
        /// the `0700` directory a real writer uses so `verify_project` passes.
        fn write_project(&self, body: &str) -> &Self {
            let store = self.config.parent().unwrap();
            fs::create_dir_all(store).unwrap();
            fs::set_permissions(store, std::os::unix::fs::PermissionsExt::from_mode(0o700))
                .unwrap();
            // #735 fixture migration (see `authorized_fixture`): the project's
            // tools are authorized unless the user file declares that name.
            let user_body = fs::read_to_string(self.user_config()).unwrap_or_default();
            fs::write(
                &self.config,
                authorized_fixture(body, &tool_names(&user_body)),
            )
            .unwrap();
            self
        }

        fn write_user(&self, body: &str) -> &Self {
            let path = self.user_config();
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, authorized_fixture(body, &[])).unwrap();
            self
        }

        fn write_repo(&self, relative: &str, body: &str) -> PathBuf {
            let path = self.repo(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, body).unwrap();
            path
        }

        fn paths(&self) -> ConfigPaths {
            ConfigPaths::with_home(Some(self.home.clone()), &self.project)
        }

        fn load(&self) -> Result<ConfigReport> {
            load(&self.paths())
        }

        /// Write the project config and load, the shape most `sources` rows take.
        fn with_project(&self, body: &str) -> Result<ConfigReport> {
            self.write_project(body);
            self.load()
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
            ("pi", "pi", 0, vec!["antigravity"], 0),
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
                    "cloudcode-pa.googleapis.com",
                    "daily-cloudcode-pa.googleapis.com",
                    "daily-cloudcode-pa.sandbox.googleapis.com",
                    "mcp-proxy.anthropic.com",
                    "oauth2.googleapis.com",
                    "pi.dev",
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
            ("pi", "pi", &[], &[Antigravity], false),
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
            ("pi", &[Antigravity], &[Anthropic, OpenAi, Antigravity]),
            ("codex", &[OpenAi], &[OpenAi]),
            (
                "opencode",
                &[OpenAi, OpencodeStatic],
                &[OpenAi, OpencodeStatic],
            ),
            ("claude", &[Anthropic], &[Anthropic]),
            ("copilot", &[Copilot], &[Copilot]),
            (
                "shell",
                &[],
                &[Anthropic, OpenAi, OpencodeStatic, Copilot, Antigravity],
            ),
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
        // The project does not authorize `pi`, so it overrides nothing: the
        // shadowed definition stays inert for the verb list while remaining
        // resolvable from its own file (ADR-0075 D3). The conflict report is about
        // an *authorized* override, so there is none here.
        assert!(
            report.conflicts().is_empty(),
            "an unauthorized project shadow overrides nothing"
        );
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
        let paths = ConfigPaths::for_test(None, project);
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
        assert_eq!(
            provisioned_of(&defaults, "pi"),
            vec![Anthropic, OpenAi, Antigravity]
        );
        // Pi requires Antigravity (it is the provider extension's own login) but
        // inherits Anthropic/OpenAI from its `tools` edges without requiring
        // them.
        assert_eq!(
            entry_of(&defaults, "pi")
                .tool()
                .credential_providers()
                .iter()
                .collect::<Vec<_>>(),
            vec![Antigravity]
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
            vec![Anthropic, OpenAi, OpencodeStatic, Copilot, Antigravity]
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
        std::fs::write(
            &unnamed.project,
            "[[tools]]\nname = \"\"\ncommand = \"t\"\n",
        )
        .unwrap();
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
            resolve_provisioning(
                ResolvedTools::from_defaults(tools),
                &mut config_mounts::MountExpansionWork::fresh(),
            )
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
        fixture.user(base).project(&format!(
            "allow_tools = [\"t\"]\n{}",
            format!("{base}interactive_shell = true\n")
                .replace("command = \"t\"", "command = \"t2\"")
        ));
        let report = fixture.load().unwrap();
        assert_eq!(report.conflicts().len(), 1);
        assert_eq!(
            report.conflicts()[0].fields(),
            &[ToolField::Command, ToolField::InteractiveShell]
        );
        assert_eq!(ToolField::InteractiveShell.as_str(), "interactive_shell");
        // ADR-0075 D3: the project config's authorization outranks the `:trust`
        // file's own verb, so the project's definition — the one with
        // `interactive_shell = true` — is what launches. The field still round-
        // trips and still sorts last in the conflict report, which is this test's
        // subject.
        assert!(first_launch(&report).is_interactive_shell());
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

    /// The *mechanism*: the validator rejects a name taken from the reserved
    /// set. Because it iterates `RESERVED_TOOL_NAMES` itself it cannot see a
    /// name *removed* from that list. The list's *contents* are owned by set
    /// equality with `cli::BUILTIN_SUBCOMMANDS` in
    /// `cli::tests::every_builtin_subcommand_is_reserved_from_tool_names`.
    /// Both halves are needed: keep them separate rather than folding one into
    /// the other.
    #[test]
    fn the_validator_rejects_a_name_from_the_reserved_set() {
        for reserved in RESERVED_TOOL_NAMES {
            let fixture = Fixture::new();
            fixture.user(&one_tool(reserved));
            let error = fixture.load().unwrap_err();
            assert!(format!("{error:#}").contains("reserved"), "{reserved}");
        }
    }

    #[test]
    fn launch_verbs_are_allowed_as_tool_names() {
        for allowed in ["claude", "shell", "copilot", "custom", "build"] {
            let fixture = Fixture::new();
            fixture.user(&one_tool(allowed));
            assert!(fixture.load().is_ok(), "{allowed} should be allowed");
        }
    }

    /// V2, R2: every rejected spelling is refused by the **declaration** rule, with
    /// its own reason. `is_err()` alone was satisfiable by the fixture's injected
    /// `allow_tools` entry, so the declaration validator could have stopped
    /// rejecting names without any row noticing (#735 review S10); each row now
    /// writes the declaration alone and pins the sentence.
    #[test]
    fn unusable_names_are_rejected() {
        const WHITESPACE: &str = "name must not contain whitespace or control characters";
        const PATH: &str = "name must be a single command-name token, not a path";
        const DOTS: &str = "name must not be `.` or `..`";
        const COLON: &str = "name must not contain ':' (':' separates a source alias from a tool \
                             name)";
        for (name, reason) in [
            ("", "name must not be empty"),
            (" ", WHITESPACE),
            ("-x", "name must not start with '-'"),
            ("a b", WHITESPACE),
            ("a\tb", WHITESPACE),
            ("a\nb", WHITESPACE),
            ("a/b", PATH),
            ("/abs", PATH),
            // A path refusal, not the dots one: '/' is decided first.
            ("../..", PATH),
            ("../../evil", PATH),
            (".", DOTS),
            ("..", DOTS),
            ("...", DOTS),
            // V2: `:` would make `<alias>:<name>` ambiguous.
            ("a:b", COLON),
        ] {
            let fixture = Fixture::new();
            let body = format!(
                "[[tools]]\nname = \"{}\"\ncommand = \"x\"\n",
                name.escape_debug()
            );
            // Written directly, never through the fixture's `allow_tools` device, so
            // only the declaration can be what refuses this body.
            write_file(&fixture.user, &body);
            let error = fixture.load().unwrap_err().to_string();
            assert!(
                error.contains("declaration [0] tool"),
                "name={name:?}: {error}"
            );
            assert!(error.contains(reason), "name={name:?}: {error}");
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

    /// R3: an authorized project definition identical to the inherited one dedupes
    /// silently — one verb, no conflict — through the `same_definition` comparison
    /// the override branch makes. The project entry must be explicit: the fixture's
    /// authorization device skips names the user declares, so without it the project
    /// copy would be inert and "no conflict" would prove nothing (#735 review S10).
    #[test]
    fn identical_cross_tier_definitions_dedupe_silently() {
        let fixture = Fixture::new();
        fixture
            .user(&one_tool("dup"))
            .project(&format!("allow_tools = [\"dup\"]\n{}", one_tool("dup")));
        let report = fixture.load().unwrap();
        assert!(report.conflicts().is_empty());
        let tools: Vec<&Tool> = report.resolved().launch_tools().collect();
        assert_eq!(tools.len(), 1);
        // The authorizing declaration is the winner: the project overrides the
        // inherited slot in place (ADR-0075 D3).
        assert_eq!(
            tools[0].origin(),
            &ToolOrigin::Project(fixture.project.clone())
        );
        assert_eq!(tools[0].command(), "dup", "the definitions were identical");
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
                    // Unreachable in this table: a project tool may not declare
                    // `mounts` at all, so its presence is a load error rather than
                    // a differing-field warning. Named here so the match stays
                    // exhaustive instead of gaining a catch-all.
                    ToolField::Mounts => unreachable!("project mounts are refused"),
                },
                mutated,
            );
            let fixture = Fixture::new();
            fixture
                .user(base)
                .project(&format!("allow_tools = [\"t\"]\n{project_body}"));
            let report = fixture.load().unwrap();
            let conflicts = report.conflicts();
            assert_eq!(conflicts.len(), 1, "case {expected:?}");
            assert_eq!(conflicts[0].fields(), &[expected]);
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
        fixture
            .user(base)
            .project(&format!("allow_tools = [\"t\"]\n{project_body}"));
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
                "allow_tools = [\"b\", \"a\"]\n[[tools]]\nname = \"b\"\ncommand = \"b2\"\n[[tools]]\nname = \"a\"\ncommand = \"a2\"\nargs = [\"1\"]\ncredentials = [\"anthropic\"]\n",
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
            .project("allow_tools = [\"t\"]\n[[tools]]\nname = \"t\"\ncommand = \"t\"\ncredentials = [\"anthropic\"]\n");
        let report = fixture.load().unwrap();
        assert_eq!(report.conflicts().len(), 1);
        assert_eq!(report.conflicts()[0].fields(), &[ToolField::Credentials]);
        // The project's authorization is what the launch offers (#735 D3).
        assert_eq!(
            first_launch(&report).origin(),
            &ToolOrigin::Project(fixture.project.clone())
        );
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
            .project("allow_tools = [\"t\"]\n[[tools]]\nname = \"t\"\ncommand = \"t\"\nargs = [\"b\", \"a\"]\n");
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
                ("pi", vec![Anthropic, OpenAi, Antigravity]),
                ("codex", vec![OpenAi]),
                ("opencode", vec![OpenAi, OpencodeStatic]),
                ("claude", vec![Anthropic]),
                ("copilot", vec![Copilot]),
                (
                    "shell",
                    vec![Anthropic, OpenAi, OpencodeStatic, Copilot, Antigravity]
                ),
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
        let paths = ConfigPaths::for_test(None, evil.join(".agent-vm/config.toml"));
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
        let paths = ConfigPaths::for_test(None, evil.join(".agent-vm/config.toml"));
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

    use crate::test_env;

    /// AC1/R1: the project tier is `$HOME/.config/agent-vm/projects/<64-hex>/
    /// config.toml`, derived from the command's captured project — and both
    /// tiers are unavailable without `$HOME`, with no project path at all.
    ///
    /// The digest is recomputed here from the canonical path's bytes, so a
    /// truncated id or a different hash input fails rather than agreeing with
    /// the product's own helper.
    #[test]
    fn discover_places_the_project_tier_under_home_by_project_digest() {
        use sha2::{Digest as _, Sha256};
        let mut env = test_env::guard();
        let home_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        // The *spelled* home, not its canonical form: both tiers keep the literal
        // `$HOME` spelling in their paths and in diagnostics.
        let home = home_dir.path().to_path_buf();
        env.set_var("HOME", &home);
        let project = crate::project::ProjectDir::from_path_for_tests(project_dir.path()).unwrap();
        let paths = ConfigPaths::discover(&project).unwrap();
        assert_eq!(
            paths.user,
            Some(home.join(USER_CONFIG_RELATIVE)),
            "the user tier keeps its literal $HOME location"
        );
        let hex: String = Sha256::digest(project.path().as_os_str().as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(hex.len(), 64);
        let expected = home
            .join(".config/agent-vm/projects")
            .join(&hex)
            .join("config.toml");
        assert_eq!(
            paths.project.as_ref().map(|tier| &tier.config),
            Some(&expected)
        );
        assert_eq!(paths.home, Some(home));
        assert!(
            matches!(
                paths.project.as_ref().map(|tier| &tier.route),
                Some(crate::project_config::RouteAnchor::Captured { root, .. })
                    if root == project.path()
            ),
            "discovery anchors the store route at the captured project root"
        );
        // Nothing the discovery produced lives in the project.
        assert!(
            !paths
                .project
                .as_ref()
                .unwrap()
                .config
                .starts_with(project.path()),
            "the project tier is host-managed, never in-repo"
        );

        env.remove_var("HOME");
        let paths = ConfigPaths::discover(&project).unwrap();
        assert_eq!(paths.user, None);
        assert!(paths.project.is_none(), "R2: no HOME means no project tier");
        assert_eq!(paths.home, None);
    }

    /// V8: the project tier's read policy, before any byte is decoded.
    ///
    /// Every row is a real filesystem shape, and the message is the only way a
    /// caller learns which check refused: a read that opened first, or a
    /// followed final symlink, would produce a different sentence (or a UTF-8
    /// error, or a "not a regular file").
    #[test]
    fn project_tier_rejects_symlinks_aliases_and_unsafe_files_before_reading() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        struct Fixture {
            _root: tempfile::TempDir,
            home: PathBuf,
            project: crate::project::ProjectDir,
            config: PathBuf,
        }
        impl Fixture {
            /// `cwd` is the project by default; a caller may pass `home` itself
            /// for the legitimate `cwd == $HOME` row.
            fn new() -> Self {
                Self::at(false)
            }
            fn at(home_is_project: bool) -> Self {
                let root = tempfile::tempdir().unwrap();
                let base = root.path().canonicalize().unwrap();
                let home = base.join("home");
                let checkout = if home_is_project {
                    home.clone()
                } else {
                    base.join("checkout")
                };
                fs::create_dir_all(&home).unwrap();
                fs::create_dir_all(&checkout).unwrap();
                let project = crate::project::ProjectDir::from_path_for_tests(&checkout).unwrap();
                let config = crate::project_config::path(&home, &project);
                Self {
                    _root: root,
                    home,
                    project,
                    config,
                }
            }
            fn store(&self) -> &Path {
                self.config.parent().unwrap()
            }
            fn write_store(&self, body: &str) {
                fs::create_dir_all(self.store()).unwrap();
                fs::write(&self.config, body).unwrap();
            }
            fn load(&self) -> Result<ConfigReport> {
                load(&ConfigPaths {
                    user: Some(self.home.join(".config/agent-vm/config.toml")),
                    project: Some(crate::project_config::ProjectTierPaths {
                        config: self.config.clone(),
                        route: crate::project_config::RouteAnchor::Captured {
                            home: self.home.clone(),
                            root: self.project.path().to_path_buf(),
                        },
                    }),
                    home: Some(self.home.clone()),
                })
            }
        }

        // (a) A final symlink is refused from the open's own verdict. The target
        // holds invalid UTF-8 and then a FIFO: either would be observable as a
        // different error if the target were opened or read.
        let f = Fixture::new();
        fs::create_dir_all(f.store()).unwrap();
        let target = f.home.join("target.toml");
        fs::write(&target, b"[[tools]]\nname = \xff\n").unwrap();
        symlink(&target, &f.config).unwrap();
        let message = f.load().unwrap_err().to_string();
        assert!(
            message.contains("reached through a symbolic link"),
            "{message}"
        );
        assert!(message.contains("the project config"), "{message}");
        fs::remove_file(&f.config).unwrap();
        let fifo = f.home.join("fifo");
        let c_path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        symlink(&fifo, &f.config).unwrap();
        assert!(
            f.load()
                .unwrap_err()
                .to_string()
                .contains("reached through a symbolic link")
        );

        // (b) A group-writable store directory refuses a tools-only file: the
        // project tier is measured whatever it declares.
        let f = Fixture::new();
        f.write_store("[[tools]]\nname = \"solo\"\ncommand = \"solo\"\n");
        fs::set_permissions(f.store(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(f.load().is_ok(), "a 0700 store with one link is trusted");
        fs::set_permissions(f.store(), fs::Permissions::from_mode(0o775)).unwrap();
        let message = f.load().unwrap_err().to_string();
        assert!(
            message.contains("whose directory is group- or other-writable"),
            "{message}"
        );
        assert!(
            message.contains(&crate::one_line::quoted_path(&f.config).to_string()),
            "the refusal names the file: {message}"
        );
        assert!(message.contains("the project config"), "{message}");

        // (c) `projects/<id>` symlinked into the active checkout: the store route
        // is refused before `config.toml` is opened.
        let f = Fixture::new();
        fs::create_dir_all(f.project.path().join(".agent-vm")).unwrap();
        fs::write(
            f.project.path().join(".agent-vm/config.toml"),
            "[[tools]]\nname = \"smuggled\"\n",
        )
        .unwrap();
        fs::create_dir_all(f.store().parent().unwrap()).unwrap();
        symlink(f.project.path().join(".agent-vm"), f.store()).unwrap();
        let message = f.load().unwrap_err().to_string();
        assert!(
            message.contains("project store directory reached through a symbolic link"),
            "{message}"
        );

        // (d) `projects/` symlinked to the checkout, and the whole authority
        // directory aliased into it.
        let f = Fixture::new();
        fs::create_dir_all(f.home.join(".config/agent-vm")).unwrap();
        symlink(f.project.path(), f.store().parent().unwrap()).unwrap();
        let message = f.load().unwrap_err().to_string();
        assert!(
            message.contains("projects directory reached through a symbolic link"),
            "{message}"
        );

        let f = Fixture::new();
        let evil = f.project.path().join("evil/projects");
        fs::create_dir_all(&evil).unwrap();
        fs::create_dir_all(f.home.join(".config")).unwrap();
        symlink(
            f.project.path().join("evil"),
            f.home.join(".config/agent-vm"),
        )
        .unwrap();
        // The store exists and is not itself a symlink: only the ancestor alias
        // is wrong, which is the row this asserts.
        fs::create_dir_all(f.store()).unwrap();
        let message = f.load().unwrap_err().to_string();
        assert!(
            message.contains("resolves inside the active project"),
            "{message}"
        );

        // (e) Running legitimately with `cwd == $HOME`: the store's canonical
        // path is under the project, and that is not an alias.
        let f = Fixture::at(true);
        f.write_store("[[tools]]\nname = \"hosted\"\ncommand = \"hosted\"\n");
        fs::set_permissions(f.store(), fs::Permissions::from_mode(0o700)).unwrap();
        let report = f.load().expect("cwd == $HOME is a legitimate run");
        assert_eq!(
            report.project().status(),
            &TierStatus::Found { declared_tools: 1 }
        );

        // (f) The user tier keeps ADR-0040's dotfile compatibility: a
        // tools-only file reached through a symlink still loads.
        let f = Fixture::new();
        let user = f.home.join(".config/agent-vm/config.toml");
        fs::create_dir_all(user.parent().unwrap()).unwrap();
        fs::write(
            f.home.join("dotfile.toml"),
            "[[tools]]\nname = \"dotty\"\ncommand = \"dotty\"\n",
        )
        .unwrap();
        symlink(f.home.join("dotfile.toml"), &user).unwrap();
        let report = f.load().expect("a tools-only symlinked user file loads");
        assert_eq!(
            report.user().status(),
            &TierStatus::Found { declared_tools: 1 }
        );
        assert!(!report.uses_defaults());
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

        /// Duplicating a catalog across both tiers is an idempotent dedupe: the
        /// project authorizes every copy it declares, so the identical-definition
        /// override path runs instead of the copies sitting inert.
        #[test]
        fn duplicating_a_catalog_across_tiers_is_idempotent(
            names in proptest::collection::vec("[a-z]{1,6}", 1..5),
        ) {
            let unique = dedupe(names);
            let body: String = unique.iter().map(|name| format!("[[tools]]\nname = \"{name}\"\ncommand = \"{name}\"\n")).collect();
            let listed = unique.iter().map(|name| format!("{name:?}")).collect::<Vec<_>>().join(", ");
            let fixture = Fixture::new();
            fixture.user(&body).project(&format!("allow_tools = [{listed}]\n{body}"));
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
        // Canonicically equal request sets do not differ, so no conflict is
        // recorded even when the project authorizes the verb (#735 D3).
        let f = Fixture::new();
        f.user("[[tools]]\nname = \"t\"\ncommand = \"t\"\nnetwork_requests = [\"a.example\",\"b.example\"]\n")
            .project("allow_tools = [\"t\"]\n[[tools]]\nname = \"t\"\ncommand = \"t\"\nnetwork_requests = [\"B.example.\",\"a.example\",\"a.example:443\"]\n");
        assert!(f.load().unwrap().conflicts().is_empty());
        f.user("[[tools]]\nname = \"t\"\ncommand = \"t\"\n");
        let report = f.load().unwrap();
        assert_eq!(
            report.conflicts()[0].fields(),
            &[ToolField::NetworkRequests]
        );
        assert_eq!(
            report.conflicts()[0].winner_file(),
            f.project.as_path(),
            "the project's authorization is the winner"
        );
        assert_eq!(
            first_launch(&report)
                .network_requests()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["a.example", "b.example"]
        );
        assert_eq!(
            first_launch(&report).origin(),
            &ToolOrigin::Project(f.project.clone())
        );
        f.project(
            "allow_tools = [\"t\"]\n[[tools]]\nname = \"t\"\ncommand = \"t\"\nnetwork_requests = [\"udp://a.example\"]\n",
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

    // -- ADR-0059 egress references ---------------------------------------

    /// Every allowance a loaded user `[network]` table grants, in order.
    fn saved_allowances(report: &ConfigReport) -> Vec<String> {
        report
            .user_network()
            .expect("the fixture declares [network]")
            .allowances()
            .allowances()
            .map(ToString::to_string)
            .collect()
    }

    fn network_table(entries: &str) -> String {
        format!("\n[network]\nallow_egress = [{entries}]\n")
    }

    /// V12: `tool:NAME` is ordinary allowance text again, so `[network]` refuses
    /// it exactly as the grammar does — a non-numeric name is a malformed port,
    /// and a numeric one is the literal hostname `tool` (the pre-#506 meaning).
    #[test]
    fn tool_names_in_allow_egress_are_refused_as_malformed_ports() {
        for text in ["tool:fetcher", "TOOL:codex", "tool:"] {
            let fixture = Fixture::new();
            let error = fixture
                .user(&network_table(&format!("{text:?}")))
                .load()
                .unwrap_err()
                .to_string();
            assert_eq!(
                error,
                format!(
                    "config: {}: network.allow_egress[0]: port must be a decimal number 1-65535",
                    crate::one_line::quoted_path(&fixture.user)
                ),
                "{text}"
            );
        }
        let fixture = Fixture::new();
        fixture.user(&network_table("\"tool:443\""));
        let report = fixture.load().unwrap();
        assert_eq!(
            saved_allowances(&report),
            ["tcp://tool:443"],
            "a numeric tool:PORT is the literal hostname `tool`"
        );
    }

    /// `set:NAME` is the one remaining reference, and it resolves against the
    /// user file's own `[egress_sets]`.
    #[test]
    fn set_reference_expands_to_its_compiled_closure() {
        let fixture = Fixture::new();
        fixture.user(&format!(
            "[egress_sets]\ncorp = [\"git.corp.example\", \"10.0.0.5\"]\n{}",
            network_table("\"set:corp\"")
        ));
        let report = fixture.load().unwrap();
        assert_eq!(
            saved_allowances(&report),
            ["git.corp.example", "10.0.0.5/32"]
        );

        // An undefined name is a resolution error, named by its position and
        // never echoed.
        let fixture = Fixture::new();
        let error = fixture
            .user(&network_table("\"set:SENTINEL735\""))
            .load()
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            format!(
                "config: {}: network.allow_egress[0]: an egress reference must name a set declared \
                 in the user config's own [egress_sets]; project and built-in configs cannot \
                 declare sets",
                crate::one_line::quoted_path(&fixture.user)
            )
        );
        assert!(!error.contains("SENTINEL735"));
    }

    /// A resolved reference uses the captured directory verdict in **both**
    /// directions, which A31 (link replaced by a file) alone cannot show: that
    /// test would still pass if resolution re-measured *only the directory*.
    ///
    /// Made writable after load, the captured passing verdict still resolves;
    /// made private after load, the captured `DirWritable` refusal still refuses.
    #[test]
    fn captured_directory_verdict_is_not_remeasured() {
        use std::os::unix::fs::PermissionsExt;
        let sets_only = "[egress_sets]\ncorp = [\"a.example\"]\n";
        let resolve_set = |report: &ConfigReport| {
            crate::egress_reference::resolve(
                vec![crate::egress_reference::AllowanceEntry::parse("set:corp").unwrap()],
                report.user_tool_requests(),
            )
        };

        let f = Fixture::new();
        f.user(sets_only);
        let report = f.load().expect("the file passes");
        // A directory the *load* accepted, made writable afterwards.
        std::fs::set_permissions(
            f.user.parent().unwrap(),
            std::fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        let resolved = resolve_set(&report).expect("the captured verdict still passes");
        assert_eq!(
            resolved
                .allowances()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["a.example"]
        );

        // The reverse direction cannot be a *captured* refusal any more: a
        // `[egress_sets]` table is authority-bearing (ADR-0040's fourth trigger),
        // so a writable directory refuses at **load**, before any verdict could be
        // captured — there is no report to resolve and no second measurement to
        // skip. What is still worth pinning is that this is a load refusal, and
        // that the mode is what decides it.
        let f = Fixture::new();
        f.user(sets_only);
        std::fs::set_permissions(
            f.user.parent().unwrap(),
            std::fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        let error = f.load().unwrap_err().to_string();
        assert!(
            error.contains("group- or other-writable") && error.contains("egress_sets"),
            "{error}"
        );
        assert!(
            error.contains("group- or other-writable"),
            "the refusal names the mode: {error}"
        );
    }

    /// A28/A31: a resolved reference uses the captured **file** verdict, in both
    /// directions, and never re-reads or re-measures.
    #[test]
    fn captured_reference_verdict_is_not_remeasured() {
        use std::os::unix::fs::PermissionsExt;
        let f = Fixture::new();
        f.user("[egress_sets]\ncorp = [\"a.example\"]\n");
        let report = f.load().expect("the file passes");
        std::fs::set_permissions(&f.user, std::fs::Permissions::from_mode(0o664)).unwrap();
        assert!(
            crate::egress_reference::resolve(
                vec![crate::egress_reference::AllowanceEntry::parse("set:corp").unwrap()],
                report.user_tool_requests(),
            )
            .is_ok(),
            "a file made writable after load does not re-measure"
        );

        // The refusal direction is a **load** refusal, not a captured one: a
        // `[egress_sets]` table is authority-bearing, so an unverified file never
        // loads and there is no report to resolve. What still matters for the
        // captured-verdict property is the direction above (a load-accepted file
        // made writable does not re-measure); a file made private after a *refused*
        // load has no verdict to reuse.
        let f = Fixture::new();
        f.user("[egress_sets]\ncorp = [\"a.example\"]\n");
        std::fs::set_permissions(&f.user, std::fs::Permissions::from_mode(0o664)).unwrap();
        let error = f.load().unwrap_err().to_string();
        assert!(
            error.contains("group- or other-writable config.toml") && error.contains("egress_sets"),
            "{error}"
        );
        std::fs::set_permissions(&f.user, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            f.load().is_ok(),
            "the same bytes are accepted once the file is private"
        );
    }

    /// A user file that declares only `[egress_sets]` still supplies a namespace,
    /// so a CLI `set:NAME` resolves without a `[network]` table.
    #[test]
    fn a_sets_only_user_file_still_supplies_a_namespace() {
        let fixture = Fixture::new();
        fixture
            .project("")
            .user("[egress_sets]\nfetcher = [\"a.example\"]\n");
        let report = fixture.load().unwrap();
        assert!(report.user_network().is_none());
        let namespace = report.user_tool_requests().expect("the user tier loaded");
        let resolved = crate::egress_reference::resolve(
            vec![crate::egress_reference::AllowanceEntry::parse("set:fetcher").unwrap()],
            Some(namespace),
        )
        .unwrap();
        assert!(
            resolved
                .allowances()
                .any(|allowance| allowance.to_string() == "a.example")
        );
    }

    // -- sources (ADR-0074) ------------------------------------------------

    use crate::config_sources::{SourceTrust, Sourcing};

    /// The documented spelling of the user config as a trusted source.
    const HOME_SOURCE: &str = "home:trust ~/.config/agent-vm/config.toml";
    /// A repository file sourced without `:trust`.
    const REPO_SOURCE: &str = "repo ./.agent-vm/config.toml";

    fn sources_block(entries: &[&str]) -> String {
        let quoted: Vec<String> = entries.iter().map(|entry| format!("{entry:?}")).collect();
        format!("sources = [{}]\n", quoted.join(", "))
    }

    /// The launch verbs a report offers, before the `shell` fallback is added.
    fn launch_names(report: &ConfigReport) -> Vec<String> {
        report
            .resolved()
            .launch_tools()
            .map(|tool| tool.name().to_string())
            .collect()
    }

    fn image_ref(image: Option<&ConfiguredImage>) -> Option<&str> {
        image.map(|image| image.reference().as_str())
    }

    /// V5: an absent project config behaves exactly as the single implicit
    /// `home:trust <user config>` entry, which is #733's shipped load.
    #[test]
    fn v5_an_absent_project_config_sources_the_user_config_implicitly() {
        let f = SourcesFixture::new();
        f.write_user(&format!(
            "image = \"localhost:1/u:latest\"\nmounts = [\"/a:/g:ro\"]\n\
             [network]\nallow_lan = true\n{}",
            one_tool("u")
        ));
        let report = f.load().expect("implicit load");
        assert!(!report.uses_defaults());
        assert_eq!(
            report.user().status(),
            &TierStatus::Found { declared_tools: 1 }
        );
        assert_eq!(report.project().status(), &TierStatus::Absent);
        assert!(report.user_network().is_some(), "user [network] loads");
        assert!(report.user_mounts().is_some(), "user mounts load");
        assert_eq!(
            image_ref(report.images().user()),
            Some("localhost:1/u:latest")
        );
        assert_eq!(
            report.sources().sourcing(),
            Sourcing::Implicit,
            "no project config means the implicit default"
        );
        let entries = report.sources().entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].alias().as_str(), "home");
        assert_eq!(entries[0].trust(), SourceTrust::Trusted);
        assert_eq!(entries[0].tier().path(), Some(f.user_config().as_path()));
        assert!(
            report.sources().listed_files().is_empty(),
            "an implicit source may not suppress the legacy notice"
        );
    }

    /// V6 (AC4): a missing `home:trust` file is absent, not an error — with no
    /// project config and with an explicit list.
    #[test]
    fn v6_a_missing_trusted_source_is_absent_not_an_error() {
        let f = SourcesFixture::new();
        let report = f.load().expect("no config files at all");
        assert_eq!(report.user().status(), &TierStatus::Absent);
        assert!(report.uses_defaults());
        assert_eq!(report.sources().sourcing(), Sourcing::Implicit);
        assert_eq!(report.sources().entries().len(), 1);

        let f = SourcesFixture::new();
        let report = f
            .with_project(&sources_block(&[HOME_SOURCE]))
            .expect("an explicit missing home:trust source is still absent");
        assert_eq!(report.user().status(), &TierStatus::Absent);
        assert_eq!(report.sources().sourcing(), Sourcing::Listed);
        assert!(report.uses_defaults());
        assert_eq!(image_ref(report.images().user()), None);
    }

    /// V7 (D2): an omitted `sources` key keeps the implicit default; an explicit
    /// list — `[]` and untrusted-only included — replaces it, so a malformed user
    /// file is never read.
    #[test]
    fn v7_an_omitted_sources_key_is_implicit_and_an_explicit_list_opts_out() {
        let f = SourcesFixture::new();
        f.write_user(&one_tool("u"));
        let report = f.with_project(&one_tool("p")).expect("omitted key");
        assert_eq!(report.sources().sourcing(), Sourcing::Implicit);
        assert_eq!(launch_names(&report), ["u", "p"]);

        // A malformed user file proves the file is not read at all: reading it
        // would fail the load.
        let f = SourcesFixture::new();
        f.write_user("this is not = = toml\n");
        let report = f
            .with_project(&format!("{}{}", sources_block(&[]), one_tool("p")))
            .expect("sources = [] sources nothing");
        assert_eq!(report.user().status(), &TierStatus::NotSourced);
        assert!(report.user_network().is_none());
        assert!(report.user_mounts().is_none());
        assert_eq!(launch_names(&report), ["p"]);

        // The alias `home` without `:trust` is a declaration-only source, not the
        // home config.
        let f = SourcesFixture::new();
        f.write_user("this is not = = toml\n");
        f.write_repo("r.toml", &one_tool("r"));
        let report = f
            .with_project(&format!(
                "{}\nallow_tools = [\"p\", \"home:r\"]\n{}",
                sources_block(&["home ./r.toml"]),
                one_tool("p")
            ))
            .expect("an untrusted-only list loads");
        assert_eq!(report.user().status(), &TierStatus::NotSourced);
        // #735: a sourced tool is a verb only when the project authorizes it.
        assert_eq!(launch_names(&report), ["p", "r"]);

        // With no tools declared anywhere, the defaults still apply.
        let f = SourcesFixture::new();
        f.write_user("this is not = = toml\n");
        let report = f.with_project(&sources_block(&[])).expect("empty list");
        assert!(report.uses_defaults());
    }

    /// V8: a source's tools carry their own provenance and reference scope, and a
    /// user shadow retains the losing source definition for that file's references.
    #[test]
    fn v8_a_source_tool_has_its_own_scope_and_a_user_shadow_keeps_the_loser() {
        let f = SourcesFixture::new();
        f.write_user(&tool(
            "name = \"u\"\ncommand = \"u\"\npersist = [\"user-path\"]\n",
        ));
        let repo = f.write_repo(
            ".agent-vm/config.toml",
            &format!(
                "{}{}",
                tool("name = \"u\"\ncommand = \"repo-u\"\npersist = [\"repo-path\"]\n"),
                tool("name = \"repo\"\ncommand = \"repo\"\ntools = [\"u\"]\n")
            ),
        );
        let report = f
            .with_project(&format!(
                "{}\nallow_tools = [\"p\", \"repo:u\", \"repo:repo\"]\n{}",
                sources_block(&[HOME_SOURCE, REPO_SOURCE]),
                one_tool("p")
            ))
            .expect("shadowed source tool loads");
        // ADR-0075 D3: the project config's authorization outranks the `:trust`
        // file's own verb, so the *source* definition is the launch verb for `u`
        // and the user's is the overridden one.
        let winner = report
            .resolved()
            .launch_tools()
            .find(|tool| tool.name() == "u")
            .expect("u");
        assert_eq!(winner.command(), "repo-u");
        let conflicts = report.conflicts();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].tool(), "u");
        assert_eq!(conflicts[0].winner_file(), repo.as_path());
        assert_eq!(conflicts[0].overridden_file(), f.user_config().as_path());

        let catalog = report.into_launch_catalog().expect("catalog");
        // The source's own `u` is what its own reference resolves to, so the
        // repo facet — not the user one — is inherited.
        let provisioned: Vec<String> = entry_of(&catalog, "repo")
            .persist()
            .iter()
            .map(|path| path.as_path().display().to_string())
            .collect();
        assert_eq!(provisioned, ["repo-path"]);
        assert_eq!(
            entry_of(&catalog, "repo").tool().origin(),
            &ToolOrigin::Source {
                alias: crate::config_sources::SourceAlias::for_test("repo"),
                file: repo.clone(),
            }
        );
    }

    /// V8 (continued): a reference that crosses a file boundary names the file
    /// that actually declares the name.
    #[test]
    fn v8_a_cross_file_reference_names_the_other_file() {
        let f = SourcesFixture::new();
        f.write_user(&one_tool("user-only"));
        f.write_repo(
            ".agent-vm/config.toml",
            &format!(
                "{}{}",
                one_tool("repo-only"),
                tool("name = \"from-repo\"\ncommand = \"x\"\ntools = [\"user-only\"]\n")
            ),
        );
        let report = f
            .with_project(&sources_block(&[HOME_SOURCE, REPO_SOURCE]))
            .expect("load");
        let error = format!(
            "{:#}",
            report.into_launch_catalog().expect_err("cross-file")
        );
        assert!(
            error.contains("declared in user config"),
            "the repo tool's miss reports the user file: {error}"
        );

        let f = SourcesFixture::new();
        f.write_user(&format!(
            "{}{}",
            one_tool("user-only"),
            tool("name = \"from-user\"\ncommand = \"x\"\ntools = [\"repo-only\"]\n")
        ));
        f.write_repo(".agent-vm/config.toml", &one_tool("repo-only"));
        let report = f
            .with_project(&sources_block(&[HOME_SOURCE, REPO_SOURCE]))
            .expect("load");
        let error = format!(
            "{:#}",
            report.into_launch_catalog().expect_err("cross-file")
        );
        assert!(
            error.contains("declared in source repo"),
            "the user tool's miss reports the source: {error}"
        );
    }

    /// V9 (R7): flat sourcing. `sources` is refused in every tier but the project
    /// config, `[]` included, and no refusal echoes the file's values.
    #[test]
    fn v9_sources_is_refused_outside_the_project_config() {
        // Implicit sourcing, user file declares the key.
        let f = SourcesFixture::new();
        f.write_user("sources = []\n");
        let error = format!("{:#}", f.load().expect_err("user tier sources"));
        assert!(
            error.contains("only the project config may declare sources"),
            "{error}"
        );
        assert!(
            error.contains(&f.user_config().display().to_string()),
            "{error}"
        );

        // Listed `:trust` source, same key.
        let f = SourcesFixture::new();
        f.write_user(&format!("{}\n", sources_block(&[])));
        f.write_project(&sources_block(&[HOME_SOURCE]));
        let error = format!("{:#}", f.load().expect_err("trusted tier sources"));
        assert!(
            error.contains("only the project config may declare sources"),
            "{error}"
        );

        // An untrusted source, and `sources = []` is no exception.
        let f = SourcesFixture::new();
        let repo = f.write_repo(".agent-vm/config.toml", &sources_block(&[]));
        f.write_project(&sources_block(&[REPO_SOURCE]));
        let error = format!("{:#}", f.load().expect_err("source tier sources"));
        assert!(error.contains(&format!("{}", repo.display())), "{error}");
        assert!(
            error.contains("only the project config may declare sources"),
            "{error}"
        );

        // The shipped text cannot carry it either.
        let error = match builtin_raw_config(&sources_block(&[])) {
            Err(error) => format!("{error:#}"),
            Ok(_) => panic!("the built-in text must not declare sources"),
        };
        assert!(
            error.contains("only the project config may declare sources"),
            "{error}"
        );

        // A malformed value is the schema error (F3), not the flat refusal.
        let f = SourcesFixture::new();
        let error = format!(
            "{:#}",
            f.with_project("sources = \"bad\"\n").expect_err("schema")
        );
        assert!(error.contains("invalid TOML or tool schema"), "{error}");

        // An unknown field is refused without echoing its value.
        let f = SourcesFixture::new();
        let error = format!(
            "{:#}",
            f.with_project("allow_tools = [\"SECRET-734\"]\n")
                .expect_err("unknown field")
        );
        assert!(!error.contains("SECRET-734"), "{error}");

        // An indirect self-source: a checkout symlink to the store makes the
        // project config a *source*, which then declares `sources`.
        let f = SourcesFixture::new();
        f.write_project(&sources_block(&["self ./link/config.toml"]));
        std::os::unix::fs::symlink(
            f.project_config().parent().unwrap(),
            f.checkout().join("link"),
        )
        .unwrap();
        let error = format!("{:#}", f.load().expect_err("indirect self-source"));
        assert!(
            error.contains("only the project config may declare sources"),
            "{error}"
        );
    }

    /// V10 (S3): an untrusted source refuses every authority field by presence,
    /// naming that file.
    #[test]
    fn v10_an_untrusted_source_cannot_grant_authority() {
        for (label, body, pointer) in [
            ("network", "[network]\n", "[network]"),
            (
                "empty network",
                "[network]\nallow_lan = false\n",
                "[network]",
            ),
            ("mounts", "mounts = []\n", "mounts"),
            (
                "mount_sets",
                "[mount_sets]\n",
                "mount_sets cannot be declared",
            ),
            (
                "egress_sets",
                "[egress_sets]\n",
                "egress_sets cannot be declared",
            ),
            (
                "allow_tools",
                "allow_tools = []\n[[tools]]\nname = \"t\"\ncommand = \"t\"\n",
                "allow_tools",
            ),
        ] {
            let f = SourcesFixture::new();
            let repo = f.write_repo(".agent-vm/config.toml", body);
            f.write_project(&sources_block(&[REPO_SOURCE]));
            let error = format!("{:#}", f.load().expect_err(label));
            assert!(
                error.contains("by a source without :trust"),
                "{label}: {error}"
            );
            assert!(
                error.contains(&repo.display().to_string()),
                "{label}: {error}"
            );
            assert!(error.contains(pointer), "{label}: {error}");
        }

        // A sourced tool's `mounts` is *not* authority any more (#735): it is inert
        // data until the project authorizes the tool, so the file loads and the
        // declaration grants nothing.
        let f = SourcesFixture::new();
        f.write_repo(
            ".agent-vm/config.toml",
            &format!(
                "{}{}",
                one_tool("t"),
                "[[tools]]\nname = \"u\"\ncommand = \"u\"\nmounts = []\n"
            ),
        );
        let report = f
            .with_project(&sources_block(&[REPO_SOURCE]))
            .expect("a sourced tool's mounts is inert, not authority");
        assert!(
            report
                .resolved()
                .launch_tools()
                .all(|tool| tool.name() != "u"),
            "an unauthorized sourced tool is not a verb"
        );
    }

    /// V11 (F7, G2): a missing source is an error naming the file and its index, a
    /// FIFO cannot hang the read, and `..` is resolved by the OS rather than
    /// collapsed by the parser.
    #[test]
    fn v11_source_reads_are_bounded_and_paths_are_not_collapsed() {
        let f = SourcesFixture::new();
        let error = format!(
            "{:#}",
            f.with_project(&sources_block(&[HOME_SOURCE, REPO_SOURCE]))
                .expect_err("missing source")
        );
        assert!(
            error.contains("not found; the project config sources it as sources[1]"),
            "{error}"
        );
        assert!(
            error.contains(&f.repo(".agent-vm/config.toml").display().to_string()),
            "{error}"
        );

        // A FIFO, and a symlink to one: the bounded regular read refuses without
        // blocking.
        for symlinked in [false, true] {
            let f = SourcesFixture::new();
            let fifo = f.repo("pipe");
            let c_path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
            let spelled = if symlinked {
                std::os::unix::fs::symlink(&fifo, f.repo("link")).unwrap();
                "./link"
            } else {
                "./pipe"
            };
            let alias = format!("x {spelled}");
            let error = format!(
                "{:#}",
                f.with_project(&sources_block(&[alias.as_str()]))
                    .expect_err("fifo")
            );
            assert!(error.contains("is not a regular file"), "{error}");
        }

        // `link/../target.toml` where `link` is a symlink to a sibling directory:
        // the OS resolves `..` through the link, so the base directory's file is
        // read — not `checkout/target.toml`, which lexical collapse would choose.
        let f = SourcesFixture::new();
        let sibling = f.base().join("sibling");
        fs::create_dir_all(&sibling).unwrap();
        fs::write(f.base().join("target.toml"), one_tool("outside-tool")).unwrap();
        fs::write(f.checkout().join("target.toml"), one_tool("checkout-tool")).unwrap();
        std::os::unix::fs::symlink(&sibling, f.checkout().join("link")).unwrap();
        let report = f
            .with_project(&format!(
                "{}\nallow_tools = [\"link:outside-tool\"]\n",
                sources_block(&["link ./link/../target.toml"])
            ))
            .expect("dot-dot through a symlink");
        assert_eq!(launch_names(&report), ["outside-tool"]);

        // An untrusted source may escape the checkout: declarations only.
        let f = SourcesFixture::new();
        let sibling = f.base().join("sibling");
        fs::create_dir_all(&sibling).unwrap();
        fs::write(
            sibling.join("config.toml"),
            "image = \"localhost:1/sibling:latest\"\n",
        )
        .unwrap();
        let report = f
            .with_project(&sources_block(&["sib ../sibling/config.toml"]))
            .expect("escape");
        assert!(report.images().inert().len() == 1);

        // Directory spellings fail cleanly once read.
        for entry in ["~/", "/", "./"] {
            let f = SourcesFixture::new();
            let alias = format!("dir {entry}");
            let error = format!(
                "{:#}",
                f.with_project(&sources_block(&[alias.as_str()]))
                    .expect_err(entry)
            );
            assert!(error.contains("is not a regular file"), "{entry}: {error}");
        }
    }

    /// V11b (D3): the `:trust` route is verified for both the implicit and the
    /// explicit entry. A checkout alias contributes neither tools, image nor
    /// authority, and the outside-checkout dotfile shapes keep working.
    #[test]
    fn v11b_a_trusted_source_is_verified_by_route_not_spelling() {
        use std::os::unix::fs::symlink;

        // Every shape a hostile checkout file could take, all of which must be
        // refused *before* reading: a UTF-8 error or a FIFO refusal would prove
        // the target was opened.
        for (label, target_body) in [
            ("tools", one_tool("evil")),
            ("image", "image = \"localhost:1/evil:latest\"\n".to_string()),
            ("network", "[network]\nallow_lan = true\n".to_string()),
            ("invalid utf-8", String::new()),
        ] {
            for explicit in [false, true] {
                let f = SourcesFixture::new();
                let target = f.checkout().join("evil.toml");
                fs::create_dir_all(target.parent().unwrap()).unwrap();
                let bytes: &[u8] = if label == "invalid utf-8" {
                    b"[[tools]]\nname = \xff\n"
                } else {
                    target_body.as_bytes()
                };
                fs::write(&target, bytes).unwrap();
                fs::create_dir_all(f.user_config().parent().unwrap()).unwrap();
                symlink(&target, f.user_config()).unwrap();
                let error = if explicit {
                    f.write_project(&sources_block(&[HOME_SOURCE]));
                    format!("{:#}", f.load().expect_err(label))
                } else {
                    format!("{:#}", f.load().expect_err(label))
                };
                assert!(
                    error.contains(
                        "the user config refuses a symbolic link whose target resolves inside the \
                         active project"
                    ),
                    "{label}/{explicit}: {error}"
                );
            }
        }

        // A FIFO target is refused by the route check too, never opened.
        let f = SourcesFixture::new();
        fs::create_dir_all(f.user_config().parent().unwrap()).unwrap();
        // Inside the checkout, so the *route* check must refuse it before the
        // read ever opens the special file.
        let fifo = f.checkout().join("fifo");
        let c_path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        symlink(&fifo, f.user_config()).unwrap();
        let error = format!("{:#}", f.load().expect_err("fifo target"));
        assert!(
            error.contains("resolves inside the active project"),
            "{error}"
        );

        // Parent and ancestor aliases into the checkout.
        for which in ["config-dir", "config-root"] {
            let f = SourcesFixture::new();
            let target = if which == "config-dir" {
                f.checkout().join("evil")
            } else {
                f.checkout().join("cfg")
            };
            let file = target.join("config.toml");
            let file = if which == "config-dir" {
                file
            } else {
                target.join("agent-vm/config.toml")
            };
            fs::create_dir_all(file.parent().unwrap()).unwrap();
            fs::write(&file, "[network]\nallow_lan = true\n").unwrap();
            fs::set_permissions(&file, std::os::unix::fs::PermissionsExt::from_mode(0o600))
                .unwrap();
            let link = if which == "config-dir" {
                f.home().join(".config/agent-vm")
            } else {
                f.home().join(".config")
            };
            fs::create_dir_all(link.parent().unwrap()).unwrap();
            symlink(&target, &link).unwrap();
            let error = format!("{:#}", f.load().expect_err(which));
            assert!(
                error.contains(
                    "the user config refuses a config directory that resolves inside the active \
                     project"
                ),
                "{which}: {error}"
            );
        }

        // Outside-checkout dotfile compatibility: a symlinked file loads tools and
        // image only, and a symlinked directory keeps ADR-0040's authority answer.
        let f = SourcesFixture::new();
        let dotfile = f.home().join("dotfiles/config.toml");
        fs::create_dir_all(dotfile.parent().unwrap()).unwrap();
        fs::write(
            &dotfile,
            format!("image = \"localhost:1/home:latest\"\n{}", one_tool("home")),
        )
        .unwrap();
        fs::create_dir_all(f.user_config().parent().unwrap()).unwrap();
        symlink(&dotfile, f.user_config()).unwrap();
        let report = f.load().expect("dotfile symlink loads");
        // ADR-0040's compatibility rule keeps the *declarations* loadable, and
        // #735 needs `allow_tools` to make one a verb — which is authority, so a
        // symlinked file cannot supply it. The tool is therefore inert.
        assert_eq!(launch_names(&report), Vec::<&str>::new());
        assert_eq!(
            report
                .inert_tools()
                .iter()
                .map(|tool| tool.name().to_string())
                .collect::<Vec<_>>(),
            ["home"]
        );
        assert_eq!(
            image_ref(report.images().user()),
            Some("localhost:1/home:latest")
        );

        let f = SourcesFixture::new();
        let realdir = f.home().join("realcfg");
        fs::create_dir_all(&realdir).unwrap();
        fs::write(realdir.join("config.toml"), "[network]\nallow_lan = true\n").unwrap();
        fs::set_permissions(
            realdir.join("config.toml"),
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        fs::create_dir_all(f.home().join(".config")).unwrap();
        symlink(&realdir, f.home().join(".config/agent-vm")).unwrap();
        let report = f.load().expect("outside-checkout directory symlink");
        assert!(report.user_network().is_some());

        // A dangling link fails closed rather than reading as absent.
        let f = SourcesFixture::new();
        fs::create_dir_all(f.user_config().parent().unwrap()).unwrap();
        symlink(f.home().join("missing.toml"), f.user_config()).unwrap();
        let error = format!("{:#}", f.load().expect_err("dangling"));
        assert!(
            error.contains("resolving the user config symbolic link failed"),
            "{error}"
        );
    }

    /// V11b (continued): from `cwd == $HOME` the normal unaliased layout still
    /// loads while an alias inside the checkout is refused.
    #[test]
    fn v11b_running_from_home_keeps_the_unaliased_layout_only() {
        let f = SourcesFixture::at_home();
        f.write_user(&one_tool("u"));
        let report = f.load().expect("unaliased home layout");
        assert_eq!(launch_names(&report), ["u"]);

        let f = SourcesFixture::at_home();
        let realcfg = f.home().join("realcfg");
        fs::create_dir_all(&realcfg).unwrap();
        fs::write(realcfg.join("config.toml"), one_tool("evil")).unwrap();
        fs::create_dir_all(f.home().join(".config")).unwrap();
        std::os::unix::fs::symlink(&realcfg, f.home().join(".config/agent-vm")).unwrap();
        let error = format!("{:#}", f.load().expect_err("aliased dir at home"));
        assert!(
            error.contains("resolves inside the active project"),
            "{error}"
        );

        let f = SourcesFixture::at_home();
        let target = f.home().join("real.toml");
        fs::write(&target, one_tool("evil")).unwrap();
        fs::create_dir_all(f.user_config().parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&target, f.user_config()).unwrap();
        let error = format!("{:#}", f.load().expect_err("aliased file at home"));
        assert!(
            error.contains("resolves inside the active project"),
            "{error}"
        );
    }

    /// V12: the project config authorizes; the `:trust` image is the fallback, and
    /// an untrusted source's unselected image is inert and never consulted.
    #[test]
    fn v12_image_declaration_and_authorization_are_distinct() {
        // Direct project image wins; the trusted image stays readable.
        let f = SourcesFixture::new();
        f.write_user("image = \"localhost:1/u:latest\"\n");
        let report = f
            .with_project(&format!(
                "image = \"localhost:1/p:latest\"\n{}",
                sources_block(&[HOME_SOURCE])
            ))
            .expect("direct");
        assert_eq!(
            image_ref(report.images().project()),
            Some("localhost:1/p:latest")
        );
        assert_eq!(report.images().project().unwrap().via(), None);
        assert_eq!(
            image_ref(report.images().user()),
            Some("localhost:1/u:latest")
        );
        assert!(report.images().inert().is_empty());

        // `ALIAS:image` resolves to that source's own image and names its file.
        let f = SourcesFixture::new();
        f.write_user("image = \"localhost:1/u:latest\"\n");
        let repo = f.write_repo(
            ".agent-vm/config.toml",
            "image = \"localhost:1/repo:latest\"\n",
        );
        let team = f.write_repo("team.toml", "image = \"localhost:1/team:latest\"\n");
        let report = f
            .with_project(&format!(
                "image = \"repo:image\"\n{}",
                sources_block(&[HOME_SOURCE, REPO_SOURCE, "team ./team.toml"])
            ))
            .expect("alias selection");
        let project = report.images().project().expect("selected");
        assert_eq!(project.reference().as_str(), "localhost:1/repo:latest");
        assert_eq!(project.file(), repo.as_path());
        assert_eq!(project.via().map(|alias| alias.as_str()), Some("repo"));
        let inert: Vec<(&str, &Path)> = report
            .images()
            .inert()
            .iter()
            .map(|inert| (inert.alias().as_str(), inert.image().file()))
            .collect();
        assert_eq!(inert, [("team", team.as_path())]);

        // With no project image, the trusted image is the fallback and the
        // untrusted image is inert.
        let f = SourcesFixture::new();
        f.write_user("image = \"localhost:1/u:latest\"\n");
        f.write_repo(
            ".agent-vm/config.toml",
            "image = \"localhost:1/repo:latest\"\n",
        );
        let report = f
            .with_project(&sources_block(&[HOME_SOURCE, REPO_SOURCE]))
            .expect("fallback");
        assert_eq!(report.images().project(), None);
        assert_eq!(
            image_ref(report.images().user()),
            Some("localhost:1/u:latest")
        );
        assert_eq!(report.images().inert().len(), 1);
        assert_eq!(
            report.images().inert()[0].image().reference().as_str(),
            "localhost:1/repo:latest"
        );

        // A non-`home` trusted alias is still the fallback, and is selectable.
        let f = SourcesFixture::new();
        f.write_user("image = \"localhost:1/u:latest\"\n");
        let report = f
            .with_project(&format!(
                "image = \"me:image\"\n{}",
                sources_block(&["me:trust ~/.config/agent-vm/config.toml"])
            ))
            .expect("me:image");
        assert_eq!(
            image_ref(report.images().project()),
            Some("localhost:1/u:latest")
        );
        assert_eq!(
            report.images().project().unwrap().via().map(|a| a.as_str()),
            Some("me")
        );
    }

    /// V13: an undeclared alias is a load error (no OCI fallback), and a declared
    /// source without an image says which.
    #[test]
    fn v13_an_undeclared_alias_is_an_error_not_an_oci_reference() {
        let f = SourcesFixture::new();
        let error = format!(
            "{:#}",
            f.with_project(&format!(
                "image = \"rpeo:image\"\n{}",
                sources_block(&[HOME_SOURCE])
            ))
            .expect_err("undeclared alias")
        );
        assert!(
            error.contains("names a source alias that sources does not declare"),
            "{error}"
        );
        assert!(
            !error.contains("rpeo"),
            "the alias must not be echoed: {error}"
        );

        let f = SourcesFixture::new();
        f.write_repo(".agent-vm/config.toml", &one_tool("r"));
        let error = format!(
            "{:#}",
            f.with_project(&format!(
                "image = \"repo:image\"\n{}",
                sources_block(&[REPO_SOURCE])
            ))
            .expect_err("no image")
        );
        assert!(error.contains("but that file declares no image"), "{error}");

        let f = SourcesFixture::new();
        let error = format!(
            "{:#}",
            f.with_project(&format!(
                "image = \"home:image\"\n{}",
                sources_block(&[HOME_SOURCE])
            ))
            .expect_err("absent file")
        );
        assert!(error.contains("but that file does not exist"), "{error}");

        // The implicit alias is declared too.
        let f = SourcesFixture::new();
        f.write_user("image = \"localhost:1/u:latest\"\n");
        let report = f
            .with_project("image = \"home:image\"\n")
            .expect("implicit alias selection");
        assert_eq!(
            image_ref(report.images().project()),
            Some("localhost:1/u:latest")
        );
    }

    /// V14 (R8), restated for #735: a name two project-side files declare is
    /// **inert** while neither is authorized — a declaration is data — and a hard
    /// error the moment both are, because the verb `x` would have two project-side
    /// definitions and no rule picks one.
    #[test]
    fn v14_a_project_side_tool_collision_is_an_error_once_authorized() {
        let f = SourcesFixture::new();
        let repo = f.write_repo(".agent-vm/config.toml", &one_tool("x"));
        let report = f
            .with_project(&format!(
                "# no allow_tools\n{}{}",
                sources_block(&[REPO_SOURCE]),
                one_tool("x")
            ))
            .expect("an inert project-side collision loads");
        assert!(report.conflicts().is_empty());
        assert_eq!(
            report
                .inert_tools()
                .iter()
                .map(|tool| tool.name().to_string())
                .collect::<Vec<_>>(),
            ["x", "x"],
            "both declarations are inert"
        );

        let error = format!(
            "{:#}",
            f.with_project(&format!(
                "allow_tools = [\"x\", \"repo:x\"]\n{}{}",
                sources_block(&[REPO_SOURCE]),
                one_tool("x")
            ))
            .expect_err("collision")
        );
        // The sentence names the verb and the file that already claims it; the
        // second declaration is the one being refused, so its path is the one the
        // reader is looking at.
        assert!(error.contains("authorizes a second tool named"), "{error}");
        assert!(
            error.contains(&f.project_config().display().to_string()),
            "{error}"
        );
        assert!(error.contains("project config"), "{error}");
        let _ = &repo;

        let f = SourcesFixture::new();
        f.write_repo("a.toml", &one_tool("x"));
        f.write_repo("b.toml", &one_tool("x"));
        let error = format!(
            "{:#}",
            f.with_project(&format!(
                "allow_tools = [\"a:x\", \"b:x\"]\n{}",
                sources_block(&["a ./a.toml", "b ./b.toml"])
            ))
            .expect_err("two sources")
        );
        assert!(error.contains("authorizes a second tool named"), "{error}");
        assert!(error.contains("source a"), "{error}");
    }

    /// V15 (R1): `sources` is a reserved set name in both set tables, so a
    /// top-level key written after the header is named rather than misparsed.
    #[test]
    fn v15_sources_is_reserved_in_both_set_tables() {
        for (table, sentence) in [
            ("mount_sets", "is not a mount set"),
            ("egress_sets", "is not an egress set"),
        ] {
            let f = Fixture::new();
            f.user(&format!("[{table}]\nsources = []\n"));
            let error = format!("{:#}", f.load().expect_err(table));
            assert!(error.contains(sentence), "{table}: {error}");
            assert!(error.contains("sources is not"), "{table}: {error}");
        }
    }

    /// The two other tables a top-level key can be written into: as a network key
    /// it is an unknown setting, as a tool field it fails the schema, and neither
    /// sentence says the line belongs above the first header. Both tiers are checked
    /// because both read through the same decoder, and the project tier is the one
    /// where `sources` is otherwise a legal key. `allow_tools` (#735) is the second
    /// order-sensitive key: written after a header it authorizes nothing, which the
    /// generic schema sentence never said.
    #[test]
    fn a_table_header_cannot_swallow_an_order_sensitive_top_level_key() {
        for (body, diagnostic) in [
            (
                "[network]\nallow_lan = true\nsources = [\"repo ./x.toml\"]\n",
                "[network]: sources is not a network setting; a top-level sources must be \
                 written before the first table header (keys after [network] belong to it)",
            ),
            (
                "[[tools]]\nname = \"t\"\ncommand = \"/bin/true\"\nsources = [\"repo ./x.toml\"]\n",
                "tools[0]: sources is not a tool field; a top-level sources must be written \
                 before the first table header (keys after [[tools]] belong to the last tool)",
            ),
            (
                "[network]\nallow_lan = true\nallow_tools = [\"t\"]\n",
                "[network]: allow_tools is not a network setting; a top-level allow_tools must be \
                 written before the first table header (keys after [network] belong to it)",
            ),
            (
                "[[tools]]\nname = \"t\"\ncommand = \"/bin/true\"\nallow_tools = [\"t\"]\n",
                "tools[0]: allow_tools is not a tool field; a top-level allow_tools must be \
                 written before the first table header (keys after [[tools]] belong to the last \
                 tool)",
            ),
        ] {
            let f = Fixture::new();
            let error = f.user(body).load().unwrap_err().to_string();
            assert_eq!(error, format!("config: {:?}: {diagnostic}", f.user));

            let f = SourcesFixture::new();
            let error = f.with_project(body).unwrap_err().to_string();
            assert_eq!(
                error,
                format!("config: {:?}: {diagnostic}", f.project_config())
            );
        }
    }
}
