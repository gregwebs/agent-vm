//! Read-only **tool configuration**: discovery, strict parsing, validation,
//! and the ordered catalog merge that `agent-vm doctor` previews.
//!
//! A **tool declaration** (`[[tools]]` in a config file) is *data*: a guest
//! command, its default argv, the credential providers it needs, extra
//! guest-HOME-relative paths to persist, guest env pairs, network requests, and
//! the **pane agent hint** a host multiplexer labels the launch with. Requests
//! never grant network access, and the hint is host-only metadata: it never
//! reaches the guest. This module
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
//! # Sources (ADR-0076)
//!
//! The project config may declare an array of `[[sources]]` tables, each with a
//! required `name` and `path` and optional `trust` (default `false`) and `allow`
//! (default `false`). An omitted key means the single implicit
//! `{ name = "home", path = "~/.config/agent-vm/config.toml", trust = true,
//! allow = true }`; an explicit list — `[]` included — replaces it. The old
//! `sources = ["<alias>[:trust] <path>"]` string syntax is rejected with a
//! migration error (a deliberate breaking change).
//!
//! Sourcing is flat (only the project config may declare `sources`). `trust` and
//! `allow` are independent: `trust` means the file's route is host-controlled and
//! its read is ADR-0040-verified, so #736's content-hash pinning does not apply;
//! `allow` means the file's top-level `image`, `mounts`, `[network]` and
//! `[[tools]]` declarations are launch verbs, and the declaration itself is
//! the authority (`#749`). A non-default `trust = true`
//! route is refused by [`crate::project_config`] the moment it enters the
//! checkout, and its read is descriptor-anchored. [`crate::config_sources`] owns
//! the grammar and path resolution; [`crate::boot_image`] owns how a declared
//! image becomes the boot image.
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

use crate::config_authority::{self, AuthorityTriggers, ContentApprovalPolicy as _};
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
pub(crate) const MAX_CONFIG_FILE_BYTES: u64 = 1024 * 1024;

/// Ceiling on the bytes one load reads from **all** its declared sources
/// together.
///
/// [`MAX_CONFIG_FILE_BYTES`] bounds one source and
/// [`crate::config_sources`]'s count bound bounds how many there are, so a list of
/// individually legal files could still cost tens of megabytes of TOML parsing on
/// every launch. Four full-size files' worth is far above any real configuration
/// (a source file is a few KiB) and is charged *before* the bytes are parsed, so
/// many individually small files cannot add up to unbounded parse work either.
pub(crate) const MAX_SOURCE_BYTES_TOTAL: u64 = 4 * 1024 * 1024;

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
                        root_id: project.identity(),
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
    /// The load's **one** leaf-visit counter, from `read_project_tier` through
    /// every source read and into the single catalog build (#735, D6).
    mount_work: config_mounts::MountExpansionWork,
    /// The pin store state this load read, `Some` only when a `trust = false`
    /// source made it read one. R12: the launch's best-effort active-baseline
    /// recording observes **this** generation, never a fresh one taken after the
    /// parse, so a reset in between is a no-op rather than a write into a store
    /// the launch never read.
    pins: Option<crate::config_pins::store::ObservedStore>,
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

    /// Every `trust = true` source this load read, so the ADR-0038 guest-write
    /// guard can refuse a writable bind over one or over a directory along its
    /// route (ADR-0076 R2.4).
    ///
    /// The default `~/.config/agent-vm/config.toml` is included; the guard skips
    /// paths already covered by the authority store's own measurement.
    pub(crate) fn trusted_source_files(&self) -> Vec<PathBuf> {
        self.sources
            .entries()
            .iter()
            .filter(|entry| entry.attributes().trust)
            .filter_map(|entry| entry.tier().path().map(Path::to_path_buf))
            .collect()
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

    /// The store observation this load made, if it read the pin store at all.
    /// The recording path carries it to the store's generation fence (R12).
    pub(crate) fn pins_observed(&self) -> Option<crate::config_pins::store::ObservedStore> {
        self.pins
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
    mut tools: ResolvedTools,
    work: &mut config_mounts::MountExpansionWork,
) -> Result<LaunchCatalog> {
    let name_conflicts = std::mem::take(&mut tools.conflicts);
    // Suppression follows **launch slots**, never names: the fallback is added
    // unless some retained definition actually claimed the bare `shell` route,
    // which only a project entry (or the shipped catalog itself) can do (E3/F6).
    // A user or sourced `shell` reachable as `home:shell`/`repo:shell` therefore
    // cannot delete the fallback, and two colliding sourced shells leave the
    // bare route to it.
    let shell_fallback_added = !tools
        .names
        .iter()
        .any(|slot| slot.bare.as_deref() == Some(SHELL_TOOL_NAME));
    let (mut entries, defaults, direct) = resolve_provisioning(tools, work)?;
    let declared_len = entries.len();
    if shell_fallback_added {
        // The fallback scope holds only the shipped `shell`, which cannot carry
        // mounts, so it contributes no candidate — but it shares the same
        // continued budget rather than getting one of its own.
        let (fallback, _, _) =
            resolve_provisioning(ResolvedTools::from_defaults(vec![builtin_shell()?]), work)?;
        entries.extend(fallback);
    }
    // The affordance receives the effective closure; every other entry keeps its
    // own. Selected by route (`is_shell_affordance`), so a uniquely named sourced
    // `shell` cannot take it over (F6/E12).
    if let Some(index) = entries.iter().position(CatalogEntry::is_shell_affordance) {
        entries[index].carry_defaults(&defaults, work)?;
    }
    Ok(LaunchCatalog {
        entries,
        name_conflicts,
        declared_len,
        direct,
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
#[allow(clippy::large_enum_variant)] // one per process, built once; boxing would add a second
// indirection to every dispatch arm's match
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
    /// Bare names two or more sources declare, with no project definition to
    /// settle them (#749). Not an error: each candidate keeps its qualified
    /// verb, and only the bare spelling is refused — naming both candidates and
    /// their qualified spellings.
    name_conflicts: Vec<NameConflict>,
    /// How many leading entries are declarations *right now*: the prefix
    /// describes the catalog's current contents, not a historical record. When
    /// dispatch removes one through [`Self::take_entry`], the prefix shrinks
    /// with it, so it always states what is still declared. The synthesized
    /// `shell` fallback, when present, is the single entry after this prefix.
    /// `cli` and `doctor` render all of `entries` ([`Self::as_slice`]); `setup`
    /// verifies only the declarations ([`Self::declarations`]), because the
    /// fallback "is not a declaration".
    declared_len: usize,
    /// The **authored** `default_tools` closure (#749 E5): what a direct command
    /// receives, and nothing when no file wrote the key. The shell affordance's
    /// copy is already folded into its entry.
    direct: DefaultFacets,
}

/// The effective `default_tools` closure as one grant (#749).
///
/// One value for both consumers of the same fold — the shell affordance's entry
/// and a direct command's grant — so the two cannot disagree about a facet.
#[derive(Debug)]
pub(crate) struct DefaultFacets {
    provisioned: ProviderSet,
    requested_names: BTreeSet<ServiceName>,
    persist: Vec<PersistPath>,
    mounts: ResolvedMountList,
    guest_env: BTreeMap<String, String>,
    network_requests: NetworkRequests,
    /// The resolved tool names, in contribution order: what `doctor` reports.
    names: Vec<String>,
    /// True when at least one contributor is a declared tool, so its requests are
    /// authority rather than report metadata.
    authored_egress: bool,
    /// The measured verdict of the read that declared a contributor, when that
    /// read failed without refusing the load (#749 E8). The shell affordance
    /// carries it, so a grant from blocked bytes refuses the launch instead of
    /// silently shrinking.
    refusal: Option<crate::config_authority::ReferenceTrust>,
}

impl DefaultFacets {
    fn empty() -> Self {
        Self {
            provisioned: ProviderSet::default(),
            requested_names: BTreeSet::new(),
            persist: Vec::new(),
            mounts: ResolvedMountList::empty(),
            guest_env: BTreeMap::new(),
            network_requests: NetworkRequests::default(),
            names: Vec::new(),
            authored_egress: false,
            refusal: None,
        }
    }

    pub(crate) fn provisioned(&self) -> ProviderSet {
        self.provisioned
    }

    /// Every named YAML service this grant's closure requests (#749 E5/E6).
    pub(crate) fn requested_names(&self) -> &BTreeSet<ServiceName> {
        &self.requested_names
    }

    pub(crate) fn persist(&self) -> &[PersistPath] {
        &self.persist
    }

    pub(crate) fn mounts(&self) -> &ResolvedMountList {
        &self.mounts
    }

    pub(crate) fn guest_env(&self) -> &BTreeMap<String, String> {
        &self.guest_env
    }

    pub(crate) fn network_requests(&self) -> &NetworkRequests {
        &self.network_requests
    }

    pub(crate) fn names(&self) -> &[String] {
        &self.names
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// The measured verdict of a read that declared one of this grant's
    /// contributors and failed without refusing the load (#749 E8/E10). Every
    /// consumer that builds a launch from this grant requires it first, so a
    /// blocked contributor refuses both the shell and the direct route.
    pub(crate) fn refusal(&self) -> Option<&crate::config_authority::ReferenceTrust> {
        self.refusal.as_ref()
    }
}

/// One launch-catalog entry: a tool plus the provisioning set resolved for it.
/// The set is computed once, here, because every consumer (launch, the proxy,
/// the guest env, `doctor`) must agree on it exactly.
#[derive(Debug)]
pub(crate) struct CatalogEntry {
    tool: Tool,
    /// The bare `<name>` spelling, `Some` when this definition wins the name:
    /// every project definition, every user definition, and a sourced one no
    /// other file shadows.
    bare_label: Option<String>,
    /// The `<alias>:<name>` spelling a sourced definition is always reachable
    /// by (`home` for the default user config). `None` for a built-in.
    qualified_label: Option<String>,
    /// The measured verdict of the default user config that declared this
    /// definition, when that read may have failed without refusing the load.
    launch_trust: Option<crate::config_authority::ReferenceTrust>,
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
    /// True iff a configuration file declared this entry: the one condition
    /// under which its own `network_requests` are granted as egress on launch
    /// (#735 R5, now #749: the declaration is the authority). False for the
    /// compiled-in defaults and for the synthesized `shell` fallback, whose
    /// build-in metadata stays report-only and which keep ADR-0036 default-deny.
    authorized_egress: bool,
    /// This launch's guest environment: the launched tool's own, then each
    /// effective `default_tools` contributor's, own first. Equal to the tool's
    /// own for every entry but the shell affordance (#749).
    guest_env: BTreeMap<String, String>,
    /// The same fold for `network_requests`: the launched tool's own, then each
    /// *declared* default contributor's. A built-in contributor's requests stay
    /// report-only, so the shipped list grants no egress request on its own
    /// (#749 E5).
    network_requests: NetworkRequests,
}

impl CatalogEntry {
    pub(crate) fn tool(&self) -> &Tool {
        &self.tool
    }

    /// This launch's guest environment, folded over the effective `default_tools`
    /// closure (#749).
    pub(crate) fn guest_env(&self) -> &BTreeMap<String, String> {
        &self.guest_env
    }

    /// The `network_requests` this launch grants, folded over the same closure.
    pub(crate) fn network_requests(&self) -> &NetworkRequests {
        &self.network_requests
    }

    /// Whether this entry is the **shell affordance** (#749 F6): the bare `shell`
    /// verb a non-source file supplies, or the shipped fallback. Route, never
    /// name: a uniquely named sourced `shell` is reachable only as
    /// `<alias>:shell` and does not take the affordance over.
    ///
    /// `pub(crate)` for the launcher's pane-hint decision: a bare `shell` declares
    /// a shell, not an agent, so a hint on it is report-only (A5).
    pub(crate) fn is_shell_affordance(&self) -> bool {
        self.bare_label.as_deref() == Some(SHELL_TOOL_NAME)
            && !matches!(self.tool.origin(), ToolOrigin::Source { .. })
    }

    /// Give the shell affordance the effective `default_tools` closure: every
    /// facet, with the entry's own value winning where the two meet.
    fn carry_defaults(
        &mut self,
        defaults: &DefaultFacets,
        work: &mut config_mounts::MountExpansionWork,
    ) -> Result<()> {
        self.provisioned = self.provisioned.union(defaults.provisioned);
        self.requested_names
            .extend(defaults.requested_names.iter().cloned());
        for path in &defaults.persist {
            if !self.persist.contains(path) {
                self.persist.push(path.clone());
            }
        }
        self.mounts = config_mounts::merge_tool_mounts([&self.mounts, &defaults.mounts], work)
            .map_err(|error| {
                tool_error(
                    &self.tool.origin,
                    self.tool.declaration_index,
                    &self.tool.name,
                    error,
                )
            })?;
        for (key, value) in &defaults.guest_env {
            self.guest_env
                .entry(key.clone())
                .or_insert_with(|| value.clone());
        }
        self.network_requests = self.network_requests.union(&defaults.network_requests);
        // A declared contributor's requests are authority, so a shell launch
        // grants them; the shipped list alone never does (E5).
        self.authorized_egress |= defaults.authored_egress;
        // The grant is only as trustworthy as the read that declared each of its
        // contributors: a blocked one refuses this launch with its own verdict,
        // rather than making the grant quietly smaller (E8/E10). The entry's own
        // failing verdict wins, because it names the file being launched from.
        let own_refused = self
            .launch_trust
            .as_ref()
            .is_some_and(|trust| trust.require_for_trusted_tool().is_err());
        if !own_refused && let Some(trust) = defaults.refusal.clone() {
            self.launch_trust = Some(trust);
        }
        Ok(())
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

    /// Whether a configuration file declares this entry, which is what makes its
    /// own `network_requests` authoritative egress (#735/#749).
    pub(crate) fn is_authorized_egress(&self) -> bool {
        self.authorized_egress
    }

    /// The verdict that must pass before this entry may launch, when its file's
    /// read is one that may fail while the file still loads (#749, E8).
    pub(crate) fn launch_trust(&self) -> Option<&crate::config_authority::ReferenceTrust> {
        self.launch_trust.as_ref()
    }

    /// The spelling this entry is launched by: the bare name when it wins one,
    /// else the qualified `<alias>:<name>` of the source that declares it.
    pub(crate) fn label(&self) -> &str {
        self.bare_label
            .as_deref()
            .or(self.qualified_label.as_deref())
            .expect("every catalog entry carries a launch spelling")
    }

    /// The `<alias>:<name>` spelling, for a sourced definition only.
    pub(crate) fn qualified_label(&self) -> Option<&str> {
        self.qualified_label.as_deref()
    }

    /// Whether `verb` names this entry: its bare spelling or its qualified one.
    pub(crate) fn is_launched_as(&self, verb: &str) -> bool {
        self.bare_label.as_deref() == Some(verb) || self.qualified_label.as_deref() == Some(verb)
    }
}

/// One bare name two or more files declare, and the qualified spellings that
/// still reach each of them (#749).
///
/// Built once, where every definition is labelled, and rendered unchanged by the
/// CLI refusal and `doctor`'s note — so the two cannot name different
/// candidates.
#[derive(Debug)]
pub(crate) struct NameConflict {
    name: String,
    /// The project config whose sources collide, when there is one: the file the
    /// reader must edit.
    file: Option<PathBuf>,
    /// `(qualified spelling, declaring origin)` in arena order.
    candidates: Vec<(String, ToolOrigin)>,
}

impl NameConflict {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// The refusal for a bare verb this name cannot settle: every candidate is
    /// named with the spelling that reaches it, and no file is re-read.
    pub(crate) fn refusal(&self) -> anyhow::Error {
        let origins: Vec<String> = self
            .candidates
            .iter()
            .map(|(_, origin)| describe_origin(origin))
            .collect();
        let spellings: Vec<String> = self
            .candidates
            .iter()
            .map(|(spelling, _)| quoted_str(spelling))
            .collect();
        let what = match self.file.as_deref() {
            Some(file) => format!("config: {}: ", crate::one_line::quoted_path(file)),
            None => "config: ".to_owned(),
        };
        anyhow!(
            "{what}{} is declared by {}; launch one as {}, or rename one definition",
            quoted_str(&self.name),
            join_clauses(&origins, "and"),
            join_clauses(&spellings, "or"),
        )
    }
}

/// `a`, `a and b`, `a, b and c` — the list grammar the refusal and `doctor` share.
fn join_clauses(items: &[String], conjunction: &str) -> String {
    match items.split_last() {
        None => String::new(),
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} {conjunction} {last}", rest.join(", ")),
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

    /// The **authored** `default_tools` closure (#749 E5): what a direct command
    /// receives, empty when no file wrote the key.
    pub(crate) fn direct_defaults(&self) -> &DefaultFacets {
        &self.direct
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
            .position(|entry| entry.is_launched_as(name))?;
        // Keep the prefix describing the catalog's *current* contents: a
        // removed declaration is no longer declared, so the prefix shrinks with
        // it. Removing the `shell` fallback (the entry at `declared_len`) leaves
        // the prefix — and every declaration in it — alone.
        if index < self.declared_len {
            self.declared_len -= 1;
        }
        Some(self.entries.remove(index))
    }

    /// The bare name an approval review and `doctor` must report as refused, if
    /// the catalog has one.
    pub(crate) fn name_conflict(&self, name: &str) -> Option<&NameConflict> {
        self.name_conflicts
            .iter()
            .find(|conflict| conflict.name == name)
    }

    /// Every bare name more than one source declares, in declaration order.
    pub(crate) fn name_conflicts(&self) -> &[NameConflict] {
        &self.name_conflicts
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

/// Every retained tool definition, each one a launch verb (#749).
///
/// Declaring a `[[tools]]` block *is* the authorization now, so there is no
/// loser arena to retain: every definition supplies its own file's `tools`
/// references and is reachable by a verb. No mutator exists, and every
/// constructor lives here.
#[derive(Debug)]
pub(crate) struct ResolvedTools {
    /// Complete user declarations, then complete project declarations, then each
    /// source's declarations in `sources` order; on the defaults path, the
    /// shipped definitions.
    definitions: Vec<Tool>,
    /// One launch spelling per definition, indexed by arena position.
    names: Vec<LaunchSlot>,
    /// Bare names two or more files declare, in arena order.
    conflicts: Vec<NameConflict>,
    /// True when the compiled-in catalog supplied the definitions: `doctor`
    /// renders its own `resolved:` label for that state.
    uses_defaults: bool,
    /// The effective `default_tools`, resolved to arena positions where every
    /// definition is known (#749).
    defaults: DefaultRoots,
}

/// The effective `default_tools` as arena positions (#749).
#[derive(Debug, Default)]
struct DefaultRoots {
    /// The shipped compatibility list (only when the compiled-in catalog
    /// applies) plus every authored contribution, deduplicated in contribution
    /// order.
    all: Vec<DefinitionId>,
    /// The authored contributions alone: what a direct command receives (E5).
    authored: Vec<DefinitionId>,
    /// True when at least one readable config wrote `default_tools` — including
    /// an explicit empty list, which is an empty contribution, not a veto.
    authored_present: bool,
}

/// One definition's launch facts: the spellings that reach it, and the verdict
/// of the read that declared it when that read may fail without refusing the
/// load (#749).
#[derive(Debug, Clone, Default)]
struct LaunchSlot {
    /// `Some` when this definition wins its bare name: a project definition, a
    /// user definition, or the only definition of that name.
    bare: Option<String>,
    /// `<alias>:<name>` for a sourced definition; `None` for a project or
    /// built-in one, which no source alias names.
    qualified: Option<String>,
    /// The default user config's measured verdict, carried to the launch so a
    /// tools-only file that failed ADR-0040 keeps loading while its tools are
    /// refused (`ReferenceTrust::require_for_trusted_tool`). Every other tier is
    /// verified or approved before it is read at all.
    trust: Option<crate::config_authority::ReferenceTrust>,
}

impl ResolvedTools {
    /// Every definition, in arena order: each is a launch verb (#749), so this is
    /// the whole catalog a test can compare a paste against.
    #[cfg(test)]
    pub(crate) fn launch_tools(&self) -> impl ExactSizeIterator<Item = &Tool> + '_ {
        self.definitions.iter()
    }

    /// Every definition's launch label, in arena order: the bare name when it
    /// wins one, else the qualified spelling (#749).
    #[cfg(test)]
    pub(crate) fn labels(&self) -> impl ExactSizeIterator<Item = &str> + '_ {
        self.names.iter().map(|slot| {
            slot.bare
                .as_deref()
                .or(slot.qualified.as_deref())
                .unwrap_or_default()
        })
    }

    /// The compiled-in catalog (or the singleton `shell` fallback scope): every
    /// definition a launch verb, under its bare name only.
    fn from_defaults(tools: Vec<Tool>) -> Self {
        let names = tools
            .iter()
            .map(|tool| LaunchSlot {
                bare: Some(tool.name().to_owned()),
                qualified: None,
                trust: None,
            })
            .collect();
        // E5: the shipped list is the shell's own compatibility grant. It is
        // every shipped definition but the shell itself, and it is never part of
        // an authored contribution — so a direct command never receives it. The
        // singleton fallback scope holds only `shell`, whose selection is a
        // definition *and* the affordance, so nothing is granted there.
        let defaults = tools
            .iter()
            .enumerate()
            .filter(|(_, tool)| tool.name() != SHELL_TOOL_NAME)
            .map(|(position, _)| DefinitionId(position))
            .collect();
        Self {
            definitions: tools,
            names,
            conflicts: Vec::new(),
            uses_defaults: true,
            defaults: DefaultRoots {
                all: defaults,
                authored: Vec::new(),
                authored_present: false,
            },
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

/// Which top-level adoptable keys were declared by an `allow = false` source
/// and therefore ignored as inert (ADR-0076 R3). Value-free: only presence
/// booleans, so a refusal or a `doctor` row can never echo config bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct InertDeclarations {
    pub(crate) image: bool,
    pub(crate) mounts: bool,
    pub(crate) network: bool,
}

impl InertDeclarations {
    pub(crate) fn is_empty(self) -> bool {
        !(self.image || self.mounts || self.network)
    }

    /// Canonical display order for `doctor`.
    pub(crate) fn labels(self) -> Vec<&'static str> {
        [
            (self.image, "image"),
            (self.mounts, "mounts"),
            (self.network, "[network]"),
        ]
        .into_iter()
        .filter_map(|(present, label)| present.then_some(label))
        .collect()
    }

    pub(crate) fn with_image(mut self, image: bool) -> Self {
        self.image = image;
        self
    }
}

/// One source and what reading it produced. The tier is the same report shape the
/// user tier uses, so `doctor` renders a source row with one renderer.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SourceReport {
    alias: crate::config_sources::SourceAlias,
    attributes: crate::config_sources::SourceAttributes,
    tier: TierReport,
    inert: InertDeclarations,
    /// `Some` only for a `trust = false` source whose exact bytes a pin lookup
    /// approved. Never set for `trust = true`, whose authority is its route.
    pin: Option<crate::config_pins::SourcePin>,
}

impl SourceReport {
    pub(crate) fn alias(&self) -> &crate::config_sources::SourceAlias {
        &self.alias
    }

    /// The approved content pin, for a `trust = false` source; `None` for a
    /// trusted one, which is not pinned at all.
    pub(crate) fn pin(&self) -> Option<&crate::config_pins::SourcePin> {
        self.pin.as_ref()
    }

    pub(crate) fn inert(&self) -> InertDeclarations {
        self.inert
    }

    pub(crate) fn attributes(&self) -> crate::config_sources::SourceAttributes {
        self.attributes
    }

    pub(crate) fn is_trusted(&self) -> bool {
        self.attributes.trust
    }

    pub(crate) fn is_allowed(&self) -> bool {
        self.attributes.allow
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
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum ToolOrigin {
    BuiltIn,
    User(PathBuf),
    Project(PathBuf),
    /// A file the project config sources without `trust = true` (ADR-0076): its
    /// own reference scope, and the alias #735 qualifies tools with.
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
    tools: Vec<ToolName>,
    persist: Vec<PersistPath>,
    interactive_shell: bool,
    /// This tool's own guest env, key-sorted. Keys are validated at
    /// construction ([`validate_env`]); values are arbitrary and may be
    /// secrets, so the field is private and `doctor` only ever sees
    /// [`Self::env_count`] — the same rule as `argv`.
    env: BTreeMap<String, String>,
    /// Declaration only: never authority and not folded over provisioning.
    network_requests: NetworkRequests,
    /// The agent kind the host's terminal multiplexer should label this
    /// launch's pane with ([`PaneAgentHint`]). Host-only: it labels the
    /// launcher's view of a launch and never enters the guest environment, and
    /// it is not folded over provisioning like `env`.
    herdr_agent: Option<PaneAgentHint>,
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
    pub(crate) fn declared_tools(&self) -> &[ToolName] {
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

    /// This definition's own pane agent hint, if it declares one. Sibling
    /// consumers ([`crate::doctor`], the launcher's re-exec) read it here rather
    /// than from a folded closure: the hint labels **this** tool's launch only.
    pub(crate) fn herdr_agent(&self) -> Option<&PaneAgentHint> {
        self.herdr_agent.as_ref()
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
            && self.herdr_agent == other.herdr_agent
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
        // Appended after `mounts` for the same reason as every field above: the
        // existing differing-field sequences keep their order.
        if self.herdr_agent != other.herdr_agent {
            fields.push(ToolField::HerdrAgent);
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
    /// The validated constructor for a launch verb's name: `None` for a name
    /// [`tool_name_rejection`] refuses.
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

/// A launch verb: a bare tool name, or `<alias>:<name>` (#749).
///
/// Parsing is one place so the CLI, the pin preflight and a bare-name conflict
/// judge the same spellings. `:` cannot appear in a tool name
/// ([`tool_name_rejection`]), so a colon is unambiguously the alias separator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LaunchVerb {
    /// A declaration in the project config, the default home config, or the one
    /// source that declares the name.
    Bare(ToolName),
    /// The tool `name` declared by the source bound to `alias`.
    Qualified {
        alias: crate::config_sources::SourceAlias,
        name: ToolName,
    },
}

impl LaunchVerb {
    /// `None` for a spelling no declaration could match: a reserved or malformed
    /// bare name, an invalid alias, or a second `:`.
    pub(crate) fn parse(raw: &str) -> Option<Self> {
        let Some((alias, name)) = raw.split_once(':') else {
            return ToolName::parse(raw).map(Self::Bare);
        };
        Some(Self::Qualified {
            alias: crate::config_sources::SourceAlias::parse(alias)?,
            name: ToolName::parse(name)?,
        })
    }

    pub(crate) fn alias(&self) -> Option<&crate::config_sources::SourceAlias> {
        match self {
            Self::Bare(_) => None,
            Self::Qualified { alias, .. } => Some(alias),
        }
    }
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

/// The source that supplied the fallback boot image (ADR-0076 R4.1): the first
/// `allow = true` source in `[[sources]]` order that declares `image`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FallbackImage {
    alias: crate::config_sources::SourceAlias,
    image: ConfiguredImage,
    /// `true` only for `~/.config/agent-vm/config.toml`, whose selection keeps
    /// its pre-#748 `ImageSource::UserConfig` provenance and `user:` row.
    is_default_user_config: bool,
}

impl FallbackImage {
    pub(crate) fn alias(&self) -> &crate::config_sources::SourceAlias {
        &self.alias
    }

    pub(crate) fn image(&self) -> &ConfiguredImage {
        &self.image
    }

    pub(crate) fn is_default_user_config(&self) -> bool {
        self.is_default_user_config
    }
}

/// What one source's declared `image` did in the precedence chain (ADR-0076
/// R5.2): it won the fallback, or lost it to one of three outranking choices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SourceImageStatus {
    /// Winning fallback: `allow = true`, first in `[[sources]]` order, and the
    /// project config set no `image`.
    SelectedFallback,
    /// `allow = true`, overridden by the project config's own `image`.
    OverriddenByProject,
    /// `allow = true`, overridden by an earlier `allow = true` source's fallback.
    OverriddenBySource(crate::config_sources::SourceAlias),
    /// `allow = false` and not selected with `ALIAS:image`.
    Inert,
}

/// One source's declared `image` that the `project:` row does not already show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceImageReport {
    alias: crate::config_sources::SourceAlias,
    image: ConfiguredImage,
    status: SourceImageStatus,
}

impl SourceImageReport {
    pub(crate) fn alias(&self) -> &crate::config_sources::SourceAlias {
        &self.alias
    }

    pub(crate) fn image(&self) -> &ConfiguredImage {
        &self.image
    }

    pub(crate) fn status(&self) -> &SourceImageStatus {
        &self.status
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        reference: &str,
        file: impl Into<PathBuf>,
        alias: &str,
        status: SourceImageStatus,
    ) -> Self {
        Self {
            alias: crate::config_sources::SourceAlias::for_test(alias),
            image: ConfiguredImage::for_test(reference, file),
            status,
        }
    }
}

/// Every configured image tier: the project config's selection, the winning
/// fallback source, the default user config's row, and every source image the
/// precedence chain did not use (ADR-0076 R4.1/R5.2).
///
/// `Default` (nothing set) is also what `image pull`
/// and `setup` use when the configuration could not be read at all: the
/// configured tiers are then unknown, and the recovery builtins fall back to
/// `--image`/env or the default boot image.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ConfiguredImages {
    /// The default user config's own `image` when that source is `allow = true`:
    /// the `user:` row and the pre-#748 accessor.
    user: Option<ConfiguredImage>,
    /// `Some(alias)` when an earlier `allow = true` source outranked `user` as
    /// the fallback, which is what the `user:` row reports.
    user_overridden_by: Option<crate::config_sources::SourceAlias>,
    /// The winning fallback, whatever source supplied it.
    fallback: Option<FallbackImage>,
    /// The project config's selection: its own `OCI_REF`, or a source's image via
    /// `ALIAS:image`.
    project: Option<ConfiguredImage>,
    /// Every other declared source image, in `[[sources]]` order.
    source_images: Vec<SourceImageReport>,
}

impl ConfiguredImages {
    pub(crate) fn user(&self) -> Option<&ConfiguredImage> {
        self.user.as_ref()
    }

    /// The earlier `allow = true` source that outranked the default user config.
    pub(crate) fn user_overridden_by(&self) -> Option<&crate::config_sources::SourceAlias> {
        self.user_overridden_by.as_ref()
    }

    /// The fallback the selector takes after the project config: the first
    /// `allow = true` source declaring `image`.
    pub(crate) fn fallback(&self) -> Option<&FallbackImage> {
        self.fallback.as_ref()
    }

    pub(crate) fn project(&self) -> Option<&ConfiguredImage> {
        self.project.as_ref()
    }

    /// Source images the `project:` row does not show, for `doctor` (ADR-0076
    /// R5.2): they change nothing until an `ALIAS:image` or `allow = true`
    /// selects one.
    pub(crate) fn source_images(&self) -> &[SourceImageReport] {
        &self.source_images
    }

    /// A fixture for tests outside this module (which cannot name the private
    /// fields). Named fields rather than two adjacent `Option<ConfiguredImage>`
    /// parameters, so a user/project swap cannot compile
    /// (`CODING_STANDARDS.md` → *Types*).
    #[cfg(test)]
    pub(crate) fn for_test(fixture: ImageTierFixture) -> Self {
        Self {
            fallback: fixture.user.clone().map(|image| FallbackImage {
                alias: crate::config_sources::SourceAlias::home(),
                image,
                is_default_user_config: true,
            }),
            user: fixture.user,
            project: fixture.project,
            source_images: fixture.source_images,
            ..Self::default()
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
    pub(crate) source_images: Vec<SourceImageReport>,
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

/// The agent kind a **tool** declares so a host terminal multiplexer (herdr)
/// recognizes the guest agent behind the **launcher**.
///
/// Host-only: it labels the host's view of a launch and never reaches the guest
/// environment. There is deliberately no allowlist of built-in labels — a new
/// agent must not need a launcher release — so the grammar is the whole rule,
/// and it is machine-checked ([`pane_hint_token_bytes`], ADR-0018).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PaneAgentHint(String);

impl PaneAgentHint {
    /// The only constructor: no trimming, case folding or normalization, so the
    /// declared spelling is the label.
    fn parse(raw: String) -> Result<Self, &'static str> {
        if pane_hint_token_bytes(raw.as_bytes()) {
            Ok(Self(raw))
        } else {
            Err("herdr_agent must match [a-z0-9-]+")
        }
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
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
    /// Appended last, like every field before it.
    HerdrAgent,
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
            ToolField::HerdrAgent => "herdr_agent",
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
/// (ADR-0076). Omitting `sources` behaves exactly as the implicit
/// `{ name = "home", path = "~/.config/agent-vm/config.toml", trust = true,
/// allow = true }`, which is #733's shipped two-tier load.
pub(crate) fn load(paths: &ConfigPaths) -> Result<ConfigReport> {
    let mut policy = crate::config_pins::PinsContentPolicy::new(paths.project.as_ref());
    load_with_content_approval(paths, &mut policy)
}

/// [`load`] with the #736 pin policy supplied. Production passes
/// [`crate::config_pins::PinsContentPolicy`]; tests use the same policy (a real
/// `pins.json` is written and approved) or one with an observation hook.
pub(crate) fn load_with_content_approval(
    paths: &ConfigPaths,
    approval: &mut dyn config_authority::ContentApprovalPolicy,
) -> Result<ConfigReport> {
    // One leaf-visit counter for the whole load (#735, D6): project tool lists,
    // then each source in `[[sources]]` order. It is moved into the report so
    // the single catalog build continues from exactly here.
    let mut work = config_mounts::MountExpansionWork::fresh();
    let ProjectRead {
        report: project,
        contents: mut project_contents,
        declared,
        // The verified project file's identity gates the self-source check and
        // authorizes its own top-level `mounts` and `[network]` (ADR-0076 R3).
        verified: project_verified,
    } = match &paths.project {
        Some(project) => read_project_tier(project, paths.home.as_deref(), &mut work)?,
        None => ProjectRead::unavailable(),
    };
    let (sources, project_image) = match &paths.project {
        Some(project) => {
            let sources = declared_sources(paths, declared.sources.as_ref(), &project.config)?;
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
    let verified_project = project_verified.as_ref();

    // R7, before any `trust = false` file is opened: the 64-key store bound and
    // every declared pin key. A path that cannot be pinned is refused here,
    // before `pins.json` is read (V27). The set is retained for the gate's
    // `CommitBatch::retained_keys`, so no store write can evict a live key.
    let all_declared_keys = declared_pin_keys(sources.entries(), project_config_path)?;
    // The checkout boundary is measured once, from the captured root, and only
    // when a route can consult it. `None` means no captured root (test routes)
    // or no untrusted source to read. Its root identity is the capture's, so a
    // replacement of the path between the capture and here cannot put the
    // captured root outside its own boundary.
    let boundary = if all_declared_keys.is_empty() {
        None
    } else {
        paths.route().checkout_boundary()?
    };

    // One read per declared source, in `[[sources]]` order. The default user
    // config is recognised **lexically** (never by canonical equality) and is
    // the only `trust = true` route with ADR-0040's dotfile compatibility.
    let mut reads: Vec<SourceRead> = Vec::with_capacity(sources.entries().len());
    let mut inspected: Vec<crate::config_pins::InspectedSource> = Vec::new();
    let mut pending: Vec<crate::config_pins::PendingSource> = Vec::new();
    // One aggregate budget for every source: the per-file ceiling and the list
    // bound alone would let a legal list multiply the parse cost. Pinned bytes
    // are charged here too (D1), so one load can never read more than one load.
    let mut budget = SourceBytes::fresh();
    for entry in sources.entries() {
        let is_default_user = entry.is_trusted() && Some(entry.path()) == paths.user.as_deref();
        let read = if is_default_user {
            let (tier, contents, inert) = read_default_user_source(
                entry,
                verified_project,
                entry.path(),
                paths.route(),
                paths.home.as_deref(),
                &mut work,
                &mut budget,
            )?;
            SourceReadOutcome::Approved {
                tier,
                contents,
                inert,
                pin: None,
                scope: None,
            }
        } else if entry.is_trusted() {
            let (tier, contents, inert) = read_trusted_source(
                entry,
                verified_project,
                paths.route(),
                paths.home.as_deref(),
                &mut work,
                &mut budget,
            )?;
            SourceReadOutcome::Approved {
                tier,
                contents,
                inert,
                pin: None,
                scope: None,
            }
        } else {
            read_source_tier(
                entry,
                verified_project.ok_or_else(|| {
                    anyhow!("internal: a trust = false source without a verified project config")
                })?,
                approval,
                paths.route(),
                boundary.as_ref(),
                paths.home.as_deref(),
                &mut work,
                &mut budget,
            )?
        };
        let (tier, contents, inert, pin) = match read {
            SourceReadOutcome::Approved {
                tier,
                contents,
                inert,
                pin,
                scope,
            } => {
                if let (Some(pin), Some(scope)) = (pin.as_ref(), scope) {
                    inspected.push(crate::config_pins::InspectedSource {
                        alias: entry.alias().clone(),
                        declared: entry.declared(),
                        scope,
                        allow: entry.is_allowed(),
                        key: pin.key().clone(),
                        hash: pin.hash(),
                        status: crate::config_pins::InspectedStatus::Approved {
                            active: pin.active(),
                        },
                    });
                }
                (tier, contents, inert, pin)
            }
            SourceReadOutcome::Pending(source) => {
                inspected.push(crate::config_pins::InspectedSource {
                    alias: source.alias.clone(),
                    declared: source.declared,
                    scope: source.scope,
                    allow: source.allow,
                    key: source.key.clone(),
                    hash: source.hash,
                    status: crate::config_pins::InspectedStatus::Pending(source.reason),
                });
                pending.push(source);
                continue;
            }
        };
        reads.push(SourceRead {
            alias: entry.alias().clone(),
            attributes: entry.attributes(),
            tier,
            contents,
            inert,
            is_default_user,
            pin,
        });
    }

    if !pending.is_empty() {
        let project_config = project_config_path
            .expect("a pending pinned source is declared by a project config")
            .to_path_buf();
        let store_dir = project_config
            .parent()
            .map_or_else(std::path::PathBuf::new, std::path::Path::to_path_buf);
        return Err(anyhow::Error::new(
            crate::config_pins::UnapprovedSources::new(
                project_config,
                store_dir,
                approval.observed(),
                inspected,
                pending,
                all_declared_keys,
            ),
        ));
    }

    let user_index = reads.iter().position(|read| read.is_default_user);
    let user = match user_index {
        Some(index) => reads[index].tier.clone(),
        None => not_sourced_tier(paths.user.as_deref()),
    };

    let images = resolve_images(project_image, &sources, &reads, project_config_path)?;
    // An `allow = false` source's `image` is inert only when the project config
    // does not select it with `ALIAS:image` (ADR-0076 R5.1).
    let inert_images: BTreeSet<crate::config_sources::SourceAlias> = images
        .source_images()
        .iter()
        .filter(|row| matches!(row.status(), SourceImageStatus::Inert))
        .map(|row| row.alias().clone())
        .collect();

    // ADR-0076 R4.2/R4.3: union the adopted top-level `mounts` and `[network]`
    // tables in `[[sources]]` order, then the project config's.
    let project_network = project_contents.network.take();
    let project_mounts = project_contents.adopted_mounts.take().map(|mounts| {
        let file = project_config_path
            .expect("an adopted project mount list came from a project config")
            .to_path_buf();
        (file, mounts)
    });
    let mut mount_contributions: Vec<(PathBuf, config_mounts::ResolvedMountList)> = Vec::new();
    let mut user_sets_mounts: Option<UserMounts> = None;
    let mut adopted_networks: Vec<UserNetwork> = Vec::new();
    for read in &reads {
        let Some(file) = read.tier.path() else {
            continue;
        };
        if let Some(mounts) = read.contents.adopted_mounts.as_ref() {
            mount_contributions.push((file.to_path_buf(), mounts.clone()));
        }
        if read.is_default_user {
            user_sets_mounts = read.contents.mounts.clone();
        }
        if let Some(network) = read.contents.network.as_ref() {
            adopted_networks.push(network.clone());
        }
    }
    if let Some((file, mounts)) = project_mounts {
        mount_contributions.push((file, mounts));
    }
    let network = UserNetwork::merge(adopted_networks, project_network);
    let mounts = config_mounts::merge_adopted_mounts(mount_contributions, user_sets_mounts)?;

    // Declaring any `[[tools]]` replaces the shipped catalog (ADR-0017); `allow`
    // stays independent of that, because a disallowed source's declarations are
    // counted by the `source_tools` emptiness test below.
    let any_allowed_source_configures_tools = reads
        .iter()
        .any(|read| read.attributes.allow && !read.contents.tools.is_empty());

    let mut source_tools: Vec<Vec<Tool>> = Vec::new();
    let mut user_contents = TierContents::empty();
    let mut reports: Vec<SourceReport> = Vec::with_capacity(reads.len());
    let mut user_alias = crate::config_sources::SourceAlias::home();
    // #749: each `allow = true` source's own `default_tools`, in `[[sources]]`
    // order. A disallowed source contributed nothing above (`record_inert`
    // dropped the key), so it is absent here by construction, not by a second
    // decision.
    let mut source_grants: Vec<(crate::config_sources::SourceAlias, Vec<DefaultEntry>)> =
        Vec::new();
    for (index, mut read) in reads.into_iter().enumerate() {
        let contents = std::mem::replace(&mut read.contents, TierContents::empty());
        if read.tier.path().is_none() {
            return Err(anyhow!(
                "internal: a read source without a path cannot be reported"
            ));
        }
        if let Some(names) = contents.default_tools.as_ref() {
            source_grants.push((read.alias.clone(), names.clone()));
        }
        if Some(index) == user_index {
            user_alias = read.alias.clone();
            user_contents = contents;
        } else {
            source_tools.push(contents.tools);
        }
        reports.push(SourceReport {
            alias: read.alias.clone(),
            attributes: read.attributes,
            tier: read.tier,
            inert: read.inert.with_image(inert_images.contains(&read.alias)),
            pin: read.pin,
        });
    }

    let defaults_apply = user_contents.tools.is_empty()
        && project_contents.tools.is_empty()
        && !any_allowed_source_configures_tools
        && source_tools.iter().all(Vec::is_empty);
    let (resolved, conflicts) = catalog_names(CatalogInputs {
        user: user_contents.tools,
        user_alias,
        project: project_contents.tools,
        sources: source_tools,
        project_file: project_config_path,
        defaults_apply,
        user_trust: user_contents.reference_trust.take(),
        grants: DefaultContributions {
            project: project_contents.default_tools.take(),
            sources: source_grants,
            use_tools: project_contents.use_tools.take().unwrap_or_default(),
        },
    })?;
    let uses_defaults = resolved.uses_defaults;

    // Ownership is checked per launch (in `resolve_provisioning`), not across
    // every declaration: two sources may each define a tool that persists one
    // path, because they never launch together (#749).
    // Taken before the report is built: the policy's observation is the one the
    // reads above used, and recording must fence on exactly that generation.
    let pins = approval.observed();
    Ok(ConfigReport {
        user,
        project,
        resolved,
        images,
        user_network: network,
        user_mounts: mounts,
        user_tools: user_contents.reference_tools,
        uses_defaults,
        conflicts,
        sources: SourcesReport {
            sourcing: sources.sourcing(),
            entries: reports,
        },
        mount_work: work,
        pins,
    })
}

/// Which pinned sources an inspection reads.
///
/// `Only` is what lets a project whose pending sources exceed the shared source
/// budget still be reviewed and approved in groups, and what binds
/// `agent-vm config approve --expect` to keys the project actually declares.
#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))] // #739's `config diff|approve`
pub(crate) enum SourceSelection {
    All,
    Only(std::collections::BTreeSet<crate::config_pins::PinKey>),
}

impl SourceSelection {
    fn includes(&self, key: &crate::config_pins::PinKey) -> bool {
        match self {
            Self::All => true,
            Self::Only(keys) => keys.contains(key),
        }
    }
}

/// Read only what a review needs: the project tier, the declared sources, and
/// every selected `trust = false` route through the same read/pin path as
/// `load`.
///
/// Deliberately stops before trusted-source reads, `resolve_images`, the
/// catalog build and any adoption, so a pinned file can be inspected and
/// approved even while its `image`/`sources` references are unresolved or its
/// unapproved TOML is malformed. It never prompts and never writes: the
/// store is opened for reading only, and an absent store stays absent.
#[cfg_attr(not(test), allow(dead_code))] // #739's `config diff|approve`
pub(crate) fn inspect_pinned_sources(
    paths: &ConfigPaths,
    selection: &SourceSelection,
) -> Result<crate::config_pins::PinInspection> {
    let Some(project) = paths.project.as_ref() else {
        return Ok(crate::config_pins::PinInspection::empty());
    };
    let mut work = config_mounts::MountExpansionWork::fresh();
    let ProjectRead {
        declared, verified, ..
    } = read_project_tier(project, paths.home.as_deref(), &mut work)?;
    let sources = declared_sources(paths, declared.sources.as_ref(), &project.config)?;
    let all_declared_keys = declared_pin_keys(sources.entries(), Some(&project.config))?;

    // Reject an unknown `Only` key before opening any source file: a typo must
    // not look like an approval of something else.
    if let SourceSelection::Only(keys) = selection {
        for key in keys {
            if !all_declared_keys.contains(key) {
                return Err(anyhow!(
                    "config: {}: {} is not a declared trust = false source; nothing was inspected",
                    crate::one_line::quoted_path(&project.config),
                    crate::one_line::quoted_path(key.as_path()),
                ));
            }
        }
    }

    let boundary = if all_declared_keys.is_empty() {
        None
    } else {
        paths.route().checkout_boundary()?
    };
    let mut policy = crate::config_pins::PinsContentPolicy::new(Some(project));
    let mut entries: Vec<crate::config_pins::InspectedSource> = Vec::new();
    let mut pending: Vec<crate::config_pins::PendingSource> = Vec::new();
    let mut budget = SourceBytes::fresh();
    if let Some(verified) = verified.as_ref() {
        for entry in sources.entries().iter().filter(|entry| !entry.is_trusted()) {
            let key = crate::config_pins::PinKey::for_source(entry.path()).map_err(|refusal| {
                anyhow!(
                    "config: {}: {}: {}",
                    crate::one_line::quoted_path(&project.config),
                    entry.declared(),
                    refusal.clause()
                )
            })?;
            if !selection.includes(&key) {
                continue;
            }
            let read = read_untrusted_bytes(
                entry,
                verified,
                paths.route(),
                boundary.as_ref(),
                &mut budget,
            )?;
            match policy.check_untrusted_source(verified, entry, read.scope, &read.bytes)? {
                config_authority::ContentApproval::Approved(approved) => {
                    let pin = approved.pin();
                    entries.push(crate::config_pins::InspectedSource {
                        alias: entry.alias().clone(),
                        declared: entry.declared(),
                        scope: read.scope,
                        allow: entry.is_allowed(),
                        key: pin.key().clone(),
                        hash: pin.hash(),
                        status: crate::config_pins::InspectedStatus::Approved {
                            active: pin.active(),
                        },
                    });
                }
                config_authority::ContentApproval::Pending(source) => {
                    entries.push(crate::config_pins::InspectedSource {
                        alias: source.alias.clone(),
                        declared: source.declared,
                        scope: source.scope,
                        allow: source.allow,
                        key: source.key.clone(),
                        hash: source.hash,
                        status: crate::config_pins::InspectedStatus::Pending(source.reason),
                    });
                    pending.push(source);
                }
            }
        }
    }
    // Read the store once even when nothing is pending, so the report names the
    // state it inspected. Absent stays absent; no lock is created.
    policy.load_state()?;
    let observed = policy
        .observed()
        .expect("the inspection read the store state");
    let store_dir = project
        .config
        .parent()
        .map_or_else(std::path::PathBuf::new, std::path::Path::to_path_buf);
    Ok(crate::config_pins::PinInspection::new(
        project.config.clone(),
        store_dir,
        observed,
        entries,
        pending,
        all_declared_keys,
    ))
}

/// Approve every pending pinned source through one real store commit.
///
/// Test support only: production approval is `pins_cmd`'s prompt/`config approve`
/// gate. This still goes through inspection, the store transaction and content
/// hashes — it is not a permissive policy, so a test cannot pass by bypassing
/// the pin check.
#[cfg(test)]
pub(crate) fn approve_all_pinned(paths: &ConfigPaths) {
    let inspection =
        inspect_pinned_sources(paths, &SourceSelection::All).expect("inspect pending sources");
    if inspection.pending().is_empty() {
        return;
    }
    let project = paths
        .project
        .as_ref()
        .expect("a pending source implies a project tier")
        .clone();
    let store = crate::config_pins::store::PinStore::new(project);
    let batch = crate::config_pins::store::CommitBatch {
        approve: inspection
            .pending()
            .iter()
            .map(|source| crate::config_pins::store::ApprovalCandidate {
                key: source.key.clone(),
                hash: source.hash,
                bytes: source.candidate.clone(),
                activate: true,
            })
            .collect(),
        activate: Vec::new(),
        retained_keys: inspection.all_declared_keys().iter().cloned().collect(),
    };
    store
        .update(&inspection.observed(), &batch, 1_000)
        .expect("the fixture's approval commits");
}

/// One declared source after its read: what `load` needs to attribute the read
/// without re-deriving the entry (ADR-0076 R4/R5).
struct SourceRead {
    alias: crate::config_sources::SourceAlias,
    attributes: crate::config_sources::SourceAttributes,
    tier: TierReport,
    contents: TierContents,
    inert: InertDeclarations,
    /// `true` only for the default `~/.config/agent-vm/config.toml` source.
    is_default_user: bool,
    /// `Some` only for an approved `trust = false` source.
    pin: Option<crate::config_pins::SourcePin>,
}

/// What reading one source decided: bytes a pin lookup approved (and what they
/// supplied), or a candidate that must be reviewed before anything is parsed.
///
/// There is no "decode and hope" arm: an unapproved source has no
/// [`TierContents`] to contribute, so adoption cannot happen by inaction.
#[allow(clippy::large_enum_variant)] // one per source; boxing would allocate on the hot path
enum SourceReadOutcome {
    Approved {
        tier: TierReport,
        contents: TierContents,
        inert: InertDeclarations,
        pin: Option<crate::config_pins::SourcePin>,
        scope: Option<crate::config_sources::SourceScope>,
    },
    Pending(crate::config_pins::PendingSource),
}

/// What one parsed tier supplied: its tools, its image, and whatever its
/// top-level adoptable keys contributed. Kept as one value so the tool count and
/// the image cannot be read from two different parses.
struct TierContents {
    network: Option<UserNetwork>,
    /// The default user config's parsed mount configuration (defaults and/or
    /// named sets), present-empty included.
    mounts: Option<UserMounts>,
    /// An adopted top-level `mounts` list, as a merge contribution (ADR-0076
    /// R4.2). `Some` only for a file that declared the key and was allowed to.
    adopted_mounts: Option<config_mounts::ResolvedMountList>,
    tools: Vec<Tool>,
    /// This tier's validated `default_tools`, in declaration order. `None` when
    /// the file did not write the key, so an explicit empty list stays distinct
    /// from an omitted one (an empty list is an empty contribution, not a veto).
    default_tools: Option<Vec<DefaultEntry>>,
    /// The project config's `use_tools`, in declaration order. Every other tier
    /// refuses the key, so this is `Some` for the project only.
    use_tools: Option<Vec<(crate::config_sources::SourceAlias, ToolName)>>,
    image: Option<ConfiguredImage>,
    /// The user tier's egress-reference namespace, built from these sets. `None`
    /// for the project tier and for an absent user file.
    reference_tools: Option<EgressNamespace>,
    /// The same read's measurement. For the default user config it outlives the
    /// read so a launch of one of its tools can be refused by the verdict of the
    /// very bytes that declared it (#749, E8).
    reference_trust: Option<crate::config_authority::ReferenceTrust>,
}

impl TierContents {
    fn empty() -> Self {
        Self {
            tools: Vec::new(),
            default_tools: None,
            use_tools: None,
            image: None,
            network: None,
            mounts: None,
            adopted_mounts: None,
            reference_tools: None,
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

/// Stage 1 of the two-stage decode (ADR-0076 R4.2): validate UTF-8 and parse the
/// root document, so every tier-specific pre-decode gate can look at the file as
/// written — before any typed decoding can mask a misplaced or inert key.
///
/// Diagnostics never echo a value, and invalid UTF-8 is its own error (see the
/// module's value-safe rules). A syntax error keeps its `file:line:col` span.
fn parse_toml_table<'a>(path: &Path, bytes: &'a [u8]) -> Result<(&'a str, toml::Table)> {
    let text = std::str::from_utf8(bytes).map_err(|_| utf8_error(path))?;
    let document: toml::Table =
        toml::from_str(text).map_err(|error| deserialize_error(path, text, &error))?;
    Ok((text, document))
}

/// Stage 2: deserialize the typed [`RawConfig`] **from the same `&str`** the
/// document was parsed from.
///
/// Never from an owned `toml::Table`: that drops `toml::de::Error::span()`, and
/// every typed schema error would lose its `file:line:col` location.
fn decode_raw_config(path: &Path, text: &str) -> Result<RawConfig> {
    toml::from_str(text).map_err(|error| deserialize_error(path, text, &error))
}

/// The keys #749 retired. Each is refused by **presence** at every readable site,
/// after the document parses and the route/pin gates pass, and before any typed
/// decode — so a malformed value is refused as a retired key rather than reported
/// as a schema error, and a file that never loads never reaches one.
///
/// `use_tools` is not here: it is a live key, refused where it does not belong
/// (every non-project tier) by [`validate_use_tools`], not as a retired one.
const RETIRED_KEYS: [&str; 1] = ["allow_tools"];

/// The migration sentence, shared by every site so no reader invents its own.
///
/// There is no equivalent launch allow list to migrate to, so the text says what
/// to delete and then names the whole replacement in the order a user meets it
/// (#749 E9): the automatic grants move to `default_tools`, a source conflict is
/// settled by `use_tools`, one file's tool is reached by its qualified
/// `<alias>:<tool>` verb, and a changed pinned source is approved again.
const RETIRED_KEY_MIGRATION: &str = "allow_tools is retired: every [[tools]] declaration is \
     launchable, so there is no launch allow list to replace it. Delete the key, or set allow = \
     false on a source that must supply nothing automatically; move the automatic grants you \
     still want to default_tools = [...] before the first table header (the shell always gets \
     them, a direct command only when you write the key); settle a bare name two sources \
     declare with use_tools in the project config; launch one file's tool as <alias>:<tool>; \
     and after editing a pinned source, approve its changed bytes again";

/// Refuse a retired key at any readable site (#749 B/F2).
///
/// Placement comes from [`crate::config_schema::misplaced_key`], the one
/// classifier the writer also reads: this is the reader's policy, and the writer
/// keeps its own (ADR-0078). Nothing from the file is echoed but the site's
/// canonical spelling.
fn refuse_retired_keys(document: &toml::Table, path: &Path) -> Result<()> {
    for key in RETIRED_KEYS {
        let Some(site) = crate::config_schema::misplaced_key(document, key) else {
            continue;
        };
        let placement = match site {
            crate::config_schema::Site::Root => String::new(),
            site => format!(" ({})", site_placement(site)),
        };
        let at = match site {
            crate::config_schema::Site::Root => key.to_owned(),
            site => format!("{key} at {}", site.label()),
        };
        return Err(anyhow!(
            "config: {}: {at}: {RETIRED_KEY_MIGRATION}{placement}",
            crate::one_line::quoted_path(path)
        ));
    }
    Ok(())
}

/// The keys #749 admits at the **document root** only, so a later assignment —
/// swallowed by a table header — is refused rather than silently ignored.
///
/// The site itself comes from [`crate::config_schema::misplaced_key`], the one
/// classifier the writer also reads; this list is the reader's *policy* (which
/// keys must sit at the root), never a second list of top-level names.
const ROOT_ONLY_KEYS: [&str; 2] = ["default_tools", "use_tools"];

/// Refuse a root-only key that landed inside a table (#749).
///
/// Before typed decode, so `default_tools = 7` inside `[[tools]]` is reported as
/// misplaced rather than as a schema error; nothing from the file is echoed but
/// the site's canonical spelling and the key's own fixed name.
fn refuse_misplaced_root_only_keys(document: &toml::Table, path: &Path) -> Result<()> {
    for key in ROOT_ONLY_KEYS {
        let Some(site) = crate::config_schema::misplaced_key(document, key) else {
            continue;
        };
        if site == crate::config_schema::Site::Root {
            continue;
        }
        return Err(anyhow!(
            "config: {}: {key} at {}: {key} is a top-level key; it must be written before the \
             first table header ({}), and a later assignment is a member of that table",
            crate::one_line::quoted_path(path),
            site.label(),
            site_placement(site),
        ));
    }
    Ok(())
}

/// Why a site cannot hold the key, in the words of the table it landed in.
fn site_placement(site: crate::config_schema::Site) -> &'static str {
    use crate::config_schema::Site;
    match site {
        Site::Root => "",
        Site::Tool(_) => {
            "it landed inside a [[tools]] declaration, where a top-level key cannot be read"
        }
        Site::Source(_) => {
            "it landed inside a [[sources]] entry, where a top-level key cannot be read"
        }
        Site::Network => "it landed inside [network], where a top-level key cannot be read",
        Site::MountSet(_) => "it landed inside a [mount_sets] definition, where it names a set",
        Site::EgressSet(_) => "it landed inside an [egress_sets] definition, where it names a set",
    }
}

/// The top-level keys whose meaning is lost the moment a `[table]` header
/// swallows them: `sources`. It is read from the document's root only, so a later
/// assignment is a different key to every reader. `allow_tools` used to be the
/// second; #749 refuses it everywhere by placement instead (see
/// [`refuse_retired_keys`]).
const ORDER_SENSITIVE_TOP_LEVEL: [&str; 1] = ["sources"];

/// A top-level key written after a table header becomes a member of that table,
/// where no reader looks for it, so the file silently sources nothing — or
/// authorizes nothing.
///
/// The document is only syntax-checked: a `sources` member is a *shape* no tool
/// and no `[network]` setting can legally have, so finding one is proof of the
/// misplacement, never of an intent about its contents, and nothing is echoed
/// from the file beyond the canonical table spelling and an index.
///
/// `check_network` is `false` for an `allow = false` source, whose `[network]` is
/// inert: a member there cannot grant anything, so it must not be able to fail the
/// load either (ADR-0076 R3).
///
/// `[mount_sets]` and `[egress_sets]` are deliberately not examined: a key there
/// is reserved by [`TOP_LEVEL_FIELDS`] and refused by the set parsers with the same
/// placement rule in their own words.
fn misplaced_sources(document: &toml::Table, check_network: bool) -> Result<()> {
    if check_network && let Some(network) = document.get("network").and_then(toml::Value::as_table)
    {
        for key in ORDER_SENSITIVE_TOP_LEVEL {
            if network.contains_key(key) {
                return Err(anyhow!(
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
                return Err(anyhow!(
                    "tools[{index}]: {key} is not a tool field; a top-level {key} must be written \
                     before the first table header (keys after [[tools]] belong to the last tool)"
                ));
            }
        }
    }
    Ok(())
}

/// ADR-0076 R4.2: refuse a source that is really the project config, judged by the
/// opened descriptor's identity — so `..`, a symlink or a hard link to
/// `projects/<id>/config.toml` is named as self-sourcing before a byte of it is
/// interpreted.
///
/// Canonical equality is never used: a differently spelled path must not be
/// upgraded into the default user config's privileges.
fn check_not_self_source(
    project: Option<&config_authority::VerifiedProject>,
    source_identity: crate::host_paths::FileIdentity,
    entry: &crate::config_sources::SourceEntry,
) -> Result<()> {
    if let Some(verified) = project
        && verified.file_identity() == source_identity
    {
        return Err(anyhow!(
            "config: {}: {}: the project config cannot source itself",
            crate::one_line::quoted_path(verified.path()),
            entry.declared(),
        ));
    }
    Ok(())
}

/// Record — and drop — the top-level keys an `allow = false` source declares
/// (ADR-0076 R3). `[[tools]]` is not one of them: a declaration is not a grant,
/// and every declaration is launchable by name (#749).
///
/// Presence only: the values are never typed, validated or echoed, so
/// `network = 42` is as inert as a well-formed table. `image` is validated by the
/// caller (it stays selectable with `ALIAS:image`), and is recorded inert later,
/// by `resolve_images`, once the project's selection is known.
fn record_inert(raw: &mut RawConfig) -> InertDeclarations {
    let inert = InertDeclarations {
        // Decided by `resolve_images` once the project's `ALIAS:image` selection
        // is known: `image` is inert only when nothing selects it.
        image: false,
        mounts: raw.mounts.is_some(),
        network: raw.network.is_some(),
    };
    raw.mounts = None;
    raw.network = None;
    // #749: an `allow = false` source supplies nothing automatically, so its own
    // `default_tools` list is dropped here and is inert (never an error: presence
    // of the key is still recorded above for `doctor`).
    //
    // `use_tools` is deliberately **not** dropped: project-only is a property of
    // the field, so every other tier must refuse it by presence (`validate_use_tools`)
    // rather than hide a forbidden key behind a successful load.
    raw.default_tools = None;
    inert
}

/// The ADR-0040 presence triggers of a user config, read from the **document** so
/// a malformed `network = 42` triggers exactly like a well-formed table.
///
/// An `allow = false` source's top-level `network` and `mounts` are inert, so
/// they are not triggers; `[mount_sets]`, `[egress_sets]`, a tool's own `mounts`
/// and the `[[tools]]` declarations themselves stay triggers, because those
/// tables are still parsed and their definitions are launchable.
fn user_authority_triggers(document: &toml::Table, allowed: bool) -> AuthorityTriggers {
    let tool_mounts = document
        .get("tools")
        .and_then(toml::Value::as_array)
        .is_some_and(|tools| {
            tools
                .iter()
                .any(|tool| tool.as_table().is_some_and(|t| t.contains_key("mounts")))
        });
    AuthorityTriggers {
        network: allowed && document.contains_key("network"),
        mounts: config_authority::mount_authority_present(config_authority::MountAuthorityFacts {
            top_level: allowed && document.contains_key("mounts"),
            tool_field: tool_mounts,
        }),
        mount_sets: document.contains_key("mount_sets"),
        egress_sets: document.contains_key("egress_sets"),
        // #749 renames #735's arm: `default_tools` is the list that will decide
        // automatic grants, so its presence keeps the file authority-bearing.
        // A `[[tools]]` declaration is launchable now, and the same verified
        // read gates its launch (`ReferenceTrust::require_for_trusted_tool`);
        // a tools-only dotfile still loads (ADR-0040, E8).
        default_tools: allowed && document.contains_key("default_tools"),
    }
}

/// What one tier's *measured* read established, before its bytes are
/// interpreted. The tiers are measured differently and must not be confusable, so
/// they are separate arms rather than an `Option` of tokens (ADR-0076 R2/R3).
enum TierAuthority<'a> {
    /// ADR-0040's verified read of the default user config: the verdict is
    /// unconditional, but the token it mints is `Some` only for a file that
    /// declares an authority-bearing field.
    User {
        authorized: Option<config_authority::AuthorizedConfig<'a>>,
        references: config_authority::ReferenceTrust,
    },
    /// ADR-0076 R2.3: a non-default `trust = true` source, verified
    /// unconditionally before any byte is read.
    Trusted {
        authorized: config_authority::AuthorizedConfig<'a>,
        references: config_authority::ReferenceTrust,
    },
    /// ADR-0073: the verified project config is the root of the project's trust.
    Project(config_authority::AuthorizedConfig<'a>),
    /// A `trust = false` source: no measurement of its own, and a token only when
    /// a [`config_authority::ContentApprovalPolicy`] approved its exact bytes
    /// (#736 seam).
    Source(Option<config_authority::AdoptedAuthority<'a>>),
}

/// The aggregate byte budget of one load's declared sources.
///
/// A value threaded through the source readers: [`MAX_CONFIG_FILE_BYTES`] bounds
/// each file and this bounds their sum, so a reader that read without charging
/// would restore the multiplication the bound exists to prevent.
struct SourceBytes {
    remaining: u64,
}

impl SourceBytes {
    fn fresh() -> Self {
        Self {
            remaining: MAX_SOURCE_BYTES_TOTAL,
        }
    }

    /// Charge `bytes` read from `path`, refusing the load once the declared
    /// sources have cost more than the total. Charged before the bytes are
    /// parsed, so no more than the total can reach a decoder. Only the file that
    /// crossed the total is named, never its size or contents.
    fn charge(&mut self, path: &Path, bytes: usize) -> Result<()> {
        let Some(remaining) = self.remaining.checked_sub(bytes as u64) else {
            return Err(anyhow!(
                "config: {}: the declared sources read more than {MAX_SOURCE_BYTES_TOTAL} bytes in \
                 total; remove the sources agent-vm does not use, or the parts of them no launch \
                 needs",
                crate::one_line::quoted_path(path)
            ));
        };
        self.remaining = remaining;
        Ok(())
    }
}

/// Read, verify, decode, and validate the **default user** config (`trust = true`
/// at `~/.config/agent-vm/config.toml`), the one route with ADR-0040's dotfile
/// compatibility (ADR-0074 D3, ADR-0076 R2.3).
///
/// Only a `NotFound` from the initial `symlink_metadata` means absent, so a host
/// without a user config never fails; a present-but-dangling symlink or a file that
/// vanishes before the read is an error, not a quiet fallback. A final symlink is
/// followed, and the bytes are read before the verdict: that is the user tier's
/// shipped rule and it is unchanged.
fn read_default_user_source(
    entry: &crate::config_sources::SourceEntry,
    project: Option<&config_authority::VerifiedProject>,
    user_path: &Path,
    route: &crate::project_config::RouteAnchor,
    home: Option<&Path>,
    work: &mut config_mounts::MountExpansionWork,
    budget: &mut SourceBytes,
) -> Result<(TierReport, TierContents, InertDeclarations)> {
    match std::fs::symlink_metadata(user_path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let (report, contents) = absent_tier(user_path);
            return Ok((report, contents, InertDeclarations::default()));
        }
        Err(error) => return Err(safe_io_error("reading metadata for", user_path, &error)),
    }

    // Before `config.toml` is opened: a `~/.config` or `~/.config/agent-vm` symlink
    // into the checkout would pass the file's own measurement.
    crate::project_config::check_user_parent_route(user_path, route)?;
    let read = match crate::host_paths::open_regular_no_follow_checkpointed(user_path, || {})
        .map_err(|error| safe_anyhow_error("reading", user_path, &error))?
    {
        Some(opened) => opened
            .into_verified_read(MAX_CONFIG_FILE_BYTES)
            .map_err(|error| safe_anyhow_error("reading", user_path, &error))?,
        None => {
            // A final symlink: decide about its target before opening it. Outside
            // the checkout this keeps ADR-0040's dotfile compatibility; an alias of
            // a checkout file is refused here (U2).
            crate::project_config::check_user_symlink_target(user_path, route)?;
            crate::host_paths::read_bounded_symlink_target(user_path, MAX_CONFIG_FILE_BYTES)
                .map_err(|error| safe_anyhow_error("reading", user_path, &error))?
        }
    };
    let path = read.path();
    budget.charge(path, read.bytes().len())?;
    check_not_self_source(project, read.identity(), entry)?;
    let (text, document) = parse_toml_table(path, read.bytes())?;
    // Before the ADR-0040 verdict: a retired key is told what to delete, even
    // when the file would also fail the verified read.
    refuse_retired_keys(&document, path)?;
    refuse_misplaced_root_only_keys(&document, path)?;
    // Authority is decided by the *presence* of an authority-bearing field, from
    // the same verified read the bytes came from, before any of it is parsed.
    // Presence, not contents: `mounts = []`, an empty `[network]`, an empty
    // `[mount_sets]`, an empty `[egress_sets]` and a tool's `mounts = []` grant
    // nothing yet are exactly the bytes an attacker would plant.
    let triggers = user_authority_triggers(&document, entry.is_allowed());
    let verification = config_authority::verify(&read, triggers).map_err(|error| {
        // A refusal caused by a tool's own field names that field first: the
        // reader has to find the list they must review, and a file with no
        // top-level `mounts` has nothing else pointing at it. The numeric site
        // is echoed, never the tool's name or the list's contents.
        let pointer = match first_tool_mounts(&document) {
            Some(declaration) if !document.contains_key("mounts") => {
                format!("tools[{declaration}].mounts: ")
            }
            _ => String::new(),
        };
        anyhow!(
            "config: {}: {pointer}{error}",
            crate::one_line::quoted_path(path)
        )
    })?;
    // ADR-0076 flat sourcing, before the placement diagnostics and before Stage 2:
    // a root `sources` key is refused by presence whatever else the file declares.
    if document.contains_key("sources") {
        return Err(sources_refusal(path));
    }
    misplaced_sources(&document, entry.is_allowed())
        .map_err(|error| anyhow!("config: {}: {error}", crate::one_line::quoted_path(path)))?;
    let mut raw = decode_raw_config(path, text)?;
    let inert = if entry.is_allowed() {
        InertDeclarations::default()
    } else {
        record_inert(&mut raw)
    };
    let (report, contents) = build_tier(
        path,
        raw,
        TierAuthority::User {
            authorized: verification.authorized,
            references: verification.references,
        },
        FileTierKind::User,
        home,
        work,
    )?;
    Ok((report, contents, inert))
}

/// The first tool declaring its own `mounts`, from the document, so the numeric
/// site can head an ADR-0040 refusal before tool validation.
fn first_tool_mounts(document: &toml::Table) -> Option<usize> {
    document
        .get("tools")
        .and_then(toml::Value::as_array)
        .and_then(|tools| {
            tools
                .iter()
                .position(|tool| tool.as_table().is_some_and(|t| t.contains_key("mounts")))
        })
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
///    field. That verdict is also what authorizes its own top-level `mounts` and
///    `[network]` (ADR-0076 R3).
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
            Ok(_) => Err(anyhow!(
                "config: {}: config.toml is a symbolic link; agent-vm will not follow it",
                crate::one_line::quoted_path(path)
            )),
        };
    };
    let final_component = FinalComponent::Regular(opened.facts());
    // Measured before its bytes are read, and whatever the file declares.
    let verified = config_authority::verify_project(path, &final_component)
        .map_err(|error| project_tier_error(path, &error))?;
    let bytes = opened
        .read_bounded(MAX_CONFIG_FILE_BYTES)
        .map_err(|error| safe_anyhow_error("reading", path, &error))?;
    let (text, document) = parse_toml_table(path, &bytes)?;
    refuse_retired_keys(&document, path)?;
    refuse_misplaced_root_only_keys(&document, path)?;
    // `[network]` is checked for a misplaced `sources` here: the project config
    // is a tier that may grant egress (ADR-0076 R3).
    misplaced_sources(&document, true)
        .map_err(|error| anyhow!("config: {}: {error}", crate::one_line::quoted_path(path)))?;
    let mut raw = decode_raw_config(path, text)?;
    // Taken before `build_tier`, which would refuse `sources` (flat sourcing) and
    // read `ALIAS:image` as an OCI reference: both need the declared source list,
    // which is only known after this read.
    let declared = ProjectDeclarations {
        sources: raw.sources.take(),
        image: raw.image.take(),
    };
    let (report, contents) = build_tier(
        path,
        raw,
        TierAuthority::Project(verified.authorized()),
        FileTierKind::Project,
        home,
        work,
    )?;
    Ok(ProjectRead {
        report,
        contents,
        declared,
        verified: Some(verified),
    })
}

/// Read, verify, decode, and validate a **non-default** `trust = true` source
/// (ADR-0076 R2.2/R2.3).
///
/// The whole route is walked from `/` and the file is opened `O_NOFOLLOW` from the
/// validated parent descriptor, so no repository-controlled ancestor, symlink or
/// spellable alias can redirect the read; then ADR-0040's checks run on the exact
/// descriptors before a byte is read, whatever the file declares.
fn read_trusted_source(
    entry: &crate::config_sources::SourceEntry,
    project: Option<&config_authority::VerifiedProject>,
    route: &crate::project_config::RouteAnchor,
    home: Option<&Path>,
    work: &mut config_mounts::MountExpansionWork,
    budget: &mut SourceBytes,
) -> Result<(TierReport, TierContents, InertDeclarations)> {
    let path = entry.path();
    let opened_route =
        crate::project_config::open_trusted_source_route(path, entry.declared(), route)?;
    let (authorized, references) = config_authority::verify_trusted_source_at(
        path,
        opened_route.parent_dir,
        &opened_route.final_component,
    )
    .map_err(|error| project_tier_error(path, &error))?;
    let opened = opened_route.opened.ok_or_else(|| {
        anyhow!("internal: a trusted source route verified a symbolic link as a regular file")
    })?;
    check_not_self_source(project, opened.identity(), entry)?;
    let bytes = opened
        .read_bounded(MAX_CONFIG_FILE_BYTES)
        .map_err(|error| safe_anyhow_error("reading", path, &error))?;
    budget.charge(path, bytes.len())?;
    let (text, document) = parse_toml_table(path, &bytes)?;
    refuse_retired_keys(&document, path)?;
    refuse_misplaced_root_only_keys(&document, path)?;
    if document.contains_key("sources") {
        return Err(sources_refusal(path));
    }
    misplaced_sources(&document, entry.is_allowed())
        .map_err(|error| anyhow!("config: {}: {error}", crate::one_line::quoted_path(path)))?;
    let mut raw = decode_raw_config(path, text)?;
    let inert = if entry.is_allowed() {
        InertDeclarations::default()
    } else {
        record_inert(&mut raw)
    };
    let (report, contents) = build_tier(
        path,
        raw,
        TierAuthority::Trusted {
            authorized,
            references,
        },
        FileTierKind::Source(entry.alias()),
        home,
        work,
    )?;
    Ok((report, contents, inert))
}

/// Read, decode, and validate a file the project config sources with
/// `trust = false` (ADR-0076 R2.4): in-repo paths are legal, the final symlink is
/// followed through the confined walker, and #736 pins the exact bytes between
/// the read and any parse.
///
/// The order is the guarantee: one route read, charged to the shared source
/// budget; the self-source check on the opened descriptor; then the SHA-256 and
/// `pins.json` lookup; only an approved slice reaches UTF-8 validation, TOML
/// decoding, inert recording or adoption. An unapproved source is not parsed at
/// all, so malformed unapproved TOML reports pending rather than a parse error.
#[allow(clippy::too_many_arguments)] // the load seam's read context, unchanged from #748
fn read_source_tier(
    entry: &crate::config_sources::SourceEntry,
    project: &config_authority::VerifiedProject,
    approval: &mut dyn config_authority::ContentApprovalPolicy,
    route: &crate::project_config::RouteAnchor,
    boundary: Option<&crate::project_config::CheckoutBoundary>,
    home: Option<&Path>,
    work: &mut config_mounts::MountExpansionWork,
    budget: &mut SourceBytes,
) -> Result<SourceReadOutcome> {
    let read = read_untrusted_bytes(entry, project, route, boundary, budget)?;
    let path = entry.path();
    match approval.check_untrusted_source(project, entry, read.scope, &read.bytes)? {
        config_authority::ContentApproval::Pending(pending) => {
            Ok(SourceReadOutcome::Pending(pending))
        }
        config_authority::ContentApproval::Approved(approved) => {
            let (text, document) = parse_toml_table(path, approved.bytes())?;
            refuse_retired_keys(&document, path)?;
            refuse_misplaced_root_only_keys(&document, path)?;
            if document.contains_key("sources") {
                return Err(sources_refusal(path));
            }
            misplaced_sources(&document, entry.is_allowed()).map_err(|error| {
                anyhow!("config: {}: {error}", crate::one_line::quoted_path(path))
            })?;
            let mut raw = decode_raw_config(path, text)?;
            let inert = if entry.is_allowed() {
                InertDeclarations::default()
            } else {
                record_inert(&mut raw)
            };
            let adopted = entry.is_allowed().then(|| approved.adopted_authority());
            let (report, contents) = build_tier(
                path,
                raw,
                TierAuthority::Source(adopted),
                FileTierKind::Source(entry.alias()),
                home,
                work,
            )?;
            Ok(SourceReadOutcome::Approved {
                tier: report,
                contents,
                inert,
                pin: Some(approved.pin().clone()),
                scope: Some(read.scope),
            })
        }
    }
}

/// Walk one `trust = false` route once, charge the bytes to the load's shared
/// budget, and refuse a source that is really the project config.
///
/// The budget is charged before the hash, the store lookup or any decoder sees
/// the bytes (D1: pinned bytes share `MAX_SOURCE_BYTES_TOTAL` with every other
/// source), and the self-source check compares the final descriptor identity
/// before any pin I/O.
fn read_untrusted_bytes(
    entry: &crate::config_sources::SourceEntry,
    project: &config_authority::VerifiedProject,
    route: &crate::project_config::RouteAnchor,
    boundary: Option<&crate::project_config::CheckoutBoundary>,
    budget: &mut SourceBytes,
) -> Result<crate::project_config::UntrustedSourceRead> {
    let read = crate::project_config::read_untrusted_source_route(
        entry,
        route,
        boundary,
        MAX_CONFIG_FILE_BYTES,
    )
    .map_err(|error| untrusted_read_error(project, entry, route, error))?;
    budget.charge(entry.path(), read.bytes.len())?;
    check_not_self_source(Some(project), read.identity, entry)?;
    Ok(read)
}

/// Render one untrusted route refusal, naming the project config, the entry and
/// its declared path, and nothing the walker did not already publish.
///
/// A relative spelling that leaves the project gets its own refusal (D9): its
/// spelling is a statement about the checkout, so leaving it is not an external
/// read. The checkout wording is kept for an absolute route that entered the
/// boundary and then left it.
fn untrusted_read_error(
    project: &config_authority::VerifiedProject,
    entry: &crate::config_sources::SourceEntry,
    route: &crate::project_config::RouteAnchor,
    error: crate::project_config::UntrustedReadError,
) -> anyhow::Error {
    use crate::project_config::UntrustedReadError;
    let project_config = crate::one_line::quoted_path(project.path());
    let declared = entry.declared();
    let alias = entry.alias();
    let path = crate::one_line::quoted_path(entry.path());
    match error {
        UntrustedReadError::NotFound => {
            anyhow!("config: {path}: not found; the project config sources it as {declared}")
        }
        UntrustedReadError::EscapesCheckout if relative_spelling_leaves_root(entry, route) => {
            anyhow!(
                "config: {project_config}: {declared} {alias} {path}: a relative source path stays \
             inside the project directory; the file outside it must be named with an absolute or \
             ~/ path in the project config"
            )
        }
        UntrustedReadError::EscapesCheckout => anyhow!(
            "config: {project_config}: {declared} {alias} {path}: checkout source resolves outside \
             the project directory; refusing to read it (use an explicit absolute or ~/ path in \
             the project config if you intend to source a host file outside the checkout)"
        ),
        UntrustedReadError::RootReplaced => anyhow!(
            "config: {project_config}: {declared} {alias} {path}: the path changed while it was \
             being read: a directory in the route, or the project directory, was replaced; \
             refusing to read it — rerun the command"
        ),
        UntrustedReadError::CheckoutHardLinked(links) => anyhow!(
            "config: {project_config}: {declared} {alias} {path}: checkout source has {links} \
             hard links, so a second name could be outside the project directory; refusing to \
             read it"
        ),
        UntrustedReadError::TooLarge => anyhow!(
            "config: {project_config}: {declared} {alias} {path}: the source is larger than \
             {MAX_CONFIG_FILE_BYTES} byte(s); refusing to read it"
        ),
        UntrustedReadError::NotRegular => anyhow!(
            "config: {project_config}: {declared} {alias} {path}: the source is not a regular \
             file; refusing to read it"
        ),
        UntrustedReadError::Io(error) => safe_anyhow_error("reading", entry.path(), &error),
    }
}

/// Whether a relative entry's own spelling walks out of the captured root with
/// `..`, as opposed to a symlink target doing so (D9).
///
/// Only the lexical-suffix case is D9's: the user wrote a path about the
/// checkout and it left. A relative symlink whose *target* is outside keeps the
/// checkout refusal, because the entry itself claimed nothing outside.
fn relative_spelling_leaves_root(
    entry: &crate::config_sources::SourceEntry,
    route: &crate::project_config::RouteAnchor,
) -> bool {
    let crate::project_config::RouteAnchor::Captured { root, .. } = route else {
        return false;
    };
    if !entry.is_spelled_relative() {
        return false;
    }
    entry.path().strip_prefix(root).is_ok_and(|suffix| {
        matches!(
            suffix.components().next(),
            Some(std::path::Component::ParentDir)
        )
    })
}

/// The 64-key store bound and every declared `trust = false` key, checked before
/// any untrusted file is opened.
///
/// A path that cannot be a pin key is refused here with R7's text, before
/// `pins.json` is touched. The returned set is what `pins_cmd` hands to
/// `CommitBatch::retained_keys`, so a full store never evicts a live key.
fn declared_pin_keys(
    entries: &[crate::config_sources::SourceEntry],
    project_config: Option<&Path>,
) -> Result<std::collections::BTreeSet<crate::config_pins::PinKey>> {
    use crate::config_pins::{MAX_PINNED_KEYS, PinKey};
    let untrusted: Vec<&crate::config_sources::SourceEntry> =
        entries.iter().filter(|entry| !entry.is_trusted()).collect();
    if untrusted.is_empty() {
        return Ok(std::collections::BTreeSet::new());
    }
    let project_config = project_config
        .ok_or_else(|| anyhow!("internal: trust = false sources without a project config path"))?;
    let quoted = crate::one_line::quoted_path(project_config);
    if untrusted.len() > MAX_PINNED_KEYS {
        return Err(anyhow!(
            "config: {quoted}: declares {} pinned (trust = false) sources, which exceeds the limit \
             of {MAX_PINNED_KEYS} pinned sources per project; remove unused sources or consolidate \
             them",
            untrusted.len(),
        ));
    }
    untrusted
        .iter()
        .map(|entry| {
            PinKey::for_source(entry.path()).map_err(|refusal| {
                anyhow!(
                    "config: {quoted}: {}: {}",
                    entry.declared(),
                    refusal.clause()
                )
            })
        })
        .collect()
}

/// The project config's read: the tier report and contents every tier shares, plus
/// the two fields only the project config may own, taken out of the raw config
/// after its verified read and before `build_tier`.
struct ProjectRead {
    report: TierReport,
    contents: TierContents,
    declared: ProjectDeclarations,
    /// `Some` when the file existed and passed ADR-0073 [`verify_project`],
    /// carrying its descriptor identity for the real self-source check.
    verified: Option<config_authority::VerifiedProject>,
}

/// The project file's own sourcing and image fields. Both need the declared source
/// list to be interpreted, which only exists once this read has finished.
#[derive(Default)]
struct ProjectDeclarations {
    sources: Option<toml::Value>,
    image: Option<String>,
}

impl ProjectRead {
    fn absent(path: &Path) -> Self {
        let (report, contents) = absent_tier(path);
        Self {
            report,
            contents,
            declared: ProjectDeclarations::default(),
            verified: None,
        }
    }

    fn unavailable() -> Self {
        let (report, contents) = unavailable_home_tier();
        Self {
            report,
            contents,
            declared: ProjectDeclarations::default(),
            verified: None,
        }
    }
}

/// Resolve the project config's own `sources` value, or the implicit single
/// `home` source (ADR-0076 R1.1).
fn declared_sources(
    paths: &ConfigPaths,
    listed: Option<&toml::Value>,
    project_config: &Path,
) -> Result<crate::config_sources::DeclaredSources> {
    use crate::config_sources::{DeclaredSources, ResolveContext};

    let Some(raw) = listed else {
        return Ok(DeclaredSources::implicit(paths.user.as_deref()));
    };
    let Some(project) = &paths.project else {
        return Err(sources_unresolvable(project_config));
    };
    let crate::project_config::RouteAnchor::Captured { home, root, .. } = &project.route else {
        return Err(sources_unresolvable(project_config));
    };
    DeclaredSources::parse(
        raw,
        &ResolveContext {
            project_config: &project.config,
            home,
            project_root: root,
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

/// Build the image tiers and the source rows (ADR-0076 R4.1/R5.2).
///
/// A project-side image either selects a source's own `image` or is a direct OCI
/// reference; the fallback is the first `allow = true` source in `[[sources]]`
/// order, so appending a source never hijacks an earlier one's boot image. Every
/// other declared image is reported, with what outranked it, for `doctor`.
fn resolve_images(
    project: Option<ProjectImage>,
    declared: &crate::config_sources::DeclaredSources,
    reads: &[SourceRead],
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
            let read = reads
                .iter()
                .find(|read| read.alias == alias)
                .ok_or_else(|| anyhow!("internal: a selected source was not read"))?;
            let image = match read.contents.image.as_ref() {
                Some(image) => image.clone(),
                None if *read.tier.status() == TierStatus::Absent => {
                    return Err(image_selection_missing(
                        file,
                        entry,
                        MissingImage::FileAbsent,
                    ));
                }
                None => {
                    return Err(image_selection_missing(
                        file,
                        entry,
                        MissingImage::DeclaresNone,
                    ));
                }
            };
            Some(image.authorized_by(&alias))
        }
    };
    let selected = project.as_ref().and_then(ConfiguredImage::via);
    let project_is_set = project.is_some();
    // First-wins in `[[sources]]` order: the earlier entry keeps the fallback even
    // when a later one declares an identical image.
    let fallback_index = reads
        .iter()
        .position(|read| read.attributes.allow && read.contents.image.is_some());
    let mut source_images = Vec::new();
    let mut user = None;
    let mut user_overridden_by = None;
    let mut fallback = None;
    for (index, read) in reads.iter().enumerate() {
        let Some(image) = read.contents.image.as_ref() else {
            continue;
        };
        // `user:` keeps its pre-#748 meaning only while its source is `allow =
        // true`; an `allow = false` default user config renders as a source row.
        if read.is_default_user && read.attributes.allow {
            user = Some(image.clone());
        }
        // Shown on the `project:` row instead, as an `ALIAS:image` selection.
        if selected == Some(&read.alias) {
            continue;
        }
        let status = if !read.attributes.allow {
            SourceImageStatus::Inert
        } else if project_is_set {
            SourceImageStatus::OverriddenByProject
        } else if fallback_index == Some(index) {
            SourceImageStatus::SelectedFallback
        } else {
            let winner = &reads[fallback_index.expect("an allowed image has a fallback")];
            SourceImageStatus::OverriddenBySource(winner.alias.clone())
        };
        if let SourceImageStatus::SelectedFallback = status {
            fallback = Some(FallbackImage {
                alias: read.alias.clone(),
                image: image.clone(),
                is_default_user_config: read.is_default_user,
            });
        }
        if read.is_default_user
            && read.attributes.allow
            && let SourceImageStatus::OverriddenBySource(winner) = &status
        {
            user_overridden_by = Some(winner.clone());
        }
        // The `user:` row already shows an `allow = true` default user config's
        // image, so it is not repeated as a source row. Every other declared image
        // is reported with what outranked it.
        if !(read.is_default_user && read.attributes.allow) {
            source_images.push(SourceImageReport {
                alias: read.alias.clone(),
                image: image.clone(),
                status,
            });
        }
    }
    Ok(ConfiguredImages {
        user,
        user_overridden_by,
        fallback,
        project,
        source_images,
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

pub(crate) fn project_tier_error(
    path: &Path,
    error: &config_authority::UntrustedConfig,
) -> anyhow::Error {
    anyhow!("config: {}: {error}", crate::one_line::quoted_path(path))
}

/// Interpret and validate one tier's parsed bytes, given what its measured read
/// established. Shared by every tier so validation, provenance and diagnostics
/// cannot drift between them.
///
/// The tier's *adoption* decision is already made: an `allow = false` source's
/// top-level `mounts` and `[network]` were dropped by its reader (and recorded
/// inert), so a remaining key here is always one this tier may adopt, and its
/// authority token must exist (ADR-0076 R3/R4).
fn build_tier(
    path: &Path,
    raw: RawConfig,
    authority: TierAuthority<'_>,
    kind: FileTierKind<'_>,
    home: Option<&Path>,
    work: &mut config_mounts::MountExpansionWork,
) -> Result<(TierReport, TierContents)> {
    // ADR-0076: flat sourcing. `read_project_tier` has already taken the project's
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
    let (authorized, reference_trust) = match &authority {
        TierAuthority::User {
            authorized,
            references,
        } => (
            authorized.as_ref(),
            // The same read's verdict for a CLI egress reference, which argv
            // parsing learns about only after this read is gone (ADR-0059).
            Some(references.clone()),
        ),
        TierAuthority::Trusted {
            authorized,
            references,
        } => (Some(authorized), Some(references.clone())),
        TierAuthority::Project(authorized) => (Some(authorized), None),
        // A `trust = false` source has no measured verdict of its own: its only
        // authority is an approved-content token, which is not a `ReferenceTrust`.
        TierAuthority::Source(_) => (None, None),
    };
    // ADR-0076 R3/R4: the adopted top-level keys' token. `Source` has one only
    // when a content policy approved its bytes.
    let adopted: Option<config_authority::AdoptedAuthority<'_>> = match &authority {
        TierAuthority::Source(adopted) => *adopted,
        _ => authorized.map(config_authority::AdoptedAuthority::from_verified),
    };
    // `[mount_sets]` and `[egress_sets]` stay the default user config's until
    // #738; every other tier refuses them by presence, empty tables included.
    match kind {
        FileTierKind::Project => refuse_non_user_sets(&raw, path, RefusingTier::Project)?,
        FileTierKind::Source(_) => refuse_non_user_sets(&raw, path, RefusingTier::Source)?,
        FileTierKind::User => {}
    }
    let parsed_network = match raw.network.as_ref() {
        Some(value) => {
            // A present field always produced a token (presence *is* the
            // trigger), so this arm cannot be reached with `None`. Refusing
            // rather than skipping keeps that invariant load-bearing: dropping
            // the grants a file declares must never be the quiet outcome.
            let Some(adopted) = adopted.as_ref() else {
                return Err(anyhow!(
                    "config: {}: [network]: authority was not measured",
                    crate::one_line::quoted_path(path)
                ));
            };
            Some(
                user_network::from_authorized_value(adopted, value).map_err(|error| {
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
            let Some(authorized) = authorized else {
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
    // project store is verified separately (ADR-0073) and a `trust = false` file
    // is pinned before decoding (#736). Demanding the ADR-0040 token for them here
    // would refuse a shape the project tier is now allowed to declare.
    let tool_mounts_need_a_token =
        matches!(kind, FileTierKind::User) && !tool_mount_values.is_empty();
    let mut mounts = None;
    let mut adopted_mounts = None;
    if matches!(kind, FileTierKind::User) {
        if raw.mounts.is_some() || raw.mount_sets.is_some() || tool_mounts_need_a_token {
            // One parser for all three fields: a sets-only file still needs the
            // verified token, because a `--mount NAME` may select one of its sets,
            // and a file whose only mount field is inside a tool must still be
            // parsed here or its declarations would reach `validate_tools`
            // unparsed.
            let Some(authorized) = authorized else {
                return Err(anyhow!(
                    "config: {}: mounts: authority was not measured",
                    crate::one_line::quoted_path(path)
                ));
            };
            let parsed = config_mounts::from_verified_value(
                authorized,
                config_mounts::MountValues {
                    defaults: raw.mounts.as_ref(),
                    sets: raw.mount_sets.as_ref(),
                    tools: &tool_mount_values,
                },
                home,
                work,
            )
            .map_err(|error| anyhow!("config: {}: {error}", crate::one_line::quoted_path(path)))?;
            // The defaults also join the cross-file merge as one contribution, so
            // a project config or another `allow = true` source can be bound
            // beside them (ADR-0076 R4.2). A file that declared no `mounts` key
            // contributes nothing.
            if raw.mounts.is_some() {
                adopted_mounts = parsed.defaults().cloned();
            }
            mounts = Some(parsed);
        }
    } else if let Some(value) = raw.mounts.as_ref() {
        let Some(adopted) = adopted.as_ref() else {
            return Err(anyhow!(
                "config: {}: mounts: authority was not measured",
                crate::one_line::quoted_path(path)
            ));
        };
        adopted_mounts = Some(
            config_mounts::from_adopted_defaults(adopted, value, home).map_err(|error| {
                anyhow!("config: {}: {error}", crate::one_line::quoted_path(path))
            })?,
        );
    }
    let image = validate_image(raw.image.as_deref(), path)?;
    // A project or sourced file's tool `mounts` are parsed here, with zero
    // host-path I/O and charged to the load's one counter. #749 makes them
    // active: the declaration is the authority, so the tool's own launch selects
    // them like any user-tier tool's. The built-in tier's refusal already fired
    // by presence.
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
    // #749: the two grant fields. `default_tools` is accepted wherever a launch
    // can be configured; `use_tools` is the project's own choice, refused by the
    // other tiers here — the embedded catalog included, through
    // `refuse_builtin_authority`.
    let default_tools = validate_default_tools(raw.default_tools, kind, path)?;
    let use_tools = validate_use_tools(raw.use_tools, kind, path)?;
    // This tier's own validated tools, before `merge` and from the same read as
    // the verdict: the only namespace an egress reference may resolve against
    // (ADR-0059). The project tier gets `None`, so it can never be one.
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
            // Only the default user config has an `[egress_sets]` namespace until
            // #738, so a `set:NAME` reference in any other tier's `[network]` is
            // refused for the file (ADR-0076 R3), never resolved against another
            // file's names.
            let resolved = match (&reference_tools, kind) {
                (Some(namespace), FileTierKind::User) => parsed.resolve(namespace),
                _ => parsed.resolve_without_sets(),
            };
            Some(resolved.map_err(|error| {
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
            default_tools,
            use_tools,
            image,
            network,
            mounts,
            adopted_mounts,
            reference_tools,
            reference_trust,
        },
    ))
}

/// ADR-0076: flat sourcing. Only the project config decides which files a launch
/// reads, so any other tier that declares `sources` — `sources = []` included —
/// is refused by its presence alone.
fn sources_refusal(file: &Path) -> anyhow::Error {
    anyhow!(
        "config: {}: sources: only the project config may declare sources; a sourced file cannot \
         source another file",
        crate::one_line::quoted_path(file)
    )
}

/// ADR-0076 R3: `[mount_sets]` and `[egress_sets]` stay the default user config's
/// alone until #738, so a project config or a sourced file refuses them by
/// presence — empty tables included, because a name that nothing may resolve must
/// not look declared.
fn refuse_non_user_sets(raw: &RawConfig, path: &Path, tier: RefusingTier) -> Result<()> {
    if raw.mount_sets.is_some() {
        return Err(mount_sets_refusal(path, tier));
    }
    if raw.egress_sets.is_some() {
        return Err(egress_sets_refusal(path, tier));
    }
    Ok(())
}

/// The compiled-in defaults may grant nothing. Every authority-bearing field is
/// refused by **presence**: empty, a table, a number, on a shadowed or otherwise
/// unreachable tool definition — asking for anything is what authority means.
fn refuse_builtin_authority(raw: &RawConfig, path: &Path) -> Result<()> {
    if let Some(value) = raw.network.as_ref() {
        return Err(network_refusal(value, path, RefusingTier::BuiltIn));
    }
    if raw.default_tools.is_some() {
        return Err(default_tools_refusal(path, RefusingTier::BuiltIn));
    }
    if raw.use_tools.is_some() {
        return Err(use_tools_refusal(path));
    }
    if raw.mounts.is_some() {
        return Err(mounts_refusal(path, RefusingTier::BuiltIn));
    }
    if raw.mount_sets.is_some() {
        return Err(mount_sets_refusal(path, RefusingTier::BuiltIn));
    }
    if raw.egress_sets.is_some() {
        return Err(egress_sets_refusal(path, RefusingTier::BuiltIn));
    }
    if let Some(declaration) = raw.tools.iter().position(|tool| tool.mounts.is_some()) {
        return Err(tool_mounts_refusal(
            path,
            RefusingTier::BuiltIn,
            declaration,
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum RefusingTier {
    Project,
    /// A file the project config sources (a `[mount_sets]`/`[egress_sets]`
    /// refusal is all that is left for this tier in #748).
    Source,
    BuiltIn,
}

/// A refused `[network]`, reported value-safely: the fixed setting names when the
/// value is a table, the bare table name otherwise (`network = 42`).
fn network_refusal(value: &toml::Value, file: &Path, tier: RefusingTier) -> anyhow::Error {
    let settings: Vec<_> = value
        .as_table()
        .map(|table| {
            user_network::SETTINGS
                .iter()
                .filter(|key| table.contains_key(**key))
                .map(|key| format!("network.{key}"))
                .collect()
        })
        .unwrap_or_default();
    let setting = if settings.is_empty() {
        "[network]".to_owned()
    } else {
        settings.join(", ")
    };
    let reason = match tier {
        RefusingTier::Project => "network access cannot be granted by the project config",
        RefusingTier::Source => "network access cannot be granted by a source that is not trusted",
        RefusingTier::BuiltIn => "network access cannot be granted by the built-in config",
    };
    anyhow!(
        "config: {}: {setting}: {reason}; use --allow-* launch flags, or [network] in the user config",
        crate::one_line::quoted_path(file)
    )
}

/// The `mounts` twin of [`network_refusal`], for the tiers that may not declare
/// one.
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
        RefusingTier::Source => "mounts cannot be declared by a source that is not trusted",
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
        RefusingTier::Source => "mount_sets are user-config-only until #738",
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
/// name against the user namespace. There is deliberately no such shadowing —
/// naming a set a file cannot resolve must never be the quiet outcome.
fn egress_sets_refusal(file: &Path, tier: RefusingTier) -> anyhow::Error {
    let reason = match tier {
        RefusingTier::Project => "egress_sets cannot be declared by the project config",
        RefusingTier::Source => "egress_sets are user-config-only until #738",
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
    // The same two-stage order every file tier applies (ADR-0076 R4.2): flat
    // sourcing by presence first, then the authority refusal, then the placement
    // diagnostics, and only then the typed decode.
    let (text, document) = parse_toml_table(path, text.as_bytes())?;
    refuse_retired_keys(&document, path)?;
    refuse_misplaced_root_only_keys(&document, path)?;
    if document.contains_key("sources") {
        return Err(sources_refusal(path));
    }
    let raw = decode_raw_config(path, text)?;
    refuse_builtin_authority(&raw, path)?;
    misplaced_sources(&document, true)
        .map_err(|error| anyhow!("config: {}: {error}", crate::one_line::quoted_path(path)))?;
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
// Merge and labels
// ---------------------------------------------------------------------------

/// The inputs one catalog build needs, as a named struct.
///
/// Three adjacent `Vec<Tool>` arguments would be transposable without the
/// compiler noticing, and they mean very different things (the user's own
/// declarations, the project config's, and each source's), so every field is
/// named at the call site.
struct CatalogInputs<'a> {
    user: Vec<Tool>,
    /// The default user config's own alias, so its definitions are also
    /// reachable as `<alias>:<name>` (`home` when implicitly sourced, #749).
    user_alias: crate::config_sources::SourceAlias,
    project: Vec<Tool>,
    /// Each non-default source's declarations, in `[[sources]]` order. The
    /// default user config's live in `user`.
    sources: Vec<Vec<Tool>>,
    project_file: Option<&'a Path>,
    /// True when no readable tier declares a tool, so the compiled-in catalog
    /// applies. Any source definition is then retained beside it: a declaration
    /// is a launch verb, never inert.
    defaults_apply: bool,
    /// The default user config's measured verdict, cloned into every definition
    /// it declares.
    user_trust: Option<crate::config_authority::ReferenceTrust>,
    /// The `default_tools` lists and the project's `use_tools` choices (#749).
    grants: DefaultContributions,
}

/// One `default_tools` entry: a bare tool name, or an explicit
/// `<alias>:<tool>` a **project** wrote to name one source's declaration
/// (#749 V6). The alias is `None` on every other tier.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DefaultEntry {
    /// `Some` for a qualified entry: it resolves against this source only.
    alias: Option<crate::config_sources::SourceAlias>,
    name: ToolName,
}

impl DefaultEntry {
    /// The spelling a refusal echoes: the qualified entry as the user wrote it.
    fn spelling(&self) -> String {
        match &self.alias {
            Some(alias) => format!("{}:{}", alias.as_str(), self.name.as_str()),
            None => self.name.as_str().to_owned(),
        }
    }
}

/// The `default_tools` lists one load contributes, in the order the effective
/// union reads them (#749): the project config's own list first, then each
/// `allow = true` source's in `[[sources]]` order.
///
/// The shipped list is not here: it is the shell's own compatibility grant and
/// applies only when the compiled-in catalog supplies the definitions (E5).
#[derive(Debug, Default)]
struct DefaultContributions {
    /// `Some` exactly when the project config wrote the key.
    project: Option<Vec<DefaultEntry>>,
    /// `(alias, entries)` per allowed source, in `[[sources]]` order.
    sources: Vec<(crate::config_sources::SourceAlias, Vec<DefaultEntry>)>,
    /// The project's qualified choices, which settle a bare name two files declare.
    use_tools: Vec<(crate::config_sources::SourceAlias, ToolName)>,
}

impl DefaultContributions {
    /// True when a readable config wrote `default_tools`, which is the one
    /// condition under which a direct command receives the grant (E5).
    fn authored_present(&self) -> bool {
        self.project.is_some() || !self.sources.is_empty()
    }
}

/// Label every declared definition, record the bare names nothing settles, and
/// note a project declaration that differs from a same-named one elsewhere
/// (#749).
///
/// Declaring a `[[tools]]` block *is* the authorization, so every definition is
/// a launch verb. What still has to be decided is the **bare** spelling: a
/// project-local definition wins it, the only definition of a name wins it, and
/// two or more sources leave it in conflict — each candidate keeps its qualified
/// `<alias>:<name>` verb, and the bare name is refused naming both.
///
/// Arena order is user, project, then each source in `[[sources]]` order. It is
/// the order a diagnostic names and nothing else.
fn catalog_names(inputs: CatalogInputs<'_>) -> Result<(ResolvedTools, Vec<ConfigConflict>)> {
    let CatalogInputs {
        user,
        user_alias,
        project,
        sources,
        project_file,
        defaults_apply,
        user_trust,
        grants,
    } = inputs;

    let mut decls: Vec<Tool> = user;
    decls.extend(project);
    for file in sources {
        decls.extend(file);
    }
    // Declaring any `[[tools]]` replaces the shipped catalog — the rule `tools
    // print` states and ADR-0017 promises. A shipped/source name rank is
    // `default_tools` P3's concern, where the fallback becomes per name.
    let definitions = if defaults_apply {
        default_tools()?
    } else {
        decls
    };

    let mut names: Vec<LaunchSlot> = definitions
        .iter()
        .map(|tool| LaunchSlot {
            bare: None,
            qualified: qualified_spelling(tool, &user_alias),
            trust: match tool.origin() {
                ToolOrigin::User(_) => user_trust.clone(),
                _ => None,
            },
        })
        .collect();
    let mut by_name: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (position, tool) in definitions.iter().enumerate() {
        by_name.entry(tool.name()).or_default().push(position);
    }
    let mut conflicts: Vec<ConfigConflict> = Vec::new();
    let mut name_conflicts: Vec<NameConflict> = Vec::new();
    for (name, candidates) in &by_name {
        let name = *name;
        let rank = |position: usize| bare_rank(definitions[position].origin());
        let best = candidates.iter().copied().map(rank).min().unwrap_or(1);
        let winners: Vec<usize> = candidates
            .iter()
            .copied()
            .filter(|position| rank(*position) == best)
            .collect();
        if let [winner] = winners.as_slice() {
            // The bare `shell` route belongs to a project entry or the shipped
            // fallback (E3). A user or sourced definition keeps its qualified
            // `<alias>:shell` spelling, so approving a source can never replace
            // the normal shell, and mere uniqueness is not enough.
            let claims_bare = name != SHELL_TOOL_NAME
                || matches!(
                    definitions[*winner].origin(),
                    ToolOrigin::Project(_) | ToolOrigin::BuiltIn
                );
            if claims_bare {
                names[*winner].bare = Some(name.to_owned());
            }
            // A project definition outranks a same-named one in the user config
            // or a source for the bare spelling. When the two differ, that is a
            // shadow `doctor` reports: the other definition is still launchable,
            // but not by this name.
            if matches!(definitions[*winner].origin(), ToolOrigin::Project(_)) {
                for loser in candidates
                    .iter()
                    .copied()
                    .filter(|position| position != winner)
                {
                    if definitions[*winner].same_definition(&definitions[loser]) {
                        continue;
                    }
                    conflicts.push(ConfigConflict {
                        tool: definitions[*winner].name.clone(),
                        winner_file: origin_file(definitions[*winner].origin()).to_path_buf(),
                        overridden_file: origin_file(definitions[loser].origin()).to_path_buf(),
                        fields: definitions[loser].differing_fields(&definitions[*winner]),
                    });
                }
            }
        } else {
            name_conflicts.push(NameConflict {
                name: name.to_owned(),
                file: project_file.map(Path::to_path_buf),
                candidates: winners
                    .iter()
                    .map(|position| {
                        let spelling = names[*position]
                            .qualified
                            .clone()
                            .unwrap_or_else(|| name.to_owned());
                        (spelling, definitions[*position].origin().clone())
                    })
                    .collect(),
            });
        }
    }
    // The effective `default_tools`, resolved here because this is the one place
    // every definition and every launch spelling is known (#749).
    let defaults = resolve_default_tools(
        &definitions,
        &by_name,
        &user_alias,
        defaults_apply,
        &grants,
        project_file,
    )?;
    drop(by_name);
    Ok((
        ResolvedTools {
            definitions,
            names,
            conflicts: name_conflicts,
            uses_defaults: defaults_apply,
            defaults,
        },
        conflicts,
    ))
}

/// Resolve the effective `default_tools` to arena positions (#749).
///
/// The union is the project config's list, then each `allow = true` source's in
/// `[[sources]]` order; a source's entries resolve **within that source**, while
/// a project entry resolves project-local first, then through the project's
/// `use_tools` choice, then by uniqueness across every other file, and otherwise
/// refuses naming both candidates. The shipped list is not part of this union: it
/// applies only when the compiled-in catalog supplies the definitions, and is
/// then the shell's own compatibility grant (E5).
///
/// Deduplication is by definition: one definition granted twice would fold its
/// facets twice.
fn resolve_default_tools(
    definitions: &[Tool],
    by_name: &BTreeMap<&str, Vec<usize>>,
    user_alias: &crate::config_sources::SourceAlias,
    defaults_apply: bool,
    grants: &DefaultContributions,
    project_file: Option<&Path>,
) -> Result<DefaultRoots> {
    // Every choice is validated here, whether or not a `default_tools` entry
    // happens to name the same tool: an entry no default consumes is still a
    // choice the project wrote, and ADR-0079/USAGE promise a config error when
    // it names no tool the source declares (V2).
    for (alias, chosen) in &grants.use_tools {
        resolve_use_tools_choice(alias, chosen, definitions, user_alias, project_file)?;
    }
    let mut all: Vec<DefinitionId> = Vec::new();
    if defaults_apply {
        // The shipped catalog is the arena here, so its compatibility list is
        // every shipped definition but the shell — six names, five providers.
        all.extend(
            definitions
                .iter()
                .enumerate()
                .filter(|(_, tool)| tool.name() != SHELL_TOOL_NAME)
                .map(|(position, _)| DefinitionId(position)),
        );
    }
    let mut authored: Vec<DefinitionId> = Vec::new();
    if let Some(project) = grants.project.as_ref() {
        for entry in project {
            let id = resolve_project_default(
                entry,
                definitions,
                by_name,
                &grants.use_tools,
                user_alias,
                project_file,
            )?;
            if !authored.contains(&id) {
                authored.push(id);
            }
        }
    }
    for (alias, entries) in &grants.sources {
        for entry in entries {
            let id = resolve_source_default(alias, entry, definitions, user_alias)?;
            if !authored.contains(&id) {
                authored.push(id);
            }
        }
    }
    for id in &authored {
        if !all.contains(id) {
            all.push(*id);
        }
    }
    Ok(DefaultRoots {
        all,
        authored,
        authored_present: grants.authored_present(),
    })
}

/// The file a defaults diagnostic names when the entry came from the project
/// config, which is the only file that can settle it.
fn project_grants_file(project_file: Option<&Path>) -> String {
    match project_file {
        Some(file) => crate::one_line::quoted_path(file).to_string(),
        None => "the project config".to_owned(),
    }
}

/// Resolve one `use_tools` choice against the one source it names (#749).
///
/// Shared by the entry a bare default consumes and the unconditional walk that
/// validates every choice, so both refuse with the same sentence.
fn resolve_use_tools_choice(
    alias: &crate::config_sources::SourceAlias,
    name: &ToolName,
    definitions: &[Tool],
    user_alias: &crate::config_sources::SourceAlias,
    project_file: Option<&Path>,
) -> Result<DefinitionId> {
    definitions
        .iter()
        .position(|tool| {
            tool.name() == name.as_str()
                && origin_alias(tool.origin(), user_alias).as_ref() == Some(alias)
        })
        .map(DefinitionId)
        .ok_or_else(|| {
            anyhow!(
                "config: {}: use_tools: {} names no tool that source declares; a qualified \
                 choice needs both an alias the project sources and a tool that file declares",
                project_grants_file(project_file),
                quoted_str(&format!("{}:{}", alias.as_str(), name.as_str()))
            )
        })
}

/// Resolve one project `default_tools` entry: project-local, then the project's
/// own `use_tools` choice, then uniqueness across every other file (#749).
fn resolve_project_default(
    entry: &DefaultEntry,
    definitions: &[Tool],
    by_name: &BTreeMap<&str, Vec<usize>>,
    use_tools: &[(crate::config_sources::SourceAlias, ToolName)],
    user_alias: &crate::config_sources::SourceAlias,
    project_file: Option<&Path>,
) -> Result<DefinitionId> {
    let name = &entry.name;
    let candidates: &[usize] = by_name.get(name.as_str()).map_or(&[], Vec::as_slice);
    let file = project_grants_file(project_file);
    // 0. A qualified entry names one source, so it bypasses every bare-name
    //    rule below: no project-local shadow, no `use_tools`, no uniqueness
    //    guess (#749 V6).
    if let Some(alias) = entry.alias.as_ref() {
        return definition_of_alias(alias, name, definitions, user_alias).ok_or_else(|| {
            anyhow!(
                "config: {file}: default_tools: {} names no tool that source declares; a \
                 qualified entry resolves against the source it names",
                quoted_str(&entry.spelling())
            )
        });
    }
    // 1. The project's own declaration always wins the bare name, so it is what
    //    the project's `default_tools` means.
    if let Some(position) = candidates
        .iter()
        .copied()
        .find(|position| matches!(definitions[*position].origin(), ToolOrigin::Project(_)))
    {
        return Ok(DefinitionId(position));
    }
    // 2. The project's explicit choice settles the shorthand.
    if let Some((alias, _)) = use_tools.iter().find(|(_, chosen)| chosen == name) {
        return resolve_use_tools_choice(alias, name, definitions, user_alias, project_file);
    }
    let name = quoted_str(name.as_str());
    match candidates {
        // 3. Exactly one other file declares it.
        [only] => Ok(DefinitionId(*only)),
        [] => Err(anyhow!(
            "config: {file}: default_tools: {name} names no tool any readable config declares; \
             declare that tool, or remove the entry"
        )),
        // 4. Two or more: name both candidates and the one way to settle them.
        many => {
            let spellings: Vec<String> = many
                .iter()
                .map(|position| {
                    quoted_str(&default_spelling(
                        definitions[*position].name(),
                        definitions[*position].origin(),
                        user_alias,
                    ))
                })
                .collect();
            let origins: Vec<String> = many
                .iter()
                .map(|position| describe_origin(definitions[*position].origin()))
                .collect();
            Err(anyhow!(
                "config: {file}: default_tools: {name} is declared by {}; launch one as {}, or \
                 settle it with use_tools = [{}]",
                join_clauses(&origins, "and"),
                join_clauses(&spellings, "or"),
                spellings.first().cloned().unwrap_or_default(),
            ))
        }
    }
}

/// The spelling a defaults conflict names a candidate by: its qualified
/// `<alias>:<name>`, or its bare name for a project definition (which no alias
/// reaches).
fn default_spelling(
    name: &str,
    origin: &ToolOrigin,
    user_alias: &crate::config_sources::SourceAlias,
) -> String {
    match origin {
        ToolOrigin::User(_) => format!("{}:{}", user_alias.as_str(), name),
        ToolOrigin::Source { alias, .. } => format!("{}:{}", alias.as_str(), name),
        ToolOrigin::BuiltIn | ToolOrigin::Project(_) => name.to_owned(),
    }
}

/// The alias a definition is reachable by, if any: the user config's own alias or
/// a source's.
fn origin_alias(
    origin: &ToolOrigin,
    user_alias: &crate::config_sources::SourceAlias,
) -> Option<crate::config_sources::SourceAlias> {
    match origin {
        ToolOrigin::User(_) => Some(user_alias.clone()),
        ToolOrigin::Source { alias, .. } => Some(alias.clone()),
        ToolOrigin::BuiltIn | ToolOrigin::Project(_) => None,
    }
}

/// Resolve one source's `default_tools` entry within that source (#749): a
/// source may grant only what it declares itself.
fn resolve_source_default(
    alias: &crate::config_sources::SourceAlias,
    entry: &DefaultEntry,
    definitions: &[Tool],
    user_alias: &crate::config_sources::SourceAlias,
) -> Result<DefinitionId> {
    // `validate_default_tools` refuses a qualified entry outside the project
    // tier, so a source's list is bare by construction; its own alias is the
    // only source this lookup can reach.
    definition_of_alias(alias, &entry.name, definitions, user_alias).ok_or_else(|| {
        anyhow!(
            "config: default_tools: {} is not declared by source {}; a source may grant only \
             the tools it declares",
            quoted_str(entry.name.as_str()),
            alias.as_str()
        )
    })
}

/// The one definition a source alias declares under `name` (#749): the
/// alias-restricted lookup both a qualified project default and a source's own
/// list use, so neither can fall back to a bare-name rank.
fn definition_of_alias(
    alias: &crate::config_sources::SourceAlias,
    name: &ToolName,
    definitions: &[Tool],
    user_alias: &crate::config_sources::SourceAlias,
) -> Option<DefinitionId> {
    definitions
        .iter()
        .position(|tool| {
            tool.name() == name.as_str()
                && origin_alias(tool.origin(), user_alias).as_ref() == Some(alias)
        })
        .map(DefinitionId)
}

/// The rank of an origin for a **bare** name. The project config is this
/// project's own decision; the shipped catalog is the local one when nothing
/// else declares tools (the two never coexist). Every other file is a source.
fn bare_rank(origin: &ToolOrigin) -> u8 {
    match origin {
        ToolOrigin::Project(_) | ToolOrigin::BuiltIn => 0,
        ToolOrigin::User(_) | ToolOrigin::Source { .. } => 1,
    }
}

/// The `<alias>:<name>` spelling a definition is always reachable by. The
/// default user config's alias is its `[[sources]]` name (`home` when implicit);
/// project and built-in definitions have none.
fn qualified_spelling(
    tool: &Tool,
    user_alias: &crate::config_sources::SourceAlias,
) -> Option<String> {
    match tool.origin() {
        ToolOrigin::User(_) => Some(format!("{}:{}", user_alias.as_str(), tool.name())),
        ToolOrigin::Source { alias, .. } => Some(format!("{}:{}", alias.as_str(), tool.name())),
        ToolOrigin::BuiltIn | ToolOrigin::Project(_) => None,
    }
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

/// One launch winner's resolved facets: everything one visited mask supplies.
///
/// A named struct rather than a positional tuple: several of these are
/// collections and two are ordered, so an opaque tuple is exactly where a
/// caller transposes two facets without the compiler noticing. Pairing this
/// with its winner happens in one place, by ordered filtering.
struct ResolvedFacets {
    provisioned: ProviderSet,
    requested_names: BTreeSet<ServiceName>,
    persist: Vec<PersistPath>,
    mounts: ResolvedMountList,
    /// The folded guest environment: the roots' own first, then every other
    /// visited member in arena order (#749 AC2).
    guest_env: BTreeMap<String, String>,
    /// The folded requests, over the same mask. A built-in member contributes
    /// none: its metadata stays report-only (E5).
    network_requests: NetworkRequests,
    /// True iff at least one visited definition is a configuration file's own,
    /// which is what makes this launch's requests authority rather than report
    /// metadata (E5/E10).
    authored_egress: bool,
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
/// names, `persist` paths, mount declarations, tool environment and
/// `network_requests` are six facets folded over *one* visited mask, so they
/// cannot disagree about what a launch provisions (#749 AC2/AC3).
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
) -> Result<(Vec<CatalogEntry>, DefaultFacets, DefaultFacets)> {
    let ResolvedTools {
        definitions,
        mut names,
        defaults,
        ..
    } = tools;
    let index = scoped_tool_index(&definitions)?;

    for tool in &definitions {
        for (position, reference) in tool.declared_tools().iter().enumerate() {
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

    // Every definition is a launch entry (#749). Each is built from its exact
    // `DefinitionId`, in arena order, and the `(DefinitionId, ResolvedFacets)`
    // pair is formed where the facets are folded, so a tool can only ever be
    // joined with its own closure's facets.
    let launches: Vec<DefinitionId> = (0..definitions.len()).map(DefinitionId).collect();
    let mut resolved: Vec<(DefinitionId, ResolvedFacets)> = Vec::with_capacity(launches.len());
    for start in &launches {
        let visited = launch_closure(&definitions, &index, *start)?;
        // Ownership before any facet escapes: two definitions selected by the
        // same launch may not claim one guest path or an ancestor/descendant
        // pair, even when one of them lost its launch verb. Unguarded here, a
        // hidden loser's paths would reach the guest-HOME link list unvalidated.
        validate_persist_ownership(closure_definitions(&definitions, &visited))?;
        let facets = fold_closure(
            &definitions,
            &visited,
            &[*start],
            RequestMembers::Every,
            work,
        )?;
        resolved.push((*start, facets));
    }

    // The effective `default_tools` closure, folded once and read twice: by the
    // shell affordance's entry (below) and by a direct command's grant (E5).
    //
    // A contributor from a read that failed without refusing the load carries its
    // measured verdict here, so the grant cannot outlive it (E8/E10). Both routes
    // read it through the same helper, so neither can build a grant the other
    // refuses. This is the indexed verdict itself, not a second check: no entry is
    // excluded before it.
    let contributor_refusal = |roots: &[DefinitionId]| {
        roots.iter().find_map(|id| {
            let trust = names[id.0].trust.clone()?;
            trust.require_for_trusted_tool().is_err().then_some(trust)
        })
    };
    let all_mask = defaults_mask(&definitions, &index, &defaults.all)?;
    // T5: the shell affordance is the one entry that carries its own persist list
    // *and* the effective grant, so the two lists are one claim set. Validating
    // each side separately lets an overlapping-but-distinct pair through, and the
    // guest-HOME link list would then hold two paths where one shadows the other.
    // The fallback's own list is empty, so there this is the grant alone.
    if !defaults.all.is_empty()
        && let Some(affordance) = (0..definitions.len()).find(|position| {
            // The same route rule `CatalogEntry::is_shell_affordance` applies: the
            // bare `shell` slot a non-source definition won (E3/F6).
            names[*position].bare.as_deref() == Some(SHELL_TOOL_NAME)
                && !matches!(definitions[*position].origin(), ToolOrigin::Source { .. })
        })
    {
        let own = launch_closure(&definitions, &index, DefinitionId(affordance))?;
        let merged: Vec<bool> = own
            .iter()
            .zip(&all_mask)
            .map(|(own, granted)| *own || *granted)
            .collect();
        validate_persist_ownership(closure_definitions(&definitions, &merged))?;
    }
    let mut all = fold_defaults(&definitions, &all_mask, &defaults.all, work)?;
    all.refusal = contributor_refusal(&defaults.all);
    // A direct command receives only what a file wrote, never the shipped list.
    let direct = if defaults.authored_present {
        let authored_mask = defaults_mask(&definitions, &index, &defaults.authored)?;
        let mut authored = fold_defaults(&definitions, &authored_mask, &defaults.authored, work)?;
        authored.refusal = contributor_refusal(&defaults.authored);
        authored
    } else {
        DefaultFacets::empty()
    };
    drop(index);

    // Retention ends here: only the launch winners survive, each taken from its
    // own arena slot so a definition can be handed on exactly once.
    let mut slots: Vec<Option<Tool>> = definitions.into_iter().map(Some).collect();
    let entries = resolved
        .into_iter()
        .map(|(id, facets)| {
            let tool = slots.get_mut(id.0).and_then(Option::take).ok_or_else(|| {
                anyhow!(
                    "internal: launch entry {} is out of range or selected twice; report this \
                     as an agent-vm bug",
                    id.0
                )
            })?;
            let authorized_egress = facets.authored_egress;
            let launch = std::mem::take(&mut names[id.0]);
            Ok(CatalogEntry {
                guest_env: facets.guest_env,
                network_requests: facets.network_requests,
                tool,
                bare_label: launch.bare,
                qualified_label: launch.qualified,
                launch_trust: launch.trust,
                provisioned: facets.provisioned,
                requested_names: facets.requested_names,
                persist: facets.persist,
                mounts: facets.mounts,
                authorized_egress,
            })
        })
        .collect::<Result<Vec<CatalogEntry>>>()?;
    Ok((entries, all, direct))
}

/// One closure's folded facets: providers, requested names, persist paths,
/// mounts, tool environment and requests, all over the same visited mask so
/// they cannot disagree (#749 AC2).
fn fold_closure(
    definitions: &[Tool],
    visited: &[bool],
    roots: &[DefinitionId],
    requests: RequestMembers,
    work: &mut config_mounts::MountExpansionWork,
) -> Result<ResolvedFacets> {
    let mut provisioned = ProviderSet::default();
    let mut requested_names = BTreeSet::new();
    let mut persist = Vec::new();
    let mut lists: Vec<&ResolvedMountList> = Vec::new();
    for tool in closure_definitions(definitions, visited) {
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
    let launcher = roots.first().map(|root| &definitions[root.0]);
    let mounts = config_mounts::merge_tool_mounts(lists, work).map_err(|error| {
        // A closure conflict is a catalog error for *this* launch: the two
        // lists agree with themselves and only disagree when one launch
        // selects both. Naming the launching declaration is what makes that
        // fixable, and the file comes from `tool_error`'s origin.
        match launcher {
            Some(launcher) => tool_error(
                &launcher.origin,
                launcher.declaration_index,
                &launcher.name,
                error,
            ),
            None => error.into(),
        }
    })?;
    let (guest_env, network_requests, authored_egress) =
        fold_env_and_requests(definitions, visited, roots, requests);
    Ok(ResolvedFacets {
        provisioned,
        requested_names,
        persist,
        mounts,
        guest_env,
        network_requests,
        authored_egress,
    })
}

/// Which visited members contribute to a folded `network_requests` set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequestMembers {
    /// Every member, built-in included: a launch reports its whole closure's
    /// requests, and its own are the ones a compiled-in definition declares.
    Every,
    /// Only the members a configuration file declared: the shipped list's
    /// requests stay that list's own report metadata and never enter the
    /// effective `default_tools` grant (E5).
    Declared,
}

/// Fold `env` and `network_requests` over the mask the other four facets use
/// (#749 AC2/AC3, E10).
///
/// The **roots** come first, in contribution order, so a root's own value wins a
/// collision; every other visited definition follows in arena order, so the
/// result cannot depend on traversal order. `env` is not authority and folds
/// over every member. `network_requests` is authority, so the returned flag is
/// true only when a *declared* member is visited: a built-in-only closure stays
/// report metadata and grants no egress on its own (E5).
fn fold_env_and_requests(
    definitions: &[Tool],
    visited: &[bool],
    roots: &[DefinitionId],
    requests: RequestMembers,
) -> (BTreeMap<String, String>, NetworkRequests, bool) {
    let mut order: Vec<usize> = Vec::with_capacity(visited.len());
    for root in roots {
        if !order.contains(&root.0) {
            order.push(root.0);
        }
    }
    for (position, seen) in visited.iter().enumerate() {
        if *seen && !order.contains(&position) {
            order.push(position);
        }
    }
    let mut guest_env = BTreeMap::new();
    let mut network_requests = NetworkRequests::default();
    let mut authored_egress = false;
    for position in order {
        let tool = &definitions[position];
        for (key, value) in tool.guest_env() {
            guest_env
                .entry(key.clone())
                .or_insert_with(|| value.clone());
        }
        let declared = !matches!(tool.origin(), ToolOrigin::BuiltIn);
        authored_egress |= declared;
        if declared || requests == RequestMembers::Every {
            network_requests = network_requests.union(tool.network_requests());
        }
    }
    (guest_env, network_requests, authored_egress)
}

/// The union of the closures of `roots`, as one visited mask (#749).
fn defaults_mask(
    definitions: &[Tool],
    index: &ScopedToolIndex<'_>,
    roots: &[DefinitionId],
) -> Result<Vec<bool>> {
    let mut mask = vec![false; definitions.len()];
    for root in roots {
        for (position, seen) in launch_closure(definitions, index, *root)?
            .into_iter()
            .enumerate()
        {
            mask[position] |= seen;
        }
    }
    Ok(mask)
}

/// The effective `default_tools` closure as one grant (#749): the same six
/// folded facets one launch resolves, plus the resolved names `doctor` reports
/// and the contributors' measured verdicts.
fn fold_defaults(
    definitions: &[Tool],
    mask: &[bool],
    roots: &[DefinitionId],
    work: &mut config_mounts::MountExpansionWork,
) -> Result<DefaultFacets> {
    if roots.is_empty() {
        return Ok(DefaultFacets::empty());
    }
    // The same ownership rule every launch closure gets: a defaults-only
    // selection may not claim one guest path twice either.
    validate_persist_ownership(closure_definitions(definitions, mask))?;
    let folded = fold_closure(definitions, mask, roots, RequestMembers::Declared, work)?;
    Ok(DefaultFacets {
        provisioned: folded.provisioned,
        requested_names: folded.requested_names,
        persist: folded.persist,
        mounts: folded.mounts,
        guest_env: folded.guest_env,
        network_requests: folded.network_requests,
        names: roots
            .iter()
            .map(|root| definitions[root.0].name().to_owned())
            .collect(),
        authored_egress: folded.authored_egress,
        // Set by the caller that holds the contributed definitions' read verdicts.
        refusal: None,
    })
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
        // Every name was proven present by `resolve_provisioning` above.
        for reference in tool.declared_tools() {
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
/// `network` that grants nothing. `sources` (#734) is reserved for the same
/// reason. `allow_tools` is not a field any more (#749), so it is not in this
/// list: the retired-key gate refuses it at every readable site, a set name
/// included ([`crate::config_schema::misplaced_key`]).
///
/// Held here rather than in `config_mounts` because this module owns the schema the
/// names come from: the test beside `RawConfig` proves each one is still accepted at
/// the top level, so a renamed field cannot leave a stale reservation behind.
pub(crate) const TOP_LEVEL_FIELDS: [&str; 9] = [
    "default_tools",
    "egress_sets",
    "image",
    "mounts",
    "mount_sets",
    "network",
    "sources",
    "tools",
    "use_tools",
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

/// The top-level fields whose own entries may carry an `image` key of their own
/// (#737).
///
/// TOML scopes a bare key to the most recent header, so `image = "REF"` written
/// after one of these belongs to that table, not to the root: inserting a root
/// assignment above it would leave the user's line meaning something else, and
/// leaving it alone would silently ignore it. The project-config writer therefore
/// refuses such a file, naming the table by the spelling below. It lives beside
/// [`RawConfig`] because that schema owns these five names; the writer keeps only
/// the semantic dispatch over the parsed shape. `sources` (#734) and #749's
/// keys are not listed: a field that cannot hold an `image` needs no entry here.
pub(crate) const IMAGE_OWNER_FIELDS: [(&str, ImageOwner); 5] = [
    ("sources", ImageOwner::Sources),
    ("network", ImageOwner::Network),
    ("tools", ImageOwner::Tools),
    ("mount_sets", ImageOwner::MountSets),
    ("egress_sets", ImageOwner::EgressSets),
];

/// Which of [`IMAGE_OWNER_FIELDS`] an `image` was found in, and how a refusal names
/// the table the user wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ImageOwner {
    Sources,
    Network,
    Tools,
    MountSets,
    EgressSets,
}

impl ImageOwner {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Sources => "[[sources]]",
            Self::Network => "[network]",
            Self::Tools => "[[tools]]",
            Self::MountSets => "[mount_sets]",
            Self::EgressSets => "[egress_sets]",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    // User tier: verified by config_authority; project/`allow = true` source:
    // adopted through the verified read's token; built-in: refused by presence.
    // Untyped at this seam (ADR-0076 R4.2, Finding 5): `network = 42` must reach
    // the authority decision and the inert/refusal wording instead of a serde
    // message, and an inert value must never fail the decode at all.
    #[serde(default)]
    network: Option<toml::Value>,
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
    /// Project config only (ADR-0076): the `[[sources]]` tables this project
    /// reads. Every other tier refuses the key by presence (flat sourcing, S2).
    /// Untyped at this seam so a non-array or a string entry reaches
    /// `config_sources`'s migration diagnostics, after the project file's
    /// verified read.
    #[serde(default)]
    sources: Option<toml::Value>,
    /// #749: the automatic grants a launch receives. The shell affordance always
    /// gets the effective list; a direct command gets it only when a file wrote
    /// the key (E5). Root-only, so the placement gate refuses a later assignment
    /// and `None` is exactly "the file did not declare it".
    #[serde(default)]
    default_tools: Option<Vec<String>>,
    /// #749: the project config's own choice settling a bare default name that
    /// two sources declare. Project-only, enforced per tier in `build_tier`.
    #[serde(default)]
    use_tools: Option<Vec<String>>,
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
    /// The pane agent hint (`[a-z0-9-]+`), host-only. A `String` here so a
    /// rejected token is diagnosed by [`validate_tools`] with the tool and the
    /// field named; a wrong type stays on the generic redacted serde path.
    #[serde(default)]
    herdr_agent: Option<String>,
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
        // The rejected token itself is never echoed: the fixed detail names the
        // field and the grammar, and nothing else.
        let herdr_agent = tool
            .herdr_agent
            .map(PaneAgentHint::parse)
            .transpose()
            .map_err(|detail| tool_error(&origin, index, &name, detail))?;

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
            herdr_agent,
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
/// caller decides a different thing from the same rule: [`LaunchVerb::parse`]
/// accepts a name iff this predicate is `None`, and a verb refusal needs a
/// *fixed* text, never the declaration diagnostic. The reasons are the same
/// strings `[[tools]]` has always printed, so a declaration and a launch verb
/// cannot disagree about what a name is — and `:` is refused by both, which is
/// what keeps `<alias>:<name>` unambiguous.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ToolNameRejection {
    Empty,
    WhitespaceOrControl,
    LeadingDash,
    Path,
    /// `:` separates a source alias from a tool name in a launch verb, so no
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

/// The one tool-name rule, shared by `[[tools]]` validation and launch verbs.
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
///
/// #749 retired the `"*"` wildcard and the shell's implicit one: a tool's list
/// names the tools in its own file, and automatic grants belong to
/// `default_tools`. The refusal names that replacement, because a user who wrote
/// `*` wanted provisioning, not a syntax lesson.
fn validate_tool_refs(
    raw: Option<Vec<String>>,
    origin: &ToolOrigin,
    index: usize,
    name: &ToolName,
) -> Result<Vec<ToolName>> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    let mut names = Vec::with_capacity(raw.len());
    for (position, entry) in raw.into_iter().enumerate() {
        if entry == ALL_TOOLS_WILDCARD {
            return Err(tool_error(
                origin,
                index,
                name,
                format!(
                    "tools[{position}]: `*` is retired: a `tools` list names the tools in this \
                     file, so write their names — or, for what a launch should be provisioned \
                     with automatically, a top-level default_tools = [...] before the first table \
                     header"
                ),
            ));
        }
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
    Ok(names)
}

/// Validate one tier's `default_tools` into entries (#749).
///
/// Shape only: whether each entry *resolves* is a catalog fact (a name may be
/// declared in another file), so [`resolve_default_tools`] decides it where every
/// definition is known. Duplicates are collapsed — the list is a set of grants,
/// and a repeated entry would fold one definition twice.
///
/// A bare name is accepted everywhere; an explicit `<alias>:<tool>` is the
/// project config's own spelling (V6), because only the project decides which
/// file a grant reads. The refusal echoes only the index: this is a name slot,
/// and a realistic mistake is pasting something secret into it.
fn validate_default_tools(
    raw: Option<Vec<String>>,
    kind: FileTierKind<'_>,
    path: &Path,
) -> Result<Option<Vec<DefaultEntry>>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let mut entries: Vec<DefaultEntry> = Vec::with_capacity(raw.len());
    for (index, entry) in raw.iter().enumerate() {
        let Some(verb) = LaunchVerb::parse(entry) else {
            return Err(anyhow!(
                "config: {}: default_tools[{index}]: not a tool name or <alias>:<tool>; name \
                 the tools a launch should provision (for example default_tools = [\"pi\"]), \
                 and settle a name two sources declare with use_tools in the project config",
                crate::one_line::quoted_path(path)
            ));
        };
        let entry = match verb {
            LaunchVerb::Bare(name) => DefaultEntry { alias: None, name },
            LaunchVerb::Qualified { alias, name } if matches!(kind, FileTierKind::Project) => {
                DefaultEntry {
                    alias: Some(alias),
                    name,
                }
            }
            LaunchVerb::Qualified { .. } => {
                return Err(anyhow!(
                    "config: {}: default_tools[{index}]: a qualified <alias>:<tool> entry is \
                     project-config only; a source grants only the tools it declares, by bare \
                     name",
                    crate::one_line::quoted_path(path)
                ));
            }
        };
        if !entries.contains(&entry) {
            entries.push(entry);
        }
    }
    Ok(Some(entries))
}

/// Validate one tier's `use_tools` into the project's qualified choices (#749).
///
/// Project-only is a property of the field, so every other tier refuses it by
/// presence — empty list included, because a key no reader may honour must not
/// look declared. Two entries may not target one tool name: each entry settles
/// *which* source supplies a bare name, and two answers settle nothing.
fn validate_use_tools(
    raw: Option<Vec<String>>,
    kind: FileTierKind<'_>,
    path: &Path,
) -> Result<Option<Vec<(crate::config_sources::SourceAlias, ToolName)>>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    if !matches!(kind, FileTierKind::Project) {
        return Err(use_tools_refusal(path));
    }
    let mut choices: Vec<(crate::config_sources::SourceAlias, ToolName)> =
        Vec::with_capacity(raw.len());
    for (index, entry) in raw.iter().enumerate() {
        let Some(LaunchVerb::Qualified { alias, name }) = LaunchVerb::parse(entry) else {
            return Err(anyhow!(
                "config: {}: use_tools[{index}]: write the choice as <alias>:<name>, the qualified \
                 spelling of the tool the project means (for example use_tools = \
                 [\"repo:pi\"])",
                crate::one_line::quoted_path(path)
            ));
        };
        if let Some(first) = choices.iter().position(|(_, chosen)| *chosen == name) {
            return Err(anyhow!(
                "config: {}: use_tools[{index}]: this entry already chosen at use_tools[{first}]; \
                 two entries may not target the one tool name, because together they settle \
                 nothing",
                crate::one_line::quoted_path(path)
            ));
        }
        choices.push((alias, name));
    }
    Ok(Some(choices))
}

/// The one sentence every tier but the project answers `use_tools` with (#749).
fn use_tools_refusal(file: &Path) -> anyhow::Error {
    anyhow!(
        "config: {}: use_tools: only the project config may settle a default name with use_tools; \
         delete the key here, move the choice to the project config, or launch the qualified \
         <alias>:<name> verb directly",
        crate::one_line::quoted_path(file)
    )
}

/// `default_tools` is an automatic grant, so the compiled-in catalog may not
/// declare one (E5: the shipped list is the shell's own compatibility grant, not
/// a config field).
fn default_tools_refusal(file: &Path, tier: RefusingTier) -> anyhow::Error {
    let reason = match tier {
        RefusingTier::Project => "default_tools cannot be declared by the project config",
        RefusingTier::Source => "default_tools cannot be declared by a source that is not trusted",
        RefusingTier::BuiltIn => "default_tools cannot be declared by the built-in config",
    };
    anyhow!(
        "config: {}: {reason}; the shipped list is the shell's own compatibility grant",
        crate::one_line::quoted_path(file)
    )
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

/// One byte accepted in a pane agent hint: ASCII lowercase, a digit, or `-`.
///
/// Deliberately narrower than [`ToolName`]'s alphabet and with no label
/// allowlist: the value is a herdr label, and a new agent must not need a
/// launcher release to be labelled. Every non-ASCII byte fails here, so a
/// Unicode spelling is rejected at its first such byte rather than folded.
pub open spec fn pane_hint_byte_spec(byte: u8) -> bool {
    (b'a' <= byte && byte <= b'z') || (b'0' <= byte && byte <= b'9') || byte == b'-'
}

/// The whole `herdr_agent` decision: accepted iff the bytes are nonempty and
/// every byte is `[a-z0-9-]`. Case is significant and nothing is trimmed.
///
/// This is the parse of untrusted config text before it enters the host's own
/// environment (ADR-0018), not a sandbox authorization: the launcher's re-exec
/// reads an already-validated [`PaneAgentHint`].
// The `<=` spelling (rather than clippy's suggested `(b'a'..=b'z').contains`) is
// kept so the exec bytes stay syntactically the predicate the `verus!` spec fn
// unfolds to — the same allow and the same reason as
// `config_mounts::mount_set_name_bytes`.
#[allow(clippy::manual_range_contains)]
pub fn pane_hint_token_bytes(bytes: &[u8]) -> (valid: bool)
    ensures
        valid == (bytes@.len() > 0
            && forall|i: int| 0 <= i < bytes@.len() ==> pane_hint_byte_spec(bytes@[i])),
{
    let len = bytes.len();
    if len == 0 {
        return false;
    }
    let mut i: usize = 0;
    while i < len
        invariant
            i <= len,
            len == bytes@.len(),
            len > 0,
            forall|j: int| 0 <= j < i ==> pane_hint_byte_spec(bytes@[j]),
        decreases len - i,
    {
        let byte = bytes[i];
        if !((b'a' <= byte && byte <= b'z')
            || (b'0' <= byte && byte <= b'9')
            || byte == b'-')
        {
            // `i` is the counterexample: inside the slice and not accepted.
            return false;
        }
        i += 1;
    }
    true
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
         Required: a string `name` and `command`; an optional string `herdr_agent`; \
         `args`, `credentials`, `tools`, `persist`, `mounts` and `network_requests` are arrays of \
         strings; `env` is a table of string values; \
         the top-level `image` and each tool's `command` are strings; the top-level \
         `sources`, accepted only in the project tier, is an array of `[[sources]]` tables \
         (or `sources = []`); the top-level \
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

pub(crate) fn utf8_error(file: &Path) -> anyhow::Error {
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

pub(crate) fn line_column(text: &str, offset: usize) -> (usize, usize) {
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

    /// ADR-0076 R3: the verified project config may now grant egress. Its
    /// `[network]` is adopted through the ADR-0073 verdict and reported like any
    /// other contributing `[network]` table.
    #[test]
    fn project_network_table_is_adopted_after_the_verified_read() {
        let f = Fixture::new();
        f.project("[network]\nallow_lan = true\nallow_egress = [\"10.0.0.0/8\"]");
        let report = f
            .load()
            .expect("the verified project config may grant egress");
        assert_eq!(
            report.user_network(),
            Some(&UserNetwork::for_test(
                &f.project,
                user_network::SavedGroups {
                    lan: Some(true),
                    ..Default::default()
                },
                &["10.0.0.0/8"],
            ))
        );
        assert_eq!(report.user_network().unwrap().file(), f.project);
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

    /// Present-empty is still present: the project config's `[network]` is
    /// recorded and grants nothing (ADR-0076 R3).
    #[test]
    fn empty_project_network_table_is_adopted_and_grants_nothing() {
        let f = Fixture::new();
        f.project("[network]");
        let report = f.load().expect("an empty [network] is adopted");
        assert_eq!(
            report.user_network(),
            Some(&UserNetwork::for_test(&f.project, Default::default(), &[]))
        );
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

    /// ADR-0076 R3: a verified project config's own `mounts` is adopted, empty and
    /// non-empty alike. A wrong type is still a schema error, from the mount
    /// parser rather than a refusal.
    #[test]
    fn project_mounts_are_adopted_after_the_verified_read() {
        for (body, expected) in [("mounts = []\n", 0usize), ("mounts = [\"/a:/g:ro\"]\n", 1)] {
            let f = Fixture::new();
            f.project(body);
            let report = f.load().unwrap_or_else(|error| panic!("{body}: {error}"));
            assert_eq!(
                report.user_mounts().map(UserMounts::len),
                Some(expected),
                "{body}"
            );
        }
        let f = Fixture::new();
        f.project("mounts = \"x\"\n");
        let error = f.load().unwrap_err().to_string();
        assert!(error.contains("must be an array"), "{error}");
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
            ("default_tools", "[]"),
            ("egress_sets", "{}"),
            ("image", "\"agent-vm-standard:local\""),
            ("mounts", "[]"),
            ("mount_sets", "{}"),
            ("network", "{}"),
            ("sources", "[]"),
            ("tools", "[]"),
            ("use_tools", "[]"),
        ];
        assert_eq!(fields.map(|(name, _)| name), TOP_LEVEL_FIELDS);
        for (name, value) in fields {
            // `sources` and `use_tools` are the project config's own keys (flat
            // sourcing, ADR-0074; project-only choices, #749); every other field
            // still loads in the user tier.
            let result = if matches!(name, "sources" | "use_tools") {
                SourcesFixture::new().with_project(&format!("{name} = {value}\n"))
            } else {
                Fixture::new().user(&format!("{name} = {value}\n")).load()
            };
            result.unwrap_or_else(|error| panic!("{name} must be a top-level field: {error:#}"));
        }
    }

    /// Every field the writer may refuse a stray `image` in is a top-level field of
    /// this schema, so the policy beside [`RawConfig`] cannot name a table serde
    /// would refuse first, and a renamed field breaks this before it silently stops
    /// being checked in the writer.
    #[test]
    fn image_owner_fields_are_top_level_fields() {
        for (name, owner) in IMAGE_OWNER_FIELDS {
            assert!(
                TOP_LEVEL_FIELDS.contains(&name),
                "{name} ({}) is a top-level field",
                owner.label()
            );
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
        // ADR-0076 R3: the set tables are the *only* project-side authority
        // fields refused now, and they are refused before the adopted fields.
        for (body, expected) in [
            (
                "[egress_sets]\n[network]\nallow_host = true\n",
                "egress_sets cannot be declared by the project config",
            ),
            (
                "mounts = []\n[egress_sets]\n",
                "egress_sets cannot be declared by the project config",
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
        // A project config's own top-level `mounts` is a direct declaration, not a
        // set reference: it is adopted through the verified read, and a name that
        // only the user config's `[mount_sets]` defines is a different namespace
        // (ADR-0076 R3).
        let f = Fixture::new();
        f.user("[mount_sets]\nagent = [\"/a:/g:ro\"]\n");
        f.project("mounts = [\"/p:/g:ro\"]\n");
        let report = f.load().expect("a project mount is adopted");
        assert_eq!(report.user_mounts().map(UserMounts::len), Some(1));
        // The set tables are refused before the adopted `[network]`.
        let f = Fixture::new();
        f.project("[mount_sets]\n[network]\nallow_host = true\n");
        let error = f.load().unwrap_err().to_string();
        assert!(
            error.contains("mount_sets cannot be declared by the project config"),
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
        // #749: a declaration is a launch verb, so the catalog lists `t` — and
        // the measured verdict that let the file load is exactly what refuses the
        // launch.
        assert_eq!(launch_names(&report), ["t"]);
        assert!(report.resolved().labels().any(|label| label == "t"));

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
        f.user(&tool(
            "name = \"t\"\ncommand = \"t\"\n[tools.env]\nmounts = \"~/private:ro\"\n",
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
            // The refusal must name the tool's own field, which is this row's
            // subject.
            f.user(&format!(
                "# tools-only\n{}",
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
        // Launching the user's `pi` definition (`home:pi`, since the project owns
        // the bare name) still selects the user list.
        assert_eq!(guest_mounts(&catalog, "home:pi"), ["/synthetic-home/.pi"]);

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
        // #749: omitted and `tools = []` are the same list — nothing — so a
        // declared shell inherits the agent's mounts only when a `default_tools`
        // list grants them (see `the_shell_affordance_gets_the_effective_defaults`).
        let f = Fixture::new();
        f.user(&declared(""));
        let catalog = f.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(guest_mounts(&catalog, "home:shell"), ["/s"]);
        assert!(
            catalog.has_shell_fallback(),
            "E3: a user-declared shell is qualified, and the bare verb is the fallback"
        );

        // `tools = []`: its own list only, unchanged.
        let f = Fixture::new();
        f.user(&declared("tools = []\n"));
        let catalog = f.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(guest_mounts(&catalog, "home:shell"), ["/s"]);

        // `default_tools` is what grants the agent's list now — to the affordance,
        // which is the fallback here. The qualified declaration keeps its own.
        let f = Fixture::new();
        f.user(&format!("default_tools = [\"agent\"]\n{}", declared("")));
        let catalog = f.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(guest_mounts(&catalog, "shell"), ["/a"]);
        assert_eq!(guest_mounts(&catalog, "home:shell"), ["/s"]);

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

        // A project shell's list covers only project definitions, which cannot
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
    /// user's mount list and pane agent hint are not grafted onto it, and the
    /// differing fields are reported with `mounts` before `herdr_agent`.
    #[test]
    fn whole_definition_merge_never_fills_user_omissions() {
        // The user tool declares a mount list and a pane hint; the project's
        // same-name definition declares neither but authorizes the verb, so it
        // wins whole — and neither of the user's fields is filled in. The pair is
        // the same shape as `env` below: a hint is a definition field, not an
        // overlay.
        let f = Fixture::new();
        f.user(&tool(
            "name = \"t\"\ncommand = \"cmd\"\nmounts = [\"/a:/a:ro\"]\nnetwork_requests = [\"a.example\"]\nherdr_agent = \"user-agent\"\n",
        ));
        f.project(&tool(
            "name = \"t\"\ncommand = \"cmd\"\nnetwork_requests = [\"b.example\"]\n",
        ));
        let report = f.load().unwrap();
        assert_eq!(report.conflicts().len(), 1);
        assert_eq!(
            report.conflicts()[0].fields(),
            &[
                ToolField::NetworkRequests,
                ToolField::Mounts,
                ToolField::HerdrAgent
            ]
        );
        let catalog = report.into_launch_catalog().unwrap();
        assert_eq!(
            entry_of(&catalog, "t").tool().herdr_agent(),
            None,
            "the bare name's definition declares no hint, and the other's is never grafted on"
        );
        assert_eq!(
            entry_of(&catalog, "home:t")
                .tool()
                .herdr_agent()
                .map(PaneAgentHint::as_str),
            Some("user-agent"),
            "the user's own definition keeps its own hint"
        );
        assert_eq!(
            guest_mounts(&catalog, "t"),
            Vec::<String>::new(),
            "the bare name's definition declares no mounts, and the other's are never grafted on"
        );
        assert_eq!(
            guest_mounts(&catalog, "home:t"),
            ["/a"],
            "the user's own definition keeps its own mount list"
        );

        // Omitting the user's mount list is *not* a difference: presence is an
        // authority fact, not access. The project entry is explicit, so the
        // identical-definition override is what `same_definition` compares (#735
        // review S10).
        let f = Fixture::new();
        f.user(&tool("name = \"t\"\ncommand = \"cmd\"\n"));
        f.project(&tool("name = \"t\"\ncommand = \"cmd\"\n"));
        assert!(f.load().unwrap().conflicts().is_empty());

        // A project cannot fill an omitted user `tools`/`env`/`persist` either.
        let f = Fixture::new();
        f.user(&tool("name = \"t\"\ncommand = \"cmd\"\n"));
        // `tools = []` would be the same value as the user's omitted field (both
        // are "no other tools"), so a non-empty list is what makes the field
        // differ — #749 retired the `["*"]` spelling that used to do this.
        f.project(&format!(
            "{}{}",
            tool("name = \"t\"\ncommand = \"cmd\"\ntools = [\"u\"]\npersist = [\"p\"]\n[tools.env]\nA = \"1\"\n"),
            tool("name = \"u\"\ncommand = \"u\"\n")
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
        let catalog = report.into_launch_catalog().unwrap();
        let winner = entry_of(&catalog, "t").tool();
        assert_eq!(winner.persist_count(), 1);
        assert_eq!(winner.env_count(), 1);
        assert_eq!(
            winner.declared_tools(),
            [ToolName("u".to_owned())],
            "the bare name's own fields, never a splice of the other's"
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
            "\
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
        assert_eq!(verbs_of(&catalog), ["first", "second", "shell"]);
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

    /// #749: the compiled-in catalog applies only when no readable tier declares
    /// a tool, so a source definition retained beside it is *also* a launch verb —
    /// and every defined reference is still validated, dangling ones included.
    #[test]
    fn defaults_path_validates_and_launches_a_sources_definitions() {
        // (a) The dangling name is refused, naming the source file.
        let f = SourcesFixture::new();
        f.write_repo(
            "r.toml",
            "[[tools]]\nname = \"a\"\ncommand = \"a\"\ntools = [\"missing\"]\n",
        );
        f.write_project(&sources_block(&["repo ./r.toml"]));
        let report = f.load().expect("the source declares a tool");
        assert!(
            !report.uses_defaults(),
            "declaring any [[tools]] replaces the shipped catalog (ADR-0017)"
        );
        let error = format!("{:#}", report.into_launch_catalog().unwrap_err());
        assert!(
            error.contains("names no tool in this configuration file"),
            "{error}"
        );

        // (b) Sibling control: a resolvable pair builds, and both are verbs
        // beside the shipped catalog.
        let f = SourcesFixture::new();
        f.write_repo(
            "r.toml",
            "[[tools]]\nname = \"a\"\ncommand = \"a\"\ntools = [\"b\"]\n\
             [[tools]]\nname = \"b\"\ncommand = \"b\"\ntools = []\n",
        );
        f.write_project(&sources_block(&["repo ./r.toml"]));
        let report = f.load().expect("a resolvable pair");
        assert!(!report.uses_defaults());
        let catalog = report.into_launch_catalog().expect("the declared catalog");
        assert_eq!(verbs_of(&catalog), ["a", "b", "shell"]);

        // (c) Cross-tier: the shipped `pi` is never a fallback for a source file.
        let f = SourcesFixture::new();
        f.write_repo(
            "r.toml",
            "[[tools]]\nname = \"a\"\ncommand = \"a\"\ntools = [\"pi\"]\n",
        );
        f.write_project(&sources_block(&["repo ./r.toml"]));
        let error = format!("{:#}", f.load().unwrap().into_launch_catalog().unwrap_err());
        assert!(
            error.contains("names no tool in this configuration file"),
            "the shipped catalog is not a fallback for a source file: {error}"
        );
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
        f.user("# tools-only\n");
        f.project(&format!(
            "# tools-only\n[[tools]]\nname = \"p\"\ncommand = \"p\"\n\
             mounts = [{}]\n",
            entries(half + 1, "/a/")
        ));
        assert!(f.load().is_ok(), "the project tier alone fits");

        let f = Fixture::new();
        f.user(&format!(
            "[[tools]]\nname = \"u\"\ncommand = \"u\"\n\
             mounts = [{}]\n",
            entries(half, "/b/")
        ));
        f.project("# tools-only\n");
        assert!(f.load().is_ok(), "the user tier alone fits");

        // Together they exceed it, and the refusal names the user file.
        let f = Fixture::new();
        f.user(&format!(
            "[[tools]]\nname = \"u\"\ncommand = \"u\"\n\
             mounts = [{}]\n",
            entries(half, "/b/")
        ));
        f.project(&format!(
            "# tools-only\n[[tools]]\nname = \"p\"\ncommand = \"p\"\n\
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
            "[[tools]]\nname = \"u\"\ncommand = \"u\"\n\
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
            "{}\n[[tools]]\nname = \"p\"\ncommand = \
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
            "[[tools]]\nname = \"p\"\ncommand = \"p\"\ntools = []\n\
             mounts = [{}]\n",
            entries(k, "/p/")
        ));
        f.user(&format!(
            "[[tools]]\nname = \"u\"\ncommand = \"u\"\ntools = []\n\
             mounts = [{}]\n",
            entries(m, "/u/")
        ));
        let report = f.load().expect("both tiers fit");
        let (catalog, work) = report.into_launch_catalog_with_work();
        assert!(catalog.is_ok(), "{catalog:?}");
        assert_eq!(work.used(), LIMIT);

        let f = Fixture::new();
        f.project(&format!(
            "[[tools]]\nname = \"p\"\ncommand = \"p\"\ntools = []\n\
             mounts = [{}]\n",
            entries(k, "/p/")
        ));
        f.user(&format!(
            "[[tools]]\nname = \"u\"\ncommand = \"u\"\ntools = []\n\
             mounts = [{}]\n",
            entries(m + 1, "/u/")
        ));
        let report = f.load().expect("the load itself still fits");
        let (catalog, work) = report.into_launch_catalog_with_work();
        let error = format!("{:#}", catalog.expect_err("the catalog fold exceeds"));
        assert!(error.contains("tool \"p\""), "{error}");
        assert_eq!(work.used(), LIMIT);
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
                documented.herdr_agent(),
                shipped.herdr_agent(),
                "{}",
                shipped.name()
            );
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
        // The affordance is the shipped fallback (E3: a user-declared `shell` stays
        // qualified), and the documented `default_tools` header is what grants it
        // the agent set and the Pi fork.
        assert!(catalog.has_shell_fallback());
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
            write_file(&self.user, contents);
            self
        }

        /// The project config's tools are authorized **unless the user file
        /// already declares that name**: a project-side authorization overrides
        /// the user's verb (ADR-0075 D3), and the pre-#735 merge tests exist to
        /// pin the *shadowed* shape, where the user definition wins and the
        /// project one stays in its own reference scope.
        fn project(&self, contents: &str) -> &Self {
            write_file(&self.project, contents);
            self
        }
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
            fs::write(&self.config, body).unwrap();
            self
        }

        fn write_user(&self, body: &str) -> &Self {
            let path = self.user_config();
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, body).unwrap();
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

        /// The production load, with one in-session approval retry: if the only
        /// thing standing in the way is a pending pinned source, approve exactly
        /// the bytes inspection read and load again.
        ///
        /// This keeps every `#748` positive row measuring the adopted/inert
        /// behaviour it was written for, and it goes through the real store and
        /// the real policy — the approval is not a permissive stand-in.
        fn load(&self) -> Result<ConfigReport> {
            match load(&self.paths()) {
                Err(error)
                    if error
                        .downcast_ref::<crate::config_pins::UnapprovedSources>()
                        .is_some() =>
                {
                    self.approve_pending();
                    load(&self.paths())
                }
                other => other,
            }
        }

        /// The load without the fixture's approval retry: what a real
        /// non-interactive launch sees.
        fn load_unapproved(&self) -> Result<ConfigReport> {
            load(&self.paths())
        }

        /// Approve every pending pinned source through one real store commit.
        fn approve_pending(&self) {
            approve_all_pinned(&self.paths());
        }

        /// Write the project config and load, the shape most `sources` rows take.
        fn with_project(&self, body: &str) -> Result<ConfigReport> {
            self.write_project(body);
            self.load()
        }
    }

    /// `[[sources]]` is bounded by count, and the bound is the documented one:
    /// one past it refuses the load with a sentence that names the limit and none
    /// of the entries, and exactly the limit loads.
    #[test]
    fn more_sources_than_the_bound_refuse_the_load() {
        let limit = crate::config_sources::MAX_DECLARED_SOURCES;
        let f = SourcesFixture::new();
        let mut over = String::new();
        for index in 0..=limit {
            let file = f.write_repo(&format!("s{index}.toml"), "# pinned\n");
            over.push_str(&source_table(&format!("s{index}"), &file, false, false));
        }
        let error = format!(
            "{:#}",
            f.with_project(&over).expect_err("one past the limit")
        );
        assert!(
            error.contains(&format!("sources: more than {limit} declared sources")),
            "the limit must be named: {error}"
        );
        assert!(
            !error.contains(&format!("s{limit}.toml")),
            "the refusal is value-free: {error}"
        );

        let mut permitted = String::new();
        for index in 0..limit {
            permitted.push_str(&source_table(
                &format!("s{index}"),
                &f.repo(&format!("s{index}.toml")),
                false,
                false,
            ));
        }
        let report = f.with_project(&permitted).expect("exactly the limit");
        assert_eq!(report.sources().entries().len(), limit);
    }

    /// A valid TOML body of exactly `size` bytes: one comment line, so a fixture
    /// can be large without declaring anything.
    fn comment_config(size: usize) -> String {
        let mut body = String::from("#");
        body.push_str(&"x".repeat(size - 2));
        body.push('\n');
        assert_eq!(body.len(), size);
        body
    }

    /// The per-file ceiling is not a bound on the list: eight files that are each
    /// legal under `MAX_CONFIG_FILE_BYTES` cost more than the declared sources may
    /// read in total, so the load refuses instead of parsing them all. The same
    /// eight, smaller, load.
    #[test]
    fn the_declared_sources_share_one_byte_budget() {
        let f = SourcesFixture::new();
        let mut over = String::new();
        for index in 0..8 {
            let file = f.write_repo(&format!("big{index}.toml"), &comment_config(700 * 1024));
            over.push_str(&source_table(&format!("s{index}"), &file, false, false));
        }
        let error = format!("{:#}", f.with_project(&over).expect_err("over the total"));
        assert!(
            error.contains(&format!(
                "the declared sources read more than {MAX_SOURCE_BYTES_TOTAL} bytes in total"
            )),
            "the total must be named: {error}"
        );
        assert!(
            !error.contains("xxxx"),
            "the refusal names no contents: {error}"
        );

        let mut under = String::new();
        for index in 0..8 {
            let file = f.write_repo(&format!("small{index}.toml"), &comment_config(400 * 1024));
            under.push_str(&source_table(&format!("s{index}"), &file, false, false));
        }
        f.with_project(&under).expect("under the total");
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
    fn a_project_declared_shell_suppresses_the_fallback() {
        // E3: the bare route belongs to a project entry or the fallback, so a
        // project declaration is the one declaration that takes it over.
        let fixture = Fixture::new();
        fixture.project("[[tools]]\nname = \"shell\"\ncommand = \"zsh\"\n");
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert!(!catalog.has_shell_fallback());
        assert_eq!(catalog.as_slice().len(), 1);
        assert_eq!(catalog.as_slice()[0].tool().name(), "shell");
        assert_eq!(catalog.as_slice()[0].tool().command(), "zsh");

        // A user declaration keeps its qualified spelling and the fallback stays.
        let fixture = Fixture::new();
        fixture.user("[[tools]]\nname = \"shell\"\ncommand = \"zsh\"\n");
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert!(catalog.has_shell_fallback());
        assert_eq!(entry_of(&catalog, "home:shell").tool().command(), "zsh");
        assert_eq!(entry_of(&catalog, "shell").tool().command(), "bash");
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
        entry_of(catalog, name).provisioned().iter().collect()
    }

    /// The catalog entry named `name` — a launch verb or the appended fallback.
    fn entry_of<'a>(catalog: &'a LaunchCatalog, name: &str) -> &'a CatalogEntry {
        catalog
            .as_slice()
            .iter()
            .find(|entry| entry.label() == name || entry.qualified_label() == Some(name))
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
    /// Every launch label, in catalog order (#749): the bare name or the
    /// qualified `<alias>:<name>` of a shadowed definition.
    fn verbs_of(catalog: &LaunchCatalog) -> Vec<String> {
        catalog
            .as_slice()
            .iter()
            .map(|entry| entry.label().to_string())
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

    /// **T2, #749.** An omitted `tools` names nothing for **any** tool: the
    /// shell's implicit wildcard is retired, and Row 3 pins that the declared
    /// shell and the explicit `tools = []` now agree. The shipped list reaches a
    /// shell launch through `default_tools` instead.
    #[test]
    fn an_omitted_tools_list_names_nothing_for_any_tool() {
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

        // Row 3 (#749): a declared `shell` with an omitted `tools` list is the
        // same as `tools = []` — the implicit wildcard is retired — so it
        // provisions nothing by itself. `default_tools` is what grants now.
        let fixture = Fixture::new();
        fixture.user(
            "[[tools]]\nname = \"shell\"\ncommand = \"zsh\"\n[[tools]]\nname = \"claude\"\ncommand = \"claude\"\ncredentials = [\"anthropic\"]\n",
        );
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(
            provisioned_of(&catalog, "shell"),
            Vec::<CredentialProvider>::new()
        );

        // Row 4: `tools = []` on a declared `shell` is the same empty list.
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
        assert_eq!(notshell.declared_tools(), []);
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
             [[tools]]\nname = \"all\"\ncommand = \"all\"\ntools = [\"a\", \"b\", \"c\", \"all\"]\n",
        );
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(provisioned_of(&catalog, "a"), vec![Anthropic, OpenAi]);
        assert_eq!(provisioned_of(&catalog, "b"), vec![Anthropic, OpenAi]);
        assert_eq!(provisioned_of(&catalog, "c"), vec![Copilot]);
        // A cycle, a repeated edge and a list that names itself each add one
        // contribution per definition, and the paths fold in arena order.
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

        // The same shape across tiers: the project `a` closes a cycle with the
        // project `b` it names, never with the user's own `a`.
        let fixture = Fixture::new();
        fixture
            .user("[[tools]]\nname = \"a\"\ncommand = \"user-a\"\ncredentials = [\"anthropic\"]\n")
            .project(
                "[[tools]]\nname = \"a\"\ncommand = \"project-a\"\ncredentials = [\"openai\"]\ntools = [\"b\"]\n\
                 [[tools]]\nname = \"b\"\ncommand = \"b\"\ncredentials = [\"copilot\"]\ntools = [\"a\"]\n",
            );
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(
            provisioned_of(&catalog, "home:a"),
            vec![Anthropic],
            "the user definition is its own closure"
        );
        assert_eq!(
            provisioned_of(&catalog, "a"),
            vec![OpenAi, Copilot],
            "the project's `a` closes over the project `b`, never the user's"
        );
        assert_eq!(
            provisioned_of(&catalog, "b"),
            vec![OpenAi, Copilot],
            "the project's `b` closes over the project `a`"
        );
        assert_eq!(names_of(&catalog, "b"), ["copilot", "openai"]);
    }

    /// **T3 / §A1.** A `tools` list names definitions in the declaring tool's
    /// **own configuration file**, never the merged catalog: the retired `*`
    /// meant exactly that file, and #749 spells the names out. Two same-file
    /// tools group; a tool in the other tier does not, and naming it is refused.
    #[test]
    fn a_tools_list_closes_over_its_own_file_only() {
        use CredentialProvider::*;
        let fixture = Fixture::new();
        fixture
            .user(
                "[[tools]]\nname = \"w\"\ncommand = \"w\"\ncredentials = [\"copilot\"]\ntools = [\"u\"]\n\
                 [[tools]]\nname = \"u\"\ncommand = \"u\"\ncredentials = [\"openai\"]\n",
            )
            .project(
                "[[tools]]\nname = \"p\"\ncommand = \"p\"\ncredentials = [\"anthropic\"]\n",
            );
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(provisioned_of(&catalog, "w"), vec![OpenAi, Copilot]);
        assert!(
            !provisioned_of(&catalog, "w").contains(&Anthropic),
            "the project tier is a different file"
        );
        // Naming the other file's tool is the refusal, not a silent skip.
        let fixture = Fixture::new();
        fixture
            .user("[[tools]]\nname = \"w\"\ncommand = \"w\"\ntools = [\"p\"]\n")
            .project("[[tools]]\nname = \"p\"\ncommand = \"p\"\n");
        let error = format!(
            "{:#}",
            fixture.load().unwrap().into_launch_catalog().unwrap_err()
        );
        assert!(
            error.contains("names no tool in this configuration file"),
            "{error}"
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
            provisioned_of(&catalog, "home:p"),
            vec![Anthropic],
            "the user's `p` is the referenced definition"
        );
        assert_eq!(
            provisioned_of(&catalog, "p"),
            vec![Copilot],
            "the project's own `p` owns the bare spelling"
        );
    }

    /// The body shared by U2's rows: a hidden project `pi`, a `bridge` that closes
    /// a cycle with it, a `helper` two edges away and a project wildcard.
    const PROJECT_CYCLE_BODY: &str = "[[tools]]\nname = \"pi\"\ncommand = \"project-pi\"\n\
         credentials = [\"anthropic\", \"project-service\"]\npersist = [\".project-pi\"]\ntools = [\"bridge\"]\n\
         [[tools]]\nname = \"bridge\"\ncommand = \"bridge\"\ncredentials = [\"bridge-service\"]\n\
         persist = [\".bridge\"]\ntools = [\"pi\"]\n\
         [[tools]]\nname = \"helper\"\ncommand = \"helper\"\ntools = [\"bridge\"]\npersist = [\".helper\"]\n\
         [[tools]]\nname = \"wide\"\ncommand = \"wide\"\n\
         tools = [\"pi\", \"bridge\", \"helper\", \"wide\"]\npersist = [\".wide\"]\n";

    /// **U2 / §A3.** The rule holds transitively and through a full list, and all
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

        // `wide`'s list names every project definition, hidden `pi` included, and
        // reaches neither the user tier nor the shipped agents.
        assert_eq!(provisioned_of(&catalog, "wide"), vec![Anthropic]);
        assert_eq!(
            names_of(&catalog, "wide"),
            ["anthropic", "bridge-service", "project-service"]
        );
        assert_eq!(
            persist_of(&catalog, "wide"),
            [".project-pi", ".bridge", ".helper", ".wide"],
            "a list that includes itself still contributes each definition once"
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
    /// Ownership is a launch property (#749): two *separate* definitions may
    /// claim one path, but a launch whose own `tools` closure meets a claim is
    /// refused — and every definition is a launch, so there is no hidden pair.
    #[test]
    fn ownership_checks_cover_each_selected_closure_only() {
        // User `pi` and project `pi` claim one path; each is alone in its own
        // tier-local closure, so no launch links both.
        let fixture = Fixture::new();
        fixture
            .user("[[tools]]\nname = \"pi\"\ncommand = \"user-pi\"\npersist = [\".shared\"]\n")
            .project(
                "[[tools]]\nname = \"pi\"\ncommand = \"project-pi\"\npersist = [\".shared\"]\n",
            );
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(persist_of(&catalog, "pi"), [".shared"]);
        assert_eq!(persist_of(&catalog, "home:pi"), [".shared"]);

        // A closure that overlaps itself is refused when that tool launches,
        // naming both members.
        const PROJECT: &str = "[[tools]]\nname = \"a\"\ncommand = \"project-a\"\npersist = [\"cache\"]\ntools = [\"b\"]\n\
             [[tools]]\nname = \"b\"\ncommand = \"project-b\"\npersist = [\"cache/x\"]\n";
        let fixture = Fixture::new();
        fixture.project(PROJECT);
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

        // #749: a declared `shell` reaches its own tier's siblings only when
        // `default_tools` names them — the implicit wildcard is retired — and
        // never the other tier's.
        let fixture = Fixture::new();
        fixture
            .user(
                "default_tools = [\"sibling\"]\n\
                 [[tools]]\nname = \"shell\"\ncommand = \"bash\"\npersist = [\".u\"]\n\
                 [[tools]]\nname = \"sibling\"\ncommand = \"sibling\"\npersist = [\".s\"]\n",
            )
            .project("[[tools]]\nname = \"sibling\"\ncommand = \"project-sibling\"\npersist = [\".p\"]\n");
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        // E3: the affordance is the fallback, so it receives the declared
        // default; the user's qualified `shell` keeps its own facet.
        assert_eq!(
            persist_of(&catalog, "shell"),
            [".s"],
            "the declared default reaches this tier's sibling, and nothing from the project"
        );
        assert_eq!(persist_of(&catalog, "home:shell"), [".u"]);
        assert!(catalog.has_shell_fallback());

        // An omitted list and `tools = []` are the same empty list.
        let fixture = Fixture::new();
        fixture.user(
            "[[tools]]\nname = \"shell\"\ncommand = \"bash\"\ntools = []\npersist = [\".u\"]\n\
             [[tools]]\nname = \"sibling\"\ncommand = \"sibling\"\npersist = [\".s\"]\n",
        );
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(persist_of(&catalog, "home:shell"), [".u"]);
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
        // `*` is retired in any shape, alone or mixed, and the refusal names the
        // working replacement (#749). A valid named list is the control, below.
        for body in [
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\ntools = [\"*\", \"claude\"]\n",
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\ntools = [\"*\"]\n",
        ] {
            let fixture = Fixture::new();
            fixture.user(body);
            let rendered = format!("{:#}", fixture.load().unwrap_err());
            assert!(rendered.contains("`*` is retired"), "{body}: {rendered}");
            assert!(rendered.contains("default_tools"), "{body}: {rendered}");
        }

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
        // The project definition wins the bare name, so the entry launched as
        // `t` is the one with `interactive_shell = true`. The field still
        // round-trips and still sorts last in the conflict report, which is this
        // test's subject.
        let catalog = report.into_launch_catalog().unwrap();
        assert!(entry_of(&catalog, "t").tool().is_interactive_shell());
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

    /// A1: `herdr_agent` is legal in every tier, and the hint a launch would read
    /// is the declared spelling — no trimming, folding or allowlist. The two
    /// source rows are the ones worth pinning: an out-of-checkout verified read
    /// (`trust = true`, `allow = false`) and an in-checkout pinned read
    /// (`trust = false`, `allow = false`) take different read paths to the same
    /// validator.
    #[test]
    fn pane_hint_parses_in_every_tool_tier() {
        const HINT: &str = "future-agent-9";
        // `-` is a legal whole hint: the grammar has no "must start with a
        // letter" clause and no label allowlist, so nothing rejects it.
        let declarations = format!(
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\nherdr_agent = \"{HINT}\"\n\
             [[tools]]\nname = \"dash\"\ncommand = \"t\"\nherdr_agent = \"-\"\n\
             [[tools]]\nname = \"plain\"\ncommand = \"t\"\n"
        );
        let hints = |tools: Vec<&Tool>| -> Vec<(String, Option<String>)> {
            tools
                .iter()
                .map(|tool| {
                    (
                        tool.name().to_owned(),
                        tool.herdr_agent().map(|hint| hint.as_str().to_owned()),
                    )
                })
                .collect()
        };
        let expected = vec![
            ("t".to_string(), Some(HINT.to_string())),
            ("dash".to_string(), Some("-".to_string())),
            ("plain".to_string(), None),
        ];

        // The shipped tier, through the embedded-catalog read.
        let shipped = tools_from_builtin_text(&declarations).unwrap();
        assert_eq!(hints(shipped.iter().collect()), expected);

        // The user tier, whose `t` is reachable as `home:t`.
        let user = Fixture::new();
        user.user(&declarations);
        let report = user.load().unwrap();
        assert_eq!(hints(report.resolved().launch_tools().collect()), expected);
        let catalog = report.into_launch_catalog().unwrap();
        assert_eq!(
            entry_of(&catalog, "home:t")
                .tool()
                .herdr_agent()
                .map(PaneAgentHint::as_str),
            Some(HINT)
        );

        // The project tier, whose `t` wins the bare spelling.
        let project = Fixture::new();
        project.project(&declarations);
        let catalog = project.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(
            entry_of(&catalog, "t")
                .tool()
                .herdr_agent()
                .map(PaneAgentHint::as_str),
            Some(HINT)
        );

        // A verified out-of-checkout source: 0600 file, 0700 directory, route
        // outside the checkout, no pin.
        let verified = SourcesFixture::new();
        let path = verified.base().join("team.toml");
        write_file(&path, &declarations);
        let catalog = verified
            .with_project(&source_table("team", &path, true, false))
            .expect("a verified source loads")
            .into_launch_catalog()
            .unwrap();
        assert_eq!(
            entry_of(&catalog, "team:t")
                .tool()
                .herdr_agent()
                .map(PaneAgentHint::as_str),
            Some(HINT)
        );

        // An in-checkout pinned source: refused until approved, then decoded
        // through the same validator.
        let pinned = SourcesFixture::new();
        let path = pinned.write_repo("team.toml", &declarations);
        pinned.write_project(&source_table("team", &path, false, false));
        let error = pinned.load_unapproved().expect_err("the source is pending");
        assert!(
            error
                .downcast_ref::<crate::config_pins::UnapprovedSources>()
                .is_some(),
            "the first load is a pin refusal: {error:#}"
        );
        let catalog = pinned
            .load()
            .expect("the real approval and reload succeed")
            .into_launch_catalog()
            .unwrap();
        assert_eq!(
            entry_of(&catalog, "team:t")
                .tool()
                .herdr_agent()
                .map(PaneAgentHint::as_str),
            Some(HINT)
        );
    }

    /// A1: the grammar is the whole rule, so every near-miss is refused with the
    /// tool, the declaration and the field named — and with **no** copy of the
    /// rejected value. A wrong type is not a token error at all: it stays on the
    /// generic redacted serde path.
    ///
    /// The detail is compared after the `declaration [i] tool "t": ` boundary
    /// instead of `contains` over the whole message: the prefix carries the
    /// config file's path, so a `TMPDIR` (or an ancestor) spelling a short
    /// rejected token such as `Pi` used to make a correct diagnostic "echo" it.
    /// Whole-message redaction is still asserted, on one high-entropy token no
    /// path can spell (#762 review M2).
    #[test]
    fn pane_hint_rejects_invalid_tokens() {
        const BOUNDARY: &str = " declaration [0] tool \"t\": ";
        const DETAIL: &str = "herdr_agent must match [a-z0-9-]+";
        fn detail_after_boundary<'a>(rendered: &'a str, boundary: &str) -> &'a str {
            rendered
                .split_once(boundary)
                .unwrap_or_else(|| panic!("no {boundary:?} in {rendered}"))
                .1
        }
        for value in [
            "",         // empty
            "Pi",       // uppercase
            "pi ",      // trailing space, not trimmed
            "p\\ti",    // a TOML-escaped tab
            "pi=codex", // `=`
            "pi/cli",   // `/`
            "pí",       // non-ASCII
        ] {
            let fixture = Fixture::new();
            fixture.user(&format!(
                "[[tools]]\nname = \"t\"\ncommand = \"t\"\nherdr_agent = \"{value}\"\n"
            ));
            let rendered = format!("{:#}", fixture.load().unwrap_err());
            assert_eq!(
                detail_after_boundary(&rendered, BOUNDARY),
                DETAIL,
                "value={value:?}"
            );
        }

        // Whole-diagnostic redaction, on a token long enough that a path cannot
        // account for a match. The exact detail is asserted too, so a regression
        // that appends the token to it fails here even if the token stayed short.
        const CANARY: &str = "pi-canary-9f3a2b7c";
        let fixture = Fixture::new();
        fixture.user(&format!(
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\nherdr_agent = \"{CANARY}!\"\n"
        ));
        let rendered = format!("{:#}", fixture.load().unwrap_err());
        assert!(
            !rendered.contains(CANARY),
            "the rejected token was echoed: {rendered}"
        );
        assert_eq!(
            detail_after_boundary(&rendered, BOUNDARY),
            DETAIL,
            "{rendered}"
        );

        // A wrong type is the redacted schema diagnostic, never the token rule.
        let fixture = Fixture::new();
        fixture.user("[[tools]]\nname = \"t\"\ncommand = \"t\"\nherdr_agent = 7\n");
        let rendered = format!("{:#}", fixture.load().unwrap_err());
        assert!(
            rendered.contains("invalid TOML or tool schema"),
            "{rendered}"
        );
        assert!(!rendered.contains("must match [a-z0-9-]+"), "{rendered}");
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
    /// its own reason. `is_err()` alone would be satisfiable by any other refusal,
    /// so each row writes the declaration alone and pins the sentence.
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
            // Written directly, so only the declaration can be what refuses this
            // body.
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
        // Arena order is user, then project (#749): the user's `a` keeps its
        // qualified spelling because the project wins the bare one.
        assert_eq!(launch_names(&report), ["z", "home:a", "b", "a", "c"]);
    }

    /// Two files may declare the same tool (#749). Nothing dedupes: the project
    /// wins the bare spelling and the user's definition keeps its own qualified
    /// one, so both are launchable. Identical definitions raise no shadow warning.
    #[test]
    fn identical_cross_tier_definitions_are_both_launchable() {
        let fixture = Fixture::new();
        fixture.user(&one_tool("dup")).project(&one_tool("dup"));
        let report = fixture.load().unwrap();
        assert!(report.conflicts().is_empty());
        assert_eq!(launch_names(&report), ["home:dup", "dup"]);
        let catalog = report.into_launch_catalog().unwrap();
        assert_eq!(
            entry_of(&catalog, "dup").tool().origin(),
            &ToolOrigin::Project(fixture.project.clone())
        );
        assert_eq!(
            entry_of(&catalog, "home:dup").tool().origin(),
            &ToolOrigin::User(fixture.user.clone())
        );
    }

    #[test]
    fn each_differing_field_is_reported_individually_in_fixed_order() {
        let base = "[[tools]]\nname = \"t\"\ncommand = \"cmd\"\nargs = [\"a\"]\ncredentials = [\"openai\"]\ntools = [\"base\"]\npersist = [\"p\"]\ninteractive_shell = false\nenv = { A = \"1\" }\nnetwork_requests = [\"a.example\"]\nherdr_agent = \"agent-a\"\n";
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
            ("herdr_agent = \"agent-b\"", ToolField::HerdrAgent),
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
                    ToolField::HerdrAgent => "herdr_agent = \"agent-a\"",
                    // Unreachable in this table: a project tool may not declare
                    // `mounts` at all, so its presence is a load error rather than
                    // a differing-field warning. Named here so the match stays
                    // exhaustive instead of gaining a catch-all.
                    ToolField::Mounts => unreachable!("project mounts are refused"),
                },
                mutated,
            );
            let fixture = Fixture::new();
            fixture.user(base).project(&project_body);
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
            )
            .replace("herdr_agent = \"agent-a\"", "herdr_agent = \"agent-b\"");
        let fixture = Fixture::new();
        fixture.user(base).project(&project_body);
        let report = fixture.load().unwrap();
        assert_eq!(report.conflicts().len(), 1);
        assert_eq!(
            report.conflicts()[0].fields(),
            &[
                ToolField::InteractiveShell,
                ToolField::Env,
                ToolField::NetworkRequests,
                ToolField::HerdrAgent
            ],
            "herdr_agent must be reported last"
        );
        assert_eq!(ToolField::Env.as_str(), "env");
        assert_eq!(ToolField::HerdrAgent.as_str(), "herdr_agent");
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
        // Names are visited in sorted order, so the report cannot depend on TOML
        // key order (#749); each name carries its own differing fields.
        assert_eq!(conflicts[0].tool(), "a");
        assert_eq!(
            conflicts[0].fields(),
            &[ToolField::Command, ToolField::Credentials]
        );
        assert_eq!(conflicts[1].tool(), "b");
        assert_eq!(conflicts[1].fields(), &[ToolField::Command]);
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
        // Both definitions launch (#749), each with its own fields: the bare name
        // is the project's, `home:t` is the user's and keeps its omissions.
        let catalog = report.into_launch_catalog().unwrap();
        assert_eq!(
            entry_of(&catalog, "t").tool().origin(),
            &ToolOrigin::Project(fixture.project.clone())
        );
        let user_entry = entry_of(&catalog, "home:t");
        assert_eq!(user_entry.tool().credentials(), &[]);
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

    /// #749: two separate tools may claim one normalized path. Ownership is a
    /// *launch* property now — each declaration is its own launch, so the two
    /// claims never meet unless one names the other in its `tools` closure.
    #[test]
    fn two_tools_may_claim_one_normalized_path_because_they_never_launch_together() {
        let fixture = Fixture::new();
        fixture.user(
            "[[tools]]\nname = \"one\"\ncommand = \"one\"\npersist = [\"./cache//x/\"]\n[[tools]]\nname = \"two\"\ncommand = \"two\"\npersist = [\"cache/x\"]\n",
        );
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(persist_of(&catalog, "one"), ["cache/x"]);
        assert_eq!(persist_of(&catalog, "two"), ["cache/x"]);

        // The control: make one name the other and the same pair is refused when
        // that one launches.
        let fixture = Fixture::new();
        fixture.user(
            "[[tools]]\nname = \"one\"\ncommand = \"one\"\npersist = [\"./cache//x/\"]\ntools = [\"two\"]\n[[tools]]\nname = \"two\"\ncommand = \"two\"\npersist = [\"cache/x\"]\n",
        );
        let error = format!(
            "{:#}",
            fixture.load().unwrap().into_launch_catalog().unwrap_err()
        );
        assert!(
            error.contains("one") && error.contains("two") && error.contains("cache/x"),
            "{error}"
        );
    }

    /// #749: a project tool and a user tool are separate launches even when they
    /// claim one path, so the load succeeds and each entry keeps its own claim.
    #[test]
    fn project_and_user_tools_may_claim_one_path_in_separate_launches() {
        let fixture = Fixture::new();
        fixture
            .user("[[tools]]\nname = \"u\"\ncommand = \"u\"\npersist = [\"shared/x\"]\n")
            .project("[[tools]]\nname = \"p\"\ncommand = \"p\"\npersist = [\"shared/x\"]\n");
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(persist_of(&catalog, "p"), ["shared/x"]);
        assert_eq!(persist_of(&catalog, "u"), ["shared/x"]);
    }

    #[test]
    fn a_projects_second_definition_keeps_its_own_persist_claim() {
        // The project's `dup` wins the bare name and its claim on `shared/x` is
        // its own; the user's `dup` and `other` are separate launches, so three
        // entries coexist and no load-time ownership check refuses them.
        let fixture = Fixture::new();
        fixture
            .user("[[tools]]\nname = \"dup\"\ncommand = \"dup\"\npersist = [\"p\"]\n[[tools]]\nname = \"other\"\ncommand = \"other\"\npersist = [\"shared/x\"]\n")
            .project("[[tools]]\nname = \"dup\"\ncommand = \"dup-different\"\npersist = [\"shared/x\"]\n");
        let report = fixture.load().unwrap();
        assert_eq!(report.resolved().launch_tools().len(), 3);
        let catalog = report.into_launch_catalog().unwrap();
        assert_eq!(persist_of(&catalog, "dup"), ["shared/x"]);
        assert_eq!(persist_of(&catalog, "home:dup"), ["p"]);
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

        // (b) Across two tools the load accepts it (#749): they are separate
        // launches. One naming the other is the closure rejection, tested beside
        // `two_tools_may_claim_one_normalized_path_because_they_never_launch_together`.
        let fixture = Fixture::new();
        fixture.user(
            "[[tools]]\nname = \"one\"\ncommand = \"one\"\npersist = [\".cache\"]\n[[tools]]\nname = \"two\"\ncommand = \"two\"\npersist = [\".cache/x\"]\n",
        );
        assert!(fixture.load().is_ok(), "separate launches may share a path");

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
        // #749: an omitted `tools` names nothing for any tool, `shell` included.
        assert!(persist_of(&catalog, "shell").is_empty());

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
                            root_id: self.project.identity(),
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

            // Arena order is every user declaration (qualified when a project
            // definition shadows it), then every project declaration (#749).
            let mut expected: Vec<String> = unique_user
                .iter()
                .map(|name| {
                    if unique_project.contains(name) {
                        format!("home:{name}")
                    } else {
                        name.clone()
                    }
                })
                .collect();
            expected.extend(unique_project.iter().cloned());
            let actual: Vec<String> = report.resolved().labels().map(str::to_owned).collect();
            proptest::prop_assert_eq!(actual, expected);

            // Every overlap keeps both definitions: the project's owns the bare
            // name, the user's is still reachable and still its own.
            let catalog = report.into_launch_catalog().unwrap();
            for name in &unique_user {
                if unique_project.contains(name) {
                    proptest::prop_assert_eq!(
                        entry_of(&catalog, name).tool().command(),
                        &format!("proj-{name}")
                    );
                    proptest::prop_assert_eq!(
                        entry_of(&catalog, &format!("home:{name}")).tool().command(),
                        &format!("user-{name}")
                    );
                }
            }
        }

        /// Two identical declarations do not dedupe (#749): the project wins the
        /// bare name, the user's keeps `home:<name>`, and identical definitions
        /// raise no shadow warning.
        #[test]
        fn duplicating_a_catalog_across_tiers_yields_two_labels(
            names in proptest::collection::vec("[a-z]{1,6}", 1..5),
        ) {
            let unique = dedupe(names);
            let body: String = unique.iter().map(|name| format!("[[tools]]\nname = \"{name}\"\ncommand = \"{name}\"\n")).collect();
            let fixture = Fixture::new();
            fixture.user(&body).project(&body);
            let report = fixture.load().unwrap();
            let mut expected: Vec<String> =
                unique.iter().map(|name| format!("home:{name}")).collect();
            expected.extend(unique.iter().cloned());
            let actual: Vec<String> = report.resolved().labels().map(str::to_owned).collect();
            proptest::prop_assert_eq!(actual, expected);
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

        /// **T7.3.** With every generated tool in one file, a tool whose `tools`
        /// list names the whole file provisions the union of that file's
        /// `credentials` — an independent re-derivation that never walks the
        /// closure — and a `default_tools` list naming the same tools agrees with
        /// it. (#749 retired the `["*"]` shorthand; the list is now spelled out,
        /// which is what the retired spelling meant.)
        #[test]
        fn a_single_file_closure_provisions_the_whole_files_credentials(
            creds in proptest::collection::vec(proptest::collection::vec(0u8..4, 0..3), 2..5),
        ) {
            let every: Vec<String> = (0..creds.len())
                .map(|index| {
                    let name = if index == 0 {
                        "shell".to_string()
                    } else {
                        format!("t{index}")
                    };
                    format!("\"{name}\"")
                })
                .collect();
            let mut body = format!("default_tools = [{}]\n", every.join(", "));
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
                    body.push_str(&format!("tools = [{}]\n", every.join(", ")));
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

            // The project's definitions own every bare name they declare, so a
            // user definition of the same name is listed as `home:<name>` (#749).
            let mut verbs: Vec<String> = (0..user.len())
                .map(|index| {
                    if index < project.len() {
                        format!("home:t{index}")
                    } else {
                        format!("t{index}")
                    }
                })
                .collect();
            for index in 0..project.len() {
                verbs.push(format!("t{index}"));
            }
            verbs.push("shell".to_string());
            proptest::prop_assert_eq!(verbs_of(&catalog), verbs);

            for (index, reach) in user_reach.iter().enumerate() {
                let name = if index < project.len() {
                    format!("home:t{index}")
                } else {
                    format!("t{index}")
                };
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
            for (index, reach) in project_reach.iter().enumerate() {
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
                    // The project owns the bare `t0`; the user's is `home:t0`.
                    proptest::prop_assert_eq!(provisioned_set(&catalog, "home:t0"), providers);
                    proptest::prop_assert_eq!(persist_of(&catalog, "home:t0"), persist);
                }
            }
        }

        /// **P2b.** A declared `shell`'s omitted `tools` is exactly its own tier's
        /// declared union; an explicit `[]` is its own definition only. A project
        /// declaration of the same name is a shadowed target, not something the
        /// user wildcard sweeps in.
        #[test]
        fn a_declared_shell_provisions_only_its_own_list(
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

            // #749: an omitted `tools` and `tools = []` are the same empty list,
            // so the shell's own facets are exactly its own declaration's — no
            // sibling's, no other tier's — whichever spelling the generator took.
            let _ = empty;
            let mut provisioned = BTreeSet::new();
            for provider in &credentials[0] {
                provisioned.insert(provider_from_u8(*provider));
            }
            // E3: a user-declared `shell` is qualified, so its own facets are read
            // at `home:shell` and the bare verb is the shipped fallback.
            proptest::prop_assert_eq!(provisioned_set(&catalog, "home:shell"), provisioned);
            proptest::prop_assert_eq!(persist_of(&catalog, "home:shell"), vec!["u-path-0"]);
            proptest::prop_assert!(catalog.has_shell_fallback());
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
                // #749 retired `["*"]`; the generator spells the same set out.
                let every: Vec<String> = (0..count).map(|index| format!("\"t{index}\"")).collect();
                body.push_str(&format!("tools = [{}]\n", every.join(", ")));
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
            .project("[[tools]]\nname = \"t\"\ncommand = \"t\"\nnetwork_requests = [\"B.example.\",\"a.example\",\"a.example:443\"]\n");
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
        let catalog = report.into_launch_catalog().unwrap();
        let winner = entry_of(&catalog, "t").tool();
        assert_eq!(
            winner
                .network_requests()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["a.example", "b.example"]
        );
        assert_eq!(winner.origin(), &ToolOrigin::Project(f.project.clone()));
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

    // -- sources (ADR-0076) ------------------------------------------------

    use crate::config_sources::Sourcing;

    /// The documented spelling of the user config as a trusted, allowed source:
    /// the implicit default's `trust = true, allow = true`.
    const HOME_SOURCE: &str = "home:trust:allow ~/.config/agent-vm/config.toml";
    /// A repository file sourced with neither attribute: pinned (#736) and inert.
    const REPO_SOURCE: &str = "repo ./.agent-vm/config.toml";

    /// Test-only shorthand for declaring sources: each element is
    /// `"<alias>[:trust][:allow] <path>"` and is emitted as a real `[[sources]]`
    /// table. The production parser accepts no string entries (ADR-0076); this
    /// keeps dozens of fixtures readable without restating four keys each time.
    fn sources_block(entries: &[&str]) -> String {
        if entries.is_empty() {
            // An explicit empty list, not an omitted key: it sources nothing.
            return "sources = []\n".to_string();
        }
        let mut out = String::new();
        for entry in entries {
            let (head, path) = entry.split_once(' ').expect("test shorthand has a space");
            let mut parts = head.split(':');
            let name = parts.next().expect("test shorthand has an alias");
            let mut trust = false;
            let mut allow = false;
            for flag in parts {
                match flag {
                    "trust" => trust = true,
                    "allow" => allow = true,
                    other => panic!("test shorthand does not know :{other}"),
                }
            }
            out.push_str(&format!("[[sources]]\nname = {name:?}\npath = {path:?}\n"));
            if trust {
                out.push_str("trust = true\n");
            }
            if allow {
                out.push_str("allow = true\n");
            }
        }
        out
    }

    /// The launch verbs a report offers, before the `shell` fallback is added.
    fn launch_names(report: &ConfigReport) -> Vec<String> {
        report.resolved().labels().map(str::to_owned).collect()
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
        assert!(entries[0].is_trusted());
        assert!(entries[0].is_allowed());
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
                "{}\n{}",
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
                "{}\n{}",
                sources_block(&[HOME_SOURCE, REPO_SOURCE]),
                one_tool("p")
            ))
            .expect("shadowed source tool loads");
        // #749: two sources declare `u` (the default user config is one), so the
        // bare spelling is refused naming both and each definition stays
        // reachable through its own qualified spelling.
        let catalog = report.into_launch_catalog().expect("catalog");
        let conflict = catalog
            .name_conflict("u")
            .expect("a user/source name collision is a conflict");
        assert!(conflict.refusal().to_string().contains("home:u"));
        assert!(conflict.refusal().to_string().contains("repo:u"));
        assert_eq!(entry_of(&catalog, "repo:u").tool().command(), "repo-u");
        assert_eq!(entry_of(&catalog, "home:u").tool().command(), "u");
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

        // A malformed value is refused by the `[[sources]]` schema, not the flat
        // refusal.
        let f = SourcesFixture::new();
        let error = format!(
            "{:#}",
            f.with_project("sources = \"bad\"\n").expect_err("schema")
        );
        assert!(
            error.contains("sources: must be an array of [[sources]] tables (or sources = [])"),
            "{error}"
        );

        // An unknown field is refused without echoing its value.
        let f = SourcesFixture::new();
        let error = format!(
            "{:#}",
            f.with_project("unknown_field = \"SECRET-734\"\n")
                .expect_err("unknown field")
        );
        assert!(!error.contains("SECRET-734"), "{error}");

        // An indirect self-source: the store is outside the checkout, so an
        // absolute external spelling reaches it and the descriptor identity —
        // not the flat-sourcing backstop — refuses it.
        let f = SourcesFixture::new();
        f.write_project(&source_table("self", f.project_config(), false, false));
        let error = format!("{:#}", f.load().expect_err("indirect self-source"));
        assert!(
            error.contains("the project config cannot source itself"),
            "the descriptor identity, not the flat-sourcing backstop, must fire: {error}"
        );
    }

    /// V10 (S3, ADR-0076 R3): an untrusted `allow = false` source's top-level
    /// `[network]` and `mounts` are **inert** — the file loads and grants nothing
    /// — while `[mount_sets]`/`[egress_sets]` stay refused by presence until
    /// #738. Its `[[tools]]` declarations are launch verbs (#749).
    #[test]
    fn v10_an_untrusted_source_declares_authority_inertly() {
        for (label, body) in [
            ("network", "[network]\n"),
            ("empty network", "[network]\nallow_lan = false\n"),
            ("malformed network", "network = 42\n"),
            ("mounts", "mounts = []\n"),
            ("malformed mounts", "mounts = \"bad\"\n"),
        ] {
            let f = SourcesFixture::new();
            f.write_repo(".agent-vm/config.toml", body);
            let report = f
                .with_project(&sources_block(&[REPO_SOURCE]))
                .unwrap_or_else(|error| panic!("{label}: {error}"));
            assert!(report.user_network().is_none(), "{label}");
            assert!(report.user_mounts().is_none(), "{label}");
        }

        // #749: a declaration is not a grant of top-level authority, but it *is*
        // a launch verb — an `allow = false` source's tools are reachable by name,
        // while its `[network]`/`mounts` stay inert.
        let f = SourcesFixture::new();
        f.write_repo(
            ".agent-vm/config.toml",
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\n",
        );
        let report = f
            .with_project(&sources_block(&[REPO_SOURCE]))
            .expect("a declaration loads");
        assert!(report.user_network().is_none());
        assert!(report.resolved().labels().any(|label| label == "t"));

        for (label, body, pointer) in [
            (
                "mount_sets",
                "[mount_sets]\n",
                "mount_sets are user-config-only",
            ),
            (
                "egress_sets",
                "[egress_sets]\n",
                "egress_sets are user-config-only",
            ),
        ] {
            let f = SourcesFixture::new();
            let repo = f.write_repo(".agent-vm/config.toml", body);
            f.write_project(&sources_block(&[REPO_SOURCE]));
            let error = format!("{:#}", f.load().expect_err(label));
            assert!(
                error.contains("user-config-only until #738"),
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
            report.resolved().labels().any(|label| label == "u"),
            "a sourced declaration is a launch verb even when nothing authorizes it (#749)"
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
        // read — not the lexical collapse. The spelling is absolute, so this is
        // an external read (D9), not a relative route leaving its checkout.
        let f = SourcesFixture::new();
        let sibling = f.base().join("sibling");
        fs::create_dir_all(&sibling).unwrap();
        fs::write(f.base().join("target.toml"), one_tool("outside-tool")).unwrap();
        fs::write(f.checkout().join("target.toml"), one_tool("checkout-tool")).unwrap();
        std::os::unix::fs::symlink(&sibling, f.base().join("link")).unwrap();
        let report = f
            .with_project(&source_table(
                "link",
                &f.base().join("link/../target.toml"),
                false,
                false,
            ))
            .expect("dot-dot through a symlink");
        assert_eq!(launch_names(&report), ["outside-tool"]);

        // A sibling of the project root is admitted when named absolutely (B8).
        let f = SourcesFixture::new();
        let sibling = f.base().join("sibling");
        fs::create_dir_all(&sibling).unwrap();
        fs::write(
            sibling.join("config.toml"),
            "image = \"localhost:1/sibling:latest\"\n",
        )
        .unwrap();
        let report = f
            .with_project(&source_table(
                "sib",
                &sibling.join("config.toml"),
                false,
                false,
            ))
            .expect("an absolute sibling is external");
        assert_eq!(report.images().source_images().len(), 1);

        // The same sibling spelled relatively never leaves the region its
        // spelling claimed: D9's own refusal, not the checkout wording.
        let f = SourcesFixture::new();
        let sibling = f.base().join("sibling");
        fs::create_dir_all(&sibling).unwrap();
        fs::write(
            sibling.join("config.toml"),
            "image = \"localhost:1/sibling:latest\"\n",
        )
        .unwrap();
        let error = format!(
            "{:#}",
            f.with_project(&sources_block(&["sib ../sibling/config.toml"]))
                .expect_err("a relative escape")
        );
        assert!(
            error.contains("a relative source path stays inside the project directory"),
            "{error}"
        );
        assert!(
            !error.contains("checkout source resolves outside"),
            "D9 gets its own wording: {error}"
        );

        // Directory spellings are refused lexically, before anything is read:
        // `target/` must never silently name the file `target`.
        for entry in ["~/", "/", "./", "sub/", "/a/b/.", "../"] {
            let f = SourcesFixture::new();
            let alias = format!("dir {entry}");
            let error = format!(
                "{:#}",
                f.with_project(&sources_block(&[alias.as_str()]))
                    .expect_err(entry)
            );
            assert!(
                error.contains("the path names a directory"),
                "{entry}: {error}"
            );
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
        // ADR-0040's compatibility rule keeps the *declarations* loadable: a
        // declaration is a launch verb now (#749), so the catalog lists it. The
        // verified read is not skipped, though — the same read's verdict travels
        // with the entry and refuses the launch (`cli` dispatch).
        assert_eq!(launch_names(&report), ["home"]);
        assert_eq!(
            image_ref(report.images().user()),
            Some("localhost:1/home:latest")
        );
        let catalog = report.into_launch_catalog().expect("the catalog builds");
        let entry = catalog
            .as_slice()
            .iter()
            .find(|entry| entry.label() == "home")
            .expect("the user config's declaration is a verb");
        assert!(
            entry.launch_trust().is_some(),
            "an unverified read's verdict must travel with the entry"
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
        assert!(report.images().source_images().is_empty());

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
        let listed: Vec<(&str, &Path)> = report
            .images()
            .source_images()
            .iter()
            .map(|row| (row.alias().as_str(), row.image().file()))
            .collect();
        assert_eq!(listed, [("team", team.as_path())]);

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
        assert_eq!(report.images().source_images().len(), 1);
        assert_eq!(
            report.images().source_images()[0]
                .image()
                .reference()
                .as_str(),
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

    // -- #749: the retired key, refused in every readable tier ----------------

    /// The migration sentence `allow_tools` is refused with, byte for byte. A
    /// retired key has no replacement, so the refusal must say so once and send
    /// the reader to the one decision that still exists (`allow = false`).
    const RETIRED_MIGRATION: &str = "allow_tools is retired: every [[tools]] declaration is \
         launchable, so there is no launch allow list to replace it. Delete the key, or set \
         allow = false on a source that must supply nothing automatically; move the automatic \
         grants you still want to default_tools = [...] before the first table header (the shell \
         always gets them, a direct command only when you write the key); settle a bare name two \
         sources declare with use_tools in the project config; launch one file's tool as \
         <alias>:<tool>; and after editing a pinned source, approve its changed bytes again";

    /// #749: the default user config refuses the retired key, and the migration
    /// wins over ADR-0040's dotfile refusal — the reader is told what to do with
    /// the key, not what is wrong with the link, because the key is going away.
    #[test]
    fn allow_tools_is_refused_in_the_default_user_config() {
        let f = Fixture::new();
        let error = f.user("allow_tools = []\n").load().unwrap_err().to_string();
        assert_eq!(
            error,
            format!("config: {:?}: allow_tools: {RETIRED_MIGRATION}", f.user)
        );

        let f = Fixture::new();
        let error = f
            .symlinked_user("allow_tools = [\"t\"]\n[[tools]]\nname = \"t\"\ncommand = \"t\"\n")
            .load()
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            format!("config: {:?}: allow_tools: {RETIRED_MIGRATION}", f.user)
        );
    }

    /// #749: the project config refuses the retired key by presence, including
    /// an empty list and a malformed value: there is nothing left to parse.
    #[test]
    fn allow_tools_is_refused_in_the_project_config() {
        for body in ["allow_tools = []\n", "allow_tools = 7\n"] {
            let f = Fixture::new();
            let error = f.project(body).load().unwrap_err().to_string();
            assert_eq!(
                error,
                format!("config: {:?}: allow_tools: {RETIRED_MIGRATION}", f.project),
                "{body}"
            );
        }
    }

    /// #749: a `trust = true` source refuses the retired key too. Its read is
    /// unconditional, so this fires before its tools are decoded.
    #[test]
    fn allow_tools_is_refused_in_a_trusted_source() {
        let f = SourcesFixture::new();
        let path = f.base().join("one.toml");
        fs::write(&path, "allow_tools = []\n").unwrap();
        let error = format!(
            "{:#}",
            f.with_project(&source_table("one", &path, true, true))
                .unwrap_err()
        );
        assert_eq!(
            error,
            format!("config: {:?}: allow_tools: {RETIRED_MIGRATION}", path)
        );
    }

    /// #749: an approved pinned source refuses the retired key after its bytes
    /// are approved and before typed decode; an unapproved one is never parsed,
    /// so it still reports pending and says nothing about its keys.
    #[test]
    fn allow_tools_is_refused_in_an_approved_pinned_source() {
        let f = SourcesFixture::new();
        let path = f.base().join("repo.toml");
        fs::write(&path, "allow_tools = []\n").unwrap();
        let project = source_table("repo", &path, false, true);

        f.write_project(&project);
        let error = f
            .load_unapproved()
            .expect_err("unapproved bytes are pending");
        assert!(
            error
                .downcast_ref::<crate::config_pins::UnapprovedSources>()
                .is_some(),
            "an unapproved source must stay pending, not reach a migration message: {error:#}"
        );

        let error = format!("{:#}", f.load().expect_err("approved bytes refuse the key"));
        assert_eq!(
            error,
            format!("config: {:?}: allow_tools: {RETIRED_MIGRATION}", path)
        );
    }

    /// #749: the embedded catalog refuses the retired key through the same
    /// two-stage read, naming the built-in file it was read from.
    #[test]
    fn allow_tools_is_refused_in_the_embedded_defaults() {
        let error = format!(
            "{:#}",
            builtin_raw_config("allow_tools = []\n")
                .err()
                .expect("the shipped catalog refuses it")
        );
        assert_eq!(
            error,
            format!("config: \"default-tools.toml\": allow_tools: {RETIRED_MIGRATION}")
        );
    }

    /// #749: the refusal is placement-aware at every readable site. A misplaced
    /// key that no reader looks at is refused by the site it landed in, never by
    /// the typed schema's generic sentence.
    #[test]
    fn allow_tools_is_refused_at_every_placement() {
        for (body, site) in [
            (
                "[[tools]]\nname = \"t\"\ncommand = \"t\"\nallow_tools = []\n",
                "allow_tools at tools[0]: ",
            ),
            (
                "[[sources]]\nname = \"repo\"\npath = \"x.toml\"\nallow_tools = []\n",
                "allow_tools at sources[0]: ",
            ),
            (
                "[network]\nallow_lan = true\nallow_tools = []\n",
                "allow_tools at [network]: ",
            ),
        ] {
            let f = Fixture::new();
            let error = f.project(body).load().unwrap_err().to_string();
            assert!(
                error.contains(&format!(
                    "config: {:?}: {site}{RETIRED_MIGRATION}",
                    f.project
                )),
                "{body}: {error}"
            );
        }
        for (body, site) in [
            (
                "[mount_sets.one]\nallow_tools = []\n",
                "allow_tools at [mount_sets] definition 0: ",
            ),
            (
                "[egress_sets.one]\nallow_tools = []\n",
                "allow_tools at [egress_sets] definition 0: ",
            ),
        ] {
            let f = Fixture::new();
            let error = f.user(body).load().unwrap_err().to_string();
            assert!(
                error.contains(&format!("config: {:?}: {site}{RETIRED_MIGRATION}", f.user)),
                "{body}: {error}"
            );
        }
    }

    /// #749: the project's declaration outranks every sourced one for the bare
    /// spelling, and the source definition stays reachable as `<alias>:<name>`.
    #[test]
    fn a_project_tool_shadows_a_source_tool_of_the_same_name() {
        let f = SourcesFixture::new();
        let repo = f.write_repo(
            "r.toml",
            "[[tools]]\nname = \"lint\"\ncommand = \"repo-lint\"\n",
        );
        let report = f
            .with_project(&format!(
                "{}\n[[tools]]\nname = \"lint\"\ncommand = \"project-lint\"\n",
                source_table("repo", &repo, false, true)
            ))
            .expect("the shadowed pair loads");
        assert_eq!(report.conflicts().len(), 1, "one shadow is reported");
        let catalog = report.into_launch_catalog().unwrap();
        assert_eq!(entry_of(&catalog, "lint").tool().command(), "project-lint");
        assert_eq!(
            entry_of(&catalog, "repo:lint").tool().command(),
            "repo-lint",
            "the sourced definition keeps its qualified spelling"
        );
        assert!(
            catalog.name_conflict("lint").is_none(),
            "the rank settles it"
        );
    }

    /// #749: two sources with no project declaration leave the bare name in
    /// conflict; each candidate keeps its qualified verb and the refusal names
    /// both.
    #[test]
    fn an_unqualified_conflict_names_both_candidates() {
        let f = SourcesFixture::new();
        let one = f.write_repo(
            "one.toml",
            "[[tools]]\nname = \"lint\"\ncommand = \"one-lint\"\n",
        );
        let two = f.write_repo(
            "two.toml",
            "[[tools]]\nname = \"lint\"\ncommand = \"two-lint\"\n",
        );
        let report = f
            .with_project(&format!(
                "{}{}",
                source_table("one", &one, false, true),
                source_table("two", &two, false, true)
            ))
            .expect("a bare-name conflict is not a load error");
        let catalog = report.into_launch_catalog().unwrap();
        let conflict = catalog
            .name_conflict("lint")
            .expect("two sources leave the bare name in conflict");
        let refusal = conflict.refusal().to_string();
        assert!(refusal.contains("one:lint"), "{refusal}");
        assert!(refusal.contains("two:lint"), "{refusal}");
        // The exact sentence ADR-0079 prints, spacing included: one list grammar
        // shared with `doctor`, so the fix is the separator, not a second
        // renderer.
        assert_eq!(
            refusal,
            format!(
                "config: {}: \"lint\" is declared by source one {} and source two {}; \
                 launch one as \"one:lint\" or \"two:lint\", or rename one definition",
                crate::one_line::quoted_path(f.project_config()),
                crate::one_line::quoted_path(&one),
                crate::one_line::quoted_path(&two),
            )
        );
        assert!(
            catalog
                .as_slice()
                .iter()
                .all(|entry| entry.label() != "lint"),
            "no entry may claim a name in conflict"
        );
        assert_eq!(entry_of(&catalog, "one:lint").tool().command(), "one-lint");
        assert_eq!(entry_of(&catalog, "two:lint").tool().command(), "two-lint");
    }

    /// #749: the renamed fifth trigger is still a presence trigger. A symlinked
    /// default user config that declares `default_tools` is refused by the
    /// verified read before any typed decode — the arm the mutation row
    /// `default-tools-authority-operand-dropped` removes.
    #[test]
    fn default_tools_presence_requires_the_verified_read() {
        for body in ["default_tools = []\n", "default_tools = 7\n"] {
            let f = Fixture::new();
            let error = f.symlinked_user(body).load().unwrap_err().to_string();
            assert_eq!(
                error,
                format!(
                    "config: {:?}: default_tools requires config.toml to be a regular file, but \
                     it is reached through a symbolic link; its target may be writable by a guest \
                     or project, so review the default_tools list before trusting the file (a \
                     symlinked config without default_tools still works)",
                    f.user
                ),
                "{body}"
            );
        }
    }

    // -- (trust, allow) matrix, adoption order, and the #736 seam ----------

    /// One explicit `[[sources]]` table, spelled the way a user writes it.
    fn source_table(name: &str, path: &Path, trust: bool, allow: bool) -> String {
        let mut out = format!(
            "[[sources]]\nname = {name:?}\npath = {:?}\n",
            path.display().to_string()
        );
        if trust {
            out.push_str("trust = true\n");
        }
        if allow {
            out.push_str("allow = true\n");
        }
        out
    }

    /// Every top-level adoptable key one source can declare, in TOML order
    /// (top-level keys before `[network]`/`[[tools]]`).
    fn adopting_source_body() -> String {
        "image = \"localhost:1/s:latest\"\n\
         mounts = [\"/host:/guest:ro\"]\n\
         \
         [network]\nallow_lan = true\nallow_egress = [\"10.0.0.0/8\"]\n\
         [[tools]]\nname = \"t\"\ncommand = \"t\"\ncredentials = [\"openai\"]\n"
            .to_string()
    }

    impl SourcesFixture {
        /// Load with a caller-supplied policy, for the ordering/observation rows
        /// that need a hook. Production's policy is the same type.
        fn load_with_policy(
            &self,
            approval: &mut dyn config_authority::ContentApprovalPolicy,
        ) -> Result<ConfigReport> {
            load_with_content_approval(&self.paths(), approval)
        }
    }

    /// The 2x2 matrix. An unapproved `trust = false` source refuses under
    /// **both** `allow` values (D2); once approved, `allow = true` adopts every
    /// top-level key and `allow = false` adopts none but still supplies tools.
    /// The launch facets and the pin field are asserted, not only `Ok`.
    #[test]
    fn the_four_trust_allow_combinations_are_independent() {
        for trust in [false, true] {
            for allow in [false, true] {
                let label = format!("trust={trust}, allow={allow}");
                let f = SourcesFixture::new();
                let path = if trust {
                    // Outside the checkout, in the 0700 test base.
                    let path = f.base().join("team.toml");
                    fs::write(&path, adopting_source_body()).unwrap();
                    path
                } else {
                    f.write_repo("team.toml", &adopting_source_body())
                };
                let project = source_table("team", &path, trust, allow);
                f.write_project(&project);
                if !trust {
                    // Neither `allow` value may decode, adopt or parse an
                    // unapproved file.
                    let unapproved = f.load_unapproved();
                    let error = format!("{:#}", unapproved.expect_err(&label));
                    assert!(
                        error.contains("1 pinned source is not approved for this project"),
                        "{label}: {error}"
                    );
                    let unapproved = f.load_unapproved().unwrap_err();
                    let pending = unapproved
                        .downcast_ref::<crate::config_pins::UnapprovedSources>()
                        .unwrap_or_else(|| panic!("{label}: a typed refusal"));
                    assert_eq!(pending.pending().len(), 1, "{label}");
                    assert_eq!(
                        pending.pending()[0].reason(),
                        crate::config_pins::PendingReason::NeverApproved,
                        "{label}"
                    );
                }
                let report = f.load().unwrap_or_else(|error| panic!("{label}: {error}"));
                if !trust {
                    let pin = report.sources().entries()[0]
                        .pin()
                        .unwrap_or_else(|| panic!("{label}: an approved pin is reported"));
                    assert!(pin.active(), "{label}");
                    assert_eq!(
                        pin.key().as_path(),
                        crate::config_sources::normalize_lexical_absolute(&path).unwrap(),
                        "{label}"
                    );
                } else {
                    assert!(
                        report.sources().entries()[0].pin().is_none(),
                        "{label}: a trusted source is unpinned"
                    );
                }
                if allow {
                    assert_eq!(
                        report.images().fallback().map(|f| f.alias().as_str()),
                        Some("team"),
                        "{label}: the fallback image is adopted"
                    );
                    assert_eq!(
                        report.user_mounts().map(UserMounts::len),
                        Some(1),
                        "{label}: mounts are adopted"
                    );
                    let network = report.user_network().expect(label.as_str());
                    assert_eq!(network.egress().lan, Some(true), "{label}");
                    assert!(launch_names(&report).contains(&"t".to_owned()), "{label}");
                } else {
                    assert_eq!(report.images().fallback(), None, "{label}");
                    assert_eq!(report.images().user(), None, "{label}");
                    assert!(report.user_mounts().is_none(), "{label}");
                    assert_eq!(report.user_network(), None, "{label}");
                    assert!(
                        launch_names(&report).contains(&"t".to_owned()),
                        "{label}: a declaration is a launch verb at either allow value (#749)"
                    );
                    let entry = &report.sources().entries()[0];
                    assert_eq!(entry.inert().labels(), ["image", "mounts", "[network]"]);
                    assert_eq!(
                        entry.inert().with_image(true).labels(),
                        ["image", "mounts", "[network]"]
                    );
                }
            }
        }
    }

    /// An inert source is still selectable, key by key: `ALIAS:image` reaches an
    /// `allow = false` file explicitly, and its declarations are launchable by
    /// their qualified spelling (#749).
    #[test]
    fn inert_declarations_are_selectable_explicitly() {
        for trust in [false, true] {
            let f = SourcesFixture::new();
            let path = if trust {
                let path = f.base().join("team.toml");
                fs::write(&path, adopting_source_body()).unwrap();
                path
            } else {
                f.write_repo("team.toml", &adopting_source_body())
            };
            let project = format!(
                "image = \"team:image\"\n{}",
                source_table("team", &path, trust, false)
            );
            let report = f
                .with_project(&project)
                .unwrap_or_else(|error| panic!("trust={trust}: {error}"));
            assert_eq!(
                image_ref(report.images().project()),
                Some("localhost:1/s:latest"),
                "trust={trust}"
            );
            assert_eq!(report.images().project().unwrap().file(), path.as_path());
            assert!(
                launch_names(&report).contains(&"t".to_owned()),
                "trust={trust}"
            );
            // The mount and the egress table stay inert: only the two explicit
            // selections above are in force.
            assert!(report.user_mounts().is_none(), "trust={trust}");
            assert_eq!(report.user_network(), None, "trust={trust}");
            assert!(
                report.sources().entries()[0]
                    .inert()
                    .labels()
                    .contains(&"mounts"),
                "trust={trust}"
            );
        }
    }

    /// The pin check runs before UTF-8/TOML decoding for **both** `allow`
    /// values: an unapproved file with deliberately broken TOML reports pending,
    /// never a syntax or unknown-tool error.
    #[test]
    fn the_approval_gate_runs_before_decoding() {
        for allow in [false, true] {
            let f = SourcesFixture::new();
            let path = f.write_repo("team.toml", "network = [unclosed\n");
            let project = source_table("team", &path, false, allow);
            f.write_project(&project);
            let error = format!("{:#}", f.load_unapproved().expect_err("pending"));
            assert!(
                error.contains("1 pinned source is not approved for this project"),
                "allow={allow}: the approval refusal must precede the parse: {error}"
            );
            assert!(
                !error.contains("unclosed") && !error.contains("TOML"),
                "allow={allow}: nothing from the unapproved file is echoed: {error}"
            );
            assert!(
                error.contains(&path.display().to_string()),
                "allow={allow}: the pending file is named: {error}"
            );
        }
    }

    /// The pin seam end to end: approved bytes adopt everything, and one changed
    /// (still valid) byte is refused before adoption, naming the approved
    /// baseline.
    #[test]
    fn approved_untrusted_bytes_adopt_and_changed_bytes_do_not() {
        let f = SourcesFixture::new();
        let body = adopting_source_body();
        let path = f.write_repo("team.toml", &body);
        let project = source_table("team", &path, false, true);
        f.write_project(&project);

        let first_hash = crate::config_pins::ContentHash::of(body.as_bytes());
        let report = f.load().expect("approved bytes are adopted");
        assert_eq!(
            report.images().fallback().map(|f| f.alias().as_str()),
            Some("team")
        );
        assert_eq!(report.user_mounts().map(UserMounts::len), Some(1));
        assert_eq!(
            report.user_network().map(|n| n.egress().lan),
            Some(Some(true))
        );
        assert!(launch_names(&report).contains(&"t".to_owned()));
        let pin = report.sources().entries()[0]
            .pin()
            .expect("an approved pin");
        assert_eq!(pin.hash(), first_hash);
        assert!(pin.active());

        // One byte changed, still valid TOML: the load refuses before adoption
        // and names the previously approved digest as the baseline.
        let mut changed = body.clone().into_bytes();
        let offset = changed
            .windows(4)
            .position(|window| window == b"host")
            .expect("the body declares a mount");
        changed[offset] = b'H';
        fs::write(&path, &changed).unwrap();
        let error = f
            .load_unapproved()
            .expect_err("changed bytes were not approved");
        let unapproved = error
            .downcast_ref::<crate::config_pins::UnapprovedSources>()
            .expect("a typed pending refusal");
        assert_eq!(
            unapproved.pending()[0].reason(),
            crate::config_pins::PendingReason::Changed {
                last_active: first_hash
            }
        );
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains(&format!("last approved {first_hash}")),
            "{rendered}"
        );
    }

    /// First-wins in `[[sources]]` order, and the project image outranks it.
    #[test]
    fn the_fallback_image_is_the_first_allowed_source_in_order() {
        let pair = |first_allow: bool, second_allow: bool| {
            let f = SourcesFixture::new();
            let one = f.base().join("one.toml");
            let two = f.base().join("two.toml");
            fs::write(&one, "image = \"localhost:1/one:latest\"\n").unwrap();
            fs::write(&two, "image = \"localhost:1/two:latest\"\n").unwrap();
            (
                f,
                format!(
                    "{}{}",
                    source_table("one", &one, true, first_allow),
                    source_table("two", &two, true, second_allow)
                ),
            )
        };

        let (f, project) = pair(true, true);
        let report = f.with_project(&project).unwrap();
        assert_eq!(
            image_ref(report.images().fallback().map(|f| f.image())),
            Some("localhost:1/one:latest")
        );
        let rows: Vec<(&str, String)> = report
            .images()
            .source_images()
            .iter()
            .map(|row| (row.alias().as_str(), format!("{:?}", row.status())))
            .collect();
        assert_eq!(rows[1].0, "two");
        assert!(
            rows[1].1.contains("OverriddenBySource"),
            "the later allowed row names the winner: {rows:?}"
        );

        let (f, project) = pair(false, true);
        let report = f.with_project(&project).unwrap();
        assert_eq!(
            image_ref(report.images().fallback().map(|f| f.image())),
            Some("localhost:1/two:latest")
        );
        assert_eq!(
            report.sources().entries()[0].inert().labels(),
            ["image"],
            "the unselected allow = false image is the only inert key"
        );

        // The project image outranks the fallback, and the winner is recorded as
        // overridden rather than silently dropped.
        let (f, project) = pair(true, true);
        let report = f
            .with_project(&format!(
                "image = \"localhost:1/project:latest\"\n{project}"
            ))
            .unwrap();
        assert_eq!(
            image_ref(report.images().project()),
            Some("localhost:1/project:latest")
        );
        assert_eq!(report.images().fallback(), None);
        assert!(
            report
                .images()
                .source_images()
                .iter()
                .all(|row| format!("{:?}", row.status()).contains("OverriddenByProject"))
        );
    }

    /// `mounts` union in `[[sources]]` order, then the project config; identical
    /// declarations dedupe, differing ones at one guest path are an error naming
    /// both files.
    #[test]
    fn adopted_mounts_union_in_order_and_dedupe_or_conflict() {
        let f = SourcesFixture::new();
        let one = f.base().join("one.toml");
        let two = f.base().join("two.toml");
        fs::write(&one, "mounts = [\"/a:/a:ro\", \"/shared:/shared:ro\"]\n").unwrap();
        fs::write(&two, "mounts = [\"/shared:/shared:ro\", \"/b:/b:rw\"]\n").unwrap();
        let project = format!(
            "mounts = [\"/c:/c:ro\"]\n{}{}",
            source_table("one", &one, true, true),
            source_table("two", &two, true, true)
        );
        let report = f.with_project(&project).unwrap();
        let guests: Vec<String> = report
            .user_mounts()
            .expect("adopted mounts")
            .defaults()
            .expect("the project declared one")
            .leaves()
            .iter()
            .map(|leaf| leaf.request.mount.guest.display().to_string())
            .collect();
        assert_eq!(guests, ["/a", "/shared", "/b", "/c"]);
        assert_eq!(
            report.user_mounts().unwrap().files().last().unwrap(),
            f.project_config(),
            "the project config is the last contributor"
        );

        // Differing declarations at one guest path conflict, naming both files.
        fs::write(&two, "mounts = [\"/elsewhere:/shared:ro\"]\n").unwrap();
        let error = format!("{:#}", f.with_project(&project).unwrap_err());
        assert!(
            error.contains("both declare the same guest path"),
            "{error}"
        );
        assert!(error.contains(&one.display().to_string()), "{error}");
        assert!(error.contains(&two.display().to_string()), "{error}");
    }

    /// `[network]` unions in `[[sources]]` order and the project's explicit
    /// booleans override the sources'.
    #[test]
    fn adopted_network_unions_in_order_and_the_project_overrides_booleans() {
        let f = SourcesFixture::new();
        let one = f.base().join("one.toml");
        let two = f.base().join("two.toml");
        fs::write(
            &one,
            "[network]\nallow_lan = true\nallow_internet_egress = true\nallow_egress = [\"a.example\"]\n",
        )
        .unwrap();
        fs::write(
            &two,
            "[network]\nallow_host = true\nallow_internet_egress = false\nallow_egress = [\"b.example\"]\n",
        )
        .unwrap();
        let project = format!(
            "[network]\nallow_internet_egress = false\nallow_egress = [\"c.example\"]\n{}{}",
            source_table("one", &one, true, true),
            source_table("two", &two, true, true)
        );
        let report = f.with_project(&project).unwrap();
        let network = report.user_network().expect("merged network");
        let egress = network.egress();
        assert_eq!(
            (egress.internet, egress.lan, egress.host),
            (Some(false), Some(true), Some(true)),
            "sources OR-union, the project overrides"
        );
        let granted: Vec<String> = egress
            .allowances
            .allowances()
            .map(ToString::to_string)
            .collect();
        assert_eq!(granted, ["a.example", "b.example", "c.example"]);
        assert_eq!(
            network.files(),
            [one.clone(), two.clone(), f.project_config().to_path_buf()]
        );
    }

    /// ADR-0076 R3: a `trust = true, allow = false` source's `mounts` and
    /// `[network]` are inert. The load must succeed and adopt nothing — a
    /// launch-plan negative control, because `load()` returning `Ok` alone would
    /// pass a mutant that quietly bound the mount.
    #[test]
    fn allow_false_trusted_source_mounts_stay_inert() {
        let f = SourcesFixture::new();
        let path = f.base().join("team.toml");
        fs::write(&path, "mounts = [\"/host:/guest:ro\"]\n").unwrap();
        let report = f
            .with_project(&source_table("team", &path, true, false))
            .expect("inert mounts load");
        assert!(report.user_mounts().is_none(), "nothing is adopted");
        assert_eq!(report.sources().entries()[0].inert().labels(), ["mounts"]);
    }

    #[test]
    fn allow_false_trusted_source_network_stays_inert() {
        let f = SourcesFixture::new();
        let path = f.base().join("team.toml");
        fs::write(
            &path,
            "[network]\nallow_lan = true\nallow_egress = [\"10.0.0.0/8\"]\n",
        )
        .unwrap();
        let report = f
            .with_project(&source_table("team", &path, true, false))
            .expect("inert [network] loads");
        assert!(report.user_network().is_none(), "nothing is adopted");
        assert_eq!(
            report.sources().entries()[0].inert().labels(),
            ["[network]"]
        );
    }

    /// ADR-0076 R2.2: a `trust = true` path inside the active checkout is refused
    /// before any byte is read, even when the file itself is perfectly safe.
    #[test]
    fn trusted_source_inside_checkout_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let f = SourcesFixture::new();
        let path = f.repo("team.toml");
        fs::write(&path, "image = \"localhost:1/team:latest\"\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let error = format!(
            "{:#}",
            f.with_project(&source_table("team", &path, true, false))
                .expect_err("an in-checkout trusted path is refused")
        );
        assert!(
            error.contains("inside the active checkout"),
            "the boundary refusal, not a file-measurement one: {error}"
        );
    }

    /// ADR-0076 R2.2: a trusted source whose final symlink targets a checkout file
    /// is refused with the **route** sentence, not as a generic symlink.
    #[test]
    fn trusted_source_symlink_into_checkout_reports_route_refusal() {
        let f = SourcesFixture::new();
        let target = f.repo("side.toml");
        fs::write(&target, "image = \"localhost:1/side:latest\"\n").unwrap();
        let link = f.base().join("link.toml");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let error = format!(
            "{:#}",
            f.with_project(&source_table("team", &link, true, false))
                .expect_err("a link into the checkout is refused")
        );
        assert!(
            error.contains("symbolic link whose target resolves inside the active project"),
            "{error}"
        );
        assert!(
            !error.contains("reached through a symbolic link"),
            "the route wording must win: {error}"
        );
    }

    /// ADR-0076 R2.3: a non-default trusted source is verified unconditionally, so
    /// a group-writable regular file with valid TOML (declaring no authority field)
    /// is still refused.
    #[test]
    fn trusted_source_group_writable_regular_file_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let f = SourcesFixture::new();
        let path = f.base().join("team.toml");
        fs::write(&path, "image = \"localhost:1/team:latest\"\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o620)).unwrap();
        let error = format!(
            "{:#}",
            f.with_project(&source_table("team", &path, true, false))
                .expect_err("a group-writable trusted file is refused")
        );
        assert!(error.contains("group- or other-writable"), "{error}");
        assert!(error.contains("a trusted source"), "{error}");
    }

    /// ADR-0073 + ADR-0076 R3: the project config is verified before its own
    /// `mounts`/`[network]` are adopted, so a writable one grants neither.
    #[test]
    fn unsafe_project_config_mounts_and_network_are_refused() {
        use std::os::unix::fs::PermissionsExt;
        let body = "mounts = [\"/host:/guest:ro\"]\n[network]\nallow_lan = true\n";
        let f = SourcesFixture::new();
        f.write_project(body);
        fs::set_permissions(f.project_config(), fs::Permissions::from_mode(0o620)).unwrap();
        let error = format!("{:#}", f.load().expect_err("a writable project config"));
        assert!(error.contains("group- or other-writable"), "{error}");
        assert!(error.contains("project config"), "{error}");

        // The positive control: the same bytes are adopted once the file is private.
        let f = SourcesFixture::new();
        f.write_project(body);
        fs::set_permissions(f.project_config(), fs::Permissions::from_mode(0o600)).unwrap();
        let report = f.load().expect("a private project config may grant");
        assert_eq!(report.user_mounts().map(UserMounts::len), Some(1));
        assert_eq!(
            report.user_network().map(|n| n.egress().lan),
            Some(Some(true))
        );
    }

    /// ADR-0076 R3 / #736 D2: an unapproved `trust = false, allow = true`
    /// source is a typed pending refusal before decoding, so no unpinned bytes
    /// can grant ambient authority.
    #[test]
    fn untrusted_allow_true_source_is_refused_before_pinning() {
        let f = SourcesFixture::new();
        let path = f.write_repo("team.toml", &adopting_source_body());
        f.write_project(&source_table("team", &path, false, true));
        let error = f
            .load_unapproved()
            .expect_err("unpinned adoption is refused");
        let unapproved = error
            .downcast_ref::<crate::config_pins::UnapprovedSources>()
            .expect("a typed pending refusal");
        assert_eq!(unapproved.pending().len(), 1);
        assert!(unapproved.pending()[0].allow);
        assert!(format!("{error:#}").contains("agent-vm config approve"));
    }

    // -- #736 phase 4: the pin-aware load, inspection, and refusals --------

    impl SourcesFixture {
        fn store_dir(&self) -> PathBuf {
            self.config.parent().unwrap().to_path_buf()
        }

        fn pins_file(&self) -> PathBuf {
            self.store_dir().join(crate::config_pins::PINS_FILE)
        }

        fn pins_lock(&self) -> PathBuf {
            self.store_dir().join(crate::config_pins::LOCK_FILE)
        }

        /// The typed root error, or a panic naming what came back instead.
        fn pending_error(&self) -> crate::config_pins::UnapprovedSources {
            let error = self.load_unapproved().expect_err("a pending refusal");
            error
                .downcast::<crate::config_pins::UnapprovedSources>()
                .expect("a typed UnapprovedSources root error")
        }
    }

    fn independent_sha256(bytes: &[u8]) -> String {
        use sha2::{Digest as _, Sha256};
        let digest = Sha256::digest(bytes);
        let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        format!("sha256:{hex}")
    }

    /// V17/R8: the refusal is typed, its digest is independently correct, its
    /// `Display` is the documented sentence, and it retains every inspected
    /// source plus the store observation.
    #[test]
    fn v17_an_unapproved_source_is_one_typed_refusal_with_the_r8_text() {
        let f = SourcesFixture::new();
        let body = one_tool("repo-tool");
        let path = f.write_repo("repo.toml", &body);
        f.write_project(&sources_block(&["repo ./repo.toml"]));

        let error = f.load_unapproved().expect_err("unapproved");
        let unapproved = error
            .downcast_ref::<crate::config_pins::UnapprovedSources>()
            .expect("a typed UnapprovedSources root error");
        assert_eq!(unapproved.pending().len(), 1);
        assert_eq!(unapproved.entries().len(), 1);
        let source = &unapproved.pending()[0];
        assert_eq!(
            source.reason(),
            crate::config_pins::PendingReason::NeverApproved
        );
        assert_eq!(source.hash.to_string(), independent_sha256(body.as_bytes()));
        assert!(
            unapproved.observed().is_some(),
            "the store state is retained"
        );

        let expected = format!(
            "config: {}: 1 pinned source is not approved for this project:\n  sources[0] repo {}: \
             never approved (current {})\nreview the change with `agent-vm config diff` and \
             approve it with `agent-vm config approve` (a later release's workflow, not this \
             version's); this version approves only from an eligible launch — a tool verb, `run` \
             or `--`, never `doctor`, help or a built-in — run in this project's interactive \
             terminal",
            crate::one_line::quoted_path(f.project_config()),
            crate::one_line::quoted_path(&path),
            independent_sha256(body.as_bytes()),
        );
        assert_eq!(error.to_string(), expected);
        assert!(!f.pins_file().exists(), "the load wrote no manifest");
        assert!(!f.pins_lock().exists(), "the load created no lock");
    }

    /// V18: an approved source reports `active`, and a trusted source never
    /// reads or creates the pin store at all.
    #[test]
    fn v18_approved_sources_report_a_pin_and_trusted_sources_have_none() {
        // Implicit home (trusted) only.
        let f = SourcesFixture::new();
        f.write_user(&one_tool("u"));
        let report = f.load().expect("trusted load");
        assert!(report.sources().entries()[0].pin().is_none());
        assert!(!f.pins_file().exists(), "no pins.json for a trusted load");
        assert!(!f.pins_lock().exists(), "no pins.lock for a trusted load");

        // Explicit non-default trusted source, outside the checkout.
        let f = SourcesFixture::new();
        let trusted = f.base().join("team.toml");
        fs::write(&trusted, one_tool("t")).unwrap();
        let report = f
            .with_project(&source_table("team", &trusted, true, true))
            .expect("trusted source load");
        assert!(report.sources().entries()[0].pin().is_none());
        assert!(!f.pins_file().exists());
        assert!(!f.pins_lock().exists());

        // An approved untrusted source carries its pin.
        let f = SourcesFixture::new();
        f.write_repo("repo.toml", &one_tool("r"));
        let report = f
            .with_project(&sources_block(&["repo ./repo.toml"]))
            .expect("approved untrusted");
        let pin = report.sources().entries()[0]
            .pin()
            .expect("an approved untrusted source is pinned");
        assert!(pin.active(), "the approved digest was activated");
        assert!(f.pins_file().exists());
    }

    /// V19/R6: a modification after approval is `Changed` against the recorded
    /// active digest, not `NeverApproved` and not a fresh approval.
    #[test]
    fn v19_an_edit_after_approval_reports_the_active_baseline() {
        let f = SourcesFixture::new();
        let first = one_tool("r");
        let path = f.write_repo("repo.toml", &first);
        f.write_project(&sources_block(&["repo ./repo.toml"]));
        f.load().expect("first approval");

        let first_hash = crate::config_pins::ContentHash::of(first.as_bytes());
        let changed = one_tool("s");
        fs::write(&path, &changed).unwrap();
        let unapproved = f.pending_error();
        assert_eq!(
            unapproved.pending()[0].reason(),
            crate::config_pins::PendingReason::Changed {
                last_active: first_hash
            }
        );
        assert!(
            format!("{unapproved}").contains(&format!("last approved {first_hash}")),
            "{unapproved}"
        );
    }

    /// V20 (load half): after two approvals, switching back to the first is an
    /// `Ok` load whose pin is approved but no longer active.
    #[test]
    fn v20_a_switch_back_to_an_approved_version_is_inactive_not_pending() {
        let f = SourcesFixture::new();
        let a = one_tool("a");
        let b = one_tool("b");
        let path = f.write_repo("repo.toml", &a);
        f.write_project(&sources_block(&["repo ./repo.toml"]));

        let first = f.load().expect("approve A");
        assert!(first.sources().entries()[0].pin().unwrap().active());
        fs::write(&path, &b).unwrap();
        let second = f.load().expect("approve B");
        assert!(second.sources().entries()[0].pin().unwrap().active());

        fs::write(&path, &a).unwrap();
        let back = f.load().expect("A is still approved");
        let pin = back.sources().entries()[0].pin().expect("approved pin");
        assert_eq!(
            pin.hash(),
            crate::config_pins::ContentHash::of(a.as_bytes())
        );
        assert!(!pin.active(), "A is approved but not the active baseline");
    }

    /// V21: an unapproved source is the pending refusal, never "unknown tool";
    /// malformed TOML is never parsed.
    #[test]
    fn v21_pending_wins_over_tool_resolution_and_parsing() {
        let f = SourcesFixture::new();
        f.write_repo("repo.toml", &one_tool("lint"));
        f.write_project(&sources_block(&["repo ./repo.toml"]));
        let error = format!("{:#}", f.load_unapproved().expect_err("pending"));
        assert!(
            error.contains("is not approved for this project"),
            "{error}"
        );
        assert!(
            !error.contains("unknown tool") && !error.contains("does not declare"),
            "{error}"
        );

        let f = SourcesFixture::new();
        f.write_repo("repo.toml", "network = [unclosed\n");
        f.write_project(&sources_block(&["repo ./repo.toml"]));
        let unapproved = f.pending_error();
        assert_eq!(unapproved.pending().len(), 1);
    }

    /// V22: a non-UTF-8 candidate is a config UTF-8 refusal, never offered for
    /// approval and never wrapped in `UnapprovedSources`.
    #[test]
    fn v22_a_non_utf8_candidate_is_refused_not_offered_for_approval() {
        let f = SourcesFixture::new();
        let path = f.repo("binary.toml");
        fs::write(&path, b"[[tools]]\nname = \"\xff\"\n").unwrap();
        f.write_project(&sources_block(&["repo ./binary.toml"]));

        let error = f.load_unapproved().expect_err("binary");
        assert!(
            error
                .downcast_ref::<crate::config_pins::UnapprovedSources>()
                .is_none(),
            "a binary source is not an approval candidate"
        );
        assert!(
            format!("{error:#}").contains("is not valid UTF-8"),
            "{error:#}"
        );
        assert!(!f.pins_file().exists());
        assert!(!f.pins_lock().exists());

        // A healthy store does not change the answer: the binary is still not
        // offered for approval, and the existing approval is untouched.
        let f = SourcesFixture::new();
        f.write_repo("good.toml", &one_tool("good"));
        f.write_project(&sources_block(&["good ./good.toml"]));
        f.load().expect("one healthy approval");
        let pins_before = fs::read(f.pins_file()).unwrap();
        fs::write(f.repo("bin.toml"), b"name = \"\xff\"\n").unwrap();
        f.write_project(&sources_block(&["good ./good.toml", "bin ./bin.toml"]));
        let error = f
            .load_unapproved()
            .expect_err("binary beside a healthy store");
        assert!(
            error
                .downcast_ref::<crate::config_pins::UnapprovedSources>()
                .is_none(),
            "a binary source is not an approval candidate"
        );
        assert!(format!("{error:#}").contains("is not valid UTF-8"));
        assert_eq!(fs::read(f.pins_file()).unwrap(), pins_before);
    }

    /// V23/R4: a damaged manifest is the store refusal for a project with pinned
    /// sources, and is not even read when every source is trusted.
    #[test]
    fn v23_a_damaged_store_is_named_only_when_a_pinned_source_needs_it() {
        let f = SourcesFixture::new();
        f.write_repo("repo.toml", &one_tool("r"));
        f.write_project(&sources_block(&["repo ./repo.toml"]));
        fs::write(f.pins_file(), b"not json").unwrap();
        let error = format!("{:#}", f.load_unapproved().expect_err("damaged"));
        assert!(
            error.contains(&f.pins_file().display().to_string()),
            "the store file is named: {error}"
        );
        assert!(
            error.contains("the source pin store could not be used"),
            "{error}"
        );

        // The same damage is irrelevant to a trusted-only load: not read.
        let f = SourcesFixture::new();
        f.write_user(&one_tool("u"));
        f.write_project(&format!("{}\n", sources_block(&[HOME_SOURCE])));
        fs::write(f.pins_file(), b"not json").unwrap();
        f.load().expect("a trusted load never reads pins.json");
    }

    /// V24(a)/(b): retargeting needs a fresh approval even for identical bytes,
    /// and a change at the same key is `Changed`; (c) two spellings that
    /// normalize identically are one key.
    #[test]
    fn v24_retargeting_is_a_new_key_and_spelling_is_normalized() {
        use crate::config_pins::PinKey;

        let f = SourcesFixture::new();
        let body = one_tool("r");
        f.write_repo("a.toml", &body);
        f.write_repo("b.toml", &body);
        f.write_project(&sources_block(&["repo ./a.toml"]));
        f.load().expect("approve a.toml");

        // (a) identical bytes at a new path is still never approved.
        f.write_project(&sources_block(&["repo ./b.toml"]));
        let unapproved = f.pending_error();
        assert_eq!(
            unapproved.pending()[0].reason(),
            crate::config_pins::PendingReason::NeverApproved
        );

        // (b) a retarget at the same key with different bytes is Changed.
        f.write_project(&sources_block(&["repo ./a.toml"]));
        fs::write(f.repo("a.toml"), one_tool("s")).unwrap();
        let unapproved = f.pending_error();
        assert!(matches!(
            unapproved.pending()[0].reason(),
            crate::config_pins::PendingReason::Changed { .. }
        ));

        // (c) `.` and repeated separators normalize to one key.
        let one = PinKey::for_source(Path::new("/w/app/conf/./a.toml")).unwrap();
        let two = PinKey::for_source(Path::new("/w/app/conf//a.toml")).unwrap();
        assert_eq!(one, two);
    }

    /// V25: the key is the lexical path the entry named, so an in-checkout
    /// symlink is pinned under its own spelling; identical bytes behind a new
    /// target stay approved, different bytes do not.
    #[test]
    fn v25_a_checkout_symlink_keeps_its_lexical_key() {
        let f = SourcesFixture::new();
        let body = one_tool("r");
        f.write_repo("a.toml", &body);
        f.write_repo("b.toml", &body);
        std::os::unix::fs::symlink(f.repo("a.toml"), f.repo("link.toml")).unwrap();
        f.write_project(&sources_block(&["repo ./link.toml"]));
        f.load().expect("approve through the link");

        let manifest = fs::read_to_string(f.pins_file()).unwrap();
        assert!(
            manifest.contains(&format!("{}/link.toml\"", f.checkout().display())),
            "the key is the lexical spelling: {manifest}"
        );
        assert!(
            !manifest.contains(&format!("{}/a.toml\"", f.checkout().display())),
            "the target is not a second key: {manifest}"
        );

        // Retarget with identical bytes: the same key and digest stay approved.
        fs::remove_file(f.repo("link.toml")).unwrap();
        std::os::unix::fs::symlink(f.repo("b.toml"), f.repo("link.toml")).unwrap();
        f.load().expect("identical bytes stay approved");

        // Different bytes behind the new target are pending.
        fs::write(f.repo("b.toml"), one_tool("s")).unwrap();
        assert_eq!(f.pending_error().pending().len(), 1);
    }

    /// V26: one refusal lists every pending source in `[[sources]]` order, and a
    /// mixed project retains both the approved and the pending entry.
    #[test]
    fn v26_pending_sources_are_collected_in_declaration_order() {
        let f = SourcesFixture::new();
        f.write_repo("one.toml", &one_tool("one"));
        f.write_repo("two.toml", &one_tool("two"));
        f.write_project(&sources_block(&["one ./one.toml", "two ./two.toml"]));
        let unapproved = f.pending_error();
        assert_eq!(unapproved.pending().len(), 2);
        assert_eq!(unapproved.entries().len(), 2);
        assert_eq!(unapproved.pending()[0].alias.as_str(), "one");
        assert_eq!(unapproved.pending()[1].alias.as_str(), "two");
        let rendered = format!("{unapproved}");
        assert!(rendered.contains("2 pinned sources are not approved"));
        let one = rendered.find("one.toml").unwrap();
        let two = rendered.find("two.toml").unwrap();
        assert!(one < two, "declaration order is kept: {rendered}");

        // Mixed: approve both, change one, and both entries survive.
        let f = SourcesFixture::new();
        f.write_repo("one.toml", &one_tool("one"));
        f.write_repo("two.toml", &one_tool("two"));
        f.write_project(&sources_block(&["one ./one.toml", "two ./two.toml"]));
        f.load().expect("both approved");
        fs::write(f.repo("two.toml"), one_tool("changed")).unwrap();
        let unapproved = f.pending_error();
        assert_eq!(unapproved.entries().len(), 2);
        assert_eq!(unapproved.pending().len(), 1);
        assert!(matches!(
            unapproved.entries()[0].status,
            crate::config_pins::InspectedStatus::Approved { .. }
        ));
        assert!(matches!(
            unapproved.entries()[1].status,
            crate::config_pins::InspectedStatus::Pending(_)
        ));
    }

    /// V27/R7: a path that cannot be a pin key is refused with the "cannot pin
    /// it" clause before any store is opened.
    #[test]
    fn v27_an_unpinnable_path_is_refused_before_the_store() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt as _;

        let path = PathBuf::from(OsString::from_vec(b"/w/app/\xff.toml".to_vec()));
        let entry = crate::config_sources::SourceEntry::for_tests(false, path);
        // The project config does not exist; a store read would fail the load
        // with a store error if it were attempted first.
        let project = Path::new("/nonexistent/store/config.toml");
        let error = super::declared_pin_keys(&[entry], Some(project)).expect_err("unpinnable");
        assert!(
            error.to_string().contains("cannot pin it"),
            "the key refusal, not a store error: {error}"
        );
        assert!(
            error
                .to_string()
                .contains("the source path is not valid UTF-8"),
            "{error}"
        );
    }

    /// The ordering guarantee, proven by instrumentation: the store lookup hook
    /// runs before UTF-8 validation rejects an unapproved binary, and before an
    /// approved malformed file's TOML error.
    #[test]
    fn the_lookup_happens_before_utf8_and_before_decoding() {
        use std::cell::Cell;
        use std::rc::Rc;

        // Unapproved binary: UTF-8 rejects only after the lookup.
        let f = SourcesFixture::new();
        fs::write(f.repo("bin.toml"), b"name = \"\xff\"\n").unwrap();
        f.write_project(&sources_block(&["repo ./bin.toml"]));
        let looked_up = Rc::new(Cell::new(false));
        let flag = Rc::clone(&looked_up);
        let mut policy = crate::config_pins::PinsContentPolicy::with_lookup_hook(
            f.paths().project.as_ref(),
            Box::new(move |_, _| flag.set(true)),
        );
        let error = f.load_with_policy(&mut policy).expect_err("binary");
        assert!(looked_up.get(), "the lookup ran before UTF-8 validation");
        assert!(format!("{error:#}").contains("is not valid UTF-8"));

        // Approved malformed TOML: the lookup approved these bytes, then the
        // parser (not the pin check) reports the syntax error.
        let f = SourcesFixture::new();
        f.write_repo("bad.toml", "network = [unclosed\n");
        f.write_project(&sources_block(&["repo ./bad.toml"]));
        f.approve_pending();
        let looked_up = Rc::new(Cell::new(false));
        let flag = Rc::clone(&looked_up);
        let mut policy = crate::config_pins::PinsContentPolicy::with_lookup_hook(
            f.paths().project.as_ref(),
            Box::new(move |_, _| flag.set(true)),
        );
        let error = f
            .load_with_policy(&mut policy)
            .expect_err("approved bytes reach the parser");
        assert!(looked_up.get(), "the lookup ran before decoding");
        assert!(
            error
                .downcast_ref::<crate::config_pins::UnapprovedSources>()
                .is_none(),
            "approved bytes are not pending"
        );
        assert!(
            format!("{error:#}").contains("TOML") || format!("{error:#}").contains("expected"),
            "the parse error is the refusal: {error:#}"
        );
    }

    /// V39(c): an approved `(false, false)` source with malformed inert values
    /// loads, stays inert, and an explicit `ALIAS:image` still selects its image.
    #[test]
    fn an_approved_inert_source_with_malformed_values_still_loads_and_selects() {
        let f = SourcesFixture::new();
        let body = "image = \"localhost:1/inert:latest\"\nnetwork = 42\nmounts = \"bad\"\n\
                    [[tools]]\nname = \"t\"\ncommand = \"t\"\n";
        f.write_repo("team.toml", body);
        f.write_project(&format!(
            "image = \"team:image\"\n{}",
            source_table("team", &f.repo("team.toml"), false, false)
        ));
        let report = f.load().expect("approved inert values load");
        assert_eq!(
            image_ref(report.images().project()),
            Some("localhost:1/inert:latest")
        );
        assert!(report.user_mounts().is_none());
        assert_eq!(report.user_network(), None);
        assert!(
            report.sources().entries()[0]
                .inert()
                .labels()
                .contains(&"mounts")
        );
        assert!(report.sources().entries()[0].pin().is_some());
    }

    /// V39(e): approval is of bytes, not attributes. Toggling `allow` on an
    /// already-pinned source adopts its top-level keys without a fresh approval
    /// or a new pin.
    #[test]
    fn toggling_allow_on_an_approved_source_needs_no_fresh_consent() {
        let f = SourcesFixture::new();
        f.write_repo("team.toml", &adopting_source_body());
        f.write_project(&source_table("team", &f.repo("team.toml"), false, false));
        let inert = f.load().expect("approved, inert");
        assert!(inert.user_mounts().is_none());
        let pins_before = fs::read(f.pins_file()).unwrap();

        f.write_project(&source_table("team", &f.repo("team.toml"), false, true));
        let adopted = f.load_unapproved().expect("same bytes, now allowed");
        assert_eq!(
            adopted.user_mounts().map(UserMounts::len),
            Some(1),
            "the approved mount list is now adopted"
        );
        assert_eq!(
            adopted.user_network().map(|network| network.egress().lan),
            Some(Some(true))
        );
        assert!(launch_names(&adopted).contains(&"t".to_owned()));
        assert_eq!(
            fs::read(f.pins_file()).unwrap(),
            pins_before,
            "no new approval was recorded"
        );
    }

    /// V40 (load half): a checkout source resolving outside the project refuses
    /// before reading the target, discloses no sentinel bytes, and leaves no
    /// store file behind.
    #[test]
    fn an_untrusted_checkout_escape_discloses_nothing_and_creates_no_store() {
        let f = SourcesFixture::new();
        let outside = tempfile::tempdir().unwrap();
        let sentinel = outside.path().canonicalize().unwrap().join("sentinel.toml");
        fs::write(&sentinel, "SECRET-SENTINEL-736\n").unwrap();
        std::os::unix::fs::symlink(&sentinel, f.repo("link.toml")).unwrap();
        f.write_project(&sources_block(&["repo ./link.toml"]));
        let error = format!("{:#}", f.load_unapproved().expect_err("escape"));
        assert!(
            error.contains("checkout source resolves outside the project directory"),
            "{error}"
        );
        assert!(!error.contains("SECRET-SENTINEL-736"), "{error}");
        assert_eq!(
            fs::read_to_string(&sentinel).unwrap(),
            "SECRET-SENTINEL-736\n"
        );
        assert!(!f.pins_file().exists());
        assert!(!f.pins_lock().exists());
    }

    /// Inspection stops before trusted reads, image resolution, authorization
    /// and any write; an unknown `Only` key is rejected before a file is opened.
    #[test]
    fn inspection_is_staged_read_only_and_rejects_unknown_keys() {
        let f = SourcesFixture::new();
        f.write_repo("team.toml", "network = [unclosed\n");
        f.write_project(&format!(
            "image = \"nope:image\"\n{}",
            sources_block(&["team ./team.toml"])
        ));
        let inspection =
            inspect_pinned_sources(&f.paths(), &SourceSelection::All).expect("pending inspects");
        assert_eq!(inspection.pending().len(), 1);
        assert_eq!(inspection.all_declared_keys().len(), 1);
        assert!(!f.pins_file().exists(), "inspection wrote no manifest");
        assert!(!f.pins_lock().exists(), "inspection created no lock");

        // A `~` spelling would point outside the project; this one does not even
        // need to exist, because the key is rejected first.
        let missing =
            crate::config_pins::PinKey::for_source(Path::new("/nonexistent/x.toml")).unwrap();
        let error = inspect_pinned_sources(
            &f.paths(),
            &SourceSelection::Only(std::collections::BTreeSet::from([missing])),
        )
        .expect_err("unknown key");
        assert!(
            error
                .to_string()
                .contains("is not a declared trust = false source"),
            "{error}"
        );
        assert!(
            !error.to_string().contains("not found"),
            "no file was opened: {error}"
        );
    }

    /// D1: pinned bytes share the 4 MiB source budget with trusted sources.
    /// Exactly the limit loads; one byte more refuses, naming the total.
    #[test]
    fn pinned_and_trusted_sources_share_one_byte_budget() {
        let f = SourcesFixture::new();
        let trusted = f.base().join("trusted.toml");
        fs::write(&trusted, comment_config(1024 * 1024)).unwrap();
        let mut project = source_table("trusted", &trusted, true, false);
        for index in 0..3 {
            f.write_repo(&format!("big{index}.toml"), &comment_config(1024 * 1024));
            project.push_str(&source_table(
                &format!("big{index}"),
                &f.repo(&format!("big{index}.toml")),
                false,
                false,
            ));
        }
        f.write_project(&project);
        f.load().expect("exactly the shared budget");

        // One more legal pinned file pushes the total over, even though every
        // file on its own is under the per-file ceiling.
        let f = SourcesFixture::new();
        let trusted = f.base().join("trusted.toml");
        fs::write(&trusted, comment_config(1024 * 1024)).unwrap();
        let mut project = source_table("trusted", &trusted, true, false);
        for index in 0..4 {
            f.write_repo(&format!("big{index}.toml"), &comment_config(1024 * 1024));
            project.push_str(&source_table(
                &format!("big{index}"),
                &f.repo(&format!("big{index}.toml")),
                false,
                false,
            ));
        }
        let error = format!(
            "{:#}",
            f.with_project(&project).expect_err("over the budget")
        );
        assert!(
            error.contains(&format!(
                "the declared sources read more than {MAX_SOURCE_BYTES_TOTAL} bytes in total"
            )),
            "{error}"
        );
    }

    /// A pending source never creates store state: neither the load nor an
    /// inspection may leave a manifest or a lock behind.
    #[test]
    fn pending_sources_never_create_store_state() {
        let f = SourcesFixture::new();
        f.write_repo("repo.toml", &one_tool("r"));
        f.write_project(&sources_block(&["repo ./repo.toml"]));
        assert!(!f.pins_file().exists());
        assert!(!f.pins_lock().exists());
        let _ = f.load_unapproved().expect_err("pending");
        assert!(!f.pins_file().exists(), "the load wrote no manifest");
        assert!(!f.pins_lock().exists(), "the load created no lock");
        let _ = inspect_pinned_sources(&f.paths(), &SourceSelection::All).expect("inspection");
        assert!(!f.pins_file().exists(), "inspection wrote no manifest");
        assert!(!f.pins_lock().exists(), "inspection created no lock");
    }
    // -- #749 G: `default_tools` and `use_tools` ---------------------------

    /// One declaration whose grant is observable: a single credential name.
    fn granting(name: &str, provider: &str) -> String {
        format!(
            "[[tools]]\nname = \"{name}\"\ncommand = \"{name}\"\ncredentials = [\"{provider}\"]\n"
        )
    }

    /// The placement suffix both misplaced-key refusals carry.
    const PLACEMENT: &str = "must be written before the first table header";

    #[test]
    fn both_new_keys_are_accepted_at_the_project_root() {
        let f = SourcesFixture::new();
        f.with_project("default_tools = []\nuse_tools = []\n")
            .expect("both keys are project top-level fields");
        // A verified config that declares `default_tools` loads: the positive
        // control for the authority trigger that was landed ahead of the field.
        let f = SourcesFixture::new();
        f.write_user(&format!(
            "default_tools = [\"helper\"]\n{}",
            granting("helper", "openai")
        ));
        let report = f
            .with_project("[[tools]]\nname = \"mine\"\ncommand = \"mine\"\n")
            .expect("a verified user config that declares default_tools loads");
        let catalog = report.into_launch_catalog().unwrap();
        assert_eq!(
            provisioned_of(&catalog, "shell"),
            vec![CredentialProvider::OpenAi],
            "the declared default grants"
        );
    }

    /// Root only: each table that can swallow a later assignment refuses the key
    /// by placement, and the refusal names the site it landed in.
    #[test]
    fn both_new_keys_are_refused_where_a_table_swallows_them() {
        for (body, key, site) in [
            (
                "[[tools]]\nname = \"t\"\ncommand = \"t\"\ndefault_tools = []\n",
                "default_tools",
                "tools[0]",
            ),
            (
                "[[tools]]\nname = \"t\"\ncommand = \"t\"\nuse_tools = []\n",
                "use_tools",
                "tools[0]",
            ),
            (
                "[[sources]]\nname = \"s\"\npath = \"/nowhere\"\ndefault_tools = []\n",
                "default_tools",
                "sources[0]",
            ),
            (
                "[network]\ndefault_tools = []\n",
                "default_tools",
                "[network]",
            ),
            ("network.use_tools = []\n", "use_tools", "[network]"),
        ] {
            let f = SourcesFixture::new();
            let error = format!("{:#}", f.with_project(body).unwrap_err());
            assert!(
                error.contains(&format!("{key} at {site}:")),
                "{body}: {error}"
            );
            assert!(error.contains(PLACEMENT), "{body}: {error}");
        }
        // The two set tables are user-only, so the placement refusal is observed
        // on the tier that may declare them at all.
        for (body, key, site) in [
            (
                "[mount_sets.s]\ndefault_tools = []\n",
                "default_tools",
                "[mount_sets] definition 0",
            ),
            (
                "[egress_sets.s]\nuse_tools = []\n",
                "use_tools",
                "[egress_sets] definition 0",
            ),
        ] {
            let fixture = Fixture::new();
            let error = format!("{:#}", fixture.user(body).load().unwrap_err());
            assert!(
                error.contains(&format!("{key} at {site}:")),
                "{body}: {error}"
            );
            assert!(error.contains(PLACEMENT), "{body}: {error}");
        }
    }

    /// #749 V3/E9/F2: a retired key is not a valid set name. A bare key after
    /// `[mount_sets]`/`[egress_sets]` becomes a definition named `allow_tools`,
    /// and the reader refused it only when it sat *inside* a definition.
    #[test]
    fn a_retired_key_is_refused_as_a_set_name() {
        for (body, site) in [
            (
                "[egress_sets]\nallow_tools = [\"example.com\"]\n",
                "[egress_sets] definition 0",
            ),
            (
                "[egress_sets.allow_tools]\nexample = [\"example.com\"]\n",
                "[egress_sets] definition 0",
            ),
            (
                "[mount_sets]\nallow_tools = [\"/a:/b:ro\"]\n",
                "[mount_sets] definition 0",
            ),
            (
                "[mount_sets.allow_tools]\na = \"/a:/b:ro\"\n",
                "[mount_sets] definition 0",
            ),
        ] {
            let fixture = Fixture::new();
            let error = format!("{:#}", fixture.user(body).load().unwrap_err());
            assert!(
                error.contains(&format!("allow_tools at {site}")),
                "{body}: {error}"
            );
            assert!(error.contains("allow_tools is retired"), "{body}: {error}");
        }
        // The control: another set name loads, and the set grants.
        let fixture = Fixture::new();
        let report = fixture
            .user("[egress_sets]\ncorp = [\"example.com\"]\n\n[network]\nallow_egress = [\"set:corp\"]\n")
            .load()
            .expect("a differently named set loads");
        assert!(report.user_network().is_some());
    }

    #[test]
    fn a_default_tools_entry_must_be_a_tool_name() {
        let f = SourcesFixture::new();
        let error = format!(
            "{:#}",
            f.with_project("default_tools = [\"*\"]\n").unwrap_err()
        );
        assert!(error.contains("default_tools[0]:"), "{error}");
        assert!(
            error.contains("name the tools a launch should provision"),
            "{error}"
        );
        assert!(!error.contains('*'), "the refusal echoes no value: {error}");
    }

    #[test]
    fn a_use_tools_entry_must_be_a_qualified_choice() {
        let f = SourcesFixture::new();
        for body in ["use_tools = [\"pi\"]\n", "use_tools = [\"a:b:c\"]\n"] {
            let error = format!("{:#}", f.with_project(body).unwrap_err());
            assert!(error.contains("use_tools[0]:"), "{body}: {error}");
            assert!(error.contains("<alias>:<name>"), "{body}: {error}");
        }
    }

    #[test]
    fn use_tools_may_not_target_one_tool_twice() {
        let f = SourcesFixture::new();
        let error = format!(
            "{:#}",
            f.with_project("use_tools = [\"one:pi\", \"two:pi\"]\n")
                .unwrap_err()
        );
        assert!(error.contains("use_tools[1]:"), "{error}");
        assert!(error.contains("already chosen at use_tools[0]"), "{error}");
    }

    /// Project-only is a property of the field: every other readable tier refuses
    /// it, including the embedded catalog, with one sentence.
    #[test]
    fn use_tools_is_project_only() {
        // The project positive: the key is accepted, empty included.
        let f = SourcesFixture::new();
        f.with_project("use_tools = []\n")
            .expect("the project may declare use_tools");
        // A user config.
        let fixture = Fixture::new();
        let error = format!(
            "{:#}",
            fixture
                .user("use_tools = [\"home:pi\"]\n")
                .load()
                .unwrap_err()
        );
        assert!(
            error.contains("only the project config may settle a default name"),
            "{error}"
        );
        // A sourced file, through the real route — in both `allow` values. An
        // `allow = false` source drops only its automatic grants; `use_tools` is
        // project-only by the field's own rule, not by the tier's inertness, so
        // hiding it behind a successful load would be silent acceptance of a
        // forbidden key (F2).
        for allow in [true, false] {
            let f = SourcesFixture::new();
            let path = f.base().join("one.toml");
            fs::write(&path, "use_tools = []\n").unwrap();
            let error = format!(
                "{:#}",
                f.with_project(&source_table("one", &path, true, allow))
                    .unwrap_err()
            );
            assert!(
                error.contains("only the project config may settle a default name"),
                "allow = {allow}: {error}"
            );
        }
        // The embedded catalog.
        let error = format!(
            "{:#}",
            tools_from_builtin_text("use_tools = []\n").unwrap_err()
        );
        assert!(
            error.contains("only the project config may settle a default name"),
            "{error}"
        );
        let error = format!(
            "{:#}",
            tools_from_builtin_text("default_tools = []\n").unwrap_err()
        );
        assert!(
            error.contains("default_tools cannot be declared by the built-in config"),
            "{error}"
        );
    }

    #[test]
    fn a_default_that_names_no_tool_is_refused() {
        let f = SourcesFixture::new();
        let error = format!(
            "{:#}",
            f.with_project(&format!(
                "default_tools = [\"nope\"]\n{}",
                granting("helper", "openai")
            ))
            .unwrap_err()
        );
        assert!(error.contains("\"nope\""), "{error}");
        assert!(
            error.contains("names no tool any readable config declares"),
            "{error}"
        );
    }

    #[test]
    fn a_use_tools_choice_must_name_a_tool_that_source_declares() {
        let f = SourcesFixture::new();
        let path = f.base().join("one.toml");
        fs::write(&path, granting("helper", "openai")).unwrap();
        let error = format!(
            "{:#}",
            f.with_project(&format!(
                "default_tools = [\"stale\"]\nuse_tools = [\"one:stale\"]\n{}",
                source_table("one", &path, true, true)
            ))
            .unwrap_err()
        );
        assert!(error.contains("use_tools:"), "{error}");
        assert!(
            error.contains("names no tool that source declares"),
            "{error}"
        );
    }

    /// #749 V2: every `use_tools` entry is validated against the source it
    /// names, whether or not a `default_tools` entry consumes it. An entry no
    /// default uses is still a choice the project wrote, and ADR-0079/USAGE
    /// promise a config error for one that names no declared tool.
    #[test]
    fn every_use_tools_choice_is_validated_without_a_consuming_default() {
        let f = SourcesFixture::new();
        let one = f.write_repo("one.toml", &granting("helper", "openai"));
        // The positive control: the same choice, with nothing consuming it,
        // loads and leaves the source's own verb reachable.
        let catalog = f
            .with_project(&format!(
                "use_tools = [\"one:helper\"]\n{}",
                source_table("one", &one, false, true)
            ))
            .expect("a valid unused choice loads")
            .into_launch_catalog()
            .expect("the catalog builds");
        assert_eq!(entry_of(&catalog, "one:helper").tool().command(), "helper");
        // A choice naming no tool that source declares is a config error even
        // when no `default_tools` entry asks for it.
        let error = format!(
            "{:#}",
            f.with_project(&format!(
                "use_tools = [\"one:stale\"]\n{}",
                source_table("one", &one, false, true)
            ))
            .unwrap_err()
        );
        assert!(error.contains("use_tools:"), "{error}");
        assert!(
            error.contains("names no tool that source declares"),
            "{error}"
        );
        // An alias that names no sourced file is the same error, not an entry
        // that silently settles nothing.
        let error = format!(
            "{:#}",
            f.with_project(&format!(
                "use_tools = [\"nope:helper\"]\n{}",
                source_table("one", &one, false, true)
            ))
            .unwrap_err()
        );
        assert!(
            error.contains("names no tool that source declares"),
            "{error}"
        );
    }

    /// #749 V6/AC4: a project `default_tools` entry may name a tool explicitly
    /// as `<alias>:<tool>`. That entry resolves against the source it names
    /// only — never by bare-name rank — and a source that does not declare the
    /// tool is refused. The bare entry `use_tools` settles still works, and a
    /// qualified spelling is project-config only.
    #[test]
    fn a_qualified_project_default_resolves_against_its_source_only() {
        use CredentialProvider::*;
        let f = SourcesFixture::new();
        let one = f.write_repo("one.toml", &granting("helper", "openai"));
        let two = f.write_repo("two.toml", &granting("helper", "copilot"));
        let sources = format!(
            "{}{}",
            source_table("one", &one, false, true),
            source_table("two", &two, false, true)
        );

        // 1. A qualified entry under a conflicting bare name grants the named
        //    source's definition; the bare name itself stays in conflict.
        let catalog = f
            .with_project(&format!("default_tools = [\"two:helper\"]\n{sources}"))
            .expect("a qualified default entry loads")
            .into_launch_catalog()
            .expect("the catalog builds");
        assert!(
            catalog.name_conflict("helper").is_some(),
            "the bare name is still a conflict"
        );
        assert_eq!(
            catalog
                .direct_defaults()
                .provisioned()
                .iter()
                .collect::<Vec<_>>(),
            vec![Copilot],
            "the entry resolved against source two, not the first candidate"
        );

        // 2. A source that does not declare the tool is refused, and the
        //    refusal names the qualified entry.
        for entry in ["one:missing", "nope:helper"] {
            let error = format!(
                "{:#}",
                f.with_project(&format!("default_tools = [\"{entry}\"]\n{sources}"))
                    .unwrap_err()
            );
            assert!(error.contains("default_tools:"), "{entry}: {error}");
            assert!(error.contains(&format!("\"{entry}\"")), "{entry}: {error}");
            assert!(
                error.contains("names no tool that source declares"),
                "{entry}: {error}"
            );
        }

        // 3. The positive control: the bare entry the project's `use_tools`
        //    settles resolves through the same source.
        let catalog = f
            .with_project(&format!(
                "default_tools = [\"helper\"]\nuse_tools = [\"two:helper\"]\n{sources}"
            ))
            .expect("the settled bare entry loads")
            .into_launch_catalog()
            .expect("the catalog builds");
        assert_eq!(
            catalog
                .direct_defaults()
                .provisioned()
                .iter()
                .collect::<Vec<_>>(),
            vec![Copilot]
        );

        // 4. A qualified spelling is project-config only: a source grants what
        //    it declares, and no other file's alias is its to name.
        let qualified_source = f.base().join("qualified.toml");
        fs::write(
            &qualified_source,
            format!(
                "default_tools = [\"one:helper\"]\n{}",
                granting("helper", "openai")
            ),
        )
        .unwrap();
        let error = format!(
            "{:#}",
            f.with_project(&format!(
                "{}{}",
                source_table("one", &one, false, true),
                source_table("qualified", &qualified_source, true, true)
            ))
            .unwrap_err()
        );
        assert!(
            error.contains("project-config only"),
            "a source may not write a qualified default: {error}"
        );
    }

    /// A project definition outranks every source for the bare name, so a
    /// `default_tools` entry naming it grants the project's definition.
    #[test]
    fn a_project_default_resolves_project_local_first() {
        let f = SourcesFixture::new();
        let path = f.base().join("one.toml");
        fs::write(&path, granting("helper", "openai")).unwrap();
        let project = format!(
            "default_tools = [\"helper\"]\n{}{}",
            granting("helper", "anthropic"),
            source_table("one", &path, true, true)
        );
        let catalog = f
            .with_project(&project)
            .unwrap()
            .into_launch_catalog()
            .unwrap();
        assert_eq!(
            provisioned_of(&catalog, "shell"),
            vec![CredentialProvider::Anthropic]
        );
    }

    #[test]
    fn use_tools_settles_which_source_a_bare_default_means() {
        let f = SourcesFixture::new();
        let one = f.base().join("one.toml");
        let two = f.base().join("two.toml");
        fs::write(&one, granting("helper", "anthropic")).unwrap();
        fs::write(&two, granting("helper", "openai")).unwrap();
        let project = format!(
            "default_tools = [\"helper\"]\nuse_tools = [\"two:helper\"]\n{}{}",
            source_table("one", &one, true, true),
            source_table("two", &two, true, true)
        );
        let catalog = f
            .with_project(&project)
            .unwrap()
            .into_launch_catalog()
            .unwrap();
        assert_eq!(
            provisioned_of(&catalog, "shell"),
            vec![CredentialProvider::OpenAi],
            "the choice picks two's definition and nothing else"
        );
    }

    #[test]
    fn a_default_one_source_declares_resolves_across_sources() {
        let f = SourcesFixture::new();
        let one = f.base().join("one.toml");
        fs::write(&one, granting("helper", "openai")).unwrap();
        let project = format!(
            "default_tools = [\"helper\"]\n{}",
            source_table("one", &one, true, true)
        );
        let catalog = f
            .with_project(&project)
            .unwrap()
            .into_launch_catalog()
            .unwrap();
        assert_eq!(
            provisioned_of(&catalog, "shell"),
            vec![CredentialProvider::OpenAi]
        );
    }

    #[test]
    fn a_default_two_sources_declare_names_both_candidates() {
        let f = SourcesFixture::new();
        let one = f.base().join("one.toml");
        let two = f.base().join("two.toml");
        fs::write(&one, granting("helper", "anthropic")).unwrap();
        fs::write(&two, granting("helper", "openai")).unwrap();
        let project = format!(
            "default_tools = [\"helper\"]\n{}{}",
            source_table("one", &one, true, true),
            source_table("two", &two, true, true)
        );
        let error = format!("{:#}", f.with_project(&project).unwrap_err());
        for expected in ["\"one:helper\"", "\"two:helper\"", "use_tools"] {
            assert!(error.contains(expected), "{expected} missing: {error}");
        }
    }

    /// A source's own entries resolve within that source, and nothing else.
    #[test]
    fn a_sources_default_resolves_within_its_own_file() {
        let f = SourcesFixture::new();
        let one = f.base().join("one.toml");
        let two = f.base().join("two.toml");
        fs::write(
            &one,
            format!("default_tools = [\"mine\"]\n{}", granting("mine", "openai")),
        )
        .unwrap();
        fs::write(&two, granting("theirs", "anthropic")).unwrap();
        let project = format!(
            "{}{}",
            source_table("one", &one, true, true),
            source_table("two", &two, true, true)
        );
        let catalog = f
            .with_project(&project)
            .unwrap()
            .into_launch_catalog()
            .unwrap();
        assert_eq!(
            provisioned_of(&catalog, "shell"),
            vec![CredentialProvider::OpenAi]
        );

        // Naming another file's tool is a refusal in this source, not a silent skip.
        fs::write(&one, "default_tools = [\"theirs\"]\n").unwrap();
        let error = format!("{:#}", f.with_project(&project).unwrap_err());
        assert!(
            error.contains("\"theirs\" is not declared by source one"),
            "{error}"
        );
    }

    /// `allow = false` contributes nothing and its own list is inert, silently.
    #[test]
    fn a_disallowed_sources_defaults_are_inert() {
        let f = SourcesFixture::new();
        let one = f.base().join("one.toml");
        fs::write(
            &one,
            format!(
                "default_tools = [\"helper\"]\n{}",
                granting("helper", "openai")
            ),
        )
        .unwrap();
        let report = f
            .with_project(&source_table("one", &one, true, false))
            .expect("a disallowed source loads");
        let catalog = report.into_launch_catalog().unwrap();
        assert_eq!(
            provisioned_of(&catalog, "shell"),
            Vec::<CredentialProvider>::new(),
            "an allow = false source adopts no default"
        );
        assert_eq!(
            provisioned_of(&catalog, "one:helper"),
            vec![CredentialProvider::OpenAi],
            "its declaration is still a launch verb"
        );
    }

    /// The shell affordance is the bare `shell` route a non-source file supplies,
    /// or the fallback; it receives the effective list.
    #[test]
    fn the_shell_affordance_gets_the_effective_defaults() {
        use CredentialProvider::*;
        let fixture = Fixture::new();
        fixture.user(&format!(
            "default_tools = [\"helper\"]\n{}",
            granting("helper", "openai")
        ));
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert!(catalog.has_shell_fallback(), "no declaration names shell");
        assert_eq!(provisioned_of(&catalog, "shell"), vec![OpenAi]);
        assert_eq!(provisioned_of(&catalog, "helper"), vec![OpenAi]);

        // A **project** shell is the affordance itself (E3: only a project
        // declaration or the fallback may take the bare route).
        let fixture = Fixture::new();
        fixture.user(&format!(
            "default_tools = [\"helper\"]\n{}",
            granting("helper", "openai")
        ));
        fixture.project("[[tools]]\nname = \"shell\"\ncommand = \"zsh\"\n");
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert!(!catalog.has_shell_fallback());
        assert_eq!(provisioned_of(&catalog, "shell"), vec![OpenAi]);

        // A user shell is qualified; the fallback keeps the bare verb and the
        // default lands there instead.
        let fixture = Fixture::new();
        fixture.user(&format!(
            "default_tools = [\"helper\"]\n{}\n[[tools]]\nname = \"shell\"\ncommand = \"zsh\"\n",
            granting("helper", "openai")
        ));
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert!(catalog.has_shell_fallback());
        assert!(matches!(
            entry_of(&catalog, "shell").tool().origin(),
            ToolOrigin::BuiltIn
        ));
        assert_eq!(
            provisioned_of(&catalog, "home:shell"),
            Vec::<CredentialProvider>::new()
        );
        assert_eq!(provisioned_of(&catalog, "shell"), vec![OpenAi]);
    }

    /// Route, not name (#749 F6/E12): a uniquely named sourced `shell` keeps its
    /// own exact closure and receives none of the project's defaults — and it
    /// never takes the bare `shell` affordance, which stays the shipped
    /// fallback (E3).
    #[test]
    fn a_sourced_shell_does_not_take_the_defaults_over() {
        let f = SourcesFixture::new();
        let one = f.base().join("one.toml");
        fs::write(
            &one,
            format!(
                "[[tools]]\nname = \"shell\"\ncommand = \"zsh\"\ncredentials = [\"copilot\"]\n{}",
                granting("helper", "openai")
            ),
        )
        .unwrap();
        let project = format!(
            "default_tools = [\"helper\"]\n{}",
            source_table("one", &one, true, true)
        );
        let catalog = f
            .with_project(&project)
            .unwrap()
            .into_launch_catalog()
            .unwrap();
        let sourced = entry_of(&catalog, "one:shell");
        assert_eq!(
            sourced.provisioned().iter().collect::<Vec<_>>(),
            [CredentialProvider::Copilot]
        );
        assert!(
            !sourced
                .provisioned()
                .iter()
                .any(|provider| provider == CredentialProvider::OpenAi),
            "the project's default did not reach repo:shell"
        );
        // Approving a source can never replace the normal shell: the bare verb
        // still reaches the shipped fallback, and the default lands there.
        assert!(
            catalog.has_shell_fallback(),
            "a sourced `shell` must not suppress the fallback"
        );
        let fallback = entry_of(&catalog, "shell");
        assert!(
            matches!(fallback.tool().origin(), ToolOrigin::BuiltIn),
            "the bare verb reached a declaration, not the fallback"
        );
        assert_eq!(
            provisioned_of(&catalog, "shell"),
            vec![CredentialProvider::OpenAi],
            "the fallback is the affordance, so it receives the project's default"
        );
        // A user-declared `shell` is qualified too: the affordance is the
        // project's or the fallback's (E3/F6).
        let fixture = Fixture::new();
        fixture.user("[[tools]]\nname = \"shell\"\ncommand = \"zsh\"\n");
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert!(
            catalog.has_shell_fallback(),
            "a user `shell` must not suppress the fallback"
        );
        entry_of(&catalog, "home:shell");
        assert!(
            matches!(
                entry_of(&catalog, "shell").tool().origin(),
                ToolOrigin::BuiltIn
            ),
            "the bare verb is the fallback, not the user declaration"
        );
    }

    /// #749 E3/V1: two `shell` declarations are an ordinary configuration, not a
    /// broken one. The fallback owns the bare route, so no hidden conflict verb
    /// may be registered for a clap name the catalog already uses (that duplicate
    /// aborts every command in a debug build), and both declarations stay
    /// reachable by their qualified spellings.
    #[test]
    fn two_shell_declarations_leave_the_bare_route_to_the_fallback() {
        let two_sources = || {
            let f = SourcesFixture::new();
            let one = f.write_repo(
                "one.toml",
                "[[tools]]\nname = \"shell\"\ncommand = \"one-shell\"\n",
            );
            let two = f.write_repo(
                "two.toml",
                "[[tools]]\nname = \"shell\"\ncommand = \"two-shell\"\n",
            );
            let catalog = f
                .with_project(&format!(
                    "{}{}",
                    source_table("one", &one, false, true),
                    source_table("two", &two, false, true)
                ))
                .expect("two sourced shells load")
                .into_launch_catalog()
                .expect("the catalog builds");
            (catalog, "one:shell", "two:shell")
        };
        let (catalog, first, second) = two_sources();
        assert!(
            catalog.has_shell_fallback(),
            "E3: the bare `shell` route is the fallback when sources collide"
        );
        assert!(
            matches!(
                entry_of(&catalog, "shell").tool().origin(),
                ToolOrigin::BuiltIn
            ),
            "the bare verb is the fallback, not a sourced declaration"
        );
        assert_eq!(entry_of(&catalog, first).tool().command(), "one-shell");
        assert_eq!(entry_of(&catalog, second).tool().command(), "two-shell");
        // The debug build's clap assertions are the whole point: this must not
        // panic with "command name `shell` is duplicated".
        let mut command = crate::cli::build_command(&Catalog::Ready(catalog));
        command.build();
        let names: Vec<&str> = command
            .get_subcommands()
            .map(clap::Command::get_name)
            .collect();
        for verb in ["shell", first, second] {
            assert!(names.contains(&verb), "{verb} is not registered: {names:?}");
        }

        // The same collision across the user tier and a source: `home:shell` and
        // `repo:shell` stay reachable, and the bare route is still the fallback.
        let f = SourcesFixture::new();
        f.write_user("[[tools]]\nname = \"shell\"\ncommand = \"home-shell\"\n");
        let repo = f.write_repo(
            "repo.toml",
            "[[tools]]\nname = \"shell\"\ncommand = \"repo-shell\"\n",
        );
        let catalog = f
            .with_project(&format!(
                "{}{}",
                sources_block(&[HOME_SOURCE]),
                source_table("repo", &repo, false, true)
            ))
            .expect("a user and a sourced shell load")
            .into_launch_catalog()
            .expect("the catalog builds");
        assert!(
            matches!(
                entry_of(&catalog, "shell").tool().origin(),
                ToolOrigin::BuiltIn
            ),
            "a user `shell` does not take the bare route from the fallback"
        );
        assert_eq!(
            entry_of(&catalog, "home:shell").tool().command(),
            "home-shell"
        );
        assert_eq!(
            entry_of(&catalog, "repo:shell").tool().command(),
            "repo-shell"
        );
        crate::cli::build_command(&Catalog::Ready(catalog)).debug_assert();
    }

    /// #749 T5: the shell's own persist list and the granted `default_tools`
    /// list are validated as **one** merged set, not separately. Two overlapping
    /// but distinct paths would otherwise reach the guest-HOME link list from one
    /// launch, where one shadows the other.
    #[test]
    fn a_merged_default_grant_cannot_claim_a_persist_path_twice() {
        let fixture = Fixture::new();
        fixture.project(
            "default_tools = [\"helper\"]\n\
             [[tools]]\nname = \"shell\"\ncommand = \"bash\"\npersist = [\"shared\"]\n\
             [[tools]]\nname = \"helper\"\ncommand = \"helper\"\npersist = [\"shared/nested\"]\n",
        );
        let error = format!(
            "{:#}",
            fixture.load().unwrap().into_launch_catalog().unwrap_err()
        );
        assert!(
            error.contains("overlaps"),
            "the merged pair is one claim set: {error}"
        );
        assert!(error.contains("\"shell\""), "{error}");
        assert!(error.contains("\"helper\""), "{error}");

        // The control: the same two lists disjunct are fine, and the affordance
        // still carries both.
        let fixture = Fixture::new();
        fixture.project(
            "default_tools = [\"helper\"]\n\
             [[tools]]\nname = \"shell\"\ncommand = \"bash\"\npersist = [\"own\"]\n\
             [[tools]]\nname = \"helper\"\ncommand = \"helper\"\npersist = [\"nested/helper\"]\n",
        );
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(persist_of(&catalog, "shell"), ["own", "nested/helper"]);
    }

    /// E5: the shipped list is the shell's own compatibility grant. It is not the
    /// effective union, and a direct command gets nothing from it.
    #[test]
    fn the_shipped_list_is_the_shells_alone() {
        use CredentialProvider::*;
        let catalog = default_launch_catalog().unwrap();
        assert_eq!(
            provisioned_of(&catalog, "shell"),
            vec![Anthropic, OpenAi, OpencodeStatic, Copilot, Antigravity],
            "six names, five providers, provisioned and not required"
        );
        assert!(persist_of(&catalog, "shell").contains(&".dsh".to_string()));
    }

    /// #749 E2 (revised) with E5: the shipped definitions are a **shell
    /// fallback**, nothing more. They are consulted only for the shell
    /// affordance, only when no declaration claims that route, and they never
    /// satisfy a `default_tools` entry or another bare verb.
    #[test]
    fn shipped_definitions_are_only_a_shell_fallback() {
        // 1. A declared name beats a shipped one: the declaration is the verb.
        let fixture = Fixture::new();
        fixture.user("[[tools]]\nname = \"pi\"\ncommand = \"user-pi\"\n");
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(verbs_of(&catalog), ["pi", "shell"]);
        assert_eq!(entry_of(&catalog, "pi").tool().command(), "user-pi");
        assert!(
            matches!(
                entry_of(&catalog, "shell").tool().origin(),
                ToolOrigin::BuiltIn
            ),
            "and the bare shell verb is the shipped fallback"
        );

        // 2. A shipped name the file does not declare is not a verb: no rank
        //    restores the shipped agent behind a declaration's back.
        for name in ["dsh", "codex", "opencode", "claude", "copilot"] {
            assert!(
                catalog
                    .as_slice()
                    .iter()
                    .all(|entry| !entry.is_launched_as(name)),
                "{name} must not be a verb"
            );
        }

        // 3. A `default_tools` entry naming only a shipped tool is refused,
        //    naming the tool: shipped definitions never satisfy a grant.
        let fixture = Fixture::new();
        fixture.project(
            "default_tools = [\"codex\"]\n[[tools]]\nname = \"solo\"\ncommand = \"solo\"\n",
        );
        let error = format!("{:#}", fixture.load().unwrap_err());
        assert!(error.contains("\"codex\""), "{error}");
        assert!(
            error.contains("names no tool any readable config declares"),
            "{error}"
        );

        // The control: with no declaration at all the shipped catalog *is* the
        // catalog, so the same entry names a real tool and is honoured (E5).
        let fixture = Fixture::new();
        fixture.project("default_tools = [\"codex\"]\n");
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(
            catalog.direct_defaults().names(),
            ["codex"],
            "the authored entry resolves against the shipped catalog it is in"
        );
        assert_eq!(
            catalog
                .direct_defaults()
                .provisioned()
                .iter()
                .collect::<Vec<_>>(),
            vec![CredentialProvider::OpenAi]
        );
    }

    // -- #749 G: the wildcard retirement ----------------------------------

    #[test]
    fn a_tools_wildcard_is_refused_with_its_replacement() {
        let fixture = Fixture::new();
        let error = format!(
            "{:#}",
            fixture
                .user(
                    "[[tools]]\nname = \"pi\"\ncommand = \"pi\"\ntools = [\"*\"]\n\
                     [[tools]]\nname = \"codex\"\ncommand = \"codex\"\n"
                )
                .load()
                .unwrap_err()
        );
        assert!(error.contains("`*` is retired"), "{error}");
        assert!(error.contains("default_tools"), "{error}");
        // The control: a valid named list still loads and still provisions.
        let fixture = Fixture::new();
        fixture.user(
            "[[tools]]\nname = \"pi\"\ncommand = \"pi\"\ntools = [\"codex\"]\n\
             [[tools]]\nname = \"codex\"\ncommand = \"codex\"\ncredentials = [\"openai\"]\n",
        );
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(
            provisioned_of(&catalog, "pi"),
            vec![CredentialProvider::OpenAi]
        );
    }

    /// The shell's omitted list no longer means `["*"]`: without a
    /// `default_tools` list it provisions nothing but itself.
    #[test]
    fn an_omitted_tools_list_no_longer_wildcards() {
        use CredentialProvider::*;
        let fixture = Fixture::new();
        fixture.user(
            "[[tools]]\nname = \"shell\"\ncommand = \"zsh\"\n\
             [[tools]]\nname = \"claude\"\ncommand = \"claude\"\ncredentials = [\"anthropic\"]\n",
        );
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(
            provisioned_of(&catalog, "shell"),
            Vec::<CredentialProvider>::new()
        );
        assert_eq!(provisioned_of(&catalog, "claude"), vec![Anthropic]);
    }

    /// #749 E8/E10: a granted default whose declaring read failed does not shrink
    /// the grant silently — the shell launch is refused with that read's verdict.
    #[test]
    fn a_blocked_default_contributor_refuses_the_shell_launch() {
        let fixture = Fixture::new();
        let target = fixture.user.with_file_name("dotfile");
        write_file(&target, &granting("pi", "openai"));
        std::os::unix::fs::symlink(&target, &fixture.user).unwrap();
        fixture.project("default_tools = [\"pi\"]\n");
        let catalog = fixture
            .load()
            .expect("a tools-only dotfile still loads")
            .into_launch_catalog()
            .unwrap();
        let shell = entry_of(&catalog, "shell");
        let trust = shell
            .launch_trust()
            .expect("the grant carries its contributor's measured verdict");
        let error = format!("{:#}", trust.require_for_trusted_tool().unwrap_err());
        assert!(
            error.contains("requires config.toml to be a regular file"),
            "{error}"
        );
        // The positive control: the same grant from a regular file launches.
        let fixture = Fixture::new();
        fixture.user(&granting("pi", "openai"));
        fixture.project("default_tools = [\"pi\"]\n");
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert!(entry_of(&catalog, "shell").launch_trust().is_none());
        assert_eq!(
            provisioned_of(&catalog, "shell"),
            vec![CredentialProvider::OpenAi]
        );
    }
}
