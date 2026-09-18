//! Read-only **tool configuration**: discovery, strict parsing, validation,
//! and the ordered user/project merge that `agent-vm doctor` previews.
//!
//! A **tool declaration** (`[[tools]]` in a config file) is *data*: a guest
//! command, its default argv, an optional tooling layer, the credential
//! providers it needs, extra guest-HOME-relative paths to persist, and guest
//! env pairs. This module never executes a command, creates guest state,
//! builds a layer, or captures a credential.
//!
//! # Two ordered catalogs, not an overlay
//!
//! The user file (`$HOME/.config/agent-vm/config.toml`) and the project file
//! (`<cwd>/.agent-vm/config.toml`) are two ordered *catalogs*. The project may
//! add whole tool definitions the user did not write; a name the user did
//! write is authoritative and the entire user definition wins (never a
//! field-by-field merge). Resolved order is user declarations first, then
//! project-only declarations. Only when **both** lists are empty do the five
//! compiled-in defaults (embedded from `default-tools.toml`) apply.
//!
//! ```
//! user file --------> parse + validate --+
//!                                        +--> ordered union  --> validate
//! project file -----> parse + validate --+    + conflicts        persist
//!                                                              ownership
//! both empty? -> embedded defaults ------+
//! ```
//!
//! Every tier is parsed and validated *before* merging, so an invalid
//! project declaration fails even when the user shadowed its name. The final
//! cross-tool persist-ownership check runs *after* merging, over the winners
//! only.
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
//! subcommands) and `doctor` (to render them) both start from: the resolved
//! merge result plus the built-in `shell` fallback (see [`LaunchCatalog`]).
//! Layer paths are still metadata only — they are compared as declared values
//! and never resolved, checked for existence, or built (#84). Persisted-path
//! overlap safety is defined here (#83): [`guest_paths_overlap`] backs the
//! within-tool, cross-tool and reserved-link checks, and `guest_home::links`
//! turns the surviving paths into the one guest-HOME link list both
//! guest-user modes provision from.

use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

use anyhow::{Result, anyhow};
use serde::Deserialize;
use vstd::prelude::*;

use crate::credential_provider::{CredentialProvider, ProviderSet};

/// Ceiling on a config file read. A project config is possibly untrusted
/// input, so a huge or special file must not be able to hang or exhaust
/// `doctor`. Deliberately a *config* policy constant, not the credential
/// file's limit.
const MAX_CONFIG_FILE_BYTES: u64 = 1024 * 1024;

const USER_CONFIG_RELATIVE: &str = ".config/agent-vm/config.toml";
const PROJECT_CONFIG_RELATIVE: &str = ".agent-vm/config.toml";

/// Subcommands `agent-vm` reserves for itself. A tool named after one would be
/// unreachable through the CLI, so it is rejected at validation. The launch
/// verbs **are** the tools (a tool named `claude` is the normal case), so the
/// reserved set is exactly the fixed built-ins plus clap's synthesized
/// `help`. `cli::BUILTIN_SUBCOMMANDS` must stay a superset of this list.
pub(crate) const RESERVED_TOOL_NAMES: &[&str] = &[
    "setup",
    "pull",
    "msb",
    "clipboard",
    "doctor",
    "_intercept-hook",
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
}

impl ConfigPaths {
    /// The environment adapter: resolve `$HOME` and the canonical cwd.
    ///
    /// There is deliberately no `XDG_CONFIG_HOME` or override variable in
    /// this PR — the ticket names the literal `$HOME` location.
    pub(crate) fn discover() -> Result<Self> {
        Ok(Self {
            user: discover_user_path()?,
            project: discover_project_path()?,
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

    /// The pure merge result, without the launch fallback. Test-only: launch
    /// and `doctor` both consume [`ConfigReport::into_launch_catalog`] so their
    /// verb lists cannot disagree.
    #[cfg(test)]
    pub(crate) fn resolved(&self) -> &ResolvedTools {
        &self.resolved
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
        catalog_from_tools(resolved.0)
    }
}

/// Append the built-in `shell` fallback when no declared tool claims the name,
/// then resolve every entry's provisioning facets. The one constructor for both
/// a loaded config ([`ConfigReport::into_launch_catalog`]) and the compiled-in
/// defaults ([`default_launch_catalog`]), so the fallback cannot differ between
/// them.
fn catalog_from_tools(mut tools: Vec<Tool>) -> Result<LaunchCatalog> {
    let shell_fallback_added = !tools.iter().any(|tool| tool.name() == SHELL_TOOL_NAME);
    if shell_fallback_added {
        tools.push(builtin_shell()?);
    }
    Ok(LaunchCatalog {
        entries: resolve_provisioning(tools)?,
        shell_fallback_added,
    })
}

/// The compiled-in default launch catalog, resolved without touching the
/// environment. Used by `setup` to verify the shipped tools when a project or
/// user config is broken (a missing default entry is already a hard error, so
/// this cannot itself fail on the shipped catalog), and by tests.
pub(crate) fn default_launch_catalog() -> Result<LaunchCatalog> {
    catalog_from_tools(default_tools()?)
}

/// The `command` values of the compiled-in default tools: the binaries the
/// published image is contractually required to carry. `setup` derives its
/// fatal-vs-warn severity from membership here, **not** from a tool's
/// [`ToolOrigin`], because that contract belongs to the *binary*, not to the
/// tier that declared the tool. Otherwise a user config that restates `claude`
/// (to change `args`, say) would turn a missing `claude` back into a warning.
/// Derived from [`default_tools`], never hand-copied.
///
/// `Result` because the compiled-in defaults are parsed through the same
/// raw-to-validated path as user input; a broken default is already a hard
/// error elsewhere ([`default_launch_catalog`]).
pub(crate) fn shipped_tool_commands() -> Result<Vec<String>> {
    Ok(default_tools()?
        .iter()
        .map(|tool| tool.command().to_string())
        .collect())
}

/// The shipped default layer sequence — the projection `tool_layer::chain_root`
/// compares a configured catalog against to decide the chain root (issue #84's
/// fast path). Derived from [`default_tools`], never hand-copied, in declaration
/// order; tools with no `layer` (such as `shell`) contribute nothing.
pub(crate) fn shipped_tool_layers() -> Result<Vec<ToolLayer>> {
    Ok(default_tools()?
        .into_iter()
        .filter_map(|tool| tool.layer().cloned())
        .collect())
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
    shell_fallback_added: bool,
}

/// One launch-catalog entry: a tool plus the provisioning set resolved for it.
/// The set is computed once, here, because every consumer (launch, the proxy,
/// the guest env, `doctor`) must agree on it exactly.
#[derive(Debug)]
pub(crate) struct CatalogEntry {
    tool: Tool,
    provisioned: ProviderSet,
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

    /// True when the built-in `shell` was appended because no declared tool
    /// claimed the name; `doctor` labels the row from this.
    pub(crate) fn shell_fallback_added(&self) -> bool {
        self.shell_fallback_added
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
        Some(self.entries.remove(index))
    }

    /// Every tool layer this catalog declares, in catalog (declaration) order,
    /// deduplicated by layer value (two tools naming the same `{ builtin = … }`
    /// produce one chain step, not two identical installs).
    ///
    /// The image a launch boots is a property of the **whole catalog**, not of
    /// the invoked verb, so this must be read *before* [`Self::take_entry`]
    /// removes one — otherwise the launched tool's own layer is dropped.
    pub(crate) fn declared_layers(&self) -> Vec<DeclaredLayer> {
        let mut seen: Vec<&ToolLayer> = Vec::new();
        let mut out = Vec::new();
        for entry in &self.entries {
            let tool = entry.tool();
            let Some(layer) = tool.layer() else {
                continue;
            };
            if seen.contains(&layer) {
                continue;
            }
            seen.push(layer);
            out.push(DeclaredLayer {
                tool: tool.name().to_string(),
                command: tool.command().to_string(),
                layer: layer.clone(),
                anchor: match tool.origin() {
                    ToolOrigin::BuiltIn => None,
                    // D7: a `path` layer anchors on the directory of the config
                    // file that declared it — a user-tier config's cwd is
                    // arbitrary, so the declaring file is the only well-defined
                    // anchor.
                    ToolOrigin::User(file) | ToolOrigin::Project(file) => {
                        file.parent().map(Path::to_path_buf)
                    }
                },
            });
        }
        out
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

/// The resolved tool catalog, in composition order. The inner value has no
/// mutable access.
#[derive(Debug)]
pub(crate) struct ResolvedTools(Vec<Tool>);

impl ResolvedTools {
    /// The pure merge result, without the launch fallback. Used by the merge
    /// tests and proptests; launch/doctor go through
    /// [`ConfigReport::into_launch_catalog`] instead.
    #[cfg(test)]
    pub(crate) fn as_slice(&self) -> &[Tool] {
        &self.0
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
/// equality.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ToolOrigin {
    BuiltIn,
    User(PathBuf),
    Project(PathBuf),
}

/// One validated tool definition. All fields are private; readers use the
/// accessors below.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Tool {
    name: ToolName,
    command: String,
    argv: Vec<String>,
    layer: Option<ToolLayer>,
    credentials: Vec<CredentialProvider>,
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

    /// True when the user's trailing args must be joined into a single bash
    /// `-c` command line instead of appended as separate `argv` entries (see
    /// `run::inner_argv`). A first-class config field rather than a
    /// `command == "bash"` check, which would silently misbehave for a
    /// user-declared `zsh`, `/bin/bash`, or `sh`.
    pub(crate) fn is_interactive_shell(&self) -> bool {
        self.interactive_shell
    }

    pub(crate) fn layer(&self) -> Option<&ToolLayer> {
        self.layer.as_ref()
    }

    pub(crate) fn credentials(&self) -> &[CredentialProvider] {
        &self.credentials
    }

    /// The catalog tools this tool declares. Names are resolved against the
    /// **launch catalog** (which includes the appended `shell` fallback), not
    /// against the tier that declared them.
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
    /// rejects them, because the launcher publishes them only in non-root
    /// mode and position would not protect them under `--root`. See
    /// ADR-0016.
    pub(crate) fn guest_env(&self) -> &BTreeMap<String, String> {
        &self.env
    }

    /// Count only, for the same reason as [`Self::arg_count`]: a value may be
    /// a credential a user pasted here by mistake.
    pub(crate) fn env_count(&self) -> usize {
        self.env.len()
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
            && self.layer == other.layer
            && self.credentials == other.credentials
            && self.tools == other.tools
            && self.persist == other.persist
            && self.interactive_shell == other.interactive_shell
            && self.env == other.env
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
        if self.layer != other.layer {
            fields.push(ToolField::Layer);
        }
        if self.credentials != other.credentials {
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
    /// Closes over the tools declared in the **same configuration file** as
    /// this tool (origin equality; `BuiltIn` = the embedded
    /// `default-tools.toml`) — never the merged catalog.
    All,
    /// Declaration order preserved (definition equality is order-significant,
    /// exactly like `credentials`). May be empty; may name the tool itself.
    Named(Vec<ToolName>),
}

/// A tool's optional tooling layer. In this PR it is metadata only: a builtin
/// selector or a declared path that is never resolved or built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ToolLayer {
    Builtin(BuiltinLayer),
    Path(LayerPath),
}

/// The closed set of builtin layers agent-vm can `FROM`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BuiltinLayer {
    Codex,
    Opencode,
    Claude,
    Copilot,
}

impl BuiltinLayer {
    pub(crate) const ALL: [BuiltinLayer; 4] = [
        BuiltinLayer::Codex,
        BuiltinLayer::Opencode,
        BuiltinLayer::Claude,
        BuiltinLayer::Copilot,
    ];

    fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|layer| layer.as_str() == name)
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            BuiltinLayer::Codex => "codex",
            BuiltinLayer::Opencode => "opencode",
            BuiltinLayer::Claude => "claude",
            BuiltinLayer::Copilot => "copilot",
        }
    }

    fn supported_names() -> String {
        Self::ALL
            .into_iter()
            .map(BuiltinLayer::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// A declared layer path, kept exactly as written (nonempty, NUL-free) at parse
/// time; anchored and existence-checked by `tool_layer::materialize` (D7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LayerPath(PathBuf);

impl LayerPath {
    pub(crate) fn as_path(&self) -> &Path {
        &self.0
    }

    /// Re-anchor this declared path against the directory of the config file
    /// that declared it (D7). An absolute path is returned unchanged; a
    /// relative one is joined onto `anchor`. The caller then canonicalises and
    /// validates existence, so a missing anchor is a hard error rather than a
    /// silent cwd-relative resolution.
    pub(crate) fn anchored(&self, anchor: Option<&Path>) -> Result<PathBuf> {
        if self.0.is_absolute() {
            return Ok(self.0.clone());
        }
        let anchor = anchor.ok_or_else(|| {
            anyhow!(
                "config: layer path {} is relative but its declaring config file has no \
                 directory to anchor it against",
                quoted_path(&self.0)
            )
        })?;
        Ok(anchor.join(&self.0))
    }
}

/// One tool layer the catalog declares, with the anchor its `path` form resolves
/// against (D7). Ordered and deduplicated by
/// [`LaunchCatalog::declared_layers`]. Carries the tool's guest `command` so
/// `setup` can decide which verification targets a not-yet-composed layer
/// supplies (D10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeclaredLayer {
    tool: String,
    command: String,
    layer: ToolLayer,
    /// `dirname` of the declaring config file; `None` for the built-in tier.
    anchor: Option<PathBuf>,
}

impl DeclaredLayer {
    pub(crate) fn tool(&self) -> &str {
        &self.tool
    }

    pub(crate) fn command(&self) -> &str {
        &self.command
    }

    pub(crate) fn layer(&self) -> &ToolLayer {
        &self.layer
    }

    pub(crate) fn anchor(&self) -> Option<&Path> {
        self.anchor.as_deref()
    }
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
    Layer,
    Credentials,
    Tools,
    Persist,
    // Appended last: `each_differing_field_is_reported_individually_in_fixed_order`
    // and the multi-field ordering test depend on this sequence.
    InteractiveShell,
    Env,
}

impl ToolField {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ToolField::Command => "command",
            ToolField::Args => "args",
            ToolField::Layer => "layer",
            ToolField::Credentials => "credentials",
            ToolField::Tools => "tools",
            ToolField::Persist => "persist",
            ToolField::InteractiveShell => "interactive_shell",
            ToolField::Env => "env",
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
    let (user, user_tools) = match &paths.user {
        Some(path) => read_file_tier(path, TierKind::User)?,
        None => (
            TierReport {
                path: None,
                status: TierStatus::UnavailableHome,
            },
            Vec::new(),
        ),
    };
    let (project, project_tools) = read_file_tier(&paths.project, TierKind::Project)?;

    let (resolved, uses_defaults, conflicts) = if user_tools.is_empty() && project_tools.is_empty()
    {
        (default_tools()?, true, Vec::new())
    } else {
        let (merged, conflicts) = merge(user_tools, project_tools);
        (merged, false, conflicts)
    };

    validate_persist_ownership(&resolved)?;

    Ok(ConfigReport {
        user,
        project,
        resolved: ResolvedTools(resolved),
        uses_defaults,
        conflicts,
    })
}

#[derive(Clone, Copy)]
enum TierKind {
    User,
    Project,
    BuiltIn,
}

impl TierKind {
    fn origin(self, file: &Path) -> ToolOrigin {
        match self {
            TierKind::User => ToolOrigin::User(file.to_path_buf()),
            TierKind::Project => ToolOrigin::Project(file.to_path_buf()),
            TierKind::BuiltIn => ToolOrigin::BuiltIn,
        }
    }
}

/// Read, decode, and validate one file-backed tier. Only a `NotFound` from
/// the initial `symlink_metadata` means absent; a present-but-dangling
/// symlink or a file that vanishes before the read is an error, not a quiet
/// fallback.
fn read_file_tier(path: &Path, kind: TierKind) -> Result<(TierReport, Vec<Tool>)> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((
                TierReport {
                    path: Some(path.to_path_buf()),
                    status: TierStatus::Absent,
                },
                Vec::new(),
            ));
        }
        Err(error) => return Err(safe_io_error("reading metadata for", path, &error)),
    }

    let bytes = crate::host_paths::read_bounded_regular_file(path, MAX_CONFIG_FILE_BYTES)
        .map_err(|error| safe_anyhow_error("reading", path, &error))?;
    let text = std::str::from_utf8(&bytes).map_err(|_| utf8_error(path))?;
    let raw: RawConfig =
        toml::from_str(text).map_err(|error| deserialize_error(path, text, &error))?;
    let tools = validate_tools(raw.tools, path, kind)?;

    Ok((
        TierReport {
            path: Some(path.to_path_buf()),
            status: TierStatus::Found {
                declared_tools: tools.len(),
            },
        },
        tools,
    ))
}

/// Parse the embedded fallback catalog through the same validated path.
fn default_tools() -> Result<Vec<Tool>> {
    let path = Path::new("default-tools.toml");
    let raw: RawConfig = toml::from_str(DEFAULT_TOOLS_TOML)
        .map_err(|error| deserialize_error(path, DEFAULT_TOOLS_TOML, &error))?;
    validate_tools(raw.tools, path, TierKind::BuiltIn)
}

fn discover_user_path() -> Result<Option<PathBuf>> {
    let Some(home) = std::env::var_os("HOME") else {
        return Ok(None);
    };
    let home = PathBuf::from(home);
    if home.as_os_str().is_empty() {
        return Err(anyhow!(
            "config: $HOME is set but empty; cannot locate {}",
            quoted_str(USER_CONFIG_RELATIVE)
        ));
    }
    if !home.is_absolute() {
        return Err(anyhow!(
            "config: $HOME {} is not absolute; cannot locate {}",
            quoted_path(&home),
            quoted_str(USER_CONFIG_RELATIVE)
        ));
    }
    Ok(Some(home.join(USER_CONFIG_RELATIVE)))
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
/// Both declaring files come from the tools' provenance rather than the
/// caller, so a conflict warning never fabricates a placeholder path.
fn merge(user_tools: Vec<Tool>, project_tools: Vec<Tool>) -> (Vec<Tool>, Vec<ConfigConflict>) {
    let index: HashMap<String, usize> = user_tools
        .iter()
        .enumerate()
        .map(|(position, tool)| (tool.name.as_str().to_string(), position))
        .collect();

    let mut resolved = user_tools;
    let mut conflicts = Vec::new();
    for project_tool in project_tools {
        match index.get(project_tool.name.as_str()) {
            Some(&position) => {
                let winner = &resolved[position];
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
            None => resolved.push(project_tool),
        }
    }
    (resolved, conflicts)
}

/// Overlap ownership across the resolved winners: two distinct tools may not
/// claim the same guest-HOME-relative location, nor an ancestor/descendant pair
/// (linking both would leave one path a dangling symlink and make the other
/// uncreatable). The compiled-in link list is checked separately, per tool, in
/// [`validate_persist`]; the launch's guest mount points are checked in
/// `run::launch` because the project path is not a config fact.
fn validate_persist_ownership(tools: &[Tool]) -> Result<()> {
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

fn describe_origin(origin: &ToolOrigin) -> String {
    match origin {
        ToolOrigin::BuiltIn => "built-in defaults".to_string(),
        ToolOrigin::User(file) => format!("user config {}", quoted_path(file)),
        ToolOrigin::Project(file) => format!("project config {}", quoted_path(file)),
    }
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

/// Resolve every tool's provisioning set as the least fixed point of
///
/// ```text
/// provisioning(t) = credentials(t) ∪ ⋃ { provisioning(u) | u ∈ tools(t) }
/// ```
///
/// where `tools(t)` names catalog tools and a `"*"` entry expands to the tools
/// **declared in the same configuration file as `t`** — the tools whose
/// `ToolOrigin` equals `t`'s — not to the whole catalog.
///
/// Dangling references fail closed *before* any closure is walked, so the
/// diagnostic names the declaring file rather than a half-resolved set. The
/// dangling check is over the **merged catalog** (an explicit name is the
/// cross-file opt-in), which is deliberately wider than the wildcard's group.
fn resolve_provisioning(tools: Vec<Tool>) -> Result<Vec<CatalogEntry>> {
    let index: HashMap<String, usize> = tools
        .iter()
        .enumerate()
        .map(|(position, tool)| (tool.name.as_str().to_string(), position))
        .collect();

    for tool in &tools {
        if let DeclaredTools::Named(names) = tool.declared_tools() {
            for (position, reference) in names.iter().enumerate() {
                if !index.contains_key(reference.as_str()) {
                    return Err(tool_error(
                        origin_file(&tool.origin),
                        tool.declaration_index,
                        &tool.name,
                        format!(
                            "tools[{position}]: {} names no tool in the resolved catalog; \
                             declare that tool or remove the entry",
                            quoted_str(reference.as_str())
                        ),
                    ));
                }
            }
        }
    }

    // One closure per tool, then both facets folded over it in catalog order so
    // the result is deterministic (the closure's stack-pop order is not).
    let closures: Vec<Vec<bool>> = (0..tools.len())
        .map(|start| launch_closure(&tools, &index, start))
        .collect();
    let facets: Vec<(ProviderSet, Vec<PersistPath>)> = closures
        .iter()
        .map(|visited| {
            let mut provisioned = ProviderSet::default();
            let mut persist = Vec::new();
            for (position, seen) in visited.iter().enumerate() {
                if !*seen {
                    continue;
                }
                provisioned = provisioned.union(tools[position].credential_providers());
                persist.extend(tools[position].persist().iter().cloned());
            }
            (provisioned, persist)
        })
        .collect();
    Ok(tools
        .into_iter()
        .zip(facets)
        .map(|(tool, (provisioned, persist))| CatalogEntry {
            tool,
            provisioned,
            persist,
        })
        .collect())
}

/// One tool's closure: which catalog tools a launch `start` visits, as a
/// visited-tool mask. The least fixed point of `tools`, with `"*"` closing over
/// the declaring tool's own configuration file. A cycle is harmless rather than
/// an error: `visited` admits each tool at most once, so the walk terminates at
/// the fixed point. (`shell`'s wildcard necessarily includes `shell` itself.)
fn launch_closure(tools: &[Tool], index: &HashMap<String, usize>, start: usize) -> Vec<bool> {
    let mut visited = vec![false; tools.len()];
    let mut stack = vec![start];
    while let Some(position) = stack.pop() {
        if std::mem::replace(&mut visited[position], true) {
            continue;
        }
        let tool = &tools[position];
        match tool.declared_tools() {
            // `"*"` closes over the declaring tool's **own configuration
            // file** — the tools whose origin equals this tool's. In the
            // shipped default catalog every tool is `BuiltIn` (the embedded
            // `default-tools.toml`), so this is all five; when a user config
            // replaces the defaults the appended fallback shell is the only
            // `BuiltIn` tool, so it closes over itself alone and provisions
            // only its own (empty) `credentials`.
            DeclaredTools::All => {
                let origin = tool.origin();
                stack.extend(
                    tools
                        .iter()
                        .enumerate()
                        .filter(|(_, candidate)| candidate.origin() == origin)
                        .map(|(position, _)| position),
                );
            }
            // Every name was proven present by `resolve_provisioning` above.
            DeclaredTools::Named(names) => stack.extend(
                names
                    .iter()
                    .filter_map(|reference| index.get(reference.as_str()).copied()),
            ),
        }
    }
    visited
}

// ---------------------------------------------------------------------------
// Raw schema and validation
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
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
    layer: Option<RawLayer>,
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
}

/// A small optional-fields struct plus exhaustive validation produces a
/// clearer diagnosis than an untagged enum that would silently accept a
/// second selector key.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLayer {
    #[serde(default)]
    builtin: Option<String>,
    #[serde(default)]
    path: Option<String>,
}

fn validate_tools(raw: Vec<RawTool>, file: &Path, kind: TierKind) -> Result<Vec<Tool>> {
    let mut tools = Vec::with_capacity(raw.len());
    let mut first_index: HashMap<String, usize> = HashMap::new();
    for (index, tool) in raw.into_iter().enumerate() {
        let name = validate_name(&tool.name, file, index)?;
        if let Some(&first) = first_index.get(name.as_str()) {
            return Err(declaration_error(
                file,
                index,
                Some(name.as_str()),
                format!(
                    "duplicate tool name; already declared at declaration [{first}]. Tool names must be unique within a config file"
                ),
            ));
        }
        first_index.insert(name.as_str().to_string(), index);

        let command = validate_command(&tool.command, file, index, &name)?;
        let argv = validate_argv(tool.args, file, index, &name)?;
        let layer = validate_layer(tool.layer, file, index, &name)?;
        let credentials = validate_credentials(tool.credentials, file, index, &name)?;
        let tools_field = validate_tool_refs(tool.tools, file, index, &name)?;
        let persist = validate_persist(tool.persist, file, index, &name)?;
        let env = validate_env(tool.env, file, index, &name)?;

        tools.push(Tool {
            name,
            command,
            argv,
            layer,
            credentials,
            tools: tools_field,
            persist,
            interactive_shell: tool.interactive_shell,
            env,
            origin: kind.origin(file),
            declaration_index: index,
        });
    }
    Ok(tools)
}

fn validate_name(raw: &str, file: &Path, index: usize) -> Result<ToolName> {
    if raw.is_empty() {
        return Err(declaration_error(
            file,
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
            file,
            index,
            Some(raw),
            "name must not contain whitespace or control characters",
        ));
    }
    if raw.starts_with('-') {
        return Err(declaration_error(
            file,
            index,
            Some(raw),
            "name must not start with '-'",
        ));
    }
    if raw.contains('/') {
        return Err(declaration_error(
            file,
            index,
            Some(raw),
            "name must be a single command-name token, not a path",
        ));
    }
    if raw.chars().all(|character| character == '.') {
        return Err(declaration_error(
            file,
            index,
            Some(raw),
            "name must not be `.` or `..`",
        ));
    }
    if raw == ALL_TOOLS_WILDCARD {
        return Err(declaration_error(
            file,
            index,
            Some(raw),
            "name `*` is reserved: it is the wildcard in a tool's `tools` list",
        ));
    }
    if RESERVED_TOOL_NAMES.contains(&raw) {
        return Err(declaration_error(
            file,
            index,
            Some(raw),
            "name is reserved for an agent-vm subcommand; choose another name",
        ));
    }
    Ok(ToolName(raw.to_string()))
}

fn validate_command(raw: &str, file: &Path, index: usize, name: &ToolName) -> Result<String> {
    if raw.is_empty() {
        return Err(tool_error(file, index, name, "command must not be empty"));
    }
    if raw.contains('\0') {
        return Err(tool_error(
            file,
            index,
            name,
            "command must not contain NUL",
        ));
    }
    Ok(raw.to_string())
}

fn validate_argv(
    raw: Vec<String>,
    file: &Path,
    index: usize,
    name: &ToolName,
) -> Result<Vec<String>> {
    for (position, argument) in raw.iter().enumerate() {
        if argument.contains('\0') {
            // Index and remedy only: never echo the argument's value.
            return Err(tool_error(
                file,
                index,
                name,
                format!("args[{position}] must not contain NUL"),
            ));
        }
    }
    Ok(raw)
}

fn validate_layer(
    raw: Option<RawLayer>,
    file: &Path,
    index: usize,
    name: &ToolName,
) -> Result<Option<ToolLayer>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    match (raw.builtin, raw.path) {
        (Some(builtin), None) => {
            let layer = BuiltinLayer::parse(&builtin).ok_or_else(|| {
                tool_error(
                    file,
                    index,
                    name,
                    format!(
                        "layer.builtin {} is not a known layer; supported: {}",
                        quoted_str(&builtin),
                        BuiltinLayer::supported_names()
                    ),
                )
            })?;
            Ok(Some(ToolLayer::Builtin(layer)))
        }
        (None, Some(path)) => {
            if path.is_empty() {
                return Err(tool_error(
                    file,
                    index,
                    name,
                    "layer.path must not be empty",
                ));
            }
            if path.contains('\0') {
                return Err(tool_error(
                    file,
                    index,
                    name,
                    "layer.path must not contain NUL",
                ));
            }
            Ok(Some(ToolLayer::Path(LayerPath(PathBuf::from(path)))))
        }
        (Some(_), Some(_)) => Err(tool_error(
            file,
            index,
            name,
            "layer must set exactly one of `builtin` or `path`, not both",
        )),
        (None, None) => Err(tool_error(
            file,
            index,
            name,
            "layer must set exactly one of `builtin` or `path`",
        )),
    }
}

fn validate_credentials(
    raw: Vec<String>,
    file: &Path,
    index: usize,
    name: &ToolName,
) -> Result<Vec<CredentialProvider>> {
    raw.into_iter()
        .map(|provider_name| {
            CredentialProvider::from_config_name(&provider_name).ok_or_else(|| {
                tool_error(
                    file,
                    index,
                    name,
                    format!(
                        "credentials: {} is not a known credential provider; valid names: {}",
                        quoted_str(&provider_name),
                        supported_provider_names()
                    ),
                )
            })
        })
        .collect()
}

/// Validate one tool's `tools` declaration *within its tier*. Reference
/// resolution is deliberately **not** here: a project tool may legitimately
/// name a user tool, or the appended `shell` fallback, so the dangling check
/// belongs to the launch catalog ([`resolve_provisioning`]).
fn validate_tool_refs(
    raw: Option<Vec<String>>,
    file: &Path,
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
                file,
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
                file,
                index,
                name,
                format!("tools[{position}]: must not be empty"),
            ));
        }
        if entry.contains('\0') {
            return Err(tool_error(
                file,
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

/// The one byte a guest path uses to separate components. Declared inside the
/// `verus!` block because Verus cannot read a `const` declared outside it (see
/// `defaults.rs`).
pub const GUEST_PATH_SEPARATOR: u8 = b'/';

/// `p` is a whole **component-wise** prefix of `q`: `q` begins with `p` followed
/// by the separator, so `a/b` is one of `a/b/c` but `a/b` is *not* one of
/// `a/bc`. Byte-level so the decision is translatable; the `Path` → bytes
/// measurement is the trusted adapter ([`guest_paths_overlap`]).
pub open spec fn is_separator_prefix(p: Seq<u8>, q: Seq<u8>) -> bool {
    p.len() < q.len()
        && q.subrange(0, p.len() as int) =~= p
        && q[p.len() as int] == GUEST_PATH_SEPARATOR
}

/// Two `/`-joined relative guest paths overlap iff they are equal or one is a
/// component-wise ancestor of the other. This is the single predicate behind
/// four call sites (within-tool, across-tool, against the compiled-in link
/// list, and against the launch's guest mount points) — see ADR-0018.
pub fn byte_paths_overlap(a: &[u8], b: &[u8]) -> (result: bool)
    ensures result == (a@ =~= b@
        || is_separator_prefix(a@, b@)
        || is_separator_prefix(b@, a@)),
{
    let alen = a.len();
    let blen = b.len();
    let min = if alen < blen { alen } else { blen };
    let mut i: usize = 0;
    while i < min
        invariant
            i <= min,
            min <= alen,
            min <= blen,
            alen == a@.len(),
            blen == b@.len(),
            min == if alen < blen { alen } else { blen },
            forall|j: int| 0 <= j < i ==> a@[j] == b@[j],
        decreases min - i,
    {
        if a[i] != b[i] {
            assert(a@ != b@);
            assert(!is_separator_prefix(a@, b@));
            assert(!is_separator_prefix(b@, a@));
            return false;
        }
        i += 1;
    }
    if alen == blen {
        assert(a@ =~= b@);
        true
    } else if alen < blen {
        b[alen] == GUEST_PATH_SEPARATOR
    } else {
        a[blen] == GUEST_PATH_SEPARATOR
    }
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
    file: &Path,
    index: usize,
    name: &ToolName,
) -> Result<Vec<PersistPath>> {
    let mut persist: Vec<PersistPath> = Vec::with_capacity(raw.len());
    for (position, declaration) in raw.into_iter().enumerate() {
        let normalized = normalize_persist(&declaration).map_err(|reason| {
            tool_error(file, index, name, format!("persist[{position}]: {reason}"))
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
                    file,
                    index,
                    name,
                    format!(
                        "persist[{position}]: duplicate declaration; this tool already claims the normalized path"
                    ),
                ));
            }
            return Err(tool_error(
                file,
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
                    file,
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
    file: &Path,
    index: usize,
    name: &ToolName,
) -> Result<BTreeMap<String, String>> {
    for (key, value) in &raw {
        if let Err(reason) = check_env_key(key) {
            return Err(tool_error(
                file,
                index,
                name,
                format!("env key {}: {reason}", quoted_str(key)),
            ));
        }
        // Key only, never the value: a user may have mistaken this for a
        // place to put a credential (same rule as `args`).
        if value.contains('\0') {
            return Err(tool_error(
                file,
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
    // The guest identity triple, and only it. `user::guest_identity_env` is the
    // single producer, and it runs *only in non-root mode* — so unlike
    // PATH/IS_SANDBOX/LANG, emission position cannot protect these: under
    // `--root` a declaration here would reach execve unopposed and would also
    // suppress agentd's passwd-derived /root fallback. Validation cannot be
    // mode-aware (this module knows nothing about launch), so the rejection is
    // unconditional; in non-root mode such a declaration was inert anyway. D3c.
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

/// A validation error that names the file and declaration but never a value.
fn declaration_error(
    file: &Path,
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
        quoted_path(file)
    )
}

fn tool_error(
    file: &Path,
    index: usize,
    name: &ToolName,
    detail: impl fmt::Display,
) -> anyhow::Error {
    declaration_error(file, index, Some(name.as_str()), detail)
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
         Required: a string `name` and `command`; `args`, `credentials`, `tools`, and `persist` are \
         arrays of strings; `env` is a table of string values; `layer` has exactly one \
         string selector, `builtin` or `path`.",
        quoted_path(file)
    )
}

fn utf8_error(file: &Path) -> anyhow::Error {
    anyhow!(
        "config: {} is not valid UTF-8; config files must be UTF-8-encoded TOML",
        quoted_path(file)
    )
}

/// **R2.** Reused-reader errors interpolate a raw `path.display()` and may
/// carry a whole cause chain. Escape every link and return a fresh error with
/// no original attached, preserving the operation and the reasons.
fn safe_anyhow_error(operation: &str, path: &Path, error: &anyhow::Error) -> anyhow::Error {
    let reasons = error
        .chain()
        .map(|cause| escape_bytes(cause.to_string().as_bytes()))
        .collect::<Vec<_>>()
        .join(": ");
    anyhow!("config: {operation} {}: {reasons}", quoted_path(path))
}

/// The same boundary for direct `std::io::Error`s (HOME/cwd discovery).
fn safe_io_error(operation: &str, path: &Path, error: &std::io::Error) -> anyhow::Error {
    anyhow!(
        "config: {operation} {}: {}",
        quoted_path(path),
        escape_bytes(error.to_string().as_bytes())
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

fn quoted_path(path: &Path) -> String {
    format!("\"{}\"", escape_bytes(path.as_os_str().as_bytes()))
}

/// Wrap a value in double quotes with the same control-byte escaping as
/// [`quoted_path`]. Exposed so `doctor`'s config warnings quote tool names
/// exactly the way config's own diagnostics do.
pub(crate) fn quoted_str(text: &str) -> String {
    format!("\"{}\"", escape_bytes(text.as_bytes()))
}

/// The escape policy for `doctor`'s own rendering, exposed so its output
/// obeys the same control-byte rule as config diagnostics.
pub(crate) fn escape_path(path: &Path) -> String {
    escape_bytes(path.as_os_str().as_bytes())
}

pub(crate) fn escape_str(text: &str) -> String {
    escape_bytes(text.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::collections::HashSet;
    use std::fs;

    // -- fixture helpers ---------------------------------------------------

    fn write_file(path: &Path, contents: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
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
            }
        }

        fn load(&self) -> Result<ConfigReport> {
            load(&self.paths())
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

    fn one_tool(name: &str) -> String {
        format!(
            "[[tools]]\nname = \"{name}\"\ncommand = \"{name}\"\nlayer = {{ builtin = \"codex\" }}\ncredentials = [\"openai\"]\n"
        )
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
    fn absent_tiers_yield_the_five_defaults_in_order() {
        let fixture = Fixture::new();
        let report = fixture.load().unwrap();

        assert!(report.uses_defaults());
        assert!(report.conflicts().is_empty());
        assert_eq!(report.user().status(), &TierStatus::Absent);
        assert!(matches!(
            report.project().status(),
            TierStatus::Found { declared_tools: 0 } | TierStatus::Absent
        ));

        let tools = report.resolved().as_slice();
        assert_eq!(tools.len(), 5);
        let names: Vec<_> = tools.iter().map(Tool::name).collect();
        assert_eq!(names, ["codex", "opencode", "claude", "copilot", "shell"]);

        let expected = [
            ("codex", "codex", 0, vec!["openai"], 0, Some("codex")),
            (
                "opencode",
                "opencode",
                0,
                vec!["openai", "opencode-static"],
                0,
                Some("opencode"),
            ),
            ("claude", "claude", 1, vec!["anthropic"], 0, Some("claude")),
            ("copilot", "copilot", 1, vec!["copilot"], 0, Some("copilot")),
            ("shell", "bash", 2, vec![], 0, None),
        ];
        for (tool, (name, command, arg_count, providers, persist, layer)) in
            tools.iter().zip(expected)
        {
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
            match layer {
                Some(builtin) => assert_eq!(
                    tool.layer(),
                    Some(&ToolLayer::Builtin(BuiltinLayer::parse(builtin).unwrap()))
                ),
                None => assert_eq!(tool.layer(), None),
            }
            assert_eq!(tool.origin(), &ToolOrigin::BuiltIn);
        }
    }

    #[test]
    fn shell_argv_keeps_two_elements_and_agents_carry_no_invented_flag() {
        let fixture = Fixture::new();
        let report = fixture.load().unwrap();
        let tools = report.resolved().as_slice();

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
            assert_eq!(report.resolved().as_slice().len(), 5);
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
        let tools = report.resolved().as_slice();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name(), "solo");
    }

    // -- the legacy `run::Agent` characterization table -------------------

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
        let cases: [Case; 5] = [
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

    /// The projection `tool_layer::chain_root` compares a configured catalog
    /// against: exactly the four builtin layers, in `default-tools.toml` order.
    /// Derived, never hand-copied, so a reordered or re-typed default is caught
    /// here rather than by a wrong-image boot.
    #[test]
    fn shipped_tool_layers_are_the_four_builtins_in_declaration_order() {
        assert_eq!(
            shipped_tool_layers().unwrap(),
            vec![
                ToolLayer::Builtin(BuiltinLayer::Codex),
                ToolLayer::Builtin(BuiltinLayer::Opencode),
                ToolLayer::Builtin(BuiltinLayer::Claude),
                ToolLayer::Builtin(BuiltinLayer::Copilot),
            ]
        );
    }

    /// **T1.** The provisioning set of each shipped verb, transcribed from
    /// ADR-0017's per-verb table. The acceptance criterion written as an
    /// assertion; fails on *any* closure or default bug. `credentials` is the
    /// *requirement* set and is asserted separately, so an implementation that
    /// conflates the two fails here.
    #[test]
    fn default_catalog_provisioning_sets_are_exactly_the_spec_table() {
        use CredentialProvider::*;
        let catalog = Fixture::new()
            .load()
            .unwrap()
            .into_launch_catalog()
            .unwrap();
        let expected: [(&str, &[CredentialProvider], &[CredentialProvider]); 5] = [
            //  verb        credentials (required)     provisioned
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
        assert!(catalog.shell_fallback_added());
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
        assert!(!catalog.shell_fallback_added());
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
            assert!(!catalog.shell_fallback_added());
            let names: Vec<&str> = catalog
                .as_slice()
                .iter()
                .map(|entry| entry.tool().name())
                .collect();
            assert_eq!(names, ["codex", "opencode", "claude", "copilot", "shell"]);
        }
    }

    /// **T4e.** `ResolvedTools` is the pure merge result and is untouched by
    /// the fallback: one declared tool, even after a catalog is built.
    #[test]
    fn the_fallback_never_leaks_into_resolved_tools() {
        let fixture = Fixture::new();
        fixture.user(&one_tool("solo"));
        let report = fixture.load().unwrap();
        assert_eq!(report.resolved().as_slice().len(), 1);
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
            "[[tools]]\nname = \"a\"\ncommand = \"a\"\ncredentials = [\"anthropic\"]\ntools = [\"b\"]\n\
             [[tools]]\nname = \"b\"\ncommand = \"b\"\ncredentials = [\"openai\"]\ntools = [\"a\"]\n\
             [[tools]]\nname = \"c\"\ncommand = \"c\"\ncredentials = [\"copilot\"]\ntools = [\"c\"]\n",
        );
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(provisioned_of(&catalog, "a"), vec![Anthropic, OpenAi]);
        assert_eq!(provisioned_of(&catalog, "b"), vec![Anthropic, OpenAi]);
        assert_eq!(provisioned_of(&catalog, "c"), vec![Copilot]);
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

    /// **T3 / §A1.** The cross-file opt-in is naming the tool explicitly.
    #[test]
    fn naming_another_files_tool_is_the_cross_file_opt_in() {
        use CredentialProvider::*;
        let fixture = Fixture::new();
        fixture
            .user(
                "[[tools]]\nname = \"w\"\ncommand = \"w\"\ncredentials = [\"copilot\"]\ntools = [\"p\"]\n\
                 [[tools]]\nname = \"u\"\ncommand = \"u\"\ncredentials = [\"openai\"]\n",
            )
            .project(
                "[[tools]]\nname = \"p\"\ncommand = \"p\"\ncredentials = [\"anthropic\"]\n",
            );
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert_eq!(provisioned_of(&catalog, "w"), vec![Anthropic, Copilot]);
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
    /// `shell`'s wildcard still closes over all five — the spec table is
    /// unchanged by the file-scoped rule. This pins the *reason* (origin
    /// equality), so a change to `default-tools.toml` or the fallback's origin
    /// is caught here.
    #[test]
    fn the_shipped_default_wildcard_covers_all_five_builtin_tools() {
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
    /// assert the **full rendered string** (the diagnostic that drops the file
    /// or the declaration index is the regression this catches).
    #[test]
    fn tools_validation_rejects_the_malformed_shapes() {
        // `*` mixed with another entry.
        let fixture = Fixture::new();
        fixture.user("[[tools]]\nname = \"t\"\ncommand = \"t\"\ntools = [\"*\", \"claude\"]\n");
        let rendered = format!("{:#}", fixture.load().unwrap_err());
        assert!(rendered.contains("must be the only entry"), "{rendered}");

        // A dangling name in the *project* tier: the full string.
        let fixture = Fixture::new();
        fixture
            .user("[[tools]]\nname = \"t\"\ncommand = \"t\"\ntools = [\"nope\"]\n")
            .project("");
        let error = fixture.load().unwrap().into_launch_catalog().unwrap_err();
        assert_eq!(
            format!("{error:#}"),
            format!(
                "config: {} declaration [0] tool \"t\": tools[0]: \"nope\" names no tool in the resolved catalog; declare that tool or remove the entry",
                quoted_path(&fixture.user)
            )
        );

        // The same in the project tier names the *project* file.
        let fixture = Fixture::new();
        fixture.project("[[tools]]\nname = \"t\"\ncommand = \"t\"\ntools = [\"nope\"]\n");
        let error = fixture.load().unwrap().into_launch_catalog().unwrap_err();
        assert_eq!(
            format!("{error:#}"),
            format!(
                "config: {} declaration [0] tool \"t\": tools[0]: \"nope\" names no tool in the resolved catalog; declare that tool or remove the entry",
                quoted_path(&fixture.project)
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
        assert!(!a.resolved().as_slice()[0].is_interactive_shell());
        assert!(a.resolved().as_slice()[0].same_definition(&b.resolved().as_slice()[0]));
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
        assert!(!report.resolved().as_slice()[0].is_interactive_shell());
    }

    #[test]
    fn omitted_and_explicit_empty_optional_lists_are_equivalent() {
        let omitted = Fixture::new();
        omitted.user("[[tools]]\nname = \"t\"\ncommand = \"t\"\n");
        let explicit = Fixture::new();
        explicit.user(
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\nargs = []\ncredentials = []\npersist = []\n",
        );
        let a = omitted.load().unwrap();
        let b = explicit.load().unwrap();
        let (left, right) = (a.resolved().as_slice(), b.resolved().as_slice());
        assert!(left[0].same_definition(&right[0]));
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
        let tool = &report.resolved().as_slice()[0];
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
        let tool = &report.resolved().as_slice()[0];
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
            // The host-conditional passthrough (`run.rs` publishes these only
            // when the host has them set), a third class that is neither
            // position-protected nor rejected — deliberately unguarded,
            // because a declaration that sets `env` can already set `command`
            // (ADR-0016).
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
    /// and `shell`; `opencode`, `claude` and `copilot` declare no env. This is
    /// the single assertion a future edit to `default-tools.toml` must
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
                "opencode" | "claude" | "copilot" => {
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

    // -- layers ------------------------------------------------------------

    #[test]
    fn layer_requires_exactly_one_selector() {
        for body in [
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\nlayer = {}\n",
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\nlayer = { builtin = \"codex\", path = \"x\" }\n",
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\nlayer = { weird = \"x\" }\n",
        ] {
            let fixture = Fixture::new();
            fixture.user(body);
            let error = fixture.load().unwrap_err();
            let rendered = format!("{error:#}");
            assert!(
                rendered.contains("exactly one") || rendered.contains("invalid TOML"),
                "body={body:?} rendered={rendered}"
            );
        }
    }

    #[test]
    fn unknown_builtin_layer_names_the_supported_set() {
        let fixture = Fixture::new();
        fixture.user("[[tools]]\nname = \"t\"\ncommand = \"t\"\nlayer = { builtin = \"nope\" }\n");
        let error = fixture.load().unwrap_err();
        let rendered = format!("{error:#}");
        assert!(rendered.contains("nope"), "{rendered}");
        assert!(rendered.contains("codex"), "{rendered}");
    }

    #[test]
    fn a_declared_layer_path_is_metadata_even_when_the_directory_does_not_exist() {
        let fixture = Fixture::new();
        fixture.user(
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\nlayer = { path = \"./does/not/exist\" }\n",
        );
        let report = fixture.load().unwrap();
        assert_eq!(
            report.resolved().as_slice()[0].layer(),
            Some(&ToolLayer::Path(LayerPath(PathBuf::from(
                "./does/not/exist"
            ))))
        );
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
        for allowed in ["claude", "shell", "copilot", "custom"] {
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

    #[test]
    fn provider_names_are_validated_against_the_registry() {
        for valid in ["anthropic", "openai", "opencode-static", "copilot"] {
            let fixture = Fixture::new();
            fixture.user(&format!(
                "[[tools]]\nname = \"t\"\ncommand = \"t\"\ncredentials = [\"{valid}\"]\n"
            ));
            assert!(fixture.load().is_ok(), "{valid} should be valid");
        }
        for invalid in ["opencode", "gh", "Anthropic", "nope"] {
            let fixture = Fixture::new();
            fixture.user(&format!(
                "[[tools]]\nname = \"t\"\ncommand = \"t\"\ncredentials = [\"{invalid}\"]\n"
            ));
            let error = fixture.load().unwrap_err();
            let rendered = format!("{error:#}");
            assert!(rendered.contains(invalid), "{rendered}");
            assert!(rendered.contains("opencode-static"), "{rendered}");
        }
    }

    // -- persist normalization --------------------------------------------

    #[test]
    fn persist_accepts_and_normalizes_safe_relative_paths() {
        let fixture = Fixture::new();
        fixture.user("[[tools]]\nname = \"t\"\ncommand = \"t\"\npersist = [\"a\", \"b\"]\n");
        let report = fixture.load().unwrap();
        assert_eq!(report.resolved().as_slice()[0].persist_count(), 2);

        let fixture = Fixture::new();
        fixture.user(
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\npersist = [\"./.cache//mytool/\", \"a..b\"]\n",
        );
        let report = fixture.load().unwrap();
        let tool = &report.resolved().as_slice()[0];
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
        let names: Vec<_> = report
            .resolved()
            .as_slice()
            .iter()
            .map(Tool::name)
            .collect();
        assert_eq!(names, ["z", "a", "b", "c"]);
    }

    #[test]
    fn identical_cross_tier_definitions_dedupe_silently() {
        let fixture = Fixture::new();
        fixture.user(&one_tool("dup")).project(&one_tool("dup"));
        let report = fixture.load().unwrap();
        assert!(report.conflicts().is_empty());
        let tools = report.resolved().as_slice();
        assert_eq!(tools.len(), 1);
        // The winner keeps user provenance.
        assert_eq!(tools[0].origin(), &ToolOrigin::User(fixture.user.clone()));
    }

    #[test]
    fn each_differing_field_is_reported_individually_in_fixed_order() {
        let base = "[[tools]]\nname = \"t\"\ncommand = \"cmd\"\nargs = [\"a\"]\nlayer = { builtin = \"codex\" }\ncredentials = [\"openai\"]\ntools = [\"base\"]\npersist = [\"p\"]\ninteractive_shell = false\nenv = { A = \"1\" }\n";
        let cases = [
            ("command = \"other\"", ToolField::Command),
            ("args = [\"b\"]", ToolField::Args),
            ("layer = { builtin = \"claude\" }", ToolField::Layer),
            ("credentials = [\"anthropic\"]", ToolField::Credentials),
            ("tools = [\"other\"]", ToolField::Tools),
            ("persist = [\"q\"]", ToolField::Persist),
            ("interactive_shell = true", ToolField::InteractiveShell),
            ("env = { A = \"2\" }", ToolField::Env),
        ];
        for (mutated, expected) in cases {
            let project_body = base.replace(
                match expected {
                    ToolField::Command => "command = \"cmd\"",
                    ToolField::Args => "args = [\"a\"]",
                    ToolField::Layer => "layer = { builtin = \"codex\" }",
                    ToolField::Credentials => "credentials = [\"openai\"]",
                    ToolField::Tools => "tools = [\"base\"]",
                    ToolField::Persist => "persist = [\"p\"]",
                    ToolField::InteractiveShell => "interactive_shell = false",
                    ToolField::Env => "env = { A = \"1\" }",
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
            assert_eq!(report.resolved().as_slice().len(), 1);
            assert_eq!(
                report.resolved().as_slice()[0].origin(),
                &ToolOrigin::User(fixture.user.clone())
            );
        }

        // With several fields differing at once, `env` is reported *last*, after
        // `interactive_shell` (D7). This is the multi-field half of V3; the
        // per-field cases above are the other half.
        let project_body = base
            .replace("interactive_shell = false", "interactive_shell = true")
            .replace("env = { A = \"1\" }", "env = { A = \"2\" }");
        let fixture = Fixture::new();
        fixture.user(base).project(&project_body);
        let report = fixture.load().unwrap();
        assert_eq!(report.conflicts().len(), 1);
        assert_eq!(
            report.conflicts()[0].fields(),
            &[ToolField::InteractiveShell, ToolField::Env],
            "env must be reported last"
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
        // User omits layer/credentials/persist; the project supplying them is
        // a conflict, not a merge — the user's empty values are authoritative.
        let fixture = Fixture::new();
        fixture
            .user("[[tools]]\nname = \"t\"\ncommand = \"t\"\n")
            .project("[[tools]]\nname = \"t\"\ncommand = \"t\"\nlayer = { builtin = \"codex\" }\ncredentials = [\"anthropic\"]\n");
        let report = fixture.load().unwrap();
        assert_eq!(report.conflicts().len(), 1);
        assert_eq!(
            report.conflicts()[0].fields(),
            &[ToolField::Layer, ToolField::Credentials]
        );
        assert_eq!(report.resolved().as_slice()[0].layer(), None);
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

    #[test]
    fn identical_relative_layer_paths_dedupe_without_touching_disk() {
        let fixture = Fixture::new();
        fixture
            .user("[[tools]]\nname = \"t\"\ncommand = \"t\"\nlayer = { path = \"layers/x\" }\n")
            .project("[[tools]]\nname = \"t\"\ncommand = \"t\"\nlayer = { path = \"layers/x\" }\n");
        let report = fixture.load().unwrap();
        assert!(report.conflicts().is_empty());
        assert!(report.resolved().as_slice()[0].layer().is_some());

        let fixture = Fixture::new();
        fixture
            .user("[[tools]]\nname = \"t\"\ncommand = \"t\"\nlayer = { path = \"layers/x\" }\n")
            .project("[[tools]]\nname = \"t\"\ncommand = \"t\"\nlayer = { path = \"layers/y\" }\n");
        let report = fixture.load().unwrap();
        assert_eq!(report.conflicts()[0].fields(), &[ToolField::Layer]);
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
        assert_eq!(report.resolved().as_slice().len(), 2);
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

    /// **V3.** `provisioned()` is unchanged for every embedded default entry by
    /// the `launch_closure` refactor.
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
        let persist_of = |catalog: &LaunchCatalog, name: &str| -> Vec<String> {
            catalog
                .as_slice()
                .iter()
                .find(|entry| entry.tool().name() == name)
                .unwrap_or_else(|| panic!("{name} missing"))
                .persist()
                .iter()
                .map(|path| path.as_path().to_string_lossy().into_owned())
                .collect()
        };

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

    #[test]
    fn non_utf8_bytes_in_a_path_are_escaped() {
        // macOS filesystems reject invalid-UTF-8 filenames, so exercise the
        // escape policy directly. (On Linux the same bytes can appear in a
        // real path and flow through `safe_io_error`.)
        let path = PathBuf::from(std::ffi::OsStr::from_bytes(b"proj\xff\xfe\x1b"));
        let rendered = escape_path(&path);
        assert_eq!(rendered, "proj\\xff\\xfe\\x1b");
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
            let actual: Vec<String> = report.resolved().as_slice().iter().map(|t| t.name().to_string()).collect();
            proptest::prop_assert_eq!(actual, expected);

            // Every overlap's definition must equal the user's.
            for name in &unique_user {
                if unique_project.contains(name) {
                    let tool = report.resolved().as_slice().iter().find(|t| t.name() == name).unwrap();
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
            let actual: Vec<String> = report.resolved().as_slice().iter().map(|t| t.name().to_string()).collect();
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
}
