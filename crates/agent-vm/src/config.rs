//! Read-only **tool configuration**: discovery, strict parsing, validation,
//! and the ordered user/project merge that `agent-vm doctor` previews.
//!
//! A **tool declaration** (`[[tools]]` in a config file) is *data*: a guest
//! command, its default argv, an optional tooling layer, the credential
//! providers it needs, and extra guest-HOME-relative paths to persist. This
//! module never executes a command, creates guest state, builds a layer, or
//! captures a credential.
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
//! and never resolved, checked for existence, or built. Relative-path
//! anchoring and persisted-path overlap safety belong to their consuming
//! tickets (#83/#84).

use std::{
    collections::{HashMap, HashSet},
    fmt,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

use anyhow::{Result, anyhow};
use serde::Deserialize;

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
        let mut tools = resolved.0;
        let shell_fallback_added = !tools.iter().any(|tool| tool.name() == SHELL_FALLBACK_NAME);
        if shell_fallback_added {
            tools.push(builtin_shell()?);
        }
        Ok(LaunchCatalog {
            tools,
            shell_fallback_added,
        })
    }
}

/// The name the built-in `shell` fallback claims. A config that declares
/// `shell` (even as a typo like `shel`) suppresses the fallback for `shell`
/// only when it declares exactly this name.
const SHELL_FALLBACK_NAME: &str = "shell";

/// The verbs a launch actually offers, in chain order: the resolved merge
/// result, plus the built-in `shell` appended when no declared tool claims
/// that name. A config that omits `shell` — or typos it — must never leave the
/// user without a way into the guest to debug that config.
#[derive(Debug)]
pub(crate) struct LaunchCatalog {
    tools: Vec<Tool>,
    shell_fallback_added: bool,
}

impl LaunchCatalog {
    pub(crate) fn as_slice(&self) -> &[Tool] {
        &self.tools
    }

    /// True when the built-in `shell` was appended because no declared tool
    /// claimed the name; `doctor` labels the row from this.
    pub(crate) fn shell_fallback_added(&self) -> bool {
        self.shell_fallback_added
    }

    /// Consume the catalog, returning the tool named `name` for dispatch (the
    /// remaining tools are dropped). `remove` rather than `swap_remove` keeps
    /// the surviving order stable, though nothing observes it once `self` is
    /// consumed.
    pub(crate) fn into_tool(mut self, name: &str) -> Option<Tool> {
        let index = self.tools.iter().position(|tool| tool.name() == name)?;
        Some(self.tools.remove(index))
    }
}

/// The shipped `shell` definition, re-parsed from `default-tools.toml` so
/// there is exactly one source of it. A missing entry is a programming error
/// (guarded by a test over [`default_tools`]), so it is a hard error rather
/// than a silent skip.
fn builtin_shell() -> Result<Tool> {
    default_tools()?
        .into_iter()
        .find(|tool| tool.name() == SHELL_FALLBACK_NAME)
        .ok_or_else(|| {
            anyhow!(
                "config: the built-in defaults have no `{SHELL_FALLBACK_NAME}` tool; this is a bug"
            )
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
    persist: Vec<PersistPath>,
    interactive_shell: bool,
    origin: ToolOrigin,
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

    pub(crate) fn persist_count(&self) -> usize {
        self.persist.len()
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
            && self.persist == other.persist
            && self.interactive_shell == other.interactive_shell
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
        if self.persist != other.persist {
            fields.push(ToolField::Persist);
        }
        // Appended last so the fixed-order warnings keep their ordering.
        if self.interactive_shell != other.interactive_shell {
            fields.push(ToolField::InteractiveShell);
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
    const ALL: [BuiltinLayer; 4] = [
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

/// A declared layer path, kept exactly as written (nonempty, NUL-free). It is
/// never canonicalized, resolved against a base directory, or checked for
/// existence — that anchoring belongs to #84.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LayerPath(PathBuf);

impl LayerPath {
    pub(crate) fn as_path(&self) -> &Path {
        &self.0
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
}

/// A configurable tool field, used to name the fields a cross-tier shadow
/// differs in. `as_str` is the canonical spelling in warnings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ToolField {
    Command,
    Args,
    Layer,
    Credentials,
    Persist,
    // Appended last: `each_differing_field_is_reported_individually_in_fixed_order`
    // and the multi-field ordering test depend on this sequence.
    InteractiveShell,
}

impl ToolField {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ToolField::Command => "command",
            ToolField::Args => "args",
            ToolField::Layer => "layer",
            ToolField::Credentials => "credentials",
            ToolField::Persist => "persist",
            ToolField::InteractiveShell => "interactive_shell",
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

/// Exact normalized-path ownership across the resolved winners: no two
/// distinct tools may claim the same guest-HOME-relative location. This is
/// not a containment proof — ancestor/descendant and provider-link overlap
/// safety is #83's to define.
fn validate_persist_ownership(tools: &[Tool]) -> Result<()> {
    let mut owners: HashMap<&Path, &Tool> = HashMap::new();
    for tool in tools {
        for path in &tool.persist {
            match owners.get(path.as_path()) {
                Some(existing) => {
                    return Err(anyhow!(
                        "config: guest persist path {} is claimed by tool {} ({}) and tool {} ({}); remove or rename one claim",
                        quoted_path(path.as_path()),
                        quoted_str(existing.name.as_str()),
                        describe_origin(&existing.origin),
                        quoted_str(tool.name.as_str()),
                        describe_origin(&tool.origin),
                    ));
                }
                None => {
                    owners.insert(path.as_path(), tool);
                }
            }
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
    #[serde(default)]
    persist: Vec<String>,
    #[serde(default)]
    interactive_shell: bool,
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
        let persist = validate_persist(tool.persist, file, index, &name)?;

        tools.push(Tool {
            name,
            command,
            argv,
            layer,
            credentials,
            persist,
            interactive_shell: tool.interactive_shell,
            origin: kind.origin(file),
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

fn validate_persist(
    raw: Vec<String>,
    file: &Path,
    index: usize,
    name: &ToolName,
) -> Result<Vec<PersistPath>> {
    let mut seen: HashSet<PathBuf> = HashSet::new();
    let mut persist = Vec::with_capacity(raw.len());
    for (position, declaration) in raw.into_iter().enumerate() {
        let normalized = normalize_persist(&declaration).map_err(|reason| {
            tool_error(file, index, name, format!("persist[{position}]: {reason}"))
        })?;
        if !seen.insert(normalized.clone()) {
            return Err(tool_error(
                file,
                index,
                name,
                format!(
                    "persist[{position}]: duplicate declaration; this tool already claims the normalized path"
                ),
            ));
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
         Required: a string `name` and `command`; `args`, `credentials`, and `persist` are \
         arrays of strings; `layer` has exactly one string selector, `builtin` or `path`.",
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
            (
                "shell",
                "bash",
                2,
                vec!["openai", "opencode-static"],
                0,
                None,
            ),
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
    /// silently wrong default launch. The provider column also re-states
    /// #81's asymmetry (`copilot ⇔ Copilot`, `opencode|shell ⇔
    /// OpencodeStatic`, `claude ⇔ Anthropic`, `codex|opencode|shell ⇔
    /// OpenAi`).
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
            (
                "shell",
                "bash",
                &["-O", "histappend"],
                &[OpenAi, OpencodeStatic],
                true,
            ),
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

    /// Every default selects a provider its legacy variant gated on, and no
    /// extra one. Re-stated as an exact set so a silently added or dropped
    /// provider trips here rather than only in the launch integration test.
    #[test]
    fn default_tools_provider_sets_are_exactly_the_legacy_asymmetry() {
        use CredentialProvider::*;
        for tool in default_tools().unwrap() {
            let set = tool.credential_providers();
            let name = tool.name();
            assert_eq!(
                set.contains(Copilot),
                name == "copilot",
                "copilot gating changed for {name}"
            );
            assert_eq!(
                set.contains(OpencodeStatic),
                name == "opencode" || name == "shell",
                "opencode-static gating changed for {name}"
            );
            assert_eq!(
                set.contains(Anthropic),
                name == "claude",
                "anthropic gating changed for {name}"
            );
            assert_eq!(
                set.contains(OpenAi),
                name == "codex" || name == "opencode" || name == "shell",
                "openai gating changed for {name}"
            );
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
        let names: Vec<&str> = catalog.as_slice().iter().map(Tool::name).collect();
        assert_eq!(names, ["solo", "shell"]);
        assert!(catalog.shell_fallback_added());
        let shell = catalog
            .as_slice()
            .iter()
            .find(|tool| tool.name() == "shell")
            .unwrap();
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
        assert_eq!(catalog.as_slice()[0].name(), "shell");
        assert_eq!(catalog.as_slice()[0].command(), "zsh");
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
            let names: Vec<&str> = catalog.as_slice().iter().map(Tool::name).collect();
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

    /// `into_tool` moves exactly the named tool out, consuming the catalog.
    #[test]
    fn launch_catalog_into_tool_returns_the_named_tool() {
        let fixture = Fixture::new();
        fixture.user(&one_tool("solo"));
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        let solo = catalog.into_tool("solo").expect("solo is in the catalog");
        assert_eq!(solo.name(), "solo");
        let catalog = fixture.load().unwrap().into_launch_catalog().unwrap();
        assert!(catalog.into_tool("absent").is_none());
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
        let base = "[[tools]]\nname = \"t\"\ncommand = \"cmd\"\nargs = [\"a\"]\nlayer = { builtin = \"codex\" }\ncredentials = [\"openai\"]\npersist = [\"p\"]\ninteractive_shell = false\n";
        let cases = [
            ("command = \"other\"", ToolField::Command),
            ("args = [\"b\"]", ToolField::Args),
            ("layer = { builtin = \"claude\" }", ToolField::Layer),
            ("credentials = [\"anthropic\"]", ToolField::Credentials),
            ("persist = [\"q\"]", ToolField::Persist),
            ("interactive_shell = true", ToolField::InteractiveShell),
        ];
        for (mutated, expected) in cases {
            let project_body = base.replace(
                match expected {
                    ToolField::Command => "command = \"cmd\"",
                    ToolField::Args => "args = [\"a\"]",
                    ToolField::Layer => "layer = { builtin = \"codex\" }",
                    ToolField::Credentials => "credentials = [\"openai\"]",
                    ToolField::Persist => "persist = [\"p\"]",
                    ToolField::InteractiveShell => "interactive_shell = false",
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
