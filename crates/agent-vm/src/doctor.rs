//! `agent-vm doctor` — diagnostic / maintenance operations for agent-vm's
//! private microsandbox state, and a read-only preview of the resolved tool
//! configuration (see [`crate::config`]).
//!
//! ## Ordinary run
//!
//! With no flag, doctor prints the active `MSB_HOME`/schema, the host
//! credential sources, the resolved tool configuration, and the selected boot
//! image. The **verb list** this section renders is authoritative — it is the
//! same [`crate::cli`] catalog `--help` shows. It shows argument *counts*
//! rather than values (a user may have mistakenly put a secret in `args`). A
//! broken config still exits nonzero, but its failure is reported *inside* the
//! config section, so it never stops the report early — and never blocks
//! recovery (below).
//!
//! ## `--reset-msb-db`
//!
//! sea-orm migrations in microsandbox are one-way: once a newer `msb` opens
//! `MSB_HOME/db/msb.db` it forward-migrates the schema, and an older bundled
//! `msb` (the one agent-vm ships) can never open that db again — every
//! subsequent `agent-vm` command that talks to the db dies. The only fix
//! today would be a manual `mv` of the `db` dir, which is undiscoverable.
//!
//! This command moves `MSB_HOME/db` aside to a timestamped sibling rather
//! than deleting it: reversible by construction (undo is the reverse
//! `mv`, which we print), and it never destroys state outright. The next
//! `agent-vm shell`/`run` then finds no `db/`, and msb (which owns that
//! directory entirely — no agent-vm code creates, opens, or writes it)
//! recreates it fresh at the bundled schema and re-pulls images on first
//! boot.
//!
//! Every path the reset report names is absolute because
//! [`crate::host_paths::state_root`] can only hand out an absolute root (#437):
//! the undo line is pasted later, in whatever directory the operator is in.
//!
//! Historically this ahead-of-bundle condition surfaced as an opaque raw
//! sea-orm error the first time any command opened the db. `src/msb_preflight.rs`
//! (#30) now detects it up front on the boot path and the `agent-vm msb`
//! passthrough, and its error message points here — closing the loop
//! between "detect" (#30) and "recover" (this command, #28).
//!
//! ## Escaping
//!
//! The report is read line by line, so no line may be forged. How that is achieved
//! is not uniform; the split is by provenance and by who else prints the value.
//!
//! *Values a config file chose* — tool names, commands, image references — go
//! through [`crate::config::escape_str`] / [`crate::config::quoted_str`], which
//! escape every non-ASCII byte so two values that differ only outside ASCII cannot
//! print alike.
//!
//! *Paths this run measured* — the unpacked runtime, `MSB_HOME` and its db, the
//! resolved project and state directories, the host credential files, the
//! `credentials.yaml` the launch would read, and whatever `--reset-msb-db` moved —
//! go through [`crate::one_line`], which escapes only control characters.
//!
//! The one value this report prints for **execution** rather than reading is
//! `--reset-msb-db`'s undo `mv`: its two operands are argv, so they take
//! [`crate::shell::PastedWord`] on the raw path bytes, and the line names its
//! shell when not every shell reads it ([`crate::shell`] holds the rule and
//! [`crate::shell::bash_zsh_note`] the wording). `from:`/`to:` above the command
//! stay [`crate::one_line`] diagnostics: a rendering that is read, not run.
//!
//! [`crate::config::escape_str`] and [`crate::config::quoted_path`] are not used
//! for any measured path in this report, and the modules whose error text this
//! report prints — `session`, `protected_config_dir`, `guest_home`, `network`,
//! `egress_policy` — now take the one-line policy too (#422). Two things remain
//! outside it. Byte-escaped paths survive in `mount`'s *declaration* sentences,
//! which attribute a config entry and must keep two entries that differ only
//! outside ASCII distinguishable ([`crate::config::quoted_path`] lists them). And
//! error text from modules that have not converted at all (`host_paths`,
//! `credential_yaml`, …) still interpolates `Path::display()`, so it escapes
//! nothing — that is #419, and it is why the guarantee below is about the escaping
//! this report does rather than about every line it prints. This report used to be
//! the exception, on the lines whose
//! values also come from `config` and `boot_image` — the config file locations
//! (`describe_tier`), the conflict lines (`render_conflicts`), each tool row's
//! `source=user:…`/`source=project:…`, the boot-image paths
//! (`describe_configured_image`, `describe_default_observation`), and
//! [`crate::boot_image::ImageSource::describe`] on the `selected` line. Those are
//! measured paths like any other, so they moved to [`crate::one_line`] too, the
//! renderers those modules own ([`crate::boot_image::ImageSource::describe`],
//! [`crate::boot_image::default_selection`]) moved with them, and so did the config
//! file a `config:` error quotes ([`crate::one_line::quoted_path`]), as do the
//! reader causes those errors repeat. A non-ASCII `$HOME` reads the same on every
//! line, including on the `error:` line a broken config produces — once for the
//! file the sentence is about, and again inside the cause that names it.
//!
//! Two channels print validated names raw, because a name cannot carry a line
//! break (`validate_name` rejects whitespace and control characters): the tool
//! names joined into a host credential row's `replaced by credentials.yaml for …`
//! suffix (`host_row_note`), and the authorization rows' `service`/`env_name`.
//! They do give up the non-ASCII consistency above — a non-ASCII tool name prints
//! as itself in that suffix and byte-escaped in its own tool row.
//!
//! Error text this report prints raw (`error: {error:#}`, `error: {message}`,
//! twice under `selected`) is built by other modules. The seven whose text this
//! report most often prints — `session`, `protected_config_dir`, `guest_home`,
//! `network`, `egress_policy`, `host_paths` and `credential_yaml` — render their
//! paths the same way, so one `$HOME` reads the same on every line (#422, #419);
//! the modules `one_line`'s ratchet still records as unconverted can print a path
//! legibly here and raw there. What holds whichever module built the text: it
//! escapes its own control bytes or it is one of the unconverted modules, and
//! `mount` keeps a *config-chosen* path byte-escaped on purpose, because two mount
//! entries that differ only outside ASCII must not print alike.
//!
//! ## Values this report withholds
//!
//! The state and cache rows — `MSB_HOME` and its db, the project state directory,
//! the unpacked embedded runtime — are derived from host variables agent-vm reads
//! as configuration ([`crate::host_paths::LAUNCHER_CONFIG_ENV_NAMES`]). Such a
//! variable can hold a secret, so a row whose path was supplied by one is
//! withheld while `credentials.yaml` is unusable — the only state in which a claim
//! can exist, because the parser refuses those names: the row keeps its label and
//! prints *that variable's name* instead of the value (#353).
//! [`crate::host_paths::RootSource`] is how the report learns which variable
//! actually supplied each root, so a `$HOME`-derived row is printed exactly as
//! before; withholding it would hide information and protect nothing. [`PathRows`]
//! is that decision, and it is taken before the first section is written — an
//! error rendered later does not undo a value already on the terminal.
//!
//! `--reset-msb-db` is the exception: that run names the db directory it moved and
//! prints a paste-ready `mv`, because withholding the path would make the recovery
//! command useless. It reads no configuration and no credentials by design, so a
//! claim cannot have been established in that run.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use clap::Args as ClapArgs;

use crate::boot_image;
use crate::config::{
    CatalogEntry, ConfigConflict, ConfigReport, ConfiguredImage, ConfiguredImages, LaunchCatalog,
    SourcesReport, TierReport, TierStatus, ToolOrigin,
};
use crate::credential_provider::{CredentialProvider, ProviderSet};
use crate::credential_resolver;
use crate::credential_yaml::{AuthorizationSet, GuestEnvName, SourceKind, SourceSelection};
use crate::host_credential::{AnthropicHostRead, ReadBudget, Unusable, read_anthropic};
use crate::host_paths::RootSource;
use crate::pi_credential_inspection::{PiCredentialReport, inspect_project};
use crate::project::ProjectDir;
use crate::project_config::LegacyProjectConfig;
use crate::secret_store::{Availability, ServiceName};

#[derive(ClapArgs)]
pub struct Args {
    /// Move MSB_HOME/db aside (non-destructive) so the next agent-vm
    /// shell/run recreates it at the bundled schema. Use this to recover
    /// from a db forward-migrated by a newer microsandbox that the
    /// bundled msb can no longer open.
    #[arg(long)]
    reset_msb_db: bool,
}

/// Result of attempting to reset the private msb db. Kept as data so the
/// filesystem logic ([`reset_msb_db_in`]) and the user-facing text
/// ([`render`]) are independently testable.
#[derive(Debug, PartialEq, Eq)]
enum ResetOutcome {
    Moved { from: PathBuf, to: PathBuf },
    NothingToMove { checked: PathBuf },
}

pub fn run(args: Args, project: Result<ProjectDir>) -> Result<()> {
    run_to(
        args,
        project,
        &mut std::io::stdout(),
        gather_credential_store,
    )
}

fn write_line(out: &mut impl std::io::Write, line: &str) -> Result<()> {
    let mut rendered = String::with_capacity(line.len() + 1);
    rendered.push_str(line);
    rendered.push('\n');
    out.write_all(rendered.as_bytes())
        .context("writing doctor output")
}

fn gather_credential_store() -> Result<Availability> {
    crate::secret_store::doctor_store()?.availability()
}

fn describe_credential_store(report: &Result<Availability>) -> (String, Option<anyhow::Error>) {
    let mut section = String::from("==> credential store\ncredential store: ");
    let failed = match report {
        Ok(Availability::NotProbed) => {
            section.push_str("not probed (0 tracked names)");
            false
        }
        Ok(Availability::Reachable) => {
            // A bare `reachable` read as "secrets work" on a host where every
            // write failed with -60008 errSecWritePermErr, so the row names the
            // check that ran (#381).
            section.push_str("reachable (read-only check)");
            false
        }
        Ok(Availability::Unavailable(failure)) => {
            section.push_str(&format!("unavailable ({})", failure.message()));
            true
        }
        Err(error) => {
            section.push_str("not probed (inventory unavailable)\nerror: ");
            section.push_str(&crate::config::quoted_str(&format!("{error:#}")));
            true
        }
    };
    (
        section,
        failed.then(|| anyhow!("credential store check failed; see credential store section")),
    )
}

fn run_to(
    args: Args,
    project: Result<ProjectDir>,
    out: &mut impl std::io::Write,
    gather_store: impl FnOnce() -> Result<Availability>,
) -> Result<()> {
    // The capture is the one `main` took at process entry (ADR-0073 D2). Doctor
    // is a report: an unreadable cwd is rendered with its cause, never a failed
    // run, so the capture is held as data rather than `?`-propagated.
    let msb_home = crate::msb_install::msb_home_dir()?;

    if !args.reset_msb_db {
        // Discover and load the read-only tool configuration, but hold the
        // result as data instead of `?`-propagating it: a repo-supplied config
        // must not blank out the state/credential sections `doctor` exists to
        // show. A load failure is rendered as the `==> tool configuration`
        // section's own body, and the trailing `return Err(...)` still exits
        // nonzero. The reset branch deliberately never reads config: a broken
        // TOML must not block recovering a forward-migrated db.
        let config = project
            .as_ref()
            .map_err(|error| anyhow!("{error:#}"))
            .and_then(crate::config::ConfigPaths::discover)
            .and_then(|paths| crate::config::load(&paths));
        // A load failure *and* a catalog-build failure (the embedded defaults
        // failing to resolve `shell`) both fail the run; either is rendered in
        // the section. `describe_config` returns the latter so `doctor` cannot
        // print an error and still exit 0.
        let load_failure = config.as_ref().err().map(|error| anyhow!("{error:#}"));

        // Build the resolved catalog once, before printing anything: the
        // credential report and the launch view are both launch-aware (#178),
        // so they read the same catalog the tool-configuration section
        // renders, and a launch-verb list cannot diverge from `--help`.
        let (config_section, catalog_failure, catalog, images, listed) = match config {
            Ok(report) => {
                // Capture the readable image tiers before `describe_config`
                // consumes the report (a catalog-build failure must not erase
                // a readable image choice).
                let images = report.images().clone();
                // Only **explicitly listed** sources may suppress the legacy
                // notice (ADR-0074 D9); a failed load has no sources at all.
                let listed: Vec<PathBuf> = report
                    .sources()
                    .listed_files()
                    .into_iter()
                    .map(Path::to_path_buf)
                    .collect();
                let (section, failure, catalog) = describe_config(report);
                (section, failure, catalog, Some(images), Some(listed))
            }
            Err(error) => (
                format!("==> tool configuration\nerror: {error:#}"),
                load_failure,
                None,
                None,
                None,
            ),
        };
        // ADR-0073: an in-repo `.agent-vm/config.toml` is never read, so its
        // presence is reported rather than silently ignored — unless the project
        // config sources it, in which case it *is* read (ADR-0074). Appended after
        // the section is built so it reads the same whether the configuration
        // loaded or failed.
        let listed: Vec<&Path> = listed.iter().flatten().map(PathBuf::as_path).collect();
        let legacy = project
            .as_ref()
            .ok()
            .map(|project| crate::project_config::legacy(project, &listed));
        let config_section = with_legacy_notice(config_section, legacy.as_ref());
        // Which variable supplied each root, so a withheld row names that one
        // rather than its sibling root's (#353).
        let roots = ActiveRoots::from_env()?;
        // The authorization file decides two facts, and both must be settled
        // before any path is printed: the launch view reports it, and the path
        // rows withhold whatever a launcher variable it may claim could supply
        // (#353). One read feeds both, so the report cannot print a path the file
        // it also reports as unusable may hold the value of.
        let authorizations = credential_resolver::load_authorizations();
        let path_rows = PathRows::from_authorizations(&authorizations, roots);
        let launch = gather_launch_view(&authorizations, catalog.as_ref());
        // `doctor` has no `--image`; it reads the env through the same
        // empty-is-unset rule the launch uses, so the two cannot disagree, while
        // still telling an unset variable apart from one that is present but not
        // valid Unicode (issue #259, Spec S1).
        let env_slot = boot_image::read_env_override();

        let db_exists = msb_home.join("db").join("msb.db").exists();
        write_line(
            out,
            &describe_home(
                &msb_home,
                db_exists,
                &crate::msb_schema::bundled_schema_version(),
                path_rows,
            ),
        )?;
        write_line(out, "")?;
        if let Some(payload) = crate::embedded_runtime::EMBEDDED.as_ref() {
            let dir = crate::msb_install::embedded_runtime_root()
                .ok()
                .map(|root| crate::embedded_runtime::unpacked_dir(&root, payload));
            write_line(
                out,
                &describe_embedded_runtime(
                    dir.as_deref(),
                    dir.as_ref().is_some_and(|p| p.exists()),
                    path_rows,
                ),
            )?;
            write_line(out, "")?;
        }
        write_line(
            out,
            &describe_credentials(&gather_credentials(&project), &launch, path_rows),
        )?;
        write_line(out, "")?;
        // Submit preceding sections before a native read can emit its slow notice.
        out.flush().context("writing doctor output")?;
        let (store_section, store_failure) = describe_credential_store(&gather_store());
        write_line(out, &store_section)?;
        write_line(out, "")?;
        // ADR-0065: this project's recorded allowances, beside the credential
        // store. Its failure joins the trailing ones, so every later section
        // still prints (a user whose store is broken still needs the rest).
        let (allowance_section, allowance_failure) =
            crate::allowances::doctor_section(project.as_ref().ok());
        write_line(out, &allowance_section)?;
        write_line(out, "")?;
        write_line(out, &config_section)?;
        if !launch.is_empty() {
            write_line(out, "")?;
            write_line(out, &describe_launch_view(&launch))?;
        }
        let (boot_image_section, boot_image_failure, selection) = describe_boot_image(
            images.as_ref(),
            catalog.is_some(),
            &env_slot,
            project.as_ref().ok(),
        );
        write_line(out, "")?;
        write_line(out, &boot_image_section)?;
        // ADR-0060's section: the current picture from the cache, without
        // acquiring. Omitted when there is no selection, because the boot-image
        // section above already reports that error. Nothing here changes the exit
        // status or writes anything.
        if let Some(boot) = selection {
            let cached = match crate::msb_install::cache_dir_for(&msb_home) {
                Ok(cache_dir) => crate::image_pin::cached_request_labels(
                    &boot,
                    project.as_ref().ok(),
                    &cache_dir,
                ),
                Err(_) => crate::image_requests::CachedLabels::LocationUnknown,
            };
            write_line(out, "")?;
            write_line(out, &crate::image_requests::doctor_section(&cached))?;
        }
        write_line(out, "")?;
        write_line(out, "==> agent-vm doctor: available operations")?;
        write_line(
            out,
            "      --reset-msb-db   move MSB_HOME/db aside (reversible) so the next",
        )?;
        write_line(
            out,
            "                       agent-vm shell/run recreates it at the bundled schema",
        )?;
        out.flush().context("writing doctor output")?;
        if let Some(error) = catalog_failure {
            return Err(error);
        }
        // A leftover of the rendered section is still a failure: `doctor` found
        // damaged state, so it must exit nonzero *after* printing every section
        // it could still read.
        if let Some(error) = boot_image_failure {
            return Err(error);
        }
        if matches!(env_slot, boot_image::EnvOverride::Invalid) {
            return Err(anyhow!(
                "AGENT_VM_IMAGE_TAG is set but is not valid Unicode; doctor cannot report a \
                 selected image"
            ));
        }
        if let Some(error) = store_failure {
            return Err(error);
        }
        if let Some(error) = allowance_failure {
            return Err(error);
        }
        return Ok(());
    }

    // `msb_home` is already absolute: either `state_root()/msb-home` or, on
    // macOS's default root, the short `$HOME/.agent-vm-msb`. `state_root` refuses
    // a relative value and validates `$HOME`, so both branches are absolute
    // (#437). The undo line is pasted later, in a terminal whose cwd is not this
    // one; that invariant is what makes the printed paths work there (#433).
    let ts = timestamp_suffix(SystemTime::now());
    let outcome = reset_msb_db_in(&msb_home, &ts)?;
    write_line(out, &render(&outcome))?;
    out.flush().context("writing doctor output")
}

fn describe_embedded_runtime(dir: Option<&Path>, exists: bool, rows: PathRows) -> String {
    match dir {
        Some(dir) => format!(
            "==> embedded runtime\nunpacked: {} ({})",
            rows.cache.render(dir),
            if exists { "present" } else { "absent" }
        ),
        None => "==> embedded runtime\nunpacked: unresolved (set XDG_CACHE_HOME or HOME)".into(),
    }
}

/// A path derived from a host variable, as this report may print it.
///
/// The variable's value can be a secret — a credential configuration names it as
/// the environment source of a credential — so the derived path is withheld
/// rather than shown, and only the variable is named (#353).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PathRow {
    /// The measured path, escaped by [`crate::one_line`].
    Shown,
    /// The variable supplying the path, which is printed instead of it.
    Withheld(&'static str),
}

impl PathRow {
    /// The row for a path whose root `source` supplied.
    ///
    /// Only a launcher configuration variable can be claimed as an environment
    /// credential source, so only such a source is withheld — and only while the
    /// authorization file cannot say what it claims. A `$HOME`-derived path is
    /// printed whatever the file's state: it is the directory `doctor` names
    /// elsewhere, and withholding it would hide information without protecting
    /// anything.
    fn for_root(source: RootSource, unusable: bool) -> Self {
        let variable = source.variable();
        if unusable && crate::host_paths::is_launcher_config_env(variable) {
            Self::Withheld(variable)
        } else {
            Self::Shown
        }
    }

    fn render(self, path: &Path) -> String {
        match self {
            Self::Shown => crate::one_line::path(path).to_string(),
            Self::Withheld(variable) => format!(
                "not shown - credentials.yaml may name {variable} as an environment credential \
                 source"
            ),
        }
    }
}

/// The variable that supplied each root this run describes, read once.
///
/// Kept beside [`PathRows`] so a row can be withheld for the variable that
/// actually supplied *its* path: naming `XDG_STATE_HOME` for a path
/// `AGENT_VM_STATE_DIR` supplied would send the reader to the wrong variable
/// (#353).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ActiveRoots {
    /// [`crate::host_paths::state_root`]'s: `MSB_HOME`, its db, and the project
    /// state directory.
    state: RootSource,
    /// [`crate::host_paths::cache_root`]'s: the unpacked embedded runtime.
    cache: RootSource,
}

impl ActiveRoots {
    /// Read the variable that supplied each root from the environment, the way
    /// the resolvers themselves read it — `state_root_source` re-reads rather
    /// than threading a path out of `msb_install`, the same shape
    /// `state_root_overridden` already has.
    ///
    /// One constructor rather than two field-by-field calls at the run site, so a
    /// default build can assert *both* answers. Only a bundled build prints the
    /// cache-derived row, and CI builds none, so wiring the cache row to the
    /// state root, to a constant or to a `Home`-only resolver used to pass every
    /// test in the suite — while putting the value back into `unpacked:`, which
    /// is the leak #353 is about.
    fn from_env() -> Result<Self> {
        Ok(Self {
            state: crate::host_paths::state_root_source()?,
            cache: crate::host_paths::cache_root_source(),
        })
    }
}

/// The rows one run prints for a launcher-derived root.
///
/// One value, and each renderer takes the row it describes from it: a call site
/// cannot hand a renderer its sibling's decision, and the embedded-runtime row is
/// chosen by the same tested code whether or not this build bundles a runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PathRows {
    /// The state-derived rows: `MSB_HOME`, its db, and the project state
    /// directory.
    state: PathRow,
    /// The cache-derived row: the unpacked embedded runtime.
    cache: PathRow,
}

impl PathRows {
    /// The rows for one run, from the authorization file's usability and the
    /// variable that actually supplied each root.
    ///
    /// A usable set cannot claim a launcher variable: [`crate::credential_yaml`]
    /// refuses those names as a `source: env` name (#163), so today a claim exists
    /// only as a *refusal*, and a refusal does not say which name it refused. An
    /// unusable file therefore withholds every row a launcher variable supplied,
    /// and no others. Refusing to print is the safe direction, and the refusal's
    /// own error is still rendered in the launch section, so the reader learns
    /// why.
    fn from_authorizations(authorizations: &Result<AuthorizationSet>, roots: ActiveRoots) -> Self {
        let unusable = authorizations.is_err();
        Self {
            state: PathRow::for_root(roots.state, unusable),
            cache: PathRow::for_root(roots.cache, unusable),
        }
    }
}

/// Names the *active* `MSB_HOME` and the schema this build understands, so
/// `agent-vm doctor` (with no flag) answers "which home and schema am I
/// acting on" up front — issue #42's AC-5. `MSB_HOME` is deliberately not
/// schema-namespaced (ADR-0004/0006): this is the detect-and-recover
/// alternative, not a reintroduction of namespacing. Pure over its inputs
/// (mirroring `render`/`reset_msb_db_in`'s testable-without-env-or-fs-reads
/// pattern above) so the wording is unit-tested without needing a real
/// `MSB_HOME` on disk.
///
/// Both printed paths are absolute because `msb_home` is: `msb_home_dir()`
/// builds it from `state_root()`, which refuses or ignores a relative value
/// (#437), so this report needs no resolution of its own (#438). It prints the
/// value verbatim — no canonicalisation — because it names the directory the
/// command acts on, not a normalised spelling of it. `rows` is the one thing that
/// replaces it: the variable `state_root()` read can hold a credential value, so a
/// claimed one is named instead (#353).
fn describe_home(msb_home: &Path, db_exists: bool, bundled_schema: &str, rows: PathRows) -> String {
    let db_path = msb_home.join("db").join("msb.db");
    format!(
        "==> active microsandbox home\n\
         MSB_HOME: {}\n\
         db:       {} ({})\n\
         this build's bundled schema: {}",
        rows.state.render(msb_home),
        rows.state.render(&db_path),
        if db_exists { "exists" } else { "absent" },
        bundled_schema,
    )
}

/// What `doctor` found for one host credential source. `Present` carries
/// an optional expiry (epoch ms) because only the Claude file exposes one
/// in a shape we already parse elsewhere.
#[derive(Debug, PartialEq, Eq)]
enum HostCred {
    Missing,
    Unreadable { why: String },
    Present { expires_at_ms: Option<i64> },
}

/// Anthropic's second host credential location, present only when a keychain
/// item exists (#492). `None` keeps the row byte-identical, and every variant
/// is data rather than a rendered string so the renderer stays pure.
#[derive(Debug, PartialEq, Eq)]
enum KeychainView {
    /// The keychain won, so the row's subject is the keychain and the file is
    /// the subordinate clause.
    Won {
        expires_at_ms: Option<i64>,
    },
    Lost {
        expires_at_ms: Option<i64>,
    },
    Unusable {
        why: String,
    },
}

/// One rendered row plus the per-project follow-through. Kept as data so
/// [`describe_credentials`] is pure and unit-testable without a real
/// `$HOME` or state dir, matching [`describe_home`]'s pattern.
#[derive(Debug, PartialEq, Eq)]
struct CredReport {
    /// `(agent label, host credential path, what we found)`. The path is a
    /// measured `$HOME` child, not prose: [`describe_credentials`] escapes it, so
    /// a directory name carrying a newline cannot split the table.
    hosts: Vec<(&'static str, Option<PathBuf>, HostCred)>,
    /// The project `doctor` was run in, and whether its per-project
    /// host-only token files exist. Never absent: an unresolved capture is
    /// [`ProjectCreds::Unresolved`], so the report can always say why.
    project: ProjectCreds,
    /// `now` in epoch ms, for rendering "expires in ...".
    now_ms: i64,
    /// The Anthropic row's macOS keychain clause. Additive on purpose: every
    /// other field keeps its shape, so no existing test literal churns.
    anthropic_keychain: Option<KeychainView>,
}

#[derive(Debug, PartialEq, Eq)]
enum ProjectCreds {
    /// The project's measured state.
    Measured(MeasuredProject),
    /// Why this project's state could not be measured. Rendered, never dropped:
    /// the cause is either the cwd capture or the state-directory derive, and
    /// both are things the user can act on. An absent row with no cause sends
    /// them looking for a bug that is really a capture failure.
    Unresolved { why: String },
}

#[derive(Debug, PartialEq, Eq)]
struct MeasuredProject {
    /// Both measured: the resolved project cwd and this project's state dir.
    /// Escaped by [`describe_credentials`] at the point of printing.
    dir: PathBuf,
    state_dir: PathBuf,
    /// Providers with a real token captured under `<hash>.secrets/`.
    captured: Vec<&'static str>,
    /// Whether the guest still holds a Claude placeholder cred file.
    guest_claude_placeholder: bool,
    /// The read-only structural report of guest-managed Pi state. It already
    /// holds only sanitized data; rendering it is pure.
    pi_credentials: PiCredentialReport,
}

/// Read every host credential source agent-vm knows about, plus the
/// per-project capture state for the cwd. Never prints or returns token
/// bytes — only presence, parseability, and the Claude expiry, which is
/// exactly what a user debugging "the in-VM agent is signed out" needs.
fn gather_credentials(project: &Result<ProjectDir>) -> CredReport {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);

    // Anthropic is read once for the whole report: its row and its keychain
    // clause must describe the same credential, or a rotation between two reads
    // could make the row name a winner it also calls older.
    let anthropic = read_anthropic(ReadBudget::Launch);

    // The host credential table is the provider table: `doctor_label`
    // (`claude`/`codex`/`opencode`/`copilot`) is retained verbatim so this output
    // stays byte-identical, and `ALL` order is the historical claude, codex,
    // opencode, copilot order.
    let hosts = crate::credential_provider::CredentialProvider::ALL
        .into_iter()
        .map(|provider| {
            let label = provider.doctor_label();
            let path = provider.host_credential_path();
            // The provider that owns a second location is inspected through the
            // two-location read, so its row agrees with the keychain clause
            // beside it and the credential is not read a second time to get
            // there.
            let state = if has_second_location(provider) {
                anthropic_host_cred(&anthropic)
            } else {
                match &path {
                    None => HostCred::Unreadable {
                        why: "no $HOME".into(),
                    },
                    Some(p) => inspect_host_cred(p),
                }
            };
            (label, path, state)
        })
        .collect();

    CredReport {
        hosts,
        project: gather_project_creds(project),
        now_ms,
        anthropic_keychain: keychain_view(&anthropic),
    }
}

/// Which row is inspected through the two-location read (#492, F02).
///
/// The criterion is the provider table's own **acquisition** fact — this provider
/// keeps a host login somewhere other than the file — and nothing else. The rule
/// exists because the opposite happened once: a `ProviderSpec.doctor_parses_expiry`
/// display setting decided this branch, so turning expiry display on for another
/// provider would have handed that row Anthropic's cached read. That field is
/// gone (it had no production reader left), and what replaces it is the rule: a
/// *display* concern must never select a *reader*.
///
/// It is also not a credential-*format* guarantee. `read_anthropic` hardcodes the
/// Anthropic shape and this row's `KeychainView` is Anthropic's; a provider that
/// ever names a keychain service still has to ship its own reader, parser and
/// clause. The table invariant (only Anthropic names one) is pinned in
/// `credential_provider`, so this stays a one-provider seam for now.
fn has_second_location(provider: CredentialProvider) -> bool {
    provider.host_keychain_service().is_some()
}

/// The Anthropic row: the *file* location's own outcome, whichever location won,
/// read by the same parser capture and the hook use. That is what keeps "file
/// exists but agent-vm can't use it" from rendering as a healthy row — an empty
/// `accessToken` reads `UNUSABLE` here rather than `ok`, which is what capture
/// wrote and the hook refused.
fn anthropic_host_cred(read: &AnthropicHostRead) -> HostCred {
    match read.file_outcome() {
        Ok(expires_at_ms) => HostCred::Present {
            expires_at_ms: *expires_at_ms,
        },
        Err(unusable) => HostCred::from(unusable),
    }
}

/// `Some` exactly when a keychain item exists, which is the whole trigger for
/// appending a source clause to the Anthropic row.
fn keychain_view(read: &AnthropicHostRead) -> Option<KeychainView> {
    let (_, other) = read.loser()?;
    Some(match (read.chosen(), other) {
        (Ok(chosen), _) if !chosen.location.is_file() => KeychainView::Won {
            expires_at_ms: chosen.expires_at_ms,
        },
        (_, Ok(expires_at_ms)) => KeychainView::Lost {
            expires_at_ms: *expires_at_ms,
        },
        (_, Err(unusable)) => KeychainView::Unusable {
            why: unusable.to_string(),
        },
    })
}

/// The three providers with one file location and no expiry to parse — the only
/// ones that reach here. Anthropic's row comes from [`anthropic_host_cred`] instead,
/// because its credential is the *fresher of two locations* rather than this
/// file (#492).
fn inspect_host_cred(path: &Path) -> HostCred {
    let bytes = match crate::host_credential::read_file(path) {
        Ok(bytes) => bytes,
        Err(unusable) => return HostCred::from(&unusable),
    };
    // Doctor never claimed to understand these providers' shapes — only whether
    // their file is readable JSON.
    match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(_) => HostCred::Present {
            expires_at_ms: None,
        },
        Err(error) => HostCred::Unreadable {
            why: format!("not valid JSON: {error}"),
        },
    }
}

impl From<&Unusable> for HostCred {
    fn from(unusable: &Unusable) -> Self {
        match unusable {
            Unusable::Absent => HostCred::Missing,
            other => HostCred::Unreadable {
                why: other.to_string(),
            },
        }
    }
}

fn gather_project_creds(project: &Result<ProjectDir>) -> ProjectCreds {
    let project = match project {
        Ok(project) => project,
        Err(error) => {
            return ProjectCreds::Unresolved {
                why: format!("{error:#}"),
            };
        }
    };
    let session = match crate::session::ProjectSession::for_project(project) {
        Ok(session) => session,
        Err(error) => {
            return ProjectCreds::Unresolved {
                why: format!("{error:#}"),
            };
        }
    };
    let captured = [
        (
            "claude",
            crate::secrets::anthropic_token_path(&session.state_dir),
        ),
        (
            "codex",
            crate::secrets::openai_token_path(&session.state_dir),
        ),
        ("gh", crate::secrets::gh_token_path(&session.state_dir)),
        (
            "copilot",
            crate::secrets::copilot_token_path(&session.state_dir),
        ),
    ]
    .into_iter()
    .filter(|(_, path)| path.exists())
    .map(|(label, _)| label)
    .collect();
    ProjectCreds::Measured(MeasuredProject {
        dir: session.project_dir.clone(),
        state_dir: session.state_dir.clone(),
        captured,
        guest_claude_placeholder: session.state_dir.join("claude/.credentials.json").exists(),
        pi_credentials: inspect_project(&session.state_dir),
    })
}

/// One row's detail with no second location to name: byte-for-byte what this
/// table printed before #492, and still everything a host with no keychain item
/// prints.
fn plain_detail(state: &HostCred, now_ms: i64) -> String {
    match state {
        HostCred::Missing => "absent".to_string(),
        // `why` is an error chain from `host_paths`, whose messages interpolate
        // the measured path (`… is not a regular file`, `opening …`). It is
        // escaped here, at the print site, like the path above it.
        HostCred::Unreadable { why } => format!("UNUSABLE - {}", crate::one_line::text(why)),
        HostCred::Present {
            expires_at_ms: None,
        } => "ok".to_string(),
        HostCred::Present {
            expires_at_ms: Some(exp),
        } => format!("ok ({})", describe_expiry(*exp, now_ms)),
    }
}

/// An expiry, or `ok` when the location has none — the form used inside a
/// clause, where the row's own `ok (` has already been printed.
fn expiry_phrase(expires_at_ms: Option<i64>, now_ms: i64) -> String {
    match expires_at_ms {
        Some(exp) => describe_expiry(exp, now_ms),
        None => "ok".to_string(),
    }
}

/// `expires in 4h42m ` / empty, ready to follow an opening `ok (`.
fn leading_expiry(expires_at_ms: Option<i64>, now_ms: i64) -> String {
    match expires_at_ms {
        Some(exp) => format!("{} ", describe_expiry(exp, now_ms)),
        None => String::new(),
    }
}

/// A location that is the row's subordinate clause: its expiry, `ok`, `absent`
/// or `UNUSABLE - …`, never a second `ok (`.
fn location_phrase(state: &HostCred, now_ms: i64) -> String {
    match state {
        HostCred::Present { expires_at_ms } => expiry_phrase(*expires_at_ms, now_ms),
        other => plain_detail(other, now_ms),
    }
}

/// The Anthropic row when a keychain item exists. The row's *subject* is
/// whichever location won, so the row stays `ok (…)` exactly when the
/// credential in use is usable, and the other location is one clause after it.
fn detail_with_keychain(state: &HostCred, view: &KeychainView, now_ms: i64) -> String {
    match view {
        // When the keychain won it is the row's subject, so the row stays
        // `ok (…)` and the file becomes the clause.
        KeychainView::Won { expires_at_ms } => format!(
            "ok ({}via macOS keychain; file {})",
            leading_expiry(*expires_at_ms, now_ms),
            location_phrase(state, now_ms)
        ),
        KeychainView::Lost { expires_at_ms } => file_row_with_keychain(
            state,
            format!("macOS keychain {}", expiry_phrase(*expires_at_ms, now_ms)),
            now_ms,
        ),
        // `why` is the keychain reader's own wording, which never holds child
        // output; escaping it here keeps a hostile item from splitting the row.
        KeychainView::Unusable { why } => file_row_with_keychain(
            state,
            format!("macOS keychain UNUSABLE - {}", crate::one_line::text(why)),
            now_ms,
        ),
    }
}

/// The row when the file is still its subject: `ok (…)` with the keychain as the
/// clause when the file is usable, and the file's own verdict leading otherwise.
fn file_row_with_keychain(state: &HostCred, keychain: String, now_ms: i64) -> String {
    match state {
        HostCred::Present { expires_at_ms } => format!(
            "ok ({}via file; {keychain})",
            leading_expiry(*expires_at_ms, now_ms)
        ),
        other => format!("{}; {keychain}", plain_detail(other, now_ms)),
    }
}

/// Render the credential report. Pure over its input so the wording is
/// unit-tested without touching `$HOME` or the filesystem.
///
/// `launch` supplies the launch-aware disposition of each host file (#178): a
/// provider some configured launch replaces is annotated so a green/absent row
/// is never read as "this launch will read this file". `rows` does the same job
/// for the project's own state directory, which is derived from a launcher
/// configuration variable when one supplied the state root (#353).
fn describe_credentials(report: &CredReport, launch: &LaunchView, rows: PathRows) -> String {
    let mut out = String::from("==> host agent credentials\n");
    let width = report
        .hosts
        .iter()
        .map(|(label, _, _)| label.len())
        .max()
        .unwrap_or(0);
    for (label, path, state) in &report.hosts {
        let detail = match (
            &report.anthropic_keychain,
            label == &CredentialProvider::Anthropic.doctor_label(),
        ) {
            (Some(view), true) => detail_with_keychain(state, view, report.now_ms),
            _ => plain_detail(state, report.now_ms),
        };
        let disposition = launch.host_row_note(label);
        let shown = path.as_deref().map_or_else(
            || crate::one_line::text("<no $HOME>"),
            crate::one_line::path,
        );
        out.push_str(&format!(
            "{label:<width$}  {shown}\n{:width$}  {detail}{disposition}\n",
            ""
        ));
    }

    match &report.project {
        ProjectCreds::Unresolved { why } => out.push_str(&format!(
            "\n==> this project: <cwd could not be resolved: {}>\n",
            crate::config::quoted_str(why)
        )),
        ProjectCreds::Measured(MeasuredProject {
            dir,
            state_dir,
            captured,
            guest_claude_placeholder,
            pi_credentials,
        }) => {
            out.push_str(&format!(
                "\n==> this project\ndir:      {}\nstate:    {}\ncaptured: {}\nguest Claude cred file: {}\n",
                crate::one_line::path(dir),
                rows.state.render(state_dir),
                if captured.is_empty() {
                    "<none> (nothing to substitute on the wire)".to_string()
                } else {
                    captured.join(", ")
                },
                if *guest_claude_placeholder {
                    "placeholder present"
                } else {
                    "absent"
                },
            ));
            out.push('\n');
            out.push_str(&pi_credentials.doctor_section());
        }
    }

    out.push_str(
        "\nFor the host-captured Claude/Codex/GitHub credentials above, the guest never\n\
         receives a real token: it gets a placeholder that the TLS proxy swaps for the\n\
         host token on the way out. So sign in ON THE HOST (`claude login`,\n\
         `codex login`, `gh auth login`): running `/login` inside the VM cannot work and fails with an OAuth 400.\n\
         Pi guest-managed state is different: a credential created inside the guest\n\
         lives in the project's persistent Pi home and is reported above, not\n\
         substituted.",
    );
    out
}

/// What `doctor` knows about the launch context a host-file listing alone
/// cannot express (#178). Pure data so the wording is unit-tested without a
/// keychain or a real `credentials.yaml`.
///
/// Replacement is a *name* fact: if the user authorizes `anthropic` and some
/// configured launch requests `anthropic`, that launch never reads the host
/// file — whichever verb it is. That is why the view can be built for the
/// whole catalog without being told which verb the user has in mind, and why it
/// needs the authorization file but never the credential store.
#[derive(Debug, Default, PartialEq, Eq)]
struct LaunchView {
    /// Built-in `doctor_label` -> the launches that replace it. The host row
    /// for that label is annotated from this.
    replaced: BTreeMap<&'static str, Vec<String>>,
    /// Built-in `doctor_label`s no configured launch requests at all, so the
    /// host file is beside the point.
    unrequested: Vec<&'static str>,
    /// One row per authorized service some configured launch requests.
    yaml: Vec<YamlRow>,
    /// `credentials.yaml` mode warnings, rendered with a `warning:` prefix.
    notes: Vec<String>,
    /// Failures (a malformed or unreadable file), rendered with an `error:`
    /// prefix.
    problems: Vec<String>,
}

impl LaunchView {
    /// Empty means `doctor` has nothing launch-specific to add: no requested
    /// authorization and no problem. The pre-#178 output is then unchanged.
    fn is_empty(&self) -> bool {
        self.yaml.is_empty() && self.notes.is_empty() && self.problems.is_empty()
    }

    /// The suffix appended to one host credential row. Empty for a provider a
    /// launch still reads — the ordinary built-in case.
    fn host_row_note(&self, doctor_label: &str) -> String {
        if let Some(tools) = self.replaced.get(doctor_label) {
            format!(
                " - replaced by credentials.yaml for {} (host file not read)",
                tools.join(", ")
            )
        } else if self.unrequested.contains(&doctor_label) {
            " - not requested by any configured launch".to_string()
        } else {
            String::new()
        }
    }
}

/// One authorized service a configured launch requests. Holds no value and no
/// storage status: `doctor` reads the authorization file, never the credential
/// store, so it cannot and does not claim whether a value is present.
#[derive(Debug, PartialEq, Eq)]
struct YamlRow {
    service: String,
    /// Whether the service name is also a built-in provider, so this launch
    /// uses the authorization *instead of* the host file rather than as a
    /// standalone credential.
    replaces_builtin: bool,
    /// The whole selection, not just its tag: the SecretSpec row prints the
    /// pinned manifest/profile/scope/executable from it, and printing them is
    /// all `doctor` does with them (it spawns and stats nothing).
    source: SourceSelection,
    env_name: GuestEnvName,
}

/// Which launches request an authorization, and which host providers a launch
/// replaces or ignores entirely. Pure: it reads no keychain, so it is the
/// cheap half of [`gather_launch_view`] and is unit-tested directly.
#[derive(Debug, Default, PartialEq, Eq)]
struct LaunchSelection {
    /// Authorized services some launch requests, in name order.
    requested: BTreeSet<ServiceName>,
    /// `doctor_label` -> launches that replace the built-in.
    replaced: BTreeMap<&'static str, Vec<String>>,
    /// `doctor_label`s no configured launch requests.
    unrequested: Vec<&'static str>,
}

/// A replacement and a request are both *name* facts: whichever verb requests
/// `anthropic` replaces it once the user authorizes that name, and a provider
/// no verb requests is never read. So the selection is exact for the whole
/// catalog without being told which verb the user has in mind.
fn launch_selection(catalog: &LaunchCatalog, authorizations: &AuthorizationSet) -> LaunchSelection {
    let mut selection = LaunchSelection::default();
    let mut requested_providers = ProviderSet::default();
    for entry in catalog.as_slice() {
        for name in entry.requested_names() {
            if let Some(provider) = CredentialProvider::from_config_name(name.as_str()) {
                requested_providers = requested_providers.union(ProviderSet::new([provider]));
            }
            // An authorization nobody requests is inert and not reported.
            if authorizations.get(name).is_some() {
                selection.requested.insert(name.clone());
            }
        }
        for provider in
            credential_resolver::replaced_providers(entry.requested_names(), authorizations).iter()
        {
            let tools = selection
                .replaced
                .entry(provider.doctor_label())
                .or_default();
            let tool = entry.tool().name().to_string();
            if !tools.contains(&tool) {
                tools.push(tool);
            }
        }
    }
    selection.unrequested = CredentialProvider::ALL
        .into_iter()
        .filter(|provider| !requested_providers.contains(*provider))
        .map(CredentialProvider::doctor_label)
        .collect();
    selection
}

/// Read the launch context `doctor` reports: which host files a launch
/// replaces, which providers no configured launch requests, and which
/// authorizations a configured launch requests.
///
/// This reads the authorization file and the resolved catalog only. It
/// deliberately does **not** read the credential store: `SecretStore::resolve`
/// takes the exclusive inventory lock (creating it if absent) and reads a
/// value, neither of which belongs in a diagnostic that must stay read-only and
/// must keep working when the keychain is locked or prompting. Whether a value
/// is stored is `agent-vm secret ls`'s answer, and the section says so.
///
/// `catalog` is `None` when the tool configuration failed to load; the
/// authorization file is still read so a malformed one is reported rather than
/// hidden behind the config failure.
///
/// `authorizations` is the run's one read of that file, taken by the caller
/// because the path rows need it too (#353).
fn gather_launch_view(
    authorizations: &Result<AuthorizationSet>,
    catalog: Option<&LaunchCatalog>,
) -> LaunchView {
    let mut view = LaunchView::default();
    let authorizations = match authorizations {
        Ok(set) => set,
        Err(error) => {
            view.problems.push(format!("{error:#}"));
            return view;
        }
    };
    view.notes = authorizations.warnings().to_vec();

    let Some(catalog) = catalog else {
        return view;
    };
    let selection = launch_selection(catalog, authorizations);
    view.replaced = selection.replaced;
    view.unrequested = selection.unrequested;
    view.yaml = selection
        .requested
        .iter()
        .filter_map(|service| {
            let credential = authorizations.get(service)?;
            Some(YamlRow {
                service: service.as_str().to_owned(),
                replaces_builtin: CredentialProvider::from_config_name(service.as_str()).is_some(),
                source: credential.selection().clone(),
                env_name: credential.env_name().clone(),
            })
        })
        .collect();
    view
}

/// Render the launch-aware credential section. Pure over its input.
///
/// Terse on success — one line per requested authorization — and explicit when
/// something is wrong: a malformed authorization file or a file-mode warning is
/// printed rather than folded into a terse status word. It never prints a
/// storage status, because it never reads one.
fn describe_launch_view(view: &LaunchView) -> String {
    let mut out = String::from("==> credentials.yaml (launch credentials)\n");
    // Both carry text from `credential_yaml`, which interpolates the measured
    // `$HOME/.config/agent-vm/credentials.yaml` (its mode warning is
    // `{path} is group- or other-readable…`), so they are escaped here: a report
    // body is assembled in one `String` and has no sink to escape for it. A launch
    // that requests a credential emits the same notes through `run`'s notice
    // channel, where `LaunchNotices::emit` escapes them (#416).
    for note in &view.notes {
        out.push_str(&format!("warning: {}\n", crate::one_line::text(note)));
    }
    for problem in &view.problems {
        out.push_str(&format!("error: {}\n", crate::one_line::text(problem)));
    }
    let width = view
        .yaml
        .iter()
        .map(|row| row.service.len())
        .max()
        .unwrap_or(0);
    for row in &view.yaml {
        let mut what = match &row.source {
            SourceSelection::Keychain => "authorized for this launch".to_owned(),
            SourceSelection::Environment => format!(
                "authorized for this launch from the host environment (`{}`)",
                row.env_name
            ),
            // The labels are upstream-bounded and control-character-free, and
            // the paths are escaped, so a `work/team` profile or a directory
            // name with a newline still renders as one line. `reason` is
            // deliberately absent: it is the one free-form field, and doctor
            // has no use for it.
            SourceSelection::Secretspec(selection) => {
                let scope = selection
                    .scope()
                    .map(|scope| format!(", scope `{scope}`"))
                    .unwrap_or_default();
                format!(
                    "authorized for this launch from SecretSpec (`{}`, profile `{}`{scope}, \
                     manifest {}, executable {})",
                    selection.name(),
                    selection.profile(),
                    crate::one_line::path(selection.manifest()),
                    crate::one_line::path(selection.executable()),
                )
            }
        };
        if row.replaces_builtin {
            what.push_str(" (replaces the host built-in)");
        }
        out.push_str(&format!("{:<width$}  {what}\n", row.service));
    }
    if view
        .yaml
        .iter()
        .any(|row| row.source.kind() == SourceKind::Keychain)
    {
        out.push_str("note: values are not read here; `agent-vm secret ls` reports whether a value is stored.\n");
    }
    if view
        .yaml
        .iter()
        .any(|row| row.source.kind() == SourceKind::Environment)
    {
        out.push_str("note: environment values are read by the launch, not by doctor.\n");
    }
    if view
        .yaml
        .iter()
        .any(|row| row.source.kind() == SourceKind::Secretspec)
    {
        out.push_str(
            "note: SecretSpec values are resolved by the launch (`secretspec serve --read-only`), \
             not by doctor.\n",
        );
    }
    out.truncate(out.trim_end_matches('\n').len());
    out
}

/// Render the tool-configuration section. Consumes its input so it can build
/// the owned [`crate::config::LaunchCatalog`] (the merge result plus the
/// built-in `shell` fallback) that `--help` also renders — the two therefore
/// cannot disagree about the verb list. Returns the section text plus the
/// catalog-build failure, if any, so the caller can fail the exit code rather
/// than print an error and still report success, and the resolved catalog
/// (when it built) so the launch-aware credential view reads the same verbs.
/// Pure over its input so the wording is unit-tested without a real
/// filesystem, mirroring [`describe_home`]/[`describe_credentials`].
///
/// The verb list is authoritative; it shows argument *counts* rather than
/// values (a user may have mistakenly put a secret in `args`) and never
/// resolves a path or builds an image.
fn describe_config(report: ConfigReport) -> (String, Option<anyhow::Error>, Option<LaunchCatalog>) {
    // Everything that needs a borrow is rendered before `report` is consumed
    // by `into_launch_catalog`.
    let tiers = format!(
        "user:    {}\nproject: {}\n",
        describe_tier(report.user(), "user"),
        describe_tier(report.project(), "project"),
    );
    let sources = describe_sources(report.sources());
    let resolved_label = if report.uses_defaults() {
        "resolved: built-in defaults; launch-verb order\n"
    } else {
        "resolved: declared tools; launch-verb order\n"
    };
    let conflicts = render_conflicts(report.conflicts());
    // The persisted egress references are user-authored authority, so `doctor`
    // shows what each one grants. Rendered before the report is consumed by
    // `into_launch_catalog`, like every other borrow here.
    let egress_references = report
        .user_network()
        .map(describe_egress_references)
        .unwrap_or_default();

    let mut out = String::from("==> tool configuration\n");
    out.push_str(&tiers);
    out.push_str(&sources);
    out.push_str(resolved_label);
    let (failure, catalog) = match report.into_launch_catalog() {
        Ok(catalog) => {
            for (index, entry) in catalog.as_slice().iter().enumerate() {
                out.push_str(&format!("  {}. {}\n", index + 1, describe_tool(entry)));
            }
            if catalog.has_shell_fallback() {
                out.push_str(
                    "note: the bare `shell` verb is the built-in fallback, because no project or\n\
                     built-in entry claims that route; a `shell` you declared stays reachable as\n\
                     its `<alias>:shell` spelling.\n",
                );
            }
            out.push_str(&describe_default_tools(&catalog));
            (None, Some(catalog))
        }
        // A dangling `tools` reference lands here, as does an internally broken
        // embedded default. Both are reported in-band so the rest of `doctor`
        // still renders.
        Err(error) => {
            out.push_str(&format!("error: {error:#}\n"));
            (Some(error), None)
        }
    };
    // After the numbered list: these blocks are about the verbs themselves, so
    // they must not split the `resolved:` header from the list it introduces.
    if let Some(catalog) = catalog.as_ref() {
        out.push_str(&render_name_conflicts(catalog.name_conflicts()));
    }
    out.push_str(&conflicts);
    out.push_str(&egress_references);
    // Drop the final newline: the caller adds one via `writeln!`.
    out.truncate(out.trim_end_matches('\n').len());
    (out, failure, catalog)
}

/// What `default_tools` grants, in the printer's words (#749): the same key `tools
/// print` writes and the reader accepts, so advice and grammar cannot drift.
///
/// Empty when nothing consulted a list, so every `doctor` output for a config that
/// wrote no `default_tools` is byte-identical to before this field existed.
fn describe_default_tools(catalog: &LaunchCatalog) -> String {
    let authored = catalog.direct_defaults();
    if authored.is_empty() {
        return String::new();
    }
    let unavailable = authored
        .refusal()
        .and_then(launch_refusal_note)
        .map(|note| format!("; {note}"))
        .unwrap_or_default();
    format!(
        "default_tools: {} -> provisioned for `shell` and a direct command{unavailable}\n",
        authored.names().join(", ")
    )
}

/// The one rendering of a blocked read's verdict, shared by a tool row and the
/// `default_tools:` line (#749 E8/V4), and byte-identical to what a launch
/// prints: `unavailable: config: "<file>": <refusal>`.
fn launch_refusal_note(trust: &crate::config_authority::ReferenceTrust) -> Option<String> {
    trust.require_for_trusted_tool().err().map(|refusal| {
        format!(
            "unavailable: config: {}: {refusal}",
            crate::one_line::quoted_path(trust.file())
        )
    })
}

/// The persisted egress references of one `[network]` table and what each
/// grants (ADR-0059): `set:NAME` only, since #735 removed `tool:NAME`.
///
/// Empty when the table has none, so `doctor` output for every config written
/// before #506 is byte-identical. Each expansion is listed because this is
/// *user-authored* authority, not ADR-0039's bounded repository metadata — but
/// bounded per reference, because one declaration can name 64 requests and a
/// set's closure is already deduplicated by value. A set reference's expansion is
/// its whole nested closure, which is what makes the entry-level attribution
/// enough: what `set:NAME` nests is visible here.
fn describe_egress_references(network: &crate::user_network::UserNetwork) -> String {
    const MAX_SHOWN: usize = 64;
    let mut out = String::new();
    for (reference, expansion) in network.allowances().expansions() {
        let mut grants: Vec<String> = expansion
            .iter()
            .take(MAX_SHOWN)
            .map(ToString::to_string)
            .collect();
        if expansion.len() > MAX_SHOWN {
            grants.push(format!("+{} more", expansion.len() - MAX_SHOWN));
        }
        if out.is_empty() {
            out.push_str(&format!(
                "persisted egress references in \"{}\" [network]:\n",
                crate::one_line::path(network.reference_file())
            ));
        }
        out.push_str(&format!("  {reference} -> {}\n", grants.join(", ")));
    }
    out
}

/// The project config's sources (ADR-0076 R5.1).
///
/// Empty when sourcing was implicit, so a run that declares no `sources` key prints
/// exactly what #733 printed. Each row uses the same renderer as a tier row, and the
/// alias is printed raw because the grammar admits no control byte.
fn describe_sources(sources: &SourcesReport) -> String {
    use crate::config_sources::Sourcing;

    if sources.sourcing() != Sourcing::Listed {
        return String::new();
    }
    if sources.entries().is_empty() {
        return "sources: none\n".to_string();
    }
    let mut out = String::from("sources:\n");
    for entry in sources.entries() {
        let mut attrs = format!("trust={}, allow={}", entry.is_trusted(), entry.is_allowed());
        // D4: the pin is a clause of #748's one block, before `; inert:`. It can
        // only exist for an approved `trust = false` source — a trusted one is
        // never pinned, and an unapproved one is a load error this function is
        // never reached with — so it cannot describe bytes nobody approved.
        if let Some(pin) = entry.pin() {
            attrs.push_str(&format!(", pin=approved {}", pin.hash()));
        }
        if !entry.inert().is_empty() {
            attrs.push_str(&format!("; inert: {}", entry.inert().labels().join(", ")));
        }
        out.push_str(&format!(
            "  {} {} [{attrs}]\n",
            entry.alias(),
            describe_tier(entry.tier(), entry.alias().as_str()),
        ));
    }
    out
}

/// The `warning:` blocks for cross-tier shadows, in project declaration order.
///
/// Since #749 a shadow no longer hides the other definition: the bare name is the
/// project's, and the other one keeps its qualified spelling. The block says that
/// instead of claiming an override.
fn render_conflicts(conflicts: &[ConfigConflict]) -> String {
    let mut out = String::new();
    for conflict in conflicts {
        let fields = conflict
            .fields()
            .iter()
            .map(|field| field.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!(
            "warning: tool {} in {} shadows\n         {}; the bare name launches the project's \
             definition, the other keeps its qualified spelling; differing fields: {}\n",
            crate::config::quoted_str(conflict.tool()),
            crate::one_line::path(conflict.winner_file()),
            crate::one_line::path(conflict.overridden_file()),
            fields,
        ));
    }
    out
}

/// The bare names more than one source declares, each with the qualified
/// spelling that still reaches every candidate (#749).
///
/// A row per conflict, so `doctor` and the CLI refusal name the same thing.
fn render_name_conflicts(conflicts: &[crate::config::NameConflict]) -> String {
    let mut out = String::new();
    for conflict in conflicts {
        out.push_str(&format!("{:#}\n", conflict.refusal()));
    }
    out
}

/// ADR-0073: an in-repo `.agent-vm/config.toml` is never read, so its presence
/// is reported rather than silently ignored.
///
/// Appended last, so it reads the same whether the configuration loaded or the
/// section is an `error:` body. `<path>` goes through [`crate::one_line::path`],
/// like every other measured path, so a directory name holding ESC cannot
/// rewrite the terminal. The note never changes the exit status.
fn with_legacy_notice(mut section: String, legacy: Option<&LegacyProjectConfig>) -> String {
    match legacy {
        Some(LegacyProjectConfig::Present(path)) => section.push_str(&format!(
            "\nnote: {} is not auto-loaded; agent-vm never reads an in-repo .agent-vm/config.toml.\n\
             To use it, review it and source it from this project's config: edit the file\n\
             `agent-vm doctor` names as its `project:` row with your own editor (this version\n\
             has no `config edit` command).",
            crate::one_line::path(path)
        )),
        Some(LegacyProjectConfig::Unexaminable { path, kind }) => section.push_str(&format!(
            "\nnote: could not check for an in-repo .agent-vm/config.toml at {} ({kind:?}); agent-vm never auto-loads it.",
            crate::one_line::path(path)
        )),
        Some(LegacyProjectConfig::Absent | LegacyProjectConfig::Sourced) | None => {}
    }
    section
}

/// Render one tier row. `label` is the tier's own word, because both tiers are
/// unavailable for the same reason and the row must say which one is missing.
fn describe_tier(tier: &TierReport, label: &str) -> String {
    match tier.status() {
        TierStatus::UnavailableHome => format!("<no HOME; {label} tier unavailable>"),
        TierStatus::Absent => format!(
            "{} (absent)",
            tier.path()
                .map_or_else(|| crate::one_line::text("<unknown>"), crate::one_line::path)
        ),
        TierStatus::NotSourced => format!(
            "{} (not sourced by the project config)",
            tier.path()
                .map_or_else(|| crate::one_line::text("<unknown>"), crate::one_line::path)
        ),
        TierStatus::Found { declared_tools } => format!(
            "{} (found, {declared_tools} tool{})",
            tier.path()
                .map_or_else(|| crate::one_line::text("<unknown>"), crate::one_line::path),
            if *declared_tools == 1 { "" } else { "s" },
        ),
    }
}

/// Renders the boot-image section and returns the failure it found, if any, plus
/// the `Ok` selection so the image-request section can observe the same one.
///
/// Observational by construction: [`boot_image::observe`] reads the retained
/// record and resolves the selection from **one** snapshot, so the `default`
/// row and `selected (without --image)` row cannot disagree across a concurrent
/// adoption, and nothing is created, locked or repaired. A damaged default still
/// renders every tier row and a clear error; the caller exits nonzero.
///
/// The `active images:` row reads its own snapshot, not that one: it reports the
/// pin authority's recorded roles, which are independent of the selection's
/// default observations, so neither can make the other stale.
fn describe_boot_image(
    images: Option<&ConfiguredImages>,
    catalog_built: bool,
    env: &boot_image::EnvOverride,
    project: Option<&ProjectDir>,
) -> (String, Option<anyhow::Error>, Option<boot_image::BootImage>) {
    let mut out = String::from("==> boot image\n");
    let (active_row, active_failure) =
        describe_active_images_observation(&crate::image_pin::observe_active_images(project));
    let env_override = match env {
        boot_image::EnvOverride::Present(override_) => {
            out.push_str(&format!(
                "AGENT_VM_IMAGE_TAG: {}\n",
                crate::config::escape_str(override_.reference().as_str())
            ));
            Some(override_.clone())
        }
        boot_image::EnvOverride::Unset => {
            out.push_str("AGENT_VM_IMAGE_TAG: <unset>\n");
            None
        }
        boot_image::EnvOverride::Invalid => {
            // Never print a fictional selection from an override doctor could
            // not read: say the value is present and unreadable, and stop. The
            // caller exits nonzero after this section. This branch is the one
            // place with no `project default:` row to anchor to, so the active
            // row follows the environment line directly — and its own failure is
            // discarded: the environment refusal is the diagnostic that must
            // own stderr at the caller.
            out.push_str(
                "AGENT_VM_IMAGE_TAG: <present but not valid Unicode; refusing to select>\n",
            );
            out.push_str(&active_row);
            return (out, None, None);
        }
    };
    // An unreadable config leaves the tiers unknown, but the default records are
    // still readable, so `doctor` reports them with the *same* selector an empty
    // config would use rather than inventing a second resolution path. The
    // selection such a catalog produces is provisional: nothing may establish a
    // project default from it (R3).
    let tiers = match images {
        Some(images) if catalog_built => boot_image::ConfiguredTiers::Read(images),
        Some(images) => boot_image::ConfiguredTiers::ReadFromBrokenCatalog(images),
        None => boot_image::ConfiguredTiers::Unreadable,
    };
    let observation = boot_image::observe(env_override, tiers, project);
    let default_row = describe_default_observation(&observation.default);
    let project_default_row = describe_project_default_observation(&observation.project_default);
    // A user scope that cannot be *located* (`$HOME` unset, empty or relative)
    // is already reported by the config section as an unavailable user tier;
    // it is not a damaged record, so on its own it does not fail the
    // diagnostic. A record that exists but cannot be read/parsed does — this
    // follows the *default* row, not the effective selection, so a valid
    // `AGENT_VM_IMAGE_TAG` cannot mask the damage (the override still wins the
    // launch; the diagnosis still fails).
    let scope_locatable = matches!(crate::config::host_home_dir(), Ok(Some(_)));
    let failure = match (&observation.default, &observation.project_default) {
        // The host record is unused by an established project, so its damage is
        // reported by its own row and this diagnosis; the project's own record
        // failing is likewise a nonzero exit. Both arms carry the same guard: an
        // authority that cannot be *located* is the config section's finding,
        // never a second, boot-image damage diagnosis.
        (boot_image::DefaultObservation::Unavailable { message }, _) if scope_locatable => {
            Some(anyhow::anyhow!(message.clone()))
        }
        (_, boot_image::ProjectDefaultObservation::Unavailable { message }) if scope_locatable => {
            Some(anyhow::anyhow!(message.clone()))
        }
        _ => None,
    };
    let Some(images) = images else {
        // The config could not be read, so the tiers are unknown.
        out.push_str("unknown (configuration could not be read)\n");
        out.push_str(&format!("default: {default_row}\n"));
        out.push_str(&format!("project default: {project_default_row}\n"));
        // The row stays available here: recorded roles do not depend on the
        // configuration, and the caller's `write_line` owns the final LF.
        out.push_str(&active_row);
        return (out, failure.or(active_failure), None);
    };
    out.push_str(&describe_image_tiers(images));
    out.push_str(&format!("default: {default_row}\n"));
    out.push_str(&format!("project default: {project_default_row}\n"));
    out.push_str(&active_row);
    out.push('\n');
    // Doctor accepts no `--image`, so the selected row excludes the command
    // line: it is the env slot, then config, then the default slot. When the
    // default slot won, the selected row reuses that record's *safe* label
    // rather than rendering its reference.
    match &observation.selected {
        Ok(selected) if selected.is_default() => {
            // The project default gets its own label so the two default rows stay
            // distinguishable: the host row says what is retained, this one says
            // which record the selection read.
            let row = match selected.source() {
                boot_image::ImageSource::ProjectDefault(path) => {
                    format!("project default [{}]", crate::one_line::path(path))
                }
                _ => default_row.clone(),
            };
            out.push_str(&format!("selected (without --image): {row}"));
        }
        Ok(selected) => out.push_str(&format!(
            "selected (without --image): {} (from {})",
            crate::config::escape_str(selected.reference().as_str()),
            selected.source().describe()
        )),
        Err(error) => out.push_str(&format!("selected (without --image): error: {error:#}")),
    }
    let selection = observation.selected.as_ref().ok().cloned();
    (out, failure.or(active_failure), selection)
}

/// The `active images:` row: the host platform's recorded roles and its
/// unclaimed count, or one of the two safe non-answers.
///
/// Its input carries no reference, digest or revision, so the row cannot leak
/// one. Only located authority damage becomes a failure: an unlocatable `$HOME`
/// is already the config section's finding, and an uncapturable project is the
/// documented `unknown` state — neither is a second diagnosis of a file that was
/// never read.
fn describe_active_images_observation(
    observation: &crate::image_pin::ActiveImagesObservation,
) -> (String, Option<anyhow::Error>) {
    use crate::image_pin::ActiveImagesObservation as Observation;
    match observation {
        Observation::Available(active) => (
            format!(
                "active images: boot={}, output={}, unclaimed={} [{}]",
                presence(active.boot_recorded),
                presence(active.output_recorded),
                active.unclaimed,
                crate::one_line::path(&active.path),
            ),
            None,
        ),
        Observation::ProjectUnknown => (
            "active images: unknown (the project directory could not be captured)".to_string(),
            None,
        ),
        Observation::Unavailable {
            message,
            authority_located,
        } => (
            format!("active images: error: {message}"),
            authority_located.then(|| anyhow::anyhow!(message.to_string())),
        ),
    }
}

/// Role presence: `recorded` iff a matching record's knowledge is Present. It
/// never says `not recorded` means resolved-absent — the row reports presence,
/// not the scope's resolution.
fn presence(recorded: bool) -> &'static str {
    if recorded { "recorded" } else { "not recorded" }
}

/// The `default:` row: which immutable image this host retains, the offered
/// recommendation when nothing is retained yet, or a safe diagnostic. Never a
/// raw record/recommendation reference — only a fixed label and the escaped
/// record path — so `doctor` can be shared or pasted without leaking a private
/// registry name.
fn describe_default_observation(observation: &boot_image::DefaultObservation) -> String {
    match observation {
        boot_image::DefaultObservation::Retained { path, .. } => {
            format!("retained default [{}]", crate::one_line::path(path))
        }
        boot_image::DefaultObservation::Uninitialized { path, .. } => format!(
            "not selected; initial recommendation [{}]",
            crate::one_line::path(path)
        ),
        boot_image::DefaultObservation::Unavailable { message } => {
            format!("error: {message}")
        }
    }
}

/// The `project default:` row: whether this project has its own default, where
/// it is recorded, and never its reference.
fn describe_project_default_observation(
    observation: &boot_image::ProjectDefaultObservation,
) -> String {
    use boot_image::ProjectDefaultObservation as Observation;
    match observation {
        Observation::Established { path, .. } => {
            format!("established [{}]", crate::one_line::path(path))
        }
        Observation::NotEstablished => {
            "not established (the next eligible default-tier use records it)".into()
        }
        Observation::Unknown => "unknown (the project directory could not be captured)".into(),
        Observation::Unavailable { message } => format!("error: {message}"),
    }
}

/// The `user:`, `project:` and `source …:` rows of the boot-image section.
///
/// ADR-0076 R5.2: the project config (its own `image`, or an `ALIAS:image`
/// selection) outranks every source, and the fallback is the first `allow = true`
/// source in `[[sources]]` order. Each other declared image says what outranked
/// it, and an `allow = false` one says how to select it instead — it changes
/// nothing, and the row must not claim the project already asks for it.
fn describe_image_tiers(images: &ConfiguredImages) -> String {
    use crate::config::SourceImageStatus;

    let mut out = if images.user().is_some() {
        let note = if images.project().is_some() {
            Some("overridden by the project image".to_owned())
        } else {
            images
                .user_overridden_by()
                .map(|winner| format!("overridden by source {winner} fallback image"))
        };
        match note {
            Some(note) => format!(
                "user:    {}  ({note})\n",
                describe_configured_image(images.user())
            ),
            None => format!("user:    {}\n", describe_configured_image(images.user())),
        }
    } else {
        format!("user:    {}\n", describe_configured_image(images.user()))
    };
    out.push_str(&format!(
        "project: {}\n",
        describe_configured_image(images.project())
    ));
    for row in images.source_images() {
        let alias = row.alias();
        let status = match row.status() {
            SourceImageStatus::SelectedFallback => "selected fallback; allow = true".to_owned(),
            SourceImageStatus::OverriddenByProject => {
                "allow = true; overridden by the project image".to_owned()
            }
            SourceImageStatus::OverriddenBySource(winner) => {
                format!("allow = true; overridden by source {winner} fallback image")
            }
            SourceImageStatus::Inert => format!(
                "inert; allow = false — to select it, write image = \"{alias}:image\" in the \
                 project config or set allow = true"
            ),
        };
        out.push_str(&format!(
            "source {alias}: {}  ({status})\n",
            describe_configured_image(Some(row.image())),
        ));
    }
    out
}

/// `ghcr.io/owner/name:tag [/path/to/config.toml]`, or
/// `ghcr.io/owner/name:tag [ALIAS:image /path/to/source.toml]` for an image the
/// project config authorized from a source (ADR-0074 R11).
fn describe_configured_image(image: Option<&ConfiguredImage>) -> String {
    match image {
        None => "none".to_string(),
        Some(image) => match image.via() {
            None => format!(
                "{} [{}]",
                crate::config::escape_str(image.reference().as_str()),
                crate::one_line::path(image.file())
            ),
            Some(alias) => format!(
                "{} [{alias}:image {}]",
                crate::config::escape_str(image.reference().as_str()),
                crate::one_line::path(image.file())
            ),
        },
    }
}

/// One `N. <name> -> ...` verb row.
///
/// The two closure columns report what a launch of this verb resolves, matching
/// the launch itself: `provisions=` is [`CatalogEntry::provisioned`] and
/// `persist=` is [`CatalogEntry::persist`], each folded over the same `tools`
/// closure — never the tool's own declaration (#429). `credentials=` stays the
/// tool's own declared **built-in** providers, the set the launch's provider
/// check reads; a custom `credentials.yaml` service is resolved from its
/// authorization at launch and appears in no column here. A closure can add
/// paths the row's own tool does not declare, so the resolved persist count
/// names the own count in parentheses when the two differ (`persist=3 (own
/// 1)`); equal counts render as a bare number.
fn describe_tool(entry: &CatalogEntry) -> String {
    let tool = entry.tool();
    // Both provider columns render through the same helper, in
    // `CredentialProvider::ALL` order. `credentials` is stored in *declaration*
    // order (`validate_credentials` — a plain map/collect), so rendering it
    // directly beside an `ALL`-ordered `provisions=` would show the same set in
    // two orders for a tool declaring `["copilot","anthropic"]`, which reads as
    // a bug. Canonicalize both to `ALL` order; the shipped rows are already in
    // that order, so no existing expectation changes.
    let credentials = provider_names(ProviderSet::new(tool.credentials().iter().copied()).iter());
    let provisions = provider_names(entry.provisioned().iter());
    let own_persist = tool.persist_count();
    let resolved_persist = entry.persist().len();
    let persist = if resolved_persist == own_persist {
        resolved_persist.to_string()
    } else {
        format!("{resolved_persist} (own {own_persist})")
    };
    let source = match tool.origin() {
        ToolOrigin::BuiltIn => "built-in".to_string(),
        ToolOrigin::User(file) => format!("user:{}", crate::one_line::path(file)),
        ToolOrigin::Project(file) => format!("project:{}", crate::one_line::path(file)),
        ToolOrigin::Source { alias, file } => {
            format!("sourced:{alias}:{}", crate::one_line::path(file))
        }
    };
    // Only surfaced when true, so this field leaves the default-config rows for
    // the six agents exactly as they were (`interactive_shell` is
    // `shell`-only; #429 changed the shell row's `persist=`, not this suffix).
    let interactive_shell = if tool.is_interactive_shell() {
        "; interactive_shell=true"
    } else {
        ""
    };
    // Count only (never the values — see `Tool::guest_env`), and only when
    // nonzero so the rows of tools that declare no env stay unchanged.
    let env_count = tool.env_count();
    let env = if env_count == 0 {
        String::new()
    } else {
        format!("; env={env_count}")
    };
    let requests = tool.network_requests();
    let requests = if requests.is_empty() {
        String::new()
    } else {
        format!("; network_requests={}", requests.bounded_display())
    };
    // A blocked or unverified declaring read still loads, but every launch
    // refuses it; the row says so with the launch's own sentence (E8/V4).
    let unavailable = entry
        .launch_trust()
        .and_then(launch_refusal_note)
        .map(|note| format!("; {note}"))
        .unwrap_or_default();
    format!(
        "{} -> \"{}\"; args={}; credentials={credentials}; \
         provisions={provisions}; persist={persist}; source={source}{interactive_shell}{env}{requests}{unavailable}",
        crate::config::escape_str(entry.label()),
        crate::config::escape_str(tool.command()),
        tool.arg_count(),
    )
}

/// `anthropic,openai` / `none`, in `CredentialProvider::ALL` order. Both
/// columns pass through here, so the requirement set and the provisioning set
/// can never render the same provider two different ways.
fn provider_names(providers: impl Iterator<Item = CredentialProvider>) -> String {
    let names: Vec<&str> = providers.map(CredentialProvider::config_name).collect();
    if names.is_empty() {
        "none".to_string()
    } else {
        names.join(",")
    }
}

/// `expires in 3h22m` / `EXPIRED 15m ago`. Minute resolution is enough to
/// answer "is my host login stale?", which is the only question this row
/// exists to settle.
fn describe_expiry(expires_at_ms: i64, now_ms: i64) -> String {
    let delta_secs = (expires_at_ms - now_ms) / 1000;
    let (verb, mut secs) = if delta_secs >= 0 {
        ("expires in", delta_secs)
    } else {
        ("EXPIRED", -delta_secs)
    };
    let hours = secs / 3600;
    secs %= 3600;
    let minutes = secs / 60;
    let span = if hours > 0 {
        format!("{hours}h{minutes:02}m")
    } else {
        format!("{minutes}m")
    };
    if delta_secs >= 0 {
        format!("{verb} {span}")
    } else {
        format!("{verb} {span} ago")
    }
}

/// Move `msb_home/db` aside to a unique `db.reset-<ts>` sibling. Pure over
/// its inputs: no env reads, so it is directly unit-testable against a
/// tempdir. Never deletes anything — worst case on a failed rename is the
/// original `db/` untouched.
fn reset_msb_db_in(msb_home: &Path, ts: &str) -> Result<ResetOutcome> {
    let db = msb_home.join("db");
    // symlink_metadata: don't follow, and treat a broken symlink as
    // present so we still move it aside rather than silently no-op.
    if std::fs::symlink_metadata(&db).is_err() {
        return Ok(ResetOutcome::NothingToMove { checked: db });
    }

    let target = unique_target(msb_home, ts);
    std::fs::rename(&db, &target).with_context(|| {
        format!(
            "moving {} -> {}",
            crate::one_line::path(&db),
            crate::one_line::path(&target)
        )
    })?;
    Ok(ResetOutcome::Moved {
        from: db,
        to: target,
    })
}

/// `msb_home/db.reset-<ts>`, disambiguated with `.2`, `.3`, ... if that
/// path is already taken, so a prior reset (e.g. a same-second re-run) is
/// never clobbered.
fn unique_target(msb_home: &Path, ts: &str) -> PathBuf {
    let base = msb_home.join(format!("db.reset-{ts}"));
    if std::fs::symlink_metadata(&base).is_err() {
        return base;
    }
    for n in 2.. {
        let candidate = msb_home.join(format!("db.reset-{ts}.{n}"));
        if std::fs::symlink_metadata(&candidate).is_err() {
            return candidate;
        }
    }
    unreachable!("unbounded loop above always returns")
}

/// Epoch-seconds suffix: dependency-free (no chrono), sortable,
/// unambiguous. Not calendar-formatted on purpose — this is a rarely-run
/// recovery command, and human readability comes from the printed
/// absolute path, not the suffix.
fn timestamp_suffix(now: SystemTime) -> String {
    now.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .to_string()
}

/// User-facing text for a [`ResetOutcome`]. Pure so the AC wording lives in
/// one testable place.
///
/// `from:`/`to:` above are [`crate::one_line`] diagnostics, so the undo command
/// takes raw path bytes through [`crate::shell::PastedWord`] instead; `mv --`
/// keeps the leading operand a path rather than an option, and
/// [`crate::shell::bash_zsh_note`] names the shell when not every shell reads
/// the operand.
///
/// The undo command is guarded rather than a bare `mv` (#432). It runs later,
/// possibly after a launch has recreated `db/`; `mv` would then move the backup
/// *inside* the new db and exit 0, so the operator would read a nested copy as a
/// restore. The guard refuses while the original name is taken, names it, and
/// exits nonzero, so nothing is restored without the status saying so.
fn render(outcome: &ResetOutcome) -> String {
    use std::os::unix::ffi::OsStrExt as _;
    match outcome {
        ResetOutcome::Moved { from, to } => {
            // The reverse of the move: the backup first, the original second.
            let to_word = crate::shell::PastedWord::new(to.as_os_str().as_bytes());
            let from_word = crate::shell::PastedWord::new(from.as_os_str().as_bytes());
            // Its own line, so the `To undo: ` line is only the command.
            let shell_note = crate::shell::bash_zsh_note(&[&to_word, &from_word])
                .map(|note| format!("\n({note})"))
                .unwrap_or_default();
            // `[ -e ]` is about the name, not the contents: an empty recreated
            // `db/` is exactly the conflict this refuses. `false` rather than
            // `exit` so pasting into an interactive shell does not close it.
            // Both paths go on stderr as `%s` arguments, so the operator can tell
            // which backup was left where, and so no byte of a name is read as
            // part of the format.
            let refusal = "printf 'refusing to undo: %s exists; %s was not restored; \
                           move the existing db aside, then run this again\\n'";
            let undo = format!(
                "if [ -e {from_word} ]; then {refusal} {from_word} {to_word} >&2; false; \
                 else mv -- {to_word} {from_word}; fi"
            );
            format!(
                "==> Moved microsandbox db aside (nothing was deleted)\n\
                 from: {}\n\
                 to:   {}\n\
                 The database will be recreated at the bundled schema on the next \
                 `agent-vm shell`/`run`, and images will be re-pulled on first boot.\n\
                 To undo: {undo}{shell_note}",
                crate::one_line::path(from),
                crate::one_line::path(to),
            )
        }
        ResetOutcome::NothingToMove { checked } => format!(
            "==> No microsandbox db to reset — nothing was moved.\n\
             checked: {}\n\
             A fresh database will be created on the next `agent-vm shell`/`run`.",
            crate::one_line::path(checked),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both rows as an unclaimed configuration leaves them.
    const SHOWN_ROWS: PathRows = PathRows {
        state: PathRow::Shown,
        cache: PathRow::Shown,
    };

    // -------------------------------------------------------------------------
    // The `active images:` row (#609)
    // -------------------------------------------------------------------------

    use crate::image_pin::{ActiveImages, ActiveImagesObservation};

    /// The documented `one_line::path` policy, reimplemented here so the
    /// expected row never comes from the production renderer: valid UTF-8 keeps
    /// its printable characters (controls become `\xNN`), and each byte of an
    /// invalid sequence becomes `\xNN`.
    fn one_line(bytes: &[u8]) -> String {
        let mut out = String::new();
        let push = |text: &str, out: &mut String| {
            for character in text.chars() {
                if character.is_control() {
                    out.push_str(&format!("\\x{:02x}", character as u32));
                } else {
                    out.push(character);
                }
            }
        };
        let mut rest = bytes;
        loop {
            match std::str::from_utf8(rest) {
                Ok(text) => {
                    push(text, &mut out);
                    return out;
                }
                Err(error) => {
                    let (valid, after) = rest.split_at(error.valid_up_to());
                    push(std::str::from_utf8(valid).unwrap(), &mut out);
                    let invalid = error.error_len().unwrap_or(after.len());
                    for byte in &after[..invalid] {
                        out.push_str(&format!("\\x{byte:02x}"));
                    }
                    rest = &after[invalid..];
                }
            }
        }
    }

    fn available(path: &Path, boot: bool, output: bool, unclaimed: usize) -> ActiveImages {
        ActiveImages {
            path: path.to_owned(),
            boot_recorded: boot,
            output_recorded: output,
            unclaimed,
        }
    }

    /// AC7: the two non-answers are exact and carry no path; only located damage
    /// is a diagnostic failure.
    #[test]
    fn active_images_row_formats_unknown_and_error_states() {
        let (row, failure) =
            describe_active_images_observation(&ActiveImagesObservation::ProjectUnknown);
        assert_eq!(
            row,
            "active images: unknown (the project directory could not be captured)"
        );
        assert!(failure.is_none(), "unknown is not a failure");
        assert!(!row.contains('['), "no path suffix on unknown: {row}");

        let message = crate::one_line::text("image pin authority is damaged");
        for (located, fails) in [(true, true), (false, false)] {
            let (row, failure) =
                describe_active_images_observation(&ActiveImagesObservation::Unavailable {
                    message: message.clone(),
                    authority_located: located,
                });
            assert_eq!(row, "active images: error: image pin authority is damaged");
            assert!(!row.contains('['), "no path suffix on error: {row}");
            match (fails, failure) {
                (true, Some(error)) => assert_eq!(error.to_string(), message.to_string()),
                (false, None) => {}
                (_, other) => panic!("located={located}: {other:?}"),
            }
        }

        // A store message that carried a control byte cannot forge a row: the
        // seam escapes it once, when the Line is built.
        let hostile = crate::one_line::text("two\nlines\u{1b}[31m");
        let (row, _) = describe_active_images_observation(&ActiveImagesObservation::Unavailable {
            message: hostile,
            authority_located: false,
        });
        assert_eq!(row.matches('\n').count(), 0, "{row:?}");
        assert!(!row.contains('\u{1b}'), "{row:?}");
        assert!(row.contains("two\\x0alines"), "{row:?}");
    }

    /// AC9: every presence pair and both count extremes render exactly, with the
    /// measured path under the one-line policy — non-ASCII readable, controls and
    /// invalid bytes escaped.
    #[test]
    fn active_images_path_is_one_line_and_keeps_unicode() {
        let raw = b"/home/boger/\xd0\xb4\xd0\xbe\xd0\xbc/ne\nw\t\x1b/\xfftail/.config/agent-vm/image-pins.json".to_vec();
        let path = {
            use std::os::unix::ffi::OsStringExt as _;
            PathBuf::from(std::ffi::OsString::from_vec(raw.clone()))
        };
        assert!(
            std::str::from_utf8(&raw).is_err(),
            "the fixture must carry an invalid byte"
        );
        for (boot, output) in [(false, false), (true, false), (false, true), (true, true)] {
            for unclaimed in [0, 2] {
                let (row, failure) = describe_active_images_observation(
                    &ActiveImagesObservation::Available(available(&path, boot, output, unclaimed)),
                );
                assert!(failure.is_none());
                assert_eq!(
                    row,
                    format!(
                        "active images: boot={}, output={}, unclaimed={} [{}]",
                        if boot { "recorded" } else { "not recorded" },
                        if output { "recorded" } else { "not recorded" },
                        unclaimed,
                        one_line(&raw),
                    )
                );
                assert_eq!(row.matches('\n').count(), 0, "{row:?}");
                assert!(!row.contains('\u{1b}') && !row.contains('\t'), "{row:?}");
                assert!(row.contains("дом"), "valid Unicode stays readable: {row}");
                assert!(row.contains("\\xff"), "the invalid byte is escaped: {row}");
                assert!(
                    !row.contains('\u{fffd}'),
                    "an invalid byte must not become U+FFFD: {row}"
                );
            }
        }
    }

    #[test]
    fn credential_store_rows_match_all_outcomes() {
        for (outcome, row, fails) in [
            (
                Availability::NotProbed,
                "not probed (0 tracked names)",
                false,
            ),
            (
                Availability::Reachable,
                "reachable (read-only check)",
                false,
            ),
        ] {
            let (text, error) = describe_credential_store(&Ok(outcome));
            assert_eq!(
                text,
                format!("==> credential store\ncredential store: {row}")
            );
            assert_eq!(error.is_some(), fails);
        }
        use crate::secret_store::KeychainFailure as F;
        for failure in [
            F::AccessDenied,
            F::Unavailable,
            F::Ambiguous,
            F::Rejected,
            F::Unresponsive,
            F::InventoryBusy,
            F::Unknown,
        ] {
            let (text, error) = describe_credential_store(&Ok(Availability::Unavailable(failure)));
            assert_eq!(
                text,
                format!(
                    "==> credential store\ncredential store: unavailable ({})",
                    failure.message()
                )
            );
            assert_eq!(
                error.unwrap().to_string(),
                "credential store check failed; see credential store section"
            );
            assert!(!text.contains("sk-CANARY-value"));
        }
        let (text, error) = describe_credential_store(&Err(anyhow!("unsafe\n\x1b path")));
        assert_eq!(
            text,
            "==> credential store\ncredential store: not probed (inventory unavailable)\nerror: \"unsafe\\x0a\\x1b path\""
        );
        assert!(error.is_some());
    }

    #[derive(Default)]
    struct RecordingWriter {
        bytes: Vec<u8>,
        flushed: std::rc::Rc<std::cell::Cell<usize>>,
        submissions: std::rc::Rc<std::cell::RefCell<Vec<Vec<u8>>>>,
        fail_write: bool,
        fail_flush_at: Option<usize>,
    }
    impl std::io::Write for RecordingWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.fail_write {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "test broken pipe",
                ));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            let n = self.flushed.get() + 1;
            self.flushed.set(n);
            self.submissions.borrow_mut().push(self.bytes.clone());
            if self.fail_flush_at == Some(n) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "test flush failure",
                ));
            }
            Ok(())
        }
    }

    #[test]
    fn doctor_output_write_failure_is_an_error() {
        let mut writer = RecordingWriter {
            fail_write: true,
            ..Default::default()
        };
        let error = write_line(&mut writer, "hello").unwrap_err();
        assert_eq!(error.to_string(), "writing doctor output");
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::BrokenPipe
        );
    }

    // Environment/cwd are held under the same cooperative guard as other unit
    // tests. No credential values, timestamps or expiry data enter this fixture.
    struct RunFixture {
        old_cwd: PathBuf,
        root: tempfile::TempDir,
        _env: crate::test_env::EnvGuard,
    }
    impl RunFixture {
        fn new() -> Self {
            Self::build(ANTHROPIC, |env, root| {
                env.set_var("XDG_CACHE_HOME", root.join("cache"));
                env.set_var("AGENT_VM_STATE_DIR", root.join("state"));
            })
        }

        /// A fixture whose `credentials.yaml` is `credentials` and whose launcher
        /// variables are `state_home` and `cache_home`, with
        /// `AGENT_VM_STATE_DIR` unset so the state root is the one
        /// `XDG_STATE_HOME` supplies — the shape #353 reproduces.
        fn with_launcher_variables(
            credentials: &str,
            state_home: &Path,
            cache_home: &Path,
        ) -> Self {
            let (state_home, cache_home) = (state_home.to_owned(), cache_home.to_owned());
            Self::build(credentials, move |env, _root| {
                env.set_var("XDG_STATE_HOME", &state_home);
                env.set_var("XDG_CACHE_HOME", &cache_home);
            })
        }

        fn build(
            credentials: &str,
            set_variables: impl FnOnce(&mut crate::test_env::EnvGuard, &Path),
        ) -> Self {
            let mut env = crate::test_env::guard();
            let root = tempfile::tempdir().unwrap();
            let home = root.path().join("home");
            let project = root.path().join("project");
            std::fs::create_dir_all(&project).unwrap();
            write_file(
                &home.join(".config/agent-vm/credentials.yaml"),
                credentials.as_bytes(),
            );
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(
                home.join(".config/agent-vm/credentials.yaml"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            env.set_var("HOME", &home);
            for key in [
                "AGENT_VM_IMAGE_TAG",
                "AGENT_VM_TEST_DEFAULT_IMAGE",
                "AGENT_VM_STATE_DIR",
                "MSB_HOME",
                "XDG_CACHE_HOME",
                "XDG_CONFIG_HOME",
                "XDG_STATE_HOME",
            ] {
                env.remove_var(key);
            }
            set_variables(&mut env, root.path());
            let old_cwd = std::env::current_dir().unwrap();
            std::env::set_current_dir(&project).unwrap();
            Self {
                old_cwd,
                root,
                _env: env,
            }
        }
        fn normalize(&self, text: &str) -> String {
            let project =
                crate::project::ProjectDir::from_path_for_tests(&std::env::current_dir().unwrap())
                    .unwrap();
            let session = crate::session::ProjectSession::for_project(&project).unwrap();
            text.replace(&session.state_dir.display().to_string(), "<project-state>")
                .replace(&project.digest_hex(), "<project-id>")
                .replace(
                    &self
                        .root
                        .path()
                        .canonicalize()
                        .unwrap()
                        .display()
                        .to_string(),
                    "<fixture>",
                )
                .replace(&self.root.path().display().to_string(), "<fixture>")
        }
    }
    impl Drop for RunFixture {
        fn drop(&mut self) {
            std::env::set_current_dir(&self.old_cwd).unwrap();
        }
    }
    fn ordinary() -> Args {
        Args {
            reset_msb_db: false,
        }
    }
    fn assert_tail(text: &str) {
        for heading in [
            "==> tool configuration",
            "==> credentials.yaml (launch credentials)",
            "==> boot image",
            "==> image network requests",
            "==> agent-vm doctor: available operations",
        ] {
            assert!(text.contains(heading), "missing {heading}: {text}");
        }
        assert!(text.ends_with(
            "                       agent-vm shell/run recreates it at the bundled schema\n"
        ));
        assert_eq!(text.matches("==> credential store\n").count(), 1);
    }

    /// V12: the legacy notice's bytes, for every outcome the probe can report,
    /// from both a rendered section and an `error:` body.
    #[test]
    fn legacy_notice_bytes_are_pinned() {
        let path = PathBuf::from("/home/u/проект/.agent-vm/config.toml");
        let present = LegacyProjectConfig::Present(path.clone());
        let rendered =
            with_legacy_notice("==> tool configuration\nfiller".to_owned(), Some(&present));
        assert_eq!(
            rendered,
            format!(
                "==> tool configuration\nfiller\nnote: {} is not auto-loaded; agent-vm never reads an in-repo .agent-vm/config.toml.\nTo use it, review it and source it from this project's config: edit the file\n`agent-vm doctor` names as its `project:` row with your own editor (this version\nhas no `config edit` command).",
                crate::one_line::path(&path)
            )
        );
        // The same note follows an error body: it must not be swallowed because
        // the configuration failed.
        let failed = with_legacy_notice(
            "==> tool configuration\nerror: boom".to_owned(),
            Some(&present),
        );
        assert!(failed.ends_with(&rendered["==> tool configuration\nfiller".len()..]));

        for kind in [
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::NotADirectory,
        ] {
            let unexaminable = LegacyProjectConfig::Unexaminable {
                path: path.clone(),
                kind,
            };
            assert_eq!(
                with_legacy_notice("section".to_owned(), Some(&unexaminable)),
                format!(
                    "section\nnote: could not check for an in-repo .agent-vm/config.toml at {} ({kind:?}); agent-vm never auto-loads it.",
                    crate::one_line::path(&path)
                )
            );
        }
        for absent in [Some(&LegacyProjectConfig::Absent), None] {
            assert_eq!(with_legacy_notice("section".to_owned(), absent), "section");
        }
    }

    /// V21: `doctor` reads the capture `main` handed it, not a fresh one. A cwd
    /// renamed after capture must not switch which project's config is rendered.
    #[test]
    fn run_to_uses_the_supplied_capture_after_cwd_moves() {
        let fixture = RunFixture::new();
        let project = std::env::current_dir().unwrap();
        let captured = ProjectDir::from_path_for_tests(&project).unwrap();
        let id_a = captured.digest_hex();
        // A rename inside the same directory: `getcwd` now spells the new name,
        // so a second capture would be a different project.
        let moved = project.with_file_name("project-moved");
        std::fs::rename(&project, &moved).unwrap();
        let id_b = crate::project::digest_hex_of(&moved.canonicalize().unwrap());
        assert_ne!(id_a, id_b);
        let store = fixture.root.path().join("home/.config/agent-vm/projects");
        for (id, name) in [(&id_a, "from-a"), (&id_b, "from-b")] {
            let config = store.join(id).join("config.toml");
            std::fs::create_dir_all(config.parent().unwrap()).unwrap();
            write_config(
                &config,
                format!("[[tools]]\nname = \"{name}\"\ncommand = \"{name}\"\n"),
            );
        }

        let mut out = Vec::new();
        run_to(ordinary(), Ok(captured), &mut out, || {
            Ok(Availability::NotProbed)
        })
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("from-a"), "{text}");
        assert!(!text.contains("from-b"), "{text}");
        assert!(
            text.contains(&id_a),
            "the rendered project is dir_a: {text}"
        );
        assert!(!text.contains(&id_b), "{text}");
    }

    #[test]
    fn run_to_flushes_before_gather_and_after_success() {
        let _fixture = RunFixture::new();
        let mut out = RecordingWriter::default();
        let flushed = out.flushed.clone();
        let submissions = out.submissions.clone();
        run_to(ordinary(), captured(), &mut out, || {
            assert_eq!(flushed.get(), 1);
            let submissions = submissions.borrow();
            let prefix = std::str::from_utf8(&submissions[0]).unwrap();
            assert!(prefix.starts_with("==> active microsandbox home\n"));
            assert!(prefix.contains("==> host agent credentials\n"));
            assert!(prefix.ends_with("substituted.\n\n"));
            assert!(!prefix.contains("==> credential store"));
            assert!(!prefix.contains("==> tool configuration"));
            Ok(Availability::NotProbed)
        })
        .unwrap();
        assert_eq!(out.flushed.get(), 2);
        assert_eq!(out.submissions.borrow().last().unwrap(), &out.bytes);
        assert_tail(std::str::from_utf8(&out.bytes).unwrap());
    }

    #[test]
    fn run_to_keeps_tail_on_unavailable() {
        let _fixture = RunFixture::new();
        let mut successful = Vec::new();
        run_to(ordinary(), captured(), &mut successful, || {
            Ok(Availability::Reachable)
        })
        .unwrap();
        let successful = std::str::from_utf8(&successful).unwrap();
        let expected_tail = successful.split_once("==> tool configuration\n").unwrap().1;
        for failure in [
            crate::secret_store::KeychainFailure::AccessDenied,
            crate::secret_store::KeychainFailure::Unresponsive,
        ] {
            let mut out = RecordingWriter::default();
            let error = run_to(ordinary(), captured(), &mut out, || {
                Ok(Availability::Unavailable(failure))
            })
            .unwrap_err();
            assert_eq!(
                error.to_string(),
                "credential store check failed; see credential store section"
            );
            let text = std::str::from_utf8(&out.bytes).unwrap();
            assert_tail(text);
            assert_eq!(
                text.split_once("==> tool configuration\n").unwrap().1,
                expected_tail
            );
            assert_eq!(out.flushed.get(), 2);
        }
    }

    #[test]
    fn run_to_io_error_precedes_health_failure() {
        let _fixture = RunFixture::new();
        for flush in [1, 2] {
            let mut out = RecordingWriter {
                fail_flush_at: Some(flush),
                ..Default::default()
            };
            let error = run_to(ordinary(), captured(), &mut out, || {
                Ok(Availability::Unavailable(
                    crate::secret_store::KeychainFailure::AccessDenied,
                ))
            })
            .unwrap_err();
            assert_eq!(error.to_string(), "writing doctor output");
            assert_eq!(
                error.downcast_ref::<std::io::Error>().unwrap().kind(),
                std::io::ErrorKind::BrokenPipe
            );
            if flush == 2 {
                assert_tail(std::str::from_utf8(&out.bytes).unwrap());
            }
        }
        let mut out = RecordingWriter {
            fail_write: true,
            ..Default::default()
        };
        let error = run_to(ordinary(), captured(), &mut out, || {
            panic!("gather after failed output")
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "writing doctor output");
    }

    #[test]
    fn run_to_reset_skips_gather() {
        let fixture = RunFixture::new();
        write_file(
            &fixture
                .root
                .path()
                .join("home/.config/agent-vm/secret-inventory.json"),
            b"corrupt inventory",
        );
        for has_db in [false, true] {
            if has_db {
                write_file(&fixture.root.path().join("state/msb-home/db/msb.db"), b"db");
            }
            let mut out = RecordingWriter::default();
            run_to(Args { reset_msb_db: true }, captured(), &mut out, || {
                panic!("reset discovered inventory")
            })
            .unwrap();
            assert_eq!(out.flushed.get(), 1);
            assert!(
                !std::str::from_utf8(&out.bytes)
                    .unwrap()
                    .contains("credential store")
            );
        }
    }

    #[test]
    fn run_to_pins_ordinary_and_reset_bytes() {
        let fixture = RunFixture::new();
        let mut out = Vec::new();
        run_to(ordinary(), captured(), &mut out, || {
            Ok(Availability::NotProbed)
        })
        .unwrap();
        let actual = fixture.normalize(std::str::from_utf8(&out).unwrap());
        let without_new_section = actual.replace(
            "==> credential store\ncredential store: not probed (0 tracked names)\n\n",
            "",
        );
        let expected = r###"==> active microsandbox home
MSB_HOME: <fixture>/state/msb-home
db:       <fixture>/state/msb-home/db/msb.db (absent)
this build's bundled schema: m20261030_000001

==> host agent credentials
claude    <fixture>/home/.claude/.credentials.json
          absent - replaced by credentials.yaml for pi, claude, shell (host file not read)
codex     <fixture>/home/.codex/auth.json
          absent
opencode  <fixture>/home/.local/share/opencode/auth.json
          absent
copilot   <fixture>/home/.cache/claude-vm/copilot-token.json
          absent
pi        <fixture>/home/.pi/agent/auth.json
          absent

==> this project
dir:      <fixture>/project
state:    <project-state>
captured: <none> (nothing to substitute on the wire)
guest Claude cred file: absent

==> guest-managed Pi credentials
Structural inspection of guest-managed Pi state only; agent-vm never resolves, imports, refreshes or removes it.
auth.json: not present
models.json: not present
Only auth.json and models.json are inspected (settings, sessions and installed packages are not).

For the host-captured Claude/Codex/GitHub credentials above, the guest never
receives a real token: it gets a placeholder that the TLS proxy swaps for the
host token on the way out. So sign in ON THE HOST (`claude login`,
`codex login`, `gh auth login`): running `/login` inside the VM cannot work and fails with an OAuth 400.
Pi guest-managed state is different: a credential created inside the guest
lives in the project's persistent Pi home and is reported above, not
substituted.

==> project allowances
file: <fixture>/home/.config/agent-vm/allowances.json (absent; nothing recorded)

==> tool configuration
user:    <fixture>/home/.config/agent-vm/config.toml (absent)
project: <fixture>/home/.config/agent-vm/projects/<project-id>/config.toml (absent)
resolved: built-in defaults; launch-verb order
  1. dsh -> "dsh"; args=1; credentials=none; provisions=none; persist=1; source=built-in
  2. pi -> "pi"; args=0; credentials=antigravity; provisions=anthropic,openai,antigravity; persist=0; source=built-in; network_requests=api.anthropic.com,auth.openai.com,chatgpt.com,cloudcode-pa.googleapis.com,daily-cloudcode-pa.googleapis.com,daily-cloudcode-pa.sandbox.googleapis.com,mcp-proxy.anthropic.com,oauth2.googleapis.com,+2 more
  3. codex -> "codex"; args=0; credentials=openai; provisions=openai; persist=0; source=built-in; env=1; network_requests=api.openai.com,auth.openai.com,chatgpt.com
  4. opencode -> "opencode"; args=0; credentials=openai,opencode-static; provisions=openai,opencode-static; persist=0; source=built-in; network_requests=api.openai.com,auth.openai.com,chatgpt.com,models.opencode.ai
  5. claude -> "claude"; args=1; credentials=anthropic; provisions=anthropic; persist=0; source=built-in; network_requests=api.anthropic.com,mcp-proxy.anthropic.com,platform.claude.com
  6. copilot -> "copilot"; args=1; credentials=copilot; provisions=copilot; persist=0; source=built-in
  7. shell -> "bash"; args=2; credentials=none; provisions=anthropic,openai,opencode-static,copilot,antigravity; persist=1 (own 0); source=built-in; interactive_shell=true; env=1

==> credentials.yaml (launch credentials)
anthropic  authorized for this launch (replaces the host built-in)
note: values are not read here; `agent-vm secret ls` reports whether a value is stored.

==> boot image
AGENT_VM_IMAGE_TAG: <unset>
user:    none
project: none
default: not selected; initial recommendation [<fixture>/home/.config/agent-vm/default-image.json]
project default: not established (the next eligible default-tier use records it)
active images: boot=not recorded, output=not recorded, unclaimed=0 [<fixture>/home/.config/agent-vm/image-pins.json]
selected (without --image): not selected; initial recommendation [<fixture>/home/.config/agent-vm/default-image.json]

==> image network requests
not cached; doctor does not acquire images

==> agent-vm doctor: available operations
      --reset-msb-db   move MSB_HOME/db aside (reversible) so the next
                       agent-vm shell/run recreates it at the bundled schema
"###;
        let expected = if let Some(payload) = crate::embedded_runtime::EMBEDDED.as_ref() {
            let runtime = crate::embedded_runtime::unpacked_dir(
                &fixture.root.path().join("cache/agent-vm/runtime"),
                payload,
            );
            let runtime = fixture.normalize(&runtime.display().to_string());
            expected.replacen(
                "==> host agent credentials\n",
                &format!(
                    "==> embedded runtime\nunpacked: {runtime} (absent)\n\n==> host agent credentials\n"
                ),
                1,
            )
        } else {
            expected.to_owned()
        };
        assert_eq!(without_new_section, expected);
        for has_db in [false, true] {
            if has_db {
                write_file(&fixture.root.path().join("state/msb-home/db/msb.db"), b"db");
            }
            let mut out = Vec::new();
            run_to(Args { reset_msb_db: true }, captured(), &mut out, || {
                panic!("reset gather")
            })
            .unwrap();
            let mut text = fixture.normalize(std::str::from_utf8(&out).unwrap());
            if has_db {
                let home = fixture.root.path().join("state/msb-home");
                let target = std::fs::read_dir(home)
                    .unwrap()
                    .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                    .find(|n| n.starts_with("db.reset-"))
                    .unwrap();
                text = text.replace(&target, "db.reset-<timestamp>");
            }
            let expected = if has_db {
                r###"==> Moved microsandbox db aside (nothing was deleted)
from: <fixture>/state/msb-home/db
to:   <fixture>/state/msb-home/db.reset-<timestamp>
The database will be recreated at the bundled schema on the next `agent-vm shell`/`run`, and images will be re-pulled on first boot.
To undo: if [ -e <fixture>/state/msb-home/db ]; then printf 'refusing to undo: %s exists; %s was not restored; move the existing db aside, then run this again\n' <fixture>/state/msb-home/db <fixture>/state/msb-home/db.reset-<timestamp> >&2; false; else mv -- <fixture>/state/msb-home/db.reset-<timestamp> <fixture>/state/msb-home/db; fi
"###
            } else {
                r###"==> No microsandbox db to reset — nothing was moved.
checked: <fixture>/state/msb-home/db
A fresh database will be created on the next `agent-vm shell`/`run`.
"###
            };
            assert_eq!(text, expected);
        }
    }

    // -------------------------------------------------------------------------
    // #353: no path derived from a variable the credential configuration may
    // claim as an environment source reaches the report
    // -------------------------------------------------------------------------

    /// The reproducer from the issue: a valid authorization that claims the
    /// launcher's own state variable as its environment source, which
    /// `credential_yaml` refuses (#163).
    const CLAIMS_STATE_HOME: &str = "\
credentials:
  - service: alpha
    source: env
    apiKey:
      name: XDG_STATE_HOME
      sentinelEnv: true
      inject: [{domain: api.example.com, scheme: bearer}]
";
    /// The same claim on the cache variable, whose only reported path is the
    /// embedded runtime's.
    const CLAIMS_CACHE_HOME: &str = "\
credentials:
  - service: alpha
    source: env
    apiKey:
      name: XDG_CACHE_HOME
      sentinelEnv: true
      inject: [{domain: api.example.com, scheme: bearer}]
";
    /// A file no parser can read: doctor cannot tell what it claims either, so it
    /// must withhold the same rows rather than assume they are unclaimed.
    const UNPARSEABLE: &str = "credentials:\n  - service: [unterminated\n";

    /// The capture `main` hands `doctor` for the fixture cwd.
    fn captured() -> Result<ProjectDir> {
        ProjectDir::from_path_for_tests(&std::env::current_dir().unwrap())
    }

    fn run_ordinary() -> String {
        let mut out = Vec::new();
        run_to(ordinary(), captured(), &mut out, || {
            Ok(Availability::NotProbed)
        })
        .unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn a_claimed_state_home_keeps_its_value_out_of_the_report() {
        let _fixture = RunFixture::with_launcher_variables(
            CLAIMS_STATE_HOME,
            Path::new("/tmp/sk-353-STATE-CANARY"),
            Path::new("/tmp/unclaimed-cache"),
        );

        let text = run_ordinary();

        assert!(!text.contains("sk-353-STATE-CANARY"), "{text}");
        // The rows keep their labels and name what to change; the unusable file is
        // still reported where it always was, so the reader is told why.
        assert!(
            text.contains(
                "MSB_HOME: not shown - credentials.yaml may name XDG_STATE_HOME as an \
                 environment credential source\n"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "state:    not shown - credentials.yaml may name XDG_STATE_HOME as an \
                 environment credential source\n"
            ),
            "{text}"
        );
        assert!(
            text.contains("==> credentials.yaml (launch credentials)\nerror: "),
            "{text}"
        );
        assert_tail(&text);
    }

    #[test]
    fn a_claimed_cache_home_keeps_its_value_out_of_the_report() {
        let _fixture = RunFixture::with_launcher_variables(
            CLAIMS_CACHE_HOME,
            Path::new("/tmp/unclaimed-state"),
            Path::new("/tmp/sk-353-CACHE-CANARY"),
        );

        let text = run_ordinary();

        assert!(!text.contains("sk-353-CACHE-CANARY"), "{text}");
        // Only a bundled build prints the cache-derived row; where it is absent
        // there is nothing to disclose, and the decision itself is covered by
        // `a_row_is_withheld_only_when_the_file_is_unusable_and_a_launcher_variable_supplied_it`
        // and `the_embedded_runtime_row_withholds_a_claimed_cache_root`.
        if crate::embedded_runtime::EMBEDDED.is_some() {
            assert!(
                text.contains(
                    "unpacked: not shown - credentials.yaml may name XDG_CACHE_HOME as an \
                     environment credential source"
                ),
                "{text}"
            );
        }
    }

    #[test]
    fn an_unparseable_credentials_file_with_launcher_roots_withholds_them() {
        let _fixture = RunFixture::with_launcher_variables(
            UNPARSEABLE,
            Path::new("/tmp/sk-353-BROKEN-CANARY"),
            Path::new("/tmp/unclaimed-cache"),
        );

        let text = run_ordinary();

        assert!(!text.contains("sk-353-BROKEN-CANARY"), "{text}");
        assert!(text.contains("MSB_HOME: not shown"), "{text}");
    }

    /// The other half of the rule: an unusable file with no launcher variable set
    /// names only `$HOME`-derived paths, which `doctor` prints in a dozen other
    /// rows. Withholding those would hide information and protect nothing.
    #[test]
    fn an_unparseable_credentials_file_with_home_defaults_prints_the_home_paths() {
        let _fixture = RunFixture::build(UNPARSEABLE, |_, _| {});
        let msb_home = crate::msb_install::msb_home_dir().unwrap();

        let text = run_ordinary();

        // The whole report, byte for byte, is what an unusable file without a
        // launcher variable prints — no row is withheld.
        assert!(!text.contains("not shown - credentials.yaml"), "{text}");
        assert!(
            text.contains(&format!("MSB_HOME: {}\n", crate::one_line::path(&msb_home))),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "db:       {}/db/msb.db",
                crate::one_line::path(&msb_home)
            )),
            "{text}"
        );
        assert!(
            text.contains("state:    /") && text.contains("dir:      /"),
            "{text}"
        );
    }

    /// A relative `XDG_STATE_HOME` is ignored, so it supplied no path: the row
    /// shows the `$HOME` default even while the file is unusable, naming no
    /// variable. The value never prints, at either verbosity (#353).
    #[test]
    fn an_ignored_relative_launcher_value_withholds_nothing() {
        let _fixture = RunFixture::build(UNPARSEABLE, |env, _root| {
            env.set_var("XDG_STATE_HOME", "sk-353-REL-CANARY");
        });

        let text = run_ordinary();

        assert!(!text.contains("sk-353-REL-CANARY"), "{text}");
        assert!(!text.contains("not shown - credentials.yaml"), "{text}");
        assert!(text.contains("MSB_HOME: /"), "{text}");
    }

    #[test]
    fn an_unclaimed_launcher_variable_still_prints_its_path() {
        let _fixture = RunFixture::with_launcher_variables(
            ANTHROPIC,
            Path::new("/tmp/unclaimed-state"),
            Path::new("/tmp/unclaimed-cache"),
        );

        // Not `normalize`d: the state row's own spelling is what must be unchanged.
        let text = run_ordinary();

        assert!(
            text.contains("MSB_HOME: /tmp/unclaimed-state/agent-vm/msb-home\n"),
            "{text}"
        );
        assert!(
            text.contains("db:       /tmp/unclaimed-state/agent-vm/msb-home/db/msb.db"),
            "{text}"
        );
        assert!(
            text.contains("state:    /tmp/unclaimed-state/agent-vm/"),
            "{text}"
        );
    }

    fn roots(state: RootSource, cache: RootSource) -> ActiveRoots {
        ActiveRoots { state, cache }
    }

    /// Each root must be wired to the resolver for *its own* variable, and the
    /// cache-derived row is only ever printed by a bundled build — the one shape
    /// CI never builds. This is the default build's only view of that wiring
    /// (#353 follow-up): swapping the two resolvers, hardcoding the state root
    /// for the cache row, or a `cache_root_source` that answers [`RootSource::Home`]
    /// all leave every other test in this suite passing while putting a
    /// `XDG_CACHE_HOME` value back into `unpacked:`.
    #[test]
    fn each_root_reads_the_variable_that_supplied_it() {
        let mut env = crate::test_env::guard();
        let root = tempfile::tempdir().unwrap();
        let (state, cache) = (root.path().join("state"), root.path().join("cache"));
        env.remove_var(crate::host_paths::STATE_ROOT_ENV_NAME);
        env.set_var(crate::host_paths::AGENT_VM_STATE_DIR_ENV_NAME, &state);
        env.set_var(crate::host_paths::CACHE_ROOT_ENV_NAME, &cache);

        let roots = ActiveRoots::from_env().unwrap();

        assert_eq!(roots.state, RootSource::AgentVmStateDir);
        assert_eq!(roots.cache, RootSource::XdgCacheHome);
    }

    /// An authorization file whose load fails — the only state in which a claim
    /// can exist, since the parser refuses the launcher's own names (#163).
    fn unusable() -> Result<AuthorizationSet> {
        Err(anyhow!("credentials.yaml is unusable"))
    }

    /// One row withheld for `variable`, the other shown, so a renderer's test
    /// pins which row it reads.
    fn state_withheld(variable: &'static str) -> PathRows {
        PathRows {
            state: PathRow::Withheld(variable),
            cache: PathRow::Shown,
        }
    }
    fn cache_withheld(variable: &'static str) -> PathRows {
        PathRows {
            state: PathRow::Shown,
            cache: PathRow::Withheld(variable),
        }
    }

    /// A row is withheld only when *both* facts hold: the file is unusable, and
    /// that row's path actually came from a launcher configuration variable
    /// (#353). Nothing else changes a row, so a claiming-nothing configuration
    /// prints what it printed before.
    #[test]
    fn a_row_is_withheld_only_when_the_file_is_unusable_and_a_launcher_variable_supplied_it() {
        let usable = Ok(AuthorizationSet::empty());
        // A usable file cannot claim a launcher variable (#163), so nothing is
        // withheld whatever supplied the roots.
        for source in [RootSource::AgentVmStateDir, RootSource::XdgStateHome] {
            assert_eq!(
                PathRows::from_authorizations(&usable, roots(source, RootSource::XdgCacheHome)),
                SHOWN_ROWS,
                "{source:?}"
            );
        }

        assert_eq!(
            PathRows::from_authorizations(
                &unusable(),
                roots(RootSource::AgentVmStateDir, RootSource::XdgCacheHome)
            ),
            PathRows {
                state: PathRow::Withheld(crate::host_paths::AGENT_VM_STATE_DIR_ENV_NAME),
                cache: PathRow::Withheld(crate::host_paths::CACHE_ROOT_ENV_NAME),
            }
        );
        assert_eq!(
            PathRows::from_authorizations(
                &unusable(),
                roots(RootSource::XdgStateHome, RootSource::Home)
            ),
            PathRows {
                state: PathRow::Withheld(crate::host_paths::STATE_ROOT_ENV_NAME),
                cache: PathRow::Shown,
            }
        );
        // No launcher variable supplied either root: both rows print, which is
        // the case the over-broad first version hid.
        assert_eq!(
            PathRows::from_authorizations(&unusable(), roots(RootSource::Home, RootSource::Home)),
            SHOWN_ROWS
        );
    }

    /// `$HOME` is not a name credentials parsing refuses, so a `$HOME`-derived
    /// path is never withheld — even from an unusable file.
    #[test]
    fn a_home_sourced_row_is_never_withheld() {
        assert_eq!(
            PathRow::for_root(RootSource::Home, true),
            PathRow::Shown,
            "a $HOME-derived path was withheld"
        );
        assert_eq!(
            PathRow::for_root(RootSource::AgentVmStateDir, true),
            PathRow::Withheld(crate::host_paths::AGENT_VM_STATE_DIR_ENV_NAME)
        );
    }

    #[test]
    fn a_withheld_home_row_names_the_variable_and_keeps_the_labels() {
        for (variable, expected) in [
            (
                crate::host_paths::STATE_ROOT_ENV_NAME,
                "MSB_HOME: not shown - credentials.yaml may name XDG_STATE_HOME",
            ),
            (
                crate::host_paths::AGENT_VM_STATE_DIR_ENV_NAME,
                "MSB_HOME: not shown - credentials.yaml may name AGENT_VM_STATE_DIR",
            ),
        ] {
            let text = describe_home(
                Path::new("/state/sk-353-CANARY/msb-home"),
                true,
                "m1",
                state_withheld(variable),
            );

            assert!(!text.contains("sk-353-CANARY"), "{text}");
            assert!(text.contains(expected), "{text}");
            // The existence fact and the schema row are not value-derived.
            assert!(text.contains("(exists)"), "{text}");
            assert!(text.contains("this build's bundled schema: m1"), "{text}");
        }
    }

    /// The home rows read the *state* row: a withheld cache row must not blank
    /// them, which is what a shared `PathRows` would allow.
    #[test]
    fn the_home_rows_ignore_a_withheld_cache_row() {
        let text = describe_home(
            Path::new("/state/msb-home"),
            false,
            "m1",
            cache_withheld(crate::host_paths::CACHE_ROOT_ENV_NAME),
        );

        assert!(text.contains("MSB_HOME: /state/msb-home\n"), "{text}");
        assert!(
            text.contains("db:       /state/msb-home/db/msb.db"),
            "{text}"
        );
    }

    #[test]
    fn the_embedded_runtime_row_withholds_a_claimed_cache_root() {
        let withheld = "==> embedded runtime\nunpacked: not shown - credentials.yaml may name \
             XDG_CACHE_HOME as an environment credential source (absent)";
        assert_eq!(
            describe_embedded_runtime(
                Some(Path::new("/cache/sk-353-CANARY/rt")),
                false,
                cache_withheld(crate::host_paths::CACHE_ROOT_ENV_NAME),
            ),
            withheld
        );
        // The same decision reaches this renderer in every build: a withheld
        // *state* row leaves the cache row shown, so swapping the rows cannot
        // pass by accident. Only a bundled build prints the section, which is
        // why the correspondence is pinned here rather than through `run_to`.
        assert_eq!(
            describe_embedded_runtime(
                Some(Path::new("/cache/rt")),
                false,
                state_withheld(crate::host_paths::STATE_ROOT_ENV_NAME),
            ),
            "==> embedded runtime\nunpacked: /cache/rt (absent)"
        );
    }

    #[test]
    fn the_project_state_row_withholds_a_claimed_state_root() {
        let mut r = report(vec![]);
        r.project.measured_mut().state_dir = PathBuf::from("/state/sk-353-CANARY/abc");

        let text = describe_credentials(
            &r,
            &LaunchView::default(),
            state_withheld(crate::host_paths::STATE_ROOT_ENV_NAME),
        );

        assert!(!text.contains("sk-353-CANARY"), "{text}");
        assert!(
            text.contains("state:    not shown - credentials.yaml may name XDG_STATE_HOME"),
            "{text}"
        );
        // The cwd row derives from no launcher variable, so it is still shown.
        assert!(text.contains("dir:      /p\n"), "{text}");
    }

    #[test]
    fn embedded_runtime_section_reports_path_and_presence() {
        assert_eq!(
            describe_embedded_runtime(Some(Path::new("/cache/runtime/id")), true, SHOWN_ROWS),
            "==> embedded runtime\nunpacked: /cache/runtime/id (present)"
        );
        assert_eq!(
            describe_embedded_runtime(Some(Path::new("/cache/runtime/id")), false, SHOWN_ROWS),
            "==> embedded runtime\nunpacked: /cache/runtime/id (absent)"
        );
    }
    #[test]
    fn embedded_runtime_section_reports_unresolved_root() {
        assert_eq!(
            describe_embedded_runtime(None, false, SHOWN_ROWS),
            "==> embedded runtime\nunpacked: unresolved (set XDG_CACHE_HOME or HOME)"
        );
    }

    use clap::Parser;

    fn write_file(path: &Path, contents: &[u8]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    /// A user or project config whose declared tools are authorized (#735).
    fn write_config(path: &Path, contents: impl AsRef<[u8]>) {
        write_file(path, contents.as_ref());
    }

    #[test]
    fn reset_moves_db_dir_with_all_files() {
        let home = tempfile::tempdir().unwrap();
        let db = home.path().join("db");
        write_file(&db.join("msb.db"), b"schema-bytes");
        write_file(&db.join("msb.db-wal"), b"wal-bytes");
        write_file(&db.join("msb.db-shm"), b"shm-bytes");
        write_file(&db.join("msb.db.lock"), b"lock-bytes");

        let outcome = reset_msb_db_in(home.path(), "123").unwrap();

        let expected_to = home.path().join("db.reset-123");
        assert_eq!(
            outcome,
            ResetOutcome::Moved {
                from: db.clone(),
                to: expected_to.clone(),
            }
        );
        assert!(!db.exists(), "db/ should be gone after the move");
        assert!(expected_to.is_dir());
        assert_eq!(
            std::fs::read(expected_to.join("msb.db")).unwrap(),
            b"schema-bytes"
        );
        assert_eq!(
            std::fs::read(expected_to.join("msb.db-wal")).unwrap(),
            b"wal-bytes"
        );
        assert_eq!(
            std::fs::read(expected_to.join("msb.db-shm")).unwrap(),
            b"shm-bytes"
        );
        assert_eq!(
            std::fs::read(expected_to.join("msb.db.lock")).unwrap(),
            b"lock-bytes"
        );
    }

    #[test]
    fn reset_is_reversible() {
        let home = tempfile::tempdir().unwrap();
        let db = home.path().join("db");
        write_file(&db.join("msb.db"), b"schema-bytes");

        let outcome = reset_msb_db_in(home.path(), "123").unwrap();
        let ResetOutcome::Moved { from, to } = outcome else {
            panic!("expected Moved");
        };

        std::fs::rename(&to, &from).expect("undo rename must succeed");
        assert!(from.is_dir());
        assert_eq!(std::fs::read(from.join("msb.db")).unwrap(), b"schema-bytes");
        assert!(!to.exists());
    }

    #[test]
    fn reset_noop_when_db_absent() {
        let home = tempfile::tempdir().unwrap();

        let outcome = reset_msb_db_in(home.path(), "123").unwrap();

        assert_eq!(
            outcome,
            ResetOutcome::NothingToMove {
                checked: home.path().join("db"),
            }
        );
        let entries: Vec<_> = std::fs::read_dir(home.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert!(
            entries.is_empty(),
            "no db.reset-* should have been created on no-op"
        );
    }

    #[test]
    fn reset_never_clobbers_existing_reset() {
        let home = tempfile::tempdir().unwrap();
        let pre_existing = home.path().join("db.reset-123");
        write_file(&pre_existing.join("marker"), b"do-not-touch");
        write_file(&home.path().join("db").join("msb.db"), b"fresh-db");

        let outcome = reset_msb_db_in(home.path(), "123").unwrap();

        let expected_to = home.path().join("db.reset-123.2");
        assert_eq!(
            outcome,
            ResetOutcome::Moved {
                from: home.path().join("db"),
                to: expected_to.clone(),
            }
        );
        assert_eq!(
            std::fs::read(pre_existing.join("marker")).unwrap(),
            b"do-not-touch",
            "pre-existing reset dir must be untouched"
        );
        assert_eq!(
            std::fs::read(expected_to.join("msb.db")).unwrap(),
            b"fresh-db"
        );
    }

    #[test]
    fn reset_moves_a_symlinked_db_without_touching_its_target() {
        // Unusual but possible: db/ is a symlink rather than a plain dir.
        // symlink_metadata must treat it as present (so it's still moved
        // aside, not silently skipped), and the rename must move the link
        // itself, not dereference it and move/delete the target.
        let home = tempfile::tempdir().unwrap();
        let real_target = tempfile::tempdir().unwrap();
        write_file(&real_target.path().join("msb.db"), b"real-target-bytes");

        let db = home.path().join("db");
        std::os::unix::fs::symlink(real_target.path(), &db).unwrap();

        let outcome = reset_msb_db_in(home.path(), "123").unwrap();

        let expected_to = home.path().join("db.reset-123");
        assert_eq!(
            outcome,
            ResetOutcome::Moved {
                from: db.clone(),
                to: expected_to.clone(),
            }
        );
        assert!(
            std::fs::symlink_metadata(&expected_to)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the moved entry must still be a symlink, not a dereferenced copy"
        );
        assert_eq!(
            std::fs::read_link(&expected_to).unwrap(),
            real_target.path(),
            "the moved symlink must still point at the original target"
        );
        assert!(!db.exists(), "db/ symlink should be gone from its old spot");
        assert_eq!(
            std::fs::read(real_target.path().join("msb.db")).unwrap(),
            b"real-target-bytes",
            "the symlink target's contents must be completely untouched"
        );
    }

    #[test]
    fn describe_home_names_home_db_path_and_schema_when_db_exists() {
        let text = describe_home(
            Path::new("/state/msb-home"),
            true,
            "m20260824_000001",
            SHOWN_ROWS,
        );

        assert!(text.contains("/state/msb-home"), "{text}");
        assert!(text.contains("/state/msb-home/db/msb.db"), "{text}");
        assert!(text.contains("exists"), "{text}");
        assert!(text.contains("m20260824_000001"), "{text}");
    }

    /// `doctor`'s report is read line by line, and a measured path comes from
    /// `$HOME`/XDG/the cwd — directories the user names, which may carry any
    /// byte. A newline must not end the section and leave the remainder looking
    /// like agent-vm's own output.
    #[test]
    fn a_measured_runtime_path_cannot_forge_a_section() {
        let text = describe_embedded_runtime(
            Some(Path::new("/cache/rt\nFORGED-RUNTIME")),
            true,
            SHOWN_ROWS,
        );

        assert_eq!(text.lines().count(), 2, "one title, one line: {text:?}");
        assert!(
            text.contains("/cache/rt\\x0aFORGED-RUNTIME"),
            "the measured path is escaped: {text:?}"
        );
    }

    #[test]
    fn a_measured_msb_home_cannot_forge_a_section() {
        let text = describe_home(
            Path::new("/state/m\nFORGED-HOME"),
            true,
            "m20260824_000001",
            SHOWN_ROWS,
        );

        assert_eq!(
            text.lines().count(),
            4,
            "the section's four lines: {text:?}"
        );
        assert!(
            text.contains("/state/m\\x0aFORGED-HOME"),
            "the measured home is escaped: {text:?}"
        );
        assert!(
            !text.contains("\nFORGED-HOME"),
            "the section was split: {text:?}"
        );
    }

    /// When the move fails, the error context is what reaches the user, and it
    /// names both paths. Same measured bytes, same rule.
    #[test]
    fn a_failed_reset_move_cannot_forge_a_line() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let msb_home = root.path().join("m\nFORGED-MOVE");
        std::fs::create_dir_all(msb_home.join("db")).unwrap();
        write_file(&msb_home.join("db/msb.db"), b"schema");
        // Read-only parent: the rename into it fails, which is the path whose
        // context prints both paths.
        std::fs::set_permissions(&msb_home, std::fs::Permissions::from_mode(0o500)).unwrap();

        let error = reset_msb_db_in(&msb_home, "123").unwrap_err();
        std::fs::set_permissions(&msb_home, std::fs::Permissions::from_mode(0o700)).unwrap();

        let rendered = format!("{error:#}");
        assert!(
            !rendered.lines().any(|line| line.starts_with("FORGED-MOVE")),
            "the measured path split the error: {rendered:?}"
        );
        assert!(
            rendered.contains("m\\x0aFORGED-MOVE/db ->"),
            "the source path is escaped in the context: {rendered:?}"
        );
        assert!(
            rendered.contains("m\\x0aFORGED-MOVE/db.reset-123"),
            "so is the target: {rendered:?}"
        );
    }

    /// The undo command has to stay runnable *and* keep the report one line per
    /// value. `from:`/`to:` are diagnostics, so the operand is
    /// [`crate::shell::PastedWord`] on the raw path bytes: `$'…'` is what makes
    /// an escaped `\x0a` the newline the directory actually holds rather than
    /// four characters no `mv` can find.
    #[test]
    fn the_reset_report_cannot_forge_a_line() {
        let from = PathBuf::from("/state/m\nFORGED-FROM/db");
        let to = PathBuf::from("/state/m\nFORGED-FROM/db.reset-123");
        let text = render(&ResetOutcome::Moved {
            from: from.clone(),
            to,
        });

        assert!(
            !text.lines().any(|line| line.starts_with("FORGED-FROM")),
            "the measured path forged a line: {text:?}"
        );
        // The display fields keep the one-line policy, which is not invertible.
        assert!(
            text.contains("from: /state/m\\x0aFORGED-FROM/db\n"),
            "the source diagnostic escaped its control byte: {text:?}"
        );
        assert!(
            text.contains("to:   /state/m\\x0aFORGED-FROM/db.reset-123\n"),
            "so did the target diagnostic: {text:?}"
        );
        let undo = text
            .lines()
            .find(|line| line.contains("To undo:"))
            .expect("the undo line");
        // Written out rather than counted: the target begins with the source, so a
        // `matches(prefix).count() == 2` would also accept `mv … "{to}" "{to}"`.
        let db = "$'/state/m\\x0aFORGED-FROM/db'";
        let backup = "$'/state/m\\x0aFORGED-FROM/db.reset-123'";
        let expected = format!(
            "To undo: if [ -e {db} ]; then printf 'refusing to undo: %s exists; %s was not \
             restored; move the existing db aside, then run this again\\n' {db} {backup} >&2; false; \
             else mv -- {backup} {db}; fi"
        );
        assert_eq!(undo, expected);
        // Only bash and zsh read `$'…'`, so the report says so; the note is its
        // own line, leaving the `To undo: ` line a command and nothing else.
        assert!(
            text.contains(&format!("{expected}\n(quoted for bash or zsh)")),
            "the undo command did not name its shell: {text:?}"
        );

        let nothing = render(&ResetOutcome::NothingToMove { checked: from });
        assert!(
            !nothing.lines().any(|line| line.starts_with("FORGED-FROM")),
            "the checked path forged a line: {nothing:?}"
        );
    }

    /// The operand is raw path bytes, not the `from:`/`to:` diagnostics: an
    /// invalid UTF-8 byte has no display spelling at all, so a `display()` or
    /// `to_string_lossy()` on the command path would silently encode U+FFFD.
    ///
    /// Decoded through a shell, without a filesystem — APFS refuses to create a
    /// directory with such a name, so this is where the byte property is checked
    /// on macOS, and `config_doctor::the_reset_undo_preserves_non_utf8_path_bytes`
    /// checks the same property end to end where the filesystem allows it.
    #[test]
    fn the_undo_operand_decodes_to_the_raw_path_bytes() {
        use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
        let from = PathBuf::from(std::ffi::OsString::from_vec(
            b"/state/\xff\\x0a\n\x7f-x/db".to_vec(),
        ));
        let to = PathBuf::from(std::ffi::OsString::from_vec(
            b"/state/\xff\\x0a\n\x7f-x/db.reset-123".to_vec(),
        ));
        let text = render(&ResetOutcome::Moved {
            from: from.clone(),
            to: to.clone(),
        });

        let instruction = text
            .lines()
            .find_map(|line| line.strip_prefix("To undo: "))
            .expect("the undo line");

        // The whole printed command runs, with a recording `mv` on PATH: nothing
        // holds these names (APFS will not create them here), so the guard falls
        // through to `mv`, which logs the argv it was handed instead of moving.
        let bin = tempfile::tempdir().unwrap();
        let log = bin.path().join("argv");
        let mv = bin.path().join("mv");
        write_config(
            &mv,
            "#!/bin/sh\nprintf '%s\\0' \"$@\" > \"${MV_ARGV_LOG:?}\"\n",
        );
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&mv, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = format!(
            "{}:{}",
            bin.path().display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let out = std::process::Command::new("bash")
            .env_clear()
            .env("PATH", path)
            .env("MV_ARGV_LOG", &log)
            // Own cwd: another test may run in this process and remove the one
            // Bash would otherwise inherit, which Bash reports on stderr.
            .current_dir(bin.path())
            .args(["-c", instruction])
            .output()
            .expect("bash must be on PATH for this test");
        assert!(
            out.status.success(),
            "bash rejected the undo command ({instruction}): {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.stdout.is_empty(), "the undo command wrote to stdout");
        assert!(
            out.stderr.is_empty(),
            "the undo command refused an absent destination: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let mut expected = b"--\0".to_vec();
        expected.extend_from_slice(to.as_os_str().as_bytes());
        expected.push(0);
        expected.extend_from_slice(from.as_os_str().as_bytes());
        expected.push(0);
        assert_eq!(
            std::fs::read(&log).unwrap(),
            expected,
            "undo operands were {instruction}"
        );
    }

    /// The discriminator against [`crate::config::escape_str`]: a measured path
    /// the user has to read back — and, for `--reset-msb-db`, copy — stays
    /// legible. Escaping every non-ASCII byte would print this as
    /// `/home/boger/\\xd0\\xbf...`.
    #[test]
    fn a_measured_path_with_non_ascii_is_printed_as_itself() {
        let text = describe_home(Path::new("/home/boger/проект"), false, "m1", SHOWN_ROWS);

        assert!(text.contains("/home/boger/проект"), "{text}");
        assert!(!text.contains("\\xd0"), "not byte-escaped: {text}");
    }

    /// Every site in this module that names a config file the run discovered —
    /// the tier lines, the conflict warning, the per-tier `image` rows and each
    /// resolved tool row's `source=` — renders it the same way as `dir:`/`state:`
    /// (issue #420). One non-ASCII `$HOME` and cwd, one assertion per site.
    #[test]
    fn every_config_path_site_prints_a_non_ascii_path_as_itself() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("дом");
        let project = dir.path().join("проект");
        std::fs::create_dir_all(home.join(".config/agent-vm")).unwrap();
        std::fs::create_dir_all(project.join(".agent-vm")).unwrap();
        let user = home.join(".config/agent-vm/config.toml");
        let project_file = project.join(".agent-vm/config.toml");
        write_config(
            &user,
            "image = \"ghcr.io/acme/user:1\"\n[[tools]]\nname = \"t\"\ncommand = \"t\"\n",
        );
        // `t` collides with the user tier (the project's authorization overrides
        // the user verb, and the differing definition is the conflict warning);
        // `u` exists only in the project tier (the `source=project:` row).
        write_config(
            &project_file,
            "image = \"ghcr.io/acme/project:1\"\n\
             [[tools]]\nname = \"t\"\ncommand = \"other\"\n\
             [[tools]]\nname = \"u\"\ncommand = \"u\"\n",
        );

        let (text, _, _) = describe_config(config_report(Some(&user), &project_file));

        for (site, needle) in [
            ("the user tier line", format!("{} (found", user.display())),
            (
                "the project tier line",
                format!("{} (found", project_file.display()),
            ),
            // #749: the project's definition owns the bare name, so the warning
            // names the project file first and the user file as the shadowed one.
            (
                "the conflict warning",
                format!("shadows\n         {}", user.display()),
            ),
            (
                "the project tool row",
                format!("source=project:{}", project_file.display()),
            ),
        ] {
            assert!(text.contains(&needle), "{site} lost the path: {text}");
        }
        assert!(!text.contains("\\xd0"), "byte-escaped somewhere: {text}");

        // The per-tier `image` rows belong to the boot-image section, not to
        // `describe_config`, so cover their renderer directly.
        let row = describe_configured_image(Some(&crate::config::ConfiguredImage::for_test(
            "ghcr.io/acme/app:1",
            user.clone(),
        )));
        assert!(row.contains(&user.display().to_string()), "{row}");
        assert!(!row.contains("\\xd0"), "byte-escaped: {row}");
    }

    /// The `default:` rows name the retained-default record, which the boot-image
    /// selection module owns — so those two go through the same renderer
    /// (issue #420).
    #[test]
    fn the_default_record_path_prints_a_non_ascii_path_as_itself() {
        let path = PathBuf::from("/home/boger/дом/.local/state/agent-vm/boot-image.json");

        let retained = describe_default_observation(
            &boot_image::DefaultObservation::Retained {
                reference: boot_image::ImmutableImageRef::parse(
                    "ghcr.io/acme/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                )
                .unwrap(),
                path: path.clone(),
            },
        );
        let uninitialized = describe_default_observation(
            &boot_image::DefaultObservation::Uninitialized {
                recommendation: boot_image::ImmutableImageRef::parse(
                    "ghcr.io/acme/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                )
                .unwrap(),
                path: path.clone(),
            },
        );

        for text in [retained, uninitialized] {
            assert!(text.contains(&path.display().to_string()), "{text}");
            assert!(!text.contains("\\xd0"), "byte-escaped: {text}");
        }
    }

    #[test]
    fn a_row_without_a_home_says_so() {
        let text = describe_credentials(
            &report(vec![(
                "claude",
                None,
                HostCred::Unreadable {
                    why: "no $HOME".into(),
                },
            )]),
            &LaunchView::default(),
            SHOWN_ROWS,
        );

        assert!(text.contains("claude  <no $HOME>"), "{text}");
        assert!(text.contains("UNUSABLE - no $HOME"), "{text}");
    }

    /// Both are `host_paths`/`credential_yaml` text that interpolates a measured
    /// path, and both are printed inside sections that escape their own paths.
    #[test]
    fn credential_details_cannot_forge_a_line() {
        let text = describe_credentials(
            &report(vec![(
                "claude",
                Some(PathBuf::from("/h/.claude/.credentials.json")),
                HostCred::Unreadable {
                    why: "/h\nFORGED-WHY/.claude/.credentials.json is not a regular file".into(),
                },
            )]),
            &LaunchView::default(),
            SHOWN_ROWS,
        );

        assert!(
            !text.lines().any(|line| line.starts_with("FORGED-WHY")),
            "the detail split the row: {text:?}"
        );
        assert!(text.contains("/h\\x0aFORGED-WHY"), "{text:?}");

        let launch = LaunchView {
            notes: vec![
                "/h\nFORGED-NOTE/.config/agent-vm/credentials.yaml is group-readable".into(),
            ],
            problems: vec!["/h\nFORGED-PROBLEM/.config/agent-vm/credentials.yaml: bad yaml".into()],
            ..LaunchView::default()
        };
        let text = describe_launch_view(&launch);

        assert!(
            !text
                .lines()
                .any(|line| line.starts_with("FORGED-NOTE") || line.starts_with("FORGED-PROBLEM")),
            "a note or problem split the section: {text:?}"
        );
        assert!(text.contains("/h\\x0aFORGED-NOTE"), "{text:?}");
        assert!(text.contains("/h\\x0aFORGED-PROBLEM"), "{text:?}");
    }

    #[test]
    fn measured_credential_rows_cannot_forge_a_line() {
        let text = describe_credentials(
            &report(vec![(
                "claude",
                Some(PathBuf::from(
                    "/home/b\nFORGED-ROW/.claude/.credentials.json",
                )),
                HostCred::Missing,
            )]),
            &LaunchView::default(),
            SHOWN_ROWS,
        );

        assert!(
            !text.lines().any(|line| line.starts_with("FORGED-ROW")),
            "the measured credential path forged a row: {text:?}"
        );
        assert!(
            text.contains("/home/b\\x0aFORGED-ROW/.claude/.credentials.json"),
            "the row escapes its own path: {text:?}"
        );
    }

    #[test]
    fn the_project_section_cannot_forge_a_line() {
        let mut r = report(vec![]);
        let project = r.project.measured_mut();
        project.dir = PathBuf::from("/work/pr\nFORGED-PROJECT");
        project.state_dir = PathBuf::from("/state/st\nFORGED-STATE");

        let text = describe_credentials(&r, &LaunchView::default(), SHOWN_ROWS);

        assert!(
            !text
                .lines()
                .any(|line| line.starts_with("FORGED-PROJECT") || line.starts_with("FORGED-STATE")),
            "a measured project path forged a line: {text:?}"
        );
        assert!(text.contains("/work/pr\\x0aFORGED-PROJECT"), "{text:?}");
        assert!(text.contains("/state/st\\x0aFORGED-STATE"), "{text:?}");
    }

    #[test]
    fn describe_home_reports_absent_db() {
        let text = describe_home(
            Path::new("/state/msb-home"),
            false,
            "m20260824_000001",
            SHOWN_ROWS,
        );

        assert!(text.contains("absent"), "{text}");
        assert!(!text.contains("exists"), "{text}");
    }

    #[test]
    fn render_moved_mentions_repull_and_paths() {
        let outcome = ResetOutcome::Moved {
            from: PathBuf::from("/state/msb-home/db"),
            to: PathBuf::from("/state/msb-home/db.reset-123"),
        };

        let text = render(&outcome);

        assert!(text.contains("/state/msb-home/db"));
        assert!(text.contains("/state/msb-home/db.reset-123"));
        assert!(text.contains("re-pulled"));
        assert!(text.contains("next"));
        assert!(text.contains("To undo"));
    }

    #[test]
    fn render_noop_mentions_nothing_moved() {
        let outcome = ResetOutcome::NothingToMove {
            checked: PathBuf::from("/state/msb-home/db"),
        };

        let text = render(&outcome);

        assert!(text.contains("No microsandbox db"));
        assert!(text.contains("nothing was moved"));
        assert!(text.contains("/state/msb-home/db"));
    }

    #[test]
    fn timestamp_suffix_is_stable_and_numeric() {
        let fixed = UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        assert_eq!(timestamp_suffix(fixed), "1700000000");
    }

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        args: Args,
    }

    #[test]
    fn args_parse_reset_msb_db_flag() {
        let cli = TestCli::try_parse_from(["t", "--reset-msb-db"]).unwrap();
        assert!(cli.args.reset_msb_db);

        let cli = TestCli::try_parse_from(["t"]).unwrap();
        assert!(!cli.args.reset_msb_db);
    }

    const HOUR_MS: i64 = 3_600_000;

    /// The report's own Anthropic read for a `$HOME`: no keychain candidate
    /// exists here, because a `cfg(test)` build spawns no `security` unless a
    /// test names one (#492, R12).
    fn claude_read(home: &Path) -> AnthropicHostRead {
        let mut env = crate::test_env::guard();
        env.set_var("HOME", home);
        env.remove_var("AGENT_VM_TEST_SECURITY");
        read_anthropic(ReadBudget::Launch)
    }

    /// The `claude` row for a `$HOME`, through that read.
    fn claude_row(home: &Path) -> HostCred {
        anthropic_host_cred(&claude_read(home))
    }

    /// F02: the row that is read through the two-location path is chosen by the
    /// provider table's *location* fact, for every provider and with no other
    /// input. The companion test
    /// [`each_row_reports_its_own_file_and_anthropic_is_the_two_location_one`]
    /// pins the same dispatch as a whole report over distinct real fixtures.
    #[test]
    fn only_the_provider_with_a_second_location_uses_the_two_location_row() {
        for provider in CredentialProvider::ALL {
            assert_eq!(
                has_second_location(provider),
                provider.host_keychain_service().is_some(),
                "{provider:?}"
            );
        }
        assert!(has_second_location(CredentialProvider::Anthropic));
        assert!(
            CredentialProvider::ALL
                .into_iter()
                .filter(|provider| has_second_location(*provider))
                .count()
                == 1,
            "exactly one provider has a second location today"
        );
    }

    /// F02: every row's detail comes from *its own* file, and the Anthropic row
    /// is the file location's outcome from the one shared read. A codex file that
    /// carries an `expiresAt` must still render `ok` (no expiry): that is what
    /// proves its row went through `inspect_host_cred` rather than Anthropic's
    /// cached, expiry-parsing read.
    #[test]
    fn each_row_reports_its_own_file_and_anthropic_is_the_two_location_one() {
        let mut env = crate::test_env::guard();
        let home = tempfile::tempdir().unwrap();
        env.set_var("HOME", home.path());
        env.remove_var("AGENT_VM_TEST_SECURITY");
        write_file(
            &home.path().join(".claude/.credentials.json"),
            br#"{"claudeAiOauth":{"accessToken":"CLAUDE","expiresAt":42}}"#,
        );
        // Valid JSON with an expiry of its own: still not expiry-parsed.
        write_file(
            &home.path().join(".codex/auth.json"),
            br#"{"tokens":{"access_token":"CODEX"},"expiresAt":99}"#,
        );
        // Unreadable, and a distinct reason from the others.
        write_file(
            &home.path().join(".local/share/opencode/auth.json"),
            b"not valid json {{{",
        );
        // Absent: the fourth one has no file at all.

        let report = gather_credentials(&Err(anyhow!("reading current directory: no cwd")));
        let text = describe_credentials(&report, &LaunchView::default(), SHOWN_ROWS);
        let detail = |label: &str| {
            let mut lines = text.lines();
            while let Some(line) = lines.next() {
                if line.starts_with(&format!("{label} ")) {
                    return lines
                        .next()
                        .expect("a detail line follows every row")
                        .trim()
                        .to_string();
                }
            }
            panic!("no {label} row in {text}");
        };
        // One fixed clock for the whole comparison: `gather_credentials` uses the
        // wall clock, so only the shapes are asserted here.
        assert!(detail("claude").starts_with("ok ("), "{text}");
        assert_eq!(detail("codex"), "ok", "{text}");
        assert!(
            detail("opencode").starts_with("UNUSABLE - not valid JSON: "),
            "{text}"
        );
        assert_eq!(detail("copilot"), "absent", "{text}");
        // No keychain item is reachable from a `cfg(test)` build, so the clause
        // that would prove the source is absent — and the row is byte-identical.
        assert!(!text.contains("macOS keychain"), "{text}");
    }

    #[test]
    fn a_claude_file_without_claudeaioauth_reads_as_unusable_not_ok() {
        // The exact shape capture rejects. Rendering this as "ok" would send
        // the user hunting anywhere but the file that is actually the problem.
        let dir = tempfile::tempdir().unwrap();
        write_file(
            &dir.path().join(".claude/.credentials.json"),
            br#"{"someOtherLogin":{"accessToken":"x"}}"#,
        );

        assert_eq!(
            claude_row(dir.path()),
            HostCred::Unreadable {
                why: "missing claudeAiOauth (API-key-only login?)".into()
            }
        );
    }

    #[test]
    fn a_well_formed_claude_file_reports_its_expiry_and_absent_stays_absent() {
        let dir = tempfile::tempdir().unwrap();
        write_file(
            &dir.path().join(".claude/.credentials.json"),
            br#"{"claudeAiOauth":{"accessToken":"tok","expiresAt":42}}"#,
        );
        assert_eq!(
            claude_row(dir.path()),
            HostCred::Present {
                expires_at_ms: Some(42)
            }
        );

        // No file at all: `absent`, not `unusable`.
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(claude_row(empty.path()), HostCred::Missing);
    }

    #[test]
    fn expiry_renders_both_directions() {
        assert_eq!(describe_expiry(3 * HOUR_MS, 0), "expires in 3h00m");
        assert_eq!(
            describe_expiry(3 * HOUR_MS + 22 * 60_000, 0),
            "expires in 3h22m"
        );
        assert_eq!(describe_expiry(15 * 60_000, 0), "expires in 15m");
        assert_eq!(describe_expiry(0, 15 * 60_000), "EXPIRED 15m ago");
    }

    impl ProjectCreds {
        /// The measured row, for the tests that rewrite one of its fields.
        /// A fixture that is unresolved is a test bug, not a rendered cause.
        fn measured_mut(&mut self) -> &mut MeasuredProject {
            match self {
                Self::Measured(project) => project,
                Self::Unresolved { why } => {
                    panic!("this fixture is measured, not unresolved: {why}")
                }
            }
        }
    }

    fn report(hosts: Vec<(&'static str, Option<PathBuf>, HostCred)>) -> CredReport {
        CredReport {
            hosts,
            project: ProjectCreds::Measured(MeasuredProject {
                dir: PathBuf::from("/p"),
                state_dir: PathBuf::from("/s/abc"),
                captured: vec!["claude"],
                guest_claude_placeholder: true,
                pi_credentials: PiCredentialReport::uninspected(),
            }),
            now_ms: 0,
            anthropic_keychain: None,
        }
    }

    /// A project row that could not be measured states its cause. Doctor's job
    /// is the diagnosis: an absent row without one is the bug this row exists to
    /// prevent.
    #[test]
    fn an_unresolved_project_renders_its_cause() {
        let mut unresolved = report(Vec::new());
        unresolved.project = ProjectCreds::Unresolved {
            why: "canonicalizing current directory: No such file or directory (os error 2)"
                .to_string(),
        };

        let text = describe_credentials(&unresolved, &LaunchView::default(), SHOWN_ROWS);

        assert!(
            text.contains("==> this project: <cwd could not be resolved: "),
            "{text}"
        );
        assert!(text.contains("No such file or directory"), "{text}");
    }

    #[test]
    fn render_flags_an_unusable_host_credential_and_always_names_the_host_login() {
        let text = describe_credentials(
            &report(vec![
                (
                    "claude",
                    Some(PathBuf::from("/h/.claude/.credentials.json")),
                    HostCred::Unreadable {
                        why: "not valid JSON: x".into(),
                    },
                ),
                (
                    "codex",
                    Some(PathBuf::from("/h/.codex/auth.json")),
                    HostCred::Missing,
                ),
            ]),
            &LaunchView::default(),
            SHOWN_ROWS,
        );

        assert!(text.contains("UNUSABLE - not valid JSON: x"), "{text}");
        assert!(text.contains("absent"), "{text}");
        // The whole point of the section: point at the host, and say why
        // the obvious in-VM workaround is not one.
        assert!(text.contains("claude login"), "{text}");
        assert!(
            text.contains("cannot work and fails with an OAuth 400"),
            "{text}"
        );
    }

    /// A report whose `claude` row is `state` and whose keychain clause is
    /// `keychain`. `now_ms` is the report's own clock, so the rendered spans are
    /// fixed rather than measured.
    fn anthropic_report(
        state: HostCred,
        keychain: Option<KeychainView>,
        now_ms: i64,
    ) -> CredReport {
        let mut report = report(vec![
            (
                "claude",
                Some(PathBuf::from("/h/.claude/.credentials.json")),
                state,
            ),
            (
                "codex",
                Some(PathBuf::from("/h/.codex/auth.json")),
                HostCred::Missing,
            ),
        ]);
        report.now_ms = now_ms;
        report.anthropic_keychain = keychain;
        report
    }

    /// The `claude` row's detail cell, trimmed of its label padding.
    fn claude_detail(report: &CredReport) -> String {
        let text = describe_credentials(report, &LaunchView::default(), SHOWN_ROWS);
        let mut lines = text.lines();
        while let Some(line) = lines.next() {
            if line.starts_with("claude ") {
                return lines
                    .next()
                    .expect("every row is followed by its detail line")
                    .trim()
                    .to_string();
            }
        }
        panic!("no claude row in {text}");
    }

    /// Story 5: the row names the location in use and shows what the other one
    /// holds, so the next 401 is diagnosable in one command.
    #[test]
    fn keychain_win_names_the_source_and_the_stale_file() {
        let now_ms = 61 * HOUR_MS + 31 * 60_000;
        let report = anthropic_report(
            HostCred::Present {
                expires_at_ms: Some(0),
            },
            Some(KeychainView::Won {
                expires_at_ms: Some(now_ms + 4 * HOUR_MS + 42 * 60_000),
            }),
            now_ms,
        );
        assert_eq!(
            claude_detail(&report),
            "ok (expires in 4h42m via macOS keychain; file EXPIRED 61h31m ago)"
        );

        // No credential file at all still names the keychain as the source.
        let report = anthropic_report(
            HostCred::Missing,
            Some(KeychainView::Won {
                expires_at_ms: Some(now_ms + 4 * HOUR_MS),
            }),
            now_ms,
        );
        assert_eq!(
            claude_detail(&report),
            "ok (expires in 4h00m via macOS keychain; file absent)"
        );

        // A keychain with no expiry at all.
        let report = anthropic_report(
            HostCred::Present {
                expires_at_ms: Some(now_ms + HOUR_MS),
            },
            Some(KeychainView::Won {
                expires_at_ms: None,
            }),
            now_ms,
        );
        assert_eq!(
            claude_detail(&report),
            "ok (via macOS keychain; file expires in 1h00m)"
        );
    }

    /// Story 11: the later expiry wins regardless of which location it is, and
    /// the row says so.
    #[test]
    fn file_win_names_the_older_keychain() {
        let now_ms = 2 * HOUR_MS;
        let report = anthropic_report(
            HostCred::Present {
                expires_at_ms: Some(now_ms + 3 * HOUR_MS),
            },
            Some(KeychainView::Lost {
                expires_at_ms: Some(0),
            }),
            now_ms,
        );
        assert_eq!(
            claude_detail(&report),
            "ok (expires in 3h00m via file; macOS keychain EXPIRED 2h00m ago)"
        );
    }

    /// Stories 7/8: a locked or failing keychain is reported, not hidden, and
    /// the file that is still in use stays the row's answer.
    #[test]
    fn an_unusable_keychain_is_an_explicit_clause() {
        let now_ms = HOUR_MS;
        let present = HostCred::Present {
            expires_at_ms: Some(now_ms + 3 * HOUR_MS),
        };
        let report = anthropic_report(
            present,
            Some(KeychainView::Unusable {
                why: "timed out after 5s (is the login keychain locked?)".into(),
            }),
            now_ms,
        );
        assert_eq!(
            claude_detail(&report),
            "ok (expires in 3h00m via file; macOS keychain UNUSABLE - timed out after 5s (is the login keychain locked?))"
        );

        // Nothing usable at all: the file's own reason leads, the keychain's
        // follows.
        let report = anthropic_report(
            HostCred::Missing,
            Some(KeychainView::Unusable {
                why: "`security` exited with status 36".into(),
            }),
            now_ms,
        );
        assert_eq!(
            claude_detail(&report),
            "absent; macOS keychain UNUSABLE - `security` exited with status 36"
        );
    }

    /// The keychain clause carries text from an outside process, so it must not
    /// be able to start a line — the same rule the row's path obeys.
    #[test]
    fn keychain_clause_cannot_forge_a_line() {
        let report = anthropic_report(
            HostCred::Missing,
            Some(KeychainView::Unusable {
                why: "garbage\nFORGED-ROW".into(),
            }),
            0,
        );
        let text = describe_credentials(&report, &LaunchView::default(), SHOWN_ROWS);
        assert!(!text.contains("\nFORGED"), "{text}");
        assert!(
            !text.lines().any(|line| line.starts_with("FORGED")),
            "{text}"
        );
    }

    /// F08: the headline promise — a host with no keychain item gets the row it
    /// always got — compared against **goldens re-recorded from base `e6cfa85`**,
    /// through the real acquisition path over real files.
    ///
    /// Provenance (F08/N4 of the follow-up review): the six details and the
    /// section tail below are the verbatim stdout of *base's own*
    /// `describe_credentials(&report, &LaunchView::default())` over base's
    /// `inspect_host_cred(path, true)`, with `now_ms = 1_700_000_000_000` and
    /// base's `report()` project fixture, printed by a throwaway test in a `git
    /// worktree` of `e6cfa85` (never committed; the worktree was removed after
    /// recording). They were regenerated, not transcribed: the previous round's
    /// goldens used `now_ms = 0`, under which the "expired" fixture rendered
    /// `expires in 0m` and so never exercised the EXPIRED rendering.
    ///
    /// One input is substituted rather than fixed: the fixture directory is a
    /// per-run `tempfile::tempdir()`, because a fixed `/tmp` path is shared
    /// mutable state that two concurrent test processes can delete under each
    /// other. `GOLDEN_HOME` is the literal the recording used, and it appears in
    /// exactly two places (the row's path and the not-a-regular-file reason);
    /// both are replaced with the real directory and everything else — wording,
    /// labels, indentation, whitespace, the clock — is compared byte for byte.
    ///
    /// This is what the hand-built `HostCred` table in
    /// [`no_keychain_item_is_byte_identical`] cannot catch: file reading,
    /// parsing, labels, paths, row spacing, the source clause's absence and the
    /// whole-section formatting all go through the production path here.
    #[test]
    fn the_no_keychain_row_is_byte_identical_to_the_base_commit() {
        const GOLDEN_HOME: &str = "/tmp/agent-vm-492-doctor-golden-home";
        /// The clock both sides were recorded and rendered at: a real instant, so
        /// `expiresAt` on either side of it is a future and an *expired* expiry
        /// rather than two flavours of "0m".
        const NOW_MS: i64 = 1_700_000_000_000;
        /// The tail from the first `==> this project` onward: identical for all
        /// six shapes in the recording, so it is compared once per shape.
        const GOLDEN_TAIL: &str = r#"==> this project
dir:      /p
state:    /s/abc
captured: claude
guest Claude cred file: placeholder present

==> guest-managed Pi credentials
Structural inspection of guest-managed Pi state only; agent-vm never resolves, imports, refreshes or removes it.
auth.json: not present
models.json: not present
Only auth.json and models.json are inspected (settings, sessions and installed packages are not).

For the host-captured Claude/Codex/GitHub credentials above, the guest never
receives a real token: it gets a placeholder that the TLS proxy swaps for the
host token on the way out. So sign in ON THE HOST (`claude login`,
`codex login`, `gh auth login`): running `/login` inside the VM cannot work and fails with an OAuth 400.
Pi guest-managed state is different: a credential created inside the guest
lives in the project's persistent Pi home and is reported above, not
substituted."#;

        let home = tempfile::tempdir().unwrap();
        let credentials = home.path().join(".claude/.credentials.json");
        let home_text = home.path().display().to_string();

        let shapes: [(&str, Option<&[u8]>, &str); 6] = [
            (
                "a future integer expiry",
                Some(br#"{"claudeAiOauth":{"accessToken":"tok","expiresAt":1700003600000}}"#),
                "ok (expires in 1h00m)",
            ),
            (
                "an expired integer expiry",
                Some(br#"{"claudeAiOauth":{"accessToken":"tok","expiresAt":1699996400000}}"#),
                "ok (EXPIRED 1h00m ago)",
            ),
            (
                "no expiry at all",
                Some(br#"{"claudeAiOauth":{"accessToken":"tok"}}"#),
                "ok",
            ),
            ("no credential file", None, "absent"),
            // Not JSON: the reason text is serde's, which is why the golden
            // pins it rather than a paraphrase.
            (
                "unusable JSON",
                Some(b"not valid json {{{" as &[u8]),
                "UNUSABLE - not valid JSON: expected ident at line 1 column 2",
            ),
            // A directory where the file should be: "present but unreadable" is
            // a different row from `absent`, and the path appears in the reason.
            (
                "a path that is not a regular file",
                Some(&[] as &[u8]),
                "UNUSABLE - /tmp/agent-vm-492-doctor-golden-home/.claude/.credentials.json is not a regular file",
            ),
        ];

        for (name, contents, detail) in shapes {
            match contents {
                None => {}
                // The "not a regular file" fixture is a directory; the empty
                // slice is its marker.
                Some([]) => std::fs::create_dir_all(&credentials).unwrap(),
                Some(bytes) => write_file(&credentials, bytes),
            }
            // The real acquisition path, read exactly once: `read_anthropic` is
            // the report's own read (file location, plus the `cfg(test)` guard
            // that only spawns `security` when a test names one), so a change to
            // reading or parsing shows up here, and the keychain clause beside
            // the row is derived from the same read rather than assumed absent —
            // otherwise `!contains("macOS keychain")` below could never fail.
            let read = claude_read(home.path());
            let row = anthropic_host_cred(&read);
            let mut report = report(vec![("claude", Some(credentials.clone()), row)]);
            report.now_ms = NOW_MS;
            report.anthropic_keychain = keychain_view(&read);
            let rendered = describe_credentials(&report, &LaunchView::default(), SHOWN_ROWS);

            let expected = format!(
                "==> host agent credentials\nclaude  {GOLDEN_HOME}/.claude/.credentials.json\n        {detail}\n\n{GOLDEN_TAIL}"
            );
            let expected = expected.replace(GOLDEN_HOME, &home_text);
            assert_eq!(rendered, expected, "case: {name}");
            // The source clause is Anthropic's second location and must never
            // appear without an item.
            assert!(!rendered.contains("macOS keychain"), "case: {name}");
            // Reset for the next shape. `remove_dir_all` refuses a regular file
            // (ENOTDIR) and `remove_file` refuses the directory fixture, so each
            // shape is cleared by the form that fits it — silently: a leftover
            // here would surface as the next case's wrong row, not as an error.
            let _ = std::fs::remove_file(&credentials)
                .or_else(|_| std::fs::remove_dir_all(&credentials));
        }
    }

    /// Story 6 at the *renderer*, narrowed by the operator's supersedance: these
    /// four `HostCred` shapes render as they always did. This pins wording only —
    /// the whole-section, real-file comparison against the base commit is
    /// [`the_no_keychain_row_is_byte_identical_to_the_base_commit`].
    #[test]
    fn no_keychain_item_is_byte_identical() {
        let cases = [
            (HostCred::Missing, "absent"),
            (
                HostCred::Present {
                    expires_at_ms: Some(HOUR_MS),
                },
                "ok (expires in 1h00m)",
            ),
            (
                HostCred::Present {
                    expires_at_ms: None,
                },
                "ok",
            ),
            (
                HostCred::Unreadable {
                    why: "not valid JSON: x".into(),
                },
                "UNUSABLE - not valid JSON: x",
            ),
        ];
        for (state, expected) in cases {
            let report = anthropic_report(state, None, 0);
            assert_eq!(claude_detail(&report), expected);
        }
    }

    /// The one parser changes three renderings on a host with no keychain item,
    /// all of them malformed credentials. Pinned here through the *real reader*
    /// (`claude_row`), not a file-only seam, and excluded from the byte-identity
    /// goldens in
    /// [`the_no_keychain_row_is_byte_identical_to_the_base_commit`], so a revert
    /// of the supersedance is a visible test failure rather than a silent one.
    #[test]
    fn the_shared_parser_pins_three_changed_renderings() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".claude/.credentials.json");
        let check = |contents: &str| {
            write_file(&path, contents.as_bytes());
            claude_row(dir.path())
        };

        // (a) An empty `accessToken` used to render `ok` while capture wrote it
        // and the hook refused it.
        assert_eq!(
            check(r#"{"claudeAiOauth":{"accessToken":"","expiresAt":9999999999000}}"#),
            HostCred::Unreadable {
                why: "claudeAiOauth has no accessToken".into()
            }
        );
        // (b) `expiresAt <= 0` is no expiry, which is the hook's reading.
        assert_eq!(
            check(r#"{"claudeAiOauth":{"accessToken":"t","expiresAt":0}}"#),
            HostCred::Present {
                expires_at_ms: None
            }
        );
        // (c) A float `expiresAt` renders its expiry instead of `ok`.
        assert_eq!(
            check(r#"{"claudeAiOauth":{"accessToken":"t","expiresAt":9999999999000.7}}"#),
            HostCred::Present {
                expires_at_ms: Some(9_999_999_999_000)
            }
        );
    }

    #[test]
    fn render_calls_out_a_project_with_nothing_captured() {
        let mut r = report(vec![(
            "claude",
            Some(PathBuf::from("/h/.claude/.credentials.json")),
            HostCred::Present {
                expires_at_ms: Some(HOUR_MS),
            },
        )]);
        r.project.measured_mut().captured.clear();
        r.project.measured_mut().guest_claude_placeholder = false;

        let text = describe_credentials(&r, &LaunchView::default(), SHOWN_ROWS);

        assert!(text.contains("ok (expires in 1h00m)"), "{text}");
        assert!(
            text.contains("<none> (nothing to substitute on the wire)"),
            "{text}"
        );
        assert!(text.contains("guest Claude cred file: absent"), "{text}");
    }

    // -- tool-configuration preview ---------------------------------------

    /// Build a report by loading real files: config construction is private,
    /// and a real `load` keeps the renderer test free of a duplicate schema.
    fn config_report(user: Option<&Path>, project: &Path) -> crate::config::ConfigReport {
        crate::config::load(&crate::config::ConfigPaths::for_test(
            user.map(Path::to_path_buf),
            project.to_path_buf(),
        ))
        .expect("fixture config should load")
    }

    /// A25: the persisted-reference block, and nothing new for a table without
    /// one. Every other `doctor` row is untouched, so the block is additive.
    #[test]
    fn doctor_lists_persisted_egress_references() {
        let dir = tempfile::tempdir().unwrap();
        let user = dir.path().join("config.toml");
        write_config(
            &user,
            "[[tools]]\nname = \"codex\"\ncommand = \"codex\"\nnetwork_requests = [\"api.openai.com\", \"auth.openai.com\", \"chatgpt.com\"]\n\n[egress_sets]\ncodex = [\"tcp://api.openai.com:443\", \"tcp://auth.openai.com:443\", \"tcp://chatgpt.com:443\"]\n\n[network]\nallow_egress = [\"set:codex\"]\n",
        );
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&user, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let report = config_report(Some(&user), &dir.path().join("absent.toml"));
        let (text, failure, _) = describe_config(report);
        assert!(failure.is_none(), "{text}");
        assert!(
            text.ends_with(&format!(
                "persisted egress references in \"{}\" [network]:\n  set:codex -> tcp://api.openai.com:443, tcp://auth.openai.com:443, tcp://chatgpt.com:443",
                crate::one_line::path(&user)
            )),
            "{text}"
        );

        // A `[network]` table with no reference prints nothing new.
        let other = dir.path().join("other.toml");
        write_config(
            &other,
            "[[tools]]\nname = \"codex\"\ncommand = \"codex\"\n\n[network]\nallow_egress = [\"10.0.0.5\"]\n",
        );
        std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o600)).unwrap();
        let report = config_report(Some(&other), &dir.path().join("absent.toml"));
        let (text, failure, _) = describe_config(report);
        assert!(failure.is_none(), "{text}");
        assert!(!text.contains("egress references"), "{text}");
    }

    /// A35 (i) and (iii): a persisted `set:` reference prints its flattened
    /// closure as one line, and an unreferenced set prints nothing at all.
    #[test]
    fn doctor_lists_persisted_set_references() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let user = dir.path().join("config.toml");
        write_config(
            &user,
            "[[tools]]\nname = \"codex\"\ncommand = \"codex\"\nnetwork_requests = [\"api.openai.com\"]\n\n\
             [egress_sets]\ncorp = [\"git.corp.example\", \"tcp://registry.corp.example:8443\", \"10.0.0.5\"]\n\
             codex = [\"tcp://api.openai.com:443\"]\n\
             agents = [\"set:codex\", \"set:corp\"]\n\
             unused = [\"10.9.9.9\"]\n\n\
             [network]\nallow_egress = [\"set:agents\"]\n",
        );
        std::fs::set_permissions(&user, std::fs::Permissions::from_mode(0o600)).unwrap();
        let report = config_report(Some(&user), &dir.path().join("absent.toml"));
        let (text, failure, _) = describe_config(report);
        assert!(failure.is_none(), "{text}");
        assert!(
            text.ends_with(&format!(
                "persisted egress references in \"{}\" [network]:\n  set:agents -> tcp://api.openai.com:443, git.corp.example, tcp://registry.corp.example:8443, 10.0.0.5/32",
                crate::one_line::path(&user)
            )),
            "{text}"
        );
        // The nested set is flattened into the entry-level line, never listed as
        // its own reference, and an unused definition adds nothing.
        assert!(!text.contains("set:corp ->"), "{text}");
        assert!(!text.contains("unused ->"), "{text}");
        assert!(!text.contains("10.9.9.9"), "{text}");
    }

    /// A35 (ii): the 64-item cap and its `+N more` suffix hold for a set's
    /// expansion too, because the cap is the renderer's, not the reference kind's.
    #[test]
    fn doctor_caps_a_large_set_expansion() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let user = dir.path().join("config.toml");
        let literals: Vec<String> = (0..65).map(|i| format!("\"10.0.0.{i}\"")).collect();
        write_config(
            &user,
            format!(
                "[egress_sets]\nbig = [{}]\n\n[network]\nallow_egress = [\"set:big\"]\n",
                literals.join(", ")
            ),
        );
        std::fs::set_permissions(&user, std::fs::Permissions::from_mode(0o600)).unwrap();
        let report = config_report(Some(&user), &dir.path().join("absent.toml"));
        let (text, failure, _) = describe_config(report);
        assert!(failure.is_none(), "{text}");
        let line = text
            .lines()
            .find(|line| line.trim_start().starts_with("set:big -> "))
            .unwrap_or_else(|| panic!("no set:big line in {text}"));
        // The whole ordered line, written out independently: the first 64 items in
        // declaration order, then the suffix. Counting items and checking a tail
        // would pass for any order, and for a cap that dropped a different 64.
        let expected = format!(
            "  set:big -> {}, +1 more",
            (0..64)
                .map(|i| format!("10.0.0.{i}/32"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        assert_eq!(line, expected);
    }

    #[test]
    fn describe_config_lists_defaults_in_order_and_shows_argument_counts_only() {
        let dir = tempfile::tempdir().unwrap();
        let report = config_report(None, &dir.path().join("absent.toml"));

        let (text, _, _) = describe_config(report);

        // The verb list is authoritative now; the header must not claim it is
        // "diagnostic only" (the pre-#82 wording), and the default catalog
        // declares `shell`, so no fallback note appears.
        assert!(text.starts_with("==> tool configuration\n"), "{text}");
        assert!(!text.contains("diagnostic only"), "{text}");
        assert!(!text.contains("was not declared"), "{text}");
        assert!(text.contains("<no HOME; user tier unavailable>"), "{text}");
        assert!(text.contains("built-in defaults"), "{text}");

        let dsh = text.find("1. dsh").expect("dsh row");
        let pi = text.find("2. pi").expect("pi row");
        let codex = text.find("3. codex").expect("codex row");
        let opencode = text.find("4. opencode").expect("opencode row");
        let claude = text.find("5. claude").expect("claude row");
        assert!(
            dsh < pi && pi < codex && codex < opencode && opencode < claude,
            "{text}"
        );

        assert!(
            text.contains(
                "dsh -> \"dsh\"; args=1; credentials=none; provisions=none; persist=1; source=built-in"
            ),
            "{text}"
        );

        // `pi` is the shipped catalog's one verb whose requirement and
        // provisioning sets differ: `tools = ["claude", "codex"]` provisions
        // anthropic and openai without requiring either, so the row is the
        // visible proof that naming a tool never inherits its hard bail.
        // Rendered as `credentials=none; provisions=anthropic,openai`
        // (ADR-0017's `provisions=` column).
        assert!(
            text.contains(
                "pi -> \"pi\"; args=0; credentials=antigravity; provisions=anthropic,openai,antigravity; persist=0; source=built-in"
            ),
            "{text}"
        );

        assert!(
            text.contains(
                "shell -> \"bash\"; args=2; credentials=none; provisions=anthropic,openai,opencode-static,copilot,antigravity; persist=1 (own 0); source=built-in; interactive_shell=true; env=1"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "codex -> \"codex\"; args=0; credentials=openai; provisions=openai; persist=0; source=built-in; env=1"
            ),
            "{text}"
        );
        assert!(text.contains("claude -> \"claude\"; args=1;"), "{text}");
        // `claude` declares no `env`, so its row must have no env suffix —
        // no `; env=0` suffix. V7 (D6/D7).
        assert!(
            !text.contains(
                "claude -> \"claude\"; args=1; credentials=anthropic; provisions=anthropic; persist=0; source=built-in; env"
            ),
            "{text}"
        );
    }

    /// **V7 (D6).** An `env` *value* is never rendered — only its count is —
    /// so a credential a user pasted into `env` cannot leak through `doctor`.
    /// The suffix renders only when nonzero, and goes after `interactive_shell`.
    ///
    /// The tool is named `vault`, not `secret`: `secret` became a reserved
    /// built-in name in #160, and the point of this fixture is the env-value
    /// redaction, not the name.
    #[test]
    fn describe_tool_shows_only_the_env_count_never_a_value() {
        let dir = tempfile::tempdir().unwrap();
        let user = dir.path().join("user.toml");
        write_config(
            &user,
            "[[tools]]\nname = \"vault\"\ncommand = \"vault\"\nenv = { TOKEN = \"sk-secret\" }\n",
        );
        let report = config_report(Some(&user), &dir.path().join("absent.toml"));

        let (text, _, _) = describe_config(report);
        assert!(
            text.contains(
                "vault -> \"vault\"; args=0; credentials=none; provisions=none; persist=0; source=user:"
            ),
            "{text}"
        );
        assert!(text.contains("; env=1"), "{text}");
        assert!(!text.contains("sk-secret"), "env value leaked: {text}");
    }

    /// #749 E8/V4: a tool whose declaring read failed still loads, but every
    /// launch refuses it. `doctor` must mark it unavailable with the same
    /// sentence the launch prints, or the listing advertises a verb that cannot
    /// run. The shell affordance carries the blocked *contributor's* verdict, so
    /// it is marked too.
    #[test]
    fn describe_config_marks_a_blocked_tool_unavailable_with_the_launch_reason() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let project = dir.path().join("project.toml");
        write_config(&project, "default_tools = [\"helper\"]\n");
        let body = "[[tools]]\nname = \"helper\"\ncommand = \"helper\"\n";

        let target = dir.path().join("dotfile.toml");
        write_config(&target, body);
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        let user = dir.path().join("config.toml");
        std::os::unix::fs::symlink(&target, &user).unwrap();

        let report = config_report(Some(&user), &project);
        let (text, failure, catalog) = describe_config(report);
        assert!(failure.is_none(), "{text}");
        let catalog = catalog.expect("the catalog builds");
        for label in ["helper", "shell"] {
            let entry = catalog
                .as_slice()
                .iter()
                .find(|entry| entry.label() == label)
                .unwrap_or_else(|| panic!("{label} row missing: {text}"));
            let trust = entry
                .launch_trust()
                .expect("the blocked read's verdict travels with the entry");
            let note = launch_refusal_note(trust)
                .unwrap_or_else(|| panic!("{label} is not marked refused: {text}"));
            let row = text
                .lines()
                .find(|line| line.contains(&format!(". {label} -> ")))
                .unwrap_or_else(|| panic!("{label} row missing: {text}"));
            assert!(
                row.contains(&format!("; {note}")),
                "{label} row does not carry the launch refusal: {row}"
            );
        }

        // The positive control: the same declarations from a regular file load
        // with no verdict and no marker.
        let regular = dir.path().join("regular.toml");
        write_config(&regular, body);
        std::fs::set_permissions(&regular, std::fs::Permissions::from_mode(0o600)).unwrap();
        let (text, failure, catalog) = describe_config(config_report(Some(&regular), &project));
        assert!(failure.is_none(), "{text}");
        assert!(!text.contains("unavailable:"), "{text}");
        assert!(
            catalog
                .expect("the catalog builds")
                .as_slice()
                .iter()
                .all(|entry| entry.launch_trust().and_then(launch_refusal_note).is_none())
        );
    }

    #[test]
    fn describe_config_distinguishes_a_found_empty_tier_from_an_absent_one() {
        let dir = tempfile::tempdir().unwrap();
        let user = dir.path().join("user.toml");
        write_config(&user, "");
        let report = config_report(Some(&user), &dir.path().join("absent.toml"));

        let (text, _, _) = describe_config(report);
        assert!(text.contains("(found, 0 tools)"), "{text}");
        assert!(text.contains("(absent)"), "{text}");
        // The default catalog declares `shell`, so the fallback does not fire.
        assert!(!text.contains("was not declared"), "{text}");
    }

    /// A one-tool catalog gains the built-in `shell` fallback row and the note
    /// that explains it, so `doctor`'s numbering matches `--help`.
    #[test]
    fn describe_config_labels_the_shell_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let user = dir.path().join("user.toml");
        write_config(&user, "[[tools]]\nname = \"solo\"\ncommand = \"solo\"\n");
        let report = config_report(Some(&user), &dir.path().join("absent.toml"));

        let (text, _, _) = describe_config(report);
        assert!(text.contains("1. solo"), "{text}");
        assert!(text.contains("2. shell"), "{text}");
        assert!(
            text.contains("the bare `shell` verb is the built-in fallback"),
            "{text}"
        );
    }

    #[test]
    fn describe_config_names_differing_fields_but_never_argument_values() {
        let dir = tempfile::tempdir().unwrap();
        let user = dir.path().join("user.toml");
        let project = dir.path().join("project.toml");
        write_config(
            &user,
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\nargs = [\"--token=SENTINEL\"]\n",
        );
        write_config(
            &project,
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\nargs = [\"other\"]\n",
        );
        let report = config_report(Some(&user), &project);

        let (text, _, _) = describe_config(report);
        assert!(text.contains("shadows"), "{text}");
        assert!(text.contains("tool \"t\" in"), "{text}");
        assert!(text.contains("differing fields: args"), "{text}");
        assert!(!text.contains("SENTINEL"), "argument value leaked: {text}");
    }

    #[test]
    fn describe_config_escapes_control_bytes_in_a_config_path() {
        let dir = tempfile::tempdir().unwrap();
        let evil = dir.path().join("user\x1b[31m\nname");
        std::fs::create_dir_all(&evil).unwrap();
        let user = evil.join("config.toml");
        write_config(&user, "");
        let report = config_report(Some(&user), &dir.path().join("absent.toml"));

        let (text, _, _) = describe_config(report);
        assert!(!text.contains('\x1b'), "raw ESC leaked: {text:?}");
        assert!(text.contains("\\x1b"), "ESC should be escaped: {text:?}");
        assert!(
            text.contains("\\x0a"),
            "newline should be escaped: {text:?}"
        );
    }

    /// A *resolved row* is not only paths: `command` accepts every byte except
    /// NUL, so it too can carry terminal controls and is escaped, so a hostile
    /// project config cannot inject an ANSI escape or split the report with a
    /// newline.
    #[test]
    fn describe_config_escapes_control_bytes_in_a_command() {
        let dir = tempfile::tempdir().unwrap();
        let user = dir.path().join("user.toml");
        write_config(
            &user,
            "[[tools]]\nname = \"t\"\ncommand = \"evil\\u001b[31m\\nred\"\n",
        );
        let report = config_report(Some(&user), &dir.path().join("absent.toml"));

        let (text, _, _) = describe_config(report);
        assert!(!text.contains('\x1b'), "raw ESC leaked: {text:?}");
        assert!(
            !text.contains("red\n"),
            "raw newline from the command leaked: {text:?}"
        );
        assert!(text.contains("evil\\x1b[31m\\x0ared"), "{text}");
    }

    // -- #178: the launch-aware credential view ----------------------------

    /// Write a `credentials.yaml` in a fresh `$HOME` and load it, mirroring
    /// `credential_resolver`'s fixture so the two test suites agree on the
    /// file grammar and its mode/ownership rules.
    fn authorizations(body: &str) -> (tempfile::TempDir, AuthorizationSet) {
        use std::os::unix::fs::PermissionsExt as _;
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join(crate::config::USER_CONFIG_DIR_RELATIVE);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join(crate::credential_yaml::CREDENTIALS_FILE_NAME);
        write_config(&path, body);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let set = crate::credential_yaml::load(home.path()).expect("the fixture loads");
        (home, set)
    }

    /// The shipped catalog (all seven verbs), so a launch-selection test does
    /// not depend on a real project directory.
    fn default_catalog() -> LaunchCatalog {
        let dir = tempfile::tempdir().unwrap();
        config_report(None, &dir.path().join("absent.toml"))
            .into_launch_catalog()
            .expect("the default catalog builds")
    }

    /// A same-named authorization for the built-in `anthropic`, which the
    /// `claude` and `pi` verbs request.
    const ANTHROPIC: &str = "\
credentials:
  - service: anthropic
    required: true
    apiKey:
      name: ANTHROPIC_API_KEY
      sentinelEnv: true
      inject: [{domain: api.anthropic.example, header: x-api-key, format: \"%s\"}]
";

    #[test]
    fn launch_selection_names_the_verbs_that_replace_a_built_in() {
        let (_home, set) = authorizations(ANTHROPIC);

        let selection = launch_selection(&default_catalog(), &set);

        // `anthropic` becomes doctor's `claude` row. `pi` (via `tools =
        // ["claude"]`), `claude` (its own `credentials`) and `shell` (via its
        // wildcard `tools`) all request it, so each replaces the host file — in
        // catalog order.
        assert_eq!(
            selection.replaced.get("claude").map(Vec::as_slice),
            Some(&["pi".to_string(), "claude".to_string(), "shell".to_string()][..]),
        );
        assert_eq!(
            selection
                .requested
                .iter()
                .map(ServiceName::as_str)
                .collect::<Vec<_>>(),
            vec!["anthropic"]
        );
        assert!(selection.unrequested.is_empty(), "{selection:?}");
    }

    #[test]
    fn launch_selection_ignores_an_inert_authorization_and_flags_an_unrequested_provider() {
        // `solo` requests nothing, so no built-in is requested and the
        // authorized `anthropic` is inert.
        let dir = tempfile::tempdir().unwrap();
        let user = dir.path().join("user.toml");
        write_config(&user, "[[tools]]\nname = \"solo\"\ncommand = \"solo\"\n");
        let catalog = config_report(Some(&user), &dir.path().join("absent.toml"))
            .into_launch_catalog()
            .expect("the one-tool catalog builds");
        let (_home, set) = authorizations(ANTHROPIC);

        let selection = launch_selection(&catalog, &set);

        assert!(selection.replaced.is_empty(), "{selection:?}");
        assert!(selection.requested.is_empty(), "{selection:?}");
        assert_eq!(
            selection.unrequested,
            vec!["claude", "codex", "opencode", "copilot", "pi"]
        );
    }

    /// A requested authorization may be a YAML-only service *or* a built-in, and
    /// an authorization no verb requests stays inert. This is the independent
    /// oracle for the whole feature: one tool requesting three names, only two
    /// of which are authorized.
    #[test]
    fn launch_selection_reports_requested_authorized_names_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let user = dir.path().join("user.toml");
        write_config(
            &user,
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\n\
             credentials = [\"alpha\", \"anthropic\", \"gamma\"]\n",
        );
        let catalog = config_report(Some(&user), &dir.path().join("absent.toml"))
            .into_launch_catalog()
            .expect("the one-tool catalog builds");
        // `alpha` and `anthropic` are authorized; `gamma` is only requested.
        let (_home, set) = authorizations(
            "credentials:\n  - service: alpha\n    apiKey:\n      name: A\n      \
             inject: [{domain: a.example, header: x-a, format: \"%s\"}]\n  \
             - service: anthropic\n    apiKey:\n      name: ANTHROPIC_API_KEY\n      \
             inject: [{domain: b.example, header: x-b, format: \"%s\"}]\n",
        );

        let selection = launch_selection(&catalog, &set);

        assert_eq!(
            selection
                .requested
                .iter()
                .map(ServiceName::as_str)
                .collect::<Vec<_>>(),
            vec!["alpha", "anthropic"]
        );
        assert_eq!(
            selection.replaced.get("claude").map(Vec::as_slice),
            Some(&["t".to_string()][..]),
        );
        // `t` requests every provider the default catalog does not; the other
        // three are unrequested.
        assert_eq!(
            selection.unrequested,
            vec!["codex", "opencode", "copilot", "pi"]
        );
    }

    /// A validated `secretspec:` selection, built through the real parser so a
    /// doctor test cannot assert a row for a table the loader would refuse.
    fn secretspec_selection(
        manifest: &str,
        scope: Option<&str>,
    ) -> crate::credential_yaml::SourceSelection {
        let mut table = serde_json::Map::new();
        table.insert("executable".into(), "/opt/secretspec".into());
        table.insert("manifest".into(), manifest.into());
        table.insert("profile".into(), "work/team".into());
        if let Some(scope) = scope {
            table.insert("scope".into(), scope.into());
        }
        table.insert("name".into(), "DEEPSEEK_API_KEY".into());
        crate::credential_yaml::SourceSelection::Secretspec(
            crate::credential_secretspec::config::parse_table(
                &table,
                &GuestEnvName::parse("DEFAULT_KEY").unwrap(),
            )
            .expect("the fixture table validates"),
        )
    }

    #[test]
    fn describe_launch_view_names_each_requested_authorization_and_never_a_value() {
        let view = LaunchView {
            yaml: vec![
                YamlRow {
                    service: "alpha".into(),
                    replaces_builtin: false,
                    source: SourceSelection::Keychain,
                    env_name: GuestEnvName::parse("ALPHA_KEY").unwrap(),
                },
                YamlRow {
                    service: "anthropic".into(),
                    replaces_builtin: true,
                    source: SourceSelection::Keychain,
                    env_name: GuestEnvName::parse("ANTHROPIC_API_KEY").unwrap(),
                },
                YamlRow {
                    service: "env".into(),
                    replaces_builtin: false,
                    source: SourceSelection::Environment,
                    env_name: GuestEnvName::parse("MY_KEY").unwrap(),
                },
                YamlRow {
                    service: "spec-scoped".into(),
                    replaces_builtin: false,
                    source: secretspec_selection("/home/u/secretspec.toml", Some("agent-vm")),
                    env_name: GuestEnvName::parse("DEEPSEEK_API_KEY").unwrap(),
                },
                YamlRow {
                    service: "spec".into(),
                    replaces_builtin: false,
                    source: secretspec_selection("/home/u/other.toml", None),
                    env_name: GuestEnvName::parse("OTHER_KEY").unwrap(),
                },
            ],
            ..LaunchView::default()
        };

        let text = describe_launch_view(&view);

        // Rows are compared by their *text*, not their padding: the column
        // width follows the longest service name, which is not the assertion.
        let what = |service: &str| -> String {
            text.lines()
                .find(|line| {
                    // Exact service prefix, so `spec` does not match `spec-scoped`.
                    line.starts_with(service) && line[service.len()..].starts_with(' ')
                })
                .unwrap_or_else(|| panic!("no row for {service}: {text}"))
                .trim_start_matches(service)
                .trim_start()
                .to_owned()
        };

        assert!(
            text.starts_with("==> credentials.yaml (launch credentials)\n"),
            "{text}"
        );
        assert_eq!(what("alpha"), "authorized for this launch");
        assert_eq!(
            what("anthropic"),
            "authorized for this launch (replaces the host built-in)"
        );
        assert_eq!(
            what("env"),
            "authorized for this launch from the host environment (`MY_KEY`)"
        );
        // The scope form and the scope-free form, verbatim. `reason` is never
        // printed: it is the one free-form field and doctor has no use for it.
        assert_eq!(
            what("spec-scoped"),
            "authorized for this launch from SecretSpec (`DEEPSEEK_API_KEY`, profile \
             `work/team`, scope `agent-vm`, manifest /home/u/secretspec.toml, executable \
             /opt/secretspec)"
        );
        assert_eq!(
            what("spec"),
            "authorized for this launch from SecretSpec (`DEEPSEEK_API_KEY`, profile \
             `work/team`, manifest /home/u/other.toml, executable /opt/secretspec)"
        );
        assert!(
            text.contains("`agent-vm secret ls` reports whether a value is stored"),
            "{text}"
        );
        assert!(
            text.contains("environment values are read by the launch, not by doctor"),
            "{text}"
        );
        assert!(
            text.contains(
                "note: SecretSpec values are resolved by the launch (`secretspec serve \
                 --read-only`), not by doctor."
            ),
            "{text}"
        );
        assert!(!text.contains("sk-CANARY"));
        // One row per authorization, and one note per source kind present.
        assert_eq!(
            text.lines()
                .filter(|line| line.starts_with("note: "))
                .count(),
            3
        );
    }

    /// A `$HOME`-derived path and a user-typed scope both land in one line: the
    /// manifest is escaped by `one_line::path`, the labels are refused at load
    /// time if they contain a control character.
    #[test]
    fn a_secretspec_manifest_path_is_escaped_in_doctor() {
        let view = LaunchView {
            yaml: vec![YamlRow {
                service: "spec".into(),
                replaces_builtin: false,
                source: secretspec_selection("/home/u/odd\nname/secretspec.toml", None),
                env_name: GuestEnvName::parse("DEFAULT_KEY").unwrap(),
            }],
            ..LaunchView::default()
        };
        let text = describe_launch_view(&view);
        assert_eq!(
            text.lines()
                .filter(|line| line.starts_with("spec "))
                .count(),
            1,
            "the row must stay one line: {text}"
        );
        assert!(
            text.contains("/home/u/odd\\x0aname/secretspec.toml"),
            "{text}"
        );
        assert!(!text.contains("odd\nname"), "{text}");
    }

    #[test]
    fn describe_launch_view_prints_warnings_and_errors_and_empty_is_silent() {
        let view = LaunchView {
            notes: vec!["the file is group-readable".into()],
            problems: vec!["credentials.yaml could not be read".into()],
            ..LaunchView::default()
        };

        let text = describe_launch_view(&view);

        assert!(
            text.contains("warning: the file is group-readable"),
            "{text}"
        );
        assert!(
            text.contains("error: credentials.yaml could not be read"),
            "{text}"
        );
        assert!(!view.is_empty());
        assert!(LaunchView::default().is_empty());
    }

    #[test]
    fn describe_credentials_annotates_a_replaced_and_an_unrequested_provider() {
        let mut launch = LaunchView::default();
        launch
            .replaced
            .insert("claude", vec!["claude".into(), "pi".into()]);
        launch.unrequested.push("copilot");

        let text = describe_credentials(
            &report(vec![
                (
                    "claude",
                    Some(PathBuf::from("/h/.claude/.credentials.json")),
                    HostCred::Missing,
                ),
                (
                    "copilot",
                    Some(PathBuf::from("/h/.copilot/config.json")),
                    HostCred::Missing,
                ),
            ]),
            &launch,
            SHOWN_ROWS,
        );

        assert!(
            text.contains(
                "absent - replaced by credentials.yaml for claude, pi (host file not read)"
            ),
            "{text}"
        );
        assert!(
            text.contains("absent - not requested by any configured launch"),
            "{text}"
        );
    }
    #[test]
    fn shipped_default_network_requests_doctor_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let (text, _, _) = describe_config(config_report(None, &dir.path().join("absent.toml")));
        let expected = [
            ("dsh", ""),
            (
                "pi",
                "api.anthropic.com,auth.openai.com,chatgpt.com,cloudcode-pa.googleapis.com,daily-cloudcode-pa.googleapis.com,daily-cloudcode-pa.sandbox.googleapis.com,mcp-proxy.anthropic.com,oauth2.googleapis.com,+2 more",
            ),
            ("codex", "api.openai.com,auth.openai.com,chatgpt.com"),
            (
                "opencode",
                "api.openai.com,auth.openai.com,chatgpt.com,models.opencode.ai",
            ),
            (
                "claude",
                "api.anthropic.com,mcp-proxy.anthropic.com,platform.claude.com",
            ),
            ("copilot", ""),
            ("shell", ""),
        ];
        let baseline_rows = [
            "dsh -> \"dsh\"; args=1; credentials=none; provisions=none; persist=1; source=built-in",
            "pi -> \"pi\"; args=0; credentials=antigravity; provisions=anthropic,openai,antigravity; persist=0; source=built-in",
            "codex -> \"codex\"; args=0; credentials=openai; provisions=openai; persist=0; source=built-in; env=1",
            "opencode -> \"opencode\"; args=0; credentials=openai,opencode-static; provisions=openai,opencode-static; persist=0; source=built-in",
            "claude -> \"claude\"; args=1; credentials=anthropic; provisions=anthropic; persist=0; source=built-in",
            "copilot -> \"copilot\"; args=1; credentials=copilot; provisions=copilot; persist=0; source=built-in",
            "shell -> \"bash\"; args=2; credentials=none; provisions=anthropic,openai,opencode-static,copilot,antigravity; persist=1 (own 0); source=built-in; interactive_shell=true; env=1",
        ];
        for (i, (name, names)) in expected.into_iter().enumerate() {
            let row = text
                .lines()
                .find(|line| line.contains(&format!("{}. {name} ->", i + 1)))
                .unwrap();
            let unchanged = row
                .split_once(". ")
                .unwrap()
                .1
                .split("; network_requests=")
                .next()
                .unwrap();
            assert_eq!(unchanged, baseline_rows[i]);
            if names.is_empty() {
                assert!(!row.contains("network_requests"), "{row}");
            } else {
                assert!(
                    row.ends_with(&format!("; network_requests={names}")),
                    "{row}"
                );
            }
        }
    }

    #[test]
    fn network_requests_doctor_bounded_metadata_and_conflict() {
        let dir = tempfile::tempdir().unwrap();
        let user = dir.path().join("user.toml");
        let project = dir.path().join("project.toml");
        let base = "[[tools]]\nname = \"t\"\ncommand = \"t\"\n";
        write_config(
            &user,
            format!("{base}network_requests = [\"b.example:8443\",\"a.example\"]\n"),
        );
        // The rendered row is the catalog's: `describe_tool` takes the resolved
        // entry, so every assertion here reads the launch verb the user sees.
        let describe = |user: &std::path::Path, project: &std::path::Path| {
            let mut catalog = config_report(Some(user), project)
                .into_launch_catalog()
                .expect("one launch winner");
            describe_tool(&catalog.take_entry("t").expect("`t` is a verb"))
        };
        assert!(
            describe(&user, &project)
                .ends_with("; network_requests=a.example,tcp://b.example:8443")
        );
        let names: Vec<_> = (0..9).map(|i| format!("\"n{i}.example\"")).collect();
        write_config(
            &user,
            format!("{base}network_requests = [{}]\n", names.join(",")),
        );
        assert!(describe(&user, &project).ends_with("; network_requests=n0.example,n1.example,n2.example,n3.example,n4.example,n5.example,n6.example,n7.example,+1 more"));
        // The project's authorization overrides the user verb; its definition is
        // the one rendered from here on.
        write_config(
            &project,
            format!("{base}network_requests = [\"b.example:8443\",\"a.example\"]\n"),
        );
        assert!(
            describe_config(config_report(Some(&user), &project))
                .0
                .contains("differing fields: network_requests")
        );
        // The project's definition is the winner, so the sentinel goes there.
        write_config(
            &project,
            format!("{base}network_requests = [\"sk-test-sensitivevalue\"]\n"),
        );
        let row = describe(&user, &project);
        assert!(row.ends_with("; network_requests=sk-test-sensitivevalue"));
        assert_eq!(row.matches("sk-test-sensitivevalue").count(), 1);
    }

    // -- sources (ADR-0074, V18) -------------------------------------------

    /// A captured host-managed store, so the ADR-0073 route and the ADR-0074
    /// `:trust` route checks run for real (the `for_test` fixtures are
    /// `Uncaptured` and would hit E13 on a listed `sources`).
    struct SourcesDoctor {
        _root: tempfile::TempDir,
        home: PathBuf,
        project: ProjectDir,
        config: PathBuf,
    }

    impl SourcesDoctor {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let base = root.path().canonicalize().unwrap();
            let home = base.join("home");
            let checkout = base.join("checkout");
            std::fs::create_dir_all(&home).unwrap();
            std::fs::create_dir_all(&checkout).unwrap();
            let project = ProjectDir::from_path_for_tests(&checkout).unwrap();
            let config = crate::project_config::path(&home, &project);
            Self {
                _root: root,
                home,
                project,
                config,
            }
        }

        fn user_config(&self) -> PathBuf {
            self.home.join(".config/agent-vm/config.toml")
        }

        fn repo(&self, relative: &str) -> PathBuf {
            self.project.path().join(relative)
        }

        /// Write one fixture file verbatim. A grant belongs in the project body
        /// these tests write themselves: a sourced file's top-level authority
        /// fields are inert (ADR-0076 R3).
        fn write(&self, path: &Path, body: &str) {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            write_file(path, body.as_bytes());
        }

        /// Write the project config into a `0700` store directory, then load.
        fn load(&self, project_body: &str, user_body: &str, repo_body: &str) -> ConfigReport {
            self.write(&self.user_config(), user_body);
            self.write(&self.repo(".agent-vm/config.toml"), repo_body);
            std::fs::create_dir_all(self.config.parent().unwrap()).unwrap();
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(
                self.config.parent().unwrap(),
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            self.write(&self.config, project_body);
            let paths = crate::config::ConfigPaths {
                user: Some(self.user_config()),
                project: Some(crate::project_config::ProjectTierPaths {
                    config: self.config.clone(),
                    route: crate::project_config::RouteAnchor::Captured {
                        home: self.home.clone(),
                        root: self.project.path().to_path_buf(),
                        root_id: self.project.identity(),
                    },
                }),
                home: Some(self.home.clone()),
            };
            crate::config::approve_all_pinned(&paths);
            crate::config::load(&paths).expect("fixture config loads")
        }
    }

    /// V18: `describe_config` renders the source list and the `sourced:` label,
    /// distinctly from an unsourced user tier and an empty list.
    #[test]
    fn v18_describe_config_renders_sources_and_a_not_sourced_user_tier() {
        let f = SourcesDoctor::new();
        let report = f.load(
            "\
             [[sources]]\nname = \"home\"\npath = \"~/.config/agent-vm/config.toml\"\ntrust = true\n\
             [[sources]]\nname = \"repo\"\npath = \"./.agent-vm/config.toml\"\n",
            "[[tools]]\nname = \"home-tool\"\ncommand = \"home-tool\"\n",
            "[[tools]]\nname = \"repo-tool\"\ncommand = \"repo-tool\"\n",
        );
        let user = f.user_config();
        let repo = f.repo(".agent-vm/config.toml");
        // The fixture approves the source's pin before loading, so the one source
        // block carries the pin clause (D4) and the trusted row does not.
        let approved = crate::config_pins::ContentHash::of(&std::fs::read(&repo).unwrap());
        let (text, failure, catalog) = describe_config(report);
        assert!(failure.is_none(), "{text}");
        assert!(catalog.is_some());
        assert!(
            text.contains(&format!(
                "sources:\n  home {} (found, 1 tool) [trust=true, allow=false]\n  repo {} (found, 1 tool) [trust=false, allow=false, pin=approved {approved}]\n",
                user.display(),
                repo.display()
            )),
            "{text}"
        );
        assert!(
            text.contains(&format!("source=sourced:repo:{}", repo.display())),
            "{text}"
        );

        // `sources = []`: nothing is sourced and the user row says so.
        let f = SourcesDoctor::new();
        let report = f.load(
            "sources = []\n",
            "[[tools]]\nname = \"home-tool\"\ncommand = \"home-tool\"\n",
            "",
        );
        let (text, _, _) = describe_config(report);
        assert!(text.contains("sources: none\n"), "{text}");
        assert!(
            text.contains(&format!(
                "user:    {} (not sourced by the project config)",
                f.user_config().display()
            )),
            "{text}"
        );
    }

    /// V36/D4: the pin is a clause of #748's one source block, before any
    /// `; inert:` clause. A trusted source is never pinned at all, and an
    /// approved `allow = false` source shows its pin *and* what it leaves inert.
    /// An unapproved source never reaches this function: `config::load` refuses
    /// it, so no `approved` row can be printed for bytes nobody approved.
    #[test]
    fn v36_describe_config_shows_the_pin_clause_beside_inert_and_never_for_trusted() {
        let f = SourcesDoctor::new();
        let report = f.load(
            "[[sources]]\nname = \"home\"\npath = \"~/.config/agent-vm/config.toml\"\ntrust = true\n\
             [[sources]]\nname = \"repo\"\npath = \"./.agent-vm/config.toml\"\nallow = false\n",
            "[[tools]]\nname = \"home-tool\"\ncommand = \"home-tool\"\n",
            "image = \"localhost:9/inert:latest\"\n[[tools]]\nname = \"repo-tool\"\ncommand = \"repo-tool\"\n",
        );
        let user = f.user_config();
        let repo = f.repo(".agent-vm/config.toml");
        let approved = crate::config_pins::ContentHash::of(&std::fs::read(&repo).unwrap());
        let (text, failure, _) = describe_config(report);
        assert!(failure.is_none(), "{text}");
        assert!(
            text.contains(&format!(
                "sources:\n  home {} (found, 1 tool) [trust=true, allow=false]\n",
                user.display()
            )),
            "a trusted source is never pinned: {text}"
        );
        assert!(
            text.contains(&format!(
                "  repo {} (found, 1 tool) [trust=false, allow=false, pin=approved {approved}; inert: image]\n",
                repo.display()
            )),
            "{text}"
        );
    }

    /// V18: the implicit cases are byte-identical where nothing changed, and the
    /// dual-image row moves the override suffix to the user row (R9).
    #[test]
    fn v18_implicit_sourcing_prints_no_sources_block_and_flips_the_override_row() {
        let dir = tempfile::tempdir().unwrap();
        let user = dir.path().join("config.toml");
        write_config(&user, "image = \"localhost:1/u:latest\"\n");
        let report = config_report(Some(&user), &dir.path().join("absent.toml"));
        let (text, _, _) = describe_config(report);
        assert!(!text.contains("sources:"), "{text}");
        assert!(!text.contains("not sourced"), "{text}");

        let images = crate::config::ConfiguredImages::for_test(crate::config::ImageTierFixture {
            user: Some(crate::config::ConfiguredImage::for_test(
                "localhost:1/u:latest",
                PathBuf::from("/h/.config/agent-vm/config.toml"),
            )),
            project: Some(crate::config::ConfiguredImage::for_test(
                "localhost:1/p:latest",
                PathBuf::from("/h/.config/agent-vm/projects/x/config.toml"),
            )),
            ..Default::default()
        });
        let rows = describe_image_tiers(&images);
        assert_eq!(
            rows,
            "user:    localhost:1/u:latest [/h/.config/agent-vm/config.toml]  (overridden by the project image)\n\
             project: localhost:1/p:latest [/h/.config/agent-vm/projects/x/config.toml]\n"
        );

        // The `ALIAS:image` form names both roles: the alias and the declaring file.
        let images = crate::config::ConfiguredImages::for_test(crate::config::ImageTierFixture {
            project: Some(crate::config::ConfiguredImage::for_test_via(
                "localhost:1/repo:latest",
                PathBuf::from("/w/app/.agent-vm/config.toml"),
                "repo",
            )),
            source_images: vec![crate::config::SourceImageReport::for_test(
                "localhost:1/team:latest",
                PathBuf::from("/w/app/team.toml"),
                "team",
                crate::config::SourceImageStatus::Inert,
            )],
            ..Default::default()
        });
        let rows = describe_image_tiers(&images);
        assert_eq!(
            rows,
            "user:    none\n\
             project: localhost:1/repo:latest [repo:image /w/app/.agent-vm/config.toml]\n\
             source team: localhost:1/team:latest [/w/app/team.toml]  (inert; allow = false — to select it, write image = \"team:image\" in the project config or set allow = true)\n"
        );

        // A path holding ESC is escaped in every new row.
        let images = crate::config::ConfiguredImages::for_test(crate::config::ImageTierFixture {
            source_images: vec![crate::config::SourceImageReport::for_test(
                "localhost:1/team:latest",
                PathBuf::from("/w/\u{1b}[31m/team.toml"),
                "team",
                crate::config::SourceImageStatus::Inert,
            )],
            ..Default::default()
        });
        let rows = describe_image_tiers(&images);
        assert!(!rows.contains('\u{1b}'), "{rows}");
        assert!(rows.contains("\\x1b"), "{rows}");

        // A sourced legacy file adds nothing to the section.
        assert_eq!(
            with_legacy_notice(
                "==> tool configuration\nuser:    x\n".to_string(),
                Some(&LegacyProjectConfig::Sourced)
            ),
            "==> tool configuration\nuser:    x\n"
        );
    }

    /// Every precedence outcome gets its own sentence: the winning fallback, a
    /// project override, an earlier source's override, and an inert `allow = false`
    /// declaration that names how to select it instead (ADR-0076 R5.2).
    #[test]
    fn source_image_rows_report_each_precedence_outcome() {
        use crate::config::{ImageTierFixture, SourceImageReport, SourceImageStatus};

        let row = |alias: &str, status: SourceImageStatus| {
            SourceImageReport::for_test(
                "localhost:1/team:latest",
                PathBuf::from(format!("/w/app/{alias}.toml")),
                alias,
                status,
            )
        };
        let images = crate::config::ConfiguredImages::for_test(ImageTierFixture {
            user: Some(crate::config::ConfiguredImage::for_test(
                "localhost:1/u:latest",
                PathBuf::from("/h/.config/agent-vm/config.toml"),
            )),
            source_images: vec![
                row("home", SourceImageStatus::SelectedFallback),
                row("repo", SourceImageStatus::OverriddenByProject),
                row(
                    "team",
                    SourceImageStatus::OverriddenBySource(
                        crate::config_sources::SourceAlias::for_test("home"),
                    ),
                ),
                row("legacy", SourceImageStatus::Inert),
            ],
            ..Default::default()
        });
        assert_eq!(
            describe_image_tiers(&images),
            "user:    localhost:1/u:latest [/h/.config/agent-vm/config.toml]\n\
             project: none\n\
             source home: localhost:1/team:latest [/w/app/home.toml]  (selected fallback; allow = true)\n\
             source repo: localhost:1/team:latest [/w/app/repo.toml]  (allow = true; overridden by the project image)\n\
             source team: localhost:1/team:latest [/w/app/team.toml]  (allow = true; overridden by source home fallback image)\n\
             source legacy: localhost:1/team:latest [/w/app/legacy.toml]  (inert; allow = false — to select it, write image = \"legacy:image\" in the project config or set allow = true)\n"
        );
    }
}
