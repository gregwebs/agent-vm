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

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use clap::Args as ClapArgs;

use crate::boot_image;
use crate::config::{
    ConfigConflict, ConfigReport, ConfiguredImage, ConfiguredImages, LaunchCatalog, TierReport,
    TierStatus, Tool, ToolOrigin,
};
use crate::credential_provider::{CredentialProvider, ProviderSet};
use crate::credential_resolver;
use crate::credential_yaml::{AuthorizationSet, GuestEnvName, SourceKind};
use crate::pi_credential_inspection::{PiCredentialReport, inspect_project};
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

pub fn run(args: Args) -> Result<()> {
    run_to(args, &mut std::io::stdout(), gather_credential_store)
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
            section.push_str("reachable");
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
    out: &mut impl std::io::Write,
    gather_store: impl FnOnce() -> Result<Availability>,
) -> Result<()> {
    let msb_home = crate::msb_install::msb_home_dir()?;

    if !args.reset_msb_db {
        // Discover and load the read-only tool configuration, but hold the
        // result as data instead of `?`-propagating it: a repo-supplied config
        // must not blank out the state/credential sections `doctor` exists to
        // show. A load failure is rendered as the `==> tool configuration`
        // section's own body, and the trailing `return Err(...)` still exits
        // nonzero. The reset branch deliberately never reads config: a broken
        // TOML must not block recovering a forward-migrated db.
        let config =
            crate::config::ConfigPaths::discover().and_then(|paths| crate::config::load(&paths));
        // A load failure *and* a catalog-build failure (the embedded defaults
        // failing to resolve `shell`) both fail the run; either is rendered in
        // the section. `describe_config` returns the latter so `doctor` cannot
        // print an error and still exit 0.
        let load_failure = config.as_ref().err().map(|error| anyhow!("{error:#}"));

        // Build the resolved catalog once, before printing anything: the
        // credential report and the launch view are both launch-aware (#178),
        // so they read the same catalog the tool-configuration section
        // renders, and a launch-verb list cannot diverge from `--help`.
        let (config_section, catalog_failure, catalog, images) = match config {
            Ok(report) => {
                // Capture the readable image tiers before `describe_config`
                // consumes the report (a catalog-build failure must not erase
                // a readable image choice).
                let images = report.images().clone();
                let (section, failure, catalog) = describe_config(report);
                (section, failure, catalog, Some(images))
            }
            Err(error) => (
                format!("==> tool configuration\nerror: {error:#}"),
                load_failure,
                None,
                None,
            ),
        };
        let launch = gather_launch_view(catalog.as_ref());
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
                ),
            )?;
            write_line(out, "")?;
        }
        write_line(out, &describe_credentials(&gather_credentials(), &launch))?;
        write_line(out, "")?;
        // Submit preceding sections before a native read can emit its slow notice.
        out.flush().context("writing doctor output")?;
        let (store_section, store_failure) = describe_credential_store(&gather_store());
        write_line(out, &store_section)?;
        write_line(out, "")?;
        write_line(out, &config_section)?;
        if !launch.is_empty() {
            write_line(out, "")?;
            write_line(out, &describe_launch_view(&launch))?;
        }
        let (boot_image_section, boot_image_failure) =
            describe_boot_image(images.as_ref(), &env_slot);
        write_line(out, "")?;
        write_line(out, &boot_image_section)?;
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

fn describe_embedded_runtime(dir: Option<&Path>, exists: bool) -> String {
    match dir {
        Some(dir) => format!(
            "==> embedded runtime\nunpacked: {} ({})",
            crate::one_line::path(dir),
            if exists { "present" } else { "absent" }
        ),
        None => "==> embedded runtime\nunpacked: unresolved (set XDG_CACHE_HOME or HOME)".into(),
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
/// command acts on, not a normalised spelling of it.
fn describe_home(msb_home: &Path, db_exists: bool, bundled_schema: &str) -> String {
    let db_path = msb_home.join("db").join("msb.db");
    format!(
        "==> active microsandbox home\n\
         MSB_HOME: {}\n\
         db:       {} ({})\n\
         this build's bundled schema: {}",
        crate::one_line::path(msb_home),
        crate::one_line::path(&db_path),
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
    /// host-only token files exist. `None` when the cwd can't be resolved.
    project: Option<ProjectCreds>,
    /// `now` in epoch ms, for rendering "expires in ...".
    now_ms: i64,
}

#[derive(Debug, PartialEq, Eq)]
struct ProjectCreds {
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
fn gather_credentials() -> CredReport {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);

    // The host credential table is the provider table: `doctor_label`
    // (`claude`/`codex`/`opencode`/`copilot`) and `doctor_parses_expiry` are
    // retained verbatim so this output stays byte-identical, and `ALL` order
    // is the historical claude, codex, opencode, copilot order.
    let hosts = crate::credential_provider::CredentialProvider::ALL
        .into_iter()
        .map(|provider| {
            let label = provider.doctor_label();
            let want_expiry = provider.doctor_parses_expiry();
            let path = provider.host_credential_path();
            let state = match &path {
                None => HostCred::Unreadable {
                    why: "no $HOME".into(),
                },
                Some(p) => inspect_host_cred(p, want_expiry),
            };
            (label, path, state)
        })
        .collect();

    CredReport {
        hosts,
        project: gather_project_creds(),
        now_ms,
    }
}

fn inspect_host_cred(path: &Path, want_expiry: bool) -> HostCred {
    if std::fs::symlink_metadata(path).is_err() {
        return HostCred::Missing;
    }
    let bytes = match crate::host_paths::read_bounded_regular_file(
        path,
        crate::host_paths::MAX_HOST_CREDENTIAL_FILE_BYTES,
    ) {
        Ok(bytes) => bytes,
        Err(error) => {
            return HostCred::Unreadable {
                why: format!("{error:#}"),
            };
        }
    };
    let json: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(json) => json,
        Err(error) => {
            return HostCred::Unreadable {
                why: format!("not valid JSON: {error}"),
            };
        }
    };
    if !want_expiry {
        return HostCred::Present {
            expires_at_ms: None,
        };
    }
    // Same shape `secrets::refresh_anthropic` requires; report the
    // *absence* of it as unreadable so "file exists but agent-vm can't
    // use it" never renders as a healthy row.
    let Some(oauth) = json.get("claudeAiOauth") else {
        return HostCred::Unreadable {
            why: "missing claudeAiOauth (API-key-only login?)".into(),
        };
    };
    if oauth.get("accessToken").and_then(|v| v.as_str()).is_none() {
        return HostCred::Unreadable {
            why: "claudeAiOauth has no accessToken".into(),
        };
    }
    HostCred::Present {
        expires_at_ms: oauth.get("expiresAt").and_then(serde_json::Value::as_i64),
    }
}

fn gather_project_creds() -> Option<ProjectCreds> {
    let session = crate::session::ProjectSession::for_cwd().ok()?;
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
    Some(ProjectCreds {
        dir: session.project_dir.clone(),
        state_dir: session.state_dir.clone(),
        captured,
        guest_claude_placeholder: session.state_dir.join("claude/.credentials.json").exists(),
        pi_credentials: inspect_project(&session.state_dir),
    })
}

/// Render the credential report. Pure over its input so the wording is
/// unit-tested without touching `$HOME` or the filesystem.
///
/// `launch` supplies the launch-aware disposition of each host file (#178): a
/// provider some configured launch replaces is annotated so a green/absent row
/// is never read as "this launch will read this file".
fn describe_credentials(report: &CredReport, launch: &LaunchView) -> String {
    let mut out = String::from("==> host agent credentials\n");
    let width = report
        .hosts
        .iter()
        .map(|(label, _, _)| label.len())
        .max()
        .unwrap_or(0);
    for (label, path, state) in &report.hosts {
        let detail = match state {
            HostCred::Missing => "absent".to_string(),
            // `why` is an error chain from `host_paths`, whose messages interpolate
            // the measured path (`… is not a regular file`, `opening …`). It is
            // escaped here, at the print site, like the path above it.
            HostCred::Unreadable { why } => {
                format!("UNUSABLE - {}", crate::one_line::text(why))
            }
            HostCred::Present {
                expires_at_ms: None,
            } => "ok".to_string(),
            HostCred::Present {
                expires_at_ms: Some(exp),
            } => format!("ok ({})", describe_expiry(*exp, report.now_ms)),
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
        None => out.push_str("\n==> this project: <cwd could not be resolved>\n"),
        Some(project) => {
            out.push_str(&format!(
                "\n==> this project\ndir:      {}\nstate:    {}\ncaptured: {}\nguest Claude cred file: {}\n",
                crate::one_line::path(&project.dir),
                crate::one_line::path(&project.state_dir),
                if project.captured.is_empty() {
                    "<none> (nothing to substitute on the wire)".to_string()
                } else {
                    project.captured.join(", ")
                },
                if project.guest_claude_placeholder {
                    "placeholder present"
                } else {
                    "absent"
                },
            ));
            out.push('\n');
            out.push_str(&project.pi_credentials.doctor_section());
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
    source: SourceKind,
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
fn gather_launch_view(catalog: Option<&LaunchCatalog>) -> LaunchView {
    let mut view = LaunchView::default();
    let authorizations = match credential_resolver::load_authorizations() {
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
    let selection = launch_selection(catalog, &authorizations);
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
                source: credential.source(),
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
    // `{path} is group- or other-readable…`), so they are escaped at the print
    // site. A launch that requests a credential emits the same notes through
    // `run`'s notice channel, which still writes them raw — the launch surface's
    // version of this bug, filed as #416 rather than fixed here.
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
        let mut what = match row.source {
            SourceKind::Keychain => "authorized for this launch".to_owned(),
            SourceKind::Environment => format!(
                "authorized for this launch from the host environment (`{}`)",
                row.env_name
            ),
        };
        if row.replaces_builtin {
            what.push_str(" (replaces the host built-in)");
        }
        out.push_str(&format!("{:<width$}  {what}\n", row.service));
    }
    if view
        .yaml
        .iter()
        .any(|row| row.source == SourceKind::Keychain)
    {
        out.push_str("note: values are not read here; `agent-vm secret ls` reports whether a value is stored.\n");
    }
    if view
        .yaml
        .iter()
        .any(|row| row.source == SourceKind::Environment)
    {
        out.push_str("note: environment values are read by the launch, not by doctor.\n");
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
        describe_tier(report.user()),
        describe_tier(report.project()),
    );
    let resolved_label = if report.uses_defaults() {
        "resolved: built-in defaults; launch-verb order\n"
    } else {
        "resolved: declared tools; launch-verb order\n"
    };
    let conflicts = render_conflicts(report.conflicts());

    let mut out = String::from("==> tool configuration\n");
    out.push_str(&tiers);
    out.push_str(resolved_label);
    let (failure, catalog) = match report.into_launch_catalog() {
        Ok(catalog) => {
            for (index, entry) in catalog.as_slice().iter().enumerate() {
                out.push_str(&format!(
                    "  {}. {}\n",
                    index + 1,
                    describe_tool(entry.tool(), entry.provisioned())
                ));
            }
            if catalog.has_shell_fallback() {
                out.push_str(
                    "note: `shell` was not declared; the built-in fallback is registered so you\n\
                     still have a way into the guest.\n",
                );
            }
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
    out.push_str(&conflicts);
    // Drop the final newline: the caller adds one via `writeln!`.
    out.truncate(out.trim_end_matches('\n').len());
    (out, failure, catalog)
}

/// The `warning:` blocks for cross-tier shadows, in project declaration order.
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
            "warning: tool {} in {} overrides\n         {}; differing fields: {}\n",
            crate::config::quoted_str(conflict.tool()),
            crate::one_line::path(conflict.user_file()),
            crate::one_line::path(conflict.project_file()),
            fields,
        ));
    }
    out
}

fn describe_tier(tier: &TierReport) -> String {
    match tier.status() {
        TierStatus::UnavailableHome => "<no HOME; user tier unavailable>".to_string(),
        TierStatus::Absent => format!(
            "{} (absent)",
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

/// Renders the boot-image section and returns the failure it found, if any.
///
/// Observational by construction: [`boot_image::observe`] reads the retained
/// record and resolves the selection from **one** snapshot, so the `default`
/// row and `selected (without --image)` row cannot disagree across a concurrent
/// adoption, and nothing is created, locked or repaired. A damaged default still
/// renders every tier row and a clear error; the caller exits nonzero.
fn describe_boot_image(
    images: Option<&ConfiguredImages>,
    env: &boot_image::EnvOverride,
) -> (String, Option<anyhow::Error>) {
    let mut out = String::from("==> boot image\n");
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
            // caller exits nonzero after this section.
            out.push_str(
                "AGENT_VM_IMAGE_TAG: <present but not valid Unicode; refusing to select>\n",
            );
            return (out, None);
        }
    };
    // An unreadable config leaves the tiers unknown, but the default slot is
    // still readable, so `doctor` reports it with the *same* selector an empty
    // config would use rather than inventing a second resolution path.
    let configured = images.cloned().unwrap_or_default();
    let observation = boot_image::observe(env_override, &configured);
    let default_row = describe_default_observation(&observation.default);
    // A user scope that cannot be *located* (`$HOME` unset, empty or relative)
    // is already reported by the config section as an unavailable user tier;
    // it is not a damaged record, so on its own it does not fail the
    // diagnostic. A record that exists but cannot be read/parsed does — this
    // follows the *default* row, not the effective selection, so a valid
    // `AGENT_VM_IMAGE_TAG` cannot mask the damage (the override still wins the
    // launch; the diagnosis still fails).
    let scope_locatable = matches!(crate::config::host_home_dir(), Ok(Some(_)));
    let failure = match &observation.default {
        boot_image::DefaultObservation::Unavailable { message } if scope_locatable => {
            Some(anyhow::anyhow!(message.clone()))
        }
        _ => None,
    };
    let Some(images) = images else {
        // The config could not be read, so the tiers are unknown.
        out.push_str("unknown (configuration could not be read)\n");
        out.push_str(&format!("default: {default_row}"));
        return (out, failure);
    };
    out.push_str(&format!(
        "user:    {}\n",
        describe_configured_image(images.user())
    ));
    let project = describe_configured_image(images.project());
    if images.user().is_some() && images.project().is_some() {
        out.push_str(&format!(
            "project: {project}  (overridden by the user image)\n"
        ));
    } else {
        out.push_str(&format!("project: {project}\n"));
    }
    out.push_str(&format!("default: {default_row}\n"));
    // Doctor accepts no `--image`, so the selected row excludes the command
    // line: it is the env slot, then config, then the default slot. When the
    // default slot won, the selected row reuses the *safe* default label rather
    // than rendering its reference.
    match &observation.selected {
        Ok(selected) if selected.is_default() => {
            out.push_str(&format!("selected (without --image): {default_row}"));
        }
        Ok(selected) => out.push_str(&format!(
            "selected (without --image): {} (from {})",
            crate::config::escape_str(selected.reference().as_str()),
            selected.source().describe()
        )),
        Err(error) => out.push_str(&format!("selected (without --image): error: {error:#}")),
    }
    (out, failure)
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

/// `ghcr.io/owner/name:tag [/path/to/config.toml]` or `none`.
fn describe_configured_image(image: Option<&ConfiguredImage>) -> String {
    match image {
        None => "none".to_string(),
        Some(image) => format!(
            "{} [{}]",
            crate::config::escape_str(image.reference().as_str()),
            crate::one_line::path(image.file())
        ),
    }
}

fn describe_tool(tool: &Tool, provisioned: ProviderSet) -> String {
    // Both columns render through the same helper, in `CredentialProvider::ALL`
    // order. `credentials` is stored in *declaration* order
    // (`validate_credentials` — a plain map/collect), so rendering it directly
    // beside an `ALL`-ordered `provisions=` would show the same set in two
    // orders for a tool declaring `["copilot","anthropic"]`, which reads as a
    // bug. Canonicalize both to `ALL` order; the shipped rows are already in
    // that order, so no existing expectation changes.
    let credentials = provider_names(ProviderSet::new(tool.credentials().iter().copied()).iter());
    let provisions = provider_names(provisioned.iter());
    let source = match tool.origin() {
        ToolOrigin::BuiltIn => "built-in".to_string(),
        ToolOrigin::User(file) => format!("user:{}", crate::one_line::path(file)),
        ToolOrigin::Project(file) => format!("project:{}", crate::one_line::path(file)),
    };
    // Only surfaced when true, so the default-config rows for the six agents
    // are byte-identical to before (`interactive_shell` is `shell`-only).
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
    format!(
        "{} -> \"{}\"; args={}; credentials={credentials}; \
         provisions={provisions}; persist={}; source={source}{interactive_shell}{env}{requests}",
        crate::config::escape_str(tool.name()),
        crate::config::escape_str(tool.command()),
        tool.arg_count(),
        tool.persist_count(),
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
/// `from:`/`to:` above are [`crate::one_line`] diagnostics, so the undo `mv`
/// takes raw path bytes through [`crate::shell::PastedWord`] instead; `mv --`
/// keeps the leading operand a path rather than an option, and
/// [`crate::shell::bash_zsh_note`] names the shell when not every shell reads
/// the operand.
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
            format!(
                "==> Moved microsandbox db aside (nothing was deleted)\n\
                 from: {}\n\
                 to:   {}\n\
                 The database will be recreated at the bundled schema on the next \
                 `agent-vm shell`/`run`, and images will be re-pulled on first boot.\n\
                 To undo: mv -- {to_word} {from_word}{shell_note}",
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
    #[test]
    fn credential_store_rows_match_all_outcomes() {
        for (outcome, row, fails) in [
            (
                Availability::NotProbed,
                "not probed (0 tracked names)",
                false,
            ),
            (Availability::Reachable, "reachable", false),
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
            let mut env = crate::test_env::guard();
            let root = tempfile::tempdir().unwrap();
            let home = root.path().join("home");
            let project = root.path().join("project");
            std::fs::create_dir_all(&project).unwrap();
            write_file(
                &home.join(".config/agent-vm/credentials.yaml"),
                ANTHROPIC.as_bytes(),
            );
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(
                home.join(".config/agent-vm/credentials.yaml"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            env.set_var("HOME", &home);
            env.set_var("XDG_CACHE_HOME", root.path().join("cache"));
            env.set_var("AGENT_VM_STATE_DIR", root.path().join("state"));
            for key in [
                "AGENT_VM_IMAGE_TAG",
                "AGENT_VM_TEST_DEFAULT_IMAGE",
                "MSB_HOME",
                "XDG_CONFIG_HOME",
            ] {
                env.remove_var(key);
            }
            let old_cwd = std::env::current_dir().unwrap();
            std::env::set_current_dir(&project).unwrap();
            Self {
                old_cwd,
                root,
                _env: env,
            }
        }
        fn normalize(&self, text: &str) -> String {
            let session = crate::session::ProjectSession::for_cwd().unwrap();
            text.replace(&session.state_dir.display().to_string(), "<project-state>")
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
            "==> agent-vm doctor: available operations",
        ] {
            assert!(text.contains(heading), "missing {heading}: {text}");
        }
        assert!(text.ends_with(
            "                       agent-vm shell/run recreates it at the bundled schema\n"
        ));
        assert_eq!(text.matches("==> credential store\n").count(), 1);
    }

    #[test]
    fn run_to_flushes_before_gather_and_after_success() {
        let _fixture = RunFixture::new();
        let mut out = RecordingWriter::default();
        let flushed = out.flushed.clone();
        let submissions = out.submissions.clone();
        run_to(ordinary(), &mut out, || {
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
        run_to(ordinary(), &mut successful, || Ok(Availability::Reachable)).unwrap();
        let successful = std::str::from_utf8(&successful).unwrap();
        let expected_tail = successful.split_once("==> tool configuration\n").unwrap().1;
        for failure in [
            crate::secret_store::KeychainFailure::AccessDenied,
            crate::secret_store::KeychainFailure::Unresponsive,
        ] {
            let mut out = RecordingWriter::default();
            let error = run_to(ordinary(), &mut out, || {
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
            let error = run_to(ordinary(), &mut out, || {
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
        let error = run_to(ordinary(), &mut out, || {
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
            run_to(Args { reset_msb_db: true }, &mut out, || {
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
        run_to(ordinary(), &mut out, || Ok(Availability::NotProbed)).unwrap();
        let actual = fixture.normalize(std::str::from_utf8(&out).unwrap());
        let without_new_section = actual.replace(
            "==> credential store\ncredential store: not probed (0 tracked names)\n\n",
            "",
        );
        let expected = r###"==> active microsandbox home
MSB_HOME: <fixture>/state/msb-home
db:       <fixture>/state/msb-home/db/msb.db (absent)
this build's bundled schema: m20260922_000001

==> host agent credentials
claude    <fixture>/home/.claude/.credentials.json
          absent - replaced by credentials.yaml for pi, claude, shell (host file not read)
codex     <fixture>/home/.codex/auth.json
          absent
opencode  <fixture>/home/.local/share/opencode/auth.json
          absent
copilot   <fixture>/home/.cache/claude-vm/copilot-token.json
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

==> tool configuration
user:    <fixture>/home/.config/agent-vm/config.toml (absent)
project: <fixture>/project/.agent-vm/config.toml (absent)
resolved: built-in defaults; launch-verb order
  1. dsh -> "dsh"; args=1; credentials=none; provisions=none; persist=1; source=built-in
  2. pi -> "pi"; args=0; credentials=none; provisions=anthropic,openai; persist=0; source=built-in; network_requests=api.anthropic.com,auth.openai.com,chatgpt.com,mcp-proxy.anthropic.com,platform.claude.com
  3. codex -> "codex"; args=0; credentials=openai; provisions=openai; persist=0; source=built-in; env=1; network_requests=api.openai.com,auth.openai.com,chatgpt.com
  4. opencode -> "opencode"; args=0; credentials=openai,opencode-static; provisions=openai,opencode-static; persist=0; source=built-in; network_requests=api.openai.com,auth.openai.com,chatgpt.com,models.opencode.ai
  5. claude -> "claude"; args=1; credentials=anthropic; provisions=anthropic; persist=0; source=built-in; network_requests=api.anthropic.com,mcp-proxy.anthropic.com,platform.claude.com
  6. copilot -> "copilot"; args=1; credentials=copilot; provisions=copilot; persist=0; source=built-in
  7. shell -> "bash"; args=2; credentials=none; provisions=anthropic,openai,opencode-static,copilot; persist=0; source=built-in; interactive_shell=true; env=1

==> credentials.yaml (launch credentials)
anthropic  authorized for this launch (replaces the host built-in)
note: values are not read here; `agent-vm secret ls` reports whether a value is stored.

==> boot image
AGENT_VM_IMAGE_TAG: <unset>
user:    none
project: none
default: not selected; initial recommendation [<fixture>/home/.config/agent-vm/default-image.json]
selected (without --image): not selected; initial recommendation [<fixture>/home/.config/agent-vm/default-image.json]

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
            run_to(Args { reset_msb_db: true }, &mut out, || {
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
To undo: mv -- <fixture>/state/msb-home/db.reset-<timestamp> <fixture>/state/msb-home/db
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

    #[test]
    fn embedded_runtime_section_reports_path_and_presence() {
        assert_eq!(
            describe_embedded_runtime(Some(Path::new("/cache/runtime/id")), true),
            "==> embedded runtime\nunpacked: /cache/runtime/id (present)"
        );
        assert_eq!(
            describe_embedded_runtime(Some(Path::new("/cache/runtime/id")), false),
            "==> embedded runtime\nunpacked: /cache/runtime/id (absent)"
        );
    }
    #[test]
    fn embedded_runtime_section_reports_unresolved_root() {
        assert_eq!(
            describe_embedded_runtime(None, false),
            "==> embedded runtime\nunpacked: unresolved (set XDG_CACHE_HOME or HOME)"
        );
    }

    use clap::Parser;

    fn write_file(path: &Path, contents: &[u8]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
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
        let text = describe_home(Path::new("/state/msb-home"), true, "m20260824_000001");

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
        let text = describe_embedded_runtime(Some(Path::new("/cache/rt\nFORGED-RUNTIME")), true);

        assert_eq!(text.lines().count(), 2, "one title, one line: {text:?}");
        assert!(
            text.contains("/cache/rt\\x0aFORGED-RUNTIME"),
            "the measured path is escaped: {text:?}"
        );
    }

    #[test]
    fn a_measured_msb_home_cannot_forge_a_section() {
        let text = describe_home(Path::new("/state/m\nFORGED-HOME"), true, "m20260824_000001");

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
        assert_eq!(
            undo,
            "To undo: mv -- $'/state/m\\x0aFORGED-FROM/db.reset-123' \
             $'/state/m\\x0aFORGED-FROM/db'"
        );
        // Only bash and zsh read `$'…'`, so the report says so; the note is its
        // own line, leaving the `To undo: ` line a command and nothing else.
        assert!(
            text.contains(
                "To undo: mv -- $'/state/m\\x0aFORGED-FROM/db.reset-123' \
                 $'/state/m\\x0aFORGED-FROM/db'\n(quoted for bash or zsh)"
            ),
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

        let operands = text
            .lines()
            .find_map(|line| line.strip_prefix("To undo: mv -- "))
            .expect("the undo line");
        // `set --` in place of the command: the shell decodes each word to one
        // argument, and nothing is moved.
        let probe =
            format!("set -- {operands}; [ \"$#\" -eq 2 ] || exit 99; printf '%s\\0' \"$1\" \"$2\"");
        let out = std::process::Command::new("bash")
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .args(["-c", &probe])
            .output()
            .expect("bash must be on PATH for this test");
        assert!(
            out.status.success(),
            "bash rejected the undo operands ({operands}): {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let mut expected = to.as_os_str().as_bytes().to_vec();
        expected.push(0);
        expected.extend_from_slice(from.as_os_str().as_bytes());
        expected.push(0);
        assert_eq!(out.stdout, expected, "undo operands were {operands}");
    }

    /// The discriminator against [`crate::config::escape_str`]: a measured path
    /// the user has to read back — and, for `--reset-msb-db`, copy — stays
    /// legible. Escaping every non-ASCII byte would print this as
    /// `/home/boger/\\xd0\\xbf...`.
    #[test]
    fn a_measured_path_with_non_ascii_is_printed_as_itself() {
        let text = describe_home(Path::new("/home/boger/проект"), false, "m1");

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
        std::fs::write(
            &user,
            "image = \"ghcr.io/acme/user:1\"\n[[tools]]\nname = \"t\"\ncommand = \"t\"\n",
        )
        .unwrap();
        // `t` collides with the user tier (the conflict warning), `u` exists only in
        // the project tier (the `source=project:` row).
        std::fs::write(
            &project_file,
            "image = \"ghcr.io/acme/project:1\"\n[[tools]]\nname = \"t\"\ncommand = \"other\"\n\
             [[tools]]\nname = \"u\"\ncommand = \"u\"\n",
        )
        .unwrap();

        let (text, _, _) = describe_config(config_report(Some(&user), &project_file));

        for (site, needle) in [
            ("the user tier line", format!("{} (found", user.display())),
            (
                "the project tier line",
                format!("{} (found", project_file.display()),
            ),
            (
                "the conflict warning",
                format!("in {} overrides", user.display()),
            ),
            (
                "the user tool row",
                format!("source=user:{}", user.display()),
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
        let project = r.project.as_mut().unwrap();
        project.dir = PathBuf::from("/work/pr\nFORGED-PROJECT");
        project.state_dir = PathBuf::from("/state/st\nFORGED-STATE");

        let text = describe_credentials(&r, &LaunchView::default());

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
        let text = describe_home(Path::new("/state/msb-home"), false, "m20260824_000001");

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

    #[test]
    fn a_claude_file_without_claudeaioauth_reads_as_unusable_not_ok() {
        // The exact shape `secrets::refresh_anthropic` rejects. Rendering
        // this as "ok" would send the user hunting anywhere but the file
        // that is actually the problem.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".credentials.json");
        write_file(&path, br#"{"someOtherLogin":{"accessToken":"x"}}"#);

        assert_eq!(
            inspect_host_cred(&path, true),
            HostCred::Unreadable {
                why: "missing claudeAiOauth (API-key-only login?)".into()
            }
        );
    }

    #[test]
    fn a_well_formed_claude_file_reports_its_expiry_and_absent_stays_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".credentials.json");
        write_file(
            &path,
            br#"{"claudeAiOauth":{"accessToken":"tok","expiresAt":42}}"#,
        );

        assert_eq!(
            inspect_host_cred(&path, true),
            HostCred::Present {
                expires_at_ms: Some(42)
            }
        );
        assert_eq!(
            inspect_host_cred(&dir.path().join("nope.json"), true),
            HostCred::Missing
        );
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

    fn report(hosts: Vec<(&'static str, Option<PathBuf>, HostCred)>) -> CredReport {
        CredReport {
            hosts,
            project: Some(ProjectCreds {
                dir: PathBuf::from("/p"),
                state_dir: PathBuf::from("/s/abc"),
                captured: vec!["claude"],
                guest_claude_placeholder: true,
                pi_credentials: PiCredentialReport::uninspected(),
            }),
            now_ms: 0,
        }
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

    #[test]
    fn render_calls_out_a_project_with_nothing_captured() {
        let mut r = report(vec![(
            "claude",
            Some(PathBuf::from("/h/.claude/.credentials.json")),
            HostCred::Present {
                expires_at_ms: Some(HOUR_MS),
            },
        )]);
        r.project.as_mut().unwrap().captured.clear();
        r.project.as_mut().unwrap().guest_claude_placeholder = false;

        let text = describe_credentials(&r, &LaunchView::default());

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
        crate::config::load(&crate::config::ConfigPaths {
            user: user.map(Path::to_path_buf),
            project: project.to_path_buf(),
            home: None,
        })
        .expect("fixture config should load")
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
                "pi -> \"pi\"; args=0; credentials=none; provisions=anthropic,openai; persist=0; source=built-in"
            ),
            "{text}"
        );

        assert!(
            text.contains(
                "shell -> \"bash\"; args=2; credentials=none; provisions=anthropic,openai,opencode-static,copilot; persist=0; source=built-in; interactive_shell=true; env=1"
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
        std::fs::write(
            &user,
            "[[tools]]\nname = \"vault\"\ncommand = \"vault\"\nenv = { TOKEN = \"sk-secret\" }\n",
        )
        .unwrap();
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

    #[test]
    fn describe_config_distinguishes_a_found_empty_tier_from_an_absent_one() {
        let dir = tempfile::tempdir().unwrap();
        let user = dir.path().join("user.toml");
        std::fs::write(&user, "").unwrap();
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
        std::fs::write(&user, "[[tools]]\nname = \"solo\"\ncommand = \"solo\"\n").unwrap();
        let report = config_report(Some(&user), &dir.path().join("absent.toml"));

        let (text, _, _) = describe_config(report);
        assert!(text.contains("1. solo"), "{text}");
        assert!(text.contains("2. shell"), "{text}");
        assert!(text.contains("`shell` was not declared"), "{text}");
    }

    #[test]
    fn describe_config_names_differing_fields_but_never_argument_values() {
        let dir = tempfile::tempdir().unwrap();
        let user = dir.path().join("user.toml");
        let project = dir.path().join("project.toml");
        std::fs::write(
            &user,
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\nargs = [\"--token=SENTINEL\"]\n",
        )
        .unwrap();
        std::fs::write(
            &project,
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\nargs = [\"other\"]\n",
        )
        .unwrap();
        let report = config_report(Some(&user), &project);

        let (text, _, _) = describe_config(report);
        assert!(text.contains("overrides"), "{text}");
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
        std::fs::write(&user, "").unwrap();
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
        std::fs::write(
            &user,
            "[[tools]]\nname = \"t\"\ncommand = \"evil\\u001b[31m\\nred\"\n",
        )
        .unwrap();
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
        std::fs::write(&path, body).unwrap();
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
        std::fs::write(&user, "[[tools]]\nname = \"solo\"\ncommand = \"solo\"\n").unwrap();
        let catalog = config_report(Some(&user), &dir.path().join("absent.toml"))
            .into_launch_catalog()
            .expect("the one-tool catalog builds");
        let (_home, set) = authorizations(ANTHROPIC);

        let selection = launch_selection(&catalog, &set);

        assert!(selection.replaced.is_empty(), "{selection:?}");
        assert!(selection.requested.is_empty(), "{selection:?}");
        assert_eq!(
            selection.unrequested,
            vec!["claude", "codex", "opencode", "copilot"]
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
        std::fs::write(
            &user,
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\n\
             credentials = [\"alpha\", \"anthropic\", \"gamma\"]\n",
        )
        .unwrap();
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
        assert_eq!(selection.unrequested, vec!["codex", "opencode", "copilot"]);
    }

    #[test]
    fn describe_launch_view_names_each_requested_authorization_and_never_a_value() {
        let view = LaunchView {
            yaml: vec![
                YamlRow {
                    service: "alpha".into(),
                    replaces_builtin: false,
                    source: SourceKind::Keychain,
                    env_name: GuestEnvName::parse("ALPHA_KEY").unwrap(),
                },
                YamlRow {
                    service: "anthropic".into(),
                    replaces_builtin: true,
                    source: SourceKind::Keychain,
                    env_name: GuestEnvName::parse("ANTHROPIC_API_KEY").unwrap(),
                },
                YamlRow {
                    service: "env".into(),
                    replaces_builtin: false,
                    source: SourceKind::Environment,
                    env_name: GuestEnvName::parse("MY_KEY").unwrap(),
                },
            ],
            ..LaunchView::default()
        };

        let text = describe_launch_view(&view);

        assert!(
            text.starts_with("==> credentials.yaml (launch credentials)\n"),
            "{text}"
        );
        assert!(
            text.contains("alpha      authorized for this launch\n"),
            "{text}"
        );
        assert!(
            text.contains("anthropic  authorized for this launch (replaces the host built-in)"),
            "{text}"
        );
        assert!(
            text.contains("`agent-vm secret ls` reports whether a value is stored"),
            "{text}"
        );
        assert!(
            text.contains(
                "env        authorized for this launch from the host environment (`MY_KEY`)"
            ),
            "{text}"
        );
        assert!(
            text.contains("environment values are read by the launch, not by doctor"),
            "{text}"
        );
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
                "api.anthropic.com,auth.openai.com,chatgpt.com,mcp-proxy.anthropic.com,platform.claude.com",
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
            "pi -> \"pi\"; args=0; credentials=none; provisions=anthropic,openai; persist=0; source=built-in",
            "codex -> \"codex\"; args=0; credentials=openai; provisions=openai; persist=0; source=built-in; env=1",
            "opencode -> \"opencode\"; args=0; credentials=openai,opencode-static; provisions=openai,opencode-static; persist=0; source=built-in",
            "claude -> \"claude\"; args=1; credentials=anthropic; provisions=anthropic; persist=0; source=built-in",
            "copilot -> \"copilot\"; args=1; credentials=copilot; provisions=copilot; persist=0; source=built-in",
            "shell -> \"bash\"; args=2; credentials=none; provisions=anthropic,openai,opencode-static,copilot; persist=0; source=built-in; interactive_shell=true; env=1",
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
        std::fs::write(
            &user,
            format!("{base}network_requests = [\"b.example:8443\",\"a.example\"]\n"),
        )
        .unwrap();
        let report = config_report(Some(&user), &project);
        // `resolved()` is the retained arena; every assertion here is about the
        // launch winner, so it names the first one rather than an arena position.
        let describe = |report: &crate::config::ConfigReport| {
            describe_tool(
                report
                    .resolved()
                    .launch_tools()
                    .next()
                    .expect("one launch winner"),
                ProviderSet::new([]),
            )
        };
        assert!(describe(&report).ends_with("; network_requests=a.example,tcp://b.example:8443"));
        let names: Vec<_> = (0..9).map(|i| format!("\"n{i}.example\"")).collect();
        std::fs::write(
            &user,
            format!("{base}network_requests = [{}]\n", names.join(",")),
        )
        .unwrap();
        let report = config_report(Some(&user), &project);
        assert!(describe(&report).ends_with("; network_requests=n0.example,n1.example,n2.example,n3.example,n4.example,n5.example,n6.example,n7.example,+1 more"));
        std::fs::write(&project, base).unwrap();
        assert!(
            describe_config(config_report(Some(&user), &project))
                .0
                .contains("differing fields: network_requests")
        );
        std::fs::write(
            &user,
            format!("{base}network_requests = [\"sk-test-sensitivevalue\"]\n"),
        )
        .unwrap();
        let report = config_report(Some(&user), &project);
        let row = describe(&report);
        assert!(row.ends_with("; network_requests=sk-test-sensitivevalue"));
        assert_eq!(row.matches("sk-test-sensitivevalue").count(), 1);
    }
}
