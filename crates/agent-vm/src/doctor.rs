//! `agent-vm doctor` — diagnostic / maintenance operations for agent-vm's
//! private microsandbox state, and a read-only preview of the resolved tool
//! configuration (see [`crate::config`]).
//!
//! ## Ordinary run
//!
//! With no flag, doctor prints the active `MSB_HOME`/schema, the host
//! credential sources, and the resolved tool configuration. The **verb list**
//! this section renders is authoritative — it is the same [`crate::cli`]
//! catalog `--help` shows. The *layer chain* is rendered from each tool's
//! declared `layer` as written: `doctor` never resolves an anchor, checks a
//! path's existence, or builds the chain — [`crate::tool_layer`] owns that at
//! launch (#84). Argument *values* are still hidden (only their count is
//! shown, so a secret in `args` is never echoed). A broken config still exits
//! nonzero, but its failure is reported *inside* the config section so it
//! never suppresses the sections above it — and never blocks recovery
//! (below).
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
//! Historically this ahead-of-bundle condition surfaced as an opaque raw
//! sea-orm error the first time any command opened the db. `src/msb_preflight.rs`
//! (#30) now detects it up front on the boot path and the `agent-vm msb`
//! passthrough, and its error message points here — closing the loop
//! between "detect" (#30) and "recover" (this command, #28).

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use clap::Args as ClapArgs;

use crate::config::{
    ConfigConflict, ConfigReport, TierReport, TierStatus, Tool, ToolLayer, ToolOrigin,
};
use crate::credential_provider::{CredentialProvider, ProviderSet};
use crate::pi_credential_inspection::{PiCredentialReport, inspect_project};

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

        let db_exists = msb_home.join("db").join("msb.db").exists();
        println!(
            "{}",
            describe_home(
                &msb_home,
                db_exists,
                &crate::msb_schema::bundled_schema_version()
            )
        );
        println!();
        println!("{}", describe_credentials(&gather_credentials()));
        println!();
        let config_failure = match config {
            Ok(report) => {
                let (section, catalog_failure) = describe_config(report);
                println!("{section}");
                catalog_failure
            }
            Err(error) => {
                println!("==> tool configuration\nerror: {error:#}");
                load_failure
            }
        };
        println!();
        println!("==> agent-vm doctor: available operations");
        println!("      --reset-msb-db   move MSB_HOME/db aside (reversible) so the next");
        println!("                       agent-vm shell/run recreates it at the bundled schema");
        if let Some(error) = config_failure {
            return Err(error);
        }
        return Ok(());
    }

    let ts = timestamp_suffix(SystemTime::now());
    let outcome = reset_msb_db_in(&msb_home, &ts)?;
    println!("{}", render(&outcome));
    Ok(())
}

/// Names the *active* `MSB_HOME` and the schema this build understands, so
/// `agent-vm doctor` (with no flag) answers "which home and schema am I
/// acting on" up front — issue #42's AC-5. `MSB_HOME` is deliberately not
/// schema-namespaced (ADR-0004/0006): this is the detect-and-recover
/// alternative, not a reintroduction of namespacing. Pure over its inputs
/// (mirroring `render`/`reset_msb_db_in`'s testable-without-env-or-fs-reads
/// pattern above) so the wording is unit-tested without needing a real
/// `MSB_HOME` on disk.
fn describe_home(msb_home: &Path, db_exists: bool, bundled_schema: &str) -> String {
    let db_path = msb_home.join("db").join("msb.db");
    format!(
        "==> active microsandbox home\n\
         MSB_HOME: {}\n\
         db:       {} ({})\n\
         this build's bundled schema: {}",
        msb_home.display(),
        db_path.display(),
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
    /// `(agent label, host path as shown, what we found)`.
    hosts: Vec<(&'static str, String, HostCred)>,
    /// The project `doctor` was run in, and whether its per-project
    /// host-only token files exist. `None` when the cwd can't be resolved.
    project: Option<ProjectCreds>,
    /// `now` in epoch ms, for rendering "expires in ...".
    now_ms: i64,
}

#[derive(Debug, PartialEq, Eq)]
struct ProjectCreds {
    dir: String,
    state_dir: String,
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
            let shown = path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "<no $HOME>".to_string());
            let state = match &path {
                None => HostCred::Unreadable {
                    why: "no $HOME".into(),
                },
                Some(p) => inspect_host_cred(p, want_expiry),
            };
            (label, shown, state)
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
        dir: session.project_dir.display().to_string(),
        state_dir: session.state_dir.display().to_string(),
        captured,
        guest_claude_placeholder: session.state_dir.join("claude/.credentials.json").exists(),
        pi_credentials: inspect_project(&session.state_dir),
    })
}

/// Render the credential report. Pure over its input so the wording is
/// unit-tested without touching `$HOME` or the filesystem.
fn describe_credentials(report: &CredReport) -> String {
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
            HostCred::Unreadable { why } => format!("UNUSABLE - {why}"),
            HostCred::Present {
                expires_at_ms: None,
            } => "ok".to_string(),
            HostCred::Present {
                expires_at_ms: Some(exp),
            } => format!("ok ({})", describe_expiry(*exp, report.now_ms)),
        };
        out.push_str(&format!(
            "{label:<width$}  {path}\n{:width$}  {detail}\n",
            ""
        ));
    }

    match &report.project {
        None => out.push_str("\n==> this project: <cwd could not be resolved>\n"),
        Some(project) => {
            out.push_str(&format!(
                "\n==> this project\ndir:      {}\nstate:    {}\ncaptured: {}\nguest Claude cred file: {}\n",
                project.dir,
                project.state_dir,
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

/// Render the tool-configuration section. Consumes its input so it can build
/// the owned [`crate::config::LaunchCatalog`] (the merge result plus the
/// built-in `shell` fallback) that `--help` also renders — the two therefore
/// cannot disagree about the verb list. Returns the section text plus the
/// catalog-build failure, if any, so the caller can fail the exit code rather
/// than print an error and still report success. Pure over its input so the
/// wording is unit-tested without a real filesystem, mirroring
/// [`describe_home`]/[`describe_credentials`].
///
/// The verb list is authoritative; the *layer chain* is rendered from each
/// tool's declared `layer` as written — `doctor` never resolves an anchor,
/// checks existence, or builds it ([`crate::tool_layer`] does, at launch, per
/// #84) — and it shows argument *counts* rather than values (a user may have
/// mistakenly put a secret in `args`). Untrusted names/paths are escaped so a
/// config file cannot inject terminal controls.
fn describe_config(report: ConfigReport) -> (String, Option<anyhow::Error>) {
    // Everything that needs a borrow is rendered before `report` is consumed
    // by `into_launch_catalog`.
    let tiers = format!(
        "user:    {}\nproject: {}\n",
        describe_tier(report.user()),
        describe_tier(report.project()),
    );
    let resolved_label = if report.uses_defaults() {
        // The verb order is the catalog order, which is exactly the tool-layer
        // chain order #84 composes (`LaunchCatalog::declared_layers`).
        "resolved: built-in defaults; launch-verb / tool-layer order\n"
    } else {
        "resolved: declared tools; launch-verb / tool-layer order\n"
    };
    let conflicts = render_conflicts(report.conflicts());

    let mut out = String::from("==> tool configuration\n");
    out.push_str(&tiers);
    out.push_str(resolved_label);
    let failure = match report.into_launch_catalog() {
        Ok(catalog) => {
            for (index, entry) in catalog.as_slice().iter().enumerate() {
                out.push_str(&format!(
                    "  {}. {}\n",
                    index + 1,
                    describe_tool(entry.tool(), entry.provisioned())
                ));
            }
            if catalog.shell_fallback_added() {
                out.push_str(
                    "note: `shell` was not declared; the built-in fallback is registered so you\n\
                     still have a way into the guest.\n",
                );
            }
            None
        }
        // A dangling `tools` reference lands here, as does an internally broken
        // embedded default. Both are reported in-band so the rest of `doctor`
        // still renders.
        Err(error) => {
            out.push_str(&format!("error: {error:#}\n"));
            Some(error)
        }
    };
    out.push_str(&conflicts);
    // Drop the final newline: the caller adds one via `writeln!`.
    out.truncate(out.trim_end_matches('\n').len());
    (out, failure)
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
            crate::config::escape_path(conflict.user_file()),
            crate::config::escape_path(conflict.project_file()),
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
                .map_or("<unknown>".to_string(), crate::config::escape_path)
        ),
        TierStatus::Found { declared_tools } => format!(
            "{} (found, {declared_tools} tool{})",
            tier.path()
                .map_or("<unknown>".to_string(), crate::config::escape_path),
            if *declared_tools == 1 { "" } else { "s" },
        ),
    }
}

fn describe_tool(tool: &Tool, provisioned: ProviderSet) -> String {
    let layer = match tool.layer() {
        None => "none".to_string(),
        Some(ToolLayer::Builtin(builtin)) => format!("builtin:{}", builtin.as_str()),
        Some(ToolLayer::Path(path)) => {
            format!("path:{}", crate::config::escape_path(path.as_path()))
        }
    };
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
        ToolOrigin::User(file) => format!("user:{}", crate::config::escape_path(file)),
        ToolOrigin::Project(file) => format!("project:{}", crate::config::escape_path(file)),
    };
    // Only surfaced when true, so the default-config rows for the five agents
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
    format!(
        "{} -> \"{}\"; args={}; layer={layer}; credentials={credentials}; \
         provisions={provisions}; persist={}; source={source}{interactive_shell}{env}",
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
    std::fs::rename(&db, &target)
        .with_context(|| format!("moving {} -> {}", db.display(), target.display()))?;
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
fn render(outcome: &ResetOutcome) -> String {
    match outcome {
        ResetOutcome::Moved { from, to } => format!(
            "==> Moved microsandbox db aside (nothing was deleted)\n\
             from: {}\n\
             to:   {}\n\
             The database will be recreated at the bundled schema on the next \
             `agent-vm shell`/`run`, and images will be re-pulled on first boot.\n\
             To undo: mv \"{}\" \"{}\"",
            from.display(),
            to.display(),
            to.display(),
            from.display(),
        ),
        ResetOutcome::NothingToMove { checked } => format!(
            "==> No microsandbox db to reset — nothing was moved.\n\
             checked: {}\n\
             A fresh database will be created on the next `agent-vm shell`/`run`.",
            checked.display(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    fn report(hosts: Vec<(&'static str, String, HostCred)>) -> CredReport {
        CredReport {
            hosts,
            project: Some(ProjectCreds {
                dir: "/p".into(),
                state_dir: "/s/abc".into(),
                captured: vec!["claude"],
                guest_claude_placeholder: true,
                pi_credentials: PiCredentialReport::uninspected(),
            }),
            now_ms: 0,
        }
    }

    #[test]
    fn render_flags_an_unusable_host_credential_and_always_names_the_host_login() {
        let text = describe_credentials(&report(vec![
            (
                "claude",
                "/h/.claude/.credentials.json".into(),
                HostCred::Unreadable {
                    why: "not valid JSON: x".into(),
                },
            ),
            ("codex", "/h/.codex/auth.json".into(), HostCred::Missing),
        ]));

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
            "/h/.claude/.credentials.json".into(),
            HostCred::Present {
                expires_at_ms: Some(HOUR_MS),
            },
        )]);
        r.project.as_mut().unwrap().captured.clear();
        r.project.as_mut().unwrap().guest_claude_placeholder = false;

        let text = describe_credentials(&r);

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
        })
        .expect("fixture config should load")
    }

    #[test]
    fn describe_config_lists_defaults_in_order_and_shows_argument_counts_only() {
        let dir = tempfile::tempdir().unwrap();
        let report = config_report(None, &dir.path().join("absent.toml"));

        let (text, _) = describe_config(report);

        // The verb list is authoritative now; the header must not claim it is
        // "diagnostic only" (the pre-#82 wording), and the default catalog
        // declares `shell`, so no fallback note appears.
        assert!(text.starts_with("==> tool configuration\n"), "{text}");
        assert!(!text.contains("diagnostic only"), "{text}");
        assert!(!text.contains("was not declared"), "{text}");
        assert!(text.contains("<no HOME; user tier unavailable>"), "{text}");
        assert!(text.contains("built-in defaults"), "{text}");

        let pi = text.find("1. pi").expect("pi row");
        let codex = text.find("2. codex").expect("codex row");
        let opencode = text.find("3. opencode").expect("opencode row");
        let claude = text.find("4. claude").expect("claude row");
        assert!(
            pi < codex && codex < opencode && opencode < claude,
            "{text}"
        );

        assert!(
            text.contains(
                "shell -> \"bash\"; args=2; layer=none; credentials=none; provisions=anthropic,openai,opencode-static,copilot; persist=0; source=built-in; interactive_shell=true; env=1"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "codex -> \"codex\"; args=0; layer=builtin:codex; credentials=openai; provisions=openai; persist=0; source=built-in; env=1"
            ),
            "{text}"
        );
        assert!(text.contains("claude -> \"claude\"; args=1;"), "{text}");
        // `claude` declares no `env`, so its row must stay byte-identical —
        // no `; env=0` suffix. V7 (D6/D7).
        assert!(
            !text.contains(
                "claude -> \"claude\"; args=1; layer=builtin:claude; credentials=anthropic; provisions=anthropic; persist=0; source=built-in; env"
            ),
            "{text}"
        );
    }

    /// **V7 (D6).** An `env` *value* is never rendered — only its count is —
    /// so a credential a user pasted into `env` cannot leak through `doctor`.
    /// The suffix renders only when nonzero, and goes after `interactive_shell`.
    #[test]
    fn describe_tool_shows_only_the_env_count_never_a_value() {
        let dir = tempfile::tempdir().unwrap();
        let user = dir.path().join("user.toml");
        std::fs::write(
            &user,
            "[[tools]]\nname = \"secret\"\ncommand = \"secret\"\nenv = { TOKEN = \"sk-secret\" }\n",
        )
        .unwrap();
        let report = config_report(Some(&user), &dir.path().join("absent.toml"));

        let (text, _) = describe_config(report);
        assert!(
            text.contains(
                "secret -> \"secret\"; args=0; layer=none; credentials=none; provisions=none; persist=0; source=user:"
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

        let (text, _) = describe_config(report);
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

        let (text, _) = describe_config(report);
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

        let (text, _) = describe_config(report);
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

        let (text, _) = describe_config(report);
        assert!(!text.contains('\x1b'), "raw ESC leaked: {text:?}");
        assert!(text.contains("\\x1b"), "ESC should be escaped: {text:?}");
        assert!(
            text.contains("\\x0a"),
            "newline should be escaped: {text:?}"
        );
    }

    /// A *resolved row* is not only paths: `command` and `layer.path` accept
    /// every byte except NUL, so they too can carry terminal controls. Both
    /// are escaped the same way; this pins the renderer that a hostile project
    /// config cannot inject an ANSI escape or split the report with a newline.
    #[test]
    fn describe_config_escapes_control_bytes_in_a_command_and_layer_path() {
        let dir = tempfile::tempdir().unwrap();
        let user = dir.path().join("user.toml");
        std::fs::write(
            &user,
            "[[tools]]\nname = \"t\"\ncommand = \"evil\\u001b[31m\\nred\"\n\
             layer = { path = \"layers/\\u001b[32m\\ngrn\" }\n",
        )
        .unwrap();
        let report = config_report(Some(&user), &dir.path().join("absent.toml"));

        let (text, _) = describe_config(report);
        assert!(!text.contains('\x1b'), "raw ESC leaked: {text:?}");
        assert!(
            !text.contains("red\n"),
            "raw newline from the command leaked: {text:?}"
        );
        assert!(text.contains("evil\\x1b[31m\\x0ared"), "{text}");
        assert!(text.contains("layers/\\x1b[32m\\x0agrn"), "{text}");
    }
}
