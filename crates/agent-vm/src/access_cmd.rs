//! `agent-vm access` — what the sandbox refused, live and after the session.
//!
//! A thin client of the launcher's control socket plus a reader of the project's
//! refusal log: the launcher owns the feed (agent-vm#301), and this command asks
//! it. The command is deliberately offline — no msb, no image, no user config —
//! because the moment a user needs it is the moment something else is broken
//! (AC13).
//!
//! Slice 1 grants nothing. Every row says why no action exists yet, rather than
//! offering one that does not work.

use anyhow::{Context as _, Result};
use clap::Args as ClapArgs;

use crate::refusal::log::{HEARTBEAT_STALE_MS, SessionsDir};
use crate::refusal::{Destination, RefusalEntry, SessionId, SessionSnapshot};
use crate::session::ProjectSession;

/// The default window: an entry last seen within this long is shown.
const WINDOW_MS: i64 = 24 * 60 * 60 * 1000;

#[derive(ClapArgs)]
// A report flag beside a verb would be accepted, validated and then dropped: the
// verbs have their own `--session`, and `--all` means nothing to them (C1). clap
// refuses the mix instead, with `unexpected argument`.
#[command(args_conflicts_with_subcommands = true)]
pub(crate) struct Args {
    #[command(subcommand)]
    pub(crate) command: Option<AccessSubcommand>,
    /// Show one session: a live or logged 8-hex session ID
    #[arg(long, value_name = "ID")]
    pub(crate) session: Option<String>,
    /// Show every retained entry, not only the last 24 hours
    #[arg(long)]
    pub(crate) all: bool,
}

/// `agent-vm access allow|allowances|revoke`.
///
/// There is deliberately no `--all-sessions` flag anywhere: every live change is
/// target-only (D2/D4), and clap refuses one with `unexpected argument`.
#[derive(clap::Subcommand)]
pub(crate) enum AccessSubcommand {
    /// Allow one refused destination in one session (and, with --project, in
    /// this project from now on)
    Allow(AllowArgs),
    /// List recorded project allowances and live session allowances
    Allowances(AllowancesArgs),
    /// Revoke an allowance from this session and/or this project
    Revoke(RevokeArgs),
}

#[derive(ClapArgs)]
pub(crate) struct AllowArgs {
    /// The refusal ID shown in the ID column
    pub(crate) id: String,
    /// Also record it for this project, so the next launch starts with it
    #[arg(long)]
    pub(crate) project: bool,
    /// Which session: the only way to choose when the ID alone is ambiguous
    #[arg(long, value_name = "ID")]
    pub(crate) session: Option<String>,
}

#[derive(ClapArgs)]
pub(crate) struct AllowancesArgs {
    /// Show only this session's allowances
    #[arg(long, value_name = "ID")]
    pub(crate) session: Option<String>,
}

#[derive(ClapArgs)]
pub(crate) struct RevokeArgs {
    /// The allowance to revoke, spelled as agent-vm records it
    pub(crate) destination: String,
    /// Remove only the project record
    #[arg(long, conflicts_with = "session_only")]
    pub(crate) project: bool,
    /// Remove only this session's in-memory allowance
    #[arg(long)]
    pub(crate) session_only: bool,
    /// Which session, when more than one is active
    #[arg(long, value_name = "ID")]
    pub(crate) session: Option<String>,
}

/// Run the command, returning the process status.
///
/// This is the only place a runtime is built: `run_in` is async so a test can
/// drive the whole command — selection, rendering and exit status — in-process,
/// against a real server and a real log, without a second `run_with_timeout`
/// copy (#514).
pub(crate) fn run(args: Args) -> Result<i32> {
    #[allow(clippy::disallowed_methods)] // one capture per command: every consumer borrows it.
    let project = crate::project::ProjectDir::capture()?;
    let session = ProjectSession::for_project(&project)?;
    // `SessionsDir::open` never creates: asking what a project refused must not
    // bring the store that would answer it into existence. A directory that
    // exists but is not host-only is a real error, because its answer would be a
    // store another user can write.
    let dir = SessionsDir::open(&session.sessions_dir())
        .with_context(|| format!("reading {}", crate::one_line::path(&session.sessions_dir())))?;
    // The project's recorded allowances, read once and before the runtime is
    // built: this command is offline, and a broken store must not stop a user
    // reading what the sandbox refused (ADR-0065).
    let allowances = crate::allowances::host_view(&crate::image_pin::ProjectId::of(&project));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the access runtime")?;
    let mut out = std::io::stdout();
    let mut err = std::io::stderr();
    runtime.block_on(run_in(
        dir.as_ref(),
        &project,
        &args,
        &allowances,
        crate::refusal::feed::now_ms(),
        &mut out,
        &mut err,
    ))
}

/// The command's whole decision, with its clock and its sinks injected.
pub(crate) async fn run_in(
    dir: Option<&SessionsDir>,
    project: &crate::project::ProjectDir,
    args: &Args,
    allowances: &crate::allowances::ProjectView,
    now_ms: i64,
    out: &mut impl std::io::Write,
    err: &mut impl std::io::Write,
) -> Result<i32> {
    let wanted = match args.session.as_deref() {
        Some(text) => Some(
            SessionId::parse(text)
                .ok_or_else(|| anyhow::anyhow!("`--session` takes an 8-hex session ID"))?,
        ),
        None => None,
    };
    let discovery = match dir {
        Some(dir) => crate::session_control::discover(dir, now_ms).await,
        None => crate::session_control::Discovery {
            live: Vec::new(),
            logged: Vec::new(),
            unresponsive: Vec::new(),
            live_allowances: Vec::new(),
            evicted_sessions: 0,
            warnings: Vec::new(),
        },
    };
    for warning in &discovery.warnings {
        writeln!(err, "warning: {warning}").context("writing a warning")?;
    }
    // One warning for a store that is not in force, with the discovery
    // warnings: a row that says "not confirmed" must not be the only trace of a
    // store this build could not read.
    if let Some(notice) = allowances.notice() {
        writeln!(err, "warning: {notice}").context("writing the store warning")?;
    }

    // Live wins over logged for the same session: the live snapshot is the one
    // that has kept moving.
    let unresponsive: Vec<&str> = discovery
        .unresponsive
        .iter()
        .map(SessionId::as_str)
        .collect();
    let mut sessions: Vec<Row> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for snapshot in discovery.live.iter().chain(discovery.logged.iter()) {
        let id = snapshot.info.id.as_str().to_owned();
        if seen.contains(&id) {
            continue;
        }
        seen.push(id.clone());
        let label = label(
            snapshot,
            discovery
                .live
                .iter()
                .any(|live| live.info.id == snapshot.info.id),
            unresponsive.contains(&id.as_str()),
            now_ms,
        );
        sessions.push(Row {
            snapshot: snapshot.clone(),
            label,
        });
    }
    match &args.command {
        Some(AccessSubcommand::Allow(allow)) => {
            return run_allow(dir, project, allowances, &sessions, allow, out, err).await;
        }
        Some(AccessSubcommand::Allowances(list)) => {
            return run_allowances(allowances, &discovery, &sessions, list, out, err);
        }
        Some(AccessSubcommand::Revoke(revoke)) => {
            return run_revoke(dir, project, allowances, &sessions, revoke, out, err).await;
        }
        None => {}
    }
    if let Some(wanted) = &wanted {
        if !sessions.iter().any(|row| row.snapshot.info.id == *wanted) {
            writeln!(
                err,
                "no session {} in this project's running sessions or refusal log",
                wanted.as_str()
            )
            .context("writing the unknown-session message")?;
            return Ok(1);
        }
        // A named session is shown whole: `--session` is a question about one
        // session, not a window over it.
        sessions.retain(|row| row.snapshot.info.id == *wanted);
    }
    // The window selects *entries*, never sessions. A session with only counters
    // to report — `suppressed`, `lost`, or a gap — has no row at all, and dropping
    // it here would drop its footer with it; and a session whose every entry is
    // old still owns those entries, so it has to be counted as "K older".

    let window = now_ms - WINDOW_MS;
    let mut entries: Vec<(Row, RefusalEntry)> = Vec::new();
    let mut older = 0usize;
    for row in &sessions {
        for entry in &row.snapshot.entries {
            if args.all || wanted.is_some() || entry.last_ms >= window {
                entries.push((row.clone(), entry.clone()));
            } else {
                older += 1;
            }
        }
    }
    entries.sort_by(|(a_row, a), (b_row, b)| {
        a_row
            .snapshot
            .info
            .started_ms
            .cmp(&b_row.snapshot.info.started_ms)
            .then_with(|| b.last_ms.cmp(&a.last_ms))
            .then_with(|| a.id.cmp(&b.id))
    });

    if entries.is_empty() {
        writeln!(out, "No refusals in the last 24 hours.").context("writing the empty report")?;
        // `older` is not zero here: a session whose every entry is outside the
        // window is exactly the case with no rows and a count to report.
        print_footers(out, &sessions, &discovery, args, older)?;
        return Ok(0);
    }
    let live: std::collections::BTreeMap<String, crate::allowances::SessionAllowancesSnapshot> =
        discovery
            .live_allowances
            .iter()
            .map(|(id, snapshot)| (id.as_str().to_owned(), snapshot.clone()))
            .collect();
    print_table(out, &entries, allowances, &live)?;
    print_footers(out, &sessions, &discovery, args, older)?;
    Ok(0)
}

/// One session's row group: the snapshot and the label its entries carry.
#[derive(Clone)]
struct Row {
    snapshot: SessionSnapshot,
    label: &'static str,
}

/// §5's session column, one rule.
fn label(
    snapshot: &SessionSnapshot,
    answered: bool,
    unresponsive: bool,
    now_ms: i64,
) -> &'static str {
    if answered {
        return "running";
    }
    if unresponsive {
        return "not responding";
    }
    if snapshot.ended_ms.is_some() {
        return "ended";
    }
    let fresh = snapshot
        .heartbeat_ms
        .is_some_and(|beat| now_ms.saturating_sub(beat) <= HEARTBEAT_STALE_MS);
    if !snapshot.info.socket && fresh {
        // Bound no socket, and the feed is still beating: the session is alive.
        return "running (no control socket)";
    }
    "ended (unclean)"
}

/// The table, with every cell escaped where it is built.
///
/// Each *field* is escaped at the point it enters a cell rather than the finished
/// cell being escaped: the columns are joined by the `·` separator and padded to a
/// width, and escaping the whole cell would turn that separator into a byte
/// escape and break the alignment. Only the host user writes these values under
/// the guard, but the documented upgrade path admits launchers that leave
/// `.sessions` writable to their guests, so a forged record must not be able to
/// put terminal escapes on the user's terminal (AC5). A credential refusal's
/// credential is escaped inside `RefusalEntry::reason` for the same reason.
fn print_table(
    out: &mut impl std::io::Write,
    entries: &[(Row, RefusalEntry)],
    allowances: &crate::allowances::ProjectView,
    live: &std::collections::BTreeMap<String, crate::allowances::SessionAllowancesSnapshot>,
) -> Result<()> {
    let rows: Vec<[String; 7]> = entries
        .iter()
        .map(|(row, entry)| {
            [
                escape(&entry.id),
                entry.key.kind.label().to_owned(),
                destination(entry),
                entry.count.to_string(),
                last_seen(entry.last_ms),
                row.label.to_owned(),
                action(entry, allowances, live.get(row.snapshot.info.id.as_str())),
            ]
        })
        .collect();
    let headers = [
        "ID",
        "KIND",
        "DESTINATION",
        "COUNT",
        "LAST-SEEN",
        "SESSION",
        "ACTION",
    ];
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in &rows {
        for (index, cell) in row.iter().enumerate() {
            widths[index] = widths[index].max(cell.chars().count());
        }
    }
    let render = |cells: &[String]| -> String {
        let mut line = String::new();
        for (index, cell) in cells.iter().enumerate() {
            if index + 1 == cells.len() {
                line.push_str(cell);
            } else {
                line.push_str(&format!("{:<width$}  ", cell, width = widths[index]));
            }
        }
        line.trim_end().to_owned()
    };
    let header_cells: Vec<String> = headers.iter().map(|h| (*h).to_owned()).collect();
    writeln!(out, "{}", render(&header_cells)).context("writing the table header")?;
    for row in &rows {
        writeln!(out, "{}", render(row)).context("writing a table row")?;
    }
    Ok(())
}

/// §6.6's three destination forms.
///
/// The destination is what an allowance would have to name, so it comes first and
/// the guest's name is evidence after it — never the other way round. A name that
/// is already in the destination is not repeated: for a hostname destination the
/// evidence contributes only its source.
fn destination(entry: &RefusalEntry) -> String {
    let evidence = |name: &crate::refusal::GuestName| {
        format!(
            "({}, guest-supplied){}",
            escape(source_label(&name.source)),
            if name.truncated {
                " [name truncated]"
            } else {
                ""
            }
        )
    };
    match &entry.key.destination {
        Destination::DnsName { name } => {
            let mut text = format!("dns {}", escape(name));
            if let Some(name) = &entry.name {
                text.push_str(&format!(" {}", evidence(name)));
            }
            text
        }
        Destination::Host {
            protocol,
            name,
            port,
        } => {
            // The name is guest text and the protocol is the runtime's, so they
            // are escaped separately: the `:port` between them is this table's.
            let mut text = match port {
                Some(port) => format!("{} {}:{port}", escape(protocol), escape(name)),
                None => format!("{} {}", escape(protocol), escape(name)),
            };
            if let Some(evidence_name) = &entry.name {
                // The destination already names it; only a *different* spelling
                // the guest used is worth printing.
                if !evidence_name.name.eq_ignore_ascii_case(name) {
                    text.push_str(&format!(" {}", escape(&evidence_name.name)));
                }
                text.push_str(&format!(" {}", evidence(evidence_name)));
            }
            if let Some(ip) = entry.last_ip {
                text.push_str(&format!(" · last IP {ip}"));
            }
            text
        }
        Destination::Address { protocol, ip, port } => {
            let target = match (ip, port) {
                (Some(ip), Some(port)) => format!("{ip}:{port}"),
                (Some(ip), None) => ip.to_string(),
                (None, Some(port)) => format!("?{port}"),
                (None, None) => "?".to_owned(),
            };
            let mut text = format!("{} {target}", escape(protocol));
            if let Some(evidence_name) = &entry.name {
                text.push_str(&format!(
                    " · {} {}",
                    escape(&evidence_name.name),
                    evidence(evidence_name)
                ));
            }
            text
        }
    }
}

/// Untrusted text, rendered so no terminal control byte can reach the screen.
fn escape(text: &str) -> String {
    crate::config::escape_str(text)
}

/// The runtime's `name_source` wire value, in the table's own words. An unknown
/// value is the runtime's own text, so it is escaped by the caller.
fn source_label(source: &str) -> &str {
    match source {
        "dns-cache" => "DNS cache",
        "sni" => "SNI",
        "http-host" => "HTTP host",
        "dns-query" => "DNS query",
        other => other,
    }
}

/// UTC, minute precision: a refusal's last sighting does not need seconds.
fn last_seen(ms: i64) -> String {
    crate::allowances::recorded_at(ms)
}

/// ADR-0066 §5's demoted sentence, written once.
///
/// It is a contract, not a string: a `--project` grant the runtime applied and the
/// store could not record must read the same way in the immediate reply and in
/// every later `access` row, and no copy may quietly drop the "not recorded" fact.
/// Five copies of it were how the drift started (C-M1).
fn demoted_sentence(destination: &str, recorded_ms: i64, revision: u64, error: &str) -> String {
    format!(
        "applied session allowance {} ({}); applied to this session only (rev {revision}), not recorded for the project: {}",
        escape(destination),
        last_seen(recorded_ms),
        escape(error)
    )
}

/// One live entry's STATUS cell, in the same words as [`demoted_sentence`].
fn live_status(item: &crate::allowances::WireAllowance) -> String {
    match (item.revision, &item.not_recorded_error) {
        (Some(revision), Some(error)) => format!(
            "applied to this session only (rev {revision}), not recorded for the project: {}",
            escape(error)
        ),
        (Some(revision), None) => format!("applied (rev {revision})"),
        (None, _) => "accepted; applied when the session finishes starting".to_owned(),
    }
}

/// §5's ACTION column: why nothing can be done, or which allowance names this
/// destination and whether this session confirmed it.
///
/// "Recorded" is a fact about a file; "applied" is a fact about a runtime. The
/// live allowance snapshot is the only evidence for the second, so a row with no
/// snapshot never claims it (ADR-0065 P5).
fn action(
    entry: &RefusalEntry,
    allowances: &crate::allowances::ProjectView,
    live: Option<&crate::allowances::SessionAllowancesSnapshot>,
) -> String {
    use crate::allowances::{AllowanceScope, Coverage};
    match allowances.covers_in_session(entry, live) {
        Some(Coverage::Applied {
            scope,
            destination,
            recorded_ms,
            revision,
            not_recorded_error: None,
        }) => format!(
            "applied {} allowance {} ({}); allowed in this session (rev {revision})",
            match scope {
                AllowanceScope::Session => "session",
                AllowanceScope::Project => "project",
            },
            escape(&destination.to_string()),
            last_seen(recorded_ms),
        ),
        // A `--project` grant the runtime applied but the store could not record:
        // it is in force, and the row must never say it was recorded (Ruling 2).
        Some(Coverage::Applied {
            destination,
            recorded_ms,
            revision,
            not_recorded_error: Some(error),
            ..
        }) => demoted_sentence(&destination.to_string(), recorded_ms, revision, &error),
        Some(Coverage::Recorded(record)) => format!(
            "recorded project allowance {} ({}); not confirmed for this session",
            escape(&record.destination().to_string()),
            last_seen(record.recorded_ms())
        ),
        None => entry.reason(),
    }
}

/// The footers: everything the table cannot show as a row (AC6).
fn print_footers(
    out: &mut impl std::io::Write,
    sessions: &[Row],
    discovery: &crate::session_control::Discovery,
    args: &Args,
    older: usize,
) -> Result<()> {
    for row in sessions {
        let snapshot = &row.snapshot;
        let id = crate::config::escape_str(snapshot.info.id.as_str());
        if snapshot.suppressed > 0 {
            writeln!(
                out,
                "session {id}: {} refusal(s) were not recorded by the runtime (suppressed)",
                snapshot.suppressed
            )
            .context("writing the suppressed footer")?;
        }
        if snapshot.lost > 0 {
            // One `lost` per refusal that could not be kept, which is one per
            // destination past the per-session limit; the footer says which.
            writeln!(
                out,
                "session {id}: {} refusal(s) to destinations beyond the per-session limit were \
                 dropped (lost)",
                snapshot.lost
            )
            .context("writing the lost footer")?;
        }
        if snapshot.gap {
            writeln!(
                out,
                "session {id}: some refusals were missed (count unknown)"
            )
            .context("writing the gap footer")?;
        }
    }
    if discovery.evicted_sessions > 0 {
        writeln!(
            out,
            "{} session(s) were evicted from the refusal log to keep it bounded",
            discovery.evicted_sessions
        )
        .context("writing the eviction footer")?;
    }
    // The same 8-hex ID in two sessions is flagged, never renamed: an ID is
    // assigned once and stays stable for the reader who copied it.
    let mut shared: Vec<String> = Vec::new();
    for (index, a) in sessions.iter().enumerate() {
        for b in &sessions[index + 1..] {
            for id in a.snapshot.ids() {
                if b.snapshot.ids().any(|other| other == id) && !shared.iter().any(|s| s == id) {
                    shared.push(id.to_owned());
                }
            }
        }
    }
    if !shared.is_empty() {
        shared.sort();
        writeln!(
            out,
            "the same refusal ID appears in more than one session: {}",
            shared.join(", ")
        )
        .context("writing the shared-ID footer")?;
    }
    if older > 0 && !args.all {
        writeln!(
            out,
            "Showing the last 24 hours; --all shows the whole log ({older} older)"
        )
        .context("writing the window footer")?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// `access allow`, `access allowances`, `access revoke` (PR 2)
// ---------------------------------------------------------------------------

/// One sibling line: every other session in the project, with its state, and the
/// fact that a live change is target-only (D2, AC8).
fn sibling_line(
    before: bool,
    sessions: &[Row],
    target: Option<&SessionId>,
    action: &str,
) -> Option<String> {
    let siblings: Vec<String> = sessions
        .iter()
        .filter(|row| target.is_none_or(|target| row.snapshot.info.id != *target))
        .map(|row| format!("{} ({})", escape(row.snapshot.info.id.as_str()), row.label))
        .collect();
    if siblings.is_empty() {
        return None;
    }
    let listed = siblings.join(", ");
    Some(if before {
        format!("sibling sessions (not targeted; unchanged until relaunch): {listed}")
    } else {
        format!("sibling sessions still unchanged until relaunch ({action}): {listed}")
    })
}

fn print_siblings_before(
    out: &mut impl std::io::Write,
    sessions: &[Row],
    target: Option<&SessionId>,
) -> Result<()> {
    if let Some(line) = sibling_line(true, sessions, target, "") {
        writeln!(out, "{line}").context("writing the sibling line")?;
    }
    Ok(())
}

fn print_siblings_after(
    out: &mut impl std::io::Write,
    sessions: &[Row],
    target: Option<&SessionId>,
    action: &str,
) -> Result<()> {
    if let Some(line) = sibling_line(false, sessions, target, action) {
        writeln!(out, "{line}").context("writing the sibling line")?;
    }
    Ok(())
}

/// The socket path for one session, when the sessions directory exists.
fn socket_of(dir: Option<&SessionsDir>, id: &SessionId) -> Option<std::path::PathBuf> {
    dir.map(|dir| dir.socket_path(id))
}

fn describe_session(id: &SessionId, label: &str) -> String {
    format!("session {} ({label})", escape(id.as_str()))
}

/// `(policy revision N)`, or nothing at all when no policy change was made.
///
/// A revoke of an entry that was never in force calls no runtime, so it has no
/// revision to report; claiming one is the overstatement A-m01 names.
fn revision_clause(revision: Option<u64>) -> String {
    revision
        .map(|revision| format!(" (policy revision {revision})"))
        .unwrap_or_default()
}

/// `agent-vm access allow <ID> [--project]`.
async fn run_allow(
    dir: Option<&SessionsDir>,
    project: &crate::project::ProjectDir,
    allowances: &crate::allowances::ProjectView,
    sessions: &[Row],
    args: &AllowArgs,
    out: &mut impl std::io::Write,
    err: &mut impl std::io::Write,
) -> Result<i32> {
    // Every entry, no window: the moment a user needs to allow something is
    // exactly the moment its refusal may be older than 24 hours (m2).
    let found = sessions.iter().find_map(|row| {
        row.snapshot
            .entries
            .iter()
            .find(|entry| entry.id == args.id)
            .map(|entry| (row.clone(), entry.clone()))
    });
    let Some((row, entry)) = found else {
        writeln!(
            err,
            "no refusal {} in this project's running sessions or refusal log",
            escape(&args.id)
        )
        .context("writing the unknown-refusal message")?;
        return Ok(1);
    };
    if let Some(wanted) = &args.session
        && wanted != row.snapshot.info.id.as_str()
    {
        writeln!(
            err,
            "refusal {} belongs to {}, not to --session {}",
            escape(&args.id),
            escape(row.snapshot.info.id.as_str()),
            escape(wanted)
        )
        .context("writing the session mismatch")?;
        return Ok(1);
    }
    let destination = match crate::allowances::grantable_destination(&entry) {
        Ok(destination) => destination,
        Err(reason) => {
            writeln!(
                err,
                "cannot allow {}: {}",
                escape(&args.id),
                escape(&reason.line())
            )
            .context("writing the refusal reason")?;
            return Ok(1);
        }
    };
    let scope = if args.project {
        crate::allowances::GrantScope::Project
    } else {
        crate::allowances::GrantScope::Session
    };
    let id = row.snapshot.info.id.clone();
    print_siblings_before(out, sessions, Some(&id))?;
    let now_ms = crate::refusal::feed::now_ms();
    let spelled = destination.to_string();

    let code = match row.label {
        "running" => match socket_of(dir, &id) {
            Some(path) => match crate::session_control::grant(&path, Some(&spelled), scope).await {
                Ok(result) => report_grant(out, err, &id, scope, result)?,
                Err(error) => {
                    writeln!(
                        err,
                        "could not reach {}: {}; nothing was recorded",
                        describe_session(&id, row.label),
                        escape(&format!("{error:#}"))
                    )
                    .context("writing the socket failure")?;
                    1
                }
            },
            None => {
                writeln!(
                    err,
                    "{} has no control socket; nothing was recorded",
                    describe_session(&id, row.label)
                )
                .context("writing the no-socket message")?;
                1
            }
        },
        "ended" | "ended (unclean)" => {
            if scope == crate::allowances::GrantScope::Session {
                writeln!(
                    err,
                    "{} has ended, so a session-only allowance cannot be recorded; \
                     relaunch it and allow the destination again",
                    describe_session(&id, row.label)
                )
                .context("writing the ended-session refusal")?;
                1
            } else {
                match allowances.record_async(project, &destination, now_ms).await {
                    Ok(record) => {
                        writeln!(
                            out,
                            "recorded project allowance {} ({}); the next launch of this project applies it",
                            escape(&record.destination().to_string()),
                            last_seen(record.recorded_ms())
                        )
                        .context("writing the recorded allowance")?;
                        0
                    }
                    Err(error) => {
                        writeln!(
                            err,
                            "could not record the project allowance: {}",
                            escape(&error.to_string())
                        )
                        .context("writing the store failure")?;
                        1
                    }
                }
            }
        }
        _ => {
            // `not responding`, `running (no control socket)`: a live session
            // that cannot confirm must not be reported as if it had.
            writeln!(
                err,
                "{} cannot confirm a live change; nothing was recorded. Relaunch the session \
                 and allow the destination again",
                describe_session(&id, row.label)
            )
            .context("writing the unresponsive-session message")?;
            1
        }
    };
    print_siblings_after(
        out,
        sessions,
        Some(&id),
        if scope == crate::allowances::GrantScope::Session {
            "running siblings keep refusing until relaunched"
        } else {
            "running siblings keep refusing until relaunched; the record reaches them then"
        },
    )?;
    Ok(code)
}

/// One `GrantResult`, in the user's words, with its exit status.
fn report_grant(
    out: &mut impl std::io::Write,
    err: &mut impl std::io::Write,
    id: &SessionId,
    scope: crate::allowances::GrantScope,
    result: crate::allowances::GrantResult,
) -> Result<i32> {
    use crate::allowances::{GrantRefusalReason, GrantResult, NextLaunchReason};
    match result {
        GrantResult::Applied {
            destination,
            revision,
            recorded_ms,
            ..
        } => {
            let destination = escape(&destination);
            match scope {
                crate::allowances::GrantScope::Session => writeln!(
                    out,
                    "allowed {destination} for {} (policy revision {revision})",
                    describe_session(id, "running")
                ),
                crate::allowances::GrantScope::Project => writeln!(
                    out,
                    "allowed {destination} for {} (policy revision {revision}) and recorded for this project ({})",
                    describe_session(id, "running"),
                    last_seen(recorded_ms)
                ),
            }
            .context("writing the grant reply")?;
            Ok(0)
        }
        GrantResult::AppliedNotRecorded {
            destination,
            revision,
            recorded_ms,
            message,
        } => {
            writeln!(
                err,
                "{}",
                demoted_sentence(&destination, recorded_ms, revision, &message)
            )
            .context("writing the demoted grant")?;
            Ok(1)
        }
        GrantResult::NextLaunch {
            destination,
            recorded_ms,
            reason,
        } => {
            let destination = escape(&destination);
            let why = match reason {
                NextLaunchReason::RuntimeUnsupported => {
                    "this runtime cannot replace its network policy while it runs"
                }
                NextLaunchReason::InterceptedPortsFixedAtLaunch => {
                    "TLS-intercepted ports are fixed at launch, so this allowance applies at the next launch"
                }
            };
            writeln!(
                out,
                "recorded {destination} for this project ({}); {why}",
                last_seen(recorded_ms)
            )
            .context("writing the next-launch sentence")?;
            Ok(0)
        }
        GrantResult::QueuedForBoot {
            destination, scope, ..
        } => {
            // Conditional on purpose: the flush may still fail, and then the
            // session says so (Ruling 3, N3).
            let destination = escape(&destination);
            match scope {
                crate::allowances::GrantScope::Session => writeln!(
                    out,
                    "accepted {destination} for this session; applied when the session finishes starting — confirm with `agent-vm access allowances`"
                ),
                crate::allowances::GrantScope::Project => writeln!(
                    out,
                    "recorded project allowance {destination} and accepted it for this session; applied when the session finishes starting — confirm with `agent-vm access allowances`"
                ),
            }
            .context("writing the queued grant")?;
            Ok(0)
        }
        GrantResult::Refused { reason } => {
            let message = match reason {
                GrantRefusalReason::HostProxyInUse => {
                    "a host HTTP proxy is in use, so this session cannot intercept hostnames"
                        .to_owned()
                }
                GrantRefusalReason::InterceptedPortsFixedAtLaunch => {
                    "TLS-intercepted ports are fixed at launch; relaunch with this hostname to intercept it"
                        .to_owned()
                }
                GrantRefusalReason::NotAllowable { message } => message,
                GrantRefusalReason::RuntimeFailed { message } => {
                    format!("the runtime could not apply the change: {message}")
                }
                GrantRefusalReason::Store { message } => {
                    format!("the project allowance record was not written: {message}")
                }
                GrantRefusalReason::Full { limit } => format!(
                    "this session already holds {limit} live allowances, the most it can carry; revoke one first"
                ),
            };
            writeln!(err, "refused: {}", escape(&message)).context("writing the grant refusal")?;
            Ok(1)
        }
    }
}

/// `agent-vm access allowances [--session <SID>]`: the store's records and every
/// live session's allowances, with each project record's per-session status.
fn run_allowances(
    allowances: &crate::allowances::ProjectView,
    discovery: &crate::session_control::Discovery,
    sessions: &[Row],
    args: &AllowancesArgs,
    out: &mut impl std::io::Write,
    err: &mut impl std::io::Write,
) -> Result<i32> {
    let live = &discovery.live_allowances;
    let wanted = args.session.as_deref();
    // A session with an ID this command cannot parse is a real error.
    if let Some(text) = wanted
        && SessionId::parse(text).is_none()
    {
        writeln!(err, "`--session` takes an 8-hex session ID")
            .context("writing the argument error")?;
        return Ok(1);
    }
    // One stderr line per session that cannot answer, so a missing row is
    // explained rather than silently absent (AC9).
    for id in &discovery.unresponsive {
        writeln!(
            err,
            "warning: session {} is not responding; its live allowances are not shown",
            escape(id.as_str())
        )
        .context("writing the unresponsive warning")?;
    }
    for row in sessions {
        if row.label == "running (no control socket)" {
            writeln!(
                err,
                "warning: session {} has no control socket; its live allowances are not shown",
                escape(row.snapshot.info.id.as_str())
            )
            .context("writing the no-socket warning")?;
        }
    }

    let mut rows: Vec<[String; 5]> = Vec::new();
    let records: Vec<&crate::allowances::ProjectAllowance> =
        allowances.allowances().entries().iter().collect();
    let active: Vec<(String, &crate::allowances::SessionAllowancesSnapshot)> = live
        .iter()
        .filter(|(id, _)| wanted.is_none_or(|wanted| wanted == id.as_str()))
        .map(|(id, snapshot)| (id.as_str().to_owned(), snapshot))
        .collect();
    // AC9: a session that cannot answer is named in the STATUS cell too, so a row
    // that reads "not in force" says whether that is a session that has not
    // adopted it or one this command could not ask. The naming is **per session**
    // and obeys `--session`: a silence belongs to the session that could not
    // answer, and lending it to another session's row made that row claim a
    // session it never asked (D1).
    let mut silent: Vec<(String, &'static str)> = discovery
        .unresponsive
        .iter()
        .map(|id| (id.as_str().to_owned(), "not responding"))
        .collect();
    for row in sessions {
        if row.label == "running (no control socket)" {
            silent.push((
                row.snapshot.info.id.as_str().to_owned(),
                "has no control socket",
            ));
        }
    }
    silent.retain(|(id, _)| wanted.is_none_or(|wanted| wanted == id));
    for record in &records {
        let destination = record.destination().to_string();
        // "Not in force" is a fact about a session that answered. With no session
        // to ask, the row for each of them says so instead of guessing.
        if active.is_empty() && silent.is_empty() {
            rows.push([
                "project".to_owned(),
                escape(&destination),
                last_seen(record.recorded_ms()),
                "-".to_owned(),
                "not in force until relaunch".to_owned(),
            ]);
            continue;
        }
        for (id, snapshot) in &active {
            let applied = snapshot
                .project
                .iter()
                .find(|item| item.destination == destination);
            let status = match applied {
                Some(item) => live_status(item),
                None => "not in force until relaunch".to_owned(),
            };
            rows.push([
                "project".to_owned(),
                escape(&destination),
                last_seen(record.recorded_ms()),
                escape(id),
                status,
            ]);
        }
    }
    // A live project entry the store read did not list (a record written by a
    // launcher after this command read the file) is still a live allowance, so
    // it is one row rather than a silently missing one.
    let known: Vec<String> = records
        .iter()
        .map(|record| record.destination().to_string())
        .collect();
    for (id, snapshot) in &active {
        for item in &snapshot.project {
            if known
                .iter()
                .any(|destination| destination == &item.destination)
            {
                continue;
            }
            let status = live_status(item);
            rows.push([
                "project".to_owned(),
                escape(&item.destination),
                last_seen(item.granted_ms),
                escape(id),
                status,
            ]);
        }
    }

    // Session-only rows (including a demoted `--project` grant, which lives in
    // the session table and says why it is not recorded).
    for (id, snapshot) in &active {
        for item in &snapshot.session {
            let status = live_status(item);
            rows.push([
                "session".to_owned(),
                escape(&item.destination),
                last_seen(item.granted_ms),
                escape(id),
                status,
            ]);
        }
    }

    // One row per (record, session that could not be asked): AC9 asks for the
    // session to be named *in STATUS*, and this is the only attribution that is
    // both true and per session — the row's own cell names the row's own session.
    for (id, state) in &silent {
        for record in &records {
            rows.push([
                "project".to_owned(),
                escape(&record.destination().to_string()),
                last_seen(record.recorded_ms()),
                escape(id),
                format!("not shown: session {id} {state}"),
            ]);
        }
    }

    if rows.is_empty() {
        writeln!(out, "No allowances.").context("writing the empty listing")?;
        return Ok(0);
    }
    let headers = ["SCOPE", "DESTINATION", "RECORDED", "SESSION", "STATUS"];
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in &rows {
        for (index, cell) in row.iter().enumerate() {
            widths[index] = widths[index].max(cell.chars().count());
        }
    }
    let render = |cells: &[String]| -> String {
        let mut line = String::new();
        for (index, cell) in cells.iter().enumerate() {
            if index + 1 == cells.len() {
                line.push_str(cell);
            } else {
                line.push_str(&format!("{:<width$}  ", cell, width = widths[index]));
            }
        }
        line.trim_end().to_owned()
    };
    let header_cells: Vec<String> = headers.iter().map(|h| (*h).to_owned()).collect();
    writeln!(out, "{}", render(&header_cells)).context("writing the allowance header")?;
    for row in &rows {
        writeln!(out, "{}", render(row)).context("writing an allowance row")?;
    }
    Ok(0)
}

/// `agent-vm access revoke <DEST> [--project | --session-only] [--session <SID>]`.
async fn run_revoke(
    dir: Option<&SessionsDir>,
    project: &crate::project::ProjectDir,
    allowances: &crate::allowances::ProjectView,
    sessions: &[Row],
    args: &RevokeArgs,
    out: &mut impl std::io::Write,
    err: &mut impl std::io::Write,
) -> Result<i32> {
    use crate::allowances::RevokeScope;
    let Ok(destination) = crate::egress_policy::Allowance::parse(&args.destination) else {
        writeln!(
            err,
            "`{}` is not an allowance spelling",
            escape(&args.destination)
        )
        .context("writing the destination error")?;
        return Ok(1);
    };
    let scope = if args.project {
        RevokeScope::Project
    } else if args.session_only {
        RevokeScope::Session
    } else {
        RevokeScope::All
    };

    // The record is deleted **before** a target can be chosen, so an ambiguous
    // target or a session that cannot confirm cannot keep a durable grant the
    // user asked to remove (R10, V7).
    let mut removed = false;
    if matches!(scope, RevokeScope::Project | RevokeScope::All) {
        match allowances
            .forget_async(&crate::image_pin::ProjectId::of(project), &destination)
            .await
        {
            Ok(was_removed) => removed = was_removed,
            Err(error) => {
                writeln!(
                    err,
                    "could not delete the project record: {}",
                    escape(&error.to_string())
                )
                .context("writing the store failure")?;
                return Ok(1);
            }
        }
    }

    // The target: the named session, or the one active session, or none.
    let active: Vec<&Row> = sessions
        .iter()
        .filter(|row| {
            matches!(
                row.label,
                "running" | "not responding" | "running (no control socket)"
            )
        })
        .collect();
    // R11: the sibling line names every other session *before* the change, and it
    // does not depend on which session is the target — so it is printed before
    // target selection, which is what the offline path (no active session, only
    // ended siblings) was missing.
    let select_record_note = |removed: bool| -> &'static str {
        match scope {
            RevokeScope::Session => "",
            _ if removed => " (the project record was deleted)",
            _ => " (no project record named it)",
        }
    };
    let target: Option<Row> = match &args.session {
        Some(text) => match sessions
            .iter()
            .find(|row| row.snapshot.info.id.as_str() == text)
        {
            Some(row) => Some(row.clone()),
            None => {
                print_siblings_before(out, sessions, None)?;
                writeln!(
                    err,
                    "no session {} in this project's running sessions or refusal log{}",
                    escape(text),
                    select_record_note(removed)
                )
                .context("writing the unknown-session message")?;
                return Ok(1);
            }
        },
        None if active.len() > 1 => {
            let named: Vec<String> = active
                .iter()
                .map(|row| format!("{} ({})", escape(row.snapshot.info.id.as_str()), row.label))
                .collect();
            print_siblings_before(out, sessions, None)?;
            writeln!(
                err,
                "more than one session is active: {}; name one with --session <ID> or stop the others{}",
                named.join(", "),
                select_record_note(removed)
            )
            .context("writing the ambiguous-target message")?;
            return Ok(1);
        }
        None => active.first().map(|row| (*row).clone()),
    };

    let target_id = target.as_ref().map(|row| row.snapshot.info.id.clone());
    print_siblings_before(out, sessions, target_id.as_ref())?;

    let Some(target) = target else {
        let spelled = escape(&destination.to_string());
        // The offline answer depends on the scope, because the scopes touch
        // different things: `--project`/default delete the record, and
        // `--session-only` never does. Reporting "no record for … the next launch
        // starts without it" for a `--session-only` revoke claimed a deletion that
        // did not happen while the record was still on disk and `access` still
        // rendered it (D2).
        //
        // Exit `0` in both cases: for `--project`/default the record is gone, and
        // for `--session-only` the postcondition the user asked for (no session
        // holds the allowance) holds trivially with no session running — the same
        // answer a live session gets for a destination it does not hold. A
        // non-zero status would tell a script the revoke failed when nothing
        // failed, and the sentence below says exactly what did and did not change.
        match scope {
            RevokeScope::Session => writeln!(
                out,
                "no session is active, so {spelled} was not revoked from any session; \
                 the project record for this project is unchanged"
            )
            .context("writing the offline session-only revoke")?,
            RevokeScope::Project | RevokeScope::All => writeln!(
                out,
                "{} {} for this project; no session is active, so the next launch starts without it",
                if removed { "deleted" } else { "no record for" },
                spelled
            )
            .context("writing the offline revoke")?,
        }
        print_siblings_after(out, sessions, None, "no running session was changed")?;
        return Ok(0);
    };
    let id = target.snapshot.info.id.clone();
    let code;
    match target.label {
        "running" => match socket_of(dir, &id) {
            Some(path) => {
                match crate::session_control::revoke(&path, &destination.to_string(), scope).await {
                    Ok(result) => code = report_revoke(out, err, &id, removed, result)?,
                    Err(error) => {
                        let record = if removed {
                            "the project record was deleted, "
                        } else {
                            ""
                        };
                        writeln!(
                        err,
                        "could not reach {}: {}; {record}the session's in-memory allowances are unchanged. Stopping the session is the guaranteed hard cut",
                        describe_session(&id, target.label),
                        escape(&format!("{error:#}")),
                    )
                    .context("writing the socket failure")?;
                        code = 1;
                    }
                }
            }
            None => {
                let record = if removed {
                    "the project record was deleted, "
                } else {
                    ""
                };
                writeln!(
                    err,
                    "{} has no control socket; {record}the session's in-memory allowances are unchanged. Stopping the session is the guaranteed hard cut",
                    describe_session(&id, target.label)
                )
                .context("writing the no-socket message")?;
                code = 1;
            }
        },
        _ => {
            let record = if removed {
                "the project record was deleted, "
            } else {
                ""
            };
            writeln!(
                err,
                "{} cannot confirm a live revoke; {record}the session's in-memory allowances are unchanged. Stopping the session is the guaranteed hard cut",
                describe_session(&id, target.label)
            )
            .context("writing the unconfirmed message")?;
            code = 1;
        }
    }
    print_siblings_after(
        out,
        sessions,
        Some(&id),
        "running siblings keep allowing it until relaunched",
    )?;
    Ok(code)
}

/// One `RevokeResult`, in the user's words, with its exit status.
fn report_revoke(
    out: &mut impl std::io::Write,
    err: &mut impl std::io::Write,
    id: &SessionId,
    removed: bool,
    result: crate::allowances::RevokeResult,
) -> Result<i32> {
    use crate::allowances::RevokeResult;
    match result {
        RevokeResult::Revoked {
            destination,
            revision,
            still_effective,
            ..
        } => {
            let destination = escape(&destination);
            writeln!(
                out,
                "revoked {destination} for {}{}{}",
                describe_session(id, "running"),
                revision_clause(revision),
                if removed {
                    "; the project record was deleted"
                } else {
                    ""
                }
            )
            .context("writing the revoke reply")?;
            if still_effective {
                writeln!(
                    out,
                    "{destination} is still in force from this launch's own --allow-egress or the other scope"
                )
                .context("writing the still-effective note")?;
            }
            Ok(0)
        }
        RevokeResult::NotInSession {
            destination,
            scope,
            revision,
            still_effective,
        } => {
            let destination = escape(&destination);
            // Not "not in force": the tables hold no allowance for it, but this
            // launch's own authority may well still allow it, and no runtime call
            // happened, so nothing is "confirmed" (B01).
            writeln!(
                out,
                "{destination} is not a{} allowance of {}{}{}",
                match scope {
                    crate::allowances::RevokeScope::Session => " session",
                    crate::allowances::RevokeScope::Project => " project",
                    crate::allowances::RevokeScope::All => " session or project",
                },
                describe_session(id, "running"),
                revision_clause(revision),
                if removed {
                    "; the project record was deleted"
                } else {
                    ""
                }
            )
            .context("writing the not-in-session reply")?;
            if still_effective {
                writeln!(
                    out,
                    "{destination} is still allowed by this launch's own --allow-egress or [network] authority, or by the other scope"
                )
                .context("writing the still-effective note")?;
            }
            Ok(0)
        }
        RevokeResult::Unconfirmed {
            destination,
            reason,
            ..
        } => {
            let destination = escape(&destination);
            writeln!(
                err,
                "{} could not confirm revoking {destination}: {}{}. Stopping the session is the guaranteed hard cut",
                describe_session(id, "running"),
                escape(&reason.line()),
                if removed {
                    " (the project record was deleted)"
                } else {
                    ""
                }
            )
            .context("writing the unconfirmed revoke")?;
            Ok(1)
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod verifier_probes;
