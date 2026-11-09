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
pub(crate) struct Args {
    /// Show one session: a live or logged 8-hex session ID
    #[arg(long, value_name = "ID")]
    pub(crate) session: Option<String>,
    /// Show every retained entry, not only the last 24 hours
    #[arg(long)]
    pub(crate) all: bool,
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
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the access runtime")?;
    let mut out = std::io::stdout();
    let mut err = std::io::stderr();
    runtime.block_on(run_in(
        dir.as_ref(),
        &args,
        crate::refusal::feed::now_ms(),
        &mut out,
        &mut err,
    ))
}

/// The command's whole decision, with its clock and its sinks injected.
pub(crate) async fn run_in(
    dir: Option<&SessionsDir>,
    args: &Args,
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
            evicted_sessions: 0,
            warnings: Vec::new(),
        },
    };
    for warning in &discovery.warnings {
        writeln!(err, "warning: {warning}").context("writing a warning")?;
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
    print_table(out, &entries)?;
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
/// put terminal escapes on the user's terminal (AC5).
fn print_table(out: &mut impl std::io::Write, entries: &[(Row, RefusalEntry)]) -> Result<()> {
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
                entry.reason(),
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
    let seconds = ms.div_euclid(1000);
    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}Z")
}

/// Howard Hinnant's `civil_from_days`, so the table needs no calendar crate.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = (z - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * shifted_month + 2) / 5 + 1) as u32;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    } as u32;
    if month <= 2 {
        year += 1;
    }
    (year, month, day)
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

#[cfg(test)]
mod tests;
