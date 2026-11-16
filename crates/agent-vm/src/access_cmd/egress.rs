//! `agent-vm access egress`: one running session's effective egress, asked of
//! its launcher (#631). The launcher holds session allowances in memory only
//! (ADR-0066), so there is nothing to read when no session runs.

use anyhow::{Context as _, Result};

use super::{EgressArgs, Row, escape, is_active_label, socket_of, write_columns};
use crate::effective_egress::EffectiveEgress;
use crate::refusal::SessionId;
use crate::refusal::log::SessionsDir;
use crate::session_control::{Discovery, EgressAnswer};

const HOST_ONLY: &str =
    "agent-vm access egress runs on the host: run it there, in this project's directory";
const NO_SESSION: &str = "No running session in this project; `agent-vm access allowances` lists its recorded project allowances.";
const NOTHING_ALLOWED: &str = "All guest egress denied.";
/// `access`'s own convention for a usage error the parser cannot see.
const USAGE_ERROR: i32 = 2;
const HEADERS: [&str; 5] = ["DESTINATION", "PORTS", "VIA", "SOURCE", "STATUS"];

/// The launcher's own guest marker (`run.rs` `GUEST_ALWAYS_ENV`).
pub(super) fn in_guest(lookup: impl Fn(&str) -> Option<String>) -> bool {
    lookup("IS_SANDBOX").as_deref() == Some("1")
}

/// The guest's whole answer: one line, and a failure status, because there is
/// nothing in a guest that could answer the question.
pub(super) fn print_host_only(err: &mut impl std::io::Write) -> Result<i32> {
    writeln!(err, "{HOST_ONLY}").context("writing the host-only message")?;
    Ok(1)
}

/// One session `access egress` can name: every listed row, plus each
/// unresponsive socket the log has no record of yet.
struct Candidate {
    id: SessionId,
    label: &'static str,
}

impl Candidate {
    fn is_active(&self) -> bool {
        is_active_label(self.label)
    }
}

/// `sessions` as `access` lists them, widened by `discovery.unresponsive` IDs
/// that have no row (labelled `not responding`). Local to this command: no
/// other command's output changes.
fn candidates(sessions: &[Row], discovery: &Discovery) -> Vec<Candidate> {
    let mut candidates: Vec<Candidate> = sessions
        .iter()
        .map(|row| Candidate {
            id: row.snapshot.info.id.clone(),
            label: row.label,
        })
        .collect();
    for id in &discovery.unresponsive {
        if !candidates.iter().any(|candidate| &candidate.id == id) {
            candidates.push(Candidate {
                id: id.clone(),
                label: "not responding",
            });
        }
    }
    candidates
}

pub(super) async fn run_egress(
    dir: Option<&SessionsDir>,
    sessions: &[Row],
    discovery: &Discovery,
    args: &EgressArgs,
    out: &mut impl std::io::Write,
    err: &mut impl std::io::Write,
) -> Result<i32> {
    let candidates = candidates(sessions, discovery);
    let selected = match args.session.as_deref() {
        Some(text) => {
            let Some(id) = SessionId::parse(text) else {
                writeln!(err, "`--session` takes an 8-hex session ID")
                    .context("writing the argument error")?;
                return Ok(1);
            };
            let Some(candidate) = candidates.iter().find(|candidate| candidate.id == id) else {
                writeln!(
                    err,
                    "no session {} in this project's running sessions or refusal log",
                    escape(id.as_str())
                )
                .context("writing the unknown-session message")?;
                return Ok(1);
            };
            if !candidate.is_active() {
                writeln!(
                    err,
                    "session {} ({}) is not running; effective egress exists only while a session runs",
                    escape(id.as_str()),
                    candidate.label
                )
                .context("writing the not-running message")?;
                return Ok(1);
            }
            candidate
        }
        None => {
            let active: Vec<&Candidate> = candidates
                .iter()
                .filter(|candidate| candidate.is_active())
                .collect();
            match active.len() {
                0 => {
                    writeln!(out, "{NO_SESSION}").context("writing the no-session pointer")?;
                    return Ok(0);
                }
                1 => active[0],
                _ => {
                    let named: Vec<String> = active
                        .iter()
                        .map(|candidate| {
                            format!("{} ({})", escape(candidate.id.as_str()), candidate.label)
                        })
                        .collect();
                    writeln!(
                        err,
                        "more than one session is running: {}; name one with --session <ID>",
                        named.join(", ")
                    )
                    .context("writing the ambiguous-target message")?;
                    return Ok(USAGE_ERROR);
                }
            }
        }
    };

    // One reason, so the message's shape cannot vary by which way the answer
    // was unavailable.
    let reason = match selected.label {
        "running" => match socket_of(dir, &selected.id) {
            Some(path) => match crate::session_control::egress(&path).await {
                Ok(EgressAnswer::Egress(egress)) => {
                    for line in render(&selected.id, &egress)? {
                        writeln!(out, "{line}").context("writing the egress table")?;
                    }
                    return Ok(0);
                }
                Ok(EgressAnswer::PredatesEgress) => {
                    "its launcher predates `access egress`; relaunch it with this agent-vm"
                        .to_owned()
                }
                Err(error) => escape(&format!("{error:#}")),
            },
            None => "it has no control socket".to_owned(),
        },
        "running (no control socket)" => "it has no control socket".to_owned(),
        "not responding" => "it is not responding".to_owned(),
        // `access` lists no other active label, so reaching this is a bug in
        // `is_active_label` or in `label()`, not a session state.
        other => {
            debug_assert!(false, "an active label with no message: {other}");
            "it is not responding".to_owned()
        }
    };
    writeln!(
        err,
        "effective egress is not available for session {} ({}): {reason}",
        escape(selected.id.as_str()),
        selected.label
    )
    .context("writing the not-available message")?;
    Ok(1)
}

/// The whole printed answer, so the renderer is testable without a socket.
pub(super) fn render(id: &SessionId, egress: &EffectiveEgress) -> Result<Vec<String>> {
    let mut lines = vec![format!(
        "Session {} ({})",
        escape(id.as_str()),
        match egress.policy_revision {
            Some(revision) => format!("policy rev {revision}"),
            None => "starting".to_owned(),
        }
    )];
    if egress.rows.is_empty() {
        lines.push(NOTHING_ALLOWED.to_owned());
        return Ok(lines);
    }
    let rows: Vec<Vec<String>> = egress
        .rows
        .iter()
        .map(|row| {
            vec![
                escape(&row.destination.cell()),
                row.ports.cell(),
                row.via.as_deref().map_or_else(|| "-".to_owned(), escape),
                row.source.cell().to_owned(),
                row.status.cell(),
            ]
        })
        .collect();
    let mut table = Vec::new();
    write_columns(&mut table, &HEADERS, &rows)?;
    lines.extend(
        String::from_utf8(table)
            .context("reading the rendered table")?
            .lines()
            .map(str::to_owned),
    );
    lines.push(egress.dns.line(escape));
    let parts = egress.narrowing.parts(escape);
    if !parts.is_empty() {
        lines.push(format!("Narrowed by: {}", parts.join("; ")));
    }
    Ok(lines)
}
