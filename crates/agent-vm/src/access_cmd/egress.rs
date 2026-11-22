//! `agent-vm access egress`: one running session's effective egress, asked of
//! its launcher (#631). The launcher holds session allowances in memory only
//! (ADR-0066), so there is nothing to read when no session runs.

use anyhow::{Context as _, Result};

use super::{
    EgressArgs, Row, SessionState, escape, parse_session_flag, socket_of, unknown_session,
    write_columns,
};
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
    state: SessionState,
}

impl Candidate {
    fn is_active(&self) -> bool {
        self.state.is_active()
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
            state: row.state,
        })
        .collect();
    for id in &discovery.unresponsive {
        if !candidates.iter().any(|candidate| &candidate.id == id) {
            candidates.push(Candidate {
                id: id.clone(),
                state: SessionState::NotResponding,
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
    let wanted = match parse_session_flag(args.session.as_deref(), err)? {
        Ok(wanted) => wanted,
        Err(code) => return Ok(code),
    };
    let selected = match &wanted {
        Some(wanted) => {
            let Some(candidate) = candidates.iter().find(|candidate| candidate.id == *wanted)
            else {
                return unknown_session(err, wanted);
            };
            if !candidate.is_active() {
                writeln!(
                    err,
                    "session {} ({}) is not running; effective egress exists only while a session runs",
                    escape(wanted.as_str()),
                    candidate.state.label()
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
                            format!(
                                "{} ({})",
                                escape(candidate.id.as_str()),
                                candidate.state.label()
                            )
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
    let reason = match selected.state {
        SessionState::Running => match socket_of(dir, &selected.id) {
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
                Ok(EgressAnswer::NewerLauncher) => {
                    "its launcher is newer than this agent-vm; update this agent-vm to read it"
                        .to_owned()
                }
                Err(error) => escape(&format!("{error:#}")),
            },
            None => "it has no control socket".to_owned(),
        },
        SessionState::RunningNoSocket => "it has no control socket".to_owned(),
        SessionState::NotResponding => "it is not responding".to_owned(),
        // Only an active state is selected, so an ended one is unreachable:
        // naming the two here keeps the match exhaustive, so a new state has to
        // say what its message is instead of inheriting a debug assertion.
        SessionState::Ended | SessionState::EndedUnclean => {
            debug_assert!(false, "an ended session has no live egress to ask for");
            "it is not running".to_owned()
        }
    };
    writeln!(
        err,
        "effective egress is not available for session {} ({}): {reason}",
        escape(selected.id.as_str()),
        selected.state.label()
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
