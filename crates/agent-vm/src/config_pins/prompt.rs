//! The interactive approval prompt for pending pinned sources (#736).
//!
//! Approval is a launch-only, foreground-only, terminal-only action (D3), so
//! this module is split in two: the sequence of decisions in [`run`], which is
//! pure over its inputs and therefore testable without a terminal, and the
//! [`ApprovalTerminal`] operations it depends on, which the real implementation
//! performs on file descriptors 0 and 2 and the tests fake.
//!
//! # What the sequence guarantees
//!
//! * The review is rendered, and refused as a whole, **before** any terminal
//!   question: a cap crossing prints the refusal and returns, so an unanswered
//!   `[y/N]` can never follow a partial diff.
//! * A source another reviewer approved between inspection and the locked diff
//!   read is dropped rather than re-asked, so a concurrent approval is not a
//!   second question.
//! * Foreground membership is verified twice: before the question is printed,
//!   and again immediately before stdin is read, because a job can be
//!   backgrounded during the write.
//! * Input is flushed immediately before the read, so bytes typed before the
//!   diff appeared cannot answer this question.
//! * [`read_answer`] reads one byte at a time and stops at the answer's LF, so
//!   nothing past the answer is consumed from the terminal.
//! * Only `y`/`yes` approves. Empty input, EOF, a control byte, a missing final
//!   newline and an over-long line all fail closed, and an absent answer is
//!   reported as [`Outcome::NoAnswer`] rather than as a decline.
//!
//! The only store state this module reads is the [`DiffState`] its caller
//! already collected; it never opens the store, prompts inside a lock, or
//! writes anything.

use std::io::{self, Read, Write};

use super::PendingSource;
use super::diff::{PendingReview, TooLarge, escape_review_line, render_review};
use super::store::DiffState;

/// Longest answer line accepted, **including** its terminating LF, so a long
/// whitespace-padded prefix can never be truncated down to its first byte.
pub(crate) const MAX_ANSWER_BYTES: usize = 64;

/// What the user's answer was, with "nothing was typed" kept apart from "no".
// The variant names are the ones spec R9 and the phase-3 plan name, and they
// are what the caller reads; renaming `NoAnswer` would only satisfy the lint.
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Answer {
    Approve,
    Decline,
    /// End of input before any byte: no question was answered at all.
    NoAnswer,
}

/// The outcome of one interactive review.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Nothing needed approval: no pending sources, or every candidate was
    /// already approved by a concurrent writer.
    NothingToReview,
    /// At least one diff crossed an interactive cap. No diff was printed, the
    /// question was never asked, and nothing was approved.
    TooLarge(TooLarge),
    Approved,
    Declined,
    NoAnswer,
}

/// The terminal operations approval needs, faked in unit tests.
pub(crate) trait ApprovalTerminal {
    /// Fails unless stdin and stderr are the same terminal and this process is
    /// its foreground process group. Fail-closed: any error or failed check is
    /// an error, never an approval.
    fn verify_foreground(&mut self) -> io::Result<()>;

    /// Discards input queued before the question, so a previously typed answer
    /// cannot answer it.
    fn discard_pending_input(&mut self) -> io::Result<()>;

    /// Reads one answer line without consuming anything past it.
    fn read_answer(&mut self) -> io::Result<Answer>;
}

/// Render one review and ask about it.
///
/// `render` is the transcript sink: production passes stderr, tests pass a
/// recorder or a writer that fails on the first byte. `state` is the review the
/// caller read under the store's `LOCK_SH`, and `pending` are the exact
/// candidate bytes inspection collected.
pub(crate) fn run(
    pending: &[PendingSource],
    state: &DiffState,
    terminal: &mut dyn ApprovalTerminal,
    render: &mut dyn Write,
) -> io::Result<Outcome> {
    let reviews: Vec<PendingReview<'_>> = pending
        .iter()
        .map(|source| PendingReview::of(source, state))
        .filter(|review| {
            // Approved while we were inspecting: the question is already
            // answered, so asking it again would be a second prompt for one
            // change.
            !state
                .current
                .is_approved(review.key, &review.candidate_hash)
        })
        .collect();
    if reviews.is_empty() {
        return Ok(Outcome::NothingToReview);
    }

    let transcript = match render_review(&reviews) {
        Ok(transcript) => transcript,
        Err(too_large) => {
            render.write_all(refusal(&too_large).as_bytes())?;
            render.flush()?;
            return Ok(Outcome::TooLarge(too_large));
        }
    };
    render.write_all(transcript.as_bytes())?;
    render.flush()?;

    // Before the question exists, so a launch that lost the terminal during
    // rendering never prints `[y/N]`.
    terminal.verify_foreground()?;
    render.write_all(question(reviews.len()).as_bytes())?;
    render.flush()?;

    // As late as possible: a process backgrounded while the question was being
    // written must not read an answer the shell is about to consume.
    terminal.verify_foreground()?;
    terminal.discard_pending_input()?;
    Ok(match terminal.read_answer()? {
        Answer::Approve => Outcome::Approved,
        Answer::Decline => Outcome::Declined,
        Answer::NoAnswer => Outcome::NoAnswer,
    })
}

/// The refusal an oversized review prints instead of itself.
///
/// It names the source key and the exact candidate digest, so a reviewer knows
/// which pending version could not be shown, and its advice is only what this
/// release can do: make the review fit and run an eligible launch again. The
/// non-interactive `agent-vm config diff`/`agent-vm config approve` workflow is
/// named as a later release's, because it does not ship in this one.
fn refusal(too_large: &TooLarge) -> String {
    format!(
        concat!(
            "==> this review is too large to approve interactively: {} for \"{}\" (current {}), so no part of it was shown.\n",
            "Nothing was approved. Reduce the source so its whole review fits, then run an eligible launch\n",
            "again (a tool verb, `run` or `--`) from this project's interactive terminal to review and\n",
            "approve it. `agent-vm config diff` and `agent-vm config approve` will offer a non-interactive\n",
            "review in a later release; they are not available in this one.\n"
        ),
        too_large.cap.clause(),
        escape_review_line(too_large.key.as_str().as_bytes()),
        too_large.candidate
    )
}

fn question(count: usize) -> String {
    match count {
        1 => "Approve 1 pinned source change for this project? [y/N] ".to_owned(),
        count => format!("Approve {count} pinned source changes for this project? [y/N] "),
    }
}

/// Read one answer line from `input`, consuming nothing past it.
///
/// One `read` per byte, stopping at LF, is what keeps the terminal's queue
/// intact for whatever runs next. A reader that would block on a second byte
/// must not be asked for one.
///
/// The 64-byte bound counts the terminating LF with the answer, so the whole
/// line the terminal delivered is what the cap bounds. Trailing whitespace is
/// trimmed only for spaces and tabs (after one optional CR): every other
/// control byte stays in the line and therefore never forms a yes.
pub(crate) fn read_answer(input: &mut impl Read) -> io::Result<Answer> {
    let mut line = Vec::with_capacity(MAX_ANSWER_BYTES);
    // Every byte consumed, the LF included, counted against the bound.
    let mut consumed = 0_usize;
    loop {
        let mut byte = [0_u8; 1];
        match input.read(&mut byte) {
            Ok(0) if consumed == 0 => return Ok(Answer::NoAnswer),
            // A line that ends at EOF without its LF is not a complete answer.
            Ok(0) => return Ok(Answer::Decline),
            Ok(_) => {
                consumed += 1;
                if consumed > MAX_ANSWER_BYTES {
                    return Ok(Answer::Decline);
                }
                if byte[0] == b'\n' {
                    break;
                }
                line.push(byte[0]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    if let Some(stripped) = line.strip_suffix(b"\r") {
        line = stripped.to_vec();
    }
    // Deliberately not `trim_ascii`: vertical tab, form feed and every other
    // control byte are not whitespace this contract accepts.
    while matches!(line.last(), Some(b' ' | b'\t')) {
        line.pop();
    }
    while matches!(line.first(), Some(b' ' | b'\t')) {
        line.remove(0);
    }
    let approved = line.eq_ignore_ascii_case(b"y") || line.eq_ignore_ascii_case(b"yes");
    Ok(if approved {
        Answer::Approve
    } else {
        Answer::Decline
    })
}

/// The real terminal: this process's own stdin and stderr.
pub(crate) struct StdTerminal;

impl StdTerminal {
    /// The preflight gate: `Some` only when a review here can be asked and
    /// answered on this process's foreground terminal.
    pub(crate) fn detect() -> Option<Self> {
        foreground_terminal().ok().map(|()| Self)
    }
}

impl ApprovalTerminal for StdTerminal {
    fn verify_foreground(&mut self) -> io::Result<()> {
        foreground_terminal()
    }

    fn discard_pending_input(&mut self) -> io::Result<()> {
        // SAFETY: `STDIN_FILENO` was just verified to be a terminal by
        // `verify_foreground`, and `TCIFLUSH` only acts on that terminal's input
        // queue.
        if unsafe { libc::tcflush(libc::STDIN_FILENO, libc::TCIFLUSH) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn read_answer(&mut self) -> io::Result<Answer> {
        read_answer(&mut StdinBytes)
    }
}

/// Descriptors 0 and 2 as one foreground terminal.
fn foreground_terminal() -> io::Result<()> {
    for fd in [libc::STDIN_FILENO, libc::STDERR_FILENO] {
        // SAFETY: `isatty` only inspects the descriptor, which this process owns.
        if unsafe { libc::isatty(fd) } != 1 {
            return Err(io::Error::other("not a terminal"));
        }
    }
    // SAFETY: `fstat` writes into two `stat` values that are live locals of the
    // right type, each naming a descriptor this process owns.
    let (input, output) = unsafe {
        let mut input: libc::stat = std::mem::zeroed();
        let mut output: libc::stat = std::mem::zeroed();
        if libc::fstat(libc::STDIN_FILENO, &mut input) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::fstat(libc::STDERR_FILENO, &mut output) != 0 {
            return Err(io::Error::last_os_error());
        }
        (input, output)
    };
    if input.st_dev != output.st_dev || input.st_rdev != output.st_rdev {
        return Err(io::Error::other("stderr is a different terminal"));
    }
    // SAFETY: `tcgetpgrp` and `getpgrp` take no pointer and only read process
    // and terminal state.
    let foreground = unsafe { libc::tcgetpgrp(libc::STDIN_FILENO) };
    if foreground == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: as above.
    if foreground != unsafe { libc::getpgrp() } {
        return Err(io::Error::other(
            "this process is not the terminal's foreground process group",
        ));
    }
    Ok(())
}

/// Stdin as an unbuffered reader: one `read(2)` per call, so no answer byte
/// after the LF is taken from the terminal.
struct StdinBytes;

impl Read for StdinBytes {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            // SAFETY: the pointer and length describe `buffer`, which the caller
            // of `Read::read` owns for the duration of the call.
            let count =
                unsafe { libc::read(libc::STDIN_FILENO, buffer.as_mut_ptr().cast(), buffer.len()) };
            if count >= 0 {
                return Ok(count as usize);
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

#[cfg(test)]
mod tests;
