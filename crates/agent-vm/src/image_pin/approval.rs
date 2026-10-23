//! Candidate-scoped consent for replacing one host approval.
//!
//! Everything the human decision needs is bound here and nowhere else: the
//! escaped source, the platform the approval is keyed by, and the two full
//! native manifest digests. The [`Approval`] this module returns names exactly
//! the candidate that was displayed, so a registry that moves again between
//! display and commit cannot ride the same consent — the commit's compare-and-
//! swap checks that digest under the host lock and refuses a different one.
//!
//! # Why the read is bounded and never repeated
//!
//! A terminal answer is one canonical line, so the program reads at most
//! [`MAX_ANSWER_BYTES`] plus one byte: a pasted stream cannot decide an
//! approval, and an overlong answer is refused rather than drained. There is no
//! reprompt — a second question would let a script answer until it got its way,
//! and the operation is repeatable by hand.
//!
//! # Why no `/dev/tty`
//!
//! Opening the controlling terminal behind a pipe would answer a question the
//! caller never showed a human. A changed approval therefore requires *both*
//! stdin and stderr to be terminals; anything else refuses with fixed,
//! value-free guidance and leaves the stored approval untouched.

use std::io::{IsTerminal as _, Read, Write};

use anyhow::{Result, anyhow};
use vstd::prelude::*;

use super::{
    Approval, ApprovalMode, ApprovedPin, HostLinuxPlatform, ManifestDigest, ValidatedCandidate,
};

/// One canonical terminal line. Larger answers are refused, not truncated.
const MAX_ANSWER_BYTES: usize = 64;

/// What the prompt may name: an already-escaped source and the approval key.
pub(super) struct ApprovalRequest<'a> {
    /// The source as the user selected it, already escaped for a terminal. For
    /// a redacted default-tier selection this is the fixed label, never the
    /// stored reference.
    pub(super) source: &'a str,
    pub(super) platform: &'a HostLinuxPlatform,
    pub(super) old: &'a ManifestDigest,
    pub(super) new: &'a ManifestDigest,
}

impl ApprovalRequest<'_> {
    fn render(&self) -> String {
        format!(
            "Replace the approved image for {} ({})?\n  old: {}\n  new: {}\n",
            self.source,
            self.platform.render(),
            self.old.as_str(),
            self.new.as_str()
        )
    }
}

/// Ask for, or take, consent to replace the approval `expected` names with
/// exactly `candidate`.
///
/// The change is always rendered, including under `--yes`: a user who
/// pre-authorized the operation still gets the old and new digests in the log.
/// A prompt that cannot be written or flushed is fatal *before* any commit, so
/// no approval is ever recorded for a change the user never saw.
pub(super) fn approve(
    candidate: &ValidatedCandidate,
    expected: ApprovedPin,
    request: &ApprovalRequest<'_>,
    mode: ApprovalMode,
) -> Result<Approval> {
    let mut stderr = std::io::stderr();
    stderr
        .write_all(request.render().as_bytes())
        .map_err(|_| prompt_failed())?;
    let consent = match mode {
        ApprovalMode::Yes => true,
        ApprovalMode::Ask => ask(&mut stderr)?,
    };
    if !consent {
        return Err(not_approved());
    }
    Ok(Approval::replacement(candidate, expected))
}

fn ask(stderr: &mut impl Write) -> Result<bool> {
    let stdin = std::io::stdin();
    if !prompt_is_permitted(TerminalFacts {
        interactive_input: stdin.is_terminal(),
        interactive_output: std::io::stderr().is_terminal(),
    }) {
        return Err(no_terminal());
    }
    stderr
        .write_all(b"Approve this exact image change? [y/N] ")
        .and_then(|()| stderr.flush())
        .map_err(|_| prompt_failed())?;
    let answer = read_answer(stdin.lock())?;
    Ok(answer_is_approval(
        answer_is_bounded(answer.len()),
        is_affirmative(&answer),
    ))
}

/// Read one canonical line, refusing to read past the cap. A terminal delivers
/// the line the user typed; a redirect supplies whatever it supplies, and the
/// caller has already refused a non-terminal.
fn read_answer(reader: impl Read) -> Result<Vec<u8>> {
    // One extra byte is the only evidence needed to recognize an overlong line.
    let mut limited = reader.take(MAX_ANSWER_BYTES as u64 + 1);
    let mut answer = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match limited.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => answer.push(byte[0]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(answer_failed()),
        }
    }
    Ok(answer)
}

/// `y`/`yes` in any ASCII case, after surrounding ASCII whitespace. Everything
/// else — empty, `n`, an unknown word, an overlong line — is a refusal.
fn is_affirmative(answer: &[u8]) -> bool {
    let answer = trim_ascii(answer);
    answer.eq_ignore_ascii_case(b"y") || answer.eq_ignore_ascii_case(b"yes")
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |last| last + 1);
    &bytes[start..end]
}

fn no_terminal() -> anyhow::Error {
    anyhow!(
        "replacing an approved image needs a terminal to confirm the exact change; re-run on a \
         terminal, or pre-authorize this one candidate with `agent-vm image refresh --yes` for \
         the selected image or `agent-vm image set-default --image REF --yes` for an explicit \
         one; the existing approval and default are unchanged"
    )
}

fn not_approved() -> anyhow::Error {
    anyhow!("the image change was not approved; the existing approval and default are unchanged")
}

fn prompt_failed() -> anyhow::Error {
    anyhow!(
        "the image change could not be presented for approval, so nothing was approved; the \
         existing approval and default are unchanged"
    )
}

fn answer_failed() -> anyhow::Error {
    anyhow!(
        "the approval answer could not be read, so the image change was not approved; the \
         existing approval and default are unchanged"
    )
}

verus! {

fn answer_is_bounded(bytes: usize) -> (ok: bool)
    ensures ok == (bytes <= 64),
{ bytes <= 64 }

fn answer_is_approval(bounded: bool, affirmative: bool) -> (ok: bool)
    ensures ok == (bounded && affirmative),
{ bounded && affirmative }

/// The two ends of the terminal, measured once. `--yes` never reaches this
/// decision: it bypasses the prompt entirely rather than being an argument to
/// it, which is what makes a pre-authorization unable to weaken the check.
struct TerminalFacts {
    interactive_input: bool,
    interactive_output: bool,
}

/// The prompt may proceed only when both ends are real terminals, so a pipe can
/// never stand in for a human.
fn prompt_is_permitted(facts: TerminalFacts) -> (ok: bool)
    ensures ok == (facts.interactive_input && facts.interactive_output),
{ facts.interactive_input && facts.interactive_output }

} // verus!

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pure_decisions_match_their_truth_tables() {
        for bytes in [0, 1, 64, 65, 4096] {
            assert_eq!(answer_is_bounded(bytes), bytes <= 64);
        }
        for bounded in [false, true] {
            for affirmative in [false, true] {
                assert_eq!(
                    answer_is_approval(bounded, affirmative),
                    bounded && affirmative
                );
            }
        }
        for interactive_input in [false, true] {
            for interactive_output in [false, true] {
                assert_eq!(
                    prompt_is_permitted(TerminalFacts {
                        interactive_input,
                        interactive_output
                    }),
                    interactive_input && interactive_output
                );
            }
        }
    }

    #[test]
    fn affirmative_answers_are_exact_words() {
        for yes in [
            &b"y"[..],
            b"Y",
            b"yes",
            b"YES",
            b" y \n",
            b"\tYes\r",
            b"  yeS  ",
        ] {
            assert!(is_affirmative(yes), "{:?}", String::from_utf8_lossy(yes));
        }
        for no in [
            &b""[..],
            b"n",
            b"no",
            b"nope",
            b"yeah",
            b"y y",
            b"1",
            b"true",
            b"yess",
        ] {
            assert!(!is_affirmative(no), "{:?}", String::from_utf8_lossy(no));
        }
    }

    #[test]
    fn answers_longer_than_the_cap_are_bounded_and_refused() {
        let long = [b'y'; 4096];
        let answer = read_answer(&long[..]).unwrap();
        assert_eq!(answer.len(), MAX_ANSWER_BYTES + 1);
        assert!(!answer_is_approval(
            answer_is_bounded(answer.len()),
            is_affirmative(&answer)
        ));
        // A line ending before the cap is read exactly.
        let short = read_answer(&b"yes\nignored"[..]).unwrap();
        assert_eq!(short, b"yes");
        assert!(answer_is_approval(
            answer_is_bounded(short.len()),
            is_affirmative(&short)
        ));
        // EOF without a newline is still one answer, and empty EOF is a refusal.
        assert!(is_affirmative(&read_answer(&b"y"[..]).unwrap()));
        assert!(!is_affirmative(&read_answer(&b""[..]).unwrap()));
    }

    #[test]
    fn rendered_change_names_both_full_digests_and_the_escaped_source() {
        let old = ManifestDigest::parse(&format!("sha256:{}", "a".repeat(64))).unwrap();
        let new = ManifestDigest::parse(&format!("sha384:{}", "b".repeat(96))).unwrap();
        let platform = HostLinuxPlatform::for_tests();
        let text = ApprovalRequest {
            // Already escaped by the caller, exactly as `image_pin::Plan`
            // renders it; this module never treats the text as a shell word.
            source: "example.com/team/\\x1b[31mimage:tag",
            platform: &platform,
            old: &old,
            new: &new,
        }
        .render();
        assert!(text.contains("old: sha256:"));
        assert!(text.contains(&"a".repeat(64)));
        assert!(text.contains("new: sha384:"));
        assert!(text.contains(&"b".repeat(96)));
        assert!(text.contains("(linux/"));
        assert!(
            !text.contains('\u{1b}'),
            "no raw control byte reaches the terminal"
        );
        assert!(text.contains("\\x1b"), "the escape is visible, not dropped");
    }
}
