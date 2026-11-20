//! The answer line: what one host read does to it, and what a submitted line means
//! (#501 slice 3 §4.4, R16, R17).
//!
//! **Enter is what submits.** A letter on its own never grants or denies: the
//! operator types one of `s`/`session`, `p`/`project`, `d`/`deny`, `n`/`never` and
//! presses Enter, and an empty line plus Enter keeps refusing. That one rule removes
//! the accident this kernel exists to prevent: a stray keystroke, the terminal's own
//! cursor-position reply, or a split escape sequence cannot answer, because none of
//! them can press Enter for the operator.
//!
//! Two proved functions, so each rule has one written form:
//!
//! * [`line_step`] — one host read: what it does to the typed line (nothing, clear
//!   it, type a letter, erase one, submit, deny).
//! * [`answer_of`] — the submitted line: the four answers and no others.
//!
//! Both are conservative in the same way. Only a **single-byte** read that *started*
//! after the prompt became visible and is not part of a paste or of an escape
//! sequence may type, erase, submit or deny; anything else **clears the line** and
//! does nothing else. A read of several bytes is a paste or coalesced typing, and a
//! paste must never answer: the prompt turns bracketed paste off (#494), so the read
//! boundary is the only evidence a paste leaves. What is cleared is the line, never
//! the question: typing so fast that two letters arrive in one read costs a retype,
//! not a decision.

use vstd::prelude::*;

verus! {

/// The most characters the line may hold. The longest accepted spelling is
/// `project`/`session` (7), so one byte more already makes a line that cannot
/// answer, and the input row stays inside the narrowest terminal the prompt draws in.
pub const MAX_ANSWER_CHARS: usize = 8;

/// The most guest output the relay holds while a prompt is up. The one event that
/// may take it past this is bounded by [`MAX_SDK_EVENT_BYTES`].
pub const HELD_OUTPUT_BYTES: usize = 256 * 1024;

/// The SDK's own bound on one output event: the negotiated `output_chunk_size`,
/// which the plan's C16 validates to at most `4 MiB − 1 KiB` (default 16 KiB).
/// Cited, not proved: the relay clamps what it accepts to it.
pub const MAX_SDK_EVENT_BYTES: usize = 4 * 1024 * 1024 - 1024;

/// How many destinations may wait for their own takeover (R22).
pub const MAX_WAITING: usize = 8;

/// What one host read does to the typed line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineStep {
    /// Nothing: a byte that is not a letter, Enter, Esc or Backspace.
    Ignore,
    /// Discard what was typed: this read is not one the operator typed (a paste, a
    /// coalesced burst, an escape sequence's tail, or input that predates the
    /// question).
    Clear,
    /// Append this letter, folded to lower case.
    Typed(u8),
    /// Erase the last letter of the line.
    Erase,
    /// The operator pressed Enter: the line is offered to [`answer_of`].
    Submit,
    /// Esc or Ctrl-C: keep refusing, without waiting for Enter.
    Deny,
}

/// What one host read is, as far as the line is concerned.
#[derive(Clone, Copy, Debug)]
pub struct LineFacts {
    /// The number of bytes this one `read(2)` returned.
    pub chunk_len: usize,
    /// Its first byte, meaningful only when `chunk_len == 1`.
    pub byte: u8,
    /// Whether the read *started* after the input flush that followed visibility.
    pub read_after_visible: bool,
    /// Whether the read continues an escape sequence begun in an earlier read.
    pub continued: bool,
    /// Whether the read is inside a bracketed paste.
    pub in_paste: bool,
    /// Whether the question has been readable for less than [`SETTLE_MS`] — long
    /// enough for the tail of typing aimed at the guest to arrive.
    pub too_soon: bool,
}

/// The four answers, and no others.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// `s` or `session`: allow for this session.
    Session,
    /// `p` or `project`: allow for this project.
    Project,
    /// `d` or `deny`, Enter on an empty line, Esc or Ctrl-C: keep refusing.
    Refuse,
    /// `n` or `never`: keep refusing and stop asking about this destination.
    StopAsking,
}

/// Whether a byte is a letter the line can hold.
pub open spec fn is_letter(byte: u8) -> bool {
    (b'a' <= byte && byte <= b'z') || (b'A' <= byte && byte <= b'Z')
}

/// [`is_letter`]'s exec form, as `egress_grammar` pairs `lower` with `lower_byte`.
pub fn is_letter_byte(byte: u8) -> (r: bool)
    ensures r == is_letter(byte),
{
    (b'a' <= byte && byte <= b'z') || (b'A' <= byte && byte <= b'Z')
}

/// Whether this read may act on the line at all.
pub open spec fn typed_read(f: LineFacts) -> bool {
    f.chunk_len == 1 && f.read_after_visible && !f.continued && !f.in_paste
}

/// §4.4's per-read rule, written once.
///
/// `Ignore` is only ever the settle window: every other read either acts on the line
/// or clears it. A byte that is not a letter clears, so a line never holds anything
/// an answer could be spelled around.
pub open spec fn line_step_spec(f: LineFacts) -> LineStep {
    if f.too_soon {
        LineStep::Ignore
    } else if !typed_read(f) {
        LineStep::Clear
    } else if f.byte == b'\r' || f.byte == b'\n' {
        LineStep::Submit
    } else if f.byte == 0x7f || f.byte == 0x08 {
        LineStep::Erase
    } else if f.byte == 0x1b || f.byte == 0x03 {
        LineStep::Deny
    } else if is_letter(f.byte) {
        LineStep::Typed(crate::egress_grammar::lower(f.byte))
    } else {
        LineStep::Clear
    }
}

/// What one host read does to the line, proved to be exactly [`line_step_spec`].
pub fn line_step(f: LineFacts) -> (step: LineStep)
    ensures
        step == line_step_spec(f),
        // The facts a caller relies on, stated separately so they do not depend on
        // reading a nested `if`: only a clean single-byte read types, erases,
        // submits or denies; a submit is Enter; a deny is Esc or Ctrl-C; typing is a
        // letter; and nothing at all happens inside the settle window.
        (step == LineStep::Submit
            || step == LineStep::Erase
            || step == LineStep::Deny
            || matches!(step, LineStep::Typed(_))) ==> typed_read(f),
        step == LineStep::Submit ==> f.byte == b'\r' || f.byte == b'\n',
        step == LineStep::Deny ==> f.byte == 0x1b || f.byte == 0x03,
        // Clearing is either an unclean read or a clean byte that is not a letter,
        // but never a read inside the settle window.
        step == LineStep::Clear ==> !f.too_soon,
        step == LineStep::Ignore ==> f.too_soon,
{
    if f.too_soon {
        return LineStep::Ignore;
    }
    if f.chunk_len != 1 || !f.read_after_visible || f.continued || f.in_paste {
        return LineStep::Clear;
    }
    if f.byte == b'\r' || f.byte == b'\n' {
        return LineStep::Submit;
    }
    if f.byte == 0x7f || f.byte == 0x08 {
        return LineStep::Erase;
    }
    if f.byte == 0x1b || f.byte == 0x03 {
        return LineStep::Deny;
    }
    if is_letter_byte(f.byte) {
        return LineStep::Typed(crate::egress_grammar::lower_byte(f.byte));
    }
    LineStep::Clear
}

/// Whether the line is exactly `word`, over the proved byte-equality kernel.
fn line_is(line: &[u8], word: &[u8]) -> (r: bool)
    ensures r == (line@ =~= word@),
{
    crate::secrets::exact_bytes_equal(line, word)
}

/// `s` alone.
pub open spec fn spells_s(line: Seq<u8>) -> bool {
    line =~= s_word()
}

/// The bytes `s` is spelled with.
pub open spec fn s_word() -> Seq<u8> {
    b"s"@
}

/// `session`, the word for the same answer.
pub open spec fn spells_session(line: Seq<u8>) -> bool {
    line =~= session_word()
}

/// The bytes `session` is spelled with.
pub open spec fn session_word() -> Seq<u8> {
    b"session"@
}

/// `p` alone.
pub open spec fn spells_p(line: Seq<u8>) -> bool {
    line =~= p_word()
}

/// The bytes `p` is spelled with.
pub open spec fn p_word() -> Seq<u8> {
    b"p"@
}

/// `project`, the word for the same answer.
pub open spec fn spells_project(line: Seq<u8>) -> bool {
    line =~= project_word()
}

/// The bytes `project` is spelled with.
pub open spec fn project_word() -> Seq<u8> {
    b"project"@
}

/// `d` alone.
pub open spec fn spells_d(line: Seq<u8>) -> bool {
    line =~= d_word()
}

/// The bytes `d` is spelled with.
pub open spec fn d_word() -> Seq<u8> {
    b"d"@
}

/// `deny`, the word for the same answer.
pub open spec fn spells_deny(line: Seq<u8>) -> bool {
    line =~= deny_word()
}

/// The bytes `deny` is spelled with.
pub open spec fn deny_word() -> Seq<u8> {
    b"deny"@
}

/// `n` alone.
pub open spec fn spells_n(line: Seq<u8>) -> bool {
    line =~= n_word()
}

/// The bytes `n` is spelled with.
pub open spec fn n_word() -> Seq<u8> {
    b"n"@
}

/// `never`, the word for the same answer.
pub open spec fn spells_never(line: Seq<u8>) -> bool {
    line =~= never_word()
}

/// The bytes `never` is spelled with.
pub open spec fn never_word() -> Seq<u8> {
    b"never"@
}

/// What the submitted line means. An empty line is Enter on its own: keep refusing.
pub open spec fn answer_of_spec(line: Seq<u8>, session_offered: bool) -> Option<Answer> {
    if line.len() == 0 {
        Some(Answer::Refuse)
    } else if spells_s(line) || spells_session(line) {
        if session_offered { Some(Answer::Session) } else { None }
    } else if spells_p(line) || spells_project(line) {
        Some(Answer::Project)
    } else if spells_d(line) || spells_deny(line) {
        Some(Answer::Refuse)
    } else if spells_n(line) || spells_never(line) {
        Some(Answer::StopAsking)
    } else {
        None
    }
}

/// The submitted line's meaning, proved to be exactly [`answer_of_spec`].
///
/// `None` is not an error: an unrecognised line does nothing at all, and the
/// question stays up with what was typed still in it.
pub fn answer_of(line: &[u8], session_offered: bool) -> (answer: Option<Answer>)
    ensures
        answer == answer_of_spec(line@, session_offered),
        // The grant facts, stated separately: an allow of either scope names that
        // scope and nothing else, and a session allow needs the session offer.
        answer == Some(Answer::Session) ==> (spells_s(line@) || spells_session(line@)),
        answer == Some(Answer::Project) ==> (spells_p(line@) || spells_project(line@)),
        answer == Some(Answer::Session) ==> session_offered,
{
    if line.is_empty() {
        return Some(Answer::Refuse);
    }
    if line_is(line, b"s") || line_is(line, b"session") {
        return if session_offered {
            Some(Answer::Session)
        } else {
            None
        };
    }
    if line_is(line, b"p") || line_is(line, b"project") {
        return Some(Answer::Project);
    }
    if line_is(line, b"d") || line_is(line, b"deny") {
        return Some(Answer::Refuse);
    }
    if line_is(line, b"n") || line_is(line, b"never") {
        return Some(Answer::StopAsking);
    }
    None
}

/// Whether the relay may receive another guest event, given what it holds.
pub fn may_hold(held: usize) -> (r: bool)
    ensures r == (held < HELD_OUTPUT_BYTES),
{
    held < HELD_OUTPUT_BYTES
}

/// The hold after one more event: bounded, not overflowed (R14, C16).
pub fn held_after(held: usize, event_len: usize) -> (r: usize)
    requires
        held < HELD_OUTPUT_BYTES,
        event_len <= MAX_SDK_EVENT_BYTES,
    ensures
        r == held + event_len,
        r <= HELD_OUTPUT_BYTES - 1 + event_len,
{
    held + event_len
}

/// Whether another destination may wait for its own takeover (R22).
pub fn may_queue(waiting: usize) -> (r: bool)
    ensures r == (waiting < MAX_WAITING),
{
    waiting < MAX_WAITING
}

} // verus!

#[cfg(test)]
mod tests;
