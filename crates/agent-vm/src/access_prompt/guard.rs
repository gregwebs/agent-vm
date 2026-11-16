//! The typing guard: is one host read an answer? (#501 slice 3 §4.4, R16, R17)
//!
//! One proved function, because this is the decision that can grant something by
//! accident. Everything it needs arrives as [`KeyFacts`]: the read's length, its
//! one byte, whether the read *started* after the prompt became visible, how long
//! the terminal had been quiet, whether the read is inside a bracketed paste and
//! whether `s` was offered.
//!
//! The rule, in one sentence: only a **single-byte read**, started **after** the
//! prompt became visible and after the input flush that followed it, read at least
//! [`TYPING_QUIET_MS`] after the later of visibility and the previous host input,
//! and not inside a paste, can answer — and then only the documented keys can.
//!
//! Every refusal here is deliberately conservative: a split arrow key arrives as a
//! lone `ESC` and refuses (safe), Caps Lock types `S` instead of `s` (typing), and a
//! multi-byte paste is never an answer. The evidence is a terminal's reply, not a
//! human's intent; the restore limits in the specification say so.

use vstd::prelude::*;

verus! {

/// The quiet period an answer needs, in milliseconds (#494).
pub const TYPING_QUIET_MS: u64 = 700;

/// The most guest output the relay holds while a prompt is up. The one event that
/// may take it past this is bounded by [`MAX_SDK_EVENT_BYTES`].
pub const HELD_OUTPUT_BYTES: usize = 256 * 1024;

/// The SDK's own bound on one output event: the negotiated `output_chunk_size`,
/// which the plan's C16 validates to at most `4 MiB − 1 KiB` (default 16 KiB).
/// Cited, not proved: the relay clamps what it accepts to it.
pub const MAX_SDK_EVENT_BYTES: usize = 4 * 1024 * 1024 - 1024;

/// How many destinations may wait for their own takeover (R22).
pub const MAX_WAITING: usize = 8;

/// What one host read is, as far as the guard is concerned.
#[derive(Clone, Copy, Debug)]
pub struct KeyFacts {
    /// The number of bytes this one `read(2)` returned.
    pub chunk_len: usize,
    /// Its first byte, meaningful only when `chunk_len == 1`.
    pub byte: u8,
    /// Whether the read *started* after the input flush that followed visibility.
    pub read_after_visible: bool,
    /// Milliseconds since the later of visibility and the previous host input.
    pub quiet_ms: u64,
    /// Whether the read is inside a bracketed paste (D4).
    pub in_paste: bool,
    /// Whether `s` is on offer for this question.
    pub session_offered: bool,
}

/// The four answers, and no others.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// `s`: allow for this session.
    Session,
    /// `p`: allow for this project.
    Project,
    /// `d`, Enter, Esc or Ctrl-C: keep refusing.
    Refuse,
    /// `n`: keep refusing and stop asking about this destination.
    StopAsking,
}

/// The guard, spelled once: a key counts only when every condition holds.
pub open spec fn guard_holds(f: KeyFacts) -> bool {
    f.chunk_len == 1
        && f.read_after_visible
        && !f.in_paste
        && f.quiet_ms >= TYPING_QUIET_MS
}

/// Whether the keys of one answer are the documented ones.
pub open spec fn answer_of_spec(f: KeyFacts) -> Option<Answer> {
    if !guard_holds(f) {
        None
    } else if f.byte == b's' {
        if f.session_offered { Some(Answer::Session) } else { None }
    } else if f.byte == b'p' {
        Some(Answer::Project)
    } else if f.byte == b'n' {
        Some(Answer::StopAsking)
    } else if f.byte == b'd' || f.byte == b'\r' || f.byte == b'\n' || f.byte == 0x1b
        || f.byte == 0x03
    {
        Some(Answer::Refuse)
    } else {
        None
    }
}

/// The guard's decision, proved to be exactly [`answer_of_spec`].
pub fn answer_of(f: KeyFacts) -> (answer: Option<Answer>)
    ensures
        answer == answer_of_spec(f),
        // The safety facts a reader of this contract needs, stated separately so
        // they do not depend on reading a nested `if`:
        !guard_holds(f) ==> answer is None,
        answer is Some ==> guard_holds(f),
        answer == Some(Answer::Session) ==> f.byte == b's' && f.session_offered,
        answer == Some(Answer::Project) ==> f.byte == b'p',
        answer == Some(Answer::StopAsking) ==> f.byte == b'n',
        answer == Some(Answer::Refuse) ==> (f.byte == b'd' || f.byte == b'\r'
            || f.byte == b'\n' || f.byte == 0x1b || f.byte == 0x03),
{
    if f.chunk_len != 1 || !f.read_after_visible || f.in_paste || f.quiet_ms < TYPING_QUIET_MS {
        return None;
    }
    if f.byte == b's' {
        if f.session_offered { Some(Answer::Session) } else { None }
    } else if f.byte == b'p' {
        Some(Answer::Project)
    } else if f.byte == b'n' {
        Some(Answer::StopAsking)
    } else if f.byte == b'd' || f.byte == b'\r' || f.byte == b'\n' || f.byte == 0x1b
        || f.byte == 0x03
    {
        Some(Answer::Refuse)
    } else {
        None
    }
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
