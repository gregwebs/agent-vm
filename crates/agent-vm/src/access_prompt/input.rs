//! What one host read contains, besides typing (#501 slice 3 §4.4).
//!
//! Two things are recognised across read boundaries, because a terminal may split
//! either anywhere:
//!
//! * the reply to our cursor-position request (`CSI row ; col R`). A reply naming
//!   the position the prompt left the cursor at is the terminal's own confirmation
//!   that it processed everything before the request — that is what "visible"
//!   means. Any other report is ordinary host input, so it restarts the guard.
//! * a bracketed paste's opening and closing markers (`CSI 200 ~`, `CSI 201 ~`).
//!   The scan runs on **every** host input in every phase, so a paste that opens
//!   before a takeover and closes during one (or the reverse) keeps its framing; it
//!   only observes, never alters.
//!
//! The buffer that spans reads is bounded: a sequence longer than
//! [`MAX_PARTIAL_BYTES`] is not one of these two, so it is typing and the buffer is
//! dropped. Nothing here can grow with a hostile stream.

/// The cursor position the prompt expects a reply to name: the status row, column 3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Position {
    pub(crate) row: u16,
    pub(crate) col: u16,
}

/// The longest escape sequence recognised across reads. A cursor report is at most
/// `ESC [ 65535 ; 65535 R`; the paste markers are shorter.
const MAX_PARTIAL_BYTES: usize = 16;

/// What one read contained.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Scan {
    /// The read contained the terminal's confirmation of the prompt's position.
    pub(crate) cpr_at_prompt: bool,
    /// The read contained anything that is host input rather than a reply or a
    /// paste marker.
    pub(crate) other_bytes: bool,
    /// Whether the read ended inside a bracketed paste.
    pub(crate) in_paste: bool,
    /// The read continued or ended a sequence that began in an earlier read.
    ///
    /// Such a read is never an answer, even when it is one byte: its final byte can
    /// be any printable character, `s` and `p` included. Before this flag existed, a
    /// split `ESC [ … s` reached the guard as a lone `s` and granted.
    pub(crate) continued: bool,
}

/// The framing scanner. One per session: the paste state must outlive a takeover.
pub(crate) struct InputScan {
    /// Bytes of a sequence that has not ended yet.
    partial: Vec<u8>,
    in_paste: bool,
}

impl InputScan {
    pub(crate) fn new() -> Self {
        Self {
            partial: Vec::new(),
            in_paste: false,
        }
    }

    /// Only the tests ask directly: the relay uses the per-read `Scan`.
    #[cfg(test)]
    pub(crate) fn in_paste(&self) -> bool {
        self.in_paste
    }

    /// Scan one read. `position` is the prompt's expected cursor position, when a
    /// prompt is waiting for its confirmation.
    pub(crate) fn scan(&mut self, bytes: &[u8], position: Option<Position>) -> Scan {
        // A read that starts with a sequence from an earlier read continues it.
        let mut scan = Scan {
            continued: !self.partial.is_empty(),
            ..Scan::default()
        };
        // A read that is exactly one `ESC` is the Esc key: the prompt offers it, so
        // it is host input, and the half sequence it would have been is abandoned
        // (which is what the terminal does with a lone Esc it has to interpret).
        if bytes == [0x1b] {
            // A deliberate Esc, even after an abandoned partial sequence: it abandons
            // that sequence (what the terminal does) and is an ordinary deny key, so
            // it must not inherit `continued` (M8/N5).
            self.partial.clear();
            scan.other_bytes = true;
            scan.continued = false;
            scan.in_paste = self.in_paste;
            return scan;
        }
        for &byte in bytes {
            if self.partial.is_empty() {
                if byte == 0x1b {
                    self.partial.push(byte);
                } else {
                    // A printable byte, a control byte or a paste's own payload:
                    // the guard decides what it means, and every one of them is
                    // host input rather than a reply.
                    scan.other_bytes = true;
                }
                continue;
            }
            self.partial.push(byte);
            if self.partial.len() == 2 {
                if matches!(self.partial[1], b'[' | b'O' | b'N') {
                    // `CSI`, `SS2` and `SS3` all take a further byte: this one is not
                    // the final byte. Treating `ESC O` as complete let `ESC O` | `s`
                    // reach the guard as a lone `s` and grant (M4).
                    continue;
                }
                // Any other two-byte escape (`ESC 7`, `ESC =`, …): host input, complete.
                self.partial.clear();
                scan.other_bytes = true;
                continue;
            }
            let ended = matches!(byte, 0x40..=0x7e);
            if !ended {
                if self.partial.len() > MAX_PARTIAL_BYTES {
                    // Not a sequence this scan recognises: treat it all as typing.
                    self.partial.clear();
                    scan.other_bytes = true;
                }
                continue;
            }
            match interpret(&self.partial) {
                Some(Sequence::Cpr(row, col)) => {
                    if position == Some(Position { row, col }) {
                        scan.cpr_at_prompt = true;
                    } else {
                        scan.other_bytes = true;
                    }
                }
                Some(Sequence::PasteOpen) => self.in_paste = true,
                Some(Sequence::PasteClose) => self.in_paste = false,
                // A real key sequence, an unrecognised control, or a malformed
                // report: host input.
                None => scan.other_bytes = true,
            }
            self.partial.clear();
        }
        scan.in_paste = self.in_paste;
        scan
    }
}

enum Sequence {
    Cpr(u16, u16),
    PasteOpen,
    PasteClose,
}

/// Recognise one complete sequence, starting at `ESC`.
fn interpret(bytes: &[u8]) -> Option<Sequence> {
    let rest = bytes.strip_prefix(b"\x1b[")?;
    let (&final_byte, params) = rest.split_last()?;
    match (final_byte, params) {
        (b'R', params) => {
            let (row, col) = split_pair(params)?;
            Some(Sequence::Cpr(row, col))
        }
        (b'~', b"200") => Some(Sequence::PasteOpen),
        (b'~', b"201") => Some(Sequence::PasteClose),
        _ => None,
    }
}

/// `row ; col`, each a decimal number that fits a `u16`.
fn split_pair(params: &[u8]) -> Option<(u16, u16)> {
    let mut parts = params.split(|byte| *byte == b';');
    let row = parse_u16(parts.next()?)?;
    let col = parse_u16(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }
    Some((row, col))
}

fn parse_u16(digits: &[u8]) -> Option<u16> {
    if digits.is_empty() || digits.len() > 5 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    digits.iter().try_fold(0u16, |value, digit| {
        value.checked_mul(10)?.checked_add(u16::from(digit - b'0'))
    })
}

#[cfg(test)]
mod tests;
