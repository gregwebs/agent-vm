//! The scan against split reads and paste framing (§10.1 `access_prompt/input`).

use super::*;

const AT_PROMPT: Position = Position { row: 12, col: 3 };

fn scan_all(pieces: &[&[u8]], position: Option<Position>) -> Scan {
    let mut scan = InputScan::new();
    let mut last = Scan::default();
    for piece in pieces {
        last = scan.scan(piece, position);
    }
    last
}

#[test]
fn a_reply_at_the_prompt_position_confirms_and_anything_else_is_input() {
    let mut scan = InputScan::new();
    let at = scan.scan(b"\x1b[12;3R", Some(AT_PROMPT));
    assert!(at.cpr_at_prompt);
    assert!(!at.other_bytes);

    let mut scan = InputScan::new();
    let away = scan.scan(b"\x1b[1;1R", Some(AT_PROMPT));
    assert!(!away.cpr_at_prompt);
    assert!(away.other_bytes, "a report for another position is input");

    // No prompt waiting: every reply is input.
    let mut scan = InputScan::new();
    let idle = scan.scan(b"\x1b[12;3R", None);
    assert!(!idle.cpr_at_prompt);
    assert!(idle.other_bytes);
}

#[test]
fn a_reply_split_across_reads_is_still_recognised_except_after_a_lone_escape() {
    // A split that leaves the first read as a lone `ESC` is the Esc key by design
    // (finding 1's trade-off: a reply split right after its introducer is refused
    // or treated as typing, which is the safe direction). Every other split is
    // still recognised.
    let whole = b"\x1b[12;3R";
    for split in 2..whole.len() {
        let result = scan_all(&[&whole[..split], &whole[split..]], Some(AT_PROMPT));
        assert!(
            result.cpr_at_prompt,
            "a reply split at {split} must still confirm"
        );
    }
    let key = scan_all(&[&whole[..1], &whole[1..]], Some(AT_PROMPT));
    assert!(!key.cpr_at_prompt, "a lone ESC is the Esc key, not a reply");
    assert!(key.other_bytes);
    // Byte by byte is the same trade-off, at its first piece.
    let pieces: Vec<&[u8]> = whole[1..].chunks(1).collect();
    let mut scan = InputScan::new();
    let lone = scan.scan(&whole[..1], Some(AT_PROMPT));
    assert!(lone.other_bytes);
    let mut seen = Scan::default();
    for piece in pieces {
        seen = scan.scan(piece, Some(AT_PROMPT));
    }
    assert!(
        !seen.cpr_at_prompt,
        "the introducer was already consumed as Esc"
    );
}

#[test]
fn a_reply_sharing_a_read_with_a_key_reports_both() {
    let mut scan = InputScan::new();
    let result = scan.scan(b"\x1b[12;3Rs", Some(AT_PROMPT));
    assert!(result.cpr_at_prompt);
    assert!(
        result.other_bytes,
        "the key in the same read must still count as input"
    );
    // And the other order.
    let mut scan = InputScan::new();
    let result = scan.scan(b"s\x1b[12;3R", Some(AT_PROMPT));
    assert!(result.cpr_at_prompt);
    assert!(result.other_bytes);
}

#[test]
fn paste_brackets_are_tracked_across_every_split_and_across_phases() {
    let open = b"\x1b[200~";
    let payload = b"pasted s";
    let close = b"\x1b[201~";
    // Splits that leave a lone `ESC` as a read are the Esc key by design.
    for open_split in 2..open.len() {
        for close_split in 2..close.len() {
            let mut scan = InputScan::new();
            // Opened in one phase (no prompt), closed in another (a prompt is
            // waiting): the framing survives.
            let opened = scan.scan(&open[..open_split], None);
            assert!(!opened.in_paste, "the marker is not complete yet");
            let opened = scan.scan(&open[open_split..], None);
            assert!(opened.in_paste);
            let inside = scan.scan(payload, Some(AT_PROMPT));
            assert!(inside.in_paste, "the payload is inside the paste");
            assert!(inside.other_bytes, "the payload is text");
            let _ = scan.scan(&close[..close_split], Some(AT_PROMPT));
            let closed = scan.scan(&close[close_split..], Some(AT_PROMPT));
            assert!(!closed.in_paste, "the close ends the paste");
            assert!(
                !closed.other_bytes,
                "the closing marker itself is not typing"
            );
        }
    }
}

#[test]
fn a_second_takeover_after_a_split_terminator_starts_clean() {
    let mut scan = InputScan::new();
    scan.scan(b"\x1b[200~paste\x1b[20", None);
    scan.scan(b"1~", None);
    assert!(!scan.in_paste());
    let next = scan.scan(b"d", Some(AT_PROMPT));
    assert!(!next.in_paste);
    assert!(next.other_bytes);
}

#[test]
fn an_unrecognised_sequence_is_typing_and_does_not_grow_the_buffer() {
    let mut scan = InputScan::new();
    let arrow = scan.scan(b"\x1b[A", Some(AT_PROMPT));
    assert!(arrow.other_bytes);
    assert!(!arrow.cpr_at_prompt);
    // A very long "sequence" is not one this scan recognises.
    let mut scan = InputScan::new();
    let mut long = b"\x1b[".to_vec();
    long.extend(std::iter::repeat_n(b'1', 40));
    long.push(b'~');
    let result = scan.scan(&long, None);
    assert!(result.other_bytes);
    // A malformed report is typing, not a confirmation.
    let mut scan = InputScan::new();
    let result = scan.scan(b"\x1b[12;R", Some(AT_PROMPT));
    assert!(!result.cpr_at_prompt);
    assert!(result.other_bytes);
    // A pair that does not fit a u16 is malformed too.
    let mut scan = InputScan::new();
    let result = scan.scan(b"\x1b[70000;3R", Some(Position { row: 3, col: 3 }));
    assert!(!result.cpr_at_prompt);
    assert!(result.other_bytes);
}

#[test]
fn a_lone_escape_is_the_escape_key_and_a_partial_sequence_carries_over() {
    // Finding 1: a lone Esc is the Esc key the prompt offers, so it is input, not an
    // unfinished sequence waiting for a final byte. The terminal abandons a lone
    // Esc too; treating it as a prefix let its next read become a one-byte `s`.
    let mut scan = InputScan::new();
    let lone = scan.scan(b"\x1b", Some(AT_PROMPT));
    assert!(!lone.cpr_at_prompt);
    assert!(lone.other_bytes, "a lone Esc is a key");
    // A read that continues a sequence begun earlier is marked, so the guard knows
    // its final byte cannot be an answer.
    let mut scan = InputScan::new();
    let first = scan.scan(b"\x1b[", Some(AT_PROMPT));
    assert!(
        !first.other_bytes,
        "an unfinished sequence is not judged yet"
    );
    assert!(!first.continued);
    let second = scan.scan(b"s", Some(AT_PROMPT));
    assert!(
        second.continued,
        "the read ended a sequence from an earlier read"
    );
    assert!(second.other_bytes);
    // A partial at the end of a session is simply dropped with the scan.
    let mut scan = InputScan::new();
    scan.scan(b"\x1b[12;", Some(AT_PROMPT));
    assert!(!scan.in_paste());
}
