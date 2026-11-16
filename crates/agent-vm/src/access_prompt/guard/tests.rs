//! The guard against an independently written table (§10.1 `access_prompt/guard`).

use super::*;

fn facts(chunk_len: usize, byte: u8) -> KeyFacts {
    KeyFacts {
        chunk_len,
        byte,
        read_after_visible: true,
        quiet_ms: TYPING_QUIET_MS,
        in_paste: false,
        session_offered: true,
    }
}

/// The exhaustive decision table: every byte, every chunk length and quiet time,
/// inside and outside a paste, with and without `s`, compared against a table
/// written from the requirement rather than from the implementation.
#[test]
fn the_exhaustive_answer_table() {
    for byte in 0u8..=255 {
        for chunk_len in [0usize, 1, 2, 5] {
            for quiet_ms in [0u64, 699, 700, 60_000] {
                for read_after_visible in [false, true] {
                    for in_paste in [false, true] {
                        for session_offered in [false, true] {
                            let f = KeyFacts {
                                chunk_len,
                                byte,
                                read_after_visible,
                                quiet_ms,
                                in_paste,
                                session_offered,
                            };
                            let guarding = chunk_len == 1
                                && read_after_visible
                                && !in_paste
                                && quiet_ms >= 700;
                            let expected = if !guarding {
                                None
                            } else {
                                match (byte, session_offered) {
                                    (b's', true) => Some(Answer::Session),
                                    (b'p', _) => Some(Answer::Project),
                                    (b'n', _) => Some(Answer::StopAsking),
                                    (b'd' | b'\r' | b'\n' | 0x1b | 0x03, _) => Some(Answer::Refuse),
                                    _ => None,
                                }
                            };
                            assert_eq!(
                                answer_of(f),
                                expected,
                                "byte {byte:#x} len {chunk_len} quiet {quiet_ms} \
                                 after_visible {read_after_visible} paste {in_paste} \
                                 offered {session_offered}"
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn s_is_not_an_answer_when_it_is_not_offered() {
    assert_eq!(answer_of(facts(1, b's')), Some(Answer::Session));
    let mut f = facts(1, b's');
    f.session_offered = false;
    assert_eq!(answer_of(f), None, "an unoffered s is typing");
}

/// §3.4's timeline, as instants.
#[test]
fn the_timeline_of_the_typing_guard() {
    // t=0.30 'l', then 0.05 s later 's': not quiet enough.
    let mut f = facts(1, b's');
    f.quiet_ms = 50;
    assert_eq!(answer_of(f), None);
    // t=1.05 the guard holds, but the key is 'l'.
    let mut f = facts(1, b'l');
    f.quiet_ms = 750;
    assert_eq!(answer_of(f), None);
    // "sp" as one read is typing whatever it contains.
    assert_eq!(answer_of(facts(2, b's')), None);
    // t=3.00 's', 0.90 s after the last input.
    let mut f = facts(1, b's');
    f.quiet_ms = 900;
    assert_eq!(answer_of(f), Some(Answer::Session));
    // Uppercase is typing, so Caps Lock cannot allow.
    assert_eq!(answer_of(facts(1, b'S')), None);
}

#[test]
fn the_hold_bound_is_bytes_and_never_overflows() {
    assert!(may_hold(HELD_OUTPUT_BYTES - 1));
    assert!(!may_hold(HELD_OUTPUT_BYTES));
    for held in [0usize, 1, HELD_OUTPUT_BYTES - 1] {
        for event in [1usize, 16 * 1024, MAX_SDK_EVENT_BYTES] {
            assert_eq!(held_after(held, event), held + event);
            assert!(held_after(held, event) <= HELD_OUTPUT_BYTES - 1 + event);
        }
    }
    assert_eq!(HELD_OUTPUT_BYTES, 256 * 1024);
    assert_eq!(MAX_SDK_EVENT_BYTES, 4 * 1024 * 1024 - 1024);
}

#[test]
fn the_waiting_queue_is_capped_at_eight() {
    assert!(may_queue(0));
    assert!(may_queue(MAX_WAITING - 1));
    assert!(!may_queue(MAX_WAITING));
    assert_eq!(MAX_WAITING, 8);
}
