//! The line rules against independently written tables (§10.1 `access_prompt/guard`).

use super::*;

fn facts(chunk_len: usize, byte: u8) -> LineFacts {
    LineFacts {
        chunk_len,
        byte,
        read_after_visible: true,
        continued: false,
        in_paste: false,
        too_soon: false,
    }
}

/// The exhaustive per-read table: every byte against every read shape, compared
/// with a table written from the requirement rather than from the implementation.
#[test]
fn the_exhaustive_line_step_table() {
    for byte in 0u8..=255 {
        for chunk_len in [0usize, 1, 2, 7] {
            for read_after_visible in [false, true] {
                for continued in [false, true] {
                    for in_paste in [false, true] {
                        for too_soon in [false, true] {
                            let f = LineFacts {
                                chunk_len,
                                byte,
                                read_after_visible,
                                continued,
                                in_paste,
                                too_soon,
                            };
                            // Only one clean key stroke — a single byte that started after
                            // the prompt was visible and is neither a sequence's tail nor
                            // inside a paste — may act on the line.
                            let clean =
                                chunk_len == 1 && read_after_visible && !continued && !in_paste;
                            // The settle window comes first: nothing at all happens while
                            // the operator may still be typing at the guest.
                            let expected = if too_soon {
                                LineStep::Ignore
                            } else if !clean {
                                LineStep::Clear
                            } else if byte == b'\r' || byte == b'\n' {
                                LineStep::Submit
                            } else if byte == 0x7f || byte == 0x08 {
                                LineStep::Erase
                            } else if byte == 0x1b || byte == 0x03 {
                                LineStep::Deny
                            } else if byte.is_ascii_alphabetic() {
                                LineStep::Typed(byte.to_ascii_lowercase())
                            } else {
                                // A byte that is not a letter clears the line, so no line
                                // ever holds something an answer could be spelled around.
                                LineStep::Clear
                            };
                            assert_eq!(
                                line_step(f),
                                expected,
                                "byte {byte:#x} len {chunk_len} after_visible {read_after_visible} \
                             continued {continued} paste {in_paste} too_soon {too_soon}"
                            );
                        }
                    }
                }
            }
        }
    }
}

/// A letter never answers on its own: it only types. This is the property Enter was
/// added for, so it is asserted against the table rather than only implied by it.
#[test]
fn only_enter_submits_and_only_esc_or_ctrl_c_deny() {
    for byte in 0u8..=255 {
        if matches!(byte, b'\r' | b'\n' | 0x1b | 0x03) {
            continue;
        }
        let step = line_step(facts(1, byte));
        assert_ne!(
            step,
            LineStep::Submit,
            "only Enter submits; {byte:#x} submitted the line"
        );
        assert_ne!(
            step,
            LineStep::Deny,
            "only Esc and Ctrl-C deny; {byte:#x} denied the question"
        );
    }
}

/// Uppercase types the same letter: Enter is the confirmation, not the case.
#[test]
fn letters_fold_to_lower_case() {
    for (typed, stored) in [
        (b'S', b's'),
        (b'P', b'p'),
        (b'D', b'd'),
        (b'N', b'n'),
        (b'A', b'a'),
        (b'Z', b'z'),
        (b's', b's'),
    ] {
        assert_eq!(line_step(facts(1, typed)), LineStep::Typed(stored));
    }
}

/// The answer table: every accepted spelling, every near miss, and the empty line.
#[test]
fn the_answer_table() {
    use Answer::*;
    let cases: &[(&[u8], Option<Answer>)] = &[
        // Enter on its own keeps refusing.
        (b"", Some(Refuse)),
        // The four answers, each spelled as a letter and as its word.
        (b"s", Some(Session)),
        (b"session", Some(Session)),
        (b"p", Some(Project)),
        (b"project", Some(Project)),
        (b"d", Some(Refuse)),
        (b"deny", Some(Refuse)),
        (b"n", Some(StopAsking)),
        (b"never", Some(StopAsking)),
        // Near misses do nothing at all.
        (b"ses", None),
        (b"sessio", None),
        (b"sessions", None),
        (b"projec", None),
        (b"projects", None),
        (b"den", None),
        (b"denys", None),
        (b"neve", None),
        (b"neverr", None),
        (b"ss", None),
        (b"sd", None),
        (b" s", None),
        (b"d ", None),
        (b"x", None),
        (b"allow", None),
    ];
    for (line, expected) in cases {
        assert_eq!(
            answer_of(line, true),
            *expected,
            "line {:?}",
            String::from_utf8_lossy(line)
        );
        // Only `s`/`session` depends on what is on offer.
        let offered = !matches!(expected, Some(Session));
        assert_eq!(
            answer_of(line, false),
            if offered { *expected } else { None },
            "line {:?} with no session grant on offer",
            String::from_utf8_lossy(line)
        );
    }
}

/// `s` and `session` do nothing when the session grant is not on offer; the other
/// three answers are unaffected.
#[test]
fn session_words_are_not_answers_when_the_session_grant_is_not_offered() {
    assert_eq!(answer_of(b"s", false), None);
    assert_eq!(answer_of(b"session", false), None);
    assert_eq!(answer_of(b"p", false), Some(Answer::Project));
    assert_eq!(answer_of(b"project", false), Some(Answer::Project));
    assert_eq!(answer_of(b"d", false), Some(Answer::Refuse));
    assert_eq!(answer_of(b"deny", false), Some(Answer::Refuse));
    assert_eq!(answer_of(b"n", false), Some(Answer::StopAsking));
    assert_eq!(answer_of(b"never", false), Some(Answer::StopAsking));
    assert_eq!(answer_of(b"", false), Some(Answer::Refuse));
}

/// The line never grows past what a word needs, so the input row cannot widen.
#[test]
fn the_answer_field_holds_more_than_the_longest_word() {
    assert_eq!(MAX_ANSWER_CHARS, 8);
    assert!(MAX_ANSWER_CHARS > "session".len());
    assert!(MAX_ANSWER_CHARS > "project".len());
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
