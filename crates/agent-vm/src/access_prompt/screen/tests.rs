//! The byte builders (§10.1 `access_prompt/screen`): golden frames, the fit rule
//! and the two properties every frame must have.

use super::*;
use crate::access_prompt::vt::{Charsets, MouseTracking, Screen, VtState};

fn view() -> View {
    View {
        destination: Cell::from_table("tcp 203.0.113.10:443".to_owned()),
        guest_named: false,
        count: 1,
        session: "3f9a12c4".to_owned(),
        offer: OfferText::SessionOrProject,
        waiting: 0,
        overflow: 0,
    }
}

fn modes() -> RestorableModes {
    RestorableModes {
        screen: Screen::Main,
        origin: false,
        mouse_tracking: MouseTracking::Off,
        bracketed_paste: false,
        sync_update: false,
        charsets: Charsets::defaults(),
    }
}

/// A guest with everything the prompt must give back (§10.4's `refuse` prelude).
fn busy_modes() -> RestorableModes {
    let state = {
        let mut state = VtState::new();
        state.advance(b"\x1b[?2004h\x1b[?1002h\x1b[?1006h\x1b[3;20r\x1b[?6h\x1b(0\x1b[?2026h");
        state
    };
    state
        .modes()
        .restorable()
        .expect("the probe's prelude is restorable")
}

fn alt_modes() -> RestorableModes {
    let mut state = VtState::new();
    state.advance(b"\x1b[?1049h\x1b[?2004h\x1b[?1002h\x1b[?6h");
    state.modes().restorable().expect("restorable")
}

/// Every printed row of a frame, in order. A row starts after its
/// `CSI 2 K` erase, so the helper reports what the terminal would show rather
/// than the byte stream.
fn printed_lines(frame: &[u8]) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut index = 0;
    while index < frame.len() {
        if frame[index] == ESC {
            let start = index;
            index += 1;
            if index < frame.len() && frame[index] == b'[' {
                index += 1;
                while index < frame.len() && !(0x40..=0x7e).contains(&frame[index]) {
                    index += 1;
                }
                if index < frame.len() {
                    index += 1;
                }
            }
            let sequence = &frame[start..index];
            if sequence.ends_with(b"K") {
                lines.push(std::mem::take(&mut current));
            }
            continue;
        }
        if frame[index] == CAN || frame[index] == 0x0e || frame[index] == 0x0f {
            index += 1;
            continue;
        }
        current.push(frame[index] as char);
        index += 1;
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines.retain(|line| !line.is_empty());
    lines
}

#[test]
fn every_line_of_an_enter_frame_is_printable_ascii_within_the_width() {
    let size = Size { rows: 30, cols: 80 };
    for view in [
        view(),
        View {
            destination: Cell::from_guest(&("dns ".to_owned() + &"a".repeat(253) + ".example")),
            guest_named: true,
            ..view()
        },
        View {
            waiting: 8,
            overflow: 3,
            ..view()
        },
    ] {
        let laid = layout(&view, size).expect("a fitting question");
        let (frame, status_row) = enter(&modes(), &laid, false, true);
        assert_eq!(status_row as usize, laid.status_row() + 1);
        for row in &laid.rows {
            assert!(row.is_ascii(), "a row must be printable ASCII: {row:?}");
            assert!(
                row.chars().count() <= usize::from(size.cols - 1),
                "a row of {} characters exceeds the width: {row:?}",
                row.chars().count()
            );
        }
        // And the drawn frame carries no line feed.
        assert!(!frame.contains(&b'\n'), "a frame never writes a line feed");
    }
}

#[test]
fn the_table_s_cell_is_shown_exactly_as_access_prints_it() {
    // Finding 16: the cell was escaped twice, so the table's ` · ` separator became
    // a literal `\xc2\xb7` and every backslash doubled. A cell the table already
    // rendered must reach the screen unchanged.
    // The table's separator is ` · `, which `config::escape_str` renders as the six
    // printable characters `\xc2\xb7`; that is what the cell already contains.
    // Exactly what `access` prints for a hostname with a last IP: the middle dot is
    // the table's own separator.
    let cell = "tcp host.example:443 \u{b7} sni host.example (SNI, guest-supplied)".to_owned();
    let laid = layout(
        &View {
            destination: Cell::from_table(cell.clone()),
            guest_named: true,
            ..view()
        },
        Size { rows: 30, cols: 80 },
    )
    .expect("it fits");
    let text = laid.rows.join("\n");
    assert!(text.contains(&cell), "{text}");
    assert!(
        !text.contains("\\\\xc2"),
        "the cell was escaped twice: {text}"
    );
}

#[test]
fn a_hostile_destination_is_escaped_and_wrapped_in_full() {
    let hostile = format!(
        "{}{}",
        "\u{1b}[31mred\u{202e}gnihtemos".repeat(10),
        "x".repeat(40)
    );
    let view = View {
        destination: Cell::from_guest(&hostile),
        guest_named: true,
        ..view()
    };
    let size = Size { rows: 60, cols: 60 };
    let laid = layout(&view, size).expect("it must still fit at 60 rows");
    let joined: String = laid.rows.join("\n");
    assert!(
        !joined.contains('\u{1b}') && joined.is_ascii(),
        "guest text must be escaped to printable ASCII"
    );
    // Nothing safety-relevant is clipped: the wrapped rows contain the escaped
    // destination's every printable character in order.
    let escaped = crate::config::escape_str(&hostile);
    let flattened: String = laid
        .rows
        .iter()
        .map(|row| row.trim().replace(' ', ""))
        .collect();
    let wanted: String = escaped.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(
        flattened.contains(&wanted),
        "the destination must appear in full"
    );
}

#[test]
fn at_exactly_forty_by_fourteen_a_fitting_question_is_complete_and_a_longer_one_declines() {
    let size = Size { rows: 14, cols: 40 };
    // The shortest question that fits: the project-only offer saves two rows.
    let compact = View {
        destination: Cell::from_table("tcp 1.2.3.4:443".to_owned()),
        offer: OfferText::ProjectNextLaunch { port: Some(443) },
        ..view()
    };
    let laid = layout(&compact, size).expect("40 x 14 must fit the minimum question");
    assert!(laid.rows.len() <= 14);
    // The full offer fits this size in its compact form, unclipped.
    let full = layout(&view(), size).expect("the full question fits compactly");
    assert!(full.rows.len() <= 14);
    // One that does not fit is declined rather than clipped (R25).
    assert_eq!(
        layout(
            &View {
                destination: Cell::from_guest(&format!("dns {}.example", "a".repeat(120))),
                guest_named: true,
                ..view()
            },
            size
        ),
        None,
        "R25: a question that does not fit is declined, never clipped"
    );
    // One row too short declines even the minimum.
    assert_eq!(layout(&compact, Size { rows: 13, cols: 40 }), None);
    assert_eq!(layout(&compact, Size { rows: 14, cols: 39 }), None);
}

#[test]
fn two_destinations_sharing_a_sixty_character_prefix_are_each_shown_in_full() {
    let prefix = "api.very-long-internal-service-name-with-a-shared-prefix-xxxx.example";
    assert!(prefix.len() >= 60);
    let first = format!("tcp {prefix}.one:443");
    let second = format!("tcp {prefix}.two:443");
    let size = Size { rows: 40, cols: 60 };
    for destination in [first.clone(), second.clone()] {
        let laid = layout(
            &View {
                destination: Cell::from_table(destination.clone()),
                ..view()
            },
            size,
        )
        .expect("each must fit on its own");
        let flattened: String = laid
            .rows
            .iter()
            .map(|row| row.trim().replace(' ', ""))
            .collect();
        assert!(
            flattened.contains(&destination.replace(' ', "")),
            "{destination} must be shown in full"
        );
        // The differing tail is visible: the two questions are distinguishable.
        assert!(flattened.contains(if destination == first {
            ".one:443"
        } else {
            ".two:443"
        }));
    }
}

#[test]
fn the_waiting_count_moves_to_its_own_row_when_it_does_not_fit_beside_the_status() {
    let size = Size { rows: 30, cols: 40 };
    let laid = layout(
        &View {
            waiting: 8,
            overflow: 12,
            offer: OfferText::ProjectNextLaunch { port: Some(443) },
            ..view()
        },
        size,
    )
    .expect("it fits");
    let count_row = laid
        .count_row
        .expect("the count cannot fit beside 40 columns");
    assert!(count_row < laid.status_row);
    let count_text: String = laid.rows[count_row..laid.status_row].join("\n");
    assert!(count_text.contains("+8 more waiting"), "{count_text}");
    assert!(count_text.contains("+12 more:"), "{count_text}");
    assert!(count_text.contains("agent-vm"), "{count_text}");
    assert!(count_text.contains("access"), "{count_text}");
    for row in &laid.rows[count_row..laid.status_row] {
        assert!(
            row.chars().count() <= usize::from(size.cols - 1),
            "{row:?} exceeds the width"
        );
    }
}

#[test]
fn the_enter_frame_saves_before_it_changes_anything() {
    // Main screen: `?1049h` first, so a cut before it changed nothing.
    let laid = layout(&view(), Size { rows: 30, cols: 80 }).unwrap();
    let (frame, _) = enter(&modes(), &laid, false, true);
    assert!(
        frame.starts_with(b"\x1b[?1049h"),
        "a main-screen guest is saved first: {frame:?}"
    );
    // Alternate screen: `DECSC`, never `?1049h`, which would clear the guest.
    let (frame, _) = enter(&alt_modes(), &laid, false, true);
    assert!(frame.starts_with(b"\x1b7"));
    assert!(!frame.windows(6).any(|window| window == b"?1049h"));
}

#[test]
fn the_enter_frame_ends_at_the_visibility_position_and_asks_for_it() {
    let laid = layout(&view(), Size { rows: 30, cols: 80 }).unwrap();
    let (frame, status_row) = enter(&modes(), &laid, false, true);
    let expected = format!("\x1b[{status_row};3H");
    let tail = &frame[frame.len() - expected.len() - 4..];
    assert!(
        tail.starts_with(expected.as_bytes()),
        "expected {expected:?} near the end of {tail:?}"
    );
    assert!(
        frame.ends_with(b"\x1b[6n"),
        "the position request comes after"
    );
    // Without a request (a terminal that never answered) the frame ends at the move.
    let (frame, _) = enter(&modes(), &laid, false, false);
    assert!(frame.ends_with(expected.as_bytes()));
}

#[test]
fn a_forced_cut_starts_with_can() {
    let laid = layout(&view(), Size { rows: 30, cols: 80 }).unwrap();
    let (frame, _) = enter(&modes(), &laid, true, false);
    assert_eq!(frame[0], 0x18);
    assert!(frame[1..].starts_with(b"\x1b[?1049h"));
}

#[test]
fn the_enter_frame_turns_off_only_the_documented_modes() {
    let laid = layout(&view(), Size { rows: 30, cols: 80 }).unwrap();
    let (frame, _) = enter(&busy_modes(), &laid, false, true);
    for expected in [
        &b"\x1b[?2026l"[..],
        b"\x1b[?1003l",
        b"\x1b[?1002l",
        b"\x1b[?1001l",
        b"\x1b[?1000l",
        b"\x1b[?9l",
        b"\x1b[?2004l",
        b"\x1b[?6l",
        b"\x1b[>0u",
        b"\x1b[0m",
        b"\x1b(B",
        b"\x0f",
    ] {
        assert!(
            frame
                .windows(expected.len())
                .any(|window| window == expected),
            "the enter frame must contain {expected:?}"
        );
    }
    // Not changed: autowrap, insert, cursor visibility, focus reporting, encodings,
    // keypad, scroll margins.
    for forbidden in [
        &b"?7"[..],
        b"?4h",
        b"?25",
        b"?1004",
        b"?1005",
        b"?1006",
        b"?1015",
        b"?1016",
        b"?1047",
        b"?47",
        b"?69",
        b"\x1b=",
        b"\x1b>",
    ] {
        assert!(
            !frame
                .windows(forbidden.len())
                .any(|window| window == forbidden),
            "the enter frame must not touch {forbidden:?}"
        );
    }
}

#[test]
fn the_leave_frame_reapplies_the_guests_modes_in_order() {
    let (frame, _) = leave(&busy_modes());
    let find = |needle: &[u8]| {
        frame
            .windows(needle.len())
            .position(|window| window == needle)
            .unwrap_or_else(|| panic!("missing {needle:?} in {frame:?}"))
    };
    // Screen restore first, charset after it (tmux's `?1049l` restores neither).
    let restore = find(b"\x1b[?1049l");
    let g0 = find(b"\x1b(0");
    let origin = find(b"\x1b[?6h");
    assert!(origin < restore, "origin mode is re-set before the restore");
    assert!(
        restore < g0,
        "the designation is re-emitted after the restore"
    );
    let mouse = find(b"\x1b[?1002h");
    let paste = find(b"\x1b[?2004h");
    let sync = find(b"\x1b[?2026h");
    assert!(g0 < mouse && mouse < paste && paste < sync, "§5.6's order");
    // The kitty pop comes early, on the screen it was pushed on.
    assert!(find(b"\x1b[<u") < restore);
    // Nothing the guest did not have is set.
    assert!(!frame.windows(6).any(|window| window == b"?1006h"));
    // The shift is not re-emitted when the guest was not shifted.
    assert!(!frame.contains(&0x0e));
}

#[test]
fn an_alternate_screen_guest_is_restored_with_decrc_not_a_screen_switch() {
    let (frame, _) = leave(&alt_modes());
    assert!(frame.windows(2).any(|window| window == b"\x1b8"));
    assert!(
        !frame.windows(6).any(|window| window == b"?1049l"),
        "?1049l would drop the guest to the main screen"
    );
    assert!(nudges(Screen::Alternate));
    assert!(!nudges(Screen::Main));
}

#[test]
fn the_guest_s_shift_state_is_reemitted() {
    let mut state = VtState::new();
    state.advance(b"\x1b(0\x1b)A\x0e");
    let (frame, _) = leave(&state.modes().restorable().unwrap());
    assert!(frame.windows(3).any(|window| window == b"\x1b(0"));
    assert!(frame.windows(3).any(|window| window == b"\x1b)A"));
    assert!(frame.contains(&0x0e), "GL=G1 must be re-selected");
}

#[test]
fn the_host_restore_ends_on_the_main_screen_with_everything_off_and_no_erase() {
    let frame = host_restore();
    assert_eq!(frame[0], 0x18);
    for expected in [
        &b"\x1b[0m"[..],
        b"\x1b[<u",
        b"\x1b[?6l",
        b"\x1b[r",
        b"\x1b[?1049l",
        b"\x1b[?1003l",
        b"\x1b[?1002l",
        b"\x1b[?1001l",
        b"\x1b[?1000l",
        b"\x1b[?9l",
        b"\x1b[?1004l",
        b"\x1b[?2004l",
        b"\x1b[?2026l",
        b"\x1b(B",
        b"\x1b)B",
        b"\x0f",
    ] {
        assert!(
            frame
                .windows(expected.len())
                .any(|window| window == expected),
            "the host restore must contain {expected:?}"
        );
    }
    // No erase: a second copy must keep the main screen.
    assert!(!frame.windows(3).any(|window| window == b"[2J"));
    assert!(!frame.windows(4).any(|window| window == b"\x1b[2K"));
    // Both `?6l` and `CSI r` home the cursor, so both precede the screen restore.
    let needle = b"\x1b[?1049l";
    let switch = frame
        .windows(needle.len())
        .position(|window| window == needle.as_slice())
        .expect("the host restore switches screens");
    assert!(frame.windows(5).any(|window| window == b"\x1b[?6l"));
    assert!(frame[..switch].windows(2).any(|window| window == b"[r"));
}

#[test]
fn the_result_frame_replaces_from_the_first_key_row_and_fits_or_shortens() {
    let size = Size { rows: 30, cols: 60 };
    let laid = layout(&view(), size).unwrap();
    let frame = result(
        &laid,
        &ResultView {
            sentence: "allowed tcp://[203.0.113.10/32]:443 for session 3f9a12c4 (running) (policy revision 2)".to_owned(),
            undo: Some("Undo: agent-vm access revoke tcp://[203.0.113.10/32]:443 --session-only".to_owned()),
            retry: true,
        },
    );
    assert!(frame.windows(4).any(|window| window == b"\x1b[2K"));
    let text: Vec<String> = printed_lines(&frame);
    let joined = text.join("\n");
    assert!(joined.contains("allowed tcp://[203.0.113.10/32]:443"));
    assert!(joined.contains("Retry the request now."));
    assert!(joined.contains("Undo: agent-vm access revoke"));
    // Every row lands inside the terminal.
    for row in &text {
        assert!(row.chars().count() <= usize::from(size.cols - 1), "{row:?}");
    }
    // An oversized result is shortened, never clipped mid-word, and points at the
    // command that has the full answer.
    let tiny = Size { rows: 14, cols: 40 };
    let laid = layout(
        &View {
            offer: OfferText::ProjectNextLaunch { port: Some(443) },
            ..view()
        },
        tiny,
    )
    .expect("the minimum question fits 40 x 14");
    let frame = result(
        &laid,
        &ResultView {
            sentence: format!(
                "allowed tcp://[203.0.113.10/32]:443 for the project and recorded for this project (12:00) {}",
                "and more text that cannot fit the remaining rows ".repeat(4)
            ),
            undo: Some("Undo: agent-vm access revoke tcp://[203.0.113.10/32]:443".to_owned()),
            retry: true,
        },
    );
    // Finding 11: R20 promises the sentence, the undo command and "Retry the
    // request now.". On a terminal too small for all three the *actionable* lines are
    // kept and the sentence's tail is what may not fit — never the reverse, and never
    // a silent "see …" substitution.
    let text = printed_lines(&frame).join("\n");
    assert!(
        text.contains("Retry the request now."),
        "the retry line must survive a small terminal: {text}"
    );
    assert!(
        text.contains("Undo: agent-vm access revoke"),
        "the undo command must survive a small terminal: {text}"
    );
    for row in printed_lines(&frame) {
        assert!(
            row.chars().count() <= usize::from(tiny.cols - 1),
            "{row:?} exceeds 40 columns"
        );
    }
    // A result the whole screen can hold is shown complete: the sentence, the retry
    // line and the undo command (R20, M11).
    let all_rows = printed_lines(&frame).join(" ");
    assert!(
        all_rows.matches("remaining rows").count() >= 4,
        "the whole sentence must be present when it fits the screen: {all_rows}"
    );
}

#[test]
fn a_result_too_long_for_the_screen_says_where_the_rest_is() {
    // M11/C-F3: an outcome longer than the terminal keeps the actionable lines and one
    // visible pointer instead of stopping silently.
    let tiny = Size { rows: 14, cols: 40 };
    let laid = layout(
        &View {
            offer: OfferText::ProjectNextLaunch { port: Some(443) },
            ..view()
        },
        tiny,
    )
    .expect("the minimum question fits 40 x 14");
    let long = format!(
        "the project allowance record was not written: {} END-OF-ERROR",
        "a very long diagnostic sentence ".repeat(40)
    );
    let frame = result(
        &laid,
        &ResultView {
            sentence: long,
            undo: Some("Undo: agent-vm access revoke tcp://[203.0.113.10/32]:443".to_owned()),
            retry: true,
        },
    );
    let text = printed_lines(&frame).join("\n");
    assert!(text.contains("Retry the request now."), "{text}");
    assert!(text.contains("Undo: agent-vm access revoke"), "{text}");
    assert!(
        text.contains("see agent-vm access allowances"),
        "the truncation must be visible: {text}"
    );
    assert_eq!(
        printed_lines(&frame).len(),
        14,
        "the result fills the screen and does not scroll it"
    );
}

#[test]
fn the_status_texts_are_the_documented_ones() {
    assert_eq!(Status::StopTyping.text(), "stop typing to answer...");
    assert_eq!(Status::Ready.text(), "ready for your answer");
    assert_eq!(Status::Allowing.text(), "allowing...");
    #[allow(clippy::assertions_on_constants)]
    {
        assert!(
            !BRACKETED_PASTE_DURING_PROMPT,
            "#494's setting until decision D4"
        );
    }
}

#[test]
fn the_enter_frame_contains_the_question_it_was_given() {
    let laid = layout(
        &View {
            destination: Cell::from_guest("dns blocked.example (DNS query, guest-supplied)"),
            guest_named: true,
            count: 4,
            ..view()
        },
        Size { rows: 30, cols: 80 },
    )
    .unwrap();
    let (frame, _) = enter(&modes(), &laid, false, true);
    let text = printed_lines(&frame).join("\n");
    assert!(text.contains("the sandbox refused a network request"));
    assert!(text.contains("dns blocked.example (DNS query, guest-supplied)"));
    assert!(text.contains("supplied by the guest and is not verified"));
    assert!(text.contains("already failed"));
    assert!(text.contains("Refused 4 time(s), session 3f9a12c4."));
    assert!(text.contains("s  allow for this session"));
    assert!(text.contains("p  allow for this project"));
    assert!(text.contains("d  keep refusing"));
    assert!(text.contains("n  keep refusing"));
    assert!(text.contains("stop typing to answer..."));
    assert!(text.contains("refuses in 60 s if unanswered"));
}

#[test]
fn the_project_only_offer_names_the_port_it_does_not_intercept() {
    let laid = layout(
        &View {
            offer: OfferText::ProjectNextLaunch { port: Some(443) },
            ..view()
        },
        Size { rows: 30, cols: 80 },
    )
    .unwrap();
    let text = laid.rows.join(" ").replace("  ", " ");
    assert!(text.contains("from the next launch"), "{text}");
    assert!(text.contains("intercept"), "{text}");
    assert!(text.contains("443"), "{text}");
    assert!(!text.contains("s allow"), "s must not be offered: {text}");
}

#[test]
fn wrap_always_consumes_a_byte_and_a_tiny_terminal_cannot_hang_it() {
    // Round 3, C C-R2-1: with a width narrower than its own indent, `wrap` appended
    // indent rows without consuming a byte and looped for ever, inside a synchronous
    // handler whose deadline could then never fire.
    let mut rows = Vec::new();
    wrap("two words here", 1, "  ", "  ", &mut rows);
    assert!(!rows.is_empty(), "a one-column wrap must terminate");
    // And the result builder is bounded on a terminal below the takeover minimum.
    let frame = result_frame(
        Size { rows: 2, cols: 2 },
        &ResultView {
            sentence: "allowed tcp://[203.0.113.10/32]:443 for session 3f9a12c4".to_owned(),
            undo: Some("Undo: agent-vm access revoke tcp://[203.0.113.10/32]:443".to_owned()),
            retry: true,
        },
    );
    assert!(
        printed_lines(&frame).len() <= 2,
        "nothing can be drawn at 2 x 2, and nothing may loop"
    );
}
