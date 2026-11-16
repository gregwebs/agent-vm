//! The parse table, the safe-cut scan and the mode table (§10.1 `access_prompt/vt`).

use super::*;

fn at(bytes: &[u8]) -> VtState {
    let mut state = VtState::new();
    state.advance(bytes);
    state
}

#[test]
fn every_parse_row_of_the_table() {
    use Parse::*;
    // Ground.
    assert_eq!(next(Ground, b'a'), Ground);
    assert_eq!(next(Ground, 0x1b), Escape);
    assert_eq!(next(Ground, 0xc3), Utf8(1));
    assert_eq!(next(Ground, 0xe2), Utf8(2));
    assert_eq!(next(Ground, 0xf0), Utf8(3));
    // UTF-8 continuation, and a byte that is not one.
    assert_eq!(next(Utf8(2), 0x80), Utf8(1));
    assert_eq!(next(Utf8(1), 0xbf), Ground);
    assert_eq!(next(Utf8(2), b'a'), Ground);
    // Escape and its continuations.
    assert_eq!(next(Escape, b'['), Csi);
    assert_eq!(next(Escape, b']'), Osc);
    assert_eq!(next(Escape, b'P'), Dcs);
    for byte in *b"X^_" {
        assert_eq!(next(Escape, byte), Ignored, "{byte}");
    }
    assert_eq!(next(Escape, b'N'), SingleShift);
    assert_eq!(next(Escape, b'O'), SingleShift);
    assert_eq!(next(Escape, b'('), EscapeIntermediate);
    assert_eq!(next(Escape, b'c'), Ground);
    // A C0 control does not leave Escape.
    assert_eq!(next(Escape, 0x07), Escape);
    // Single shift ends after one byte.
    assert_eq!(next(SingleShift, b'q'), Ground);
    assert_eq!(next(SingleShift, 0x1b), Escape);
    // EscapeIntermediate.
    assert_eq!(next(EscapeIntermediate, 0x30), Ground);
    assert_eq!(next(EscapeIntermediate, 0x1b), EscapeIntermediate);
    // CSI: final, ESC, and a byte >= 0x80.
    assert_eq!(next(Csi, b'm'), Ground);
    assert_eq!(next(Csi, 0x1b), Escape);
    assert_eq!(next(Csi, 0x9b), CsiIgnore);
    assert_eq!(next(CsiIgnore, b'm'), Ground);
    assert_eq!(next(CsiIgnore, b'0'), CsiIgnore);
    // OSC ends on BEL or ST, never on a bare ESC.
    assert_eq!(next(Osc, 0x07), Ground);
    assert_eq!(next(Osc, 0x1b), StringEscape(StringKind::Osc));
    assert_eq!(next(StringEscape(StringKind::Osc), b'\\'), Ground);
    // A DCS or ignored string is not ended by BEL: only ST.
    assert_eq!(next(Dcs, 0x07), Dcs);
    assert_eq!(next(Ignored, 0x07), Ignored);
    assert_eq!(next(Dcs, 0x1b), StringEscape(StringKind::Dcs));
    assert_eq!(next(Ignored, 0x1b), StringEscape(StringKind::Ignored));
    // ESC inside a string abandons it and starts whatever the byte starts.
    assert_eq!(next(StringEscape(StringKind::Dcs), b'['), Csi);
    assert_eq!(next(StringEscape(StringKind::Osc), b'a'), Ground);
    // CAN and SUB return to Ground from every state.
    for state in [
        Ground,
        Utf8(3),
        Escape,
        SingleShift,
        EscapeIntermediate,
        Csi,
        CsiIgnore,
        Osc,
        Dcs,
        Ignored,
        StringEscape(StringKind::Osc),
    ] {
        for byte in [0x18u8, 0x1a] {
            assert_eq!(next(state, byte), Ground, "{state:?} + {byte:#x}");
        }
    }
}

#[test]
fn a_utf8_character_split_at_every_byte_is_only_safe_at_its_ends() {
    let text = "héllo → 漢".as_bytes();
    let mut state = VtState::new();
    for (end, byte) in text.iter().enumerate() {
        state.advance(&[*byte]);
        let boundary = state.at_safe_boundary();
        let expected = text
            .iter()
            .take(end + 1)
            .fold(Parse::Ground, |parse, byte| next(parse, *byte))
            == Parse::Ground;
        assert_eq!(boundary, expected, "boundary after byte {end}");
    }
    assert!(state.at_safe_boundary());
}

#[test]
fn the_safe_cut_is_the_last_boundary_in_the_frame() {
    // "ok" + `?2004h` + the first two bytes of CSI 31m.
    let frame = b"ok\x1b[?2004h\x1b[3";
    let state = VtState::new();
    assert_eq!(state.last_safe_cut(frame), Some(10));
    // In a frame that is all one sequence the only safe cut is its start.
    assert_eq!(state.last_safe_cut(b"\x1b[3"), Some(0));
    // A frame that starts mid-sequence and ends at ground: the boundary is the end.
    let mut mid = VtState::new();
    mid.advance(b"\x1b[3");
    assert_eq!(mid.last_safe_cut(b"1m"), Some(2));
    // And a cancelled sequence is at ground.
    let mut cancelled = VtState::new();
    cancelled.advance(b"\x1b[3");
    cancelled.cancelled();
    assert!(cancelled.at_safe_boundary());
    assert_eq!(cancelled.last_safe_cut(b""), Some(0));
}

/// The kernel against a brute-force scan: "last" is the property, so the oracle is
/// a scan from the end rather than a second implementation of the loop.
#[test]
fn the_safe_cut_agrees_with_a_brute_force_scan() {
    let alphabet: &[u8] = b"\x1b[]P^_XNO()0BA;a1m?0123456789\x18\x1a\x07\x80\xc3\xe2\xf0\xff";
    let mut streams: Vec<Vec<u8>> = Vec::new();
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    for _ in 0..400 {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let len = (seed >> 33) as usize % 24;
        let mut bytes = Vec::with_capacity(len);
        for _ in 0..len {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            bytes.push(alphabet[(seed >> 33) as usize % alphabet.len()]);
        }
        streams.push(bytes);
    }
    for stream in streams {
        for carried in 0..=stream.len() {
            let mut state = VtState::new();
            state.advance(&stream[..carried]);
            let frame = &stream[carried..];
            let expected = (0..=frame.len()).rev().find(|&end| {
                let mut probe = state.clone();
                probe.advance(&frame[..end]);
                probe.at_safe_boundary()
            });
            assert_eq!(
                state.last_safe_cut(frame),
                expected,
                "carried {carried} of {stream:?}"
            );
        }
    }
}

#[test]
fn split_invariance_holds_over_every_piece_boundary() {
    let stream = b"\x1b[?1002h\x1b[?6h\x1b(0\x1b[1;2Hx\x1b]0;title\x07\x1b[?2004h\xc3\xa9\x1b[?25l";
    for split in 0..=stream.len() {
        let mut whole = VtState::new();
        whole.advance(stream);
        let mut pieces = VtState::new();
        pieces.advance(&stream[..split]);
        pieces.advance(&stream[split..]);
        assert_eq!(pieces.parse, whole.parse, "split at {split}");
        assert_eq!(pieces.modes, whole.modes, "split at {split}");
    }
}

#[test]
fn mixed_mouse_sequences_follow_the_any_reset_rule() {
    // `1000h 1002h 1000l` leaves no tracking: any reset clears all of them.
    let state = at(b"\x1b[?1000h\x1b[?1002h\x1b[?1000l");
    assert_eq!(
        state.modes().mouse_tracking(),
        Known::Known(MouseTracking::Off)
    );
    let state = at(b"\x1b[?1002h\x1b[?1002l");
    assert_eq!(
        state.modes().mouse_tracking(),
        Known::Known(MouseTracking::Off)
    );
    // And a later set selects that mode again.
    let state = at(b"\x1b[?1002h\x1b[?1002l\x1b[?1000h");
    assert_eq!(
        state.modes().mouse_tracking(),
        Known::Known(MouseTracking::Normal)
    );
}

#[test]
fn a_full_reset_on_the_alternate_screen_is_unknown() {
    let state = at(b"\x1b[?1049h\x1b[?6h\x1b[?2004h\x1b(0\x1b[?1002h\x1b[?69h\x1b[?2026h");
    assert_eq!(state.modes().screen(), Known::Known(Screen::Alternate));
    let reset = at(b"\x1b[?1049h\x1b[?6h\x1b[?2004h\x1b(0\x1b[?1002h\x1b[?69h\x1b[?2026h\x1bc");
    assert_eq!(reset.modes().screen(), Known::Unknown);
    assert_eq!(reset.modes().restorable(), None);
    // On the main screen it stays known.
    let reset = at(b"\x1b[?6h\x1bc");
    assert_eq!(
        reset.modes().screen(),
        Known::Known(Screen::Main),
        "RIS on the main screen is main in both emulators"
    );
    assert_eq!(reset.modes().origin, Known::Known(false));
}

#[test]
fn a_soft_reset_keeps_defaults_known_and_changed_fields_unknown() {
    let clean = at(b"\x1b[!p");
    assert!(
        clean.modes().restorable().is_some(),
        "a reset at defaults leaves every field known"
    );
    for (bytes, field) in [
        (&b"\x1b[?6h\x1b[!p"[..], "origin"),
        (b"\x1b[?1002h\x1b[!p", "mouse"),
        (b"\x1b[?2004h\x1b[!p", "paste"),
        (b"\x1b[?2026h\x1b[!p", "sync"),
        (b"\x1b(0\x1b[!p", "charset"),
        (b"\x1b[?69h\x1b[!p", "margins"),
    ] {
        assert_eq!(
            at(bytes).modes().restorable(),
            None,
            "DECSTR over a non-default {field} must be unknown"
        );
    }
    // An explicit set afterwards makes the field known again.
    let recovered = at(b"\x1b[?6h\x1b[!p\x1b[?6l");
    assert_eq!(recovered.modes().origin, Known::Known(false));
    let recovered = at(b"\x1b(0\x1b[!p\x1b(B");
    assert_eq!(
        recovered.modes().restorable(),
        Some(RestorableModes {
            screen: Screen::Main,
            origin: false,
            mouse_tracking: MouseTracking::Off,
            bracketed_paste: false,
            sync_update: false,
            charsets: Charsets::defaults(),
        })
    );
}

#[test]
fn designation_and_shift_are_tracked_and_unknown_designations_decline() {
    // Every G0/G1 designation and both shifts.
    let state = at(b"\x1b(0\x1b)A\x0e");
    assert_eq!(
        state.modes().charsets.restorable(),
        Some(Charsets {
            g0: Charset::LineDrawing,
            g1: Charset::Uk,
            gl: Gl::G1,
        })
    );
    // An unrecognised designation makes that half unknown.
    let state = at(b"\x1b(B\x1b)Z");
    assert_eq!(state.modes().charsets.g1, Known::Unknown);
    assert_eq!(state.modes().charsets.g0, Known::Known(Charset::Ascii));
    // A shift into a set whose designation is not tracked is unknown too.
    let state = at(b"\x1b(B\x1bn");
    assert_eq!(
        state.modes().restorable(),
        None,
        "G2 is never tracked, so a shift into it cannot be restored"
    );
    // SI returns to G0.
    let state = at(b"\x1b(0\x0e\x0f");
    assert_eq!(state.modes().charsets.gl, Known::Known(Gl::G0));
}

#[test]
fn a_guest_cursor_restore_makes_origin_and_charsets_unknown_only_when_a_save_could_have() {
    // The re-review's counterexamples: a non-default saved, then restored.
    for prelude in [
        &b"\x1b[?6h\x1b7\x1b[?6l\x1b8"[..],
        b"\x1b(0\x1b7\x1b(B\x1b8".as_slice(),
        b"\x1b[?6h\x1b[?1049h\x1b[?1049l".as_slice(),
        b"\x1b(0\x1b[?1048h\x1b[?1048l".as_slice(),
        b"\x1b[?6h\x1b[s\x1b[?6l\x1b[u".as_slice(),
    ] {
        let state = at(prelude);
        assert_eq!(state.modes().origin, Known::Unknown, "prelude {prelude:?}");
        assert_eq!(
            state.modes().charsets.restorable(),
            None,
            "prelude {prelude:?}"
        );
        assert_eq!(state.modes().restorable(), None);
    }
    // With defaults throughout, nothing can have changed: both stay known.
    for prelude in [
        &b"\x1b7\x1b8"[..],
        b"\x1b[s\x1b[u".as_slice(),
        b"\x1b[?1048h\x1b[?1048l".as_slice(),
        b"\x1b[?1049h\x1b[?1049l".as_slice(),
    ] {
        let state = at(prelude);
        assert_eq!(
            state.modes().origin,
            Known::Known(false),
            "prelude {prelude:?}"
        );
        assert_eq!(
            state.modes().charsets.restorable(),
            Some(Charsets::defaults()),
            "prelude {prelude:?}"
        );
    }
    // A save at a non-default origin, then a reset, clears the sticky bit.
    let state = at(b"\x1b[?6h\x1b7\x1bc\x1b8");
    assert_eq!(state.modes().origin, Known::Known(false));
}

#[test]
fn a_csi_with_more_parameters_than_the_collector_keeps_forgets_every_field() {
    // Sixteen `25`s then `1002` in one set: the 17th parameter is one tmux acts on
    // and this collector drops.
    let mut bytes = b"\x1b[?".to_vec();
    for _ in 0..16 {
        bytes.extend_from_slice(b"25;");
    }
    bytes.extend_from_slice(b"1002h");
    let state = at(&bytes);
    assert_eq!(state.modes().mouse_tracking, Known::Unknown);
    assert_eq!(state.modes().screen, Known::Unknown);
    assert_eq!(state.modes().restorable(), None);
    // Sixteen exactly is still a sequence this tracker reads.
    let mut bytes = b"\x1b[?".to_vec();
    for _ in 0..15 {
        bytes.extend_from_slice(b"25;");
    }
    bytes.extend_from_slice(b"1002h");
    let state = at(&bytes);
    assert_eq!(
        state.modes().mouse_tracking(),
        Known::Known(MouseTracking::ButtonEvent)
    );
}

#[test]
fn left_right_margin_mode_declines_the_takeover() {
    assert_eq!(at(b"\x1b[?69h").modes().restorable(), None);
    assert!(at(b"\x1b[?69h\x1b[?69l").modes().restorable().is_some());
}

#[test]
fn the_prompt_never_touches_the_modes_it_does_not_track() {
    // Autowrap, insert, cursor visibility, focus reporting, encodings, keypad and
    // scroll margins are set and reset here; nothing may become unknown.
    let state = at(
        b"\x1b[?7l\x1b[?7h\x1b[4h\x1b[4l\x1b[?25l\x1b[?25h\x1b[?1004h\x1b[?1004l\
          \x1b[?1006h\x1b[?1006l\x1b[?1005h\x1b[?1015h\x1b[?1016h\x1b=\x1b>\x1b[3;20r",
    );
    assert!(state.modes().restorable().is_some());
}

#[test]
fn cancel_abandons_a_partial_sequence_and_its_collected_parameters() {
    let mut state = VtState::new();
    state.advance(b"\x1b[?100");
    state.advance(b"\x18");
    assert!(state.at_safe_boundary());
    // The parameters of the abandoned sequence are not applied by the next one.
    state.advance(b"\x1b[?6h");
    assert_eq!(state.modes.origin, Known::Known(true));
    assert_eq!(
        state.modes().mouse_tracking(),
        Known::Known(MouseTracking::Off)
    );
}
