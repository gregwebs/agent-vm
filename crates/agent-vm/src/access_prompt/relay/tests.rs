//! The lifecycle's own tests, with injected instants (§10.1 `access_prompt::relay`).

use super::*;
use crate::allowances::{GrantResult, Offer};

/// The first instant input is accepted: the question has been readable for the
/// settle window (R17's tail of typing aimed at the guest).
fn settled(at: Instant) -> Instant {
    at + super::SETTLE_MS
}

/// The terminal's reply naming the prompt's visibility position.
fn reply_to(laid: screen::Layout) -> String {
    format!("\x1b[{};{}R", laid.input_row() + 1, laid.cursor_col())
}

/// Type `text` one byte per read, as a terminal delivers it, then press Enter.
/// `asking` flushed the reader at epoch 1, so every read here starts after it.
fn typed(relay: &mut Relay, text: &[u8], now: Instant) {
    let mut epoch = 2;
    for byte in text {
        relay.host_input(chunk(&[*byte], epoch), now);
        epoch += 1;
    }
    relay.host_input(chunk(b"\r", epoch), now);
}

/// One key stroke: a single-byte read after the flush that does not submit.
fn key(relay: &mut Relay, byte: u8, epoch: u64, now: Instant) {
    relay.host_input(chunk(&[byte], epoch), now);
}

fn allowance() -> Allowance {
    Allowance::parse("tcp://[203.0.113.10/32]:443").expect("a canonical allowance")
}

fn candidate(destination: &Allowance, count: u64) -> Candidate {
    Candidate {
        entry_id: "46d712fd".to_owned(),
        destination: destination.clone(),
        cell: crate::access_prompt::screen::Cell::from_table(format!("tcp {destination}")),
        count,
        offer: Offer::SessionOrProject,
        port: Some(443),
    }
}

fn fresh() -> Relay {
    Relay::new(
        "3f9a12c4".to_owned(),
        Size { rows: 30, cols: 80 },
        Timings::default(),
        None,
    )
}

/// A relay with the hint routed to it, as a PTY launch on a terminal has: the
/// route, the session's `Hint` and the relay.
fn fresh_routed() -> (
    Relay,
    std::sync::Arc<crate::refusal::feed::Hint>,
    crate::refusal::feed::HintRelay,
) {
    let hint = std::sync::Arc::new(crate::refusal::feed::Hint::new());
    let route = hint.redirect();
    let relay = Relay::new(
        "3f9a12c4".to_owned(),
        Size { rows: 30, cols: 80 },
        Timings::default(),
        Some(route.clone()),
    );
    (relay, hint, route)
}

/// Fire the session's hint and hand the relay the event, as the facade does.
fn fire_hint(hint: &std::sync::Arc<crate::refusal::feed::Hint>, relay: &mut Relay, now: Instant) {
    hint.fire_for_test();
    relay.hint_fired(now);
}

fn chunk(bytes: &[u8], epoch: u64) -> HostChunk {
    HostChunk {
        bytes: bytes.to_vec(),
        epoch,
    }
}

fn frames(relay: &mut Relay) -> Vec<OutputItem> {
    let mut out = Vec::new();
    while let Some(item) = relay.take_outbound_if(|_| true) {
        if let Outbound::Frame(frame) = item {
            out.push(frame);
        }
    }
    out
}

fn data_of(items: &[OutputItem]) -> Vec<u8> {
    items
        .iter()
        .flat_map(|item| match item {
            OutputItem::Data(bytes) => bytes.clone(),
            // The hint is its own frame type; its bytes are today's line.
            OutputItem::Hint => crate::refusal::feed::HintRelay::BYTES.to_vec(),
            OutputItem::Takeover { .. } => Vec::new(),
        })
        .collect()
}

fn take_steps(items: &[OutputItem]) -> Vec<Step> {
    items
        .iter()
        .filter_map(|item| match item {
            OutputItem::Takeover { step, .. } => Some(*step),
            _ => None,
        })
        .collect()
}

/// Drive to `Asking`: offer, write the enter, confirm visibility with the reply.
/// Bring the question up, and return the first instant input is accepted: the
/// question became visible at `now`, so nothing typed before `now + SETTLE_MS` counts.
fn asking(relay: &mut Relay, now: Instant) -> Instant {
    relay.offer(candidate(&allowance(), 1), now);
    let g = relay.generation();
    relay.written(g, now);
    // The reply names the prompt's status row.
    let laid = screen::layout(&relay.current_view(), relay.size).expect("fits");
    let reply = reply_to(laid);
    relay.host_input(chunk(reply.as_bytes(), 1), now);
    assert!(relay.wants_input_flush(), "visibility asks for the flush");
    relay.input_flushed(1, now);
    assert_eq!(relay.phase_name(), "asking");
    settled(now)
}

/// The rows a frame would print, splitting on the erase-to-end-of-line each row is
/// written after. Used to assert what the terminal ends up showing, not just the
/// bytes' shape.
fn printed_rows(frame: &[u8]) -> Vec<String> {
    let mut rows = Vec::new();
    let mut current = String::new();
    let mut index = 0;
    while index < frame.len() {
        if frame[index] == 0x1b {
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
            if frame[start..index].ends_with(b"K") {
                rows.push(std::mem::take(&mut current));
            }
            continue;
        }
        if matches!(frame[index], 0x18 | 0x0e | 0x0f) {
            index += 1;
            continue;
        }
        current.push(frame[index] as char);
        index += 1;
    }
    if !current.is_empty() {
        rows.push(current);
    }
    rows.retain(|row| !row.is_empty());
    rows
}

fn last_redraw(items: &[OutputItem]) -> Option<String> {
    items.iter().rev().find_map(|item| match item {
        OutputItem::Takeover {
            step: Step::Redraw,
            bytes,
            ..
        } => Some(printed_rows(bytes).join("\n")),
        _ => None,
    })
}

#[test]
fn with_no_refusal_output_is_forwarded_frame_for_frame() {
    let mut relay = fresh();
    let now = Instant::now();
    let guest = b"plain \x1b[31mred\x1b[0m \x1b]0;title\x07 \xc3\xa9".to_vec();
    relay.guest_output(guest.clone(), now);
    let out = frames(&mut relay);
    assert_eq!(out, vec![OutputItem::Data(guest)]);
    assert_eq!(relay.phase_name(), "idle");
    assert!(!relay.wants_host_input());
    assert_eq!(
        relay.host_input(chunk(b"k", 1), now),
        InputRoute::Guest(b"k".to_vec())
    );
}

#[test]
fn the_cut_is_the_last_safe_boundary_of_the_frame() {
    let mut relay = fresh();
    let now = Instant::now();
    // A partial sequence before the refusal: the relay is not at a boundary.
    relay.guest_output(b"\x1b[3".to_vec(), now);
    let _ = frames(&mut relay);
    relay.offer(candidate(&allowance(), 1), now);
    assert_eq!(relay.phase_name(), "cutting");
    relay.guest_output(b"1mred\x1b[0m".to_vec(), now);
    let out = frames(&mut relay);
    // The frame ends at a boundary, so the last safe cut is its end: everything the
    // guest finished drawing is on screen behind the prompt and nothing is held.
    assert_eq!(data_of(&out), b"1mred\x1b[0m".to_vec());
    assert_eq!(
        take_steps(&out),
        vec![Step::Enter {
            screen: Screen::Main
        }]
    );
    assert_eq!(relay.held_bytes(), 0);
    // A frame that stops mid-sequence is cut at its last boundary and the rest held.
    let mut relay = fresh();
    relay.guest_output(b"\x1b[3".to_vec(), now);
    let _ = frames(&mut relay);
    relay.offer(candidate(&allowance(), 1), now);
    relay.guest_output(b"1mred".to_vec(), now);
    let out = frames(&mut relay);
    // The frame reaches a boundary at "1m" and stays there: the whole frame is
    // forwarded and the takeover starts after it, with nothing held.
    assert_eq!(data_of(&out), b"1mred".to_vec());
    assert_eq!(relay.held_bytes(), 0);
    assert_eq!(
        take_steps(&out),
        vec![Step::Enter {
            screen: Screen::Main
        }]
    );
}

#[test]
fn a_stalled_sequence_is_cancelled_at_exactly_the_cut_deadline() {
    let mut relay = fresh();
    let now = Instant::now();
    relay.guest_output(b"\x1b[?20".to_vec(), now);
    let _ = frames(&mut relay);
    relay.offer(candidate(&allowance(), 1), now);
    assert_eq!(relay.phase_name(), "cutting");
    assert_eq!(
        relay.deadline(),
        Some(now + CUT_DEADLINE),
        "the deadline bounds the queuing"
    );
    relay.handle_deadline(now + CUT_DEADLINE);
    let out = frames(&mut relay);
    let enter = out
        .iter()
        .find_map(|item| match item {
            OutputItem::Takeover { bytes, .. } => Some(bytes.clone()),
            _ => None,
        })
        .expect("an enter frame");
    assert_eq!(enter[0], 0x18, "CAN abandons the half sequence");
    assert_eq!(relay.phase_name(), "entering");
}

#[test]
fn a_close_during_entering_waits_for_the_enter_to_be_written() {
    // I1: no leave before the enter is confirmed.
    let mut relay = fresh();
    let now = Instant::now();
    relay.offer(candidate(&allowance(), 1), now);
    let g = relay.generation();
    relay.answered(&allowance(), now);
    let out = frames(&mut relay);
    assert!(
        !take_steps(&out).contains(&Step::Leave),
        "the leave must wait for the enter"
    );
    assert_eq!(relay.phase_name(), "entering");
    relay.written(g, now);
    let out = frames(&mut relay);
    assert_eq!(take_steps(&out), vec![Step::Leave]);
    assert_eq!(relay.phase_name(), "restoring");
}

#[test]
fn host_input_is_consumed_during_a_takeover_and_held_output_follows_the_leave() {
    // I2 and I3.
    let mut relay = fresh();
    let now = Instant::now();
    relay.offer(candidate(&allowance(), 1), now);
    let g = relay.generation();
    let _ = frames(&mut relay);
    relay.written(g, now);
    assert!(relay.wants_host_input());
    assert_eq!(
        relay.host_input(chunk(b"typed", 1), now),
        InputRoute::Consumed
    );
    relay.guest_output(b"held".to_vec(), now);
    assert_eq!(relay.held_bytes(), 4);
    let out = frames(&mut relay);
    assert!(out.is_empty(), "held output is not forwarded");

    relay.handle_deadline(now + PROMPT_TIMEOUT);
    let out = frames(&mut relay);
    assert_eq!(take_steps(&out), vec![Step::Leave], "the leave comes first");
    assert_eq!(data_of(&out), b"held".to_vec());
    relay.written(g, now + PROMPT_TIMEOUT);
    assert_eq!(relay.phase_name(), "idle");
}

#[test]
fn visibility_is_the_reply_that_names_the_prompt_position_and_nothing_else() {
    let mut relay = fresh();
    let now = Instant::now();
    relay.offer(candidate(&allowance(), 1), now);
    let g = relay.generation();
    relay.written(g, now);
    // A report for another position is ordinary input, not a confirmation.
    relay.host_input(chunk(b"\x1b[1;1R", 1), now);
    assert_eq!(relay.phase_name(), "confirming");
    let laid = screen::layout(&relay.current_view(), relay.size).unwrap();
    let reply = reply_to(laid);
    relay.host_input(chunk(reply.as_bytes(), 2), now);
    assert_eq!(relay.phase_name(), "asking");
}

#[test]
fn without_a_reply_visibility_is_the_write_plus_the_wait_and_the_session_stops_asking() {
    let mut relay = fresh();
    let now = Instant::now();
    relay.offer(candidate(&allowance(), 1), now);
    let g = relay.generation();
    relay.written(g, now);
    assert!(
        relay
            .deadline()
            .is_some_and(|deadline| deadline == now + CPR_WAIT)
    );
    relay.handle_deadline(now + CPR_WAIT);
    assert_eq!(relay.phase_name(), "asking");
    assert!(relay.wants_input_flush());
    relay.input_flushed(9, now + CPR_WAIT);

    // Refuse this one, then answer the next: its enter frame must not ask again. The
    // refusal is typed once the settle window is over.
    let answer_at = settled(now + CPR_WAIT);
    relay.host_input(chunk(b"\r", 10), answer_at);
    relay.handle_deadline(answer_at + RESULT_LINGER + CPR_WAIT);
    for item in frames(&mut relay) {
        let _ = item;
    }
    relay.written(g, answer_at);
    relay.handle_deadline(settled(now + CPR_WAIT + RELEASE_GAP));
    relay.offer(
        candidate(&allowance(), 1),
        settled(now + CPR_WAIT + RELEASE_GAP),
    );
    let next = relay.generation();
    let out = frames(&mut relay);
    let enter = out
        .iter()
        .find_map(|item| match item {
            OutputItem::Takeover {
                generation,
                bytes,
                step: Step::Enter { .. },
            } if *generation == next => Some(bytes.clone()),
            _ => None,
        })
        .expect("the next enter frame");
    assert!(
        !enter.windows(4).any(|window| window == b"\x1b[6n"),
        "the session stopped asking for the position after one unanswered request"
    );
}

#[test]
fn a_question_whose_enter_was_written_near_the_timeout_is_refused_at_the_timeout() {
    // N1: the two bounds are independent.
    let mut relay = fresh();
    let now = Instant::now();
    relay.offer(candidate(&allowance(), 1), now);
    let g = relay.generation();
    relay.written(
        g,
        now + PROMPT_TIMEOUT - std::time::Duration::from_millis(100),
    );
    assert_eq!(relay.phase_name(), "confirming");
    assert_eq!(relay.deadline(), Some(now + PROMPT_TIMEOUT));
    relay.handle_deadline(now + PROMPT_TIMEOUT);
    assert_eq!(relay.phase_name(), "restoring");
}

#[test]
fn an_answer_needs_the_epoch_and_enter() {
    let mut relay = fresh();
    let now = Instant::now();
    let visible = asking(&mut relay, now);

    // Read started before the flush: it cannot even type.
    relay.host_input(chunk(b"s", 1), visible);
    assert_eq!(relay.answer_line, "");
    assert_eq!(relay.phase_name(), "asking");

    // A letter typed after the flush is echoed and does nothing else.
    key(&mut relay, b's', 2, visible);
    assert_eq!(relay.answer_line, "s");
    let out = frames(&mut relay);
    assert!(
        out.iter().any(|item| matches!(
            item,
            OutputItem::Takeover {
                step: Step::Redraw,
                ..
            }
        )),
        "the typed letter is drawn"
    );
    assert_eq!(relay.phase_name(), "asking", "a letter alone never answers");

    // Enter submits it.
    key(&mut relay, b'\r', 3, visible);
    assert_eq!(relay.phase_name(), "granting");
    let mut grants = 0;
    while let Some(item) = relay.take_outbound_if(|_| true) {
        if let Outbound::Grant(grant) = item {
            assert_eq!(grant.scope, GrantScope::Session);
            grants += 1;
        }
    }
    assert_eq!(grants, 1);
}

#[test]
fn a_lone_escape_refuses_and_a_split_sequence_never_types() {
    // A lone Esc is a key the prompt offers (`d`/Enter/Esc refuse), so it must
    // refuse — and a sequence split across reads must never be read as a letter.
    let mut relay = fresh();
    let now = Instant::now();
    let visible = asking(&mut relay, now);
    key(&mut relay, 0x1b, 2, visible);
    assert_eq!(relay.phase_name(), "restoring", "a lone Esc must refuse");

    // `ESC [` in one read, then `s` (a valid CSI final byte): the `s` is the tail of
    // a sequence, so it clears the line and types nothing.
    let mut relay = fresh();
    let now = Instant::now();
    let visible = asking(&mut relay, now);
    relay.host_input(chunk(b"\x1b[", 2), visible);
    assert_eq!(relay.phase_name(), "asking");
    let after = visible + std::time::Duration::from_millis(10);
    key(&mut relay, b's', 3, after);
    assert_eq!(
        relay.answer_line, "",
        "the final byte of a split sequence must not type"
    );
    // Typing it properly does answer: the line needs its own letter and Enter.
    typed(&mut relay, b"s", after);
    assert_eq!(relay.phase_name(), "granting");
}

#[test]
fn a_read_that_started_before_the_flush_cannot_type_or_submit() {
    let mut relay = fresh();
    let now = Instant::now();
    let visible = asking(&mut relay, now);
    // Started at epoch 1 (before the flush), delivered later: nothing happens.
    relay.host_input(chunk(b"s", 1), visible + std::time::Duration::from_secs(1));
    relay.host_input(chunk(b"\r", 1), visible + std::time::Duration::from_secs(2));
    assert_eq!(relay.answer_line, "");
    assert_eq!(relay.phase_name(), "asking");
    // A read that started after the flush does type.
    typed(&mut relay, b"s", visible);
    assert_eq!(relay.phase_name(), "granting");
}

#[test]
fn a_multi_byte_or_pasted_read_clears_the_line_and_never_answers() {
    let mut relay = fresh();
    let now = Instant::now();
    let visible = asking(&mut relay, now);
    let mut at = visible;
    // Typing, then a burst of two letters in one read: the line is cleared.
    relay.host_input(chunk(b"ss", 2), at);
    assert_eq!(relay.answer_line, "", "a multi-byte read clears the line");
    assert_eq!(relay.phase_name(), "asking");

    // A pasted line, markers and all, never answers — even with Enter in the paste.
    at += std::time::Duration::from_millis(10);
    relay.host_input(chunk(b"\x1b[200~", 3), at);
    at += std::time::Duration::from_millis(10);
    relay.host_input(chunk(b"s\r", 4), at);
    assert_eq!(relay.phase_name(), "asking", "inside a paste");
    assert_eq!(relay.answer_line, "");
    at += std::time::Duration::from_millis(10);
    relay.host_input(chunk(b"\x1b[201~", 5), at);
    at += std::time::Duration::from_millis(10);
    key(&mut relay, b's', 6, at);
    assert_eq!(
        relay.answer_line, "s",
        "after the paste ends, keys type again"
    );
    typed(&mut relay, b"", at);
    assert_eq!(relay.phase_name(), "granting", "and Enter submits it");
}

#[test]
fn s_queues_one_grant_and_the_result_lingers_through_its_own_wakeup() {
    // I8 and B4: the relay cannot leave `Granting` before its own grant settles, and
    // a wakeup for its own answer does not cut the result short.
    let mut relay = fresh();
    let now = Instant::now();
    let visible = asking(&mut relay, now);
    let g = relay.generation();
    let quiet = settled(visible);
    typed(&mut relay, b"s", quiet);
    let mut grants = 0;
    while let Some(item) = relay.take_outbound_if(|_| true) {
        if matches!(item, Outbound::Grant(_)) {
            grants += 1;
        }
    }
    assert_eq!(grants, 1);

    // The prompt's own answer wakes the answers channel; nothing changes.
    relay.answered(&allowance(), quiet);
    assert_eq!(relay.phase_name(), "granting");

    // A result for another generation is ignored.
    relay.granted(g + 1, PromptGrant::AnsweredElsewhere, quiet);
    assert_eq!(relay.phase_name(), "granting");

    relay.granted(
        g,
        PromptGrant::Reached(GrantResult::Applied {
            destination: allowance().to_string(),
            scope: GrantScope::Session,
            revision: 2,
            recorded_ms: 0,
        }),
        quiet,
    );
    assert_eq!(relay.phase_name(), "lingering");
    // Queuing the result already bounds the takeover; the writer's acceptance then
    // restarts the full 1.5 s the user reads it for (R20, M1).
    assert_eq!(relay.deadline(), Some(quiet + RESULT_LINGER));
    let accepted = quiet + std::time::Duration::from_millis(200);
    relay.frame_taken(accepted);
    assert_eq!(relay.deadline(), Some(accepted + RESULT_LINGER));
    // The wakeup after the result changes nothing either.
    relay.answered(&allowance(), quiet);
    assert_eq!(relay.phase_name(), "lingering");
    relay.handle_deadline(accepted + RESULT_LINGER);
    assert_eq!(relay.phase_name(), "restoring");
}

#[test]
fn a_reply_after_visibility_clears_the_line_and_does_nothing_else() {
    // The driver answers the terminal's request once; that reply is a multi-byte
    // read, so it clears the typed line — it can never type, submit or deny.
    let mut relay = fresh();
    let now = Instant::now();
    let visible = asking(&mut relay, now);
    // The enter frame is still queued; clear it so only later frames are examined.
    let _ = frames(&mut relay);
    key(&mut relay, b's', 2, visible);
    assert_eq!(relay.answer_line, "s");
    let reply_at = visible + std::time::Duration::from_millis(20);
    relay.host_input(chunk(b"\x1b[12;3R", 3), visible);
    assert_eq!(relay.phase_name(), "asking");
    assert_eq!(relay.answer_line, "", "a reply clears the line");
    assert!(
        last_redraw(&frames(&mut relay)).is_some(),
        "the cleared line is drawn"
    );
    // Nothing redraws by itself after that: there is no "ready" state any more.
    relay.handle_deadline(settled(reply_at));
    assert!(relay.deadline().is_some_and(|at| at > settled(reply_at)));
    // And Enter on the now-empty line keeps refusing.
    key(&mut relay, b'\r', 4, settled(reply_at));
    assert_eq!(relay.phase_name(), "restoring");
}

#[test]
fn an_answer_from_elsewhere_follows_the_per_phase_schedule() {
    // Asking: the close is immediate at the next feed turn.
    let mut relay = fresh();
    let now = Instant::now();
    asking(&mut relay, now);
    relay.answered(&allowance(), now);
    assert_eq!(relay.phase_name(), "restoring");

    // Cutting: nothing is queued yet, so the relay simply drops the question.
    let mut relay = fresh();
    let now = Instant::now();
    relay.guest_output(b"\x1b[?20".to_vec(), now);
    let _ = frames(&mut relay);
    relay.offer(candidate(&allowance(), 1), now);
    assert_eq!(relay.phase_name(), "cutting");
    relay.answered(&allowance(), now);
    assert_eq!(relay.phase_name(), "idle");

    // Entering: the close waits for the write, then the leave.
    let mut relay = fresh();
    let now = Instant::now();
    relay.offer(candidate(&allowance(), 1), now);
    let g = relay.generation();
    relay.answered(&allowance(), now);
    relay.written(g, now);
    assert_eq!(relay.phase_name(), "restoring");
}

#[test]
fn the_queue_coalesces_repeats_caps_at_eight_and_counts_the_rest() {
    let mut relay = fresh();
    let now = Instant::now();
    relay.offer(candidate(&allowance(), 1), now);
    let g = relay.generation();
    relay.written(g, now);
    // A repeat of the shown destination only raises its count.
    relay.offer(candidate(&allowance(), 3), now);
    assert_eq!(relay.shown.as_ref().map(|item| item.count), Some(3));
    // Eight more destinations wait; the ninth is counted.
    for index in 0..9u16 {
        let destination =
            Allowance::parse(&format!("tcp://[203.0.113.{}]:443", index + 20)).unwrap();
        relay.offer(candidate(&destination, 1), now);
    }
    assert_eq!(relay.waiting_len(), 8);
    assert_eq!(relay.overflowed.len(), 1);
    // A repeat of the overflowed destination does not count twice (finding 10).
    let overflowed = relay.overflowed[0].clone();
    relay.offer(candidate(&overflowed, 2), now);
    assert_eq!(relay.overflowed.len(), 1);
    assert_eq!(relay.waiting_len(), 8);
}

#[test]
fn the_hold_is_bounded_and_the_receive_gate_closes_at_the_cap() {
    let mut relay = fresh();
    let now = Instant::now();
    relay.offer(candidate(&allowance(), 1), now);
    let g = relay.generation();
    let _ = frames(&mut relay);
    relay.written(g, now);
    // One event short of the cap still accepts; at the cap it does not.
    let event = vec![b'x'; 16 * 1024];
    while relay.held_bytes() + event.len() < guard::HELD_OUTPUT_BYTES {
        relay.guest_output(event.clone(), now);
        assert!(relay.may_receive_guest_output());
    }
    relay.guest_output(event, now);
    assert!(!relay.may_receive_guest_output());
}

#[test]
fn output_received_while_the_leave_is_unconfirmed_is_forwarded() {
    // Finding 2: bytes that arrive after `Leave` is queued but before the writer
    // confirms it are the guest's, and must reach the terminal behind the leave.
    let mut relay = fresh();
    let now = Instant::now();
    let visible = asking(&mut relay, now);
    let quiet = settled(visible);
    typed(&mut relay, b"d", quiet);
    assert_eq!(relay.phase_name(), "restoring");
    // The leave is queued by the refusal; now drain up to it.
    let mut items = Vec::new();
    while let Some(item) = relay.take_outbound_if(|_| true) {
        items.push(item);
    }
    assert!(items.iter().any(|item| matches!(
        item,
        Outbound::Frame(OutputItem::Takeover {
            step: Step::Leave,
            ..
        })
    )));
    // Guest output arrives while the leave is unconfirmed: forwarded in order, not
    // held (the old code held it and then cleared the hold on the confirmation).
    relay.guest_output(b"LATE".to_vec(), quiet);
    let out = frames(&mut relay);
    assert_eq!(data_of(&out), b"LATE".to_vec());
    assert_eq!(relay.held_bytes(), 0);
    // The confirmation ends the takeover without dropping anything.
    let g = relay.generation();
    relay.written(g, quiet);
    assert_eq!(relay.phase_name(), "idle");
}

#[test]
fn held_output_advances_the_tracker_so_the_next_prompt_sees_it() {
    // Finding 6: a mode the guest set while the question was up is the terminal's
    // mode when the question ends, so the next prompt must save and restore it.
    let mut relay = fresh();
    let now = Instant::now();
    let visible = asking(&mut relay, now);
    // The guest goes to the alternate screen during the takeover.
    relay.guest_output(b"\x1b[?1049h".to_vec(), now);
    let quiet = settled(visible);
    typed(&mut relay, b"d", quiet);
    let g = relay.generation();
    while let Some(_item) = relay.take_outbound_if(|_| true) {}
    relay.written(g, quiet);
    assert_eq!(relay.phase_name(), "idle");
    // The next question must draw on the alternate screen, not the main one.
    relay.offer(candidate(&allowance(), 1), quiet + RELEASE_GAP);
    assert_eq!(relay.phase_name(), "entering");
    let out = frames(&mut relay);
    assert_eq!(
        take_steps(&out),
        vec![Step::Enter {
            screen: Screen::Alternate
        }],
        "the guest's held `?1049h` must be tracked"
    );
}

#[test]
fn modes_changed_while_cutting_are_the_ones_the_prompt_saves() {
    // Finding 7: `maybe_start` used to capture the modes before cutting, so a frame
    // forwarded in `Cutting` changed the guest's screen behind the prompt's back.
    let mut relay = fresh();
    let now = Instant::now();
    relay.guest_output(b"\x1b[?10".to_vec(), now);
    let _ = frames(&mut relay);
    relay.offer(candidate(&allowance(), 1), now);
    assert_eq!(relay.phase_name(), "cutting");
    // The rest of the sequence completes `?1049h` while the cut is in progress.
    relay.guest_output(b"49h".to_vec(), now);
    let out = frames(&mut relay);
    assert_eq!(
        take_steps(&out),
        vec![Step::Enter {
            screen: Screen::Alternate
        }],
        "the screen the guest set during the cut is the one the prompt must save"
    );
}

#[test]
fn a_lagged_answer_set_closes_only_what_is_actually_answered() {
    // Finding 18: a lag used to close the shown question as "answered elsewhere"
    // without re-checking. The facade now asks `answered()`; the relay's part is that
    // it reports every open destination and closes only the one named.
    let mut relay = fresh();
    let now = Instant::now();
    asking(&mut relay, now);
    let other = Allowance::parse("tcp://[203.0.113.11]:443").unwrap();
    relay.offer(candidate(&other, 1), now);
    let pending = relay.pending_destinations();
    assert!(pending.contains(&allowance()), "{pending:?}");
    assert!(pending.contains(&other), "{pending:?}");
    // Nothing is answered: nothing closes.
    assert_eq!(relay.phase_name(), "asking");
    // One is: only that one closes.
    relay.answered(&other, now);
    assert!(
        relay.waiting_len() == 0,
        "the queued destination is dropped"
    );
    assert_eq!(relay.phase_name(), "asking", "the shown question stays");
}

#[test]
fn a_state_the_cut_learns_about_declines_the_takeover() {
    // M13/A's counterexample: the state that matters arrives *during* the cut. The old
    // code captured the modes when the question started, so it queued an `Enter` for a
    // screen the guest had already left.
    let mut relay = fresh();
    let now = Instant::now();
    relay.guest_output(b"\x1b[?20".to_vec(), now);
    let _ = frames(&mut relay);
    relay.offer(candidate(&allowance(), 1), now);
    assert_eq!(relay.phase_name(), "cutting");
    // Completing `?69h` turns left/right margin mode on while the cut is in progress.
    relay.guest_output(b"\x1b[?69h".to_vec(), now);
    assert_eq!(
        relay.phase_name(),
        "idle",
        "a mode the cut learned about must decline the takeover"
    );
    let out = frames(&mut relay);
    assert!(
        !take_steps(&out)
            .iter()
            .any(|step| matches!(step, Step::Enter { .. })),
        "no prompt frame: {out:?}"
    );
    // The guest's bytes were forwarded (they are not the prompt's to keep).
    assert_eq!(data_of(&out), b"\x1b[?69h".to_vec());
}

#[test]
fn a_too_small_terminal_at_the_cut_declines_and_releases_held_bytes_in_order() {
    // Finding 8: the cut holds a frame's tail and then finds the question no longer
    // fits. The tail is the guest's, so the decline releases it in order rather than
    // stranding it while later output overtakes it.
    let mut relay = fresh();
    let now = Instant::now();
    relay.guest_output(b"\x1b[?20".to_vec(), now);
    let _ = frames(&mut relay);
    relay.offer(candidate(&allowance(), 1), now);
    assert_eq!(relay.phase_name(), "cutting");
    // The terminal shrinks under the question before the cut completes.
    relay.resized(Size { rows: 10, cols: 30 }, now);
    relay.guest_output(b"2hTAIL\x1b[?3".to_vec(), now);
    let out = frames(&mut relay);
    // The cut forwards `2hTAIL`, holds the half sequence, and the decline then
    // releases the tail behind it, in order.
    assert_eq!(data_of(&out), b"2hTAIL\x1b[?3".to_vec());
    assert!(
        !take_steps(&out)
            .iter()
            .any(|step| matches!(step, Step::Enter { .. }))
    );
    assert_eq!(relay.phase_name(), "idle");
    assert_eq!(relay.held_bytes(), 0);
    // And later output follows it, not ahead of it.
    relay.guest_output(b"AFTER".to_vec(), now);
    let out = frames(&mut relay);
    assert_eq!(data_of(&out), b"AFTER".to_vec());
}

#[test]
fn finish_returns_the_owed_frames_in_wire_order() {
    // Enter queued but not written: the drain's tail is enter, leave, held.
    let mut relay = fresh();
    let now = Instant::now();
    relay.offer(candidate(&allowance(), 1), now);
    let g = relay.generation();
    // Nothing was taken from the queue: the enter is still in `outbound`.
    assert_eq!(relay.queued_frames(), 1);
    relay.guest_output(b"held".to_vec(), now);
    let (owed, grants) = relay.finish();
    assert!(
        grants.is_empty(),
        "no answer was given, so no grant is owed"
    );
    assert_eq!(
        take_steps(&owed),
        vec![
            Step::Enter {
                screen: Screen::Main
            },
            Step::Leave
        ]
    );
    assert_eq!(data_of(&owed), b"held".to_vec());
    assert_eq!(relay.phase_name(), "idle");
    let _ = g;
}

#[test]
fn finish_hands_a_queued_grant_to_the_caller() {
    // Finding 17: a guest exit while the user's `s` was still queued dropped it.
    let mut relay = fresh();
    let now = Instant::now();
    let visible = asking(&mut relay, now);
    let quiet = settled(visible);
    typed(&mut relay, b"s", quiet);
    assert_eq!(relay.phase_name(), "granting");
    // The pump has not taken the grant yet; the guest exits now.
    let (owed, grants) = relay.finish();
    assert_eq!(
        grants.len(),
        1,
        "the user's answer survives the session's end"
    );
    assert_eq!(grants[0].scope, GrantScope::Session);
    // The frames that were owed are still returned, in order.
    let _ = (owed,);
}

#[test]
fn a_hint_is_written_at_a_safe_boundary_and_never_during_a_takeover() {
    let now = Instant::now();
    let (mut relay, hint, _route) = fresh_routed();
    fire_hint(&hint, &mut relay, now);
    let out = frames(&mut relay);
    assert_eq!(
        data_of(&out),
        crate::refusal::feed::HintRelay::BYTES.to_vec()
    );
    // Mid-sequence: held until the boundary.
    let (mut relay, hint, _route) = fresh_routed();
    relay.guest_output(b"\x1b[3".to_vec(), now);
    let _ = frames(&mut relay);
    fire_hint(&hint, &mut relay, now);
    let out = frames(&mut relay);
    assert!(data_of(&out).is_empty(), "not at a boundary");
    relay.guest_output(b"1m".to_vec(), now);
    let out = frames(&mut relay);
    let data = data_of(&out);
    assert!(
        data.ends_with(crate::refusal::feed::HintRelay::BYTES),
        "the hint goes out at the boundary the guest's bytes reached"
    );
    // During a takeover it waits for the leave.
    let (mut relay, hint, _route) = fresh_routed();
    relay.offer(candidate(&allowance(), 1), now);
    let g = relay.generation();
    relay.written(g, now);
    fire_hint(&hint, &mut relay, now);
    let out = frames(&mut relay);
    assert!(data_of(&out).is_empty(), "never between enter and leave");
    // With no route the relay emits nothing: the hint already went to stderr.
    let mut relay = fresh();
    relay.hint_fired(now);
    assert!(frames(&mut relay).is_empty());
}

#[test]
fn a_forced_cut_does_not_queue_the_hint_inside_the_stalled_sequence() {
    // Finding 9: at a forced cut the tracker is set to ground by `cancelled`, but the
    // terminal only reaches ground on the `CAN` that follows the hint. The hint must
    // wait for the leave instead of becoming the stalled OSC's payload.
    let now = Instant::now();
    let (mut relay, hint, _route) = fresh_routed();
    // An unterminated OSC: nothing in it is safe, so the cut is forced.
    relay.guest_output(b"\x1b]0;title".to_vec(), now);
    let _ = frames(&mut relay);
    fire_hint(&hint, &mut relay, now);
    relay.offer(candidate(&allowance(), 1), now);
    assert_eq!(relay.phase_name(), "cutting");
    relay.handle_deadline(now + CUT_DEADLINE);
    let out = frames(&mut relay);
    assert!(
        data_of(&out).is_empty(),
        "the hint must not precede the CAN that ends the sequence: {:?}",
        data_of(&out)
    );
    let steps = take_steps(&out);
    assert_eq!(
        steps,
        vec![Step::Enter {
            screen: Screen::Main
        }]
    );
    // The hint would have gone out at the leave — but the question was up and readable
    // by then, and the question is the notice, so nothing is queued after the answer.
    let g = relay.generation();
    relay.written(g, now);
    // Visibility, as a terminal gives it, then the refusal key.
    let laid = screen::layout(&relay.current_view(), relay.size).expect("fits");
    let reply = reply_to(laid);
    relay.host_input(chunk(reply.as_bytes(), 1), now);
    relay.input_flushed(1, now);
    let quiet = settled(now);
    typed(&mut relay, b"d", quiet);
    assert_eq!(relay.phase_name(), "restoring");
    while let Some(_item) = relay.take_outbound_if(|_| true) {}
    relay.written(g, quiet);
    let queued = relay
        .outbound
        .iter()
        .any(|item| matches!(item, Outbound::Frame(OutputItem::Hint)));
    assert!(
        !queued,
        "the visible question replaced the hint: {:?}",
        relay.outbound
    );
    let route = relay.take_hint().expect("a route to hand back");
    assert!(!route.detach(), "the question delivered the notice");
}

#[test]
fn one_fire_queues_exactly_one_hint_and_a_queued_hint_is_owed_to_stderr() {
    // Finding 5: the hint fired once produced one frame per poll and kept a
    // `select!` branch ready; and a frame queued but never handed over was lost from
    // both surfaces. Here: two notifications give one frame, and until the frame is
    // handed to the writer the route is still the epilogue's to print.
    let (mut relay, hint, _route) = fresh_routed();
    let now = Instant::now();
    fire_hint(&hint, &mut relay, now);
    fire_hint(&hint, &mut relay, now);
    let queued = relay.outbound.len();
    assert_eq!(queued, 1, "one hint per fire, and one fire per session");
    // Not yet handed over: the epilogue would still print it.
    relay.hint_fired(now);
    assert_eq!(relay.outbound.len(), 1, "a second fire queues nothing new");
    assert!(relay.hint_queued, "the bytes are queued, not delivered");
    let hint = relay.take_hint().expect("a route to hand back");
    assert!(
        hint.detach(),
        "a queued hint that never reached the writer is owed to stderr"
    );
}

#[test]
fn answering_the_question_claims_the_hint_instead_of_printing_it_under_the_answer() {
    // The operator answered `s`, and the terminal then said "the sandbox refused a
    // guest network request": a notice about a request that had just been allowed.
    // The question *is* the notice, so answering claims it. The claim is what makes
    // this pass: without it, the leave frees the terminal and the hint is queued.
    let (mut relay, hint, _route) = fresh_routed();
    let now = Instant::now();
    let visible = asking(&mut relay, now);
    // The refusal's own hint arrives while the question is already up, which is the
    // order that used to print it under the answer.
    fire_hint(&hint, &mut relay, now);
    assert!(
        !relay
            .outbound
            .iter()
            .any(|item| matches!(item, Outbound::Frame(OutputItem::Hint))),
        "a hint owed while a question is up waits for its answer: {:?}",
        relay.outbound
    );
    typed(&mut relay, b"s", visible);
    let g = relay.generation();
    while relay.take_outbound_if(|_| true).is_some() {}
    relay.written(g, visible + std::time::Duration::from_millis(400));
    relay.handle_deadline(visible + RESULT_LINGER);
    while relay.take_outbound_if(|_| true).is_some() {}
    assert!(
        !relay
            .outbound
            .iter()
            .any(|item| matches!(item, Outbound::Frame(OutputItem::Hint))),
        "the answer must not be followed by the hint: {:?}",
        relay.outbound
    );
    let route = relay.take_hint().expect("a route to hand back");
    assert!(
        !route.detach(),
        "a claimed hint is delivered by the question, not by the epilogue"
    );
}

#[test]
fn a_hint_fired_after_the_answer_stays_quiet() {
    // The refusal feed and the watcher race: the claim is unconditional, so a hint
    // that fires once the operator has answered is not owed to stderr either.
    let (mut relay, hint, _route) = fresh_routed();
    let now = Instant::now();
    let visible = asking(&mut relay, now);
    typed(&mut relay, b"d", visible);
    fire_hint(&hint, &mut relay, now);
    assert!(
        !relay
            .outbound
            .iter()
            .any(|item| matches!(item, Outbound::Frame(OutputItem::Hint))),
        "a claimed hint never queues, even if it fires later: {:?}",
        relay.outbound
    );
    let route = relay.take_hint().expect("a route to hand back");
    assert!(!route.detach(), "nothing is owed to stderr");
}

#[test]
fn a_question_withdrawn_unanswered_leaves_the_hint_to_stderr() {
    // A question drawn and withdrawn (the guest exited) was never answered, so the
    // line is the only notice the operator can still read: it must reach the
    // epilogue, not be claimed by a question nobody could answer.
    let (mut relay, hint, _route) = fresh_routed();
    let now = Instant::now();
    let visible = asking(&mut relay, now);
    fire_hint(&hint, &mut relay, now);
    assert_eq!(relay.phase_name(), "asking");
    relay.input_ended(visible);
    assert_eq!(relay.phase_name(), "restoring");
    while relay.take_outbound_if(|_| true).is_some() {}
    relay.written(relay.generation(), visible);
    assert!(
        relay
            .outbound
            .iter()
            .any(|item| matches!(item, Outbound::Frame(OutputItem::Hint))),
        "an unanswered question does not claim the hint: {:?}",
        relay.outbound
    );
}

#[test]
fn a_guest_frame_identical_to_the_hint_is_not_mistaken_for_it() {
    // M9/N6: the hint used to be identified by byte equality, so a guest frame with the
    // same bytes consumed its one-shot claim.
    let (mut relay, hint, _route) = fresh_routed();
    let now = Instant::now();
    relay.guest_output(crate::refusal::feed::HintRelay::BYTES.to_vec(), now);
    fire_hint(&hint, &mut relay, now);
    let first = relay.take_outbound_if(|_| true).expect("the guest frame");
    assert!(
        matches!(first, Outbound::Frame(OutputItem::Data(_))),
        "the guest's frame is data, not the hint: {first:?}"
    );
    let second = relay.take_outbound_if(|_| true).expect("the hint frame");
    assert!(matches!(second, Outbound::Frame(OutputItem::Hint)));
    // Popped but never accepted by the writer: still owed to stderr.
    let route = relay.take_hint().expect("a route");
    assert!(
        route.detach(),
        "a hint popped but not accepted is still owed to stderr"
    );
}

#[test]
fn a_hint_handed_to_the_writer_is_not_printed_again() {
    let (mut relay, hint, _route) = fresh_routed();
    let now = Instant::now();
    fire_hint(&hint, &mut relay, now);
    // The pump hands the frame to the writer.
    let taken = relay.take_outbound_if(|_| true).expect("the hint frame");
    assert!(matches!(taken, Outbound::Frame(OutputItem::Hint)));
    assert!(!relay.hint_queued, "handed over, so no longer queued");
    // The pump marks the route written when the writer accepts the bytes (M9); this
    // test has no pump, so it performs that acceptance itself.
    let route = relay.hint_route().expect("a route");
    assert!(route.take(), "accepting the frame owns the hint");
    let hint = relay.take_hint().expect("a route to hand back");
    assert!(
        !hint.detach(),
        "a hint the writer accepted is not printed a second time"
    );
}

#[test]
fn a_newer_redraw_replaces_an_unsent_one() {
    let mut relay = fresh();
    let now = Instant::now();
    let visible = asking(&mut relay, now);
    // Before anything is taken, force two status redraws.
    relay.redraw_status(Status::Allowing);
    relay.redraw_status(Status::Asking);
    let mut redraws = 0;
    while let Some(item) = relay.take_outbound_if(|_| true) {
        if matches!(
            item,
            Outbound::Frame(OutputItem::Takeover {
                step: Step::Redraw,
                ..
            })
        ) {
            redraws += 1;
        }
    }
    assert_eq!(redraws, 1, "one redraw is in flight, never two");
    let _ = visible;
}

#[test]
fn an_alternate_screen_guest_is_nudged_and_a_main_screen_one_is_not() {
    let now = Instant::now();
    let mut main = fresh();
    main.offer(candidate(&allowance(), 1), now);
    let g = main.generation();
    main.written(g, now);
    main.handle_deadline(now + PROMPT_TIMEOUT);
    let mut nudges = 0;
    while let Some(item) = main.take_outbound_if(|_| true) {
        if matches!(item, Outbound::Nudge) {
            nudges += 1;
        }
    }
    assert_eq!(nudges, 0);

    let mut alternate = fresh();
    alternate.guest_output(b"\x1b[?1049h".to_vec(), now);
    let _ = frames(&mut alternate);
    alternate.offer(candidate(&allowance(), 1), now);
    let g = alternate.generation();
    alternate.written(g, now);
    alternate.handle_deadline(now + PROMPT_TIMEOUT);
    let mut nudges = 0;
    while let Some(item) = alternate.take_outbound_if(|_| true) {
        if matches!(item, Outbound::Nudge) {
            nudges += 1;
        }
    }
    assert_eq!(nudges, 1);
}

/// One event of I5's random walk, shared by the deterministic sweep and the
/// proptest so a change to the vocabulary reaches both.
fn apply_step(relay: &mut Relay, step: u8, now: Instant, entropy: u64) {
    match step {
        0 => relay.offer(candidate(&allowance(), 1), now),
        1 => relay.guest_output(b"abc\x1b[3".to_vec(), now),
        2 => relay.guest_output(b"2mdef".to_vec(), now),
        3 => {
            let g = relay.generation();
            relay.written(g, now);
        }
        4 => {
            relay.host_input(chunk(b"s", entropy), now);
        }
        5 => {
            let g = relay.generation();
            relay.granted(
                g,
                PromptGrant::Reached(GrantResult::Refused {
                    reason: crate::allowances::GrantRefusalReason::Full { limit: 256 },
                }),
                now,
            );
        }
        6 => relay.resized(Size { rows: 30, cols: 80 }, now),
        7 => relay.answered(&allowance(), now),
        _ => relay.handle_deadline(now),
    }
}

/// I5, checked exactly as stated: after `handle_deadline(now)`, the next deadline
/// is `None` or later than `now`.
fn assert_deadline_consumed(relay: &mut Relay, now: Instant) {
    relay.handle_deadline(now);
    if let Some(deadline) = relay.deadline() {
        assert!(
            deadline > now,
            "after handling a deadline at {now:?}, the relay reports {deadline:?}"
        );
    }
}

#[test]
fn a_deadline_is_consumed_when_it_fires() {
    // The deterministic sweep (a fixed LCG), kept alongside the proptest: it runs
    // on every build with no test budget, and it is the one a reader can replay.
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        seed >> 33
    };
    for _ in 0..200 {
        let mut relay = fresh();
        let mut now = Instant::now();
        for _ in 0..12 {
            let step = (next() % 9) as u8;
            now += std::time::Duration::from_millis(next() % 3000);
            apply_step(&mut relay, step, now, next());
            assert_deadline_consumed(&mut relay, now);
        }
    }
}

proptest::proptest! {
    // I5 as the plan names it: a property over random input/output/grant/write/
    // resize/deadline sequences. The generator produces event *kinds* and the
    // clock advances between them, so the walk reaches every phase.
    #![proptest_config(proptest::prelude::ProptestConfig {
        cases: 128,
        ..proptest::prelude::ProptestConfig::default()
    })]

    #[test]
    fn no_fired_deadline_is_reported_again(
        events in proptest::collection::vec(
            (0u8..9, 0u64..4000, proptest::prelude::any::<u64>()),
            1..40
        )
    ) {
        let mut relay = fresh();
        let mut now = Instant::now();
        for (step, delay, entropy) in events {
            now += std::time::Duration::from_millis(delay);
            apply_step(&mut relay, step, now, entropy);
            relay.handle_deadline(now);
            if let Some(deadline) = relay.deadline() {
                proptest::prop_assert!(
                    deadline > now,
                    "after handling a deadline at {:?}, the relay reports {:?}",
                    now, deadline
                );
            }
        }
    }
}

#[test]
fn an_unanswered_question_is_refused_sixty_seconds_after_it_became_visible() {
    let mut relay = fresh();
    let now = Instant::now();
    asking(&mut relay, now);
    assert_eq!(
        relay.deadline(),
        Some(now + PROMPT_TIMEOUT),
        "the timeout is the only deadline a visible question has, and it runs from \
         visibility, not from the settle window"
    );
    relay.handle_deadline(now + PROMPT_TIMEOUT);
    assert_eq!(relay.phase_name(), "restoring");
}

#[test]
fn a_second_destination_draws_the_waiting_count_with_the_current_status() {
    // Finding 10: a queued second destination produced no frame at all, so the
    // "+N more waiting" the plan promises was never shown.
    let mut relay = fresh();
    let now = Instant::now();
    let visible = asking(&mut relay, now);
    while let Some(_item) = relay.take_outbound_if(|_| true) {}
    let other = Allowance::parse("tcp://[203.0.113.11]:443").unwrap();
    relay.offer(candidate(&other, 1), visible);
    let out = frames(&mut relay);
    let redraw = out
        .iter()
        .find_map(|item| match item {
            OutputItem::Takeover {
                step: Step::Redraw,
                bytes,
                ..
            } => Some(String::from_utf8_lossy(bytes).into_owned()),
            _ => None,
        })
        .expect("a count change must be drawn");
    assert!(redraw.contains("+1 more waiting"), "{redraw}");
    // The waiting count sits under the input row, where the status would be.
    assert!(redraw.contains("Type one of the below letters"), "{redraw}");
}

#[test]
fn a_resize_in_lingering_redraws_the_result() {
    // Finding 10: a resize in `Lingering` replaced the grant's sentence with the
    // whole question.
    let mut relay = fresh();
    let now = Instant::now();
    let visible = asking(&mut relay, now);
    let g = relay.generation();
    let quiet = settled(visible);
    typed(&mut relay, b"s", quiet);
    relay.granted(
        g,
        PromptGrant::Reached(GrantResult::Applied {
            destination: allowance().to_string(),
            scope: GrantScope::Session,
            revision: 2,
            recorded_ms: 0,
        }),
        quiet,
    );
    while let Some(_item) = relay.take_outbound_if(|_| true) {}
    relay.resized(
        Size {
            rows: 40,
            cols: 100,
        },
        quiet,
    );
    let out = frames(&mut relay);
    let redraw = out
        .iter()
        .find_map(|item| match item {
            OutputItem::Takeover {
                step: Step::Redraw,
                bytes,
                ..
            } => Some(String::from_utf8_lossy(bytes).into_owned()),
            _ => None,
        })
        .expect("the resize must redraw");
    assert!(redraw.contains("Retry the request now."), "{redraw}");
    assert!(redraw.contains("Undo: agent-vm access revoke"), "{redraw}");
    assert!(
        !redraw.contains("keep refusing"),
        "the result must not be replaced by the question: {redraw}"
    );
}

#[test]
fn a_resize_while_confirming_keeps_the_position_the_request_named() {
    // Finding 20: the expected position was recomputed from the current size, so a
    // resize between the request and its reply made the real reply look like typing,
    // cost the 1 s fallback and turned cursor-position replies off for the session.
    let mut relay = fresh();
    let now = Instant::now();
    relay.offer(candidate(&allowance(), 1), now);
    let g = relay.generation();
    relay.written(g, now);
    assert_eq!(relay.phase_name(), "confirming");
    let asked = relay
        .asked_position
        .expect("the frame asked for a position");
    // The terminal is resized before it answers.
    relay.resized(Size { rows: 24, cols: 60 }, now);
    assert_eq!(
        relay.phase_name(),
        "confirming",
        "a confirming resize does not close"
    );
    let reply = format!("\x1b[{};{}R", asked.row, asked.col);
    relay.host_input(chunk(reply.as_bytes(), 1), now);
    assert_eq!(
        relay.phase_name(),
        "asking",
        "the reply that names the requested position must make the prompt visible"
    );
}

#[test]
fn a_resize_that_does_not_fit_refuses_the_question() {
    let mut relay = fresh();
    let now = Instant::now();
    asking(&mut relay, now);
    relay.resized(Size { rows: 30, cols: 80 }, now);
    assert_eq!(relay.phase_name(), "asking");
    let mut redraws = 0;
    while let Some(item) = relay.take_outbound_if(|_| true) {
        if matches!(
            item,
            Outbound::Frame(OutputItem::Takeover {
                step: Step::Redraw,
                ..
            })
        ) {
            redraws += 1;
        }
    }
    assert_eq!(redraws, 1, "a fitting resize redraws the question");
    relay.resized(Size { rows: 10, cols: 30 }, now);
    assert_eq!(relay.phase_name(), "restoring");
}

#[test]
fn input_ending_refuses_the_open_question_and_stops_further_prompts() {
    let mut relay = fresh();
    let now = Instant::now();
    asking(&mut relay, now);
    relay.input_ended(now);
    assert_eq!(relay.phase_name(), "restoring");
    let g = relay.generation();
    relay.written(g, now);
    relay.handle_deadline(now + RELEASE_GAP);
    relay.offer(candidate(&allowance(), 1), now + RELEASE_GAP);
    assert_eq!(
        relay.phase_name(),
        "idle",
        "no further prompt in this session"
    );
}

#[test]
fn an_unknown_terminal_state_declines_the_takeover() {
    let mut relay = fresh();
    let now = Instant::now();
    relay.guest_output(b"\x1b[?1049h\x1bc".to_vec(), now);
    let _ = frames(&mut relay);
    assert!(relay.vt.modes().restorable().is_none());
    relay.offer(candidate(&allowance(), 1), now);
    assert_eq!(relay.phase_name(), "idle", "declined, left to `access`");
}

#[test]
fn the_release_gap_starts_at_the_leave_s_confirmation() {
    // I4: a second question cannot start before the gap ends.
    let mut relay = fresh();
    let now = Instant::now();
    asking(&mut relay, now);
    let other = Allowance::parse("tcp://[203.0.113.11]:443").unwrap();
    relay.offer(candidate(&other, 1), now);
    let quiet = settled(now);
    typed(&mut relay, b"d", quiet);
    let g = relay.generation();
    relay.handle_deadline(now);
    // Now Restoring (the refusal queued the leave); confirm the leave later.
    let released = now + std::time::Duration::from_millis(100);
    relay.written(g, released);
    assert_eq!(relay.phase_name(), "idle");
    assert_eq!(relay.deadline(), Some(released + RELEASE_GAP));
    relay.handle_deadline(released + RELEASE_GAP - std::time::Duration::from_millis(1));
    assert_eq!(relay.phase_name(), "idle");
    relay.handle_deadline(released + RELEASE_GAP);
    // At a boundary the next question takes over at once (`Cutting` → `Entering`).
    assert_eq!(relay.phase_name(), "entering");
}

#[test]
fn a_grant_whose_result_no_longer_fits_still_ends_the_takeover() {
    // M1: no result frame meant no 1.5 s, no deadline, and a takeover that never
    // ended — input consumed and guest output held for ever.
    let mut relay = Relay::new(
        "3f9a12c4".to_owned(),
        Size { rows: 30, cols: 80 },
        Timings::default(),
        None,
    );
    let now = Instant::now();
    let visible = asking(&mut relay, now);
    let g = relay.generation();
    let quiet = settled(visible);
    typed(&mut relay, b"s", quiet);
    assert_eq!(relay.phase_name(), "granting");
    // Eight destinations wait and one overflows while the grant is running.
    for index in 0..9u16 {
        let destination =
            Allowance::parse(&format!("tcp://[203.0.113.{}]:443", index + 20)).unwrap();
        relay.offer(candidate(&destination, 1), now);
    }
    assert_eq!(relay.waiting_len(), 8);
    // The question can no longer be laid out at all (a terminal below the takeover
    // minimum): the result must still be drawn, because it is laid out from the
    // geometry alone.
    relay.size = Size { rows: 12, cols: 40 };
    relay.granted(
        g,
        PromptGrant::Reached(GrantResult::Applied {
            destination: allowance().to_string(),
            scope: GrantScope::Session,
            revision: 2,
            recorded_ms: 0,
        }),
        quiet,
    );
    assert_eq!(relay.phase_name(), "lingering");
    let deadline = relay
        .deadline()
        .expect("a lingering takeover always has a deadline (M1)");
    let out = frames(&mut relay);
    assert!(
        out.iter().any(|item| matches!(
            item,
            OutputItem::Takeover {
                step: Step::Redraw,
                ..
            }
        )),
        "the result must be drawn from the terminal's geometry, not the question's"
    );
    relay.handle_deadline(deadline);
    assert_eq!(relay.phase_name(), "restoring");
}

#[test]
fn every_redraw_lays_out_the_whole_question() {
    // M2: a partial redraw used a layout of its own, so at narrow widths it wrote
    // over the key lines. Every redraw is a whole layout, and a typed letter is
    // echoed on the input row with the keys still visible.
    let mut relay = Relay::new(
        "3f9a12c4".to_owned(),
        Size {
            rows: crate::access_prompt::screen::MIN_ROWS,
            cols: crate::access_prompt::screen::MIN_COLS,
        },
        Timings::default(),
        None,
    );
    let now = Instant::now();
    let visible = asking(&mut relay, now);
    let quiet = settled(visible);
    // A second destination: the question now carries a count row.
    let other = Allowance::parse("tcp://[203.0.113.11]:443").unwrap();
    relay.offer(candidate(&other, 1), now);
    while let Some(_item) = relay.take_outbound_if(|_| true) {}
    // A typed letter is echoed, and the whole question is redrawn around it.
    relay.host_input(chunk(b"s", 2), visible);
    let out = frames(&mut relay);
    let rows = last_redraw(&out).expect("the typed letter is drawn");
    assert!(rows.contains("s_"), "the letter is echoed: {rows}");
    assert!(rows.contains("d deny"), "the d key line is hidden: {rows}");
    assert!(rows.contains("n never"), "the n key line is hidden: {rows}");
    assert!(rows.contains("+1 more waiting"), "{rows}");
    for row in rows.lines() {
        assert!(row.chars().count() <= 39, "{row:?} exceeds 40 columns");
    }
    // A paste (a multi-byte read) clears the line and is drawn as cleared.
    relay.host_input(chunk(b"\x1b[200~", 3), quiet);
    let out = frames(&mut relay);
    let rows = last_redraw(&out).expect("the cleared line is drawn");
    assert!(rows.contains("Type one of the below letters"), "{rows}");
    assert!(rows.contains("d deny"), "{rows}");
}

#[test]
fn a_lone_escape_after_an_abandoned_partial_still_refuses() {
    // M8: a deliberate Esc after an unfinished sequence was marked `continued` and
    // ignored, so the prompt stayed open instead of refusing.
    let mut relay = fresh();
    let now = Instant::now();
    let visible = asking(&mut relay, now);
    relay.host_input(chunk(b"\x1b[", 2), visible);
    assert_eq!(relay.phase_name(), "asking");
    relay.host_input(chunk(b"\x1b", 3), visible);
    assert_eq!(
        relay.phase_name(),
        "restoring",
        "a quiet lone Esc must refuse"
    );
}

#[test]
fn a_split_ss3_sequence_never_grants() {
    // M4: `ESC O` (SS3) takes one more byte; treating it as complete let `ESC O` |
    // `s` reach the guard as a lone `s`.
    let mut relay = fresh();
    let now = Instant::now();
    let visible = asking(&mut relay, now);
    relay.host_input(chunk(b"\x1bO", 2), visible);
    let later = settled(visible) + std::time::Duration::from_millis(800);
    // The final byte of the sequence is not one of the operator's keys.
    relay.host_input(chunk(b"s", 3), visible);
    assert_eq!(relay.answer_line, "", "the SS3 final byte must not type");
    assert_eq!(relay.phase_name(), "asking");
    // Typed properly, the same letter does answer.
    typed(&mut relay, b"s", later);
    assert_eq!(relay.phase_name(), "granting");
}

#[test]
fn a_declined_forced_cut_leaves_the_tracker_where_the_terminal_is() {
    // M7: `cancelled()` ran before the takeover was decided, so a decline left the
    // tracker at ground while the terminal was still inside the guest's sequence.
    let mut relay = fresh();
    let now = Instant::now();
    relay.guest_output(b"\x1b[3".to_vec(), now);
    let _ = frames(&mut relay);
    relay.offer(candidate(&allowance(), 1), now);
    assert_eq!(relay.phase_name(), "cutting");
    relay.resized(Size { rows: 10, cols: 30 }, now);
    relay.handle_deadline(now + CUT_DEADLINE);
    assert_eq!(relay.phase_name(), "idle", "the question cannot fit");
    assert!(
        !relay.vt.at_safe_boundary(),
        "no CAN was sent, so the terminal is still inside the sequence"
    );
    // A later question cuts at the real boundary rather than entering blind.
    relay.resized(Size { rows: 30, cols: 80 }, now);
    let next = now + CUT_DEADLINE + RELEASE_GAP;
    relay.handle_deadline(next);
    relay.offer(candidate(&allowance(), 1), next);
    assert_eq!(relay.phase_name(), "cutting");
    relay.guest_output(b"1m".to_vec(), next);
    let out = frames(&mut relay);
    assert_eq!(
        take_steps(&out),
        vec![Step::Enter {
            screen: Screen::Main
        }],
        "the completed sequence is forwarded, then the prompt"
    );
}

#[test]
fn a_settling_destination_is_not_asked_again_after_its_late_grant() {
    // M10/R29: the late grant's own wakeup used to un-settle the destination, so a
    // fresh refusal prompted again.
    let mut relay = fresh();
    let now = Instant::now();
    let visible = asking(&mut relay, now);
    let g = relay.generation();
    let quiet = settled(visible);
    typed(&mut relay, b"p", quiet);
    relay.grant_unconfirmed(g, quiet);
    let destination = allowance();
    assert!(relay.settling.contains(&destination));
    // The grant lands late: its wakeup arrives.
    relay.answered(&destination, quiet);
    assert!(
        relay.settling.contains(&destination),
        "settling must survive the wakeup (R29)"
    );
    // And a later refusal of the same destination does not prompt.
    let linger = relay
        .deadline()
        .expect("a lingering takeover has a deadline");
    relay.handle_deadline(linger);
    assert_eq!(relay.phase_name(), "restoring");
    let g = relay.generation();
    while let Some(_item) = relay.take_outbound_if(|_| true) {}
    relay.written(g, linger);
    assert_eq!(relay.phase_name(), "idle");
    relay.handle_deadline(linger + RELEASE_GAP);
    relay.offer(candidate(&destination, 1), linger + RELEASE_GAP);
    assert_eq!(
        relay.phase_name(),
        "idle",
        "a settling destination is not re-asked"
    );
}

#[test]
fn a_grant_waiting_for_its_slot_does_not_block_the_frames_behind_it() {
    // M6: a `Grant` at the head of the outbound queue held back every frame while its
    // slot was busy, including the "allowing..." redraw.
    let mut relay = fresh();
    let now = Instant::now();
    let visible = asking(&mut relay, now);
    let quiet = settled(visible);
    typed(&mut relay, b"s", quiet);
    let mut order = Vec::new();
    while let Some(item) = relay.take_outbound_if(|head| matches!(head, Outbound::Frame(_))) {
        order.push(match item {
            Outbound::Frame(_) => "frame",
            _ => "other",
        });
    }
    assert!(
        order.contains(&"frame"),
        "a frame behind the grant must be takeable: {order:?}"
    );
    // The grant is still there, and the next predicate gets it.
    assert!(matches!(
        relay.take_outbound_if(|head| matches!(head, Outbound::Grant(_))),
        Some(Outbound::Grant(_))
    ));
}

#[test]
fn an_answer_that_closes_the_question_does_not_grant_or_queue_a_second_leave() {
    // Round 3, A R2-1/B B1: an "allowing..." redraw that no longer fitted closed the
    // question (queueing the Leave), and `answer` then overwrote the phase with
    // `Granting`. The Leave's confirmation was dropped, the result discarded, the next
    // Leave refused by the writer, and the session died with a writer error.
    //
    // The status row is always present now, so a status change cannot add a row: the
    // only way a redraw fails is a terminal below the takeover minimum.
    let mut relay = Relay::new(
        "3f9a12c4".to_owned(),
        Size { rows: 30, cols: 80 },
        Timings::default(),
        None,
    );
    let now = Instant::now();
    let visible = asking(&mut relay, now);
    let quiet = settled(visible);
    relay.size = Size { rows: 12, cols: 40 };
    typed(&mut relay, b"s", quiet);
    assert_eq!(
        relay.phase_name(),
        "restoring",
        "an answer that cannot be drawn closes the question"
    );
    let out = frames(&mut relay);
    let leaves = out
        .iter()
        .filter(|item| {
            matches!(
                item,
                OutputItem::Takeover {
                    step: Step::Leave,
                    ..
                }
            )
        })
        .count();
    assert_eq!(leaves, 1, "exactly one Leave is queued: {out:?}");
    assert!(
        !out.iter().any(|item| matches!(
            item,
            OutputItem::Takeover {
                step: Step::Redraw,
                ..
            }
        )),
        "no frame follows the leave: {out:?}"
    );
    // The leave's confirmation ends the takeover normally; no second leave is owed.
    let g = relay.generation();
    relay.written(g, quiet);
    assert_eq!(relay.phase_name(), "idle");
    assert!(frames(&mut relay).is_empty(), "nothing else is queued");
}

#[test]
fn a_refusal_while_the_result_is_up_does_not_extend_the_linger() {
    // Round 3, A R2-2/AC11: every accepted redraw restarted the 1.5 s, so a refusal per
    // second held the terminal indefinitely.
    let mut relay = fresh();
    let now = Instant::now();
    let visible = asking(&mut relay, now);
    let g = relay.generation();
    let quiet = settled(visible);
    typed(&mut relay, b"s", quiet);
    relay.granted(
        g,
        PromptGrant::Reached(GrantResult::Applied {
            destination: allowance().to_string(),
            scope: GrantScope::Session,
            revision: 2,
            recorded_ms: 0,
        }),
        quiet,
    );
    let accepted = quiet + std::time::Duration::from_millis(100);
    relay.frame_taken(accepted);
    let deadline = relay.deadline().expect("a deadline");
    assert_eq!(deadline, accepted + RESULT_LINGER);
    // A destination refused a second later: the result is redrawn, the timer is not.
    let later = accepted + std::time::Duration::from_secs(1);
    let other = Allowance::parse("tcp://[203.0.113.11]:443").unwrap();
    relay.offer(candidate(&other, 1), later);
    while let Some(item) = relay.take_outbound_if(|_| true) {
        if matches!(
            item,
            Outbound::Frame(OutputItem::Takeover {
                step: Step::Redraw,
                ..
            })
        ) {
            relay.frame_taken(later + std::time::Duration::from_millis(50));
        }
    }
    assert_eq!(
        relay.deadline(),
        Some(deadline),
        "an arriving refusal may update the result but not extend the linger"
    );
    relay.handle_deadline(deadline);
    assert_eq!(relay.phase_name(), "restoring");
}

#[test]
fn a_resize_to_a_tiny_terminal_closes_a_lingering_question() {
    // Round 3, C C-R2-1: `close_phase` had no `Lingering` arm, so a too-small resize
    // could not end a result that was on screen.
    let mut relay = fresh();
    let now = Instant::now();
    let visible = asking(&mut relay, now);
    let g = relay.generation();
    let quiet = settled(visible);
    typed(&mut relay, b"d", quiet);
    assert_eq!(relay.phase_name(), "restoring");
    // A second takeover, this time answered with a grant, to reach Lingering.
    let released = quiet;
    while let Some(_item) = relay.take_outbound_if(|_| true) {}
    relay.written(g, released);
    relay.handle_deadline(released + RELEASE_GAP);
    relay.offer(candidate(&allowance(), 1), released + RELEASE_GAP);
    let g = relay.generation();
    relay.written(g, released + RELEASE_GAP);
    let quiet2 = settled(released + RELEASE_GAP);
    let laid = screen::layout(&relay.current_view(), relay.size).expect("fits");
    let reply = reply_to(laid);
    relay.host_input(chunk(reply.as_bytes(), 1), released + RELEASE_GAP);
    relay.input_flushed(1, released + RELEASE_GAP);
    typed(&mut relay, b"s", quiet2);
    assert_eq!(relay.phase_name(), "granting");
    while let Some(_item) = relay.take_outbound_if(|_| true) {}
    relay.granted(
        g,
        PromptGrant::Reached(GrantResult::Applied {
            destination: allowance().to_string(),
            scope: GrantScope::Session,
            revision: 2,
            recorded_ms: 0,
        }),
        quiet2,
    );
    assert_eq!(relay.phase_name(), "lingering");
    relay.resized(Size { rows: 2, cols: 2 }, quiet2);
    assert_eq!(
        relay.phase_name(),
        "restoring",
        "a terminal the result cannot fit must close the question"
    );
}

// ------------------------------------------------- the line, through the relay ---
// The proved kernels own the rules; these run them through `host_input` and
// `edit_line`, the adapter ADR-0018 names, so a rule that is right but wired wrong
// still fails here.

#[test]
fn a_word_answers_exactly_as_its_letter_does() {
    // The two spellings are one answer each, and the question draws words, so a
    // word typed letter by letter must submit the same thing as the letter.
    for (word, letter, expected) in [
        (b"session".as_slice(), b's', "granting"),
        (b"project".as_slice(), b'p', "granting"),
        (b"deny".as_slice(), b'd', "restoring"),
        (b"never".as_slice(), b'n', "restoring"),
    ] {
        for keys in [word.to_vec(), vec![letter]] {
            let mut relay = fresh();
            let now = Instant::now();
            let visible = asking(&mut relay, now);
            typed(&mut relay, &keys, visible);
            assert_eq!(
                relay.phase_name(),
                expected,
                "{:?} must answer as {:?}",
                String::from_utf8_lossy(&keys),
                expected
            );
        }
    }
}

#[test]
fn backspace_erases_and_the_line_stops_at_the_cap() {
    let mut relay = fresh();
    let now = Instant::now();
    let visible = asking(&mut relay, now);
    // `sessionx`, then one Backspace: the line is `session` and answers.
    for (epoch, byte) in b"sessionx".iter().enumerate() {
        key(&mut relay, *byte, epoch as u64 + 2, visible);
    }
    assert_eq!(relay.answer_line, "sessionx");
    key(&mut relay, 0x7f, 20, visible);
    assert_eq!(relay.answer_line, "session");
    key(&mut relay, b'\r', 22, visible);
    assert_eq!(relay.phase_name(), "granting", "the erased line answers");

    // Backspace on an empty line does nothing and never redraws.
    let mut relay = fresh();
    let now = Instant::now();
    let visible = asking(&mut relay, now);
    while relay.take_outbound_if(|_| true).is_some() {}
    key(&mut relay, 0x7f, 2, visible);
    assert_eq!(relay.answer_line, "");
    assert!(
        relay.outbound.iter().all(|item| !matches!(
            item,
            Outbound::Frame(OutputItem::Takeover {
                step: Step::Redraw,
                ..
            })
        )),
        "an erase that erases nothing draws nothing"
    );

    // The cap: the line stops at `MAX_ANSWER_CHARS` and further letters are dropped
    // rather than growing it.
    let mut relay = fresh();
    let now = Instant::now();
    let visible = asking(&mut relay, now);
    for epoch in 0..(guard::MAX_ANSWER_CHARS as u64 + 4) {
        key(&mut relay, b's', epoch + 2, visible);
    }
    assert_eq!(relay.answer_line.len(), guard::MAX_ANSWER_CHARS);
    assert_eq!(relay.phase_name(), "asking", "the line is not an answer");
}

#[test]
fn a_line_that_is_not_an_answer_does_nothing_at_all() {
    let mut relay = fresh();
    let now = Instant::now();
    let visible = asking(&mut relay, now);
    // `sessionx`: nearly an answer, and Enter submits it to nothing.
    typed(&mut relay, b"sessionx", visible);
    assert_eq!(
        relay.phase_name(),
        "asking",
        "an unknown line is not an answer"
    );
    assert_eq!(relay.answer_line, "sessionx", "the line is still there");
    // Case is folded, so the operator's capitals still answer.
    let mut relay = fresh();
    let now = Instant::now();
    let visible = asking(&mut relay, now);
    typed(&mut relay, b"SESSION", visible);
    assert_eq!(relay.phase_name(), "granting");
}

#[test]
fn a_non_letter_clears_the_line_so_a_line_never_holds_one() {
    // `s` then `1`: the `1` clears, so the line is empty and Enter refuses — it can
    // never submit the `s` the operator did not mean to offer.
    let mut relay = fresh();
    let now = Instant::now();
    let visible = asking(&mut relay, now);
    key(&mut relay, b's', 2, visible);
    assert_eq!(relay.answer_line, "s");
    key(&mut relay, b'1', 3, visible);
    assert_eq!(relay.answer_line, "", "a byte that is not a letter clears");
    key(&mut relay, b'\r', 4, visible);
    assert_eq!(
        relay.phase_name(),
        "restoring",
        "Enter on the empty line refuses"
    );
}

#[test]
fn nothing_counts_until_the_question_has_been_readable_for_the_settle_window() {
    // The tail of typing aimed at the guest: a key, a Backspace and an Esc that all
    // arrive in the first `SETTLE_MS` do nothing at all — the Esc must not even
    // refuse, because the operator has not read the question yet.
    let mut relay = fresh();
    let now = Instant::now();
    let visible = asking(&mut relay, now);
    let too_soon = visible - super::SETTLE_MS + std::time::Duration::from_millis(1);
    for (epoch, byte) in [(2u64, b's'), (3, b'p'), (4, 0x7f), (5, 0x1b), (6, b'\r')] {
        relay.host_input(chunk(&[byte], epoch), too_soon);
    }
    assert_eq!(
        relay.phase_name(),
        "asking",
        "the settle window ignores everything"
    );
    assert_eq!(relay.answer_line, "");
    // One instant later the same bytes are the operator's.
    key(&mut relay, b's', 7, visible);
    assert_eq!(relay.answer_line, "s");
}
