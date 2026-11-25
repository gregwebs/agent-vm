//! V15-V16: the answer reader and the prompt's decision sequence, with a faked
//! terminal. Nothing here opens a store, a terminal, or a file: the prompt's
//! inputs are a [`DiffState`] and a fake, which is what makes the
//! foreground/flush ordering testable at all.

use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Read, Write};
use std::path::Path;

use super::*;
use crate::config_pins::{ContentHash, Current, LiveGeneration, PinKey, StoreId};

const PATH: &str = "/w/app/conf/agent-vm.toml";

fn key() -> PinKey {
    PinKey::for_source(Path::new(PATH)).unwrap()
}

fn generation() -> LiveGeneration {
    LiveGeneration {
        store_id: StoreId::parse_hex("22222222222222222222222222222222").unwrap(),
        reset_epoch: 1,
    }
}

/// A state with no manifest: every key is a first approval.
fn empty_state() -> DiffState {
    DiffState {
        generation: generation(),
        current: Current::empty(generation()),
        snapshots: BTreeMap::new(),
        unavailable: BTreeMap::new(),
    }
}

/// A state whose one key has exactly `candidate` approved, as a concurrent
/// reviewer's commit would leave it.
fn approved_state(candidate: &[u8]) -> DiffState {
    let hash = ContentHash::of(candidate);
    let manifest = format!(
        r#"{{"v":1,"store_id":"{id}","reset_epoch":1,"sources":[{{"path":"{PATH}","active":"{hash}","approved":[{{"sha256":"{hash}","approved_ms":1,"active_ms":1}}]}}]}}"#,
        id = generation().store_id.hex(),
        hash = hash.hex(),
    );
    DiffState {
        generation: generation(),
        current: Current::decode(manifest.as_bytes()).expect("the fixture manifest decodes"),
        snapshots: BTreeMap::new(),
        unavailable: BTreeMap::new(),
    }
}

fn candidate() -> Vec<u8> {
    b"a = 1\nb = 2\n".to_vec()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Call {
    Verify,
    Discard,
    Read,
}

/// A terminal whose every operation, result and order is chosen by the test.
struct Fake {
    calls: Vec<Call>,
    verify: VecDeque<Result<(), &'static str>>,
    discard: Result<(), &'static str>,
    read: Result<Answer, &'static str>,
}

impl Fake {
    fn answering(answer: Answer) -> Self {
        Self {
            calls: Vec::new(),
            verify: VecDeque::new(),
            discard: Ok(()),
            read: Ok(answer),
        }
    }

    fn verifying(results: impl IntoIterator<Item = Result<(), &'static str>>) -> Self {
        Self {
            verify: results.into_iter().collect(),
            ..Self::answering(Answer::Decline)
        }
    }
}

impl ApprovalTerminal for Fake {
    fn verify_foreground(&mut self) -> io::Result<()> {
        self.calls.push(Call::Verify);
        self.verify.pop_front().unwrap_or(Ok(())).map_err(failure)
    }

    fn discard_pending_input(&mut self) -> io::Result<()> {
        self.calls.push(Call::Discard);
        self.discard.map_err(failure)
    }

    fn read_answer(&mut self) -> io::Result<Answer> {
        self.calls.push(Call::Read);
        self.read.map_err(failure)
    }
}

fn failure(message: &'static str) -> io::Error {
    io::Error::other(message)
}

/// A transcript sink that fails on its first byte.
struct FailingSink;

impl Write for FailingSink {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("no transcript today"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// One pending source rendered to a recorder, so a test can assert both the
/// outcome and exactly what the user would have seen.
fn run_with(
    state: &DiffState,
    terminal: &mut dyn ApprovalTerminal,
) -> (io::Result<Outcome>, Vec<u8>) {
    let candidate = candidate();
    let pin_key = key();
    let pending = [PendingSource::for_tests(pin_key, candidate)];
    let mut sink = Vec::new();
    let outcome = run(&pending, state, terminal, &mut sink);
    (outcome, sink)
}

// ---- V15: the answer reader ----

#[test]
fn only_a_complete_yes_approves() {
    let approved: [&[u8]; 4] = [b"y\n", b"Y\r\n", b"yes\n", b"  YES \t\n"];
    for input in approved {
        assert_eq!(
            read_answer(&mut &input[..]).unwrap(),
            Answer::Approve,
            "{input:?}"
        );
    }

    let denied: [&[u8]; 9] = [
        b"\n",
        b"n\n",
        b"no\n",
        b"yess\n",
        b"y es\n",
        b"y",
        b"y\xff\n",
        b"\x04\n",
        b"yesnow\n",
    ];
    for input in denied {
        assert_eq!(
            read_answer(&mut &input[..]).unwrap(),
            Answer::Decline,
            "{input:?}"
        );
    }
}

/// R9/B3: the answer bound is 64 bytes **including** the terminating LF, so a
/// padded line one byte over the cap is refused rather than trimmed down to a
/// yes. The boundary is exercised at both sides, not asserted as a constant.
#[test]
fn the_answer_bound_counts_the_terminating_newline() {
    // 1 + 62 + 1 = 64 bytes: the longest answer this build accepts.
    let mut at_cap = b"y".to_vec();
    at_cap.extend_from_slice(&[b' '; 62]);
    at_cap.push(b'\n');
    assert_eq!(at_cap.len(), MAX_ANSWER_BYTES);
    assert_eq!(read_answer(&mut &at_cap[..]).unwrap(), Answer::Approve);

    // 1 + 63 + 1 = 65 bytes: one byte over, so it is not an answer at all.
    let mut over = b"y".to_vec();
    over.extend_from_slice(&[b' '; 63]);
    over.push(b'\n');
    assert_eq!(over.len(), MAX_ANSWER_BYTES + 1);
    assert_eq!(
        over.len() - 1,
        MAX_ANSWER_BYTES,
        "one content byte too many"
    );
    assert_eq!(read_answer(&mut &over[..]).unwrap(), Answer::Decline);
}

/// R9/B3: only spaces and tabs are trailing whitespace. A vertical tab or a
/// form feed is a control byte, and a control byte never approves.
#[test]
fn only_spaces_and_tabs_are_trimmed_from_an_answer() {
    assert_eq!(
        read_answer(&mut &b"  yes \t\n"[..]).unwrap(),
        Answer::Approve
    );
    for denied in [
        &b"y\x0b\n"[..],
        &b"y\x0c\n"[..],
        &b"\x0by\n"[..],
        &b"\x0cy\n"[..],
        &b"y\x00\n"[..],
        &b"y\x1f\n"[..],
    ] {
        assert_eq!(
            read_answer(&mut &denied[..]).unwrap(),
            Answer::Decline,
            "{denied:?}"
        );
    }
}

#[test]
fn a_long_whitespace_padded_prefix_cannot_be_truncated_into_a_yes() {
    let mut input = b"y".to_vec();
    input.extend_from_slice(&[b' '; 70]);
    input.extend_from_slice(b"no\n");
    assert_eq!(read_answer(&mut &input[..]).unwrap(), Answer::Decline);
}

#[test]
fn no_byte_at_all_is_no_answer_and_not_a_decline() {
    assert_eq!(read_answer(&mut &b""[..]).unwrap(), Answer::NoAnswer);
}

#[test]
fn nothing_after_the_answer_line_is_consumed() {
    let mut input: &[u8] = b"y\nleft for the guest";
    assert_eq!(read_answer(&mut input).unwrap(), Answer::Approve);
    assert_eq!(input, b"left for the guest");
}

#[test]
fn a_read_error_fails_closed() {
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from_raw_os_error(libc::EIO))
        }
    }
    let error = read_answer(&mut Broken).unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::EIO));
}

// ---- V16: the prompt sequence ----

#[test]
fn a_typed_yes_approves_after_showing_the_review() {
    let state = empty_state();
    let mut terminal = Fake::answering(Answer::Approve);
    let (outcome, transcript) = run_with(&state, &mut terminal);
    assert_eq!(outcome.unwrap(), Outcome::Approved);
    assert!(transcript.starts_with(b"==> source /w/app/conf/agent-vm.toml: never approved\n"));
    assert!(
        transcript.windows(4).any(|window| window == &b"+a ="[..]),
        "the review is in the transcript"
    );
    assert!(transcript.ends_with(b"? [y/N] "));
    assert_eq!(
        terminal.calls,
        vec![Call::Verify, Call::Verify, Call::Discard, Call::Read],
        "foreground twice, flush, then read"
    );
}

#[test]
fn a_decline_and_an_absent_answer_are_different_outcomes() {
    for (answer, expected) in [
        (Answer::Decline, Outcome::Declined),
        (Answer::NoAnswer, Outcome::NoAnswer),
    ] {
        let mut terminal = Fake::answering(answer);
        let (outcome, transcript) = run_with(&empty_state(), &mut terminal);
        assert_eq!(outcome.unwrap(), expected);
        assert_eq!(terminal.calls.last(), Some(&Call::Read));
        assert!(transcript.ends_with(b"? [y/N] "));
    }
}

#[test]
fn an_oversized_review_never_asks_and_names_the_cap_and_the_advice() {
    let state = empty_state();
    let huge = vec![b'a'; crate::config_pins::diff::MAX_LINE_CHARS + 1];
    let pin_key = key();
    let pending = [PendingSource::for_tests(pin_key, huge)];
    let mut terminal = Fake::answering(Answer::Approve);
    let mut sink = Vec::new();
    let outcome = run(&pending, &state, &mut terminal, &mut sink).unwrap();
    let Outcome::TooLarge(too_large) = outcome else {
        panic!("an oversized review must not be answered: {outcome:?}");
    };
    assert_eq!(too_large.cap, crate::config_pins::diff::Cap::LineChars);
    assert_eq!(too_large.key, key());

    let refusal = String::from_utf8(sink).unwrap();
    assert!(
        refusal.contains("too large to approve interactively"),
        "{refusal}"
    );
    assert!(
        refusal.contains(&format!(
            "{} characters",
            crate::config_pins::diff::MAX_LINE_CHARS
        )),
        "the cap is named: {refusal}"
    );
    assert!(refusal.contains("`agent-vm config diff`"), "{refusal}");
    assert!(refusal.contains("`agent-vm config approve`"), "{refusal}");
    assert!(!refusal.contains("[y/N]"), "{refusal}");
    assert!(terminal.calls.is_empty(), "the terminal is not touched");
}

#[test]
fn a_terminal_that_is_not_the_foreground_process_group_never_prompts() {
    let mut terminal = Fake::verifying([Err("not the foreground process group")]);
    let (outcome, transcript) = run_with(&empty_state(), &mut terminal);
    let error = outcome.unwrap_err();
    assert!(error.to_string().contains("foreground"), "{error}");
    assert_eq!(terminal.calls, vec![Call::Verify]);
    assert!(
        !transcript.windows(4).any(|window| window == &b"[y/N"[..]),
        "no question was printed"
    );
}

#[test]
fn losing_the_foreground_after_the_question_is_written_is_caught_before_reading() {
    let mut terminal = Fake::verifying([Ok(()), Err("backgrounded during the question")]);
    let (outcome, transcript) = run_with(&empty_state(), &mut terminal);
    assert!(outcome.is_err());
    assert_eq!(
        terminal.calls,
        vec![Call::Verify, Call::Verify],
        "the second check runs before any read"
    );
    assert!(
        transcript.ends_with(b"? [y/N] "),
        "the question was written"
    );
}

#[test]
fn a_failed_input_flush_never_reads() {
    let mut terminal = Fake::answering(Answer::Approve);
    terminal.discard = Err("tcflush failed");
    let (outcome, _) = run_with(&empty_state(), &mut terminal);
    assert!(outcome.is_err());
    assert_eq!(
        terminal.calls,
        vec![Call::Verify, Call::Verify, Call::Discard]
    );
}

#[test]
fn a_read_error_is_not_an_approval() {
    let mut terminal = Fake::answering(Answer::Approve);
    terminal.read = Err("input/output error");
    let (outcome, _) = run_with(&empty_state(), &mut terminal);
    assert!(outcome.is_err());
}

#[test]
fn a_source_approved_while_we_waited_is_not_asked_about_again() {
    let candidate = candidate();
    let state = approved_state(&candidate);
    let mut terminal = Fake::answering(Answer::Approve);
    let (outcome, transcript) = run_with(&state, &mut terminal);
    assert_eq!(outcome.unwrap(), Outcome::NothingToReview);
    assert!(transcript.is_empty(), "nothing to show and nothing to ask");
    assert!(terminal.calls.is_empty());
}

#[test]
fn nothing_pending_writes_and_asks_nothing() {
    let mut terminal = Fake::answering(Answer::Approve);
    let mut sink = Vec::new();
    let outcome = run(&[], &empty_state(), &mut terminal, &mut sink).unwrap();
    assert_eq!(outcome, Outcome::NothingToReview);
    assert!(sink.is_empty());
    assert!(terminal.calls.is_empty());
}

#[test]
fn a_transcript_write_error_never_reads_stdin() {
    let mut terminal = Fake::answering(Answer::Approve);
    let candidate = candidate();
    let pin_key = key();
    let pending = [PendingSource::for_tests(pin_key, candidate)];
    let mut sink = FailingSink;
    let outcome = run(&pending, &empty_state(), &mut terminal, &mut sink);
    assert!(outcome.is_err());
    assert!(terminal.calls.is_empty(), "stdin is untouched");
}

#[test]
fn the_question_counts_the_sources_it_asks_about() {
    let state = empty_state();
    let first = b"a\n".to_vec();
    let second = b"b\n".to_vec();
    let pin_key = key();
    let pending = [
        PendingSource::for_tests(pin_key.clone(), first),
        PendingSource::for_tests(pin_key, second),
    ];
    let mut terminal = Fake::answering(Answer::Decline);
    let mut sink = Vec::new();
    run(&pending, &state, &mut terminal, &mut sink).unwrap();
    let transcript = String::from_utf8(sink).unwrap();
    assert!(
        transcript.ends_with("Approve 2 pinned source changes for this project? [y/N] "),
        "{transcript}"
    );
}

// ---- the real terminal ----

/// The real checks, exercised without assuming the test harness has a terminal:
/// a `Some` must verify, and a `None` is a terminal this process may not ask
/// on. The foreground/background matrix needs real PTY pairs and belongs to the
/// phase-7 rows.
#[test]
fn the_real_terminal_only_offers_itself_when_it_verifies() {
    if let Some(mut terminal) = StdTerminal::detect() {
        terminal
            .verify_foreground()
            .expect("detect and the foreground check agree");
    }
}
