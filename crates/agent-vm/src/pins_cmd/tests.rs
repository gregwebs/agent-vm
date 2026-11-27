//! In-crate tests for the pin gate: the eligibility conjunction, the one
//! question, the one commit and the one reload (V28-V32, V41).

use std::cell::Cell;
use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use super::*;
use crate::config_pins::PendingReason;
use crate::config_pins::diff::MAX_LINE_CHARS;
use crate::config_pins::prompt::Answer;
use crate::config_pins::store::{Receipt, ReceiptKind};

/// A real host-managed project store plus a checkout and a `$HOME`, all under
/// one canonical temp base, so the ADR-0073 route checks are real observations.
struct Fixture {
    _root: tempfile::TempDir,
    home: PathBuf,
    project: crate::project::ProjectDir,
    config: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let base = root.path().canonicalize().unwrap();
        let home = base.join("home");
        let checkout = base.join("checkout");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&checkout).unwrap();
        let project = crate::project::ProjectDir::from_path_for_tests(&checkout).unwrap();
        let config = crate::project_config::path(&home, &project);
        Self {
            _root: root,
            home,
            project,
            config,
        }
    }

    fn paths(&self) -> ConfigPaths {
        ConfigPaths::for_test_captured(self.home.clone(), &self.project)
    }

    fn store_dir(&self) -> PathBuf {
        self.config.parent().unwrap().to_path_buf()
    }

    fn write_project(&self, body: &str) -> &Self {
        let store = self.store_dir();
        fs::create_dir_all(&store).unwrap();
        fs::set_permissions(&store, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        fs::write(&self.config, body).unwrap();
        self
    }

    fn write_repo(&self, relative: &str, body: &str) -> PathBuf {
        let path = self.project.path().join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, body).unwrap();
        path
    }

    /// The store's directory listing, sorted, to prove nothing was created.
    fn store_entries(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(self.store_dir())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    fn pin_store(&self) -> PinStore {
        PinStore::at_for_tests(&self.home, &self.project)
    }

    /// The load, so a test starts from the typed refusal a launch sees.
    fn refusal(&self) -> UnapprovedSources {
        self.paths_load_error()
            .downcast::<UnapprovedSources>()
            .unwrap()
    }

    fn paths_load_error(&self) -> anyhow::Error {
        config::load(&self.paths()).expect_err("the fixture's sources are pending")
    }
}

/// The two source bodies the tests approve: valid config text, so an approved
/// source still loads.
const SOURCE: &str = "# pinned\n";
const OTHER_SOURCE: &str = "# pinned changed\n";

/// A path as the TOML string literal a `[[sources]] path =` needs, without a
/// `display()` site (this crate renders paths for people through `one_line`).
fn toml_path(path: &Path) -> String {
    format!("{path:?}")
}

/// One project body declaring a tool plus one pinned source.
fn project_with_source(source: &Path) -> String {
    format!(
        "\
         [[tools]]\nname = \"t\"\ncommand = \"true\"\n\
         [[sources]]\nname = \"repo\"\npath = {}\n",
        toml_path(source)
    )
}

/// A terminal that answers from a fixed list and counts what it was asked.
struct FakeTerminal {
    answers: VecDeque<Answer>,
    reads: Rc<Cell<usize>>,
    flushes: Rc<Cell<usize>>,
    foreground: bool,
}

impl FakeTerminal {
    fn answering(answers: &[Answer]) -> Self {
        Self {
            answers: answers.iter().copied().collect(),
            reads: Rc::new(Cell::new(0)),
            flushes: Rc::new(Cell::new(0)),
            foreground: true,
        }
    }

    fn reads(&self) -> usize {
        self.reads.get()
    }

    fn flushes(&self) -> usize {
        self.flushes.get()
    }
}

impl ApprovalTerminal for FakeTerminal {
    fn verify_foreground(&mut self) -> std::io::Result<()> {
        if self.foreground {
            Ok(())
        } else {
            Err(std::io::Error::other("not the foreground process group"))
        }
    }

    fn discard_pending_input(&mut self) -> std::io::Result<()> {
        self.flushes.set(self.flushes.get() + 1);
        Ok(())
    }

    fn read_answer(&mut self) -> std::io::Result<Answer> {
        self.reads.set(self.reads.get() + 1);
        Ok(self.answers.pop_front().unwrap_or(Answer::NoAnswer))
    }
}

fn interact(
    fixture: &Fixture,
    refusal: UnapprovedSources,
    route: Option<LaunchRoute>,
    terminal: Option<&mut FakeTerminal>,
    now_ms: i64,
) -> (Result<ConfigReport>, String) {
    let mut transcript = Vec::new();
    let result = gate_with(
        Err(anyhow::Error::new(refusal)),
        route,
        Some(&fixture.paths()),
        terminal.map(|terminal| terminal as &mut dyn ApprovalTerminal),
        &mut transcript,
        now_ms,
    );
    (result, String::from_utf8(transcript).unwrap())
}

/// The exact phase-4 refusal text, which every ineligible route must reproduce.
fn refusal_text(refusal: &UnapprovedSources) -> String {
    format!("{refusal}")
}

#[test]
fn a_pending_launch_in_an_eligible_terminal_prompts_once_and_continues() {
    let fixture = Fixture::new();
    let source = fixture.write_repo("conf/agent-vm.toml", SOURCE);
    fixture.write_project(&project_with_source(&source));
    let refusal = fixture.refusal();
    let candidate = refusal.pending()[0].hash;
    let before = fixture.store_entries();

    let mut terminal = FakeTerminal::answering(&[Answer::Approve]);
    let (result, transcript) = interact(
        &fixture,
        refusal,
        Some(LaunchRoute::Verb),
        Some(&mut terminal),
        1_000,
    );

    let report = result.expect("the reloaded configuration continues the launch");
    assert_eq!(terminal.reads(), 1, "one question, asked once");
    assert_eq!(
        terminal.flushes(),
        1,
        "input is flushed once, before the read"
    );
    assert!(
        transcript.contains("==> source "),
        "the review names the source: {transcript}"
    );
    assert!(
        transcript.contains("+# pinned"),
        "the review shows the candidates's bytes: {transcript}"
    );
    assert!(
        transcript.contains("Approve 1 pinned source change for this project? [y/N] "),
        "{transcript}"
    );
    assert!(
        transcript.contains("==> approved repo "),
        "the receipt is printed after the commit: {transcript}"
    );
    assert!(
        transcript.contains(&format!("{candidate}")),
        "the receipt names the approved digest: {transcript}"
    );

    let entry = &report.sources().entries()[0];
    let pin = entry.pin().expect("the reloaded source is approved");
    assert_eq!(pin.hash(), candidate);
    assert!(pin.active(), "the approval is the active baseline");
    // The store was created by the commit, which is the only write.
    let after = fixture.store_entries();
    assert!(
        after.iter().any(|name| name == "pins.json"),
        "the commit recorded the approval: {after:?}"
    );
    assert!(
        after.iter().any(|name| name == "pins.lock"),
        "the commit created the lock: {after:?}"
    );
    assert_eq!(
        before.len() + 3,
        after.len(),
        "only the lock, the manifest and one snapshot were added: {before:?} -> {after:?}"
    );
    assert_eq!(
        after
            .iter()
            .filter(|name| crate::config_pins::is_snapshot_name(std::ffi::OsStr::new(name)))
            .count(),
        1,
        "exactly one snapshot was written: {after:?}"
    );
}

#[test]
fn declining_refuses_without_committing() {
    let fixture = Fixture::new();
    let source = fixture.write_repo("conf/agent-vm.toml", SOURCE);
    fixture.write_project(&project_with_source(&source));
    let refusal = fixture.refusal();
    let before = fixture.store_entries();

    let mut terminal = FakeTerminal::answering(&[Answer::Decline]);
    let (result, transcript) = interact(
        &fixture,
        refusal,
        Some(LaunchRoute::Verb),
        Some(&mut terminal),
        1_000,
    );

    let error = format!("{:#}", result.expect_err("a decline refuses the launch"));
    assert!(
        error.contains("the pinned source change was not approved; nothing was recorded"),
        "{error}"
    );
    assert_eq!(terminal.reads(), 1);
    assert!(!transcript.contains("==> approved"), "{transcript}");
    assert_eq!(
        fixture.store_entries(),
        before,
        "a decline writes no pin state"
    );
}

#[test]
fn no_answer_refuses() {
    let fixture = Fixture::new();
    let source = fixture.write_repo("conf/agent-vm.toml", SOURCE);
    fixture.write_project(&project_with_source(&source));
    let refusal = fixture.refusal();
    let before = fixture.store_entries();

    let mut terminal = FakeTerminal::answering(&[]);
    let (result, _) = interact(
        &fixture,
        refusal,
        Some(LaunchRoute::Verb),
        Some(&mut terminal),
        1_000,
    );

    let error = format!("{:#}", result.expect_err("an absent answer refuses"));
    assert!(
        error.contains("no answer was read (end of input); nothing was approved"),
        "{error}"
    );
    assert_eq!(terminal.reads(), 1);
    assert_eq!(fixture.store_entries(), before);
}

#[test]
fn a_truncated_review_refuses_with_the_cap_named_and_asks_nothing() {
    let fixture = Fixture::new();
    let long = format!("key = \"{}\"\n", "x".repeat(MAX_LINE_CHARS + 1));
    let source = fixture.write_repo("conf/agent-vm.toml", &long);
    fixture.write_project(&project_with_source(&source));
    let refusal = fixture.refusal();
    let before = fixture.store_entries();

    let mut terminal = FakeTerminal::answering(&[Answer::Approve]);
    let (result, transcript) = interact(
        &fixture,
        refusal,
        Some(LaunchRoute::Verb),
        Some(&mut terminal),
        1_000,
    );

    let error = format!("{:#}", result.expect_err("an oversized review refuses"));
    assert_eq!(
        terminal.reads(),
        0,
        "a truncated review must never ask the question"
    );
    assert_eq!(terminal.flushes(), 0, "and never touches the input queue");
    assert!(!transcript.contains("[y/N]"), "{transcript}");
    assert!(
        transcript.contains("too large to approve interactively"),
        "{transcript}"
    );
    assert!(
        error.contains(&format!(
            "a diff line is longer than {MAX_LINE_CHARS} characters"
        )),
        "the cap is named: {error}"
    );
    // The refusal names the source and the exact candidate, so a reviewer can
    // tell which pending version was too large to show.
    let candidate = crate::config_pins::ContentHash::of(long.as_bytes());
    assert!(
        transcript.contains(&format!(
            "for \"{}\"",
            crate::config_pins::diff::escape_review_line(source.to_str().unwrap().as_bytes())
        )),
        "the source key is named: {transcript}"
    );
    assert!(
        transcript.contains(&format!("current {candidate}")),
        "the exact candidate digest is named: {transcript}"
    );
    // Advice that is true today: reduce the input and run an eligible launch
    // again. The batch commands are named as future, not as available now.
    assert!(
        transcript.contains("Reduce the source so its whole review fits"),
        "{transcript}"
    );
    assert!(
        transcript.contains("then run an eligible launch\nagain (a tool verb, `run` or `--`)"),
        "the available remedy is a launch, not a command this release lacks: {transcript}"
    );
    assert!(
        transcript.contains("`agent-vm config diff`")
            && transcript.contains("`agent-vm config approve`"),
        "both future command names are kept: {transcript}"
    );
    assert!(
        transcript.contains("in a later release")
            && transcript.contains("not available in this one"),
        "and are marked as not available in this release: {transcript}"
    );
    assert!(
        !transcript.contains("--expect")
            && !transcript.contains("give it the source's actual path"),
        "the escaped display is not offered as a flag value: {transcript}"
    );
    assert_eq!(
        fixture.store_entries(),
        before,
        "a truncated review writes nothing"
    );
}

/// Every route that is not a launch: no prompt, no lock, no pin state, and the
/// phase-4 refusal byte for byte.
#[test]
fn an_ineligible_route_or_terminal_never_prompts() {
    let fixture = Fixture::new();
    let source = fixture.write_repo("conf/agent-vm.toml", SOURCE);
    fixture.write_project(&project_with_source(&source));
    let before = fixture.store_entries();

    // (route, terminal) combinations the gate must refuse without asking.
    let mut cases: Vec<(Option<LaunchRoute>, bool)> = vec![
        // Not a launch: help, version, built-in, `config …`, a usage error.
        (None, true),
        // A launch, but no eligible (foreground, TTY) terminal.
        (Some(LaunchRoute::Verb), false),
        (Some(LaunchRoute::Direct), false),
    ];
    // `None` for the terminal is `StdTerminal::detect()` having returned none.
    for (route, with_terminal) in cases.drain(..) {
        let refusal = fixture.refusal();
        let expected = refusal_text(&refusal);
        let mut terminal = FakeTerminal::answering(&[Answer::Approve]);
        let (result, transcript) = interact(
            &fixture,
            refusal,
            route,
            with_terminal.then_some(&mut terminal),
            1_000,
        );
        let error = result.expect_err("an ineligible route refuses");
        assert_eq!(
            format!("{error}"),
            expected,
            "the refusal must stay byte-identical"
        );
        assert_eq!(terminal.reads(), 0, "no question is asked for {route:?}");
        assert_eq!(terminal.flushes(), 0);
        assert_eq!(transcript, "", "nothing is printed for {route:?}");
        assert_eq!(
            fixture.store_entries(),
            before,
            "no lock or pin state for {route:?}"
        );
    }
}

#[test]
fn a_broken_configuration_is_never_reviewed() {
    let fixture = Fixture::new();
    fixture.write_project("[[tools]]\nname = \"t\"\ncommand = \"true\"\n");
    let before = fixture.store_entries();
    let mut terminal = FakeTerminal::answering(&[Answer::Approve]);
    let mut transcript = Vec::new();
    let result = gate_with(
        Err(anyhow::anyhow!("config: sentinel")),
        Some(LaunchRoute::Verb),
        Some(&fixture.paths()),
        Some(&mut terminal),
        &mut transcript,
        1_000,
    );
    assert_eq!(
        format!(
            "{}",
            result.expect_err("a broken config is not a pin refusal")
        ),
        "config: sentinel"
    );
    assert_eq!(terminal.reads(), 0);
    assert!(transcript.is_empty());
    assert_eq!(fixture.store_entries(), before);
}

#[test]
fn a_source_that_changed_again_is_refused_by_the_one_reload() {
    let fixture = Fixture::new();
    let source = fixture.write_repo("conf/agent-vm.toml", SOURCE);
    fixture.write_project(&project_with_source(&source));
    let refusal = fixture.refusal();
    let reviewed = refusal.pending()[0].hash;

    // The source changes again between the load and the review: the reviewed
    // bytes are still what the user is asked about, and what is committed.
    let changed = OTHER_SOURCE;
    fs::write(&source, changed).unwrap();
    let rewritten = crate::config_pins::ContentHash::of(changed.as_bytes());

    let mut terminal = FakeTerminal::answering(&[Answer::Approve]);
    let (result, transcript) = interact(
        &fixture,
        refusal,
        Some(LaunchRoute::Verb),
        Some(&mut terminal),
        1_000,
    );

    let error = format!(
        "{:#}",
        result.expect_err("the reload refuses the new bytes")
    );
    assert_eq!(
        terminal.reads(),
        1,
        "the changed source is never prompted a second time"
    );
    assert!(
        transcript.contains(&reviewed.to_string()),
        "the review is about the bytes that were read: {transcript}"
    );
    assert!(
        error.contains(&rewritten.to_string()),
        "the refusal names the bytes now on disk: {error}"
    );
    assert!(
        error.contains("review the change with `agent-vm config diff`"),
        "and is the phase-4 text: {error}"
    );
}

#[test]
fn a_committed_with_warning_receipt_is_printed_and_the_launch_continues() {
    let fixture = Fixture::new();
    let source = fixture.write_repo("conf/agent-vm.toml", SOURCE);
    fixture.write_project(&project_with_source(&source));
    let refusal = fixture.refusal();

    // The real transaction, with the post-publish lock-header finalization
    // failing: the approvals are on disk, so this is a warning, never a failure.
    let mut store = fixture.pin_store();
    store.faults.fail_finalize = true;
    let mut terminal = FakeTerminal::answering(&[Answer::Approve]);
    let mut transcript = Vec::new();
    let decided =
        approve_interactively_with(&store, &refusal, &mut terminal, &mut transcript, 1_000)
            .expect("a post-commit warning is not an error");
    assert_eq!(decided, Interactive::Approved);
    let transcript = String::from_utf8(transcript).unwrap();
    assert!(transcript.contains("==> approved repo "), "{transcript}");
    assert!(
        transcript.contains("==> warning: the approvals were recorded,"),
        "the warning says what was recorded: {transcript}"
    );
    assert!(
        !transcript.contains("nothing was approved"),
        "a warning must not imply nothing was approved: {transcript}"
    );

    // The launch continues on bytes that are already approved.
    let report = config::load(&fixture.paths()).expect("the committed bytes load");
    assert!(report.sources().entries()[0].pin().unwrap().active());
}

#[test]
fn an_inactive_approval_is_activated_by_the_same_commit() {
    let fixture = Fixture::new();
    let source = fixture.write_repo("conf/agent-vm.toml", SOURCE);
    let other = fixture.write_repo("conf/other.toml", OTHER_SOURCE);
    // `a` is approved, then `b` is a second pending source: `a`'s approved bytes
    // are no longer its active digest when the review happens.
    let body = format!(
        "\
         [[tools]]\nname = \"t\"\ncommand = \"true\"\n\
         [[sources]]\nname = \"repo\"\npath = {}\n\
         [[sources]]\nname = \"other\"\npath = {}\n",
        toml_path(&source),
        toml_path(&other)
    );
    fixture.write_project(&body);

    // Approve `a` alone first, through the real gate (the only approval path).
    let first = fixture.refusal();
    assert_eq!(first.pending().len(), 2);
    let mut terminal = FakeTerminal::answering(&[Answer::Approve]);
    let (result, _) = interact(
        &fixture,
        first,
        Some(LaunchRoute::Verb),
        Some(&mut terminal),
        1_000,
    );
    result.expect("the first review approves both");

    // Now rewind `a`'s bytes to an *older* digest that is still approved.
    let original = fs::read(&source).unwrap();
    let original_hash = crate::config_pins::ContentHash::of(&original);
    // A second approved digest for `a`, with the original still approved.
    fs::write(&source, OTHER_SOURCE).unwrap();
    approve_for_test(&fixture);
    fs::write(&source, &original).unwrap();

    let report = config::load(&fixture.paths()).expect("the rewind is approved bytes");
    let pinned = report
        .sources()
        .entries()
        .iter()
        .find(|entry| entry.alias().as_str() == "repo")
        .unwrap();
    assert_eq!(pinned.pin().unwrap().hash(), original_hash);
    assert!(
        !pinned.pin().unwrap().active(),
        "the rewind is approved but not active"
    );

    // The next launch records it as active: that is `record_active`'s job, not
    // the gate's.
    let updates = ActiveUpdates::of(&report).expect("one inactive approval");
    record_active(Some(&fixture.paths()), &updates).expect("recording succeeds");
    let report = config::load(&fixture.paths()).expect("reload");
    let pinned = report
        .sources()
        .entries()
        .iter()
        .find(|entry| entry.alias().as_str() == "repo")
        .unwrap();
    assert!(
        pinned.pin().unwrap().active(),
        "record_active marks the used digest active"
    );
}

/// Approve whatever is pending through the real store, the way the interactive
/// gate does, from the non-interactive side.
fn approve_for_test(fixture: &Fixture) {
    let refusal = fixture
        .paths_load_error()
        .downcast::<UnapprovedSources>()
        .expect("the rewritten source is pending");
    let mut terminal = FakeTerminal::answering(&[Answer::Approve]);
    let mut transcript = Vec::new();
    approve_interactively_with(
        &fixture.pin_store(),
        &refusal,
        &mut terminal,
        &mut transcript,
        2_000,
    )
    .expect("the fixture's approval commits");
    assert_eq!(terminal.reads(), 1);
}

#[test]
fn record_active_after_a_reset_writes_nothing() {
    let fixture = Fixture::new();
    let source = fixture.write_repo("conf/agent-vm.toml", SOURCE);
    fixture.write_project(&project_with_source(&source));
    let refusal = fixture.refusal();
    let mut terminal = FakeTerminal::answering(&[Answer::Approve]);
    let mut transcript = Vec::new();
    approve_interactively_with(
        &fixture.pin_store(),
        &refusal,
        &mut terminal,
        &mut transcript,
        1_000,
    )
    .expect("approval commits");

    // An older, still-approved digest becomes active: approve a second version
    // and then rewind, so the load reports an inactive approval.
    let store = fixture.pin_store();
    let (_, current) = store.read_state().unwrap();
    let key = crate::config_pins::PinKey::for_source(&source).unwrap();
    let first = current.key_state(&key).unwrap().active;
    let second = OTHER_SOURCE.as_bytes();
    let second_hash = crate::config_pins::ContentHash::of(second);
    store
        .update(
            &store.observe().unwrap(),
            &CommitBatch {
                approve: vec![ApprovalCandidate {
                    key: key.clone(),
                    hash: second_hash,
                    bytes: second.to_vec(),
                    activate: true,
                }],
                activate: Vec::new(),
                retained_keys: vec![key.clone()],
            },
            2_000,
        )
        .unwrap();
    // Rewind the file to the first version, which stays approved.
    fs::write(&source, SOURCE).unwrap();
    let (_, current) = store.read_state().unwrap();
    assert_eq!(current.key_state(&key).unwrap().active, second_hash);
    assert_eq!(
        first,
        crate::config_pins::ContentHash::of(SOURCE.as_bytes())
    );

    let report = config::load(&fixture.paths()).unwrap();
    let updates = ActiveUpdates::of(&report).expect("one inactive approval");

    // A reset between the load and the recording removes the key: activation is
    // not an approval, so this is an explicit no-update outcome.
    store
        .reset(crate::config_pins::store::ResetMode::Normal)
        .unwrap();
    record_active(Some(&fixture.paths()), &updates).expect("a reset is not an error");
    let (_, after) = store.read_state().unwrap();
    assert!(
        after.sources().is_empty(),
        "a reset key is never recreated: {:?}",
        after.sources().keys().collect::<Vec<_>>()
    );
}

/// R12/B4: the recording observes the generation the **load** did. A reset in
/// between means the store this launch read no longer exists, so there is
/// nothing to record into even when the new store approves the same key again.
/// A recorder that re-observed would find that new approval and move its active
/// pointer from a launch that never read it.
#[test]
fn a_reset_between_the_load_and_the_recorder_records_nothing() {
    let fixture = Fixture::new();
    let source = fixture.write_repo("conf/agent-vm.toml", SOURCE);
    fixture.write_project(&project_with_source(&source));
    let store = fixture.pin_store();

    // V1 approved and active, then V2 approved and active: V1 stays approved.
    approve_body(&fixture, &source, SOURCE, true, 1_000);
    approve_body(&fixture, &source, OTHER_SOURCE, true, 2_000);
    // The launch reads V1, which is approved but not active.
    fs::write(&source, SOURCE).unwrap();
    let report = config::load(&fixture.paths()).unwrap();
    let updates = ActiveUpdates::of(&report).expect("one inactive approval");
    let v1 = crate::config_pins::ContentHash::of(SOURCE.as_bytes());
    let v2 = crate::config_pins::ContentHash::of(OTHER_SOURCE.as_bytes());
    assert_eq!(recorded_active(&fixture, &source), v2);

    // A reset between the load and the recorder, then the new store approves
    // both versions again with V2 active: an observation taken now would find
    // V1 approved and inactive, and would happily resurrect it.
    store
        .reset(crate::config_pins::store::ResetMode::Normal)
        .unwrap();
    approve_body(&fixture, &source, SOURCE, false, 3_000);
    approve_body(&fixture, &source, OTHER_SOURCE, true, 4_000);
    assert_eq!(recorded_active(&fixture, &source), v2);
    let manifest = fs::read(fixture.store_dir().join(crate::config_pins::PINS_FILE)).unwrap();

    record_active(Some(&fixture.paths()), &updates).expect("a reset is not a failed launch");
    assert_eq!(
        fs::read(fixture.store_dir().join(crate::config_pins::PINS_FILE)).unwrap(),
        manifest,
        "the reset generation's manifest was not written by a stale recording"
    );
    assert_eq!(
        recorded_active(&fixture, &source),
        v2,
        "the load's inactive digest is not resurrected as active"
    );
    assert_ne!(v1, v2, "the fixture's two versions are distinct");
}

#[test]
fn a_load_with_no_inactive_approval_records_nothing() {
    let fixture = Fixture::new();
    let source = fixture.write_repo("conf/agent-vm.toml", SOURCE);
    fixture.write_project(&project_with_source(&source));
    let refusal = fixture.refusal();
    let mut terminal = FakeTerminal::answering(&[Answer::Approve]);
    let mut transcript = Vec::new();
    approve_interactively_with(
        &fixture.pin_store(),
        &refusal,
        &mut terminal,
        &mut transcript,
        1_000,
    )
    .expect("approval commits");

    let report = config::load(&fixture.paths()).unwrap();
    assert!(
        report.sources().entries()[0].pin().unwrap().active(),
        "the approved digest is active"
    );
    assert!(
        ActiveUpdates::of(&report).is_none(),
        "an all-active load has nothing to record"
    );

    // A load with no pinned sources at all captures nothing either.
    fixture.write_project("[[tools]]\nname = \"t\"\ncommand = \"true\"\n");
    let report = config::load(&fixture.paths()).unwrap();
    assert!(ActiveUpdates::of(&report).is_none());
}

#[test]
fn a_held_lock_is_reported_as_a_failed_recording() {
    let fixture = Fixture::new();
    let source = fixture.write_repo("conf/agent-vm.toml", SOURCE);
    fixture.write_project(&project_with_source(&source));
    let refusal = fixture.refusal();
    let mut terminal = FakeTerminal::answering(&[Answer::Approve]);
    let mut transcript = Vec::new();
    approve_interactively_with(
        &fixture.pin_store(),
        &refusal,
        &mut terminal,
        &mut transcript,
        1_000,
    )
    .expect("approval commits");

    // Make the loaded digest inactive, then hold the writer lock across
    // `record_active`: the recording must refuse rather than wait forever, and
    // the launch must still be able to continue.
    let store = fixture.pin_store();
    let key = crate::config_pins::PinKey::for_source(&source).unwrap();
    let (_, current) = store.read_state().unwrap();
    let loaded = current.key_state(&key).unwrap().active;
    let other = OTHER_SOURCE.as_bytes();
    store
        .update(
            &store.observe().unwrap(),
            &CommitBatch {
                approve: vec![ApprovalCandidate {
                    key: key.clone(),
                    hash: crate::config_pins::ContentHash::of(other),
                    bytes: other.to_vec(),
                    activate: true,
                }],
                activate: Vec::new(),
                retained_keys: vec![key.clone()],
            },
            2_000,
        )
        .unwrap();
    fs::write(&source, SOURCE).unwrap();
    let report = config::load(&fixture.paths()).unwrap();
    assert_eq!(report.sources().entries()[0].pin().unwrap().hash(), loaded);
    let updates = ActiveUpdates::of(&report).expect("one inactive approval");

    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(fixture.store_dir().join(crate::config_pins::LOCK_FILE))
        .unwrap();
    use std::os::unix::io::AsRawFd as _;
    // SAFETY: `LOCK_EX` on a descriptor this test owns.
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
    let error = record_active(Some(&fixture.paths()), &updates)
        .expect_err("a held lock refuses the recording");
    let warning = record_active_warning(&error, &updates);
    assert!(
        warning.contains("the source pin store is busy"),
        "the warning names the cause: {warning}"
    );
    assert!(
        warning.contains(&crate::config_pins::diff::escape_review_line(
            key.as_str().as_bytes()
        )),
        "the warning names what was not recorded: {warning}"
    );
    assert!(
        warning.contains("the launch continues"),
        "a failed recording is never fatal: {warning}"
    );
    // SAFETY: releasing the lock this test took.
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) }, 0);

    // The approval itself is untouched by the failure.
    let report = config::load(&fixture.paths()).unwrap();
    assert_eq!(report.sources().entries()[0].pin().unwrap().hash(), loaded);
}

#[test]
fn a_commit_that_names_no_entry_is_still_printed() {
    // The receipts are the store's, not the inspection's: a commit whose
    // receipt has no inspected entry (only reachable through a hand-built
    // transaction) still prints truthfully, without inventing an alias.
    let fixture = Fixture::new();
    let source = fixture.write_repo("conf/agent-vm.toml", SOURCE);
    fixture.write_project(&project_with_source(&source));
    let refusal = fixture.refusal();
    let committed = CommitOutcome {
        receipts: vec![Receipt {
            key: crate::config_pins::PinKey::for_source(Path::new("/tmp/not-inspected")).unwrap(),
            hash: crate::config_pins::ContentHash::of(b"x"),
            kind: ReceiptKind::Approved,
        }],
        warnings: vec!["a warning".to_owned()],
        generation: crate::config_pins::LiveGeneration {
            store_id: crate::config_pins::StoreId::parse_hex(&"0".repeat(32)).unwrap(),
            reset_epoch: 1,
        },
    };
    let mut transcript = Vec::new();
    print_commit(&mut transcript, &refusal, &committed).unwrap();
    let transcript = String::from_utf8(transcript).unwrap();
    assert!(
        transcript.contains("==> approved /tmp/not-inspected sha256:"),
        "{transcript}"
    );
    assert!(
        transcript.contains("==> warning: a warning"),
        "{transcript}"
    );
}

// ---- B7/the live baseline: the review reads the store, not its own guess ----
//
// The baseline of a review is the key's `active` digest in the manifest read
// under the diff's shared lock. `PendingReason` is what the *load* observed, and
// another launch can move `active` between that inspection and the locked read,
// so a review that fetches the digests the pending reason named compares against
// a baseline the store no longer records. These rows drive the production join
// (`approve_interactively_with`) with a deterministic peer update in that
// window, which is where the defect lived: the store API alone was always fed
// the right digests by its tests.

/// Three distinct approved-able versions of the fixture's one source.
const V1: &str = "# pinned version one\n";
const V2: &str = "# pinned version two\n";
const V3: &str = "# pinned version three\n";

/// Approve `body` for the fixture's source through the real gate, with the
/// given activation choice, from the non-interactive side.
fn approve_body(fixture: &Fixture, path: &Path, body: &str, activate: bool, now_ms: i64) {
    fs::write(path, body).unwrap();
    let refusal = fixture
        .paths_load_error()
        .downcast::<UnapprovedSources>()
        .expect("the rewritten source is pending");
    let store = fixture.pin_store();
    let batch = CommitBatch {
        approve: refusal
            .pending()
            .iter()
            .map(|source| ApprovalCandidate {
                key: source.key().clone(),
                hash: source.hash,
                bytes: source.candidate().to_vec(),
                activate,
            })
            .collect(),
        activate: Vec::new(),
        retained_keys: refusal.all_declared_keys().iter().cloned().collect(),
    };
    assert_eq!(refusal.pending().len(), 1, "one source in this fixture");
    store
        .update(&store.observe().unwrap(), &batch, now_ms)
        .unwrap();
}

/// The recorded active digest for the fixture's one source, from the manifest.
fn recorded_active(fixture: &Fixture, path: &Path) -> crate::config_pins::ContentHash {
    let store = fixture.pin_store();
    let (_, current) = store.read_state().unwrap();
    let key = crate::config_pins::PinKey::for_source(path).unwrap();
    current.key_state(&key).unwrap().active
}

#[test]
fn a_peer_update_before_the_locked_read_reviews_against_the_new_active_digest() {
    let fixture = Fixture::new();
    let source = fixture.write_repo("conf/agent-vm.toml", V1);
    fixture.write_project(&project_with_source(&source));
    // V1 is active; V2 is approved but never activated.
    approve_body(&fixture, &source, V1, true, 1_000);
    approve_body(&fixture, &source, V2, false, 2_000);
    assert_eq!(
        recorded_active(&fixture, &source),
        crate::config_pins::ContentHash::of(V1.as_bytes()),
        "V2 is approved but V1 is still the recorded baseline"
    );

    // The load inspects V3 against V1, the active digest at that instant.
    fs::write(&source, V3).unwrap();
    let refusal = fixture.refusal();
    assert_eq!(
        refusal.pending()[0].reason(),
        PendingReason::Changed {
            last_active: crate::config_pins::ContentHash::of(V1.as_bytes())
        }
    );

    // A peer launch makes V2 active before the review takes its shared lock.
    {
        let store = fixture.pin_store();
        let key = crate::config_pins::PinKey::for_source(&source).unwrap();
        store
            .update(
                &store.observe().unwrap(),
                &CommitBatch {
                    approve: Vec::new(),
                    activate: vec![(
                        key.clone(),
                        crate::config_pins::ContentHash::of(V2.as_bytes()),
                    )],
                    retained_keys: vec![key],
                },
                3_000,
            )
            .unwrap();
    }

    // The production join reviews V3 against what the store records now: V2.
    let mut terminal = FakeTerminal::answering(&[Answer::Approve]);
    let (result, transcript) = interact(
        &fixture,
        refusal,
        Some(LaunchRoute::Verb),
        Some(&mut terminal),
        4_000,
    );
    let v2 = crate::config_pins::ContentHash::of(V2.as_bytes());
    assert!(
        transcript.contains(&format!("--- {}\t(last approved {v2})", diff_path(&source))),
        "the baseline is the digest the locked manifest records: {transcript}"
    );
    assert!(
        transcript.contains("-# pinned version two\n"),
        "the peer's baseline is what the review removes: {transcript}"
    );
    assert!(
        !transcript.contains("is unavailable"),
        "V2's snapshot exists, so nothing is unavailable: {transcript}"
    );
    assert!(
        !transcript.contains("-# pinned version one\n"),
        "V1 is no longer the baseline: {transcript}"
    );
    result.expect("the reviewed approval commits and the reload succeeds");
    assert_eq!(
        recorded_active(&fixture, &source),
        crate::config_pins::ContentHash::of(V3.as_bytes()),
        "the approved candidate is the new baseline"
    );
}

/// The control: when the recorded baseline's snapshot is genuinely gone, the
/// review must still say so instead of calling the source never approved.
#[test]
fn a_missing_baseline_snapshot_is_labelled_unavailable_not_never_approved() {
    let fixture = Fixture::new();
    let source = fixture.write_repo("conf/agent-vm.toml", V1);
    fixture.write_project(&project_with_source(&source));
    approve_body(&fixture, &source, V1, true, 1_000);
    fs::write(&source, V2).unwrap();
    let refusal = fixture.refusal();

    // Remove the only snapshot file: the manifest still records V1 as active.
    let store_dir = fixture.store_dir();
    let entries = fs::read_dir(&store_dir).unwrap();
    let mut removed = 0;
    for entry in entries {
        let entry = entry.unwrap();
        if crate::config_pins::is_snapshot_name(&entry.file_name()) {
            fs::remove_file(entry.path()).unwrap();
            removed += 1;
        }
    }
    assert_eq!(removed, 1, "the fixture had exactly one snapshot");

    let mut terminal = FakeTerminal::answering(&[Answer::Decline]);
    let (_, transcript) = interact(
        &fixture,
        refusal,
        Some(LaunchRoute::Verb),
        Some(&mut terminal),
        2_000,
    );
    let v1 = crate::config_pins::ContentHash::of(V1.as_bytes());
    assert!(
        transcript.contains(&format!("last approved {v1} is unavailable (missing)")),
        "an absent snapshot is reported as unavailable: {transcript}"
    );
    assert!(
        !transcript.contains("never approved"),
        "and never as a first use: {transcript}"
    );
}

/// The review transcript's spelling of a fixture path.
fn diff_path(path: &Path) -> String {
    crate::config_pins::diff::escape_review_line(path.to_str().unwrap().as_bytes())
}

// ---- B3: only a verb the approval can make dispatchable may prompt ----
//
// A broken catalog registers no tool subcommands and absorbs every
// syntactically valid external verb, so the preflight cannot answer "will this
// dispatch after the reload" from the parse. It is asked what the pending
// sources could still contribute: an `allow = true` one may adopt `[[tools]]`,
// an `allow = false` one may only re-supply a name the project already claims.

fn argv_of(tokens: &[&str]) -> Vec<std::ffi::OsString> {
    tokens.iter().map(std::ffi::OsString::from).collect()
}

/// #749: a pending `allow = false` source may declare *any* bare tool, so a
/// bare verb is always a legitimate review — including one the parsed tiers do
/// not spell yet. The approval commits and the reloaded catalog dispatches it.
#[test]
fn a_pending_inert_source_may_supply_a_bare_verb() {
    let _env = crate::test_env::guard();
    let fixture = Fixture::new();
    let source = fixture.write_repo(
        "conf/agent-vm.toml",
        "[[tools]]\nname = \"lint\"\ncommand = \"true\"\n",
    );
    fixture.write_project(&project_with_source(&source));
    let refusal = fixture.refusal();
    assert!(
        refusal.pending().iter().all(|source| !source.allow),
        "the fixture's only pending source is allow = false"
    );

    let argv = argv_of(&["agent-vm", "lint"]);
    let route = crate::cli::preflight_unapproved_route(&argv, refusal.verb_candidates());
    assert_eq!(route, Some(LaunchRoute::Verb), "the source may supply it");

    let mut terminal = FakeTerminal::answering(&[Answer::Approve]);
    let (result, _) = interact(&fixture, refusal, route, Some(&mut terminal), 1_000);
    assert_eq!(terminal.reads(), 1, "one question");
    let report = result.expect("the single reload succeeded");
    let catalog = report
        .into_launch_catalog()
        .expect("the approved catalog builds");
    assert!(
        catalog
            .as_slice()
            .iter()
            .any(|entry| entry.label() == "lint"),
        "the approved verb is in the catalog that dispatches"
    );
}

/// A qualified verb names one source: it may prompt only while that alias is
/// pending, and never when the pending set is unknown.
#[test]
fn a_qualified_verb_for_an_approved_source_cannot_prompt() {
    let _env = crate::test_env::guard();
    let fixture = Fixture::new();
    let repo = fixture.write_repo(
        "conf/repo.toml",
        "[[tools]]\nname = \"lint\"\ncommand = \"true\"\n",
    );
    // `home` is the default user config: it is read (and so approved) whether or
    // not the project names it, and its tools carry the `home:` spelling.
    let user = fixture.home.join(".config/agent-vm/config.toml");
    fs::create_dir_all(user.parent().unwrap()).unwrap();
    fs::write(&user, "[[tools]]\nname = \"other\"\ncommand = \"true\"\n").unwrap();
    fixture.write_project(&format!(
        "\
         [[tools]]\nname = \"t\"\ncommand = \"true\"\n\
         [[sources]]\nname = \"repo\"\npath = {}\n",
        toml_path(&repo),
    ));
    let refusal = fixture.refusal();
    assert_eq!(refusal.pending().len(), 1, "only repo is pending");

    let argv = argv_of(&["agent-vm", "home:other"]);
    assert_eq!(
        crate::cli::preflight_unapproved_route(&argv, refusal.verb_candidates()),
        None,
        "an approved alias is already in the catalog"
    );
    let argv = argv_of(&["agent-vm", "repo:lint"]);
    assert_eq!(
        crate::cli::preflight_unapproved_route(&argv, refusal.verb_candidates()),
        Some(LaunchRoute::Verb),
        "the pending alias may supply it"
    );
}

/// When the config failure is not a pending review, no source alias can be
/// confirmed, so only a bare verb may prompt.
#[test]
fn an_unknown_pending_set_never_prompts_for_a_qualified_verb() {
    let _env = crate::test_env::guard();
    let argv = argv_of(&["agent-vm", "foo:bar"]);
    assert_eq!(
        crate::cli::preflight_unapproved_route(&argv, crate::cli::VerbCandidates::AnyPendingSource),
        None
    );
    let argv = argv_of(&["agent-vm", "bar"]);
    assert_eq!(
        crate::cli::preflight_unapproved_route(&argv, crate::cli::VerbCandidates::AnyPendingSource),
        Some(LaunchRoute::Verb)
    );
}

/// The control: a pending `allow = true` source may supply the verb, so the
/// review is legitimate — one question, one commit, and the reloaded catalog
/// contains the verb that will dispatch.
#[test]
fn a_pending_allowed_source_that_supplies_the_verb_still_prompts() {
    let _env = crate::test_env::guard();
    let fixture = Fixture::new();
    let source = fixture.write_repo(
        "conf/agent-vm.toml",
        "[[tools]]\nname = \"lint\"\ncommand = \"true\"\n",
    );
    // The project claims the source's tool, so approving the source is what
    // puts `lint` into the catalog.
    fixture.write_project(&format!(
        "\
         [[sources]]\nname = \"repo\"\npath = {}\nallow = true\n",
        toml_path(&source)
    ));
    let refusal = fixture.refusal();
    assert!(refusal.pending().iter().all(|source| source.allow));

    let argv = argv_of(&["agent-vm", "lint"]);
    let route = crate::cli::preflight_unapproved_route(&argv, refusal.verb_candidates());
    assert_eq!(route, Some(LaunchRoute::Verb), "the source may supply it");

    let mut terminal = FakeTerminal::answering(&[Answer::Approve]);
    let (result, _) = interact(&fixture, refusal, route, Some(&mut terminal), 1_000);
    assert_eq!(terminal.reads(), 1, "one question");
    let report = result.expect("the single reload succeeded");
    let catalog = report
        .into_launch_catalog()
        .expect("the approved catalog builds");
    assert!(
        catalog
            .as_slice()
            .iter()
            .any(|entry| entry.tool().name() == "lint"),
        "the approved verb is in the catalog that dispatches"
    );
}
