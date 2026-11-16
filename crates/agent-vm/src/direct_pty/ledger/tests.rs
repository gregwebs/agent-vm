//! The `admit` table exhaustively, and the ledger's transitions (§10.1 ledger).

use super::*;

fn all_owed() -> Vec<Option<u64>> {
    vec![None, Some(0), Some(1), Some(7)]
}

#[test]
fn the_admission_table_is_exhaustive_and_matches_the_contract() {
    for owed in all_owed() {
        for writer in [
            WriterState::Running,
            WriterState::Aborted,
            WriterState::Abandoned,
        ] {
            for frame in [
                Frame::Data,
                Frame::Enter(0),
                Frame::Enter(1),
                Frame::Redraw(0),
                Frame::Redraw(1),
                Frame::Leave(0),
                Frame::Leave(1),
            ] {
                let expected = if writer != WriterState::Running {
                    Admit::Discard
                } else {
                    match frame {
                        Frame::Data => Admit::Write,
                        Frame::Enter(_) => {
                            if owed.is_none() {
                                Admit::Write
                            } else {
                                Admit::Discard
                            }
                        }
                        Frame::Redraw(g) | Frame::Leave(g) => {
                            if owed == Some(g) {
                                Admit::Write
                            } else {
                                Admit::Discard
                            }
                        }
                    }
                };
                assert_eq!(
                    admit(owed, writer, frame),
                    expected,
                    "owed {owed:?} writer {writer:?} frame {frame:?}"
                );
            }
        }
    }
}

#[test]
fn an_enter_claims_ownership_and_a_complete_leave_releases_it() {
    let ledger = TerminalLedger::new();
    assert_eq!(ledger.owed(), None);
    assert_eq!(
        ledger.admit(
            1,
            Step::Enter {
                screen: crate::access_prompt::vt::Screen::Main
            }
        ),
        Admit::Write
    );
    assert_eq!(ledger.owed(), Some(1));
    // Redraws of another generation are refused; its own are written.
    assert_eq!(ledger.admit(0, Step::Redraw), Admit::Discard);
    assert_eq!(ledger.admit(1, Step::Redraw), Admit::Write);
    // A second enter cannot claim the terminal.
    assert_eq!(
        ledger.admit(
            2,
            Step::Enter {
                screen: crate::access_prompt::vt::Screen::Main
            }
        ),
        Admit::Discard
    );
    // A leave of the owning generation is admitted; its completion releases `owed`.
    assert_eq!(ledger.admit(1, Step::Leave), Admit::Write);
    assert_eq!(
        ledger.owed(),
        Some(1),
        "still owed until every byte is written"
    );
    ledger.wrote_completely(1, Step::Leave);
    assert_eq!(ledger.owed(), None);
    // A second leave is refused: a redraw or leave queued behind one never lands.
    assert_eq!(ledger.admit(1, Step::Leave), Admit::Discard);
    // And the next takeover may claim it.
    assert_eq!(
        ledger.admit(
            2,
            Step::Enter {
                screen: crate::access_prompt::vt::Screen::Main
            }
        ),
        Admit::Write
    );
}

#[test]
fn a_leave_completed_after_the_abort_does_not_cancel_the_host_restore() {
    // Finding 4: the epilogue saw `owed`, then a Leave's write that was already in
    // flight completed and cleared it, and the writer skipped the host restore.
    for screen in [
        crate::access_prompt::vt::Screen::Main,
        crate::access_prompt::vt::Screen::Alternate,
    ] {
        let ledger = TerminalLedger::new();
        assert_eq!(ledger.admit(1, Step::Enter { screen }), Admit::Write);
        let wait = ledger.abort().expect("a prompt may be on screen");
        // The in-flight Leave completes now.
        ledger.wrote_completely(1, Step::Leave);
        assert_eq!(
            ledger.owed(),
            Some(1),
            "the restore must still be owed after an in-flight leave completes"
        );
        let runtime = tokio::runtime::Runtime::new().expect("a runtime");
        assert!(
            !runtime.block_on(wait.wait()),
            "no host restore was written, so the wait reports incompleteness"
        );
        // And the writer's own decision point still sees the debt.
        assert_eq!(ledger.owed(), Some(1));
    }
}

#[test]
fn abort_says_whether_a_restore_is_owed_and_nothing_is_admitted_after() {
    let ledger = TerminalLedger::new();
    assert!(ledger.abort().is_none(), "nothing owns the terminal");
    assert_eq!(ledger.admit_data(), Admit::Discard);
    assert_eq!(
        ledger.admit(
            1,
            Step::Enter {
                screen: crate::access_prompt::vt::Screen::Main
            }
        ),
        Admit::Discard
    );

    let ledger = TerminalLedger::new();
    assert_eq!(
        ledger.admit(
            1,
            Step::Enter {
                screen: crate::access_prompt::vt::Screen::Main
            }
        ),
        Admit::Write
    );
    let wait = ledger.abort().expect("a restore is owed");
    // A frame already queued behind the abort is refused, so no late prompt byte.
    assert_eq!(ledger.admit(1, Step::Redraw), Admit::Discard);
    // The writer completes the restore.
    ledger.restored();
    assert!(ledger.may_write());
    drop(wait);
}

#[test]
fn a_check_that_passed_before_the_abandoned_state_starts_at_most_one_more_write() {
    // B2's counterexample, on the real handshake: the writer passes its
    // `Abandoned` check, is paused **before** the syscall, the epilogue's wait
    // expires, and only then does the writer resume. G3 allows that one committed
    // `write(2)` and nothing after it.
    let (ledger, reached, release) = TerminalLedger::armed_for_pause();
    assert_eq!(
        ledger.admit(
            1,
            Step::Enter {
                screen: crate::access_prompt::vt::Screen::Main
            }
        ),
        Admit::Write,
        "a prompt may be on screen, so a restore is owed"
    );
    let (mut read_end, write_end) = std::io::pipe().expect("a pipe");
    let writer_ledger = Arc::clone(&ledger);
    let thread = std::thread::spawn(move || {
        use std::io::Write as _;
        use std::os::fd::AsRawFd as _;
        let mut sink = write_end;
        let fd = sink.as_raw_fd();
        let mut writes = 0;
        // The write whose check passed before the abort, paused before its syscall.
        if writer_ledger.may_write() {
            writer_ledger.pause_before_write();
            writes += 1;
            // SAFETY: `sink` owns an open pipe write end.
            unsafe { libc::write(fd, b"committed".as_ptr().cast(), 9) };
        }
        // Every later write re-checks, and none may start.
        for _ in 0..3 {
            if !writer_ledger.may_write() {
                break;
            }
            writes += 1;
            // SAFETY: as above.
            unsafe { libc::write(fd, b"late".as_ptr().cast(), 4) };
        }
        let _ = sink.flush();
        writes
    });
    reached
        .recv_timeout(Duration::from_secs(5))
        .expect("the writer reached the hook between check and syscall");
    let wait = ledger.abort().expect("the restore is owed");
    let runtime = tokio::runtime::Runtime::new().expect("a runtime");
    let started = std::time::Instant::now();
    assert!(
        !runtime.block_on(wait.wait()),
        "no restore reached the terminal"
    );
    assert!(
        started.elapsed() <= HOST_RESTORE_WAIT + Duration::from_millis(250),
        "the wait must be bounded, took {:?}",
        started.elapsed()
    );
    let _ = release.send(());
    let writes = thread.join().expect("the writer exits");
    assert_eq!(writes, 1, "at most one committed write may land");
    let mut captured = Vec::new();
    use std::io::Read as _;
    read_end.read_to_end(&mut captured).expect("read the pipe");
    assert_eq!(captured, b"committed");
}

#[tokio::test]
async fn the_wait_is_bounded_and_gives_the_writer_one_more_syscall() {
    let ledger = TerminalLedger::new();
    assert_eq!(
        ledger.admit(
            1,
            Step::Enter {
                screen: crate::access_prompt::vt::Screen::Main
            }
        ),
        Admit::Write
    );
    let wait = ledger.abort().expect("owed");
    let started = std::time::Instant::now();
    assert!(!wait.wait().await, "no writer restored it");
    assert!(
        started.elapsed() <= HOST_RESTORE_WAIT + Duration::from_millis(300),
        "the wait must be bounded, took {:?}",
        started.elapsed()
    );
    assert!(!ledger.may_write(), "after the wait no new write starts");
    assert_eq!(HOST_RESTORE_WAIT, Duration::from_millis(250));
}
