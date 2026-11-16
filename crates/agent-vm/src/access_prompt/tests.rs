//! The facade: eligibility, the R3 warning, the candidate rule and the baseline.

use super::*;

fn facts(setting: FlagValue, term: Option<&str>, out: bool, same: bool) -> Facts {
    Facts {
        setting,
        term: term.map(str::to_owned),
        stdout_is_terminal: out,
        same_terminal: same,
    }
}

#[test]
fn the_setting_is_read_once_with_its_warning() {
    // Finding 12: the warning must not depend on the launch being a PTY. The read
    // is one function, used at the launch boundary, and it answers both questions.
    const VAR: &str = "AGENT_VM_NO_ACCESS_PROMPT";
    let mut env = crate::test_env::guard();
    env.set_var(VAR, "maybe");
    let (value, warning) = read_setting();
    assert_eq!(value, FlagValue::Unrecognized("maybe".to_owned()));
    let warning = warning.expect("a typo warns");
    assert!(warning.contains(VAR), "{warning}");
    env.set_var(VAR, "1");
    let (value, warning) = read_setting();
    assert_eq!(value, FlagValue::On);
    assert_eq!(warning, None);
    env.remove_var(VAR);
}

#[test]
fn the_eligibility_table() {
    use Ineligible::*;
    assert_eq!(
        eligible(&facts(FlagValue::Unset, Some("xterm-256color"), true, true)),
        Ok(())
    );
    // Every explicit "no" value leaves the prompt on.
    for value in [FlagValue::Unset, FlagValue::Off] {
        let ok = eligible(&facts(value.clone(), Some("xterm"), true, true));
        assert_eq!(ok, Ok(()), "{value:?}");
    }
    assert_eq!(
        eligible(&facts(FlagValue::On, Some("xterm"), true, true)),
        Err(SettingOff)
    );
    assert_eq!(
        eligible(&facts(FlagValue::Unset, None, true, true)),
        Err(NoTerm)
    );
    assert_eq!(
        eligible(&facts(FlagValue::Unset, Some(""), true, true)),
        Err(NoTerm)
    );
    assert_eq!(
        eligible(&facts(FlagValue::Unset, Some("dumb"), true, true)),
        Err(DumbTerm)
    );
    assert_eq!(
        eligible(&facts(FlagValue::Unset, Some("xterm"), false, false)),
        Err(StdoutNotTerminal)
    );
    assert_eq!(
        eligible(&facts(FlagValue::Unset, Some("xterm"), true, false)),
        Err(DifferentTerminals)
    );
    // A typo leaves the prompt on (which the warning then explains).
    assert_eq!(
        eligible(&facts(
            FlagValue::Unrecognized("maybe".into()),
            Some("xterm"),
            true,
            true
        )),
        Ok(())
    );
}

#[test]
fn the_warning_names_the_variable_and_every_accepted_value() {
    assert_eq!(warning_for(&FlagValue::Unset), None);
    assert_eq!(warning_for(&FlagValue::On), None);
    assert_eq!(warning_for(&FlagValue::Off), None);
    let warning = warning_for(&FlagValue::Unrecognized("maybe".into())).expect("a warning");
    assert!(warning.contains(SETTING), "{warning}");
    assert!(warning.contains("maybe"), "{warning}");
    for value in ["1", "true", "yes", "on", "0", "false", "no", "off"] {
        assert!(warning.contains(value), "{warning} lacks {value}");
    }
    assert!(warning.contains("stays on"), "{warning}");
    // Guest- or user-supplied text is escaped, so a control byte cannot reach the
    // terminal through the setting.
    let warning = warning_for(&FlagValue::Unrecognized("a\u{1b}b".into())).expect("a warning");
    assert!(!warning.contains('\u{1b}'), "{warning}");
    assert!(warning.contains("\\x1b"), "{warning}");
}

#[test]
fn the_timings_are_the_documented_ones() {
    let timings = relay::Timings::default();
    assert_eq!(timings.cut, relay::CUT_DEADLINE);
    assert_eq!(timings.cpr_wait, relay::CPR_WAIT);
    assert_eq!(timings.prompt_timeout, relay::PROMPT_TIMEOUT);
    assert_eq!(timings.result_linger, relay::RESULT_LINGER);
    assert_eq!(timings.release_gap, relay::RELEASE_GAP);
    assert_eq!(timings.typing_quiet.as_millis(), 700);
    assert_eq!(PROMPT_GRANT_WAIT.as_secs(), 40);
    assert_eq!(relay::CUT_DEADLINE.as_millis(), 500);
    assert_eq!(relay::CPR_WAIT.as_secs(), 1);
    assert_eq!(relay::PROMPT_TIMEOUT.as_secs(), 60);
    assert_eq!(relay::RESULT_LINGER.as_millis(), 1500);
    assert_eq!(relay::RELEASE_GAP.as_secs(), 2);
}

#[test]
fn size_converts_without_losing_the_geometry() {
    let size = Size {
        rows: 43,
        cols: 119,
    };
    assert_eq!(size.rows, 43);
    assert_eq!(size.cols, 119);
}

/// A session ID both halves agree on.
fn session() -> SessionId {
    SessionId::parse("3f9a12c4").unwrap()
}

fn feed() -> (Feed, tempfile::TempDir) {
    let root = tempfile::tempdir().unwrap();
    let project = crate::project::ProjectDir::from_path_for_tests(root.path()).unwrap();
    let store = crate::allowances::StoreHandle::at_for_tests(&root.path().join("store"));
    let plan = crate::network::plan_for_tests(&[], false).live_policy_plan(None);
    let allowances = crate::allowances::LiveAllowances::new(&project, store, plan);
    let refusals = crate::refusal::feed::LiveRefusals::new(crate::refusal::SessionRefusals::new(
        crate::refusal::SessionInfo {
            id: session(),
            pid: 1,
            started_ms: 0,
            socket: true,
        },
    ));
    (
        Feed {
            refusals,
            allowances,
            session: session(),
            hint: Arc::new(crate::refusal::feed::Hint::new()),
        },
        root,
    )
}

fn refusal() -> crate::refusal::RefusalEntry {
    let address: std::net::IpAddr = "203.0.113.10".parse().unwrap();
    crate::refusal::RefusalEntry {
        id: "46d712fd".to_owned(),
        key: crate::refusal::EntryKey {
            kind: crate::refusal::Kind::NetworkDenial,
            destination: crate::refusal::Destination::Address {
                protocol: "tcp".to_owned(),
                ip: Some(address),
                port: Some(443),
            },
            credential: None,
        },
        layer: "tenant".to_owned(),
        last_site: "tcp-syn".to_owned(),
        last_ip: Some(address),
        name: None,
        last_location: None,
        last_reason: None,
        last_revision: 1,
        count: 1,
        first_ms: 0,
        last_ms: 0,
    }
}

#[test]
fn a_grantable_unanswered_refusal_becomes_a_candidate() {
    let (feed, _root) = feed();
    let entry = refusal();
    let candidate = candidate_for(&entry, &feed.allowances).expect("a candidate");
    assert_eq!(candidate.entry_id, "46d712fd");
    assert_eq!(
        candidate.destination.to_string(),
        "tcp://[203.0.113.10/32]:443"
    );
    assert_eq!(candidate.offer, crate::allowances::Offer::SessionOrProject);
    assert_eq!(candidate.port, Some(443));
    assert!(!candidate.guest_named, "an address is not a guest name");
    assert_eq!(candidate.cell.as_str(), entry.destination_cell());

    // A policy lock, a credential refusal and a plain-HTTP hostname never prompt.
    for mutate in [
        |entry: &mut crate::refusal::RefusalEntry| {
            entry.key.kind = crate::refusal::Kind::PolicyLock
        },
        |entry: &mut crate::refusal::RefusalEntry| {
            entry.key.kind = crate::refusal::Kind::CredentialRefusal
        },
        |entry: &mut crate::refusal::RefusalEntry| entry.layer = "platform".to_owned(),
    ] {
        let mut entry = refusal();
        mutate(&mut entry);
        assert!(candidate_for(&entry, &feed.allowances).is_none());
    }
}

#[tokio::test]
async fn an_answered_destination_is_never_a_candidate() {
    let (feed, _root) = feed();
    let entry = refusal();
    let destination = crate::allowances::grantable_destination(&entry).expect("grantable");
    assert!(!feed.allowances.answered(&destination));
    assert!(candidate_for(&entry, &feed.allowances).is_some());
    // An answer given elsewhere under the handler's own lock.
    let grant = feed
        .allowances
        .grant_unless_answered(
            &feed.refusals,
            &entry.id,
            crate::allowances::GrantScope::Session,
            0,
        )
        .await;
    // The refusal is not in the live feed, so the handler cannot resolve it: what
    // this asserts is that an unresolvable ID is reported, not granted.
    assert!(matches!(
        grant,
        crate::allowances::PromptGrant::Reached(crate::allowances::GrantResult::Refused { .. })
    ));
}

#[tokio::test]
async fn a_lagged_answers_channel_closes_only_what_was_actually_answered() {
    // M13: the old lag test called `relay.answered()` directly and never drove a lag,
    // so it passed with the unconditional close restored. This one drives the facade's
    // `recheck_answers` through `handle_feed`, both ways.
    let (feed, _root) = feed();
    let allowances = Arc::clone(&feed.allowances);
    let refusals = Arc::clone(&feed.refusals);
    let size = Size { rows: 30, cols: 80 };
    let mut prompt = Prompt::start(feed, size, relay::Timings::default());
    let now = Instant::now();
    let entry = refusal();
    prompt.handle_feed(
        FeedEvent::Refusal(Ok(Update {
            rev: 1,
            entry: Some(Box::new(entry.clone())),
            suppressed: 0,
            lost: 0,
            gap: false,
        })),
        now,
    );
    assert_eq!(prompt.relay.phase_name(), "entering");
    // Ask the terminal's confirmation, then refuse with the CR... no: reach Asking by
    // writing the enter and answering the position request.
    let g = prompt.relay.generation();
    prompt.written(g, now);
    let laid =
        crate::access_prompt::screen::layout(&prompt.relay.current_view(), size).expect("fits");
    let reply = format!("\x1b[{};3R", laid.status_row() + 1);
    prompt.host_input(
        relay::HostChunk {
            bytes: reply.into_bytes(),
            epoch: 1,
            read_at: now,
        },
        now,
    );
    prompt.input_flushed(1, now);
    assert_eq!(prompt.relay.phase_name(), "asking");

    // Nothing has been answered: a lag must not close the question.
    prompt.handle_feed(
        FeedEvent::Answered(Err(tokio::sync::broadcast::error::RecvError::Lagged(3))),
        now,
    );
    assert_eq!(
        prompt.relay.phase_name(),
        "asking",
        "a lag is not an answer"
    );

    // Now the destination is answered by the handler (a session grant), and the same
    // lag closes the question.
    let destination = crate::allowances::grantable_destination(&entry).expect("grantable");
    let grant = allowances
        .grant(
            &refusals,
            None,
            Some(&destination.to_string()),
            crate::allowances::GrantScope::Session,
            0,
        )
        .await;
    assert!(
        !matches!(grant, crate::allowances::GrantResult::Refused { .. }),
        "{grant:?}"
    );
    prompt.handle_feed(
        FeedEvent::Answered(Err(tokio::sync::broadcast::error::RecvError::Lagged(3))),
        now,
    );
    assert_eq!(
        prompt.relay.phase_name(),
        "restoring",
        "an answered destination closes on the re-check"
    );
}

#[test]
fn the_prompt_starts_idle() {
    let size = Size { rows: 30, cols: 80 };
    let (feed, _root) = feed();
    let mut prompt = Prompt::start(feed, size, relay::Timings::default());
    assert_eq!(prompt.relay.phase_name(), "idle");
    assert_eq!(prompt.deadline(), None);
    assert!(!prompt.wants_host_input());
    // A guest frame with no refusal forwards unchanged.
    let now = Instant::now();
    prompt.guest_output(b"hi".to_vec(), now);
    match prompt.take_outbound_if(|_| true) {
        Some(relay::Outbound::Frame(relay::OutputItem::Data(bytes))) => assert_eq!(bytes, b"hi"),
        other => panic!("expected the guest's bytes, got {other:?}"),
    }
    // No crash on an ended input, and no further prompt.
    prompt.input_ended(now);
    assert_eq!(prompt.relay.phase_name(), "idle");
}
