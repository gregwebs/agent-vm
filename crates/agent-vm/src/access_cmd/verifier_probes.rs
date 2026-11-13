//! Independent verification probes for #557 slice 2, PR 2.
//!
//! These are the verifier's own probes of the four review blockers and of the
//! `--session` narrowing of `access allowances`. They drive the real
//! `LiveSession`, the real `LiveAllowances` controller and the real `run_in`,
//! over a real Unix socket and a real store under a `tempdir` — not the
//! implementer's tests, and not a copy of them.
//!
//! A probe that fails is a finding, not a broken test: it is kept red until the
//! defect it names is fixed.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use super::*;
use crate::allowances::{
    GrantResult, GrantScope, ProjectView, RevokeResult, RevokeScope, StoreHandle,
};
use crate::refusal::SessionId;
use crate::refusal::feed::LiveRefusals;
use crate::refusal::log::SessionsDir;
use crate::session::ProjectSession;
use crate::session_control::{LiveSession, LiveSetup};

/// A destination the fixture grants and revokes.
const DESTINATION: &str = "tcp://[203.0.113.10/32]:443";
const SESSION_ONLY: &str = "udp://[203.0.113.10/32]:53";

/// A policy updater the probe controls: it counts calls, can fail, and remembers
/// the policy it was last asked to apply.
#[derive(Default)]
struct Recorder {
    fail: AtomicBool,
    seen: Mutex<Vec<microsandbox::NetworkPolicy>>,
}

impl Recorder {
    fn handle(self: &Arc<Self>) -> crate::allowances::PolicyUpdater {
        let recorder = Arc::clone(self);
        Arc::new(move |policy| {
            let recorder = Arc::clone(&recorder);
            Box::pin(async move {
                recorder.seen.lock().unwrap().push(policy);
                if recorder.fail.load(Ordering::SeqCst) {
                    return Err(microsandbox::MicrosandboxError::ControlStateChanged);
                }
                Ok(2)
            })
        })
    }

    fn calls(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

fn sessions(root: &Path) -> SessionsDir {
    SessionsDir::open_or_create(&root.join("ab12cd34ef56.sessions")).unwrap()
}

fn project_session(root: &Path) -> ProjectSession {
    ProjectSession {
        project_dir: root.to_path_buf(),
        project_hash: "ab12cd34ef56".to_owned(),
        state_dir: root.join("ab12cd34ef56"),
        sandbox_name: "agent-vm-ab12cd34ef56-1".to_owned(),
    }
}

fn project_dir(root: &Path) -> crate::project::ProjectDir {
    crate::project::ProjectDir::from_path_for_tests(root).expect("a capturable project")
}

/// The store directory a probe writes into. Never `$HOME`.
fn store_dir(root: &Path) -> PathBuf {
    root.join("allowances-store")
}

/// Start the launcher's own controller, as `run::launch` does, with a launch
/// whose configured authority is `allow_egress`.
async fn start(
    root: &Path,
    allow_egress: &[&str],
    store: StoreHandle,
) -> (LiveSession, Arc<LiveRefusals>) {
    let project = project_dir(root);
    let plan = crate::network::plan_for_tests(allow_egress, false).live_policy_plan(None);
    let live = LiveSession::start(
        &project_session(root),
        LiveSetup {
            project: &project,
            store,
            plan,
        },
    )
    .await;
    let refusals = live.refusals().expect("a live refusal feed");
    (live, refusals)
}

fn allowance(text: &str) -> crate::egress_policy::Allowance {
    crate::egress_policy::Allowance::parse(text).expect(text)
}

/// The store's records (`destination` strings), read as a later launch would.
fn stored(root: &Path) -> Vec<String> {
    let file = store_dir(root).join("allowances.json");
    let Ok(text) = std::fs::read_to_string(&file) else {
        return Vec::new();
    };
    let value: serde_json::Value = serde_json::from_str(&text).expect("the store is JSON");
    value["records"]
        .as_array()
        .map(|records| {
            records
                .iter()
                .map(|record| record["destination"].as_str().unwrap_or("").to_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// `agent-vm access` with no subcommand: the refusal table.
async fn run_report(root: &Path) -> (i32, String, String) {
    let view = ProjectView::at_dir_for_tests(
        &store_dir(root),
        &crate::image_pin::ProjectId::of(&project_dir(root)),
    );
    let args = Args {
        command: None,
        session: None,
        all: true,
    };
    let mut out = Vec::new();
    let mut err = Vec::new();
    let status = run_in(
        Some(&sessions(root)),
        &project_dir(root),
        &args,
        &view,
        crate::refusal::feed::now_ms(),
        &mut out,
        &mut err,
    )
    .await
    .expect("the command succeeds");
    (
        status,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

async fn run(
    root: &Path,
    command: AccessSubcommand,
    session: Option<&str>,
) -> (i32, String, String) {
    let view = ProjectView::at_dir_for_tests(
        &store_dir(root),
        &crate::image_pin::ProjectId::of(&project_dir(root)),
    );
    let args = Args {
        command: Some(command),
        session: session.map(str::to_owned),
        all: false,
    };
    let mut out = Vec::new();
    let mut err = Vec::new();
    let status = run_in(
        Some(&sessions(root)),
        &project_dir(root),
        &args,
        &view,
        crate::refusal::feed::now_ms(),
        &mut out,
        &mut err,
    )
    .await
    .expect("the command succeeds");
    (
        status,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

// ---------------------------------------------------------------------------
// Blocker 1 (A-B01): revoking a destination the launch's own --allow-egress
// grants must not claim it is gone.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn verifier_blocker1_revoke_names_the_launch_authority_it_cannot_remove() {
    let root = tempfile::tempdir().unwrap();
    // The launch grants the whole /24; no allowance entry names the destination.
    let (live, _) = start(
        root.path(),
        &["tcp://[203.0.113.0/24]:443"],
        StoreHandle::at_for_tests(&store_dir(root.path())),
    )
    .await;
    let destination = allowance("tcp://[203.0.113.0/24]:443");

    match live
        .allowances()
        .revoke(&destination, RevokeScope::Project)
        .await
    {
        RevokeResult::NotInSession {
            still_effective,
            revision,
            ..
        } => {
            assert!(
                still_effective,
                "a destination the launch's own --allow-egress grants is still in force"
            );
            assert_eq!(revision, None, "no runtime call happened, so no revision");
        }
        other => panic!("expected NotInSession, got {other:?}"),
    }
    live.finish().await;
}

// ---------------------------------------------------------------------------
// Blocker 2 (A-B02): a --project grant over a queued session entry must write
// the record or refuse, never say `recorded` with nothing on disk.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn verifier_blocker2_project_grant_over_a_queued_session_entry_records_it() {
    let root = tempfile::tempdir().unwrap();
    let (live, refusals) = start(
        root.path(),
        &[],
        StoreHandle::at_for_tests(&store_dir(root.path())),
    )
    .await;
    let controller = live.allowances();
    // Queued for boot: no updater is attached yet.
    let first = controller
        .grant(
            &refusals,
            None,
            Some(DESTINATION),
            GrantScope::Session,
            1_000,
        )
        .await;
    assert!(
        matches!(first, GrantResult::QueuedForBoot { .. }),
        "{first:?}"
    );
    assert!(
        stored(root.path()).is_empty(),
        "a session grant writes nothing"
    );

    // The same destination asked for as a project grant, still before `follow`.
    let second = controller
        .grant(
            &refusals,
            None,
            Some(DESTINATION),
            GrantScope::Project,
            2_000,
        )
        .await;
    match &second {
        GrantResult::QueuedForBoot { scope, .. } => assert_eq!(
            scope,
            &GrantScope::Project,
            "the reply must echo the scope the entry now lives in"
        ),
        other => panic!("expected a queued project grant, got {other:?}"),
    }
    assert_eq!(
        stored(root.path()),
        vec![DESTINATION.to_owned()],
        "the reply claims `recorded project allowance`; the store must carry it: {second:?}"
    );
    live.finish().await;
}

#[tokio::test]
async fn verifier_blocker2_a_refusing_store_never_claims_recorded() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = tempfile::tempdir().unwrap();
    let dir = store_dir(root.path());
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    let (live, refusals) = start(root.path(), &[], StoreHandle::at_for_tests(&dir)).await;
    let controller = live.allowances();
    controller
        .grant(
            &refusals,
            None,
            Some(DESTINATION),
            GrantScope::Session,
            1_000,
        )
        .await;

    let result = controller
        .grant(
            &refusals,
            None,
            Some(DESTINATION),
            GrantScope::Project,
            2_000,
        )
        .await;
    assert!(
        matches!(result, GrantResult::Refused { .. }),
        "an untrusted store is a refusal, not a claim: {result:?}"
    );
    assert!(
        std::fs::read_dir(&dir).unwrap().next().is_none(),
        "an untrusted directory gained an entry"
    );
    let snapshot = controller.snapshot();
    assert_eq!(snapshot.session.len(), 1, "{snapshot:?}");
    assert!(snapshot.project.is_empty(), "{snapshot:?}");
    live.finish().await;
}

/// The same two facts as the user sees them, through the real command and a real
/// socket: the sentence says `recorded project allowance`, so the store must
/// carry it.
#[tokio::test]
async fn verifier_blocker2_the_users_sentence_matches_the_store() {
    let root = tempfile::tempdir().unwrap();
    let (live, _) = start(
        root.path(),
        &[],
        StoreHandle::at_for_tests(&store_dir(root.path())),
    )
    .await;
    let id = parked_refusal(&live, "203.0.113.10", 443).await;

    let (status, out, err) = run(
        root.path(),
        AccessSubcommand::Allow(AllowArgs {
            id,
            project: true,
            session: None,
        }),
        None,
    )
    .await;
    assert_eq!(status, 0, "{out}{err}");
    assert!(
        out.contains("recorded project allowance tcp://[203.0.113.10/32]:443"),
        "{out}"
    );
    assert_eq!(
        stored(root.path()),
        vec![DESTINATION.to_owned()],
        "the sentence claims a record the store does not carry: {out}"
    );
    live.finish().await;
}

/// One refusal in this session's live feed, returned by its ID.
async fn parked_refusal(live: &LiveSession, ip: &str, port: u16) -> String {
    let now_ms = crate::refusal::feed::now_ms();
    let record = microsandbox::logs::NetworkLogRecord {
        v: 1,
        t: chrono::DateTime::from_timestamp_millis(now_ms).unwrap(),
        s: microsandbox::logs::LogSource::Network,
        event: microsandbox::logs::NetworkLogEvent::Refusal(microsandbox::logs::NetworkRefusal {
            site: microsandbox::logs::RefusalSite::TcpSyn,
            layer: microsandbox::logs::RefusalLayer::Tenant,
            protocol: microsandbox_types::Protocol::Tcp,
            dst_ip: Some(ip.parse().unwrap()),
            dst_port: Some(port),
            name: None,
            name_source: microsandbox::logs::NameSource::Absent,
            revision: 1,
            credential: None,
            location: None,
            reason: None,
        }),
    };
    let feed = live.refusals().expect("a live refusal feed");
    let mut dirty = false;
    assert!(feed.ingest(&record, &mut dirty, now_ms));
    feed.snapshot().entries[0].id.clone()
}

// ---------------------------------------------------------------------------
// Blocker 3 (A-B03): no live swap may carry unconfirmed queued entries, and a
// failed boot flush must not drop an allowance the runtime accepted.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn verifier_blocker3_a_swap_while_the_boot_queue_is_pending_makes_no_call() {
    let root = tempfile::tempdir().unwrap();
    let (live, refusals) = start(
        root.path(),
        &[],
        StoreHandle::at_for_tests(&store_dir(root.path())),
    )
    .await;
    let controller = live.allowances();
    // Queued before `follow`.
    controller
        .grant(
            &refusals,
            None,
            Some(DESTINATION),
            GrantScope::Session,
            1_000,
        )
        .await;

    let recorder = Arc::new(Recorder::default());
    assert!(
        controller.attach_updater(recorder.handle()),
        "a queue is pending"
    );

    // A second grant in the pending window must queue, not swap: a swap here
    // would carry the unconfirmed entry.
    let queued = controller
        .grant(
            &refusals,
            None,
            Some(SESSION_ONLY),
            GrantScope::Session,
            2_000,
        )
        .await;
    assert!(
        matches!(queued, GrantResult::QueuedForBoot { .. }),
        "{queued:?}"
    );
    assert_eq!(
        recorder.calls(),
        0,
        "a swap was sent while the boot queue was pending"
    );
    let snapshot = controller.snapshot();
    assert_eq!(snapshot.session.len(), 2, "{snapshot:?}");
    assert!(
        snapshot
            .session
            .iter()
            .all(|entry| entry.revision.is_none()),
        "nothing was confirmed by the runtime: {snapshot:?}"
    );
    live.finish().await;
}

#[tokio::test]
async fn verifier_blocker3_a_failed_flush_keeps_what_the_runtime_accepted() {
    let root = tempfile::tempdir().unwrap();
    let (live, refusals) = start(
        root.path(),
        &[],
        StoreHandle::at_for_tests(&store_dir(root.path())),
    )
    .await;
    let controller = live.allowances();
    // A boot-adopted record (rev 1) is what the runtime accepted at boot. It goes
    // through the launch's own adoption path, so the record is a real one.
    let project = project_dir(root.path());
    let view = ProjectView::for_tests(&[SESSION_ONLY], 500, None);
    let mut launch = crate::network::plan_for_tests(&[], false);
    let file = std::path::Path::new("/home/a/.config/agent-vm/allowances.json");
    let (adopted, notice) = launch.adopt_recorded(file, view.allowances());
    assert!(notice.is_none(), "{notice:?}");
    assert_eq!(adopted.len(), 1);
    let warnings =
        controller.adopt_boot_allowances(&view, &adopted, launch.live_policy_plan(Some(file)));
    assert!(warnings.is_empty(), "{warnings:?}");
    let _ = &project;
    // And a grant that cannot be in the boot policy.
    controller
        .grant(
            &refusals,
            None,
            Some(DESTINATION),
            GrantScope::Session,
            1_000,
        )
        .await;

    let recorder = Arc::new(Recorder::default());
    recorder.fail.store(true, Ordering::SeqCst);
    assert!(controller.attach_updater(recorder.handle()));

    // A revoke of the confirmed entry cannot confirm while the queue is pending.
    match controller
        .revoke(&allowance(SESSION_ONLY), RevokeScope::Project)
        .await
    {
        RevokeResult::Unconfirmed { reason, .. } => assert!(
            format!("{reason:?}").contains("BootPending"),
            "a confirmed entry cannot be revoked while the boot queue is pending: {reason:?}"
        ),
        other => panic!("expected Unconfirmed(BootPending), got {other:?}"),
    }

    let notices = controller.flush_queued().await;
    assert_eq!(notices.len(), 1, "{notices:?}");
    assert!(notices[0].contains(DESTINATION), "{notices:?}");
    let snapshot = controller.snapshot();
    assert!(
        snapshot.session.is_empty(),
        "the queued session grant was dropped: {snapshot:?}"
    );
    assert_eq!(
        snapshot.project.len(),
        1,
        "the runtime accepted the adopted record; memory must keep it: {snapshot:?}"
    );
    assert_eq!(snapshot.project[0].revision, Some(1), "{snapshot:?}");
    live.finish().await;
}

// ---------------------------------------------------------------------------
// A finding of this pass: `access allowances --session X` attributes another
// session's silence to X's own row.
// ---------------------------------------------------------------------------

/// `--session aaaaaaaa` narrows the rows to that session; the STATUS cell of a
/// row that is not in force must then say why *that* session has not adopted it,
/// not name a different session that could not be asked.
///
/// This is red on the tree as delivered: `run_allowances` builds one `silent`
/// suffix from every unresponsive session, before it filters by `--session`.
#[tokio::test]
async fn verifier_allowances_session_filter_never_names_another_session() {
    use std::os::unix::net::UnixListener;
    let root = tempfile::tempdir().unwrap();
    let (live, _) = start(
        root.path(),
        &[],
        StoreHandle::at_for_tests(&store_dir(root.path())),
    )
    .await;
    // A record this session has not adopted: the row must say "not in force".
    crate::allowances::record(
        StoreHandle::at_for_tests(&store_dir(root.path())),
        &project_dir(root.path()),
        &allowance("tcp://[198.51.100.9/32]:8443"),
        1_000,
    )
    .await
    .expect("a record");

    let dir = sessions(root.path());
    // A second session that answers nothing: it is alive (not refused), so
    // discovery reports it as `not responding`.
    let silent = SessionId::parse("bbbbbbbb").unwrap();
    let _listener = UnixListener::bind(dir.socket_path(&silent)).unwrap();
    let asked = dir
        .path()
        .read_dir()
        .unwrap()
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name();
            let stem = name.to_str()?.strip_suffix(".sock")?;
            (stem != "bbbbbbbb").then(|| stem.to_owned())
        })
        .collect::<Vec<_>>();
    assert_eq!(asked.len(), 1, "the live session's socket: {asked:?}");
    let session = asked[0].clone();

    let (status, out, err) = run(
        root.path(),
        AccessSubcommand::Allowances(AllowancesArgs {
            session: Some(session.clone()),
        }),
        None,
    )
    .await;
    assert_eq!(status, 0, "{out}{err}");
    assert!(
        err.contains("session bbbbbbbb is not responding"),
        "the unresponsive session is named on stderr (AC9): {err}"
    );
    let row = out
        .lines()
        .find(|line| line.starts_with("project ") && line.contains("198.51.100.9"))
        .unwrap_or_else(|| panic!("no row for the record: {out}"));
    assert!(
        row.contains(&session),
        "the row is about --session {session}: {row}"
    );
    assert!(
        !row.contains("bbbbbbbb"),
        "--session {session} must not lend another session's silence to its row: {row}"
    );
    live.finish().await;
}

// ---------------------------------------------------------------------------
// The acceptance criteria the blockers are not about, probed at the same
// boundaries: the union and scoped revoke (AC5), the older runtime (AC7), the
// demotion on a store failure (AC13), fixed ports (AC3), and the queued wording
// a user reads (AC4).
// ---------------------------------------------------------------------------

/// Rules in `policy` that name exactly `cidr`.
fn cidr_rules(policy: &microsandbox::NetworkPolicy, cidr: &str) -> usize {
    let network: ipnetwork::IpNetwork = cidr.parse().expect(cidr);
    policy
        .rules
        .iter()
        .filter(|rule| match &rule.destination {
            microsandbox_network::policy::Destination::Cidr(named) => *named == network,
            _ => false,
        })
        .count()
}

/// AC5: a session allowance and a project record for the same destination
/// collapse to one rule, and a `--project` revoke deletes the record while the
/// session's allowance stays in force.
#[tokio::test]
async fn verifier_ac5_union_collapses_and_a_project_revoke_leaves_the_session_allowance() {
    let root = tempfile::tempdir().unwrap();
    let (live, _) = start(
        root.path(),
        &[],
        StoreHandle::at_for_tests(&store_dir(root.path())),
    )
    .await;
    let recorder = Arc::new(Recorder::default());
    live.allowances().attach_updater(recorder.handle());
    let id = parked_refusal(&live, "203.0.113.10", 443).await;

    // Both halves, as a user asks for them.
    for project in [false, true] {
        let (status, out, err) = run(
            root.path(),
            AccessSubcommand::Allow(AllowArgs {
                id: id.clone(),
                project,
                session: None,
            }),
            None,
        )
        .await;
        assert_eq!(status, 0, "{out}{err}");
    }
    assert_eq!(stored(root.path()), vec![DESTINATION.to_owned()]);
    // One rule for the destination both tables name.
    {
        let seen = recorder.seen.lock().unwrap();
        let last = seen.last().expect("a swap");
        assert_eq!(cidr_rules(last, "203.0.113.10/32"), 1, "{last:?}");
    }

    // A `--project` revoke: the record goes, the session's rule stays.
    let (status, out, err) = run(
        root.path(),
        AccessSubcommand::Revoke(RevokeArgs {
            destination: DESTINATION.to_owned(),
            project: true,
            session_only: false,
            session: None,
        }),
        None,
    )
    .await;
    assert_eq!(status, 0, "{out}{err}");
    assert!(stored(root.path()).is_empty(), "the record was deleted");
    assert!(out.contains("still in force"), "{out}");
    let snapshot = live.allowances().snapshot();
    assert_eq!(
        snapshot.session.len(),
        1,
        "the session half survives: {snapshot:?}"
    );
    assert!(snapshot.project.is_empty(), "{snapshot:?}");
    {
        let seen = recorder.seen.lock().unwrap();
        let last = seen.last().expect("a swap");
        assert_eq!(
            cidr_rules(last, "203.0.113.10/32"),
            1,
            "the session allowance still allows it: {last:?}"
        );
    }

    // The default revoke removes the rest.
    let (status, out, err) = run(
        root.path(),
        AccessSubcommand::Revoke(RevokeArgs {
            destination: DESTINATION.to_owned(),
            project: false,
            session_only: false,
            session: None,
        }),
        None,
    )
    .await;
    assert_eq!(status, 0, "{out}{err}");
    assert!(!out.contains("still in force"), "{out}");
    let snapshot = live.allowances().snapshot();
    assert!(snapshot.session.is_empty(), "{snapshot:?}");
    {
        let seen = recorder.seen.lock().unwrap();
        let last = seen.last().expect("a swap");
        assert_eq!(cidr_rules(last, "203.0.113.10/32"), 0, "{last:?}");
    }
    live.finish().await;
}

/// AC7: a runtime without `network_policy_update` records the next-launch grant,
/// says so, and exit 0 — never a failure, never a silent no-op.
#[tokio::test]
async fn verifier_ac7_an_older_runtime_records_and_never_fails() {
    let root = tempfile::tempdir().unwrap();
    let (live, _) = start(
        root.path(),
        &[],
        StoreHandle::at_for_tests(&store_dir(root.path())),
    )
    .await;
    let unsupported = Arc::new(Recorder::default());
    unsupported.fail.store(true, Ordering::SeqCst);
    // The recorder's `fail` is a ControlClient error; an Unsupported answer is
    // its own arm, so build it directly.
    let updater: crate::allowances::PolicyUpdater = Arc::new(|_policy| {
        Box::pin(async {
            Err(microsandbox::MicrosandboxError::Unsupported {
                op: microsandbox::Operation::SandboxUpdateNetworkPolicy,
                reason: microsandbox::UnsupportedReason::NotAvailable("old runtime".to_owned()),
            })
        })
    });
    live.allowances().attach_updater(updater);
    let id = parked_refusal(&live, "203.0.113.10", 443).await;

    let (status, out, err) = run(
        root.path(),
        AccessSubcommand::Allow(AllowArgs {
            id,
            project: false,
            session: None,
        }),
        None,
    )
    .await;
    assert_eq!(status, 0, "{out}{err}");
    assert!(
        out.contains("this runtime cannot replace its network policy while it runs"),
        "one sentence says why: {out}"
    );
    assert!(!out.contains("policy revision"), "{out}");
    assert_eq!(
        stored(root.path()),
        vec![DESTINATION.to_owned()],
        "the next-launch grant is recorded"
    );
    live.finish().await;
}

/// AC13: a store that refuses after the runtime accepted demotes the entry to
/// the session, and both later commands keep saying so.
#[tokio::test]
async fn verifier_ac13_a_refused_record_demotes_and_says_so_everywhere() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = tempfile::tempdir().unwrap();
    let dir = store_dir(root.path());
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    let (live, _) = start(root.path(), &[], StoreHandle::at_for_tests(&dir)).await;
    let recorder = Arc::new(Recorder::default());
    live.allowances().attach_updater(recorder.handle());
    let id = parked_refusal(&live, "203.0.113.10", 443).await;

    let (status, out, err) = run(
        root.path(),
        AccessSubcommand::Allow(AllowArgs {
            id: id.clone(),
            project: true,
            session: None,
        }),
        None,
    )
    .await;
    assert_eq!(status, 1, "{out}{err}");
    let reply = format!("{out}{err}");
    let claim = "applied session allowance tcp://[203.0.113.10/32]:443";
    assert!(reply.contains(claim), "{reply}");
    assert!(
        reply.contains("applied to this session only (rev 2), not recorded for the project"),
        "{reply}"
    );

    // The table and the listing agree with the reply.
    let (status, table, table_err) = run_report(root.path()).await;
    assert_eq!(status, 0, "{table_err}");
    let row = table
        .lines()
        .find(|line| line.starts_with(&id))
        .unwrap_or_else(|| panic!("no row: {table}"));
    assert!(
        row.contains("applied to this session only (rev 2)"),
        "{row}"
    );
    assert!(row.contains("not recorded for the project"), "{row}");

    let (status, listing, _) = run(
        root.path(),
        AccessSubcommand::Allowances(AllowancesArgs { session: None }),
        None,
    )
    .await;
    assert_eq!(status, 0);
    let row = listing
        .lines()
        .find(|line| line.starts_with("session ") && line.contains(DESTINATION))
        .unwrap_or_else(|| panic!("no session row: {listing}"));
    assert!(
        row.contains("applied to this session only (rev 2)"),
        "{row}"
    );
    live.finish().await;
}

/// AC3: adding a TLS-intercepted port a launch did not fix is refused in the
/// session, and deferred (with a record) for the project.
#[tokio::test]
async fn verifier_ac3_an_unfixed_intercepted_port_is_refused_or_deferred() {
    let root = tempfile::tempdir().unwrap();
    // The launch fixed port 443 by granting one hostname; 8443 is not in it.
    let (live, refusals) = start(
        root.path(),
        &["api.example.com"],
        StoreHandle::at_for_tests(&store_dir(root.path())),
    )
    .await;
    let controller = live.allowances();
    let recorder = Arc::new(Recorder::default());
    controller.attach_updater(recorder.handle());
    let destination = "tcp://other.example:8443";

    let refused = controller
        .grant(
            &refusals,
            None,
            Some(destination),
            GrantScope::Session,
            1_000,
        )
        .await;
    assert!(
        matches!(refused, GrantResult::Refused { .. }),
        "a session grant of an unfixed port is refused: {refused:?}"
    );
    assert_eq!(recorder.calls(), 0, "no swap was attempted");

    let deferred = controller
        .grant(
            &refusals,
            None,
            Some(destination),
            GrantScope::Project,
            2_000,
        )
        .await;
    assert!(
        matches!(deferred, GrantResult::NextLaunch { .. }),
        "a project grant of an unfixed port is deferred: {deferred:?}"
    );
    assert_eq!(recorder.calls(), 0, "no swap was attempted");
    assert_eq!(stored(root.path()), vec![destination.to_owned()]);
    live.finish().await;
}

/// AC4: a grant accepted before `follow` reads as conditional, not as applied.
#[tokio::test]
async fn verifier_ac4_a_queued_grant_does_not_promise_an_outcome() {
    let root = tempfile::tempdir().unwrap();
    let (live, _) = start(
        root.path(),
        &[],
        StoreHandle::at_for_tests(&store_dir(root.path())),
    )
    .await;
    let id = parked_refusal(&live, "203.0.113.10", 443).await;
    let (status, out, err) = run(
        root.path(),
        AccessSubcommand::Allow(AllowArgs {
            id,
            project: false,
            session: None,
        }),
        None,
    )
    .await;
    assert_eq!(status, 0, "{out}{err}");
    assert!(
        out.contains(
            "accepted tcp://[203.0.113.10/32]:443 for this session; applied when the session finishes starting — confirm with `agent-vm access allowances`"
        ),
        "{out}"
    );
    assert!(
        !out.contains("policy revision"),
        "a queued grant has no revision to claim: {out}"
    );
    live.finish().await;
}

/// A second finding of this pass: `access revoke <D> --session-only` with no
/// active session reports the project record as absent and the next launch as
/// starting without it, although `--session-only` never touches the record and
/// the record is still there.
///
/// This is red on the tree as delivered: `run_revoke`'s no-active-session branch
/// prints `if removed { "deleted" } else { "no record for" }` without consulting
/// `scope`, and `removed` is false for `RevokeScope::Session` by construction.
#[tokio::test]
async fn verifier_revoke_session_only_never_claims_the_record_is_gone() {
    let root = tempfile::tempdir().unwrap();
    crate::allowances::record(
        StoreHandle::at_for_tests(&store_dir(root.path())),
        &project_dir(root.path()),
        &allowance(DESTINATION),
        1_000,
    )
    .await
    .expect("a record");
    let (status, out, err) = run(
        root.path(),
        AccessSubcommand::Revoke(RevokeArgs {
            destination: DESTINATION.to_owned(),
            project: false,
            session_only: true,
            session: None,
        }),
        None,
    )
    .await;
    assert_eq!(status, 0, "{out}{err}");
    let sentence = format!("{out}{err}");
    assert!(
        !sentence.contains("no record for"),
        "the record is still there; --session-only never deletes it: {sentence}"
    );
    assert!(
        !sentence.contains("the next launch starts without it"),
        "the record still carries it to the next launch: {sentence}"
    );
    assert_eq!(
        stored(root.path()),
        vec![DESTINATION.to_owned()],
        "the record is untouched"
    );
}

/// AC13/AC2's write order, from the refusing side: when the runtime cannot apply
/// the change, no record is written — the store is touched only after a
/// confirmed revision.
#[tokio::test]
async fn verifier_ac13_a_failed_runtime_writes_no_record() {
    let root = tempfile::tempdir().unwrap();
    let (live, _) = start(
        root.path(),
        &[],
        StoreHandle::at_for_tests(&store_dir(root.path())),
    )
    .await;
    let failing = Arc::new(Recorder::default());
    failing.fail.store(true, Ordering::SeqCst);
    live.allowances().attach_updater(failing.handle());
    let id = parked_refusal(&live, "203.0.113.10", 443).await;

    let (status, out, err) = run(
        root.path(),
        AccessSubcommand::Allow(AllowArgs {
            id,
            project: true,
            session: None,
        }),
        None,
    )
    .await;
    assert_eq!(status, 1, "{out}{err}");
    assert!(
        format!("{out}{err}").contains("the runtime could not apply the change"),
        "{out}{err}"
    );
    assert!(
        stored(root.path()).is_empty(),
        "a failed swap wrote a project record"
    );
    assert!(
        !store_dir(root.path()).join("allowances.lock").exists(),
        "the writer was never opened"
    );
    live.finish().await;
}
