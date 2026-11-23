//! The driver's lifecycle, on a virtual clock and an in-memory helper.
//!
//! Every test here names the rule it pins. The backend is [`FakeHelperBackend`],
//! so the invariants that matter — one operation at a time, a bounded
//! acknowledgement, the acknowledged banner state, the idle exit and the
//! teardown order — are exercised with no child process, no AppKit and no real
//! time (S6). Phase 7 adds the `#[ignore]` contract tests that drive the real
//! [`super::ChildHelperBackend`] against `harness fake-notifier`.
//!
//! The refusal and allowance sides are *real*: `LiveRefusals` and
//! `LiveAllowances` are the production types, so an "answer" here goes through
//! the same `answered()`/broadcast path an `access allow` or a prompt `s` uses.
//!
//! Two seams exist only for these tests: [`super::Frames::from_bytes`], which
//! drives the production line framing over a byte slice, and the pre-commit hook
//! on [`DriverInputs`], which reaches the one instant no channel can.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use microsandbox::logs::{
    LogSource, NameSource, NetworkLogEvent, NetworkLogRecord, NetworkRefusal, RefusalLayer,
    RefusalSite,
};
use microsandbox_types::Protocol;
use tokio::sync::mpsc;

use super::*;
use crate::allowances::{GrantScope, StoreHandle};
use crate::notify::{FinalWriteStatus, NOTIFICATIONS_OFF, NotifierHandle};
use crate::refusal::SessionInfo;
use crate::refusal::SessionRefusals;
use crate::refusal::feed::LiveRefusals;

const SID: &str = "3f9a12c4";
const PROJECT_HASH: &str = "0f9a";
const BANNER: &str = "agent-vm.0f9a.3f9a12c4";
const FIRST_IP: &str = "203.0.113.10";
const OTHER_IP: &str = "198.51.100.7";

// ---------------------------------------------------------------------------
// The fake helper
// ---------------------------------------------------------------------------

/// One spawned fake child, as the test drives it.
struct FakeHelper {
    commands: mpsc::UnboundedReceiver<HelperCommand>,
    /// `None` once the test has killed the child: the backend's `read` then sees
    /// EOF, exactly like a process that exited.
    events: Option<mpsc::UnboundedSender<HelperEvent>>,
    closed: mpsc::UnboundedReceiver<()>,
    killed: mpsc::UnboundedReceiver<()>,
}

impl FakeHelper {
    async fn next_command(&mut self) -> HelperCommand {
        tokio::time::timeout(Duration::from_secs(60), self.commands.recv())
            .await
            .expect("the driver writes a command")
            .expect("the driver keeps the helper's stdin")
    }

    fn try_command(&mut self) -> Option<HelperCommand> {
        self.commands.try_recv().ok()
    }

    fn send(&mut self, event: HelperEvent) {
        self.events
            .as_ref()
            .expect("the helper is alive")
            .send(event)
            .expect("the driver still reads");
    }

    /// The child exits without being asked to.
    fn die(&mut self) {
        self.events = None;
    }

    fn stdin_closed(&mut self) -> bool {
        self.closed.try_recv().is_ok()
    }

    async fn wait_reaped(&mut self) {
        tokio::time::timeout(Duration::from_secs(60), self.killed.recv())
            .await
            .expect("the child is killed and reaped")
            .expect("a kill was signalled");
    }

    /// Whether a kill has been signalled, without waiting for one.
    fn was_killed(&mut self) -> bool {
        self.killed.try_recv().is_ok()
    }
}

struct FakeHelperBackend {
    commands: mpsc::UnboundedSender<HelperCommand>,
    events: mpsc::UnboundedReceiver<HelperEvent>,
    closed: mpsc::UnboundedSender<()>,
    killed: mpsc::UnboundedSender<()>,
}

impl HelperBackend for FakeHelperBackend {
    fn write<'a>(&'a mut self, command: &'a HelperCommand) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            self.commands
                .send(command.clone())
                .map_err(|_| io::Error::other("the test dropped its helper handle"))
        })
    }

    fn read(&mut self) -> BoxFuture<'_, io::Result<Option<HelperEvent>>> {
        // A closed channel is EOF; there is no partial-line state to keep, so a
        // cancelled `recv` loses nothing.
        Box::pin(async move { Ok(self.events.recv().await) })
    }

    fn close_stdin(&mut self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let _ = self.closed.send(());
        })
    }

    fn terminate(&mut self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let _ = self.killed.send(());
        })
    }
}

struct FakeSpawner {
    spawned: mpsc::UnboundedSender<FakeHelper>,
}

impl HelperSpawner for FakeSpawner {
    fn spawn(&self) -> BoxFuture<'static, io::Result<Box<dyn HelperBackend>>> {
        let (commands, command_rx) = mpsc::unbounded_channel();
        let (event_tx, events) = mpsc::unbounded_channel();
        let (closed, closed_rx) = mpsc::unbounded_channel();
        let (killed, killed_rx) = mpsc::unbounded_channel();
        let helper = FakeHelper {
            commands: command_rx,
            events: Some(event_tx),
            closed: closed_rx,
            killed: killed_rx,
        };
        let spawned = self.spawned.clone();
        Box::pin(async move {
            let _ = spawned.send(helper);
            Ok(Box::new(FakeHelperBackend {
                commands,
                events,
                closed,
                killed,
            }) as Box<dyn HelperBackend>)
        })
    }
}

/// The same fake child, but every spawn waits for the test to let it through, so
/// the test can act during the driver's `ensure_spawn` await.
struct GatedSpawner {
    spawned: mpsc::UnboundedSender<FakeHelper>,
    gate: Arc<tokio::sync::Notify>,
}

impl HelperSpawner for GatedSpawner {
    fn spawn(&self) -> BoxFuture<'static, io::Result<Box<dyn HelperBackend>>> {
        let (commands, command_rx) = mpsc::unbounded_channel();
        let (event_tx, events) = mpsc::unbounded_channel();
        let (closed, closed_rx) = mpsc::unbounded_channel();
        let (killed, killed_rx) = mpsc::unbounded_channel();
        let helper = FakeHelper {
            commands: command_rx,
            events: Some(event_tx),
            closed: closed_rx,
            killed: killed_rx,
        };
        let spawned = self.spawned.clone();
        let gate = Arc::clone(&self.gate);
        Box::pin(async move {
            let _ = spawned.send(helper);
            gate.notified().await;
            Ok(Box::new(FakeHelperBackend {
                commands,
                events,
                closed,
                killed,
            }) as Box<dyn HelperBackend>)
        })
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn session() -> SessionId {
    SessionId::parse(SID).expect("a valid session ID")
}

fn destination(ip: &str) -> String {
    format!("tcp://[{ip}/32]:443")
}

fn record(ip: &str, revision: u64) -> NetworkLogRecord {
    NetworkLogRecord {
        v: 1,
        t: chrono::DateTime::from_timestamp_millis(1_760_000_000_000 + revision as i64 * 1000)
            .expect("a timestamp"),
        s: LogSource::Network,
        event: NetworkLogEvent::Refusal(NetworkRefusal {
            site: RefusalSite::TcpSyn,
            layer: RefusalLayer::Tenant,
            protocol: Protocol::Tcp,
            dst_ip: ip.parse().ok(),
            dst_port: Some(443),
            name: None,
            name_source: NameSource::Absent,
            revision,
            credential: None,
            location: None,
            reason: None,
        }),
    }
}

/// The operator answered this destination: the live tables hold it and the
/// answers broadcast fires, exactly as `access allow` or a prompt `s` does.
async fn grant(allowances: &LiveAllowances, refusals: &LiveRefusals, ip: &str) {
    let destination = destination(ip);
    let result = allowances
        .grant(
            refusals,
            None,
            Some(destination.as_str()),
            GrantScope::Session,
            0,
        )
        .await;
    assert!(result.allowed().is_some(), "{result:?}");
    assert!(
        allowances.answered(&Allowance::parse(&destination).expect("a canonical allowance")),
        "the destination is answered"
    );
}

fn ingest(refusals: &LiveRefusals, ip: &str, revision: u64) {
    let mut dirty = false;
    assert!(
        refusals.ingest(&record(ip, revision), &mut dirty, 0),
        "every record here changes the entry"
    );
}

fn entry_id(refusals: &LiveRefusals, ip: &str) -> String {
    refusals
        .snapshot()
        .entries
        .iter()
        .find(|entry| entry.destination_cell().contains(ip))
        .expect("the entry exists")
        .id
        .clone()
}

/// The real refusal feed and allowance controller, plus the temp directory they
/// live in.
struct Fixture {
    refusals: Arc<LiveRefusals>,
    allowances: Arc<LiveAllowances>,
    _root: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("a temp directory");
        let project = crate::project::ProjectDir::from_path_for_tests(root.path())
            .expect("a project directory");
        let store = StoreHandle::at_for_tests(&root.path().join("store"));
        let plan = crate::network::plan_for_tests(&[], false).live_policy_plan(None);
        let allowances = LiveAllowances::new(&project, store, plan);
        let refusals = LiveRefusals::new(SessionRefusals::new(SessionInfo {
            id: session(),
            pid: 1,
            started_ms: 0,
            socket: true,
        }));
        Self {
            refusals,
            allowances,
            _root: root,
        }
    }

    fn ingest(&self, ip: &str, revision: u64) {
        ingest(&self.refusals, ip, revision);
    }

    async fn grant(&self, ip: &str) {
        grant(&self.allowances, &self.refusals, ip).await;
    }

    fn start(self, mode: PromptMode) -> Bench {
        self.start_with(mode, None)
    }

    /// The same, with a hook at the driver's pre-commit instant (F1, F6).
    fn start_with(self, mode: PromptMode, before_commit: Option<Box<dyn FnMut() + Send>>) -> Bench {
        let (spawned, spawned_rx) = mpsc::unbounded_channel();
        self.start_over(
            mode,
            before_commit,
            Box::new(FakeSpawner { spawned }),
            spawned_rx,
        )
    }

    /// The same, with every spawn waiting for the test's `notify_one`, so the test
    /// can act while the driver is inside `ensure_spawn` — the one await where it
    /// reads no channel and holds no timer.
    fn start_gated(self, mode: PromptMode) -> (Bench, Arc<tokio::sync::Notify>) {
        let (spawned, spawned_rx) = mpsc::unbounded_channel();
        let gate = Arc::new(tokio::sync::Notify::new());
        let bench = self.start_over(
            mode,
            None,
            Box::new(GatedSpawner {
                spawned,
                gate: Arc::clone(&gate),
            }),
            spawned_rx,
        );
        (bench, gate)
    }

    fn start_over(
        self,
        mode: PromptMode,
        before_commit: Option<Box<dyn FnMut() + Send>>,
        spawner: Box<dyn HelperSpawner>,
        spawned: mpsc::UnboundedReceiver<FakeHelper>,
    ) -> Bench {
        let (inputs, lines) = self.inputs(mode, before_commit);
        let handle = NotifierHandle::start_with_spawner(inputs, spawner);
        Bench {
            handle,
            spawned,
            lines,
            refusals: self.refusals,
            allowances: self.allowances,
            _root: self._root,
        }
    }

    /// The driver's inputs and the captured hint sink, for a test that brings its
    /// own spawner: the child contract's real `harness fake-notifier`.
    fn inputs(
        &self,
        mode: PromptMode,
        before_commit: Option<Box<dyn FnMut() + Send>>,
    ) -> (DriverInputs, Arc<Mutex<Vec<String>>>) {
        let (hint, lines) = Hint::capture_notifications_off();
        let inputs = DriverInputs {
            refusals: Arc::clone(&self.refusals),
            allowances: Arc::clone(&self.allowances),
            notifications_off: Arc::new(hint),
            meta: SessionMeta {
                project_hash: PROJECT_HASH.to_owned(),
                project_name: "demo".to_owned(),
                session_id: session(),
            },
            mode,
            click: ClickUserInfo {
                session: SID.to_owned(),
                project: "/Users/me/proj".to_owned(),
                state_dir: "/Users/me/.local/state/agent-vm".to_owned(),
                terminal: "terminal".to_owned(),
            },
            before_commit,
        };
        (inputs, lines)
    }
}

struct Bench {
    handle: NotifierHandle,
    spawned: mpsc::UnboundedReceiver<FakeHelper>,
    lines: Arc<Mutex<Vec<String>>>,
    refusals: Arc<LiveRefusals>,
    allowances: Arc<LiveAllowances>,
    _root: tempfile::TempDir,
}

impl Bench {
    fn new(mode: PromptMode) -> Self {
        Fixture::new().start(mode)
    }

    fn ingest(&self, ip: &str, revision: u64) {
        ingest(&self.refusals, ip, revision);
    }

    async fn grant(&self, ip: &str) {
        grant(&self.allowances, &self.refusals, ip).await;
    }

    fn entry_id(&self, ip: &str) -> String {
        entry_id(&self.refusals, ip)
    }

    fn signal(&self, signal: PromptSignal) {
        // The same non-blocking sink the prompt's loop holds (R12).
        self.handle.signals().signal(signal);
    }

    async fn next_child(&mut self) -> FakeHelper {
        tokio::time::timeout(Duration::from_secs(60), self.spawned.recv())
            .await
            .expect("the driver spawns a helper")
            .expect("a fake helper")
    }

    fn lines(&self) -> Vec<String> {
        self.lines
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

/// Let the driver run without moving the clock to its next deadline.
async fn settle() {
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
}

/// Move the virtual clock forward and let the driver act on what fired.
async fn advance(seconds: u64) {
    advance_for(Duration::from_secs(seconds)).await;
}

async fn advance_for(duration: Duration) {
    tokio::time::advance(duration).await;
    settle().await;
}

fn seq_of(command: &HelperCommand) -> u64 {
    match command {
        HelperCommand::Post { seq, .. } | HelperCommand::Remove { seq, .. } => *seq,
        HelperCommand::Quit { .. } => 0,
    }
}

/// The banner a command names, empty for `Quit`.
fn id_of(command: &HelperCommand) -> &str {
    match command {
        HelperCommand::Post { id, .. } | HelperCommand::Remove { id, .. } => id,
        HelperCommand::Quit { .. } => "",
    }
}

fn posted(seq: u64, ok: bool) -> HelperEvent {
    HelperEvent::Posted {
        v: PROTOCOL_VERSION,
        seq,
        id: BANNER.to_owned(),
        ok,
        denied: false,
        error: String::new(),
    }
}

fn denied_post(seq: u64) -> HelperEvent {
    HelperEvent::Posted {
        v: PROTOCOL_VERSION,
        seq,
        id: BANNER.to_owned(),
        ok: false,
        denied: true,
        error: String::new(),
    }
}

fn removed(seq: u64) -> HelperEvent {
    HelperEvent::Removed {
        v: PROTOCOL_VERSION,
        seq,
        id: BANNER.to_owned(),
        ok: true,
    }
}

fn auth(status: &str) -> HelperEvent {
    HelperEvent::Auth {
        v: PROTOCOL_VERSION,
        granted: status == "authorized",
        status: status.to_owned(),
        alert_style: String::new(),
        error: String::new(),
    }
}

/// The banner text, for the assertions about *which* entries a post speaks for.
fn banner_text(command: &HelperCommand) -> String {
    match command {
        HelperCommand::Post {
            title,
            subtitle,
            body,
            ..
        } => format!("{title} {subtitle} {body}"),
        other => panic!("expected a post, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The invariants
// ---------------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn an_answered_destination_arriving_before_the_scheduled_post_suppresses_it() {
    let mut bench = Bench::new(PromptMode::AfterPromptGrace);
    bench.ingest(FIRST_IP, 1);
    settle().await;
    let entry = bench.entry_id(FIRST_IP);
    // The question became visible: the full grace starts here.
    bench.signal(PromptSignal::Shown {
        entry_id: entry,
        count: 1,
        observed_at: super::std_now(),
    });
    settle().await;
    advance(4).await;
    assert!(
        bench.spawned.try_recv().is_err(),
        "the grace has not expired, so nothing has posted yet"
    );

    // The operator answers at 4 s — before the 5 s deadline.
    bench.grant(FIRST_IP).await;
    settle().await;
    advance(10).await;
    assert!(
        bench.spawned.try_recv().is_err(),
        "an answer disposes of its attempt, whenever it is observed"
    );

    // Control: the same mode and clock do post an attempt nobody answered, so
    // the silence above is the answer and not a stopped driver.
    bench.ingest(OTHER_IP, 1);
    settle().await;
    let other = bench.entry_id(OTHER_IP);
    bench.signal(PromptSignal::Shown {
        entry_id: other,
        count: 1,
        observed_at: super::std_now(),
    });
    advance(6).await;
    let mut helper = bench.next_child().await;
    let post = helper.next_command().await;
    let text = banner_text(&post);
    assert!(text.contains(OTHER_IP), "{text}");
    assert!(
        !text.contains(FIRST_IP),
        "the answered destination is not in the banner: {text}"
    );
}

#[tokio::test(start_paused = true)]
async fn a_lagged_refusals_channel_rechecks_against_answered() {
    let mut bench = Bench::new(PromptMode::Immediate);
    // Answered before the feed ever reports it.
    bench.grant(FIRST_IP).await;
    // 300 live updates for the answered entry, then one for an unanswered one —
    // all without yielding, so the driver's 256-slot receiver lags and both live
    // wakeups are lost. Only the snapshot recovery can see either entry.
    for revision in 1..=300 {
        bench.ingest(FIRST_IP, revision);
    }
    bench.ingest(OTHER_IP, 1);
    settle().await;

    let mut helper = bench.next_child().await;
    let post = helper.next_command().await;
    let text = banner_text(&post);
    // The unanswered entry is posted, and it can only have been seen through the
    // lag-recovery snapshot: its own update was in the lost window.
    assert!(text.contains(OTHER_IP), "{text}");
    // The answered one is not, on that same path.
    assert!(!text.contains(FIRST_IP), "{text}");
}

#[tokio::test(start_paused = true)]
async fn a_grant_before_the_subscription_is_never_posted() {
    let fixture = Fixture::new();
    fixture.grant(FIRST_IP).await;
    fixture.ingest(FIRST_IP, 1);
    // The entry is in the subscription's own snapshot and is already answered, so
    // the snapshot intake path filters it (B3).
    let mut bench = fixture.start(PromptMode::Immediate);
    settle().await;
    advance(10).await;
    assert!(
        bench.spawned.try_recv().is_err(),
        "the subscription snapshot is filtered through `answered`"
    );
}

#[tokio::test(start_paused = true)]
async fn an_ack_timeout_leaves_the_banner_ambiguous_and_the_next_op_reconciles() {
    let mut bench = Bench::new(PromptMode::Immediate);
    bench.ingest(FIRST_IP, 1);
    let mut first = bench.next_child().await;
    let post = first.next_command().await;
    let first_seq = seq_of(&post);
    assert!(matches!(post, HelperCommand::Post { .. }), "{post:?}");

    // No acknowledgement: the bound expires, the outcome is unknown, and the
    // unresponsive child is killed and reaped.
    advance(3).await;
    first.wait_reaped().await;

    // The driver is not wedged: it respawns and writes the next operation.
    let mut second = bench.next_child().await;
    let retry = second.next_command().await;
    let retry_seq = seq_of(&retry);
    assert!(
        retry_seq > first_seq,
        "seq is monotonic: {retry_seq} after {first_seq}"
    );
    second.send(posted(retry_seq, true));

    // `Ambiguous` is reconciled by a remove the moment nothing is owed.
    bench.grant(FIRST_IP).await;
    let remove = second.next_command().await;
    assert!(matches!(remove, HelperCommand::Remove { .. }), "{remove:?}");
    assert_eq!(
        match &remove {
            HelperCommand::Remove { id, .. } => id.as_str(),
            _ => unreachable!(),
        },
        BANNER,
        "the remove names the id the post used"
    );
    second.send(removed(seq_of(&remove)));
    settle().await;
}

#[tokio::test(start_paused = true)]
async fn a_denied_authorization_fires_the_notifications_off_hint_exactly_once() {
    let mut bench = Bench::new(PromptMode::Immediate);
    bench.ingest(FIRST_IP, 1);
    let mut helper = bench.next_child().await;
    let seq = seq_of(&helper.next_command().await);

    helper.send(auth("denied"));
    helper.send(denied_post(seq));
    settle().await;
    assert_eq!(bench.lines(), vec![NOTIFICATIONS_OFF.to_owned()]);

    // Repeated denials are no-ops: the `Hint`'s own once-flag is the gate, so the
    // driver may call `fire` without counting.
    helper.send(auth("denied"));
    helper.send(denied_post(seq));
    settle().await;
    assert_eq!(bench.lines().len(), 1, "{:?}", bench.lines());

    // Posting stops for the session: a new refusal writes nothing at all.
    bench.ingest(OTHER_IP, 1);
    advance(5).await;
    assert!(
        helper.try_command().is_none(),
        "a denied session posts nothing more"
    );
}

#[tokio::test(start_paused = true)]
async fn idle_exit_keeps_the_acked_state_and_arms_one_cleanup_spawn() {
    let mut bench = Bench::new(PromptMode::Immediate);
    bench.ingest(FIRST_IP, 1);
    let mut helper = bench.next_child().await;
    let post = helper.next_command().await;
    helper.send(posted(seq_of(&post), true));
    settle().await;

    // 30 s with nothing to do: the helper is quit and reaped, and the banner state
    // is kept, because the banner is still in Notification Center.
    advance(31).await;
    let quit = helper.next_command().await;
    assert!(matches!(quit, HelperCommand::Quit { .. }), "{quit:?}");
    helper.wait_reaped().await;

    // The banner is still up, so the removal a later answer owes is written by
    // exactly one bounded cleanup-only spawn.
    bench.grant(FIRST_IP).await;
    let mut cleanup = bench.next_child().await;
    let remove = cleanup.next_command().await;
    assert!(matches!(remove, HelperCommand::Remove { .. }), "{remove:?}");
    let quit = cleanup.next_command().await;
    assert!(matches!(quit, HelperCommand::Quit { .. }), "{quit:?}");
    assert!(
        cleanup.stdin_closed(),
        "the quit drops stdin, so a well-behaved helper exits"
    );

    // One per idle period: an unacknowledged cleanup is not retried, however long
    // the session then does nothing.
    advance(60).await;
    assert!(
        bench.spawned.try_recv().is_err(),
        "exactly one cleanup-only spawn, never a retry loop"
    );
}

#[tokio::test(start_paused = true)]
async fn the_cleanup_spawn_never_happens_without_a_banner() {
    let mut bench = Bench::new(PromptMode::Immediate);
    bench.ingest(FIRST_IP, 1);
    let mut helper = bench.next_child().await;
    let post = helper.next_command().await;
    helper.send(posted(seq_of(&post), true));
    settle().await;
    // The banner is taken away for real, so `AckedState` is `Absent`.
    bench.grant(FIRST_IP).await;
    let remove = helper.next_command().await;
    helper.send(removed(seq_of(&remove)));
    settle().await;

    advance(31).await;
    let quit = helper.next_command().await;
    assert!(matches!(quit, HelperCommand::Quit { .. }), "{quit:?}");
    settle().await;
    advance(60).await;
    assert!(
        bench.spawned.try_recv().is_err(),
        "nothing was ever left showing, so nothing is spawned"
    );
}

#[tokio::test(start_paused = true)]
async fn finish_flushes_a_final_post_only_when_the_final_write_persisted() {
    // (a) The final persist failed: a new banner would claim durability the
    // record does not have, so only the quit is written.
    let mut bench = Bench::new(PromptMode::Immediate);
    bench.ingest(FIRST_IP, 1);
    let mut helper = bench.next_child().await;
    let post = helper.next_command().await;
    helper.send(posted(seq_of(&post), true));
    settle().await;
    // A later count for the same entry leaves the payload dirty; flood control
    // would hold the post back for 3 s, so the finish is what decides.
    bench.ingest(FIRST_IP, 2);
    let snapshot = bench.refusals.snapshot();
    tokio::join!(
        bench.handle.finish(snapshot, FinalWriteStatus::Failed),
        async {
            let quit = helper.next_command().await;
            assert!(
                matches!(quit, HelperCommand::Quit { .. }),
                "a failed final write suppresses the post: {quit:?}"
            );
        }
    );

    // (b) The final persist succeeded: the owed banner is flushed immediately, and
    // the close is a quit with no remove, so the banner stays clickable as an
    // ended session.
    let mut bench = Bench::new(PromptMode::Immediate);
    bench.ingest(FIRST_IP, 1);
    let mut helper = bench.next_child().await;
    let post = helper.next_command().await;
    helper.send(posted(seq_of(&post), true));
    settle().await;
    bench.ingest(FIRST_IP, 2);
    let snapshot = bench.refusals.snapshot();
    tokio::join!(
        bench.handle.finish(snapshot, FinalWriteStatus::Persisted),
        async {
            let final_post = helper.next_command().await;
            assert!(
                matches!(final_post, HelperCommand::Post { .. }),
                "{final_post:?}"
            );
            helper.send(posted(seq_of(&final_post), true));
            let quit = helper.next_command().await;
            assert!(
                matches!(quit, HelperCommand::Quit { .. }),
                "a teardown never removes: {quit:?}"
            );
        }
    );
}

#[tokio::test(start_paused = true)]
async fn a_child_that_dies_mid_op_is_reaped_and_does_not_wedge_the_driver() {
    let mut bench = Bench::new(PromptMode::Immediate);
    bench.ingest(FIRST_IP, 1);
    let mut first = bench.next_child().await;
    let post = first.next_command().await;
    assert_eq!(
        seq_of(&post),
        1,
        "the first operation is the post: {post:?}"
    );
    // An unexpected EOF while the operation is in flight: its outcome is unknown.
    first.die();
    first.wait_reaped().await;

    // The driver recovers: a new child is spawned and the owed banner written.
    let mut second = bench.next_child().await;
    let retry = second.next_command().await;
    assert!(matches!(retry, HelperCommand::Post { .. }), "{retry:?}");
    second.send(posted(seq_of(&retry), true));

    // And a later removal still reconciles on the new child.
    bench.grant(FIRST_IP).await;
    let remove = second.next_command().await;
    assert!(matches!(remove, HelperCommand::Remove { .. }), "{remove:?}");
    second.send(removed(seq_of(&remove)));
    settle().await;
}

// ---------------------------------------------------------------------------
// The commit point (F1, and F6's pin on the pre-commit drain)
// ---------------------------------------------------------------------------

/// The hook fires at the instant before a post is committed: the one point a test
/// cannot otherwise reach, because every other step of a `desired()` pass is
/// synchronous, so no channel can deliver anything between them.
#[tokio::test(start_paused = true)]
async fn an_answer_drained_at_the_commit_point_is_never_posted() {
    let fixture = Fixture::new();
    fixture.ingest(FIRST_IP, 1);
    let sender: Arc<Mutex<Option<mpsc::UnboundedSender<PromptSignal>>>> =
        Arc::new(Mutex::new(None));
    let hook = {
        let sender = Arc::clone(&sender);
        let refusals = Arc::clone(&fixture.refusals);
        let mut calls = 0usize;
        Box::new(move || {
            calls += 1;
            // The first post is written and its acknowledgement is held by the
            // test below; the answer arrives at the second commit, the retry.
            if calls != 2 {
                return;
            }
            let destination = Allowance::parse(&destination(FIRST_IP)).expect("canonical");
            if let Some(sender) = sender
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_ref()
            {
                let _ = sender.send(PromptSignal::Answered {
                    entry_id: entry_id(&refusals, FIRST_IP),
                    count: 1,
                    destination,
                    suppress_destination: false,
                    observed_at: std_now(),
                });
            }
        }) as Box<dyn FnMut() + Send>
    };
    let mut bench = fixture.start_with(PromptMode::Immediate, Some(hook));
    *sender
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(bench.handle.signal_sender());

    let mut helper = bench.next_child().await;
    let first = helper.next_command().await;
    assert!(matches!(first, HelperCommand::Post { .. }), "{first:?}");
    // No acknowledgement: the banner is still unconfirmed, so the next round still
    // wants to post this attempt. That is where the answer lands.
    advance(2).await;

    let mut next_child = bench.next_child().await;
    let next = next_child.next_command().await;
    assert!(
        matches!(next, HelperCommand::Remove { .. }),
        "an attempt an answer disposed of must never be posted: {next:?}"
    );
    assert_eq!(
        id_of(&next),
        BANNER,
        "the removal reconciles the banner this session posted"
    );
    next_child.send(removed(seq_of(&next)));
    let quit = next_child.next_command().await;
    assert!(matches!(quit, HelperCommand::Quit { .. }), "{quit:?}");
}

// ---------------------------------------------------------------------------
// The teardown budget (F2)
// ---------------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn a_slow_acknowledgement_still_lets_finish_fold_and_post_the_final_snapshot() {
    // The operation in flight acknowledges at 1.8 s: inside `OP_ACK_TIMEOUT`
    // (2 s) but outside the old 1.5 s finish budget, which would have aborted the
    // driver before the fold, the final post and the graceful close.
    let mut bench = Bench::new(PromptMode::Immediate);
    bench.ingest(FIRST_IP, 1);
    let mut helper = bench.next_child().await;
    let post = helper.next_command().await;
    // A later count leaves the payload owed, so the final snapshot has something
    // to flush once the in-flight acknowledgement settles.
    bench.ingest(FIRST_IP, 2);
    let snapshot = bench.refusals.snapshot();
    tokio::join!(
        bench.handle.finish(snapshot, FinalWriteStatus::Persisted),
        async {
            settle().await;
            advance_for(Duration::from_secs(1)).await;
            advance_for(Duration::from_millis(800)).await;
            helper.send(posted(seq_of(&post), true));

            let final_post = helper.next_command().await;
            assert!(
                matches!(final_post, HelperCommand::Post { .. }),
                "the final snapshot is still flushed: {final_post:?}"
            );
            helper.send(posted(seq_of(&final_post), true));
            let quit = helper.next_command().await;
            assert!(matches!(quit, HelperCommand::Quit { .. }), "{quit:?}");
            advance_for(Duration::from_millis(500)).await;
        }
    );
}

// ---------------------------------------------------------------------------
// Reaping (F3)
// ---------------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn dropping_the_handle_closes_the_child_instead_of_aborting_the_driver() {
    let mut bench = Bench::new(PromptMode::Immediate);
    bench.ingest(FIRST_IP, 1);
    let mut helper = bench.next_child().await;
    let post = helper.next_command().await;
    helper.send(posted(seq_of(&post), true));
    settle().await;

    // A dropped handle asks the driver for the same bounded close `finish` uses,
    // so the child is quit, killed and reaped instead of being left to
    // `kill_on_drop`'s best effort.
    let handle = bench.handle;
    drop(handle);
    let quit = helper.next_command().await;
    assert!(matches!(quit, HelperCommand::Quit { .. }), "{quit:?}");
    helper.wait_reaped().await;
}

/// A backend over a real child that panics on its first read, so the driver's own
/// unwinding is the only thing left that can kill and reap the child.
struct PanickingRead {
    child: ChildHelperBackend,
}

impl HelperBackend for PanickingRead {
    fn write<'a>(&'a mut self, command: &'a HelperCommand) -> BoxFuture<'a, io::Result<()>> {
        self.child.write(command)
    }

    fn read(&mut self) -> BoxFuture<'_, io::Result<Option<HelperEvent>>> {
        panic!("a driver panic under test")
    }

    fn close_stdin(&mut self) -> BoxFuture<'_, ()> {
        self.child.close_stdin()
    }

    fn terminate(&mut self) -> BoxFuture<'_, ()> {
        self.child.terminate()
    }
}

struct RealChildSpawner {
    script: PathBuf,
    pids: mpsc::UnboundedSender<u32>,
}

impl HelperSpawner for RealChildSpawner {
    fn spawn(&self) -> BoxFuture<'static, io::Result<Box<dyn HelperBackend>>> {
        let script = self.script.clone();
        let pids = self.pids.clone();
        Box::pin(async move {
            let child = ChildHelperBackend::spawn(&script)?;
            if let Some(pid) = child.pid() {
                let _ = pids.send(pid);
            }
            Ok(Box::new(PanickingRead { child }) as Box<dyn HelperBackend>)
        })
    }
}

/// Whether `pid` still exists. A killed but unreaped child is a zombie and still
/// answers signal 0, so this is a *reaped* check and not merely a killed one.
fn exists(pid: u32) -> bool {
    // SAFETY: signal 0 is never delivered; it only asks the kernel whether this
    // process may signal that pid.
    (unsafe { libc::kill(pid as libc::pid_t, 0) }) == 0
}

/// A real child that ignores its `serve` argument and sleeps, so nothing but the
/// guard can end it.
fn sleeping_helper(root: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let script = root.join("agent-vm-notifier");
    std::fs::write(&script, "#!/bin/sh\nexec sleep 60\n").expect("a script");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
        .expect("an executable");
    script
}

#[cfg(unix)]
#[tokio::test]
async fn a_panicking_driver_kills_and_reaps_its_child() {
    let root = tempfile::tempdir().expect("a temp directory");
    let script = sleeping_helper(root.path());
    let fixture = Fixture::new();
    fixture.ingest(FIRST_IP, 1);
    let (hint, _lines) = Hint::capture_notifications_off();
    let (pids, mut pid_rx) = mpsc::unbounded_channel();
    let handle = NotifierHandle::start_with_spawner(
        DriverInputs {
            refusals: Arc::clone(&fixture.refusals),
            allowances: Arc::clone(&fixture.allowances),
            notifications_off: Arc::new(hint),
            meta: SessionMeta {
                project_hash: PROJECT_HASH.to_owned(),
                project_name: "demo".to_owned(),
                session_id: session(),
            },
            mode: PromptMode::Immediate,
            click: ClickUserInfo {
                session: SID.to_owned(),
                project: "/Users/me/proj".to_owned(),
                state_dir: "/Users/me/.local/state/agent-vm".to_owned(),
                terminal: "terminal".to_owned(),
            },
            before_commit: None,
        },
        Box::new(RealChildSpawner { script, pids }),
    );
    let pid = tokio::time::timeout(Duration::from_secs(10), pid_rx.recv())
        .await
        .expect("the driver spawns a child")
        .expect("a pid");

    // The driver panics on its first read, so the guard on the backend is the only
    // thing that can end this child, and a zombie would still answer signal 0.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while exists(pid) {
        assert!(
            std::time::Instant::now() < deadline,
            "the child is killed and reaped, not left running"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    drop(handle);
}

// ---------------------------------------------------------------------------
// The acknowledgement's id (F4)
// ---------------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn a_post_acknowledged_with_the_wrong_id_is_a_protocol_failure() {
    let mut bench = Bench::new(PromptMode::Immediate);
    bench.ingest(FIRST_IP, 1);
    let mut helper = bench.next_child().await;
    let seq = seq_of(&helper.next_command().await);
    helper.send(HelperEvent::Posted {
        v: PROTOCOL_VERSION,
        seq,
        id: "agent-vm.0f9a.elsewhere".to_owned(),
        ok: true,
        denied: false,
        error: String::new(),
    });
    settle().await;

    // Not an accept: the banner this driver speaks for is still unconfirmed, so
    // the owed post is written again and still names this session's banner.
    let retry = helper.next_command().await;
    assert!(matches!(retry, HelperCommand::Post { .. }), "{retry:?}");
    assert_eq!(id_of(&retry), BANNER, "the wrong id was never adopted");

    // And it was counted: a second mismatch retires the helper for this session.
    helper.send(HelperEvent::Posted {
        v: PROTOCOL_VERSION,
        seq: seq_of(&retry),
        id: "agent-vm.0f9a.elsewhere".to_owned(),
        ok: true,
        denied: false,
        error: String::new(),
    });
    settle().await;
    helper.wait_reaped().await;
}

#[tokio::test(start_paused = true)]
async fn a_remove_acknowledged_with_the_wrong_id_leaves_the_banner_ambiguous() {
    let mut bench = Bench::new(PromptMode::Immediate);
    bench.ingest(FIRST_IP, 1);
    let mut helper = bench.next_child().await;
    let post = helper.next_command().await;
    helper.send(posted(seq_of(&post), true));
    settle().await;
    bench.grant(FIRST_IP).await;
    let remove = helper.next_command().await;
    assert!(matches!(remove, HelperCommand::Remove { .. }), "{remove:?}");
    helper.send(HelperEvent::Removed {
        v: PROTOCOL_VERSION,
        seq: seq_of(&remove),
        id: "agent-vm.0f9a.elsewhere".to_owned(),
        ok: true,
    });
    settle().await;

    // `Absent` is only for a `removed` naming the banner this driver posted.
    // Anything else leaves the state unknown, so the reconcile is written again.
    advance(3).await;
    let again = helper.next_command().await;
    assert!(matches!(again, HelperCommand::Remove { .. }), "{again:?}");
    assert_eq!(id_of(&again), BANNER);
}

// ---------------------------------------------------------------------------
// The rules the mutation review left unpinned (F6)
// ---------------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn a_lagged_answer_wakeup_still_disposes_of_the_answered_attempt() {
    // `subscribe_answers` is a 16-slot channel that says so itself: a lagging
    // subscriber re-checks `answered()`. That re-check is the only thing that can
    // settle an answer the wakeup list no longer names.
    let fixture = Fixture::new();
    fixture.ingest(FIRST_IP, 1);
    let (mut bench, gate) = fixture.start_gated(PromptMode::Immediate);

    // Acknowledged once, so `AckedState` is `Present`: the removal below is owed.
    let mut helper = bench.next_child().await;
    gate.notify_one();
    let post = helper.next_command().await;
    helper.send(posted(seq_of(&post), true));
    settle().await;

    // A retry the refusal feed has not reported yet leaves a post owed, and the
    // child dying is what makes the next operation a fresh spawn.
    bench.ingest(FIRST_IP, 2);
    settle().await;
    helper.die();
    settle().await;

    // The retry (after the failure delay) is where the driver waits for a spawn.
    advance(4).await;
    let mut retry_child = bench.next_child().await;

    // The answer to *this* attempt, then more answers than the wakeup channel
    // holds while the driver waits in `ensure_spawn`. The answer to this one is
    // rotated out of the ring, so the wakeups the driver finally reads name only
    // other destinations: `answered()` is the only thing left that can settle it.
    bench.grant(FIRST_IP).await;
    for host in 1..=20 {
        bench.grant(&format!("198.51.100.{host}")).await;
    }
    gate.notify_one();
    settle().await;

    let retry = retry_child.next_command().await;
    assert!(matches!(retry, HelperCommand::Post { .. }), "{retry:?}");
    // Acknowledged, so the driver is not retired by its own failure count: the
    // answered attempt is what the next operation has to reconcile.
    retry_child.send(posted(seq_of(&retry), true));
    settle().await;
    let next = retry_child.next_command().await;
    assert!(
        matches!(next, HelperCommand::Remove { .. }),
        "the answer set, not the wakeup list, disposes of it: {next:?}"
    );
    assert_eq!(id_of(&next), BANNER);
}

#[tokio::test(start_paused = true)]
async fn a_post_the_helper_rejected_is_never_a_banner_and_is_retried() {
    let mut bench = Bench::new(PromptMode::Immediate);
    bench.ingest(FIRST_IP, 1);
    let mut helper = bench.next_child().await;
    let seq = seq_of(&helper.next_command().await);
    helper.send(posted(seq, false));
    settle().await;

    // `Present` is only for `posted { ok: true }`: a rejection leaves the banner
    // unknown, so the coalescer still owes it and the driver writes it again.
    advance(3).await;
    let retry = helper.next_command().await;
    assert!(matches!(retry, HelperCommand::Post { .. }), "{retry:?}");
    assert_eq!(id_of(&retry), BANNER);
}

#[tokio::test(start_paused = true)]
async fn one_cleanup_spawn_per_idle_period_even_when_the_driver_wakes() {
    let mut bench = Bench::new(PromptMode::Immediate);
    bench.ingest(FIRST_IP, 1);
    let mut helper = bench.next_child().await;
    let post = helper.next_command().await;
    helper.send(posted(seq_of(&post), true));
    settle().await;

    // Idle: the helper is quit and the banner is left showing, so exactly one
    // cleanup-only spawn is armed for the next removal that is owed.
    advance(31).await;
    let quit = helper.next_command().await;
    assert!(matches!(quit, HelperCommand::Quit { .. }), "{quit:?}");
    helper.wait_reaped().await;

    // The answer arrives while idle: the removal is written by that one cleanup
    // spawn, whose acknowledgement never comes.
    bench.grant(FIRST_IP).await;
    let mut cleanup = bench.next_child().await;
    let remove = cleanup.next_command().await;
    assert!(matches!(remove, HelperCommand::Remove { .. }), "{remove:?}");
    let quit = cleanup.next_command().await;
    assert!(matches!(quit, HelperCommand::Quit { .. }), "{quit:?}");
    cleanup.wait_reaped().await;

    // Another wakeup in the same idle period must not spawn again: the banner may
    // still exist, so without the single-spawn guard every pass would.
    let entry = bench.entry_id(FIRST_IP);
    bench.signal(PromptSignal::Shown {
        entry_id: entry,
        count: 1,
        observed_at: super::std_now(),
    });
    settle().await;
    advance(60).await;
    assert!(
        bench.spawned.try_recv().is_err(),
        "exactly one cleanup-only spawn per idle period"
    );
}

// ---------------------------------------------------------------------------
// The permission dialog (Phase 6's protocol decision, S1/B6)
// ---------------------------------------------------------------------------

/// The helper emits `auth` twice: `notDetermined` while a human-paced dialog is
/// up, then the settled status. While it is up the driver writes nothing, so no
/// acknowledgement timer runs and no failure is counted — the whole rule, from
/// the driver's side of the wire.
#[tokio::test(start_paused = true)]
async fn a_pending_authorization_holds_the_post_and_counts_no_failure() {
    let mut bench = Bench::new(PromptMode::Immediate);
    bench.ingest(FIRST_IP, 1);
    let mut helper = bench.next_child().await;
    let post = helper.next_command().await;
    assert!(matches!(post, HelperCommand::Post { .. }), "{post:?}");

    // The dialog is up: the first post was written before this driver could know,
    // so it is abandoned rather than blamed.
    helper.send(auth("notDetermined"));
    settle().await;

    // A minute of a dialog nobody answers yet: no post, no remove, no quit, and no
    // kill — a counted timeout would have terminated the child holding the dialog.
    advance(60).await;
    assert!(
        helper.try_command().is_none(),
        "nothing is written while the dialog is up"
    );
    assert!(!helper.was_killed(), "the wait counts no failure");
    assert!(
        bench.spawned.try_recv().is_err(),
        "and therefore spawns no replacement"
    );

    // Settled `authorized`: the owed refusal is posted, on the same child, because
    // the coalescer kept it and nothing was counted against the helper.
    helper.send(auth("authorized"));
    settle().await;
    let retry = helper.next_command().await;
    assert!(matches!(retry, HelperCommand::Post { .. }), "{retry:?}");
    let text = banner_text(&retry);
    assert!(text.contains(FIRST_IP), "{text}");

    // And the session is healthy: the banner is acked and a later answer removes
    // it, so the wait left nothing behind.
    helper.send(posted(seq_of(&retry), true));
    settle().await;
    bench.grant(FIRST_IP).await;
    let remove = helper.next_command().await;
    assert!(matches!(remove, HelperCommand::Remove { .. }), "{remove:?}");
    assert_eq!(id_of(&remove), BANNER);
}

#[tokio::test(start_paused = true)]
async fn a_pending_authorization_that_settles_denied_fires_the_hint_once() {
    let mut bench = Bench::new(PromptMode::Immediate);
    bench.ingest(FIRST_IP, 1);
    let mut helper = bench.next_child().await;
    assert!(matches!(
        helper.next_command().await,
        HelperCommand::Post { .. }
    ));
    helper.send(auth("notDetermined"));
    settle().await;
    advance(60).await;
    assert!(helper.try_command().is_none());

    // Settled `denied` takes the existing path: the session's hint, once.
    helper.send(auth("denied"));
    settle().await;
    assert_eq!(bench.lines(), vec![NOTIFICATIONS_OFF.to_owned()]);
    helper.send(auth("denied"));
    settle().await;
    assert_eq!(bench.lines().len(), 1, "{:?}", bench.lines());

    // And posting has stopped for the session. The one command that may still
    // follow the denial is the reconcile of the banner the interrupted post left
    // unknown — never a post, however many refusals arrive afterwards.
    bench.ingest(OTHER_IP, 1);
    settle().await;
    advance(60).await;
    while let Some(command) = helper.try_command() {
        assert!(
            !matches!(command, HelperCommand::Post { .. }),
            "a denied session posts nothing more: {command:?}"
        );
    }
}

/// The fail-open control: only an explicit `notDetermined` may hold a post back,
/// so a helper that never mentions authorization — an older build, or one that
/// died before asking — behaves exactly as before.
#[tokio::test(start_paused = true)]
async fn a_helper_that_never_sends_auth_still_posts() {
    let mut bench = Bench::new(PromptMode::Immediate);
    bench.ingest(FIRST_IP, 1);
    let mut helper = bench.next_child().await;
    let post = helper.next_command().await;
    assert!(matches!(post, HelperCommand::Post { .. }), "{post:?}");
    let text = banner_text(&post);
    assert!(text.contains(FIRST_IP), "{text}");
    helper.send(posted(seq_of(&post), true));

    // A later refusal still posts, a minute after a spawn whose `auth` never came:
    // absence gates nothing, however long it lasts.
    bench.ingest(OTHER_IP, 1);
    settle().await;
    advance(60).await;
    let second = helper.next_command().await;
    assert!(matches!(second, HelperCommand::Post { .. }), "{second:?}");
    let text = banner_text(&second);
    assert!(text.contains(OTHER_IP), "{text}");
}

/// A dialog nobody ever answers must neither wedge the intake nor accumulate work:
/// the driver stays event-driven while the phase is open, keeps folding refusals,
/// and posts exactly what it folded when the answer finally comes.
#[tokio::test(start_paused = true)]
async fn a_pending_authorization_that_never_settles_keeps_the_intake_live() {
    let mut bench = Bench::new(PromptMode::Immediate);
    bench.ingest(FIRST_IP, 1);
    let mut helper = bench.next_child().await;
    assert!(matches!(
        helper.next_command().await,
        HelperCommand::Post { .. }
    ));
    helper.send(auth("notDetermined"));
    settle().await;

    // Ten minutes with the dialog up: the only wakeups are events, so there is
    // nothing to write and nothing that grows per pass.
    for _ in 0..10 {
        advance(60).await;
    }
    assert!(helper.try_command().is_none(), "no command in ten minutes");
    assert!(!helper.was_killed(), "no failure, so no kill");
    assert!(bench.spawned.try_recv().is_err(), "no respawn");

    // The intake is live: a refusal, a prompt signal and an answer that arrives
    // mid-dialog are all folded, and the settled post speaks for what survived.
    bench.ingest(OTHER_IP, 1);
    let entry = bench.entry_id(FIRST_IP);
    bench.signal(PromptSignal::Shown {
        entry_id: entry,
        count: 1,
        observed_at: super::std_now(),
    });
    settle().await;
    assert!(helper.try_command().is_none(), "still nothing written");

    helper.send(auth("authorized"));
    settle().await;
    let post = helper.next_command().await;
    assert!(matches!(post, HelperCommand::Post { .. }), "{post:?}");
    let text = banner_text(&post);
    assert!(text.contains(FIRST_IP), "{text}");
    assert!(text.contains(OTHER_IP), "{text}");
    assert!(
        helper.try_command().is_none(),
        "one post for what was folded, not one per pump"
    );
}

/// The phase arms no timer at all, and that is asserted on the driver's own
/// deadline rather than through a test's clock: the coalescer reports
/// already-due work as `now`, so a driver that recomputed its timer while the
/// dialog is up would spin the loop for as long as the operator takes. A paused
/// clock cannot show a spin, so the rule is pinned where it lives.
#[tokio::test(start_paused = true)]
async fn a_pending_authorization_arms_no_timer_even_when_work_is_due() {
    let fixture = Fixture::new();
    fixture.ingest(FIRST_IP, 1);
    let (signals, signal_rx) = mpsc::unbounded_channel();
    let (_requests, requests) = mpsc::unbounded_channel();
    let (spawned, _spawned_rx) = mpsc::unbounded_channel();
    let (inputs, _lines) = fixture.inputs(PromptMode::AfterPromptGrace, None);
    let mut driver = Driver::new(
        inputs,
        signal_rx,
        Box::new(FakeSpawner { spawned }),
        requests,
    );
    // A question became visible ten seconds ago, so its grace is long expired: the
    // coalescer has work that is already due and would ask for a timer at once.
    signals
        .send(PromptSignal::Shown {
            entry_id: entry_id(&fixture.refusals, FIRST_IP),
            count: 1,
            observed_at: std_now() - Duration::from_secs(10),
        })
        .expect("the driver's signal channel");
    driver.drain_intake();
    assert!(
        driver.coalescer.next_deadline(std_now()).is_some(),
        "the work this test needs is the work that is already due"
    );

    driver.authorization(true);
    assert!(
        driver.deadline().is_none(),
        "a phase with no timeout arms no timer: {:?}",
        driver.deadline()
    );
}

/// Teardown obeys the same silence: a final flush while the dialog is up would be
/// answered `ok: false` by the helper, and no banner may claim durability that
/// permission has not allowed.
#[tokio::test(start_paused = true)]
async fn a_teardown_while_authorization_is_pending_writes_only_the_quit() {
    let mut bench = Bench::new(PromptMode::Immediate);
    bench.ingest(FIRST_IP, 1);
    let mut helper = bench.next_child().await;
    assert!(matches!(
        helper.next_command().await,
        HelperCommand::Post { .. }
    ));
    helper.send(auth("notDetermined"));
    settle().await;
    bench.ingest(OTHER_IP, 1);
    let snapshot = bench.refusals.snapshot();
    tokio::join!(
        bench.handle.finish(snapshot, FinalWriteStatus::Persisted),
        async {
            let quit = helper.next_command().await;
            assert!(
                matches!(quit, HelperCommand::Quit { .. }),
                "the dialog is up, so nothing may be posted: {quit:?}"
            );
            assert!(helper.try_command().is_none(), "and nothing follows it");
        }
    );
}

// ---------------------------------------------------------------------------
// The reader's boundaries (F5)
// ---------------------------------------------------------------------------

/// A valid frame whose `error` field is padded so the frame, without its
/// newline, is exactly [`MAX_HELPER_LINE_BYTES`].
const FRAME_PREFIX: &[u8] = br##"{"v":1,"type":"open_failed","session":"3f9a12c4","error":""##;
const FRAME_SUFFIX: &[u8] = br#""}"#;
const FRAME_PAD: usize = MAX_HELPER_LINE_BYTES - FRAME_PREFIX.len() - FRAME_SUFFIX.len();

fn frame_of_length(len: usize) -> Vec<u8> {
    let pad = len - FRAME_PREFIX.len() - FRAME_SUFFIX.len();
    let mut frame = Vec::with_capacity(len + 1);
    frame.extend_from_slice(FRAME_PREFIX);
    frame.extend(std::iter::repeat_n(b'x', pad));
    frame.extend_from_slice(FRAME_SUFFIX);
    frame.push(b'\n');
    assert_eq!(frame.len(), len + 1);
    frame
}

#[tokio::test]
async fn a_frame_of_exactly_sixteen_kibibytes_is_read() {
    // The cap is a maximum, not a trigger: `>` rather than `>=` is the whole rule.
    let mut frames = Frames::from_bytes(frame_of_length(MAX_HELPER_LINE_BYTES));
    match frames.next().await.expect("no read error") {
        Some(HelperEvent::OpenFailed { session, error, .. }) => {
            assert_eq!(session, SID);
            assert_eq!(error.len(), FRAME_PAD, "the frame is 16 KiB, not truncated");
        }
        other => panic!("a 16 KiB frame is a frame: {other:?}"),
    }
    assert_eq!(frames.next().await.expect("EOF is not an error"), None);
}

#[tokio::test]
async fn an_oversize_frame_is_skipped_and_the_reader_resynchronizes() {
    let mut bytes = vec![b'x'; MAX_HELPER_LINE_BYTES * 2];
    bytes.push(b'\n');
    bytes.extend_from_slice(b"{\"v\":1,\"type\":\"stdin_closed\"}\n");
    let mut frames = Frames::from_bytes(bytes);
    assert_eq!(
        frames.next().await.expect("no read error"),
        Some(HelperEvent::StdinClosed {
            v: PROTOCOL_VERSION
        }),
        "the frame after an oversize one still arrives"
    );
    assert_eq!(frames.next().await.expect("EOF is not an error"), None);
}

#[tokio::test]
async fn invalid_json_is_skipped() {
    let mut bytes = b"not a frame at all\n{\"v\":1,\n\0\0\0\n".to_vec();
    bytes.extend_from_slice(b"{\"v\":1,\"type\":\"stdin_closed\"}\n");
    let mut frames = Frames::from_bytes(bytes);
    assert_eq!(
        frames.next().await.expect("no read error"),
        Some(HelperEvent::StdinClosed {
            v: PROTOCOL_VERSION
        })
    );
    assert_eq!(frames.next().await.expect("EOF is not an error"), None);
}

#[tokio::test]
async fn an_unknown_event_type_is_reported_as_unknown() {
    // A newer helper must not break an older launcher: the frame decodes to
    // `Unknown`, and the next one still arrives.
    let mut bytes = b"{\"v\":1,\"type\":\"measured\",\"rss\":7}\n".to_vec();
    bytes.extend_from_slice(b"{\"v\":1,\"type\":\"stdin_closed\"}\n");
    let mut frames = Frames::from_bytes(bytes);
    assert_eq!(
        frames.next().await.expect("no read error"),
        Some(HelperEvent::Unknown)
    );
    assert_eq!(
        frames.next().await.expect("no read error"),
        Some(HelperEvent::StdinClosed {
            v: PROTOCOL_VERSION
        })
    );
    assert_eq!(frames.next().await.expect("EOF is not an error"), None);
}

#[tokio::test]
async fn a_frame_with_the_wrong_version_is_skipped() {
    let mut bytes = b"{\"v\":2,\"type\":\"stdin_closed\"}\n".to_vec();
    bytes.extend_from_slice(b"{\"v\":1,\"type\":\"stdin_closed\"}\n");
    let mut frames = Frames::from_bytes(bytes);
    assert_eq!(
        frames.next().await.expect("no read error"),
        Some(HelperEvent::StdinClosed {
            v: PROTOCOL_VERSION
        })
    );
    assert_eq!(frames.next().await.expect("EOF is not an error"), None);
}

#[tokio::test]
async fn a_truncated_final_line_is_dropped_at_eof() {
    // Nothing can tell whether the rest would have made it a frame, so it is
    // dropped rather than half-decoded; the complete frame before it still counts.
    let mut bytes = b"{\"v\":1,\"type\":\"stdin_closed\"}\n".to_vec();
    bytes.extend_from_slice(br#"{"v":1,"type":"posted","seq":1,"id":"x""#);
    let mut frames = Frames::from_bytes(bytes);
    assert_eq!(
        frames.next().await.expect("no read error"),
        Some(HelperEvent::StdinClosed {
            v: PROTOCOL_VERSION
        })
    );
    assert_eq!(frames.next().await.expect("EOF is not an error"), None);
    // And a stream that never held a newline is EOF immediately.
    let mut truncated = Frames::from_bytes(br#"{"v":1,"type":"posted","seq":1"#.to_vec());
    assert_eq!(truncated.next().await.expect("EOF is not an error"), None);
}

// ---------------------------------------------------------------------------
// The child-process contract (Phase 7, S6)
// ---------------------------------------------------------------------------

/// The production [`ChildHelperBackend`] over **real pipes**, against
/// `harness fake-notifier`: the independent NDJSON v1 oracle (ADR-0072), so the
/// launcher cannot drift from the wire and still pass.
///
/// Ignored by default because it needs the harness binary: the units shard of
/// `script/test/ci-test-shard.sh` builds it, exports `HARNESS_BIN_DIR` and runs
/// this filter with `--ignored`. Every test here **fails** when the binary is
/// missing — a contract that cannot run is not a pass.
///
/// The wire-level tests hold the backend directly. The four driver-level ones
/// (`a_cleanup_only_spawn_…`, `nothing_posted_…`, `dropping_the_handle_…`,
/// `cancelling_the_driver_…`) run the production driver over the same backend,
/// on a real clock: their timers (2 s acknowledgement, 30 s idle) are real ones.
mod child_contract {
    use std::os::unix::fs::PermissionsExt as _;

    use serde_json::{Value, json};

    use super::*;

    /// One operand, safe for `/bin/sh`: single-quoted, with any quote inside
    /// closed and reopened.
    fn quoted(path: &Path) -> String {
        format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
    }

    /// `$HARNESS_BIN_DIR/harness`, or a failure: the shard builds it, so a test
    /// that cannot find it must not pass quietly.
    fn harness_binary() -> PathBuf {
        let dir = std::env::var_os("HARNESS_BIN_DIR").unwrap_or_else(|| {
            panic!(
                "HARNESS_BIN_DIR is not set: it must name the directory holding the harness \
                 binary (cargo build --locked -p agent-vm-harness --bins), and \
                 script/test/ci-test-shard.sh exports it on the units shard"
            )
        });
        let path = PathBuf::from(dir).join("harness");
        assert!(
            path.is_file(),
            "no harness binary at {}: run cargo build --locked -p agent-vm-harness --bins",
            crate::one_line::path(&path)
        );
        path
    }

    /// One oracle scenario, and the runs it played.
    ///
    /// The backend always spawns `<binary> serve`, so the binary it is given is a
    /// one-line wrapper: it records that a run started, hands the oracle its
    /// scenario, and passes the backend's own argv through. Each run's verdict goes
    /// to `verdict.<pid>`, which keeps two runs of the same scenario apart — and a
    /// scenario with no verdict is a run that was killed before it could report.
    struct Oracle {
        root: tempfile::TempDir,
        wrapper: PathBuf,
    }

    impl Oracle {
        fn new(scenario: &str) -> Self {
            let root = tempfile::tempdir().expect("a temp directory");
            let dir = root.path();
            std::fs::write(dir.join("scenario.json"), scenario).expect("a scenario file");
            let wrapper = dir.join("fake-notifier");
            let script = format!(
                "#!/bin/sh\n\
                 : > {dir}/started.$$\n\
                 exec {harness} fake-notifier --scenario {scenario} --verdict {dir}/verdict.$$ \"$@\"\n",
                dir = quoted(dir),
                harness = quoted(&harness_binary()),
                scenario = quoted(&dir.join("scenario.json")),
            );
            std::fs::write(&wrapper, script).expect("a wrapper script");
            std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755))
                .expect("an executable wrapper");
            Self { root, wrapper }
        }

        /// The production backend, over this oracle.
        fn spawn(&self) -> ChildHelperBackend {
            ChildHelperBackend::for_binary(&self.wrapper).expect("the oracle binary is spawnable")
        }

        /// How many runs started, whether or not they finished.
        fn starts(&self) -> usize {
            self.named("started.")
        }

        /// The verdicts of the runs that ended on their own. The order is the file
        /// order (by pid), so no test may depend on it.
        fn verdicts(&self) -> Vec<Value> {
            let mut paths = self.paths("verdict.");
            paths.sort();
            paths
                .iter()
                .map(|path| {
                    let text = std::fs::read_to_string(path).unwrap_or_else(|error| {
                        panic!("reading {}: {error}", crate::one_line::path(path))
                    });
                    serde_json::from_str(&text).unwrap_or_else(|error| {
                        panic!("{} is not JSON: {error}", crate::one_line::path(path))
                    })
                })
                .collect()
        }

        fn named(&self, prefix: &str) -> usize {
            self.paths(prefix).len()
        }

        fn paths(&self, prefix: &str) -> Vec<PathBuf> {
            std::fs::read_dir(self.root.path())
                .expect("the scenario directory")
                .map(|entry| entry.expect("a directory entry").path())
                .filter(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with(prefix))
                })
                .collect()
        }
    }

    /// The production backend with the child's pid recorded, so a test can watch
    /// the reap from outside. Every method is the production one.
    struct RecordingBackend {
        child: ChildHelperBackend,
    }

    impl HelperBackend for RecordingBackend {
        fn write<'a>(&'a mut self, command: &'a HelperCommand) -> BoxFuture<'a, io::Result<()>> {
            self.child.write(command)
        }

        fn read(&mut self) -> BoxFuture<'_, io::Result<Option<HelperEvent>>> {
            self.child.read()
        }

        fn close_stdin(&mut self) -> BoxFuture<'_, ()> {
            self.child.close_stdin()
        }

        fn terminate(&mut self) -> BoxFuture<'_, ()> {
            self.child.terminate()
        }
    }

    struct RecordingSpawner {
        binary: PathBuf,
        pids: mpsc::UnboundedSender<u32>,
    }

    impl HelperSpawner for RecordingSpawner {
        fn spawn(&self) -> BoxFuture<'static, io::Result<Box<dyn HelperBackend>>> {
            let binary = self.binary.clone();
            let pids = self.pids.clone();
            Box::pin(async move {
                let child = ChildHelperBackend::for_binary(&binary)?;
                if let Some(pid) = child.pid() {
                    let _ = pids.send(pid);
                }
                Ok(Box::new(RecordingBackend { child }) as Box<dyn HelperBackend>)
            })
        }
    }

    /// The next frame, or a named failure: no assertion here can hang.
    async fn read(helper: &mut ChildHelperBackend) -> HelperEvent {
        tokio::time::timeout(Duration::from_secs(10), helper.read())
            .await
            .expect("the oracle answers within ten seconds")
            .expect("no read error")
            .expect("a frame, not end-of-file")
    }

    /// Nothing arrives in `wait`, and the cancelled read loses nothing.
    async fn silence(helper: &mut ChildHelperBackend, wait: Duration, why: &str) {
        assert!(
            tokio::time::timeout(wait, helper.read()).await.is_err(),
            "{why}"
        );
    }

    async fn launched(helper: &mut ChildHelperBackend) {
        match read(helper).await {
            HelperEvent::Launched { v, serving, .. } => {
                assert_eq!(v, PROTOCOL_VERSION);
                assert!(
                    serving,
                    "the wrapper passes the helper's own `serve` through"
                );
            }
            other => panic!("the first frame is `launched`, not {other:?}"),
        }
    }

    /// The status and `granted` flag of the next frame.
    async fn auth(helper: &mut ChildHelperBackend) -> (String, bool) {
        match read(helper).await {
            HelperEvent::Auth {
                v, status, granted, ..
            } => {
                assert_eq!(v, PROTOCOL_VERSION);
                (status, granted)
            }
            other => panic!("expected `auth`, got {other:?}"),
        }
    }

    fn payload() -> NotificationPayload {
        NotificationPayload {
            id: BANNER.to_owned(),
            thread: format!("agent-vm.{PROJECT_HASH}"),
            title: "1 refusal".to_owned(),
            subtitle: format!("demo · session {SID}"),
            body: format!("tcp://[{FIRST_IP}/32]:443"),
            passive: false,
        }
    }

    fn click() -> ClickUserInfo {
        ClickUserInfo {
            session: SID.to_owned(),
            project: "/Users/me/proj".to_owned(),
            state_dir: "/Users/me/.local/state/agent-vm".to_owned(),
            terminal: "terminal".to_owned(),
        }
    }

    /// Write one `post` and return the frame it earned.
    async fn post(helper: &mut ChildHelperBackend, seq: u64) -> HelperEvent {
        helper
            .write(&HelperCommand::post(seq, &payload(), &click()))
            .await
            .expect("the oracle reads the post");
        read(helper).await
    }

    /// Write one `remove` and return the frame it earned.
    async fn remove(helper: &mut ChildHelperBackend, seq: u64) -> HelperEvent {
        helper
            .write(&HelperCommand::remove(seq, BANNER))
            .await
            .expect("the oracle reads the remove");
        read(helper).await
    }

    /// `quit`, drop stdin, wait for the child to go. The oracle writes its verdict
    /// before it exits, so the verdict is there afterwards.
    async fn quit(helper: &mut ChildHelperBackend) {
        helper
            .write(&HelperCommand::quit())
            .await
            .expect("the oracle reads the quit");
        helper.close_stdin().await;
        assert_eq!(
            helper.read().await.expect("no read error"),
            None,
            "`quit` ends the oracle's stdout"
        );
        helper.terminate().await;
    }

    /// The one verdict of a run that was closed with [`quit`].
    fn verdict(oracle: &Oracle) -> Value {
        let verdicts = oracle.verdicts();
        assert_eq!(verdicts.len(), 1, "one run, one verdict: {verdicts:?}");
        let verdict = verdicts.into_iter().next().expect("one verdict");
        assert_eq!(verdict["ok"], json!(true), "{verdict}");
        assert_eq!(verdict["violations"], json!([]), "{verdict}");
        verdict
    }

    /// Poll `done` for a real child, whose timing no virtual clock can move.
    async fn eventually(what: &str, mut done: impl FnMut() -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !done() {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for {what}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn next_pid(pids: &mut mpsc::UnboundedReceiver<u32>) -> u32 {
        tokio::time::timeout(Duration::from_secs(10), pids.recv())
            .await
            .expect("the driver spawns the oracle within ten seconds")
            .expect("a live helper")
    }

    /// The driver over the real oracle, with the child's pid observed.
    fn start(fixture: &Fixture, oracle: &Oracle) -> (NotifierHandle, mpsc::UnboundedReceiver<u32>) {
        let (pids_tx, pids) = mpsc::unbounded_channel();
        let (inputs, _lines) = fixture.inputs(PromptMode::Immediate, None);
        let handle = NotifierHandle::start_with_spawner(
            inputs,
            Box::new(RecordingSpawner {
                binary: oracle.wrapper.clone(),
                pids: pids_tx,
            }),
        );
        (handle, pids)
    }

    // -- the wire ----------------------------------------------------------

    #[ignore = "needs the harness binary: script/test/ci-test-shard.sh runs it"]
    #[tokio::test]
    async fn a_full_transcript_has_zero_violations() {
        let oracle = Oracle::new(r#"{"expect":{"violations":0,"ops":["post","remove","quit"]}}"#);
        let mut helper = oracle.spawn();
        launched(&mut helper).await;
        assert_eq!(
            auth(&mut helper).await,
            ("authorized".to_owned(), true),
            "the settled status a first-run operator gives"
        );

        match post(&mut helper, 1).await {
            HelperEvent::Posted {
                v,
                seq,
                id,
                ok,
                denied,
                error,
            } => {
                assert_eq!(v, PROTOCOL_VERSION);
                assert_eq!(seq, 1, "the oracle echoes the sequence it was given");
                assert_eq!(id, BANNER, "and the banner the command named");
                assert!(ok, "an honest add: {error}");
                assert!(!denied);
            }
            other => panic!("expected `posted`, got {other:?}"),
        }
        match remove(&mut helper, 2).await {
            HelperEvent::Removed { v, seq, id, ok } => {
                assert_eq!(v, PROTOCOL_VERSION);
                assert_eq!(seq, 2, "the sequence keeps increasing across operations");
                assert_eq!(id, BANNER);
                assert!(ok);
            }
            other => panic!("expected `removed`, got {other:?}"),
        }
        quit(&mut helper).await;

        let verdict = verdict(&oracle);
        assert_eq!(
            verdict["sequence"],
            json!(["post", "remove", "quit"]),
            "the oracle accepted exactly the operations the driver wrote: {verdict}"
        );
    }

    #[ignore = "needs the harness binary: script/test/ci-test-shard.sh runs it"]
    #[tokio::test]
    async fn a_malformed_answer_is_skipped_and_the_reader_resynchronizes() {
        let oracle = Oracle::new(
            r#"{"ops":{"post":{"emit":"malformed"}},"expect":{"ops":["post","remove","quit"]}}"#,
        );
        let mut helper = oracle.spawn();
        launched(&mut helper).await;
        auth(&mut helper).await;

        helper
            .write(&HelperCommand::post(1, &payload(), &click()))
            .await
            .expect("the oracle reads the post");
        // A truncated line is not a frame: it is skipped, never reported as one,
        // and the reader keeps waiting rather than failing the operation early.
        silence(
            &mut helper,
            Duration::from_millis(250),
            "a truncated answer is skipped, never returned",
        )
        .await;
        // And the stream resynchronizes: the next real frame still lands.
        match remove(&mut helper, 2).await {
            HelperEvent::Removed { seq, ok, .. } => {
                assert_eq!(seq, 2);
                assert!(ok);
            }
            other => panic!("the reader did not resynchronize: {other:?}"),
        }
        quit(&mut helper).await;
        verdict(&oracle);
    }

    #[ignore = "needs the harness binary: script/test/ci-test-shard.sh runs it"]
    #[tokio::test]
    async fn an_oversize_answer_is_skipped_without_buffering_it() {
        let oracle = Oracle::new(
            r#"{"ops":{"post":{"emit":"oversize"}},"expect":{"ops":["post","remove","quit"]}}"#,
        );
        let mut helper = oracle.spawn();
        launched(&mut helper).await;
        auth(&mut helper).await;

        helper
            .write(&HelperCommand::post(1, &payload(), &click()))
            .await
            .expect("the oracle reads the post");
        // One frame longer than the 16 KiB cap: the reader drops it and keeps
        // reading, so neither the frame nor the buffer behind it reaches a caller.
        silence(
            &mut helper,
            Duration::from_millis(250),
            "an oversize answer is skipped, never returned",
        )
        .await;
        match remove(&mut helper, 2).await {
            HelperEvent::Removed { seq, ok, .. } => {
                assert_eq!(seq, 2);
                assert!(ok);
            }
            other => panic!("the reader did not resynchronize: {other:?}"),
        }
        quit(&mut helper).await;
        verdict(&oracle);
    }

    #[ignore = "needs the harness binary: script/test/ci-test-shard.sh runs it"]
    #[tokio::test]
    async fn an_answer_with_the_wrong_version_is_skipped() {
        let oracle = Oracle::new(
            r#"{"ops":{"post":{"emit":"bad_version"}},"expect":{"ops":["post","remove","quit"]}}"#,
        );
        let mut helper = oracle.spawn();
        launched(&mut helper).await;
        auth(&mut helper).await;

        helper
            .write(&HelperCommand::post(1, &payload(), &click()))
            .await
            .expect("the oracle reads the post");
        // `v: 2` is a frame this build does not speak, so it is neither an
        // acknowledgement nor an error.
        silence(
            &mut helper,
            Duration::from_millis(250),
            "a frame from another protocol version is skipped, never returned",
        )
        .await;
        match remove(&mut helper, 2).await {
            HelperEvent::Removed { seq, ok, .. } => {
                assert_eq!(seq, 2);
                assert!(ok);
            }
            other => panic!("the reader did not skip past it: {other:?}"),
        }
        quit(&mut helper).await;
        verdict(&oracle);
    }

    #[ignore = "needs the harness binary: script/test/ci-test-shard.sh runs it"]
    #[tokio::test]
    async fn a_missing_acknowledgement_leaves_the_operation_to_the_drivers_timer() {
        let oracle = Oracle::new(r#"{"ops":{"post":{"emit":"none"}},"expect":{"ops":["post"]}}"#);
        let mut helper = oracle.spawn();
        launched(&mut helper).await;
        auth(&mut helper).await;

        helper
            .write(&HelperCommand::post(1, &payload(), &click()))
            .await
            .expect("the oracle reads the post");
        // The oracle accepted the command and stays silent: nothing on the wire can
        // settle this operation, which is why `OP_ACK_TIMEOUT` has to.
        silence(
            &mut helper,
            Duration::from_millis(250),
            "the oracle accepted the post and answered nothing",
        )
        .await;
        let pid = helper.pid().expect("the child is still running");
        assert!(
            exists(pid),
            "a silent helper is left alive, not killed by the reader"
        );
        helper.terminate().await;
        assert!(!exists(pid), "terminate kills and reaps it");
    }

    #[ignore = "needs the harness binary: script/test/ci-test-shard.sh runs it"]
    #[tokio::test]
    async fn a_delayed_authorization_arrives_after_launched() {
        let oracle = Oracle::new(r#"{"auth":{"delay_ms":600}}"#);
        let mut helper = oracle.spawn();
        launched(&mut helper).await;
        // 600 ms behind `launched`, so the first read cannot have it: the frame is
        // its own read, which is what makes a cancelled read safe to retry.
        silence(
            &mut helper,
            Duration::from_millis(200),
            "the auth frame is delayed past the first read",
        )
        .await;
        assert_eq!(auth(&mut helper).await, ("authorized".to_owned(), true));
        helper.terminate().await;
    }

    #[ignore = "needs the harness binary: script/test/ci-test-shard.sh runs it"]
    #[tokio::test]
    async fn a_helper_that_never_answers_authorization_still_serves_operations() {
        let oracle = Oracle::new(r#"{"auth":{"emit":"none"},"expect":{"ops":["post","quit"]}}"#);
        let mut helper = oracle.spawn();
        launched(&mut helper).await;
        silence(
            &mut helper,
            Duration::from_millis(250),
            "this helper never sends `auth`: its absence is the control",
        )
        .await;
        // Nothing on the wire gates a post, so the launcher's own fail-open rule is
        // the only thing that could — and it posts.
        match post(&mut helper, 1).await {
            HelperEvent::Posted { seq, ok, .. } => {
                assert_eq!(seq, 1);
                assert!(ok);
            }
            other => panic!("expected `posted`, got {other:?}"),
        }
        quit(&mut helper).await;
        let verdict = verdict(&oracle);
        assert_eq!(
            verdict["events"],
            json!(["launched", "posted:1"]),
            "no `auth` was ever emitted: {verdict}"
        );
    }

    #[ignore = "needs the harness binary: script/test/ci-test-shard.sh runs it"]
    #[tokio::test]
    async fn a_backpressured_stdin_still_takes_the_writes_and_their_acks() {
        let oracle = Oracle::new(
            r#"{"stdin":{"pause_after_ops":1,"pause_ms":400},"expect":{"ops":["post","remove","quit"]}}"#,
        );
        let mut helper = oracle.spawn();
        launched(&mut helper).await;
        auth(&mut helper).await;

        let started = std::time::Instant::now();
        assert!(matches!(
            post(&mut helper, 1).await,
            HelperEvent::Posted { ok: true, .. }
        ));
        // The oracle stops reading after that command for 400 ms: the remove is
        // written into a pipe nobody is draining, and it is still read afterwards.
        match remove(&mut helper, 2).await {
            HelperEvent::Removed { seq, ok, .. } => {
                assert_eq!(seq, 2);
                assert!(ok);
            }
            other => panic!("expected `removed`, got {other:?}"),
        }
        assert!(
            started.elapsed() >= Duration::from_millis(300),
            "the second acknowledgement waited for the reader's pause, not a shortcut: {:?}",
            started.elapsed()
        );
        quit(&mut helper).await;
        verdict(&oracle);
    }

    #[ignore = "needs the harness binary: script/test/ci-test-shard.sh runs it"]
    #[tokio::test]
    async fn a_failed_add_is_followed_by_a_remove_on_the_same_wire() {
        let oracle = Oracle::new(
            r#"{"ops":{"post":{"ok":false,"error":"notifications not allowed"},"remove":{"ok":true}},"expect":{"ops":["post","remove","quit"]}}"#,
        );
        let mut helper = oracle.spawn();
        launched(&mut helper).await;
        auth(&mut helper).await;

        match post(&mut helper, 1).await {
            HelperEvent::Posted { seq, ok, error, .. } => {
                assert_eq!(seq, 1);
                assert!(!ok, "the add failed");
                assert_eq!(error, "notifications not allowed", "the reason survives");
            }
            other => panic!("expected `posted`, got {other:?}"),
        }
        // A failed add does not close the wire, and what may be showing is still
        // taken away by the next operation.
        match remove(&mut helper, 2).await {
            HelperEvent::Removed { seq, ok, .. } => {
                assert_eq!(seq, 2);
                assert!(ok);
            }
            other => panic!("expected `removed`, got {other:?}"),
        }
        quit(&mut helper).await;
        verdict(&oracle);
    }

    // -- the driver over the real child ------------------------------------

    #[ignore = "needs the harness binary: script/test/ci-test-shard.sh runs it"]
    #[tokio::test]
    async fn a_cleanup_only_spawn_after_the_idle_exit_takes_the_banner_away() {
        // Real time, and the slow one in this contract on purpose: the idle exit is
        // 30 s and nothing may move it. Two runs, so `expect.ops` is left out and
        // the sequences are checked here.
        let oracle = Oracle::new(r#"{"expect":{"violations":0}}"#);
        let fixture = Fixture::new();
        fixture.ingest(FIRST_IP, 1);
        let (handle, mut pids) = start(&fixture, &oracle);
        let pid = next_pid(&mut pids).await;

        eventually("the post", || oracle.starts() == 1).await;
        tokio::time::sleep(HELPER_IDLE_EXIT + Duration::from_secs(1)).await;
        eventually("the idle exit", || !oracle.verdicts().is_empty()).await;
        assert!(
            !exists(pid),
            "the idle exit quits and reaps the helper the banner does not need"
        );

        // The banner is still in Notification Center, so the removal a later answer
        // owes is written by exactly one bounded cleanup-only spawn.
        grant(&fixture.allowances, &fixture.refusals, FIRST_IP).await;
        eventually("the cleanup spawn", || oracle.starts() == 2).await;
        eventually("its verdict", || oracle.verdicts().len() == 2).await;

        let mut sequences: Vec<Vec<String>> = oracle
            .verdicts()
            .iter()
            .map(|verdict| {
                verdict["sequence"]
                    .as_array()
                    .expect("a sequence")
                    .iter()
                    .map(|op| op.as_str().expect("an op").to_owned())
                    .collect()
            })
            .collect();
        sequences.sort();
        assert_eq!(
            sequences,
            vec![
                vec!["post".to_owned(), "quit".to_owned()],
                vec!["remove".to_owned(), "quit".to_owned()],
            ],
            "one post then the idle quit; then the cleanup's remove and its quit"
        );
        for verdict in oracle.verdicts() {
            assert_eq!(verdict["ok"], json!(true), "{verdict}");
            assert_eq!(verdict["violations"], json!([]), "{verdict}");
        }
        // One per idle period: the guard, not a retry loop.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(oracle.starts(), 2, "exactly one cleanup-only spawn");
        drop(handle);
    }

    #[ignore = "needs the harness binary: script/test/ci-test-shard.sh runs it"]
    #[tokio::test]
    async fn nothing_owed_spawns_nothing() {
        let oracle = Oracle::new(r#"{"expect":{"violations":0}}"#);
        let fixture = Fixture::new();
        let (handle, mut pids) = start(&fixture, &oracle);
        // No refusal was ever ingested, so no banner is owed and no banner can
        // exist: not even the cleanup-only spawn has anything to do.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(oracle.starts(), 0, "no child ran");
        assert!(
            pids.try_recv().is_err(),
            "and the driver spawned no backend at all"
        );
        drop(handle);
    }

    #[ignore = "needs the harness binary: script/test/ci-test-shard.sh runs it"]
    #[tokio::test]
    async fn dropping_the_handle_reaps_the_child() {
        let oracle = Oracle::new(r#"{"expect":{"violations":0,"ops":["post","quit"]}}"#);
        let fixture = Fixture::new();
        fixture.ingest(FIRST_IP, 1);
        let (handle, mut pids) = start(&fixture, &oracle);
        let pid = next_pid(&mut pids).await;
        assert!(exists(pid), "the oracle is running");

        // A dropped handle asks the driver for the same bounded close `finish`
        // uses, so the child is quit and reaped instead of left to `kill_on_drop`.
        drop(handle);
        eventually("the reap", || !exists(pid)).await;
        eventually("the verdict", || !oracle.verdicts().is_empty()).await;
        let verdict = verdict(&oracle);
        assert_eq!(
            verdict["sequence"],
            json!(["post", "quit"]),
            "the close is a quit, never a kill: {verdict}"
        );
    }

    #[ignore = "needs the harness binary: script/test/ci-test-shard.sh runs it"]
    #[tokio::test]
    async fn cancelling_the_driver_reaps_the_child() {
        // The backend's own guard, not the graceful close: the driver's future is
        // aborted, so only `ReapingChild::drop` can end the child. `kill(pid, 0)`
        // failing is the *reap* — a killed but unreaped child still answers it.
        let oracle = Oracle::new(r#"{"ops":{"post":{"emit":"none"}}}"#);
        let fixture = Fixture::new();
        fixture.ingest(FIRST_IP, 1);
        let (pids_tx, mut pids) = mpsc::unbounded_channel();
        let (inputs, _lines) = fixture.inputs(PromptMode::Immediate, None);
        let (_signals, signals) = mpsc::unbounded_channel();
        let (_requests, requests) = mpsc::unbounded_channel();
        let task = tokio::spawn(super::super::run(
            inputs,
            signals,
            Box::new(RecordingSpawner {
                binary: oracle.wrapper.clone(),
                pids: pids_tx,
            }),
            requests,
        ));
        let pid = next_pid(&mut pids).await;
        assert!(exists(pid), "the oracle is running");

        task.abort();
        let _ = task.await;
        eventually("the reap", || !exists(pid)).await;
        assert_eq!(
            oracle.verdicts().len(),
            0,
            "a cancelled driver never got the child's verdict, so the reap was the guard's"
        );
    }
}
