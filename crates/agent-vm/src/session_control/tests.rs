//! The protocol, the peer check, and discovery.
//!
//! Every case here runs the *production* accept loop and connection handler over
//! a real Unix socket in a real 0700 directory: the properties being asserted —
//! a race-free handoff, a slot kept free for `list`, a dropped silent client, a
//! deadline that holds against a hung server — are properties of that loop.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use microsandbox::logs::{LogSource, NetworkLogEvent, NetworkLogRecord, NetworkRefusal};
use microsandbox_types::Protocol;
use tokio::sync::watch;

use super::*;
use crate::refusal::SessionRefusals;
use crate::refusal::feed::LiveRefusals;
use crate::refusal::log::SessionsDir;

const SID: &str = "0a1b2c3d";

/// Start a session with an explicit `LiveSetup` over a temporary store. Every
/// test in this file starts a *real* server; none of them may touch the real
/// `~/.config/agent-vm`, which is why the store handle is a tempdir.
async fn start_live(session: &ProjectSession) -> LiveSession {
    let project = crate::project::ProjectDir::from_path_for_tests(&session.project_dir)
        .expect("a captured project");
    let store =
        crate::allowances::StoreHandle::at_for_tests(&session.project_dir.join("allowances-store"));
    let plan = crate::network::plan_for_tests(&[], false).live_policy_plan(None);
    LiveSession::start(
        session,
        LiveSetup {
            project: &project,
            store,
            plan,
        },
    )
    .await
}
const BASE_MS: i64 = 1_760_000_000_000;

/// A refused `tls-sni` record for `port`, one second after the last.
fn record(offset_secs: i64, port: u16) -> NetworkLogRecord {
    NetworkLogRecord {
        v: 1,
        t: chrono::DateTime::from_timestamp_millis(BASE_MS + offset_secs * 1000).unwrap(),
        s: LogSource::Network,
        event: NetworkLogEvent::Refusal(NetworkRefusal {
            site: microsandbox::logs::RefusalSite::TlsSni,
            layer: microsandbox::logs::RefusalLayer::Tenant,
            protocol: Protocol::Tcp,
            dst_ip: Some("198.51.100.7".parse().unwrap()),
            dst_port: Some(port),
            name: None,
            name_source: microsandbox::logs::NameSource::Absent,
            revision: 1,
            credential: None,
            location: None,
            reason: None,
        }),
    }
}

fn session(socket: bool) -> SessionRefusals {
    SessionRefusals::new(SessionInfo {
        id: SessionId::parse(SID).unwrap(),
        pid: 1,
        started_ms: 0,
        socket,
    })
}

/// A directory, a bound socket and the production accept loop, with the feed
/// driven directly so a test controls exactly when an update is published.
struct Harness {
    _root: tempfile::TempDir,
    live: Arc<LiveRefusals>,
    allowances: Arc<crate::allowances::LiveAllowances>,
    socket: PathBuf,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
    offset: std::sync::atomic::AtomicI64,
}

impl Harness {
    async fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let dir = SessionsDir::open_or_create(&root.path().join("ab12cd34ef56.sessions")).unwrap();
        let live = LiveRefusals::new(session(true));
        let socket = dir.socket_path(&SessionId::parse(SID).unwrap());
        let listener = UnixListener::bind(&socket).unwrap();
        let project = crate::project::ProjectDir::from_path_for_tests(root.path()).unwrap();
        let store =
            crate::allowances::StoreHandle::at_for_tests(&root.path().join("allowances-store"));
        let plan = crate::network::plan_for_tests(&[], false).live_policy_plan(None);
        let allowances = crate::allowances::LiveAllowances::new(&project, store, plan);
        let (stop, receiver) = watch::channel(false);
        let task = tokio::spawn(serve(
            listener,
            Arc::clone(&live),
            Arc::clone(&allowances),
            receiver,
        ));
        Self {
            _root: root,
            live,
            allowances,
            socket,
            stop,
            task,
            offset: std::sync::atomic::AtomicI64::new(0),
        }
    }

    fn ingest(&self, port: u16) -> u64 {
        let offset = self
            .offset
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut dirty = false;
        let changed = self
            .live
            .ingest(&record(offset + 1, port), &mut dirty, BASE_MS);
        assert!(changed, "a new destination is a change");
        assert!(dirty, "a new destination dirties the record");
        self.live.snapshot().rev
    }

    async fn shutdown(self) {
        let _ = self.stop.send(true);
        let _ = self.task.await;
    }
}

/// A client that reads NDJSON replies one line at a time.
///
/// One reader for the whole conversation on purpose: a `BufReader` built per line
/// can read past the line it returns and drop the rest with itself, so a reply the
/// server had already sent would look like the server closing — which is exactly
/// what a test of "the subscriber is told the session ended" must not mistake for
/// behaviour.
struct Client {
    reader: tokio::io::BufReader<UnixStream>,
}

impl Client {
    async fn connect(path: &std::path::Path) -> Self {
        let stream = UnixStream::connect(path).await.expect("a connection");
        Self {
            reader: tokio::io::BufReader::new(stream),
        }
    }

    async fn send(&mut self, text: &str) {
        tokio::io::AsyncWriteExt::write_all(self.reader.get_mut(), format!("{text}\n").as_bytes())
            .await
            .expect("the request is written");
    }

    /// The next reply, or `None` when the server closed.
    async fn reply_or_close(&mut self) -> Option<Reply> {
        let mut line = String::new();
        tokio::time::timeout(
            Duration::from_secs(5),
            tokio::io::AsyncBufReadExt::read_line(&mut self.reader, &mut line),
        )
        .await
        .expect("a reply within 5 s")
        .expect("a readable reply");
        (!line.is_empty()).then(|| parse_reply(&line).expect("a decodable reply"))
    }

    async fn reply(&mut self) -> Reply {
        self.reply_or_close()
            .await
            .expect("the server closed instead of replying")
    }
}

#[tokio::test]
async fn list_round_trips_a_snapshot() {
    let harness = Harness::new().await;
    harness.ingest(443);
    let expected = harness.live.snapshot();
    let snapshot = list(&harness.socket).await.expect("a list answer");
    assert_eq!(snapshot, expected);
    assert_eq!(snapshot.entries.len(), 1);
    assert_eq!(snapshot.info.id.as_str(), SID);
    harness.shutdown().await;
}

/// The handoff, with updates arriving *while* it happens.
///
/// The earlier version ingested only after the client had its snapshot, so the
/// window the handoff exists to close — an update landing between taking the
/// snapshot and subscribing — was never actually exercised. Here the producer
/// starts before the subscribe request and outlives it.
#[tokio::test]
async fn subscribe_handoff_loses_and_repeats_nothing_across_the_window() {
    let harness = std::sync::Arc::new(Harness::new().await);
    harness.ingest(1000);
    const UPDATES: u16 = 32;
    // Start ingesting before the client subscribes and keep going after it.
    let producer = {
        let harness = std::sync::Arc::clone(&harness);
        tokio::spawn(async move {
            for port in 0..UPDATES {
                tokio::time::sleep(Duration::from_millis(3)).await;
                harness.ingest(2000 + port);
            }
        })
    };
    let mut client = Client::connect(&harness.socket).await;
    client.send("{\"v\":1,\"op\":\"subscribe\"}").await;

    // Every reported revision is one more than the last, whether it arrived in the
    // snapshot or in an update: across the handoff nothing is repeated and
    // nothing is skipped.
    let mut last = None;
    loop {
        let reply = tokio::time::timeout(Duration::from_secs(10), client.reply())
            .await
            .expect("a reply inside the deadline");
        let rev = match reply {
            Reply::Snapshot { session, .. } => session.rev,
            Reply::Update { update, .. } => {
                assert!(
                    last.is_some_and(|last| update.rev > last),
                    "no update repeats a revision: {} <= {last:?}",
                    update.rev
                );
                update.rev
            }
            other => panic!("only snapshots and updates here: {other:?}"),
        };
        if let Some(previous) = last {
            assert_eq!(
                rev,
                previous + 1,
                "no revision is skipped across the handoff"
            );
        }
        last = Some(rev);
        if rev >= harness.live.snapshot().rev {
            break;
        }
    }
    producer.await.expect("the producer did not panic");
    let final_rev = harness.live.snapshot().rev;
    // The producer may have moved on after the last reply; read to its end.
    while let Some(rev) = last.filter(|last| *last < final_rev) {
        let reply = tokio::time::timeout(Duration::from_secs(10), client.reply())
            .await
            .expect("a reply inside the deadline");
        let next = match reply {
            Reply::Update { update, .. } => update.rev,
            other => panic!("only updates left: {other:?}"),
        };
        assert!(next > rev, "{next} <= {rev}");
        last = Some(next);
    }
    assert_eq!(
        last,
        Some(harness.live.snapshot().rev),
        "the client ends where the server is"
    );
    let snapshot = harness.live.snapshot();
    assert_eq!(snapshot.entries.len(), 1 + usize::from(UPDATES));
    std::sync::Arc::try_unwrap(harness)
        .ok()
        .expect("the harness is free")
        .shutdown()
        .await;
}

/// The server's answer to a slow subscriber, over a real connection.
///
/// A subscriber that stops reading stops draining its subscription, so the
/// server falls behind and `broadcast` reports a lag. The answer must be a fresh
/// whole snapshot — the counters are absolute, so nothing the client missed stays
/// wrong — and not just a resumption of the update stream. (The previous version
/// of this case drove a bare `broadcast::Receiver` and so asserted Tokio's
/// behaviour rather than the server's reply.)
#[tokio::test]
async fn a_lagging_subscriber_is_resynced_with_a_whole_snapshot() {
    let harness = Harness::new().await;
    let mut client = Client::connect(&harness.socket).await;
    client.send("{\"v\":1,\"op\":\"subscribe\"}").await;
    let Reply::Snapshot { session, .. } = client.reply().await else {
        panic!("the first reply is a snapshot");
    };
    assert!(session.entries.is_empty());

    // More updates than the ring buffer, while the client reads nothing: the
    // socket buffer fills and the connection stops draining the subscription.
    let updates = crate::refusal::feed::UPDATE_BUFFER as u16 + 44;
    for port in 1..=updates {
        harness.ingest(port);
    }
    let live = harness.live.snapshot();

    // The only later snapshot the protocol has is the resync: the client is told
    // it lagged and is handed every counter.
    let resync = loop {
        let reply = tokio::time::timeout(Duration::from_secs(10), client.reply())
            .await
            .expect("the connection is still there");
        if let Reply::Snapshot { session, .. } = reply {
            break session;
        }
    };
    assert_eq!(
        resync.entries.len(),
        usize::from(updates),
        "the resync carries every entry, not just the recent ones"
    );
    assert_eq!(resync.rev, live.rev, "and the current revision");
}

#[tokio::test]
async fn twelve_subscribers_leave_room_for_list() {
    let harness = Harness::new().await;
    let mut subscribers = Vec::new();
    for _ in 0..MAX_SUBSCRIBERS {
        let mut client = Client::connect(&harness.socket).await;
        client.send("{\"v\":1,\"op\":\"subscribe\"}").await;
        assert!(matches!(client.reply().await, Reply::Snapshot { .. }));
        subscribers.push(client);
    }
    // Every subscriber slot is taken, and `list` still answers.
    let snapshot = tokio::time::timeout(Duration::from_secs(5), list(&harness.socket))
        .await
        .expect("list is not queued behind the subscribers")
        .expect("list is answered");
    assert_eq!(snapshot.info.id.as_str(), SID);
    drop(subscribers);
    harness.shutdown().await;
}

#[tokio::test]
async fn a_silent_client_is_dropped() {
    let harness = Harness::new().await;
    let mut stream = UnixStream::connect(&harness.socket).await.unwrap();
    // Say nothing. The server's read deadline closes the connection.
    let mut buffer = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(6), stream.read(&mut buffer)).await;
    match read {
        Ok(Ok(0)) => {}
        Ok(Ok(_)) => panic!("a silent client must not be answered"),
        Ok(Err(_)) => {}
        Err(_) => panic!("a silent client must be dropped within the exchange deadline"),
    }
    harness.shutdown().await;
}

#[tokio::test]
async fn unknown_version_gets_unsupported_version() {
    let harness = Harness::new().await;
    let mut client = Client::connect(&harness.socket).await;
    client.send("{\"v\":9,\"op\":\"list\"}").await;
    match client.reply().await {
        Reply::Error {
            code, supported, ..
        } => {
            assert_eq!(code, "unsupported-version");
            assert_eq!(supported, Some(vec![1, 2]));
        }
        other => panic!("{other:?}"),
    }
    // Garbage on the same socket kind gets `bad-request`, not a silent close.
    let mut client = Client::connect(&harness.socket).await;
    client.send("not json at all").await;
    match client.reply().await {
        Reply::Error { code, .. } => assert_eq!(code, "bad-request"),
        other => panic!("{other:?}"),
    }
    harness.shutdown().await;
}

/// The peer check is one comparison; the test drives it directly because a
/// second uid is not available in-process.
#[test]
fn peer_uid_mismatch_is_refused() {
    assert!(peer_is_allowed(501, 501));
    assert!(!peer_is_allowed(0, 501));
    assert!(!peer_is_allowed(501, 0));
}

#[tokio::test]
async fn stale_socket_is_removed_and_reported_ended() {
    let root = tempfile::tempdir().unwrap();
    let dir = SessionsDir::open_or_create(&root.path().join("ab12cd34ef56.sessions")).unwrap();
    let id = SessionId::parse("deadbeef").unwrap();
    // A socket file with nothing listening: bind, then drop the listener.
    {
        let _listener = UnixListener::bind(dir.socket_path(&id)).unwrap();
    }
    let discovery = discover(&dir, BASE_MS).await;
    assert!(discovery.live.is_empty());
    assert!(
        !dir.socket_path(&id).exists(),
        "the stale socket is unlinked"
    );
    assert!(
        discovery.unresponsive.is_empty(),
        "a refused connection is not a hung session: {:?}",
        discovery.unresponsive
    );
}

#[tokio::test]
async fn a_symlinked_sock_is_never_connected_or_removed() {
    let root = tempfile::tempdir().unwrap();
    let dir = SessionsDir::open_or_create(&root.path().join("ab12cd34ef56.sessions")).unwrap();
    let elsewhere = root.path().join("real.sock");
    let _listener = UnixListener::bind(&elsewhere).unwrap();
    let id = SessionId::parse("deadbeef").unwrap();
    std::os::unix::fs::symlink(&elsewhere, dir.socket_path(&id)).unwrap();
    let discovery = discover(&dir, BASE_MS).await;
    assert!(discovery.live.is_empty(), "a symlink is never dialed");
    assert!(
        std::fs::symlink_metadata(dir.socket_path(&id)).is_ok(),
        "a symlink is never removed"
    );
    assert!(discovery.unresponsive.is_empty());
}

#[tokio::test]
async fn discovery_meets_its_deadline_with_a_hung_server() {
    let root = tempfile::tempdir().unwrap();
    let dir = SessionsDir::open_or_create(&root.path().join("ab12cd34ef56.sessions")).unwrap();
    let id = SessionId::parse("deadbeef").unwrap();
    // A server that accepts and never answers.
    let listener = UnixListener::bind(dir.socket_path(&id)).unwrap();
    let hung = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    let started = Instant::now();
    let hung_discovery = discover(&dir, BASE_MS).await;
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "discovery has a total deadline: {elapsed:?}"
    );
    assert_eq!(hung_discovery.unresponsive.len(), 1);
    assert!(hung_discovery.live.is_empty());
    assert!(
        dir.socket_path(&id).exists(),
        "a hung session is reported, not unlinked"
    );
    hung.abort();
    // A server that answers `list` and then goes silent must not cost a second
    // open-ended wait: the `allowances` answer is bounded by `EXCHANGE_TIMEOUT`
    // too, and its absence only means "no live allowances to show".
    std::fs::remove_file(dir.socket_path(&id)).unwrap();
    let answering = UnixListener::bind(dir.socket_path(&id)).unwrap();
    let answering_id = id.as_str().to_owned();
    let answering = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = answering.accept().await {
            let mut reader = tokio::io::BufReader::new(stream);
            let mut line = String::new();
            use tokio::io::AsyncBufReadExt as _;
            use tokio::io::AsyncWriteExt as _;
            let _ = reader.read_line(&mut line).await;
            if line.contains("\"op\":\"list\"") {
                // Answer the list, then hold the connection so the next request
                // never gets an answer.
                let reply = serde_json::json!({
                    "reply": "session",
                    "v": 1,
                    "session": {
                        "info": {"id": answering_id, "pid": 1, "started_ms": BASE_MS, "socket": true},
                        "rev": 1, "ended_ms": null, "heartbeat_ms": null,
                        "suppressed": 0, "lost": 0, "gap": false, "entries": []
                    }
                })
                .to_string()
                    + "\n";
                let mut stream = reader.into_inner();
                let _ = stream.write_all(reply.as_bytes()).await;
                held.push(stream);
            }
        }
    });
    let started = Instant::now();
    let discovery = discover(&dir, BASE_MS).await;
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "a silent `allowances` answer has its own bound: {elapsed:?}"
    );
    assert_eq!(
        discovery.live.len(),
        1,
        "the list answer is used: {:?}",
        discovery.warnings
    );
    assert!(
        discovery.live_allowances.is_empty(),
        "a session with no allowances answer contributes no live allowances"
    );
    answering.abort();
}

#[test]
fn socket_path_budget_boundary() {
    // 103 bytes fits on macOS, 104 does not; the predicate is the same proof the
    // runtime's own path check uses.
    let fits = PathBuf::from("/".to_owned() + &"a".repeat(102));
    let over = PathBuf::from("/".to_owned() + &"a".repeat(103));
    assert_eq!(fits.as_os_str().len(), 103);
    assert_eq!(over.as_os_str().len(), 104);
    assert!(crate::msb_install::unix_socket_path_fits(&fits));
    #[cfg(target_os = "macos")]
    assert!(!crate::msb_install::unix_socket_path_fits(&over));
}

#[tokio::test]
async fn overlong_path_degrades_with_one_notice() {
    // A state root deep enough that `<root>/<hash>.sessions/<sid>.sock` cannot be
    // bound. The session keeps its log and loses only the live view.
    let root = tempfile::tempdir().unwrap();
    let mut deep = root.path().to_path_buf();
    while deep.as_os_str().len() < 120 {
        deep.push("aaaaaaaaaaaaaaaaaaaa");
    }
    std::fs::create_dir_all(&deep).unwrap();
    let project = ProjectSession {
        project_dir: root.path().to_path_buf(),
        project_hash: "ab12cd34ef56".to_owned(),
        state_dir: deep.join("ab12cd34ef56"),
        sandbox_name: "agent-vm-ab12cd34ef56-1".to_owned(),
    };
    std::fs::create_dir_all(project.state_dir.parent().unwrap()).unwrap();
    let live = start_live(&project).await;
    assert!(
        !live.info.socket,
        "the socket was not bound, and the launch was not failed"
    );
    assert!(
        !project
            .sessions_dir()
            .join(format!("{}.sock", live.id().as_str()))
            .exists(),
        "no socket file was left behind"
    );
    // The log still exists, so `access` will list this session afterwards.
    live.finish().await;
    let dir = SessionsDir::open(&project.sessions_dir()).unwrap().unwrap();
    assert!(
        dir.read()
            .unwrap()
            .sessions
            .iter()
            .any(|session| session.info.id == *live.id()),
        "an over-long socket path costs the live view, not the record"
    );
}

#[tokio::test]
async fn a_session_with_a_socket_binds_it_at_start_and_unlinks_at_finish() {
    let root = tempfile::tempdir().unwrap();
    let project = ProjectSession {
        project_dir: root.path().to_path_buf(),
        project_hash: "ab12cd34ef56".to_owned(),
        state_dir: root.path().join("ab12cd34ef56"),
        sandbox_name: "agent-vm-ab12cd34ef56-1".to_owned(),
    };
    let live = start_live(&project).await;
    let socket = project
        .sessions_dir()
        .join(format!("{}.sock", live.id().as_str()));
    assert!(socket.exists(), "the socket is bound before create (AC9)");
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    assert_eq!(
        std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(&socket).unwrap().uid(),
        crate::host_paths::current_euid()
    );
    // `list` answers for the session the launcher reserved.
    let snapshot = list(&socket).await.expect("a live answer");
    assert_eq!(snapshot.info.id, *live.id());
    live.finish().await;
    assert!(!socket.exists(), "finish unlinks its own socket");
    // The final record says the session ended.
    let dir = SessionsDir::open(&project.sessions_dir()).unwrap().unwrap();
    let logged = dir
        .read()
        .unwrap()
        .sessions
        .into_iter()
        .find(|session| session.info.id == *live.id())
        .expect("the session is in the log");
    assert!(
        logged.ended_ms.is_some(),
        "ended is persisted before remove"
    );
    // `finish` is idempotent: a second teardown path cannot move the record.
    live.finish().await;
}

#[tokio::test]
async fn discovery_sees_a_live_session_and_the_log_beside_it() {
    let root = tempfile::tempdir().unwrap();
    let project = ProjectSession {
        project_dir: root.path().to_path_buf(),
        project_hash: "ab12cd34ef56".to_owned(),
        state_dir: root.path().join("ab12cd34ef56"),
        sandbox_name: "agent-vm-ab12cd34ef56-1".to_owned(),
    };
    let live = start_live(&project).await;
    let dir = SessionsDir::open(&project.sessions_dir()).unwrap().unwrap();
    let discovery = discover(&dir, BASE_MS).await;
    assert_eq!(discovery.live.len(), 1);
    assert_eq!(discovery.live[0].info.id, *live.id());
    assert!(discovery.logged.iter().any(|s| s.info.id == *live.id()));
    live.finish().await;
}

/// A launch that errors before `create` never reaches a teardown, so `Drop` is
/// the only chance to leave no socket behind.
#[tokio::test]
async fn dropping_a_session_unlinks_its_socket() {
    let root = tempfile::tempdir().unwrap();
    let project = ProjectSession {
        project_dir: root.path().to_path_buf(),
        project_hash: "ab12cd34ef56".to_owned(),
        state_dir: root.path().join("ab12cd34ef56"),
        sandbox_name: "agent-vm-ab12cd34ef56-1".to_owned(),
    };
    let socket = {
        let live = start_live(&project).await;
        let socket = project
            .sessions_dir()
            .join(format!("{}.sock", live.id().as_str()));
        assert!(socket.exists());
        socket
    };
    assert!(
        !socket.exists(),
        "dropping the session unlinks its own socket"
    );
}

// -- the teardown path -----------------------------------------------------

/// A refused record stamped `now`, because a real `LiveSession` starts now and
/// ignores anything older (a reused sandbox name).
fn record_now(port: u16) -> NetworkLogRecord {
    let mut record = record(0, port);
    record.t = chrono::DateTime::from_timestamp_millis(crate::refusal::feed::now_ms()).unwrap();
    record
}

/// A cursor in the engine's own wire form, so a drained entry looks like one the
/// engine produced.
fn base64_cursor(offset: u64) -> microsandbox::logs::LogCursor {
    use base64::Engine as _;
    let mut bytes = vec![1u8];
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&offset.to_le_bytes());
    base64::engine::general_purpose::STANDARD
        .encode(bytes)
        .parse()
        .expect("a cursor in the engine's encoding")
}

fn logs_entry(record: &NetworkLogRecord, offset: u64) -> microsandbox::logs::LogEntry {
    microsandbox::logs::LogEntry {
        timestamp: chrono::Utc::now(),
        source: LogSource::Network,
        session_id: None,
        data: serde_json::to_vec(record).unwrap().into(),
        cursor: base64_cursor(offset),
    }
}

fn project(root: &std::path::Path) -> ProjectSession {
    ProjectSession {
        project_dir: root.to_path_buf(),
        project_hash: "ab12cd34ef56".to_owned(),
        state_dir: root.join("ab12cd34ef56"),
        sandbox_name: "agent-vm-ab12cd34ef56-1".to_owned(),
    }
}

/// The `ended` reply a subscriber waits for. Nothing closes the broadcast
/// channel — `LiveState` owns the sender and every connection holds an `Arc` to
/// it — so the stop signal is the only thing that can deliver it, and aborting the
/// connections instead is what used to leave every subscriber hanging.
#[tokio::test]
async fn finish_tells_a_connected_subscriber_the_session_ended() {
    let root = tempfile::tempdir().unwrap();
    let live = start_live(&project(root.path())).await;
    let socket = project(root.path())
        .sessions_dir()
        .join(format!("{}.sock", live.id().as_str()));

    let mut client = Client::connect(&socket).await;
    client.send("{\"v\":1,\"op\":\"subscribe\"}").await;
    let Reply::Snapshot { session, .. } = client.reply().await else {
        panic!("the first reply is a snapshot");
    };
    assert!(session.ended_ms.is_none(), "the session is running");
    // One real update through the production ingest path, so the subscriber is
    // waiting in `updates.recv()` when the session ends.
    let mut dirty = false;
    assert!(
        live.live
            .as_ref()
            .expect("a session with a socket has a feed")
            .ingest(&record_now(443), &mut dirty, crate::refusal::feed::now_ms())
    );
    let Reply::Update { update, .. } = client.reply().await else {
        panic!("the refusal is an update");
    };
    assert_eq!(update.entry.expect("an entry").count, 1);

    live.finish().await;

    // `ended` is also published as an ordinary update (`Update` carries no
    // `ended_ms`, so a client cannot tell the two apart), which is why the
    // explicit reply below is the only thing that says the session is over.
    let mut replies = Vec::new();
    let ended = loop {
        let reply = tokio::time::timeout(Duration::from_secs(5), client.reply())
            .await
            .unwrap_or_else(|_| panic!("the subscriber is told within the grace: {replies:?}"));
        if matches!(reply, Reply::Ended { .. }) {
            break reply;
        }
        replies.push(format!("{reply:?}"));
        assert!(replies.len() < 5, "{replies:?}");
    };
    assert!(matches!(ended, Reply::Ended { .. }));
}

/// AC7 is once per *session*, not once per reader. The drain used to build its
/// own `Hint`, so a refusal first read at teardown — or one the follower had
/// already reported, read again — printed a second line.
#[tokio::test]
async fn the_drain_prints_the_session_s_one_hint() {
    let root = tempfile::tempdir().unwrap();
    let mut live = start_live(&project(root.path())).await;
    let (hint, lines) = Hint::capture();
    live.hint = Arc::new(hint);
    // No `Sandbox` is available here, so the opener the drain shares is set
    // directly: it yields one refusal, which the drain is the first to read.
    let opener: Opener = Arc::new(|_options| {
        let entry = logs_entry(&record_now(443), 10);
        Box::pin(async move { Ok(Box::pin(futures::stream::iter(vec![Ok(entry)])) as LogStream) })
    });
    *lock(&live.open) = Some(opener);
    // A follower that has already stopped and left no cursor, so `finish` takes
    // the drain path.
    let (stop, _receiver) = watch::channel(false);
    *lock(&live.following) = Some(Following {
        stop,
        task: tokio::spawn(async { None }),
    });

    live.finish().await;

    let lines = lines.lock().unwrap();
    assert_eq!(lines.len(), 1, "{lines:?}");
}

/// A `finish` that was cancelled part-way has already set `finished` and may not
/// have unlinked the socket. `Drop` therefore decides from what it still holds,
/// not from the flag.
#[tokio::test]
async fn dropping_after_a_cancelled_finish_still_unlinks_the_socket() {
    let root = tempfile::tempdir().unwrap();
    let socket;
    {
        let live = start_live(&project(root.path())).await;
        socket = project(root.path())
            .sessions_dir()
            .join(format!("{}.sock", live.id().as_str()));
        assert!(socket.exists());
        // What a cancelled `finish` leaves behind: the flag set, the socket
        // bound, the accept loop still running.
        live.finished.store(true, Ordering::SeqCst);
        assert!(
            socket.exists(),
            "setting the flag alone does not unlink anything"
        );
    }
    assert!(
        !socket.exists(),
        "dropping the session unlinks the socket it still holds"
    );
}

/// A launch that errors before `create` never reaches a teardown, so `Drop` is
/// the only writer left. The record it leaves must still say the session ended.
#[tokio::test]
async fn dropping_a_session_writes_a_record_that_says_it_ended() {
    let root = tempfile::tempdir().unwrap();
    let id;
    {
        let live = start_live(&project(root.path())).await;
        id = live.id().clone();
    }
    let dir = SessionsDir::open(&project(root.path()).sessions_dir())
        .unwrap()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let ended = dir
            .read()
            .unwrap()
            .sessions
            .into_iter()
            .find(|session| session.info.id == id)
            // `and_then`, not `map`: a found session with no end is the case
            // this waits through, and `Some(None)` would look like success.
            .and_then(|session| session.ended_ms);
        if ended.is_some() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "`Drop` offered no final record: {ended:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The window `Hidden` exists for: a socket that is bound but not yet listening
/// used to answer `ECONNREFUSED`, which discovery reads as stale and unlinks — so
/// the session read `ended (unclean)` for its whole life. The hidden name is
/// invisible to discovery, and the published name never refuses a connection.
#[tokio::test]
async fn a_socket_is_listening_before_its_name_appears() {
    let root = tempfile::tempdir().unwrap();
    let dir = SessionsDir::open_or_create(&root.path().join("ab12cd34ef56.sessions")).unwrap();
    let id = SessionId::parse("deadbeef").unwrap();
    let hidden = Hidden::bind(&dir, &id).unwrap();

    // Not announced yet: discovery neither dials nor unlinks either name.
    let discovery = discover(&dir, BASE_MS).await;
    assert!(discovery.live.is_empty());
    assert!(discovery.unresponsive.is_empty());
    assert!(
        !dir.socket_path(&id).exists(),
        "the visible name is not there yet"
    );
    assert!(
        Hidden::tmp_path(&dir, &id).exists(),
        "the hidden name is left alone"
    );

    let listener = hidden.publish().unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    assert_eq!(
        std::fs::metadata(dir.socket_path(&id))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600,
        "the mode is set before the name appears"
    );

    // Published means listening: the first connect succeeds, so discovery reports
    // the session as busy rather than unlinking a socket that is about to serve.
    let discovery = discover(&dir, BASE_MS).await;
    assert_eq!(
        discovery.unresponsive.len(),
        1,
        "{:?}",
        discovery.unresponsive
    );
    assert!(
        dir.socket_path(&id).exists(),
        "a listening socket is never unlinked"
    );
    drop(listener);
}

/// A publish that cannot rename leaves no hidden name behind: nothing in
/// discovery can ever see or clean one up.
#[tokio::test]
async fn a_failed_publish_leaves_no_hidden_name() {
    let root = tempfile::tempdir().unwrap();
    let dir = SessionsDir::open_or_create(&root.path().join("ab12cd34ef56.sessions")).unwrap();
    let id = SessionId::parse("deadbeef").unwrap();
    let hidden = Hidden::bind(&dir, &id).unwrap();
    // The rename cannot land on a directory.
    std::fs::create_dir(dir.socket_path(&id)).unwrap();
    let error = hidden
        .publish()
        .expect_err("the rename cannot land")
        .to_string();
    assert!(error.contains("deadbeef.sock"), "{error}");
    assert!(
        !Hidden::tmp_path(&dir, &id).exists(),
        "the hidden name is gone"
    );
}

// ---------------------------------------------------------------------------
// Group P: protocol v2 and the queued boot window (PR 2)
// ---------------------------------------------------------------------------

use std::sync::atomic::AtomicUsize;

/// A policy updater that counts its calls and confirms the next revision.
fn counting_updater(calls: Arc<AtomicUsize>) -> crate::allowances::PolicyUpdater {
    Arc::new(move |_policy| {
        let calls = Arc::clone(&calls);
        Box::pin(async move {
            let previous = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(previous as u64 + 2)
        })
    })
}

/// P1: `v: 1` and `v: 2` coexist; an unknown version is answered with the list of
/// versions even when it carries extra fields; a `v: 1` mutation is refused; and
/// discovery keeps `live` and `unresponsive` disjoint.
#[tokio::test]
async fn protocol_v1_and_v2_coexist_and_reject_unknown_versions() {
    let harness = Harness::new().await;
    let calls = Arc::new(AtomicUsize::new(0));
    harness
        .allowances
        .attach_updater(counting_updater(Arc::clone(&calls)));

    // `v: 1` list and subscribe answer with `v: 1`.
    let mut client = Client::connect(&harness.socket).await;
    client.send("{\"v\":1,\"op\":\"list\"}").await;
    match client.reply().await {
        Reply::Session { v, .. } => assert_eq!(v, 1, "a v1 client sees v1 replies"),
        other => panic!("{other:?}"),
    }
    let mut client = Client::connect(&harness.socket).await;
    client.send("{\"v\":1,\"op\":\"subscribe\"}").await;
    match client.reply().await {
        Reply::Snapshot { v, .. } => assert_eq!(v, 1),
        other => panic!("{other:?}"),
    }

    // A `v: 1` mutation does not exist in version 1.
    let mut client = Client::connect(&harness.socket).await;
    client
        .send("{\"v\":1,\"op\":\"grant\",\"destination\":\"tcp://[203.0.113.10/32]:443\"}")
        .await;
    match client.reply().await {
        Reply::Error { code, .. } => assert_eq!(code, "bad-request"),
        other => panic!("{other:?}"),
    }

    // An unknown version, with extra fields, is `unsupported-version`, not
    // `bad-request`: the lenient probe runs first.
    let mut client = Client::connect(&harness.socket).await;
    client
        .send("{\"v\":3,\"op\":\"list\",\"future\":{\"a\":1}}")
        .await;
    match client.reply().await {
        Reply::Error {
            code, supported, ..
        } => {
            assert_eq!(code, "unsupported-version");
            assert_eq!(supported, Some(vec![1, 2]));
        }
        other => panic!("{other:?}"),
    }

    // `v: 2` list, grant and allowances.
    let mut client = Client::connect(&harness.socket).await;
    client.send("{\"v\":2,\"op\":\"list\"}").await;
    match client.reply().await {
        Reply::Session { v, .. } => assert_eq!(v, 2),
        other => panic!("{other:?}"),
    }
    let mut client = Client::connect(&harness.socket).await;
    client
        .send("{\"v\":2,\"op\":\"grant\",\"destination\":\"tcp://[203.0.113.10/32]:443\",\"scope\":\"session\"}")
        .await;
    match client.reply().await {
        Reply::Grant {
            v,
            result:
                crate::allowances::GrantResult::Applied {
                    revision, scope, ..
                },
        } => {
            assert_eq!(v, 2);
            assert_eq!(revision, 2);
            assert_eq!(scope, crate::allowances::GrantScope::Session);
        }
        other => panic!("{other:?}"),
    }
    let mut client = Client::connect(&harness.socket).await;
    client.send("{\"v\":2,\"op\":\"allowances\"}").await;
    match client.reply().await {
        Reply::Allowances { v, allowances } => {
            assert_eq!(v, 2);
            assert_eq!(allowances.session.len(), 1);
            assert_eq!(
                allowances.session[0].destination,
                "tcp://[203.0.113.10/32]:443"
            );
        }
        other => panic!("{other:?}"),
    }

    // Disjoint discovery: bound sockets that answer are `live`; one that does
    // not is `unresponsive`; only the live ones have a live allowance view.
    let session = ProjectSession {
        project_dir: harness._root.path().to_path_buf(),
        project_hash: "ab12cd34ef56".to_owned(),
        // `sessions_dir` replaces the state dir's file name, so this puts the
        // second session's socket in the harness's own `<hash>.sessions`.
        state_dir: harness._root.path().join("state"),
        sandbox_name: "agent-vm-ab12cd34ef56-2".to_owned(),
    };
    let second = start_live(&session).await;
    let dir = SessionsDir::open(&harness._root.path().join("ab12cd34ef56.sessions"))
        .unwrap()
        .unwrap();
    let hung_id = SessionId::parse("00000009").unwrap();
    let listener = UnixListener::bind(dir.socket_path(&hung_id)).unwrap();
    let held = tokio::spawn(async move {
        let mut streams = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            streams.push(stream);
        }
    });
    let discovery = discover(&dir, BASE_MS).await;
    let live_ids: Vec<SessionId> = discovery.live.iter().map(|s| s.info.id.clone()).collect();
    assert!(
        live_ids.contains(&SessionId::parse(SID).unwrap()),
        "{live_ids:?}"
    );
    assert!(live_ids.contains(second.id()), "{live_ids:?}");
    assert_eq!(discovery.unresponsive, vec![hung_id.clone()]);
    assert!(
        discovery.live.iter().all(|s| s.info.id != hung_id),
        "the hung session is never also live"
    );
    assert_eq!(discovery.live_allowances.len(), live_ids.len());
    held.abort();
    second.finish().await;
    harness.shutdown().await;
}

/// P2: a grant before the runtime is attached is queued; the flush either
/// promotes it or drops it with a notice naming the destination.
#[tokio::test]
async fn grant_before_follow_is_queued_for_boot_and_applied_or_dropped_with_notice_on_follow() {
    // Part A: a queued grant is promoted by the flush.
    let harness = Harness::new().await;
    let queued = crate::session_control::grant(
        &harness.socket,
        Some("tcp://[203.0.113.10/32]:443"),
        crate::allowances::GrantScope::Session,
    )
    .await
    .unwrap();
    assert!(
        matches!(queued, crate::allowances::GrantResult::QueuedForBoot { .. }),
        "{queued:?}"
    );
    let calls = Arc::new(AtomicUsize::new(0));
    assert!(
        harness
            .allowances
            .attach_updater(counting_updater(Arc::clone(&calls))),
        "the queued grant is waiting"
    );
    assert!(harness.allowances.flush_queued().await.is_empty());
    let snapshot = harness.allowances.snapshot();
    assert_eq!(snapshot.session.len(), 1);
    assert_eq!(snapshot.session[0].revision, Some(2));

    // Part B: a failing flush drops both queued tables and names each.
    let harness = Harness::new().await;
    crate::session_control::grant(
        &harness.socket,
        Some("tcp://[198.51.100.0/24]:443"),
        crate::allowances::GrantScope::Project,
    )
    .await
    .unwrap();
    crate::session_control::grant(
        &harness.socket,
        Some("tcp://[203.0.113.0/24]:443"),
        crate::allowances::GrantScope::Session,
    )
    .await
    .unwrap();
    let failing: crate::allowances::PolicyUpdater = Arc::new(|_policy| {
        Box::pin(async move { Err(microsandbox::MicrosandboxError::ControlStateChanged) })
    });
    assert!(harness.allowances.attach_updater(failing));
    let warnings = harness.allowances.flush_queued().await;
    assert_eq!(warnings.len(), 2, "{warnings:?}");
    assert!(
        warnings
            .iter()
            .any(|line| line.contains("still carries it to the next launch")),
        "{warnings:?}"
    );
    assert!(
        warnings
            .iter()
            .any(|line| line.contains("no project record was written")),
        "{warnings:?}"
    );
    assert!(harness.allowances.snapshot().session.is_empty());
    assert!(harness.allowances.snapshot().project.is_empty());
    harness.shutdown().await;
}

/// P3: two concurrent identical grants call the runtime once and store one entry.
#[tokio::test]
async fn concurrent_grants_on_socket_are_idempotent_first_writer_wins() {
    let harness = Harness::new().await;
    let calls = Arc::new(AtomicUsize::new(0));
    harness
        .allowances
        .attach_updater(counting_updater(Arc::clone(&calls)));
    let socket = harness.socket.clone();
    let first = tokio::spawn(async move {
        crate::session_control::grant(
            &socket,
            Some("tcp://[203.0.113.10/32]:443"),
            crate::allowances::GrantScope::Session,
        )
        .await
    });
    let socket = harness.socket.clone();
    let second = tokio::spawn(async move {
        crate::session_control::grant(
            &socket,
            Some("tcp://[203.0.113.10/32]:443"),
            crate::allowances::GrantScope::Session,
        )
        .await
    });
    let (a, b) = (
        first.await.unwrap().unwrap(),
        second.await.unwrap().unwrap(),
    );
    assert!(
        matches!(a, crate::allowances::GrantResult::Applied { .. }),
        "{a:?}"
    );
    assert!(
        matches!(b, crate::allowances::GrantResult::Applied { .. }),
        "{b:?}"
    );
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the duplicate grant did not swap the policy again"
    );
    assert_eq!(harness.allowances.snapshot().session.len(), 1);
    harness.shutdown().await;
}
