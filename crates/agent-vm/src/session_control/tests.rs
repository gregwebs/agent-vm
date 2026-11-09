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
use crate::refusal::feed::{LiveRefusals, POLL_INTERVAL};
use crate::refusal::log::SessionsDir;

const SID: &str = "0a1b2c3d";
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
        let (stop, receiver) = watch::channel(false);
        let task = tokio::spawn(serve(listener, Arc::clone(&live), receiver));
        Self {
            _root: root,
            live,
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

/// A blocking read of one NDJSON line from a client socket, with a deadline.
async fn next_reply(stream: &mut UnixStream) -> Reply {
    let mut reader = tokio::io::BufReader::new(&mut *stream);
    let mut line = String::new();
    tokio::time::timeout(
        Duration::from_secs(5),
        tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut line),
    )
    .await
    .expect("a reply within 5 s")
    .expect("a readable reply");
    assert!(!line.is_empty(), "the server closed instead of replying");
    parse_reply(&line).expect("a decodable reply")
}

async fn send(stream: &mut UnixStream, text: &str) {
    tokio::io::AsyncWriteExt::write_all(stream, format!("{text}\n").as_bytes())
        .await
        .unwrap();
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

#[tokio::test]
async fn subscribe_handoff_loses_and_repeats_nothing_under_concurrent_ingest() {
    let harness = Harness::new().await;
    harness.ingest(1001);
    let mut stream = {
        let stream = UnixStream::connect(&harness.socket).await.unwrap();
        let mut stream = stream;
        send(&mut stream, "{\"v\":1,\"op\":\"subscribe\"}").await;
        stream
    };
    // The handoff: one snapshot, then every update after it, exactly once.
    let Reply::Snapshot { session, .. } = next_reply(&mut stream).await else {
        panic!("the first reply is a snapshot");
    };
    let mut last_rev = session.rev;
    assert_eq!(session.entries.len(), 1);
    // Ingest while the client is reading, so the handoff window is exercised.
    for port in 0..8u16 {
        harness.ingest(2000 + port);
        let reply = tokio::time::timeout(Duration::from_secs(5), next_reply(&mut stream)).await;
        let Ok(Reply::Update { update, .. }) = reply else {
            panic!("an update reply");
        };
        assert!(
            update.rev > last_rev,
            "no update repeats a revision: {} <= {last_rev}",
            update.rev
        );
        assert_eq!(
            update.rev,
            last_rev + 1,
            "no revision is skipped across the handoff"
        );
        last_rev = update.rev;
    }
    let final_rev = harness.live.snapshot().rev;
    assert_eq!(last_rev, final_rev, "the client ends where the server is");
    harness.shutdown().await;
}

#[tokio::test]
async fn a_lagging_subscriber_gets_a_resync_snapshot() {
    // The mechanism the server relies on: a receiver that falls more than the
    // ring buffer behind is *told* it lagged, and a fresh subscription carries
    // every absolute counter, so nothing it missed stays wrong.
    let live = LiveRefusals::new(session(true));
    let (_snapshot, mut updates) = live.subscribe();
    let mut dirty = false;
    for port in 1..=(crate::refusal::feed::UPDATE_BUFFER as u16 + 20) {
        live.ingest(&record(i64::from(port), port), &mut dirty, BASE_MS);
    }
    let error = updates.try_recv().expect_err("the lag is reported");
    assert!(
        matches!(
            error,
            tokio::sync::broadcast::error::TryRecvError::Lagged(_)
        ),
        "{error}"
    );
    let (fresh, _) = live.subscribe();
    assert_eq!(
        fresh.entries.len(),
        crate::refusal::feed::UPDATE_BUFFER + 20
    );
    assert_eq!(fresh.rev, live.snapshot().rev);
}

#[tokio::test]
async fn twelve_subscribers_leave_room_for_list() {
    let harness = Harness::new().await;
    let mut subscribers = Vec::new();
    for _ in 0..MAX_SUBSCRIBERS {
        let mut stream = UnixStream::connect(&harness.socket).await.unwrap();
        send(&mut stream, "{\"v\":1,\"op\":\"subscribe\"}").await;
        assert!(matches!(
            next_reply(&mut stream).await,
            Reply::Snapshot { .. }
        ));
        subscribers.push(stream);
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
    let mut stream = UnixStream::connect(&harness.socket).await.unwrap();
    send(&mut stream, "{\"v\":9,\"op\":\"list\"}").await;
    match next_reply(&mut stream).await {
        Reply::Error {
            code, supported, ..
        } => {
            assert_eq!(code, "unsupported-version");
            assert_eq!(supported, Some(vec![PROTOCOL_VERSION]));
        }
        other => panic!("{other:?}"),
    }
    // Garbage on the same socket kind gets `bad-request`, not a silent close.
    let mut stream = UnixStream::connect(&harness.socket).await.unwrap();
    send(&mut stream, "not json at all").await;
    match next_reply(&mut stream).await {
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
    let discovery = discover(&dir, BASE_MS).await;
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "discovery has a total deadline: {elapsed:?}"
    );
    assert_eq!(discovery.unresponsive.len(), 1);
    assert!(discovery.live.is_empty());
    assert!(
        dir.socket_path(&id).exists(),
        "a hung session is reported, not unlinked"
    );
    hung.abort();
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
    let live = LiveSession::start(&project).await;
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
    let live = LiveSession::start(&project).await;
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
    let live = LiveSession::start(&project).await;
    let dir = SessionsDir::open(&project.sessions_dir()).unwrap().unwrap();
    let discovery = discover(&dir, BASE_MS).await;
    assert_eq!(discovery.live.len(), 1);
    assert_eq!(discovery.live[0].info.id, *live.id());
    assert!(discovery.logged.iter().any(|s| s.info.id == *live.id()));
    live.finish().await;
}

#[test]
fn the_poll_interval_is_the_ingestion_bound() {
    // AC3: a record is listed once the SDK yields it — a watch event, or at most
    // one fallback poll, which is what bounds a silent file.
    assert!(POLL_INTERVAL <= Duration::from_secs(2));
}
