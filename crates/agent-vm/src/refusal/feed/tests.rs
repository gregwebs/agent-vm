//! The follower against a fake stream, and against the real SDK log engine over
//! a hand-written `network.log`.
//!
//! The real-engine cases matter because the properties they assert — rotation
//! without double counting, a drain to EOF after the producer stops, and a
//! persistence deadline — are properties of the *engine's* cursor and rotation
//! behaviour, not of this crate's loop. A fake stream cannot falsify them.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use microsandbox::MicrosandboxError;
use microsandbox::logs::{LogCursor, LogEntry, LogSource, LogStreamOptions, LogStreamStart};
use microsandbox_types::Protocol;

use futures::FutureExt as _;
use futures::StreamExt as _;

use super::*;
use crate::refusal::log::SessionsDir;
use crate::refusal::{Kind, SessionId, SessionInfo, SessionRefusals};

const BASE_MS: i64 = 1_760_000_000_000;
const SID: &str = "3f9a12c4";

/// A cursor for `offset`, in the engine's own wire form. Distinct offsets give
/// distinct cursors, which is what lets a test see *which* cursor was resumed.
fn cursor(offset: u64) -> LogCursor {
    let mut bytes = vec![1u8];
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&offset.to_le_bytes());
    base64::engine::general_purpose::STANDARD
        .encode(bytes)
        .parse()
        .expect("a cursor built in the engine's own encoding")
}

fn record_line(offset_secs: i64, port: u16, name: Option<&str>) -> String {
    let at = chrono::DateTime::from_timestamp_millis(BASE_MS + offset_secs * 1000).unwrap();
    let name = match name {
        Some(name) => format!(r#""name":"{name}","name_source":"sni","#),
        None => "\"name_source\":\"none\",".to_owned(),
    };
    format!(
        r#"{{"v":1,"t":"{}","s":"network","event":"refusal","site":"tls-sni","layer":"tenant","protocol":"tcp","dst_ip":"198.51.100.7","dst_port":{port},{name}"revision":1}}"#,
        at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    )
}

fn entry(data: String, offset: u64) -> LogEntry {
    LogEntry {
        timestamp: chrono::DateTime::from_timestamp_millis(BASE_MS).unwrap(),
        source: LogSource::Network,
        session_id: None,
        data: data.into_bytes().into(),
        cursor: cursor(offset),
    }
}

fn live() -> Arc<LiveRefusals> {
    Arc::new(LiveRefusals {
        state: Mutex::new(LiveState {
            session: SessionRefusals::new(SessionInfo {
                id: SessionId::parse(SID).unwrap(),
                pid: 1,
                started_ms: BASE_MS,
                socket: true,
            }),
            updates: broadcast::channel(UPDATE_BUFFER).0,
        }),
    })
}

fn dir() -> (tempfile::TempDir, SessionsDir) {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("ab12cd34ef56.sessions");
    let dir = SessionsDir::open_or_create(&path).unwrap();
    (root, dir)
}

/// An opener that yields `items` on its first call and an empty (never-ending)
/// stream afterwards, recording every option set it was given.
fn scripted(
    items: Vec<microsandbox::MicrosandboxResult<LogEntry>>,
) -> (Opener, Arc<Mutex<Vec<LogStreamOptions>>>) {
    let seen: Arc<Mutex<Vec<LogStreamOptions>>> = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&seen);
    let first = Arc::new(Mutex::new(Some(items)));
    let opener: Opener = Arc::new(move |options| {
        recorder.lock().unwrap().push(options);
        let items = first.lock().unwrap().take();
        async move {
            match items {
                Some(items) => Ok(Box::pin(futures::stream::iter(items)) as LogStream),
                None => Ok(Box::pin(futures::stream::pending()) as LogStream),
            }
        }
        .boxed()
    });
    (opener, seen)
}

/// Run `follow` until it has done its work, then stop it.
async fn drive(
    opener: Opener,
    live: Arc<LiveRefusals>,
    persist: Persister,
    hint: Arc<Hint>,
    settle: Duration,
) -> Option<LogCursor> {
    let (stop, receiver) = watch::channel(false);
    let task = tokio::spawn(follow(
        opener,
        Arc::clone(&live),
        persist.handle(),
        hint,
        receiver,
        true,
    ));
    tokio::time::sleep(settle).await;
    let _ = stop.send(true);
    task.await.expect("the follower task did not panic")
}

#[tokio::test]
async fn fake_stream_ingests_and_hints_once() {
    let (_root, dir) = dir();
    let persist = Persister::new(dir.clone());
    let opener = scripted(vec![
        Ok(entry(record_line(1, 443, Some("cdn.example")), 10)),
        Ok(entry(record_line(2, 443, Some("cdn.example")), 20)),
        Ok(entry(
            r#"{"v":1,"t":"2025-10-09T09:33:24.000Z","s":"network","event":"suppressed","site":"udp","count":7}"#.to_owned(),
            30,
        )),
        Ok(entry(record_line(4, 8443, Some("other.example")), 40)),
    ])
    .0;
    let live = live();
    let (hint, lines) = Hint::capture();
    let hint = Arc::new(hint);

    let cursor = drive(
        opener,
        Arc::clone(&live),
        persist,
        Arc::clone(&hint),
        Duration::from_millis(200),
    )
    .await;

    let snapshot = live.snapshot();
    assert_eq!(snapshot.entries.len(), 2, "one entry per destination");
    assert_eq!(snapshot.entries[0].count, 2);
    assert_eq!(snapshot.suppressed, 7);
    assert!(hint.fired(), "the hint fires at the first refusal");
    // Three refusals were folded in; exactly one line was emitted. A flag would
    // say the same thing whether the sink had been written once or five times.
    let lines = lines.lock().unwrap();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0], HINT);
    assert_eq!(
        cursor,
        Some(cursor_for(40)),
        "the cursor tracks the last entry read, decodable or not"
    );
}

/// The cursor of the last entry in [`fake_stream_ingests_and_hints_once`].
fn cursor_for(offset: u64) -> LogCursor {
    cursor(offset)
}

#[tokio::test]
async fn records_before_session_start_are_ignored() {
    let (_root, dir) = dir();
    let persist = Persister::new(dir.clone());
    // Before `BASE_MS`, which is when this session started.
    let stale = record_line(-5, 443, None);
    let opener = scripted(vec![Ok(entry(stale, 10))]).0;
    let live = live();
    let hint = Arc::new(Hint::new());
    let cursor = drive(
        opener,
        Arc::clone(&live),
        persist,
        Arc::clone(&hint),
        Duration::from_millis(150),
    )
    .await;
    assert!(live.snapshot().entries.is_empty());
    assert_eq!(live.snapshot().rev, 0);
    assert!(!hint.fired(), "no entry, no hint");
    assert!(cursor.is_some(), "the line was still consumed");
}

/// A *general* I/O error leaves the cursor valid, so following resumes from it.
/// This is the arm that keeps a healthy stream from being re-read from the
/// beginning after one transient failure.
#[tokio::test]
async fn a_generic_error_resumes_from_the_last_cursor() {
    let (_root, dir) = dir();
    let persist = Persister::new(dir.clone());
    let (opener, seen) = scripted(vec![
        Ok(entry(record_line(1, 443, None), 10)),
        Err(MicrosandboxError::Io(std::io::Error::other(
            "the log file went away",
        ))),
    ]);
    let live = live();
    let hint = Arc::new(Hint::new());
    drive(
        opener,
        Arc::clone(&live),
        persist,
        hint,
        Duration::from_millis(1_600),
    )
    .await;

    let seen = seen.lock().unwrap();
    assert!(seen.len() >= 2, "the stream was reopened");
    assert!(matches!(seen[0].start, LogStreamStart::Beginning));
    assert!(
        matches!(&seen[1].start, LogStreamStart::From(cursor) if *cursor == cursor_for(10)),
        "a general error resumes from the last cursor, not the beginning: {:?}",
        seen[1].start
    );
    assert!(live.snapshot().gap, "the failure is still visible as a gap");
    assert_eq!(live.snapshot().entries.len(), 1, "nothing was re-read");
}

/// An invalid cursor means the file being read has left the retention chain, so
/// every retained file is newer: reopening from the beginning cannot double
/// count.
#[tokio::test]
async fn an_invalid_cursor_reopens_from_the_beginning() {
    let (_root, dir) = dir();
    let persist = Persister::new(dir.clone());
    let (opener, seen) = scripted(vec![
        Ok(entry(record_line(1, 443, None), 10)),
        Err(MicrosandboxError::InvalidCursor("stale".to_owned())),
    ]);
    let live = live();
    let hint = Arc::new(Hint::new());
    drive(
        opener,
        Arc::clone(&live),
        persist,
        hint,
        Duration::from_millis(1_600),
    )
    .await;

    let seen = seen.lock().unwrap();
    assert!(seen.len() >= 2, "the stream was reopened");
    assert!(matches!(seen[0].start, LogStreamStart::Beginning));
    // A missed rotation or an invalid cursor leaves only *newer* files, so the
    // reopen starts at the beginning instead of resuming a dead position.
    assert!(
        matches!(seen[1].start, LogStreamStart::Beginning),
        "an invalid cursor reopens from the beginning: {:?}",
        seen[1].start
    );
    assert_eq!(
        seen[0].sources,
        vec![LogSource::Network],
        "the feed reads only refusal records"
    );
    // A gap is marked, and counted as unknown rather than guessed.
    assert!(live.snapshot().gap);
    assert_eq!(live.snapshot().entries.len(), 1);
}

#[tokio::test]
async fn gap_only_change_notifies_and_dirties() {
    let (_root, dir) = dir();
    let persist = Persister::new(dir.clone());
    let opener = scripted(vec![Err(MicrosandboxError::MissedRotation {
        dropped_from_offset: 3,
    })])
    .0;
    let live = live();
    let mut updates = live.lock().updates.subscribe();
    let hint = Arc::new(Hint::new());
    drive(
        opener,
        Arc::clone(&live),
        persist,
        Arc::clone(&hint),
        Duration::from_millis(1_600),
    )
    .await;
    assert!(live.snapshot().gap, "the gap is recorded");
    assert!(live.snapshot().entries.is_empty());
    // The gap was published, so a subscriber sees it without re-reading the list.
    let update = updates.try_recv().expect("a gap update was published");
    assert!(update.gap);
    assert!(update.entry.is_none());
    assert!(!hint.fired(), "a gap is not a refusal");
}

#[tokio::test]
async fn open_failure_degrades_without_error() {
    let (_root, dir) = dir();
    let persist = Persister::new(dir.clone());
    let attempts = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&attempts);
    let opener: Opener = Arc::new(move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
        async move { Err(MicrosandboxError::InvalidCursor("no stream".to_owned())) }.boxed()
    });
    let live = live();
    let hint = Arc::new(Hint::new());
    let (stop, receiver) = watch::channel(false);
    let task = tokio::spawn(follow(
        opener,
        Arc::clone(&live),
        persist.handle(),
        hint,
        receiver,
        true,
    ));
    let cursor = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("following stops on its own instead of spinning")
        .expect("no panic");
    let _ = stop.send(true);
    assert!(cursor.is_none());
    assert!(attempts.load(Ordering::SeqCst) >= 2, "it did retry");
    assert!(live.snapshot().gap, "the failure is visible as a gap");
}

/// AC3's persistence bound is measured from *ingestion*, and it holds even when
/// the stream never opens again: repeated open failures, the resume budget
/// running out and the pause between attempts are exactly when a dirty record
/// used to sit unposted, because the ticker only lived inside an open stream.
#[tokio::test]
async fn a_dirty_record_is_persisted_within_two_seconds_however_the_stream_fails() {
    let (_root, dir) = dir();
    let persist = Persister::new(dir.clone());
    let live = live();
    let hint = Arc::new(Hint::new());
    let opened = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&opened);
    let opener: Opener = Arc::new(move |_options| {
        let nth = counter.fetch_add(1, Ordering::SeqCst);
        async move {
            if nth == 0 {
                // One refusal, then the stream dies and every reopen fails.
                Ok(Box::pin(futures::stream::iter(vec![
                    Ok(entry(record_line(1, 443, None), 10)),
                    Err(MicrosandboxError::InvalidCursor("stale".to_owned())),
                ])) as LogStream)
            } else {
                Err(MicrosandboxError::InvalidCursor("no stream".to_owned()))
            }
        }
        .boxed()
    });
    let (stop, receiver) = watch::channel(false);
    let task = tokio::spawn(follow(
        opener,
        Arc::clone(&live),
        persist.handle(),
        hint,
        receiver,
        true,
    ));

    let ingested = loop {
        if !live.snapshot().entries.is_empty() {
            break std::time::Instant::now();
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    };
    let written = loop {
        let persisted = dir
            .read()
            .unwrap()
            .sessions
            .iter()
            .any(|session| session.info.id.as_str() == SID && !session.entries.is_empty());
        if persisted {
            break std::time::Instant::now();
        }
        assert!(
            std::time::Instant::now().duration_since(ingested) < POST_INTERVAL,
            "the record was still unposted {POST_INTERVAL:?} after ingestion"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    let trailed = written.duration_since(ingested);
    assert!(
        trailed <= POST_INTERVAL,
        "the log trailed ingestion by {trailed:?}"
    );

    // The write happened *while* the stream was failing, not after it recovered:
    // the follower then exhausts its reopen budget and the pauses it sleeps are
    // the ones that used to run without a ticker.
    let cursor = tokio::time::timeout(Duration::from_secs(15), task)
        .await
        .expect("following stops on its own")
        .expect("no panic");
    assert!(cursor.is_some(), "the one entry was read");
    assert!(
        opened.load(Ordering::SeqCst) >= 3,
        "the open-failure path ran: {} opens",
        opened.load(Ordering::SeqCst)
    );
    assert!(live.snapshot().gap, "the failures are visible as a gap");
    let _ = stop.send(true);
}

/// A record the runtime wrote in a shape this build cannot decode is a gap, not
/// silence: whether it was a refusal is unknown, and a session that hid that
/// would understate what it refused.
#[tokio::test]
async fn an_undecodable_record_marks_a_gap() {
    let (_root, dir) = dir();
    let persist = Persister::new(dir.clone());
    let opener = scripted(vec![
        // A newer format version, and an event tag these enums do not carry:
        // `serde` has no `#[serde(other)]`, so the whole record fails to decode.
        Ok(entry(
            r#"{"v":2,"t":"2025-10-09T09:33:24.000Z","s":"network","event":"quota"}"#.to_owned(),
            10,
        )),
        Ok(entry(record_line(2, 443, None), 20)),
    ])
    .0;
    let live = live();
    let hint = Arc::new(Hint::new());
    let cursor = drive(
        opener,
        Arc::clone(&live),
        persist,
        Arc::clone(&hint),
        Duration::from_millis(200),
    )
    .await;
    assert!(live.snapshot().gap, "the undecodable line is a gap");
    assert_eq!(
        live.snapshot().entries.len(),
        1,
        "the decodable line after it is still read"
    );
    assert_eq!(cursor, Some(cursor_for(20)));
}

// -- the persister ---------------------------------------------------------

fn snapshot(rev: u64, ended: bool) -> crate::refusal::SessionSnapshot {
    let mut snapshot = crate::refusal::SessionSnapshot::new(SessionInfo {
        id: SessionId::parse(SID).unwrap(),
        pid: 1,
        started_ms: BASE_MS,
        socket: true,
    });
    snapshot.rev = rev;
    if ended {
        snapshot.ended_ms = Some(BASE_MS + 1);
    }
    snapshot
}

#[test]
fn an_older_snapshot_never_overwrites_the_final() {
    let (_root, dir) = dir();
    let persist = Persister::new(dir.clone());
    persist.post(snapshot(1, false));
    persist.post(snapshot(2, false));
    let final_wait = persist.post_final(snapshot(3, true));
    assert!(final_wait.wait(FINAL_WAIT), "the final write landed");
    // A post after the final one is ignored, however new it claims to be.
    persist.post(snapshot(9, false));
    std::thread::sleep(Duration::from_millis(100));
    let log = dir.read().unwrap();
    let mine = log
        .sessions
        .iter()
        .find(|session| session.info.id.as_str() == SID)
        .expect("written");
    assert_eq!(mine.rev, 3);
    assert!(mine.ended_ms.is_some());
}

/// `post` and `post_final` share one slot, so a dirty tick that lands between the
/// final offer and the final write must not replace it: the record that says the
/// session ended is the one a reader needs.
///
/// The window is made deterministic by keeping the writer busy: it is stuck
/// writing an earlier snapshot while the final is *offered* and the second post
/// arrives, so the final is still only pending when the second post would replace
/// it.
#[test]
fn a_post_cannot_displace_a_pending_final() {
    let (_root, dir) = dir();
    let held = crate::host_paths::open_lock_file(&dir.path().join("refusals.lock")).unwrap();
    crate::host_paths::flock_exclusive(&held).unwrap();
    let persist = Persister::new(dir.clone());
    // The writer takes this job and blocks in the log's own lock, leaving the
    // pending slot free for the two below.
    persist.post(snapshot(0, false));
    std::thread::sleep(Duration::from_millis(100));
    let wait = persist.post_final(snapshot(1, true));
    persist.post(snapshot(2, false));
    std::thread::sleep(Duration::from_millis(50));
    drop(held);
    assert!(wait.wait(FINAL_WAIT), "the final write landed");
    let log = dir.read().unwrap();
    let mine = log
        .sessions
        .iter()
        .find(|session| session.info.id.as_str() == SID)
        .expect("written");
    assert_eq!(mine.rev, 1, "the post did not replace the final record");
    assert!(mine.ended_ms.is_some());
}

#[test]
fn drop_does_not_block() {
    let (_root, dir) = dir();
    // Hold the log's own lock so the writer thread is stuck waiting for it.
    let held = crate::host_paths::open_lock_file(&dir.path().join("refusals.lock")).unwrap();
    crate::host_paths::flock_exclusive(&held).unwrap();
    let persist = Persister::new(dir.clone());
    persist.post_final(snapshot(1, true));
    std::thread::sleep(Duration::from_millis(50));
    let started = std::time::Instant::now();
    drop(persist);
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "dropping a persister must not wait for the disk ({:?})",
        started.elapsed()
    );
    let _ = crate::host_paths::try_flock(&held, crate::host_paths::FlockMode::Exclusive);
}

#[test]
fn final_wait_is_bounded_with_a_held_lock() {
    let (_root, dir) = dir();
    let held = crate::host_paths::open_lock_file(&dir.path().join("refusals.lock")).unwrap();
    crate::host_paths::flock_exclusive(&held).unwrap();
    let persist = Persister::new(dir.clone());
    let wait = persist.post_final(snapshot(1, true));
    let started = std::time::Instant::now();
    let finished = wait.wait(Duration::from_millis(200));
    let elapsed = started.elapsed();
    assert!(
        !finished,
        "the write could not land while the lock was held"
    );
    assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
    drop(held);
}

// -- the real SDK engine, no VM --------------------------------------------

/// A real `LocalBackend` over a temp home, with a hand-written `network.log` for
/// `name`. No DB row and no VM: the log engine only needs the directory.
fn real_engine_home(name: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let home = tempfile::tempdir().unwrap();
    let logs = home.path().join("sandboxes").join(name).join("logs");
    std::fs::create_dir_all(&logs).unwrap();
    (home, logs)
}

fn backend(home: &std::path::Path) -> Arc<dyn microsandbox::Backend> {
    Arc::new(
        microsandbox::LocalBackend::builder()
            .home(home)
            .build_lazy()
            .expect("a local backend over a temp home"),
    )
}

/// The production opener's shape, over the SDK's public stream entry point: the
/// scoped backend is what makes it read *this* home, and no `Sandbox` is needed
/// because the log engine only reads the directory.
///
/// The scope is established *here*, inside whatever task calls the opener, not
/// around the test body: a task-local installed around a `spawn` is not reliably
/// visible to the spawned task, and the feed is always a spawned task.
fn public_opener(name: &str, backend: Arc<dyn microsandbox::Backend>) -> Opener {
    let name = name.to_owned();
    Arc::new(move |options: LogStreamOptions| {
        let name = name.clone();
        let backend = Arc::clone(&backend);
        async move {
            microsandbox::with_backend(backend, async move {
                let stream = microsandbox::logs::log_stream(&name, &options).await?;
                Ok(Box::pin(stream) as LogStream)
            })
            .await
        }
        .boxed()
    })
}

#[tokio::test]
async fn missed_rotation_reopens_without_double_counting() {
    const NAME: &str = "agent-vm-refusal-rotation";
    let (home, logs) = real_engine_home(NAME);
    let backend = backend(home.path());
    let live = live();
    let hint = Arc::new(Hint::new());
    let (_root, dir) = dir();
    let persist = Persister::new(dir.clone());

    microsandbox::with_backend(Arc::clone(&backend), async {
        std::fs::write(
            logs.join("network.log"),
            format!(
                "{}\n{}\n",
                record_line(1, 1001, None),
                record_line(2, 1002, None)
            ),
        )
        .unwrap();
        let (stop, receiver) = watch::channel(false);
        let task = tokio::spawn(follow(
            public_opener(NAME, Arc::clone(&backend)),
            Arc::clone(&live),
            persist.handle(),
            Arc::clone(&hint),
            receiver,
            true,
        ));
        // Wait for both lines to land, then rotate the live file out of the
        // retention chain and start a new one with two more.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while live.snapshot().entries.len() < 2 && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(live.snapshot().entries.len(), 2, "both lines were ingested");
        std::fs::rename(logs.join("network.log"), logs.join("network.log.gone")).unwrap();
        std::fs::write(
            logs.join("network.log"),
            format!(
                "{}\n{}\n",
                record_line(3, 1003, None),
                record_line(4, 1004, None)
            ),
        )
        .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while live.snapshot().entries.len() < 4 && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let _ = stop.send(true);
        let _ = task.await;
    })
    .await;

    let snapshot = live.snapshot();
    assert_eq!(
        snapshot.entries.len(),
        4,
        "four distinct destinations, none counted twice: {:?}",
        snapshot
            .entries
            .iter()
            .map(|entry| entry.key.destination.clone())
            .collect::<Vec<_>>()
    );
    for entry in &snapshot.entries {
        assert_eq!(
            entry.count, 1,
            "a re-read from the beginning must not double count"
        );
        assert_eq!(entry.key.kind, Kind::NetworkDenial);
    }
    assert!(
        snapshot.gap,
        "the rotation was reported as a gap, not as silence"
    );
}

#[tokio::test]
async fn finish_drains_lines_written_after_the_last_poll() {
    const NAME: &str = "agent-vm-refusal-drain";
    let (home, logs) = real_engine_home(NAME);
    let backend = backend(home.path());
    let path = logs.join("network.log");

    microsandbox::with_backend(Arc::clone(&backend), async {
        std::fs::write(&path, format!("{}\n", record_line(1, 2001, None))).unwrap();
        let live = live();
        let (_root, dir) = dir();
        let persist = Persister::new(dir.clone());
        let (stop, receiver) = watch::channel(false);
        let task = tokio::spawn(follow(
            public_opener(NAME, Arc::clone(&backend)),
            Arc::clone(&live),
            persist.handle(),
            Arc::new(Hint::new()),
            receiver,
            true,
        ));
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while live.snapshot().entries.is_empty() && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let _ = stop.send(true);
        let cursor = task
            .await
            .unwrap()
            .expect("the follower had read at least one entry");

        // The producer wrote two more lines while the follower was stopping.
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        use std::io::Write as _;
        write!(
            file,
            "{}\n{}\n",
            record_line(2, 2002, None),
            record_line(3, 2003, None)
        )
        .unwrap();
        file.sync_all().unwrap();

        // `finish`'s drain: the same engine, from the cursor, not following.
        let drained = microsandbox::logs::log_stream(
            NAME,
            &LogStreamOptions {
                sources: vec![LogSource::Network],
                start: LogStreamStart::From(cursor),
                until: None,
                follow: false,
            },
        )
        .await
        .expect("the drain opens");
        let mut drain = Box::pin(drained);
        let mut ports = Vec::new();
        while let Some(item) = drain.next().await {
            let entry = item.expect("a drained entry");
            let record: microsandbox::logs::NetworkLogRecord =
                serde_json::from_slice(&entry.data).unwrap();
            if let microsandbox::logs::NetworkLogEvent::Refusal(refusal) = record.event {
                ports.push(refusal.dst_port);
            }
        }
        assert_eq!(
            ports,
            vec![Some(2002), Some(2003)],
            "the lines written after the last poll are exactly what the drain returns"
        );
    })
    .await;
}

/// The whole path, real engine and real log: a line written to the runtime's
/// file reaches the project log within AC3's two seconds — measured from the
/// moment the follower *ingested* it, not from the moment the file appeared,
/// because the runtime's own poll (up to two seconds) is ingestion and the
/// deadline is about what happens after it.
#[tokio::test]
async fn a_line_reaches_the_log_within_two_seconds_of_ingestion() {
    const NAME: &str = "agent-vm-refusal-persist";
    let (home, logs) = real_engine_home(NAME);
    let backend = backend(home.path());
    let live = live();
    let (_root, dir) = dir();
    let persist = Persister::new(dir.clone());

    microsandbox::with_backend(Arc::clone(&backend), async {
        let task_start = std::time::Instant::now();
        let (stop, receiver) = watch::channel(false);
        let task = tokio::spawn(follow(
            public_opener(NAME, Arc::clone(&backend)),
            Arc::clone(&live),
            persist.handle(),
            Arc::new(Hint::new()),
            receiver,
            true,
        ));
        std::fs::write(
            logs.join("network.log"),
            format!("{}\n", record_line(1, 3001, None)),
        )
        .unwrap();
        let ingested = loop {
            if !live.snapshot().entries.is_empty() {
                break std::time::Instant::now();
            }
            assert!(
                task_start.elapsed() < Duration::from_secs(30),
                "the runtime's own stream never yielded the line"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        loop {
            let persisted = dir
                .read()
                .unwrap()
                .sessions
                .iter()
                .any(|session| session.info.id.as_str() == SID && !session.entries.is_empty());
            if persisted {
                break;
            }
            let trailed = std::time::Instant::now().duration_since(ingested);
            assert!(
                trailed < POST_INTERVAL,
                "the log trailed ingestion by {trailed:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            ingested.duration_since(task_start) <= Duration::from_secs(2),
            "ingestion itself is bounded by one fallback poll: {:?}",
            ingested.duration_since(task_start)
        );
        let _ = stop.send(true);
        let _ = task.await;
    })
    .await;
    assert_eq!(live.snapshot().entries.len(), 1);
    assert_eq!(live.snapshot().entries[0].key.kind, Kind::NetworkDenial);
    // The decode went through the runtime's own record type.
    assert!(record_line(1, 3001, None).contains("tls-sni"));
    let _ = Protocol::Tcp;
}
