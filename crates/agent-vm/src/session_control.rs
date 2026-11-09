//! The launcher's per-session control socket, and the one place a launch's
//! refusal feed lives.
//!
//! The launcher owns the socket and the CLI is a thin client (agent-vm#301): a
//! Unix socket in a host-only directory, peer-UID checked, never TCP — because
//! `--allow-host` exposes host loopback. The protocol is revisioned NDJSON so a
//! later GUI can use the same interface, and `subscribe`'s snapshot and
//! subscription are taken under the ingest lock, so an update can be neither lost
//! nor repeated across the handoff.
//!
//! Nothing here may fail a launch (AC14). Every failure degrades: no socket (one
//! notice), no log (one notice), a stalled subscriber (dropped), a path over the
//! kernel's `sun_path` budget (one notice, launch continues). The VM always
//! outranks its record.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use anyhow::{Context as _, Result};
use futures::StreamExt as _;
use microsandbox::Sandbox;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, broadcast, watch};
use tokio::task::JoinSet;

use crate::refusal::feed::{self, Hint, LiveRefusals, LogStream, Opener, Persister};
use crate::refusal::log::SessionsDir;
use crate::refusal::{SessionId, SessionInfo, SessionRefusals, SessionSnapshot, Update};
use crate::session::ProjectSession;

/// Protocol version. Additive changes keep it; a client that asks for another
/// version gets `unsupported-version` and the list of versions this build speaks.
pub(crate) const PROTOCOL_VERSION: u32 = 1;

/// A request is one short JSON line. Anything longer is not a request.
const MAX_REQUEST_BYTES: usize = 4 * 1024;
/// Per-line deadline for a client that connects and then says nothing, and for
/// one that stops reading. A subscriber that does not read is dropped rather
/// than allowed to pin a slot.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(2);
/// At most this many connections at once, of which at most [`MAX_SUBSCRIBERS`]
/// may be subscribers: `list` always has a slot, so a monitoring tool cannot lock
/// out the command a user just ran.
const MAX_CONNECTIONS: usize = 16;
const MAX_SUBSCRIBERS: usize = 16 - 4;
/// How long `finish` waits for open connections after telling them the session
/// ended, before aborting them.
const CONNECTION_GRACE: Duration = Duration::from_millis(500);

/// A notice that must not delay a launch or a teardown.
fn notice(message: impl std::fmt::Display) {
    drop(crate::launch_notice::LaunchNotices::to_stderr().emit_detached(message));
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// One launch's refusal feed, socket and log.
///
/// Constructed before `Sandbox::create` (AC9) so a session that is still
/// starting cannot miss a change aimed at it, and torn down from exactly one
/// place ([`crate::teardown::ExecTeardown::before_remove`]).
pub(crate) struct LiveSession {
    info: SessionInfo,
    live: Option<Arc<LiveRefusals>>,
    persister: Option<Persister>,
    /// The opener the follower and the drain share: a `Sandbox` clone behind an
    /// `Arc<dyn Fn>`, so both can hold it.
    open: Mutex<Option<Opener>>,
    running: Mutex<Option<Running>>,
    following: Mutex<Option<Following>>,
    finished: AtomicBool,
}

/// What a bound socket needs to be served and then closed.
struct Running {
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
    socket: PathBuf,
}

/// A running follower.
struct Following {
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<Option<microsandbox::logs::LogCursor>>,
}

impl LiveSession {
    /// Reserve a session ID, bind the socket and open the log.
    ///
    /// Never fails: a launch whose refusal record cannot be kept still runs, with
    /// one notice saying what is missing.
    pub(crate) async fn start(session: &ProjectSession) -> Self {
        let path = session.sessions_dir();
        let info = SessionInfo {
            id: SessionId::generate(),
            pid: std::process::id(),
            started_ms: feed::now_ms(),
            socket: false,
        };
        let dir = match SessionsDir::open_or_create(&path) {
            Ok(dir) => dir,
            Err(error) => {
                notice(format!("==> Refusals are not recorded: {error}"));
                return Self::degraded(info);
            }
        };
        let socket = dir.socket_path(&info.id);
        if !crate::msb_install::unix_socket_path_fits(&socket) {
            notice(format!(
                "==> Refusals are recorded but not served live: {} is longer than a Unix \
                 socket path allows. Set a shorter AGENT_VM_STATE_DIR to get live refusals.",
                crate::one_line::path(&socket)
            ));
            return Self::with_dir(
                &dir,
                SessionInfo {
                    socket: false,
                    ..info
                },
            );
        }

        // Binding happens inside the reservation, so a name another session still
        // holds is redrawn rather than adopted.
        let reserved = match dir.reserve(info.started_ms, info.pid, true, |id| {
            UnixListener::bind(dir.socket_path(id))
        }) {
            Ok(Some(reserved)) => reserved,
            Ok(None) => {
                notice("==> Refusals are not recorded: the project's refusal log is busy");
                return Self::with_dir(
                    &dir,
                    SessionInfo {
                        socket: false,
                        ..info
                    },
                );
            }
            Err(error) => {
                notice(format!(
                    "==> Refusals are recorded but not served live: {error:#}"
                ));
                return Self::with_dir(
                    &dir,
                    SessionInfo {
                        socket: false,
                        ..info
                    },
                );
            }
        };
        let bound_socket = dir.socket_path(&reserved.snapshot.info.id);
        if let Err(error) = set_socket_mode(&bound_socket) {
            notice(format!(
                "==> Refusals are recorded but not served live: {error:#}"
            ));
            let _ = std::fs::remove_file(&bound_socket);
            return Self::with_dir(
                &dir,
                SessionInfo {
                    socket: false,
                    ..info
                },
            );
        }
        let listening = LiveRefusals::new(SessionRefusals::resume(reserved.snapshot.clone()));
        let persister = Persister::new(dir.clone());
        let (stop, receiver) = watch::channel(false);
        let task = tokio::spawn(serve(reserved.bound, Arc::clone(&listening), receiver));
        Self {
            info: reserved.snapshot.info,
            live: Some(listening),
            persister: Some(persister),
            open: Mutex::new(None),
            running: Mutex::new(Some(Running {
                stop,
                task,
                socket: bound_socket,
            })),
            following: Mutex::new(None),
            finished: AtomicBool::new(false),
        }
    }

    fn degraded(info: SessionInfo) -> Self {
        Self {
            info,
            live: None,
            persister: None,
            open: Mutex::new(None),
            running: Mutex::new(None),
            following: Mutex::new(None),
            finished: AtomicBool::new(false),
        }
    }

    /// The log without a socket: the feed still runs, `access` still lists it.
    fn with_dir(dir: &SessionsDir, info: SessionInfo) -> Self {
        let live = LiveRefusals::new(SessionRefusals::new(info.clone()));
        let persister = Persister::new(dir.clone());
        // The session's empty record is written now, so `access --session` can
        // name a session that exists but has refused nothing yet.
        persister.post(live.snapshot());
        Self {
            info,
            live: Some(live),
            persister: Some(persister),
            open: Mutex::new(None),
            running: Mutex::new(None),
            following: Mutex::new(None),
            finished: AtomicBool::new(false),
        }
    }

    /// The session's own ID. Read by the teardown tests and by any caller that
    /// needs to name this session before it has refused anything.
    #[cfg(test)]
    pub(crate) fn id(&self) -> &SessionId {
        &self.info.id
    }

    /// Start following the sandbox's `network.log`.
    ///
    /// Called right after the sandbox exists: the producer is the runtime, so
    /// following before it has written anything is the only way not to lose the
    /// first refusal.
    pub(crate) fn follow(&self, sandbox: &Sandbox) {
        let (Some(live), Some(persister)) = (self.live.as_ref().cloned(), self.persister.as_ref())
        else {
            return;
        };
        let sandbox = sandbox.clone();
        let open: Opener = Arc::new(move |options| {
            let sandbox = sandbox.clone();
            Box::pin(async move {
                let stream = sandbox.log_stream(&options).await?;
                Ok(Box::pin(stream) as LogStream)
            })
        });
        *lock(&self.open) = Some(Arc::clone(&open));
        let (stop, receiver) = watch::channel(false);
        let task = tokio::spawn(feed::follow(
            open,
            Arc::clone(&live),
            persister.handle(),
            Arc::new(Hint::new()),
            receiver,
            self.info.socket,
        ));
        *lock(&self.following) = Some(Following { stop, task });
    }

    /// Stop the producer, drain what it wrote, persist, then close the socket.
    ///
    /// The order is the point (§6.4): draining before the persist keeps the
    /// runtime's last writes, and persisting before the broadcast means a reader
    /// never sees an entry without the `ended` that follows it. Idempotent,
    /// because teardown can arrive twice.
    pub(crate) async fn finish(&self) {
        if self.finished.swap(true, Ordering::SeqCst) {
            return;
        }
        let Some(live) = self.live.clone() else {
            self.close_socket().await;
            return;
        };
        // 1–2. Stop the follower, then drain from its last cursor to end of file.
        let following = lock(&self.following).take();
        if let Some(following) = following {
            let _ = following.stop.send(true);
            let cursor = following.task.await.ok().flatten();
            self.drain(&live, cursor).await;
        }
        // 3. The final snapshot, written before any reader is told it ended.
        let snapshot = live.ended(feed::now_ms());
        if let Some(persister) = &self.persister {
            let _ = persister.post_final(snapshot).wait(feed::FINAL_WAIT);
        }
        // 4–5. Tell subscribers, close, unlink.
        self.close_socket().await;
    }

    /// One non-following read from `cursor` to the end of the runtime's file.
    ///
    /// Best effort: a drain that fails leaves the entries already ingested, which
    /// is the same outcome as a runtime that never flushed.
    async fn drain(&self, live: &Arc<LiveRefusals>, cursor: Option<microsandbox::logs::LogCursor>) {
        let Some(open) = lock(&self.open).clone() else {
            return;
        };
        let options = feed::drain_options(cursor);
        let Ok(mut stream) = open(options).await else {
            return;
        };
        // A drain must terminate: the stream was opened without `follow`, so it
        // ends at EOF. The bound is for a runtime whose file never closes.
        let mut dirty = false;
        let mut cursor = None;
        let hint = Arc::new(Hint::new());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            let next = tokio::time::timeout_at(deadline, stream.next()).await;
            match next {
                // The drain is the last chance to see these records, so the hint
                // fires here too — a refusal the operator never saw live is still
                // a refusal they should be told to look at.
                Ok(Some(Ok(entry))) => feed::accept(entry, live, &hint, &mut dirty, &mut cursor),
                Ok(Some(Err(_))) | Ok(None) | Err(_) => break,
            }
        }
    }

    async fn close_socket(&self) {
        let running = lock(&self.running).take();
        if let Some(running) = running {
            let _ = running.stop.send(true);
            let _ = tokio::time::timeout(CONNECTION_GRACE + EXCHANGE_TIMEOUT, running.task).await;
            let _ = std::fs::remove_file(&running.socket);
        }
    }
}

/// The one peer check: this process's own uid, and nothing else.
fn peer_is_allowed(peer_uid: u32, euid: u32) -> bool {
    peer_uid == euid
}

fn set_socket_mode(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("setting the mode of {}", crate::one_line::path(path)))
}

impl Drop for LiveSession {
    /// Nonblocking: a launch that errors before `create`, or a non-direct
    /// `live_launch_result` failure, never reaches a teardown, so the follower and
    /// the socket are released here instead. The socket is unlinked by the accept
    /// loop when it observes the stop.
    fn drop(&mut self) {
        if self.finished.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Some(following) = lock(&self.following).take() {
            let _ = following.stop.send(true);
        }
        if let Some(running) = lock(&self.running).take() {
            let _ = running.stop.send(true);
            // The accept loop exits when it observes the stop, but nothing here
            // can await it: unlink now, so a launch that errors early leaves no
            // socket behind for the next `access` to dial. Unlinking a bound
            // socket is safe — the listener keeps working, and a *new* dial gets
            // ENOENT, which is what a session that is gone should answer.
            let _ = std::fs::remove_file(&running.socket);
        }
    }
}

// -- protocol --------------------------------------------------------------

/// One request line.
#[derive(Debug, Deserialize)]
struct Request {
    v: u32,
    op: String,
}

/// One reply line. `v` is on every variant so a client can refuse a newer
/// server's reply instead of guessing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "kebab-case")]
pub(crate) enum Reply {
    /// A `list` answer: the whole session, then the server closes.
    Session { v: u32, session: SessionSnapshot },
    /// The `subscribe` handoff: the snapshot the subscription starts from.
    Snapshot { v: u32, session: SessionSnapshot },
    /// One absolute change since the client's last `rev`.
    Update { v: u32, update: Update },
    /// The session ended; the server then closes.
    Ended { v: u32 },
    /// A request this server cannot answer.
    Error {
        v: u32,
        code: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        supported: Option<Vec<u32>>,
    },
}

impl Reply {
    fn encode(&self) -> Vec<u8> {
        let mut line = serde_json::to_vec(self).unwrap_or_else(|_| b"{}".to_vec());
        line.push(b'\n');
        line
    }
}

fn error(code: &str) -> Reply {
    Reply::Error {
        v: PROTOCOL_VERSION,
        code: code.to_owned(),
        supported: None,
    }
}

/// Serve `list` and `subscribe` until `stop` is set.
///
/// Connections run in a `JoinSet` off the accept loop, so one client that stops
/// reading cannot stop the next client from connecting.
async fn serve(listener: UnixListener, live: Arc<LiveRefusals>, mut stop: watch::Receiver<bool>) {
    let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let subscribers = Arc::new(Semaphore::new(MAX_SUBSCRIBERS));
    let mut tasks: JoinSet<()> = JoinSet::new();
    loop {
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else {
                    // A failed accept on a listening socket is transient (EMFILE,
                    // a client that vanished). Keep serving.
                    continue;
                };
                let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
                    // Every slot is busy. Refusing is what keeps a monitoring
                    // tool from starving `access`; the client sees EOF.
                    continue;
                };
                let live = Arc::clone(&live);
                let subscribers = Arc::clone(&subscribers);
                tasks.spawn(async move {
                    let _permit = permit;
                    handle_connection(stream, live, subscribers).await;
                });
            }
            // Reap finished connections so the set does not grow forever.
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
    drop(listener);
    let deadline = tokio::time::Instant::now() + CONNECTION_GRACE;
    while !tasks.is_empty() {
        if tokio::time::timeout_at(deadline, tasks.join_next())
            .await
            .is_err()
        {
            tasks.abort_all();
            break;
        }
    }
}

async fn handle_connection(
    stream: UnixStream,
    live: Arc<LiveRefusals>,
    subscribers: Arc<Semaphore>,
) {
    // The peer must be this user. A socket in a 0700 directory is already
    // unreachable by another user; this is the check the kernel can make, not a
    // promise about the filesystem's mode.
    let Ok(credentials) = stream.peer_cred() else {
        return;
    };
    if !peer_is_allowed(credentials.uid(), crate::host_paths::current_euid()) {
        return;
    }
    let mut reader = BufReader::new(stream);
    let mut request = Vec::new();
    let read = tokio::time::timeout(EXCHANGE_TIMEOUT, async {
        let mut limited = (&mut reader).take(MAX_REQUEST_BYTES as u64 + 1);
        limited.read_until(b'\n', &mut request).await
    })
    .await;
    if !matches!(read, Ok(Ok(_))) {
        return;
    }
    let mut writer = reader.into_inner();
    if request.len() > MAX_REQUEST_BYTES {
        let _ = write_reply(&mut writer, &error("bad-request")).await;
        return;
    }
    let Ok(request) = serde_json::from_slice::<Request>(&request) else {
        let _ = write_reply(&mut writer, &error("bad-request")).await;
        return;
    };
    if request.v != PROTOCOL_VERSION {
        let reply = Reply::Error {
            v: PROTOCOL_VERSION,
            code: "unsupported-version".to_owned(),
            supported: Some(vec![PROTOCOL_VERSION]),
        };
        let _ = write_reply(&mut writer, &reply).await;
        return;
    }
    match request.op.as_str() {
        "list" => {
            let reply = Reply::Session {
                v: PROTOCOL_VERSION,
                session: live.snapshot(),
            };
            let _ = write_reply(&mut writer, &reply).await;
        }
        "subscribe" => {
            let Ok(_slot) = Arc::clone(&subscribers).try_acquire_owned() else {
                let _ = write_reply(&mut writer, &error("too-many-subscribers")).await;
                return;
            };
            subscribe_connection(&mut writer, &live).await;
        }
        _ => {
            let _ = write_reply(&mut writer, &error("bad-request")).await;
        }
    }
}

async fn write_reply(stream: &mut UnixStream, reply: &Reply) -> std::io::Result<()> {
    let bytes = reply.encode();
    match tokio::time::timeout(EXCHANGE_TIMEOUT, async {
        stream.write_all(&bytes).await?;
        stream.flush().await
    })
    .await
    {
        Ok(result) => result,
        // A full socket buffer means the client stopped reading. Dropping the
        // connection is the only way a slow subscriber cannot slow the feed.
        Err(_) => Err(std::io::ErrorKind::TimedOut.into()),
    }
}

async fn subscribe_connection(stream: &mut UnixStream, live: &LiveRefusals) {
    // The handoff: snapshot and subscription under one lock, so the client
    // receives everything after the snapshot exactly once.
    let (snapshot, mut updates) = live.subscribe();
    let ended = snapshot.ended_ms.is_some();
    if write_reply(
        stream,
        &Reply::Snapshot {
            v: PROTOCOL_VERSION,
            session: snapshot,
        },
    )
    .await
    .is_err()
    {
        return;
    }
    if ended {
        let _ = write_reply(
            stream,
            &Reply::Ended {
                v: PROTOCOL_VERSION,
            },
        )
        .await;
        return;
    }
    loop {
        match updates.recv().await {
            Ok(update) => {
                let reply = Reply::Update {
                    v: PROTOCOL_VERSION,
                    update,
                };
                if write_reply(stream, &reply).await.is_err() {
                    return;
                }
            }
            // The subscriber fell behind the ring buffer. A fresh snapshot is the
            // only correct answer: it carries every counter, so nothing the client
            // missed stays wrong.
            Err(broadcast::error::RecvError::Lagged(_)) => {
                let (snapshot, fresh) = live.subscribe();
                updates = fresh;
                let ended = snapshot.ended_ms.is_some();
                if write_reply(
                    stream,
                    &Reply::Snapshot {
                        v: PROTOCOL_VERSION,
                        session: snapshot,
                    },
                )
                .await
                .is_err()
                {
                    return;
                }
                if ended {
                    let _ = write_reply(
                        stream,
                        &Reply::Ended {
                            v: PROTOCOL_VERSION,
                        },
                    )
                    .await;
                    return;
                }
            }
            Err(broadcast::error::RecvError::Closed) => {
                let _ = write_reply(
                    stream,
                    &Reply::Ended {
                        v: PROTOCOL_VERSION,
                    },
                )
                .await;
                return;
            }
        }
    }
}

// -- client ----------------------------------------------------------------

/// Subscribe to one session.
///
/// `agent-vm access` lists, it does not stream, so nothing in this release calls
/// this: it is the interface agent-vm#301's GUI is for, and the protocol tests
/// drive it so it cannot rot.
#[allow(dead_code)]
pub(crate) async fn subscribe(path: &Path) -> Result<impl futures::Stream<Item = Result<Reply>>> {
    let stream = UnixStream::connect(path)
        .await
        .with_context(|| format!("connecting to {}", crate::one_line::path(path)))?;
    let mut writer = stream;
    writer
        .write_all(format!("{{\"v\":{PROTOCOL_VERSION},\"op\":\"subscribe\"}}\n").as_bytes())
        .await
        .context("sending the subscribe request")?;
    writer
        .flush()
        .await
        .context("sending the subscribe request")?;
    let lines = BufReader::new(writer).lines();
    Ok(futures::stream::unfold(lines, |mut lines| async move {
        match lines.next_line().await {
            Ok(Some(line)) => Some((parse_reply(&line), lines)),
            Ok(None) => None,
            Err(error) => Some((Err(anyhow::Error::new(error)), lines)),
        }
    }))
}

fn parse_reply(line: &str) -> Result<Reply> {
    serde_json::from_str(line).with_context(|| format!("decoding the reply {line:?}"))
}

/// Ask one session for its snapshot.
async fn list(path: &Path) -> Result<SessionSnapshot> {
    let stream = tokio::time::timeout(Duration::from_secs(1), UnixStream::connect(path))
        .await
        .map_err(|_| {
            anyhow::anyhow!("connecting to {} timed out", crate::one_line::path(path))
        })??;
    let mut reader = BufReader::new(stream);
    reader
        .get_mut()
        .write_all(format!("{{\"v\":{PROTOCOL_VERSION},\"op\":\"list\"}}\n").as_bytes())
        .await
        .context("sending the list request")?;
    let mut line = String::new();
    tokio::time::timeout(EXCHANGE_TIMEOUT, reader.read_line(&mut line))
        .await
        .map_err(|_| anyhow::anyhow!("{} did not answer in time", crate::one_line::path(path)))??;
    match parse_reply(&line)? {
        Reply::Session { session, .. } => Ok(session),
        other => Err(anyhow::anyhow!(
            "{} answered {} instead of a session",
            crate::one_line::path(path),
            format_args!("{other:?}")
        )),
    }
}

// -- discovery -------------------------------------------------------------

/// Everything `agent-vm access` can see: the sessions that answered, the ones the
/// log remembers, the ones that did not answer, and what went wrong on the way.
pub(crate) struct Discovery {
    pub(crate) live: Vec<SessionSnapshot>,
    pub(crate) logged: Vec<SessionSnapshot>,
    pub(crate) unresponsive: Vec<SessionId>,
    pub(crate) warnings: Vec<String>,
}

/// List the directory and ask every session that is still listening.
///
/// The directory listing is the whole discovery mechanism — no msb database, no
/// `pid_alive` (which always returns false on macOS). A socket that refuses a
/// connection is a session that ended without cleaning up, so it is removed and
/// reported as ended from the log.
pub(crate) async fn discover(dir: &SessionsDir, _now_ms: i64) -> Discovery {
    let mut warnings = Vec::new();
    let mut candidates: Vec<(PathBuf, SessionId)> = Vec::new();
    match std::fs::read_dir(dir.path()) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                let Some(stem) = name.strip_suffix(".sock") else {
                    continue;
                };
                let Some(id) = SessionId::parse(stem) else {
                    continue;
                };
                // Only a socket this user owns is even considered: a symlink or
                // another user's entry is never connected to and never removed.
                let Ok(metadata) = std::fs::symlink_metadata(entry.path()) else {
                    continue;
                };
                use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
                if !metadata.file_type().is_socket()
                    || metadata.uid() != crate::host_paths::current_euid()
                {
                    continue;
                }
                candidates.push((entry.path(), id));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => warnings.push(format!(
            "could not read {}: {error}",
            crate::one_line::path(dir.path())
        )),
    }

    // Concurrently, because one hung session must not delay the others by its
    // whole deadline.
    let asked = candidates
        .iter()
        .map(|(path, id)| {
            let path = path.clone();
            let id = id.clone();
            async move {
                let result = list(&path).await;
                (path, id, result)
            }
        })
        .collect::<Vec<_>>();
    let answers = futures::future::join_all(asked).await;

    let mut live = Vec::new();
    let mut unresponsive = Vec::new();
    for (path, id, result) in answers {
        match result {
            Ok(session) => live.push(session),
            Err(error) => {
                // A refused connection is a stale socket: unlink it, and let the
                // log speak for that session. A timeout is a session that is alive
                // but busy; it is reported, not removed.
                if is_refused(&error) {
                    let _ = std::fs::remove_file(&path);
                } else {
                    unresponsive.push(id);
                }
            }
        }
    }

    // Every logged session is kept, including one whose socket was just stale:
    // that is exactly the `ended (unclean)` case, and dropping it here would hide
    // the record that says the session ran at all.
    let logged = match dir.read() {
        Ok(log) => log.sessions,
        Err(error) => {
            warnings.push(format!("could not read the refusal log: {error:#}"));
            Vec::new()
        }
    };
    Discovery {
        live,
        logged,
        unresponsive,
        warnings,
    }
}

fn is_refused(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|error| error.kind() == std::io::ErrorKind::ConnectionRefused)
}

/// The launcher's teardown hook: everything `Sandbox` does, plus the feed.
pub(crate) struct LaunchTeardown<'a> {
    sandbox: &'a Sandbox,
    live: &'a LiveSession,
}

impl<'a> LaunchTeardown<'a> {
    pub(crate) fn new(sandbox: &'a Sandbox, live: &'a LiveSession) -> Self {
        Self { sandbox, live }
    }
}

impl crate::teardown::ExecTeardown for LaunchTeardown<'_> {
    async fn stop_and_wait(&self) -> Result<()> {
        crate::teardown::ExecTeardown::stop_and_wait(self.sandbox).await
    }
    async fn kill_with_timeout(&self, timeout: Duration) -> Result<()> {
        crate::teardown::ExecTeardown::kill_with_timeout(self.sandbox, timeout).await
    }
    async fn wait(&self) -> Result<()> {
        crate::teardown::ExecTeardown::wait(self.sandbox).await
    }
    async fn remove(&self) -> Result<()> {
        crate::teardown::ExecTeardown::remove(self.sandbox).await
    }
    /// Producer stopped → drain → persist → remove.
    async fn before_remove(&self) {
        self.live.finish().await;
    }
}

#[cfg(test)]
mod tests;
