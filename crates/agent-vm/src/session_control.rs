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

/// Protocol version this build *prefers*. Additive changes keep it; a client
/// that asks for another version gets `unsupported-version` and the list of
/// versions this build speaks.
pub(crate) const PROTOCOL_VERSION: u32 = 2;
/// The version this build's **read** calls ask for: `list` and `subscribe` only,
/// with `v: 1` replies, so an older server sees byte-identical requests (AC10).
///
/// Named for the client's side on purpose: `PROTOCOL_VERSION` is what this build
/// *prefers* and what a mutation uses, and `SUPPORTED_VERSIONS` is what it
/// serves — three questions, three names (C-m9).
pub(crate) const CLIENT_READ_VERSION: u32 = 1;
/// Every version this build serves. `v: 2` adds `grant`, `revoke`, `allowances`.
const SUPPORTED_VERSIONS: &[u32] = &[1, 2];

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
/// The client's deadline for a mutation. `40 s > 30 s runtime deadline
/// (handshake.rs:27) + 1 s LOCK_WAIT + write slack`: a client timeout shorter
/// than the runtime's would race a swap that is still going to commit (Ruling 4).
const MUTATION_TIMEOUT: Duration = Duration::from_secs(40);
/// How long `finish` waits for open connections after telling them the session
/// ended, before aborting them.
const CONNECTION_GRACE: Duration = Duration::from_millis(500);
/// The whole teardown drain, `open` included. A drain that cannot open the
/// runtime's file has nothing to read, and waiting for one is not worth the
/// teardown's time.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
/// The backstop join on the follower after its stop is set. Its own waits all
/// honour the stop, so this only decides how long an uncancellable `open` may
/// hold up the teardown.
const FOLLOWER_STOP_WAIT: Duration = Duration::from_secs(1);

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
/// Explicit setup for [`LiveSession::start`] — no hidden construction and no
/// production default (Ruling 1, B3, M1).
pub(crate) struct LiveSetup<'a> {
    pub(crate) project: &'a crate::project::ProjectDir,
    pub(crate) store: crate::allowances::StoreHandle,
    pub(crate) plan: crate::network::LivePolicyPlan,
}

pub(crate) struct LiveSession {
    info: SessionInfo,
    /// The live allowance controller: in memory only, owned by this session.
    allowances: Arc<crate::allowances::LiveAllowances>,
    live: Option<Arc<LiveRefusals>>,
    persister: Option<Persister>,
    /// The one hint this session ever prints (AC7). Shared by the follower and by
    /// the teardown drain: a second `Hint` would let a refusal first read at
    /// teardown — or one the follower already reported, read again by the drain —
    /// print a second line.
    hint: Arc<Hint>,
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
    pub(crate) async fn start(session: &ProjectSession, setup: LiveSetup<'_>) -> Self {
        let path = session.sessions_dir();
        let info = SessionInfo {
            id: SessionId::generate(),
            pid: std::process::id(),
            started_ms: feed::now_ms(),
            socket: false,
        };
        let allowances =
            crate::allowances::LiveAllowances::new(setup.project, setup.store, setup.plan);
        let dir = match SessionsDir::open_or_create(&path) {
            Ok(dir) => dir,
            Err(error) => {
                notice(format!("==> Refusals are not recorded: {error}"));
                return Self::degraded(info, allowances);
            }
        };
        let socket = dir.socket_path(&info.id);
        // The name bound first is the hidden one, so the path budget has to be
        // checked for it: it is the longest spelling this session ever binds.
        if !crate::msb_install::unix_socket_path_fits(&Hidden::tmp_path(&dir, &info.id)) {
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
                allowances,
            );
        }

        // Binding happens inside the reservation, so a name another session still
        // holds is redrawn rather than adopted. The socket is bound under a hidden
        // name and renamed into place by `publish`.
        let reserved =
            match dir.reserve(info.started_ms, info.pid, true, |id| Hidden::bind(&dir, id)) {
                Ok(Some(reserved)) => reserved,
                Ok(None) => {
                    // Only the *live view* is lost: the session keeps its log, and
                    // the persister below writes through it on its first attempt, so
                    // "not recorded" would be wrong.
                    notice(
                        "==> Refusals are not served live: another session holds this project's \
                     refusal log lock. They are still recorded once the lock is free.",
                    );
                    return Self::with_dir(
                        &dir,
                        SessionInfo {
                            socket: false,
                            ..info
                        },
                        allowances,
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
                        allowances,
                    );
                }
            };
        let bound_socket = dir.socket_path(&reserved.snapshot.info.id);
        let listener = match reserved.bound.publish() {
            Ok(listener) => listener,
            Err(error) => {
                notice(format!(
                    "==> Refusals are recorded but not served live: {error:#}"
                ));
                // The session is left with no socket, and with *its own* reserved
                // ID: writing the unreserved one would orphan the reservation.
                return Self::with_dir(
                    &dir,
                    SessionInfo {
                        socket: false,
                        ..reserved.snapshot.info
                    },
                    allowances,
                );
            }
        };
        let listening = LiveRefusals::new(SessionRefusals::resume(reserved.snapshot.clone()));
        let persister = Persister::new(dir.clone());
        let (stop, receiver) = watch::channel(false);
        let task = tokio::spawn(serve(
            listener,
            Arc::clone(&listening),
            Arc::clone(&allowances),
            receiver,
        ));
        Self {
            info: reserved.snapshot.info,
            allowances: Arc::clone(&allowances),
            live: Some(listening),
            persister: Some(persister),
            hint: Arc::new(Hint::new()),
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

    fn degraded(info: SessionInfo, allowances: Arc<crate::allowances::LiveAllowances>) -> Self {
        Self {
            info,
            allowances,
            live: None,
            persister: None,
            hint: Arc::new(Hint::new()),
            open: Mutex::new(None),
            running: Mutex::new(None),
            following: Mutex::new(None),
            finished: AtomicBool::new(false),
        }
    }

    /// The log without a socket: the feed still runs, `access` still lists it.
    fn with_dir(
        dir: &SessionsDir,
        info: SessionInfo,
        allowances: Arc<crate::allowances::LiveAllowances>,
    ) -> Self {
        let live = LiveRefusals::new(SessionRefusals::new(info.clone()));
        let persister = Persister::new(dir.clone());
        // The session's empty record is written now, so `access --session` can
        // name a session that exists but has refused nothing yet.
        persister.post(live.snapshot());
        Self {
            info,
            allowances,
            live: Some(live),
            persister: Some(persister),
            hint: Arc::new(Hint::new()),
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

    /// Adopt the project allowances the launch actually applied (ADR-0065).
    ///
    /// Called once, after `allowances::for_launch` read the store and before
    /// `follow` attaches the runtime, so a grant that arrived in between is
    /// re-derived over the post-adoption plan.
    /// Returns the launch notices the adoption owes: it drops a queued entry only
    /// in the unreachable case that the post-adoption policy cannot express it.
    pub(crate) fn adopt_boot_allowances(
        &self,
        recorded: &crate::allowances::ProjectView,
        adopted: &[crate::allowances::ProjectAllowance],
        plan: crate::network::LivePolicyPlan,
    ) -> Vec<String> {
        self.allowances
            .adopt_boot_allowances(recorded, adopted, plan)
    }

    /// This session's live allowance controller (the tests' view of it).
    #[cfg(test)]
    pub(crate) fn allowances(&self) -> &Arc<crate::allowances::LiveAllowances> {
        &self.allowances
    }

    /// This session's live refusal feed, so a test can ingest one refusal and see
    /// it through the control socket.
    #[cfg(test)]
    pub(crate) fn refusals(&self) -> Option<Arc<LiveRefusals>> {
        self.live.clone()
    }

    /// Start following the sandbox's `network.log`.
    ///
    /// Called right after the sandbox exists: the producer is the runtime, so
    /// following before it has written anything is the only way not to lose the
    /// first refusal.
    pub(crate) fn follow(&self, sandbox: &Sandbox) {
        // The runtime is attached before the early return below: a session whose
        // refusal feed is degraded still launched a sandbox, and `access allow`
        // must still be able to swap its policy.
        let owner = sandbox.clone();
        let updater: crate::allowances::PolicyUpdater = Arc::new(move |policy| {
            let sandbox = owner.clone();
            Box::pin(async move { sandbox.update_network_policy(policy).await })
        });
        if self.allowances.attach_updater(updater) {
            let allowances = Arc::clone(&self.allowances);
            tokio::spawn(async move {
                for warning in allowances.flush_queued().await {
                    notice(format!("==> {warning}"));
                }
            });
        }
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
            Arc::clone(&self.hint),
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
        // The slot is emptied before the awaits: a `std::sync::MutexGuard` held
        // across one would stall every other thread that wanted it.
        let following = lock(&self.following).take();
        if let Some(following) = following {
            let _ = following.stop.send(true);
            // The follower's own stop check is inside every wait it does, so this
            // join is prompt; the bound is the backstop for an `open` that cannot
            // be cancelled.
            match tokio::time::timeout(FOLLOWER_STOP_WAIT, following.task).await {
                Ok(Ok(cursor)) => self.drain(&live, cursor).await,
                // A panicked or unresponsive follower has no known position, so
                // draining from the beginning could count records twice. Saying
                // the count is unknown is the honest record (AC6).
                Ok(Err(_)) | Err(_) => live.note_gap(),
            }
        }
        // 3. The final snapshot, written before any reader is told it ended.
        let snapshot = live.ended(feed::now_ms());
        if let Some(persister) = &self.persister {
            let wait = persister.post_final(snapshot);
            // Off a worker thread: the wait is a `Condvar`, and blocking a
            // runtime worker for up to `FINAL_WAIT` would stall every other task
            // on it — including the connections `close_socket` is about to tell
            // the session ended.
            let _ = tokio::task::spawn_blocking(move || wait.wait(feed::FINAL_WAIT)).await;
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
        // The deadline covers the `open` as well as the reads: an `open` that
        // never returns used to sit in front of the deadline, not inside it.
        let deadline = tokio::time::Instant::now() + DRAIN_TIMEOUT;
        let Ok(Ok(mut stream)) =
            tokio::time::timeout_at(deadline, open(feed::drain_options(cursor))).await
        else {
            return;
        };
        // A drain must terminate: the stream was opened without `follow`, so it
        // ends at EOF. The bound is for a runtime whose file never closes.
        let mut dirty = false;
        let mut cursor = None;
        loop {
            let next = tokio::time::timeout_at(deadline, stream.next()).await;
            match next {
                // The drain is the last chance to see these records, so the hint
                // fires here too — a refusal the operator never saw live is still
                // a refusal they should be told to look at. It is the session's
                // one `Hint`, so a refusal the follower already reported cannot
                // print a second line (AC7).
                Ok(Some(Ok(entry))) => {
                    feed::accept(entry, live, &self.hint, &mut dirty, &mut cursor)
                }
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

/// A socket bound but not yet announced: the hidden name, and the name it will
/// be renamed to.
///
/// Tokio's `UnixListener::bind` is `bind()` then `listen()`. A `connect` that
/// lands between the two gets `ECONNREFUSED`, and [`discover`] reads a refused
/// connection as a stale socket and unlinks it — so the session would spend its
/// whole life reading `ended (unclean)` and `access` could never reach it. Bound
/// under `<sid>.sock.tmp`, listened, chmodded and *then* renamed, the visible name
/// never exists in a not-listening state. The rename is also what lets the mode be
/// set before anything can connect.
///
/// Discovery ignores the hidden name for free: it only ever considers a name that
/// ends in `.sock` whose stem is 8 hex, and `deadbeef.sock.tmp` is neither.
struct Hidden {
    listener: UnixListener,
    tmp: PathBuf,
    path: PathBuf,
}

impl Hidden {
    /// The hidden name this session binds first.
    fn tmp_path(dir: &SessionsDir, id: &SessionId) -> PathBuf {
        dir.path().join(format!("{}.sock.tmp", id.as_str()))
    }

    /// Bind and listen under the hidden name. Nothing can dial it under this name,
    /// and nothing can dial the visible name until [`Self::publish`] runs.
    fn bind(dir: &SessionsDir, id: &SessionId) -> std::io::Result<Self> {
        let tmp = Self::tmp_path(dir, id);
        let listener = UnixListener::bind(&tmp)?;
        Ok(Self {
            listener,
            tmp,
            path: dir.socket_path(id),
        })
    }

    /// Mode 0600, then rename into place. Both happen while the socket is already
    /// listening, so a client that sees the name can connect.
    fn publish(self) -> Result<UnixListener> {
        use std::os::unix::fs::PermissionsExt as _;
        let result = std::fs::set_permissions(&self.tmp, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("setting the mode of {}", crate::one_line::path(&self.tmp)))
            .and_then(|()| {
                std::fs::rename(&self.tmp, &self.path).with_context(|| {
                    format!(
                        "moving {} to {}",
                        crate::one_line::path(&self.tmp),
                        crate::one_line::path(&self.path)
                    )
                })
            });
        if result.is_err() {
            // The hidden name must not outlive a failed publish: it is not a name
            // discovery can ever report or clean up.
            let _ = std::fs::remove_file(&self.tmp);
        }
        // The listener is returned even for an error so it is closed with `self`.
        result.map(|()| self.listener)
    }
}

impl Drop for LiveSession {
    /// Nonblocking: a launch that errors before `create`, or a non-direct
    /// `live_launch_result` failure, never reaches a teardown, so the follower and
    /// the socket are released here instead. The socket is unlinked by the accept
    /// loop when it observes the stop.
    ///
    /// What is still here decides what runs, not the `finished` flag: a `finish`
    /// that was cancelled part-way has already set the flag and left the socket
    /// bound, and returning early on the flag leaked it for the rest of the
    /// process's life. The slots are taken out by `finish` as it uses them, so a
    /// completed `finish` leaves nothing for this to repeat.
    fn drop(&mut self) {
        self.finished.store(true, Ordering::SeqCst);
        if let (Some(live), Some(persister)) = (&self.live, &self.persister) {
            // The final record, so a launch that never reaches a teardown still
            // leaves one that says the session ended. Not waited for: `Drop` may
            // not block, and a `finish` that already wrote it makes this a no-op.
            drop(persister.post_final(live.ended(feed::now_ms())));
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

/// The lenient version probe: `{"v":n}` and nothing else examined.
///
/// Decoded **before** the strict request so a client asking for a version this
/// build does not speak — with any extra fields a later version added — is told
/// `unsupported-version` and the versions that would work, rather than
/// `bad-request` (m1).
#[derive(Debug, Deserialize)]
struct VersionProbe {
    v: u32,
}

/// One request line. Strict: an unknown field is a client this build cannot
/// answer, which is exactly what `deny_unknown_fields` says.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    v: u32,
    op: String,
    /// `grant`: the refusal to allow. `revoke`: unused.
    #[serde(default)]
    id: Option<String>,
    /// `grant`/`revoke`: the allowance spelling. The CLI resolves `<ID>` to this
    /// before sending, so a refusal it cannot grant never reaches the socket.
    #[serde(default)]
    destination: Option<String>,
    /// `grant`: `session` (default) or `project`. `revoke`: `session`,
    /// `project`, or `all` (default).
    #[serde(default)]
    scope: Option<String>,
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
    /// A `grant` answer (`v: 2`).
    Grant {
        v: u32,
        result: crate::allowances::GrantResult,
    },
    /// A `revoke` answer (`v: 2`).
    Revoke {
        v: u32,
        result: crate::allowances::RevokeResult,
    },
    /// An `allowances` answer (`v: 2`): this session's active allowances.
    Allowances {
        v: u32,
        allowances: crate::allowances::SessionAllowancesSnapshot,
    },
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
async fn serve(
    listener: UnixListener,
    live: Arc<LiveRefusals>,
    allowances: Arc<crate::allowances::LiveAllowances>,
    mut stop: watch::Receiver<bool>,
) {
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
                let allowances = Arc::clone(&allowances);
                let subscribers = Arc::clone(&subscribers);
                // The session's stop signal reaches the connection, so a
                // subscriber waiting in `updates.recv()` learns the session ended
                // instead of only being aborted. Nothing closes the broadcast
                // channel: `LiveState` holds the sender and every connection holds
                // an `Arc` to it, so `RecvError::Closed` can never fire.
                let stop = stop.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    handle_connection(stream, live, allowances, subscribers, stop).await;
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
    allowances: Arc<crate::allowances::LiveAllowances>,
    subscribers: Arc<Semaphore>,
    mut stop: watch::Receiver<bool>,
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
    // Version first, leniently: an unknown version with extra fields is still an
    // unsupported version, never a malformed request (m1, AC10).
    let Ok(probe) = serde_json::from_slice::<VersionProbe>(&request) else {
        let _ = write_reply(&mut writer, &error("bad-request")).await;
        return;
    };
    if !SUPPORTED_VERSIONS.contains(&probe.v) {
        let reply = Reply::Error {
            v: PROTOCOL_VERSION,
            code: "unsupported-version".to_owned(),
            supported: Some(SUPPORTED_VERSIONS.to_vec()),
        };
        let _ = write_reply(&mut writer, &reply).await;
        return;
    }
    let version = probe.v;
    let Ok(request) = serde_json::from_slice::<Request>(&request) else {
        let _ = write_reply(&mut writer, &error("bad-request")).await;
        return;
    };
    if request.v != version {
        let _ = write_reply(&mut writer, &error("bad-request")).await;
        return;
    }
    match (version, request.op.as_str()) {
        (1 | 2, "list") => {
            let reply = Reply::Session {
                v: version,
                session: live.snapshot(),
            };
            let _ = write_reply(&mut writer, &reply).await;
        }
        (1 | 2, "subscribe") => {
            let Ok(_slot) = Arc::clone(&subscribers).try_acquire_owned() else {
                let _ = write_reply(&mut writer, &error("too-many-subscribers")).await;
                return;
            };
            subscribe_connection(&mut writer, &live, version, &mut stop).await;
        }
        // `v: 2` operations are not part of `v: 1`: a v1 request for one is a
        // request this version cannot answer, not a mutation to guess at.
        (1, "grant" | "revoke" | "allowances") => {
            let _ = write_reply(&mut writer, &error("bad-request")).await;
        }
        (2, "grant") => {
            let scope = match request.scope.as_deref() {
                None | Some("session") => crate::allowances::GrantScope::Session,
                Some("project") => crate::allowances::GrantScope::Project,
                Some(_) => {
                    let _ = write_reply(&mut writer, &error("bad-request")).await;
                    return;
                }
            };
            let result = allowances
                .grant(
                    &live,
                    request.id.as_deref(),
                    request.destination.as_deref(),
                    scope,
                    feed::now_ms(),
                )
                .await;
            let _ = write_reply(&mut writer, &Reply::Grant { v: version, result }).await;
        }
        (2, "revoke") => {
            let scope = match request.scope.as_deref() {
                None | Some("all") => crate::allowances::RevokeScope::All,
                Some("session") => crate::allowances::RevokeScope::Session,
                Some("project") => crate::allowances::RevokeScope::Project,
                Some(_) => {
                    let _ = write_reply(&mut writer, &error("bad-request")).await;
                    return;
                }
            };
            let Some(destination) = request
                .destination
                .as_deref()
                .and_then(|text| crate::egress_policy::Allowance::parse(text).ok())
            else {
                let _ = write_reply(&mut writer, &error("bad-request")).await;
                return;
            };
            let result = allowances.revoke(&destination, scope).await;
            let _ = write_reply(&mut writer, &Reply::Revoke { v: version, result }).await;
        }
        (2, "allowances") => {
            let reply = Reply::Allowances {
                v: version,
                allowances: allowances.snapshot(),
            };
            let _ = write_reply(&mut writer, &reply).await;
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

async fn subscribe_connection(
    stream: &mut UnixStream,
    live: &LiveRefusals,
    version: u32,
    stop: &mut watch::Receiver<bool>,
) {
    // The handoff: snapshot and subscription under one lock, so the client
    // receives everything after the snapshot exactly once.
    let (snapshot, mut updates) = live.subscribe();
    let ended = snapshot.ended_ms.is_some();
    if write_reply(
        stream,
        &Reply::Snapshot {
            v: version,
            session: snapshot,
        },
    )
    .await
    .is_err()
    {
        return;
    }
    if ended {
        let _ = write_reply(stream, &Reply::Ended { v: version }).await;
        return;
    }
    loop {
        // The ended reply is the point of subscribing: a client that waits for it
        // must be told, and a broadcast channel that is never closed cannot tell
        // it. The stop is the one signal the server owns.
        let received = tokio::select! {
            biased;
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    None
                } else {
                    continue;
                }
            }
            update = updates.recv() => Some(update),
        };
        let Some(received) = received else {
            let _ = write_reply(stream, &Reply::Ended { v: version }).await;
            return;
        };
        match received {
            Ok(update) => {
                let reply = Reply::Update { v: version, update };
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
                        v: version,
                        session: snapshot,
                    },
                )
                .await
                .is_err()
                {
                    return;
                }
                if ended {
                    let _ = write_reply(stream, &Reply::Ended { v: version }).await;
                    return;
                }
            }
            Err(broadcast::error::RecvError::Closed) => {
                let _ = write_reply(stream, &Reply::Ended { v: version }).await;
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
        .write_all(format!("{{\"v\":{CLIENT_READ_VERSION},\"op\":\"subscribe\"}}\n").as_bytes())
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
        .write_all(format!("{{\"v\":{CLIENT_READ_VERSION},\"op\":\"list\"}}\n").as_bytes())
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

/// Send one `v: 2` request and read its one reply.
///
/// The deadline is [`MUTATION_TIMEOUT`] for a mutation and [`EXCHANGE_TIMEOUT`]
/// for a read: a mutation that times out on the client while the runtime is still
/// going to commit would leave the CLI's story and the sandbox's policy disagreeing
/// (Ruling 4, M3).
async fn exchange(path: &Path, request: serde_json::Value, timeout: Duration) -> Result<Reply> {
    let stream = tokio::time::timeout(Duration::from_secs(1), UnixStream::connect(path))
        .await
        .map_err(|_| {
            anyhow::anyhow!("connecting to {} timed out", crate::one_line::path(path))
        })??;
    let mut line = serde_json::to_vec(&request).context("encoding the request")?;
    line.push(b'\n');
    let mut reader = BufReader::new(stream);
    reader
        .get_mut()
        .write_all(&line)
        .await
        .context("sending the request")?;
    let mut answer = String::new();
    tokio::time::timeout(timeout, reader.read_line(&mut answer))
        .await
        .map_err(|_| anyhow::anyhow!("{} did not answer in time", crate::one_line::path(path)))??;
    parse_reply(&answer)
}

/// Ask one session to apply a live grant.
pub(crate) async fn grant(
    path: &Path,
    destination: Option<&str>,
    scope: crate::allowances::GrantScope,
) -> Result<crate::allowances::GrantResult> {
    let request = serde_json::json!({
        "v": PROTOCOL_VERSION,
        "op": "grant",
        "destination": destination,
        "scope": match scope {
            crate::allowances::GrantScope::Session => "session",
            crate::allowances::GrantScope::Project => "project",
        },
    });
    match exchange(path, request, MUTATION_TIMEOUT).await? {
        Reply::Grant { result, .. } => Ok(result),
        other => Err(anyhow::anyhow!(
            "{} answered {} instead of a grant",
            crate::one_line::path(path),
            format_args!("{other:?}")
        )),
    }
}

/// Ask one session to revoke a destination.
pub(crate) async fn revoke(
    path: &Path,
    destination: &str,
    scope: crate::allowances::RevokeScope,
) -> Result<crate::allowances::RevokeResult> {
    let request = serde_json::json!({
        "v": PROTOCOL_VERSION,
        "op": "revoke",
        "destination": destination,
        "scope": match scope {
            crate::allowances::RevokeScope::All => "all",
            crate::allowances::RevokeScope::Session => "session",
            crate::allowances::RevokeScope::Project => "project",
        },
    });
    match exchange(path, request, MUTATION_TIMEOUT).await? {
        Reply::Revoke { result, .. } => Ok(result),
        other => Err(anyhow::anyhow!(
            "{} answered {} instead of a revoke",
            crate::one_line::path(path),
            format_args!("{other:?}")
        )),
    }
}

/// Ask one session for its active allowances.
pub(crate) async fn allowances(
    path: &Path,
) -> Result<crate::allowances::SessionAllowancesSnapshot> {
    let request = serde_json::json!({"v": PROTOCOL_VERSION, "op": "allowances"});
    match exchange(path, request, EXCHANGE_TIMEOUT).await? {
        Reply::Allowances { allowances, .. } => Ok(allowances),
        other => Err(anyhow::anyhow!(
            "{} answered {} instead of its allowances",
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
    /// Each live session's active allowances, for the `access allowances` union.
    /// A session that cannot answer is in `unresponsive`, not here.
    pub(crate) live_allowances: Vec<(SessionId, crate::allowances::SessionAllowancesSnapshot)>,
    /// Every session the log has had to evict, ever. Read once, here, so a caller
    /// prints one number instead of re-reading the log it just read.
    pub(crate) evicted_sessions: u64,
    pub(crate) warnings: Vec<String>,
}

/// List the directory and ask every session that is still listening.
///
/// The directory listing is the whole discovery mechanism — no msb database, no
/// `pid_alive` (which always returns false on macOS). A socket that refuses a
/// connection is a session that ended without cleaning up, so it is removed and
/// reported as ended from the log.
///
/// Cost: two round trips per live session — the `v: 1` `list` and, for v2
/// sessions, the `allowances` answer — each bounded by `EXCHANGE_TIMEOUT`, and
/// the pairs run concurrently. A session that answers `list` and then stops
/// answering costs at most one more `EXCHANGE_TIMEOUT` on this command, and
/// nothing at all if it refuses the connection.
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
    let mut live_allowances = Vec::new();
    for (path, id, result) in answers {
        match result {
            Ok(session) => {
                // A session that predates `v: 2` answers `unsupported-version`;
                // that is not a failure to report, it just has no live view.
                if let Ok(snapshot) = allowances(&path).await {
                    live_allowances.push((id.clone(), snapshot));
                }
                live.push(session);
            }
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
    //
    // A record this build cannot use is reported, not silently replaced: it is
    // the reader's only chance to tell "nothing was refused" from "the records are
    // gone", and the reading itself repairs nothing (ADR-0064).
    let (logged, evicted_sessions) = match dir.read() {
        Ok(log) => {
            // A newer build's log is read, and never replaced: the one warning is
            // the reader's only clue that these rows came from a file this build
            // may only partly understand (ADR-0064 decision 2).
            if log.written_by_a_newer_version() {
                warnings.push(format!(
                    "the refusal log {} was written by a newer agent-vm; it is read but never \
                     replaced, so a record this version cannot decode is not shown",
                    crate::one_line::path(&dir.record())
                ));
            }
            if let Some(damage) = &log.damaged {
                warnings.push(format!(
                    "the refusal log {} could not be used ({damage}); the sessions it held are \
                     not listed here. It is moved to refusals.json.damaged and replaced by the \
                     next session that writes",
                    crate::one_line::path(&dir.record())
                ));
            }
            (log.sessions, log.evicted_sessions)
        }
        Err(error) => {
            warnings.push(format!("could not read the refusal log: {error:#}"));
            (Vec::new(), 0)
        }
    };
    Discovery {
        live,
        logged,
        unresponsive,
        live_allowances,
        evicted_sessions,
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
