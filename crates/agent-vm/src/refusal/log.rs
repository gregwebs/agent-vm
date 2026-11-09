//! The project refusal log: one bounded, host-only file per project.
//!
//! The runtime's own `network.log` dies with its sandbox, so the launcher keeps
//! its own copy of what a project's sessions refused — that copy is what
//! `agent-vm access` reads after a session ends.
//!
//! The store follows ADR-0047/0063's shape (flock plus atomic replace) with one
//! deliberate difference: it may self-heal. A damaged *display* log is set aside
//! and rewritten, because nothing is authorized by it; an authority store must
//! refuse instead. ADR-0064 records why.
//!
//! Writers are serialized by one exclusive `flock` on `refusals.lock`, and each
//! write is a whole read-modify-write, so two sessions in one project can never
//! lose each other's update to a race. Readers take no lock: the atomic rename
//! always leaves a complete file, which is why a reader cannot observe a
//! half-written log.

use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};

use super::{SessionId, SessionSnapshot};
use crate::host_paths::{self, FlockWait};

/// The log's own schema version. A file with a greater one is a newer build's
/// and is never overwritten: this build cannot know what it would destroy.
const LOG_VERSION: u32 = 1;
/// Entry and byte bounds for the whole log (AC12). A session is bounded at
/// [`MAX_ENTRIES_PER_SESSION`] on its own, so these bound the number of
/// *sessions* that can be retained.
const MAX_LOG_ENTRIES: usize = 2048;
const MAX_LOG_BYTES: u64 = 2 * 1024 * 1024;
/// A session with no activity for this long is history, not state.
const RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;
/// A session with no control socket is `running` only while its heartbeat is
/// this fresh (§5).
pub(crate) const HEARTBEAT_STALE_MS: i64 = 90_000;
/// One bounded wait for the writer lock. A session whose log cannot be written
/// within this has no log; that degrades the feed and never fails the launch.
const LOCK_WAIT: Duration = Duration::from_secs(1);
/// Attempts at a session ID whose socket we can actually bind.
const RESERVE_TRIES: usize = 4;

/// The directory holding one project's refusal artefacts.
///
/// Opening it is a decision, not a lookup: it must be a real directory (never a
/// symlink), owned by this euid, with mode exactly 0700. Anything else is not
/// adopted — one notice names it and the session runs without a feed — because a
/// directory with another owner or a looser mode is not a host-only store, and
/// silently using it would put refusal records where the guest may read or
/// rewrite them.
#[derive(Clone, Debug)]
pub(crate) struct SessionsDir {
    path: PathBuf,
}

impl SessionsDir {
    /// Open, creating the directory (mode 0700) when it is absent.
    pub(crate) fn open_or_create(path: &Path) -> Result<Self> {
        match std::fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("creating {}", crate::one_line::path(path)));
            }
        }
        Self::open(path)?.ok_or_else(|| anyhow!("{} vanished", crate::one_line::path(path)))
    }

    /// Open an existing directory, never creating one. `Ok(None)` when absent,
    /// which is what a read-only command needs: asking what a project's sessions
    /// refused must not create the store that would answer.
    pub(crate) fn open(path: &Path) -> Result<Option<Self>> {
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("stating {}", crate::one_line::path(path)));
            }
        };
        if !metadata.is_dir() {
            bail!(
                "{} is not a directory; agent-vm keeps refusal records in a plain \
                 directory it owns",
                crate::one_line::path(path)
            );
        }
        let euid = host_paths::current_euid();
        if metadata.uid() != euid {
            bail!(
                "{} is owned by uid {}, not by this user (uid {euid}); agent-vm will not \
                 adopt another user's directory",
                crate::one_line::path(path),
                metadata.uid()
            );
        }
        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o700 {
            bail!(
                "{} has mode {mode:04o}, not 0700; agent-vm will not adopt a directory other \
                 users can reach",
                crate::one_line::path(path)
            );
        }
        Ok(Some(Self {
            path: path.to_path_buf(),
        }))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    fn record(&self) -> PathBuf {
        self.path.join("refusals.json")
    }

    fn lock_path(&self) -> PathBuf {
        self.path.join("refusals.lock")
    }

    pub(crate) fn socket_path(&self, session: &SessionId) -> PathBuf {
        self.path.join(format!("{}.sock", session.as_str()))
    }

    /// The log as it stands. No lock and no creation: the atomic replace always
    /// leaves a complete file, so a reader cannot see a partial one.
    ///
    /// A damaged or unreadable record is reported as an empty log here — reading
    /// must not have the side effect of repairing it; [`Self::write`] is the one
    /// place that sets damage aside.
    pub(crate) fn read(&self) -> Result<Log> {
        Ok(self.load()?.unwrap_or_else(|| Log {
            evicted_sessions: 0,
            sessions: Vec::new(),
            writable: true,
        }))
    }

    /// Decode the record. `Ok(None)` when it is absent or damaged.
    ///
    /// The `writable` flag is the only reason this is not a plain `Log`: a file
    /// written by a newer build must not be replaced, and the difference has to
    /// survive the decode.
    fn load(&self) -> Result<Option<Log>> {
        let bytes = match host_paths::read_optional_bounded_regular_file_no_follow(
            &self.record(),
            MAX_LOG_BYTES,
        ) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Ok(None),
            // A symlink, a directory or an oversized file is damage, not an
            // error to propagate: this is a display store.
            Err(_) => {
                self.set_aside();
                return Ok(None);
            }
        };
        let file: LogFile = match serde_json::from_slice(&bytes) {
            Ok(file) => file,
            Err(_) => {
                self.set_aside();
                return Ok(None);
            }
        };
        if file.v > LOG_VERSION {
            return Ok(Some(Log {
                evicted_sessions: file.evicted_sessions,
                sessions: file.sessions,
                writable: false,
            }));
        }
        if file.v < LOG_VERSION {
            self.set_aside();
            return Ok(None);
        }
        Ok(Some(Log {
            evicted_sessions: file.evicted_sessions,
            sessions: file.sessions,
            writable: true,
        }))
    }

    /// Move a damaged record out of the way so the next write can start over.
    ///
    /// `rename` is atomic, so a concurrent reader sees either the damaged file or
    /// none; the suffix keeps the evidence instead of deleting it.
    fn set_aside(&self) {
        let damaged = self.path.join("refusals.json.damaged");
        if let Err(error) = std::fs::rename(self.record(), &damaged) {
            tracing::warn!(
                "could not set aside the damaged refusal log {}: {error}",
                crate::one_line::path(&self.record())
            );
        }
    }

    /// Upsert `own`, prune, evict, and replace the record atomically.
    ///
    /// `own` is this process's session, and it is never pruned or evicted: the
    /// session that is writing is the one a reader is watching.
    pub(crate) fn write(&self, own: &SessionSnapshot, now_ms: i64) -> Result<WriteReport> {
        let lock = host_paths::open_lock_file(&self.lock_path())?;
        if host_paths::flock_exclusive_within(&lock, LOCK_WAIT, |_| {})? == FlockWait::TimedOut {
            bail!("the refusal log is locked by another session");
        }
        let mut log = self.load()?.unwrap_or_else(|| Log {
            evicted_sessions: 0,
            sessions: Vec::new(),
            writable: true,
        });
        if !log.writable {
            // One warning, and never an overwrite: a newer build's log may hold
            // fields this one would silently drop.
            return Ok(WriteReport {
                evicted_sessions: log.evicted_sessions,
                warning: Some(format!(
                    "{} was written by a newer agent-vm; not updating it",
                    crate::one_line::path(&self.record())
                )),
            });
        }

        log.upsert(own);
        log.prune(now_ms, own.info.id.as_str());
        let evicted = log.evict(own.info.id.as_str());
        log.evicted_sessions = log.evicted_sessions.saturating_add(evicted);

        let bytes = log.encode()?;
        if bytes.len() as u64 > MAX_LOG_BYTES {
            // The writer's own session is bounded at 1 MiB, so reaching this
            // means the accounting above is wrong and a larger file would be a
            // silent truncation for a reader.
            bail!("the refusal log would exceed {MAX_LOG_BYTES} bytes");
        }
        host_paths::atomic_write(&self.record(), &bytes, 0o600)
            .with_context(|| format!("writing {}", crate::one_line::path(&self.record())))?;
        Ok(WriteReport {
            evicted_sessions: log.evicted_sessions,
            warning: None,
        })
    }

    /// Reserve a session ID and write the empty session, all under the log lock.
    ///
    /// Reserving under the lock is what makes "unique within a project" true
    /// rather than likely: two launchers starting at the same instant contend on
    /// the same lock, so the second sees the first's write. `bind` gets each
    /// candidate and may refuse it (the socket name is taken by a live session
    /// whose log entry is gone); a candidate that collides is redrawn.
    ///
    /// `Ok(None)` when the lock could not be taken: the session then has no log,
    /// and one notice says so. It never fails the launch (AC14).
    pub(crate) fn reserve<T>(
        &self,
        now_ms: i64,
        pid: u32,
        socket: bool,
        mut bind: impl FnMut(&SessionId) -> std::io::Result<T>,
    ) -> Result<Option<Reserved<T>>> {
        let lock = host_paths::open_lock_file(&self.lock_path())?;
        if host_paths::flock_exclusive_within(&lock, LOCK_WAIT, |_| {})? == FlockWait::TimedOut {
            return Ok(None);
        }
        let mut log = self.load()?.unwrap_or_else(|| Log {
            evicted_sessions: 0,
            sessions: Vec::new(),
            writable: true,
        });
        if !log.writable {
            return Ok(None);
        }
        for _ in 0..RESERVE_TRIES {
            let id = SessionId::generate();
            if log.contains(id.as_str()) || self.socket_path(&id).exists() {
                continue;
            }
            let bound = match bind(&id) {
                Ok(bound) => bound,
                // Another process took the socket name between the check and
                // the bind: redraw rather than adopt a name that is not ours.
                Err(error) if error.kind() == ErrorKind::AddrInUse => continue,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "binding {}",
                            crate::one_line::path(&self.socket_path(&id))
                        )
                    });
                }
            };
            let snapshot = SessionSnapshot::new(super::SessionInfo {
                id,
                pid,
                started_ms: now_ms,
                socket,
            });
            log.upsert(&snapshot);
            log.prune(now_ms, snapshot.info.id.as_str());
            let bytes = log.encode()?;
            host_paths::atomic_write(&self.record(), &bytes, 0o600)
                .with_context(|| format!("writing {}", crate::one_line::path(&self.record())))?;
            return Ok(Some(Reserved {
                snapshot,
                bound,
                evicted_sessions: log.evicted_sessions,
            }));
        }
        bail!("could not reserve a session ID free of a live socket")
    }
}

/// A reserved session and whatever `reserve` bound for it.
pub(crate) struct Reserved<T> {
    pub(crate) snapshot: SessionSnapshot,
    pub(crate) bound: T,
    pub(crate) evicted_sessions: u64,
}

/// What one write changed, for the notice the launcher may print.
pub(crate) struct WriteReport {
    pub(crate) evicted_sessions: u64,
    pub(crate) warning: Option<String>,
}

/// The log's content, decoded.
pub(crate) struct Log {
    pub(crate) evicted_sessions: u64,
    pub(crate) sessions: Vec<SessionSnapshot>,
    writable: bool,
}

impl Log {
    fn new(evicted_sessions: u64, sessions: Vec<SessionSnapshot>) -> Self {
        Self {
            evicted_sessions,
            sessions,
            writable: true,
        }
    }

    fn contains(&self, sid: &str) -> bool {
        self.sessions
            .iter()
            .any(|session| session.info.id.as_str() == sid)
    }

    fn upsert(&mut self, own: &SessionSnapshot) {
        match self
            .sessions
            .iter_mut()
            .find(|session| session.info.id == own.info.id)
        {
            Some(slot) => *slot = own.clone(),
            None => self.sessions.push(own.clone()),
        }
    }

    /// Drop sessions that are history or that no longer exist.
    ///
    /// `own` is never pruned. The idle rule is the retention bound AC12 states;
    /// the other three drop an entry that says nothing a reader could act on: an
    /// ended session with no refusals, a socketless session whose heartbeat
    /// stopped, and a session whose socket file is gone.
    fn prune(&mut self, now_ms: i64, own: &str) {
        self.sessions.retain(|session| {
            if session.info.id.as_str() == own {
                return true;
            }
            let idle = now_ms.saturating_sub(activity_ms(session));
            if idle > RETENTION_MS {
                return false;
            }
            if !session.entries.is_empty() {
                return true;
            }
            if session.ended_ms.is_some() {
                return false;
            }
            match (session.info.socket, session.heartbeat_ms) {
                (true, _) => true,
                (false, Some(beat)) => now_ms.saturating_sub(beat) <= HEARTBEAT_STALE_MS,
                (false, None) => false,
            }
        });
    }

    /// Evict whole other sessions until the log fits, most-disposable first.
    ///
    /// Deterministic: one ordering, computed once, then taken from the front. An
    /// evicted *live* session is restored whole by its owner's next write, which
    /// is why evicting it is safe at all (AC12).
    fn evict(&mut self, own: &str) -> u64 {
        let mut evicted = 0;
        loop {
            let over_entries = self.total_entries() > MAX_LOG_ENTRIES;
            let over_bytes = self.encoded_len() > MAX_LOG_BYTES;
            if !over_entries && !over_bytes {
                return evicted;
            }
            let Some(victim) = self
                .sessions
                .iter()
                .enumerate()
                .filter(|(_, session)| session.info.id.as_str() != own)
                .min_by(|(_, a), (_, b)| eviction_order(a, b))
                .map(|(position, _)| position)
            else {
                return evicted;
            };
            self.sessions.remove(victim);
            evicted += 1;
        }
    }

    fn total_entries(&self) -> usize {
        self.sessions.iter().map(|s| s.entries.len()).sum()
    }

    fn encoded_len(&self) -> u64 {
        self.encode().map(|bytes| bytes.len() as u64).unwrap_or(u64::MAX)
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let file = LogFile {
            v: LOG_VERSION,
            evicted_sessions: self.evicted_sessions,
            sessions: self.sessions.clone(),
        };
        serde_json::to_vec(&file).context("encoding the refusal log")
    }
}

/// When this session was last doing anything at all.
pub(crate) fn activity_ms(session: &SessionSnapshot) -> i64 {
    let entries = session
        .entries
        .iter()
        .map(|entry| entry.last_ms)
        .max()
        .unwrap_or(session.info.started_ms);
    entries
        .max(session.info.started_ms)
        .max(session.heartbeat_ms.unwrap_or(i64::MIN))
        .max(session.ended_ms.unwrap_or(i64::MIN))
}

/// `(disposability rank, activity)` for eviction: ended first, then a session
/// that ended without telling anyone, then a live one; oldest activity first.
fn eviction_key(session: &SessionSnapshot) -> (u8, i64) {
    let rank = if session.ended_ms.is_some() {
        // Ended and said so: nothing can still be listening.
        0
    } else if !session.info.socket {
        // No control socket: whether it is `running (no control socket)` or
        // `ended (unclean)` depends on a heartbeat that only gets staler, so it
        // goes before any session that can still answer.
        1
    } else {
        2
    };
    (rank, activity_ms(session))
}

fn eviction_order(a: &SessionSnapshot, b: &SessionSnapshot) -> std::cmp::Ordering {
    eviction_key(a)
        .cmp(&eviction_key(b))
        // Ties are broken by ID so two runs over the same log agree.
        .then_with(|| a.info.id.as_str().cmp(b.info.id.as_str()))
}

/// The on-disk shape. `v` decides whether this build may write the file.
#[derive(Serialize, Deserialize)]
struct LogFile {
    v: u32,
    #[serde(default)]
    evicted_sessions: u64,
    #[serde(default)]
    sessions: Vec<SessionSnapshot>,
}

#[cfg(test)]
mod tests;
