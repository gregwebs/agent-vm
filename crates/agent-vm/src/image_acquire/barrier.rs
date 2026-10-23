//! The shared/exclusive publication barrier over one native image cache.
//!
//! Native publication has a window no reference lock can cover: the loader
//! writes archive aliases one reference at a time, and an ordinary preparation
//! reads metadata and hands the reference to the SDK, which consumes the cache
//! after our last reference-guarded read. Per-reference locks cannot express
//! "no alias moved while a launch consumes the cache". A single cache-wide
//! `flock` can:
//!
//! - **shared** for preparation, validation, canonical metadata/receipt writes,
//!   launch and setup verification — many coexist;
//! - **exclusive** for archive publication (import/build) — at most one, and
//!   no reader at the same time.
//!
//! This barrier is the outermost edge of the one lock-order hierarchy
//! documented in [ARCHITECTURE.md](../../../ARCHITECTURE.md#same-cache-publication-barrier-and-reference-guards):
//! nothing below it takes a host lock, and no caller takes it after one.
//!
//! # Why the wait is unbounded but interruptible
//!
//! A shared holder may be blocked in a stalled registry stream or a VM create
//! for an unbounded time, so there is no acquisition deadline and no lock
//! bypass. The wait is a real async loop, not a detached `spawn_blocking` task:
//! dropping the future releases the descriptor immediately, so a cancelled
//! caller cannot leave an orphan that later takes the lock with nobody left to
//! release it. One reference-free notice after a second of observed contention
//! keeps a long wait from looking like a hang; the total remains unlimited.

use std::path::Path;
use std::time::{Duration, Instant};

use crate::host_paths::{self, FlockAttempt, FlockMode};

/// The one cache-wide lock file. Stable inode: never unlinked or truncated.
pub(crate) const PUBLICATION_LOCK_FILE: &str = ".agent-vm-publication.lock";

/// Poll interval. Short enough that a released lock is noticed promptly, long
/// enough that an unbounded wait is not a busy loop.
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Emit the contention notice once this much contention has been observed.
const NOTICE_AFTER: Duration = Duration::from_secs(1);

/// The one reference-free contention notice: names no reference, path,
/// registry or credential.
pub(crate) const CONTENTION_NOTICE: &str =
    "waiting for another agent-vm image preparation or publication to finish";

/// Why the barrier could not be opened or taken. Closed text only.
#[derive(Debug)]
pub(crate) enum BarrierError {
    Open(anyhow::Error),
    Wait(anyhow::Error),
}

impl BarrierError {
    pub(crate) fn message(&self) -> String {
        match self {
            Self::Open(_) => {
                "opening the image-cache publication lock failed; check the image cache permissions"
                    .to_string()
            }
            Self::Wait(_) => "waiting for the image-cache publication lock failed".to_string(),
        }
    }

    /// Explicit-source rendering. The barrier's own paths are cache paths, not
    /// record-sourced references, so an operator can see the cause.
    pub(crate) fn into_explicit_error(self) -> anyhow::Error {
        match self {
            Self::Open(error) => error.context("opening the image-cache publication lock"),
            Self::Wait(error) => error.context("waiting for the image-cache publication lock"),
        }
    }
}

impl std::fmt::Display for BarrierError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message())
    }
}

impl std::error::Error for BarrierError {}

/// A held barrier. Dropping it closes the descriptor, which releases the
/// `flock`; the mode can never be upgraded in place.
pub(crate) struct PublicationBarrier {
    _file: std::fs::File,
}

impl PublicationBarrier {
    /// Shared: preparation, validation, canonical publication, launch,
    /// setup verification.
    pub(crate) async fn shared(cache_dir: &Path) -> Result<Self, BarrierError> {
        Self::acquire(cache_dir, FlockMode::Shared).await
    }

    /// Exclusive: archive publication (import/build), including the requested
    /// alias snapshot and rollback.
    pub(crate) async fn exclusive(cache_dir: &Path) -> Result<Self, BarrierError> {
        Self::acquire(cache_dir, FlockMode::Exclusive).await
    }

    async fn acquire(cache_dir: &Path, mode: FlockMode) -> Result<Self, BarrierError> {
        // A cold launch reaches this before the SDK has created its cache; the
        // directory is not a lock artifact, it is where the lock lives. `msb`
        // would create the same directory moments later, so creating it here
        // changes no ownership.
        std::fs::create_dir_all(cache_dir).map_err(|error| BarrierError::Open(error.into()))?;
        let path = cache_dir.join(PUBLICATION_LOCK_FILE);
        let file = host_paths::open_lock_file(&path).map_err(BarrierError::Open)?;
        let started = Instant::now();
        let mut noticed = false;
        let mut reported = false;
        loop {
            match host_paths::try_flock(&file, mode).map_err(BarrierError::Wait)? {
                FlockAttempt::Acquired => return Ok(Self { _file: file }),
                FlockAttempt::Contended => {
                    if !reported {
                        reported = true;
                        super::gate::checkpoint(super::gate::Stage::PublicationContended)
                            .map_err(BarrierError::Wait)?;
                    }
                }
            }
            if !noticed && started.elapsed() >= NOTICE_AFTER {
                noticed = true;
                eprintln!("{CONTENTION_NOTICE}");
            }
            // Cancellation-safe: dropping this future drops `file` and the
            // descriptor, so no orphan task can take the lock later.
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }
}

/// The path of the lock file in `cache_dir`, for independent `flock` probes.
#[cfg(test)]
pub(crate) fn lock_path(cache_dir: &Path) -> std::path::PathBuf {
    cache_dir.join(PUBLICATION_LOCK_FILE)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Runtime::new().unwrap()
    }

    #[test]
    fn shared_locks_coexist_and_exclude_exclusive() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = runtime();
        runtime.block_on(async {
            let first = PublicationBarrier::shared(directory.path()).await.unwrap();
            let second = PublicationBarrier::shared(directory.path()).await.unwrap();
            drop((first, second));
            let exclusive = PublicationBarrier::exclusive(directory.path())
                .await
                .unwrap();
            drop(exclusive);
        });
    }

    /// A cancelled waiter must not leave a task that takes the lock later.
    #[test]
    fn a_cancelled_waiter_releases_its_descriptor() {
        let directory = tempfile::tempdir().unwrap();
        let held = host_paths::open_lock_file(&lock_path(directory.path())).unwrap();
        assert_eq!(
            host_paths::try_flock(&held, FlockMode::Exclusive).unwrap(),
            FlockAttempt::Acquired
        );
        let runtime = runtime();
        runtime.block_on(async {
            let waiter = tokio::spawn({
                let dir = directory.path().to_path_buf();
                async move {
                    let barrier = PublicationBarrier::shared(&dir).await.unwrap();
                    drop(barrier);
                }
            });
            tokio::time::sleep(Duration::from_millis(150)).await;
            waiter.abort();
            let _ = waiter.await;
        });
        drop(held);
        // No detached waiter remains. Poll briefly: the abort is observed at
        // the waiter's next await point, so a straggler may still be unwinding
        // its descriptor for a few scheduler ticks. A waiter that survived
        // cancellation would hold the shared lock forever and time out here.
        let probe = host_paths::open_lock_file(&lock_path(directory.path())).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if host_paths::try_flock(&probe, FlockMode::Exclusive).unwrap()
                == FlockAttempt::Acquired
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "a cancelled waiter kept the publication barrier"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// An exclusive holder blocks a shared acquisition; releasing it lets the
    /// waiter make progress. This is real `flock`, not a test double.
    #[test]
    fn exclusive_holder_blocks_shared_acquisition_until_release() {
        let directory = tempfile::tempdir().unwrap();
        let held = host_paths::open_lock_file(&lock_path(directory.path())).unwrap();
        assert_eq!(
            host_paths::try_flock(&held, FlockMode::Exclusive).unwrap(),
            FlockAttempt::Acquired
        );
        let runtime = runtime();
        runtime.block_on(async {
            let mut waiter = tokio::spawn({
                let dir = directory.path().to_path_buf();
                async move { PublicationBarrier::shared(&dir).await.map(|_| ()) }
            });
            tokio::select! {
                outcome = &mut waiter => panic!("shared acquisition completed while exclusive was held: {outcome:?}"),
                _ = tokio::time::sleep(Duration::from_millis(200)) => {}
            }
            drop(held);
            tokio::time::timeout(Duration::from_secs(5), waiter)
                .await
                .expect("waiter made no progress after release")
                .expect("waiter join")
                .expect("shared acquisition");
        });
    }

    /// Independent probe: a shared holder refuses a non-blocking exclusive
    /// attempt, and vice versa.
    #[test]
    fn probe_helper_observes_both_modes() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = runtime();
        runtime.block_on(async {
            let shared = PublicationBarrier::shared(directory.path()).await.unwrap();
            let probe = host_paths::open_lock_file(&lock_path(directory.path())).unwrap();
            assert_eq!(
                host_paths::try_flock(&probe, FlockMode::Exclusive).unwrap(),
                FlockAttempt::Contended
            );
            assert_eq!(
                host_paths::try_flock(&probe, FlockMode::Shared).unwrap(),
                FlockAttempt::Acquired
            );
            drop(probe);
            drop(shared);
        });
    }
}
