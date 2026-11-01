//! One child per session key, for the length of one launch (#202).
//!
//! A slot is `Idle`, `Live` or `Failed`. Starting is lazy: a launch that never
//! reads a SecretSpec-sourced credential spawns nothing. A **start** failure is
//! sticky for the launch, so a broken executable costs one attempt rather than
//! one per rule; a **request** failure kills and re-arms the slot, so the next
//! read gets a fresh child. A leader that exited while idle — the phase-1 →
//! phase-2 window — is replaced once, transparently, and only when the request
//! provably never reached it (`EPIPE` before a byte, or an observed exit).

use std::collections::BTreeMap;
use std::sync::Mutex;

use super::config::{SecretspecName, SessionKey};
use super::failure::SecretspecFailure;
use super::protocol::Keep;
use super::session::{Bounds, Exchange, Session};
use crate::secret_store::{Resolved, ServiceName};

/// At most one transparent restart per read: a single read must not become a
/// spawn loop against a child that dies on every request.
const RESTART_ATTEMPTS: usize = 2;

/// The test-only spawn seam. `None` in production, where [`Session::start`] is
/// called directly: the pool stores no trait object outside a test build.
#[cfg(test)]
pub(super) type TestStarter =
    Box<dyn Fn(&SessionKey, &Bounds) -> Result<Session, SecretspecFailure> + Send + Sync>;

pub(super) struct SessionPool {
    bounds: Bounds,
    state: Mutex<PoolState>,
    #[cfg(test)]
    starter: Option<TestStarter>,
}

struct PoolState {
    /// Set before any session is shut down, so no later read can start one.
    closed: bool,
    slots: BTreeMap<SessionKey, Slot>,
}

enum Slot {
    /// Nothing has been started for this key, or the last child is gone.
    Idle,
    Live(Session),
    /// A start failed. Sticky for the launch.
    Failed(SecretspecFailure),
}

impl SessionPool {
    pub(super) fn production() -> Self {
        Self::new(Bounds::production())
    }

    fn new(bounds: Bounds) -> Self {
        Self {
            bounds,
            state: Mutex::new(PoolState {
                closed: false,
                slots: BTreeMap::new(),
            }),
            #[cfg(test)]
            starter: None,
        }
    }

    #[cfg(test)]
    pub(super) fn with_bounds(bounds: Bounds) -> Self {
        Self::new(bounds)
    }

    #[cfg(test)]
    pub(super) fn with_starter(bounds: Bounds, starter: TestStarter) -> Self {
        Self {
            bounds,
            state: Mutex::new(PoolState {
                closed: false,
                slots: BTreeMap::new(),
            }),
            starter: Some(starter),
        }
    }

    fn start(&self, key: &SessionKey) -> Result<Session, SecretspecFailure> {
        #[cfg(test)]
        if let Some(starter) = &self.starter {
            return starter(key, &self.bounds);
        }
        Session::start(key, &self.bounds)
    }

    /// Read one secret, starting or restarting the child as needed.
    pub(super) fn get(
        &self,
        key: &SessionKey,
        name: &SecretspecName,
        label: &ServiceName,
    ) -> Resolved {
        let Ok(mut state) = self.state.lock() else {
            // A panic in another thread is not a SecretSpec failure; from the
            // launch's point of view the session could not be used.
            return Resolved::SecretspecUnavailable(SecretspecFailure::SessionLost);
        };
        if state.closed {
            return Resolved::SecretspecUnavailable(SecretspecFailure::SessionClosed);
        }
        let slot = state.slots.entry(key.clone()).or_insert(Slot::Idle);
        for _ in 0..RESTART_ATTEMPTS {
            if let Slot::Failed(failure) = slot {
                return Resolved::SecretspecUnavailable(*failure);
            }
            if matches!(slot, Slot::Idle) {
                match self.start(key) {
                    Ok(session) => *slot = Slot::Live(session),
                    Err(failure) => {
                        *slot = Slot::Failed(failure);
                        return Resolved::SecretspecUnavailable(failure);
                    }
                }
            }
            let Some(session) = live(slot) else {
                // Unreachable: the two arms above leave `Live`.
                return Resolved::SecretspecUnavailable(SecretspecFailure::SessionLost);
            };
            // An idle death between phases is observed without reaping and
            // never touches the group; replacing the slot drops the old
            // session, whose guard signals that group.
            if session.leader_exited() {
                *slot = Slot::Idle;
                continue;
            }
            return match session.get(name, &self.bounds, label) {
                Exchange::Answered(resolved, Keep::Session) => resolved,
                Exchange::Answered(resolved, Keep::Kill) => {
                    *slot = Slot::Idle;
                    resolved
                }
                // `EPIPE` before a byte: the child died while idle, so the
                // request provably never reached it.
                Exchange::DeadBeforeRequest => {
                    *slot = Slot::Idle;
                    continue;
                }
            };
        }
        Resolved::SecretspecUnavailable(SecretspecFailure::SessionLost)
    }

    /// Test-only: whether the leader behind `key`'s slot has exited, observed
    /// without reaping it — the pool's own restart condition, without a sleep.
    ///
    /// A test that had to guess when the leader exited would either race the
    /// restart or mask it; this reads the same predicate `get` reads.
    #[cfg(test)]
    pub(super) fn leader_exited_for_test(&self, key: &SessionKey) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        match state.slots.get_mut(key) {
            Some(Slot::Live(session)) => session.leader_exited(),
            Some(Slot::Idle) | Some(Slot::Failed(_)) | None => false,
        }
    }

    /// Idempotent. Marks the pool closed **first**, so no read can start a child
    /// afterwards, and it closes even a poisoned lock: `into_inner` still yields
    /// the state, so a panic elsewhere cannot leave sessions alive.
    pub(super) fn close(&self) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.closed = true;
        let live: Vec<Session> = std::mem::take(&mut state.slots)
            .into_values()
            .filter_map(|slot| match slot {
                Slot::Live(session) => Some(session),
                Slot::Idle | Slot::Failed(_) => None,
            })
            .collect();
        drop(state);
        for session in live {
            session.shutdown();
        }
    }
}

/// The `Live` session behind a slot, without a panic path.
fn live(slot: &mut Slot) -> Option<&mut Session> {
    match slot {
        Slot::Live(session) => Some(session),
        Slot::Idle | Slot::Failed(_) => None,
    }
}
