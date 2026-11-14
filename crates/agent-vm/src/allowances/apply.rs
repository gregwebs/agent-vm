//! The launcher's live allowance controller: session-scope grants, the policy
//! swap that confirms them, and a revoke that only forgets what the runtime
//! confirmed.
//!
//! One policy computation, one writer: every live change derives its policy
//! through [`crate::network::LivePolicyPlan::derive_for`] — the same
//! `EgressAuthority::set_recorded` + `EgressAuthority::policy` the launch used —
//! and only then asks the runtime for a revision. Nothing here constructs a rule.
//!
//! # In memory, and only in memory
//!
//! A [`SessionAllowance`] lives in this struct's `session` table and vanishes at
//! teardown. It is never written to `allowances.json`, `refusals.json` or any
//! other file (R5). A confirmed `--project` grant is written through the facade
//! *after* the runtime confirms it, so a socket that cannot answer leaves the
//! store untouched (R9).
//!
//! # Three states of one entry
//!
//! * `revision: None` — accepted before `follow` attached the runtime. The CLI
//!   says so, and `flush_queued` either promotes it or drops it with a notice.
//! * `revision: Some(1)` — adopted from the project record at boot.
//! * `revision: Some(rev >= 2)` — confirmed by a live swap.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex as AsyncMutex;

use crate::egress_policy::Allowance;
use crate::image_pin::ProjectId;
use crate::network::{LivePolicyPlan, LivePolicyPrecondition};
use crate::project::ProjectDir;

use super::store::{RecordOutcome, StoreHandle};
use super::{ProjectAllowance, ProjectView, SessionAllowance};

/// The runtime's policy-replacement call, as the launcher holds it.
pub(crate) type PolicyUpdater = Arc<
    dyn Fn(microsandbox::NetworkPolicy) -> BoxFuture<'static, microsandbox::MicrosandboxResult<u64>>
        + Send
        + Sync,
>;

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// How many live entries one session may hold.
///
/// The store bounds itself (`MAX_RECORDS`, `MAX_BYTES`); the live tables had no
/// bound at all, and every entry is a rule in the policy handed to the runtime.
/// Cheap defence in depth with the store's own precedent (CODING_STANDARDS,
/// Configuration and Constants): a grant past this is refused, never dropped.
const MAX_LIVE_ALLOWANCES: usize = 256;

/// Which table a grant or revoke applies to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum GrantScope {
    Session,
    Project,
}

impl GrantScope {
    /// The scope a destination's *entry* lives in, for a reply that must not
    /// claim the scope the caller asked for (m06). Project wins when both tables
    /// name it: that is the entry that survives this launch.
    fn of_tables(in_project: bool) -> Self {
        if in_project {
            Self::Project
        } else {
            Self::Session
        }
    }
}

/// The three things every store write in the launcher needs, in one value.
///
/// They travelled as a positional `(store, project_id, project_path)` triple
/// through five functions, which is the confusion a named bundle removes: two of
/// the three are string-ish identifiers of different things
/// (CODING_STANDARDS, Types).
#[derive(Clone, Debug)]
pub(crate) struct ProjectRecord {
    store: super::StoreHandle,
    id: ProjectId,
    path: PathBuf,
}

impl ProjectRecord {
    /// Record one destination, mapping the writer's line to the reply's.
    async fn record(
        &self,
        destination: &Allowance,
        recorded_ms: i64,
    ) -> Result<RecordOutcome, String> {
        let store = self.store.clone();
        let id = self.id.as_str().to_owned();
        let path = self.path.clone();
        let destination = destination.clone();
        tokio::task::spawn_blocking(move || {
            store.record_path(&id, &path, &destination, recorded_ms)
        })
        .await
        .map_err(|error| format!("the project allowance write stopped: {error}"))?
        .map_err(|error| error.line())
    }
}

/// What a revoke removes. `All` removes the destination from both tables.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum RevokeScope {
    Session,
    Project,
    All,
}

impl RevokeScope {
    fn removes_session(self) -> bool {
        matches!(self, Self::Session | Self::All)
    }

    fn removes_project(self) -> bool {
        matches!(self, Self::Project | Self::All)
    }
}

/// Why a grant became a next-launch record instead of a live swap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum NextLaunchReason {
    /// The runtime is older than `network_policy_update`.
    RuntimeUnsupported,
    /// The destination would add a TLS-intercepted port the launch did not fix.
    InterceptedPortsFixedAtLaunch,
}

/// Why a grant was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum GrantRefusalReason {
    HostProxyInUse,
    InterceptedPortsFixedAtLaunch,
    /// The request names no destination, or its spelling is not an allowance.
    NotAllowable {
        message: String,
    },
    /// The runtime failed operationally: neither memory nor the store changed.
    RuntimeFailed {
        message: String,
    },
    /// The store write failed.
    Store {
        message: String,
    },
    /// This session already holds the maximum number of live allowances.
    Full {
        limit: usize,
    },
}

/// What one `grant` did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum GrantResult {
    Applied {
        destination: String,
        scope: GrantScope,
        revision: u64,
        recorded_ms: i64,
    },
    /// The runtime confirmed the swap, but the store write failed: the entry stays
    /// in force in the sandbox, demoted in memory to session scope (Ruling 2, N2).
    AppliedNotRecorded {
        destination: String,
        revision: u64,
        recorded_ms: i64,
        message: String,
    },
    /// Recorded for the next launch; nothing changed in this session.
    NextLaunch {
        destination: String,
        recorded_ms: i64,
        reason: NextLaunchReason,
    },
    /// Accepted before the runtime was attached; `flush_queued` decides.
    QueuedForBoot {
        destination: String,
        scope: GrantScope,
        recorded_ms: i64,
    },
    Refused {
        reason: GrantRefusalReason,
    },
}

/// Why a revoke could not be confirmed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum UnconfirmedReason {
    /// The runtime is older than `network_policy_update`.
    RuntimeUnsupported { message: String },
    /// The sandbox does not exist yet (`LiveSession::start < create`).
    SandboxStarting,
    /// The runtime failed operationally.
    RuntimeFailed { message: String },
    /// The narrowed policy could not be expressed, so nothing was sent.
    PolicyNotDerivable { clause: String },
    /// The session is still applying its queued boot grants, so a swap now would
    /// carry allowances the queue has not confirmed (ADR-0066 B03).
    BootPending,
}

impl UnconfirmedReason {
    /// One escaped sentence, for a terminal. The caller owns the framing.
    pub(crate) fn line(&self) -> String {
        let text = match self {
            Self::RuntimeUnsupported { message } => format!(
                "this runtime cannot replace its network policy ({message})"
            ),
            Self::SandboxStarting => {
                "the sandbox is still starting, so it cannot apply the change yet".to_owned()
            }
            Self::RuntimeFailed { message } => {
                format!("the runtime could not apply the change ({message})")
            }
            Self::PolicyNotDerivable { clause } => {
                format!("the narrowed policy cannot be expressed ({clause})")
            }
            Self::BootPending => {
                "the session is still applying its queued allowances; nothing changed — retry in a moment"
                    .to_owned()
            }
        };
        crate::one_line::text(&text).to_string()
    }
}

/// What one `revoke` did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum RevokeResult {
    Revoked {
        destination: String,
        scope: RevokeScope,
        /// The revision the runtime confirmed, or `None` when nothing was sent
        /// (a queued entry that was never in force). A claim of a revision nobody
        /// observed is exactly what A-m01 forbids.
        revision: Option<u64>,
        /// The destination is still in force from the other table or from this
        /// launch's configured authority.
        still_effective: bool,
    },
    /// Nothing in the requested scope named the destination. `still_effective`
    /// says whether the other scope — or this launch's own `--allow-egress` /
    /// `[network]` authority, which a revoke cannot remove — still admits it.
    NotInSession {
        destination: String,
        /// The scope that was asked for, so the sentence can name it.
        scope: RevokeScope,
        /// The last confirmed revision, if this session ever had one.
        revision: Option<u64>,
        still_effective: bool,
    },
    /// Nothing in memory changed; the caller must say so and exit non-zero.
    Unconfirmed {
        destination: String,
        scope: RevokeScope,
        reason: UnconfirmedReason,
    },
}

/// One allowance as the socket and the listing render it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct WireAllowance {
    pub(crate) destination: String,
    pub(crate) granted_ms: i64,
    pub(crate) revision: Option<u64>,
    pub(crate) not_recorded_error: Option<String>,
}

/// One session's active allowances, as `agent-vm access allowances` reads them.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SessionAllowancesSnapshot {
    pub(crate) session: Vec<WireAllowance>,
    pub(crate) project: Vec<WireAllowance>,
}

/// One active entry: the allowance, its confirmed revision and, for a demoted
/// `--project` grant, why it is not recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ActiveEntry {
    allowance: SessionAllowance,
    /// `Some(1)` for boot-adopted project records; `Some(rev)` (`rev >= 2`) for
    /// confirmed live swaps; `None` only for grants queued before `follow`.
    revision: Option<u64>,
    not_recorded_error: Option<String>,
}

impl ActiveEntry {
    /// An entry the runtime confirmed at `revision`.
    fn confirmed(
        allowance: SessionAllowance,
        revision: u64,
        not_recorded_error: Option<String>,
    ) -> Self {
        Self {
            allowance,
            revision: Some(revision),
            not_recorded_error,
        }
    }

    /// An entry accepted but not applied yet (`revision: None`).
    fn queued(allowance: SessionAllowance) -> Self {
        Self {
            allowance,
            revision: None,
            not_recorded_error: None,
        }
    }

    fn destination(&self) -> &Allowance {
        self.allowance.destination()
    }

    fn wire(&self) -> WireAllowance {
        WireAllowance {
            destination: self.allowance.destination().to_string(),
            granted_ms: self.allowance.granted_ms(),
            revision: self.revision,
            not_recorded_error: self.not_recorded_error.clone(),
        }
    }
}

struct State {
    record: ProjectRecord,
    /// The launch's base plan (updated once at `adopt_boot_allowances`).
    base_plan: LivePolicyPlan,
    /// The policy that plan derives with no live additions.
    base_policy: microsandbox::NetworkPolicy,
    /// Current derived plan, including active `session ∪ project` entries.
    plan: LivePolicyPlan,
    /// The policy `plan` derived. Kept beside the plan so `flush_queued` can hand
    /// it to the runtime without recomputing under a lock.
    policy: microsandbox::NetworkPolicy,
    /// The plan and policy the runtime last *accepted*. A failed flush restores
    /// these, not the boot plan: an intervening accepted swap would otherwise be
    /// forgotten while the sandbox still enforces it (B03).
    attached_plan: LivePolicyPlan,
    attached_policy: microsandbox::NetworkPolicy,
    updater: Option<PolicyUpdater>,
    /// `Some(1)` once `follow` attached the runtime; `Some(rev)` after a swap.
    policy_revision: Option<u64>,
    queued_for_boot: bool,
    session: Vec<ActiveEntry>,
    project: Vec<ActiveEntry>,
}

/// What one `revoke` needs from the state under one lock, so the tables can be
/// proposed on a copy and only committed once the runtime answers.
struct Snapshot {
    updater: Option<PolicyUpdater>,
    session: Vec<ActiveEntry>,
    project: Vec<ActiveEntry>,
    plan: LivePolicyPlan,
    revision: Option<u64>,
    queued_for_boot: bool,
}

impl State {
    fn entries(&self) -> impl Iterator<Item = &ActiveEntry> {
        self.session.iter().chain(self.project.iter())
    }

    fn any_queued(&self) -> bool {
        self.entries().any(|entry| entry.revision.is_none())
    }

    fn combined(&self) -> Vec<Allowance> {
        let mut combined: Vec<Allowance> = Vec::new();
        for entry in self.entries() {
            if !combined.contains(entry.destination()) {
                combined.push(entry.destination().clone());
            }
        }
        combined
    }
}

/// The live allowance controller one session owns behind an `Arc`.
pub(crate) struct LiveAllowances {
    /// Serializes every mutation and the boot flush, so two grants cannot derive
    /// from the same plan and commit out of order (first writer wins).
    op_lock: AsyncMutex<()>,
    state: Mutex<State>,
}

impl LiveAllowances {
    pub(crate) fn new(project: &ProjectDir, store: StoreHandle, plan: LivePolicyPlan) -> Arc<Self> {
        let base_policy = plan.policy();
        Arc::new(Self {
            op_lock: AsyncMutex::new(()),
            state: Mutex::new(State {
                record: ProjectRecord {
                    store,
                    id: ProjectId::of(project),
                    path: project.path().to_owned(),
                },
                base_policy: base_policy.clone(),
                base_plan: plan.clone(),
                plan: plan.clone(),
                policy: base_policy.clone(),
                attached_plan: plan,
                attached_policy: base_policy,
                updater: None,
                policy_revision: None,
                queued_for_boot: false,
                session: Vec::new(),
                project: Vec::new(),
            }),
        })
    }

    /// Adopt the project records the launch actually applied.
    ///
    /// Runs after `for_launch` read the store and before `follow` attaches the
    /// runtime. Any grant that arrived in between is queued (`revision: None`):
    /// the post-adoption plan re-derives over `configured ∪ adopted ∪ queued`, so
    /// the queued grant is not lost and does not sit on the configured-only plan.
    pub(crate) fn adopt_boot_allowances(
        &self,
        recorded: &ProjectView,
        adopted: &[ProjectAllowance],
        post_adoption_plan: LivePolicyPlan,
    ) -> Vec<String> {
        let mut warnings = Vec::new();
        let mut state = lock(&self.state);
        state.record.store = recorded.store_handle();
        state.base_plan = post_adoption_plan.clone();
        state.base_policy = post_adoption_plan.policy();
        for allowance in adopted {
            if let Some(entry) = state
                .project
                .iter_mut()
                .find(|entry| entry.destination() == allowance.destination())
            {
                // A pre-adoption `--project` grant that the store read back: it
                // was in the boot policy after all, so it is `rev 1`, not queued.
                entry.revision = Some(1);
            } else {
                state.project.push(ActiveEntry {
                    allowance: SessionAllowance::new(
                        allowance.destination().clone(),
                        allowance.recorded_ms(),
                    ),
                    revision: Some(1),
                    not_recorded_error: None,
                });
            }
        }
        state.queued_for_boot = state.any_queued();
        if state.queued_for_boot {
            match post_adoption_plan.derive_for(state.combined()) {
                Ok((plan, policy)) => {
                    state.plan = plan;
                    state.policy = policy;
                }
                Err(precondition) => {
                    // Two invariants make this arm unreachable: adoption only
                    // *adds* hostnames, so the subset test can only get easier, and
                    // `host_proxy_used` is constant for the whole launch, so a set
                    // that derived before adoption derives after it. If it is ever
                    // reached anyway, memory must not keep an entry the policy in
                    // hand does not contain: drop the queue here, exactly as a
                    // failed flush would, and say why in debug builds.
                    debug_assert!(
                        false,
                        "post-adoption re-derivation cannot fail: {precondition:?}"
                    );
                    for entry in state
                        .entries()
                        .filter(|entry| entry.revision.is_none())
                        .collect::<Vec<_>>()
                    {
                        let destination =
                            crate::config::escape_str(&entry.destination().to_string());
                        warnings.push(format!(
                            "queued allowance {destination} was not applied to this session: the policy after boot could not express it"
                        ));
                    }
                    state.session.retain(|entry| entry.revision.is_some());
                    state.project.retain(|entry| entry.revision.is_some());
                    state.plan = post_adoption_plan.clone();
                    state.policy = post_adoption_plan.policy();
                    state.queued_for_boot = false;
                }
            }
        } else {
            state.plan = post_adoption_plan.clone();
            state.policy = post_adoption_plan.policy();
        }
        warnings
    }

    /// Attach the runtime, synchronously under the state lock. Returns whether a
    /// queued grant is waiting for `flush_queued`.
    pub(crate) fn attach_updater(&self, updater: PolicyUpdater) -> bool {
        let mut state = lock(&self.state);
        state.policy_revision = Some(state.policy_revision.unwrap_or(1));
        // The policy the runtime is known to accept: the boot plan this session
        // was created with. Every accepted swap updates it.
        state.attached_plan = state.base_plan.clone();
        state.attached_policy = state.base_policy.clone();
        state.updater = Some(updater);
        state.queued_for_boot
    }

    /// Apply every queued grant, or drop it with a notice.
    ///
    /// On failure memory must match the runtime: every `revision: None` entry is
    /// removed, the plan returns to the boot plan, and each dropped destination is
    /// named with whether a project record still carries it forward.
    pub(crate) async fn flush_queued(&self) -> Vec<String> {
        let _op = self.op_lock.lock().await;
        let (updater, policy) = {
            let state = lock(&self.state);
            (state.updater.clone(), state.policy.clone())
        };
        let Some(updater) = updater else {
            return Vec::new();
        };
        match updater(policy).await {
            Ok(revision) => {
                let mut state = lock(&self.state);
                state.policy_revision = Some(revision);
                state.attached_plan = state.plan.clone();
                state.attached_policy = state.policy.clone();
                state.queued_for_boot = false;
                for entry in state.session.iter_mut() {
                    if entry.revision.is_none() {
                        entry.revision = Some(revision);
                    }
                }
                for entry in state.project.iter_mut() {
                    if entry.revision.is_none() {
                        entry.revision = Some(revision);
                    }
                }
                Vec::new()
            }
            Err(error) => {
                let reason = crate::one_line::text(&format!("{error:#}")).to_string();
                let mut warnings = Vec::new();
                let mut state = lock(&self.state);
                for (in_project, entry) in state
                    .session
                    .iter()
                    .map(|entry| (false, entry))
                    .chain(state.project.iter().map(|entry| (true, entry)))
                    .filter(|(_, entry)| entry.revision.is_none())
                    .collect::<Vec<_>>()
                {
                    let destination = crate::config::escape_str(&entry.destination().to_string());
                    warnings.push(if in_project {
                        format!(
                            "warning: queued allowance {destination} was not applied to this session ({reason}); the project allowance record still carries it to the next launch"
                        )
                    } else {
                        format!(
                            "warning: queued session allowance {destination} was not applied to this session ({reason}); no project record was written"
                        )
                    });
                }
                state.session.retain(|entry| entry.revision.is_some());
                state.project.retain(|entry| entry.revision.is_some());
                // The runtime keeps what it last accepted, which need not be the
                // boot plan. Restoring the boot plan here was the half of B03 that
                // could outlive the guard in `grant`/`revoke`.
                state.plan = state.attached_plan.clone();
                state.policy = state.attached_policy.clone();
                state.queued_for_boot = false;
                warnings
            }
        }
    }

    /// Grant one destination, to this session and optionally the project.
    pub(crate) async fn grant(
        &self,
        destination: Option<&str>,
        scope: GrantScope,
        now_ms: i64,
    ) -> GrantResult {
        let _op = self.op_lock.lock().await;
        let Some(text) = destination else {
            return GrantResult::Refused {
                reason: GrantRefusalReason::NotAllowable {
                    message: "the request names no destination".to_owned(),
                },
            };
        };
        let destination = match Allowance::parse(text) {
            Ok(destination) => destination,
            Err(error) => {
                return GrantResult::Refused {
                    reason: GrantRefusalReason::NotAllowable {
                        message: format!("{error}"),
                    },
                };
            }
        };

        let (record, already, held) = {
            let state = lock(&self.state);
            let already = state
                .entries()
                .find(|item| item.destination() == &destination)
                .cloned();
            (
                state.record.clone(),
                already,
                state.session.len() + state.project.len(),
            )
        };

        // First writer wins: an allowance this session already holds is not
        // re-applied, so a duplicate `grant` costs no runtime call (R7, M4).
        if let Some(entry) = already {
            return self
                .settle_existing(entry, &destination, scope, &record)
                .await;
        }

        // The live tables are bounded like the store's own, and refused rather
        // than silently dropped: every entry is a rule the runtime would enforce.
        if held >= MAX_LIVE_ALLOWANCES {
            return GrantResult::Refused {
                reason: GrantRefusalReason::Full {
                    limit: MAX_LIVE_ALLOWANCES,
                },
            };
        }

        let (updater, plan, queued_for_boot) = {
            let state = lock(&self.state);
            (
                state.updater.clone(),
                state.plan.clone(),
                state.queued_for_boot,
            )
        };
        // A swap may not carry an entry the runtime has not confirmed: while the
        // boot flush is pending, its queue is the only writer of that policy, so a
        // grant in the window is queued exactly as it would be before `follow`
        // (B03). A swap that won this lock first would leave memory and runtime
        // disagreeing as soon as the flush failed.
        let updater = if queued_for_boot { None } else { updater };
        let mut combined = {
            let state = lock(&self.state);
            state.combined()
        };
        combined.push(destination.clone());

        let derived = plan.derive_for(combined);
        let (next_plan, policy) = match derived {
            Ok(derived) => derived,
            Err(LivePolicyPrecondition::HostProxyInUse) => {
                return GrantResult::Refused {
                    reason: GrantRefusalReason::HostProxyInUse,
                };
            }
            Err(LivePolicyPrecondition::InterceptedPortsFixedAtLaunch) => {
                return self
                    .defer_or_refuse(
                        &destination,
                        scope,
                        NextLaunchReason::InterceptedPortsFixedAtLaunch,
                        now_ms,
                        &record,
                    )
                    .await;
            }
        };

        let Some(updater) = updater else {
            // Pre-`follow` (or with the boot queue still pending): record first if
            // the grant is a project one, then queue it. `flush_queued` either
            // promotes it or drops it with a notice.
            if scope == GrantScope::Project {
                match record.record(&destination, now_ms).await {
                    Ok(outcome) => {
                        self.queue_grant(
                            destination.clone(),
                            GrantScope::Project,
                            outcome.recorded_ms(),
                            next_plan,
                            policy,
                        );
                        return GrantResult::QueuedForBoot {
                            destination: destination.to_string(),
                            scope: GrantScope::Project,
                            recorded_ms: outcome.recorded_ms(),
                        };
                    }
                    Err(message) => {
                        return GrantResult::Refused {
                            reason: GrantRefusalReason::Store { message },
                        };
                    }
                }
            }
            self.queue_grant(
                destination.clone(),
                GrantScope::Session,
                now_ms,
                next_plan,
                policy,
            );
            return GrantResult::QueuedForBoot {
                destination: destination.to_string(),
                scope: GrantScope::Session,
                recorded_ms: now_ms,
            };
        };

        match updater(policy.clone()).await {
            Ok(revision) => {
                if scope == GrantScope::Project {
                    match record.record(&destination, now_ms).await {
                        Ok(outcome) => {
                            self.commit_grant(
                                GrantScope::Project,
                                ActiveEntry::confirmed(
                                    SessionAllowance::new(
                                        destination.clone(),
                                        outcome.recorded_ms(),
                                    ),
                                    revision,
                                    None,
                                ),
                                next_plan,
                                policy,
                            );
                            GrantResult::Applied {
                                destination: destination.to_string(),
                                scope: GrantScope::Project,
                                revision,
                                recorded_ms: outcome.recorded_ms(),
                            }
                        }
                        Err(message) => {
                            // Demote to session scope: the sandbox has it, the
                            // project does not, and every later render must say so.
                            self.commit_grant(
                                GrantScope::Session,
                                ActiveEntry::confirmed(
                                    SessionAllowance::new(destination.clone(), now_ms),
                                    revision,
                                    Some(message.clone()),
                                ),
                                next_plan,
                                policy,
                            );
                            GrantResult::AppliedNotRecorded {
                                destination: destination.to_string(),
                                revision,
                                recorded_ms: now_ms,
                                message,
                            }
                        }
                    }
                } else {
                    self.commit_grant(
                        GrantScope::Session,
                        ActiveEntry::confirmed(
                            SessionAllowance::new(destination.clone(), now_ms),
                            revision,
                            None,
                        ),
                        next_plan,
                        policy,
                    );
                    GrantResult::Applied {
                        destination: destination.to_string(),
                        scope: GrantScope::Session,
                        revision,
                        recorded_ms: now_ms,
                    }
                }
            }
            Err(microsandbox::MicrosandboxError::Unsupported { .. }) => {
                match record.record(&destination, now_ms).await {
                    Ok(outcome) => GrantResult::NextLaunch {
                        destination: destination.to_string(),
                        recorded_ms: outcome.recorded_ms(),
                        reason: NextLaunchReason::RuntimeUnsupported,
                    },
                    Err(message) => GrantResult::Refused {
                        reason: GrantRefusalReason::Store { message },
                    },
                }
            }
            Err(other) => {
                // The branch below is deliberately never taken, and deliberately
                // present: recording a project allowance on a *failed* runtime
                // swap would write a record no runtime confirmed (R9, AC13), and
                // the switch is the mutation control's anchor
                // (`grant-failed-writes-project-record`, plan §8.7) — flipping it
                // to `true` must be caught by
                // `project_grant_writes_no_record_when_live_session_cannot_confirm`.
                // Deleting the branch would delete the check.
                let record_on_runtime_failure = false;
                if record_on_runtime_failure && scope == GrantScope::Project {
                    let _ = record.record(&destination, now_ms).await;
                }
                GrantResult::Refused {
                    reason: GrantRefusalReason::RuntimeFailed {
                        message: crate::one_line::text(&format!("{other:#}")).to_string(),
                    },
                }
            }
        }
    }

    /// Revoke one destination from this session, the project, or both.
    pub(crate) async fn revoke(&self, destination: &Allowance, scope: RevokeScope) -> RevokeResult {
        let _op = self.op_lock.lock().await;
        let snapshot = {
            let state = lock(&self.state);
            Snapshot {
                updater: state.updater.clone(),
                session: state.session.clone(),
                project: state.project.clone(),
                plan: state.plan.clone(),
                revision: state.policy_revision,
                queued_for_boot: state.queued_for_boot,
            }
        };
        let mut next_session = snapshot.session;
        let mut next_project = snapshot.project;
        let removed_confirmed = {
            let confirmed = |entries: &[ActiveEntry]| {
                entries
                    .iter()
                    .any(|entry| entry.destination() == destination && entry.revision.is_some())
            };
            (scope.removes_session() && confirmed(&next_session))
                || (scope.removes_project() && confirmed(&next_project))
        };
        let before_session = next_session.len();
        let before_project = next_project.len();
        if scope.removes_session() {
            next_session.retain(|entry| entry.destination() != destination);
        }
        if scope.removes_project() {
            next_project.retain(|entry| entry.destination() != destination);
        }
        let removed = next_session.len() != before_session || next_project.len() != before_project;
        if !removed {
            // What is in force is a fact about the **policy**, not about the
            // tables: this launch's own `--allow-egress` / `[network]` authority
            // cannot be revoked from here, so a destination it admits is still
            // allowed even though no allowance names it (ADR-0066 §7, B01).
            let still_effective = snapshot.plan.is_configured(destination)
                || next_session
                    .iter()
                    .chain(next_project.iter())
                    .any(|entry| entry.destination() == destination);
            return RevokeResult::NotInSession {
                destination: destination.to_string(),
                scope,
                revision: snapshot.revision,
                still_effective,
            };
        }
        // A queued entry (`revision: None`) is not in force yet: dropping only
        // entries that were never confirmed needs no runtime call and no policy
        // swap. A *confirmed* removed entry always needs one, or memory would
        // forget an allowance the sandbox still enforces.
        let only_queued = !removed_confirmed;
        let mut combined: Vec<Allowance> = Vec::new();
        for entry in next_session.iter().chain(next_project.iter()) {
            if !combined.contains(entry.destination()) {
                combined.push(entry.destination().clone());
            }
        }
        let derived = match snapshot.plan.derive_for(combined) {
            Ok(derived) => derived,
            Err(precondition) => {
                return RevokeResult::Unconfirmed {
                    destination: destination.to_string(),
                    scope,
                    reason: UnconfirmedReason::PolicyNotDerivable {
                        clause: precondition.clause().to_owned(),
                    },
                };
            }
        };
        if only_queued {
            // Dropping an entry that was never in force needs no runtime call: the
            // plan narrows, and whichever writer owns the policy next (the boot
            // flush, or the next swap) sends the narrowed set. Nothing was in
            // force, so there is no revision to report.
            let still_effective = derived.0.is_configured(destination);
            let mut state = lock(&self.state);
            state.session = next_session;
            state.project = next_project;
            state.plan = derived.0;
            state.policy = derived.1;
            state.queued_for_boot = state.any_queued();
            return RevokeResult::Revoked {
                destination: destination.to_string(),
                scope,
                revision: None,
                still_effective,
            };
        }
        let Some(updater) = snapshot.updater else {
            return RevokeResult::Unconfirmed {
                destination: destination.to_string(),
                scope,
                reason: UnconfirmedReason::SandboxStarting,
            };
        };
        if snapshot.queued_for_boot {
            // A swap now would carry entries the boot flush has not confirmed, and
            // that flush is the only writer of the pending policy (B03). A queued
            // entry was already droppable above; a *confirmed* one cannot be
            // removed until the queue has settled.
            return RevokeResult::Unconfirmed {
                destination: destination.to_string(),
                scope,
                reason: UnconfirmedReason::BootPending,
            };
        }
        match updater(derived.1.clone()).await {
            Ok(revision) => {
                // What remains in force is a fact about the derived policy, not
                // only about the tables: the launch's configured authority cannot
                // be revoked, so it still admits the destination.
                let still_effective = derived.0.is_configured(destination)
                    || next_session
                        .iter()
                        .chain(next_project.iter())
                        .any(|entry| entry.destination() == destination);
                let mut state = lock(&self.state);
                state.session = next_session;
                state.project = next_project;
                state.plan = derived.0.clone();
                state.policy = derived.1.clone();
                state.attached_plan = derived.0;
                state.attached_policy = derived.1;
                state.policy_revision = Some(revision);
                state.queued_for_boot = state.any_queued();
                RevokeResult::Revoked {
                    destination: destination.to_string(),
                    scope,
                    revision: Some(revision),
                    still_effective,
                }
            }
            Err(microsandbox::MicrosandboxError::Unsupported { .. }) => RevokeResult::Unconfirmed {
                destination: destination.to_string(),
                scope,
                reason: UnconfirmedReason::RuntimeUnsupported {
                    message: "this runtime cannot replace its network policy".to_owned(),
                },
            },
            Err(error) => RevokeResult::Unconfirmed {
                destination: destination.to_string(),
                scope,
                reason: UnconfirmedReason::RuntimeFailed {
                    message: crate::one_line::text(&format!("{error:#}")).to_string(),
                },
            },
        }
    }

    /// This session's active allowances, for the socket's `allowances` op.
    pub(crate) fn snapshot(&self) -> SessionAllowancesSnapshot {
        let state = lock(&self.state);
        SessionAllowancesSnapshot {
            session: state.session.iter().map(ActiveEntry::wire).collect(),
            project: state.project.iter().map(ActiveEntry::wire).collect(),
        }
    }

    /// Answer a `grant` for a destination this session already holds.
    ///
    /// Two honesty rules live here. A queued entry is not in force, so it is
    /// answered as queued — but a `--project` request must still leave a record
    /// behind, or say why it did not (B02): the reply the CLI renders claims
    /// "recorded project allowance", and a claim without a record is the one thing
    /// R9/AC13 forbid. And the scope echoed back is the scope the entry *lives in*,
    /// not the one the caller asked for (m06), so a later `revoke --session-only`
    /// does not contradict what the grant said.
    async fn settle_existing(
        &self,
        entry: ActiveEntry,
        destination: &Allowance,
        scope: GrantScope,
        record: &ProjectRecord,
    ) -> GrantResult {
        let in_project = {
            let state = lock(&self.state);
            state
                .project
                .iter()
                .any(|item| item.destination() == destination)
        };
        if entry.revision.is_none() {
            return match (scope, in_project) {
                (GrantScope::Project, false) => {
                    self.record_queued_as_project(entry, destination, record)
                        .await
                }
                _ => GrantResult::QueuedForBoot {
                    destination: destination.to_string(),
                    scope: GrantScope::of_tables(in_project),
                    recorded_ms: entry.allowance.granted_ms(),
                },
            };
        }
        let revision = entry.revision.unwrap_or(1);
        match scope {
            // Already in force in this session: report it without another swap.
            GrantScope::Session => GrantResult::Applied {
                destination: destination.to_string(),
                scope: GrantScope::of_tables(in_project),
                revision,
                recorded_ms: entry.allowance.granted_ms(),
            },
            // A project grant already recorded and confirmed: nothing to do.
            GrantScope::Project if in_project && entry.not_recorded_error.is_none() => {
                GrantResult::Applied {
                    destination: destination.to_string(),
                    scope: GrantScope::Project,
                    revision,
                    recorded_ms: entry.allowance.granted_ms(),
                }
            }
            // A demoted session grant (or a session-only one) asked for as a
            // project grant: try the store, keeping the session entry.
            GrantScope::Project => self.retry_project_record(entry, destination, record).await,
        }
    }

    /// A `--project` grant that lands on an entry still queued for boot.
    ///
    /// There is no swap to make — the entry is not in force yet — but the record
    /// can be written now, and must be: the reply says `recorded project
    /// allowance`. The entry moves to the project table so the queue flush and
    /// every later render agree with the store.
    async fn record_queued_as_project(
        &self,
        entry: ActiveEntry,
        destination: &Allowance,
        record: &ProjectRecord,
    ) -> GrantResult {
        match record
            .record(destination, entry.allowance.granted_ms())
            .await
        {
            Ok(outcome) => {
                let mut state = lock(&self.state);
                state
                    .session
                    .retain(|item| item.destination() != destination);
                if !state
                    .project
                    .iter()
                    .any(|item| item.destination() == destination)
                {
                    state
                        .project
                        .push(ActiveEntry::queued(SessionAllowance::new(
                            destination.clone(),
                            outcome.recorded_ms(),
                        )));
                }
                state.queued_for_boot = state.any_queued();
                GrantResult::QueuedForBoot {
                    destination: destination.to_string(),
                    scope: GrantScope::Project,
                    recorded_ms: outcome.recorded_ms(),
                }
            }
            // Never claim `recorded` without a record: the caller gets the store's
            // own refusal, and nothing moved between the tables.
            Err(message) => GrantResult::Refused {
                reason: GrantRefusalReason::Store { message },
            },
        }
    }

    async fn retry_project_record(
        &self,
        entry: ActiveEntry,
        destination: &Allowance,
        record: &ProjectRecord,
    ) -> GrantResult {
        let revision = entry.revision.unwrap_or(1);
        match record
            .record(destination, entry.allowance.granted_ms())
            .await
        {
            Ok(outcome) => {
                let mut state = lock(&self.state);
                if !state
                    .project
                    .iter()
                    .any(|item| item.destination() == destination)
                {
                    state.project.push(ActiveEntry::confirmed(
                        SessionAllowance::new(destination.clone(), outcome.recorded_ms()),
                        revision,
                        None,
                    ));
                }
                state.queued_for_boot = state.any_queued();
                GrantResult::Applied {
                    destination: destination.to_string(),
                    scope: GrantScope::Project,
                    revision,
                    recorded_ms: outcome.recorded_ms(),
                }
            }
            Err(message) => {
                // The demotion must outlive the reply: R9/AC13 require *every*
                // later `access` / `access allowances` render to keep saying the
                // session holds it and no record does (A-M02).
                {
                    let mut state = lock(&self.state);
                    for item in state.session.iter_mut() {
                        if item.destination() == destination {
                            item.not_recorded_error = Some(message.clone());
                        }
                    }
                }
                GrantResult::AppliedNotRecorded {
                    destination: destination.to_string(),
                    revision,
                    recorded_ms: entry.allowance.granted_ms(),
                    message,
                }
            }
        }
    }

    async fn defer_or_refuse(
        &self,
        destination: &Allowance,
        scope: GrantScope,
        reason: NextLaunchReason,
        now_ms: i64,
        record: &ProjectRecord,
    ) -> GrantResult {
        if scope == GrantScope::Session {
            return GrantResult::Refused {
                reason: GrantRefusalReason::InterceptedPortsFixedAtLaunch,
            };
        }
        match record.record(destination, now_ms).await {
            Ok(outcome) => GrantResult::NextLaunch {
                destination: destination.to_string(),
                recorded_ms: outcome.recorded_ms(),
                reason,
            },
            Err(message) => GrantResult::Refused {
                reason: GrantRefusalReason::Store { message },
            },
        }
    }

    /// Commit one confirmed entry, and the policy that carries it.
    ///
    /// The accepted policy is recorded here as well, so a later flush failure
    /// restores what the runtime actually holds rather than the boot plan (B03).
    fn commit_grant(
        &self,
        scope: GrantScope,
        entry: ActiveEntry,
        next_plan: LivePolicyPlan,
        policy: microsandbox::NetworkPolicy,
    ) {
        let revision = entry.revision;
        let mut state = lock(&self.state);
        match scope {
            GrantScope::Session => state.session.push(entry),
            GrantScope::Project => state.project.push(entry),
        }
        state.plan = next_plan.clone();
        state.policy = policy.clone();
        state.attached_plan = next_plan;
        state.attached_policy = policy;
        if revision.is_some() {
            state.policy_revision = revision;
        }
        state.queued_for_boot = state.any_queued();
    }

    fn queue_grant(
        &self,
        destination: Allowance,
        scope: GrantScope,
        recorded_ms: i64,
        next_plan: LivePolicyPlan,
        policy: microsandbox::NetworkPolicy,
    ) {
        let mut state = lock(&self.state);
        let entry = ActiveEntry::queued(SessionAllowance::new(destination, recorded_ms));
        match scope {
            GrantScope::Session => state.session.push(entry),
            GrantScope::Project => state.project.push(entry),
        }
        state.plan = next_plan;
        state.policy = policy;
        state.queued_for_boot = true;
    }
}
