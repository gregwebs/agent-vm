//! Private strict schema and short, bounded HOME transactions.
//!
//! # Why the retained-default module is both a dependency and a caller
//!
//! `boot_image::default_selection` owns the host record's v1 bytes
//! (`SELECTION_FILE`, `decode_snapshot`, `encode_snapshot`, `snapshot_at`) and
//! consults this module for the *logical* record, so the two modules name each
//! other. The cycle is acyclic where it matters: this module calls only the pure
//! byte-level helpers, never `load`, and `boot_image` reaches this module through
//! three **observations** — `default_selection::load` → [`Store::load_default`],
//! `image_pin::load_default_slot` → [`Store::default_slot`], and
//! `image_pin::observe_defaults` → [`Store::observe_defaults`]. None is a
//! transaction, and `image_pin` never calls `boot_image`'s selection, so no lock
//! is taken twice. Putting the schema here instead would duplicate the host
//! record's format in the module that must preserve a user's own bytes; putting
//! the transaction there would move approval into a module that knows only one
//! tier.
//!
//! # Why a project default is stored here
//!
//! A project's established default (ADR-0067) must be written in the **same**
//! save as the pin that first approved its content, so its record lives in this
//! file rather than beside it. Everything else about it — the concepts, the
//! flows and the host's starting choice — is [`super::project_default`].
use std::collections::BTreeSet;
use std::fs::{DirBuilder, File};
use std::io::{ErrorKind, Write as _};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rustix::fs::{FileType, Mode, OFlags};

use super::active::{
    Change, ClaimFacts, ClaimPlan, HeldRoles, ResolvedRoles, Role, RoleClaim, RoleMask, ScopeKey,
    after_role, checked_next_sequence, claim_knowledge, knowledge, may_retire,
};
use super::completion::{CommitReport, Completion};
use super::presentation::{ObservedPin, ProjectPinsSnapshot};
use super::project_default::{DefaultAdoption, ProjectDefault};
use super::*;
use crate::boot_image::default_selection::{self as default, SELECTION_FILE};
use crate::config;
use crate::host_paths::{self, FlockMode, FlockWait};

const MAX_BYTES: u64 = 4 * 1024 * 1024;
const STORE_VERSION: u32 = 2;
/// The host-wide format before #532. Recognized only to refuse it with upgrade
/// instructions: it is never read, rewritten, moved or recovered, because
/// guessing which project each approval belonged to would authorize content
/// nothing measured.
const LEGACY_VERSION: u32 = 1;
const READ_WAIT: Duration = Duration::from_secs(2);
const WRITE_WAIT: Duration = Duration::from_secs(30);

/// The fallback's coordination file, beside `SELECTION_FILE`. It exists so a
/// default-only write and a pin+default write serialize against each other.
const DEFAULT_LOCK_FILE: &str = "default-image.lock";

/// The debug-build-only deterministic checkpoint/fault seam for the pin
/// transaction tests. A release binary ignores `AGENT_VM_TEST_PIN_GATE`
/// entirely; with no gate configured every call is a no-op.
///
/// Hooks report stages only — never a reference, digest, path or consent value —
/// so a gate can neither forge content nor grant approval, and a fault reply is
/// accepted only at the stage that describes it.
mod gate {
    #[cfg(debug_assertions)]
    use std::io::{BufRead, BufReader, Write};

    #[cfg(debug_assertions)]
    use anyhow::{Result, anyhow};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum Stage {
        /// The result reference is published and the exclusive barrier is
        /// released, before its read-back (#391).
        Published,
        /// The candidate is acquired and validated but not yet approved.
        CandidateReady,
        BeforePinLock,
        PinLocked,
        /// Before the single host-record save of a default-tier preparation.
        BeforeDefaultSave,
        DefaultSaved,
        BeforePinSave,
        PinCommitted,
        /// Emitted immediately after the one-time authority-lock wait notice was
        /// *attempted*, so a test can prove the write happened while it still
        /// held the real pin lock. Carries no reference, path, digest or consent.
        AuthorityNoticeAttempted,
    }

    impl Stage {
        #[cfg(debug_assertions)]
        fn wire(self) -> &'static str {
            match self {
                Self::Published => "published",
                Self::CandidateReady => "candidate-ready",
                Self::BeforePinLock => "before-pin-lock",
                Self::PinLocked => "pin-locked",
                Self::BeforeDefaultSave => "before-default-save",
                Self::DefaultSaved => "default-saved",
                Self::BeforePinSave => "before-pin-save",
                Self::PinCommitted => "pin-committed",
                Self::AuthorityNoticeAttempted => "authority-notice-attempted",
            }
        }

        /// Only the stages immediately before a real write accept a fault.
        #[cfg(debug_assertions)]
        fn accepts_fault(self) -> bool {
            matches!(self, Self::BeforeDefaultSave | Self::BeforePinSave)
        }
    }

    #[cfg(debug_assertions)]
    pub(super) fn checkpoint(stage: Stage) -> Result<()> {
        use std::os::unix::net::UnixStream;
        let Ok(path) = std::env::var("AGENT_VM_TEST_PIN_GATE") else {
            return Ok(());
        };
        let mut stream = UnixStream::connect(&path)?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(60)))?;
        stream.set_write_timeout(Some(std::time::Duration::from_secs(60)))?;
        writeln!(stream, "{}", stage.wire())?;
        stream.flush()?;
        let mut reply = String::new();
        BufReader::new(stream).read_line(&mut reply)?;
        match (reply.trim(), stage) {
            ("continue", _) => Ok(()),
            // The seam is one atomic save, so this covers a rename fault too:
            // either way the previous bytes stay in place.
            ("fail-before-save", stage) if stage.accepts_fault() => Err(super::failure()),
            ("", _) => Err(anyhow!("image pin gate closed without a reply")),
            (other, _) => Err(anyhow!(
                "unexpected image pin gate reply {other:?} at {}",
                stage.wire()
            )),
        }
    }

    #[cfg(not(debug_assertions))]
    pub(super) fn checkpoint(_stage: Stage) -> anyhow::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinFile {
    version: u32,
    pins: Vec<PinRecord>,
    // No serde default: omission is not the version 1 schema.
    #[serde(deserialize_with = "required_option")]
    pending_default: Option<PendingDefault>,
    /// Absent in every store 0.7.39–0.7.46 wrote, and that is exact: no project
    /// had a default of its own then (ADR-0067). Empty and absent are one state,
    /// so the writer omits it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    defaults: Vec<ProjectDefaultRecord>,
    /// Which single-holder slots each project/platform scope has resolved
    /// (ADR-0068). A missing record means **both roles unknown**, not absent, so
    /// omission is safe for every store written before 0.7.51.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    scopes: Vec<ScopeRecord>,
    /// The HOME-wide write sequence: the high-water mark of allocated approval
    /// revisions. It survives deletion of the records it was allocated for, so a
    /// reinsertion cannot reuse a retired approval's token. Optional in the same
    /// lazy way: absent until a real save after 0.7.51.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "active::present_sequence"
    )]
    sequence: Option<u64>,
}

/// One project on one measured platform, and the roles a successful claim has
/// resolved there. Its `resolved` mask is required and nonempty: a record that
/// resolves nothing should have been omitted instead.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeRecord {
    project: String,
    platform: HostLinuxPlatform,
    resolved: RoleMask,
}
/// One project's established default. Strict like every other record: the
/// project is a scope this module could have produced, and the image is a
/// canonical reference that states its digest.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectDefaultRecord {
    project: String,
    image: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinRecord {
    project: String,
    reference: String,
    platform: HostLinuxPlatform,
    manifest_digest: String,
    revision: u64,
    /// The single-holder slots this approval currently fills. Omitted means it
    /// holds none, which is **not** the same as "both roles known absent": only
    /// the scope's resolution can say that.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "active::present_mask"
    )]
    roles: Option<RoleMask>,
}
/// Lenient on purpose: it reads only `version`, so a legacy file is recognized
/// even though version 2's strict schema rejects it.
#[derive(Deserialize)]
struct VersionProbe {
    version: u32,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingDefault {
    #[serde(deserialize_with = "required_option")]
    previous: Option<String>,
    proposed: String,
}

impl PinRecord {
    fn validated(&self) -> Result<ApprovedPin> {
        let project = ProjectId::parse(&self.project).map_err(|()| corrupt())?;
        let reference = CanonicalOciReference::parse(&self.reference).map_err(|_| corrupt())?;
        let digest = ManifestDigest::parse(&self.manifest_digest).map_err(|_| corrupt())?;
        if !pin_fields_are_acceptable(PinFieldFacts {
            project: project_id_bytes_are_acceptable(&self.project),
            source_bounded: source_within_limit(self.reference.len()),
            canonical: reference.whole() == self.reference,
            platform: self.platform.valid(),
            revision: revision_is_acceptable(self.revision),
            digest: digest.as_str() == self.manifest_digest,
        }) {
            return Err(corrupt());
        }
        Ok(ApprovedPin {
            key: PinKey {
                project,
                reference,
                platform: self.platform.clone(),
            },
            digest,
            revision: PinRevision(self.revision),
        })
    }
    fn of(pin: &ApprovedPin) -> Self {
        Self {
            project: pin.key.project.as_str().to_owned(),
            reference: pin.key.reference.whole(),
            platform: pin.key.platform.clone(),
            manifest_digest: pin.digest.as_str().to_owned(),
            revision: pin.revision.0,
            roles: None,
        }
    }
    /// The held roles, if any. A record can only carry a nonempty mask.
    fn held(&self) -> Option<HeldRoles> {
        self.roles.and_then(HeldRoles::new)
    }
    fn set_roles(&mut self, roles: Option<HeldRoles>) {
        self.roles = roles.map(HeldRoles::mask);
    }
}

impl ProjectDefaultRecord {
    fn validated(&self) -> Result<ProjectDefault> {
        let project = ProjectId::parse(&self.project).map_err(|()| corrupt())?;
        let reference = CanonicalOciReference::parse(&self.image).map_err(|_| corrupt())?;
        // A tag, a non-canonical spelling or an unparseable digest is damage on
        // every read path, exactly like a pin's fields.
        if !source_within_limit(self.image.len())
            || reference.whole() != self.image
            || reference.digest().is_none()
            || ImmutableImageRef::parse(&self.image).is_err()
        {
            return Err(corrupt());
        }
        ProjectDefault::from_canonical(project, reference).map_err(|_| corrupt())
    }
    fn of(default: &ProjectDefault) -> Self {
        Self {
            project: default.project().as_str().to_owned(),
            image: default.reference().whole(),
        }
    }
}

/// A comparable scope identity: project plus measured platform. The pin records,
/// the scope records and the runtime `ScopeKey` all build this one shape, so the
/// three readers of a scope cannot disagree about what it is.
type ScopeIdentity = (String, String, String, Option<String>);

fn scope_identity(project: &str, platform: &HostLinuxPlatform) -> ScopeIdentity {
    (
        project.to_owned(),
        platform.os.clone(),
        platform.architecture.clone(),
        platform.variant.clone(),
    )
}

impl ScopeKey {
    fn identity(&self) -> ScopeIdentity {
        scope_identity(self.project().as_str(), self.platform())
    }
}

/// How many records hold each role in one scope. Addressed by `Role`, so no
/// reader depends on a mask's bit order or on an array's literal order.
#[derive(Clone, Copy, Default)]
struct HolderCounts {
    boot: usize,
    output: usize,
}

impl HolderCounts {
    fn of(&self, role: Role) -> usize {
        match role {
            Role::Boot => self.boot,
            Role::Output => self.output,
        }
    }
    fn of_mut(&mut self, role: Role) -> &mut usize {
        match role {
            Role::Boot => &mut self.boot,
            Role::Output => &mut self.output,
        }
    }
}

impl ScopeRecord {
    fn validated(&self) -> Result<()> {
        ProjectId::parse(&self.project).map_err(|()| corrupt())?;
        if !self.platform.valid() || !mask_is_acceptable(!self.resolved.is_empty()) {
            return Err(corrupt());
        }
        Ok(())
    }
    fn matches(&self, scope: &ScopeKey) -> bool {
        self.project == scope.project().as_str() && self.platform == *scope.platform()
    }
    fn identity(&self) -> ScopeIdentity {
        scope_identity(&self.project, &self.platform)
    }
}

impl PinFile {
    fn empty() -> Self {
        Self {
            version: STORE_VERSION,
            pins: Vec::new(),
            pending_default: None,
            defaults: Vec::new(),
            scopes: Vec::new(),
            sequence: None,
        }
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        if !store_bytes_within_limit(bytes.len()) {
            return Err(corrupt());
        }
        // Every read path (observation and `begin`'s pre-read) reaches this
        // before the directory, a lock or a record exists, so a legacy store is
        // refused before any approval-authority write.
        if matches!(
            serde_json::from_slice::<VersionProbe>(bytes),
            Ok(VersionProbe {
                version: LEGACY_VERSION
            })
        ) {
            return Err(legacy());
        }
        let file: Self = serde_json::from_slice(bytes).map_err(|_| corrupt())?;
        file.validate()?;
        Ok(file)
    }
    fn validate(&self) -> Result<()> {
        if !pin_count_within_limit(self.pins.len())
            || !pin_count_within_limit(self.defaults.len())
            || !pin_count_within_limit(self.scopes.len())
        {
            return Err(corrupt());
        }
        let mut keys = BTreeSet::new();
        let mut projects = BTreeSet::new();
        let mut scopes = BTreeSet::new();
        // One uniqueness fact covers all three record kinds: a pin is unique by
        // its whole key, a project default by its project, a scope by its
        // project and platform.
        let mut unique = true;
        let mut pins = Vec::with_capacity(self.pins.len());
        for record in &self.pins {
            pins.push(record.validated()?);
            unique &= keys.insert((
                scope_identity(&record.project, &record.platform),
                record.reference.clone(),
            ));
        }
        for record in &self.defaults {
            record.validated()?;
            unique &= projects.insert(record.project.clone());
        }
        for record in &self.scopes {
            record.validated()?;
            unique &= scopes.insert(record.identity());
        }
        if !schema_is_acceptable(self.version, unique) {
            return Err(corrupt());
        }
        self.validate_roles(&pins)?;
        if let Some(pending) = &self.pending_default {
            if let Some(previous) = &pending.previous {
                default::decode_snapshot(previous.as_bytes()).map_err(|_| corrupt())?;
            }
            default::decode_snapshot(pending.proposed.as_bytes()).map_err(|_| corrupt())?;
        }
        Ok(())
    }
    fn encode(&self) -> Result<Vec<u8>> {
        // Growth past either bound is a full store, not damage: the file on disk
        // is still well-formed, and reporting it as damage would tell a user to
        // restore a backup that does not exist. The byte bound is checked after
        // serializing, because that is where the size is known. Decoding keeps
        // `corrupt()` for an over-bound file on disk: there it *is* damage.
        if !pin_count_within_limit(self.pins.len()) || !pin_count_within_limit(self.defaults.len())
        {
            return Err(full());
        }
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| corrupt())?;
        if !store_bytes_within_limit(bytes.len()) {
            return Err(full());
        }
        Ok(bytes)
    }
    fn lookup(&self, key: &PinKey) -> Result<Option<ApprovedPin>> {
        for record in &self.pins {
            let pin = record.validated()?;
            if &pin.key == key {
                return Ok(Some(pin));
            }
        }
        Ok(None)
    }
    fn project_default(&self, project: &ProjectId) -> Result<Option<ProjectDefault>> {
        for record in &self.defaults {
            let default = record.validated()?;
            if default.project() == project {
                return Ok(Some(default));
            }
        }
        Ok(None)
    }
    /// Insert or replace this project's record; callers decide write-once vs
    /// compare-and-swap, so this makes no policy decision of its own.
    fn set_project_default(&mut self, default: ProjectDefault) {
        self.defaults
            .retain(|record| record.project != default.project().as_str());
        self.defaults.push(ProjectDefaultRecord::of(&default));
    }

    /// The relational half of the schema: roles and scopes are validated on
    /// every read, never only by the writers that produced them.
    ///
    /// `pins` are the already-validated records, in file order. One pass builds
    /// the join both ways — a held role needs its scope resolved, and a resolved
    /// role needs exactly one holder — so a 4096-record read stays linear-ish.
    fn validate_roles(&self, pins: &[ApprovedPin]) -> Result<()> {
        let any_roles = self.pins.iter().any(|record| record.roles.is_some());
        // Any role or scope knowledge needs the sequence that allocated the
        // revisions beside it; a file with neither is an untouched old file.
        if (any_roles || !self.scopes.is_empty()) && self.sequence.is_none() {
            return Err(corrupt());
        }
        if let Some(sequence) = self.sequence {
            // The high-water mark must cover every live token. Old files with
            // duplicate per-key revisions stay valid: the check is a maximum.
            let live_max = self
                .pins
                .iter()
                .map(|record| record.revision)
                .max()
                .unwrap_or(0);
            if sequence == 0 || sequence < live_max {
                return Err(corrupt());
            }
        }
        let resolved: std::collections::BTreeMap<_, _> = self
            .scopes
            .iter()
            .map(|record| (record.identity(), record.resolved))
            .collect();
        let mut holders: std::collections::BTreeMap<ScopeIdentity, HolderCounts> =
            std::collections::BTreeMap::new();
        for (record, pin) in self.pins.iter().zip(pins) {
            let Some(held) = record.held() else {
                continue;
            };
            let key = pin.key.scope().identity();
            let Some(bits) = resolved.get(&key) else {
                return Err(corrupt());
            };
            if !bits.covers(held.mask()) {
                return Err(corrupt());
            }
            let counts = holders.entry(key).or_default();
            for role in [Role::Boot, Role::Output] {
                if held.contains(role) {
                    *counts.of_mut(role) += 1;
                }
            }
        }
        for record in &self.scopes {
            let counts = holders.get(&record.identity()).copied().unwrap_or_default();
            for role in [Role::Boot, Role::Output] {
                if record.resolved.contains(role) && counts.of(role) != 1 {
                    return Err(corrupt());
                }
            }
        }
        Ok(())
    }

    fn resolved_in(&self, scope: &ScopeKey) -> Option<ResolvedRoles> {
        self.scopes
            .iter()
            .find(|record| record.matches(scope))
            .and_then(|record| ResolvedRoles::new(record.resolved))
    }

    fn set_resolved(&mut self, scope: &ScopeKey, resolved: ResolvedRoles) {
        if let Some(record) = self.scopes.iter_mut().find(|record| record.matches(scope)) {
            record.resolved = resolved.mask();
            return;
        }
        self.scopes.push(ScopeRecord {
            project: scope.project().as_str().to_owned(),
            platform: scope.platform().clone(),
            resolved: resolved.mask(),
        });
    }

    /// The plan a successful claim of `role` on `key` will apply. Built from one
    /// validated snapshot; the target may not be inserted yet.
    fn plan_claim(&self, key: &PinKey, role: Role) -> Result<ClaimPlan> {
        let scope = key.scope();
        let prior = self
            .resolved_in(&scope)
            .map(ResolvedRoles::mask)
            .unwrap_or(RoleMask::EMPTY);
        let resolved = prior.with(role);
        Ok(ClaimPlan::of(scope, key.clone(), role, prior, resolved))
    }

    /// Apply a claim: resolve its slot for the whole scope, make the target its
    /// sole holder, and retire exactly the records whose **both** roles are now
    /// known absent. The other role's resolution and holder are preserved, as is
    /// every record in a foreign scope or platform.
    fn apply_claim(&mut self, plan: &ClaimPlan) -> Result<Change> {
        let mut changed = false;
        if self.resolved_in(plan.scope()).map(ResolvedRoles::mask) != Some(plan.resolved()) {
            let resolved = ResolvedRoles::new(plan.resolved()).ok_or_else(corrupt)?;
            self.set_resolved(plan.scope(), resolved);
            changed = true;
        }
        let mut kept = Vec::with_capacity(self.pins.len());
        for mut record in std::mem::take(&mut self.pins) {
            let pin = record.validated()?;
            if pin.key.scope() != *plan.scope() {
                kept.push(record);
                continue;
            }
            let held = record.held();
            let target = &pin.key == plan.target();
            // The proved kernel decides both questions: what each slot's
            // knowledge becomes, and whether that licenses retirement. The
            // trusted adapter only maps masks to knowledge and back.
            let prior = knowledge(plan.prior(), held);
            let after = claim_knowledge(ClaimFacts {
                boot: prior.boot,
                output: prior.output,
                claimed: plan.role(),
                target,
            });
            let next = after_role(after, held, plan.role());
            if next != held {
                record.set_roles(next);
                changed = true;
            }
            if may_retire(after) {
                changed = true;
                continue;
            }
            kept.push(record);
        }
        self.pins = kept;
        Ok(if changed {
            Change::Changed
        } else {
            Change::Unchanged
        })
    }

    /// Replace an approval's content fields, preserving its held roles and its
    /// position. A new record starts holding nothing: membership is decided by
    /// the claim this transaction applies, never by insertion.
    fn upsert_approval(&mut self, pin: &ApprovedPin) -> Result<Change> {
        for record in &mut self.pins {
            if record.validated()?.key != pin.key {
                continue;
            }
            if record.manifest_digest == pin.digest.as_str() && record.revision == pin.revision.0 {
                return Ok(Change::Unchanged);
            }
            record.manifest_digest = pin.digest.as_str().to_owned();
            record.revision = pin.revision.0;
            return Ok(Change::Changed);
        }
        self.pins.push(PinRecord::of(pin));
        Ok(Change::Changed)
    }

    /// The read-only effective high-water mark: the persisted sequence, else the
    /// highest live legacy revision (0 when there are none).
    fn effective_sequence(&self) -> u64 {
        self.sequence.unwrap_or_else(|| {
            self.pins
                .iter()
                .map(|record| record.revision)
                .max()
                .unwrap_or(0)
        })
    }

    /// Reserve the next global allocation. Tentative until a successful rename:
    /// a no-op or failed save persists nothing.
    fn reserve_write(&self) -> Result<u64> {
        let reservation = checked_next_sequence(self.effective_sequence());
        if !reservation.reserved {
            return Err(sequence_exhausted());
        }
        Ok(reservation.next)
    }

    /// Seal this proposed state with its write sequence and encode its final
    /// bytes: counts, relational facts and the 4 MiB budget are all checked
    /// here, after justified retirement, before any write.
    fn seal_write(&mut self, old: &PinFile, reserved: Option<u64>) -> Result<Vec<u8>> {
        let next = match reserved {
            Some(next) => {
                if next != old.reserve_write()? {
                    return Err(anyhow!(
                        "internal error: the reserved pin write sequence does not match the \
                         state being sealed"
                    ));
                }
                next
            }
            None => old.reserve_write()?,
        };
        self.sequence = Some(next);
        self.encode()
    }
}

/// Report that a result reference is published and the exclusive publication
/// barrier is released, before its read-back (#391).
pub(super) fn published_ready() -> Result<()> {
    gate::checkpoint(gate::Stage::Published)
}

/// Report that a candidate is acquired and validated but not yet approved.
pub(super) fn candidate_ready() -> Result<()> {
    gate::checkpoint(gate::Stage::CandidateReady)
}

fn corrupt() -> anyhow::Error {
    anyhow!(
        "image pin authority at $HOME/.config/agent-vm/image-pins.json is damaged; restore its intended records from backup or deliberately move it aside to reset approvals"
    )
}
fn legacy() -> anyhow::Error {
    anyhow!(
        "image pin authority at $HOME/.config/agent-vm/image-pins.json uses the host-wide \
         version 1 format, which this agent-vm no longer reads: approvals are now per \
         project. Archiving it resets approvals, and mutable tags may then resolve to newer \
         content; see \"Upgrading from host-wide approvals\" in USAGE.md"
    )
}
fn full() -> anyhow::Error {
    // Update-local on purpose: a refresh may commit earlier operations and then
    // fail this one, so a batch-wide "nothing was approved" claim would be false.
    // The wording is accurate for every caller (launch, setup, publication and
    // refresh) because each of them is refused this one save.
    anyhow!(
        "image pin authority at $HOME/.config/agent-vm/image-pins.json holds the maximum \
         number of approvals it can store (the record or byte bound); this proposed pin-store \
         update was not committed; archive it to reset approvals"
    )
}
fn failure() -> anyhow::Error {
    anyhow!(
        "image pin authority at $HOME/.config/agent-vm/image-pins.json could not be accessed or saved"
    )
}
fn sequence_exhausted() -> anyhow::Error {
    anyhow!(
        "image pin write sequence is exhausted; this proposed pin-store update was not committed"
    )
}
fn recovery_required() -> anyhow::Error {
    anyhow!(
        "image pin default transaction requires recovery; restore the intended records from backup"
    )
}

/// Whether an observation needs the host record, and why.
///
/// The record's own journal (`pending_default`) is always read, whichever
/// variant applies: it is a fact of the pin store, not of the caller's question.
enum HostRead<'a> {
    /// `doctor`, set-default's health check, `load_default`.
    Always,
    /// Pin lookups: the host record matters only to validate a pending journal.
    Never,
    /// Default-slot selection: read the host only when the project has none.
    UnlessEstablished(&'a ProjectId),
}

impl HostRead<'_> {
    fn reads_host(&self, file: &PinFile) -> Result<bool> {
        Ok(match self {
            Self::Always => true,
            Self::Never => file.pending_default.is_some(),
            Self::UnlessEstablished(project) => {
                file.pending_default.is_some() || file.project_default(project)?.is_none()
            }
        })
    }

    /// With no store on disk no project can be established, so a slot
    /// observation reads the host exactly as `Always` would.
    fn reads_host_without_store(&self) -> bool {
        !matches!(self, Self::Never)
    }
}

pub(super) struct Store {
    directory: PathBuf,
}
impl Store {
    pub(super) fn host() -> Result<Self> {
        let home = config::host_home_dir()
            .map_err(|_| failure())?
            .ok_or_else(failure)?;
        Ok(Self {
            directory: home.join(config::USER_CONFIG_DIR_RELATIVE),
        })
    }
    fn record(&self) -> PathBuf {
        self.directory.join("image-pins.json")
    }
    fn lock_path(&self) -> PathBuf {
        self.directory.join("image-pins.lock")
    }
    fn read(&self) -> Result<Option<PinFile>> {
        if !exists(&self.record())? {
            return Ok(None);
        }
        let (bytes, _) = host_paths::read_bounded_regular_file_no_follow(&self.record(), MAX_BYTES)
            .map_err(|_| corrupt())?;
        PinFile::decode(&bytes).map(Some)
    }
    fn save(&self, bytes: &[u8]) -> Result<()> {
        atomic_save(&self.record(), bytes)
    }
    /// A missing lock is rechecked AFTER the legacy snapshot. A newly created
    /// lock forces retry under SH, within the original observation deadline.
    fn observe(&self) -> Result<(PinFile, Option<Vec<u8>>)> {
        let (file, host) = self.observe_slot_independently(HostRead::Always)?;
        Ok((file, host?))
    }
    fn observe_slot(&self, host: HostRead<'_>) -> Result<(PinFile, Option<Vec<u8>>)> {
        let (file, host) = self.observe_slot_independently(host)?;
        Ok((file, host?))
    }
    /// One shared-lock snapshot, with the host record's failure kept apart from
    /// the pin file that was read beside it: `doctor` reports both records, and a
    /// damaged host record must not hide a project default that decoded fine.
    /// Only the store read itself (lock, record, journal) fails the whole
    /// observation.
    fn observe_slot_independently(
        &self,
        host: HostRead<'_>,
    ) -> Result<(PinFile, Result<Option<Vec<u8>>>)> {
        let deadline = Instant::now() + READ_WAIT;
        loop {
            if let Some(lock) = open_lock(&self.lock_path(), false)? {
                wait(&lock, FlockMode::Shared, deadline, &mut false)?;
                let file = self.read()?.unwrap_or_else(PinFile::empty);
                let physical = if host.reads_host(&file)? {
                    default::snapshot_at(&self.directory)
                } else {
                    Ok(None)
                };
                let logical = physical.and_then(|physical| logical_default(&file, physical));
                return Ok((file, logical));
            }
            // No store exists, so no project can have an established default
            // and the host record is the only record there is.
            let physical = if host.reads_host_without_store() {
                default::snapshot_at(&self.directory)
            } else {
                Ok(None)
            };
            if exists(&self.lock_path())? {
                if Instant::now() >= deadline {
                    return Err(anyhow!("image pin observation timed out"));
                }
                continue;
            }
            // One statement of the authority rule, shared with `begin` and the
            // lock-free projection: a record without its stable lock is damage.
            self.require_lock_present_for_record()?;
            return Ok((PinFile::empty(), physical));
        }
    }
    pub(super) fn lookup(&self, key: &PinKey) -> Result<Option<ApprovedPin>> {
        self.observe_slot(HostRead::Never)?.0.lookup(key)
    }

    /// The read-only projection of one project's approvals, for the explicit
    /// listing and `doctor`'s count-only row (ADR-0068).
    ///
    /// A **snapshot, not a transaction**: the coordination-file metadata and the
    /// record bytes are read without acquiring the lock, so an exclusive writer
    /// never delays an inspection and the two reads need not be contemporaneous.
    /// The bytes themselves come from one complete atomic save. Whole-file
    /// validation precedes projection, so a malformed foreign record is damage
    /// rather than something to filter away, and nothing is created, repaired or
    /// written.
    ///
    /// The order is the observer's effective one: existence, then lock shape for
    /// a *present* authority, then the record. `open_lock` reaches the shape
    /// failure first on the two locked paths; this path states it explicitly
    /// because it never opens the file.
    ///
    /// Only a present authority needs its regular coordination file (R4/AC1,
    /// D2): a directory, symlink or FIFO left at the lock path beside **no**
    /// record is not damage, because an absent store is a successful empty
    /// listing and nothing here creates the file it would then have to be.
    pub(super) fn project_pins(&self, project: &ProjectId) -> Result<ProjectPinsSnapshot> {
        if self.require_lock_present_for_record()? {
            self.require_lock_metadata_is_regular()?;
        }
        let file = self.read()?.unwrap_or_else(PinFile::empty);
        let mut pins = Vec::new();
        for record in &file.pins {
            let pin = record.validated()?;
            if pin.key.project != *project {
                continue;
            }
            // A missing scope record is both roles *unknown*; the join supplies
            // Present/Absent/Unknown, so this projection never infers a role from
            // selection, order or a default.
            let resolved = file
                .resolved_in(&pin.key.scope())
                .map(ResolvedRoles::mask)
                .unwrap_or(RoleMask::EMPTY);
            pins.push(ObservedPin {
                knowledge: knowledge(resolved, record.held()),
                pin,
            });
        }
        Ok(ProjectPinsSnapshot {
            path: self.record(),
            pins,
        })
    }

    /// ADR-0063 Decision 3's existence rule, stated once for all three readers:
    /// a present record without its stable coordination file is damage. Metadata
    /// only — an absent record short-circuits before any lock lookup, and this
    /// never opens, creates or locks anything, so a lockless authority is refused
    /// rather than silently adopted by a new writer.
    ///
    /// Returns whether the record exists, which is the one fact that decides
    /// whether a coordination file is required at all: the two transaction paths
    /// ignore it because a write always creates the lock, and
    /// [`Self::project_pins`] uses it to scope the shape rule to a present
    /// authority.
    ///
    /// A present non-regular lock still *exists*, so its shape is deliberately
    /// not this helper's question: `open_lock` answers that for the two locked
    /// paths, and [`Self::require_lock_metadata_is_regular`] for the lock-free
    /// one.
    fn require_lock_present_for_record(&self) -> Result<bool> {
        let record_present = exists(&self.record())?;
        if record_present && !exists(&self.lock_path())? {
            return Err(corrupt());
        }
        Ok(record_present)
    }

    /// The shape half of the same authority rule, for the lock-free projection
    /// only. `open_lock` reports a non-regular coordination file as the access
    /// failure before either transaction path reads a record, so this keeps the
    /// inspection's classification identical without touching their order.
    fn require_lock_metadata_is_regular(&self) -> Result<()> {
        lock_shape(
            std::fs::symlink_metadata(self.lock_path())
                .map(|metadata| metadata.file_type())
                .map_err(|error| error.kind()),
        )
    }

    /// The one read-only snapshot a refresh invocation freezes its worklist
    /// from: every record in exactly this project/host-platform scope, with its
    /// held roles.
    ///
    /// One `observe_slot(HostRead::Never)` decodes and validates the entire
    /// authority, so foreign records are still *checked* (a malformed foreign
    /// role join is damage) without being projected. Nothing is created,
    /// recovered or rewritten, and a healthy unrelated host record is not read.
    pub(super) fn refresh_scope(&self, scope: &ScopeKey) -> Result<RefreshScopeSnapshot> {
        let (file, _host) = self.observe_slot(HostRead::Never)?;
        let mut pins = Vec::new();
        for record in &file.pins {
            let pin = record.validated()?;
            if pin.key.scope() != *scope {
                continue;
            }
            pins.push(ScopedRefreshPin {
                pin,
                held: record.held(),
            });
        }
        Ok(RefreshScopeSnapshot {
            scope: scope.clone(),
            pins,
        })
    }
    /// Whether the whole work of a warm Boot claim — resolution, holder move,
    /// justified cleanup and default establishment — is already done. A complete
    /// no-op must not take the exclusive lock, recover a journal or allocate.
    fn claim_is_noop(
        &self,
        file: &PinFile,
        consumed: &ApprovedPin,
        action: &DefaultAction,
    ) -> Result<bool> {
        if file.lookup(&consumed.key)?.as_ref() != Some(consumed) {
            return Ok(false);
        }
        let plan = file.plan_claim(&consumed.key, Role::Boot)?;
        let mut trial = file.clone();
        if trial.apply_claim(&plan)? != Change::Unchanged {
            return Ok(false);
        }
        let default_done = match action.retained_reference() {
            None => true,
            Some(_) => {
                trial.project_default(&consumed.key.project)?.is_some()
                    && (!action.initializes_host()
                        || default::snapshot_at(&self.directory)?.is_some())
            }
        };
        Ok(default_done)
    }

    /// The default slot as one project's selection reads it.
    ///
    /// The project's own default wins, and only then is the host record read —
    /// under the same shared-lock hold, so a concurrent writer cannot pair one
    /// project read with a different host read. A damaged host record therefore
    /// does not break an established project's selection.
    pub(super) fn default_slot(&self, project: &ProjectId) -> Result<DefaultSlot> {
        let (file, logical) = self.observe_slot(HostRead::UnlessEstablished(project))?;
        match file.project_default(project)? {
            Some(default) => Ok(DefaultSlot::Project {
                reference: default.immutable()?,
                file: self.record(),
            }),
            None => Ok(DefaultSlot::Host(
                logical
                    .as_deref()
                    .map(default::decode_snapshot)
                    .transpose()?,
            )),
        }
    }
    /// Both default records from one shared-lock read, for `doctor`.
    ///
    /// The two rows are returned independently: a host record that cannot be
    /// read or decoded must not erase a project default that did (R10), and a
    /// project record that fails still leaves the host row truthful.
    pub(super) fn observe_defaults(&self, project: Option<&ProjectId>) -> Result<ObservedDefaults> {
        let (file, host) = self.observe_slot_independently(HostRead::Always)?;
        Ok(ObservedDefaults {
            project: match project {
                Some(project) => file
                    .project_default(project)
                    .and_then(|default| default.map(|default| default.immutable()).transpose()),
                None => Ok(None),
            },
            host: host
                .and_then(|logical| logical.as_deref().map(default::decode_snapshot).transpose()),
            file: self.record(),
        })
    }
    /// Validate the logical retained default — the pin store, any pending
    /// journal pair and the physical record — without writing anything.
    /// An operation that will touch the default checks this BEFORE its network
    /// work, so a corrupt record can never be re-pinned by a partial success.
    pub(super) fn default_health(&self) -> Result<()> {
        self.observe().map(|_| ())
    }
    pub(super) fn load_default(&self) -> Result<Option<ImmutableImageRef>> {
        self.observe()?
            .1
            .as_deref()
            .map(default::decode_snapshot)
            .transpose()
    }
    /// One bounded exclusive read-modify-write.
    ///
    /// Damage is rejected before the directory or a coordination file exists, a
    /// store without its stable lock is never silently adopted by a new writer,
    /// the pin lock is always taken before the default lock, and any previous
    /// intent is recovered here — the only place recovery happens.
    fn begin(&self, touch_default: bool) -> Result<(PinFile, Locks)> {
        // Before the pre-read, matching `observe_slot`: a record without its
        // stable lock is damage on both paths, whatever the record's version.
        // Only a lockless legacy store observes this order (it used to report
        // the legacy error here and now reports damage, as a version-1 binary
        // already did for it).
        self.require_lock_present_for_record()?;
        let preread = self.read()?;
        if touch_default
            || preread
                .as_ref()
                .is_some_and(|f| f.pending_default.is_some())
        {
            default::snapshot_at(&self.directory)?;
        }
        let deadline = Instant::now() + WRITE_WAIT;
        gate::checkpoint(gate::Stage::BeforePinLock)?;
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.directory)
            .map_err(|_| failure())?;
        let pin = open_lock(&self.lock_path(), true)?.ok_or_else(failure)?;
        let mut noticed = false;
        wait(&pin, FlockMode::Exclusive, deadline, &mut noticed)?;
        gate::checkpoint(gate::Stage::PinLocked)?;
        let mut file = self.read()?.unwrap_or_else(PinFile::empty);
        let default_lock = if touch_default || file.pending_default.is_some() {
            let lock =
                open_lock(&self.directory.join(DEFAULT_LOCK_FILE), true)?.ok_or_else(failure)?;
            wait(&lock, FlockMode::Exclusive, deadline, &mut noticed)?;
            Some(lock)
        } else {
            None
        };
        self.recover(&mut file)?;
        Ok((
            file,
            Locks {
                _pin: pin,
                _default: default_lock,
            },
        ))
    }

    /// One ordinary approval transaction: insert, replace or confirm the
    /// candidate, then apply the caller's role claim and any eligible default
    /// work in the **same** atomic save.
    ///
    /// Returns a typed conflict (a concurrent writer won) apart from a genuine
    /// failure: only a first-pin preparation may re-read a winner after a
    /// conflict, and it may never do so for an arbitrary I/O, full or
    /// sequence-exhausted error.
    pub(super) fn commit(
        &self,
        candidate: &ValidatedCandidate,
        approval: &Approval,
        action: DefaultAction,
        claim: RoleClaim,
    ) -> Result<CommitOutcome> {
        if let Some(reference) = action.retained_reference() {
            self.adoption_binds(&candidate.key, reference)?;
        }
        let (old, _locks) = self.begin(action.initializes_host())?;
        let current = old.lookup(&candidate.key)?;
        if approval.key != candidate.key || approval.candidate != candidate.digest {
            return Err(anyhow!("image approval does not bind this candidate"));
        }
        let facts = CommitFacts {
            current_present: current.is_some(),
            expected_present: approval.expected().is_some(),
            candidate_equal: current.as_ref().is_some_and(|pin| {
                pin.digest == candidate.digest
                    || (approval.is_equivalent() && approval.expected() == Some(pin))
            }),
            predecessor_matches: current.as_ref() == approval.expected(),
            mutable_source: candidate.key.reference.digest().is_none(),
            consent: approval.is_replacement(),
        };
        let decision = commit_decision(facts);
        // Built from the under-lock snapshot, before the target may be inserted.
        let claim_plan = match claim {
            RoleClaim::Keep => None,
            RoleClaim::Claim(role) => Some(old.plan_claim(&candidate.key, role)?),
        };
        let mut new = old.clone();
        let mut reserved = None;
        let previous = current.clone();
        let pin = match decision {
            CommitDecision::AlreadyApproved => current.ok_or_else(failure)?,
            CommitDecision::Insert | CommitDecision::Replace => {
                let next = old.reserve_write()?;
                let pin = ApprovedPin {
                    key: candidate.key.clone(),
                    digest: candidate.digest.clone(),
                    revision: PinRevision(next),
                };
                new.upsert_approval(&pin)?;
                reserved = Some(next);
                pin
            }
            CommitDecision::Conflict => return Ok(CommitOutcome::Conflict),
        };
        let membership = match &claim_plan {
            Some(plan) => new.apply_claim(plan)?,
            None => Change::Unchanged,
        };
        let project_default = Self::establish_in(&mut new, &old, &candidate.key.project, &action)?;
        let status = Status {
            approval: if decision == CommitDecision::AlreadyApproved {
                Change::Unchanged
            } else {
                Change::Changed
            },
            membership,
            project_default,
        };
        let report = if status.needs_save() {
            let final_bytes = new.seal_write(&old, reserved)?;
            // Host first: "host seeded, project not yet established" is a state
            // the next default-tier use completes (ADR-0067 narrows ADR-0047's
            // failed-operation guarantee to allow exactly this).
            self.seed_host_if_absent(&action)?;
            gate::checkpoint(gate::Stage::BeforePinSave)?;
            self.save(&final_bytes)?;
            self.committed_report()
        } else {
            // A complete no-op may still have S2 host-only work, but allocates no
            // sequence and rewrites no approval bytes.
            self.seed_host_if_absent(&action)?;
            CommitReport::Complete
        };
        Ok(CommitOutcome::Committed(Box::new(Completion {
            value: Committed {
                pin,
                project_default,
                previous,
            },
            report,
        })))
    }

    /// The post-rename checkpoint is a *report*, not part of the commit: the
    /// rename already succeeded, so its failure must not become an error.
    fn committed_report(&self) -> CommitReport {
        match gate::checkpoint(gate::Stage::PinCommitted) {
            Ok(()) => CommitReport::Complete,
            Err(_) => CommitReport::CheckpointUnavailable,
        }
    }

    /// Record that a **warm** preparation successfully acquired and validated
    /// exactly `consumed`: claim Boot for it and do the eligible default work.
    ///
    /// The consumed approval is the whole predecessor: if a peer retired and
    /// reinserted the same digest with a new global token, the tuple differs and
    /// this is stale, never a silent acceptance of a different lifetime.
    pub(super) fn claim_selected(
        &self,
        consumed: &ApprovedPin,
        action: &DefaultAction,
    ) -> Result<Completion<ProjectDefaultChange>> {
        if let Some(reference) = action.retained_reference() {
            self.adoption_binds(&consumed.key, reference)?;
        }
        // A complete no-op takes no exclusive lock, recovers no journal and
        // allocates no sequence.
        let (snapshot, _logical) = self.observe_slot(HostRead::Never)?;
        if self.claim_is_noop(&snapshot, consumed, action)? {
            return Ok(Completion {
                value: ProjectDefaultChange::Unchanged,
                report: CommitReport::Complete,
            });
        }
        let (old, _locks) = self.begin(action.initializes_host())?;
        if old.lookup(&consumed.key)?.as_ref() != Some(consumed) {
            return Err(anyhow!(
                "image approval is stale; retry the explicit operation"
            ));
        }
        let plan = old.plan_claim(&consumed.key, Role::Boot)?;
        let mut new = old.clone();
        let membership = new.apply_claim(&plan)?;
        let change = Self::establish_in(&mut new, &old, &consumed.key.project, action)?;
        let status = Status {
            approval: Change::Unchanged,
            membership,
            project_default: change,
        };
        let report = if status.needs_save() {
            let final_bytes = new.seal_write(&old, None)?;
            self.seed_host_if_absent(action)?;
            gate::checkpoint(gate::Stage::BeforePinSave)?;
            self.save(&final_bytes)?;
            self.committed_report()
        } else {
            self.seed_host_if_absent(action)?;
            CommitReport::Complete
        };
        Ok(Completion {
            value: change,
            report,
        })
    }

    /// R7's transaction: one project's established default moves to the host
    /// record, and the host reference's pin is inserted if it is absent.
    ///
    /// Both records live in this one file, so the compare-and-swap on the
    /// project's default and the pin's first-pin decision are one save.
    pub(super) fn adopt(
        &self,
        candidate: &ValidatedCandidate,
        adoption: &DefaultAdoption,
    ) -> Result<Completion<Committed>> {
        adoption.binds(candidate)?;
        let (old, _locks) = self.begin(false)?;
        if old.project_default(adoption.expected().project())?.as_ref() != Some(adoption.expected())
        {
            return Err(anyhow!(
                "image approval is stale; retry the explicit operation"
            ));
        }
        // The proposed key is immutable, so the proved decision has only three
        // legitimate outcomes: a first pin, the same digest, or a conflict that
        // is either a stale observation or an integrity failure. The
        // observation — not a fresh read — is what the CAS compares, so a peer
        // that retired H cannot have it silently reinserted.
        let current = old.lookup(&candidate.key)?;
        let expected = adoption.observed_host();
        let predecessor_matches = current.as_ref() == expected;
        let decision = commit_decision(CommitFacts {
            current_present: current.is_some(),
            expected_present: expected.is_some(),
            candidate_equal: current
                .as_ref()
                .is_some_and(|pin| pin.digest == candidate.digest),
            predecessor_matches,
            // H is an immutable retained reference: it never becomes a
            // replacement, so no consent can authorize different content.
            mutable_source: false,
            consent: false,
        });
        let previous = current.clone();
        let mut new = old.clone();
        let pin = match decision {
            CommitDecision::AlreadyApproved => current.ok_or_else(failure)?,
            CommitDecision::Insert => {
                let next = old.reserve_write()?;
                let pin = ApprovedPin {
                    key: candidate.key.clone(),
                    digest: candidate.digest.clone(),
                    revision: PinRevision(next),
                };
                // Adoption is not a successful launch: a new record holds no
                // role, and its scope is untouched.
                new.upsert_approval(&pin)?;
                pin
            }
            // Fail closed: an immutable retained reference is never replaced.
            CommitDecision::Replace => {
                return Err(anyhow!(
                    "image approval is stale; retry the explicit operation"
                ));
            }
            CommitDecision::Conflict => {
                // Any observed H that no longer matches live state — changed or
                // vanished — is a stale observation: retrying the explicit
                // operation is the only correct next step, and a vanished H is
                // never reinserted. What remains is a live H that *does* match
                // the observation, where unequal immutable content can only be
                // the existing integrity failure (an equal live candidate
                // reconciles above, whatever its revision).
                if expected.is_some() && current.as_ref() != expected {
                    return Err(anyhow!(
                        "image approval is stale; retry the explicit operation"
                    ));
                }
                return Err(immutable_integrity_failure());
            }
        };
        new.set_project_default(ProjectDefault::new(
            adoption.expected().project(),
            adoption.proposed(),
        )?);
        // Adoption changes a bookmark; it advances the write sequence but keeps
        // every existing approval token.
        let bytes = new.seal_write(&old, None)?;
        gate::checkpoint(gate::Stage::BeforePinSave)?;
        self.save(&bytes)?;
        let report = self.committed_report();
        Ok(Completion {
            value: Committed {
                pin,
                project_default: ProjectDefaultChange::Adopted,
                previous,
            },
            report,
        })
    }

    /// Insert this project's default iff the action establishes and the project
    /// has none; `SeedHostOnly` and `None` never establish. Shared by `commit`
    /// and `claim_selected` so the two cannot diverge.
    fn establish_in(
        new: &mut PinFile,
        old: &PinFile,
        project: &ProjectId,
        action: &DefaultAction,
    ) -> Result<ProjectDefaultChange> {
        let DefaultAction::Establish { reference, .. } = action else {
            return Ok(ProjectDefaultChange::Unchanged);
        };
        if old.project_default(project)?.is_some() {
            return Ok(ProjectDefaultChange::Unchanged);
        }
        new.set_project_default(ProjectDefault::new(project, reference)?);
        Ok(ProjectDefaultChange::Established)
    }

    /// Initialize an absent host record with the measured recommendation. Only a
    /// selection that *was* the initial recommendation (or an unreadable-config
    /// recommendation, which establishes nothing) reaches this.
    fn seed_host_if_absent(&self, action: &DefaultAction) -> Result<()> {
        if !action.initializes_host() {
            return Ok(());
        }
        let reference = action.retained_reference().ok_or_else(failure)?;
        if default::snapshot_at(&self.directory)?.is_some() {
            return Ok(());
        }
        let bytes = default::encode_snapshot(reference)?;
        gate::checkpoint(gate::Stage::BeforeDefaultSave)?;
        atomic_save(&self.directory.join(SELECTION_FILE), &bytes)?;
        gate::checkpoint(gate::Stage::DefaultSaved)?;
        Ok(())
    }

    /// Adoption only ever binds the validated source of the key it was resolved
    /// from: a record naming a different reference would retain content this
    /// launch did not measure.
    fn adoption_binds(&self, key: &PinKey, reference: &ImmutableImageRef) -> Result<()> {
        let source = CanonicalOciReference::parse(reference.as_str()).map_err(|_| failure())?;
        if source != key.reference || source.digest().is_none() {
            return Err(anyhow!(
                "default adoption does not bind the validated source"
            ));
        }
        Ok(())
    }

    fn write_default(&self, bytes: Option<&[u8]>) -> Result<()> {
        let path = self.directory.join(SELECTION_FILE);
        if let Some(bytes) = bytes {
            atomic_save(&path, bytes)
        } else {
            match std::fs::remove_file(path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
                Err(_) => Err(failure()),
            }
        }
    }
    /// Called only under pin EX then default EX. Restore physical old bytes
    /// before clearing intent. A failed clear remains safe and retryable.
    fn recover(&self, file: &mut PinFile) -> Result<()> {
        self.recover_using(file, &mut atomic_save)
    }
    fn recover_using(
        &self,
        file: &mut PinFile,
        save: &mut impl FnMut(&Path, &[u8]) -> Result<()>,
    ) -> Result<()> {
        if let Some(pending) = &file.pending_default {
            logical_default(file, default::snapshot_at(&self.directory)?)
                .map_err(|_| recovery_required())?;
            // Seal the cleared state (and its write sequence) **before** the
            // physical host restoration: a sequence/bound failure must leave
            // every byte alone rather than half-recover. Roles are not touched
            // by recovery.
            let mut recovered = file.clone();
            recovered.pending_default = None;
            let recovered_bytes = recovered.seal_write(file, None)?;
            if let Some(previous) = &pending.previous {
                save(&self.directory.join(SELECTION_FILE), previous.as_bytes())
                    .map_err(|_| recovery_required())?;
            } else {
                self.write_default(None).map_err(|_| recovery_required())?;
            }
            save(&self.record(), &recovered_bytes).map_err(|_| recovery_required())?;
            *file = recovered;
        }
        Ok(())
    }
}

fn atomic_save(path: &Path, bytes: &[u8]) -> Result<()> {
    host_paths::atomic_write(path, bytes, 0o600).map_err(|_| failure())
}

/// The exclusive locks one mutation holds; dropping them ends the transaction.
struct Locks {
    _pin: File,
    _default: Option<File>,
}

/// What one host transaction left behind in the pin store.
pub(super) struct Committed {
    pub(super) pin: ApprovedPin,
    pub(super) project_default: ProjectDefaultChange,
    /// The approval measured **under the transaction's lock, before any
    /// mutation**: the only honest predecessor for a reported delta. A peer's
    /// reconcile therefore reports as `Unchanged`, and a metadata-only save
    /// cannot look like a replacement.
    pub(super) previous: Option<ApprovedPin>,
}

/// One record of a frozen refresh scope: its approval and the roles it holds.
/// `held: None` is a retained-but-unheld approval, which is evidence but not
/// membership.
pub(super) struct ScopedRefreshPin {
    pub(super) pin: ApprovedPin,
    pub(super) held: Option<HeldRoles>,
}

/// The strict, read-only scope projection a refresh worklist is planned from.
/// The scope key stays private so a snapshot cannot be reused for another
/// project or platform.
pub(crate) struct RefreshScopeSnapshot {
    scope: ScopeKey,
    pins: Vec<ScopedRefreshPin>,
}

impl RefreshScopeSnapshot {
    /// A literal scope for unit tests of the membership adapter, so a planner
    /// test needs no `$HOME` and no file.
    #[cfg(test)]
    pub(super) fn for_tests(
        project: &ProjectId,
        platform: HostLinuxPlatform,
        pins: Vec<(ApprovedPin, Option<HeldRoles>)>,
    ) -> Self {
        Self {
            scope: ScopeKey::of(project.clone(), platform),
            pins: pins
                .into_iter()
                .map(|(pin, held)| ScopedRefreshPin { pin, held })
                .collect(),
        }
    }

    /// Every record in the frozen scope, in file order. The worklist decides
    /// ordering; this is evidence, not a plan.
    pub(super) fn pins(&self) -> &[ScopedRefreshPin] {
        &self.pins
    }

    /// The observed predecessor for one key, if the scope holds a record for it.
    pub(super) fn predecessor(&self, key: &PinKey) -> Option<ApprovedPin> {
        self.pins
            .iter()
            .find(|record| &record.pin.key == key)
            .map(|record| record.pin.clone())
    }

    /// Whether this exact scope holds a role for `target`. Membership evidence
    /// only: it reads no default record and performs no I/O.
    pub(crate) fn has_held_target(&self, target: &OciTarget) -> bool {
        self.pins
            .iter()
            .any(|record| record.held.is_some() && &record.pin.key.reference == target.canonical())
    }

    /// This snapshot may only plan for the project and host platform it was
    /// taken for; anything else would silently mix two scopes.
    pub(super) fn covers(&self, project: &ProjectId, platform: &HostLinuxPlatform) -> bool {
        self.covers_project(project) && self.covers_platform(platform)
    }

    pub(super) fn covers_project(&self, project: &ProjectId) -> bool {
        self.scope.project() == project
    }

    pub(super) fn covers_platform(&self, platform: &HostLinuxPlatform) -> bool {
        self.scope.platform() == platform
    }
}

/// Every dimension one pin transaction can change. `needs_save` is their
/// disjunction, so a role-only or default-only write cannot be mistaken for a
/// no-op and a complete no-op cannot be mistaken for work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Status {
    approval: Change,
    membership: Change,
    project_default: ProjectDefaultChange,
}

impl Status {
    fn needs_save(&self) -> bool {
        self.approval == Change::Changed
            || self.membership == Change::Changed
            || self.project_default != ProjectDefaultChange::Unchanged
    }
}

/// The two outcomes of an approval CAS: a committed transaction (with its
/// post-commit report) or a concurrent writer's conflict.
pub(super) enum CommitOutcome {
    /// Boxed because a committed value is much larger than the bare conflict.
    Committed(Box<Completion<Committed>>),
    Conflict,
}

fn logical_default(file: &PinFile, physical: Option<Vec<u8>>) -> Result<Option<Vec<u8>>> {
    if let Some(pending) = &file.pending_default {
        let previous = pending.previous.as_ref().map(|s| s.as_bytes().to_vec());
        if !journal_pair_is_acceptable(JournalFacts {
            previous_matches: physical == previous,
            proposed_matches: physical.as_deref() == Some(pending.proposed.as_bytes()),
        }) {
            return Err(recovery_required());
        }
        Ok(previous)
    } else {
        Ok(physical)
    }
}

fn exists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(_) => Err(failure()),
    }
}

/// The measured shape of a coordination file, classified apart from the syscall
/// so every branch is testable on a host that does not enforce permissions.
///
/// A missing lock is `Ok` here: the *existence* rule owns that case and has
/// already run. Everything present but not a regular file is the same access
/// failure `open_lock` reports, never `corrupt()` — a store present with an
/// unusable lock is not the same damage as a store present with no lock.
fn lock_shape(shape: std::result::Result<std::fs::FileType, ErrorKind>) -> Result<()> {
    match shape {
        Ok(kind) if kind.is_file() => Ok(()),
        Ok(_) => Err(failure()),
        Err(ErrorKind::NotFound) => Ok(()),
        Err(_) => Err(failure()),
    }
}
fn open_lock(path: &Path, create: bool) -> Result<Option<File>> {
    let flags = if create {
        OFlags::RDWR | OFlags::CREATE
    } else {
        OFlags::RDONLY
    };
    let fd = match rustix::fs::open(
        path,
        flags | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::RUSR | Mode::WUSR,
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) if !create => return Ok(None),
        Err(_) => return Err(failure()),
    };
    let stat = rustix::fs::fstat(&fd).map_err(|_| failure())?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(failure());
    }
    Ok(Some(File::from(fd)))
}
fn wait(lock: &File, mode: FlockMode, deadline: Instant, noticed: &mut bool) -> Result<()> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(anyhow!("image pin authority lock timed out"));
    }
    let start = Instant::now();
    // The checkpoint seam cannot fail the wait from inside its callback, so its
    // error is captured here and returned once `flock_within` has unwound.
    let mut gate_error: Option<anyhow::Error> = None;
    let result = host_paths::flock_within(lock, mode, remaining, |_| {
        if matches!(mode, FlockMode::Exclusive)
            && !*noticed
            && start.elapsed() + WRITE_WAIT.saturating_sub(remaining) >= Duration::from_secs(1)
        {
            // Best effort: a closed stderr must not turn a contended lock into a
            // failure of the operation that is waiting for it.
            let _ = writeln!(
                std::io::stderr(),
                "Waiting for another agent-vm image approval operation..."
            );
            *noticed = true;
            if gate_error.is_none() {
                gate_error = gate::checkpoint(gate::Stage::AuthorityNoticeAttempted).err();
            }
        }
    })
    .map_err(|_| failure())?;
    if let Some(error) = gate_error {
        return Err(error);
    }
    if result == FlockWait::TimedOut {
        return Err(anyhow!("image pin authority lock timed out"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::active::RoleKnowledge;
    use super::*;
    use crate::image_pin::project_default::HostRetention;
    use std::os::unix::fs::PermissionsExt;

    /// The rows here assert the committed pin; the reported change set is
    /// covered by the CLI rows that print it.
    /// Existing rows assert approval content and byte isolation, not membership:
    /// `Keep` is their explicit claim, and every real save still advances the
    /// global sequence. Rows about roles/each claim build one explicitly.
    impl Store {
        fn commit_with(
            &self,
            candidate: &ValidatedCandidate,
            approval: &Approval,
            action: DefaultAction,
        ) -> Result<Committed> {
            self.commit_outcome(candidate, approval, action, RoleClaim::Keep)
        }
        fn commit_outcome(
            &self,
            candidate: &ValidatedCandidate,
            approval: &Approval,
            action: DefaultAction,
            claim: RoleClaim,
        ) -> Result<Committed> {
            match self.commit(candidate, approval, action, claim)? {
                CommitOutcome::Committed(completion) => Ok(completion.value),
                CommitOutcome::Conflict => Err(anyhow!(
                    "image approval is stale; retry the explicit operation"
                )),
            }
        }
        fn commit_pin(
            &self,
            candidate: &ValidatedCandidate,
            approval: &Approval,
            action: DefaultAction,
        ) -> Result<ApprovedPin> {
            self.commit_with(candidate, approval, action)
                .map(|committed| committed.pin)
        }
        fn claim_pin(
            &self,
            candidate: &ValidatedCandidate,
            approval: &Approval,
            action: DefaultAction,
            role: Role,
        ) -> Result<ApprovedPin> {
            self.commit_outcome(candidate, approval, action, RoleClaim::Claim(role))
                .map(|committed| committed.pin)
        }
        fn claim_selected_change(
            &self,
            consumed: &ApprovedPin,
            action: &DefaultAction,
        ) -> Result<ProjectDefaultChange> {
            self.claim_selected(consumed, action)
                .map(|completion| completion.value)
        }
    }

    fn fifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: valid NUL-terminated path owned for the duration of the call.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    }

    const SOURCE: &str = "docker.io/library/alpine:latest";
    /// The project every single-project fixture uses: one fill character, so a
    /// row that accidentally scopes to another project cannot pass by luck.
    fn project() -> ProjectId {
        ProjectId::for_tests('a')
    }
    fn candidate(byte: char) -> ValidatedCandidate {
        candidate_in(&project(), byte)
    }
    fn candidate_in(project: &ProjectId, byte: char) -> ValidatedCandidate {
        // This test-only constructor exercises the store independently of
        // registry I/O. Production construction requires ValidatedImage.
        ValidatedCandidate {
            key: PinKey::new(project, &OciTarget::parse(SOURCE).unwrap()).unwrap(),
            digest: ManifestDigest::parse(&format!("sha256:{}", byte.to_string().repeat(64)))
                .unwrap(),
            identity: ContentIdentity {
                config_digest: "test-native-config".into(),
                diff_ids: vec![],
            },
        }
    }
    fn paths() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store {
            directory: dir.path().join("config"),
        };
        (dir, store)
    }
    fn file() -> PinFile {
        let c = candidate('a');
        PinFile {
            version: STORE_VERSION,
            pins: vec![PinRecord::of(&ApprovedPin {
                key: c.key,
                digest: c.digest,
                revision: PinRevision(1),
            })],
            pending_default: None,
            defaults: Vec::new(),
            scopes: Vec::new(),
            sequence: None,
        }
    }
    fn install(store: &Store, file: &PinFile) {
        std::fs::create_dir_all(&store.directory).unwrap();
        open_lock(&store.lock_path(), true).unwrap();
        store.save(&file.encode().unwrap()).unwrap();
    }
    fn default_bytes(byte: char) -> Vec<u8> {
        format!(
            "{{ \"image\": \"docker.io/library/alpine@sha256:{}\", \"version\": 1 }}\n",
            byte.to_string().repeat(64)
        )
        .into_bytes()
    }
    fn replacement(candidate: &ValidatedCandidate, expected: ApprovedPin) -> Approval {
        Approval::replacement(candidate, expected)
    }
    /// `repo@<child>`: the immutable spelling of one measured content.
    fn child(byte: char) -> ImmutableImageRef {
        ImmutableImageRef::parse(&format!(
            "docker.io/library/alpine@sha256:{}",
            byte.to_string().repeat(64)
        ))
        .unwrap()
    }
    /// A default-tier selection of one canonical repository pinned by digest,
    /// and the candidate its acquisition measured (`child`).
    fn selected_in(project: &ProjectId, byte: char) -> (ValidatedCandidate, ImmutableImageRef) {
        let reference = child(byte);
        let mut c = candidate_in(project, byte);
        c.key.reference = CanonicalOciReference::parse(reference.as_str()).unwrap();
        (c, reference)
    }
    fn selected(byte: char) -> (ValidatedCandidate, ImmutableImageRef) {
        selected_in(&project(), byte)
    }
    fn establish(reference: &ImmutableImageRef, host: HostRetention) -> DefaultAction {
        DefaultAction::Establish {
            reference: reference.clone(),
            host,
        }
    }
    fn defaults_of(store: &Store) -> Vec<ProjectDefault> {
        store
            .read()
            .unwrap()
            .unwrap()
            .defaults
            .iter()
            .map(|record| record.validated().unwrap())
            .collect()
    }
    fn host_default(store: &Store) -> Option<Vec<u8>> {
        default::snapshot_at(&store.directory).unwrap()
    }
    /// The host record's logical reference, compared as a reference so the
    /// encoder's exact bytes are not the subject of these rows.
    fn host_reference(store: &Store) -> Option<String> {
        host_default(store).map(|bytes| {
            default::decode_snapshot(&bytes)
                .unwrap()
                .as_str()
                .to_owned()
        })
    }

    /// Test 1: the bytes 0.7.39–0.7.46 wrote decode as "no project has an
    /// established default", and re-encoding them omits the field.
    #[test]
    fn an_s1_store_decodes_with_no_project_defaults_and_re_encodes_without_the_field() {
        let s1 = br#"{"version":2,"pins":[],"pending_default":null}"#.to_vec();
        let decoded = PinFile::decode(&s1).unwrap();
        assert!(decoded.defaults.is_empty());
        assert_eq!(decoded.encode().unwrap(), s1);
        let (_dir, store) = paths();
        install(&store, &decoded);
        let file = store.read().unwrap().unwrap();
        assert!(file.project_default(&project()).unwrap().is_none());
        assert!(matches!(
            store.default_slot(&project()).unwrap(),
            DefaultSlot::Host(_)
        ));
    }

    /// Test 2: the new records are strict on every read path, and growth past
    /// their bound is a full store rather than damage.
    #[test]
    fn project_default_records_are_strict() {
        let valid = child('a');
        let value: serde_json::Value = serde_json::from_slice(&file().encode().unwrap()).unwrap();
        let record = |image: serde_json::Value, project: serde_json::Value| {
            let mut v = value.clone();
            v["defaults"] = serde_json::json!([{"project": project, "image": image}]);
            serde_json::to_vec(&v).unwrap()
        };
        let mut cases = vec![
            record(serde_json::json!(valid.as_str()), serde_json::json!("")),
            record(
                serde_json::json!(valid.as_str()),
                serde_json::json!("a".repeat(63)),
            ),
            record(
                serde_json::json!(valid.as_str()),
                serde_json::json!("A".repeat(64)),
            ),
            // A tag is never a project default.
            record(
                serde_json::json!("docker.io/library/alpine:latest"),
                serde_json::json!("a".repeat(64)),
            ),
            // Nor is a non-canonical spelling or a short digest.
            record(
                serde_json::json!(format!("alpine@sha256:{}", "a".repeat(64))),
                serde_json::json!("a".repeat(64)),
            ),
            record(
                serde_json::json!("docker.io/library/alpine@sha256:00ff"),
                serde_json::json!("a".repeat(64)),
            ),
            record(
                serde_json::json!("/rootfs"),
                serde_json::json!("a".repeat(64)),
            ),
        ];
        // An unknown field inside a record, `null`, and a duplicate project.
        let mut unknown = value.clone();
        unknown["defaults"] = serde_json::json!([{
            "project": "a".repeat(64),
            "image": valid.as_str(),
            "extra": 1
        }]);
        cases.push(serde_json::to_vec(&unknown).unwrap());
        let mut null = value.clone();
        null["defaults"] = serde_json::json!(null);
        cases.push(serde_json::to_vec(&null).unwrap());
        let mut duplicate = value.clone();
        let entry = serde_json::json!({"project": "a".repeat(64), "image": valid.as_str()});
        duplicate["defaults"] = serde_json::json!([entry, entry]);
        cases.push(serde_json::to_vec(&duplicate).unwrap());
        for (i, bytes) in cases.iter().enumerate() {
            let error = PinFile::decode(bytes)
                .err()
                .unwrap_or_else(|| panic!("accepted project-default corruption case {i}"));
            assert_eq!(format!("{error:#}"), error.to_string());
            assert!(!error.to_string().contains("alpine"));
        }
        assert!(
            PinFile::decode(&record(
                serde_json::json!(valid.as_str()),
                serde_json::json!("a".repeat(64))
            ))
            .is_ok()
        );

        // 4097 records decode as damage, and growing to them is a full store.
        let mut f = file();
        f.defaults = (0..4096)
            .map(|i| ProjectDefaultRecord {
                project: format!("{i:064x}"),
                image: valid.as_str().to_string(),
            })
            .collect();
        let bytes = f.encode().unwrap();
        assert!(PinFile::decode(&bytes).is_ok());
        f.defaults.push(ProjectDefaultRecord {
            project: "f".repeat(64),
            image: valid.as_str().to_string(),
        });
        assert!(f.encode().is_err());
    }

    #[test]
    fn strict_schema_corruption_matrix() {
        let valid = file().encode().unwrap();
        let value: serde_json::Value = serde_json::from_slice(&valid).unwrap();
        let mut cases = vec![
            vec![],
            b"not JSON".to_vec(),
            vec![0xff],
            [valid.clone(), b" trailing".to_vec()].concat(),
        ];
        for field in ["version", "pins", "pending_default"] {
            let mut v = value.clone();
            v.as_object_mut().unwrap().remove(field);
            cases.push(serde_json::to_vec(&v).unwrap());
        }
        for field in [
            "project",
            "reference",
            "platform",
            "manifest_digest",
            "revision",
        ] {
            let mut v = value.clone();
            v["pins"][0].as_object_mut().unwrap().remove(field);
            cases.push(serde_json::to_vec(&v).unwrap());
        }
        for field in ["os", "architecture", "variant"] {
            let mut v = value.clone();
            v["pins"][0]["platform"]
                .as_object_mut()
                .unwrap()
                .remove(field);
            cases.push(serde_json::to_vec(&v).unwrap());
        }
        for (path, bad) in [
            ("version", serde_json::json!(3)),
            ("version", serde_json::json!("1")),
            ("extra", serde_json::json!(null)),
        ] {
            let mut v = value.clone();
            v[path] = bad;
            cases.push(serde_json::to_vec(&v).unwrap());
        }
        for (field, bad) in [
            ("project", serde_json::json!("")),
            ("project", serde_json::json!("a".repeat(63))),
            ("project", serde_json::json!("a".repeat(65))),
            ("project", serde_json::json!("A".repeat(64))),
            ("project", serde_json::json!("g".repeat(64))),
            ("project", serde_json::json!(7)),
            ("reference", serde_json::json!("alpine")),
            (
                "reference",
                serde_json::json!("registry-1.docker.io/alpine:latest"),
            ),
            ("reference", serde_json::json!("/rootfs")),
            ("revision", serde_json::json!(0)),
            ("revision", serde_json::json!(-1)),
            ("manifest_digest", serde_json::json!("sha256:abc")),
            ("extra", serde_json::json!(1)),
        ] {
            let mut v = value.clone();
            v["pins"][0][field] = bad;
            cases.push(serde_json::to_vec(&v).unwrap());
        }
        for (field, bad) in [
            ("os", serde_json::json!("darwin")),
            ("architecture", serde_json::json!("ARM64")),
            ("architecture", serde_json::json!("unknown")),
            ("variant", serde_json::json!("")),
            ("variant", serde_json::json!("v 8")),
            ("variant", serde_json::json!("\u{1b}")),
            ("variant", serde_json::json!("v".repeat(65))),
            ("extra", serde_json::json!(1)),
        ] {
            let mut v = value.clone();
            v["pins"][0]["platform"][field] = bad;
            cases.push(serde_json::to_vec(&v).unwrap());
        }
        let text = String::from_utf8(valid.clone()).unwrap();
        cases.push(
            text.replacen("\"version\":2", "\"version\":2,\"version\":2", 1)
                .into_bytes(),
        );
        cases.push(
            text.replacen("\"revision\":1", "\"revision\":18446744073709551616", 1)
                .into_bytes(),
        );
        let mut duplicated = value.clone();
        duplicated["pins"]
            .as_array_mut()
            .unwrap()
            .push(value["pins"][0].clone());
        cases.push(serde_json::to_vec(&duplicated).unwrap());
        let proposed = String::from_utf8(default_bytes('b')).unwrap();
        for pending in [
            serde_json::json!({"proposed":proposed}),
            serde_json::json!({"previous":null,"proposed":proposed,"extra":1}),
            serde_json::json!({"previous":"bad","proposed":proposed}),
            serde_json::json!({"previous":null,"proposed":"bad"}),
        ] {
            let mut v = value.clone();
            v["pending_default"] = pending;
            cases.push(serde_json::to_vec(&v).unwrap());
        }
        for (i, bytes) in cases.iter().enumerate() {
            let error = PinFile::decode(bytes)
                .err()
                .unwrap_or_else(|| panic!("accepted corruption case {i}"));
            assert_eq!(format!("{error:#}"), error.to_string());
            assert!(!error.to_string().contains("alpine"));
        }
        assert!(PinFile::decode(&valid).is_ok());
    }

    #[test]
    fn encode_and_decode_enforce_limits_and_foreign_keys() {
        let mut f = file();
        f.pins[0].platform.architecture = "amd64".into();
        f.pins[0].platform.variant = Some("v3".into());
        assert!(PinFile::decode(&f.encode().unwrap()).is_ok());
        f.pins[0].reference = format!("example.com/{}:tag", "a".repeat(4096));
        assert!(f.encode().is_err());
        let mut f = file();
        f.pins = (0..4096)
            .map(|i| {
                let mut p = f.pins[0].clone();
                p.reference = format!("example.com/image{i}:latest");
                p
            })
            .collect();
        let bytes = f.encode().unwrap();
        assert!(PinFile::decode(&bytes).is_ok());
        let extra = f.pins[0].clone();
        f.pins.push(extra);
        assert!(f.encode().is_err());
        assert!(PinFile::decode(&vec![b' '; MAX_BYTES as usize + 1]).is_err());
        let mut f = file();
        f.pending_default = Some(PendingDefault {
            previous: None,
            proposed: " ".repeat(16 * 1024 + 1),
        });
        assert!(f.encode().is_err());
    }

    #[test]
    fn corruption_never_creates_lock_or_resets_authority() {
        for kind in ["json", "symlink", "directory", "fifo", "oversize"] {
            let (dir, store) = paths();
            std::fs::create_dir_all(&store.directory).unwrap();
            match kind {
                "json" => std::fs::write(store.record(), b"private-canary damaged").unwrap(),
                "oversize" => {
                    std::fs::write(store.record(), vec![b' '; MAX_BYTES as usize + 1]).unwrap()
                }
                "directory" => std::fs::create_dir(store.record()).unwrap(),
                "symlink" => {
                    std::os::unix::fs::symlink(dir.path().join("absent"), store.record()).unwrap()
                }
                _ => {
                    fifo(&store.record());
                }
            }
            let c = candidate('a');
            for error in [
                store.lookup(&c.key).unwrap_err(),
                store
                    .commit_pin(&c, &Approval::initial(&c), DefaultAction::None)
                    .unwrap_err(),
            ] {
                assert!(!format!("{error:#}").contains("private-canary"));
            }
            assert!(!store.lock_path().exists());
            assert!(std::fs::symlink_metadata(store.record()).is_ok());
        }
        let (_dir, store) = paths();
        std::fs::create_dir_all(&store.directory).unwrap();
        store.save(&file().encode().unwrap()).unwrap();
        assert!(store.lookup(&candidate('a').key).is_err()); // missing lock
        assert!(!store.lock_path().exists());
    }

    #[test]
    fn cas_insert_same_candidate_stale_revision_and_aba() {
        let (_dir, store) = paths();
        let a = candidate('a');
        let b = candidate('b');
        let c = candidate('c');
        let first = store
            .commit_pin(&a, &Approval::initial(&a), DefaultAction::None)
            .unwrap();
        assert_eq!(first.revision, PinRevision(1));
        let bytes = std::fs::read(store.record()).unwrap();
        assert_eq!(
            store
                .commit_pin(&a, &Approval::initial(&a), DefaultAction::None)
                .unwrap(),
            first
        );
        assert_eq!(std::fs::read(store.record()).unwrap(), bytes);
        assert!(
            store
                .commit_pin(&b, &Approval::initial(&b), DefaultAction::None)
                .is_err()
        );
        let approve_b = replacement(&b, first.clone());
        let second = store
            .commit_pin(&b, &approve_b, DefaultAction::None)
            .unwrap();
        assert_eq!(second.revision, PinRevision(2));
        // Same peer candidate reconciles even with old expected revision.
        assert_eq!(
            store
                .commit_pin(&b, &approve_b, DefaultAction::None)
                .unwrap(),
            second
        );
        assert!(
            store
                .commit_pin(&c, &replacement(&c, first.clone()), DefaultAction::None)
                .is_err()
        );
        let third = store
            .commit_pin(&a, &replacement(&a, second), DefaultAction::None)
            .unwrap();
        assert_eq!(third.revision, PinRevision(3));
        assert!(
            store
                .commit_pin(&b, &approve_b, DefaultAction::None)
                .is_err()
        );
        // Allocation exhaustion is its own outcome: a real save at the
        // sequence's maximum fails as exhausted, never as damage or full.
        let mut exhausted = store.read().unwrap().unwrap();
        exhausted.sequence = Some(u64::MAX);
        store.save(&exhausted.encode().unwrap()).unwrap();
        let old = store.lookup(&a.key).unwrap().unwrap();
        let before = std::fs::read(store.record()).unwrap();
        let error = store
            .commit_pin(&b, &replacement(&b, old), DefaultAction::None)
            .unwrap_err();
        assert!(
            error.to_string().contains("sequence is exhausted"),
            "{error}"
        );
        assert_eq!(std::fs::read(store.record()).unwrap(), before);
        // A true no-op still succeeds at the maximum: it allocates nothing.
        let a_pin = store.lookup(&a.key).unwrap().unwrap();
        assert_eq!(
            store
                .commit_pin(&a, &Approval::initial(&a), DefaultAction::None)
                .unwrap(),
            a_pin
        );
        assert_eq!(std::fs::read(store.record()).unwrap(), before);
        assert!(store.read().unwrap().unwrap().pending_default.is_none());
        assert!(!store.directory.join(SELECTION_FILE).exists());
    }

    #[test]
    fn immutable_source_never_replaces_and_consent_binds_candidate() {
        let (_dir, store) = paths();
        let mut a = candidate('a');
        a.key.reference =
            CanonicalOciReference::parse(&format!("alpine@{}", a.digest.as_str())).unwrap();
        let old = store
            .commit_pin(&a, &Approval::initial(&a), DefaultAction::None)
            .unwrap();
        let mut b = candidate('b');
        b.key = a.key.clone();
        assert!(
            store
                .commit_pin(&b, &replacement(&b, old), DefaultAction::None)
                .is_err()
        );
        assert!(
            store
                .commit_pin(&b, &Approval::initial(&a), DefaultAction::None)
                .is_err()
        );
    }

    #[test]
    fn journal_observation_and_idempotent_recovery_at_each_precommit_state() {
        for installed in [false, true] {
            for previous in [None, Some(String::from_utf8(default_bytes('a')).unwrap())] {
                let (_dir, store) = paths();
                let proposed = String::from_utf8(default_bytes('b')).unwrap();
                let mut f = file();
                f.pending_default = Some(PendingDefault {
                    previous: previous.clone(),
                    proposed: proposed.clone(),
                });
                install(&store, &f);
                let physical = if installed {
                    Some(proposed.as_bytes())
                } else {
                    previous.as_deref().map(str::as_bytes)
                };
                store.write_default(physical).unwrap();
                let before = std::fs::read(store.record()).unwrap();
                assert_eq!(
                    store.observe().unwrap().1,
                    previous.as_ref().map(|s| s.as_bytes().to_vec())
                );
                assert_eq!(std::fs::read(store.record()).unwrap(), before); // observation cannot recover
                let a = candidate('a');
                store
                    .commit_pin(&a, &Approval::initial(&a), DefaultAction::None)
                    .unwrap();
                assert!(store.read().unwrap().unwrap().pending_default.is_none());
                assert_eq!(
                    default::snapshot_at(&store.directory).unwrap(),
                    previous.as_ref().map(|s| s.as_bytes().to_vec())
                );
                store
                    .commit_pin(&a, &Approval::initial(&a), DefaultAction::None)
                    .unwrap();
            }
        }
    }

    /// A leftover S1 journal is recovered by the next write that touches the
    /// default — here a first establishment, the live caller that still asks for
    /// the host lock — so a new save never stacks on an unrecovered transaction.
    #[test]
    fn an_establishing_write_recovers_a_leftover_journal_before_saving() {
        let (_dir, store) = paths();
        let previous = default_bytes('a');
        let proposed = String::from_utf8(default_bytes('b')).unwrap();
        let mut f = file();
        f.pending_default = Some(PendingDefault {
            previous: Some(String::from_utf8(previous.clone()).unwrap()),
            proposed: proposed.clone(),
        });
        install(&store, &f);
        // An interrupted 0.7.46 run: the pin store names the old bytes, the host
        // record already holds the proposed ones.
        store.write_default(Some(proposed.as_bytes())).unwrap();
        assert_eq!(store.observe().unwrap().1.unwrap(), previous);

        let (candidate, reference) = selected('c');
        let committed = store
            .commit_with(
                &candidate,
                &Approval::initial(&candidate),
                establish(&reference, HostRetention::InitializeIfAbsent),
            )
            .unwrap();
        assert_eq!(committed.project_default, ProjectDefaultChange::Established);
        assert!(store.read().unwrap().unwrap().pending_default.is_none());
        assert_eq!(
            defaults_of(&store)[0].reference().whole(),
            reference.as_str()
        );
        // The journal's rollback restored the old host bytes, and an existing
        // record is not replaced by an establishing write.
        assert_eq!(host_reference(&store).unwrap(), child('a').as_str());
    }

    #[test]
    fn unrelated_default_edit_blocks_observation_and_recovery() {
        let (_dir, store) = paths();
        let mut f = file();
        f.pending_default = Some(PendingDefault {
            previous: Some(String::from_utf8(default_bytes('a')).unwrap()),
            proposed: String::from_utf8(default_bytes('b')).unwrap(),
        });
        install(&store, &f);
        store.write_default(Some(&default_bytes('c'))).unwrap();
        let before = std::fs::read(store.record()).unwrap();
        assert!(store.load_default().is_err());
        let a = candidate('a');
        assert!(
            store
                .commit_pin(&a, &Approval::initial(&a), DefaultAction::None)
                .is_err()
        );
        assert_eq!(std::fs::read(store.record()).unwrap(), before);
        assert_eq!(
            default::snapshot_at(&store.directory).unwrap().unwrap(),
            default_bytes('c')
        );
    }

    #[test]
    fn observational_reads_create_nothing_and_share_locks() {
        let (_dir, store) = paths();
        assert!(store.load_default().unwrap().is_none());
        assert!(store.lookup(&candidate('a').key).unwrap().is_none());
        assert!(!store.directory.exists());
        install(&store, &file());
        let lock = open_lock(&store.lock_path(), false).unwrap().unwrap();
        wait(
            &lock,
            FlockMode::Shared,
            Instant::now() + READ_WAIT,
            &mut false,
        )
        .unwrap();
        std::fs::set_permissions(&store.directory, std::fs::Permissions::from_mode(0o500)).unwrap();
        assert!(store.lookup(&candidate('a').key).unwrap().is_some());
        assert!(store.load_default().unwrap().is_none());
        assert!(!store.directory.join(DEFAULT_LOCK_FILE).exists());
        std::fs::set_permissions(&store.directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn observational_exclusive_contention_is_bounded_and_does_not_create() {
        let (_dir, store) = paths();
        install(&store, &file());
        let lock = open_lock(&store.lock_path(), false).unwrap().unwrap();
        wait(
            &lock,
            FlockMode::Exclusive,
            Instant::now() + READ_WAIT,
            &mut false,
        )
        .unwrap();
        let start = Instant::now();
        assert!(
            store
                .load_default()
                .unwrap_err()
                .to_string()
                .contains("timed out")
        );
        assert!(start.elapsed() >= READ_WAIT);
        assert!(start.elapsed() < Duration::from_secs(4));
        assert!(!store.directory.join(DEFAULT_LOCK_FILE).exists());
    }

    #[test]
    fn symlink_and_nonregular_locks_are_closed_errors() {
        for kind in ["symlink", "fifo", "directory"] {
            let (dir, store) = paths();
            std::fs::create_dir_all(&store.directory).unwrap();
            match kind {
                "symlink" => {
                    std::os::unix::fs::symlink(dir.path().join("absent"), store.lock_path())
                        .unwrap()
                }
                "directory" => std::fs::create_dir(store.lock_path()).unwrap(),
                _ => {
                    fifo(&store.lock_path());
                }
            }
            assert!(store.load_default().is_err());
            assert!(!store.record().exists());
        }
    }
    /// Test 11: a journal 0.7.39–0.7.46 wrote is still the authority. A restore
    /// that cannot be written demands recovery and keeps the journal; a later
    /// write recovers it.
    #[test]
    fn journal_real_write_failures_roll_back_or_require_recovery() {
        let (_dir, store) = paths();
        let previous = default_bytes('a');
        let proposed = String::from_utf8(default_bytes('b')).unwrap();
        let mut f = file();
        f.pending_default = Some(PendingDefault {
            previous: Some(String::from_utf8(previous.clone()).unwrap()),
            proposed: proposed.clone(),
        });
        install(&store, &f);
        // Interrupted after the host save.
        store.write_default(Some(proposed.as_bytes())).unwrap();
        let mut file = store.read().unwrap().unwrap();
        let error = store
            .recover_using(&mut file, &mut |_path, _bytes| Err(failure()))
            .unwrap_err();
        assert!(error.to_string().contains("requires recovery"), "{error}");
        assert!(store.read().unwrap().unwrap().pending_default.is_some());
        // The logical old bytes stay observable without clearing the intent.
        assert_eq!(store.observe().unwrap().1.unwrap(), previous);

        let a = candidate('a');
        store
            .commit_pin(&a, &Approval::initial(&a), DefaultAction::None)
            .unwrap();
        assert!(store.read().unwrap().unwrap().pending_default.is_none());
        assert_eq!(host_default(&store).unwrap(), previous);
    }

    #[test]
    fn two_first_writers_cannot_overwrite_the_winner() {
        let (_dir, store) = paths();
        let start = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            let handles: Vec<_> = ['a', 'b']
                .into_iter()
                .map(|byte| {
                    let store = &store;
                    let start = &start;
                    scope.spawn(move || {
                        let c = candidate(byte);
                        start.wait();
                        store.commit_pin(&c, &Approval::initial(&c), DefaultAction::None)
                    })
                })
                .collect();
            let outcomes: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
            assert_eq!(outcomes.iter().filter(|r| r.is_ok()).count(), 1);
            assert_eq!(
                store.lookup(&candidate('a').key).unwrap().unwrap().revision,
                PinRevision(1)
            );
        });
    }

    /// Test 3 + 4: one save carries the first pin and the project's default,
    /// keyed by the *selected* reference; a recommendation selection also seeds
    /// an absent host record first.
    #[test]
    fn a_first_default_pin_establishes_the_project_in_one_save() {
        for host in [HostRetention::Keep, HostRetention::InitializeIfAbsent] {
            let (_dir, store) = paths();
            let (c, reference) = selected('a');
            let committed = store
                .commit_with(&c, &Approval::initial(&c), establish(&reference, host))
                .unwrap();
            assert_eq!(committed.project_default, ProjectDefaultChange::Established);
            let file = store.read().unwrap().unwrap();
            assert_eq!(file.pins.len(), 1);
            assert_eq!(file.defaults.len(), 1);
            assert_eq!(file.defaults[0].image, reference.as_str());
            assert_eq!(file.defaults[0].project, project().as_str());
            assert!(file.pending_default.is_none());
            assert_eq!(
                host_default(&store).is_some(),
                host == HostRetention::InitializeIfAbsent
            );
        }
    }

    /// Test 4: host-first ordering. The recommendation initializes an absent
    /// host record, and a project default never does.
    #[test]
    fn the_recommendation_seeds_an_absent_host_record_first() {
        let (_dir, store) = paths();
        let (c, reference) = selected('a');
        store
            .commit_with(
                &c,
                &Approval::initial(&c),
                establish(&reference, HostRetention::InitializeIfAbsent),
            )
            .unwrap();
        assert_eq!(host_reference(&store).unwrap(), child('a').as_str());

        // A selection read from an existing host record leaves those bytes alone.
        let other = ProjectId::for_tests('b');
        let (d, reference_d) = selected_in(&other, 'f');
        let host_bytes = host_default(&store).unwrap();
        store
            .commit_with(
                &d,
                &Approval::initial(&d),
                establish(&reference_d, HostRetention::Keep),
            )
            .unwrap();
        assert_eq!(host_default(&store).unwrap(), host_bytes);
    }

    /// Test 5: write-once per project. A second establishment in the same
    /// project never moves it; another project establishes independently.
    #[test]
    fn establishment_is_write_once_and_per_project() {
        let (_dir, store) = paths();
        let (a, reference_a) = selected('a');
        store
            .commit_with(
                &a,
                &Approval::initial(&a),
                establish(&reference_a, HostRetention::Keep),
            )
            .unwrap();
        let (b, reference_b) = selected('b');
        let committed = store
            .commit_with(
                &b,
                &Approval::initial(&b),
                establish(&reference_b, HostRetention::Keep),
            )
            .unwrap();
        assert_eq!(committed.project_default, ProjectDefaultChange::Unchanged);
        assert_eq!(
            defaults_of(&store)[0].reference().whole(),
            reference_a.as_str()
        );

        let other = ProjectId::for_tests('b');
        let (d, reference_d) = selected_in(&other, 'f');
        store
            .commit_with(
                &d,
                &Approval::initial(&d),
                establish(&reference_d, HostRetention::Keep),
            )
            .unwrap();
        let defaults = defaults_of(&store);
        assert_eq!(defaults.len(), 2);
        assert_eq!(
            defaults
                .iter()
                .find(|default| default.project() == &other)
                .unwrap()
                .reference()
                .whole(),
            reference_d.as_str()
        );
    }

    /// The warm path shares that write-once rule without creating locks when the
    /// project is already established.
    #[test]
    fn warm_establishment_validates_the_record_without_creating_locks() {
        let (_dir, store) = paths();
        let (c, reference) = selected('a');
        store
            .commit_with(
                &c,
                &Approval::initial(&c),
                establish(&reference, HostRetention::Keep),
            )
            .unwrap();
        let record = store.record();
        let pin = store.lookup(&c.key).unwrap().unwrap();
        // The first warm claim records Boot (and resolves the scope); only after
        // that whole claim/default work is done is there a no-op to observe.
        assert_eq!(
            store
                .claim_selected_change(&pin, &establish(&reference, HostRetention::Keep))
                .unwrap(),
            ProjectDefaultChange::Unchanged
        );
        let pins = std::fs::read(&record).unwrap();
        let bars = std::fs::read(store.lock_path()).unwrap();
        let pin = store.lookup(&c.key).unwrap().unwrap();
        assert_eq!(
            store
                .claim_selected_change(&pin, &establish(&reference, HostRetention::Keep))
                .unwrap(),
            ProjectDefaultChange::Unchanged
        );
        assert_eq!(std::fs::read(&record).unwrap(), pins);
        assert_eq!(std::fs::read(store.lock_path()).unwrap(), bars);
        // A reference that does not bind this key's own source is refused.
        let unrelated = child('b');
        assert!(
            store
                .claim_selected_change(&pin, &establish(&unrelated, HostRetention::Keep))
                .is_err()
        );
        assert_eq!(std::fs::read(&record).unwrap(), pins);
    }

    #[test]
    fn write_once_establishment_initializes_an_absent_host_record_only() {
        let (_dir, store) = paths();
        let (c, reference) = selected('a');
        // An existing approval is no obstacle: the project default is a
        // separate record in the same file.
        store
            .commit_pin(&c, &Approval::initial(&c), DefaultAction::None)
            .unwrap();
        let pin = store.lookup(&c.key).unwrap().unwrap();
        assert_eq!(
            store
                .claim_selected_change(
                    &pin,
                    &establish(&reference, HostRetention::InitializeIfAbsent)
                )
                .unwrap(),
            ProjectDefaultChange::Established
        );
        assert_eq!(host_reference(&store).unwrap(), child('a').as_str());
        let bytes = std::fs::read(store.directory.join(SELECTION_FILE)).unwrap();
        let pin = store.lookup(&c.key).unwrap().unwrap();
        assert_eq!(
            store
                .claim_selected_change(
                    &pin,
                    &establish(&reference, HostRetention::InitializeIfAbsent)
                )
                .unwrap(),
            ProjectDefaultChange::Unchanged
        );
        assert_eq!(
            std::fs::read(store.directory.join(SELECTION_FILE)).unwrap(),
            bytes
        );
        // A record that does not name this key's own source is refused rather
        // than retained: it would authorize content nothing measured.
        let unrelated = child('c');
        assert!(
            store
                .claim_selected_change(
                    &pin,
                    &establish(&unrelated, HostRetention::InitializeIfAbsent)
                )
                .is_err()
        );
        assert_eq!(
            std::fs::read(store.directory.join(SELECTION_FILE)).unwrap(),
            bytes
        );
    }

    /// Test 8: adoption is a compare-and-swap on the project default that was
    /// read, and the host reference's pin enters in the same save.
    #[test]
    fn adoption_is_a_compare_and_swap_on_the_read_default() {
        let (_dir, store) = paths();
        let (a, reference_a) = selected('a');
        store
            .commit_with(
                &a,
                &Approval::initial(&a),
                establish(&reference_a, HostRetention::Keep),
            )
            .unwrap();
        let expected = store
            .read()
            .unwrap()
            .unwrap()
            .project_default(&project())
            .unwrap()
            .unwrap();
        let (host, reference_host) = selected('b');
        let sequence_before = store.read().unwrap().unwrap().sequence;
        // H was genuinely absent from this project's pins, so the frozen
        // observation is `None`.
        let adoption = DefaultAdoption::new(expected.clone(), reference_host.clone(), &host, None);
        let committed = store.adopt(&host, &adoption).unwrap();
        assert_eq!(
            committed.value.project_default,
            ProjectDefaultChange::Adopted
        );
        let file = store.read().unwrap().unwrap();
        assert_eq!(file.defaults[0].image, reference_host.as_str());
        assert!(file.lookup(&host.key).unwrap().is_some());
        // ADR-0068 R7: adoption is not a successful launch, so the new record
        // holds no role; the save advances the sequence but keeps the approval
        // token it allocated.
        let inserted = file
            .pins
            .iter()
            .find(|record| record.validated().unwrap().key == host.key)
            .expect("the host reference's approval exists");
        assert_eq!(inserted.roles, None, "adoption claims no Boot");
        assert!(file.sequence.unwrap() > sequence_before.unwrap());
        assert!(
            file.pending_default.is_none(),
            "AC12: adoption commits no journal"
        );
        let bytes = std::fs::read(store.record()).unwrap();

        // A second adoption against the default that was read is stale: the
        // candidate binds, but the project's default moved.
        drop(host);
        let (host, _) = selected('b');
        let stale = DefaultAdoption::new(expected, reference_host.clone(), &host, None);
        let error = store
            .adopt(&host, &stale)
            .err()
            .expect("a stale adoption is refused");
        assert!(
            error
                .to_string()
                .contains("image approval is stale; retry the explicit operation"),
            "{error}"
        );
        assert_eq!(std::fs::read(store.record()).unwrap(), bytes);
    }

    /// Test 9: the host reference is immutable, so adopting different content
    /// for the same reference is an integrity failure, not a replacement.
    #[test]
    fn adoption_of_an_immutable_key_never_replaces_another_digest() {
        let (_dir, store) = paths();
        let (a, reference_a) = selected('a');
        let expected = ProjectDefault::new(&project(), &reference_a).unwrap();
        let mut f = PinFile::empty();
        // The established default, already approved at other content for its
        // own immutable key. Only a hand edit (or a registry serving different
        // bytes for one digest) can produce this.
        let live = ApprovedPin {
            key: a.key.clone(),
            digest: ManifestDigest::parse(&format!("sha256:{}", "c".repeat(64))).unwrap(),
            revision: PinRevision(1),
        };
        f.pins.push(PinRecord::of(&live));
        f.set_project_default(expected.clone());
        install(&store, &f);
        let bytes = std::fs::read(store.record()).unwrap();
        let mut proposed_candidate = candidate('b');
        proposed_candidate.key.reference =
            CanonicalOciReference::parse(reference_a.as_str()).unwrap();
        let adoption = DefaultAdoption::new(
            expected,
            reference_a.clone(),
            &proposed_candidate,
            Some(live),
        );
        let error = store
            .adopt(&proposed_candidate, &adoption)
            .err()
            .expect("an immutable key never replaces");
        assert!(error.to_string().contains("integrity failure"), "{error}");
        assert_eq!(std::fs::read(store.record()).unwrap(), bytes);
    }

    /// Test 10: an established project's slot never reads the host record, so a
    /// damaged one does not break its selection.
    #[test]
    fn the_default_slot_ignores_the_host_record_for_an_established_project() {
        let (_dir, store) = paths();
        let (a, reference_a) = selected('a');
        store
            .commit_with(
                &a,
                &Approval::initial(&a),
                establish(&reference_a, HostRetention::Keep),
            )
            .unwrap();
        std::fs::write(store.directory.join(SELECTION_FILE), b"damaged host record").unwrap();
        match store.default_slot(&project()).unwrap() {
            DefaultSlot::Project { reference, file } => {
                assert_eq!(reference.as_str(), reference_a.as_str());
                assert_eq!(file, store.record());
            }
            DefaultSlot::Host(_) => panic!("an established project selects its own default"),
        }
        // A project without one still reads — and refuses — the damaged host
        // record: damage is never absence.
        assert!(store.default_slot(&ProjectId::for_tests('b')).is_err());
    }

    #[test]
    fn mutation_default_lock_wait_has_one_combined_thirty_second_budget() {
        let (_dir, store) = paths();
        let a = candidate('a');
        store
            .commit_pin(&a, &Approval::initial(&a), DefaultAction::None)
            .unwrap();
        let before = std::fs::read(store.record()).unwrap();
        let lock = open_lock(&store.directory.join(DEFAULT_LOCK_FILE), true)
            .unwrap()
            .unwrap();
        wait(
            &lock,
            FlockMode::Exclusive,
            Instant::now() + READ_WAIT,
            &mut false,
        )
        .unwrap();
        let start = Instant::now();
        // A first establishment takes pin EX then default EX, the one live path
        // that needs both.
        let (candidate, reference) = selected('b');
        let error = match store.commit(
            &candidate,
            &Approval::initial(&candidate),
            establish(&reference, HostRetention::InitializeIfAbsent),
            RoleClaim::Keep,
        ) {
            Err(error) => error,
            Ok(_) => panic!("a contended default lock must fail this write"),
        };
        assert!(error.to_string().contains("timed out"));
        assert!(start.elapsed() >= WRITE_WAIT);
        // One budget, not two: a run that also spent the pin's share before the
        // default wait could not finish under twice `WRITE_WAIT`. The margin is
        // for a stalled runner, not for the property: scheduler delay lands
        // between the syscalls, never on the deadline that bounds them.
        assert!(start.elapsed() < WRITE_WAIT + Duration::from_secs(10));
        assert_eq!(std::fs::read(store.record()).unwrap(), before);
        assert!(!store.directory.join(SELECTION_FILE).exists());
        // Failure releases the already-acquired pin EX, not merely default EX.
        //
        // Poll to a bound rather than sample once: a descriptor closed on the
        // failing path can still read as held for a few scheduler ticks after
        // the call returned, which is why the sibling assertion in
        // `image_acquire::barrier::tests::a_cancelled_waiter_releases_its_descriptor`
        // polls the same way. A single sample made this test fail on CI with the
        // budget met and the record untouched, reporting the pin as contended
        // (#585). The bound keeps the property: a pin the failed write dropped
        // only late, or never, still fails here, far inside the 30 s the
        // transaction could have held it.
        let probe = open_lock(&store.lock_path(), false).unwrap().unwrap();
        let released = Instant::now() + Duration::from_secs(5);
        loop {
            if host_paths::try_flock(&probe, FlockMode::Exclusive).unwrap()
                == host_paths::FlockAttempt::Acquired
            {
                break;
            }
            assert!(
                Instant::now() < released,
                "the failed write kept the pin EX instead of releasing it"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    #[test]
    fn pin_only_work_does_not_observe_an_unused_damaged_default() {
        let (_dir, store) = paths();
        std::fs::create_dir_all(&store.directory).unwrap();
        std::fs::write(
            store.directory.join(SELECTION_FILE),
            b"damaged unused fallback",
        )
        .unwrap();
        let a = candidate('a');
        assert!(store.lookup(&a.key).unwrap().is_none());
        assert!(!store.lock_path().exists());
        store
            .commit_pin(&a, &Approval::initial(&a), DefaultAction::None)
            .unwrap();
        assert!(store.lookup(&a.key).unwrap().is_some());
        assert!(store.load_default().is_err());
        assert_eq!(
            std::fs::read(store.directory.join(SELECTION_FILE)).unwrap(),
            b"damaged unused fallback"
        );
    }

    /// One reference, two projects: the uniqueness tuple and the lookup both
    /// select by project, so neither project's record can answer for the other.
    #[test]
    fn same_reference_in_two_projects_is_two_keys() {
        let (_dir, store) = paths();
        let a = candidate_in(&ProjectId::for_tests('a'), 'a');
        let b = candidate_in(&ProjectId::for_tests('b'), 'b');
        assert_eq!(a.key.reference, b.key.reference);
        let first = store
            .commit_pin(&a, &Approval::initial(&a), DefaultAction::None)
            .unwrap();
        let second = store
            .commit_pin(&b, &Approval::initial(&b), DefaultAction::None)
            .unwrap();
        // One HOME-wide sequence: the two independent inserts allocate 1 then 2,
        // not a per-key reset to 1.
        assert_eq!(
            (first.revision, second.revision),
            (PinRevision(1), PinRevision(2))
        );
        assert_eq!(store.read().unwrap().unwrap().pins.len(), 2);
        assert_eq!(store.lookup(&a.key).unwrap().unwrap().digest, a.digest);
        assert_eq!(store.lookup(&b.key).unwrap().unwrap().digest, b.digest);
    }

    /// Spec R4, at the store: a first pin, an equivalent re-resolution and a
    /// consented replacement in project A leave project B's record
    /// byte-for-byte identical, and B's lookup never returns A's record.
    #[test]
    fn a_commit_in_one_project_leaves_another_byte_identical() {
        let (_dir, store) = paths();
        let other_project = ProjectId::for_tests('b');
        let other = candidate_in(&other_project, 'f');
        store
            .commit_pin(&other, &Approval::initial(&other), DefaultAction::None)
            .unwrap();
        let record_of = |project: &ProjectId| {
            let file = store.read().unwrap().unwrap();
            serde_json::to_value(
                file.pins
                    .iter()
                    .find(|record| record.project == project.as_str())
                    .expect("the project has a record"),
            )
            .unwrap()
        };
        let untouched = record_of(&other_project);

        let a = candidate('a');
        let first = store
            .commit_pin(&a, &Approval::initial(&a), DefaultAction::None)
            .unwrap();
        assert_eq!(record_of(&other_project), untouched, "after a first pin");
        store
            .commit_pin(&a, &Approval::initial(&a), DefaultAction::None)
            .unwrap();
        assert_eq!(
            record_of(&other_project),
            untouched,
            "after an equivalent re-resolution"
        );
        let b = candidate('b');
        let replaced = store
            .commit_pin(&b, &replacement(&b, first), DefaultAction::None)
            .unwrap();
        // The other project's insert allocated 1, A's insert 2, the equal
        // re-resolution nothing, and this replacement 3.
        assert_eq!(replaced.revision, PinRevision(3));
        assert_eq!(record_of(&other_project), untouched, "after a replacement");
        assert_eq!(
            store.lookup(&other.key).unwrap().unwrap().digest,
            other.digest
        );
    }

    /// Spec R7: a version-1 store with its lock is refused with the legacy
    /// error, never read as empty, never rewritten, and never reported as
    /// damage on any approval-authority path.
    #[test]
    fn legacy_store_is_refused_not_read_or_rewritten() {
        let bytes = br#"{"version":1,"pins":[],"pending_default":null}"#.to_vec();
        let (_dir, store) = paths();
        std::fs::create_dir_all(&store.directory).unwrap();
        open_lock(&store.lock_path(), true).unwrap();
        std::fs::write(store.record(), &bytes).unwrap();
        let a = candidate('a');
        for error in [
            store.lookup(&a.key).unwrap_err(),
            store
                .commit_pin(&a, &Approval::initial(&a), DefaultAction::None)
                .unwrap_err(),
            store.load_default().unwrap_err(),
        ] {
            let text = format!("{error:#}");
            assert!(text.contains("host-wide version 1 format"), "{text}");
            assert!(text.contains("image-pins.json"), "{text}");
            assert!(text.contains("USAGE.md"), "{text}");
            assert!(!text.contains("damaged"), "{text}");
        }
        assert_eq!(std::fs::read(store.record()).unwrap(), bytes);
        assert!(!store.directory.join(SELECTION_FILE).exists());
        assert!(!store.directory.join(DEFAULT_LOCK_FILE).exists());
    }

    /// Spec R8: a record present without its stable lock is damage on both the
    /// observation and the `begin` path, whatever its version — matching what a
    /// version-1 binary already reported for it.
    #[test]
    fn a_lockless_store_is_damage_on_both_paths() {
        let legacy = br#"{"version":1,"pins":[],"pending_default":null}"#.to_vec();
        for bytes in [legacy, file().encode().unwrap()] {
            let (_dir, store) = paths();
            std::fs::create_dir_all(&store.directory).unwrap();
            std::fs::write(store.record(), &bytes).unwrap();
            let a = candidate('a');
            for error in [
                store.lookup(&a.key).unwrap_err(),
                store
                    .commit_pin(&a, &Approval::initial(&a), DefaultAction::None)
                    .unwrap_err(),
            ] {
                assert!(error.to_string().contains("damaged"), "{error}");
            }
            assert!(!store.lock_path().exists());
            assert_eq!(std::fs::read(store.record()).unwrap(), bytes);
        }
    }

    /// Spec R9: reaching the record bound at commit is a full store, not
    /// damage, and leaves the store unchanged.
    #[test]
    fn a_full_store_is_reported_as_full() {
        let (_dir, store) = paths();
        let mut f = file();
        let template = f.pins[0].clone();
        f.pins = (0..4096)
            .map(|i| {
                let mut record = template.clone();
                record.reference = format!("example.com/image{i}:latest");
                record
            })
            .collect();
        install(&store, &f);
        let before = std::fs::read(store.record()).unwrap();
        let a = candidate('a');
        let error = store
            .commit_pin(&a, &Approval::initial(&a), DefaultAction::None)
            .unwrap_err();
        assert!(
            error.to_string().contains("maximum number of approvals"),
            "{error}"
        );
        assert_eq!(std::fs::read(store.record()).unwrap(), before);
    }

    /// The byte bound is reachable by a **later replacement**: a save that lands
    /// exactly on the bound is followed by one whose longer revision digits cross
    /// it. This is the store-level counterpart of the CLI partial-progress rows,
    /// measured at the encoder so it needs no cache, registry or subprocess.
    ///
    /// The two adds are what a refresh does: each replacement rewrites only its
    /// own record's digest and takes the next global token, so the file grows by
    /// the digits the token gains and nothing else.
    #[test]
    fn a_later_replacement_crosses_the_byte_bound() {
        const FIRST_REF: &str = "example.com/x:tag";
        const SECOND_REF: &str = "example.com/z:tag";
        // One short of the token digit boundary: the first save's revision gains
        // 17 digits, the second save's revision gains 18 and the sequence one.
        const SEQUENCE: u64 = 999_999_999_999_999_998;
        let project = project();
        let variant = Some("v".repeat(64));
        let mut pins = vec![
            pin_record(&project, FIRST_REF, 'a', 1, None),
            pin_record(&project, SECOND_REF, 'c', 1, None),
        ];
        // Pads hold Boot with a matching scope record: scopes add the bytes that
        // make 4 MiB reachable while every array stays inside its record cap.
        let mut scopes = Vec::new();
        // One wide reference and one wide default image, parsed once: the pads
        // differ only by project (the key includes it), so reusing the spellings
        // keeps the fixture's own construction cheap.
        let wide_reference = reference_of_length(270);
        for index in 0..4094u32 {
            let mut record = pin_record(
                &project_at(index),
                "example.com/y:tag",
                'b',
                1,
                Some(RoleMask::BOOT),
            );
            record.reference = wide_reference.clone();
            record.platform.variant = variant.clone();
            pins.push(record);
            scopes.push(scope_record_with(
                &project_at(index),
                RoleMask::BOOT,
                variant.clone(),
            ));
        }
        let mut file = PinFile {
            version: STORE_VERSION,
            pins,
            pending_default: None,
            defaults: {
                let wide_image = digest_reference_of_length(270);
                (0..4096u32)
                    .map(|index| ProjectDefaultRecord {
                        project: format!("{index:064x}"),
                        image: wide_image.clone(),
                    })
                    .collect()
            },
            scopes,
            sequence: Some(SEQUENCE),
        };
        // Size without validating (the maximal shape may exceed the bound), then
        // shorten references — one encoded byte each — to 17 bytes below it, so
        // the first replacement lands exactly on the bound.
        let target = MAX_BYTES as usize - 17;
        let mut excess = serde_json::to_vec(&file).unwrap().len() - target;
        assert!(excess > 0, "the maximal fixture must exceed {target} bytes");
        for record in file.pins.iter_mut().skip(2) {
            if excess == 0 {
                break;
            }
            let take = excess.min(record.reference.len() - FIRST_REF.len());
            record.reference = reference_of_length(record.reference.len() - take);
            excess -= take;
        }
        for record in file.defaults.iter_mut() {
            if excess == 0 {
                break;
            }
            let take = excess.min(record.image.len() - 89);
            record.image = digest_reference_of_length(record.image.len() - take);
            excess -= take;
        }
        assert_eq!(excess, 0, "the references have enough slack");

        // The first replacement: its record and the sequence take the next token.
        // Measured, not validated: the *next* step's validation covers the same
        // shape, so a second 4 MiB validation would only cost time.
        let mut after_first = file.clone();
        after_first.pins[0].manifest_digest = candidate_at(&project, FIRST_REF, 'b')
            .digest
            .as_str()
            .to_owned();
        after_first.pins[0].revision = SEQUENCE + 1;
        after_first.sequence = Some(SEQUENCE + 1);
        assert_eq!(
            serde_json::to_vec(&after_first).unwrap().len(),
            MAX_BYTES as usize,
            "the first save lands exactly on the byte bound"
        );

        // The second replacement gains one more token digit than the sequence
        // does, so its encoded file is larger than the bound: `full()`, with the
        // update-local wording and nothing that denies the earlier commit. This
        // single encode validates the whole 4 MiB shape first (it passes — the
        // error below is the bound, not damage) and then refuses the bound.
        let mut after_second = after_first.clone();
        after_second.pins[1].manifest_digest = candidate_at(&project, SECOND_REF, 'd')
            .digest
            .as_str()
            .to_owned();
        after_second.pins[1].revision = SEQUENCE + 2;
        after_second.sequence = Some(SEQUENCE + 2);
        let error = after_second
            .encode()
            .expect_err("the later replacement crosses the byte bound");
        full_error(&error);
        assert!(
            error
                .to_string()
                .contains("this proposed pin-store update was not committed"),
            "{error}"
        );
        assert!(
            !error.to_string().contains("nothing was approved"),
            "the capacity text must stay update-local: {error}"
        );
        // A refused encode writes nothing by construction; the store-level
        // invariance of a capacity failure beside a committed sibling is what the
        // CLI rows assert (`refresh_late_sequence_exhaustion_keeps_the_earlier_commit`
        // compares the file byte for byte), so no second 4 MiB store read here.
        assert_eq!(
            after_second.pins[1].manifest_digest,
            candidate_at(&project, SECOND_REF, 'd').digest.as_str(),
            "the refused state names the replacement, never a saved one"
        );
    }

    /// Spec R9 for the *other* growth limit: `encode` reports a full store for
    /// the byte bound as well as the record bound, so a valid store can never be
    /// reported as damaged only because it grew.
    ///
    /// The check is defensive by measurement, not by assumption: a record is
    /// bounded by a 64-byte project, the longest canonical reference the OCI
    /// parser accepts, a platform with a 64-byte variant, a 71-byte digest and a
    /// `u64` revision, so 4096 of them do not reach 4 MiB. This builds that
    /// worst case, proves it fits, and proves the next record is refused as
    /// full — with the store's bytes untouched.
    #[test]
    fn a_store_at_its_growth_limit_is_full_not_damaged() {
        let longest_reference = (1..275usize)
            .map(|n| format!("example.com/{n}{}:latest", "e".repeat(n)))
            .rfind(|reference| CanonicalOciReference::parse(reference).is_ok())
            .expect("the OCI parser accepts some long reference");
        let mut f = file();
        let mut template = f.pins[0].clone();
        template.platform.variant = Some("v".repeat(64));
        // A pins-only capacity control: revisions below exhaustion, so growth is
        // refused for count, not for the write sequence (whose exhaustion has its
        // own test in `cas_insert_same_candidate_stale_revision_and_aba`).
        template.revision = 4096;
        f.pins = (0..4096)
            .map(|i| {
                let mut record = template.clone();
                // Unique keys, each as large as the schema allows.
                record.reference = format!("{i}.{longest_reference}");
                record
            })
            .collect();
        let bytes = f
            .encode()
            .expect("the schema's maximum store fits in the byte bound");
        assert!(
            store_bytes_within_limit(bytes.len()),
            "the byte bound is unreachable by growth: {} bytes",
            bytes.len()
        );
        let (_dir, store) = paths();
        install(&store, &f);
        let before = std::fs::read(store.record()).unwrap();
        let a = candidate('a');
        let error = store
            .commit_pin(&a, &Approval::initial(&a), DefaultAction::None)
            .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("maximum number of approvals"), "{message}");
        assert!(!message.contains("damaged"), "{message}");
        assert_eq!(std::fs::read(store.record()).unwrap(), before);
    }

    /// Spec R7: the legacy refusal is the user's only map to the procedure, and
    /// every OCI command fails until they run it. So the message must carry the
    /// three facts R7 names — the format it found, that archiving resets
    /// approvals, and that a mutable tag may resolve to newer content — and the
    /// USAGE section it points at must exist, holding exactly the one upgrade
    /// and one rollback block an operator is told to paste.
    ///
    /// The section name is taken *from the error*, not restated here, so
    /// renaming the heading without the message (or the reverse) fails.
    #[test]
    fn the_legacy_refusal_names_its_facts_and_an_existing_usage_section() {
        let message = format!("{:#}", legacy());
        for fact in [
            "host-wide version 1 format",
            "resets approvals",
            "newer content",
            "image-pins.json",
        ] {
            assert!(message.contains(fact), "R7 requires {fact:?}: {message}");
        }
        let section = message
            .split('"')
            .nth(1)
            .filter(|quoted| quoted.contains("Upgrading"))
            .unwrap_or_else(|| panic!("the message must quote the section it names: {message}"));

        let usage = include_str!("../../../../USAGE.md");
        let heading = usage
            .lines()
            .find(|line| line.trim_start_matches('#').trim() == section);
        assert!(
            heading.is_some(),
            "USAGE.md has no {section:?} heading for the refusal that quotes it"
        );
        assert!(
            heading.unwrap().starts_with("###"),
            "{section:?} must be a section of its own: {}",
            heading.unwrap()
        );
        for marker in ["upgrade", "rollback"] {
            for tag in [
                format!("<!-- pin-store-{marker} -->"),
                format!("<!-- /pin-store-{marker} -->"),
            ] {
                assert_eq!(
                    usage.matches(&tag).count(),
                    1,
                    "USAGE.md must carry exactly one {tag}"
                );
            }
        }
    }

    // ---------------------------------------------------------------------
    // ADR-0068: held roles, scope resolution, retirement and the global
    // write sequence.
    // ---------------------------------------------------------------------

    /// A key on the fixture's own canonical source spelling, distinct per test
    /// reference so two records can share one project/platform scope.
    fn candidate_at(project: &ProjectId, reference: &str, byte: char) -> ValidatedCandidate {
        let mut c = candidate_in(project, byte);
        c.key.reference = CanonicalOciReference::parse(reference).unwrap();
        c
    }
    fn scope_of(project: &ProjectId) -> ScopeKey {
        candidate_in(project, 'a').key.scope()
    }
    fn scope_record(project: &ProjectId, resolved: RoleMask) -> ScopeRecord {
        ScopeRecord {
            project: project.as_str().to_owned(),
            platform: HostLinuxPlatform::for_tests(),
            resolved,
        }
    }
    fn scope_record_with(
        project: &ProjectId,
        resolved: RoleMask,
        variant: Option<String>,
    ) -> ScopeRecord {
        let mut platform = HostLinuxPlatform::for_tests();
        platform.variant = variant;
        ScopeRecord {
            project: project.as_str().to_owned(),
            platform,
            resolved,
        }
    }
    fn pin_record(
        project: &ProjectId,
        reference: &str,
        byte: char,
        revision: u64,
        roles: Option<RoleMask>,
    ) -> PinRecord {
        let c = candidate_at(project, reference, byte);
        PinRecord {
            project: project.as_str().to_owned(),
            reference: reference.to_owned(),
            platform: HostLinuxPlatform::for_tests(),
            manifest_digest: c.digest.as_str().to_owned(),
            revision,
            roles,
        }
    }
    /// The literal 0.7.49 record shape: no `roles`, no `scopes`, no `sequence`.
    /// Built as JSON so the fixture cannot acquire a field a new writer adds.
    fn old_v2_record(
        project: &ProjectId,
        reference: &str,
        byte: char,
        revision: u64,
    ) -> serde_json::Value {
        serde_json::json!({
            "project": project.as_str(),
            "reference": reference,
            "platform": serde_json::to_value(HostLinuxPlatform::for_tests()).unwrap(),
            "manifest_digest": format!("sha256:{}", byte.to_string().repeat(64)),
            "revision": revision,
        })
    }
    fn old_v2_bytes(pins: Vec<serde_json::Value>) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "version": 2,
            "pins": pins,
            "pending_default": null,
        }))
        .unwrap()
    }
    /// Install exact bytes with the stable lock a real store always has.
    fn install_raw(store: &Store, bytes: &[u8]) {
        std::fs::create_dir_all(&store.directory).unwrap();
        open_lock(&store.lock_path(), true).unwrap();
        std::fs::write(store.record(), bytes).unwrap();
    }
    fn pin_json(file: &PinFile, reference: &str) -> Option<serde_json::Value> {
        file.pins
            .iter()
            .find(|record| record.reference == reference)
            .map(|record| serde_json::to_value(record).unwrap())
    }
    fn roles_of(file: &PinFile, reference: &str) -> Option<RoleMask> {
        file.pins
            .iter()
            .find(|record| record.reference == reference)
            .and_then(|record| record.roles)
    }
    fn resolved_of(file: &PinFile, project: &ProjectId) -> Option<RoleMask> {
        file.resolved_in(&scope_of(project))
            .map(ResolvedRoles::mask)
    }

    /// AC1/AC12: untouched old bytes decode as "both roles unknown" without any
    /// write, and re-encoding them omits every new field.
    #[test]
    fn old_v2_decodes_with_no_scope_knowledge() {
        let bytes = old_v2_bytes(vec![old_v2_record(&project(), SOURCE, 'a', 7)]);
        let file = PinFile::decode(&bytes).unwrap();
        assert!(file.scopes.is_empty());
        assert_eq!(file.sequence, None);
        assert_eq!(file.effective_sequence(), 7);
        assert_eq!(file.pins[0].roles, None);
        assert!(file.resolved_in(&scope_of(&project())).is_none());
        assert_eq!(file.encode().unwrap(), bytes);
        let (_dir, store) = paths();
        install_raw(&store, &bytes);
        assert_eq!(
            store.lookup(&candidate('a').key).unwrap().unwrap().revision,
            PinRevision(7)
        );
        assert_eq!(
            std::fs::read(store.record()).unwrap(),
            bytes,
            "a read writes nothing"
        );
    }

    /// AC12: every new relational fact is validated on read, and the messages
    /// never leak a reference.
    #[test]
    fn strict_role_and_scope_decode() {
        let project = project();
        let valid = PinFile {
            version: STORE_VERSION,
            pins: vec![
                pin_record(&project, "example.com/x:tag", 'a', 1, Some(RoleMask::BOOT)),
                pin_record(
                    &project,
                    "example.com/o:tag",
                    'b',
                    2,
                    Some(RoleMask::OUTPUT),
                ),
            ],
            pending_default: None,
            defaults: Vec::new(),
            scopes: vec![scope_record(&project, RoleMask::BOOT_AND_OUTPUT)],
            sequence: Some(2),
        };
        let bytes = valid.encode().unwrap();
        assert!(PinFile::decode(&bytes).is_ok());
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let mutate = |f: &dyn Fn(&mut serde_json::Value)| {
            let mut v = value.clone();
            f(&mut v);
            serde_json::to_vec(&v).unwrap()
        };
        let mut cases = vec![
            // Present null / empty / unknown masks are damage, not "none".
            mutate(&|v| v["pins"][0]["roles"] = serde_json::json!(null)),
            mutate(&|v| v["pins"][0]["roles"] = serde_json::json!("")),
            mutate(&|v| v["pins"][0]["roles"] = serde_json::json!("boot+output")),
            mutate(&|v| v["scopes"][0]["resolved"] = serde_json::json!("")),
            mutate(&|v| v["scopes"][0]["resolved"] = serde_json::json!(null)),
            // Duplicate scope key.
            mutate(&|v| {
                let entry = v["scopes"][0].clone();
                v["scopes"].as_array_mut().unwrap().push(entry);
            }),
            // A holder whose scope resolves nothing (no scope record at all).
            mutate(&|v| v["scopes"] = serde_json::json!([])),
            // A resolved slot with no holder.
            mutate(&|v| v["pins"][1]["roles"] = serde_json::json!(null)),
            // A resolved role with two holders, while every other slot keeps
            // its holder: the rejection cannot be "Output lost its only holder".
            mutate(&|v| {
                let mut duplicate = v["pins"][0].clone();
                duplicate["reference"] = serde_json::json!("example.com/y:tag");
                duplicate["revision"] = serde_json::json!(3);
                v["pins"].as_array_mut().unwrap().push(duplicate);
                v["sequence"] = serde_json::json!(3);
            }),
            // Any roles/scopes require a sequence.
            mutate(&|v| {
                v.as_object_mut().unwrap().remove("sequence");
            }),
            // A present sequence must be positive and cover live revisions.
            mutate(&|v| v["sequence"] = serde_json::json!(0)),
            mutate(&|v| v["sequence"] = serde_json::json!(1)),
        ];
        // Old files with no roles/scopes may omit the sequence even with
        // duplicate per-key revisions: that is a legacy maximum, not damage.
        let old = old_v2_bytes(vec![
            old_v2_record(&project, "example.com/a:tag", 'a', 1),
            old_v2_record(&project, "example.com/b:tag", 'b', 1),
        ]);
        assert!(PinFile::decode(&old).is_ok());
        // Duplicate keys and a scope-record unknown field cannot be expressed as
        // a `Value`, so the byte-level cases use the raw text the decoder sees.
        let raw = std::str::from_utf8(&bytes).unwrap().to_owned();
        let duplicate = |needle: &str, replacement: &str| -> Vec<u8> {
            let once = raw.replacen(needle, replacement, 1);
            assert_ne!(once, raw, "the fixture must contain {needle}");
            once.into_bytes()
        };
        cases.push(duplicate(
            "\"roles\":\"boot\"",
            "\"roles\":\"boot\",\"roles\":\"boot\"",
        ));
        cases.push(duplicate(
            "\"resolved\":\"boot-and-output\"",
            "\"resolved\":\"boot-and-output\",\"resolved\":\"boot\"",
        ));
        cases.push(duplicate("\"sequence\":2", "\"sequence\":2,\"sequence\":2"));
        cases.push(duplicate(
            "\"resolved\":\"boot-and-output\"",
            "\"resolved\":\"boot-and-output\",\"extra\":1",
        ));
        for (i, bytes) in cases.drain(..).enumerate() {
            let error = PinFile::decode(&bytes)
                .err()
                .unwrap_or_else(|| panic!("accepted role/scope corruption case {i}"));
            assert!(!error.to_string().contains("example.com"), "{error}");
            assert!(!error.to_string().contains("sha256"), "{error}");
        }
        // Cross-scope controls are accepted: two projects, two platforms, each
        // with its own single holder.
        let other = ProjectId::for_tests('b');
        let mut foreign = HostLinuxPlatform::for_tests();
        foreign.architecture = if foreign.architecture == "amd64" {
            "arm64"
        } else {
            "amd64"
        }
        .into();
        let cross = PinFile {
            version: STORE_VERSION,
            pins: vec![
                pin_record(&project, "example.com/x:tag", 'a', 1, Some(RoleMask::BOOT)),
                PinRecord {
                    platform: foreign.clone(),
                    ..pin_record(&project, "example.com/x:tag", 'a', 2, Some(RoleMask::BOOT))
                },
                pin_record(&other, "example.com/x:tag", 'a', 3, Some(RoleMask::OUTPUT)),
            ],
            pending_default: None,
            defaults: Vec::new(),
            scopes: vec![
                scope_record(&project, RoleMask::BOOT),
                ScopeRecord {
                    project: project.as_str().to_owned(),
                    platform: foreign,
                    resolved: RoleMask::BOOT,
                },
                scope_record(&other, RoleMask::OUTPUT),
            ],
            sequence: Some(3),
        };
        assert!(PinFile::decode(&cross.encode().unwrap()).is_ok());
    }

    /// AC2/AC4/AC5: with both slots resolved, a claim leaves exactly the two
    /// holders; a shared record survives until neither role holds it.
    #[test]
    fn both_roles_resolved_claim_leaves_only_holders() {
        let project = project();
        let x_ref = "example.com/x:tag";
        let y_ref = "example.com/y:tag";
        let file = PinFile {
            version: STORE_VERSION,
            pins: vec![
                pin_record(&project, x_ref, 'a', 1, Some(RoleMask::BOOT_AND_OUTPUT)),
                pin_record(&project, y_ref, 'b', 2, None),
            ],
            pending_default: None,
            defaults: Vec::new(),
            scopes: vec![scope_record(&project, RoleMask::BOOT_AND_OUTPUT)],
            sequence: Some(2),
        };
        let (_dir, store) = paths();
        install(&store, &file);
        // Y claims Boot: X keeps Output, so it stays.
        let y = candidate_at(&project, y_ref, 'b');
        store
            .claim_pin(&y, &Approval::initial(&y), DefaultAction::None, Role::Boot)
            .unwrap();
        let after = store.read().unwrap().unwrap();
        assert_eq!(roles_of(&after, x_ref), Some(RoleMask::OUTPUT));
        assert_eq!(roles_of(&after, y_ref), Some(RoleMask::BOOT));
        assert_eq!(after.pins.len(), 2);
        assert_eq!(after.sequence, Some(3));
        // Surviving content, not only masks: X's whole record except its roles is
        // the one that was installed, and Y's carries its own digest/token.
        let mut x_expected = pin_json(&file, x_ref).unwrap();
        x_expected["roles"] = serde_json::json!("output");
        assert_eq!(pin_json(&after, x_ref), Some(x_expected));
        let mut y_expected = pin_json(&file, y_ref).unwrap();
        y_expected["roles"] = serde_json::json!("boot");
        assert_eq!(
            pin_json(&after, y_ref),
            Some(y_expected),
            "a metadata-only claim keeps Y's approval token"
        );
        // Y then claims Output: X loses its last role while the scope is fully
        // resolved, so it is both known-absent and retires.
        store
            .claim_pin(
                &y,
                &Approval::initial(&y),
                DefaultAction::None,
                Role::Output,
            )
            .unwrap();
        let after = store.read().unwrap().unwrap();
        assert_eq!(after.pins.len(), 1);
        assert!(pin_json(&after, x_ref).is_none());
        assert_eq!(roles_of(&after, y_ref), Some(RoleMask::BOOT_AND_OUTPUT));
        // The reverse switch order: Output first, then Boot.
        install(&store, &file);
        assert!(pin_json(&store.read().unwrap().unwrap(), x_ref).is_some());
        store
            .claim_pin(
                &y,
                &Approval::initial(&y),
                DefaultAction::None,
                Role::Output,
            )
            .unwrap();
        let after = store.read().unwrap().unwrap();
        assert_eq!(roles_of(&after, x_ref), Some(RoleMask::BOOT));
        assert_eq!(roles_of(&after, y_ref), Some(RoleMask::OUTPUT));
        assert_eq!(after.pins.len(), 2, "X keeps Boot, so it stays");
        store
            .claim_pin(&y, &Approval::initial(&y), DefaultAction::None, Role::Boot)
            .unwrap();
        let after = store.read().unwrap().unwrap();
        assert_eq!(after.pins.len(), 1);
        assert!(
            pin_json(&after, x_ref).is_none(),
            "X retires on the second claim"
        );
        assert_eq!(roles_of(&after, y_ref), Some(RoleMask::BOOT_AND_OUTPUT));

        // Foreign project/platform records are never touched. The foreign record
        // shares the operated reference *text* but carries its own content and
        // token, so comparing it whole proves the identity join rather than a
        // content coincidence (`'d'`, revision 4, versus the local `'a'`, r5).
        let other = ProjectId::for_tests('b');
        let mut mixed = after.clone();
        mixed
            .pins
            .push(pin_record(&other, "example.com/x:tag", 'd', 4, None));
        mixed.pins.push(pin_record(&project, x_ref, 'a', 5, None));
        mixed.sequence = Some(5);
        install(&store, &mixed);
        let before = std::fs::read(store.record()).unwrap();
        let x = candidate_at(&project, x_ref, 'a');
        store
            .claim_pin(&x, &Approval::initial(&x), DefaultAction::None, Role::Boot)
            .unwrap();
        let after = store.read().unwrap().unwrap();
        assert!(pin_json(&after, "example.com/x:tag").is_some());
        // The foreign record is compared whole — project, reference, platform,
        // digest and token — not by its revision alone.
        let foreign = |file: &PinFile| -> Option<serde_json::Value> {
            file.pins
                .iter()
                .find(|record| record.project == other.as_str())
                .map(|record| serde_json::to_value(record).unwrap())
        };
        let before_foreign = foreign(&mixed).expect("the fixture's foreign record");
        let local = mixed
            .pins
            .iter()
            .find(|record| record.project == project.as_str() && record.reference == x_ref)
            .expect("the operated local record");
        assert_eq!(
            before_foreign["manifest_digest"],
            serde_json::json!(format!("sha256:{}", "d".repeat(64))),
            "the foreign record carries its own content"
        );
        assert_eq!(
            local.manifest_digest,
            format!("sha256:{}", "a".repeat(64)),
            "the operated record carries the claim's content"
        );
        assert_ne!(
            before_foreign["manifest_digest"],
            serde_json::json!(local.manifest_digest),
            "the two records differ in content and token, not only in project"
        );
        assert_ne!(
            before_foreign["revision"],
            serde_json::json!(local.revision)
        );
        assert_eq!(
            foreign(&after),
            Some(before_foreign),
            "the foreign record is untouched"
        );
        assert_ne!(std::fs::read(store.record()).unwrap(), before);
    }

    /// AC9: a refresh-created record in an unresolved scope is protected by
    /// that role; once both slots resolve, the next successful claim retires it.
    #[test]
    fn refresh_created_unknown_role_survives_until_scope_resolution() {
        let project = project();
        let (_dir, store) = paths();
        // Refresh inserts an unheld record (Keep) in a fresh scope.
        let u = candidate_at(&project, "example.com/u:tag", 'a');
        store
            .commit_pin(&u, &Approval::initial(&u), DefaultAction::None)
            .unwrap();
        let file = store.read().unwrap().unwrap();
        assert_eq!(roles_of(&file, "example.com/u:tag"), None);
        assert_eq!(resolved_of(&file, &project), None);
        // Output resolution alone cannot justify deleting it: Boot is unknown.
        let p = candidate_at(&project, "example.com/p:tag", 'b');
        store
            .claim_pin(
                &p,
                &Approval::initial(&p),
                DefaultAction::None,
                Role::Output,
            )
            .unwrap();
        let file = store.read().unwrap().unwrap();
        assert!(
            pin_json(&file, "example.com/u:tag").is_some(),
            "?Boot protects it"
        );
        assert_eq!(resolved_of(&file, &project), Some(RoleMask::OUTPUT));
        // Claiming Boot on a third record resolves the missing slot; U is now
        // both known-absent and retires.
        let q = candidate_at(&project, "example.com/q:tag", 'c');
        store
            .claim_pin(&q, &Approval::initial(&q), DefaultAction::None, Role::Boot)
            .unwrap();
        let file = store.read().unwrap().unwrap();
        assert!(pin_json(&file, "example.com/u:tag").is_none());
        assert_eq!(roles_of(&file, "example.com/q:tag"), Some(RoleMask::BOOT));
        assert_eq!(roles_of(&file, "example.com/p:tag"), Some(RoleMask::OUTPUT));
    }

    /// AC9: refresh itself never retires; with both slots already resolved, the
    /// next successful claim — even on the same target — cleans it up.
    #[test]
    fn refresh_after_resolution_waits_for_next_claim() {
        let project = project();
        let b_ref = "example.com/b:tag";
        let o_ref = "example.com/o:tag";
        let file = PinFile {
            version: STORE_VERSION,
            pins: vec![
                pin_record(&project, b_ref, 'a', 1, Some(RoleMask::BOOT)),
                pin_record(&project, o_ref, 'b', 2, Some(RoleMask::OUTPUT)),
            ],
            pending_default: None,
            defaults: Vec::new(),
            scopes: vec![scope_record(&project, RoleMask::BOOT_AND_OUTPUT)],
            sequence: Some(2),
        };
        let (_dir, store) = paths();
        install(&store, &file);
        let v = candidate_at(&project, "example.com/v:tag", 'c');
        store
            .commit_pin(&v, &Approval::initial(&v), DefaultAction::None)
            .unwrap();
        let after = store.read().unwrap().unwrap();
        assert!(
            pin_json(&after, "example.com/v:tag").is_some(),
            "refresh prunes nothing"
        );
        assert_eq!(after.pins.len(), 3);
        assert_eq!(
            roles_of(&after, "example.com/v:tag"),
            None,
            "refresh claims no role for the record it inserts"
        );
        assert_eq!(
            resolved_of(&after, &project),
            Some(RoleMask::BOOT_AND_OUTPUT),
            "refresh changes no resolution"
        );
        // A successful same-target Boot claim retires the known-inactive V.
        let b = candidate_at(&project, b_ref, 'a');
        store
            .claim_pin(&b, &Approval::initial(&b), DefaultAction::None, Role::Boot)
            .unwrap();
        let after = store.read().unwrap().unwrap();
        assert!(pin_json(&after, "example.com/v:tag").is_none());
        assert_eq!(roles_of(&after, b_ref), Some(RoleMask::BOOT));
        assert_eq!(roles_of(&after, o_ref), Some(RoleMask::OUTPUT));
    }

    /// AC19 at the store: a legacy record claimed as Output keeps its unknown
    /// Boot — and its exact bytes — through displacement, until Boot is claimed.
    #[test]
    fn legacy_boot_survives_output_claim_and_displacement() {
        let project = project();
        let x_ref = "example.com/x:tag";
        let bytes = old_v2_bytes(vec![old_v2_record(&project, x_ref, 'a', 7)]);
        let (_dir, store) = paths();
        install_raw(&store, &bytes);
        let x = candidate_at(&project, x_ref, 'a');
        // A successful unchanged build/import of X is an Output claim.
        store
            .claim_pin(
                &x,
                &Approval::initial(&x),
                DefaultAction::None,
                Role::Output,
            )
            .unwrap();
        let file = store.read().unwrap().unwrap();
        assert_eq!(roles_of(&file, x_ref), Some(RoleMask::OUTPUT));
        assert_eq!(resolved_of(&file, &project), Some(RoleMask::OUTPUT));
        // AC1's envelope: the version stays 2 and the save persists the
        // allocated sequence (the legacy maximum was 7).
        assert_eq!(file.version, STORE_VERSION);
        assert_eq!(file.sequence, Some(8));
        // Publishing a different reference takes the sole Output slot.
        let y = candidate_at(&project, "example.com/y:tag", 'b');
        store
            .claim_pin(
                &y,
                &Approval::initial(&y),
                DefaultAction::None,
                Role::Output,
            )
            .unwrap();
        let file = store.read().unwrap().unwrap();
        assert_eq!(
            pin_json(&file, x_ref),
            Some(old_v2_record(&project, x_ref, 'a', 7))
        );
        assert_eq!(
            file.lookup(&x.key).unwrap().unwrap().revision,
            PinRevision(7)
        );
        // Only a Boot claim in the same scope proves it absent and retires it.
        let z = candidate_at(&project, "example.com/z:tag", 'c');
        store
            .claim_pin(&z, &Approval::initial(&z), DefaultAction::None, Role::Boot)
            .unwrap();
        let file = store.read().unwrap().unwrap();
        assert!(pin_json(&file, x_ref).is_none());
        assert_eq!(roles_of(&file, "example.com/y:tag"), Some(RoleMask::OUTPUT));
        assert_eq!(roles_of(&file, "example.com/z:tag"), Some(RoleMask::BOOT));
    }

    /// AC20 at the store: the symmetric legacy record claimed as Boot keeps its
    /// unknown Output through displacement until Output is claimed.
    #[test]
    fn legacy_output_survives_boot_claim_and_displacement() {
        let project = project();
        let x_ref = "example.com/x:tag";
        let bytes = old_v2_bytes(vec![old_v2_record(&project, x_ref, 'a', 7)]);
        let (_dir, store) = paths();
        install_raw(&store, &bytes);
        let x = candidate_at(&project, x_ref, 'a');
        // A successful launch/setup of X is a Boot claim (warm claim path).
        let consumed = store.lookup(&x.key).unwrap().unwrap();
        store
            .claim_selected(&consumed, &DefaultAction::None)
            .unwrap();
        let file = store.read().unwrap().unwrap();
        assert_eq!(roles_of(&file, x_ref), Some(RoleMask::BOOT));
        assert_eq!(resolved_of(&file, &project), Some(RoleMask::BOOT));
        // A different Boot selection moves the slot; ?Output protects X.
        let y = candidate_at(&project, "example.com/y:tag", 'b');
        store
            .claim_pin(&y, &Approval::initial(&y), DefaultAction::None, Role::Boot)
            .unwrap();
        let file = store.read().unwrap().unwrap();
        assert_eq!(
            pin_json(&file, x_ref),
            Some(old_v2_record(&project, x_ref, 'a', 7))
        );
        // Resolving Output elsewhere retires it.
        let z = candidate_at(&project, "example.com/z:tag", 'c');
        store
            .claim_pin(
                &z,
                &Approval::initial(&z),
                DefaultAction::None,
                Role::Output,
            )
            .unwrap();
        let file = store.read().unwrap().unwrap();
        assert!(pin_json(&file, x_ref).is_none());
        assert_eq!(roles_of(&file, "example.com/y:tag"), Some(RoleMask::BOOT));
        assert_eq!(roles_of(&file, "example.com/z:tag"), Some(RoleMask::OUTPUT));
    }

    /// AC21/AC22: a new global allocation defeats same-digest retire/reinsert
    /// ABA. The consumed tuple carries the old lifetime's token.
    #[test]
    fn warm_claim_rejects_new_lifetime_same_digest() {
        let project = project();
        let x_ref = "example.com/x:tag";
        let bytes = old_v2_bytes(vec![
            old_v2_record(&project, x_ref, 'a', 1),
            old_v2_record(&project, "example.com/b:tag", 'b', 2),
        ]);
        let (_dir, store) = paths();
        install_raw(&store, &bytes);
        let x = candidate_at(&project, x_ref, 'a');
        let consumed = store.lookup(&x.key).unwrap().unwrap();
        assert_eq!(consumed.revision, PinRevision(1));
        // Peers resolve both slots, retiring X, then reinsert the same digest.
        let y = candidate_at(&project, "example.com/y:tag", 'c');
        store
            .claim_pin(
                &y,
                &Approval::initial(&y),
                DefaultAction::None,
                Role::Output,
            )
            .unwrap();
        let z = candidate_at(&project, "example.com/z:tag", 'd');
        store
            .claim_pin(&z, &Approval::initial(&z), DefaultAction::None, Role::Boot)
            .unwrap();
        assert!(store.lookup(&x.key).unwrap().is_none(), "X is absent");
        let x = candidate_at(&project, x_ref, 'a');
        store
            .commit_pin(&x, &Approval::initial(&x), DefaultAction::None)
            .unwrap();
        let reinserted = store.lookup(&x.key).unwrap().unwrap();
        assert_ne!(reinserted.revision, PinRevision(1), "no lifetime reuse");
        assert!(reinserted.revision.0 > 1);
        // The suspended operation's predecessor is now stale.
        let before = std::fs::read(store.record()).unwrap();
        let error = match store.claim_selected(&consumed, &DefaultAction::None) {
            Err(error) => error,
            Ok(_) => panic!("a reinserted lifetime must not satisfy the old tuple"),
        };
        assert!(error.to_string().contains("stale"), "{error}");
        assert_eq!(std::fs::read(store.record()).unwrap(), before);
    }

    /// S5/§1 C3/C4: the equal-digest publication decision is pinned, not
    /// incidental.
    ///
    /// C3: a publication that read X=A/r1 and rendered `equivalent` from it
    /// resumes *after* peers retired X and reinserted the same digest under a new
    /// global token. `commit_decision` reconciles on the digest, so it claims
    /// Output on the **live** lifetime: it commits, its bytes equal those of a
    /// publication that started after the reinsert, and the live token is
    /// untouched. C4: with the record absent the same observed predecessor is
    /// stale — an equal digest never resurrects a retired lifetime.
    #[test]
    fn equal_digest_publication_claims_the_live_lifetime() {
        let project = project();
        let x_ref = "example.com/x:tag";
        let o_ref = "example.com/o:tag";
        let z_ref = "example.com/z:tag";
        let start = PinFile {
            version: STORE_VERSION,
            pins: vec![
                pin_record(&project, x_ref, 'a', 1, Some(RoleMask::BOOT)),
                pin_record(&project, o_ref, 'b', 2, Some(RoleMask::OUTPUT)),
                pin_record(&project, z_ref, 'c', 3, None),
            ],
            pending_default: None,
            defaults: Vec::new(),
            scopes: vec![scope_record(&project, RoleMask::BOOT_AND_OUTPUT)],
            sequence: Some(3),
        };
        let x = candidate_at(&project, x_ref, 'a');
        // The suspended publication read X=A/r1 and rendered `equivalent` from it.
        let (_observed_dir, observed) = paths();
        install(&observed, &start);
        let observed_tuple = observed.lookup(&x.key).unwrap().unwrap();
        assert_eq!(observed_tuple.revision, PinRevision(1));
        let approval = Approval::equivalent(&observed_tuple, &x);

        // Peers retire X with a metadata-only Boot claim on the existing, unheld Z
        // (which allocates no revision), then reinsert the same digest A.
        let z_pin = observed
            .lookup(&candidate_at(&project, z_ref, 'c').key)
            .unwrap()
            .unwrap();
        observed
            .claim_selected(&z_pin, &DefaultAction::None)
            .unwrap();
        assert!(observed.lookup(&x.key).unwrap().is_none(), "X is retired");
        observed
            .commit_pin(&x, &Approval::initial(&x), DefaultAction::None)
            .unwrap();
        let reinserted = observed.lookup(&x.key).unwrap().unwrap();
        assert_eq!(
            reinserted.revision,
            PinRevision(5),
            "a new global allocation"
        );
        assert_ne!(reinserted.revision, observed_tuple.revision);
        let peer_bytes = std::fs::read(observed.record()).unwrap();

        // C3: the suspended publication's predecessor no longer exists, but its
        // candidate equals the live digest, so it commits on that live lifetime.
        observed
            .claim_pin(&x, &approval, DefaultAction::None, Role::Output)
            .unwrap();
        let after_observed = std::fs::read(observed.record()).unwrap();

        // C3b/control: the same publication started *after* the reinsert, i.e.
        // with the reinserted tuple as its observed predecessor.
        let (_fresh_dir, fresh) = paths();
        install_raw(&fresh, &peer_bytes);
        let fresh_tuple = fresh.lookup(&x.key).unwrap().unwrap();
        assert_eq!(fresh_tuple, reinserted);
        fresh
            .claim_pin(
                &x,
                &Approval::equivalent(&fresh_tuple, &x),
                DefaultAction::None,
                Role::Output,
            )
            .unwrap();
        assert_eq!(
            std::fs::read(fresh.record()).unwrap(),
            after_observed,
            "the reconciled publication equals a later-started publication"
        );
        let after = observed.read().unwrap().unwrap();
        let x_after = after.lookup(&x.key).unwrap().unwrap();
        assert_eq!(
            x_after.revision,
            PinRevision(5),
            "the live lifetime's token is not reallocated"
        );
        assert_eq!(x_after.digest, x.digest);
        assert_eq!(roles_of(&after, x_ref), Some(RoleMask::OUTPUT));
        assert_eq!(
            roles_of(&after, z_ref),
            Some(RoleMask::BOOT),
            "Boot stays with the peer's holder"
        );
        assert!(
            after
                .lookup(&candidate_at(&project, o_ref, 'b').key)
                .unwrap()
                .is_none(),
            "the displaced Output holder retires"
        );
        assert_eq!(after.sequence, Some(6));

        // C4: the same digest with the record absent is stale, not a resurrection.
        let (_absent_dir, absent) = paths();
        install(
            &absent,
            &PinFile {
                pins: vec![pin_record(&project, o_ref, 'b', 2, Some(RoleMask::OUTPUT))],
                scopes: vec![scope_record(&project, RoleMask::OUTPUT)],
                sequence: Some(2),
                ..start.clone()
            },
        );
        let before = std::fs::read(absent.record()).unwrap();
        let error = absent
            .claim_pin(&x, &approval, DefaultAction::None, Role::Output)
            .unwrap_err();
        assert!(error.to_string().contains("stale"), "{error}");
        assert_eq!(
            std::fs::read(absent.record()).unwrap(),
            before,
            "no record is recreated"
        );
    }

    /// AC21/AC22: the retired record holds the **high-water** revision and is
    /// retired by a metadata-only claim that allocates no revision, so an
    /// allocator reading the live maximum instead of the persisted sequence would
    /// reissue the retired token and accept the old lifetime.
    #[test]
    fn high_water_retired_record_reinserts_above_it() {
        let project = project();
        let x_ref = "example.com/x:tag";
        let file = PinFile {
            version: STORE_VERSION,
            pins: vec![
                pin_record(&project, x_ref, 'a', 5, Some(RoleMask::BOOT)),
                pin_record(
                    &project,
                    "example.com/o:tag",
                    'b',
                    3,
                    Some(RoleMask::OUTPUT),
                ),
                pin_record(&project, "example.com/z:tag", 'c', 4, None),
            ],
            pending_default: None,
            defaults: Vec::new(),
            scopes: vec![scope_record(&project, RoleMask::BOOT_AND_OUTPUT)],
            sequence: Some(5),
        };
        let (_dir, store) = paths();
        install(&store, &file);
        let x = candidate_at(&project, x_ref, 'a');
        let consumed = store.lookup(&x.key).unwrap().unwrap();
        assert_eq!(consumed.revision, PinRevision(5), "X holds the high-water");
        // A metadata-only Boot claim on the existing, unheld Z retires X: no
        // revision is allocated for Z, so the live maximum drops below X's token.
        let z = store
            .lookup(&candidate_at(&project, "example.com/z:tag", 'c').key)
            .unwrap()
            .unwrap();
        store.claim_selected(&z, &DefaultAction::None).unwrap();
        let retired = store.read().unwrap().unwrap();
        assert!(retired.lookup(&x.key).unwrap().is_none(), "X is retired");
        assert_eq!(retired.sequence, Some(6));
        let live_max = retired
            .pins
            .iter()
            .map(|record| record.revision)
            .max()
            .unwrap();
        assert!(
            live_max < consumed.revision.0,
            "the high-water outlived the record: {live_max} < {}",
            consumed.revision.0
        );
        // Reinserting the same digest draws a token above the retired one.
        store
            .commit_pin(&x, &Approval::initial(&x), DefaultAction::None)
            .unwrap();
        let reinserted = store.lookup(&x.key).unwrap().unwrap();
        assert_eq!(
            reinserted.revision,
            PinRevision(7),
            "the persisted sequence, not the live maximum, allocates"
        );
        // The suspended operation's predecessor is stale, with the peer bytes
        // untouched.
        let before = std::fs::read(store.record()).unwrap();
        let error = match store.claim_selected(&consumed, &DefaultAction::None) {
            Err(error) => error,
            Ok(_) => panic!("the retired lifetime still satisfies the old tuple"),
        };
        assert!(error.to_string().contains("stale"), "{error}");
        assert_eq!(std::fs::read(store.record()).unwrap(), before);
    }

    /// AC23: every real save advances the global sequence; metadata-only saves
    /// keep approval tokens; no-ops persist nothing.
    #[test]
    fn sequence_allocates_across_keys_and_metadata_saves() {
        let project = project();
        let (_dir, store) = paths();
        let a = candidate_at(&project, "example.com/a:tag", 'a');
        let first = store
            .claim_pin(
                &a,
                &Approval::initial(&a),
                DefaultAction::None,
                Role::Output,
            )
            .unwrap();
        assert_eq!(first.revision, PinRevision(1));
        assert_eq!(store.read().unwrap().unwrap().sequence, Some(1));
        // A content replacement on another key draws the next allocation.
        let b = candidate_at(&project, "example.com/b:tag", 'b');
        let b_pin = store
            .commit_pin(&b, &Approval::initial(&b), DefaultAction::None)
            .unwrap();
        assert_eq!(b_pin.revision, PinRevision(2));
        // A metadata-only Boot claim advances the sequence but not the token.
        // B was inserted unheld in a scope that already resolved Output, so
        // resolving Boot retires it as known-inactive: its allocation (2) stays
        // consumed, which is exactly why the high-water must persist.
        let a = store.lookup(&a.key).unwrap().unwrap();
        store.claim_selected(&a, &DefaultAction::None).unwrap();
        let file = store.read().unwrap().unwrap();
        assert_eq!(file.sequence, Some(3));
        assert_eq!(
            file.lookup(&a.key).unwrap().unwrap().revision,
            PinRevision(1)
        );
        assert!(file.lookup(&b.key).unwrap().is_none());
        assert_eq!(file.pins.len(), 1);
        // A complete no-op consumes no allocation and writes nothing.
        let bytes = std::fs::read(store.record()).unwrap();
        let a = store.lookup(&a.key).unwrap().unwrap();
        store.claim_selected(&a, &DefaultAction::None).unwrap();
        assert_eq!(std::fs::read(store.record()).unwrap(), bytes);
        // A failed save consumes nothing either.
        let mut over = store.read().unwrap().unwrap();
        over.sequence = Some(u64::MAX);
        store.save(&over.encode().unwrap()).unwrap();
        let exhausted = std::fs::read(store.record()).unwrap();
        let c = candidate_at(&project, "example.com/c:tag", 'c');
        assert!(
            store
                .commit_pin(&c, &Approval::initial(&c), DefaultAction::None)
                .is_err()
        );
        assert_eq!(std::fs::read(store.record()).unwrap(), exhausted);
    }

    /// AC12/R9: the effective high-water of an old file is its highest live
    /// revision, read without a write; the next real save allocates above it.
    #[test]
    fn missing_sequence_uses_max_live_revision_without_write() {
        let project = project();
        let bytes = old_v2_bytes(vec![
            old_v2_record(&project, "example.com/a:tag", 'a', 2),
            old_v2_record(&project, "example.com/b:tag", 'b', 7),
        ]);
        let (_dir, store) = paths();
        install_raw(&store, &bytes);
        let file = store.read().unwrap().unwrap();
        assert_eq!(file.sequence, None);
        assert_eq!(file.effective_sequence(), 7);
        assert_eq!(std::fs::read(store.record()).unwrap(), bytes);
        let c = candidate_at(&project, "example.com/c:tag", 'c');
        let pin = store
            .commit_pin(&c, &Approval::initial(&c), DefaultAction::None)
            .unwrap();
        assert_eq!(pin.revision, PinRevision(8));
        assert_eq!(store.read().unwrap().unwrap().sequence, Some(8));
    }

    /// AC17/AC23: mutating recovery preserves roles and resolution, allocates a
    /// sequence, and only then rewrites the host record.
    #[test]
    fn recovery_allocates_and_preserves_roles() {
        let project = project();
        let x_ref = "example.com/x:tag";
        let previous = String::from_utf8(default_bytes('a')).unwrap();
        let proposed = String::from_utf8(default_bytes('b')).unwrap();
        let file = PinFile {
            version: STORE_VERSION,
            pins: vec![pin_record(&project, x_ref, 'a', 1, Some(RoleMask::BOOT))],
            pending_default: Some(PendingDefault {
                previous: Some(previous.clone()),
                proposed: proposed.clone(),
            }),
            defaults: Vec::new(),
            scopes: vec![scope_record(&project, RoleMask::BOOT)],
            sequence: Some(1),
        };
        let (_dir, store) = paths();
        install(&store, &file);
        std::fs::write(store.directory.join(SELECTION_FILE), &proposed).unwrap();
        // Any mutating begin recovers first.
        let c = candidate_at(&project, "example.com/c:tag", 'c');
        store
            .commit_pin(&c, &Approval::initial(&c), DefaultAction::None)
            .unwrap();
        let after = store.read().unwrap().unwrap();
        assert!(after.pending_default.is_none());
        assert_eq!(
            std::fs::read_to_string(store.directory.join(SELECTION_FILE)).unwrap(),
            previous
        );
        assert_eq!(roles_of(&after, x_ref), Some(RoleMask::BOOT));
        assert_eq!(resolved_of(&after, &project), Some(RoleMask::BOOT));
        // Recovery allocated one sequence; the following insert another.
        assert_eq!(after.sequence, Some(3));
        assert_eq!(
            after
                .lookup(&candidate_at(&project, "example.com/c:tag", 'c').key)
                .unwrap()
                .unwrap()
                .revision,
            PinRevision(3)
        );
    }

    // ---------------------------------------------------------------------
    // AC11a-d: four independent capacity fixtures. Count, bytes, scopes and
    // sequence are different budgets; no fixture stands in for another.
    // ---------------------------------------------------------------------

    fn project_at(index: u32) -> ProjectId {
        ProjectId::parse(&format!("{index:064x}")).expect("a formatted project id")
    }
    fn foreign_pin(index: u32, roles: Option<RoleMask>) -> PinRecord {
        pin_record(&project_at(index), "example.com/foreign:tag", 'b', 1, roles)
    }
    fn full_error(error: &anyhow::Error) {
        let message = error.to_string();
        assert!(message.contains("maximum number of approvals"), "{message}");
        assert!(!message.contains("damaged"), "{message}");
    }

    /// AC11a: 4096 pins where X holds both slots. A new publication keeps X's
    /// Boot, so it cannot retire and the final 4097th record is refused as full.
    #[test]
    fn full_count_output_also_boot_cannot_retire() {
        let project = project();
        let x_ref = "example.com/x:tag";
        let mut pins = vec![pin_record(
            &project,
            x_ref,
            'a',
            1,
            Some(RoleMask::BOOT_AND_OUTPUT),
        )];
        pins.extend((0..4095).map(|index| foreign_pin(index, None)));
        let file = PinFile {
            version: STORE_VERSION,
            pins,
            pending_default: None,
            defaults: Vec::new(),
            scopes: vec![scope_record(&project, RoleMask::BOOT_AND_OUTPUT)],
            sequence: Some(1),
        };
        let bytes = file.encode().unwrap();
        assert!(bytes.len() < MAX_BYTES as usize);
        let (_dir, store) = paths();
        install_raw(&store, &bytes);
        let y = candidate_at(&project, "example.com/y:tag", 'c');
        let error = store
            .claim_pin(
                &y,
                &Approval::initial(&y),
                DefaultAction::None,
                Role::Output,
            )
            .unwrap_err();
        full_error(&error);
        assert_eq!(std::fs::read(store.record()).unwrap(), bytes);
        let after = store.read().unwrap().unwrap();
        assert_eq!(after.pins.len(), 4096);
        assert!(
            after.lookup(&y.key).unwrap().is_none(),
            "no Y pin was written"
        );
        assert_eq!(roles_of(&after, x_ref), Some(RoleMask::BOOT_AND_OUTPUT));
    }

    /// AC11b: the same full count, but X is only the Output holder, so a new
    /// publication retires it and the final state is exactly 4096 pins.
    #[test]
    fn final_state_retirement_at_full_count_succeeds() {
        let project = project();
        let b_ref = "example.com/b:tag";
        let x_ref = "example.com/x:tag";
        let mut pins = vec![
            pin_record(&project, b_ref, 'a', 1, Some(RoleMask::BOOT)),
            pin_record(&project, x_ref, 'b', 2, Some(RoleMask::OUTPUT)),
        ];
        pins.extend((0..4094).map(|index| foreign_pin(index, None)));
        let file = PinFile {
            version: STORE_VERSION,
            pins,
            pending_default: None,
            defaults: Vec::new(),
            scopes: vec![scope_record(&project, RoleMask::BOOT_AND_OUTPUT)],
            sequence: Some(2),
        };
        let bytes = file.encode().unwrap();
        assert!(bytes.len() < MAX_BYTES as usize);
        let (_dir, store) = paths();
        install_raw(&store, &bytes);
        let y = candidate_at(&project, "example.com/y:tag", 'c');
        store
            .claim_pin(
                &y,
                &Approval::initial(&y),
                DefaultAction::None,
                Role::Output,
            )
            .unwrap();
        let after = store.read().unwrap().unwrap();
        let x = candidate_at(&project, x_ref, 'b');
        assert_eq!(after.pins.len(), 4096);
        assert!(after.lookup(&x.key).unwrap().is_none(), "X retired");
        assert_eq!(roles_of(&after, b_ref), Some(RoleMask::BOOT));
        assert_eq!(
            roles_of(&after, "example.com/y:tag"),
            Some(RoleMask::OUTPUT)
        );
        assert_eq!(after.sequence, Some(3));
        // The Boot holder's approval tuple is untouched.
        assert_eq!(
            after
                .lookup(&candidate_at(&project, b_ref, 'a').key)
                .unwrap()
                .unwrap()
                .revision,
            PinRevision(1)
        );
    }

    /// AC11c: a valid store at 4 MiB - 1 where a metadata-only Output claim adds
    /// holder/resolution bytes. The proposed final state is full, not damage,
    /// and the old bytes stay.
    #[test]
    fn metadata_role_resolution_exceeds_shared_byte_bound() {
        const DEFAULT_IMAGE_MIN: usize = 89; // docker.io/library/alpine@sha256:<64>
        let project = project();
        let x_ref = "example.com/x:tag";
        let revision = 999_999_999_999_999_999u64;
        let mut pins = vec![pin_record(
            &project,
            x_ref,
            'a',
            revision,
            Some(RoleMask::BOOT),
        )];
        let variant = Some("v".repeat(64));
        // The target's own platform stays native: `candidate_at` builds its key
        // from the measured host platform (no variant), so a variant-bearing
        // target would be *inserted* as a second record instead of claimed. The
        // variant padding therefore lives on the foreign records only, which is
        // how this fixture reaches the metadata-only path at all.
        let mut scopes = vec![scope_record(&project, RoleMask::BOOT)];
        // Start from the largest legal encoding: a 270-byte reference, a 64-byte
        // variant and an 18-digit token per pin, and a 270-byte digest reference
        // per default. Then shorten references by the exact excess, because a
        // reference byte is one encoded byte (no escaping).
        for index in 0..4094u32 {
            let p = project_at(index);
            let mut record =
                pin_record(&p, "example.com/y:tag", 'b', revision, Some(RoleMask::BOOT));
            record.reference = reference_of_length(270);
            record.platform.variant = variant.clone();
            pins.push(record);
            scopes.push(scope_record_with(&p, RoleMask::BOOT, variant.clone()));
        }
        let defaults = (0..4096u32)
            .map(|index| ProjectDefaultRecord {
                project: format!("{index:064x}"),
                image: digest_reference_of_length(270),
            })
            .collect();
        let mut file = PinFile {
            version: STORE_VERSION,
            pins,
            pending_default: None,
            defaults,
            scopes,
            sequence: Some(revision),
        };
        assert_eq!(file.pins.len(), 4095);
        assert_eq!(file.defaults.len(), 4096);
        assert_eq!(file.scopes.len(), 4095);
        let target = MAX_BYTES as usize - 1;
        // Measured without the bound check: the maximal shape may exceed it.
        let base = serde_json::to_vec(&file).unwrap().len();
        assert!(
            base >= target,
            "the fixture must reach the byte bound: only {base} of {target} bytes"
        );
        let mut excess = base - target;
        // The target's own reference stays fixed: it is the claim's key.
        for record in file.pins.iter_mut().skip(1) {
            if excess == 0 {
                break;
            }
            let floor = "example.com/x:tag".len();
            let take = excess.min(record.reference.len() - floor);
            record.reference = reference_of_length(record.reference.len() - take);
            excess -= take;
        }
        for record in file.defaults.iter_mut() {
            if excess == 0 {
                break;
            }
            let take = excess.min(record.image.len() - DEFAULT_IMAGE_MIN);
            record.image = digest_reference_of_length(record.image.len() - take);
            excess -= take;
        }
        assert_eq!(excess, 0, "references alone have enough slack");
        let bytes = file.encode().expect("the fixture reaches the byte bound");
        assert_eq!(bytes.len(), target, "the builder reaches 4 MiB - 1 exactly");
        let (_dir, store) = paths();
        install_raw(&store, &bytes);
        assert!(
            store.read().unwrap().is_some(),
            "the real decoder accepts it"
        );
        let x = candidate_at(&project, x_ref, 'a');
        // The claim's key *is* the existing record's key: this row is a
        // metadata-only claim, never an insertion.
        assert!(
            store.lookup(&x.key).unwrap().is_some(),
            "the claim targets the existing Boot holder"
        );
        // Only the three metadata fields this claim writes add bytes: the pin's
        // roles, the scope's resolution and the sequence's nineteenth digit.
        let mut proposed = file.clone();
        proposed.pins[0].roles = Some(RoleMask::BOOT_AND_OUTPUT);
        proposed.scopes[0].resolved = RoleMask::BOOT_AND_OUTPUT;
        proposed.sequence = Some(revision + 1);
        let proposed_len = serde_json::to_vec(&proposed).unwrap().len();
        // The pin's `roles` and the scope's `resolved` both grow from `boot` to
        // `boot-and-output`, and the sequence gains its nineteenth digit.
        let metadata_bytes = ("boot-and-output".len() - "boot".len()) * 2 + 1;
        assert_eq!(
            proposed_len,
            bytes.len() + metadata_bytes,
            "the claim adds role, resolution and sequence bytes and nothing else"
        );
        assert!(
            proposed_len > MAX_BYTES as usize,
            "the metadata alone crosses the shared byte bound: {proposed_len}"
        );
        let error = store
            .claim_pin(
                &x,
                &Approval::initial(&x),
                DefaultAction::None,
                Role::Output,
            )
            .unwrap_err();
        full_error(&error);
        assert_eq!(std::fs::read(store.record()).unwrap(), bytes);
        let after = store.read().unwrap().unwrap();
        assert_eq!(after.pins.len(), 4095, "no record was inserted");
        assert_eq!(roles_of(&after, x_ref), Some(RoleMask::BOOT));
        assert_eq!(after.scopes[0].resolved, RoleMask::BOOT);
        assert_eq!(after.scopes.len(), 4095);
    }

    /// A canonical `repo@sha256:…` of exactly `len` bytes.
    fn digest_reference_of_length(len: usize) -> String {
        let name_len = len - "example.com/".len() - "@sha256:".len() - 64;
        let reference = format!(
            "example.com/{}@sha256:{}",
            "a".repeat(name_len),
            "0".repeat(64)
        );
        assert_eq!(reference.len(), len);
        CanonicalOciReference::parse(&reference).expect("a legal digest reference");
        reference
    }

    /// A canonical reference of exactly `len` bytes, built from legal 50-byte
    /// path components so the parser's own rules are never bypassed.
    fn reference_of_length(len: usize) -> String {
        let name_len = len - "example.com/".len() - ":tag".len();
        let reference = format!("example.com/{}:tag", path_components(name_len));
        assert_eq!(reference.len(), len);
        reference
    }
    /// A repository path of exactly `len` bytes in 50-byte components. Many
    /// short components keep the OCI parser's own matching cheap; the fixture
    /// still never bypasses its grammar.
    fn path_components(name_len: usize) -> String {
        let mut name = String::new();
        while name.len() < name_len {
            if !name.is_empty() {
                name.push('/');
            }
            let take = (name_len - name.len()).min(50);
            name.push_str(&"a".repeat(take));
        }
        name
    }

    /// AC11d: 4096 small old-v2 records with both roles unresolved. A metadata
    /// claim on an existing target adds a role/scope/sequence but no pin, keeps
    /// every approval tuple and leaves Output unknown.
    #[test]
    fn full_count_metadata_only_first_claim_succeeds() {
        let project = project();
        let x_ref = "example.com/x:tag";
        let mut pins = vec![old_v2_record(&project, x_ref, 'a', 1)];
        for index in 0..4095u32 {
            pins.push(old_v2_record(
                &project_at(index),
                "example.com/y:tag",
                'b',
                1,
            ));
        }
        let bytes = old_v2_bytes(pins.clone());
        let (_dir, store) = paths();
        install_raw(&store, &bytes);
        let tuples = |file: &PinFile| -> Vec<(String, u64)> {
            let mut tuples: Vec<_> = file
                .pins
                .iter()
                .map(|record| (record.manifest_digest.clone(), record.revision))
                .collect();
            tuples.sort();
            tuples
        };
        let before = store.read().unwrap().unwrap();
        assert_eq!(before.pins.len(), 4096);
        assert_eq!(before.effective_sequence(), 1);
        let x = candidate_at(&project, x_ref, 'a');
        store
            .claim_pin(&x, &Approval::initial(&x), DefaultAction::None, Role::Boot)
            .unwrap();
        let after = store.read().unwrap().unwrap();
        assert_eq!(after.pins.len(), 4096, "no new pin was inserted");
        assert_eq!(tuples(&after), tuples(&before));
        assert_eq!(roles_of(&after, x_ref), Some(RoleMask::BOOT));
        assert_eq!(resolved_of(&after, &project), Some(RoleMask::BOOT));
        assert_eq!(after.sequence, Some(2));
        assert!(after.encode().unwrap().len() < MAX_BYTES as usize);
    }

    /// The strict refresh snapshot: only this project's exact host platform and
    /// variant are projected, the whole file is still validated (a malformed
    /// foreign role join is damage), and taking one reads without creating,
    /// rewriting or recovering anything.
    #[test]
    fn refresh_scope_snapshot_is_strict_read_only_and_scoped() {
        let (_dir, store) = paths();
        let scope = project().clone();
        let host = HostLinuxPlatform::host();

        // A missing authority is an empty snapshot and stays missing.
        let empty = store
            .refresh_scope(&ScopeKey::of(scope.clone(), host.clone()))
            .unwrap();
        assert!(empty.pins().is_empty());
        assert!(!store.record().exists(), "a snapshot creates no authority");
        assert!(!store.lock_path().exists(), "a snapshot creates no lock");

        // Two projects, two platforms, one variant difference, all in one file.
        let (mine, mine_ref) = selected('a');
        let (other_project, other_ref) = selected_in(&ProjectId::for_tests('b'), 'b');
        let mut foreign_platform = candidate('c');
        let mut variant = HostLinuxPlatform::host();
        variant.variant = Some("v8".to_owned());
        foreign_platform.key.platform = variant.clone();
        let mut f = PinFile::empty();
        f.pins.push(PinRecord {
            roles: Some(RoleMask::BOOT),
            ..PinRecord::of(&ApprovedPin {
                key: mine.key.clone(),
                digest: mine.digest.clone(),
                revision: PinRevision(1),
            })
        });
        f.scopes.push(ScopeRecord {
            project: scope.as_str().to_owned(),
            platform: host.clone(),
            resolved: RoleMask::BOOT,
        });
        f.sequence = Some(3);
        f.pins.push(PinRecord::of(&ApprovedPin {
            key: other_project.key.clone(),
            digest: other_project.digest.clone(),
            revision: PinRevision(2),
        }));
        f.pins.push(PinRecord::of(&ApprovedPin {
            key: foreign_platform.key.clone(),
            digest: foreign_platform.digest.clone(),
            revision: PinRevision(3),
        }));
        install(&store, &f);
        let bytes = std::fs::read(store.record()).unwrap();

        let snapshot = store
            .refresh_scope(&ScopeKey::of(scope.clone(), host.clone()))
            .unwrap();
        assert_eq!(snapshot.pins().len(), 1, "only this project/platform");
        assert_eq!(snapshot.pins()[0].pin.key.reference, mine.key.reference);
        assert_eq!(
            snapshot.pins()[0].held.map(HeldRoles::mask),
            Some(RoleMask::BOOT)
        );
        assert!(snapshot.has_held_target(&OciTarget::parse(mine_ref.as_str()).unwrap()));
        assert!(snapshot.covers_project(&scope));
        assert!(snapshot.covers_platform(&host));
        assert!(!snapshot.covers_platform(&variant));
        assert_eq!(snapshot.predecessor(&mine.key).unwrap().digest, mine.digest);
        assert!(
            snapshot.predecessor(&other_project.key).is_none(),
            "a foreign project's record is never projected"
        );
        assert!(
            !snapshot.has_held_target(&OciTarget::parse(other_ref.as_str()).unwrap()),
            "a foreign project's holder is not this scope's membership"
        );
        assert_eq!(
            std::fs::read(store.record()).unwrap(),
            bytes,
            "the snapshot never rewrites the authority"
        );

        // A malformed *foreign* role join is still damage: the whole authority is
        // decoded and validated before anything is projected.
        let mut damaged = f.clone();
        damaged.pins[1].roles = Some(RoleMask::BOOT);
        // Written as raw bytes: `encode` itself would refuse the damaged state.
        std::fs::write(store.record(), serde_json::to_vec(&damaged).unwrap()).unwrap();
        assert!(
            store.refresh_scope(&ScopeKey::of(scope, host)).is_err(),
            "a foreign record with a role outside its resolution is damage"
        );
    }

    /// The adoption decision matrix over the observed H tuple the frozen worklist
    /// carried: absent-then-absent inserts, an observed-but-vanished H is stale,
    /// a changed live H with a matching observation is an integrity failure, and
    /// a live equal candidate reconciles regardless of its revision.
    #[test]
    fn adoption_uses_the_observed_host_predecessor() {
        /// What H's record looks like under the pin lock when the save runs.
        #[derive(Clone, Copy, Debug)]
        enum Live {
            /// H was genuinely absent at planning and is still absent.
            Absent,
            /// H holds the candidate digest at an older revision.
            CandidateOlderRevision,
            /// H holds the candidate digest at the observed revision.
            CandidateSameRevision,
            /// H holds a different digest.
            DifferentDigest,
        }
        /// What the frozen worklist observed for H.
        #[derive(Clone, Copy, Debug)]
        enum Observed {
            Absent,
            Candidate,
        }

        let rows = [
            (Live::Absent, Observed::Absent, "insert"),
            (Live::Absent, Observed::Candidate, "stale"),
            (Live::CandidateSameRevision, Observed::Candidate, "already"),
            (Live::CandidateOlderRevision, Observed::Candidate, "already"),
            (Live::CandidateSameRevision, Observed::Absent, "already"),
            // A changed live H is a stale observation, not an integrity
            // failure: the frozen predecessor no longer exists.
            (Live::DifferentDigest, Observed::Candidate, "stale"),
            // A matching live observation whose immutable content differs can
            // only be an integrity failure (the identity itself moved).
            (Live::DifferentDigest, Observed::Absent, "integrity"),
        ];
        for (live, observed, expected) in rows {
            let (_dir, store) = paths();
            let (host, reference_host) = selected('b');
            let expected_default = ProjectDefault::new(&project(), &reference_host).unwrap();
            let observed_pin = ApprovedPin {
                key: host.key.clone(),
                digest: host.digest.clone(),
                revision: PinRevision(2),
            };
            let mut f = PinFile::empty();
            f.set_project_default(expected_default.clone());
            let live_pin = match live {
                Live::Absent | Live::DifferentDigest => None,
                Live::CandidateOlderRevision => Some(ApprovedPin {
                    revision: PinRevision(1),
                    ..observed_pin.clone()
                }),
                Live::CandidateSameRevision => Some(observed_pin.clone()),
            };
            match (live, live_pin) {
                (_, Some(pin)) => f.pins.push(PinRecord::of(&pin)),
                (Live::DifferentDigest, None) => f.pins.push(PinRecord::of(&ApprovedPin {
                    key: host.key.clone(),
                    digest: ManifestDigest::parse(&format!("sha256:{}", "c".repeat(64))).unwrap(),
                    revision: PinRevision(1),
                })),
                _ => {}
            }
            f.sequence = Some(2);
            install(&store, &f);
            let bytes = std::fs::read(store.record()).unwrap();

            let observation = match observed {
                Observed::Absent => None,
                Observed::Candidate => Some(observed_pin.clone()),
            };
            let adoption = DefaultAdoption::new(
                expected_default.clone(),
                reference_host.clone(),
                &host,
                observation,
            );
            let outcome = store.adopt(&host, &adoption);
            match expected {
                "insert" => {
                    let committed = outcome.expect("a genuinely absent H may be inserted");
                    assert_eq!(
                        committed.value.project_default,
                        ProjectDefaultChange::Adopted
                    );
                    assert!(committed.value.previous.is_none(), "{live:?}/{observed:?}");
                    let file = store.read().unwrap().unwrap();
                    assert!(file.lookup(&host.key).unwrap().is_some());
                    assert_eq!(file.defaults[0].image, reference_host.as_str());
                }
                "already" => {
                    let committed = outcome.expect("a live equal candidate reconciles");
                    assert_eq!(
                        committed.value.pin.digest, host.digest,
                        "the live tuple is kept: {live:?}/{observed:?}"
                    );
                    assert_eq!(
                        committed.value.project_default,
                        ProjectDefaultChange::Adopted
                    );
                }
                "stale" => {
                    let error = outcome.err().expect("an observed H that vanished is stale");
                    assert!(
                        error
                            .to_string()
                            .contains("image approval is stale; retry the explicit operation"),
                        "{error}"
                    );
                    assert_eq!(
                        std::fs::read(store.record()).unwrap(),
                        bytes,
                        "a stale adoption writes nothing"
                    );
                }
                "integrity" => {
                    let error = outcome
                        .err()
                        .expect("a different immutable digest is an integrity failure");
                    assert!(error.to_string().contains("integrity failure"), "{error}");
                    assert_eq!(
                        std::fs::read(store.record()).unwrap(),
                        bytes,
                        "an integrity failure writes nothing"
                    );
                }
                other => panic!("unexpected row {other}"),
            }
        }
    }

    // ---------------------------------------------------------------------
    // ADR-0068 / #609: the two read-only projections of the authority.
    // ---------------------------------------------------------------------

    /// The messages are literals here, not `corrupt()`/`failure()`/`legacy()`
    /// calls: an oracle built from the production constructor would pass even if
    /// the two were swapped (plan §7's N1 literals).
    const N1_DAMAGED: &str = "image pin authority at $HOME/.config/agent-vm/image-pins.json is damaged; restore its intended records from backup or deliberately move it aside to reset approvals";
    const N1_ACCESS: &str = "image pin authority at $HOME/.config/agent-vm/image-pins.json could not be accessed or saved";
    const N1_V1: &str = "image pin authority at $HOME/.config/agent-vm/image-pins.json uses the host-wide version 1 format, which this agent-vm no longer reads: approvals are now per project. Archiving it resets approvals, and mutable tags may then resolve to newer content; see \"Upgrading from host-wide approvals\" in USAGE.md";
    const N1_MALFORMED: &[u8] = b"not json";

    /// `project_pins` returns a snapshot type without `Debug` on purpose, so
    /// `unwrap_err` is unavailable: extract the message without printing the
    /// value that must never be printable.
    #[track_caller]
    fn pins_error(store: &Store, project: &ProjectId) -> String {
        match store.project_pins(project) {
            Ok(_) => panic!("the projection must fail here"),
            Err(error) => error.to_string(),
        }
    }
    const N1_V1_BYTES: &[u8] = br#"{"version":1,"pins":[],"pending_default":null}"#;

    /// A lock that exists but is not the regular file the protocol requires.
    fn nonregular_lock(store: &Store, kind: &str, target: &Path) {
        std::fs::create_dir_all(&store.directory).unwrap();
        match kind {
            "symlink" => std::os::unix::fs::symlink(target, store.lock_path()).unwrap(),
            "directory" => std::fs::create_dir(store.lock_path()).unwrap(),
            "fifo" => fifo(&store.lock_path()),
            other => panic!("unexpected lock shape {other}"),
        }
    }

    /// The metadata the no-write oracle compares: type, mode and inode, plus a
    /// symlink's target. A read is allowed to touch atime, so it is excluded.
    fn shape(path: &Path) -> (u32, u32, u64, Option<PathBuf>) {
        use std::os::unix::fs::MetadataExt as _;
        let metadata = std::fs::symlink_metadata(path).unwrap();
        (
            metadata.mode(),
            u32::from(metadata.file_type().is_symlink()),
            metadata.ino(),
            std::fs::read_link(path).ok(),
        )
    }

    /// One directory listing, sorted: the inventory a projection must not change.
    fn inventory(directory: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// AC5: both helpers classify without I/O beyond `symlink_metadata`, and the
    /// existence rule deliberately does *not* decide lock shape.
    #[test]
    fn presentation_lock_helpers_classify_without_io_side_effects() {
        // (record present, lock shape, the helper's answer) — a present
        // non-regular lock still exists, so the shape is not this helper's
        // question, and its returned "record present" fact is what scopes the
        // shape rule to a present authority.
        for (record, lock, ok) in [
            (false, None, true),
            (false, Some("directory"), true),
            (true, None, false),
            (true, Some("regular"), true),
            (true, Some("directory"), true),
            (true, Some("symlink"), true),
            (true, Some("fifo"), true),
        ] {
            let (dir, store) = paths();
            std::fs::create_dir_all(&store.directory).unwrap();
            if record {
                std::fs::write(store.record(), file().encode().unwrap()).unwrap();
            }
            match lock {
                None => {}
                Some("regular") => {
                    std::fs::write(store.lock_path(), b"").unwrap();
                }
                Some(kind) => nonregular_lock(&store, kind, &dir.path().join("absent")),
            }
            let before = inventory(&store.directory);
            let lock_before = std::fs::symlink_metadata(store.lock_path())
                .ok()
                .map(|_| shape(&store.lock_path()));
            let outcome = store.require_lock_present_for_record();
            match (ok, outcome) {
                (true, Ok(present)) => assert_eq!(present, record, "record={record} lock={lock:?}"),
                (false, Err(error)) => assert_eq!(error.to_string(), N1_DAMAGED),
                (_, other) => panic!("record={record} lock={lock:?}: {other:?}"),
            }
            assert_eq!(
                inventory(&store.directory),
                before,
                "a metadata-only check creates nothing"
            );
            assert_eq!(
                std::fs::symlink_metadata(store.lock_path())
                    .ok()
                    .map(|_| shape(&store.lock_path())),
                lock_before,
                "a metadata-only check leaves the lock as it found it"
            );
        }

        // The shape mapping, including the branches a privileged test host
        // cannot reach through the filesystem at all.
        let (_dir, store) = paths();
        std::fs::create_dir_all(&store.directory).unwrap();
        std::fs::write(store.lock_path(), b"").unwrap();
        let file_type = std::fs::symlink_metadata(store.lock_path())
            .unwrap()
            .file_type();
        assert!(lock_shape(Ok(file_type)).is_ok());
        let (other_dir, other_store) = paths();
        nonregular_lock(&other_store, "directory", &other_dir.path().join("absent"));
        let directory = std::fs::symlink_metadata(other_store.lock_path())
            .unwrap()
            .file_type();
        assert_eq!(
            lock_shape(Ok(directory)).unwrap_err().to_string(),
            N1_ACCESS
        );
        assert!(lock_shape(Err(ErrorKind::NotFound)).is_ok());
        for kind in [
            ErrorKind::PermissionDenied,
            ErrorKind::InvalidInput,
            ErrorKind::Other,
        ] {
            assert_eq!(
                lock_shape(Err(kind)).unwrap_err().to_string(),
                N1_ACCESS,
                "{kind:?}"
            );
        }
    }

    /// AC5/N1: the shared existence rule must not reorder either transaction
    /// path. `begin` keeps read-before-shape (so malformed bytes and a v1 file
    /// keep their own messages), while the observer's `open_lock` fails the
    /// relationship first.
    #[test]
    fn presentation_diagnostic_order_is_preserved_for_begin_and_observe() {
        for (bytes, begin_message) in [(N1_MALFORMED, N1_DAMAGED), (N1_V1_BYTES, N1_V1)] {
            let (dir, store) = paths();
            std::fs::create_dir_all(&store.directory).unwrap();
            std::fs::write(store.record(), bytes).unwrap();
            nonregular_lock(&store, "directory", &dir.path().join("absent"));
            let lock_before = shape(&store.lock_path());

            let error = store
                .begin(false)
                .err()
                .expect("a directory lock must fail the transaction");
            assert_eq!(error.to_string(), begin_message);

            let error = store
                .observe_slot_independently(HostRead::Never)
                .err()
                .expect("the observer fails access before it reads");
            assert_eq!(error.to_string(), N1_ACCESS);

            assert_eq!(std::fs::read(store.record()).unwrap(), bytes);
            assert_eq!(shape(&store.lock_path()), lock_before);
            assert!(
                store.lock_path().is_dir(),
                "no path replaces the coordination file"
            );
        }
    }

    /// AC5: the lock-free projection refuses a lockless authority with the damage
    /// message, and an unusable lock with the access message — never the other
    /// way round, which is what reading before the shape check would produce.
    #[test]
    fn presentation_snapshot_rejects_missing_or_nonregular_lock_without_creating_it() {
        let (_dir, store) = paths();
        let fixture = file();
        install(&store, &fixture);
        let bytes = std::fs::read(store.record()).unwrap();
        std::fs::remove_file(store.lock_path()).unwrap();

        assert_eq!(pins_error(&store, &project()), N1_DAMAGED);
        assert!(
            !store.lock_path().exists(),
            "a failed projection creates no lock"
        );
        assert_eq!(std::fs::read(store.record()).unwrap(), bytes);

        for (kind, target) in [
            ("symlink", Some("absent")),
            ("directory", None),
            ("fifo", None),
        ] {
            let (dir, store) = paths();
            install(&store, &fixture);
            std::fs::remove_file(store.lock_path()).unwrap();
            let target = target.map(|name| dir.path().join(name));
            match &target {
                Some(target) => nonregular_lock(&store, kind, target),
                None => nonregular_lock(&store, kind, &dir.path().join("absent")),
            }
            let lock_before = shape(&store.lock_path());
            assert_eq!(pins_error(&store, &project()), N1_ACCESS, "{kind}");
            assert_eq!(std::fs::read(store.record()).unwrap(), bytes, "{kind}");
            assert_eq!(shape(&store.lock_path()), lock_before, "{kind}");
            if let Some(target) = target {
                assert!(!target.exists(), "{kind} target untouched");
            }
        }

        // An absent record needs no coordination file at all: a stale
        // non-regular path there is not damage, and the projection is the same
        // empty snapshot an absent store produces (R4/AC1, D2).
        for kind in ["symlink", "directory", "fifo"] {
            let (dir, store) = paths();
            nonregular_lock(&store, kind, &dir.path().join("absent"));
            let lock_before = shape(&store.lock_path());
            let snapshot = store
                .project_pins(&project())
                .unwrap_or_else(|error| panic!("{kind}: {error}"));
            assert!(snapshot.pins.is_empty(), "{kind}");
            assert_eq!(snapshot.path, store.record(), "{kind}");
            assert!(
                !store.record().exists(),
                "{kind}: a projection never creates the record"
            );
            assert_eq!(shape(&store.lock_path()), lock_before, "{kind}");
        }

        // A present directory lock plus malformed bytes: the shape check runs
        // *before* the record read, so this is the access failure rather than
        // the damage the bytes would report.
        let (dir, store) = paths();
        std::fs::create_dir_all(&store.directory).unwrap();
        std::fs::write(store.record(), N1_MALFORMED).unwrap();
        nonregular_lock(&store, "directory", &dir.path().join("absent"));
        assert_eq!(pins_error(&store, &project()), N1_ACCESS);
    }

    /// AC9: the projection is a snapshot. An exclusive holder of the authority
    /// lock must not delay it — a call that went through `observe_slot` would
    /// wait `READ_WAIT` and fail instead of returning this snapshot.
    ///
    /// The wait is bounded externally and measured: a projection that blocks,
    /// or that merely pauses long enough to look lock-free in a final state,
    /// fails here instead of hanging the suite or passing on success alone.
    #[test]
    fn presentation_snapshot_does_not_wait_for_authority_lock() {
        const WAIT_BOUND: Duration = Duration::from_secs(10);
        const ELAPSED_BOUND: Duration = Duration::from_secs(5);
        let (_dir, store) = paths();
        let mut fixture = file();
        fixture.scopes = vec![scope_record(&project(), RoleMask::BOOT)];
        fixture.pins[0].set_roles(Some(HeldRoles::new(RoleMask::BOOT).unwrap()));
        fixture.sequence = Some(1);
        install(&store, &fixture);
        let bytes = std::fs::read(store.record()).unwrap();
        let lock_before = shape(&store.lock_path());

        let held = open_lock(&store.lock_path(), false).unwrap().unwrap();
        assert_eq!(
            host_paths::try_flock(&held, FlockMode::Exclusive).unwrap(),
            host_paths::FlockAttempt::Acquired,
            "this test must hold the authority EX"
        );

        // A detached worker, so a projection that blocks forever cannot keep the
        // test (or the suite) alive: the receive below decides.
        let directory = store.directory.clone();
        let project = project();
        let (sender, receiver) = std::sync::mpsc::channel();
        let started = Instant::now();
        let worker = std::thread::spawn(move || {
            let store = Store { directory };
            let result = store.project_pins(&project);
            let _ = sender.send(());
            result
        });
        match receiver.recv_timeout(WAIT_BOUND) {
            Ok(()) => {}
            Err(error) => panic!(
                "the projection did not return within {WAIT_BOUND:?} while an EX was held \
                 ({error:?}): a lock-free snapshot must not queue behind a writer"
            ),
        }
        let elapsed = started.elapsed();
        let snapshot = worker
            .join()
            .expect("the projection thread must not panic")
            .expect("a read-only projection does not queue behind a writer");
        assert!(
            elapsed < ELAPSED_BOUND,
            "the projection took {elapsed:?} while an EX was held; a lock-free snapshot reads \
             metadata and one bounded file, so {ELAPSED_BOUND:?} is already generous"
        );
        assert_eq!(snapshot.path, store.record());
        assert_eq!(snapshot.pins.len(), 1);
        assert_eq!(snapshot.pins[0].knowledge.boot, RoleKnowledge::Present);
        assert_eq!(snapshot.pins[0].knowledge.output, RoleKnowledge::Unknown);
        assert_eq!(std::fs::read(store.record()).unwrap(), bytes);
        assert_eq!(shape(&store.lock_path()), lock_before);
    }

    /// AC1/R1: the projection is the whole project across platforms, and a
    /// foreign project's records never appear.
    #[test]
    fn presentation_snapshot_projects_only_the_invoking_project() {
        let project = project();
        let other = ProjectId::for_tests('b');
        let mut fixture = file();
        fixture.pins = vec![
            pin_record(
                &project,
                "example.com/b:tag",
                'b',
                2,
                Some(RoleMask::OUTPUT),
            ),
            pin_record(&other, "example.com/c:tag", 'c', 3, Some(RoleMask::OUTPUT)),
            pin_record(&project, "example.com/a:tag", 'a', 1, Some(RoleMask::BOOT)),
        ];
        // Every resolved role needs exactly one holder in its own scope: the
        // whole file is validated before this projection filters anything.
        fixture.scopes = vec![
            scope_record(&project, RoleMask::BOOT_AND_OUTPUT),
            scope_record(&other, RoleMask::OUTPUT),
        ];
        fixture.sequence = Some(3);
        let (_dir, store) = paths();
        install(&store, &fixture);

        let snapshot = store.project_pins(&project).unwrap();
        let references: Vec<String> = snapshot
            .pins
            .iter()
            .map(|observed| observed.pin.key.reference.whole())
            .collect();
        assert_eq!(
            references,
            ["example.com/b:tag", "example.com/a:tag"],
            "file order, project filter: the listing sorts, the store does not"
        );
        assert_eq!(snapshot.pins[0].knowledge.boot, RoleKnowledge::Absent);
        assert_eq!(snapshot.pins[0].knowledge.output, RoleKnowledge::Present);
        assert_eq!(snapshot.pins[1].knowledge.boot, RoleKnowledge::Present);
        assert_eq!(snapshot.pins[1].knowledge.output, RoleKnowledge::Absent);
    }
}
