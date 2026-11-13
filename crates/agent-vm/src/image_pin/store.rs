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
use std::io::ErrorKind;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rustix::fs::{FileType, Mode, OFlags};

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
        }
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

impl PinFile {
    fn empty() -> Self {
        Self {
            version: STORE_VERSION,
            pins: Vec::new(),
            pending_default: None,
            defaults: Vec::new(),
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
        if !pin_count_within_limit(self.pins.len()) || !pin_count_within_limit(self.defaults.len())
        {
            return Err(corrupt());
        }
        let mut keys = BTreeSet::new();
        let mut projects = BTreeSet::new();
        // One uniqueness fact covers both record kinds: a pin is unique by its
        // whole key, a project default by its project.
        let mut unique = true;
        for record in &self.pins {
            record.validated()?;
            unique &= keys.insert((
                record.project.clone(),
                record.reference.clone(),
                record.platform.os.clone(),
                record.platform.architecture.clone(),
                record.platform.variant.clone(),
            ));
        }
        for record in &self.defaults {
            record.validated()?;
            unique &= projects.insert(record.project.clone());
        }
        if !schema_is_acceptable(self.version, unique) {
            return Err(corrupt());
        }
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
    anyhow!(
        "image pin authority at $HOME/.config/agent-vm/image-pins.json holds the maximum \
         number of approvals it can store (the record or byte bound), so nothing was approved; \
         archive it to reset approvals"
    )
}
fn failure() -> anyhow::Error {
    anyhow!(
        "image pin authority at $HOME/.config/agent-vm/image-pins.json could not be accessed or saved"
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
            let record_present = exists(&self.record())?;
            if exists(&self.lock_path())? {
                if Instant::now() >= deadline {
                    return Err(anyhow!("image pin observation timed out"));
                }
                continue;
            }
            if record_present {
                return Err(corrupt());
            }
            return Ok((PinFile::empty(), physical));
        }
    }
    pub(super) fn lookup(&self, key: &PinKey) -> Result<Option<ApprovedPin>> {
        self.observe_slot(HostRead::Never)?.0.lookup(key)
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
        if exists(&self.record())? && !exists(&self.lock_path())? {
            return Err(corrupt());
        }
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

    pub(super) fn commit(
        &self,
        candidate: &ValidatedCandidate,
        approval: &Approval,
        action: DefaultAction,
    ) -> Result<Committed> {
        if let Some(reference) = action.retained_reference() {
            self.adoption_binds(&candidate.key, reference)?;
        }
        let touch_host = action.initializes_host();
        let (old, _locks) = self.begin(touch_host)?;
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
        let pin = match decision {
            CommitDecision::AlreadyApproved => current.ok_or_else(failure)?,
            CommitDecision::Insert => ApprovedPin {
                key: candidate.key.clone(),
                digest: candidate.digest.clone(),
                revision: PinRevision(1),
            },
            CommitDecision::Replace => ApprovedPin {
                key: candidate.key.clone(),
                digest: candidate.digest.clone(),
                revision: PinRevision(
                    current
                        .as_ref()
                        .ok_or_else(failure)?
                        .revision
                        .0
                        .checked_add(1)
                        .ok_or_else(|| anyhow!("image pin revision is exhausted"))?,
                ),
            },
            CommitDecision::Conflict => {
                return Err(anyhow!(
                    "image approval is stale; retry the explicit operation"
                ));
            }
        };
        let mut new = old.clone();
        if decision != CommitDecision::AlreadyApproved {
            // A record that cannot be re-validated is a hard error, not
            // something to drop from the next write.
            let mut kept = Vec::with_capacity(new.pins.len());
            for record in &new.pins {
                if record.validated()?.key != pin.key {
                    kept.push(record.clone());
                }
            }
            new.pins = kept;
            new.pins.push(PinRecord::of(&pin));
        }
        let project_default = Self::establish_in(&mut new, &old, &candidate.key.project, &action)?;
        let final_bytes = new.encode()?; // every future byte checked before the first write
        // Host first: "host seeded, project not yet established" is a state the
        // next default-tier use completes (ADR-0067 narrows ADR-0047's
        // failed-operation guarantee to allow exactly this).
        self.seed_host_if_absent(&action)?;
        if decision != CommitDecision::AlreadyApproved
            || project_default != ProjectDefaultChange::Unchanged
        {
            gate::checkpoint(gate::Stage::BeforePinSave)?;
            self.save(&final_bytes)?;
        }
        gate::checkpoint(gate::Stage::PinCommitted)?;
        Ok(Committed {
            pin,
            project_default,
        })
    }

    /// The write-once establishment that belongs with **every** successful
    /// default-tier preparation, not only a first pin.
    ///
    /// A default-tier selection whose key is already approved (an explicit
    /// `image refresh` pins without establishing) still establishes the project,
    /// while an established project is left byte-for-byte alone and takes no
    /// exclusive lock.
    pub(super) fn establish_default_if_absent(
        &self,
        key: &PinKey,
        action: &DefaultAction,
    ) -> Result<ProjectDefaultChange> {
        let Some(reference) = action.retained_reference() else {
            return Ok(ProjectDefaultChange::Unchanged);
        };
        self.adoption_binds(key, reference)?;
        // A warm launch of an established project must not create locks or
        // recover an interrupted writer's journal.
        let (file, _logical) = self.observe_slot(HostRead::Never)?;
        let established = file.project_default(&key.project)?.is_some();
        let host_present =
            !action.initializes_host() || default::snapshot_at(&self.directory)?.is_some();
        if established && host_present {
            return Ok(ProjectDefaultChange::Unchanged);
        }
        let (old, _locks) = self.begin(action.initializes_host())?;
        let mut new = old.clone();
        let change = Self::establish_in(&mut new, &old, &key.project, action)?;
        let final_bytes = new.encode()?;
        self.seed_host_if_absent(action)?;
        if change != ProjectDefaultChange::Unchanged {
            gate::checkpoint(gate::Stage::BeforePinSave)?;
            self.save(&final_bytes)?;
            gate::checkpoint(gate::Stage::PinCommitted)?;
        }
        Ok(change)
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
    ) -> Result<Committed> {
        adoption.binds(candidate)?;
        let (old, _locks) = self.begin(false)?;
        if old.project_default(adoption.expected().project())?.as_ref() != Some(adoption.expected())
        {
            return Err(anyhow!(
                "image approval is stale; retry the explicit operation"
            ));
        }
        // The proposed key is immutable, so the proved decision has only three
        // legitimate outcomes: a first pin, the same digest, or integrity
        // failure. Reuse it with first-pin facts.
        let current = old.lookup(&candidate.key)?;
        let decision = commit_decision(CommitFacts {
            current_present: current.is_some(),
            expected_present: false,
            candidate_equal: current
                .as_ref()
                .is_some_and(|pin| pin.digest == candidate.digest),
            predecessor_matches: false,
            mutable_source: candidate.key.reference.digest().is_none(),
            consent: false,
        });
        let pin = match decision {
            CommitDecision::AlreadyApproved => current.ok_or_else(failure)?,
            CommitDecision::Insert => ApprovedPin {
                key: candidate.key.clone(),
                digest: candidate.digest.clone(),
                revision: PinRevision(1),
            },
            _ => return Err(immutable_integrity_failure()),
        };
        let mut new = old.clone();
        if decision == CommitDecision::Insert {
            new.pins.push(PinRecord::of(&pin));
        }
        new.set_project_default(ProjectDefault::new(
            adoption.expected().project(),
            adoption.proposed(),
        )?);
        let bytes = new.encode()?;
        gate::checkpoint(gate::Stage::BeforePinSave)?;
        self.save(&bytes)?;
        gate::checkpoint(gate::Stage::PinCommitted)?;
        Ok(Committed {
            pin,
            project_default: ProjectDefaultChange::Adopted,
        })
    }

    /// `image set-default`: replace only the host's starting choice.
    ///
    /// Writes no pin and no project default. Reports whether the invoking
    /// project already boots the new host child, measured under the same pin
    /// lock as the write.
    pub(super) fn set_host_default(
        &self,
        retained: &ImmutableImageRef,
        project: &ProjectId,
    ) -> Result<HostDefaultSet> {
        // pin EX then default EX, and this is also where a leftover S1 journal
        // is recovered before the new bytes are measured.
        let (file, _locks) = self.begin(true)?;
        let previous = default::snapshot_at(&self.directory)?;
        let proposed = default::encode_snapshot(retained)?;
        let retained_default = if fallback_bytes_differ(&previous, &proposed)? {
            gate::checkpoint(gate::Stage::BeforeDefaultSave)?;
            atomic_save(&self.directory.join(SELECTION_FILE), &proposed)?;
            gate::checkpoint(gate::Stage::DefaultSaved)?;
            if previous.is_none() {
                DefaultChange::Initialized
            } else {
                DefaultChange::Replaced
            }
        } else {
            DefaultChange::Unchanged
        };
        let this_project = match file.project_default(project)? {
            None => InvokingProject::NotEstablished,
            Some(own) => {
                // The content this project boots: its approved child, else the
                // digest it states (only a hand-edited store has no pin).
                // A stored project default is always a canonical OCI reference,
                // so an unusable one is damage rather than a user-input error.
                let target = OciTarget::parse(own.immutable()?.as_str()).map_err(|_| corrupt())?;
                let key = PinKey::new(project, &target)?;
                let boots = match file.lookup(&key)? {
                    Some(pin) => pin.digest,
                    None => own.stated_digest(),
                };
                // R5 asks whether this project already boots the retained child:
                // the content, never which repository serves it. A mirror of the
                // same manifest is the same content.
                if boots == stated_digest(retained)? {
                    InvokingProject::AlreadyUses
                } else {
                    InvokingProject::KeepsItsOwn
                }
            }
        };
        Ok(HostDefaultSet {
            retained_default,
            this_project,
        })
    }

    /// Insert this project's default iff the action establishes and the project
    /// has none; `SeedHostOnly` and `None` never establish. Shared by `commit`
    /// and [`Self::establish_default_if_absent`] so the two cannot diverge.
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
            if let Some(previous) = &pending.previous {
                save(&self.directory.join(SELECTION_FILE), previous.as_bytes())
                    .map_err(|_| recovery_required())?;
            } else {
                self.write_default(None).map_err(|_| recovery_required())?;
            }
            let mut recovered = file.clone();
            recovered.pending_default = None;
            save(&self.record(), &recovered.encode()?).map_err(|_| recovery_required())?;
            *file = recovered;
        }
        Ok(())
    }
}

fn atomic_save(path: &Path, bytes: &[u8]) -> Result<()> {
    host_paths::atomic_write(path, bytes, 0o600).map_err(|_| failure())
}

/// Whether writing `proposed` would change the logical fallback. An equivalent
/// selection keeps the exact existing bytes, so it never rewrites the user's
/// formatting or a legacy spelling; a record that cannot be decoded here was
/// already validated by `snapshot_at`, so it is a hard error, not a change.
fn fallback_bytes_differ(previous: &Option<Vec<u8>>, proposed: &[u8]) -> Result<bool> {
    let Some(previous) = previous else {
        return Ok(true);
    };
    let previous = default::decode_snapshot(previous)?;
    let proposed = default::decode_snapshot(proposed)?;
    Ok(!same_canonical(previous.as_str(), proposed.as_str())?)
}

/// The digest one immutable reference states: the content half of R5's "already
/// uses it". `ImmutableImageRef::parse` already required a digest, so a reference
/// that states none is damage.
fn stated_digest(reference: &ImmutableImageRef) -> Result<ManifestDigest> {
    CanonicalOciReference::parse(reference.as_str())
        .ok()
        .and_then(|canonical| canonical.digest().cloned())
        .ok_or_else(corrupt)
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
    let result = host_paths::flock_within(lock, mode, remaining, |_| {
        if matches!(mode, FlockMode::Exclusive)
            && !*noticed
            && start.elapsed() + WRITE_WAIT.saturating_sub(remaining) >= Duration::from_secs(1)
        {
            eprintln!("Waiting for another agent-vm image approval operation...");
            *noticed = true;
        }
    })
    .map_err(|_| failure())?;
    if result == FlockWait::TimedOut {
        return Err(anyhow!("image pin authority lock timed out"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_pin::project_default::HostRetention;
    use std::os::unix::fs::PermissionsExt;

    /// The rows here assert the committed pin; the reported change set is
    /// covered by the CLI rows that print it.
    impl Store {
        fn commit_pin(
            &self,
            candidate: &ValidatedCandidate,
            approval: &Approval,
            action: DefaultAction,
        ) -> Result<ApprovedPin> {
            self.commit(candidate, approval, action)
                .map(|committed| committed.pin)
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
        let mut exhausted = store.read().unwrap().unwrap();
        exhausted.pins[0].revision = u64::MAX;
        store.save(&exhausted.encode().unwrap()).unwrap();
        let old = store.lookup(&a.key).unwrap().unwrap();
        assert!(
            store
                .commit_pin(&b, &replacement(&b, old), DefaultAction::None)
                .is_err()
        );
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

    /// Test 6: `image set-default` writes only the host record, keeps an
    /// equivalent spelling byte-for-byte, and reports what the invoking project
    /// boots from the same under-lock read.
    #[test]
    fn set_host_default_writes_only_the_host_record() {
        let (_dir, store) = paths();
        let a = candidate('a');
        store
            .commit_pin(&a, &Approval::initial(&a), DefaultAction::None)
            .unwrap();
        let pins = std::fs::read(store.record()).unwrap();
        let outcome = store.set_host_default(&child('b'), &project()).unwrap();
        assert_eq!(outcome.retained_default, DefaultChange::Initialized);
        assert_eq!(outcome.this_project, InvokingProject::NotEstablished);
        assert!(
            store.read().unwrap().unwrap().pending_default.is_none(),
            "AC12: set-default's host save commits no journal"
        );
        assert_eq!(
            std::fs::read(store.record()).unwrap(),
            pins,
            "no pin written"
        );
        assert_eq!(host_reference(&store).unwrap(), child('b').as_str());

        // An established project that boots other content keeps its own default,
        // and nothing about the project's record changes.
        let (selected_a, reference_a) = selected('a');
        store
            .commit(
                &selected_a,
                &Approval::initial(&selected_a),
                establish(&reference_a, HostRetention::Keep),
            )
            .unwrap();
        let pins = std::fs::read(store.record()).unwrap();
        let outcome = store.set_host_default(&child('c'), &project()).unwrap();
        assert_eq!(outcome.retained_default, DefaultChange::Replaced);
        assert_eq!(outcome.this_project, InvokingProject::KeepsItsOwn);
        assert_eq!(std::fs::read(store.record()).unwrap(), pins);
        assert_eq!(host_reference(&store).unwrap(), child('c').as_str());
        assert_eq!(
            defaults_of(&store)[0].reference().whole(),
            reference_a.as_str()
        );

        // An index default whose approved child is the new host child already
        // uses it, even though it boots a different reference.
        let other_project = ProjectId::for_tests('b');
        let (index, reference_index) = selected_in(&other_project, 'd');
        store
            .commit(
                &index,
                &Approval::initial(&index),
                establish(&reference_index, HostRetention::Keep),
            )
            .unwrap();
        let outcome = store.set_host_default(&child('d'), &other_project).unwrap();
        assert_eq!(outcome.this_project, InvokingProject::AlreadyUses);

        // The same booted child served by another repository is still "already
        // uses it" (R5): the disposition compares content, not repository
        // identity, so a mirror of the manifest does not read as different
        // content.
        let mirrored_project = ProjectId::for_tests('c');
        let elsewhere =
            ImmutableImageRef::parse(&format!("ghcr.io/example/mirror@sha256:{}", "e".repeat(64)))
                .unwrap();
        let mut mirrored = candidate_in(&mirrored_project, 'e');
        mirrored.key.reference = CanonicalOciReference::parse(elsewhere.as_str()).unwrap();
        store
            .commit(
                &mirrored,
                &Approval::initial(&mirrored),
                establish(&elsewhere, HostRetention::Keep),
            )
            .unwrap();
        let outcome = store
            .set_host_default(&child('e'), &mirrored_project)
            .unwrap();
        assert_eq!(
            outcome.this_project,
            InvokingProject::AlreadyUses,
            "same content in another repository already boots"
        );

        // A semantically identical record preserves the user's exact bytes,
        // including a legacy spelling.
        let hand = format!(
            "{{ \"image\": \"alpine@sha256:{}\", \"version\": 1 }}\n",
            "c".repeat(64)
        )
        .into_bytes();
        std::fs::write(store.directory.join(SELECTION_FILE), &hand).unwrap();
        let outcome = store.set_host_default(&child('c'), &project()).unwrap();
        assert_eq!(outcome.retained_default, DefaultChange::Unchanged);
        assert_eq!(host_default(&store).unwrap(), hand);
        for path in [
            store.record(),
            store.lock_path(),
            store.directory.join(SELECTION_FILE),
            store.directory.join(DEFAULT_LOCK_FILE),
        ] {
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    /// Test 7: a leftover S1 journal is recovered by the next write, so
    /// set-default's host save never stacks on an unrecovered transaction.
    #[test]
    fn set_host_default_recovers_an_s1_journal_before_writing() {
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

        let outcome = store.set_host_default(&child('c'), &project()).unwrap();
        assert_eq!(outcome.retained_default, DefaultChange::Replaced);
        assert!(store.read().unwrap().unwrap().pending_default.is_none());
        assert_eq!(host_reference(&store).unwrap(), child('c').as_str());
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
                .commit(&c, &Approval::initial(&c), establish(&reference, host))
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
            .commit(
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
            .commit(
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
            .commit(
                &a,
                &Approval::initial(&a),
                establish(&reference_a, HostRetention::Keep),
            )
            .unwrap();
        let (b, reference_b) = selected('b');
        let committed = store
            .commit(
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
            .commit(
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
            .commit(
                &c,
                &Approval::initial(&c),
                establish(&reference, HostRetention::Keep),
            )
            .unwrap();
        let record = store.record();
        let pins = std::fs::read(&record).unwrap();
        let bars = std::fs::read(store.lock_path()).unwrap();
        assert_eq!(
            store
                .establish_default_if_absent(&c.key, &establish(&reference, HostRetention::Keep))
                .unwrap(),
            ProjectDefaultChange::Unchanged
        );
        assert_eq!(std::fs::read(&record).unwrap(), pins);
        assert_eq!(std::fs::read(store.lock_path()).unwrap(), bars);
        // A reference that does not bind this key's own source is refused.
        let unrelated = child('b');
        assert!(
            store
                .establish_default_if_absent(&c.key, &establish(&unrelated, HostRetention::Keep))
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
        assert_eq!(
            store
                .establish_default_if_absent(
                    &c.key,
                    &establish(&reference, HostRetention::InitializeIfAbsent)
                )
                .unwrap(),
            ProjectDefaultChange::Established
        );
        assert_eq!(host_reference(&store).unwrap(), child('a').as_str());
        let bytes = std::fs::read(store.directory.join(SELECTION_FILE)).unwrap();
        assert_eq!(
            store
                .establish_default_if_absent(
                    &c.key,
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
                .establish_default_if_absent(
                    &c.key,
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
            .commit(
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
        let adoption = DefaultAdoption::new(expected.clone(), reference_host.clone(), &host);
        let committed = store.adopt(&host, &adoption).unwrap();
        assert_eq!(committed.project_default, ProjectDefaultChange::Adopted);
        let file = store.read().unwrap().unwrap();
        assert_eq!(file.defaults[0].image, reference_host.as_str());
        assert!(file.lookup(&host.key).unwrap().is_some());
        assert!(
            file.pending_default.is_none(),
            "AC12: adoption commits no journal"
        );
        let bytes = std::fs::read(store.record()).unwrap();

        // A second adoption against the default that was read is stale: the
        // candidate binds, but the project's default moved.
        drop(host);
        let (host, _) = selected('b');
        let stale = DefaultAdoption::new(expected, reference_host.clone(), &host);
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
        f.pins.push(PinRecord::of(&ApprovedPin {
            key: a.key.clone(),
            digest: ManifestDigest::parse(&format!("sha256:{}", "c".repeat(64))).unwrap(),
            revision: PinRevision(1),
        }));
        f.set_project_default(expected.clone());
        install(&store, &f);
        let bytes = std::fs::read(store.record()).unwrap();
        let mut proposed_candidate = candidate('b');
        proposed_candidate.key.reference =
            CanonicalOciReference::parse(reference_a.as_str()).unwrap();
        let adoption = DefaultAdoption::new(expected, reference_a.clone(), &proposed_candidate);
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
            .commit(
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
        // set-default takes pin EX then default EX, the one path that needs both.
        let error = store.set_host_default(&child('b'), &project()).unwrap_err();
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
        assert_eq!(
            (first.revision, second.revision),
            (PinRevision(1), PinRevision(1))
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
        assert_eq!(replaced.revision, PinRevision(2));
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
            store.set_host_default(&child('b'), &project()).unwrap_err(),
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
        template.revision = u64::MAX;
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
}
