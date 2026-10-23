//! Private strict schema and short, bounded HOME transactions.
//!
//! # Why the retained-default module is both a dependency and a caller
//!
//! `boot_image::default_selection` owns the fallback's v1 bytes
//! (`SELECTION_FILE`, `decode_snapshot`, `encode_snapshot`, `snapshot_at`) and
//! consults this module for the *logical* record, so the two modules name each
//! other. The cycle is acyclic where it matters: this module calls only the pure
//! byte-level helpers, never `load`, and `load` is the sole edge back into
//! `image_pin` — it reaches `Store::observe` and nothing else, so no transaction
//! can re-enter an observation and no lock is ever taken twice. Putting the
//! schema here instead would duplicate the fallback's format in the module that
//! must preserve a user's own bytes; putting the transaction there would move
//! approval into a module that knows only one tier.
use std::collections::BTreeSet;
use std::fs::{DirBuilder, File};
use std::io::ErrorKind;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rustix::fs::{FileType, Mode, OFlags};

use super::*;
use crate::boot_image::default_selection::{self as default, SELECTION_FILE};
use crate::config;
use crate::host_paths::{self, FlockMode, FlockWait};

const MAX_BYTES: u64 = 4 * 1024 * 1024;
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
        /// The candidate is acquired and validated but not yet approved.
        CandidateReady,
        BeforePinLock,
        PinLocked,
        BeforeIntentSave,
        IntentSaved,
        DefaultSaved,
        BeforePinSave,
        PinCommitted,
    }

    impl Stage {
        #[cfg(debug_assertions)]
        fn wire(self) -> &'static str {
            match self {
                Self::CandidateReady => "candidate-ready",
                Self::BeforePinLock => "before-pin-lock",
                Self::PinLocked => "pin-locked",
                Self::BeforeIntentSave => "before-intent-save",
                Self::IntentSaved => "intent-saved",
                Self::DefaultSaved => "default-saved",
                Self::BeforePinSave => "before-pin-save",
                Self::PinCommitted => "pin-committed",
            }
        }

        /// Only the stages immediately before a real write accept a fault.
        #[cfg(debug_assertions)]
        fn accepts_fault(self) -> bool {
            matches!(self, Self::BeforeIntentSave | Self::BeforePinSave)
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
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinRecord {
    reference: String,
    platform: HostLinuxPlatform,
    manifest_digest: String,
    revision: u64,
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
        let reference = CanonicalOciReference::parse(&self.reference).map_err(|_| corrupt())?;
        let digest = ManifestDigest::parse(&self.manifest_digest).map_err(|_| corrupt())?;
        if !pin_fields_are_acceptable(PinFieldFacts {
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
                reference,
                platform: self.platform.clone(),
            },
            digest,
            revision: PinRevision(self.revision),
        })
    }
    fn of(pin: &ApprovedPin) -> Self {
        Self {
            reference: pin.key.reference.whole(),
            platform: pin.key.platform.clone(),
            manifest_digest: pin.digest.as_str().to_owned(),
            revision: pin.revision.0,
        }
    }
}

impl PinFile {
    fn empty() -> Self {
        Self {
            version: 1,
            pins: Vec::new(),
            pending_default: None,
        }
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        if !store_bytes_within_limit(bytes.len()) {
            return Err(corrupt());
        }
        let file: Self = serde_json::from_slice(bytes).map_err(|_| corrupt())?;
        file.validate()?;
        Ok(file)
    }
    fn validate(&self) -> Result<()> {
        if !pin_count_within_limit(self.pins.len()) {
            return Err(corrupt());
        }
        let mut keys = BTreeSet::new();
        let mut unique = true;
        for record in &self.pins {
            record.validated()?;
            unique &= keys.insert((
                record.reference.clone(),
                record.platform.os.clone(),
                record.platform.architecture.clone(),
                record.platform.variant.clone(),
            ));
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
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| corrupt())?;
        if !store_bytes_within_limit(bytes.len()) || !pin_count_within_limit(self.pins.len()) {
            return Err(corrupt());
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
        self.observe_slot(true)
    }
    fn observe_slot(&self, observe_default: bool) -> Result<(PinFile, Option<Vec<u8>>)> {
        let deadline = Instant::now() + READ_WAIT;
        loop {
            if let Some(lock) = open_lock(&self.lock_path(), false)? {
                wait(&lock, FlockMode::Shared, deadline, &mut false)?;
                let file = self.read()?.unwrap_or_else(PinFile::empty);
                let physical = if observe_default || file.pending_default.is_some() {
                    default::snapshot_at(&self.directory)?
                } else {
                    None
                };
                let logical = logical_default(&file, physical)?;
                return Ok((file, logical));
            }
            let physical = if observe_default {
                default::snapshot_at(&self.directory)?
            } else {
                None
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
        self.observe_slot(false)?.0.lookup(key)
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
        let preread = self.read()?;
        if exists(&self.record())? && !exists(&self.lock_path())? {
            return Err(corrupt());
        }
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
        if let DefaultAction::Adopt(reference) = &action {
            self.adoption_binds(&candidate.key, reference)?;
        }
        let touch_default = !matches!(action, DefaultAction::None);
        let (old, _locks) = self.begin(touch_default)?;
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
        let final_bytes = new.encode()?; // Check ALL future writes before intent.
        let previous = if touch_default {
            default::snapshot_at(&self.directory)?
        } else {
            None
        };
        let (proposed, retained) = match action {
            DefaultAction::None => (None, DefaultChange::Unchanged),
            DefaultAction::Adopt(reference) if previous.is_none() => (
                Some(default::encode_snapshot(&reference)?),
                DefaultChange::Initialized,
            ),
            DefaultAction::Adopt(_) => (None, DefaultChange::Unchanged),
            DefaultAction::Set => {
                let retained = if previous.is_none() {
                    DefaultChange::Initialized
                } else {
                    DefaultChange::Replaced
                };
                (
                    Some(default::encode_snapshot(&pin.immutable_reference()?)?),
                    retained,
                )
            }
        };
        // A semantically identical fallback preserves exact existing bytes.
        let (proposed, retained) = match proposed {
            Some(bytes) if fallback_bytes_differ(&previous, &bytes)? => (Some(bytes), retained),
            _ => (None, DefaultChange::Unchanged),
        };
        if let Some(proposed) = proposed {
            let pending = PendingDefault {
                previous: previous
                    .map(String::from_utf8)
                    .transpose()
                    .map_err(|_| corrupt())?,
                proposed: String::from_utf8(proposed).map_err(|_| corrupt())?,
            };
            self.publish_default(&old, &final_bytes, pending, atomic_save)?;
        } else if decision != CommitDecision::AlreadyApproved {
            gate::checkpoint(gate::Stage::BeforePinSave)?;
            self.save(&final_bytes)?;
            gate::checkpoint(gate::Stage::PinCommitted)?;
        } else {
            gate::checkpoint(gate::Stage::PinCommitted)?;
        }
        Ok(Committed {
            approval: approval_change(decision),
            retained_default: retained,
            pin,
        })
    }

    /// Retain the default tier's own immutable selection when no fallback exists,
    /// regardless of the approval for its key.
    ///
    /// Write-once: a default-tier launch whose key was already pinned (an
    /// explicit `image refresh` establishes one without adopting) still
    /// initializes an absent fallback, and an existing fallback is never
    /// replaced here — only `image set-default` does that.
    pub(super) fn adopt_default_if_absent(
        &self,
        key: &PinKey,
        reference: &ImmutableImageRef,
    ) -> Result<DefaultChange> {
        self.adoption_binds(key, reference)?;
        // Warm launches must not recover an interrupted writer's journal or
        // create locks. Only an absent fallback needs the write transaction.
        if default::snapshot_at(&self.directory)?.is_some() {
            return Ok(DefaultChange::Unchanged);
        }
        let (old, _locks) = self.begin(true)?;
        if default::snapshot_at(&self.directory)?.is_some() {
            return Ok(DefaultChange::Unchanged);
        }
        let final_bytes = old.clone().encode()?;
        let pending = PendingDefault {
            previous: None,
            proposed: String::from_utf8(default::encode_snapshot(reference)?)
                .map_err(|_| corrupt())?,
        };
        self.publish_default(&old, &final_bytes, pending, atomic_save)?;
        Ok(DefaultChange::Initialized)
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
    /// The three real writes, with a narrow I/O seam for fault controls. The
    /// encoder has checked the complete future state before the first write.
    fn publish_default(
        &self,
        old: &PinFile,
        final_bytes: &[u8],
        pending: PendingDefault,
        mut save: impl FnMut(&Path, &[u8]) -> Result<()>,
    ) -> Result<()> {
        let mut intent = old.clone();
        intent.pending_default = Some(pending.clone());
        let intent_bytes = intent.encode()?;
        gate::checkpoint(gate::Stage::BeforeIntentSave)?;
        save(&self.record(), &intent_bytes)?;
        gate::checkpoint(gate::Stage::IntentSaved)?;
        let result = save(
            &self.directory.join(SELECTION_FILE),
            pending.proposed.as_bytes(),
        )
        .and_then(|()| {
            gate::checkpoint(gate::Stage::DefaultSaved)?;
            gate::checkpoint(gate::Stage::BeforePinSave)?;
            save(&self.record(), final_bytes)
        })
        .and_then(|()| gate::checkpoint(gate::Stage::PinCommitted));
        if let Err(error) = result {
            self.recover_using(&mut intent, &mut save)
                .map_err(|_| recovery_required())?;
            return Err(error);
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
    let canonical = |reference: &ImmutableImageRef| {
        CanonicalOciReference::parse(reference.as_str()).map_err(|_| corrupt())
    };
    Ok(canonical(&previous)? != canonical(&proposed)?)
}

/// The approval decision the compare-and-swap reached, as the caller reports it.
fn approval_change(decision: CommitDecision) -> ApprovalChange {
    match decision {
        CommitDecision::AlreadyApproved => ApprovalChange::Unchanged,
        CommitDecision::Insert => ApprovalChange::FirstPin,
        CommitDecision::Replace => ApprovalChange::Replaced,
        CommitDecision::Conflict => ApprovalChange::Unchanged,
    }
}

/// The exclusive locks one mutation holds; dropping them ends the transaction.
struct Locks {
    _pin: File,
    _default: Option<File>,
}

/// What one host transaction changed, reported per record so a matching pin
/// with a moved fallback is not reported as "nothing changed".
pub(super) struct Committed {
    pub(super) pin: ApprovedPin,
    pub(super) approval: ApprovalChange,
    pub(super) retained_default: DefaultChange,
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
    fn candidate(byte: char) -> ValidatedCandidate {
        // This test-only constructor exercises the store independently of
        // registry I/O. Production construction requires ValidatedImage.
        ValidatedCandidate {
            key: PinKey::new(&OciTarget::parse(SOURCE).unwrap()).unwrap(),
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
            version: 1,
            pins: vec![PinRecord::of(&ApprovedPin {
                key: c.key,
                digest: c.digest,
                revision: PinRevision(1),
            })],
            pending_default: None,
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
        for field in ["reference", "platform", "manifest_digest", "revision"] {
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
            ("version", serde_json::json!(2)),
            ("version", serde_json::json!("1")),
            ("extra", serde_json::json!(null)),
        ] {
            let mut v = value.clone();
            v[path] = bad;
            cases.push(serde_json::to_vec(&v).unwrap());
        }
        for (field, bad) in [
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
            text.replacen("\"version\":1", "\"version\":1,\"version\":1", 1)
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
                .commit_pin(&b, &replacement(&b, old), DefaultAction::Set)
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

    #[test]
    fn default_transaction_preintent_and_after_commit_preserve_exact_bytes() {
        let (_dir, store) = paths();
        let a = candidate('a');
        let b = candidate('b');
        let old = store
            .commit_pin(&a, &Approval::initial(&a), DefaultAction::None)
            .unwrap();
        let previous = String::from_utf8(default_bytes('a'))
            .unwrap()
            .replace("docker.io/library/alpine", "alpine")
            .into_bytes();
        store.write_default(Some(&previous)).unwrap();
        // Same digest default must preserve formatting and legacy spelling.
        store
            .commit_pin(&a, &Approval::initial(&a), DefaultAction::Set)
            .unwrap();
        assert_eq!(
            default::snapshot_at(&store.directory).unwrap().unwrap(),
            previous
        );
        // A stale failure has no intent and does not move the fallback.
        assert!(
            store
                .commit_pin(&b, &Approval::initial(&b), DefaultAction::Set)
                .is_err()
        );
        assert_eq!(
            default::snapshot_at(&store.directory).unwrap().unwrap(),
            previous
        );
        let new = store
            .commit_pin(&b, &replacement(&b, old), DefaultAction::Set)
            .unwrap();
        assert_eq!(new.digest, b.digest);
        assert!(store.read().unwrap().unwrap().pending_default.is_none());
        assert_eq!(
            store.load_default().unwrap().unwrap().as_str(),
            b.key.reference.with_digest(&b.digest).unwrap().whole()
        );
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
    #[test]
    fn journal_real_write_failures_roll_back_or_require_recovery() {
        for failed_write in [1, 2, 3] {
            for fail_restore in [false, true] {
                let (_dir, store) = paths();
                let old = file();
                install(&store, &old);
                let previous = default_bytes('a');
                store.write_default(Some(&previous)).unwrap();
                let old_bytes = std::fs::read(store.record()).unwrap();
                let mut new = old.clone();
                new.pins[0].manifest_digest = candidate('b').digest.as_str().into();
                new.pins[0].revision = 2;
                let pending = PendingDefault {
                    previous: Some(String::from_utf8(previous.clone()).unwrap()),
                    proposed: String::from_utf8(default_bytes('b')).unwrap(),
                };
                let mut writes = 0;
                let error = store
                    .publish_default(&old, &new.encode().unwrap(), pending, |path, bytes| {
                        writes += 1;
                        if writes == failed_write || (fail_restore && writes > failed_write) {
                            return Err(failure());
                        }
                        atomic_save(path, bytes)
                    })
                    .unwrap_err();
                if fail_restore && failed_write > 1 {
                    assert!(error.to_string().contains("requires recovery"));
                    assert!(store.read().unwrap().unwrap().pending_default.is_some());
                    // Logical old remains observable without clearing intent.
                    assert_eq!(store.observe().unwrap().1.unwrap(), previous);
                    let a = candidate('a');
                    store
                        .commit_pin(&a, &Approval::initial(&a), DefaultAction::None)
                        .unwrap();
                }
                assert!(store.read().unwrap().unwrap().pending_default.is_none());
                assert_eq!(
                    default::snapshot_at(&store.directory).unwrap().unwrap(),
                    previous
                );
                assert_eq!(std::fs::read(store.record()).unwrap(), old_bytes);
            }
        }
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

    #[test]
    fn automatic_adoption_binds_original_immutable_source() {
        let (_dir, store) = paths();
        let mut c = candidate('b');
        let original = default_bytes('a');
        let source = default::decode_snapshot(&original).unwrap();
        c.key.reference = CanonicalOciReference::parse(source.as_str()).unwrap();
        // Index A→host child B: retain A verbatim, pin B separately.
        store
            .commit_pin(
                &c,
                &Approval::initial(&c),
                DefaultAction::Adopt(source.clone()),
            )
            .unwrap();
        assert_eq!(store.load_default().unwrap().unwrap(), source);
        let before = default::snapshot_at(&store.directory).unwrap();
        let unrelated = default::decode_snapshot(&default_bytes('c')).unwrap();
        assert!(
            store
                .commit_pin(&c, &Approval::initial(&c), DefaultAction::Adopt(unrelated))
                .is_err()
        );
        assert_eq!(default::snapshot_at(&store.directory).unwrap(), before);
    }
    #[test]
    fn warm_adoption_validates_the_record_without_creating_locks() {
        let (_dir, store) = paths();
        let mut c = candidate('a');
        let retained = default::decode_snapshot(&default_bytes('a')).unwrap();
        c.key.reference = CanonicalOciReference::parse(retained.as_str()).unwrap();
        std::fs::create_dir_all(&store.directory).unwrap();
        let record = store.directory.join(SELECTION_FILE);
        std::fs::write(&record, default_bytes('a')).unwrap();
        assert_eq!(
            store.adopt_default_if_absent(&c.key, &retained).unwrap(),
            DefaultChange::Unchanged
        );
        std::fs::write(&record, b"corrupt").unwrap();
        assert!(store.adopt_default_if_absent(&c.key, &retained).is_err());
        assert!(!store.lock_path().exists());
        assert!(!store.directory.join(DEFAULT_LOCK_FILE).exists());
        assert!(!store.record().exists());
    }

    #[test]
    fn matching_pin_reports_a_replaced_fallback() {
        let (_dir, store) = paths();
        let c = candidate('a');
        store
            .commit_pin(&c, &Approval::initial(&c), DefaultAction::None)
            .unwrap();
        std::fs::write(store.directory.join(SELECTION_FILE), default_bytes('b')).unwrap();
        let before = std::fs::read(store.record()).unwrap();
        let committed = store
            .commit(&c, &Approval::initial(&c), DefaultAction::Set)
            .unwrap();
        assert_eq!(committed.approval, ApprovalChange::Unchanged);
        assert_eq!(committed.retained_default, DefaultChange::Replaced);
        assert_eq!(std::fs::read(store.record()).unwrap(), before);
        assert_eq!(
            store.load_default().unwrap().unwrap(),
            committed.pin.immutable_reference().unwrap()
        );
    }

    #[test]
    fn write_once_adoption_initializes_an_absent_fallback_only() {
        let (_dir, store) = paths();
        let mut c = candidate('b');
        let retained = default::decode_snapshot(&default_bytes('a')).unwrap();
        c.key.reference = CanonicalOciReference::parse(retained.as_str()).unwrap();
        // An existing approval is no obstacle: retention is a separate record.
        store
            .commit_pin(&c, &Approval::initial(&c), DefaultAction::None)
            .unwrap();
        assert_eq!(
            store.adopt_default_if_absent(&c.key, &retained).unwrap(),
            DefaultChange::Initialized
        );
        assert_eq!(store.load_default().unwrap().unwrap(), retained);
        let bytes = std::fs::read(store.directory.join(SELECTION_FILE)).unwrap();
        assert_eq!(
            store.adopt_default_if_absent(&c.key, &retained).unwrap(),
            DefaultChange::Unchanged
        );
        assert_eq!(
            std::fs::read(store.directory.join(SELECTION_FILE)).unwrap(),
            bytes
        );
        // A record that does not name this key's own source is refused rather
        // than retained: it would authorize content nothing measured.
        let unrelated = default::decode_snapshot(&default_bytes('c')).unwrap();
        assert!(store.adopt_default_if_absent(&c.key, &unrelated).is_err());
        assert_eq!(
            std::fs::read(store.directory.join(SELECTION_FILE)).unwrap(),
            bytes
        );
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
        let error = store
            .commit_pin(&a, &Approval::initial(&a), DefaultAction::Set)
            .unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(start.elapsed() >= WRITE_WAIT);
        assert!(start.elapsed() < WRITE_WAIT + Duration::from_secs(3));
        assert_eq!(std::fs::read(store.record()).unwrap(), before);
        assert!(!store.directory.join(SELECTION_FILE).exists());
        // Failure releases the already-acquired pin EX, not merely default EX.
        let probe = open_lock(&store.lock_path(), false).unwrap().unwrap();
        assert_eq!(
            host_paths::try_flock(&probe, FlockMode::Exclusive).unwrap(),
            host_paths::FlockAttempt::Acquired
        );
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
}
