//! ADR-0040's verified read, generalised to every authority-bearing user field.
//!
//! The user config is shared by every project on the host, so a guest in one
//! project can plant a file that a later launch in another project reads. A
//! field that *grants* something — egress under ADR-0040, host mounts under
//! ADR-0046, named mount sets under ADR-0048, named egress sets under #511 — may
//! therefore only be taken from bytes whose file and immediate directory this
//! user owns, singly named, and not group- or other-writable.
//!
//! **Presence, not contents, is what makes a file authority-bearing.** An empty
//! `[network]` table, an empty `mounts` array, an empty `[mount_sets]` table and
//! an empty `[egress_sets]` table grant nothing, yet all four are the bytes an
//! attacker would plant: what is being decided is whether the *file* is the
//! user's own, so a caller that reads contents to decide would skip the check on
//! exactly the cheapest file to plant. A file that declares `mount_sets` without `mounts` is therefore just as
//! authority-bearing as one that declares `mounts`, and so is one whose only
//! mount list sits inside a full `[[tools]]` definition (#396):
//! [`mount_authority_present`] is where those two mount sites are aggregated, so
//! the rule stays "any mount list" rather than "the defaults list".
//!
//! The rules live in one place. [`verify`] is the only producer of
//! [`AuthorizedConfig`] and every authority-bearing parser takes that token as
//! an argument, so a second, laxer read cannot appear without contradicting this
//! module. The decision itself is a pure kernel ([`authority_refusal`]); the
//! measurements it needs — the parent's `metadata`, the open descriptor's
//! `fstat` facts, the effective uid — stay in the trusted adapter, per
//! ADR-0018.
//!
//! Deliberately *not* claimed, unchanged from ADR-0040: an immediate parent
//! directory that is itself a symlink is followed (only the final component is
//! refused), mode 0600 is never required, and no ancestor, race or ACL
//! protection is asserted.
//!
//! # One measurement, two consumers (ADR-0059)
//!
//! [`verify`] now measures the file on **every** user read, not only when an
//! authority-bearing field is present: a `tool:NAME` egress reference is passed
//! on the command line, which is parsed *after* this read is gone, yet it must
//! be decided by the facts of the very read whose bytes supplied the tools
//! (ADR-0040 forbids a second observation). So the measured verdict is kept
//! beside the bytes it came from, in a [`ReferenceTrust`] that carries its file
//! and outlives the read.
//!
//! Refusal at *load* time is still decided by presence alone: only a file that
//! declares `[network]`, `mounts`, `[mount_sets]` or `[egress_sets]` is refused
//! for being untrusted, so a tools-only dotfile symlink keeps loading exactly as
//! before.
//! The verdict waits, unused, for a CLI reference to consult it.

use crate::protected_config_dir::authority_file_singly_linked;
use vstd::prelude::*;

verus! {
#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub enum AuthorityRefusal { DirNotDirectory, DirOwner, DirWritable, ThroughSymlink, FileOwner, FileWritable, FileLinks(u64) }

#[derive(Clone, Copy, Debug)]
pub struct FileFacts { pub uid: u32, pub mode: u32, pub nlink: u64 }
#[derive(Clone, Copy, Debug)]
pub struct DirFacts { pub is_dir: bool, pub uid: u32, pub mode: u32 }
#[derive(Clone, Copy, Debug)]
pub enum Reached { ThroughSymlink, Direct(FileFacts) }

pub open spec fn others_may_write(mode: u32) -> bool { mode & 0o022u32 != 0u32 }
pub open spec fn dir_ok(d: DirFacts, euid: u32) -> bool { d.is_dir && d.uid == euid && !others_may_write(d.mode) }
pub open spec fn file_ok(f: FileFacts, euid: u32) -> bool { f.uid == euid && !others_may_write(f.mode) && crate::protected_config_dir::authority_file_singly_linked_spec(f.nlink) }

/// Precedence mirrors credential_yaml::load: directory first, then the file.
pub fn authority_refusal(reached: Reached, dir: DirFacts, euid: u32) -> (r: Option<AuthorityRefusal>)
    ensures
        r.is_none() == (dir_ok(dir, euid) && match reached { Reached::Direct(f) => file_ok(f, euid), Reached::ThroughSymlink => false }),
        !dir.is_dir ==> r == Some(AuthorityRefusal::DirNotDirectory),
        dir.is_dir && dir.uid != euid ==> r == Some(AuthorityRefusal::DirOwner),
        dir.is_dir && dir.uid == euid && others_may_write(dir.mode) ==> r == Some(AuthorityRefusal::DirWritable),
        dir_ok(dir, euid) ==> match reached {
            Reached::ThroughSymlink => r == Some(AuthorityRefusal::ThroughSymlink),
            Reached::Direct(f) =>
                (f.uid != euid ==> r == Some(AuthorityRefusal::FileOwner))
                && (f.uid == euid && others_may_write(f.mode) ==> r == Some(AuthorityRefusal::FileWritable))
                && (f.uid == euid && !others_may_write(f.mode) && !crate::protected_config_dir::authority_file_singly_linked_spec(f.nlink) ==> r == Some(AuthorityRefusal::FileLinks(f.nlink))),
        },
{
    if !dir.is_dir { return Some(AuthorityRefusal::DirNotDirectory); }
    if dir.uid != euid { return Some(AuthorityRefusal::DirOwner); }
    if dir.mode & 0o022 != 0 { return Some(AuthorityRefusal::DirWritable); }
    match reached {
        Reached::ThroughSymlink => Some(AuthorityRefusal::ThroughSymlink),
        Reached::Direct(f) => {
            if f.uid != euid { Some(AuthorityRefusal::FileOwner) }
            else if f.mode & 0o022 != 0 { Some(AuthorityRefusal::FileWritable) }
            // The one-name rule is ADR-0038's, shared with the launch-time check.
            else if !authority_file_singly_linked(f.nlink) { Some(AuthorityRefusal::FileLinks(f.nlink)) }
            else { None }
        }
    }
}
} // verus!

use crate::host_paths::{FinalComponent, VerifiedRead};
use std::{
    fmt,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

verus! {
/// The two places one user file can declare a mount selection: the top-level
/// `mounts` array and any full `[[tools]]` definition's `mounts` field.
///
/// Named fields rather than adjacent booleans, so a call site cannot swap them
/// — they are both "this file selects mounts" and a transposition would decide
/// which one the diagnostic points at.
#[derive(Clone, Copy, Debug)]
pub struct MountAuthorityFacts { pub top_level: bool, pub tool_field: bool }

/// #396: **any** mount list makes the file authority-bearing, wherever it is
/// declared. Presence, not contents, stays the rule — an empty tool list and an
/// empty top-level list are exactly the bytes an attacker would plant, so this
/// is one OR, never a nonempty test.
///
/// This only widens *which* files are measured; [`authority_required`] keeps its
/// four-trigger contract and [`AuthoritySubject`] keeps its wording, so a file
/// whose only old authority field is `[network]` prints the same bytes as before.
pub fn mount_authority_present(f: MountAuthorityFacts) -> (r: bool)
    ensures r == (f.top_level || f.tool_field),
{
    if f.top_level { true } else { f.tool_field }
}

/// Which authority-bearing fields one user file declares. Named facts rather
/// than adjacent booleans, so a call site cannot swap them.
#[derive(Clone, Copy, Debug)]
pub struct AuthorityTriggers { pub network: bool, pub mounts: bool, pub mount_sets: bool, pub egress_sets: bool }

/// ADR-0040/0046/0048/#511: presence, not contents, makes a user file
/// authority-bearing. `t.mounts` is already the aggregate of the top-level
/// `mounts` array and every tool's `mounts` field ([`mount_authority_present`]).
pub fn authority_required(t: AuthorityTriggers) -> (r: bool)
    ensures r == (t.network || t.mounts || t.mount_sets || t.egress_sets),
{
    if t.network { true } else { t.mounts || t.mount_sets || t.egress_sets }
}
} // verus!

/// Which of the four authority-bearing fields one file declares, in the order
/// every sentence names them.
///
/// `Default` is the empty set, which is reachable only from tests and is
/// normalized by [`AuthoritySubject::of`]; no sentence can be built from it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct AuthorityFields {
    network: bool,
    mounts: bool,
    mount_sets: bool,
    egress_sets: bool,
}

/// The field(s) a refusal is about, so one refusal kernel can report itself
/// under any nonempty combination of `[network]`, `mounts`, `[mount_sets]` and
/// `[egress_sets]`.
///
/// Only diagnostic wording depends on this; which refusals fire does not. Held
/// as data rather than as sixteen enum variants: the three slots are one shared
/// grammar (list the present fields, `and`/`or` before the last), enumerating
/// them would triple with every future field, and a *folded* subject — say,
/// naming `[egress_sets]` under `[network]` — would send a reader to review a
/// table the file does not have (ADR-0040's #397 amendment).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthoritySubject {
    /// Never all-false: only [`Self::of`] builds one, and it normalizes the
    /// empty set.
    Fields(AuthorityFields),
    /// ADR-0059: a CLI `tool:NAME` egress reference reads `[[tools]]`
    /// `network_requests`, so *that* is the field a file is being trusted for.
    /// Not a file field, so [`Self::of`] cannot return it.
    EgressReference,
}

/// `(label, object, without)` per field, in the fixed order sentences name them.
const FIELD_PHRASES: [(&str, &str, &str); 4] = [
    ("[network]", "[network] table", "[network]"),
    ("mounts", "mounts list", "mounts"),
    ("[mount_sets]", "[mount_sets] table", "[mount_sets]"),
    ("[egress_sets]", "[egress_sets] table", "[egress_sets]"),
];

/// `a`, `a and b`, `a, b and c`: the one list grammar all three slots share.
fn join_phrases(phrases: &[&str], conjunction: &str) -> String {
    match phrases.split_last() {
        None => String::new(),
        Some((last, [])) => (*last).to_owned(),
        Some((last, rest)) => format!("{}{conjunction}{last}", rest.join(", ")),
    }
}

impl AuthoritySubject {
    // Three slots, because one sentence per refusal is assembled from three
    // grammatical positions and a subject fills each differently. Keeping the
    // tails in one `format!` (see `write_refusal`) and the slots here is what
    // lets `[network]` and `mounts` stay byte-identical while each later field
    // reuses the sentence.

    /// Opens every refusal sentence.
    fn label(self) -> String {
        match self {
            Self::Fields(fields) => join_phrases(&fields.present(0), " and "),
            Self::EgressReference => "an egress reference".to_owned(),
        }
    }

    /// What the reader is told to review before trusting the file.
    fn object(self) -> String {
        match self {
            Self::Fields(fields) => join_phrases(&fields.present(1), " and "),
            Self::EgressReference => "[[tools]] network_requests".to_owned(),
        }
    }

    /// The "a symlinked config without …" aside names the fields, unqualified
    /// by "table"/"list", because it describes the file's compatibility. A file
    /// without `mounts` is *not* safe when it declares `mount_sets`.
    fn without(self) -> String {
        match self {
            Self::Fields(fields) => join_phrases(&fields.present(2), " or "),
            Self::EgressReference => "an egress reference".to_owned(),
        }
    }

    /// Which subject a set of triggers is about.
    ///
    /// The all-false input is *unreachable*: callers only ask once
    /// [`authority_required`] has said yes. It is nevertheless normalized to the
    /// `[network]`-only subject rather than copied, because a slot built from an
    /// empty set would render an empty word in the middle of a refusal sentence
    /// while claiming nothing about the file.
    ///
    /// `EgressReference` is deliberately unnameable here: a flag is not a file
    /// field, so a presence trigger can never be about one.
    fn of(triggers: AuthorityTriggers) -> Self {
        let fields = AuthorityFields {
            network: triggers.network,
            mounts: triggers.mounts,
            mount_sets: triggers.mount_sets,
            egress_sets: triggers.egress_sets,
        };
        if !(triggers.network || triggers.mounts || triggers.mount_sets || triggers.egress_sets) {
            return Self::Fields(AuthorityFields {
                network: true,
                ..AuthorityFields::default()
            });
        }
        Self::Fields(fields)
    }
}

impl AuthorityFields {
    /// The phrases of the present fields for one of the three slots, in the order
    /// a sentence names them.
    fn present(self, slot: usize) -> Vec<&'static str> {
        let flags = [self.network, self.mounts, self.mount_sets, self.egress_sets];
        flags
            .iter()
            .zip(FIELD_PHRASES)
            .filter(|(present, _)| **present)
            .map(|(_, phrases)| match slot {
                0 => phrases.0,
                1 => phrases.1,
                _ => phrases.2,
            })
            .collect()
    }
}

/// Proof that one user file passed the ADR-0040 checks.
///
/// The field is private to this module, so the only way to hold one is to have
/// called [`verify`]. Authority-bearing parsers take this type instead of a
/// path precisely so they cannot be called on an unverified read.
#[derive(Debug)]
pub(crate) struct AuthorizedConfig<'a> {
    file: &'a Path,
}

impl AuthorizedConfig<'_> {
    pub(crate) fn file(&self) -> &Path {
        self.file
    }
}

/// Why a user file could not be trusted, as the field(s) that made it
/// authority-bearing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UntrustedConfig {
    /// The verified-read rules rejected the file or its immediate directory.
    /// The refusal variant carries the one extra datum that is valid for it
    /// (`FileLinks`), so a symlink refusal cannot also hold a link count.
    Refused {
        refusal: AuthorityRefusal,
        subject: AuthoritySubject,
    },
    /// The immediate directory could not be examined at all.
    DirUnexaminable {
        kind: std::io::ErrorKind,
        subject: AuthoritySubject,
    },
}

impl fmt::Display for UntrustedConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused { refusal, subject } => write_refusal(f, *subject, refusal),
            Self::DirUnexaminable { kind, subject } => write!(
                f,
                "{} requires examining the config directory, which failed ({kind:?})",
                subject.label()
            ),
        }
    }
}

/// The one place a refusal becomes user-facing text.
///
/// Three phrase slots per subject are interpolated into per-variant tails: most
/// say "before trusting the file", `DirWritable` says "before trusting it", and
/// `DirNotDirectory` has no review caveat at all. The tails are deliberately
/// *not* normalised — they are read by a human deciding whether to trust a
/// hostile file, and they are byte-pinned for the `[network]`-only subject
/// because #394 changed nothing about persisted network authority.
fn write_refusal(
    f: &mut fmt::Formatter<'_>,
    subject: AuthoritySubject,
    refusal: &AuthorityRefusal,
) -> fmt::Result {
    use AuthorityRefusal::*;
    let label = subject.label();
    let object = subject.object();
    // These refusals fire where a guest or another account may have authored
    // the bytes, so none advises making the file trusted before the field has
    // been reviewed.
    match refusal {
        ThroughSymlink => write!(
            f,
            "{label} requires config.toml to be a regular file, but it is reached through a symbolic link; its target may be writable by a guest or project, so review the {object} before trusting the file (a symlinked config without {} still works)",
            subject.without()
        ),
        FileOwner => write!(
            f,
            "{label} refuses a config.toml owned by another user; review the {object} before trusting the file"
        ),
        FileWritable => write!(
            f,
            "{label} refuses a group- or other-writable config.toml; a guest or another account may have written its {object}, so review the {object} before trusting the file (fixing the mode does not establish authorship)"
        ),
        FileLinks(nlink) => write!(
            f,
            "{label} refuses a config.toml with {nlink} hard links; another name for it may be guest- or project-writable, so review the {object} before trusting the file"
        ),
        DirNotDirectory => write!(
            f,
            "{label} refuses a config.toml whose directory is not a directory"
        ),
        DirOwner => write!(
            f,
            "{label} refuses a config.toml whose directory is owned by another user; review the {object} before trusting the file"
        ),
        DirWritable => write!(
            f,
            "{label} refuses a config.toml whose directory is group- or other-writable; a guest or another account may be able to replace the file, so review the {object} before trusting it"
        ),
    }
}

/// The verified read's verdict for an egress reference, owned so it can outlive
/// the read that produced it (ADR-0059).
///
/// A CLI `tool:NAME` is only known after argv is parsed, which is after
/// `config::load` has dropped its [`VerifiedRead`]. Re-reading or re-measuring at
/// launch would decide from a second observation, so the verdict from the read
/// whose bytes supplied the tools is carried here instead.
///
/// The file is stored with the verdict and never supplied separately, so a
/// verdict for one file cannot be paired with another file's tools:
/// [`crate::egress_reference::UserToolRequests::new`] keeps only tools whose
/// origin file equals [`Self::file`].
///
/// Private fields: only [`verify`] mints one that vouches for anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReferenceTrust {
    file: PathBuf,
    verdict: Result<(), UntrustedConfig>,
}

impl ReferenceTrust {
    pub(crate) fn file(&self) -> &Path {
        &self.file
    }

    /// The verdict, with no second check: the value is what the read measured.
    pub(crate) fn require(&self) -> Result<(), UntrustedConfig> {
        self.verdict
    }

    #[cfg(test)]
    pub(crate) fn verified_for_test(file: &Path) -> Self {
        Self {
            file: file.to_owned(),
            verdict: Ok(()),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test_untrusted(file: &Path, refusal: UntrustedConfig) -> Self {
        Self {
            file: file.to_owned(),
            verdict: Err(refusal),
        }
    }
}

/// What one read's measurements said, before it is attributed to a field.
///
/// Private: it is an intermediate of [`verify`], never a decision a caller can
/// hold. Attribution is separate because the *same* measurement is reported
/// under the field that made the file authority-bearing, and under
/// [`AuthoritySubject::EgressReference`] when it is a CLI reference asking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Measurement {
    Refused(AuthorityRefusal),
    DirUnexaminable(std::io::ErrorKind),
}

impl Measurement {
    fn into_untrusted(self, subject: AuthoritySubject) -> UntrustedConfig {
        match self {
            Self::Refused(refusal) => UntrustedConfig::Refused { refusal, subject },
            Self::DirUnexaminable(kind) => UntrustedConfig::DirUnexaminable { kind, subject },
        }
    }
}

/// The result of one verified user read.
#[derive(Debug)]
pub(crate) struct Verification<'a> {
    /// `Some` iff an authority-bearing field is present *and* the file passed.
    /// Unchanged rule: presence is the only load-time trigger.
    pub(crate) authorized: Option<AuthorizedConfig<'a>>,
    /// The same read's verdict for a CLI egress reference, which is only known
    /// after argv is parsed.
    pub(crate) references: ReferenceTrust,
}

/// Decide whether a verified read establishes authority, and mint the tokens the
/// authority-bearing parsers require.
///
/// The file is measured on every call, but `authorized` is `None` whenever the
/// file declares no authority-bearing field, so a tools/image-only config keeps
/// working through a dotfile symlink (ADR-0040's compatibility rule). A refusal
/// is returned only when such a field is present; the verdict for a later CLI
/// egress reference is returned in [`Verification::references`] instead, because
/// a reference is not a file field and must not change what loads.
///
/// This is the only I/O in the module and it happens before any credential
/// handling, runtime identity work or launch state, because a caller loads
/// config first.
pub(crate) fn verify<'a>(
    read: &'a VerifiedRead,
    triggers: AuthorityTriggers,
) -> Result<Verification<'a>, UntrustedConfig> {
    let file = read.path();
    let measured = measure(read);
    if !authority_required(triggers) {
        // Never a refusal here: presence stays the only load-time trigger, so a
        // tools-only symlink loads as before. The verdict waits for a CLI
        // reference, which consult `require()` before resolving a name.
        return Ok(Verification {
            authorized: None,
            references: ReferenceTrust {
                file: file.to_owned(),
                verdict: measured.map_err(|measurement| {
                    measurement.into_untrusted(AuthoritySubject::EgressReference)
                }),
            },
        });
    }
    measured.map_err(|measurement| measurement.into_untrusted(AuthoritySubject::of(triggers)))?;
    Ok(Verification {
        authorized: Some(AuthorizedConfig { file }),
        references: ReferenceTrust {
            file: file.to_owned(),
            verdict: Ok(()),
        },
    })
}

/// ADR-0040's measurements: the immediate directory's `metadata`, the read's own
/// final-component facts and the effective uid, handed to the proved kernel.
fn measure(read: &VerifiedRead) -> Result<(), Measurement> {
    let file = read.path();
    // Separate path observation, not anchored to the read descriptor; ancestors
    // remain trusted (ADR-0040's accepted gap).
    let parent = file
        .parent()
        .ok_or(Measurement::DirUnexaminable(std::io::ErrorKind::NotFound))?;
    let meta =
        std::fs::metadata(parent).map_err(|error| Measurement::DirUnexaminable(error.kind()))?;
    let dir = DirFacts {
        is_dir: meta.is_dir(),
        uid: meta.uid(),
        mode: meta.mode(),
    };
    let reached = match read.final_component() {
        FinalComponent::Symlink => Reached::ThroughSymlink,
        FinalComponent::Regular(f) => Reached::Direct(FileFacts {
            uid: f.uid,
            mode: raw_mode_u32(f.mode),
            nlink: f.nlink,
        }),
    };
    match authority_refusal(reached, dir, crate::host_paths::current_euid()) {
        Some(refusal) => Err(Measurement::Refused(refusal)),
        None => Ok(()),
    }
}

pub(crate) fn raw_mode_u32(mode: rustix::fs::RawMode) -> u32 {
    // RawMode is u16 on macOS, u32 on Linux.
    #[allow(clippy::useless_conversion)]
    u32::from(mode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_paths::read_bounded_regular_file_noting_symlink;
    use proptest::prelude::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    /// Every subject a refusal can be built for: the fifteen nonempty field
    /// combinations, then ADR-0059's reference subject.
    fn every_subject() -> Vec<AuthoritySubject> {
        let mut subjects = Vec::new();
        for network in [false, true] {
            for mounts in [false, true] {
                for mount_sets in [false, true] {
                    for egress_sets in [false, true] {
                        if network || mounts || mount_sets || egress_sets {
                            subjects.push(AuthoritySubject::of(AuthorityTriggers {
                                network,
                                mounts,
                                mount_sets,
                                egress_sets,
                            }));
                        }
                    }
                }
            }
        }
        subjects.push(AuthoritySubject::EgressReference);
        subjects
    }

    /// The three interchangeable slots one refusal sentence is assembled from,
    /// written out per subject.
    ///
    /// These are literals, so a subject whose wording changes fails here; the
    /// composition in `pinned_refusal_display` is a `format!` of the same shape
    /// as `write_refusal`, which is why the `[network]`-only subject additionally
    /// has whole-sentence literals in `network_subject_display_is_byte_identical`.
    /// The rows are never composed from `FIELD_PHRASES`: a table that agrees with
    /// itself would accept any wrong wording.
    fn pinned_subject_slots(
        subject: AuthoritySubject,
    ) -> (&'static str, &'static str, &'static str) {
        match subject {
            AuthoritySubject::Fields(fields) => match (
                fields.network,
                fields.mounts,
                fields.mount_sets,
                fields.egress_sets,
            ) {
                (true, false, false, false) => ("[network]", "[network] table", "[network]"),
                (false, true, false, false) => ("mounts", "mounts list", "mounts"),
                (false, false, true, false) => {
                    ("[mount_sets]", "[mount_sets] table", "[mount_sets]")
                }
                (true, true, false, false) => (
                    "[network] and mounts",
                    "[network] table and mounts list",
                    "[network] or mounts",
                ),
                (true, false, true, false) => (
                    "[network] and [mount_sets]",
                    "[network] table and [mount_sets] table",
                    "[network] or [mount_sets]",
                ),
                (false, true, true, false) => (
                    "mounts and [mount_sets]",
                    "mounts list and [mount_sets] table",
                    "mounts or [mount_sets]",
                ),
                (true, true, true, false) => (
                    "[network], mounts and [mount_sets]",
                    "[network] table, mounts list and [mount_sets] table",
                    "[network], mounts or [mount_sets]",
                ),
                // #511: `[egress_sets]` is the fourth field, so it is last in
                // every list — including when it is the only one.
                (false, false, false, true) => {
                    ("[egress_sets]", "[egress_sets] table", "[egress_sets]")
                }
                (true, false, false, true) => (
                    "[network] and [egress_sets]",
                    "[network] table and [egress_sets] table",
                    "[network] or [egress_sets]",
                ),
                (false, true, false, true) => (
                    "mounts and [egress_sets]",
                    "mounts list and [egress_sets] table",
                    "mounts or [egress_sets]",
                ),
                (false, false, true, true) => (
                    "[mount_sets] and [egress_sets]",
                    "[mount_sets] table and [egress_sets] table",
                    "[mount_sets] or [egress_sets]",
                ),
                (true, true, false, true) => (
                    "[network], mounts and [egress_sets]",
                    "[network] table, mounts list and [egress_sets] table",
                    "[network], mounts or [egress_sets]",
                ),
                (true, false, true, true) => (
                    "[network], [mount_sets] and [egress_sets]",
                    "[network] table, [mount_sets] table and [egress_sets] table",
                    "[network], [mount_sets] or [egress_sets]",
                ),
                (false, true, true, true) => (
                    "mounts, [mount_sets] and [egress_sets]",
                    "mounts list, [mount_sets] table and [egress_sets] table",
                    "mounts, [mount_sets] or [egress_sets]",
                ),
                (true, true, true, true) => (
                    "[network], mounts, [mount_sets] and [egress_sets]",
                    "[network] table, mounts list, [mount_sets] table and [egress_sets] table",
                    "[network], mounts, [mount_sets] or [egress_sets]",
                ),
                (false, false, false, false) => {
                    unreachable!("`of` normalizes the empty trigger set")
                }
            },
            // ADR-0059: not a file field, so all three slots say the same thing
            // — what a CLI reference needs the file for.
            AuthoritySubject::EgressReference => (
                "an egress reference",
                "[[tools]] network_requests",
                "an egress reference",
            ),
        }
    }

    /// Every refusal's exact sentence for every subject, and whether that
    /// variant can fire on guest- or project-authored bytes (so it must carry
    /// the review caveat).
    ///
    /// Each variant's sentence is a literal here and each subject's three slots
    /// are literals in [`pinned_subject_slots`], so this is the independent
    /// oracle for the templated `Display`: a reworded tail, a reworded slot, or a
    /// row that picks the wrong slot all fail. The pre-#394 `Network` bytes have
    /// their own whole-sentence literals below, because *that* column must not
    /// depend on the composition being right.
    ///
    /// The `match` is exhaustive over `AuthorityRefusal`, so a new variant fails
    /// to compile here until its row is added.
    fn pinned_refusal_display(
        refusal: AuthorityRefusal,
        subject: AuthoritySubject,
    ) -> (String, bool) {
        use AuthorityRefusal::*;
        let (label, object, without) = pinned_subject_slots(subject);
        match refusal {
            DirNotDirectory => (
                format!("{label} refuses a config.toml whose directory is not a directory"),
                false,
            ),
            DirOwner => (
                format!(
                    "{label} refuses a config.toml whose directory is owned by another user; review the {object} before trusting the file"
                ),
                true,
            ),
            DirWritable => (
                format!(
                    "{label} refuses a config.toml whose directory is group- or other-writable; a guest or another account may be able to replace the file, so review the {object} before trusting it"
                ),
                true,
            ),
            ThroughSymlink => (
                format!(
                    "{label} requires config.toml to be a regular file, but it is reached through a symbolic link; its target may be writable by a guest or project, so review the {object} before trusting the file (a symlinked config without {without} still works)"
                ),
                true,
            ),
            FileOwner => (
                format!(
                    "{label} refuses a config.toml owned by another user; review the {object} before trusting the file"
                ),
                true,
            ),
            FileWritable => (
                format!(
                    "{label} refuses a group- or other-writable config.toml; a guest or another account may have written its {object}, so review the {object} before trusting the file (fixing the mode does not establish authorship)"
                ),
                true,
            ),
            FileLinks(nlink) => (
                format!(
                    "{label} refuses a config.toml with {nlink} hard links; another name for it may be guest- or project-writable, so review the {object} before trusting the file"
                ),
                true,
            ),
        }
    }

    fn every_refusal() -> [AuthorityRefusal; 7] {
        use AuthorityRefusal::*;
        [
            DirNotDirectory,
            DirOwner,
            DirWritable,
            ThroughSymlink,
            FileOwner,
            FileWritable,
            FileLinks(3),
        ]
    }

    /// Extracting the verified read into this module changed no byte of a
    /// persisted-network diagnostic.
    ///
    /// The oracle is the literal pre-#394 text below — whole sentences, not the
    /// slot table — so a change to a slot *or* to a per-variant tail fails here
    /// even when every subject changed consistently.
    #[test]
    fn network_subject_display_is_byte_identical() {
        use AuthorityRefusal::*;
        // The `[network]`-only subject, built the one way a subject now can be.
        // Every expected sentence below is frozen at its pre-#394 spelling.
        let subject = AuthoritySubject::of(AuthorityTriggers {
            network: true,
            mounts: false,
            mount_sets: false,
            egress_sets: false,
        });
        for (refusal, pinned) in [
            (
                DirNotDirectory,
                "[network] refuses a config.toml whose directory is not a directory",
            ),
            (
                DirOwner,
                "[network] refuses a config.toml whose directory is owned by another user; review the [network] table before trusting the file",
            ),
            (
                DirWritable,
                "[network] refuses a config.toml whose directory is group- or other-writable; a guest or another account may be able to replace the file, so review the [network] table before trusting it",
            ),
            (
                ThroughSymlink,
                "[network] requires config.toml to be a regular file, but it is reached through a symbolic link; its target may be writable by a guest or project, so review the [network] table before trusting the file (a symlinked config without [network] still works)",
            ),
            (
                FileOwner,
                "[network] refuses a config.toml owned by another user; review the [network] table before trusting the file",
            ),
            (
                FileWritable,
                "[network] refuses a group- or other-writable config.toml; a guest or another account may have written its [network] table, so review the [network] table before trusting the file (fixing the mode does not establish authorship)",
            ),
            (
                FileLinks(3),
                "[network] refuses a config.toml with 3 hard links; another name for it may be guest- or project-writable, so review the [network] table before trusting the file",
            ),
        ] {
            let text = UntrustedConfig::Refused { refusal, subject }.to_string();
            assert_eq!(text, pinned, "network refusal text changed for {refusal:?}");
        }
        // The unexaminable-directory error is not a refusal variant (it carries
        // an `ErrorKind`), so it is pinned separately: same label slot, same tail.
        let kind = std::io::ErrorKind::PermissionDenied;
        assert_eq!(
            UntrustedConfig::DirUnexaminable { kind, subject }.to_string(),
            "[network] requires examining the config directory, which failed (PermissionDenied)"
        );
    }

    /// Every refusal's exact sentence for every subject, plus the durable
    /// positive half: a refusal that can fire on guest- or project-authored
    /// bytes must tell the reader to review the field first.
    #[test]
    fn untrusted_refusals_never_advise_adopting_a_guests_file() {
        for subject in every_subject() {
            let caveat = format!("review the {} before trusting", subject.object());
            for refusal in every_refusal() {
                let text = UntrustedConfig::Refused { refusal, subject }.to_string();
                let (pinned, carries_caveat) = pinned_refusal_display(refusal, subject);
                // Exact pin: any reworded sentence — verbatim or paraphrased —
                // changes the text and fails here.
                assert_eq!(
                    text, pinned,
                    "refusal text changed for {subject:?} {refusal:?}"
                );
                if carries_caveat {
                    assert!(text.contains(&caveat), "{text}");
                } else {
                    assert!(!text.contains(&caveat), "{text}");
                }
            }
            // The unexaminable-directory error uses the same label slot and
            // carries no review caveat (there is no field to review).
            let kind = std::io::ErrorKind::PermissionDenied;
            let text = UntrustedConfig::DirUnexaminable { kind, subject }.to_string();
            assert_eq!(
                text,
                format!(
                    "{} requires examining the config directory, which failed (PermissionDenied)",
                    subject.label()
                )
            );
            assert!(!text.contains(&caveat), "{text}");
        }
    }

    /// The whole-sentence literals for the `[egress_sets]`-only subject (#511).
    ///
    /// One of the eight new subjects, and the one a tools-and-sets-only user file
    /// produces. Written out whole rather than composed from `pinned_subject_slots`,
    /// so a composition bug cannot hide behind a table that agrees with itself.
    #[test]
    fn egress_sets_subject_display_is_byte_identical() {
        use AuthorityRefusal::*;
        let subject = AuthoritySubject::of(AuthorityTriggers {
            network: false,
            mounts: false,
            mount_sets: false,
            egress_sets: true,
        });
        for (refusal, pinned) in [
            (
                DirNotDirectory,
                "[egress_sets] refuses a config.toml whose directory is not a directory",
            ),
            (
                ThroughSymlink,
                "[egress_sets] requires config.toml to be a regular file, but it is reached through a symbolic link; its target may be writable by a guest or project, so review the [egress_sets] table before trusting the file (a symlinked config without [egress_sets] still works)",
            ),
            (
                FileWritable,
                "[egress_sets] refuses a group- or other-writable config.toml; a guest or another account may have written its [egress_sets] table, so review the [egress_sets] table before trusting the file (fixing the mode does not establish authorship)",
            ),
            (
                FileLinks(3),
                "[egress_sets] refuses a config.toml with 3 hard links; another name for it may be guest- or project-writable, so review the [egress_sets] table before trusting the file",
            ),
        ] {
            assert_eq!(
                UntrustedConfig::Refused { refusal, subject }.to_string(),
                pinned,
                "egress-sets refusal text changed for {refusal:?}"
            );
        }
        let kind = std::io::ErrorKind::PermissionDenied;
        assert_eq!(
            UntrustedConfig::DirUnexaminable { kind, subject }.to_string(),
            "[egress_sets] requires examining the config directory, which failed (PermissionDenied)"
        );
    }

    /// A44: the all-false trigger set names `[network]` in all three slots.
    ///
    /// The input is unreachable through [`verify`], but `of` is what a future
    /// caller would reuse, and an empty slot would render a refusal sentence with a
    /// missing word — a diagnostic that describes no file field at all.
    #[test]
    fn the_empty_trigger_set_names_network() {
        let subject = AuthoritySubject::of(AuthorityTriggers {
            network: false,
            mounts: false,
            mount_sets: false,
            egress_sets: false,
        });
        assert_eq!(subject.label(), "[network]");
        assert_eq!(subject.object(), "[network] table");
        assert_eq!(subject.without(), "[network]");
        assert_eq!(
            UntrustedConfig::Refused {
                refusal: AuthorityRefusal::FileWritable,
                subject,
            }
            .to_string(),
            "[network] refuses a group- or other-writable config.toml; a guest or another account may have written its [network] table, so review the [network] table before trusting the file (fixing the mode does not establish authorship)"
        );
    }

    /// The whole-sentence literals for the egress-reference subject (ADR-0059).
    ///
    /// A15b and A16 pin these bytes, and they are the *only* text a guest-planted
    /// tools-only symlink produces, so they are written out here rather than only
    /// composed from slots above.
    #[test]
    fn egress_reference_subject_display_is_byte_identical() {
        use AuthorityRefusal::*;
        let subject = AuthoritySubject::EgressReference;
        for (refusal, pinned) in [
            (
                ThroughSymlink,
                "an egress reference requires config.toml to be a regular file, but it is reached through a symbolic link; its target may be writable by a guest or project, so review the [[tools]] network_requests before trusting the file (a symlinked config without an egress reference still works)",
            ),
            (
                FileWritable,
                "an egress reference refuses a group- or other-writable config.toml; a guest or another account may have written its [[tools]] network_requests, so review the [[tools]] network_requests before trusting the file (fixing the mode does not establish authorship)",
            ),
            (
                FileLinks(2),
                "an egress reference refuses a config.toml with 2 hard links; another name for it may be guest- or project-writable, so review the [[tools]] network_requests before trusting the file",
            ),
        ] {
            assert_eq!(
                UntrustedConfig::Refused { refusal, subject }.to_string(),
                pinned,
                "egress-reference refusal text changed for {refusal:?}"
            );
        }
        let kind = std::io::ErrorKind::PermissionDenied;
        assert_eq!(
            UntrustedConfig::DirUnexaminable { kind, subject }.to_string(),
            "an egress reference requires examining the config directory, which failed (PermissionDenied)"
        );
    }

    fn oracle(reached: Reached, dir: DirFacts, euid: u32) -> Option<AuthorityRefusal> {
        use AuthorityRefusal::*;
        if !dir.is_dir {
            return Some(DirNotDirectory);
        }
        if dir.uid != euid {
            return Some(DirOwner);
        }
        if dir.mode & (0o020 | 0o002) != 0 {
            return Some(DirWritable);
        }
        match reached {
            Reached::ThroughSymlink => Some(ThroughSymlink),
            Reached::Direct(f) => {
                if f.uid != euid {
                    Some(FileOwner)
                } else if f.mode & (0o020 | 0o002) != 0 {
                    Some(FileWritable)
                } else if f.nlink == 1 {
                    None
                } else {
                    Some(FileLinks(f.nlink))
                }
            }
        }
    }

    #[test]
    fn refusal_matches_independent_oracle_table() {
        for is_dir in [false, true] {
            for dir_uid in [7, 8] {
                for dir_mode in [0o700, 0o720, 0o702, 0o775] {
                    for file_uid in [7, 8] {
                        for file_mode in [0o600, 0o620, 0o602, 0o664] {
                            for nlink in [0, 1, 2, u64::MAX] {
                                for reached in [
                                    Reached::ThroughSymlink,
                                    Reached::Direct(FileFacts {
                                        uid: file_uid,
                                        mode: file_mode,
                                        nlink,
                                    }),
                                ] {
                                    let dir = DirFacts {
                                        is_dir,
                                        uid: dir_uid,
                                        mode: dir_mode,
                                    };
                                    assert_eq!(
                                        authority_refusal(reached, dir, 7),
                                        oracle(reached, dir, 7)
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// The presence-not-contents rule, against an independent table.
    ///
    /// The oracle is an explicit `match` on all sixteen rows rather than a
    /// disjunction: written as `network || mounts || mount_sets || egress_sets` it
    /// would be the same expression as the contract, so a body that computed
    /// something else could only be caught by the proof. The all-false row is the
    /// one that keeps `egress_sets` from turning "declares nothing" into
    /// "authority-bearing".
    #[test]
    fn authority_required_matches_the_sixteen_rows() {
        for network in [false, true] {
            for mounts in [false, true] {
                for mount_sets in [false, true] {
                    for egress_sets in [false, true] {
                        let expected = match (network, mounts, mount_sets, egress_sets) {
                            (false, false, false, false) => false,
                            (false, false, false, true) => true,
                            (false, false, true, false) => true,
                            (false, false, true, true) => true,
                            (false, true, false, false) => true,
                            (false, true, false, true) => true,
                            (false, true, true, false) => true,
                            (false, true, true, true) => true,
                            (true, false, false, false) => true,
                            (true, false, false, true) => true,
                            (true, false, true, false) => true,
                            (true, false, true, true) => true,
                            (true, true, false, false) => true,
                            (true, true, false, true) => true,
                            (true, true, true, false) => true,
                            (true, true, true, true) => true,
                        };
                        assert_eq!(
                            authority_required(AuthorityTriggers {
                                network,
                                mounts,
                                mount_sets,
                                egress_sets
                            }),
                            expected,
                            "network={network} mounts={mounts} mount_sets={mount_sets} egress_sets={egress_sets}"
                        );
                    }
                }
            }
        }
    }

    /// The mount half of the presence rule, against an independent table.
    ///
    /// Four rows, and the oracle is an explicit `match` rather than the
    /// disjunction the contract uses, so a body computing something else is
    /// caught here as well as by the proof. `tool_field` alone is the row #396
    /// added: a file whose only mount list is inside a full `[[tools]]`
    /// definition is authority-bearing exactly like a defaults-only file.
    #[test]
    fn mount_authority_present_matches_four_rows() {
        for top_level in [false, true] {
            for tool_field in [false, true] {
                let expected = match (top_level, tool_field) {
                    (false, false) => false,
                    (false, true) => true,
                    (true, false) => true,
                    (true, true) => true,
                };
                assert_eq!(
                    mount_authority_present(MountAuthorityFacts {
                        top_level,
                        tool_field
                    }),
                    expected,
                    "top_level={top_level} tool_field={tool_field}"
                );
            }
        }
    }

    /// Every nonempty presence combination names a distinct sentence subject,
    /// and the subject names exactly the fields that are present. This is what
    /// keeps a `[mount_sets]`-only file from being described as a `mounts` file,
    /// and a `[egress_sets]`-only file from being described as a `[network]` one.
    #[test]
    fn subject_names_exactly_the_present_fields() {
        let mut labels = Vec::new();
        for network in [false, true] {
            for mounts in [false, true] {
                for mount_sets in [false, true] {
                    for egress_sets in [false, true] {
                        if !(network || mounts || mount_sets || egress_sets) {
                            continue;
                        }
                        let subject = AuthoritySubject::of(AuthorityTriggers {
                            network,
                            mounts,
                            mount_sets,
                            egress_sets,
                        });
                        let expected = match (network, mounts, mount_sets, egress_sets) {
                            (true, false, false, false) => "[network]",
                            (false, true, false, false) => "mounts",
                            (false, false, true, false) => "[mount_sets]",
                            (false, false, false, true) => "[egress_sets]",
                            (true, true, false, false) => "[network] and mounts",
                            (true, false, true, false) => "[network] and [mount_sets]",
                            (true, false, false, true) => "[network] and [egress_sets]",
                            (false, true, true, false) => "mounts and [mount_sets]",
                            (false, true, false, true) => "mounts and [egress_sets]",
                            (false, false, true, true) => "[mount_sets] and [egress_sets]",
                            (true, true, true, false) => "[network], mounts and [mount_sets]",
                            (true, true, false, true) => "[network], mounts and [egress_sets]",
                            (true, false, true, true) => {
                                "[network], [mount_sets] and [egress_sets]"
                            }
                            (false, true, true, true) => "mounts, [mount_sets] and [egress_sets]",
                            (true, true, true, true) => {
                                "[network], mounts, [mount_sets] and [egress_sets]"
                            }
                            (false, false, false, false) => unreachable!("skipped above"),
                        };
                        assert_eq!(subject.label(), expected);
                        labels.push(subject.label());
                    }
                }
            }
        }
        // Fifteen nonempty field combinations, and no two worded alike: a
        // collision would let one file's refusal describe another's fields.
        assert_eq!(labels.len(), 15);
        let mut distinct = labels.clone();
        distinct.sort();
        distinct.dedup();
        assert_eq!(distinct.len(), 15);
    }

    /// A file with no authority-bearing field is never refused, but the same
    /// read's verdict for a CLI egress reference is kept.
    ///
    /// The fixture's directory is world-writable, which the kernel refuses: so a
    /// passing load here can only come from presence staying the trigger. That is
    /// ADR-0040's compatibility rule — a tools/image-only config keeps working
    /// through a dotfile symlink — and ADR-0059's addition is that the *refusal*
    /// is retained, attributed to the reference, for a CLI `tool:NAME` to consult.
    #[test]
    fn verify_never_refuses_without_triggers_and_keeps_the_reference_verdict() {
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("open");
        fs::create_dir(&nested).unwrap();
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o777)).unwrap();
        let file = nested.join("config.toml");
        fs::write(&file, b"").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let read = read_bounded_regular_file_noting_symlink(&file, 100).unwrap();
        let none = AuthorityTriggers {
            network: false,
            mounts: false,
            mount_sets: false,
            egress_sets: false,
        };
        let verification = verify(&read, none).unwrap();
        assert!(verification.authorized.is_none());
        assert_eq!(verification.references.file(), file);
        // The positive half of A17: `Ok` load, no authority, a refusal retained.
        assert_eq!(
            verification.references.require().unwrap_err(),
            UntrustedConfig::Refused {
                refusal: AuthorityRefusal::DirWritable,
                subject: AuthoritySubject::EgressReference,
            }
        );
        for triggers in [
            AuthorityTriggers {
                network: true,
                mounts: false,
                mount_sets: false,
                egress_sets: false,
            },
            AuthorityTriggers {
                network: false,
                mounts: true,
                mount_sets: false,
                egress_sets: false,
            },
            AuthorityTriggers {
                network: false,
                mounts: false,
                mount_sets: true,
                egress_sets: false,
            },
            // #511: `[egress_sets]` alone is authority-bearing by presence, so a
            // sets-only file that is reached through a symlink is refused before
            // anything reads a definition.
            AuthorityTriggers {
                network: false,
                mounts: false,
                mount_sets: false,
                egress_sets: true,
            },
        ] {
            let error = verify(&read, triggers).unwrap_err().to_string();
            assert!(
                error.contains("directory is group- or other-writable"),
                "{error}"
            );
        }
    }

    /// A file that passes carries an unqualified verdict, so a CLI reference can
    /// resolve against it with no second measurement.
    #[test]
    fn passing_reads_mint_an_ok_reference_verdict() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("config.toml");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&file, b"").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let read = read_bounded_regular_file_noting_symlink(&file, 100).unwrap();
        for triggers in [
            AuthorityTriggers {
                network: false,
                mounts: false,
                mount_sets: false,
                egress_sets: false,
            },
            AuthorityTriggers {
                network: true,
                mounts: false,
                mount_sets: false,
                egress_sets: false,
            },
            AuthorityTriggers {
                network: false,
                mounts: false,
                mount_sets: false,
                egress_sets: true,
            },
        ] {
            let verification = verify(&read, triggers).unwrap();
            assert_eq!(verification.references.require(), Ok(()));
            assert_eq!(
                verification.authorized.is_some(),
                authority_required(triggers)
            );
        }
    }

    #[test]
    fn verify_verdicts_on_real_files() {
        if crate::host_paths::current_euid() == 0 {
            eprintln!(
                "foreign ownership fixture NOT RUN: running as root; kernel oracle covers ownership"
            );
        }
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("config.toml");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&file, b"[network]\n").unwrap();
        let triggers = AuthorityTriggers {
            network: true,
            mounts: false,
            mount_sets: false,
            egress_sets: false,
        };
        let load = || {
            let read = read_bounded_regular_file_noting_symlink(&file, 100).unwrap();
            assert_eq!(read.path(), file);
            assert_eq!(read.bytes(), b"[network]\n");
            verify(&read, triggers).map(|verification| verification.authorized.is_some())
        };
        assert!(load().unwrap());
        for mode in [0o600, 0o644, 0o664, 0o646] {
            fs::set_permissions(&file, fs::Permissions::from_mode(mode)).unwrap();
            if mode == 0o600 || mode == 0o644 {
                assert!(load().is_ok());
            } else {
                assert!(
                    load()
                        .unwrap_err()
                        .to_string()
                        .contains("group- or other-writable config.toml")
                );
            }
        }
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let alias = root.path().join("alias");
        fs::hard_link(&file, &alias).unwrap();
        assert!(load().unwrap_err().to_string().contains("2 hard links"));
        fs::remove_file(&alias).unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o775)).unwrap();
        assert!(
            load()
                .unwrap_err()
                .to_string()
                .contains("directory is group- or other-writable")
        );
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::rename(&file, &alias).unwrap();
        std::os::unix::fs::symlink(&alias, &file).unwrap();
        assert!(
            load()
                .unwrap_err()
                .to_string()
                .contains("reached through a symbolic link")
        );
    }

    proptest! {
        #[test]
        fn refusal_mode_mask_is_exactly_group_and_other_write(mode in any::<u32>()) {
            let writable = mode & 0o020 != 0 || mode & 0o002 != 0;
            let file = Reached::Direct(FileFacts { uid: 7, mode, nlink: 1 });
            let dir = DirFacts { is_dir: true, uid: 7, mode: 0o700 };
            prop_assert_eq!(authority_refusal(file, dir, 7),
                if writable { Some(AuthorityRefusal::FileWritable) } else { None });
            let file = Reached::Direct(FileFacts { uid: 7, mode: 0o600, nlink: 1 });
            let dir = DirFacts { mode, ..dir };
            prop_assert_eq!(authority_refusal(file, dir, 7),
                if writable { Some(AuthorityRefusal::DirWritable) } else { None });
        }
    }
}
