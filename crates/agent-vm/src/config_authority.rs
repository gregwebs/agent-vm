//! ADR-0040's verified read, generalised to every authority-bearing user field.
//!
//! The user config is shared by every project on the host, so a guest in one
//! project can plant a file that a later launch in another project reads. A
//! field that *grants* something — egress under ADR-0040, host mounts under
//! ADR-0046, named mount sets under ADR-0048 — may therefore only be taken from
//! bytes whose file and immediate directory this user owns, singly named, and
//! not group- or other-writable.
//!
//! **Presence, not contents, is what makes a file authority-bearing.** An empty
//! `[network]` table, an empty `mounts` array and an empty `[mount_sets]` table
//! grant nothing, yet all three are the bytes an attacker would plant: what is
//! being decided is whether the *file* is the user's own, so a caller that reads
//! contents to decide would skip the check on exactly the cheapest file to
//! plant. A file that declares `mount_sets` without `mounts` is therefore just as
//! authority-bearing as one that declares `mounts`.
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
use std::{fmt, os::unix::fs::MetadataExt, path::Path};

verus! {
/// Which authority-bearing fields one user file declares. Named facts rather
/// than adjacent booleans, so a call site cannot swap them.
#[derive(Clone, Copy, Debug)]
pub struct AuthorityTriggers { pub network: bool, pub mounts: bool, pub mount_sets: bool }

/// ADR-0040/0046/0048: presence, not contents, makes a user file
/// authority-bearing.
pub fn authority_required(t: AuthorityTriggers) -> (r: bool)
    ensures r == (t.network || t.mounts || t.mount_sets),
{
    if t.network { true } else { t.mounts || t.mount_sets }
}
} // verus!

/// The field(s) a refusal is about, so one refusal kernel can report itself
/// under `[network]`, under `mounts`, under `mount_sets`, or under any
/// combination of the three.
///
/// Only diagnostic wording depends on this; which refusals fire does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthoritySubject {
    Network,
    Mounts,
    MountSets,
    NetworkAndMounts,
    NetworkAndMountSets,
    MountsAndMountSets,
    NetworkMountsAndMountSets,
}

impl AuthoritySubject {
    // Three slots, because one sentence per refusal is assembled from three
    // grammatical positions and a subject fills each differently. Keeping the
    // tails in one `match` (see `write_refusal`) and the slots here is what lets
    // `[network]` and `mounts` stay byte-identical while `mount_sets` reuses the
    // sentence.

    /// Opens every refusal sentence.
    fn label(self) -> &'static str {
        match self {
            Self::Network => "[network]",
            Self::Mounts => "mounts",
            Self::MountSets => "[mount_sets]",
            Self::NetworkAndMounts => "[network] and mounts",
            Self::NetworkAndMountSets => "[network] and [mount_sets]",
            Self::MountsAndMountSets => "mounts and [mount_sets]",
            Self::NetworkMountsAndMountSets => "[network], mounts and [mount_sets]",
        }
    }

    /// What the reader is told to review before trusting the file.
    fn object(self) -> &'static str {
        match self {
            Self::Network => "[network] table",
            Self::Mounts => "mounts list",
            Self::MountSets => "[mount_sets] table",
            Self::NetworkAndMounts => "[network] table and mounts list",
            Self::NetworkAndMountSets => "[network] table and [mount_sets] table",
            Self::MountsAndMountSets => "mounts list and [mount_sets] table",
            Self::NetworkMountsAndMountSets => {
                "[network] table, mounts list and [mount_sets] table"
            }
        }
    }

    /// The "a symlinked config without …" aside names the fields, unqualified
    /// by "table"/"list", because it describes the file's compatibility. A file
    /// without `mounts` is *not* safe when it declares `mount_sets`.
    fn without(self) -> &'static str {
        match self {
            Self::Network => "[network]",
            Self::Mounts => "mounts",
            Self::MountSets => "[mount_sets]",
            Self::NetworkAndMounts => "[network] or mounts",
            Self::NetworkAndMountSets => "[network] or [mount_sets]",
            Self::MountsAndMountSets => "mounts or [mount_sets]",
            Self::NetworkMountsAndMountSets => "[network], mounts or [mount_sets]",
        }
    }

    /// Which subject a set of triggers is about.
    ///
    /// `(false, false, false)` is unreachable: callers only ask once
    /// [`authority_required`] has said yes. Naming the subject never decides
    /// anything, so it carries no kernel of its own; the `match` is exhaustive
    /// over the three measured facts with no catch-all arm.
    fn of(triggers: AuthorityTriggers) -> Self {
        match (triggers.network, triggers.mounts, triggers.mount_sets) {
            (false, false, false) => Self::Network,
            (true, false, false) => Self::Network,
            (false, true, false) => Self::Mounts,
            (false, false, true) => Self::MountSets,
            (true, true, false) => Self::NetworkAndMounts,
            (true, false, true) => Self::NetworkAndMountSets,
            (false, true, true) => Self::MountsAndMountSets,
            (true, true, true) => Self::NetworkMountsAndMountSets,
        }
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
#[derive(Debug)]
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
/// hostile file, and they are byte-pinned for the `Network` subject because
/// #394 changed nothing about persisted network authority.
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

/// Decide whether a verified read establishes authority, and mint the token the
/// authority-bearing parsers require.
///
/// `Ok(None)` means the file declares no authority-bearing field, so nothing is
/// measured: a tools/image-only config keeps working through a dotfile symlink
/// (ADR-0040's compatibility rule). This is the only I/O in the module and it
/// happens before any credential handling, runtime identity work or launch
/// state, because a caller loads config first.
pub(crate) fn verify<'a>(
    read: &'a VerifiedRead,
    triggers: AuthorityTriggers,
) -> Result<Option<AuthorizedConfig<'a>>, UntrustedConfig> {
    if !authority_required(triggers) {
        return Ok(None);
    }
    let subject = AuthoritySubject::of(triggers);
    let file = read.path();
    // Separate path observation, not anchored to the read descriptor; ancestors
    // remain trusted (ADR-0040's accepted gap).
    let parent = file.parent().ok_or(UntrustedConfig::DirUnexaminable {
        kind: std::io::ErrorKind::NotFound,
        subject,
    })?;
    let meta = std::fs::metadata(parent).map_err(|error| UntrustedConfig::DirUnexaminable {
        kind: error.kind(),
        subject,
    })?;
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
        Some(refusal) => Err(UntrustedConfig::Refused { refusal, subject }),
        None => Ok(Some(AuthorizedConfig { file })),
    }
}

fn raw_mode_u32(mode: rustix::fs::RawMode) -> u32 {
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

    const SUBJECTS: [AuthoritySubject; 7] = [
        AuthoritySubject::Network,
        AuthoritySubject::Mounts,
        AuthoritySubject::MountSets,
        AuthoritySubject::NetworkAndMounts,
        AuthoritySubject::NetworkAndMountSets,
        AuthoritySubject::MountsAndMountSets,
        AuthoritySubject::NetworkMountsAndMountSets,
    ];

    /// The three interchangeable slots one refusal sentence is assembled from,
    /// written out per subject.
    ///
    /// These are literals, so a subject whose wording changes fails here; the
    /// composition in `pinned_refusal_display` is a `format!` of the same shape
    /// as `write_refusal`, which is why the `Network` subject additionally has
    /// whole-sentence literals in `network_subject_display_is_byte_identical`.
    fn pinned_subject_slots(
        subject: AuthoritySubject,
    ) -> (&'static str, &'static str, &'static str) {
        match subject {
            AuthoritySubject::Network => ("[network]", "[network] table", "[network]"),
            AuthoritySubject::Mounts => ("mounts", "mounts list", "mounts"),
            AuthoritySubject::MountSets => ("[mount_sets]", "[mount_sets] table", "[mount_sets]"),
            AuthoritySubject::NetworkAndMounts => (
                "[network] and mounts",
                "[network] table and mounts list",
                "[network] or mounts",
            ),
            AuthoritySubject::NetworkAndMountSets => (
                "[network] and [mount_sets]",
                "[network] table and [mount_sets] table",
                "[network] or [mount_sets]",
            ),
            AuthoritySubject::MountsAndMountSets => (
                "mounts and [mount_sets]",
                "mounts list and [mount_sets] table",
                "mounts or [mount_sets]",
            ),
            AuthoritySubject::NetworkMountsAndMountSets => (
                "[network], mounts and [mount_sets]",
                "[network] table, mounts list and [mount_sets] table",
                "[network], mounts or [mount_sets]",
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
        let subject = AuthoritySubject::Network;
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
        for subject in SUBJECTS {
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
    /// The oracle is an explicit `match` on the eight rows rather than a
    /// disjunction: written as `network || mounts || mount_sets` it would be the
    /// same expression as the contract, so a body that computed something else
    /// could only be caught by the proof.
    #[test]
    fn authority_required_matches_the_eight_rows() {
        for network in [false, true] {
            for mounts in [false, true] {
                for mount_sets in [false, true] {
                    let expected = match (network, mounts, mount_sets) {
                        (false, false, false) => false,
                        (false, false, true) => true,
                        (false, true, false) => true,
                        (false, true, true) => true,
                        (true, false, false) => true,
                        (true, false, true) => true,
                        (true, true, false) => true,
                        (true, true, true) => true,
                    };
                    assert_eq!(
                        authority_required(AuthorityTriggers {
                            network,
                            mounts,
                            mount_sets
                        }),
                        expected,
                        "network={network} mounts={mounts} mount_sets={mount_sets}"
                    );
                }
            }
        }
    }

    /// Every nonempty presence combination names a distinct sentence subject,
    /// and the subject names exactly the fields that are present. This is what
    /// keeps a `[mount_sets]`-only file from being described as a `mounts` file.
    #[test]
    fn subject_names_exactly_the_present_fields() {
        for network in [false, true] {
            for mounts in [false, true] {
                for mount_sets in [false, true] {
                    if !(network || mounts || mount_sets) {
                        continue;
                    }
                    let subject = AuthoritySubject::of(AuthorityTriggers {
                        network,
                        mounts,
                        mount_sets,
                    });
                    let expected = match (network, mounts, mount_sets) {
                        (true, false, false) => "[network]",
                        (false, true, false) => "mounts",
                        (false, false, true) => "[mount_sets]",
                        (true, true, false) => "[network] and mounts",
                        (true, false, true) => "[network] and [mount_sets]",
                        (false, true, true) => "mounts and [mount_sets]",
                        (true, true, true) => "[network], mounts and [mount_sets]",
                        (false, false, false) => unreachable!("skipped above"),
                    };
                    assert_eq!(subject.label(), expected);
                }
            }
        }
    }

    /// A file with no authority-bearing field is never measured.
    ///
    /// The fixture's directory is world-writable, which the kernel refuses: so
    /// `Ok(None)` here can only come from `verify` not having looked at all.
    /// That is ADR-0040's compatibility rule — a tools/image-only config keeps
    /// working through a dotfile symlink.
    #[test]
    fn verify_measures_nothing_without_triggers() {
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
        };
        assert!(verify(&read, none).is_ok_and(|authorized| authorized.is_none()));
        for triggers in [
            AuthorityTriggers {
                network: true,
                mounts: false,
                mount_sets: false,
            },
            AuthorityTriggers {
                network: false,
                mounts: true,
                mount_sets: false,
            },
            AuthorityTriggers {
                network: false,
                mounts: false,
                mount_sets: true,
            },
        ] {
            let error = verify(&read, triggers).unwrap_err().to_string();
            assert!(
                error.contains("directory is group- or other-writable"),
                "{error}"
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
        };
        let load = || {
            let read = read_bounded_regular_file_noting_symlink(&file, 100).unwrap();
            assert_eq!(read.path(), file);
            assert_eq!(read.bytes(), b"[network]\n");
            verify(&read, triggers).map(|authorized| authorized.is_some())
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
