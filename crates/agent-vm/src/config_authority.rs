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
//! `[network]` table, an empty `mounts` array, an empty `[mount_sets]` table, an
//! empty `[egress_sets]` table and an empty `allow_tools` list grant nothing, yet
//! all five are the bytes an attacker would plant: what is being decided is
//! whether the *file* is the user's own, so a caller that reads contents to decide
//! would skip the check on exactly the cheapest file to plant. A file that declares `mount_sets` without `mounts` is therefore just as
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
//! authority-bearing field is present: a `set:NAME` egress reference is passed on
//! the command line, and a project `allow_tools` entry may select a `:trust`
//! tool — both decided *after* this read is gone, yet both must be decided by the
//! facts of the very read whose bytes supplied the definitions (ADR-0040 forbids
//! a second observation). So the measured verdict is kept beside the bytes it came
//! from, in a [`ReferenceTrust`] that carries its file and outlives the read.
//!
//! Refusal at *load* time is still decided by presence alone: only a file that
//! declares `[network]`, `mounts`, `[mount_sets]`, `[egress_sets]` or
//! `allow_tools` is refused for being untrusted, so a tools-only dotfile symlink
//! keeps loading exactly as before. The verdict is then read by either later
//! consumer: a CLI `set:NAME` reference, or a project `allow_tools` entry that
//! selects a `:trust` tool.
//!
//! # The project config (ADR-0073)
//!
//! The host-managed project config is measured on **every** present file, not
//! by the presence of a field. It is the root of a project's trust — `sources`,
//! `:trust` and `allow_tools` will all live in it — and it has no
//! dotfile-symlink compatibility to preserve, so a tools-only planted file is
//! already the attack.
//!
//! [`verify_project`] therefore reuses the same proved [`authority_refusal`]
//! kernel with `symlink_metadata(parent)`: a symlinked store directory is
//! refused as `DirNotDirectory` rather than followed. Its [`FinalComponent`]
//! comes from a no-follow open, so a final symlink is refused without the target
//! ever being opened or read. What this does *not* claim is unchanged from
//! ADR-0040: a concurrent host-side swap of a store directory between the route
//! check and `open` rests on the same stable-route assumption.

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
///
/// # Why the directory check is its own kernel
///
/// A writer must refuse an untrusted directory *before* it opens the lock file
/// inside it, and again under that lock (ADR-0065 Constraint 1). Both the launch
/// guard and the writer ask the same question, so it is spelled once here and
/// both call it.
pub fn authority_dir_refusal(dir: DirFacts, euid: u32) -> (r: Option<AuthorityRefusal>)
    ensures
        r.is_none() == dir_ok(dir, euid),
        !dir.is_dir ==> r == Some(AuthorityRefusal::DirNotDirectory),
        dir.is_dir && dir.uid != euid ==> r == Some(AuthorityRefusal::DirOwner),
        dir.is_dir && dir.uid == euid && others_may_write(dir.mode) ==> r == Some(AuthorityRefusal::DirWritable),
{
    if !dir.is_dir { return Some(AuthorityRefusal::DirNotDirectory); }
    if dir.uid != euid { return Some(AuthorityRefusal::DirOwner); }
    if dir.mode & 0o022 != 0 { return Some(AuthorityRefusal::DirWritable); }
    None
}

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
    if let Some(refusal) = authority_dir_refusal(dir, euid) { return Some(refusal); }
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
/// five-trigger contract and [`AuthoritySubject`] keeps its wording, so a file
/// whose only old authority field is `[network]` prints the same bytes as before.
pub fn mount_authority_present(f: MountAuthorityFacts) -> (r: bool)
    ensures r == (f.top_level || f.tool_field),
{
    if f.top_level { true } else { f.tool_field }
}

/// Which authority-bearing fields one user file declares. Named facts rather
/// than adjacent booleans, so a call site cannot swap them.
#[derive(Clone, Copy, Debug)]
pub struct AuthorityTriggers {
    pub network: bool,
    pub mounts: bool,
    pub mount_sets: bool,
    pub egress_sets: bool,
    pub allow_tools: bool,
}

/// ADR-0040/0046/0048/#511/#735: presence, not contents, makes a user file
/// authority-bearing. `t.mounts` is already the aggregate of the top-level
/// `mounts` array and every tool's `mounts` field ([`mount_authority_present`]).
pub fn authority_required(t: AuthorityTriggers) -> (r: bool)
    ensures r == (t.network || t.mounts || t.mount_sets || t.egress_sets || t.allow_tools),
{
    if t.network { true } else { t.mounts || t.mount_sets || t.egress_sets || t.allow_tools }
}
} // verus!

/// Which of the five authority-bearing fields one file declares, in the order
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
    /// #735: `allow_tools` is the fifth trigger. Its presence — `[]` included —
    /// means the file decides which declarations become launch verbs, so it must
    /// pass the same verified read as the four grant-bearing fields.
    allow_tools: bool,
}

/// The field(s) a refusal is about, so one refusal kernel can report itself
/// under any nonempty combination of `[network]`, `mounts`, `[mount_sets]` and
/// `[egress_sets]`.
///
/// Only diagnostic wording depends on this; which refusals fire does not. Held
/// as data rather than as one enum variant per combination: the slots are one
/// shared grammar (list the present fields, `and`/`or` before the last),
/// enumerating them would multiply with every future field, and a *folded*
/// subject — say, naming `[egress_sets]` under `[network]` — would send a reader
/// to review a table the file does not have (ADR-0040's #397 amendment).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthoritySubject {
    /// Never all-false: only [`Self::of`] builds one, and it normalizes the
    /// empty set.
    Fields(AuthorityFields),
    /// A CLI `set:NAME` egress reference resolves against the `[egress_sets]`
    /// table of the user file, so *that* is the field a file is being trusted
    /// for. Not a file field, so [`Self::of`] cannot return it. (#735 removed
    /// `tool:NAME`, which is why this subject now names a set table rather than
    /// `[[tools]] network_requests`.)
    EgressReference,
    /// #735: the project config authorizes a tool declared in a `:trust` source.
    /// The trusted file may declare none of the five triggers (a tools-only file
    /// loads through ADR-0040's compatibility rule), yet the project would hand
    /// its `mounts` and `network_requests` to a launch — so the project's
    /// selection needs that read's verdict, attributed to the definition it
    /// selects rather than to a user `allow_tools` list the file may not have.
    TrustedTool,
    /// ADR-0073: the host-managed project config is verified whatever it
    /// declares; it is the root of the project's trust, so there is no field
    /// whose absence makes a symlinked or shared file acceptable.
    ProjectConfig,
}

/// `(label, object, without)` per field, in the fixed order sentences name them.
const FIELD_PHRASES: [(&str, &str, &str); 5] = [
    ("[network]", "[network] table", "[network]"),
    ("mounts", "mounts list", "mounts"),
    ("[mount_sets]", "[mount_sets] table", "[mount_sets]"),
    ("[egress_sets]", "[egress_sets] table", "[egress_sets]"),
    ("allow_tools", "allow_tools list", "allow_tools"),
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
            Self::TrustedTool => "authorizing a :trust tool from the project config".to_owned(),
            Self::ProjectConfig => "the project config".to_owned(),
        }
    }

    /// What the reader is told to review before trusting the file.
    fn object(self) -> String {
        match self {
            Self::Fields(fields) => join_phrases(&fields.present(1), " and "),
            // Only `set:NAME` remains, so the table a reference reads is the
            // user file's own `[egress_sets]`.
            Self::EgressReference => "[egress_sets] table".to_owned(),
            Self::TrustedTool => "[[tools]] definition it selects".to_owned(),
            Self::ProjectConfig => "project config".to_owned(),
        }
    }

    /// The "a symlinked config without …" aside names the fields, unqualified
    /// by "table"/"list", because it describes the file's compatibility. A file
    /// without `mounts` is *not* safe when it declares `mount_sets`.
    ///
    /// `None` where no compatibility exists: the project tier (ADR-0073) has
    /// never accepted a symlink and a tools-only one is refused too, so
    /// claiming "a symlinked config without … still works" there would be
    /// false.
    fn without(self) -> Option<String> {
        match self {
            Self::Fields(fields) => Some(join_phrases(&fields.present(2), " or ")),
            Self::EgressReference => Some("an egress reference".to_owned()),
            // A symlinked file nothing selects still works: the trigger is the
            // project's selection, not the file's own bytes.
            Self::TrustedTool => Some("a project allow_tools entry naming its tools".to_owned()),
            Self::ProjectConfig => None,
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
    /// `EgressReference` and `TrustedTool` are deliberately unnameable here: a
    /// flag is not a file field, so a presence trigger can never be about one.
    fn of(triggers: AuthorityTriggers) -> Self {
        let fields = AuthorityFields {
            network: triggers.network,
            mounts: triggers.mounts,
            mount_sets: triggers.mount_sets,
            egress_sets: triggers.egress_sets,
            allow_tools: triggers.allow_tools,
        };
        if !(triggers.network
            || triggers.mounts
            || triggers.mount_sets
            || triggers.egress_sets
            || triggers.allow_tools)
        {
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
        let flags = [
            self.network,
            self.mounts,
            self.mount_sets,
            self.egress_sets,
            self.allow_tools,
        ];
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
        ThroughSymlink => {
            let aside = subject
                .without()
                .map(|without| format!(" (a symlinked config without {without} still works)"))
                .unwrap_or_default();
            write!(
                f,
                "{label} requires config.toml to be a regular file, but it is reached through a symbolic link; its target may be writable by a guest or project, so review the {object} before trusting the file{aside}"
            )
        }
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

/// The verified read's verdict for a *later* decision that depends on the same
/// bytes, owned so it can outlive the read that produced it (ADR-0059, #735).
///
/// Two callers need one measurement after `config::load` has dropped its
/// [`VerifiedRead`]: a CLI `set:NAME` reference, known only once argv is parsed,
/// and a project `allow_tools = ["home:x"]` entry, which hands a tools-only
/// `:trust` file's `mounts` and `network_requests` to a launch. Re-reading or
/// re-measuring at that point would decide from a second observation, so the
/// measurement from the read whose bytes supplied the definitions is carried here.
///
/// The file is stored with the measurement and never supplied separately, so a
/// verdict for one file cannot be paired with another file's tools.
///
/// Private fields: only [`verify`] mints one that vouches for anything, and the
/// measurement is *unattributed* — [`Self::require`] and
/// [`Self::require_for_trusted_tool`] name the two different subjects the same
/// measurement is reported under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReferenceTrust {
    file: PathBuf,
    measurement: Result<(), Measurement>,
}

impl ReferenceTrust {
    pub(crate) fn file(&self) -> &Path {
        &self.file
    }

    /// The verdict, with no second check: the value is what the read measured.
    /// Attributed to a CLI egress reference, which is what the callers are.
    pub(crate) fn require(&self) -> Result<(), UntrustedConfig> {
        self.measurement
            .map_err(|measurement| measurement.into_untrusted(AuthoritySubject::EgressReference))
    }

    /// The same verdict, attributed to the *definition* a project `allow_tools`
    /// entry selects from this file.
    ///
    /// A separate reader rather than a caller-side re-attribution: a tools-only
    /// `:trust` file declares no trigger of its own, so it loads without a token
    /// and the only thing standing between a guest-writable dotfile target and a
    /// project-authorized launch is this check naming the right field.
    pub(crate) fn require_for_trusted_tool(&self) -> Result<(), UntrustedConfig> {
        self.measurement
            .map_err(|measurement| measurement.into_untrusted(AuthoritySubject::TrustedTool))
    }

    #[cfg(test)]
    pub(crate) fn verified_for_test(file: &Path) -> Self {
        Self {
            file: file.to_owned(),
            measurement: Ok(()),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test_untrusted(file: &Path, refusal: Measurement) -> Self {
        Self {
            file: file.to_owned(),
            measurement: Err(refusal),
        }
    }
}

/// What one read's measurements said, before it is attributed to a field.
///
/// Private: it is an intermediate of [`verify`], never a decision a caller can
/// hold. Attribution is separate because the *same* measurement is reported
/// under the field that made the file authority-bearing, under
/// [`AuthoritySubject::EgressReference`] when a CLI reference asks, and under
/// [`AuthoritySubject::TrustedTool`] when a project authorization asks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Measurement {
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
        // tools-only symlink loads as before. The verdict is consulted later, by a
        // CLI reference or a project `allow_tools` entry, through `require()` and
        // `require_for_trusted_tool()` before either resolves a name.
        return Ok(Verification {
            authorized: None,
            references: ReferenceTrust {
                file: file.to_owned(),
                measurement: measured,
            },
        });
    }
    measured.map_err(|measurement| measurement.into_untrusted(AuthoritySubject::of(triggers)))?;
    Ok(Verification {
        authorized: Some(AuthorizedConfig { file }),
        references: ReferenceTrust {
            file: file.to_owned(),
            measurement: Ok(()),
        },
    })
}

/// ADR-0040's measurements: the immediate directory's `metadata`, the read's own
/// final-component facts and the effective uid, handed to the proved kernel.
fn measure(read: &VerifiedRead) -> Result<(), Measurement> {
    measure_facts(read.path(), read.final_component(), true)
}

/// One measurement policy, two tiers.
///
/// `follow_parent` is the only difference and it is the whole of ADR-0040's
/// dotfile compatibility: the user tier follows a symlinked immediate directory,
/// the project store (ADR-0073) does not, because `projects/<id>` being a
/// symlink is exactly how a store route could redirect the read elsewhere.
fn measure_facts(
    file: &Path,
    final_component: &FinalComponent,
    follow_parent: bool,
) -> Result<(), Measurement> {
    // Separate path observation, not anchored to the read descriptor; ancestors
    // remain trusted (ADR-0040's accepted gap).
    let parent = file
        .parent()
        .ok_or(Measurement::DirUnexaminable(std::io::ErrorKind::NotFound))?;
    let parent_metadata = if follow_parent {
        std::fs::metadata(parent)
    } else {
        std::fs::symlink_metadata(parent)
    };
    let meta = parent_metadata.map_err(|error| Measurement::DirUnexaminable(error.kind()))?;
    let dir = DirFacts {
        is_dir: meta.is_dir(),
        uid: meta.uid(),
        mode: meta.mode(),
    };
    let reached = match final_component {
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

/// ADR-0073: the project tier's verification. Reuses the proved
/// [`authority_refusal`] kernel with `symlink_metadata(parent)` (no parent
/// symlink following) and no presence trigger. Takes the path and
/// [`FinalComponent`] from a no-follow open
/// (`host_paths::open_regular_no_follow_checkpointed`), so a final symlink is
/// refused without ever opening or reading its target, and no
/// [`AuthorizedConfig`] is minted because the project tier still parses no
/// authority-bearing field (`config::refuse_project_authority`).
pub(crate) fn verify_project(
    path: &Path,
    final_component: &FinalComponent,
) -> Result<(), UntrustedConfig> {
    measure_facts(path, final_component, false)
        .map_err(|measurement| measurement.into_untrusted(AuthoritySubject::ProjectConfig))
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

    /// Every subject a refusal can be built for: the thirty-one nonempty field
    /// combinations, then ADR-0059's reference subject and #735's two.
    fn every_subject() -> Vec<AuthoritySubject> {
        let mut subjects = Vec::new();
        for network in [false, true] {
            for mounts in [false, true] {
                for mount_sets in [false, true] {
                    for egress_sets in [false, true] {
                        for allow_tools in [false, true] {
                            if network || mounts || mount_sets || egress_sets || allow_tools {
                                subjects.push(AuthoritySubject::of(AuthorityTriggers {
                                    network,
                                    mounts,
                                    mount_sets,
                                    egress_sets,
                                    allow_tools,
                                }));
                            }
                        }
                    }
                }
            }
        }
        subjects.push(AuthoritySubject::EgressReference);
        subjects.push(AuthoritySubject::TrustedTool);
        subjects.push(AuthoritySubject::ProjectConfig);
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
    ) -> (&'static str, &'static str, Option<&'static str>) {
        match subject {
            AuthoritySubject::Fields(fields) => match (
                fields.network,
                fields.mounts,
                fields.mount_sets,
                fields.egress_sets,
                fields.allow_tools,
            ) {
                (false, false, false, false, true) => {
                    ("allow_tools", "allow_tools list", Some("allow_tools"))
                }
                (false, false, false, true, false) => (
                    "[egress_sets]",
                    "[egress_sets] table",
                    Some("[egress_sets]"),
                ),
                (false, false, false, true, true) => (
                    "[egress_sets] and allow_tools",
                    "[egress_sets] table and allow_tools list",
                    Some("[egress_sets] or allow_tools"),
                ),
                (false, false, true, false, false) => {
                    ("[mount_sets]", "[mount_sets] table", Some("[mount_sets]"))
                }
                (false, false, true, false, true) => (
                    "[mount_sets] and allow_tools",
                    "[mount_sets] table and allow_tools list",
                    Some("[mount_sets] or allow_tools"),
                ),
                (false, false, true, true, false) => (
                    "[mount_sets] and [egress_sets]",
                    "[mount_sets] table and [egress_sets] table",
                    Some("[mount_sets] or [egress_sets]"),
                ),
                (false, false, true, true, true) => (
                    "[mount_sets], [egress_sets] and allow_tools",
                    "[mount_sets] table, [egress_sets] table and allow_tools list",
                    Some("[mount_sets], [egress_sets] or allow_tools"),
                ),
                (false, true, false, false, false) => ("mounts", "mounts list", Some("mounts")),
                (false, true, false, false, true) => (
                    "mounts and allow_tools",
                    "mounts list and allow_tools list",
                    Some("mounts or allow_tools"),
                ),
                (false, true, false, true, false) => (
                    "mounts and [egress_sets]",
                    "mounts list and [egress_sets] table",
                    Some("mounts or [egress_sets]"),
                ),
                (false, true, false, true, true) => (
                    "mounts, [egress_sets] and allow_tools",
                    "mounts list, [egress_sets] table and allow_tools list",
                    Some("mounts, [egress_sets] or allow_tools"),
                ),
                (false, true, true, false, false) => (
                    "mounts and [mount_sets]",
                    "mounts list and [mount_sets] table",
                    Some("mounts or [mount_sets]"),
                ),
                (false, true, true, false, true) => (
                    "mounts, [mount_sets] and allow_tools",
                    "mounts list, [mount_sets] table and allow_tools list",
                    Some("mounts, [mount_sets] or allow_tools"),
                ),
                (false, true, true, true, false) => (
                    "mounts, [mount_sets] and [egress_sets]",
                    "mounts list, [mount_sets] table and [egress_sets] table",
                    Some("mounts, [mount_sets] or [egress_sets]"),
                ),
                (false, true, true, true, true) => (
                    "mounts, [mount_sets], [egress_sets] and allow_tools",
                    "mounts list, [mount_sets] table, [egress_sets] table and allow_tools list",
                    Some("mounts, [mount_sets], [egress_sets] or allow_tools"),
                ),
                (true, false, false, false, false) => {
                    ("[network]", "[network] table", Some("[network]"))
                }
                (true, false, false, false, true) => (
                    "[network] and allow_tools",
                    "[network] table and allow_tools list",
                    Some("[network] or allow_tools"),
                ),
                (true, false, false, true, false) => (
                    "[network] and [egress_sets]",
                    "[network] table and [egress_sets] table",
                    Some("[network] or [egress_sets]"),
                ),
                (true, false, false, true, true) => (
                    "[network], [egress_sets] and allow_tools",
                    "[network] table, [egress_sets] table and allow_tools list",
                    Some("[network], [egress_sets] or allow_tools"),
                ),
                (true, false, true, false, false) => (
                    "[network] and [mount_sets]",
                    "[network] table and [mount_sets] table",
                    Some("[network] or [mount_sets]"),
                ),
                (true, false, true, false, true) => (
                    "[network], [mount_sets] and allow_tools",
                    "[network] table, [mount_sets] table and allow_tools list",
                    Some("[network], [mount_sets] or allow_tools"),
                ),
                (true, false, true, true, false) => (
                    "[network], [mount_sets] and [egress_sets]",
                    "[network] table, [mount_sets] table and [egress_sets] table",
                    Some("[network], [mount_sets] or [egress_sets]"),
                ),
                (true, false, true, true, true) => (
                    "[network], [mount_sets], [egress_sets] and allow_tools",
                    "[network] table, [mount_sets] table, [egress_sets] table and allow_tools list",
                    Some("[network], [mount_sets], [egress_sets] or allow_tools"),
                ),
                (true, true, false, false, false) => (
                    "[network] and mounts",
                    "[network] table and mounts list",
                    Some("[network] or mounts"),
                ),
                (true, true, false, false, true) => (
                    "[network], mounts and allow_tools",
                    "[network] table, mounts list and allow_tools list",
                    Some("[network], mounts or allow_tools"),
                ),
                (true, true, false, true, false) => (
                    "[network], mounts and [egress_sets]",
                    "[network] table, mounts list and [egress_sets] table",
                    Some("[network], mounts or [egress_sets]"),
                ),
                (true, true, false, true, true) => (
                    "[network], mounts, [egress_sets] and allow_tools",
                    "[network] table, mounts list, [egress_sets] table and allow_tools list",
                    Some("[network], mounts, [egress_sets] or allow_tools"),
                ),
                (true, true, true, false, false) => (
                    "[network], mounts and [mount_sets]",
                    "[network] table, mounts list and [mount_sets] table",
                    Some("[network], mounts or [mount_sets]"),
                ),
                (true, true, true, false, true) => (
                    "[network], mounts, [mount_sets] and allow_tools",
                    "[network] table, mounts list, [mount_sets] table and allow_tools list",
                    Some("[network], mounts, [mount_sets] or allow_tools"),
                ),
                (true, true, true, true, false) => (
                    "[network], mounts, [mount_sets] and [egress_sets]",
                    "[network] table, mounts list, [mount_sets] table and [egress_sets] table",
                    Some("[network], mounts, [mount_sets] or [egress_sets]"),
                ),
                (true, true, true, true, true) => (
                    "[network], mounts, [mount_sets], [egress_sets] and allow_tools",
                    "[network] table, mounts list, [mount_sets] table, [egress_sets] table and allow_tools list",
                    Some("[network], mounts, [mount_sets], [egress_sets] or allow_tools"),
                ),
                (false, false, false, false, false) => {
                    unreachable!("`of` normalizes the empty trigger set")
                }
            },
            // ADR-0059/#735: not a file field, so all three slots say the same
            // thing — what a `set:NAME` reference needs the file for.
            AuthoritySubject::EgressReference => (
                "an egress reference",
                "[egress_sets] table",
                Some("an egress reference"),
            ),
            // #735: the trigger is the project's selection, so the
            // compatibility aside describes a file nothing selects.
            AuthoritySubject::TrustedTool => (
                "authorizing a :trust tool from the project config",
                "[[tools]] definition it selects",
                Some("a project allow_tools entry naming its tools"),
            ),
            // ADR-0073: no field made the file authority-bearing, so there is
            // no "without …" compatibility to claim.
            AuthoritySubject::ProjectConfig => ("the project config", "project config", None),
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
            ThroughSymlink => {
                let aside = without
                    .map(|without| format!(" (a symlinked config without {without} still works)"))
                    .unwrap_or_default();
                (
                    format!(
                        "{label} requires config.toml to be a regular file, but it is reached through a symbolic link; its target may be writable by a guest or project, so review the {object} before trusting the file{aside}"
                    ),
                    true,
                )
            }
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
            allow_tools: false,
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
            allow_tools: false,
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
            allow_tools: false,
        });
        assert_eq!(subject.label(), "[network]");
        assert_eq!(subject.object(), "[network] table");
        assert_eq!(subject.without(), Some("[network]".to_owned()));
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
                "an egress reference requires config.toml to be a regular file, but it is reached through a symbolic link; its target may be writable by a guest or project, so review the [egress_sets] table before trusting the file (a symlinked config without an egress reference still works)",
            ),
            (
                FileWritable,
                "an egress reference refuses a group- or other-writable config.toml; a guest or another account may have written its [egress_sets] table, so review the [egress_sets] table before trusting the file (fixing the mode does not establish authorship)",
            ),
            (
                FileLinks(2),
                "an egress reference refuses a config.toml with 2 hard links; another name for it may be guest- or project-writable, so review the [egress_sets] table before trusting the file",
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

    /// The whole-sentence literals for the `allow_tools`-only subject (#735).
    ///
    /// The fifth trigger's own wording, written out whole: a user file whose only
    /// authority field is an `allow_tools` list is refused under *this* subject,
    /// and every one of these sentences is the only thing the reader sees.
    #[test]
    fn allow_tools_subject_display_is_byte_identical() {
        use AuthorityRefusal::*;
        let subject = AuthoritySubject::of(AuthorityTriggers {
            network: false,
            mounts: false,
            mount_sets: false,
            egress_sets: false,
            allow_tools: true,
        });
        for (refusal, pinned) in [
            (
                DirNotDirectory,
                "allow_tools refuses a config.toml whose directory is not a directory",
            ),
            (
                ThroughSymlink,
                "allow_tools requires config.toml to be a regular file, but it is reached through a symbolic link; its target may be writable by a guest or project, so review the allow_tools list before trusting the file (a symlinked config without allow_tools still works)",
            ),
            (
                FileWritable,
                "allow_tools refuses a group- or other-writable config.toml; a guest or another account may have written its allow_tools list, so review the allow_tools list before trusting the file (fixing the mode does not establish authorship)",
            ),
            (
                FileLinks(2),
                "allow_tools refuses a config.toml with 2 hard links; another name for it may be guest- or project-writable, so review the allow_tools list before trusting the file",
            ),
        ] {
            assert_eq!(
                UntrustedConfig::Refused { refusal, subject }.to_string(),
                pinned,
                "allow-tools refusal text changed for {refusal:?}"
            );
        }
        let kind = std::io::ErrorKind::PermissionDenied;
        assert_eq!(
            UntrustedConfig::DirUnexaminable { kind, subject }.to_string(),
            "allow_tools requires examining the config directory, which failed (PermissionDenied)"
        );
    }

    /// The whole-sentence literals for #735's trusted-tool subject.
    ///
    /// A project `allow_tools = ["home:x"]` against a tools-only `:trust` file is
    /// refused under this subject, and the sentence must name the definition the
    /// project selected rather than a user `allow_tools` list the file does not
    /// have.
    #[test]
    fn trusted_tool_subject_display_is_byte_identical() {
        use AuthorityRefusal::*;
        let subject = AuthoritySubject::TrustedTool;
        for (refusal, pinned) in [
            (
                ThroughSymlink,
                "authorizing a :trust tool from the project config requires config.toml to be a regular file, but it is reached through a symbolic link; its target may be writable by a guest or project, so review the [[tools]] definition it selects before trusting the file (a symlinked config without a project allow_tools entry naming its tools still works)",
            ),
            (
                FileLinks(2),
                "authorizing a :trust tool from the project config refuses a config.toml with 2 hard links; another name for it may be guest- or project-writable, so review the [[tools]] definition it selects before trusting the file",
            ),
        ] {
            assert_eq!(
                UntrustedConfig::Refused { refusal, subject }.to_string(),
                pinned,
                "trusted-tool refusal text changed for {refusal:?}"
            );
        }
    }

    /// The two readers over one measurement attribute the *same* refusal to their
    /// own subject, and neither re-measures. Dropping one attribution is what
    /// `allow-tools-trusted-verdict-bypassed` kills.
    #[test]
    fn one_measurement_has_two_attributions() {
        let file = Path::new("/home/u/.config/agent-vm/config.toml");
        let trust = ReferenceTrust::for_test_untrusted(
            file,
            Measurement::Refused(AuthorityRefusal::ThroughSymlink),
        );
        assert_eq!(
            trust.require(),
            Err(UntrustedConfig::Refused {
                refusal: AuthorityRefusal::ThroughSymlink,
                subject: AuthoritySubject::EgressReference,
            })
        );
        assert_eq!(
            trust.require_for_trusted_tool(),
            Err(UntrustedConfig::Refused {
                refusal: AuthorityRefusal::ThroughSymlink,
                subject: AuthoritySubject::TrustedTool,
            })
        );
        assert_eq!(trust.file(), file);
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

    /// The writer's directory-only kernel, against its own independent table.
    ///
    /// `authority_refusal` delegates to it, so a row that changed here would move
    /// both callers; the oracle is written out rather than calling `dir_ok`, so a
    /// table that agrees with itself cannot pass.
    #[test]
    fn authority_dir_refusal_table_matches_oracle() {
        fn dir_oracle(dir: DirFacts, euid: u32) -> Option<AuthorityRefusal> {
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
            None
        }
        for is_dir in [false, true] {
            for uid in [7, 8] {
                for mode in [0o700, 0o720, 0o702, 0o770, 0o775, 0o777, 0o600] {
                    let dir = DirFacts { is_dir, uid, mode };
                    assert_eq!(
                        authority_dir_refusal(dir, 7),
                        dir_oracle(dir, 7),
                        "is_dir {is_dir}, uid {uid}, mode {mode:o}"
                    );
                }
            }
        }
    }

    /// The file half is untouched: a trusted directory answers exactly as before,
    /// and the directory kernel is what decides the directory half.
    #[test]
    fn authority_refusal_delegates_the_directory_half() {
        let trusted = DirFacts {
            is_dir: true,
            uid: 7,
            mode: 0o700,
        };
        let file = FileFacts {
            uid: 7,
            mode: 0o600,
            nlink: 1,
        };
        assert_eq!(authority_refusal(Reached::Direct(file), trusted, 7), None);
        let untrusted = DirFacts {
            is_dir: true,
            uid: 7,
            mode: 0o770,
        };
        assert_eq!(
            authority_refusal(Reached::Direct(file), untrusted, 7),
            Some(AuthorityRefusal::DirWritable)
        );
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
    /// The oracle is an explicit `match` on all thirty-two rows rather than a
    /// disjunction: written as `network || mounts || mount_sets || egress_sets ||
    /// allow_tools` it would be the same expression as the contract, so a body
    /// that computed something else could only be caught by the proof. The
    /// all-false row is the one that keeps the fifth trigger (#735's
    /// `allow_tools`) from turning "declares nothing" into "authority-bearing".
    #[test]
    fn authority_required_matches_the_thirty_two_rows() {
        for network in [false, true] {
            for mounts in [false, true] {
                for mount_sets in [false, true] {
                    for egress_sets in [false, true] {
                        for allow_tools in [false, true] {
                            let expected =
                                match (network, mounts, mount_sets, egress_sets, allow_tools) {
                                    (false, false, false, false, false) => false,
                                    (false, false, false, false, true) => true,
                                    (false, false, false, true, false) => true,
                                    (false, false, false, true, true) => true,
                                    (false, false, true, false, false) => true,
                                    (false, false, true, false, true) => true,
                                    (false, false, true, true, false) => true,
                                    (false, false, true, true, true) => true,
                                    (false, true, false, false, false) => true,
                                    (false, true, false, false, true) => true,
                                    (false, true, false, true, false) => true,
                                    (false, true, false, true, true) => true,
                                    (false, true, true, false, false) => true,
                                    (false, true, true, false, true) => true,
                                    (false, true, true, true, false) => true,
                                    (false, true, true, true, true) => true,
                                    (true, false, false, false, false) => true,
                                    (true, false, false, false, true) => true,
                                    (true, false, false, true, false) => true,
                                    (true, false, false, true, true) => true,
                                    (true, false, true, false, false) => true,
                                    (true, false, true, false, true) => true,
                                    (true, false, true, true, false) => true,
                                    (true, false, true, true, true) => true,
                                    (true, true, false, false, false) => true,
                                    (true, true, false, false, true) => true,
                                    (true, true, false, true, false) => true,
                                    (true, true, false, true, true) => true,
                                    (true, true, true, false, false) => true,
                                    (true, true, true, false, true) => true,
                                    (true, true, true, true, false) => true,
                                    (true, true, true, true, true) => true,
                                };
                            assert_eq!(
                                authority_required(AuthorityTriggers {
                                    network,
                                    mounts,
                                    mount_sets,
                                    egress_sets,
                                    allow_tools,
                                }),
                                expected,
                                "network={network} mounts={mounts} mount_sets={mount_sets} \
                                 egress_sets={egress_sets} allow_tools={allow_tools}"
                            );
                        }
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
                        for allow_tools in [false, true] {
                            if !(network || mounts || mount_sets || egress_sets || allow_tools) {
                                continue;
                            }
                            let subject = AuthoritySubject::of(AuthorityTriggers {
                                network,
                                mounts,
                                mount_sets,
                                egress_sets,
                                allow_tools,
                            });
                            let expected = match (
                                network,
                                mounts,
                                mount_sets,
                                egress_sets,
                                allow_tools,
                            ) {
                                (false, false, false, false, true) => "allow_tools",
                                (false, false, false, true, false) => "[egress_sets]",
                                (false, false, false, true, true) => {
                                    "[egress_sets] and allow_tools"
                                }
                                (false, false, true, false, false) => "[mount_sets]",
                                (false, false, true, false, true) => "[mount_sets] and allow_tools",
                                (false, false, true, true, false) => {
                                    "[mount_sets] and [egress_sets]"
                                }
                                (false, false, true, true, true) => {
                                    "[mount_sets], [egress_sets] and allow_tools"
                                }
                                (false, true, false, false, false) => "mounts",
                                (false, true, false, false, true) => "mounts and allow_tools",
                                (false, true, false, true, false) => "mounts and [egress_sets]",
                                (false, true, false, true, true) => {
                                    "mounts, [egress_sets] and allow_tools"
                                }
                                (false, true, true, false, false) => "mounts and [mount_sets]",
                                (false, true, true, false, true) => {
                                    "mounts, [mount_sets] and allow_tools"
                                }
                                (false, true, true, true, false) => {
                                    "mounts, [mount_sets] and [egress_sets]"
                                }
                                (false, true, true, true, true) => {
                                    "mounts, [mount_sets], [egress_sets] and allow_tools"
                                }
                                (true, false, false, false, false) => "[network]",
                                (true, false, false, false, true) => "[network] and allow_tools",
                                (true, false, false, true, false) => "[network] and [egress_sets]",
                                (true, false, false, true, true) => {
                                    "[network], [egress_sets] and allow_tools"
                                }
                                (true, false, true, false, false) => "[network] and [mount_sets]",
                                (true, false, true, false, true) => {
                                    "[network], [mount_sets] and allow_tools"
                                }
                                (true, false, true, true, false) => {
                                    "[network], [mount_sets] and [egress_sets]"
                                }
                                (true, false, true, true, true) => {
                                    "[network], [mount_sets], [egress_sets] and allow_tools"
                                }
                                (true, true, false, false, false) => "[network] and mounts",
                                (true, true, false, false, true) => {
                                    "[network], mounts and allow_tools"
                                }
                                (true, true, false, true, false) => {
                                    "[network], mounts and [egress_sets]"
                                }
                                (true, true, false, true, true) => {
                                    "[network], mounts, [egress_sets] and allow_tools"
                                }
                                (true, true, true, false, false) => {
                                    "[network], mounts and [mount_sets]"
                                }
                                (true, true, true, false, true) => {
                                    "[network], mounts, [mount_sets] and allow_tools"
                                }
                                (true, true, true, true, false) => {
                                    "[network], mounts, [mount_sets] and [egress_sets]"
                                }
                                (true, true, true, true, true) => {
                                    "[network], mounts, [mount_sets], [egress_sets] and allow_tools"
                                }
                                (false, false, false, false, false) => {
                                    unreachable!("skipped above")
                                }
                            };
                            assert_eq!(subject.label(), expected);
                            labels.push(subject.label());
                        }
                    }
                }
            }
        }
        // Thirty-one nonempty field combinations, and no two worded alike: a
        // collision would let one file's refusal describe another's fields.
        assert_eq!(labels.len(), 31);
        let mut distinct = labels.clone();
        distinct.sort();
        distinct.dedup();
        assert_eq!(distinct.len(), 31);
    }

    /// A file with no authority-bearing field is never refused, but the same
    /// read's verdict for a CLI egress reference is kept.
    ///
    /// The fixture's directory is world-writable, which the kernel refuses: so a
    /// passing load here can only come from presence staying the trigger. That is
    /// ADR-0040's compatibility rule — a tools/image-only config keeps working
    /// through a dotfile symlink — and ADR-0059's addition is that the *refusal*
    /// is retained, attributed to the reference, for a CLI `set:NAME` to consult.
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
            allow_tools: false,
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
                allow_tools: false,
            },
            AuthorityTriggers {
                network: false,
                mounts: true,
                mount_sets: false,
                egress_sets: false,
                allow_tools: false,
            },
            AuthorityTriggers {
                network: false,
                mounts: false,
                mount_sets: true,
                egress_sets: false,
                allow_tools: false,
            },
            // #511: `[egress_sets]` alone is authority-bearing by presence, so a
            // sets-only file that is reached through a symlink is refused before
            // anything reads a definition.
            AuthorityTriggers {
                network: false,
                mounts: false,
                mount_sets: false,
                egress_sets: true,
                allow_tools: false,
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
                allow_tools: false,
            },
            AuthorityTriggers {
                network: true,
                mounts: false,
                mount_sets: false,
                egress_sets: false,
                allow_tools: false,
            },
            AuthorityTriggers {
                network: false,
                mounts: false,
                mount_sets: false,
                egress_sets: true,
                allow_tools: false,
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
            allow_tools: false,
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

    /// The whole-sentence literals for the project-config subject (ADR-0073).
    ///
    /// The project tier has no presence trigger, so every sentence here is the
    /// only thing a user sees when their host-managed file is refused. Written
    /// out whole so a change to a slot and to the composition cannot cancel.
    #[test]
    fn project_config_subject_display_is_byte_identical() {
        use AuthorityRefusal::*;
        let subject = AuthoritySubject::ProjectConfig;
        for (refusal, pinned) in [
            (
                DirNotDirectory,
                "the project config refuses a config.toml whose directory is not a directory",
            ),
            (
                DirOwner,
                "the project config refuses a config.toml whose directory is owned by another user; review the project config before trusting the file",
            ),
            (
                DirWritable,
                "the project config refuses a config.toml whose directory is group- or other-writable; a guest or another account may be able to replace the file, so review the project config before trusting it",
            ),
            (
                ThroughSymlink,
                "the project config requires config.toml to be a regular file, but it is reached through a symbolic link; its target may be writable by a guest or project, so review the project config before trusting the file",
            ),
            (
                FileOwner,
                "the project config refuses a config.toml owned by another user; review the project config before trusting the file",
            ),
            (
                FileWritable,
                "the project config refuses a group- or other-writable config.toml; a guest or another account may have written its project config, so review the project config before trusting the file (fixing the mode does not establish authorship)",
            ),
            (
                FileLinks(2),
                "the project config refuses a config.toml with 2 hard links; another name for it may be guest- or project-writable, so review the project config before trusting the file",
            ),
        ] {
            assert_eq!(
                UntrustedConfig::Refused { refusal, subject }.to_string(),
                pinned,
                "project-config refusal text changed for {refusal:?}"
            );
        }
        let kind = std::io::ErrorKind::PermissionDenied;
        assert_eq!(
            UntrustedConfig::DirUnexaminable { kind, subject }.to_string(),
            "the project config requires examining the config directory, which failed (PermissionDenied)"
        );
    }

    /// Opens `path` without following a final symlink, and returns what
    /// [`verify_project`] decides about the facts that open produced.
    fn verify_project_at(path: &Path) -> Result<(), UntrustedConfig> {
        match crate::host_paths::open_regular_no_follow_checkpointed(path, || {})
            .expect("opening the fixture")
        {
            Some(opened) => verify_project(path, &FinalComponent::Regular(opened.facts())),
            None => verify_project(path, &FinalComponent::Symlink),
        }
    }

    /// One mutation per fixture, each on a real file: a defect that skipped a
    /// check would have to survive the shape it is meant to refuse.
    #[test]
    fn verify_project_refuses_every_unsafe_shape_on_real_files() {
        use AuthorityRefusal::*;
        let refused = |refusal| {
            Err(UntrustedConfig::Refused {
                refusal,
                subject: AuthoritySubject::ProjectConfig,
            })
        };
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();

        // A final symlink is refused without the target being opened or read.
        let target = root.path().join("target.toml");
        fs::write(&target, b"[[tools]]\n").unwrap();
        let link = root.path().join("config.toml");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(verify_project_at(&link), refused(ThroughSymlink));
        fs::remove_file(&link).unwrap();
        // A dangling link is still a symlink, not an absent file.
        std::os::unix::fs::symlink(root.path().join("missing"), &link).unwrap();
        assert_eq!(verify_project_at(&link), refused(ThroughSymlink));
        fs::remove_file(&link).unwrap();

        // A passing file: `0644` in a `0755` directory.
        let file = root.path().join("config.toml");
        fs::write(&file, b"[[tools]]\n").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(verify_project_at(&file), Ok(()));

        fs::set_permissions(&file, fs::Permissions::from_mode(0o664)).unwrap();
        assert_eq!(verify_project_at(&file), refused(FileWritable));
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();

        let second = root.path().join("second.toml");
        fs::hard_link(&file, &second).unwrap();
        assert_eq!(verify_project_at(&file), refused(FileLinks(2)));
        fs::remove_file(&second).unwrap();

        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o775)).unwrap();
        assert_eq!(verify_project_at(&file), refused(DirWritable));
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();

        // A symlinked immediate directory is not followed: the project store
        // route must be a real directory.
        let store_dir = root.path().join("store");
        fs::create_dir(&store_dir).unwrap();
        fs::set_permissions(&store_dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::copy(&file, store_dir.join("config.toml")).unwrap();
        fs::set_permissions(
            store_dir.join("config.toml"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let linked_dir = root.path().join("linked");
        std::os::unix::fs::symlink(&store_dir, &linked_dir).unwrap();
        assert_eq!(
            verify_project_at(&linked_dir.join("config.toml")),
            refused(DirNotDirectory)
        );
    }

    /// The variants a portable fixture cannot produce (foreign ownership,
    /// an unexaminable directory) still attribute to the project-config subject
    /// exactly, through the same measurement-to-refusal adapter production uses.
    #[test]
    fn verify_project_attributes_every_kernel_refusal_and_dir_error() {
        use AuthorityRefusal::*;
        let euid = crate::host_paths::current_euid();
        let other = euid.wrapping_add(1);
        let subject = AuthoritySubject::ProjectConfig;
        let trusted_dir = DirFacts {
            is_dir: true,
            uid: euid,
            mode: 0o700,
        };
        let trusted_file = FileFacts {
            uid: euid,
            mode: 0o644,
            nlink: 1,
        };
        let cases = [
            (
                Reached::Direct(trusted_file),
                DirFacts {
                    is_dir: false,
                    ..trusted_dir
                },
                DirNotDirectory,
            ),
            (
                Reached::Direct(trusted_file),
                DirFacts {
                    uid: other,
                    ..trusted_dir
                },
                DirOwner,
            ),
            (
                Reached::Direct(FileFacts {
                    uid: other,
                    ..trusted_file
                }),
                trusted_dir,
                FileOwner,
            ),
        ];
        for (reached, dir, expected) in cases {
            let measurement = match authority_refusal(reached, dir, euid) {
                Some(refusal) => Measurement::Refused(refusal),
                None => panic!("the kernel accepted an unsafe fixture: {expected:?}"),
            };
            assert_eq!(
                measurement.into_untrusted(subject),
                UntrustedConfig::Refused {
                    refusal: expected,
                    subject,
                }
            );
        }
        let unexaminable = Measurement::DirUnexaminable(std::io::ErrorKind::PermissionDenied)
            .into_untrusted(subject);
        assert_eq!(
            unexaminable,
            UntrustedConfig::DirUnexaminable {
                kind: std::io::ErrorKind::PermissionDenied,
                subject,
            }
        );
        assert_eq!(
            unexaminable.to_string(),
            "the project config requires examining the config directory, which failed (PermissionDenied)"
        );
    }

    /// ADR-0040's compatibility rule is the user tier's alone: a tools-only
    /// project config reached through a symlink is refused, not loaded.
    #[test]
    fn verify_project_has_no_presence_exception() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let target = root.path().join("real.toml");
        fs::write(&target, b"[[tools]]\nname = \"x\"\ncommand = \"true\"\n").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let link = root.path().join("config.toml");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let none = AuthorityTriggers {
            network: false,
            mounts: false,
            mount_sets: false,
            egress_sets: false,
            allow_tools: false,
        };
        let read = read_bounded_regular_file_noting_symlink(&link, 100).unwrap();
        let verification = verify(&read, none).expect("the user tier's presence rule is unchanged");
        assert!(verification.authorized.is_none());
        assert_eq!(
            verify_project(&link, &FinalComponent::Symlink),
            Err(UntrustedConfig::Refused {
                refusal: AuthorityRefusal::ThroughSymlink,
                subject: AuthoritySubject::ProjectConfig,
            })
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
