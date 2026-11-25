//! ADR-0059/#511/#735: the `set:NAME` egress reference, and the one namespace it
//! resolves against.
//!
//! `set:NAME` grants a user-config `[egress_sets]` entry's compiled closure. It is
//! a *reference*, not a grant: the authority it confers is whatever the user's own
//! `config.toml` already declares, so once an entry is written it changes only
//! when that file is edited, and never because a repository declared something.
//!
//! #735 (ADR-0075) removed the `tool:NAME` reference: a tool's own
//! `network_requests` are granted when `allow_tools` authorizes it, so nothing
//! needs to name a tool from an egress list. [`expand`] survives as that one
//! grant path's converter.
//!
//! **That is post-migration behaviour, and the migration is the exception.**
//! Upgrading *into* 0.7.31 rebinds an existing `tool:P` entry from the hostname
//! `tool` on port `P` to a tool of that name, silently if such a tool exists
//! (R27). "Never on upgrade" would be false for that one step, which is why
//! USAGE's *Upgrade note (0.7.31)* tells the reader to rewrite the entry as
//! `tcp://tool:P` **before** upgrading, and why ADR-0059 records the break in
//! full.
//!
//! **Scope is one table: the user file's own `[[tools]]`.** Not the project
//! tier, even when the project's same-named definition is the verb being
//! launched; not the shipped built-in catalog; not the appended `shell`
//! fallback (ADR-0059). [`EgressNamespace`] is the whole namespace — that file's
//! validated tools and its compiled `[egress_sets]` — built once in
//! `config::read_file_tier`'s user arm, *before* the cross-tier merge, and it
//! keeps only tools whose origin file is the file the trust verdict measured.
//!
//! #511 adds `set:NAME`, a reference to a list the same file declares in its own
//! `[egress_sets]` table. It is the same kind of thing — a name for allowances
//! the file already contains, never a new source of authority — so it shares the
//! namespace, the namespace's trust verdict, the reference rows and the
//! attribution. What differs is what a name *resolves to*: a set resolves to a
//! closure compiled once at load by [`sets`], tools included, rather than to one
//! tool's request list.
//!
//! **Routing is proved, for both kinds.** [`AllowanceEntry::parse`] is a trusted
//! `&str` adapter over the [`reference_claim`] and [`set_reference_claim`]
//! kernels: text either kernel claims never reaches `egress_policy::Allowance`'s
//! grammar, and text neither claims is parsed by exactly the grammar it always
//! was. That is what makes "is this text a reference?" a decision rather than a
//! series of prefix comparisons scattered through the config paths (ADR-0018).
//!
//! **Expansion re-enters the grammar.** [`expand`] renders `tcp://HOST:PORT`
//! and parses it with the same unchanged `Allowance::parse`, so every hostname
//! allowance in launch policy still passed the proved scheme/target/hostname
//! kernels; nothing can construct an allowance the grammar would refuse. Since
//! #735 the one caller is an authorized tool's own `network_requests`, which are
//! granted on launch instead of referenced by name (ADR-0075).
//!
//! Parsing and resolution are deliberately two steps. The persisted path must
//! report a `[network]` *syntax* error before it reports a `[egress_sets]`
//! error, and a *resolution* error after it — so `user_network` parses entries
//! where it always parsed them and calls [`resolve`] once, after
//! `validate_tools`.

mod sets;

use crate::config_authority::{AuthorizedConfig, ReferenceTrust, UntrustedConfig};
use crate::egress_grammar::AllowanceError;
use crate::egress_hostname::HostnameAllowance;
use crate::egress_policy::Allowance;
use crate::network_requests::NetworkRequests;
use microsandbox_network::policy::DomainName;
use std::{fmt, path::PathBuf};
use vstd::prelude::*;

verus! {
/// #511 R1: `set:` in any ASCII case, not followed by `//`, because `set://host`
/// is a scheme the allowance grammar refuses and must keep refusing.
///
/// #735 removed the `tool:` claim (ADR-0075): an authorized tool's
/// `network_requests` are granted on launch, so no egress reference reads
/// `[[tools]]` any more. `set:` is therefore the only claimed prefix, and every
/// other text reaches `Allowance::parse` unchanged.
pub open spec fn set_reference_claim_spec(s: Seq<u8>) -> bool {
    crate::egress_grammar::ci_prefix(s, seq![0x73u8, 0x65, 0x74, 0x3a])
        && !(s.len() >= 6 && s[4] == 0x2f && s[5] == 0x2f)
}

/// The four claimed bytes are ASCII, so the adapter may slice the name off
/// unguarded.
pub fn set_reference_claim(s: &[u8]) -> (claimed: bool)
    ensures
        claimed == set_reference_claim_spec(s@),
        claimed ==> s@.len() >= 4,
{
    if s.len() < 4 { return false; }
    let prefix = (s[0] == 0x73 || s[0] == 0x53) && (s[1] == 0x65 || s[1] == 0x45)
        && (s[2] == 0x74 || s[2] == 0x54) && s[3] == 0x3a;
    prefix && !(s.len() >= 6 && s[4] == 0x2f && s[5] == 0x2f)
}
} // verus!

/// The four claimed bytes of `set:`, ASCII by the claim.
const SET_PREFIX_LEN: usize = 4;

const MALFORMED_SET: &str = "an egress reference must be set:NAME with a valid egress-set name ([A-Za-z0-9_] first, then [A-Za-z0-9_.-])";
const UNKNOWN_SET: &str = "an egress reference must name a set declared in the user config's own [egress_sets]; project and built-in configs cannot declare sets";
const NO_USER_SETS: &str = "an egress reference resolves only against the user config's own [egress_sets], and no user config file was found";
const UNEXPANDABLE: &str = "a declared network request could not be expanded as an exact hostname allowance (internal error; please report it)";

/// One `set:NAME` reference. The name is byte-exact: the prefix is
/// case-insensitive, the name it holds is not.
///
/// A set's name is minted only by [`sets::EgressSetName::parse`], over the same
/// rule `[mount_sets]` uses, so a reference can only name a set some file could
/// declare — and [`Display`] is safe to render.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EgressReference(sets::EgressSetName);

impl EgressReference {
    /// How a collapsed launch line names this reference: the set's own name (#631).
    pub(crate) fn notice_label(&self) -> String {
        self.0.as_str().to_owned()
    }

    /// The set it names.
    pub(in crate::egress_reference) fn set_name(&self) -> &sets::EgressSetName {
        &self.0
    }
}

impl fmt::Display for EgressReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "set:{}", self.0.as_str())
    }
}

/// One `allow_egress` entry, already classified.
///
/// `Literal` is what the entry always was; `Reference` is resolved later
/// against [`EgressNamespace`]. Nothing else converts text into an allowance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AllowanceEntry {
    Literal(Allowance),
    Reference(EgressReference),
}

impl AllowanceEntry {
    /// The trusted `&str` adapter over [`set_reference_claim`] (ADR-0018).
    ///
    /// Claimed text never reaches `Allowance::parse`; unclaimed text is parsed by
    /// it unchanged, so every text whose meaning did not change keeps exactly the
    /// `Ok` or error it had. `set://x.example` is still the scheme error, byte for
    /// byte, and #735's removal of the `tool:` claim means `tool:NAME` is now
    /// parsed as an ordinary allowance text: `tool:443` is the hostname `tool` on
    /// port 443, and `tool:codex` fails as a malformed port.
    pub(crate) fn parse(text: &str) -> Result<Self, EntryError> {
        if set_reference_claim(text.as_bytes()) {
            // R3: the name is accepted iff a mount set could be called it, so a
            // name no set can have is a *syntax* error, never "unknown set".
            let name = text
                .get(SET_PREFIX_LEN..)
                .ok_or(EntryError::MalformedSetReference)?;
            let name =
                sets::EgressSetName::parse(name).map_err(|_| EntryError::MalformedSetReference)?;
            return Ok(Self::Reference(EgressReference(name)));
        }
        Allowance::parse(text)
            .map(Self::Literal)
            .map_err(EntryError::Allowance)
    }
}

/// Why one entry, or one reference, was refused.
///
/// Every variant's text is fixed: ADR-0039 forbids echoing user or repository
/// values in a diagnostic, and a reference's name is exactly the value a
/// mistyped entry would carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EntryError {
    /// The unchanged allowance error, rendered by its own `Display`.
    Allowance(AllowanceError),
    MalformedSetReference,
    /// #511: no set of that name in the user file's own `[egress_sets]`.
    UnknownSet,
    /// #511: there is no user config file, so there are no sets to resolve.
    NoUserSets,
    /// The user file did not pass ADR-0040's read, as a reference needs it to.
    Untrusted {
        file: PathBuf,
        refusal: UntrustedConfig,
    },
}

impl fmt::Display for EntryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allowance(error) => error.fmt(f),
            Self::MalformedSetReference => f.write_str(MALFORMED_SET),
            Self::UnknownSet => f.write_str(UNKNOWN_SET),
            Self::NoUserSets => f.write_str(NO_USER_SETS),
            Self::Untrusted { file, refusal } => {
                write!(
                    f,
                    "config: {}: {refusal}",
                    crate::one_line::quoted_path(file)
                )
            }
        }
    }
}

/// Why one `network_requests` entry could not be expanded into an allowance.
///
/// A single sentence, because there is a single cause: the grammar proved the
/// rendered `tcp://HOST:PORT` is not a hostname allowance. A declaration that
/// cannot be rendered is a programming error in the *validator*, never user
/// input — `NetworkRequests` already constrained the name and port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExpandRequestError;

impl fmt::Display for ExpandRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(UNEXPANDABLE)
    }
}

impl std::error::Error for ExpandRequestError {}

/// The zero-based position of the first failing entry, with its reason.
///
/// The position is part of the error rather than a call-site variable because
/// both callers number entries differently (`network.allow_egress[N]` is
/// zero-based, `--allow-egress #N` one-based), and a caller that lost the index
/// could only re-derive it by guessing.
#[derive(Debug)]
pub(crate) struct EntryFailure {
    pub(crate) index: usize,
    pub(crate) error: EntryError,
}

/// Parse `[egress_sets]` from a **verified** file, and only from one.
///
/// The token is the point: `sets::parse` is private to this module, so there is no
/// order in which a definition is read unverified — the same shape `[network]`
/// and the mount fields already have (ADR-0040, #511 R10).
pub(crate) fn parse_sets(
    _authorized: &AuthorizedConfig<'_>,
    value: &toml::Value,
) -> Result<ParsedEgressSets, EgressSetError> {
    sets::parse(value)
}

pub(crate) use sets::{EgressSetError, ParsedEgressSets};

/// The only namespace an egress reference resolves against (ADR-0059): the
/// `[egress_sets]` one verified user file compiles.
///
/// Built once, in `config::build_tier`'s user arm, from that tier's own
/// `[egress_sets]` — before the cross-tier merge, before the defaults catalog,
/// and from the same read as `trust`. There is no other constructor outside
/// tests, so no second source of sets can exist, and a set can never be resolved
/// against another file's name.
///
/// Owned data: [`resolve`] performs no I/O, so resolution can neither re-read the
/// file nor re-measure its directory (A31, A32).
///
/// #735 removed the `[[tools]] network_requests` map: a `tool`'s requests are
/// granted when `allow_tools` authorizes it on launch, not by an egress reference
/// (ADR-0075). What is left is the set graph and the verdict for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EgressNamespace {
    trust: ReferenceTrust,
    /// Every declared set's closure, compiled here and nowhere else.
    ///
    /// Boxed because a namespace is carried by `cli::Dispatch`'s launch arm, and
    /// the graph's two fields would otherwise tip that enum past clippy's
    /// large-variant threshold — the fix belongs here, not in the launch types.
    sets: Box<sets::EgressSets>,
}

impl EgressNamespace {
    /// Compile one verified file's egress sets.
    ///
    /// A set is compiled whether or not anything references it, so an unused set
    /// cannot smuggle an unknown reference past the load.
    pub(crate) fn new(
        trust: ReferenceTrust,
        egress_sets: Option<ParsedEgressSets>,
    ) -> Result<Self, EgressSetError> {
        let sets = match egress_sets {
            None => sets::EgressSets::default(),
            Some(parsed) => sets::compile(parsed)?,
        };
        Ok(Self {
            trust,
            sets: Box::new(sets),
        })
    }
}

/// Turn every entry into the allowances it grants, or refuse the first bad one.
///
/// Entry order is preserved: user entries before CLI entries, as the union has
/// always been. Deduplication is by canonical value, so a duplicate reference
/// grants once and an allowance reached both directly and through a reference is
/// one entry attributed to all of them.
pub(crate) fn resolve(
    entries: Vec<AllowanceEntry>,
    user_sets: Option<&EgressNamespace>,
) -> Result<ResolvedAllowances, EntryFailure> {
    let mut resolved = ResolvedAllowances::default();
    for (index, entry) in entries.into_iter().enumerate() {
        let fail = |error| EntryFailure { index, error };
        match entry {
            AllowanceEntry::Literal(allowance) => resolved.insert(allowance, true, None),
            AllowanceEntry::Reference(reference) => {
                // R12/R11 before R9 before R10: a reference in an untrusted file
                // is refused for the file, not for its contents, because the
                // contents are what the refusal is about.
                let Some(namespace) = user_sets else {
                    return Err(fail(EntryError::NoUserSets));
                };
                // R21: the file before its contents.
                namespace
                    .trust
                    .require()
                    .map_err(untrusted(&namespace.trust))
                    .map_err(fail)?;
                // R23: a repeated reference already granted everything it can
                // grant, so re-applying its expansion would only re-insert
                // allowances the first occurrence put there.
                if resolved.reference_index(&reference).is_some() {
                    continue;
                }
                // R20: the closure the file's own `[egress_sets]` compiled. A
                // copy per entry, because the rows are stored by value; the
                // repeat skip above is what keeps that one copy per reference.
                let expansion = namespace
                    .sets
                    .closure(reference.set_name())
                    .map(<[_]>::to_vec)
                    .ok_or(EntryError::UnknownSet)
                    .map_err(fail)?;
                let slot = resolved.push_reference(reference, expansion);
                // Cloned once per entry, not once per allowance: `insert` mutates
                // the same struct the expansion is stored in.
                let expansion = resolved.references[slot].1.clone();
                for allowance in expansion {
                    resolved.insert(allowance, false, Some(slot));
                }
            }
        }
    }
    Ok(resolved)
}

/// Attribute a refusal to the file whose verdict carried it, once, for both
/// reference kinds.
fn untrusted(trust: &ReferenceTrust) -> impl Fn(UntrustedConfig) -> EntryError + '_ {
    move |refusal| EntryError::Untrusted {
        file: trust.file().to_owned(),
        refusal,
    }
}

/// Render an authorized tool's own declarations as exact allowances.
///
/// Re-enter the proved grammar instead of constructing an allowance directly, so
/// every hostname allowance in policy passed the scheme, target and hostname
/// kernels (ADR-0018). The port is always explicit — including 443 — because an
/// expanded name must be pinned to exactly the port the request declared: a bare
/// request grants `tcp://HOST:443` and never widens to another port.
///
/// This is the single converter from `network_requests` into egress (ADR-0075),
/// called by `EgressAuthority::resolve` for a launch of an authorized tool.
pub(crate) fn expand(requests: &NetworkRequests) -> Result<Vec<Allowance>, ExpandRequestError> {
    requests
        .iter()
        .map(|request| {
            let text = format!("tcp://{}:{}", request.name().as_str(), request.port());
            match Allowance::parse(&text) {
                Ok(hostname @ Allowance::Hostname(_)) => Ok(hostname),
                _ => Err(ExpandRequestError),
            }
        })
        .collect()
}

/// One allowance in a resolved set, and how it was reached.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SourcedAllowance {
    allowance: Allowance,
    /// Granted by a literal entry, so it would exist without any reference.
    direct: bool,
    /// Indices into [`ResolvedAllowances::references`], first use first.
    via: Vec<usize>,
}

/// Allowances in first-occurrence order, plus each reference's expansion.
///
/// Private fields and no other constructor public to the crate: an allowance in
/// one of these either came from `Allowance::parse` on a literal or from
/// [`expand`], so "how it was granted" cannot be forged.
#[derive(Clone, Debug, Default)]
pub(crate) struct ResolvedAllowances {
    entries: Vec<SourcedAllowance>,
    /// One row per distinct reference, in first-use order, with its expansion in
    /// request order.
    references: Vec<(EgressReference, Vec<Allowance>)>,
    /// How many times [`Self::insert`] was called, deduplicated calls included.
    ///
    /// The bound R23 promises — one tier's *insert* work is bounded by its distinct
    /// references, not by how often each was written — is invisible in the output,
    /// because `insert` folds both repeated values and repeated provenance. So the
    /// work itself is counted, and equality ignores it: a work measure is not part
    /// of the value.
    ///
    /// It bounds `insert` calls and nothing else. [`Self::reference_index`] is a
    /// linear scan over the rows seen so far, so a repeat costs one probe *per
    /// repeat* rather than constant time, and a selected empty set costs one scan
    /// and no inserts at all. Total resolver cost is file-bounded, not
    /// reference-count-bounded; indexing those rows is a follow-up beside the
    /// pre-existing scan in `insert`.
    insertions: usize,
}

impl PartialEq for ResolvedAllowances {
    fn eq(&self, other: &Self) -> bool {
        self.entries == other.entries && self.references == other.references
    }
}

impl Eq for ResolvedAllowances {}

/// How one entry reached one allowance, per tier.
///
/// `via` borrows the reference rows so a caller can name them without cloning.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct EntryOrigin<'a> {
    pub(crate) direct: bool,
    pub(crate) via: Vec<&'a EgressReference>,
}

impl ResolvedAllowances {
    fn insert(&mut self, allowance: Allowance, direct: bool, via: Option<usize>) {
        self.insertions += 1;
        // First occurrence keeps its position: the union's order is the entry
        // order, which is what notices and tests read.
        match self
            .entries
            .iter_mut()
            .find(|entry| entry.allowance == allowance)
        {
            Some(existing) => {
                existing.direct |= direct;
                if let Some(index) = via
                    && !existing.via.contains(&index)
                {
                    existing.via.push(index);
                }
            }
            None => self.entries.push(SourcedAllowance {
                allowance,
                direct,
                via: via.into_iter().collect(),
            }),
        }
    }

    /// Fold another resolved set of allowances into this one (ADR-0076 R4.3).
    ///
    /// Appends `other`'s reference rows, remapping their indices, and re-inserts
    /// each of its sourced allowances so deduplication and `set:NAME` provenance
    /// both survive a union. First occurrence keeps its position, so the union's
    /// order is the adoption order the caller folded in.
    pub(crate) fn extend_from(&mut self, other: &ResolvedAllowances) {
        let offset = self.references.len();
        self.references.extend(other.references.iter().cloned());
        for entry in &other.entries {
            self.insertions += 1;
            let via = entry
                .via
                .iter()
                .map(|index| index + offset)
                .collect::<Vec<_>>();
            let allowance = entry.allowance.clone();
            match self
                .entries
                .iter_mut()
                .find(|existing| existing.allowance == allowance)
            {
                Some(existing) => {
                    existing.direct |= entry.direct;
                    for index in via {
                        if !existing.via.contains(&index) {
                            existing.via.push(index);
                        }
                    }
                }
                None => self.entries.push(SourcedAllowance {
                    allowance,
                    direct: entry.direct,
                    via,
                }),
            }
        }
    }

    /// The row already registered for `reference`, if it has one.
    ///
    /// A linear scan over the rows so far, not an index: rows are bounded by the
    /// file's distinct references, so this is a probe whose cost is the repeat
    /// count times the row count. It bounds *applications* (R23), not resolver
    /// CPU; see [`Self::insertions`]. An index is a follow-up.
    fn reference_index(&self, reference: &EgressReference) -> Option<usize> {
        self.references
            .iter()
            .position(|(existing, _)| existing == reference)
    }

    /// Register one reference's expansion. Called only when
    /// [`Self::reference_index`] found no row, so the expansion it stores was
    /// computed exactly once per resolution.
    fn push_reference(&mut self, reference: EgressReference, expansion: Vec<Allowance>) -> usize {
        self.references.push((reference, expansion));
        self.references.len() - 1
    }

    pub(crate) fn allowances(&self) -> impl Iterator<Item = &Allowance> {
        self.entries.iter().map(|entry| &entry.allowance)
    }

    pub(crate) fn has_hostnames(&self) -> bool {
        self.entries
            .iter()
            .any(|entry| matches!(entry.allowance, Allowance::Hostname(_)))
    }

    /// How `allowance` was reached, per tier.
    pub(crate) fn entry_origin(&self, allowance: &Allowance) -> EntryOrigin<'_> {
        self.origin_matching(|candidate| candidate == allowance)
    }

    /// How the allowance(s) for one hostname were reached: the union of
    /// [`Self::hostname_grants`], so the notice and a row view derive a name's
    /// origins from one traversal.
    pub(crate) fn hostname_origin(&self, name: &DomainName) -> EntryOrigin<'_> {
        let mut origin = EntryOrigin::default();
        for (_, grant) in self.hostname_grants(name) {
            origin.direct |= grant.direct;
            for reference in grant.via {
                if !origin.via.contains(&reference) {
                    origin.via.push(reference);
                }
            }
        }
        origin
    }

    /// Each allowance naming `name`, with how this tier reached *that* allowance
    /// — the per-allowance view `hostname_origin` unions (#631: a row's ports are
    /// its own grants' ports, because one name may be granted bare and pinned to
    /// several ports by different entries).
    pub(crate) fn hostname_grants(
        &self,
        name: &DomainName,
    ) -> Vec<(&HostnameAllowance, EntryOrigin<'_>)> {
        self.entries
            .iter()
            .filter_map(|entry| match &entry.allowance {
                Allowance::Hostname(hostname) if hostname.domain() == name => Some((
                    hostname,
                    EntryOrigin {
                        direct: entry.direct,
                        via: entry
                            .via
                            .iter()
                            .map(|index| &self.references[*index].0)
                            .collect(),
                    },
                )),
                _ => None,
            })
            .collect()
    }

    fn origin_matching(&self, wanted: impl Fn(&Allowance) -> bool) -> EntryOrigin<'_> {
        let mut origin = EntryOrigin::default();
        for entry in self.entries.iter().filter(|entry| wanted(&entry.allowance)) {
            origin.direct |= entry.direct;
            for index in &entry.via {
                let reference = &self.references[*index].0;
                if !origin.via.contains(&reference) {
                    origin.via.push(reference);
                }
            }
        }
        origin
    }

    /// Every distinct reference that granted something, in first-use order.
    pub(crate) fn references(&self) -> impl ExactSizeIterator<Item = &EgressReference> {
        self.references.iter().map(|(reference, _)| reference)
    }

    /// Every distinct reference whose **own expansion** contains a hostname, in
    /// first-use order.
    ///
    /// The proxy refusal names what a reader can delete to stop granting a
    /// hostname, so a reference that expands to addresses only, or to nothing,
    /// does not belong in it: `set:num` naming `10.0.0.1` is not why a hostname
    /// allowance exists (R26, G4). Narrower than [`Self::references`], which is
    /// what notices and `doctor` want.
    pub(crate) fn hostname_references(&self) -> impl Iterator<Item = &EgressReference> {
        self.references
            .iter()
            .filter(|(_, expansion)| {
                expansion
                    .iter()
                    .any(|allowance| matches!(allowance, Allowance::Hostname(_)))
            })
            .map(|(reference, _)| reference)
    }

    /// Each reference with the exact allowances it expanded to, for `doctor`.
    pub(crate) fn expansions(&self) -> impl Iterator<Item = (&EgressReference, &[Allowance])> {
        self.references
            .iter()
            .map(|(reference, expansion)| (reference, expansion.as_slice()))
    }
}

/// Render references as a list: `a`, `a and b`, `a, b and c`.
///
/// One place, because the notice tag, the proxy refusal and `doctor` must word
/// the same set identically.
pub(crate) fn render_list(references: &[&EgressReference]) -> String {
    let rendered: Vec<String> = references
        .iter()
        .map(|reference| reference.to_string())
        .collect();
    match rendered.split_last() {
        None => String::new(),
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
    }
}

#[cfg(test)]
mod tests;

/// The test-only namespace and resolution helpers live in the test module with
/// everything else test-only; this re-export keeps `egress_reference::test_support`
/// the path other modules' tests already use.
#[cfg(test)]
pub(crate) use tests::test_support;
