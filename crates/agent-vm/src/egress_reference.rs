//! ADR-0059: `tool:NAME` egress references, and the one namespace they resolve
//! against.
//!
//! `tool:NAME` grants that tool's own `network_requests`, each as an exact
//! `tcp://HOST:PORT` hostname allowance. It is a *reference*, not a grant: the
//! authority it confers is whatever the user's own `config.toml` file already
//! declares, so once an entry is written it changes only when that file is
//! edited, and never because a repository declared something.
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
//! kernels; a reference cannot construct an allowance the grammar would refuse.
//!
//! Parsing and resolution are deliberately two steps. The persisted path must
//! report a `[network]` *syntax* error before it reports a tool-validation
//! error, and a *resolution* error after it — so `user_network` parses entries
//! where it always parsed them and calls [`resolve`] once, after
//! `validate_tools`.

mod sets;

use crate::config::{Tool, ToolOrigin, tool_name_rejection};
use crate::config_authority::{AuthorizedConfig, ReferenceTrust, UntrustedConfig};
use crate::egress_grammar::AllowanceError;
use crate::egress_policy::Allowance;
use crate::network_requests::NetworkRequests;
use microsandbox_network::policy::DomainName;
use std::{collections::BTreeMap, fmt, path::PathBuf};
use vstd::prelude::*;

verus! {
/// ADR-0059 R1: `tool:` in any ASCII case, not followed by `//`.
///
/// Reuses the grammar's own case-folding predicate, so "case-insensitive" means
/// one thing across `tcp:`, `udp:` and `tool:` — and the `//` exclusion mirrors
/// `tcp_scheme`'s, because `tool://host` is a *scheme* the allowance grammar
/// refuses and must keep refusing (A4).
pub open spec fn reference_claim_spec(s: Seq<u8>) -> bool {
    crate::egress_grammar::ci_prefix(s, seq![0x74u8, 0x6f, 0x6f, 0x6c, 0x3a])
        && !(s.len() >= 7 && s[5] == 0x2f && s[6] == 0x2f)
}

/// Which grammar one allowance text is handed to. Exhaustive: no third answer.
///
/// The postcondition `claimed ==> len >= 5` is what lets the adapter slice the
/// name off without a length check of its own: the five claimed bytes are ASCII
/// by [`reference_claim_spec`], so the slice boundary is a `char` boundary.
pub fn reference_claim(s: &[u8]) -> (claimed: bool)
    ensures
        claimed == reference_claim_spec(s@),
        claimed ==> s@.len() >= 5,
{
    if s.len() < 5 { return false; }
    // Two explicit cases per letter rather than the grammar's private
    // `lower_byte`, so no existing verus! item changes visibility or contract.
    let prefix = (s[0] == 0x74 || s[0] == 0x54) && (s[1] == 0x6f || s[1] == 0x4f)
        && (s[2] == 0x6f || s[2] == 0x4f) && (s[3] == 0x6c || s[3] == 0x4c)
        && s[4] == 0x3a;
    prefix && !(s.len() >= 7 && s[5] == 0x2f && s[6] == 0x2f)
}

/// #511 R1: `set:` in any ASCII case, not followed by `//` — [`reference_claim`]'s
/// rule with its own prefix, because `set://host` is a scheme the allowance
/// grammar refuses and must keep refusing.
///
/// The two claims are disjoint by construction (different third byte) and by test
/// (A3), which is what lets the adapter ask them in either order.
pub open spec fn set_reference_claim_spec(s: Seq<u8>) -> bool {
    crate::egress_grammar::ci_prefix(s, seq![0x73u8, 0x65, 0x74, 0x3a])
        && !(s.len() >= 6 && s[4] == 0x2f && s[5] == 0x2f)
}

/// The `set:` half of [`reference_claim`], with the same postcondition: the four
/// claimed bytes are ASCII, so the adapter may slice the name off unguarded.
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

/// The five claimed bytes: `tool:`, ASCII by the claim.
const PREFIX_LEN: usize = 5;

/// The four claimed bytes of `set:`, ASCII by the claim.
const SET_PREFIX_LEN: usize = 4;

const MALFORMED: &str = "an egress reference must be tool:NAME with a valid tool name (no whitespace, control characters or '/', not starting with '-', and not `.`, `..`, `*` or a reserved subcommand name)";
const UNKNOWN: &str = "an egress reference must name a tool declared in the user config's own [[tools]]; built-in and project tools are never used (`agent-vm tools print` prints the shipped tools to copy there)";
const NO_REQUESTS: &str = "an egress reference must name a tool that declares network_requests; this tool declares none, so the reference would grant nothing";
const NO_USER_CONFIG: &str = "an egress reference resolves only against the user config's own [[tools]], and no user config file was found";
const UNEXPANDABLE: &str = "a declared network request could not be expanded as an exact hostname allowance (internal error; please report it)";
const MALFORMED_SET: &str = "an egress reference must be set:NAME with a valid egress-set name ([A-Za-z0-9_] first, then [A-Za-z0-9_.-])";
const UNKNOWN_SET: &str = "an egress reference must name a set declared in the user config's own [egress_sets]; project and built-in configs cannot declare sets";
const NO_USER_SETS: &str = "an egress reference resolves only against the user config's own [egress_sets], and no user config file was found";

/// What one reference names, and therefore what resolves it.
///
/// Two variants, not a prefix plus a string: the claim decided which namespace
/// the name belongs to, and a resolver that had to re-derive that from the bytes
/// could look a set up in the tool map.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Target {
    Tool(String),
    Set(sets::EgressSetName),
}

/// One `tool:NAME` or `set:NAME` reference. The name is byte-exact: the prefix is
/// case-insensitive, the name it holds is not.
///
/// A tool's name is a `String` rather than `config::ToolName` because `ToolName`
/// has exactly one mint site (`validate_name`, which is where a declaration's
/// uniqueness is established) and a reference must not become a second way to
/// hold one. The invariant is equal either way: [`AllowanceEntry::parse`] accepts
/// the name only through `config::tool_name_rejection`, so it is a name some
/// `[[tools]]` entry could declare — never empty, and never containing
/// whitespace or control characters, which is what makes [`Display`] safe to
/// render. A set's name is minted only by [`sets::EgressSetName::parse`], over
/// the same rule `[mount_sets]` uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EgressReference(Target);

impl EgressReference {
    /// The refusal for a launch with no user config file at all, worded for the
    /// namespace the reference needed. The two differ because the fix differs:
    /// nothing can hold tools *or* sets, but the reader is told which.
    fn no_user_config(&self) -> EntryError {
        match self.0 {
            Target::Tool(_) => EntryError::NoUserConfig,
            Target::Set(_) => EntryError::NoUserSets,
        }
    }
}

impl fmt::Display for EgressReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Target::Tool(name) => write!(f, "tool:{name}"),
            Target::Set(name) => write!(f, "set:{}", name.as_str()),
        }
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
    /// The trusted `&str` adapter over [`reference_claim`] and
    /// [`set_reference_claim`] (ADR-0018).
    ///
    /// Claimed text never reaches `Allowance::parse`; unclaimed text is parsed by
    /// it unchanged, so every text whose meaning did not change keeps exactly the
    /// `Ok` or error it had. That includes `tool:P`/`set:P`-shaped text a kernel
    /// declines: `set://x.example` is still the scheme error, byte for byte.
    pub(crate) fn parse(text: &str) -> Result<Self, EntryError> {
        if set_reference_claim(text.as_bytes()) {
            // R3: the name is accepted iff a mount set could be called it, so a
            // name no set can have is a *syntax* error, never "unknown set".
            let name = text
                .get(SET_PREFIX_LEN..)
                .ok_or(EntryError::MalformedSetReference)?;
            let name =
                sets::EgressSetName::parse(name).map_err(|_| EntryError::MalformedSetReference)?;
            return Ok(Self::Reference(EgressReference(Target::Set(name))));
        }
        if !reference_claim(text.as_bytes()) {
            return Allowance::parse(text)
                .map(Self::Literal)
                .map_err(EntryError::Allowance);
        }
        // Unreachable refusal: the claim guarantees five leading ASCII bytes, so
        // index 5 is a `char` boundary. Written as a `get` rather than an index
        // because a panic must not be reachable from user text.
        let name = text
            .get(PREFIX_LEN..)
            .ok_or(EntryError::MalformedReference)?;
        // R2: the name is accepted iff `[[tools]]` would accept it, so a name no
        // tool can have is a *syntax* error, never "unknown tool".
        if tool_name_rejection(name).is_some() {
            return Err(EntryError::MalformedReference);
        }
        Ok(Self::Reference(EgressReference(Target::Tool(
            name.to_owned(),
        ))))
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
    MalformedReference,
    MalformedSetReference,
    UnknownTool,
    NoRequests,
    NoUserConfig,
    /// #511: no set of that name in the user file's own `[egress_sets]`.
    UnknownSet,
    /// #511: there is no user config file, so there are no sets to resolve.
    NoUserSets,
    /// The user file did not pass ADR-0040's read, as a reference needs it to.
    Untrusted {
        file: PathBuf,
        refusal: UntrustedConfig,
    },
    Unexpandable,
}

impl fmt::Display for EntryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allowance(error) => error.fmt(f),
            Self::MalformedReference => f.write_str(MALFORMED),
            Self::MalformedSetReference => f.write_str(MALFORMED_SET),
            Self::UnknownSet => f.write_str(UNKNOWN_SET),
            Self::NoUserSets => f.write_str(NO_USER_SETS),
            Self::UnknownTool => f.write_str(UNKNOWN),
            Self::NoRequests => f.write_str(NO_REQUESTS),
            Self::NoUserConfig => f.write_str(NO_USER_CONFIG),
            Self::Untrusted { file, refusal } => {
                write!(
                    f,
                    "config: {}: {refusal}",
                    crate::one_line::quoted_path(file)
                )
            }
            Self::Unexpandable => f.write_str(UNEXPANDABLE),
        }
    }
}

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

/// The only namespace an egress reference resolves against (ADR-0059): one user
/// file's validated tools and the `[egress_sets]` it compiles.
///
/// Built once, in `config::read_file_tier`'s user arm, from that tier's own
/// validated tools and its own `[egress_sets]` — before the cross-tier merge,
/// before the defaults catalog, and from the same read as `trust`. There is no
/// other constructor outside tests, so no second source of tools *or sets* can
/// exist, and a set can never be resolved against another file's name.
///
/// Owned data: [`resolve`] performs no I/O, so resolution can neither re-read the
/// file nor re-measure its directory (A31, A32).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EgressNamespace {
    trust: ReferenceTrust,
    requests: BTreeMap<String, NetworkRequests>,
    /// Every declared set's closure, compiled here and nowhere else.
    ///
    /// Boxed because a namespace is carried by `cli::Dispatch`'s launch arm, and
    /// the graph's three fields would otherwise tip that enum past clippy's
    /// large-variant threshold — the fix belongs here, not in the launch types.
    sets: Box<sets::EgressSets>,
}

impl EgressNamespace {
    /// Keep this tier's tools whose origin is the file `trust` measured, and
    /// compile that same file's egress sets against them.
    ///
    /// The file comparison is a **runtime** check, not a type-level one, and it
    /// is load-bearing: two reads of one path carry equal `PathBuf`s, so only the
    /// single construction site plus this filter keeps a verdict for file A from
    /// vouching for tools of file B (A13).
    ///
    /// Compilation happens here, after `validate_tools`, because a `tool:` entry
    /// inside a set resolves against validated tools; a set is compiled whether or
    /// not anything references it, so an unused set cannot smuggle an unknown tool
    /// past the load.
    pub(crate) fn new(
        trust: ReferenceTrust,
        tools: &[Tool],
        egress_sets: Option<ParsedEgressSets>,
    ) -> Result<Self, EgressSetError> {
        let file = trust.file();
        let requests = tools
            .iter()
            .filter(|tool| matches!(tool.origin(), ToolOrigin::User(origin) if origin == file))
            .map(|tool| (tool.name().to_owned(), tool.network_requests().clone()))
            .collect();
        let sets = match egress_sets {
            None => sets::EgressSets::default(),
            Some(parsed) => sets::compile(parsed, |name| {
                // Unreachable in practice — a file that declares `[egress_sets]`
                // was verified by presence at load — but checked per entry rather
                // than assumed, so the compile path cannot outlive its verdict.
                trust.require().map_err(untrusted(&trust))?;
                tool_expansion(&requests, name)
            })?,
        };
        Ok(Self {
            trust,
            requests,
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
    user_tools: Option<&EgressNamespace>,
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
                let Some(namespace) = user_tools else {
                    return Err(fail(reference.no_user_config()));
                };
                // R21: the file before its contents, for both kinds. A set can
                // only meet a refused verdict in a file *without* `[egress_sets]`
                // — presence would have refused the file at load — so the
                // sentence is the tool one for a case a tool also reaches
                // (ADR-0059's reachability argument).
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
                let expansion = match &reference.0 {
                    Target::Tool(name) => tool_expansion(&namespace.requests, name),
                    // R20: the closure the file's own `[egress_sets]` compiled. A
                    // copy per entry, because the rows are stored by value; the
                    // repeat skip above is what keeps that one copy per reference.
                    Target::Set(name) => namespace
                        .sets
                        .closure(name)
                        .map(<[_]>::to_vec)
                        .ok_or(EntryError::UnknownSet),
                }
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

/// One tool's requests, as allowances: unknown, then empty, then expanded.
///
/// The two refusals come first because they are about the *name*, and `expand`
/// can only fail on a request the file already declared.
fn tool_expansion(
    requests: &BTreeMap<String, NetworkRequests>,
    name: &str,
) -> Result<Vec<Allowance>, EntryError> {
    let requests = requests.get(name).ok_or(EntryError::UnknownTool)?;
    if requests.is_empty() {
        return Err(EntryError::NoRequests);
    }
    expand(requests)
}

/// Re-enter the proved grammar instead of constructing an allowance directly, so
/// every hostname allowance in policy passed the scheme, target and hostname
/// kernels (ADR-0018). The port is always explicit — including 443 — because an
/// expanded name must be pinned to exactly the port the request declared (R6).
fn expand(requests: &NetworkRequests) -> Result<Vec<Allowance>, EntryError> {
    requests
        .iter()
        .map(|request| {
            let text = format!("tcp://{}:{}", request.name().as_str(), request.port());
            match Allowance::parse(&text) {
                Ok(hostname @ Allowance::Hostname(_)) => Ok(hostname),
                _ => Err(EntryError::Unexpandable),
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

    /// How the allowance(s) for one hostname were reached. Unioned over every
    /// allowance naming it, because one name may be granted bare and pinned to
    /// several ports by different entries.
    pub(crate) fn hostname_origin(&self, name: &DomainName) -> EntryOrigin<'_> {
        self.origin_matching(
            |candidate| matches!(candidate, Allowance::Hostname(h) if h.domain() == name),
        )
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
