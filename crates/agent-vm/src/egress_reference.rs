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
//! fallback (ADR-0059). [`UserToolRequests`] is the whole namespace, built once
//! in `config::read_file_tier`'s user arm from that tier's validated tools,
//! *before* the cross-tier merge, and it keeps only tools whose origin file is
//! the file the trust verdict measured.
//!
//! **Routing is proved.** [`AllowanceEntry::parse`] is a trusted `&str` adapter
//! over the [`reference_claim`] kernel: text the kernel claims never reaches
//! `egress_policy::Allowance`'s grammar, and text it does not claim is parsed by
//! exactly the grammar it always was. That is what makes "is this text a
//! reference?" a decision rather than a series of prefix comparisons scattered
//! through the config paths (ADR-0018).
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

use crate::config::{Tool, ToolOrigin, tool_name_rejection};
use crate::config_authority::{ReferenceTrust, UntrustedConfig};
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
} // verus!

/// The five claimed bytes: `tool:`, ASCII by the claim.
const PREFIX_LEN: usize = 5;

const MALFORMED: &str = "an egress reference must be tool:NAME with a valid tool name (no whitespace, control characters or '/', not starting with '-', and not `.`, `..`, `*` or a reserved subcommand name)";
const UNKNOWN: &str = "an egress reference must name a tool declared in the user config's own [[tools]]; built-in and project tools are never used (`agent-vm tools print` prints the shipped tools to copy there)";
const NO_REQUESTS: &str = "an egress reference must name a tool that declares network_requests; this tool declares none, so the reference would grant nothing";
const NO_USER_CONFIG: &str = "an egress reference resolves only against the user config's own [[tools]], and no user config file was found";
const UNEXPANDABLE: &str = "a declared network request could not be expanded as an exact hostname allowance (internal error; please report it)";

/// One `tool:NAME` reference. The name is byte-exact: the prefix is
/// case-insensitive, the tool it names is not.
///
/// The name is a `String` rather than `config::ToolName` because `ToolName` has
/// exactly one mint site (`validate_name`, which is where a declaration's
/// uniqueness is established) and a reference must not become a second way to
/// hold one. The invariant is equal either way: [`AllowanceEntry::parse`] accepts
/// the name only through `config::tool_name_rejection`, so it is a name some
/// `[[tools]]` entry could declare — never empty, and never containing
/// whitespace or control characters, which is what makes [`Display`] safe to
/// render.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EgressReference {
    tool: String,
}

impl EgressReference {
    pub(crate) fn tool(&self) -> &str {
        &self.tool
    }
}

impl fmt::Display for EgressReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tool:{}", self.tool)
    }
}

/// One `allow_egress` entry, already classified.
///
/// `Literal` is what the entry always was; `Reference` is resolved later
/// against [`UserToolRequests`]. Nothing else converts text into an allowance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AllowanceEntry {
    Literal(Allowance),
    Reference(EgressReference),
}

impl AllowanceEntry {
    /// The trusted `&str` adapter over [`reference_claim`] (ADR-0018).
    ///
    /// Claimed text never reaches `Allowance::parse`; unclaimed text is parsed by
    /// it unchanged, so every text whose meaning did not change keeps exactly the
    /// `Ok` or error it had.
    pub(crate) fn parse(text: &str) -> Result<Self, EntryError> {
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
        Ok(Self::Reference(EgressReference {
            tool: name.to_owned(),
        }))
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
    UnknownTool,
    NoRequests,
    NoUserConfig,
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

/// The only namespace an egress reference resolves against (ADR-0059).
///
/// Built once, in `config::read_file_tier`'s user arm, from that tier's own
/// validated tools — before the cross-tier merge, before the defaults catalog,
/// and from the same read as `trust`. There is no other constructor outside
/// tests, so no second source of tools can exist.
///
/// Owned data: [`resolve`] performs no I/O, so resolution can neither re-read the
/// file nor re-measure its directory (A31, A32).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UserToolRequests {
    trust: ReferenceTrust,
    requests: BTreeMap<String, NetworkRequests>,
}

impl UserToolRequests {
    /// Keep this tier's tools whose origin is the file `trust` measured.
    ///
    /// The file comparison is a **runtime** check, not a type-level one, and it
    /// is load-bearing: two reads of one path carry equal `PathBuf`s, so only the
    /// single construction site plus this filter keeps a verdict for file A from
    /// vouching for tools of file B (A13).
    pub(crate) fn new(trust: ReferenceTrust, tools: &[Tool]) -> Self {
        let file = trust.file();
        let requests = tools
            .iter()
            .filter(|tool| matches!(tool.origin(), ToolOrigin::User(origin) if origin == file))
            .map(|tool| (tool.name().to_owned(), tool.network_requests().clone()))
            .collect();
        Self { trust, requests }
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
    user_tools: Option<&UserToolRequests>,
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
                let tools = user_tools.ok_or_else(|| fail(EntryError::NoUserConfig))?;
                tools.trust.require().map_err(|refusal| {
                    fail(EntryError::Untrusted {
                        file: tools.trust.file().to_owned(),
                        refusal,
                    })
                })?;
                let requests = tools
                    .requests
                    .get(reference.tool())
                    .ok_or_else(|| fail(EntryError::UnknownTool))?;
                if requests.is_empty() {
                    return Err(fail(EntryError::NoRequests));
                }
                // The slot is looked up *before* expanding, so a repeated
                // reference is expanded exactly once, as its comment says.
                let slot = match resolved.reference_index(&reference) {
                    Some(index) => index,
                    None => {
                        let expansion = expand(requests).map_err(fail)?;
                        resolved.push_reference(reference, expansion)
                    }
                };
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
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ResolvedAllowances {
    entries: Vec<SourcedAllowance>,
    /// One row per distinct reference, in first-use order, with its expansion in
    /// request order.
    references: Vec<(EgressReference, Vec<Allowance>)>,
}

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
