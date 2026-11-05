//! #511: the `[egress_sets]` graph — names, definitions, the reference walk and
//! each set's compiled closure.
//!
//! Private to [`super`], which owns the *entry* side of the feature (claiming
//! `set:NAME`, resolving it, attributing what it grants). This module owns the
//! *table*: what a definition is called, what it may hold, whether the graph has
//! a cycle, and what one set grants once nested sets and tools are folded in.
//! Nothing here reaches a caller outside `egress_reference`, so no second named
//! resolver can exist.
//!
//! Two properties shape it, and both are about what a config can cost rather
//! than what it may say:
//!
//! * **Every declared set is validated and compiled**, whether or not anything
//!   references it: a set nobody selected is still text that claims authority,
//!   and a chain's cost is decided by its edges, not by who walked it.
//! * **That work is bounded** by one counter for the whole file, never reset per
//!   set or per reference, so a crafted table is a value-free config error
//!   instead of a hang or an unbounded expansion.
//!
//! This file is production-only, like [`super`]: its tests live in
//! `egress_reference/sets/tests.rs`, so the A37 source guard can scan it as
//! production by construction.

use crate::config_mounts::mount_set_name_bytes;
use crate::config_mounts::{VisitDecision, VisitState, visit_decision};
use crate::egress_policy::Allowance;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fmt,
};
use vstd::prelude::*;

verus! {
/// How many allowance visits the whole user file may spend compiling egress-set
/// closures (#511 R17).
///
/// A *visit* is one candidate allowance considered while compiling a set's
/// closure: a literal entry, one allowance of a `tool:` expansion, or one
/// allowance of a child set's closure. The counter is global and never reset, so
/// a crafted table cannot turn load into a hang by fanning out widely; 65,536
/// admits hundreds of ordinary sets (100 sets of 100 allowances costs 10,000)
/// while bounding the admitted work to 65,536 hash probes and inserts. The
/// number and the reasoning are the mount graph's (`MAX_MOUNT_SET_EXPANSION_WORK`),
/// kept as a separate counter because a set reference is a different expansion
/// from a mount selection and one must not be able to exhaust the other.
pub const MAX_EGRESS_SET_EXPANSION_WORK: usize = 65_536;

/// Exhaustion polarity. Checked *before* an increment, so the counter can reach
/// the limit exactly and never overflow.
pub fn egress_set_expansion_work_allowed(used: usize) -> (r: bool)
    ensures r == (used < MAX_EGRESS_SET_EXPANSION_WORK),
{
    used < MAX_EGRESS_SET_EXPANSION_WORK
}
} // verus!

/// One user-declared egress-set name, in its exact spelling.
///
/// A distinct type from `config_mounts::MountSetName` on purpose: one name type
/// for both namespaces would let a mount-set name reach an egress lookup (and the
/// reverse) with the compiler's blessing. The *rule* is shared — both ask the one
/// proved [`mount_set_name_bytes`], so the two grammars cannot drift — but the
/// value one table produced stays inside that table.
///
/// Case is preserved: `Corp` and `corp` are two sets.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct EgressSetName(String);

impl EgressSetName {
    /// The proved mount-set name rule, stated once for both namespaces.
    pub(super) fn parse(raw: &str) -> Result<Self, InvalidEgressSetName> {
        if !mount_set_name_bytes(raw.as_bytes()) {
            return Err(InvalidEgressSetName);
        }
        Ok(Self(raw.to_owned()))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

/// A name that failed the shared name rule. Carries no bytes: every sentence this
/// turns into names the numeric site instead, because the key is exactly the
/// value a mistyped definition would carry (ADR-0039).
#[derive(Debug)]
pub(super) struct InvalidEgressSetName;

impl fmt::Display for InvalidEgressSetName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "an egress-set name is one or more ASCII characters: [A-Za-z0-9_] first, then \
             [A-Za-z0-9_.-]",
        )
    }
}

/// A set's position in the sorted definition order, which is also the number
/// every diagnostic about it prints.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct SetId(usize);

/// One entry of one definition, after classification but before tool resolution.
///
/// `Tool` keeps the name rather than the requests because a `tool:` entry may
/// only be resolved *after* `validate_tools` has produced the file's tools, which
/// is later than this parse; `Set` keeps the target's id because the walk needs
/// edges, and the lookup that produced it is the one that proved the name exists.
#[derive(Debug, PartialEq, Eq)]
enum Bound {
    Literal(Allowance),
    Tool(String),
    Set(SetId),
}

/// A syntactically valid `[egress_sets]`: names, bound entries and the
/// dependency-first order. Nothing here has resolved a tool yet.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ParsedEgressSets {
    names: Vec<EgressSetName>,
    definitions: Vec<Vec<Bound>>,
    order: Vec<SetId>,
}

/// Every declared set's compiled closure, and the visits compiling them cost.
///
/// `work` is a plain field rather than a `#[cfg(test)]` one: the budget's exact
/// arithmetic is the property the tests discriminate, and a test-only field would
/// make the production type differ from the type under test.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct EgressSets {
    index: BTreeMap<EgressSetName, SetId>,
    closures: Vec<Vec<Allowance>>,
    work: usize,
}

impl EgressSets {
    /// What `name` grants, or `None` when the file does not declare it.
    pub(super) fn closure(&self, name: &EgressSetName) -> Option<&[Allowance]> {
        self.index
            .get(name)
            .map(|set| self.closures[set.0].as_slice())
    }
}

/// Why one `[egress_sets]` table was refused.
///
/// Every variant's text is fixed. Two of them may name a *top-level field*
/// spelling, which is a `&'static str` from the schema rather than bytes read from
/// the file, and none names a key or an entry: those are exactly the values a
/// mistyped definition carries (ADR-0039, #511 R28).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum EgressSetError {
    NotTable,
    /// A key equal to a top-level field name, i.e. a TOML-scoping mistake rather
    /// than a set definition.
    TopLevelKey {
        definition: usize,
        key: &'static str,
    },
    Name {
        definition: usize,
    },
    NotArray {
        definition: usize,
    },
    NotString {
        definition: usize,
        index: usize,
    },
    /// The entry's own error, reported at the entry's site.
    Entry {
        definition: usize,
        index: usize,
        error: super::EntryError,
    },
    /// The entry that closes a reference cycle.
    Cycle {
        definition: usize,
        index: usize,
    },
    ExpansionWorkLimit,
    ReferenceOrder,
}

impl fmt::Display for EgressSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotTable => f.write_str(
                "egress_sets: must be a table of named arrays of egress allowances and references",
            ),
            // The key is a schema spelling, never a value: a top-level field
            // written after `[egress_sets]` is scoped into it by TOML, so the
            // sentence names the fix instead of only the position.
            Self::TopLevelKey { definition, key } => write!(
                f,
                "egress_sets[{definition}]: {key} is not an egress set; a top-level {key} must be \
                 written before the first table header (keys after [egress_sets] belong to it)"
            ),
            Self::Name { definition } => write!(
                f,
                "egress_sets: definition {definition} has an invalid name; {InvalidEgressSetName}"
            ),
            Self::NotArray { definition } => {
                write!(f, "egress_sets[{definition}]: must be an array of strings")
            }
            Self::NotString { definition, index } => {
                write!(f, "egress_sets[{definition}][{index}]: must be a string")
            }
            Self::Entry {
                definition,
                index,
                error,
            } => write!(f, "egress_sets[{definition}][{index}]: {error}"),
            Self::Cycle { definition, index } => write!(
                f,
                "egress_sets[{definition}][{index}]: egress-set reference cycle"
            ),
            Self::ExpansionWorkLimit => write!(
                f,
                "egress_sets: expansion work exceeds limit of {MAX_EGRESS_SET_EXPANSION_WORK} \
                 allowance visits"
            ),
            Self::ReferenceOrder => {
                f.write_str("egress_sets: internal reference order was not resolved (agent-vm bug)")
            }
        }
    }
}

/// The file's one expansion counter.
struct ExpansionWork {
    used: usize,
}

impl ExpansionWork {
    /// Admit one candidate, or refuse. Checked before the increment, so `used`
    /// reaches the limit exactly and the probe and insert that follow each admit
    /// are the only work the budget has to cover.
    fn admit(&mut self) -> Result<(), EgressSetError> {
        if !egress_set_expansion_work_allowed(self.used) {
            return Err(EgressSetError::ExpansionWorkLimit);
        }
        self.used += 1;
        Ok(())
    }
}

/// Parse one `[egress_sets]` value into names, bound entries and a walk order.
///
/// Two passes over the already-deserialized table, as the mount graph does: names
/// first so a forward reference resolves and so definition numbers follow the
/// *sorted* keys rather than TOML's order, then entries. Nothing here looks at the
/// tools, which is why structure surfaces before tool validation — and why a cycle
/// needs no more than the names.
pub(super) fn parse(value: &toml::Value) -> Result<ParsedEgressSets, EgressSetError> {
    let table = value.as_table().ok_or(EgressSetError::NotTable)?;
    let mut pairs: Vec<(&String, &toml::Value)> = table.iter().collect();
    pairs.sort_by(|a, b| a.0.cmp(b.0));

    let mut names: Vec<EgressSetName> = Vec::with_capacity(pairs.len());
    let mut index: BTreeMap<EgressSetName, SetId> = BTreeMap::new();
    for (definition, (key, _)) in pairs.iter().enumerate() {
        // Reserved on the *name*, before the shape check, because shape is what
        // hides it: `network = { ... }` is a valid set definition that would grant
        // nothing and leave the defaults silently gone.
        if let Some(top_level) = crate::config::top_level_field(key) {
            return Err(EgressSetError::TopLevelKey {
                definition,
                key: top_level,
            });
        }
        let name = EgressSetName::parse(key).map_err(|_| EgressSetError::Name { definition })?;
        index.insert(name.clone(), SetId(definition));
        names.push(name);
    }

    let mut definitions: Vec<Vec<Bound>> = Vec::with_capacity(pairs.len());
    for (definition, (_, value)) in pairs.iter().enumerate() {
        let entries = value
            .as_array()
            .ok_or(EgressSetError::NotArray { definition })?;
        let mut bound: Vec<Bound> = Vec::with_capacity(entries.len());
        for (index_in_set, entry) in entries.iter().enumerate() {
            // One order inside a definition, so the reader is told the shape
            // before the contents: not-a-string, then the entry's own syntax, then
            // whether the set it names exists.
            let text = entry.as_str().ok_or(EgressSetError::NotString {
                definition,
                index: index_in_set,
            })?;
            let site = |error| EgressSetError::Entry {
                definition,
                index: index_in_set,
                error,
            };
            bound.push(match super::AllowanceEntry::parse(text).map_err(site)? {
                super::AllowanceEntry::Literal(allowance) => Bound::Literal(allowance),
                super::AllowanceEntry::Reference(reference) => match &reference.0 {
                    super::Target::Tool(name) => Bound::Tool(name.clone()),
                    // A forward reference is legal: every name is bound above,
                    // from the one TOML parse, before any entry is read.
                    super::Target::Set(name) => match index.get(name) {
                        Some(&target) => Bound::Set(target),
                        None => return Err(site(super::EntryError::UnknownSet)),
                    },
                },
            });
        }
        definitions.push(bound);
    }

    let order = walk(&definitions)?;
    Ok(ParsedEgressSets {
        names,
        definitions,
        order,
    })
}

/// Reject every cycle and return the dependency-first postorder.
///
/// Explicit frames with a colour per set, never recursion: a chain may be as long
/// as the file allows, and the Rust stack must not be the thing that decides
/// whether a config loads. Every definition is a root, so a cycle inside a
/// component nothing references is still refused; a set enters the postorder only
/// when it is complete, which is what makes the result dependency-first.
fn walk(definitions: &[Vec<Bound>]) -> Result<Vec<SetId>, EgressSetError> {
    let mut colors = vec![VisitState::Unseen; definitions.len()];
    let mut order: Vec<SetId> = Vec::with_capacity(definitions.len());
    let mut stack: Vec<(SetId, usize)> = Vec::new();
    for root in 0..definitions.len() {
        if colors[root] != VisitState::Unseen {
            continue;
        }
        colors[root] = VisitState::Active;
        stack.push((SetId(root), 0));
        while let Some((set, next)) = stack.last_mut() {
            let entries = &definitions[set.0];
            if *next == entries.len() {
                colors[set.0] = VisitState::Complete;
                order.push(*set);
                stack.pop();
                continue;
            }
            let index = *next;
            *next += 1;
            let Bound::Set(target) = entries[index] else {
                continue;
            };
            match visit_decision(colors[target.0]) {
                VisitDecision::Enter => {
                    colors[target.0] = VisitState::Active;
                    stack.push((target, 0));
                }
                // Named by the entry that closes the cycle, so the reader can find
                // the line without the sentence echoing a key.
                VisitDecision::Cycle => {
                    return Err(EgressSetError::Cycle {
                        definition: set.0,
                        index,
                    });
                }
                VisitDecision::Skip => {}
            }
        }
    }
    Ok(order)
}

/// Compile every declared set's unique closure, dependency-first.
///
/// One counter for the whole file, one hash index per set, and one charge per
/// *candidate*: a literal entry, each allowance of a tool expansion, and each
/// allowance of a child's closure. A second `tool:` or `set:` entry in the same
/// definition is skipped **before** it is charged, because the child's closure is
/// already unique by value and a second pass could only produce duplicates.
///
/// Errors stream: sets are compiled in the walk's postorder and entries in
/// declaration order, so the first failure — an entry error or exhaustion — is the
/// one reported (R19). No earlier stage is re-ordered to make that nicer.
pub(super) fn compile(
    parsed: ParsedEgressSets,
    tool_expansion: impl Fn(&str) -> Result<Vec<Allowance>, super::EntryError>,
) -> Result<EgressSets, EgressSetError> {
    let ParsedEgressSets {
        names,
        definitions,
        order,
    } = parsed;
    // Fail closed if the walk did not order every definition exactly once: a set
    // left out would be silently unvalidated, which is the whole property at
    // stake.
    let mut ordered = vec![false; definitions.len()];
    for set in &order {
        if std::mem::replace(&mut ordered[set.0], true) {
            return Err(EgressSetError::ReferenceOrder);
        }
    }
    if ordered.iter().any(|seen| !seen) {
        return Err(EgressSetError::ReferenceOrder);
    }

    let mut work = ExpansionWork { used: 0 };
    let mut closures: Vec<Vec<Allowance>> = vec![Vec::new(); definitions.len()];
    let mut compiled = vec![false; definitions.len()];
    for set in &order {
        // A hash index, not a scan: a wide closure would otherwise be quadratic in
        // its own length before the budget could bound anything.
        let mut seen: HashSet<Allowance> = HashSet::new();
        let mut unique: Vec<Allowance> = Vec::new();
        // Per set, so a repeated child or tool costs one membership probe rather
        // than a pass over its closure.
        let mut children: HashSet<SetId> = HashSet::new();
        let mut tools: BTreeSet<&str> = BTreeSet::new();
        for (index, entry) in definitions[set.0].iter().enumerate() {
            match entry {
                Bound::Literal(allowance) => {
                    admit_allowance(&mut seen, &mut unique, allowance, &mut work)?;
                }
                Bound::Tool(name) => {
                    if !tools.insert(name.as_str()) {
                        continue;
                    }
                    let expansion =
                        tool_expansion(name).map_err(|error| EgressSetError::Entry {
                            definition: set.0,
                            index,
                            error,
                        })?;
                    for allowance in expansion {
                        admit_allowance(&mut seen, &mut unique, &allowance, &mut work)?;
                    }
                }
                Bound::Set(child) => {
                    if !children.insert(*child) {
                        continue;
                    }
                    if !compiled[child.0] {
                        return Err(EgressSetError::ReferenceOrder);
                    }
                    for allowance in &closures[child.0] {
                        admit_allowance(&mut seen, &mut unique, allowance, &mut work)?;
                    }
                }
            }
        }
        closures[set.0] = unique;
        compiled[set.0] = true;
    }

    // The index is rebuilt from the names in sorted-definition order, so it holds
    // exactly the ids this compile used.
    let index = names
        .into_iter()
        .enumerate()
        .map(|(definition, name)| (name, SetId(definition)))
        .collect();
    Ok(EgressSets {
        index,
        closures,
        work: work.used,
    })
}

/// Admit one candidate allowance: charge it, then fold it into the closure.
///
/// The order is the contract (R17, ADR-0018): the charge precedes the hash probe,
/// so the budget bounds probes and inserts rather than being checked after them.
fn admit_allowance(
    seen: &mut HashSet<Allowance>,
    unique: &mut Vec<Allowance>,
    allowance: &Allowance,
    work: &mut ExpansionWork,
) -> Result<(), EgressSetError> {
    work.admit()?;
    if seen.insert(allowance.clone()) {
        unique.push(allowance.clone());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
